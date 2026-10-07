import contextlib
import os
from pathlib import Path
import random
import re
import socket
import struct
import subprocess
import tempfile
import threading
import time
import unittest

from wire_peer import (DATA_GOLDEN, REQUEST_GOLDEN, RESPONSE_GOLDEN, exact, frame,
                       headers, read_frame, read_response, request, response)

ROOT = Path(__file__).resolve().parents[1]
BIN = Path(os.environ.get("BHTTP_BIN_DIR", ROOT))
DEADLINE = 8


def decode_dump(text):
    frames = []
    for line in text.splitlines():
        if line in (b"TX frame", b"RX frame"):
            frames.append((line[:2], bytearray()))
        elif re.match(rb"^[0-9a-f]{8}:", line):
            offset, payload = line.split(b":", 1)
            assert int(offset, 16) == len(frames[-1][1])
            frames[-1][1].extend(bytes.fromhex(payload.decode()))
    return [(direction, bytes(raw)) for direction, raw in frames]


def client(port, path="/index.html", verbose=False, **kwargs):
    args = [str(BIN / "bcurl")]
    if verbose:
        args += ["-v"]
    args += [f"127.0.0.1:{port}{path}"]
    return subprocess.run(args, capture_output=True, timeout=DEADLINE, **kwargs)


@contextlib.contextmanager
def running_server(root):
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    with tempfile.TemporaryFile() as errors:
        proc = subprocess.Popen([str(BIN / "bserve"), str(root), str(port)], stderr=errors)
        try:
            end = time.monotonic() + DEADLINE
            while True:
                if proc.poll() is not None:
                    errors.seek(0)
                    raise AssertionError(f"server exited: {errors.read()!r}")
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=.1):
                        break
                except (ConnectionRefusedError, TimeoutError):
                    if time.monotonic() > end:
                        raise AssertionError("server startup deadline")
                    time.sleep(.01)
            yield port, proc
        finally:
            proc.terminate()
            proc.wait(timeout=DEADLINE)
            errors.seek(0)
            output = errors.read()
            if b"Sanitizer" in output or b"runtime error:" in output:
                raise AssertionError(output.decode(errors="replace"))


def with_peer(callback, path="/index.html", verbose=False):
    """Run bcurl against an independent server; detect any second connection."""
    errors, captured = [], []
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(4)
    listener.settimeout(DEADLINE)
    port = listener.getsockname()[1]

    def serve():
        try:
            conn, _ = listener.accept()
            with conn:
                conn.settimeout(DEADLINE)
                captured.append(read_frame(conn)[-1])
                try:
                    callback(conn)
                except (BrokenPipeError, ConnectionResetError):
                    pass  # A rejecting client may stop reading a malformed reply.
            listener.settimeout(.1)
            try:
                extra, _ = listener.accept()
            except TimeoutError:
                return
            else:
                extra.close()
                raise AssertionError("client opened a second connection")
        except BaseException as error:
            errors.append(error)
        finally:
            listener.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        result = client(port, path, verbose)
    finally:
        thread.join(DEADLINE)
        if thread.is_alive():
            listener.close()
            raise AssertionError("peer deadline")
    if errors:
        raise errors[0]
    if b"Sanitizer" in result.stderr or b"runtime error:" in result.stderr:
        raise AssertionError(result.stderr.decode(errors="replace"))
    assert captured == [request((path or "/").encode())], captured
    return result


class ServerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "index.html").write_bytes(b"hello\n")
        (self.root / "empty.txt").write_bytes(b"")
        self.binary = bytes(range(256)) * 1200
        (self.root / "binary.bin").write_bytes(self.binary)
        (self.root / "nested").mkdir()
        (self.root / "nested" / "a b.txt").write_bytes(b"nested")
        self.context = running_server(self.root)
        self.port, self.proc = self.context.__enter__()
        self.addCleanup(self.context.__exit__, None, None, None)

    def connect(self):
        return socket.create_connection(("127.0.0.1", self.port), timeout=DEADLINE)

    def check_request(self, sock, raw, status, body=b"", ident=1):
        sock.sendall(raw)
        got, request_id, fields, actual, frames = read_response(sock)
        self.assertEqual((got, request_id, actual), (status, ident, body))
        self.assertEqual(int(fields[b"content-length"]), len(body))
        return fields, frames

    def test_golden_persistent_binary_empty_and_root(self):
        with self.connect() as sock:
            fields, raws = self.check_request(sock, REQUEST_GOLDEN, 200, b"hello\n")
            self.assertEqual(raws, [RESPONSE_GOLDEN, DATA_GOLDEN])
            self.assertEqual(fields[b"content-type"], b"text/html")
            self.check_request(sock, request(b"/missing", 2), 404, ident=2)
            self.check_request(sock, request(b"/", 3), 200, b"hello\n", 3)
            fields, raws = self.check_request(sock, request(b"/empty.txt", 4), 200, ident=4)
            self.assertEqual(fields[b"content-type"], b"text/plain")
            self.assertEqual(len(raws), 1)
            fields, raws = self.check_request(sock, request(b"/binary.bin", 5), 200, self.binary, 5)
            self.assertEqual(fields[b"content-type"], b"application/octet-stream")
            self.assertGreater(len(raws), 3)

    def test_fragmented_coalesced_and_unknown_frames(self):
        unknown = frame(222, b"extension", 255, 0, 65535)
        with self.connect() as sock:
            for byte in unknown + REQUEST_GOLDEN:
                sock.sendall(bytes([byte]))
            self.assertEqual(read_response(sock)[3], b"hello\n")
            sock.sendall(frame(0, request_id=0, reserved=65535, flags=255) +
                         request(b"/missing", 2) + request(b"/index.html", 3))
            self.assertEqual(read_response(sock)[0], 404)
            self.assertEqual(read_response(sock)[3], b"hello\n")

    def test_path_statuses_and_methods(self):
        (self.root / "link").symlink_to("index.html")
        (self.root / "dirlink").symlink_to("nested")
        (self.root / "outside").symlink_to("/etc/passwd")
        os.mkfifo(self.root / "pipe")
        (self.root / "denied").write_bytes(b"secret")
        (self.root / "denied").chmod(0)
        cases = [(b"/nested/a%20b.txt", 200, b"nested"),
                 (b"/nested%2Fa%20b.txt", 200, b"nested"),
                 (b"/link", 403, b""), (b"/dirlink/a%20b.txt", 403, b""),
                 (b"/outside", 403, b""), (b"/nested", 403, b""),
                 (b"/pipe", 403, b""), (b"/index.html/child", 404, b""),
                 (b"/../etc/passwd", 400, b""), (b"/%2e%2e/x", 400, b""),
                 (b"/%00", 400, b""), (b"/%ff", 400, b""),
                 (b"/a?b", 400, b""), (b"/a#b", 400, b""),
                 (b"/a//b", 400, b""), (b"/nested/", 400, b""),
                 (b"/%xy", 400, b""), (b"/\\", 400, b""),
                 (b"/\x7f", 400, b""), (b"/\xff", 400, b"")]
        if os.geteuid() != 0:
            cases.append((b"/denied", 403, b""))
        with self.connect() as sock:
            for ident, (path, status, body) in enumerate(cases, 1):
                with self.subTest(path=path):
                    self.check_request(sock, request(path, ident), status, body, ident)
            self.check_request(sock, request(method=2), 405)
            self.check_request(sock, request(b"/..", method=2), 400)

    def test_header_validation_and_recovery(self):
        good = request(entries=[(b"host", b"localhost"), (b"x-example", b"")])
        bad_payloads = [b"", b"\x01\x00\x00\x00\x00", REQUEST_GOLDEN[12:] + b"x",
            b"\x01\x00\x01/" + headers([(b"host", b"a"), (b"host", b"b")]),
            b"\x01\x00\x01/" + headers([(b"x-a", b"a"), (b"x-a", b"b")]),
            b"\x01\x00\x01/" + headers([(b"x-A", b"")]),
            b"\x01\x00\x01/" + headers([(b"host", b"\n")]),
            b"\x01\x00\x01/" + headers([(b"host", b"x" * 4097)]),
            b"\x01\x00\x01/\x00\x01\x0b\x00\x00",
            b"\x01\x00\x01/\x00\x21",
            b"\x01\x00\x01/\x00\x01\x00\x00\x04host\x00\x00"]
        with self.connect() as sock:
            for index, payload in enumerate(bad_payloads, 1):
                with self.subTest(index=index):
                    self.check_request(sock, frame(1, payload, request_id=index), 400, ident=index)
                    self.check_request(sock, good, 200, b"hello\n")
            for bad in (frame(1, REQUEST_GOLDEN[12:], flags=1),
                        frame(1, REQUEST_GOLDEN[12:], reserved=1),
                        frame(3, b"invalid-client-data"), frame(2, b"invalid-response")):
                self.check_request(sock, bad, 400)
            self.check_request(sock, request(request_id=0), 400, ident=0)
            self.check_request(sock, good, 200, b"hello\n")

    def test_oversized_and_truncated_then_new_client(self):
        for kind in (1, 222):
            with self.connect() as sock:
                sock.sendall(frame(kind, length=1048577))
                self.assertEqual(read_response(sock)[:2], (400, 0))
                self.assertEqual(sock.recv(1), b"")
        for truncated in (REQUEST_GOLDEN[:5], REQUEST_GOLDEN[:-1]):
            with self.connect() as sock:
                sock.sendall(truncated)
                sock.shutdown(socket.SHUT_WR)
                self.assertEqual(sock.recv(1), b"")
        result = client(self.port)
        self.assertEqual((result.returncode, result.stdout), (0, b"hello\n"))

    def test_random_malformed_frames_and_resources(self):
        rng = random.Random(0)
        fd_dir = Path(f"/proc/{self.proc.pid}/fd")
        baseline = len(list(fd_dir.iterdir())) if fd_dir.exists() else None
        with self.connect() as sock:
            for ident in range(1, 101):
                payload = bytes([255, 255, 255]) + rng.randbytes(rng.randrange(128))
                self.check_request(sock, frame(1, payload, request_id=ident), 400, ident=ident)
                self.check_request(sock, request(b"/nested/a%20b.txt", ident), 200, b"nested", ident)
        result = client(self.port, "/missing")
        self.assertEqual((result.returncode, result.stdout), (22, b""))
        if baseline is not None:
            end = time.monotonic() + 1
            while len(list(fd_dir.iterdir())) != baseline and time.monotonic() < end:
                time.sleep(.01)
            self.assertEqual(len(list(fd_dir.iterdir())), baseline)

    def test_file_size_changes_after_response(self):
        # A body larger than the socket buffers keeps the server streaming while
        # the peer changes the file after receiving the declared length.
        declared = 32 * 1024 * 1024
        target = self.root / "changing.bin"
        for shrink in (False, True):
            with self.subTest(shrink=shrink):
                with target.open("wb") as fixture:
                    fixture.truncate(declared)
                with self.connect() as sock:
                    sock.sendall(request(b"/changing.bin"))
                    kind, flags, _, _, payload, _ = read_frame(sock)
                    self.assertEqual((kind, flags), (2, 0))
                    with target.open("r+b") as fixture:
                        fixture.truncate(0 if shrink else declared + 65536)
                    total, complete = 0, False
                    while True:
                        try:
                            kind, flags, _, _, data, _ = read_frame(sock)
                        except EOFError:
                            break
                        self.assertEqual(kind, 3)  # No replacement RESPONSE.
                        total += len(data)
                        if flags == 1:
                            complete = True
                            break
                    if shrink:
                        self.assertFalse(complete)
                        self.assertLess(total, declared)
                    else:
                        self.assertTrue(complete)
                        self.assertEqual(total, declared)

    def test_verbose_actual_client(self):
        result = client(self.port, verbose=True)
        self.assertEqual((result.returncode, result.stdout), (0, b"hello\n"))
        self.assertEqual(result.stderr.count(b"TX frame"), 1)
        self.assertEqual(result.stderr.count(b"RX frame"), 2)
        self.assertEqual(decode_dump(result.stderr), [(b"TX", REQUEST_GOLDEN),
                         (b"RX", RESPONSE_GOLDEN), (b"RX", DATA_GOLDEN)])


class ClientTests(unittest.TestCase):
    def test_unknown_and_fragmented_response(self):
        frames = [frame(222, b"before", 255, 0, 65535), RESPONSE_GOLDEN,
                  frame(0, flags=255, reserved=65535, request_id=0),
                  frame(3, b"hel"), frame(99, b"between", 255, 123, 65535),
                  frame(3, b"lo\n", flags=1)]
        raw = b"".join(frames)
        def serve(sock):
            for byte in raw:
                sock.sendall(bytes([byte]))
        result = with_peer(serve, verbose=True)
        self.assertEqual((result.returncode, result.stdout), (0, b"hello\n"))
        self.assertEqual(result.stderr.count(b"RX frame"), 6)
        self.assertEqual(decode_dump(result.stderr), [(b"TX", REQUEST_GOLDEN)] +
                         [(b"RX", raw) for raw in frames])

    def test_large_unknown_payload_and_empty_final_data(self):
        raw = frame(222, b"x" * 1048576, 255, 0, 65535) + response(3) + frame(3, b"abc") + frame(3, flags=1)
        result = with_peer(lambda sock: sock.sendall(raw), verbose=True)
        self.assertEqual((result.returncode, result.stdout), (0, b"abc"))
        self.assertEqual(decode_dump(result.stderr)[1][1], raw[:1048576 + 12])

    def test_stdout_failure(self):
        if not Path("/dev/full").exists():
            self.skipTest("requires /dev/full")
        listener = socket.socket()
        self.addCleanup(listener.close)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(DEADLINE)
        with open("/dev/full", "wb") as output:
            proc = subprocess.Popen([str(BIN / "bcurl"),
                f"127.0.0.1:{listener.getsockname()[1]}/index.html"],
                stdout=output, stderr=subprocess.PIPE)
            try:
                conn, _ = listener.accept()
                with conn:
                    conn.settimeout(DEADLINE)
                    self.assertEqual(read_frame(conn)[-1], REQUEST_GOLDEN)
                    conn.sendall(RESPONSE_GOLDEN + DATA_GOLDEN)
                _, errors = proc.communicate(timeout=DEADLINE)
                self.assertEqual(proc.returncode, 1)
                self.assertIn(b"I/O failure", errors)
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.communicate()

    def test_zero_body_error_statuses_and_id_zero(self):
        for status, ident, exit_code in [(200, 1, 0), (204, 1, 0), (301, 1, 1),
                                         (400, 1, 22), (404, 1, 22), (500, 1, 22),
                                         (400, 0, 22)]:
            with self.subTest(status=status, ident=ident):
                result = with_peer(lambda sock: sock.sendall(response(status=status, request_id=ident)))
                self.assertEqual((result.returncode, result.stdout), (exit_code, b""))

    def test_invalid_responses(self):
        malformed_fields = [[], [(b"content-length", b"01")], [(b"content-length", b"-1")],
            [(b"content-length", b"18446744073709551616")],
            [(b"content-length", b"0"), (b"content-length", b"0")],
            [(b"content-length", b"0"), (b"x-A", b"")],
            [(b"content-length", b"0"), (b"x-a", b"\n")]]
        bad = [response(entries=entries) for entries in malformed_fields]
        bad += [response(status=199), response(status=600), response(request_id=2),
                response(status=404, request_id=0), response(size=0, flags=0),
                response(size=1, flags=1), response(size=1, status=400),
                frame(2, RESPONSE_GOLDEN[12:], reserved=1),
                frame(2, RESPONSE_GOLDEN[12:], flags=2),
                frame(2, RESPONSE_GOLDEN[12:] + b"extra"),
                frame(1, b"unexpected"), frame(3, b"premature", flags=1),
                frame(222, length=1048577), response(3) + frame(3, b"abc", 1, 2),
                response(3) + frame(3, b"abc", 2),
                response(3) + frame(3, b"ab", 1), response(3) + frame(3, b"abcd", 1),
                response(3) + frame(3), response(3) + frame(3, b"abc"),
                response(3) + response(3), response(3) + frame(1),
                response(65537) + frame(3, b"x" * 65537, 1),
                RESPONSE_GOLDEN[:5], RESPONSE_GOLDEN[:-1],
                RESPONSE_GOLDEN + DATA_GOLDEN[:-1]]
        for index, raw in enumerate(bad):
            with self.subTest(index=index):
                result = with_peer(lambda sock: sock.sendall(raw))
                self.assertEqual(result.returncode, 1, result.stderr)

    def test_default_root_path_and_literal_headers(self):
        raw = response(entries=[(b"content-length", b"0"), (b"x-example", b"")])
        result = with_peer(lambda sock: sock.sendall(raw), path="")
        self.assertEqual(result.returncode, 0)

    def test_invalid_cli_and_startup(self):
        for args in [[], ["-v"], ["http://localhost/a"], ["localhost:0"],
                     ["localhost:65536"], ["localhost:abc"], ["[::1]:9000/a"],
                     ["localhost/a?b"], ["localhost/%00"], ["localhost", "extra"]]:
            with self.subTest(args=args):
                result = subprocess.run([str(BIN / "bcurl"), *args], capture_output=True, timeout=DEADLINE)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, b"")
        for args in [[], [".", "0"], [".", "65536"]]:
            result = subprocess.run([str(BIN / "bserve"), *args], capture_output=True, timeout=DEADLINE)
            self.assertEqual(result.returncode, 2)
        result = subprocess.run([str(BIN / "bserve"), "/nonexistent-bhttp-root", "9000"],
                                capture_output=True, timeout=DEADLINE)
        self.assertEqual(result.returncode, 1)


if __name__ == "__main__":
    unittest.main()
