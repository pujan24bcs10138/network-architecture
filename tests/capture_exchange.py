"""Capture actual bcurl/bserve application bytes through a loopback proxy."""
import socket
import subprocess
import threading

from test_integration import BIN, DEADLINE, ROOT, running_server
from wire_peer import DATA_GOLDEN, REQUEST_GOLDEN, RESPONSE_GOLDEN, read_frame, read_response


def capture():
    captured, errors = [], []
    with running_server(ROOT / "tests/fixtures") as (server_port, _):
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            listener.settimeout(DEADLINE)
            port = listener.getsockname()[1]

            def proxy():
                try:
                    downstream, _ = listener.accept()
                    with downstream, socket.create_connection(("127.0.0.1", server_port), timeout=DEADLINE) as upstream:
                        downstream.settimeout(DEADLINE)
                        raw_request = read_frame(downstream)[-1]
                        captured.append(raw_request)
                        upstream.sendall(raw_request)
                        status, _, _, body, raws = read_response(upstream)
                        assert status == 200 and body == b"hello\n"
                        captured.extend(raws)
                        downstream.sendall(b"".join(raws))
                except BaseException as error:
                    errors.append(error)

            worker = threading.Thread(target=proxy, daemon=True)
            worker.start()
            result = subprocess.run([str(BIN / "bcurl"), f"localhost:{port}/index.html"],
                                    capture_output=True, timeout=DEADLINE)
            worker.join(DEADLINE)
            assert not worker.is_alive(), "capture deadline"
            if errors:
                raise errors[0]
            assert result.returncode == 0 and result.stdout == b"hello\n", result
    assert captured == [REQUEST_GOLDEN, RESPONSE_GOLDEN, DATA_GOLDEN]
    return captured


def main():
    frames = capture()
    labels = ["Client → server: REQUEST", "Server → client: RESPONSE", "Server → client: DATA"]
    annotations = [
        "Header: length 16, type 1, flags 0, reserved 0, ID 1. Payload: method 1 (GET), "
        "path length 11, `/index.html`, header count 0.",
        "Header: length 20, type 2, flags 0, reserved 0, ID 1. Payload: status 200, "
        "header count 2; ID 2, length 9, `text/html`; ID 3, length 1, `6`.",
        "Header: length 6, type 3, flags 1 (END), reserved 0, ID 1. "
        "Payload: `hello\\n`, exactly six body bytes."
    ]
    lines = ["# Captured BHTTP/1 exchange", "",
        "Captured by `make capture` from the C executables through a loopback proxy. "
        "The fixture is `tests/fixtures/index.html`, containing exactly `hello\\n`. "
        "All three captured frames are checked against the golden wire bytes before this document is written.", ""]
    for label, raw, note in zip(labels, frames, annotations):
        lines += [f"## {label} ({len(raw)} bytes)", "", "```text"]
        for offset in range(0, len(raw), 16):
            lines.append(f"{offset:08x}: " + raw[offset:offset + 16].hex(" "))
        lines += ["```", "", note, ""]
    lines += ["Total: **78 bytes**. The client writes the six body bytes and exits 0. "
              "The server remains available for further requests/connections.", ""]
    (ROOT / "docs").mkdir(exist_ok=True)
    (ROOT / "docs/annotated-exchange.md").write_text("\n".join(lines))
    for label, raw in zip(("request", "response", "data"), frames):
        (ROOT / f"tests/fixtures/golden-{label}.hex").write_text(raw.hex(" ") + "\n")
    print("Captured and verified 78 bytes; wrote docs/annotated-exchange.md and golden hex fixtures.")


if __name__ == "__main__":
    main()
