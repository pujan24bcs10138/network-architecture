"""Independent BHTTP/1 wire encoding: deliberately does not use the C codec."""
import struct

NAMES = [None, b"host", b"content-type", b"content-length", b"user-agent",
         b"accept", b"accept-encoding", b"cache-control", b"date", b"server",
         b"last-modified"]
REQUEST_GOLDEN = bytes.fromhex(
    "00000010010000000000000101000b2f696e6465782e68746d6c0000")
RESPONSE_GOLDEN = bytes.fromhex(
    "00000014020000000000000100c80002020009746578742f68746d6c03000136")
DATA_GOLDEN = bytes.fromhex("00000006030100000000000168656c6c6f0a")


def frame(kind, payload=b"", flags=0, request_id=1, reserved=0, length=None):
    size = len(payload) if length is None else length
    return struct.pack("!IBBHI", size, kind, flags, reserved, request_id) + payload


def headers(entries):
    result = struct.pack("!H", len(entries))
    for name, value in entries:
        if name in NAMES:
            result += bytes([NAMES.index(name)])
        else:
            result += b"\0" + struct.pack("!H", len(name)) + name
        result += struct.pack("!H", len(value)) + value
    return result


def request(path=b"/index.html", request_id=1, method=1, entries=()):
    payload = bytes([method]) + struct.pack("!H", len(path)) + path + headers(entries)
    return frame(1, payload, request_id=request_id)


def response(size=0, status=200, request_id=1, entries=None, flags=None):
    if entries is None:
        entries = [(b"content-length", str(size).encode())]
    if flags is None:
        flags = 1 if size == 0 else 0
    return frame(2, struct.pack("!H", status) + headers(entries), flags, request_id)


def exact(sock, size):
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise EOFError(f"expected {size} bytes; received {len(data)}")
        data.extend(chunk)
    return bytes(data)


def read_frame(sock):
    head = exact(sock, 12)
    length, kind, flags, reserved, request_id = struct.unpack("!IBBHI", head)
    if length > 1048576:
        raise ValueError("oversized test-peer input")
    payload = exact(sock, length)
    return kind, flags, reserved, request_id, payload, head + payload


def decode_headers(payload, offset):
    count, = struct.unpack_from("!H", payload, offset)
    offset += 2
    fields = {}
    for _ in range(count):
        ident = payload[offset]
        offset += 1
        if ident:
            name = NAMES[ident]
        else:
            size, = struct.unpack_from("!H", payload, offset)
            offset += 2
            name = payload[offset:offset + size]
            offset += size
        size, = struct.unpack_from("!H", payload, offset)
        offset += 2
        if name in fields:
            raise ValueError("duplicate field")
        fields[name] = payload[offset:offset + size]
        offset += size
    if offset != len(payload):
        raise ValueError("trailing payload bytes")
    return fields


def read_response(sock):
    kind, flags, reserved, ident, payload, raw = read_frame(sock)
    assert kind == 2 and reserved == 0 and flags in (0, 1)
    status, = struct.unpack_from("!H", payload)
    fields = decode_headers(payload, 2)
    length = int(fields[b"content-length"])
    raws = [raw]
    body = bytearray()
    if flags:
        assert length == 0
    else:
        while True:
            kind, flags, reserved, data_id, data, raw = read_frame(sock)
            assert kind == 3 and reserved == 0 and data_id == ident
            assert len(data) <= 65536 and flags in (0, 1)
            assert data or flags
            body.extend(data)
            raws.append(raw)
            assert len(body) <= length
            if flags:
                break
    assert len(body) == length
    return status, ident, fields, bytes(body), raws
