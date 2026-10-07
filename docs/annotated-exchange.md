# Captured BHTTP/1 exchange

Captured by `make capture` from the C executables through a loopback proxy. The fixture is `tests/fixtures/index.html`, containing exactly `hello\n`. All three captured frames are checked against the golden wire bytes before this document is written.

## Client → server: REQUEST (28 bytes)

```text
00000000: 00 00 00 10 01 00 00 00 00 00 00 01 01 00 0b 2f
00000010: 69 6e 64 65 78 2e 68 74 6d 6c 00 00
```

Header: length 16, type 1, flags 0, reserved 0, ID 1. Payload: method 1 (GET), path length 11, `/index.html`, header count 0.

## Server → client: RESPONSE (32 bytes)

```text
00000000: 00 00 00 14 02 00 00 00 00 00 00 01 00 c8 00 02
00000010: 02 00 09 74 65 78 74 2f 68 74 6d 6c 03 00 01 36
```

Header: length 20, type 2, flags 0, reserved 0, ID 1. Payload: status 200, header count 2; ID 2, length 9, `text/html`; ID 3, length 1, `6`.

## Server → client: DATA (18 bytes)

```text
00000000: 00 00 00 06 03 01 00 00 00 00 00 01 68 65 6c 6c
00000010: 6f 0a
```

Header: length 6, type 3, flags 1 (END), reserved 0, ID 1. Payload: `hello\n`, exactly six body bytes.

Total: **78 bytes**. The client writes the six body bytes and exits 0. The server remains available for further requests/connections.
