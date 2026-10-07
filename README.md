# BHTTP/1 in C

`bserve` serves regular files over persistent TCP connections. `bcurl` sends one binary GET on one connection and writes the response body unchanged to stdout. Both are written in C17 and use the BHTTP/1 binary protocol.

## Build and run

Requires a C17 compiler, POSIX sockets/filesystem APIs, and Make. Developed and tested on Linux with GCC. Python 3.9 or newer is needed for the test and capture harnesses, with no extra packages.

```sh
make
./bserve ./tests/fixtures 9000
```

In another terminal:

```sh
./bcurl -v localhost:9000/index.html
./bcurl localhost:9000/ > downloaded.html
```

The fixture returns exactly `hello\n`. Port 9000 and path `/` are the client's defaults. The server binds IPv4 on all interfaces and processes connections sequentially. It stays on a connection until the peer closes, including after 400/404 responses; `bcurl` closes after its single completed response. Stop the server with Ctrl-C.

`-v` writes hexadecimal frame bytes, direction, and offsets to stderr; stdout contains only body bytes. A failed transfer can leave partial output. Client exits are 0 for completed 2xx, 22 for completed 4xx/5xx, 1 for transport/protocol/output failure or 3xx, and 2 for invalid arguments. Server startup/accept failures exit 1 and invalid arguments exit 2.

## Verification

```sh
make test
make sanitize
make capture
```

`make test` runs C codec/path/I/O checks and independent Python wire peers against both executables. Coverage includes the golden exchange, persistent requests, error recovery, fragmented input, unknown frame types, binary/empty files, path traversal and symlink denial, response length/END validation, file-size changes, CLI behavior, stdout errors, and single-connection behavior.

`make sanitize` builds separate binaries under `build/sanitize` with AddressSanitizer and UndefinedBehaviorSanitizer, then runs the same checks. The Linux sanitizer build disables PIE for stable sanitizer address-space placement. `make capture` runs the programs through a loopback proxy and regenerates [the annotated exchange](docs/annotated-exchange.md) and golden hex fixtures, checking all 78 bytes against the expected wire bytes.

Verified in this workspace: both C check programs and all 15 integration tests passed in normal and sanitizer builds; the actual captured exchange matched all 78 expected bytes.

Tests use local sockets. Permission-denial cases require a non-root account; `/proc` descriptor checks and `/dev/full` output-failure checks run where those Linux facilities are available. The Python peers encode and decode frames independently of the C codec.

## Implementation

| Module | Role |
| --- | --- |
| `src/protocol.c` | Frame and metadata codec, static header dictionary, checked integers. |
| `src/io.c` | Short-transfer/EINTR handling, bounded draining, streamed dumps. |
| `src/path.c` | One-pass path decoding and descriptor-based traversal under ROOT. |
| `src/bserve.c` | Listener, persistent request loop, statuses, file streaming. |
| `src/bcurl.c` | CLI, one connection attempt, response validation, stdout. |

Unknown types are skipped before interpreting their flags, reserved fields, or IDs. Metadata allocations are capped at 1 MiB; files, DATA, and skipped frames use bounded buffers. File lookup forbids symlinks and serves only opened regular files, using `openat()`/`O_NOFOLLOW` and `fstat()`.

This implementation uses blocking I/O, with no idle timeout or concurrent clients. CLI IPv6 syntax, TLS, request bodies, redirects, compression, and HTTP/2 compatibility are outside version 1's scope. Standard build variables (`CC`, `CPPFLAGS`, `CFLAGS`, `LDFLAGS`) are supported. `make clean` removes generated binaries and build objects.
