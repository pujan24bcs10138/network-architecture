#include "bhttp.h"
#include "io.h"
#include "path.h"

#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

typedef struct { char *host; const char *path; uint16_t port; bool verbose; } Options;

static bool parse_options(int argc, char **argv, Options *options)
{
    int index = 1;
    options->verbose = argc > 1 && !strcmp(argv[1], "-v");
    if (options->verbose) ++index;
    if (argc != index + 1 || !argv[index][0] || argv[index][0] == '-')
        return false;
    const char *input = argv[index];
    const char *slash = strchr(input, '/');
    size_t authority = slash ? (size_t)(slash - input) : strlen(input);
    if (!authority || authority > 260)
        return false;
    options->host = malloc(authority + 1);
    if (!options->host)
        return false;
    memcpy(options->host, input, authority);
    options->host[authority] = '\0';
    options->port = 9000;
    char *colon = strchr(options->host, ':');
    if (colon) {
        *colon++ = '\0';
        if (!bh_parse_port(colon, &options->port))
            return false;
    }
    if (!*options->host || strlen(options->host) > 253)
        return false;
    for (const char *p = options->host; *p; ++p)
        if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
              (*p >= '0' && *p <= '9') || *p == '-' || *p == '.'))
            return false;
    options->path = slash ? slash : "/";
    char normalized[BH_MAX_PATH + 1];
    return bh_normalize_path((const uint8_t *)options->path,
                             strlen(options->path), normalized);
}

static int connect_once(const Options *options)
{
    char service[6];
    snprintf(service, sizeof(service), "%u", options->port);
    struct addrinfo hints = {.ai_family = AF_INET, .ai_socktype = SOCK_STREAM};
    struct addrinfo *address = NULL;
    int error = getaddrinfo(options->host, service, &hints, &address);
    if (error) {
        fprintf(stderr, "bcurl: resolve: %s\n", gai_strerror(error));
        return -1;
    }
    int fd = socket(address->ai_family, address->ai_socktype, address->ai_protocol);
    if (fd < 0) {
        perror("bcurl: socket");
    } else if (connect(fd, address->ai_addr, address->ai_addrlen) < 0) {
        perror("bcurl: connect");
        close(fd);
        fd = -1;
    }
    freeaddrinfo(address);
    return fd;
}

static int receive_response(BHIO *io)
{
    bool have_response = false;
    uint16_t status = 0;
    uint64_t expected = 0, received = 0;
    uint8_t buffer[16384];
    for (;;) {
        BHFrame frame;
        if (bh_read_frame(io, &frame) != IO_OK)
            break;
        if (frame.length > BH_MAX_PAYLOAD) {
            bh_dump_end(&io->dump, false);
            break;
        }
        if (!bh_known_type(frame.type)) {
            if (bh_drain(io, frame.length) != IO_OK)
                break;
            continue;
        }
        if (!bh_valid_metadata(&frame) ||
            frame.type != (have_response ? BH_DATA : BH_RESPONSE)) {
            bh_dump_end(&io->dump, false);
            break;
        }
        bool complete = false;
        if (!have_response) {
            uint8_t *payload = malloc(frame.length ? frame.length : 1);
            if (!payload) {
                bh_dump_end(&io->dump, false);
                break;
            }
            IOResult result = bh_read_exact(io->fd, payload, frame.length, &io->dump);
            bh_dump_end(&io->dump, result == IO_OK);
            BHResponse response;
            bool valid = result == IO_OK &&
                bh_parse_response(payload, frame.length, &response);
            if (valid) {
                status = response.status;
                expected = response.content_length;
                valid = (frame.id == 1 || (frame.id == 0 && status == 400)) &&
                    (expected == 0 ? frame.flags == BH_END : frame.flags == 0) &&
                    (status < 400 || expected == 0);
            }
            free(payload);
            if (!valid) break;
            have_response = true;
            complete = frame.flags == BH_END;
        } else {
            if (frame.id != 1 || frame.length > expected - received ||
                (!frame.length && !(frame.flags & BH_END))) {
                bh_dump_end(&io->dump, false);
                break;
            }
            uint32_t remaining = frame.length;
            while (remaining) {
                size_t chunk = remaining < sizeof(buffer) ? remaining : sizeof(buffer);
                if (bh_read_exact(io->fd, buffer, chunk, &io->dump) != IO_OK ||
                    !bh_write_all(STDOUT_FILENO, buffer, chunk, NULL)) {
                    bh_dump_end(&io->dump, false);
                    goto failed;
                }
                remaining -= (uint32_t)chunk;
                received += chunk;
            }
            bh_dump_end(&io->dump, true);
            complete = frame.flags == BH_END;
            if (complete && received != expected)
                break;
        }
        if (complete)
            return status < 300 ? 0 : status < 400 ? 1 : 22;
    }
failed:
    fputs("bcurl: invalid or incomplete response, or I/O failure\n", stderr);
    return 1;
}

int main(int argc, char **argv)
{
    Options options = {0};
    if (!parse_options(argc, argv, &options)) {
        free(options.host);
        fputs("usage: bcurl [-v] HOST[:PORT][/PATH]\n", stderr);
        return 2;
    }
    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        perror("bcurl: signal");
        free(options.host);
        return 1;
    }
    int fd = connect_once(&options);
    free(options.host);
    if (fd < 0) return 1;
    BHIO io = {.fd = fd, .dump = {.enabled = options.verbose}};
    uint8_t payload[BH_MAX_PATH + 5];
    BHFields fields = {0};
    size_t size;
    bool ok = bh_encode_request(payload, sizeof(payload), &size, 1,
        (const uint8_t *)options.path, strlen(options.path), &fields);
    int result = 1;
    if (ok) {
        BHFrame frame = {(uint32_t)size, BH_REQUEST, 0, 0, 1};
        if (bh_send_frame(&io, &frame, payload))
            result = receive_response(&io);
        else
            perror("bcurl: send");
    }
    close(fd);
    return result;
}
