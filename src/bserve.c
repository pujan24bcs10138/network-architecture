#include "bhttp.h"
#include "io.h"
#include "path.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static bool send_response(BHIO *io, uint32_t id, uint16_t status,
                          uint64_t length, const char *mime)
{
    char decimal[21];
    int chars = snprintf(decimal, sizeof(decimal), "%" PRIu64, length);
    if (chars < 1 || (size_t)chars >= sizeof(decimal))
        return false;
    BHFields fields = {0};
    if (mime)
        fields.entries[fields.count++] = (BHField){"content-type", 12,
            (const uint8_t *)mime, strlen(mime)};
    fields.entries[fields.count++] = (BHField){"content-length", 14,
        (const uint8_t *)decimal, (size_t)chars};
    uint8_t payload[128];
    size_t size;
    if (!bh_encode_response(payload, sizeof(payload), &size, status, &fields))
        return false;
    BHFrame frame = {(uint32_t)size, BH_RESPONSE, length ? 0 : BH_END, 0, id};
    return bh_send_frame(io, &frame, payload);
}

static bool send_file(BHIO *io, uint32_t id, int fd, uint64_t size)
{
    uint8_t buffer[BH_MAX_DATA];
    while (size) {
        size_t chunk = size < sizeof(buffer) ? (size_t)size : sizeof(buffer);
        if (bh_read_exact(fd, buffer, chunk, NULL) != IO_OK)
            return false;
        BHFrame frame = {(uint32_t)chunk, BH_DATA, size == chunk ? BH_END : 0, 0, id};
        if (!bh_send_frame(io, &frame, buffer))
            return false;
        size -= chunk;
    }
    return true;
}

static void serve_connection(int socket_fd, int root_fd)
{
    BHIO io = {.fd = socket_fd};
    for (;;) {
        BHFrame frame;
        if (bh_read_frame(&io, &frame) != IO_OK)
            return;
        if (frame.length > BH_MAX_PAYLOAD) {
            (void)send_response(&io, 0, 400, 0, NULL);
            return;
        }
        if (!bh_known_type(frame.type)) {
            if (bh_drain(&io, frame.length) != IO_OK)
                return;
            continue;
        }
        if (frame.type != BH_REQUEST || !bh_valid_metadata(&frame)) {
            if (bh_drain(&io, frame.length) != IO_OK ||
                !send_response(&io, frame.id, 400, 0, NULL))
                return;
            continue;
        }
        uint8_t *payload = malloc(frame.length ? frame.length : 1);
        if (!payload) {
            if (bh_drain(&io, frame.length) != IO_OK ||
                !send_response(&io, frame.id, 500, 0, NULL))
                return;
            continue;
        }
        IOResult result = bh_read_exact(socket_fd, payload, frame.length, &io.dump);
        bh_dump_end(&io.dump, result == IO_OK);
        if (result != IO_OK) {
            free(payload);
            return;
        }
        BHRequest request;
        char path[BH_MAX_PATH + 1];
        bool valid = bh_parse_request(payload, frame.length, &request) &&
            bh_normalize_path(request.path, request.path_length, path);
        uint16_t status = !valid ? 400 : request.method != 1 ? 405 : 200;
        /* No payload view is used after this point. */
        free(payload);
        int file_fd = -1;
        uint64_t size = 0;
        if (status == 200)
            status = bh_open_file(root_fd, path, &file_fd, &size);
        bool ok = send_response(&io, frame.id, status, size,
                                status == 200 ? bh_mime_type(path) : NULL);
        if (ok && status == 200 && size)
            ok = send_file(&io, frame.id, file_fd, size);
        if (file_fd >= 0) close(file_fd);
        if (!ok)
            return;
    }
}

int main(int argc, char **argv)
{
    uint16_t port;
    if (argc != 3 || !bh_parse_port(argv[2], &port)) {
        fputs("usage: bserve ROOT PORT\n", stderr);
        return 2;
    }
    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        perror("bserve: signal");
        return 1;
    }
    int root_fd = open(argv[1], O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (root_fd < 0) {
        perror("bserve: root");
        return 1;
    }
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0) {
        perror("bserve: socket");
        close(root_fd);
        return 1;
    }
    int reuse = 1;
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons(port),
                                 .sin_addr = {.s_addr = htonl(INADDR_ANY)}};
    if (setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0 ||
        bind(listener, (struct sockaddr *)&address, sizeof(address)) < 0 ||
        listen(listener, 16) < 0) {
        perror("bserve: listen");
        close(listener);
        close(root_fd);
        return 1;
    }
    for (;;) {
        int fd = accept(listener, NULL, NULL);
        if (fd < 0) {
            if (errno == EINTR) continue;
            perror("bserve: accept");
            break;
        }
        serve_connection(fd, root_fd);
        close(fd);
    }
    close(listener);
    close(root_fd);
    return 1;
}
