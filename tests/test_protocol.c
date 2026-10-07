#include "bhttp.h"
#include "io.h"

#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static void golden_and_boundaries(void)
{
    const uint8_t request_bytes[] = {
        1, 0, 11, '/', 'i', 'n', 'd', 'e', 'x', '.', 'h', 't', 'm', 'l', 0, 0
    };
    const uint8_t response_bytes[] = {
        0, 200, 0, 2, 2, 0, 9, 't', 'e', 'x', 't', '/', 'h', 't', 'm', 'l',
        3, 0, 1, '6'
    };
    const uint8_t frame_bytes[] = {0, 0, 0, 16, 1, 0, 0, 0, 0, 0, 0, 1};
    uint8_t out[256];
    size_t size;
    BHFrame frame = {16, BH_REQUEST, 0, 0, 1}, decoded;
    bh_encode_frame(out + 1, &frame); /* Exercise unaligned byte storage. */
    assert(!memcmp(out + 1, frame_bytes, sizeof(frame_bytes)));
    bh_decode_frame(frame_bytes, &decoded);
    assert(decoded.length == 16 && decoded.type == BH_REQUEST && decoded.id == 1);
    assert(bh_valid_metadata(&decoded));
    decoded.reserved = 1;
    assert(!bh_valid_metadata(&decoded));
    decoded.reserved = 0; decoded.flags = BH_END;
    assert(!bh_valid_metadata(&decoded));
    BHFields fields = {0};
    assert(bh_encode_request(out, sizeof(out), &size, 1,
        (const uint8_t *)"/index.html", 11, &fields));
    assert(size == sizeof(request_bytes) && !memcmp(out, request_bytes, size));
    BHRequest request;
    for (size_t i = 0; i < sizeof(request_bytes); ++i)
        assert(!bh_parse_request(request_bytes, i, &request));
    assert(bh_parse_request(request_bytes, sizeof(request_bytes), &request));
    assert(request.path_length == 11 && request.fields.count == 0);
    out[size] = 0;
    assert(!bh_parse_request(out, size + 1, &request));
    fields.count = 2;
    fields.entries[0] = (BHField){"content-type", 12, (const uint8_t *)"text/html", 9};
    fields.entries[1] = (BHField){"content-length", 14, (const uint8_t *)"6", 1};
    assert(bh_encode_response(out, sizeof(out), &size, 200, &fields));
    assert(size == sizeof(response_bytes) && !memcmp(out, response_bytes, size));
    BHResponse response;
    for (size_t i = 0; i < sizeof(response_bytes); ++i)
        assert(!bh_parse_response(response_bytes, i, &response));
    assert(bh_parse_response(response_bytes, sizeof(response_bytes), &response));
    assert(response.content_length == 6 && response.status == 200);
    assert(!bh_encode_response(out, 19, &size, 200, &fields));
    fields.count = 0;
    assert(!bh_encode_response(out, sizeof(out), &size, 200, &fields));
    uint64_t number;
    assert(bh_parse_decimal((const uint8_t *)"18446744073709551615", 20, &number));
    assert(number == UINT64_MAX);
    assert(bh_parse_decimal((const uint8_t *)"0", 1, &number) && number == 0);
    const char *bad[] = {"", "00", "01", "-1", "+1", " 1", "1 ", "1a",
                         "18446744073709551616"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(*bad); ++i)
        assert(!bh_parse_decimal((const uint8_t *)bad[i], strlen(bad[i]), &number));
    uint16_t port;
    assert(bh_parse_port("65535", &port) && port == 65535);
    assert(!bh_parse_port("65536", &port));
    assert(!bh_parse_port("0", &port));
    assert(!bh_parse_port("9999999999999999999999", &port));
}

static void header_rules(void)
{
    uint8_t out[140000], value[4097];
    memset(value, 'x', sizeof(value));
    BHFields fields = {.count = 1};
    fields.entries[0] = (BHField){"x-example", 9, value, 4096};
    size_t size;
    BHRequest request;
    assert(bh_encode_request(out, sizeof(out), &size, 1, (const uint8_t *)"/", 1, &fields));
    assert(bh_parse_request(out, size, &request));
    assert(request.fields.entries[0].value_length == 4096);
    fields.entries[0].value_length = 4097;
    assert(!bh_encode_request(out, sizeof(out), &size, 1, (const uint8_t *)"/", 1, &fields));
    fields.entries[0].value_length = 0;
    assert(bh_encode_request(out, sizeof(out), &size, 1, (const uint8_t *)"/", 1, &fields));
    assert(bh_parse_request(out, size, &request));
    fields.count = 2;
    fields.entries[1] = fields.entries[0];
    assert(!bh_encode_request(out, sizeof(out), &size, 1, (const uint8_t *)"/", 1, &fields));
    fields.count = 1;
    fields.entries[0].name = "X-example";
    assert(!bh_encode_request(out, sizeof(out), &size, 1, (const uint8_t *)"/", 1, &fields));
    fields.entries[0].name = "x-example";
    fields.entries[0].value_length = 1;
    value[0] = '\n';
    assert(!bh_encode_request(out, sizeof(out), &size, 1, (const uint8_t *)"/", 1, &fields));
    value[0] = 'x';
    char field_names[BH_MAX_FIELDS][16];
    fields.count = BH_MAX_FIELDS;
    for (size_t i = 0; i < fields.count; ++i) {
        int chars = snprintf(field_names[i], sizeof(field_names[i]), "x-%zu", i);
        assert(chars > 0);
        fields.entries[i] = (BHField){field_names[i], (size_t)chars, value, 1};
    }
    assert(bh_encode_request(out, sizeof(out), &size, 1, (const uint8_t *)"/", 1, &fields));
    assert(bh_parse_request(out, size, &request));
    out[5] = 33; /* Header count is at offsets 4..5. */
    assert(!bh_parse_request(out, size, &request));
    const uint8_t bad_id[] = {1, 0, 1, '/', 0, 1, 11, 0, 0};
    assert(!bh_parse_request(bad_id, sizeof(bad_id), &request));
    const uint8_t literal_alias[] = {1, 0, 1, '/', 0, 1, 0, 0, 4, 'h','o','s','t', 0, 0};
    assert(!bh_parse_request(literal_alias, sizeof(literal_alias), &request));
    const uint8_t duplicates[] = {1, 0, 1, '/', 0, 2, 1, 0, 0, 1, 0, 0};
    assert(!bh_parse_request(duplicates, sizeof(duplicates), &request));
    char long_name[65];
    memset(long_name, 'x', sizeof(long_name));
    fields.count = 1;
    fields.entries[0] = (BHField){long_name, 64, value, 0};
    assert(bh_encode_request(out, sizeof(out), &size, 1, (const uint8_t *)"/", 1, &fields));
    assert(bh_parse_request(out, size, &request));
    fields.entries[0].name_length = 65;
    assert(!bh_encode_request(out, sizeof(out), &size, 1, (const uint8_t *)"/", 1, &fields));
}

static volatile sig_atomic_t interrupted;
static void handle_signal(int sig) { (void)sig; interrupted = 1; }

static void io_rules(void)
{
    assert(signal(SIGPIPE, SIG_IGN) != SIG_ERR);
    int pair[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    assert(bh_write_all(pair[1], "ab", 2, NULL));
    close(pair[1]);
    uint8_t bytes[4];
    assert(bh_read_exact(pair[0], bytes, 4, NULL) == IO_TRUNCATED);
    assert(bytes[0] == 'a' && bytes[1] == 'b');
    assert(bh_read_exact(pair[0], bytes, 4, NULL) == IO_EOF);
    assert(!bh_write_all(pair[0], "x", 1, NULL) && errno == EPIPE);
    close(pair[0]);

    struct sigaction action = {.sa_handler = handle_signal};
    assert(sigemptyset(&action.sa_mask) == 0);
    assert(sigaction(SIGUSR1, &action, NULL) == 0);
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    pid_t parent = getpid(), child = fork();
    assert(child >= 0);
    if (child == 0) {
        close(pair[0]);
        struct timespec delay = {.tv_nsec = 100000000};
        nanosleep(&delay, NULL);
        assert(kill(parent, SIGUSR1) == 0);
        nanosleep(&delay, NULL);
        assert(bh_write_all(pair[1], "ab", 2, NULL));
        nanosleep(&delay, NULL);
        assert(bh_write_all(pair[1], "cd", 2, NULL));
        close(pair[1]);
        _exit(0);
    }
    close(pair[1]);
    assert(bh_read_exact(pair[0], bytes, 4, NULL) == IO_OK);
    assert(interrupted && !memcmp(bytes, "abcd", 4));
    close(pair[0]);
    int status;
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);

    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    int small = 1024;
    assert(setsockopt(pair[0], SOL_SOCKET, SO_SNDBUF, &small, sizeof(small)) == 0);
    child = fork();
    assert(child >= 0);
    if (child == 0) {
        close(pair[0]);
        uint8_t chunk[1024];
        for (size_t i = 0; i < 512; ++i) {
            assert(bh_read_exact(pair[1], chunk, sizeof(chunk), NULL) == IO_OK);
            for (size_t j = 0; j < sizeof(chunk); ++j) assert(chunk[j] == 0x5a);
        }
        close(pair[1]);
        _exit(0);
    }
    close(pair[1]);
    uint8_t *large = malloc(512 * 1024);
    assert(large);
    memset(large, 0x5a, 512 * 1024);
    assert(bh_write_all(pair[0], large, 512 * 1024, NULL));
    free(large);
    close(pair[0]);
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

int main(void)
{
    golden_and_boundaries();
    header_rules();
    io_rules();
    puts("protocol and I/O checks passed");
    return 0;
}
