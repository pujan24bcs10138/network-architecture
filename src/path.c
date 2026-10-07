#include "path.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int hex_digit(uint8_t c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

bool bh_normalize_path(const uint8_t *input, size_t size,
                       char output[BH_MAX_PATH + 1])
{
    if (!input || !size || size > BH_MAX_PATH || input[0] != '/')
        return false;
    char decoded[BH_MAX_PATH + 1];
    size_t length = 0;
    for (size_t i = 0; i < size; ++i) {
        uint8_t c = input[i];
        if (c == '%') {
            if (size - i < 3)
                return false;
            int hi = hex_digit(input[i + 1]), lo = hex_digit(input[i + 2]);
            if (hi < 0 || lo < 0)
                return false;
            c = (uint8_t)(hi * 16 + lo);
            i += 2;
        }
        if (c < 0x20 || c >= 0x7f || c == '\\' || c == '?' || c == '#')
            return false;
        decoded[length++] = (char)c;
    }
    decoded[length] = '\0';
    if (length == 1) {
        strcpy(output, "index.html");
        return true;
    }
    if (decoded[length - 1] == '/')
        return false;
    size_t start = 1;
    for (size_t i = 1; i <= length; ++i) {
        if (i != length && decoded[i] != '/')
            continue;
        size_t component = i - start;
        if (!component || (component == 1 && decoded[start] == '.') ||
            (component == 2 && decoded[start] == '.' && decoded[start + 1] == '.'))
            return false;
        start = i + 1;
    }
    memcpy(output, decoded + 1, length); /* Includes the terminator. */
    return true;
}

const char *bh_mime_type(const char *path)
{
    const char *suffix = strrchr(path, '.');
    if (suffix && (!strcmp(suffix, ".html") || !strcmp(suffix, ".htm")))
        return "text/html";
    if (suffix && !strcmp(suffix, ".txt"))
        return "text/plain";
    return "application/octet-stream";
}

static uint16_t open_error(int parent, const char *name, int error, bool final)
{
    struct stat st;
    if (fstatat(parent, name, &st, AT_SYMLINK_NOFOLLOW) == 0 &&
        (S_ISLNK(st.st_mode) || (final && !S_ISREG(st.st_mode))))
        return 403;
    if (error == EACCES || error == EPERM || error == ELOOP)
        return 403;
    if (error == ENOENT || error == ENOTDIR)
        return 404;
    return 500;
}

uint16_t bh_open_file(int root_fd, const char *path, int *file_fd, uint64_t *size)
{
    char copy[BH_MAX_PATH + 1];
    size_t length = strlen(path);
    if (!length || length > BH_MAX_PATH)
        return 400;
    memcpy(copy, path, length + 1);
    int parent = root_fd;
    char *component = copy;
    for (;;) {
        char *slash = strchr(component, '/');
        bool final = slash == NULL;
        if (slash) *slash = '\0';
        int flags = O_RDONLY | O_NOFOLLOW | O_CLOEXEC;
        flags |= final ? O_NONBLOCK : O_DIRECTORY;
        int fd = openat(parent, component, flags);
        if (fd < 0) {
            int error = errno;
            uint16_t status = open_error(parent, component, error, final);
            if (parent != root_fd) close(parent);
            return status;
        }
        if (parent != root_fd) close(parent);
        if (final) {
            struct stat st;
            if (fstat(fd, &st) < 0 || st.st_size < 0) {
                close(fd);
                return 500;
            }
            if (!S_ISREG(st.st_mode)) {
                close(fd);
                return 403;
            }
            *file_fd = fd;
            *size = (uint64_t)st.st_size;
            return 200;
        }
        parent = fd;
        component = slash + 1;
    }
}
