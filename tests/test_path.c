#include "path.h"

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void normalization(void)
{
    char output[BH_MAX_PATH + 1];
    const char *bad[] = {"", "index.html", "/..", "/.", "/a/../b", "/a//b",
        "//", "/a/", "/%2e%2e/x", "/%00", "/%7f", "/%80", "/%5c", "/%3f",
        "/%23", "/%", "/%0", "/%gg", "/a?b", "/a#b", "/a\\b", "/\n"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(*bad); ++i)
        assert(!bh_normalize_path((const uint8_t *)bad[i], strlen(bad[i]), output));
    assert(bh_normalize_path((const uint8_t *)"/", 1, output));
    assert(!strcmp(output, "index.html"));
    assert(bh_normalize_path((const uint8_t *)"/a%2Fb%20c.txt", strlen("/a%2Fb%20c.txt"), output));
    assert(!strcmp(output, "a/b c.txt"));
    assert(bh_normalize_path((const uint8_t *)"/%252e%252e", 11, output));
    assert(!strcmp(output, "%2e%2e"));
    assert(!strcmp(bh_mime_type("index.html"), "text/html"));
    assert(!strcmp(bh_mime_type("a.htm"), "text/html"));
    assert(!strcmp(bh_mime_type("a.txt"), "text/plain"));
    assert(!strcmp(bh_mime_type("a.HTML"), "application/octet-stream"));
    uint8_t long_path[BH_MAX_PATH + 1];
    memset(long_path, 'a', sizeof(long_path)); long_path[0] = '/';
    assert(bh_normalize_path(long_path, BH_MAX_PATH, output));
    assert(!bh_normalize_path(long_path, sizeof(long_path), output));
}

static void lookup(void)
{
    char temp[] = "/tmp/bhttp-path-XXXXXX";
    assert(mkdtemp(temp));
    int root = open(temp, O_RDONLY | O_DIRECTORY);
    assert(root >= 0);
    int file = openat(root, "index.html", O_CREAT | O_WRONLY, 0600);
    assert(file >= 0 && write(file, "hello\n", 6) == 6);
    close(file);
    assert(mkdirat(root, "nested", 0700) == 0);
    file = openat(root, "nested/empty", O_CREAT | O_WRONLY, 0600);
    assert(file >= 0); close(file);
    assert(symlinkat("index.html", root, "link") == 0);
    assert(symlinkat("nested", root, "dirlink") == 0);
    assert(mkfifoat(root, "pipe", 0600) == 0);
    uint64_t size;
    assert(bh_open_file(root, "index.html", &file, &size) == 200 && size == 6);
    close(file);
    assert(bh_open_file(root, "nested/empty", &file, &size) == 200 && size == 0);
    close(file);
    assert(bh_open_file(root, "missing", &file, &size) == 404);
    assert(bh_open_file(root, "index.html/child", &file, &size) == 404);
    assert(bh_open_file(root, "nested", &file, &size) == 403);
    assert(bh_open_file(root, "link", &file, &size) == 403);
    assert(bh_open_file(root, "dirlink/empty", &file, &size) == 403);
    assert(bh_open_file(root, "pipe", &file, &size) == 403);
    assert(fchmodat(root, "index.html", 0000, 0) == 0);
    if (geteuid() != 0)
        assert(bh_open_file(root, "index.html", &file, &size) == 403);
    assert(fchmodat(root, "index.html", 0600, 0) == 0);
    for (size_t i = 0; i < 100; ++i) {
        assert(bh_open_file(root, "nested/empty", &file, &size) == 200);
        close(file);
        assert(bh_open_file(root, "dirlink/empty", &file, &size) == 403);
    }
    assert(unlinkat(root, "nested/empty", 0) == 0);
    assert(unlinkat(root, "nested", AT_REMOVEDIR) == 0);
    assert(unlinkat(root, "index.html", 0) == 0);
    assert(unlinkat(root, "link", 0) == 0);
    assert(unlinkat(root, "dirlink", 0) == 0);
    assert(unlinkat(root, "pipe", 0) == 0);
    close(root);
    assert(rmdir(temp) == 0);
}

int main(void)
{
    normalization();
    lookup();
    puts("path checks passed");
    return 0;
}
