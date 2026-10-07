#include "io.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static void dump_row(BHDump *dump)
{
    static const char hex[] = "0123456789abcdef";
    char line[80];
    snprintf(line, sizeof(line), "%08zx:", dump->offset);
    size_t used = strlen(line);
    for (size_t i = 0; i < dump->used; ++i) {
        line[used++] = ' ';
        line[used++] = hex[dump->row[i] >> 4];
        line[used++] = hex[dump->row[i] & 15];
    }
    line[used++] = '\n';
    (void)fwrite(line, 1, used, stderr);
    dump->offset += dump->used;
    dump->used = 0;
}

void bh_dump_start(BHDump *dump, const char *direction)
{
    dump->offset = dump->used = 0;
    if (dump->enabled)
        fprintf(stderr, "%s frame\n", direction);
}

void bh_dump_feed(BHDump *dump, const uint8_t *bytes, size_t size)
{
    if (!dump || !dump->enabled)
        return;
    for (size_t i = 0; i < size; ++i) {
        dump->row[dump->used++] = bytes[i];
        if (dump->used == sizeof(dump->row))
            dump_row(dump);
    }
}

void bh_dump_end(BHDump *dump, bool complete)
{
    if (!dump->enabled)
        return;
    if (dump->used)
        dump_row(dump);
    if (!complete)
        fputs("[incomplete frame]\n", stderr);
}

IOResult bh_read_exact(int fd, void *buffer, size_t size, BHDump *dump)
{
    uint8_t *bytes = buffer;
    size_t done = 0;
    while (done < size) {
        ssize_t got = read(fd, bytes + done, size - done);
        if (got < 0) {
            if (errno == EINTR)
                continue;
            return IO_ERROR;
        }
        if (got == 0)
            return done ? IO_TRUNCATED : IO_EOF;
        bh_dump_feed(dump, bytes + done, (size_t)got);
        done += (size_t)got;
    }
    return IO_OK;
}

bool bh_write_all(int fd, const void *buffer, size_t size, BHDump *dump)
{
    const uint8_t *bytes = buffer;
    size_t done = 0;
    while (done < size) {
        ssize_t sent = write(fd, bytes + done, size - done);
        if (sent < 0) {
            if (errno == EINTR)
                continue;
            return false;
        }
        if (!sent) {
            errno = EIO;
            return false;
        }
        bh_dump_feed(dump, bytes + done, (size_t)sent);
        done += (size_t)sent;
    }
    return true;
}

IOResult bh_read_frame(BHIO *io, BHFrame *frame)
{
    uint8_t bytes[BH_FRAME_SIZE];
    bh_dump_start(&io->dump, "RX");
    IOResult result = bh_read_exact(io->fd, bytes, sizeof(bytes), &io->dump);
    if (result != IO_OK) {
        bh_dump_end(&io->dump, false);
        return result;
    }
    bh_decode_frame(bytes, frame);
    return IO_OK;
}

IOResult bh_drain(BHIO *io, uint32_t length)
{
    uint8_t buffer[16384];
    while (length) {
        size_t chunk = length < sizeof(buffer) ? length : sizeof(buffer);
        IOResult result = bh_read_exact(io->fd, buffer, chunk, &io->dump);
        if (result != IO_OK) {
            bh_dump_end(&io->dump, false);
            return result;
        }
        length -= (uint32_t)chunk;
    }
    bh_dump_end(&io->dump, true);
    return IO_OK;
}

bool bh_send_frame(BHIO *io, const BHFrame *frame, const void *payload)
{
    if (frame->length > BH_MAX_PAYLOAD || (frame->length && !payload)) {
        errno = EINVAL;
        return false;
    }
    uint8_t bytes[BH_FRAME_SIZE];
    bh_encode_frame(bytes, frame);
    bh_dump_start(&io->dump, "TX");
    bool ok = bh_write_all(io->fd, bytes, sizeof(bytes), &io->dump) &&
              bh_write_all(io->fd, payload, frame->length, &io->dump);
    bh_dump_end(&io->dump, ok);
    return ok;
}
