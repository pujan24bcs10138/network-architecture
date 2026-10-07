#ifndef BH_IO_H
#define BH_IO_H

#include "bhttp.h"

typedef enum { IO_OK, IO_EOF, IO_TRUNCATED, IO_ERROR } IOResult;
typedef struct {
    bool enabled;
    size_t offset, used;
    uint8_t row[16];
} BHDump;
typedef struct { int fd; BHDump dump; } BHIO;

void bh_dump_start(BHDump *dump, const char *direction);
void bh_dump_feed(BHDump *dump, const uint8_t *bytes, size_t size);
void bh_dump_end(BHDump *dump, bool complete);
IOResult bh_read_exact(int fd, void *buffer, size_t size, BHDump *dump);
bool bh_write_all(int fd, const void *buffer, size_t size, BHDump *dump);
IOResult bh_read_frame(BHIO *io, BHFrame *frame);
IOResult bh_drain(BHIO *io, uint32_t length);
bool bh_send_frame(BHIO *io, const BHFrame *frame, const void *payload);

#endif
