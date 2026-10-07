#ifndef BH_PATH_H
#define BH_PATH_H

#include "bhttp.h"

/* Produces a validated relative path, mapping / to index.html. */
bool bh_normalize_path(const uint8_t *input, size_t size,
                       char output[BH_MAX_PATH + 1]);
const char *bh_mime_type(const char *path);
/* Requires a normalized relative path. On 200, caller owns *file_fd.
 * Returns HTTP status; ROOT stays owned by caller. */
uint16_t bh_open_file(int root_fd, const char *path, int *file_fd, uint64_t *size);

#endif
