#ifndef BHTTP_H
#define BHTTP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define BH_FRAME_SIZE 12u
#define BH_MAX_PAYLOAD 1048576u
#define BH_MAX_DATA 65536u
#define BH_MAX_PATH 4096u
#define BH_MAX_FIELDS 32u
#define BH_REQUEST 1u
#define BH_RESPONSE 2u
#define BH_DATA 3u
#define BH_END 1u

typedef struct {
    uint32_t length;
    uint8_t type, flags;
    uint16_t reserved;
    uint32_t id;
} BHFrame;

/* Parsed strings are views into the caller's payload or static dictionary. */
typedef struct {
    const char *name;
    size_t name_length;
    const uint8_t *value;
    size_t value_length;
} BHField;

typedef struct {
    size_t count;
    BHField entries[BH_MAX_FIELDS];
} BHFields;

typedef struct {
    uint8_t method;
    const uint8_t *path;
    size_t path_length;
    BHFields fields;
} BHRequest;

typedef struct {
    uint16_t status;
    uint64_t content_length;
    BHFields fields;
} BHResponse;

uint16_t bh_get16(const uint8_t *p);
uint32_t bh_get32(const uint8_t *p);
void bh_put16(uint8_t *p, uint16_t value);
void bh_put32(uint8_t *p, uint32_t value);
void bh_decode_frame(const uint8_t bytes[BH_FRAME_SIZE], BHFrame *frame);
void bh_encode_frame(uint8_t bytes[BH_FRAME_SIZE], const BHFrame *frame);
bool bh_known_type(uint8_t type);
bool bh_valid_metadata(const BHFrame *frame);
bool bh_parse_request(const uint8_t *payload, size_t size, BHRequest *request);
bool bh_parse_response(const uint8_t *payload, size_t size, BHResponse *response);
bool bh_parse_decimal(const uint8_t *text, size_t size, uint64_t *value);
bool bh_encode_request(uint8_t *out, size_t capacity, size_t *size,
                       uint8_t method, const uint8_t *path, size_t path_length,
                       const BHFields *fields);
bool bh_encode_response(uint8_t *out, size_t capacity, size_t *size,
                        uint16_t status, const BHFields *fields);
bool bh_parse_port(const char *text, uint16_t *port);

#endif
