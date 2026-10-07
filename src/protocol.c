#include "bhttp.h"

#include <string.h>

static const char *const names[] = {
    NULL, "host", "content-type", "content-length", "user-agent", "accept",
    "accept-encoding", "cache-control", "date", "server", "last-modified"
};

uint16_t bh_get16(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] << 8 | p[1]);
}

uint32_t bh_get32(const uint8_t *p)
{
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
           (uint32_t)p[2] << 8 | p[3];
}

void bh_put16(uint8_t *p, uint16_t value)
{
    p[0] = (uint8_t)(value >> 8);
    p[1] = (uint8_t)value;
}

void bh_put32(uint8_t *p, uint32_t value)
{
    p[0] = (uint8_t)(value >> 24);
    p[1] = (uint8_t)(value >> 16);
    p[2] = (uint8_t)(value >> 8);
    p[3] = (uint8_t)value;
}

void bh_decode_frame(const uint8_t bytes[BH_FRAME_SIZE], BHFrame *frame)
{
    *frame = (BHFrame){bh_get32(bytes), bytes[4], bytes[5],
                       bh_get16(bytes + 6), bh_get32(bytes + 8)};
}

void bh_encode_frame(uint8_t bytes[BH_FRAME_SIZE], const BHFrame *frame)
{
    bh_put32(bytes, frame->length);
    bytes[4] = frame->type;
    bytes[5] = frame->flags;
    bh_put16(bytes + 6, frame->reserved);
    bh_put32(bytes + 8, frame->id);
}

bool bh_known_type(uint8_t type)
{
    return type >= BH_REQUEST && type <= BH_DATA;
}

bool bh_valid_metadata(const BHFrame *frame)
{
    if (!bh_known_type(frame->type) || frame->reserved ||
        frame->length > BH_MAX_PAYLOAD)
        return false;
    if (frame->type == BH_REQUEST)
        return frame->flags == 0 && frame->id != 0;
    if (frame->flags & ~BH_END)
        return false;
    /* ID 0 on RESPONSE is checked against its status by the client. */
    return frame->type != BH_DATA ||
           (frame->id != 0 && frame->length <= BH_MAX_DATA);
}

typedef struct { const uint8_t *p; size_t left; } Reader;

static const uint8_t *take(Reader *r, size_t size)
{
    if (size > r->left)
        return NULL;
    const uint8_t *p = r->p;
    r->p += size;
    r->left -= size;
    return p;
}

static unsigned name_id(const char *name, size_t size)
{
    for (unsigned i = 1; i <= 10; ++i)
        if (strlen(names[i]) == size && !memcmp(names[i], name, size))
            return i;
    return 0;
}

static bool valid_name(const char *name, size_t size)
{
    if (!size || size > 64)
        return false;
    for (size_t i = 0; i < size; ++i)
        if (!((name[i] >= 'a' && name[i] <= 'z') ||
              (name[i] >= '0' && name[i] <= '9') || name[i] == '-'))
            return false;
    return true;
}

static bool valid_value(const uint8_t *value, size_t size)
{
    if (size > 4096)
        return false;
    for (size_t i = 0; i < size; ++i)
        if (value[i] < 0x20 || value[i] > 0x7e)
            return false;
    return true;
}

static bool duplicate(const BHFields *fields, size_t index)
{
    const BHField *field = &fields->entries[index];
    for (size_t i = 0; i < index; ++i) {
        const BHField *other = &fields->entries[i];
        if (field->name_length == other->name_length &&
            !memcmp(field->name, other->name, field->name_length))
            return true;
    }
    return false;
}

static bool parse_fields(Reader *r, BHFields *fields)
{
    const uint8_t *p = take(r, 2);
    if (!p || bh_get16(p) > BH_MAX_FIELDS)
        return false;
    fields->count = bh_get16(p);
    for (size_t i = 0; i < fields->count; ++i) {
        BHField *f = &fields->entries[i];
        p = take(r, 1);
        if (!p || *p > 10)
            return false;
        if (*p) {
            f->name = names[*p];
            f->name_length = strlen(f->name);
        } else {
            p = take(r, 2);
            if (!p)
                return false;
            f->name_length = bh_get16(p);
            f->name = (const char *)take(r, f->name_length);
            if (!f->name || !valid_name(f->name, f->name_length) ||
                name_id(f->name, f->name_length))
                return false;
        }
        p = take(r, 2);
        if (!p)
            return false;
        f->value_length = bh_get16(p);
        f->value = take(r, f->value_length);
        if (!f->value || !valid_value(f->value, f->value_length) || duplicate(fields, i))
            return false;
    }
    return true;
}

bool bh_parse_request(const uint8_t *payload, size_t size, BHRequest *request)
{
    if (!payload || size > BH_MAX_PAYLOAD)
        return false;
    Reader r = {payload, size};
    const uint8_t *p = take(&r, 3);
    if (!p)
        return false;
    request->method = p[0];
    request->path_length = bh_get16(p + 1);
    if (!request->path_length || request->path_length > BH_MAX_PATH)
        return false;
    request->path = take(&r, request->path_length);
    return request->path && parse_fields(&r, &request->fields) && !r.left;
}

bool bh_parse_decimal(const uint8_t *text, size_t size, uint64_t *value)
{
    if (!size || (size > 1 && text[0] == '0'))
        return false;
    uint64_t result = 0;
    for (size_t i = 0; i < size; ++i) {
        if (text[i] < '0' || text[i] > '9')
            return false;
        unsigned digit = text[i] - '0';
        if (result > (UINT64_MAX - digit) / 10)
            return false;
        result = result * 10 + digit;
    }
    *value = result;
    return true;
}

bool bh_parse_response(const uint8_t *payload, size_t size, BHResponse *response)
{
    if (!payload || size > BH_MAX_PAYLOAD)
        return false;
    Reader r = {payload, size};
    const uint8_t *p = take(&r, 2);
    if (!p)
        return false;
    response->status = bh_get16(p);
    if (response->status < 200 || response->status > 599 ||
        !parse_fields(&r, &response->fields) || r.left)
        return false;
    for (size_t i = 0; i < response->fields.count; ++i) {
        const BHField *field = &response->fields.entries[i];
        if (name_id(field->name, field->name_length) == 3)
            return bh_parse_decimal(field->value, field->value_length,
                                    &response->content_length);
    }
    return false;
}

typedef struct { uint8_t *p; size_t left, size; } Writer;

static bool append(Writer *w, const void *data, size_t size)
{
    if (size > w->left)
        return false;
    if (size)
        memcpy(w->p, data, size);
    w->p += size;
    w->left -= size;
    w->size += size;
    return true;
}

static bool put16(Writer *w, uint16_t value)
{
    uint8_t bytes[2];
    bh_put16(bytes, value);
    return append(w, bytes, 2);
}

static bool encode_fields(Writer *w, const BHFields *fields)
{
    if (fields->count > BH_MAX_FIELDS || !put16(w, (uint16_t)fields->count))
        return false;
    for (size_t i = 0; i < fields->count; ++i) {
        const BHField *f = &fields->entries[i];
        if (!f->name || (!f->value && f->value_length) ||
            !valid_name(f->name, f->name_length) ||
            !valid_value(f->value, f->value_length) || duplicate(fields, i))
            return false;
        uint8_t id = (uint8_t)name_id(f->name, f->name_length);
        if (!append(w, &id, 1))
            return false;
        if (!id && (!put16(w, (uint16_t)f->name_length) ||
                    !append(w, f->name, f->name_length)))
            return false;
        if (!put16(w, (uint16_t)f->value_length) ||
            !append(w, f->value, f->value_length))
            return false;
    }
    return true;
}

bool bh_encode_request(uint8_t *out, size_t capacity, size_t *size,
                       uint8_t method, const uint8_t *path, size_t path_length,
                       const BHFields *fields)
{
    Writer w = {out, capacity, 0};
    if (!path || !path_length || path_length > BH_MAX_PATH ||
        !append(&w, &method, 1) || !put16(&w, (uint16_t)path_length) ||
        !append(&w, path, path_length) || !encode_fields(&w, fields) ||
        w.size > BH_MAX_PAYLOAD)
        return false;
    *size = w.size;
    return true;
}

bool bh_encode_response(uint8_t *out, size_t capacity, size_t *size,
                        uint16_t status, const BHFields *fields)
{
    Writer w = {out, capacity, 0};
    if (status < 200 || status > 599 || !put16(&w, status) ||
        !encode_fields(&w, fields) || w.size > BH_MAX_PAYLOAD)
        return false;
    BHResponse response;
    if (!bh_parse_response(out, w.size, &response))
        return false;
    *size = w.size;
    return true;
}

bool bh_parse_port(const char *text, uint16_t *port)
{
    if (!text || !*text)
        return false;
    unsigned value = 0;
    for (const char *p = text; *p; ++p) {
        if (*p < '0' || *p > '9')
            return false;
        value = value * 10 + (unsigned)(*p - '0');
        if (value > 65535)
            return false;
    }
    if (!value)
        return false;
    *port = (uint16_t)value;
    return true;
}
