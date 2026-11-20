#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

size_t scan_byte_x64(const uint8_t *buf, size_t len, uint8_t needle);
size_t scan_calls_x64(const uint8_t *buf, size_t len, uint32_t *out, size_t max_out);
size_t scan_ascii_next_x64(const uint8_t *buf, size_t len, size_t pos);
size_t scan_ascii_run_x64(const uint8_t *buf, size_t len);

bool   scan_has_avx2(void);
size_t scan_byte_avx2(const uint8_t *buf, size_t len, uint8_t needle);
size_t scan_calls_avx2(const uint8_t *buf, size_t len, uint32_t *out, size_t max_out);
size_t scan_byte_fast(const uint8_t *buf, size_t len, uint8_t needle);
size_t scan_calls_fast(const uint8_t *buf, size_t len, uint32_t *out, size_t max_out);

#define SCAN_PAT_MAX 64

typedef struct {
    uint8_t bytes[SCAN_PAT_MAX];
    uint8_t mask[SCAN_PAT_MAX];
    size_t  len;
    size_t  anchor;
} scan_pat;

bool   scan_pat_parse(scan_pat *p, const char *text);
size_t scan_pat_find(const uint8_t *buf, size_t len, size_t start, const scan_pat *p);
size_t scan_text_find(const uint8_t *buf, size_t len, size_t start, const char *needle);
