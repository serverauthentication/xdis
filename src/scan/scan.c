#include "scan.h"

#include <ctype.h>
#include <immintrin.h>
#include <intrin.h>
#include <string.h>

bool scan_has_avx2(void) {
    static int cached = -1;
    if (cached >= 0) return cached != 0;

    int info[4] = {0};
    __cpuid(info, 0);
    if (info[0] < 7) {
        cached = 0;
        return false;
    }

    __cpuid(info, 1);
    uint32_t ecx = (uint32_t)info[2];
    if ((ecx & (1u << 27)) == 0 || (ecx & (1u << 28)) == 0) {
        cached = 0;
        return false;
    }

    // verify os saves ymm state
    uint64_t xcr0 = _xgetbv(0);
    if ((xcr0 & 6ULL) != 6ULL) {
        cached = 0;
        return false;
    }

    __cpuidex(info, 7, 0);
    int ok = (((uint32_t)info[1] & (1u << 5)) != 0) ? 1 : 0;
    cached = ok;
    return ok != 0;
}

size_t scan_byte_fast(const uint8_t *buf, size_t len, uint8_t needle) {
    if (scan_has_avx2()) return scan_byte_avx2(buf, len, needle);
    return scan_byte_x64(buf, len, needle);
}

size_t scan_calls_fast(const uint8_t *buf, size_t len, uint32_t *out, size_t max_out) {
    if (scan_has_avx2()) return scan_calls_avx2(buf, len, out, max_out);
    return scan_calls_x64(buf, len, out, max_out);
}

static int scan_hex(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

bool scan_pat_parse(scan_pat *p, const char *text) {
    memset(p, 0, sizeof(*p));
    p->anchor = SCAN_PAT_MAX;
    if (!text) return false;

    const char *s = text;
    while (*s && p->len < SCAN_PAT_MAX) {
        while (*s == ' ' || *s == '\t' || *s == ',') s++;
        if (!*s) break;

        if (*s == '?') {
            if (s[1] == '?') s++;
            p->bytes[p->len] = 0;
            p->mask[p->len] = 0;
            p->len++;
            s++;
            continue;
        }

        int hi = scan_hex(s[0]);
        int lo = s[1] ? scan_hex(s[1]) : -1;
        if (hi < 0 || lo < 0) return false;

        if (p->anchor == SCAN_PAT_MAX) p->anchor = p->len;
        p->bytes[p->len] = (uint8_t)((hi << 4) | lo);
        p->mask[p->len] = 0xFF;
        p->len++;
        s += 2;
    }

    return p->len > 0;
}

size_t scan_pat_find(const uint8_t *buf, size_t len, size_t start, const scan_pat *p) {
    if (!buf || !p || p->len == 0 || start + p->len > len) return len;

    if (p->anchor >= p->len) return start;

    size_t pos = start;
    size_t limit = len - p->len;
    uint8_t needle = p->bytes[p->anchor];

    while (pos <= limit) {
        size_t base = pos + p->anchor;
        size_t span = (limit - pos) + 1;
        size_t rel = scan_byte_fast(buf + base, span, needle);
        if (rel >= span) return len;

        size_t cand = pos + rel;
        size_t i = 0;
        for (; i < p->len; i++) {
            if (p->mask[i] && buf[cand + i] != p->bytes[i]) break;
        }
        if (i == p->len) return cand;
        pos = cand + 1;
    }

    return len;
}

size_t scan_text_find(const uint8_t *buf, size_t len, size_t start, const char *needle) {
    if (!buf || !needle || !needle[0]) return len;
    size_t nlen = strlen(needle);
    if (start + nlen > len) return len;

    size_t pos = start;
    size_t limit = len - nlen;
    uint8_t first = (uint8_t)needle[0];

    while (pos <= limit) {
        size_t span = (limit - pos) + 1;
        size_t rel = scan_byte_fast(buf + pos, span, first);
        if (rel >= span) return len;
        size_t cand = pos + rel;
        if (memcmp(buf + cand, needle, nlen) == 0) return cand;
        pos = cand + 1;
    }

    return len;
}
