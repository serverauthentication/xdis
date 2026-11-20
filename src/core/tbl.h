#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define TBL_NONE UINT32_MAX

typedef struct {
    uint64_t key;
    uint32_t val;
} tbl_slot;

typedef struct {
    tbl_slot *slots;
    uint32_t  cap;
    uint32_t  len;
} tbl_u64;

static inline uint64_t tbl_hash(uint64_t k) {
    k ^= k >> 30;
    k *= 0xbf58476d1ce4e5b9ULL;
    k ^= k >> 27;
    k *= 0x94d049bb133111ebULL;
    return k ^ (k >> 31);
}

static inline void tbl_init(tbl_u64 *t) {
    t->slots = NULL;
    t->cap = 0;
    t->len = 0;
}

static inline void tbl_free(tbl_u64 *t) {
    free(t->slots);
    t->slots = NULL;
    t->cap = 0;
    t->len = 0;
}

static inline void tbl_clear(tbl_u64 *t) {
    if (!t->slots) return;
    for (uint32_t i = 0; i < t->cap; i++) t->slots[i].val = TBL_NONE;
    t->len = 0;
}

static inline bool tbl_grow(tbl_u64 *t, uint32_t need) {
    uint32_t ncap = t->cap ? t->cap : 64;
    while ((uint64_t)ncap * 7 < (uint64_t)need * 10) ncap <<= 1;

    tbl_slot *ns = (tbl_slot *)malloc((size_t)ncap * sizeof(tbl_slot));
    if (!ns) return false;
    for (uint32_t i = 0; i < ncap; i++) ns[i].val = TBL_NONE;

    uint32_t mask = ncap - 1;
    for (uint32_t i = 0; i < t->cap; i++) {
        if (t->slots[i].val == TBL_NONE) continue;
        uint32_t idx = (uint32_t)tbl_hash(t->slots[i].key) & mask;
        while (ns[idx].val != TBL_NONE) idx = (idx + 1) & mask;
        ns[idx] = t->slots[i];
    }

    free(t->slots);
    t->slots = ns;
    t->cap = ncap;
    return true;
}

static inline bool tbl_put(tbl_u64 *t, uint64_t key, uint32_t val) {
    if (val == TBL_NONE) return false;
    if ((uint64_t)(t->len + 1) * 10 >= (uint64_t)t->cap * 7) {
        if (!tbl_grow(t, t->len + 1)) return false;
    }
    uint32_t mask = t->cap - 1;
    uint32_t idx = (uint32_t)tbl_hash(key) & mask;
    while (t->slots[idx].val != TBL_NONE) {
        if (t->slots[idx].key == key) {
            t->slots[idx].val = val;
            return true;
        }
        idx = (idx + 1) & mask;
    }
    t->slots[idx].key = key;
    t->slots[idx].val = val;
    t->len++;
    return true;
}

static inline uint32_t tbl_get(const tbl_u64 *t, uint64_t key) {
    if (!t->slots || t->cap == 0) return TBL_NONE;
    uint32_t mask = t->cap - 1;
    uint32_t idx = (uint32_t)tbl_hash(key) & mask;
    while (t->slots[idx].val != TBL_NONE) {
        if (t->slots[idx].key == key) return t->slots[idx].val;
        idx = (idx + 1) & mask;
    }
    return TBL_NONE;
}
