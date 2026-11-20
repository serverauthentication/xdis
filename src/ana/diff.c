#include "ana.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DIF_MAX_FUNC 2000

typedef struct {
    uint64_t    va;
    uint32_t    size;
    uint64_t    dna;
    uint32_t    nins;
    uint32_t    nblk;
    uint32_t    ncall;
    uint64_t    bhash;
    const char *name;
    uint8_t     named;
    uint8_t     used;
} dif_fn;

typedef struct {
    uint32_t    idx;
    const char *name;
} dif_nidx;

typedef struct {
    uint32_t idx;
    uint64_t k1;
    uint32_t k2;
} dif_kidx;

void dif_free(dif_res *d) {
    if (!d) return;
    free(d->items);
    memset(d, 0, sizeof(*d));
}

static uint64_t dif_hash_bytes(const ana_ctx *a, uint64_t va, uint32_t size) {
    if (size == 0) return 0;
    size_t len = size > 4096 ? 4096 : (size_t)size;
    size_t av = 0;
    const uint8_t *p = bin_ptr(&a->bin, va, &av);
    if (!p || av == 0) return 0;
    if (len > av) len = av;

    uint64_t h = 14695981039346656037ULL;
    for (size_t i = 0; i < len; i++) {
        h ^= (uint64_t)p[i];
        h *= 1099511628211ULL;
    }
    return h ? h : 1;
}

static bool dif_bytes_eq(const ana_ctx *a, const dif_fn *fa, const ana_ctx *b, const dif_fn *fb) {
    if (fa->size == 0 || fa->size != fb->size) return false;
    size_t len = fa->size > 4096 ? 4096 : (size_t)fa->size;
    size_t aa = 0, ab = 0;
    const uint8_t *pa = bin_ptr(&a->bin, fa->va, &aa);
    const uint8_t *pb = bin_ptr(&b->bin, fb->va, &ab);
    if (!pa || !pb || aa < len || ab < len) return false;
    return memcmp(pa, pb, len) == 0;
}

static int dif_ratio(uint32_t x, uint32_t y) {
    if (x == 0 && y == 0) return 100;
    uint32_t mx = x > y ? x : y;
    uint32_t mn = x < y ? x : y;
    return (int)((100ULL * mn) / mx);
}

static int dif_calc_sim(const dif_fn *fa, const dif_fn *fb) {
    int si = dif_ratio(fa->nins, fb->nins);
    int sb = dif_ratio(fa->nblk, fb->nblk);
    int sc = dif_ratio(fa->ncall, fb->ncall);
    int ss = dif_ratio(fa->size, fb->size);
    int sim = (fa->nins || fb->nins) ? ((si * 4 + sb * 3 + sc * 2 + ss) / 10) : ss;
    if (fa->dna != 0 && fa->dna == fb->dna) sim = (sim + 99) / 2;
    if (sim < 0) sim = 0;
    if (sim > 99) sim = 99;
    return sim;
}

static void dif_fill_fns(const ana_ctx *ctx, dif_fn *arr, uint32_t n) {
    for (uint32_t i = 0; i < n; i++) {
        const ana_func *f = &ctx->funcs[i];
        dif_fn *d = &arr[i];
        memset(d, 0, sizeof(*d));
        d->va = f->start;
        d->size = (f->end > f->start) ? (uint32_t)(f->end - f->start) : 0;
        d->dna = sig_dna(ctx, f->start, &d->nins, &d->nblk, &d->ncall);
        d->bhash = dif_hash_bytes(ctx, f->start, d->size);
        const char *nm = ana_pool_str(ctx, f->name_off);
        if (!nm || !nm[0]) nm = ana_sym_at(ctx, f->start);
        d->name = nm ? nm : "";
        d->named = (d->name[0] && strncmp(d->name, "sub_", 4) != 0 && strncmp(d->name, "loc_", 4) != 0) ? 1 : 0;
    }
}

static int dif_nidx_cmp(const void *a, const void *b) {
    return strcmp(((const dif_nidx *)a)->name, ((const dif_nidx *)b)->name);
}

static int dif_kidx_cmp(const void *a, const void *b) {
    const dif_kidx *x = (const dif_kidx *)a;
    const dif_kidx *y = (const dif_kidx *)b;
    if (x->k1 != y->k1) return (x->k1 > y->k1) - (x->k1 < y->k1);
    return (x->k2 > y->k2) - (x->k2 < y->k2);
}

static int dif_kind_rank(uint8_t k) {
    if (k == DIF_MOD) return 0;
    if (k == DIF_ADD) return 1;
    if (k == DIF_DEL) return 2;
    return 3;
}

static int dif_item_cmp(const void *a, const void *b) {
    const dif_item *x = (const dif_item *)a;
    const dif_item *y = (const dif_item *)b;
    int rx = dif_kind_rank(x->kind);
    int ry = dif_kind_rank(y->kind);
    if (rx != ry) return rx - ry;
    if (x->kind == DIF_MOD && x->sim != y->sim) return x->sim - y->sim;
    uint64_t vx = x->va_a ? x->va_a : x->va_b;
    uint64_t vy = y->va_a ? y->va_a : y->va_b;
    return (vx > vy) - (vx < vy);
}

static void dif_push(dif_res *out, uint64_t va_a, uint64_t va_b, const char *name,
                     uint8_t kind, int sim, uint32_t sz_a, uint32_t sz_b) {
    dif_item *it = &out->items[out->nitem++];
    memset(it, 0, sizeof(*it));
    it->va_a = va_a;
    it->va_b = va_b;
    it->kind = kind;
    it->sim = sim;
    it->size_a = sz_a;
    it->size_b = sz_b;
    if (name && name[0]) snprintf(it->name, sizeof(it->name), "%s", name);
    else snprintf(it->name, sizeof(it->name), "sub_%llx", (unsigned long long)(va_a ? va_a : va_b));

    if (kind == DIF_SAME) out->same++;
    else if (kind == DIF_MOD) out->mod++;
    else if (kind == DIF_ADD) out->add++;
    else if (kind == DIF_DEL) out->del++;
}

bool dif_compare(const ana_ctx *a, const ana_ctx *b, dif_res *out) {
    if (!a || !b || !out) return false;
    dif_free(out);

    uint32_t na = a->nfunc < DIF_MAX_FUNC ? a->nfunc : DIF_MAX_FUNC;
    uint32_t nb = b->nfunc < DIF_MAX_FUNC ? b->nfunc : DIF_MAX_FUNC;
    if (na == 0 && nb == 0) return true;

    dif_fn *fa = na ? (dif_fn *)calloc(na, sizeof(dif_fn)) : NULL;
    dif_fn *fb = nb ? (dif_fn *)calloc(nb, sizeof(dif_fn)) : NULL;
    out->items = (dif_item *)calloc((size_t)(na + nb), sizeof(dif_item));
    if ((na && !fa) || (nb && !fb) || !out->items) {
        free(fa);
        free(fb);
        dif_free(out);
        return false;
    }

    dif_fill_fns(a, fa, na);
    dif_fill_fns(b, fb, nb);

    // pass 1: exact symbol name match
    dif_nidx *bn = nb ? (dif_nidx *)malloc((size_t)nb * sizeof(dif_nidx)) : NULL;
    uint32_t nbn = 0;
    if (bn) {
        for (uint32_t j = 0; j < nb; j++) {
            if (fb[j].named) {
                bn[nbn].idx = j;
                bn[nbn].name = fb[j].name;
                nbn++;
            }
        }
        if (nbn > 1) qsort(bn, nbn, sizeof(dif_nidx), dif_nidx_cmp);

        for (uint32_t i = 0; i < na; i++) {
            if (!fa[i].named || nbn == 0) continue;
            uint32_t lo = 0, hi = nbn;
            while (lo < hi) {
                uint32_t mid = lo + (hi - lo) / 2;
                if (strcmp(bn[mid].name, fa[i].name) < 0) lo = mid + 1;
                else hi = mid;
            }
            for (uint32_t k = lo; k < nbn && strcmp(bn[k].name, fa[i].name) == 0; k++) {
                uint32_t j = bn[k].idx;
                if (fb[j].used) continue;
                fa[i].used = 1;
                fb[j].used = 1;
                bool same = (fa[i].dna != 0 && fa[i].dna == fb[j].dna && fa[i].size == fb[j].size) ||
                            (fa[i].dna == 0 && fb[j].dna == 0 && dif_bytes_eq(a, &fa[i], b, &fb[j]));
                if (same) dif_push(out, fa[i].va, fb[j].va, fa[i].name, DIF_SAME, 100, fa[i].size, fb[j].size);
                else dif_push(out, fa[i].va, fb[j].va, fa[i].name, DIF_MOD, dif_calc_sim(&fa[i], &fb[j]), fa[i].size, fb[j].size);
                break;
            }
        }
        free(bn);
    }

    // pass 2: structural dna match
    dif_kidx *bd = nb ? (dif_kidx *)malloc((size_t)nb * sizeof(dif_kidx)) : NULL;
    uint32_t nbd = 0;
    if (bd) {
        for (uint32_t j = 0; j < nb; j++) {
            if (!fb[j].used && fb[j].dna != 0 && fb[j].nins >= 4) {
                bd[nbd].idx = j;
                bd[nbd].k1 = fb[j].dna;
                bd[nbd].k2 = fb[j].nblk;
                nbd++;
            }
        }
        if (nbd > 1) qsort(bd, nbd, sizeof(dif_kidx), dif_kidx_cmp);

        for (uint32_t i = 0; i < na; i++) {
            if (fa[i].used || fa[i].dna == 0 || fa[i].nins < 4 || nbd == 0) continue;
            uint32_t lo = 0, hi = nbd;
            while (lo < hi) {
                uint32_t mid = lo + (hi - lo) / 2;
                if (bd[mid].k1 < fa[i].dna) lo = mid + 1;
                else hi = mid;
            }
            int best = -1;
            for (uint32_t k = lo; k < nbd && bd[k].k1 == fa[i].dna; k++) {
                uint32_t j = bd[k].idx;
                if (fb[j].used || fb[j].nblk != fa[i].nblk || fb[j].ncall != fa[i].ncall) continue;
                if (best < 0 || (fb[j].size == fa[i].size && fb[j].nins == fa[i].nins)) {
                    best = (int)j;
                    if (fb[j].size == fa[i].size && fb[j].nins == fa[i].nins) break;
                }
            }
            if (best >= 0) {
                uint32_t j = (uint32_t)best;
                fa[i].used = 1;
                fb[j].used = 1;
                const char *nm = fa[i].named ? fa[i].name : (fb[j].named ? fb[j].name : fa[i].name);
                if (fa[i].size == fb[j].size && fa[i].nins == fb[j].nins) {
                    dif_push(out, fa[i].va, fb[j].va, nm, DIF_SAME, 100, fa[i].size, fb[j].size);
                } else {
                    dif_push(out, fa[i].va, fb[j].va, nm, DIF_MOD, dif_calc_sim(&fa[i], &fb[j]), fa[i].size, fb[j].size);
                }
            }
        }
        free(bd);
    }

    // pass 3: exact byte match
    dif_kidx *bh = nb ? (dif_kidx *)malloc((size_t)nb * sizeof(dif_kidx)) : NULL;
    uint32_t nbh = 0;
    if (bh) {
        for (uint32_t j = 0; j < nb; j++) {
            if (!fb[j].used && fb[j].size > 0 && fb[j].bhash != 0) {
                bh[nbh].idx = j;
                bh[nbh].k1 = fb[j].bhash;
                bh[nbh].k2 = fb[j].size;
                nbh++;
            }
        }
        if (nbh > 1) qsort(bh, nbh, sizeof(dif_kidx), dif_kidx_cmp);

        for (uint32_t i = 0; i < na; i++) {
            if (fa[i].used || fa[i].size == 0 || fa[i].bhash == 0 || nbh == 0) continue;
            uint32_t lo = 0, hi = nbh;
            while (lo < hi) {
                uint32_t mid = lo + (hi - lo) / 2;
                if (bh[mid].k1 < fa[i].bhash) lo = mid + 1;
                else hi = mid;
            }
            for (uint32_t k = lo; k < nbh && bh[k].k1 == fa[i].bhash; k++) {
                uint32_t j = bh[k].idx;
                if (fb[j].used || fb[j].size != fa[i].size) continue;
                if (!dif_bytes_eq(a, &fa[i], b, &fb[j])) continue;
                fa[i].used = 1;
                fb[j].used = 1;
                const char *nm = fa[i].named ? fa[i].name : (fb[j].named ? fb[j].name : fa[i].name);
                dif_push(out, fa[i].va, fb[j].va, nm, DIF_SAME, 100, fa[i].size, fb[j].size);
                break;
            }
        }
        free(bh);
    }

    for (uint32_t j = 0; j < nb; j++) {
        if (!fb[j].used) dif_push(out, 0, fb[j].va, fb[j].name, DIF_ADD, 0, 0, fb[j].size);
    }
    for (uint32_t i = 0; i < na; i++) {
        if (!fa[i].used) dif_push(out, fa[i].va, 0, fa[i].name, DIF_DEL, 0, fa[i].size, 0);
    }

    if (out->nitem > 1) qsort(out->items, out->nitem, sizeof(dif_item), dif_item_cmp);

    free(fa);
    free(fb);
    return true;
}
