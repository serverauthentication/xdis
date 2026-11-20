#include "ana.h"

#include <stdlib.h>
#include <string.h>

#define GRP_MAX_BLKS     2048
#define GRP_MAX_INS      65536
#define GRP_MAX_SPAN     0x100000ULL
#define GRP_MAX_SW_ROUND 16

void grp_free(grp_cfg *g) {
    if (!g) return;
    free(g->blks);
    free(g->edges);
    free(g->ins);
    memset(g, 0, sizeof(*g));
}

static int grp_u64_cmp(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

static int grp_blk_find(const grp_cfg *g, uint64_t va) {
    if (g->nblk == 0) return -1;
    if (g->blks[0].start == va) return 0;
    uint32_t lo = 1, hi = g->nblk;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        if (g->blks[mid].start < va) lo = mid + 1;
        else hi = mid;
    }
    if (lo < g->nblk && g->blks[lo].start == va) return (int)lo;
    return -1;
}

typedef struct {
    uint64_t *leaders;
    uint32_t  nlead;
    uint32_t  lead_cap;
    uint64_t *queue;
    uint32_t  qhead;
    uint32_t  qtail;
    uint32_t  qcap;
    tbl_u64   lead_set;
    uint32_t  dropped_blks;
} grp_disc;

static int grp_add_leader(grp_disc *d, grp_cfg *g, uint64_t va) {
    if (tbl_get(&d->lead_set, va) != TBL_NONE) return 0;
    if (d->nlead >= GRP_MAX_BLKS) {
        g->truncated = true;
        g->trunc_reason |= 1;
        d->dropped_blks++;
        return -1;
    }
    if (d->nlead >= d->lead_cap) {
        uint32_t nc = d->lead_cap ? d->lead_cap * 2 : 256;
        if (nc > GRP_MAX_BLKS) nc = GRP_MAX_BLKS;
        uint64_t *nl = (uint64_t *)realloc(d->leaders, (size_t)nc * sizeof(uint64_t));
        if (!nl) return -1;
        d->leaders = nl;
        d->lead_cap = nc;
    }
    if (d->qtail >= d->qcap) {
        uint32_t nc = d->qcap ? d->qcap * 2 : 256;
        if (nc > GRP_MAX_BLKS) nc = GRP_MAX_BLKS;
        uint64_t *nq = (uint64_t *)realloc(d->queue, (size_t)nc * sizeof(uint64_t));
        if (!nq) return -1;
        d->queue = nq;
        d->qcap = nc;
    }
    tbl_put(&d->lead_set, va, d->nlead);
    d->leaders[d->nlead++] = va;
    d->queue[d->qtail++] = va;
    return 1;
}

static bool grp_add_edge(grp_cfg *g, uint32_t *edge_cap, uint32_t from, uint32_t to, uint8_t kind, bool dedup_all) {
    if (dedup_all) {
        for (uint32_t e = 0; e < g->nedge; e++) {
            if (g->edges[e].from == from && g->edges[e].to == to && g->edges[e].kind == kind) return true;
        }
    } else if (g->nedge > 0) {
        for (uint32_t e = g->nedge; e > 0; e--) {
            if (g->edges[e - 1].from != from) break;
            if (g->edges[e - 1].to == to && g->edges[e - 1].kind == kind) return true;
        }
    }
    if (g->nedge >= *edge_cap) {
        uint32_t nc = *edge_cap ? (*edge_cap * 2) : 64;
        grp_edge *ne = (grp_edge *)realloc(g->edges, (size_t)nc * sizeof(grp_edge));
        if (!ne) return false;
        g->edges = ne;
        *edge_cap = nc;
    }
    g->edges[g->nedge].from = from;
    g->edges[g->nedge].to = to;
    g->edges[g->nedge].kind = kind;
    g->edges[g->nedge].back = 0;
    g->nedge++;
    return true;
}

typedef struct {
    bin_range *items;
    uint32_t   count;
    uint32_t   cap;
    bool       loaded;
} grp_chunks;

static uint16_t grp_u16(const uint8_t *d, uint64_t sz, uint64_t off) {
    uint16_t v = 0;
    if (!d || off > sz || sz - off < 2ULL) return 0;
    memcpy(&v, d + off, 2);
    return v;
}

static uint32_t grp_u32(const uint8_t *d, uint64_t sz, uint64_t off) {
    uint32_t v = 0;
    if (!d || off > sz || sz - off < 4ULL) return 0;
    memcpy(&v, d + off, 4);
    return v;
}

static int grp_rng_cmp(const void *pa, const void *pb) {
    const bin_range *a = (const bin_range *)pa;
    const bin_range *b = (const bin_range *)pb;
    if (a->start != b->start) return (a->start > b->start) ? 1 : -1;
    return (a->end < b->end) ? 1 : (a->end > b->end ? -1 : 0);
}

static void grp_chunks_load(const ana_ctx *a, uint64_t fstart, const ana_func *fn, grp_chunks *ch) {
    if (!ch) return;
    ch->loaded = true;
    if (!a || a->bin.fmt != BIN_PE64 || a->bin.arch != BIN_ARCH_X64 ||
        !a->bin.map.data || a->bin.map.size < 0x40ULL) {
        return;
    }

    const uint8_t *d = a->bin.map.data;
    uint64_t sz = a->bin.map.size;
    if (d[0] != 'M' || d[1] != 'Z') return;

    uint32_t pe_off = grp_u32(d, sz, 0x3CULL);
    if ((uint64_t)pe_off > sz || sz - (uint64_t)pe_off < 24ULL) return;
    if (grp_u32(d, sz, (uint64_t)pe_off) != 0x00004550U) return;

    uint16_t opt_sz = grp_u16(d, sz, (uint64_t)pe_off + 20ULL);
    uint64_t opt = (uint64_t)pe_off + 24ULL;
    if (opt_sz < 112U || opt > sz || sz - opt < (uint64_t)opt_sz) return;
    if (grp_u16(d, sz, opt) != 0x20BU) return;

    uint32_t max_dd = ((uint32_t)opt_sz - 112U) / 8U;
    uint32_t ndd = grp_u32(d, sz, opt + 108ULL);
    if (ndd > max_dd) ndd = max_dd;
    if (ndd <= 3U) return;

    uint64_t dd_off = opt + 112ULL;
    uint32_t dir_rva = grp_u32(d, sz, dd_off + 24ULL);
    uint32_t dir_sz  = grp_u32(d, sz, dd_off + 28ULL);
    if (dir_rva == 0U || dir_sz < 12U || (uint64_t)dir_rva > UINT64_MAX - a->bin.base) return;

    uint64_t off = 0;
    if (!bin_va_to_off(&a->bin, a->bin.base + (uint64_t)dir_rva, &off) || off >= sz) return;

    uint64_t avail_ents = (sz - off) / 12ULL;
    uint32_t count = dir_sz / 12U;
    if ((uint64_t)count > avail_ents) count = (uint32_t)avail_ents;
    if (count > 1048576U) count = 1048576U;

    for (uint32_t i = 0; i < count; i++) {
        uint64_t eoff = off + (uint64_t)i * 12ULL;
        uint32_t beg = grp_u32(d, sz, eoff);
        uint32_t end = grp_u32(d, sz, eoff + 4ULL);
        uint32_t unw = grp_u32(d, sz, eoff + 8ULL);
        if (!beg || end <= beg || !unw ||
            a->bin.base > UINT64_MAX - (uint64_t)end ||
            (uint64_t)unw > UINT64_MAX - a->bin.base) {
            continue;
        }

        uint64_t uoff = 0;
        if (!bin_va_to_off(&a->bin, a->bin.base + (uint64_t)unw, &uoff) ||
            uoff >= sz || sz - uoff < 4ULL) {
            continue;
        }

        uint8_t ver = d[uoff] & 0x07U;
        uint8_t flg = (d[uoff] >> 3) & 0x1FU;
        if ((ver != 1U && ver != 2U) || !(flg & 0x04U)) continue;

        uint64_t seen[32];
        uint32_t cur_beg = beg;
        uint64_t cur_uoff = uoff;
        uint32_t root_beg = 0;
        bool ok_root = false;

        for (uint32_t depth = 0; depth < 32U; depth++) {
            bool cyc = false;
            for (uint32_t s = 0; s < depth; s++) {
                if (seen[s] == cur_uoff) { cyc = true; break; }
            }
            if (cyc || cur_uoff >= sz || sz - cur_uoff < 4ULL) break;
            seen[depth] = cur_uoff;

            uint8_t ver2 = d[cur_uoff] & 0x07U;
            uint8_t flg2 = (d[cur_uoff] >> 3) & 0x1FU;
            if (ver2 != 1U && ver2 != 2U) break;
            if (!(flg2 & 0x04U)) {
                root_beg = cur_beg;
                ok_root = true;
                break;
            }

            uint8_t cnt = d[cur_uoff + 2ULL];
            uint64_t padded = ((uint64_t)cnt + 1ULL) & ~1ULL;
            uint64_t chain_rel = 4ULL + padded * 2ULL;
            if (chain_rel > sz - cur_uoff || sz - (cur_uoff + chain_rel) < 12ULL) break;

            uint32_t cbeg = grp_u32(d, sz, cur_uoff + chain_rel);
            uint32_t cend = grp_u32(d, sz, cur_uoff + chain_rel + 4ULL);
            uint32_t cunw = grp_u32(d, sz, cur_uoff + chain_rel + 8ULL);
            if (!cbeg || cend <= cbeg || !cunw || (uint64_t)cunw > UINT64_MAX - a->bin.base) break;

            uint64_t next_uoff = 0;
            if (!bin_va_to_off(&a->bin, a->bin.base + (uint64_t)cunw, &next_uoff)) break;
            cur_beg = cbeg;
            cur_uoff = next_uoff;
        }

        if (!ok_root || (uint64_t)root_beg > UINT64_MAX - a->bin.base) continue;
        uint64_t root_va = a->bin.base + (uint64_t)root_beg;
        bool owns = (root_va == fstart) || (fn && root_va >= fn->start && root_va < fn->end);
        uint64_t cstart  = a->bin.base + (uint64_t)beg;
        uint64_t cend_va = a->bin.base + (uint64_t)end;
        if (owns && bin_is_exec(&a->bin, cstart)) {
            if (ch->count >= ch->cap) {
                uint32_t nc = ch->cap ? (ch->cap * 2U) : 16U;
                if (nc < ch->cap) continue;
                bin_range *ni = (bin_range *)realloc(ch->items, (size_t)nc * sizeof(bin_range));
                if (!ni) continue;
                ch->items = ni;
                ch->cap = nc;
            }
            ch->items[ch->count].start = cstart;
            ch->items[ch->count].end   = cend_va;
            ch->count++;
        }
    }

    if (ch->count > 1U) {
        qsort(ch->items, ch->count, sizeof(bin_range), grp_rng_cmp);
        uint32_t out = 0;
        for (uint32_t i = 0; i < ch->count; i++) {
            if (out == 0U || ch->items[i].start >= ch->items[out - 1U].end) {
                ch->items[out++] = ch->items[i];
            } else if (ch->items[i].end > ch->items[out - 1U].end) {
                ch->items[out - 1U].end = ch->items[i].end;
            }
        }
        ch->count = out;
    }
}

static int grp_find_chunk(const ana_ctx *a, grp_chunks *ch, uint64_t fstart, const ana_func *fn, uint64_t va) {
    if (!ch) return -1;
    if (!ch->loaded) grp_chunks_load(a, fstart, fn, ch);
    if (ch->count == 0U) return -1;
    uint32_t lo = 0U, hi = ch->count;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2U;
        if (ch->items[mid].start <= va) lo = mid + 1U;
        else hi = mid;
    }
    if (lo == 0U) return -1;
    uint32_t idx = lo - 1U;
    if (va >= ch->items[idx].start && va < ch->items[idx].end) return (int)idx;
    return -1;
}

static bool grp_can_follow_target(const ana_ctx *a, grp_chunks *ch, const ana_func *fn,
                                  uint64_t sec_va, uint64_t max_end,
                                  uint64_t fstart, uint64_t fend, uint64_t tva) {
    if (tva >= fstart && tva < fend) return true;
    if (grp_find_chunk(a, ch, fstart, fn, tva) >= 0) return true;
    if (tva >= sec_va && tva < max_end) {
        const ana_func *tf = ana_func_at(a, tva);
        if (!tf || tf->start == fstart) return true;
    }
    return false;
}

static uint64_t grp_blk_limit(const ana_ctx *a, uint64_t fstart, uint64_t fend,
                              uint64_t max_end, uint64_t va) {
    if (va >= fstart && va < fend) return fend;
    uint64_t lim = max_end;
    if (va < fstart && fstart < lim) lim = fstart;
    if (a->nfunc > 0) {
        uint32_t lo = 0, hi = a->nfunc;
        while (lo < hi) {
            uint32_t mid = lo + (hi - lo) / 2;
            if (a->funcs[mid].start <= va) lo = mid + 1;
            else hi = mid;
        }
        if (lo < a->nfunc && a->funcs[lo].start < lim) lim = a->funcs[lo].start;
    }
    return lim;
}

static bool grp_chunk_bounds(const ana_ctx *a, grp_chunks *ch,
                             uint64_t fstart, uint64_t fend, const ana_func *fn,
                             uint64_t sec_va, uint64_t max_end, uint64_t va,
                             uint64_t *out_min, uint64_t *out_lim) {
    if (va >= fstart && va < fend) {
        *out_min = sec_va;
        *out_lim = fend;
        return va >= sec_va && va < fend;
    }
    int ci = grp_find_chunk(a, ch, fstart, fn, va);
    if (ci >= 0) {
        const bin_sec *csec = bin_sec_at(&a->bin, va);
        if (!csec || !(csec->perm & BIN_PERM_X)) return false;
        uint64_t csec_end = (csec->vsize > UINT64_MAX - csec->va) ? UINT64_MAX : (csec->va + csec->vsize);
        uint64_t cspan_end = (ch->items[ci].start > UINT64_MAX - GRP_MAX_SPAN)
                           ? UINT64_MAX : (ch->items[ci].start + GRP_MAX_SPAN);
        uint64_t clim = ch->items[ci].end;
        if (csec_end < clim) clim = csec_end;
        if (cspan_end < clim) clim = cspan_end;
        if (va < fstart && fstart < clim) clim = fstart;
        uint64_t cmin = (ch->items[ci].start > csec->va) ? ch->items[ci].start : csec->va;
        *out_min = cmin;
        *out_lim = clim;
        return va >= cmin && va < clim;
    }
    *out_min = sec_va;
    *out_lim = grp_blk_limit(a, fstart, fend, max_end, va);
    return va >= sec_va && va < *out_lim;
}

typedef struct {
    uint64_t from_va;
    uint64_t to_va;
} grp_sw_edge;

bool grp_build(const ana_ctx *a, uint64_t va, int upper, grp_cfg *g) {
    grp_free(g);
    if (!a || !g) return false;
    const bin_sec *sec = bin_sec_at(&a->bin, va);
    if (!sec || !(sec->perm & BIN_PERM_X)) return false;

    const ana_func *fn = ana_func_at(a, va);
    uint64_t sec_va  = sec->va;
    uint64_t sec_end = (sec->vsize > UINT64_MAX - sec->va) ? UINT64_MAX : (sec->va + sec->vsize);
    uint64_t fstart  = fn ? fn->start : va;
    uint64_t fend    = fn ? fn->end : sec_end;
    if (fend <= fstart) fend = sec_end;

    uint64_t span_end = (fstart > UINT64_MAX - GRP_MAX_SPAN) ? UINT64_MAX : (fstart + GRP_MAX_SPAN);
    uint64_t max_end  = (sec_end < span_end) ? sec_end : span_end;
    if (fend > max_end) {
        fend = max_end;
        g->truncated = true;
        g->trunc_reason |= 4;
    }
    g->func_va = fstart;

    grp_disc disc;
    memset(&disc, 0, sizeof(disc));
    tbl_init(&disc.lead_set);

    tbl_u64 visited;
    tbl_init(&visited);

    grp_sw_edge *sw_edges = NULL;
    uint32_t nsw_edges = 0, sw_edge_cap = 0;
    grp_chunks chunks;
    memset(&chunks, 0, sizeof(chunks));
    ir_switch *sws = (ir_switch *)malloc(32U * sizeof(ir_switch));
    uint64_t *tgts = (uint64_t *)malloc(512U * sizeof(uint64_t));

    if (!sws || !tgts || grp_add_leader(&disc, g, fstart) < 0) {
        free(chunks.items);
        free(sws);
        free(tgts);
        free(disc.leaders);
        free(disc.queue);
        tbl_free(&disc.lead_set);
        tbl_free(&visited);
        grp_free(g);
        return false;
    }

    x86_ins ins;
    bool ok = true;

    for (int round = 0; round < GRP_MAX_SW_ROUND; round++) {
        while (disc.qhead < disc.qtail) {
            uint64_t cur = disc.queue[disc.qhead++];
            uint64_t min_va = 0, lim = 0;
            if (!grp_chunk_bounds(a, &chunks, fstart, fend, fn, sec_va, max_end, cur, &min_va, &lim)) {
                continue;
            }
            while (cur >= min_va && cur < lim) {
                if (tbl_get(&visited, cur) != TBL_NONE) break;
                tbl_put(&visited, cur, 1);

                size_t avail = 0;
                const uint8_t *p = bin_ptr(&a->bin, cur, &avail);
                if (!p || avail == 0) break;
                int n = arch_decode(a->bin.arch, p, avail, cur, 0, 0, &ins);
                if (n <= 0) break;

                uint64_t next = cur + (uint64_t)n;
                if (ins.flow == X86_FLOW_RET || ins.flow == X86_FLOW_TRAP) break;

                if (ins.flow == X86_FLOW_JMP) {
                    if (ins.has_target && !ins.target_mem) {
                        bool follow = (ins.target >= fstart && ins.target < fend);
                        if (!follow && grp_find_chunk(a, &chunks, fstart, fn, ins.target) >= 0) {
                            follow = true;
                        }
                        if (follow) grp_add_leader(&disc, g, ins.target);
                    }
                    break;
                }

                if (ins.flow == X86_FLOW_JCC) {
                    if (ins.has_target && !ins.target_mem &&
                        grp_can_follow_target(a, &chunks, fn, sec_va, max_end, fstart, fend, ins.target)) {
                        grp_add_leader(&disc, g, ins.target);
                    }
                    if (next < lim) {
                        grp_add_leader(&disc, g, next);
                    }
                    break;
                }
                cur = next;
            }
        }

        if (disc.nlead == 0) {
            ok = false;
            break;
        }
        if (disc.nlead > 2U) {
            qsort(disc.leaders + 1, disc.nlead - 1U, sizeof(uint64_t), grp_u64_cmp);
        }

        free(g->blks);  g->blks  = NULL; g->nblk  = 0;
        free(g->edges); g->edges = NULL; g->nedge = 0;
        free(g->ins);   g->ins   = NULL; g->nins  = 0;

        uint32_t edge_cap = disc.nlead * 2U + 16U;
        uint32_t ins_cap  = 256U;
        g->blks  = (grp_blk *)calloc(disc.nlead, sizeof(grp_blk));
        g->edges = (grp_edge *)calloc(edge_cap, sizeof(grp_edge));
        g->ins   = (x86_ins *)malloc((size_t)ins_cap * sizeof(x86_ins));
        if (!g->blks || !g->edges || !g->ins) {
            ok = false;
            break;
        }
        g->nblk = disc.nlead;

        for (uint32_t i = 0; i < disc.nlead; i++) {
            uint64_t cur = disc.leaders[i];
            uint64_t min_va = 0, lim = 0;
            if (!grp_chunk_bounds(a, &chunks, fstart, fend, fn, sec_va, max_end, cur, &min_va, &lim)) {
                lim = cur;
            }
            if (i == 0U) {
                for (uint32_t j = 1U; j < disc.nlead; j++) {
                    if (disc.leaders[j] > cur && disc.leaders[j] < lim) {
                        lim = disc.leaders[j];
                        break;
                    }
                }
            } else if (i + 1U < disc.nlead && disc.leaders[i + 1U] > cur && disc.leaders[i + 1U] < lim) {
                lim = disc.leaders[i + 1U];
            }
            g->blks[i].start = cur;
            g->blks[i].ins_first = g->nins;
            g->blks[i].layer = -1;

            while (cur < lim) {
                if (g->nins >= GRP_MAX_INS) {
                    g->truncated = true;
                    g->trunc_reason |= 2;
                    break;
                }
                if (g->nins >= ins_cap) {
                    uint32_t nc = ins_cap * 2U;
                    if (nc > GRP_MAX_INS) nc = GRP_MAX_INS;
                    x86_ins *ni = (x86_ins *)realloc(g->ins, (size_t)nc * sizeof(x86_ins));
                    if (!ni) {
                        ok = false;
                        break;
                    }
                    g->ins = ni;
                    ins_cap = nc;
                }
                size_t avail = 0;
                const uint8_t *p = bin_ptr(&a->bin, cur, &avail);
                if (!p || avail == 0) break;
                x86_ins *dst = &g->ins[g->nins];
                int n = arch_decode(a->bin.arch, p, avail, cur, 1, upper, dst);
                if (n <= 0) break;
                g->nins++;
                cur += (uint64_t)n;
                if (dst->flow == X86_FLOW_JMP || dst->flow == X86_FLOW_JCC ||
                    dst->flow == X86_FLOW_RET || dst->flow == X86_FLOW_TRAP) break;
            }
            if (!ok) break;
            g->blks[i].end = cur;
            g->blks[i].ins_count = g->nins - g->blks[i].ins_first;
        }
        if (!ok) break;

        for (uint32_t i = 0; i < g->nblk; i++) {
            grp_blk *b = &g->blks[i];
            if (b->ins_count == 0) continue;
            const x86_ins *last = &g->ins[b->ins_first + b->ins_count - 1];

            if (last->flow == X86_FLOW_RET || last->flow == X86_FLOW_TRAP) continue;

            if (last->flow == X86_FLOW_JMP) {
                if (last->has_target && !last->target_mem) {
                    int to = grp_blk_find(g, last->target);
                    if (to >= 0) grp_add_edge(g, &edge_cap, i, (uint32_t)to, GRP_EDGE_UNCOND, false);
                }
                continue;
            }

            if (last->flow == X86_FLOW_JCC) {
                if (last->has_target && !last->target_mem) {
                    int to = grp_blk_find(g, last->target);
                    if (to >= 0) grp_add_edge(g, &edge_cap, i, (uint32_t)to, GRP_EDGE_TRUE, false);
                }
                int fall = grp_blk_find(g, b->end);
                if (fall >= 0) grp_add_edge(g, &edge_cap, i, (uint32_t)fall, GRP_EDGE_FALSE, false);
                continue;
            }

            int fall = grp_blk_find(g, b->end);
            if (fall >= 0) grp_add_edge(g, &edge_cap, i, (uint32_t)fall, GRP_EDGE_UNCOND, false);
        }

        for (uint32_t se = 0; se < nsw_edges; se++) {
            int fb = grp_blk_find(g, sw_edges[se].from_va);
            int tb = grp_blk_find(g, sw_edges[se].to_va);
            if (fb >= 0 && tb >= 0) {
                grp_add_edge(g, &edge_cap, (uint32_t)fb, (uint32_t)tb, GRP_EDGE_UNCOND, true);
            }
        }

        if (round + 1 >= GRP_MAX_SW_ROUND || disc.nlead >= GRP_MAX_BLKS) break;

        bool added_new = false;
        int nsw = ir_scan_switches_cfg(a, g, sws, 32);
        for (int si = 0; si < nsw; si++) {
            int sw_blk = -1;
            for (uint32_t bi = 0; bi < g->nblk; bi++) {
                if (g->blks[bi].start <= sws[si].va && sws[si].va < g->blks[bi].end) {
                    sw_blk = (int)bi;
                    break;
                }
            }
            if (sw_blk < 0) continue;
            uint64_t from_va = g->blks[sw_blk].start;
            uint32_t nt = ir_read_switch_targets(a, &sws[si], tgts, 512U);
            for (uint32_t ti = 0; ti < nt; ti++) {
                uint64_t tva = tgts[ti];
                if (!grp_can_follow_target(a, &chunks, fn, sec_va, max_end, fstart, fend, tva)) continue;
                bool dup_se = false;
                for (uint32_t k = 0; k < nsw_edges; k++) {
                    if (sw_edges[k].from_va == from_va && sw_edges[k].to_va == tva) {
                        dup_se = true;
                        break;
                    }
                }
                if (!dup_se) {
                    if (nsw_edges >= sw_edge_cap) {
                        uint32_t nc = sw_edge_cap ? sw_edge_cap * 2U : 64U;
                        grp_sw_edge *nse = (grp_sw_edge *)realloc(sw_edges, (size_t)nc * sizeof(grp_sw_edge));
                        if (nse) {
                            sw_edges = nse;
                            sw_edge_cap = nc;
                        }
                    }
                    if (nsw_edges < sw_edge_cap) {
                        sw_edges[nsw_edges].from_va = from_va;
                        sw_edges[nsw_edges].to_va = tva;
                        nsw_edges++;
                    }
                }
                if (grp_add_leader(&disc, g, tva) == 1) added_new = true;
            }
        }
        if (!added_new) {
            for (uint32_t se = 0; se < nsw_edges; se++) {
                int fb = grp_blk_find(g, sw_edges[se].from_va);
                int tb = grp_blk_find(g, sw_edges[se].to_va);
                if (fb >= 0 && tb >= 0) {
                    grp_add_edge(g, &edge_cap, (uint32_t)fb, (uint32_t)tb, GRP_EDGE_UNCOND, true);
                }
            }
            break;
        }
    }

    if (ok && g->truncated) {
        g->orig_blks = g->nblk + disc.dropped_blks;
        g->orig_ins  = g->nins;
    }

    free(chunks.items);
    free(sw_edges);
    free(sws);
    free(tgts);
    free(disc.leaders);
    free(disc.queue);
    tbl_free(&disc.lead_set);
    tbl_free(&visited);

    if (!ok) {
        grp_free(g);
        return false;
    }
    return g->nblk > 0;
}

void grp_layout(grp_cfg *g, int char_w, int line_h) {
    if (!g || g->nblk == 0) return;

    uint32_t *q = (uint32_t *)malloc((size_t)g->nblk * sizeof(uint32_t));
    if (!q) return;
    uint32_t qh = 0, qt = 0;
    g->blks[0].layer = 0;
    q[qt++] = 0;

    int max_layer = 0;
    while (qh < qt) {
        uint32_t u = q[qh++];
        for (uint32_t e = 0; e < g->nedge; e++) {
            if (g->edges[e].from != u) continue;
            uint32_t v = g->edges[e].to;
            if (v < g->nblk && g->blks[v].layer < 0) {
                g->blks[v].layer = g->blks[u].layer + 1;
                if (g->blks[v].layer > max_layer) max_layer = g->blks[v].layer;
                if (qt < g->nblk) q[qt++] = v;
            }
        }
    }
    free(q);

    for (uint32_t i = 0; i < g->nblk; i++) {
        if (g->blks[i].layer < 0) g->blks[i].layer = ++max_layer;
    }

    for (uint32_t e = 0; e < g->nedge; e++) {
        g->edges[e].back = (g->blks[g->edges[e].to].layer <= g->blks[g->edges[e].from].layer);
    }

    for (uint32_t i = 0; i < g->nblk; i++) {
        grp_blk *b = &g->blks[i];
        int max_ch = 26;
        for (uint32_t k = 0; k < b->ins_count; k++) {
            const x86_ins *in = &g->ins[b->ins_first + k];
            int ch = 12 + (int)strlen(in->mnem) + 2 + (int)strlen(in->ops);
            if (ch > max_ch) max_ch = ch;
        }
        b->w = max_ch * char_w + 24;
        b->h = (int)(b->ins_count + 1) * line_h + 18;
    }

    int pad_x = 36, pad_y = 48;
    int cur_y = 24;
    int max_w = 0;

    for (int lyr = 0; lyr <= max_layer; lyr++) {
        int row_w = 0, row_h = 0, cnt = 0;
        for (uint32_t i = 0; i < g->nblk; i++) {
            if (g->blks[i].layer != lyr) continue;
            if (cnt) row_w += pad_x;
            row_w += g->blks[i].w;
            if (g->blks[i].h > row_h) row_h = g->blks[i].h;
            cnt++;
        }
        if (row_w > max_w) max_w = row_w;
    }

    for (int lyr = 0; lyr <= max_layer; lyr++) {
        int row_w = 0, row_h = 0, cnt = 0;
        for (uint32_t i = 0; i < g->nblk; i++) {
            if (g->blks[i].layer != lyr) continue;
            if (cnt) row_w += pad_x;
            row_w += g->blks[i].w;
            if (g->blks[i].h > row_h) row_h = g->blks[i].h;
            cnt++;
        }
        int cur_x = 32 + (max_w - row_w) / 2;
        int ord = 0;
        for (uint32_t i = 0; i < g->nblk; i++) {
            if (g->blks[i].layer != lyr) continue;
            g->blks[i].order = ord++;
            g->blks[i].x = cur_x;
            g->blks[i].y = cur_y;
            cur_x += g->blks[i].w + pad_x;
        }
        cur_y += row_h + pad_y;
    }

    g->total_w = max_w + 64;
    g->total_h = cur_y + 32;
}
