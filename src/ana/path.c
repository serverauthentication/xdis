#include "ana.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PTH_MAX_Q     32768
#define PTH_MAX_NODES 96
#define PTH_MAX_EDGES 192

typedef struct {
    uint64_t va;
    int      next_idx;
    int      depth;
} pth_qent;

typedef struct {
    uint64_t start;
    uint64_t end;
    int      node;
} pth_span;

static void pth_sym_name(const ana_ctx *a, uint64_t va, char *dst, size_t max) {
    const char *sym = ana_sym_at(a, va);
    if (sym && sym[0]) {
        snprintf(dst, max, "%s", sym);
        return;
    }
    const ana_func *f = ana_func_at(a, va);
    if (f && f->start == va) {
        const char *fn = ana_pool_str(a, f->name_off);
        if (fn && fn[0]) {
            snprintf(dst, max, "%s", fn);
            return;
        }
    }
    snprintf(dst, max, "0x%llx", (unsigned long long)va);
}

bool pth_find(const ana_ctx *a, uint64_t from_va, uint64_t to_va, pth_chain *out) {
    if (!a || !out) return false;
    memset(out, 0, sizeof(*out));

    const ana_func *ff = ana_func_at(a, from_va);
    const ana_func *ft = ana_func_at(a, to_va);
    uint64_t src = ff ? ff->start : from_va;
    uint64_t dst = ft ? ft->start : to_va;

    if (src == dst) {
        out->vas[0] = src;
        pth_sym_name(a, src, out->names[0], sizeof(out->names[0]));
        out->len = 1;
        return true;
    }

    uint32_t qcap = a->nfunc + 256;
    if (qcap > PTH_MAX_Q) qcap = PTH_MAX_Q;
    pth_qent *q = (pth_qent *)malloc((size_t)qcap * sizeof(pth_qent));
    if (!q) return false;

    tbl_u64 vis;
    tbl_init(&vis);

    uint32_t qh = 0, qt = 0;
    q[qt].va = dst;
    q[qt].next_idx = -1;
    q[qt].depth = 0;
    tbl_put(&vis, dst, qt);
    qt++;

    bool found = false;
    int dst_is_data = (ft == NULL);

    while (qh < qt && !found) {
        pth_qent cur = q[qh];
        int cur_idx = (int)qh;
        qh++;

        if (cur.depth >= 63) continue;

        uint32_t first = 0;
        uint32_t cnt = ana_xrefs_to(a, cur.va, &first);
        for (uint32_t k = 0; k < cnt; k++) {
            const ana_xref *x = &a->xrefs[first + k];
            if (x->type == ANA_XREF_DATA && !(cur.va == dst && dst_is_data)) continue;

            const ana_func *cf = ana_func_at(a, x->from);
            if (!cf) continue;
            uint64_t caller = cf->start;
            if (caller == cur.va) continue;
            if (tbl_get(&vis, caller) != TBL_NONE) continue;
            if (qt >= qcap) break;

            q[qt].va = caller;
            q[qt].next_idx = cur_idx;
            q[qt].depth = cur.depth + 1;
            tbl_put(&vis, caller, qt);

            if (caller == src) {
                int idx = (int)qt;
                while (idx >= 0 && out->len < 64) {
                    out->vas[out->len] = q[idx].va;
                    pth_sym_name(a, q[idx].va, out->names[out->len], sizeof(out->names[out->len]));
                    out->len++;
                    idx = q[idx].next_idx;
                }
                found = true;
                break;
            }
            qt++;
        }
    }

    tbl_free(&vis);
    free(q);
    return found;
}

static int pth_add_node(const ana_ctx *a, pth_xgraph *g, tbl_u64 *map, uint64_t va, int depth, int *is_new) {
    *is_new = 0;
    uint32_t ex = tbl_get(map, va);
    if (ex != TBL_NONE) return (int)ex;
    if (g->nnode >= PTH_MAX_NODES) return -1;

    int idx = g->nnode++;
    g->nodes[idx].va = va;
    g->nodes[idx].depth = depth;
    pth_sym_name(a, va, g->nodes[idx].name, sizeof(g->nodes[idx].name));
    tbl_put(map, va, (uint32_t)idx);
    *is_new = 1;
    return idx;
}

static void pth_add_edge(pth_xgraph *g, int from, int to, int type) {
    if (from < 0 || to < 0 || from == to || g->nedge >= PTH_MAX_EDGES) return;
    for (int i = 0; i < g->nedge; i++) {
        if (g->edges[i].from == from && g->edges[i].to == to) return;
    }
    g->edges[g->nedge].from = from;
    g->edges[g->nedge].to = to;
    g->edges[g->nedge].type = type;
    g->nedge++;
}

static int pth_span_cmp(const void *a, const void *b) {
    uint64_t x = ((const pth_span *)a)->start;
    uint64_t y = ((const pth_span *)b)->start;
    return (x > y) - (x < y);
}

static int pth_find_span(const pth_span *sp, int n, uint64_t va) {
    int lo = 0, hi = n;
    while (lo < hi) {
        int mid = lo + (hi - lo) / 2;
        if (sp[mid].start <= va) lo = mid + 1;
        else hi = mid;
    }
    if (lo == 0) return -1;
    return (va >= sp[lo - 1].start && va < sp[lo - 1].end) ? (lo - 1) : -1;
}

bool pth_xgraph_build(const ana_ctx *a, uint64_t center_va, int max_depth, pth_xgraph *out) {
    if (!a || !out) return false;
    memset(out, 0, sizeof(*out));

    if (max_depth < 1) max_depth = 1;
    if (max_depth > 3) max_depth = 3;

    const ana_func *cf = ana_func_at(a, center_va);
    uint64_t root = cf ? cf->start : center_va;

    tbl_u64 map;
    tbl_init(&map);

    int is_new = 0;
    pth_add_node(a, out, &map, root, 0, &is_new);

    // incoming callers bfs
    int in_cur[PTH_MAX_NODES], in_nxt[PTH_MAX_NODES];
    int nin = 1;
    in_cur[0] = 0;

    for (int d = 0; d < max_depth && nin > 0 && out->nnode < PTH_MAX_NODES; d++) {
        int nnxt = 0;
        for (int i = 0; i < nin && out->nnode < PTH_MAX_NODES; i++) {
            int u = in_cur[i];
            uint64_t uva = out->nodes[u].va;
            uint32_t first = 0;
            uint32_t cnt = ana_xrefs_to(a, uva, &first);
            for (uint32_t k = 0; k < cnt; k++) {
                const ana_xref *x = &a->xrefs[first + k];
                const ana_func *sf = ana_func_at(a, x->from);
                uint64_t sva = sf ? sf->start : x->from;
                if (sva == uva) continue;
                int v = pth_add_node(a, out, &map, sva, -(d + 1), &is_new);
                if (v < 0) break;
                pth_add_edge(out, v, u, x->type);
                if (is_new && nnxt < PTH_MAX_NODES) in_nxt[nnxt++] = v;
            }
        }
        memcpy(in_cur, in_nxt, (size_t)nnxt * sizeof(int));
        nin = nnxt;
    }

    // outgoing callees bfs
    int out_cur[PTH_MAX_NODES], out_nxt[PTH_MAX_NODES];
    int nout = 1;
    out_cur[0] = 0;

    for (int d = 0; d < max_depth && nout > 0 && out->nnode < PTH_MAX_NODES; d++) {
        pth_span sp[PTH_MAX_NODES];
        int nsp = 0;
        for (int i = 0; i < nout; i++) {
            const ana_func *fn = ana_func_at(a, out->nodes[out_cur[i]].va);
            if (!fn) continue;
            sp[nsp].start = fn->start;
            sp[nsp].end = fn->end;
            sp[nsp].node = out_cur[i];
            nsp++;
        }
        if (nsp == 0) break;
        if (nsp > 1) qsort(sp, (size_t)nsp, sizeof(pth_span), pth_span_cmp);

        uint64_t min_s = sp[0].start;
        uint64_t max_e = sp[0].end;
        for (int i = 1; i < nsp; i++) {
            if (sp[i].end > max_e) max_e = sp[i].end;
        }

        int nnxt = 0;
        // prioritize call/jmp over data refs
        for (int pass = 0; pass < (d == 0 ? 2 : 1) && out->nnode < PTH_MAX_NODES; pass++) {
            for (uint32_t xi = 0; xi < a->nxref; xi++) {
                const ana_xref *x = &a->xrefs[xi];
                if (x->from < min_s || x->from >= max_e) continue;
                if (pass == 0 && x->type == ANA_XREF_DATA) continue;
                if (pass == 1 && x->type != ANA_XREF_DATA) continue;

                int si = pth_find_span(sp, nsp, x->from);
                if (si < 0) continue;
                if (x->type == ANA_XREF_JMP && x->to >= sp[si].start && x->to < sp[si].end) continue;

                const ana_func *tf = ana_func_at(a, x->to);
                uint64_t tva = tf ? tf->start : x->to;
                int u = sp[si].node;
                if (tva == out->nodes[u].va) continue;
                if (pass == 1 && !ana_sym_at(a, tva) && !ana_str_at(a, tva)) continue;

                int v = pth_add_node(a, out, &map, tva, d + 1, &is_new);
                if (v < 0) break;
                pth_add_edge(out, u, v, x->type);
                if (is_new && tf && nnxt < PTH_MAX_NODES) out_nxt[nnxt++] = v;
            }
        }
        memcpy(out_cur, out_nxt, (size_t)nnxt * sizeof(int));
        nout = nnxt;
    }

    tbl_free(&map);
    return out->nnode > 0;
}
