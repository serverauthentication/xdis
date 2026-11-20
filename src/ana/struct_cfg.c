#include "dec_ir.h"

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SC_MAX_BLKS     HL_MAX_BLKS
#define SC_WORDS        33
#define SC_MAX_SW_CASES 512
#define SC_MAX_DEPTH    48
#define SC_MAX_CMTS     256

typedef struct {
    uint64_t w[SC_WORDS];
} sc_bits;

typedef struct {
    char  *p;
    size_t len;
    size_t cap;
} sc_buf;

typedef enum {
    SCN_SEQ = 0,
    SCN_STMT,
    SCN_RET,
    SCN_IF,
    SCN_WHILE,
    SCN_DO_WHILE,
    SCN_FOR,
    SCN_SWITCH,
    SCN_BREAK,
    SCN_CONTINUE,
    SCN_GOTO,
    SCN_LABEL,
    SCN_COMMENT
} sc_node_kind;

typedef struct {
    int64_t  val;
    int      is_default;
    int      is_char;
    uint64_t va;
    int      body;
    int      group_id;
} sc_case;

typedef struct {
    uint8_t  kind;
    uint64_t va;
    uint64_t end_va;
    int      first;
    int      last;
    int      next;
    int      prev;
    int      stmt_id;
    int      cond_expr;
    int      then_body;
    int      else_body;
    int      for_init_stmt;
    int      for_step_stmt;
    int      sw_expr;
    int      case_first;
    int      ncase;
    int      target_blk;
    uint64_t target_va;
    char     comment[80];
} sc_node;

typedef struct {
    int *items;
    int  len;
    int  cap;
} sc_intvec;

typedef struct {
    hl_fn     *fn;
    dec_out   *out;
    int        nblk;

    sc_intvec  succ[SC_MAX_BLKS];
    sc_intvec  pred[SC_MAX_BLKS];
    int        in_deg[SC_MAX_BLKS];
    uint8_t    reach[SC_MAX_BLKS];
    sc_bits    dom[SC_MAX_BLKS];
    sc_bits    pdom[SC_MAX_BLKS + 1];
    int        ipdom[SC_MAX_BLKS];
    uint8_t    is_loop_hdr[SC_MAX_BLKS];
    uint8_t    emitted[SC_MAX_BLKS];
    uint8_t    inlined_exit[SC_MAX_BLKS];
    uint8_t    need_lbl[SC_MAX_BLKS];

    uint8_t   *extracted_stmt;
    int        extracted_cap;

    sc_node   *nodes;
    int        nnode;
    int        node_cap;

    sc_case   *cases;
    int        ncase;
    int        case_cap;

    uint8_t   *var_used;
    int        var_used_cap;

    uint64_t   cmt_seen[SC_MAX_CMTS];
    int        ncmt_seen;
} sc_ctx;

// --- bitset helpers ---

static void sc_bits_zero(sc_bits *b) {
    memset(b, 0, sizeof(*b));
}

static void sc_bits_all(sc_bits *b, int n) {
    sc_bits_zero(b);
    for (int i = 0; i < n; i++) b->w[i >> 6] |= (1ULL << (i & 63));
}

static void sc_bits_set(sc_bits *b, int idx) {
    b->w[idx >> 6] |= (1ULL << (idx & 63));
}

static int sc_bits_test(const sc_bits *b, int idx) {
    return (int)((b->w[idx >> 6] >> (idx & 63)) & 1ULL);
}

static void sc_bits_and(sc_bits *dst, const sc_bits *src) {
    for (int i = 0; i < SC_WORDS; i++) dst->w[i] &= src->w[i];
}

static int sc_bits_eq(const sc_bits *a, const sc_bits *b) {
    for (int i = 0; i < SC_WORDS; i++) {
        if (a->w[i] != b->w[i]) return 0;
    }
    return 1;
}

static int sc_u64_popcnt(uint64_t x) {
    int c = 0;
    while (x) {
        x &= x - 1;
        c++;
    }
    return c;
}

static int sc_bits_popcnt(const sc_bits *b) {
    int c = 0;
    for (int i = 0; i < SC_WORDS; i++) c += sc_u64_popcnt(b->w[i]);
    return c;
}

static void sc_iv_push_uniq(sc_intvec *v, int val) {
    for (int i = 0; i < v->len; i++) {
        if (v->items[i] == val) return;
    }
    if (v->len == v->cap) {
        int nc = v->cap ? v->cap * 2 : 4;
        int *ni = (int *)realloc(v->items, (size_t)nc * sizeof(int));
        if (!ni) return;
        v->items = ni;
        v->cap = nc;
    }
    v->items[v->len++] = val;
}

// --- string buffer helpers ---

static void sb_init(sc_buf *sb, char *storage, size_t cap) {
    sb->p = storage;
    sb->len = 0;
    sb->cap = cap;
    if (cap > 0) sb->p[0] = 0;
}

static void sb_putc(sc_buf *sb, char c) {
    if (sb->len + 1 < sb->cap) {
        sb->p[sb->len++] = c;
        sb->p[sb->len] = 0;
    }
}

static void sb_puts(sc_buf *sb, const char *s) {
    if (!s) return;
    while (*s && sb->len + 1 < sb->cap) sb->p[sb->len++] = *s++;
    if (sb->cap > 0) sb->p[sb->len] = 0;
}

static void sb_printf(sc_buf *sb, const char *fmt, ...) {
    if (sb->len + 1 >= sb->cap) return;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(sb->p + sb->len, sb->cap - sb->len, fmt, ap);
    va_end(ap);
    if (n > 0) {
        size_t adv = (size_t)n;
        if (sb->len + adv >= sb->cap) sb->len = sb->cap - 1;
        else sb->len += adv;
    }
}

// --- symbol & type formatting helpers ---

static void sc_clean_sym(const char *sym, char *dst, size_t cap) {
    if (!sym || !sym[0]) {
        snprintf(dst, cap, "fn");
        return;
    }
    const char *bang = strchr(sym, '!');
    const char *src = bang ? bang + 1 : sym;
    if (strncmp(src, "__imp_", 6) == 0) src += 6;
    else if (strncmp(src, "imp_", 4) == 0) src += 4;
    size_t k = 0;
    for (size_t i = 0; src[i] && k + 1 < cap; i++) {
        char c = src[i];
        if (c == '@' && i > 0 && isdigit((unsigned char)src[i + 1])) break;
        dst[k++] = (isalnum((unsigned char)c) || c == '_') ? c : '_';
    }
    dst[k] = 0;
    if (!dst[0]) snprintf(dst, cap, "fn");
}

static void sc_fmt_decl(const char *type, const char *name, char *dst, size_t cap) {
    size_t tl = strlen(type);
    if (tl > 0 && type[tl - 1] == '*') snprintf(dst, cap, "%s%s", type, name);
    else snprintf(dst, cap, "%s %s", type, name);
}

static const char *sc_fallback_ctype(int bits, int is_flt) {
    if (is_flt) return (bits == 32) ? "float" : "double";
    if (bits == 8) return "uint8_t";
    if (bits == 16) return "uint16_t";
    if (bits == 32) return "int32_t";
    return "int64_t";
}

static int sc_ty_is_signed(const hl_type *t) {
    if (!t || t->ptr_depth > 0) return 0;
    return t->kind == HL_TY_I8 || t->kind == HL_TY_I16 ||
           t->kind == HL_TY_I32 || t->kind == HL_TY_I64 ||
           t->kind == HL_TY_CHAR;
}

static int64_t sc_sext_int(uint64_t v, int bits) {
    if (bits == 8) return (int64_t)(int8_t)v;
    if (bits == 16) return (int64_t)(int16_t)v;
    if (bits == 32) return (int64_t)(int32_t)v;
    return (int64_t)v;
}

static int sc_ty_pointee_bits(const hl_type *t, int ptr_bits) {
    if (!t || t->ptr_depth == 0) return 0;
    if (t->ptr_depth >= 2) return ptr_bits;
    switch (t->kind) {
        case HL_TY_BOOL:
        case HL_TY_I8:
        case HL_TY_U8:
        case HL_TY_CHAR:    return 8;
        case HL_TY_I16:
        case HL_TY_U16:
        case HL_TY_WCHAR:   return 16;
        case HL_TY_I32:
        case HL_TY_U32:
        case HL_TY_F32:     return 32;
        case HL_TY_I64:
        case HL_TY_U64:
        case HL_TY_F64:
        case HL_TY_SIZE_T:
        case HL_TY_HANDLE:
        case HL_TY_HMODULE:
        case HL_TY_HWND:
        case HL_TY_HKEY:
        case HL_TY_SOCKET:  return ptr_bits;
        default:            return 0;
    }
}

static int sc_canon_var(const hl_fn *fn, int vid) {
    if (!fn || vid < 0 || vid >= fn->nvar) return -1;
    int c = hl_var_canon(fn, vid);
    if (c < 0 || c >= fn->nvar) return vid;
    return c;
}

static const ana_lvar *sc_find_lvar(const hl_fn *fn, const hl_var *v) {
    if (!fn || !fn->a || !fn->g || !v) return NULL;
    char arg_orig[16] = "";
    if (v->is_arg && v->arg_idx >= 0) snprintf(arg_orig, sizeof(arg_orig), "a%d", v->arg_idx + 1);
    for (uint32_t i = 0; i < fn->a->nlvar; i++) {
        const ana_lvar *lv = &fn->a->lvars[i];
        if (lv->func_va != fn->g->func_va) continue;
        if (v->orig[0] && strcmp(lv->orig, v->orig) == 0) return lv;
        if (arg_orig[0] && strcmp(lv->orig, arg_orig) == 0) return lv;
        if (v->name[0] && strcmp(lv->orig, v->name) == 0) return lv;
    }
    return NULL;
}

static void sc_var_resolve(const hl_fn *fn, int vid, char *orig_out, size_t ocap,
                           char *name_out, size_t ncap, char *type_out, size_t tcap) {
    int cv = sc_canon_var(fn, vid);
    if (cv < 0) {
        if (orig_out && ocap) snprintf(orig_out, ocap, "v0");
        if (name_out && ncap) snprintf(name_out, ncap, "v0");
        if (type_out && tcap) snprintf(type_out, tcap, "int64_t");
        return;
    }
    const hl_var *v = &fn->vars[cv];
    char orig_buf[32];
    if (v->orig[0]) snprintf(orig_buf, sizeof(orig_buf), "%s", v->orig);
    else if (v->is_arg && v->arg_idx >= 0) snprintf(orig_buf, sizeof(orig_buf), "a%d", v->arg_idx + 1);
    else if (v->name[0]) snprintf(orig_buf, sizeof(orig_buf), "%s", v->name);
    else snprintf(orig_buf, sizeof(orig_buf), "v%d", cv + 1);

    if (orig_out && ocap) snprintf(orig_out, ocap, "%s", orig_buf);

    const ana_lvar *lv = sc_find_lvar(fn, v);
    if (name_out && ncap) {
        if (lv && lv->name[0]) snprintf(name_out, ncap, "%s", lv->name);
        else if (v->name[0]) snprintf(name_out, ncap, "%s", v->name);
        else snprintf(name_out, ncap, "%s", orig_buf);
    }

    if (type_out && tcap) {
        if (lv && lv->type[0]) {
            snprintf(type_out, tcap, "%s", lv->type);
        } else {
            hl_type tmp = v->ty;
            int vbits = v->bits ? v->bits : (fn->ptr_bits ? fn->ptr_bits : 64);
            if (tmp.kind == HL_TY_UNK && tmp.ptr_depth == 0) {
                if (v->is_flt) tmp.kind = (vbits == 32) ? HL_TY_F32 : HL_TY_F64;
                else if (vbits == 8) tmp.kind = HL_TY_U8;
                else if (vbits == 16) tmp.kind = HL_TY_U16;
                else if (vbits == 32) tmp.kind = HL_TY_I32;
                else tmp.kind = HL_TY_I64;
                tmp.bits = (uint8_t)vbits;
            }
            type_out[0] = 0;
            hl_type_fmt(&tmp, type_out, tcap);
            if (!type_out[0]) snprintf(type_out, tcap, "%s", sc_fallback_ctype(vbits, v->is_flt));
        }
    }
}

// --- jump table target resolution ---

static int sc_find_blk_va(const hl_fn *fn, uint64_t va) {
    int lim = (fn->nblk > SC_MAX_BLKS) ? SC_MAX_BLKS : fn->nblk;
    for (int i = 0; i < lim; i++) {
        if (fn->blks[i].start == va) return i;
    }
    return -1;
}

static uint32_t sc_read_jtbl(const hl_fn *fn, int sw_idx, uint64_t *tgts, uint32_t max_tgts) {
    if (!fn || !fn->a || sw_idx < 0 || sw_idx >= fn->nsw) return 0;
    const ir_switch *sw = &fn->sws[sw_idx];
    uint32_t nc = sw->ncases;
    if (nc > max_tgts) nc = max_tgts;
    if (nc < 2 || sw->table_va == 0) return 0;

    int psz = (fn->ptr_bits == 32 || fn->a->bin.bits == 32) ? 4 : 8;
    uint32_t valid = 0;
    for (uint32_t i = 0; i < nc; i++) {
        uint64_t ptr = 0;
        if (bin_read(&fn->a->bin, sw->table_va + (uint64_t)i * (uint64_t)psz,
                     (uint8_t *)&ptr, (size_t)psz) == (size_t)psz &&
            bin_is_exec(&fn->a->bin, ptr)) {
            tgts[valid++] = ptr;
        } else {
            break;
        }
    }
    if (valid >= 2) return valid;

    // 32-bit image-base RVA jump table (MSVC x64)
    valid = 0;
    for (uint32_t i = 0; i < nc; i++) {
        uint32_t rva = 0;
        if (bin_read(&fn->a->bin, sw->table_va + (uint64_t)i * 4, (uint8_t *)&rva, 4) == 4 &&
            rva != 0 && (uint64_t)rva <= UINT64_MAX - fn->a->bin.base &&
            bin_is_exec(&fn->a->bin, fn->a->bin.base + (uint64_t)rva)) {
            tgts[valid++] = fn->a->bin.base + (uint64_t)rva;
        } else {
            break;
        }
    }
    if (valid >= 2) return valid;

    // 32-bit table-relative signed offset table (GCC/Clang PIC)
    valid = 0;
    for (uint32_t i = 0; i < nc; i++) {
        int32_t rel = 0;
        if (bin_read(&fn->a->bin, sw->table_va + (uint64_t)i * 4, (uint8_t *)&rel, 4) == 4) {
            int64_t srel = (int64_t)rel;
            if (srel < 0 && (uint64_t)(-srel) > sw->table_va) break;
            if (srel > 0 && (uint64_t)srel > UINT64_MAX - sw->table_va) break;
            uint64_t tgt = sw->table_va + (uint64_t)srel;
            if (bin_is_exec(&fn->a->bin, tgt)) tgts[valid++] = tgt;
            else break;
        } else {
            break;
        }
    }
    return valid >= 2 ? valid : 0;
}

// --- CFG, dominators, and exact bitset post-dominators ---

static void sc_build_cfg_and_doms(sc_ctx *sc) {
    hl_fn *fn = sc->fn;
    int n = sc->nblk;
    uint64_t *tgts = NULL;

    for (int i = 0; i < n; i++) {
        const hl_blk *b = &fn->blks[i];
        int bt = (b->out_t >= 0 && b->out_t < n) ? b->out_t : -1;
        int bf = (b->out_f >= 0 && b->out_f < n) ? b->out_f : -1;
        int bu = (b->out_u >= 0 && b->out_u < n) ? b->out_u : -1;
        if (bt >= 0) {
            sc_iv_push_uniq(&sc->succ[i], bt);
            sc_iv_push_uniq(&sc->pred[bt], i);
        }
        if (bf >= 0) {
            sc_iv_push_uniq(&sc->succ[i], bf);
            sc_iv_push_uniq(&sc->pred[bf], i);
        }
        if (bu >= 0) {
            sc_iv_push_uniq(&sc->succ[i], bu);
            sc_iv_push_uniq(&sc->pred[bu], i);
        }
        if (b->sw_idx >= 0 && b->sw_idx < fn->nsw) {
            if (!tgts) tgts = (uint64_t *)malloc(SC_MAX_SW_CASES * sizeof(uint64_t));
            if (tgts) {
                uint32_t nt = sc_read_jtbl(fn, b->sw_idx, tgts, SC_MAX_SW_CASES);
                for (uint32_t t = 0; t < nt; t++) {
                    int tb = sc_find_blk_va(fn, tgts[t]);
                    if (tb >= 0 && tb < n) {
                        sc_iv_push_uniq(&sc->succ[i], tb);
                        sc_iv_push_uniq(&sc->pred[tb], i);
                    }
                }
            }
        }
    }
    free(tgts);

    for (int i = 0; i < n; i++) sc->in_deg[i] = sc->pred[i].len;

    // forward reachability from entry block 0
    int *q = (int *)malloc((size_t)(n > 0 ? n : 1) * sizeof(int));
    uint8_t *to_exit = (uint8_t *)calloc((size_t)(n > 0 ? n : 1), 1);
    uint8_t *can_exit = (uint8_t *)calloc((size_t)(n > 0 ? n : 1), 1);
    int *pcnt = (int *)malloc((size_t)(n + 1) * sizeof(int));
    if (!q || !to_exit || !can_exit || !pcnt) {
        free(q);
        free(to_exit);
        free(can_exit);
        free(pcnt);
        return;
    }

    int qh = 0, qt = 0;
    if (n > 0) {
        sc->reach[0] = 1;
        q[qt++] = 0;
    }
    while (qh < qt) {
        int u = q[qh++];
        for (int k = 0; k < sc->succ[u].len; k++) {
            int v = sc->succ[u].items[k];
            if (!sc->reach[v]) {
                sc->reach[v] = 1;
                q[qt++] = v;
            }
        }
    }

    // iterative bitset dominators
    if (n > 0) {
        sc_bits_zero(&sc->dom[0]);
        sc_bits_set(&sc->dom[0], 0);
        for (int i = 1; i < n; i++) {
            if (sc->reach[i]) sc_bits_all(&sc->dom[i], n);
            else {
                sc_bits_zero(&sc->dom[i]);
                sc_bits_set(&sc->dom[i], i);
            }
        }
        int changed = 1;
        while (changed) {
            changed = 0;
            for (int i = 1; i < n; i++) {
                if (!sc->reach[i]) continue;
                sc_bits tmp;
                sc_bits_all(&tmp, n);
                int has_p = 0;
                for (int k = 0; k < sc->pred[i].len; k++) {
                    int p = sc->pred[i].items[k];
                    if (!sc->reach[p]) continue;
                    sc_bits_and(&tmp, &sc->dom[p]);
                    has_p = 1;
                }
                if (!has_p) sc_bits_zero(&tmp);
                sc_bits_set(&tmp, i);
                if (!sc_bits_eq(&tmp, &sc->dom[i])) {
                    sc->dom[i] = tmp;
                    changed = 1;
                }
            }
        }
    }

    // mark natural loop headers (target h of back-edge u -> h where h dom u)
    for (int u = 0; u < n; u++) {
        if (!sc->reach[u]) continue;
        for (int k = 0; k < sc->succ[u].len; k++) {
            int h = sc->succ[u].items[k];
            if (sc_bits_test(&sc->dom[u], h)) {
                sc->is_loop_hdr[h] = 1;
                fn->blks[h].is_loop_hdr = 1;
            }
        }
    }

    // exact bitset post-dominators with virtual EXIT = n
    int exit_node = n;
    int total_nodes = n + 1;
    for (int i = 0; i < n; i++) {
        if (sc->succ[i].len == 0) to_exit[i] = 1;
    }

    // connect non-exiting SCCs (infinite loops) to virtual EXIT so pdom always converges
    for (;;) {
        memset(can_exit, 0, (size_t)n);
        qh = 0; qt = 0;
        for (int i = 0; i < n; i++) {
            if (to_exit[i]) {
                can_exit[i] = 1;
                q[qt++] = i;
            }
        }
        while (qh < qt) {
            int v = q[qh++];
            for (int k = 0; k < sc->pred[v].len; k++) {
                int p = sc->pred[v].items[k];
                if (!can_exit[p]) {
                    can_exit[p] = 1;
                    q[qt++] = p;
                }
            }
        }
        int pick = -1;
        for (int i = n - 1; i >= 0; i--) {
            if (can_exit[i]) continue;
            if (pick < 0) pick = i;
            int has_back = 0;
            for (int k = 0; k < sc->succ[i].len; k++) {
                if (sc_bits_test(&sc->dom[i], sc->succ[i].items[k])) {
                    has_back = 1;
                    break;
                }
            }
            if (has_back) {
                pick = i;
                break;
            }
        }
        if (pick < 0) break;
        to_exit[pick] = 1;
    }

    sc_bits_zero(&sc->pdom[exit_node]);
    sc_bits_set(&sc->pdom[exit_node], exit_node);
    for (int i = 0; i < n; i++) sc_bits_all(&sc->pdom[i], total_nodes);

    int pchanged = 1;
    while (pchanged) {
        pchanged = 0;
        for (int i = n - 1; i >= 0; i--) {
            sc_bits tmp;
            sc_bits_all(&tmp, total_nodes);
            for (int k = 0; k < sc->succ[i].len; k++) {
                sc_bits_and(&tmp, &sc->pdom[sc->succ[i].items[k]]);
            }
            if (to_exit[i]) sc_bits_and(&tmp, &sc->pdom[exit_node]);
            sc_bits_set(&tmp, i);
            if (!sc_bits_eq(&tmp, &sc->pdom[i])) {
                sc->pdom[i] = tmp;
                pchanged = 1;
            }
        }
    }

    for (int i = 0; i <= n; i++) pcnt[i] = sc_bits_popcnt(&sc->pdom[i]);

    for (int i = 0; i < n; i++) {
        int best = -1;
        int best_cnt = -1;
        for (int d = 0; d <= n; d++) {
            if (d == i) continue;
            if (sc_bits_test(&sc->pdom[i], d) && pcnt[d] > best_cnt) {
                best = d;
                best_cnt = pcnt[d];
            }
        }
        int ip = (best == exit_node || best < 0) ? -1 : best;
        sc->ipdom[i] = ip;
        fn->blks[i].ipdom = ip;
    }

    free(q);
    free(to_exit);
    free(can_exit);
    free(pcnt);
}

static int sc_doms(const sc_ctx *sc, int d, int b) {
    if (d < 0 || d >= sc->nblk || b < 0 || b >= sc->nblk) return 0;
    return sc_bits_test(&sc->dom[b], d);
}

static int sc_postdoms(const sc_ctx *sc, int d, int b) {
    if (d < 0 || d >= sc->nblk || b < 0 || b >= sc->nblk) return 0;
    return sc_bits_test(&sc->pdom[b], d);
}

// --- IR expression & statement predicates ---

static int sc_expr_has_call(const hl_fn *fn, int eid, int depth) {
    if (!fn || eid < 0 || eid >= fn->nexpr || depth > 24) return 0;
    const hl_expr *e = &fn->exprs[eid];
    if (e->kind == HLE_CALL) return 1;
    if (e->sub0 >= 0 && sc_expr_has_call(fn, e->sub0, depth + 1)) return 1;
    if (e->sub1 >= 0 && sc_expr_has_call(fn, e->sub1, depth + 1)) return 1;
    if (e->sub2 >= 0 && sc_expr_has_call(fn, e->sub2, depth + 1)) return 1;
    return 0;
}

static int sc_expr_has_deref(const hl_fn *fn, int eid, int depth) {
    if (!fn || eid < 0 || eid >= fn->nexpr || depth > 24) return 0;
    const hl_expr *e = &fn->exprs[eid];
    if (e->kind == HLE_DEREF || e->kind == HLE_FIELD || e->kind == HLE_INDEX || e->kind == HLE_CALL) return 1;
    if (e->sub0 >= 0 && sc_expr_has_deref(fn, e->sub0, depth + 1)) return 1;
    if (e->sub1 >= 0 && sc_expr_has_deref(fn, e->sub1, depth + 1)) return 1;
    if (e->sub2 >= 0 && sc_expr_has_deref(fn, e->sub2, depth + 1)) return 1;
    return 0;
}

static int sc_expr_count_var(const hl_fn *fn, int eid, int cv, int depth) {
    if (!fn || eid < 0 || eid >= fn->nexpr || depth > 24) return 0;
    const hl_expr *e = &fn->exprs[eid];
    int cnt = 0;
    if (e->kind == HLE_VAR && sc_canon_var(fn, e->var_id) == cv) cnt++;
    if (e->sub0 >= 0) cnt += sc_expr_count_var(fn, e->sub0, cv, depth + 1);
    if (e->sub1 >= 0) cnt += sc_expr_count_var(fn, e->sub1, cv, depth + 1);
    if (e->sub2 >= 0) cnt += sc_expr_count_var(fn, e->sub2, cv, depth + 1);
    if (e->kind == HLE_CALL) {
        int na = (e->narg > HL_MAX_CALL_ARG) ? HL_MAX_CALL_ARG : (int)e->narg;
        for (int i = 0; i < na; i++) {
            if (e->args[i] >= 0) cnt += sc_expr_count_var(fn, e->args[i], cv, depth + 1);
        }
    }
    return cnt;
}

static int sc_expr_equal(const hl_fn *fn, int a, int b, int depth) {
    if (a == b) return 1;
    if (!fn || a < 0 || a >= fn->nexpr || b < 0 || b >= fn->nexpr || depth > 16) return 0;
    const hl_expr *ea = &fn->exprs[a];
    const hl_expr *eb = &fn->exprs[b];
    if (ea->kind != eb->kind || ea->op != eb->op) return 0;
    switch (ea->kind) {
        case HLE_INT:     return ea->uval == eb->uval;
        case HLE_FLT:     return ea->fval == eb->fval;
        case HLE_STR:     return ea->va == eb->va;
        case HLE_SYM:     return ea->va == eb->va && strcmp(ea->sym, eb->sym) == 0;
        case HLE_VAR:     return sc_canon_var(fn, ea->var_id) == sc_canon_var(fn, eb->var_id);
        case HLE_ADDR:
        case HLE_DEREF:
            return ea->disp == eb->disp && ea->va == eb->va && ea->bits == eb->bits &&
                   sc_expr_equal(fn, ea->sub0, eb->sub0, depth + 1);
        case HLE_FIELD:
            return ea->disp == eb->disp && ea->is_dot == eb->is_dot &&
                   strcmp(ea->field, eb->field) == 0 &&
                   sc_expr_equal(fn, ea->sub0, eb->sub0, depth + 1);
        case HLE_INDEX:
            return ea->scale == eb->scale && ea->disp == eb->disp &&
                   sc_expr_equal(fn, ea->sub0, eb->sub0, depth + 1) &&
                   sc_expr_equal(fn, ea->sub1, eb->sub1, depth + 1);
        case HLE_UNOP:
            return sc_expr_equal(fn, ea->sub0, eb->sub0, depth + 1);
        case HLE_BINOP:
            return sc_expr_equal(fn, ea->sub0, eb->sub0, depth + 1) &&
                   sc_expr_equal(fn, ea->sub1, eb->sub1, depth + 1);
        case HLE_BITSET:
            return ea->uval == eb->uval && ea->disp == eb->disp &&
                   sc_expr_equal(fn, ea->sub0, eb->sub0, depth + 1);
        default:
            return 0;
    }
}

static int sc_expr_subst_var(hl_fn *fn, int eid, int cv, int repl, int depth) {
    if (!fn || eid < 0 || eid >= fn->nexpr || depth > 24) return eid;
    hl_expr copy = fn->exprs[eid];
    if (copy.kind == HLE_VAR && sc_canon_var(fn, copy.var_id) == cv) {
        return hl_expr_clone(fn, repl);
    }
    int nid = hl_expr_new(fn, copy.kind);
    if (nid < 0) return eid;
    fn->exprs[nid] = copy;
    if (copy.sub0 >= 0) fn->exprs[nid].sub0 = sc_expr_subst_var(fn, copy.sub0, cv, repl, depth + 1);
    if (copy.sub1 >= 0) fn->exprs[nid].sub1 = sc_expr_subst_var(fn, copy.sub1, cv, repl, depth + 1);
    if (copy.sub2 >= 0) fn->exprs[nid].sub2 = sc_expr_subst_var(fn, copy.sub2, cv, repl, depth + 1);
    if (copy.kind == HLE_CALL) {
        int na = (copy.narg > HL_MAX_CALL_ARG) ? HL_MAX_CALL_ARG : (int)copy.narg;
        for (int i = 0; i < na; i++) {
            if (copy.args[i] >= 0) {
                fn->exprs[nid].args[i] = sc_expr_subst_var(fn, copy.args[i], cv, repl, depth + 1);
            }
        }
    }
    return nid;
}

static int sc_is_bool_expr(const hl_fn *fn, int eid) {
    if (!fn || eid < 0 || eid >= fn->nexpr) return 0;
    const hl_expr *e = &fn->exprs[eid];
    if (e->ty.kind == HL_TY_BOOL && e->ty.ptr_depth == 0) return 1;
    if (e->kind == HLE_BITSET) return 1;
    if (e->kind == HLE_UNOP && e->op == HLU_LOGNOT) return 1;
    if (e->kind == HLE_BINOP) {
        return (e->op >= HLB_EQ && e->op <= HLB_LOR);
    }
    return 0;
}

static int sc_stmt_is_live(const sc_ctx *sc, int sid) {
    const hl_fn *fn = sc->fn;
    if (sid < 0 || sid >= fn->nstmt) return 0;
    if (sc->extracted_stmt && sid < sc->extracted_cap && sc->extracted_stmt[sid]) return 0;
    const hl_stmt *s = &fn->stmts[sid];
    if (s->dead || s->kind == HLS_NOP || s->kind == HLS_PHI) return 0;
    if (s->kind == HLS_ASSIGN && s->dst_var >= 0) {
        int dv = sc_canon_var(fn, s->dst_var);
        if (dv >= 0 && s->rhs_expr >= 0 && s->rhs_expr < fn->nexpr) {
            const hl_expr *rhs = &fn->exprs[s->rhs_expr];
            if (rhs->kind == HLE_VAR && sc_canon_var(fn, rhs->var_id) == dv) return 0;
            if ((fn->vars[dv].is_dead || fn->vars[dv].is_canary) &&
                !sc_expr_has_call(fn, s->rhs_expr, 0)) {
                return 0;
            }
        }
    }
    return 1;
}

static int sc_blk_live_count(const sc_ctx *sc, int bi) {
    if (bi < 0 || bi >= sc->nblk) return 0;
    const hl_blk *b = &sc->fn->blks[bi];
    int cnt = 0;
    for (int i = 0; i < b->nstmt; i++) {
        if (sc_stmt_is_live(sc, b->stmts[i])) cnt++;
    }
    return cnt;
}

static int sc_blk_last_live_stmt(const sc_ctx *sc, int bi) {
    if (bi < 0 || bi >= sc->nblk) return -1;
    const hl_blk *b = &sc->fn->blks[bi];
    for (int i = b->nstmt - 1; i >= 0; i--) {
        if (sc_stmt_is_live(sc, b->stmts[i])) return b->stmts[i];
    }
    return -1;
}

static int sc_is_direct_small_exit(const sc_ctx *sc, int bi) {
    if (bi < 0 || bi >= sc->nblk) return 0;
    const hl_blk *b = &sc->fn->blks[bi];
    if (b->out_t >= 0 || b->out_f >= 0 || b->out_u >= 0 || b->sw_idx >= 0) return 0;
    if (sc->is_loop_hdr[bi]) return 0;
    int live = sc_blk_live_count(sc, bi);
    if (live > 3) return 0;
    if (live == 0) return b->is_exit != 0;
    int last = sc_blk_last_live_stmt(sc, bi);
    return last >= 0 && sc->fn->stmts[last].kind == HLS_RET;
}

static int sc_is_small_exit(const sc_ctx *sc, int bi) {
    if (sc_is_direct_small_exit(sc, bi)) return 1;
    if (bi < 0 || bi >= sc->nblk) return 0;
    const hl_blk *b = &sc->fn->blks[bi];
    if (b->out_t >= 0 || b->out_f >= 0 || b->sw_idx >= 0 || b->out_u < 0 || b->out_u == bi) return 0;
    if (sc->is_loop_hdr[bi]) return 0;
    if (sc_blk_live_count(sc, bi) > 2) return 0;
    return sc_is_direct_small_exit(sc, b->out_u);
}

static int sc_branch_returns(const sc_ctx *sc, int bi) {
    int cur = bi;
    for (int hop = 0; hop < 3; hop++) {
        if (cur < 0 || cur >= sc->nblk) return 0;
        if (sc_is_small_exit(sc, cur)) return 1;
        const hl_blk *b = &sc->fn->blks[cur];
        if (b->out_t < 0 && b->out_f < 0 && b->out_u < 0 && b->sw_idx < 0) {
            int last = sc_blk_last_live_stmt(sc, cur);
            return (last >= 0 && sc->fn->stmts[last].kind == HLS_RET) || b->is_exit;
        }
        if (b->out_t < 0 && b->out_f < 0 && b->out_u >= 0 && b->sw_idx < 0 &&
            !sc->is_loop_hdr[cur] && b->out_u != cur) {
            cur = b->out_u;
            continue;
        }
        return 0;
    }
    return 0;
}

static int sc_var_used_outside_blk(const sc_ctx *sc, int cv, int skip_bi) {
    const hl_fn *fn = sc->fn;
    for (int i = 0; i < sc->nblk; i++) {
        if (i == skip_bi) continue;
        const hl_blk *b = &fn->blks[i];
        if (b->cond_expr >= 0 && sc_expr_count_var(fn, b->cond_expr, cv, 0) > 0) return 1;
        if (b->sw_expr >= 0 && sc_expr_count_var(fn, b->sw_expr, cv, 0) > 0) return 1;
        for (int k = 0; k < b->nstmt; k++) {
            int sid = b->stmts[k];
            if (!sc_stmt_is_live(sc, sid)) continue;
            const hl_stmt *s = &fn->stmts[sid];
            if (s->lhs_expr >= 0 && sc_expr_count_var(fn, s->lhs_expr, cv, 0) > 0) return 1;
            if (s->rhs_expr >= 0 && sc_expr_count_var(fn, s->rhs_expr, cv, 0) > 0) return 1;
            if (s->len_expr >= 0 && sc_expr_count_var(fn, s->len_expr, cv, 0) > 0) return 1;
        }
    }
    return 0;
}

// --- AST arena helpers ---

static int sc_node_new(sc_ctx *sc, uint8_t kind, uint64_t va) {
    if (sc->nnode == sc->node_cap) {
        int nc = sc->node_cap ? sc->node_cap * 2 : 128;
        sc_node *nn = (sc_node *)realloc(sc->nodes, (size_t)nc * sizeof(sc_node));
        if (!nn) return -1;
        sc->nodes = nn;
        sc->node_cap = nc;
    }
    int id = sc->nnode++;
    sc_node *n = &sc->nodes[id];
    memset(n, 0, sizeof(*n));
    n->kind = kind;
    n->va = va;
    n->first = n->last = n->next = n->prev = -1;
    n->stmt_id = -1;
    n->cond_expr = -1;
    n->then_body = -1;
    n->else_body = -1;
    n->for_init_stmt = -1;
    n->for_step_stmt = -1;
    n->sw_expr = -1;
    n->case_first = -1;
    n->target_blk = -1;
    return id;
}

static int sc_case_alloc(sc_ctx *sc, int count) {
    if (count <= 0) return -1;
    if (sc->ncase + count > sc->case_cap) {
        int nc = sc->case_cap ? sc->case_cap * 2 : 32;
        while (nc < sc->ncase + count) nc *= 2;
        sc_case *arr = (sc_case *)realloc(sc->cases, (size_t)nc * sizeof(sc_case));
        if (!arr) return -1;
        sc->cases = arr;
        sc->case_cap = nc;
    }
    int base = sc->ncase;
    memset(&sc->cases[base], 0, (size_t)count * sizeof(sc_case));
    for (int i = 0; i < count; i++) sc->cases[base + i].body = -1;
    sc->ncase += count;
    return base;
}

static void sc_seq_add(sc_ctx *sc, int seq_id, int child_id) {
    if (seq_id < 0 || child_id < 0) return;
    sc_node *seq = &sc->nodes[seq_id];
    sc_node *ch = &sc->nodes[child_id];
    ch->prev = seq->last;
    ch->next = -1;
    if (seq->last >= 0) sc->nodes[seq->last].next = child_id;
    else seq->first = child_id;
    seq->last = child_id;
}

static void sc_seq_remove(sc_ctx *sc, int seq_id, int child_id) {
    if (seq_id < 0 || child_id < 0) return;
    sc_node *seq = &sc->nodes[seq_id];
    sc_node *ch = &sc->nodes[child_id];
    if (ch->prev >= 0) sc->nodes[ch->prev].next = ch->next;
    else seq->first = ch->next;
    if (ch->next >= 0) sc->nodes[ch->next].prev = ch->prev;
    else seq->last = ch->prev;
    ch->prev = ch->next = -1;
}

static void sc_seq_replace(sc_ctx *sc, int seq_id, int old_id, int new_id) {
    if (seq_id < 0 || old_id < 0 || new_id < 0) return;
    sc_node *seq = &sc->nodes[seq_id];
    sc_node *o = &sc->nodes[old_id];
    sc_node *n = &sc->nodes[new_id];
    n->prev = o->prev;
    n->next = o->next;
    if (o->prev >= 0) sc->nodes[o->prev].next = new_id;
    else seq->first = new_id;
    if (o->next >= 0) sc->nodes[o->next].prev = new_id;
    else seq->last = new_id;
    o->prev = o->next = -1;
}

static int sc_seq_is_empty(const sc_ctx *sc, int seq_id) {
    if (seq_id < 0) return 1;
    return sc->nodes[seq_id].first < 0;
}

static int sc_node_terminates(const sc_ctx *sc, int nid);

static int sc_seq_terminates(const sc_ctx *sc, int seq_id) {
    if (seq_id < 0) return 0;
    int last = sc->nodes[seq_id].last;
    if (last < 0) return 0;
    return sc_node_terminates(sc, last);
}

static int sc_node_terminates(const sc_ctx *sc, int nid) {
    if (nid < 0) return 0;
    const sc_node *n = &sc->nodes[nid];
    switch (n->kind) {
        case SCN_RET:
        case SCN_BREAK:
        case SCN_CONTINUE:
        case SCN_GOTO:
            return 1;
        case SCN_STMT:
            return n->stmt_id >= 0 && n->stmt_id < sc->fn->nstmt &&
                   sc->fn->stmts[n->stmt_id].kind == HLS_RET;
        case SCN_IF:
            return n->else_body >= 0 &&
                   sc_seq_terminates(sc, n->then_body) &&
                   sc_seq_terminates(sc, n->else_body);
        case SCN_SEQ:
            return sc_seq_terminates(sc, nid);
        default:
            return 0;
    }
}

static void sc_emit_blk_stmts(sc_ctx *sc, int seq, int bi) {
    const hl_blk *b = &sc->fn->blks[bi];
    for (int i = 0; i < b->nstmt; i++) {
        int sid = b->stmts[i];
        if (!sc_stmt_is_live(sc, sid)) continue;
        int sn = sc_node_new(sc, SCN_STMT, sc->fn->stmts[sid].va);
        if (sn >= 0) {
            sc->nodes[sn].stmt_id = sid;
            sc_seq_add(sc, seq, sn);
        }
    }
}

// --- multi-block compound boolean folding (&& / ||) ---

static int sc_can_fold_cond_blk(sc_ctx *sc, int blk, int stop, int loop_hdr, int *out_stmt_sid) {
    *out_stmt_sid = -1;
    if (blk < 0 || blk >= sc->nblk || blk == stop || blk == loop_hdr) return 0;
    if (sc->emitted[blk] || sc->is_loop_hdr[blk] || sc->in_deg[blk] > 1) return 0;
    const hl_blk *b = &sc->fn->blks[blk];
    if (b->sw_idx >= 0 || b->cond_expr < 0) return 0;
    if (b->out_t < 0 || b->out_f < 0 || b->out_t == b->out_f) return 0;

    int live = sc_blk_live_count(sc, blk);
    if (live == 0) return 1;
    if (live == 1) {
        int sid = sc_blk_last_live_stmt(sc, blk);
        const hl_stmt *s = &sc->fn->stmts[sid];
        if (s->kind != HLS_ASSIGN || s->dst_var < 0 || s->rhs_expr < 0) return 0;
        if (sc_expr_has_call(sc->fn, s->rhs_expr, 0)) return 0;
        int dv = sc_canon_var(sc->fn, s->dst_var);
        if (dv < 0) return 0;
        int in_cond = sc_expr_count_var(sc->fn, b->cond_expr, dv, 0);
        if (in_cond <= 0) return 0;
        if (in_cond > 1 && sc_expr_has_deref(sc->fn, s->rhs_expr, 0)) return 0;
        if (sc_var_used_outside_blk(sc, dv, blk)) return 0;
        *out_stmt_sid = sid;
        return 1;
    }
    return 0;
}

static int sc_materialize_cond(sc_ctx *sc, int blk, int single_sid) {
    int c = sc->fn->blks[blk].cond_expr;
    if (single_sid < 0) return c;
    const hl_stmt *s = &sc->fn->stmts[single_sid];
    int dv = sc_canon_var(sc->fn, s->dst_var);
    return sc_expr_subst_var(sc->fn, c, dv, s->rhs_expr, 0);
}

static void sc_fold_cond(sc_ctx *sc, int *condp, int *btp, int *bfp, int stop, int loop_hdr) {
    hl_fn *fn = sc->fn;
    for (int step = 0; step < 8; step++) {
        int bt = *btp, bf = *bfp;
        int sid = -1;

        if (sc_can_fold_cond_blk(sc, bt, stop, loop_hdr, &sid)) {
            const hl_blk *b = &fn->blks[bt];
            if (b->out_f == bf) {
                int c2 = sc_materialize_cond(sc, bt, sid);
                *condp = hl_expr_binop(fn, HLB_LAND, *condp, c2, 1);
                sc->emitted[bt] = 1;
                *btp = b->out_t;
                continue;
            }
            if (b->out_t == bf) {
                int c2 = hl_expr_invert(fn, sc_materialize_cond(sc, bt, sid));
                *condp = hl_expr_binop(fn, HLB_LAND, *condp, c2, 1);
                sc->emitted[bt] = 1;
                *btp = b->out_f;
                continue;
            }
        }

        if (sc_can_fold_cond_blk(sc, bf, stop, loop_hdr, &sid)) {
            const hl_blk *b = &fn->blks[bf];
            if (b->out_t == bt) {
                int c2 = sc_materialize_cond(sc, bf, sid);
                *condp = hl_expr_binop(fn, HLB_LOR, *condp, c2, 1);
                sc->emitted[bf] = 1;
                *bfp = b->out_f;
                continue;
            }
            if (b->out_f == bt) {
                int c2 = hl_expr_invert(fn, sc_materialize_cond(sc, bf, sid));
                *condp = hl_expr_binop(fn, HLB_LOR, *condp, c2, 1);
                sc->emitted[bf] = 1;
                *bfp = b->out_t;
                continue;
            }
        }
        break;
    }
}

// --- switch builders ---

static void sc_build_seq(sc_ctx *sc, int seq, int bi, int stop,
                         int loop_hdr, int loop_exit, int do_latch,
                         int in_branch, int depth);

static int sc_extract_guard_expr(const hl_fn *fn, int cond_eid) {
    if (!fn || cond_eid < 0 || cond_eid >= fn->nexpr) return -1;
    const hl_expr *e = &fn->exprs[cond_eid];
    if (e->kind == HLE_BINOP && e->op >= HLB_EQ && e->op <= HLB_UGE) {
        if (e->sub0 >= 0 && fn->exprs[e->sub0].kind != HLE_INT) return e->sub0;
        if (e->sub1 >= 0 && fn->exprs[e->sub1].kind != HLE_INT) return e->sub1;
    }
    return -1;
}

static int sc_expr_is_unsigned(const hl_fn *fn, int eid, int bits);

static int sc_build_jtbl_switch(sc_ctx *sc, int seq, int guard_bi, int sw_bi, int sw_idx,
                                int def_blk, int sw_expr, int stop, int loop_hdr, int depth) {
    hl_fn *fn = sc->fn;
    if (guard_bi >= 0 && guard_bi < sc->nblk && sw_expr >= 0) {
        int gce = fn->blks[guard_bi].cond_expr;
        if (gce >= 0 && gce < fn->nexpr) {
            const hl_expr *ge = &fn->exprs[gce];
            if (ge->kind == HLE_BINOP && ge->op >= HLB_ULT && ge->op <= HLB_UGE) {
                int b0 = (ge->sub0 >= 0 && ge->sub0 < fn->nexpr) ? fn->exprs[ge->sub0].bits : 0;
                int b1 = (ge->sub1 >= 0 && ge->sub1 < fn->nexpr) ? fn->exprs[ge->sub1].bits : 0;
                int gb = (b0 > b1) ? b0 : b1;
                if (gb <= 1) gb = fn->ptr_bits ? fn->ptr_bits : 64;
                if (!sc_expr_is_unsigned(fn, sw_expr, gb)) {
                    int z = hl_expr_unop(fn, HLU_ZEXT, sw_expr, gb);
                    if (z >= 0) sw_expr = z;
                }
            }
        }
    }
    uint64_t *tgts = (uint64_t *)malloc(SC_MAX_SW_CASES * sizeof(uint64_t));
    uint8_t *done = (uint8_t *)calloc(SC_MAX_SW_CASES, 1);
    if (!tgts || !done) {
        free(tgts);
        free(done);
        return stop;
    }
    uint32_t valid = sc_read_jtbl(fn, sw_idx, tgts, SC_MAX_SW_CASES);
    if (valid < 2) {
        free(tgts);
        free(done);
        return stop;
    }

    int merge = (guard_bi >= 0) ? sc->ipdom[guard_bi] : sc->ipdom[sw_bi];
    if (merge == guard_bi || merge == sw_bi) merge = -1;
    if (merge >= 0 && stop >= 0 && merge != stop && sc_postdoms(sc, merge, stop)) merge = stop;
    if (merge < 0) merge = stop;

    int max_cases = (int)valid + (def_blk >= 0 ? 1 : 0);
    int cbase = sc_case_alloc(sc, max_cases);
    if (cbase < 0) {
        free(tgts);
        free(done);
        return merge;
    }

    int nout = 0;
    int group = 0;

    for (uint32_t i = 0; i < valid; i++) {
        if (done[i]) continue;
        int last_ci = -1;
        for (uint32_t j = i; j < valid; j++) {
            if (tgts[j] == tgts[i]) {
                done[j] = 1;
                int ci = cbase + nout++;
                sc->cases[ci].val = (int64_t)j;
                sc->cases[ci].is_default = 0;
                sc->cases[ci].is_char = 0;
                sc->cases[ci].va = tgts[i];
                sc->cases[ci].group_id = group;
                sc->cases[ci].body = -1;
                last_ci = ci;
            }
        }
        group++;
        if (last_ci < 0) continue;

        int cseq = sc_node_new(sc, SCN_SEQ, tgts[i]);
        sc->cases[last_ci].body = cseq;
        int tb = sc_find_blk_va(fn, tgts[i]);
        if (tb >= 0 && tb < sc->nblk) {
            if (tb != merge) {
                sc_build_seq(sc, cseq, tb, merge, loop_hdr, -1, -1, 1, depth + 1);
            }
            if (!sc_seq_terminates(sc, cseq)) {
                int brk = sc_node_new(sc, SCN_BREAK, fn->blks[tb].end);
                sc_seq_add(sc, cseq, brk);
            }
        } else {
            int cn = sc_node_new(sc, SCN_COMMENT, tgts[i]);
            if (cn >= 0) {
                const char *sym = ana_sym_at(fn->a, tgts[i]);
                if (sym) {
                    char clean[64];
                    sc_clean_sym(sym, clean, sizeof(clean));
                    snprintf(sc->nodes[cn].comment, sizeof(sc->nodes[cn].comment), "%s();", clean);
                } else {
                    snprintf(sc->nodes[cn].comment, sizeof(sc->nodes[cn].comment),
                             "/* case 0x%llx */", (unsigned long long)tgts[i]);
                }
                sc_seq_add(sc, cseq, cn);
            }
            int brk = sc_node_new(sc, SCN_BREAK, tgts[i]);
            sc_seq_add(sc, cseq, brk);
        }
    }

    if (def_blk >= 0 && def_blk < sc->nblk && def_blk != merge &&
        (!sc->emitted[def_blk] || sc_is_small_exit(sc, def_blk))) {
        int ci = cbase + nout++;
        sc->cases[ci].is_default = 1;
        sc->cases[ci].va = fn->blks[def_blk].start;
        sc->cases[ci].group_id = group++;
        int dseq = sc_node_new(sc, SCN_SEQ, fn->blks[def_blk].start);
        sc->cases[ci].body = dseq;
        sc_build_seq(sc, dseq, def_blk, merge, loop_hdr, -1, -1, 1, depth + 1);
        if (!sc_seq_terminates(sc, dseq)) {
            int brk = sc_node_new(sc, SCN_BREAK, fn->blks[def_blk].end);
            sc_seq_add(sc, dseq, brk);
        }
    }

    int swn = sc_node_new(sc, SCN_SWITCH, fn->sws[sw_idx].va ? fn->sws[sw_idx].va : fn->blks[sw_bi].start);
    if (swn >= 0) {
        sc->nodes[swn].end_va = fn->blks[sw_bi].end;
        sc->nodes[swn].sw_expr = sw_expr;
        sc->nodes[swn].case_first = cbase;
        sc->nodes[swn].ncase = nout;
        sc_seq_add(sc, seq, swn);
    }
    free(tgts);
    free(done);
    return merge;
}

static int sc_match_eq_imm(const hl_fn *fn, int eid, int *lhs_out, int64_t *val_out,
                           int *is_eq_out, int *is_char_out) {
    if (!fn || eid < 0 || eid >= fn->nexpr) return 0;
    const hl_expr *e = &fn->exprs[eid];
    if (e->kind == HLE_BINOP && (e->op == HLB_EQ || e->op == HLB_NE)) {
        int l = e->sub0, r = e->sub1;
        if (l < 0 || r < 0 || l >= fn->nexpr || r >= fn->nexpr) return 0;
        const hl_expr *el = &fn->exprs[l];
        const hl_expr *er = &fn->exprs[r];
        if (er->kind == HLE_INT && el->kind != HLE_INT) {
            *lhs_out = l;
            *val_out = (er->is_signed || sc_ty_is_signed(&er->ty))
                           ? sc_sext_int(er->uval, er->bits ? er->bits : 64)
                           : (int64_t)er->uval;
            *is_eq_out = (e->op == HLB_EQ);
            *is_char_out = (er->ty.kind == HL_TY_CHAR || el->ty.kind == HL_TY_CHAR);
            return 1;
        }
        if (el->kind == HLE_INT && er->kind != HLE_INT) {
            *lhs_out = r;
            *val_out = (el->is_signed || sc_ty_is_signed(&el->ty))
                           ? sc_sext_int(el->uval, el->bits ? el->bits : 64)
                           : (int64_t)el->uval;
            *is_eq_out = (e->op == HLB_EQ);
            *is_char_out = (el->ty.kind == HL_TY_CHAR || er->ty.kind == HL_TY_CHAR);
            return 1;
        }
    }
    if (e->kind == HLE_UNOP && e->op == HLU_LOGNOT && e->sub0 >= 0 && e->sub0 < fn->nexpr) {
        const hl_expr *sub = &fn->exprs[e->sub0];
        if (sub->kind == HLE_VAR || sub->kind == HLE_FIELD || sub->kind == HLE_DEREF || sub->kind == HLE_INDEX) {
            *lhs_out = e->sub0;
            *val_out = 0;
            *is_eq_out = 1;
            *is_char_out = (sub->ty.kind == HL_TY_CHAR);
            return 1;
        }
    }
    return 0;
}

static int sc_try_switch_chain(sc_ctx *sc, int seq, int bi, int stop, int loop_hdr,
                               int depth, int *next_bi) {
    hl_fn *fn = sc->fn;
    int base_lhs = -1, is_eq = 0, is_ch = 0;
    int64_t val = 0;
    if (!sc_match_eq_imm(fn, fn->blks[bi].cond_expr, &base_lhs, &val, &is_eq, &is_ch)) return 0;

    int test_blks[32];
    int case_blks[32];
    int64_t case_vals[32];
    int case_chars[32];
    int nc = 0;
    int cur = bi;
    int def_blk = -1;

    while (cur >= 0 && cur < sc->nblk && nc < 32) {
        const hl_blk *cb = &fn->blks[cur];
        if (cur != bi && (sc->emitted[cur] || sc->is_loop_hdr[cur] || sc->in_deg[cur] > 1 ||
                          sc_blk_live_count(sc, cur) > 0 || cb->sw_idx >= 0)) {
            break;
        }
        if (cb->out_t < 0 || cb->out_f < 0 || cb->out_t == cb->out_f) break;

        int clhs = -1, ceq = 0, cch = 0;
        int64_t cval = 0;
        if (!sc_match_eq_imm(fn, cb->cond_expr, &clhs, &cval, &ceq, &cch)) break;
        if (!sc_expr_equal(fn, clhs, base_lhs, 0)) break;

        int cblk = ceq ? cb->out_t : cb->out_f;
        int nblk = ceq ? cb->out_f : cb->out_t;
        test_blks[nc] = cur;
        case_blks[nc] = cblk;
        case_vals[nc] = cval;
        case_chars[nc] = cch;
        nc++;
        def_blk = nblk;
        if (nblk == stop || nblk == loop_hdr) break;
        cur = nblk;
    }

    if (nc < 3) return 0;
    for (int i = 0; i < nc; i++) sc->emitted[test_blks[i]] = 1;

    int merge = sc->ipdom[bi];
    if (merge == bi) merge = -1;
    if (merge >= 0 && stop >= 0 && merge != stop && sc_postdoms(sc, merge, stop)) merge = stop;
    if (merge < 0) merge = stop;

    int cbase = sc_case_alloc(sc, nc + 1);
    if (cbase < 0) return 0;

    int nout = 0;
    int group = 0;
    uint8_t done[32];
    memset(done, 0, sizeof(done));

    for (int i = 0; i < nc; i++) {
        if (done[i]) continue;
        int cb = case_blks[i];
        int last_ci = -1;
        for (int j = i; j < nc; j++) {
            if (case_blks[j] == cb) {
                done[j] = 1;
                int ci = cbase + nout++;
                sc->cases[ci].val = case_vals[j];
                sc->cases[ci].is_default = 0;
                sc->cases[ci].is_char = case_chars[j];
                sc->cases[ci].va = fn->blks[test_blks[j]].start;
                sc->cases[ci].group_id = group;
                sc->cases[ci].body = -1;
                last_ci = ci;
            }
        }
        group++;
        if (last_ci < 0) continue;

        int cseq = sc_node_new(sc, SCN_SEQ, fn->blks[test_blks[i]].start);
        sc->cases[last_ci].body = cseq;
        if (cb >= 0 && cb < sc->nblk && cb != merge) {
            sc_build_seq(sc, cseq, cb, merge, loop_hdr, -1, -1, 1, depth + 1);
        }
        if (!sc_seq_terminates(sc, cseq)) {
            uint64_t bva = (cb >= 0 && cb < sc->nblk) ? fn->blks[cb].end : fn->blks[test_blks[i]].end;
            int brk = sc_node_new(sc, SCN_BREAK, bva);
            sc_seq_add(sc, cseq, brk);
        }
    }

    if (def_blk >= 0 && def_blk < sc->nblk && def_blk != merge &&
        (!sc->emitted[def_blk] || sc_is_small_exit(sc, def_blk))) {
        int ci = cbase + nout++;
        sc->cases[ci].is_default = 1;
        sc->cases[ci].va = fn->blks[def_blk].start;
        sc->cases[ci].group_id = group++;
        int dseq = sc_node_new(sc, SCN_SEQ, fn->blks[def_blk].start);
        sc->cases[ci].body = dseq;
        sc_build_seq(sc, dseq, def_blk, merge, loop_hdr, -1, -1, 1, depth + 1);
        if (!sc_seq_terminates(sc, dseq)) {
            int brk = sc_node_new(sc, SCN_BREAK, fn->blks[def_blk].end);
            sc_seq_add(sc, dseq, brk);
        }
    }

    uint64_t sva = fn->blks[bi].cond_va ? fn->blks[bi].cond_va : fn->blks[bi].start;
    int swn = sc_node_new(sc, SCN_SWITCH, sva);
    if (swn >= 0) {
        sc->nodes[swn].end_va = fn->blks[test_blks[nc - 1]].end;
        sc->nodes[swn].sw_expr = base_lhs;
        sc->nodes[swn].case_first = cbase;
        sc->nodes[swn].ncase = nout;
        sc_seq_add(sc, seq, swn);
    }
    *next_bi = merge;
    return 1;
}

// --- loop builder ---

static void sc_loop_body(const sc_ctx *sc, int hdr, uint8_t *in_loop,
                         int *latch_out, int *nlatch_out, int *ext_preds_out) {
    memset(in_loop, 0, (size_t)sc->nblk);
    in_loop[hdr] = 1;
    int latch = -1, nlatch = 0;
    int *stack = (int *)malloc((size_t)(sc->nblk > 0 ? sc->nblk : 1) * sizeof(int));
    int sp = 0;

    if (stack) {
        for (int k = 0; k < sc->pred[hdr].len; k++) {
            int u = sc->pred[hdr].items[k];
            if (sc_doms(sc, hdr, u)) {
                nlatch++;
                latch = u;
                if (!in_loop[u]) {
                    in_loop[u] = 1;
                    stack[sp++] = u;
                }
            }
        }

        while (sp > 0) {
            int x = stack[--sp];
            for (int k = 0; k < sc->pred[x].len; k++) {
                int p = sc->pred[x].items[k];
                if (!in_loop[p]) {
                    in_loop[p] = 1;
                    stack[sp++] = p;
                }
            }
        }
        free(stack);
    }

    int ext = 0;
    for (int k = 0; k < sc->pred[hdr].len; k++) {
        if (!in_loop[sc->pred[hdr].items[k]]) ext++;
    }
    *latch_out = latch;
    *nlatch_out = nlatch;
    if (ext_preds_out) *ext_preds_out = ext;
}

static int sc_find_loop_exit(const sc_ctx *sc, const uint8_t *in_loop) {
    int found = -1;
    int cnt = 0;
    for (int u = 0; u < sc->nblk; u++) {
        if (!in_loop[u]) continue;
        for (int k = 0; k < sc->succ[u].len; k++) {
            int v = sc->succ[u].items[k];
            if (!in_loop[v]) {
                if (found != v) {
                    found = v;
                    cnt++;
                }
            }
        }
    }
    return (cnt == 1) ? found : -1;
}

static int sc_is_for_step(const hl_fn *fn, int sid, int *var_out) {
    if (!fn || sid < 0 || sid >= fn->nstmt) return 0;
    const hl_stmt *s = &fn->stmts[sid];
    if (s->kind != HLS_ASSIGN || s->dst_var < 0 || s->rhs_expr < 0 || s->rhs_expr >= fn->nexpr) return 0;
    int dv = sc_canon_var(fn, s->dst_var);
    if (dv < 0) return 0;
    const hl_expr *rhs = &fn->exprs[s->rhs_expr];
    if (rhs->kind != HLE_BINOP || (rhs->op != HLB_ADD && rhs->op != HLB_SUB)) return 0;
    if (rhs->sub0 < 0 || rhs->sub1 < 0 || rhs->sub0 >= fn->nexpr || rhs->sub1 >= fn->nexpr) return 0;
    const hl_expr *l = &fn->exprs[rhs->sub0];
    const hl_expr *r = &fn->exprs[rhs->sub1];
    if (l->kind == HLE_VAR && sc_canon_var(fn, l->var_id) == dv && !sc_expr_has_call(fn, rhs->sub1, 0)) {
        *var_out = dv;
        return 1;
    }
    if (rhs->op == HLB_ADD && r->kind == HLE_VAR && sc_canon_var(fn, r->var_id) == dv &&
        !sc_expr_has_call(fn, rhs->sub0, 0)) {
        *var_out = dv;
        return 1;
    }
    return 0;
}

static int sc_pull_for_init(sc_ctx *sc, int parent_seq, int step_var, int hdr_blk) {
    if (parent_seq < 0) return -1;
    int cur = sc->nodes[parent_seq].last;
    // skip the tentative label for hdr_blk itself if immediately preceding the loop
    if (cur >= 0 && sc->nodes[cur].kind == SCN_LABEL && sc->nodes[cur].target_blk == hdr_blk) {
        if (sc->need_lbl[hdr_blk]) return -1;
        cur = sc->nodes[cur].prev;
    }
    if (cur < 0 || sc->nodes[cur].kind != SCN_STMT) return -1;
    int sid = sc->nodes[cur].stmt_id;
    if (sid < 0 || sid >= sc->fn->nstmt) return -1;
    const hl_stmt *s = &sc->fn->stmts[sid];
    if (s->kind != HLS_ASSIGN || s->dst_var < 0 || s->rhs_expr < 0) return -1;
    if (sc_canon_var(sc->fn, s->dst_var) != step_var) return -1;
    if (sc_expr_has_call(sc->fn, s->rhs_expr, 0)) return -1;
    sc_seq_remove(sc, parent_seq, cur);
    return sid;
}

static int sc_build_loop(sc_ctx *sc, int parent_seq, int bi, int stop, int depth) {
    hl_fn *fn = sc->fn;
    uint8_t *in_loop = (uint8_t *)calloc((size_t)(sc->nblk > 0 ? sc->nblk : 1), 1);
    if (!in_loop) return stop;
    int latch = -1, nlatch = 0, ext_preds = 0;
    sc_loop_body(sc, bi, in_loop, &latch, &nlatch, &ext_preds);

    const hl_blk *b = &fn->blks[bi];
    int bt = (b->out_t >= 0 && b->out_t < sc->nblk) ? b->out_t : -1;
    int bf = (b->out_f >= 0 && b->out_f < sc->nblk) ? b->out_f : -1;
    int bu = (b->out_u >= 0 && b->out_u < sc->nblk) ? b->out_u : -1;

    // single-block self-loop -> do { ... } while (cond);
    if (bt >= 0 && bf >= 0 && (bt == bi || bf == bi) && bt != bf && b->cond_expr >= 0) {
        int wcond = (bt == bi) ? b->cond_expr : hl_expr_invert(fn, b->cond_expr);
        int exit_b = (bt == bi) ? bf : bt;
        int body = sc_node_new(sc, SCN_SEQ, b->start);
        sc_emit_blk_stmts(sc, body, bi);
        int dw = sc_node_new(sc, SCN_DO_WHILE, b->start);
        if (dw >= 0) {
            sc->nodes[dw].end_va = b->end;
            sc->nodes[dw].cond_expr = wcond;
            sc->nodes[dw].then_body = body;
            sc_seq_add(sc, parent_seq, dw);
        }
        free(in_loop);
        return exit_b;
    }

    // header-tested while / for loop
    if (bt >= 0 && bf >= 0 && bt != bf && sc_blk_live_count(sc, bi) == 0 && b->cond_expr >= 0) {
        int t_in = in_loop[bt];
        int f_in = in_loop[bf];
        if (t_in != f_in) {
            int wcond = t_in ? b->cond_expr : hl_expr_invert(fn, b->cond_expr);
            int body_blk = t_in ? bt : bf;
            int exit_b = t_in ? bf : bt;

            // fold short-circuit header conditions (e.g. while (i < n && p[i] != 0))
            for (int step = 0; step < 6; step++) {
                int sid = -1;
                if (body_blk == bi || !in_loop[body_blk]) break;
                if (!sc_can_fold_cond_blk(sc, body_blk, exit_b, bi, &sid)) break;
                const hl_blk *bb = &fn->blks[body_blk];
                if (bb->out_f == exit_b && bb->out_t >= 0 && in_loop[bb->out_t]) {
                    int c2 = sc_materialize_cond(sc, body_blk, sid);
                    wcond = hl_expr_binop(fn, HLB_LAND, wcond, c2, 1);
                    sc->emitted[body_blk] = 1;
                    body_blk = bb->out_t;
                } else if (bb->out_t == exit_b && bb->out_f >= 0 && in_loop[bb->out_f]) {
                    int c2 = hl_expr_invert(fn, sc_materialize_cond(sc, body_blk, sid));
                    wcond = hl_expr_binop(fn, HLB_LAND, wcond, c2, 1);
                    sc->emitted[body_blk] = 1;
                    body_blk = bb->out_f;
                } else {
                    break;
                }
            }

            // detect for (init; cond; step)
            int for_step = -1, for_init = -1;
            if (nlatch == 1 && latch >= 0 && latch != bi &&
                fn->blks[latch].out_u == bi && fn->blks[latch].out_t < 0 && fn->blks[latch].out_f < 0) {
                int last_sid = sc_blk_last_live_stmt(sc, latch);
                int step_var = -1;
                if (last_sid >= 0 && sc_is_for_step(fn, last_sid, &step_var) &&
                    (sc_expr_count_var(fn, wcond, step_var, 0) > 0 || fn->vars[step_var].is_loop_idx)) {
                    for_step = last_sid;
                    if (sc->extracted_stmt && last_sid < sc->extracted_cap) {
                        sc->extracted_stmt[last_sid] = 1;
                    }
                    if (ext_preds <= 1) {
                        for_init = sc_pull_for_init(sc, parent_seq, step_var, bi);
                    }
                }
            }

            int body = sc_node_new(sc, SCN_SEQ, fn->blks[body_blk].start);
            if (body_blk != bi) {
                sc_build_seq(sc, body, body_blk, exit_b, bi, exit_b, -1, 0, depth + 1);
            }
            if (for_step >= 0) {
                int fn_node = sc_node_new(sc, SCN_FOR, b->cond_va ? b->cond_va : b->start);
                if (fn_node >= 0) {
                    sc->nodes[fn_node].end_va = b->end;
                    sc->nodes[fn_node].cond_expr = wcond;
                    sc->nodes[fn_node].for_init_stmt = for_init;
                    sc->nodes[fn_node].for_step_stmt = for_step;
                    sc->nodes[fn_node].then_body = body;
                    sc_seq_add(sc, parent_seq, fn_node);
                }
            } else {
                int wn = sc_node_new(sc, SCN_WHILE, b->cond_va ? b->cond_va : b->start);
                if (wn >= 0) {
                    sc->nodes[wn].end_va = b->end;
                    sc->nodes[wn].cond_expr = wcond;
                    sc->nodes[wn].then_body = body;
                    sc_seq_add(sc, parent_seq, wn);
                }
            }
            free(in_loop);
            return exit_b;
        }
    }

    // bottom-tested multi-block do { ... } while (cond);
    if (nlatch == 1 && latch >= 0 && latch != bi &&
        fn->blks[latch].out_t >= 0 && fn->blks[latch].out_f >= 0 &&
        fn->blks[latch].cond_expr >= 0 &&
        ((fn->blks[latch].out_t == bi && !in_loop[fn->blks[latch].out_f]) ||
         (fn->blks[latch].out_f == bi && !in_loop[fn->blks[latch].out_t]))) {
        const hl_blk *lb = &fn->blks[latch];
        int wcond = (lb->out_t == bi) ? lb->cond_expr : hl_expr_invert(fn, lb->cond_expr);
        int exit_b = (lb->out_t == bi) ? lb->out_f : lb->out_t;

        int body = sc_node_new(sc, SCN_SEQ, b->start);
        sc_emit_blk_stmts(sc, body, bi);
        if (bu >= 0 && bu != bi) {
            sc_build_seq(sc, body, bu, exit_b, bi, exit_b, latch, 0, depth + 1);
        } else if (bt >= 0 && bf >= 0 && bt != bf) {
            int c = b->cond_expr;
            uint64_t cva = b->cond_va ? b->cond_va : b->start;
            int t_in = in_loop[bt], f_in = in_loop[bf];
            if (t_in && !f_in && bf == exit_b) {
                int ifn = sc_node_new(sc, SCN_IF, cva);
                int tseq = sc_node_new(sc, SCN_SEQ, cva);
                sc_seq_add(sc, tseq, sc_node_new(sc, SCN_BREAK, cva));
                sc->nodes[ifn].cond_expr = hl_expr_invert(fn, c);
                sc->nodes[ifn].then_body = tseq;
                sc_seq_add(sc, body, ifn);
                sc_build_seq(sc, body, bt, exit_b, bi, exit_b, latch, 0, depth + 1);
            } else if (f_in && !t_in && bt == exit_b) {
                int ifn = sc_node_new(sc, SCN_IF, cva);
                int tseq = sc_node_new(sc, SCN_SEQ, cva);
                sc_seq_add(sc, tseq, sc_node_new(sc, SCN_BREAK, cva));
                sc->nodes[ifn].cond_expr = c;
                sc->nodes[ifn].then_body = tseq;
                sc_seq_add(sc, body, ifn);
                sc_build_seq(sc, body, bf, exit_b, bi, exit_b, latch, 0, depth + 1);
            } else {
                int ifn = sc_node_new(sc, SCN_IF, cva);
                int tseq = sc_node_new(sc, SCN_SEQ, fn->blks[bt].start);
                int eseq = sc_node_new(sc, SCN_SEQ, fn->blks[bf].start);
                sc_build_seq(sc, tseq, bt, latch, bi, exit_b, latch, 1, depth + 1);
                sc_build_seq(sc, eseq, bf, latch, bi, exit_b, latch, 1, depth + 1);
                sc->nodes[ifn].cond_expr = c;
                sc->nodes[ifn].then_body = tseq;
                sc->nodes[ifn].else_body = eseq;
                sc_seq_add(sc, body, ifn);
            }
        }
        if (!sc->emitted[latch]) {
            sc->emitted[latch] = 1;
            sc_emit_blk_stmts(sc, body, latch);
        }
        int dw = sc_node_new(sc, SCN_DO_WHILE, b->start);
        if (dw >= 0) {
            sc->nodes[dw].end_va = lb->end;
            sc->nodes[dw].cond_expr = wcond;
            sc->nodes[dw].then_body = body;
            sc_seq_add(sc, parent_seq, dw);
        }
        free(in_loop);
        return exit_b;
    }

    // general multi-exit while (1) loop
    int body = sc_node_new(sc, SCN_SEQ, b->start);
    sc_emit_blk_stmts(sc, body, bi);
    int exit_b = sc_find_loop_exit(sc, in_loop);

    if (bt >= 0 && bf >= 0 && bt != bf && b->cond_expr >= 0) {
        int c = b->cond_expr;
        uint64_t cva = b->cond_va ? b->cond_va : b->start;
        int t_in = in_loop[bt];
        int f_in = in_loop[bf];
        if (t_in && !f_in) {
            exit_b = bf;
            int ifn = sc_node_new(sc, SCN_IF, cva);
            int tseq = sc_node_new(sc, SCN_SEQ, cva);
            sc_seq_add(sc, tseq, sc_node_new(sc, SCN_BREAK, cva));
            sc->nodes[ifn].cond_expr = hl_expr_invert(fn, c);
            sc->nodes[ifn].then_body = tseq;
            sc_seq_add(sc, body, ifn);
            if (bt != bi) sc_build_seq(sc, body, bt, exit_b, bi, exit_b, -1, 0, depth + 1);
        } else if (f_in && !t_in) {
            exit_b = bt;
            int ifn = sc_node_new(sc, SCN_IF, cva);
            int tseq = sc_node_new(sc, SCN_SEQ, cva);
            sc_seq_add(sc, tseq, sc_node_new(sc, SCN_BREAK, cva));
            sc->nodes[ifn].cond_expr = c;
            sc->nodes[ifn].then_body = tseq;
            sc_seq_add(sc, body, ifn);
            if (bf != bi) sc_build_seq(sc, body, bf, exit_b, bi, exit_b, -1, 0, depth + 1);
        } else {
            int bstop = (exit_b >= 0) ? exit_b : stop;
            int merge = sc->ipdom[bi];
            if (merge < 0 || merge == bi || !in_loop[merge]) merge = bstop;
            int ifn = sc_node_new(sc, SCN_IF, cva);
            int tseq = sc_node_new(sc, SCN_SEQ, fn->blks[bt].start);
            sc_build_seq(sc, tseq, bt, merge, bi, exit_b, -1, 1, depth + 1);
            sc->nodes[ifn].cond_expr = c;
            sc->nodes[ifn].then_body = tseq;
            if (bf != merge) {
                int eseq = sc_node_new(sc, SCN_SEQ, fn->blks[bf].start);
                sc_build_seq(sc, eseq, bf, merge, bi, exit_b, -1, 1, depth + 1);
                sc->nodes[ifn].else_body = eseq;
            }
            sc_seq_add(sc, body, ifn);
            if (merge >= 0 && merge != bstop && merge != bi && in_loop[merge]) {
                sc_build_seq(sc, body, merge, bstop, bi, exit_b, -1, 0, depth + 1);
            }
        }
    } else if (bu >= 0 && bu != bi) {
        int bstop = (exit_b >= 0) ? exit_b : stop;
        sc_build_seq(sc, body, bu, bstop, bi, exit_b, -1, 0, depth + 1);
    }

    int wn = sc_node_new(sc, SCN_WHILE, b->start);
    if (wn >= 0) {
        sc->nodes[wn].end_va = b->end;
        sc->nodes[wn].cond_expr = -1;
        sc->nodes[wn].then_body = body;
        sc_seq_add(sc, parent_seq, wn);
    }
    free(in_loop);
    return exit_b;
}

// --- region-based structured AST builder ---

static int sc_is_elif_blk(const sc_ctx *sc, int blk, int merge) {
    if (blk < 0 || blk >= sc->nblk || blk == merge) return 0;
    if (sc->emitted[blk] || sc->is_loop_hdr[blk] || sc->in_deg[blk] > 1) return 0;
    const hl_blk *b = &sc->fn->blks[blk];
    return sc_blk_live_count(sc, blk) == 0 && b->sw_idx < 0 &&
           b->out_t >= 0 && b->out_f >= 0 && b->out_t != b->out_f && b->cond_expr >= 0;
}

static int sc_cond_is_negated(const hl_fn *fn, int eid) {
    if (!fn || eid < 0 || eid >= fn->nexpr) return 0;
    const hl_expr *e = &fn->exprs[eid];
    return (e->kind == HLE_UNOP && e->op == HLU_LOGNOT) ||
           (e->kind == HLE_BINOP && e->op == HLB_NE);
}

static void sc_emit_small_exit(sc_ctx *sc, int seq, int bi) {
    sc_emit_blk_stmts(sc, seq, bi);
    sc->inlined_exit[bi] = 1;
    const hl_blk *b = &sc->fn->blks[bi];
    if (b->out_t < 0 && b->out_f < 0 && b->sw_idx < 0 && b->out_u >= 0 && b->out_u != bi &&
        sc_is_direct_small_exit(sc, b->out_u)) {
        sc_emit_blk_stmts(sc, seq, b->out_u);
        sc->inlined_exit[b->out_u] = 1;
    }
}

static void sc_build_seq(sc_ctx *sc, int seq, int bi, int stop,
                         int loop_hdr, int loop_exit, int do_latch,
                         int in_branch, int depth) {
    hl_fn *fn = sc->fn;
    if (depth > SC_MAX_DEPTH) {
        if (bi >= 0 && bi < sc->nblk) {
            if (sc_is_small_exit(sc, bi)) {
                sc_emit_small_exit(sc, seq, bi);
            } else {
                sc->need_lbl[bi] = 1;
                int gn = sc_node_new(sc, SCN_GOTO, fn->blks[bi].start);
                if (gn >= 0) {
                    sc->nodes[gn].target_blk = bi;
                    sc->nodes[gn].target_va = fn->blks[bi].start;
                    sc_seq_add(sc, seq, gn);
                }
            }
        }
        return;
    }

    while (bi >= 0 && bi < sc->nblk && bi != stop) {
        if (bi == loop_exit && loop_hdr >= 0 && in_branch) {
            sc_seq_add(sc, seq, sc_node_new(sc, SCN_BREAK, fn->blks[bi].start));
            return;
        }

        if (sc->emitted[bi]) {
            const hl_blk *eb = &fn->blks[bi];
            int is_empty_latch = (loop_hdr >= 0 && eb->out_u == loop_hdr &&
                                  eb->out_t < 0 && eb->out_f < 0 && eb->sw_idx < 0 &&
                                  sc_blk_live_count(sc, bi) == 0);
            if (bi == loop_hdr || is_empty_latch) {
                if (in_branch) {
                    sc_seq_add(sc, seq, sc_node_new(sc, SCN_CONTINUE, eb->start));
                }
            } else if (sc_is_small_exit(sc, bi)) {
                // smart tail duplication eliminates goto loc_ret
                sc_emit_small_exit(sc, seq, bi);
            } else {
                sc->need_lbl[bi] = 1;
                int gn = sc_node_new(sc, SCN_GOTO, fn->blks[bi].start);
                if (gn >= 0) {
                    sc->nodes[gn].target_blk = bi;
                    sc->nodes[gn].target_va = fn->blks[bi].start;
                    sc_seq_add(sc, seq, gn);
                }
            }
            return;
        }

        // inline shared small exits inside branches without emitting labels
        if (in_branch && sc_is_small_exit(sc, bi) && sc->in_deg[bi] > 1) {
            sc_emit_small_exit(sc, seq, bi);
            return;
        }

        sc->emitted[bi] = 1;

        if (bi == do_latch) {
            sc_emit_blk_stmts(sc, seq, bi);
            return;
        }

        // tentative label pruned later if no goto targets bi
        if (bi != 0) {
            int ln = sc_node_new(sc, SCN_LABEL, fn->blks[bi].start);
            if (ln >= 0) {
                sc->nodes[ln].target_blk = bi;
                sc->nodes[ln].target_va = fn->blks[bi].start;
                sc_seq_add(sc, seq, ln);
            }
        }

        if (sc->is_loop_hdr[bi] && bi != loop_hdr) {
            bi = sc_build_loop(sc, seq, bi, stop, depth + 1);
            continue;
        }

        sc_emit_blk_stmts(sc, seq, bi);

        const hl_blk *b = &fn->blks[bi];
        if (b->sw_idx >= 0 && b->sw_idx < fn->nsw) {
            bi = sc_build_jtbl_switch(sc, seq, -1, bi, b->sw_idx, -1, b->sw_expr, stop, loop_hdr, depth + 1);
            continue;
        }

        int bt = (b->out_t >= 0 && b->out_t < sc->nblk) ? b->out_t : -1;
        int bf = (b->out_f >= 0 && b->out_f < sc->nblk) ? b->out_f : -1;
        int bu = (b->out_u >= 0 && b->out_u < sc->nblk) ? b->out_u : -1;

        if (bt >= 0 && bt == bf) {
            bu = bt;
            bt = bf = -1;
        }

        if (bt >= 0 && bf >= 0) {
            // absorb bounds-check guard block into jump-table switch
            if (fn->blks[bf].sw_idx >= 0 && fn->blks[bf].sw_idx < fn->nsw &&
                !sc->emitted[bf] && sc->in_deg[bf] <= 1) {
                sc->emitted[bf] = 1;
                sc_emit_blk_stmts(sc, seq, bf);
                int swe = (fn->blks[bf].sw_expr >= 0) ? fn->blks[bf].sw_expr : sc_extract_guard_expr(fn, b->cond_expr);
                bi = sc_build_jtbl_switch(sc, seq, bi, bf, fn->blks[bf].sw_idx, bt, swe, stop, loop_hdr, depth + 1);
                continue;
            }
            if (fn->blks[bt].sw_idx >= 0 && fn->blks[bt].sw_idx < fn->nsw &&
                !sc->emitted[bt] && sc->in_deg[bt] <= 1) {
                sc->emitted[bt] = 1;
                sc_emit_blk_stmts(sc, seq, bt);
                int swe = (fn->blks[bt].sw_expr >= 0) ? fn->blks[bt].sw_expr : sc_extract_guard_expr(fn, b->cond_expr);
                bi = sc_build_jtbl_switch(sc, seq, bi, bt, fn->blks[bt].sw_idx, bf, swe, stop, loop_hdr, depth + 1);
                continue;
            }

            int next_after_sw = -1;
            if (sc_try_switch_chain(sc, seq, bi, stop, loop_hdr, depth + 1, &next_after_sw)) {
                bi = next_after_sw;
                continue;
            }

            int cond = b->cond_expr;
            uint64_t cva = b->cond_va ? b->cond_va : b->start;
            if (cond >= 0) sc_fold_cond(sc, &cond, &bt, &bf, stop, loop_hdr);

            if (bt == bf) {
                bi = bt;
                continue;
            }

            if (bt == stop) {
                int ifn = sc_node_new(sc, SCN_IF, cva);
                int tseq = sc_node_new(sc, SCN_SEQ, fn->blks[bf].start);
                sc_build_seq(sc, tseq, bf, stop, loop_hdr, loop_exit, do_latch, 1, depth + 1);
                sc->nodes[ifn].cond_expr = (cond >= 0) ? hl_expr_invert(fn, cond) : -1;
                sc->nodes[ifn].then_body = tseq;
                sc_seq_add(sc, seq, ifn);
                return;
            }
            if (bf == stop) {
                int ifn = sc_node_new(sc, SCN_IF, cva);
                int tseq = sc_node_new(sc, SCN_SEQ, fn->blks[bt].start);
                sc_build_seq(sc, tseq, bt, stop, loop_hdr, loop_exit, do_latch, 1, depth + 1);
                sc->nodes[ifn].cond_expr = cond;
                sc->nodes[ifn].then_body = tseq;
                sc_seq_add(sc, seq, ifn);
                return;
            }

            // loop-exit break flattening inside loops
            if (loop_hdr >= 0 && loop_exit >= 0) {
                if (bt == loop_exit && bf != loop_exit) {
                    int ifn = sc_node_new(sc, SCN_IF, cva);
                    int tseq = sc_node_new(sc, SCN_SEQ, cva);
                    sc_seq_add(sc, tseq, sc_node_new(sc, SCN_BREAK, cva));
                    sc->nodes[ifn].cond_expr = cond;
                    sc->nodes[ifn].then_body = tseq;
                    sc_seq_add(sc, seq, ifn);
                    bi = bf;
                    continue;
                }
                if (bf == loop_exit && bt != loop_exit) {
                    int ifn = sc_node_new(sc, SCN_IF, cva);
                    int tseq = sc_node_new(sc, SCN_SEQ, cva);
                    sc_seq_add(sc, tseq, sc_node_new(sc, SCN_BREAK, cva));
                    sc->nodes[ifn].cond_expr = (cond >= 0) ? hl_expr_invert(fn, cond) : -1;
                    sc->nodes[ifn].then_body = tseq;
                    sc_seq_add(sc, seq, ifn);
                    bi = bt;
                    continue;
                }
            }

            // early-return flattening keeps main path unindented (never capture shared non-exit blocks)
            int t_ret = sc_branch_returns(sc, bt) && (sc->in_deg[bt] <= 1 || sc_is_small_exit(sc, bt));
            int f_ret = sc_branch_returns(sc, bf) && (sc->in_deg[bf] <= 1 || sc_is_small_exit(sc, bf));
            int ret_stop = (stop >= 0 && sc_is_small_exit(sc, stop)) ? -1 : stop;
            if (t_ret && !f_ret) {
                int ifn = sc_node_new(sc, SCN_IF, cva);
                int tseq = sc_node_new(sc, SCN_SEQ, fn->blks[bt].start);
                sc_build_seq(sc, tseq, bt, ret_stop, loop_hdr, loop_exit, do_latch, 1, depth + 1);
                sc->nodes[ifn].cond_expr = cond;
                sc->nodes[ifn].then_body = tseq;
                sc_seq_add(sc, seq, ifn);
                bi = bf;
                continue;
            }
            if (f_ret && !t_ret) {
                int ifn = sc_node_new(sc, SCN_IF, cva);
                int tseq = sc_node_new(sc, SCN_SEQ, fn->blks[bf].start);
                sc_build_seq(sc, tseq, bf, ret_stop, loop_hdr, loop_exit, do_latch, 1, depth + 1);
                sc->nodes[ifn].cond_expr = (cond >= 0) ? hl_expr_invert(fn, cond) : -1;
                sc->nodes[ifn].then_body = tseq;
                sc_seq_add(sc, seq, ifn);
                bi = bt;
                continue;
            }

            // exact IPDOM-driven structured if / else
            int merge = sc->ipdom[bi];
            if (merge == bi) merge = -1;
            if (merge >= 0 && stop >= 0 && merge != stop && sc_postdoms(sc, merge, stop)) merge = stop;
            if (merge >= 0 && loop_hdr >= 0 && loop_exit >= 0 && merge == loop_exit && stop != loop_exit) {
                merge = -1;
            }

            if (merge == bt) {
                int ifn = sc_node_new(sc, SCN_IF, cva);
                int tseq = sc_node_new(sc, SCN_SEQ, fn->blks[bf].start);
                sc_build_seq(sc, tseq, bf, merge, loop_hdr, loop_exit, do_latch, 1, depth + 1);
                sc->nodes[ifn].cond_expr = (cond >= 0) ? hl_expr_invert(fn, cond) : -1;
                sc->nodes[ifn].then_body = tseq;
                sc_seq_add(sc, seq, ifn);
                bi = merge;
                continue;
            }
            if (merge == bf) {
                int ifn = sc_node_new(sc, SCN_IF, cva);
                int tseq = sc_node_new(sc, SCN_SEQ, fn->blks[bt].start);
                sc_build_seq(sc, tseq, bt, merge, loop_hdr, loop_exit, do_latch, 1, depth + 1);
                sc->nodes[ifn].cond_expr = cond;
                sc->nodes[ifn].then_body = tseq;
                sc_seq_add(sc, seq, ifn);
                bi = merge;
                continue;
            }
            if (merge >= 0 && sc_postdoms(sc, merge, bt) && sc_postdoms(sc, merge, bf)) {
                int swap = 0;
                int t_elif = sc_is_elif_blk(sc, bt, merge);
                int f_elif = sc_is_elif_blk(sc, bf, merge);
                if (t_elif && !f_elif) swap = 1;
                else if (!t_elif && !f_elif && cond >= 0 && sc_cond_is_negated(fn, cond)) swap = 1;

                if (swap) {
                    if (cond >= 0) cond = hl_expr_invert(fn, cond);
                    int tmp = bt; bt = bf; bf = tmp;
                }
                int ifn = sc_node_new(sc, SCN_IF, cva);
                int tseq = sc_node_new(sc, SCN_SEQ, fn->blks[bt].start);
                int eseq = sc_node_new(sc, SCN_SEQ, fn->blks[bf].start);
                sc_build_seq(sc, tseq, bt, merge, loop_hdr, loop_exit, do_latch, 1, depth + 1);
                sc_build_seq(sc, eseq, bf, merge, loop_hdr, loop_exit, do_latch, 1, depth + 1);
                sc->nodes[ifn].cond_expr = cond;
                sc->nodes[ifn].then_body = tseq;
                sc->nodes[ifn].else_body = eseq;
                sc_seq_add(sc, seq, ifn);
                bi = merge;
                continue;
            }

            // prefer keeping a shared non-exit continuation flat outside the if-branch
            if (sc->in_deg[bt] >= 2 && !sc_is_small_exit(sc, bt) && sc->in_deg[bf] <= 1 && !sc->emitted[bt]) {
                int ifn = sc_node_new(sc, SCN_IF, cva);
                int tseq = sc_node_new(sc, SCN_SEQ, fn->blks[bf].start);
                sc_build_seq(sc, tseq, bf, bt, loop_hdr, loop_exit, do_latch, 1, depth + 1);
                sc->nodes[ifn].cond_expr = (cond >= 0) ? hl_expr_invert(fn, cond) : -1;
                sc->nodes[ifn].then_body = tseq;
                sc_seq_add(sc, seq, ifn);
                bi = bt;
                continue;
            }
            if (sc->in_deg[bf] >= 2 && !sc_is_small_exit(sc, bf) && sc->in_deg[bt] <= 1 && !sc->emitted[bf]) {
                int ifn = sc_node_new(sc, SCN_IF, cva);
                int tseq = sc_node_new(sc, SCN_SEQ, fn->blks[bt].start);
                sc_build_seq(sc, tseq, bt, bf, loop_hdr, loop_exit, do_latch, 1, depth + 1);
                sc->nodes[ifn].cond_expr = cond;
                sc->nodes[ifn].then_body = tseq;
                sc_seq_add(sc, seq, ifn);
                bi = bf;
                continue;
            }

            // no in-function post-dominator: emit then-branch, keep sibling flat if then terminates
            int ifn = sc_node_new(sc, SCN_IF, cva);
            int tseq = sc_node_new(sc, SCN_SEQ, fn->blks[bt].start);
            sc_build_seq(sc, tseq, bt, stop, loop_hdr, loop_exit, do_latch, 1, depth + 1);
            sc->nodes[ifn].cond_expr = cond;
            sc->nodes[ifn].then_body = tseq;
            sc_seq_add(sc, seq, ifn);
            if (sc_seq_terminates(sc, tseq)) {
                bi = bf;
                continue;
            }
            int eseq = sc_node_new(sc, SCN_SEQ, fn->blks[bf].start);
            sc_build_seq(sc, eseq, bf, stop, loop_hdr, loop_exit, do_latch, 1, depth + 1);
            sc->nodes[ifn].else_body = eseq;
            return;
        }

        if (bu >= 0) {
            if (bu == loop_hdr && !in_branch) return;
            if (bu == loop_exit && loop_hdr >= 0 && in_branch) {
                sc_seq_add(sc, seq, sc_node_new(sc, SCN_BREAK, fn->blks[bu].start));
                return;
            }
            bi = bu;
            continue;
        }
        return;
    }
}

// --- AST optimization & cleanup passes ---

static void sc_mark_goto_targets(const sc_ctx *sc, int nid, uint8_t *used) {
    if (nid < 0) return;
    const sc_node *n = &sc->nodes[nid];
    switch (n->kind) {
        case SCN_SEQ:
            for (int c = n->first; c >= 0; c = sc->nodes[c].next) sc_mark_goto_targets(sc, c, used);
            break;
        case SCN_IF:
            sc_mark_goto_targets(sc, n->then_body, used);
            sc_mark_goto_targets(sc, n->else_body, used);
            break;
        case SCN_WHILE:
        case SCN_DO_WHILE:
        case SCN_FOR:
            sc_mark_goto_targets(sc, n->then_body, used);
            break;
        case SCN_SWITCH:
            for (int i = 0; i < n->ncase; i++) {
                sc_mark_goto_targets(sc, sc->cases[n->case_first + i].body, used);
            }
            break;
        case SCN_GOTO:
            if (n->target_blk >= 0 && n->target_blk < sc->nblk) used[n->target_blk] = 1;
            break;
        default:
            break;
    }
}

static int sc_prune_unused_labels_rec(sc_ctx *sc, int nid, const uint8_t *used) {
    if (nid < 0) return 0;
    int changed = 0;
    sc_node *n = &sc->nodes[nid];
    switch (n->kind) {
        case SCN_SEQ: {
            int c = n->first;
            while (c >= 0) {
                int nxt = sc->nodes[c].next;
                if (sc->nodes[c].kind == SCN_LABEL) {
                    int tb = sc->nodes[c].target_blk;
                    if (tb < 0 || tb >= sc->nblk || !used[tb]) {
                        sc_seq_remove(sc, nid, c);
                        changed = 1;
                    }
                } else {
                    changed |= sc_prune_unused_labels_rec(sc, c, used);
                }
                c = nxt;
            }
            break;
        }
        case SCN_IF:
            changed |= sc_prune_unused_labels_rec(sc, n->then_body, used);
            changed |= sc_prune_unused_labels_rec(sc, n->else_body, used);
            break;
        case SCN_WHILE:
        case SCN_DO_WHILE:
        case SCN_FOR:
            changed |= sc_prune_unused_labels_rec(sc, n->then_body, used);
            break;
        case SCN_SWITCH:
            for (int i = 0; i < n->ncase; i++) {
                changed |= sc_prune_unused_labels_rec(sc, sc->cases[n->case_first + i].body, used);
            }
            break;
        default:
            break;
    }
    return changed;
}

static int sc_prune_unused_labels(sc_ctx *sc, int root) {
    uint8_t *used = (uint8_t *)calloc((size_t)(sc->nblk > 0 ? sc->nblk : 1), 1);
    if (!used) return 0;
    sc_mark_goto_targets(sc, root, used);
    int changed = sc_prune_unused_labels_rec(sc, root, used);
    free(used);
    return changed;
}

static int sc_match_ret_const(const sc_ctx *sc, int nid, uint64_t *val_out) {
    if (nid < 0) return 0;
    const sc_node *n = &sc->nodes[nid];
    int eid = -1;
    if (n->kind == SCN_STMT && n->stmt_id >= 0 && n->stmt_id < sc->fn->nstmt) {
        const hl_stmt *s = &sc->fn->stmts[n->stmt_id];
        if (s->kind != HLS_RET) return 0;
        eid = s->rhs_expr;
    } else if (n->kind == SCN_RET) {
        eid = n->cond_expr;
    } else {
        return 0;
    }
    if (eid < 0 || eid >= sc->fn->nexpr) return 0;
    const hl_expr *e = &sc->fn->exprs[eid];
    if (e->kind != HLE_INT) return 0;
    *val_out = e->uval;
    return 1;
}

static int sc_seq_only_ret_const(const sc_ctx *sc, int seq_id, uint64_t *val_out) {
    if (seq_id < 0) return 0;
    int first = sc->nodes[seq_id].first;
    if (first < 0 || sc->nodes[first].next >= 0) return 0;
    return sc_match_ret_const(sc, first, val_out);
}

static int sc_opt_ast_rec(sc_ctx *sc, int nid) {
    if (nid < 0) return 0;
    int changed = 0;
    sc_node *n = &sc->nodes[nid];

    switch (n->kind) {
        case SCN_SEQ: {
            int c = n->first;
            int dead_after_term = 0;
            while (c >= 0) {
                int nxt = sc->nodes[c].next;
                sc_node *cn = &sc->nodes[c];

                if (cn->kind == SCN_LABEL) {
                    dead_after_term = 0;
                    c = nxt;
                    continue;
                }
                if (dead_after_term) {
                    sc_seq_remove(sc, nid, c);
                    changed = 1;
                    c = nxt;
                    continue;
                }
                if (cn->kind == SCN_STMT && !sc_stmt_is_live(sc, cn->stmt_id)) {
                    sc_seq_remove(sc, nid, c);
                    changed = 1;
                    c = nxt;
                    continue;
                }

                // collapse: v = expr; return v; -> return expr;
                if (cn->kind == SCN_STMT && nxt >= 0 && cn->stmt_id >= 0 && cn->stmt_id < sc->fn->nstmt) {
                    const hl_stmt *as = &sc->fn->stmts[cn->stmt_id];
                    int ret_eid = -1;
                    const sc_node *nn = &sc->nodes[nxt];
                    if (nn->kind == SCN_STMT && nn->stmt_id >= 0 && nn->stmt_id < sc->fn->nstmt &&
                        sc->fn->stmts[nn->stmt_id].kind == HLS_RET) {
                        ret_eid = sc->fn->stmts[nn->stmt_id].rhs_expr;
                    } else if (nn->kind == SCN_RET) {
                        ret_eid = nn->cond_expr;
                    }
                    if (as->kind == HLS_ASSIGN && as->dst_var >= 0 && as->rhs_expr >= 0 &&
                        ret_eid >= 0 && ret_eid < sc->fn->nexpr && sc->fn->exprs[ret_eid].kind == HLE_VAR &&
                        hl_var_canon(sc->fn, sc->fn->exprs[ret_eid].var_id) == hl_var_canon(sc->fn, as->dst_var)) {
                        int after_nxt = nn->next;
                        int rn = sc_node_new(sc, SCN_RET, cn->va);
                        if (rn >= 0) {
                            sc->nodes[rn].cond_expr = as->rhs_expr;
                            sc_seq_remove(sc, nid, nxt);
                            sc_seq_replace(sc, nid, c, rn);
                            changed = 1;
                            dead_after_term = 1;
                            c = after_nxt;
                            continue;
                        }
                    }
                }

                // redundant goto immediately before its own label
                if (cn->kind == SCN_GOTO && nxt >= 0 && sc->nodes[nxt].kind == SCN_LABEL &&
                    sc->nodes[nxt].target_blk == cn->target_blk) {
                    sc_seq_remove(sc, nid, c);
                    changed = 1;
                    c = nxt;
                    continue;
                }

                changed |= sc_opt_ast_rec(sc, c);
                cn = &sc->nodes[c];
                nxt = cn->next;

                // remove empty no-side-effect if
                if (cn->kind == SCN_IF && sc_seq_is_empty(sc, cn->then_body) &&
                    sc_seq_is_empty(sc, cn->else_body) &&
                    !sc_expr_has_call(sc->fn, cn->cond_expr, 0)) {
                    sc_seq_remove(sc, nid, c);
                    changed = 1;
                    c = nxt;
                    continue;
                }

                // collapse: if (c) { return 1; } else { return 0; } -> return c;
                if (cn->kind == SCN_IF && cn->cond_expr >= 0 && sc_is_bool_expr(sc->fn, cn->cond_expr)) {
                    uint64_t tv = 0, fv = 0;
                    if (cn->else_body >= 0 &&
                        sc_seq_only_ret_const(sc, cn->then_body, &tv) &&
                        sc_seq_only_ret_const(sc, cn->else_body, &fv) &&
                        ((tv == 1 && fv == 0) || (tv == 0 && fv == 1))) {
                        int re = (tv == 1) ? cn->cond_expr : hl_expr_invert(sc->fn, cn->cond_expr);
                        int rn = sc_node_new(sc, SCN_RET, cn->va);
                        if (rn >= 0) {
                            sc->nodes[rn].cond_expr = re;
                            sc_seq_replace(sc, nid, c, rn);
                            changed = 1;
                            dead_after_term = 1;
                            c = sc->nodes[rn].next;
                            continue;
                        }
                    }
                    // collapse: if (c) { return 1; } return 0; -> return c;
                    if (cn->else_body < 0 && nxt >= 0 &&
                        sc_seq_only_ret_const(sc, cn->then_body, &tv) &&
                        sc_match_ret_const(sc, nxt, &fv) &&
                        ((tv == 1 && fv == 0) || (tv == 0 && fv == 1))) {
                        int re = (tv == 1) ? cn->cond_expr : hl_expr_invert(sc->fn, cn->cond_expr);
                        int after_nxt = sc->nodes[nxt].next;
                        int rn = sc_node_new(sc, SCN_RET, cn->va);
                        if (rn >= 0) {
                            sc->nodes[rn].cond_expr = re;
                            sc_seq_remove(sc, nid, nxt);
                            sc_seq_replace(sc, nid, c, rn);
                            changed = 1;
                            dead_after_term = 1;
                            c = after_nxt;
                            continue;
                        }
                    }
                }

                if (sc_node_terminates(sc, c)) dead_after_term = 1;
                c = sc->nodes[c].next;
            }
            break;
        }
        case SCN_IF: {
            changed |= sc_opt_ast_rec(sc, n->then_body);
            changed |= sc_opt_ast_rec(sc, n->else_body);
            n = &sc->nodes[nid];
            if (n->else_body >= 0 && sc_seq_is_empty(sc, n->else_body)) {
                n->else_body = -1;
                changed = 1;
            }
            if (sc_seq_is_empty(sc, n->then_body) && n->else_body >= 0 && !sc_seq_is_empty(sc, n->else_body)) {
                if (n->cond_expr >= 0) n->cond_expr = hl_expr_invert(sc->fn, n->cond_expr);
                n->then_body = n->else_body;
                n->else_body = -1;
                changed = 1;
            }
            // flatten if (a) { if (b) { X } } -> if (a && b) { X }
            if (n->else_body < 0 && n->then_body >= 0 && n->cond_expr >= 0) {
                int only = sc->nodes[n->then_body].first;
                if (only >= 0 && sc->nodes[only].next < 0 && sc->nodes[only].kind == SCN_IF &&
                    sc->nodes[only].else_body < 0 && sc->nodes[only].cond_expr >= 0) {
                    n->cond_expr = hl_expr_binop(sc->fn, HLB_LAND, n->cond_expr, sc->nodes[only].cond_expr, 1);
                    n->then_body = sc->nodes[only].then_body;
                    changed = 1;
                }
            }
            break;
        }
        case SCN_WHILE:
        case SCN_DO_WHILE:
        case SCN_FOR: {
            changed |= sc_opt_ast_rec(sc, n->then_body);
            n = &sc->nodes[nid];
            if (n->then_body >= 0) {
                int last = sc->nodes[n->then_body].last;
                if (last >= 0 && sc->nodes[last].kind == SCN_CONTINUE) {
                    sc_seq_remove(sc, n->then_body, last);
                    changed = 1;
                }
            }
            // while (1) { if (c) { break; } ... } -> while (!c) { ... }
            if (n->kind == SCN_WHILE && n->cond_expr < 0 && n->then_body >= 0) {
                int first = sc->nodes[n->then_body].first;
                if (first >= 0 && sc->nodes[first].kind == SCN_IF &&
                    sc->nodes[first].else_body < 0 && sc->nodes[first].cond_expr >= 0) {
                    int tb = sc->nodes[first].then_body;
                    if (tb >= 0) {
                        int tf = sc->nodes[tb].first;
                        if (tf >= 0 && sc->nodes[tf].next < 0 && sc->nodes[tf].kind == SCN_BREAK) {
                            n->cond_expr = hl_expr_invert(sc->fn, sc->nodes[first].cond_expr);
                            sc_seq_remove(sc, n->then_body, first);
                            changed = 1;
                        }
                    }
                }
            }
            break;
        }
        case SCN_SWITCH: {
            int cf = n->case_first;
            int nc = n->ncase;
            for (int i = 0; i < nc; i++) {
                changed |= sc_opt_ast_rec(sc, sc->cases[cf + i].body);
            }
            break;
        }
        default:
            break;
    }
    return changed;
}

static void sc_optimize_ast(sc_ctx *sc, int root) {
    sc_prune_unused_labels(sc, root);
    for (int pass = 0; pass < 6; pass++) {
        int ch = sc_opt_ast_rec(sc, root);
        ch |= sc_prune_unused_labels(sc, root);
        if (!ch) break;
    }
}

// --- collect variables referenced in final AST ---

static void sc_mark_expr_vars(sc_ctx *sc, int eid, int depth) {
    const hl_fn *fn = sc->fn;
    if (!fn || eid < 0 || eid >= fn->nexpr || depth > 32) return;
    const hl_expr *e = &fn->exprs[eid];
    if (e->kind == HLE_VAR) {
        int cv = sc_canon_var(fn, e->var_id);
        if (cv >= 0 && cv < sc->var_used_cap) sc->var_used[cv] = 1;
    }
    if (e->sub0 >= 0) sc_mark_expr_vars(sc, e->sub0, depth + 1);
    if (e->sub1 >= 0) sc_mark_expr_vars(sc, e->sub1, depth + 1);
    if (e->sub2 >= 0) sc_mark_expr_vars(sc, e->sub2, depth + 1);
    if (e->kind == HLE_CALL) {
        int na = (e->narg > HL_MAX_CALL_ARG) ? HL_MAX_CALL_ARG : (int)e->narg;
        for (int i = 0; i < na; i++) {
            if (e->args[i] >= 0) sc_mark_expr_vars(sc, e->args[i], depth + 1);
        }
    }
}

static void sc_mark_stmt_vars(sc_ctx *sc, int sid) {
    const hl_fn *fn = sc->fn;
    if (!fn || sid < 0 || sid >= fn->nstmt) return;
    const hl_stmt *s = &fn->stmts[sid];
    if (s->dst_var >= 0) {
        int dv = sc_canon_var(fn, s->dst_var);
        if (dv >= 0 && dv < sc->var_used_cap && !fn->vars[dv].is_dead && !fn->vars[dv].is_canary) {
            sc->var_used[dv] = 1;
        }
    }
    if (s->lhs_expr >= 0) sc_mark_expr_vars(sc, s->lhs_expr, 0);
    if (s->rhs_expr >= 0) sc_mark_expr_vars(sc, s->rhs_expr, 0);
    if (s->len_expr >= 0) sc_mark_expr_vars(sc, s->len_expr, 0);
}

static void sc_collect_ast_vars(sc_ctx *sc, int nid) {
    if (nid < 0) return;
    const sc_node *n = &sc->nodes[nid];
    switch (n->kind) {
        case SCN_SEQ:
            for (int c = n->first; c >= 0; c = sc->nodes[c].next) sc_collect_ast_vars(sc, c);
            break;
        case SCN_STMT:
            sc_mark_stmt_vars(sc, n->stmt_id);
            break;
        case SCN_RET:
            sc_mark_expr_vars(sc, n->cond_expr, 0);
            break;
        case SCN_IF:
            sc_mark_expr_vars(sc, n->cond_expr, 0);
            sc_collect_ast_vars(sc, n->then_body);
            sc_collect_ast_vars(sc, n->else_body);
            break;
        case SCN_WHILE:
        case SCN_DO_WHILE:
            sc_mark_expr_vars(sc, n->cond_expr, 0);
            sc_collect_ast_vars(sc, n->then_body);
            break;
        case SCN_FOR:
            sc_mark_stmt_vars(sc, n->for_init_stmt);
            sc_mark_expr_vars(sc, n->cond_expr, 0);
            sc_mark_stmt_vars(sc, n->for_step_stmt);
            sc_collect_ast_vars(sc, n->then_body);
            break;
        case SCN_SWITCH:
            sc_mark_expr_vars(sc, n->sw_expr, 0);
            for (int i = 0; i < n->ncase; i++) {
                sc_collect_ast_vars(sc, sc->cases[n->case_first + i].body);
            }
            break;
        default:
            break;
    }
}

// --- C pretty-printer ---

static int sc_is_bitset_char(int64_t ch) {
    return ch == '\t' || ch == '\n' || ch == '\r' || (ch >= 0x20 && ch <= 0x7E);
}

static void sc_fmt_char_lit(sc_buf *sb, int ch) {
    if (ch == '\0') sb_puts(sb, "'\\0'");
    else if (ch == '\t') sb_puts(sb, "'\\t'");
    else if (ch == '\n') sb_puts(sb, "'\\n'");
    else if (ch == '\r') sb_puts(sb, "'\\r'");
    else if (ch == '\'') sb_puts(sb, "'\\''");
    else if (ch == '\\') sb_puts(sb, "'\\\\'");
    else if (ch >= 0x20 && ch <= 0x7E) sb_printf(sb, "'%c'", (char)ch);
    else sb_printf(sb, "0x%x", ch & 0xFF);
}

static int sc_bitset_printable(const hl_expr *e, int64_t out_chars[6]) {
    int cnt = 0;
    for (int k = 0; k < 64; k++) {
        if ((e->uval >> k) & 1ULL) {
            if (cnt >= 6) return 0;
            int64_t ch = e->disp + (int64_t)k;
            if (!sc_is_bitset_char(ch)) return 0;
            out_chars[cnt++] = ch;
        }
    }
    return cnt;
}

static int sc_binop_prec(uint8_t op, int *nonassoc_rhs) {
    *nonassoc_rhs = 0;
    switch (op) {
        case HLB_LOR:   return 3;
        case HLB_LAND:  return 4;
        case HLB_OR:    return 5;
        case HLB_XOR:   return 6;
        case HLB_AND:   return 7;
        case HLB_EQ:
        case HLB_NE:    *nonassoc_rhs = 1; return 8;
        case HLB_SLT:
        case HLB_SLE:
        case HLB_SGT:
        case HLB_SGE:
        case HLB_ULT:
        case HLB_ULE:
        case HLB_UGT:
        case HLB_UGE:   *nonassoc_rhs = 1; return 9;
        case HLB_SHL:
        case HLB_SHR:
        case HLB_SAR:   *nonassoc_rhs = 1; return 10;
        case HLB_ADD:
        case HLB_FADD:  return 11;
        case HLB_SUB:
        case HLB_FSUB:  *nonassoc_rhs = 1; return 11;
        case HLB_MUL:
        case HLB_FMUL:  return 12;
        case HLB_SDIV:
        case HLB_UDIV:
        case HLB_SMOD:
        case HLB_UMOD:
        case HLB_FDIV:  *nonassoc_rhs = 1; return 12;
        case HLB_ROL:
        case HLB_ROR:
        case HLB_MIN:
        case HLB_MAX:   return 14;
        default:        return 11;
    }
}

static const char *sc_binop_str(uint8_t op) {
    switch (op) {
        case HLB_ADD:
        case HLB_FADD:  return "+";
        case HLB_SUB:
        case HLB_FSUB:  return "-";
        case HLB_MUL:
        case HLB_FMUL:  return "*";
        case HLB_SDIV:
        case HLB_UDIV:
        case HLB_FDIV:  return "/";
        case HLB_SMOD:
        case HLB_UMOD:  return "%";
        case HLB_AND:   return "&";
        case HLB_OR:    return "|";
        case HLB_XOR:   return "^";
        case HLB_SHL:   return "<<";
        case HLB_SHR:
        case HLB_SAR:   return ">>";
        case HLB_EQ:    return "==";
        case HLB_NE:    return "!=";
        case HLB_SLT:
        case HLB_ULT:   return "<";
        case HLB_SLE:
        case HLB_ULE:   return "<=";
        case HLB_SGT:
        case HLB_UGT:   return ">";
        case HLB_SGE:
        case HLB_UGE:   return ">=";
        case HLB_LAND:  return "&&";
        case HLB_LOR:   return "||";
        default:        return "+";
    }
}

static uint8_t sc_inv_cmp_op(uint8_t op) {
    switch (op) {
        case HLB_EQ:  return HLB_NE;
        case HLB_NE:  return HLB_EQ;
        case HLB_SLT: return HLB_SGE;
        case HLB_SLE: return HLB_SGT;
        case HLB_SGT: return HLB_SLE;
        case HLB_SGE: return HLB_SLT;
        case HLB_ULT: return HLB_UGE;
        case HLB_ULE: return HLB_UGT;
        case HLB_UGT: return HLB_ULE;
        case HLB_UGE: return HLB_ULT;
        default:      return 0;
    }
}

static int sc_match_mulhi_expr(const hl_fn *fn, uint8_t op, int sub0, int sub1, int e_bits,
                               int *out_lhs, int *out_rhs, int *out_is64, int *out_signed, int *out_extra) {
    if (!fn || (op != HLB_SHR && op != HLB_SAR)) return 0;
    if (sub0 < 0 || sub0 >= fn->nexpr || sub1 < 0 || sub1 >= fn->nexpr) return 0;
    const hl_expr *ml = &fn->exprs[sub0];
    const hl_expr *sh = &fn->exprs[sub1];
    if (ml->kind != HLE_BINOP || ml->op != HLB_MUL) return 0;
    if (sh->kind != HLE_INT) return 0;
    uint64_t s_amt = sh->uval;
    if (ml->bits == 128 && s_amt >= 64 && s_amt < 128) {
        *out_lhs = ml->sub0;
        *out_rhs = ml->sub1;
        *out_is64 = 1;
        *out_signed = (op == HLB_SAR || ml->is_signed) ? 1 : 0;
        *out_extra = (int)(s_amt - 64);
        return 1;
    }
    if (ml->bits == 64 && e_bits > 0 && e_bits <= 32 && s_amt >= 32 && s_amt < 64) {
        *out_lhs = ml->sub0;
        *out_rhs = ml->sub1;
        *out_is64 = 0;
        *out_signed = (op == HLB_SAR || ml->is_signed) ? 1 : 0;
        *out_extra = (int)(s_amt - 32);
        return 1;
    }
    return 0;
}

static int sc_expr_prec(const hl_fn *fn, int eid) {
    if (!fn || eid < 0 || eid >= fn->nexpr) return 14;
    const hl_expr *e = &fn->exprs[eid];
    switch (e->kind) {
        case HLE_INT:
        case HLE_FLT:
        case HLE_STR:
        case HLE_SYM:
        case HLE_VAR:
        case HLE_CALL:
        case HLE_FIELD:
        case HLE_INDEX:
            return 14;
        case HLE_ADDR:
        case HLE_DEREF:
            return 13;
        case HLE_UNOP:
            if (e->op == HLU_FABS || e->op == HLU_BSWAP || e->op == HLU_POPCNT ||
                e->op == HLU_CLZ || e->op == HLU_CTZ || e->op == HLU_ABS) {
                return 14;
            }
            if (e->op == HLU_LOGNOT && e->sub0 >= 0 && e->sub0 < fn->nexpr) {
                const hl_expr *sub = &fn->exprs[e->sub0];
                if (sub->kind == HLE_BINOP && !sub->is_flt && sc_inv_cmp_op(sub->op)) {
                    int na = 0;
                    return sc_binop_prec(sc_inv_cmp_op(sub->op), &na);
                }
                if (sub->kind == HLE_BITSET) {
                    int64_t chs[6];
                    int nch = sc_bitset_printable(sub, chs);
                    if (nch == 1) return 8;
                    if (nch > 1) return 4;
                }
            }
            return 13;
        case HLE_BINOP: {
            int l = 0, r = 0, is64 = 0, sgn = 0, ex = 0;
            if (sc_match_mulhi_expr(fn, e->op, e->sub0, e->sub1, e->bits, &l, &r, &is64, &sgn, &ex)) {
                return 14;
            }
            int na = 0;
            return sc_binop_prec(e->op, &na);
        }
        case HLE_TERNARY:
            return 2;
        case HLE_BITSET: {
            int64_t chs[6];
            int nch = sc_bitset_printable(e, chs);
            if (nch == 1) return 8;
            if (nch > 1) return 3;
            return 7;
        }
        default:
            return 14;
    }
}

static void sc_fmt_int_val(sc_buf *sb, uint64_t uval, int bits, int is_signed, const hl_type *ty) {
    if (ty && ty->kind == HL_TY_CHAR && ty->ptr_depth == 0 && uval <= 0x7E) {
        if (uval == 0 || uval == '\t' || uval == '\n' || uval == '\r' ||
            (uval >= 0x20 && uval <= 0x7E)) {
            sc_fmt_char_lit(sb, (int)uval);
            return;
        }
    }
    if (ty && (ty->kind == HL_TY_PTR || ty->ptr_depth > 0) && uval == 0) {
        sb_puts(sb, "NULL");
        return;
    }
    int sgn = is_signed || sc_ty_is_signed(ty);
    if (sgn) {
        int64_t sv = sc_sext_int(uval, bits ? bits : 64);
        if (sv < 0 && sv > -0x10000) {
            sb_printf(sb, "%lld", (long long)sv);
            return;
        }
        if (sv >= 0 && sv < 16) {
            sb_printf(sb, "%lld", (long long)sv);
            return;
        }
    }
    uint64_t mv = uval;
    if (bits == 8) mv &= 0xFFULL;
    else if (bits == 16) mv &= 0xFFFFULL;
    else if (bits == 32) mv &= 0xFFFFFFFFULL;
    if (mv < 16) sb_printf(sb, "%llu", (unsigned long long)mv);
    else sb_printf(sb, "0x%llx", (unsigned long long)mv);
}

static void sc_fmt_str_lit(const hl_fn *fn, const hl_expr *e, sc_buf *sb) {
    char raw[72];
    raw[0] = 0;
    int wide = e->is_wide ? 1 : 0;

    if (fn && fn->a && e->va) {
        const ana_str *st = ana_str_at(fn->a, e->va);
        if (st) {
            ana_read_str(fn->a, st, raw, sizeof(raw));
            wide = st->wide ? 1 : wide;
        } else if (wide) {
            uint16_t wbuf[64];
            size_t got = bin_read(&fn->a->bin, e->va, (uint8_t *)wbuf, sizeof(wbuf));
            size_t n = 0;
            for (size_t i = 0; i * 2 + 1 < got && n + 1 < sizeof(raw); i++) {
                if (wbuf[i] == 0) break;
                raw[n++] = (wbuf[i] <= 0x7E) ? (char)wbuf[i] : '?';
            }
            raw[n] = 0;
        } else {
            size_t got = bin_read(&fn->a->bin, e->va, (uint8_t *)raw, sizeof(raw) - 1);
            raw[got] = 0;
            for (size_t i = 0; i < got; i++) {
                if (raw[i] == 0) break;
            }
        }
    }
    if (!raw[0] && e->sym[0]) {
        snprintf(raw, sizeof(raw), "%s", e->sym);
    }

    if (wide) sb_putc(sb, 'L');
    sb_putc(sb, '"');
    for (size_t i = 0; raw[i] && i < 60; i++) {
        unsigned char c = (unsigned char)raw[i];
        if (c == '\n') sb_puts(sb, "\\n");
        else if (c == '\r') sb_puts(sb, "\\r");
        else if (c == '\t') sb_puts(sb, "\\t");
        else if (c == '"') sb_puts(sb, "\\\"");
        else if (c == '\\') sb_puts(sb, "\\\\");
        else if (c >= 0x20 && c <= 0x7E) sb_putc(sb, (char)c);
        else sb_printf(sb, "\\x%02x", c);
    }
    sb_putc(sb, '"');
}

static void sc_fmt_expr(const sc_ctx *sc, int eid, int min_prec, sc_buf *sb, int depth);

static int sc_ctype_is_unsigned(const char *tstr, int bits) {
    if (!tstr || !tstr[0]) return 0;
    if (bits == 0 || bits == 8) {
        if (strcmp(tstr, "uint8_t") == 0 || strcmp(tstr, "unsigned char") == 0 ||
            strcmp(tstr, "BYTE") == 0 || strcmp(tstr, "UCHAR") == 0 ||
            strcmp(tstr, "UINT8") == 0 || strcmp(tstr, "bool") == 0) return 1;
    }
    if (bits == 0 || bits == 16) {
        if (strcmp(tstr, "uint16_t") == 0 || strcmp(tstr, "unsigned short") == 0 ||
            strcmp(tstr, "WORD") == 0 || strcmp(tstr, "USHORT") == 0 ||
            strcmp(tstr, "UINT16") == 0 || strcmp(tstr, "wchar_t") == 0 ||
            strcmp(tstr, "WCHAR") == 0) return 1;
    }
    if (bits == 0 || bits == 32) {
        if (strcmp(tstr, "uint32_t") == 0 || strcmp(tstr, "unsigned int") == 0 ||
            strcmp(tstr, "unsigned") == 0 || strcmp(tstr, "DWORD") == 0 ||
            strcmp(tstr, "ULONG") == 0 || strcmp(tstr, "UINT") == 0 ||
            strcmp(tstr, "UINT32") == 0) return 1;
    }
    if (bits == 0 || bits == 64) {
        if (strcmp(tstr, "uint64_t") == 0 || strcmp(tstr, "unsigned long long") == 0 ||
            strcmp(tstr, "size_t") == 0 || strcmp(tstr, "ULONG64") == 0 ||
            strcmp(tstr, "ULONGLONG") == 0 || strcmp(tstr, "UINT64") == 0 ||
            strcmp(tstr, "uintptr_t") == 0 || strcmp(tstr, "DWORD64") == 0) return 1;
    }
    return 0;
}

static int sc_expr_is_unsigned(const hl_fn *fn, int eid, int bits) {
    if (!fn || eid < 0 || eid >= fn->nexpr) return 0;
    const hl_expr *e = &fn->exprs[eid];
    if (e->kind == HLE_VAR) {
        char vt[48] = "";
        sc_var_resolve(fn, e->var_id, NULL, 0, NULL, 0, vt, sizeof(vt));
        return sc_ctype_is_unsigned(vt, bits);
    }
    if (e->kind == HLE_UNOP && (e->op == HLU_ZEXT || e->op == HLU_CAST)) {
        char tbuf[48] = "";
        if (e->ty.kind != HL_TY_UNK || e->ty.ptr_depth > 0) {
            hl_type_fmt(&e->ty, tbuf, sizeof(tbuf));
            if (tbuf[0]) return sc_ctype_is_unsigned(tbuf, bits);
        }
        if (e->op == HLU_ZEXT) {
            int eb = e->bits ? e->bits : fn->ptr_bits;
            return (bits == 0 || eb == bits);
        }
        return 0;
    }
    if (e->kind == HLE_BINOP) {
        int l = 0, r = 0, is64 = 0, sgn = 0, ex = 0;
        if (sc_match_mulhi_expr(fn, e->op, e->sub0, e->sub1, e->bits, &l, &r, &is64, &sgn, &ex)) {
            int mb = is64 ? 64 : 32;
            return !sgn && (bits == 0 || bits == mb);
        }
        if (e->op == HLB_UDIV || e->op == HLB_UMOD || e->op == HLB_SHR) {
            int eb = e->bits ? e->bits : fn->ptr_bits;
            return (bits == 0 || eb == bits);
        }
        return 0;
    }
    if (e->kind == HLE_DEREF && e->ty.ptr_depth == 0) {
        if (bits == 8 && (e->ty.kind == HL_TY_U8 || e->ty.kind == HL_TY_BOOL)) return 1;
        if (bits == 16 && (e->ty.kind == HL_TY_U16 || e->ty.kind == HL_TY_WCHAR)) return 1;
        if (bits == 32 && e->ty.kind == HL_TY_U32) return 1;
        if (bits == 64 && (e->ty.kind == HL_TY_U64 || e->ty.kind == HL_TY_SIZE_T)) return 1;
    }
    return 0;
}

static const char *sc_utype_name(int bits) {
    if (bits == 8) return "uint8_t";
    if (bits == 16) return "uint16_t";
    if (bits == 32) return "uint32_t";
    return "uint64_t";
}

static void sc_fmt_expr_unsigned(const sc_ctx *sc, int eid, int min_prec, int op_bits,
                                 sc_buf *sb, int depth, int force_cast_int) {
    const hl_fn *fn = sc->fn;
    if (!fn || eid < 0 || eid >= fn->nexpr) {
        sb_puts(sb, "0");
        return;
    }
    const hl_expr *e = &fn->exprs[eid];
    if (e->kind == HLE_INT) {
        if (force_cast_int) sb_printf(sb, "(%s)", sc_utype_name(op_bits));
        const hl_type *cty = (e->ty.kind == HL_TY_CHAR && e->ty.ptr_depth == 0) ? &e->ty : NULL;
        sc_fmt_int_val(sb, e->uval, op_bits, 0, cty);
        return;
    }
    if (!sc_expr_is_unsigned(fn, eid, op_bits)) {
        sb_printf(sb, "(%s)", sc_utype_name(op_bits));
        sc_fmt_expr(sc, eid, 13, sb, depth + 1);
        return;
    }
    sc_fmt_expr(sc, eid, min_prec, sb, depth + 1);
}

static void sc_fmt_mulhi_operand(const sc_ctx *sc, int eid, int mul_bits, int is_s, sc_buf *sb, int depth) {
    const hl_fn *fn = sc->fn;
    if (eid >= 0 && eid < fn->nexpr && fn->exprs[eid].kind == HLE_INT && !is_s) {
        sc_fmt_int_val(sb, fn->exprs[eid].uval, mul_bits, 0, NULL);
        return;
    }
    sc_fmt_expr(sc, eid, 13, sb, depth + 1);
}

static int sc_fmt_mulhi(const sc_ctx *sc, uint8_t op, int sub0, int sub1, int e_bits, sc_buf *sb, int depth) {
    const hl_fn *fn = sc->fn;
    int lhs = -1, rhs = -1, is64 = 0, is_s = 0, extra = 0;
    if (!sc_match_mulhi_expr(fn, op, sub0, sub1, e_bits, &lhs, &rhs, &is64, &is_s, &extra)) return 0;

    const hl_expr *wmul = &fn->exprs[sub0];
    int s_signed = (op == HLB_SAR || wmul->is_signed) ? 1 : 0;
    const char *wide_t = is64 ? (s_signed ? "__int128" : "unsigned __int128")
                              : (s_signed ? "int64_t" : "uint64_t");
    const char *nar_t  = is64 ? (s_signed ? "int64_t" : "uint64_t")
                              : (s_signed ? "int32_t" : "uint32_t");
    int mul_bits = is64 ? 64 : 32;
    int sh_amt   = is64 ? 64 : 32;

    if (extra > 0) sb_putc(sb, '(');
    if (extra > 0 && op == HLB_SHR && s_signed) {
        sb_printf(sb, "(%s)", is64 ? "uint64_t" : "uint32_t");
    }
    sb_printf(sb, "((%s)(((%s)(%s)", nar_t, wide_t, nar_t);
    sc_fmt_mulhi_operand(sc, lhs, mul_bits, s_signed, sb, depth);
    sb_printf(sb, " * (%s)(%s)", wide_t, nar_t);
    sc_fmt_mulhi_operand(sc, rhs, mul_bits, s_signed, sb, depth);
    sb_printf(sb, ") >> %d))", sh_amt);
    if (extra > 0) sb_printf(sb, " >> %d)", extra);
    return 1;
}

static void sc_fmt_binop(const sc_ctx *sc, uint8_t op, int sub0, int sub1, int e_bits, sc_buf *sb, int depth) {
    const hl_fn *fn = sc->fn;
    if (sc_fmt_mulhi(sc, op, sub0, sub1, e_bits, sb, depth)) return;

    int nonassoc = 0;
    int bp = sc_binop_prec(op, &nonassoc);

    if (op == HLB_SHR) {
        int op_bits = e_bits ? e_bits : (fn->ptr_bits ? fn->ptr_bits : 64);
        sc_fmt_expr_unsigned(sc, sub0, bp, op_bits, sb, depth, 1);
        sb_puts(sb, " >> ");
        sc_fmt_expr(sc, sub1, nonassoc ? bp + 1 : bp, sb, depth + 1);
        return;
    }

    if (op == HLB_UDIV || op == HLB_UMOD || (op >= HLB_ULT && op <= HLB_UGE)) {
        int op_bits = 0;
        if (op == HLB_UDIV || op == HLB_UMOD) {
            op_bits = e_bits ? e_bits : (fn->ptr_bits ? fn->ptr_bits : 64);
        } else {
            int b0 = (sub0 >= 0 && sub0 < fn->nexpr) ? fn->exprs[sub0].bits : 0;
            int b1 = (sub1 >= 0 && sub1 < fn->nexpr) ? fn->exprs[sub1].bits : 0;
            op_bits = (b0 > b1) ? b0 : b1;
            if (op_bits <= 1) op_bits = fn->ptr_bits ? fn->ptr_bits : 64;
        }
        int both_int = (sub0 >= 0 && sub0 < fn->nexpr && fn->exprs[sub0].kind == HLE_INT) &&
                       (sub1 >= 0 && sub1 < fn->nexpr && fn->exprs[sub1].kind == HLE_INT);
        sc_fmt_expr_unsigned(sc, sub0, bp, op_bits, sb, depth, both_int);
        sb_printf(sb, " %s ", sc_binop_str(op));
        sc_fmt_expr_unsigned(sc, sub1, nonassoc ? bp + 1 : bp, op_bits, sb, depth, 0);
        return;
    }

    sc_fmt_expr(sc, sub0, bp, sb, depth + 1);
    sb_printf(sb, " %s ", sc_binop_str(op));
    sc_fmt_expr(sc, sub1, nonassoc ? bp + 1 : bp, sb, depth + 1);
}

static void sc_fmt_expr(const sc_ctx *sc, int eid, int min_prec, sc_buf *sb, int depth) {
    const hl_fn *fn = sc->fn;
    if (!fn || eid < 0 || eid >= fn->nexpr) {
        sb_puts(sb, "0");
        return;
    }
    if (depth > 32) {
        sb_puts(sb, "...");
        return;
    }

    const hl_expr *e = &fn->exprs[eid];

    // simplify &(*x) -> x and *(&x) -> x
    if (e->kind == HLE_ADDR && e->sub0 >= 0 && e->sub0 < fn->nexpr &&
        fn->exprs[e->sub0].kind == HLE_DEREF && fn->exprs[e->sub0].disp == 0 &&
        fn->exprs[e->sub0].sub0 >= 0) {
        sc_fmt_expr(sc, fn->exprs[e->sub0].sub0, min_prec, sb, depth + 1);
        return;
    }
    if (e->kind == HLE_DEREF && e->disp == 0 && e->sub0 >= 0 && e->sub0 < fn->nexpr &&
        fn->exprs[e->sub0].kind == HLE_ADDR && fn->exprs[e->sub0].sub0 >= 0) {
        sc_fmt_expr(sc, fn->exprs[e->sub0].sub0, min_prec, sb, depth + 1);
        return;
    }

    int prec = sc_expr_prec(fn, eid);
    int wrap = (prec < min_prec);
    if (wrap) sb_putc(sb, '(');

    switch (e->kind) {
        case HLE_INT:
            sc_fmt_int_val(sb, e->uval, e->bits, e->is_signed, &e->ty);
            break;

        case HLE_FLT: {
            char fbuf[48];
            snprintf(fbuf, sizeof(fbuf), "%.6g", e->fval);
            int has_dot = 0;
            for (const char *p = fbuf; *p; p++) {
                if (*p == '.' || *p == 'e' || *p == 'E' || *p == 'n' || *p == 'N' || *p == 'i' || *p == 'I') {
                    has_dot = 1;
                    break;
                }
            }
            sb_puts(sb, fbuf);
            if (!has_dot) sb_puts(sb, ".0");
            if ((e->bits == 32 || e->ty.kind == HL_TY_F32) && !strchr(fbuf, 'n') && !strchr(fbuf, 'i')) {
                sb_putc(sb, 'f');
            }
            break;
        }

        case HLE_STR:
            sc_fmt_str_lit(fn, e, sb);
            break;

        case HLE_SYM: {
            char clean[64];
            if (e->sym[0]) {
                sc_clean_sym(e->sym, clean, sizeof(clean));
                sb_puts(sb, clean);
            } else if (e->va) {
                const char *sym = fn->a ? ana_sym_at(fn->a, e->va) : NULL;
                if (sym) {
                    sc_clean_sym(sym, clean, sizeof(clean));
                    sb_puts(sb, clean);
                } else {
                    sb_printf(sb, "g_%llx", (unsigned long long)e->va);
                }
            } else {
                sb_puts(sb, "0");
            }
            break;
        }

        case HLE_VAR: {
            char nm[48];
            sc_var_resolve(fn, e->var_id, NULL, 0, nm, sizeof(nm), NULL, 0);
            sb_puts(sb, nm);
            break;
        }

        case HLE_ADDR:
            if (e->sub0 >= 0) {
                sb_putc(sb, '&');
                sc_fmt_expr(sc, e->sub0, 13, sb, depth + 1);
            } else if (e->sym[0]) {
                char clean[64];
                sc_clean_sym(e->sym, clean, sizeof(clean));
                sb_printf(sb, "&%s", clean);
            } else if (e->va) {
                const char *sym = fn->a ? ana_sym_at(fn->a, e->va) : NULL;
                if (sym) {
                    char clean[64];
                    sc_clean_sym(sym, clean, sizeof(clean));
                    sb_printf(sb, "&%s", clean);
                } else {
                    sb_printf(sb, "&g_%llx", (unsigned long long)e->va);
                }
            } else {
                sb_puts(sb, "NULL");
            }
            break;

        case HLE_DEREF: {
            if (e->sub0 < 0 && e->va) {
                const char *sym = fn->a ? ana_sym_at(fn->a, e->va) : NULL;
                if (sym) {
                    char clean[64];
                    sc_clean_sym(sym, clean, sizeof(clean));
                    sb_puts(sb, clean);
                } else {
                    char tbuf[48] = "";
                    if (e->ty.kind != HL_TY_UNK || e->ty.ptr_depth > 0) hl_type_fmt(&e->ty, tbuf, sizeof(tbuf));
                    if (!tbuf[0]) snprintf(tbuf, sizeof(tbuf), "%s", sc_fallback_ctype(e->bits ? e->bits : fn->ptr_bits, e->is_flt));
                    sb_printf(sb, "*(%s *)0x%llx", tbuf, (unsigned long long)e->va);
                }
                break;
            }
            // check whether sub0 already has matching concrete pointer type
            int typed_ok = 0;
            if (e->disp == 0 && e->sub0 >= 0 && e->sub0 < fn->nexpr) {
                hl_type pty = fn->exprs[e->sub0].ty;
                if (pty.ptr_depth == 0 && fn->exprs[e->sub0].kind == HLE_VAR) {
                    int cv = sc_canon_var(fn, fn->exprs[e->sub0].var_id);
                    if (cv >= 0) pty = fn->vars[cv].ty;
                }
                int pb = sc_ty_pointee_bits(&pty, fn->ptr_bits ? fn->ptr_bits : 64);
                if (pb > 0 && (e->bits == 0 || pb == (int)e->bits)) typed_ok = 1;
            }
            if (typed_ok) {
                sb_putc(sb, '*');
                sc_fmt_expr(sc, e->sub0, 13, sb, depth + 1);
            } else {
                char tbuf[48] = "";
                if (e->ty.kind != HL_TY_UNK || e->ty.ptr_depth > 0) hl_type_fmt(&e->ty, tbuf, sizeof(tbuf));
                if (!tbuf[0]) snprintf(tbuf, sizeof(tbuf), "%s", sc_fallback_ctype(e->bits ? e->bits : fn->ptr_bits, e->is_flt));
                sb_printf(sb, "*(%s", tbuf);
                size_t tl = strlen(tbuf);
                if (tl > 0 && tbuf[tl - 1] == '*') sb_puts(sb, "*)");
                else sb_puts(sb, " *)");
                if (e->disp != 0) {
                    sb_putc(sb, '(');
                    sc_fmt_expr(sc, e->sub0, 11, sb, depth + 1);
                    if (e->disp > 0) sb_printf(sb, " + 0x%llx)", (unsigned long long)e->disp);
                    else sb_printf(sb, " - 0x%llx)", (unsigned long long)(-e->disp));
                } else {
                    sc_fmt_expr(sc, e->sub0, 13, sb, depth + 1);
                }
            }
            break;
        }

        case HLE_FIELD:
            sc_fmt_expr(sc, e->sub0, 14, sb, depth + 1);
            sb_puts(sb, e->is_dot ? "." : "->");
            if (e->field[0]) sb_puts(sb, e->field);
            else sb_printf(sb, "field_%llx", (unsigned long long)(e->disp < 0 ? -e->disp : e->disp));
            break;

        case HLE_INDEX:
            sc_fmt_expr(sc, e->sub0, 14, sb, depth + 1);
            sb_putc(sb, '[');
            sc_fmt_expr(sc, e->sub1, 0, sb, depth + 1);
            if (e->disp != 0) {
                int64_t off = (e->scale > 1 && (e->disp % e->scale) == 0) ? (e->disp / e->scale) : e->disp;
                if (off > 0) sb_printf(sb, " + %lld", (long long)off);
                else if (off < 0) sb_printf(sb, " - %lld", (long long)(-off));
            }
            sb_putc(sb, ']');
            break;

        case HLE_UNOP:
            switch (e->op) {
                case HLU_NEG:
                case HLU_FNEG: {
                    int sub_min = 13;
                    if (e->sub0 >= 0 && e->sub0 < fn->nexpr) {
                        const hl_expr *se = &fn->exprs[e->sub0];
                        if ((se->kind == HLE_UNOP && (se->op == HLU_NEG || se->op == HLU_FNEG)) ||
                            (se->kind == HLE_INT && se->is_signed && sc_sext_int(se->uval, se->bits ? se->bits : 64) < 0)) {
                            sub_min = 14;
                        }
                    }
                    sb_putc(sb, '-');
                    sc_fmt_expr(sc, e->sub0, sub_min, sb, depth + 1);
                    break;
                }
                case HLU_BITNOT:
                    sb_putc(sb, '~');
                    sc_fmt_expr(sc, e->sub0, 13, sb, depth + 1);
                    break;
                case HLU_LOGNOT:
                    if (e->sub0 >= 0 && e->sub0 < fn->nexpr) {
                        const hl_expr *se = &fn->exprs[e->sub0];
                        if (se->kind == HLE_BINOP && !se->is_flt && sc_inv_cmp_op(se->op)) {
                            uint8_t iop = sc_inv_cmp_op(se->op);
                            sc_fmt_binop(sc, iop, se->sub0, se->sub1, se->bits, sb, depth);
                            break;
                        }
                        if (se->kind == HLE_BITSET) {
                            int64_t chs[6];
                            int nch = sc_bitset_printable(se, chs);
                            if (nch > 0) {
                                for (int i = 0; i < nch; i++) {
                                    if (i) sb_puts(sb, " && ");
                                    sc_fmt_expr(sc, se->sub0, 9, sb, depth + 1);
                                    sb_puts(sb, " != ");
                                    sc_fmt_char_lit(sb, (int)chs[i]);
                                }
                                break;
                            }
                        }
                    }
                    sb_putc(sb, '!');
                    sc_fmt_expr(sc, e->sub0, 13, sb, depth + 1);
                    break;
                case HLU_ZEXT:
                case HLU_SEXT:
                case HLU_CAST:
                case HLU_I2F:
                case HLU_F2I: {
                    char tbuf[48] = "";
                    if (e->ty.kind != HL_TY_UNK || e->ty.ptr_depth > 0) {
                        hl_type_fmt(&e->ty, tbuf, sizeof(tbuf));
                    }
                    if (!tbuf[0]) {
                        int b = e->bits ? e->bits : fn->ptr_bits;
                        if (e->op == HLU_I2F || e->is_flt) snprintf(tbuf, sizeof(tbuf), "%s", (b == 32) ? "float" : "double");
                        else if (e->op == HLU_ZEXT) {
                            if (b == 8) snprintf(tbuf, sizeof(tbuf), "uint8_t");
                            else if (b == 16) snprintf(tbuf, sizeof(tbuf), "uint16_t");
                            else if (b == 32) snprintf(tbuf, sizeof(tbuf), "uint32_t");
                            else snprintf(tbuf, sizeof(tbuf), "uint64_t");
                        } else if (e->op == HLU_SEXT || e->op == HLU_F2I || e->is_signed) {
                            if (b == 8) snprintf(tbuf, sizeof(tbuf), "int8_t");
                            else if (b == 16) snprintf(tbuf, sizeof(tbuf), "int16_t");
                            else if (b == 32) snprintf(tbuf, sizeof(tbuf), "int32_t");
                            else snprintf(tbuf, sizeof(tbuf), "int64_t");
                        } else {
                            snprintf(tbuf, sizeof(tbuf), "%s", sc_fallback_ctype(b, 0));
                        }
                    }
                    // elide cast when var already has the exact same C type
                    if (e->sub0 >= 0 && e->sub0 < fn->nexpr && fn->exprs[e->sub0].kind == HLE_VAR) {
                        char vt[48];
                        sc_var_resolve(fn, fn->exprs[e->sub0].var_id, NULL, 0, NULL, 0, vt, sizeof(vt));
                        if (strcmp(vt, tbuf) == 0) {
                            sc_fmt_expr(sc, e->sub0, min_prec, sb, depth + 1);
                            break;
                        }
                    }
                    sb_printf(sb, "(%s)", tbuf);
                    sc_fmt_expr(sc, e->sub0, 13, sb, depth + 1);
                    break;
                }
                case HLU_FABS:
                    sb_puts(sb, (e->bits == 32) ? "fabsf(" : "fabs(");
                    sc_fmt_expr(sc, e->sub0, 0, sb, depth + 1);
                    sb_putc(sb, ')');
                    break;
                case HLU_BSWAP:
                    sb_printf(sb, "bswap%d(", e->bits ? e->bits : 32);
                    sc_fmt_expr(sc, e->sub0, 0, sb, depth + 1);
                    sb_putc(sb, ')');
                    break;
                case HLU_POPCNT:
                    sb_puts(sb, "popcnt(");
                    sc_fmt_expr(sc, e->sub0, 0, sb, depth + 1);
                    sb_putc(sb, ')');
                    break;
                case HLU_CLZ:
                    sb_puts(sb, "clz(");
                    sc_fmt_expr(sc, e->sub0, 0, sb, depth + 1);
                    sb_putc(sb, ')');
                    break;
                case HLU_CTZ:
                    sb_puts(sb, "ctz(");
                    sc_fmt_expr(sc, e->sub0, 0, sb, depth + 1);
                    sb_putc(sb, ')');
                    break;
                case HLU_ABS:
                    sb_puts(sb, "abs(");
                    sc_fmt_expr(sc, e->sub0, 0, sb, depth + 1);
                    sb_putc(sb, ')');
                    break;
                default:
                    sc_fmt_expr(sc, e->sub0, min_prec, sb, depth + 1);
                    break;
            }
            break;

        case HLE_BINOP: {
            if (e->op == HLB_ROL || e->op == HLB_ROR || e->op == HLB_MIN || e->op == HLB_MAX) {
                const char *fnm = (e->op == HLB_ROL) ? "rol"
                                : (e->op == HLB_ROR) ? "ror"
                                : (e->op == HLB_MIN) ? "min" : "max";
                sb_printf(sb, "%s(", fnm);
                sc_fmt_expr(sc, e->sub0, 0, sb, depth + 1);
                sb_puts(sb, ", ");
                sc_fmt_expr(sc, e->sub1, 0, sb, depth + 1);
                sb_putc(sb, ')');
                break;
            }
            // normalize x + (-k) -> x - k and x - (-k) -> x + k
            if ((e->op == HLB_ADD || e->op == HLB_SUB) && e->sub1 >= 0 && e->sub1 < fn->nexpr) {
                const hl_expr *re = &fn->exprs[e->sub1];
                if (re->kind == HLE_INT && (re->is_signed || sc_ty_is_signed(&re->ty))) {
                    int64_t sv = sc_sext_int(re->uval, re->bits ? re->bits : 64);
                    if (sv == 0) {
                        sc_fmt_expr(sc, e->sub0, wrap ? 0 : min_prec, sb, depth + 1);
                        break;
                    }
                    if (sv < 0 && sv > -0x10000) {
                        uint8_t flipped = (e->op == HLB_ADD) ? HLB_SUB : HLB_ADD;
                        sc_fmt_expr(sc, e->sub0, 11, sb, depth + 1);
                        sb_printf(sb, " %s ", sc_binop_str(flipped));
                        sc_fmt_int_val(sb, (uint64_t)(-sv), re->bits, 0, &re->ty);
                        break;
                    }
                }
            }
            if (e->op == HLB_MUL && e->bits == 128) {
                sb_puts(sb, "((");
                sb_puts(sb, e->is_signed ? "__int128" : "unsigned __int128");
                sb_puts(sb, ")(");
                sb_puts(sb, e->is_signed ? "int64_t" : "uint64_t");
                sb_puts(sb, ")");
                sc_fmt_expr(sc, e->sub0, 13, sb, depth + 1);
                sb_puts(sb, " * (");
                sb_puts(sb, e->is_signed ? "__int128" : "unsigned __int128");
                sb_puts(sb, ")(");
                sb_puts(sb, e->is_signed ? "int64_t" : "uint64_t");
                sb_puts(sb, ")");
                sc_fmt_expr(sc, e->sub1, 13, sb, depth + 1);
                sb_putc(sb, ')');
                break;
            }
            sc_fmt_binop(sc, e->op, e->sub0, e->sub1, e->bits, sb, depth);
            break;
        }

        case HLE_TERNARY:
            sc_fmt_expr(sc, e->sub0, 3, sb, depth + 1);
            sb_puts(sb, " ? ");
            sc_fmt_expr(sc, e->sub1, 2, sb, depth + 1);
            sb_puts(sb, " : ");
            sc_fmt_expr(sc, e->sub2, 2, sb, depth + 1);
            break;

        case HLE_CALL: {
            if (e->sym[0]) {
                char clean[64];
                sc_clean_sym(e->sym, clean, sizeof(clean));
                sb_puts(sb, clean);
            } else if (e->sub0 >= 0) {
                const hl_expr *cal = (e->sub0 < fn->nexpr) ? &fn->exprs[e->sub0] : NULL;
                int simple = cal && (cal->kind == HLE_VAR || cal->kind == HLE_FIELD ||
                                     cal->kind == HLE_SYM || cal->kind == HLE_INDEX);
                if (!simple) sb_putc(sb, '(');
                sc_fmt_expr(sc, e->sub0, 14, sb, depth + 1);
                if (!simple) sb_putc(sb, ')');
            } else if (e->va) {
                const char *sym = fn->a ? ana_sym_at(fn->a, e->va) : NULL;
                if (sym) {
                    char clean[64];
                    sc_clean_sym(sym, clean, sizeof(clean));
                    sb_puts(sb, clean);
                } else {
                    sb_printf(sb, "sub_%llx", (unsigned long long)e->va);
                }
            } else {
                sb_puts(sb, "fn_unk");
            }
            sb_putc(sb, '(');
            int na = (e->narg > HL_MAX_CALL_ARG) ? HL_MAX_CALL_ARG : (int)e->narg;
            for (int i = 0; i < na; i++) {
                if (i) sb_puts(sb, ", ");
                sc_fmt_expr(sc, e->args[i], 0, sb, depth + 1);
            }
            sb_putc(sb, ')');
            break;
        }

        case HLE_BITSET: {
            int64_t chs[6];
            int nch = sc_bitset_printable(e, chs);
            if (nch > 0) {
                for (int i = 0; i < nch; i++) {
                    if (i) sb_puts(sb, " || ");
                    sc_fmt_expr(sc, e->sub0, 9, sb, depth + 1);
                    sb_puts(sb, " == ");
                    sc_fmt_char_lit(sb, (int)chs[i]);
                }
            } else if (e->uval == 0) {
                sb_puts(sb, "0");
            } else {
                sb_printf(sb, "((0x%llxULL >> ", (unsigned long long)e->uval);
                if (e->disp != 0) {
                    sb_putc(sb, '(');
                    sc_fmt_expr(sc, e->sub0, 11, sb, depth + 1);
                    if (e->disp > 0) sb_printf(sb, " - %lld)", (long long)e->disp);
                    else sb_printf(sb, " + %lld)", (long long)(-e->disp));
                } else {
                    sc_fmt_expr(sc, e->sub0, 11, sb, depth + 1);
                }
                sb_puts(sb, ") & 1)");
            }
            break;
        }

        default:
            sb_puts(sb, "0");
            break;
    }

    if (wrap) sb_putc(sb, ')');
}

static void sc_fmt_expr_str(const sc_ctx *sc, int eid, char *dst, size_t cap) {
    sc_buf sb;
    sb_init(&sb, dst, cap);
    if (eid < 0) sb_puts(&sb, "cond");
    else sc_fmt_expr(sc, eid, 0, &sb, 0);
}

static const char *sc_compound_op_str(uint8_t op) {
    switch (op) {
        case HLB_ADD:
        case HLB_FADD: return "+=";
        case HLB_SUB:
        case HLB_FSUB: return "-=";
        case HLB_MUL:
        case HLB_FMUL: return "*=";
        case HLB_AND:  return "&=";
        case HLB_OR:   return "|=";
        case HLB_XOR:  return "^=";
        case HLB_SHL:  return "<<=";
        case HLB_SHR:
        case HLB_SAR:  return ">>=";
        default:       return NULL;
    }
}

static int sc_is_const_one(const hl_fn *fn, int eid, int *is_neg_one) {
    *is_neg_one = 0;
    if (!fn || eid < 0 || eid >= fn->nexpr) return 0;
    const hl_expr *e = &fn->exprs[eid];
    if (e->kind != HLE_INT) return 0;
    if (e->uval == 1) return 1;
    if ((e->is_signed || sc_ty_is_signed(&e->ty)) &&
        sc_sext_int(e->uval, e->bits ? e->bits : 64) == -1) {
        *is_neg_one = 1;
        return 1;
    }
    return 0;
}

static int sc_fmt_stmt_body(const sc_ctx *sc, int sid, char *dst, size_t cap) {
    const hl_fn *fn = sc->fn;
    sc_buf sb;
    sb_init(&sb, dst, cap);
    if (!fn || sid < 0 || sid >= fn->nstmt) return 0;
    const hl_stmt *s = &fn->stmts[sid];

    switch (s->kind) {
        case HLS_ASSIGN: {
            int dv = sc_canon_var(fn, s->dst_var);
            if (dv >= 0 && (fn->vars[dv].is_dead || fn->vars[dv].is_canary)) {
                if (s->rhs_expr >= 0 && sc_expr_has_call(fn, s->rhs_expr, 0)) {
                    sc_fmt_expr(sc, s->rhs_expr, 0, &sb, 0);
                    return 1;
                }
                return 0;
            }
            char vname[48] = "";
            if (dv >= 0) sc_var_resolve(fn, dv, NULL, 0, vname, sizeof(vname), NULL, 0);

            // idiomatic v++, v--, v += x, v -= x, v |= x, v &= x, v ^= x
            if (dv >= 0 && s->rhs_expr >= 0 && s->rhs_expr < fn->nexpr) {
                const hl_expr *rhs = &fn->exprs[s->rhs_expr];
                if (rhs->kind == HLE_BINOP && rhs->sub0 >= 0 && rhs->sub1 >= 0 &&
                    rhs->sub0 < fn->nexpr && rhs->sub1 < fn->nexpr) {
                    const hl_expr *l = &fn->exprs[rhs->sub0];
                    const hl_expr *r = &fn->exprs[rhs->sub1];
                    int other = -1;
                    if (l->kind == HLE_VAR && sc_canon_var(fn, l->var_id) == dv) {
                        other = rhs->sub1;
                    } else if ((rhs->op == HLB_ADD || rhs->op == HLB_MUL ||
                                rhs->op == HLB_AND || rhs->op == HLB_OR || rhs->op == HLB_XOR ||
                                rhs->op == HLB_FADD || rhs->op == HLB_FMUL) &&
                               r->kind == HLE_VAR && sc_canon_var(fn, r->var_id) == dv) {
                        other = rhs->sub0;
                    }
                    if (other >= 0) {
                        int neg1 = 0;
                        if (rhs->op == HLB_ADD && sc_is_const_one(fn, other, &neg1)) {
                            sb_printf(&sb, "%s%s", vname, neg1 ? "--" : "++");
                            return 1;
                        }
                        if (rhs->op == HLB_SUB && sc_is_const_one(fn, other, &neg1)) {
                            sb_printf(&sb, "%s%s", vname, neg1 ? "++" : "--");
                            return 1;
                        }
                        // v = v + (-k) -> v -= k
                        if ((rhs->op == HLB_ADD || rhs->op == HLB_SUB) &&
                            fn->exprs[other].kind == HLE_INT &&
                            (fn->exprs[other].is_signed || sc_ty_is_signed(&fn->exprs[other].ty))) {
                            const hl_expr *oe = &fn->exprs[other];
                            int64_t sv = sc_sext_int(oe->uval, oe->bits ? oe->bits : 64);
                            if (sv < 0 && sv > -0x10000) {
                                sb_printf(&sb, "%s %s ", vname, (rhs->op == HLB_ADD) ? "-=" : "+=");
                                sc_fmt_int_val(&sb, (uint64_t)(-sv), oe->bits, 0, &oe->ty);
                                return 1;
                            }
                        }
                        const char *cop = sc_compound_op_str(rhs->op);
                        if (cop && rhs->op == HLB_SHR) {
                            char vt[48] = "";
                            int rb = rhs->bits ? rhs->bits : fn->ptr_bits;
                            sc_var_resolve(fn, dv, NULL, 0, NULL, 0, vt, sizeof(vt));
                            if (!sc_ctype_is_unsigned(vt, rb)) cop = NULL;
                        }
                        if (cop) {
                            sb_printf(&sb, "%s %s ", vname, cop);
                            sc_fmt_expr(sc, other, 0, &sb, 0);
                            return 1;
                        }
                    }
                }
            }

            if (dv >= 0) sb_puts(&sb, vname);
            else if (s->lhs_expr >= 0) sc_fmt_expr(sc, s->lhs_expr, 0, &sb, 0);
            else sb_puts(&sb, "v0");
            sb_puts(&sb, " = ");
            sc_fmt_expr(sc, s->rhs_expr, 0, &sb, 0);
            return 1;
        }

        case HLS_STORE:
            if (s->lhs_expr >= 0 && s->rhs_expr >= 0 && s->rhs_expr < fn->nexpr &&
                !sc_expr_has_call(fn, s->lhs_expr, 0)) {
                const hl_expr *rhs = &fn->exprs[s->rhs_expr];
                if (rhs->kind == HLE_BINOP && sc_expr_equal(fn, rhs->sub0, s->lhs_expr, 0)) {
                    int neg1 = 0;
                    if (rhs->op == HLB_ADD && sc_is_const_one(fn, rhs->sub1, &neg1)) {
                        sc_fmt_expr(sc, s->lhs_expr, 14, &sb, 0);
                        sb_puts(&sb, neg1 ? "--" : "++");
                        return 1;
                    }
                    if (rhs->op == HLB_SUB && sc_is_const_one(fn, rhs->sub1, &neg1)) {
                        sc_fmt_expr(sc, s->lhs_expr, 14, &sb, 0);
                        sb_puts(&sb, neg1 ? "++" : "--");
                        return 1;
                    }
                    const char *cop = sc_compound_op_str(rhs->op);
                    if (cop && rhs->op == HLB_SHR) {
                        int rb = rhs->bits ? rhs->bits : fn->ptr_bits;
                        if (!sc_expr_is_unsigned(fn, s->lhs_expr, rb)) cop = NULL;
                    }
                    if (cop) {
                        sc_fmt_expr(sc, s->lhs_expr, 0, &sb, 0);
                        sb_printf(&sb, " %s ", cop);
                        sc_fmt_expr(sc, rhs->sub1, 0, &sb, 0);
                        return 1;
                    }
                }
            }
            sc_fmt_expr(sc, s->lhs_expr, 0, &sb, 0);
            sb_puts(&sb, " = ");
            sc_fmt_expr(sc, s->rhs_expr, 0, &sb, 0);
            return 1;

        case HLS_CALL: {
            int ce = (s->rhs_expr >= 0) ? s->rhs_expr : s->lhs_expr;
            int dv = sc_canon_var(fn, s->dst_var);
            if (dv >= 0 && !fn->vars[dv].is_dead && !fn->vars[dv].is_canary && fn->vars[dv].use_cnt > 0) {
                char vname[48];
                sc_var_resolve(fn, dv, NULL, 0, vname, sizeof(vname), NULL, 0);
                sb_printf(&sb, "%s = ", vname);
            }
            sc_fmt_expr(sc, ce, 0, &sb, 0);
            return 1;
        }

        case HLS_RET:
            if (s->rhs_expr >= 0 && (fn->ret_ty.kind != HL_TY_VOID || fn->has_ret_val)) {
                sb_puts(&sb, "return ");
                sc_fmt_expr(sc, s->rhs_expr, 0, &sb, 0);
            } else {
                sb_puts(&sb, "return");
            }
            return 1;

        case HLS_MEMCPY:
            sb_puts(&sb, "memcpy(");
            sc_fmt_expr(sc, s->lhs_expr, 0, &sb, 0);
            sb_puts(&sb, ", ");
            sc_fmt_expr(sc, s->rhs_expr, 0, &sb, 0);
            sb_puts(&sb, ", ");
            sc_fmt_expr(sc, s->len_expr, 0, &sb, 0);
            sb_putc(&sb, ')');
            return 1;

        case HLS_MEMSET:
            sb_puts(&sb, "memset(");
            sc_fmt_expr(sc, s->lhs_expr, 0, &sb, 0);
            sb_puts(&sb, ", ");
            sc_fmt_expr(sc, s->rhs_expr, 0, &sb, 0);
            sb_puts(&sb, ", ");
            sc_fmt_expr(sc, s->len_expr, 0, &sb, 0);
            sb_putc(&sb, ')');
            return 1;

        default:
            return 0;
    }
}

// --- line emitter with inline user comments ---

static int sc_cmt_mark(sc_ctx *sc, uint64_t va) {
    for (int i = 0; i < sc->ncmt_seen; i++) {
        if (sc->cmt_seen[i] == va) return 0;
    }
    if (sc->ncmt_seen < SC_MAX_CMTS) sc->cmt_seen[sc->ncmt_seen++] = va;
    return 1;
}

static void sc_emit_line(sc_ctx *sc, uint64_t va, int indent, int allow_cmt, const char *fmt, ...) {
    dec_out *d = sc->out;
    if (d->nline == d->cap) {
        uint32_t nc = d->cap ? d->cap * 2 : 128;
        dec_line *nl = (dec_line *)realloc(d->lines, (size_t)nc * sizeof(dec_line));
        if (!nl) return;
        d->lines = nl;
        d->cap = nc;
    }
    dec_line *ln = &d->lines[d->nline++];
    ln->va = va;
    if (indent < 0) indent = 0;
    int pad = indent * 4;
    if (pad > 44) pad = 44;
    for (int i = 0; i < pad; i++) ln->text[i] = ' ';

    va_list ap;
    va_start(ap, fmt);
    vsnprintf(ln->text + pad, sizeof(ln->text) - (size_t)pad, fmt, ap);
    va_end(ap);

    if (allow_cmt && va != 0 && sc->fn && sc->fn->a) {
        const char *cmt = ana_cmt_at(sc->fn->a, va);
        if (cmt && cmt[0] && sc_cmt_mark(sc, va)) {
            size_t cur = strlen(ln->text);
            if (cur + 5 < sizeof(ln->text)) {
                snprintf(ln->text + cur, sizeof(ln->text) - cur, " // %s", cmt);
            }
        }
    }
}

// --- AST printer ---

static int sc_seq_single_if(const sc_ctx *sc, int seq_id) {
    if (seq_id < 0) return -1;
    int first = sc->nodes[seq_id].first;
    if (first < 0 || sc->nodes[first].next >= 0) return -1;
    return (sc->nodes[first].kind == SCN_IF) ? first : -1;
}

static void sc_print_seq(sc_ctx *sc, int seq_id, int indent);

static void sc_print_node(sc_ctx *sc, int nid, int indent) {
    if (nid < 0) return;
    const sc_node *n = &sc->nodes[nid];
    char buf[256];

    switch (n->kind) {
        case SCN_SEQ:
            sc_print_seq(sc, nid, indent);
            break;

        case SCN_STMT:
            if (sc_fmt_stmt_body(sc, n->stmt_id, buf, sizeof(buf))) {
                sc_emit_line(sc, n->va, indent, 1, "%s;", buf);
            }
            break;

        case SCN_RET:
            if (n->cond_expr >= 0 && (sc->fn->ret_ty.kind != HL_TY_VOID || sc->fn->has_ret_val)) {
                sc_fmt_expr_str(sc, n->cond_expr, buf, sizeof(buf));
                sc_emit_line(sc, n->va, indent, 1, "return %s;", buf);
            } else {
                sc_emit_line(sc, n->va, indent, 1, "return;");
            }
            break;

        case SCN_IF: {
            sc_fmt_expr_str(sc, n->cond_expr, buf, sizeof(buf));
            sc_emit_line(sc, n->va, indent, 1, "if (%s) {", buf);
            sc_print_seq(sc, n->then_body, indent + 1);
            int eb = n->else_body;
            while (eb >= 0) {
                int single_if = sc_seq_single_if(sc, eb);
                if (single_if >= 0) {
                    const sc_node *ein = &sc->nodes[single_if];
                    sc_fmt_expr_str(sc, ein->cond_expr, buf, sizeof(buf));
                    sc_emit_line(sc, ein->va, indent, 1, "} else if (%s) {", buf);
                    sc_print_seq(sc, ein->then_body, indent + 1);
                    eb = ein->else_body;
                } else {
                    sc_emit_line(sc, n->va, indent, 0, "} else {");
                    sc_print_seq(sc, eb, indent + 1);
                    eb = -1;
                }
            }
            sc_emit_line(sc, n->end_va ? n->end_va : n->va, indent, 0, "}");
            break;
        }

        case SCN_WHILE:
            if (n->cond_expr < 0) {
                sc_emit_line(sc, n->va, indent, 1, "while (1) {");
            } else {
                sc_fmt_expr_str(sc, n->cond_expr, buf, sizeof(buf));
                sc_emit_line(sc, n->va, indent, 1, "while (%s) {", buf);
            }
            sc_print_seq(sc, n->then_body, indent + 1);
            sc_emit_line(sc, n->end_va ? n->end_va : n->va, indent, 0, "}");
            break;

        case SCN_DO_WHILE:
            sc_emit_line(sc, n->va, indent, 0, "do {");
            sc_print_seq(sc, n->then_body, indent + 1);
            sc_fmt_expr_str(sc, n->cond_expr, buf, sizeof(buf));
            sc_emit_line(sc, n->end_va ? n->end_va : n->va, indent, 1, "} while (%s);", buf);
            break;

        case SCN_FOR: {
            char init_s[96] = "", cond_s[128] = "", step_s[96] = "";
            if (n->for_init_stmt >= 0) sc_fmt_stmt_body(sc, n->for_init_stmt, init_s, sizeof(init_s));
            if (n->cond_expr >= 0) sc_fmt_expr_str(sc, n->cond_expr, cond_s, sizeof(cond_s));
            if (n->for_step_stmt >= 0) sc_fmt_stmt_body(sc, n->for_step_stmt, step_s, sizeof(step_s));
            sc_emit_line(sc, n->va, indent, 1, "for (%s; %s; %s) {", init_s, cond_s, step_s);
            sc_print_seq(sc, n->then_body, indent + 1);
            sc_emit_line(sc, n->end_va ? n->end_va : n->va, indent, 0, "}");
            break;
        }

        case SCN_SWITCH: {
            if (n->sw_expr >= 0) sc_fmt_expr_str(sc, n->sw_expr, buf, sizeof(buf));
            else snprintf(buf, sizeof(buf), "v0");
            sc_emit_line(sc, n->va, indent, 1, "switch (%s) {", buf);
            for (int i = 0; i < n->ncase; i++) {
                const sc_case *c = &sc->cases[n->case_first + i];
                if (c->is_default) {
                    sc_emit_line(sc, c->va, indent, 0, "default:");
                } else {
                    sc_buf cb;
                    char cstr[32];
                    sb_init(&cb, cstr, sizeof(cstr));
                    if (c->is_char && c->val >= 0 && c->val <= 0x7E &&
                        (c->val == 0 || c->val == '\t' || c->val == '\n' || c->val == '\r' ||
                         (c->val >= 0x20 && c->val <= 0x7E))) {
                        sc_fmt_char_lit(&cb, (int)c->val);
                    } else if (c->val >= -256 && c->val <= 255) {
                        sb_printf(&cb, "%lld", (long long)c->val);
                    } else {
                        sb_printf(&cb, "0x%llx", (unsigned long long)c->val);
                    }
                    sc_emit_line(sc, c->va, indent, 0, "case %s:", cstr);
                }
                if (c->body >= 0) sc_print_seq(sc, c->body, indent + 1);
            }
            sc_emit_line(sc, n->end_va ? n->end_va : n->va, indent, 0, "}");
            break;
        }

        case SCN_BREAK:
            sc_emit_line(sc, n->va, indent, 1, "break;");
            break;

        case SCN_CONTINUE:
            sc_emit_line(sc, n->va, indent, 1, "continue;");
            break;

        case SCN_GOTO:
            sc_emit_line(sc, n->va, indent, 1, "goto loc_%llx;", (unsigned long long)n->target_va);
            break;

        case SCN_LABEL:
            sc_emit_line(sc, n->target_va, indent > 0 ? indent - 1 : 0, 0,
                         "loc_%llx:", (unsigned long long)n->target_va);
            break;

        case SCN_COMMENT:
            sc_emit_line(sc, n->va, indent, 0, "%s", n->comment);
            break;

        default:
            break;
    }
}

static void sc_print_seq(sc_ctx *sc, int seq_id, int indent) {
    if (seq_id < 0) return;
    for (int c = sc->nodes[seq_id].first; c >= 0; c = sc->nodes[c].next) {
        sc_print_node(sc, c, indent);
    }
}

// --- header, sorted variable declarations, and out->vars population ---

typedef struct {
    int     vid;
    int     is_arg;
    int     arg_idx;
    int     is_stack;
    int64_t stack_off;
    int     bits;
    char    orig[24];
    char    name[32];
    char    type[48];
} sc_var_entry;

static int sc_local_cmp(const void *pa, const void *pb) {
    const sc_var_entry *a = (const sc_var_entry *)pa;
    const sc_var_entry *b = (const sc_var_entry *)pb;
    if (a->is_stack != b->is_stack) return b->is_stack - a->is_stack;
    if (a->is_stack) {
        int64_t oa = a->stack_off < 0 ? -a->stack_off : a->stack_off;
        int64_t ob = b->stack_off < 0 ? -b->stack_off : b->stack_off;
        if (oa != ob) return (oa > ob) - (oa < ob);
        if (a->stack_off != b->stack_off) return (a->stack_off > b->stack_off) - (a->stack_off < b->stack_off);
    }
    return (a->vid > b->vid) - (a->vid < b->vid);
}

static void sc_emit_header_and_vars(sc_ctx *sc) {
    hl_fn *fn = sc->fn;
    dec_out *out = sc->out;
    uint64_t fva = fn->g ? fn->g->func_va : (fn->nblk > 0 ? fn->blks[0].start : 0);
    out->func_va = fva;

    // collect canonical arguments and live AST-referenced locals
    sc_var_entry args[16];
    int narg_found = 0;
    int max_arg_idx = -1;

    sc_var_entry *locals = NULL;
    int nlocal = 0, local_cap = 0;

    for (int i = 0; i < fn->nvar; i++) {
        if (sc_canon_var(fn, i) != i) continue;
        const hl_var *v = &fn->vars[i];
        if (v->is_dead || v->is_canary) continue;
        int used = (i < sc->var_used_cap && sc->var_used[i]);
        const ana_lvar *lv = sc_find_lvar(fn, v);

        if (v->is_arg && v->arg_idx >= 0 && v->arg_idx < 16) {
            if (used || v->use_cnt > 0 || lv != NULL) {
                if (v->arg_idx > max_arg_idx) max_arg_idx = v->arg_idx;
            }
            if (narg_found < 16) {
                sc_var_entry *e = &args[narg_found++];
                memset(e, 0, sizeof(*e));
                e->vid = i;
                e->is_arg = 1;
                e->arg_idx = v->arg_idx;
                e->bits = v->bits ? v->bits : (v->ty.bits ? (int)v->ty.bits : (fn->ptr_bits ? fn->ptr_bits : 64));
                sc_var_resolve(fn, i, e->orig, sizeof(e->orig), e->name, sizeof(e->name), e->type, sizeof(e->type));
            }
            continue;
        }

        if (!used) continue;
        if (nlocal == local_cap) {
            int nc = local_cap ? local_cap * 2 : 32;
            sc_var_entry *nl = (sc_var_entry *)realloc(locals, (size_t)nc * sizeof(sc_var_entry));
            if (!nl) continue;
            locals = nl;
            local_cap = nc;
        }
        sc_var_entry *e = &locals[nlocal++];
        memset(e, 0, sizeof(*e));
        e->vid = i;
        e->is_arg = 0;
        e->is_stack = v->is_stack ? 1 : 0;
        e->stack_off = v->is_stack ? v->stack_off : 0;
        e->bits = v->bits ? v->bits : (v->ty.bits ? (int)v->ty.bits : (fn->ptr_bits ? fn->ptr_bits : 64));
        sc_var_resolve(fn, i, e->orig, sizeof(e->orig), e->name, sizeof(e->name), e->type, sizeof(e->type));
    }

    if (nlocal > 1) qsort(locals, (size_t)nlocal, sizeof(sc_var_entry), sc_local_cmp);

    // order parameters 0 .. max_arg_idx
    sc_var_entry ordered_args[16];
    int nordered_args = 0;
    for (int idx = 0; idx <= max_arg_idx && idx < 16; idx++) {
        int found = -1;
        for (int k = 0; k < narg_found; k++) {
            if (args[k].arg_idx == idx) { found = k; break; }
        }
        sc_var_entry *dst = &ordered_args[nordered_args++];
        if (found >= 0) {
            *dst = args[found];
        } else {
            memset(dst, 0, sizeof(*dst));
            dst->vid = -1;
            dst->is_arg = 1;
            dst->arg_idx = idx;
            dst->bits = fn->ptr_bits ? fn->ptr_bits : 64;
            snprintf(dst->orig, sizeof(dst->orig), "a%d", idx + 1);
            snprintf(dst->name, sizeof(dst->name), "a%d", idx + 1);
            snprintf(dst->type, sizeof(dst->type), "%s", (dst->bits == 32) ? "int32_t" : "int64_t");
            // apply user lvar override even for placeholder args
            if (fn->a && fn->g) {
                for (uint32_t li = 0; li < fn->a->nlvar; li++) {
                    const ana_lvar *lv = &fn->a->lvars[li];
                    if (lv->func_va == fn->g->func_va && strcmp(lv->orig, dst->orig) == 0) {
                        if (lv->name[0]) snprintf(dst->name, sizeof(dst->name), "%s", lv->name);
                        if (lv->type[0]) snprintf(dst->type, sizeof(dst->type), "%s", lv->type);
                        break;
                    }
                }
            }
        }
    }

    // format function header line
    char fname[80];
    const char *sym = fn->a ? ana_sym_at(fn->a, fva) : NULL;
    if (sym) sc_clean_sym(sym, fname, sizeof(fname));
    else snprintf(fname, sizeof(fname), "sub_%llx", (unsigned long long)fva);

    char rtype[48] = "";
    if (fn->ret_ty.kind != HL_TY_UNK || fn->ret_ty.ptr_depth > 0) {
        hl_type_fmt(&fn->ret_ty, rtype, sizeof(rtype));
    }
    if (!rtype[0]) {
        if (fn->has_ret_val) snprintf(rtype, sizeof(rtype), "%s", (fn->ptr_bits == 32) ? "int32_t" : "int64_t");
        else snprintf(rtype, sizeof(rtype), "void");
    }

    char fhdr[128];
    sc_fmt_decl(rtype, fname, fhdr, sizeof(fhdr));

    char sig[256];
    sc_buf sb;
    sb_init(&sb, sig, sizeof(sig));
    sb_printf(&sb, "%s(", fhdr);
    if (nordered_args == 0) {
        sb_puts(&sb, "void");
    } else {
        for (int i = 0; i < nordered_args; i++) {
            if (i) sb_puts(&sb, ", ");
            char pdecl[96];
            sc_fmt_decl(ordered_args[i].type, ordered_args[i].name, pdecl, sizeof(pdecl));
            sb_puts(&sb, pdecl);
        }
    }
    sb_puts(&sb, ") {");
    sc_emit_line(sc, fva, 0, 1, "%s", sig);
    if ((fn->g && fn->g->truncated) || (fn->g && (int)fn->g->nblk > sc->nblk) || fn->nblk > sc->nblk) {
        sc_emit_line(sc, fva, 1, 0,
            "/* WARNING: CFG truncated (%u blocks, %u insns shown; limit reached) */",
            fn->g ? fn->g->nblk : (uint32_t)sc->nblk, fn->g ? fn->g->nins : 0U);
    }

    // emit sorted local variable declarations
    for (int i = 0; i < nlocal; i++) {
        char ldecl[96];
        sc_fmt_decl(locals[i].type, locals[i].name, ldecl, sizeof(ldecl));
        sc_emit_line(sc, 0, 1, 0, "%s;", ldecl);
    }
    if (nlocal > 0) sc_emit_line(sc, 0, 0, 0, "");

    // populate out->vars (dec_var_info array)
    uint32_t total = (uint32_t)(nordered_args + nlocal);
    if (total > 0) {
        out->vars = (dec_var_info *)calloc(total, sizeof(dec_var_info));
        if (out->vars) {
            uint32_t wi = 0;
            for (int i = 0; i < nordered_args; i++) {
                dec_var_info *vi = &out->vars[wi++];
                snprintf(vi->orig, sizeof(vi->orig), "%s", ordered_args[i].orig);
                snprintf(vi->name, sizeof(vi->name), "%s", ordered_args[i].name);
                snprintf(vi->type, sizeof(vi->type), "%s", ordered_args[i].type);
                vi->is_arg = 1;
                vi->bits = ordered_args[i].bits;
                vi->stack_off = 0;
            }
            for (int i = 0; i < nlocal; i++) {
                dec_var_info *vi = &out->vars[wi++];
                snprintf(vi->orig, sizeof(vi->orig), "%s", locals[i].orig);
                snprintf(vi->name, sizeof(vi->name), "%s", locals[i].name);
                snprintf(vi->type, sizeof(vi->type), "%s", locals[i].type);
                vi->is_arg = 0;
                vi->bits = locals[i].bits;
                vi->stack_off = locals[i].stack_off;
            }
            out->nvar = wi;
        }
    }

    free(locals);
}

static void sc_ctx_free(sc_ctx *sc) {
    if (!sc) return;
    for (int i = 0; i < sc->nblk; i++) {
        free(sc->succ[i].items);
        free(sc->pred[i].items);
    }
    free(sc->extracted_stmt);
    free(sc->nodes);
    free(sc->cases);
    free(sc->var_used);
    free(sc);
}

bool hl_structure_and_emit(hl_fn *fn, dec_out *out) {
    if (!fn || !out || !fn->blks || fn->nblk <= 0) return false;

    sc_ctx *sc = (sc_ctx *)calloc(1, sizeof(sc_ctx));
    if (!sc) return false;
    sc->fn = fn;
    sc->out = out;
    sc->nblk = (fn->nblk > SC_MAX_BLKS) ? SC_MAX_BLKS : fn->nblk;

    if (fn->nstmt > 0) {
        sc->extracted_stmt = (uint8_t *)calloc((size_t)fn->nstmt, 1);
        sc->extracted_cap = fn->nstmt;
    }
    if (fn->nvar > 0) {
        sc->var_used = (uint8_t *)calloc((size_t)fn->nvar, 1);
        sc->var_used_cap = fn->nvar;
    }

    sc_build_cfg_and_doms(sc);

    int root = sc_node_new(sc, SCN_SEQ, fn->blks[0].start);
    if (root < 0) {
        sc_ctx_free(sc);
        return false;
    }

    sc_build_seq(sc, root, 0, -1, -1, -1, -1, 0, 0);

    // emit any remaining unreachable or goto-referenced blocks
    for (int i = 0; i < sc->nblk; i++) {
        if (sc->emitted[i]) continue;
        if (sc->inlined_exit[i] && !sc->need_lbl[i]) continue;
        if (!sc->reach[i] && !sc->need_lbl[i]) continue;
        sc_build_seq(sc, root, i, -1, -1, -1, -1, 0, 0);
    }

    sc_optimize_ast(sc, root);
    sc_collect_ast_vars(sc, root);

    sc_emit_header_and_vars(sc);
    sc_print_seq(sc, root, 1);

    uint64_t end_va = fn->blks[sc->nblk - 1].end;
    sc_emit_line(sc, end_va, 0, 0, "}");

    sc_ctx_free(sc);
    return out->nline > 0;
}
