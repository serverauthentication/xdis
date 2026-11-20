#include "dec_ir.h"

#include <ctype.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* =========================================================================
 * Constants & Bitset Utilities
 * ========================================================================= */

#define HL_BS_WORDS      33   /* 33 * 64 = 2112 bits (>= HL_MAX_BLKS + 1) */
#define HL_LIFT_REGS     40   /* x86: 0..15 GPR, 16..31 XMM; a64: 0..30 X, 31 SP, 32..39 V */
#define HL_MAX_STK_SLOTS 256
#define HL_MAX_OUT_ARGS  24
#define HL_MAX_DEPTH     48
#define HL_COAL_MAX_VARS 512
#define HL_COAL_WORDS    8    /* 8 * 64 = 512 */

static inline void hl_bs_set(uint64_t *bs, int idx) {
    bs[idx >> 6] |= (1ULL << (idx & 63));
}

static inline void hl_bs_clr(uint64_t *bs, int idx) {
    bs[idx >> 6] &= ~(1ULL << (idx & 63));
}

static inline int hl_bs_get(const uint64_t *bs, int idx) {
    return (int)((bs[idx >> 6] >> (idx & 63)) & 1ULL);
}

static inline int hl_bs_eq(const uint64_t *a, const uint64_t *b, int nwords) {
    for (int i = 0; i < nwords; i++) {
        if (a[i] != b[i]) return 0;
    }
    return 1;
}

static int hl_bs_popcnt(const uint64_t *bs, int nwords) {
    int c = 0;
    for (int i = 0; i < nwords; i++) {
        uint64_t x = bs[i];
        while (x) {
            x &= x - 1ULL;
            c++;
        }
    }
    return c;
}

static uint64_t hl_mask_bits(uint64_t v, int bits) {
    if (bits <= 0 || bits >= 64) return v;
    return v & ((1ULL << bits) - 1ULL);
}

static int64_t hl_sext_bits(uint64_t v, int bits) {
    if (bits <= 0 || bits >= 64) return (int64_t)v;
    uint64_t m = 1ULL << (bits - 1);
    uint64_t x = hl_mask_bits(v, bits);
    return (int64_t)((x ^ m) - m);
}

static uint64_t hl_neg_u64(uint64_t v) {
    return (uint64_t)(0ULL - v);
}

/* =========================================================================
 * Arena & Core Public Helpers
 * ========================================================================= */

void hl_fn_free(hl_fn *fn) {
    if (!fn) return;
    if (fn->blks) {
        for (int i = 0; i < fn->nblk; i++) {
            free(fn->blks[i].stmts);
        }
        free(fn->blks);
    }
    free(fn->stmts);
    free(fn->exprs);
    free(fn->vars);
    memset(fn, 0, sizeof(*fn));
}

int hl_expr_new(hl_fn *fn, uint8_t kind) {
    if (!fn) return -1;
    if (fn->nexpr >= fn->expr_cap) {
        int nc = fn->expr_cap ? fn->expr_cap * 2 : 256;
        hl_expr *ne = (hl_expr *)realloc(fn->exprs, (size_t)nc * sizeof(hl_expr));
        if (!ne) return -1;
        fn->exprs = ne;
        fn->expr_cap = nc;
    }
    int id = fn->nexpr++;
    hl_expr *e = &fn->exprs[id];
    memset(e, 0, sizeof(*e));
    e->kind   = kind;
    e->var_id = -1;
    e->sub0   = -1;
    e->sub1   = -1;
    e->sub2   = -1;
    e->scale  = 1;
    for (int i = 0; i < HL_MAX_CALL_ARG; i++) e->args[i] = -1;
    return id;
}

int hl_expr_int(hl_fn *fn, uint64_t v, int bits, int is_signed) {
    int id = hl_expr_new(fn, HLE_INT);
    if (id < 0) return -1;
    hl_expr *e = &fn->exprs[id];
    e->uval      = v;
    e->bits      = (uint8_t)(bits > 0 ? bits : 64);
    e->is_signed = (uint8_t)(is_signed ? 1 : 0);
    return id;
}

int hl_expr_flt(hl_fn *fn, double v, int bits) {
    int id = hl_expr_new(fn, HLE_FLT);
    if (id < 0) return -1;
    hl_expr *e = &fn->exprs[id];
    e->fval   = v;
    e->bits   = (uint8_t)(bits == 32 ? 32 : 64);
    e->is_flt = 1;
    return id;
}

int hl_expr_var(hl_fn *fn, int var_id) {
    int id = hl_expr_new(fn, HLE_VAR);
    if (id < 0) return -1;
    hl_expr *e = &fn->exprs[id];
    e->var_id = var_id;
    if (var_id >= 0 && var_id < fn->nvar) {
        const hl_var *v = &fn->vars[var_id];
        e->bits   = (uint8_t)(v->bits > 0 ? v->bits : fn->ptr_bits);
        e->is_flt = (uint8_t)(v->is_flt ? 1 : 0);
        e->ty     = v->ty;
    } else {
        e->bits = (uint8_t)(fn->ptr_bits ? fn->ptr_bits : 64);
    }
    return id;
}

int hl_expr_unop(hl_fn *fn, uint8_t op, int sub, int bits) {
    int id = hl_expr_new(fn, HLE_UNOP);
    if (id < 0) return -1;
    int b = bits;
    if (b <= 0) {
        b = (sub >= 0 && sub < fn->nexpr && fn->exprs[sub].bits) ? fn->exprs[sub].bits : 64;
    }
    hl_expr *e = &fn->exprs[id];
    e->op   = op;
    e->sub0 = sub;
    e->bits = (uint8_t)b;
    if (op == HLU_FNEG || op == HLU_FABS || op == HLU_I2F) e->is_flt = 1;
    if (op == HLU_SEXT || op == HLU_F2I || op == HLU_ABS) e->is_signed = 1;
    return id;
}

int hl_expr_binop(hl_fn *fn, uint8_t op, int a, int b, int bits) {
    int id = hl_expr_new(fn, HLE_BINOP);
    if (id < 0) return -1;
    int bw = bits;
    if (bw <= 0) {
        if (a >= 0 && a < fn->nexpr && fn->exprs[a].bits) bw = fn->exprs[a].bits;
        else if (b >= 0 && b < fn->nexpr && fn->exprs[b].bits) bw = fn->exprs[b].bits;
        else bw = 64;
    }
    hl_expr *e = &fn->exprs[id];
    e->op   = op;
    e->sub0 = a;
    e->sub1 = b;
    e->bits = (uint8_t)bw;
    if (op == HLB_FADD || op == HLB_FSUB || op == HLB_FMUL || op == HLB_FDIV) {
        e->is_flt = 1;
    }
    if (op == HLB_SDIV || op == HLB_SMOD || op == HLB_SAR ||
        op == HLB_SLT  || op == HLB_SLE  || op == HLB_SGT || op == HLB_SGE) {
        e->is_signed = 1;
    }
    return id;
}

static int hl_expr_clone_rec(hl_fn *fn, int eid, int depth) {
    if (!fn || eid < 0 || eid >= fn->nexpr || depth > HL_MAX_DEPTH) return -1;
    hl_expr orig = fn->exprs[eid];
    int nid = hl_expr_new(fn, orig.kind);
    if (nid < 0) return -1;

    int c0 = (orig.sub0 >= 0) ? hl_expr_clone_rec(fn, orig.sub0, depth + 1) : -1;
    int c1 = (orig.sub1 >= 0) ? hl_expr_clone_rec(fn, orig.sub1, depth + 1) : -1;
    int c2 = (orig.sub2 >= 0) ? hl_expr_clone_rec(fn, orig.sub2, depth + 1) : -1;
    int cargs[HL_MAX_CALL_ARG];
    for (int i = 0; i < HL_MAX_CALL_ARG; i++) {
        cargs[i] = (i < (int)orig.narg && orig.args[i] >= 0)
                 ? hl_expr_clone_rec(fn, orig.args[i], depth + 1) : -1;
    }

    fn->exprs[nid] = orig;
    fn->exprs[nid].sub0 = c0;
    fn->exprs[nid].sub1 = c1;
    fn->exprs[nid].sub2 = c2;
    for (int i = 0; i < HL_MAX_CALL_ARG; i++) fn->exprs[nid].args[i] = cargs[i];
    return nid;
}

int hl_expr_clone(hl_fn *fn, int eid) {
    return hl_expr_clone_rec(fn, eid, 0);
}

static int hl_is_cmp_op(uint8_t op) {
    return op >= HLB_EQ && op <= HLB_UGE;
}

static int hl_is_bool_expr(const hl_fn *fn, int eid) {
    if (!fn || eid < 0 || eid >= fn->nexpr) return 0;
    const hl_expr *e = &fn->exprs[eid];
    if (e->kind == HLE_BINOP && (hl_is_cmp_op(e->op) || e->op == HLB_LAND || e->op == HLB_LOR)) return 1;
    if (e->kind == HLE_UNOP && e->op == HLU_LOGNOT) return 1;
    if (e->kind == HLE_BITSET) return 1;
    return 0;
}

static uint8_t hl_invert_cmp_op(uint8_t op) {
    switch (op) {
    case HLB_EQ:  return HLB_NE;
    case HLB_NE:  return HLB_EQ;
    case HLB_SLT: return HLB_SGE;
    case HLB_SGE: return HLB_SLT;
    case HLB_SLE: return HLB_SGT;
    case HLB_SGT: return HLB_SLE;
    case HLB_ULT: return HLB_UGE;
    case HLB_UGE: return HLB_ULT;
    case HLB_ULE: return HLB_UGT;
    case HLB_UGT: return HLB_ULE;
    default:      return 0;
    }
}

static int hl_expr_invert_rec(hl_fn *fn, int eid, int depth) {
    if (!fn || eid < 0 || eid >= fn->nexpr || depth > HL_MAX_DEPTH) return -1;
    hl_expr e = fn->exprs[eid];

    if (e.kind == HLE_UNOP && e.op == HLU_LOGNOT && e.sub0 >= 0) {
        return hl_expr_clone_rec(fn, e.sub0, depth + 1);
    }
    if (e.kind == HLE_INT) {
        return hl_expr_int(fn, e.uval ? 0ULL : 1ULL, 1, 0);
    }
    if (e.kind == HLE_BINOP) {
        uint8_t inv = hl_invert_cmp_op(e.op);
        if (inv) {
            int c0 = hl_expr_clone_rec(fn, e.sub0, depth + 1);
            int c1 = hl_expr_clone_rec(fn, e.sub1, depth + 1);
            int nid = hl_expr_binop(fn, inv, c0, c1, e.bits ? e.bits : 1);
            if (nid >= 0) fn->exprs[nid].is_flt = e.is_flt;
            return nid;
        }
        if (e.op == HLB_LAND || e.op == HLB_LOR) {
            int i0 = hl_expr_invert_rec(fn, e.sub0, depth + 1);
            int i1 = hl_expr_invert_rec(fn, e.sub1, depth + 1);
            return hl_expr_binop(fn, (e.op == HLB_LAND) ? HLB_LOR : HLB_LAND, i0, i1, 1);
        }
    }
    int c = hl_expr_clone_rec(fn, eid, depth + 1);
    return hl_expr_unop(fn, HLU_LOGNOT, c, 1);
}

int hl_expr_invert(hl_fn *fn, int eid) {
    return hl_expr_invert_rec(fn, eid, 0);
}

int hl_var_canon(const hl_fn *fn, int vid) {
    if (!fn || vid < 0 || vid >= fn->nvar) return -1;
    int steps = 0;
    while (vid >= 0 && vid < fn->nvar && fn->vars[vid].coal_to >= 0 && steps < 64) {
        int nxt = fn->vars[vid].coal_to;
        if (nxt == vid || nxt >= fn->nvar) break;
        vid = nxt;
        steps++;
    }
    return vid;
}

int hl_stmt_new(hl_fn *fn, int bi, uint64_t va, uint8_t kind) {
    if (!fn) return -1;
    if (fn->nstmt >= fn->stmt_cap) {
        int nc = fn->stmt_cap ? fn->stmt_cap * 2 : 256;
        hl_stmt *ns = (hl_stmt *)realloc(fn->stmts, (size_t)nc * sizeof(hl_stmt));
        if (!ns) return -1;
        fn->stmts = ns;
        fn->stmt_cap = nc;
    }
    int sid = fn->nstmt++;
    hl_stmt *s = &fn->stmts[sid];
    memset(s, 0, sizeof(*s));
    s->va       = va;
    s->kind     = kind;
    s->dst_var  = -1;
    s->lhs_expr = -1;
    s->rhs_expr = -1;
    s->len_expr = -1;
    for (int i = 0; i < 8; i++) {
        s->phi_vars[i] = -1;
        s->phi_blks[i] = -1;
    }
    if (bi >= 0 && bi < fn->nblk) {
        hl_blk *b = &fn->blks[bi];
        if (b->nstmt >= b->stmt_cap) {
            int nc = b->stmt_cap ? b->stmt_cap * 2 : 16;
            int *na = (int *)realloc(b->stmts, (size_t)nc * sizeof(int));
            if (!na) return -1;
            b->stmts = na;
            b->stmt_cap = nc;
        }
        b->stmts[b->nstmt++] = sid;
    }
    return sid;
}

static int hl_var_new(hl_fn *fn, int bits, int reg_hint, int is_flt) {
    if (!fn) return -1;
    if (fn->nvar >= fn->var_cap) {
        int nc = fn->var_cap ? fn->var_cap * 2 : 64;
        hl_var *nv = (hl_var *)realloc(fn->vars, (size_t)nc * sizeof(hl_var));
        if (!nv) return -1;
        fn->vars = nv;
        fn->var_cap = nc;
    }
    int id = fn->nvar++;
    hl_var *v = &fn->vars[id];
    memset(v, 0, sizeof(*v));
    v->id       = id;
    v->bits     = (bits > 0) ? bits : (fn->ptr_bits ? fn->ptr_bits : 64);
    v->reg_hint = reg_hint;
    v->is_flt   = is_flt ? 1 : 0;
    v->coal_to  = -1;
    v->arg_idx  = -1;
    if (v->is_flt) {
        v->ty.kind = (v->bits == 32) ? HL_TY_F32 : HL_TY_F64;
        v->ty.bits = (uint8_t)v->bits;
    }
    snprintf(v->orig, sizeof(v->orig), "t%d", id);
    snprintf(v->name, sizeof(v->name), "t%d", id);
    return id;
}

static int hl_expr_eq(const hl_fn *fn, int a, int b, int depth) {
    if (a == b) return 1;
    if (!fn || a < 0 || b < 0 || a >= fn->nexpr || b >= fn->nexpr || depth > HL_MAX_DEPTH) return 0;
    const hl_expr *ea = &fn->exprs[a];
    const hl_expr *eb = &fn->exprs[b];
    if (ea->kind != eb->kind || ea->op != eb->op) return 0;
    switch (ea->kind) {
    case HLE_INT:
        return ea->uval == eb->uval;
    case HLE_FLT:
        return ea->fval == eb->fval && ea->bits == eb->bits;
    case HLE_STR:
    case HLE_SYM:
        return ea->va == eb->va && strcmp(ea->sym, eb->sym) == 0;
    case HLE_VAR:
        return hl_var_canon(fn, ea->var_id) == hl_var_canon(fn, eb->var_id);
    case HLE_ADDR:
        return hl_expr_eq(fn, ea->sub0, eb->sub0, depth + 1);
    case HLE_DEREF:
        return ea->bits == eb->bits && ea->is_flt == eb->is_flt &&
               hl_expr_eq(fn, ea->sub0, eb->sub0, depth + 1);
    case HLE_FIELD:
        return ea->disp == eb->disp && ea->is_dot == eb->is_dot &&
               strcmp(ea->field, eb->field) == 0 &&
               hl_expr_eq(fn, ea->sub0, eb->sub0, depth + 1);
    case HLE_INDEX:
        return ea->scale == eb->scale && ea->bits == eb->bits &&
               hl_expr_eq(fn, ea->sub0, eb->sub0, depth + 1) &&
               hl_expr_eq(fn, ea->sub1, eb->sub1, depth + 1);
    case HLE_UNOP:
        return ea->bits == eb->bits && hl_expr_eq(fn, ea->sub0, eb->sub0, depth + 1);
    case HLE_BINOP:
        return hl_expr_eq(fn, ea->sub0, eb->sub0, depth + 1) &&
               hl_expr_eq(fn, ea->sub1, eb->sub1, depth + 1);
    case HLE_TERNARY:
        return hl_expr_eq(fn, ea->sub0, eb->sub0, depth + 1) &&
               hl_expr_eq(fn, ea->sub1, eb->sub1, depth + 1) &&
               hl_expr_eq(fn, ea->sub2, eb->sub2, depth + 1);
    case HLE_BITSET:
        return ea->uval == eb->uval &&
               hl_expr_eq(fn, ea->sub0, eb->sub0, depth + 1) &&
               hl_expr_eq(fn, ea->sub1, eb->sub1, depth + 1);
    case HLE_CALL:
        return 0; /* calls are never treated as pure-equal */
    default:
        return 0;
    }
}

static int hl_expr_nodes(const hl_fn *fn, int eid, int depth) {
    if (!fn || eid < 0 || eid >= fn->nexpr || depth > HL_MAX_DEPTH) return 0;
    const hl_expr *e = &fn->exprs[eid];
    int n = 1;
    if (e->sub0 >= 0) n += hl_expr_nodes(fn, e->sub0, depth + 1);
    if (e->sub1 >= 0) n += hl_expr_nodes(fn, e->sub1, depth + 1);
    if (e->sub2 >= 0) n += hl_expr_nodes(fn, e->sub2, depth + 1);
    for (int i = 0; i < (int)e->narg && i < HL_MAX_CALL_ARG; i++) {
        if (e->args[i] >= 0) n += hl_expr_nodes(fn, e->args[i], depth + 1);
    }
    return n;
}

static int hl_expr_has_kind(const hl_fn *fn, int eid, uint8_t kind, int depth) {
    if (!fn || eid < 0 || eid >= fn->nexpr || depth > HL_MAX_DEPTH) return 0;
    const hl_expr *e = &fn->exprs[eid];
    if (e->kind == kind) return 1;
    if (e->sub0 >= 0 && hl_expr_has_kind(fn, e->sub0, kind, depth + 1)) return 1;
    if (e->sub1 >= 0 && hl_expr_has_kind(fn, e->sub1, kind, depth + 1)) return 1;
    if (e->sub2 >= 0 && hl_expr_has_kind(fn, e->sub2, kind, depth + 1)) return 1;
    for (int i = 0; i < (int)e->narg && i < HL_MAX_CALL_ARG; i++) {
        if (e->args[i] >= 0 && hl_expr_has_kind(fn, e->args[i], kind, depth + 1)) return 1;
    }
    return 0;
}

static int hl_expr_has_stack_var(const hl_fn *fn, int eid, int depth) {
    if (!fn || eid < 0 || eid >= fn->nexpr || depth > HL_MAX_DEPTH) return 0;
    const hl_expr *e = &fn->exprs[eid];
    if (e->kind == HLE_ADDR) return 0; /* &var_XX is a pure stack address */
    if (e->kind == HLE_VAR && e->var_id >= 0 && e->var_id < fn->nvar) {
        int cv = hl_var_canon(fn, e->var_id);
        if (cv >= 0 && fn->vars[cv].is_stack && !fn->vars[cv].is_arg) return 1;
    }
    if (e->sub0 >= 0 && hl_expr_has_stack_var(fn, e->sub0, depth + 1)) return 1;
    if (e->sub1 >= 0 && hl_expr_has_stack_var(fn, e->sub1, depth + 1)) return 1;
    if (e->sub2 >= 0 && hl_expr_has_stack_var(fn, e->sub2, depth + 1)) return 1;
    for (int i = 0; i < (int)e->narg && i < HL_MAX_CALL_ARG; i++) {
        if (e->args[i] >= 0 && hl_expr_has_stack_var(fn, e->args[i], depth + 1)) return 1;
    }
    return 0;
}

static int hl_expr_uses_var(const hl_fn *fn, int eid, int target_vid, int depth) {
    if (!fn || eid < 0 || eid >= fn->nexpr || depth > HL_MAX_DEPTH) return 0;
    const hl_expr *e = &fn->exprs[eid];
    if (e->kind == HLE_VAR && hl_var_canon(fn, e->var_id) == target_vid) return 1;
    if (e->sub0 >= 0 && hl_expr_uses_var(fn, e->sub0, target_vid, depth + 1)) return 1;
    if (e->sub1 >= 0 && hl_expr_uses_var(fn, e->sub1, target_vid, depth + 1)) return 1;
    if (e->sub2 >= 0 && hl_expr_uses_var(fn, e->sub2, target_vid, depth + 1)) return 1;
    for (int i = 0; i < (int)e->narg && i < HL_MAX_CALL_ARG; i++) {
        if (e->args[i] >= 0 && hl_expr_uses_var(fn, e->args[i], target_vid, depth + 1)) return 1;
    }
    return 0;
}

/* =========================================================================
 * Register & Operand Parsing (x86/x64 & ARM64)
 * ========================================================================= */

typedef enum {
    HLO_NONE = 0,
    HLO_REG,
    HLO_IMM,
    HLO_MEM
} hl_opr_kind;

typedef struct {
    uint8_t  kind;
    int      reg;      /* base reg (or reg for HLO_REG), -1 if none */
    int      idx;      /* index reg for HLO_MEM, -1 if none */
    int      scale;    /* 1, 2, 4, 8 */
    int      bits;     /* operand width in bits (0 if unspecified) */
    int      is_flt;   /* 1=f32, 2=f64, 3=vec128+ */
    int      is_hi8;   /* ah/ch/dh/bh */
    int      is_abs;   /* [0x...] without base/idx */
    int      a64_wb;   /* 1=pre-index !, 2=post-index */
    char     seg;      /* 'f' for fs:, 'g' for gs:, etc., 0 if none */
    int64_t  disp;
    uint64_t uval;
} hl_opr;

static const char *const hl_x64_r64[16] = {
    "rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi",
    "r8","r9","r10","r11","r12","r13","r14","r15"
};
static const char *const hl_x64_r32[16] = {
    "eax","ecx","edx","ebx","esp","ebp","esi","edi",
    "r8d","r9d","r10d","r11d","r12d","r13d","r14d","r15d"
};
static const char *const hl_x64_r16[16] = {
    "ax","cx","dx","bx","sp","bp","si","di",
    "r8w","r9w","r10w","r11w","r12w","r13w","r14w","r15w"
};
static const char *const hl_x64_r8[16] = {
    "al","cl","dl","bl","spl","bpl","sil","dil",
    "r8b","r9b","r10b","r11b","r12b","r13b","r14b","r15b"
};
static const char *const hl_x64_r8h[4] = {"ah","ch","dh","bh"};

static void hl_trim(char *s) {
    char *p = s;
    while (*p == ' ' || *p == '\t') p++;
    if (p != s) memmove(s, p, strlen(p) + 1);
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\t')) s[--n] = 0;
}

static void hl_lower_copy(const char *src, char *dst, size_t cap) {
    size_t i = 0;
    if (src) {
        for (; src[i] && i + 1 < cap; i++) {
            dst[i] = (char)tolower((unsigned char)src[i]);
        }
    }
    dst[i] = 0;
}

static void hl_clean_sym(const char *raw, char *dst, size_t cap) {
    if (!raw || !raw[0]) {
        if (cap) dst[0] = 0;
        return;
    }
    const char *s = raw;
    const char *bang = strchr(s, '!');
    if (bang) s = bang + 1;
    if (strncmp(s, "__imp_", 6) == 0) s += 6;
    else if (strncmp(s, "imp_", 4) == 0) s += 4;
    if (strncmp(s, "j_", 2) == 0 && s[2]) s += 2;

    size_t k = 0;
    for (size_t i = 0; s[i] && k + 1 < cap; i++) {
        char ch = s[i];
        if (ch == '@' && i > 0) break; /* strip stdcall @N decoration */
        dst[k++] = (isalnum((unsigned char)ch) || ch == '_') ? ch : '_';
    }
    dst[k] = 0;
    if (!dst[0]) snprintf(dst, cap, "fn");
}

static int hl_split_ops(const char *ops, char out[4][80]) {
    for (int i = 0; i < 4; i++) out[i][0] = 0;
    if (!ops || !ops[0]) return 0;
    int cnt = 0, depth = 0;
    const char *start = ops;
    for (const char *p = ops; ; p++) {
        if (*p == '[') depth++;
        else if (*p == ']' && depth > 0) depth--;
        if ((*p == ',' && depth == 0) || *p == 0) {
            if (cnt < 4) {
                size_t len = (size_t)(p - start);
                if (len >= 79) len = 79;
                memcpy(out[cnt], start, len);
                out[cnt][len] = 0;
                hl_trim(out[cnt]);
                if (out[cnt][0]) cnt++;
            }
            if (*p == 0) break;
            start = p + 1;
        }
    }
    return cnt;
}

static int hl_parse_int(const char *p, int64_t *out) {
    if (!p || !*p) return 0;
    if (*p == '#') p++;
    int neg = 0;
    if (*p == '-') { neg = 1; p++; }
    else if (*p == '+') p++;
    if (!*p) return 0;
    char *end = NULL;
    uint64_t v = 0;
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
        if (!isxdigit((unsigned char)p[2])) return 0;
        v = strtoull(p + 2, &end, 16);
    } else if (isdigit((unsigned char)p[0])) {
        v = strtoull(p, &end, 10);
    } else {
        return 0;
    }
    if (!end || *end != 0) return 0;
    *out = neg ? (int64_t)hl_neg_u64(v) : (int64_t)v;
    return 1;
}

static int hl_parse_x86_reg(const char *s, int *bits, int *is_flt, int *is_hi8) {
    *bits   = 64;
    *is_flt = 0;
    *is_hi8 = 0;
    if (!s || !s[0]) return -1;
    if ((s[0] == 'x' || s[0] == 'y' || s[0] == 'z') &&
        s[1] == 'm' && s[2] == 'm' && isdigit((unsigned char)s[3])) {
        char *end = NULL;
        long idx = strtol(s + 3, &end, 10);
        if (end && *end == 0 && idx >= 0 && idx < 32) {
            *bits   = (s[0] == 'z') ? 512 : (s[0] == 'y') ? 256 : 128;
            *is_flt = 3;
            return 16 + (int)(idx & 15);
        }
    }
    for (int i = 0; i < 16; i++) {
        if (strcmp(s, hl_x64_r64[i]) == 0) { *bits = 64; return i; }
        if (strcmp(s, hl_x64_r32[i]) == 0) { *bits = 32; return i; }
        if (strcmp(s, hl_x64_r16[i]) == 0) { *bits = 16; return i; }
        if (strcmp(s, hl_x64_r8[i]) == 0)  { *bits = 8;  return i; }
    }
    for (int i = 0; i < 4; i++) {
        if (strcmp(s, hl_x64_r8h[i]) == 0) { *bits = 8; *is_hi8 = 1; return i; }
    }
    return -1;
}

static int hl_parse_a64_reg(const char *s, int *bits, int *is_zero, int *is_flt) {
    *bits    = 64;
    *is_zero = 0;
    *is_flt  = 0;
    if (!s || !s[0]) return -1;
    if (strcmp(s, "xzr") == 0) { *bits = 64; *is_zero = 1; return -1; }
    if (strcmp(s, "wzr") == 0) { *bits = 32; *is_zero = 1; return -1; }
    if (strcmp(s, "sp") == 0)  { *bits = 64; return 31; }
    if (strcmp(s, "wsp") == 0) { *bits = 32; return 31; }
    if (strcmp(s, "fp") == 0)  { *bits = 64; return 29; }
    if (strcmp(s, "lr") == 0)  { *bits = 64; return 30; }
    if ((s[0] == 'x' || s[0] == 'w') && isdigit((unsigned char)s[1])) {
        char *end = NULL;
        long r = strtol(s + 1, &end, 10);
        if (end && *end == 0 && r >= 0 && r <= 30) {
            *bits = (s[0] == 'x') ? 64 : 32;
            return (int)r;
        }
    }
    if ((s[0] == 'd' || s[0] == 's' || s[0] == 'v' || s[0] == 'q') && isdigit((unsigned char)s[1])) {
        char *end = NULL;
        long r = strtol(s + 1, &end, 10);
        if (end && *end == 0 && r >= 0 && r <= 31) {
            *bits   = (s[0] == 's') ? 32 : 64;
            *is_flt = (s[0] == 's') ? 1 : 2;
            return 32 + (int)(r & 7);
        }
    }
    return -1;
}

static void hl_parse_mem_x86(const char *in_raw, hl_opr *op) {
    char in[72];
    snprintf(in, sizeof(in), "%s", in_raw);
    char *rb = strchr(in, ']');
    if (rb) *rb = 0;
    hl_trim(in);

    if (strncmp(in, "0x", 2) == 0 && !strchr(in, '+') && !strchr(in, '-') && !strchr(in, '*')) {
        op->uval   = strtoull(in + 2, NULL, 16);
        op->disp   = (int64_t)op->uval;
        op->is_abs = 1;
        return;
    }

    char *cur = in;
    int sign = 1;
    while (*cur) {
        if (*cur == ' ') { cur++; continue; }
        if (*cur == '+') { sign = 1; cur++; continue; }
        if (*cur == '-') { sign = -1; cur++; continue; }
        char tok[32];
        int k = 0;
        while (*cur && *cur != '+' && *cur != '-' && k < 31) tok[k++] = *cur++;
        tok[k] = 0;
        hl_trim(tok);
        if (!tok[0]) continue;

        char *star = strchr(tok, '*');
        if (star) {
            *star = 0;
            hl_trim(tok);
            int b2 = 0, fl = 0, hi8 = 0;
            int r = hl_parse_x86_reg(tok, &b2, &fl, &hi8);
            if (r >= 0 && !fl) {
                op->idx   = r;
                op->scale = atoi(star + 1);
                if (op->scale <= 0) op->scale = 1;
            }
        } else {
            int64_t iv = 0;
            if (hl_parse_int(tok, &iv)) {
                op->disp += (int64_t)sign * iv;
            } else {
                int b2 = 0, fl = 0, hi8 = 0;
                int r = hl_parse_x86_reg(tok, &b2, &fl, &hi8);
                if (r >= 0 && !fl) {
                    if (op->reg < 0) op->reg = r;
                    else op->idx = r;
                }
            }
        }
    }
    if (op->reg < 0 && op->idx < 0) {
        op->is_abs = 1;
        op->uval   = (uint64_t)op->disp;
    }
}

static void hl_parse_mem_a64(const char *in_raw, hl_opr *op) {
    char in[72];
    snprintf(in, sizeof(in), "%s", in_raw);
    char *rb = strchr(in, ']');
    if (rb) {
        if (rb[1] == '!') op->a64_wb = 1;
        *rb = 0;
    }
    hl_trim(in);

    if (strncmp(in, "0x", 2) == 0 && !strchr(in, ',')) {
        op->uval   = strtoull(in + 2, NULL, 16);
        op->disp   = (int64_t)op->uval;
        op->is_abs = 1;
        return;
    }

    char *comma = strchr(in, ',');
    if (comma) *comma = 0;
    hl_trim(in);
    int b2 = 64, zr = 0, fl = 0;
    int r = hl_parse_a64_reg(in, &b2, &zr, &fl);
    if (r >= 0) op->reg = r;

    if (comma) {
        char *rhs = comma + 1;
        hl_trim(rhs);
        int64_t iv = 0;
        if (hl_parse_int(rhs, &iv)) {
            op->disp = iv;
        } else {
            int r2 = hl_parse_a64_reg(rhs, &b2, &zr, &fl);
            if (r2 >= 0) op->idx = r2;
        }
    }
}

static void hl_parse_opr(const hl_fn *fn, const char *raw, hl_opr *op) {
    memset(op, 0, sizeof(*op));
    op->reg   = -1;
    op->idx   = -1;
    op->scale = 1;
    if (!raw || !raw[0]) return;

    char buf[80];
    hl_lower_copy(raw, buf, sizeof(buf));
    hl_trim(buf);

    const char *p = buf;
    if (!fn->is_a64) {
        if (strncmp(p, "byte ptr ", 9) == 0)          { op->bits = 8;   p += 9; }
        else if (strncmp(p, "word ptr ", 9) == 0)     { op->bits = 16;  p += 9; }
        else if (strncmp(p, "dword ptr ", 10) == 0)   { op->bits = 32;  p += 10; }
        else if (strncmp(p, "qword ptr ", 10) == 0)   { op->bits = 64;  p += 10; }
        else if (strncmp(p, "xmmword ptr ", 12) == 0) { op->bits = 128; p += 12; }
        else if (strncmp(p, "ymmword ptr ", 12) == 0) { op->bits = 256; p += 12; }
        if (p[0] && p[1] && p[2] == ':') {
            op->seg = p[0];
            p += 3;
        }
    }

    if (*p == '[') {
        op->kind = HLO_MEM;
        if (fn->is_a64) hl_parse_mem_a64(p + 1, op);
        else hl_parse_mem_x86(p + 1, op);
        return;
    }

    int64_t iv = 0;
    if (hl_parse_int(p, &iv)) {
        op->kind = HLO_IMM;
        op->disp = iv;
        op->uval = (uint64_t)iv;
        return;
    }

    int rb = fn->ptr_bits, fl = 0, zr = 0, hi8 = 0;
    int r = fn->is_a64 ? hl_parse_a64_reg(p, &rb, &zr, &fl)
                       : hl_parse_x86_reg(p, &rb, &fl, &hi8);
    if (zr) {
        op->kind = HLO_IMM;
        op->uval = 0;
        op->bits = rb;
        return;
    }
    if (r >= 0) {
        op->kind   = HLO_REG;
        op->reg    = r;
        op->bits   = rb;
        op->is_flt = fl;
        op->is_hi8 = hi8;
    }
}

static int hl_try_read_ro_cstring(const ana_ctx *a, uint64_t va, char *out, size_t cap, int *is_wide) {
    *is_wide = 0;
    if (!a || !va) return 0;
    const ana_str *st = ana_str_at(a, va);
    if (st) {
        *is_wide = st->wide ? 1 : 0;
        if (out && cap) ana_read_str(a, st, out, cap);
        return 1;
    }
    const bin_sec *sec = bin_sec_at(&a->bin, va);
    if (!sec || (sec->perm & BIN_PERM_X)) return 0;
    int is_ro = !(sec->perm & BIN_PERM_W) ||
                strstr(sec->name, "rdata") != NULL ||
                strstr(sec->name, "rodata") != NULL ||
                strstr(sec->name, "cstring") != NULL;
    if (!is_ro) return 0;

    uint8_t buf[256];
    size_t got = bin_read(&a->bin, va, buf, sizeof(buf));
    if (got < 2) return 0;

    /* Check narrow ASCII string (e.g. "%d", "%s", "rb", "\n", or long format strings) */
    size_t len = 0;
    while (len < got && buf[len] != 0) {
        uint8_t c = buf[len];
        if (!((c >= 0x20 && c <= 0x7E) || c == '\t' || c == '\r' || c == '\n')) break;
        len++;
    }
    if ((len >= 1 && len < got && buf[len] == 0) || (len == got && len >= 16)) {
        if (out && cap) {
            size_t cp = (len < cap - 1) ? len : (cap - 1);
            memcpy(out, buf, cp);
            out[cp] = 0;
        }
        return 1;
    }

    /* Check UTF-16LE wide string */
    if (got >= 4 && buf[1] == 0 && (buf[0] >= 0x20 && buf[0] <= 0x7E)) {
        size_t wlen = 0;
        while (wlen * 2 + 1 < got) {
            uint8_t lo = buf[wlen * 2];
            uint8_t hi = buf[wlen * 2 + 1];
            if (lo == 0 && hi == 0) break;
            if (hi != 0 || !((lo >= 0x20 && lo <= 0x7E) || lo == '\t' || lo == '\r' || lo == '\n')) {
                wlen = 0;
                break;
            }
            wlen++;
        }
        if ((wlen >= 2 && wlen * 2 + 1 < got && buf[wlen * 2] == 0 && buf[wlen * 2 + 1] == 0) ||
            (wlen * 2 + 1 >= got && wlen >= 8)) {
            *is_wide = 1;
            if (out && cap) {
                size_t k = 0;
                for (size_t i = 0; i < wlen && k + 1 < cap; i++) out[k++] = (char)buf[i * 2];
                out[k] = 0;
            }
            return 1;
        }
    }
    return 0;
}

static int hl_try_read_ro_float(const ana_ctx *a, uint64_t va, int bits, double *out_val, uint64_t *out_raw) {
    if (!a || !va) return 0;
    const bin_sec *sec = bin_sec_at(&a->bin, va);
    if (!sec || (sec->perm & BIN_PERM_X)) return 0;
    int is_ro = !(sec->perm & BIN_PERM_W) ||
                strstr(sec->name, "rdata") != NULL ||
                strstr(sec->name, "rodata") != NULL ||
                strstr(sec->name, "const") != NULL;
    if (!is_ro) return 0;

    if (bits == 32) {
        uint32_t raw = 0;
        if (bin_read(&a->bin, va, (uint8_t *)&raw, 4) != 4) return 0;
        if (out_raw) *out_raw = raw;
        float fv = 0.0f;
        memcpy(&fv, &raw, 4);
        if (out_val) *out_val = (double)fv;
        return 1;
    } else {
        uint64_t raw = 0;
        if (bin_read(&a->bin, va, (uint8_t *)&raw, 8) != 8) return 0;
        if (out_raw) *out_raw = raw;
        double dv = 0.0;
        memcpy(&dv, &raw, 8);
        if (out_val) *out_val = dv;
        return 1;
    }
}

static int hl_expr_addr_const(hl_fn *fn, uint64_t va) {
    if (!fn || !fn->a) return hl_expr_int(fn, va, fn ? fn->ptr_bits : 64, 0);
    const ana_ctx *a = fn->a;

    char sbuf[64];
    int is_wide = 0;
    if (hl_try_read_ro_cstring(a, va, sbuf, sizeof(sbuf), &is_wide)) {
        int id = hl_expr_new(fn, HLE_STR);
        if (id >= 0) {
            fn->exprs[id].va      = va;
            fn->exprs[id].is_wide = (uint8_t)is_wide;
            fn->exprs[id].bits    = (uint8_t)fn->ptr_bits;
            snprintf(fn->exprs[id].sym, sizeof(fn->exprs[id].sym), "%s", sbuf);
        }
        return id;
    }

    const char *sym = ana_sym_at(a, va);
    if (sym && sym[0]) {
        int id = hl_expr_new(fn, HLE_SYM);
        if (id >= 0) {
            fn->exprs[id].va   = va;
            fn->exprs[id].bits = (uint8_t)fn->ptr_bits;
            hl_clean_sym(sym, fn->exprs[id].sym, sizeof(fn->exprs[id].sym));
        }
        return id;
    }

    if (bin_sec_at(&a->bin, va) != NULL) {
        const ana_func *af = ana_func_at(a, va);
        int id = hl_expr_new(fn, HLE_SYM);
        if (id >= 0) {
            fn->exprs[id].va   = va;
            fn->exprs[id].bits = (uint8_t)fn->ptr_bits;
            if (af && af->start == va) {
                snprintf(fn->exprs[id].sym, sizeof(fn->exprs[id].sym), "sub_%llx", (unsigned long long)va);
            } else {
                snprintf(fn->exprs[id].sym, sizeof(fn->exprs[id].sym), "g_%llx", (unsigned long long)va);
            }
        }
        return id;
    }

    return hl_expr_int(fn, va, fn->ptr_bits, 0);
}

/* =========================================================================
 * Lifter Context, CFG, Dominators, Post-Dominators, Loops
 * ========================================================================= */

typedef enum {
    HLF_NONE = 0,
    HLF_CMP,
    HLF_TEST,
    HLF_BT,
    HLF_FCMP,
    HLF_ZERO,
    HLF_CMN,
    HLF_NEG
} hl_flag_kind;

typedef struct {
    int kind;
    int lhs_expr;
    int rhs_expr;
    int res_expr;
    int bits;
    int is_flt;
} hl_flag_state;

typedef struct {
    int64_t off;
    int     var_id;
    int     bits;
    int     is_flt;
    int     is_arg;
    int     addr_taken;
    int     written;
} hl_stk_slot;

typedef struct {
    int64_t disp;      /* entry-relative stack offset (soff) */
    int     val_expr;
    int     stmt_id;
    int     blk_id;
} hl_out_arg;

typedef struct {
    hl_fn     *fn;
    int        nblk;
    int        nregs;
    uint64_t   saved_reg_mask;
    uint64_t   vol_reg_mask;
    int        flt_ret_reg;

    uint64_t   succ_bs[HL_MAX_BLKS][HL_BS_WORDS];
    uint64_t   pred_bs[HL_MAX_BLKS][HL_BS_WORDS];
    uint64_t   dom_bs[HL_MAX_BLKS][HL_BS_WORDS];
    uint64_t   df_bs[HL_MAX_BLKS][HL_BS_WORDS];
    uint8_t    reach[HL_MAX_BLKS];
    int        dom_head[HL_MAX_BLKS];
    int        dom_next[HL_MAX_BLKS];

    /* Pre-scan: SP/BP tracking, prologue/epilogue, canary */
    int64_t    blk_sp_in[HL_MAX_BLKS];
    int64_t    blk_bp_in[HL_MAX_BLKS];
    uint8_t    blk_has_bp_in[HL_MAX_BLKS];
    uint8_t    blk_sp_vis[HL_MAX_BLKS];
    uint8_t    blk_is_epi[HL_MAX_BLKS];

    int        has_saved_slot[HL_LIFT_REGS];
    int64_t    saved_slot[HL_LIFT_REGS];
    int        uses_fp;
    int        cur_alias_reg;
    int64_t    cur_alias_delta;

    uint8_t   *skip_ins;
    uint32_t   nins;

    /* Liveness & SSA PHIs */
    uint64_t   def_blks[HL_LIFT_REGS][HL_BS_WORDS];
    uint64_t   blk_use_reg[HL_MAX_BLKS];
    uint64_t   blk_def_reg[HL_MAX_BLKS];
    uint64_t   live_in_reg[HL_MAX_BLKS];
    uint64_t   live_out_reg[HL_MAX_BLKS];
    int        phi_stmt[HL_MAX_BLKS][HL_LIFT_REGS];

    /* SSA version stacks during dom-tree DFS */
    int       *reg_stk[HL_LIFT_REGS];
    int        reg_stk_len[HL_LIFT_REGS];
    int        reg_stk_cap[HL_LIFT_REGS];
    int        reg_next_ver[HL_LIFT_REGS];
    int        entry_var[HL_LIFT_REGS];
    int        cur_bits[HL_LIFT_REGS];
    int        cur_flt[HL_LIFT_REGS];

    /* Per-block exit flag, ret-validity & outgoing stack arg state (inherited via idom) */
    hl_flag_state blk_exit_fl[HL_MAX_BLKS];
    uint8_t       blk_exit_ret_valid[HL_MAX_BLKS];
    uint8_t       blk_exit_fret_valid[HL_MAX_BLKS];
    uint8_t       blk_exit_last_ret_is_flt[HL_MAX_BLKS];
    uint8_t       blk_exit_fret_bits[HL_MAX_BLKS];
    hl_out_arg    blk_exit_out_args[HL_MAX_BLKS][HL_MAX_OUT_ARGS];
    int           blk_exit_nout_args[HL_MAX_BLKS];

    /* Canonical stack slots */
    hl_stk_slot stk_slots[HL_MAX_STK_SLOTS];
    int         nstk;

    /* Return statement tracking */
    int        ret_stmts[HL_MAX_BLKS];
    int        ret_vars[HL_MAX_BLKS];
    int        ret_flt_vars[HL_MAX_BLKS];
    uint8_t    ret_is_flt[HL_MAX_BLKS];
    uint8_t    ret_flt_bits[HL_MAX_BLKS];
    int        nret_stmts;

    /* Fast var -> defining stmt lookup (for format string resolution etc.) */
    int       *var_def_stmt;
    int        var_def_cap;
} hl_lift_ctx;

static void hl_lift_ctx_free(hl_lift_ctx *c) {
    if (!c) return;
    free(c->skip_ins);
    free(c->var_def_stmt);
    for (int r = 0; r < HL_LIFT_REGS; r++) free(c->reg_stk[r]);
    free(c);
}

static void hl_record_var_def(hl_lift_ctx *c, int vid, int sid) {
    if (vid < 0) return;
    if (vid >= c->var_def_cap) {
        int nc = c->var_def_cap ? c->var_def_cap * 2 : 128;
        while (nc <= vid) nc *= 2;
        int *na = (int *)realloc(c->var_def_stmt, (size_t)nc * sizeof(int));
        if (!na) return;
        for (int i = c->var_def_cap; i < nc; i++) na[i] = -1;
        c->var_def_stmt = na;
        c->var_def_cap = nc;
    }
    c->var_def_stmt[vid] = sid;
}

static void hl_reg_stk_push(hl_lift_ctx *c, int r, int vid) {
    if (r < 0 || r >= HL_LIFT_REGS) return;
    if (c->reg_stk_len[r] >= c->reg_stk_cap[r]) {
        int nc = c->reg_stk_cap[r] ? c->reg_stk_cap[r] * 2 : 32;
        int *na = (int *)realloc(c->reg_stk[r], (size_t)nc * sizeof(int));
        if (!na) return;
        c->reg_stk[r] = na;
        c->reg_stk_cap[r] = nc;
    }
    c->reg_stk[r][c->reg_stk_len[r]++] = vid;
}

static int hl_reg_stk_top(const hl_lift_ctx *c, int r) {
    if (r < 0 || r >= HL_LIFT_REGS || c->reg_stk_len[r] <= 0) return -1;
    return c->reg_stk[r][c->reg_stk_len[r] - 1];
}

static int hl_blk_of_va(const hl_fn *fn, uint64_t va) {
    for (int i = 0; i < fn->nblk; i++) {
        if (fn->blks[i].start == va) return i;
    }
    return -1;
}

static int hl_is_stack_chk_sym(const char *sym) {
    if (!sym) return 0;
    return strstr(sym, "stack_chk_fail") != NULL ||
           strstr(sym, "security_check_cookie") != NULL ||
           strstr(sym, "__GSHandlerCheck") != NULL;
}

static int hl_is_chkstk_sym(const char *sym) {
    if (!sym) return 0;
    return strstr(sym, "chkstk") != NULL ||
           strstr(sym, "alloca_probe") != NULL ||
           strstr(sym, "___chkstk_ms") != NULL;
}

static int hl_is_cookie_sym(const char *sym) {
    if (!sym) return 0;
    return strstr(sym, "security_cookie") != NULL ||
           strstr(sym, "stack_chk_guard") != NULL;
}

static void hl_build_cfg_doms(hl_lift_ctx *c) {
    hl_fn *fn = c->fn;
    const grp_cfg *g = fn->g;
    int nb = fn->nblk;

    for (int b = 0; b < nb; b++) {
        hl_blk *hb = &fn->blks[b];
        hb->start     = g->blks[b].start;
        hb->end       = g->blks[b].end;
        hb->cond_expr = -1;
        hb->sw_expr   = -1;
        hb->sw_idx    = -1;
        hb->out_t     = -1;
        hb->out_f     = -1;
        hb->out_u     = -1;
        hb->idom      = -1;
        hb->ipdom     = -1;
    }

    for (uint32_t e = 0; e < g->nedge; e++) {
        int u = (int)g->edges[e].from;
        int v = (int)g->edges[e].to;
        if (u < 0 || u >= nb || v < 0 || v >= nb) continue;
        if (g->edges[e].kind == GRP_EDGE_TRUE) fn->blks[u].out_t = v;
        else if (g->edges[e].kind == GRP_EDGE_FALSE) fn->blks[u].out_f = v;
        else fn->blks[u].out_u = v;

        hl_bs_set(c->succ_bs[u], v);
        if (!hl_bs_get(c->pred_bs[v], u)) {
            hl_bs_set(c->pred_bs[v], u);
            fn->blks[v].in_deg++;
        }
    }

    /* Mark exit blocks */
    for (int b = 0; b < nb; b++) {
        const grp_blk *gb = &g->blks[b];
        if (fn->blks[b].out_t < 0 && fn->blks[b].out_f < 0 && fn->blks[b].out_u < 0) {
            fn->blks[b].is_exit = 1;
        } else if (gb->ins_count > 0) {
            const x86_ins *last = &g->ins[gb->ins_first + gb->ins_count - 1];
            if (last->flow == X86_FLOW_RET || last->flow == X86_FLOW_TRAP) {
                fn->blks[b].is_exit = 1;
            }
        }
    }

    /* Scan jump-table switches */
    fn->nsw = ir_scan_switches_cfg(fn->a, g, fn->sws, HL_MAX_SW);
    for (int si = 0; si < fn->nsw; si++) {
        uint64_t sva = fn->sws[si].va;
        for (int b = 0; b < nb; b++) {
            if (fn->blks[b].start <= sva && sva < fn->blks[b].end) {
                fn->blks[b].sw_idx = si;
                break;
            }
        }
    }

    /* Reachability BFS from block 0 */
    int *q = (int *)malloc((size_t)(nb > 0 ? nb : 1) * sizeof(int));
    if (q) {
        int qh = 0, qt = 0;
        c->reach[0] = 1;
        q[qt++] = 0;
        while (qh < qt) {
            int u = q[qh++];
            for (int v = 0; v < nb; v++) {
                if (!c->reach[v] && hl_bs_get(c->succ_bs[u], v)) {
                    c->reach[v] = 1;
                    q[qt++] = v;
                }
            }
        }
        free(q);
    }

    /* Dominators */
    uint64_t all_r[HL_BS_WORDS];
    memset(all_r, 0, sizeof(all_r));
    for (int b = 0; b < nb; b++) {
        fn->blks[b].idom = -1;
        c->dom_head[b] = -1;
        c->dom_next[b] = -1;
        if (c->reach[b]) hl_bs_set(all_r, b);
    }

    hl_bs_set(c->dom_bs[0], 0);
    for (int b = 1; b < nb; b++) {
        if (c->reach[b]) memcpy(c->dom_bs[b], all_r, sizeof(all_r));
    }

    int changed = 1;
    while (changed) {
        changed = 0;
        for (int b = 1; b < nb; b++) {
            if (!c->reach[b]) continue;
            uint64_t nd[HL_BS_WORDS];
            memcpy(nd, all_r, sizeof(nd));
            int has_p = 0;
            for (int p = 0; p < nb; p++) {
                if (!c->reach[p] || !hl_bs_get(c->pred_bs[b], p)) continue;
                for (int w = 0; w < HL_BS_WORDS; w++) nd[w] &= c->dom_bs[p][w];
                has_p = 1;
            }
            if (!has_p) memset(nd, 0, sizeof(nd));
            hl_bs_set(nd, b);
            if (!hl_bs_eq(nd, c->dom_bs[b], HL_BS_WORDS)) {
                memcpy(c->dom_bs[b], nd, sizeof(nd));
                changed = 1;
            }
        }
    }

    int *dom_cnt = (int *)malloc((size_t)(nb > 0 ? nb : 1) * sizeof(int));
    if (dom_cnt) {
        for (int b = 0; b < nb; b++) {
            dom_cnt[b] = c->reach[b] ? hl_bs_popcnt(c->dom_bs[b], HL_BS_WORDS) : 0;
        }
        for (int b = 1; b < nb; b++) {
            if (!c->reach[b]) continue;
            int best = -1, best_cnt = -1;
            for (int d = 0; d < nb; d++) {
                if (d == b || !c->reach[d]) continue;
                if (hl_bs_get(c->dom_bs[b], d) && dom_cnt[d] > best_cnt) {
                    best = d;
                    best_cnt = dom_cnt[d];
                }
            }
            fn->blks[b].idom = best;
        }
        free(dom_cnt);
    }

    /* Build dom-tree child lists in ascending block order */
    for (int b = nb - 1; b >= 1; b--) {
        int id = fn->blks[b].idom;
        if (id >= 0) {
            c->dom_next[b] = c->dom_head[id];
            c->dom_head[id] = b;
        }
    }

    /* Dominance Frontiers */
    for (int b = 0; b < nb; b++) {
        if (!c->reach[b]) continue;
        int npred = 0;
        for (int p = 0; p < nb; p++) {
            if (c->reach[p] && hl_bs_get(c->pred_bs[b], p)) npred++;
        }
        if (npred < 2 && !(b == 0 && npred >= 1)) continue;
        for (int p = 0; p < nb; p++) {
            if (!c->reach[p] || !hl_bs_get(c->pred_bs[b], p)) continue;
            int runner = p;
            int guard = 0;
            while (runner >= 0 && runner != fn->blks[b].idom && guard < nb + 2) {
                hl_bs_set(c->df_bs[runner], b);
                runner = fn->blks[runner].idom;
                guard++;
            }
        }
    }

    /* Natural Loop Headers: back-edge u -> v where v dominates u */
    for (int u = 0; u < nb; u++) {
        if (!c->reach[u]) continue;
        for (int v = 0; v < nb; v++) {
            if (!c->reach[v] || !hl_bs_get(c->succ_bs[u], v)) continue;
            if (hl_bs_get(c->dom_bs[u], v)) {
                fn->blks[v].is_loop_hdr = 1;
            }
        }
    }

    /* Post-Dominators (virtual exit node = nb) */
    int vexit = nb;
    uint64_t (*pdom)[HL_BS_WORDS] = (uint64_t (*)[HL_BS_WORDS])calloc((size_t)(nb + 1), sizeof(uint64_t[HL_BS_WORDS]));
    uint8_t *preach = (uint8_t *)calloc((size_t)(nb + 1), 1);
    int *pq = (int *)malloc((size_t)(nb + 1) * sizeof(int));
    int *pdom_cnt = (int *)malloc((size_t)(nb + 1) * sizeof(int));
    if (pdom && preach && pq && pdom_cnt) {
        int pqh = 0, pqt = 0;
        preach[vexit] = 1;
        pq[pqt++] = vexit;
        for (int b = 0; b < nb; b++) {
            if (!c->reach[b]) continue;
            int has_s = 0;
            for (int s = 0; s < nb; s++) {
                if (c->reach[s] && hl_bs_get(c->succ_bs[b], s)) { has_s = 1; break; }
            }
            if (!has_s) {
                preach[b] = 1;
                pq[pqt++] = b;
            }
        }
        while (pqh < pqt) {
            int u = pq[pqh++];
            if (u == vexit) continue;
            for (int p = 0; p < nb; p++) {
                if (c->reach[p] && !preach[p] && hl_bs_get(c->pred_bs[u], p)) {
                    preach[p] = 1;
                    pq[pqt++] = p;
                }
            }
        }

        uint64_t all_pr[HL_BS_WORDS];
        memset(all_pr, 0, sizeof(all_pr));
        for (int b = 0; b <= vexit; b++) {
            if (preach[b]) hl_bs_set(all_pr, b);
        }
        hl_bs_set(pdom[vexit], vexit);
        for (int b = 0; b < nb; b++) {
            if (preach[b]) memcpy(pdom[b], all_pr, sizeof(all_pr));
        }

        int pchanged = 1;
        while (pchanged) {
            pchanged = 0;
            for (int b = nb - 1; b >= 0; b--) {
                if (!preach[b]) continue;
                uint64_t nd[HL_BS_WORDS];
                memcpy(nd, all_pr, sizeof(nd));
                int has_s = 0;
                for (int s = 0; s < nb; s++) {
                    if (preach[s] && hl_bs_get(c->succ_bs[b], s)) {
                        for (int w = 0; w < HL_BS_WORDS; w++) nd[w] &= pdom[s][w];
                        has_s = 1;
                    }
                }
                if (!has_s) {
                    for (int w = 0; w < HL_BS_WORDS; w++) nd[w] &= pdom[vexit][w];
                }
                hl_bs_set(nd, b);
                if (!hl_bs_eq(nd, pdom[b], HL_BS_WORDS)) {
                    memcpy(pdom[b], nd, sizeof(nd));
                    pchanged = 1;
                }
            }
        }

        for (int b = 0; b <= vexit; b++) {
            pdom_cnt[b] = preach[b] ? hl_bs_popcnt(pdom[b], HL_BS_WORDS) : 0;
        }
        for (int b = 0; b < nb; b++) {
            if (!preach[b]) continue;
            int best = -1, best_cnt = -1;
            for (int d = 0; d <= vexit; d++) {
                if (d == b || !preach[d]) continue;
                if (hl_bs_get(pdom[b], d) && pdom_cnt[d] > best_cnt) {
                    best = d;
                    best_cnt = pdom_cnt[d];
                }
            }
            fn->blks[b].ipdom = (best == vexit || best < 0) ? -1 : best;
        }
    }
    free(pdom_cnt);
    free(pq);
    free(pdom);
    free(preach);
}

/* =========================================================================
 * Pre-Pass: SP/BP Tracking, Callee-Saved Prologue/Epilogue, Canary, Stack Slots
 * ========================================================================= */

static int hl_find_or_add_stk_slot(hl_lift_ctx *c, int64_t off, int bits, int is_flt, int is_arg) {
    for (int i = 0; i < c->nstk; i++) {
        if (c->stk_slots[i].off == off) {
            if (bits > c->stk_slots[i].bits) c->stk_slots[i].bits = bits;
            if (is_flt) c->stk_slots[i].is_flt = 1;
            return i;
        }
    }
    if (c->nstk >= HL_MAX_STK_SLOTS) return -1;
    int idx = c->nstk++;
    hl_stk_slot *s = &c->stk_slots[idx];
    memset(s, 0, sizeof(*s));
    s->off    = off;
    s->bits   = (bits > 0) ? bits : c->fn->ptr_bits;
    s->is_flt = is_flt ? 1 : 0;
    s->is_arg = is_arg ? 1 : 0;
    s->var_id = -1;
    return idx;
}

static int hl_get_stk_var(hl_lift_ctx *c, int64_t off, int bits, int is_flt, int is_read) {
    hl_fn *fn = c->fn;
    int64_t arg_base = fn->is_win64 ? 0x28 : (fn->is_x86_32 ? 4 : 8);
    int ptr_bytes = fn->ptr_bits / 8;

    int existing = -1;
    for (int i = 0; i < c->nstk; i++) {
        if (c->stk_slots[i].off == off) { existing = i; break; }
    }
    int is_arg = 0;
    if (existing >= 0) {
        is_arg = c->stk_slots[existing].is_arg;
    } else if (is_read && off >= arg_base && (off % ptr_bytes) == 0) {
        is_arg = 1;
    }

    int idx = hl_find_or_add_stk_slot(c, off, bits, is_flt, is_arg);
    if (idx < 0) return -1;
    hl_stk_slot *s = &c->stk_slots[idx];
    if (s->var_id < 0) {
        int vid = hl_var_new(fn, s->bits, -1, s->is_flt);
        if (vid < 0) return -1;
        hl_var *v = &fn->vars[vid];
        v->is_stack  = 1;
        v->stack_off = off;
        v->is_arg    = s->is_arg;
        if (s->is_arg) {
            int stk_arg_ord = (int)((off - arg_base) / ptr_bytes);
            v->arg_idx = fn->is_x86_32 ? stk_arg_ord : (fn->narg_abi + stk_arg_ord);
        }
        s->var_id = vid;
    } else {
        hl_var *v = &fn->vars[s->var_id];
        if (bits > v->bits) v->bits = bits;
        if (is_flt && !v->is_flt) {
            v->is_flt = 1;
            v->ty.kind = (bits == 32) ? HL_TY_F32 : HL_TY_F64;
            v->ty.bits = (uint8_t)bits;
        }
    }
    return s->var_id;
}

static int hl_mem_to_stack_off_ex(const hl_fn *fn, const hl_opr *op,
                                  int64_t cur_sp, int64_t cur_bp, int has_bp,
                                  int alias_reg, int64_t alias_delta,
                                  int64_t *out_off) {
    if (op->kind != HLO_MEM || op->idx >= 0 || op->seg != 0) return 0;
    if (op->reg == fn->sp_reg) {
        *out_off = cur_sp + op->disp;
        return 1;
    }
    if (has_bp && op->reg == fn->bp_reg) {
        *out_off = cur_bp + op->disp;
        return 1;
    }
    if (alias_reg >= 0 && op->reg == alias_reg) {
        *out_off = alias_delta + op->disp;
        return 1;
    }
    return 0;
}

static void hl_step_sp_x86(const hl_fn *fn, const char *m, const hl_opr *o0, const hl_opr *o1,
                           int64_t *sp, int64_t *bp, int *has_bp, int64_t *last_eax_imm,
                           int *alias_reg, int64_t *alias_delta) {
    int psz = fn->ptr_bits / 8;
    if (strcmp(m, "push") == 0) {
        *sp -= psz;
    } else if (strcmp(m, "pop") == 0) {
        *sp += psz;
        if (alias_reg && o0->kind == HLO_REG && o0->reg == *alias_reg) *alias_reg = -1;
    } else if (strcmp(m, "sub") == 0 && o0->kind == HLO_REG && o0->reg == fn->sp_reg) {
        if (o1->kind == HLO_IMM) *sp -= o1->disp;
        else if (o1->kind == HLO_REG && o1->reg == 0 && *last_eax_imm > 0) *sp -= *last_eax_imm;
    } else if (strcmp(m, "add") == 0 && o0->kind == HLO_REG && o0->reg == fn->sp_reg && o1->kind == HLO_IMM) {
        *sp += o1->disp;
    } else if (strcmp(m, "lea") == 0 && o0->kind == HLO_REG && o0->reg == fn->sp_reg && o1->kind == HLO_MEM && o1->idx < 0) {
        if (o1->reg == fn->sp_reg) *sp += o1->disp;
        else if (*has_bp && o1->reg == fn->bp_reg) *sp = *bp + o1->disp;
        else if (alias_reg && *alias_reg >= 0 && o1->reg == *alias_reg) *sp = *alias_delta + o1->disp;
    } else if (strcmp(m, "mov") == 0 && o0->kind == HLO_REG && o0->reg == fn->bp_reg &&
               o1->kind == HLO_REG && o1->reg == fn->sp_reg) {
        *bp = *sp;
        *has_bp = 1;
    } else if (strcmp(m, "lea") == 0 && o0->kind == HLO_REG && o0->reg == fn->bp_reg &&
               o1->kind == HLO_MEM && o1->reg == fn->sp_reg && o1->idx < 0) {
        *bp = *sp + o1->disp;
        *has_bp = 1;
    } else if (strcmp(m, "mov") == 0 && o0->kind == HLO_REG && o0->reg == fn->sp_reg &&
               o1->kind == HLO_REG) {
        if (*has_bp && o1->reg == fn->bp_reg) *sp = *bp;
        else if (alias_reg && *alias_reg >= 0 && o1->reg == *alias_reg) *sp = *alias_delta;
    } else if (strcmp(m, "leave") == 0) {
        if (*has_bp) { *sp = *bp + psz; *has_bp = 0; }
    } else if (alias_reg && strcmp(m, "mov") == 0 && o0->kind == HLO_REG &&
               o0->reg != fn->sp_reg && o0->reg != fn->bp_reg &&
               o1->kind == HLO_REG && o1->reg == fn->sp_reg) {
        *alias_reg   = o0->reg;
        *alias_delta = *sp;
    } else if (alias_reg && strcmp(m, "lea") == 0 && o0->kind == HLO_REG &&
               o0->reg != fn->sp_reg && o0->reg != fn->bp_reg &&
               o1->kind == HLO_MEM && o1->idx < 0 && o1->seg == 0 &&
               (o1->reg == fn->sp_reg || (*has_bp && o1->reg == fn->bp_reg))) {
        *alias_reg   = o0->reg;
        *alias_delta = ((o1->reg == fn->sp_reg) ? *sp : *bp) + o1->disp;
    } else {
        if (strcmp(m, "mov") == 0 && o0->kind == HLO_REG && o0->reg == 0 && o1->kind == HLO_IMM) {
            *last_eax_imm = o1->disp;
        }
        if (alias_reg && *alias_reg >= 0 && o0->kind == HLO_REG && o0->reg == *alias_reg &&
            strcmp(m, "cmp") != 0 && strcmp(m, "test") != 0 && strcmp(m, "bt") != 0) {
            *alias_reg = -1;
        }
    }
}

static void hl_step_sp_a64(const hl_fn *fn, const char *m, const hl_opr *o0, const hl_opr *o1,
                           const hl_opr *o2, const hl_opr *o3, int nops,
                           int64_t *sp, int64_t *bp, int *has_bp) {
    if (strcmp(m, "sub") == 0 && o0->kind == HLO_REG && o0->reg == fn->sp_reg &&
        o1->kind == HLO_REG && o1->reg == fn->sp_reg && o2->kind == HLO_IMM) {
        *sp -= o2->disp;
    } else if (strcmp(m, "add") == 0 && o0->kind == HLO_REG && o0->reg == fn->sp_reg &&
               o1->kind == HLO_REG && o1->reg == fn->sp_reg && o2->kind == HLO_IMM) {
        *sp += o2->disp;
    } else if ((strcmp(m, "stp") == 0 || strcmp(m, "ldp") == 0) && o2->kind == HLO_MEM && o2->reg == fn->sp_reg) {
        if (o2->a64_wb == 1) *sp += o2->disp;
        else if (nops >= 4 && o3->kind == HLO_IMM) *sp += o3->disp;
    } else if (strcmp(m, "mov") == 0 && o0->kind == HLO_REG && o0->reg == fn->bp_reg &&
               o1->kind == HLO_REG && o1->reg == fn->sp_reg) {
        *bp = *sp;
        *has_bp = 1;
    } else if (strcmp(m, "add") == 0 && o0->kind == HLO_REG && o0->reg == fn->bp_reg &&
               o1->kind == HLO_REG && o1->reg == fn->sp_reg && o2->kind == HLO_IMM) {
        *bp = *sp + o2->disp;
        *has_bp = 1;
    } else if (strcmp(m, "mov") == 0 && o0->kind == HLO_REG && o0->reg == fn->sp_reg &&
               o1->kind == HLO_REG && o1->reg == fn->bp_reg && *has_bp) {
        *sp = *bp;
    }
}

static int hl_is_mov_mnem(const char *m) {
    return strcmp(m, "mov") == 0 || strcmp(m, "movabs") == 0 ||
           strcmp(m, "movaps") == 0 || strcmp(m, "movups") == 0 ||
           strcmp(m, "movapd") == 0 || strcmp(m, "movupd") == 0 ||
           strcmp(m, "movdqa") == 0 || strcmp(m, "movdqu") == 0 ||
           strcmp(m, "movq") == 0 || strcmp(m, "movsd") == 0 || strcmp(m, "movss") == 0 ||
           strcmp(m, "vmovaps") == 0 || strcmp(m, "vmovups") == 0 ||
           strcmp(m, "vmovdqa") == 0 || strcmp(m, "vmovdqu") == 0;
}

static void hl_prescan(hl_lift_ctx *c) {
    hl_fn *fn = c->fn;
    const grp_cfg *g = fn->g;
    int nb = fn->nblk;

    /* 1. Propagate entry-relative SP & BP across CFG via BFS */
    int *q = (int *)malloc((size_t)(nb > 0 ? nb : 1) * sizeof(int));
    if (q) {
        int qh = 0, qt = 0;
        c->blk_sp_vis[0]    = 1;
        c->blk_sp_in[0]     = 0;
        c->blk_bp_in[0]     = 0;
        c->blk_has_bp_in[0] = 0;
        q[qt++] = 0;

        while (qh < qt) {
            int b = q[qh++];
            int64_t sp = c->blk_sp_in[b];
            int64_t bp = c->blk_bp_in[b];
            int has_bp = c->blk_has_bp_in[b];
            int64_t last_eax = 0;
            int alias_reg = -1;
            int64_t alias_delta = 0;

            const grp_blk *gb = &g->blks[b];
            for (uint32_t k = 0; k < gb->ins_count; k++) {
                const x86_ins *in = &g->ins[gb->ins_first + k];
                char mn[24];
                hl_lower_copy(in->mnem, mn, sizeof(mn));
                const char *m = (strncmp(mn, "lock ", 5) == 0) ? (mn + 5) : mn;
                char ops[4][80];
                int nops = hl_split_ops(in->ops, ops);
                hl_opr o0, o1, o2, o3;
                hl_parse_opr(fn, ops[0], &o0);
                hl_parse_opr(fn, ops[1], &o1);
                hl_parse_opr(fn, ops[2], &o2);
                hl_parse_opr(fn, ops[3], &o3);
                if (fn->is_a64) hl_step_sp_a64(fn, m, &o0, &o1, &o2, &o3, nops, &sp, &bp, &has_bp);
                else {
                    if (in->flow == X86_FLOW_CALL && alias_reg >= 0 && (c->vol_reg_mask & (1ULL << alias_reg))) {
                        alias_reg = -1;
                    }
                    hl_step_sp_x86(fn, m, &o0, &o1, &sp, &bp, &has_bp, &last_eax, &alias_reg, &alias_delta);
                }
                if (has_bp) c->uses_fp = 1;
            }

            int succs[3] = {fn->blks[b].out_t, fn->blks[b].out_f, fn->blks[b].out_u};
            for (int si = 0; si < 3; si++) {
                int s = succs[si];
                if (s >= 0 && s < nb && !c->blk_sp_vis[s]) {
                    c->blk_sp_vis[s]    = 1;
                    c->blk_sp_in[s]     = sp;
                    c->blk_bp_in[s]     = bp;
                    c->blk_has_bp_in[s] = (uint8_t)has_bp;
                    q[qt++] = s;
                }
            }
            if (fn->blks[b].sw_idx >= 0) {
                for (int s = 0; s < nb; s++) {
                    if (hl_bs_get(c->succ_bs[b], s) && !c->blk_sp_vis[s]) {
                        c->blk_sp_vis[s]    = 1;
                        c->blk_sp_in[s]     = sp;
                        c->blk_bp_in[s]     = bp;
                        c->blk_has_bp_in[s] = (uint8_t)has_bp;
                        q[qt++] = s;
                    }
                }
            }
        }
        free(q);
    }

    /* 2. Identify epilogue blocks (exit / tail-call blocks & blocks jumping straight to pure epilogue) */
    for (int b = 0; b < nb; b++) {
        if (!c->reach[b]) continue;
        const grp_blk *gb = &g->blks[b];
        if (fn->blks[b].is_exit) {
            c->blk_is_epi[b] = 1;
        } else if (gb->ins_count > 0) {
            const x86_ins *last = &g->ins[gb->ins_first + gb->ins_count - 1];
            if (last->flow == X86_FLOW_JMP && fn->blks[b].sw_idx < 0 && fn->blks[b].out_u < 0) {
                c->blk_is_epi[b] = 1; /* external tail call */
            }
        }
    }
    /* Propagate epilogue flag backward one hop across unconditional jumps to small epilogue tails */
    for (int pass = 0; pass < 2; pass++) {
        for (int b = 0; b < nb; b++) {
            int u = fn->blks[b].out_u;
            if (!c->blk_is_epi[b] && u >= 0 && c->blk_is_epi[u] && g->blks[u].ins_count <= 12) {
                c->blk_is_epi[b] = 1;
            }
        }
    }

    /* 3. Block 0 Prologue: callee-saved saves, frame setup, __chkstk, stack canary setup */
    {
        int64_t sp = 0, bp = 0, last_eax = 0;
        int has_bp = 0;
        int alias_reg = -1;
        int64_t alias_delta = 0;
        uint8_t reg_unmod[HL_LIFT_REGS];
        memset(reg_unmod, 1, sizeof(reg_unmod));

        struct {
            int      ins1;
            int      ins2;
            uint64_t va;
            int      is_tls;
            int      xored;
        } cnd[HL_LIFT_REGS];
        for (int r = 0; r < HL_LIFT_REGS; r++) {
            cnd[r].ins1 = -1;
            cnd[r].ins2 = -1;
            cnd[r].va = 0;
            cnd[r].is_tls = 0;
            cnd[r].xored = 0;
        }

        int last_eax_ins = -1;
        int seen_real_call = 0;
        const grp_blk *gb = &g->blks[0];

        for (uint32_t k = 0; k < gb->ins_count; k++) {
            uint32_t gidx = gb->ins_first + k;
            const x86_ins *in = &g->ins[gidx];
            char mn[24];
            hl_lower_copy(in->mnem, mn, sizeof(mn));
            const char *m = (strncmp(mn, "lock ", 5) == 0) ? (mn + 5) : mn;
            char ops[4][80];
            int nops = hl_split_ops(in->ops, ops);
            hl_opr o0, o1, o2, o3;
            hl_parse_opr(fn, ops[0], &o0);
            hl_parse_opr(fn, ops[1], &o1);
            hl_parse_opr(fn, ops[2], &o2);
            hl_parse_opr(fn, ops[3], &o3);

            int64_t pre_sp = sp;
            int64_t pre_bp = bp;
            int pre_has_bp = has_bp;
            int pre_areg = alias_reg;
            int64_t pre_adelta = alias_delta;

            if (!fn->is_a64) {
                /* __chkstk / _alloca_probe */
                if (in->flow == X86_FLOW_CALL) {
                    const char *sym = in->has_target ? ana_sym_at(fn->a, in->target) : NULL;
                    if (hl_is_chkstk_sym(sym)) {
                        c->skip_ins[gidx] = 1;
                        if (last_eax_ins >= 0) c->skip_ins[last_eax_ins] = 1;
                        continue;
                    }
                    if (alias_reg >= 0 && (c->vol_reg_mask & (1ULL << alias_reg))) alias_reg = -1;
                    seen_real_call = 1;
                }

                /* Stack frame management instructions */
                if ((strcmp(m, "sub") == 0 || strcmp(m, "add") == 0 || strcmp(m, "and") == 0) &&
                    o0.kind == HLO_REG && o0.reg == fn->sp_reg) {
                    c->skip_ins[gidx] = 1;
                    hl_step_sp_x86(fn, m, &o0, &o1, &sp, &bp, &has_bp, &last_eax, &alias_reg, &alias_delta);
                    continue;
                }
                if (strcmp(m, "mov") == 0 && o0.kind == HLO_REG && o0.reg == fn->bp_reg &&
                    o1.kind == HLO_REG && o1.reg == fn->sp_reg) {
                    c->skip_ins[gidx] = 1;
                    hl_step_sp_x86(fn, m, &o0, &o1, &sp, &bp, &has_bp, &last_eax, &alias_reg, &alias_delta);
                    reg_unmod[fn->bp_reg] = 0;
                    continue;
                }
                /* MSVC x64 SP-alias prologue: mov rax, rsp / mov r11, rsp */
                if (!seen_real_call && strcmp(m, "mov") == 0 && o0.kind == HLO_REG &&
                    o0.reg != fn->sp_reg && o0.reg != fn->bp_reg &&
                    o1.kind == HLO_REG && o1.reg == fn->sp_reg) {
                    c->skip_ins[gidx] = 1;
                    hl_step_sp_x86(fn, m, &o0, &o1, &sp, &bp, &has_bp, &last_eax, &alias_reg, &alias_delta);
                    reg_unmod[o0.reg] = 0;
                    continue;
                }
                if (strcmp(m, "lea") == 0 && o0.kind == HLO_REG && o0.reg == fn->bp_reg &&
                    o1.kind == HLO_MEM && o1.reg == fn->sp_reg && o1.idx < 0) {
                    c->skip_ins[gidx] = 1;
                    hl_step_sp_x86(fn, m, &o0, &o1, &sp, &bp, &has_bp, &last_eax, &alias_reg, &alias_delta);
                    reg_unmod[fn->bp_reg] = 0;
                    continue;
                }
                if (strcmp(m, "lea") == 0 && o0.kind == HLO_REG && o0.reg == fn->sp_reg &&
                    o1.kind == HLO_MEM && o1.idx < 0 &&
                    (o1.reg == fn->sp_reg || (has_bp && o1.reg == fn->bp_reg) ||
                     (alias_reg >= 0 && o1.reg == alias_reg))) {
                    c->skip_ins[gidx] = 1;
                    hl_step_sp_x86(fn, m, &o0, &o1, &sp, &bp, &has_bp, &last_eax, &alias_reg, &alias_delta);
                    continue;
                }

                /* Prologue push callee-saved */
                if (!seen_real_call && strcmp(m, "push") == 0 && o0.kind == HLO_REG &&
                    o0.reg >= 0 && o0.reg < HL_LIFT_REGS &&
                    (c->saved_reg_mask & (1ULL << o0.reg)) && reg_unmod[o0.reg]) {
                    hl_step_sp_x86(fn, m, &o0, &o1, &sp, &bp, &has_bp, &last_eax, &alias_reg, &alias_delta);
                    c->has_saved_slot[o0.reg] = 1;
                    c->saved_slot[o0.reg]     = sp;
                    c->skip_ins[gidx]         = 1;
                    continue;
                }

                /* Prologue mov [rsp/rbp/alias+off], callee-saved */
                if (!seen_real_call && hl_is_mov_mnem(m) && o0.kind == HLO_MEM && o1.kind == HLO_REG &&
                    o1.reg >= 0 && o1.reg < HL_LIFT_REGS &&
                    (c->saved_reg_mask & (1ULL << o1.reg)) && reg_unmod[o1.reg] &&
                    !c->has_saved_slot[o1.reg]) {
                    int64_t soff = 0;
                    if (hl_mem_to_stack_off_ex(fn, &o0, pre_sp, pre_bp, pre_has_bp, pre_areg, pre_adelta, &soff)) {
                        c->has_saved_slot[o1.reg] = 1;
                        c->saved_slot[o1.reg]     = soff;
                        c->skip_ins[gidx]         = 1;
                        continue;
                    }
                }

                /* Stack canary setup detection */
                if (!fn->has_canary && hl_is_mov_mnem(m) && o0.kind == HLO_REG && o1.kind == HLO_MEM &&
                    o0.reg >= 0 && o0.reg < 16) {
                    if ((o1.seg == 'f' || o1.seg == 'g') && (o1.uval == 0x28 || o1.uval == 0x14)) {
                        cnd[o0.reg].ins1   = (int)gidx;
                        cnd[o0.reg].ins2   = -1;
                        cnd[o0.reg].va     = o1.uval;
                        cnd[o0.reg].is_tls = 1;
                        cnd[o0.reg].xored  = 0;
                    } else if (o1.is_abs && o1.seg == 0) {
                        uint64_t tva = in->has_target ? in->target : o1.uval;
                        cnd[o0.reg].ins1   = (int)gidx;
                        cnd[o0.reg].ins2   = -1;
                        cnd[o0.reg].va     = tva;
                        cnd[o0.reg].is_tls = 0;
                        cnd[o0.reg].xored  = 0;
                    } else {
                        cnd[o0.reg].ins1 = -1;
                    }
                } else if (!fn->has_canary && strcmp(m, "xor") == 0 &&
                           o0.kind == HLO_REG && o0.reg >= 0 && o0.reg < 16 &&
                           o1.kind == HLO_REG &&
                           (o1.reg == fn->sp_reg || o1.reg == fn->bp_reg ||
                            (pre_areg >= 0 && o1.reg == pre_areg)) &&
                           cnd[o0.reg].ins1 >= 0) {
                    cnd[o0.reg].xored = 1;
                    cnd[o0.reg].ins2  = (int)gidx;
                } else if (!fn->has_canary && hl_is_mov_mnem(m) &&
                           o0.kind == HLO_MEM && o1.kind == HLO_REG &&
                           o1.reg >= 0 && o1.reg < 16 && cnd[o1.reg].ins1 >= 0) {
                    int64_t soff = 0;
                    if (hl_mem_to_stack_off_ex(fn, &o0, pre_sp, pre_bp, pre_has_bp, pre_areg, pre_adelta, &soff)) {
                        const char *csym = cnd[o1.reg].is_tls ? NULL : ana_sym_at(fn->a, cnd[o1.reg].va);
                        int match = cnd[o1.reg].is_tls ||
                                    cnd[o1.reg].xored ||
                                    (fn->a->bin.sec_cookie != 0 && cnd[o1.reg].va == fn->a->bin.sec_cookie) ||
                                    hl_is_cookie_sym(csym);
                        if (match) {
                            fn->has_canary = 1;
                            fn->canary_off = soff;
                            c->skip_ins[cnd[o1.reg].ins1] = 1;
                            if (cnd[o1.reg].ins2 >= 0) c->skip_ins[cnd[o1.reg].ins2] = 1;
                            c->skip_ins[gidx] = 1;
                            cnd[o1.reg].ins1 = -1;
                            continue;
                        }
                    }
                } else if (o0.kind == HLO_REG && o0.reg >= 0 && o0.reg < 16 &&
                           strcmp(m, "cmp") != 0 && strcmp(m, "test") != 0 && strcmp(m, "bt") != 0) {
                    cnd[o0.reg].ins1 = -1;
                }

                if (strcmp(m, "mov") == 0 && o0.kind == HLO_REG && o0.reg == 0 && o1.kind == HLO_IMM) {
                    last_eax_ins = (int)gidx;
                } else if (o0.kind == HLO_REG && o0.reg == 0) {
                    last_eax_ins = -1;
                }

                hl_step_sp_x86(fn, m, &o0, &o1, &sp, &bp, &has_bp, &last_eax, &alias_reg, &alias_delta);
                if (o0.kind == HLO_REG && o0.reg >= 0 && o0.reg < HL_LIFT_REGS &&
                    strcmp(m, "cmp") != 0 && strcmp(m, "test") != 0 && strcmp(m, "bt") != 0 &&
                    strcmp(m, "push") != 0) {
                    reg_unmod[o0.reg] = 0;
                }
            } else {
                /* ARM64 prologue */
                if (in->flow == X86_FLOW_CALL) seen_real_call = 1;
                if ((strcmp(m, "sub") == 0 || strcmp(m, "add") == 0) &&
                    o0.kind == HLO_REG && o0.reg == fn->sp_reg &&
                    o1.kind == HLO_REG && o1.reg == fn->sp_reg && o2.kind == HLO_IMM) {
                    c->skip_ins[gidx] = 1;
                    hl_step_sp_a64(fn, m, &o0, &o1, &o2, &o3, nops, &sp, &bp, &has_bp);
                    continue;
                }
                if ((strcmp(m, "mov") == 0 || strcmp(m, "add") == 0) &&
                    o0.kind == HLO_REG && o0.reg == fn->bp_reg &&
                    o1.kind == HLO_REG && o1.reg == fn->sp_reg) {
                    c->skip_ins[gidx] = 1;
                    hl_step_sp_a64(fn, m, &o0, &o1, &o2, &o3, nops, &sp, &bp, &has_bp);
                    reg_unmod[fn->bp_reg] = 0;
                    continue;
                }
                if (!seen_real_call && strcmp(m, "stp") == 0 && o2.kind == HLO_MEM && o2.reg == fn->sp_reg) {
                    int r1 = (o0.kind == HLO_REG) ? o0.reg : -1;
                    int r2 = (o1.kind == HLO_REG) ? o1.reg : -1;
                    int s1 = (r1 >= 0 && r1 < HL_LIFT_REGS && (c->saved_reg_mask & (1ULL << r1)) && reg_unmod[r1]);
                    int s2 = (r2 >= 0 && r2 < HL_LIFT_REGS && (c->saved_reg_mask & (1ULL << r2)) && reg_unmod[r2]);
                    hl_step_sp_a64(fn, m, &o0, &o1, &o2, &o3, nops, &sp, &bp, &has_bp);
                    if (s1 && s2) {
                        int64_t base_off = (o2.a64_wb == 1) ? sp : (pre_sp + o2.disp);
                        int step = (o0.bits == 32) ? 4 : 8;
                        c->has_saved_slot[r1] = 1; c->saved_slot[r1] = base_off;
                        c->has_saved_slot[r2] = 1; c->saved_slot[r2] = base_off + step;
                        c->skip_ins[gidx] = 1;
                        continue;
                    }
                } else if (!seen_real_call && strcmp(m, "str") == 0 && o0.kind == HLO_REG &&
                           o1.kind == HLO_MEM && o1.reg == fn->sp_reg && o0.reg >= 0 && o0.reg < HL_LIFT_REGS &&
                           (c->saved_reg_mask & (1ULL << o0.reg)) && reg_unmod[o0.reg]) {
                    int64_t soff = pre_sp + o1.disp;
                    c->has_saved_slot[o0.reg] = 1;
                    c->saved_slot[o0.reg] = soff;
                    c->skip_ins[gidx] = 1;
                    continue;
                } else {
                    hl_step_sp_a64(fn, m, &o0, &o1, &o2, &o3, nops, &sp, &bp, &has_bp);
                }
                if (o0.kind == HLO_REG && o0.reg >= 0 && o0.reg < HL_LIFT_REGS &&
                    strcmp(m, "str") != 0 && strcmp(m, "strb") != 0 && strcmp(m, "strh") != 0 &&
                    strcmp(m, "stp") != 0 && strcmp(m, "cmp") != 0 && strcmp(m, "tst") != 0) {
                    reg_unmod[o0.reg] = 0;
                }
            }
        }
    }

    /* 4. All-blocks scan: epilogue restores, canary checks, stack frame cleanup, addr-taken stack slots */
    for (int b = 0; b < nb; b++) {
        if (!c->reach[b]) continue;
        int64_t sp = c->blk_sp_in[b];
        int64_t bp = c->blk_bp_in[b];
        int has_bp = c->blk_has_bp_in[b];
        int64_t last_eax = 0;
        int alias_reg = -1;
        int64_t alias_delta = 0;

        struct {
            int     ins1;
            int     ins2;
            int     xored;
            int64_t soff;
        } ecnd[16];
        for (int r = 0; r < 16; r++) { ecnd[r].ins1 = -1; ecnd[r].ins2 = -1; ecnd[r].xored = 0; ecnd[r].soff = 0; }

        const grp_blk *gb = &g->blks[b];
        for (uint32_t k = 0; k < gb->ins_count; k++) {
            uint32_t gidx = gb->ins_first + k;
            const x86_ins *in = &g->ins[gidx];
            char mn[24];
            hl_lower_copy(in->mnem, mn, sizeof(mn));
            const char *m = (strncmp(mn, "lock ", 5) == 0) ? (mn + 5) : mn;
            char ops[4][80];
            int nops = hl_split_ops(in->ops, ops);
            hl_opr o0, o1, o2, o3;
            hl_parse_opr(fn, ops[0], &o0);
            hl_parse_opr(fn, ops[1], &o1);
            hl_parse_opr(fn, ops[2], &o2);
            hl_parse_opr(fn, ops[3], &o3);

            int64_t pre_sp = sp;
            int64_t pre_bp = bp;
            int pre_has_bp = has_bp;
            int pre_areg = alias_reg;
            int64_t pre_adelta = alias_delta;

            if (c->skip_ins[gidx]) {
                if (fn->is_a64) hl_step_sp_a64(fn, m, &o0, &o1, &o2, &o3, nops, &sp, &bp, &has_bp);
                else hl_step_sp_x86(fn, m, &o0, &o1, &sp, &bp, &has_bp, &last_eax, &alias_reg, &alias_delta);
                continue;
            }

            if (!fn->is_a64) {
                /* Skip stack pointer adjustment / leave / mov rsp, bp or alias_reg anywhere */
                if (((strcmp(m, "add") == 0 || strcmp(m, "sub") == 0 || strcmp(m, "and") == 0) &&
                     o0.kind == HLO_REG && o0.reg == fn->sp_reg) ||
                    (strcmp(m, "lea") == 0 && o0.kind == HLO_REG && o0.reg == fn->sp_reg) ||
                    (strcmp(m, "mov") == 0 && o0.kind == HLO_REG && o0.reg == fn->sp_reg &&
                     o1.kind == HLO_REG && (o1.reg == fn->bp_reg || (pre_areg >= 0 && o1.reg == pre_areg))) ||
                    strcmp(m, "leave") == 0) {
                    c->skip_ins[gidx] = 1;
                    hl_step_sp_x86(fn, m, &o0, &o1, &sp, &bp, &has_bp, &last_eax, &alias_reg, &alias_delta);
                    continue;
                }

                /* Epilogue callee-saved restore: pop r or mov r, [saved_slot[r]] */
                if (strcmp(m, "pop") == 0 && o0.kind == HLO_REG &&
                    o0.reg >= 0 && o0.reg < HL_LIFT_REGS &&
                    c->has_saved_slot[o0.reg] &&
                    (pre_sp == c->saved_slot[o0.reg] || c->blk_is_epi[b])) {
                    c->skip_ins[gidx] = 1;
                    hl_step_sp_x86(fn, m, &o0, &o1, &sp, &bp, &has_bp, &last_eax, &alias_reg, &alias_delta);
                    continue;
                }
                if (hl_is_mov_mnem(m) && o0.kind == HLO_REG && o1.kind == HLO_MEM &&
                    o0.reg >= 0 && o0.reg < HL_LIFT_REGS && c->has_saved_slot[o0.reg]) {
                    int64_t soff = 0;
                    if (hl_mem_to_stack_off_ex(fn, &o1, pre_sp, pre_bp, pre_has_bp, pre_areg, pre_adelta, &soff) &&
                        soff == c->saved_slot[o0.reg]) {
                        c->skip_ins[gidx] = 1;
                        hl_step_sp_x86(fn, m, &o0, &o1, &sp, &bp, &has_bp, &last_eax, &alias_reg, &alias_delta);
                        continue;
                    }
                }

                /* Epilogue stack canary check detection (named or stripped!) */
                if (hl_is_mov_mnem(m) && o0.kind == HLO_REG && o0.reg >= 0 && o0.reg < 16 &&
                    o1.kind == HLO_MEM) {
                    int64_t soff = 0;
                    if (hl_mem_to_stack_off_ex(fn, &o1, pre_sp, pre_bp, pre_has_bp, pre_areg, pre_adelta, &soff) &&
                        ((fn->has_canary && soff == fn->canary_off) || (!fn->has_canary && c->blk_is_epi[b]))) {
                        ecnd[o0.reg].ins1  = (int)gidx;
                        ecnd[o0.reg].ins2  = -1;
                        ecnd[o0.reg].xored = 0;
                        ecnd[o0.reg].soff  = soff;
                    } else {
                        ecnd[o0.reg].ins1 = -1;
                    }
                } else if (strcmp(m, "xor") == 0 && o0.kind == HLO_REG && o0.reg >= 0 && o0.reg < 16 &&
                           o1.kind == HLO_REG &&
                           (o1.reg == fn->sp_reg || o1.reg == fn->bp_reg ||
                            (pre_areg >= 0 && o1.reg == pre_areg)) &&
                           ecnd[o0.reg].ins1 >= 0) {
                    ecnd[o0.reg].xored = 1;
                    ecnd[o0.reg].ins2  = (int)gidx;
                } else if (in->flow == X86_FLOW_CALL) {
                    const char *sym = in->has_target ? ana_sym_at(fn->a, in->target) : NULL;
                    int by_name = sym && strstr(sym, "security_check_cookie") != NULL;
                    int by_pat  = ecnd[1].ins1 >= 0 && ecnd[1].xored &&
                                  (fn->has_canary || c->blk_is_epi[b]);
                    if (by_name || by_pat) {
                        if (!fn->has_canary && ecnd[1].ins1 >= 0) {
                            fn->has_canary = 1;
                            fn->canary_off = ecnd[1].soff;
                        }
                        if (ecnd[1].ins1 >= 0) c->skip_ins[ecnd[1].ins1] = 1;
                        if (ecnd[1].ins2 >= 0) c->skip_ins[ecnd[1].ins2] = 1;
                        c->skip_ins[gidx] = 1;
                        ecnd[1].ins1 = -1;
                        continue;
                    }
                    if (alias_reg >= 0 && (c->vol_reg_mask & (1ULL << alias_reg))) alias_reg = -1;
                } else if ((strcmp(m, "sub") == 0 || strcmp(m, "xor") == 0 || strcmp(m, "cmp") == 0) &&
                           o0.kind == HLO_REG && o0.reg >= 0 && o0.reg < 16 &&
                           ecnd[o0.reg].ins1 >= 0 && o1.kind == HLO_MEM &&
                           (o1.seg == 'f' || o1.seg == 'g') && (o1.uval == 0x28 || o1.uval == 0x14)) {
                    if (!fn->has_canary) {
                        fn->has_canary = 1;
                        fn->canary_off = ecnd[o0.reg].soff;
                    }
                    c->skip_ins[ecnd[o0.reg].ins1] = 1;
                    c->skip_ins[gidx] = 1;
                    ecnd[o0.reg].ins1 = -1;
                    /* Also skip trailing jcc to __stack_chk_fail if present */
                    if (k + 1 < gb->ins_count) {
                        const x86_ins *nxt = &g->ins[gidx + 1];
                        if (nxt->flow == X86_FLOW_JCC) {
                            int t = fn->blks[b].out_t;
                            int f = fn->blks[b].out_f;
                            int t_fail = 0, f_fail = 0;
                            if (t >= 0) {
                                const grp_blk *tb = &g->blks[t];
                                for (uint32_t j = 0; j < tb->ins_count; j++) {
                                    const x86_ins *ti = &g->ins[tb->ins_first + j];
                                    if (ti->flow == X86_FLOW_CALL && ti->has_target &&
                                        hl_is_stack_chk_sym(ana_sym_at(fn->a, ti->target))) t_fail = 1;
                                }
                            }
                            if (f >= 0) {
                                const grp_blk *fb = &g->blks[f];
                                for (uint32_t j = 0; j < fb->ins_count; j++) {
                                    const x86_ins *fi = &g->ins[fb->ins_first + j];
                                    if (fi->flow == X86_FLOW_CALL && fi->has_target &&
                                        hl_is_stack_chk_sym(ana_sym_at(fn->a, fi->target))) f_fail = 1;
                                }
                            }
                            if (t_fail != f_fail) {
                                c->skip_ins[gidx + 1] = 1;
                                fn->blks[b].out_u = t_fail ? f : t;
                                fn->blks[b].out_t = -1;
                                fn->blks[b].out_f = -1;
                            }
                        }
                    }
                    continue;
                }

                /* Record address-taken local stack slots (`lea reg, [rsp/rbp/alias+disp]`) */
                if (strcmp(m, "lea") == 0 && o0.kind == HLO_REG && o1.kind == HLO_MEM) {
                    int64_t soff = 0;
                    if (hl_mem_to_stack_off_ex(fn, &o1, pre_sp, pre_bp, pre_has_bp, pre_areg, pre_adelta, &soff)) {
                        int si = hl_find_or_add_stk_slot(c, soff, fn->ptr_bits, 0, 0);
                        if (si >= 0) c->stk_slots[si].addr_taken = 1;
                    }
                }

                /* Track stack writes so we know which positive offsets are written vs caller args */
                if (o0.kind == HLO_MEM) {
                    int64_t soff = 0;
                    if (hl_mem_to_stack_off_ex(fn, &o0, pre_sp, pre_bp, pre_has_bp, pre_areg, pre_adelta, &soff)) {
                        int si = hl_find_or_add_stk_slot(c, soff, o0.bits ? o0.bits : fn->ptr_bits, 0, 0);
                        if (si >= 0) c->stk_slots[si].written = 1;
                    }
                }

                hl_step_sp_x86(fn, m, &o0, &o1, &sp, &bp, &has_bp, &last_eax, &alias_reg, &alias_delta);
            } else {
                /* ARM64 epilogue restores & SP restores */
                if ((strcmp(m, "add") == 0 || strcmp(m, "sub") == 0) &&
                    o0.kind == HLO_REG && o0.reg == fn->sp_reg &&
                    o1.kind == HLO_REG && o1.reg == fn->sp_reg) {
                    c->skip_ins[gidx] = 1;
                    hl_step_sp_a64(fn, m, &o0, &o1, &o2, &o3, nops, &sp, &bp, &has_bp);
                    continue;
                }
                if (strcmp(m, "mov") == 0 && o0.kind == HLO_REG && o0.reg == fn->sp_reg &&
                    o1.kind == HLO_REG && o1.reg == fn->bp_reg) {
                    c->skip_ins[gidx] = 1;
                    hl_step_sp_a64(fn, m, &o0, &o1, &o2, &o3, nops, &sp, &bp, &has_bp);
                    continue;
                }
                if (strcmp(m, "ldp") == 0 && o2.kind == HLO_MEM && o2.reg == fn->sp_reg) {
                    int r1 = (o0.kind == HLO_REG) ? o0.reg : -1;
                    int r2 = (o1.kind == HLO_REG) ? o1.reg : -1;
                    int64_t base_off = (o2.a64_wb == 1) ? (pre_sp + o2.disp) : (pre_sp + o2.disp);
                    int m1 = (r1 >= 0 && r1 < HL_LIFT_REGS && c->has_saved_slot[r1] &&
                              (c->saved_slot[r1] == base_off || c->blk_is_epi[b]));
                    int m2 = (r2 >= 0 && r2 < HL_LIFT_REGS && c->has_saved_slot[r2] && c->blk_is_epi[b]);
                    if (m1 && m2) {
                        c->skip_ins[gidx] = 1;
                        hl_step_sp_a64(fn, m, &o0, &o1, &o2, &o3, nops, &sp, &bp, &has_bp);
                        continue;
                    }
                }
                if (strcmp(m, "ldr") == 0 && o0.kind == HLO_REG && o1.kind == HLO_MEM &&
                    o1.reg == fn->sp_reg && o0.reg >= 0 && o0.reg < HL_LIFT_REGS &&
                    c->has_saved_slot[o0.reg] && (pre_sp + o1.disp == c->saved_slot[o0.reg])) {
                    c->skip_ins[gidx] = 1;
                    hl_step_sp_a64(fn, m, &o0, &o1, &o2, &o3, nops, &sp, &bp, &has_bp);
                    continue;
                }
                if (strcmp(m, "add") == 0 && o0.kind == HLO_REG && o1.kind == HLO_REG &&
                    (o1.reg == fn->sp_reg || (pre_has_bp && o1.reg == fn->bp_reg)) &&
                    o2.kind == HLO_IMM && o0.reg != fn->sp_reg && o0.reg != fn->bp_reg) {
                    int64_t soff = ((o1.reg == fn->sp_reg) ? pre_sp : pre_bp) + o2.disp;
                    int si = hl_find_or_add_stk_slot(c, soff, 64, 0, 0);
                    if (si >= 0) c->stk_slots[si].addr_taken = 1;
                }
                hl_step_sp_a64(fn, m, &o0, &o1, &o2, &o3, nops, &sp, &bp, &has_bp);
            }
        }
    }
}

/* =========================================================================
 * Liveness Analysis & Pruned SSA PHI Insertion
 * ========================================================================= */

static void hl_mark_opr_reads(const hl_lift_ctx *c, const hl_opr *op,
                              uint64_t *use_m, uint64_t def_m) {
    int sp = c->fn->sp_reg;
    int bp = c->uses_fp ? c->fn->bp_reg : -1;
    if (op->kind == HLO_REG && op->reg >= 0 && op->reg < c->nregs) {
        if (op->reg != sp && op->reg != bp && !(def_m & (1ULL << op->reg))) {
            *use_m |= (1ULL << op->reg);
        }
    } else if (op->kind == HLO_MEM) {
        if (op->reg >= 0 && op->reg < c->nregs && op->reg != sp && op->reg != bp &&
            !(def_m & (1ULL << op->reg))) {
            *use_m |= (1ULL << op->reg);
        }
        if (op->idx >= 0 && op->idx < c->nregs && op->idx != sp && op->idx != bp &&
            !(def_m & (1ULL << op->idx))) {
            *use_m |= (1ULL << op->idx);
        }
    }
}

static void hl_mark_reg_def(hl_lift_ctx *c, int b, int r, uint64_t *def_m) {
    if (r < 0 || r >= c->nregs) return;
    if (r == c->fn->sp_reg || (c->uses_fp && r == c->fn->bp_reg)) return;
    *def_m |= (1ULL << r);
    hl_bs_set(c->def_blks[r], b);
}

static void hl_insert_phis(hl_lift_ctx *c) {
    hl_fn *fn = c->fn;
    const grp_cfg *g = fn->g;
    int nb = fn->nblk;

    for (int b = 0; b < nb; b++) {
        for (int r = 0; r < HL_LIFT_REGS; r++) c->phi_stmt[b][r] = -1;
        if (!c->reach[b]) continue;

        uint64_t use_m = 0, def_m = 0;
        const grp_blk *gb = &g->blks[b];

        for (uint32_t k = 0; k < gb->ins_count; k++) {
            uint32_t gidx = gb->ins_first + k;
            if (c->skip_ins[gidx]) continue;
            const x86_ins *in = &g->ins[gidx];
            char mn[24];
            hl_lower_copy(in->mnem, mn, sizeof(mn));
            const char *m = (strncmp(mn, "lock ", 5) == 0) ? (mn + 5) : mn;
            char ops[4][80];
            int nops = hl_split_ops(in->ops, ops);
            hl_opr o0, o1, o2, o3;
            hl_parse_opr(fn, ops[0], &o0);
            hl_parse_opr(fn, ops[1], &o1);
            hl_parse_opr(fn, ops[2], &o2);
            hl_parse_opr(fn, ops[3], &o3);

            if (in->flow == X86_FLOW_CALL) {
                if (!in->has_target || in->target_mem) hl_mark_opr_reads(c, &o0, &use_m, def_m);
                /* Calls may read ABI arg regs & clobber volatile regs */
                for (int ai = 0; ai < fn->narg_abi; ai++) {
                    int ar = fn->arg_regs[ai];
                    if (ar >= 0 && ar < c->nregs && !(def_m & (1ULL << ar))) use_m |= (1ULL << ar);
                }
                hl_mark_reg_def(c, b, fn->ret_reg, &def_m);
                hl_mark_reg_def(c, b, c->flt_ret_reg, &def_m);
                def_m |= c->vol_reg_mask;
                continue;
            }
            if (in->flow == X86_FLOW_RET) {
                if (!(def_m & (1ULL << fn->ret_reg))) use_m |= (1ULL << fn->ret_reg);
                if (c->flt_ret_reg >= 0 && !(def_m & (1ULL << c->flt_ret_reg))) {
                    use_m |= (1ULL << c->flt_ret_reg);
                }
                continue;
            }
            if (in->flow == X86_FLOW_JMP) {
                if (!in->has_target || in->target_mem) hl_mark_opr_reads(c, &o0, &use_m, def_m);
                if (fn->blks[b].out_u < 0 && fn->blks[b].sw_idx < 0) {
                    /* Tail call reads ABI args */
                    for (int ai = 0; ai < fn->narg_abi; ai++) {
                        int ar = fn->arg_regs[ai];
                        if (ar >= 0 && ar < c->nregs && !(def_m & (1ULL << ar))) use_m |= (1ULL << ar);
                    }
                }
                continue;
            }
            if (in->flow == X86_FLOW_JCC) {
                if (!fn->is_a64) {
                    if (strcmp(m, "jrcxz") == 0 || strcmp(m, "jecxz") == 0 || strncmp(m, "loop", 4) == 0) {
                        if (!(def_m & (1ULL << 1))) use_m |= (1ULL << 1);
                        if (strncmp(m, "loop", 4) == 0) hl_mark_reg_def(c, b, 1, &def_m);
                    }
                } else {
                    if (strcmp(m, "cbz") == 0 || strcmp(m, "cbnz") == 0 ||
                        strcmp(m, "tbz") == 0 || strcmp(m, "tbnz") == 0) {
                        hl_mark_opr_reads(c, &o0, &use_m, def_m);
                    }
                }
                continue;
            }

            if (!fn->is_a64) {
                if (strncmp(m, "rep ", 4) == 0) {
                    const char *sm = m + 4;
                    if (strncmp(sm, "movs", 4) == 0) {
                        int rs[3] = {7, 6, 1};
                        for (int i = 0; i < 3; i++) {
                            if (!(def_m & (1ULL << rs[i]))) use_m |= (1ULL << rs[i]);
                            hl_mark_reg_def(c, b, rs[i], &def_m);
                        }
                    } else if (strncmp(sm, "stos", 4) == 0) {
                        int rs[3] = {7, 0, 1};
                        for (int i = 0; i < 3; i++) {
                            if (!(def_m & (1ULL << rs[i]))) use_m |= (1ULL << rs[i]);
                        }
                        hl_mark_reg_def(c, b, 7, &def_m);
                        hl_mark_reg_def(c, b, 1, &def_m);
                    }
                    continue;
                }
                if (strcmp(m, "cmp") == 0 || strcmp(m, "test") == 0 || strcmp(m, "bt") == 0 ||
                    strstr(m, "comis") != NULL) {
                    hl_mark_opr_reads(c, &o0, &use_m, def_m);
                    hl_mark_opr_reads(c, &o1, &use_m, def_m);
                    continue;
                }
                if (strcmp(m, "push") == 0) {
                    hl_mark_opr_reads(c, &o0, &use_m, def_m);
                    continue;
                }
                if (strcmp(m, "cdqe") == 0 || strcmp(m, "cwde") == 0 || strcmp(m, "cbw") == 0) {
                    if (!(def_m & 1ULL)) use_m |= 1ULL;
                    hl_mark_reg_def(c, b, 0, &def_m);
                    continue;
                }
                if (strcmp(m, "cdq") == 0 || strcmp(m, "cqo") == 0 || strcmp(m, "cwd") == 0) {
                    if (!(def_m & 1ULL)) use_m |= 1ULL;
                    hl_mark_reg_def(c, b, 2, &def_m);
                    continue;
                }
                if ((strcmp(m, "mul") == 0 || strcmp(m, "imul") == 0) && nops == 1) {
                    if (!(def_m & 1ULL)) use_m |= 1ULL;
                    hl_mark_opr_reads(c, &o0, &use_m, def_m);
                    hl_mark_reg_def(c, b, 0, &def_m);
                    hl_mark_reg_def(c, b, 2, &def_m);
                    continue;
                }
                if (strcmp(m, "div") == 0 || strcmp(m, "idiv") == 0) {
                    if (!(def_m & 1ULL)) use_m |= 1ULL;
                    if (!(def_m & (1ULL << 2))) use_m |= (1ULL << 2);
                    hl_mark_opr_reads(c, &o0, &use_m, def_m);
                    hl_mark_reg_def(c, b, 0, &def_m);
                    hl_mark_reg_def(c, b, 2, &def_m);
                    continue;
                }
                /* Zeroing idioms: xor r,r / sub r,r / sbb r,r / pxor x,x / xorps x,x / xorpd x,x */
                if ((strcmp(m, "xor") == 0 || strcmp(m, "sub") == 0 || strcmp(m, "sbb") == 0 ||
                     strcmp(m, "pxor") == 0 || strcmp(m, "xorps") == 0 || strcmp(m, "xorpd") == 0) &&
                    o0.kind == HLO_REG && o1.kind == HLO_REG && o0.reg == o1.reg) {
                    hl_mark_reg_def(c, b, o0.reg, &def_m);
                    continue;
                }
                if (strcmp(m, "xchg") == 0 || strcmp(m, "xadd") == 0) {
                    hl_mark_opr_reads(c, &o0, &use_m, def_m);
                    hl_mark_opr_reads(c, &o1, &use_m, def_m);
                    if (o0.kind == HLO_REG) hl_mark_reg_def(c, b, o0.reg, &def_m);
                    if (o1.kind == HLO_REG) hl_mark_reg_def(c, b, o1.reg, &def_m);
                    continue;
                }
                /* Pure overwrite ops (do not read o0 when o0 is a reg) */
                int pure_def = hl_is_mov_mnem(m) || strcmp(m, "lea") == 0 ||
                               strcmp(m, "movzx") == 0 || strcmp(m, "movsx") == 0 || strcmp(m, "movsxd") == 0 ||
                               strcmp(m, "pop") == 0 || strncmp(m, "set", 3) == 0 ||
                               strncmp(m, "cvt", 3) == 0 || strcmp(m, "popcnt") == 0 ||
                               strcmp(m, "bsf") == 0 || strcmp(m, "bsr") == 0 ||
                               strcmp(m, "tzcnt") == 0 || strcmp(m, "lzcnt") == 0 ||
                               strcmp(m, "sqrtss") == 0 || strcmp(m, "sqrtsd") == 0 ||
                               (strcmp(m, "imul") == 0 && nops == 3) ||
                               (m[0] == 'v' && nops == 3 &&
                                strncmp(m, "vfm", 3) != 0 && strncmp(m, "vfnm", 4) != 0);

                if (o0.kind == HLO_MEM) {
                    hl_mark_opr_reads(c, &o0, &use_m, def_m);
                    hl_mark_opr_reads(c, &o1, &use_m, def_m);
                    hl_mark_opr_reads(c, &o2, &use_m, def_m);
                } else if (o0.kind == HLO_REG) {
                    if (!pure_def) hl_mark_opr_reads(c, &o0, &use_m, def_m);
                    hl_mark_opr_reads(c, &o1, &use_m, def_m);
                    hl_mark_opr_reads(c, &o2, &use_m, def_m);
                    hl_mark_reg_def(c, b, o0.reg, &def_m);
                }
            } else {
                /* ARM64 use/def */
                if (strcmp(m, "cmp") == 0 || strcmp(m, "cmn") == 0 || strcmp(m, "tst") == 0 || strcmp(m, "fcmp") == 0) {
                    hl_mark_opr_reads(c, &o0, &use_m, def_m);
                    hl_mark_opr_reads(c, &o1, &use_m, def_m);
                    continue;
                }
                if (strcmp(m, "str") == 0 || strcmp(m, "strb") == 0 || strcmp(m, "strh") == 0) {
                    hl_mark_opr_reads(c, &o0, &use_m, def_m);
                    hl_mark_opr_reads(c, &o1, &use_m, def_m);
                    continue;
                }
                if (strcmp(m, "stp") == 0) {
                    hl_mark_opr_reads(c, &o0, &use_m, def_m);
                    hl_mark_opr_reads(c, &o1, &use_m, def_m);
                    hl_mark_opr_reads(c, &o2, &use_m, def_m);
                    continue;
                }
                if (strcmp(m, "ldp") == 0) {
                    hl_mark_opr_reads(c, &o2, &use_m, def_m);
                    if (o0.kind == HLO_REG) hl_mark_reg_def(c, b, o0.reg, &def_m);
                    if (o1.kind == HLO_REG) hl_mark_reg_def(c, b, o1.reg, &def_m);
                    continue;
                }
                if (strcmp(m, "movk") == 0 && o0.kind == HLO_REG) {
                    hl_mark_opr_reads(c, &o0, &use_m, def_m);
                    hl_mark_reg_def(c, b, o0.reg, &def_m);
                    continue;
                }
                if (o0.kind == HLO_REG) {
                    hl_mark_opr_reads(c, &o1, &use_m, def_m);
                    hl_mark_opr_reads(c, &o2, &use_m, def_m);
                    hl_mark_opr_reads(c, &o3, &use_m, def_m);
                    hl_mark_reg_def(c, b, o0.reg, &def_m);
                }
            }
        }

        c->blk_use_reg[b] = use_m;
        c->blk_def_reg[b] = def_m;
    }

    /* Standard backward liveness fixpoint */
    int changed = 1;
    while (changed) {
        changed = 0;
        for (int b = nb - 1; b >= 0; b--) {
            if (!c->reach[b]) continue;
            uint64_t out_m = 0;
            for (int s = 0; s < nb; s++) {
                if (c->reach[s] && hl_bs_get(c->succ_bs[b], s)) {
                    out_m |= c->live_in_reg[s];
                }
            }
            uint64_t in_m = c->blk_use_reg[b] | (out_m & ~c->blk_def_reg[b]);
            if (in_m != c->live_in_reg[b] || out_m != c->live_out_reg[b]) {
                c->live_in_reg[b]  = in_m;
                c->live_out_reg[b] = out_m;
                changed = 1;
            }
        }
    }

    /* Iterated Dominance Frontier Pruned PHI insertion */
    int *wl = (int *)malloc((size_t)(nb > 0 ? nb : 1) * sizeof(int));
    uint8_t *in_wl = (uint8_t *)calloc((size_t)(nb > 0 ? nb : 1), 1);
    uint8_t *has_phi = (uint8_t *)calloc((size_t)(nb > 0 ? nb : 1), 1);
    if (wl && in_wl && has_phi) {
        for (int r = 0; r < c->nregs; r++) {
            if (r == fn->sp_reg || (c->uses_fp && r == fn->bp_reg)) continue;

            int wh = 0, wt = 0;
            memset(in_wl, 0, (size_t)nb);
            memset(has_phi, 0, (size_t)nb);

            for (int b = 0; b < nb; b++) {
                if (c->reach[b] && hl_bs_get(c->def_blks[r], b)) {
                    wl[wt++] = b;
                    in_wl[b] = 1;
                }
            }

            int is_flt_reg = (!fn->is_a64 && r >= 16) || (fn->is_a64 && r >= 32);
            while (wh < wt) {
                int x = wl[wh++];
                for (int y = 0; y < nb; y++) {
                    if (!c->reach[y] || !hl_bs_get(c->df_bs[x], y)) continue;
                    if (has_phi[y]) continue;
                    /* Pruned SSA: only insert PHI if register r is live-in to block y */
                    if (!(c->live_in_reg[y] & (1ULL << r))) continue;
                    has_phi[y] = 1;

                    int pv = hl_var_new(fn, fn->ptr_bits, r, is_flt_reg);
                    if (pv < 0) continue;
                    fn->vars[pv].ssa_ver = ++c->reg_next_ver[r];
                    int sid = hl_stmt_new(fn, y, fn->blks[y].start, HLS_PHI);
                    if (sid >= 0) {
                        fn->stmts[sid].dst_var = pv;
                        c->phi_stmt[y][r] = sid;
                        hl_record_var_def(c, pv, sid);
                    }

                    if (!in_wl[y]) {
                        in_wl[y] = 1;
                        wl[wt++] = y;
                    }
                }
            }
        }
    }
    free(wl);
    free(in_wl);
    free(has_phi);
}

/* =========================================================================
 * Condition Code Evaluation & Expression Lifting Helpers
 * ========================================================================= */

typedef enum {
    HLCC_NONE = 0,
    HLCC_EQ,
    HLCC_NE,
    HLCC_SLT,
    HLCC_SLE,
    HLCC_SGT,
    HLCC_SGE,
    HLCC_ULT,
    HLCC_ULE,
    HLCC_UGT,
    HLCC_UGE,
    HLCC_NEG,
    HLCC_POS
} hl_cc_kind;

static int hl_parse_cc(const char *raw, int is_a64) {
    if (!raw || !raw[0]) return HLCC_NONE;
    if (strcmp(raw, "e") == 0 || strcmp(raw, "z") == 0 || strcmp(raw, "eq") == 0) return HLCC_EQ;
    if (strcmp(raw, "ne") == 0 || strcmp(raw, "nz") == 0) return HLCC_NE;
    if (strcmp(raw, "l") == 0 || strcmp(raw, "nge") == 0 || strcmp(raw, "lt") == 0) return HLCC_SLT;
    if (strcmp(raw, "le") == 0 || strcmp(raw, "ng") == 0) return HLCC_SLE;
    if (strcmp(raw, "g") == 0 || strcmp(raw, "nle") == 0 || strcmp(raw, "gt") == 0) return HLCC_SGT;
    if (strcmp(raw, "ge") == 0 || strcmp(raw, "nl") == 0) return HLCC_SGE;
    if (is_a64) {
        if (strcmp(raw, "cc") == 0 || strcmp(raw, "lo") == 0) return HLCC_ULT;
        if (strcmp(raw, "cs") == 0 || strcmp(raw, "hs") == 0) return HLCC_UGE;
    } else {
        if (strcmp(raw, "b") == 0 || strcmp(raw, "c") == 0 || strcmp(raw, "nae") == 0) return HLCC_ULT;
        if (strcmp(raw, "ae") == 0 || strcmp(raw, "nb") == 0 || strcmp(raw, "nc") == 0) return HLCC_UGE;
    }
    if (strcmp(raw, "be") == 0 || strcmp(raw, "na") == 0 || strcmp(raw, "ls") == 0) return HLCC_ULE;
    if (strcmp(raw, "a") == 0 || strcmp(raw, "nbe") == 0 || strcmp(raw, "hi") == 0) return HLCC_UGT;
    if (strcmp(raw, "s") == 0 || strcmp(raw, "mi") == 0) return HLCC_NEG;
    if (strcmp(raw, "ns") == 0 || strcmp(raw, "pl") == 0) return HLCC_POS;
    return HLCC_NONE;
}

static uint8_t hl_cc_to_binop(int cc, int is_flt) {
    if (is_flt) {
        switch (cc) {
        case HLCC_EQ:  return HLB_EQ;
        case HLCC_NE:  return HLB_NE;
        case HLCC_ULT: case HLCC_SLT: return HLB_SLT;
        case HLCC_ULE: case HLCC_SLE: return HLB_SLE;
        case HLCC_UGT: case HLCC_SGT: return HLB_SGT;
        case HLCC_UGE: case HLCC_SGE: return HLB_SGE;
        default:       return HLB_NE;
        }
    }
    switch (cc) {
    case HLCC_EQ:  return HLB_EQ;
    case HLCC_NE:  return HLB_NE;
    case HLCC_SLT: return HLB_SLT;
    case HLCC_SLE: return HLB_SLE;
    case HLCC_SGT: return HLB_SGT;
    case HLCC_SGE: return HLB_SGE;
    case HLCC_ULT: return HLB_ULT;
    case HLCC_ULE: return HLB_ULE;
    case HLCC_UGT: return HLB_UGT;
    case HLCC_UGE: return HLB_UGE;
    default:       return HLB_NE;
    }
}

static int hl_eval_cc(hl_fn *fn, const hl_flag_state *fl, const char *cc_raw) {
    int cc = hl_parse_cc(cc_raw, fn->is_a64);
    if (!fl || fl->kind == HLF_NONE || cc == HLCC_NONE) {
        return hl_expr_int(fn, 1, 1, 0);
    }

    int bw = fl->bits > 0 ? fl->bits : fn->ptr_bits;

    if (fl->kind == HLF_BT) {
        int m_e = hl_expr_clone(fn, fl->lhs_expr);
        int i_e = hl_expr_clone(fn, fl->rhs_expr);
        int bs  = hl_expr_new(fn, HLE_BITSET);
        if (bs >= 0) {
            fn->exprs[bs].sub0 = i_e;
            fn->exprs[bs].sub1 = m_e;
            fn->exprs[bs].bits = (uint8_t)bw;
            if (m_e >= 0 && fn->exprs[m_e].kind == HLE_INT) {
                fn->exprs[bs].uval = fn->exprs[m_e].uval;
            }
        }
        if (cc == HLCC_UGE) return hl_expr_invert(fn, bs);
        return bs;
    }

    if (fl->kind == HLF_FCMP) {
        int l = hl_expr_clone(fn, fl->lhs_expr);
        int r = hl_expr_clone(fn, fl->rhs_expr);
        int id = hl_expr_binop(fn, hl_cc_to_binop(cc, 1), l, r, 1);
        if (id >= 0) fn->exprs[id].is_flt = 1;
        return id;
    }

    if (fl->kind == HLF_TEST) {
        int same = hl_expr_eq(fn, fl->lhs_expr, fl->rhs_expr, 0);
        int lhs = same ? hl_expr_clone(fn, fl->lhs_expr)
                       : hl_expr_binop(fn, HLB_AND, hl_expr_clone(fn, fl->lhs_expr),
                                       hl_expr_clone(fn, fl->rhs_expr), bw);
        int zero = hl_expr_int(fn, 0, bw, (cc == HLCC_NEG || cc == HLCC_POS ||
                                           cc == HLCC_SLT || cc == HLCC_SLE ||
                                           cc == HLCC_SGT || cc == HLCC_SGE));
        uint8_t bop = HLB_NE;
        if (cc == HLCC_EQ) bop = HLB_EQ;
        else if (cc == HLCC_NE) bop = HLB_NE;
        else if (cc == HLCC_NEG || cc == HLCC_SLT) bop = HLB_SLT;
        else if (cc == HLCC_POS || cc == HLCC_SGE) bop = HLB_SGE;
        else if (cc == HLCC_SLE) bop = HLB_SLE;
        else if (cc == HLCC_SGT) bop = HLB_SGT;
        return hl_expr_binop(fn, bop, lhs, zero, 1);
    }

    if (fl->kind == HLF_NEG) {
        int l = hl_expr_clone(fn, fl->lhs_expr);
        int z = hl_expr_int(fn, 0, bw, 0);
        /* neg x sets CF = (x != 0), ZF = (x == 0) */
        if (cc == HLCC_ULT || cc == HLCC_NE) return hl_expr_binop(fn, HLB_NE, l, z, 1);
        if (cc == HLCC_UGE || cc == HLCC_EQ) return hl_expr_binop(fn, HLB_EQ, l, z, 1);
        int r = (fl->res_expr >= 0) ? hl_expr_clone(fn, fl->res_expr) : hl_expr_unop(fn, HLU_NEG, l, bw);
        uint8_t bop = (cc == HLCC_NEG || cc == HLCC_SLT) ? HLB_SLT :
                      (cc == HLCC_POS || cc == HLCC_SGE) ? HLB_SGE : hl_cc_to_binop(cc, 0);
        return hl_expr_binop(fn, bop, r, z, 1);
    }

    if (fl->kind == HLF_ZERO) {
        int l = hl_expr_clone(fn, fl->res_expr >= 0 ? fl->res_expr : fl->lhs_expr);
        int is_s = (cc == HLCC_NEG || cc == HLCC_POS ||
                    cc == HLCC_SLT || cc == HLCC_SLE || cc == HLCC_SGT || cc == HLCC_SGE);
        int z = hl_expr_int(fn, 0, bw, is_s);
        uint8_t bop = HLB_NE;
        if (cc == HLCC_EQ) bop = HLB_EQ;
        else if (cc == HLCC_NE) bop = HLB_NE;
        else if (cc == HLCC_NEG || cc == HLCC_SLT) bop = HLB_SLT;
        else if (cc == HLCC_POS || cc == HLCC_SGE) bop = HLB_SGE;
        else if (cc == HLCC_SLE) bop = HLB_SLE;
        else if (cc == HLCC_SGT) bop = HLB_SGT;
        else bop = hl_cc_to_binop(cc, 0);
        return hl_expr_binop(fn, bop, l, z, 1);
    }

    if (fl->kind == HLF_CMN) {
        int l = hl_expr_clone(fn, fl->lhs_expr);
        int r = hl_expr_unop(fn, HLU_NEG, hl_expr_clone(fn, fl->rhs_expr), bw);
        return hl_expr_binop(fn, hl_cc_to_binop(cc, 0), l, r, 1);
    }

    /* HLF_CMP (cmp or sub) */
    if (fl->res_expr >= 0 && (cc == HLCC_EQ || cc == HLCC_NE) &&
        fl->rhs_expr >= 0 && fn->exprs[fl->rhs_expr].kind == HLE_INT &&
        fn->exprs[fl->rhs_expr].uval == 1ULL) {
        /* sub reg, 1; jne -> new_reg != 0 (loop decrement idiom) */
        int l = hl_expr_clone(fn, fl->res_expr);
        int z = hl_expr_int(fn, 0, bw, 0);
        return hl_expr_binop(fn, (cc == HLCC_EQ) ? HLB_EQ : HLB_NE, l, z, 1);
    }
    if (cc == HLCC_NEG || cc == HLCC_POS) {
        int l = hl_expr_clone(fn, fl->lhs_expr);
        int r = hl_expr_clone(fn, fl->rhs_expr);
        int diff = (r >= 0 && fn->exprs[r].kind == HLE_INT && fn->exprs[r].uval == 0)
                 ? l : hl_expr_binop(fn, HLB_SUB, l, r, bw);
        int z = hl_expr_int(fn, 0, bw, 1);
        return hl_expr_binop(fn, (cc == HLCC_NEG) ? HLB_SLT : HLB_SGE, diff, z, 1);
    }
    int l = hl_expr_clone(fn, fl->lhs_expr);
    int r = hl_expr_clone(fn, fl->rhs_expr);
    return hl_expr_binop(fn, hl_cc_to_binop(cc, 0), l, r, 1);
}

static int hl_eval_cf(hl_fn *fn, const hl_flag_state *fl) {
    if (!fl || fl->kind == HLF_NONE) return -1;
    if (fl->kind == HLF_BT)  return hl_eval_cc(fn, fl, "b");
    if (fl->kind == HLF_CMP) return hl_eval_cc(fn, fl, "b");
    if (fl->kind == HLF_NEG) return hl_eval_cc(fn, fl, "b");
    return -1;
}

static int hl_get_reg_var(hl_lift_ctx *c, int r, int bits, int is_flt) {
    if (r < 0 || r >= c->nregs) return -1;
    int top = hl_reg_stk_top(c, r);
    if (top >= 0) return top;
    if (c->entry_var[r] < 0) {
        int is_f = is_flt || (!c->fn->is_a64 && r >= 16) || (c->fn->is_a64 && r >= 32);
        int bw = (bits > 0 && bits <= 64) ? bits : c->fn->ptr_bits;
        int vid = hl_var_new(c->fn, bw, r, is_f);
        c->entry_var[r] = vid;
    }
    return c->entry_var[r];
}

static int hl_read_reg_expr(hl_lift_ctx *c, int r, int bits, int is_flt, int is_hi8) {
    int vid = hl_get_reg_var(c, r, bits, is_flt);
    if (vid < 0) return hl_expr_int(c->fn, 0, bits > 0 ? bits : c->fn->ptr_bits, 0);
    int e = hl_expr_var(c->fn, vid);
    if (e >= 0) {
        if (bits > 0 && bits <= 64) c->fn->exprs[e].bits = (uint8_t)bits;
        if (is_flt) c->fn->exprs[e].is_flt = 1;
    }
    if (is_hi8) {
        int sh = hl_expr_binop(c->fn, HLB_SHR, e, hl_expr_int(c->fn, 8, 8, 0), 32);
        return hl_expr_binop(c->fn, HLB_AND, sh, hl_expr_int(c->fn, 0xFF, 8, 0), 8);
    }
    return e;
}

static int hl_def_reg(hl_lift_ctx *c, int bi, uint64_t va, int r, int bits, int is_flt, int rhs_eid) {
    hl_fn *fn = c->fn;
    if (r < 0 || r >= c->nregs || r == fn->sp_reg || (c->uses_fp && r == fn->bp_reg)) return -1;
    int bw = (bits > 0 && bits <= 64) ? bits : fn->ptr_bits;
    int is_f = is_flt || (!fn->is_a64 && r >= 16 && rhs_eid >= 0 && fn->exprs[rhs_eid].is_flt) ||
               (fn->is_a64 && r >= 32);
    int nv = hl_var_new(fn, bw, r, is_f);
    if (nv < 0) return -1;
    fn->vars[nv].ssa_ver = ++c->reg_next_ver[r];
    int sid = hl_stmt_new(fn, bi, va, HLS_ASSIGN);
    if (sid >= 0) {
        fn->stmts[sid].dst_var  = nv;
        fn->stmts[sid].rhs_expr = rhs_eid;
        hl_record_var_def(c, nv, sid);
    }
    hl_reg_stk_push(c, r, nv);
    c->cur_bits[r] = bw;
    c->cur_flt[r]  = is_f;
    if (c->cur_alias_reg == r) c->cur_alias_reg = -1;
    return nv;
}

static int hl_lift_mem_addr(hl_lift_ctx *c, const hl_opr *op, const x86_ins *in,
                            int64_t cur_sp, int64_t cur_bp, int has_bp) {
    hl_fn *fn = c->fn;

    /* Segment-relative TLS/TEB/PEB access (fs:[...], gs:[...]) */
    if (op->seg == 'f' || op->seg == 'g') {
        int id = hl_expr_new(fn, HLE_SYM);
        if (id >= 0) {
            fn->exprs[id].bits = (uint8_t)fn->ptr_bits;
            fn->exprs[id].va   = op->uval;
            snprintf(fn->exprs[id].sym, sizeof(fn->exprs[id].sym),
                     "__%cs_0x%llx", op->seg, (unsigned long long)op->uval);
        }
        return id;
    }

    /* Stack address with no index register -> &var_XX */
    int64_t soff = 0;
    if (hl_mem_to_stack_off_ex(fn, op, cur_sp, cur_bp, has_bp, c->cur_alias_reg, c->cur_alias_delta, &soff)) {
        int sv = hl_get_stk_var(c, soff, op->bits ? op->bits : fn->ptr_bits, op->is_flt, 0);
        if (sv >= 0) {
            int ve = hl_expr_var(fn, sv);
            int ae = hl_expr_new(fn, HLE_ADDR);
            if (ae >= 0) {
                fn->exprs[ae].sub0 = ve;
                fn->exprs[ae].bits = (uint8_t)fn->ptr_bits;
            }
            return ae;
        }
    }

    /* RIP-relative or absolute memory address [0xVA] */
    if (op->is_abs || (op->reg < 0 && op->idx < 0)) {
        uint64_t va = (in && in->has_target && in->target_mem) ? in->target : op->uval;
        return hl_expr_addr_const(fn, va);
    }

    int acc = -1;
    if (op->reg >= 0) {
        if (op->reg == fn->sp_reg || (has_bp && op->reg == fn->bp_reg) ||
            (c->cur_alias_reg >= 0 && op->reg == c->cur_alias_reg)) {
            /* Indexed stack buffer: [rsp/rbp/alias + rax*4 + disp] -> &var_base + rax*4 */
            int64_t base_d = (op->reg == fn->sp_reg) ? cur_sp
                           : (has_bp && op->reg == fn->bp_reg) ? cur_bp : c->cur_alias_delta;
            int64_t boff = base_d + op->disp;
            int sv = hl_get_stk_var(c, boff, op->bits ? op->bits : fn->ptr_bits, 0, 0);
            if (sv >= 0) {
                int ve = hl_expr_var(fn, sv);
                int ae = hl_expr_new(fn, HLE_ADDR);
                if (ae >= 0) { fn->exprs[ae].sub0 = ve; fn->exprs[ae].bits = (uint8_t)fn->ptr_bits; }
                int ie = hl_read_reg_expr(c, op->idx, fn->ptr_bits, 0, 0);
                if (op->scale > 1) {
                    ie = hl_expr_binop(fn, HLB_MUL, ie, hl_expr_int(fn, (uint64_t)op->scale, fn->ptr_bits, 0), fn->ptr_bits);
                }
                return hl_expr_binop(fn, HLB_ADD, ae, ie, fn->ptr_bits);
            }
        }
        acc = hl_read_reg_expr(c, op->reg, fn->ptr_bits, 0, 0);
    }

    if (op->idx >= 0) {
        int ie = hl_read_reg_expr(c, op->idx, fn->ptr_bits, 0, 0);
        if (op->scale > 1) {
            ie = hl_expr_binop(fn, HLB_MUL, ie, hl_expr_int(fn, (uint64_t)op->scale, fn->ptr_bits, 0), fn->ptr_bits);
        }
        acc = (acc >= 0) ? hl_expr_binop(fn, HLB_ADD, acc, ie, fn->ptr_bits) : ie;
    }

    if (op->disp != 0) {
        if (acc < 0) {
            acc = hl_expr_addr_const(fn, (uint64_t)op->disp);
        } else if (op->disp > 0) {
            acc = hl_expr_binop(fn, HLB_ADD, acc, hl_expr_int(fn, (uint64_t)op->disp, fn->ptr_bits, 0), fn->ptr_bits);
        } else {
            acc = hl_expr_binop(fn, HLB_SUB, acc, hl_expr_int(fn, hl_neg_u64((uint64_t)op->disp), fn->ptr_bits, 0), fn->ptr_bits);
        }
    }
    return (acc >= 0) ? acc : hl_expr_int(fn, 0, fn->ptr_bits, 0);
}

static int hl_lift_opr_read(hl_lift_ctx *c, const hl_opr *op, const x86_ins *in,
                            int default_bits, int is_flt,
                            int64_t cur_sp, int64_t cur_bp, int has_bp) {
    hl_fn *fn = c->fn;
    int bw = op->bits ? op->bits : (default_bits > 0 ? default_bits : fn->ptr_bits);
    if (bw > 64) bw = is_flt ? 64 : fn->ptr_bits;

    if (op->kind == HLO_IMM) {
        /* On x86-32, immediate that points to a rodata string or symbol */
        if (fn->is_x86_32 && !is_flt && op->uval >= fn->a->bin.min_va && op->uval < fn->a->bin.max_va) {
            char sb[64];
            int wide = 0;
            if (hl_try_read_ro_cstring(fn->a, op->uval, sb, sizeof(sb), &wide)) {
                return hl_expr_addr_const(fn, op->uval);
            }
            if (ana_sym_at(fn->a, op->uval)) {
                return hl_expr_addr_const(fn, op->uval);
            }
        }
        return hl_expr_int(fn, op->uval, bw, 0);
    }

    if (op->kind == HLO_REG) {
        if (c->cur_alias_reg >= 0 && op->reg == c->cur_alias_reg && hl_reg_stk_top(c, op->reg) < 0) {
            int sv = hl_get_stk_var(c, c->cur_alias_delta, fn->ptr_bits, 0, 0);
            if (sv >= 0) {
                int ae = hl_expr_new(fn, HLE_ADDR);
                if (ae >= 0) {
                    fn->exprs[ae].sub0 = hl_expr_var(fn, sv);
                    fn->exprs[ae].bits = (uint8_t)fn->ptr_bits;
                }
                return ae;
            }
        }
        return hl_read_reg_expr(c, op->reg, bw, is_flt || op->is_flt, op->is_hi8);
    }

    if (op->kind == HLO_MEM) {
        /* Stack slot read */
        int64_t soff = 0;
        if (hl_mem_to_stack_off_ex(fn, op, cur_sp, cur_bp, has_bp, c->cur_alias_reg, c->cur_alias_delta, &soff)) {
            int sv = hl_get_stk_var(c, soff, bw, is_flt, 1);
            if (sv >= 0) {
                int ve = hl_expr_var(fn, sv);
                if (ve >= 0) {
                    fn->exprs[ve].bits   = (uint8_t)bw;
                    fn->exprs[ve].is_flt = (uint8_t)(is_flt ? 1 : 0);
                }
                return ve;
            }
        }

        /* RIP-relative / absolute float/double constant in .rdata */
        if (is_flt && (op->is_abs || (op->reg < 0 && op->idx < 0)) && op->seg == 0) {
            uint64_t va = (in && in->has_target && in->target_mem) ? in->target : op->uval;
            double dv = 0.0;
            int fbits = (is_flt == 1 || bw == 32) ? 32 : 64;
            if (hl_try_read_ro_float(fn->a, va, fbits, &dv, NULL) && dv == dv) {
                return hl_expr_flt(fn, dv, fbits);
            }
        }

        int addr = hl_lift_mem_addr(c, op, in, cur_sp, cur_bp, has_bp);
        int de = hl_expr_new(fn, HLE_DEREF);
        if (de >= 0) {
            fn->exprs[de].sub0   = addr;
            fn->exprs[de].bits   = (uint8_t)bw;
            fn->exprs[de].is_flt = (uint8_t)(is_flt ? 1 : 0);
        }
        return de;
    }

    return hl_expr_int(fn, 0, bw, 0);
}

static int hl_lift_mem_store(hl_lift_ctx *c, int bi, uint64_t va,
                             const hl_opr *dst, const x86_ins *in,
                             int val_eid, int store_bits, int is_flt,
                             int64_t cur_sp, int64_t cur_bp, int has_bp,
                             hl_out_arg *out_args, int *nout_args) {
    hl_fn *fn = c->fn;
    int bw = dst->bits ? dst->bits : (store_bits > 0 ? store_bits : fn->ptr_bits);
    if (bw > 64) bw = is_flt ? 64 : fn->ptr_bits;

    int64_t soff = 0;
    if (hl_mem_to_stack_off_ex(fn, dst, cur_sp, cur_bp, has_bp, c->cur_alias_reg, c->cur_alias_delta, &soff)) {
        int sv = hl_get_stk_var(c, soff, bw, is_flt, 0);
        if (sv >= 0) {
            int sid = hl_stmt_new(fn, bi, va, HLS_ASSIGN);
            if (sid >= 0) {
                fn->stmts[sid].dst_var  = sv;
                fn->stmts[sid].rhs_expr = val_eid;
                hl_record_var_def(c, sv, sid);
            }
            /* Record potential outgoing stack arg relative to current SP (supports rsp/rbp/alias) */
            if (out_args && nout_args && dst->idx < 0) {
                int64_t sp_rel = soff - cur_sp;
                int in_out_win = 0;
                if (fn->is_win64) in_out_win = (sp_rel >= 0x20 && sp_rel <= 0x60);
                else if (fn->is_x86_32) in_out_win = (sp_rel >= 0 && sp_rel <= 0x30);
                else in_out_win = (sp_rel >= 0 && sp_rel <= 0x48);

                if (in_out_win) {
                    int slot = -1;
                    for (int i = 0; i < *nout_args; i++) {
                        if (out_args[i].disp == soff) { slot = i; break; }
                    }
                    if (slot < 0) {
                        if (*nout_args < HL_MAX_OUT_ARGS) {
                            slot = (*nout_args)++;
                        } else {
                            memmove(&out_args[0], &out_args[1], (size_t)(HL_MAX_OUT_ARGS - 1) * sizeof(hl_out_arg));
                            slot = HL_MAX_OUT_ARGS - 1;
                        }
                    }
                    out_args[slot].disp     = soff;
                    out_args[slot].val_expr = val_eid;
                    out_args[slot].stmt_id  = sid;
                    out_args[slot].blk_id   = bi;
                }
            }
            return sid;
        }
    }

    int addr = hl_lift_mem_addr(c, dst, in, cur_sp, cur_bp, has_bp);
    int lhs  = hl_expr_new(fn, HLE_DEREF);
    if (lhs >= 0) {
        fn->exprs[lhs].sub0   = addr;
        fn->exprs[lhs].bits   = (uint8_t)bw;
        fn->exprs[lhs].is_flt = (uint8_t)(is_flt ? 1 : 0);
    }
    int sid = hl_stmt_new(fn, bi, va, HLS_STORE);
    if (sid >= 0) {
        fn->stmts[sid].lhs_expr = lhs;
        fn->stmts[sid].rhs_expr = val_eid;
    }
    return sid;
}

static int hl_read_fmt_string(const ana_ctx *a, uint64_t va, char *out, size_t cap, int prefer_wide) {
    if (!a || !va || !out || cap < 2) return 0;
    const bin_sec *sec = bin_sec_at(&a->bin, va);
    if (!sec || (sec->perm & BIN_PERM_X)) return 0;

    const ana_str *st = ana_str_at(a, va);
    if (st && st->wide) prefer_wide = 1;

    uint8_t raw[512];
    size_t got = bin_read(&a->bin, va, raw, sizeof(raw));
    if (got < 2) return 0;

    int try_wide = prefer_wide || (got >= 4 && raw[1] == 0 &&
                                   ((raw[0] >= 0x20 && raw[0] <= 0x7E) || raw[0] == '\t' || raw[0] == '\r' || raw[0] == '\n'));
    if (try_wide) {
        size_t k = 0;
        int saw_nul = 0;
        int valid = 1;
        for (size_t i = 0; i * 2 + 1 < got && k + 1 < cap; i++) {
            uint8_t lo = raw[i * 2];
            uint8_t hi = raw[i * 2 + 1];
            if (lo == 0 && hi == 0) { saw_nul = 1; break; }
            if (hi == 0 && ((lo >= 0x20 && lo <= 0x7E) || lo == '\t' || lo == '\r' || lo == '\n')) {
                out[k++] = (char)lo;
            } else if (prefer_wide) {
                out[k++] = '?';
            } else {
                valid = 0;
                break;
            }
        }
        if (valid && k >= 1 && (saw_nul || prefer_wide || st != NULL)) {
            out[k] = 0;
            return 1;
        }
    }

    size_t len = 0;
    int saw_nul = 0;
    while (len < got && len + 1 < cap) {
        uint8_t ch = raw[len];
        if (ch == 0) { saw_nul = 1; break; }
        if ((ch >= 0x20 && ch <= 0x7E) || ch == '\t' || ch == '\r' || ch == '\n') {
            out[len++] = (char)ch;
        } else if (st != NULL && ch >= 0x80) {
            out[len++] = '?';
        } else {
            break;
        }
    }
    if (len >= 1 && (saw_nul || st != NULL || len >= 16)) {
        out[len] = 0;
        return 1;
    }
    return 0;
}

static int hl_find_blk_var_def_rhs(const hl_fn *fn, int bi, int var_id) {
    if (!fn || bi < 0 || bi >= fn->nblk || var_id < 0) return -1;
    const hl_blk *hb = &fn->blks[bi];
    for (int si = hb->nstmt - 1; si >= 0; si--) {
        int sid = hb->stmts[si];
        if (sid < 0 || sid >= fn->nstmt) continue;
        const hl_stmt *s = &fn->stmts[sid];
        if (!s->dead && s->kind == HLS_ASSIGN && s->dst_var == var_id) {
            return s->rhs_expr;
        }
    }
    return -1;
}

static int hl_resolve_fmt_str(const hl_lift_ctx *c, int bi, int eid, int prefer_wide,
                              char *out_buf, size_t out_cap) {
    const hl_fn *fn = c->fn;
    for (int hop = 0; hop < 10 && eid >= 0 && eid < fn->nexpr; hop++) {
        const hl_expr *e = &fn->exprs[eid];
        if (e->kind == HLE_UNOP && (e->op == HLU_CAST || e->op == HLU_ZEXT || e->op == HLU_SEXT) && e->sub0 >= 0) {
            eid = e->sub0;
            continue;
        }
        if (e->kind == HLE_STR) {
            if (e->va != 0 && hl_read_fmt_string(fn->a, e->va, out_buf, out_cap, prefer_wide || e->is_wide)) {
                return 1;
            }
            if (e->sym[0]) {
                snprintf(out_buf, out_cap, "%s", e->sym);
                return 1;
            }
            return 0;
        }
        if (e->kind == HLE_SYM) {
            if (e->va != 0 && hl_read_fmt_string(fn->a, e->va, out_buf, out_cap, prefer_wide)) return 1;
            return 0;
        }
        if (e->kind == HLE_ADDR) {
            if (e->va != 0 && hl_read_fmt_string(fn->a, e->va, out_buf, out_cap, prefer_wide)) return 1;
            if (e->sub0 >= 0) { eid = e->sub0; continue; }
            return 0;
        }
        if (e->kind == HLE_INT) {
            if (e->uval != 0 && hl_read_fmt_string(fn->a, e->uval, out_buf, out_cap, prefer_wide)) return 1;
            return 0;
        }
        if (e->kind == HLE_VAR && e->var_id >= 0) {
            int next_eid = -1;
            if (e->var_id < c->var_def_cap) {
                int sid = c->var_def_stmt[e->var_id];
                if (sid >= 0 && sid < fn->nstmt) {
                    const hl_stmt *ds = &fn->stmts[sid];
                    if (ds->kind == HLS_ASSIGN) {
                        next_eid = ds->rhs_expr;
                    } else if (ds->kind == HLS_PHI && ds->nphi > 0) {
                        for (int pi = 0; pi < (int)ds->nphi; pi++) {
                            int pv = ds->phi_vars[pi];
                            if (pv >= 0 && pv < c->var_def_cap) {
                                int psid = c->var_def_stmt[pv];
                                if (psid >= 0 && psid < fn->nstmt && fn->stmts[psid].kind == HLS_ASSIGN) {
                                    if (hl_resolve_fmt_str(c, bi, fn->stmts[psid].rhs_expr, prefer_wide, out_buf, out_cap)) {
                                        return 1;
                                    }
                                }
                            }
                        }
                        return 0;
                    }
                }
            }
            if (next_eid < 0) next_eid = hl_find_blk_var_def_rhs(fn, bi, e->var_id);
            if (next_eid >= 0) {
                eid = next_eid;
                continue;
            }
        }
        break;
    }
    return 0;
}

static int hl_parse_fmt_info(const char *fmt, int is_scanf, uint8_t *flt_flags, int max_args) {
    if (!fmt || !flt_flags || max_args <= 0) return 0;
    int cnt = 0;
    const char *p = fmt;
    while (*p && cnt < max_args) {
        if (*p != '%') { p++; continue; }
        p++;
        if (*p == '%') { p++; continue; }
        if (!*p) break;

        const char *q = p;
        while (isdigit((unsigned char)*q)) q++;
        if (q > p && *q == '$') p = q + 1;

        while (*p && strchr("-#0 +'", *p) != NULL) p++;

        int suppressed = 0;
        if (*p == '*') {
            if (is_scanf) {
                suppressed = 1;
            } else if (cnt < max_args) {
                flt_flags[cnt++] = 0;
            }
            p++;
            q = p;
            while (isdigit((unsigned char)*q)) q++;
            if (q > p && *q == '$') p = q + 1;
        } else {
            while (isdigit((unsigned char)*p)) p++;
        }

        if (*p == '.') {
            p++;
            if (*p == '*') {
                if (!is_scanf && cnt < max_args) flt_flags[cnt++] = 0;
                p++;
                q = p;
                while (isdigit((unsigned char)*q)) q++;
                if (q > p && *q == '$') p = q + 1;
            } else {
                while (isdigit((unsigned char)*p)) p++;
            }
        }

        if (p[0] == 'h' && p[1] == 'h') p += 2;
        else if (p[0] == 'l' && p[1] == 'l') p += 2;
        else if (p[0] == 'I' && p[1] == '6' && p[2] == '4') p += 3;
        else if (p[0] == 'I' && p[1] == '3' && p[2] == '2') p += 3;
        else if (*p && strchr("hlLztjqIw", *p) != NULL) p++;

        if (!*p) break;
        if (*p == '[') {
            p++;
            if (*p == '^') p++;
            if (*p == ']') p++;
            while (*p && *p != ']') p++;
            if (*p == ']') p++;
            if (!suppressed && cnt < max_args) flt_flags[cnt++] = 0;
        } else if (strchr("diuoxXfFeEgGaAcspnSC", *p) != NULL) {
            int is_fp = (!is_scanf && strchr("fFeEgGaA", *p) != NULL) ? 1 : 0;
            if (!suppressed && cnt < max_args) flt_flags[cnt++] = (uint8_t)is_fp;
            p++;
        }
    }
    return cnt;
}

static int hl_find_out_arg(hl_out_arg *out_args, int nout_args, int64_t disp,
                           int *out_stmt_id, int *out_blk_id) {
    for (int i = 0; i < nout_args; i++) {
        if (out_args[i].disp == disp && out_args[i].val_expr >= 0) {
            if (out_stmt_id) *out_stmt_id = out_args[i].stmt_id;
            if (out_blk_id)  *out_blk_id  = out_args[i].blk_id;
            return out_args[i].val_expr;
        }
    }
    return -1;
}

static int hl_fetch_call_arg(hl_lift_ctx *c, int bi, int k, int known,
                             const hl_callee_sig *csig, uint16_t call_flt_mask,
                             uint32_t written_gpr, uint32_t written_flt,
                             hl_out_arg *out_args, int nout_args,
                             int *push_exprs, int *push_stmts, int npush,
                             int64_t cur_sp, int *gi, int *fi, int *si_stk) {
    hl_fn *fn = c->fn;
    int is_farg = known ? (((call_flt_mask & (uint16_t)(1u << k)) != 0) ? 1 : 0)
                        : (((k < 32) && (written_flt & (1u << k)) && !(written_gpr & (1u << k))) ? 1 : 0);

    if (fn->is_win64) {
        if (k < 4) {
            int use_xmm = is_farg;
            if (use_xmm && !(written_flt & (1u << k)) && (written_gpr & (1u << k)) &&
                hl_reg_stk_top(c, 16 + k) < 0) {
                use_xmm = 0;
            }
            int reg = use_xmm ? (16 + k) : fn->arg_regs[k];
            int ab  = use_xmm ? ((known && k < HL_MAX_CALL_ARG && csig->arg_ty[k].bits) ? csig->arg_ty[k].bits : 64)
                              : ((known && k < HL_MAX_CALL_ARG && csig->arg_ty[k].bits) ? csig->arg_ty[k].bits : c->cur_bits[reg]);
            return hl_read_reg_expr(c, reg, ab > 0 ? ab : 64, use_xmm, 0);
        }
        int sid = -1, sblk = -1;
        int oe = hl_find_out_arg(out_args, nout_args, cur_sp + 0x20 + (int64_t)(k - 4) * 8, &sid, &sblk);
        if (oe >= 0) {
            if (sid >= 0 && sid < fn->nstmt && sblk == bi) fn->stmts[sid].dead = 1;
            return hl_expr_clone(fn, oe);
        }
        return hl_expr_int(fn, 0, 64, 0);
    }

    if (fn->is_x86_32) {
        if (npush > k) {
            int pidx = npush - 1 - k;
            if (push_stmts[pidx] >= 0 && push_stmts[pidx] < fn->nstmt) {
                fn->stmts[push_stmts[pidx]].dead = 1;
            }
            return hl_expr_clone(fn, push_exprs[pidx]);
        }
        int sid = -1, sblk = -1;
        int oe = hl_find_out_arg(out_args, nout_args, cur_sp + (int64_t)k * 4, &sid, &sblk);
        if (oe >= 0) {
            if (sid >= 0 && sid < fn->nstmt && sblk == bi) fn->stmts[sid].dead = 1;
            return hl_expr_clone(fn, oe);
        }
        return hl_expr_int(fn, 0, 32, 0);
    }

    if (fn->is_a64) {
        if (is_farg && *fi < 8) {
            return hl_read_reg_expr(c, 32 + ((*fi)++), 64, 1, 0);
        }
        if (!is_farg && *gi < 8) {
            return hl_read_reg_expr(c, fn->arg_regs[(*gi)++], 64, 0, 0);
        }
        int sid = -1, sblk = -1;
        int oe = hl_find_out_arg(out_args, nout_args, cur_sp + (int64_t)((*si_stk)++) * 8, &sid, &sblk);
        if (oe >= 0) {
            if (sid >= 0 && sid < fn->nstmt && sblk == bi) fn->stmts[sid].dead = 1;
            return hl_expr_clone(fn, oe);
        }
        return hl_expr_int(fn, 0, 64, 0);
    }

    /* SysV x64 */
    if (is_farg && *fi < 8) {
        return hl_read_reg_expr(c, 16 + ((*fi)++), 64, 1, 0);
    }
    if (!is_farg && *gi < 6) {
        int reg = fn->arg_regs[(*gi)++];
        int ab = (known && k < HL_MAX_CALL_ARG && csig->arg_ty[k].bits) ? csig->arg_ty[k].bits : c->cur_bits[reg];
        return hl_read_reg_expr(c, reg, ab > 0 ? ab : 64, 0, 0);
    }
    int sid = -1, sblk = -1;
    int oe = hl_find_out_arg(out_args, nout_args, cur_sp + (int64_t)((*si_stk)++) * 8, &sid, &sblk);
    if (oe >= 0) {
        if (sid >= 0 && sid < fn->nstmt && sblk == bi) fn->stmts[sid].dead = 1;
        return hl_expr_clone(fn, oe);
    }
    return hl_expr_int(fn, 0, 64, 0);
}

static int hl_lift_call_expr(hl_lift_ctx *c, int bi, const x86_ins *in, const hl_opr *o0,
                             uint32_t written_gpr, uint32_t written_flt,
                             hl_out_arg *out_args, int *nout_args,
                             int *push_exprs, int *push_stmts, int *npush,
                             int64_t cur_sp, int64_t cur_bp, int has_bp,
                             hl_callee_sig *out_sig, int *out_known) {
    hl_fn *fn = c->fn;
    uint64_t tgt_va = 0;
    const char *raw_sym = NULL;
    char csym[64];
    csym[0] = 0;
    int callee_e = -1;

    if (in->has_target && !in->target_mem) {
        tgt_va  = in->target;
        raw_sym = ana_sym_at(fn->a, tgt_va);
        if (raw_sym && raw_sym[0]) hl_clean_sym(raw_sym, csym, sizeof(csym));
        else snprintf(csym, sizeof(csym), "sub_%llx", (unsigned long long)tgt_va);
    } else if (in->has_target && in->target_mem) {
        raw_sym = ana_sym_at(fn->a, in->target);
        if (raw_sym && raw_sym[0]) {
            tgt_va = in->target;
            hl_clean_sym(raw_sym, csym, sizeof(csym));
        } else {
            callee_e = hl_lift_opr_read(c, o0, in, fn->ptr_bits, 0, cur_sp, cur_bp, has_bp);
        }
    } else {
        callee_e = hl_lift_opr_read(c, o0, in, fn->ptr_bits, 0, cur_sp, cur_bp, has_bp);
    }

    hl_callee_sig csig;
    memset(&csig, 0, sizeof(csig));
    csig.fmt_arg = -1;
    int known = 0;
    if (tgt_va != 0 || csym[0] != 0) {
        known = hl_lookup_callee(fn->a, fn->types, tgt_va, raw_sym ? raw_sym : csym, &csig) ? 1 : 0;
    }

    int arg_eids[HL_MAX_CALL_ARG];
    for (int i = 0; i < HL_MAX_CALL_ARG; i++) arg_eids[i] = -1;

    uint16_t call_flt_mask = (uint16_t)csig.flt_mask;
    int gi = 0, fi = 0, si_stk = 0;
    int lifted = 0;
    int na = 0;

    if (known) {
        int nfixed = csig.narg;
        if (nfixed > HL_MAX_CALL_ARG) nfixed = HL_MAX_CALL_ARG;
        if (nfixed < 0) nfixed = 0;
        na = nfixed;

        if (csig.is_vararg && csig.fmt_arg >= 0 && csig.fmt_arg < nfixed) {
            /* Lift fixed args first so format arg expression is directly in arg_eids[fmt_arg] */
            for (int k = 0; k < nfixed; k++) {
                arg_eids[k] = hl_fetch_call_arg(c, bi, k, known, &csig, call_flt_mask,
                                                written_gpr, written_flt, out_args, *nout_args,
                                                push_exprs, push_stmts, *npush, cur_sp,
                                                &gi, &fi, &si_stk);
            }
            lifted = nfixed;

            int expect_wide = (csig.arg_ty[csig.fmt_arg].kind == HL_TY_WCHAR) ||
                              (strstr(csym, "wsprintfW") != NULL) ||
                              (strstr(csym, "swprintf") != NULL) ||
                              (strstr(csym, "wprintf") != NULL) ||
                              (strstr(csym, "wscanf") != NULL);
            char fbuf[512];
            if (hl_resolve_fmt_str(c, bi, arg_eids[csig.fmt_arg], expect_wide, fbuf, sizeof(fbuf))) {
                int is_scanf = (strstr(csym, "scanf") != NULL);
                uint8_t flt_flags[HL_MAX_CALL_ARG];
                memset(flt_flags, 0, sizeof(flt_flags));
                int parsed_n = hl_parse_fmt_info(fbuf, is_scanf, flt_flags, HL_MAX_CALL_ARG);
                int extra_args = is_scanf ? parsed_n : hl_count_fmt_args(fbuf);
                int tot = nfixed + extra_args;
                if (tot > HL_MAX_CALL_ARG) tot = HL_MAX_CALL_ARG;
                if (tot > na) na = tot;
                for (int j = 0; j < parsed_n && (nfixed + j) < HL_MAX_CALL_ARG; j++) {
                    if (flt_flags[j]) {
                        call_flt_mask |= (uint16_t)(1u << (nfixed + j));
                        csig.arg_ty[nfixed + j].kind = HL_TY_F64;
                        csig.arg_ty[nfixed + j].bits = 64;
                    }
                }
            } else {
                /* Dynamic format string: infer varargs from written registers and outgoing stack slots */
                if (fn->is_win64) {
                    for (int k = nfixed; k < 4; k++) {
                        if ((written_gpr & (1u << k)) || (written_flt & (1u << k))) {
                            na = k + 1;
                            if ((written_flt & (1u << k)) && !(written_gpr & (1u << k))) {
                                call_flt_mask |= (uint16_t)(1u << k);
                            }
                        }
                    }
                    if (na >= 4 && *nout_args > 0) {
                        for (int extra = 0; extra < HL_MAX_CALL_ARG - 4; extra++) {
                            if (hl_find_out_arg(out_args, *nout_args, cur_sp + 0x20 + (int64_t)extra * 8, NULL, NULL) >= 0) {
                                na = 4 + extra + 1;
                            } else {
                                break;
                            }
                        }
                    }
                } else if (fn->is_x86_32) {
                    if (*npush > na) na = *npush;
                } else if (!fn->is_a64) {
                    for (int k = nfixed; k < 6; k++) {
                        if (written_gpr & (1u << k)) na = k + 1;
                    }
                    if (na >= 6 && *nout_args > 0) {
                        for (int extra = 0; extra < HL_MAX_CALL_ARG - 6; extra++) {
                            if (hl_find_out_arg(out_args, *nout_args, cur_sp + (int64_t)extra * 8, NULL, NULL) >= 0) {
                                na = 6 + extra + 1;
                            } else {
                                break;
                            }
                        }
                    }
                }
            }
        }
    } else {
        if (fn->is_x86_32) {
            na = (*npush > 0) ? *npush : 0;
            if (na == 0 && *nout_args > 0) {
                int max_k = -1;
                for (int i = 0; i < *nout_args; i++) {
                    int64_t sp_rel = out_args[i].disp - cur_sp;
                    if (sp_rel >= 0 && (sp_rel % 4) == 0) {
                        int k = (int)(sp_rel / 4);
                        if (k < HL_MAX_CALL_ARG && k > max_k) max_k = k;
                    }
                }
                if (max_k >= 0) na = max_k + 1;
            }
        } else {
            int max_k = -1;
            for (int k = 0; k < fn->narg_abi; k++) {
                if ((written_gpr & (1u << k)) || (written_flt & (1u << k))) max_k = k;
            }
            na = (max_k >= 0) ? (max_k + 1) : 0;
            if (fn->is_win64 && na >= 4 && *nout_args > 0) {
                for (int extra = 0; extra < HL_MAX_CALL_ARG - 4; extra++) {
                    if (hl_find_out_arg(out_args, *nout_args, cur_sp + 0x20 + (int64_t)extra * 8, NULL, NULL) >= 0) {
                        na = 4 + extra + 1;
                    } else {
                        break;
                    }
                }
            }
        }
    }
    if (na > HL_MAX_CALL_ARG) na = HL_MAX_CALL_ARG;
    if (na < 0) na = 0;

    for (int k = lifted; k < na; k++) {
        arg_eids[k] = hl_fetch_call_arg(c, bi, k, known, &csig, call_flt_mask,
                                        written_gpr, written_flt, out_args, *nout_args,
                                        push_exprs, push_stmts, *npush, cur_sp,
                                        &gi, &fi, &si_stk);
    }

    int ce = hl_expr_new(fn, HLE_CALL);
    if (ce >= 0) {
        hl_expr *e = &fn->exprs[ce];
        e->sub0 = callee_e;
        e->va   = tgt_va;
        e->narg = (uint8_t)na;
        snprintf(e->sym, sizeof(e->sym), "%s", csym);
        for (int k = 0; k < na; k++) e->args[k] = arg_eids[k];
        if (known) {
            e->ty     = csig.ret_ty;
            e->bits   = csig.ret_ty.bits ? csig.ret_ty.bits : (uint8_t)fn->ptr_bits;
            e->is_flt = (csig.ret_ty.kind == HL_TY_F32 || csig.ret_ty.kind == HL_TY_F64) ? 1 : 0;
            if (csig.ret_ty.kind == HL_TY_I8 || csig.ret_ty.kind == HL_TY_I16 ||
                csig.ret_ty.kind == HL_TY_I32 || csig.ret_ty.kind == HL_TY_I64) {
                e->is_signed = 1;
            }
        } else {
            e->bits = (uint8_t)fn->ptr_bits;
        }
    }

    *nout_args = 0;
    *npush     = 0;
    if (out_sig)   *out_sig   = csig;
    if (out_known) *out_known = known;
    return ce;
}

static void hl_mark_arg_written(const hl_fn *fn, int reg, int is_flt,
                                uint32_t *wgpr, uint32_t *wflt) {
    if (fn->is_win64) {
        for (int k = 0; k < fn->narg_abi; k++) {
            if (fn->arg_regs[k] == reg) *wgpr |= (1u << k);
        }
        if (reg >= 16 && reg < 20) *wflt |= (1u << (reg - 16));
    } else if (fn->is_a64) {
        if (reg >= 0 && reg < 8) *wgpr |= (1u << reg);
        if (reg >= 32 && reg < 40) *wflt |= (1u << (reg - 32));
    } else if (!fn->is_x86_32) {
        for (int k = 0; k < fn->narg_abi; k++) {
            if (fn->arg_regs[k] == reg) *wgpr |= (1u << k);
        }
        if (is_flt && reg >= 16 && reg < 24) *wflt |= (1u << (reg - 16));
    }
}

/* =========================================================================
 * Block Instruction Lifting (x86/x64 & ARM64)
 * ========================================================================= */

static int hl_x86_is_flt_arith(const char *m, uint8_t *bop, int *fbits) {
    const char *s = (m[0] == 'v') ? (m + 1) : m;
    if (strncmp(s, "add", 3) == 0) *bop = HLB_FADD;
    else if (strncmp(s, "sub", 3) == 0) *bop = HLB_FSUB;
    else if (strncmp(s, "mul", 3) == 0) *bop = HLB_FMUL;
    else if (strncmp(s, "div", 3) == 0) *bop = HLB_FDIV;
    else if (strncmp(s, "min", 3) == 0) *bop = HLB_MIN;
    else if (strncmp(s, "max", 3) == 0) *bop = HLB_MAX;
    else return 0;

    const char *suf = s + 3;
    if (strcmp(suf, "ss") == 0 || strcmp(suf, "ps") == 0) { *fbits = 32; return 1; }
    if (strcmp(suf, "sd") == 0 || strcmp(suf, "pd") == 0) { *fbits = 64; return 1; }
    return 0;
}

static int hl_x86_alu_op(const char *m, uint8_t *bop, int *is_signed) {
    *is_signed = 0;
    if (strcmp(m, "add") == 0) { *bop = HLB_ADD; return 1; }
    if (strcmp(m, "sub") == 0) { *bop = HLB_SUB; return 1; }
    if (strcmp(m, "and") == 0 || strcmp(m, "pand") == 0) { *bop = HLB_AND; return 1; }
    if (strcmp(m, "or") == 0  || strcmp(m, "por") == 0  || strcmp(m, "orps") == 0  || strcmp(m, "orpd") == 0)  { *bop = HLB_OR;  return 1; }
    if (strcmp(m, "xor") == 0) { *bop = HLB_XOR; return 1; }
    if (strcmp(m, "shl") == 0 || strcmp(m, "sal") == 0) { *bop = HLB_SHL; return 1; }
    if (strcmp(m, "shr") == 0) { *bop = HLB_SHR; return 1; }
    if (strcmp(m, "sar") == 0) { *bop = HLB_SAR; *is_signed = 1; return 1; }
    if (strcmp(m, "rol") == 0 || strcmp(m, "rcl") == 0) { *bop = HLB_ROL; return 1; }
    if (strcmp(m, "ror") == 0 || strcmp(m, "rcr") == 0) { *bop = HLB_ROR; return 1; }
    return 0;
}

static int hl_a64_shift_amt(const char *s) {
    if (!s || !s[0]) return 0;
    const char *p = strchr(s, '#');
    if (!p) return 0;
    int64_t v = 0;
    return hl_parse_int(p, &v) ? (int)v : 0;
}

static int hl_x86_is_vec_store_mnem(const char *m) {
    if (!m || !m[0]) return 0;
    const char *s = (m[0] == 'v') ? (m + 1) : m;
    return strcmp(s, "movups") == 0 || strcmp(s, "movaps") == 0 ||
           strcmp(s, "movupd") == 0 || strcmp(s, "movapd") == 0 ||
           strcmp(s, "movdqu") == 0 || strcmp(s, "movdqa") == 0;
}

static int hl_next_ins_is_vec_store_xmm0(const grp_cfg *g, const grp_blk *gb, uint32_t k, const hl_fn *fn) {
    for (uint32_t step = 1; step <= 3 && (k + step) < gb->ins_count; step++) {
        const x86_ins *ni = &g->ins[gb->ins_first + k + step];
        if (ni->flow != X86_FLOW_NONE) break;
        char nmn[24];
        hl_lower_copy(ni->mnem, nmn, sizeof(nmn));
        const char *nm = (strncmp(nmn, "lock ", 5) == 0) ? (nmn + 5) : nmn;
        char nops_s[4][80];
        int nn = hl_split_ops(ni->ops, nops_s);
        hl_opr no0, no1;
        hl_parse_opr(fn, nops_s[0], &no0);
        hl_parse_opr(fn, nops_s[1], &no1);
        if (nn >= 2 && hl_x86_is_vec_store_mnem(nm) && no0.kind == HLO_MEM &&
            no1.kind == HLO_REG && no1.reg == 16) {
            return 1;
        }
        if (nn >= 1 && no0.kind == HLO_REG && no0.reg == 16 &&
            strcmp(nm, "ucomiss") != 0 && strcmp(nm, "ucomisd") != 0 &&
            strcmp(nm, "comiss") != 0 && strcmp(nm, "comisd") != 0) {
            break;
        }
    }
    return 0;
}

static int hl_var_has_real_def_rec(const hl_lift_ctx *c, int vid, int require_flt, int *vis, int *nvis) {
    if (!c || !c->fn || vid < 0 || vid >= c->fn->nvar) return 0;
    const hl_fn *fn = c->fn;
    if (require_flt) {
        if (c->flt_ret_reg >= 0 && vid == c->entry_var[c->flt_ret_reg]) return 0;
        if (!fn->vars[vid].is_flt) return 0;
    } else {
        if (fn->ret_reg >= 0 && vid == c->entry_var[fn->ret_reg]) return 0;
    }
    for (int i = 0; i < *nvis; i++) {
        if (vis[i] == vid) return 0;
    }
    if (*nvis >= 32) return 0;
    vis[(*nvis)++] = vid;
    int sid = (vid < c->var_def_cap) ? c->var_def_stmt[vid] : -1;
    if (sid < 0 || sid >= fn->nstmt) return 0;
    const hl_stmt *ds = &fn->stmts[sid];
    if (ds->kind == HLS_ASSIGN) return 1;
    if (ds->kind == HLS_PHI) {
        for (int pi = 0; pi < (int)ds->nphi && pi < 8; pi++) {
            if (hl_var_has_real_def_rec(c, ds->phi_vars[pi], require_flt, vis, nvis)) return 1;
        }
        return 0;
    }
    return 0;
}

static int hl_var_has_real_def(const hl_lift_ctx *c, int vid, int require_flt) {
    int vis[32];
    int nvis = 0;
    return hl_var_has_real_def_rec(c, vid, require_flt, vis, &nvis);
}

static int hl_var_has_real_flt_def(const hl_lift_ctx *c, int vid) {
    return hl_var_has_real_def(c, vid, 1);
}

static void hl_lift_block(hl_lift_ctx *c, int bi) {
    hl_fn *fn = c->fn;
    const grp_cfg *g = fn->g;
    const grp_blk *gb = &g->blks[bi];

    int64_t cur_sp = c->blk_sp_in[bi];
    int64_t cur_bp = c->blk_bp_in[bi];
    int     has_bp = c->blk_has_bp_in[bi];
    int64_t last_eax_imm = 0;
    c->cur_alias_reg   = -1;
    c->cur_alias_delta = 0;

    hl_flag_state fl;
    memset(&fl, 0, sizeof(fl));
    fl.lhs_expr = fl.rhs_expr = fl.res_expr = -1;
    int ret_valid       = 0;
    int fret_valid      = 0;
    int last_ret_is_flt = 0;
    int fret_bits       = 64;

    uint32_t written_gpr = 0;
    uint32_t written_flt = 0;
    hl_out_arg out_args[HL_MAX_OUT_ARGS];
    int nout_args = 0;

    int idom = fn->blks[bi].idom;
    if (bi > 0 && idom >= 0 && idom < fn->nblk) {
        fl              = c->blk_exit_fl[idom];
        ret_valid       = c->blk_exit_ret_valid[idom];
        fret_valid      = c->blk_exit_fret_valid[idom];
        last_ret_is_flt = c->blk_exit_last_ret_is_flt[idom];
        fret_bits       = c->blk_exit_fret_bits[idom] ? (int)c->blk_exit_fret_bits[idom] : 64;
        nout_args       = c->blk_exit_nout_args[idom];
        if (nout_args > HL_MAX_OUT_ARGS) nout_args = HL_MAX_OUT_ARGS;
        if (nout_args > 0) {
            memcpy(out_args, c->blk_exit_out_args[idom], (size_t)nout_args * sizeof(hl_out_arg));
        }
    }

    if (c->flt_ret_reg >= 0 && c->phi_stmt[bi][c->flt_ret_reg] >= 0 && c->phi_stmt[bi][fn->ret_reg] < 0) {
        fret_valid      = 1;
        last_ret_is_flt = 1;
    } else if (c->phi_stmt[bi][fn->ret_reg] >= 0 &&
               (c->flt_ret_reg < 0 || c->phi_stmt[bi][c->flt_ret_reg] < 0)) {
        ret_valid       = 1;
        last_ret_is_flt = 0;
    }

    int push_exprs[HL_MAX_OUT_ARGS];
    int push_stmts[HL_MAX_OUT_ARGS];
    int npush = 0;
    int last_idx_expr = -1;

    for (uint32_t k = 0; k < gb->ins_count; k++) {
        uint32_t gidx = gb->ins_first + k;
        const x86_ins *in = &g->ins[gidx];
        char mn[24];
        hl_lower_copy(in->mnem, mn, sizeof(mn));
        const char *m = (strncmp(mn, "lock ", 5) == 0) ? (mn + 5) : mn;

        char ops[4][80];
        int nops = hl_split_ops(in->ops, ops);
        hl_opr o0, o1, o2, o3;
        hl_parse_opr(fn, ops[0], &o0);
        hl_parse_opr(fn, ops[1], &o1);
        hl_parse_opr(fn, ops[2], &o2);
        hl_parse_opr(fn, ops[3], &o3);

        int64_t pre_sp = cur_sp;
        int64_t pre_bp = cur_bp;
        int pre_has_bp = has_bp;

        if (c->skip_ins[gidx]) {
            if (fn->is_a64) hl_step_sp_a64(fn, m, &o0, &o1, &o2, &o3, nops, &cur_sp, &cur_bp, &has_bp);
            else hl_step_sp_x86(fn, m, &o0, &o1, &cur_sp, &cur_bp, &has_bp, &last_eax_imm, &c->cur_alias_reg, &c->cur_alias_delta);
            continue;
        }

        /* Track indexed memory accesses for switch selector recovery */
        if (fn->blks[bi].sw_idx >= 0) {
            if (o1.kind == HLO_MEM && o1.idx >= 0) {
                last_idx_expr = hl_read_reg_expr(c, o1.idx, fn->ptr_bits, 0, 0);
            } else if (o0.kind == HLO_MEM && o0.idx >= 0) {
                last_idx_expr = hl_read_reg_expr(c, o0.idx, fn->ptr_bits, 0, 0);
            }
        }

        /* ---------- Control Flow (common x86 & ARM64) ---------- */
        if (in->flow == X86_FLOW_CALL) {
            hl_callee_sig csig;
            int known = 0;
            int ce = hl_lift_call_expr(c, bi, in, &o0, written_gpr, written_flt,
                                       out_args, &nout_args, push_exprs, push_stmts, &npush,
                                       pre_sp, pre_bp, pre_has_bp, &csig, &known);
            written_gpr = 0;
            written_flt = 0;
            if (c->cur_alias_reg >= 0 && (c->vol_reg_mask & (1ULL << c->cur_alias_reg))) {
                c->cur_alias_reg = -1;
            }
            if (known && !csig.has_ret) {
                int sid = hl_stmt_new(fn, bi, in->ip, HLS_CALL);
                if (sid >= 0) fn->stmts[sid].rhs_expr = ce;
                if (fn->ret_reg >= 0) hl_reg_stk_push(c, fn->ret_reg, -2);
                if (c->flt_ret_reg >= 0 && c->flt_ret_reg != fn->ret_reg) {
                    hl_reg_stk_push(c, c->flt_ret_reg, -2);
                }
                ret_valid       = 0;
                fret_valid      = 0;
                last_ret_is_flt = 0;
            } else {
                int ret_is_f = (known && (csig.ret_ty.kind == HL_TY_F32 || csig.ret_ty.kind == HL_TY_F64));
                int rreg = ret_is_f ? c->flt_ret_reg : fn->ret_reg;
                int rbits = (known && csig.ret_ty.bits) ? csig.ret_ty.bits : fn->ptr_bits;
                int nv = hl_def_reg(c, bi, in->ip, rreg, rbits, ret_is_f, ce);
                if (nv >= 0 && known && csig.ret_ty.kind != HL_TY_UNK) {
                    fn->vars[nv].ty = csig.ret_ty;
                }
                if (ret_is_f) {
                    if (fn->ret_reg >= 0 && fn->ret_reg != c->flt_ret_reg) {
                        hl_reg_stk_push(c, fn->ret_reg, -2);
                    }
                    fret_valid      = 1;
                    ret_valid       = 0;
                    last_ret_is_flt = 1;
                    fret_bits       = (csig.ret_ty.kind == HL_TY_F32) ? 32 : 64;
                } else {
                    if (c->flt_ret_reg >= 0 && c->flt_ret_reg != fn->ret_reg) {
                        hl_reg_stk_push(c, c->flt_ret_reg, -2);
                    }
                    ret_valid       = 1;
                    fret_valid      = 0;
                    last_ret_is_flt = 0;
                }
            }
            continue;
        }

        if (in->flow == X86_FLOW_RET) {
            int sid = hl_stmt_new(fn, bi, in->ip, HLS_RET);
            if (sid >= 0) {
                int rv = -1;
                int rfv = -1;
                uint8_t rf = 0;
                uint8_t rfb = 0;
                if (c->flt_ret_reg >= 0) {
                    int ftop = hl_reg_stk_top(c, c->flt_ret_reg);
                    rfv = (ftop >= 0) ? ftop : ((ftop == -2) ? -1 : c->entry_var[c->flt_ret_reg]);
                }
                if (last_ret_is_flt && fret_valid && c->flt_ret_reg >= 0) {
                    rv = hl_reg_stk_top(c, c->flt_ret_reg);
                    if (rv >= 0) {
                        fn->stmts[sid].rhs_expr = hl_expr_var(fn, rv);
                        rf  = 1;
                        rfb = (uint8_t)(fret_bits == 32 ? 32 : 64);
                    }
                } else if (ret_valid) {
                    rv = hl_reg_stk_top(c, fn->ret_reg);
                    if (rv >= 0) fn->stmts[sid].rhs_expr = hl_expr_var(fn, rv);
                } else if (fret_valid && c->flt_ret_reg >= 0) {
                    rv = hl_reg_stk_top(c, c->flt_ret_reg);
                    if (rv >= 0) {
                        fn->stmts[sid].rhs_expr = hl_expr_var(fn, rv);
                        rf  = 1;
                        rfb = (uint8_t)(fret_bits == 32 ? 32 : 64);
                    }
                } else {
                    /* Even if ret_valid wasn't flagged locally, check if ret_reg has a non-entry SSA def */
                    int top_r = hl_reg_stk_top(c, fn->ret_reg);
                    if (top_r >= 0 && top_r != c->entry_var[fn->ret_reg] &&
                        hl_var_has_real_def(c, top_r, 0)) {
                        rv = top_r;
                        fn->stmts[sid].rhs_expr = hl_expr_var(fn, rv);
                    }
                }
                if (c->nret_stmts < HL_MAX_BLKS) {
                    c->ret_stmts[c->nret_stmts]    = sid;
                    c->ret_vars[c->nret_stmts]     = rv;
                    c->ret_flt_vars[c->nret_stmts] = rfv;
                    c->ret_is_flt[c->nret_stmts]   = rf;
                    c->ret_flt_bits[c->nret_stmts] = rfb;
                    c->nret_stmts++;
                }
            }
            continue;
        }

        if (in->flow == X86_FLOW_JMP) {
            /* Jump-table switch indirect jmp */
            if (fn->blks[bi].sw_idx >= 0) {
                if (last_idx_expr >= 0) {
                    fn->blks[bi].sw_expr = last_idx_expr;
                } else {
                    fn->blks[bi].sw_expr = hl_lift_opr_read(c, &o0, in, fn->ptr_bits, 0, pre_sp, pre_bp, pre_has_bp);
                }
                continue;
            }
            /* Internal CFG jump -> handled by out_u */
            if (fn->blks[bi].out_u >= 0) continue;
            if (in->has_target && !in->target_mem && hl_blk_of_va(fn, in->target) >= 0) continue;

            /* External / IAT / indirect tail call! */
            hl_callee_sig csig;
            int known = 0;
            int ce = hl_lift_call_expr(c, bi, in, &o0, written_gpr, written_flt,
                                       out_args, &nout_args, push_exprs, push_stmts, &npush,
                                       pre_sp, pre_bp, pre_has_bp, &csig, &known);
            fn->blks[bi].is_exit = 1;
            if (known && !csig.has_ret) {
                int csid = hl_stmt_new(fn, bi, in->ip, HLS_CALL);
                if (csid >= 0) fn->stmts[csid].rhs_expr = ce;
                hl_stmt_new(fn, bi, in->ip, HLS_RET);
            } else {
                int rsid = hl_stmt_new(fn, bi, in->ip, HLS_RET);
                if (rsid >= 0) {
                    fn->stmts[rsid].rhs_expr = ce;
                    fn->has_ret_val = 1;
                    if (known && (csig.ret_ty.kind == HL_TY_F32 || csig.ret_ty.kind == HL_TY_F64)) {
                        fn->ret_ty = csig.ret_ty;
                    }
                }
            }
            continue;
        }

        if (in->flow == X86_FLOW_JCC) {
            fn->blks[bi].cond_va = in->ip;
            if (!fn->is_a64) {
                if (strcmp(m, "jrcxz") == 0 || strcmp(m, "jecxz") == 0) {
                    int bw = (strcmp(m, "jecxz") == 0) ? 32 : fn->ptr_bits;
                    int r1 = hl_read_reg_expr(c, 1, bw, 0, 0);
                    fn->blks[bi].cond_expr = hl_expr_binop(fn, HLB_EQ, r1, hl_expr_int(fn, 0, bw, 0), 1);
                } else if (strncmp(m, "loop", 4) == 0) {
                    int r1 = hl_read_reg_expr(c, 1, fn->ptr_bits, 0, 0);
                    int dec = hl_expr_binop(fn, HLB_SUB, r1, hl_expr_int(fn, 1, fn->ptr_bits, 0), fn->ptr_bits);
                    int nv = hl_def_reg(c, bi, in->ip, 1, fn->ptr_bits, 0, dec);
                    fn->blks[bi].cond_expr = hl_expr_binop(fn, HLB_NE, hl_expr_var(fn, nv),
                                                           hl_expr_int(fn, 0, fn->ptr_bits, 0), 1);
                } else {
                    fn->blks[bi].cond_expr = hl_eval_cc(fn, &fl, (m[0] == 'j' && m[1]) ? (m + 1) : m);
                }
            } else {
                if (strcmp(m, "cbz") == 0 || strcmp(m, "cbnz") == 0) {
                    int e0 = hl_lift_opr_read(c, &o0, in, 64, 0, pre_sp, pre_bp, pre_has_bp);
                    uint8_t bop = (strcmp(m, "cbz") == 0) ? HLB_EQ : HLB_NE;
                    fn->blks[bi].cond_expr = hl_expr_binop(fn, bop, e0, hl_expr_int(fn, 0, o0.bits ? o0.bits : 64, 0), 1);
                } else if (strcmp(m, "tbz") == 0 || strcmp(m, "tbnz") == 0) {
                    int e0 = hl_lift_opr_read(c, &o0, in, 64, 0, pre_sp, pre_bp, pre_has_bp);
                    uint64_t mask = 1ULL << (o1.uval & 63U);
                    int band = hl_expr_binop(fn, HLB_AND, e0, hl_expr_int(fn, mask, 64, 0), 64);
                    uint8_t bop = (strcmp(m, "tbz") == 0) ? HLB_EQ : HLB_NE;
                    fn->blks[bi].cond_expr = hl_expr_binop(fn, bop, band, hl_expr_int(fn, 0, 64, 0), 1);
                } else {
                    const char *dot = strchr(m, '.');
                    fn->blks[bi].cond_expr = hl_eval_cc(fn, &fl, dot ? (dot + 1) : m);
                }
            }
            continue;
        }

        /* ==============================================================
         * x86 / x86-64 Instruction Semantics
         * ============================================================== */
        if (!fn->is_a64) {
            if (strcmp(m, "nop") == 0 || strcmp(m, "fnop") == 0 || strcmp(m, "pause") == 0 ||
                strcmp(m, "endbr64") == 0 || strcmp(m, "endbr32") == 0 || strcmp(m, "int3") == 0 ||
                strcmp(m, "ud2") == 0 || strcmp(m, "prefetch") == 0 || strcmp(m, "cld") == 0 ||
                strcmp(m, "std") == 0 || strcmp(m, "lfence") == 0 || strcmp(m, "mfence") == 0 ||
                strcmp(m, "sfence") == 0 || strcmp(m, "fwait") == 0 || strcmp(m, "vzeroupper") == 0 ||
                strcmp(m, "vzeroall") == 0 || strcmp(m, "emms") == 0 ||
                (strcmp(m, "add") == 0 && strcmp(in->ops, "byte ptr [rax], al") == 0)) {
                continue;
            }

            /* Bulk Memory: rep movs* / rep stos* */
            if (strncmp(m, "rep ", 4) == 0 ||
                ((strncmp(m, "movs", 4) == 0 || strncmp(m, "stos", 4) == 0) && nops == 0)) {
                int has_rep = (strncmp(m, "rep ", 4) == 0);
                const char *sm = has_rep ? (m + 4) : m;
                if ((has_rep || nops == 0) &&
                    (strncmp(sm, "movs", 4) == 0 || strncmp(sm, "stos", 4) == 0) &&
                    sm[4] && sm[5] == 0 &&
                    (sm[4] == 'b' || sm[4] == 'w' || sm[4] == 'd' || sm[4] == 'q')) {
                    int esz = (sm[4] == 'b') ? 1 : (sm[4] == 'w') ? 2 : (sm[4] == 'd') ? 4 : 8;
                    int dst_e = hl_read_reg_expr(c, 7, fn->ptr_bits, 0, 0);
                    int len_e = has_rep ? hl_read_reg_expr(c, 1, fn->ptr_bits, 0, 0)
                                        : hl_expr_int(fn, 1, fn->ptr_bits, 0);
                    if (esz > 1) {
                        len_e = hl_expr_binop(fn, HLB_MUL, len_e, hl_expr_int(fn, (uint64_t)esz, fn->ptr_bits, 0), fn->ptr_bits);
                    }
                    if (sm[0] == 'm') {
                        int src_e = hl_read_reg_expr(c, 6, fn->ptr_bits, 0, 0);
                        int sid = hl_stmt_new(fn, bi, in->ip, HLS_MEMCPY);
                        if (sid >= 0) {
                            fn->stmts[sid].lhs_expr = dst_e;
                            fn->stmts[sid].rhs_expr = src_e;
                            fn->stmts[sid].len_expr = len_e;
                        }
                        int n_dst = hl_expr_binop(fn, HLB_ADD, hl_expr_clone(fn, dst_e), hl_expr_clone(fn, len_e), fn->ptr_bits);
                        int n_src = hl_expr_binop(fn, HLB_ADD, hl_expr_clone(fn, src_e), hl_expr_clone(fn, len_e), fn->ptr_bits);
                        hl_def_reg(c, bi, in->ip, 7, fn->ptr_bits, 0, n_dst);
                        hl_def_reg(c, bi, in->ip, 6, fn->ptr_bits, 0, n_src);
                        if (has_rep) hl_def_reg(c, bi, in->ip, 1, fn->ptr_bits, 0, hl_expr_int(fn, 0, fn->ptr_bits, 0));
                    } else {
                        int val_e = hl_read_reg_expr(c, 0, esz * 8, 0, 0);
                        int sid = hl_stmt_new(fn, bi, in->ip, HLS_MEMSET);
                        if (sid >= 0) {
                            fn->stmts[sid].lhs_expr = dst_e;
                            fn->stmts[sid].rhs_expr = val_e;
                            fn->stmts[sid].len_expr = len_e;
                        }
                        int n_dst = hl_expr_binop(fn, HLB_ADD, hl_expr_clone(fn, dst_e), hl_expr_clone(fn, len_e), fn->ptr_bits);
                        hl_def_reg(c, bi, in->ip, 7, fn->ptr_bits, 0, n_dst);
                        if (has_rep) hl_def_reg(c, bi, in->ip, 1, fn->ptr_bits, 0, hl_expr_int(fn, 0, fn->ptr_bits, 0));
                    }
                    continue;
                }
            }

            /* Push (x86-32 call arguments or non-callee-saved stack temp) */
            if (strcmp(m, "push") == 0 && o0.kind != HLO_NONE) {
                int ve = hl_lift_opr_read(c, &o0, in, fn->ptr_bits, 0, pre_sp, pre_bp, pre_has_bp);
                hl_step_sp_x86(fn, m, &o0, &o1, &cur_sp, &cur_bp, &has_bp, &last_eax_imm, &c->cur_alias_reg, &c->cur_alias_delta);
                int sv = hl_get_stk_var(c, cur_sp, fn->ptr_bits, 0, 0);
                int sid = -1;
                if (sv >= 0) {
                    sid = hl_stmt_new(fn, bi, in->ip, HLS_ASSIGN);
                    if (sid >= 0) {
                        fn->stmts[sid].dst_var  = sv;
                        fn->stmts[sid].rhs_expr = ve;
                    }
                }
                if (fn->is_x86_32 && npush < HL_MAX_OUT_ARGS) {
                    push_exprs[npush] = ve;
                    push_stmts[npush] = sid;
                    npush++;
                }
                continue;
            }

            if (strcmp(m, "pop") == 0 && o0.kind == HLO_REG) {
                int sv = hl_get_stk_var(c, pre_sp, fn->ptr_bits, 0, 1);
                hl_step_sp_x86(fn, m, &o0, &o1, &cur_sp, &cur_bp, &has_bp, &last_eax_imm, &c->cur_alias_reg, &c->cur_alias_delta);
                int ve = (sv >= 0) ? hl_expr_var(fn, sv) : hl_expr_int(fn, 0, fn->ptr_bits, 0);
                hl_def_reg(c, bi, in->ip, o0.reg, o0.bits ? o0.bits : fn->ptr_bits, 0, ve);
                hl_mark_arg_written(fn, o0.reg, 0, &written_gpr, &written_flt);
                if (o0.reg == fn->ret_reg) { ret_valid = 1; last_ret_is_flt = 0; }
                continue;
            }

            /* Flag-setting comparisons: cmp / test / bt / ucomiss / ucomisd / comiss / comisd */
            if (strcmp(m, "cmp") == 0 || strcmp(m, "test") == 0 || strcmp(m, "bt") == 0 ||
                strstr(m, "ucomis") != NULL || strstr(m, "comis") != NULL) {
                int is_fc = (strstr(m, "comis") != NULL);
                int is_f  = is_fc ? ((strstr(m, "sd") != NULL) ? 2 : 1) : 0;
                int bw    = is_f ? (is_f == 2 ? 64 : 32)
                                 : (o0.bits ? o0.bits : (o1.bits ? o1.bits : fn->ptr_bits));
                int e0 = hl_lift_opr_read(c, &o0, in, bw, is_f, pre_sp, pre_bp, pre_has_bp);
                int e1 = hl_lift_opr_read(c, &o1, in, bw, is_f, pre_sp, pre_bp, pre_has_bp);
                fl.lhs_expr = e0;
                fl.rhs_expr = e1;
                fl.res_expr = -1;
                fl.bits     = bw;
                fl.is_flt   = is_f ? 1 : 0;
                if (is_fc) fl.kind = HLF_FCMP;
                else if (strcmp(m, "test") == 0) fl.kind = HLF_TEST;
                else if (strcmp(m, "bt") == 0)   fl.kind = HLF_BT;
                else fl.kind = HLF_CMP;
                continue;
            }

            /* bts / btr / btc */
            if (strcmp(m, "bts") == 0 || strcmp(m, "btr") == 0 || strcmp(m, "btc") == 0) {
                int bw = o0.bits ? o0.bits : fn->ptr_bits;
                int e0 = hl_lift_opr_read(c, &o0, in, bw, 0, pre_sp, pre_bp, pre_has_bp);
                int e1 = hl_lift_opr_read(c, &o1, in, bw, 0, pre_sp, pre_bp, pre_has_bp);
                fl.kind = HLF_BT; fl.lhs_expr = hl_expr_clone(fn, e0); fl.rhs_expr = hl_expr_clone(fn, e1);
                fl.res_expr = -1; fl.bits = bw; fl.is_flt = 0;
                int bit = hl_expr_binop(fn, HLB_SHL, hl_expr_int(fn, 1, bw, 0), e1, bw);
                int res = (strcmp(m, "bts") == 0) ? hl_expr_binop(fn, HLB_OR, e0, bit, bw)
                        : (strcmp(m, "btr") == 0) ? hl_expr_binop(fn, HLB_AND, e0, hl_expr_unop(fn, HLU_BITNOT, bit, bw), bw)
                                                  : hl_expr_binop(fn, HLB_XOR, e0, bit, bw);
                if (o0.kind == HLO_REG) {
                    hl_def_reg(c, bi, in->ip, o0.reg, bw, 0, res);
                    hl_mark_arg_written(fn, o0.reg, 0, &written_gpr, &written_flt);
                    if (o0.reg == fn->ret_reg) { ret_valid = 1; last_ret_is_flt = 0; }
                } else if (o0.kind == HLO_MEM) {
                    hl_lift_mem_store(c, bi, in->ip, &o0, in, res, bw, 0, pre_sp, pre_bp, pre_has_bp, out_args, &nout_args);
                }
                continue;
            }

            /* LEA */
            if (strcmp(m, "lea") == 0 && o0.kind == HLO_REG && o1.kind == HLO_MEM) {
                int bw = o0.bits ? o0.bits : fn->ptr_bits;
                int64_t lea_soff = 0;
                int is_stk_lea = hl_mem_to_stack_off_ex(fn, &o1, pre_sp, pre_bp, pre_has_bp,
                                                        c->cur_alias_reg, c->cur_alias_delta, &lea_soff);
                int ae = hl_lift_mem_addr(c, &o1, in, pre_sp, pre_bp, pre_has_bp);
                if (ae >= 0 && bw < fn->ptr_bits) fn->exprs[ae].bits = (uint8_t)bw;
                hl_def_reg(c, bi, in->ip, o0.reg, bw, 0, ae);
                if (is_stk_lea && o0.reg != fn->sp_reg && o0.reg != fn->bp_reg) {
                    c->cur_alias_reg   = o0.reg;
                    c->cur_alias_delta = lea_soff;
                }
                hl_mark_arg_written(fn, o0.reg, 0, &written_gpr, &written_flt);
                if (o0.reg == fn->ret_reg) { ret_valid = 1; last_ret_is_flt = 0; }
                continue;
            }

            /* movzx / movsx / movsxd */
            if ((strcmp(m, "movzx") == 0 || strcmp(m, "movsx") == 0 || strcmp(m, "movsxd") == 0) &&
                o0.kind == HLO_REG) {
                int is_sext = (strcmp(m, "movzx") != 0);
                int db = o0.bits ? o0.bits : 32;
                int sb = o1.bits ? o1.bits : (strcmp(m, "movsxd") == 0 ? 32 : 8);
                int src_e = hl_lift_opr_read(c, &o1, in, sb, 0, pre_sp, pre_bp, pre_has_bp);
                if (src_e >= 0 && fn->exprs[src_e].kind == HLE_DEREF) {
                    fn->exprs[src_e].is_signed = (uint8_t)(is_sext ? 1 : 0);
                }
                int ue = hl_expr_unop(fn, is_sext ? HLU_SEXT : HLU_ZEXT, src_e, db);
                hl_def_reg(c, bi, in->ip, o0.reg, db, 0, ue);
                hl_mark_arg_written(fn, o0.reg, 0, &written_gpr, &written_flt);
                if (o0.reg == fn->ret_reg) { ret_valid = 1; last_ret_is_flt = 0; }
                continue;
            }

            /* cbw / cwde / cdqe */
            if (strcmp(m, "cbw") == 0 || strcmp(m, "cwde") == 0 || strcmp(m, "cdqe") == 0) {
                int db = (strcmp(m, "cdqe") == 0) ? 64 : (strcmp(m, "cwde") == 0 ? 32 : 16);
                int e0 = hl_read_reg_expr(c, 0, db / 2, 0, 0);
                int ue = hl_expr_unop(fn, HLU_SEXT, e0, db);
                hl_def_reg(c, bi, in->ip, 0, db, 0, ue);
                if (fn->ret_reg == 0) { ret_valid = 1; last_ret_is_flt = 0; }
                continue;
            }

            /* cwd / cdq / cqo */
            if (strcmp(m, "cwd") == 0 || strcmp(m, "cdq") == 0 || strcmp(m, "cqo") == 0) {
                int bw = (strcmp(m, "cqo") == 0) ? 64 : (strcmp(m, "cdq") == 0 ? 32 : 16);
                int e0 = hl_read_reg_expr(c, 0, bw, 0, 0);
                int sh = hl_expr_binop(fn, HLB_SAR, e0, hl_expr_int(fn, (uint64_t)(bw - 1), bw, 0), bw);
                hl_def_reg(c, bi, in->ip, 2, bw, 0, sh);
                continue;
            }

            /* Scalar & Vector MOVs */
            if (hl_is_mov_mnem(m) || strcmp(m, "movd") == 0 || strcmp(m, "movlps") == 0 ||
                strcmp(m, "movlpd") == 0 || strcmp(m, "movhps") == 0 || strcmp(m, "movhpd") == 0 ||
                strcmp(m, "vmovss") == 0 || strcmp(m, "vmovsd") == 0) {
                int is_scalar_fp = (strcmp(m, "movss") == 0 || strcmp(m, "vmovss") == 0 ||
                                    strcmp(m, "movsd") == 0 || strcmp(m, "vmovsd") == 0);
                int is_vec_fp_reg_copy = ((strcmp(m, "movaps") == 0 || strcmp(m, "movapd") == 0 ||
                                           strcmp(m, "vmovaps") == 0 || strcmp(m, "vmovapd") == 0) &&
                                          o0.kind == HLO_REG && o1.kind == HLO_REG && o1.reg >= 16);
                int fl_sz = 0;
                if (strcmp(m, "movss") == 0 || strcmp(m, "vmovss") == 0) fl_sz = 1;
                else if (strcmp(m, "movsd") == 0 || strcmp(m, "vmovsd") == 0 ||
                         strstr(m, "pd") != NULL) fl_sz = 2;
                else if (strstr(m, "ps") != NULL) {
                    if (is_vec_fp_reg_copy) fl_sz = (c->cur_bits[o1.reg] == 32) ? 1 : 2;
                    else fl_sz = 1;
                }
                int bw = fl_sz ? (fl_sz == 2 ? 64 : 32)
                               : (o0.bits ? o0.bits : (o1.bits ? o1.bits : fn->ptr_bits));
                if (bw > 64) bw = fl_sz ? 64 : fn->ptr_bits;

                int src_e = hl_lift_opr_read(c, &o1, in, bw, fl_sz, pre_sp, pre_bp, pre_has_bp);
                if (o0.kind == HLO_REG) {
                    if (o0.is_hi8) {
                        int old_e = hl_read_reg_expr(c, o0.reg, 32, 0, 0);
                        int clr = hl_expr_binop(fn, HLB_AND, old_e, hl_expr_int(fn, ~0xFF00ULL, 32, 0), 32);
                        int ins = hl_expr_binop(fn, HLB_SHL, hl_expr_binop(fn, HLB_AND, src_e, hl_expr_int(fn, 0xFF, 32, 0), 32),
                                                hl_expr_int(fn, 8, 32, 0), 32);
                        src_e = hl_expr_binop(fn, HLB_OR, clr, ins, 32);
                        bw = 32;
                    }
                    int is_f = fl_sz ? 1 : (src_e >= 0 && fn->exprs[src_e].is_flt);
                    hl_def_reg(c, bi, in->ip, o0.reg, bw, is_f, src_e);
                    hl_mark_arg_written(fn, o0.reg, is_f, &written_gpr, &written_flt);
                    if (o0.reg == fn->ret_reg) { ret_valid = 1; last_ret_is_flt = 0; }
                    if (o0.reg == c->flt_ret_reg &&
                        (is_scalar_fp || (is_vec_fp_reg_copy && !hl_next_ins_is_vec_store_xmm0(g, gb, k, fn)))) {
                        fret_valid      = 1;
                        last_ret_is_flt = 1;
                        fret_bits       = (bw == 32) ? 32 : 64;
                    }
                } else if (o0.kind == HLO_MEM) {
                    int is_f = fl_sz ? 1 : (src_e >= 0 && fn->exprs[src_e].is_flt);
                    hl_lift_mem_store(c, bi, in->ip, &o0, in, src_e, bw, is_f, pre_sp, pre_bp, pre_has_bp, out_args, &nout_args);
                }
                continue;
            }

            /* Float conversions: cvtsi2ss/sd, cvttss2si/sd2si, cvtss2sd, cvtsd2ss */
            if (strncmp(m, "cvt", 3) == 0 || strncmp(m, "vcvt", 4) == 0) {
                const char *cm = (m[0] == 'v') ? (m + 1) : m;
                if (o0.kind == HLO_REG) {
                    const hl_opr *src_op = (nops == 3) ? &o2 : &o1;
                    if (strstr(cm, "si2ss") || strstr(cm, "si2sd")) {
                        int db = strstr(cm, "2sd") ? 64 : 32;
                        int sb = src_op->bits ? src_op->bits : 32;
                        int se = hl_lift_opr_read(c, src_op, in, sb, 0, pre_sp, pre_bp, pre_has_bp);
                        int ue = hl_expr_unop(fn, HLU_I2F, se, db);
                        hl_def_reg(c, bi, in->ip, o0.reg, db, 1, ue);
                        hl_mark_arg_written(fn, o0.reg, 1, &written_gpr, &written_flt);
                        if (o0.reg == c->flt_ret_reg) {
                            fret_valid      = 1;
                            last_ret_is_flt = 1;
                            fret_bits       = db;
                        }
                    } else if (strstr(cm, "2si")) {
                        int db = o0.bits ? o0.bits : 32;
                        int sf = strstr(cm, "sd2") ? 2 : 1;
                        int se = hl_lift_opr_read(c, src_op, in, sf == 2 ? 64 : 32, sf, pre_sp, pre_bp, pre_has_bp);
                        int ue = hl_expr_unop(fn, HLU_F2I, se, db);
                        hl_def_reg(c, bi, in->ip, o0.reg, db, 0, ue);
                        hl_mark_arg_written(fn, o0.reg, 0, &written_gpr, &written_flt);
                        if (o0.reg == fn->ret_reg) { ret_valid = 1; last_ret_is_flt = 0; }
                    } else if (strstr(cm, "ss2sd") || strstr(cm, "sd2ss")) {
                        int db = strstr(cm, "2sd") ? 64 : 32;
                        int sf = (db == 64) ? 1 : 2;
                        int se = hl_lift_opr_read(c, src_op, in, sf == 2 ? 64 : 32, sf, pre_sp, pre_bp, pre_has_bp);
                        int ue = hl_expr_unop(fn, HLU_CAST, se, db);
                        if (ue >= 0) fn->exprs[ue].is_flt = 1;
                        hl_def_reg(c, bi, in->ip, o0.reg, db, 1, ue);
                        hl_mark_arg_written(fn, o0.reg, 1, &written_gpr, &written_flt);
                        if (o0.reg == c->flt_ret_reg) {
                            fret_valid      = 1;
                            last_ret_is_flt = 1;
                            fret_bits       = db;
                        }
                    }
                }
                continue;
            }

            /* Scalar sqrt: sqrtss / sqrtsd / vsqrtss / vsqrtsd */
            if (strcmp(m, "sqrtss") == 0 || strcmp(m, "sqrtsd") == 0 ||
                strcmp(m, "vsqrtss") == 0 || strcmp(m, "vsqrtsd") == 0) {
                if (o0.kind == HLO_REG) {
                    int fbits = (strstr(m, "sd") != NULL) ? 64 : 32;
                    int fs = (fbits == 32) ? 1 : 2;
                    const hl_opr *src_op = (nops == 3) ? &o2 : &o1;
                    int se = hl_lift_opr_read(c, src_op, in, fbits, fs, pre_sp, pre_bp, pre_has_bp);
                    int ce = hl_expr_new(fn, HLE_CALL);
                    if (ce >= 0) {
                        fn->exprs[ce].narg = 1;
                        fn->exprs[ce].args[0] = se;
                        fn->exprs[ce].bits = (uint8_t)fbits;
                        fn->exprs[ce].is_flt = 1;
                        fn->exprs[ce].ty.kind = (fbits == 32) ? HL_TY_F32 : HL_TY_F64;
                        fn->exprs[ce].ty.bits = (uint8_t)fbits;
                        snprintf(fn->exprs[ce].sym, sizeof(fn->exprs[ce].sym), "%s", fbits == 32 ? "sqrtf" : "sqrt");
                    }
                    hl_def_reg(c, bi, in->ip, o0.reg, fbits, 1, ce);
                    hl_mark_arg_written(fn, o0.reg, 1, &written_gpr, &written_flt);
                    if (o0.reg == c->flt_ret_reg) {
                        fret_valid      = 1;
                        last_ret_is_flt = 1;
                        fret_bits       = fbits;
                    }
                }
                continue;
            }

            /* Scalar FMA: vfmadd*ss/*sd, vfmsub*ss/*sd, vfnmadd*ss/*sd, vfnmsub*ss/*sd */
            if ((strncmp(m, "vfmadd", 6) == 0 || strncmp(m, "vfmsub", 6) == 0 ||
                 strncmp(m, "vfnmadd", 7) == 0 || strncmp(m, "vfnmsub", 7) == 0) &&
                o0.kind == HLO_REG && nops == 3) {
                size_t ml = strlen(m);
                int is_sd = (ml >= 2 && m[ml - 2] == 's' && m[ml - 1] == 'd');
                int is_ss = (ml >= 2 && m[ml - 2] == 's' && m[ml - 1] == 's');
                if (is_sd || is_ss) {
                    int fbits = is_sd ? 64 : 32;
                    int fs = is_sd ? 2 : 1;
                    int e0 = hl_lift_opr_read(c, &o0, in, fbits, fs, pre_sp, pre_bp, pre_has_bp);
                    int e1 = hl_lift_opr_read(c, &o1, in, fbits, fs, pre_sp, pre_bp, pre_has_bp);
                    int e2 = hl_lift_opr_read(c, &o2, in, fbits, fs, pre_sp, pre_bp, pre_has_bp);
                    int m0 = e0, m1 = e1, addend = e2;
                    if (strstr(m, "132")) { m0 = e0; m1 = e2; addend = e1; }
                    else if (strstr(m, "213")) { m0 = e1; m1 = e0; addend = e2; }
                    else if (strstr(m, "231")) { m0 = e1; m1 = e2; addend = e0; }
                    int prod = hl_expr_binop(fn, HLB_FMUL, m0, m1, fbits);
                    if (prod >= 0) fn->exprs[prod].is_flt = 1;
                    int res = -1;
                    if (strncmp(m, "vfmadd", 6) == 0) {
                        res = hl_expr_binop(fn, HLB_FADD, prod, addend, fbits);
                    } else if (strncmp(m, "vfmsub", 6) == 0) {
                        res = hl_expr_binop(fn, HLB_FSUB, prod, addend, fbits);
                    } else if (strncmp(m, "vfnmadd", 7) == 0) {
                        res = hl_expr_binop(fn, HLB_FSUB, addend, prod, fbits);
                    } else {
                        int nprod = hl_expr_unop(fn, HLU_FNEG, prod, fbits);
                        res = hl_expr_binop(fn, HLB_FSUB, nprod, addend, fbits);
                    }
                    if (res >= 0) fn->exprs[res].is_flt = 1;
                    hl_def_reg(c, bi, in->ip, o0.reg, fbits, 1, res);
                    hl_mark_arg_written(fn, o0.reg, 1, &written_gpr, &written_flt);
                    if (o0.reg == c->flt_ret_reg) {
                        fret_valid      = 1;
                        last_ret_is_flt = 1;
                        fret_bits       = fbits;
                    }
                    continue;
                }
            }

            /* XMM bitwise idioms: xorps/xorpd/pxor (0.0 or FNEG) & andps/andpd (FABS) */
            if (strcmp(m, "xorps") == 0 || strcmp(m, "xorpd") == 0 || strcmp(m, "pxor") == 0 ||
                strcmp(m, "vxorps") == 0 || strcmp(m, "vxorpd") == 0 || strcmp(m, "vpxor") == 0 ||
                strcmp(m, "andps") == 0 || strcmp(m, "andpd") == 0 ||
                strcmp(m, "vandps") == 0 || strcmp(m, "vandpd") == 0) {
                if (o0.kind == HLO_REG) {
                    const hl_opr *a_op = (nops == 3) ? &o1 : &o0;
                    const hl_opr *b_op = (nops == 3) ? &o2 : &o1;
                    int is_xor = (strstr(m, "xor") != NULL);
                    int is_pd  = (strstr(m, "pd") != NULL);
                    int is_ps  = (strstr(m, "ps") != NULL);
                    int fbits  = is_ps ? 32 : 64;

                    if (is_xor && a_op->kind == HLO_REG && b_op->kind == HLO_REG && a_op->reg == b_op->reg) {
                        int ze = (is_ps || is_pd) ? hl_expr_flt(fn, 0.0, fbits)
                                                  : hl_expr_int(fn, 0, 64, 0);
                        hl_def_reg(c, bi, in->ip, o0.reg, fbits, (is_ps || is_pd), ze);
                        hl_mark_arg_written(fn, o0.reg, (is_ps || is_pd), &written_gpr, &written_flt);
                        if (o0.reg == c->flt_ret_reg && (is_ps || is_pd) &&
                            !hl_next_ins_is_vec_store_xmm0(g, gb, k, fn)) {
                            fret_valid      = 1;
                            last_ret_is_flt = 1;
                            fret_bits       = fbits;
                        }
                        continue;
                    }

                    /* Check .rdata sign-bit flip or abs mask */
                    if (b_op->kind == HLO_MEM && (b_op->is_abs || (b_op->reg < 0 && b_op->idx < 0)) && b_op->seg == 0) {
                        uint64_t va = (in->has_target && in->target_mem) ? in->target : b_op->uval;
                        uint64_t raw32 = 0, raw64 = 0;
                        int ok32 = hl_try_read_ro_float(fn->a, va, 32, NULL, &raw32);
                        int ok64 = hl_try_read_ro_float(fn->a, va, 64, NULL, &raw64);
                        if (is_xor && ((ok32 && raw32 == 0x80000000ULL) || (ok64 && raw64 == 0x8000000000000000ULL))) {
                            int mb = (ok64 && raw64 == 0x8000000000000000ULL) ? 64 : 32;
                            int ae = hl_lift_opr_read(c, a_op, in, mb, mb == 64 ? 2 : 1, pre_sp, pre_bp, pre_has_bp);
                            int ue = hl_expr_unop(fn, HLU_FNEG, ae, mb);
                            hl_def_reg(c, bi, in->ip, o0.reg, mb, 1, ue);
                            hl_mark_arg_written(fn, o0.reg, 1, &written_gpr, &written_flt);
                            if (o0.reg == c->flt_ret_reg) {
                                fret_valid      = 1;
                                last_ret_is_flt = 1;
                                fret_bits       = mb;
                            }
                            continue;
                        }
                        if (!is_xor && ((ok32 && raw32 == 0x7FFFFFFFULL) || (ok64 && raw64 == 0x7FFFFFFFFFFFFFFFULL))) {
                            int mb = (ok64 && raw64 == 0x7FFFFFFFFFFFFFFFULL) ? 64 : 32;
                            int ae = hl_lift_opr_read(c, a_op, in, mb, mb == 64 ? 2 : 1, pre_sp, pre_bp, pre_has_bp);
                            int ue = hl_expr_unop(fn, HLU_FABS, ae, mb);
                            hl_def_reg(c, bi, in->ip, o0.reg, mb, 1, ue);
                            hl_mark_arg_written(fn, o0.reg, 1, &written_gpr, &written_flt);
                            if (o0.reg == c->flt_ret_reg) {
                                fret_valid      = 1;
                                last_ret_is_flt = 1;
                                fret_bits       = mb;
                            }
                            continue;
                        }
                    }

                    int ae = hl_lift_opr_read(c, a_op, in, fbits, 0, pre_sp, pre_bp, pre_has_bp);
                    int be = hl_lift_opr_read(c, b_op, in, fbits, 0, pre_sp, pre_bp, pre_has_bp);
                    int re = hl_expr_binop(fn, is_xor ? HLB_XOR : HLB_AND, ae, be, fbits);
                    hl_def_reg(c, bi, in->ip, o0.reg, fbits, 0, re);
                    hl_mark_arg_written(fn, o0.reg, 0, &written_gpr, &written_flt);
                }
                continue;
            }

            /* Scalar/Packed Float arithmetic: addss/sd, subss/sd, mulss/sd, divss/sd, min/max */
            {
                uint8_t fbop = 0;
                int fbits = 64;
                if (hl_x86_is_flt_arith(m, &fbop, &fbits) && o0.kind == HLO_REG) {
                    const hl_opr *a_op = (nops == 3) ? &o1 : &o0;
                    const hl_opr *b_op = (nops == 3) ? &o2 : &o1;
                    int fs = (fbits == 32) ? 1 : 2;
                    int ae = hl_lift_opr_read(c, a_op, in, fbits, fs, pre_sp, pre_bp, pre_has_bp);
                    int be = hl_lift_opr_read(c, b_op, in, fbits, fs, pre_sp, pre_bp, pre_has_bp);
                    int re = hl_expr_binop(fn, fbop, ae, be, fbits);
                    if (re >= 0) fn->exprs[re].is_flt = 1;
                    hl_def_reg(c, bi, in->ip, o0.reg, fbits, 1, re);
                    hl_mark_arg_written(fn, o0.reg, 1, &written_gpr, &written_flt);
                    if (o0.reg == c->flt_ret_reg) {
                        fret_valid      = 1;
                        last_ret_is_flt = 1;
                        fret_bits       = fbits;
                    }
                    continue;
                }
            }

            /* 1-op mul / imul (rdx:rax = rax * o0) */
            if ((strcmp(m, "mul") == 0 || strcmp(m, "imul") == 0) && nops == 1 && o0.kind != HLO_NONE) {
                int is_s = (m[0] == 'i');
                int bw   = o0.bits ? o0.bits : fn->ptr_bits;
                int e_ax = hl_read_reg_expr(c, 0, bw, 0, 0);
                int e_op = hl_lift_opr_read(c, &o0, in, bw, 0, pre_sp, pre_bp, pre_has_bp);

                int lo = hl_expr_binop(fn, HLB_MUL, e_ax, e_op, bw);
                if (lo >= 0) fn->exprs[lo].is_signed = (uint8_t)is_s;

                /* Hi-part: ((wide)(rax * op) >> bw) for magic division recognition */
                int wide_b = (bw <= 32) ? 64 : 128;
                int wmul = hl_expr_binop(fn, HLB_MUL, hl_expr_clone(fn, e_ax), hl_expr_clone(fn, e_op), wide_b);
                if (wmul >= 0) fn->exprs[wmul].is_signed = (uint8_t)is_s;
                int hi = hl_expr_binop(fn, is_s ? HLB_SAR : HLB_SHR, wmul,
                                       hl_expr_int(fn, (uint64_t)bw, wide_b, 0), bw);
                if (hi >= 0) fn->exprs[hi].is_signed = (uint8_t)is_s;

                hl_def_reg(c, bi, in->ip, 0, bw, 0, lo);
                hl_def_reg(c, bi, in->ip, 2, bw, 0, hi);
                hl_mark_arg_written(fn, 2, 0, &written_gpr, &written_flt);
                if (fn->ret_reg == 0) { ret_valid = 1; last_ret_is_flt = 0; }
                continue;
            }

            /* 2-op and 3-op imul */
            if (strcmp(m, "imul") == 0 && o0.kind == HLO_REG) {
                int bw = o0.bits ? o0.bits : fn->ptr_bits;
                int a_e = (nops == 3)
                        ? hl_lift_opr_read(c, &o1, in, bw, 0, pre_sp, pre_bp, pre_has_bp)
                        : hl_lift_opr_read(c, &o0, in, bw, 0, pre_sp, pre_bp, pre_has_bp);
                int b_e = (nops == 3)
                        ? hl_lift_opr_read(c, &o2, in, bw, 0, pre_sp, pre_bp, pre_has_bp)
                        : hl_lift_opr_read(c, &o1, in, bw, 0, pre_sp, pre_bp, pre_has_bp);
                int re = hl_expr_binop(fn, HLB_MUL, a_e, b_e, bw);
                if (re >= 0) fn->exprs[re].is_signed = 1;
                hl_def_reg(c, bi, in->ip, o0.reg, bw, 0, re);
                hl_mark_arg_written(fn, o0.reg, 0, &written_gpr, &written_flt);
                if (o0.reg == fn->ret_reg) { ret_valid = 1; last_ret_is_flt = 0; }
                continue;
            }

            /* div / idiv (rax = rax / o0, rdx = rax % o0) */
            if ((strcmp(m, "div") == 0 || strcmp(m, "idiv") == 0) && o0.kind != HLO_NONE) {
                int is_s = (m[0] == 'i');
                int bw   = o0.bits ? o0.bits : fn->ptr_bits;
                int e_ax = hl_read_reg_expr(c, 0, bw, 0, 0);
                int e_op = hl_lift_opr_read(c, &o0, in, bw, 0, pre_sp, pre_bp, pre_has_bp);
                int q_e  = hl_expr_binop(fn, is_s ? HLB_SDIV : HLB_UDIV, e_ax, e_op, bw);
                int r_e  = hl_expr_binop(fn, is_s ? HLB_SMOD : HLB_UMOD,
                                         hl_expr_clone(fn, e_ax), hl_expr_clone(fn, e_op), bw);
                hl_def_reg(c, bi, in->ip, 0, bw, 0, q_e);
                hl_def_reg(c, bi, in->ip, 2, bw, 0, r_e);
                hl_mark_arg_written(fn, 2, 0, &written_gpr, &written_flt);
                if (fn->ret_reg == 0) { ret_valid = 1; last_ret_is_flt = 0; }
                continue;
            }

            /* sbb / adc */
            if (strcmp(m, "sbb") == 0 || strcmp(m, "adc") == 0) {
                int is_sbb = (m[0] == 's');
                int bw = o0.bits ? o0.bits : (o1.bits ? o1.bits : fn->ptr_bits);
                int cf = hl_eval_cf(fn, &fl);
                int res = -1;
                if (is_sbb && o0.kind == HLO_REG && o1.kind == HLO_REG && o0.reg == o1.reg) {
                    /* sbb r, r -> (cf ? -1 : 0) */
                    if (cf >= 0) {
                        int te = hl_expr_new(fn, HLE_TERNARY);
                        if (te >= 0) {
                            fn->exprs[te].sub0 = cf;
                            fn->exprs[te].sub1 = hl_expr_int(fn, hl_mask_bits(~0ULL, bw), bw, 1);
                            fn->exprs[te].sub2 = hl_expr_int(fn, 0, bw, 1);
                            fn->exprs[te].bits = (uint8_t)bw;
                            fn->exprs[te].is_signed = 1;
                        }
                        res = te;
                    } else {
                        res = hl_expr_int(fn, 0, bw, 1);
                    }
                } else {
                    int e0 = hl_lift_opr_read(c, &o0, in, bw, 0, pre_sp, pre_bp, pre_has_bp);
                    int e1 = hl_lift_opr_read(c, &o1, in, bw, 0, pre_sp, pre_bp, pre_has_bp);
                    int base = (o1.kind == HLO_IMM && o1.uval == 0)
                             ? e0
                             : hl_expr_binop(fn, is_sbb ? HLB_SUB : HLB_ADD, e0, e1, bw);
                    res = (cf >= 0) ? hl_expr_binop(fn, is_sbb ? HLB_SUB : HLB_ADD, base, cf, bw) : base;
                }
                if (o0.kind == HLO_REG) {
                    int nv = hl_def_reg(c, bi, in->ip, o0.reg, bw, 0, res);
                    hl_mark_arg_written(fn, o0.reg, 0, &written_gpr, &written_flt);
                    if (o0.reg == fn->ret_reg) { ret_valid = 1; last_ret_is_flt = 0; }
                    fl.kind = HLF_ZERO; fl.lhs_expr = hl_expr_var(fn, nv); fl.rhs_expr = -1;
                    fl.res_expr = fl.lhs_expr; fl.bits = bw; fl.is_flt = 0;
                } else if (o0.kind == HLO_MEM) {
                    hl_lift_mem_store(c, bi, in->ip, &o0, in, res, bw, 0, pre_sp, pre_bp, pre_has_bp, out_args, &nout_args);
                }
                continue;
            }

            /* Bit manipulation: bswap, popcnt, bsf/tzcnt, bsr/lzcnt */
            if (strcmp(m, "bswap") == 0 && o0.kind == HLO_REG) {
                int bw = o0.bits ? o0.bits : 32;
                int e0 = hl_lift_opr_read(c, &o0, in, bw, 0, pre_sp, pre_bp, pre_has_bp);
                int ue = hl_expr_unop(fn, HLU_BSWAP, e0, bw);
                hl_def_reg(c, bi, in->ip, o0.reg, bw, 0, ue);
                hl_mark_arg_written(fn, o0.reg, 0, &written_gpr, &written_flt);
                if (o0.reg == fn->ret_reg) { ret_valid = 1; last_ret_is_flt = 0; }
                continue;
            }
            if ((strcmp(m, "popcnt") == 0 || strcmp(m, "bsf") == 0 || strcmp(m, "tzcnt") == 0 ||
                 strcmp(m, "bsr") == 0 || strcmp(m, "lzcnt") == 0) && o0.kind == HLO_REG) {
                int bw = o0.bits ? o0.bits : 32;
                uint8_t uop = (strcmp(m, "popcnt") == 0) ? HLU_POPCNT
                            : (strcmp(m, "bsf") == 0 || strcmp(m, "tzcnt") == 0) ? HLU_CTZ : HLU_CLZ;
                int e1 = hl_lift_opr_read(c, &o1, in, bw, 0, pre_sp, pre_bp, pre_has_bp);
                int ue = hl_expr_unop(fn, uop, e1, bw);
                hl_def_reg(c, bi, in->ip, o0.reg, bw, 0, ue);
                hl_mark_arg_written(fn, o0.reg, 0, &written_gpr, &written_flt);
                if (o0.reg == fn->ret_reg) { ret_valid = 1; last_ret_is_flt = 0; }
                /* bsf/bsr set ZF if src == 0 */
                if (strcmp(m, "bsf") == 0 || strcmp(m, "bsr") == 0) {
                    fl.kind = HLF_ZERO; fl.lhs_expr = hl_expr_clone(fn, e1); fl.rhs_expr = -1;
                    fl.res_expr = fl.lhs_expr; fl.bits = bw; fl.is_flt = 0;
                }
                continue;
            }

            /* xchg / xadd */
            if (strcmp(m, "xchg") == 0) {
                if (o0.kind == HLO_REG && o1.kind == HLO_REG && o0.reg == o1.reg) continue;
                int bw = o0.bits ? o0.bits : (o1.bits ? o1.bits : fn->ptr_bits);
                int e0 = hl_lift_opr_read(c, &o0, in, bw, 0, pre_sp, pre_bp, pre_has_bp);
                int e1 = hl_lift_opr_read(c, &o1, in, bw, 0, pre_sp, pre_bp, pre_has_bp);
                if (o0.kind == HLO_REG) {
                    hl_def_reg(c, bi, in->ip, o0.reg, bw, 0, e1);
                    if (o0.reg == fn->ret_reg) { ret_valid = 1; last_ret_is_flt = 0; }
                } else if (o0.kind == HLO_MEM) {
                    hl_lift_mem_store(c, bi, in->ip, &o0, in, e1, bw, 0, pre_sp, pre_bp, pre_has_bp, out_args, &nout_args);
                }
                if (o1.kind == HLO_REG) {
                    hl_def_reg(c, bi, in->ip, o1.reg, bw, 0, e0);
                    if (o1.reg == fn->ret_reg) { ret_valid = 1; last_ret_is_flt = 0; }
                }
                continue;
            }
            if (strcmp(m, "xadd") == 0) {
                int bw = o0.bits ? o0.bits : (o1.bits ? o1.bits : fn->ptr_bits);
                int e0 = hl_lift_opr_read(c, &o0, in, bw, 0, pre_sp, pre_bp, pre_has_bp);
                int e1 = hl_lift_opr_read(c, &o1, in, bw, 0, pre_sp, pre_bp, pre_has_bp);
                int sum = hl_expr_binop(fn, HLB_ADD, hl_expr_clone(fn, e0), e1, bw);
                if (o0.kind == HLO_REG) {
                    hl_def_reg(c, bi, in->ip, o0.reg, bw, 0, sum);
                    if (o0.reg == fn->ret_reg) { ret_valid = 1; last_ret_is_flt = 0; }
                } else if (o0.kind == HLO_MEM) {
                    hl_lift_mem_store(c, bi, in->ip, &o0, in, sum, bw, 0, pre_sp, pre_bp, pre_has_bp, out_args, &nout_args);
                }
                if (o1.kind == HLO_REG) {
                    hl_def_reg(c, bi, in->ip, o1.reg, bw, 0, e0);
                    if (o1.reg == fn->ret_reg) { ret_valid = 1; last_ret_is_flt = 0; }
                }
                continue;
            }

            /* cmovcc -> HLE_TERNARY */
            if (strncmp(m, "cmov", 4) == 0 && o0.kind == HLO_REG) {
                int bw   = o0.bits ? o0.bits : fn->ptr_bits;
                int cond = hl_eval_cc(fn, &fl, m + 4);
                int t_e  = hl_lift_opr_read(c, &o1, in, bw, 0, pre_sp, pre_bp, pre_has_bp);
                int f_e  = hl_lift_opr_read(c, &o0, in, bw, 0, pre_sp, pre_bp, pre_has_bp);
                int te   = hl_expr_new(fn, HLE_TERNARY);
                if (te >= 0) {
                    fn->exprs[te].sub0 = cond;
                    fn->exprs[te].sub1 = t_e;
                    fn->exprs[te].sub2 = f_e;
                    fn->exprs[te].bits = (uint8_t)bw;
                }
                hl_def_reg(c, bi, in->ip, o0.reg, bw, 0, te);
                hl_mark_arg_written(fn, o0.reg, 0, &written_gpr, &written_flt);
                if (o0.reg == fn->ret_reg) { ret_valid = 1; last_ret_is_flt = 0; }
                continue;
            }

            /* setcc -> boolean comparison expr */
            if (strncmp(m, "set", 3) == 0) {
                int cond = hl_eval_cc(fn, &fl, m + 3);
                if (o0.kind == HLO_REG) {
                    hl_def_reg(c, bi, in->ip, o0.reg, 8, 0, cond);
                    hl_mark_arg_written(fn, o0.reg, 0, &written_gpr, &written_flt);
                    if (o0.reg == fn->ret_reg) { ret_valid = 1; last_ret_is_flt = 0; }
                } else if (o0.kind == HLO_MEM) {
                    hl_lift_mem_store(c, bi, in->ip, &o0, in, cond, 8, 0, pre_sp, pre_bp, pre_has_bp, out_args, &nout_args);
                }
                continue;
            }

            /* shld / shrd */
            if ((strcmp(m, "shld") == 0 || strcmp(m, "shrd") == 0) && o0.kind == HLO_REG && nops == 3) {
                int bw = o0.bits ? o0.bits : fn->ptr_bits;
                int e0 = hl_lift_opr_read(c, &o0, in, bw, 0, pre_sp, pre_bp, pre_has_bp);
                int e1 = hl_lift_opr_read(c, &o1, in, bw, 0, pre_sp, pre_bp, pre_has_bp);
                int e2 = hl_lift_opr_read(c, &o2, in, 8, 0, pre_sp, pre_bp, pre_has_bp);
                int res = -1;
                if (o1.kind == HLO_REG && o1.reg == o0.reg) {
                    res = hl_expr_binop(fn, (strcmp(m, "shld") == 0) ? HLB_ROL : HLB_ROR, e0, e2, bw);
                } else {
                    int inv = hl_expr_binop(fn, HLB_SUB, hl_expr_int(fn, (uint64_t)bw, 8, 0), hl_expr_clone(fn, e2), 8);
                    int p1  = hl_expr_binop(fn, (strcmp(m, "shld") == 0) ? HLB_SHL : HLB_SHR, e0, e2, bw);
                    int p2  = hl_expr_binop(fn, (strcmp(m, "shld") == 0) ? HLB_SHR : HLB_SHL, e1, inv, bw);
                    res = hl_expr_binop(fn, HLB_OR, p1, p2, bw);
                }
                hl_def_reg(c, bi, in->ip, o0.reg, bw, 0, res);
                if (o0.reg == fn->ret_reg) { ret_valid = 1; last_ret_is_flt = 0; }
                continue;
            }

            /* inc / dec / neg / not */
            if (strcmp(m, "inc") == 0 || strcmp(m, "dec") == 0 ||
                strcmp(m, "neg") == 0 || strcmp(m, "not") == 0) {
                int bw = o0.bits ? o0.bits : fn->ptr_bits;
                int e0 = hl_lift_opr_read(c, &o0, in, bw, 0, pre_sp, pre_bp, pre_has_bp);
                int res = -1;
                if (strcmp(m, "inc") == 0) res = hl_expr_binop(fn, HLB_ADD, e0, hl_expr_int(fn, 1, bw, 0), bw);
                else if (strcmp(m, "dec") == 0) res = hl_expr_binop(fn, HLB_SUB, e0, hl_expr_int(fn, 1, bw, 0), bw);
                else if (strcmp(m, "neg") == 0) res = hl_expr_unop(fn, HLU_NEG, e0, bw);
                else res = hl_expr_unop(fn, HLU_BITNOT, e0, bw);

                if (o0.kind == HLO_REG) {
                    int nv = hl_def_reg(c, bi, in->ip, o0.reg, bw, 0, res);
                    hl_mark_arg_written(fn, o0.reg, 0, &written_gpr, &written_flt);
                    if (o0.reg == fn->ret_reg) { ret_valid = 1; last_ret_is_flt = 0; }
                    if (strcmp(m, "neg") == 0) {
                        fl.kind = HLF_NEG; fl.lhs_expr = hl_expr_clone(fn, e0); fl.rhs_expr = -1;
                        fl.res_expr = hl_expr_var(fn, nv); fl.bits = bw; fl.is_flt = 0;
                    } else if (strcmp(m, "not") != 0) {
                        fl.kind = HLF_ZERO; fl.lhs_expr = hl_expr_var(fn, nv); fl.rhs_expr = -1;
                        fl.res_expr = fl.lhs_expr; fl.bits = bw; fl.is_flt = 0;
                    }
                } else if (o0.kind == HLO_MEM) {
                    hl_lift_mem_store(c, bi, in->ip, &o0, in, res, bw, 0, pre_sp, pre_bp, pre_has_bp, out_args, &nout_args);
                    if (strcmp(m, "not") != 0) {
                        fl.kind = HLF_ZERO; fl.lhs_expr = hl_expr_clone(fn, res); fl.rhs_expr = -1;
                        fl.res_expr = fl.lhs_expr; fl.bits = bw; fl.is_flt = 0;
                    }
                }
                continue;
            }

            /* General integer ALU: add, sub, and, or, xor, shl/sal, shr, sar, rol, ror */
            {
                uint8_t bop = 0;
                int is_s = 0;
                if (hl_x86_alu_op(m, &bop, &is_s)) {
                    int bw = o0.bits ? o0.bits : (o1.bits ? o1.bits : fn->ptr_bits);
                    if ((bop == HLB_XOR || bop == HLB_SUB) &&
                        o0.kind == HLO_REG && o1.kind == HLO_REG && o0.reg == o1.reg) {
                        int ze = hl_expr_int(fn, 0, bw, 0);
                        int nv = hl_def_reg(c, bi, in->ip, o0.reg, bw, 0, ze);
                        hl_mark_arg_written(fn, o0.reg, 0, &written_gpr, &written_flt);
                        if (o0.reg == fn->ret_reg) { ret_valid = 1; last_ret_is_flt = 0; }
                        fl.kind = HLF_ZERO; fl.lhs_expr = hl_expr_var(fn, nv); fl.rhs_expr = -1;
                        fl.res_expr = fl.lhs_expr; fl.bits = bw; fl.is_flt = 0;
                        continue;
                    }

                    int e0 = hl_lift_opr_read(c, &o0, in, bw, 0, pre_sp, pre_bp, pre_has_bp);
                    int b1_w = (bop == HLB_SHL || bop == HLB_SHR || bop == HLB_SAR ||
                                bop == HLB_ROL || bop == HLB_ROR) ? 8 : bw;
                    int e1 = hl_lift_opr_read(c, &o1, in, b1_w, 0, pre_sp, pre_bp, pre_has_bp);
                    int res = hl_expr_binop(fn, bop, e0, e1, bw);
                    if (res >= 0 && is_s) fn->exprs[res].is_signed = 1;

                    if (o0.kind == HLO_REG) {
                        int nv = hl_def_reg(c, bi, in->ip, o0.reg, bw, 0, res);
                        hl_mark_arg_written(fn, o0.reg, 0, &written_gpr, &written_flt);
                        if (o0.reg == fn->ret_reg) { ret_valid = 1; last_ret_is_flt = 0; }
                        if (bop == HLB_SUB) {
                            fl.kind = HLF_CMP;
                            fl.lhs_expr = hl_expr_clone(fn, e0);
                            fl.rhs_expr = hl_expr_clone(fn, e1);
                            fl.res_expr = hl_expr_var(fn, nv);
                            fl.bits = bw; fl.is_flt = 0;
                        } else if (bop != HLB_ROL && bop != HLB_ROR) {
                            fl.kind = HLF_ZERO;
                            fl.lhs_expr = hl_expr_var(fn, nv);
                            fl.rhs_expr = -1;
                            fl.res_expr = fl.lhs_expr;
                            fl.bits = bw; fl.is_flt = 0;
                        }
                    } else if (o0.kind == HLO_MEM) {
                        hl_lift_mem_store(c, bi, in->ip, &o0, in, res, bw, 0, pre_sp, pre_bp, pre_has_bp, out_args, &nout_args);
                        if (bop == HLB_SUB) {
                            fl.kind = HLF_CMP;
                            fl.lhs_expr = hl_expr_clone(fn, e0);
                            fl.rhs_expr = hl_expr_clone(fn, e1);
                            fl.res_expr = hl_expr_clone(fn, res);
                            fl.bits = bw; fl.is_flt = 0;
                        } else if (bop != HLB_ROL && bop != HLB_ROR) {
                            fl.kind = HLF_ZERO;
                            fl.lhs_expr = hl_expr_clone(fn, res);
                            fl.rhs_expr = -1;
                            fl.res_expr = fl.lhs_expr;
                            fl.bits = bw; fl.is_flt = 0;
                        }
                    }
                    continue;
                }
            }
        } else {
            /* ==============================================================
             * ARM64 Instruction Semantics
             * ============================================================== */
            if (strcmp(m, "nop") == 0 || strcmp(m, "pacibsp") == 0 || strcmp(m, "autibsp") == 0 ||
                strcmp(m, "paciasp") == 0 || strcmp(m, "autiasp") == 0 || strcmp(m, "brk") == 0) {
                continue;
            }

            if (strcmp(m, "cmp") == 0 || strcmp(m, "cmn") == 0 || strcmp(m, "tst") == 0 || strcmp(m, "fcmp") == 0) {
                int is_fc = (strcmp(m, "fcmp") == 0);
                int bw = o0.bits ? o0.bits : 64;
                int e0 = hl_lift_opr_read(c, &o0, in, bw, is_fc ? (bw == 32 ? 1 : 2) : 0, pre_sp, pre_bp, pre_has_bp);
                int e1 = hl_lift_opr_read(c, &o1, in, bw, is_fc ? (bw == 32 ? 1 : 2) : 0, pre_sp, pre_bp, pre_has_bp);
                fl.lhs_expr = e0; fl.rhs_expr = e1; fl.res_expr = -1;
                fl.bits = bw; fl.is_flt = is_fc ? 1 : 0;
                fl.kind = is_fc ? HLF_FCMP : (strcmp(m, "tst") == 0 ? HLF_TEST : (strcmp(m, "cmn") == 0 ? HLF_CMN : HLF_CMP));
                continue;
            }

            if ((strcmp(m, "adrp") == 0 || strcmp(m, "adr") == 0) && o0.kind == HLO_REG) {
                uint64_t va = in->has_target ? in->target : o1.uval;
                int ae = (strcmp(m, "adr") == 0) ? hl_expr_addr_const(fn, va) : hl_expr_int(fn, va, 64, 0);
                hl_def_reg(c, bi, in->ip, o0.reg, 64, 0, ae);
                hl_mark_arg_written(fn, o0.reg, 0, &written_gpr, &written_flt);
                if (o0.reg == fn->ret_reg) { ret_valid = 1; last_ret_is_flt = 0; }
                continue;
            }

            if ((strcmp(m, "movz") == 0 || strcmp(m, "movn") == 0 || strcmp(m, "movk") == 0) && o0.kind == HLO_REG) {
                int bw = o0.bits ? o0.bits : 64;
                int sh = (nops >= 3) ? hl_a64_shift_amt(ops[2]) : 0;
                uint64_t val = (o1.uval & 0xFFFFULL) << (sh & 63);
                if (strcmp(m, "movn") == 0) val = hl_mask_bits(~val, bw);
                int res = -1;
                if (strcmp(m, "movk") == 0) {
                    int e0 = hl_read_reg_expr(c, o0.reg, bw, 0, 0);
                    uint64_t clr = hl_mask_bits(~(0xFFFFULL << (sh & 63)), bw);
                    int m0 = hl_expr_binop(fn, HLB_AND, e0, hl_expr_int(fn, clr, bw, 0), bw);
                    res = hl_expr_binop(fn, HLB_OR, m0, hl_expr_int(fn, val, bw, 0), bw);
                } else {
                    res = hl_expr_int(fn, val, bw, 0);
                }
                hl_def_reg(c, bi, in->ip, o0.reg, bw, 0, res);
                hl_mark_arg_written(fn, o0.reg, 0, &written_gpr, &written_flt);
                if (o0.reg == fn->ret_reg) { ret_valid = 1; last_ret_is_flt = 0; }
                continue;
            }

            if ((strcmp(m, "mov") == 0 || strcmp(m, "fmov") == 0) && o0.kind == HLO_REG) {
                int bw = o0.bits ? o0.bits : 64;
                int is_f = (m[0] == 'f') || o0.is_flt;
                int e1 = hl_lift_opr_read(c, &o1, in, bw, is_f, pre_sp, pre_bp, pre_has_bp);
                hl_def_reg(c, bi, in->ip, o0.reg, bw, is_f, e1);
                hl_mark_arg_written(fn, o0.reg, is_f, &written_gpr, &written_flt);
                if (o0.reg == fn->ret_reg) { ret_valid = 1; last_ret_is_flt = 0; }
                if (o0.reg == c->flt_ret_reg && is_f) {
                    fret_valid      = 1;
                    last_ret_is_flt = 1;
                    fret_bits       = (bw == 32) ? 32 : 64;
                }
                continue;
            }

            if (strcmp(m, "mvn") == 0 && o0.kind == HLO_REG) {
                int bw = o0.bits ? o0.bits : 64;
                int e1 = hl_lift_opr_read(c, (nops >= 3) ? &o2 : &o1, in, bw, 0, pre_sp, pre_bp, pre_has_bp);
                hl_def_reg(c, bi, in->ip, o0.reg, bw, 0, hl_expr_unop(fn, HLU_BITNOT, e1, bw));
                hl_mark_arg_written(fn, o0.reg, 0, &written_gpr, &written_flt);
                if (o0.reg == fn->ret_reg) { ret_valid = 1; last_ret_is_flt = 0; }
                continue;
            }

            if ((strcmp(m, "ldr") == 0 || strcmp(m, "ldrb") == 0 || strcmp(m, "ldrh") == 0 ||
                 strcmp(m, "ldrsb") == 0 || strcmp(m, "ldrsh") == 0 || strcmp(m, "ldrsw") == 0) &&
                o0.kind == HLO_REG) {
                int bw = (strcmp(m, "ldrb") == 0 || strcmp(m, "ldrsb") == 0) ? 8
                       : (strcmp(m, "ldrh") == 0 || strcmp(m, "ldrsh") == 0) ? 16
                       : (strcmp(m, "ldrsw") == 0) ? 32 : (o0.bits ? o0.bits : 64);
                int is_f = o0.is_flt;
                o1.bits = bw;
                int le = hl_lift_opr_read(c, &o1, in, bw, is_f, pre_sp, pre_bp, pre_has_bp);
                if (strncmp(m, "ldrs", 4) == 0) {
                    le = hl_expr_unop(fn, HLU_SEXT, le, o0.bits ? o0.bits : 64);
                }
                hl_def_reg(c, bi, in->ip, o0.reg, o0.bits ? o0.bits : 64, is_f, le);
                hl_mark_arg_written(fn, o0.reg, is_f, &written_gpr, &written_flt);
                if (o0.reg == fn->ret_reg) { ret_valid = 1; last_ret_is_flt = 0; }
                if (o0.reg == c->flt_ret_reg && is_f) {
                    fret_valid      = 1;
                    last_ret_is_flt = 1;
                    fret_bits       = (bw == 32) ? 32 : 64;
                }
                continue;
            }

            if (strcmp(m, "str") == 0 || strcmp(m, "strb") == 0 || strcmp(m, "strh") == 0) {
                int bw = (strcmp(m, "strb") == 0) ? 8 : (strcmp(m, "strh") == 0 ? 16 : (o0.bits ? o0.bits : 64));
                int is_f = o0.is_flt;
                o1.bits = bw;
                int ve = hl_lift_opr_read(c, &o0, in, bw, is_f, pre_sp, pre_bp, pre_has_bp);
                hl_lift_mem_store(c, bi, in->ip, &o1, in, ve, bw, is_f, pre_sp, pre_bp, pre_has_bp, out_args, &nout_args);
                continue;
            }

            if (strcmp(m, "ldp") == 0 || strcmp(m, "stp") == 0) {
                int is_ld = (m[0] == 'l');
                int bw = o0.bits ? o0.bits : 64;
                int step = bw / 8;
                int64_t use_sp = (o2.a64_wb == 1 && o2.reg == fn->sp_reg) ? (pre_sp + o2.disp) : pre_sp;
                hl_opr m0 = o2, m1 = o2;
                if (o2.a64_wb == 1 && o2.reg == fn->sp_reg) { m0.disp = 0; m1.disp = step; }
                else { m1.disp += step; }
                m0.bits = bw; m1.bits = bw;
                if (is_ld) {
                    if (o0.kind == HLO_REG) {
                        int e0 = hl_lift_opr_read(c, &m0, in, bw, o0.is_flt, use_sp, pre_bp, pre_has_bp);
                        hl_def_reg(c, bi, in->ip, o0.reg, bw, o0.is_flt, e0);
                    }
                    if (o1.kind == HLO_REG) {
                        int e1 = hl_lift_opr_read(c, &m1, in, bw, o1.is_flt, use_sp, pre_bp, pre_has_bp);
                        hl_def_reg(c, bi, in->ip, o1.reg, bw, o1.is_flt, e1);
                    }
                } else {
                    int v0 = hl_lift_opr_read(c, &o0, in, bw, o0.is_flt, use_sp, pre_bp, pre_has_bp);
                    int v1 = hl_lift_opr_read(c, &o1, in, bw, o1.is_flt, use_sp, pre_bp, pre_has_bp);
                    hl_lift_mem_store(c, bi, in->ip, &m0, in, v0, bw, o0.is_flt, use_sp, pre_bp, pre_has_bp, out_args, &nout_args);
                    hl_lift_mem_store(c, bi, in->ip, &m1, in, v1, bw, o1.is_flt, use_sp, pre_bp, pre_has_bp, out_args, &nout_args);
                }
                hl_step_sp_a64(fn, m, &o0, &o1, &o2, &o3, nops, &cur_sp, &cur_bp, &has_bp);
                continue;
            }

            if (strcmp(m, "csel") == 0 && o0.kind == HLO_REG) {
                int bw = o0.bits ? o0.bits : 64;
                int cond = hl_eval_cc(fn, &fl, ops[3]);
                int t_e = hl_lift_opr_read(c, &o1, in, bw, 0, pre_sp, pre_bp, pre_has_bp);
                int f_e = hl_lift_opr_read(c, &o2, in, bw, 0, pre_sp, pre_bp, pre_has_bp);
                int te = hl_expr_new(fn, HLE_TERNARY);
                if (te >= 0) {
                    fn->exprs[te].sub0 = cond; fn->exprs[te].sub1 = t_e;
                    fn->exprs[te].sub2 = f_e;  fn->exprs[te].bits = (uint8_t)bw;
                }
                hl_def_reg(c, bi, in->ip, o0.reg, bw, 0, te);
                hl_mark_arg_written(fn, o0.reg, 0, &written_gpr, &written_flt);
                if (o0.reg == fn->ret_reg) { ret_valid = 1; last_ret_is_flt = 0; }
                continue;
            }

            if ((strcmp(m, "mul") == 0 || strcmp(m, "madd") == 0 || strcmp(m, "msub") == 0) && o0.kind == HLO_REG) {
                int bw = o0.bits ? o0.bits : 64;
                int e1 = hl_lift_opr_read(c, &o1, in, bw, 0, pre_sp, pre_bp, pre_has_bp);
                int e2 = hl_lift_opr_read(c, &o2, in, bw, 0, pre_sp, pre_bp, pre_has_bp);
                int prod = hl_expr_binop(fn, HLB_MUL, e1, e2, bw);
                if (strcmp(m, "madd") == 0 && o3.kind != HLO_NONE) {
                    int e3 = hl_lift_opr_read(c, &o3, in, bw, 0, pre_sp, pre_bp, pre_has_bp);
                    prod = hl_expr_binop(fn, HLB_ADD, e3, prod, bw);
                } else if (strcmp(m, "msub") == 0 && o3.kind != HLO_NONE) {
                    int e3 = hl_lift_opr_read(c, &o3, in, bw, 0, pre_sp, pre_bp, pre_has_bp);
                    prod = hl_expr_binop(fn, HLB_SUB, e3, prod, bw);
                }
                hl_def_reg(c, bi, in->ip, o0.reg, bw, 0, prod);
                hl_mark_arg_written(fn, o0.reg, 0, &written_gpr, &written_flt);
                if (o0.reg == fn->ret_reg) { ret_valid = 1; last_ret_is_flt = 0; }
                continue;
            }

            /* ARM64 add reg, sp/fp, #imm -> &var_XX */
            if (strcmp(m, "add") == 0 && o0.kind == HLO_REG && o1.kind == HLO_REG &&
                (o1.reg == fn->sp_reg || (pre_has_bp && o1.reg == fn->bp_reg)) && o2.kind == HLO_IMM) {
                int64_t soff = ((o1.reg == fn->sp_reg) ? pre_sp : pre_bp) + o2.disp;
                int sv = hl_get_stk_var(c, soff, 64, 0, 0);
                if (sv >= 0) {
                    int ae = hl_expr_new(fn, HLE_ADDR);
                    if (ae >= 0) { fn->exprs[ae].sub0 = hl_expr_var(fn, sv); fn->exprs[ae].bits = 64; }
                    hl_def_reg(c, bi, in->ip, o0.reg, 64, 0, ae);
                    hl_mark_arg_written(fn, o0.reg, 0, &written_gpr, &written_flt);
                    if (o0.reg == fn->ret_reg) { ret_valid = 1; last_ret_is_flt = 0; }
                    continue;
                }
            }

            /* ARM64 ALU & FP */
            if (o0.kind == HLO_REG) {
                uint8_t bop = 0;
                int setf = 0, is_f = 0, is_bic = 0;
                if (strcmp(m, "add") == 0) bop = HLB_ADD;
                else if (strcmp(m, "adds") == 0) { bop = HLB_ADD; setf = 1; }
                else if (strcmp(m, "sub") == 0) bop = HLB_SUB;
                else if (strcmp(m, "subs") == 0) { bop = HLB_SUB; setf = 1; }
                else if (strcmp(m, "and") == 0) bop = HLB_AND;
                else if (strcmp(m, "ands") == 0) { bop = HLB_AND; setf = 1; }
                else if (strcmp(m, "bic") == 0) { bop = HLB_AND; is_bic = 1; }
                else if (strcmp(m, "orr") == 0) bop = HLB_OR;
                else if (strcmp(m, "eor") == 0) bop = HLB_XOR;
                else if (strcmp(m, "lsl") == 0) bop = HLB_SHL;
                else if (strcmp(m, "lsr") == 0) bop = HLB_SHR;
                else if (strcmp(m, "asr") == 0) bop = HLB_SAR;
                else if (strcmp(m, "ror") == 0) bop = HLB_ROR;
                else if (strcmp(m, "sdiv") == 0) bop = HLB_SDIV;
                else if (strcmp(m, "udiv") == 0) bop = HLB_UDIV;
                else if (strcmp(m, "fadd") == 0) { bop = HLB_FADD; is_f = 1; }
                else if (strcmp(m, "fsub") == 0) { bop = HLB_FSUB; is_f = 1; }
                else if (strcmp(m, "fmul") == 0) { bop = HLB_FMUL; is_f = 1; }
                else if (strcmp(m, "fdiv") == 0) { bop = HLB_FDIV; is_f = 1; }

                if (bop != 0) {
                    int bw = o0.bits ? o0.bits : 64;
                    int fs = is_f ? (bw == 32 ? 1 : 2) : 0;
                    int e1 = hl_lift_opr_read(c, &o1, in, bw, fs, pre_sp, pre_bp, pre_has_bp);
                    int e2 = hl_lift_opr_read(c, &o2, in, bw, fs, pre_sp, pre_bp, pre_has_bp);
                    if (is_bic) e2 = hl_expr_unop(fn, HLU_BITNOT, e2, bw);
                    int res = hl_expr_binop(fn, bop, e1, e2, bw);
                    int nv = hl_def_reg(c, bi, in->ip, o0.reg, bw, is_f, res);
                    hl_mark_arg_written(fn, o0.reg, is_f, &written_gpr, &written_flt);
                    if (o0.reg == fn->ret_reg) { ret_valid = 1; last_ret_is_flt = 0; }
                    if (o0.reg == c->flt_ret_reg && is_f) {
                        fret_valid      = 1;
                        last_ret_is_flt = 1;
                        fret_bits       = (bw == 32) ? 32 : 64;
                    }
                    if (setf) {
                        if (bop == HLB_SUB) {
                            fl.kind = HLF_CMP; fl.lhs_expr = hl_expr_clone(fn, e1);
                            fl.rhs_expr = hl_expr_clone(fn, e2); fl.res_expr = hl_expr_var(fn, nv);
                        } else {
                            fl.kind = HLF_ZERO; fl.lhs_expr = hl_expr_var(fn, nv);
                            fl.rhs_expr = -1; fl.res_expr = fl.lhs_expr;
                        }
                        fl.bits = bw; fl.is_flt = 0;
                    }
                    continue;
                }
            }
        }
    }

    c->blk_exit_fl[bi]              = fl;
    c->blk_exit_ret_valid[bi]       = (uint8_t)ret_valid;
    c->blk_exit_fret_valid[bi]      = (uint8_t)fret_valid;
    c->blk_exit_last_ret_is_flt[bi] = (uint8_t)last_ret_is_flt;
    c->blk_exit_fret_bits[bi]       = (uint8_t)fret_bits;
    if (nout_args > HL_MAX_OUT_ARGS) nout_args = HL_MAX_OUT_ARGS;
    c->blk_exit_nout_args[bi]       = nout_args;
    if (nout_args > 0) {
        memcpy(c->blk_exit_out_args[bi], out_args, (size_t)nout_args * sizeof(hl_out_arg));
    }
}

static void hl_lift_dom_dfs(hl_lift_ctx *c, int bi) {
    hl_fn *fn = c->fn;
    int saved_top[HL_LIFT_REGS];
    for (int r = 0; r < c->nregs; r++) saved_top[r] = c->reg_stk_len[r];

    /* Push PHI destinations for this block onto SSA register stacks */
    for (int r = 0; r < c->nregs; r++) {
        int psid = c->phi_stmt[bi][r];
        if (psid >= 0 && psid < fn->nstmt) {
            hl_reg_stk_push(c, r, fn->stmts[psid].dst_var);
        }
    }

    hl_lift_block(c, bi);

    /* Fill incoming PHI arguments on every outgoing CFG edge bi -> s */
    int succs[3] = {fn->blks[bi].out_t, fn->blks[bi].out_f, fn->blks[bi].out_u};
    for (int si = 0; si < 3; si++) {
        int s = succs[si];
        if (s < 0 || s >= fn->nblk) continue;
        /* Avoid duplicate edge if out_t == out_f */
        int dup = 0;
        for (int sj = 0; sj < si; sj++) {
            if (succs[sj] == s) { dup = 1; break; }
        }
        if (dup) continue;

        for (int r = 0; r < c->nregs; r++) {
            int psid = c->phi_stmt[s][r];
            if (psid < 0 || psid >= fn->nstmt) continue;
            hl_stmt *ps = &fn->stmts[psid];
            if (ps->nphi >= 8) continue;
            int has_blk = 0;
            for (int pi = 0; pi < (int)ps->nphi; pi++) {
                if (ps->phi_blks[pi] == bi) { has_blk = 1; break; }
            }
            if (has_blk) continue;
            int is_f = (!fn->is_a64 && r >= 16) || (fn->is_a64 && r >= 32);
            int vid = hl_get_reg_var(c, r, c->cur_bits[r] > 0 ? c->cur_bits[r] : fn->ptr_bits, is_f);
            ps->phi_vars[ps->nphi] = vid;
            ps->phi_blks[ps->nphi] = bi;
            ps->nphi++;
        }
    }

    /* Recurse on Dominator-Tree children */
    for (int ch = c->dom_head[bi]; ch >= 0; ch = c->dom_next[ch]) {
        hl_lift_dom_dfs(c, ch);
    }

    /* Restore SSA register stack heights */
    for (int r = 0; r < c->nregs; r++) c->reg_stk_len[r] = saved_top[r];
}

/* =========================================================================
 * Return Value Finalization, Switch Selector Recovery & hl_lift_cfg
 * ========================================================================= */

static void hl_count_non_ret_uses_expr(const hl_fn *fn, int eid, int *uses, int depth) {
    if (!fn || eid < 0 || eid >= fn->nexpr || depth > HL_MAX_DEPTH) return;
    const hl_expr *e = &fn->exprs[eid];
    if (e->kind == HLE_VAR && e->var_id >= 0 && e->var_id < fn->nvar) {
        uses[e->var_id]++;
    }
    if (e->sub0 >= 0) hl_count_non_ret_uses_expr(fn, e->sub0, uses, depth + 1);
    if (e->sub1 >= 0) hl_count_non_ret_uses_expr(fn, e->sub1, uses, depth + 1);
    if (e->sub2 >= 0) hl_count_non_ret_uses_expr(fn, e->sub2, uses, depth + 1);
    for (int i = 0; i < (int)e->narg && i < HL_MAX_CALL_ARG; i++) {
        if (e->args[i] >= 0) hl_count_non_ret_uses_expr(fn, e->args[i], uses, depth + 1);
    }
}

static void hl_finalize_returns_and_switches(hl_lift_ctx *c) {
    hl_fn *fn = c->fn;

    /* Check if this function itself has a known signature */
    hl_callee_sig self_sig;
    memset(&self_sig, 0, sizeof(self_sig));
    const char *self_sym = ana_sym_at(fn->a, fn->g->func_va);
    int self_known = hl_lookup_callee(fn->a, fn->types, fn->g->func_va, self_sym, &self_sig) ? 1 : 0;

    if (self_known && !self_sig.has_ret) {
        fn->has_ret_val  = 0;
        fn->ret_ty.kind  = HL_TY_VOID;
        fn->ret_ty.bits  = 0;
        for (int i = 0; i < c->nret_stmts; i++) {
            fn->stmts[c->ret_stmts[i]].rhs_expr = -1;
        }
    } else if (c->nret_stmts > 0) {
        int *non_ret_uses = (int *)calloc((size_t)(fn->nvar + 1), sizeof(int));
        if (non_ret_uses) {
            for (int b = 0; b < fn->nblk; b++) {
                const hl_blk *hb = &fn->blks[b];
                for (int si = 0; si < hb->nstmt; si++) {
                    const hl_stmt *s = &fn->stmts[hb->stmts[si]];
                    if (s->dead || s->kind == HLS_RET) continue;
                    hl_count_non_ret_uses_expr(fn, s->lhs_expr, non_ret_uses, 0);
                    hl_count_non_ret_uses_expr(fn, s->rhs_expr, non_ret_uses, 0);
                    hl_count_non_ret_uses_expr(fn, s->len_expr, non_ret_uses, 0);
                    if (s->kind == HLS_PHI) {
                        for (int pi = 0; pi < (int)s->nphi; pi++) {
                            int pv = s->phi_vars[pi];
                            if (pv >= 0 && pv < fn->nvar) non_ret_uses[pv]++;
                        }
                    }
                }
                hl_count_non_ret_uses_expr(fn, hb->cond_expr, non_ret_uses, 0);
                hl_count_non_ret_uses_expr(fn, hb->sw_expr, non_ret_uses, 0);
            }

            int any_dedicated = fn->has_ret_val || (self_known && self_sig.has_ret);
            int any_flt = 0;
            int any_flt_direct = 0;
            int any_unconsumed_gpr = 0;
            int flt_bits = 0;
            int ret_bits = fn->ptr_bits;

            for (int i = 0; i < c->nret_stmts; i++) {
                int rv = c->ret_vars[i];
                if (rv < 0 || rv >= fn->nvar) continue;
                /* Unconsumed ret_reg value => true return value */
                if (non_ret_uses[rv] == 0) {
                    if (c->ret_is_flt[i]) {
                        if (hl_var_has_real_flt_def(c, rv)) {
                            any_dedicated = 1;
                            any_flt = 1;
                            any_flt_direct = 1;
                            int fb = c->ret_flt_bits[i] ? (int)c->ret_flt_bits[i]
                                   : (fn->vars[rv].bits == 32 ? 32 : 64);
                            if (fb > flt_bits) flt_bits = fb;
                            if (fn->vars[rv].bits > 0) ret_bits = fn->vars[rv].bits;
                        } else {
                            fn->stmts[c->ret_stmts[i]].rhs_expr = -1;
                        }
                    } else {
                        any_dedicated = 1;
                        any_unconsumed_gpr = 1;
                        if (fn->vars[rv].bits > 0) ret_bits = fn->vars[rv].bits;
                    }
                }
            }
            if (!any_flt && self_known && self_sig.has_ret &&
                (self_sig.ret_ty.kind == HL_TY_F32 || self_sig.ret_ty.kind == HL_TY_F64)) {
                any_flt = 1;
                flt_bits = (self_sig.ret_ty.kind == HL_TY_F32) ? 32 : 64;
            }
            if (!any_flt && !any_unconsumed_gpr && c->flt_ret_reg >= 0) {
                for (int i = 0; i < c->nret_stmts; i++) {
                    int rfv = c->ret_flt_vars[i];
                    if (rfv >= 0 && rfv < fn->nvar &&
                        hl_var_has_real_flt_def(c, rfv) &&
                        non_ret_uses[rfv] == 0) {
                        any_dedicated = 1;
                        any_flt = 1;
                        int fb = (fn->vars[rfv].bits == 32) ? 32 : 64;
                        if (fb > flt_bits) flt_bits = fb;
                    }
                }
            }

            if (any_dedicated) {
                fn->has_ret_val = 1;
                if (any_flt) {
                    int fb = flt_bits ? flt_bits : ((self_known && self_sig.ret_ty.kind == HL_TY_F32) ? 32 : 64);
                    if (self_known && (self_sig.ret_ty.kind == HL_TY_F32 || self_sig.ret_ty.kind == HL_TY_F64)) {
                        fn->ret_ty = self_sig.ret_ty;
                        if (fb == 64 && fn->ret_ty.kind == HL_TY_F32) {
                            fn->ret_ty.kind = HL_TY_F64;
                            fn->ret_ty.bits = 64;
                        }
                    } else {
                        fn->ret_ty.kind = (fb == 32) ? HL_TY_F32 : HL_TY_F64;
                        fn->ret_ty.bits = (uint8_t)fb;
                    }
                    int win64_slot0_gpr_used = (fn->is_win64 && fn->narg_abi > 0 &&
                                                c->entry_var[fn->arg_regs[0]] >= 0 &&
                                                c->entry_var[fn->arg_regs[0]] < fn->nvar &&
                                                non_ret_uses[c->entry_var[fn->arg_regs[0]]] > 0);
                    int self_is_flt = (self_known && self_sig.has_ret &&
                                       (self_sig.ret_ty.kind == HL_TY_F32 || self_sig.ret_ty.kind == HL_TY_F64));
                    /* Fix any return path whose GPR was scratch (consumed) or empty to return flt_ret_reg */
                    for (int i = 0; i < c->nret_stmts; i++) {
                        if (c->ret_is_flt[i]) continue;
                        int rv = c->ret_vars[i];
                        int rfv = c->ret_flt_vars[i];
                        if (rfv < 0 || rfv >= fn->nvar) continue;
                        if (!(rv < 0 || rv >= fn->nvar || non_ret_uses[rv] > 0)) continue;
                        int rfv_ok = hl_var_has_real_flt_def(c, rfv);
                        if (!rfv_ok && c->flt_ret_reg >= 0 && rfv == c->entry_var[c->flt_ret_reg]) {
                            if (!fn->is_x86_32 && !win64_slot0_gpr_used &&
                                (non_ret_uses[rfv] > 0 || any_flt_direct || self_is_flt)) {
                                rfv_ok = 1;
                            }
                        }
                        if (rfv_ok) {
                            fn->stmts[c->ret_stmts[i]].rhs_expr = hl_expr_var(fn, rfv);
                        }
                    }
                } else if (self_known && self_sig.ret_ty.kind != HL_TY_UNK) {
                    fn->ret_ty = self_sig.ret_ty;
                } else {
                    fn->ret_ty.bits = (uint8_t)ret_bits;
                }
            } else {
                fn->has_ret_val = 0;
                fn->ret_ty.kind = HL_TY_VOID;
                fn->ret_ty.bits = 0;
                for (int i = 0; i < c->nret_stmts; i++) {
                    fn->stmts[c->ret_stmts[i]].rhs_expr = -1;
                }
            }
            free(non_ret_uses);
        }
    } else if (!fn->has_ret_val) {
        fn->ret_ty.kind = HL_TY_VOID;
        fn->ret_ty.bits = 0;
    }

    /* Refine switch selector expressions from dominating range-check blocks if needed */
    for (int b = 0; b < fn->nblk; b++) {
        if (fn->blks[b].sw_idx < 0) continue;
        int id = fn->blks[b].idom;
        if (fn->blks[b].sw_expr < 0 && id >= 0 && fn->blks[id].cond_expr >= 0) {
            const hl_expr *ce = &fn->exprs[fn->blks[id].cond_expr];
            if (ce->kind == HLE_BINOP && hl_is_cmp_op(ce->op) && ce->sub0 >= 0) {
                fn->blks[b].sw_expr = hl_expr_clone(fn, ce->sub0);
            }
        }
    }

    /* Mark address-taken stack variables using is_canary? No, keep is_canary solely for canary!
     * Propagate address-taken metadata via stk_slots (checked during hl_optimize via HLE_ADDR scan). */
}

bool hl_lift_cfg(const ana_ctx *a, const typ_store *types, const grp_cfg *g, hl_fn *fn) {
    if (!a || !g || !fn || g->nblk == 0) return false;

    memset(fn, 0, sizeof(*fn));
    fn->a     = a;
    fn->types = types;
    fn->g     = g;

    fn->is_a64    = (a->bin.arch == BIN_ARCH_ARM64) ? 1 : 0;
    fn->is_x86_32 = (!fn->is_a64 && (a->bin.arch == BIN_ARCH_X86 || a->bin.bits == 32)) ? 1 : 0;
    fn->is_win64  = (!fn->is_a64 && !fn->is_x86_32 && (a->bin.fmt == BIN_PE64 || a->bin.fmt == BIN_RAW)) ? 1 : 0;
    fn->ptr_bits  = fn->is_x86_32 ? 32 : 64;

    uint64_t saved_mask64 = 0;
    uint64_t vol_mask64   = 0;
    int flt_ret_reg       = 16;
    int nregs             = 32;

    if (fn->is_a64) {
        for (int i = 0; i < 8; i++) fn->arg_regs[i] = i;
        fn->narg_abi = 8;
        fn->ret_reg  = 0;
        fn->sp_reg   = 31;
        fn->bp_reg   = 29;
        flt_ret_reg  = 32;
        nregs        = 40;
        for (int r = 19; r <= 30; r++) saved_mask64 |= (1ULL << r);
        for (int r = 0; r <= 18; r++)  vol_mask64   |= (1ULL << r);
        for (int r = 32; r < 40; r++)  vol_mask64   |= (1ULL << r);
    } else if (fn->is_win64) {
        fn->arg_regs[0] = 1; /* rcx */
        fn->arg_regs[1] = 2; /* rdx */
        fn->arg_regs[2] = 8; /* r8  */
        fn->arg_regs[3] = 9; /* r9  */
        fn->narg_abi = 4;
        fn->ret_reg  = 0;
        fn->sp_reg   = 4;
        fn->bp_reg   = 5;
        saved_mask64 = (1ULL << 3) | (1ULL << 5) | (1ULL << 6) | (1ULL << 7) |
                       (1ULL << 12) | (1ULL << 13) | (1ULL << 14) | (1ULL << 15) |
                       (((1ULL << 10) - 1ULL) << 22); /* xmm6..xmm15 */
        vol_mask64   = (1ULL << 0) | (1ULL << 1) | (1ULL << 2) | (1ULL << 8) |
                       (1ULL << 9) | (1ULL << 10) | (1ULL << 11) |
                       (((1ULL << 6) - 1ULL) << 16);  /* xmm0..xmm5 */
    } else if (fn->is_x86_32) {
        fn->arg_regs[0] = 1; /* ecx (thiscall/fastcall if live-in) */
        fn->arg_regs[1] = 2; /* edx */
        fn->narg_abi = 2;
        fn->ret_reg  = 0;
        fn->sp_reg   = 4;
        fn->bp_reg   = 5;
        nregs        = 24;
        saved_mask64 = (1ULL << 3) | (1ULL << 5) | (1ULL << 6) | (1ULL << 7);
        vol_mask64   = (1ULL << 0) | (1ULL << 1) | (1ULL << 2) | (((1ULL << 8) - 1ULL) << 16);
    } else {
        /* SysV x86-64 */
        fn->arg_regs[0] = 7; /* rdi */
        fn->arg_regs[1] = 6; /* rsi */
        fn->arg_regs[2] = 2; /* rdx */
        fn->arg_regs[3] = 1; /* rcx */
        fn->arg_regs[4] = 8; /* r8  */
        fn->arg_regs[5] = 9; /* r9  */
        fn->narg_abi = 6;
        fn->ret_reg  = 0;
        fn->sp_reg   = 4;
        fn->bp_reg   = 5;
        saved_mask64 = (1ULL << 3) | (1ULL << 5) | (1ULL << 12) |
                       (1ULL << 13) | (1ULL << 14) | (1ULL << 15);
        vol_mask64   = (1ULL << 0) | (1ULL << 1) | (1ULL << 2) | (1ULL << 6) |
                       (1ULL << 7) | (1ULL << 8) | (1ULL << 9) | (1ULL << 10) | (1ULL << 11) |
                       (((1ULL << 16) - 1ULL) << 16);
    }
    fn->saved_mask = (int)(uint32_t)saved_mask64;

    int nb = (g->nblk > HL_MAX_BLKS) ? HL_MAX_BLKS : (int)g->nblk;
    fn->blks = (hl_blk *)calloc((size_t)nb, sizeof(hl_blk));
    if (!fn->blks) {
        hl_fn_free(fn);
        return false;
    }
    fn->nblk = nb;

    hl_lift_ctx *c = (hl_lift_ctx *)calloc(1, sizeof(hl_lift_ctx));
    if (!c) {
        hl_fn_free(fn);
        return false;
    }
    c->fn             = fn;
    c->nblk           = nb;
    c->nregs          = nregs;
    c->saved_reg_mask = saved_mask64;
    c->vol_reg_mask   = vol_mask64;
    c->flt_ret_reg    = flt_ret_reg;
    c->nins           = g->nins;
    c->skip_ins       = (uint8_t *)calloc((size_t)(g->nins + 1), 1);
    if (!c->skip_ins) {
        hl_lift_ctx_free(c);
        hl_fn_free(fn);
        return false;
    }
    for (int r = 0; r < HL_LIFT_REGS; r++) {
        c->entry_var[r] = -1;
        c->cur_bits[r]  = fn->ptr_bits;
    }
    for (int b = 0; b < nb; b++) {
        c->blk_exit_fl[b].lhs_expr = -1;
        c->blk_exit_fl[b].rhs_expr = -1;
        c->blk_exit_fl[b].res_expr = -1;
    }

    /* Step 1: CFG topology, switches, dominators, dominance frontiers, post-dominators, loops */
    hl_build_cfg_doms(c);

    /* Step 2: Pre-pass (SP/BP tracking, prologue/epilogue callee-saves, stack canary, stack slots) */
    hl_prescan(c);

    /* Step 3: Entry ABI argument versions */
    for (int k = 0; k < fn->narg_abi; k++) {
        int r = fn->arg_regs[k];
        if (r >= 0 && r < c->nregs && c->entry_var[r] < 0) {
            int vid = hl_var_new(fn, fn->ptr_bits, r, 0);
            if (vid >= 0) {
                fn->vars[vid].is_arg  = 1;
                fn->vars[vid].arg_idx = k;
                c->entry_var[r]       = vid;
            }
        }
    }
    if (fn->is_win64) {
        for (int k = 0; k < 4; k++) {
            int r = 16 + k;
            int vid = hl_var_new(fn, 64, r, 1);
            if (vid >= 0) {
                fn->vars[vid].is_arg  = 1;
                fn->vars[vid].arg_idx = k;
                c->entry_var[r]       = vid;
            }
        }
    } else if (fn->is_a64) {
        for (int k = 0; k < 8; k++) {
            int r = 32 + k;
            int vid = hl_var_new(fn, 64, r, 1);
            if (vid >= 0) {
                fn->vars[vid].is_arg  = 1;
                fn->vars[vid].arg_idx = 8 + k;
                c->entry_var[r]       = vid;
            }
        }
    } else if (!fn->is_x86_32) {
        for (int k = 0; k < 8; k++) {
            int r = 16 + k;
            int vid = hl_var_new(fn, 64, r, 1);
            if (vid >= 0) {
                fn->vars[vid].is_arg  = 1;
                fn->vars[vid].arg_idx = 6 + k;
                c->entry_var[r]       = vid;
            }
        }
    }

    /* Step 4: Liveness & Pruned SSA PHI insertion */
    hl_insert_phis(c);

    /* Step 5: Dominator-Tree DFS Lifting */
    hl_lift_dom_dfs(c, 0);

    /* Step 6: Return value & switch selector finalization */
    hl_finalize_returns_and_switches(c);

    hl_lift_ctx_free(c);
    return true;
}

/* =========================================================================
 * Optimizer Helpers: 128-bit MulHi & Exact Magic-Number Division Solvers
 * ========================================================================= */

static uint64_t hl_mulhi_u64(uint64_t a, uint64_t b) {
    uint64_t a0 = a & 0xFFFFFFFFULL, a1 = a >> 32;
    uint64_t b0 = b & 0xFFFFFFFFULL, b1 = b >> 32;
    uint64_t p00 = a0 * b0;
    uint64_t p01 = a0 * b1;
    uint64_t p10 = a1 * b0;
    uint64_t p11 = a1 * b1;
    uint64_t mid = (p00 >> 32) + (p01 & 0xFFFFFFFFULL) + (p10 & 0xFFFFFFFFULL);
    return p11 + (p01 >> 32) + (p10 >> 32) + (mid >> 32);
}

static int64_t hl_mulhi_s64(int64_t a, int64_t b) {
    uint64_t hi = hl_mulhi_u64((uint64_t)a, (uint64_t)b);
    if (a < 0) hi -= (uint64_t)b;
    if (b < 0) hi -= (uint64_t)a;
    return (int64_t)hi;
}

static uint32_t hl_eval_magic_u32(uint32_t x, uint64_t M, int sh, int ovf_add) {
    uint64_t hi = ((uint64_t)x * (M & 0xFFFFFFFFULL)) >> 32;
    if (!ovf_add) return (uint32_t)(hi >> sh);
    uint64_t t = (((uint64_t)x - hi) >> 1) + hi;
    return (uint32_t)(t >> sh);
}

static int hl_solve_magic_udiv32(uint64_t M, int sh, int ovf_add, uint64_t *out_D) {
    M &= 0xFFFFFFFFULL;
    if (M == 0 || sh < 0 || sh >= 32) return 0;
    uint64_t m_eff = ovf_add ? (M + (1ULL << 32)) : M;
    int total = ovf_add ? (33 + sh) : (32 + sh);
    if (total >= 64) return 0;
    uint64_t num = 1ULL << total;
    uint64_t base_d = num / m_eff;

    for (uint64_t delta = 0; delta <= 2; delta++) {
        uint64_t D = base_d + delta;
        if (D < 2 || D > 0x7FFFFFFFULL) continue;
        uint32_t d32 = (uint32_t)D;
        uint32_t tests[14] = {
            0U, 1U, 2U, d32 - 1U, d32, d32 + 1U,
            (d32 <= 0x3FFFFFFFU) ? (2U * d32 - 1U) : d32,
            (d32 <= 0x3FFFFFFFU) ? (2U * d32) : d32,
            (d32 <= 0x2AAAAAAAu) ? (3U * d32 - 1U) : d32,
            0xFFFFU, 0x7FFFFFFEU, 0x7FFFFFFFU, 0xFFFFFFFEU, 0xFFFFFFFFU
        };
        int ok = 1;
        for (int i = 0; i < 14; i++) {
            if (hl_eval_magic_u32(tests[i], M, sh, ovf_add) != tests[i] / d32) {
                ok = 0;
                break;
            }
        }
        if (ok) {
            *out_D = D;
            return 1;
        }
    }
    return 0;
}

static int32_t hl_eval_magic_s32(int32_t x, uint64_t M, int sh, int add_x, int sub_x) {
    int64_t prod = (int64_t)x * (int64_t)(int32_t)(M & 0xFFFFFFFFULL);
    int32_t hi   = (int32_t)(prod >> 32);
    if (add_x) hi = (int32_t)((uint32_t)hi + (uint32_t)x);
    if (sub_x) hi = (int32_t)((uint32_t)hi - (uint32_t)x);
    int32_t q = hi >> sh;
    uint32_t sign = (uint32_t)q >> 31;
    return (int32_t)((uint32_t)q + sign);
}

static int hl_solve_magic_sdiv32(uint64_t M, int sh, int add_x, int sub_x, uint64_t *out_D) {
    M &= 0xFFFFFFFFULL;
    if (M == 0 || sh < 0 || sh >= 32) return 0;
    int64_t m_eff = (int64_t)(int32_t)M;
    if (add_x) m_eff += (1LL << 32);
    if (sub_x) m_eff -= (1LL << 32);
    if (m_eff <= 0) return 0;
    int total = 32 + sh;
    if (total >= 63) return 0;
    uint64_t num = 1ULL << total;
    uint64_t base_d = num / (uint64_t)m_eff;

    for (uint64_t delta = 0; delta <= 2; delta++) {
        uint64_t D = base_d + delta;
        if (D < 2 || D > 0x3FFFFFFFULL) continue;
        int32_t d32 = (int32_t)D;
        int32_t tests[18] = {
            0, 1, -1, 2, -2, d32 - 1, -(d32 - 1), d32, -d32, d32 + 1, -(d32 + 1),
            (d32 <= 0x1FFFFFFF) ? (2 * d32 - 1) : d32,
            (d32 <= 0x1FFFFFFF) ? -(2 * d32 - 1) : -d32,
            100003, -100003, 0x7FFFFFFE, 0x7FFFFFFF, -0x7FFFFFFF
        };
        int ok = 1;
        for (int i = 0; i < 18; i++) {
            if (hl_eval_magic_s32(tests[i], M, sh, add_x, sub_x) != tests[i] / d32) {
                ok = 0;
                break;
            }
        }
        if (ok) {
            *out_D = D;
            return 1;
        }
    }
    return 0;
}

static uint64_t hl_eval_magic_u64(uint64_t x, uint64_t M, int sh, int ovf_add) {
    uint64_t hi = hl_mulhi_u64(x, M);
    if (!ovf_add) return hi >> sh;
    uint64_t t = ((x - hi) >> 1) + hi;
    return t >> sh;
}

static int hl_solve_magic_udiv64(uint64_t M, int sh, int ovf_add, uint64_t *out_D) {
    if (M == 0 || sh < 0 || sh >= 64) return 0;
    double m_eff = (double)M + (ovf_add ? ldexp(1.0, 64) : 0.0);
    double est   = ldexp(1.0, (ovf_add ? 65 : 64) + sh) / m_eff;
    if (est < 1.5 || est > ldexp(1.0, 48)) return 0;
    uint64_t base_d = (uint64_t)est;

    for (int64_t delta = -2; delta <= 2; delta++) {
        if ((int64_t)base_d + delta < 2) continue;
        uint64_t D = (uint64_t)((int64_t)base_d + delta);
        uint64_t tests[11] = {
            0ULL, 1ULL, 2ULL, D - 1ULL, D, D + 1ULL,
            2ULL * D - 1ULL, 2ULL * D, 1000000007ULL,
            0x7FFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL
        };
        int ok = 1;
        for (int i = 0; i < 11; i++) {
            if (hl_eval_magic_u64(tests[i], M, sh, ovf_add) != tests[i] / D) {
                ok = 0;
                break;
            }
        }
        if (ok) {
            *out_D = D;
            return 1;
        }
    }
    return 0;
}

static int64_t hl_eval_magic_s64(int64_t x, uint64_t M, int sh, int add_x, int sub_x) {
    int64_t hi = hl_mulhi_s64(x, (int64_t)M);
    if (add_x) hi = (int64_t)((uint64_t)hi + (uint64_t)x);
    if (sub_x) hi = (int64_t)((uint64_t)hi - (uint64_t)x);
    int64_t q = hi >> sh;
    uint64_t sign = (uint64_t)q >> 63;
    return (int64_t)((uint64_t)q + sign);
}

static int hl_solve_magic_sdiv64(uint64_t M, int sh, int add_x, int sub_x, uint64_t *out_D) {
    if (M == 0 || sh < 0 || sh >= 64) return 0;
    double m_eff = (double)(int64_t)M;
    if (add_x) m_eff += ldexp(1.0, 64);
    if (sub_x) m_eff -= ldexp(1.0, 64);
    if (m_eff <= 0.0) return 0;
    double est = ldexp(1.0, 64 + sh) / m_eff;
    if (est < 1.5 || est > ldexp(1.0, 48)) return 0;
    uint64_t base_d = (uint64_t)est;

    for (int64_t delta = -2; delta <= 2; delta++) {
        if ((int64_t)base_d + delta < 2) continue;
        int64_t D = (int64_t)base_d + delta;
        int64_t tests[14] = {
            0, 1, -1, D - 1, -(D - 1), D, -D, D + 1, -(D + 1),
            2 * D - 1, -(2 * D - 1), 1000000007LL, -1000000007LL,
            0x7FFFFFFFFFFFFFFELL
        };
        int ok = 1;
        for (int i = 0; i < 14; i++) {
            if (hl_eval_magic_s64(tests[i], M, sh, add_x, sub_x) != tests[i] / D) {
                ok = 0;
                break;
            }
        }
        if (ok) {
            *out_D = (uint64_t)D;
            return 1;
        }
    }
    return 0;
}

/* =========================================================================
 * Optimizer Utilities: Address-Taken Stack Scan & Expression Substitution
 * ========================================================================= */

static void hl_scan_addr_expr(const hl_fn *fn, int eid, uint8_t *addr_taken, int depth) {
    if (!fn || eid < 0 || eid >= fn->nexpr || depth > HL_MAX_DEPTH) return;
    const hl_expr *e = &fn->exprs[eid];
    if (e->kind == HLE_ADDR && e->sub0 >= 0 && e->sub0 < fn->nexpr) {
        const hl_expr *s = &fn->exprs[e->sub0];
        if (s->kind == HLE_VAR) {
            int cv = hl_var_canon(fn, s->var_id);
            if (cv >= 0 && cv < fn->nvar) addr_taken[cv] = 1;
        }
    }
    if (e->sub0 >= 0) hl_scan_addr_expr(fn, e->sub0, addr_taken, depth + 1);
    if (e->sub1 >= 0) hl_scan_addr_expr(fn, e->sub1, addr_taken, depth + 1);
    if (e->sub2 >= 0) hl_scan_addr_expr(fn, e->sub2, addr_taken, depth + 1);
    for (int i = 0; i < (int)e->narg && i < HL_MAX_CALL_ARG; i++) {
        if (e->args[i] >= 0) hl_scan_addr_expr(fn, e->args[i], addr_taken, depth + 1);
    }
}

static uint8_t *hl_compute_addr_aliased(const hl_fn *fn) {
    uint8_t *aliased = (uint8_t *)calloc((size_t)(fn->nvar + 1), 1);
    uint8_t *direct  = (uint8_t *)calloc((size_t)(fn->nvar + 1), 1);
    if (!aliased || !direct) {
        free(aliased);
        free(direct);
        return NULL;
    }
    for (int b = 0; b < fn->nblk; b++) {
        const hl_blk *hb = &fn->blks[b];
        for (int si = 0; si < hb->nstmt; si++) {
            const hl_stmt *s = &fn->stmts[hb->stmts[si]];
            if (s->dead) continue;
            hl_scan_addr_expr(fn, s->lhs_expr, direct, 0);
            hl_scan_addr_expr(fn, s->rhs_expr, direct, 0);
            hl_scan_addr_expr(fn, s->len_expr, direct, 0);
        }
        hl_scan_addr_expr(fn, hb->cond_expr, direct, 0);
        hl_scan_addr_expr(fn, hb->sw_expr, direct, 0);
    }
    for (int i = 0; i < fn->nvar; i++) {
        if (!direct[i]) continue;
        aliased[i] = 1;
        if (fn->vars[i].is_stack) {
            int64_t base_off = fn->vars[i].stack_off;
            for (int j = 0; j < fn->nvar; j++) {
                if (fn->vars[j].is_stack && !fn->vars[j].is_arg) {
                    int64_t d = fn->vars[j].stack_off - base_off;
                    if (d >= 0 && d < 256) aliased[j] = 1;
                }
            }
        }
    }
    free(direct);
    return aliased;
}

static int hl_expr_subst_map(hl_fn *fn, int eid, const int *prop_expr, int *changed, int depth) {
    if (!fn || eid < 0 || eid >= fn->nexpr || depth > HL_MAX_DEPTH) return eid;
    hl_expr e = fn->exprs[eid];

    if (e.kind == HLE_ADDR) {
        /* Never replace the lvalue variable inside &var_XX */
        return eid;
    }
    if (e.kind == HLE_VAR && e.var_id >= 0 && e.var_id < fn->nvar) {
        int rep = prop_expr[e.var_id];
        if (rep >= 0) {
            int cl = hl_expr_clone(fn, rep);
            if (cl >= 0) {
                *changed = 1;
                return cl;
            }
        }
        return eid;
    }

    int n0 = (e.sub0 >= 0) ? hl_expr_subst_map(fn, e.sub0, prop_expr, changed, depth + 1) : -1;
    int n1 = (e.sub1 >= 0) ? hl_expr_subst_map(fn, e.sub1, prop_expr, changed, depth + 1) : -1;
    int n2 = (e.sub2 >= 0) ? hl_expr_subst_map(fn, e.sub2, prop_expr, changed, depth + 1) : -1;
    int nargs[HL_MAX_CALL_ARG];
    for (int i = 0; i < (int)e.narg && i < HL_MAX_CALL_ARG; i++) {
        nargs[i] = (e.args[i] >= 0) ? hl_expr_subst_map(fn, e.args[i], prop_expr, changed, depth + 1) : -1;
    }

    fn->exprs[eid].sub0 = n0;
    fn->exprs[eid].sub1 = n1;
    fn->exprs[eid].sub2 = n2;
    for (int i = 0; i < (int)e.narg && i < HL_MAX_CALL_ARG; i++) {
        fn->exprs[eid].args[i] = nargs[i];
    }
    return eid;
}

static int hl_expr_subst_one(hl_fn *fn, int eid, int target_vid, int repl_eid, int *did, int depth) {
    if (!fn || eid < 0 || eid >= fn->nexpr || depth > HL_MAX_DEPTH) return eid;
    hl_expr e = fn->exprs[eid];
    if (e.kind == HLE_ADDR) return eid;
    if (e.kind == HLE_VAR && e.var_id == target_vid) {
        *did = 1;
        return hl_expr_clone(fn, repl_eid);
    }

    int n0 = (e.sub0 >= 0) ? hl_expr_subst_one(fn, e.sub0, target_vid, repl_eid, did, depth + 1) : -1;
    int n1 = (e.sub1 >= 0) ? hl_expr_subst_one(fn, e.sub1, target_vid, repl_eid, did, depth + 1) : -1;
    int n2 = (e.sub2 >= 0) ? hl_expr_subst_one(fn, e.sub2, target_vid, repl_eid, did, depth + 1) : -1;
    int nargs[HL_MAX_CALL_ARG];
    for (int i = 0; i < (int)e.narg && i < HL_MAX_CALL_ARG; i++) {
        nargs[i] = (e.args[i] >= 0)
                 ? hl_expr_subst_one(fn, e.args[i], target_vid, repl_eid, did, depth + 1) : -1;
    }
    fn->exprs[eid].sub0 = n0;
    fn->exprs[eid].sub1 = n1;
    fn->exprs[eid].sub2 = n2;
    for (int i = 0; i < (int)e.narg && i < HL_MAX_CALL_ARG; i++) {
        fn->exprs[eid].args[i] = nargs[i];
    }
    return eid;
}

/* =========================================================================
 * Pass 1: Trivial PHI Folding + Global Copy & Constant Propagation
 * ========================================================================= */

static int hl_opt_copy_const_prop(hl_fn *fn, const uint8_t *aliased) {
    int changed = 0;

    /* 1a. Fold trivial PHIs: v = phi(u, v) or phi(u, u) -> v = u */
    for (int b = 0; b < fn->nblk; b++) {
        const hl_blk *hb = &fn->blks[b];
        for (int si = 0; si < hb->nstmt; si++) {
            hl_stmt *s = &fn->stmts[hb->stmts[si]];
            if (s->dead || s->kind != HLS_PHI) continue;
            int common = -1;
            int trivial = 1;
            for (int pi = 0; pi < (int)s->nphi; pi++) {
                int pv = s->phi_vars[pi];
                if (pv < 0 || pv == s->dst_var) continue;
                if (common < 0) common = pv;
                else if (common != pv) { trivial = 0; break; }
            }
            if (trivial && common >= 0) {
                int ve = hl_expr_var(fn, common);
                /* Re-fetch pointer after hl_expr_var */
                hl_stmt *st = &fn->stmts[hb->stmts[si]];
                st->kind     = HLS_ASSIGN;
                st->rhs_expr = ve;
                st->nphi     = 0;
                changed      = 1;
            }
        }
    }

    /* 1b. Count definitions per variable */
    int *def_cnt  = (int *)calloc((size_t)(fn->nvar + 1), sizeof(int));
    int *def_stmt = (int *)malloc((size_t)(fn->nvar + 1) * sizeof(int));
    int *prop     = (int *)malloc((size_t)(fn->nvar + 1) * sizeof(int));
    if (!def_cnt || !def_stmt || !prop) {
        free(def_cnt); free(def_stmt); free(prop);
        return changed;
    }
    for (int i = 0; i <= fn->nvar; i++) { def_stmt[i] = -1; prop[i] = -1; }

    for (int b = 0; b < fn->nblk; b++) {
        const hl_blk *hb = &fn->blks[b];
        for (int si = 0; si < hb->nstmt; si++) {
            int sid = hb->stmts[si];
            const hl_stmt *s = &fn->stmts[sid];
            if (s->dead) continue;
            if ((s->kind == HLS_ASSIGN || s->kind == HLS_PHI) && s->dst_var >= 0 && s->dst_var < fn->nvar) {
                def_cnt[s->dst_var]++;
                def_stmt[s->dst_var] = sid;
            }
        }
    }

    /* 1c. Identify propagatable single-def constants, addresses & pure SSA copies */
    for (int v = 0; v < fn->nvar; v++) {
        if (def_cnt[v] != 1 || def_stmt[v] < 0) continue;
        if (fn->vars[v].is_arg) continue;
        const hl_stmt *s = &fn->stmts[def_stmt[v]];
        if (s->kind != HLS_ASSIGN || s->rhs_expr < 0 || s->rhs_expr >= fn->nexpr) continue;
        const hl_expr *rhs = &fn->exprs[s->rhs_expr];

        if (fn->vars[v].is_stack) {
            if (aliased && aliased[v]) continue;
            if (rhs->kind == HLE_INT || rhs->kind == HLE_FLT ||
                rhs->kind == HLE_STR || rhs->kind == HLE_SYM) {
                prop[v] = s->rhs_expr;
            }
            continue;
        }

        if (rhs->kind == HLE_INT || rhs->kind == HLE_FLT ||
            rhs->kind == HLE_STR || rhs->kind == HLE_SYM) {
            prop[v] = s->rhs_expr;
        } else if (rhs->kind == HLE_ADDR && rhs->sub0 >= 0 &&
                   fn->exprs[rhs->sub0].kind == HLE_VAR) {
            prop[v] = s->rhs_expr;
        } else if (rhs->kind == HLE_VAR && rhs->var_id >= 0 && rhs->var_id < fn->nvar &&
                   rhs->var_id != v) {
            int src = rhs->var_id;
            /* Only propagate copies from immutable SSA vars (not mutable stack vars) */
            if (!fn->vars[src].is_stack || (fn->vars[src].is_arg && def_cnt[src] == 0)) {
                if (def_cnt[src] <= 1) prop[v] = s->rhs_expr;
            }
        }
    }

    /* Break any copy cycles defensively */
    for (int v = 0; v < fn->nvar; v++) {
        if (prop[v] < 0) continue;
        int cur = v;
        for (int step = 0; step < 24; step++) {
            int pe = prop[cur];
            if (pe < 0 || fn->exprs[pe].kind != HLE_VAR) break;
            int nxt = fn->exprs[pe].var_id;
            if (nxt == v) { prop[v] = -1; break; }
            if (nxt < 0 || nxt >= fn->nvar || prop[nxt] < 0) break;
            cur = nxt;
        }
    }

    /* 1d. Substitute across all live statements, PHIs, cond_expr, sw_expr */
    for (int b = 0; b < fn->nblk; b++) {
        hl_blk *hb = &fn->blks[b];
        for (int si = 0; si < hb->nstmt; si++) {
            int sid = hb->stmts[si];
            if (fn->stmts[sid].dead) continue;
            uint8_t sk = fn->stmts[sid].kind;
            if (sk == HLS_PHI) {
                for (int pi = 0; pi < (int)fn->stmts[sid].nphi; pi++) {
                    int pv = fn->stmts[sid].phi_vars[pi];
                    if (pv >= 0 && pv < fn->nvar && prop[pv] >= 0 &&
                        fn->exprs[prop[pv]].kind == HLE_VAR) {
                        int nv = fn->exprs[prop[pv]].var_id;
                        if (nv >= 0 && nv != pv) {
                            fn->stmts[sid].phi_vars[pi] = nv;
                            changed = 1;
                        }
                    }
                }
                continue;
            }
            if (fn->stmts[sid].lhs_expr >= 0) {
                int nl = hl_expr_subst_map(fn, fn->stmts[sid].lhs_expr, prop, &changed, 0);
                fn->stmts[sid].lhs_expr = nl;
            }
            if (fn->stmts[sid].rhs_expr >= 0) {
                int nr = hl_expr_subst_map(fn, fn->stmts[sid].rhs_expr, prop, &changed, 0);
                fn->stmts[sid].rhs_expr = nr;
            }
            if (fn->stmts[sid].len_expr >= 0) {
                int nln = hl_expr_subst_map(fn, fn->stmts[sid].len_expr, prop, &changed, 0);
                fn->stmts[sid].len_expr = nln;
            }
        }
        if (hb->cond_expr >= 0) {
            hb->cond_expr = hl_expr_subst_map(fn, hb->cond_expr, prop, &changed, 0);
        }
        if (hb->sw_expr >= 0) {
            hb->sw_expr = hl_expr_subst_map(fn, hb->sw_expr, prop, &changed, 0);
        }
    }

    free(def_cnt);
    free(def_stmt);
    free(prop);
    return changed;
}

/* =========================================================================
 * Pass 2: Algebraic & Compiler Idiom Simplification
 * ========================================================================= */

static uint64_t hl_bswap_val(uint64_t v, int bits) {
    if (bits == 16) return ((v & 0xFFULL) << 8) | ((v >> 8) & 0xFFULL);
    if (bits == 32) {
        return ((v & 0x000000FFULL) << 24) | ((v & 0x0000FF00ULL) << 8) |
               ((v & 0x00FF0000ULL) >> 8)  | ((v & 0xFF000000ULL) >> 24);
    }
    return ((v & 0x00000000000000FFULL) << 56) | ((v & 0x000000000000FF00ULL) << 40) |
           ((v & 0x0000000000FF0000ULL) << 24) | ((v & 0x00000000FF000000ULL) << 8)  |
           ((v & 0x000000FF00000000ULL) >> 8)  | ((v & 0x0000FF0000000000ULL) >> 24) |
           ((v & 0x00FF000000000000ULL) >> 40) | ((v & 0xFF00000000000000ULL) >> 56);
}

static int hl_is_neg1_int(const hl_expr *e) {
    if (e->kind != HLE_INT) return 0;
    uint64_t m = hl_mask_bits(~0ULL, e->bits ? e->bits : 64);
    return (e->uval & m) == m;
}

/* Extract (x, M, mul_bits) from mulhi(x, M) = (x * M) >> (32 or 64) */
static int hl_match_mulhi(const hl_fn *fn, int eid, int *out_x, uint64_t *out_M,
                          int *out_is64, int *out_signed, int *out_extra_sh) {
    if (eid < 0 || eid >= fn->nexpr) return 0;
    const hl_expr *e = &fn->exprs[eid];
    if (e->kind != HLE_BINOP || (e->op != HLB_SHR && e->op != HLB_SAR)) return 0;
    if (e->sub0 < 0 || e->sub1 < 0) return 0;
    const hl_expr *sh_e = &fn->exprs[e->sub1];
    const hl_expr *ml_e = &fn->exprs[e->sub0];
    if (sh_e->kind != HLE_INT || ml_e->kind != HLE_BINOP || ml_e->op != HLB_MUL) return 0;
    if (ml_e->sub0 < 0 || ml_e->sub1 < 0) return 0;

    int x_id = -1;
    uint64_t M = 0;
    if (fn->exprs[ml_e->sub1].kind == HLE_INT) {
        x_id = ml_e->sub0;
        M    = fn->exprs[ml_e->sub1].uval;
    } else if (fn->exprs[ml_e->sub0].kind == HLE_INT) {
        x_id = ml_e->sub1;
        M    = fn->exprs[ml_e->sub0].uval;
    } else {
        return 0;
    }

    /* Strip trivial zext/sext wrapper on x */
    if (x_id >= 0 && fn->exprs[x_id].kind == HLE_UNOP &&
        (fn->exprs[x_id].op == HLU_ZEXT || fn->exprs[x_id].op == HLU_SEXT)) {
        x_id = fn->exprs[x_id].sub0;
    }

    int s_amt = (int)sh_e->uval;
    if (ml_e->bits == 128 && s_amt >= 64 && s_amt < 128) {
        *out_x        = x_id;
        *out_M        = M;
        *out_is64     = 1;
        *out_signed   = (e->op == HLB_SAR || ml_e->is_signed) ? 1 : 0;
        *out_extra_sh = s_amt - 64;
        return 1;
    }
    if (ml_e->bits <= 64 && s_amt >= 32 && s_amt < 64) {
        *out_x        = x_id;
        *out_M        = M & 0xFFFFFFFFULL;
        *out_is64     = 0;
        *out_signed   = (e->op == HLB_SAR || ml_e->is_signed) ? 1 : 0;
        *out_extra_sh = s_amt - 32;
        return 1;
    }
    return 0;
}

/* Match signed magic div core: q = (hi [+/- x]) >> sh */
static int hl_match_sdiv_core(const hl_fn *fn, int q_id, int *out_x, uint64_t *out_M,
                              int *out_is64, int *out_sh, int *out_add_x, int *out_sub_x) {
    if (q_id < 0 || q_id >= fn->nexpr) return 0;
    *out_add_x = 0;
    *out_sub_x = 0;

    int x = -1, is64 = 0, sgn = 0, ex = 0;
    uint64_t M = 0;
    /* Direct: (x * M) >> (32+sh) or (64+sh) */
    if (hl_match_mulhi(fn, q_id, &x, &M, &is64, &sgn, &ex) && sgn) {
        *out_x = x; *out_M = M; *out_is64 = is64; *out_sh = ex;
        return 1;
    }

    const hl_expr *q = &fn->exprs[q_id];
    int inner = q_id;
    int sh = 0;
    if (q->kind == HLE_BINOP && (q->op == HLB_SAR || q->op == HLB_SHR) &&
        q->sub1 >= 0 && fn->exprs[q->sub1].kind == HLE_INT) {
        sh    = (int)fn->exprs[q->sub1].uval;
        inner = q->sub0;
    }

    /* inner = mulhi(x, M) */
    if (hl_match_mulhi(fn, inner, &x, &M, &is64, &sgn, &ex)) {
        *out_x = x; *out_M = M; *out_is64 = is64; *out_sh = ex + sh;
        return 1;
    }

    /* inner = mulhi(x, M) + x  or  mulhi(x, M) - x */
    if (inner >= 0 && fn->exprs[inner].kind == HLE_BINOP &&
        (fn->exprs[inner].op == HLB_ADD || fn->exprs[inner].op == HLB_SUB)) {
        const hl_expr *ie = &fn->exprs[inner];
        int hi_id = ie->sub0, ox_id = ie->sub1;
        if (ie->op == HLB_ADD && !hl_match_mulhi(fn, hi_id, &x, &M, &is64, &sgn, &ex)) {
            hi_id = ie->sub1;
            ox_id = ie->sub0;
        }
        if (hl_match_mulhi(fn, hi_id, &x, &M, &is64, &sgn, &ex) && ex == 0 &&
            hl_expr_eq(fn, x, ox_id, 0)) {
            *out_x = x; *out_M = M; *out_is64 = is64; *out_sh = sh;
            if (ie->op == HLB_ADD) *out_add_x = 1;
            else *out_sub_x = 1;
            return 1;
        }
    }
    return 0;
}

static int hl_simplify_expr(hl_fn *fn, int eid, int *changed, int depth) {
    if (!fn || eid < 0 || eid >= fn->nexpr || depth > HL_MAX_DEPTH) return eid;

    /* Recursively simplify children first (always reload fn->exprs[eid] after recursion!) */
    {
        hl_expr cur = fn->exprs[eid];
        int s0 = (cur.sub0 >= 0) ? hl_simplify_expr(fn, cur.sub0, changed, depth + 1) : -1;
        int s1 = (cur.sub1 >= 0) ? hl_simplify_expr(fn, cur.sub1, changed, depth + 1) : -1;
        int s2 = (cur.sub2 >= 0) ? hl_simplify_expr(fn, cur.sub2, changed, depth + 1) : -1;
        int nargs[HL_MAX_CALL_ARG];
        for (int i = 0; i < (int)cur.narg && i < HL_MAX_CALL_ARG; i++) {
            nargs[i] = (cur.args[i] >= 0)
                     ? hl_simplify_expr(fn, cur.args[i], changed, depth + 1) : -1;
        }
        fn->exprs[eid].sub0 = s0;
        fn->exprs[eid].sub1 = s1;
        fn->exprs[eid].sub2 = s2;
        for (int i = 0; i < (int)cur.narg && i < HL_MAX_CALL_ARG; i++) {
            fn->exprs[eid].args[i] = nargs[i];
        }
    }

    hl_expr e = fn->exprs[eid];

    /* ----- HLE_BITSET ----- */
    if (e.kind == HLE_BITSET) {
        if (e.sub1 >= 0 && fn->exprs[e.sub1].kind == HLE_INT) {
            uint64_t mask = fn->exprs[e.sub1].uval;
            if (fn->exprs[eid].uval != mask) {
                fn->exprs[eid].uval = mask;
                *changed = 1;
            }
            if (mask == 0) {
                *changed = 1;
                return hl_expr_int(fn, 0, 1, 0);
            }
            if (e.sub0 >= 0 && fn->exprs[e.sub0].kind == HLE_INT) {
                uint64_t idx = fn->exprs[e.sub0].uval;
                uint64_t bit = (idx < 64) ? ((mask >> idx) & 1ULL) : 0ULL;
                *changed = 1;
                return hl_expr_int(fn, bit, 1, 0);
            }
        }
        return eid;
    }

    /* ----- HLE_UNOP ----- */
    if (e.kind == HLE_UNOP && e.sub0 >= 0) {
        hl_expr sub = fn->exprs[e.sub0];
        int bw = e.bits ? e.bits : 64;

        /* Constant folding */
        if (sub.kind == HLE_INT) {
            uint64_t v = sub.uval;
            if (e.op == HLU_NEG)    { *changed = 1; return hl_expr_int(fn, hl_mask_bits(hl_neg_u64(v), bw), bw, 1); }
            if (e.op == HLU_BITNOT) { *changed = 1; return hl_expr_int(fn, hl_mask_bits(~v, bw), bw, 0); }
            if (e.op == HLU_LOGNOT) { *changed = 1; return hl_expr_int(fn, v ? 0ULL : 1ULL, 1, 0); }
            if (e.op == HLU_ZEXT)   { *changed = 1; return hl_expr_int(fn, hl_mask_bits(v, sub.bits ? sub.bits : bw), bw, 0); }
            if (e.op == HLU_SEXT)   { *changed = 1; return hl_expr_int(fn, hl_mask_bits((uint64_t)hl_sext_bits(v, sub.bits ? sub.bits : bw), bw), bw, 1); }
            if (e.op == HLU_I2F)    { *changed = 1; return hl_expr_flt(fn, (double)hl_sext_bits(v, sub.bits ? sub.bits : 32), bw); }
            if (e.op == HLU_BSWAP)  { *changed = 1; return hl_expr_int(fn, hl_bswap_val(v, bw), bw, 0); }
            if (e.op == HLU_ABS) {
                int64_t sv = hl_sext_bits(v, bw);
                uint64_t av = (sv < 0) ? hl_neg_u64((uint64_t)sv) : (uint64_t)sv;
                *changed = 1;
                return hl_expr_int(fn, hl_mask_bits(av, bw), bw, 1);
            }
            if (e.op == HLU_POPCNT) {
                uint64_t x = hl_mask_bits(v, bw), cnt = 0;
                while (x) { cnt += (x & 1ULL); x >>= 1; }
                *changed = 1;
                return hl_expr_int(fn, cnt, bw, 0);
            }
        }
        if (sub.kind == HLE_FLT) {
            if (e.op == HLU_FNEG) { *changed = 1; return hl_expr_flt(fn, -sub.fval, bw); }
            if (e.op == HLU_FABS) { *changed = 1; return hl_expr_flt(fn, sub.fval < 0.0 ? -sub.fval : sub.fval, bw); }
            if (e.op == HLU_F2I)  { *changed = 1; return hl_expr_int(fn, (uint64_t)(int64_t)sub.fval, bw, 1); }
            if (e.op == HLU_CAST) { *changed = 1; return hl_expr_flt(fn, sub.fval, bw); }
        }

        /* Unary algebraic identities */
        if (e.op == HLU_LOGNOT) {
            if (sub.kind == HLE_UNOP && sub.op == HLU_LOGNOT && hl_is_bool_expr(fn, sub.sub0)) {
                *changed = 1;
                return sub.sub0;
            }
            if (sub.kind == HLE_BINOP && hl_is_cmp_op(sub.op)) {
                *changed = 1;
                return hl_expr_invert(fn, e.sub0);
            }
        }
        if (e.op == HLU_NEG && sub.kind == HLE_UNOP && sub.op == HLU_NEG) { *changed = 1; return sub.sub0; }
        if (e.op == HLU_BITNOT && sub.kind == HLE_UNOP && sub.op == HLU_BITNOT) { *changed = 1; return sub.sub0; }
        if (e.op == HLU_FNEG && sub.kind == HLE_UNOP && sub.op == HLU_FNEG) { *changed = 1; return sub.sub0; }

        /* -(cond ? -1 : 0) -> cond ; ~(cond ? -1 : 0) -> (cond ? 0 : -1) */
        if (sub.kind == HLE_TERNARY && sub.sub1 >= 0 && sub.sub2 >= 0 &&
            hl_is_neg1_int(&fn->exprs[sub.sub1]) &&
            fn->exprs[sub.sub2].kind == HLE_INT && fn->exprs[sub.sub2].uval == 0) {
            if (e.op == HLU_NEG) { *changed = 1; return sub.sub0; }
            if (e.op == HLU_BITNOT) {
                int te = hl_expr_new(fn, HLE_TERNARY);
                if (te >= 0) {
                    fn->exprs[te].sub0 = sub.sub0;
                    fn->exprs[te].sub1 = hl_expr_int(fn, 0, bw, 1);
                    fn->exprs[te].sub2 = hl_expr_int(fn, hl_mask_bits(~0ULL, bw), bw, 1);
                    fn->exprs[te].bits = (uint8_t)bw;
                    *changed = 1;
                    return te;
                }
            }
        }

        /* Redundant ZEXT/SEXT stripping */
        if (e.op == HLU_ZEXT) {
            if (hl_is_bool_expr(fn, e.sub0)) { *changed = 1; return e.sub0; }
            if (sub.bits == bw && sub.kind != HLE_DEREF) { *changed = 1; return e.sub0; }
        }
        if (e.op == HLU_SEXT && sub.bits == bw && sub.kind != HLE_DEREF) {
            *changed = 1;
            return e.sub0;
        }
        return eid;
    }

    /* ----- HLE_TERNARY ----- */
    if (e.kind == HLE_TERNARY && e.sub0 >= 0 && e.sub1 >= 0 && e.sub2 >= 0) {
        hl_expr c_e = fn->exprs[e.sub0];
        hl_expr t_e = fn->exprs[e.sub1];
        hl_expr f_e = fn->exprs[e.sub2];

        if (c_e.kind == HLE_INT) {
            *changed = 1;
            return c_e.uval ? e.sub1 : e.sub2;
        }
        if (hl_expr_eq(fn, e.sub1, e.sub2, 0)) {
            *changed = 1;
            return e.sub1;
        }
        if (t_e.kind == HLE_INT && f_e.kind == HLE_INT) {
            if (t_e.uval == 1 && f_e.uval == 0 && hl_is_bool_expr(fn, e.sub0)) {
                *changed = 1;
                return e.sub0;
            }
            if (t_e.uval == 0 && f_e.uval == 1) {
                *changed = 1;
                return hl_expr_invert(fn, e.sub0);
            }
        }
        if (c_e.kind == HLE_UNOP && c_e.op == HLU_LOGNOT && c_e.sub0 >= 0) {
            fn->exprs[eid].sub0 = c_e.sub0;
            fn->exprs[eid].sub1 = e.sub2;
            fn->exprs[eid].sub2 = e.sub1;
            *changed = 1;
            return hl_simplify_expr(fn, eid, changed, depth + 1);
        }
        /* MIN / MAX / ABS from ternary */
        if (c_e.kind == HLE_BINOP && hl_is_cmp_op(c_e.op) && c_e.sub0 >= 0 && c_e.sub1 >= 0) {
            int ca = c_e.sub0, cb = c_e.sub1;
            int is_lt = (c_e.op == HLB_SLT || c_e.op == HLB_SLE || c_e.op == HLB_ULT || c_e.op == HLB_ULE);
            int is_gt = (c_e.op == HLB_SGT || c_e.op == HLB_SGE || c_e.op == HLB_UGT || c_e.op == HLB_UGE);
            int is_sg = (c_e.op == HLB_SLT || c_e.op == HLB_SLE || c_e.op == HLB_SGT || c_e.op == HLB_SGE);
            if (hl_expr_eq(fn, ca, e.sub1, 0) && hl_expr_eq(fn, cb, e.sub2, 0)) {
                if (is_lt || is_gt) {
                    int nid = hl_expr_binop(fn, is_lt ? HLB_MIN : HLB_MAX, e.sub1, e.sub2, e.bits);
                    if (nid >= 0) { fn->exprs[nid].is_signed = (uint8_t)is_sg; fn->exprs[nid].is_flt = e.is_flt; }
                    *changed = 1;
                    return nid;
                }
            }
            if (hl_expr_eq(fn, cb, e.sub1, 0) && hl_expr_eq(fn, ca, e.sub2, 0)) {
                if (is_lt || is_gt) {
                    int nid = hl_expr_binop(fn, is_lt ? HLB_MAX : HLB_MIN, e.sub1, e.sub2, e.bits);
                    if (nid >= 0) { fn->exprs[nid].is_signed = (uint8_t)is_sg; fn->exprs[nid].is_flt = e.is_flt; }
                    *changed = 1;
                    return nid;
                }
            }
            /* (x < 0) ? -x : x  or  (x >= 0) ? x : -x -> ABS(x) */
            if (fn->exprs[cb].kind == HLE_INT && fn->exprs[cb].uval == 0) {
                if ((c_e.op == HLB_SLT || c_e.op == HLB_SLE) &&
                    t_e.kind == HLE_UNOP && t_e.op == HLU_NEG &&
                    hl_expr_eq(fn, t_e.sub0, ca, 0) && hl_expr_eq(fn, e.sub2, ca, 0)) {
                    *changed = 1;
                    return hl_expr_unop(fn, HLU_ABS, e.sub2, e.bits);
                }
                if ((c_e.op == HLB_SGE || c_e.op == HLB_SGT) &&
                    f_e.kind == HLE_UNOP && f_e.op == HLU_NEG &&
                    hl_expr_eq(fn, f_e.sub0, ca, 0) && hl_expr_eq(fn, e.sub1, ca, 0)) {
                    *changed = 1;
                    return hl_expr_unop(fn, HLU_ABS, e.sub1, e.bits);
                }
            }
        }
        return eid;
    }

    /* ----- HLE_BINOP ----- */
    if (e.kind == HLE_BINOP && e.sub0 >= 0 && e.sub1 >= 0) {
        int a_id = e.sub0, b_id = e.sub1;
        hl_expr ea = fn->exprs[a_id];
        hl_expr eb = fn->exprs[b_id];
        int bw = e.bits ? e.bits : 64;

        /* Normalize integer 0 in float operations to 0.0 */
        if (e.is_flt) {
            if (ea.kind == HLE_INT && ea.uval == 0) {
                a_id = hl_expr_flt(fn, 0.0, bw == 32 ? 32 : 64);
                fn->exprs[eid].sub0 = a_id;
                ea = fn->exprs[a_id];
                *changed = 1;
            }
            if (eb.kind == HLE_INT && eb.uval == 0) {
                b_id = hl_expr_flt(fn, 0.0, bw == 32 ? 32 : 64);
                fn->exprs[eid].sub1 = b_id;
                eb = fn->exprs[b_id];
                *changed = 1;
            }
        }

        /* Float constant folding */
        if (ea.kind == HLE_FLT && eb.kind == HLE_FLT) {
            if (e.op == HLB_FADD) { *changed = 1; return hl_expr_flt(fn, ea.fval + eb.fval, bw); }
            if (e.op == HLB_FSUB) { *changed = 1; return hl_expr_flt(fn, ea.fval - eb.fval, bw); }
            if (e.op == HLB_FMUL) { *changed = 1; return hl_expr_flt(fn, ea.fval * eb.fval, bw); }
            if (e.op == HLB_FDIV && eb.fval != 0.0) { *changed = 1; return hl_expr_flt(fn, ea.fval / eb.fval, bw); }
            if (e.op == HLB_EQ)  { *changed = 1; return hl_expr_int(fn, ea.fval == eb.fval, 1, 0); }
            if (e.op == HLB_NE)  { *changed = 1; return hl_expr_int(fn, ea.fval != eb.fval, 1, 0); }
            if (e.op == HLB_SLT) { *changed = 1; return hl_expr_int(fn, ea.fval <  eb.fval, 1, 0); }
            if (e.op == HLB_SLE) { *changed = 1; return hl_expr_int(fn, ea.fval <= eb.fval, 1, 0); }
            if (e.op == HLB_SGT) { *changed = 1; return hl_expr_int(fn, ea.fval >  eb.fval, 1, 0); }
            if (e.op == HLB_SGE) { *changed = 1; return hl_expr_int(fn, ea.fval >= eb.fval, 1, 0); }
        }

        /* Integer constant folding */
        if (ea.kind == HLE_INT && eb.kind == HLE_INT && bw <= 64) {
            uint64_t ua = hl_mask_bits(ea.uval, bw);
            uint64_t ub = hl_mask_bits(eb.uval, bw);
            int64_t  sa = hl_sext_bits(ea.uval, bw);
            int64_t  sb = hl_sext_bits(eb.uval, bw);
            uint64_t res = 0;
            int folded = 1;
            int res_b = bw;
            int res_s = e.is_signed;

            switch (e.op) {
            case HLB_ADD: res = hl_mask_bits(ua + ub, bw); break;
            case HLB_SUB: res = hl_mask_bits(ua - ub, bw); break;
            case HLB_MUL: res = hl_mask_bits(ua * ub, bw); break;
            case HLB_UDIV: if (ub == 0) folded = 0; else res = ua / ub; break;
            case HLB_UMOD: if (ub == 0) folded = 0; else res = ua % ub; break;
            case HLB_SDIV: if (sb == 0 || (bw == 64 && sa == INT64_MIN && sb == -1)) folded = 0;
                           else res = hl_mask_bits((uint64_t)(sa / sb), bw); break;
            case HLB_SMOD: if (sb == 0 || (bw == 64 && sa == INT64_MIN && sb == -1)) folded = 0;
                           else res = hl_mask_bits((uint64_t)(sa % sb), bw); break;
            case HLB_AND:  res = ua & ub; break;
            case HLB_OR:   res = ua | ub; break;
            case HLB_XOR:  res = ua ^ ub; break;
            case HLB_SHL:  res = (ub < 64) ? hl_mask_bits(ua << ub, bw) : 0; break;
            case HLB_SHR:  res = (ub < 64) ? (ua >> ub) : 0; break;
            case HLB_SAR:  res = (ub < 64) ? hl_mask_bits((uint64_t)(sa >> ub), bw) : (sa < 0 ? hl_mask_bits(~0ULL, bw) : 0); break;
            case HLB_ROL:  { int r = (bw > 0) ? (int)(ub % (uint64_t)bw) : 0; res = r ? hl_mask_bits((ua << r) | (ua >> (bw - r)), bw) : ua; } break;
            case HLB_ROR:  { int r = (bw > 0) ? (int)(ub % (uint64_t)bw) : 0; res = r ? hl_mask_bits((ua >> r) | (ua << (bw - r)), bw) : ua; } break;
            case HLB_EQ:   res = (ua == ub); res_b = 1; break;
            case HLB_NE:   res = (ua != ub); res_b = 1; break;
            case HLB_SLT:  res = (sa <  sb); res_b = 1; break;
            case HLB_SLE:  res = (sa <= sb); res_b = 1; break;
            case HLB_SGT:  res = (sa >  sb); res_b = 1; break;
            case HLB_SGE:  res = (sa >= sb); res_b = 1; break;
            case HLB_ULT:  res = (ua <  ub); res_b = 1; break;
            case HLB_ULE:  res = (ua <= ub); res_b = 1; break;
            case HLB_UGT:  res = (ua >  ub); res_b = 1; break;
            case HLB_UGE:  res = (ua >= ub); res_b = 1; break;
            case HLB_LAND: res = (ua && ub); res_b = 1; break;
            case HLB_LOR:  res = (ua || ub); res_b = 1; break;
            case HLB_MIN:  res = e.is_signed ? hl_mask_bits((uint64_t)(sa < sb ? sa : sb), bw) : (ua < ub ? ua : ub); break;
            case HLB_MAX:  res = e.is_signed ? hl_mask_bits((uint64_t)(sa > sb ? sa : sb), bw) : (ua > ub ? ua : ub); break;
            default: folded = 0; break;
            }
            if (folded) {
                *changed = 1;
                /* ARM64 adrp + add -> resolve folded section address to string/symbol */
                if (fn->is_a64 && e.op == HLB_ADD && bw == 64 && fn->a &&
                    res >= fn->a->bin.min_va && res < fn->a->bin.max_va &&
                    (ua & 0xFFFULL) == 0 && ub < 0x1000ULL) {
                    return hl_expr_addr_const(fn, res);
                }
                return hl_expr_int(fn, res, res_b, res_s);
            }
        }

        /* Canonicalize commutative ops: constant on RHS */
        if ((e.op == HLB_ADD || e.op == HLB_MUL || e.op == HLB_AND ||
             e.op == HLB_OR  || e.op == HLB_XOR || e.op == HLB_EQ  || e.op == HLB_NE) &&
            ea.kind == HLE_INT && eb.kind != HLE_INT) {
            fn->exprs[eid].sub0 = b_id;
            fn->exprs[eid].sub1 = a_id;
            int tmp = a_id; a_id = b_id; b_id = tmp;
            ea = fn->exprs[a_id];
            eb = fn->exprs[b_id];
            *changed = 1;
        }

        /* Self-identities */
        if (hl_expr_eq(fn, a_id, b_id, 0)) {
            if (e.op == HLB_XOR || e.op == HLB_SUB) { *changed = 1; return hl_expr_int(fn, 0, bw, 0); }
            if (e.op == HLB_AND || e.op == HLB_OR || e.op == HLB_MIN || e.op == HLB_MAX) { *changed = 1; return a_id; }
            if (e.op == HLB_ADD) {
                *changed = 1;
                return hl_expr_binop(fn, HLB_MUL, a_id, hl_expr_int(fn, 2, bw, 0), bw);
            }
            if (e.op == HLB_EQ || e.op == HLB_SLE || e.op == HLB_SGE || e.op == HLB_ULE || e.op == HLB_UGE) {
                *changed = 1; return hl_expr_int(fn, 1, 1, 0);
            }
            if (e.op == HLB_NE || e.op == HLB_SLT || e.op == HLB_SGT || e.op == HLB_ULT || e.op == HLB_UGT) {
                *changed = 1; return hl_expr_int(fn, 0, 1, 0);
            }
        }

        /* Zero / One / All-Ones identities */
        if (eb.kind == HLE_INT) {
            uint64_t c = eb.uval;
            if (c == 0) {
                if (e.op == HLB_ADD || e.op == HLB_SUB || e.op == HLB_OR || e.op == HLB_XOR ||
                    e.op == HLB_SHL || e.op == HLB_SHR || e.op == HLB_SAR || e.op == HLB_ROL || e.op == HLB_ROR) {
                    *changed = 1; return a_id;
                }
                if (e.op == HLB_MUL || e.op == HLB_AND) {
                    *changed = 1; return hl_expr_int(fn, 0, bw, 0);
                }
            }
            if (c == 1) {
                if (e.op == HLB_MUL || e.op == HLB_SDIV || e.op == HLB_UDIV) {
                    *changed = 1; return a_id;
                }
                if (e.op == HLB_SMOD || e.op == HLB_UMOD) {
                    *changed = 1; return hl_expr_int(fn, 0, bw, 0);
                }
            }
            if (e.op == HLB_AND && bw <= 64 && (c & hl_mask_bits(~0ULL, bw)) == hl_mask_bits(~0ULL, bw)) {
                *changed = 1; return a_id;
            }
            /* x + (-small) -> x - small */
            if (e.op == HLB_ADD && bw <= 64) {
                int64_t sc = hl_sext_bits(c, bw);
                if (sc < 0 && sc >= -0x100000LL) {
                    int nimm = hl_expr_int(fn, (uint64_t)(-sc), bw, 0);
                    fn->exprs[eid].op   = HLB_SUB;
                    fn->exprs[eid].sub1 = nimm;
                    *changed = 1;
                    return hl_simplify_expr(fn, eid, changed, depth + 1);
                }
            }
        }
        if (ea.kind == HLE_INT && ea.uval == 0) {
            if (e.op == HLB_SUB) { *changed = 1; return hl_expr_unop(fn, HLU_NEG, b_id, bw); }
            if (e.op == HLB_SHL || e.op == HLB_SHR || e.op == HLB_SAR) { *changed = 1; return hl_expr_int(fn, 0, bw, 0); }
        }

        /* Associative constant combining */
        if (ea.kind == HLE_BINOP && ea.sub0 >= 0 && ea.sub1 >= 0 &&
            eb.kind == HLE_INT && fn->exprs[ea.sub1].kind == HLE_INT && bw <= 64) {
            uint64_t c1 = fn->exprs[ea.sub1].uval;
            uint64_t c2 = eb.uval;
            if ((e.op == HLB_ADD || e.op == HLB_SUB) && (ea.op == HLB_ADD || ea.op == HLB_SUB)) {
                int64_t d1 = (ea.op == HLB_ADD) ? hl_sext_bits(c1, bw) : -hl_sext_bits(c1, bw);
                int64_t d2 = (e.op  == HLB_ADD) ? hl_sext_bits(c2, bw) : -hl_sext_bits(c2, bw);
                int64_t tot = d1 + d2;
                *changed = 1;
                if (tot == 0) return ea.sub0;
                if (tot > 0) return hl_expr_binop(fn, HLB_ADD, ea.sub0, hl_expr_int(fn, (uint64_t)tot, bw, 0), bw);
                return hl_expr_binop(fn, HLB_SUB, ea.sub0, hl_expr_int(fn, (uint64_t)(-tot), bw, 0), bw);
            }
            if (e.op == HLB_MUL && ea.op == HLB_MUL) {
                *changed = 1;
                return hl_expr_binop(fn, HLB_MUL, ea.sub0, hl_expr_int(fn, hl_mask_bits(c1 * c2, bw), bw, 0), bw);
            }
            if (e.op == HLB_MUL && ea.op == HLB_SHL && c1 < 32) {
                *changed = 1;
                return hl_expr_binop(fn, HLB_MUL, ea.sub0, hl_expr_int(fn, hl_mask_bits((1ULL << c1) * c2, bw), bw, 0), bw);
            }
            if (e.op == HLB_SHL && ea.op == HLB_MUL && c2 < 32) {
                *changed = 1;
                return hl_expr_binop(fn, HLB_MUL, ea.sub0, hl_expr_int(fn, hl_mask_bits(c1 << c2, bw), bw, 0), bw);
            }
            if (e.op == HLB_SHL && ea.op == HLB_SHL && c1 + c2 < (uint64_t)bw) {
                *changed = 1;
                return hl_expr_binop(fn, HLB_SHL, ea.sub0, hl_expr_int(fn, c1 + c2, 8, 0), bw);
            }
            if (((e.op == HLB_SHR && ea.op == HLB_SHR) || (e.op == HLB_SAR && ea.op == HLB_SAR)) &&
                ea.bits == bw) {
                /* Don't lose wide mulhi width! Preserve ea.sub0 (mul) shift amount cleanly */
                int max_b = (ea.sub0 >= 0 && fn->exprs[ea.sub0].bits > bw) ? fn->exprs[ea.sub0].bits : bw;
                if (c1 + c2 < (uint64_t)max_b) {
                    int nid = hl_expr_binop(fn, e.op, ea.sub0, hl_expr_int(fn, c1 + c2, 8, 0), bw);
                    if (nid >= 0) fn->exprs[nid].is_signed = e.is_signed;
                    *changed = 1;
                    return hl_simplify_expr(fn, nid, changed, depth + 1);
                }
            }
            if (e.op == HLB_AND && ea.op == HLB_AND) {
                *changed = 1;
                return hl_expr_binop(fn, HLB_AND, ea.sub0, hl_expr_int(fn, c1 & c2, bw, 0), bw);
            }
            if (e.op == HLB_OR && ea.op == HLB_OR) {
                *changed = 1;
                return hl_expr_binop(fn, HLB_OR, ea.sub0, hl_expr_int(fn, c1 | c2, bw, 0), bw);
            }
            if (e.op == HLB_XOR && ea.op == HLB_XOR) {
                *changed = 1;
                return hl_expr_binop(fn, HLB_XOR, ea.sub0, hl_expr_int(fn, c1 ^ c2, bw, 0), bw);
            }
        }

        /* LEA multiply combines: x + x*c -> x*(c+1), x + (x<<s) -> x*((1<<s)+1), (x<<s) - x -> x*((1<<s)-1) */
        if (e.op == HLB_ADD) {
            if (eb.kind == HLE_BINOP && eb.op == HLB_MUL && eb.sub1 >= 0 &&
                fn->exprs[eb.sub1].kind == HLE_INT && hl_expr_eq(fn, a_id, eb.sub0, 0)) {
                *changed = 1;
                return hl_expr_binop(fn, HLB_MUL, a_id, hl_expr_int(fn, fn->exprs[eb.sub1].uval + 1ULL, bw, 0), bw);
            }
            if (ea.kind == HLE_BINOP && ea.op == HLB_MUL && ea.sub1 >= 0 &&
                fn->exprs[ea.sub1].kind == HLE_INT && hl_expr_eq(fn, b_id, ea.sub0, 0)) {
                *changed = 1;
                return hl_expr_binop(fn, HLB_MUL, b_id, hl_expr_int(fn, fn->exprs[ea.sub1].uval + 1ULL, bw, 0), bw);
            }
            if (eb.kind == HLE_BINOP && eb.op == HLB_SHL && eb.sub1 >= 0 &&
                fn->exprs[eb.sub1].kind == HLE_INT && fn->exprs[eb.sub1].uval < 32 &&
                hl_expr_eq(fn, a_id, eb.sub0, 0)) {
                *changed = 1;
                return hl_expr_binop(fn, HLB_MUL, a_id, hl_expr_int(fn, (1ULL << fn->exprs[eb.sub1].uval) + 1ULL, bw, 0), bw);
            }
            if (ea.kind == HLE_BINOP && ea.op == HLB_SHL && ea.sub1 >= 0 &&
                fn->exprs[ea.sub1].kind == HLE_INT && fn->exprs[ea.sub1].uval < 32 &&
                hl_expr_eq(fn, b_id, ea.sub0, 0)) {
                *changed = 1;
                return hl_expr_binop(fn, HLB_MUL, b_id, hl_expr_int(fn, (1ULL << fn->exprs[ea.sub1].uval) + 1ULL, bw, 0), bw);
            }
        }
        if (e.op == HLB_SUB && ea.kind == HLE_BINOP && ea.op == HLB_SHL && ea.sub1 >= 0 &&
            fn->exprs[ea.sub1].kind == HLE_INT && fn->exprs[ea.sub1].uval >= 1 &&
            fn->exprs[ea.sub1].uval < 32 && hl_expr_eq(fn, b_id, ea.sub0, 0)) {
            *changed = 1;
            return hl_expr_binop(fn, HLB_MUL, b_id, hl_expr_int(fn, (1ULL << fn->exprs[ea.sub1].uval) - 1ULL, bw, 0), bw);
        }

        /* SBB ternary combines: (cond ? -1 : 0) & k -> cond ? k : 0 ; + 1 -> !cond ; + k -> cond ? k-1 : k */
        if (ea.kind == HLE_TERNARY && ea.sub1 >= 0 && ea.sub2 >= 0 &&
            hl_is_neg1_int(&fn->exprs[ea.sub1]) &&
            fn->exprs[ea.sub2].kind == HLE_INT && fn->exprs[ea.sub2].uval == 0) {
            if (e.op == HLB_AND) {
                int te = hl_expr_new(fn, HLE_TERNARY);
                if (te >= 0) {
                    fn->exprs[te].sub0 = ea.sub0;
                    fn->exprs[te].sub1 = b_id;
                    fn->exprs[te].sub2 = hl_expr_int(fn, 0, bw, 0);
                    fn->exprs[te].bits = (uint8_t)bw;
                    *changed = 1;
                    return te;
                }
            }
            if (e.op == HLB_ADD && eb.kind == HLE_INT) {
                if (eb.uval == 1) {
                    *changed = 1;
                    return hl_expr_invert(fn, ea.sub0);
                }
                int te = hl_expr_new(fn, HLE_TERNARY);
                if (te >= 0) {
                    fn->exprs[te].sub0 = ea.sub0;
                    fn->exprs[te].sub1 = hl_expr_int(fn, hl_mask_bits(eb.uval - 1ULL, bw), bw, 0);
                    fn->exprs[te].sub2 = b_id;
                    fn->exprs[te].bits = (uint8_t)bw;
                    *changed = 1;
                    return te;
                }
            }
        }

        /* Comparison idioms */
        if (e.op == HLB_EQ || e.op == HLB_NE) {
            if (eb.kind == HLE_INT && eb.uval == 0) {
                if (hl_is_bool_expr(fn, a_id)) {
                    *changed = 1;
                    return (e.op == HLB_EQ) ? hl_expr_invert(fn, a_id) : a_id;
                }
                /* (a - b) == 0 -> a == b ; (a ^ b) == 0 -> a == b */
                if (ea.kind == HLE_BINOP && (ea.op == HLB_SUB || ea.op == HLB_XOR)) {
                    *changed = 1;
                    return hl_expr_binop(fn, e.op, ea.sub0, ea.sub1, 1);
                }
                /* ((bool_expr & 1) == 0) -> !bool_expr */
                if (ea.kind == HLE_BINOP && ea.op == HLB_AND && ea.sub1 >= 0 &&
                    fn->exprs[ea.sub1].kind == HLE_INT && fn->exprs[ea.sub1].uval == 1 &&
                    hl_is_bool_expr(fn, ea.sub0)) {
                    *changed = 1;
                    return (e.op == HLB_EQ) ? hl_expr_invert(fn, ea.sub0) : ea.sub0;
                }
            }
            if (eb.kind == HLE_INT && eb.uval == 1 && hl_is_bool_expr(fn, a_id)) {
                *changed = 1;
                return (e.op == HLB_EQ) ? a_id : hl_expr_invert(fn, a_id);
            }
            /* Strip ZEXT in comparison with small constant */
            if (eb.kind == HLE_INT && ea.kind == HLE_UNOP && ea.op == HLU_ZEXT && ea.sub0 >= 0) {
                int sb = fn->exprs[ea.sub0].bits;
                if (sb > 0 && sb < 64 && eb.uval < (1ULL << sb)) {
                    fn->exprs[eid].sub0 = ea.sub0;
                    *changed = 1;
                    return hl_simplify_expr(fn, eid, changed, depth + 1);
                }
            }
        }
        if (eb.kind == HLE_INT) {
            if (e.op == HLB_ULT && eb.uval == 1) { *changed = 1; return hl_expr_binop(fn, HLB_EQ, a_id, hl_expr_int(fn, 0, ea.bits, 0), 1); }
            if (e.op == HLB_UGE && eb.uval == 1) { *changed = 1; return hl_expr_binop(fn, HLB_NE, a_id, hl_expr_int(fn, 0, ea.bits, 0), 1); }
            if (e.op == HLB_UGT && eb.uval == 0) { *changed = 1; return hl_expr_binop(fn, HLB_NE, a_id, hl_expr_int(fn, 0, ea.bits, 0), 1); }
            if (e.op == HLB_ULE && eb.uval == 0) { *changed = 1; return hl_expr_binop(fn, HLB_EQ, a_id, hl_expr_int(fn, 0, ea.bits, 0), 1); }
        }

        /* Branchless abs(x): (x ^ (x >> 31/63)) - (x >> 31/63)  OR  (x + (x >> 31/63)) ^ (x >> 31/63) */
        if (e.op == HLB_SUB && ea.kind == HLE_BINOP && ea.op == HLB_XOR &&
            eb.kind == HLE_BINOP && eb.op == HLB_SAR && eb.sub1 >= 0 &&
            fn->exprs[eb.sub1].kind == HLE_INT &&
            (fn->exprs[eb.sub1].uval == 31 || fn->exprs[eb.sub1].uval == 63)) {
            int sx = eb.sub0;
            if ((hl_expr_eq(fn, ea.sub0, sx, 0) && hl_expr_eq(fn, ea.sub1, b_id, 0)) ||
                (hl_expr_eq(fn, ea.sub1, sx, 0) && hl_expr_eq(fn, ea.sub0, b_id, 0))) {
                *changed = 1;
                return hl_expr_unop(fn, HLU_ABS, sx, bw);
            }
        }
        if (e.op == HLB_XOR && ea.kind == HLE_BINOP && ea.op == HLB_ADD &&
            eb.kind == HLE_BINOP && eb.op == HLB_SAR && eb.sub1 >= 0 &&
            fn->exprs[eb.sub1].kind == HLE_INT &&
            (fn->exprs[eb.sub1].uval == 31 || fn->exprs[eb.sub1].uval == 63)) {
            int sx = eb.sub0;
            if ((hl_expr_eq(fn, ea.sub0, sx, 0) && hl_expr_eq(fn, ea.sub1, b_id, 0)) ||
                (hl_expr_eq(fn, ea.sub1, sx, 0) && hl_expr_eq(fn, ea.sub0, b_id, 0))) {
                *changed = 1;
                return hl_expr_unop(fn, HLU_ABS, sx, bw);
            }
        }

        /* Magic-Number Division: Unsigned Direct ((x * M) >> (32+sh) or (64+sh)) */
        if (e.op == HLB_SHR) {
            int x_id = -1, is64 = 0, sgn = 0, ex = 0;
            uint64_t M = 0, D = 0;
            if (hl_match_mulhi(fn, eid, &x_id, &M, &is64, &sgn, &ex) && !sgn) {
                int ok = is64 ? hl_solve_magic_udiv64(M, ex, 0, &D)
                              : hl_solve_magic_udiv32(M, ex, 0, &D);
                if (ok) {
                    int db = is64 ? 64 : 32;
                    *changed = 1;
                    return hl_expr_binop(fn, HLB_UDIV, x_id, hl_expr_int(fn, D, db, 0), db);
                }
            }
            /* Unsigned overflow-add form: ((((x - hi) >> 1) + hi) >> sh) */
            if (eb.kind == HLE_INT && ea.kind == HLE_BINOP && ea.op == HLB_ADD) {
                int p0 = ea.sub0, p1 = ea.sub1;
                for (int sw = 0; sw < 2; sw++) {
                    int hi_id = sw ? p0 : p1;
                    int sh_id = sw ? p1 : p0;
                    if (hl_match_mulhi(fn, hi_id, &x_id, &M, &is64, &sgn, &ex) && ex == 0 && !sgn &&
                        sh_id >= 0 && fn->exprs[sh_id].kind == HLE_BINOP && fn->exprs[sh_id].op == HLB_SHR &&
                        fn->exprs[sh_id].sub1 >= 0 && fn->exprs[fn->exprs[sh_id].sub1].kind == HLE_INT &&
                        fn->exprs[fn->exprs[sh_id].sub1].uval == 1) {
                        int sub_id = fn->exprs[sh_id].sub0;
                        if (sub_id >= 0 && fn->exprs[sub_id].kind == HLE_BINOP && fn->exprs[sub_id].op == HLB_SUB &&
                            hl_expr_eq(fn, fn->exprs[sub_id].sub0, x_id, 0) &&
                            hl_expr_eq(fn, fn->exprs[sub_id].sub1, hi_id, 0)) {
                            int ok = is64 ? hl_solve_magic_udiv64(M, (int)eb.uval, 1, &D)
                                          : hl_solve_magic_udiv32(M, (int)eb.uval, 1, &D);
                            if (ok) {
                                int db = is64 ? 64 : 32;
                                *changed = 1;
                                return hl_expr_binop(fn, HLB_UDIV, x_id, hl_expr_int(fn, D, db, 0), db);
                            }
                        }
                    }
                }
            }
        }

        /* Magic-Number Division: Signed q + (q >>> 31/63) or q - (x >> 31/63) */
        if ((e.op == HLB_ADD || e.op == HLB_SUB) && bw <= 64) {
            for (int sw = 0; sw < (e.op == HLB_ADD ? 2 : 1); sw++) {
                int q_id = sw ? b_id : a_id;
                int s_id = sw ? a_id : b_id;
                if (s_id < 0 || fn->exprs[s_id].kind != HLE_BINOP) continue;
                const hl_expr *se = &fn->exprs[s_id];
                if (se->sub1 < 0 || fn->exprs[se->sub1].kind != HLE_INT) continue;
                uint64_t ssh = fn->exprs[se->sub1].uval;
                int sign_ok = (e.op == HLB_ADD && se->op == HLB_SHR && (ssh == 31 || ssh == 63)) ||
                              (e.op == HLB_SUB && se->op == HLB_SAR && (ssh == 31 || ssh == 63));
                if (!sign_ok) continue;

                int x_id = -1, is64 = 0, sh = 0, add_x = 0, sub_x = 0;
                uint64_t M = 0, D = 0;
                if (hl_match_sdiv_core(fn, q_id, &x_id, &M, &is64, &sh, &add_x, &sub_x)) {
                    int expected_ssh = is64 ? 63 : 31;
                    if ((int)ssh == expected_ssh &&
                        (hl_expr_eq(fn, se->sub0, q_id, 0) || hl_expr_eq(fn, se->sub0, x_id, 0))) {
                        int ok = is64 ? hl_solve_magic_sdiv64(M, sh, add_x, sub_x, &D)
                                      : hl_solve_magic_sdiv32(M, sh, add_x, sub_x, &D);
                        if (ok) {
                            int db = is64 ? 64 : 32;
                            *changed = 1;
                            return hl_expr_binop(fn, HLB_SDIV, x_id, hl_expr_int(fn, D, db, 1), db);
                        }
                    }
                }
            }
        }

        /* Signed power-of-2 division: (x + ((x >> 31) >>> (32-k))) >> k  or  (x + (x >>> 31)) >> 1 */
        if (e.op == HLB_SAR && eb.kind == HLE_INT && eb.uval >= 1 && eb.uval < 31 &&
            ea.kind == HLE_BINOP && ea.op == HLB_ADD) {
            int k = (int)eb.uval;
            for (int sw = 0; sw < 2; sw++) {
                int x_id = sw ? ea.sub1 : ea.sub0;
                int b_part = sw ? ea.sub0 : ea.sub1;
                if (b_part < 0 || fn->exprs[b_part].kind != HLE_BINOP || fn->exprs[b_part].op != HLB_SHR) continue;
                const hl_expr *bp = &fn->exprs[b_part];
                if (bp->sub1 < 0 || fn->exprs[bp->sub1].kind != HLE_INT) continue;
                uint64_t rsh = fn->exprs[bp->sub1].uval;
                if (k == 1 && (rsh == 31 || rsh == 63) && hl_expr_eq(fn, bp->sub0, x_id, 0)) {
                    int db = (rsh == 63) ? 64 : 32;
                    *changed = 1;
                    return hl_expr_binop(fn, HLB_SDIV, x_id, hl_expr_int(fn, 2, db, 1), db);
                }
                if (bp->sub0 >= 0 && fn->exprs[bp->sub0].kind == HLE_BINOP &&
                    fn->exprs[bp->sub0].op == HLB_SAR && fn->exprs[bp->sub0].sub1 >= 0 &&
                    fn->exprs[fn->exprs[bp->sub0].sub1].kind == HLE_INT &&
                    hl_expr_eq(fn, fn->exprs[bp->sub0].sub0, x_id, 0)) {
                    uint64_t ash = fn->exprs[fn->exprs[bp->sub0].sub1].uval;
                    if ((ash == 31 && (int)rsh == 32 - k) || (ash == 63 && (int)rsh == 64 - k)) {
                        int db = (ash == 63) ? 64 : 32;
                        *changed = 1;
                        return hl_expr_binop(fn, HLB_SDIV, x_id, hl_expr_int(fn, 1ULL << k, db, 1), db);
                    }
                }
            }
        }

        /* Modulo folding: x - (x / D) * D -> x % D  and  x - ((x / D) << k) -> x % (1<<k) */
        if (e.op == HLB_SUB && eb.kind == HLE_BINOP && (eb.op == HLB_MUL || eb.op == HLB_SHL) &&
            eb.sub0 >= 0 && eb.sub1 >= 0 && fn->exprs[eb.sub1].kind == HLE_INT) {
            uint64_t factor = (eb.op == HLB_MUL) ? fn->exprs[eb.sub1].uval
                            : (fn->exprs[eb.sub1].uval < 64 ? (1ULL << fn->exprs[eb.sub1].uval) : 0ULL);
            const hl_expr *dv = &fn->exprs[eb.sub0];
            if (factor >= 2 && dv->kind == HLE_BINOP && (dv->op == HLB_SDIV || dv->op == HLB_UDIV) &&
                dv->sub1 >= 0 && fn->exprs[dv->sub1].kind == HLE_INT &&
                fn->exprs[dv->sub1].uval == factor && hl_expr_eq(fn, a_id, dv->sub0, 0)) {
                *changed = 1;
                return hl_expr_binop(fn, (dv->op == HLB_SDIV) ? HLB_SMOD : HLB_UMOD,
                                     a_id, hl_expr_int(fn, factor, bw, dv->op == HLB_SDIV), bw);
            }
        }
    }

    return eid;
}

static int hl_opt_simplify_all(hl_fn *fn) {
    int changed = 0;
    for (int b = 0; b < fn->nblk; b++) {
        hl_blk *hb = &fn->blks[b];
        for (int si = 0; si < hb->nstmt; si++) {
            int sid = hb->stmts[si];
            if (fn->stmts[sid].dead || fn->stmts[sid].kind == HLS_PHI) continue;
            if (fn->stmts[sid].lhs_expr >= 0) {
                int nl = hl_simplify_expr(fn, fn->stmts[sid].lhs_expr, &changed, 0);
                fn->stmts[sid].lhs_expr = nl;
            }
            if (fn->stmts[sid].rhs_expr >= 0) {
                int nr = hl_simplify_expr(fn, fn->stmts[sid].rhs_expr, &changed, 0);
                fn->stmts[sid].rhs_expr = nr;
            }
            if (fn->stmts[sid].len_expr >= 0) {
                int nln = hl_simplify_expr(fn, fn->stmts[sid].len_expr, &changed, 0);
                fn->stmts[sid].len_expr = nln;
            }
        }
        if (hb->cond_expr >= 0) {
            hb->cond_expr = hl_simplify_expr(fn, hb->cond_expr, &changed, 0);
        }
        if (hb->sw_expr >= 0) {
            hb->sw_expr = hl_simplify_expr(fn, hb->sw_expr, &changed, 0);
        }
    }
    return changed;
}

/* =========================================================================
 * Pass 3: Alias-Safe Single-Use Forward Substitution (Expression Folding)
 * ========================================================================= */

typedef struct {
    int blk;
    int pos; /* statement index in block, or blks[blk].nstmt for cond/sw */
    int kind; /* 0 = stmt, 1 = cond_expr, 2 = sw_expr */
    int sid;
} hl_use_site;

static void hl_count_uses_in_expr(const hl_fn *fn, int eid, int *use_cnt, hl_use_site *sites,
                                  int bi, int pos, int site_kind, int sid, int depth) {
    if (!fn || eid < 0 || eid >= fn->nexpr || depth > HL_MAX_DEPTH) return;
    const hl_expr *e = &fn->exprs[eid];
    if (e->kind == HLE_VAR && e->var_id >= 0 && e->var_id < fn->nvar) {
        int v = e->var_id;
        use_cnt[v]++;
        if (use_cnt[v] == 1 && sites) {
            sites[v].blk  = bi;
            sites[v].pos  = pos;
            sites[v].kind = site_kind;
            sites[v].sid  = sid;
        }
    }
    if (e->sub0 >= 0) hl_count_uses_in_expr(fn, e->sub0, use_cnt, sites, bi, pos, site_kind, sid, depth + 1);
    if (e->sub1 >= 0) hl_count_uses_in_expr(fn, e->sub1, use_cnt, sites, bi, pos, site_kind, sid, depth + 1);
    if (e->sub2 >= 0) hl_count_uses_in_expr(fn, e->sub2, use_cnt, sites, bi, pos, site_kind, sid, depth + 1);
    for (int i = 0; i < (int)e->narg && i < HL_MAX_CALL_ARG; i++) {
        if (e->args[i] >= 0) hl_count_uses_in_expr(fn, e->args[i], use_cnt, sites, bi, pos, site_kind, sid, depth + 1);
    }
}

static int hl_opt_fold_single_use(hl_fn *fn) {
    int nv = fn->nvar;
    if (nv <= 0) return 0;

    int *def_cnt  = (int *)calloc((size_t)(nv + 1), sizeof(int));
    int *use_cnt  = (int *)calloc((size_t)(nv + 1), sizeof(int));
    int *phi_use  = (int *)calloc((size_t)(nv + 1), sizeof(int));
    int *def_blk  = (int *)malloc((size_t)(nv + 1) * sizeof(int));
    int *def_pos  = (int *)malloc((size_t)(nv + 1) * sizeof(int));
    int *def_sid  = (int *)malloc((size_t)(nv + 1) * sizeof(int));
    hl_use_site *site = (hl_use_site *)calloc((size_t)(nv + 1), sizeof(hl_use_site));

    if (!def_cnt || !use_cnt || !phi_use || !def_blk || !def_pos || !def_sid || !site) {
        free(def_cnt); free(use_cnt); free(phi_use);
        free(def_blk); free(def_pos); free(def_sid); free(site);
        return 0;
    }
    for (int i = 0; i <= nv; i++) { def_blk[i] = -1; def_pos[i] = -1; def_sid[i] = -1; }

    for (int b = 0; b < fn->nblk; b++) {
        const hl_blk *hb = &fn->blks[b];
        for (int pos = 0; pos < hb->nstmt; pos++) {
            int sid = hb->stmts[pos];
            const hl_stmt *s = &fn->stmts[sid];
            if (s->dead) continue;
            if ((s->kind == HLS_ASSIGN || s->kind == HLS_PHI) && s->dst_var >= 0 && s->dst_var < nv) {
                def_cnt[s->dst_var]++;
                def_blk[s->dst_var] = b;
                def_pos[s->dst_var] = pos;
                def_sid[s->dst_var] = sid;
            }
            if (s->kind == HLS_PHI) {
                for (int pi = 0; pi < (int)s->nphi; pi++) {
                    int pv = s->phi_vars[pi];
                    if (pv >= 0 && pv < nv) {
                        use_cnt[pv]++;
                        phi_use[pv]++;
                    }
                }
            } else {
                hl_count_uses_in_expr(fn, s->lhs_expr, use_cnt, site, b, pos, 0, sid, 0);
                hl_count_uses_in_expr(fn, s->rhs_expr, use_cnt, site, b, pos, 0, sid, 0);
                hl_count_uses_in_expr(fn, s->len_expr, use_cnt, site, b, pos, 0, sid, 0);
            }
        }
        hl_count_uses_in_expr(fn, hb->cond_expr, use_cnt, site, b, hb->nstmt, 1, -1, 0);
        hl_count_uses_in_expr(fn, hb->sw_expr,   use_cnt, site, b, hb->nstmt, 2, -1, 0);
    }

    int changed = 0;
    for (int v = 0; v < nv; v++) {
        if (def_cnt[v] != 1 || use_cnt[v] != 1 || phi_use[v] > 0) continue;
        if (fn->vars[v].is_arg || fn->vars[v].is_stack) continue;
        int dsid = def_sid[v];
        if (dsid < 0 || fn->stmts[dsid].dead || fn->stmts[dsid].kind != HLS_ASSIGN) continue;
        int rhs = fn->stmts[dsid].rhs_expr;
        if (rhs < 0 || rhs >= fn->nexpr) continue;
        if (hl_expr_uses_var(fn, rhs, v, 0)) continue;

        int has_call  = hl_expr_has_kind(fn, rhs, HLE_CALL, 0);
        int has_deref = hl_expr_has_kind(fn, rhs, HLE_DEREF, 0);
        int has_stk   = hl_expr_has_stack_var(fn, rhs, 0);
        int nodes     = hl_expr_nodes(fn, rhs, 0);

        hl_use_site us = site[v];
        int can_fold = 0;

        if (!has_call && !has_deref && !has_stk) {
            /* Pure expression: global forward substitution if node count <= 10 */
            if (nodes <= 10) can_fold = 1;
        } else if (us.blk == def_blk[v] && us.pos > def_pos[v]) {
            /* Same basic block */
            const hl_blk *hb = &fn->blks[us.blk];
            if (has_call) {
                /* For HLE_CALL: only when immediately used in HLS_RET, HLS_ASSIGN, HLS_STORE, or cond_expr */
                int ok_kind = (us.kind == 1);
                if (us.kind == 0 && us.sid >= 0 && !fn->stmts[us.sid].dead) {
                    uint8_t uk = fn->stmts[us.sid].kind;
                    if (uk == HLS_RET || uk == HLS_ASSIGN || uk == HLS_STORE) {
                        /* Avoid nesting call inside another call or store lhs */
                        if (!hl_expr_has_kind(fn, fn->stmts[us.sid].rhs_expr, HLE_CALL, 0) &&
                            !hl_expr_has_kind(fn, fn->stmts[us.sid].lhs_expr, HLE_CALL, 0) &&
                            !hl_expr_uses_var(fn, fn->stmts[us.sid].lhs_expr, v, 0)) {
                            ok_kind = 1;
                        }
                    }
                }
                int intervening_live = 0;
                for (int p = def_pos[v] + 1; p < us.pos; p++) {
                    if (!fn->stmts[hb->stmts[p]].dead) { intervening_live = 1; break; }
                }
                if (ok_kind && !intervening_live && nodes <= 14) can_fold = 1;
            } else if (nodes <= 10) {
                /* HLE_DEREF or stack read: require no intervening side-effects / stores / calls */
                int hazard = 0;
                for (int p = def_pos[v] + 1; p < us.pos; p++) {
                    const hl_stmt *mid = &fn->stmts[hb->stmts[p]];
                    if (mid->dead) continue;
                    if (mid->kind == HLS_STORE || mid->kind == HLS_CALL ||
                        mid->kind == HLS_MEMCPY || mid->kind == HLS_MEMSET) {
                        hazard = 1;
                        break;
                    }
                    if (mid->kind == HLS_ASSIGN) {
                        if (mid->dst_var >= 0 && fn->vars[mid->dst_var].is_stack) { hazard = 1; break; }
                        if (hl_expr_has_kind(fn, mid->rhs_expr, HLE_CALL, 0)) { hazard = 1; break; }
                    }
                }
                if (!hazard) can_fold = 1;
            }
        }

        if (!can_fold) continue;

        int did = 0;
        if (us.kind == 0 && us.sid >= 0 && !fn->stmts[us.sid].dead) {
            int nl = hl_expr_subst_one(fn, fn->stmts[us.sid].lhs_expr, v, rhs, &did, 0);
            int nr = hl_expr_subst_one(fn, fn->stmts[us.sid].rhs_expr, v, rhs, &did, 0);
            int nln = hl_expr_subst_one(fn, fn->stmts[us.sid].len_expr, v, rhs, &did, 0);
            fn->stmts[us.sid].lhs_expr = nl;
            fn->stmts[us.sid].rhs_expr = nr;
            fn->stmts[us.sid].len_expr = nln;
        } else if (us.kind == 1 && us.blk >= 0) {
            fn->blks[us.blk].cond_expr = hl_expr_subst_one(fn, fn->blks[us.blk].cond_expr, v, rhs, &did, 0);
        } else if (us.kind == 2 && us.blk >= 0) {
            fn->blks[us.blk].sw_expr = hl_expr_subst_one(fn, fn->blks[us.blk].sw_expr, v, rhs, &did, 0);
        }

        if (did) {
            fn->stmts[dsid].dead = 1;
            changed = 1;
        }
    }

    free(def_cnt); free(use_cnt); free(phi_use);
    free(def_blk); free(def_pos); free(def_sid); free(site);
    return changed;
}

/* =========================================================================
 * Pass 4: Global Dead Code Elimination (DCE)
 * ========================================================================= */

static void hl_mark_expr_vars_live(const hl_fn *fn, int eid, uint8_t *var_live, int *changed, int depth) {
    if (!fn || eid < 0 || eid >= fn->nexpr || depth > HL_MAX_DEPTH) return;
    const hl_expr *e = &fn->exprs[eid];
    if (e->kind == HLE_VAR && e->var_id >= 0 && e->var_id < fn->nvar) {
        if (!var_live[e->var_id]) {
            var_live[e->var_id] = 1;
            *changed = 1;
        }
    }
    if (e->sub0 >= 0) hl_mark_expr_vars_live(fn, e->sub0, var_live, changed, depth + 1);
    if (e->sub1 >= 0) hl_mark_expr_vars_live(fn, e->sub1, var_live, changed, depth + 1);
    if (e->sub2 >= 0) hl_mark_expr_vars_live(fn, e->sub2, var_live, changed, depth + 1);
    for (int i = 0; i < (int)e->narg && i < HL_MAX_CALL_ARG; i++) {
        if (e->args[i] >= 0) hl_mark_expr_vars_live(fn, e->args[i], var_live, changed, depth + 1);
    }
}

static void hl_dce_propagate(const hl_fn *fn, uint8_t *stmt_live, uint8_t *var_live) {
    int changed = 1;
    while (changed) {
        changed = 0;
        for (int b = 0; b < fn->nblk; b++) {
            const hl_blk *hb = &fn->blks[b];
            for (int si = 0; si < hb->nstmt; si++) {
                int sid = hb->stmts[si];
                const hl_stmt *s = &fn->stmts[sid];
                if (s->dead) continue;
                if (!stmt_live[sid] && (s->kind == HLS_ASSIGN || s->kind == HLS_PHI) &&
                    s->dst_var >= 0 && s->dst_var < fn->nvar && var_live[s->dst_var]) {
                    stmt_live[sid] = 1;
                    changed = 1;
                }
                if (stmt_live[sid]) {
                    hl_mark_expr_vars_live(fn, s->lhs_expr, var_live, &changed, 0);
                    hl_mark_expr_vars_live(fn, s->rhs_expr, var_live, &changed, 0);
                    hl_mark_expr_vars_live(fn, s->len_expr, var_live, &changed, 0);
                    if (s->kind == HLS_PHI) {
                        for (int pi = 0; pi < (int)s->nphi; pi++) {
                            int pv = s->phi_vars[pi];
                            if (pv >= 0 && pv < fn->nvar && !var_live[pv]) {
                                var_live[pv] = 1;
                                changed = 1;
                            }
                        }
                    }
                }
            }
        }
    }
}

static int hl_opt_dce(hl_fn *fn, const uint8_t *aliased) {
    if (fn->nstmt <= 0) return 0;
    uint8_t *stmt_live = (uint8_t *)calloc((size_t)(fn->nstmt + 1), 1);
    uint8_t *var_live  = (uint8_t *)calloc((size_t)(fn->nvar + 1), 1);
    if (!stmt_live || !var_live) {
        free(stmt_live);
        free(var_live);
        return 0;
    }

    int dummy = 0;
    for (int b = 0; b < fn->nblk; b++) {
        const hl_blk *hb = &fn->blks[b];
        hl_mark_expr_vars_live(fn, hb->cond_expr, var_live, &dummy, 0);
        hl_mark_expr_vars_live(fn, hb->sw_expr,   var_live, &dummy, 0);
        for (int si = 0; si < hb->nstmt; si++) {
            int sid = hb->stmts[si];
            const hl_stmt *s = &fn->stmts[sid];
            if (s->dead) continue;
            if (s->kind == HLS_STORE || s->kind == HLS_CALL || s->kind == HLS_RET ||
                s->kind == HLS_MEMCPY || s->kind == HLS_MEMSET) {
                stmt_live[sid] = 1;
            } else if (s->kind == HLS_ASSIGN && s->dst_var >= 0 && s->dst_var < fn->nvar &&
                       aliased && aliased[s->dst_var]) {
                /* Writes to address-taken stack variables/buffers are observable side effects */
                stmt_live[sid] = 1;
            }
        }
    }

    hl_dce_propagate(fn, stmt_live, var_live);

    /* Convert unreached assignments whose RHS is/contains HLE_CALL into side-effecting HLS_CALL */
    int converted_call = 0;
    for (int b = 0; b < fn->nblk; b++) {
        const hl_blk *hb = &fn->blks[b];
        for (int si = 0; si < hb->nstmt; si++) {
            int sid = hb->stmts[si];
            hl_stmt *s = &fn->stmts[sid];
            if (s->dead || stmt_live[sid] || s->kind != HLS_ASSIGN) continue;
            if (hl_expr_has_kind(fn, s->rhs_expr, HLE_CALL, 0)) {
                if (s->rhs_expr >= 0 && fn->exprs[s->rhs_expr].kind == HLE_CALL) {
                    s->kind    = HLS_CALL;
                    s->dst_var = -1;
                }
                stmt_live[sid] = 1;
                converted_call = 1;
            }
        }
    }
    if (converted_call) hl_dce_propagate(fn, stmt_live, var_live);

    int changed = converted_call;
    for (int b = 0; b < fn->nblk; b++) {
        const hl_blk *hb = &fn->blks[b];
        for (int si = 0; si < hb->nstmt; si++) {
            int sid = hb->stmts[si];
            if (!fn->stmts[sid].dead && !stmt_live[sid]) {
                fn->stmts[sid].dead = 1;
                changed = 1;
            }
        }
    }

    free(stmt_live);
    free(var_live);
    return changed;
}

/* =========================================================================
 * Pass 5: Exact Liveness, Interference, SSA Coalescing & Clean Variable Naming
 * ========================================================================= */

static void hl_collect_expr_var_bits(const hl_fn *fn, int eid, const int *var_to_dense,
                                     uint64_t *bits, int depth) {
    if (!fn || eid < 0 || eid >= fn->nexpr || depth > HL_MAX_DEPTH) return;
    const hl_expr *e = &fn->exprs[eid];
    if (e->kind == HLE_VAR) {
        int cv = hl_var_canon(fn, e->var_id);
        if (cv >= 0 && cv < fn->nvar && var_to_dense[cv] >= 0) {
            hl_bs_set(bits, var_to_dense[cv]);
        }
    }
    if (e->sub0 >= 0) hl_collect_expr_var_bits(fn, e->sub0, var_to_dense, bits, depth + 1);
    if (e->sub1 >= 0) hl_collect_expr_var_bits(fn, e->sub1, var_to_dense, bits, depth + 1);
    if (e->sub2 >= 0) hl_collect_expr_var_bits(fn, e->sub2, var_to_dense, bits, depth + 1);
    for (int i = 0; i < (int)e->narg && i < HL_MAX_CALL_ARG; i++) {
        if (e->args[i] >= 0) hl_collect_expr_var_bits(fn, e->args[i], var_to_dense, bits, depth + 1);
    }
}

static void hl_rewrite_expr_canon(hl_fn *fn, int eid, int depth) {
    if (!fn || eid < 0 || eid >= fn->nexpr || depth > HL_MAX_DEPTH) return;
    hl_expr *e = &fn->exprs[eid];
    if (e->kind == HLE_VAR && e->var_id >= 0) {
        e->var_id = hl_var_canon(fn, e->var_id);
    }
    if (e->bits == 128 && !(e->kind == HLE_BINOP && e->op == HLB_MUL)) e->bits = 64;
    if (e->sub0 >= 0) hl_rewrite_expr_canon(fn, e->sub0, depth + 1);
    if (e->sub1 >= 0) hl_rewrite_expr_canon(fn, e->sub1, depth + 1);
    if (e->sub2 >= 0) hl_rewrite_expr_canon(fn, e->sub2, depth + 1);
    for (int i = 0; i < (int)e->narg && i < HL_MAX_CALL_ARG; i++) {
        if (e->args[i] >= 0) hl_rewrite_expr_canon(fn, e->args[i], depth + 1);
    }
}

static void hl_recount_vars_expr(hl_fn *fn, int eid, int depth) {
    if (!fn || eid < 0 || eid >= fn->nexpr || depth > HL_MAX_DEPTH) return;
    const hl_expr *e = &fn->exprs[eid];
    if (e->kind == HLE_VAR && e->var_id >= 0 && e->var_id < fn->nvar) {
        fn->vars[e->var_id].use_cnt++;
        fn->vars[e->var_id].is_dead = 0;
    }
    if (e->sub0 >= 0) hl_recount_vars_expr(fn, e->sub0, depth + 1);
    if (e->sub1 >= 0) hl_recount_vars_expr(fn, e->sub1, depth + 1);
    if (e->sub2 >= 0) hl_recount_vars_expr(fn, e->sub2, depth + 1);
    for (int i = 0; i < (int)e->narg && i < HL_MAX_CALL_ARG; i++) {
        if (e->args[i] >= 0) hl_recount_vars_expr(fn, e->args[i], depth + 1);
    }
}

static void hl_emit_parallel_edge_copies(hl_fn *fn, int pb, int *dsts, int *srcs, int ncopy) {
    if (ncopy <= 0 || pb < 0 || pb >= fn->nblk) return;

    /* Protect pb's cond_expr / sw_expr if any copy destination is referenced there */
    int cond_clob = 0;
    for (int i = 0; i < ncopy; i++) {
        if (fn->blks[pb].cond_expr >= 0 && hl_expr_uses_var(fn, fn->blks[pb].cond_expr, dsts[i], 0)) {
            cond_clob = 1;
            break;
        }
    }
    if (cond_clob) {
        int ctmp = hl_var_new(fn, 1, -1, 0);
        if (ctmp >= 0) {
            int sid = hl_stmt_new(fn, pb, fn->blks[pb].cond_va ? fn->blks[pb].cond_va : fn->blks[pb].end, HLS_ASSIGN);
            if (sid >= 0) {
                fn->stmts[sid].dst_var  = ctmp;
                fn->stmts[sid].rhs_expr = fn->blks[pb].cond_expr;
                fn->blks[pb].cond_expr  = hl_expr_var(fn, ctmp);
            }
        }
    }

    /* Parallel copy lowering: break write-before-read dependencies with a temp */
    int done[32];
    int n = (ncopy > 32) ? 32 : ncopy;
    for (int i = 0; i < n; i++) done[i] = (dsts[i] == srcs[i]) ? 1 : 0;

    for (int iter = 0; iter < n * 2; iter++) {
        int progressed = 0;
        for (int i = 0; i < n; i++) {
            if (done[i]) continue;
            int blocked = 0;
            for (int j = 0; j < n; j++) {
                if (!done[j] && j != i && srcs[j] == dsts[i]) { blocked = 1; break; }
            }
            if (!blocked) {
                int re = hl_expr_var(fn, srcs[i]);
                int sid = hl_stmt_new(fn, pb, fn->blks[pb].end, HLS_ASSIGN);
                if (sid >= 0) {
                    fn->stmts[sid].dst_var  = dsts[i];
                    fn->stmts[sid].rhs_expr = re;
                }
                done[i] = 1;
                progressed = 1;
            }
        }
        if (progressed) continue;

        /* Remaining entries form a cycle (e.g. a = b; b = a): break with one temp */
        int cyc = -1;
        for (int i = 0; i < n; i++) {
            if (!done[i]) { cyc = i; break; }
        }
        if (cyc < 0) break;
        int tv = hl_var_new(fn, fn->vars[srcs[cyc]].bits, -1, fn->vars[srcs[cyc]].is_flt);
        if (tv < 0) break;
        int re = hl_expr_var(fn, srcs[cyc]);
        int sid = hl_stmt_new(fn, pb, fn->blks[pb].end, HLS_ASSIGN);
        if (sid >= 0) {
            fn->stmts[sid].dst_var  = tv;
            fn->stmts[sid].rhs_expr = re;
        }
        int old_src = srcs[cyc];
        for (int j = 0; j < n; j++) {
            if (!done[j] && srcs[j] == old_src) srcs[j] = tv;
        }
    }
}

static void hl_lower_block_phis_edge_copies(hl_fn *fn, int b, int orig_nstmt) {
    /* Collect all distinct predecessor blocks of live PHIs in block b */
    int preds[16];
    int npred = 0;
    for (int si = 0; si < orig_nstmt; si++) {
        int sid = fn->blks[b].stmts[si];
        if (fn->stmts[sid].dead || fn->stmts[sid].kind != HLS_PHI) continue;
        int nphi = (int)fn->stmts[sid].nphi;
        for (int pi = 0; pi < nphi; pi++) {
            int pb = fn->stmts[sid].phi_blks[pi];
            if (pb < 0 || pb >= fn->nblk) continue;
            int found = 0;
            for (int k = 0; k < npred; k++) {
                if (preds[k] == pb) { found = 1; break; }
            }
            if (!found && npred < 16) preds[npred++] = pb;
        }
    }

    for (int k = 0; k < npred; k++) {
        int pb = preds[k];
        int dsts[32], srcs[32];
        int ncopy = 0;
        for (int si = 0; si < orig_nstmt; si++) {
            int sid = fn->blks[b].stmts[si];
            if (fn->stmts[sid].dead || fn->stmts[sid].kind != HLS_PHI) continue;
            int dst_c = hl_var_canon(fn, fn->stmts[sid].dst_var);
            int nphi  = (int)fn->stmts[sid].nphi;
            for (int pi = 0; pi < nphi; pi++) {
                if (fn->stmts[sid].phi_blks[pi] != pb) continue;
                int pv = hl_var_canon(fn, fn->stmts[sid].phi_vars[pi]);
                if (dst_c >= 0 && pv >= 0 && pv != dst_c && ncopy < 32) {
                    dsts[ncopy] = dst_c;
                    srcs[ncopy] = pv;
                    ncopy++;
                }
            }
        }
        hl_emit_parallel_edge_copies(fn, pb, dsts, srcs, ncopy);
    }

    for (int si = 0; si < orig_nstmt; si++) {
        int sid = fn->blks[b].stmts[si];
        if (!fn->stmts[sid].dead && fn->stmts[sid].kind == HLS_PHI) {
            fn->stmts[sid].dead = 1;
        }
    }
}

static void hl_opt_coalesce(hl_fn *fn) {
    int nv = fn->nvar;
    int nb = fn->nblk;
    if (nv <= 0 || nb <= 0) return;

    /* 5a. Identify which entry ABI args are actually live BEFORE coalescing */
    uint8_t *arg_used_pre = (uint8_t *)calloc((size_t)(nv + 1), 1);
    int *var_to_dense     = (int *)malloc((size_t)(nv + 1) * sizeof(int));
    int *dense_to_var     = (int *)malloc((size_t)(HL_COAL_MAX_VARS + 1) * sizeof(int));
    if (!arg_used_pre || !var_to_dense || !dense_to_var) {
        free(arg_used_pre); free(var_to_dense); free(dense_to_var);
        return;
    }
    for (int i = 0; i <= nv; i++) var_to_dense[i] = -1;

    /* Mark live vars before coalescing */
    uint8_t *v_seen = (uint8_t *)calloc((size_t)(nv + 1), 1);
    if (v_seen) {
        int dummy = 0;
        for (int b = 0; b < nb; b++) {
            const hl_blk *hb = &fn->blks[b];
            hl_mark_expr_vars_live(fn, hb->cond_expr, v_seen, &dummy, 0);
            hl_mark_expr_vars_live(fn, hb->sw_expr,   v_seen, &dummy, 0);
            for (int si = 0; si < hb->nstmt; si++) {
                const hl_stmt *s = &fn->stmts[hb->stmts[si]];
                if (s->dead) continue;
                hl_mark_expr_vars_live(fn, s->lhs_expr, v_seen, &dummy, 0);
                hl_mark_expr_vars_live(fn, s->rhs_expr, v_seen, &dummy, 0);
                hl_mark_expr_vars_live(fn, s->len_expr, v_seen, &dummy, 0);
                if (s->kind == HLS_PHI) {
                    for (int pi = 0; pi < (int)s->nphi; pi++) {
                        int pv = s->phi_vars[pi];
                        if (pv >= 0 && pv < nv) v_seen[pv] = 1;
                    }
                }
            }
        }
        for (int v = 0; v < nv; v++) {
            if (fn->vars[v].is_arg) {
                if (v_seen[v]) arg_used_pre[v] = 1;
                else fn->vars[v].is_arg = 0; /* unused ABI arg reg -> never a parameter */
            }
        }
        /* Also mark defined vars so they get dense indices */
        for (int b = 0; b < nb; b++) {
            const hl_blk *hb = &fn->blks[b];
            for (int si = 0; si < hb->nstmt; si++) {
                const hl_stmt *s = &fn->stmts[hb->stmts[si]];
                if (s->dead) continue;
                if ((s->kind == HLS_ASSIGN || s->kind == HLS_PHI) && s->dst_var >= 0 && s->dst_var < nv) {
                    v_seen[s->dst_var] = 1;
                }
            }
        }
    }

    int ndense = 0;
    for (int v = 0; v < nv && ndense < HL_COAL_MAX_VARS; v++) {
        if (v_seen && v_seen[v]) {
            var_to_dense[v] = ndense;
            dense_to_var[ndense] = v;
            ndense++;
        }
    }
    free(v_seen);

    /* 5b. Exact block-level liveness & interference graph for PHI coalescing */
    int nwords = (ndense + 63) / 64;
    if (nwords < 1) nwords = 1;
    uint64_t (*live_in)[HL_COAL_WORDS]  = (uint64_t (*)[HL_COAL_WORDS])calloc((size_t)nb, sizeof(uint64_t[HL_COAL_WORDS]));
    uint64_t (*live_out)[HL_COAL_WORDS] = (uint64_t (*)[HL_COAL_WORDS])calloc((size_t)nb, sizeof(uint64_t[HL_COAL_WORDS]));
    uint64_t (*blk_use)[HL_COAL_WORDS]  = (uint64_t (*)[HL_COAL_WORDS])calloc((size_t)nb, sizeof(uint64_t[HL_COAL_WORDS]));
    uint64_t (*blk_def)[HL_COAL_WORDS]  = (uint64_t (*)[HL_COAL_WORDS])calloc((size_t)nb, sizeof(uint64_t[HL_COAL_WORDS]));
    uint64_t (*phi_edge)[HL_COAL_WORDS] = (uint64_t (*)[HL_COAL_WORDS])calloc((size_t)nb, sizeof(uint64_t[HL_COAL_WORDS]));
    uint64_t (*interf)[HL_COAL_WORDS]   = (uint64_t (*)[HL_COAL_WORDS])calloc((size_t)(ndense + 1), sizeof(uint64_t[HL_COAL_WORDS]));

    if (live_in && live_out && blk_use && blk_def && phi_edge && interf) {
        /* Compute per-block use/def & PHI edge uses */
        for (int b = 0; b < nb; b++) {
            const hl_blk *hb = &fn->blks[b];
            for (int si = 0; si < hb->nstmt; si++) {
                const hl_stmt *s = &fn->stmts[hb->stmts[si]];
                if (s->dead) continue;
                if (s->kind == HLS_PHI) {
                    if (s->dst_var >= 0 && var_to_dense[s->dst_var] >= 0) {
                        hl_bs_set(blk_def[b], var_to_dense[s->dst_var]);
                    }
                    for (int pi = 0; pi < (int)s->nphi; pi++) {
                        int pv = s->phi_vars[pi];
                        int pb = s->phi_blks[pi];
                        if (pv >= 0 && pv < nv && var_to_dense[pv] >= 0 && pb >= 0 && pb < nb) {
                            hl_bs_set(phi_edge[pb], var_to_dense[pv]);
                        }
                    }
                    continue;
                }
                uint64_t u[HL_COAL_WORDS];
                memset(u, 0, sizeof(u));
                hl_collect_expr_var_bits(fn, s->lhs_expr, var_to_dense, u, 0);
                hl_collect_expr_var_bits(fn, s->rhs_expr, var_to_dense, u, 0);
                hl_collect_expr_var_bits(fn, s->len_expr, var_to_dense, u, 0);
                for (int w = 0; w < nwords; w++) blk_use[b][w] |= (u[w] & ~blk_def[b][w]);
                if (s->kind == HLS_ASSIGN && s->dst_var >= 0 && var_to_dense[s->dst_var] >= 0) {
                    hl_bs_set(blk_def[b], var_to_dense[s->dst_var]);
                }
            }
            uint64_t cu[HL_COAL_WORDS];
            memset(cu, 0, sizeof(cu));
            hl_collect_expr_var_bits(fn, hb->cond_expr, var_to_dense, cu, 0);
            hl_collect_expr_var_bits(fn, hb->sw_expr,   var_to_dense, cu, 0);
            for (int w = 0; w < nwords; w++) blk_use[b][w] |= (cu[w] & ~blk_def[b][w]);
        }

        /* Backward liveness fixpoint */
        int lchg = 1;
        while (lchg) {
            lchg = 0;
            for (int b = nb - 1; b >= 0; b--) {
                uint64_t nout[HL_COAL_WORDS], nin[HL_COAL_WORDS];
                memcpy(nout, phi_edge[b], sizeof(nout));
                int succs[3] = {fn->blks[b].out_t, fn->blks[b].out_f, fn->blks[b].out_u};
                for (int si = 0; si < 3; si++) {
                    int s = succs[si];
                    if (s >= 0 && s < nb) {
                        for (int w = 0; w < nwords; w++) nout[w] |= live_in[s][w];
                    }
                }
                for (int w = 0; w < nwords; w++) {
                    nin[w] = blk_use[b][w] | (nout[w] & ~blk_def[b][w]);
                }
                if (!hl_bs_eq(nin, live_in[b], nwords) || !hl_bs_eq(nout, live_out[b], nwords)) {
                    memcpy(live_in[b],  nin,  sizeof(nin));
                    memcpy(live_out[b], nout, sizeof(nout));
                    lchg = 1;
                }
            }
        }

        /* Build interference matrix */
        for (int b = 0; b < nb; b++) {
            const hl_blk *hb = &fn->blks[b];
            uint64_t live[HL_COAL_WORDS];
            memcpy(live, live_out[b], sizeof(live));
            hl_collect_expr_var_bits(fn, hb->cond_expr, var_to_dense, live, 0);
            hl_collect_expr_var_bits(fn, hb->sw_expr,   var_to_dense, live, 0);

            for (int si = hb->nstmt - 1; si >= 0; si--) {
                const hl_stmt *s = &fn->stmts[hb->stmts[si]];
                if (s->dead) continue;
                if (s->kind == HLS_ASSIGN && s->dst_var >= 0 && var_to_dense[s->dst_var] >= 0) {
                    int dd = var_to_dense[s->dst_var];
                    int copy_src = -1;
                    if (s->rhs_expr >= 0 && fn->exprs[s->rhs_expr].kind == HLE_VAR) {
                        int sv = fn->exprs[s->rhs_expr].var_id;
                        if (sv >= 0 && sv < nv) copy_src = var_to_dense[sv];
                    }
                    for (int u = 0; u < ndense; u++) {
                        if (u != dd && u != copy_src && hl_bs_get(live, u)) {
                            hl_bs_set(interf[dd], u);
                            hl_bs_set(interf[u], dd);
                        }
                    }
                    hl_bs_clr(live, dd);
                    hl_collect_expr_var_bits(fn, s->rhs_expr, var_to_dense, live, 0);
                } else if (s->kind == HLS_PHI && s->dst_var >= 0 && var_to_dense[s->dst_var] >= 0) {
                    int dd = var_to_dense[s->dst_var];
                    for (int u = 0; u < ndense; u++) {
                        if (u != dd && hl_bs_get(live, u)) {
                            hl_bs_set(interf[dd], u);
                            hl_bs_set(interf[u], dd);
                        }
                    }
                    hl_bs_clr(live, dd);
                } else {
                    hl_collect_expr_var_bits(fn, s->lhs_expr, var_to_dense, live, 0);
                    hl_collect_expr_var_bits(fn, s->rhs_expr, var_to_dense, live, 0);
                    hl_collect_expr_var_bits(fn, s->len_expr, var_to_dense, live, 0);
                }
            }
        }

        /* Distinct live-in args and distinct stack slots always interfere */
        for (int i = 0; i < ndense; i++) {
            const hl_var *vi = &fn->vars[dense_to_var[i]];
            for (int j = i + 1; j < ndense; j++) {
                const hl_var *vj = &fn->vars[dense_to_var[j]];
                if ((vi->is_arg && vj->is_arg) || (vi->is_stack && vj->is_stack) ||
                    (vi->is_flt != vj->is_flt)) {
                    hl_bs_set(interf[i], j);
                    hl_bs_set(interf[j], i);
                }
            }
        }

        /* Resolve all live HLS_PHI nodes via coalescing + parallel edge-copy fallback */
        for (int b = 0; b < nb; b++) {
            int orig_nstmt = fn->blks[b].nstmt;
            for (int si = 0; si < orig_nstmt; si++) {
                int sid = fn->blks[b].stmts[si];
                if (fn->stmts[sid].dead || fn->stmts[sid].kind != HLS_PHI) continue;

                int nphi = (int)fn->stmts[sid].nphi;
                for (int pi = 0; pi < nphi; pi++) {
                    int dv = hl_var_canon(fn, fn->stmts[sid].dst_var);
                    int pv = hl_var_canon(fn, fn->stmts[sid].phi_vars[pi]);
                    if (dv < 0 || pv < 0 || dv == pv) continue;
                    int dd = var_to_dense[dv];
                    int pd = var_to_dense[pv];
                    if (dd < 0 || pd < 0 || hl_bs_get(interf[dd], pd)) continue;

                    /* Pick canonical representative (prefer arg > stack > dst) */
                    int rep_v = dv, oth_v = pv;
                    if (fn->vars[pv].is_arg && !fn->vars[dv].is_arg) { rep_v = pv; oth_v = dv; }
                    else if (fn->vars[pv].is_stack && !fn->vars[dv].is_stack && !fn->vars[dv].is_arg) {
                        rep_v = pv; oth_v = dv;
                    }
                    int rep_d = var_to_dense[rep_v];
                    int oth_d = var_to_dense[oth_v];
                    fn->vars[oth_v].coal_to = rep_v;
                    if (fn->vars[oth_v].bits > fn->vars[rep_v].bits) {
                        fn->vars[rep_v].bits = fn->vars[oth_v].bits;
                    }
                    /* Merge interference neighborhoods */
                    for (int w = 0; w < nwords; w++) interf[rep_d][w] |= interf[oth_d][w];
                    hl_bs_clr(interf[rep_d], rep_d);
                    for (int u = 0; u < ndense; u++) {
                        if (hl_bs_get(interf[rep_d], u)) hl_bs_set(interf[u], rep_d);
                    }
                }
            }
            hl_lower_block_phis_edge_copies(fn, b, orig_nstmt);
        }
    } else {
        /* Fallback if OOM on interference tables: pure parallel edge-copy PHI lowering */
        for (int b = 0; b < nb; b++) {
            hl_lower_block_phis_edge_copies(fn, b, fn->blks[b].nstmt);
        }
    }

    free(live_in); free(live_out); free(blk_use);
    free(blk_def); free(phi_edge); free(interf);
    free(arg_used_pre); free(var_to_dense); free(dense_to_var);

    /* 5c. Rewrite all HLE_VAR & dst_var to canonical vars, delete self-assignments (v = v) */
    for (int b = 0; b < nb; b++) {
        hl_blk *hb = &fn->blks[b];
        for (int si = 0; si < hb->nstmt; si++) {
            hl_stmt *s = &fn->stmts[hb->stmts[si]];
            if (s->dead) continue;
            if (s->dst_var >= 0) s->dst_var = hl_var_canon(fn, s->dst_var);
            hl_rewrite_expr_canon(fn, s->lhs_expr, 0);
            hl_rewrite_expr_canon(fn, s->rhs_expr, 0);
            hl_rewrite_expr_canon(fn, s->len_expr, 0);
            if (s->kind == HLS_ASSIGN && s->rhs_expr >= 0 &&
                fn->exprs[s->rhs_expr].kind == HLE_VAR &&
                fn->exprs[s->rhs_expr].var_id == s->dst_var) {
                s->dead = 1;
            }
        }
        hl_rewrite_expr_canon(fn, hb->cond_expr, 0);
        hl_rewrite_expr_canon(fn, hb->sw_expr,   0);
    }
}

static void hl_opt_recount_and_name(hl_fn *fn) {
    int nb = fn->nblk;
    if (fn->nvar <= 0 || nb <= 0) return;

    /* 5d. Recompute exact use_cnt / def_cnt / is_dead on canonical vars */
    for (int v = 0; v < fn->nvar; v++) {
        fn->vars[v].use_cnt = 0;
        fn->vars[v].def_cnt = 0;
        fn->vars[v].is_dead = 1;
    }
    for (int b = 0; b < nb; b++) {
        const hl_blk *hb = &fn->blks[b];
        for (int si = 0; si < hb->nstmt; si++) {
            const hl_stmt *s = &fn->stmts[hb->stmts[si]];
            if (s->dead) continue;
            if (s->kind == HLS_ASSIGN && s->dst_var >= 0 && s->dst_var < fn->nvar) {
                fn->vars[s->dst_var].def_cnt++;
                fn->vars[s->dst_var].is_dead = 0;
            }
            hl_recount_vars_expr(fn, s->lhs_expr, 0);
            hl_recount_vars_expr(fn, s->rhs_expr, 0);
            hl_recount_vars_expr(fn, s->len_expr, 0);
        }
        hl_recount_vars_expr(fn, hb->cond_expr, 0);
        hl_recount_vars_expr(fn, hb->sw_expr,   0);
    }

    /* 5e. Detect loop counter variables (i / j / k) */
    for (int b = 0; b < nb; b++) {
        const hl_blk *hb = &fn->blks[b];
        for (int si = 0; si < hb->nstmt; si++) {
            const hl_stmt *s = &fn->stmts[hb->stmts[si]];
            if (s->dead || s->kind != HLS_ASSIGN || s->dst_var < 0 || s->rhs_expr < 0) continue;
            int dv = s->dst_var;
            if (fn->vars[dv].is_arg || fn->vars[dv].is_stack || fn->vars[dv].is_flt) continue;
            const hl_expr *rhs = &fn->exprs[s->rhs_expr];
            if (rhs->kind == HLE_BINOP && (rhs->op == HLB_ADD || rhs->op == HLB_SUB) &&
                rhs->sub0 >= 0 && rhs->sub1 >= 0 &&
                fn->exprs[rhs->sub0].kind == HLE_VAR && fn->exprs[rhs->sub0].var_id == dv &&
                fn->exprs[rhs->sub1].kind == HLE_INT && fn->exprs[rhs->sub1].uval <= 8) {
                int tested_in_loop = 0;
                for (int lb = 0; lb < nb; lb++) {
                    if ((fn->blks[lb].is_loop_hdr || lb == b) && fn->blks[lb].cond_expr >= 0 &&
                        hl_expr_uses_var(fn, fn->blks[lb].cond_expr, dv, 0)) {
                        tested_in_loop = 1;
                        break;
                    }
                }
                if (tested_in_loop) fn->vars[dv].is_loop_idx = 1;
            }
        }
    }

    /* 5f. Assign clean compact names (a1..aN, var_XX, i/j/k, v1..vM) + apply user ana_lvar */
    int arg_list[32];
    int nlive_args = 0;
    for (int v = 0; v < fn->nvar; v++) {
        if (!fn->vars[v].is_dead && fn->vars[v].coal_to < 0 && fn->vars[v].is_arg) {
            if (nlive_args < 32) arg_list[nlive_args++] = v;
        }
    }
    for (int i = 0; i < nlive_args; i++) {
        for (int j = i + 1; j < nlive_args; j++) {
            const hl_var *va = &fn->vars[arg_list[i]];
            const hl_var *vb = &fn->vars[arg_list[j]];
            int swap = 0;
            if (va->is_stack != vb->is_stack) swap = va->is_stack > vb->is_stack;
            else if (va->is_stack) swap = va->stack_off > vb->stack_off;
            else swap = va->arg_idx > vb->arg_idx;
            if (swap) { int t = arg_list[i]; arg_list[i] = arg_list[j]; arg_list[j] = t; }
        }
    }
    for (int i = 0; i < nlive_args; i++) {
        hl_var *v = &fn->vars[arg_list[i]];
        v->arg_idx = i;
        snprintf(v->orig, sizeof(v->orig), "a%d", i + 1);
        snprintf(v->name, sizeof(v->name), "a%d", i + 1);
    }

    static const char *const loop_names[3] = {"i", "j", "k"};
    int loop_cnt = 0;
    int loc_cnt  = 0;

    for (int v = 0; v < fn->nvar; v++) {
        hl_var *hv = &fn->vars[v];
        if (hv->is_dead || hv->coal_to >= 0 || hv->is_arg) continue;
        if (hv->is_stack) {
            uint64_t aoff = (hv->stack_off < 0) ? hl_neg_u64((uint64_t)hv->stack_off) : (uint64_t)hv->stack_off;
            if (hv->stack_off < 0) {
                snprintf(hv->orig, sizeof(hv->orig), "var_%llx", (unsigned long long)aoff);
            } else {
                snprintf(hv->orig, sizeof(hv->orig), "stk_%llx", (unsigned long long)aoff);
            }
            snprintf(hv->name, sizeof(hv->name), "%s", hv->orig);
        } else if (hv->is_loop_idx && loop_cnt < 3) {
            snprintf(hv->orig, sizeof(hv->orig), "%s", loop_names[loop_cnt]);
            snprintf(hv->name, sizeof(hv->name), "%s", loop_names[loop_cnt]);
            loop_cnt++;
        } else {
            loc_cnt++;
            snprintf(hv->orig, sizeof(hv->orig), "v%d", loc_cnt);
            snprintf(hv->name, sizeof(hv->name), "v%d", loc_cnt);
        }
    }

    /* Apply user-saved local variable renames from ana_ctx if present */
    if (fn->a && fn->g && fn->a->lvars && fn->a->nlvar > 0) {
        uint64_t fva = fn->g->func_va;
        for (uint32_t li = 0; li < fn->a->nlvar; li++) {
            const ana_lvar *lv = &fn->a->lvars[li];
            if (lv->func_va != fva || !lv->orig[0] || !lv->name[0]) continue;
            for (int v = 0; v < fn->nvar; v++) {
                if (!fn->vars[v].is_dead && fn->vars[v].coal_to < 0 &&
                    strcmp(fn->vars[v].orig, lv->orig) == 0) {
                    snprintf(fn->vars[v].name, sizeof(fn->vars[v].name), "%s", lv->name);
                    break;
                }
            }
        }
    }
}

/* =========================================================================
 * Public Fixpoint Optimizer Entrypoint
 * ========================================================================= */

static int hl_is_zero_val(const hl_fn *fn, int eid) {
    if (eid < 0 || eid >= fn->nexpr) return 0;
    const hl_expr *e = &fn->exprs[eid];
    if (e->kind == HLE_INT && e->uval == 0) return 1;
    if (e->kind == HLE_FLT && e->fval == 0.0) return 1;
    return 0;
}

static int hl_extract_store_base_off(const hl_fn *fn, int lhs_eid, int *base_var, int64_t *off, int *width_bytes) {
    if (lhs_eid < 0 || lhs_eid >= fn->nexpr) return 0;
    const hl_expr *d = &fn->exprs[lhs_eid];
    if (d->kind != HLE_DEREF || d->sub0 < 0 || d->sub0 >= fn->nexpr) return 0;
    int wb = d->bits >= 128 ? 16 : (d->bits >= 64 ? 8 : (d->bits >= 32 ? 4 : 0));
    if (wb < 4) return 0;
    const hl_expr *a = &fn->exprs[d->sub0];
    if (a->kind == HLE_VAR && a->var_id >= 0) {
        *base_var = hl_var_canon(fn, a->var_id);
        *off = 0;
        *width_bytes = wb;
        return 1;
    }
    if (a->kind == HLE_BINOP && (a->op == HLB_ADD || a->op == HLB_SUB) &&
        a->sub0 >= 0 && a->sub1 >= 0 &&
        fn->exprs[a->sub0].kind == HLE_VAR && fn->exprs[a->sub1].kind == HLE_INT) {
        int64_t k = (int64_t)fn->exprs[a->sub1].uval;
        if (a->op == HLB_SUB) k = -k;
        *base_var = hl_var_canon(fn, fn->exprs[a->sub0].var_id);
        *off = k;
        *width_bytes = wb;
        return 1;
    }
    return 0;
}

static void hl_opt_coalesce_zero_stores(hl_fn *fn) {
    for (int b = 0; b < fn->nblk; b++) {
        hl_blk *hb = &fn->blks[b];
        int i = 0;
        while (i < hb->nstmt) {
            hl_stmt *s0 = &fn->stmts[hb->stmts[i]];
            int bv0 = -1, w0 = 0;
            int64_t off0 = 0;
            if (s0->dead || s0->kind != HLS_STORE || !hl_is_zero_val(fn, s0->rhs_expr) ||
                !hl_extract_store_base_off(fn, s0->lhs_expr, &bv0, &off0, &w0)) {
                i++;
                continue;
            }
            int stride = w0;
            int is_xmm0 = (s0->rhs_expr >= 0 && fn->exprs[s0->rhs_expr].kind == HLE_FLT);
            int run_cnt = 1;
            int run_idx[32];
            run_idx[0] = i;
            int j = i + 1;
            int64_t cur_end = off0 + stride;
            while (j < hb->nstmt && run_cnt < 32) {
                hl_stmt *sj = &fn->stmts[hb->stmts[j]];
                if (sj->dead || sj->kind == HLS_NOP) { j++; continue; }
                int bvj = -1, wj = 0;
                int64_t offj = 0;
                if (sj->kind == HLS_STORE && hl_is_zero_val(fn, sj->rhs_expr) &&
                    hl_extract_store_base_off(fn, sj->lhs_expr, &bvj, &offj, &wj) && bvj == bv0) {
                    int sj_is_xmm = (sj->rhs_expr >= 0 && fn->exprs[sj->rhs_expr].kind == HLE_FLT);
                    if (run_cnt == 1 && is_xmm0 && sj_is_xmm && offj - off0 == 16) {
                        stride = 16;
                        cur_end = off0 + 16;
                    }
                    if (offj == cur_end) {
                        cur_end += (stride == 16 && sj_is_xmm) ? 16 : wj;
                        run_idx[run_cnt++] = j;
                        j++;
                        continue;
                    }
                }
                break;
            }
            int64_t total = cur_end - off0;
            if ((stride == 16 && run_cnt >= 2) || (run_cnt >= 4 && total >= 32)) {
                int dst = hl_expr_var(fn, bv0);
                if (off0 != 0) {
                    int k = hl_expr_int(fn, (uint64_t)(off0 > 0 ? off0 : -off0), fn->ptr_bits, 0);
                    dst = hl_expr_binop(fn, off0 > 0 ? HLB_ADD : HLB_SUB, dst, k, fn->ptr_bits);
                }
                s0 = &fn->stmts[hb->stmts[run_idx[0]]];
                s0->kind = HLS_MEMSET;
                s0->lhs_expr = dst;
                s0->rhs_expr = hl_expr_int(fn, 0, 32, 0);
                s0->len_expr = hl_expr_int(fn, (uint64_t)total, fn->ptr_bits, 0);
                for (int r = 1; r < run_cnt; r++) fn->stmts[hb->stmts[run_idx[r]]].dead = 1;
                i = run_idx[run_cnt - 1] + 1;
            } else {
                i++;
            }
        }
    }
}

void hl_optimize(hl_fn *fn) {
    if (!fn || fn->nblk <= 0) return;

    for (int round = 0; round < 4; round++) {
        uint8_t *aliased = hl_compute_addr_aliased(fn);
        int chg = 0;
        chg |= hl_opt_copy_const_prop(fn, aliased);
        chg |= hl_opt_simplify_all(fn);
        chg |= hl_opt_fold_single_use(fn);
        chg |= hl_opt_simplify_all(fn);
        chg |= hl_opt_dce(fn, aliased);
        free(aliased);
        if (!chg) break;
    }

    hl_opt_coalesce(fn);
    hl_opt_coalesce_zero_stores(fn);

    /* Final cleanup pass after coalescing, BEFORE final recount & gap-free naming */
    uint8_t *aliased = hl_compute_addr_aliased(fn);
    hl_opt_simplify_all(fn);
    hl_opt_dce(fn, aliased);
    free(aliased);

    hl_opt_recount_and_name(fn);
}
