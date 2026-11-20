#include "ana.h"

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
    IR_OP_LABEL = 0,
    IR_OP_LOAD  = 1,
    IR_OP_STORE = 2,
    IR_OP_BINOP = 3,
    IR_OP_UNOP  = 4,
    IR_OP_LEA   = 5,
    IR_OP_CMP   = 6,
    IR_OP_JCC   = 7,
    IR_OP_JMP   = 8,
    IR_OP_CALL  = 9,
    IR_OP_RET   = 10,
    IR_OP_MISC  = 11
};

typedef struct {
    int      kind;
    int      reg;
    int      idx;
    int      scale;
    int      bits;
    int64_t  disp;
    uint64_t uval;
    int      is_rip;
} ir_opr;

typedef struct {
    char     expr[48];
    int      tid;
    uint8_t  is_const;
    uint64_t cval;
} ir_rval;

typedef struct {
    uint64_t va;
    uint8_t  op;
    uint8_t  pure;
    uint8_t  dead;
    int      def_tid;
    int      uses[6];
    int      nuse;
    char     text[128];
} ir_raw;

typedef struct {
    int off;
    int size;
} ir_frec;

typedef struct {
    int     reg;
    ir_frec recs[64];
    int     nrec;
} ir_strack;

static const char *const ir_rnames[16] = {
    "rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi",
    "r8","r9","r10","r11","r12","r13","r14","r15"
};

static const int ir_cand_regs[8] = {1, 2, 8, 9, 7, 6, 3, 5};

static void ir_trim(char *s) {
    char *p = s;
    while (*p == ' ' || *p == '\t') p++;
    if (p != s) memmove(s, p, strlen(p) + 1);
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\t')) s[--n] = 0;
}

static int ir_parse_reg(const char *s, int *bits, int *is_xmm) {
    *is_xmm = 0;
    *bits = 64;
    if ((s[0] == 'x' || s[0] == 'y' || s[0] == 'z') && s[1] == 'm' && s[2] == 'm' && isdigit((unsigned char)s[3])) {
        *is_xmm = 1;
        *bits = (s[0] == 'z') ? 512 : (s[0] == 'y') ? 256 : 128;
        return atoi(s + 3) & 31;
    }
    static const char *const r32[16] = {"eax","ecx","edx","ebx","esp","ebp","esi","edi","r8d","r9d","r10d","r11d","r12d","r13d","r14d","r15d"};
    static const char *const r16[16] = {"ax","cx","dx","bx","sp","bp","si","di","r8w","r9w","r10w","r11w","r12w","r13w","r14w","r15w"};
    static const char *const r8a[16] = {"al","cl","dl","bl","spl","bpl","sil","dil","r8b","r9b","r10b","r11b","r12b","r13b","r14b","r15b"};
    static const char *const r8h[4]  = {"ah","ch","dh","bh"};
    for (int i = 0; i < 16; i++) {
        if (strcmp(s, ir_rnames[i]) == 0) { *bits = 64; return i; }
        if (strcmp(s, r32[i]) == 0)       { *bits = 32; return i; }
        if (strcmp(s, r16[i]) == 0)       { *bits = 16; return i; }
        if (strcmp(s, r8a[i]) == 0)       { *bits = 8;  return i; }
    }
    for (int i = 0; i < 4; i++) {
        if (strcmp(s, r8h[i]) == 0) { *bits = 8; return i; }
    }
    return -1;
}

static int ir_split_ops(const char *ops, char a[76], char b[76], char c[76]) {
    a[0] = b[0] = c[0] = 0;
    if (!ops || !ops[0]) return 0;
    const char *p1 = strchr(ops, ',');
    if (!p1) {
        snprintf(a, 76, "%s", ops);
        ir_trim(a);
        return 1;
    }
    size_t n1 = (size_t)(p1 - ops);
    if (n1 >= 75) n1 = 75;
    memcpy(a, ops, n1); a[n1] = 0; ir_trim(a);

    const char *p2 = strchr(p1 + 1, ',');
    if (!p2) {
        snprintf(b, 76, "%s", p1 + 1);
        ir_trim(b);
        return 2;
    }
    size_t n2 = (size_t)(p2 - (p1 + 1));
    if (n2 >= 75) n2 = 75;
    memcpy(b, p1 + 1, n2); b[n2] = 0; ir_trim(b);
    snprintf(c, 76, "%s", p2 + 1); ir_trim(c);
    return 3;
}

static void ir_parse_op(const char *raw, const x86_ins *ins, ir_opr *op) {
    memset(op, 0, sizeof(*op));
    op->reg = -1;
    op->idx = -1;
    op->scale = 1;
    if (!raw || !raw[0]) return;

    char buf[80];
    snprintf(buf, sizeof(buf), "%s", raw);
    ir_trim(buf);

    const char *p = buf;
    if (strncmp(p, "byte ptr ", 9) == 0)        { op->bits = 8;   p += 9; }
    else if (strncmp(p, "word ptr ", 9) == 0)   { op->bits = 16;  p += 9; }
    else if (strncmp(p, "dword ptr ", 10) == 0) { op->bits = 32;  p += 10; }
    else if (strncmp(p, "qword ptr ", 10) == 0) { op->bits = 64;  p += 10; }
    else if (strncmp(p, "xmmword ptr ", 12) == 0) { op->bits = 128; p += 12; }
    else if (strncmp(p, "ymmword ptr ", 12) == 0) { op->bits = 256; p += 12; }

    if (p[0] && p[1] && p[2] == ':') p += 3;

    if (*p == '[') {
        op->kind = 3;
        char in[64];
        snprintf(in, sizeof(in), "%s", p + 1);
        char *rb = strchr(in, ']');
        if (rb) *rb = 0;

        if (strncmp(in, "0x", 2) == 0 && !strchr(in, '+') && !strchr(in, '-') && !strchr(in, '*')) {
            op->uval = strtoull(in + 2, NULL, 16);
            op->is_rip = ins->target_mem ? 1 : 0;
            return;
        }

        char *cur = in;
        int sign = 1;
        while (*cur) {
            if (*cur == '+') { sign = 1; cur++; continue; }
            if (*cur == '-') { sign = -1; cur++; continue; }
            char tok[32];
            int k = 0;
            while (*cur && *cur != '+' && *cur != '-' && k < 31) tok[k++] = *cur++;
            tok[k] = 0;
            char *star = strchr(tok, '*');
            if (star) {
                *star = 0;
                int b2, xm;
                int r = ir_parse_reg(tok, &b2, &xm);
                if (r >= 0 && !xm) {
                    op->idx = r;
                    op->scale = atoi(star + 1);
                }
            } else if (strncmp(tok, "0x", 2) == 0 || isdigit((unsigned char)tok[0])) {
                uint64_t v = (strncmp(tok, "0x", 2) == 0) ? strtoull(tok + 2, NULL, 16) : strtoull(tok, NULL, 10);
                op->disp += sign * (int64_t)v;
            } else {
                int b2, xm;
                int r = ir_parse_reg(tok, &b2, &xm);
                if (r >= 0 && !xm) {
                    if (op->reg < 0) op->reg = r;
                    else op->idx = r;
                }
            }
        }
        return;
    }

    if (strncmp(p, "0x", 2) == 0 || isdigit((unsigned char)p[0])) {
        op->kind = 2;
        op->uval = (strncmp(p, "0x", 2) == 0) ? strtoull(p + 2, NULL, 16) : strtoull(p, NULL, 10);
        return;
    }

    int rb, xm;
    int r = ir_parse_reg(p, &rb, &xm);
    if (r >= 0) {
        op->kind = xm ? 4 : 1;
        op->reg = r;
        op->bits = rb;
    }
}

static void ir_fmt_imm(uint64_t v, char *dst, size_t cap) {
    if (v < 16) snprintf(dst, cap, "%llu", (unsigned long long)v);
    else snprintf(dst, cap, "0x%llx", (unsigned long long)v);
}

static void ir_clean_sym(const char *sym, char *dst, size_t max) {
    const char *bang = strchr(sym, '!');
    const char *src = bang ? bang + 1 : sym;
    size_t k = 0;
    for (size_t i = 0; src[i] && k + 1 < max; i++) {
        char c = src[i];
        dst[k++] = (isalnum((unsigned char)c) || c == '_') ? c : '_';
    }
    dst[k] = 0;
    if (!dst[0]) snprintf(dst, max, "fn");
}

static uint64_t ir_mask(uint64_t v, int bits) {
    if (bits == 8) return v & 0xFFULL;
    if (bits == 16) return v & 0xFFFFULL;
    if (bits == 32) return v & 0xFFFFFFFFULL;
    return v;
}

static int ir_fold_binop(const char *m, uint64_t x, uint64_t y, int bits, uint64_t *out) {
    uint64_t r = 0;
    if (strcmp(m, "add") == 0) r = x + y;
    else if (strcmp(m, "sub") == 0) r = x - y;
    else if (strcmp(m, "xor") == 0) r = x ^ y;
    else if (strcmp(m, "and") == 0) r = x & y;
    else if (strcmp(m, "or") == 0)  r = x | y;
    else if (strcmp(m, "shl") == 0 || strcmp(m, "sal") == 0) r = x << (y & 63);
    else if (strcmp(m, "shr") == 0) r = x >> (y & 63);
    else if (strcmp(m, "sar") == 0) r = (uint64_t)((int64_t)x >> (y & 63));
    else if (strcmp(m, "imul") == 0) r = x * y;
    else return 0;
    *out = ir_mask(r, bits);
    return 1;
}

static int ir_fold_unop(const char *m, uint64_t x, int bits, uint64_t *out) {
    uint64_t r = 0;
    if (strcmp(m, "neg") == 0) r = (uint64_t)(-(int64_t)x);
    else if (strcmp(m, "not") == 0) r = ~x;
    else if (strcmp(m, "inc") == 0) r = x + 1;
    else if (strcmp(m, "dec") == 0) r = x - 1;
    else return 0;
    *out = ir_mask(r, bits);
    return 1;
}

static void ir_track_mem(ir_strack tr[8], const ir_opr *op, int fallback_bits) {
    if (op->kind != 3 || op->reg < 0 || op->disp < 0 || op->disp >= 0x10000) return;
    int slot = -1;
    for (int i = 0; i < 8; i++) {
        if (ir_cand_regs[i] == op->reg) { slot = i; break; }
    }
    if (slot < 0) return;

    int bits = op->bits ? op->bits : (fallback_bits ? fallback_bits : 64);
    int sz = bits / 8;
    if (sz != 1 && sz != 2 && sz != 4 && sz != 8 && sz != 16) sz = 8;
    int off = (int)op->disp;

    ir_strack *st = &tr[slot];
    for (int i = 0; i < st->nrec; i++) {
        if (st->recs[i].off == off && st->recs[i].size == sz) return;
    }
    if (st->nrec < 64) {
        st->recs[st->nrec].off = off;
        st->recs[st->nrec].size = sz;
        st->nrec++;
    }
}

static int ir_frec_cmp(const void *a, const void *b) {
    const ir_frec *x = (const ir_frec *)a;
    const ir_frec *y = (const ir_frec *)b;
    if (x->off != y->off) return (x->off > y->off) - (x->off < y->off);
    return (x->size > y->size) - (x->size < y->size);
}

static const char *ir_field_type(int sz) {
    if (sz == 1) return "uint8_t";
    if (sz == 2) return "uint16_t";
    if (sz == 4) return "uint32_t";
    if (sz == 16) return "__m128";
    return "uint64_t";
}

static void ir_finalize_structs(ir_strack tr[8], ir_func *out) {
    for (int i = 0; i < 8 && out->nstruct < 8; i++) {
        ir_strack *st = &tr[i];
        if (st->nrec < 2) continue;
        qsort(st->recs, (size_t)st->nrec, sizeof(ir_frec), ir_frec_cmp);

        int dist_pos = 0, prev_off = -1;
        for (int k = 0; k < st->nrec; k++) {
            if (st->recs[k].off != prev_off) {
                if (st->recs[k].off > 0) dist_pos++;
                prev_off = st->recs[k].off;
            }
        }
        int dist_all = 0;
        prev_off = -1;
        for (int k = 0; k < st->nrec; k++) {
            if (st->recs[k].off != prev_off) { dist_all++; prev_off = st->recs[k].off; }
        }
        if (dist_all < 2 || dist_pos < 1) continue;

        ir_struct *ds = &out->structs[out->nstruct++];
        memset(ds, 0, sizeof(*ds));
        ds->base_reg = st->reg;
        snprintf(ds->name, sizeof(ds->name), "struct_%s", ir_rnames[st->reg & 15]);
        for (int k = 0; k < st->nrec && ds->nfield < 32; k++) {
            ir_field *f = &ds->fields[ds->nfield++];
            f->off = st->recs[k].off;
            f->size = st->recs[k].size;
            snprintf(f->name, sizeof(f->name), "field_%x", f->off);
            snprintf(f->type, sizeof(f->type), "%s", ir_field_type(f->size));
        }
    }
}

static void ir_add_use(ir_raw *r, int tid) {
    if (tid <= 0 || r->nuse >= 6) return;
    for (int i = 0; i < r->nuse; i++) if (r->uses[i] == tid) return;
    r->uses[r->nuse++] = tid;
}

static void ir_fmt_addr(const ana_ctx *a, const ir_opr *op, const ir_rval rv[16], ir_raw *rec, char *dst, size_t cap) {
    if (op->uval && op->reg < 0 && op->idx < 0) {
        const char *sym = ana_sym_at(a, op->uval);
        if (sym) {
            char clean[48];
            ir_clean_sym(sym, clean, sizeof(clean));
            snprintf(dst, cap, "%s", clean);
        } else {
            snprintf(dst, cap, "0x%llx", (unsigned long long)op->uval);
        }
        return;
    }
    char buf[96] = "";
    size_t n = 0;
    if (op->reg >= 0) {
        n += (size_t)snprintf(buf + n, sizeof(buf) - n, "%s", rv[op->reg].expr);
        ir_add_use(rec, rv[op->reg].tid);
    }
    if (op->idx >= 0) {
        if (n) n += (size_t)snprintf(buf + n, sizeof(buf) - n, " + ");
        if (op->scale > 1) n += (size_t)snprintf(buf + n, sizeof(buf) - n, "%s*%d", rv[op->idx].expr, op->scale);
        else n += (size_t)snprintf(buf + n, sizeof(buf) - n, "%s", rv[op->idx].expr);
        ir_add_use(rec, rv[op->idx].tid);
    }
    if (op->disp != 0) {
        if (!n) snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)(uint64_t)op->disp);
        else if (op->disp < 0) snprintf(buf + n, sizeof(buf) - n, " - 0x%llx", (unsigned long long)(-op->disp));
        else snprintf(buf + n, sizeof(buf) - n, " + 0x%llx", (unsigned long long)op->disp);
    }
    if (!buf[0]) snprintf(buf, sizeof(buf), "0");
    snprintf(dst, cap, "%s", buf);
}

static void ir_set_const(ir_rval *r, uint64_t v) {
    r->is_const = 1;
    r->cval = v;
    r->tid = 0;
    ir_fmt_imm(v, r->expr, sizeof(r->expr));
}

static void ir_set_temp(ir_rval *r, int tid) {
    r->is_const = 0;
    r->cval = 0;
    r->tid = tid;
    snprintf(r->expr, sizeof(r->expr), "t%d", tid);
}

static void ir_init_regs(const ana_ctx *a, ir_rval rv[16], int arg_regs[6], int *narg) {
    int win64 = (a->bin.fmt == BIN_PE64 || a->bin.fmt == BIN_RAW);
    if (win64) {
        int r[4] = {1, 2, 8, 9};
        memcpy(arg_regs, r, sizeof(r));
        *narg = 4;
    } else {
        int r[6] = {7, 6, 2, 1, 8, 9};
        memcpy(arg_regs, r, sizeof(r));
        *narg = 6;
    }
    for (int i = 0; i < 16; i++) {
        rv[i].tid = 0;
        rv[i].is_const = 0;
        rv[i].cval = 0;
        snprintf(rv[i].expr, sizeof(rv[i].expr), "%s", ir_rnames[i]);
    }
    for (int i = 0; i < *narg; i++) {
        snprintf(rv[arg_regs[i]].expr, sizeof(rv[arg_regs[i]].expr), "a%d", i + 1);
    }
}

static void ir_dce_block(ir_raw *raw, int nraw, const ir_rval rv[16], int ends_ret, int max_tid, ir_func *out) {
    uint8_t *live = (uint8_t *)calloc((size_t)(max_tid + 2), 1);
    if (!live) return;

    if (ends_ret) {
        if (rv[0].tid > 0 && rv[0].tid <= max_tid) live[rv[0].tid] = 1;
    } else {
        // preserve live-out temps across blocks
        for (int r = 0; r < 16; r++) {
            if (rv[r].tid > 0 && rv[r].tid <= max_tid) live[rv[r].tid] = 1;
        }
    }

    for (int i = nraw - 1; i >= 0; i--) {
        ir_raw *op = &raw[i];
        if (!op->pure) {
            for (int u = 0; u < op->nuse; u++) {
                if (op->uses[u] > 0 && op->uses[u] <= max_tid) live[op->uses[u]] = 1;
            }
        } else if (op->def_tid > 0 && op->def_tid <= max_tid && live[op->def_tid]) {
            for (int u = 0; u < op->nuse; u++) {
                if (op->uses[u] > 0 && op->uses[u] <= max_tid) live[op->uses[u]] = 1;
            }
        } else if (op->pure && op->def_tid > 0) {
            op->dead = 1;
            out->ndce++;
        }
    }

    for (int i = 0; i < nraw && out->nop < 512; i++) {
        if (raw[i].dead) continue;
        ir_op *dst = &out->ops[out->nop++];
        dst->va = raw[i].va;
        dst->op = raw[i].op;
        snprintf(dst->text, sizeof(dst->text), "%s", raw[i].text);
    }
    free(live);
}

static void ir_lift_block(const ana_ctx *a, const grp_cfg *g, uint32_t bi, ir_strack tr[8], int *next_tid, ir_func *out) {
    const grp_blk *b = &g->blks[bi];
    int cap = (int)b->ins_count + 8;
    ir_raw *raw = (ir_raw *)calloc((size_t)cap, sizeof(ir_raw));
    if (!raw) return;
    int nraw = 0;

    ir_rval rv[16];
    int arg_regs[6], narg = 0;
    ir_init_regs(a, rv, arg_regs, &narg);
    int rax_set = 0, ends_ret = 0;

    if (g->nblk > 1 && nraw < cap) {
        raw[nraw].va = b->start;
        raw[nraw].op = IR_OP_LABEL;
        snprintf(raw[nraw].text, sizeof(raw[nraw].text), "loc_%llx:", (unsigned long long)b->start);
        nraw++;
    }

    for (uint32_t k = 0; k < b->ins_count && nraw < cap; k++) {
        const x86_ins *in = &g->ins[b->ins_first + k];
        const char *m = in->mnem;
        if (strcmp(m, "nop") == 0 || strcmp(m, "endbr64") == 0 || strcmp(m, "endbr32") == 0 ||
            strcmp(m, "int3") == 0 || (strcmp(m, "add") == 0 && strcmp(in->ops, "byte ptr [rax], al") == 0)) {
            continue;
        }

        char s0[76], s1[76], s2[76];
        int nops = ir_split_ops(in->ops, s0, s1, s2);
        ir_opr o0, o1, o2;
        ir_parse_op(s0, in, &o0);
        ir_parse_op(s1, in, &o1);
        ir_parse_op(s2, in, &o2);

        if (o0.kind == 3) ir_track_mem(tr, &o0, o1.kind == 1 ? o1.bits : 64);
        if (o1.kind == 3) ir_track_mem(tr, &o1, o0.kind == 1 ? o0.bits : 64);

        ir_raw *cur = &raw[nraw];
        memset(cur, 0, sizeof(*cur));
        cur->va = in->ip;

        if (in->flow == X86_FLOW_CALL) {
            char tgt[64];
            if (in->has_target) {
                const char *sym = ana_sym_at(a, in->target);
                if (sym) ir_clean_sym(sym, tgt, sizeof(tgt));
                else snprintf(tgt, sizeof(tgt), "sub_%llx", (unsigned long long)in->target);
            } else if (o0.kind == 1) {
                snprintf(tgt, sizeof(tgt), "%s", rv[o0.reg].expr);
                ir_add_use(cur, rv[o0.reg].tid);
            } else if (o0.kind == 3) {
                char addr[80];
                ir_fmt_addr(a, &o0, rv, cur, addr, sizeof(addr));
                snprintf(tgt, sizeof(tgt), "load64(%s)", addr);
            } else {
                snprintf(tgt, sizeof(tgt), "indirect");
            }
            for (int i = 0; i < narg; i++) ir_add_use(cur, rv[arg_regs[i]].tid);
            int tid = (*next_tid)++;
            cur->op = IR_OP_CALL;
            cur->def_tid = tid;
            snprintf(cur->text, sizeof(cur->text), "t%d = call(%s)", tid, tgt);
            ir_set_temp(&rv[0], tid);
            rax_set = 1;
            nraw++;
            continue;
        }

        if (in->flow == X86_FLOW_RET) {
            ends_ret = 1;
            cur->op = IR_OP_RET;
            if (rax_set || rv[0].tid > 0 || rv[0].is_const) {
                ir_add_use(cur, rv[0].tid);
                snprintf(cur->text, sizeof(cur->text), "ret(%s)", rv[0].expr);
            } else {
                snprintf(cur->text, sizeof(cur->text), "ret()");
            }
            nraw++;
            continue;
        }

        if (in->flow == X86_FLOW_JCC) {
            cur->op = IR_OP_JCC;
            const char *cc = (m[0] == 'j' && m[1]) ? (m + 1) : m;
            snprintf(cur->text, sizeof(cur->text), "jcc(cc.%s, 0x%llx)", cc, (unsigned long long)in->target);
            nraw++;
            continue;
        }

        if (in->flow == X86_FLOW_JMP) {
            cur->op = IR_OP_JMP;
            if (in->has_target && !in->target_mem) {
                snprintf(cur->text, sizeof(cur->text), "jmp(0x%llx)", (unsigned long long)in->target);
            } else if (o0.kind == 1) {
                ir_add_use(cur, rv[o0.reg].tid);
                snprintf(cur->text, sizeof(cur->text), "jmp(%s)", rv[o0.reg].expr);
            } else if (o0.kind == 3) {
                char addr[80];
                ir_fmt_addr(a, &o0, rv, cur, addr, sizeof(addr));
                snprintf(cur->text, sizeof(cur->text), "jmp(load64(%s))", addr);
            } else {
                snprintf(cur->text, sizeof(cur->text), "jmp(%s)", in->ops);
            }
            nraw++;
            continue;
        }

        if (strcmp(m, "cmp") == 0 || strcmp(m, "test") == 0) {
            char lhs[64] = "0", rhs[64] = "0";
            if (o0.kind == 1) {
                snprintf(lhs, sizeof(lhs), "%s", rv[o0.reg].expr);
                ir_add_use(cur, rv[o0.reg].tid);
            } else if (o0.kind == 3) {
                char addr[64];
                ir_fmt_addr(a, &o0, rv, cur, addr, sizeof(addr));
                int sz = o0.bits ? o0.bits : (o1.bits ? o1.bits : 64);
                snprintf(lhs, sizeof(lhs), "load%d(%s)", sz, addr);
            }
            if (o1.kind == 1) {
                snprintf(rhs, sizeof(rhs), "%s", rv[o1.reg].expr);
                ir_add_use(cur, rv[o1.reg].tid);
            } else if (o1.kind == 2) {
                ir_fmt_imm(o1.uval, rhs, sizeof(rhs));
            } else if (o1.kind == 3) {
                char addr[64];
                ir_fmt_addr(a, &o1, rv, cur, addr, sizeof(addr));
                int sz = o1.bits ? o1.bits : (o0.bits ? o0.bits : 64);
                snprintf(rhs, sizeof(rhs), "load%d(%s)", sz, addr);
            }
            cur->op = IR_OP_CMP;
            snprintf(cur->text, sizeof(cur->text), "cc = %s(%s, %s)", m, lhs, rhs);
            nraw++;
            continue;
        }

        if (strcmp(m, "xor") == 0 && o0.kind == 1 && o1.kind == 1 && o0.reg == o1.reg) {
            ir_set_const(&rv[o0.reg], 0);
            out->nconst++;
            if (o0.reg == 0) rax_set = 1;
            continue;
        }

        if (strcmp(m, "lea") == 0 && o0.kind == 1 && o1.kind == 3) {
            if (o1.uval && o1.reg < 0 && o1.idx < 0) {
                ir_set_const(&rv[o0.reg], o1.uval);
                const char *sym = ana_sym_at(a, o1.uval);
                if (sym) ir_clean_sym(sym, rv[o0.reg].expr, sizeof(rv[o0.reg].expr));
                if (o0.reg == 0) rax_set = 1;
                continue;
            }
            char addr[80];
            ir_fmt_addr(a, &o1, rv, cur, addr, sizeof(addr));
            int tid = (*next_tid)++;
            cur->op = IR_OP_LEA;
            cur->pure = 1;
            cur->def_tid = tid;
            snprintf(cur->text, sizeof(cur->text), "t%d = lea(%s)", tid, addr);
            ir_set_temp(&rv[o0.reg], tid);
            if (o0.reg == 0) rax_set = 1;
            nraw++;
            continue;
        }

        if (strcmp(m, "mov") == 0 || strcmp(m, "movabs") == 0 ||
            strcmp(m, "movzx") == 0 || strcmp(m, "movsx") == 0 || strcmp(m, "movsxd") == 0) {
            if (o0.kind == 1 && o1.kind == 2) {
                ir_set_const(&rv[o0.reg], ir_mask(o1.uval, o0.bits));
                if (o0.reg == 0) rax_set = 1;
                continue;
            }
            if (o0.kind == 1 && o1.kind == 1) {
                if (strcmp(m, "mov") == 0) {
                    if (rv[o1.reg].is_const) out->nconst++;
                    rv[o0.reg] = rv[o1.reg];
                    if (o0.reg == 0) rax_set = 1;
                    continue;
                }
                if (rv[o1.reg].is_const) {
                    uint64_t cv = ir_mask(rv[o1.reg].cval, o1.bits);
                    ir_set_const(&rv[o0.reg], cv);
                    out->nconst++;
                    if (o0.reg == 0) rax_set = 1;
                    continue;
                }
                ir_add_use(cur, rv[o1.reg].tid);
                int tid = (*next_tid)++;
                cur->op = IR_OP_UNOP;
                cur->pure = 1;
                cur->def_tid = tid;
                snprintf(cur->text, sizeof(cur->text), "t%d = %s(%s)",
                         tid, strcmp(m, "movzx") == 0 ? "zext" : "sext", rv[o1.reg].expr);
                ir_set_temp(&rv[o0.reg], tid);
                if (o0.reg == 0) rax_set = 1;
                nraw++;
                continue;
            }
            if (o0.kind == 1 && o1.kind == 3) {
                char addr[80];
                ir_fmt_addr(a, &o1, rv, cur, addr, sizeof(addr));
                int sz = o1.bits ? o1.bits : (o0.bits ? o0.bits : 64);
                int tid = (*next_tid)++;
                cur->op = IR_OP_LOAD;
                cur->pure = 1;
                cur->def_tid = tid;
                snprintf(cur->text, sizeof(cur->text), "t%d = load%d(%s)", tid, sz, addr);
                ir_set_temp(&rv[o0.reg], tid);
                if (o0.reg == 0) rax_set = 1;
                nraw++;
                continue;
            }
            if (o0.kind == 3) {
                char addr[80], rhs[48] = "0";
                ir_fmt_addr(a, &o0, rv, cur, addr, sizeof(addr));
                int sz = o0.bits ? o0.bits : (o1.bits ? o1.bits : 64);
                if (o1.kind == 1) {
                    snprintf(rhs, sizeof(rhs), "%s", rv[o1.reg].expr);
                    ir_add_use(cur, rv[o1.reg].tid);
                } else if (o1.kind == 2) {
                    ir_fmt_imm(o1.uval, rhs, sizeof(rhs));
                } else {
                    snprintf(rhs, sizeof(rhs), "%s", s1);
                }
                cur->op = IR_OP_STORE;
                snprintf(cur->text, sizeof(cur->text), "store%d(%s, %s)", sz, addr, rhs);
                nraw++;
                continue;
            }
        }

        if (strcmp(m, "add") == 0 || strcmp(m, "sub") == 0 || strcmp(m, "xor") == 0 ||
            strcmp(m, "and") == 0 || strcmp(m, "or") == 0 || strcmp(m, "shl") == 0 ||
            strcmp(m, "sal") == 0 || strcmp(m, "shr") == 0 || strcmp(m, "sar") == 0 ||
            strcmp(m, "imul") == 0) {
            if (o0.kind == 1) {
                int l_const = rv[o0.reg].is_const;
                uint64_t lv = rv[o0.reg].cval;
                int r_const = 0;
                uint64_t rval = 0;
                char rhs[64] = "";

                if (nops == 3 && strcmp(m, "imul") == 0 && o2.kind == 2) {
                    if (o1.kind == 1 && rv[o1.reg].is_const) {
                        uint64_t folded = ir_mask(rv[o1.reg].cval * o2.uval, o0.bits);
                        ir_set_const(&rv[o0.reg], folded);
                        out->nconst++;
                        if (o0.reg == 0) rax_set = 1;
                        continue;
                    }
                    char im[32];
                    ir_fmt_imm(o2.uval, im, sizeof(im));
                    if (o1.kind == 1) {
                        ir_add_use(cur, rv[o1.reg].tid);
                        snprintf(rhs, sizeof(rhs), "%s", rv[o1.reg].expr);
                    } else if (o1.kind == 3) {
                        char addr[64];
                        ir_fmt_addr(a, &o1, rv, cur, addr, sizeof(addr));
                        snprintf(rhs, sizeof(rhs), "load%d(%s)", o1.bits ? o1.bits : o0.bits, addr);
                    }
                    int tid = (*next_tid)++;
                    cur->op = IR_OP_BINOP;
                    cur->pure = 1;
                    cur->def_tid = tid;
                    snprintf(cur->text, sizeof(cur->text), "t%d = imul(%s, %s)", tid, rhs, im);
                    ir_set_temp(&rv[o0.reg], tid);
                    if (o0.reg == 0) rax_set = 1;
                    nraw++;
                    continue;
                }

                if (o1.kind == 2) {
                    r_const = 1; rval = o1.uval;
                    ir_fmt_imm(o1.uval, rhs, sizeof(rhs));
                } else if (o1.kind == 1) {
                    r_const = rv[o1.reg].is_const; rval = rv[o1.reg].cval;
                    snprintf(rhs, sizeof(rhs), "%s", rv[o1.reg].expr);
                } else if (o1.kind == 3) {
                    char addr[64];
                    ir_fmt_addr(a, &o1, rv, cur, addr, sizeof(addr));
                    snprintf(rhs, sizeof(rhs), "load%d(%s)", o1.bits ? o1.bits : o0.bits, addr);
                }

                if (l_const && r_const) {
                    uint64_t folded = 0;
                    if (ir_fold_binop(m, lv, rval, o0.bits, &folded)) {
                        ir_set_const(&rv[o0.reg], folded);
                        out->nconst++;
                        if (o0.reg == 0) rax_set = 1;
                        continue;
                    }
                }
                ir_add_use(cur, rv[o0.reg].tid);
                if (o1.kind == 1) ir_add_use(cur, rv[o1.reg].tid);
                int tid = (*next_tid)++;
                cur->op = IR_OP_BINOP;
                cur->pure = 1;
                cur->def_tid = tid;
                snprintf(cur->text, sizeof(cur->text), "t%d = %s(%s, %s)", tid, m, rv[o0.reg].expr, rhs);
                ir_set_temp(&rv[o0.reg], tid);
                if (o0.reg == 0) rax_set = 1;
                nraw++;
                continue;
            }
            if (o0.kind == 3) {
                char addr[64], rhs[48] = "0";
                ir_fmt_addr(a, &o0, rv, cur, addr, sizeof(addr));
                int sz = o0.bits ? o0.bits : (o1.bits ? o1.bits : 64);
                if (o1.kind == 1) {
                    snprintf(rhs, sizeof(rhs), "%s", rv[o1.reg].expr);
                    ir_add_use(cur, rv[o1.reg].tid);
                } else if (o1.kind == 2) {
                    ir_fmt_imm(o1.uval, rhs, sizeof(rhs));
                }
                cur->op = IR_OP_STORE;
                snprintf(cur->text, sizeof(cur->text), "store%d(%s, %s(load%d(%s), %s))", sz, addr, m, sz, addr, rhs);
                nraw++;
                continue;
            }
        }

        if ((strcmp(m, "neg") == 0 || strcmp(m, "not") == 0 ||
             strcmp(m, "inc") == 0 || strcmp(m, "dec") == 0) && o0.kind == 1) {
            if (rv[o0.reg].is_const) {
                uint64_t folded = 0;
                if (ir_fold_unop(m, rv[o0.reg].cval, o0.bits, &folded)) {
                    ir_set_const(&rv[o0.reg], folded);
                    out->nconst++;
                    if (o0.reg == 0) rax_set = 1;
                    continue;
                }
            }
            ir_add_use(cur, rv[o0.reg].tid);
            int tid = (*next_tid)++;
            cur->op = IR_OP_UNOP;
            cur->pure = 1;
            cur->def_tid = tid;
            if (strcmp(m, "inc") == 0) snprintf(cur->text, sizeof(cur->text), "t%d = add(%s, 1)", tid, rv[o0.reg].expr);
            else if (strcmp(m, "dec") == 0) snprintf(cur->text, sizeof(cur->text), "t%d = sub(%s, 1)", tid, rv[o0.reg].expr);
            else snprintf(cur->text, sizeof(cur->text), "t%d = %s(%s)", tid, m, rv[o0.reg].expr);
            ir_set_temp(&rv[o0.reg], tid);
            if (o0.reg == 0) rax_set = 1;
            nraw++;
            continue;
        }

        if (strncmp(m, "cmov", 4) == 0 && o0.kind == 1) {
            char rhs[64] = "";
            if (o1.kind == 1) {
                snprintf(rhs, sizeof(rhs), "%s", rv[o1.reg].expr);
                ir_add_use(cur, rv[o1.reg].tid);
            } else if (o1.kind == 3) {
                char addr[64];
                ir_fmt_addr(a, &o1, rv, cur, addr, sizeof(addr));
                snprintf(rhs, sizeof(rhs), "load%d(%s)", o1.bits ? o1.bits : o0.bits, addr);
            }
            ir_add_use(cur, rv[o0.reg].tid);
            int tid = (*next_tid)++;
            cur->op = IR_OP_BINOP;
            cur->pure = 1;
            cur->def_tid = tid;
            snprintf(cur->text, sizeof(cur->text), "t%d = select(cc.%s, %s, %s)", tid, m + 4, rhs, rv[o0.reg].expr);
            ir_set_temp(&rv[o0.reg], tid);
            if (o0.reg == 0) rax_set = 1;
            nraw++;
            continue;
        }

        if (strncmp(m, "set", 3) == 0 && o0.kind == 1) {
            int tid = (*next_tid)++;
            cur->op = IR_OP_UNOP;
            cur->pure = 1;
            cur->def_tid = tid;
            snprintf(cur->text, sizeof(cur->text), "t%d = setcc(cc.%s)", tid, m + 3);
            ir_set_temp(&rv[o0.reg], tid);
            if (o0.reg == 0) rax_set = 1;
            nraw++;
            continue;
        }

        if (strcmp(m, "push") == 0 || strcmp(m, "pop") == 0) continue;

        cur->op = IR_OP_MISC;
        if (in->ops[0]) snprintf(cur->text, sizeof(cur->text), "%s(%s)", m, in->ops);
        else snprintf(cur->text, sizeof(cur->text), "%s()", m);
        nraw++;
    }

    ir_dce_block(raw, nraw, rv, ends_ret, *next_tid, out);
    free(raw);
}

bool ir_lift_func(const ana_ctx *a, uint64_t va, ir_func *out) {
    if (!a || !out) return false;
    memset(out, 0, sizeof(*out));

    grp_cfg g = {0};
    if (!grp_build(a, va, 0, &g)) return false;
    out->func_va = g.func_va;

    ir_strack tr[8];
    memset(tr, 0, sizeof(tr));
    for (int i = 0; i < 8; i++) tr[i].reg = ir_cand_regs[i];

    int next_tid = 1;
    for (uint32_t i = 0; i < g.nblk; i++) {
        ir_lift_block(a, &g, i, tr, &next_tid, out);
    }

    ir_finalize_structs(tr, out);
    grp_free(&g);
    return out->nop > 0 || out->nstruct > 0;
}

static bool ir_is_code_ptr(const bin_img *b, uint64_t va) {
    if (va < b->min_va || va >= b->max_va) return false;
    if (!bin_is_exec(b, va)) return false;
    size_t av = 0;
    const uint8_t *p = bin_ptr(b, va, &av);
    if (!p || av < 1) return false;
    return p[0] != 0x00;
}

static bool ir_clean_rtti(const char *raw, char *dst, size_t max) {
    if (!raw || raw[0] != '.' || raw[1] != '?' || raw[2] != 'A' || !raw[3] || !raw[4]) return false;
    const char *p = raw + 4;
    const char *parts[8];
    size_t lens[8];
    int npart = 0;

    while (*p && npart < 8) {
        if (p[0] == '@' && p[1] == '@') break;
        const char *s = p;
        while (*p && *p != '@') {
            if ((unsigned char)*p < 0x20 || (unsigned char)*p > 0x7E) return false;
            p++;
        }
        if (p > s) {
            parts[npart] = s;
            lens[npart] = (size_t)(p - s);
            npart++;
        }
        if (*p == '@') p++;
    }
    if (npart == 0) return false;

    size_t n = 0;
    for (int i = npart - 1; i >= 0 && n + 1 < max; i--) {
        if (i < npart - 1) n += (size_t)snprintf(dst + n, max - n, "::");
        size_t cp = lens[i];
        if (n + cp >= max) cp = max - 1 - n;
        memcpy(dst + n, parts[i], cp);
        n += cp;
        dst[n] = 0;
    }
    return n > 0;
}

static bool ir_rtti_msvc(const ana_ctx *a, uint64_t vt_va, char *cls, size_t max) {
    int psz = (a->bin.bits == 32) ? 4 : 8;
    if (vt_va < (uint64_t)psz) return false;

    uint64_t col_va = 0;
    if (bin_read(&a->bin, vt_va - (uint64_t)psz, (uint8_t *)&col_va, (size_t)psz) != (size_t)psz) return false;
    if (col_va < a->bin.min_va || col_va >= a->bin.max_va) return false;

    uint32_t col[6] = {0};
    size_t col_sz = (psz == 8) ? 24 : 20;
    if (bin_read(&a->bin, col_va, (uint8_t *)col, col_sz) != col_sz) return false;

    uint64_t td_va = 0;
    uint64_t name_off = 0;
    if (psz == 8) {
        if (col[0] != 1) return false;
        uint64_t base = (col[5] && col_va >= col[5]) ? (col_va - col[5]) : a->bin.base;
        td_va = base + col[3];
        name_off = 16;
    } else {
        if (col[0] != 0) return false;
        td_va = col[3];
        name_off = 8;
    }

    char raw[96];
    memset(raw, 0, sizeof(raw));
    size_t got = bin_read(&a->bin, td_va + name_off, (uint8_t *)raw, sizeof(raw) - 1);
    if (got < 6) return false;
    return ir_clean_rtti(raw, cls, max);
}

static bool ir_rtti_itanium(const ana_ctx *a, uint64_t vt_va, char *cls, size_t max) {
    int psz = (a->bin.bits == 32) ? 4 : 8;
    if (vt_va < (uint64_t)psz) return false;

    uint64_t ti_va = 0;
    if (bin_read(&a->bin, vt_va - (uint64_t)psz, (uint8_t *)&ti_va, (size_t)psz) != (size_t)psz) return false;
    if (ti_va < a->bin.min_va || ti_va >= a->bin.max_va) return false;

    uint64_t nm_va = 0;
    if (bin_read(&a->bin, ti_va + (uint64_t)psz, (uint8_t *)&nm_va, (size_t)psz) != (size_t)psz) return false;
    char raw[96];
    memset(raw, 0, sizeof(raw));
    if (bin_read(&a->bin, nm_va, (uint8_t *)raw, sizeof(raw) - 1) < 2) return false;

    const char *p = raw;
    if (*p == 'N') p++;
    size_t n = 0;
    int seg = 0;
    while (isdigit((unsigned char)*p) && n + 1 < max) {
        int len = 0;
        while (isdigit((unsigned char)*p)) { len = len * 10 + (*p - '0'); p++; }
        if (len <= 0 || len > 80) break;
        if (seg++) n += (size_t)snprintf(cls + n, max - n, "::");
        for (int i = 0; i < len && *p && n + 1 < max; i++, p++) {
            if ((unsigned char)*p < 0x20 || (unsigned char)*p > 0x7E) return false;
            cls[n++] = *p;
        }
        cls[n] = 0;
    }
    return n > 0;
}

int ir_scan_vtables(const ana_ctx *a, ir_vtable *out, int max_out) {
    if (!a || !out || max_out <= 0) return 0;
    const bin_img *b = &a->bin;
    int psz = (b->bits == 32) ? 4 : 8;
    int found = 0;

    for (uint32_t si = 0; si < b->nsec && found < max_out; si++) {
        const bin_sec *s = &b->secs[si];
        if (!(s->perm & BIN_PERM_R) || (s->perm & BIN_PERM_X)) continue;
        int is_ro = !(s->perm & BIN_PERM_W) || strstr(s->name, "rdata") != NULL || strstr(s->name, "rodata") != NULL;
        if (!is_ro) continue;
        if (s->fsize == 0 || s->foff >= b->map.size) continue;

        uint64_t sz = s->fsize;
        if (s->foff + sz > b->map.size) sz = b->map.size - s->foff;
        const uint8_t *base_ptr = b->map.data + s->foff;

        uint64_t off = 0;
        while (off + (uint64_t)psz * 3 <= sz && found < max_out) {
            uint64_t ptr = 0;
            memcpy(&ptr, base_ptr + off, (size_t)psz);
            if (!ir_is_code_ptr(b, ptr)) {
                off += (uint64_t)psz;
                continue;
            }
            uint64_t start = off;
            uint32_t cnt = 0;
            while (off + (uint64_t)psz <= sz && cnt < 512) {
                ptr = 0;
                memcpy(&ptr, base_ptr + off, (size_t)psz);
                if (!ir_is_code_ptr(b, ptr)) break;
                cnt++;
                off += (uint64_t)psz;
            }
            if (cnt >= 3) {
                uint64_t vt_va = s->va + start;
                ir_vtable *vt = &out[found++];
                memset(vt, 0, sizeof(*vt));
                vt->va = vt_va;
                vt->nentry = cnt;
                if (!ir_rtti_msvc(a, vt_va, vt->cls, sizeof(vt->cls)) &&
                    !ir_rtti_itanium(a, vt_va, vt->cls, sizeof(vt->cls))) {
                    const char *sym = ana_sym_at(a, vt_va);
                    if (sym && sym[0]) snprintf(vt->cls, sizeof(vt->cls), "%s", sym);
                    else snprintf(vt->cls, sizeof(vt->cls), "vtable_%llx", (unsigned long long)vt_va);
                }
            }
        }
    }
    return found;
}

static bool ir_mnem_is(const char *mnem, const char *lit) {
    if (!mnem || !lit) return false;
    for (; *mnem && *lit; mnem++, lit++) {
        if (tolower((unsigned char)*mnem) != tolower((unsigned char)*lit)) return false;
    }
    return *mnem == 0 && *lit == 0;
}

static bool ir_is_ind_jmp(const x86_ins *in) {
    if (in->flow != X86_FLOW_JMP) return false;
    if (in->has_target && !in->target_mem) return false;
    if (in->has_target && in->target_mem) {
        // reject bare rip-relative import thunks
        const char *lb = strchr(in->ops, '[');
        if (lb && strncmp(lb + 1, "0x", 2) == 0 && !strchr(lb, '+') && !strchr(lb, '*')) return false;
    }
    return true;
}

static uint32_t ir_find_cmp_bound(const grp_cfg *g, uint32_t bi) {
    const grp_blk *b = &g->blks[bi];
    if (b->ins_count == 0) return 0;

    int add_one = 1;
    const x86_ins *last = &g->ins[b->ins_first + b->ins_count - 1];
    if (last->flow == X86_FLOW_JCC) {
        if (ir_mnem_is(last->mnem, "jae") || ir_mnem_is(last->mnem, "jge") ||
            ir_mnem_is(last->mnem, "jb")  || ir_mnem_is(last->mnem, "jl")) {
            add_one = 0;
        }
    }

    for (int k = (int)b->ins_count - 1; k >= 0; k--) {
        const x86_ins *in = &g->ins[b->ins_first + (uint32_t)k];
        if (!ir_mnem_is(in->mnem, "cmp")) continue;
        char s0[76], s1[76], s2[76];
        if (ir_split_ops(in->ops, s0, s1, s2) < 2) continue;
        ir_opr o1;
        ir_parse_op(s1, in, &o1);
        if (o1.kind == 2 && o1.uval >= 1 && o1.uval <= 1024) {
            return (uint32_t)o1.uval + (uint32_t)add_one;
        }
    }
    return 0;
}

uint32_t ir_read_switch_targets(const ana_ctx *a, const ir_switch *sw, uint64_t *tgts, uint32_t max_tgts) {
    if (!a || !sw || !tgts || max_tgts == 0 || sw->table_va == 0) return 0;
    uint32_t nc = (sw->ncases > 0) ? sw->ncases : max_tgts;
    if (nc > max_tgts) nc = max_tgts;
    if (nc < 2) return 0;

    int psz = (a->bin.bits == 32) ? 4 : 8;
    uint32_t valid = 0;

    // 1. Direct code pointer table (psz bytes per entry)
    for (uint32_t i = 0; i < nc; i++) {
        uint64_t ptr = 0;
        if (bin_read(&a->bin, sw->table_va + (uint64_t)i * (uint64_t)psz, (uint8_t *)&ptr, (size_t)psz) != (size_t)psz) break;
        if (!ir_is_code_ptr(&a->bin, ptr)) break;
        tgts[valid++] = ptr;
    }
    if (valid >= 2) return valid;

    // 2. MSVC x64 32-bit RVA table (ImageBase + rva)
    valid = 0;
    for (uint32_t i = 0; i < nc; i++) {
        uint32_t rva = 0;
        if (bin_read(&a->bin, sw->table_va + (uint64_t)i * 4ULL, (uint8_t *)&rva, 4) != 4) break;
        if (rva == 0 || (uint64_t)rva > UINT64_MAX - a->bin.base) break;
        uint64_t tgt = a->bin.base + (uint64_t)rva;
        if (!ir_is_code_ptr(&a->bin, tgt)) break;
        tgts[valid++] = tgt;
    }
    if (valid >= 2) return valid;

    // 3. Table-relative 32-bit signed offset table (GCC/Clang PIC: table_va + rel)
    valid = 0;
    for (uint32_t i = 0; i < nc; i++) {
        int32_t rel = 0;
        if (bin_read(&a->bin, sw->table_va + (uint64_t)i * 4ULL, (uint8_t *)&rel, 4) != 4) break;
        int64_t srel = (int64_t)rel;
        if (srel < 0 && (uint64_t)(-srel) > sw->table_va) break;
        if (srel > 0 && (uint64_t)srel > UINT64_MAX - sw->table_va) break;
        uint64_t tgt = sw->table_va + (uint64_t)srel;
        if (!ir_is_code_ptr(&a->bin, tgt)) break;
        tgts[valid++] = tgt;
    }
    return valid >= 2 ? valid : 0;
}

static bool ir_is_reg_volatile_call(const ana_ctx *a, int reg) {
    if (a->bin.bits == 32) return (reg == 0 || reg == 1 || reg == 2);
    if (a->bin.fmt == BIN_PE64) {
        return (reg == 0 || reg == 1 || reg == 2 || reg == 8 || reg == 9 || reg == 10 || reg == 11);
    }
    return (reg == 0 || reg == 1 || reg == 2 || reg == 6 || reg == 7 ||
            reg == 8 || reg == 9 || reg == 10 || reg == 11);
}

static bool ir_scan_blk_reg_const(const ana_ctx *a, const grp_cfg *g, uint32_t bi,
                                  int start_k, int target_reg, uint64_t *out_va,
                                  bool *clobbered, int *alias_reg) {
    const grp_blk *b = &g->blks[bi];
    *clobbered = false;
    *alias_reg = target_reg;
    if (start_k < 0 || b->ins_count == 0) return false;
    if ((uint32_t)start_k >= b->ins_count) start_k = (int)b->ins_count - 1;

    int cur_reg = target_reg;
    for (int k = start_k; k >= 0; k--) {
        const x86_ins *in = &g->ins[b->ins_first + (uint32_t)k];
        if (in->flow == X86_FLOW_CALL) {
            if (ir_is_reg_volatile_call(a, cur_reg)) {
                *clobbered = true;
                return false;
            }
            continue;
        }
        char s0[76], s1[76], s2[76];
        int nops = ir_split_ops(in->ops, s0, s1, s2);
        if (nops < 1) continue;
        ir_opr o0, o1;
        ir_parse_op(s0, in, &o0);
        ir_parse_op(s1, in, &o1);

        if (o0.kind != 1 || o0.reg != cur_reg) continue;

        if (ir_mnem_is(in->mnem, "lea") && nops >= 2) {
            uint64_t cand = 0;
            if (in->has_target) cand = in->target;
            else if (o1.kind == 3 && o1.reg < 0 && o1.idx < 0) cand = o1.uval ? o1.uval : (uint64_t)o1.disp;
            if (cand && (cand == a->bin.base || bin_sec_at(&a->bin, cand) != NULL)) {
                *out_va = cand;
                return true;
            }
            *clobbered = true;
            return false;
        }
        if ((ir_mnem_is(in->mnem, "mov") || ir_mnem_is(in->mnem, "movabs")) && nops >= 2) {
            if (o1.kind == 2) {
                uint64_t cand = o1.uval;
                if (cand && (cand == a->bin.base || bin_sec_at(&a->bin, cand) != NULL)) {
                    *out_va = cand;
                    return true;
                }
                *clobbered = true;
                return false;
            }
            if (o1.kind == 1) {
                cur_reg = o1.reg;
                continue;
            }
            *clobbered = true;
            return false;
        }
        if (!ir_mnem_is(in->mnem, "cmp") && !ir_mnem_is(in->mnem, "test")) {
            *clobbered = true;
            return false;
        }
    }
    *alias_reg = cur_reg;
    return false;
}

typedef struct {
    uint32_t blk;
    int      reg;
    int      dist;
} ir_bfs_item;

static bool ir_resolve_reg_const_bfs(const ana_ctx *a, const grp_cfg *g,
                                     const int *pred_head, const int *pred_to, const int *pred_next,
                                     uint32_t start_bi, int start_k, int target_reg, uint64_t *out_va) {
    bool clobbered = false;
    int cur_reg = target_reg;
    if (ir_scan_blk_reg_const(a, g, start_bi, start_k, target_reg, out_va, &clobbered, &cur_reg)) {
        return true;
    }
    if (clobbered || cur_reg < 0 || !pred_head || g->nblk == 0) return false;

    uint8_t *vis = (uint8_t *)calloc((size_t)g->nblk * 16U, 1);
    ir_bfs_item *q = (ir_bfs_item *)malloc((size_t)(g->nblk < 64 ? 64 : g->nblk) * 4U * sizeof(ir_bfs_item));
    if (!vis || !q) {
        free(vis);
        free(q);
        return false;
    }
    size_t qcap = (size_t)(g->nblk < 64 ? 64 : g->nblk) * 4U;
    size_t qh = 0, qt = 0;

    vis[(size_t)start_bi * 16U + (size_t)(cur_reg & 15)] = 1;
    for (int ei = pred_head[start_bi]; ei >= 0; ei = pred_next[ei]) {
        uint32_t p = (uint32_t)pred_to[ei];
        if (p < g->nblk && qt < qcap && !vis[(size_t)p * 16U + (size_t)(cur_reg & 15)]) {
            vis[(size_t)p * 16U + (size_t)(cur_reg & 15)] = 1;
            q[qt++] = (ir_bfs_item){ p, cur_reg, 1 };
        }
    }

    bool found = false;
    while (qh < qt) {
        ir_bfs_item it = q[qh++];
        int nxt_reg = it.reg;
        bool p_clob = false;
        const grp_blk *pb = &g->blks[it.blk];
        if (pb->ins_count > 0 &&
            ir_scan_blk_reg_const(a, g, it.blk, (int)pb->ins_count - 1, it.reg, out_va, &p_clob, &nxt_reg)) {
            found = true;
            break;
        }
        if (p_clob || nxt_reg < 0 || it.dist >= 64) continue;
        for (int ei = pred_head[it.blk]; ei >= 0; ei = pred_next[ei]) {
            uint32_t p = (uint32_t)pred_to[ei];
            if (p < g->nblk && qt < qcap && !vis[(size_t)p * 16U + (size_t)(nxt_reg & 15)]) {
                vis[(size_t)p * 16U + (size_t)(nxt_reg & 15)] = 1;
                q[qt++] = (ir_bfs_item){ p, nxt_reg, it.dist + 1 };
            }
        }
    }

    free(vis);
    free(q);
    return found;
}

static uint32_t ir_find_cmp_bound_bfs(const grp_cfg *g, const int *pred_head, const int *pred_to,
                                      const int *pred_next, uint32_t start_bi) {
    uint32_t bnd = ir_find_cmp_bound(g, start_bi);
    if (bnd >= 2) return bnd;
    if (!pred_head || g->nblk == 0) return 0;

    uint8_t *vis = (uint8_t *)calloc(g->nblk, 1);
    ir_bfs_item *q = (ir_bfs_item *)malloc(g->nblk * sizeof(ir_bfs_item));
    if (!vis || !q) {
        free(vis);
        free(q);
        return 0;
    }

    size_t qh = 0, qt = 0;
    vis[start_bi] = 1;
    q[qt++] = (ir_bfs_item){ start_bi, 0, 0 };

    while (qh < qt) {
        ir_bfs_item it = q[qh++];
        if (it.blk != start_bi) {
            bnd = ir_find_cmp_bound(g, it.blk);
            if (bnd >= 2) break;
        }
        if (it.dist >= 6) continue;
        for (int ei = pred_head[it.blk]; ei >= 0; ei = pred_next[ei]) {
            uint32_t p = (uint32_t)pred_to[ei];
            if (p < g->nblk && !vis[p]) {
                vis[p] = 1;
                q[qt++] = (ir_bfs_item){ p, 0, it.dist + 1 };
            }
        }
    }

    free(vis);
    free(q);
    return bnd;
}

int ir_scan_switches_cfg(const ana_ctx *a, const grp_cfg *g, ir_switch *out, int max_out) {
    if (!a || !g || !out || max_out <= 0 || g->nblk == 0) return 0;

    int *pred_head = (int *)malloc(g->nblk * sizeof(int));
    int *pred_to   = g->nedge ? (int *)malloc(g->nedge * sizeof(int)) : NULL;
    int *pred_next = g->nedge ? (int *)malloc(g->nedge * sizeof(int)) : NULL;
    uint64_t *tgts = (uint64_t *)malloc(512U * sizeof(uint64_t));
    if (!pred_head || (g->nedge && (!pred_to || !pred_next)) || !tgts) {
        free(pred_head);
        free(pred_to);
        free(pred_next);
        free(tgts);
        return 0;
    }
    for (uint32_t i = 0; i < g->nblk; i++) pred_head[i] = -1;
    for (uint32_t e = 0; e < g->nedge; e++) {
        uint32_t u = g->edges[e].from;
        uint32_t v = g->edges[e].to;
        if (u < g->nblk && v < g->nblk) {
            pred_to[e] = (int)u;
            pred_next[e] = pred_head[v];
            pred_head[v] = (int)e;
        }
    }

    int found = 0;
    for (uint32_t bi = 0; bi < g->nblk && found < max_out; bi++) {
        const grp_blk *b = &g->blks[bi];
        if (b->ins_count == 0) continue;
        const x86_ins *last = &g->ins[b->ins_first + b->ins_count - 1];
        if (!ir_is_ind_jmp(last)) continue;

        char js0[76], js1[76], js2[76];
        ir_split_ops(last->ops, js0, js1, js2);
        ir_opr jo0;
        ir_parse_op(js0, last, &jo0);

        uint64_t table_va = 0;
        uint64_t rva_disp = 0;
        int tbl_base_reg = -1;
        int add_base_reg = -1;
        int start_k = (int)b->ins_count - 2;

        if (jo0.kind == 3) {
            if (jo0.idx < 0) continue; // reject non-indexed indirect jmp (e.g., jmp qword ptr [rcx])
            if (jo0.reg < 0 && jo0.disp > 0 && bin_sec_at(&a->bin, (uint64_t)jo0.disp)) {
                table_va = (uint64_t)jo0.disp;
            } else {
                tbl_base_reg = jo0.reg;
                rva_disp = (uint64_t)jo0.disp;
            }
        } else if (jo0.kind == 1) {
            int cur_reg = jo0.reg;
            for (int k = (int)b->ins_count - 2; k >= 0; k--) {
                const x86_ins *in = &g->ins[b->ins_first + (uint32_t)k];
                if (in->flow == X86_FLOW_CALL) break;
                char s0[76], s1[76], s2[76];
                int nops = ir_split_ops(in->ops, s0, s1, s2);
                if (nops < 2) continue;
                ir_opr o0, o1;
                ir_parse_op(s0, in, &o0);
                ir_parse_op(s1, in, &o1);

                if (o0.kind != 1 || o0.reg != cur_reg) continue;
                if (ir_mnem_is(in->mnem, "add") && o1.kind == 1) {
                    if (add_base_reg < 0) add_base_reg = o1.reg;
                    continue;
                }
                if ((ir_mnem_is(in->mnem, "mov") || ir_mnem_is(in->mnem, "movsxd") ||
                     ir_mnem_is(in->mnem, "movzx")) && o1.kind == 3 && o1.idx >= 0) {
                    tbl_base_reg = o1.reg;
                    rva_disp = (uint64_t)o1.disp;
                    if (tbl_base_reg < 0 && o1.disp > 0 && bin_sec_at(&a->bin, (uint64_t)o1.disp)) {
                        table_va = (uint64_t)o1.disp;
                    }
                    start_k = k - 1;
                    break;
                }
                if (ir_mnem_is(in->mnem, "mov") && o1.kind == 1) {
                    cur_reg = o1.reg;
                    continue;
                }
                break;
            }
        } else {
            continue;
        }

        if (!table_va && tbl_base_reg >= 0) {
            uint64_t base_va = 0;
            if (ir_resolve_reg_const_bfs(a, g, pred_head, pred_to, pred_next, bi, start_k, tbl_base_reg, &base_va)) {
                if (rva_disp <= UINT64_MAX - base_va && bin_sec_at(&a->bin, base_va + rva_disp)) {
                    table_va = base_va + rva_disp;
                }
            }
        }
        if (!table_va && add_base_reg >= 0 && add_base_reg != tbl_base_reg) {
            uint64_t base_va = 0;
            if (ir_resolve_reg_const_bfs(a, g, pred_head, pred_to, pred_next, bi, start_k, add_base_reg, &base_va)) {
                if (rva_disp <= UINT64_MAX - base_va && bin_sec_at(&a->bin, base_va + rva_disp)) {
                    table_va = base_va + rva_disp;
                }
            }
        }
        if (!table_va && rva_disp > 0 && bin_sec_at(&a->bin, rva_disp)) {
            table_va = rva_disp;
        }
        if (!table_va) continue;

        uint32_t cmp_bound = ir_find_cmp_bound_bfs(g, pred_head, pred_to, pred_next, bi);
        ir_switch tmp = { last->ip, table_va, (cmp_bound >= 2) ? cmp_bound : 512U };
        uint32_t valid = ir_read_switch_targets(a, &tmp, tgts, 512U);
        if (valid < 2) continue;

        out[found].va = last->ip;
        out[found].table_va = table_va;
        out[found].ncases = valid;
        found++;
    }

    free(pred_head);
    free(pred_to);
    free(pred_next);
    free(tgts);
    return found;
}

int ir_scan_switches(const ana_ctx *a, uint64_t func_va, ir_switch *out, int max_out) {
    if (!a || !out || max_out <= 0) return 0;

    grp_cfg g = {0};
    if (!grp_build(a, func_va, 0, &g)) return 0;

    int found = ir_scan_switches_cfg(a, &g, out, max_out);
    grp_free(&g);
    return found;
}
