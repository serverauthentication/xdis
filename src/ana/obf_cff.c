#include "ana.h"

#include <ctype.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CFF_MAX_BLKS   2048
#define CFF_DOM_WORDS  32
#define CFF_MAX_STATES 512
#define MBA_MAX_NODES  256
#define MBA_MAX_EXPR   256
#define MBA_MAX_SLOTS  32

static const char *const cff_r64[16] = {
    "rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi",
    "r8","r9","r10","r11","r12","r13","r14","r15"
};

static void cff_trim(char *s) {
    char *p = s;
    while (*p == ' ' || *p == '\t') p++;
    if (p != s) memmove(s, p, strlen(p) + 1);
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\t')) s[--n] = 0;
}

static int cff_reg_id(const char *s, int *bits) {
    static const char *const r32[16] = {"eax","ecx","edx","ebx","esp","ebp","esi","edi","r8d","r9d","r10d","r11d","r12d","r13d","r14d","r15d"};
    static const char *const r16[16] = {"ax","cx","dx","bx","sp","bp","si","di","r8w","r9w","r10w","r11w","r12w","r13w","r14w","r15w"};
    static const char *const r8a[16] = {"al","cl","dl","bl","spl","bpl","sil","dil","r8b","r9b","r10b","r11b","r12b","r13b","r14b","r15b"};
    static const char *const r8h[4]  = {"ah","ch","dh","bh"};
    if (!s || !s[0]) return -1;
    for (int i = 0; i < 16; i++) {
        if (strcmp(s, cff_r64[i]) == 0) { if (bits) *bits = 64; return i; }
        if (strcmp(s, r32[i]) == 0)     { if (bits) *bits = 32; return i; }
        if (strcmp(s, r16[i]) == 0)     { if (bits) *bits = 16; return i; }
        if (strcmp(s, r8a[i]) == 0)     { if (bits) *bits = 8;  return i; }
    }
    for (int i = 0; i < 4; i++) {
        if (strcmp(s, r8h[i]) == 0) { if (bits) *bits = 8; return i; }
    }
    return -1;
}

static int cff_split_ops(const char *ops, char a[76], char b[76], char c[76]) {
    a[0] = b[0] = c[0] = 0;
    if (!ops || !ops[0]) return 0;
    const char *p1 = strchr(ops, ',');
    if (!p1) {
        snprintf(a, 76, "%s", ops);
        cff_trim(a);
        return 1;
    }
    size_t n1 = (size_t)(p1 - ops);
    if (n1 >= 75) n1 = 75;
    memcpy(a, ops, n1); a[n1] = 0; cff_trim(a);

    const char *p2 = strchr(p1 + 1, ',');
    if (!p2) {
        snprintf(b, 76, "%s", p1 + 1);
        cff_trim(b);
        return 2;
    }
    size_t n2 = (size_t)(p2 - (p1 + 1));
    if (n2 >= 75) n2 = 75;
    memcpy(b, p1 + 1, n2); b[n2] = 0; cff_trim(b);
    snprintf(c, 76, "%s", p2 + 1);
    cff_trim(c);
    return 3;
}

static bool cff_parse_imm(const char *s, uint64_t *val) {
    if (!s || !s[0]) return false;
    const char *p = s;
    int neg = 0;
    if (*p == '-') { neg = 1; p++; }
    else if (*p == '+') { p++; }
    if (!*p) return false;

    char *end = NULL;
    uint64_t v = 0;
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
        if (!isxdigit((unsigned char)p[2])) return false;
        v = strtoull(p + 2, &end, 16);
    } else if (isdigit((unsigned char)p[0])) {
        v = strtoull(p, &end, 10);
    } else {
        return false;
    }
    if (!end || *end != 0) return false;
    *val = neg ? ((uint64_t)0 - v) : v;
    return true;
}

static uint64_t cff_mask(uint64_t v, int bits) {
    if (bits == 8)  return v & 0xFFULL;
    if (bits == 16) return v & 0xFFFFULL;
    if (bits == 32) return v & 0xFFFFFFFFULL;
    return v;
}

typedef struct {
    int     kind;
    int     reg;
    int     bits;
    int64_t disp;
    char    name[32];
} cff_loc;

typedef struct {
    int     base;
    int     idx;
    int     scale;
    int     bits;
    int64_t disp;
    int     is_abs;
    uint8_t has_seg;
} cff_mem;

static const char *cff_strip_ptr(const char *p, int *bits) {
    *bits = 0;
    if (strncmp(p, "byte ptr ", 9) == 0)         { *bits = 8;  return p + 9; }
    if (strncmp(p, "word ptr ", 9) == 0)         { *bits = 16; return p + 9; }
    if (strncmp(p, "dword ptr ", 10) == 0)       { *bits = 32; return p + 10; }
    if (strncmp(p, "qword ptr ", 10) == 0)       { *bits = 64; return p + 10; }
    return p;
}

static bool cff_parse_mem(const char *raw, cff_mem *m) {
    memset(m, 0, sizeof(*m));
    m->base = -1;
    m->idx = -1;
    m->scale = 1;
    if (!raw || !raw[0]) return false;

    const char *p = cff_strip_ptr(raw, &m->bits);
    if (p[0] && p[1] && p[2] == ':') {
        m->has_seg = 1;
        p += 3;
    }
    if (*p != '[') return false;

    char in[64];
    snprintf(in, sizeof(in), "%s", p + 1);
    char *rb = strchr(in, ']');
    if (!rb) return false;
    *rb = 0;

    char *cur = in;
    int sign = 1;
    while (*cur) {
        if (*cur == ' ' || *cur == '\t') { cur++; continue; }
        if (*cur == '+') { sign = 1; cur++; continue; }
        if (*cur == '-') { sign = -1; cur++; continue; }
        char tok[32];
        int k = 0;
        while (*cur && *cur != '+' && *cur != '-' && k < 31) tok[k++] = *cur++;
        tok[k] = 0;
        cff_trim(tok);
        if (!tok[0]) continue;

        char *star = strchr(tok, '*');
        if (star) {
            *star = 0;
            cff_trim(tok);
            int rb2 = 64;
            int r = cff_reg_id(tok, &rb2);
            if (r < 0) return false;
            m->idx = r;
            m->scale = atoi(star + 1);
            if (m->scale <= 0) m->scale = 1;
            continue;
        }
        uint64_t uv = 0;
        if (cff_parse_imm(tok, &uv)) {
            int64_t dv = (sign < 0) ? (int64_t)((uint64_t)0 - uv) : (int64_t)uv;
            m->disp = (int64_t)((uint64_t)m->disp + (uint64_t)dv);
            continue;
        }
        int rb2 = 64;
        int r = cff_reg_id(tok, &rb2);
        if (r < 0) return false;
        if (m->base < 0) m->base = r;
        else if (m->idx < 0) m->idx = r;
        else return false;
    }

    if (m->base < 0 && m->idx < 0) m->is_abs = 1;
    return true;
}

static bool cff_parse_loc(const char *raw, cff_loc *loc) {
    memset(loc, 0, sizeof(*loc));
    loc->reg = -1;
    if (!raw || !raw[0]) return false;

    int bits = 0;
    int r = cff_reg_id(raw, &bits);
    if (r >= 0) {
        loc->kind = 1;
        loc->reg = r;
        loc->bits = bits;
        snprintf(loc->name, sizeof(loc->name), "%s", raw);
        return true;
    }

    cff_mem mem;
    if (!cff_parse_mem(raw, &mem)) return false;
    if ((mem.base == 4 || mem.base == 5) && mem.idx < 0) {
        loc->kind = 2;
        loc->reg = mem.base;
        loc->bits = mem.bits ? mem.bits : 32;
        loc->disp = mem.disp;
        const char *bn = (mem.base == 5) ? "rbp" : "rsp";
        if (mem.disp == 0) {
            snprintf(loc->name, sizeof(loc->name), "[%s]", bn);
        } else if (mem.disp < 0) {
            uint64_t mag = (uint64_t)0 - (uint64_t)mem.disp;
            snprintf(loc->name, sizeof(loc->name), "[%s-0x%llx]", bn, (unsigned long long)mag);
        } else {
            snprintf(loc->name, sizeof(loc->name), "[%s+0x%llx]", bn, (unsigned long long)mem.disp);
        }
        return true;
    }
    return false;
}

static bool cff_loc_eq(const cff_loc *a, const cff_loc *b) {
    if (a->kind == 0 || a->kind != b->kind) return false;
    if (a->reg != b->reg) return false;
    if (a->kind == 2 && a->disp != b->disp) return false;
    return true;
}

typedef struct {
    int      succ_t[CFF_MAX_BLKS];
    int      succ_f[CFF_MAX_BLKS];
    int      succ_u[CFF_MAX_BLKS];
    int      in_deg[CFF_MAX_BLKS];
    int      back_in[CFF_MAX_BLKS];
    uint64_t dom[CFF_MAX_BLKS][CFF_DOM_WORDS];
} cff_cfg_info;

static bool cff_dom_has(const uint64_t d[CFF_DOM_WORDS], uint32_t b) {
    return b < CFF_MAX_BLKS && ((d[b >> 6] >> (b & 63)) & 1ULL) != 0;
}

static void cff_build_info(const grp_cfg *g, cff_cfg_info *ci) {
    memset(ci, 0, sizeof(*ci));
    uint32_t n = g->nblk;
    if (n > CFF_MAX_BLKS) n = CFF_MAX_BLKS;

    for (uint32_t i = 0; i < n; i++) {
        ci->succ_t[i] = -1;
        ci->succ_f[i] = -1;
        ci->succ_u[i] = -1;
    }
    for (uint32_t e = 0; e < g->nedge; e++) {
        uint32_t u = g->edges[e].from;
        uint32_t v = g->edges[e].to;
        if (u >= n || v >= n) continue;
        ci->in_deg[v]++;
        if (g->edges[e].kind == GRP_EDGE_TRUE) ci->succ_t[u] = (int)v;
        else if (g->edges[e].kind == GRP_EDGE_FALSE) ci->succ_f[u] = (int)v;
        else ci->succ_u[u] = (int)v;
    }

    uint64_t all[CFF_DOM_WORDS];
    memset(all, 0, sizeof(all));
    for (uint32_t i = 0; i < n; i++) all[i >> 6] |= (1ULL << (i & 63));

    ci->dom[0][0] = 1ULL;
    for (uint32_t i = 1; i < n; i++) memcpy(ci->dom[i], all, sizeof(all));

    // iterative bitset dominators
    for (int iter = 0; iter < 64; iter++) {
        int changed = 0;
        for (uint32_t i = 1; i < n; i++) {
            uint64_t nd[CFF_DOM_WORDS];
            memcpy(nd, all, sizeof(nd));
            int has_pred = 0;
            for (uint32_t e = 0; e < g->nedge; e++) {
                if (g->edges[e].to != i || g->edges[e].from >= n) continue;
                uint32_t p = g->edges[e].from;
                for (int w = 0; w < CFF_DOM_WORDS; w++) nd[w] &= ci->dom[p][w];
                has_pred = 1;
            }
            if (!has_pred) memset(nd, 0, sizeof(nd));
            nd[i >> 6] |= (1ULL << (i & 63));
            if (memcmp(nd, ci->dom[i], sizeof(nd)) != 0) {
                memcpy(ci->dom[i], nd, sizeof(nd));
                changed = 1;
            }
        }
        if (!changed) break;
    }

    for (uint32_t e = 0; e < g->nedge; e++) {
        uint32_t u = g->edges[e].from;
        uint32_t v = g->edges[e].to;
        if (u < n && v < n && cff_dom_has(ci->dom[u], v)) {
            ci->back_in[v]++;
        }
    }
}

static int cff_blk_find_va(const grp_cfg *g, uint64_t va) {
    for (uint32_t i = 0; i < g->nblk; i++) {
        if (g->blks[i].start == va) return (int)i;
    }
    return -1;
}

typedef struct {
    uint64_t state_val;
    int      blk_idx;
    uint64_t target_va;
} cff_state;

typedef struct {
    int       disp_blk;
    cff_loc   state_loc;
    cff_loc   cmp_loc;
    uint8_t   is_backbone[CFF_MAX_BLKS];
    cff_state states[CFF_MAX_STATES];
    int       nstate;
    int       nback;
    int       nbackbone;
} cff_cand;

static void cff_cand_add_state(cff_cand *c, uint64_t val, int blk_idx, uint64_t va, int bits) {
    uint64_t mv = cff_mask(val, bits);
    for (int i = 0; i < c->nstate; i++) {
        if (cff_mask(c->states[i].state_val, bits) == mv) return;
    }
    if (c->nstate >= CFF_MAX_STATES) return;
    cff_state *st = &c->states[c->nstate++];
    st->state_val = mv;
    st->blk_idx = blk_idx;
    st->target_va = va;
}

static const cff_state *cff_cand_find_state(const cff_cand *c, uint64_t val, int bits) {
    uint64_t mv = cff_mask(val, bits);
    for (int i = 0; i < c->nstate; i++) {
        if (cff_mask(c->states[i].state_val, bits) == mv) return &c->states[i];
    }
    return NULL;
}

static int cff_jcc_kind(const char *m) {
    if (strcmp(m, "je") == 0 || strcmp(m, "jz") == 0) return 1;
    if (strcmp(m, "jne") == 0 || strcmp(m, "jnz") == 0) return 2;
    if (strcmp(m, "ja") == 0 || strcmp(m, "jae") == 0 ||
        strcmp(m, "jb") == 0 || strcmp(m, "jbe") == 0 ||
        strcmp(m, "jg") == 0 || strcmp(m, "jge") == 0 ||
        strcmp(m, "jl") == 0 || strcmp(m, "jle") == 0) return 3;
    return 0;
}

static uint32_t cff_real_ins_count(const grp_cfg *g, int bi) {
    const grp_blk *b = &g->blks[bi];
    uint32_t n = 0;
    for (uint32_t k = 0; k < b->ins_count; k++) {
        if (strcmp(g->ins[b->ins_first + k].mnem, "nop") != 0) n++;
    }
    return n;
}

static void cff_fixup_acc_alu(const ana_ctx *a, grp_cfg *g) {
    if (a->bin.arch == BIN_ARCH_ARM64) return;
    static const char *const alu_mnem[8] = {"add","or","adc","sbb","and","sub","xor","cmp"};

    for (uint32_t bi = 0; bi < g->nblk; bi++) {
        const grp_blk *b = &g->blks[bi];
        for (uint32_t k = 0; k < b->ins_count; k++) {
            x86_ins *in = &g->ins[b->ins_first + k];
            if (strcmp(in->mnem, "db") != 0) continue;

            size_t av = 0;
            const uint8_t *p = bin_ptr(&a->bin, in->ip, &av);
            if (!p || av < 2) continue;

            size_t pos = 0;
            int osz = 4;
            if (p[pos] == 0x66 && pos + 1 < av) { osz = 2; pos++; }
            if (a->bin.bits == 64 && (p[pos] & 0xF0) == 0x40 && pos + 1 < av) {
                if (p[pos] & 8) osz = 8;
                pos++;
            }
            if (pos >= av) continue;

            uint8_t op = p[pos++];
            // decode short-form al/ax/eax/rax ALU imm opcodes
            if ((op & 0xC6) != 0x04) continue;

            int alu = (op >> 3) & 7;
            int is_byte = ((op & 1) == 0);
            size_t imm_sz = is_byte ? 1 : (osz == 2 ? 2 : 4);
            if (pos + imm_sz > av) continue;

            uint64_t end_ip = in->ip + (uint64_t)(pos + imm_sz);
            if (end_ip > b->end) continue;

            int aligned = (end_ip == b->end);
            for (uint32_t j = k + 1; j < b->ins_count && !aligned; j++) {
                if (g->ins[b->ins_first + j].ip == end_ip) aligned = 1;
            }
            if (!aligned) continue;

            uint64_t imm = 0;
            if (imm_sz == 1) {
                imm = p[pos];
            } else if (imm_sz == 2) {
                uint16_t v = 0;
                memcpy(&v, p + pos, 2);
                imm = v;
            } else {
                uint32_t v = 0;
                memcpy(&v, p + pos, 4);
                imm = (osz == 8) ? (uint64_t)(int64_t)(int32_t)v : (uint64_t)v;
            }

            const char *rn = is_byte ? "al" : (osz == 2 ? "ax" : (osz == 8 ? "rax" : "eax"));
            snprintf(in->mnem, sizeof(in->mnem), "%s", alu_mnem[alu]);
            snprintf(in->ops, sizeof(in->ops), "%s, 0x%llx", rn, (unsigned long long)imm);
            in->len = (uint8_t)(pos + imm_sz);
            in->flow = X86_FLOW_NONE;

            for (uint32_t j = k + 1; j < b->ins_count; j++) {
                x86_ins *sk = &g->ins[b->ins_first + j];
                if (sk->ip >= end_ip) break;
                snprintf(sk->mnem, sizeof(sk->mnem), "nop");
                sk->ops[0] = 0;
                sk->flow = X86_FLOW_NONE;
            }
        }
    }
}

static bool cff_inspect_cmp_blk(const grp_cfg *g, const cff_cfg_info *ci, int bi,
                                const cff_loc *expect_st, const cff_loc *expect_cmp,
                                uint64_t delta_in, cff_loc *out_st, cff_loc *out_cmp,
                                uint64_t *out_imm, uint64_t *out_delta, int *out_kind) {
    const grp_blk *b = &g->blks[bi];
    uint32_t rn = cff_real_ins_count(g, bi);
    if (b->ins_count < 2 || rn < 2 || rn > 8) return false;
    if (ci->succ_t[bi] < 0 || ci->succ_f[bi] < 0) return false;

    const x86_ins *last = &g->ins[b->ins_first + b->ins_count - 1];
    if (last->flow != X86_FLOW_JCC) return false;
    int jk = cff_jcc_kind(last->mnem);
    if (!jk) return false;

    cff_loc reg_from[16];
    uint64_t reg_imm[16];
    uint8_t has_imm[16];
    memset(reg_from, 0, sizeof(reg_from));
    memset(reg_imm, 0, sizeof(reg_imm));
    memset(has_imm, 0, sizeof(has_imm));

    int found_cmp = 0;
    cff_loc cmp_lhs;
    memset(&cmp_lhs, 0, sizeof(cmp_lhs));
    uint64_t cmp_val = 0;
    uint64_t delta = delta_in;

    for (uint32_t k = 0; k + 1 < b->ins_count; k++) {
        const x86_ins *in = &g->ins[b->ins_first + k];
        const char *m = in->mnem;
        if (in->flow == X86_FLOW_CALL || in->flow == X86_FLOW_RET || in->flow == X86_FLOW_TRAP) return false;
        if (strcmp(m, "nop") == 0) continue;

        char s0[76], s1[76], s2[76];
        int nops = cff_split_ops(in->ops, s0, s1, s2);
        cff_loc l0 = {0}, l1 = {0};
        bool ok0 = (nops >= 1) && cff_parse_loc(s0, &l0);
        bool ok1 = (nops >= 2) && cff_parse_loc(s1, &l1);
        uint64_t imm = 0;
        bool imm1 = (nops >= 2) && cff_parse_imm(s1, &imm);

        if (strcmp(m, "mov") == 0 || strcmp(m, "movabs") == 0 ||
            strcmp(m, "movzx") == 0 || strcmp(m, "movsx") == 0 || strcmp(m, "movsxd") == 0) {
            if (!ok0 || l0.kind != 1) return false;
            if (imm1) {
                reg_imm[l0.reg] = cff_mask(imm, l0.bits);
                has_imm[l0.reg] = 1;
                memset(&reg_from[l0.reg], 0, sizeof(cff_loc));
            } else if (ok1) {
                has_imm[l0.reg] = 0;
                if (l1.kind == 2) reg_from[l0.reg] = l1;
                else if (l1.kind == 1 && reg_from[l1.reg].kind != 0) reg_from[l0.reg] = reg_from[l1.reg];
                else reg_from[l0.reg] = l1;
            } else {
                return false;
            }
            continue;
        }

        if (strcmp(m, "cmp") == 0 && ok0 && nops == 2) {
            uint64_t rv = 0;
            if (imm1) rv = imm;
            else if (ok1 && l1.kind == 1 && has_imm[l1.reg]) rv = reg_imm[l1.reg];
            else return false;
            cmp_lhs = l0;
            cmp_val = delta + rv;
            found_cmp = 1;
            continue;
        }

        if (strcmp(m, "test") == 0 && ok0 && ok1 && cff_loc_eq(&l0, &l1)) {
            cmp_lhs = l0;
            cmp_val = delta;
            found_cmp = 1;
            continue;
        }

        if (strcmp(m, "sub") == 0 && ok0 && imm1) {
            cmp_lhs = l0;
            delta += imm;
            cmp_val = delta;
            found_cmp = 1;
            continue;
        }

        if (strcmp(m, "dec") == 0 && ok0) {
            cmp_lhs = l0;
            delta += 1;
            cmp_val = delta;
            found_cmp = 1;
            continue;
        }

        return false;
    }

    if (!found_cmp || cmp_lhs.kind == 0) return false;

    cff_loc resolved_st = cmp_lhs;
    if (cmp_lhs.kind == 1 && reg_from[cmp_lhs.reg].kind == 2) {
        resolved_st = reg_from[cmp_lhs.reg];
    }

    if (expect_st && expect_st->kind != 0) {
        bool match = cff_loc_eq(&resolved_st, expect_st) ||
                     cff_loc_eq(&cmp_lhs, expect_st) ||
                     (expect_cmp && expect_cmp->kind != 0 && cff_loc_eq(&cmp_lhs, expect_cmp));
        if (!match && cmp_lhs.kind == 1 && reg_from[cmp_lhs.reg].kind != 0) {
            match = cff_loc_eq(&reg_from[cmp_lhs.reg], expect_st) ||
                    (expect_cmp && cff_loc_eq(&reg_from[cmp_lhs.reg], expect_cmp));
        }
        if (!match) return false;
        *out_st = *expect_st;
        *out_cmp = (cmp_lhs.kind == 1) ? cmp_lhs : *expect_cmp;
    } else {
        *out_st = resolved_st;
        *out_cmp = cmp_lhs;
    }

    *out_imm = cff_mask(cmp_val, out_st->bits);
    *out_delta = delta;
    *out_kind = jk;
    return true;
}

static bool cff_is_reload_hdr(const grp_cfg *g, const cff_cfg_info *ci, int bi,
                              cff_loc *out_st, cff_loc *out_cmp, int *next_blk) {
    const grp_blk *b = &g->blks[bi];
    uint32_t rn = cff_real_ins_count(g, bi);
    if (rn == 0 || rn > 3) return false;
    if (ci->succ_u[bi] < 0 || ci->succ_t[bi] >= 0 || ci->succ_f[bi] >= 0) return false;

    memset(out_st, 0, sizeof(*out_st));
    memset(out_cmp, 0, sizeof(*out_cmp));

    for (uint32_t k = 0; k < b->ins_count; k++) {
        const x86_ins *in = &g->ins[b->ins_first + k];
        if (in->flow == X86_FLOW_JMP) continue;
        if (strcmp(in->mnem, "nop") == 0) continue;
        if (strcmp(in->mnem, "mov") != 0 && strcmp(in->mnem, "movzx") != 0 && strcmp(in->mnem, "movsx") != 0) return false;
        char s0[76], s1[76], s2[76];
        if (cff_split_ops(in->ops, s0, s1, s2) != 2) return false;
        cff_loc l0 = {0}, l1 = {0};
        if (!cff_parse_loc(s0, &l0) || !cff_parse_loc(s1, &l1) || l0.kind != 1) return false;
        *out_cmp = l0;
        *out_st = l1;
    }
    *next_blk = ci->succ_u[bi];
    return true;
}

static bool cff_is_pure_jmp_to(const grp_cfg *g, const cff_cfg_info *ci, int bi, int target) {
    const grp_blk *b = &g->blks[bi];
    uint32_t rn = cff_real_ins_count(g, bi);
    if (rn == 0 || rn > 2) return false;
    if (ci->succ_u[bi] != target || ci->succ_t[bi] >= 0 || ci->succ_f[bi] >= 0) return false;
    for (uint32_t k = 0; k < b->ins_count; k++) {
        const x86_ins *in = &g->ins[b->ins_first + k];
        if (in->flow != X86_FLOW_JMP && strcmp(in->mnem, "nop") != 0) return false;
    }
    return true;
}

static bool cff_try_cascade(const grp_cfg *g, const cff_cfg_info *ci, int disp_blk, cff_cand *out) {
    if (disp_blk < 0 || disp_blk >= CFF_MAX_BLKS || (uint32_t)disp_blk >= g->nblk) return false;
    uint32_t nblk = (g->nblk < CFF_MAX_BLKS) ? g->nblk : CFF_MAX_BLKS;
    memset(out, 0, sizeof(*out));
    out->disp_blk = disp_blk;

    int start_blk = disp_blk;
    cff_loc init_st, init_cmp;
    memset(&init_st, 0, sizeof(init_st));
    memset(&init_cmp, 0, sizeof(init_cmp));

    cff_loc st_loc = {0}, cmp_loc = {0};
    uint64_t imm0 = 0, d0 = 0;
    int jk0 = 0;

    if (!cff_inspect_cmp_blk(g, ci, disp_blk, NULL, NULL, 0, &st_loc, &cmp_loc, &imm0, &d0, &jk0)) {
        int nb = -1;
        if (!cff_is_reload_hdr(g, ci, disp_blk, &init_st, &init_cmp, &nb) || nb < 0 || nb == disp_blk) return false;
        if (!cff_inspect_cmp_blk(g, ci, nb, init_st.kind ? &init_st : NULL,
                                 init_cmp.kind ? &init_cmp : NULL, 0,
                                 &st_loc, &cmp_loc, &imm0, &d0, &jk0)) {
            return false;
        }
        out->is_backbone[disp_blk] = 1;
        start_blk = nb;
    }

    out->state_loc = st_loc;
    out->cmp_loc = cmp_loc;

    int *q_blk = (int *)malloc(CFF_MAX_BLKS * sizeof(int));
    uint64_t *q_del = (uint64_t *)malloc(CFF_MAX_BLKS * sizeof(uint64_t));
    uint8_t *vis = (uint8_t *)calloc(CFF_MAX_BLKS, 1);
    if (!q_blk || !q_del || !vis) {
        free(q_blk);
        free(q_del);
        free(vis);
        return false;
    }
    int qh = 0, qt = 0;
    q_blk[qt] = start_blk;
    q_del[qt] = 0;
    qt++;

    while (qh < qt) {
        int bi = q_blk[qh];
        uint64_t del = q_del[qh];
        qh++;
        if (bi < 0 || (uint32_t)bi >= nblk || vis[bi]) continue;
        vis[bi] = 1;

        if (bi != disp_blk && !cff_dom_has(ci->dom[bi], (uint32_t)disp_blk)) continue;

        cff_loc cur_st = {0}, cur_cmp = {0};
        uint64_t imm = 0, ndel = 0;
        int jk = 0;
        if (!cff_inspect_cmp_blk(g, ci, bi, &out->state_loc, &out->cmp_loc, del,
                                 &cur_st, &cur_cmp, &imm, &ndel, &jk)) {
            continue;
        }
        out->is_backbone[bi] = 1;

        int t = ci->succ_t[bi];
        int f = ci->succ_f[bi];
        if (jk == 1) {
            if (t >= 0) cff_cand_add_state(out, imm, t, g->blks[t].start, out->state_loc.bits);
            if (f >= 0 && f != disp_blk && qt < CFF_MAX_BLKS) {
                q_blk[qt] = f; q_del[qt] = ndel; qt++;
            }
        } else if (jk == 2) {
            if (f >= 0) cff_cand_add_state(out, imm, f, g->blks[f].start, out->state_loc.bits);
            if (t >= 0 && t != disp_blk && qt < CFF_MAX_BLKS) {
                q_blk[qt] = t; q_del[qt] = ndel; qt++;
            }
        } else {
            if (t >= 0 && t != disp_blk && qt < CFF_MAX_BLKS) {
                q_blk[qt] = t; q_del[qt] = ndel; qt++;
            }
            if (f >= 0 && f != disp_blk && qt < CFF_MAX_BLKS) {
                q_blk[qt] = f; q_del[qt] = ndel; qt++;
            }
        }
    }
    free(q_blk);
    free(q_del);
    free(vis);

    // drop states that turned out to be backbone blocks
    int kept = 0;
    for (int i = 0; i < out->nstate; i++) {
        int b = out->states[i].blk_idx;
        if (b >= 0 && (uint32_t)b < nblk && out->is_backbone[b]) continue;
        out->states[kept++] = out->states[i];
    }
    out->nstate = kept;

    // include pure latch hubs jumping straight to disp_blk
    for (uint32_t i = 0; i < nblk; i++) {
        if (out->is_backbone[i] || ci->in_deg[i] < 2) continue;
        if (cff_is_pure_jmp_to(g, ci, (int)i, disp_blk)) {
            out->is_backbone[i] = 1;
        }
    }

    int nbb = 0;
    for (uint32_t i = 0; i < nblk; i++) {
        if (out->is_backbone[i]) nbb++;
    }
    out->nbackbone = nbb;

    int nback = ci->back_in[disp_blk];
    if (nback == 0) {
        // fallback: count edges from non-backbone blocks looping back to disp_blk
        for (uint32_t e = 0; e < g->nedge; e++) {
            uint32_t u = g->edges[e].from;
            uint32_t v = g->edges[e].to;
            if (v == (uint32_t)disp_blk && u < nblk && u > (uint32_t)disp_blk && !out->is_backbone[u]) {
                nback++;
            }
        }
    }
    out->nback = nback;

    return out->nstate >= 2 && out->nback >= 1;
}

static bool cff_find_switch_state(const grp_cfg *g, int bi, cff_loc *out_loc) {
    const grp_blk *b = &g->blks[bi];
    cff_loc reg_from[16];
    memset(reg_from, 0, sizeof(reg_from));

    for (uint32_t k = 0; k < b->ins_count; k++) {
        const x86_ins *in = &g->ins[b->ins_first + k];
        char s0[76], s1[76], s2[76];
        int nops = cff_split_ops(in->ops, s0, s1, s2);
        cff_loc l0 = {0}, l1 = {0};
        bool ok0 = (nops >= 1) && cff_parse_loc(s0, &l0);
        bool ok1 = (nops >= 2) && cff_parse_loc(s1, &l1);
        if ((strcmp(in->mnem, "mov") == 0 || strcmp(in->mnem, "movzx") == 0) && ok0 && ok1 && l0.kind == 1 && l1.kind == 2) {
            reg_from[l0.reg] = l1;
        }
        if (strcmp(in->mnem, "cmp") == 0 && ok0) {
            if (l0.kind == 1 && reg_from[l0.reg].kind == 2) *out_loc = reg_from[l0.reg];
            else *out_loc = l0;
            return true;
        }
    }
    return false;
}

static bool cff_try_switch(const ana_ctx *a, const grp_cfg *g, const cff_cfg_info *ci,
                           const ir_switch *sw, cff_cand *out) {
    if (!sw->table_va || sw->ncases < 2) return false;
    uint32_t nblk = (g->nblk < CFF_MAX_BLKS) ? g->nblk : CFF_MAX_BLKS;
    memset(out, 0, sizeof(*out));

    int sw_blk = -1;
    for (uint32_t i = 0; i < nblk; i++) {
        if (sw->va >= g->blks[i].start && sw->va < g->blks[i].end) {
            sw_blk = (int)i;
            break;
        }
    }
    if (sw_blk < 0) return false;

    int disp = sw_blk;
    if (ci->back_in[disp] == 0) {
        for (uint32_t e = 0; e < g->nedge; e++) {
            if (g->edges[e].to == (uint32_t)sw_blk && g->edges[e].from < nblk && ci->back_in[g->edges[e].from] >= 1) {
                disp = (int)g->edges[e].from;
                break;
            }
        }
    }
    if (ci->back_in[disp] == 0) return false;

    out->disp_blk = disp;
    out->is_backbone[disp] = 1;
    out->is_backbone[sw_blk] = 1;
    out->nback = ci->back_in[disp];

    if (!cff_find_switch_state(g, disp, &out->state_loc) &&
        !cff_find_switch_state(g, sw_blk, &out->state_loc)) {
        out->state_loc.kind = 1;
        out->state_loc.reg = 0;
        out->state_loc.bits = 32;
        snprintf(out->state_loc.name, sizeof(out->state_loc.name), "eax");
    }
    out->cmp_loc = out->state_loc;

    uint32_t lim = sw->ncases;
    if (lim > CFF_MAX_STATES) lim = CFF_MAX_STATES;

    int psz = (a->bin.bits == 32) ? 4 : 8;
    int mode = 0;
    for (int try_mode = 1; try_mode <= 3 && !mode; try_mode++) {
        int good = 0;
        for (uint32_t i = 0; i < lim && i < 4; i++) {
            uint64_t tgt = 0;
            if (try_mode == 1) {
                if (bin_read(&a->bin, sw->table_va + (uint64_t)i * (uint64_t)psz, (uint8_t *)&tgt, (size_t)psz) != (size_t)psz) break;
            } else if (try_mode == 2) {
                uint32_t rva = 0;
                if (bin_read(&a->bin, sw->table_va + (uint64_t)i * 4, (uint8_t *)&rva, 4) != 4) break;
                if (rva == 0U || (uint64_t)rva > UINT64_MAX - a->bin.base) break;
                tgt = a->bin.base + (uint64_t)rva;
            } else {
                int32_t rel = 0;
                if (bin_read(&a->bin, sw->table_va + (uint64_t)i * 4, (uint8_t *)&rel, 4) != 4) break;
                int64_t srel = (int64_t)rel;
                if (srel < 0 && (uint64_t)(-srel) > sw->table_va) break;
                if (srel > 0 && (uint64_t)srel > UINT64_MAX - sw->table_va) break;
                tgt = sw->table_va + (uint64_t)srel;
            }
            if (bin_is_exec(&a->bin, tgt)) good++;
        }
        if (good >= 2) mode = try_mode;
    }
    if (!mode) return false;

    for (uint32_t i = 0; i < lim; i++) {
        uint64_t tgt = 0;
        if (mode == 1) {
            if (bin_read(&a->bin, sw->table_va + (uint64_t)i * (uint64_t)psz, (uint8_t *)&tgt, (size_t)psz) != (size_t)psz) break;
        } else if (mode == 2) {
            uint32_t rva = 0;
            if (bin_read(&a->bin, sw->table_va + (uint64_t)i * 4, (uint8_t *)&rva, 4) != 4) break;
            if (rva == 0U || (uint64_t)rva > UINT64_MAX - a->bin.base) break;
            tgt = a->bin.base + (uint64_t)rva;
        } else {
            int32_t rel = 0;
            if (bin_read(&a->bin, sw->table_va + (uint64_t)i * 4, (uint8_t *)&rel, 4) != 4) break;
            int64_t srel = (int64_t)rel;
            if (srel < 0 && (uint64_t)(-srel) > sw->table_va) break;
            if (srel > 0 && (uint64_t)srel > UINT64_MAX - sw->table_va) break;
            tgt = sw->table_va + (uint64_t)srel;
        }
        if (!bin_is_exec(&a->bin, tgt)) break;
        int tb = cff_blk_find_va(g, tgt);
        cff_cand_add_state(out, (uint64_t)i, tb, tgt, out->state_loc.bits);
    }

    int nbb = 0;
    for (uint32_t i = 0; i < nblk; i++) if (out->is_backbone[i]) nbb++;
    out->nbackbone = nbb;
    return out->nstate >= 2;
}

typedef struct {
    uint8_t  known;
    uint64_t val;
    uint64_t alt_val;
} cff_val;

typedef struct {
    cff_val reg[16];
    cff_val slot;
    uint8_t written;
} cff_sim;

static cff_val *cff_sim_slot_ptr(cff_sim *sim, const cff_loc *st_loc, const cff_loc *loc) {
    if (loc->kind == 1) return &sim->reg[loc->reg];
    if (loc->kind == 2 && cff_loc_eq(loc, st_loc)) return &sim->slot;
    return NULL;
}

static bool cff_alu_apply(const char *m, uint64_t a, uint64_t b, int bits, uint64_t *res) {
    uint64_t r = 0;
    if (strcmp(m, "add") == 0) r = a + b;
    else if (strcmp(m, "sub") == 0) r = a - b;
    else if (strcmp(m, "xor") == 0) r = a ^ b;
    else if (strcmp(m, "and") == 0) r = a & b;
    else if (strcmp(m, "or") == 0)  r = a | b;
    else if (strcmp(m, "shl") == 0 || strcmp(m, "sal") == 0) r = a << (b & 63);
    else if (strcmp(m, "shr") == 0) r = a >> (b & 63);
    else if (strcmp(m, "imul") == 0) r = a * b;
    else return false;
    *res = cff_mask(r, bits);
    return true;
}

static void cff_eval_blk(const grp_cfg *g, int bi, const cff_loc *st_loc, cff_sim *sim) {
    const grp_blk *b = &g->blks[bi];
    for (uint32_t k = 0; k < b->ins_count; k++) {
        const x86_ins *in = &g->ins[b->ins_first + k];
        const char *m = in->mnem;
        if (in->flow == X86_FLOW_CALL) {
            static const int vol[7] = {0, 1, 2, 8, 9, 10, 11};
            for (int v = 0; v < 7; v++) sim->reg[vol[v]].known = 0;
            continue;
        }
        if (in->flow == X86_FLOW_JMP || in->flow == X86_FLOW_JCC ||
            in->flow == X86_FLOW_RET || in->flow == X86_FLOW_TRAP) {
            continue;
        }
        if (strcmp(m, "cmp") == 0 || strcmp(m, "test") == 0 ||
            strcmp(m, "push") == 0 || strcmp(m, "nop") == 0) {
            continue;
        }

        char s0[76], s1[76], s2[76];
        int nops = cff_split_ops(in->ops, s0, s1, s2);
        cff_loc l0 = {0}, l1 = {0};
        bool ok0 = (nops >= 1) && cff_parse_loc(s0, &l0);
        bool ok1 = (nops >= 2) && cff_parse_loc(s1, &l1);
        uint64_t imm = 0;
        bool imm1 = (nops >= 2) && cff_parse_imm(s1, &imm);

        cff_val *dst = ok0 ? cff_sim_slot_ptr(sim, st_loc, &l0) : NULL;
        if (!dst) continue;
        int is_st = cff_loc_eq(&l0, st_loc);

        if ((strcmp(m, "xor") == 0 || strcmp(m, "sub") == 0) && ok1 && cff_loc_eq(&l0, &l1)) {
            dst->known = 1;
            dst->val = 0;
            if (is_st) sim->written = 1;
            continue;
        }

        if (strcmp(m, "mov") == 0 || strcmp(m, "movabs") == 0 ||
            strcmp(m, "movzx") == 0 || strcmp(m, "movsx") == 0 || strcmp(m, "movsxd") == 0) {
            if (imm1) {
                dst->known = 1;
                dst->val = cff_mask(imm, l0.bits);
            } else if (ok1) {
                cff_val *src = cff_sim_slot_ptr(sim, st_loc, &l1);
                if (src && src->known) {
                    dst->known = src->known;
                    dst->val = cff_mask(src->val, l0.bits);
                    dst->alt_val = cff_mask(src->alt_val, l0.bits);
                } else {
                    dst->known = 0;
                }
            } else {
                dst->known = 0;
            }
            if (is_st) sim->written = 1;
            continue;
        }

        if (strncmp(m, "cmov", 4) == 0 && l0.kind == 1) {
            uint64_t rv = 0;
            int rok = 0;
            if (imm1) { rv = cff_mask(imm, l0.bits); rok = 1; }
            else if (ok1) {
                cff_val *src = cff_sim_slot_ptr(sim, st_loc, &l1);
                if (src && src->known == 1) { rv = cff_mask(src->val, l0.bits); rok = 1; }
            }
            if (dst->known == 1 && rok) {
                dst->known = 2;
                dst->alt_val = rv;
            } else {
                dst->known = 0;
            }
            if (is_st) sim->written = 1;
            continue;
        }

        if (strcmp(m, "lea") == 0 && l0.kind == 1) {
            cff_mem mem;
            if (in->has_target) {
                dst->known = 1;
                dst->val = cff_mask(in->target, l0.bits);
            } else if (cff_parse_mem(s1, &mem)) {
                uint64_t acc = (uint64_t)mem.disp;
                int ok = 1;
                if (mem.base >= 0) {
                    if (sim->reg[mem.base].known == 1) acc += sim->reg[mem.base].val;
                    else ok = 0;
                }
                if (mem.idx >= 0) {
                    if (sim->reg[mem.idx].known == 1) acc += sim->reg[mem.idx].val * (uint64_t)mem.scale;
                    else ok = 0;
                }
                if (ok) { dst->known = 1; dst->val = cff_mask(acc, l0.bits); }
                else dst->known = 0;
            } else {
                dst->known = 0;
            }
            if (is_st) sim->written = 1;
            continue;
        }

        if (strcmp(m, "not") == 0 || strcmp(m, "neg") == 0 ||
            strcmp(m, "inc") == 0 || strcmp(m, "dec") == 0) {
            if (dst->known) {
                for (int pass = 0; pass < dst->known; pass++) {
                    uint64_t *pv = (pass == 0) ? &dst->val : &dst->alt_val;
                    if (strcmp(m, "not") == 0) *pv = cff_mask(~(*pv), l0.bits);
                    else if (strcmp(m, "neg") == 0) *pv = cff_mask((uint64_t)0 - (*pv), l0.bits);
                    else if (strcmp(m, "inc") == 0) *pv = cff_mask((*pv) + 1, l0.bits);
                    else *pv = cff_mask((*pv) - 1, l0.bits);
                }
            }
            if (is_st) sim->written = 1;
            continue;
        }

        if (nops >= 2 && (strcmp(m, "add") == 0 || strcmp(m, "sub") == 0 ||
            strcmp(m, "xor") == 0 || strcmp(m, "and") == 0 || strcmp(m, "or") == 0 ||
            strcmp(m, "shl") == 0 || strcmp(m, "sal") == 0 || strcmp(m, "shr") == 0 ||
            strcmp(m, "imul") == 0)) {
            uint64_t rv = 0;
            int rok = 0;
            if (imm1) { rv = imm; rok = 1; }
            else if (ok1) {
                cff_val *src = cff_sim_slot_ptr(sim, st_loc, &l1);
                if (src && src->known == 1) { rv = src->val; rok = 1; }
            }
            if (dst->known && rok) {
                uint64_t r0 = 0, r1 = 0;
                if (cff_alu_apply(m, dst->val, rv, l0.bits, &r0)) {
                    dst->val = r0;
                    if (dst->known == 2 && cff_alu_apply(m, dst->alt_val, rv, l0.bits, &r1)) {
                        dst->alt_val = r1;
                    }
                } else {
                    dst->known = 0;
                }
            } else {
                dst->known = 0;
            }
            if (is_st) sim->written = 1;
            continue;
        }

        dst->known = 0;
        if (is_st) sim->written = 1;
    }
}

static bool cff_flows_to_backbone(const cff_cfg_info *ci, const uint8_t is_bb[CFF_MAX_BLKS], int bi) {
    if (bi < 0 || bi >= CFF_MAX_BLKS) return false;
    int u = ci->succ_u[bi];
    if (u < 0 || ci->succ_t[bi] >= 0 || ci->succ_f[bi] >= 0) return false;
    if (is_bb[u]) return true;
    int u2 = ci->succ_u[u];
    return u2 >= 0 && ci->succ_t[u] < 0 && ci->succ_f[u] < 0 && is_bb[u2];
}

static bool cff_resolve_branch_side(const grp_cfg *g, const cff_cfg_info *ci, const cff_cand *cand,
                                    int bi, const cff_sim *in_sim, uint64_t *out_st, int *is_stub) {
    *is_stub = 0;
    if (bi < 0 || bi >= CFF_MAX_BLKS || (uint32_t)bi >= g->nblk) return false;

    if (cand->is_backbone[bi]) {
        const cff_val *v = (cand->state_loc.kind == 1) ? &in_sim->reg[cand->state_loc.reg] : &in_sim->slot;
        if (v->known == 1 && cff_cand_find_state(cand, v->val, cand->state_loc.bits)) {
            *out_st = cff_mask(v->val, cand->state_loc.bits);
            return true;
        }
        return false;
    }

    const grp_blk *b = &g->blks[bi];
    if (cff_real_ins_count(g, bi) > 6 || !cff_flows_to_backbone(ci, cand->is_backbone, bi)) return false;
    for (uint32_t k = 0; k < b->ins_count; k++) {
        uint8_t fl = g->ins[b->ins_first + k].flow;
        if (fl == X86_FLOW_CALL || fl == X86_FLOW_RET || fl == X86_FLOW_TRAP) return false;
    }

    cff_sim s = *in_sim;
    s.written = 0;
    cff_eval_blk(g, bi, &cand->state_loc, &s);
    const cff_val *v = (cand->state_loc.kind == 1) ? &s.reg[cand->state_loc.reg] : &s.slot;
    if (v->known == 1 && cff_cand_find_state(cand, v->val, cand->state_loc.bits)) {
        *out_st = cff_mask(v->val, cand->state_loc.bits);
        *is_stub = 1;
        return true;
    }
    return false;
}

static void cff_add_edge(cff_res *out, uint64_t from_va, uint64_t to_va, uint64_t state_val, uint8_t kind) {
    if (out->nedge >= 256) return;
    for (int i = 0; i < out->nedge; i++) {
        if (out->edges[i].from_va == from_va &&
            out->edges[i].to_va == to_va &&
            out->edges[i].kind == kind) {
            return;
        }
    }
    cff_edge *e = &out->edges[out->nedge++];
    e->from_va = from_va;
    e->to_va = to_va;
    e->state_val = state_val;
    e->kind = kind;
}

static bool cff_is_state_target(const cff_cand *cand, int bi) {
    for (int i = 0; i < cand->nstate; i++) {
        if (cand->states[i].blk_idx == bi) return true;
    }
    return false;
}

static void cff_extract_edges(const grp_cfg *g, const cff_cfg_info *ci, const cff_cand *cand, cff_res *out) {
    uint8_t skip_stub[CFF_MAX_BLKS];
    memset(skip_stub, 0, sizeof(skip_stub));
    uint32_t nblk = (g->nblk < CFF_MAX_BLKS) ? g->nblk : CFF_MAX_BLKS;

    for (uint32_t bi = 0; bi < nblk; bi++) {
        if (cand->is_backbone[bi] || skip_stub[bi]) continue;

        cff_sim sim;
        memset(&sim, 0, sizeof(sim));

        // seed incoming state if block belongs to a unique state
        int hits = 0;
        uint64_t in_st = 0;
        for (int s = 0; s < cand->nstate; s++) {
            if (cand->states[s].blk_idx == (int)bi) {
                in_st = cand->states[s].state_val;
                hits++;
            }
        }
        if (hits == 1) {
            if (cand->state_loc.kind == 1) {
                sim.reg[cand->state_loc.reg].known = 1;
                sim.reg[cand->state_loc.reg].val = in_st;
            } else if (cand->state_loc.kind == 2) {
                sim.slot.known = 1;
                sim.slot.val = in_st;
            }
        }

        cff_eval_blk(g, (int)bi, &cand->state_loc, &sim);
        uint64_t from_va = g->blks[bi].start;

        if (cff_flows_to_backbone(ci, cand->is_backbone, (int)bi)) {
            const cff_val *v = (cand->state_loc.kind == 1) ? &sim.reg[cand->state_loc.reg] : &sim.slot;
            if (!sim.written) continue;
            if (v->known == 1) {
                const cff_state *st = cff_cand_find_state(cand, v->val, cand->state_loc.bits);
                if (st) cff_add_edge(out, from_va, st->target_va, st->state_val, GRP_EDGE_UNCOND);
            } else if (v->known == 2) {
                const cff_state *st_t = cff_cand_find_state(cand, v->alt_val, cand->state_loc.bits);
                const cff_state *st_f = cff_cand_find_state(cand, v->val, cand->state_loc.bits);
                if (st_t) cff_add_edge(out, from_va, st_t->target_va, st_t->state_val, GRP_EDGE_TRUE);
                if (st_f) cff_add_edge(out, from_va, st_f->target_va, st_f->state_val, GRP_EDGE_FALSE);
            }
            continue;
        }

        if (ci->succ_t[bi] >= 0 && ci->succ_f[bi] >= 0) {
            uint64_t st_t = 0, st_f = 0;
            int stub_t = 0, stub_f = 0;
            bool ok_t = cff_resolve_branch_side(g, ci, cand, ci->succ_t[bi], &sim, &st_t, &stub_t);
            bool ok_f = cff_resolve_branch_side(g, ci, cand, ci->succ_f[bi], &sim, &st_f, &stub_f);
            if (ok_t && ok_f) {
                const cff_state *mt = cff_cand_find_state(cand, st_t, cand->state_loc.bits);
                const cff_state *mf = cff_cand_find_state(cand, st_f, cand->state_loc.bits);
                if (mt) cff_add_edge(out, from_va, mt->target_va, mt->state_val, GRP_EDGE_TRUE);
                if (mf) cff_add_edge(out, from_va, mf->target_va, mf->state_val, GRP_EDGE_FALSE);
                if (stub_t && ci->in_deg[ci->succ_t[bi]] == 1 && !cff_is_state_target(cand, ci->succ_t[bi])) {
                    skip_stub[ci->succ_t[bi]] = 1;
                }
                if (stub_f && ci->in_deg[ci->succ_f[bi]] == 1 && !cff_is_state_target(cand, ci->succ_f[bi])) {
                    skip_stub[ci->succ_f[bi]] = 1;
                }
            }
        }
    }
}

bool cff_analyze(const ana_ctx *a, uint64_t va, cff_res *out) {
    if (!a || !out) return false;
    memset(out, 0, sizeof(*out));

    grp_cfg g = {0};
    if (!grp_build(a, va, 0, &g)) return false;
    cff_fixup_acc_alu(a, &g);

    out->func_va = g.func_va;
    out->orig_blks = (int)g.nblk;
    out->real_blks = (int)g.nblk;

    if (g.nblk < 3) {
        grp_free(&g);
        return true;
    }

    cff_cfg_info *ci = (cff_cfg_info *)calloc(1, sizeof(cff_cfg_info));
    cff_cand *best = (cff_cand *)calloc(1, sizeof(cff_cand));
    cff_cand *cur = (cff_cand *)calloc(1, sizeof(cff_cand));
    if (!ci || !best || !cur) {
        free(ci); free(best); free(cur);
        grp_free(&g);
        return false;
    }

    cff_build_info(&g, ci);

    uint32_t nblk = (g.nblk < CFF_MAX_BLKS) ? g.nblk : CFF_MAX_BLKS;
    int have_best = 0;
    for (uint32_t i = 0; i < nblk; i++) {
        if (ci->back_in[i] == 0 && ci->in_deg[i] < 2) continue;
        if (!cff_try_cascade(&g, ci, (int)i, cur)) continue;
        if (!have_best || cur->nstate > best->nstate ||
            (cur->nstate == best->nstate && cur->nback > best->nback)) {
            *best = *cur;
            have_best = 1;
        }
    }

    ir_switch sws[32];
    int nsw = ir_scan_switches_cfg(a, &g, sws, 32);
    for (int i = 0; i < nsw; i++) {
        if (!cff_try_switch(a, &g, ci, &sws[i], cur)) continue;
        if (!have_best || cur->nstate > best->nstate ||
            (cur->nstate == best->nstate && cur->nback > best->nback)) {
            *best = *cur;
            have_best = 1;
        }
    }

    if (have_best) {
        out->detected = 1;
        out->disp_va = g.blks[best->disp_blk].start;
        snprintf(out->state_var, sizeof(out->state_var), "%s", best->state_loc.name);
        out->backbone_cut = best->nbackbone;
        out->real_blks = out->orig_blks - out->backbone_cut;
        if (out->real_blks < 0) out->real_blks = 0;
        cff_extract_edges(&g, ci, best, out);
    }

    free(ci);
    free(best);
    free(cur);
    grp_free(&g);
    return true;
}

typedef enum {
    MBA_NUM = 0,
    MBA_VAR,
    MBA_NEG,
    MBA_NOT,
    MBA_ADD,
    MBA_SUB,
    MBA_MUL,
    MBA_SHL,
    MBA_SHR,
    MBA_AND,
    MBA_XOR,
    MBA_OR
} mba_op;

typedef struct {
    uint8_t  op;
    int      a;
    int      b;
    uint64_t val;
} mba_node;

typedef struct {
    mba_node nodes[MBA_MAX_NODES];
    int      nnodes;
    int      root;
    char     vars[4][32];
    int      nvar;
    int      nops;
} mba_ast;

typedef struct {
    const char    *p;
    const mba_ast *var_ref;
    mba_ast       *ast;
    int            err;
    int            depth;
} mba_parser;

static void mba_skip_ws(mba_parser *ps) {
    while (*ps->p == ' ' || *ps->p == '\t' || *ps->p == '\r' || *ps->p == '\n') ps->p++;
}

static int mba_add_node(mba_parser *ps, uint8_t op, int a, int b, uint64_t val) {
    if (ps->err || ps->ast->nnodes >= MBA_MAX_NODES) {
        ps->err = 1;
        return -1;
    }
    int id = ps->ast->nnodes++;
    ps->ast->nodes[id].op = op;
    ps->ast->nodes[id].a = a;
    ps->ast->nodes[id].b = b;
    ps->ast->nodes[id].val = val;
    if (op != MBA_NUM && op != MBA_VAR) ps->ast->nops++;
    return id;
}

static int mba_var_idx(mba_parser *ps, const char *name) {
    if (ps->var_ref) {
        for (int i = 0; i < ps->var_ref->nvar; i++) {
            if (strcmp(ps->var_ref->vars[i], name) == 0) return i;
        }
        ps->err = 1;
        return -1;
    }
    for (int i = 0; i < ps->ast->nvar; i++) {
        if (strcmp(ps->ast->vars[i], name) == 0) return i;
    }
    if (ps->ast->nvar >= 4) {
        ps->err = 1;
        return -1;
    }
    int idx = ps->ast->nvar++;
    snprintf(ps->ast->vars[idx], sizeof(ps->ast->vars[idx]), "%s", name);
    return idx;
}

static int mba_parse_or(mba_parser *ps);

static int mba_parse_primary(mba_parser *ps) {
    mba_skip_ws(ps);
    if (ps->err || ps->depth > 64) { ps->err = 1; return -1; }

    if (*ps->p == '(') {
        ps->p++;
        ps->depth++;
        int inner = mba_parse_or(ps);
        ps->depth--;
        mba_skip_ws(ps);
        if (*ps->p != ')') { ps->err = 1; return -1; }
        ps->p++;
        return inner;
    }

    if (isdigit((unsigned char)*ps->p)) {
        const char *st = ps->p;
        char *end = NULL;
        uint64_t v = 0;
        if (st[0] == '0' && (st[1] == 'x' || st[1] == 'X')) {
            if (!isxdigit((unsigned char)st[2])) { ps->err = 1; return -1; }
            v = strtoull(st + 2, &end, 16);
        } else {
            v = strtoull(st, &end, 10);
        }
        if (!end || end == st) { ps->err = 1; return -1; }
        ps->p = end;
        return mba_add_node(ps, MBA_NUM, -1, -1, v);
    }

    if (isalpha((unsigned char)*ps->p) || *ps->p == '_') {
        char name[32];
        int k = 0;
        while ((isalnum((unsigned char)*ps->p) || *ps->p == '_') && k < 31) {
            name[k++] = *ps->p++;
        }
        if (isalnum((unsigned char)*ps->p) || *ps->p == '_') {
            ps->err = 1;
            return -1;
        }
        name[k] = 0;
        int vi = mba_var_idx(ps, name);
        if (vi < 0) return -1;
        return mba_add_node(ps, MBA_VAR, vi, -1, 0);
    }

    ps->err = 1;
    return -1;
}

static int mba_parse_unary(mba_parser *ps) {
    mba_skip_ws(ps);
    if (ps->err || ps->depth > 64) { ps->err = 1; return -1; }
    if (*ps->p == '~') {
        ps->p++;
        ps->depth++;
        int c = mba_parse_unary(ps);
        ps->depth--;
        return mba_add_node(ps, MBA_NOT, c, -1, 0);
    }
    if (*ps->p == '-') {
        ps->p++;
        ps->depth++;
        int c = mba_parse_unary(ps);
        ps->depth--;
        return mba_add_node(ps, MBA_NEG, c, -1, 0);
    }
    if (*ps->p == '+') {
        ps->p++;
        ps->depth++;
        int c = mba_parse_unary(ps);
        ps->depth--;
        return c;
    }
    return mba_parse_primary(ps);
}

static int mba_parse_mul(mba_parser *ps) {
    int lhs = mba_parse_unary(ps);
    while (!ps->err) {
        mba_skip_ws(ps);
        if (*ps->p != '*') break;
        ps->p++;
        int rhs = mba_parse_unary(ps);
        lhs = mba_add_node(ps, MBA_MUL, lhs, rhs, 0);
    }
    return lhs;
}

static int mba_parse_add(mba_parser *ps) {
    int lhs = mba_parse_mul(ps);
    while (!ps->err) {
        mba_skip_ws(ps);
        uint8_t op = 0;
        if (*ps->p == '+') op = MBA_ADD;
        else if (*ps->p == '-') op = MBA_SUB;
        else break;
        ps->p++;
        int rhs = mba_parse_mul(ps);
        lhs = mba_add_node(ps, op, lhs, rhs, 0);
    }
    return lhs;
}

static int mba_parse_shift(mba_parser *ps) {
    int lhs = mba_parse_add(ps);
    while (!ps->err) {
        mba_skip_ws(ps);
        uint8_t op = 0;
        if (ps->p[0] == '<' && ps->p[1] == '<') op = MBA_SHL;
        else if (ps->p[0] == '>' && ps->p[1] == '>') op = MBA_SHR;
        else break;
        ps->p += 2;
        int rhs = mba_parse_add(ps);
        lhs = mba_add_node(ps, op, lhs, rhs, 0);
    }
    return lhs;
}

static int mba_parse_and(mba_parser *ps) {
    int lhs = mba_parse_shift(ps);
    while (!ps->err) {
        mba_skip_ws(ps);
        if (*ps->p != '&' || ps->p[1] == '&') break;
        ps->p++;
        int rhs = mba_parse_shift(ps);
        lhs = mba_add_node(ps, MBA_AND, lhs, rhs, 0);
    }
    return lhs;
}

static int mba_parse_xor(mba_parser *ps) {
    int lhs = mba_parse_and(ps);
    while (!ps->err) {
        mba_skip_ws(ps);
        if (*ps->p != '^') break;
        ps->p++;
        int rhs = mba_parse_and(ps);
        lhs = mba_add_node(ps, MBA_XOR, lhs, rhs, 0);
    }
    return lhs;
}

static int mba_parse_or(mba_parser *ps) {
    int lhs = mba_parse_xor(ps);
    while (!ps->err) {
        mba_skip_ws(ps);
        if (*ps->p != '|' || ps->p[1] == '|') break;
        ps->p++;
        int rhs = mba_parse_xor(ps);
        lhs = mba_add_node(ps, MBA_OR, lhs, rhs, 0);
    }
    return lhs;
}

static bool mba_parse_expr(const char *s, const mba_ast *var_ref, mba_ast *ast) {
    if (!s || !ast) return false;
    memset(ast, 0, sizeof(*ast));
    if (var_ref) {
        ast->nvar = var_ref->nvar;
        memcpy(ast->vars, var_ref->vars, sizeof(ast->vars));
    }
    mba_parser ps;
    memset(&ps, 0, sizeof(ps));
    ps.p = s;
    ps.var_ref = var_ref;
    ps.ast = ast;

    ast->root = mba_parse_or(&ps);
    mba_skip_ws(&ps);
    if (ps.err || ast->root < 0 || *ps.p != 0) return false;
    if (!var_ref && (ast->nvar < 1 || ast->nvar > 4)) return false;
    return true;
}

static uint64_t mba_eval_node(const mba_ast *ast, int id, const uint64_t vals[4]) {
    const mba_node *n = &ast->nodes[id];
    switch (n->op) {
    case MBA_NUM: return n->val;
    case MBA_VAR: return vals[n->a];
    case MBA_NEG: return (uint64_t)0 - mba_eval_node(ast, n->a, vals);
    case MBA_NOT: return ~mba_eval_node(ast, n->a, vals);
    case MBA_ADD: return mba_eval_node(ast, n->a, vals) + mba_eval_node(ast, n->b, vals);
    case MBA_SUB: return mba_eval_node(ast, n->a, vals) - mba_eval_node(ast, n->b, vals);
    case MBA_MUL: return mba_eval_node(ast, n->a, vals) * mba_eval_node(ast, n->b, vals);
    case MBA_SHL: {
        uint64_t l = mba_eval_node(ast, n->a, vals);
        uint64_t r = mba_eval_node(ast, n->b, vals);
        return (r >= 64) ? 0ULL : (l << r);
    }
    case MBA_SHR: {
        uint64_t l = mba_eval_node(ast, n->a, vals);
        uint64_t r = mba_eval_node(ast, n->b, vals);
        return (r >= 64) ? 0ULL : (l >> r);
    }
    case MBA_AND: return mba_eval_node(ast, n->a, vals) & mba_eval_node(ast, n->b, vals);
    case MBA_XOR: return mba_eval_node(ast, n->a, vals) ^ mba_eval_node(ast, n->b, vals);
    case MBA_OR:  return mba_eval_node(ast, n->a, vals) | mba_eval_node(ast, n->b, vals);
    default: return 0;
    }
}

static uint64_t mba_splitmix64(uint64_t *st) {
    uint64_t z = (*st += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

static void mba_classify_node(const mba_ast *ast, int id, int depth,
                              bool *is_const, bool *is_pure_bool,
                              bool *is_linear, bool *is_bw_const) {
    if (!ast || id < 0 || id >= ast->nnodes || depth > MBA_MAX_NODES) {
        *is_const = *is_pure_bool = *is_linear = *is_bw_const = false;
        return;
    }
    const mba_node *n = &ast->nodes[id];
    if (n->op == MBA_NUM) {
        *is_const = true;
        *is_pure_bool = (n->val == 0ULL || n->val == ~0ULL);
        *is_linear = true;
        *is_bw_const = true;
        return;
    }
    if (n->op == MBA_VAR) {
        *is_const = false;
        *is_pure_bool = true;
        *is_linear = true;
        *is_bw_const = true;
        return;
    }
    bool ca = false, ba = false, la = false, wa = false;
    bool cb = false, bb = false, lb = false, wb = false;
    mba_classify_node(ast, n->a, depth + 1, &ca, &ba, &la, &wa);
    if (n->op == MBA_NEG) {
        *is_const = ca;
        *is_pure_bool = false;
        *is_linear = la;
        *is_bw_const = false;
        return;
    }
    if (n->op == MBA_NOT) {
        *is_const = ca;
        *is_pure_bool = ba;
        *is_linear = la;
        *is_bw_const = wa;
        return;
    }
    mba_classify_node(ast, n->b, depth + 1, &cb, &bb, &lb, &wb);
    *is_const = ca && cb;
    switch (n->op) {
        case MBA_ADD:
        case MBA_SUB:
            *is_pure_bool = false;
            *is_linear = la && lb;
            *is_bw_const = false;
            break;
        case MBA_MUL:
            *is_pure_bool = false;
            *is_linear = (ca && lb) || (la && cb);
            *is_bw_const = false;
            break;
        case MBA_SHL:
            *is_pure_bool = false;
            *is_linear = la && cb;
            *is_bw_const = false;
            break;
        case MBA_SHR:
            *is_pure_bool = false;
            *is_linear = ca && cb;
            *is_bw_const = false;
            break;
        case MBA_AND:
        case MBA_XOR:
        case MBA_OR:
            *is_pure_bool = ba && bb;
            *is_linear = (ca && cb) || (ba && bb);
            *is_bw_const = wa && wb;
            break;
        default:
            *is_const = *is_pure_bool = *is_linear = *is_bw_const = false;
            break;
    }
}

static bool mba_verify_equiv(const mba_ast *orig, const char *cand, int *cand_ops) {
    mba_ast ca;
    if (!mba_parse_expr(cand, orig, &ca)) return false;
    if (orig->nvar < 1 || orig->nvar > 4) return false;

    bool orig_c = false, orig_pb = false, orig_lin = false, orig_bw = false;
    bool ca_c = false, ca_pb = false, ca_lin = false, ca_bw = false;
    mba_classify_node(orig, orig->root, 0, &orig_c, &orig_pb, &orig_lin, &orig_bw);
    mba_classify_node(&ca, ca.root, 0, &ca_c, &ca_pb, &ca_lin, &ca_bw);

    int npts = 1 << orig->nvar;
    if (orig_lin && ca_lin) {
        for (int m = 0; m < npts; m++) {
            uint64_t vec[4] = {0, 0, 0, 0};
            for (int v = 0; v < orig->nvar; v++) vec[v] = (uint64_t)((m >> v) & 1);
            if (mba_eval_node(orig, orig->root, vec) != mba_eval_node(&ca, ca.root, vec)) {
                return false;
            }
        }
    } else if (orig_bw) {
        bool all_uniform = true;
        for (int m = 0; m < npts; m++) {
            uint64_t vec[4] = {0, 0, 0, 0};
            for (int v = 0; v < orig->nvar; v++) vec[v] = ((m >> v) & 1) ? ~0ULL : 0ULL;
            uint64_t ov = mba_eval_node(orig, orig->root, vec);
            uint64_t cv = mba_eval_node(&ca, ca.root, vec);
            if (ov != cv) return false;
            if (ov != 0ULL && ov != ~0ULL) all_uniform = false;
        }
        if (ca_bw) {
            /* exact across all 64 bit positions */
        } else if (ca_lin && all_uniform) {
            for (int m = 0; m < npts; m++) {
                uint64_t vec[4] = {0, 0, 0, 0};
                for (int v = 0; v < orig->nvar; v++) vec[v] = (uint64_t)((m >> v) & 1);
                if (mba_eval_node(orig, orig->root, vec) != mba_eval_node(&ca, ca.root, vec)) {
                    return false;
                }
            }
        } else {
            return false;
        }
    } else {
        return false;
    }

    uint64_t rng = 0x243F6A8885A308D3ULL;
    for (int t = 0; t < 64; t++) {
        uint64_t vec[4] = {0, 0, 0, 0};
        for (int v = 0; v < orig->nvar; v++) vec[v] = mba_splitmix64(&rng);
        if (mba_eval_node(orig, orig->root, vec) != mba_eval_node(&ca, ca.root, vec)) {
            return false;
        }
    }
    if (cand_ops) *cand_ops = ca.nops;
    return true;
}

static void mba_fmt_u64(uint64_t v, char *buf, size_t max) {
    if (v <= 0xFFFFULL) snprintf(buf, max, "%llu", (unsigned long long)v);
    else snprintf(buf, max, "0x%llx", (unsigned long long)v);
}

typedef struct {
    uint64_t coeff;
    char     atom[160];
    uint8_t  paren_add;
    uint8_t  paren_mul;
} mba_term;

static bool mba_emit_terms(const mba_term *terms, int nterm, uint64_t c0, char *out, size_t max) {
    int order[16];
    int n = 0;
    for (int i = 0; i < nterm && n < 16; i++) {
        if (terms[i].coeff == 0) continue;
        if ((int64_t)terms[i].coeff > 0) order[n++] = i;
    }
    for (int i = 0; i < nterm && n < 16; i++) {
        if (terms[i].coeff == 0) continue;
        if ((int64_t)terms[i].coeff < 0) order[n++] = i;
    }

    if (n == 0) {
        int64_t sc = (int64_t)c0;
        int w = 0;
        if (sc >= 0) {
            if (c0 <= 0xFFFFULL) w = snprintf(out, max, "%llu", (unsigned long long)c0);
            else w = snprintf(out, max, "0x%llx", (unsigned long long)c0);
        } else if (c0 == 0x8000000000000000ULL) {
            w = snprintf(out, max, "0x8000000000000000");
        } else {
            char mag[32];
            mba_fmt_u64((uint64_t)0 - c0, mag, sizeof(mag));
            w = snprintf(out, max, "-%s", mag);
        }
        return w >= 0 && (size_t)w < max;
    }

    size_t pos = 0;
    out[0] = 0;
    int multi = (n > 1) || (c0 != 0);

    for (int idx = 0; idx < n; idx++) {
        const mba_term *t = &terms[order[idx]];
        int64_t sc = (int64_t)t->coeff;
        int neg = (sc < 0 && t->coeff != 0x8000000000000000ULL);
        uint64_t mag = neg ? ((uint64_t)0 - t->coeff) : t->coeff;

        char piece[224];
        int pw = 0;
        if (mag == 1) {
            if (multi && t->paren_add) pw = snprintf(piece, sizeof(piece), "(%s)", t->atom);
            else if (idx == 0 && neg && (t->paren_mul || t->paren_add)) pw = snprintf(piece, sizeof(piece), "(%s)", t->atom);
            else pw = snprintf(piece, sizeof(piece), "%s", t->atom);
        } else {
            char cb[32];
            mba_fmt_u64(mag, cb, sizeof(cb));
            if (t->paren_mul) pw = snprintf(piece, sizeof(piece), "%s * (%s)", cb, t->atom);
            else pw = snprintf(piece, sizeof(piece), "%s * %s", cb, t->atom);
        }
        if (pw < 0 || (size_t)pw >= sizeof(piece)) return false;

        int w = 0;
        if (idx == 0) {
            w = snprintf(out + pos, max - pos, "%s%s", neg ? "-" : "", piece);
        } else {
            w = snprintf(out + pos, max - pos, " %c %s", neg ? '-' : '+', piece);
        }
        if (w < 0 || pos + (size_t)w >= max) return false;
        pos += (size_t)w;
    }

    if (c0 != 0) {
        int64_t sc = (int64_t)c0;
        char cb[32];
        int w = 0;
        if (sc < 0 && c0 != 0x8000000000000000ULL) {
            mba_fmt_u64((uint64_t)0 - c0, cb, sizeof(cb));
            w = snprintf(out + pos, max - pos, " - %s", cb);
        } else {
            mba_fmt_u64(c0, cb, sizeof(cb));
            w = snprintf(out + pos, max - pos, " + %s", cb);
        }
        if (w < 0 || pos + (size_t)w >= max) return false;
    }
    return true;
}

typedef struct {
    const mba_ast *orig;
    char           best[MBA_MAX_EXPR];
    int            best_ops;
    int            have;
    size_t         out_max;
} mba_chooser;

static void mba_try_cand(mba_chooser *ch, const char *cand) {
    if (!cand || !cand[0]) return;
    if (ch->out_max > 0 && strlen(cand) >= ch->out_max) return;
    int cand_ops = 0;
    if (!mba_verify_equiv(ch->orig, cand, &cand_ops)) return;
    if (!ch->have || cand_ops < ch->best_ops ||
        (cand_ops == ch->best_ops && strlen(cand) < strlen(ch->best))) {
        snprintf(ch->best, sizeof(ch->best), "%s", cand);
        ch->best_ops = cand_ops;
        ch->have = 1;
    }
}

static void mba_synth_linear(mba_chooser *ch, int k, const char *const vnames[4],
                             const uint64_t lin[4], uint64_t c0) {
    mba_term ts[4];
    int nt = 0;
    for (int i = 0; i < k; i++) {
        if (!lin[i]) continue;
        ts[nt].coeff = lin[i];
        snprintf(ts[nt].atom, sizeof(ts[nt].atom), "%s", vnames[i]);
        ts[nt].paren_add = 0;
        ts[nt].paren_mul = 0;
        nt++;
    }

    char buf[MBA_MAX_EXPR];
    if (mba_emit_terms(ts, nt, c0, buf, sizeof(buf))) mba_try_cand(ch, buf);

    // c0 == -1 and all -1 coeffs -> ~(x + y + ...)
    if (nt >= 1 && c0 == ~0ULL) {
        int all_neg1 = 1;
        for (int i = 0; i < nt; i++) {
            if (ts[i].coeff != ~0ULL) all_neg1 = 0;
        }
        if (all_neg1) {
            if (nt == 1) {
                int w = snprintf(buf, sizeof(buf), "~%s", ts[0].atom);
                if (w > 0 && (size_t)w < sizeof(buf)) mba_try_cand(ch, buf);
            } else {
                mba_term pos[4];
                for (int i = 0; i < nt; i++) { pos[i] = ts[i]; pos[i].coeff = 1; }
                char inner[MBA_MAX_EXPR];
                if (mba_emit_terms(pos, nt, 0, inner, sizeof(inner))) {
                    int w = snprintf(buf, sizeof(buf), "~(%s)", inner);
                    if (w > 0 && (size_t)w < sizeof(buf)) mba_try_cand(ch, buf);
                }
            }
        }
    }

    // c0 > 0 with single negative term -> c0 - x
    if (nt == 1 && ts[0].coeff == ~0ULL && (int64_t)c0 > 0) {
        char cb[32];
        mba_fmt_u64(c0, cb, sizeof(cb));
        int w = snprintf(buf, sizeof(buf), "%s - %s", cb, ts[0].atom);
        if (w > 0 && (size_t)w < sizeof(buf)) mba_try_cand(ch, buf);
    }

    // c0 == -k and single -k term -> k * ~x
    if (nt == 1 && ts[0].coeff == c0 && (int64_t)c0 < -1 && c0 != 0x8000000000000000ULL) {
        char cb[32];
        mba_fmt_u64((uint64_t)0 - c0, cb, sizeof(cb));
        int w = snprintf(buf, sizeof(buf), "%s * ~%s", cb, ts[0].atom);
        if (w > 0 && (size_t)w < sizeof(buf)) mba_try_cand(ch, buf);
    }

    // common factor across linear terms when c0 == 0
    if (nt >= 2 && c0 == 0) {
        uint64_t m0 = ((int64_t)ts[0].coeff < 0) ? ((uint64_t)0 - ts[0].coeff) : ts[0].coeff;
        if (m0 > 1 && m0 != 0x8000000000000000ULL) {
            int same = 1;
            mba_term unit[4];
            for (int i = 0; i < nt; i++) {
                uint64_t mi = ((int64_t)ts[i].coeff < 0) ? ((uint64_t)0 - ts[i].coeff) : ts[i].coeff;
                if (mi != m0) { same = 0; break; }
                unit[i] = ts[i];
                unit[i].coeff = ((int64_t)ts[i].coeff < 0) ? ~0ULL : 1ULL;
            }
            if (same) {
                char inner[MBA_MAX_EXPR], cb[32];
                mba_fmt_u64(m0, cb, sizeof(cb));
                if (mba_emit_terms(unit, nt, 0, inner, sizeof(inner))) {
                    int w = snprintf(buf, sizeof(buf), "%s * (%s)", cb, inner);
                    if (w > 0 && (size_t)w < sizeof(buf)) mba_try_cand(ch, buf);
                }
            }
        }
    }
}

static void mba_try_2var_basis(mba_chooser *ch, const char *vx, const char *vy,
                               const char *atom, uint8_t p_add, uint8_t p_mul,
                               uint64_t k, uint64_t r0, uint64_t rx, uint64_t ry) {
    mba_term ts[3];
    int nt = 0;
    if (k) {
        ts[nt].coeff = k;
        snprintf(ts[nt].atom, sizeof(ts[nt].atom), "%s", atom);
        ts[nt].paren_add = p_add;
        ts[nt].paren_mul = p_mul;
        nt++;
    }
    if (rx) {
        ts[nt].coeff = rx;
        snprintf(ts[nt].atom, sizeof(ts[nt].atom), "%s", vx);
        ts[nt].paren_add = 0;
        ts[nt].paren_mul = 0;
        nt++;
    }
    if (ry) {
        ts[nt].coeff = ry;
        snprintf(ts[nt].atom, sizeof(ts[nt].atom), "%s", vy);
        ts[nt].paren_add = 0;
        ts[nt].paren_mul = 0;
        nt++;
    }
    char buf[MBA_MAX_EXPR];
    if (mba_emit_terms(ts, nt, r0, buf, sizeof(buf))) mba_try_cand(ch, buf);
}

static void mba_synth_2(mba_chooser *ch, const char *vx, const char *vy, const uint64_t a[4]) {
    uint64_t a0 = a[0], ax = a[1], ay = a[2], axy = a[3];
    if (axy == 0) {
        const char *vn[4] = {vx, vy, NULL, NULL};
        uint64_t lin[4] = {ax, ay, 0, 0};
        mba_synth_linear(ch, 2, vn, lin, a0);
        return;
    }

    char b_and[80], b_or[80], b_xor[80], b_xny[80], b_ynx[80];
    char b_nand[80], b_nor[80], b_xnor[80], b_xony[80], b_nxy[80];
    snprintf(b_and,  sizeof(b_and),  "%s & %s",  vx, vy);
    snprintf(b_or,   sizeof(b_or),   "%s | %s",  vx, vy);
    snprintf(b_xor,  sizeof(b_xor),  "%s ^ %s",  vx, vy);
    snprintf(b_xny,  sizeof(b_xny),  "%s & ~%s", vx, vy);
    snprintf(b_ynx,  sizeof(b_ynx),  "%s & ~%s", vy, vx);
    snprintf(b_nand, sizeof(b_nand), "~(%s & %s)", vx, vy);
    snprintf(b_nor,  sizeof(b_nor),  "~(%s | %s)", vx, vy);
    snprintf(b_xnor, sizeof(b_xnor), "~(%s ^ %s)", vx, vy);
    snprintf(b_xony, sizeof(b_xony), "%s | ~%s", vx, vy);
    snprintf(b_nxy,  sizeof(b_nxy),  "~%s | %s", vx, vy);

    uint64_t neg_axy = (uint64_t)0 - axy;

    mba_try_2var_basis(ch, vx, vy, b_and, 1, 1, axy, a0, ax, ay);
    mba_try_2var_basis(ch, vx, vy, b_or, 1, 1, neg_axy, a0, ax + axy, ay + axy);
    if ((axy & 1ULL) == 0) {
        int64_t h = (int64_t)axy / 2;
        uint64_t k = (uint64_t)0 - (uint64_t)h;
        mba_try_2var_basis(ch, vx, vy, b_xor, 1, 1, k, a0, ax - k, ay - k);
    }
    mba_try_2var_basis(ch, vx, vy, b_xny, 1, 1, neg_axy, a0, ax + axy, ay);
    mba_try_2var_basis(ch, vx, vy, b_ynx, 1, 1, neg_axy, a0, ax, ay + axy);
    mba_try_2var_basis(ch, vx, vy, b_nand, 0, 0, neg_axy, a0 + neg_axy, ax, ay);
    mba_try_2var_basis(ch, vx, vy, b_nor, 0, 0, axy, a0 + axy, ax + axy, ay + axy);
    if ((axy & 1ULL) == 0) {
        uint64_t k = (uint64_t)((int64_t)axy / 2);
        mba_try_2var_basis(ch, vx, vy, b_xnor, 0, 0, k, a0 + k, ax + k, ay + k);
    }
    mba_try_2var_basis(ch, vx, vy, b_xony, 1, 1, axy, a0 + axy, ax, ay + axy);
    mba_try_2var_basis(ch, vx, vy, b_nxy, 1, 1, axy, a0 + axy, ax + axy, ay);

    // odd axy xor split
    if (axy & 1ULL) {
        for (int sgn = -1; sgn <= 1; sgn += 2) {
            uint64_t rem_xy = axy - (uint64_t)(int64_t)sgn;
            int64_t h = (int64_t)rem_xy / 2;
            uint64_t kx = (uint64_t)0 - (uint64_t)h;
            mba_term ts[4];
            int nt = 0;
            if (kx) {
                ts[nt].coeff = kx; snprintf(ts[nt].atom, sizeof(ts[nt].atom), "%s", b_xor);
                ts[nt].paren_add = 1; ts[nt].paren_mul = 1; nt++;
            }
            ts[nt].coeff = (uint64_t)(int64_t)sgn; snprintf(ts[nt].atom, sizeof(ts[nt].atom), "%s", b_and);
            ts[nt].paren_add = 1; ts[nt].paren_mul = 1; nt++;
            uint64_t rx = ax - kx, ry = ay - kx;
            if (rx) { ts[nt].coeff = rx; snprintf(ts[nt].atom, sizeof(ts[nt].atom), "%s", vx); ts[nt].paren_add = 0; ts[nt].paren_mul = 0; nt++; }
            if (ry) { ts[nt].coeff = ry; snprintf(ts[nt].atom, sizeof(ts[nt].atom), "%s", vy); ts[nt].paren_add = 0; ts[nt].paren_mul = 0; nt++; }
            char buf[MBA_MAX_EXPR];
            if (mba_emit_terms(ts, nt, a0, buf, sizeof(buf))) mba_try_cand(ch, buf);

            nt = 0;
            if (kx) {
                ts[nt].coeff = kx; snprintf(ts[nt].atom, sizeof(ts[nt].atom), "%s", b_xor);
                ts[nt].paren_add = 1; ts[nt].paren_mul = 1; nt++;
            }
            uint64_t ko = (uint64_t)(int64_t)(-sgn);
            ts[nt].coeff = ko; snprintf(ts[nt].atom, sizeof(ts[nt].atom), "%s", b_or);
            ts[nt].paren_add = 1; ts[nt].paren_mul = 1; nt++;
            rx = ax - kx - ko; ry = ay - kx - ko;
            if (rx) { ts[nt].coeff = rx; snprintf(ts[nt].atom, sizeof(ts[nt].atom), "%s", vx); ts[nt].paren_add = 0; ts[nt].paren_mul = 0; nt++; }
            if (ry) { ts[nt].coeff = ry; snprintf(ts[nt].atom, sizeof(ts[nt].atom), "%s", vy); ts[nt].paren_add = 0; ts[nt].paren_mul = 0; nt++; }
            if (mba_emit_terms(ts, nt, a0, buf, sizeof(buf))) mba_try_cand(ch, buf);
        }
    }
}

static uint8_t mba_bool_apply(int op, uint8_t a, uint8_t b) {
    if (op == 0) return (uint8_t)(a & b);
    if (op == 1) return (uint8_t)(a | b);
    return (uint8_t)(a ^ b);
}

static void mba_synth_pure_bool(mba_chooser *ch, int k, const char *const vnames[4], const uint64_t f[16]) {
    int npts = 1 << k;
    int all01 = 1, all_neg = 1;
    for (int m = 0; m < npts; m++) {
        if (f[m] != 0ULL && f[m] != 1ULL) all01 = 0;
        if (f[m] != ~0ULL && f[m] != ~1ULL) all_neg = 0;
    }
    if (!all01 && !all_neg) return;

    int inv = !all01;
    uint16_t tt = 0;
    for (int m = 0; m < npts; m++) {
        int bit = inv ? (f[m] == ~1ULL) : (f[m] == 1ULL);
        if (bit) tt |= (uint16_t)(1U << m);
    }

    char buf[MBA_MAX_EXPR];
    static const char ops[3] = {'&', '|', '^'};

    if (k == 3) {
        for (int outer = 2; outer >= 0; outer--) {
            int u = (outer == 0) ? 1 : 0;
            int w = (outer == 2) ? 1 : 2;
            for (int op1 = 0; op1 < 3; op1++) {
                for (int op2 = 0; op2 < 3; op2++) {
                    uint16_t got = 0;
                    for (int m = 0; m < 8; m++) {
                        uint8_t bu = (uint8_t)((m >> u) & 1);
                        uint8_t bw = (uint8_t)((m >> w) & 1);
                        uint8_t bv = (uint8_t)((m >> outer) & 1);
                        uint8_t r = mba_bool_apply(op2, mba_bool_apply(op1, bu, bw), bv);
                        if (r) got |= (uint16_t)(1U << m);
                    }
                    if (got != tt) continue;
                    int sw = 0;
                    if (op1 == op2) {
                        if (inv) sw = snprintf(buf, sizeof(buf), "~(%s %c %s %c %s)", vnames[u], ops[op1], vnames[w], ops[op2], vnames[outer]);
                        else     sw = snprintf(buf, sizeof(buf), "%s %c %s %c %s", vnames[u], ops[op1], vnames[w], ops[op2], vnames[outer]);
                    } else {
                        if (inv) sw = snprintf(buf, sizeof(buf), "~((%s %c %s) %c %s)", vnames[u], ops[op1], vnames[w], ops[op2], vnames[outer]);
                        else     sw = snprintf(buf, sizeof(buf), "(%s %c %s) %c %s", vnames[u], ops[op1], vnames[w], ops[op2], vnames[outer]);
                    }
                    if (sw > 0 && (size_t)sw < sizeof(buf)) mba_try_cand(ch, buf);
                }
            }
        }
    } else if (k == 4) {
        for (int op = 0; op < 3; op++) {
            uint16_t got = 0;
            for (int m = 0; m < 16; m++) {
                uint8_t r = (uint8_t)(m & 1);
                for (int i = 1; i < 4; i++) r = mba_bool_apply(op, r, (uint8_t)((m >> i) & 1));
                if (r) got |= (uint16_t)(1U << m);
            }
            if (got != tt) continue;
            int w = 0;
            if (inv) w = snprintf(buf, sizeof(buf), "~(%s %c %s %c %s %c %s)", vnames[0], ops[op], vnames[1], ops[op], vnames[2], ops[op], vnames[3]);
            else     w = snprintf(buf, sizeof(buf), "%s %c %s %c %s %c %s", vnames[0], ops[op], vnames[1], ops[op], vnames[2], ops[op], vnames[3]);
            if (w > 0 && (size_t)w < sizeof(buf)) mba_try_cand(ch, buf);
        }
    }
}

static int mba_popcnt(int x) {
    int c = 0;
    while (x) { c += (x & 1); x >>= 1; }
    return c;
}

static int mba_count_nz(const uint64_t r[16], int npts) {
    int c = 0;
    for (int i = 0; i < npts; i++) if (r[i]) c++;
    return c;
}

static void mba_synth_general(mba_chooser *ch, int k, const char *const vnames[4],
                              const uint64_t f[16], const uint64_t a[16]) {
    int npts = 1 << k;
    mba_synth_pure_bool(ch, k, vnames, f);

    int any_hi = 0;
    for (int m = 1; m < npts; m++) {
        if (mba_popcnt(m) >= 2 && a[m] != 0) any_hi = 1;
    }
    if (!any_hi) {
        uint64_t lin[4] = {0, 0, 0, 0};
        for (int i = 0; i < k; i++) lin[i] = a[(size_t)1 << i];
        mba_synth_linear(ch, k, vnames, lin, a[0]);
        return;
    }

    uint64_t rem[16];
    memcpy(rem, a, sizeof(rem));
    mba_term ts[16];
    int nt = 0;

    // reduce high-order conjunctions
    for (int sz = k; sz >= 3; sz--) {
        for (int m = 1; m < npts; m++) {
            if (mba_popcnt(m) != sz || rem[m] == 0) continue;

            int best_kind = 0;
            uint64_t best_k = rem[m];
            uint64_t best_rem[16];
            memcpy(best_rem, rem, sizeof(best_rem));
            best_rem[m] = 0;
            int best_nz = mba_count_nz(best_rem, npts);

            {
                uint64_t k_or = (sz & 1) ? rem[m] : ((uint64_t)0 - rem[m]);
                uint64_t tr[16];
                memcpy(tr, rem, sizeof(tr));
                for (int s = m; s > 0; s = (s - 1) & m) {
                    uint64_t coef = (mba_popcnt(s) & 1) ? k_or : ((uint64_t)0 - k_or);
                    tr[s] -= coef;
                }
                int nz = mba_count_nz(tr, npts);
                if (nz < best_nz) { best_nz = nz; best_kind = 1; best_k = k_or; memcpy(best_rem, tr, sizeof(tr)); }
            }

            {
                uint64_t div = 1ULL << (sz - 1);
                if ((rem[m] & (div - 1)) == 0) {
                    int64_t q = (int64_t)rem[m] / (int64_t)div;
                    uint64_t k_xor = (sz & 1) ? (uint64_t)q : ((uint64_t)0 - (uint64_t)q);
                    uint64_t tr[16];
                    memcpy(tr, rem, sizeof(tr));
                    for (int s = m; s > 0; s = (s - 1) & m) {
                        int pc = mba_popcnt(s);
                        uint64_t mag = k_xor << (pc - 1);
                        uint64_t coef = (pc & 1) ? mag : ((uint64_t)0 - mag);
                        tr[s] -= coef;
                    }
                    int nz = mba_count_nz(tr, npts);
                    if (nz < best_nz) { best_nz = nz; best_kind = 2; best_k = k_xor; memcpy(best_rem, tr, sizeof(tr)); }
                }
            }

            memcpy(rem, best_rem, sizeof(rem));
            if (nt < 16) {
                char op = (best_kind == 0) ? '&' : (best_kind == 1) ? '|' : '^';
                ts[nt].coeff = best_k;
                ts[nt].paren_add = 1;
                ts[nt].paren_mul = 1;
                size_t pos = 0;
                bool atom_ok = true;
                ts[nt].atom[0] = 0;
                for (int i = 0; i < k; i++) {
                    if (!(m & (1 << i))) continue;
                    int aw = snprintf(ts[nt].atom + pos, sizeof(ts[nt].atom) - pos,
                                      "%s%s", pos ? (op == '&' ? " & " : op == '|' ? " | " : " ^ ") : "", vnames[i]);
                    if (aw < 0 || pos + (size_t)aw >= sizeof(ts[nt].atom)) { atom_ok = false; break; }
                    pos += (size_t)aw;
                }
                if (!atom_ok) return;
                nt++;
            } else {
                return;
            }
        }
    }

    for (int i = 0; i < k; i++) {
        for (int j = i + 1; j < k; j++) {
            int bi = 1 << i, bj = 1 << j, m = bi | bj;
            if (rem[m] == 0) continue;

            uint64_t axy = rem[m];
            uint64_t neg = (uint64_t)0 - axy;
            int best_kind = 0;
            uint64_t best_k = axy;
            uint64_t best_ri = rem[bi], best_rj = rem[bj];
            int best_score = (best_ri != 0) + (best_rj != 0);

            {
                uint64_t ri = rem[bi] + axy, rj = rem[bj] + axy;
                int sc = (ri != 0) + (rj != 0);
                if (sc < best_score) { best_score = sc; best_kind = 1; best_k = neg; best_ri = ri; best_rj = rj; }
            }
            if ((axy & 1ULL) == 0) {
                uint64_t kx = (uint64_t)0 - (uint64_t)((int64_t)axy / 2);
                uint64_t ri = rem[bi] - kx, rj = rem[bj] - kx;
                int sc = (ri != 0) + (rj != 0);
                if (sc < best_score) { best_score = sc; best_kind = 2; best_k = kx; best_ri = ri; best_rj = rj; }
            }
            {
                uint64_t ri = rem[bi] + axy, rj = rem[bj];
                int sc = (ri != 0) + (rj != 0) + 1;
                if (sc < best_score) { best_score = sc; best_kind = 3; best_k = neg; best_ri = ri; best_rj = rj; }
            }
            {
                uint64_t ri = rem[bi], rj = rem[bj] + axy;
                int sc = (ri != 0) + (rj != 0) + 1;
                if (sc < best_score) { best_score = sc; best_kind = 4; best_k = neg; best_ri = ri; best_rj = rj; }
            }

            rem[m] = 0;
            rem[bi] = best_ri;
            rem[bj] = best_rj;
            if (nt < 16) {
                ts[nt].coeff = best_k;
                ts[nt].paren_add = 1;
                ts[nt].paren_mul = 1;
                int aw = 0;
                if (best_kind == 0)      aw = snprintf(ts[nt].atom, sizeof(ts[nt].atom), "%s & %s", vnames[i], vnames[j]);
                else if (best_kind == 1) aw = snprintf(ts[nt].atom, sizeof(ts[nt].atom), "%s | %s", vnames[i], vnames[j]);
                else if (best_kind == 2) aw = snprintf(ts[nt].atom, sizeof(ts[nt].atom), "%s ^ %s", vnames[i], vnames[j]);
                else if (best_kind == 3) aw = snprintf(ts[nt].atom, sizeof(ts[nt].atom), "%s & ~%s", vnames[i], vnames[j]);
                else                     aw = snprintf(ts[nt].atom, sizeof(ts[nt].atom), "%s & ~%s", vnames[j], vnames[i]);
                if (aw < 0 || (size_t)aw >= sizeof(ts[nt].atom)) return;
                nt++;
            } else {
                return;
            }
        }
    }

    for (int i = 0; i < k && nt < 16; i++) {
        uint64_t c = rem[(size_t)1 << i];
        if (!c) continue;
        ts[nt].coeff = c;
        snprintf(ts[nt].atom, sizeof(ts[nt].atom), "%s", vnames[i]);
        ts[nt].paren_add = 0;
        ts[nt].paren_mul = 0;
        nt++;
    }

    char buf[MBA_MAX_EXPR];
    if (mba_emit_terms(ts, nt, rem[0], buf, sizeof(buf))) mba_try_cand(ch, buf);
}

bool mba_simplify_expr(const char *expr, char *out, size_t max, int *ops_saved) {
    if (ops_saved) *ops_saved = 0;
    if (!expr || !out || max == 0) return false;
    out[0] = 0;

    mba_ast orig;
    if (!mba_parse_expr(expr, NULL, &orig)) return false;

    bool orig_c = false, orig_pb = false, orig_lin = false, orig_bw = false;
    mba_classify_node(&orig, orig.root, 0, &orig_c, &orig_pb, &orig_lin, &orig_bw);

    int n = orig.nvar;
    int npts = 1 << n;
    bool can_synth = orig_lin;
    if (!can_synth && orig_bw) {
        can_synth = true;
        for (int m = 0; m < npts; m++) {
            uint64_t vec[4] = {0, 0, 0, 0};
            for (int i = 0; i < n; i++) vec[i] = ((m >> i) & 1) ? ~0ULL : 0ULL;
            uint64_t ov = mba_eval_node(&orig, orig.root, vec);
            if (ov != 0ULL && ov != ~0ULL) { can_synth = false; break; }
        }
    }

    if (can_synth) {
        uint64_t f[16], a[16];
        memset(f, 0, sizeof(f));
        memset(a, 0, sizeof(a));

        for (int m = 0; m < npts; m++) {
            uint64_t vec[4] = {0, 0, 0, 0};
            for (int i = 0; i < n; i++) vec[i] = (uint64_t)((m >> i) & 1);
            f[m] = mba_eval_node(&orig, orig.root, vec);
            a[m] = f[m];
        }

        // exact mobius transform over Z / 2^64 Z
        for (int i = 0; i < n; i++) {
            int bit = 1 << i;
            for (int m = 0; m < npts; m++) {
                if (m & bit) a[m] -= a[m ^ bit];
            }
        }

        // project out dead variables
        int active[4];
        const char *vnames[4] = {NULL, NULL, NULL, NULL};
        int k = 0;
        for (int i = 0; i < n; i++) {
            int bit = 1 << i;
            int used = 0;
            for (int m = 0; m < npts; m++) {
                if ((m & bit) && a[m] != 0) { used = 1; break; }
            }
            if (used) {
                active[k] = i;
                vnames[k] = orig.vars[i];
                k++;
            }
        }

        uint64_t pf[16], pa[16];
        memset(pf, 0, sizeof(pf));
        memset(pa, 0, sizeof(pa));
        for (int pm = 0; pm < (1 << k); pm++) {
            int om = 0;
            for (int j = 0; j < k; j++) {
                if (pm & (1 << j)) om |= (1 << active[j]);
            }
            pf[pm] = f[om];
            pa[pm] = a[om];
        }

        mba_chooser ch;
        memset(&ch, 0, sizeof(ch));
        ch.orig = &orig;
        ch.out_max = max;

        if (k == 0) {
            char buf[64];
            if (mba_emit_terms(NULL, 0, pa[0], buf, sizeof(buf))) mba_try_cand(&ch, buf);
        } else if (k == 1) {
            uint64_t lin[4] = {pa[1], 0, 0, 0};
            mba_synth_linear(&ch, 1, vnames, lin, pa[0]);
        } else if (k == 2) {
            mba_synth_2(&ch, vnames[0], vnames[1], pa);
        } else {
            mba_synth_general(&ch, k, vnames, pf, pa);
        }

        int cand_ops = orig.nops;
        if (ch.have && ch.best_ops < orig.nops && strlen(ch.best) < max &&
            mba_verify_equiv(&orig, ch.best, &cand_ops)) {
            snprintf(out, max, "%s", ch.best);
            if (ops_saved) *ops_saved = orig.nops - cand_ops;
            return true;
        }
    }

    // already minimal or nonlinear
    char copy[MBA_MAX_EXPR];
    if (strlen(expr) >= sizeof(copy)) return false;
    snprintf(copy, sizeof(copy), "%s", expr);
    cff_trim(copy);
    if (strlen(copy) >= max) return false;
    snprintf(out, max, "%s", copy);
    if (ops_saved) *ops_saved = 0;
    return true;
}

typedef struct {
    int     base;
    int64_t disp;
    int     bits;
    char    expr[MBA_MAX_EXPR];
} mba_slot;

typedef struct {
    char     reg[16][MBA_MAX_EXPR];
    uint8_t  bits[16];
    mba_slot slots[MBA_MAX_SLOTS];
    int      nslot;
    int      fresh_id;
} mba_bstate;

static bool mba_is_hi8_reg(const char *s) {
    if (!s) return false;
    return strcmp(s, "ah") == 0 || strcmp(s, "ch") == 0 ||
           strcmp(s, "dh") == 0 || strcmp(s, "bh") == 0;
}

static bool mba_is_atom(const char *s) {
    if (!s || !s[0]) return false;
    const char *p = s;
    if (*p == '~' && p[1]) p++;
    for (; *p; p++) {
        if (!isalnum((unsigned char)*p) && *p != '_') return false;
    }
    return true;
}

static bool mba_is_wrapped(const char *s) {
    size_t n = strlen(s);
    if (n < 2 || s[0] != '(' || s[n - 1] != ')') return false;
    int d = 0;
    for (size_t i = 0; i + 1 < n; i++) {
        if (s[i] == '(') d++;
        else if (s[i] == ')') d--;
        if (d == 0) return false;
    }
    return d == 1;
}

static void mba_strip_parens(const char *src, char *dst, size_t max) {
    char tmp[MBA_MAX_EXPR];
    snprintf(tmp, sizeof(tmp), "%s", src);
    cff_trim(tmp);
    while (mba_is_wrapped(tmp)) {
        size_t n = strlen(tmp);
        memmove(tmp, tmp + 1, n - 2);
        tmp[n - 2] = 0;
        cff_trim(tmp);
    }
    snprintf(dst, max, "%s", tmp);
}

static bool mba_has_bitwise(const char *s) {
    for (; *s; s++) {
        if (*s == '&' || *s == '|' || *s == '^' || *s == '~') return true;
    }
    return false;
}

static void mba_fresh_var(mba_bstate *st, char *dst, size_t max) {
    snprintf(dst, max, "v%d", st->fresh_id++);
}

static bool mba_fmt_bin(const char *lhs, const char *op, const char *rhs, char *dst, size_t max) {
    char lb[MBA_MAX_EXPR], rb[MBA_MAX_EXPR];
    if (mba_is_atom(lhs) || mba_is_wrapped(lhs)) snprintf(lb, sizeof(lb), "%s", lhs);
    else snprintf(lb, sizeof(lb), "(%s)", lhs);

    if (mba_is_atom(rhs) || mba_is_wrapped(rhs)) snprintf(rb, sizeof(rb), "%s", rhs);
    else snprintf(rb, sizeof(rb), "(%s)", rhs);

    int w = snprintf(dst, max, "%s %s %s", lb, op, rb);
    return w > 0 && (size_t)w < max - 8;
}

static bool mba_fmt_un(char op, const char *arg, char *dst, size_t max) {
    int w = 0;
    if (mba_is_atom(arg) || mba_is_wrapped(arg)) w = snprintf(dst, max, "%c%s", op, arg);
    else w = snprintf(dst, max, "%c(%s)", op, arg);
    return w > 0 && (size_t)w < max - 8;
}

static bool mba_mask_expr(const char *src, int mask_bits, char *dst, size_t max) {
    if (mask_bits <= 0 || mask_bits >= 64) {
        int w = snprintf(dst, max, "%s", src);
        return w > 0 && (size_t)w < max - 8;
    }
    const char *mstr = (mask_bits == 8) ? "0xff" : (mask_bits == 16) ? "0xffff" : "0xffffffff";
    return mba_fmt_bin(src, "&", mstr, dst, max);
}

static bool mba_ranges_overlap(int64_t a0, int abits, int64_t b0, int bbits) {
    uint64_t aw = (uint64_t)((abits > 0) ? ((abits + 7) / 8) : 8);
    uint64_t bw = (uint64_t)((bbits > 0) ? ((bbits + 7) / 8) : 8);
    if (a0 <= b0) {
        return ((uint64_t)b0 - (uint64_t)a0) < aw;
    }
    return ((uint64_t)a0 - (uint64_t)b0) < bw;
}

static void mba_slot_invalidate_mem(mba_bstate *st, const cff_mem *mem, int default_bits) {
    if (!st) return;
    if (mem && mem->has_seg) return;
    if (!mem || mem->base < 0 || mem->idx >= 0 || mem->is_abs) {
        st->nslot = 0;
        return;
    }
    int wb = mem->bits ? mem->bits : (default_bits ? default_bits : 64);
    int keep = 0;
    for (int i = 0; i < st->nslot; i++) {
        const mba_slot *sl = &st->slots[i];
        bool drop = false;
        if (sl->base != mem->base) {
            drop = true;
        } else if (mba_ranges_overlap(sl->disp, sl->bits, mem->disp, wb)) {
            drop = true;
        }
        if (!drop) {
            if (keep != i) st->slots[keep] = st->slots[i];
            keep++;
        }
    }
    st->nslot = keep;
}

static const char *mba_slot_load_w(mba_bstate *st, int base, int64_t disp, int bits) {
    int b = bits ? bits : 64;
    for (int i = 0; i < st->nslot; i++) {
        if (st->slots[i].base == base && st->slots[i].disp == disp && st->slots[i].bits == b) {
            return st->slots[i].expr;
        }
    }
    if (st->nslot < MBA_MAX_SLOTS) {
        mba_slot *sl = &st->slots[st->nslot++];
        sl->base = base;
        sl->disp = disp;
        sl->bits = b;
        mba_fresh_var(st, sl->expr, sizeof(sl->expr));
        return sl->expr;
    }
    return NULL;
}

static void mba_slot_store_w(mba_bstate *st, int base, int64_t disp, int bits, const char *expr) {
    int b = bits ? bits : 64;
    cff_mem mem;
    memset(&mem, 0, sizeof(mem));
    mem.base = base;
    mem.idx = -1;
    mem.bits = b;
    mem.disp = disp;
    mba_slot_invalidate_mem(st, &mem, b);
    if (st->nslot < MBA_MAX_SLOTS) {
        mba_slot *sl = &st->slots[st->nslot++];
        sl->base = base;
        sl->disp = disp;
        sl->bits = b;
        snprintf(sl->expr, sizeof(sl->expr), "%s", expr);
    }
}

static bool mba_eval_op_str_w(mba_bstate *st, const char *op, int read_bits, char *dst, size_t max) {
    int rb = 0;
    int r = cff_reg_id(op, &rb);
    if (r >= 0) {
        if (mba_is_hi8_reg(op)) return false;
        int eff = (read_bits > 0 && read_bits < rb) ? read_bits : rb;
        if (eff < 64 && (int)st->bits[r] > eff) {
            return mba_mask_expr(st->reg[r], eff, dst, max);
        }
        int w = snprintf(dst, max, "%s", st->reg[r]);
        return w > 0 && (size_t)w < max;
    }
    uint64_t imm = 0;
    if (cff_parse_imm(op, &imm)) {
        if (read_bits > 0 && read_bits < 64) imm = cff_mask(imm, read_bits);
        mba_fmt_u64(imm, dst, max);
        return true;
    }
    cff_mem mem;
    if (cff_parse_mem(op, &mem) && !mem.has_seg && mem.base >= 0 && mem.idx < 0) {
        int mb = mem.bits ? mem.bits : (read_bits ? read_bits : 64);
        const char *sl = mba_slot_load_w(st, mem.base, mem.disp, mb);
        if (sl) {
            if (mb < 64 && strchr(sl, '&') == NULL) {
                return mba_mask_expr(sl, mb, dst, max);
            }
            int w = snprintf(dst, max, "%s", sl);
            return w > 0 && (size_t)w < max;
        }
    }
    return false;
}

static bool mba_build_lea(const mba_bstate *st, const x86_ins *in, const char *op, char *dst, size_t max) {
    if (in->has_target) {
        mba_fmt_u64(in->target, dst, max);
        return true;
    }
    cff_mem mem;
    if (!cff_parse_mem(op, &mem)) return false;

    char acc[MBA_MAX_EXPR] = "";
    int has = 0;
    if (mem.base >= 0) {
        snprintf(acc, sizeof(acc), "%s", st->reg[mem.base]);
        has = 1;
    }
    if (mem.idx >= 0) {
        char iterm[MBA_MAX_EXPR];
        if (mem.scale > 1) {
            char sb[16];
            snprintf(sb, sizeof(sb), "%d", mem.scale);
            if (!mba_fmt_bin(st->reg[mem.idx], "*", sb, iterm, sizeof(iterm))) return false;
        } else {
            snprintf(iterm, sizeof(iterm), "%s", st->reg[mem.idx]);
        }
        if (!has) {
            snprintf(acc, sizeof(acc), "%s", iterm);
            has = 1;
        } else {
            char tmp[MBA_MAX_EXPR];
            if (!mba_fmt_bin(acc, "+", iterm, tmp, sizeof(tmp))) return false;
            snprintf(acc, sizeof(acc), "%s", tmp);
        }
    }
    if (mem.disp != 0 || !has) {
        char db[32];
        if (!has) {
            mba_fmt_u64((uint64_t)mem.disp, acc, sizeof(acc));
        } else if (mem.disp < 0 && (uint64_t)mem.disp != 0x8000000000000000ULL) {
            mba_fmt_u64((uint64_t)0 - (uint64_t)mem.disp, db, sizeof(db));
            char tmp[MBA_MAX_EXPR];
            if (!mba_fmt_bin(acc, "-", db, tmp, sizeof(tmp))) return false;
            snprintf(acc, sizeof(acc), "%s", tmp);
        } else {
            mba_fmt_u64((uint64_t)mem.disp, db, sizeof(db));
            char tmp[MBA_MAX_EXPR];
            if (!mba_fmt_bin(acc, "+", db, tmp, sizeof(tmp))) return false;
            snprintf(acc, sizeof(acc), "%s", tmp);
        }
    }
    snprintf(dst, max, "%s", acc);
    return true;
}

static void mba_check_reg(mba_res *out, uint64_t va, int r, mba_bstate *st) {
    if (r == 4) return; // skip rsp stack adjustments
    if (!mba_has_bitwise(st->reg[r])) return;

    mba_ast ast;
    if (!mba_parse_expr(st->reg[r], NULL, &ast)) return;
    if (ast.nops < 3 || ast.nvar < 1 || ast.nvar > 4) return;

    char simple[96] = "";
    int saved = 0;
    if (!mba_simplify_expr(st->reg[r], simple, sizeof(simple), &saved) || saved < 2) return;

    char clean_orig[MBA_MAX_EXPR];
    mba_strip_parens(st->reg[r], clean_orig, sizeof(clean_orig));

    if (strlen(clean_orig) < sizeof(out->hits[0].orig)) {
        int dup = 0;
        for (int i = 0; i < out->nhit; i++) {
            if (out->hits[i].va == va ||
                (strcmp(out->hits[i].orig, clean_orig) == 0 && strcmp(out->hits[i].simple, simple) == 0)) {
                dup = 1;
                break;
            }
        }
        if (!dup && out->nhit < 64) {
            mba_hit *h = &out->hits[out->nhit++];
            h->va = va;
            snprintf(h->orig, sizeof(h->orig), "%s", clean_orig);
            snprintf(h->simple, sizeof(h->simple), "%s", simple);
            h->ops_saved = saved;
        }
    }

    snprintf(st->reg[r], sizeof(st->reg[r]), "%s", simple);
}

static void mba_slot_invalidate_base(mba_bstate *st, int reg_id) {
    if (!st) return;
    if (reg_id < 0) {
        st->nslot = 0;
        return;
    }
    int keep = 0;
    for (int i = 0; i < st->nslot; i++) {
        const mba_slot *sl = &st->slots[i];
        if (sl->base < 0 || sl->base == reg_id) continue;
        if (keep != i) st->slots[keep] = st->slots[i];
        keep++;
    }
    st->nslot = keep;
}

static void mba_clobber_reg(mba_bstate *st, int reg_id, int bits) {
    if (!st || reg_id < 0 || reg_id >= 16) return;
    mba_fresh_var(st, st->reg[reg_id], sizeof(st->reg[reg_id]));
    st->bits[reg_id] = (uint8_t)((bits == 32) ? 32 : 64);
    mba_slot_invalidate_base(st, reg_id);
}

static void mba_scan_blk(const ana_ctx *a, const grp_cfg *g, uint32_t bi, mba_res *out) {
    mba_bstate st;
    memset(&st, 0, sizeof(st));
    for (int i = 0; i < 16; i++) {
        snprintf(st.reg[i], sizeof(st.reg[i]), "%s", cff_r64[i]);
        st.bits[i] = 64;
    }

    const grp_blk *b = &g->blks[bi];
    for (uint32_t k = 0; k < b->ins_count; k++) {
        const x86_ins *in = &g->ins[b->ins_first + k];
        const char *m = in->mnem;

        if (in->flow == X86_FLOW_CALL) {
            static const int vol[7] = {0, 1, 2, 8, 9, 10, 11};
            for (int v = 0; v < 7; v++) {
                mba_clobber_reg(&st, vol[v], 64);
            }
            if (a && a->bin.bits == 64 && a->bin.fmt != BIN_PE64) {
                mba_clobber_reg(&st, 6, 64);
                mba_clobber_reg(&st, 7, 64);
            }
            st.nslot = 0;
            continue;
        }
        if (in->flow == X86_FLOW_JMP || in->flow == X86_FLOW_JCC ||
            in->flow == X86_FLOW_RET || in->flow == X86_FLOW_TRAP) {
            continue;
        }

        const char *bm = m;
        bool has_rep = false;
        if (strncmp(bm, "lock ", 5) == 0) bm += 5;
        if (strncmp(bm, "repe ", 5) == 0) { bm += 5; has_rep = true; }
        else if (strncmp(bm, "repne ", 6) == 0) { bm += 6; has_rep = true; }
        else if (strncmp(bm, "rep ", 4) == 0) { bm += 4; has_rep = true; }

        if (strcmp(bm, "cmp") == 0 || strcmp(bm, "test") == 0 ||
            strcmp(bm, "nop") == 0 || strcmp(bm, "pause") == 0 ||
            strcmp(bm, "endbr64") == 0 || strcmp(bm, "endbr32") == 0 ||
            strcmp(bm, "bt") == 0 || strcmp(bm, "out") == 0) {
            continue;
        }

        char s0[76], s1[76], s2[76];
        int nops = cff_split_ops(in->ops, s0, s1, s2);
        int b0 = 0, b1 = 0;
        int r0 = (nops >= 1) ? cff_reg_id(s0, &b0) : -1;
        int r1 = (nops >= 2) ? cff_reg_id(s1, &b1) : -1;

        if (strcmp(bm, "push") == 0 || strcmp(bm, "pusha") == 0 || strcmp(bm, "pushad") == 0 ||
            strcmp(bm, "pushf") == 0 || strcmp(bm, "pushfd") == 0 || strcmp(bm, "pushfq") == 0) {
            mba_clobber_reg(&st, 4, 64);
            st.nslot = 0;
            continue;
        }
        if (strcmp(bm, "pop") == 0 || strcmp(bm, "popf") == 0 ||
            strcmp(bm, "popfd") == 0 || strcmp(bm, "popfq") == 0) {
            mba_clobber_reg(&st, 4, 64);
            if (strcmp(bm, "pop") == 0) {
                if (r0 >= 0 && r0 != 4) {
                    mba_clobber_reg(&st, r0, b0);
                } else if (r0 < 0 && nops >= 1) {
                    cff_mem mem;
                    if (cff_parse_mem(s0, &mem)) {
                        mba_slot_invalidate_mem(&st, &mem, mem.bits ? mem.bits : 64);
                    } else if (strchr(s0, '[') != NULL) {
                        st.nslot = 0;
                    }
                }
            }
            continue;
        }
        if (strcmp(bm, "popa") == 0 || strcmp(bm, "popad") == 0) {
            for (int r = 0; r < 8; r++) mba_clobber_reg(&st, r, 64);
            continue;
        }
        if (strcmp(bm, "leave") == 0) {
            mba_clobber_reg(&st, 4, 64);
            mba_clobber_reg(&st, 5, 64);
            continue;
        }
        if (strcmp(bm, "enter") == 0) {
            mba_clobber_reg(&st, 4, 64);
            mba_clobber_reg(&st, 5, 64);
            st.nslot = 0;
            continue;
        }

        if (strcmp(bm, "aam") == 0 || strcmp(bm, "aad") == 0 ||
            (nops == 0 && (strcmp(bm, "cbw") == 0 || strcmp(bm, "cwde") == 0 || strcmp(bm, "cdqe") == 0 ||
                           strcmp(bm, "lahf") == 0 || strcmp(bm, "xlatb") == 0 || strcmp(bm, "xlat") == 0 ||
                           strcmp(bm, "daa") == 0 || strcmp(bm, "das") == 0 ||
                           strcmp(bm, "aaa") == 0 || strcmp(bm, "aas") == 0 || strcmp(bm, "salc") == 0))) {
            mba_clobber_reg(&st, 0, 64);
            continue;
        }
        if (nops == 0) {
            if (strcmp(bm, "cwd") == 0 || strcmp(bm, "cdq") == 0 || strcmp(bm, "cqo") == 0) {
                mba_clobber_reg(&st, 2, 64);
                continue;
            }
            if (strcmp(bm, "rdtsc") == 0 || strcmp(bm, "rdmsr") == 0 || strcmp(bm, "rdpmc") == 0 ||
                strcmp(bm, "xgetbv") == 0 || strcmp(bm, "rdpkru") == 0 || strcmp(bm, "rdpru") == 0) {
                mba_clobber_reg(&st, 0, 64);
                mba_clobber_reg(&st, 2, 64);
                continue;
            }
            if (strcmp(bm, "rdtscp") == 0) {
                mba_clobber_reg(&st, 0, 64);
                mba_clobber_reg(&st, 1, 64);
                mba_clobber_reg(&st, 2, 64);
                continue;
            }
            if (strcmp(bm, "cpuid") == 0 || strcmp(bm, "getsec") == 0) {
                mba_clobber_reg(&st, 0, 64);
                mba_clobber_reg(&st, 1, 64);
                mba_clobber_reg(&st, 2, 64);
                mba_clobber_reg(&st, 3, 64);
                continue;
            }
            if (strcmp(bm, "syscall") == 0 || strcmp(bm, "sysret") == 0 ||
                strcmp(bm, "sysenter") == 0 || strcmp(bm, "sysexit") == 0 ||
                strcmp(bm, "vmcall") == 0 || strcmp(bm, "vmmcall") == 0 ||
                strcmp(bm, "encls") == 0 || strcmp(bm, "enclu") == 0 || strcmp(bm, "pconfig") == 0) {
                static const int sys_vol[10] = {0, 1, 2, 3, 6, 7, 8, 9, 10, 11};
                for (int i = 0; i < 10; i++) mba_clobber_reg(&st, sys_vol[i], 64);
                st.nslot = 0;
                continue;
            }
            if (strcmp(bm, "movsb") == 0 || strcmp(bm, "movsw") == 0 ||
                strcmp(bm, "movsd") == 0 || strcmp(bm, "movsq") == 0) {
                mba_clobber_reg(&st, 6, 64);
                mba_clobber_reg(&st, 7, 64);
                if (has_rep) mba_clobber_reg(&st, 1, 64);
                st.nslot = 0;
                continue;
            }
            if (strcmp(bm, "stosb") == 0 || strcmp(bm, "stosw") == 0 ||
                strcmp(bm, "stosd") == 0 || strcmp(bm, "stosq") == 0) {
                mba_clobber_reg(&st, 7, 64);
                if (has_rep) mba_clobber_reg(&st, 1, 64);
                st.nslot = 0;
                continue;
            }
            if (strcmp(bm, "lodsb") == 0 || strcmp(bm, "lodsw") == 0 ||
                strcmp(bm, "lodsd") == 0 || strcmp(bm, "lodsq") == 0) {
                mba_clobber_reg(&st, 0, 64);
                mba_clobber_reg(&st, 6, 64);
                if (has_rep) mba_clobber_reg(&st, 1, 64);
                continue;
            }
            if (strcmp(bm, "cmpsb") == 0 || strcmp(bm, "cmpsw") == 0 ||
                strcmp(bm, "cmpsd") == 0 || strcmp(bm, "cmpsq") == 0) {
                mba_clobber_reg(&st, 6, 64);
                mba_clobber_reg(&st, 7, 64);
                if (has_rep) mba_clobber_reg(&st, 1, 64);
                continue;
            }
            if (strcmp(bm, "scasb") == 0 || strcmp(bm, "scasw") == 0 ||
                strcmp(bm, "scasd") == 0 || strcmp(bm, "scasq") == 0) {
                mba_clobber_reg(&st, 7, 64);
                if (has_rep) mba_clobber_reg(&st, 1, 64);
                continue;
            }
            if (strcmp(bm, "insb") == 0 || strcmp(bm, "insw") == 0 || strcmp(bm, "insd") == 0) {
                mba_clobber_reg(&st, 7, 64);
                if (has_rep) mba_clobber_reg(&st, 1, 64);
                st.nslot = 0;
                continue;
            }
            if (strcmp(bm, "outsb") == 0 || strcmp(bm, "outsw") == 0 || strcmp(bm, "outsd") == 0) {
                mba_clobber_reg(&st, 6, 64);
                if (has_rep) mba_clobber_reg(&st, 1, 64);
                continue;
            }
            if (strcmp(bm, "sahf") == 0 || strcmp(bm, "clc") == 0 || strcmp(bm, "stc") == 0 ||
                strcmp(bm, "cmc") == 0 || strcmp(bm, "cld") == 0 || strcmp(bm, "std") == 0 ||
                strcmp(bm, "cli") == 0 || strcmp(bm, "sti") == 0 || strcmp(bm, "fwait") == 0 ||
                strcmp(bm, "emms") == 0 || strcmp(bm, "vzeroupper") == 0 || strcmp(bm, "vzeroall") == 0 ||
                strcmp(bm, "lfence") == 0 || strcmp(bm, "mfence") == 0 || strcmp(bm, "sfence") == 0 ||
                strcmp(bm, "clts") == 0 || strcmp(bm, "xtest") == 0 || strcmp(bm, "xend") == 0) {
                continue;
            }
        }

        if (nops == 1 && (strcmp(bm, "mul") == 0 || strcmp(bm, "imul") == 0 ||
                          strcmp(bm, "div") == 0 || strcmp(bm, "idiv") == 0)) {
            int wbits = 0;
            if (r0 >= 0) {
                wbits = b0;
            } else {
                cff_mem mem;
                wbits = (cff_parse_mem(s0, &mem) && mem.bits) ? mem.bits : 64;
            }
            mba_clobber_reg(&st, 0, (wbits == 32) ? 32 : 64);
            if (wbits != 8) {
                mba_clobber_reg(&st, 2, (wbits == 32) ? 32 : 64);
            }
            continue;
        }
        if (strcmp(bm, "cmpxchg8b") == 0 || strcmp(bm, "cmpxchg16b") == 0) {
            mba_clobber_reg(&st, 0, 64);
            mba_clobber_reg(&st, 2, 64);
            cff_mem mem;
            if (nops >= 1 && cff_parse_mem(s0, &mem)) {
                mba_slot_invalidate_mem(&st, &mem, (strcmp(bm, "cmpxchg16b") == 0) ? 128 : 64);
            } else {
                st.nslot = 0;
            }
            continue;
        }

        if (strcmp(bm, "xchg") == 0) {
            if (r0 >= 0 && r1 >= 0) {
                if (b0 < 32 || b1 < 32 || mba_is_hi8_reg(s0) || mba_is_hi8_reg(s1)) {
                    mba_clobber_reg(&st, r0, 64);
                    mba_clobber_reg(&st, r1, 64);
                } else if (b0 == 32 || b1 == 32) {
                    char e0[MBA_MAX_EXPR], e1[MBA_MAX_EXPR];
                    bool ok0 = mba_eval_op_str_w(&st, s0, 32, e0, sizeof(e0));
                    bool ok1 = mba_eval_op_str_w(&st, s1, 32, e1, sizeof(e1));
                    if (ok0 && ok1) {
                        snprintf(st.reg[r0], sizeof(st.reg[r0]), "%s", e1);
                        snprintf(st.reg[r1], sizeof(st.reg[r1]), "%s", e0);
                    } else {
                        mba_fresh_var(&st, st.reg[r0], sizeof(st.reg[r0]));
                        mba_fresh_var(&st, st.reg[r1], sizeof(st.reg[r1]));
                    }
                    st.bits[r0] = 32;
                    st.bits[r1] = 32;
                    mba_slot_invalidate_base(&st, r0);
                    mba_slot_invalidate_base(&st, r1);
                } else {
                    char tmp[MBA_MAX_EXPR];
                    uint8_t tb = st.bits[r0];
                    snprintf(tmp, sizeof(tmp), "%s", st.reg[r0]);
                    snprintf(st.reg[r0], sizeof(st.reg[r0]), "%s", st.reg[r1]);
                    st.bits[r0] = st.bits[r1];
                    snprintf(st.reg[r1], sizeof(st.reg[r1]), "%s", tmp);
                    st.bits[r1] = tb;
                    if (r0 != r1) {
                        mba_slot_invalidate_base(&st, r0);
                        mba_slot_invalidate_base(&st, r1);
                    }
                }
            } else {
                cff_mem mem;
                if (r0 >= 0) {
                    mba_clobber_reg(&st, r0, b0);
                    mba_slot_invalidate_mem(&st, (nops >= 2 && cff_parse_mem(s1, &mem)) ? &mem : NULL, b0);
                } else if (r1 >= 0) {
                    mba_clobber_reg(&st, r1, b1);
                    mba_slot_invalidate_mem(&st, (nops >= 1 && cff_parse_mem(s0, &mem)) ? &mem : NULL, b1);
                } else {
                    st.nslot = 0;
                }
            }
            continue;
        }

        if ((strcmp(bm, "mov") == 0 || strcmp(bm, "movabs") == 0 ||
             strcmp(bm, "movzx") == 0 || strcmp(bm, "movsx") == 0 || strcmp(bm, "movsxd") == 0) && nops >= 2) {
            if (r0 >= 0) {
                if (b0 < 32 || mba_is_hi8_reg(s0)) {
                    mba_fresh_var(&st, st.reg[r0], sizeof(st.reg[r0]));
                    st.bits[r0] = 64;
                } else if (strcmp(bm, "movsx") == 0 || strcmp(bm, "movsxd") == 0) {
                    mba_fresh_var(&st, st.reg[r0], sizeof(st.reg[r0]));
                    st.bits[r0] = (uint8_t)((b0 == 32) ? 32 : 64);
                } else if (strcmp(bm, "movzx") == 0) {
                    int src_w = 0;
                    cff_mem mem;
                    if (r1 >= 0 && !mba_is_hi8_reg(s1)) src_w = b1;
                    else if (cff_parse_mem(s1, &mem)) src_w = mem.bits;
                    char rhs[MBA_MAX_EXPR];
                    if ((src_w == 8 || src_w == 16) && mba_eval_op_str_w(&st, s1, src_w, rhs, sizeof(rhs))) {
                        snprintf(st.reg[r0], sizeof(st.reg[r0]), "%s", rhs);
                        st.bits[r0] = (uint8_t)src_w;
                    } else {
                        mba_fresh_var(&st, st.reg[r0], sizeof(st.reg[r0]));
                        st.bits[r0] = (uint8_t)((b0 == 32) ? 32 : 64);
                    }
                } else {
                    char rhs[MBA_MAX_EXPR];
                    if (mba_eval_op_str_w(&st, s1, b0, rhs, sizeof(rhs))) {
                        snprintf(st.reg[r0], sizeof(st.reg[r0]), "%s", rhs);
                        st.bits[r0] = (uint8_t)b0;
                    } else {
                        mba_fresh_var(&st, st.reg[r0], sizeof(st.reg[r0]));
                        st.bits[r0] = (uint8_t)b0;
                    }
                }
                mba_slot_invalidate_base(&st, r0);
            } else {
                cff_mem mem;
                if (cff_parse_mem(s0, &mem)) {
                    int mb = mem.bits ? mem.bits : (r1 >= 0 ? b1 : 64);
                    mba_slot_invalidate_mem(&st, &mem, mb);
                    char rhs[MBA_MAX_EXPR];
                    if (strcmp(bm, "mov") == 0 && !mem.has_seg && mem.base >= 0 && mem.idx < 0 &&
                        mb >= 32 && mba_eval_op_str_w(&st, s1, mb, rhs, sizeof(rhs))) {
                        mba_slot_store_w(&st, mem.base, mem.disp, mb, rhs);
                    }
                } else {
                    st.nslot = 0;
                }
            }
            continue;
        }

        if (strcmp(bm, "xadd") == 0 && r1 >= 0) {
            mba_clobber_reg(&st, r1, b1);
        } else if (strcmp(bm, "cmpxchg") == 0) {
            mba_clobber_reg(&st, 0, 64);
        } else if (strcmp(bm, "mulx") == 0 && r1 >= 0) {
            mba_clobber_reg(&st, r1, b1);
        }

        if (r0 < 0) {
            if (strcmp(bm, "fxsave") == 0 || strcmp(bm, "fxsave64") == 0 ||
                strcmp(bm, "xsave") == 0 || strcmp(bm, "xsave64") == 0 ||
                strcmp(bm, "xsavec") == 0 || strcmp(bm, "xsavec64") == 0 ||
                strcmp(bm, "xsaves") == 0 || strcmp(bm, "xsaves64") == 0 ||
                strcmp(bm, "xsaveopt") == 0 || strcmp(bm, "xsaveopt64") == 0 ||
                strcmp(bm, "fnsave") == 0 || strcmp(bm, "fsave") == 0 ||
                strcmp(bm, "fnstenv") == 0 || strcmp(bm, "fstenv") == 0 ||
                strcmp(bm, "sgdt") == 0 || strcmp(bm, "sidt") == 0 || strcmp(bm, "vmptrst") == 0) {
                st.nslot = 0;
                continue;
            }
            cff_mem mem;
            if (nops >= 1 && cff_parse_mem(s0, &mem)) {
                int mb = mem.bits ? mem.bits : (r1 >= 0 ? b1 : 64);
                mba_slot_invalidate_mem(&st, &mem, mb);
            } else if (nops == 0 || strchr(s0, '[') != NULL) {
                st.nslot = 0;
            }
            continue;
        }

        if (b0 < 32 || mba_is_hi8_reg(s0)) {
            mba_clobber_reg(&st, r0, 64);
            continue;
        }

        char next_expr[MBA_MAX_EXPR] = "";
        bool updated = false;

        if ((strcmp(bm, "xor") == 0 || strcmp(bm, "sub") == 0) && r1 == r0) {
            snprintf(st.reg[r0], sizeof(st.reg[r0]), "0");
            st.bits[r0] = (uint8_t)b0;
            mba_slot_invalidate_base(&st, r0);
            continue;
        }

        char lhs_expr[MBA_MAX_EXPR];
        bool lhs_ok = true;
        if (b0 == 32 && st.bits[r0] > 32) {
            lhs_ok = mba_mask_expr(st.reg[r0], 32, lhs_expr, sizeof(lhs_expr));
        } else {
            int w = snprintf(lhs_expr, sizeof(lhs_expr), "%s", st.reg[r0]);
            lhs_ok = (w > 0 && (size_t)w < sizeof(lhs_expr));
        }

        bool need_mask32 = false;
        if (strcmp(bm, "lea") == 0 && nops >= 2) {
            updated = mba_build_lea(&st, in, s1, next_expr, sizeof(next_expr));
            if (b0 == 32) need_mask32 = true;
        } else if (strcmp(bm, "not") == 0 && lhs_ok) {
            updated = mba_fmt_un('~', lhs_expr, next_expr, sizeof(next_expr));
            if (b0 == 32) need_mask32 = true;
        } else if (strcmp(bm, "neg") == 0 && lhs_ok) {
            updated = mba_fmt_un('-', lhs_expr, next_expr, sizeof(next_expr));
            if (b0 == 32) need_mask32 = true;
        } else if (strcmp(bm, "inc") == 0 && lhs_ok) {
            updated = mba_fmt_bin(lhs_expr, "+", "1", next_expr, sizeof(next_expr));
            if (b0 == 32) need_mask32 = true;
        } else if (strcmp(bm, "dec") == 0 && lhs_ok) {
            updated = mba_fmt_bin(lhs_expr, "-", "1", next_expr, sizeof(next_expr));
            if (b0 == 32) need_mask32 = true;
        } else if (strcmp(bm, "imul") == 0 && nops == 3) {
            char a1[MBA_MAX_EXPR], a2[MBA_MAX_EXPR];
            if (mba_eval_op_str_w(&st, s1, b0, a1, sizeof(a1)) &&
                mba_eval_op_str_w(&st, s2, b0, a2, sizeof(a2))) {
                updated = mba_fmt_bin(a1, "*", a2, next_expr, sizeof(next_expr));
                if (b0 == 32) need_mask32 = true;
            }
        } else if (nops >= 2 && lhs_ok) {
            const char *op = NULL;
            if (strcmp(bm, "add") == 0) { op = "+"; need_mask32 = (b0 == 32); }
            else if (strcmp(bm, "sub") == 0) { op = "-"; need_mask32 = (b0 == 32); }
            else if (strcmp(bm, "xor") == 0) op = "^";
            else if (strcmp(bm, "and") == 0) op = "&";
            else if (strcmp(bm, "or") == 0)  op = "|";
            else if (strcmp(bm, "imul") == 0) { op = "*"; need_mask32 = (b0 == 32); }
            else if (strcmp(bm, "shl") == 0 || strcmp(bm, "sal") == 0) { op = "<<"; need_mask32 = (b0 == 32); }

            if (op) {
                char rhs[MBA_MAX_EXPR];
                if (mba_eval_op_str_w(&st, s1, b0, rhs, sizeof(rhs))) {
                    if (strcmp(op, "<<") == 0) {
                        static const mba_ast empty_ref = {0};
                        uint64_t smask = (b0 == 32) ? 31ULL : 63ULL;
                        uint64_t imm_cnt = 0;
                        mba_ast rast;
                        if (cff_parse_imm(rhs, &imm_cnt)) {
                            mba_fmt_u64(imm_cnt & smask, rhs, sizeof(rhs));
                            updated = mba_fmt_bin(lhs_expr, op, rhs, next_expr, sizeof(next_expr));
                        } else if (mba_parse_expr(rhs, &empty_ref, &rast)) {
                            uint64_t cnt_val = mba_eval_node(&rast, rast.root, NULL);
                            mba_fmt_u64(cnt_val & smask, rhs, sizeof(rhs));
                            updated = mba_fmt_bin(lhs_expr, op, rhs, next_expr, sizeof(next_expr));
                        } else {
                            char mrhs[MBA_MAX_EXPR];
                            if (mba_fmt_bin(rhs, "&", (b0 == 32) ? "31" : "63", mrhs, sizeof(mrhs))) {
                                updated = mba_fmt_bin(lhs_expr, op, mrhs, next_expr, sizeof(next_expr));
                            }
                        }
                    } else {
                        updated = mba_fmt_bin(lhs_expr, op, rhs, next_expr, sizeof(next_expr));
                    }
                }
            }
        }

        if (updated && need_mask32) {
            char masked[MBA_MAX_EXPR];
            if (mba_mask_expr(next_expr, 32, masked, sizeof(masked))) {
                snprintf(next_expr, sizeof(next_expr), "%s", masked);
            } else {
                updated = false;
            }
        }

        if (updated) {
            snprintf(st.reg[r0], sizeof(st.reg[r0]), "%s", next_expr);
            st.bits[r0] = (uint8_t)b0;
            mba_slot_invalidate_base(&st, r0);
            mba_check_reg(out, in->ip, r0, &st);
        } else {
            mba_clobber_reg(&st, r0, b0);
        }
    }
}

bool mba_scan_func(const ana_ctx *a, uint64_t va, mba_res *out) {
    if (!a || !out) return false;
    memset(out, 0, sizeof(*out));

    grp_cfg g = {0};
    if (!grp_build(a, va, 0, &g)) return false;
    cff_fixup_acc_alu(a, &g);

    out->func_va = g.func_va;
    for (uint32_t bi = 0; bi < g.nblk && out->nhit < 64; bi++) {
        mba_scan_blk(a, &g, bi, out);
    }

    grp_free(&g);
    return true;
}
