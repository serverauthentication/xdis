#include "ana.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define VM_MAX_HANDLERS 64
#define VM_MAX_HINS     48
#define VM_MAX_BLKS     256

typedef struct {
    int      kind;
    int      reg;
    int      idx;
    int      scale;
    int      bits;
    int64_t  disp;
    uint64_t uval;
    int      is_rip;
} vm_opr;

typedef struct {
    char     style[24];
    uint64_t disp_va;
    uint64_t disp_start;
    uint64_t disp_end;
    uint64_t latch_va;
    uint64_t table_va;
    int      disp_blk;
    int      vip_idx;
    int      score;
    uint64_t h_vas[VM_MAX_HANDLERS];
    uint32_t h_ops[VM_MAX_HANDLERS];
    int      nhandler;
} vm_cand;

typedef struct {
    x86_ins  ins[VM_MAX_HINS];
    int      count;
    int      meaningful;
    int      ends_ret;
    int      peek_vip_mod;
    int      peek_ret;
} vm_hinfo;

static const char *const vm_r64[16] = {
    "rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi",
    "r8","r9","r10","r11","r12","r13","r14","r15"
};

static const char *const vm_r32[16] = {
    "eax","ecx","edx","ebx","esp","ebp","esi","edi",
    "r8d","r9d","r10d","r11d","r12d","r13d","r14d","r15d"
};

static const char *vm_reg_name(int bits, int id) {
    if (id < 0 || id >= 16) return "";
    return (bits == 32) ? vm_r32[id] : vm_r64[id];
}

static int vm_reg_id(const char *s, int *bits) {
    static const char *const r16[16] = {
        "ax","cx","dx","bx","sp","bp","si","di",
        "r8w","r9w","r10w","r11w","r12w","r13w","r14w","r15w"
    };
    static const char *const r8[16] = {
        "al","cl","dl","bl","spl","bpl","sil","dil",
        "r8b","r9b","r10b","r11b","r12b","r13b","r14b","r15b"
    };
    static const char *const r8h[4] = {"ah","ch","dh","bh"};
    if (!s || !s[0]) return -1;
    for (int i = 0; i < 16; i++) {
        if (strcmp(s, vm_r64[i]) == 0) { if (bits) *bits = 64; return i; }
        if (strcmp(s, vm_r32[i]) == 0) { if (bits) *bits = 32; return i; }
        if (strcmp(s, r16[i]) == 0)    { if (bits) *bits = 16; return i; }
        if (strcmp(s, r8[i]) == 0)     { if (bits) *bits = 8;  return i; }
    }
    for (int i = 0; i < 4; i++) {
        if (strcmp(s, r8h[i]) == 0) { if (bits) *bits = 8; return i; }
    }
    return -1;
}

static void vm_trim(char *s) {
    char *p = s;
    while (*p == ' ' || *p == '\t') p++;
    if (p != s) memmove(s, p, strlen(p) + 1);
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\t')) s[--n] = 0;
}

static int vm_split_ops(const char *ops, char a[76], char b[76], char c[76]) {
    a[0] = b[0] = c[0] = 0;
    if (!ops || !ops[0]) return 0;
    const char *p1 = strchr(ops, ',');
    if (!p1) {
        snprintf(a, 76, "%s", ops);
        vm_trim(a);
        return 1;
    }
    size_t n1 = (size_t)(p1 - ops);
    if (n1 >= 75) n1 = 75;
    memcpy(a, ops, n1);
    a[n1] = 0;
    vm_trim(a);

    const char *p2 = strchr(p1 + 1, ',');
    if (!p2) {
        snprintf(b, 76, "%s", p1 + 1);
        vm_trim(b);
        return 2;
    }
    size_t n2 = (size_t)(p2 - (p1 + 1));
    if (n2 >= 75) n2 = 75;
    memcpy(b, p1 + 1, n2);
    b[n2] = 0;
    vm_trim(b);
    snprintf(c, 76, "%s", p2 + 1);
    vm_trim(c);
    return 3;
}

static void vm_parse_op(const char *raw, const x86_ins *ins, vm_opr *op) {
    memset(op, 0, sizeof(*op));
    op->reg = -1;
    op->idx = -1;
    op->scale = 1;
    if (!raw || !raw[0]) return;

    char buf[80];
    snprintf(buf, sizeof(buf), "%s", raw);
    vm_trim(buf);

    const char *p = buf;
    if (strncmp(p, "byte ptr ", 9) == 0)          { op->bits = 8;   p += 9; }
    else if (strncmp(p, "word ptr ", 9) == 0)     { op->bits = 16;  p += 9; }
    else if (strncmp(p, "dword ptr ", 10) == 0)   { op->bits = 32;  p += 10; }
    else if (strncmp(p, "qword ptr ", 10) == 0)   { op->bits = 64;  p += 10; }
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
            op->disp = (int64_t)op->uval;
            op->is_rip = (ins && ins->target_mem) ? 1 : 0;
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
                int b2 = 64;
                int r = vm_reg_id(tok, &b2);
                if (r >= 0) {
                    op->idx = r;
                    op->scale = atoi(star + 1);
                }
            } else if (strncmp(tok, "0x", 2) == 0 || isdigit((unsigned char)tok[0])) {
                uint64_t v = (strncmp(tok, "0x", 2) == 0) ? strtoull(tok + 2, NULL, 16) : strtoull(tok, NULL, 10);
                op->disp += (int64_t)sign * (int64_t)v;
            } else {
                int b2 = 64;
                int r = vm_reg_id(tok, &b2);
                if (r >= 0) {
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

    int rb = 64;
    int r = vm_reg_id(p, &rb);
    if (r >= 0) {
        op->kind = 1;
        op->reg = r;
        op->bits = rb;
    }
}

static bool vm_is_code_ptr(const bin_img *b, uint64_t va) {
    if (!va || !bin_is_exec(b, va)) return false;
    size_t av = 0;
    const uint8_t *p = bin_ptr(b, va, &av);
    if (!p || av == 0) return false;
    // reject zero-filled padding
    if (av >= 2 && p[0] == 0x00 && p[1] == 0x00) return false;
    return true;
}

static bool vm_is_bare_rip_mem(const x86_ins *in) {
    if (!in->has_target || !in->target_mem) return false;
    const char *lb = strchr(in->ops, '[');
    return lb && strncmp(lb + 1, "0x", 2) == 0 && !strchr(lb, '+') && !strchr(lb, '*');
}

static bool vm_is_ind_jmp(const x86_ins *in) {
    if (in->flow != X86_FLOW_JMP) return false;
    if (in->has_target && !in->target_mem) return false;
    if (vm_is_bare_rip_mem(in)) return false;
    return true;
}

static bool vm_is_ind_call(const x86_ins *in) {
    if (in->flow != X86_FLOW_CALL) return false;
    if (in->has_target && !in->target_mem) return false;
    if (vm_is_bare_rip_mem(in)) return false;
    return true;
}

static bool vm_is_boilerplate(const x86_ins *in) {
    const char *m = in->mnem;
    if (strcmp(m, "nop") == 0 || strcmp(m, "endbr64") == 0 ||
        strcmp(m, "endbr32") == 0 || strcmp(m, "pause") == 0 ||
        strcmp(m, "fnop") == 0) {
        return true;
    }
    char s0[76], s1[76], s2[76];
    int nops = vm_split_ops(in->ops, s0, s1, s2);
    if (nops == 2) {
        vm_opr o0, o1;
        vm_parse_op(s0, in, &o0);
        vm_parse_op(s1, in, &o1);
        if (strcmp(m, "xchg") == 0 && o0.kind == 1 && o1.kind == 1 && o0.reg == o1.reg) return true;
        if (strcmp(m, "and") == 0 && o0.kind == 1 && o0.reg == 4 && o1.kind == 2) {
            // stack alignment mask
            uint64_t lo = o1.uval & 0xFFULL;
            if (lo == 0xF0ULL || lo == 0xE0ULL || lo == 0xF8ULL) return true;
        }
        if ((strcmp(m, "add") == 0 || strcmp(m, "sub") == 0) && o0.kind == 1 && o1.kind == 2 && o1.uval == 0) {
            return true;
        }
        if (strcmp(m, "lea") == 0 && o0.kind == 1 && o1.kind == 3 &&
            o1.reg == o0.reg && o1.idx < 0 && o1.disp == 0) {
            return true;
        }
    }
    return false;
}

static int vm_blk_containing(const grp_cfg *g, uint64_t va) {
    uint32_t lo = 0, hi = g->nblk;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        if (g->blks[mid].end <= va) lo = mid + 1;
        else hi = mid;
    }
    if (lo < g->nblk && va >= g->blks[lo].start && va < g->blks[lo].end) return (int)lo;
    return -1;
}

static void vm_reach_from(const grp_cfg *g, uint32_t start, uint8_t vis[VM_MAX_BLKS]) {
    memset(vis, 0, VM_MAX_BLKS);
    if (start >= g->nblk || start >= VM_MAX_BLKS) return;
    uint32_t q[VM_MAX_BLKS];
    uint32_t qh = 0, qt = 0;
    vis[start] = 1;
    q[qt++] = start;
    while (qh < qt) {
        uint32_t u = q[qh++];
        for (uint32_t e = 0; e < g->nedge; e++) {
            if (g->edges[e].from != u) continue;
            uint32_t v = g->edges[e].to;
            if (v < VM_MAX_BLKS && !vis[v]) {
                vis[v] = 1;
                q[qt++] = v;
            }
        }
    }
}

static void vm_can_reach(const grp_cfg *g, uint32_t target, const uint8_t mask[VM_MAX_BLKS], uint8_t can[VM_MAX_BLKS]) {
    memset(can, 0, VM_MAX_BLKS);
    if (target >= g->nblk || target >= VM_MAX_BLKS) return;
    uint32_t q[VM_MAX_BLKS];
    uint32_t qh = 0, qt = 0;
    can[target] = 1;
    q[qt++] = target;
    while (qh < qt) {
        uint32_t v = q[qh++];
        for (uint32_t e = 0; e < g->nedge; e++) {
            if (g->edges[e].to != v) continue;
            uint32_t u = g->edges[e].from;
            if (u < VM_MAX_BLKS && !can[u] && (!mask || mask[u])) {
                can[u] = 1;
                q[qt++] = u;
            }
        }
    }
}

static bool vm_blk_in_loop(const grp_cfg *g, uint32_t bi) {
    if (bi >= g->nblk || bi >= VM_MAX_BLKS) return false;
    uint8_t vis[VM_MAX_BLKS];
    memset(vis, 0, sizeof(vis));
    uint32_t q[VM_MAX_BLKS];
    uint32_t qh = 0, qt = 0;
    for (uint32_t e = 0; e < g->nedge; e++) {
        if (g->edges[e].from != bi) continue;
        uint32_t v = g->edges[e].to;
        if (v == bi) return true;
        if (v < VM_MAX_BLKS && !vis[v]) {
            vis[v] = 1;
            q[qt++] = v;
        }
    }
    while (qh < qt) {
        uint32_t u = q[qh++];
        for (uint32_t e = 0; e < g->nedge; e++) {
            if (g->edges[e].from != u) continue;
            uint32_t v = g->edges[e].to;
            if (v == bi) return true;
            if (v < VM_MAX_BLKS && !vis[v]) {
                vis[v] = 1;
                q[qt++] = v;
            }
        }
    }
    return false;
}

static bool vm_check_lods(const x86_ins *in, int *stride_out) {
    const char *m = in->mnem;
    if (strcmp(m, "lodsb") == 0) { if (stride_out) *stride_out = 1; return true; }
    if (strcmp(m, "lodsw") == 0) { if (stride_out) *stride_out = 2; return true; }
    if (strcmp(m, "lodsd") == 0) { if (stride_out) *stride_out = 4; return true; }
    if (strcmp(m, "lodsq") == 0) { if (stride_out) *stride_out = 8; return true; }
    return false;
}

static bool vm_check_vip_adv(const x86_ins *in, int *adv_reg, int *step_out) {
    int st = 0;
    if (vm_check_lods(in, &st)) {
        *adv_reg = 6;
        if (step_out) *step_out = st;
        return true;
    }
    char s0[76], s1[76], s2[76];
    int nops = vm_split_ops(in->ops, s0, s1, s2);
    vm_opr o0, o1;
    vm_parse_op(s0, in, &o0);
    vm_parse_op(s1, in, &o1);

    if (strcmp(in->mnem, "inc") == 0 && nops == 1 && o0.kind == 1 && o0.reg != 4) {
        *adv_reg = o0.reg;
        if (step_out) *step_out = 1;
        return true;
    }
    if (strcmp(in->mnem, "add") == 0 && nops == 2 && o0.kind == 1 && o0.reg != 4 && o1.kind == 2) {
        if (o1.uval == 1 || o1.uval == 2 || o1.uval == 4 || o1.uval == 8) {
            *adv_reg = o0.reg;
            if (step_out) *step_out = (int)o1.uval;
            return true;
        }
    }
    if (strcmp(in->mnem, "lea") == 0 && nops == 2 && o0.kind == 1 && o0.reg != 4 &&
        o1.kind == 3 && o1.reg == o0.reg && o1.idx < 0) {
        if (o1.disp == 1 || o1.disp == 2 || o1.disp == 4 || o1.disp == 8) {
            *adv_reg = o0.reg;
            if (step_out) *step_out = (int)o1.disp;
            return true;
        }
    }
    return false;
}

static bool vm_scan_vip_insns(const x86_ins *ins, uint32_t count, int *vip_out, int *stride_out) {
    uint8_t deref[16] = {0};
    uint8_t adv[16] = {0};
    int adv_step[16] = {0};

    for (uint32_t k = 0; k < count; k++) {
        const x86_ins *in = &ins[k];
        int st = 0;
        if (vm_check_lods(in, &st)) {
            if (vip_out) *vip_out = 6;
            if (stride_out) *stride_out = st;
            return true;
        }
        int ar = -1;
        if (vm_check_vip_adv(in, &ar, &st) && ar >= 0 && ar < 16) {
            adv[ar] = 1;
            adv_step[ar] = st;
        }
        if (strcmp(in->mnem, "movzx") == 0 || strcmp(in->mnem, "movsx") == 0 ||
            strcmp(in->mnem, "mov") == 0 || strcmp(in->mnem, "movsxd") == 0) {
            char s0[76], s1[76], s2[76];
            if (vm_split_ops(in->ops, s0, s1, s2) >= 2) {
                vm_opr o0, o1;
                vm_parse_op(s0, in, &o0);
                vm_parse_op(s1, in, &o1);
                if (o0.kind == 1 && o1.kind == 3 && !o1.is_rip) {
                    if (o1.reg >= 0 && o1.reg != 4 && o1.scale == 1 && o1.disp >= -8 && o1.disp <= 8) {
                        deref[o1.reg] = 1;
                    }
                    if (o1.idx >= 0 && o1.idx != 4 && o1.scale <= 4 && o1.disp >= -8 && o1.disp <= 8) {
                        deref[o1.idx] = 1;
                    }
                }
            }
        }
    }

    for (int r = 0; r < 16; r++) {
        if (r == 4) continue;
        if (deref[r] && adv[r]) {
            if (vip_out) *vip_out = r;
            if (stride_out) *stride_out = adv_step[r];
            return true;
        }
    }
    return false;
}

static bool vm_find_vip_near(const grp_cfg *g, uint32_t bi, int *vip_out, int *stride_out, int *fetch_blk_out) {
    const grp_blk *b = &g->blks[bi];
    if (vm_scan_vip_insns(g->ins + b->ins_first, b->ins_count, vip_out, stride_out)) {
        if (fetch_blk_out) *fetch_blk_out = (int)bi;
        return true;
    }

    // check immediate predecessors when bounds-check splits fetch from jmp
    for (uint32_t e = 0; e < g->nedge; e++) {
        if (g->edges[e].to != bi) continue;
        uint32_t p = g->edges[e].from;
        const grp_blk *pb = &g->blks[p];
        if (vm_scan_vip_insns(g->ins + pb->ins_first, pb->ins_count, vip_out, stride_out)) {
            if (fetch_blk_out) *fetch_blk_out = (int)p;
            return true;
        }
        // combined pred + bi sequence for split fetch / advance
        x86_ins comb[64];
        uint32_t nc = 0;
        uint32_t pstart = (pb->ins_count > 32) ? (pb->ins_count - 32) : 0;
        for (uint32_t k = pstart; k < pb->ins_count && nc < 64; k++) comb[nc++] = g->ins[pb->ins_first + k];
        for (uint32_t k = 0; k < b->ins_count && nc < 64; k++) comb[nc++] = g->ins[b->ins_first + k];
        if (vm_scan_vip_insns(comb, nc, vip_out, stride_out)) {
            if (fetch_blk_out) *fetch_blk_out = (int)p;
            return true;
        }
    }
    return false;
}

static bool vm_is_addr(const bin_img *b, uint64_t va) {
    return va && (va == b->base || bin_sec_at(b, va) != NULL);
}

static void vm_step_addr_state(const ana_ctx *a, const x86_ins *in,
                               uint64_t raddr[16], uint64_t rtbl[16], uint64_t rbase[16]) {
    char s0[76], s1[76], s2[76];
    int nops = vm_split_ops(in->ops, s0, s1, s2);
    if (nops < 1) return;
    vm_opr o0, o1;
    vm_parse_op(s0, in, &o0);
    vm_parse_op(s1, in, &o1);
    if (o0.kind != 1 || o0.reg < 0) return;

    int dst = o0.reg;
    const char *m = in->mnem;

    if (strcmp(m, "lea") == 0) {
        if (in->has_target && vm_is_addr(&a->bin, in->target)) {
            raddr[dst] = in->target;
            rtbl[dst] = 0;
            rbase[dst] = 0;
            return;
        }
        if (o1.kind == 3 && o1.reg >= 0 && raddr[o1.reg]) {
            uint64_t cand = raddr[o1.reg] + (uint64_t)o1.disp;
            if (o1.idx >= 0) {
                rtbl[dst] = cand;
                rbase[dst] = raddr[o1.reg];
            } else if (vm_is_addr(&a->bin, cand)) {
                raddr[dst] = cand;
            }
            return;
        }
        raddr[dst] = 0;
        return;
    }

    if (strcmp(m, "mov") == 0 || strcmp(m, "movabs") == 0 || strcmp(m, "movsxd") == 0 ||
        strcmp(m, "movzx") == 0 || strcmp(m, "movsx") == 0) {
        if (o1.kind == 2 && vm_is_addr(&a->bin, o1.uval)) {
            raddr[dst] = o1.uval;
            rtbl[dst] = 0;
            rbase[dst] = 0;
            return;
        }
        if (o1.kind == 1 && o1.reg >= 0) {
            raddr[dst] = raddr[o1.reg];
            rtbl[dst] = rtbl[o1.reg];
            rbase[dst] = rbase[o1.reg];
            return;
        }
        if (o1.kind == 3) {
            uint64_t tbl = 0, bva = 0;
            if (o1.reg >= 0 && raddr[o1.reg] && (o1.idx >= 0 || o1.disp != 0)) {
                uint64_t cand = raddr[o1.reg] + (uint64_t)o1.disp;
                if (bin_sec_at(&a->bin, cand)) {
                    tbl = cand;
                    bva = raddr[o1.reg];
                }
            } else if (o1.reg < 0 && o1.idx >= 0 && o1.disp > 0 && bin_sec_at(&a->bin, (uint64_t)o1.disp)) {
                tbl = (uint64_t)o1.disp;
            } else if (o1.reg >= 0 && rtbl[o1.reg] && o1.idx < 0 && o1.disp == 0) {
                tbl = rtbl[o1.reg];
                bva = rbase[o1.reg];
            }
            rtbl[dst] = tbl;
            rbase[dst] = bva;
            raddr[dst] = 0;
            return;
        }
        raddr[dst] = 0;
        rtbl[dst] = 0;
        return;
    }

    if (strcmp(m, "add") == 0 && nops == 2) {
        if (o1.kind == 1 && o1.reg >= 0) {
            if (rtbl[dst] && raddr[o1.reg]) {
                rbase[dst] = raddr[o1.reg];
                return;
            }
            if (raddr[dst] && rtbl[o1.reg]) {
                rtbl[dst] = rtbl[o1.reg];
                rbase[dst] = raddr[dst];
                raddr[dst] = 0;
                return;
            }
            if (raddr[dst] && !rtbl[dst]) {
                rtbl[dst] = raddr[dst];
                rbase[dst] = raddr[dst];
                return;
            }
        } else if (o1.kind == 2 && rtbl[dst] && vm_is_addr(&a->bin, o1.uval)) {
            rbase[dst] = o1.uval;
            return;
        }
    }
}

static void vm_track_reg_addrs(const ana_ctx *a, const grp_cfg *g, uint32_t bi,
                               uint64_t raddr[16], uint64_t rtbl[16], uint64_t rbase[16]) {
    memset(raddr, 0, sizeof(uint64_t) * 16);
    memset(rtbl, 0, sizeof(uint64_t) * 16);
    memset(rbase, 0, sizeof(uint64_t) * 16);

    // seed hoisted table bases from entry block
    if (bi != 0 && g->nblk > 0) {
        const grp_blk *b0 = &g->blks[0];
        for (uint32_t k = 0; k < b0->ins_count; k++) {
            vm_step_addr_state(a, &g->ins[b0->ins_first + k], raddr, rtbl, rbase);
        }
    }

    // apply immediate non-loop predecessors
    for (uint32_t e = 0; e < g->nedge; e++) {
        if (g->edges[e].to != bi) continue;
        uint32_t p = g->edges[e].from;
        if (p == 0 || p == bi) continue;
        const grp_blk *pb = &g->blks[p];
        for (uint32_t k = 0; k < pb->ins_count; k++) {
            vm_step_addr_state(a, &g->ins[pb->ins_first + k], raddr, rtbl, rbase);
        }
    }

    const grp_blk *b = &g->blks[bi];
    for (uint32_t k = 0; k + 1 < b->ins_count; k++) {
        vm_step_addr_state(a, &g->ins[b->ins_first + k], raddr, rtbl, rbase);
    }
}

static uint32_t vm_find_cmp_bound_blk(const grp_cfg *g, uint32_t bi) {
    const grp_blk *b = &g->blks[bi];
    if (b->ins_count == 0) return 0;
    const x86_ins *last = &g->ins[b->ins_first + b->ins_count - 1];
    if (last->flow != X86_FLOW_JCC) return 0;

    int add_one = 1;
    if (strcmp(last->mnem, "jae") == 0 || strcmp(last->mnem, "jge") == 0 ||
        strcmp(last->mnem, "jb") == 0 || strcmp(last->mnem, "jl") == 0) {
        add_one = 0;
    } else if (strcmp(last->mnem, "ja") != 0 && strcmp(last->mnem, "jg") != 0 &&
               strcmp(last->mnem, "jbe") != 0 && strcmp(last->mnem, "jle") != 0) {
        return 0;
    }

    for (int k = (int)b->ins_count - 2; k >= 0; k--) {
        const x86_ins *in = &g->ins[b->ins_first + (uint32_t)k];
        if (strcmp(in->mnem, "cmp") != 0) continue;
        char s0[76], s1[76], s2[76];
        if (vm_split_ops(in->ops, s0, s1, s2) < 2) continue;
        vm_opr o1;
        vm_parse_op(s1, in, &o1);
        if (o1.kind == 2 && o1.uval >= 2 && o1.uval <= 255) {
            return (uint32_t)o1.uval + (uint32_t)add_one;
        }
    }
    return 0;
}

static uint32_t vm_find_cmp_bound(const grp_cfg *g, uint32_t bi) {
    uint32_t bound = vm_find_cmp_bound_blk(g, bi);
    if (bound) return bound;
    for (uint32_t e = 0; e < g->nedge; e++) {
        if (g->edges[e].to != bi) continue;
        bound = vm_find_cmp_bound_blk(g, g->edges[e].from);
        if (bound) return bound;
    }
    return 0;
}

static bool vm_add_unique_handler(uint64_t *vas, uint32_t *ops, int *nh, uint64_t hva, uint32_t op) {
    for (int i = 0; i < *nh; i++) {
        if (vas[i] == hva) return false;
    }
    if (*nh >= VM_MAX_HANDLERS) return false;
    vas[*nh] = hva;
    ops[*nh] = op;
    (*nh)++;
    return true;
}

static int vm_read_table_mode(const ana_ctx *a, uint64_t table_va, uint64_t rel_base,
                              const bin_sec *fsec, uint32_t lim, int mode,
                              uint64_t *out_vas, uint32_t *out_ops, int *raw_cnt) {
    int psz = (a->bin.bits == 32) ? 4 : 8;
    int nh = 0;
    int raw = 0;
    for (uint32_t i = 0; i < lim; i++) {
        uint64_t target = 0;
        if (mode == 0) {
            if (bin_read(&a->bin, table_va + (uint64_t)i * (uint64_t)psz, (uint8_t *)&target, (size_t)psz) != (size_t)psz) break;
            if (target == table_va || !vm_is_code_ptr(&a->bin, target)) break;
        } else if (mode == 1) {
            // msvc 32-bit unsigned rva table
            uint32_t rva = 0;
            if (bin_read(&a->bin, table_va + (uint64_t)i * 4, (uint8_t *)&rva, 4) != 4) break;
            if (rva == 0) break;
            target = rel_base + (uint64_t)rva;
            if (target == table_va || !vm_is_code_ptr(&a->bin, target)) break;
            if (fsec && bin_sec_at(&a->bin, target) != fsec) break;
        } else {
            // pic 32-bit signed offset table
            int32_t off = 0;
            if (bin_read(&a->bin, table_va + (uint64_t)i * 4, (uint8_t *)&off, 4) != 4) break;
            if (off == 0 || off > 0x1000000 || off < -0x1000000) break;
            target = rel_base + (uint64_t)(int64_t)off;
            if (target == table_va || !vm_is_code_ptr(&a->bin, target)) break;
            if (fsec && bin_sec_at(&a->bin, target) != fsec) break;
        }
        raw++;
        vm_add_unique_handler(out_vas, out_ops, &nh, target, i);
    }
    if (raw_cnt) *raw_cnt = raw;
    return nh;
}

static int vm_read_table(const ana_ctx *a, uint64_t table_va, uint64_t rel_base, uint64_t func_va,
                         uint32_t bound, uint64_t *out_vas, uint32_t *out_ops, int *raw_cnt) {
    if (!table_va || !bin_sec_at(&a->bin, table_va)) {
        if (raw_cnt) *raw_cnt = 0;
        return 0;
    }
    uint32_t lim = (bound >= 2 && bound <= 256) ? bound : 256;
    const bin_sec *fsec = bin_sec_at(&a->bin, func_va);

    int raw = 0;
    int nh = vm_read_table_mode(a, table_va, 0, fsec, lim, 0, out_vas, out_ops, &raw);
    if (raw >= 2) {
        if (raw_cnt) *raw_cnt = raw;
        return nh;
    }

    uint64_t bases[3] = { rel_base, a->bin.base, table_va };
    for (int bi = 0; bi < 3; bi++) {
        if (!bases[bi]) continue;
        int dup = 0;
        for (int bj = 0; bj < bi; bj++) if (bases[bj] == bases[bi]) dup = 1;
        if (dup) continue;

        nh = vm_read_table_mode(a, table_va, bases[bi], fsec, lim, 1, out_vas, out_ops, &raw);
        if (raw >= 2) {
            if (raw_cnt) *raw_cnt = raw;
            return nh;
        }
        nh = vm_read_table_mode(a, table_va, bases[bi], fsec, lim, 2, out_vas, out_ops, &raw);
        if (raw >= 2) {
            if (raw_cnt) *raw_cnt = raw;
            return nh;
        }
    }
    if (raw_cnt) *raw_cnt = 0;
    return 0;
}

static bool vm_handler_returns_to_disp(const ana_ctx *a, const grp_cfg *g, uint64_t hva,
                                       uint32_t disp_blk, uint64_t *back_va_out) {
    uint64_t cur = hva;
    x86_ins in;
    for (int step = 0; step < VM_MAX_HINS; step++) {
        size_t av = 0;
        const uint8_t *p = bin_ptr(&a->bin, cur, &av);
        if (!p || av == 0) break;
        int n = arch_decode(a->bin.arch, p, av, cur, 1, 0, &in);
        if (n <= 0) break;
        if (in.flow == X86_FLOW_RET || in.flow == X86_FLOW_TRAP) return false;
        if (in.flow == X86_FLOW_JMP) {
            if (in.has_target && !in.target_mem) {
                int tb = vm_blk_containing(g, in.target);
                if (tb >= 0) {
                    uint8_t reach[VM_MAX_BLKS];
                    vm_reach_from(g, (uint32_t)tb, reach);
                    if (disp_blk < VM_MAX_BLKS && reach[disp_blk]) {
                        if (back_va_out && !*back_va_out) *back_va_out = in.target;
                        return true;
                    }
                }
            } else if (vm_is_ind_jmp(&in)) {
                return true;
            }
            return false;
        }
        cur += (uint64_t)n;
    }
    return false;
}

static void vm_eval_table_cand(const ana_ctx *a, const grp_cfg *g, uint32_t bi,
                               uint64_t table_va, uint64_t rel_base, uint32_t bound, vm_cand *best) {
    if (!table_va) return;
    uint64_t vas[VM_MAX_HANDLERS];
    uint32_t ops[VM_MAX_HANDLERS];
    int raw = 0;
    int nh = vm_read_table(a, table_va, rel_base, g->func_va, bound, vas, ops, &raw);
    if (nh < 2) return;

    int vip_idx = -1, stride = 0, fetch_blk = -1;
    bool has_vip = vm_find_vip_near(g, bi, &vip_idx, &stride, &fetch_blk);
    bool in_loop = vm_blk_in_loop(g, bi);

    int nback = 0;
    uint64_t back_va = 0;
    for (int i = 0; i < nh; i++) {
        if (vm_handler_returns_to_disp(a, g, vas[i], bi, &back_va)) nback++;
    }
    if (nback > 0) in_loop = true;

    if (!in_loop && raw < 3) return;
    if (raw < 3 && nback < 2) return;

    int score = 40 + nback * 20 + (has_vip ? 50 : 0) + (in_loop ? 30 : 0) + nh * 3;
    if (score <= best->score) return;

    const grp_blk *b = &g->blks[bi];
    const x86_ins *last = &g->ins[b->ins_first + b->ins_count - 1];

    memset(best, 0, sizeof(*best));
    snprintf(best->style, sizeof(best->style), "table-dispatch");
    best->disp_va = last->ip;
    best->disp_start = back_va ? back_va : ((fetch_blk >= 0) ? g->blks[fetch_blk].start : b->start);
    best->disp_end = b->end;
    best->table_va = table_va;
    best->disp_blk = (int)bi;
    best->vip_idx = has_vip ? vip_idx : -1;
    best->score = score;
    best->nhandler = nh;
    memcpy(best->h_vas, vas, (size_t)nh * sizeof(uint64_t));
    memcpy(best->h_ops, ops, (size_t)nh * sizeof(uint32_t));
}

static void vm_detect_table(const ana_ctx *a, const grp_cfg *g, vm_cand *best) {
    for (uint32_t bi = 0; bi < g->nblk; bi++) {
        const grp_blk *b = &g->blks[bi];
        if (b->ins_count == 0) continue;
        const x86_ins *last = &g->ins[b->ins_first + b->ins_count - 1];
        if (!vm_is_ind_jmp(last)) continue;

        uint64_t raddr[16], rtbl[16], rbase[16];
        vm_track_reg_addrs(a, g, bi, raddr, rtbl, rbase);

        char s0[76], s1[76], s2[76];
        vm_split_ops(last->ops, s0, s1, s2);
        vm_opr o0;
        vm_parse_op(s0, last, &o0);

        uint64_t table_va = 0, rel_base = 0;
        if (o0.kind == 3) {
            if (o0.reg >= 0 && raddr[o0.reg]) {
                uint64_t cand = raddr[o0.reg] + (uint64_t)o0.disp;
                if (bin_sec_at(&a->bin, cand)) {
                    table_va = cand;
                    rel_base = raddr[o0.reg];
                }
            } else if (o0.reg >= 0 && rtbl[o0.reg]) {
                table_va = rtbl[o0.reg];
                rel_base = rbase[o0.reg];
            } else if (o0.disp > 0 && bin_sec_at(&a->bin, (uint64_t)o0.disp)) {
                table_va = (uint64_t)o0.disp;
            }
        } else if (o0.kind == 1 && o0.reg >= 0) {
            table_va = rtbl[o0.reg];
            rel_base = rbase[o0.reg];
        }

        uint32_t bound = vm_find_cmp_bound(g, bi);
        if (table_va) vm_eval_table_cand(a, g, bi, table_va, rel_base, bound, best);
    }

    ir_switch sw[16];
    int nsw = ir_scan_switches(a, g->func_va, sw, 16);
    for (int i = 0; i < nsw; i++) {
        if (!sw[i].table_va) continue;
        int bi = -1;
        for (uint32_t k = 0; k < g->nblk; k++) {
            const grp_blk *b = &g->blks[k];
            if (b->ins_count > 0 && g->ins[b->ins_first + b->ins_count - 1].ip == sw[i].va) {
                bi = (int)k;
                break;
            }
        }
        if (bi < 0) continue;
        vm_eval_table_cand(a, g, (uint32_t)bi, sw[i].table_va, a->bin.base, sw[i].ncases, best);
    }
}

static bool vm_has_threaded_tail(const x86_ins *ins, int count, int vip_idx, uint64_t disp_start) {
    if (count <= 0) return false;
    const x86_ins *last = &ins[count - 1];
    if (last->flow == X86_FLOW_RET) return true;
    if (last->flow == X86_FLOW_JMP && last->has_target && !last->target_mem && last->target == disp_start) {
        return true;
    }
    if (vm_is_ind_jmp(last)) {
        for (int k = count - 2; k >= 0 && k >= count - 6; k--) {
            int ar = -1, st = 0;
            if (vm_check_lods(&ins[k], &st)) return true;
            if (vip_idx >= 0 && vm_check_vip_adv(&ins[k], &ar, &st) && ar == vip_idx) return true;
        }
    }
    return false;
}

static void vm_collect_threaded_handlers(const ana_ctx *a, const grp_cfg *g, uint32_t bi,
                                         int vip_idx, const uint64_t raddr[16],
                                         uint64_t table_va, uint64_t rel_base,
                                         uint64_t disp_start, vm_cand *cand) {
    if (table_va) {
        int raw = 0;
        cand->nhandler = vm_read_table(a, table_va, rel_base, g->func_va, 0, cand->h_vas, cand->h_ops, &raw);
        if (cand->nhandler > 0) {
            cand->table_va = table_va;
            return;
        }
    }

    // check direct-threaded bytecode stream initialized into vip
    if (vip_idx >= 0 && raddr[vip_idx] && bin_sec_at(&a->bin, raddr[vip_idx])) {
        int psz = (a->bin.bits == 32) ? 4 : 8;
        const bin_sec *fsec = bin_sec_at(&a->bin, g->func_va);
        uint64_t cur_ptr = raddr[vip_idx];
        int miss = 0;
        for (uint32_t i = 0; i < 64 && miss < 4; i++) {
            uint64_t ptr = 0;
            if (bin_read(&a->bin, cur_ptr + (uint64_t)i * (uint64_t)psz, (uint8_t *)&ptr, (size_t)psz) != (size_t)psz) break;
            if (vm_is_code_ptr(&a->bin, ptr) && (!fsec || bin_sec_at(&a->bin, ptr) == fsec)) {
                vm_add_unique_handler(cand->h_vas, cand->h_ops, &cand->nhandler, ptr, i);
                miss = 0;
            } else {
                miss++;
            }
        }
        if (cand->nhandler > 0) return;
    }

    // scan post-dispatcher inline threaded stubs within known function bounds
    const ana_func *fn = ana_func_at(a, g->func_va);
    if (!fn || fn->end <= g->blks[bi].end || fn->end - fn->start > 0x4000) return;

    uint64_t cur = g->blks[bi].end;
    uint32_t op_idx = 0;
    while (cur < fn->end && cand->nhandler < VM_MAX_HANDLERS) {
        size_t av = 0;
        const uint8_t *p = bin_ptr(&a->bin, cur, &av);
        if (!p || av == 0) break;
        if (p[0] == 0x90 || p[0] == 0xCC) { cur++; continue; }

        uint64_t hstart = cur;
        x86_ins tmp[VM_MAX_HINS];
        int cnt = 0;
        while (cur < fn->end && cnt < VM_MAX_HINS) {
            p = bin_ptr(&a->bin, cur, &av);
            if (!p || av == 0) break;
            int n = arch_decode(a->bin.arch, p, av, cur, 1, 0, &tmp[cnt]);
            if (n <= 0) break;
            cur += (uint64_t)n;
            uint8_t fl = tmp[cnt].flow;
            cnt++;
            if (fl == X86_FLOW_JMP || fl == X86_FLOW_RET || fl == X86_FLOW_TRAP) break;
        }
        if (cnt == 0 || !vm_has_threaded_tail(tmp, cnt, vip_idx, disp_start)) break;
        vm_add_unique_handler(cand->h_vas, cand->h_ops, &cand->nhandler, hstart, op_idx++);
    }
}

static void vm_detect_threaded(const ana_ctx *a, const grp_cfg *g, vm_cand *best) {
    for (uint32_t bi = 0; bi < g->nblk; bi++) {
        const grp_blk *b = &g->blks[bi];
        if (b->ins_count == 0) continue;

        int disp_idx = -1;
        for (int k = (int)b->ins_count - 1; k >= 0; k--) {
            const x86_ins *in = &g->ins[b->ins_first + (uint32_t)k];
            if (vm_is_ind_jmp(in) || vm_is_ind_call(in)) {
                disp_idx = k;
                break;
            }
        }
        if (disp_idx < 0) continue;

        int vip_idx = -1, stride = 0, fetch_blk = -1;
        if (!vm_find_vip_near(g, bi, &vip_idx, &stride, &fetch_blk)) continue;

        const x86_ins *din = &g->ins[b->ins_first + (uint32_t)disp_idx];
        uint64_t raddr[16], rtbl[16], rbase[16];
        vm_track_reg_addrs(a, g, bi, raddr, rtbl, rbase);

        char s0[76], s1[76], s2[76];
        vm_split_ops(din->ops, s0, s1, s2);
        vm_opr o0;
        vm_parse_op(s0, din, &o0);

        uint64_t table_va = 0, rel_base = 0;
        if (o0.kind == 3) {
            if (o0.reg >= 0 && raddr[o0.reg]) {
                uint64_t c = raddr[o0.reg] + (uint64_t)o0.disp;
                if (bin_sec_at(&a->bin, c)) { table_va = c; rel_base = raddr[o0.reg]; }
            } else if (o0.reg >= 0 && rtbl[o0.reg]) {
                table_va = rtbl[o0.reg];
                rel_base = rbase[o0.reg];
            } else if (o0.disp > 0 && bin_sec_at(&a->bin, (uint64_t)o0.disp)) {
                table_va = (uint64_t)o0.disp;
            }
        } else if (o0.kind == 1 && o0.reg >= 0) {
            table_va = rtbl[o0.reg];
            rel_base = rbase[o0.reg];
        }

        vm_cand cand;
        memset(&cand, 0, sizeof(cand));
        snprintf(cand.style, sizeof(cand.style), "threaded");
        cand.disp_va = din->ip;
        cand.disp_start = (fetch_blk >= 0) ? g->blks[fetch_blk].start : b->start;
        cand.disp_end = b->end;
        cand.disp_blk = (int)bi;
        cand.vip_idx = vip_idx;

        vm_collect_threaded_handlers(a, g, bi, vip_idx, raddr, table_va, rel_base, cand.disp_start, &cand);

        bool is_jmp = vm_is_ind_jmp(din);
        bool in_loop = vm_blk_in_loop(g, bi);
        int score = 35 + (is_jmp ? 20 : 10) + (in_loop ? 20 : 0) + cand.nhandler * 3;
        if (score > best->score) {
            cand.score = score;
            *best = cand;
        }
    }
}

static bool vm_blk_cmp_info(const grp_cfg *g, uint32_t bi, int *reg_out, uint64_t *imm_out,
                            int *is_sub_out, int *jcc_kind_out, int *true_blk, int *false_blk) {
    const grp_blk *b = &g->blks[bi];
    if (b->ins_count == 0) return false;
    const x86_ins *last = &g->ins[b->ins_first + b->ins_count - 1];
    if (last->flow != X86_FLOW_JCC) return false;

    int jk = 0;
    if (strcmp(last->mnem, "je") == 0 || strcmp(last->mnem, "jz") == 0) jk = 1;
    else if (strcmp(last->mnem, "jne") == 0 || strcmp(last->mnem, "jnz") == 0) jk = 2;
    else if (strcmp(last->mnem, "ja") == 0 || strcmp(last->mnem, "jae") == 0 ||
             strcmp(last->mnem, "jb") == 0 || strcmp(last->mnem, "jbe") == 0 ||
             strcmp(last->mnem, "jg") == 0 || strcmp(last->mnem, "jge") == 0 ||
             strcmp(last->mnem, "jl") == 0 || strcmp(last->mnem, "jle") == 0) jk = 3;
    else return false;

    int tb = -1, fb = -1;
    for (uint32_t e = 0; e < g->nedge; e++) {
        if (g->edges[e].from != bi) continue;
        if (g->edges[e].kind == GRP_EDGE_TRUE) tb = (int)g->edges[e].to;
        else if (g->edges[e].kind == GRP_EDGE_FALSE) fb = (int)g->edges[e].to;
    }
    if (tb < 0 || fb < 0) return false;

    for (int k = (int)b->ins_count - 2; k >= 0; k--) {
        const x86_ins *in = &g->ins[b->ins_first + (uint32_t)k];
        char s0[76], s1[76], s2[76];
        int nops = vm_split_ops(in->ops, s0, s1, s2);
        vm_opr o0, o1;
        vm_parse_op(s0, in, &o0);
        vm_parse_op(s1, in, &o1);

        if (strcmp(in->mnem, "cmp") == 0 && nops == 2 && o0.kind == 1 && o1.kind == 2) {
            *reg_out = o0.reg;
            *imm_out = o1.uval;
            *is_sub_out = 0;
            *jcc_kind_out = jk;
            *true_blk = tb;
            *false_blk = fb;
            return true;
        }
        if (strcmp(in->mnem, "test") == 0 && nops == 2 && o0.kind == 1 && o1.kind == 1 && o0.reg == o1.reg) {
            *reg_out = o0.reg;
            *imm_out = 0;
            *is_sub_out = 0;
            *jcc_kind_out = jk;
            *true_blk = tb;
            *false_blk = fb;
            return true;
        }
        if (strcmp(in->mnem, "sub") == 0 && nops == 2 && o0.kind == 1 && o1.kind == 2 && o0.reg != 4) {
            *reg_out = o0.reg;
            *imm_out = o1.uval;
            *is_sub_out = 1;
            *jcc_kind_out = jk;
            *true_blk = tb;
            *false_blk = fb;
            return true;
        }
        if (strcmp(in->mnem, "dec") == 0 && nops == 1 && o0.kind == 1 && o0.reg != 4) {
            *reg_out = o0.reg;
            *imm_out = 1;
            *is_sub_out = 1;
            *jcc_kind_out = jk;
            *true_blk = tb;
            *false_blk = fb;
            return true;
        }
    }
    return false;
}

static void vm_eval_switch_root(const grp_cfg *g, uint32_t hdr, uint32_t root,
                                const uint8_t can_hdr[VM_MAX_BLKS], vm_cand *best) {
    uint32_t q_blk[VM_MAX_BLKS];
    uint64_t q_off[VM_MAX_BLKS];
    uint8_t seen[VM_MAX_BLKS];
    memset(seen, 0, sizeof(seen));

    int op_reg = -1;
    uint32_t qh = 0, qt = 0;
    q_blk[qt] = root;
    q_off[qt] = 0;
    qt++;
    seen[root] = 1;

    uint64_t vas[VM_MAX_HANDLERS];
    uint32_t ops[VM_MAX_HANDLERS];
    int nh = 0;
    int nback = 0;
    int ncases = 0;

    while (qh < qt) {
        uint32_t u = q_blk[qh];
        uint64_t boff = q_off[qh];
        qh++;

        if (u != root && g->blks[u].ins_count > 6) continue;
        int creg = -1, is_sub = 0, jk = 0, tb = -1, fb = -1;
        uint64_t cimm = 0;
        if (!vm_blk_cmp_info(g, u, &creg, &cimm, &is_sub, &jk, &tb, &fb)) continue;

        if (op_reg < 0) op_reg = creg;
        else if (creg != op_reg) continue;

        uint64_t op_val = is_sub ? (boff + cimm) : cimm;
        uint64_t next_off = is_sub ? (boff + cimm) : boff;

        if (jk == 1 || jk == 2) {
            int hblk = (jk == 1) ? tb : fb;
            int nblk = (jk == 1) ? fb : tb;
            if (hblk >= 0 && (uint32_t)hblk != hdr && (uint32_t)hblk < g->nblk) {
                ncases++;
                if ((uint32_t)hblk < VM_MAX_BLKS && can_hdr[hblk]) nback++;
                vm_add_unique_handler(vas, ops, &nh, g->blks[hblk].start, (uint32_t)op_val);
            }
            if (nblk >= 0 && (uint32_t)nblk != hdr && (uint32_t)nblk < VM_MAX_BLKS && !seen[nblk]) {
                seen[nblk] = 1;
                q_blk[qt] = (uint32_t)nblk;
                q_off[qt] = next_off;
                qt++;
            }
        } else if (jk == 3) {
            // binary-search switch split
            if (tb >= 0 && (uint32_t)tb != hdr && (uint32_t)tb < VM_MAX_BLKS && !seen[tb]) {
                seen[tb] = 1;
                q_blk[qt] = (uint32_t)tb;
                q_off[qt] = boff;
                qt++;
            }
            if (fb >= 0 && (uint32_t)fb != hdr && (uint32_t)fb < VM_MAX_BLKS && !seen[fb]) {
                seen[fb] = 1;
                q_blk[qt] = (uint32_t)fb;
                q_off[qt] = boff;
                qt++;
            }
        }
    }

    int vip_idx = -1, stride = 0, fblk = -1;
    bool has_vip = vm_find_vip_near(g, root, &vip_idx, &stride, &fblk);
    if (!has_vip && root != hdr) has_vip = vm_find_vip_near(g, hdr, &vip_idx, &stride, &fblk);

    if (nback < 6 && !(ncases >= 6 && nback >= 5 && has_vip)) return;

    int score = 45 + nback * 15 + (has_vip ? 40 : 0) + nh * 2;
    if (score <= best->score) return;

    // detect common single-jump latch feeding hdr
    uint64_t latch_va = 0;
    int latch_in = 0;
    for (uint32_t e = 0; e < g->nedge; e++) {
        if (g->edges[e].to != hdr) continue;
        uint32_t p = g->edges[e].from;
        if (g->blks[p].ins_count <= 2) {
            int indeg = 0;
            for (uint32_t e2 = 0; e2 < g->nedge; e2++) if (g->edges[e2].to == p) indeg++;
            if (indeg > latch_in && indeg >= 2) {
                latch_in = indeg;
                latch_va = g->blks[p].start;
            }
        }
    }

    memset(best, 0, sizeof(*best));
    snprintf(best->style, sizeof(best->style), "switch-vm");
    best->disp_va = g->blks[hdr].start;
    best->disp_start = g->blks[hdr].start;
    best->disp_end = g->blks[hdr].end;
    best->latch_va = latch_va;
    best->disp_blk = (int)hdr;
    best->vip_idx = has_vip ? vip_idx : -1;
    best->score = score;
    best->nhandler = nh;
    memcpy(best->h_vas, vas, (size_t)nh * sizeof(uint64_t));
    memcpy(best->h_ops, ops, (size_t)nh * sizeof(uint32_t));
}

static void vm_detect_switch(const grp_cfg *g, vm_cand *best) {
    uint32_t lim = (g->nblk < VM_MAX_BLKS) ? g->nblk : VM_MAX_BLKS;
    for (uint32_t hdr = 0; hdr < lim; hdr++) {
        if (!vm_blk_in_loop(g, hdr)) continue;
        uint8_t reach[VM_MAX_BLKS], can_hdr[VM_MAX_BLKS];
        vm_reach_from(g, hdr, reach);
        vm_can_reach(g, hdr, reach, can_hdr);

        vm_eval_switch_root(g, hdr, hdr, can_hdr, best);

        // allow while-condition loop header stepping into dispatch root
        for (uint32_t e = 0; e < g->nedge; e++) {
            if (g->edges[e].from != hdr) continue;
            uint32_t nxt = g->edges[e].to;
            if (nxt != hdr && nxt < lim && can_hdr[nxt]) {
                vm_eval_switch_root(g, hdr, nxt, can_hdr, best);
            }
        }
    }
}

static bool vm_is_disp_target(uint64_t target, uint64_t disp_start, uint64_t disp_end, uint64_t latch_va) {
    if (target == disp_start) return true;
    if (disp_start && disp_end > disp_start && target >= disp_start && target < disp_end) return true;
    if (latch_va && target == latch_va) return true;
    return false;
}

static bool vm_peek_epilogue_ret(const ana_ctx *a, uint64_t va, uint64_t disp_start, uint64_t disp_end, uint64_t latch_va) {
    uint64_t cur = va;
    x86_ins in;
    for (int i = 0; i < 12; i++) {
        size_t av = 0;
        const uint8_t *p = bin_ptr(&a->bin, cur, &av);
        if (!p || av == 0) return false;
        int n = arch_decode(a->bin.arch, p, av, cur, 1, 0, &in);
        if (n <= 0) return false;
        if (in.flow == X86_FLOW_RET) return true;
        if (in.flow == X86_FLOW_JMP) {
            if (in.has_target && !in.target_mem && vm_is_disp_target(in.target, disp_start, disp_end, latch_va)) {
                return false;
            }
            return false;
        }
        cur += (uint64_t)n;
    }
    return false;
}

static uint16_t vm_collect_vip_aliases(const grp_cfg *g, int disp_blk, int vip_idx) {
    if (vip_idx < 0 || vip_idx >= 16) return 0;
    uint16_t mask = (uint16_t)(1u << vip_idx);
    if (disp_blk < 0 || (uint32_t)disp_blk >= g->nblk) return mask;

    const grp_blk *b = &g->blks[disp_blk];
    for (uint32_t k = 0; k < b->ins_count; k++) {
        const x86_ins *in = &g->ins[b->ins_first + k];
        char s0[76], s1[76], s2[76];
        if (vm_split_ops(in->ops, s0, s1, s2) < 2) continue;
        vm_opr o0, o1;
        vm_parse_op(s0, in, &o0);
        vm_parse_op(s1, in, &o1);
        if (o0.kind != 1 || o0.reg < 0 || o0.reg == 4) continue;
        if (strcmp(in->mnem, "mov") == 0 && o1.kind == 1 && o1.reg >= 0 && (mask & (1u << o1.reg))) {
            mask |= (uint16_t)(1u << o0.reg);
        } else if (strcmp(in->mnem, "lea") == 0 && o1.kind == 3 && o1.reg >= 0 && o1.idx < 0 &&
                   o1.disp >= -8 && o1.disp <= 8 && (mask & (1u << o1.reg))) {
            mask |= (uint16_t)(1u << o0.reg);
        }
    }
    return mask;
}

static bool vm_ins_mods_vip_nonconst(const x86_ins *in, int vip_idx, uint16_t vip_mask) {
    if (vip_idx < 0) return false;
    char s0[76], s1[76], s2[76];
    int nops = vm_split_ops(in->ops, s0, s1, s2);
    if (nops < 2) return false;
    vm_opr o0, o1;
    vm_parse_op(s0, in, &o0);
    vm_parse_op(s1, in, &o1);
    if (o0.kind != 1 || o0.reg != vip_idx) return false;

    const char *m = in->mnem;
    if (strncmp(m, "cmov", 4) == 0) return true;
    if (strcmp(m, "mov") == 0 || strcmp(m, "movabs") == 0 || strcmp(m, "movsxd") == 0 ||
        strcmp(m, "movzx") == 0 || strcmp(m, "movsx") == 0) {
        return !(o1.kind == 1 && o1.reg >= 0 && (vip_mask & (1u << o1.reg)));
    }
    if (strcmp(m, "sub") == 0) return true;
    if (strcmp(m, "add") == 0) {
        if (o1.kind == 2 && (o1.uval == 1 || o1.uval == 2 || o1.uval == 4 || o1.uval == 8)) return false;
        return true;
    }
    if (strcmp(m, "lea") == 0 && o1.kind == 3) {
        if (o1.reg >= 0 && (vip_mask & (1u << o1.reg)) && o1.idx < 0 &&
            (o1.disp >= 1 && o1.disp <= 8)) {
            return false;
        }
        return true;
    }
    return false;
}

static void vm_peek_branch(const ana_ctx *a, uint64_t tgt, int vip_idx, uint16_t vip_mask,
                           uint64_t disp_start, uint64_t disp_end, uint64_t latch_va,
                           int *vip_mod, int *has_ret) {
    uint64_t cur = tgt;
    x86_ins in;
    for (int i = 0; i < 16; i++) {
        size_t av = 0;
        const uint8_t *p = bin_ptr(&a->bin, cur, &av);
        if (!p || av == 0) break;
        int n = arch_decode(a->bin.arch, p, av, cur, 1, 0, &in);
        if (n <= 0) break;
        if (vm_ins_mods_vip_nonconst(&in, vip_idx, vip_mask)) *vip_mod = 1;
        if (in.flow == X86_FLOW_RET) { *has_ret = 1; break; }
        if (in.flow == X86_FLOW_JMP) {
            if (in.has_target && !in.target_mem && !vm_is_disp_target(in.target, disp_start, disp_end, latch_va)) {
                if (vm_peek_epilogue_ret(a, in.target, disp_start, disp_end, latch_va)) *has_ret = 1;
            }
            break;
        }
        cur += (uint64_t)n;
    }
}

static void vm_decode_handler(const ana_ctx *a, uint64_t hva, int vip_idx, uint16_t vip_mask,
                              uint64_t disp_start, uint64_t disp_end, uint64_t latch_va,
                              vm_hinfo *hi) {
    memset(hi, 0, sizeof(*hi));
    uint64_t cur = hva;
    uint64_t local_jcc_tgt = 0;

    for (int i = 0; i < VM_MAX_HINS; i++) {
        size_t av = 0;
        const uint8_t *p = bin_ptr(&a->bin, cur, &av);
        if (!p || av == 0) break;
        x86_ins *in = &hi->ins[hi->count];
        int n = arch_decode(a->bin.arch, p, av, cur, 1, 0, in);
        if (n <= 0) break;
        hi->count++;
        cur += (uint64_t)n;

        if (!vm_is_boilerplate(in)) {
            bool is_back_jmp = (in->flow == X86_FLOW_JMP && in->has_target && !in->target_mem &&
                                vm_is_disp_target(in->target, disp_start, disp_end, latch_va));
            if (!is_back_jmp) hi->meaningful++;
        }

        if (in->flow == X86_FLOW_JCC && in->has_target && !in->target_mem &&
            in->target > hva && in->target < hva + 96 && !local_jcc_tgt) {
            local_jcc_tgt = in->target;
        }

        if (in->flow == X86_FLOW_RET) {
            hi->ends_ret = 1;
            break;
        }
        if (in->flow == X86_FLOW_TRAP) break;
        if (in->flow == X86_FLOW_JMP) {
            if (in->has_target && !in->target_mem) {
                if (!vm_is_disp_target(in->target, disp_start, disp_end, latch_va)) {
                    if (vm_peek_epilogue_ret(a, in->target, disp_start, disp_end, latch_va)) {
                        hi->peek_ret = 1;
                    }
                }
            }
            break;
        }
    }

    if (local_jcc_tgt) {
        vm_peek_branch(a, local_jcc_tgt, vip_idx, vip_mask, disp_start, disp_end, latch_va,
                       &hi->peek_vip_mod, &hi->peek_ret);
    }
    if (hi->meaningful == 0 && hi->count > 0) hi->meaningful = 1;
}

static void vm_refine_vip(const vm_hinfo *hs, int nh, int *vip_idx) {
    if (*vip_idx >= 0 || nh <= 0) return;
    int score[16] = {0};
    for (int hi = 0; hi < nh; hi++) {
        int vr = -1, st = 0;
        if (vm_scan_vip_insns(hs[hi].ins, (uint32_t)hs[hi].count, &vr, &st) && vr >= 0 && vr != 4) {
            score[vr] += 3;
        }
    }
    int best_r = -1, best_s = 0;
    for (int r = 0; r < 16; r++) {
        if (score[r] > best_s) { best_s = score[r]; best_r = r; }
    }
    if (best_s >= 3) *vip_idx = best_r;
}

static void vm_detect_vsp(const vm_hinfo *hs, int nh, int vip_idx, int *vsp_idx, int *vsp_indexed) {
    *vsp_idx = -1;
    *vsp_indexed = 0;

    int deref[16] = {0}, adj[16] = {0}, inc_f[16] = {0}, dec_f[16] = {0};
    int idx_deref[16] = {0}, idx_adj[16] = {0}, idx_inc[16] = {0}, idx_dec[16] = {0};
    int native_pp = 0;

    for (int hi = 0; hi < nh; hi++) {
        const vm_hinfo *h = &hs[hi];
        for (int k = 0; k < h->count; k++) {
            const x86_ins *in = &h->ins[k];
            const char *m = in->mnem;
            char s0[76], s1[76], s2[76];
            int nops = vm_split_ops(in->ops, s0, s1, s2);
            vm_opr o0, o1;
            vm_parse_op(s0, in, &o0);
            vm_parse_op(s1, in, &o1);

            if (strcmp(m, "push") == 0 || strcmp(m, "pop") == 0) {
                if (strcmp(m, "pushfq") != 0 && strcmp(m, "popfq") != 0) native_pp++;
            }

            if (o0.kind == 1 && o0.reg >= 0 && o0.reg != vip_idx) {
                int r = o0.reg;
                if (strcmp(m, "add") == 0 && o1.kind == 2) {
                    if (o1.uval == 4 || o1.uval == 8 || o1.uval == 16) { adj[r]++; inc_f[r] = 1; }
                    else if (o1.uval == 1) { idx_adj[r]++; idx_inc[r] = 1; }
                } else if (strcmp(m, "sub") == 0 && o1.kind == 2) {
                    if (o1.uval == 4 || o1.uval == 8 || o1.uval == 16) { adj[r]++; dec_f[r] = 1; }
                    else if (o1.uval == 1) { idx_adj[r]++; idx_dec[r] = 1; }
                } else if (strcmp(m, "inc") == 0) {
                    idx_adj[r]++; idx_inc[r] = 1;
                } else if (strcmp(m, "dec") == 0) {
                    idx_adj[r]++; idx_dec[r] = 1;
                } else if (strcmp(m, "lea") == 0 && o1.kind == 3 && o1.reg == r && o1.idx < 0) {
                    if (o1.disp == 4 || o1.disp == 8 || o1.disp == 16) { adj[r]++; inc_f[r] = 1; }
                    else if (o1.disp == -4 || o1.disp == -8 || o1.disp == -16) { adj[r]++; dec_f[r] = 1; }
                    else if (o1.disp == 1) { idx_adj[r]++; idx_inc[r] = 1; }
                    else if (o1.disp == -1) { idx_adj[r]++; idx_dec[r] = 1; }
                }
            }

            const vm_opr *ops[2] = { &o0, &o1 };
            int no = (nops >= 2) ? 2 : (nops == 1 ? 1 : 0);
            for (int oi = 0; oi < no; oi++) {
                const vm_opr *op = ops[oi];
                if (op->kind != 3 || op->is_rip) continue;
                if (op->reg >= 0 && op->reg != vip_idx && op->idx < 0 &&
                    op->disp >= -16 && op->disp <= 16 && (op->disp % 4) == 0) {
                    deref[op->reg]++;
                }
                if (op->idx >= 0 && op->idx != vip_idx && (op->scale == 4 || op->scale == 8)) {
                    idx_deref[op->idx]++;
                }
            }
        }
    }

    int best_r = -1, best_s = 0, best_idx = 0;
    for (int r = 0; r < 16; r++) {
        if (r == 4 || r == vip_idx) continue;
        if (deref[r] > 0 && adj[r] > 0) {
            int s = deref[r] * 3 + adj[r] * 5 + ((inc_f[r] && dec_f[r]) ? 15 : 0);
            if (s > best_s) { best_s = s; best_r = r; best_idx = 0; }
        }
        if (idx_deref[r] > 0 && idx_adj[r] > 0) {
            int s = idx_deref[r] * 3 + idx_adj[r] * 5 + ((idx_inc[r] && idx_dec[r]) ? 15 : 0);
            if (s > best_s) { best_s = s; best_r = r; best_idx = 1; }
        }
    }

    if (best_s >= 8) {
        *vsp_idx = best_r;
        *vsp_indexed = best_idx;
        return;
    }
    if (vip_idx != 4 && (native_pp >= 2 || (deref[4] > 0 && adj[4] > 0))) {
        *vsp_idx = 4;
        *vsp_indexed = 0;
    }
}

static bool vm_op_uses_vsp(const vm_opr *op, int vsp_idx, int vsp_indexed) {
    if (vsp_idx < 0 || op->kind != 3 || op->is_rip) return false;
    if (!vsp_indexed && op->reg == vsp_idx && op->idx < 0 && op->disp >= -16 && op->disp <= 16) return true;
    if (vsp_indexed && op->idx == vsp_idx && (op->scale == 4 || op->scale == 8)) return true;
    return false;
}

static bool vm_op_uses_vip(const vm_opr *op, uint16_t vip_mask) {
    if (!vip_mask || op->kind != 3 || op->is_rip) return false;
    if (op->reg >= 0 && (vip_mask & (1u << op->reg))) return true;
    if (op->idx >= 0 && (vip_mask & (1u << op->idx))) return true;
    return false;
}

static bool vm_is_other_mem(const vm_opr *op, uint16_t vip_mask, int vsp_idx, int vsp_indexed) {
    if (op->kind != 3) return false;
    if (vm_op_uses_vsp(op, vsp_idx, vsp_indexed)) return false;
    if (vm_op_uses_vip(op, vip_mask)) return false;
    // ignore native stack frame spills when rsp/rbp is not vsp
    if ((op->reg == 4 || op->reg == 5) && op->idx < 0 && op->reg != vsp_idx) return false;
    if (op->is_rip) return false;
    return true;
}

enum {
    VA_XOR = 0, VA_ADD, VA_SUB, VA_MUL, VA_AND, VA_OR,
    VA_SHL, VA_SHR, VA_NOT, VA_NEG, VA_COUNT
};

static const char *const vm_alu_kind[VA_COUNT] = {
    "VM_XOR","VM_ADD","VM_SUB","VM_MUL","VM_AND","VM_OR",
    "VM_SHL","VM_SHR","VM_NOT","VM_NEG"
};

static const char *const vm_alu_sym[VA_COUNT] = {
    "^", "+", "-", "*", "&", "|", "<<", ">>", "~", "-"
};

typedef struct {
    int  alu_w[VA_COUNT];
    char alu_a[VA_COUNT][36];
    char alu_b[VA_COUNT][36];
    int  alu_has_imm[VA_COUNT];
    int  has_call;
    char call_tgt[64];
    int  has_jcc;
    int  has_cmp;
    int  has_setcc;
    int  vip_adv;
    int  vip_jmp;
    int  vip_cmov;
    int  vsp_delta;
    int  vsp_load;
    int  vsp_store;
    int  vip_load;
    int  mem_load_other;
    int  mem_store_other;
    char other_ld_op[36];
    char other_st_dst[36];
    char other_st_src[36];
    char push_src[36];
    char pop_dst[36];
    char cmp_a[32];
    char cmp_b[32];
    char custom_buf[96];
    int  nbody;
} vm_hfeat;

static int vm_match_alu_kind(const char *m, const vm_opr *o0, const vm_opr *o1,
                             int vip_idx, int vsp_idx, bool tail_disp) {
    if (strcmp(m, "xor") == 0) return VA_XOR;
    if (strcmp(m, "add") == 0 || strcmp(m, "adc") == 0 || strcmp(m, "inc") == 0) return VA_ADD;
    if (strcmp(m, "sub") == 0 || strcmp(m, "sbb") == 0 || strcmp(m, "dec") == 0) return VA_SUB;
    if (strcmp(m, "mul") == 0 || strcmp(m, "imul") == 0) return VA_MUL;
    if (strcmp(m, "and") == 0) return VA_AND;
    if (strcmp(m, "or") == 0)  return VA_OR;
    if (strcmp(m, "shl") == 0 || strcmp(m, "sal") == 0) return VA_SHL;
    if (strcmp(m, "shr") == 0 || strcmp(m, "sar") == 0) return VA_SHR;
    if (strcmp(m, "not") == 0) return VA_NOT;
    if (strcmp(m, "neg") == 0) return VA_NEG;
    if (strcmp(m, "lea") == 0 && o0->kind == 1 && o1->kind == 3 && !o1->is_rip &&
        o1->reg >= 0 && o1->reg != 4 && o1->reg != 5 && o1->reg != vsp_idx && o1->reg != vip_idx &&
        o1->idx >= 0 && o1->idx != vsp_idx && o1->idx != vip_idx && o1->scale == 1 && !tail_disp) {
        return VA_ADD;
    }
    return -1;
}

static void vm_scan_handler_feats(const ana_ctx *a, const vm_hinfo *hi,
                                  int vip_idx, uint16_t vip_mask, int vsp_idx, int vsp_indexed,
                                  vm_hfeat *f) {
    memset(f, 0, sizeof(*f));
    for (int k = 0; k < hi->count; k++) {
        const x86_ins *in = &hi->ins[k];
        if (vm_is_boilerplate(in)) continue;

        const char *m = in->mnem;
        if (in->flow == X86_FLOW_JMP || in->flow == X86_FLOW_RET || in->flow == X86_FLOW_TRAP) continue;

        bool tail_disp = (k + 1 < hi->count && vm_is_ind_jmp(&hi->ins[k + 1]));
        int lods_st = 0;
        if (vm_check_lods(in, &lods_st)) {
            f->vip_adv += lods_st;
            f->vip_load = 1;
            continue;
        }
        if (in->flow == X86_FLOW_CALL) {
            f->has_call = 1;
            f->nbody++;
            if (in->has_target && !in->target_mem) {
                const char *sym = ana_sym_at(a, in->target);
                if (sym && sym[0]) snprintf(f->call_tgt, sizeof(f->call_tgt), "%s", sym);
                else snprintf(f->call_tgt, sizeof(f->call_tgt), "0x%llx", (unsigned long long)in->target);
            } else {
                snprintf(f->call_tgt, sizeof(f->call_tgt), "%s", in->ops);
            }
            continue;
        }
        if (in->flow == X86_FLOW_JCC) { f->has_jcc = 1; continue; }

        char s0[76], s1[76], s2[76];
        int nops = vm_split_ops(in->ops, s0, s1, s2);
        vm_opr o0, o1;
        vm_parse_op(s0, in, &o0);
        vm_parse_op(s1, in, &o1);

        int ar = -1, ast = 0;
        if (vip_idx >= 0 && vm_check_vip_adv(in, &ar, &ast) && ar == vip_idx) {
            f->vip_adv += ast;
            continue;
        }
        if (vip_idx >= 0 && strcmp(m, "lea") == 0 && o0.kind == 1 && o0.reg == vip_idx &&
            o1.kind == 3 && o1.reg >= 0 && (vip_mask & (1u << o1.reg)) && o1.idx < 0 &&
            o1.disp >= 1 && o1.disp <= 8) {
            f->vip_adv += (int)o1.disp;
            continue;
        }
        if (vm_ins_mods_vip_nonconst(in, vip_idx, vip_mask)) {
            if (strncmp(m, "cmov", 4) == 0) f->vip_cmov = 1;
            else f->vip_jmp = 1;
            f->nbody++;
            continue;
        }

        if (strcmp(m, "push") == 0) {
            if (vsp_idx == 4) {
                f->vsp_delta -= (a->bin.bits == 32) ? 4 : 8;
                f->vsp_store = 1;
                if (!f->push_src[0]) snprintf(f->push_src, sizeof(f->push_src), "%s", s0);
                f->nbody++;
            }
            continue;
        }
        if (strcmp(m, "pop") == 0) {
            if (vsp_idx == 4) {
                f->vsp_delta += (a->bin.bits == 32) ? 4 : 8;
                f->vsp_load = 1;
                if (!f->pop_dst[0]) snprintf(f->pop_dst, sizeof(f->pop_dst), "%s", s0);
                f->nbody++;
            }
            continue;
        }
        if (strcmp(m, "pushfq") == 0 || strcmp(m, "pushfd") == 0) { f->has_setcc = 1; f->nbody++; continue; }

        if (vsp_idx >= 0 && o0.kind == 1 && o0.reg == vsp_idx) {
            if (strcmp(m, "add") == 0 && o1.kind == 2 && o1.uval <= 32) { f->vsp_delta += (int)o1.uval; f->nbody++; continue; }
            if (strcmp(m, "sub") == 0 && o1.kind == 2 && o1.uval <= 32) { f->vsp_delta -= (int)o1.uval; f->nbody++; continue; }
            if (vsp_indexed && strcmp(m, "inc") == 0) { f->vsp_delta += 1; f->nbody++; continue; }
            if (vsp_indexed && strcmp(m, "dec") == 0) { f->vsp_delta -= 1; f->nbody++; continue; }
            if (strcmp(m, "lea") == 0 && o1.kind == 3 && o1.reg == vsp_idx && o1.idx < 0 && o1.disp >= -32 && o1.disp <= 32) {
                f->vsp_delta += (int)o1.disp;
                f->nbody++;
                continue;
            }
        }
        if (vsp_idx != 4 && o0.kind == 1 && o0.reg == 4 && (strcmp(m, "add") == 0 || strcmp(m, "sub") == 0) && o1.kind == 2) {
            continue;
        }

        if (vm_op_uses_vsp(&o0, vsp_idx, vsp_indexed)) f->vsp_store = 1;
        if (nops >= 2 && vm_op_uses_vsp(&o1, vsp_idx, vsp_indexed) && strcmp(m, "lea") != 0) f->vsp_load = 1;
        if (nops >= 2 && vm_op_uses_vip(&o1, vip_mask) && strcmp(m, "lea") != 0) f->vip_load = 1;

        if (strcmp(m, "mov") == 0 || strcmp(m, "movabs") == 0 || strcmp(m, "movzx") == 0 ||
            strcmp(m, "movsx") == 0 || strcmp(m, "movsxd") == 0) {
            if (vm_op_uses_vsp(&o0, vsp_idx, vsp_indexed)) {
                if (!f->push_src[0]) snprintf(f->push_src, sizeof(f->push_src), "%s", s1);
            } else if (vm_op_uses_vsp(&o1, vsp_idx, vsp_indexed) && o0.kind == 1) {
                if (!f->pop_dst[0]) snprintf(f->pop_dst, sizeof(f->pop_dst), "%s", s0);
            }
            if (vm_is_other_mem(&o0, vip_mask, vsp_idx, vsp_indexed)) {
                f->mem_store_other = 1;
                if (!f->other_st_dst[0]) {
                    snprintf(f->other_st_dst, sizeof(f->other_st_dst), "%s", s0);
                    snprintf(f->other_st_src, sizeof(f->other_st_src), "%s", s1);
                }
            }
            if (vm_is_other_mem(&o1, vip_mask, vsp_idx, vsp_indexed) && !tail_disp) {
                f->mem_load_other = 1;
                if (!f->other_ld_op[0]) snprintf(f->other_ld_op, sizeof(f->other_ld_op), "%s", s1);
            }
            f->nbody++;
            if (!f->custom_buf[0] && !tail_disp) snprintf(f->custom_buf, sizeof(f->custom_buf), "%s %s", m, in->ops);
            continue;
        }

        // ignore zeroing idioms xor r,r / sub r,r
        if ((strcmp(m, "xor") == 0 || strcmp(m, "sub") == 0) && o0.kind == 1 && o1.kind == 1 && o0.reg == o1.reg) {
            if (!f->push_src[0]) snprintf(f->push_src, sizeof(f->push_src), "0");
            f->nbody++;
            continue;
        }
        if (strcmp(m, "cmp") == 0 || strcmp(m, "test") == 0) {
            f->has_cmp = 1;
            if (!f->cmp_a[0]) {
                snprintf(f->cmp_a, sizeof(f->cmp_a), "%s", s0);
                snprintf(f->cmp_b, sizeof(f->cmp_b), "%s", s1);
            }
            f->nbody++;
            continue;
        }
        if (strncmp(m, "set", 3) == 0) { f->has_setcc = 1; f->nbody++; continue; }
        if (tail_disp && (strcmp(m, "add") == 0 || strcmp(m, "shl") == 0)) continue;

        int ak = vm_match_alu_kind(m, &o0, &o1, vip_idx, vsp_idx, tail_disp);
        if (ak >= 0) {
            int w = 2;
            if (vm_op_uses_vsp(&o0, vsp_idx, vsp_indexed) || (nops >= 2 && vm_op_uses_vsp(&o1, vsp_idx, vsp_indexed))) w += 3;
            if (ak != VA_ADD && ak != VA_SUB) w += 1;
            // discount shift-count masking like and cl, 0x3f
            if (ak == VA_AND && o0.kind == 1 && o0.reg == 1 && o1.kind == 2 &&
                (o1.uval == 7 || o1.uval == 15 || o1.uval == 31 || o1.uval == 63)) {
                w = 1;
            }
            f->alu_w[ak] += w;
            if (!f->alu_a[ak][0]) {
                snprintf(f->alu_a[ak], sizeof(f->alu_a[ak]), "%s", s0);
                if (strcmp(m, "inc") == 0 || strcmp(m, "dec") == 0) {
                    snprintf(f->alu_b[ak], sizeof(f->alu_b[ak]), "1");
                    f->alu_has_imm[ak] = 1;
                } else if (nops >= 2) {
                    snprintf(f->alu_b[ak], sizeof(f->alu_b[ak]), "%s", s1);
                    if (o1.kind == 2) f->alu_has_imm[ak] = 1;
                }
            }
            f->nbody++;
            continue;
        }

        f->nbody++;
        if (!f->custom_buf[0] && !tail_disp) snprintf(f->custom_buf, sizeof(f->custom_buf), "%s %s", m, in->ops);
    }
}

static void vm_emit_handler_sem(const vm_hinfo *hi, const vm_hfeat *f, int vsp_idx, vm_handler *out) {
    if (hi->ends_ret || (hi->peek_ret && !f->has_jcc)) {
        snprintf(out->kind, sizeof(out->kind), "VM_RET");
        snprintf(out->sem, sizeof(out->sem), "exit vm; return");
        return;
    }
    if (f->has_call) {
        snprintf(out->kind, sizeof(out->kind), "VM_CALL");
        snprintf(out->sem, sizeof(out->sem), "call %s", f->call_tgt[0] ? f->call_tgt : "native");
        return;
    }
    if (f->vip_cmov || (f->has_jcc && (f->vip_jmp || hi->peek_vip_mod))) {
        snprintf(out->kind, sizeof(out->kind), "VM_JCC");
        snprintf(out->sem, sizeof(out->sem), "if (cond) vip = target");
        return;
    }
    if (f->vip_jmp) {
        snprintf(out->kind, sizeof(out->kind), "VM_JMP");
        snprintf(out->sem, sizeof(out->sem), "vip = target");
        return;
    }

    int best_ak = -1, best_aw = 0;
    for (int ak = 0; ak < VA_COUNT; ak++) {
        if (f->alu_w[ak] > best_aw) { best_aw = f->alu_w[ak]; best_ak = ak; }
    }
    if (best_ak >= 0) {
        snprintf(out->kind, sizeof(out->kind), "%s", vm_alu_kind[best_ak]);
        bool touches_vsp = (vsp_idx >= 0 && (f->vsp_load || f->vsp_store || f->vsp_delta != 0));
        if (best_ak == VA_NOT || best_ak == VA_NEG) {
            if (touches_vsp) snprintf(out->sem, sizeof(out->sem), "vsp[0] = %svsp[0]", vm_alu_sym[best_ak]);
            else snprintf(out->sem, sizeof(out->sem), "%s = %s%s", f->alu_a[best_ak], vm_alu_sym[best_ak], f->alu_a[best_ak]);
        } else if (touches_vsp) {
            if (f->alu_has_imm[best_ak] && f->vsp_delta == 0) {
                snprintf(out->sem, sizeof(out->sem), "vsp[0] = vsp[0] %s %s", vm_alu_sym[best_ak], f->alu_b[best_ak]);
            } else {
                snprintf(out->sem, sizeof(out->sem), "vsp[0] = vsp[0] %s vsp[1]", vm_alu_sym[best_ak]);
            }
        } else if (f->alu_b[best_ak][0]) {
            snprintf(out->sem, sizeof(out->sem), "%s = %s %s %s", f->alu_a[best_ak], f->alu_a[best_ak], vm_alu_sym[best_ak], f->alu_b[best_ak]);
        } else {
            snprintf(out->sem, sizeof(out->sem), "%s %s", vm_alu_kind[best_ak], f->alu_a[best_ak]);
        }
        return;
    }

    if (f->has_cmp && (f->has_setcc || (!f->mem_load_other && !f->mem_store_other))) {
        snprintf(out->kind, sizeof(out->kind), "VM_CMP");
        if (vsp_idx >= 0 && (f->vsp_load || f->vsp_store)) snprintf(out->sem, sizeof(out->sem), "vflags = cmp(vsp[0], vsp[1])");
        else snprintf(out->sem, sizeof(out->sem), "cmp %s, %s", f->cmp_a, f->cmp_b);
        return;
    }
    if (f->mem_store_other) {
        snprintf(out->kind, sizeof(out->kind), "VM_STORE");
        if (vsp_idx >= 0 && (f->vsp_load || f->vsp_delta != 0)) snprintf(out->sem, sizeof(out->sem), "*(uint64_t *)vsp[1] = vsp[0]");
        else snprintf(out->sem, sizeof(out->sem), "%s = %s", f->other_st_dst, f->other_st_src);
        return;
    }
    if ((f->vsp_store && !f->vsp_load && f->vsp_delta != 0) || (f->vsp_delta < 0 && !f->vsp_load && !f->mem_load_other)) {
        snprintf(out->kind, sizeof(out->kind), "VM_PUSH");
        if (f->vip_load) snprintf(out->sem, sizeof(out->sem), "*--vsp = *vip++");
        else if (f->push_src[0]) snprintf(out->sem, sizeof(out->sem), "*--vsp = %s", f->push_src);
        else snprintf(out->sem, sizeof(out->sem), "push vsp");
        return;
    }
    if (f->mem_load_other) {
        snprintf(out->kind, sizeof(out->kind), "VM_LOAD");
        if (vsp_idx >= 0 && (f->vsp_load || f->vsp_store)) snprintf(out->sem, sizeof(out->sem), "vsp[0] = *(uint64_t *)vsp[0]");
        else snprintf(out->sem, sizeof(out->sem), "load %s", f->other_ld_op);
        return;
    }
    if (f->vsp_delta != 0) {
        snprintf(out->kind, sizeof(out->kind), "VM_POP");
        if (f->pop_dst[0]) snprintf(out->sem, sizeof(out->sem), "%s = *vsp++", f->pop_dst);
        else snprintf(out->sem, sizeof(out->sem), "pop vsp");
        return;
    }
    if (f->nbody == 0) {
        snprintf(out->kind, sizeof(out->kind), "VM_NOP");
        if (f->vip_adv > 0) snprintf(out->sem, sizeof(out->sem), "nop; vip += %d", f->vip_adv);
        else snprintf(out->sem, sizeof(out->sem), "nop");
        return;
    }

    snprintf(out->kind, sizeof(out->kind), "VM_CUSTOM");
    if (f->custom_buf[0]) snprintf(out->sem, sizeof(out->sem), "%s", f->custom_buf);
    else snprintf(out->sem, sizeof(out->sem), "custom (%d insns)", hi->meaningful);
}

static void vm_classify_handler(const ana_ctx *a, const vm_hinfo *hi,
                                int vip_idx, uint16_t vip_mask, int vsp_idx, int vsp_indexed,
                                vm_handler *out) {
    out->nins = hi->meaningful;
    vm_hfeat feat;
    vm_scan_handler_feats(a, hi, vip_idx, vip_mask, vsp_idx, vsp_indexed, &feat);
    vm_emit_handler_sem(hi, &feat, vsp_idx, out);
}

static int vm_find_handler_idx(const vm_res *out, uint64_t va) {
    for (int i = 0; i < out->nhandler; i++) {
        if (out->handlers[i].va == va) return i;
    }
    return -1;
}

static void vm_best_effect(const emu_out *e, int start, int end, char *dst, size_t max) {
    dst[0] = 0;
    for (int i = end - 1; i >= start; i--) {
        const char *ef = e->steps[i].effect;
        if (!ef[0]) continue;
        if (strncmp(ef, "jmp ->", 6) == 0 || strncmp(ef, "TAKEN", 5) == 0 ||
            strncmp(ef, "fallthrough", 11) == 0) {
            continue;
        }
        snprintf(dst, max, "%s", ef);
        return;
    }
}

static bool vm_vip_is_concrete(const ana_ctx *a, const grp_cfg *g, int disp_blk, int vip_idx) {
    if (vip_idx < 0 || vip_idx >= 16) return true;
    uint32_t bi = (disp_blk >= 0 && (uint32_t)disp_blk < g->nblk) ? (uint32_t)disp_blk : 0;
    uint64_t raddr[16], rtbl[16], rbase[16];
    vm_track_reg_addrs(a, g, bi, raddr, rtbl, rbase);
    if (raddr[vip_idx] && bin_sec_at(&a->bin, raddr[vip_idx])) return true;

    // also allow stack-based bytecode initialized via rsp/rbp
    if (g->nblk > 0) {
        const grp_blk *b0 = &g->blks[0];
        for (uint32_t k = 0; k < b0->ins_count; k++) {
            const x86_ins *in = &g->ins[b0->ins_first + k];
            char s0[76], s1[76], s2[76];
            if (vm_split_ops(in->ops, s0, s1, s2) < 2) continue;
            vm_opr o0, o1;
            vm_parse_op(s0, in, &o0);
            vm_parse_op(s1, in, &o1);
            if (o0.kind != 1 || o0.reg != vip_idx) continue;
            if (strcmp(in->mnem, "lea") == 0 && o1.kind == 3 && (o1.reg == 4 || o1.reg == 5)) return true;
            if (strcmp(in->mnem, "mov") == 0 && o1.kind == 1 && (o1.reg == 4 || o1.reg == 5)) return true;
        }
    }
    return false;
}

static bool vm_safe_emu_trace(const ana_ctx *a, uint64_t start_va, int max_steps, emu_out *e) {
#ifdef _MSC_VER
    __try {
        return emu_trace(a, start_va, max_steps, e);
    } __except (1) {
        return false;
    }
#else
    return emu_trace(a, start_va, max_steps, e);
#endif
}

static void vm_slice_trace(const ana_ctx *a, const grp_cfg *g, int disp_blk, int vip_idx,
                           uint64_t disp_start, uint64_t disp_end, vm_res *out) {
    if (out->nhandler <= 0) return;
    if (!vm_vip_is_concrete(a, g, disp_blk, vip_idx)) return;

    emu_out *e = (emu_out *)calloc(1, sizeof(emu_out));
    if (!e) return;

    if (vm_safe_emu_trace(a, g->func_va, 192, e)) {
        for (int i = 0; i < e->nstep && out->ntrace < 128; i++) {
            int hi = vm_find_handler_idx(out, e->steps[i].va);
            if (hi < 0) continue;

            int end = i + 1;
            while (end < e->nstep && end < i + VM_MAX_HINS) {
                uint64_t sv = e->steps[end].va;
                if (sv == out->disp_va || sv == disp_start ||
                    (disp_start && disp_end > disp_start && sv >= disp_start && sv < disp_end)) {
                    break;
                }
                if (vm_find_handler_idx(out, sv) >= 0) break;
                end++;
            }

            char eff[40];
            vm_best_effect(e, i, end, eff, sizeof(eff));

            const vm_handler *h = &out->handlers[hi];
            vm_step *vs = &out->trace[out->ntrace++];
            vs->va = h->va;
            snprintf(vs->op, sizeof(vs->op), "%s", h->kind);
            if (eff[0]) snprintf(vs->detail, sizeof(vs->detail), "%.44s | %.31s", h->sem, eff);
            else snprintf(vs->detail, sizeof(vs->detail), "%s", h->sem);

            i = end - 1;
        }
    }

    free(e);
}

bool vm_analyze(const ana_ctx *a, uint64_t va, vm_res *out) {
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    if (!a) return false;

    grp_cfg g = {0};
    if (!grp_build(a, va, 0, &g)) return false;
    out->func_va = g.func_va;

    vm_cand best;
    memset(&best, 0, sizeof(best));
    best.disp_blk = -1;
    best.vip_idx = -1;

    vm_detect_table(a, &g, &best);
    vm_detect_threaded(a, &g, &best);
    vm_detect_switch(&g, &best);

    if (best.score <= 0) {
        grp_free(&g);
        return true;
    }

    out->detected = 1;
    out->disp_va = best.disp_va;
    out->table_va = best.table_va;
    snprintf(out->style, sizeof(out->style), "%s", best.style);

    int vip_idx = best.vip_idx;
    uint16_t vip_mask = vm_collect_vip_aliases(&g, best.disp_blk, vip_idx);
    int vsp_idx = -1;
    int vsp_indexed = 0;

    if (best.nhandler > 0) {
        vm_hinfo *hs = (vm_hinfo *)calloc((size_t)best.nhandler, sizeof(vm_hinfo));
        if (hs) {
            for (int i = 0; i < best.nhandler; i++) {
                vm_decode_handler(a, best.h_vas[i], vip_idx, vip_mask,
                                  best.disp_start, best.disp_end, best.latch_va, &hs[i]);
            }
            vm_refine_vip(hs, best.nhandler, &vip_idx);
            vip_mask = vm_collect_vip_aliases(&g, best.disp_blk, vip_idx);
            vm_detect_vsp(hs, best.nhandler, vip_idx, &vsp_idx, &vsp_indexed);

            for (int i = 0; i < best.nhandler && out->nhandler < VM_MAX_HANDLERS; i++) {
                vm_handler *h = &out->handlers[out->nhandler++];
                h->opcode = best.h_ops[i];
                h->va = best.h_vas[i];
                vm_classify_handler(a, &hs[i], vip_idx, vip_mask, vsp_idx, vsp_indexed, h);
            }
            free(hs);
        }
    }

    if (vip_idx >= 0) snprintf(out->vip_reg, sizeof(out->vip_reg), "%s", vm_reg_name(a->bin.bits, vip_idx));
    if (vsp_idx >= 0) snprintf(out->vsp_reg, sizeof(out->vsp_reg), "%s", vm_reg_name(a->bin.bits, vsp_idx));

    vm_slice_trace(a, &g, best.disp_blk, vip_idx, best.disp_start, best.disp_end, out);

    grp_free(&g);
    return true;
}
