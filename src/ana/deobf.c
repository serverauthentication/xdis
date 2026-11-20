#include "ana.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int dob_reg_id(const char *s, int *bits) {
    static const char *const r64[16] = {"rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi","r8","r9","r10","r11","r12","r13","r14","r15"};
    static const char *const r32[16] = {"eax","ecx","edx","ebx","esp","ebp","esi","edi","r8d","r9d","r10d","r11d","r12d","r13d","r14d","r15d"};
    static const char *const r16[16] = {"ax","cx","dx","bx","sp","bp","si","di","r8w","r9w","r10w","r11w","r12w","r13w","r14w","r15w"};
    static const char *const r8[16]  = {"al","cl","dl","bl","spl","bpl","sil","dil","r8b","r9b","r10b","r11b","r12b","r13b","r14b","r15b"};
    for (int i = 0; i < 16; i++) {
        if (strcmp(s, r64[i]) == 0) { *bits = 64; return i; }
        if (strcmp(s, r32[i]) == 0) { *bits = 32; return i; }
        if (strcmp(s, r16[i]) == 0) { *bits = 16; return i; }
        if (strcmp(s, r8[i])  == 0) { *bits = 8;  return i; }
    }
    return -1;
}

static void dob_trim(char *s) {
    char *p = s;
    while (*p == ' ' || *p == '\t') p++;
    if (p != s) memmove(s, p, strlen(p) + 1);
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\t')) s[--n] = 0;
}

static int dob_split(const char *ops, char a[76], char b[76]) {
    a[0] = b[0] = 0;
    if (!ops || !ops[0]) return 0;
    const char *c = strchr(ops, ',');
    if (!c) { snprintf(a, 76, "%s", ops); dob_trim(a); return 1; }
    size_t n = (size_t)(c - ops);
    if (n >= 75) n = 75;
    memcpy(a, ops, n); a[n] = 0; dob_trim(a);
    snprintf(b, 76, "%s", c + 1); dob_trim(b);
    return 2;
}

static bool dob_parse_imm(const char *s, uint64_t *v) {
    if (!s || !s[0]) return false;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        char *e = NULL;
        *v = strtoull(s + 2, &e, 16);
        return e != s + 2 && *e == 0;
    }
    return false;
}

static uint64_t dob_mask(uint64_t v, int bits) {
    if (bits == 8) return v & 0xFFULL;
    if (bits == 16) return v & 0xFFFFULL;
    if (bits == 32) return v & 0xFFFFFFFFULL;
    return v;
}

static int dob_stack_slot(const char *op, int *bits) {
    const char *p = op;
    *bits = 0;
    if (strncmp(p, "byte ptr ", 9) == 0) { *bits = 8; p += 9; }
    else if (strncmp(p, "word ptr ", 9) == 0) { *bits = 16; p += 9; }
    else if (strncmp(p, "dword ptr ", 10) == 0) { *bits = 32; p += 10; }
    else if (strncmp(p, "qword ptr ", 10) == 0) { *bits = 64; p += 10; }
    if (*p != '[') return -1;
    p++;
    int base_off = 0;
    if (strncmp(p, "rsp", 3) == 0) { base_off = 256; p += 3; }
    else if (strncmp(p, "rbp", 3) == 0) { base_off = 384; p += 3; }
    else return -1;

    int sign = 1;
    int64_t disp = 0;
    if (*p == '+') { sign = 1; p++; }
    else if (*p == '-') { sign = -1; p++; }
    else if (*p != ']') return -1;
    if (*p != ']') {
        if (strncmp(p, "0x", 2) != 0) return -1;
        disp = (int64_t)strtoull(p + 2, NULL, 16);
    }
    int idx = base_off + (int)(sign * disp);
    return (idx >= 0 && idx < 504) ? idx : -1;
}

static void dob_flush_strings(uint8_t sbuf[512], uint8_t smask[512], uint64_t sva[512], dob_res *out) {
    int i = 0;
    while (i < 512 && out->nstr < 32) {
        if (!smask[i] || sbuf[i] < 0x20 || sbuf[i] > 0x7E) { i++; continue; }
        int start = i;
        while (i < 512 && smask[i] && sbuf[i] >= 0x20 && sbuf[i] <= 0x7E) i++;
        int len = i - start;
        if (len >= 4) {
            if (len > 78) len = 78;
            dob_str *ds = &out->strs[out->nstr++];
            ds->va = sva[start];
            memcpy(ds->text, sbuf + start, (size_t)len);
            ds->text[len] = 0;
        }
    }
}

static int dob_eval_cc(const char *cc, int zf, int sf, int cf, int of) {
    if (strcmp(cc, "e") == 0 || strcmp(cc, "z") == 0) return zf;
    if (strcmp(cc, "ne") == 0 || strcmp(cc, "nz") == 0) return !zf;
    if (strcmp(cc, "b") == 0 || strcmp(cc, "c") == 0) return cf;
    if (strcmp(cc, "ae") == 0 || strcmp(cc, "nc") == 0) return !cf;
    if (strcmp(cc, "be") == 0) return cf || zf;
    if (strcmp(cc, "a") == 0) return !cf && !zf;
    if (strcmp(cc, "s") == 0) return sf;
    if (strcmp(cc, "ns") == 0) return !sf;
    if (strcmp(cc, "l") == 0) return sf != of;
    if (strcmp(cc, "ge") == 0) return sf == of;
    if (strcmp(cc, "le") == 0) return zf || (sf != of);
    if (strcmp(cc, "g") == 0) return !zf && (sf == of);
    return -1;
}

bool dob_analyze(const ana_ctx *a, uint64_t va, int upper, dob_res *out) {
    memset(out, 0, sizeof(*out));
    const bin_sec *sec = bin_sec_at(&a->bin, va);
    if (!sec || !(sec->perm & BIN_PERM_X)) return false;

    const ana_func *f = ana_func_at(a, va);
    uint64_t fstart = f ? f->start : va;
    uint64_t fend = f ? f->end : (sec->va + sec->vsize);
    if (fend - fstart > 8192) fend = fstart + 8192;
    out->func_va = fstart;

    uint64_t reg[16] = {0};
    uint8_t known[16] = {0};
    uint8_t sbuf[512] = {0}, smask[512] = {0};
    uint64_t sva[512] = {0};
    int fl_known = 0, zf = 0, sf = 0, cf = 0, of = 0;

    uint64_t cur = fstart;
    x86_ins ins;
    while (cur < fend && out->orig_ins < 512) {
        size_t av = 0;
        const uint8_t *p = bin_ptr(&a->bin, cur, &av);
        if (!p || !av) break;
        int n = arch_decode(a->bin.arch, p, av, cur, 1, 0, &ins);
        if (n <= 0) break;
        out->orig_ins++;

        const char *m = ins.mnem;
        char s0[76], s1[76];
        int nops = dob_split(ins.ops, s0, s1);
        int b0 = 64, b1 = 64;
        int r0 = dob_reg_id(s0, &b0);
        int r1 = dob_reg_id(s1, &b1);
        uint64_t imm = 0;
        int has_imm = dob_parse_imm(s1, &imm);

        if (strcmp(m, "nop") == 0 ||
            (strcmp(m, "xchg") == 0 && r0 >= 0 && r0 == r1) ||
            ((strcmp(m, "add") == 0 || strcmp(m, "sub") == 0 || strcmp(m, "or") == 0 || strcmp(m, "xor") == 0) && has_imm && imm == 0)) {
            out->junk_cut++;
            cur += (uint64_t)n;
            continue;
        }

        char note[72] = "";
        uint8_t tag = 0;

        int sslot = dob_stack_slot(s0, &b0);
        if (strcmp(m, "mov") == 0 && sslot >= 0) {
            uint64_t sv = 0;
            int got = 0;
            if (has_imm) { sv = imm; got = 1; }
            else if (r1 >= 0 && known[r1]) { sv = reg[r1]; got = 1; if (!b0) b0 = b1; }
            if (got) {
                int nb = (b0 == 8) ? 1 : (b0 == 16) ? 2 : (b0 == 32) ? 4 : 8;
                for (int k = 0; k < nb && sslot + k < 512; k++) {
                    sbuf[sslot + k] = (uint8_t)((sv >> (k * 8)) & 0xFF);
                    smask[sslot + k] = 1;
                    sva[sslot + k] = cur;
                }
            }
        }

        if (strcmp(m, "xor") == 0 && r0 >= 0 && r0 == r1) {
            reg[r0] = 0; known[r0] = 1;
            fl_known = 1; zf = 1; sf = 0; cf = 0; of = 0;
            snprintf(note, sizeof(note), "%s = 0", s0);
            out->const_folded++;
            tag = 1;
        } else if ((strcmp(m, "mov") == 0 || strcmp(m, "movabs") == 0) && r0 >= 0) {
            if (has_imm) {
                reg[r0] = dob_mask(imm, b0);
                known[r0] = 1;
            } else if (r1 >= 0 && known[r1]) {
                reg[r0] = dob_mask(reg[r1], b0);
                known[r0] = 1;
                snprintf(note, sizeof(note), "%s = 0x%llx", s0, (unsigned long long)reg[r0]);
                out->const_folded++;
                tag = 1;
            } else {
                known[r0] = 0;
            }
        } else if (strcmp(m, "lea") == 0 && r0 >= 0 && ins.has_target) {
            reg[r0] = ins.target;
            known[r0] = 1;
        } else if (r0 >= 0 && known[r0] && (has_imm || (r1 >= 0 && known[r1]))) {
            uint64_t rhs = has_imm ? imm : reg[r1];
            uint64_t lhs = reg[r0];
            int hit = 1;
            if (strcmp(m, "add") == 0) reg[r0] = dob_mask(lhs + rhs, b0);
            else if (strcmp(m, "sub") == 0) reg[r0] = dob_mask(lhs - rhs, b0);
            else if (strcmp(m, "xor") == 0) reg[r0] = dob_mask(lhs ^ rhs, b0);
            else if (strcmp(m, "and") == 0) reg[r0] = dob_mask(lhs & rhs, b0);
            else if (strcmp(m, "or") == 0)  reg[r0] = dob_mask(lhs | rhs, b0);
            else if (strcmp(m, "shl") == 0) reg[r0] = dob_mask(lhs << (rhs & 63), b0);
            else if (strcmp(m, "shr") == 0) reg[r0] = dob_mask(lhs >> (rhs & 63), b0);
            else hit = 0;
            if (hit) {
                fl_known = 1; zf = (reg[r0] == 0); sf = ((int64_t)reg[r0] < 0); cf = 0; of = 0;
                snprintf(note, sizeof(note), "folded: %s = 0x%llx", s0, (unsigned long long)reg[r0]);
                out->const_folded++;
                tag = 1;
            }
        } else if (strcmp(m, "cmp") == 0 || strcmp(m, "test") == 0) {
            int l_ok = (r0 >= 0 && known[r0]);
            int r_ok = has_imm || (r1 >= 0 && known[r1]);
            if (l_ok && r_ok) {
                uint64_t lv = reg[r0], rv = has_imm ? imm : reg[r1];
                uint64_t res = (strcmp(m, "test") == 0) ? (lv & rv) : (lv - rv);
                fl_known = 1;
                zf = (res == 0);
                sf = ((int64_t)res < 0);
                cf = (strcmp(m, "cmp") == 0) ? (lv < rv) : 0;
                of = 0;
            } else if (strcmp(m, "cmp") == 0 && r0 >= 0 && r0 == r1) {
                fl_known = 1; zf = 1; sf = 0; cf = 0; of = 0;
            } else {
                fl_known = 0;
            }
        } else if (ins.flow == X86_FLOW_JCC && fl_known) {
            int taken = dob_eval_cc(m + 1, zf, sf, cf, of);
            if (taken >= 0) {
                out->opaque_cut++;
                tag = 2;
                snprintf(note, sizeof(note), taken ? "opaque: ALWAYS TAKEN -> 0x%llx" : "opaque: NEVER TAKEN (dead branch)",
                         (unsigned long long)ins.target);
            }
        } else if ((ins.flow == X86_FLOW_JMP || ins.flow == X86_FLOW_CALL) && !ins.has_target && r0 >= 0 && known[r0]) {
            const char *sym = ana_sym_at(a, reg[r0]);
            snprintf(note, sizeof(note), "resolved -> 0x%llx %s", (unsigned long long)reg[r0], sym ? sym : "");
            out->ind_resolved++;
            tag = 3;
        } else if (ins.flow == X86_FLOW_CALL) {
            // calls clobber volatile regs
            known[0] = known[1] = known[2] = known[8] = known[9] = known[10] = known[11] = 0;
            fl_known = 0;
        } else if (r0 >= 0 && nops >= 1 && strcmp(m, "push") != 0) {
            known[r0] = 0;
        }

        if (out->nrow < 512) {
            dob_row *dr = &out->rows[out->nrow++];
            dr->va = cur;
            dr->flow = ins.flow;
            dr->tag = tag;
            snprintf(dr->mnem, sizeof(dr->mnem), "%s", ins.mnem);
            if (upper) for (char *q = dr->mnem; *q; q++) *q = (char)toupper((unsigned char)*q);
            snprintf(dr->ops, sizeof(dr->ops), "%s", ins.ops);
            snprintf(dr->note, sizeof(dr->note), "%s", note);
        }

        if (ins.flow == X86_FLOW_RET || ins.flow == X86_FLOW_TRAP) {
            memset(known, 0, sizeof(known));
            fl_known = 0;
        }
        cur += (uint64_t)n;
    }

    dob_flush_strings(sbuf, smask, sva, out);
    out->clean_ins = out->nrow;
    return out->orig_ins > 0;
}

static bool emu_read_mem(const ana_ctx *a, const uint8_t stack[4096], uint64_t sp_base, uint64_t addr, int bits, uint64_t *val) {
    int nb = bits / 8;
    if (nb < 1 || nb > 8) nb = 8;
    *val = 0;
    if (addr >= sp_base && (addr - sp_base) <= 4096ULL && (uint64_t)nb <= 4096ULL - (addr - sp_base)) {
        memcpy(val, stack + (addr - sp_base), (size_t)nb);
        return true;
    }
    uint8_t tmp[8] = {0};
    if (bin_read(&a->bin, addr, tmp, (size_t)nb) == (size_t)nb) {
        memcpy(val, tmp, (size_t)nb);
        return true;
    }
    return false;
}

static bool emu_write_mem(uint8_t stack[4096], uint64_t sp_base, uint64_t addr, int bits, uint64_t val) {
    int nb = bits / 8;
    if (nb < 1 || nb > 8) nb = 8;
    if (addr >= sp_base && (addr - sp_base) <= 4096ULL && (uint64_t)nb <= 4096ULL - (addr - sp_base)) {
        memcpy(stack + (addr - sp_base), &val, (size_t)nb);
        return true;
    }
    return false;
}

static bool emu_eval_ea(const char *raw, const uint64_t regs[16], const x86_ins *ins, uint64_t *ea, int *bits) {
    const char *p = raw;
    *bits = 64;
    if (strncmp(p, "byte ptr ", 9) == 0) { *bits = 8; p += 9; }
    else if (strncmp(p, "word ptr ", 9) == 0) { *bits = 16; p += 9; }
    else if (strncmp(p, "dword ptr ", 10) == 0) { *bits = 32; p += 10; }
    else if (strncmp(p, "qword ptr ", 10) == 0) { *bits = 64; p += 10; }
    if (*p != '[') return false;
    if (ins->target_mem && ins->has_target) { *ea = ins->target; return true; }

    char in[64];
    snprintf(in, sizeof(in), "%s", p + 1);
    char *rb = strchr(in, ']');
    if (rb) *rb = 0;
    uint64_t acc = 0;
    int sign = 1;
    char *c = in;
    while (*c) {
        if (*c == '+') { sign = 1; c++; continue; }
        if (*c == '-') { sign = -1; c++; continue; }
        char tok[32];
        int k = 0;
        while (*c && *c != '+' && *c != '-' && k < 31) tok[k++] = *c++;
        tok[k] = 0;
        char *st = strchr(tok, '*');
        if (st) {
            *st = 0;
            int rb2 = 64, r = dob_reg_id(tok, &rb2);
            if (r >= 0) acc += (uint64_t)(sign * (int64_t)(regs[r] * (uint64_t)atoi(st + 1)));
        } else if (strncmp(tok, "0x", 2) == 0) {
            acc += (uint64_t)(sign * (int64_t)strtoull(tok + 2, NULL, 16));
        } else {
            int rb2 = 64, r = dob_reg_id(tok, &rb2);
            if (r >= 0) acc += (uint64_t)(sign * (int64_t)regs[r]);
        }
    }
    *ea = acc;
    return true;
}

bool emu_trace(const ana_ctx *a, uint64_t start_va, int max_steps, emu_out *out) {
    memset(out, 0, sizeof(*out));
    if (!a || !bin_is_exec(&a->bin, start_va)) return false;
    if (max_steps < 1) max_steps = 48;
    if (max_steps > 256) max_steps = 256;

    const uint64_t sp_base = 0x7FFF0000ULL;
    uint8_t stack[4096];
    memset(stack, 0, sizeof(stack));

    out->start_va = start_va;
    out->rip = start_va;
    out->regs[4] = sp_base + 3072; // rsp
    out->regs[5] = sp_base + 3072; // rbp
    uint64_t ret_sentinel = 0xDEAD0000ULL;
    emu_write_mem(stack, sp_base, out->regs[4], 64, ret_sentinel);

    static const char *const rnames[16] = {"rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi","r8","r9","r10","r11","r12","r13","r14","r15"};
    x86_ins ins;

    for (int step = 0; step < max_steps; step++) {
        if (out->rip == ret_sentinel) {
            out->halted = 1;
            snprintf(out->stop_reason, sizeof(out->stop_reason), "returned cleanly");
            break;
        }
        size_t av = 0;
        const uint8_t *p = bin_ptr(&a->bin, out->rip, &av);
        if (!p || !av) {
            out->halted = 1;
            snprintf(out->stop_reason, sizeof(out->stop_reason), "unmapped rip 0x%llx", (unsigned long long)out->rip);
            break;
        }
        int n = arch_decode(a->bin.arch, p, av, out->rip, 1, 0, &ins);
        if (n <= 0) break;

        emu_step *st = &out->steps[out->nstep++];
        st->va = out->rip;
        snprintf(st->text, sizeof(st->text), "%-8s %s", ins.mnem, ins.ops);
        st->effect[0] = 0;

        uint64_t next_ip = out->rip + (uint64_t)n;
        const char *m = ins.mnem;
        char s0[76], s1[76];
        int nops = dob_split(ins.ops, s0, s1);
        int b0 = 64, b1 = 64;
        int r0 = dob_reg_id(s0, &b0);
        int r1 = dob_reg_id(s1, &b1);
        uint64_t imm = 0, ea = 0;
        int has_imm = dob_parse_imm(s1, &imm);
        int mb = 64;

        uint64_t rhs = 0;
        if (nops >= 2) {
            if (r1 >= 0) rhs = dob_mask(out->regs[r1], b1);
            else if (has_imm) rhs = imm;
            else if (emu_eval_ea(s1, out->regs, &ins, &ea, &mb)) {
                if (strcmp(m, "lea") == 0) rhs = ea;
                else emu_read_mem(a, stack, sp_base, ea, mb, &rhs);
            }
        }

        if (strcmp(m, "push") == 0) {
            uint64_t v = (r0 >= 0) ? out->regs[r0] : (dob_parse_imm(s0, &imm) ? imm : 0);
            out->regs[4] -= 8;
            emu_write_mem(stack, sp_base, out->regs[4], 64, v);
            snprintf(st->effect, sizeof(st->effect), "rsp=0x%llx [rsp]=0x%llx", (unsigned long long)out->regs[4], (unsigned long long)v);
        } else if (strcmp(m, "pop") == 0 && r0 >= 0) {
            uint64_t v = 0;
            emu_read_mem(a, stack, sp_base, out->regs[4], 64, &v);
            out->regs[4] += 8;
            out->regs[r0] = v;
            snprintf(st->effect, sizeof(st->effect), "%s=0x%llx", rnames[r0], (unsigned long long)v);
        } else if (strcmp(m, "mov") == 0 || strcmp(m, "movabs") == 0 || strcmp(m, "lea") == 0 || strcmp(m, "movzx") == 0 || strcmp(m, "movsx") == 0) {
            if (r0 >= 0) {
                out->regs[r0] = (b0 == 32) ? (rhs & 0xFFFFFFFFULL) : dob_mask(rhs, b0);
                snprintf(st->effect, sizeof(st->effect), "%s=0x%llx", rnames[r0], (unsigned long long)out->regs[r0]);
            } else if (emu_eval_ea(s0, out->regs, &ins, &ea, &mb)) {
                emu_write_mem(stack, sp_base, ea, mb, rhs);
                snprintf(st->effect, sizeof(st->effect), "[0x%llx]=0x%llx", (unsigned long long)ea, (unsigned long long)rhs);
            }
        } else if (r0 >= 0 && (strcmp(m, "add") == 0 || strcmp(m, "sub") == 0 || strcmp(m, "xor") == 0 ||
                   strcmp(m, "and") == 0 || strcmp(m, "or") == 0 || strcmp(m, "shl") == 0 || strcmp(m, "shr") == 0)) {
            uint64_t lv = dob_mask(out->regs[r0], b0), res = lv;
            if (strcmp(m, "add") == 0) res = lv + rhs;
            else if (strcmp(m, "sub") == 0) res = lv - rhs;
            else if (strcmp(m, "xor") == 0) res = lv ^ rhs;
            else if (strcmp(m, "and") == 0) res = lv & rhs;
            else if (strcmp(m, "or") == 0)  res = lv | rhs;
            else if (strcmp(m, "shl") == 0) res = lv << (rhs & 63);
            else if (strcmp(m, "shr") == 0) res = lv >> (rhs & 63);
            out->regs[r0] = dob_mask(res, b0);
            out->zf = (out->regs[r0] == 0);
            out->sf = ((int64_t)out->regs[r0] < 0);
            snprintf(st->effect, sizeof(st->effect), "%s=0x%llx zf=%d", rnames[r0], (unsigned long long)out->regs[r0], out->zf);
        } else if (strcmp(m, "cmp") == 0 || strcmp(m, "test") == 0) {
            uint64_t lv = (r0 >= 0) ? dob_mask(out->regs[r0], b0) : 0;
            if (r0 < 0 && emu_eval_ea(s0, out->regs, &ins, &ea, &mb)) emu_read_mem(a, stack, sp_base, ea, mb, &lv);
            uint64_t res = (strcmp(m, "test") == 0) ? (lv & rhs) : (lv - rhs);
            out->zf = (res == 0);
            out->sf = ((int64_t)res < 0);
            out->cf = (strcmp(m, "cmp") == 0) ? (lv < rhs) : 0;
            snprintf(st->effect, sizeof(st->effect), "zf=%d sf=%d cf=%d", out->zf, out->sf, out->cf);
        } else if (ins.flow == X86_FLOW_JCC && ins.has_target) {
            int taken = dob_eval_cc(m + 1, out->zf, out->sf, out->cf, 0);
            if (taken > 0) next_ip = ins.target;
            snprintf(st->effect, sizeof(st->effect), "%s -> 0x%llx", taken > 0 ? "TAKEN" : "fallthrough", (unsigned long long)next_ip);
        } else if (ins.flow == X86_FLOW_JMP) {
            if (ins.has_target && !ins.target_mem) next_ip = ins.target;
            else if (r0 >= 0) next_ip = out->regs[r0];
            snprintf(st->effect, sizeof(st->effect), "jmp -> 0x%llx", (unsigned long long)next_ip);
        } else if (ins.flow == X86_FLOW_CALL) {
            const char *sym = ins.has_target ? ana_sym_at(a, ins.target) : NULL;
            snprintf(st->effect, sizeof(st->effect), "step over call %s", sym ? sym : (ins.has_target ? ins.ops : "indirect"));
        } else if (ins.flow == X86_FLOW_RET) {
            uint64_t rv = ret_sentinel;
            emu_read_mem(a, stack, sp_base, out->regs[4], 64, &rv);
            out->regs[4] += 8;
            next_ip = rv;
            snprintf(st->effect, sizeof(st->effect), "ret -> 0x%llx (rax=0x%llx)", (unsigned long long)next_ip, (unsigned long long)out->regs[0]);
        } else if (ins.flow == X86_FLOW_TRAP) {
            out->halted = 1;
            snprintf(out->stop_reason, sizeof(out->stop_reason), "trap (%s)", m);
            break;
        }

        out->rip = next_ip;
    }

    if (!out->stop_reason[0]) snprintf(out->stop_reason, sizeof(out->stop_reason), "step limit (%d)", out->nstep);

    size_t k = 0;
    for (int i = 0; i < 4096 && k + 2 < sizeof(out->stack_ascii); ) {
        if (stack[i] >= 0x20 && stack[i] <= 0x7E) {
            int s = i;
            while (i < 4096 && stack[i] >= 0x20 && stack[i] <= 0x7E) i++;
            if (i - s >= 4) {
                if (k) out->stack_ascii[k++] = ' ';
                for (int j = s; j < i && k + 1 < sizeof(out->stack_ascii); j++) out->stack_ascii[k++] = (char)stack[j];
            }
        } else {
            i++;
        }
    }
    out->stack_ascii[k] = 0;
    return true;
}
