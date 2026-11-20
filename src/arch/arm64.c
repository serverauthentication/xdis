#include "arch.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

static const char *const a64_cc[16] = {
    "eq","ne","cs","cc","mi","pl","vs","vc",
    "hi","ls","ge","lt","gt","le","al","nv"
};

static const char *const a64_x_zr[32] = {
    "x0","x1","x2","x3","x4","x5","x6","x7",
    "x8","x9","x10","x11","x12","x13","x14","x15",
    "x16","x17","x18","x19","x20","x21","x22","x23",
    "x24","x25","x26","x27","x28","fp","lr","xzr"
};

static const char *const a64_x_sp[32] = {
    "x0","x1","x2","x3","x4","x5","x6","x7",
    "x8","x9","x10","x11","x12","x13","x14","x15",
    "x16","x17","x18","x19","x20","x21","x22","x23",
    "x24","x25","x26","x27","x28","fp","lr","sp"
};

static const char *const a64_w_zr[32] = {
    "w0","w1","w2","w3","w4","w5","w6","w7",
    "w8","w9","w10","w11","w12","w13","w14","w15",
    "w16","w17","w18","w19","w20","w21","w22","w23",
    "w24","w25","w26","w27","w28","w29","w30","wzr"
};

static const char *const a64_w_sp[32] = {
    "w0","w1","w2","w3","w4","w5","w6","w7",
    "w8","w9","w10","w11","w12","w13","w14","w15",
    "w16","w17","w18","w19","w20","w21","w22","w23",
    "w24","w25","w26","w27","w28","w29","w30","wsp"
};

static const char *const a64_fp_reg[5][32] = {
    { "b0","b1","b2","b3","b4","b5","b6","b7","b8","b9","b10","b11","b12","b13","b14","b15",
      "b16","b17","b18","b19","b20","b21","b22","b23","b24","b25","b26","b27","b28","b29","b30","b31" },
    { "h0","h1","h2","h3","h4","h5","h6","h7","h8","h9","h10","h11","h12","h13","h14","h15",
      "h16","h17","h18","h19","h20","h21","h22","h23","h24","h25","h26","h27","h28","h29","h30","h31" },
    { "s0","s1","s2","s3","s4","s5","s6","s7","s8","s9","s10","s11","s12","s13","s14","s15",
      "s16","s17","s18","s19","s20","s21","s22","s23","s24","s25","s26","s27","s28","s29","s30","s31" },
    { "d0","d1","d2","d3","d4","d5","d6","d7","d8","d9","d10","d11","d12","d13","d14","d15",
      "d16","d17","d18","d19","d20","d21","d22","d23","d24","d25","d26","d27","d28","d29","d30","d31" },
    { "q0","q1","q2","q3","q4","q5","q6","q7","q8","q9","q10","q11","q12","q13","q14","q15",
      "q16","q17","q18","q19","q20","q21","q22","q23","q24","q25","q26","q27","q28","q29","q30","q31" }
};

static const char *a64_reg(int r, int sf, int use_sp) {
    r &= 31;
    if (sf) return use_sp ? a64_x_sp[r] : a64_x_zr[r];
    return use_sp ? a64_w_sp[r] : a64_w_zr[r];
}

static const char *a64_freg(int r, int scale) {
    if (scale < 0) scale = 0;
    if (scale > 4) scale = 4;
    return a64_fp_reg[scale][r & 31];
}

static int a64_ftype_scale(int ftype) {
    if (ftype == 0) return 2; // s
    if (ftype == 1) return 3; // d
    if (ftype == 3) return 1; // h
    return -1;
}

static const char *a64_arr(int q, int size) {
    static const char *const tbl[2][4] = {
        { "8b", "4h", "2s", "1d" },
        { "16b", "8h", "4s", "2d" }
    };
    return tbl[q & 1][size & 3];
}

static const char *a64_farr(int q, int sz) {
    if (sz) return q ? "2d" : "1d";
    return q ? "4s" : "2s";
}

static int64_t a64_sext(uint32_t v, int bits) {
    uint64_t mask = (1ULL << bits) - 1ULL;
    uint64_t m = 1ULL << (bits - 1);
    return (int64_t)((((uint64_t)v & mask) ^ m) - m);
}

static int a64_decode_bitmask(int sf, int N, int immr, int imms, uint64_t *val) {
    if (!sf && N) return 0;
    uint32_t comb = ((uint32_t)(N & 1) << 6) | (~(uint32_t)(imms & 63) & 0x3FU);
    int len = -1;
    for (int i = 6; i >= 0; i--) {
        if ((comb >> i) & 1U) {
            len = i;
            break;
        }
    }
    if (len < 1) return 0;
    unsigned esize = 1U << len;
    unsigned levels = esize - 1U;
    unsigned s = (unsigned)imms & levels;
    if (s == levels) return 0;
    unsigned r = (unsigned)immr & levels;
    uint64_t mask = (esize == 64U) ? ~0ULL : ((1ULL << esize) - 1ULL);
    uint64_t welem = (s + 1U == 64U) ? ~0ULL : ((1ULL << (s + 1U)) - 1ULL);
    uint64_t rot = (r == 0U) ? welem : (((welem >> r) | (welem << (esize - r))) & mask);
    uint64_t out = 0;
    unsigned regbits = sf ? 64U : 32U;
    for (unsigned pos = 0; pos < regbits; pos += esize) out |= (rot << pos);
    *val = out;
    return 1;
}

static void a64_fmt_fpimm(uint32_t imm8, char *buf, size_t sz) {
    static const double pow2[8] = { 0.125, 0.25, 0.5, 1.0, 2.0, 4.0, 8.0, 16.0 };
    unsigned sign = (imm8 >> 7) & 1U;
    unsigned exp = ((imm8 >> 4) & 7U) ^ 4U;
    double v = (double)(16U + (imm8 & 15U)) * (1.0 / 16.0) * pow2[exp];
    if (sign) v = -v;
    snprintf(buf, sz, "#%.8g", v);
    if (!strchr(buf, '.') && !strchr(buf, 'e') && !strchr(buf, 'E')) {
        size_t n = strlen(buf);
        if (n + 2 < sz) {
            buf[n] = '.';
            buf[n + 1] = '0';
            buf[n + 2] = 0;
        }
    }
}

static void a64_fmt_prfop(int rt, char *buf, size_t sz) {
    static const char *const ty[3] = { "pld", "pli", "pst" };
    static const char *const lv[3] = { "l1", "l2", "l3" };
    int t = (rt >> 3) & 3;
    int l = (rt >> 1) & 3;
    int p = rt & 1;
    if (t <= 2 && l <= 2) {
        snprintf(buf, sz, "%s%s%s", ty[t], lv[l], p ? "strm" : "keep");
    } else {
        snprintf(buf, sz, "#0x%x", rt & 31);
    }
}

static void a64_fmt_barrier_opt(int crm, char *buf, size_t sz) {
    static const char *const opt[16] = {
        NULL,"oshld","oshst","osh",NULL,"nshld","nshst","nsh",
        NULL,"ishld","ishst","ish",NULL,"ld","st","sy"
    };
    if (opt[crm & 15]) snprintf(buf, sz, "%s", opt[crm & 15]);
    else snprintf(buf, sz, "#0x%x", crm & 15);
}

static void a64_fmt_sysreg(unsigned op0, unsigned op1, unsigned crn, unsigned crm, unsigned op2, char *buf, size_t sz) {
    uint32_t key = (op0 << 14) | (op1 << 11) | (crn << 7) | (crm << 3) | op2;
    const char *name = NULL;
    switch (key) {
    case (3U<<14)|(3U<<11)|(4U<<7)|(2U<<3)|0U:  name = "nzcv"; break;
    case (3U<<14)|(3U<<11)|(4U<<7)|(2U<<3)|1U:  name = "daif"; break;
    case (3U<<14)|(3U<<11)|(4U<<7)|(4U<<3)|0U:  name = "fpcr"; break;
    case (3U<<14)|(3U<<11)|(4U<<7)|(4U<<3)|1U:  name = "fpsr"; break;
    case (3U<<14)|(3U<<11)|(13U<<7)|(0U<<3)|2U: name = "tpidr_el0"; break;
    case (3U<<14)|(3U<<11)|(13U<<7)|(0U<<3)|3U: name = "tpidrro_el0"; break;
    case (3U<<14)|(0U<<11)|(13U<<7)|(0U<<3)|4U: name = "tpidr_el1"; break;
    case (3U<<14)|(3U<<11)|(14U<<7)|(0U<<3)|0U: name = "cntfrq_el0"; break;
    case (3U<<14)|(3U<<11)|(14U<<7)|(0U<<3)|1U: name = "cntpct_el0"; break;
    case (3U<<14)|(3U<<11)|(14U<<7)|(0U<<3)|2U: name = "cntvct_el0"; break;
    case (3U<<14)|(3U<<11)|(0U<<7)|(0U<<3)|1U:  name = "ctr_el0"; break;
    case (3U<<14)|(3U<<11)|(0U<<7)|(0U<<3)|7U:  name = "dczid_el0"; break;
    case (3U<<14)|(0U<<11)|(0U<<7)|(0U<<3)|0U:  name = "midr_el1"; break;
    case (3U<<14)|(0U<<11)|(0U<<7)|(0U<<3)|5U:  name = "mpidr_el1"; break;
    case (3U<<14)|(0U<<11)|(1U<<7)|(0U<<3)|0U:  name = "sctlr_el1"; break;
    case (3U<<14)|(0U<<11)|(2U<<7)|(0U<<3)|0U:  name = "ttbr0_el1"; break;
    case (3U<<14)|(0U<<11)|(2U<<7)|(0U<<3)|1U:  name = "ttbr1_el1"; break;
    case (3U<<14)|(0U<<11)|(2U<<7)|(0U<<3)|2U:  name = "tcr_el1"; break;
    case (3U<<14)|(0U<<11)|(4U<<7)|(0U<<3)|0U:  name = "spsr_el1"; break;
    case (3U<<14)|(0U<<11)|(4U<<7)|(0U<<3)|1U:  name = "elr_el1"; break;
    case (3U<<14)|(0U<<11)|(4U<<7)|(1U<<3)|0U:  name = "sp_el0"; break;
    case (3U<<14)|(0U<<11)|(4U<<7)|(2U<<3)|2U:  name = "currentel"; break;
    case (3U<<14)|(0U<<11)|(5U<<7)|(2U<<3)|0U:  name = "esr_el1"; break;
    case (3U<<14)|(0U<<11)|(6U<<7)|(0U<<3)|0U:  name = "far_el1"; break;
    case (3U<<14)|(0U<<11)|(10U<<7)|(2U<<3)|0U: name = "mair_el1"; break;
    case (3U<<14)|(0U<<11)|(12U<<7)|(0U<<3)|0U: name = "vbar_el1"; break;
    default: break;
    }
    if (name) snprintf(buf, sz, "%s", name);
    else snprintf(buf, sz, "s%u_%u_c%u_c%u_%u", op0, op1, crn, crm, op2);
}

static void a64_fmt_vlist(int rt, int count, const char *arr, int elem_idx, char *buf, size_t sz) {
    size_t pos = 0;
    if (sz < 4) return;
    buf[pos++] = '{';
    for (int i = 0; i < count; i++) {
        int n = snprintf(buf + pos, sz - pos, "%sv%d.%s", i ? ", " : "", (rt + i) & 31, arr);
        if (n < 0 || pos + (size_t)n + 8 >= sz) break;
        pos += (size_t)n;
    }
    if (elem_idx >= 0) {
        snprintf(buf + pos, sz - pos, "}[%d]", elem_idx);
    } else if (pos + 1 < sz) {
        buf[pos++] = '}';
        buf[pos] = 0;
    }
}

static int a64_decode_dp_imm(uint32_t w, uint64_t ip, int want_text, x86_ins *out) {
    int sf = (int)(w >> 31);
    int rd = (int)(w & 31U);
    int rn = (int)((w >> 5) & 31U);
    unsigned op1 = (w >> 23) & 7U;

    if (op1 == 0U || op1 == 1U) {
        int is_page = sf;
        uint32_t imm = (((w >> 5) & 0x7FFFFU) << 2) | ((w >> 29) & 3U);
        int64_t off = a64_sext(imm, 21);
        uint64_t tgt = is_page ? ((ip & ~0xFFFULL) + (uint64_t)(off << 12)) : (ip + (uint64_t)off);
        out->target = tgt;
        out->has_target = 1;
        out->target_mem = 1;
        if (want_text) {
            snprintf(out->mnem, sizeof(out->mnem), "%s", is_page ? "adrp" : "adr");
            snprintf(out->ops, sizeof(out->ops), "%s, 0x%llx", a64_reg(rd, 1, 0), (unsigned long long)tgt);
        }
        return 1;
    }

    if (op1 == 2U) {
        int sub = (int)((w >> 30) & 1U);
        int setf = (int)((w >> 29) & 1U);
        int sh = (int)((w >> 22) & 1U);
        uint32_t imm = (w >> 10) & 0xFFFU;
        if (sh) imm <<= 12;
        if (want_text) {
            if (!sub && !setf && !sh && imm == 0 && (rd == 31 || rn == 31)) {
                snprintf(out->mnem, sizeof(out->mnem), "mov");
                snprintf(out->ops, sizeof(out->ops), "%s, %s", a64_reg(rd, sf, 1), a64_reg(rn, sf, 1));
            } else if (setf && rd == 31) {
                snprintf(out->mnem, sizeof(out->mnem), "%s", sub ? "cmp" : "cmn");
                snprintf(out->ops, sizeof(out->ops), "%s, #0x%x", a64_reg(rn, sf, 1), imm);
            } else {
                snprintf(out->mnem, sizeof(out->mnem), "%s%s", sub ? "sub" : "add", setf ? "s" : "");
                snprintf(out->ops, sizeof(out->ops), "%s, %s, #0x%x", a64_reg(rd, sf, !setf), a64_reg(rn, sf, 1), imm);
            }
        }
        return 1;
    }

    if (op1 == 4U) {
        int opc = (int)((w >> 29) & 3U);
        int N = (int)((w >> 22) & 1U);
        int immr = (int)((w >> 16) & 63U);
        int imms = (int)((w >> 10) & 63U);
        uint64_t val = 0;
        if (!a64_decode_bitmask(sf, N, immr, imms, &val)) return 0;
        if (want_text) {
            static const char *const lg[4] = { "and", "orr", "eor", "ands" };
            if (opc == 1 && rn == 31) {
                snprintf(out->mnem, sizeof(out->mnem), "mov");
                snprintf(out->ops, sizeof(out->ops), "%s, #0x%llx", a64_reg(rd, sf, 1), (unsigned long long)val);
            } else if (opc == 3 && rd == 31) {
                snprintf(out->mnem, sizeof(out->mnem), "tst");
                snprintf(out->ops, sizeof(out->ops), "%s, #0x%llx", a64_reg(rn, sf, 0), (unsigned long long)val);
            } else {
                snprintf(out->mnem, sizeof(out->mnem), "%s", lg[opc]);
                snprintf(out->ops, sizeof(out->ops), "%s, %s, #0x%llx",
                         a64_reg(rd, sf, opc != 3), a64_reg(rn, sf, 0), (unsigned long long)val);
            }
        }
        return 1;
    }

    if (op1 == 5U) {
        static const char *const mv[4] = { "movn", NULL, "movz", "movk" };
        int opc = (int)((w >> 29) & 3U);
        int hw = (int)((w >> 21) & 3U);
        if (!mv[opc] || (!sf && hw >= 2)) return 0;
        uint32_t imm = (w >> 5) & 0xFFFFU;
        if (want_text) {
            snprintf(out->mnem, sizeof(out->mnem), "%s", mv[opc]);
            if (hw) snprintf(out->ops, sizeof(out->ops), "%s, #0x%x, lsl #%d", a64_reg(rd, sf, 0), imm, hw * 16);
            else snprintf(out->ops, sizeof(out->ops), "%s, #0x%x", a64_reg(rd, sf, 0), imm);
        }
        return 1;
    }

    if (op1 == 6U) {
        int opc = (int)((w >> 29) & 3U);
        int N = (int)((w >> 22) & 1U);
        if (opc == 3 || N != sf) return 0;
        int immr = (int)((w >> 16) & 63U);
        int imms = (int)((w >> 10) & 63U);
        int W = sf ? 64 : 32;
        if (!sf && (immr >= 32 || imms >= 32)) return 0;
        if (!want_text) return 1;

        if (opc == 0) {
            if (imms == W - 1) {
                snprintf(out->mnem, sizeof(out->mnem), "asr");
                snprintf(out->ops, sizeof(out->ops), "%s, %s, #%d", a64_reg(rd, sf, 0), a64_reg(rn, sf, 0), immr);
            } else if (immr == 0 && imms == 7) {
                snprintf(out->mnem, sizeof(out->mnem), "sxtb");
                snprintf(out->ops, sizeof(out->ops), "%s, %s", a64_reg(rd, sf, 0), a64_reg(rn, 0, 0));
            } else if (immr == 0 && imms == 15) {
                snprintf(out->mnem, sizeof(out->mnem), "sxth");
                snprintf(out->ops, sizeof(out->ops), "%s, %s", a64_reg(rd, sf, 0), a64_reg(rn, 0, 0));
            } else if (sf && immr == 0 && imms == 31) {
                snprintf(out->mnem, sizeof(out->mnem), "sxtw");
                snprintf(out->ops, sizeof(out->ops), "%s, %s", a64_reg(rd, 1, 0), a64_reg(rn, 0, 0));
            } else if (imms < immr) {
                snprintf(out->mnem, sizeof(out->mnem), "sbfiz");
                snprintf(out->ops, sizeof(out->ops), "%s, %s, #%d, #%d", a64_reg(rd, sf, 0), a64_reg(rn, sf, 0), W - immr, imms + 1);
            } else {
                snprintf(out->mnem, sizeof(out->mnem), "sbfx");
                snprintf(out->ops, sizeof(out->ops), "%s, %s, #%d, #%d", a64_reg(rd, sf, 0), a64_reg(rn, sf, 0), immr, imms - immr + 1);
            }
        } else if (opc == 1) {
            if (imms < immr) {
                if (rn == 31) {
                    snprintf(out->mnem, sizeof(out->mnem), "bfc");
                    snprintf(out->ops, sizeof(out->ops), "%s, #%d, #%d", a64_reg(rd, sf, 0), W - immr, imms + 1);
                } else {
                    snprintf(out->mnem, sizeof(out->mnem), "bfi");
                    snprintf(out->ops, sizeof(out->ops), "%s, %s, #%d, #%d", a64_reg(rd, sf, 0), a64_reg(rn, sf, 0), W - immr, imms + 1);
                }
            } else {
                snprintf(out->mnem, sizeof(out->mnem), "bfxil");
                snprintf(out->ops, sizeof(out->ops), "%s, %s, #%d, #%d", a64_reg(rd, sf, 0), a64_reg(rn, sf, 0), immr, imms - immr + 1);
            }
        } else {
            if (imms == W - 1) {
                snprintf(out->mnem, sizeof(out->mnem), "lsr");
                snprintf(out->ops, sizeof(out->ops), "%s, %s, #%d", a64_reg(rd, sf, 0), a64_reg(rn, sf, 0), immr);
            } else if (imms + 1 == immr) {
                snprintf(out->mnem, sizeof(out->mnem), "lsl");
                snprintf(out->ops, sizeof(out->ops), "%s, %s, #%d", a64_reg(rd, sf, 0), a64_reg(rn, sf, 0), W - immr);
            } else if (!sf && immr == 0 && imms == 7) {
                snprintf(out->mnem, sizeof(out->mnem), "uxtb");
                snprintf(out->ops, sizeof(out->ops), "%s, %s", a64_reg(rd, 0, 0), a64_reg(rn, 0, 0));
            } else if (!sf && immr == 0 && imms == 15) {
                snprintf(out->mnem, sizeof(out->mnem), "uxth");
                snprintf(out->ops, sizeof(out->ops), "%s, %s", a64_reg(rd, 0, 0), a64_reg(rn, 0, 0));
            } else if (imms < immr) {
                snprintf(out->mnem, sizeof(out->mnem), "ubfiz");
                snprintf(out->ops, sizeof(out->ops), "%s, %s, #%d, #%d", a64_reg(rd, sf, 0), a64_reg(rn, sf, 0), W - immr, imms + 1);
            } else {
                snprintf(out->mnem, sizeof(out->mnem), "ubfx");
                snprintf(out->ops, sizeof(out->ops), "%s, %s, #%d, #%d", a64_reg(rd, sf, 0), a64_reg(rn, sf, 0), immr, imms - immr + 1);
            }
        }
        return 1;
    }

    if (op1 == 7U) {
        int op21 = (int)((w >> 29) & 3U);
        int N = (int)((w >> 22) & 1U);
        int o0 = (int)((w >> 21) & 1U);
        int rm = (int)((w >> 16) & 31U);
        int imms = (int)((w >> 10) & 63U);
        if (op21 != 0 || N != sf || o0 != 0 || (!sf && imms >= 32)) return 0;
        if (want_text) {
            if (rn == rm) {
                snprintf(out->mnem, sizeof(out->mnem), "ror");
                snprintf(out->ops, sizeof(out->ops), "%s, %s, #%d", a64_reg(rd, sf, 0), a64_reg(rn, sf, 0), imms);
            } else {
                snprintf(out->mnem, sizeof(out->mnem), "extr");
                snprintf(out->ops, sizeof(out->ops), "%s, %s, %s, #%d", a64_reg(rd, sf, 0), a64_reg(rn, sf, 0), a64_reg(rm, sf, 0), imms);
            }
        }
        return 1;
    }

    return 0;
}

static int a64_decode_branch_sys(uint32_t w, uint64_t ip, int want_text, x86_ins *out) {
    int sf = (int)(w >> 31);
    int rd = (int)(w & 31U);
    int rn = (int)((w >> 5) & 31U);

    if ((w & 0x7C000000U) == 0x14000000U) {
        int is_bl = sf;
        int64_t off = a64_sext(w & 0x03FFFFFFU, 26) << 2;
        out->flow = is_bl ? X86_FLOW_CALL : X86_FLOW_JMP;
        out->target = ip + (uint64_t)off;
        out->has_target = 1;
        if (want_text) {
            snprintf(out->mnem, sizeof(out->mnem), "%s", is_bl ? "bl" : "b");
            snprintf(out->ops, sizeof(out->ops), "0x%llx", (unsigned long long)out->target);
        }
        return 1;
    }

    if ((w & 0x7E000000U) == 0x34000000U) {
        int nz = (int)((w >> 24) & 1U);
        int64_t off = a64_sext((w >> 5) & 0x7FFFFU, 19) << 2;
        out->flow = X86_FLOW_JCC;
        out->target = ip + (uint64_t)off;
        out->has_target = 1;
        if (want_text) {
            snprintf(out->mnem, sizeof(out->mnem), "%s", nz ? "cbnz" : "cbz");
            snprintf(out->ops, sizeof(out->ops), "%s, 0x%llx", a64_reg(rd, sf, 0), (unsigned long long)out->target);
        }
        return 1;
    }

    if ((w & 0x7E000000U) == 0x36000000U) {
        int nz = (int)((w >> 24) & 1U);
        int bit = (int)(((w >> 26) & 0x20U) | ((w >> 19) & 0x1FU));
        int64_t off = a64_sext((w >> 5) & 0x3FFFU, 14) << 2;
        out->flow = X86_FLOW_JCC;
        out->target = ip + (uint64_t)off;
        out->has_target = 1;
        if (want_text) {
            snprintf(out->mnem, sizeof(out->mnem), "%s", nz ? "tbnz" : "tbz");
            snprintf(out->ops, sizeof(out->ops), "%s, #%d, 0x%llx", a64_reg(rd, bit >= 32, 0), bit, (unsigned long long)out->target);
        }
        return 1;
    }

    if ((w & 0xFF000000U) == 0x54000000U) {
        int is_bc = (int)((w >> 4) & 1U);
        int64_t off = a64_sext((w >> 5) & 0x7FFFFU, 19) << 2;
        out->flow = X86_FLOW_JCC;
        out->target = ip + (uint64_t)off;
        out->has_target = 1;
        if (want_text) {
            snprintf(out->mnem, sizeof(out->mnem), "%s.%s", is_bc ? "bc" : "b", a64_cc[w & 15U]);
            snprintf(out->ops, sizeof(out->ops), "0x%llx", (unsigned long long)out->target);
        }
        return 1;
    }

    if ((w & 0xFF000000U) == 0xD4000000U) {
        unsigned opc = (w >> 21) & 7U;
        unsigned imm16 = (w >> 5) & 0xFFFFU;
        unsigned op2 = (w >> 2) & 7U;
        unsigned ll = w & 3U;
        if (op2 != 0U) return 0;
        const char *mn = NULL;
        if (opc == 0U && ll == 1U) mn = "svc";
        else if (opc == 0U && ll == 2U) mn = "hvc";
        else if (opc == 0U && ll == 3U) mn = "smc";
        else if (opc == 1U && ll == 0U) { mn = "brk"; out->flow = X86_FLOW_TRAP; }
        else if (opc == 2U && ll == 0U) { mn = "hlt"; out->flow = X86_FLOW_TRAP; }
        else if (opc == 5U && ll >= 1U) mn = (ll == 1U) ? "dcps1" : (ll == 2U) ? "dcps2" : "dcps3";
        if (!mn) return 0;
        if (want_text) {
            snprintf(out->mnem, sizeof(out->mnem), "%s", mn);
            if (opc != 5U || imm16) snprintf(out->ops, sizeof(out->ops), "#0x%x", imm16);
        }
        return 1;
    }

    if ((w & 0xFFC00000U) == 0xD5000000U) {
        unsigned L = (w >> 21) & 1U;
        unsigned op0 = (w >> 19) & 3U;
        unsigned op1 = (w >> 16) & 7U;
        unsigned crn = (w >> 12) & 15U;
        unsigned crm = (w >> 8) & 15U;
        unsigned op2 = (w >> 5) & 7U;
        unsigned rt = w & 31U;

        if ((w & 0xFFFFF01FU) == 0xD503201FU) {
            unsigned hint = (crm << 3) | op2;
            if (!want_text) return 1;
            switch (hint) {
            case 0:  snprintf(out->mnem, sizeof(out->mnem), "nop"); break;
            case 1:  snprintf(out->mnem, sizeof(out->mnem), "yield"); break;
            case 2:  snprintf(out->mnem, sizeof(out->mnem), "wfe"); break;
            case 3:  snprintf(out->mnem, sizeof(out->mnem), "wfi"); break;
            case 4:  snprintf(out->mnem, sizeof(out->mnem), "sev"); break;
            case 5:  snprintf(out->mnem, sizeof(out->mnem), "sevl"); break;
            case 7:  snprintf(out->mnem, sizeof(out->mnem), "xpaclri"); break;
            case 8:  snprintf(out->mnem, sizeof(out->mnem), "pacia1716"); break;
            case 10: snprintf(out->mnem, sizeof(out->mnem), "pacib1716"); break;
            case 12: snprintf(out->mnem, sizeof(out->mnem), "autia1716"); break;
            case 14: snprintf(out->mnem, sizeof(out->mnem), "autib1716"); break;
            case 16: snprintf(out->mnem, sizeof(out->mnem), "esb"); break;
            case 17: snprintf(out->mnem, sizeof(out->mnem), "psb"); snprintf(out->ops, sizeof(out->ops), "csync"); break;
            case 20: snprintf(out->mnem, sizeof(out->mnem), "csdb"); break;
            case 24: snprintf(out->mnem, sizeof(out->mnem), "paciaz"); break;
            case 25: snprintf(out->mnem, sizeof(out->mnem), "paciasp"); break;
            case 26: snprintf(out->mnem, sizeof(out->mnem), "pacibz"); break;
            case 27: snprintf(out->mnem, sizeof(out->mnem), "pacibsp"); break;
            case 28: snprintf(out->mnem, sizeof(out->mnem), "autiaz"); break;
            case 29: snprintf(out->mnem, sizeof(out->mnem), "autiasp"); break;
            case 30: snprintf(out->mnem, sizeof(out->mnem), "autibz"); break;
            case 31: snprintf(out->mnem, sizeof(out->mnem), "autibsp"); break;
            case 32: snprintf(out->mnem, sizeof(out->mnem), "bti"); break;
            case 34: snprintf(out->mnem, sizeof(out->mnem), "bti"); snprintf(out->ops, sizeof(out->ops), "c"); break;
            case 36: snprintf(out->mnem, sizeof(out->mnem), "bti"); snprintf(out->ops, sizeof(out->ops), "j"); break;
            case 38: snprintf(out->mnem, sizeof(out->mnem), "bti"); snprintf(out->ops, sizeof(out->ops), "jc"); break;
            default: snprintf(out->mnem, sizeof(out->mnem), "hint"); snprintf(out->ops, sizeof(out->ops), "#0x%x", hint); break;
            }
            return 1;
        }

        if ((w & 0xFFFFF01FU) == 0xD503301FU) {
            if (!want_text) return 1;
            char opt[16];
            a64_fmt_barrier_opt((int)crm, opt, sizeof(opt));
            if (op2 == 2U) {
                snprintf(out->mnem, sizeof(out->mnem), "clrex");
                if (crm != 15U) snprintf(out->ops, sizeof(out->ops), "#0x%x", crm);
                return 1;
            }
            if (op2 == 4U || op2 == 5U) {
                snprintf(out->mnem, sizeof(out->mnem), "%s", op2 == 4U ? "dsb" : "dmb");
                snprintf(out->ops, sizeof(out->ops), "%s", opt);
                return 1;
            }
            if (op2 == 6U) {
                snprintf(out->mnem, sizeof(out->mnem), "isb");
                if (crm != 15U) snprintf(out->ops, sizeof(out->ops), "%s", opt);
                return 1;
            }
            if (op2 == 7U && crm == 0U) {
                snprintf(out->mnem, sizeof(out->mnem), "sb");
                return 1;
            }
        }

        if (L == 0U && op0 == 0U && crn == 4U && rt == 31U) {
            if (want_text) {
                const char *pf = NULL;
                if (op1 == 0U && op2 == 5U) pf = "spsel";
                else if (op1 == 3U && op2 == 6U) pf = "daifset";
                else if (op1 == 3U && op2 == 7U) pf = "daifclr";
                else if (op1 == 0U && op2 == 4U) pf = "pan";
                else if (op1 == 0U && op2 == 3U) pf = "uao";
                snprintf(out->mnem, sizeof(out->mnem), "msr");
                if (pf) snprintf(out->ops, sizeof(out->ops), "%s, #0x%x", pf, crm);
                else snprintf(out->ops, sizeof(out->ops), "s0_%u_c4_c%u_%u, #0x%x", op1, crm, op2, crm);
            }
            return 1;
        }

        if (op0 == 1U) {
            if (want_text) {
                if (L == 0U) {
                    snprintf(out->mnem, sizeof(out->mnem), "sys");
                    if (rt == 31U) snprintf(out->ops, sizeof(out->ops), "#%u, c%u, c%u, #%u", op1, crn, crm, op2);
                    else snprintf(out->ops, sizeof(out->ops), "#%u, c%u, c%u, #%u, %s", op1, crn, crm, op2, a64_reg((int)rt, 1, 0));
                } else {
                    snprintf(out->mnem, sizeof(out->mnem), "sysl");
                    snprintf(out->ops, sizeof(out->ops), "%s, #%u, c%u, c%u, #%u", a64_reg((int)rt, 1, 0), op1, crn, crm, op2);
                }
            }
            return 1;
        }

        if (op0 >= 2U) {
            if (want_text) {
                char sr[28];
                a64_fmt_sysreg(op0, op1, crn, crm, op2, sr, sizeof(sr));
                if (L == 1U) {
                    snprintf(out->mnem, sizeof(out->mnem), "mrs");
                    snprintf(out->ops, sizeof(out->ops), "%s, %s", a64_reg((int)rt, 1, 0), sr);
                } else {
                    snprintf(out->mnem, sizeof(out->mnem), "msr");
                    snprintf(out->ops, sizeof(out->ops), "%s, %s", sr, a64_reg((int)rt, 1, 0));
                }
            }
            return 1;
        }
        return 0;
    }

    if ((w & 0xFE000000U) == 0xD6000000U) {
        unsigned opc = (w >> 21) & 15U;
        unsigned op2 = (w >> 16) & 31U;
        unsigned op3 = (w >> 10) & 63U;
        unsigned op4 = w & 31U;
        if (op2 != 31U) return 0;

        if (op3 == 0U && op4 == 0U) {
            if (opc == 0U) {
                out->flow = X86_FLOW_JMP;
                if (want_text) { snprintf(out->mnem, sizeof(out->mnem), "br"); snprintf(out->ops, sizeof(out->ops), "%s", a64_reg(rn, 1, 0)); }
                return 1;
            }
            if (opc == 1U) {
                out->flow = X86_FLOW_CALL;
                if (want_text) { snprintf(out->mnem, sizeof(out->mnem), "blr"); snprintf(out->ops, sizeof(out->ops), "%s", a64_reg(rn, 1, 0)); }
                return 1;
            }
            if (opc == 2U) {
                out->flow = X86_FLOW_RET;
                if (want_text) {
                    snprintf(out->mnem, sizeof(out->mnem), "ret");
                    if (rn != 30) snprintf(out->ops, sizeof(out->ops), "%s", a64_reg(rn, 1, 0));
                }
                return 1;
            }
            if (opc == 4U && rn == 31) {
                out->flow = X86_FLOW_RET;
                if (want_text) snprintf(out->mnem, sizeof(out->mnem), "eret");
                return 1;
            }
            if (opc == 5U && rn == 31) {
                if (want_text) snprintf(out->mnem, sizeof(out->mnem), "drps");
                return 1;
            }
        }
        if ((op3 == 2U || op3 == 3U) && op4 == 31U) {
            int b = (op3 == 3U);
            if (opc == 0U) {
                out->flow = X86_FLOW_JMP;
                if (want_text) { snprintf(out->mnem, sizeof(out->mnem), "%s", b ? "brabz" : "braaz"); snprintf(out->ops, sizeof(out->ops), "%s", a64_reg(rn, 1, 0)); }
                return 1;
            }
            if (opc == 1U) {
                out->flow = X86_FLOW_CALL;
                if (want_text) { snprintf(out->mnem, sizeof(out->mnem), "%s", b ? "blrabz" : "blraaz"); snprintf(out->ops, sizeof(out->ops), "%s", a64_reg(rn, 1, 0)); }
                return 1;
            }
            if (opc == 2U && rn == 31) {
                out->flow = X86_FLOW_RET;
                if (want_text) snprintf(out->mnem, sizeof(out->mnem), "%s", b ? "retab" : "retaa");
                return 1;
            }
            if (opc == 4U && rn == 31) {
                out->flow = X86_FLOW_RET;
                if (want_text) snprintf(out->mnem, sizeof(out->mnem), "%s", b ? "eretab" : "eretaa");
                return 1;
            }
        }
        if ((op3 == 2U || op3 == 3U) && (opc == 8U || opc == 9U)) {
            int b = (op3 == 3U);
            out->flow = (opc == 9U) ? X86_FLOW_CALL : X86_FLOW_JMP;
            if (want_text) {
                snprintf(out->mnem, sizeof(out->mnem), "%s%s", opc == 9U ? "blra" : "bra", b ? "b" : "a");
                snprintf(out->ops, sizeof(out->ops), "%s, %s", a64_reg(rn, 1, 0), a64_reg((int)op4, 1, 1));
            }
            return 1;
        }
    }

    return 0;
}

static int a64_decode_ldst(uint32_t w, uint64_t ip, int want_text, x86_ins *out) {
    int rt = (int)(w & 31U);
    int rn = (int)((w >> 5) & 31U);
    int rm = (int)((w >> 16) & 31U);

    // AdvSIMD Load/Store multiple structures
    if ((w & 0xBFBF0000U) == 0x0C000000U || (w & 0xBFA00000U) == 0x0C800000U) {
        int q = (int)((w >> 30) & 1U);
        int post = (int)((w >> 23) & 1U);
        int ld = (int)((w >> 22) & 1U);
        unsigned opc = (w >> 12) & 15U;
        int sz = (int)((w >> 10) & 3U);
        int nregs = 0, stype = 0;
        switch (opc) {
        case 0x0U: nregs = 4; stype = 4; break;
        case 0x2U: nregs = 4; stype = 1; break;
        case 0x4U: nregs = 3; stype = 3; break;
        case 0x6U: nregs = 3; stype = 1; break;
        case 0x7U: nregs = 1; stype = 1; break;
        case 0x8U: nregs = 2; stype = 2; break;
        case 0xAU: nregs = 2; stype = 1; break;
        default: return 0;
        }
        if (sz == 3 && !q && stype != 1) return 0;
        if (want_text) {
            char vlist[48];
            a64_fmt_vlist(rt, nregs, a64_arr(q, sz), -1, vlist, sizeof(vlist));
            snprintf(out->mnem, sizeof(out->mnem), "%s%d", ld ? "ld" : "st", stype);
            if (!post) {
                snprintf(out->ops, sizeof(out->ops), "%s, [%s]", vlist, a64_reg(rn, 1, 1));
            } else if (rm == 31) {
                snprintf(out->ops, sizeof(out->ops), "%s, [%s], #%d", vlist, a64_reg(rn, 1, 1), nregs * (q ? 16 : 8));
            } else {
                snprintf(out->ops, sizeof(out->ops), "%s, [%s], %s", vlist, a64_reg(rn, 1, 1), a64_reg(rm, 1, 0));
            }
        }
        return 1;
    }

    // AdvSIMD Load/Store single structure & replicate (ld1r..ld4r)
    if ((w & 0xBF9F0000U) == 0x0D000000U || (w & 0xBF800000U) == 0x0D800000U) {
        int q = (int)((w >> 30) & 1U);
        int post = (int)((w >> 23) & 1U);
        int ld = (int)((w >> 22) & 1U);
        int R = (int)((w >> 21) & 1U);
        unsigned opc = (w >> 13) & 7U;
        int S = (int)((w >> 12) & 1U);
        int sz = (int)((w >> 10) & 3U);
        int selem = (int)(((opc & 1U) << 1) | (unsigned)R) + 1;
        unsigned scale_hi = opc >> 1;

        if (scale_hi == 3U) {
            if (!ld || S) return 0;
            if (want_text) {
                char vlist[48];
                a64_fmt_vlist(rt, selem, a64_arr(q, sz), -1, vlist, sizeof(vlist));
                snprintf(out->mnem, sizeof(out->mnem), "ld%dr", selem);
                if (!post) {
                    snprintf(out->ops, sizeof(out->ops), "%s, [%s]", vlist, a64_reg(rn, 1, 1));
                } else if (rm == 31) {
                    snprintf(out->ops, sizeof(out->ops), "%s, [%s], #%d", vlist, a64_reg(rn, 1, 1), selem * (1 << sz));
                } else {
                    snprintf(out->ops, sizeof(out->ops), "%s, [%s], %s", vlist, a64_reg(rn, 1, 1), a64_reg(rm, 1, 0));
                }
            }
            return 1;
        }

        const char *ename = NULL;
        int idx = 0, ebytes = 0;
        if (scale_hi == 0U) {
            ename = "b"; idx = (q << 3) | (S << 2) | sz; ebytes = 1;
        } else if (scale_hi == 1U && (sz & 1) == 0) {
            ename = "h"; idx = (q << 2) | (S << 1) | (sz >> 1); ebytes = 2;
        } else if (scale_hi == 2U && sz == 0) {
            ename = "s"; idx = (q << 1) | S; ebytes = 4;
        } else if (scale_hi == 2U && sz == 1 && S == 0) {
            ename = "d"; idx = q; ebytes = 8;
        } else {
            return 0;
        }
        if (want_text) {
            char vlist[48];
            a64_fmt_vlist(rt, selem, ename, idx, vlist, sizeof(vlist));
            snprintf(out->mnem, sizeof(out->mnem), "%s%d", ld ? "ld" : "st", selem);
            if (!post) {
                snprintf(out->ops, sizeof(out->ops), "%s, [%s]", vlist, a64_reg(rn, 1, 1));
            } else if (rm == 31) {
                snprintf(out->ops, sizeof(out->ops), "%s, [%s], #%d", vlist, a64_reg(rn, 1, 1), selem * ebytes);
            } else {
                snprintf(out->ops, sizeof(out->ops), "%s, [%s], %s", vlist, a64_reg(rn, 1, 1), a64_reg(rm, 1, 0));
            }
        }
        return 1;
    }

    // Load/Store Exclusive, Load-Acquire/Store-Release, CAS/CASP
    if ((w & 0x3F000000U) == 0x08000000U) {
        static const char *const szs[4] = { "b", "h", "", "" };
        int sz = (int)((w >> 30) & 3U);
        int o2 = (int)((w >> 23) & 1U);
        int L = (int)((w >> 22) & 1U);
        int o1 = (int)((w >> 21) & 1U);
        int rs = (int)((w >> 16) & 31U);
        int o0 = (int)((w >> 15) & 1U);
        int rt2 = (int)((w >> 10) & 31U);
        int sf = (sz == 3);

        if (!want_text) return 1;
        if (o2 == 0 && o1 == 0) {
            if (L == 0) {
                snprintf(out->mnem, sizeof(out->mnem), "%s%s", o0 ? "stlxr" : "stxr", szs[sz]);
                snprintf(out->ops, sizeof(out->ops), "%s, %s, [%s]", a64_reg(rs, 0, 0), a64_reg(rt, sf, 0), a64_reg(rn, 1, 1));
            } else {
                snprintf(out->mnem, sizeof(out->mnem), "%s%s", o0 ? "ldaxr" : "ldxr", szs[sz]);
                snprintf(out->ops, sizeof(out->ops), "%s, [%s]", a64_reg(rt, sf, 0), a64_reg(rn, 1, 1));
            }
            return 1;
        }
        if (o2 == 0 && o1 == 1) {
            if (sz >= 2) {
                if (L == 0) {
                    snprintf(out->mnem, sizeof(out->mnem), "%s", o0 ? "stlxp" : "stxp");
                    snprintf(out->ops, sizeof(out->ops), "%s, %s, %s, [%s]", a64_reg(rs, 0, 0), a64_reg(rt, sf, 0), a64_reg(rt2, sf, 0), a64_reg(rn, 1, 1));
                } else {
                    snprintf(out->mnem, sizeof(out->mnem), "%s", o0 ? "ldaxp" : "ldxp");
                    snprintf(out->ops, sizeof(out->ops), "%s, %s, [%s]", a64_reg(rt, sf, 0), a64_reg(rt2, sf, 0), a64_reg(rn, 1, 1));
                }
                return 1;
            }
            if (rt2 == 31) {
                int psf = (sz == 1);
                snprintf(out->mnem, sizeof(out->mnem), "casp%s%s", L ? "a" : "", o0 ? "l" : "");
                snprintf(out->ops, sizeof(out->ops), "%s, %s, %s, %s, [%s]",
                         a64_reg(rs, psf, 0), a64_reg((rs + 1) & 31, psf, 0),
                         a64_reg(rt, psf, 0), a64_reg((rt + 1) & 31, psf, 0), a64_reg(rn, 1, 1));
                return 1;
            }
            return 0;
        }
        if (o2 == 1 && o1 == 0) {
            const char *base = L ? (o0 ? "ldar" : "ldlar") : (o0 ? "stlr" : "stllr");
            snprintf(out->mnem, sizeof(out->mnem), "%s%s", base, szs[sz]);
            snprintf(out->ops, sizeof(out->ops), "%s, [%s]", a64_reg(rt, sf, 0), a64_reg(rn, 1, 1));
            return 1;
        }
        if (o2 == 1 && o1 == 1 && rt2 == 31) {
            snprintf(out->mnem, sizeof(out->mnem), "cas%s%s%s", L ? "a" : "", o0 ? "l" : "", szs[sz]);
            snprintf(out->ops, sizeof(out->ops), "%s, %s, [%s]", a64_reg(rs, sf, 0), a64_reg(rt, sf, 0), a64_reg(rn, 1, 1));
            return 1;
        }
        return 0;
    }

    // Load Register (PC-relative literal — Integer & SIMD/FP)
    if ((w & 0x3B000000U) == 0x18000000U) {
        int opc = (int)((w >> 30) & 3U);
        int V = (int)((w >> 26) & 1U);
        int64_t off = a64_sext((w >> 5) & 0x7FFFFU, 19) << 2;
        if (V && opc == 3) return 0;
        out->target = ip + (uint64_t)off;
        out->has_target = 1;
        out->target_mem = 1;
        if (want_text) {
            if (V) {
                snprintf(out->mnem, sizeof(out->mnem), "ldr");
                snprintf(out->ops, sizeof(out->ops), "%s, 0x%llx", a64_freg(rt, opc + 2), (unsigned long long)out->target);
            } else if (opc == 3) {
                char pf[16];
                a64_fmt_prfop(rt, pf, sizeof(pf));
                snprintf(out->mnem, sizeof(out->mnem), "prfm");
                snprintf(out->ops, sizeof(out->ops), "%s, 0x%llx", pf, (unsigned long long)out->target);
            } else {
                snprintf(out->mnem, sizeof(out->mnem), "%s", opc == 2 ? "ldrsw" : "ldr");
                snprintf(out->ops, sizeof(out->ops), "%s, 0x%llx", a64_reg(rt, opc >= 1, 0), (unsigned long long)out->target);
            }
        }
        return 1;
    }

    // Load/Store Pair (ldp/stp/ldnp/stnp/ldpsw — Integer & SIMD/FP s/d/q)
    if ((w & 0x3A000000U) == 0x28000000U) {
        int opc = (int)((w >> 30) & 3U);
        int V = (int)((w >> 26) & 1U);
        int mode = (int)((w >> 23) & 3U);
        int ld = (int)((w >> 22) & 1U);
        int rt2 = (int)((w >> 10) & 31U);
        if (opc == 3) return 0;
        if (!V && opc == 1 && (!ld || mode == 0)) return 0;

        int scale = V ? (4 << opc) : (opc == 2 ? 8 : 4);
        int64_t imm = a64_sext((w >> 15) & 0x7FU, 7) * (int64_t)scale;
        if (want_text) {
            const char *r1 = V ? a64_freg(rt, opc + 2) : a64_reg(rt, opc >= 1, 0);
            const char *r2 = V ? a64_freg(rt2, opc + 2) : a64_reg(rt2, opc >= 1, 0);
            const char *mn = (!V && opc == 1) ? "ldpsw"
                           : (mode == 0) ? (ld ? "ldnp" : "stnp")
                           : (ld ? "ldp" : "stp");
            snprintf(out->mnem, sizeof(out->mnem), "%s", mn);
            if (mode == 1) {
                snprintf(out->ops, sizeof(out->ops), "%s, %s, [%s], #%lld", r1, r2, a64_reg(rn, 1, 1), (long long)imm);
            } else if (mode == 3) {
                snprintf(out->ops, sizeof(out->ops), "%s, %s, [%s, #%lld]!", r1, r2, a64_reg(rn, 1, 1), (long long)imm);
            } else if (imm == 0) {
                snprintf(out->ops, sizeof(out->ops), "%s, %s, [%s]", r1, r2, a64_reg(rn, 1, 1));
            } else {
                snprintf(out->ops, sizeof(out->ops), "%s, %s, [%s, #%lld]", r1, r2, a64_reg(rn, 1, 1), (long long)imm);
            }
        }
        return 1;
    }

    // Load/Store Register family (Unsigned imm, Unscaled, Pre/Post, Unpriv, Reg offset, LSE Atomics, PAC ldraa/ldrab)
    if ((w & 0x3A000000U) == 0x38000000U) {
        int sz = (int)((w >> 30) & 3U);
        int V = (int)((w >> 26) & 1U);
        int is_uimm = (int)((w >> 24) & 1U);
        int opc = (int)((w >> 22) & 3U);
        int bit21 = (int)((w >> 21) & 1U);
        int lo2 = (int)((w >> 10) & 3U);

        // LSE Atomics & LDAPR (V==0, is_uimm==0, bit21==1, lo2==0)
        if (!V && !is_uimm && bit21 && lo2 == 0) {
            static const char *const szs[4] = { "b", "h", "", "" };
            static const char *const aop[8] = { "add","clr","eor","set","smax","smin","umax","umin" };
            int A = (opc >> 1) & 1;
            int R = opc & 1;
            int rs = rm;
            int o3 = (int)((w >> 15) & 1U);
            int op = (int)((w >> 12) & 7U);
            int sf = (sz == 3);
            if (o3 == 1 && op == 4 && A == 1 && R == 0 && rs == 31) {
                if (want_text) {
                    snprintf(out->mnem, sizeof(out->mnem), "ldapr%s", szs[sz]);
                    snprintf(out->ops, sizeof(out->ops), "%s, [%s]", a64_reg(rt, sf, 0), a64_reg(rn, 1, 1));
                }
                return 1;
            }
            if (o3 == 1 && op == 0) {
                if (want_text) {
                    snprintf(out->mnem, sizeof(out->mnem), "swp%s%s%s", A ? "a" : "", R ? "l" : "", szs[sz]);
                    snprintf(out->ops, sizeof(out->ops), "%s, %s, [%s]", a64_reg(rs, sf, 0), a64_reg(rt, sf, 0), a64_reg(rn, 1, 1));
                }
                return 1;
            }
            if (o3 == 0) {
                if (want_text) {
                    if (rt == 31 && !A) {
                        snprintf(out->mnem, sizeof(out->mnem), "st%s%s%s", aop[op], R ? "l" : "", szs[sz]);
                        snprintf(out->ops, sizeof(out->ops), "%s, [%s]", a64_reg(rs, sf, 0), a64_reg(rn, 1, 1));
                    } else {
                        snprintf(out->mnem, sizeof(out->mnem), "ld%s%s%s%s", aop[op], A ? "a" : "", R ? "l" : "", szs[sz]);
                        snprintf(out->ops, sizeof(out->ops), "%s, %s, [%s]", a64_reg(rs, sf, 0), a64_reg(rt, sf, 0), a64_reg(rn, 1, 1));
                    }
                }
                return 1;
            }
            return 0;
        }

        // PAC Load Register (ldraa/ldrab: V==0, is_uimm==0, bit21==1, sz==3, (lo2 & 1)==1)
        if (!V && !is_uimm && bit21 && sz == 3 && (lo2 & 1) == 1) {
            int M = (opc >> 1) & 1;
            int S = (int)((w >> 22) & 1U);
            int W = (lo2 >> 1) & 1;
            uint32_t imm10 = ((uint32_t)S << 9) | ((w >> 12) & 0x1FFU);
            int64_t off = a64_sext(imm10, 10) * 8;
            if (want_text) {
                snprintf(out->mnem, sizeof(out->mnem), "%s", M ? "ldrab" : "ldraa");
                if (W) snprintf(out->ops, sizeof(out->ops), "%s, [%s, #%lld]!", a64_reg(rt, 1, 0), a64_reg(rn, 1, 1), (long long)off);
                else if (off) snprintf(out->ops, sizeof(out->ops), "%s, [%s, #%lld]", a64_reg(rt, 1, 0), a64_reg(rn, 1, 1), (long long)off);
                else snprintf(out->ops, sizeof(out->ops), "%s, [%s]", a64_reg(rt, 1, 0), a64_reg(rn, 1, 1));
            }
            return 1;
        }

        // Determine mnemonic, register width, and scale for Integer vs SIMD/FP
        int scale = 0;
        int reg_sf = 0;
        int is_prf = 0;
        const char *base_mn = NULL;

        if (V) {
            if ((opc & 2) && sz != 0) return 0;
            scale = (opc & 2) ? 4 : sz;
            base_mn = (opc & 1) ? "ldr" : "str";
        } else {
            scale = sz;
            static const char *const imn[4][4] = {
                { "strb", "ldrb", "ldrsb", "ldrsb" },
                { "strh", "ldrh", "ldrsh", "ldrsh" },
                { "str",  "ldr",  "ldrsw", NULL    },
                { "str",  "ldr",  "prfm",  NULL    }
            };
            base_mn = imn[sz][opc];
            if (!base_mn) return 0;
            if (sz == 3 && opc == 2) is_prf = 1;
            reg_sf = (sz == 3) || (opc == 2);
        }

        char rbuf[16];
        const char *rt_str;
        if (V) {
            rt_str = a64_freg(rt, scale);
        } else if (is_prf) {
            a64_fmt_prfop(rt, rbuf, sizeof(rbuf));
            rt_str = rbuf;
        } else {
            rt_str = a64_reg(rt, reg_sf, 0);
        }

        // Unsigned Immediate Offset (is_uimm == 1)
        if (is_uimm) {
            uint32_t imm = ((w >> 10) & 0xFFFU) << scale;
            if (want_text) {
                snprintf(out->mnem, sizeof(out->mnem), "%s", base_mn);
                if (imm) snprintf(out->ops, sizeof(out->ops), "%s, [%s, #0x%x]", rt_str, a64_reg(rn, 1, 1), imm);
                else snprintf(out->ops, sizeof(out->ops), "%s, [%s]", rt_str, a64_reg(rn, 1, 1));
            }
            return 1;
        }

        // Register Offset (is_uimm == 0, bit21 == 1, lo2 == 2)
        if (bit21 && lo2 == 2) {
            int opt = (int)((w >> 13) & 7U);
            int S = (int)((w >> 12) & 1U);
            const char *ext = (opt == 2) ? "uxtw" : (opt == 3) ? "lsl" : (opt == 6) ? "sxtw" : (opt == 7) ? "sxtx" : NULL;
            if (!ext) return 0;
            if (want_text) {
                snprintf(out->mnem, sizeof(out->mnem), "%s", base_mn);
                const char *rm_str = a64_reg(rm, (opt & 1) != 0, 0);
                if (opt == 3 && !S) {
                    snprintf(out->ops, sizeof(out->ops), "%s, [%s, %s]", rt_str, a64_reg(rn, 1, 1), rm_str);
                } else if (S) {
                    snprintf(out->ops, sizeof(out->ops), "%s, [%s, %s, %s #%d]", rt_str, a64_reg(rn, 1, 1), rm_str, ext, scale);
                } else {
                    snprintf(out->ops, sizeof(out->ops), "%s, [%s, %s, %s]", rt_str, a64_reg(rn, 1, 1), rm_str, ext);
                }
            }
            return 1;
        }

        // Unscaled / Post-index / Unprivileged / Pre-index (is_uimm == 0, bit21 == 0)
        if (!bit21) {
            if (V && lo2 == 2) return 0;
            int64_t imm9 = a64_sext((w >> 12) & 0x1FFU, 9);
            if (!want_text) return 1;

            if (lo2 == 0 || lo2 == 2) {
                char ins = (lo2 == 0) ? 'u' : 't';
                if (is_prf) {
                    if (lo2 == 2) return 0;
                    snprintf(out->mnem, sizeof(out->mnem), "prfum");
                } else {
                    // Insert 'u' or 't' after "ld"/"st" (skipping 'r' -> "ldur"/"stur"/"ldtr"/"sttr")
                    snprintf(out->mnem, sizeof(out->mnem), "%c%c%c%s", base_mn[0], base_mn[1], ins, base_mn + 2);
                }
                if (imm9) snprintf(out->ops, sizeof(out->ops), "%s, [%s, #%lld]", rt_str, a64_reg(rn, 1, 1), (long long)imm9);
                else snprintf(out->ops, sizeof(out->ops), "%s, [%s]", rt_str, a64_reg(rn, 1, 1));
                return 1;
            }
            if (is_prf) return 0;
            snprintf(out->mnem, sizeof(out->mnem), "%s", base_mn);
            if (lo2 == 1) snprintf(out->ops, sizeof(out->ops), "%s, [%s], #%lld", rt_str, a64_reg(rn, 1, 1), (long long)imm9);
            else snprintf(out->ops, sizeof(out->ops), "%s, [%s, #%lld]!", rt_str, a64_reg(rn, 1, 1), (long long)imm9);
            return 1;
        }
    }

    return 0;
}

static int a64_decode_dp_reg(uint32_t w, int want_text, x86_ins *out) {
    static const char *const sh_n[4] = { "lsl", "lsr", "asr", "ror" };
    static const char *const ext_n[8] = { "uxtb","uxth","uxtw","uxtx","sxtb","sxth","sxtw","sxtx" };
    int sf = (int)(w >> 31);
    int rd = (int)(w & 31U);
    int rn = (int)((w >> 5) & 31U);
    int rm = (int)((w >> 16) & 31U);
    int op1 = (int)((w >> 28) & 1U);
    unsigned op2 = (w >> 21) & 15U;

    // Logical (shifted register)
    if (op1 == 0 && (op2 & 8U) == 0U) {
        static const char *const lg[4][2] = {
            { "and", "bic" }, { "orr", "orn" }, { "eor", "eon" }, { "ands", "bics" }
        };
        int opc = (int)((w >> 29) & 3U);
        int sh = (int)((w >> 22) & 3U);
        int neg = (int)((w >> 21) & 1U);
        int imm6 = (int)((w >> 10) & 63U);
        if (!sf && imm6 >= 32) return 0;
        if (!want_text) return 1;

        char sbuf[16] = "";
        if (imm6) snprintf(sbuf, sizeof(sbuf), ", %s #%d", sh_n[sh], imm6);

        if (opc == 1 && !neg && rn == 31 && sh == 0 && imm6 == 0) {
            snprintf(out->mnem, sizeof(out->mnem), "mov");
            snprintf(out->ops, sizeof(out->ops), "%s, %s", a64_reg(rd, sf, 0), a64_reg(rm, sf, 0));
        } else if (opc == 1 && neg && rn == 31) {
            snprintf(out->mnem, sizeof(out->mnem), "mvn");
            snprintf(out->ops, sizeof(out->ops), "%s, %s%s", a64_reg(rd, sf, 0), a64_reg(rm, sf, 0), sbuf);
        } else if (opc == 3 && !neg && rd == 31) {
            snprintf(out->mnem, sizeof(out->mnem), "tst");
            snprintf(out->ops, sizeof(out->ops), "%s, %s%s", a64_reg(rn, sf, 0), a64_reg(rm, sf, 0), sbuf);
        } else {
            snprintf(out->mnem, sizeof(out->mnem), "%s", lg[opc][neg]);
            snprintf(out->ops, sizeof(out->ops), "%s, %s, %s%s", a64_reg(rd, sf, 0), a64_reg(rn, sf, 0), a64_reg(rm, sf, 0), sbuf);
        }
        return 1;
    }

    // Add/Subtract (shifted register)
    if (op1 == 0 && (op2 & 9U) == 8U) {
        int sub = (int)((w >> 30) & 1U);
        int setf = (int)((w >> 29) & 1U);
        int sh = (int)((w >> 22) & 3U);
        int imm6 = (int)((w >> 10) & 63U);
        if (sh == 3 || (!sf && imm6 >= 32)) return 0;
        if (!want_text) return 1;

        char sbuf[16] = "";
        if (imm6) snprintf(sbuf, sizeof(sbuf), ", %s #%d", sh_n[sh], imm6);

        if (setf && rd == 31) {
            snprintf(out->mnem, sizeof(out->mnem), "%s", sub ? "cmp" : "cmn");
            snprintf(out->ops, sizeof(out->ops), "%s, %s%s", a64_reg(rn, sf, 0), a64_reg(rm, sf, 0), sbuf);
        } else if (sub && rn == 31) {
            snprintf(out->mnem, sizeof(out->mnem), "%s", setf ? "negs" : "neg");
            snprintf(out->ops, sizeof(out->ops), "%s, %s%s", a64_reg(rd, sf, 0), a64_reg(rm, sf, 0), sbuf);
        } else {
            snprintf(out->mnem, sizeof(out->mnem), "%s%s", sub ? "sub" : "add", setf ? "s" : "");
            snprintf(out->ops, sizeof(out->ops), "%s, %s, %s%s", a64_reg(rd, sf, 0), a64_reg(rn, sf, 0), a64_reg(rm, sf, 0), sbuf);
        }
        return 1;
    }

    // Add/Subtract (extended register)
    if (op1 == 0 && (op2 & 9U) == 9U) {
        int sub = (int)((w >> 30) & 1U);
        int setf = (int)((w >> 29) & 1U);
        int opt = (int)((w >> 22) & 3U);
        int ext = (int)((w >> 13) & 7U);
        int imm3 = (int)((w >> 10) & 7U);
        if (opt != 0 || imm3 > 4) return 0;
        if (!want_text) return 1;

        int rm_sf = sf && (ext == 3 || ext == 7);
        int use_lsl = (rd == 31 || rn == 31) && ((sf && ext == 3) || (!sf && ext == 2));
        char ebuf[20] = "";
        if (use_lsl) {
            if (imm3) snprintf(ebuf, sizeof(ebuf), ", lsl #%d", imm3);
        } else if (imm3) {
            snprintf(ebuf, sizeof(ebuf), ", %s #%d", ext_n[ext], imm3);
        } else {
            snprintf(ebuf, sizeof(ebuf), ", %s", ext_n[ext]);
        }

        if (setf && rd == 31) {
            snprintf(out->mnem, sizeof(out->mnem), "%s", sub ? "cmp" : "cmn");
            snprintf(out->ops, sizeof(out->ops), "%s, %s%s", a64_reg(rn, sf, 1), a64_reg(rm, rm_sf, 0), ebuf);
        } else {
            snprintf(out->mnem, sizeof(out->mnem), "%s%s", sub ? "sub" : "add", setf ? "s" : "");
            snprintf(out->ops, sizeof(out->ops), "%s, %s, %s%s", a64_reg(rd, sf, !setf), a64_reg(rn, sf, 1), a64_reg(rm, rm_sf, 0), ebuf);
        }
        return 1;
    }

    // Add/Subtract (with carry)
    if ((w & 0x1FE0FC00U) == 0x1A000000U) {
        int sub = (int)((w >> 30) & 1U);
        int setf = (int)((w >> 29) & 1U);
        if (want_text) {
            if (sub && rn == 31) {
                snprintf(out->mnem, sizeof(out->mnem), "%s", setf ? "ngcs" : "ngc");
                snprintf(out->ops, sizeof(out->ops), "%s, %s", a64_reg(rd, sf, 0), a64_reg(rm, sf, 0));
            } else {
                snprintf(out->mnem, sizeof(out->mnem), "%s%s", sub ? "sbc" : "adc", setf ? "s" : "");
                snprintf(out->ops, sizeof(out->ops), "%s, %s, %s", a64_reg(rd, sf, 0), a64_reg(rn, sf, 0), a64_reg(rm, sf, 0));
            }
        }
        return 1;
    }

    // Conditional Compare (register & immediate)
    if ((w & 0x3FE00410U) == 0x3A400000U) {
        int sub = (int)((w >> 30) & 1U);
        int is_imm = (int)((w >> 11) & 1U);
        int cond = (int)((w >> 12) & 15U);
        int nzcv = (int)(w & 15U);
        if (want_text) {
            snprintf(out->mnem, sizeof(out->mnem), "%s", sub ? "ccmp" : "ccmn");
            if (is_imm) snprintf(out->ops, sizeof(out->ops), "%s, #0x%x, #0x%x, %s", a64_reg(rn, sf, 0), rm, nzcv, a64_cc[cond]);
            else snprintf(out->ops, sizeof(out->ops), "%s, %s, #0x%x, %s", a64_reg(rn, sf, 0), a64_reg(rm, sf, 0), nzcv, a64_cc[cond]);
        }
        return 1;
    }

    // Conditional Select
    if ((w & 0x3FE00800U) == 0x1A800000U) {
        int op = (int)((w >> 30) & 1U);
        int cond = (int)((w >> 12) & 15U);
        int op2_cs = (int)((w >> 10) & 3U);
        if (op2_cs > 1) return 0;
        if (!want_text) return 1;

        int inv = (cond & 0xE) != 0xE;
        if (op == 0 && op2_cs == 0) {
            snprintf(out->mnem, sizeof(out->mnem), "csel");
            snprintf(out->ops, sizeof(out->ops), "%s, %s, %s, %s", a64_reg(rd, sf, 0), a64_reg(rn, sf, 0), a64_reg(rm, sf, 0), a64_cc[cond]);
        } else if (op == 0 && op2_cs == 1) {
            if (rn == 31 && rm == 31 && inv) {
                snprintf(out->mnem, sizeof(out->mnem), "cset");
                snprintf(out->ops, sizeof(out->ops), "%s, %s", a64_reg(rd, sf, 0), a64_cc[cond ^ 1]);
            } else if (rn == rm && rn != 31 && inv) {
                snprintf(out->mnem, sizeof(out->mnem), "cinc");
                snprintf(out->ops, sizeof(out->ops), "%s, %s, %s", a64_reg(rd, sf, 0), a64_reg(rn, sf, 0), a64_cc[cond ^ 1]);
            } else {
                snprintf(out->mnem, sizeof(out->mnem), "csinc");
                snprintf(out->ops, sizeof(out->ops), "%s, %s, %s, %s", a64_reg(rd, sf, 0), a64_reg(rn, sf, 0), a64_reg(rm, sf, 0), a64_cc[cond]);
            }
        } else if (op == 1 && op2_cs == 0) {
            if (rn == 31 && rm == 31 && inv) {
                snprintf(out->mnem, sizeof(out->mnem), "csetm");
                snprintf(out->ops, sizeof(out->ops), "%s, %s", a64_reg(rd, sf, 0), a64_cc[cond ^ 1]);
            } else if (rn == rm && rn != 31 && inv) {
                snprintf(out->mnem, sizeof(out->mnem), "cinv");
                snprintf(out->ops, sizeof(out->ops), "%s, %s, %s", a64_reg(rd, sf, 0), a64_reg(rn, sf, 0), a64_cc[cond ^ 1]);
            } else {
                snprintf(out->mnem, sizeof(out->mnem), "csinv");
                snprintf(out->ops, sizeof(out->ops), "%s, %s, %s, %s", a64_reg(rd, sf, 0), a64_reg(rn, sf, 0), a64_reg(rm, sf, 0), a64_cc[cond]);
            }
        } else {
            if (rn == rm && inv) {
                snprintf(out->mnem, sizeof(out->mnem), "cneg");
                snprintf(out->ops, sizeof(out->ops), "%s, %s, %s", a64_reg(rd, sf, 0), a64_reg(rn, sf, 0), a64_cc[cond ^ 1]);
            } else {
                snprintf(out->mnem, sizeof(out->mnem), "csneg");
                snprintf(out->ops, sizeof(out->ops), "%s, %s, %s, %s", a64_reg(rd, sf, 0), a64_reg(rn, sf, 0), a64_reg(rm, sf, 0), a64_cc[cond]);
            }
        }
        return 1;
    }

    // Data-processing (2 source)
    if ((w & 0x5FE00000U) == 0x1AC00000U) {
        unsigned opc = (w >> 10) & 63U;
        const char *mn = NULL;
        int rm_sp = 0;
        switch (opc) {
        case 0x02U: mn = "udiv"; break;
        case 0x03U: mn = "sdiv"; break;
        case 0x08U: mn = "lslv"; break;
        case 0x09U: mn = "lsrv"; break;
        case 0x0AU: mn = "asrv"; break;
        case 0x0BU: mn = "rorv"; break;
        case 0x0CU: if (sf) { mn = "pacga"; rm_sp = 1; } break;
        case 0x10U: if (!sf) mn = "crc32b"; break;
        case 0x11U: if (!sf) mn = "crc32h"; break;
        case 0x12U: if (!sf) mn = "crc32w"; break;
        case 0x13U: if (sf) mn = "crc32x"; break;
        case 0x14U: if (!sf) mn = "crc32cb"; break;
        case 0x15U: if (!sf) mn = "crc32ch"; break;
        case 0x16U: if (!sf) mn = "crc32cw"; break;
        case 0x17U: if (sf) mn = "crc32cx"; break;
        default: break;
        }
        if (!mn) return 0;
        if (want_text) {
            snprintf(out->mnem, sizeof(out->mnem), "%s", mn);
            if (opc == 0x13U || opc == 0x17U) {
                snprintf(out->ops, sizeof(out->ops), "%s, %s, %s", a64_reg(rd, 0, 0), a64_reg(rn, 0, 0), a64_reg(rm, 1, 0));
            } else {
                snprintf(out->ops, sizeof(out->ops), "%s, %s, %s", a64_reg(rd, sf, 0), a64_reg(rn, sf, 0), a64_reg(rm, sf, rm_sp));
            }
        }
        return 1;
    }

    // Data-processing (1 source) & Pointer-Auth 1-source
    if ((w & 0x5FE00000U) == 0x5AC00000U) {
        unsigned opc2 = (w >> 16) & 31U;
        unsigned opc = (w >> 10) & 63U;
        if (opc2 == 0U) {
            const char *mn = NULL;
            switch (opc) {
            case 0x00U: mn = "rbit"; break;
            case 0x01U: mn = "rev16"; break;
            case 0x02U: mn = sf ? "rev32" : "rev"; break;
            case 0x03U: if (sf) mn = "rev"; break;
            case 0x04U: mn = "clz"; break;
            case 0x05U: mn = "cls"; break;
            default: break;
            }
            if (!mn) return 0;
            if (want_text) {
                snprintf(out->mnem, sizeof(out->mnem), "%s", mn);
                snprintf(out->ops, sizeof(out->ops), "%s, %s", a64_reg(rd, sf, 0), a64_reg(rn, sf, 0));
            }
            return 1;
        }
        if (opc2 == 1U && sf) {
            static const char *const pac1[18] = {
                "pacia","pacib","pacda","pacdb","autia","autib","autda","autdb",
                "paciza","pacizb","pacdza","pacdzb","autiza","autizb","autdza","autdzb",
                "xpaci","xpacd"
            };
            if (opc < 18U) {
                if (opc >= 8U && rn != 31) return 0;
                if (want_text) {
                    snprintf(out->mnem, sizeof(out->mnem), "%s", pac1[opc]);
                    if (opc < 8U) snprintf(out->ops, sizeof(out->ops), "%s, %s", a64_reg(rd, 1, 0), a64_reg(rn, 1, 1));
                    else snprintf(out->ops, sizeof(out->ops), "%s", a64_reg(rd, 1, 0));
                }
                return 1;
            }
        }
        return 0;
    }

    // Data-processing (3 source)
    if ((w & 0x7F000000U) == 0x1B000000U) {
        unsigned op31 = (w >> 21) & 7U;
        unsigned o0 = (w >> 15) & 1U;
        int ra = (int)((w >> 10) & 31U);
        if (!want_text) return 1;

        if (op31 == 0U) {
            if (ra == 31) {
                snprintf(out->mnem, sizeof(out->mnem), "%s", o0 ? "mneg" : "mul");
                snprintf(out->ops, sizeof(out->ops), "%s, %s, %s", a64_reg(rd, sf, 0), a64_reg(rn, sf, 0), a64_reg(rm, sf, 0));
            } else {
                snprintf(out->mnem, sizeof(out->mnem), "%s", o0 ? "msub" : "madd");
                snprintf(out->ops, sizeof(out->ops), "%s, %s, %s, %s", a64_reg(rd, sf, 0), a64_reg(rn, sf, 0), a64_reg(rm, sf, 0), a64_reg(ra, sf, 0));
            }
            return 1;
        }
        if (sf && (op31 == 1U || op31 == 5U)) {
            int uns = (op31 == 5U);
            if (ra == 31) {
                snprintf(out->mnem, sizeof(out->mnem), "%c%s", uns ? 'u' : 's', o0 ? "mnegl" : "mull");
                snprintf(out->ops, sizeof(out->ops), "%s, %s, %s", a64_reg(rd, 1, 0), a64_reg(rn, 0, 0), a64_reg(rm, 0, 0));
            } else {
                snprintf(out->mnem, sizeof(out->mnem), "%c%s", uns ? 'u' : 's', o0 ? "msubl" : "maddl");
                snprintf(out->ops, sizeof(out->ops), "%s, %s, %s, %s", a64_reg(rd, 1, 0), a64_reg(rn, 0, 0), a64_reg(rm, 0, 0), a64_reg(ra, 1, 0));
            }
            return 1;
        }
        if (sf && o0 == 0U && ra == 31 && (op31 == 2U || op31 == 6U)) {
            snprintf(out->mnem, sizeof(out->mnem), "%s", op31 == 6U ? "umulh" : "smulh");
            snprintf(out->ops, sizeof(out->ops), "%s, %s, %s", a64_reg(rd, 1, 0), a64_reg(rn, 1, 0), a64_reg(rm, 1, 0));
            return 1;
        }
    }

    return 0;
}

static int a64_decode_scalar_fp(uint32_t w, int want_text, x86_ins *out) {
    int sf = (int)(w >> 31);
    int rd = (int)(w & 31U);
    int rn = (int)((w >> 5) & 31U);
    int rm = (int)((w >> 16) & 31U);
    int ftype = (int)((w >> 22) & 3U);
    int fsc = a64_ftype_scale(ftype);

    // FP data-processing (3 source): fmadd/fmsub/fnmadd/fnmsub
    if ((w & 0xFF000000U) == 0x1F000000U) {
        if (fsc < 0) return 0;
        static const char *const fm3[4] = { "fmadd", "fmsub", "fnmadd", "fnmsub" };
        int o1 = (int)((w >> 21) & 1U);
        int o0 = (int)((w >> 15) & 1U);
        int ra = (int)((w >> 10) & 31U);
        if (want_text) {
            snprintf(out->mnem, sizeof(out->mnem), "%s", fm3[(o1 << 1) | o0]);
            snprintf(out->ops, sizeof(out->ops), "%s, %s, %s, %s",
                     a64_freg(rd, fsc), a64_freg(rn, fsc), a64_freg(rm, fsc), a64_freg(ra, fsc));
        }
        return 1;
    }

    if ((w & 0x7F000000U) != 0x1E000000U) return 0;
    int bit21 = (int)((w >> 21) & 1U);

    // Fixed-point FP <-> Int conversion (bit21 == 0)
    if (!bit21) {
        if (fsc < 0) return 0;
        int rmode = (int)((w >> 19) & 3U);
        int opc = (int)((w >> 16) & 7U);
        int scale = 64 - (int)((w >> 10) & 63U);
        if (rmode == 0 && (opc == 2 || opc == 3)) {
            if (want_text) {
                snprintf(out->mnem, sizeof(out->mnem), "%s", opc == 2 ? "scvtf" : "ucvtf");
                snprintf(out->ops, sizeof(out->ops), "%s, %s, #%d", a64_freg(rd, fsc), a64_reg(rn, sf, 0), scale);
            }
            return 1;
        }
        if (rmode == 3 && (opc == 0 || opc == 1)) {
            if (want_text) {
                snprintf(out->mnem, sizeof(out->mnem), "%s", opc == 0 ? "fcvtzs" : "fcvtzu");
                snprintf(out->ops, sizeof(out->ops), "%s, %s, #%d", a64_reg(rd, sf, 0), a64_freg(rn, fsc), scale);
            }
            return 1;
        }
        return 0;
    }

    // Integer <-> FP conversion & FMOV GPR<->FP (bit21 == 1, bits[15:10] == 0)
    if ((w & 0x0000FC00U) == 0U) {
        int rmode = (int)((w >> 19) & 3U);
        int opc = (int)((w >> 16) & 7U);
        if (sf && ftype == 2 && rmode == 1 && (opc == 6 || opc == 7)) {
            if (want_text) {
                snprintf(out->mnem, sizeof(out->mnem), "fmov");
                if (opc == 6) snprintf(out->ops, sizeof(out->ops), "%s, v%d.d[1]", a64_reg(rd, 1, 0), rn);
                else snprintf(out->ops, sizeof(out->ops), "v%d.d[1], %s", rd, a64_reg(rn, 1, 0));
            }
            return 1;
        }
        if (fsc < 0) return 0;
        const char *mn = NULL;
        int to_fp = 0;
        if (rmode == 0) {
            static const char *const m0[8] = { "fcvtns","fcvtnu","scvtf","ucvtf","fcvtas","fcvtau","fmov","fmov" };
            mn = m0[opc];
            to_fp = (opc == 2 || opc == 3 || opc == 7);
        } else if (rmode == 1 && opc <= 1) {
            mn = opc ? "fcvtpu" : "fcvtps";
        } else if (rmode == 2 && opc <= 1) {
            mn = opc ? "fcvtmu" : "fcvtms";
        } else if (rmode == 3 && opc <= 1) {
            mn = opc ? "fcvtzu" : "fcvtzs";
        } else if (rmode == 3 && opc == 6 && !sf && ftype == 1) {
            mn = "fjcvtzs";
        }
        if (!mn) return 0;
        if (want_text) {
            snprintf(out->mnem, sizeof(out->mnem), "%s", mn);
            if (to_fp) snprintf(out->ops, sizeof(out->ops), "%s, %s", a64_freg(rd, fsc), a64_reg(rn, sf, 0));
            else snprintf(out->ops, sizeof(out->ops), "%s, %s", a64_reg(rd, sf, 0), a64_freg(rn, fsc));
        }
        return 1;
    }

    if (sf || fsc < 0) return 0;

    // FP data-processing (1 source): bits[14:10] == 10000
    if ((w & 0x00007C00U) == 0x00004000U) {
        unsigned opc = (w >> 15) & 63U;
        const char *mn = NULL;
        int dst_sc = fsc;
        switch (opc) {
        case 0x00U: mn = "fmov"; break;
        case 0x01U: mn = "fabs"; break;
        case 0x02U: mn = "fneg"; break;
        case 0x03U: mn = "fsqrt"; break;
        case 0x04U: mn = "fcvt"; dst_sc = 2; break;
        case 0x05U: mn = "fcvt"; dst_sc = 3; break;
        case 0x07U: mn = "fcvt"; dst_sc = 1; break;
        case 0x08U: mn = "frintn"; break;
        case 0x09U: mn = "frintp"; break;
        case 0x0AU: mn = "frintm"; break;
        case 0x0BU: mn = "frintz"; break;
        case 0x0CU: mn = "frinta"; break;
        case 0x0EU: mn = "frintx"; break;
        case 0x0FU: mn = "frinti"; break;
        case 0x10U: mn = "frint32z"; break;
        case 0x11U: mn = "frint32x"; break;
        case 0x12U: mn = "frint64z"; break;
        case 0x13U: mn = "frint64x"; break;
        default: break;
        }
        if (!mn) return 0;
        if (want_text) {
            snprintf(out->mnem, sizeof(out->mnem), "%s", mn);
            snprintf(out->ops, sizeof(out->ops), "%s, %s", a64_freg(rd, dst_sc), a64_freg(rn, fsc));
        }
        return 1;
    }

    // FP compare: bits[15:10] == 001000, bits[2:0] == 000
    if ((w & 0x0000FC07U) == 0x00002000U) {
        int is_e = (int)((w >> 4) & 1U);
        int is_z = (int)((w >> 3) & 1U);
        if (want_text) {
            snprintf(out->mnem, sizeof(out->mnem), "%s", is_e ? "fcmpe" : "fcmp");
            if (is_z) snprintf(out->ops, sizeof(out->ops), "%s, #0.0", a64_freg(rn, fsc));
            else snprintf(out->ops, sizeof(out->ops), "%s, %s", a64_freg(rn, fsc), a64_freg(rm, fsc));
        }
        return 1;
    }

    // FP immediate: bits[12:10] == 100, bits[9:5] == 00000
    if ((w & 0x00001FE0U) == 0x00001000U) {
        if (want_text) {
            char ib[24];
            a64_fmt_fpimm((w >> 13) & 0xFFU, ib, sizeof(ib));
            snprintf(out->mnem, sizeof(out->mnem), "fmov");
            snprintf(out->ops, sizeof(out->ops), "%s, %s", a64_freg(rd, fsc), ib);
        }
        return 1;
    }

    unsigned lo2 = (w >> 10) & 3U;
    // FP conditional compare: lo2 == 1
    if (lo2 == 1U) {
        int is_e = (int)((w >> 4) & 1U);
        int cond = (int)((w >> 12) & 15U);
        int nzcv = (int)(w & 15U);
        if (want_text) {
            snprintf(out->mnem, sizeof(out->mnem), "%s", is_e ? "fccmpe" : "fccmp");
            snprintf(out->ops, sizeof(out->ops), "%s, %s, #0x%x, %s", a64_freg(rn, fsc), a64_freg(rm, fsc), nzcv, a64_cc[cond]);
        }
        return 1;
    }

    // FP data-processing (2 source): lo2 == 2
    if (lo2 == 2U) {
        static const char *const fp2[9] = {
            "fmul","fdiv","fadd","fsub","fmax","fmin","fmaxnm","fminnm","fnmul"
        };
        unsigned opc = (w >> 12) & 15U;
        if (opc >= 9U) return 0;
        if (want_text) {
            snprintf(out->mnem, sizeof(out->mnem), "%s", fp2[opc]);
            snprintf(out->ops, sizeof(out->ops), "%s, %s, %s", a64_freg(rd, fsc), a64_freg(rn, fsc), a64_freg(rm, fsc));
        }
        return 1;
    }

    // FP conditional select: lo2 == 3
    if (lo2 == 3U) {
        int cond = (int)((w >> 12) & 15U);
        if (want_text) {
            snprintf(out->mnem, sizeof(out->mnem), "fcsel");
            snprintf(out->ops, sizeof(out->ops), "%s, %s, %s, %s", a64_freg(rd, fsc), a64_freg(rn, fsc), a64_freg(rm, fsc), a64_cc[cond]);
        }
        return 1;
    }

    return 0;
}

static int a64_decode_simd(uint32_t w, int want_text, x86_ins *out) {
    int q = (int)((w >> 30) & 1U);
    int u = (int)((w >> 29) & 1U);
    int sz = (int)((w >> 22) & 3U);
    int rm = (int)((w >> 16) & 31U);
    int rn = (int)((w >> 5) & 31U);
    int rd = (int)(w & 31U);
    static const char es[4] = { 'b', 'h', 's', 'd' };

    // Crypto AES (2-reg)
    if ((w & 0xFFFE0C00U) == 0x4E280800U) {
        unsigned opc = (w >> 12) & 31U;
        const char *mn = (opc == 4U) ? "aese" : (opc == 5U) ? "aesd" : (opc == 6U) ? "aesmc" : (opc == 7U) ? "aesimc" : NULL;
        if (!mn) return 0;
        if (want_text) {
            snprintf(out->mnem, sizeof(out->mnem), "%s", mn);
            snprintf(out->ops, sizeof(out->ops), "v%d.16b, v%d.16b", rd, rn);
        }
        return 1;
    }

    // Crypto SHA (3-reg & 2-reg in 0x5E)
    if ((w & 0xFFE08C00U) == 0x5E000000U) {
        unsigned opc = (w >> 12) & 7U;
        static const char *const sh3[8] = { "sha1c","sha1p","sha1m","sha1su0","sha256h","sha256h2","sha256su1",NULL };
        if (!sh3[opc]) return 0;
        if (want_text) {
            snprintf(out->mnem, sizeof(out->mnem), "%s", sh3[opc]);
            if (opc <= 2U) snprintf(out->ops, sizeof(out->ops), "q%d, s%d, v%d.4s", rd, rn, rm);
            else if (opc == 4U || opc == 5U) snprintf(out->ops, sizeof(out->ops), "q%d, q%d, v%d.4s", rd, rn, rm);
            else snprintf(out->ops, sizeof(out->ops), "v%d.4s, v%d.4s, v%d.4s", rd, rn, rm);
        }
        return 1;
    }
    if ((w & 0xFFFE0C00U) == 0x5E280800U) {
        unsigned opc = (w >> 12) & 31U;
        const char *mn = (opc == 0U) ? "sha1h" : (opc == 1U) ? "sha1su1" : (opc == 2U) ? "sha256su0" : NULL;
        if (!mn) return 0;
        if (want_text) {
            snprintf(out->mnem, sizeof(out->mnem), "%s", mn);
            if (opc == 0U) snprintf(out->ops, sizeof(out->ops), "s%d, s%d", rd, rn);
            else snprintf(out->ops, sizeof(out->ops), "v%d.4s, v%d.4s", rd, rn);
        }
        return 1;
    }

    // AdvSIMD Scalar group (bits[31:28] == 0101 / 0111 -> 0x5E/0x7E/0x5F/0x7F)
    if ((w & 0xDE000000U) == 0x5E000000U) {
        // Scalar Copy (dup Dd, Vn.d[idx] / mov)
        if ((w & 0xFFE0FC00U) == 0x5E000400U) {
            unsigned imm5 = (w >> 16) & 31U;
            if (!imm5) return 0;
            int sc = 0;
            while (sc < 4 && !((imm5 >> sc) & 1U)) sc++;
            int idx = (int)(imm5 >> (sc + 1));
            if (want_text) {
                snprintf(out->mnem, sizeof(out->mnem), "mov");
                snprintf(out->ops, sizeof(out->ops), "%s, v%d.%c[%d]", a64_freg(rd, sc), rn, es[sc], idx);
            }
            return 1;
        }
        // Scalar Pairwise
        if ((w & 0xDF3E0C00U) == 0x5E300800U) {
            unsigned opc = (w >> 12) & 31U;
            const char *mn = NULL;
            int fsz = sz & 1;
            int is_fp = 0;
            if (!u && opc == 0x1BU && sz == 3) mn = "addp";
            else if (u && opc == 0x0DU && (sz & 2) == 0) { mn = "faddp"; is_fp = 1; }
            else if (u && opc == 0x0CU) { mn = (sz & 2) ? "fminnmp" : "fmaxnmp"; is_fp = 1; }
            else if (u && opc == 0x0FU) { mn = (sz & 2) ? "fminp" : "fmaxp"; is_fp = 1; }
            if (!mn) return 0;
            if (want_text) {
                snprintf(out->mnem, sizeof(out->mnem), "%s", mn);
                if (is_fp) snprintf(out->ops, sizeof(out->ops), "%s, v%d.%s", a64_freg(rd, fsz + 2), rn, fsz ? "2d" : "2s");
                else snprintf(out->ops, sizeof(out->ops), "d%d, v%d.2d", rd, rn);
            }
            return 1;
        }
        // Scalar Three Same
        if ((w & 0xDF200400U) == 0x5E200400U) {
            unsigned opc = (w >> 11) & 31U;
            const char *mn = NULL;
            int fsc = sz;
            if (opc == 0x10U) mn = u ? "sub" : "add";
            else if (opc == 0x01U) mn = u ? "uqadd" : "sqadd";
            else if (opc == 0x05U) mn = u ? "uqsub" : "sqsub";
            else if (opc == 0x06U) mn = u ? "cmhi" : "cmgt";
            else if (opc == 0x07U) mn = u ? "cmhs" : "cmge";
            else if (opc == 0x08U) mn = u ? "ushl" : "sshl";
            else if (opc == 0x09U) mn = u ? "uqshl" : "sqshl";
            else if (opc == 0x11U) mn = u ? "cmeq" : "cmtst";
            else if (opc == 0x1AU && u && (sz & 2)) { mn = "fabd"; fsc = (sz & 1) + 2; }
            else if (opc == 0x1BU && !u && !(sz & 2)) { mn = "fmulx"; fsc = (sz & 1) + 2; }
            else if (opc == 0x1CU) { mn = !u ? ((sz & 2) ? NULL : "fcmeq") : ((sz & 2) ? "fcmgt" : "fcmge"); fsc = (sz & 1) + 2; }
            else if (opc == 0x1DU && u) { mn = (sz & 2) ? "facgt" : "facge"; fsc = (sz & 1) + 2; }
            if (!mn) return 0;
            if (want_text) {
                snprintf(out->mnem, sizeof(out->mnem), "%s", mn);
                snprintf(out->ops, sizeof(out->ops), "%s, %s, %s", a64_freg(rd, fsc), a64_freg(rn, fsc), a64_freg(rm, fsc));
            }
            return 1;
        }
        // Scalar Two-reg misc
        if ((w & 0xDF3E0C00U) == 0x5E200800U) {
            unsigned opc = (w >> 12) & 31U;
            const char *mn = NULL;
            int zero_cmp = 0;
            int fsc = sz;
            if (opc == 0x0BU) mn = u ? "neg" : "abs";
            else if (opc == 0x08U) { mn = u ? "cmge" : "cmgt"; zero_cmp = 1; }
            else if (opc == 0x09U) { mn = u ? "cmle" : "cmeq"; zero_cmp = 1; }
            else if (opc == 0x0AU && !u) { mn = "cmlt"; zero_cmp = 1; }
            else if (opc == 0x1DU && !(sz & 2)) { mn = u ? "ucvtf" : "scvtf"; fsc = (sz & 1) + 2; }
            else if (opc == 0x1BU && (sz & 2)) { mn = u ? "fcvtzu" : "fcvtzs"; fsc = (sz & 1) + 2; }
            if (!mn) return 0;
            if (want_text) {
                snprintf(out->mnem, sizeof(out->mnem), "%s", mn);
                if (zero_cmp) snprintf(out->ops, sizeof(out->ops), "%s, %s, #0", a64_freg(rd, fsc), a64_freg(rn, fsc));
                else snprintf(out->ops, sizeof(out->ops), "%s, %s", a64_freg(rd, fsc), a64_freg(rn, fsc));
            }
            return 1;
        }
        // Scalar Shift by Immediate
        if ((w & 0xDF800400U) == 0x5F000400U) {
            unsigned immh = (w >> 19) & 15U;
            unsigned immb = (w >> 16) & 7U;
            if (!immh) return 0;
            unsigned imm7 = (immh << 3) | immb;
            unsigned opc = (w >> 11) & 31U;
            int sc = (immh & 8U) ? 3 : (immh & 4U) ? 2 : (immh & 2U) ? 1 : 0;
            unsigned ew = 8U << sc;
            unsigned rsh = (ew * 2U) - imm7;
            unsigned lsh = imm7 - ew;
            const char *mn = NULL;
            unsigned sh = rsh;
            if (opc == 0x00U) mn = u ? "ushr" : "sshr";
            else if (opc == 0x02U) mn = u ? "usra" : "ssra";
            else if (opc == 0x04U) mn = u ? "urshr" : "srshr";
            else if (opc == 0x08U && u) mn = "sri";
            else if (opc == 0x0AU) { mn = u ? "sli" : "shl"; sh = lsh; }
            else if (opc == 0x0EU) { mn = u ? "uqshl" : "sqshl"; sh = lsh; }
            else if (opc == 0x1CU) mn = u ? "ucvtf" : "scvtf";
            else if (opc == 0x1FU) mn = u ? "fcvtzu" : "fcvtzs";
            if (!mn) return 0;
            if (want_text) {
                snprintf(out->mnem, sizeof(out->mnem), "%s", mn);
                snprintf(out->ops, sizeof(out->ops), "%s, %s, #%u", a64_freg(rd, sc), a64_freg(rn, sc), sh);
            }
            return 1;
        }
        return 0;
    }

    // AdvSIMD Vector (bits[31]==0, bits[28:25]==0111)
    if ((w & 0x9E000000U) != 0x0E000000U) return 0;

    // Bit 24 == 0: Copy, Ext, Tbl/Tbx, Permute, Three-Same, Two-Reg-Misc, Across-Lanes, Three-Diff
    if ((w & 0x01000000U) == 0U) {
        // Copy: dup (element/general), smov, umov/mov, ins (general/element)
        if ((w & 0x9FE08400U) == 0x0E000400U) {
            unsigned imm5 = (w >> 16) & 31U;
            unsigned imm4 = (w >> 11) & 15U;
            if (!imm5) return 0;
            int sc = 0;
            while (sc < 4 && !((imm5 >> sc) & 1U)) sc++;
            int idx = (int)(imm5 >> (sc + 1));
            if (!want_text) return 1;

            if (u == 1) {
                if (!q) return 0;
                snprintf(out->mnem, sizeof(out->mnem), "ins");
                snprintf(out->ops, sizeof(out->ops), "v%d.%c[%d], v%d.%c[%u]", rd, es[sc], idx, rn, es[sc], imm4 >> sc);
                return 1;
            }
            if (imm4 == 0U) {
                snprintf(out->mnem, sizeof(out->mnem), "dup");
                snprintf(out->ops, sizeof(out->ops), "v%d.%s, v%d.%c[%d]", rd, a64_arr(q, sc), rn, es[sc], idx);
                return 1;
            }
            if (imm4 == 1U) {
                snprintf(out->mnem, sizeof(out->mnem), "dup");
                snprintf(out->ops, sizeof(out->ops), "v%d.%s, %s", rd, a64_arr(q, sc), a64_reg(rn, sc == 3, 0));
                return 1;
            }
            if (imm4 == 3U && q) {
                snprintf(out->mnem, sizeof(out->mnem), "ins");
                snprintf(out->ops, sizeof(out->ops), "v%d.%c[%d], %s", rd, es[sc], idx, a64_reg(rn, sc == 3, 0));
                return 1;
            }
            if (imm4 == 5U) {
                snprintf(out->mnem, sizeof(out->mnem), "smov");
                snprintf(out->ops, sizeof(out->ops), "%s, v%d.%c[%d]", a64_reg(rd, q, 0), rn, es[sc], idx);
                return 1;
            }
            if (imm4 == 7U) {
                int is_mov = (!q && sc == 2) || (q && sc == 3);
                snprintf(out->mnem, sizeof(out->mnem), "%s", is_mov ? "mov" : "umov");
                snprintf(out->ops, sizeof(out->ops), "%s, v%d.%c[%d]", a64_reg(rd, q, 0), rn, es[sc], idx);
                return 1;
            }
            return 0;
        }

        // Extract: ext
        if ((w & 0xBFE08400U) == 0x2E000000U) {
            unsigned imm4 = (w >> 11) & 15U;
            if (!q && imm4 >= 8U) return 0;
            if (want_text) {
                const char *a = q ? "16b" : "8b";
                snprintf(out->mnem, sizeof(out->mnem), "ext");
                snprintf(out->ops, sizeof(out->ops), "v%d.%s, v%d.%s, v%d.%s, #%u", rd, a, rn, a, rm, a, imm4);
            }
            return 1;
        }

        // Table Lookup: tbl / tbx
        if ((w & 0xBFE09C00U) == 0x0E000000U) {
            int len = (int)((w >> 13) & 3U) + 1;
            int is_tbx = (int)((w >> 12) & 1U);
            if (want_text) {
                const char *a = q ? "16b" : "8b";
                char vlist[44];
                a64_fmt_vlist(rn, len, "16b", -1, vlist, sizeof(vlist));
                snprintf(out->mnem, sizeof(out->mnem), "%s", is_tbx ? "tbx" : "tbl");
                snprintf(out->ops, sizeof(out->ops), "v%d.%s, %s, v%d.%s", rd, a, vlist, rm, a);
            }
            return 1;
        }

        // Permute: uzp1/trn1/zip1/uzp2/trn2/zip2
        if ((w & 0xBF208C00U) == 0x0E000800U) {
            static const char *const pm[8] = { NULL,"uzp1","trn1","zip1",NULL,"uzp2","trn2","zip2" };
            unsigned opc = (w >> 12) & 7U;
            if (!pm[opc]) return 0;
            if (want_text) {
                const char *a = a64_arr(q, sz);
                snprintf(out->mnem, sizeof(out->mnem), "%s", pm[opc]);
                snprintf(out->ops, sizeof(out->ops), "v%d.%s, v%d.%s, v%d.%s", rd, a, rn, a, rm, a);
            }
            return 1;
        }

        // Three Same (integer & FP & bitwise)
        if ((w & 0x9F200400U) == 0x0E200400U) {
            unsigned opc = (w >> 11) & 31U;
            if (opc == 0x03U) {
                static const char *const bw[2][4] = {
                    { "and", "bic", "orr", "orn" },
                    { "eor", "bsl", "bit", "bif" }
                };
                if (want_text) {
                    const char *a = q ? "16b" : "8b";
                    if (!u && sz == 2 && rn == rm) {
                        snprintf(out->mnem, sizeof(out->mnem), "mov");
                        snprintf(out->ops, sizeof(out->ops), "v%d.%s, v%d.%s", rd, a, rn, a);
                    } else {
                        snprintf(out->mnem, sizeof(out->mnem), "%s", bw[u][sz]);
                        snprintf(out->ops, sizeof(out->ops), "v%d.%s, v%d.%s, v%d.%s", rd, a, rn, a, rm, a);
                    }
                }
                return 1;
            }

            const char *mn = NULL;
            int is_fp = 0;
            switch (opc) {
            case 0x00U: mn = u ? "uhadd" : "shadd"; break;
            case 0x01U: mn = u ? "uqadd" : "sqadd"; break;
            case 0x02U: mn = u ? "urhadd" : "srhadd"; break;
            case 0x04U: mn = u ? "uhsub" : "shsub"; break;
            case 0x05U: mn = u ? "uqsub" : "sqsub"; break;
            case 0x06U: mn = u ? "cmhi" : "cmgt"; break;
            case 0x07U: mn = u ? "cmhs" : "cmge"; break;
            case 0x08U: mn = u ? "ushl" : "sshl"; break;
            case 0x09U: mn = u ? "uqshl" : "sqshl"; break;
            case 0x0AU: mn = u ? "urshl" : "srshl"; break;
            case 0x0CU: mn = u ? "umax" : "smax"; break;
            case 0x0DU: mn = u ? "umin" : "smin"; break;
            case 0x0EU: mn = u ? "uabd" : "sabd"; break;
            case 0x0FU: mn = u ? "uaba" : "saba"; break;
            case 0x10U: mn = u ? "sub" : "add"; break;
            case 0x11U: mn = u ? "cmeq" : "cmtst"; break;
            case 0x12U: mn = u ? "mls" : "mla"; break;
            case 0x13U: mn = u ? "pmul" : "mul"; break;
            case 0x14U: mn = u ? "umaxp" : "smaxp"; break;
            case 0x15U: mn = u ? "uminp" : "sminp"; break;
            case 0x16U: mn = u ? "sqrdmulh" : "sqdmulh"; break;
            case 0x17U: if (!u) mn = "addp"; break;
            case 0x18U: is_fp = 1; mn = u ? ((sz & 2) ? "fminnmp" : "fmaxnmp") : ((sz & 2) ? "fminnm" : "fmaxnm"); break;
            case 0x19U: is_fp = 1; if (!u) mn = (sz & 2) ? "fmls" : "fmla"; break;
            case 0x1AU: is_fp = 1; mn = u ? ((sz & 2) ? "fabd" : "faddp") : ((sz & 2) ? "fsub" : "fadd"); break;
            case 0x1BU: is_fp = 1; if (!(sz & 2)) mn = u ? "fmul" : "fmulx"; break;
            case 0x1CU: is_fp = 1; mn = !u ? ((sz & 2) ? NULL : "fcmeq") : ((sz & 2) ? "fcmgt" : "fcmge"); break;
            case 0x1DU: is_fp = 1; if (u) mn = (sz & 2) ? "facgt" : "facge"; break;
            case 0x1EU: is_fp = 1; mn = u ? ((sz & 2) ? "fminp" : "fmaxp") : ((sz & 2) ? "fmin" : "fmax"); break;
            case 0x1FU: is_fp = 1; if (u && !(sz & 2)) mn = "fdiv"; break;
            default: break;
            }
            if (!mn) return 0;
            if (want_text) {
                const char *a = is_fp ? a64_farr(q, sz & 1) : a64_arr(q, sz);
                snprintf(out->mnem, sizeof(out->mnem), "%s", mn);
                snprintf(out->ops, sizeof(out->ops), "v%d.%s, v%d.%s, v%d.%s", rd, a, rn, a, rm, a);
            }
            return 1;
        }

        // Two-register Miscellaneous
        if ((w & 0x9F3E0C00U) == 0x0E200800U) {
            unsigned opc = (w >> 12) & 31U;
            const char *mn = NULL;
            int is_fp = 0, cmp0 = 0, fcmp0 = 0, is_shll = 0, is_xtn = 0, is_lp = 0;
            switch (opc) {
            case 0x00U: mn = u ? "rev32" : "rev64"; break;
            case 0x01U: if (!u) mn = "rev16"; break;
            case 0x02U: mn = u ? "uaddlp" : "saddlp"; is_lp = 1; break;
            case 0x03U: mn = u ? "usqadd" : "suqadd"; break;
            case 0x04U: mn = u ? "cls" : "clz"; break;
            case 0x05U: mn = u ? "mvn" : "cnt"; break;
            case 0x06U: mn = u ? "uadalp" : "sadalp"; is_lp = 1; break;
            case 0x07U: mn = u ? "sqneg" : "sqabs"; break;
            case 0x08U: mn = u ? "cmge" : "cmgt"; cmp0 = 1; break;
            case 0x09U: mn = u ? "cmle" : "cmeq"; cmp0 = 1; break;
            case 0x0AU: if (!u) { mn = "cmlt"; cmp0 = 1; } break;
            case 0x0BU: mn = u ? "neg" : "abs"; break;
            case 0x0CU: if (!(sz & 2)) { mn = u ? "fcmge" : "fcmgt"; is_fp = 1; fcmp0 = 1; } break;
            case 0x0DU: if (!(sz & 2)) { mn = u ? "fcmle" : "fcmeq"; is_fp = 1; fcmp0 = 1; } break;
            case 0x0EU: if (!u && !(sz & 2)) { mn = "fcmlt"; is_fp = 1; fcmp0 = 1; } break;
            case 0x0FU: if (sz & 2) { mn = u ? "fneg" : "fabs"; is_fp = 1; } break;
            case 0x12U: if (!u) { mn = q ? "xtn2" : "xtn"; is_xtn = 1; } break;
            case 0x13U: if (!u) { mn = q ? "shll2" : "shll"; is_shll = 1; } break;
            case 0x14U: mn = u ? (q ? "uqxtn2" : "uqxtn") : (q ? "sqxtn2" : "sqxtn"); is_xtn = 1; break;
            case 0x18U: is_fp = 1; mn = (sz & 2) ? (u ? "frintx" : "frintp") : (u ? "frinta" : "frintn"); break;
            case 0x19U: is_fp = 1; mn = (sz & 2) ? (u ? NULL : "frintz") : (u ? "frinti" : "frintm"); break;
            case 0x1AU: is_fp = 1; mn = (sz & 2) ? (u ? "fcvtpu" : "fcvtps") : (u ? "fcvtnu" : "fcvtns"); break;
            case 0x1BU: is_fp = 1; mn = (sz & 2) ? (u ? "fcvtzu" : "fcvtzs") : (u ? "fcvtmu" : "fcvtms"); break;
            case 0x1CU: is_fp = 1; if (!(sz & 2)) mn = u ? "fcvtau" : "fcvtas"; break;
            case 0x1DU: is_fp = 1; mn = (sz & 2) ? (u ? "frsqrte" : "frecpe") : (u ? "ucvtf" : "scvtf"); break;
            case 0x1FU: is_fp = 1; if (u && (sz & 2)) mn = "fsqrt"; break;
            default: break;
            }
            if (!mn) return 0;
            if (want_text) {
                snprintf(out->mnem, sizeof(out->mnem), "%s", mn);
                if (is_shll) {
                    snprintf(out->ops, sizeof(out->ops), "v%d.%s, v%d.%s, #%d", rd, a64_arr(1, (sz + 1) & 3), rn, a64_arr(q, sz), 8 << sz);
                } else if (is_xtn) {
                    snprintf(out->ops, sizeof(out->ops), "v%d.%s, v%d.%s", rd, a64_arr(q, sz), rn, a64_arr(1, (sz + 1) & 3));
                } else if (is_lp) {
                    snprintf(out->ops, sizeof(out->ops), "v%d.%s, v%d.%s", rd, a64_arr(q, (sz + 1) & 3), rn, a64_arr(q, sz));
                } else {
                    const char *a = (opc == 0x05U) ? (q ? "16b" : "8b") : (is_fp ? a64_farr(q, sz & 1) : a64_arr(q, sz));
                    if (fcmp0) snprintf(out->ops, sizeof(out->ops), "v%d.%s, v%d.%s, #0.0", rd, a, rn, a);
                    else if (cmp0) snprintf(out->ops, sizeof(out->ops), "v%d.%s, v%d.%s, #0", rd, a, rn, a);
                    else snprintf(out->ops, sizeof(out->ops), "v%d.%s, v%d.%s", rd, a, rn, a);
                }
            }
            return 1;
        }

        // Across Lanes: addv, smaxv, umaxv, sminv, uminv, saddlv, uaddlv, fmaxv, fminv
        if ((w & 0x9F3E0C00U) == 0x0E300800U) {
            unsigned opc = (w >> 12) & 31U;
            const char *mn = NULL;
            int dsc = sz;
            int is_fp = 0;
            if (opc == 0x03U) { mn = u ? "uaddlv" : "saddlv"; dsc = sz + 1; }
            else if (opc == 0x0AU) mn = u ? "umaxv" : "smaxv";
            else if (opc == 0x1AU) mn = u ? "uminv" : "sminv";
            else if (opc == 0x1BU && !u) mn = "addv";
            else if (opc == 0x0CU && u) { mn = (sz & 2) ? "fminnmv" : "fmaxnmv"; dsc = (sz & 1) + 2; is_fp = 1; }
            else if (opc == 0x0FU && u) { mn = (sz & 2) ? "fminv" : "fmaxv"; dsc = (sz & 1) + 2; is_fp = 1; }
            if (!mn) return 0;
            if (want_text) {
                snprintf(out->mnem, sizeof(out->mnem), "%s", mn);
                snprintf(out->ops, sizeof(out->ops), "%s, v%d.%s", a64_freg(rd, dsc), rn, is_fp ? a64_farr(q, sz & 1) : a64_arr(q, sz));
            }
            return 1;
        }

        // Three Different: umull/smull/pmull/saddl/uaddl/ssubl/usubl/smlal/umlal
        if ((w & 0x9F200C00U) == 0x0E200000U) {
            unsigned opc = (w >> 12) & 15U;
            const char *mn = NULL;
            int wide_rn = 0;
            switch (opc) {
            case 0x0U: mn = u ? "uaddl" : "saddl"; break;
            case 0x1U: mn = u ? "uaddw" : "saddw"; wide_rn = 1; break;
            case 0x2U: mn = u ? "usubl" : "ssubl"; break;
            case 0x3U: mn = u ? "usubw" : "ssubw"; wide_rn = 1; break;
            case 0x8U: mn = u ? "umlal" : "smlal"; break;
            case 0xAU: mn = u ? "umlsl" : "smlsl"; break;
            case 0xCU: mn = u ? "umull" : "smull"; break;
            case 0xEU: if (!u) mn = "pmull"; break;
            default: break;
            }
            if (!mn) return 0;
            if (want_text) {
                int dsz = (sz == 3 && opc == 0xEU) ? 4 : ((sz + 1) & 3);
                const char *da = (dsz == 4) ? "1q" : a64_arr(1, dsz);
                const char *sa = a64_arr(q, sz);
                snprintf(out->mnem, sizeof(out->mnem), "%s%s", mn, q ? "2" : "");
                snprintf(out->ops, sizeof(out->ops), "v%d.%s, v%d.%s, v%d.%s", rd, da, rn, wide_rn ? da : sa, rm, sa);
            }
            return 1;
        }
        return 0;
    }

    // Bit 24 == 1: Modified Immediate, Shift by Immediate, Vector x Indexed Element
    // Modified Immediate (immh == 0, bit 10 == 1)
    if ((w & 0x9FF80400U) == 0x0F000400U) {
        unsigned cmode = (w >> 12) & 15U;
        unsigned o2 = (w >> 11) & 1U;
        uint32_t imm8 = (((w >> 16) & 7U) << 5) | ((w >> 5) & 31U);
        if (!want_text) return 1;

        if (cmode == 14U && o2 == 0U) {
            snprintf(out->mnem, sizeof(out->mnem), "movi");
            if (u == 0) {
                snprintf(out->ops, sizeof(out->ops), "v%d.%s, #0x%x", rd, q ? "16b" : "8b", imm8);
            } else {
                uint64_t val = 0;
                for (int i = 0; i < 8; i++) {
                    if ((imm8 >> i) & 1U) val |= (0xFFULL << (i * 8));
                }
                snprintf(out->ops, sizeof(out->ops), "%s%d%s, #0x%llx", q ? "v" : "d", rd, q ? ".2d" : "", (unsigned long long)val);
            }
            return 1;
        }
        if (cmode == 15U && o2 == 0U) {
            if (u && !q) return 0;
            char ib[24];
            a64_fmt_fpimm(imm8, ib, sizeof(ib));
            snprintf(out->mnem, sizeof(out->mnem), "fmov");
            snprintf(out->ops, sizeof(out->ops), "v%d.%s, %s", rd, u ? "2d" : (q ? "4s" : "2s"), ib);
            return 1;
        }
        if ((cmode & 8U) == 0U) {
            unsigned sh = (cmode >> 1) * 8U;
            const char *mn = (cmode & 1U) ? (u ? "bic" : "orr") : (u ? "mvni" : "movi");
            snprintf(out->mnem, sizeof(out->mnem), "%s", mn);
            if (sh) snprintf(out->ops, sizeof(out->ops), "v%d.%s, #0x%x, lsl #%u", rd, q ? "4s" : "2s", imm8, sh);
            else snprintf(out->ops, sizeof(out->ops), "v%d.%s, #0x%x", rd, q ? "4s" : "2s", imm8);
            return 1;
        }
        if ((cmode & 12U) == 8U) {
            unsigned sh = (cmode & 2U) ? 8U : 0U;
            const char *mn = (cmode & 1U) ? (u ? "bic" : "orr") : (u ? "mvni" : "movi");
            snprintf(out->mnem, sizeof(out->mnem), "%s", mn);
            if (sh) snprintf(out->ops, sizeof(out->ops), "v%d.%s, #0x%x, lsl #%u", rd, q ? "8h" : "4h", imm8, sh);
            else snprintf(out->ops, sizeof(out->ops), "v%d.%s, #0x%x", rd, q ? "8h" : "4h", imm8);
            return 1;
        }
        if ((cmode & 14U) == 12U) {
            snprintf(out->mnem, sizeof(out->mnem), "%s", u ? "mvni" : "movi");
            snprintf(out->ops, sizeof(out->ops), "v%d.%s, #0x%x, msl #%u", rd, q ? "4s" : "2s", imm8, (cmode & 1U) ? 16U : 8U);
            return 1;
        }
        return 0;
    }

    // Shift by Immediate (immh != 0, bit 10 == 1)
    if ((w & 0x9F800400U) == 0x0F000400U) {
        unsigned immh = (w >> 19) & 15U;
        unsigned immb = (w >> 16) & 7U;
        if (!immh) return 0;
        unsigned imm7 = (immh << 3) | immb;
        unsigned opc = (w >> 11) & 31U;
        int sc = (immh & 8U) ? 3 : (immh & 4U) ? 2 : (immh & 2U) ? 1 : 0;
        unsigned ew = 8U << sc;
        unsigned rsh = (ew * 2U) - imm7;
        unsigned lsh = imm7 - ew;
        if (!want_text) return 1;

        if (opc == 0x14U) {
            if (sc >= 3) return 0;
            const char *da = a64_arr(1, sc + 1);
            const char *sa = a64_arr(q, sc);
            if (lsh == 0U) {
                snprintf(out->mnem, sizeof(out->mnem), "%s%s", u ? "uxtl" : "sxtl", q ? "2" : "");
                snprintf(out->ops, sizeof(out->ops), "v%d.%s, v%d.%s", rd, da, rn, sa);
            } else {
                snprintf(out->mnem, sizeof(out->mnem), "%s%s", u ? "ushll" : "sshll", q ? "2" : "");
                snprintf(out->ops, sizeof(out->ops), "v%d.%s, v%d.%s, #%u", rd, da, rn, sa, lsh);
            }
            return 1;
        }
        if (opc == 0x10U && !u) {
            if (sc >= 3) return 0;
            snprintf(out->mnem, sizeof(out->mnem), "%s", q ? "shrn2" : "shrn");
            snprintf(out->ops, sizeof(out->ops), "v%d.%s, v%d.%s, #%u", rd, a64_arr(q, sc), rn, a64_arr(1, sc + 1), rsh);
            return 1;
        }

        const char *mn = NULL;
        unsigned sh = rsh;
        switch (opc) {
        case 0x00U: mn = u ? "ushr" : "sshr"; break;
        case 0x02U: mn = u ? "usra" : "ssra"; break;
        case 0x04U: mn = u ? "urshr" : "srshr"; break;
        case 0x06U: mn = u ? "ursra" : "srsra"; break;
        case 0x08U: if (u) mn = "sri"; break;
        case 0x0AU: mn = u ? "sli" : "shl"; sh = lsh; break;
        case 0x0EU: mn = u ? "uqshl" : "sqshl"; sh = lsh; break;
        case 0x1CU: mn = u ? "ucvtf" : "scvtf"; break;
        case 0x1FU: mn = u ? "fcvtzu" : "fcvtzs"; break;
        default: break;
        }
        if (!mn) return 0;
        const char *a = a64_arr(q, sc);
        snprintf(out->mnem, sizeof(out->mnem), "%s", mn);
        snprintf(out->ops, sizeof(out->ops), "v%d.%s, v%d.%s, #%u", rd, a, rn, a, sh);
        return 1;
    }

    // Vector x Indexed Element (bit 10 == 0)
    if ((w & 0x9F000400U) == 0x0F000000U) {
        unsigned opc = (w >> 12) & 15U;
        unsigned L = (w >> 21) & 1U;
        unsigned M = (w >> 20) & 1U;
        unsigned H = (w >> 11) & 1U;
        int rm4 = (int)((w >> 16) & 15U);
        int em = (sz == 1) ? rm4 : ((int)(M << 4) | rm4);
        int idx = (sz == 1) ? (int)((H << 2) | (L << 1) | M) : (sz == 2) ? (int)((H << 1) | L) : (int)H;
        const char *mn = NULL;
        int is_fp = 0, is_long = 0;
        if (!u) {
            if (opc == 0x0U) mn = "mla";
            else if (opc == 0x1U) { mn = "fmla"; is_fp = 1; }
            else if (opc == 0x4U) mn = "mls";
            else if (opc == 0x5U) { mn = "fmls"; is_fp = 1; }
            else if (opc == 0x8U) mn = "mul";
            else if (opc == 0x9U) { mn = "fmul"; is_fp = 1; }
            else if (opc == 0xAU) { mn = q ? "smull2" : "smull"; is_long = 1; }
            else if (opc == 0x2U) { mn = q ? "smlal2" : "smlal"; is_long = 1; }
            else if (opc == 0x6U) { mn = q ? "smlsl2" : "smlsl"; is_long = 1; }
        } else {
            if (opc == 0x9U) { mn = "fmulx"; is_fp = 1; }
            else if (opc == 0xAU) { mn = q ? "umull2" : "umull"; is_long = 1; }
            else if (opc == 0x2U) { mn = q ? "umlal2" : "umlal"; is_long = 1; }
            else if (opc == 0x6U) { mn = q ? "umlsl2" : "umlsl"; is_long = 1; }
        }
        if (!mn) return 0;
        if (want_text) {
            snprintf(out->mnem, sizeof(out->mnem), "%s", mn);
            if (is_fp) {
                int fsz = sz & 1;
                int fem = (int)(M << 4) | rm4;
                const char *a = a64_farr(q, fsz);
                snprintf(out->ops, sizeof(out->ops), "v%d.%s, v%d.%s, v%d.%c[%d]", rd, a, rn, a, fem, fsz ? 'd' : 's', fsz ? (int)H : (int)((H << 1) | L));
            } else if (is_long) {
                snprintf(out->ops, sizeof(out->ops), "v%d.%s, v%d.%s, v%d.%c[%d]", rd, a64_arr(1, (sz + 1) & 3), rn, a64_arr(q, sz), em, es[sz], idx);
            } else {
                const char *a = a64_arr(q, sz);
                snprintf(out->ops, sizeof(out->ops), "v%d.%s, v%d.%s, v%d.%c[%d]", rd, a, rn, a, em, es[sz], idx);
            }
        }
        return 1;
    }

    return 0;
}

int a64_decode(const uint8_t *code, size_t avail, uint64_t ip, int want_text, int upper, x86_ins *out) {
    memset(out, 0, sizeof(*out));
    out->ip = ip;
    if (!code || avail < 4) {
        out->len = (avail > 0) ? 1 : 0;
        if (want_text && avail > 0) {
            snprintf(out->mnem, sizeof(out->mnem), "db");
            snprintf(out->ops, sizeof(out->ops), "0x%02x", code[0]);
            if (upper) {
                for (char *p = out->mnem; *p; p++) *p = (char)toupper((unsigned char)*p);
            }
        }
        return out->len;
    }

    uint32_t w;
    memcpy(&w, code, 4);
    out->len = 4;

    uint32_t op0 = (w >> 25) & 15U;
    int ok = 0;

    if ((w & 0xFFFF0000U) == 0x00000000U) {
        out->flow = X86_FLOW_TRAP;
        if (want_text) {
            snprintf(out->mnem, sizeof(out->mnem), "udf");
            snprintf(out->ops, sizeof(out->ops), "#0x%x", w & 0xFFFFU);
        }
        ok = 1;
    } else if ((op0 & 0xEU) == 0x8U) {
        ok = a64_decode_dp_imm(w, ip, want_text, out);
    } else if ((op0 & 0xEU) == 0xAU) {
        ok = a64_decode_branch_sys(w, ip, want_text, out);
    } else if ((op0 & 0x5U) == 0x4U) {
        ok = a64_decode_ldst(w, ip, want_text, out);
    } else if ((op0 & 0x7U) == 0x5U) {
        ok = a64_decode_dp_reg(w, want_text, out);
    } else if ((op0 & 0x7U) == 0x7U) {
        if ((w & 0x5E000000U) == 0x1E000000U) {
            ok = a64_decode_scalar_fp(w, want_text, out);
        } else {
            ok = a64_decode_simd(w, want_text, out);
        }
    }

    if (!ok && want_text) {
        snprintf(out->mnem, sizeof(out->mnem), "a64_%x", op0);
        snprintf(out->ops, sizeof(out->ops), "0x%08x", w);
    }

    if (want_text && upper) {
        for (char *p = out->mnem; *p; p++) *p = (char)toupper((unsigned char)*p);
    }
    return 4;
}
