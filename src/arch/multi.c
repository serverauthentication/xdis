#include "arch.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

static uint16_t m_u16(const uint8_t *p) {
    uint16_t v;
    memcpy(&v, p, 2);
    return v;
}

static uint32_t m_u32(const uint8_t *p) {
    uint32_t v;
    memcpy(&v, p, 4);
    return v;
}

static uint64_t m_u64(const uint8_t *p) {
    uint64_t v;
    memcpy(&v, p, 8);
    return v;
}

static int64_t m_sext(uint64_t v, int bits) {
    uint64_t m = 1ULL << (bits - 1);
    return (int64_t)((v ^ m) - m);
}

static void m_upper(x86_ins *out, int want_text, int upper) {
    if (!want_text || !upper) return;
    for (char *p = out->mnem; *p; p++) *p = (char)toupper((unsigned char)*p);
}

static int m_db(const uint8_t *code, size_t avail, int want_text, int upper, x86_ins *out) {
    if (!code || avail == 0) return 0;
    out->len = 1;
    if (want_text) {
        snprintf(out->mnem, sizeof(out->mnem), "db");
        snprintf(out->ops, sizeof(out->ops), "0x%02x", code[0]);
        m_upper(out, want_text, upper);
    }
    return 1;
}

static const char *const arm_cc[16] = {
    "eq","ne","cs","cc","mi","pl","vs","vc",
    "hi","ls","ge","lt","gt","le","","nv"
};

static const char *const arm_rn[16] = {
    "r0","r1","r2","r3","r4","r5","r6","r7",
    "r8","r9","r10","fp","ip","sp","lr","pc"
};

static void arm_reglist(uint16_t mask, char *buf, size_t sz) {
    size_t pos = 0;
    if (sz < 3) return;
    buf[pos++] = '{';
    int first = 1;
    for (int i = 0; i < 16; i++) {
        if (!((mask >> i) & 1U)) continue;
        int n = snprintf(buf + pos, sz - pos, "%s%s", first ? "" : ", ", arm_rn[i]);
        if (n < 0 || pos + (size_t)n + 2 >= sz) break;
        pos += (size_t)n;
        first = 0;
    }
    if (pos + 1 < sz) buf[pos++] = '}';
    buf[pos] = 0;
}

static const char *arm_barrier_opt(unsigned opt) {
    switch (opt & 15U) {
    case 1:  return "oshld";
    case 2:  return "oshst";
    case 3:  return "osh";
    case 5:  return "nshld";
    case 6:  return "nshst";
    case 7:  return "nsh";
    case 9:  return "ishld";
    case 10: return "ishst";
    case 11: return "ish";
    case 13: return "ld";
    case 14: return "st";
    case 15: return "sy";
    default: return NULL;
    }
}

static void arm_op2(uint32_t w, char *buf, size_t sz) {
    static const char *const sh_name[4] = {"lsl","lsr","asr","ror"};
    if ((w >> 25) & 1U) {
        uint32_t imm = w & 0xFFU;
        uint32_t rot = ((w >> 8) & 15U) * 2U;
        uint32_t val = rot ? ((imm >> rot) | (imm << (32U - rot))) : imm;
        snprintf(buf, sz, "#0x%x", val);
        return;
    }
    int rm = (int)(w & 15U);
    int st = (int)((w >> 5) & 3U);
    if ((w & 0x10U) == 0) {
        int sa = (int)((w >> 7) & 31U);
        if (sa == 0 && st == 0) snprintf(buf, sz, "%s", arm_rn[rm]);
        else if (sa == 0 && st == 3) snprintf(buf, sz, "%s, rrx", arm_rn[rm]);
        else snprintf(buf, sz, "%s, %s #%d", arm_rn[rm], sh_name[st], (sa == 0 && (st == 1 || st == 2)) ? 32 : sa);
    } else {
        int rs = (int)((w >> 8) & 15U);
        snprintf(buf, sz, "%s, %s %s", arm_rn[rm], sh_name[st], arm_rn[rs]);
    }
}

static void arm_ldm_stm(uint32_t w, const char *cc, int want_text, x86_ins *out) {
    static const char *const am[4] = {"da","ia","db","ib"};
    int p = (int)((w >> 24) & 1U);
    int u = (int)((w >> 23) & 1U);
    int wb = (int)((w >> 21) & 1U);
    int ld = (int)((w >> 20) & 1U);
    int rn = (int)((w >> 16) & 15U);
    uint16_t regs = (uint16_t)(w & 0xFFFFU);

    if (ld && (regs & 0x8000U)) out->flow = X86_FLOW_RET;
    if (!want_text) return;

    char list[68];
    arm_reglist(regs, list, sizeof(list));
    if (rn == 13 && wb && ((!ld && p && !u) || (ld && !p && u))) {
        snprintf(out->mnem, sizeof(out->mnem), "%s%s", ld ? "pop" : "push", cc);
        snprintf(out->ops, sizeof(out->ops), "%s", list);
        return;
    }
    snprintf(out->mnem, sizeof(out->mnem), "%s%s%s", ld ? "ldm" : "stm", am[(p << 1) | u], cc);
    snprintf(out->ops, sizeof(out->ops), "%s%s, %s", arm_rn[rn], wb ? "!" : "", list);
}

static void arm_ldr_str(uint32_t w, uint64_t ip, const char *cc, int want_text, x86_ins *out) {
    int reg_off = (int)((w >> 25) & 1U);
    int p = (int)((w >> 24) & 1U);
    int u = (int)((w >> 23) & 1U);
    int b = (int)((w >> 22) & 1U);
    int wb = (int)((w >> 21) & 1U);
    int ld = (int)((w >> 20) & 1U);
    int rn = (int)((w >> 16) & 15U);
    int rd = (int)((w >> 12) & 15U);
    uint32_t imm = w & 0xFFFU;

    if (ld && rd == 15) out->flow = (rn == 13) ? X86_FLOW_RET : X86_FLOW_JMP;
    if (!reg_off && rn == 15) {
        int64_t off = u ? (int64_t)imm : -(int64_t)imm;
        out->target = ip + 8ULL + (uint64_t)off;
        out->has_target = 1;
        out->target_mem = 1;
    }
    if (!want_text) return;

    snprintf(out->mnem, sizeof(out->mnem), "%s%s%s", ld ? "ldr" : "str", b ? "b" : "", cc);
    const char *sgn = u ? "" : "-";
    if (!reg_off) {
        if (p) {
            if (imm == 0) snprintf(out->ops, sizeof(out->ops), "%s, [%s]", arm_rn[rd], arm_rn[rn]);
            else snprintf(out->ops, sizeof(out->ops), "%s, [%s, #%s0x%x]%s", arm_rn[rd], arm_rn[rn], sgn, imm, wb ? "!" : "");
        } else {
            snprintf(out->ops, sizeof(out->ops), "%s, [%s], #%s0x%x", arm_rn[rd], arm_rn[rn], sgn, imm);
        }
    } else {
        static const char *const sh_name[4] = {"lsl","lsr","asr","ror"};
        int rm = (int)(w & 15U);
        int st = (int)((w >> 5) & 3U);
        int sa = (int)((w >> 7) & 31U);
        char sbuf[20] = "";
        if (sa != 0 || st != 0) {
            if (sa == 0 && st == 3) snprintf(sbuf, sizeof(sbuf), ", rrx");
            else snprintf(sbuf, sizeof(sbuf), ", %s #%d", sh_name[st], (sa == 0 && (st == 1 || st == 2)) ? 32 : sa);
        }
        if (p) snprintf(out->ops, sizeof(out->ops), "%s, [%s, %s%s%s]%s", arm_rn[rd], arm_rn[rn], sgn, arm_rn[rm], sbuf, wb ? "!" : "");
        else snprintf(out->ops, sizeof(out->ops), "%s, [%s], %s%s%s", arm_rn[rd], arm_rn[rn], sgn, arm_rn[rm], sbuf);
    }
}

static void arm_ldst_extra(uint32_t w, uint64_t ip, const char *cc, int want_text, x86_ins *out) {
    int p = (int)((w >> 24) & 1U);
    int u = (int)((w >> 23) & 1U);
    int is_imm = (int)((w >> 22) & 1U);
    int wb = (int)((w >> 21) & 1U);
    int ld = (int)((w >> 20) & 1U);
    int rn = (int)((w >> 16) & 15U);
    int rt = (int)((w >> 12) & 15U);
    unsigned op2 = (w >> 5) & 3U;
    uint32_t imm8 = (((w >> 8) & 15U) << 4) | (w & 15U);
    int rm = (int)(w & 15U);

    if (is_imm && rn == 15) {
        int64_t off = u ? (int64_t)imm8 : -(int64_t)imm8;
        out->target = ip + 8ULL + (uint64_t)off;
        out->has_target = 1;
        out->target_mem = 1;
    }
    if (!want_text) return;

    int dual = (!ld && op2 >= 2U);
    const char *mn = (op2 == 1U) ? (ld ? "ldrh" : "strh")
                   : (op2 == 2U) ? (ld ? "ldrsb" : "ldrd")
                   : (ld ? "ldrsh" : "strd");
    const char *sgn = u ? "" : "-";
    char regs[20];
    if (dual) snprintf(regs, sizeof(regs), "%s, %s", arm_rn[rt], arm_rn[(rt + 1) & 15]);
    else snprintf(regs, sizeof(regs), "%s", arm_rn[rt]);

    snprintf(out->mnem, sizeof(out->mnem), "%s%s", mn, cc);
    if (is_imm) {
        if (p) {
            if (imm8 == 0U && !wb) snprintf(out->ops, sizeof(out->ops), "%s, [%s]", regs, arm_rn[rn]);
            else snprintf(out->ops, sizeof(out->ops), "%s, [%s, #%s0x%x]%s", regs, arm_rn[rn], sgn, imm8, wb ? "!" : "");
        } else {
            snprintf(out->ops, sizeof(out->ops), "%s, [%s], #%s0x%x", regs, arm_rn[rn], sgn, imm8);
        }
    } else {
        if (p) snprintf(out->ops, sizeof(out->ops), "%s, [%s, %s%s]%s", regs, arm_rn[rn], sgn, arm_rn[rm], wb ? "!" : "");
        else snprintf(out->ops, sizeof(out->ops), "%s, [%s], %s%s", regs, arm_rn[rn], sgn, arm_rn[rm]);
    }
}

static void arm_dp(uint32_t w, const char *cc, int want_text, x86_ins *out) {
    static const char *const dp_m[16] = {
        "and","eor","sub","rsb","add","adc","sbc","rsc",
        "tst","teq","cmp","cmn","orr","mov","bic","mvn"
    };
    int is_imm = (int)((w >> 25) & 1U);
    int opc = (int)((w >> 21) & 15U);
    int s = (int)((w >> 20) & 1U);
    int rn = (int)((w >> 16) & 15U);
    int rd = (int)((w >> 12) & 15U);

    // mov pc, lr returns in armv4t
    if (opc == 13 && !is_imm && rd == 15 && (w & 0xFFFU) == 14U) out->flow = X86_FLOW_RET;
    if (!want_text) return;

    char op2[32];
    arm_op2(w, op2, sizeof(op2));
    if (opc >= 8 && opc <= 11) {
        snprintf(out->mnem, sizeof(out->mnem), "%s%s", dp_m[opc], cc);
        snprintf(out->ops, sizeof(out->ops), "%s, %s", arm_rn[rn], op2);
    } else if (opc == 13 || opc == 15) {
        snprintf(out->mnem, sizeof(out->mnem), "%s%s%s", dp_m[opc], s ? "s" : "", cc);
        snprintf(out->ops, sizeof(out->ops), "%s, %s", arm_rn[rd], op2);
    } else {
        snprintf(out->mnem, sizeof(out->mnem), "%s%s%s", dp_m[opc], s ? "s" : "", cc);
        snprintf(out->ops, sizeof(out->ops), "%s, %s, %s", arm_rn[rd], arm_rn[rn], op2);
    }
}

static int arm_vfp_decode(uint32_t w, uint64_t pc_base, const char *cc, int want_text, x86_ins *out) {
    // vpush / vpop
    if ((w & 0x0FBF0E00U) == 0x0D2D0A00U || (w & 0x0FBF0E00U) == 0x0CBD0A00U) {
        int is_pop = (int)((w >> 20) & 1U);
        unsigned D = (w >> 22) & 1U;
        unsigned vd = (w >> 12) & 15U;
        unsigned sz = (w >> 8) & 1U;
        unsigned imm8 = w & 0xFFU;
        unsigned start = sz ? ((D << 4) | vd) : ((vd << 1) | D);
        unsigned cnt = sz ? (imm8 >> 1) : imm8;
        if (cnt == 0U) return 0;
        if (want_text) {
            char rc = sz ? 'd' : 's';
            snprintf(out->mnem, sizeof(out->mnem), "%s%s", is_pop ? "vpop" : "vpush", cc);
            if (cnt == 1U) snprintf(out->ops, sizeof(out->ops), "{%c%u}", rc, start);
            else snprintf(out->ops, sizeof(out->ops), "{%c%u-%c%u}", rc, start, rc, start + cnt - 1U);
        }
        return 1;
    }

    // vldr / vstr
    if ((w & 0x0F200E00U) == 0x0D000A00U) {
        int u = (int)((w >> 23) & 1U);
        unsigned D = (w >> 22) & 1U;
        int ld = (int)((w >> 20) & 1U);
        int rn = (int)((w >> 16) & 15U);
        unsigned vd = (w >> 12) & 15U;
        unsigned sz = (w >> 8) & 1U;
        uint32_t imm = (w & 0xFFU) << 2;
        unsigned reg = sz ? ((D << 4) | vd) : ((vd << 1) | D);
        if (ld && rn == 15) {
            int64_t off = u ? (int64_t)imm : -(int64_t)imm;
            out->target = pc_base + (uint64_t)off;
            out->has_target = 1;
            out->target_mem = 1;
        }
        if (want_text) {
            snprintf(out->mnem, sizeof(out->mnem), "%s%s", ld ? "vldr" : "vstr", cc);
            if (imm == 0U) snprintf(out->ops, sizeof(out->ops), "%c%u, [%s]", sz ? 'd' : 's', reg, arm_rn[rn]);
            else snprintf(out->ops, sizeof(out->ops), "%c%u, [%s, #%s0x%x]", sz ? 'd' : 's', reg, arm_rn[rn], u ? "" : "-", imm);
        }
        return 1;
    }

    // vmov GPR <-> single
    if ((w & 0x0FE00F10U) == 0x0E000A10U) {
        int ld = (int)((w >> 20) & 1U);
        unsigned vn = (w >> 16) & 15U;
        int rt = (int)((w >> 12) & 15U);
        unsigned N = (w >> 7) & 1U;
        unsigned sn = (vn << 1) | N;
        if (want_text) {
            snprintf(out->mnem, sizeof(out->mnem), "vmov%s", cc);
            if (ld) snprintf(out->ops, sizeof(out->ops), "%s, s%u", arm_rn[rt], sn);
            else snprintf(out->ops, sizeof(out->ops), "s%u, %s", sn, arm_rn[rt]);
        }
        return 1;
    }

    // vmov 2 GPRs <-> double
    if ((w & 0x0FE00F50U) == 0x0C400B10U) {
        int ld = (int)((w >> 20) & 1U);
        int rt2 = (int)((w >> 16) & 15U);
        int rt = (int)((w >> 12) & 15U);
        unsigned M = (w >> 5) & 1U;
        unsigned dm = (M << 4) | (w & 15U);
        if (want_text) {
            snprintf(out->mnem, sizeof(out->mnem), "vmov%s", cc);
            if (ld) snprintf(out->ops, sizeof(out->ops), "%s, %s, d%u", arm_rn[rt], arm_rn[rt2], dm);
            else snprintf(out->ops, sizeof(out->ops), "d%u, %s, %s", dm, arm_rn[rt], arm_rn[rt2]);
        }
        return 1;
    }

    // vmrs / vmsr
    if ((w & 0x0FEF0FFFU) == 0x0EE10A10U) {
        int ld = (int)((w >> 20) & 1U);
        int rt = (int)((w >> 12) & 15U);
        if (want_text) {
            snprintf(out->mnem, sizeof(out->mnem), "%s%s", ld ? "vmrs" : "vmsr", cc);
            if (ld) snprintf(out->ops, sizeof(out->ops), "%s, fpscr", rt == 15 ? "apsr_nzcv" : arm_rn[rt]);
            else snprintf(out->ops, sizeof(out->ops), "fpscr, %s", arm_rn[rt]);
        }
        return 1;
    }

    // VFP Data-processing (vadd, vsub, vmul, vdiv, vmla, vmls, vmov, vabs, vneg, vsqrt, vcmp, vcvt)
    if ((w & 0x0F000E10U) == 0x0E000A00U) {
        unsigned p = (w >> 23) & 1U;
        unsigned q = (w >> 21) & 1U;
        unsigned r = (w >> 20) & 1U;
        unsigned s = (w >> 6) & 1U;
        unsigned sz = (w >> 8) & 1U;
        unsigned D = (w >> 22) & 1U;
        unsigned N = (w >> 7) & 1U;
        unsigned M = (w >> 5) & 1U;
        unsigned vn = (w >> 16) & 15U;
        unsigned vd = (w >> 12) & 15U;
        unsigned vm = w & 15U;
        unsigned rd = sz ? ((D << 4) | vd) : ((vd << 1) | D);
        unsigned rn = sz ? ((N << 4) | vn) : ((vn << 1) | N);
        unsigned rm = sz ? ((M << 4) | vm) : ((vm << 1) | M);
        char rc = sz ? 'd' : 's';
        const char *ft = sz ? "f64" : "f32";
        unsigned opc = (p << 3) | (q << 2) | (r << 1) | s;

        static const char *const fp3[9] = {
            "vmla","vmls","vnmls","vnmla","vmul","vnmul","vadd","vsub","vdiv"
        };
        if (opc < 9U) {
            if (want_text) {
                snprintf(out->mnem, sizeof(out->mnem), "%s%s.%s", fp3[opc], cc, ft);
                snprintf(out->ops, sizeof(out->ops), "%c%u, %c%u, %c%u", rc, rd, rc, rn, rc, rm);
            }
            return 1;
        }
        if (opc == 14U) {
            if (want_text) {
                snprintf(out->mnem, sizeof(out->mnem), "vmov%s.%s", cc, ft);
                snprintf(out->ops, sizeof(out->ops), "%c%u, #0x%x", rc, rd, (vn << 4) | vm);
            }
            return 1;
        }
        if (opc == 15U) {
            if (!want_text) return 1;
            if (vn == 0U) {
                snprintf(out->mnem, sizeof(out->mnem), "%s%s.%s", N ? "vabs" : "vmov", cc, ft);
                snprintf(out->ops, sizeof(out->ops), "%c%u, %c%u", rc, rd, rc, rm);
                return 1;
            }
            if (vn == 1U) {
                snprintf(out->mnem, sizeof(out->mnem), "%s%s.%s", N ? "vsqrt" : "vneg", cc, ft);
                snprintf(out->ops, sizeof(out->ops), "%c%u, %c%u", rc, rd, rc, rm);
                return 1;
            }
            if (vn == 4U || vn == 5U) {
                snprintf(out->mnem, sizeof(out->mnem), "vcmp%s%s.%s", N ? "e" : "", cc, ft);
                if (vn == 4U) snprintf(out->ops, sizeof(out->ops), "%c%u, %c%u", rc, rd, rc, rm);
                else snprintf(out->ops, sizeof(out->ops), "%c%u, #0.0", rc, rd);
                return 1;
            }
            if (vn == 7U && N) {
                unsigned d_alt = sz ? ((vd << 1) | D) : ((D << 4) | vd);
                snprintf(out->mnem, sizeof(out->mnem), "vcvt%s.%s.%s", cc, sz ? "f32" : "f64", ft);
                snprintf(out->ops, sizeof(out->ops), "%c%u, %c%u", sz ? 's' : 'd', d_alt, rc, rm);
                return 1;
            }
            if (vn == 8U) {
                unsigned sm = (vm << 1) | M;
                snprintf(out->mnem, sizeof(out->mnem), "vcvt%s.%s.%s", cc, ft, N ? "s32" : "u32");
                snprintf(out->ops, sizeof(out->ops), "%c%u, s%u", rc, rd, sm);
                return 1;
            }
            if (vn == 12U || vn == 13U) {
                unsigned sd = (vd << 1) | D;
                snprintf(out->mnem, sizeof(out->mnem), "vcvt%s.%s.%s", cc, vn == 13U ? "s32" : "u32", ft);
                snprintf(out->ops, sizeof(out->ops), "s%u, %c%u", sd, rc, rm);
                return 1;
            }
        }
    }
    return 0;
}

static uint32_t thumb_expand_imm(unsigned imm12) {
    unsigned hi = (imm12 >> 8) & 15U;
    uint32_t imm8 = imm12 & 0xFFU;
    if ((hi >> 2) == 0U) {
        switch (hi & 3U) {
        case 0U: return imm8;
        case 1U: return (imm8 << 16) | imm8;
        case 2U: return (imm8 << 24) | (imm8 << 8);
        default: return (imm8 << 24) | (imm8 << 16) | (imm8 << 8) | imm8;
        }
    }
    uint32_t unrot = 0x80U | (imm8 & 0x7FU);
    unsigned rot = (imm12 >> 7) & 31U;
    return rot ? ((unrot >> rot) | (unrot << (32U - rot))) : unrot;
}

static int thumb_decode_32(uint16_t h1, uint16_t h2, uint64_t pc, int want_text, x86_ins *out) {
    unsigned op1 = (h1 >> 11) & 3U;

    // Coprocessor / VFP (h1 bits[15:10] == 111x11 -> 0xEC../0xED../0xEE../0xEF../0xFC../0xFD../0xFE../0xFF..)
    if ((h1 & 0xEC00U) == 0xEC00U && (op1 == 1U || op1 == 3U)) {
        uint32_t w = ((uint32_t)h1 << 16) | (uint32_t)h2;
        if (arm_vfp_decode(w, (pc + 4ULL) & ~3ULL, "", want_text, out)) return 1;
    }

    // op1 == 2 (0xF000..0xF7FF): Branches, Misc Control, Data-proc Mod Imm, Data-proc Plain Imm
    if (op1 == 2U) {
        if (h2 & 0x8000U) {
            unsigned S = (h1 >> 10) & 1U;
            unsigned J1 = (h2 >> 13) & 1U;
            unsigned J2 = (h2 >> 11) & 1U;

            // bl / blx / b.w
            if ((h2 & 0xD000U) == 0xD000U || (h2 & 0xD000U) == 0xC000U || (h2 & 0xD000U) == 0x9000U) {
                unsigned I1 = (~(J1 ^ S)) & 1U;
                unsigned I2 = (~(J2 ^ S)) & 1U;
                int is_blx = ((h2 & 0xD000U) == 0xC000U);
                int is_bl = ((h2 & 0xD000U) == 0xD000U);
                uint64_t imm25 = ((uint64_t)S << 24) | ((uint64_t)I1 << 23) | ((uint64_t)I2 << 22)
                               | ((uint64_t)(h1 & 0x3FFU) << 12)
                               | ((uint64_t)(is_blx ? (h2 & 0x7FEU) : (h2 & 0x7FFU)) << 1);
                int64_t off = m_sext(imm25, 25);
                uint64_t base = is_blx ? ((pc + 4ULL) & ~3ULL) : (pc + 4ULL);
                out->target = base + (uint64_t)off;
                out->has_target = 1;
                out->flow = (is_bl || is_blx) ? X86_FLOW_CALL : X86_FLOW_JMP;
                if (want_text) {
                    snprintf(out->mnem, sizeof(out->mnem), "%s", is_bl ? "bl" : is_blx ? "blx" : "b.w");
                    snprintf(out->ops, sizeof(out->ops), "0x%llx", (unsigned long long)out->target);
                }
                return 1;
            }

            // Conditional branch b<cc>.w
            if ((h2 & 0xD000U) == 0x8000U && ((h1 >> 6) & 0xEU) != 0xEU) {
                unsigned cond = (h1 >> 6) & 15U;
                uint64_t imm21 = ((uint64_t)S << 20) | ((uint64_t)J2 << 19) | ((uint64_t)J1 << 18)
                               | ((uint64_t)(h1 & 0x3FU) << 12) | ((uint64_t)(h2 & 0x7FFU) << 1);
                out->target = pc + 4ULL + (uint64_t)m_sext(imm21, 21);
                out->has_target = 1;
                out->flow = X86_FLOW_JCC;
                if (want_text) {
                    snprintf(out->mnem, sizeof(out->mnem), "b%s.w", arm_cc[cond]);
                    snprintf(out->ops, sizeof(out->ops), "0x%llx", (unsigned long long)out->target);
                }
                return 1;
            }

            // Barriers & Misc control
            if (h1 == 0xF3BFU) {
                unsigned op = (h2 >> 4) & 15U;
                unsigned opt = h2 & 15U;
                if (op == 2U) {
                    if (want_text) snprintf(out->mnem, sizeof(out->mnem), "clrex");
                    return 1;
                }
                if (op == 4U || op == 5U || op == 6U) {
                    if (want_text) {
                        const char *oname = arm_barrier_opt(opt);
                        snprintf(out->mnem, sizeof(out->mnem), "%s", op == 4U ? "dsb" : op == 5U ? "dmb" : "isb");
                        if (oname) snprintf(out->ops, sizeof(out->ops), "%s", oname);
                        else snprintf(out->ops, sizeof(out->ops), "#0x%x", opt);
                    }
                    return 1;
                }
            }
            if (h1 == 0xF3AFU && (h2 & 0xFF00U) == 0x8000U) {
                static const char *const hn[5] = { "nop.w","yield.w","wfe.w","wfi.w","sev.w" };
                unsigned sub = h2 & 0xFFU;
                if (want_text) {
                    if (sub < 5U) snprintf(out->mnem, sizeof(out->mnem), "%s", hn[sub]);
                    else { snprintf(out->mnem, sizeof(out->mnem), "hint.w"); snprintf(out->ops, sizeof(out->ops), "#0x%x", sub); }
                }
                return 1;
            }
            if ((h1 & 0xFFF0U) == 0xF7F0U && (h2 & 0xF000U) == 0xA000U) {
                out->flow = X86_FLOW_TRAP;
                if (want_text) {
                    snprintf(out->mnem, sizeof(out->mnem), "udf.w");
                    snprintf(out->ops, sizeof(out->ops), "#0x%x", ((h1 & 15U) << 12) | (h2 & 0xFFFU));
                }
                return 1;
            }
            if ((h1 & 0xFFE0U) == 0xF380U) {
                if (want_text) {
                    snprintf(out->mnem, sizeof(out->mnem), "msr");
                    snprintf(out->ops, sizeof(out->ops), "#0x%x, %s", h2 & 0xFFU, arm_rn[h1 & 15U]);
                }
                return 1;
            }
            if ((h1 & 0xFFE0U) == 0xF3E0U) {
                if (want_text) {
                    snprintf(out->mnem, sizeof(out->mnem), "mrs");
                    snprintf(out->ops, sizeof(out->ops), "%s, #0x%x", arm_rn[(h2 >> 8) & 15U], h2 & 0xFFU);
                }
                return 1;
            }
            return 0;
        }

        // Data processing (modified immediate): bit 9 of h1 == 0
        if ((h1 & 0x0200U) == 0U) {
            static const char *const opm[16] = {
                "and","bic","orr","orn","eor",NULL,NULL,NULL,
                "add",NULL,"adc","sbc",NULL,"sub","rsb",NULL
            };
            unsigned i = (h1 >> 10) & 1U;
            unsigned opc = (h1 >> 5) & 15U;
            unsigned S = (h1 >> 4) & 1U;
            unsigned rn = h1 & 15U;
            unsigned imm3 = (h2 >> 12) & 7U;
            unsigned rd = (h2 >> 8) & 15U;
            unsigned imm8 = h2 & 0xFFU;
            if (!opm[opc]) return 0;
            uint32_t val = thumb_expand_imm((i << 11) | (imm3 << 8) | imm8);
            if (!want_text) return 1;

            if (rd == 15U && S && (opc == 0U || opc == 4U || opc == 8U || opc == 13U)) {
                const char *cm = (opc == 0U) ? "tst.w" : (opc == 4U) ? "teq.w" : (opc == 8U) ? "cmn.w" : "cmp.w";
                snprintf(out->mnem, sizeof(out->mnem), "%s", cm);
                snprintf(out->ops, sizeof(out->ops), "%s, #0x%x", arm_rn[rn], val);
            } else if (rn == 15U && (opc == 2U || opc == 3U)) {
                snprintf(out->mnem, sizeof(out->mnem), "%s%s.w", opc == 2U ? "mov" : "mvn", S ? "s" : "");
                snprintf(out->ops, sizeof(out->ops), "%s, #0x%x", arm_rn[rd], val);
            } else {
                snprintf(out->mnem, sizeof(out->mnem), "%s%s.w", opm[opc], S ? "s" : "");
                snprintf(out->ops, sizeof(out->ops), "%s, %s, #0x%x", arm_rn[rd], arm_rn[rn], val);
            }
            return 1;
        }

        // Data processing (plain binary immediate): bit 9 of h1 == 1
        {
            unsigned i = (h1 >> 10) & 1U;
            unsigned op5 = (h1 >> 4) & 31U;
            unsigned rn = h1 & 15U;
            unsigned imm3 = (h2 >> 12) & 7U;
            unsigned rd = (h2 >> 8) & 15U;
            unsigned imm8 = h2 & 0xFFU;

            if (op5 == 0x04U || op5 == 0x0CU) {
                uint32_t imm16 = (rn << 12) | (i << 11) | (imm3 << 8) | imm8;
                if (want_text) {
                    snprintf(out->mnem, sizeof(out->mnem), "%s", op5 == 0x0CU ? "movt" : "movw");
                    snprintf(out->ops, sizeof(out->ops), "%s, #0x%x", arm_rn[rd], imm16);
                }
                return 1;
            }
            if (op5 == 0x00U || op5 == 0x0AU) {
                uint32_t imm12 = (i << 11) | (imm3 << 8) | imm8;
                if (rn == 15U) {
                    int64_t off = (op5 == 0x00U) ? (int64_t)imm12 : -(int64_t)imm12;
                    out->target = ((pc + 4ULL) & ~3ULL) + (uint64_t)off;
                    out->has_target = 1;
                    out->target_mem = 1;
                    if (want_text) {
                        snprintf(out->mnem, sizeof(out->mnem), "adr.w");
                        snprintf(out->ops, sizeof(out->ops), "%s, 0x%llx", arm_rn[rd], (unsigned long long)out->target);
                    }
                    return 1;
                }
                if (want_text) {
                    snprintf(out->mnem, sizeof(out->mnem), "%s", op5 == 0x00U ? "addw" : "subw");
                    snprintf(out->ops, sizeof(out->ops), "%s, %s, #0x%x", arm_rn[rd], arm_rn[rn], imm12);
                }
                return 1;
            }
            if (op5 == 0x14U || op5 == 0x16U || op5 == 0x1CU) {
                unsigned lsb = (imm3 << 2) | ((h2 >> 6) & 3U);
                unsigned f5 = h2 & 31U;
                if (want_text) {
                    if (op5 == 0x16U) {
                        unsigned width = (f5 >= lsb) ? (f5 - lsb + 1U) : 1U;
                        if (rn == 15U) {
                            snprintf(out->mnem, sizeof(out->mnem), "bfc");
                            snprintf(out->ops, sizeof(out->ops), "%s, #%u, #%u", arm_rn[rd], lsb, width);
                        } else {
                            snprintf(out->mnem, sizeof(out->mnem), "bfi");
                            snprintf(out->ops, sizeof(out->ops), "%s, %s, #%u, #%u", arm_rn[rd], arm_rn[rn], lsb, width);
                        }
                    } else {
                        snprintf(out->mnem, sizeof(out->mnem), "%s", op5 == 0x1CU ? "ubfx" : "sbfx");
                        snprintf(out->ops, sizeof(out->ops), "%s, %s, #%u, #%u", arm_rn[rd], arm_rn[rn], lsb, f5 + 1U);
                    }
                }
                return 1;
            }
            if (op5 == 0x10U || op5 == 0x12U || op5 == 0x18U || op5 == 0x1AU) {
                unsigned sat = (h2 & 31U) + ((op5 < 0x18U) ? 1U : 0U);
                if (want_text) {
                    snprintf(out->mnem, sizeof(out->mnem), "%s", op5 < 0x18U ? "ssat" : "usat");
                    snprintf(out->ops, sizeof(out->ops), "%s, #%u, %s", arm_rn[rd], sat, arm_rn[rn]);
                }
                return 1;
            }
        }
        return 0;
    }

    // op1 == 1 (0xE800..0xEFFF): LDM/STM, LDRD/STRD/Exclusive/TBB/TBH, Data-proc Shifted Reg
    if (op1 == 1U) {
        // Load/Store Multiple (push.w/pop.w/ldmia.w/stmdb.w)
        if ((h1 & 0xFE40U) == 0xE800U) {
            unsigned opc = (h1 >> 7) & 3U;
            unsigned W = (h1 >> 5) & 1U;
            unsigned L = (h1 >> 4) & 1U;
            unsigned rn = h1 & 15U;
            if (opc != 1U && opc != 2U) return 0;
            if (L && (h2 & 0x8000U)) out->flow = X86_FLOW_RET;
            if (!want_text) return 1;
            char list[68];
            arm_reglist(h2, list, sizeof(list));
            if (rn == 13U && W && ((!L && opc == 2U) || (L && opc == 1U))) {
                snprintf(out->mnem, sizeof(out->mnem), "%s", L ? "pop.w" : "push.w");
                snprintf(out->ops, sizeof(out->ops), "%s", list);
            } else {
                snprintf(out->mnem, sizeof(out->mnem), "%s%s.w", L ? "ldm" : "stm", opc == 1U ? "ia" : "db");
                snprintf(out->ops, sizeof(out->ops), "%s%s, %s", arm_rn[rn], W ? "!" : "", list);
            }
            return 1;
        }

        // Load/Store Dual, Exclusive, Table Branch
        if ((h1 & 0xFE40U) == 0xE840U) {
            unsigned P = (h1 >> 8) & 1U;
            unsigned U = (h1 >> 7) & 1U;
            unsigned W = (h1 >> 5) & 1U;
            unsigned L = (h1 >> 4) & 1U;
            unsigned rn = h1 & 15U;
            unsigned rt = (h2 >> 12) & 15U;
            unsigned rt2 = (h2 >> 8) & 15U;

            if (!P && !U && !W) {
                uint32_t imm = (h2 & 0xFFU) << 2;
                if (want_text) {
                    snprintf(out->mnem, sizeof(out->mnem), "%s", L ? "ldrex" : "strex");
                    if (L) {
                        if (imm) snprintf(out->ops, sizeof(out->ops), "%s, [%s, #0x%x]", arm_rn[rt], arm_rn[rn], imm);
                        else snprintf(out->ops, sizeof(out->ops), "%s, [%s]", arm_rn[rt], arm_rn[rn]);
                    } else {
                        if (imm) snprintf(out->ops, sizeof(out->ops), "%s, %s, [%s, #0x%x]", arm_rn[rt2], arm_rn[rt], arm_rn[rn], imm);
                        else snprintf(out->ops, sizeof(out->ops), "%s, %s, [%s]", arm_rn[rt2], arm_rn[rt], arm_rn[rn]);
                    }
                }
                return 1;
            }
            if (!P && U && !W) {
                unsigned op3 = (h2 >> 4) & 15U;
                unsigned rm = h2 & 15U;
                if (L && (op3 == 0U || op3 == 1U)) {
                    out->flow = X86_FLOW_JMP;
                    if (want_text) {
                        snprintf(out->mnem, sizeof(out->mnem), "%s", op3 ? "tbh" : "tbb");
                        if (op3) snprintf(out->ops, sizeof(out->ops), "[%s, %s, lsl #1]", arm_rn[rn], arm_rn[rm]);
                        else snprintf(out->ops, sizeof(out->ops), "[%s, %s]", arm_rn[rn], arm_rn[rm]);
                    }
                    return 1;
                }
                if (op3 == 4U || op3 == 5U || op3 == 7U) {
                    const char *sfx = (op3 == 4U) ? "b" : (op3 == 5U) ? "h" : "d";
                    if (want_text) {
                        snprintf(out->mnem, sizeof(out->mnem), "%s%s", L ? "ldrex" : "strex", sfx);
                        if (op3 == 7U) {
                            if (L) snprintf(out->ops, sizeof(out->ops), "%s, %s, [%s]", arm_rn[rt], arm_rn[rt2], arm_rn[rn]);
                            else snprintf(out->ops, sizeof(out->ops), "%s, %s, %s, [%s]", arm_rn[rm], arm_rn[rt], arm_rn[rt2], arm_rn[rn]);
                        } else {
                            if (L) snprintf(out->ops, sizeof(out->ops), "%s, [%s]", arm_rn[rt], arm_rn[rn]);
                            else snprintf(out->ops, sizeof(out->ops), "%s, %s, [%s]", arm_rn[rm], arm_rn[rt], arm_rn[rn]);
                        }
                    }
                    return 1;
                }
                return 0;
            }
            // ldrd / strd
            uint32_t imm = (h2 & 0xFFU) << 2;
            if (L && rn == 15U) {
                int64_t off = U ? (int64_t)imm : -(int64_t)imm;
                out->target = ((pc + 4ULL) & ~3ULL) + (uint64_t)off;
                out->has_target = 1;
                out->target_mem = 1;
            }
            if (want_text) {
                const char *sgn = U ? "" : "-";
                snprintf(out->mnem, sizeof(out->mnem), "%s", L ? "ldrd" : "strd");
                if (P) {
                    if (imm == 0U && !W) snprintf(out->ops, sizeof(out->ops), "%s, %s, [%s]", arm_rn[rt], arm_rn[rt2], arm_rn[rn]);
                    else snprintf(out->ops, sizeof(out->ops), "%s, %s, [%s, #%s0x%x]%s", arm_rn[rt], arm_rn[rt2], arm_rn[rn], sgn, imm, W ? "!" : "");
                } else {
                    snprintf(out->ops, sizeof(out->ops), "%s, %s, [%s], #%s0x%x", arm_rn[rt], arm_rn[rt2], arm_rn[rn], sgn, imm);
                }
            }
            return 1;
        }

        // Data processing (shifted register): 0xEA00..0xEBFF
        if ((h1 & 0xFE00U) == 0xEA00U) {
            static const char *const opm[16] = {
                "and","bic","orr","orn","eor",NULL,"pkh",NULL,
                "add",NULL,"adc","sbc",NULL,"sub","rsb",NULL
            };
            static const char *const sh_n[4] = { "lsl","lsr","asr","ror" };
            unsigned opc = (h1 >> 5) & 15U;
            unsigned S = (h1 >> 4) & 1U;
            unsigned rn = h1 & 15U;
            unsigned imm3 = (h2 >> 12) & 7U;
            unsigned rd = (h2 >> 8) & 15U;
            unsigned imm2 = (h2 >> 6) & 3U;
            unsigned stype = (h2 >> 4) & 3U;
            unsigned rm = h2 & 15U;
            unsigned sh = (imm3 << 2) | imm2;
            if (!opm[opc] || opc == 6U) return 0;
            if (!want_text) return 1;

            char op2[24];
            if (sh == 0U && stype == 0U) snprintf(op2, sizeof(op2), "%s", arm_rn[rm]);
            else if (sh == 0U && stype == 3U) snprintf(op2, sizeof(op2), "%s, rrx", arm_rn[rm]);
            else snprintf(op2, sizeof(op2), "%s, %s #%u", arm_rn[rm], sh_n[stype], (sh == 0U && (stype == 1U || stype == 2U)) ? 32U : sh);

            if (rd == 15U && S && (opc == 0U || opc == 4U || opc == 8U || opc == 13U)) {
                const char *cm = (opc == 0U) ? "tst.w" : (opc == 4U) ? "teq.w" : (opc == 8U) ? "cmn.w" : "cmp.w";
                snprintf(out->mnem, sizeof(out->mnem), "%s", cm);
                snprintf(out->ops, sizeof(out->ops), "%s, %s", arm_rn[rn], op2);
            } else if (rn == 15U && opc == 2U) {
                if (sh == 0U && stype == 0U) {
                    snprintf(out->mnem, sizeof(out->mnem), "mov%s.w", S ? "s" : "");
                    snprintf(out->ops, sizeof(out->ops), "%s, %s", arm_rn[rd], arm_rn[rm]);
                } else if (sh == 0U && stype == 3U) {
                    snprintf(out->mnem, sizeof(out->mnem), "rrx%s", S ? "s" : "");
                    snprintf(out->ops, sizeof(out->ops), "%s, %s", arm_rn[rd], arm_rn[rm]);
                } else {
                    snprintf(out->mnem, sizeof(out->mnem), "%s%s.w", sh_n[stype], S ? "s" : "");
                    snprintf(out->ops, sizeof(out->ops), "%s, %s, #%u", arm_rn[rd], arm_rn[rm], (sh == 0U && (stype == 1U || stype == 2U)) ? 32U : sh);
                }
            } else if (rn == 15U && opc == 3U) {
                snprintf(out->mnem, sizeof(out->mnem), "mvn%s.w", S ? "s" : "");
                snprintf(out->ops, sizeof(out->ops), "%s, %s", arm_rn[rd], op2);
            } else {
                snprintf(out->mnem, sizeof(out->mnem), "%s%s.w", opm[opc], S ? "s" : "");
                snprintf(out->ops, sizeof(out->ops), "%s, %s, %s", arm_rn[rd], arm_rn[rn], op2);
            }
            return 1;
        }
        return 0;
    }

    // op1 == 3 (0xF800..0xFFFF): Single Load/Store, Data-proc Reg, Multiply/Divide
    if (op1 == 3U) {
        // Load/Store Single Data Item (0xF800..0xF9FF)
        if ((h1 & 0xFE00U) == 0xF800U) {
            unsigned S_sign = (h1 >> 8) & 1U;
            unsigned U_add = (h1 >> 7) & 1U;
            unsigned size = (h1 >> 5) & 3U;
            unsigned L = (h1 >> 4) & 1U;
            unsigned rn = h1 & 15U;
            unsigned rt = (h2 >> 12) & 15U;
            if (size == 3U || (S_sign && (!L || size == 2U))) return 0;

            if (L && rt == 15U && size == 2U && !S_sign) {
                out->flow = (rn == 13U) ? X86_FLOW_RET : X86_FLOW_JMP;
            }

            if (rn == 15U && L) {
                uint32_t imm12 = h2 & 0xFFFU;
                int64_t off = U_add ? (int64_t)imm12 : -(int64_t)imm12;
                out->target = ((pc + 4ULL) & ~3ULL) + (uint64_t)off;
                out->has_target = 1;
                out->target_mem = 1;
                if (want_text) {
                    snprintf(out->mnem, sizeof(out->mnem), "ldr%s%s.w", S_sign ? "s" : "", size == 0U ? "b" : size == 1U ? "h" : "");
                    snprintf(out->ops, sizeof(out->ops), "%s, [pc, #%s0x%x]", arm_rn[rt], U_add ? "" : "-", imm12);
                }
                return 1;
            }

            if (!want_text) return 1;
            if (L && rt == 15U && size <= 1U) {
                snprintf(out->mnem, sizeof(out->mnem), "%s", S_sign ? "pli" : "pld");
            } else {
                snprintf(out->mnem, sizeof(out->mnem), "%s%s%s.w", L ? "ldr" : "str", S_sign ? "s" : "", size == 0U ? "b" : size == 1U ? "h" : "");
            }

            if (U_add) {
                uint32_t imm12 = h2 & 0xFFFU;
                if (imm12) snprintf(out->ops, sizeof(out->ops), "%s, [%s, #0x%x]", arm_rn[rt], arm_rn[rn], imm12);
                else snprintf(out->ops, sizeof(out->ops), "%s, [%s]", arm_rn[rt], arm_rn[rn]);
                return 1;
            }
            if (h2 & 0x0800U) {
                unsigned P = (h2 >> 10) & 1U;
                unsigned U = (h2 >> 9) & 1U;
                unsigned W = (h2 >> 8) & 1U;
                uint32_t imm8 = h2 & 0xFFU;
                if (size == 2U && !S_sign && rn == 13U && imm8 == 4U && W) {
                    if (!L && P && !U) {
                        snprintf(out->mnem, sizeof(out->mnem), "push.w");
                        snprintf(out->ops, sizeof(out->ops), "{%s}", arm_rn[rt]);
                        return 1;
                    }
                    if (L && !P && U) {
                        snprintf(out->mnem, sizeof(out->mnem), "pop.w");
                        snprintf(out->ops, sizeof(out->ops), "{%s}", arm_rn[rt]);
                        return 1;
                    }
                }
                const char *sgn = U ? "" : "-";
                if (P) snprintf(out->ops, sizeof(out->ops), "%s, [%s, #%s0x%x]%s", arm_rn[rt], arm_rn[rn], sgn, imm8, W ? "!" : "");
                else snprintf(out->ops, sizeof(out->ops), "%s, [%s], #%s0x%x", arm_rn[rt], arm_rn[rn], sgn, imm8);
                return 1;
            }
            if ((h2 & 0x0FC0U) == 0x0000U) {
                unsigned rm = h2 & 15U;
                unsigned sh = (h2 >> 4) & 3U;
                if (sh) snprintf(out->ops, sizeof(out->ops), "%s, [%s, %s, lsl #%u]", arm_rn[rt], arm_rn[rn], arm_rn[rm], sh);
                else snprintf(out->ops, sizeof(out->ops), "%s, [%s, %s]", arm_rn[rt], arm_rn[rn], arm_rn[rm]);
                return 1;
            }
            return 0;
        }

        // Data processing (register): 0xFA00..0xFAFF
        if ((h1 & 0xFF00U) == 0xFA00U) {
            unsigned op1_r = (h1 >> 4) & 15U;
            unsigned rn = h1 & 15U;
            unsigned rd = (h2 >> 8) & 15U;
            unsigned op2_r = (h2 >> 4) & 15U;
            unsigned rm = h2 & 15U;
            if (!want_text) return 1;

            if (op1_r < 8U && op2_r == 0U) {
                static const char *const sh_n[4] = { "lsl","lsr","asr","ror" };
                snprintf(out->mnem, sizeof(out->mnem), "%s%s.w", sh_n[op1_r >> 1], (op1_r & 1U) ? "s" : "");
                snprintf(out->ops, sizeof(out->ops), "%s, %s, %s", arm_rn[rd], arm_rn[rn], arm_rn[rm]);
                return 1;
            }
            if (op1_r <= 5U && (op2_r & 0xCU) == 8U) {
                static const char *const xta[6] = { "sxtah","uxtah","sxtab16","uxtab16","sxtab","uxtab" };
                static const char *const xt[6] = { "sxth.w","uxth.w","sxtb16","uxtb16","sxtb.w","uxtb.w" };
                if (rn == 15U) {
                    snprintf(out->mnem, sizeof(out->mnem), "%s", xt[op1_r]);
                    snprintf(out->ops, sizeof(out->ops), "%s, %s", arm_rn[rd], arm_rn[rm]);
                } else {
                    snprintf(out->mnem, sizeof(out->mnem), "%s", xta[op1_r]);
                    snprintf(out->ops, sizeof(out->ops), "%s, %s, %s", arm_rn[rd], arm_rn[rn], arm_rn[rm]);
                }
                return 1;
            }
            if (op1_r == 9U && op2_r >= 8U && op2_r <= 11U) {
                static const char *const rv[4] = { "rev.w","rev16.w","rbit","revsh.w" };
                snprintf(out->mnem, sizeof(out->mnem), "%s", rv[op2_r - 8U]);
                snprintf(out->ops, sizeof(out->ops), "%s, %s", arm_rn[rd], arm_rn[rm]);
                return 1;
            }
            if (op1_r == 11U && op2_r == 8U) {
                snprintf(out->mnem, sizeof(out->mnem), "clz");
                snprintf(out->ops, sizeof(out->ops), "%s, %s", arm_rn[rd], arm_rn[rm]);
                return 1;
            }
            return 0;
        }

        // Multiply, Multiply Accumulate, Divide: 0xFB00..0xFBFF
        if ((h1 & 0xFF00U) == 0xFB00U) {
            unsigned op1_m = (h1 >> 4) & 15U;
            unsigned rn = h1 & 15U;
            unsigned ra = (h2 >> 12) & 15U;
            unsigned rd = (h2 >> 8) & 15U;
            unsigned op2_m = (h2 >> 4) & 15U;
            unsigned rm = h2 & 15U;
            if (!want_text) return 1;

            if (op1_m == 0U && op2_m == 0U) {
                if (ra == 15U) {
                    snprintf(out->mnem, sizeof(out->mnem), "mul");
                    snprintf(out->ops, sizeof(out->ops), "%s, %s, %s", arm_rn[rd], arm_rn[rn], arm_rn[rm]);
                } else {
                    snprintf(out->mnem, sizeof(out->mnem), "mla");
                    snprintf(out->ops, sizeof(out->ops), "%s, %s, %s, %s", arm_rn[rd], arm_rn[rn], arm_rn[rm], arm_rn[ra]);
                }
                return 1;
            }
            if (op1_m == 0U && op2_m == 1U) {
                snprintf(out->mnem, sizeof(out->mnem), "mls");
                snprintf(out->ops, sizeof(out->ops), "%s, %s, %s, %s", arm_rn[rd], arm_rn[rn], arm_rn[rm], arm_rn[ra]);
                return 1;
            }
            if ((op1_m == 9U || op1_m == 11U) && op2_m == 15U) {
                snprintf(out->mnem, sizeof(out->mnem), "%s", op1_m == 9U ? "sdiv" : "udiv");
                snprintf(out->ops, sizeof(out->ops), "%s, %s, %s", arm_rn[rd], arm_rn[rn], arm_rn[rm]);
                return 1;
            }
            if ((op1_m == 8U || op1_m == 10U || op1_m == 12U || op1_m == 14U) && op2_m == 0U) {
                const char *mn = (op1_m == 8U) ? "smull" : (op1_m == 10U) ? "umull" : (op1_m == 12U) ? "smlal" : "umlal";
                snprintf(out->mnem, sizeof(out->mnem), "%s", mn);
                snprintf(out->ops, sizeof(out->ops), "%s, %s, %s, %s", arm_rn[ra], arm_rn[rd], arm_rn[rn], arm_rn[rm]);
                return 1;
            }
        }
    }

    return 0;
}

int thumb_decode(const uint8_t *code, size_t avail, uint64_t ip, int want_text, int upper, x86_ins *out) {
    memset(out, 0, sizeof(*out));
    out->ip = ip;
    uint64_t pc = ip & ~1ULL;
    if (!code || avail < 2) return m_db(code, avail, want_text, upper, out);

    uint16_t h1 = m_u16(code);
    unsigned top5 = (h1 >> 11) & 0x1FU;

    // 32-bit Thumb-2 instruction
    if (top5 >= 0x1DU) {
        if (avail < 4) return m_db(code, avail, want_text, upper, out);
        uint16_t h2 = m_u16(code + 2);
        out->len = 4;
        if (!thumb_decode_32(h1, h2, pc, want_text, out) && want_text) {
            snprintf(out->mnem, sizeof(out->mnem), "t32");
            snprintf(out->ops, sizeof(out->ops), "0x%04x%04x", h1, h2);
        }
        m_upper(out, want_text, upper);
        return 4;
    }

    // 16-bit Thumb-1 instruction
    out->len = 2;
    unsigned top3 = (h1 >> 13) & 7U;
    unsigned top4 = (h1 >> 12) & 15U;

    if (top3 == 0U) {
        unsigned op = (h1 >> 11) & 3U;
        unsigned rd = h1 & 7U;
        unsigned rn = (h1 >> 3) & 7U;
        if (op < 3U) {
            static const char *const sh_m[3] = { "lsls", "lsrs", "asrs" };
            unsigned imm5 = (h1 >> 6) & 31U;
            if (want_text) {
                if (op == 0U && imm5 == 0U) {
                    snprintf(out->mnem, sizeof(out->mnem), "movs");
                    snprintf(out->ops, sizeof(out->ops), "%s, %s", arm_rn[rd], arm_rn[rn]);
                } else {
                    snprintf(out->mnem, sizeof(out->mnem), "%s", sh_m[op]);
                    snprintf(out->ops, sizeof(out->ops), "%s, %s, #%u", arm_rn[rd], arm_rn[rn], (imm5 == 0U && op != 0U) ? 32U : imm5);
                }
            }
        } else {
            unsigned sub_op = (h1 >> 9) & 3U;
            unsigned rm_imm = (h1 >> 6) & 7U;
            if (want_text) {
                snprintf(out->mnem, sizeof(out->mnem), "%s", (sub_op & 1U) ? "subs" : "adds");
                if (sub_op & 2U) snprintf(out->ops, sizeof(out->ops), "%s, %s, #%u", arm_rn[rd], arm_rn[rn], rm_imm);
                else snprintf(out->ops, sizeof(out->ops), "%s, %s, %s", arm_rn[rd], arm_rn[rn], arm_rn[rm_imm]);
            }
        }
    } else if (top3 == 1U) {
        static const char *const im_m[4] = { "movs", "cmp", "adds", "subs" };
        unsigned op = (h1 >> 11) & 3U;
        unsigned rd = (h1 >> 8) & 7U;
        if (want_text) {
            snprintf(out->mnem, sizeof(out->mnem), "%s", im_m[op]);
            snprintf(out->ops, sizeof(out->ops), "%s, #0x%x", arm_rn[rd], h1 & 0xFFU);
        }
    } else if ((h1 >> 10) == 0x10U) {
        static const char *const alu_m[16] = {
            "ands","eors","lsls","lsrs","asrs","adcs","sbcs","rors",
            "tst","rsbs","cmp","cmn","orrs","muls","bics","mvns"
        };
        unsigned op = (h1 >> 6) & 15U;
        unsigned rm = (h1 >> 3) & 7U;
        unsigned rdn = h1 & 7U;
        if (want_text) {
            snprintf(out->mnem, sizeof(out->mnem), "%s", alu_m[op]);
            if (op == 9U) snprintf(out->ops, sizeof(out->ops), "%s, %s, #0", arm_rn[rdn], arm_rn[rm]);
            else snprintf(out->ops, sizeof(out->ops), "%s, %s", arm_rn[rdn], arm_rn[rm]);
        }
    } else if ((h1 >> 10) == 0x11U) {
        unsigned op = (h1 >> 8) & 3U;
        unsigned rm = (h1 >> 3) & 15U;
        unsigned rd = (((h1 >> 7) & 1U) << 3) | (h1 & 7U);
        if (op == 3U) {
            unsigned link = (h1 >> 7) & 1U;
            out->flow = link ? X86_FLOW_CALL : (rm == 14U ? X86_FLOW_RET : X86_FLOW_JMP);
            if (want_text) {
                snprintf(out->mnem, sizeof(out->mnem), "%s", link ? "blx" : "bx");
                snprintf(out->ops, sizeof(out->ops), "%s", arm_rn[rm]);
            }
        } else {
            if (op == 0U && rd == 15U) out->flow = X86_FLOW_JMP;
            else if (op == 2U && rd == 15U) out->flow = (rm == 14U) ? X86_FLOW_RET : X86_FLOW_JMP;
            if (want_text) {
                if (h1 == 0x46C0U) {
                    snprintf(out->mnem, sizeof(out->mnem), "nop");
                } else {
                    static const char *const sp_m[3] = { "add", "cmp", "mov" };
                    snprintf(out->mnem, sizeof(out->mnem), "%s", sp_m[op]);
                    snprintf(out->ops, sizeof(out->ops), "%s, %s", arm_rn[rd], arm_rn[rm]);
                }
            }
        }
    } else if (top5 == 9U) {
        unsigned rt = (h1 >> 8) & 7U;
        uint32_t imm = (h1 & 0xFFU) << 2;
        out->target = ((pc + 4ULL) & ~3ULL) + (uint64_t)imm;
        out->has_target = 1;
        out->target_mem = 1;
        if (want_text) {
            snprintf(out->mnem, sizeof(out->mnem), "ldr");
            snprintf(out->ops, sizeof(out->ops), "%s, [pc, #0x%x]", arm_rn[rt], imm);
        }
    } else if (top4 == 5U) {
        static const char *const rls[8] = { "str","strh","strb","ldrsb","ldr","ldrh","ldrb","ldrsh" };
        unsigned op = (h1 >> 9) & 7U;
        unsigned rm = (h1 >> 6) & 7U;
        unsigned rn = (h1 >> 3) & 7U;
        unsigned rt = h1 & 7U;
        if (want_text) {
            snprintf(out->mnem, sizeof(out->mnem), "%s", rls[op]);
            snprintf(out->ops, sizeof(out->ops), "%s, [%s, %s]", arm_rn[rt], arm_rn[rn], arm_rn[rm]);
        }
    } else if (top4 >= 6U && top4 <= 8U) {
        static const char *const ils[3][2] = { {"str","ldr"}, {"strb","ldrb"}, {"strh","ldrh"} };
        static const unsigned sh[3] = { 2U, 0U, 1U };
        unsigned ld = (h1 >> 11) & 1U;
        uint32_t imm = ((h1 >> 6) & 31U) << sh[top4 - 6U];
        unsigned rn = (h1 >> 3) & 7U;
        unsigned rt = h1 & 7U;
        if (want_text) {
            snprintf(out->mnem, sizeof(out->mnem), "%s", ils[top4 - 6U][ld]);
            if (imm) snprintf(out->ops, sizeof(out->ops), "%s, [%s, #0x%x]", arm_rn[rt], arm_rn[rn], imm);
            else snprintf(out->ops, sizeof(out->ops), "%s, [%s]", arm_rn[rt], arm_rn[rn]);
        }
    } else if (top4 == 9U) {
        unsigned ld = (h1 >> 11) & 1U;
        unsigned rt = (h1 >> 8) & 7U;
        uint32_t imm = (h1 & 0xFFU) << 2;
        if (want_text) {
            snprintf(out->mnem, sizeof(out->mnem), "%s", ld ? "ldr" : "str");
            if (imm) snprintf(out->ops, sizeof(out->ops), "%s, [sp, #0x%x]", arm_rn[rt], imm);
            else snprintf(out->ops, sizeof(out->ops), "%s, [sp]", arm_rn[rt]);
        }
    } else if (top4 == 10U) {
        unsigned is_sp = (h1 >> 11) & 1U;
        unsigned rd = (h1 >> 8) & 7U;
        uint32_t imm = (h1 & 0xFFU) << 2;
        if (!is_sp) {
            out->target = ((pc + 4ULL) & ~3ULL) + (uint64_t)imm;
            out->has_target = 1;
            out->target_mem = 1;
            if (want_text) {
                snprintf(out->mnem, sizeof(out->mnem), "adr");
                snprintf(out->ops, sizeof(out->ops), "%s, 0x%llx", arm_rn[rd], (unsigned long long)out->target);
            }
        } else if (want_text) {
            snprintf(out->mnem, sizeof(out->mnem), "add");
            snprintf(out->ops, sizeof(out->ops), "%s, sp, #0x%x", arm_rn[rd], imm);
        }
    } else if (top4 == 11U) {
        if ((h1 & 0xFF00U) == 0xB000U) {
            if (want_text) {
                snprintf(out->mnem, sizeof(out->mnem), "%s", (h1 & 0x80U) ? "sub" : "add");
                snprintf(out->ops, sizeof(out->ops), "sp, #0x%x", (h1 & 0x7FU) << 2);
            }
        } else if ((h1 & 0xF500U) == 0xB100U) {
            unsigned nz = (h1 >> 11) & 1U;
            unsigned i = (h1 >> 9) & 1U;
            unsigned imm5 = (h1 >> 3) & 31U;
            unsigned rn = h1 & 7U;
            uint64_t off = (uint64_t)(((i << 5) | imm5) << 1);
            out->flow = X86_FLOW_JCC;
            out->target = pc + 4ULL + off;
            out->has_target = 1;
            if (want_text) {
                snprintf(out->mnem, sizeof(out->mnem), "%s", nz ? "cbnz" : "cbz");
                snprintf(out->ops, sizeof(out->ops), "%s, 0x%llx", arm_rn[rn], (unsigned long long)out->target);
            }
        } else if ((h1 & 0xFF00U) == 0xB200U) {
            static const char *const xm[4] = { "sxth","sxtb","uxth","uxtb" };
            if (want_text) {
                snprintf(out->mnem, sizeof(out->mnem), "%s", xm[(h1 >> 6) & 3U]);
                snprintf(out->ops, sizeof(out->ops), "%s, %s", arm_rn[h1 & 7U], arm_rn[(h1 >> 3) & 7U]);
            }
        } else if ((h1 & 0xF600U) == 0xB400U) {
            unsigned is_pop = (h1 >> 11) & 1U;
            unsigned m = (h1 >> 8) & 1U;
            uint16_t regs = (uint16_t)(h1 & 0xFFU);
            if (!is_pop && m) regs |= (uint16_t)(1U << 14);
            if (is_pop && m) {
                regs |= (uint16_t)(1U << 15);
                out->flow = X86_FLOW_RET;
            }
            if (want_text) {
                char list[68];
                arm_reglist(regs, list, sizeof(list));
                snprintf(out->mnem, sizeof(out->mnem), "%s", is_pop ? "pop" : "push");
                snprintf(out->ops, sizeof(out->ops), "%s", list);
            }
        } else if ((h1 & 0xFF00U) == 0xBA00U && ((h1 >> 6) & 3U) != 2U) {
            static const char *const rm_m[4] = { "rev","rev16",NULL,"revsh" };
            if (want_text) {
                snprintf(out->mnem, sizeof(out->mnem), "%s", rm_m[(h1 >> 6) & 3U]);
                snprintf(out->ops, sizeof(out->ops), "%s, %s", arm_rn[h1 & 7U], arm_rn[(h1 >> 3) & 7U]);
            }
        } else if ((h1 & 0xFF00U) == 0xBE00U) {
            out->flow = X86_FLOW_TRAP;
            if (want_text) {
                snprintf(out->mnem, sizeof(out->mnem), "bkpt");
                snprintf(out->ops, sizeof(out->ops), "#0x%x", h1 & 0xFFU);
            }
        } else if ((h1 & 0xFFE0U) == 0xB660U) {
            if (want_text) {
                char fl[4];
                int k = 0;
                if (h1 & 4U) fl[k++] = 'a';
                if (h1 & 2U) fl[k++] = 'i';
                if (h1 & 1U) fl[k++] = 'f';
                fl[k] = 0;
                snprintf(out->mnem, sizeof(out->mnem), "%s", (h1 & 0x10U) ? "cpsid" : "cpsie");
                snprintf(out->ops, sizeof(out->ops), "%s", fl);
            }
        } else if ((h1 & 0xFF00U) == 0xBF00U) {
            unsigned mask = h1 & 15U;
            unsigned fc = (h1 >> 4) & 15U;
            if (mask == 0U) {
                static const char *const hn[5] = { "nop","yield","wfe","wfi","sev" };
                if (want_text) {
                    if (fc < 5U) snprintf(out->mnem, sizeof(out->mnem), "%s", hn[fc]);
                    else { snprintf(out->mnem, sizeof(out->mnem), "hint"); snprintf(out->ops, sizeof(out->ops), "#0x%x", fc); }
                }
            } else if (want_text) {
                char itm[8] = "it";
                int pos = 2;
                int n = (mask & 1U) ? 3 : (mask & 2U) ? 2 : (mask & 4U) ? 1 : 0;
                for (int b = 0; b < n; b++) {
                    unsigned bit = (mask >> (3 - b)) & 1U;
                    itm[pos++] = (bit == (fc & 1U)) ? 't' : 'e';
                }
                itm[pos] = 0;
                snprintf(out->mnem, sizeof(out->mnem), "%s", itm);
                snprintf(out->ops, sizeof(out->ops), "%s", fc == 14U ? "al" : arm_cc[fc]);
            }
        } else if (want_text) {
            snprintf(out->mnem, sizeof(out->mnem), "t16");
            snprintf(out->ops, sizeof(out->ops), "0x%04x", h1);
        }
    } else if (top4 == 12U) {
        unsigned ld = (h1 >> 11) & 1U;
        unsigned rn = (h1 >> 8) & 7U;
        uint16_t regs = (uint16_t)(h1 & 0xFFU);
        if (want_text) {
            char list[48];
            arm_reglist(regs, list, sizeof(list));
            int wb = !ld || !((regs >> rn) & 1U);
            snprintf(out->mnem, sizeof(out->mnem), "%s", ld ? "ldmia" : "stmia");
            snprintf(out->ops, sizeof(out->ops), "%s%s, %s", arm_rn[rn], wb ? "!" : "", list);
        }
    } else if (top4 == 13U) {
        unsigned cond = (h1 >> 8) & 15U;
        unsigned imm8 = h1 & 0xFFU;
        if (cond == 14U || cond == 15U) {
            out->flow = X86_FLOW_TRAP;
            if (want_text) {
                snprintf(out->mnem, sizeof(out->mnem), "%s", cond == 15U ? "svc" : "udf");
                snprintf(out->ops, sizeof(out->ops), "#0x%x", imm8);
            }
        } else {
            out->flow = X86_FLOW_JCC;
            out->target = pc + 4ULL + (uint64_t)(m_sext(imm8, 8) << 1);
            out->has_target = 1;
            if (want_text) {
                snprintf(out->mnem, sizeof(out->mnem), "b%s", arm_cc[cond]);
                snprintf(out->ops, sizeof(out->ops), "0x%llx", (unsigned long long)out->target);
            }
        }
    } else if (top5 == 0x1CU) {
        out->flow = X86_FLOW_JMP;
        out->target = pc + 4ULL + (uint64_t)(m_sext(h1 & 0x7FFU, 11) << 1);
        out->has_target = 1;
        if (want_text) {
            snprintf(out->mnem, sizeof(out->mnem), "b");
            snprintf(out->ops, sizeof(out->ops), "0x%llx", (unsigned long long)out->target);
        }
    } else if (want_text) {
        snprintf(out->mnem, sizeof(out->mnem), "t16");
        snprintf(out->ops, sizeof(out->ops), "0x%04x", h1);
    }

    m_upper(out, want_text, upper);
    return 2;
}

int arm32_decode(const uint8_t *code, size_t avail, uint64_t ip, int want_text, int upper, x86_ins *out) {
    if (ip & 1ULL) return thumb_decode(code, avail, ip, want_text, upper, out);

    memset(out, 0, sizeof(*out));
    out->ip = ip;
    if (!code || avail < 4) return m_db(code, avail, want_text, upper, out);

    uint32_t w = m_u32(code);
    out->len = 4;
    int cond = (int)((w >> 28) & 15U);
    const char *cc = arm_cc[cond];

    if (w == 0xE320F000U || w == 0xE1A00000U) {
        if (want_text) snprintf(out->mnem, sizeof(out->mnem), "nop");
    } else if ((w & 0x0FFFFFF0U) == 0x0320F000U && (w & 15U) <= 4U) {
        static const char *const hn[5] = { "nop","yield","wfe","wfi","sev" };
        if (want_text) snprintf(out->mnem, sizeof(out->mnem), "%s%s", hn[w & 15U], cc);
    } else if (cond == 15 && w == 0xF57FF01FU) {
        if (want_text) snprintf(out->mnem, sizeof(out->mnem), "clrex");
    } else if (cond == 15 && ((w & 0xFFFFFFF0U) == 0xF57FF040U || (w & 0xFFFFFFF0U) == 0xF57FF050U || (w & 0xFFFFFFF0U) == 0xF57FF060U)) {
        if (want_text) {
            unsigned op = (w >> 4) & 15U;
            const char *opt = arm_barrier_opt(w & 15U);
            snprintf(out->mnem, sizeof(out->mnem), "%s", op == 4U ? "dsb" : op == 5U ? "dmb" : "isb");
            if (opt) snprintf(out->ops, sizeof(out->ops), "%s", opt);
            else snprintf(out->ops, sizeof(out->ops), "#0x%x", w & 15U);
        }
    } else if ((w & 0x0FFFFFF0U) == 0x012FFF10U) {
        int rm = (int)(w & 15U);
        out->flow = (rm == 14) ? X86_FLOW_RET : X86_FLOW_JMP;
        if (want_text) {
            snprintf(out->mnem, sizeof(out->mnem), "bx%s", cc);
            snprintf(out->ops, sizeof(out->ops), "%s", arm_rn[rm]);
        }
    } else if ((w & 0x0FFFFFF0U) == 0x012FFF30U) {
        int rm = (int)(w & 15U);
        out->flow = X86_FLOW_CALL;
        if (want_text) {
            snprintf(out->mnem, sizeof(out->mnem), "blx%s", cc);
            snprintf(out->ops, sizeof(out->ops), "%s", arm_rn[rm]);
        }
    } else if ((w & 0x0FFF0FF0U) == 0x016F0F10U) {
        if (want_text) {
            snprintf(out->mnem, sizeof(out->mnem), "clz%s", cc);
            snprintf(out->ops, sizeof(out->ops), "%s, %s", arm_rn[(w >> 12) & 15U], arm_rn[w & 15U]);
        }
    } else if ((w & 0x0FF000F0U) == 0x01200070U) {
        out->flow = X86_FLOW_TRAP;
        if (want_text) {
            uint32_t imm = (((w >> 8) & 0xFFFU) << 4) | (w & 15U);
            snprintf(out->mnem, sizeof(out->mnem), "bkpt");
            snprintf(out->ops, sizeof(out->ops), "#0x%x", imm);
        }
    } else if ((w & 0x0FF000F0U) == 0x07F000F0U && cond != 15) {
        out->flow = X86_FLOW_TRAP;
        if (want_text) {
            uint32_t imm = (((w >> 8) & 0xFFFU) << 4) | (w & 15U);
            snprintf(out->mnem, sizeof(out->mnem), "udf");
            snprintf(out->ops, sizeof(out->ops), "#0x%x", imm);
        }
    } else if ((w & 0x0FBF0FFFU) == 0x010F0000U && cond != 15) {
        if (want_text) {
            snprintf(out->mnem, sizeof(out->mnem), "mrs%s", cc);
            snprintf(out->ops, sizeof(out->ops), "%s, %s", arm_rn[(w >> 12) & 15U], ((w >> 22) & 1U) ? "spsr" : "apsr");
        }
    } else if ((w & 0x0FB0FFF0U) == 0x0120F000U && cond != 15) {
        if (want_text) {
            snprintf(out->mnem, sizeof(out->mnem), "msr%s", cc);
            snprintf(out->ops, sizeof(out->ops), "%s, %s", ((w >> 22) & 1U) ? "spsr" : "apsr", arm_rn[w & 15U]);
        }
    } else if ((w & 0x0F000000U) == 0x0F000000U && cond != 15) {
        out->flow = X86_FLOW_TRAP;
        if (want_text) {
            snprintf(out->mnem, sizeof(out->mnem), "svc%s", cc);
            snprintf(out->ops, sizeof(out->ops), "#0x%x", w & 0x00FFFFFFU);
        }
    } else if ((w & 0x0E000000U) == 0x0A000000U) {
        int link = (int)((w >> 24) & 1U);
        int64_t off = m_sext(w & 0x00FFFFFFU, 24) << 2;
        if (cond == 15) {
            off |= (int64_t)((uint64_t)link << 1);
            out->flow = X86_FLOW_CALL;
            out->target = ip + 8ULL + (uint64_t)off;
            out->has_target = 1;
            if (want_text) {
                snprintf(out->mnem, sizeof(out->mnem), "blx");
                snprintf(out->ops, sizeof(out->ops), "0x%llx", (unsigned long long)out->target);
            }
        } else {
            out->target = ip + 8ULL + (uint64_t)off;
            out->has_target = 1;
            out->flow = link ? X86_FLOW_CALL : (cond == 14 ? X86_FLOW_JMP : X86_FLOW_JCC);
            if (want_text) {
                snprintf(out->mnem, sizeof(out->mnem), "b%s%s", link ? "l" : "", cc);
                snprintf(out->ops, sizeof(out->ops), "0x%llx", (unsigned long long)out->target);
            }
        }
    } else if ((w & 0x0E000000U) == 0x08000000U && cond != 15) {
        arm_ldm_stm(w, cc, want_text, out);
    } else if ((w & 0x0C000000U) == 0x04000000U && (w & 0x0E000010U) != 0x06000010U && cond != 15) {
        arm_ldr_str(w, ip, cc, want_text, out);
    } else if ((w & 0x0E000010U) == 0x06000010U && cond != 15) {
        if ((w & 0x0FA00070U) == 0x07A00050U) {
            if (want_text) {
                unsigned is_u = (w >> 22) & 1U;
                unsigned width = ((w >> 16) & 31U) + 1U;
                unsigned rd = (w >> 12) & 15U;
                unsigned lsb = (w >> 7) & 31U;
                unsigned rn = w & 15U;
                snprintf(out->mnem, sizeof(out->mnem), "%s%s", is_u ? "ubfx" : "sbfx", cc);
                snprintf(out->ops, sizeof(out->ops), "%s, %s, #%u, #%u", arm_rn[rd], arm_rn[rn], lsb, width);
            }
        } else if ((w & 0x0FE00070U) == 0x07C00010U) {
            if (want_text) {
                unsigned msb = (w >> 16) & 31U;
                unsigned rd = (w >> 12) & 15U;
                unsigned lsb = (w >> 7) & 31U;
                unsigned rn = w & 15U;
                unsigned width = (msb >= lsb) ? (msb - lsb + 1U) : 1U;
                if (rn == 15U) {
                    snprintf(out->mnem, sizeof(out->mnem), "bfc%s", cc);
                    snprintf(out->ops, sizeof(out->ops), "%s, #%u, #%u", arm_rn[rd], lsb, width);
                } else {
                    snprintf(out->mnem, sizeof(out->mnem), "bfi%s", cc);
                    snprintf(out->ops, sizeof(out->ops), "%s, %s, #%u, #%u", arm_rn[rd], arm_rn[rn], lsb, width);
                }
            }
        } else if ((w & 0x0FBF0F70U) == 0x06BF0F30U) {
            if (want_text) {
                unsigned b22 = (w >> 22) & 1U;
                unsigned b7 = (w >> 7) & 1U;
                const char *mn = (!b22 && !b7) ? "rev" : (!b22 && b7) ? "rev16" : (b22 && !b7) ? "rbit" : "revsh";
                snprintf(out->mnem, sizeof(out->mnem), "%s%s", mn, cc);
                snprintf(out->ops, sizeof(out->ops), "%s, %s", arm_rn[(w >> 12) & 15U], arm_rn[w & 15U]);
            }
        } else if ((w & 0x0FD0F0F0U) == 0x0710F010U) {
            if (want_text) {
                snprintf(out->mnem, sizeof(out->mnem), "%s%s", ((w >> 21) & 1U) ? "udiv" : "sdiv", cc);
                snprintf(out->ops, sizeof(out->ops), "%s, %s, %s", arm_rn[(w >> 16) & 15U], arm_rn[w & 15U], arm_rn[(w >> 8) & 15U]);
            }
        } else if ((w & 0x0FA00070U) == 0x06A00070U) {
            if (want_text) {
                unsigned u = (w >> 22) & 1U;
                unsigned b = (w >> 20) & 1U;
                unsigned rn = (w >> 16) & 15U;
                unsigned rd = (w >> 12) & 15U;
                unsigned rm = w & 15U;
                if (rn == 15U) {
                    snprintf(out->mnem, sizeof(out->mnem), "%cxt%c%s", u ? 'u' : 's', b ? 'h' : 'b', cc);
                    snprintf(out->ops, sizeof(out->ops), "%s, %s", arm_rn[rd], arm_rn[rm]);
                } else {
                    snprintf(out->mnem, sizeof(out->mnem), "%cxta%c%s", u ? 'u' : 's', b ? 'h' : 'b', cc);
                    snprintf(out->ops, sizeof(out->ops), "%s, %s, %s", arm_rn[rd], arm_rn[rn], arm_rn[rm]);
                }
            }
        } else if ((w & 0x0FF00030U) == 0x06800010U) {
            if (want_text) {
                snprintf(out->mnem, sizeof(out->mnem), "%s%s", ((w >> 6) & 1U) ? "pkhtb" : "pkhbt", cc);
                snprintf(out->ops, sizeof(out->ops), "%s, %s, %s", arm_rn[(w >> 12) & 15U], arm_rn[(w >> 16) & 15U], arm_rn[w & 15U]);
            }
        } else if (want_text) {
            snprintf(out->mnem, sizeof(out->mnem), "arm");
            snprintf(out->ops, sizeof(out->ops), "0x%08x", w);
        }
    } else if ((w & 0x0FC000F0U) == 0x00000090U && cond != 15) {
        if (want_text) {
            int acc = (int)((w >> 21) & 1U);
            int s = (int)((w >> 20) & 1U);
            int rd = (int)((w >> 16) & 15U);
            int rn = (int)((w >> 12) & 15U);
            int rs = (int)((w >> 8) & 15U);
            int rm = (int)(w & 15U);
            snprintf(out->mnem, sizeof(out->mnem), "%s%s%s", acc ? "mla" : "mul", s ? "s" : "", cc);
            if (acc) snprintf(out->ops, sizeof(out->ops), "%s, %s, %s, %s", arm_rn[rd], arm_rn[rm], arm_rn[rs], arm_rn[rn]);
            else snprintf(out->ops, sizeof(out->ops), "%s, %s, %s", arm_rn[rd], arm_rn[rm], arm_rn[rs]);
        }
    } else if ((w & 0x0FF000F0U) == 0x00600090U && cond != 15) {
        if (want_text) {
            snprintf(out->mnem, sizeof(out->mnem), "mls%s", cc);
            snprintf(out->ops, sizeof(out->ops), "%s, %s, %s, %s",
                     arm_rn[(w >> 16) & 15U], arm_rn[w & 15U], arm_rn[(w >> 8) & 15U], arm_rn[(w >> 12) & 15U]);
        }
    } else if ((w & 0x0F8000F0U) == 0x00800090U && cond != 15) {
        if (want_text) {
            int sgn = (int)((w >> 22) & 1U);
            int acc = (int)((w >> 21) & 1U);
            int s = (int)((w >> 20) & 1U);
            int rdhi = (int)((w >> 16) & 15U);
            int rdlo = (int)((w >> 12) & 15U);
            int rm = (int)((w >> 8) & 15U);
            int rn = (int)(w & 15U);
            snprintf(out->mnem, sizeof(out->mnem), "%c%s%s%s", sgn ? 's' : 'u', acc ? "mlal" : "mull", s ? "s" : "", cc);
            snprintf(out->ops, sizeof(out->ops), "%s, %s, %s, %s", arm_rn[rdlo], arm_rn[rdhi], arm_rn[rn], arm_rn[rm]);
        }
    } else if ((w & 0x0F8000F0U) == 0x01800090U && cond != 15) {
        if (want_text) {
            static const char *const exsz[4] = { "", "d", "b", "h" };
            unsigned sz = (w >> 21) & 3U;
            unsigned ld = (w >> 20) & 1U;
            unsigned rn = (w >> 16) & 15U;
            unsigned rt = (w >> 12) & 15U;
            unsigned rm = w & 15U;
            snprintf(out->mnem, sizeof(out->mnem), "%s%s%s", ld ? "ldrex" : "strex", exsz[sz], cc);
            if (ld) snprintf(out->ops, sizeof(out->ops), "%s, [%s]", arm_rn[rt], arm_rn[rn]);
            else snprintf(out->ops, sizeof(out->ops), "%s, %s, [%s]", arm_rn[rt], arm_rn[rm], arm_rn[rn]);
        }
    } else if ((w & 0x0E000090U) == 0x00000090U && (w & 0x60U) != 0U && cond != 15) {
        arm_ldst_extra(w, ip, cc, want_text, out);
    } else if ((w & 0x0FB00000U) == 0x03000000U && cond != 15) {
        if (want_text) {
            int top = (int)((w >> 22) & 1U);
            int rd = (int)((w >> 12) & 15U);
            uint32_t imm = (((w >> 16) & 15U) << 12) | (w & 0xFFFU);
            snprintf(out->mnem, sizeof(out->mnem), "%s%s", top ? "movt" : "movw", cc);
            snprintf(out->ops, sizeof(out->ops), "%s, #0x%x", arm_rn[rd], imm);
        }
    } else if ((w & 0x0C000000U) == 0x00000000U && cond != 15 &&
               (((w >> 25) & 1U) || (w & 0x90U) != 0x90U) &&
               !((((w >> 21) & 15U) >= 8U && ((w >> 21) & 15U) <= 11U) && ((w >> 20) & 1U) == 0U)) {
        arm_dp(w, cc, want_text, out);
    } else if (cond != 15 && arm_vfp_decode(w, (ip + 8ULL) & ~3ULL, cc, want_text, out)) {
        // decoded by VFP
    } else if ((w & 0x0F000010U) == 0x0E000010U && cond != 15) {
        if (want_text) {
            unsigned ld = (w >> 20) & 1U;
            unsigned opc1 = (w >> 21) & 7U;
            unsigned crn = (w >> 16) & 15U;
            unsigned rt = (w >> 12) & 15U;
            unsigned cp = (w >> 8) & 15U;
            unsigned opc2 = (w >> 5) & 7U;
            unsigned crm = w & 15U;
            snprintf(out->mnem, sizeof(out->mnem), "%s%s", ld ? "mrc" : "mcr", cc);
            snprintf(out->ops, sizeof(out->ops), "p%u, %u, %s, c%u, c%u, %u", cp, opc1, arm_rn[rt], crn, crm, opc2);
        }
    } else if (want_text) {
        snprintf(out->mnem, sizeof(out->mnem), "arm");
        snprintf(out->ops, sizeof(out->ops), "0x%08x", w);
    }

    m_upper(out, want_text, upper);
    return 4;
}

static const char *const rv_rn[32] = {
    "zero","ra","sp","gp","tp","t0","t1","t2",
    "s0","s1","a0","a1","a2","a3","a4","a5",
    "a6","a7","s2","s3","s4","s5","s6","s7",
    "s8","s9","s10","s11","t3","t4","t5","t6"
};

static int64_t rvc_j_imm(uint16_t c) {
    uint64_t u = (((uint64_t)(c >> 3) & 7U) << 1)
               | (((uint64_t)(c >> 11) & 1U) << 4)
               | (((uint64_t)(c >> 2) & 1U) << 5)
               | (((uint64_t)(c >> 7) & 1U) << 6)
               | (((uint64_t)(c >> 6) & 1U) << 7)
               | (((uint64_t)(c >> 9) & 3U) << 8)
               | (((uint64_t)(c >> 8) & 1U) << 10)
               | (((uint64_t)(c >> 12) & 1U) << 11);
    return m_sext(u, 12);
}

static int64_t rvc_b_imm(uint16_t c) {
    uint64_t u = (((uint64_t)(c >> 3) & 3U) << 1)
               | (((uint64_t)(c >> 10) & 3U) << 3)
               | (((uint64_t)(c >> 2) & 1U) << 5)
               | (((uint64_t)(c >> 5) & 3U) << 6)
               | (((uint64_t)(c >> 12) & 1U) << 8);
    return m_sext(u, 9);
}

static void rv_decode_c(uint16_t c, uint64_t ip, int bits, int want_text, x86_ins *out) {
    unsigned q = c & 3U;
    unsigned f3 = (c >> 13) & 7U;
    unsigned rdp = 8U + ((c >> 2) & 7U);
    unsigned rs1p = 8U + ((c >> 7) & 7U);

    if (q == 0) {
        if (f3 == 0) {
            unsigned imm = (((c >> 6) & 1U) << 2) | (((c >> 5) & 1U) << 3)
                         | (((c >> 11) & 3U) << 4) | (((c >> 7) & 15U) << 6);
            if (want_text) {
                if (imm) {
                    snprintf(out->mnem, sizeof(out->mnem), "c.addi4spn");
                    snprintf(out->ops, sizeof(out->ops), "%s, sp, %u", rv_rn[rdp], imm);
                } else {
                    snprintf(out->mnem, sizeof(out->mnem), "c.unimp");
                }
            }
        } else if (f3 == 1 || f3 == 5) {
            unsigned imm = (((c >> 10) & 7U) << 3) | (((c >> 5) & 3U) << 6);
            if (want_text) {
                snprintf(out->mnem, sizeof(out->mnem), "%s", f3 == 1 ? "c.fld" : "c.fsd");
                snprintf(out->ops, sizeof(out->ops), "f%u, %u(%s)", rdp, imm, rv_rn[rs1p]);
            }
        } else if (f3 == 2 || f3 == 6) {
            unsigned imm = (((c >> 6) & 1U) << 2) | (((c >> 10) & 7U) << 3) | (((c >> 5) & 1U) << 6);
            if (want_text) {
                snprintf(out->mnem, sizeof(out->mnem), "%s", f3 == 2 ? "c.lw" : "c.sw");
                snprintf(out->ops, sizeof(out->ops), "%s, %u(%s)", rv_rn[rdp], imm, rv_rn[rs1p]);
            }
        } else if (f3 == 3 || f3 == 7) {
            if (bits == 64) {
                unsigned imm = (((c >> 10) & 7U) << 3) | (((c >> 5) & 3U) << 6);
                if (want_text) {
                    snprintf(out->mnem, sizeof(out->mnem), "%s", f3 == 3 ? "c.ld" : "c.sd");
                    snprintf(out->ops, sizeof(out->ops), "%s, %u(%s)", rv_rn[rdp], imm, rv_rn[rs1p]);
                }
            } else {
                unsigned imm = (((c >> 6) & 1U) << 2) | (((c >> 10) & 7U) << 3) | (((c >> 5) & 1U) << 6);
                if (want_text) {
                    snprintf(out->mnem, sizeof(out->mnem), "%s", f3 == 3 ? "c.flw" : "c.fsw");
                    snprintf(out->ops, sizeof(out->ops), "f%u, %u(%s)", rdp, imm, rv_rn[rs1p]);
                }
            }
        } else if (want_text) {
            snprintf(out->mnem, sizeof(out->mnem), "rvc");
            snprintf(out->ops, sizeof(out->ops), "0x%04x", c);
        }
        return;
    }

    if (q == 1) {
        unsigned rd = (c >> 7) & 31U;
        int64_t imm6 = m_sext((((uint64_t)(c >> 12) & 1U) << 5) | ((c >> 2) & 31U), 6);
        if (f3 == 0) {
            if (!want_text) return;
            if (c == 0x0001U || (rd == 0 && imm6 == 0)) {
                snprintf(out->mnem, sizeof(out->mnem), "c.nop");
            } else {
                snprintf(out->mnem, sizeof(out->mnem), "c.addi");
                snprintf(out->ops, sizeof(out->ops), "%s, %lld", rv_rn[rd], (long long)imm6);
            }
        } else if (f3 == 1) {
            if (bits == 32) {
                out->flow = X86_FLOW_CALL;
                out->target = ip + (uint64_t)rvc_j_imm(c);
                out->has_target = 1;
                if (want_text) {
                    snprintf(out->mnem, sizeof(out->mnem), "c.jal");
                    snprintf(out->ops, sizeof(out->ops), "0x%llx", (unsigned long long)out->target);
                }
            } else if (want_text) {
                snprintf(out->mnem, sizeof(out->mnem), "c.addiw");
                snprintf(out->ops, sizeof(out->ops), "%s, %lld", rv_rn[rd], (long long)imm6);
            }
        } else if (f3 == 2) {
            if (want_text) {
                snprintf(out->mnem, sizeof(out->mnem), "c.li");
                snprintf(out->ops, sizeof(out->ops), "%s, %lld", rv_rn[rd], (long long)imm6);
            }
        } else if (f3 == 3) {
            if (!want_text) return;
            if (rd == 2) {
                uint64_t u = (((uint64_t)(c >> 6) & 1U) << 4) | (((uint64_t)(c >> 2) & 1U) << 5)
                           | (((uint64_t)(c >> 5) & 1U) << 6) | (((uint64_t)(c >> 3) & 3U) << 7)
                           | (((uint64_t)(c >> 12) & 1U) << 9);
                snprintf(out->mnem, sizeof(out->mnem), "c.addi16sp");
                snprintf(out->ops, sizeof(out->ops), "sp, %lld", (long long)m_sext(u, 10));
            } else {
                uint32_t hi = (uint32_t)((uint64_t)imm6 & 0xFFFFFU);
                snprintf(out->mnem, sizeof(out->mnem), "c.lui");
                snprintf(out->ops, sizeof(out->ops), "%s, 0x%x", rv_rn[rd], hi);
            }
        } else if (f3 == 4) {
            if (!want_text) return;
            unsigned sub = (c >> 10) & 3U;
            unsigned sh = (((c >> 12) & 1U) << 5) | ((c >> 2) & 31U);
            if (sub == 0 || sub == 1) {
                snprintf(out->mnem, sizeof(out->mnem), "%s", sub ? "c.srai" : "c.srli");
                snprintf(out->ops, sizeof(out->ops), "%s, %u", rv_rn[rs1p], sh);
            } else if (sub == 2) {
                snprintf(out->mnem, sizeof(out->mnem), "c.andi");
                snprintf(out->ops, sizeof(out->ops), "%s, %lld", rv_rn[rs1p], (long long)imm6);
            } else {
                static const char *const alu[8] = {
                    "c.sub","c.xor","c.or","c.and","c.subw","c.addw","rvc","rvc"
                };
                unsigned op = (((c >> 12) & 1U) << 2) | ((c >> 5) & 3U);
                snprintf(out->mnem, sizeof(out->mnem), "%s", alu[op]);
                snprintf(out->ops, sizeof(out->ops), "%s, %s", rv_rn[rs1p], rv_rn[rdp]);
            }
        } else if (f3 == 5) {
            out->flow = X86_FLOW_JMP;
            out->target = ip + (uint64_t)rvc_j_imm(c);
            out->has_target = 1;
            if (want_text) {
                snprintf(out->mnem, sizeof(out->mnem), "c.j");
                snprintf(out->ops, sizeof(out->ops), "0x%llx", (unsigned long long)out->target);
            }
        } else if (f3 == 6 || f3 == 7) {
            out->flow = X86_FLOW_JCC;
            out->target = ip + (uint64_t)rvc_b_imm(c);
            out->has_target = 1;
            if (want_text) {
                snprintf(out->mnem, sizeof(out->mnem), "%s", f3 == 6 ? "c.beqz" : "c.bnez");
                snprintf(out->ops, sizeof(out->ops), "%s, 0x%llx", rv_rn[rs1p], (unsigned long long)out->target);
            }
        }
        return;
    }

    unsigned rd = (c >> 7) & 31U;
    unsigned rs2 = (c >> 2) & 31U;
    if (f3 == 0) {
        if (want_text) {
            unsigned sh = (((c >> 12) & 1U) << 5) | rs2;
            snprintf(out->mnem, sizeof(out->mnem), "c.slli");
            snprintf(out->ops, sizeof(out->ops), "%s, %u", rv_rn[rd], sh);
        }
    } else if (f3 == 1) {
        if (want_text) {
            unsigned imm = (((c >> 5) & 3U) << 3) | (((c >> 12) & 1U) << 5) | (((c >> 2) & 7U) << 6);
            snprintf(out->mnem, sizeof(out->mnem), "c.fldsp");
            snprintf(out->ops, sizeof(out->ops), "f%u, %u(sp)", rd, imm);
        }
    } else if (f3 == 2) {
        if (want_text) {
            unsigned imm = (((c >> 4) & 7U) << 2) | (((c >> 12) & 1U) << 5) | (((c >> 2) & 3U) << 6);
            snprintf(out->mnem, sizeof(out->mnem), "c.lwsp");
            snprintf(out->ops, sizeof(out->ops), "%s, %u(sp)", rv_rn[rd], imm);
        }
    } else if (f3 == 3) {
        if (want_text) {
            if (bits == 64) {
                unsigned imm = (((c >> 5) & 3U) << 3) | (((c >> 12) & 1U) << 5) | (((c >> 2) & 7U) << 6);
                snprintf(out->mnem, sizeof(out->mnem), "c.ldsp");
                snprintf(out->ops, sizeof(out->ops), "%s, %u(sp)", rv_rn[rd], imm);
            } else {
                unsigned imm = (((c >> 4) & 7U) << 2) | (((c >> 12) & 1U) << 5) | (((c >> 2) & 3U) << 6);
                snprintf(out->mnem, sizeof(out->mnem), "c.flwsp");
                snprintf(out->ops, sizeof(out->ops), "f%u, %u(sp)", rd, imm);
            }
        }
    } else if (f3 == 4) {
        unsigned b12 = (c >> 12) & 1U;
        if (!b12) {
            if (rs2 == 0) {
                if (c == 0x8082U) {
                    out->flow = X86_FLOW_RET;
                    if (want_text) snprintf(out->mnem, sizeof(out->mnem), "c.ret");
                } else if (rd != 0) {
                    out->flow = X86_FLOW_JMP;
                    if (want_text) {
                        snprintf(out->mnem, sizeof(out->mnem), "c.jr");
                        snprintf(out->ops, sizeof(out->ops), "%s", rv_rn[rd]);
                    }
                }
            } else if (want_text) {
                snprintf(out->mnem, sizeof(out->mnem), "c.mv");
                snprintf(out->ops, sizeof(out->ops), "%s, %s", rv_rn[rd], rv_rn[rs2]);
            }
        } else {
            if (rd == 0 && rs2 == 0) {
                out->flow = X86_FLOW_TRAP;
                if (want_text) snprintf(out->mnem, sizeof(out->mnem), "c.ebreak");
            } else if (rs2 == 0) {
                out->flow = X86_FLOW_CALL;
                if (want_text) {
                    snprintf(out->mnem, sizeof(out->mnem), "c.jalr");
                    snprintf(out->ops, sizeof(out->ops), "%s", rv_rn[rd]);
                }
            } else if (want_text) {
                snprintf(out->mnem, sizeof(out->mnem), "c.add");
                snprintf(out->ops, sizeof(out->ops), "%s, %s", rv_rn[rd], rv_rn[rs2]);
            }
        }
    } else if (f3 == 5) {
        if (want_text) {
            unsigned imm = (((c >> 10) & 7U) << 3) | (((c >> 7) & 7U) << 6);
            snprintf(out->mnem, sizeof(out->mnem), "c.fsdsp");
            snprintf(out->ops, sizeof(out->ops), "f%u, %u(sp)", rs2, imm);
        }
    } else if (f3 == 6) {
        if (want_text) {
            unsigned imm = (((c >> 9) & 15U) << 2) | (((c >> 7) & 3U) << 6);
            snprintf(out->mnem, sizeof(out->mnem), "c.swsp");
            snprintf(out->ops, sizeof(out->ops), "%s, %u(sp)", rv_rn[rs2], imm);
        }
    } else if (f3 == 7) {
        if (want_text) {
            if (bits == 64) {
                unsigned imm = (((c >> 10) & 7U) << 3) | (((c >> 7) & 7U) << 6);
                snprintf(out->mnem, sizeof(out->mnem), "c.sdsp");
                snprintf(out->ops, sizeof(out->ops), "%s, %u(sp)", rv_rn[rs2], imm);
            } else {
                unsigned imm = (((c >> 9) & 15U) << 2) | (((c >> 7) & 3U) << 6);
                snprintf(out->mnem, sizeof(out->mnem), "c.fswsp");
                snprintf(out->ops, sizeof(out->ops), "f%u, %u(sp)", rs2, imm);
            }
        }
    } else if (want_text) {
        snprintf(out->mnem, sizeof(out->mnem), "rvc");
        snprintf(out->ops, sizeof(out->ops), "0x%04x", c);
    }
}

static void rv_decode_32(uint32_t w, uint64_t ip, int bits, int want_text, x86_ins *out) {
    unsigned opc = w & 0x7FU;
    unsigned rd = (w >> 7) & 31U;
    unsigned f3 = (w >> 12) & 7U;
    unsigned rs1 = (w >> 15) & 31U;
    unsigned rs2 = (w >> 20) & 31U;
    unsigned f7 = (w >> 25) & 0x7FU;

    int64_t i_imm = m_sext(w >> 20, 12);
    int64_t s_imm = m_sext((((uint64_t)f7) << 5) | rd, 12);

    if (opc == 0x37U || opc == 0x17U) {
        if (opc == 0x17U) {
            out->target = ip + (uint64_t)(int64_t)(int32_t)(w & 0xFFFFF000U);
            out->has_target = 1;
            out->target_mem = 1;
        }
        if (want_text) {
            snprintf(out->mnem, sizeof(out->mnem), "%s", opc == 0x37U ? "lui" : "auipc");
            snprintf(out->ops, sizeof(out->ops), "%s, 0x%x", rv_rn[rd], w >> 12);
        }
    } else if (opc == 0x6FU) {
        uint64_t u = (((uint64_t)(w >> 21) & 0x3FFU) << 1)
                   | (((uint64_t)(w >> 20) & 1U) << 11)
                   | (((uint64_t)(w >> 12) & 0xFFU) << 12)
                   | (((uint64_t)(w >> 31) & 1U) << 20);
        out->target = ip + (uint64_t)m_sext(u, 21);
        out->has_target = 1;
        out->flow = (rd == 0) ? X86_FLOW_JMP : X86_FLOW_CALL;
        if (want_text) {
            if (rd == 0) {
                snprintf(out->mnem, sizeof(out->mnem), "j");
                snprintf(out->ops, sizeof(out->ops), "0x%llx", (unsigned long long)out->target);
            } else if (rd == 1) {
                snprintf(out->mnem, sizeof(out->mnem), "call");
                snprintf(out->ops, sizeof(out->ops), "0x%llx", (unsigned long long)out->target);
            } else {
                snprintf(out->mnem, sizeof(out->mnem), "jal");
                snprintf(out->ops, sizeof(out->ops), "%s, 0x%llx", rv_rn[rd], (unsigned long long)out->target);
            }
        }
    } else if (opc == 0x67U && f3 == 0) {
        if (rd == 0 && rs1 == 1 && i_imm == 0) {
            out->flow = X86_FLOW_RET;
            if (want_text) snprintf(out->mnem, sizeof(out->mnem), "ret");
        } else if (rd == 0) {
            out->flow = X86_FLOW_JMP;
            if (want_text) {
                if (i_imm == 0) {
                    snprintf(out->mnem, sizeof(out->mnem), "jr");
                    snprintf(out->ops, sizeof(out->ops), "%s", rv_rn[rs1]);
                } else {
                    snprintf(out->mnem, sizeof(out->mnem), "jalr");
                    snprintf(out->ops, sizeof(out->ops), "zero, %lld(%s)", (long long)i_imm, rv_rn[rs1]);
                }
            }
        } else {
            out->flow = X86_FLOW_CALL;
            if (want_text) {
                snprintf(out->mnem, sizeof(out->mnem), "jalr");
                if (rd == 1 && i_imm == 0) snprintf(out->ops, sizeof(out->ops), "%s", rv_rn[rs1]);
                else snprintf(out->ops, sizeof(out->ops), "%s, %lld(%s)", rv_rn[rd], (long long)i_imm, rv_rn[rs1]);
            }
        }
    } else if (opc == 0x63U) {
        static const char *const br[8] = {"beq","bne",NULL,NULL,"blt","bge","bltu","bgeu"};
        if (br[f3]) {
            uint64_t u = (((uint64_t)(w >> 8) & 0xFU) << 1)
                       | (((uint64_t)(w >> 25) & 0x3FU) << 5)
                       | (((uint64_t)(w >> 7) & 1U) << 11)
                       | (((uint64_t)(w >> 31) & 1U) << 12);
            out->target = ip + (uint64_t)m_sext(u, 13);
            out->has_target = 1;
            out->flow = X86_FLOW_JCC;
            if (want_text) {
                snprintf(out->mnem, sizeof(out->mnem), "%s", br[f3]);
                snprintf(out->ops, sizeof(out->ops), "%s, %s, 0x%llx", rv_rn[rs1], rv_rn[rs2], (unsigned long long)out->target);
            }
        }
    } else if (opc == 0x03U) {
        static const char *const ld[8] = {"lb","lh","lw","ld","lbu","lhu","lwu",NULL};
        if (want_text && ld[f3]) {
            snprintf(out->mnem, sizeof(out->mnem), "%s", ld[f3]);
            snprintf(out->ops, sizeof(out->ops), "%s, %lld(%s)", rv_rn[rd], (long long)i_imm, rv_rn[rs1]);
        }
    } else if (opc == 0x23U) {
        static const char *const st[8] = {"sb","sh","sw","sd",NULL,NULL,NULL,NULL};
        if (want_text && st[f3]) {
            snprintf(out->mnem, sizeof(out->mnem), "%s", st[f3]);
            snprintf(out->ops, sizeof(out->ops), "%s, %lld(%s)", rv_rn[rs2], (long long)s_imm, rv_rn[rs1]);
        }
    } else if (opc == 0x07U || opc == 0x27U) {
        if (want_text && (f3 == 2 || f3 == 3)) {
            int is_st = (opc == 0x27U);
            snprintf(out->mnem, sizeof(out->mnem), "%s%c", is_st ? "fs" : "fl", f3 == 2 ? 'w' : 'd');
            snprintf(out->ops, sizeof(out->ops), "f%u, %lld(%s)", is_st ? rs2 : rd, (long long)(is_st ? s_imm : i_imm), rv_rn[rs1]);
        }
    } else if (opc == 0x2FU) {
        // RV32A / RV64A Atomic extension
        if (want_text && (f3 == 2U || f3 == 3U)) {
            unsigned f5 = f7 >> 2;
            unsigned aq = (f7 >> 1) & 1U;
            unsigned rl = f7 & 1U;
            const char *ws = (f3 == 2U) ? ".w" : ".d";
            const char *ord = (aq && rl) ? ".aqrl" : aq ? ".aq" : rl ? ".rl" : "";
            const char *mn = NULL;
            switch (f5) {
            case 0x00U: mn = "amoadd";  break;
            case 0x01U: mn = "amoswap"; break;
            case 0x02U: mn = "lr";      break;
            case 0x03U: mn = "sc";      break;
            case 0x04U: mn = "amoxor";  break;
            case 0x08U: mn = "amoor";   break;
            case 0x0CU: mn = "amoand";  break;
            case 0x10U: mn = "amomin";  break;
            case 0x14U: mn = "amomax";  break;
            case 0x18U: mn = "amominu"; break;
            case 0x1CU: mn = "amomaxu"; break;
            default: break;
            }
            if (mn) {
                snprintf(out->mnem, sizeof(out->mnem), "%s%s%s", mn, ws, ord);
                if (f5 == 0x02U) snprintf(out->ops, sizeof(out->ops), "%s, (%s)", rv_rn[rd], rv_rn[rs1]);
                else snprintf(out->ops, sizeof(out->ops), "%s, %s, (%s)", rv_rn[rd], rv_rn[rs2], rv_rn[rs1]);
            }
        }
    } else if (opc == 0x43U || opc == 0x47U || opc == 0x4BU || opc == 0x4FU) {
        // RV F/D Fused Multiply-Add
        unsigned fmt = f7 & 3U;
        if (want_text && fmt <= 1U) {
            unsigned rs3 = f7 >> 2;
            const char *mn = (opc == 0x43U) ? "fmadd" : (opc == 0x47U) ? "fmsub" : (opc == 0x4BU) ? "fnmsub" : "fnmadd";
            snprintf(out->mnem, sizeof(out->mnem), "%s.%c", mn, fmt ? 'd' : 's');
            snprintf(out->ops, sizeof(out->ops), "f%u, f%u, f%u, f%u", rd, rs1, rs2, rs3);
        }
    } else if (opc == 0x53U) {
        // RV F/D OP-FP
        unsigned fmt = f7 & 3U;
        unsigned f5 = f7 >> 2;
        if (want_text && fmt <= 1U) {
            char fc = fmt ? 'd' : 's';
            if (f5 <= 3U) {
                static const char *const fp2[4] = { "fadd","fsub","fmul","fdiv" };
                snprintf(out->mnem, sizeof(out->mnem), "%s.%c", fp2[f5], fc);
                snprintf(out->ops, sizeof(out->ops), "f%u, f%u, f%u", rd, rs1, rs2);
            } else if (f5 == 0x0BU && rs2 == 0U) {
                snprintf(out->mnem, sizeof(out->mnem), "fsqrt.%c", fc);
                snprintf(out->ops, sizeof(out->ops), "f%u, f%u", rd, rs1);
            } else if (f5 == 0x04U && f3 <= 2U) {
                static const char *const sg[3] = { "fsgnj","fsgnjn","fsgnjx" };
                static const char *const sga[3] = { "fmv","fneg","fabs" };
                if (rs1 == rs2) {
                    snprintf(out->mnem, sizeof(out->mnem), "%s.%c", sga[f3], fc);
                    snprintf(out->ops, sizeof(out->ops), "f%u, f%u", rd, rs1);
                } else {
                    snprintf(out->mnem, sizeof(out->mnem), "%s.%c", sg[f3], fc);
                    snprintf(out->ops, sizeof(out->ops), "f%u, f%u, f%u", rd, rs1, rs2);
                }
            } else if (f5 == 0x05U && f3 <= 1U) {
                snprintf(out->mnem, sizeof(out->mnem), "%s.%c", f3 ? "fmax" : "fmin", fc);
                snprintf(out->ops, sizeof(out->ops), "f%u, f%u, f%u", rd, rs1, rs2);
            } else if (f5 == 0x08U && ((fmt == 0U && rs2 == 1U) || (fmt == 1U && rs2 == 0U))) {
                snprintf(out->mnem, sizeof(out->mnem), "fcvt.%c.%c", fc, fmt ? 's' : 'd');
                snprintf(out->ops, sizeof(out->ops), "f%u, f%u", rd, rs1);
            } else if (f5 == 0x14U && f3 <= 2U) {
                static const char *const fc_m[3] = { "fle","flt","feq" };
                snprintf(out->mnem, sizeof(out->mnem), "%s.%c", fc_m[f3], fc);
                snprintf(out->ops, sizeof(out->ops), "%s, f%u, f%u", rv_rn[rd], rs1, rs2);
            } else if ((f5 == 0x18U || f5 == 0x1AU) && rs2 <= 3U) {
                static const char *const cv[4] = { "w","wu","l","lu" };
                if (f5 == 0x18U) {
                    snprintf(out->mnem, sizeof(out->mnem), "fcvt.%s.%c", cv[rs2], fc);
                    snprintf(out->ops, sizeof(out->ops), "%s, f%u", rv_rn[rd], rs1);
                } else {
                    snprintf(out->mnem, sizeof(out->mnem), "fcvt.%c.%s", fc, cv[rs2]);
                    snprintf(out->ops, sizeof(out->ops), "f%u, %s", rd, rv_rn[rs1]);
                }
            } else if (f5 == 0x1CU && rs2 == 0U && f3 <= 1U) {
                if (f3 == 0U) {
                    snprintf(out->mnem, sizeof(out->mnem), "fmv.x.%c", fmt ? 'd' : 'w');
                    snprintf(out->ops, sizeof(out->ops), "%s, f%u", rv_rn[rd], rs1);
                } else {
                    snprintf(out->mnem, sizeof(out->mnem), "fclass.%c", fc);
                    snprintf(out->ops, sizeof(out->ops), "%s, f%u", rv_rn[rd], rs1);
                }
            } else if (f5 == 0x1EU && rs2 == 0U && f3 == 0U) {
                snprintf(out->mnem, sizeof(out->mnem), "fmv.%c.x", fmt ? 'd' : 'w');
                snprintf(out->ops, sizeof(out->ops), "f%u, %s", rd, rv_rn[rs1]);
            }
        }
    } else if (opc == 0x13U) {
        if (!want_text) return;
        if (w == 0x00000013U) {
            snprintf(out->mnem, sizeof(out->mnem), "nop");
            return;
        }
        static const char *const oi[8] = {"addi","slli","slti","sltiu","xori","srli","ori","andi"};
        const char *mn = (f3 == 5 && (w & 0x40000000U)) ? "srai" : oi[f3];
        snprintf(out->mnem, sizeof(out->mnem), "%s", mn);
        if (f3 == 1 || f3 == 5) {
            unsigned sh = (w >> 20) & (bits == 64 ? 63U : 31U);
            snprintf(out->ops, sizeof(out->ops), "%s, %s, %u", rv_rn[rd], rv_rn[rs1], sh);
        } else {
            snprintf(out->ops, sizeof(out->ops), "%s, %s, %lld", rv_rn[rd], rv_rn[rs1], (long long)i_imm);
        }
    } else if (opc == 0x1BU) {
        if (!want_text) return;
        if (f3 == 0) {
            snprintf(out->mnem, sizeof(out->mnem), "addiw");
            snprintf(out->ops, sizeof(out->ops), "%s, %s, %lld", rv_rn[rd], rv_rn[rs1], (long long)i_imm);
        } else if (f3 == 1 || f3 == 5) {
            const char *mn = (f3 == 1) ? "slliw" : ((w & 0x40000000U) ? "sraiw" : "srliw");
            snprintf(out->mnem, sizeof(out->mnem), "%s", mn);
            snprintf(out->ops, sizeof(out->ops), "%s, %s, %u", rv_rn[rd], rv_rn[rs1], (w >> 20) & 31U);
        }
    } else if (opc == 0x33U) {
        if (!want_text) return;
        static const char *const op_m[8] = {"mul","mulh","mulhsu","mulhu","div","divu","rem","remu"};
        static const char *const op_i[8] = {"add","sll","slt","sltu","xor","srl","or","and"};
        const char *mn = NULL;
        if (f7 == 1U) mn = op_m[f3];
        else if (f7 == 0x20U && f3 == 0U) mn = "sub";
        else if (f7 == 0x20U && f3 == 5U) mn = "sra";
        else if (f7 == 0U) mn = op_i[f3];
        if (mn) {
            snprintf(out->mnem, sizeof(out->mnem), "%s", mn);
            snprintf(out->ops, sizeof(out->ops), "%s, %s, %s", rv_rn[rd], rv_rn[rs1], rv_rn[rs2]);
        }
    } else if (opc == 0x3BU) {
        if (!want_text) return;
        const char *mn = NULL;
        if (f7 == 1U) {
            static const char *const mw[8] = {"mulw",NULL,NULL,NULL,"divw","divuw","remw","remuw"};
            mn = mw[f3];
        } else if (f7 == 0x20U && f3 == 0U) mn = "subw";
        else if (f7 == 0x20U && f3 == 5U) mn = "sraw";
        else if (f7 == 0U) {
            if (f3 == 0U) mn = "addw";
            else if (f3 == 1U) mn = "sllw";
            else if (f3 == 5U) mn = "srlw";
        }
        if (mn) {
            snprintf(out->mnem, sizeof(out->mnem), "%s", mn);
            snprintf(out->ops, sizeof(out->ops), "%s, %s, %s", rv_rn[rd], rv_rn[rs1], rv_rn[rs2]);
        }
    } else if (opc == 0x73U) {
        if (w == 0x00000073U || w == 0x00100073U) {
            out->flow = X86_FLOW_TRAP;
            if (want_text) snprintf(out->mnem, sizeof(out->mnem), "%s", w == 0x00000073U ? "ecall" : "ebreak");
        } else if (w == 0x30200073U || w == 0x10200073U) {
            out->flow = X86_FLOW_RET;
            if (want_text) snprintf(out->mnem, sizeof(out->mnem), "%s", w == 0x30200073U ? "mret" : "sret");
        } else if (w == 0x10500073U) {
            if (want_text) snprintf(out->mnem, sizeof(out->mnem), "wfi");
        } else if (f3 == 0U && f7 == 0x09U && rd == 0U) {
            if (want_text) {
                snprintf(out->mnem, sizeof(out->mnem), "sfence.vma");
                snprintf(out->ops, sizeof(out->ops), "%s, %s", rv_rn[rs1], rv_rn[rs2]);
            }
        } else if (want_text && f3 != 0) {
            static const char *const csr[8] = {NULL,"csrrw","csrrs","csrrc",NULL,"csrrwi","csrrsi","csrrci"};
            if (csr[f3]) {
                snprintf(out->mnem, sizeof(out->mnem), "%s", csr[f3]);
                if (f3 >= 5U) snprintf(out->ops, sizeof(out->ops), "%s, 0x%x, %u", rv_rn[rd], (w >> 20) & 0xFFFU, rs1);
                else snprintf(out->ops, sizeof(out->ops), "%s, 0x%x, %s", rv_rn[rd], (w >> 20) & 0xFFFU, rv_rn[rs1]);
            }
        }
    } else if (opc == 0x0FU) {
        if (want_text) snprintf(out->mnem, sizeof(out->mnem), "%s", f3 == 1U ? "fence.i" : "fence");
    }

    if (want_text && !out->mnem[0]) {
        snprintf(out->mnem, sizeof(out->mnem), "rv");
        snprintf(out->ops, sizeof(out->ops), "0x%08x", w);
    }
}

int rv_decode(const uint8_t *code, size_t avail, uint64_t ip, int bits, int want_text, int upper, x86_ins *out) {
    memset(out, 0, sizeof(*out));
    out->ip = ip;
    if (!code || avail == 0) return 0;

    if ((code[0] & 3U) != 3U) {
        if (avail < 2) return m_db(code, avail, want_text, upper, out);
        out->len = 2;
        rv_decode_c(m_u16(code), ip, bits, want_text, out);
        m_upper(out, want_text, upper);
        return 2;
    }

    if (avail < 4) return m_db(code, avail, want_text, upper, out);
    out->len = 4;
    rv_decode_32(m_u32(code), ip, bits, want_text, out);
    m_upper(out, want_text, upper);
    return 4;
}

static const char *const mips_rn[32] = {
    "$zero","$at","$v0","$v1","$a0","$a1","$a2","$a3",
    "$t0","$t1","$t2","$t3","$t4","$t5","$t6","$t7",
    "$s0","$s1","$s2","$s3","$s4","$s5","$s6","$s7",
    "$t8","$t9","$k0","$k1","$gp","$sp","$fp","$ra"
};

static void mips_special(uint32_t w, int want_text, x86_ins *out) {
    unsigned rs = (w >> 21) & 31U;
    unsigned rt = (w >> 16) & 31U;
    unsigned rd = (w >> 11) & 31U;
    unsigned sa = (w >> 6) & 31U;
    unsigned fn = w & 0x3FU;

    if (fn == 0x08U) {
        out->flow = (rs == 31U) ? X86_FLOW_RET : X86_FLOW_JMP;
        if (want_text) {
            snprintf(out->mnem, sizeof(out->mnem), "jr");
            snprintf(out->ops, sizeof(out->ops), "%s", mips_rn[rs]);
        }
        return;
    }
    if (fn == 0x09U) {
        out->flow = X86_FLOW_CALL;
        if (want_text) {
            snprintf(out->mnem, sizeof(out->mnem), "jalr");
            if (rd == 31U) snprintf(out->ops, sizeof(out->ops), "%s", mips_rn[rs]);
            else snprintf(out->ops, sizeof(out->ops), "%s, %s", mips_rn[rd], mips_rn[rs]);
        }
        return;
    }
    if (fn == 0x0CU || fn == 0x0DU) {
        out->flow = X86_FLOW_TRAP;
        if (want_text) {
            snprintf(out->mnem, sizeof(out->mnem), "%s", fn == 0x0CU ? "syscall" : "break");
            unsigned code20 = (w >> 6) & 0xFFFFFU;
            if (code20) snprintf(out->ops, sizeof(out->ops), "0x%x", code20);
        }
        return;
    }
    if (fn >= 0x30U && fn <= 0x36U && fn != 0x35U) {
        static const char *const tr[7] = { "tge","tgeu","tlt","tltu","teq",NULL,"tne" };
        out->flow = X86_FLOW_TRAP;
        if (want_text) {
            snprintf(out->mnem, sizeof(out->mnem), "%s", tr[fn - 0x30U]);
            snprintf(out->ops, sizeof(out->ops), "%s, %s", mips_rn[rs], mips_rn[rt]);
        }
        return;
    }
    if (!want_text) return;

    switch (fn) {
    case 0x00U: snprintf(out->mnem, sizeof(out->mnem), "sll");   snprintf(out->ops, sizeof(out->ops), "%s, %s, %u", mips_rn[rd], mips_rn[rt], sa); break;
    case 0x02U: snprintf(out->mnem, sizeof(out->mnem), "%s", rs == 1U ? "rotr" : "srl"); snprintf(out->ops, sizeof(out->ops), "%s, %s, %u", mips_rn[rd], mips_rn[rt], sa); break;
    case 0x03U: snprintf(out->mnem, sizeof(out->mnem), "sra");   snprintf(out->ops, sizeof(out->ops), "%s, %s, %u", mips_rn[rd], mips_rn[rt], sa); break;
    case 0x04U: snprintf(out->mnem, sizeof(out->mnem), "sllv");  snprintf(out->ops, sizeof(out->ops), "%s, %s, %s", mips_rn[rd], mips_rn[rt], mips_rn[rs]); break;
    case 0x06U: snprintf(out->mnem, sizeof(out->mnem), "%s", sa == 1U ? "rotrv" : "srlv"); snprintf(out->ops, sizeof(out->ops), "%s, %s, %s", mips_rn[rd], mips_rn[rt], mips_rn[rs]); break;
    case 0x07U: snprintf(out->mnem, sizeof(out->mnem), "srav");  snprintf(out->ops, sizeof(out->ops), "%s, %s, %s", mips_rn[rd], mips_rn[rt], mips_rn[rs]); break;
    case 0x0AU: snprintf(out->mnem, sizeof(out->mnem), "movz");  snprintf(out->ops, sizeof(out->ops), "%s, %s, %s", mips_rn[rd], mips_rn[rs], mips_rn[rt]); break;
    case 0x0BU: snprintf(out->mnem, sizeof(out->mnem), "movn");  snprintf(out->ops, sizeof(out->ops), "%s, %s, %s", mips_rn[rd], mips_rn[rs], mips_rn[rt]); break;
    case 0x0FU: snprintf(out->mnem, sizeof(out->mnem), "sync");  break;
    case 0x10U: snprintf(out->mnem, sizeof(out->mnem), "mfhi");  snprintf(out->ops, sizeof(out->ops), "%s", mips_rn[rd]); break;
    case 0x11U: snprintf(out->mnem, sizeof(out->mnem), "mthi");  snprintf(out->ops, sizeof(out->ops), "%s", mips_rn[rs]); break;
    case 0x12U: snprintf(out->mnem, sizeof(out->mnem), "mflo");  snprintf(out->ops, sizeof(out->ops), "%s", mips_rn[rd]); break;
    case 0x13U: snprintf(out->mnem, sizeof(out->mnem), "mtlo");  snprintf(out->ops, sizeof(out->ops), "%s", mips_rn[rs]); break;
    case 0x18U: snprintf(out->mnem, sizeof(out->mnem), "mult");  snprintf(out->ops, sizeof(out->ops), "%s, %s", mips_rn[rs], mips_rn[rt]); break;
    case 0x19U: snprintf(out->mnem, sizeof(out->mnem), "multu"); snprintf(out->ops, sizeof(out->ops), "%s, %s", mips_rn[rs], mips_rn[rt]); break;
    case 0x1AU: snprintf(out->mnem, sizeof(out->mnem), "div");   snprintf(out->ops, sizeof(out->ops), "%s, %s", mips_rn[rs], mips_rn[rt]); break;
    case 0x1BU: snprintf(out->mnem, sizeof(out->mnem), "divu");  snprintf(out->ops, sizeof(out->ops), "%s, %s", mips_rn[rs], mips_rn[rt]); break;
    case 0x20U: snprintf(out->mnem, sizeof(out->mnem), "add");   snprintf(out->ops, sizeof(out->ops), "%s, %s, %s", mips_rn[rd], mips_rn[rs], mips_rn[rt]); break;
    case 0x21U: snprintf(out->mnem, sizeof(out->mnem), "addu");  snprintf(out->ops, sizeof(out->ops), "%s, %s, %s", mips_rn[rd], mips_rn[rs], mips_rn[rt]); break;
    case 0x22U: snprintf(out->mnem, sizeof(out->mnem), "sub");   snprintf(out->ops, sizeof(out->ops), "%s, %s, %s", mips_rn[rd], mips_rn[rs], mips_rn[rt]); break;
    case 0x23U: snprintf(out->mnem, sizeof(out->mnem), "subu");  snprintf(out->ops, sizeof(out->ops), "%s, %s, %s", mips_rn[rd], mips_rn[rs], mips_rn[rt]); break;
    case 0x24U: snprintf(out->mnem, sizeof(out->mnem), "and");   snprintf(out->ops, sizeof(out->ops), "%s, %s, %s", mips_rn[rd], mips_rn[rs], mips_rn[rt]); break;
    case 0x25U: snprintf(out->mnem, sizeof(out->mnem), "or");    snprintf(out->ops, sizeof(out->ops), "%s, %s, %s", mips_rn[rd], mips_rn[rs], mips_rn[rt]); break;
    case 0x26U: snprintf(out->mnem, sizeof(out->mnem), "xor");   snprintf(out->ops, sizeof(out->ops), "%s, %s, %s", mips_rn[rd], mips_rn[rs], mips_rn[rt]); break;
    case 0x27U: snprintf(out->mnem, sizeof(out->mnem), "nor");   snprintf(out->ops, sizeof(out->ops), "%s, %s, %s", mips_rn[rd], mips_rn[rs], mips_rn[rt]); break;
    case 0x2AU: snprintf(out->mnem, sizeof(out->mnem), "slt");   snprintf(out->ops, sizeof(out->ops), "%s, %s, %s", mips_rn[rd], mips_rn[rs], mips_rn[rt]); break;
    case 0x2BU: snprintf(out->mnem, sizeof(out->mnem), "sltu");  snprintf(out->ops, sizeof(out->ops), "%s, %s, %s", mips_rn[rd], mips_rn[rs], mips_rn[rt]); break;
    default: break;
    }
}

static void mips_cop1(uint32_t w, uint64_t ip, int want_text, x86_ins *out) {
    unsigned fmt = (w >> 21) & 31U;
    unsigned ft = (w >> 16) & 31U;
    unsigned fs = (w >> 11) & 31U;
    unsigned fd = (w >> 6) & 31U;
    unsigned fn = w & 0x3FU;

    if (fmt == 8U) {
        int16_t simm = (int16_t)(w & 0xFFFFU);
        out->target = ip + 4ULL + (uint64_t)((int64_t)simm << 2);
        out->has_target = 1;
        out->flow = X86_FLOW_JCC;
        if (want_text) {
            snprintf(out->mnem, sizeof(out->mnem), "%s%s", (ft & 1U) ? "bc1t" : "bc1f", (ft & 2U) ? "l" : "");
            snprintf(out->ops, sizeof(out->ops), "0x%llx", (unsigned long long)out->target);
        }
        return;
    }
    if (!want_text) return;

    if (fmt == 0U || fmt == 4U) {
        snprintf(out->mnem, sizeof(out->mnem), "%s", fmt == 0U ? "mfc1" : "mtc1");
        snprintf(out->ops, sizeof(out->ops), "%s, $f%u", mips_rn[ft], fs);
        return;
    }
    if (fmt == 16U || fmt == 17U) {
        char fc = (fmt == 16U) ? 's' : 'd';
        if (fn <= 3U) {
            static const char *const fp3[4] = { "add","sub","mul","div" };
            snprintf(out->mnem, sizeof(out->mnem), "%s.%c", fp3[fn], fc);
            snprintf(out->ops, sizeof(out->ops), "$f%u, $f%u, $f%u", fd, fs, ft);
        } else if (fn >= 4U && fn <= 7U) {
            static const char *const fp2[4] = { "sqrt","abs","mov","neg" };
            snprintf(out->mnem, sizeof(out->mnem), "%s.%c", fp2[fn - 4U], fc);
            snprintf(out->ops, sizeof(out->ops), "$f%u, $f%u", fd, fs);
        } else if (fn == 0x0DU) {
            snprintf(out->mnem, sizeof(out->mnem), "trunc.w.%c", fc);
            snprintf(out->ops, sizeof(out->ops), "$f%u, $f%u", fd, fs);
        } else if (fn == 0x20U && fmt == 17U) {
            snprintf(out->mnem, sizeof(out->mnem), "cvt.s.d");
            snprintf(out->ops, sizeof(out->ops), "$f%u, $f%u", fd, fs);
        } else if (fn == 0x21U && fmt == 16U) {
            snprintf(out->mnem, sizeof(out->mnem), "cvt.d.s");
            snprintf(out->ops, sizeof(out->ops), "$f%u, $f%u", fd, fs);
        } else if (fn == 0x24U) {
            snprintf(out->mnem, sizeof(out->mnem), "cvt.w.%c", fc);
            snprintf(out->ops, sizeof(out->ops), "$f%u, $f%u", fd, fs);
        } else if (fn >= 0x30U) {
            const char *cc = (fn == 0x32U) ? "eq" : (fn == 0x3CU) ? "lt" : (fn == 0x3EU) ? "le" : "cond";
            snprintf(out->mnem, sizeof(out->mnem), "c.%s.%c", cc, fc);
            snprintf(out->ops, sizeof(out->ops), "$f%u, $f%u", fs, ft);
        }
        return;
    }
    if (fmt == 20U && (fn == 0x20U || fn == 0x21U)) {
        snprintf(out->mnem, sizeof(out->mnem), "cvt.%c.w", fn == 0x20U ? 's' : 'd');
        snprintf(out->ops, sizeof(out->ops), "$f%u, $f%u", fd, fs);
    }
}

int mips_decode(const uint8_t *code, size_t avail, uint64_t ip, int want_text, int upper, x86_ins *out) {
    memset(out, 0, sizeof(*out));
    out->ip = ip;
    if (!code || avail < 4) return m_db(code, avail, want_text, upper, out);

    uint32_t w = m_u32(code);
    out->len = 4;

    if (w == 0x00000000U) {
        if (want_text) snprintf(out->mnem, sizeof(out->mnem), "nop");
        m_upper(out, want_text, upper);
        return 4;
    }

    unsigned opc = (w >> 26) & 0x3FU;
    unsigned rs = (w >> 21) & 31U;
    unsigned rt = (w >> 16) & 31U;
    unsigned rd = (w >> 11) & 31U;
    unsigned sa = (w >> 6) & 31U;
    unsigned fn = w & 0x3FU;
    uint16_t imm = (uint16_t)(w & 0xFFFFU);
    int16_t simm = (int16_t)imm;

    if (opc == 0x00U) {
        mips_special(w, want_text, out);
    } else if (opc == 0x01U && (rt <= 3U || rt == 16U || rt == 17U)) {
        out->target = ip + 4ULL + (uint64_t)((int64_t)simm << 2);
        out->has_target = 1;
        out->flow = (rt >= 16U) ? X86_FLOW_CALL : X86_FLOW_JCC;
        if (want_text) {
            const char *mn = (rt == 0U) ? "bltz" : (rt == 1U) ? "bgez" : (rt == 2U) ? "bltzl"
                           : (rt == 3U) ? "bgezl" : (rt == 16U) ? "bltzal" : "bgezal";
            snprintf(out->mnem, sizeof(out->mnem), "%s", mn);
            snprintf(out->ops, sizeof(out->ops), "%s, 0x%llx", mips_rn[rs], (unsigned long long)out->target);
        }
    } else if (opc == 0x02U || opc == 0x03U) {
        out->target = ((ip + 4ULL) & 0xF0000000ULL) | ((uint64_t)(w & 0x03FFFFFFU) << 2);
        out->has_target = 1;
        out->flow = (opc == 0x03U) ? X86_FLOW_CALL : X86_FLOW_JMP;
        if (want_text) {
            snprintf(out->mnem, sizeof(out->mnem), "%s", opc == 0x03U ? "jal" : "j");
            snprintf(out->ops, sizeof(out->ops), "0x%llx", (unsigned long long)out->target);
        }
    } else if ((opc >= 0x04U && opc <= 0x07U) || (opc >= 0x14U && opc <= 0x17U)) {
        static const char *const br[4] = {"beq","bne","blez","bgtz"};
        int likely = (opc >= 0x14U);
        unsigned bidx = likely ? (opc - 0x14U) : (opc - 0x04U);
        out->target = ip + 4ULL + (uint64_t)((int64_t)simm << 2);
        out->has_target = 1;
        out->flow = X86_FLOW_JCC;
        if (want_text) {
            snprintf(out->mnem, sizeof(out->mnem), "%s%s", br[bidx], likely ? "l" : "");
            if (bidx <= 1U) snprintf(out->ops, sizeof(out->ops), "%s, %s, 0x%llx", mips_rn[rs], mips_rn[rt], (unsigned long long)out->target);
            else snprintf(out->ops, sizeof(out->ops), "%s, 0x%llx", mips_rn[rs], (unsigned long long)out->target);
        }
    } else if (opc >= 0x08U && opc <= 0x0FU) {
        static const char *const ai[8] = {"addi","addiu","slti","sltiu","andi","ori","xori","lui"};
        if (want_text) {
            snprintf(out->mnem, sizeof(out->mnem), "%s", ai[opc - 8U]);
            if (opc == 0x0FU) snprintf(out->ops, sizeof(out->ops), "%s, 0x%x", mips_rn[rt], (unsigned)imm);
            else if (opc >= 0x0CU) snprintf(out->ops, sizeof(out->ops), "%s, %s, 0x%x", mips_rn[rt], mips_rn[rs], (unsigned)imm);
            else snprintf(out->ops, sizeof(out->ops), "%s, %s, %d", mips_rn[rt], mips_rn[rs], (int)simm);
        }
    } else if (opc == 0x10U) {
        if (w == 0x42000018U) {
            out->flow = X86_FLOW_RET;
            if (want_text) snprintf(out->mnem, sizeof(out->mnem), "eret");
        } else if (want_text && (rs == 0U || rs == 4U)) {
            snprintf(out->mnem, sizeof(out->mnem), "%s", rs == 0U ? "mfc0" : "mtc0");
            snprintf(out->ops, sizeof(out->ops), "%s, $%u, %u", mips_rn[rt], rd, w & 7U);
        }
    } else if (opc == 0x11U) {
        mips_cop1(w, ip, want_text, out);
    } else if (opc == 0x1CU) {
        if (want_text) {
            switch (fn) {
            case 0x00U: snprintf(out->mnem, sizeof(out->mnem), "madd");  snprintf(out->ops, sizeof(out->ops), "%s, %s", mips_rn[rs], mips_rn[rt]); break;
            case 0x01U: snprintf(out->mnem, sizeof(out->mnem), "maddu"); snprintf(out->ops, sizeof(out->ops), "%s, %s", mips_rn[rs], mips_rn[rt]); break;
            case 0x02U: snprintf(out->mnem, sizeof(out->mnem), "mul");   snprintf(out->ops, sizeof(out->ops), "%s, %s, %s", mips_rn[rd], mips_rn[rs], mips_rn[rt]); break;
            case 0x04U: snprintf(out->mnem, sizeof(out->mnem), "msub");  snprintf(out->ops, sizeof(out->ops), "%s, %s", mips_rn[rs], mips_rn[rt]); break;
            case 0x05U: snprintf(out->mnem, sizeof(out->mnem), "msubu"); snprintf(out->ops, sizeof(out->ops), "%s, %s", mips_rn[rs], mips_rn[rt]); break;
            case 0x20U: snprintf(out->mnem, sizeof(out->mnem), "clz");   snprintf(out->ops, sizeof(out->ops), "%s, %s", mips_rn[rd], mips_rn[rs]); break;
            case 0x21U: snprintf(out->mnem, sizeof(out->mnem), "clo");   snprintf(out->ops, sizeof(out->ops), "%s, %s", mips_rn[rd], mips_rn[rs]); break;
            default: break;
            }
        }
    } else if (opc == 0x1FU) {
        if (want_text) {
            if (fn == 0x00U) {
                snprintf(out->mnem, sizeof(out->mnem), "ext");
                snprintf(out->ops, sizeof(out->ops), "%s, %s, %u, %u", mips_rn[rt], mips_rn[rs], sa, rd + 1U);
            } else if (fn == 0x04U) {
                snprintf(out->mnem, sizeof(out->mnem), "ins");
                snprintf(out->ops, sizeof(out->ops), "%s, %s, %u, %u", mips_rn[rt], mips_rn[rs], sa, (rd >= sa) ? (rd - sa + 1U) : 1U);
            } else if (fn == 0x20U) {
                const char *mn = (sa == 0x02U) ? "wsbh" : (sa == 0x10U) ? "seb" : (sa == 0x18U) ? "seh" : NULL;
                if (mn) {
                    snprintf(out->mnem, sizeof(out->mnem), "%s", mn);
                    snprintf(out->ops, sizeof(out->ops), "%s, %s", mips_rn[rd], mips_rn[rt]);
                }
            }
        }
    } else if (want_text) {
        const char *ls = NULL;
        int is_fp = 0;
        switch (opc) {
        case 0x20U: ls = "lb";   break;
        case 0x21U: ls = "lh";   break;
        case 0x22U: ls = "lwl";  break;
        case 0x23U: ls = "lw";   break;
        case 0x24U: ls = "lbu";  break;
        case 0x25U: ls = "lhu";  break;
        case 0x26U: ls = "lwr";  break;
        case 0x28U: ls = "sb";   break;
        case 0x29U: ls = "sh";   break;
        case 0x2AU: ls = "swl";  break;
        case 0x2BU: ls = "sw";   break;
        case 0x2EU: ls = "swr";  break;
        case 0x30U: ls = "ll";   break;
        case 0x31U: ls = "lwc1"; is_fp = 1; break;
        case 0x35U: ls = "ldc1"; is_fp = 1; break;
        case 0x38U: ls = "sc";   break;
        case 0x39U: ls = "swc1"; is_fp = 1; break;
        case 0x3DU: ls = "sdc1"; is_fp = 1; break;
        default: break;
        }
        if (ls) {
            snprintf(out->mnem, sizeof(out->mnem), "%s", ls);
            if (is_fp) snprintf(out->ops, sizeof(out->ops), "$f%u, %d(%s)", rt, (int)simm, mips_rn[rs]);
            else snprintf(out->ops, sizeof(out->ops), "%s, %d(%s)", mips_rn[rt], (int)simm, mips_rn[rs]);
        }
    }

    if (want_text && !out->mnem[0]) {
        snprintf(out->mnem, sizeof(out->mnem), "mips");
        snprintf(out->ops, sizeof(out->ops), "0x%08x", w);
    }
    m_upper(out, want_text, upper);
    return 4;
}

static size_t wasm_uleb(const uint8_t *p, size_t avail, uint64_t *val) {
    uint64_t v = 0;
    unsigned sh = 0;
    size_t i = 0;
    while (i < avail && i < 10) {
        uint8_t b = p[i++];
        if (sh < 64U) v |= (uint64_t)(b & 0x7FU) << sh;
        if ((b & 0x80U) == 0) {
            *val = v;
            return i;
        }
        sh += 7U;
    }
    return 0;
}

static size_t wasm_sleb(const uint8_t *p, size_t avail, int64_t *val) {
    uint64_t v = 0;
    unsigned sh = 0;
    size_t i = 0;
    while (i < avail && i < 10) {
        uint8_t b = p[i++];
        if (sh < 64U) v |= (uint64_t)(b & 0x7FU) << sh;
        sh += 7U;
        if ((b & 0x80U) == 0) {
            if (sh < 64U && (b & 0x40U)) v |= (~0ULL << sh);
            *val = (int64_t)v;
            return i;
        }
    }
    return 0;
}

static const char *const wasm_mem_m[23] = {
    "i32.load","i64.load","f32.load","f64.load",
    "i32.load8_s","i32.load8_u","i32.load16_s","i32.load16_u",
    "i64.load8_s","i64.load8_u","i64.load16_s","i64.load16_u",
    "i64.load32_s","i64.load32_u","i32.store","i64.store",
    "f32.store","f64.store","i32.store8","i32.store16",
    "i64.store8","i64.store16","i64.store32"
};

static const char *const wasm_num_m[128] = {
    "i32.eqz","i32.eq","i32.ne","i32.lt_s","i32.lt_u","i32.gt_s","i32.gt_u","i32.le_s",
    "i32.le_u","i32.ge_s","i32.ge_u","i64.eqz","i64.eq","i64.ne","i64.lt_s","i64.lt_u",
    "i64.gt_s","i64.gt_u","i64.le_s","i64.le_u","i64.ge_s","i64.ge_u","f32.eq","f32.ne",
    "f32.lt","f32.gt","f32.le","f32.ge","f64.eq","f64.ne","f64.lt","f64.gt",
    "f64.le","f64.ge","i32.clz","i32.ctz","i32.popcnt","i32.add","i32.sub","i32.mul",
    "i32.div_s","i32.div_u","i32.rem_s","i32.rem_u","i32.and","i32.or","i32.xor","i32.shl",
    "i32.shr_s","i32.shr_u","i32.rotl","i32.rotr","i64.clz","i64.ctz","i64.popcnt","i64.add",
    "i64.sub","i64.mul","i64.div_s","i64.div_u","i64.rem_s","i64.rem_u","i64.and","i64.or",
    "i64.xor","i64.shl","i64.shr_s","i64.shr_u","i64.rotl","i64.rotr","f32.abs","f32.neg",
    "f32.ceil","f32.floor","f32.trunc","f32.nearest","f32.sqrt","f32.add","f32.sub","f32.mul",
    "f32.div","f32.min","f32.max","f32.copysign","f64.abs","f64.neg","f64.ceil","f64.floor",
    "f64.trunc","f64.nearest","f64.sqrt","f64.add","f64.sub","f64.mul","f64.div","f64.min",
    "f64.max","f64.copysign","i32.wrap_i64","i32.trunc_f32_s","i32.trunc_f32_u","i32.trunc_f64_s",
    "i32.trunc_f64_u","i64.extend_i32_s","i64.extend_i32_u","i64.trunc_f32_s","i64.trunc_f32_u",
    "i64.trunc_f64_s","i64.trunc_f64_u","f32.convert_i32_s","f32.convert_i32_u","f32.convert_i64_s",
    "f32.convert_i64_u","f32.demote_f64","f64.convert_i32_s","f64.convert_i32_u","f64.convert_i64_s",
    "f64.convert_i64_u","f64.promote_f32","i32.reinterpret_f32","i64.reinterpret_f64",
    "f32.reinterpret_i32","f64.reinterpret_i64","i32.extend8_s","i32.extend16_s",
    "i64.extend8_s","i64.extend16_s","i64.extend32_s"
};

static const char *wasm_btype(int64_t bt) {
    if (bt == -64) return "";
    if (bt == -1) return "i32";
    if (bt == -2) return "i64";
    if (bt == -3) return "f32";
    if (bt == -4) return "f64";
    return NULL;
}

static int wasm_decode_fc(const uint8_t *code, size_t avail, int want_text, int upper, x86_ins *out) {
    static const char *const fc_sat[8] = {
        "i32.trunc_sat_f32_s", "i32.trunc_sat_f32_u",
        "i32.trunc_sat_f64_s", "i32.trunc_sat_f64_u",
        "i64.trunc_sat_f32_s", "i64.trunc_sat_f32_u",
        "i64.trunc_sat_f64_s", "i64.trunc_sat_f64_u"
    };
    uint64_t sub = 0, u1 = 0, u2 = 0;
    size_t n = wasm_uleb(code + 1, avail - 1, &sub);
    if (!n) return m_db(code, avail, want_text, upper, out);
    size_t len = 1 + n;

    if (sub <= 7ULL) {
        if (want_text) snprintf(out->mnem, sizeof(out->mnem), "%s", fc_sat[sub]);
    } else if (sub == 8ULL || sub == 10ULL || sub == 12ULL || sub == 14ULL) {
        size_t n1 = wasm_uleb(code + len, avail - len, &u1);
        if (!n1) return m_db(code, avail, want_text, upper, out);
        len += n1;
        size_t n2 = wasm_uleb(code + len, avail - len, &u2);
        if (!n2) return m_db(code, avail, want_text, upper, out);
        len += n2;
        if (want_text) {
            const char *mn = (sub == 8ULL)  ? "memory.init"
                           : (sub == 10ULL) ? "memory.copy"
                           : (sub == 12ULL) ? "table.init"
                                            : "table.copy";
            snprintf(out->mnem, sizeof(out->mnem), "%s", mn);
            snprintf(out->ops, sizeof(out->ops), "%llu, %llu",
                     (unsigned long long)u1, (unsigned long long)u2);
        }
    } else if (sub == 9ULL || sub == 11ULL || sub == 13ULL ||
               (sub >= 15ULL && sub <= 17ULL)) {
        size_t n1 = wasm_uleb(code + len, avail - len, &u1);
        if (!n1) return m_db(code, avail, want_text, upper, out);
        len += n1;
        if (want_text) {
            const char *mn = (sub == 9ULL)  ? "data.drop"
                           : (sub == 11ULL) ? "memory.fill"
                           : (sub == 13ULL) ? "elem.drop"
                           : (sub == 15ULL) ? "table.grow"
                           : (sub == 16ULL) ? "table.size"
                                            : "table.fill";
            snprintf(out->mnem, sizeof(out->mnem), "%s", mn);
            snprintf(out->ops, sizeof(out->ops), "%llu", (unsigned long long)u1);
        }
    } else if (want_text) {
        snprintf(out->mnem, sizeof(out->mnem), "wasm.fc");
        snprintf(out->ops, sizeof(out->ops), "0x%llx", (unsigned long long)sub);
    }

    out->len = (uint8_t)len;
    m_upper(out, want_text, upper);
    return (int)len;
}

static int wasm_decode_fd(const uint8_t *code, size_t avail, int want_text, int upper, x86_ins *out) {
    uint64_t sub = 0, u1 = 0, u2 = 0;
    size_t n = wasm_uleb(code + 1, avail - 1, &sub);
    if (!n) return m_db(code, avail, want_text, upper, out);
    size_t len = 1 + n;

    if (sub <= 11ULL || sub == 92ULL || sub == 93ULL) {
        size_t n1 = wasm_uleb(code + len, avail - len, &u1);
        if (!n1) return m_db(code, avail, want_text, upper, out);
        len += n1;
        size_t n2 = wasm_uleb(code + len, avail - len, &u2);
        if (!n2) return m_db(code, avail, want_text, upper, out);
        len += n2;
    } else if (sub == 12ULL || sub == 13ULL) {
        if (avail - len < 16) return m_db(code, avail, want_text, upper, out);
        len += 16;
    } else if (sub >= 21ULL && sub <= 34ULL) {
        if (avail - len < 1) return m_db(code, avail, want_text, upper, out);
        len += 1;
    } else if (sub >= 84ULL && sub <= 91ULL) {
        size_t n1 = wasm_uleb(code + len, avail - len, &u1);
        if (!n1) return m_db(code, avail, want_text, upper, out);
        len += n1;
        size_t n2 = wasm_uleb(code + len, avail - len, &u2);
        if (!n2) return m_db(code, avail, want_text, upper, out);
        len += n2;
        if (avail - len < 1) return m_db(code, avail, want_text, upper, out);
        len += 1;
    }

    if (want_text) {
        snprintf(out->mnem, sizeof(out->mnem), "wasm.fd");
        snprintf(out->ops, sizeof(out->ops), "0x%llx", (unsigned long long)sub);
    }
    out->len = (uint8_t)len;
    m_upper(out, want_text, upper);
    return (int)len;
}

static int wasm_decode_fe(const uint8_t *code, size_t avail, int want_text, int upper, x86_ins *out) {
    uint64_t sub = 0, u1 = 0, u2 = 0;
    size_t n = wasm_uleb(code + 1, avail - 1, &sub);
    if (!n) return m_db(code, avail, want_text, upper, out);
    size_t len = 1 + n;

    if (sub == 3ULL) {
        if (avail - len < 1) return m_db(code, avail, want_text, upper, out);
        len += 1;
        if (want_text) snprintf(out->mnem, sizeof(out->mnem), "atomic.fence");
    } else {
        if (sub <= 2ULL || (sub >= 0x10ULL && sub <= 0x4EULL)) {
            size_t n1 = wasm_uleb(code + len, avail - len, &u1);
            if (!n1) return m_db(code, avail, want_text, upper, out);
            len += n1;
            size_t n2 = wasm_uleb(code + len, avail - len, &u2);
            if (!n2) return m_db(code, avail, want_text, upper, out);
            len += n2;
        }
        if (want_text) {
            snprintf(out->mnem, sizeof(out->mnem), "wasm.fe");
            snprintf(out->ops, sizeof(out->ops), "0x%llx", (unsigned long long)sub);
        }
    }

    out->len = (uint8_t)len;
    m_upper(out, want_text, upper);
    return (int)len;
}

int wasm_decode(const uint8_t *code, size_t avail, uint64_t ip, int want_text, int upper, x86_ins *out) {
    memset(out, 0, sizeof(*out));
    out->ip = ip;
    if (!code || avail == 0) return 0;

    uint8_t op = code[0];
    if (op == 0xFCU) return wasm_decode_fc(code, avail, want_text, upper, out);
    if (op == 0xFDU) return wasm_decode_fd(code, avail, want_text, upper, out);
    if (op == 0xFEU) return wasm_decode_fe(code, avail, want_text, upper, out);
    size_t len = 1;
    uint64_t u1 = 0, u2 = 0;
    int64_t s1 = 0;

    if (op == 0x00U) {
        out->flow = X86_FLOW_TRAP;
        if (want_text) snprintf(out->mnem, sizeof(out->mnem), "unreachable");
    } else if (op == 0x01U) {
        if (want_text) snprintf(out->mnem, sizeof(out->mnem), "nop");
    } else if (op >= 0x02U && op <= 0x04U) {
        static const char *const blk[3] = {"block","loop","if"};
        size_t n = wasm_sleb(code + 1, avail - 1, &s1);
        if (!n) return m_db(code, avail, want_text, upper, out);
        len += n;
        if (want_text) {
            snprintf(out->mnem, sizeof(out->mnem), "%s", blk[op - 2U]);
            const char *bt = wasm_btype(s1);
            if (bt && bt[0]) snprintf(out->ops, sizeof(out->ops), "%s", bt);
            else if (!bt) snprintf(out->ops, sizeof(out->ops), "type %lld", (long long)s1);
        }
    } else if (op == 0x05U) {
        if (want_text) snprintf(out->mnem, sizeof(out->mnem), "else");
    } else if (op == 0x0BU) {
        if (avail == 1) out->flow = X86_FLOW_RET;
        if (want_text) snprintf(out->mnem, sizeof(out->mnem), "end");
    } else if (op == 0x0CU || op == 0x0DU) {
        size_t n = wasm_uleb(code + 1, avail - 1, &u1);
        if (!n) return m_db(code, avail, want_text, upper, out);
        len += n;
        out->flow = (op == 0x0CU) ? X86_FLOW_JMP : X86_FLOW_JCC;
        if (want_text) {
            snprintf(out->mnem, sizeof(out->mnem), "%s", op == 0x0CU ? "br" : "br_if");
            snprintf(out->ops, sizeof(out->ops), "%llu", (unsigned long long)u1);
        }
    } else if (op == 0x0EU) {
        size_t n = wasm_uleb(code + 1, avail - 1, &u1);
        if (!n || u1 > 64ULL) return m_db(code, avail, want_text, upper, out);
        len += n;
        uint64_t def = 0;
        for (uint64_t i = 0; i <= u1; i++) {
            size_t m = wasm_uleb(code + len, avail - len, &def);
            if (!m || len + m > 255) return m_db(code, avail, want_text, upper, out);
            len += m;
        }
        out->flow = X86_FLOW_JMP;
        if (want_text) {
            snprintf(out->mnem, sizeof(out->mnem), "br_table");
            snprintf(out->ops, sizeof(out->ops), "%llu, default %llu", (unsigned long long)u1, (unsigned long long)def);
        }
    } else if (op == 0x0FU) {
        out->flow = X86_FLOW_RET;
        if (want_text) snprintf(out->mnem, sizeof(out->mnem), "return");
    } else if (op == 0x10U) {
        size_t n = wasm_uleb(code + 1, avail - 1, &u1);
        if (!n) return m_db(code, avail, want_text, upper, out);
        len += n;
        out->flow = X86_FLOW_CALL;
        if (want_text) {
            snprintf(out->mnem, sizeof(out->mnem), "call");
            snprintf(out->ops, sizeof(out->ops), "%llu", (unsigned long long)u1);
        }
    } else if (op == 0x11U) {
        size_t n1 = wasm_uleb(code + 1, avail - 1, &u1);
        if (!n1) return m_db(code, avail, want_text, upper, out);
        size_t n2 = wasm_uleb(code + 1 + n1, avail - 1 - n1, &u2);
        if (!n2) return m_db(code, avail, want_text, upper, out);
        len += n1 + n2;
        out->flow = X86_FLOW_CALL;
        if (want_text) {
            snprintf(out->mnem, sizeof(out->mnem), "call_indirect");
            snprintf(out->ops, sizeof(out->ops), "type=%llu, table=%llu", (unsigned long long)u1, (unsigned long long)u2);
        }
    } else if (op == 0x1AU || op == 0x1BU) {
        if (want_text) snprintf(out->mnem, sizeof(out->mnem), "%s", op == 0x1AU ? "drop" : "select");
    } else if (op >= 0x20U && op <= 0x24U) {
        static const char *const lg[5] = {"local.get","local.set","local.tee","global.get","global.set"};
        size_t n = wasm_uleb(code + 1, avail - 1, &u1);
        if (!n) return m_db(code, avail, want_text, upper, out);
        len += n;
        if (want_text) {
            snprintf(out->mnem, sizeof(out->mnem), "%s", lg[op - 0x20U]);
            snprintf(out->ops, sizeof(out->ops), "%llu", (unsigned long long)u1);
        }
    } else if (op >= 0x28U && op <= 0x3EU) {
        size_t n1 = wasm_uleb(code + 1, avail - 1, &u1);
        if (!n1) return m_db(code, avail, want_text, upper, out);
        size_t n2 = wasm_uleb(code + 1 + n1, avail - 1 - n1, &u2);
        if (!n2) return m_db(code, avail, want_text, upper, out);
        len += n1 + n2;
        if (want_text) {
            snprintf(out->mnem, sizeof(out->mnem), "%s", wasm_mem_m[op - 0x28U]);
            snprintf(out->ops, sizeof(out->ops), "offset=%llu align=%llu", (unsigned long long)u2, (unsigned long long)u1);
        }
    } else if (op == 0x3FU || op == 0x40U) {
        size_t n = wasm_uleb(code + 1, avail - 1, &u1);
        if (!n) return m_db(code, avail, want_text, upper, out);
        len += n;
        if (want_text) {
            snprintf(out->mnem, sizeof(out->mnem), "%s", op == 0x3FU ? "memory.size" : "memory.grow");
            snprintf(out->ops, sizeof(out->ops), "%llu", (unsigned long long)u1);
        }
    } else if (op == 0x41U || op == 0x42U) {
        size_t n = wasm_sleb(code + 1, avail - 1, &s1);
        if (!n) return m_db(code, avail, want_text, upper, out);
        len += n;
        if (want_text) {
            snprintf(out->mnem, sizeof(out->mnem), "%s", op == 0x41U ? "i32.const" : "i64.const");
            snprintf(out->ops, sizeof(out->ops), "%lld", (long long)s1);
        }
    } else if (op == 0x43U) {
        if (avail < 5) return m_db(code, avail, want_text, upper, out);
        len = 5;
        if (want_text) {
            float fv;
            memcpy(&fv, code + 1, 4);
            snprintf(out->mnem, sizeof(out->mnem), "f32.const");
            snprintf(out->ops, sizeof(out->ops), "%g", (double)fv);
        }
    } else if (op == 0x44U) {
        if (avail < 9) return m_db(code, avail, want_text, upper, out);
        len = 9;
        if (want_text) {
            double dv;
            memcpy(&dv, code + 1, 8);
            snprintf(out->mnem, sizeof(out->mnem), "f64.const");
            snprintf(out->ops, sizeof(out->ops), "%g", dv);
        }
    } else if (op >= 0x45U && op <= 0xC4U) {
        if (want_text) snprintf(out->mnem, sizeof(out->mnem), "%s", wasm_num_m[op - 0x45U]);
    } else if (want_text) {
        snprintf(out->mnem, sizeof(out->mnem), "wasm");
        snprintf(out->ops, sizeof(out->ops), "0x%02x", op);
    }

    out->len = (uint8_t)len;
    m_upper(out, want_text, upper);
    return (int)len;
}

static int cil_decode_fe(const uint8_t *code, size_t avail, int want_text, int upper, x86_ins *out) {
    if (avail < 2) return m_db(code, avail, want_text, upper, out);
    uint8_t sub = code[1];
    size_t len = 2;

    if (sub == 0x01U || sub == 0x02U || sub == 0x03U || sub == 0x04U || sub == 0x05U) {
        static const char *const cm[5] = {"ceq","cgt","cgt.un","clt","clt.un"};
        if (want_text) snprintf(out->mnem, sizeof(out->mnem), "%s", cm[sub - 1U]);
    } else if (sub == 0x00U) {
        if (want_text) snprintf(out->mnem, sizeof(out->mnem), "arglist");
    } else if (sub >= 0x09U && sub <= 0x0EU) {
        static const char *const ls[6] = {"ldarg","ldarga","starg","ldloc","ldloca","stloc"};
        if (avail < 4) return m_db(code, avail, want_text, upper, out);
        len = 4;
        if (want_text) {
            snprintf(out->mnem, sizeof(out->mnem), "%s", ls[sub - 0x09U]);
            snprintf(out->ops, sizeof(out->ops), "%u", (unsigned)m_u16(code + 2));
        }
    } else if (sub == 0x06U || sub == 0x07U || sub == 0x15U || sub == 0x16U || sub == 0x1CU) {
        if (avail < 6) return m_db(code, avail, want_text, upper, out);
        len = 6;
        if (want_text) {
            const char *mn = (sub == 0x06U) ? "ldftn" : (sub == 0x07U) ? "ldvirtftn"
                           : (sub == 0x15U) ? "initobj" : (sub == 0x16U) ? "constrained." : "sizeof";
            snprintf(out->mnem, sizeof(out->mnem), "%s", mn);
            snprintf(out->ops, sizeof(out->ops), "0x%08x", m_u32(code + 2));
        }
    } else if (sub == 0x1AU) {
        out->flow = X86_FLOW_TRAP;
        if (want_text) snprintf(out->mnem, sizeof(out->mnem), "rethrow");
    } else if (want_text) {
        snprintf(out->mnem, sizeof(out->mnem), "cil_fe");
        snprintf(out->ops, sizeof(out->ops), "0x%02x", sub);
    }

    out->len = (uint8_t)len;
    m_upper(out, want_text, upper);
    return (int)len;
}

static const char *const cil_jcc_s[12] = {
    "brfalse.s","brtrue.s","beq.s","bge.s","bgt.s","ble.s",
    "blt.s","bne.un.s","bge.un.s","bgt.un.s","ble.un.s","blt.un.s"
};

static const char *const cil_jcc_l[12] = {
    "brfalse","brtrue","beq","bge","bgt","ble",
    "blt","bne.un","bge.un","bgt.un","ble.un","blt.un"
};

static const char *const cil_alu[15] = {
    "add","sub","mul","div","div.un","rem","rem.un","and",
    "or","xor","shl","shr","shr.un","neg","not"
};

int cil_decode(const uint8_t *code, size_t avail, uint64_t ip, int want_text, int upper, x86_ins *out) {
    memset(out, 0, sizeof(*out));
    out->ip = ip;
    if (!code || avail == 0) return 0;

    uint8_t op = code[0];
    if (op == 0xFEU) return cil_decode_fe(code, avail, want_text, upper, out);

    size_t len = 1;
    if (op == 0x00U) {
        if (want_text) snprintf(out->mnem, sizeof(out->mnem), "nop");
    } else if (op == 0x01U) {
        out->flow = X86_FLOW_TRAP;
        if (want_text) snprintf(out->mnem, sizeof(out->mnem), "break");
    } else if (op >= 0x02U && op <= 0x0DU) {
        if (want_text) {
            const char *p = (op <= 0x05U) ? "ldarg" : (op <= 0x09U) ? "ldloc" : "stloc";
            snprintf(out->mnem, sizeof(out->mnem), "%s.%u", p, (unsigned)((op - 2U) & 3U));
        }
    } else if (op >= 0x0EU && op <= 0x13U) {
        static const char *const sv[6] = {"ldarg.s","ldarga.s","starg.s","ldloc.s","ldloca.s","stloc.s"};
        if (avail < 2) return m_db(code, avail, want_text, upper, out);
        len = 2;
        if (want_text) {
            snprintf(out->mnem, sizeof(out->mnem), "%s", sv[op - 0x0EU]);
            snprintf(out->ops, sizeof(out->ops), "%u", (unsigned)code[1]);
        }
    } else if (op == 0x14U) {
        if (want_text) snprintf(out->mnem, sizeof(out->mnem), "ldnull");
    } else if (op >= 0x15U && op <= 0x1EU) {
        if (want_text) {
            if (op == 0x15U) snprintf(out->mnem, sizeof(out->mnem), "ldc.i4.m1");
            else snprintf(out->mnem, sizeof(out->mnem), "ldc.i4.%u", (unsigned)(op - 0x16U));
        }
    } else if (op == 0x1FU) {
        if (avail < 2) return m_db(code, avail, want_text, upper, out);
        len = 2;
        if (want_text) {
            snprintf(out->mnem, sizeof(out->mnem), "ldc.i4.s");
            snprintf(out->ops, sizeof(out->ops), "%d", (int)(int8_t)code[1]);
        }
    } else if (op == 0x20U) {
        if (avail < 5) return m_db(code, avail, want_text, upper, out);
        len = 5;
        if (want_text) {
            snprintf(out->mnem, sizeof(out->mnem), "ldc.i4");
            snprintf(out->ops, sizeof(out->ops), "%d", (int)(int32_t)m_u32(code + 1));
        }
    } else if (op == 0x21U) {
        if (avail < 9) return m_db(code, avail, want_text, upper, out);
        len = 9;
        if (want_text) {
            snprintf(out->mnem, sizeof(out->mnem), "ldc.i8");
            snprintf(out->ops, sizeof(out->ops), "%lld", (long long)(int64_t)m_u64(code + 1));
        }
    } else if (op == 0x22U) {
        if (avail < 5) return m_db(code, avail, want_text, upper, out);
        len = 5;
        if (want_text) {
            float fv;
            memcpy(&fv, code + 1, 4);
            snprintf(out->mnem, sizeof(out->mnem), "ldc.r4");
            snprintf(out->ops, sizeof(out->ops), "%g", (double)fv);
        }
    } else if (op == 0x23U) {
        if (avail < 9) return m_db(code, avail, want_text, upper, out);
        len = 9;
        if (want_text) {
            double dv;
            memcpy(&dv, code + 1, 8);
            snprintf(out->mnem, sizeof(out->mnem), "ldc.r8");
            snprintf(out->ops, sizeof(out->ops), "%g", dv);
        }
    } else if (op == 0x25U || op == 0x26U) {
        if (want_text) snprintf(out->mnem, sizeof(out->mnem), "%s", op == 0x25U ? "dup" : "pop");
    } else if (op == 0x27U || op == 0x28U || op == 0x29U || op == 0x6FU || op == 0x73U) {
        if (avail < 5) return m_db(code, avail, want_text, upper, out);
        len = 5;
        out->flow = (op == 0x27U) ? X86_FLOW_JMP : X86_FLOW_CALL;
        if (want_text) {
            const char *mn = (op == 0x27U) ? "jmp" : (op == 0x28U) ? "call"
                           : (op == 0x29U) ? "calli" : (op == 0x6FU) ? "callvirt" : "newobj";
            snprintf(out->mnem, sizeof(out->mnem), "%s", mn);
            snprintf(out->ops, sizeof(out->ops), "0x%08x", m_u32(code + 1));
        }
    } else if (op == 0x2AU) {
        out->flow = X86_FLOW_RET;
        if (want_text) snprintf(out->mnem, sizeof(out->mnem), "ret");
    } else if (op == 0x2BU || op == 0xDEU) {
        if (avail < 2) return m_db(code, avail, want_text, upper, out);
        len = 2;
        out->flow = X86_FLOW_JMP;
        out->target = ip + 2ULL + (uint64_t)(int64_t)(int8_t)code[1];
        out->has_target = 1;
        if (want_text) {
            snprintf(out->mnem, sizeof(out->mnem), "%s", op == 0x2BU ? "br.s" : "leave.s");
            snprintf(out->ops, sizeof(out->ops), "0x%llx", (unsigned long long)out->target);
        }
    } else if (op >= 0x2CU && op <= 0x37U) {
        if (avail < 2) return m_db(code, avail, want_text, upper, out);
        len = 2;
        out->flow = X86_FLOW_JCC;
        out->target = ip + 2ULL + (uint64_t)(int64_t)(int8_t)code[1];
        out->has_target = 1;
        if (want_text) {
            snprintf(out->mnem, sizeof(out->mnem), "%s", cil_jcc_s[op - 0x2CU]);
            snprintf(out->ops, sizeof(out->ops), "0x%llx", (unsigned long long)out->target);
        }
    } else if (op == 0x38U || op == 0xDDU) {
        if (avail < 5) return m_db(code, avail, want_text, upper, out);
        len = 5;
        out->flow = X86_FLOW_JMP;
        out->target = ip + 5ULL + (uint64_t)(int64_t)(int32_t)m_u32(code + 1);
        out->has_target = 1;
        if (want_text) {
            snprintf(out->mnem, sizeof(out->mnem), "%s", op == 0x38U ? "br" : "leave");
            snprintf(out->ops, sizeof(out->ops), "0x%llx", (unsigned long long)out->target);
        }
    } else if (op >= 0x39U && op <= 0x44U) {
        if (avail < 5) return m_db(code, avail, want_text, upper, out);
        len = 5;
        out->flow = X86_FLOW_JCC;
        out->target = ip + 5ULL + (uint64_t)(int64_t)(int32_t)m_u32(code + 1);
        out->has_target = 1;
        if (want_text) {
            snprintf(out->mnem, sizeof(out->mnem), "%s", cil_jcc_l[op - 0x39U]);
            snprintf(out->ops, sizeof(out->ops), "0x%llx", (unsigned long long)out->target);
        }
    } else if (op == 0x45U) {
        if (avail < 5) return m_db(code, avail, want_text, upper, out);
        uint32_t cnt = m_u32(code + 1);
        if (cnt > 60U || avail < 5ULL + (size_t)cnt * 4ULL) return m_db(code, avail, want_text, upper, out);
        len = 5U + (size_t)cnt * 4U;
        out->flow = X86_FLOW_JMP;
        if (want_text) {
            snprintf(out->mnem, sizeof(out->mnem), "switch");
            snprintf(out->ops, sizeof(out->ops), "%u", cnt);
        }
    } else if (op >= 0x58U && op <= 0x66U) {
        if (want_text) snprintf(out->mnem, sizeof(out->mnem), "%s", cil_alu[op - 0x58U]);
    } else if (op >= 0x67U && op <= 0x6EU) {
        static const char *const cv[8] = {"conv.i1","conv.i2","conv.i4","conv.i8","conv.r4","conv.r8","conv.u4","conv.u8"};
        if (want_text) snprintf(out->mnem, sizeof(out->mnem), "%s", cv[op - 0x67U]);
    } else if (op == 0x7AU) {
        out->flow = X86_FLOW_TRAP;
        if (want_text) snprintf(out->mnem, sizeof(out->mnem), "throw");
    } else if (op == 0x72U || op == 0x74U || op == 0x75U || op == 0x79U ||
               (op >= 0x7BU && op <= 0x81U) || op == 0x8CU || op == 0x8DU ||
               op == 0xA5U || op == 0xD0U) {
        if (avail < 5) return m_db(code, avail, want_text, upper, out);
        len = 5;
        if (want_text) {
            const char *mn = "tok";
            switch (op) {
            case 0x72U: mn = "ldstr";     break;
            case 0x74U: mn = "castclass"; break;
            case 0x75U: mn = "isinst";    break;
            case 0x79U: mn = "unbox";     break;
            case 0x7BU: mn = "ldfld";     break;
            case 0x7CU: mn = "ldflda";    break;
            case 0x7DU: mn = "stfld";     break;
            case 0x7EU: mn = "ldsfld";    break;
            case 0x7FU: mn = "ldsflda";   break;
            case 0x80U: mn = "stsfld";    break;
            case 0x81U: mn = "stobj";     break;
            case 0x8CU: mn = "box";       break;
            case 0x8DU: mn = "newarr";    break;
            case 0xA5U: mn = "unbox.any"; break;
            case 0xD0U: mn = "ldtoken";   break;
            default: break;
            }
            snprintf(out->mnem, sizeof(out->mnem), "%s", mn);
            snprintf(out->ops, sizeof(out->ops), "0x%08x", m_u32(code + 1));
        }
    } else if (op == 0x8EU) {
        if (want_text) snprintf(out->mnem, sizeof(out->mnem), "ldlen");
    } else if (want_text) {
        snprintf(out->mnem, sizeof(out->mnem), "cil");
        snprintf(out->ops, sizeof(out->ops), "0x%02x", op);
    }

    out->len = (uint8_t)len;
    m_upper(out, want_text, upper);
    return (int)len;
}
