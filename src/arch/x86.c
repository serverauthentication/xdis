#include "x86.h"
#include "x86_tbl.h"

#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    const uint8_t *code;
    size_t   avail;
    size_t   pos;
    uint64_t ip;
    int      bits;
    int      want_text;
    uint8_t  has_rex;
    uint8_t  rex;
    uint8_t  vex_w;
    uint8_t  osz;
    uint8_t  asz;
    uint8_t  rep;
    uint8_t  lock;
    uint8_t  seg;
    uint8_t  vex_l;
    uint8_t  vex_v;
    uint8_t  vex_pp;
    uint8_t  is_vex;
    uint8_t  is_evex;
    uint8_t  evex_k;
    uint8_t  evex_z;
    uint8_t  evex_b;
    uint8_t  evex_rp;
    uint8_t  evex_vp;
    uint8_t  evex_x;
    uint8_t  has_modrm;
    uint8_t  modrm;
    uint8_t  has_sib;
    uint8_t  sib;
    int64_t  disp;
    uint8_t  disp_sz;
    uint8_t  is_rip;
    int      disp8_scale;
} x86_st;

static bool x86_rd8(x86_st *s, uint8_t *v) {
    if (s->pos >= s->avail || s->pos >= 15) return false;
    *v = s->code[s->pos++];
    return true;
}

static bool x86_rd16(x86_st *s, uint16_t *v) {
    if (s->pos + 2 > s->avail || s->pos + 2 > 15) return false;
    memcpy(v, s->code + s->pos, 2);
    s->pos += 2;
    return true;
}

static bool x86_rd32(x86_st *s, uint32_t *v) {
    if (s->pos + 4 > s->avail || s->pos + 4 > 15) return false;
    memcpy(v, s->code + s->pos, 4);
    s->pos += 4;
    return true;
}

static bool x86_rd64(x86_st *s, uint64_t *v) {
    if (s->pos + 8 > s->avail || s->pos + 8 > 15) return false;
    memcpy(v, s->code + s->pos, 8);
    s->pos += 8;
    return true;
}

static int x86_w(const x86_st *s) {
    return s->is_vex ? (int)s->vex_w : ((s->rex & 8) != 0);
}

static int x86_opsize(const x86_st *s) {
    if (s->bits == 64 && x86_w(s)) return 8;
    if (s->osz && !s->is_vex) return 2;
    return 4;
}

static int x86_opsize_def64(const x86_st *s) {
    if (s->bits == 64) return s->osz ? 2 : 8;
    return s->osz ? 2 : 4;
}

static const char *x86_reg_name(const x86_st *s, int idx, int sz) {
    idx &= (s->bits == 64) ? 15 : 7;
    if (sz == 1) return s->has_rex ? x86_r8_rex[idx] : x86_r8[idx];
    if (sz == 2) return x86_r16[idx];
    if (sz == 4) return x86_r32[idx];
    return x86_r64[idx];
}

static const char *x86_ptr_name(int sz) {
    switch (sz) {
    case 1:  return "byte ptr ";
    case 2:  return "word ptr ";
    case 4:  return "dword ptr ";
    case 6:  return "fword ptr ";
    case 8:  return "qword ptr ";
    case 10: return "tbyte ptr ";
    case 16: return "xmmword ptr ";
    case 32: return "ymmword ptr ";
    case 64: return "zmmword ptr ";
    default: return "";
    }
}

static int x86_modrm_reg_gpr(const x86_st *s) {
    int r = ((s->modrm >> 3) & 7) | ((s->rex & 4) ? 8 : 0);
    return (s->bits == 64) ? r : (r & 7);
}

static int x86_modrm_reg_vec(const x86_st *s) {
    int r = ((s->modrm >> 3) & 7) | ((s->rex & 4) ? 8 : 0) | (s->evex_rp ? 16 : 0);
    return (s->bits == 64) ? r : (r & 7);
}

static int x86_modrm_rm_gpr(const x86_st *s) {
    int r = (s->modrm & 7) | ((s->rex & 1) ? 8 : 0);
    return (s->bits == 64) ? r : (r & 7);
}

static int x86_modrm_rm_vec(const x86_st *s) {
    int r = (s->modrm & 7) | ((s->rex & 1) ? 8 : 0) | (s->evex_x ? 16 : 0);
    return (s->bits == 64) ? r : (r & 7);
}

static int x86_vec_vl(const x86_st *s, int is_scalar, int supports_er) {
    if (is_scalar) return 0;
    if (s->is_evex && s->evex_b && (s->modrm >> 6) == 3 && supports_er) return 2;
    return (s->vex_l <= 2) ? (int)s->vex_l : 2;
}

static int x86_vec_bytes(int vl) {
    return (vl == 2) ? 64 : (vl == 1) ? 32 : 16;
}

static void x86_xmm_name(char *buf, size_t cap, int idx, int vl) {
    char p = (vl == 2) ? 'z' : (vl == 1) ? 'y' : 'x';
    snprintf(buf, cap, "%cmm%d", p, idx & 31);
}

static void x86_mm_name(char *buf, size_t cap, int idx) {
    snprintf(buf, cap, "mm%d", idx & 7);
}

static void x86_kreg_name(char *buf, size_t cap, int idx) {
    snprintf(buf, cap, "k%d", idx & 7);
}

static uint64_t x86_mask_imm(int64_t imm, int sz) {
    uint64_t u = (uint64_t)imm;
    if (sz == 1) return u & 0xFFULL;
    if (sz == 2) return u & 0xFFFFULL;
    if (sz == 4) return u & 0xFFFFFFFFULL;
    return u;
}

static void x86_append_mask(const x86_st *s, char *buf, size_t cap, int allow_zero) {
    if (!s->is_evex || s->evex_k == 0) return;
    size_t n = strlen(buf);
    if (n >= cap) return;
    if (s->evex_z && allow_zero)
        snprintf(buf + n, cap - n, "{k%u}{z}", (unsigned)s->evex_k);
    else
        snprintf(buf + n, cap - n, "{k%u}", (unsigned)s->evex_k);
}

static void x86_append_er(const x86_st *s, char *buf, size_t cap, int er_mode) {
    if (!s->is_evex || !s->evex_b || (s->modrm >> 6) != 3 || er_mode == 0) return;
    size_t n = strlen(buf);
    if (n >= cap) return;
    if (er_mode == 1) {
        snprintf(buf + n, cap - n, ", {sae}");
    } else {
        static const char *const rm_s[4] = {"{rn-sae}", "{rd-sae}", "{ru-sae}", "{rz-sae}"};
        snprintf(buf + n, cap - n, ", %s", rm_s[s->vex_l & 3]);
    }
}

/* EVEX compressed disp8*N helper */
enum {
    TUPLE_NONE = 0,
    TUPLE_FV,    /* Full Vector (supports broadcast: elem if b=1 else vec_bytes) */
    TUPLE_FVM,   /* Full Vector Mem (always vec_bytes) */
    TUPLE_HV,    /* Half Vector (elem if b=1 else vec_bytes/2) */
    TUPLE_HVM,   /* Half Vector Mem (vec_bytes/2) */
    TUPLE_QVM,   /* Quarter Vector Mem (vec_bytes/4) */
    TUPLE_OVM,   /* Eighth Vector Mem (vec_bytes/8) */
    TUPLE_T1S,   /* Tuple1 Scalar (elem_sz) */
    TUPLE_T2,    /* Tuple2 (2 * elem_sz) */
    TUPLE_T4,    /* Tuple4 (4 * elem_sz) */
    TUPLE_T8,    /* Tuple8 (8 * elem_sz) */
    TUPLE_M128   /* Fixed 16 bytes */
};

static int x86_evex_disp8_scale(const x86_st *s, int tuple, int vl, int elem_sz) {
    if (!s->is_evex) return 1;
    int vb = x86_vec_bytes(vl);
    switch (tuple) {
    case TUPLE_FV:   return s->evex_b ? elem_sz : vb;
    case TUPLE_FVM:  return vb;
    case TUPLE_HV:   return s->evex_b ? elem_sz : (vb / 2);
    case TUPLE_HVM:  return (vb / 2 > 0) ? (vb / 2) : 1;
    case TUPLE_QVM:  return (vb / 4 > 0) ? (vb / 4) : 1;
    case TUPLE_OVM:  return (vb / 8 > 0) ? (vb / 8) : 1;
    case TUPLE_T1S:  return elem_sz > 0 ? elem_sz : 1;
    case TUPLE_T2:   return (elem_sz > 0 ? elem_sz : 4) * 2;
    case TUPLE_T4:   return (elem_sz > 0 ? elem_sz : 4) * 4;
    case TUPLE_T8:   return (elem_sz > 0 ? elem_sz : 4) * 8;
    case TUPLE_M128: return 16;
    default:         return 1;
    }
}

static bool x86_parse_modrm(x86_st *s) {
    if (!x86_rd8(s, &s->modrm)) return false;
    s->has_modrm = 1;
    uint8_t mod = s->modrm >> 6;
    uint8_t rm  = s->modrm & 7;
    if (mod == 3) return true;

    int addr64 = (s->bits == 64 && !s->asz);
    if (s->bits == 32 && s->asz) {
        if (mod == 0 && rm == 6) {
            uint16_t d;
            if (!x86_rd16(s, &d)) return false;
            s->disp = (int16_t)d;
            s->disp_sz = 2;
        } else if (mod == 1) {
            uint8_t d;
            if (!x86_rd8(s, &d)) return false;
            s->disp = (int8_t)d;
            s->disp_sz = 1;
        } else if (mod == 2) {
            uint16_t d;
            if (!x86_rd16(s, &d)) return false;
            s->disp = (int16_t)d;
            s->disp_sz = 2;
        }
        return true;
    }

    if (rm == 4) {
        if (!x86_rd8(s, &s->sib)) return false;
        s->has_sib = 1;
        uint8_t base = s->sib & 7;
        if (mod == 0 && base == 5) {
            uint32_t d;
            if (!x86_rd32(s, &d)) return false;
            s->disp = (int32_t)d;
            s->disp_sz = 4;
            return true;
        }
    } else if (mod == 0 && rm == 5) {
        uint32_t d;
        if (!x86_rd32(s, &d)) return false;
        s->disp = (int32_t)d;
        s->disp_sz = 4;
        if (addr64) s->is_rip = 1;
        return true;
    }

    if (mod == 1) {
        uint8_t d;
        if (!x86_rd8(s, &d)) return false;
        s->disp = (int8_t)d;
        s->disp_sz = 1;
    } else if (mod == 2) {
        uint32_t d;
        if (!x86_rd32(s, &d)) return false;
        s->disp = (int32_t)d;
        s->disp_sz = 4;
    }
    return true;
}

static void x86_fmt_rm_ex(const x86_st *s, char *buf, size_t cap, int sz, int is_vec,
                          int show_ptr, int vec_vl, int bcst_elem_sz, int vsib_vl) {
    uint8_t mod = s->modrm >> 6;
    if (mod == 3) {
        if (is_vec == 3) {
            x86_mm_name(buf, cap, s->modrm & 7);
        } else if (is_vec == 2) {
            x86_kreg_name(buf, cap, s->modrm & 7);
        } else if (is_vec) {
            x86_xmm_name(buf, cap, x86_modrm_rm_vec(s), vec_vl);
        } else {
            snprintf(buf, cap, "%s", x86_reg_name(s, x86_modrm_rm_gpr(s), sz));
        }
        return;
    }

    int is_bcst = (s->is_evex && s->evex_b && bcst_elem_sz > 0);
    int mem_sz = is_bcst ? bcst_elem_sz : sz;
    int64_t disp = s->disp;
    if (s->is_evex && s->disp_sz == 1 && s->disp8_scale > 1) {
        disp *= (int64_t)s->disp8_scale;
    }

    char segp[8] = "";
    if (s->seg) snprintf(segp, sizeof(segp), "%s:", x86_seg[s->seg - 1]);
    const char *ptr = (show_ptr || is_bcst) ? x86_ptr_name(mem_sz) : "";

    char bcst_suf[16] = "";
    if (is_bcst) {
        int cnt = x86_vec_bytes(vec_vl) / bcst_elem_sz;
        if (cnt > 1) snprintf(bcst_suf, sizeof(bcst_suf), "{1to%d}", cnt);
    }

    if (s->is_rip) {
        uint64_t va = s->ip + s->pos + (uint64_t)s->disp;
        snprintf(buf, cap, "%s%s[0x%llx]%s", ptr, segp, (unsigned long long)va, bcst_suf);
        return;
    }

    char inner[56] = "";

    /* 16-bit addressing mode (0x67 prefix in 32-bit mode) */
    if (s->bits == 32 && s->asz) {
        static const char *const rm16[8] = {
            "bx+si", "bx+di", "bp+si", "bp+di", "si", "di", "bp", "bx"
        };
        if (mod == 0 && (s->modrm & 7) == 6) {
            snprintf(inner, sizeof(inner), "0x%x", (unsigned)(uint16_t)disp);
        } else {
            size_t n = (size_t)snprintf(inner, sizeof(inner), "%s", rm16[s->modrm & 7]);
            if (s->disp_sz && disp != 0) {
                if (disp < 0) snprintf(inner + n, sizeof(inner) - n, "-0x%llx", (unsigned long long)(-disp));
                else snprintf(inner + n, sizeof(inner) - n, "+0x%llx", (unsigned long long)disp);
            }
        }
        snprintf(buf, cap, "%s%s[%s]%s", ptr, segp, inner, bcst_suf);
        return;
    }

    int asz = (s->bits == 64 && !s->asz) ? 8 : 4;
    if (s->has_sib) {
        uint8_t sc   = (uint8_t)(1u << (s->sib >> 6));
        int idx      = ((s->sib >> 3) & 7) | ((s->rex & 2) ? 8 : 0);
        int base     = (s->sib & 7) | ((s->rex & 1) ? 8 : 0);
        int has_base = !(mod == 0 && (s->sib & 7) == 5);
        int has_idx  = (vsib_vl >= 0) ? 1 : (idx != 4);
        size_t n = 0;

        if (has_base) n += (size_t)snprintf(inner + n, sizeof(inner) - n, "%s", x86_reg_name(s, base, asz));
        if (has_idx) {
            if (n) n += (size_t)snprintf(inner + n, sizeof(inner) - n, "+");
            if (vsib_vl >= 0) {
                int vidx = idx | (s->evex_vp ? 16 : 0);
                if (s->bits == 32) vidx &= 7;
                char vname[12];
                x86_xmm_name(vname, sizeof(vname), vidx, vsib_vl);
                n += (size_t)snprintf(inner + n, sizeof(inner) - n, "%s", vname);
            } else {
                n += (size_t)snprintf(inner + n, sizeof(inner) - n, "%s", x86_reg_name(s, idx, asz));
            }
            if (sc > 1) n += (size_t)snprintf(inner + n, sizeof(inner) - n, "*%u", (unsigned)sc);
        }
        if (s->disp_sz) {
            if (!n) snprintf(inner, sizeof(inner), "0x%x", (uint32_t)disp);
            else if (disp < 0) snprintf(inner + n, sizeof(inner) - n, "-0x%llx", (unsigned long long)(-disp));
            else if (disp > 0) snprintf(inner + n, sizeof(inner) - n, "+0x%llx", (unsigned long long)disp);
        }
        if (!inner[0]) snprintf(inner, sizeof(inner), "0");
    } else if (mod == 0 && (s->modrm & 7) == 5) {
        snprintf(inner, sizeof(inner), "0x%x", (uint32_t)disp);
    } else {
        int rm = x86_modrm_rm_gpr(s);
        size_t n = (size_t)snprintf(inner, sizeof(inner), "%s", x86_reg_name(s, rm, asz));
        if (s->disp_sz && disp != 0) {
            if (disp < 0) snprintf(inner + n, sizeof(inner) - n, "-0x%llx", (unsigned long long)(-disp));
            else snprintf(inner + n, sizeof(inner) - n, "+0x%llx", (unsigned long long)disp);
        }
    }

    snprintf(buf, cap, "%s%s[%s]%s", ptr, segp, inner, bcst_suf);
}

static void x86_fmt_rm(const x86_st *s, char *buf, size_t cap, int sz, int is_vec, int show_ptr) {
    int vl = x86_vec_vl(s, 0, 0);
    x86_fmt_rm_ex(s, buf, cap, sz, is_vec, show_ptr, vl, 0, -1);
}

static void x86_set_mnem(x86_st *s, x86_ins *out, const char *m) {
    if (!s->want_text) return;
    if (s->lock) {
        snprintf(out->mnem, sizeof(out->mnem), "lock %s", m);
    } else {
        snprintf(out->mnem, sizeof(out->mnem), "%s", m);
    }
}

static void x86_finish_rip(const x86_st *s, x86_ins *out) {
    if (s->is_rip && !out->has_target) {
        out->target = s->ip + s->pos + (uint64_t)s->disp;
        out->has_target = 1;
        out->target_mem = 1;
    }
}

/* =========================================================================
 * x87 FPU Decoder (0xD8 .. 0xDF) — Complete & Intel DC/DE Swap-Accurate
 * ========================================================================= */
static bool x86_decode_x87(x86_st *s, uint8_t op, x86_ins *out) {
    if (!x86_parse_modrm(s)) return false;
    x86_finish_rip(s, out);

    int g   = (s->modrm >> 3) & 7;
    int mod = s->modrm >> 6;
    int rm  = s->modrm & 7;

    if (mod == 3) {
        switch (op) {
        case 0xD8: {
            static const char *const m8[8] = {"fadd","fmul","fcom","fcomp","fsub","fsubr","fdiv","fdivr"};
            x86_set_mnem(s, out, m8[g]);
            if (s->want_text) {
                if (g == 2 || g == 3) snprintf(out->ops, sizeof(out->ops), "st(%d)", rm);
                else snprintf(out->ops, sizeof(out->ops), "st(0), st(%d)", rm);
            }
            return true;
        }
        case 0xD9: {
            if (g == 0) { x86_set_mnem(s, out, "fld");  if (s->want_text) snprintf(out->ops, sizeof(out->ops), "st(%d)", rm); return true; }
            if (g == 1) { x86_set_mnem(s, out, "fxch"); if (s->want_text) snprintf(out->ops, sizeof(out->ops), "st(%d)", rm); return true; }
            if (s->modrm == 0xD0) { x86_set_mnem(s, out, "fnop"); return true; }
            if (g == 3) { x86_set_mnem(s, out, "fstp"); if (s->want_text) snprintf(out->ops, sizeof(out->ops), "st(%d)", rm); return true; }
            static const char *const d9_e0[16] = {
                "fchs","fabs",NULL,NULL,"ftst","fxam",NULL,NULL,
                "fld1","fldl2t","fldl2e","fldpi","fldlg2","fldln2","fldz",NULL
            };
            static const char *const d9_f0[16] = {
                "f2xm1","fyl2x","fptan","fpatan","fxtract","fprem1","fdecstp","fincstp",
                "fprem","fyl2xp1","fsqrt","fsincos","frndint","fscale","fsin","fcos"
            };
            if (s->modrm >= 0xE0 && s->modrm <= 0xEF && d9_e0[s->modrm - 0xE0]) {
                x86_set_mnem(s, out, d9_e0[s->modrm - 0xE0]);
                return true;
            }
            if (s->modrm >= 0xF0) {
                x86_set_mnem(s, out, d9_f0[s->modrm - 0xF0]);
                return true;
            }
            return false;
        }
        case 0xDA: {
            if (s->modrm == 0xE9) { x86_set_mnem(s, out, "fucompp"); return true; }
            if (g <= 3) {
                static const char *const mda[4] = {"fcmovb","fcmove","fcmovbe","fcmovu"};
                x86_set_mnem(s, out, mda[g]);
                if (s->want_text) snprintf(out->ops, sizeof(out->ops), "st(0), st(%d)", rm);
                return true;
            }
            return false;
        }
        case 0xDB: {
            if (g <= 3) {
                static const char *const mdb[4] = {"fcmovnb","fcmovne","fcmovnbe","fcmovnu"};
                x86_set_mnem(s, out, mdb[g]);
                if (s->want_text) snprintf(out->ops, sizeof(out->ops), "st(0), st(%d)", rm);
                return true;
            }
            if (s->modrm == 0xE2) { x86_set_mnem(s, out, "fnclex"); return true; }
            if (s->modrm == 0xE3) { x86_set_mnem(s, out, "fninit"); return true; }
            if (s->modrm == 0xE0) { x86_set_mnem(s, out, "fneni");  return true; }
            if (s->modrm == 0xE1) { x86_set_mnem(s, out, "fndisi"); return true; }
            if (s->modrm == 0xE4) { x86_set_mnem(s, out, "fnsetpm"); return true; }
            if (g == 5) {
                x86_set_mnem(s, out, "fucomi");
                if (s->want_text) snprintf(out->ops, sizeof(out->ops), "st(0), st(%d)", rm);
                return true;
            }
            if (g == 6) {
                x86_set_mnem(s, out, "fcomi");
                if (s->want_text) snprintf(out->ops, sizeof(out->ops), "st(0), st(%d)", rm);
                return true;
            }
            return false;
        }
        case 0xDC: {
            /* Intel SDM: DC mod==3 swaps fsub/fsubr (E0=fsubr, E8=fsub) and fdiv/fdivr (F0=fdivr, F8=fdiv)! */
            static const char *const mdc[8] = {"fadd","fmul","fcom","fcomp","fsubr","fsub","fdivr","fdiv"};
            x86_set_mnem(s, out, mdc[g]);
            if (s->want_text) {
                if (g == 2 || g == 3) snprintf(out->ops, sizeof(out->ops), "st(%d)", rm);
                else snprintf(out->ops, sizeof(out->ops), "st(%d), st(0)", rm);
            }
            return true;
        }
        case 0xDD: {
            static const char *const mdd[8] = {"ffree","fxch","fst","fstp","fucom","fucomp",NULL,NULL};
            if (!mdd[g]) return false;
            x86_set_mnem(s, out, mdd[g]);
            if (s->want_text) snprintf(out->ops, sizeof(out->ops), "st(%d)", rm);
            return true;
        }
        case 0xDE: {
            /* Intel SDM: DE mod==3 swaps fsubp/fsubrp (E0=fsubrp, E8=fsubp) and fdivp/fdivrp (F0=fdivrp, F8=fdivp)! */
            if (s->modrm == 0xD9) { x86_set_mnem(s, out, "fcompp"); return true; }
            static const char *const mde[8] = {"faddp","fmulp","fcomp",NULL,"fsubrp","fsubp","fdivrp","fdivp"};
            if (!mde[g]) return false;
            x86_set_mnem(s, out, mde[g]);
            if (s->want_text) {
                if (g == 2) snprintf(out->ops, sizeof(out->ops), "st(%d)", rm);
                else snprintf(out->ops, sizeof(out->ops), "st(%d), st(0)", rm);
            }
            return true;
        }
        case 0xDF: {
            if (g == 0) { x86_set_mnem(s, out, "ffreep"); if (s->want_text) snprintf(out->ops, sizeof(out->ops), "st(%d)", rm); return true; }
            if (g == 1) { x86_set_mnem(s, out, "fxch"); if (s->want_text) snprintf(out->ops, sizeof(out->ops), "st(%d)", rm); return true; }
            if (g == 2 || g == 3) { x86_set_mnem(s, out, "fstp"); if (s->want_text) snprintf(out->ops, sizeof(out->ops), "st(%d)", rm); return true; }
            if (s->modrm == 0xE0) {
                x86_set_mnem(s, out, "fnstsw");
                if (s->want_text) snprintf(out->ops, sizeof(out->ops), "ax");
                return true;
            }
            if (g == 5) {
                x86_set_mnem(s, out, "fucomip");
                if (s->want_text) snprintf(out->ops, sizeof(out->ops), "st(0), st(%d)", rm);
                return true;
            }
            if (g == 6) {
                x86_set_mnem(s, out, "fcomip");
                if (s->want_text) snprintf(out->ops, sizeof(out->ops), "st(0), st(%d)", rm);
                return true;
            }
            return false;
        }
        default:
            return false;
        }
    }

    /* mod != 3: memory operands */
    const char *m = NULL;
    int msz = 4;
    int show_ptr = 1;
    switch (op) {
    case 0xD8: {
        static const char *const t[8] = {"fadd","fmul","fcom","fcomp","fsub","fsubr","fdiv","fdivr"};
        m = t[g]; msz = 4; break;
    }
    case 0xD9: {
        static const char *const t[8] = {"fld",NULL,"fst","fstp","fldenv","fldcw","fnstenv","fnstcw"};
        m = t[g];
        if (g == 5 || g == 7) msz = 2;
        else if (g == 4 || g == 6) { msz = 0; show_ptr = 0; }
        else msz = 4;
        break;
    }
    case 0xDA: {
        static const char *const t[8] = {"fiadd","fimul","ficom","ficomp","fisub","fisubr","fidiv","fidivr"};
        m = t[g]; msz = 4; break;
    }
    case 0xDB: {
        static const char *const t[8] = {"fild","fisttp","fist","fistp",NULL,"fld",NULL,"fstp"};
        m = t[g];
        msz = (g == 5 || g == 7) ? 10 : 4;
        break;
    }
    case 0xDC: {
        static const char *const t[8] = {"fadd","fmul","fcom","fcomp","fsub","fsubr","fdiv","fdivr"};
        m = t[g]; msz = 8; break;
    }
    case 0xDD: {
        static const char *const t[8] = {"fld","fisttp","fst","fstp","frstor",NULL,"fnsave","fnstsw"};
        m = t[g];
        if (g == 7) msz = 2;
        else if (g == 4 || g == 6) { msz = 0; show_ptr = 0; }
        else msz = 8;
        break;
    }
    case 0xDE: {
        static const char *const t[8] = {"fiadd","fimul","ficom","ficomp","fisub","fisubr","fidiv","fidivr"};
        m = t[g]; msz = 2; break;
    }
    case 0xDF: {
        static const char *const t[8] = {"fild","fisttp","fist","fistp","fbld","fild","fbstp","fistp"};
        m = t[g];
        if (g == 4 || g == 6) msz = 10;
        else if (g == 5 || g == 7) msz = 8;
        else msz = 2;
        break;
    }
    default:
        break;
    }

    if (!m) return false;
    x86_set_mnem(s, out, m);
    if (s->want_text) {
        char mem[56];
        x86_fmt_rm(s, mem, sizeof(mem), msz, 0, show_ptr);
        snprintf(out->ops, sizeof(out->ops), "%s", mem);
    }
    return true;
}

/* =========================================================================
 * Map 2: 0F 38 XX (SSSE3, SSE4.1/4.2, AVX/AVX2, FMA3, BMI1/2, ADX, AVX-512)
 * ========================================================================= */
static bool x86_decode_0f38(x86_st *s, x86_ins *out) {
    uint8_t op;
    if (!x86_rd8(s, &op)) return false;
    if (!x86_parse_modrm(s)) return false;

    int w = x86_w(s);
    int pp = s->is_vex ? (int)s->vex_pp : ((s->rep == 0xF2) ? 3 : (s->rep == 0xF3) ? 2 : (s->osz ? 1 : 0));
    int mod = s->modrm >> 6;

    /* --- 1. GPR / BMI1 / BMI2 / ADX / MOVBE / CRC32 / VMX --- */
    if (!s->is_vex && (op == 0xF0 || op == 0xF1)) {
        x86_finish_rip(s, out);
        int is_crc = (s->rep == 0xF2);
        int gsz = x86_opsize(s);
        int reg = x86_modrm_reg_gpr(s);
        x86_set_mnem(s, out, is_crc ? "crc32" : "movbe");
        if (s->want_text) {
            char rm[56];
            if (is_crc) {
                int dst_sz = (s->bits == 64 && w) ? 8 : 4;
                int src_sz = (op == 0xF0) ? 1 : ((s->osz && !(s->bits == 64 && w)) ? 2 : dst_sz);
                x86_fmt_rm(s, rm, sizeof(rm), src_sz, 0, 1);
                snprintf(out->ops, sizeof(out->ops), "%s, %s", x86_reg_name(s, reg, dst_sz), rm);
            } else {
                x86_fmt_rm(s, rm, sizeof(rm), gsz, 0, 1);
                if (op == 0xF0) snprintf(out->ops, sizeof(out->ops), "%s, %s", x86_reg_name(s, reg, gsz), rm);
                else snprintf(out->ops, sizeof(out->ops), "%s, %s", rm, x86_reg_name(s, reg, gsz));
            }
        }
        return true;
    }

    if (!s->is_vex && op == 0xF6 && (pp == 1 || pp == 2)) {
        x86_finish_rip(s, out);
        int gsz = (s->bits == 64 && w) ? 8 : 4;
        int reg = x86_modrm_reg_gpr(s);
        x86_set_mnem(s, out, (pp == 2) ? "adox" : "adcx");
        if (s->want_text) {
            char rm[56];
            x86_fmt_rm(s, rm, sizeof(rm), gsz, 0, 0);
            snprintf(out->ops, sizeof(out->ops), "%s, %s", x86_reg_name(s, reg, gsz), rm);
        }
        return true;
    }

    if (!s->is_vex && (op == 0x80 || op == 0x81 || op == 0x82) && pp == 1) {
        x86_finish_rip(s, out);
        int gsz = (s->bits == 64) ? 8 : 4;
        int reg = x86_modrm_reg_gpr(s);
        x86_set_mnem(s, out, op == 0x80 ? "invept" : op == 0x81 ? "invvpid" : "invpcid");
        if (s->want_text) {
            char rm[56];
            x86_fmt_rm(s, rm, sizeof(rm), 16, 0, 1);
            snprintf(out->ops, sizeof(out->ops), "%s, %s", x86_reg_name(s, reg, gsz), rm);
        }
        return true;
    }

    if (s->is_vex && !s->is_evex && (op == 0xF2 || op == 0xF3 || op == 0xF5 || op == 0xF6 || op == 0xF7)) {
        x86_finish_rip(s, out);
        int gsz = (s->bits == 64 && w) ? 8 : 4;
        int reg = x86_modrm_reg_gpr(s);
        int vvvv = s->vex_v & ((s->bits == 64) ? 15 : 7);
        const char *m = NULL;
        int fmt = 0; /* 0 = reg, vvvv, rm; 1 = reg, rm, vvvv; 2 = vvvv, rm */
        if (op == 0xF2 && pp == 0) { m = "andn"; fmt = 0; }
        else if (op == 0xF3 && pp == 0) {
            int g = (s->modrm >> 3) & 7;
            if (g == 1) m = "blsr";
            else if (g == 2) m = "blsmsk";
            else if (g == 3) m = "blsi";
            fmt = 2;
        } else if (op == 0xF5) {
            if (pp == 0) { m = "bzhi"; fmt = 1; }
            else if (pp == 2) { m = "pext"; fmt = 0; }
            else if (pp == 3) { m = "pdep"; fmt = 0; }
        } else if (op == 0xF6 && pp == 3) {
            m = "mulx"; fmt = 0;
        } else if (op == 0xF7) {
            if (pp == 0) { m = "bextr"; fmt = 1; }
            else if (pp == 1) { m = "shlx"; fmt = 1; }
            else if (pp == 2) { m = "sarx"; fmt = 1; }
            else if (pp == 3) { m = "shrx"; fmt = 1; }
        }
        if (m) {
            x86_set_mnem(s, out, m);
            if (s->want_text) {
                char rm[56];
                x86_fmt_rm(s, rm, sizeof(rm), gsz, 0, 0);
                if (fmt == 0) snprintf(out->ops, sizeof(out->ops), "%s, %s, %s", x86_reg_name(s, reg, gsz), x86_reg_name(s, vvvv, gsz), rm);
                else if (fmt == 1) snprintf(out->ops, sizeof(out->ops), "%s, %s, %s", x86_reg_name(s, reg, gsz), rm, x86_reg_name(s, vvvv, gsz));
                else snprintf(out->ops, sizeof(out->ops), "%s, %s", x86_reg_name(s, vvvv, gsz), rm);
            }
            return true;
        }
    }

    /* --- 2. FMA3 (0F 38 96..BF, VEX/EVEX, pp == 1) --- */
    if (s->is_vex && pp == 1 && ((op >= 0x96 && op <= 0x9F) || (op >= 0xA6 && op <= 0xAF) || (op >= 0xB6 && op <= 0xBF))) {
        static const char *const fma_ord[3] = {"132", "213", "231"};
        int grp = (op - 0x96) >> 4; /* 0=132, 1=213, 2=231 */
        int sub = (op & 0x0F);      /* 6..15 */
        int is_scalar = (sub >= 8 && (sub & 1));
        const char *base = (sub == 6) ? "vfmaddsub"
                         : (sub == 7) ? "vfmsubadd"
                         : (sub <= 9) ? "vfmadd"
                         : (sub <= 11) ? "vfmsub"
                         : (sub <= 13) ? "vfnmadd"
                         : "vfnmsub";
        const char *suf = is_scalar ? (w ? "sd" : "ss") : (w ? "pd" : "ps");
        int vl = x86_vec_vl(s, is_scalar, 1);
        int elem = w ? 8 : 4;
        s->disp8_scale = x86_evex_disp8_scale(s, is_scalar ? TUPLE_T1S : TUPLE_FV, vl, elem);
        x86_finish_rip(s, out);
        if (s->want_text) {
            char mn[20], dst[24], src1[16], src2[56];
            snprintf(mn, sizeof(mn), "%s%s%s", base, fma_ord[grp], suf);
            x86_set_mnem(s, out, mn);
            x86_xmm_name(dst, sizeof(dst), x86_modrm_reg_vec(s), vl);
            x86_append_mask(s, dst, sizeof(dst), 1);
            x86_xmm_name(src1, sizeof(src1), s->vex_v, vl);
            x86_fmt_rm_ex(s, src2, sizeof(src2), is_scalar ? elem : x86_vec_bytes(vl), 1, 0, vl, is_scalar ? 0 : elem, -1);
            snprintf(out->ops, sizeof(out->ops), "%s, %s, %s", dst, src1, src2);
            x86_append_er(s, out->ops, sizeof(out->ops), 2);
        }
        return true;
    }

    /* --- 3. EVEX vpmov* downconverts (pp == 2 / F3, 0x10..0x35) --- */
    if (s->is_evex && pp == 2 && ((op >= 0x10 && op <= 0x15) || (op >= 0x20 && op <= 0x25) || (op >= 0x30 && op <= 0x35))) {
        const char *m = NULL;
        int tuple = TUPLE_HVM;
        int shift = 1; /* dst_vl = max(0, src_vl - shift) */
        int sub = op & 7;
        const char *pfx = (op < 0x20) ? "vpmovus" : (op < 0x30) ? "vpmovs" : "vpmov";
        const char *sfx = (sub == 0) ? "wb" : (sub == 1) ? "db" : (sub == 2) ? "qb"
                        : (sub == 3) ? "dw" : (sub == 4) ? "qw" : "qd";
        if (sub == 1 || sub == 4) { tuple = TUPLE_QVM; shift = 2; }
        else if (sub == 2) { tuple = TUPLE_OVM; shift = 3; }
        int src_vl = x86_vec_vl(s, 0, 0);
        int dst_vl = (src_vl >= shift) ? (src_vl - shift) : 0;
        int msz = x86_vec_bytes(src_vl) >> shift;
        s->disp8_scale = x86_evex_disp8_scale(s, tuple, src_vl, 1);
        x86_finish_rip(s, out);
        if (s->want_text) {
            char mn[20], dst[56], src[16];
            snprintf(mn, sizeof(mn), "%s%s", pfx, sfx);
            m = mn;
            x86_set_mnem(s, out, m);
            x86_fmt_rm_ex(s, dst, sizeof(dst), msz, 1, 1, dst_vl, 0, -1);
            x86_append_mask(s, dst, sizeof(dst), mod == 3);
            x86_xmm_name(src, sizeof(src), x86_modrm_reg_vec(s), src_vl);
            snprintf(out->ops, sizeof(out->ops), "%s, %s", dst, src);
        }
        return true;
    }

    /* --- 3b. EVEX mask<->vec conversions (F3 0F 38 28/29/38/39) --- */
    if (s->is_evex && pp == 2 && (op == 0x28 || op == 0x29 || op == 0x38 || op == 0x39)) {
        int vl_m = x86_vec_vl(s, 0, 0);
        int to_mask = (op == 0x29 || op == 0x39);
        const char *m_m;
        if (op == 0x28) m_m = w ? "vpmovm2w" : "vpmovm2b";
        else if (op == 0x29) m_m = w ? "vpmovw2m" : "vpmovb2m";
        else if (op == 0x38) m_m = w ? "vpmovm2q" : "vpmovm2d";
        else m_m = w ? "vpmovq2m" : "vpmovd2m";
        x86_set_mnem(s, out, m_m);
        if (s->want_text) {
            char vreg[16];
            if (to_mask) {
                x86_xmm_name(vreg, sizeof(vreg), x86_modrm_rm_vec(s), vl_m);
                snprintf(out->ops, sizeof(out->ops), "k%d, %s", (s->modrm >> 3) & 7, vreg);
            } else {
                x86_xmm_name(vreg, sizeof(vreg), x86_modrm_reg_vec(s), vl_m);
                snprintf(out->ops, sizeof(out->ops), "%s, k%d", vreg, s->modrm & 7);
            }
        }
        return true;
    }

    /* --- 4. EVEX GPR-to-vec broadcasts (0x7A/7B/7C, pp == 1) --- */
    if (s->is_evex && pp == 1 && (op == 0x7A || op == 0x7B || op == 0x7C)) {
        int vl = x86_vec_vl(s, 0, 0);
        int gsz = (op == 0x7C && w && s->bits == 64) ? 8 : 4;
        const char *m = (op == 0x7A) ? "vpbroadcastb" : (op == 0x7B) ? "vpbroadcastw" : (w ? "vpbroadcastq" : "vpbroadcastd");
        x86_finish_rip(s, out);
        x86_set_mnem(s, out, m);
        if (s->want_text) {
            char dst[24], src[56];
            x86_xmm_name(dst, sizeof(dst), x86_modrm_reg_vec(s), vl);
            x86_append_mask(s, dst, sizeof(dst), 1);
            x86_fmt_rm(s, src, sizeof(src), gsz, 0, 0);
            snprintf(out->ops, sizeof(out->ops), "%s, %s", dst, src);
        }
        return true;
    }

    /* --- 5. VSIB Gather / Scatter (0x90..93, 0xA0..A3) --- */
    if (s->is_vex && pp == 1 && ((op >= 0x90 && op <= 0x93) || (s->is_evex && op >= 0xA0 && op <= 0xA3))) {
        int is_scatter = (op >= 0xA0);
        int sub = op & 3; /* 0=dd/dq, 1=qd/qq, 2=dps/dpd, 3=qps/qpd */
        const char *m = NULL;
        if (!is_scatter) {
            if (sub == 0) m = w ? "vpgatherdq" : "vpgatherdd";
            else if (sub == 1) m = w ? "vpgatherqq" : "vpgatherqd";
            else if (sub == 2) m = w ? "vgatherdpd" : "vgatherdps";
            else m = w ? "vgatherqpd" : "vgatherqps";
        } else {
            if (sub == 0) m = w ? "vpscatterdq" : "vpscatterdd";
            else if (sub == 1) m = w ? "vpscatterqq" : "vpscatterqd";
            else if (sub == 2) m = w ? "vscatterdpd" : "vscatterdps";
            else m = w ? "vscatterqpd" : "vscatterqps";
        }
        int vl = x86_vec_vl(s, 0, 0);
        int idx_vl = vl;
        if ((sub == 0 || sub == 2) && w && vl > 0) idx_vl = vl - 1; /* 32-bit indices for 64-bit elements */
        int elem = w ? 8 : 4;
        s->disp8_scale = x86_evex_disp8_scale(s, TUPLE_T1S, vl, elem);
        x86_finish_rip(s, out);
        x86_set_mnem(s, out, m);
        if (s->want_text) {
            char vreg[24], mem[56], vmask[16];
            x86_xmm_name(vreg, sizeof(vreg), x86_modrm_reg_vec(s), vl);
            x86_fmt_rm_ex(s, mem, sizeof(mem), elem, 0, 1, vl, 0, idx_vl);
            if (s->is_evex) {
                if (is_scatter) {
                    x86_append_mask(s, mem, sizeof(mem), 0);
                    snprintf(out->ops, sizeof(out->ops), "%s, %s", mem, vreg);
                } else {
                    x86_append_mask(s, vreg, sizeof(vreg), 0);
                    snprintf(out->ops, sizeof(out->ops), "%s, %s", vreg, mem);
                }
            } else {
                x86_xmm_name(vmask, sizeof(vmask), s->vex_v, vl);
                snprintf(out->ops, sizeof(out->ops), "%s, %s, %s", vreg, mem, vmask);
            }
        }
        return true;
    }

    /* --- 6. General SIMD / AVX / AVX2 / AVX-512 / AES / SHA in 0F 38 --- */
    const char *m = NULL;
    int is_3op = 0;       /* VEX/EVEX uses vvvv as middle src */
    int is_store = 0;     /* rm is dest, reg is src */
    int dest_k = 0;       /* dest is opmask k0..k7 (EVEX) */
    int tuple = TUPLE_FVM;
    int elem = 4;
    int bcst_elem = 0;
    int src_vl_override = -1;
    int mem_sz_override = 0;
    int er_mode = 0;
    int vl = x86_vec_vl(s, 0, 0);

    switch (op) {
    case 0x00: m = "pshufb"; is_3op = 1; tuple = TUPLE_FVM; break;
    case 0x01: m = "phaddw"; is_3op = 1; break;
    case 0x02: m = "phaddd"; is_3op = 1; break;
    case 0x03: m = "phaddsw"; is_3op = 1; break;
    case 0x04: m = "pmaddubsw"; is_3op = 1; tuple = TUPLE_FVM; break;
    case 0x05: m = "phsubw"; is_3op = 1; break;
    case 0x06: m = "phsubd"; is_3op = 1; break;
    case 0x07: m = "phsubsw"; is_3op = 1; break;
    case 0x08: m = "psignb"; is_3op = 1; break;
    case 0x09: m = "psignw"; is_3op = 1; break;
    case 0x0A: m = "psignd"; is_3op = 1; break;
    case 0x0B: m = "pmulhrsw"; is_3op = 1; tuple = TUPLE_FVM; break;
    case 0x0C: m = "permilps"; is_3op = 1; tuple = TUPLE_FV; elem = 4; bcst_elem = 4; break;
    case 0x0D: m = "permilpd"; is_3op = 1; tuple = TUPLE_FV; elem = 8; bcst_elem = 8; break;
    case 0x0E: m = "testps"; break;
    case 0x0F: m = "testpd"; break;
    case 0x10: m = "pblendvb"; break;
    case 0x13: m = "cvtph2ps"; tuple = TUPLE_HVM; src_vl_override = (vl > 0 ? vl - 1 : 0); mem_sz_override = x86_vec_bytes(vl) / 2; er_mode = 1; break;
    case 0x14:
        if (s->is_evex) { m = w ? "prorvq" : "prorvd"; is_3op = 1; tuple = TUPLE_FV; elem = w ? 8 : 4; bcst_elem = elem; }
        else m = "blendvps";
        break;
    case 0x15:
        if (s->is_evex) { m = w ? "prolvq" : "prolvd"; is_3op = 1; tuple = TUPLE_FV; elem = w ? 8 : 4; bcst_elem = elem; }
        else m = "blendvpd";
        break;
    case 0x16: m = (s->is_evex && w) ? "permpd" : "permps"; is_3op = 1; tuple = TUPLE_FV; elem = w ? 8 : 4; bcst_elem = elem; break;
    case 0x17: m = "ptest"; break;
    case 0x18: m = "broadcastss"; tuple = TUPLE_T1S; elem = 4; src_vl_override = 0; mem_sz_override = 4; break;
    case 0x19:
        if (s->is_evex && !w) { m = "broadcastf32x2"; tuple = TUPLE_T2; elem = 4; src_vl_override = 0; mem_sz_override = 8; }
        else { m = "broadcastsd"; tuple = TUPLE_T1S; elem = 8; src_vl_override = 0; mem_sz_override = 8; }
        break;
    case 0x1A:
        if (s->is_evex) { m = w ? "broadcastf64x2" : "broadcastf32x4"; tuple = w ? TUPLE_T2 : TUPLE_T4; elem = w ? 8 : 4; mem_sz_override = 16; }
        else { m = "broadcastf128"; mem_sz_override = 16; }
        break;
    case 0x1B:
        if (s->is_evex) { m = w ? "broadcastf64x4" : "broadcastf32x8"; tuple = w ? TUPLE_T4 : TUPLE_T8; elem = w ? 8 : 4; mem_sz_override = 32; }
        break;
    case 0x1C: m = "pabsb"; tuple = TUPLE_FVM; break;
    case 0x1D: m = "pabsw"; tuple = TUPLE_FVM; break;
    case 0x1E: m = "pabsd"; tuple = TUPLE_FV; elem = 4; bcst_elem = 4; break;
    case 0x1F: m = "pabsq"; tuple = TUPLE_FV; elem = 8; bcst_elem = 8; break;
    case 0x20: m = "pmovsxbw"; tuple = TUPLE_HVM; src_vl_override = (vl > 0 ? vl - 1 : 0); mem_sz_override = x86_vec_bytes(vl) / 2; break;
    case 0x21: m = "pmovsxbd"; tuple = TUPLE_QVM; src_vl_override = 0; mem_sz_override = x86_vec_bytes(vl) / 4; break;
    case 0x22: m = "pmovsxbq"; tuple = TUPLE_OVM; src_vl_override = 0; mem_sz_override = x86_vec_bytes(vl) / 8; break;
    case 0x23: m = "pmovsxwd"; tuple = TUPLE_HVM; src_vl_override = (vl > 0 ? vl - 1 : 0); mem_sz_override = x86_vec_bytes(vl) / 2; break;
    case 0x24: m = "pmovsxwq"; tuple = TUPLE_QVM; src_vl_override = 0; mem_sz_override = x86_vec_bytes(vl) / 4; break;
    case 0x25: m = "pmovsxdq"; tuple = TUPLE_HVM; src_vl_override = (vl > 0 ? vl - 1 : 0); mem_sz_override = x86_vec_bytes(vl) / 2; break;
    case 0x26:
        if (s->is_evex) {
            m = (pp == 2) ? (w ? "ptestnmw" : "ptestnmb") : (w ? "ptestmw" : "ptestmb");
            is_3op = 1; dest_k = 1; tuple = TUPLE_FVM;
        }
        break;
    case 0x27:
        if (s->is_evex) {
            m = (pp == 2) ? (w ? "ptestnmq" : "ptestnmd") : (w ? "ptestmq" : "ptestmd");
            is_3op = 1; dest_k = 1; tuple = TUPLE_FV; elem = w ? 8 : 4; bcst_elem = elem;
        }
        break;
    case 0x28: m = "pmuldq"; is_3op = 1; tuple = TUPLE_FV; elem = 8; bcst_elem = 8; break;
    case 0x29: m = "pcmpeqq"; is_3op = 1; dest_k = s->is_evex; tuple = TUPLE_FV; elem = 8; bcst_elem = 8; break;
    case 0x2A: m = "movntdqa"; tuple = TUPLE_FVM; break;
    case 0x2B: m = "packusdw"; is_3op = 1; tuple = TUPLE_FV; elem = 4; bcst_elem = 4; break;
    case 0x2C:
        if (s->is_evex) { m = w ? "scalefpd" : "scalefps"; is_3op = 1; tuple = TUPLE_FV; elem = w ? 8 : 4; bcst_elem = elem; er_mode = 2; }
        else { m = "maskmovps"; is_3op = 1; }
        break;
    case 0x2D:
        if (s->is_evex) { m = w ? "scalefsd" : "scalefss"; is_3op = 1; tuple = TUPLE_T1S; elem = w ? 8 : 4; vl = 0; er_mode = 2; }
        else { m = "maskmovpd"; is_3op = 1; }
        break;
    case 0x2E: m = "maskmovps"; is_3op = 1; is_store = 1; break;
    case 0x2F: m = "maskmovpd"; is_3op = 1; is_store = 1; break;
    case 0x30: m = "pmovzxbw"; tuple = TUPLE_HVM; src_vl_override = (vl > 0 ? vl - 1 : 0); mem_sz_override = x86_vec_bytes(vl) / 2; break;
    case 0x31: m = "pmovzxbd"; tuple = TUPLE_QVM; src_vl_override = 0; mem_sz_override = x86_vec_bytes(vl) / 4; break;
    case 0x32: m = "pmovzxbq"; tuple = TUPLE_OVM; src_vl_override = 0; mem_sz_override = x86_vec_bytes(vl) / 8; break;
    case 0x33: m = "pmovzxwd"; tuple = TUPLE_HVM; src_vl_override = (vl > 0 ? vl - 1 : 0); mem_sz_override = x86_vec_bytes(vl) / 2; break;
    case 0x34: m = "pmovzxwq"; tuple = TUPLE_QVM; src_vl_override = 0; mem_sz_override = x86_vec_bytes(vl) / 4; break;
    case 0x35: m = "pmovzxdq"; tuple = TUPLE_HVM; src_vl_override = (vl > 0 ? vl - 1 : 0); mem_sz_override = x86_vec_bytes(vl) / 2; break;
    case 0x36: m = (s->is_evex && w) ? "permq" : "permd"; is_3op = 1; tuple = TUPLE_FV; elem = w ? 8 : 4; bcst_elem = elem; break;
    case 0x37: m = "pcmpgtq"; is_3op = 1; dest_k = s->is_evex; tuple = TUPLE_FV; elem = 8; bcst_elem = 8; break;
    case 0x38: m = "pminsb"; is_3op = 1; tuple = TUPLE_FVM; break;
    case 0x39: m = (s->is_evex && w) ? "pminsq" : "pminsd"; is_3op = 1; tuple = TUPLE_FV; elem = w ? 8 : 4; bcst_elem = elem; break;
    case 0x3A: m = "pminuw"; is_3op = 1; tuple = TUPLE_FVM; break;
    case 0x3B: m = (s->is_evex && w) ? "pminuq" : "pminud"; is_3op = 1; tuple = TUPLE_FV; elem = w ? 8 : 4; bcst_elem = elem; break;
    case 0x3C: m = "pmaxsb"; is_3op = 1; tuple = TUPLE_FVM; break;
    case 0x3D: m = (s->is_evex && w) ? "pmaxsq" : "pmaxsd"; is_3op = 1; tuple = TUPLE_FV; elem = w ? 8 : 4; bcst_elem = elem; break;
    case 0x3E: m = "pmaxuw"; is_3op = 1; tuple = TUPLE_FVM; break;
    case 0x3F: m = (s->is_evex && w) ? "pmaxuq" : "pmaxud"; is_3op = 1; tuple = TUPLE_FV; elem = w ? 8 : 4; bcst_elem = elem; break;
    case 0x40: m = (s->is_evex && w) ? "pmullq" : "pmulld"; is_3op = 1; tuple = TUPLE_FV; elem = w ? 8 : 4; bcst_elem = elem; break;
    case 0x41: m = "phminposuw"; break;
    case 0x45: m = w ? "psrlvq" : "psrlvd"; is_3op = 1; tuple = TUPLE_FV; elem = w ? 8 : 4; bcst_elem = elem; break;
    case 0x46: m = w ? "psravq" : "psravd"; is_3op = 1; tuple = TUPLE_FV; elem = w ? 8 : 4; bcst_elem = elem; break;
    case 0x47: m = w ? "psllvq" : "psllvd"; is_3op = 1; tuple = TUPLE_FV; elem = w ? 8 : 4; bcst_elem = elem; break;
    case 0x58: m = "pbroadcastd"; tuple = TUPLE_T1S; elem = 4; src_vl_override = 0; mem_sz_override = 4; break;
    case 0x59:
        if (s->is_evex && !w) { m = "broadcasti32x2"; tuple = TUPLE_T2; elem = 4; src_vl_override = 0; mem_sz_override = 8; }
        else { m = "pbroadcastq"; tuple = TUPLE_T1S; elem = 8; src_vl_override = 0; mem_sz_override = 8; }
        break;
    case 0x5A:
        if (s->is_evex) { m = w ? "broadcasti64x2" : "broadcasti32x4"; tuple = w ? TUPLE_T2 : TUPLE_T4; elem = w ? 8 : 4; mem_sz_override = 16; }
        else { m = "broadcasti128"; mem_sz_override = 16; }
        break;
    case 0x5B:
        if (s->is_evex) { m = w ? "broadcasti64x4" : "broadcasti32x8"; tuple = w ? TUPLE_T4 : TUPLE_T8; elem = w ? 8 : 4; mem_sz_override = 32; }
        break;
    case 0x64: if (s->is_evex) { m = w ? "pblendmq" : "pblendmd"; is_3op = 1; tuple = TUPLE_FV; elem = w ? 8 : 4; bcst_elem = elem; } break;
    case 0x65: if (s->is_evex) { m = w ? "blendmpd" : "blendmps"; is_3op = 1; tuple = TUPLE_FV; elem = w ? 8 : 4; bcst_elem = elem; } break;
    case 0x66: if (s->is_evex) { m = w ? "pblendmw" : "pblendmb"; is_3op = 1; tuple = TUPLE_FVM; } break;
    case 0x75: if (s->is_evex) { m = w ? "permi2w" : "permi2b"; is_3op = 1; tuple = TUPLE_FVM; } break;
    case 0x76: if (s->is_evex) { m = w ? "permi2q" : "permi2d"; is_3op = 1; tuple = TUPLE_FV; elem = w ? 8 : 4; bcst_elem = elem; } break;
    case 0x77: if (s->is_evex) { m = w ? "permi2pd" : "permi2ps"; is_3op = 1; tuple = TUPLE_FV; elem = w ? 8 : 4; bcst_elem = elem; } break;
    case 0x78: m = "pbroadcastb"; tuple = TUPLE_T1S; elem = 1; src_vl_override = 0; mem_sz_override = 1; break;
    case 0x79: m = "pbroadcastw"; tuple = TUPLE_T1S; elem = 2; src_vl_override = 0; mem_sz_override = 2; break;
    case 0x7D: if (s->is_evex) { m = w ? "permt2q" : "permt2d"; is_3op = 1; tuple = TUPLE_FV; elem = w ? 8 : 4; bcst_elem = elem; } break;
    case 0x7E: if (s->is_evex) { m = w ? "permt2pd" : "permt2ps"; is_3op = 1; tuple = TUPLE_FV; elem = w ? 8 : 4; bcst_elem = elem; } break;
    case 0x8C: m = w ? "pmaskmovq" : "pmaskmovd"; is_3op = 1; break;
    case 0x8E: m = w ? "pmaskmovq" : "pmaskmovd"; is_3op = 1; is_store = 1; break;
    case 0xC8: m = "sha1nexte"; break;
    case 0xC9: m = "sha1msg1"; break;
    case 0xCA: m = "sha1msg2"; break;
    case 0xCB: m = "sha256rnds2"; break;
    case 0xCC: m = "sha256msg1"; break;
    case 0xCD: m = "sha256msg2"; break;
    case 0xDB: m = "aesimc"; break;
    case 0xDC: m = "aesenc"; is_3op = 1; tuple = TUPLE_FVM; break;
    case 0xDD: m = "aesenclast"; is_3op = 1; tuple = TUPLE_FVM; break;
    case 0xDE: m = "aesdec"; is_3op = 1; tuple = TUPLE_FVM; break;
    case 0xDF: m = "aesdeclast"; is_3op = 1; tuple = TUPLE_FVM; break;
    default: break;
    }

    if (er_mode) vl = x86_vec_vl(s, (op == 0x2D), er_mode);
    s->disp8_scale = x86_evex_disp8_scale(s, tuple, vl, elem);
    x86_finish_rip(s, out);
    if (!s->want_text) return true;

    char mn[20];
    if (!m) {
        snprintf(mn, sizeof(mn), "0f38_%02x", op);
    } else if (s->is_vex) {
        snprintf(mn, sizeof(mn), "v%s", m);
    } else {
        snprintf(mn, sizeof(mn), "%s", m);
    }
    x86_set_mnem(s, out, mn);

    int reg = x86_modrm_reg_vec(s);
    int is_mmx = (!s->is_vex && pp == 0 && (op <= 0x0B || (op >= 0x1C && op <= 0x1E)));
    int rvl = (src_vl_override >= 0) ? src_vl_override : vl;
    int msz = is_mmx ? 8 : ((mem_sz_override > 0) ? mem_sz_override : x86_vec_bytes(rvl));
    char dst[24], vsrc[16], rm[56];
    if (dest_k) {
        x86_kreg_name(dst, sizeof(dst), reg);
        x86_append_mask(s, dst, sizeof(dst), 0);
    } else if (is_mmx) {
        x86_mm_name(dst, sizeof(dst), reg);
    } else {
        x86_xmm_name(dst, sizeof(dst), reg, vl);
        if (!is_store) x86_append_mask(s, dst, sizeof(dst), 1);
    }
    x86_fmt_rm_ex(s, rm, sizeof(rm), msz, is_mmx ? 3 : 1, is_store || (is_mmx && mod != 3), rvl, bcst_elem, -1);

    if (is_store && is_3op && s->is_vex) {
        x86_xmm_name(vsrc, sizeof(vsrc), s->vex_v, vl);
        snprintf(out->ops, sizeof(out->ops), "%s, %s, %s", rm, vsrc, dst);
    } else if (is_store) {
        snprintf(out->ops, sizeof(out->ops), "%s, %s", rm, dst);
    } else if (is_3op && s->is_vex) {
        x86_xmm_name(vsrc, sizeof(vsrc), s->vex_v, vl);
        snprintf(out->ops, sizeof(out->ops), "%s, %s, %s", dst, vsrc, rm);
    } else {
        snprintf(out->ops, sizeof(out->ops), "%s, %s", dst, rm);
    }
    x86_append_er(s, out->ops, sizeof(out->ops), er_mode);
    return true;
}

/* =========================================================================
 * Map 3: 0F 3A XX + imm8 (SSE4.1/4.2, AVX/AVX2, AVX-512, BMI2 rorx, KSHIFT)
 * ========================================================================= */
static bool x86_decode_0f3a(x86_st *s, x86_ins *out) {
    uint8_t op, imm;
    if (!x86_rd8(s, &op)) return false;
    if (!x86_parse_modrm(s)) return false;
    if (!x86_rd8(s, &imm)) return false;

    int w = x86_w(s);
    int w64 = (s->bits == 64 && w);
    int pp = s->is_vex ? (int)s->vex_pp : ((s->rep == 0xF2) ? 3 : (s->rep == 0xF3) ? 2 : (s->osz ? 1 : 0));
    int mod = s->modrm >> 6;

    /* --- 1. BMI2 rorx (VEX.LZ.F2.0F3A F0 /r ib) --- */
    if (s->is_vex && !s->is_evex && op == 0xF0) {
        x86_finish_rip(s, out);
        int gsz = w64 ? 8 : 4;
        int reg = x86_modrm_reg_gpr(s);
        x86_set_mnem(s, out, "rorx");
        if (s->want_text) {
            char rm[56];
            x86_fmt_rm(s, rm, sizeof(rm), gsz, 0, 0);
            snprintf(out->ops, sizeof(out->ops), "%s, %s, 0x%x", x86_reg_name(s, reg, gsz), rm, imm);
        }
        return true;
    }

    /* --- 2. AVX-512 opmask shifts (VEX.L0.66.0F3A 30..33 /r ib) --- */
    if (s->is_vex && !s->is_evex && op >= 0x30 && op <= 0x33) {
        const char *m = (op == 0x30) ? (w ? "kshiftrw" : "kshiftrb")
                      : (op == 0x31) ? (w ? "kshiftrq" : "kshiftrd")
                      : (op == 0x32) ? (w ? "kshiftlw" : "kshiftlb")
                      : (w ? "kshiftlq" : "kshiftld");
        x86_set_mnem(s, out, m);
        if (s->want_text) {
            snprintf(out->ops, sizeof(out->ops), "k%d, k%d, 0x%x", (s->modrm >> 3) & 7, s->modrm & 7, imm);
        }
        return true;
    }

    /* --- 3. Extract/Insert to/from GPR (pextrb/w/d/q, extractps, pinsrb/d/q) --- */
    if (op == 0x14 || op == 0x15 || op == 0x16 || op == 0x17) {
        const char *m = (op == 0x14) ? "pextrb"
                      : (op == 0x15) ? "pextrw"
                      : (op == 0x17) ? "extractps"
                      : (w64 ? "pextrq" : "pextrd");
        int msz = (op == 0x14) ? 1 : (op == 0x15) ? 2 : (op == 0x16 && w64) ? 8 : 4;
        int gsz = ((op == 0x14 || op == 0x15 || op == 0x16) && w64) ? 8 : 4;
        s->disp8_scale = x86_evex_disp8_scale(s, TUPLE_T1S, 0, msz);
        x86_finish_rip(s, out);
        if (s->want_text) {
            char mn[20], dst[56], src[16];
            snprintf(mn, sizeof(mn), "%s%s", s->is_vex ? "v" : "", m);
            x86_set_mnem(s, out, mn);
            x86_fmt_rm(s, dst, sizeof(dst), (mod == 3) ? gsz : msz, 0, mod != 3);
            x86_xmm_name(src, sizeof(src), x86_modrm_reg_vec(s), 0);
            snprintf(out->ops, sizeof(out->ops), "%s, %s, 0x%x", dst, src, imm);
        }
        return true;
    }

    if (op == 0x20 || op == 0x22) {
        const char *m = (op == 0x20) ? "pinsrb" : (w64 ? "pinsrq" : "pinsrd");
        int msz = (op == 0x20) ? 1 : (w64 ? 8 : 4);
        int gsz = (op == 0x22 && w64) ? 8 : 4;
        s->disp8_scale = x86_evex_disp8_scale(s, TUPLE_T1S, 0, msz);
        x86_finish_rip(s, out);
        if (s->want_text) {
            char mn[20], dst[16], vsrc[16], rm[56];
            snprintf(mn, sizeof(mn), "%s%s", s->is_vex ? "v" : "", m);
            x86_set_mnem(s, out, mn);
            x86_xmm_name(dst, sizeof(dst), x86_modrm_reg_vec(s), 0);
            x86_fmt_rm(s, rm, sizeof(rm), (mod == 3) ? gsz : msz, 0, mod != 3);
            if (s->is_vex) {
                x86_xmm_name(vsrc, sizeof(vsrc), s->vex_v, 0);
                snprintf(out->ops, sizeof(out->ops), "%s, %s, %s, 0x%x", dst, vsrc, rm, imm);
            } else {
                snprintf(out->ops, sizeof(out->ops), "%s, %s, 0x%x", dst, rm, imm);
            }
        }
        return true;
    }

    /* --- 4. VEX 4-register variable blends (vblendvps/pd, vpblendvb) --- */
    if (s->is_vex && !s->is_evex && (op == 0x4A || op == 0x4B || op == 0x4C)) {
        const char *m = (op == 0x4A) ? "vblendvps" : (op == 0x4B) ? "vblendvpd" : "vpblendvb";
        int vl = x86_vec_vl(s, 0, 0);
        x86_finish_rip(s, out);
        x86_set_mnem(s, out, m);
        if (s->want_text) {
            char dst[16], s1[16], s2[56], s3[16];
            x86_xmm_name(dst, sizeof(dst), x86_modrm_reg_vec(s), vl);
            x86_xmm_name(s1, sizeof(s1), s->vex_v, vl);
            x86_fmt_rm_ex(s, s2, sizeof(s2), x86_vec_bytes(vl), 1, 0, vl, 0, -1);
            x86_xmm_name(s3, sizeof(s3), (imm >> 4) & ((s->bits == 64) ? 15 : 7), vl);
            snprintf(out->ops, sizeof(out->ops), "%s, %s, %s, %s", dst, s1, s2, s3);
        }
        return true;
    }

    /* --- 5. General SIMD / AVX / AVX2 / AVX-512 in 0F 3A --- */
    const char *m = NULL;
    int is_3op = 0;
    int is_store = 0;
    int dest_k = 0;
    int tuple = TUPLE_FVM;
    int elem = 4;
    int bcst_elem = 0;
    int is_scalar = 0;
    int rm_vl_override = -1;
    int mem_sz_override = 0;
    int er_mode = 0;
    int vl = x86_vec_vl(s, 0, 0);

    switch (op) {
    case 0x00: m = "permq"; tuple = TUPLE_FV; elem = 8; bcst_elem = 8; break;
    case 0x01: m = "permpd"; tuple = TUPLE_FV; elem = 8; bcst_elem = 8; break;
    case 0x02: m = "pblendd"; is_3op = 1; break;
    case 0x03: if (s->is_evex) { m = w ? "alignq" : "alignd"; is_3op = 1; tuple = TUPLE_FV; elem = w ? 8 : 4; bcst_elem = elem; } break;
    case 0x04: m = "permilps"; tuple = TUPLE_FV; elem = 4; bcst_elem = 4; break;
    case 0x05: m = "permilpd"; tuple = TUPLE_FV; elem = 8; bcst_elem = 8; break;
    case 0x06: m = "perm2f128"; is_3op = 1; break;
    case 0x08: m = s->is_evex ? "rndscaleps" : "roundps"; tuple = TUPLE_FV; elem = 4; bcst_elem = 4; er_mode = 1; break;
    case 0x09: m = s->is_evex ? "rndscalepd" : "roundpd"; tuple = TUPLE_FV; elem = 8; bcst_elem = 8; er_mode = 1; break;
    case 0x0A: m = s->is_evex ? "rndscaless" : "roundss"; is_3op = 1; is_scalar = 1; tuple = TUPLE_T1S; elem = 4; er_mode = 1; break;
    case 0x0B: m = s->is_evex ? "rndscalesd" : "roundsd"; is_3op = 1; is_scalar = 1; tuple = TUPLE_T1S; elem = 8; er_mode = 1; break;
    case 0x0C: m = "blendps"; is_3op = 1; break;
    case 0x0D: m = "blendpd"; is_3op = 1; break;
    case 0x0E: m = "pblendw"; is_3op = 1; break;
    case 0x0F: m = "palignr"; is_3op = 1; tuple = TUPLE_FVM; break;
    case 0x18:
        if (s->is_evex) { m = w ? "insertf64x2" : "insertf32x4"; is_3op = 1; tuple = w ? TUPLE_T2 : TUPLE_T4; elem = w ? 8 : 4; rm_vl_override = 0; mem_sz_override = 16; }
        else { m = "insertf128"; is_3op = 1; rm_vl_override = 0; mem_sz_override = 16; }
        break;
    case 0x19:
        if (s->is_evex) { m = w ? "extractf64x2" : "extractf32x4"; is_store = 1; tuple = w ? TUPLE_T2 : TUPLE_T4; elem = w ? 8 : 4; rm_vl_override = 0; mem_sz_override = 16; }
        else { m = "extractf128"; is_store = 1; rm_vl_override = 0; mem_sz_override = 16; }
        break;
    case 0x1A: if (s->is_evex) { m = w ? "insertf64x4" : "insertf32x8"; is_3op = 1; tuple = w ? TUPLE_T4 : TUPLE_T8; elem = w ? 8 : 4; rm_vl_override = 1; mem_sz_override = 32; } break;
    case 0x1B: if (s->is_evex) { m = w ? "extractf64x4" : "extractf32x8"; is_store = 1; tuple = w ? TUPLE_T4 : TUPLE_T8; elem = w ? 8 : 4; rm_vl_override = 1; mem_sz_override = 32; } break;
    case 0x1D: m = "cvtps2ph"; is_store = 1; tuple = TUPLE_HVM; rm_vl_override = (vl > 0 ? vl - 1 : 0); mem_sz_override = x86_vec_bytes(vl) / 2; er_mode = 1; break;
    case 0x1E: if (s->is_evex) { m = w ? "pcmpuq" : "pcmpud"; is_3op = 1; dest_k = 1; tuple = TUPLE_FV; elem = w ? 8 : 4; bcst_elem = elem; } break;
    case 0x1F: if (s->is_evex) { m = w ? "pcmpq" : "pcmpd"; is_3op = 1; dest_k = 1; tuple = TUPLE_FV; elem = w ? 8 : 4; bcst_elem = elem; } break;
    case 0x21: m = "insertps"; is_3op = 1; is_scalar = 1; tuple = TUPLE_T1S; elem = 4; mem_sz_override = 4; break;
    case 0x23: if (s->is_evex) { m = w ? "shuff64x2" : "shuff32x4"; is_3op = 1; tuple = TUPLE_FV; elem = w ? 8 : 4; bcst_elem = elem; } break;
    case 0x25: if (s->is_evex) { m = w ? "pternlogq" : "pternlogd"; is_3op = 1; tuple = TUPLE_FV; elem = w ? 8 : 4; bcst_elem = elem; } break;
    case 0x26: if (s->is_evex) { m = w ? "getmantpd" : "getmantps"; tuple = TUPLE_FV; elem = w ? 8 : 4; bcst_elem = elem; er_mode = 1; } break;
    case 0x27: if (s->is_evex) { m = w ? "getmantsd" : "getmantss"; is_3op = 1; is_scalar = 1; tuple = TUPLE_T1S; elem = w ? 8 : 4; er_mode = 1; } break;
    case 0x38:
        if (s->is_evex) { m = w ? "inserti64x2" : "inserti32x4"; is_3op = 1; tuple = w ? TUPLE_T2 : TUPLE_T4; elem = w ? 8 : 4; rm_vl_override = 0; mem_sz_override = 16; }
        else { m = "inserti128"; is_3op = 1; rm_vl_override = 0; mem_sz_override = 16; }
        break;
    case 0x39:
        if (s->is_evex) { m = w ? "extracti64x2" : "extracti32x4"; is_store = 1; tuple = w ? TUPLE_T2 : TUPLE_T4; elem = w ? 8 : 4; rm_vl_override = 0; mem_sz_override = 16; }
        else { m = "extracti128"; is_store = 1; rm_vl_override = 0; mem_sz_override = 16; }
        break;
    case 0x3A: if (s->is_evex) { m = w ? "inserti64x4" : "inserti32x8"; is_3op = 1; tuple = w ? TUPLE_T4 : TUPLE_T8; elem = w ? 8 : 4; rm_vl_override = 1; mem_sz_override = 32; } break;
    case 0x3B: if (s->is_evex) { m = w ? "extracti64x4" : "extracti32x8"; is_store = 1; tuple = w ? TUPLE_T4 : TUPLE_T8; elem = w ? 8 : 4; rm_vl_override = 1; mem_sz_override = 32; } break;
    case 0x3E: if (s->is_evex) { m = w ? "pcmpuw" : "pcmpub"; is_3op = 1; dest_k = 1; tuple = TUPLE_FVM; } break;
    case 0x3F: if (s->is_evex) { m = w ? "pcmpw" : "pcmpb"; is_3op = 1; dest_k = 1; tuple = TUPLE_FVM; } break;
    case 0x40: m = "dpps"; is_3op = 1; break;
    case 0x41: m = "dppd"; is_3op = 1; break;
    case 0x42: m = "mpsadbw"; is_3op = 1; break;
    case 0x43: if (s->is_evex) { m = w ? "shufi64x2" : "shufi32x4"; is_3op = 1; tuple = TUPLE_FV; elem = w ? 8 : 4; bcst_elem = elem; } break;
    case 0x44: m = "pclmulqdq"; is_3op = 1; tuple = TUPLE_FVM; break;
    case 0x46: m = "perm2i128"; is_3op = 1; break;
    case 0x50: if (s->is_evex) { m = w ? "rangepd" : "rangeps"; is_3op = 1; tuple = TUPLE_FV; elem = w ? 8 : 4; bcst_elem = elem; er_mode = 1; } break;
    case 0x51: if (s->is_evex) { m = w ? "rangesd" : "rangess"; is_3op = 1; is_scalar = 1; tuple = TUPLE_T1S; elem = w ? 8 : 4; er_mode = 1; } break;
    case 0x54: if (s->is_evex) { m = w ? "fixupimmpd" : "fixupimmps"; is_3op = 1; tuple = TUPLE_FV; elem = w ? 8 : 4; bcst_elem = elem; er_mode = 1; } break;
    case 0x55: if (s->is_evex) { m = w ? "fixupimmsd" : "fixupimmss"; is_3op = 1; is_scalar = 1; tuple = TUPLE_T1S; elem = w ? 8 : 4; er_mode = 1; } break;
    case 0x56: if (s->is_evex) { m = w ? "reducepd" : "reduceps"; tuple = TUPLE_FV; elem = w ? 8 : 4; bcst_elem = elem; er_mode = 1; } break;
    case 0x57: if (s->is_evex) { m = w ? "reducesd" : "reducess"; is_3op = 1; is_scalar = 1; tuple = TUPLE_T1S; elem = w ? 8 : 4; er_mode = 1; } break;
    case 0x60: m = "pcmpestrm"; break;
    case 0x61: m = "pcmpestri"; break;
    case 0x62: m = "pcmpistrm"; break;
    case 0x63: m = "pcmpistri"; break;
    case 0x66: if (s->is_evex) { m = w ? "fpclasspd" : "fpclassps"; dest_k = 1; tuple = TUPLE_FV; elem = w ? 8 : 4; bcst_elem = elem; } break;
    case 0x67: if (s->is_evex) { m = w ? "fpclasssd" : "fpclassss"; dest_k = 1; is_scalar = 1; tuple = TUPLE_T1S; elem = w ? 8 : 4; } break;
    case 0xCC: m = "sha1rnds4"; break;
    case 0xDF: m = "aeskeygenassist"; break;
    default: break;
    }

    vl = x86_vec_vl(s, is_scalar, er_mode);
    s->disp8_scale = x86_evex_disp8_scale(s, tuple, vl, elem);
    x86_finish_rip(s, out);
    if (!s->want_text) return true;

    char mn[20];
    if (!m) snprintf(mn, sizeof(mn), "0f3a_%02x", op);
    else if (s->is_vex) snprintf(mn, sizeof(mn), "v%s", m);
    else snprintf(mn, sizeof(mn), "%s", m);
    x86_set_mnem(s, out, mn);

    int reg = x86_modrm_reg_vec(s);
    int is_mmx = (!s->is_vex && pp == 0 && op == 0x0F);
    int rvl = (rm_vl_override >= 0) ? rm_vl_override : vl;
    int msz = is_mmx ? 8 : ((mem_sz_override > 0) ? mem_sz_override : (is_scalar ? elem : x86_vec_bytes(rvl)));
    char vreg[24], vsrc[16], rm[56];
    if (dest_k) {
        x86_kreg_name(vreg, sizeof(vreg), reg);
        x86_append_mask(s, vreg, sizeof(vreg), 0);
    } else if (is_mmx) {
        x86_mm_name(vreg, sizeof(vreg), reg);
    } else {
        x86_xmm_name(vreg, sizeof(vreg), reg, vl);
        if (!is_store) x86_append_mask(s, vreg, sizeof(vreg), 1);
    }
    x86_fmt_rm_ex(s, rm, sizeof(rm), msz, is_mmx ? 3 : 1, is_store || (is_mmx && mod != 3), rvl, bcst_elem, -1);
    if (is_store) {
        x86_append_mask(s, rm, sizeof(rm), mod == 3);
        snprintf(out->ops, sizeof(out->ops), "%s, %s, 0x%x", rm, vreg, imm);
    } else if (is_3op && s->is_vex) {
        x86_xmm_name(vsrc, sizeof(vsrc), s->vex_v, vl);
        snprintf(out->ops, sizeof(out->ops), "%s, %s, %s, 0x%x", vreg, vsrc, rm, imm);
    } else {
        snprintf(out->ops, sizeof(out->ops), "%s, %s, 0x%x", vreg, rm, imm);
    }
    x86_append_er(s, out->ops, sizeof(out->ops), er_mode);
    return true;
}

/* =========================================================================
 * Map 1: 0F XX (Legacy 2-byte, SSE/SSE2/SSE3, AVX/AVX-512, Opmask k*)
 * ========================================================================= */
static bool x86_decode_0f(x86_st *s, x86_ins *out) {
    uint8_t op;
    if (!x86_rd8(s, &op)) return false;

    if (op == 0x38) return x86_decode_0f38(s, out);
    if (op == 0x3A) return x86_decode_0f3a(s, out);

    int w = x86_w(s);
    int pp = s->is_vex ? (int)s->vex_pp : ((s->rep == 0xF2) ? 3 : (s->rep == 0xF3) ? 2 : (s->osz ? 1 : 0));

    /* --- 1. Conditional near jumps (0F 80..8F) --- */
    if (!s->is_vex && op >= 0x80 && op <= 0x8F) {
        int64_t rel = 0;
        if (s->bits == 32 && s->osz) {
            uint16_t v;
            if (!x86_rd16(s, &v)) return false;
            rel = (int16_t)v;
        } else {
            uint32_t v;
            if (!x86_rd32(s, &v)) return false;
            rel = (int32_t)v;
        }
        out->flow = X86_FLOW_JCC;
        out->target = s->ip + s->pos + (uint64_t)rel;
        out->has_target = 1;
        if (s->want_text) {
            snprintf(out->mnem, sizeof(out->mnem), "j%s", x86_cc[op & 15]);
            snprintf(out->ops, sizeof(out->ops), "0x%llx", (unsigned long long)out->target);
        }
        return true;
    }

    /* --- 2. Zero-ModRM 0F opcodes --- */
    if (op == 0x05 || op == 0x06 || op == 0x07 || op == 0x08 || op == 0x09 || op == 0x0B ||
        op == 0x0E || op == 0x30 || op == 0x31 || op == 0x32 || op == 0x33 || op == 0x34 ||
        op == 0x35 || op == 0x37 || op == 0x77 || op == 0xA0 || op == 0xA1 || op == 0xA2 ||
        op == 0xA8 || op == 0xA9 || op == 0xAA) {
        const char *m = "??";
        if (op == 0x05) m = "syscall";
        else if (op == 0x06) m = "clts";
        else if (op == 0x07) m = "sysret";
        else if (op == 0x08) m = "invd";
        else if (op == 0x09) m = "wbinvd";
        else if (op == 0x0B) { m = "ud2"; out->flow = X86_FLOW_TRAP; }
        else if (op == 0x0E) m = "femms";
        else if (op == 0x30) m = "wrmsr";
        else if (op == 0x31) m = "rdtsc";
        else if (op == 0x32) m = "rdmsr";
        else if (op == 0x33) m = "rdpmc";
        else if (op == 0x34) m = "sysenter";
        else if (op == 0x35) m = "sysexit";
        else if (op == 0x37) m = "getsec";
        else if (op == 0x77) m = s->is_vex ? (s->vex_l ? "vzeroall" : "vzeroupper") : "emms";
        else if (op == 0xA0) { x86_set_mnem(s, out, "push"); if (s->want_text) snprintf(out->ops, sizeof(out->ops), "fs"); return true; }
        else if (op == 0xA1) { x86_set_mnem(s, out, "pop");  if (s->want_text) snprintf(out->ops, sizeof(out->ops), "fs"); return true; }
        else if (op == 0xA8) { x86_set_mnem(s, out, "push"); if (s->want_text) snprintf(out->ops, sizeof(out->ops), "gs"); return true; }
        else if (op == 0xA9) { x86_set_mnem(s, out, "pop");  if (s->want_text) snprintf(out->ops, sizeof(out->ops), "gs"); return true; }
        else if (op == 0xA2) m = "cpuid";
        else if (op == 0xAA) m = "rsm";
        x86_set_mnem(s, out, m);
        return true;
    }

    if (!s->is_vex && op >= 0xC8 && op <= 0xCF) {
        int reg = (op & 7) | ((s->rex & 1) ? 8 : 0);
        if (s->bits == 32) reg &= 7;
        x86_set_mnem(s, out, "bswap");
        if (s->want_text) snprintf(out->ops, sizeof(out->ops), "%s", x86_reg_name(s, reg, x86_opsize(s)));
        return true;
    }

    /* ENDBR64 / ENDBR32 */
    if (!s->is_vex && op == 0x1E && s->rep == 0xF3 && s->pos < s->avail) {
        uint8_t b = s->code[s->pos];
        if (b == 0xFA || b == 0xFB) {
            s->pos++;
            x86_set_mnem(s, out, b == 0xFA ? "endbr64" : "endbr32");
            return true;
        }
    }

    if (!x86_parse_modrm(s)) return false;
    int mod = s->modrm >> 6;
    int reg_g = x86_modrm_reg_gpr(s);
    int reg_v = x86_modrm_reg_vec(s);
    int sz  = x86_opsize(s);

    /* --- 3. 3DNow! (0F 0F /r ib) --- */
    if (!s->is_vex && op == 0x0F) {
        uint8_t suf;
        if (!x86_rd8(s, &suf)) return false;
        x86_finish_rip(s, out);
        const char *m = "3dnow";
        switch (suf) {
        case 0x0C: m = "pi2fw"; break;
        case 0x0D: m = "pi2fd"; break;
        case 0x1C: m = "pf2iw"; break;
        case 0x1D: m = "pf2id"; break;
        case 0x8A: m = "pfnacc"; break;
        case 0x8E: m = "pfpnacc"; break;
        case 0x90: m = "pfcmpge"; break;
        case 0x94: m = "pfmin"; break;
        case 0x96: m = "pfrcp"; break;
        case 0x97: m = "pfrsqrt"; break;
        case 0x9A: m = "pfsub"; break;
        case 0x9E: m = "pfadd"; break;
        case 0xA0: m = "pfcmpgt"; break;
        case 0xA4: m = "pfmax"; break;
        case 0xA6: m = "pfrcpit1"; break;
        case 0xA7: m = "pfrsqit1"; break;
        case 0xAA: m = "pfsubr"; break;
        case 0xAE: m = "pfacc"; break;
        case 0xB0: m = "pfcmpeq"; break;
        case 0xB4: m = "pfmul"; break;
        case 0xB6: m = "pfrcpit2"; break;
        case 0xB7: m = "pmulhrw"; break;
        case 0xBB: m = "pswapd"; break;
        case 0xBF: m = "pavgusb"; break;
        default: break;
        }
        x86_set_mnem(s, out, m);
        if (s->want_text) {
            char rm[56];
            if (mod == 3) snprintf(rm, sizeof(rm), "mm%d", s->modrm & 7);
            else x86_fmt_rm(s, rm, sizeof(rm), 8, 0, 1);
            snprintf(out->ops, sizeof(out->ops), "mm%d, %s", (s->modrm >> 3) & 7, rm);
        }
        return true;
    }

    /* --- 4. System / Prefetch / NOP / CET --- */
    if (!s->is_vex && op == 0x00) {
        x86_finish_rip(s, out);
        static const char *const g6[8] = {"sldt","str","lldt","ltr","verr","verw","jmpe",NULL};
        int g = (s->modrm >> 3) & 7;
        if (!g6[g]) return false;
        x86_set_mnem(s, out, g6[g]);
        if (s->want_text) {
            char rm[56];
            x86_fmt_rm(s, rm, sizeof(rm), (mod == 3 && g <= 1) ? sz : 2, 0, mod != 3);
            snprintf(out->ops, sizeof(out->ops), "%s", rm);
        }
        return true;
    }

    if (!s->is_vex && op == 0x01) {
        x86_finish_rip(s, out);
        const char *m = NULL;
        int g = (s->modrm >> 3) & 7;
        if (mod == 3) {
            switch (s->modrm) {
            case 0xC1: m = "vmcall"; break;
            case 0xC2: m = "vmlaunch"; break;
            case 0xC3: m = "vmresume"; break;
            case 0xC4: m = "vmxoff"; break;
            case 0xC5: m = "pconfig"; break;
            case 0xC6: m = "wrmsrns"; break;
            case 0xC8: m = "monitor"; break;
            case 0xC9: m = "mwait"; break;
            case 0xCA: m = "clac"; break;
            case 0xCB: m = "stac"; break;
            case 0xCF: m = "encls"; break;
            case 0xD0: m = "xgetbv"; break;
            case 0xD1: m = "xsetbv"; break;
            case 0xD4: m = "vmfunc"; break;
            case 0xD5: m = "xend"; break;
            case 0xD6: m = "xtest"; break;
            case 0xD7: m = "enclu"; break;
            case 0xD8: m = "vmrun"; break;
            case 0xD9: m = "vmmcall"; break;
            case 0xDA: m = "vmload"; break;
            case 0xDB: m = "vmsave"; break;
            case 0xDC: m = "stgi"; break;
            case 0xDD: m = "clgi"; break;
            case 0xDE: m = "skinit"; break;
            case 0xDF: m = "invlpga"; break;
            case 0xE8: m = "serialize"; break;
            case 0xEE: m = "rdpkru"; break;
            case 0xEF: m = "wrpkru"; break;
            case 0xF8: m = "swapgs"; break;
            case 0xF9: m = "rdtscp"; break;
            case 0xFA: m = "monitorx"; break;
            case 0xFB: m = "mwaitx"; break;
            case 0xFC: m = "clzero"; break;
            case 0xFD: m = "rdpru"; break;
            default:
                if (g == 4) m = "smsw";
                else if (g == 6) m = "lmsw";
                else m = "grp01";
                break;
            }
            x86_set_mnem(s, out, m);
            if (s->want_text && (strcmp(m, "smsw") == 0 || strcmp(m, "lmsw") == 0)) {
                char rm[56];
                x86_fmt_rm(s, rm, sizeof(rm), (g == 4) ? sz : 2, 0, 0);
                snprintf(out->ops, sizeof(out->ops), "%s", rm);
            }
        } else {
            static const char *const g7[8] = {"sgdt","sidt","lgdt","lidt","smsw",NULL,"lmsw","invlpg"};
            m = g7[g] ? g7[g] : "grp01";
            x86_set_mnem(s, out, m);
            if (s->want_text) {
                char rm[56];
                x86_fmt_rm(s, rm, sizeof(rm), (g == 4 || g == 6) ? 2 : 0, 0, (g == 4 || g == 6));
                snprintf(out->ops, sizeof(out->ops), "%s", rm);
            }
        }
        return true;
    }

    if (!s->is_vex && (op == 0x02 || op == 0x03)) {
        x86_finish_rip(s, out);
        x86_set_mnem(s, out, op == 0x02 ? "lar" : "lsl");
        if (s->want_text) {
            char rm[56];
            x86_fmt_rm(s, rm, sizeof(rm), (mod == 3) ? sz : 2, 0, mod != 3);
            snprintf(out->ops, sizeof(out->ops), "%s, %s", x86_reg_name(s, reg_g, sz), rm);
        }
        return true;
    }

    if (!s->is_vex && op == 0x0D) {
        x86_finish_rip(s, out);
        int g = (s->modrm >> 3) & 7;
        x86_set_mnem(s, out, (g == 1) ? "prefetchw" : (g == 2) ? "prefetchwt1" : "prefetch");
        if (s->want_text) {
            char rm[56];
            x86_fmt_rm(s, rm, sizeof(rm), 1, 0, 0);
            snprintf(out->ops, sizeof(out->ops), "%s", rm);
        }
        return true;
    }

    if (!s->is_vex && op == 0x18) {
        x86_finish_rip(s, out);
        int g = (s->modrm >> 3) & 7;
        static const char *const pf[4] = {"prefetchnta","prefetcht0","prefetcht1","prefetcht2"};
        x86_set_mnem(s, out, (g < 4) ? pf[g] : "nop");
        if (s->want_text && g < 4) {
            char rm[56];
            x86_fmt_rm(s, rm, sizeof(rm), 1, 0, 0);
            snprintf(out->ops, sizeof(out->ops), "%s", rm);
        }
        return true;
    }

    if (!s->is_vex && (op >= 0x19 && op <= 0x1F)) {
        x86_finish_rip(s, out);
        if (op == 0x1E && s->rep == 0xF3 && mod == 3 && ((s->modrm >> 3) & 7) == 1) {
            x86_set_mnem(s, out, (s->bits == 64 && w) ? "rdsspq" : "rdsspd");
            if (s->want_text) snprintf(out->ops, sizeof(out->ops), "%s", x86_reg_name(s, x86_modrm_rm_gpr(s), (s->bits == 64 && w) ? 8 : 4));
            return true;
        }
        x86_set_mnem(s, out, "nop");
        return true;
    }

    if (!s->is_vex && op >= 0x20 && op <= 0x23) {
        int rm = x86_modrm_rm_gpr(s);
        int gsz = (s->bits == 64) ? 8 : 4;
        int is_dr = (op == 0x21 || op == 0x23);
        int to_cr = (op >= 0x22);
        x86_set_mnem(s, out, "mov");
        if (s->want_text) {
            if (to_cr) snprintf(out->ops, sizeof(out->ops), "%cr%d, %s", is_dr ? 'd' : 'c', reg_g, x86_reg_name(s, rm, gsz));
            else snprintf(out->ops, sizeof(out->ops), "%s, %cr%d", x86_reg_name(s, rm, gsz), is_dr ? 'd' : 'c', reg_g);
        }
        return true;
    }

    /* --- 5. AVX-512 Opmask k* instructions (VEX 0F 41..4B, 90..99) --- */
    if (s->is_vex && !s->is_evex && ((op >= 0x41 && op <= 0x4B) || (op >= 0x90 && op <= 0x99))) {
        const char *base = NULL;
        int kind = 0; /* 0=3op k,k,k; 1=2op k,k; 2=kmov load; 3=kmov store; 4=kmov from gpr; 5=kmov to gpr */
        char wsuf = (pp == 1) ? (w ? 'd' : 'b') : (w ? 'q' : 'w');
        if (op == 0x41) { base = "kand"; kind = 0; }
        else if (op == 0x42) { base = "kandn"; kind = 0; }
        else if (op == 0x44) { base = "knot"; kind = 1; }
        else if (op == 0x45) { base = "kor"; kind = 0; }
        else if (op == 0x46) { base = "kxnor"; kind = 0; }
        else if (op == 0x47) { base = "kxor"; kind = 0; }
        else if (op == 0x4A) { base = "kadd"; kind = 0; }
        else if (op == 0x4B) {
            x86_set_mnem(s, out, (pp == 1) ? "kunpckbw" : (w ? "kunpckdq" : "kunpckwd"));
            if (s->want_text) snprintf(out->ops, sizeof(out->ops), "k%d, k%d, k%d", (s->modrm >> 3) & 7, s->vex_v & 7, s->modrm & 7);
            return true;
        }
        else if (op == 0x90) { base = "kmov"; kind = 2; }
        else if (op == 0x91) { base = "kmov"; kind = 3; }
        else if (op == 0x92) { base = "kmov"; kind = 4; wsuf = (pp == 3) ? (w ? 'q' : 'd') : (pp == 1 ? 'b' : 'w'); }
        else if (op == 0x93) { base = "kmov"; kind = 5; wsuf = (pp == 3) ? (w ? 'q' : 'd') : (pp == 1 ? 'b' : 'w'); }
        else if (op == 0x98) { base = "kortest"; kind = 1; }
        else if (op == 0x99) { base = "ktest"; kind = 1; }
        if (base) {
            x86_finish_rip(s, out);
            char mn[20];
            snprintf(mn, sizeof(mn), "%s%c", base, wsuf);
            x86_set_mnem(s, out, mn);
            if (s->want_text) {
                int kr = (s->modrm >> 3) & 7;
                int kv = s->vex_v & 7;
                int krm = s->modrm & 7;
                int msz = (wsuf == 'b') ? 1 : (wsuf == 'w') ? 2 : (wsuf == 'd') ? 4 : 8;
                char rm[56];
                if (kind == 0) snprintf(out->ops, sizeof(out->ops), "k%d, k%d, k%d", kr, kv, krm);
                else if (kind == 1) snprintf(out->ops, sizeof(out->ops), "k%d, k%d", kr, krm);
                else if (kind == 2) {
                    x86_fmt_rm_ex(s, rm, sizeof(rm), msz, 2, 1, 0, 0, -1);
                    snprintf(out->ops, sizeof(out->ops), "k%d, %s", kr, rm);
                } else if (kind == 3) {
                    x86_fmt_rm_ex(s, rm, sizeof(rm), msz, 2, 1, 0, 0, -1);
                    snprintf(out->ops, sizeof(out->ops), "%s, k%d", rm, kr);
                } else if (kind == 4) {
                    int gsz = (wsuf == 'q' && s->bits == 64) ? 8 : 4;
                    snprintf(out->ops, sizeof(out->ops), "k%d, %s", kr, x86_reg_name(s, x86_modrm_rm_gpr(s), gsz));
                } else {
                    int gsz = (wsuf == 'q' && s->bits == 64) ? 8 : 4;
                    snprintf(out->ops, sizeof(out->ops), "%s, k%d", x86_reg_name(s, reg_g, gsz), krm);
                }
            }
            return true;
        }
    }

    /* --- 6. Group 9 (0F C7), Group 15 (0F AE), CMOV, SETCC, MOVZX/SX, BITOPS, SHLD/SHRD --- */
    if (!s->is_vex && op == 0xC7) {
        x86_finish_rip(s, out);
        int g = (s->modrm >> 3) & 7;
        const char *m = "grp9";
        int msz = sz;
        if (mod == 3) {
            if (g == 6) m = "rdrand";
            else if (g == 7) m = (s->rep == 0xF3) ? "rdpid" : "rdseed";
            if (g == 7 && s->rep == 0xF3) msz = (s->bits == 64) ? 8 : 4;
        } else {
            if (g == 1) { m = (s->bits == 64 && w) ? "cmpxchg16b" : "cmpxchg8b"; msz = (s->bits == 64 && w) ? 16 : 8; }
            else if (g == 3) m = "xrstors";
            else if (g == 4) m = "xsavec";
            else if (g == 5) m = "xsaves";
            else if (g == 6) m = (s->rep == 0xF3) ? "vmxon" : (s->osz ? "vmclear" : "vmptrld");
            else if (g == 7) m = "vmptrst";
        }
        x86_set_mnem(s, out, m);
        if (s->want_text) {
            char rm[56];
            x86_fmt_rm(s, rm, sizeof(rm), msz, 0, (mod != 3 && g == 1));
            snprintf(out->ops, sizeof(out->ops), "%s", rm);
        }
        return true;
    }

    if (op == 0xAE) {
        x86_finish_rip(s, out);
        int g = (s->modrm >> 3) & 7;
        const char *m = "grp15";
        if (s->is_vex && (g == 2 || g == 3)) {
            m = (g == 2) ? "vldmxcsr" : "vstmxcsr";
            x86_set_mnem(s, out, m);
            if (s->want_text) {
                char rm[56];
                x86_fmt_rm(s, rm, sizeof(rm), 4, 0, 1);
                snprintf(out->ops, sizeof(out->ops), "%s", rm);
            }
            return true;
        }
        if (mod == 3) {
            if (s->rep == 0xF3 && g <= 3) {
                static const char *const fsgs[4] = {"rdfsbase","rdgsbase","wrfsbase","wrgsbase"};
                m = fsgs[g];
                x86_set_mnem(s, out, m);
                if (s->want_text) snprintf(out->ops, sizeof(out->ops), "%s", x86_reg_name(s, x86_modrm_rm_gpr(s), (s->bits == 64 && w) ? 8 : 4));
                return true;
            }
            if (g == 5) m = (s->rep == 0xF3) ? ((s->bits == 64 && w) ? "incsspq" : "incsspd") : "lfence";
            else if (g == 6) m = (s->osz) ? "tpause" : (s->rep == 0xF3) ? "umwait" : (s->rep == 0xF2) ? "umonitor" : "mfence";
            else if (g == 7) m = "sfence";
            x86_set_mnem(s, out, m);
            return true;
        } else {
            if (g == 0) m = "fxsave";
            else if (g == 1) m = "fxrstor";
            else if (g == 2) m = "ldmxcsr";
            else if (g == 3) m = "stmxcsr";
            else if (g == 4) m = (s->rep == 0xF3) ? "ptwrite" : "xsave";
            else if (g == 5) m = "xrstor";
            else if (g == 6) m = s->osz ? "clwb" : "xsaveopt";
            else if (g == 7) m = s->osz ? "clflushopt" : "clflush";
            x86_set_mnem(s, out, m);
            if (s->want_text) {
                char rm[56];
                x86_fmt_rm(s, rm, sizeof(rm), (g == 2 || g == 3) ? 4 : 1, 0, (g == 2 || g == 3));
                snprintf(out->ops, sizeof(out->ops), "%s", rm);
            }
            return true;
        }
    }

    if (!s->is_vex && op >= 0x40 && op <= 0x4F) {
        x86_finish_rip(s, out);
        if (s->want_text) {
            char rhs[56];
            x86_fmt_rm(s, rhs, sizeof(rhs), sz, 0, 0);
            snprintf(out->mnem, sizeof(out->mnem), "cmov%s", x86_cc[op & 15]);
            snprintf(out->ops, sizeof(out->ops), "%s, %s", x86_reg_name(s, reg_g, sz), rhs);
        }
        return true;
    }

    if (!s->is_vex && op >= 0x90 && op <= 0x9F) {
        x86_finish_rip(s, out);
        if (s->want_text) {
            char rm[56];
            x86_fmt_rm(s, rm, sizeof(rm), 1, 0, 1);
            snprintf(out->mnem, sizeof(out->mnem), "set%s", x86_cc[op & 15]);
            snprintf(out->ops, sizeof(out->ops), "%s", rm);
        }
        return true;
    }

    if (!s->is_vex && (op == 0xB2 || op == 0xB4 || op == 0xB5)) {
        x86_finish_rip(s, out);
        x86_set_mnem(s, out, op == 0xB2 ? "lss" : op == 0xB4 ? "lfs" : "lgs");
        if (s->want_text) {
            char rhs[56];
            x86_fmt_rm(s, rhs, sizeof(rhs), (sz == 2) ? 4 : 6, 0, 1);
            snprintf(out->ops, sizeof(out->ops), "%s, %s", x86_reg_name(s, reg_g, sz), rhs);
        }
        return true;
    }

    if (!s->is_vex && (op == 0xB6 || op == 0xB7 || op == 0xBE || op == 0xBF)) {
        int src_sz = (op == 0xB6 || op == 0xBE) ? 1 : 2;
        x86_finish_rip(s, out);
        if (s->want_text) {
            char rhs[56];
            x86_fmt_rm(s, rhs, sizeof(rhs), src_sz, 0, 1);
            x86_set_mnem(s, out, (op < 0xB8) ? "movzx" : "movsx");
            snprintf(out->ops, sizeof(out->ops), "%s, %s", x86_reg_name(s, reg_g, sz), rhs);
        }
        return true;
    }

    if (!s->is_vex && (op == 0xB9 || op == 0xFF)) {
        x86_finish_rip(s, out);
        out->flow = X86_FLOW_TRAP;
        x86_set_mnem(s, out, op == 0xB9 ? "ud1" : "ud0");
        if (s->want_text) {
            char rhs[56];
            x86_fmt_rm(s, rhs, sizeof(rhs), sz, 0, 0);
            snprintf(out->ops, sizeof(out->ops), "%s, %s", x86_reg_name(s, reg_g, sz), rhs);
        }
        return true;
    }

    if (!s->is_vex && (op == 0xAF || op == 0xBC || op == 0xBD || op == 0xB8)) {
        x86_finish_rip(s, out);
        if (s->want_text) {
            const char *m = "imul";
            if (op == 0xBC) m = (s->rep == 0xF3) ? "tzcnt" : "bsf";
            else if (op == 0xBD) m = (s->rep == 0xF3) ? "lzcnt" : "bsr";
            else if (op == 0xB8) m = (s->rep == 0xF3) ? "popcnt" : "jmpe";
            char rhs[56];
            x86_fmt_rm(s, rhs, sizeof(rhs), sz, 0, 0);
            x86_set_mnem(s, out, m);
            snprintf(out->ops, sizeof(out->ops), "%s, %s", x86_reg_name(s, reg_g, sz), rhs);
        }
        return true;
    }

    if (!s->is_vex && (op == 0xB0 || op == 0xB1 || op == 0xC0 || op == 0xC1)) {
        int osz = (op == 0xB0 || op == 0xC0) ? 1 : sz;
        x86_finish_rip(s, out);
        if (s->want_text) {
            char lhs[56];
            x86_fmt_rm(s, lhs, sizeof(lhs), osz, 0, 1);
            x86_set_mnem(s, out, (op < 0xC0) ? "cmpxchg" : "xadd");
            snprintf(out->ops, sizeof(out->ops), "%s, %s", lhs, x86_reg_name(s, reg_g, osz));
        }
        return true;
    }

    if (!s->is_vex && (op == 0xA3 || op == 0xAB || op == 0xB3 || op == 0xBB)) {
        const char *m = (op == 0xA3) ? "bt" : (op == 0xAB) ? "bts" : (op == 0xB3) ? "btr" : "btc";
        x86_finish_rip(s, out);
        if (s->want_text) {
            char lhs[56];
            x86_fmt_rm(s, lhs, sizeof(lhs), sz, 0, 1);
            x86_set_mnem(s, out, m);
            snprintf(out->ops, sizeof(out->ops), "%s, %s", lhs, x86_reg_name(s, reg_g, sz));
        }
        return true;
    }

    if (!s->is_vex && op == 0xBA) {
        uint8_t imm;
        if (!x86_rd8(s, &imm)) return false;
        x86_finish_rip(s, out);
        if (s->want_text) {
            char lhs[56];
            x86_fmt_rm(s, lhs, sizeof(lhs), sz, 0, 1);
            x86_set_mnem(s, out, x86_bt[reg_g & 7]);
            snprintf(out->ops, sizeof(out->ops), "%s, 0x%x", lhs, imm);
        }
        return true;
    }

    if (!s->is_vex && (op == 0xA4 || op == 0xA5 || op == 0xAC || op == 0xAD)) {
        uint8_t imm = 0;
        int has_imm = (op == 0xA4 || op == 0xAC);
        if (has_imm && !x86_rd8(s, &imm)) return false;
        x86_finish_rip(s, out);
        if (s->want_text) {
            char lhs[56];
            x86_fmt_rm(s, lhs, sizeof(lhs), sz, 0, 1);
            x86_set_mnem(s, out, (op < 0xA8) ? "shld" : "shrd");
            if (has_imm) snprintf(out->ops, sizeof(out->ops), "%s, %s, 0x%x", lhs, x86_reg_name(s, reg_g, sz), imm);
            else snprintf(out->ops, sizeof(out->ops), "%s, %s, cl", lhs, x86_reg_name(s, reg_g, sz));
        }
        return true;
    }

    if (!s->is_vex && op == 0xC3) {
        x86_finish_rip(s, out);
        x86_set_mnem(s, out, "movnti");
        if (s->want_text) {
            char lhs[56];
            int gsz = (s->bits == 64 && w) ? 8 : 4;
            x86_fmt_rm(s, lhs, sizeof(lhs), gsz, 0, 1);
            snprintf(out->ops, sizeof(out->ops), "%s, %s", lhs, x86_reg_name(s, reg_g, gsz));
        }
        return true;
    }

    if (!s->is_vex && (op == 0x78 || op == 0x79) && pp == 0) {
        x86_finish_rip(s, out);
        int gsz = (s->bits == 64) ? 8 : 4;
        x86_set_mnem(s, out, op == 0x78 ? "vmread" : "vmwrite");
        if (s->want_text) {
            char rm[56];
            x86_fmt_rm(s, rm, sizeof(rm), gsz, 0, 1);
            if (op == 0x78) snprintf(out->ops, sizeof(out->ops), "%s, %s", rm, x86_reg_name(s, reg_g, gsz));
            else snprintf(out->ops, sizeof(out->ops), "%s, %s", x86_reg_name(s, reg_g, gsz), rm);
        }
        return true;
    }

    /* --- 7. Special SIMD with GPR or imm8 in Map 1 (0F) --- */
    if (op == 0x50 || op == 0xD7) {
        int vl = x86_vec_vl(s, 0, 0);
        int gsz = (s->bits == 64 && w) ? 8 : 4;
        int is_mmx = (!s->is_vex && pp == 0 && op == 0xD7);
        x86_finish_rip(s, out);
        if (s->want_text) {
            const char *m = (op == 0xD7) ? "pmovmskb" : (pp == 1 ? "movmskpd" : "movmskps");
            char mn[20], rhs[56];
            snprintf(mn, sizeof(mn), "%s%s", s->is_vex ? "v" : "", m);
            x86_set_mnem(s, out, mn);
            x86_fmt_rm_ex(s, rhs, sizeof(rhs), is_mmx ? 8 : x86_vec_bytes(vl), is_mmx ? 3 : 1, is_mmx && mod != 3, vl, 0, -1);
            snprintf(out->ops, sizeof(out->ops), "%s, %s", x86_reg_name(s, reg_g, gsz), rhs);
        }
        return true;
    }

    if (op == 0x2A || op == 0x2C || op == 0x2D ||
        (s->is_evex && (op == 0x78 || op == 0x79 || op == 0x7B) && (pp == 2 || pp == 3))) {
        int is_to_vec = (op == 0x2A || op == 0x7B);
        int is_mmx_cvt = (!s->is_vex && (op == 0x2A || op == 0x2C || op == 0x2D) && pp <= 1);
        int gsz = (s->bits == 64 && w) ? 8 : 4;
        const char *m = NULL;
        int msz = 4;
        if (op == 0x2A) { m = (pp == 3) ? "cvtsi2sd" : (pp == 2) ? "cvtsi2ss" : (pp == 1 ? "cvtpi2pd" : "cvtpi2ps"); msz = (pp >= 2) ? gsz : 8; }
        else if (op == 0x2C) { m = (pp == 3) ? "cvttsd2si" : (pp == 2) ? "cvttss2si" : (pp == 1 ? "cvttpd2pi" : "cvttps2pi"); msz = (pp == 1) ? 16 : (pp == 0 || pp == 3) ? 8 : 4; }
        else if (op == 0x2D) { m = (pp == 3) ? "cvtsd2si" : (pp == 2) ? "cvtss2si" : (pp == 1 ? "cvtpd2pi" : "cvtps2pi"); msz = (pp == 1) ? 16 : (pp == 0 || pp == 3) ? 8 : 4; }
        else if (op == 0x78) { m = (pp == 3) ? "cvttsd2usi" : "cvttss2usi"; msz = (pp == 3) ? 8 : 4; }
        else if (op == 0x79) { m = (pp == 3) ? "cvtsd2usi" : "cvtss2usi"; msz = (pp == 3) ? 8 : 4; }
        else { m = (pp == 3) ? "cvtusi2sd" : "cvtusi2ss"; msz = gsz; }

        s->disp8_scale = x86_evex_disp8_scale(s, TUPLE_T1S, 0, msz);
        x86_finish_rip(s, out);
        if (s->want_text) {
            char mn[20], lhs[24], vsrc[16], rhs[56];
            snprintf(mn, sizeof(mn), "%s%s", s->is_vex ? "v" : "", m);
            x86_set_mnem(s, out, mn);
            if (is_to_vec) {
                x86_xmm_name(lhs, sizeof(lhs), reg_v, 0);
                if (is_mmx_cvt) {
                    x86_fmt_rm_ex(s, rhs, sizeof(rhs), 8, 3, mod != 3, 0, 0, -1);
                } else {
                    x86_fmt_rm(s, rhs, sizeof(rhs), gsz, 0, mod != 3);
                }
                if (s->is_vex) {
                    x86_xmm_name(vsrc, sizeof(vsrc), s->vex_v, 0);
                    snprintf(out->ops, sizeof(out->ops), "%s, %s, %s", lhs, vsrc, rhs);
                } else {
                    snprintf(out->ops, sizeof(out->ops), "%s, %s", lhs, rhs);
                }
            } else {
                if (is_mmx_cvt) x86_mm_name(lhs, sizeof(lhs), reg_v);
                else snprintf(lhs, sizeof(lhs), "%s", x86_reg_name(s, reg_g, gsz));
                x86_fmt_rm_ex(s, rhs, sizeof(rhs), msz, 1, mod != 3, 0, 0, -1);
                snprintf(out->ops, sizeof(out->ops), "%s, %s", lhs, rhs);
            }
            x86_append_er(s, out->ops, sizeof(out->ops), (op == 0x2C || op == 0x78) ? 1 : 2);
        }
        return true;
    }

    /* Packed shift / rotate by imm8: 0F 71 / 72 / 73 */
    if (op == 0x71 || op == 0x72 || op == 0x73) {
        uint8_t imm;
        if (!x86_rd8(s, &imm)) return false;
        int is_mmx = (!s->is_vex && pp == 0);
        int vl = x86_vec_vl(s, 0, 0);
        int g = (s->modrm >> 3) & 7;
        const char *m = NULL;
        int bcst = 0;
        if (op == 0x71) {
            if (g == 2) m = "psrlw"; else if (g == 4) m = "psraw"; else if (g == 6) m = "psllw";
        } else if (op == 0x72) {
            if (g == 0 && s->is_evex) { m = "prord"; bcst = 4; }
            else if (g == 1 && s->is_evex) { m = "prold"; bcst = 4; }
            else if (g == 2) { m = "psrld"; bcst = 4; }
            else if (g == 4) { m = "psrad"; bcst = 4; }
            else if (g == 6) { m = "pslld"; bcst = 4; }
        } else {
            if (g == 0 && s->is_evex) { m = "prorq"; bcst = 8; }
            else if (g == 1 && s->is_evex) { m = "prolq"; bcst = 8; }
            else if (g == 2) { m = "psrlq"; bcst = 8; }
            else if (g == 3 && !is_mmx) { m = "psrldq"; }
            else if (g == 4 && !is_mmx) { m = "psraq"; bcst = 8; }
            else if (g == 6) { m = "psllq"; bcst = 8; }
            else if (g == 7 && !is_mmx) { m = "pslldq"; }
        }
        s->disp8_scale = x86_evex_disp8_scale(s, bcst ? TUPLE_FV : TUPLE_FVM, vl, bcst ? bcst : 4);
        x86_finish_rip(s, out);
        if (!m) return false;
        if (s->want_text) {
            char mn[20], rm[56];
            snprintf(mn, sizeof(mn), "%s%s", s->is_vex ? "v" : "", m);
            x86_set_mnem(s, out, mn);
            x86_fmt_rm_ex(s, rm, sizeof(rm), is_mmx ? 8 : x86_vec_bytes(vl), is_mmx ? 3 : 1, is_mmx && mod != 3, vl, bcst, -1);
            if (s->is_vex) {
                char dst[24];
                x86_xmm_name(dst, sizeof(dst), s->vex_v, vl);
                x86_append_mask(s, dst, sizeof(dst), 1);
                snprintf(out->ops, sizeof(out->ops), "%s, %s, 0x%x", dst, rm, imm);
            } else {
                snprintf(out->ops, sizeof(out->ops), "%s, 0x%x", rm, imm);
            }
        }
        return true;
    }

    /* 0F C4 pinsrw, 0F C5 pextrw (ModRM + imm8!) */
    if (op == 0xC4 || op == 0xC5) {
        uint8_t imm;
        if (!x86_rd8(s, &imm)) return false;
        int is_mmx = (!s->is_vex && pp == 0);
        int gsz = (s->bits == 64 && w) ? 8 : 4;
        s->disp8_scale = x86_evex_disp8_scale(s, TUPLE_T1S, 0, 2);
        x86_finish_rip(s, out);
        if (s->want_text) {
            char mn[20];
            snprintf(mn, sizeof(mn), "%s%s", s->is_vex ? "v" : "", (op == 0xC4) ? "pinsrw" : "pextrw");
            x86_set_mnem(s, out, mn);
            if (op == 0xC4) {
                char dst[16], vsrc[16], rm[56];
                if (is_mmx) x86_mm_name(dst, sizeof(dst), reg_v);
                else x86_xmm_name(dst, sizeof(dst), reg_v, 0);
                x86_fmt_rm(s, rm, sizeof(rm), (mod == 3) ? 4 : 2, 0, mod != 3);
                if (s->is_vex) {
                    x86_xmm_name(vsrc, sizeof(vsrc), s->vex_v, 0);
                    snprintf(out->ops, sizeof(out->ops), "%s, %s, %s, 0x%x", dst, vsrc, rm, imm);
                } else {
                    snprintf(out->ops, sizeof(out->ops), "%s, %s, 0x%x", dst, rm, imm);
                }
            } else {
                char rm[56];
                x86_fmt_rm_ex(s, rm, sizeof(rm), is_mmx ? 8 : 16, is_mmx ? 3 : 1, is_mmx && mod != 3, 0, 0, -1);
                snprintf(out->ops, sizeof(out->ops), "%s, %s, 0x%x", x86_reg_name(s, reg_g, gsz), rm, imm);
            }
        }
        return true;
    }

    /* 0F 70 pshuf*, 0F C2 cmp*, 0F C6 shuf* (ModRM + imm8!) */
    if (op == 0x70 || op == 0xC2 || op == 0xC6) {
        uint8_t imm;
        if (!x86_rd8(s, &imm)) return false;
        int is_mmx = (!s->is_vex && pp == 0 && op == 0x70);
        int is_scalar = (op == 0xC2 && (pp == 2 || pp == 3));
        int er_mode = (op == 0xC2) ? 1 : 0;
        int vl = x86_vec_vl(s, is_scalar, er_mode);
        const char *m = NULL;
        int is_3op = (op != 0x70);
        int dest_k = (op == 0xC2 && s->is_evex);
        int elem = (pp == 1 || pp == 3) ? 8 : 4;
        int bcst = 0;
        int tuple = TUPLE_FVM;
        if (op == 0x70) {
            m = (pp == 2) ? "pshufhw" : (pp == 3) ? "pshuflw" : (pp == 1) ? "pshufd" : "pshufw";
            if (pp == 1) { tuple = TUPLE_FV; elem = 4; bcst = 4; }
        } else if (op == 0xC2) {
            m = (pp == 2) ? "cmpss" : (pp == 3) ? "cmpsd" : (pp == 1) ? "cmppd" : "cmpps";
            tuple = is_scalar ? TUPLE_T1S : TUPLE_FV;
            bcst = is_scalar ? 0 : elem;
        } else {
            m = (pp == 1) ? "shufpd" : "shufps";
            tuple = TUPLE_FV;
            bcst = elem;
        }
        s->disp8_scale = x86_evex_disp8_scale(s, tuple, vl, elem);
        x86_finish_rip(s, out);
        if (s->want_text) {
            char mn[20], dst[24], vsrc[16], rm[56];
            snprintf(mn, sizeof(mn), "%s%s", s->is_vex ? "v" : "", m);
            x86_set_mnem(s, out, mn);
            if (dest_k) {
                x86_kreg_name(dst, sizeof(dst), reg_v);
                x86_append_mask(s, dst, sizeof(dst), 0);
            } else if (is_mmx) {
                x86_mm_name(dst, sizeof(dst), reg_v);
            } else {
                x86_xmm_name(dst, sizeof(dst), reg_v, vl);
                x86_append_mask(s, dst, sizeof(dst), 1);
            }
            x86_fmt_rm_ex(s, rm, sizeof(rm), is_mmx ? 8 : (is_scalar ? elem : x86_vec_bytes(vl)), is_mmx ? 3 : 1, is_mmx && mod != 3, vl, bcst, -1);
            if (is_3op && s->is_vex) {
                x86_xmm_name(vsrc, sizeof(vsrc), s->vex_v, vl);
                snprintf(out->ops, sizeof(out->ops), "%s, %s, %s, 0x%x", dst, vsrc, rm, imm);
            } else {
                snprintf(out->ops, sizeof(out->ops), "%s, %s, 0x%x", dst, rm, imm);
            }
            x86_append_er(s, out->ops, sizeof(out->ops), er_mode);
        }
        return true;
    }

    /* --- 8. Complete SSE / AVX / AVX-512 / MMX Map 1 (0F) Table --- */
    const char *m = NULL;
    int is_3op = 0;
    int is_store = 0;
    int gpr_rm = 0;
    int dst_mm = 0;
    int rm_mm = 0;
    int is_mmx = (!s->is_vex && pp == 0);
    int w64 = (s->bits == 64 && w);
    int is_scalar = 0;
    int dest_k = 0;
    int tuple = TUPLE_FVM;
    int elem = 4;
    int bcst = 0;
    int er_mode = 0;
    int dst_vl_override = -1;
    int rm_vl_override = -1;
    int mem_sz_override = 0;
    int vl = x86_vec_vl(s, 0, 0);

    switch (op) {
    case 0x10:
    case 0x11:
        is_store = (op == 0x11);
        if (pp == 2) { m = "movss"; is_scalar = 1; is_3op = (mod == 3); tuple = TUPLE_T1S; elem = 4; }
        else if (pp == 3) { m = "movsd"; is_scalar = 1; is_3op = (mod == 3); tuple = TUPLE_T1S; elem = 8; }
        else if (pp == 1) { m = "movupd"; tuple = TUPLE_FVM; elem = 8; }
        else { m = "movups"; tuple = TUPLE_FVM; elem = 4; }
        break;
    case 0x12:
        if (pp == 2) { m = "movsldup"; tuple = TUPLE_FVM; }
        else if (pp == 3) { m = "movddup"; tuple = (vl == 0) ? TUPLE_T1S : TUPLE_FVM; elem = 8; if (vl == 0) mem_sz_override = 8; }
        else if (pp == 1) { m = "movlpd"; is_3op = 1; is_scalar = 1; tuple = TUPLE_T1S; elem = 8; mem_sz_override = 8; }
        else {
            m = (mod == 3) ? "movhlps" : "movlps";
            is_3op = 1; is_scalar = 1; tuple = TUPLE_T2; elem = 4; mem_sz_override = 8;
        }
        break;
    case 0x13: m = (pp == 1) ? "movlpd" : "movlps"; is_store = 1; is_scalar = 1; tuple = (pp == 1) ? TUPLE_T1S : TUPLE_T2; elem = (pp == 1) ? 8 : 4; mem_sz_override = 8; break;
    case 0x14: m = (pp == 1) ? "unpcklpd" : "unpcklps"; is_3op = 1; tuple = TUPLE_FV; elem = (pp == 1) ? 8 : 4; bcst = elem; break;
    case 0x15: m = (pp == 1) ? "unpckhpd" : "unpckhps"; is_3op = 1; tuple = TUPLE_FV; elem = (pp == 1) ? 8 : 4; bcst = elem; break;
    case 0x16:
        if (pp == 2) { m = "movshdup"; tuple = TUPLE_FVM; }
        else if (pp == 1) { m = "movhpd"; is_3op = 1; is_scalar = 1; tuple = TUPLE_T1S; elem = 8; mem_sz_override = 8; }
        else {
            m = (mod == 3) ? "movlhps" : "movhps";
            is_3op = 1; is_scalar = 1; tuple = TUPLE_T2; elem = 4; mem_sz_override = 8;
        }
        break;
    case 0x17: m = (pp == 1) ? "movhpd" : "movhps"; is_store = 1; is_scalar = 1; tuple = (pp == 1) ? TUPLE_T1S : TUPLE_T2; elem = (pp == 1) ? 8 : 4; mem_sz_override = 8; break;
    case 0x28:
    case 0x29: m = (pp == 1) ? "movapd" : "movaps"; is_store = (op == 0x29); tuple = TUPLE_FVM; elem = (pp == 1) ? 8 : 4; break;
    case 0x2B: m = (pp == 2) ? "movntss" : (pp == 3) ? "movntsd" : (pp == 1) ? "movntpd" : "movntps"; is_store = 1; tuple = TUPLE_FVM; break;
    case 0x2E: m = (pp == 1) ? "ucomisd" : "ucomiss"; is_scalar = 1; tuple = TUPLE_T1S; elem = (pp == 1) ? 8 : 4; er_mode = 1; break;
    case 0x2F: m = (pp == 1) ? "comisd" : "comiss"; is_scalar = 1; tuple = TUPLE_T1S; elem = (pp == 1) ? 8 : 4; er_mode = 1; break;
    case 0x51:
        m = (pp == 2) ? "sqrtss" : (pp == 3) ? "sqrtsd" : (pp == 1) ? "sqrtpd" : "sqrtps";
        is_scalar = (pp >= 2); is_3op = is_scalar; elem = (pp == 1 || pp == 3) ? 8 : 4;
        tuple = is_scalar ? TUPLE_T1S : TUPLE_FV; bcst = is_scalar ? 0 : elem; er_mode = 2;
        break;
    case 0x52: m = (pp == 2) ? "rsqrtss" : "rsqrtps"; is_scalar = (pp == 2); is_3op = is_scalar; break;
    case 0x53: m = (pp == 2) ? "rcpss" : "rcpps"; is_scalar = (pp == 2); is_3op = is_scalar; break;
    case 0x54: m = (pp == 1) ? "andpd" : "andps"; is_3op = 1; tuple = TUPLE_FV; elem = (pp == 1) ? 8 : 4; bcst = elem; break;
    case 0x55: m = (pp == 1) ? "andnpd" : "andnps"; is_3op = 1; tuple = TUPLE_FV; elem = (pp == 1) ? 8 : 4; bcst = elem; break;
    case 0x56: m = (pp == 1) ? "orpd" : "orps"; is_3op = 1; tuple = TUPLE_FV; elem = (pp == 1) ? 8 : 4; bcst = elem; break;
    case 0x57: m = (pp == 1) ? "xorpd" : "xorps"; is_3op = 1; tuple = TUPLE_FV; elem = (pp == 1) ? 8 : 4; bcst = elem; break;
    case 0x58:
    case 0x59:
    case 0x5C:
    case 0x5D:
    case 0x5E:
    case 0x5F: {
        const char *b = (op == 0x58) ? "add" : (op == 0x59) ? "mul" : (op == 0x5C) ? "sub"
                      : (op == 0x5D) ? "min" : (op == 0x5E) ? "div" : "max";
        is_scalar = (pp >= 2);
        is_3op = 1;
        elem = (pp == 1 || pp == 3) ? 8 : 4;
        tuple = is_scalar ? TUPLE_T1S : TUPLE_FV;
        bcst = is_scalar ? 0 : elem;
        er_mode = (op == 0x5D || op == 0x5F) ? 1 : 2;
        vl = x86_vec_vl(s, is_scalar, er_mode);
        s->disp8_scale = x86_evex_disp8_scale(s, tuple, vl, elem);
        x86_finish_rip(s, out);
        if (s->want_text) {
            const char *sfx = (pp == 2) ? "ss" : (pp == 3) ? "sd" : (pp == 1) ? "pd" : "ps";
            char mn[20], dst[24], vsrc[16], rm[56];
            snprintf(mn, sizeof(mn), "%s%s%s", s->is_vex ? "v" : "", b, sfx);
            x86_set_mnem(s, out, mn);
            x86_xmm_name(dst, sizeof(dst), reg_v, vl);
            x86_append_mask(s, dst, sizeof(dst), 1);
            x86_fmt_rm_ex(s, rm, sizeof(rm), is_scalar ? elem : x86_vec_bytes(vl), 1, 0, vl, bcst, -1);
            if (s->is_vex) {
                x86_xmm_name(vsrc, sizeof(vsrc), s->vex_v, vl);
                snprintf(out->ops, sizeof(out->ops), "%s, %s, %s", dst, vsrc, rm);
            } else {
                snprintf(out->ops, sizeof(out->ops), "%s, %s", dst, rm);
            }
            x86_append_er(s, out->ops, sizeof(out->ops), er_mode);
        }
        return true;
    }
    case 0x5A:
        if (pp == 2) { m = "cvtss2sd"; is_scalar = 1; is_3op = 1; tuple = TUPLE_T1S; elem = 4; er_mode = 1; }
        else if (pp == 3) { m = "cvtsd2ss"; is_scalar = 1; is_3op = 1; tuple = TUPLE_T1S; elem = 8; er_mode = 2; }
        else if (pp == 1) { m = "cvtpd2ps"; tuple = TUPLE_FV; elem = 8; bcst = 8; dst_vl_override = (vl > 0 ? vl - 1 : 0); er_mode = 2; }
        else { m = "cvtps2pd"; tuple = TUPLE_HV; elem = 4; bcst = 4; rm_vl_override = (vl > 0 ? vl - 1 : 0); mem_sz_override = x86_vec_bytes(vl) / 2; er_mode = 1; }
        break;
    case 0x5B:
        if (pp == 2) { m = "cvttps2dq"; tuple = TUPLE_FV; elem = 4; bcst = 4; er_mode = 1; }
        else if (pp == 1) { m = "cvtps2dq"; tuple = TUPLE_FV; elem = 4; bcst = 4; er_mode = 2; }
        else {
            m = (s->is_evex && w) ? "cvtqq2ps" : "cvtdq2ps";
            tuple = TUPLE_FV; elem = (s->is_evex && w) ? 8 : 4; bcst = elem; er_mode = 2;
            if (s->is_evex && w) dst_vl_override = (vl > 0 ? vl - 1 : 0);
        }
        break;
    case 0x60: m = "punpcklbw"; is_3op = 1; tuple = TUPLE_FVM; if (is_mmx) { dst_mm = 1; rm_mm = 1; } break;
    case 0x61: m = "punpcklwd"; is_3op = 1; tuple = TUPLE_FVM; if (is_mmx) { dst_mm = 1; rm_mm = 1; } break;
    case 0x62: m = "punpckldq"; is_3op = 1; tuple = TUPLE_FV; elem = 4; bcst = 4; if (is_mmx) { dst_mm = 1; rm_mm = 1; } break;
    case 0x63: m = "packsswb"; is_3op = 1; tuple = TUPLE_FVM; if (is_mmx) { dst_mm = 1; rm_mm = 1; } break;
    case 0x64: m = "pcmpgtb"; is_3op = 1; dest_k = s->is_evex; tuple = TUPLE_FVM; if (is_mmx) { dst_mm = 1; rm_mm = 1; } break;
    case 0x65: m = "pcmpgtw"; is_3op = 1; dest_k = s->is_evex; tuple = TUPLE_FVM; if (is_mmx) { dst_mm = 1; rm_mm = 1; } break;
    case 0x66: m = "pcmpgtd"; is_3op = 1; dest_k = s->is_evex; tuple = TUPLE_FV; elem = 4; bcst = 4; if (is_mmx) { dst_mm = 1; rm_mm = 1; } break;
    case 0x67: m = "packuswb"; is_3op = 1; tuple = TUPLE_FVM; if (is_mmx) { dst_mm = 1; rm_mm = 1; } break;
    case 0x68: m = "punpckhbw"; is_3op = 1; tuple = TUPLE_FVM; if (is_mmx) { dst_mm = 1; rm_mm = 1; } break;
    case 0x69: m = "punpckhwd"; is_3op = 1; tuple = TUPLE_FVM; if (is_mmx) { dst_mm = 1; rm_mm = 1; } break;
    case 0x6A: m = "punpckhdq"; is_3op = 1; tuple = TUPLE_FV; elem = 4; bcst = 4; if (is_mmx) { dst_mm = 1; rm_mm = 1; } break;
    case 0x6B: m = "packssdw"; is_3op = 1; tuple = TUPLE_FV; elem = 4; bcst = 4; if (is_mmx) { dst_mm = 1; rm_mm = 1; } break;
    case 0x6C: m = "punpcklqdq"; is_3op = 1; tuple = TUPLE_FV; elem = 8; bcst = 8; break;
    case 0x6D: m = "punpckhqdq"; is_3op = 1; tuple = TUPLE_FV; elem = 8; bcst = 8; break;
    case 0x6E: m = w64 ? "movq" : "movd"; gpr_rm = 1; is_scalar = 1; tuple = TUPLE_T1S; elem = w64 ? 8 : 4; if (is_mmx) dst_mm = 1; break;
    case 0x6F:
    case 0x7F:
        is_store = (op == 0x7F);
        if (s->is_evex) {
            if (pp == 1) m = w ? "movdqa64" : "movdqa32";
            else if (pp == 2) m = w ? "movdqu64" : "movdqu32";
            else m = w ? "movdqu16" : "movdqu8";
            tuple = TUPLE_FVM;
        } else {
            m = (pp == 2) ? "movdqu" : (pp == 1) ? "movdqa" : "movq";
            if (is_mmx) { dst_mm = 1; rm_mm = 1; }
        }
        break;
    case 0x74: m = "pcmpeqb"; is_3op = 1; dest_k = s->is_evex; tuple = TUPLE_FVM; if (is_mmx) { dst_mm = 1; rm_mm = 1; } break;
    case 0x75: m = "pcmpeqw"; is_3op = 1; dest_k = s->is_evex; tuple = TUPLE_FVM; if (is_mmx) { dst_mm = 1; rm_mm = 1; } break;
    case 0x76: m = "pcmpeqd"; is_3op = 1; dest_k = s->is_evex; tuple = TUPLE_FV; elem = 4; bcst = 4; if (is_mmx) { dst_mm = 1; rm_mm = 1; } break;
    case 0x78:
        if (s->is_evex) {
            if (pp == 0) { m = w ? "cvttpd2udq" : "cvttps2udq"; tuple = TUPLE_FV; elem = w ? 8 : 4; bcst = elem; if (w) dst_vl_override = (vl > 0 ? vl - 1 : 0); er_mode = 1; }
            else if (pp == 1) { m = w ? "cvttpd2uqq" : "cvttps2uqq"; tuple = w ? TUPLE_FV : TUPLE_HV; elem = w ? 8 : 4; bcst = elem; if (!w) { rm_vl_override = (vl > 0 ? vl - 1 : 0); mem_sz_override = x86_vec_bytes(vl) / 2; } er_mode = 1; }
        }
        break;
    case 0x79:
        if (s->is_evex) {
            if (pp == 0) { m = w ? "cvtpd2udq" : "cvtps2udq"; tuple = TUPLE_FV; elem = w ? 8 : 4; bcst = elem; if (w) dst_vl_override = (vl > 0 ? vl - 1 : 0); er_mode = 2; }
            else if (pp == 1) { m = w ? "cvtpd2uqq" : "cvtps2uqq"; tuple = w ? TUPLE_FV : TUPLE_HV; elem = w ? 8 : 4; bcst = elem; if (!w) { rm_vl_override = (vl > 0 ? vl - 1 : 0); mem_sz_override = x86_vec_bytes(vl) / 2; } er_mode = 2; }
        }
        break;
    case 0x7A:
        if (s->is_evex) {
            if (pp == 1) { m = w ? "cvttpd2qq" : "cvttps2qq"; tuple = w ? TUPLE_FV : TUPLE_HV; elem = w ? 8 : 4; bcst = elem; if (!w) { rm_vl_override = (vl > 0 ? vl - 1 : 0); mem_sz_override = x86_vec_bytes(vl) / 2; } er_mode = 1; }
            else if (pp == 2) { m = w ? "cvtuqq2pd" : "cvtudq2pd"; tuple = w ? TUPLE_FV : TUPLE_HV; elem = w ? 8 : 4; bcst = elem; if (!w) { rm_vl_override = (vl > 0 ? vl - 1 : 0); mem_sz_override = x86_vec_bytes(vl) / 2; } er_mode = 2; }
            else if (pp == 3) { m = w ? "cvtuqq2ps" : "cvtudq2ps"; tuple = TUPLE_FV; elem = w ? 8 : 4; bcst = elem; if (w) dst_vl_override = (vl > 0 ? vl - 1 : 0); er_mode = 2; }
        }
        break;
    case 0x7B:
        if (s->is_evex && pp == 1) { m = w ? "cvtpd2qq" : "cvtps2qq"; tuple = w ? TUPLE_FV : TUPLE_HV; elem = w ? 8 : 4; bcst = elem; if (!w) { rm_vl_override = (vl > 0 ? vl - 1 : 0); mem_sz_override = x86_vec_bytes(vl) / 2; } er_mode = 2; }
        break;
    case 0x7C: m = (pp == 3) ? "haddps" : "haddpd"; is_3op = 1; break;
    case 0x7D: m = (pp == 3) ? "hsubps" : "hsubpd"; is_3op = 1; break;
    case 0x7E:
        if (pp == 2) { m = "movq"; is_scalar = 1; tuple = TUPLE_T1S; elem = 8; mem_sz_override = 8; }
        else { m = w64 ? "movq" : "movd"; is_store = 1; gpr_rm = 1; is_scalar = 1; tuple = TUPLE_T1S; elem = w64 ? 8 : 4; if (is_mmx) dst_mm = 1; }
        break;
    case 0xD0: m = (pp == 3) ? "addsubps" : "addsubpd"; is_3op = 1; break;
    case 0xD1: m = "psrlw"; is_3op = 1; tuple = TUPLE_M128; if (is_mmx) { dst_mm = 1; rm_mm = 1; } break;
    case 0xD2: m = "psrld"; is_3op = 1; tuple = TUPLE_M128; if (is_mmx) { dst_mm = 1; rm_mm = 1; } break;
    case 0xD3: m = "psrlq"; is_3op = 1; tuple = TUPLE_M128; if (is_mmx) { dst_mm = 1; rm_mm = 1; } break;
    case 0xD4: m = "paddq"; is_3op = 1; tuple = TUPLE_FV; elem = 8; bcst = 8; if (is_mmx) { dst_mm = 1; rm_mm = 1; } break;
    case 0xD5: m = "pmullw"; is_3op = 1; tuple = TUPLE_FVM; if (is_mmx) { dst_mm = 1; rm_mm = 1; } break;
    case 0xD6:
        if (is_mmx) return false;
        if (pp == 2) { m = "movq2dq"; rm_mm = 1; }
        else if (pp == 3) { m = "movdq2q"; dst_mm = 1; }
        else { m = "movq"; is_store = 1; is_scalar = 1; tuple = TUPLE_T1S; elem = 8; mem_sz_override = 8; }
        break;
    case 0xD8: m = "psubusb"; is_3op = 1; tuple = TUPLE_FVM; if (is_mmx) { dst_mm = 1; rm_mm = 1; } break;
    case 0xD9: m = "psubusw"; is_3op = 1; tuple = TUPLE_FVM; if (is_mmx) { dst_mm = 1; rm_mm = 1; } break;
    case 0xDA: m = "pminub"; is_3op = 1; tuple = TUPLE_FVM; if (is_mmx) { dst_mm = 1; rm_mm = 1; } break;
    case 0xDB: m = s->is_evex ? (w ? "pandq" : "pandd") : "pand"; is_3op = 1; tuple = TUPLE_FV; elem = w ? 8 : 4; bcst = elem; if (is_mmx) { dst_mm = 1; rm_mm = 1; } break;
    case 0xDC: m = "paddusb"; is_3op = 1; tuple = TUPLE_FVM; if (is_mmx) { dst_mm = 1; rm_mm = 1; } break;
    case 0xDD: m = "paddusw"; is_3op = 1; tuple = TUPLE_FVM; if (is_mmx) { dst_mm = 1; rm_mm = 1; } break;
    case 0xDE: m = "pmaxub"; is_3op = 1; tuple = TUPLE_FVM; if (is_mmx) { dst_mm = 1; rm_mm = 1; } break;
    case 0xDF: m = s->is_evex ? (w ? "pandnq" : "pandnd") : "pandn"; is_3op = 1; tuple = TUPLE_FV; elem = w ? 8 : 4; bcst = elem; if (is_mmx) { dst_mm = 1; rm_mm = 1; } break;
    case 0xE0: m = "pavgb"; is_3op = 1; tuple = TUPLE_FVM; if (is_mmx) { dst_mm = 1; rm_mm = 1; } break;
    case 0xE1: m = "psraw"; is_3op = 1; tuple = TUPLE_M128; if (is_mmx) { dst_mm = 1; rm_mm = 1; } break;
    case 0xE2: m = "psrad"; is_3op = 1; tuple = TUPLE_M128; if (is_mmx) { dst_mm = 1; rm_mm = 1; } break;
    case 0xE3: m = "pavgw"; is_3op = 1; tuple = TUPLE_FVM; if (is_mmx) { dst_mm = 1; rm_mm = 1; } break;
    case 0xE4: m = "pmulhuw"; is_3op = 1; tuple = TUPLE_FVM; if (is_mmx) { dst_mm = 1; rm_mm = 1; } break;
    case 0xE5: m = "pmulhw"; is_3op = 1; tuple = TUPLE_FVM; if (is_mmx) { dst_mm = 1; rm_mm = 1; } break;
    case 0xE6:
        if (pp == 2) {
            m = (s->is_evex && w) ? "cvtqq2pd" : "cvtdq2pd";
            tuple = (s->is_evex && w) ? TUPLE_FV : TUPLE_HV;
            elem = (s->is_evex && w) ? 8 : 4; bcst = elem;
            if (!(s->is_evex && w)) { rm_vl_override = (vl > 0 ? vl - 1 : 0); mem_sz_override = x86_vec_bytes(vl) / 2; }
            er_mode = 2;
        } else if (pp == 3) { m = "cvtpd2dq"; tuple = TUPLE_FV; elem = 8; bcst = 8; dst_vl_override = (vl > 0 ? vl - 1 : 0); er_mode = 2; }
        else { m = "cvttpd2dq"; tuple = TUPLE_FV; elem = 8; bcst = 8; dst_vl_override = (vl > 0 ? vl - 1 : 0); er_mode = 1; }
        break;
    case 0xE7: m = (pp == 1) ? "movntdq" : "movntq"; is_store = 1; tuple = TUPLE_FVM; if (is_mmx) { dst_mm = 1; rm_mm = 1; } break;
    case 0xE8: m = "psubsb"; is_3op = 1; tuple = TUPLE_FVM; if (is_mmx) { dst_mm = 1; rm_mm = 1; } break;
    case 0xE9: m = "psubsw"; is_3op = 1; tuple = TUPLE_FVM; if (is_mmx) { dst_mm = 1; rm_mm = 1; } break;
    case 0xEA: m = "pminsw"; is_3op = 1; tuple = TUPLE_FVM; if (is_mmx) { dst_mm = 1; rm_mm = 1; } break;
    case 0xEB: m = s->is_evex ? (w ? "porq" : "pord") : "por"; is_3op = 1; tuple = TUPLE_FV; elem = w ? 8 : 4; bcst = elem; if (is_mmx) { dst_mm = 1; rm_mm = 1; } break;
    case 0xEC: m = "paddsb"; is_3op = 1; tuple = TUPLE_FVM; if (is_mmx) { dst_mm = 1; rm_mm = 1; } break;
    case 0xED: m = "paddsw"; is_3op = 1; tuple = TUPLE_FVM; if (is_mmx) { dst_mm = 1; rm_mm = 1; } break;
    case 0xEE: m = "pmaxsw"; is_3op = 1; tuple = TUPLE_FVM; if (is_mmx) { dst_mm = 1; rm_mm = 1; } break;
    case 0xEF: m = s->is_evex ? (w ? "pxorq" : "pxord") : "pxor"; is_3op = 1; tuple = TUPLE_FV; elem = w ? 8 : 4; bcst = elem; if (is_mmx) { dst_mm = 1; rm_mm = 1; } break;
    case 0xF0: m = "lddqu"; break;
    case 0xF1: m = "psllw"; is_3op = 1; tuple = TUPLE_M128; if (is_mmx) { dst_mm = 1; rm_mm = 1; } break;
    case 0xF2: m = "pslld"; is_3op = 1; tuple = TUPLE_M128; if (is_mmx) { dst_mm = 1; rm_mm = 1; } break;
    case 0xF3: m = "psllq"; is_3op = 1; tuple = TUPLE_M128; if (is_mmx) { dst_mm = 1; rm_mm = 1; } break;
    case 0xF4: m = "pmuludq"; is_3op = 1; tuple = TUPLE_FV; elem = 8; bcst = 8; if (is_mmx) { dst_mm = 1; rm_mm = 1; } break;
    case 0xF5: m = "pmaddwd"; is_3op = 1; tuple = TUPLE_FVM; if (is_mmx) { dst_mm = 1; rm_mm = 1; } break;
    case 0xF6: m = "psadbw"; is_3op = 1; tuple = TUPLE_FVM; if (is_mmx) { dst_mm = 1; rm_mm = 1; } break;
    case 0xF7: m = (pp == 1) ? "maskmovdqu" : "maskmovq"; if (is_mmx) { dst_mm = 1; rm_mm = 1; } break;
    case 0xF8: m = "psubb"; is_3op = 1; tuple = TUPLE_FVM; if (is_mmx) { dst_mm = 1; rm_mm = 1; } break;
    case 0xF9: m = "psubw"; is_3op = 1; tuple = TUPLE_FVM; if (is_mmx) { dst_mm = 1; rm_mm = 1; } break;
    case 0xFA: m = "psubd"; is_3op = 1; tuple = TUPLE_FV; elem = 4; bcst = 4; if (is_mmx) { dst_mm = 1; rm_mm = 1; } break;
    case 0xFB: m = "psubq"; is_3op = 1; tuple = TUPLE_FV; elem = 8; bcst = 8; if (is_mmx) { dst_mm = 1; rm_mm = 1; } break;
    case 0xFC: m = "paddb"; is_3op = 1; tuple = TUPLE_FVM; if (is_mmx) { dst_mm = 1; rm_mm = 1; } break;
    case 0xFD: m = "paddw"; is_3op = 1; tuple = TUPLE_FVM; if (is_mmx) { dst_mm = 1; rm_mm = 1; } break;
    case 0xFE: m = "paddd"; is_3op = 1; tuple = TUPLE_FV; elem = 4; bcst = 4; if (is_mmx) { dst_mm = 1; rm_mm = 1; } break;
    default: break;
    }

    if (m) {
        vl = x86_vec_vl(s, is_scalar, er_mode);
        s->disp8_scale = x86_evex_disp8_scale(s, tuple, vl, elem);
        x86_finish_rip(s, out);
        if (s->want_text) {
            char mn[20], vreg[24], vsrc[16], rm[56];
            snprintf(mn, sizeof(mn), "%s%s", s->is_vex ? "v" : "", m);
            x86_set_mnem(s, out, mn);
            if (dest_k) {
                x86_kreg_name(vreg, sizeof(vreg), reg_v);
                x86_append_mask(s, vreg, sizeof(vreg), 0);
            } else if (dst_mm) {
                x86_mm_name(vreg, sizeof(vreg), reg_v);
            } else {
                int dvl = (dst_vl_override >= 0) ? dst_vl_override : vl;
                x86_xmm_name(vreg, sizeof(vreg), reg_v, dvl);
                if (!is_store) x86_append_mask(s, vreg, sizeof(vreg), 1);
            }
            int rvl = (rm_vl_override >= 0) ? rm_vl_override : vl;
            int gsz = w64 ? 8 : 4;
            int msz = gpr_rm ? gsz : (rm_mm ? 8 : (mem_sz_override > 0 ? mem_sz_override : (is_scalar ? elem : x86_vec_bytes(rvl))));
            int rm_kind = gpr_rm ? 0 : (rm_mm ? 3 : 1);
            int show_ptr = ((is_store || rm_mm || gpr_rm) && mod != 3 && msz <= 32);
            x86_fmt_rm_ex(s, rm, sizeof(rm), msz, rm_kind, show_ptr, rvl, bcst, -1);
            if (is_store) {
                x86_append_mask(s, rm, sizeof(rm), mod == 3);
                if (is_3op && s->is_vex) {
                    x86_xmm_name(vsrc, sizeof(vsrc), s->vex_v, vl);
                    snprintf(out->ops, sizeof(out->ops), "%s, %s, %s", rm, vsrc, vreg);
                } else {
                    snprintf(out->ops, sizeof(out->ops), "%s, %s", rm, vreg);
                }
            } else if (is_3op && s->is_vex) {
                x86_xmm_name(vsrc, sizeof(vsrc), s->vex_v, vl);
                snprintf(out->ops, sizeof(out->ops), "%s, %s, %s", vreg, vsrc, rm);
            } else {
                snprintf(out->ops, sizeof(out->ops), "%s, %s", vreg, rm);
            }
            x86_append_er(s, out->ops, sizeof(out->ops), er_mode);
        }
        return true;
    }

    x86_finish_rip(s, out);
    if (s->want_text) {
        snprintf(out->mnem, sizeof(out->mnem), "op0f_%02x", op);
    }
    return true;
}

/* =========================================================================
 * 1-Byte Opcodes (Complete 64-bit & 32-bit x86)
 * ========================================================================= */
static bool x86_decode_1b(x86_st *s, uint8_t op, x86_ins *out) {
    int sz = x86_opsize(s);

    /* ALU 00..3D (cols 0..5) */
    if ((op & 0xC0) == 0x00 && (op & 7) < 6) {
        int alu = (op >> 3) & 7;
        int col = op & 7;
        if (col < 4) {
            if (!x86_parse_modrm(s)) return false;
            int osz = (col & 1) ? sz : 1;
            int reg = x86_modrm_reg_gpr(s);
            x86_finish_rip(s, out);
            if (s->want_text) {
                char rm[56];
                x86_fmt_rm(s, rm, sizeof(rm), osz, 0, !(col & 2));
                x86_set_mnem(s, out, x86_alu[alu]);
                if (col & 2) snprintf(out->ops, sizeof(out->ops), "%s, %s", x86_reg_name(s, reg, osz), rm);
                else snprintf(out->ops, sizeof(out->ops), "%s, %s", rm, x86_reg_name(s, reg, osz));
            }
            return true;
        }
        int osz = (col == 4) ? 1 : sz;
        int64_t imm = 0;
        if (osz == 1) { uint8_t v; if (!x86_rd8(s, &v)) return false; imm = v; }
        else if (osz == 2) { uint16_t v; if (!x86_rd16(s, &v)) return false; imm = v; }
        else { uint32_t v; if (!x86_rd32(s, &v)) return false; imm = (osz == 8) ? (int64_t)(int32_t)v : (int64_t)v; }
        x86_set_mnem(s, out, x86_alu[alu]);
        if (s->want_text) snprintf(out->ops, sizeof(out->ops), "%s, 0x%llx", x86_reg_name(s, 0, osz), (unsigned long long)x86_mask_imm(imm, osz));
        return true;
    }

    /* 32-bit segment push/pop & BCD instructions */
    if (s->bits == 32) {
        if (op == 0x06 || op == 0x07 || op == 0x0E || op == 0x16 || op == 0x17 || op == 0x1E || op == 0x1F) {
            const char *sr = (op <= 0x07) ? "es" : (op == 0x0E) ? "cs" : (op <= 0x17) ? "ss" : "ds";
            x86_set_mnem(s, out, (op & 1) ? "pop" : "push");
            if (s->want_text) snprintf(out->ops, sizeof(out->ops), "%s", sr);
            return true;
        }
        if (op == 0x27) { x86_set_mnem(s, out, "daa"); return true; }
        if (op == 0x2F) { x86_set_mnem(s, out, "das"); return true; }
        if (op == 0x37) { x86_set_mnem(s, out, "aaa"); return true; }
        if (op == 0x3F) { x86_set_mnem(s, out, "aas"); return true; }
        if (op >= 0x40 && op <= 0x4F) {
            x86_set_mnem(s, out, op < 0x48 ? "inc" : "dec");
            if (s->want_text) snprintf(out->ops, sizeof(out->ops), "%s", x86_reg_name(s, op & 7, sz));
            return true;
        }
        if (op == 0x60) { x86_set_mnem(s, out, s->osz ? "pusha" : "pushad"); return true; }
        if (op == 0x61) { x86_set_mnem(s, out, s->osz ? "popa" : "popad"); return true; }
        if (op == 0x62) {
            if (!x86_parse_modrm(s)) return false;
            if ((s->modrm >> 6) == 3) return false;
            x86_set_mnem(s, out, "bound");
            if (s->want_text) {
                char rhs[56];
                x86_fmt_rm(s, rhs, sizeof(rhs), sz * 2, 0, 1);
                snprintf(out->ops, sizeof(out->ops), "%s, %s", x86_reg_name(s, x86_modrm_reg_gpr(s), sz), rhs);
            }
            return true;
        }
        if (op == 0x9A || op == 0xEA) {
            uint32_t off = 0;
            uint16_t sel = 0;
            if (s->osz) { uint16_t o16; if (!x86_rd16(s, &o16)) return false; off = o16; }
            else { if (!x86_rd32(s, &off)) return false; }
            if (!x86_rd16(s, &sel)) return false;
            out->flow = (op == 0x9A) ? X86_FLOW_CALL : X86_FLOW_JMP;
            x86_set_mnem(s, out, (op == 0x9A) ? "callf" : "jmpf");
            if (s->want_text) snprintf(out->ops, sizeof(out->ops), "0x%x:0x%x", sel, off);
            return true;
        }
        if (op == 0xC4 || op == 0xC5) {
            if (!x86_parse_modrm(s)) return false;
            if ((s->modrm >> 6) == 3) return false;
            x86_set_mnem(s, out, op == 0xC4 ? "les" : "lds");
            if (s->want_text) {
                char rhs[56];
                x86_fmt_rm(s, rhs, sizeof(rhs), (sz == 2) ? 4 : 6, 0, 1);
                snprintf(out->ops, sizeof(out->ops), "%s, %s", x86_reg_name(s, x86_modrm_reg_gpr(s), sz), rhs);
            }
            return true;
        }
        if (op == 0xCE) { x86_set_mnem(s, out, "into"); return true; }
        if (op == 0xD4 || op == 0xD5) {
            uint8_t base;
            if (!x86_rd8(s, &base)) return false;
            x86_set_mnem(s, out, op == 0xD4 ? "aam" : "aad");
            if (s->want_text && base != 0x0A) snprintf(out->ops, sizeof(out->ops), "0x%x", base);
            return true;
        }
        if (op == 0xD6) { x86_set_mnem(s, out, "salc"); return true; }
    }

    if (op >= 0x50 && op <= 0x5F) {
        int reg = (op & 7) | ((s->rex & 1) ? 8 : 0);
        if (s->bits == 32) reg &= 7;
        int ps  = x86_opsize_def64(s);
        x86_set_mnem(s, out, op < 0x58 ? "push" : "pop");
        if (s->want_text) snprintf(out->ops, sizeof(out->ops), "%s", x86_reg_name(s, reg, ps));
        return true;
    }

    if (op >= 0x70 && op <= 0x7F) {
        uint8_t rel;
        if (!x86_rd8(s, &rel)) return false;
        out->flow = X86_FLOW_JCC;
        out->target = s->ip + s->pos + (uint64_t)(int64_t)(int8_t)rel;
        out->has_target = 1;
        if (s->want_text) {
            snprintf(out->mnem, sizeof(out->mnem), "j%s", x86_cc[op & 15]);
            snprintf(out->ops, sizeof(out->ops), "0x%llx", (unsigned long long)out->target);
        }
        return true;
    }

    if (op == 0x63) {
        if (!x86_parse_modrm(s)) return false;
        int reg = x86_modrm_reg_gpr(s);
        x86_finish_rip(s, out);
        if (s->bits == 32) {
            x86_set_mnem(s, out, "arpl");
            if (s->want_text) {
                char lhs[56];
                x86_fmt_rm(s, lhs, sizeof(lhs), 2, 0, 1);
                snprintf(out->ops, sizeof(out->ops), "%s, %s", lhs, x86_reg_name(s, reg, 2));
            }
        } else {
            x86_set_mnem(s, out, "movsxd");
            if (s->want_text) {
                char rhs[56];
                x86_fmt_rm(s, rhs, sizeof(rhs), 4, 0, 1);
                snprintf(out->ops, sizeof(out->ops), "%s, %s", x86_reg_name(s, reg, sz), rhs);
            }
        }
        return true;
    }

    if (op == 0x68 || op == 0x6A) {
        int64_t imm = 0;
        int ps = (s->bits == 64 && (s->rex & 8)) ? 8 : x86_opsize_def64(s);
        if (op == 0x6A) { uint8_t v; if (!x86_rd8(s, &v)) return false; imm = (int8_t)v; }
        else if (s->osz && !(s->bits == 64 && (s->rex & 8))) { uint16_t v; if (!x86_rd16(s, &v)) return false; imm = (int16_t)v; }
        else { uint32_t v; if (!x86_rd32(s, &v)) return false; imm = (int32_t)v; }
        x86_set_mnem(s, out, "push");
        if (s->want_text) snprintf(out->ops, sizeof(out->ops), "0x%llx", (unsigned long long)x86_mask_imm(imm, ps));
        return true;
    }

    if (op == 0x69 || op == 0x6B) {
        if (!x86_parse_modrm(s)) return false;
        int64_t imm = 0;
        if (op == 0x6B) { uint8_t v; if (!x86_rd8(s, &v)) return false; imm = (int8_t)v; }
        else if (sz == 2) { uint16_t v; if (!x86_rd16(s, &v)) return false; imm = (int16_t)v; }
        else { uint32_t v; if (!x86_rd32(s, &v)) return false; imm = (int32_t)v; }
        int reg = x86_modrm_reg_gpr(s);
        x86_finish_rip(s, out);
        if (s->want_text) {
            char rhs[56];
            x86_fmt_rm(s, rhs, sizeof(rhs), sz, 0, 0);
            x86_set_mnem(s, out, "imul");
            snprintf(out->ops, sizeof(out->ops), "%s, %s, 0x%llx", x86_reg_name(s, reg, sz), rhs, (unsigned long long)x86_mask_imm(imm, sz));
        }
        return true;
    }

    /* insb/w/d, outsb/w/d (0x6C..0x6F, valid in both 32-bit and 64-bit) */
    if (op >= 0x6C && op <= 0x6F) {
        const char *base = (op <= 0x6D) ? "ins" : "outs";
        char suf = (op & 1) ? (s->osz ? 'w' : 'd') : 'b';
        if (s->want_text) {
            const char *rp = (s->rep == 0xF3) ? "rep " : (s->rep == 0xF2) ? "repne " : "";
            char tmp[20];
            snprintf(tmp, sizeof(tmp), "%s%s%c", rp, base, suf);
            x86_set_mnem(s, out, tmp);
        }
        return true;
    }

    if (op >= 0x80 && op <= 0x83) {
        if (op == 0x82 && s->bits == 64) return false;
        if (!x86_parse_modrm(s)) return false;
        int osz = (op == 0x80 || op == 0x82) ? 1 : sz;
        int64_t imm = 0;
        if (op == 0x80 || op == 0x82 || op == 0x83) {
            uint8_t v;
            if (!x86_rd8(s, &v)) return false;
            imm = (op == 0x83) ? (int8_t)v : v;
        } else if (sz == 2) {
            uint16_t v;
            if (!x86_rd16(s, &v)) return false;
            imm = v;
        } else {
            uint32_t v;
            if (!x86_rd32(s, &v)) return false;
            imm = (int32_t)v;
        }
        int grp = (s->modrm >> 3) & 7;
        x86_finish_rip(s, out);
        if (s->want_text) {
            char lhs[56];
            x86_fmt_rm(s, lhs, sizeof(lhs), osz, 0, 1);
            x86_set_mnem(s, out, x86_alu[grp]);
            snprintf(out->ops, sizeof(out->ops), "%s, 0x%llx", lhs, (unsigned long long)x86_mask_imm(imm, osz));
        }
        return true;
    }

    if (op == 0x84 || op == 0x85 || op == 0x86 || op == 0x87 || (op >= 0x88 && op <= 0x8B) || op == 0x8D) {
        if (!x86_parse_modrm(s)) return false;
        if (op == 0x8D && (s->modrm >> 6) == 3) return false;
        int osz = (op == 0x84 || op == 0x86 || op == 0x88 || op == 0x8A) ? 1 : sz;
        int reg = x86_modrm_reg_gpr(s);
        int to_reg = (op == 0x8A || op == 0x8B || op == 0x8D);
        x86_finish_rip(s, out);
        if (s->want_text) {
            const char *m = (op <= 0x85) ? "test" : (op <= 0x87) ? "xchg" : (op == 0x8D) ? "lea" : "mov";
            char rm[56];
            x86_fmt_rm(s, rm, sizeof(rm), osz, 0, op != 0x8D && !to_reg);
            x86_set_mnem(s, out, m);
            if (to_reg) snprintf(out->ops, sizeof(out->ops), "%s, %s", x86_reg_name(s, reg, osz), rm);
            else snprintf(out->ops, sizeof(out->ops), "%s, %s", rm, x86_reg_name(s, reg, osz));
        }
        return true;
    }

    if (op == 0x8C || op == 0x8E || op == 0x8F) {
        if (!x86_parse_modrm(s)) return false;
        int reg = (s->modrm >> 3) & 7;
        if (op == 0x8F && reg != 0) return false;
        x86_finish_rip(s, out);
        if (s->want_text) {
            char rm[56];
            x86_fmt_rm(s, rm, sizeof(rm), op == 0x8F ? x86_opsize_def64(s) : 2, 0, 1);
            if (op == 0x8F) {
                x86_set_mnem(s, out, "pop");
                snprintf(out->ops, sizeof(out->ops), "%s", rm);
            } else if (op == 0x8C) {
                x86_set_mnem(s, out, "mov");
                snprintf(out->ops, sizeof(out->ops), "%s, %s", rm, x86_seg[reg]);
            } else {
                x86_set_mnem(s, out, "mov");
                snprintf(out->ops, sizeof(out->ops), "%s, %s", x86_seg[reg], rm);
            }
        }
        return true;
    }

    if (op >= 0x90 && op <= 0x97) {
        int reg = (op & 7) | ((s->rex & 1) ? 8 : 0);
        if (s->bits == 32) reg &= 7;
        if (op == 0x90 && !(s->rex & 1)) {
            x86_set_mnem(s, out, s->rep == 0xF3 ? "pause" : "nop");
            return true;
        }
        x86_set_mnem(s, out, "xchg");
        if (s->want_text) snprintf(out->ops, sizeof(out->ops), "%s, %s", x86_reg_name(s, reg, sz), x86_reg_name(s, 0, sz));
        return true;
    }

    if (op == 0x98 || op == 0x99 || op == 0x9C || op == 0x9D || op == 0x9E || op == 0x9F) {
        const char *m = "??";
        if (op == 0x98) m = (s->bits == 64 && (s->rex & 8)) ? "cdqe" : (s->osz ? "cbw" : "cwde");
        else if (op == 0x99) m = (s->bits == 64 && (s->rex & 8)) ? "cqo" : (s->osz ? "cwd" : "cdq");
        else if (op == 0x9C) m = s->osz ? "pushf" : ((s->bits == 64) ? "pushfq" : "pushfd");
        else if (op == 0x9D) m = s->osz ? "popf" : ((s->bits == 64) ? "popfq" : "popfd");
        else if (op == 0x9E) m = "sahf";
        else m = "lahf";
        x86_set_mnem(s, out, m);
        return true;
    }

    if (op >= 0xA0 && op <= 0xA3) {
        uint64_t addr = 0;
        if (s->bits == 64 && !s->asz) { if (!x86_rd64(s, &addr)) return false; }
        else if (s->bits == 32 && s->asz) { uint16_t v; if (!x86_rd16(s, &v)) return false; addr = v; }
        else { uint32_t v; if (!x86_rd32(s, &v)) return false; addr = v; }
        int osz = (op == 0xA0 || op == 0xA2) ? 1 : sz;
        out->target = addr;
        out->has_target = 1;
        out->target_mem = 1;
        x86_set_mnem(s, out, "mov");
        if (s->want_text) {
            char segp[8] = "";
            if (s->seg) snprintf(segp, sizeof(segp), "%s:", x86_seg[s->seg - 1]);
            if (op <= 0xA1) snprintf(out->ops, sizeof(out->ops), "%s, %s[0x%llx]", x86_reg_name(s, 0, osz), segp, (unsigned long long)addr);
            else snprintf(out->ops, sizeof(out->ops), "%s[0x%llx], %s", segp, (unsigned long long)addr, x86_reg_name(s, 0, osz));
        }
        return true;
    }

    if (op >= 0xA4 && op <= 0xAF) {
        if (op == 0xA8 || op == 0xA9) {
            int osz = (op == 0xA8) ? 1 : sz;
            int64_t imm = 0;
            if (op == 0xA8) { uint8_t v; if (!x86_rd8(s, &v)) return false; imm = v; }
            else if (sz == 2) { uint16_t v; if (!x86_rd16(s, &v)) return false; imm = v; }
            else { uint32_t v; if (!x86_rd32(s, &v)) return false; imm = (sz == 8) ? (int64_t)(int32_t)v : (int64_t)v; }
            x86_set_mnem(s, out, "test");
            if (s->want_text) snprintf(out->ops, sizeof(out->ops), "%s, 0x%llx", x86_reg_name(s, 0, osz), (unsigned long long)x86_mask_imm(imm, osz));
            return true;
        }
        static const char *const st[6] = {"movs","cmps","??","stos","lods","scas"};
        int kind = (op - 0xA4) >> 1;
        char suf = (op & 1) ? ((s->bits == 64 && (s->rex & 8)) ? 'q' : (s->osz ? 'w' : 'd')) : 'b';
        if (s->want_text) {
            const char *rp = "";
            if (s->rep == 0xF3) rp = (kind == 1 || kind == 5) ? "repe " : "rep ";
            else if (s->rep == 0xF2) rp = "repne ";
            snprintf(out->mnem, sizeof(out->mnem), "%s%s%c", rp, st[kind], suf);
        }
        return true;
    }

    if (op >= 0xB0 && op <= 0xBF) {
        int reg = (op & 7) | ((s->rex & 1) ? 8 : 0);
        if (s->bits == 32) reg &= 7;
        int osz = (op < 0xB8) ? 1 : sz;
        uint64_t imm = 0;
        if (osz == 1) { uint8_t v; if (!x86_rd8(s, &v)) return false; imm = v; }
        else if (osz == 2) { uint16_t v; if (!x86_rd16(s, &v)) return false; imm = v; }
        else if (osz == 4) { uint32_t v; if (!x86_rd32(s, &v)) return false; imm = v; }
        else { if (!x86_rd64(s, &imm)) return false; }
        x86_set_mnem(s, out, (osz == 8) ? "movabs" : "mov");
        if (s->want_text) snprintf(out->ops, sizeof(out->ops), "%s, 0x%llx", x86_reg_name(s, reg, osz), (unsigned long long)imm);
        return true;
    }

    if (op == 0xC0 || op == 0xC1 || (op >= 0xD0 && op <= 0xD3)) {
        if (!x86_parse_modrm(s)) return false;
        int osz = (op == 0xC0 || op == 0xD0 || op == 0xD2) ? 1 : sz;
        uint8_t imm = 1;
        int use_cl = (op == 0xD2 || op == 0xD3);
        if (op == 0xC0 || op == 0xC1) {
            if (!x86_rd8(s, &imm)) return false;
        }
        int grp = (s->modrm >> 3) & 7;
        x86_finish_rip(s, out);
        if (s->want_text) {
            char lhs[56];
            x86_fmt_rm(s, lhs, sizeof(lhs), osz, 0, 1);
            x86_set_mnem(s, out, x86_shift[grp]);
            if (use_cl) snprintf(out->ops, sizeof(out->ops), "%s, cl", lhs);
            else snprintf(out->ops, sizeof(out->ops), "%s, 0x%x", lhs, imm);
        }
        return true;
    }

    if (op == 0xC2 || op == 0xC3 || op == 0xCA || op == 0xCB || op == 0xCF) {
        uint16_t imm = 0;
        int has_imm = (op == 0xC2 || op == 0xCA);
        if (has_imm && !x86_rd16(s, &imm)) return false;
        out->flow = X86_FLOW_RET;
        const char *m;
        if (op == 0xCF) {
            m = (s->bits == 64 && (s->rex & 8)) ? "iretq" : (s->osz ? "iret" : "iretd");
        } else {
            m = (op >= 0xCA) ? "retf" : "ret";
        }
        x86_set_mnem(s, out, m);
        if (s->want_text && has_imm) snprintf(out->ops, sizeof(out->ops), "0x%x", imm);
        return true;
    }

    if (op == 0xC6 || op == 0xC7) {
        if (!x86_parse_modrm(s)) return false;
        if (op == 0xC6 && s->modrm == 0xF8) {
            uint8_t imm8;
            if (!x86_rd8(s, &imm8)) return false;
            x86_set_mnem(s, out, "xabort");
            if (s->want_text) snprintf(out->ops, sizeof(out->ops), "0x%x", imm8);
            return true;
        }
        if (op == 0xC7 && s->modrm == 0xF8) {
            uint32_t rel;
            if (!x86_rd32(s, &rel)) return false;
            out->target = s->ip + s->pos + (uint64_t)(int64_t)(int32_t)rel;
            out->has_target = 1;
            x86_set_mnem(s, out, "xbegin");
            if (s->want_text) snprintf(out->ops, sizeof(out->ops), "0x%llx", (unsigned long long)out->target);
            return true;
        }
        int osz = (op == 0xC6) ? 1 : sz;
        int64_t imm = 0;
        if (osz == 1) { uint8_t v; if (!x86_rd8(s, &v)) return false; imm = v; }
        else if (osz == 2) { uint16_t v; if (!x86_rd16(s, &v)) return false; imm = v; }
        else { uint32_t v; if (!x86_rd32(s, &v)) return false; imm = (osz == 8) ? (int64_t)(int32_t)v : (int64_t)v; }
        x86_finish_rip(s, out);
        if (s->want_text) {
            char lhs[56];
            x86_fmt_rm(s, lhs, sizeof(lhs), osz, 0, 1);
            x86_set_mnem(s, out, "mov");
            snprintf(out->ops, sizeof(out->ops), "%s, 0x%llx", lhs, (unsigned long long)x86_mask_imm(imm, osz));
        }
        return true;
    }

    if (op == 0xC8) {
        uint16_t a; uint8_t b;
        if (!x86_rd16(s, &a) || !x86_rd8(s, &b)) return false;
        x86_set_mnem(s, out, "enter");
        if (s->want_text) snprintf(out->ops, sizeof(out->ops), "0x%x, 0x%x", a, b);
        return true;
    }

    if (op == 0xC9) { x86_set_mnem(s, out, "leave"); return true; }
    if (op == 0xCC) { out->flow = X86_FLOW_TRAP; x86_set_mnem(s, out, "int3"); return true; }
    if (op == 0xCD) {
        uint8_t v;
        if (!x86_rd8(s, &v)) return false;
        x86_set_mnem(s, out, "int");
        if (s->want_text) snprintf(out->ops, sizeof(out->ops), "0x%x", v);
        return true;
    }

    if (op >= 0xE0 && op <= 0xE3) {
        uint8_t rel;
        if (!x86_rd8(s, &rel)) return false;
        out->flow = X86_FLOW_JCC;
        out->target = s->ip + s->pos + (uint64_t)(int64_t)(int8_t)rel;
        out->has_target = 1;
        const char *m;
        if (op == 0xE0) m = "loopne";
        else if (op == 0xE1) m = "loope";
        else if (op == 0xE2) m = "loop";
        else m = (s->bits == 64) ? (s->asz ? "jecxz" : "jrcxz") : (s->asz ? "jcxz" : "jecxz");
        x86_set_mnem(s, out, m);
        if (s->want_text) snprintf(out->ops, sizeof(out->ops), "0x%llx", (unsigned long long)out->target);
        return true;
    }

    if (op == 0xE8 || op == 0xE9 || op == 0xEB) {
        int64_t rel = 0;
        if (op == 0xEB) { uint8_t v; if (!x86_rd8(s, &v)) return false; rel = (int8_t)v; }
        else if (s->bits == 32 && s->osz) { uint16_t v; if (!x86_rd16(s, &v)) return false; rel = (int16_t)v; }
        else { uint32_t v; if (!x86_rd32(s, &v)) return false; rel = (int32_t)v; }
        out->flow = (op == 0xE8) ? X86_FLOW_CALL : X86_FLOW_JMP;
        out->target = s->ip + s->pos + (uint64_t)rel;
        out->has_target = 1;
        x86_set_mnem(s, out, (op == 0xE8) ? "call" : "jmp");
        if (s->want_text) snprintf(out->ops, sizeof(out->ops), "0x%llx", (unsigned long long)out->target);
        return true;
    }

    if (op == 0xF4 || op == 0xF5 || (op >= 0xF8 && op <= 0xFD)) {
        static const char *const fm[10] = {"hlt","cmc","??","??","clc","stc","cli","sti","cld","std"};
        if (op == 0xF4) out->flow = X86_FLOW_TRAP;
        x86_set_mnem(s, out, fm[op - 0xF4]);
        return true;
    }

    if (op == 0xF6 || op == 0xF7) {
        if (!x86_parse_modrm(s)) return false;
        int osz = (op == 0xF6) ? 1 : sz;
        int grp = (s->modrm >> 3) & 7;
        int64_t imm = 0;
        int has_imm = (grp == 0 || grp == 1);
        if (has_imm) {
            if (osz == 1) { uint8_t v; if (!x86_rd8(s, &v)) return false; imm = v; }
            else if (osz == 2) { uint16_t v; if (!x86_rd16(s, &v)) return false; imm = v; }
            else { uint32_t v; if (!x86_rd32(s, &v)) return false; imm = (osz == 8) ? (int64_t)(int32_t)v : (int64_t)v; }
        }
        x86_finish_rip(s, out);
        if (s->want_text) {
            char lhs[56];
            x86_fmt_rm(s, lhs, sizeof(lhs), osz, 0, 1);
            x86_set_mnem(s, out, x86_grp3[grp]);
            if (has_imm) snprintf(out->ops, sizeof(out->ops), "%s, 0x%llx", lhs, (unsigned long long)x86_mask_imm(imm, osz));
            else snprintf(out->ops, sizeof(out->ops), "%s", lhs);
        }
        return true;
    }

    if (op == 0xFE || op == 0xFF) {
        if (!x86_parse_modrm(s)) return false;
        int grp = (s->modrm >> 3) & 7;
        if (op == 0xFE && grp > 1) return false;
        if (op == 0xFF && grp == 7) return false;
        int osz = (op == 0xFE) ? 1 : (grp == 2 || grp == 4 || grp == 6 ? x86_opsize_def64(s) : (grp == 3 || grp == 5 ? 6 : sz));
        if (op == 0xFF && (grp == 2 || grp == 3)) out->flow = X86_FLOW_CALL;
        else if (op == 0xFF && (grp == 4 || grp == 5)) out->flow = X86_FLOW_JMP;
        x86_finish_rip(s, out);
        if (s->want_text) {
            char rm[56];
            x86_fmt_rm(s, rm, sizeof(rm), osz, 0, 1);
            x86_set_mnem(s, out, x86_grp5[grp]);
            snprintf(out->ops, sizeof(out->ops), "%s", rm);
        }
        return true;
    }

    if (op == 0x9B) { x86_set_mnem(s, out, "fwait"); return true; }
    if (op == 0xD7) { x86_set_mnem(s, out, "xlatb"); return true; }
    if (op == 0xF1) { out->flow = X86_FLOW_TRAP; x86_set_mnem(s, out, "int1"); return true; }

    if (op >= 0xE4 && op <= 0xE7) {
        uint8_t port;
        if (!x86_rd8(s, &port)) return false;
        int is_out = (op >= 0xE6);
        int osz = (op & 1) ? (s->osz ? 2 : 4) : 1;
        x86_set_mnem(s, out, is_out ? "out" : "in");
        if (s->want_text) {
            if (is_out) snprintf(out->ops, sizeof(out->ops), "0x%x, %s", port, x86_reg_name(s, 0, osz));
            else snprintf(out->ops, sizeof(out->ops), "%s, 0x%x", x86_reg_name(s, 0, osz), port);
        }
        return true;
    }

    if (op >= 0xEC && op <= 0xEF) {
        int is_out = (op >= 0xEE);
        int osz = (op & 1) ? (s->osz ? 2 : 4) : 1;
        x86_set_mnem(s, out, is_out ? "out" : "in");
        if (s->want_text) {
            if (is_out) snprintf(out->ops, sizeof(out->ops), "dx, %s", x86_reg_name(s, 0, osz));
            else snprintf(out->ops, sizeof(out->ops), "%s, dx", x86_reg_name(s, 0, osz));
        }
        return true;
    }

    if (op >= 0xD8 && op <= 0xDF) {
        return x86_decode_x87(s, op, out);
    }

    return false;
}

/* =========================================================================
 * VEX (0xC4 / 0xC5) & EVEX (0x62) Prefix Decoders
 * ========================================================================= */
static bool x86_decode_vex(x86_st *s, uint8_t lead, x86_ins *out) {
    uint8_t b1, b2, map = 1;
    if (!x86_rd8(s, &b1)) return false;
    s->is_vex = 1;
    if (lead == 0xC5) {
        if (s->bits == 64 && !(b1 & 0x80)) s->rex |= 4;
        s->vex_v = (uint8_t)(((~b1) >> 3) & (s->bits == 64 ? 15 : 7));
        s->vex_l = (b1 >> 2) & 1;
        s->vex_pp = b1 & 3;
        s->vex_w = 0;
    } else {
        if (!x86_rd8(s, &b2)) return false;
        if (s->bits == 64) {
            if (!(b1 & 0x80)) s->rex |= 4;
            if (!(b1 & 0x40)) s->rex |= 2;
            if (!(b1 & 0x20)) s->rex |= 1;
        }
        map = b1 & 31;
        s->vex_w = (b2 >> 7) & 1;
        if (s->bits == 64 && s->vex_w) s->rex |= 8;
        s->vex_v = (uint8_t)(((~b2) >> 3) & (s->bits == 64 ? 15 : 7));
        s->vex_l = (b2 >> 2) & 1;
        s->vex_pp = b2 & 3;
    }
    s->osz = (s->vex_pp == 1);
    s->rep = (s->vex_pp == 2) ? 0xF3 : (s->vex_pp == 3) ? 0xF2 : 0;

    if (map == 1) return x86_decode_0f(s, out);
    if (map == 2) return x86_decode_0f38(s, out);
    if (map == 3) return x86_decode_0f3a(s, out);
    return false;
}

static bool x86_decode_evex(x86_st *s, x86_ins *out) {
    uint8_t p0, p1, p2;
    if (!x86_rd8(s, &p0) || !x86_rd8(s, &p1) || !x86_rd8(s, &p2)) return false;
    if ((p0 & 0x0C) != 0 || !(p1 & 0x04)) return false;
    uint8_t map = p0 & 3;
    if (map == 0) return false;

    s->is_vex = 1;
    s->is_evex = 1;
    if (s->bits == 64) {
        if (!(p0 & 0x80)) s->rex |= 4;
        if (!(p0 & 0x40)) { s->rex |= 2; s->evex_x = 1; }
        if (!(p0 & 0x20)) s->rex |= 1;
        if (!(p0 & 0x10)) s->evex_rp = 1;
        if (!(p2 & 0x08)) s->evex_vp = 1;
    }
    s->vex_w = (p1 >> 7) & 1;
    if (s->bits == 64 && s->vex_w) s->rex |= 8;
    s->vex_v = (uint8_t)((((~p1) >> 3) & 15) | (s->evex_vp ? 16 : 0));
    if (s->bits == 32) s->vex_v &= 7;
    s->vex_pp = p1 & 3;
    s->evex_z = (p2 >> 7) & 1;
    s->vex_l  = (p2 >> 5) & 3;
    s->evex_b = (p2 >> 4) & 1;
    s->evex_k = p2 & 7;
    s->osz = (s->vex_pp == 1);
    s->rep = (s->vex_pp == 2) ? 0xF3 : (s->vex_pp == 3) ? 0xF2 : 0;

    if (map == 1) return x86_decode_0f(s, out);
    if (map == 2) return x86_decode_0f38(s, out);
    if (map == 3) return x86_decode_0f3a(s, out);
    return false;
}

/* =========================================================================
 * AMD XOP (0x8F) Prefix Decoder (Maps 8, 9, 10 + TBM / LWP)
 * ========================================================================= */
static bool x86_decode_xop(x86_st *s, x86_ins *out) {
    uint8_t b1, b2, op;
    if (!x86_rd8(s, &b1) || !x86_rd8(s, &b2) || !x86_rd8(s, &op)) return false;
    uint8_t map = b1 & 0x1F;
    if (map < 8 || map > 10) return false;
    if ((b2 & 3) != 0) return false; /* AMD XOP requires pp == 0 */

    s->is_vex = 1;
    if (s->bits == 64) {
        if (!(b1 & 0x80)) s->rex |= 4;
        if (!(b1 & 0x40)) s->rex |= 2;
        if (!(b1 & 0x20)) s->rex |= 1;
    }
    s->vex_w = (b2 >> 7) & 1;
    if (s->bits == 64 && s->vex_w) s->rex |= 8;
    s->vex_v = (uint8_t)(((~b2) >> 3) & (s->bits == 64 ? 15 : 7));
    s->vex_l = (b2 >> 2) & 1;
    s->vex_pp = 0;

    if (!x86_parse_modrm(s)) return false;

    int w = (int)s->vex_w;
    int vl = (int)s->vex_l;
    int reg_v = x86_modrm_reg_vec(s);
    int reg_g = x86_modrm_reg_gpr(s);
    int gsz = (s->bits == 64 && w) ? 8 : 4;

    if (map == 8) {
        uint8_t imm;
        if (!x86_rd8(s, &imm)) return false;
        if (((op >= 0xCC && op <= 0xCF) || (op >= 0xEC && op <= 0xEF)) && (w || vl)) return false;
        x86_finish_rip(s, out);
        if (!s->want_text) return true;

        const char *m = NULL;
        int kind = 0; /* 0=4reg(reg,vvvv,rm,s3), 1=4reg_w(vpcmov/vpperm), 2=rot_imm(reg,rm,imm), 3=cmp_imm(reg,vvvv,rm,imm) */
        switch (op) {
        case 0x85: m = "vpmacssww"; kind = 0; vl = 0; break;
        case 0x86: m = "vpmacsswd"; kind = 0; vl = 0; break;
        case 0x87: m = "vpmacssdql"; kind = 0; vl = 0; break;
        case 0x8E: m = "vpmacssdd"; kind = 0; vl = 0; break;
        case 0x8F: m = "vpmacssdqh"; kind = 0; vl = 0; break;
        case 0x95: m = "vpmacsww"; kind = 0; vl = 0; break;
        case 0x96: m = "vpmacswd"; kind = 0; vl = 0; break;
        case 0x97: m = "vpmacsdql"; kind = 0; vl = 0; break;
        case 0x9E: m = "vpmacsdd"; kind = 0; vl = 0; break;
        case 0x9F: m = "vpmacsdqh"; kind = 0; vl = 0; break;
        case 0xA2: m = "vpcmov"; kind = 1; break;
        case 0xA3: m = "vpperm"; kind = 1; vl = 0; break;
        case 0xA6: m = "vpmadcsswd"; kind = 0; vl = 0; break;
        case 0xB6: m = "vpmadcswd"; kind = 0; vl = 0; break;
        case 0xC0: m = "vprotb"; kind = 2; vl = 0; break;
        case 0xC1: m = "vprotw"; kind = 2; vl = 0; break;
        case 0xC2: m = "vprotd"; kind = 2; vl = 0; break;
        case 0xC3: m = "vprotq"; kind = 2; vl = 0; break;
        case 0xCC: m = "vpcomb"; kind = 3; vl = 0; break;
        case 0xCD: m = "vpcomw"; kind = 3; vl = 0; break;
        case 0xCE: m = "vpcomd"; kind = 3; vl = 0; break;
        case 0xCF: m = "vpcomq"; kind = 3; vl = 0; break;
        case 0xEC: m = "vpcomub"; kind = 3; vl = 0; break;
        case 0xED: m = "vpcomuw"; kind = 3; vl = 0; break;
        case 0xEE: m = "vpcomud"; kind = 3; vl = 0; break;
        case 0xEF: m = "vpcomuq"; kind = 3; vl = 0; break;
        default: break;
        }

        char mn[20], dst[16], vsrc[16], rm[56], s3[16];
        if (m) snprintf(mn, sizeof(mn), "%s", m);
        else snprintf(mn, sizeof(mn), "xop8_%02x", op);
        x86_set_mnem(s, out, mn);
        x86_xmm_name(dst, sizeof(dst), reg_v, vl);
        x86_xmm_name(vsrc, sizeof(vsrc), s->vex_v, vl);
        x86_fmt_rm_ex(s, rm, sizeof(rm), x86_vec_bytes(vl), 1, 0, vl, 0, -1);
        if (!m || kind == 3) {
            snprintf(out->ops, sizeof(out->ops), "%s, %s, %s, 0x%x", dst, vsrc, rm, imm);
        } else if (kind == 2) {
            snprintf(out->ops, sizeof(out->ops), "%s, %s, 0x%x", dst, rm, imm);
        } else {
            int s3_idx = (imm >> 4) & ((s->bits == 64) ? 15 : 7);
            x86_xmm_name(s3, sizeof(s3), s3_idx, vl);
            if (kind == 1 && w) snprintf(out->ops, sizeof(out->ops), "%s, %s, %s, %s", dst, vsrc, s3, rm);
            else snprintf(out->ops, sizeof(out->ops), "%s, %s, %s, %s", dst, vsrc, rm, s3);
        }
        return true;
    }

    if (map == 9) {
        x86_finish_rip(s, out);
        if (op == 0x01 || op == 0x02) {
            int g = (s->modrm >> 3) & 7;
            const char *m = NULL;
            if (op == 0x01) {
                static const char *const tbm1[8] = {NULL,"blcfill","blsfill","blcs","tzmsk","blcic","blsic","t1mskc"};
                m = tbm1[g];
            } else {
                if (g == 1) m = "blcmsk";
                else if (g == 6) m = "blci";
            }
            if (m) {
                x86_set_mnem(s, out, m);
                if (s->want_text) {
                    char rm[56];
                    int vvvv = s->vex_v & ((s->bits == 64) ? 15 : 7);
                    x86_fmt_rm(s, rm, sizeof(rm), gsz, 0, 0);
                    snprintf(out->ops, sizeof(out->ops), "%s, %s", x86_reg_name(s, vvvv, gsz), rm);
                }
                return true;
            }
        }
        if (op == 0x12) {
            int g = (s->modrm >> 3) & 7;
            if (g == 0 || g == 1) {
                x86_set_mnem(s, out, g == 0 ? "llwpcb" : "slwpcb");
                if (s->want_text) {
                    char rm[56];
                    x86_fmt_rm(s, rm, sizeof(rm), gsz, 0, 0);
                    snprintf(out->ops, sizeof(out->ops), "%s", rm);
                }
                return true;
            }
        }
        if (!s->want_text) return true;

        const char *m = NULL;
        int kind = 0; /* 0=2op(reg,rm), 1=3op_w(reg,rm,vvvv / reg,vvvv,rm) */
        int msz_ov = 0;
        switch (op) {
        case 0x80: m = "vfrczps"; break;
        case 0x81: m = "vfrczpd"; break;
        case 0x82: m = "vfrczss"; vl = 0; msz_ov = 4; break;
        case 0x83: m = "vfrczsd"; vl = 0; msz_ov = 8; break;
        case 0x90: m = "vprotb"; kind = 1; vl = 0; break;
        case 0x91: m = "vprotw"; kind = 1; vl = 0; break;
        case 0x92: m = "vprotd"; kind = 1; vl = 0; break;
        case 0x93: m = "vprotq"; kind = 1; vl = 0; break;
        case 0x94: m = "vpshlb"; kind = 1; vl = 0; break;
        case 0x95: m = "vpshlw"; kind = 1; vl = 0; break;
        case 0x96: m = "vpshld"; kind = 1; vl = 0; break;
        case 0x97: m = "vpshlq"; kind = 1; vl = 0; break;
        case 0x98: m = "vpshab"; kind = 1; vl = 0; break;
        case 0x99: m = "vpshaw"; kind = 1; vl = 0; break;
        case 0x9A: m = "vpshad"; kind = 1; vl = 0; break;
        case 0x9B: m = "vpshaq"; kind = 1; vl = 0; break;
        case 0xC1: m = "vphaddbw"; vl = 0; break;
        case 0xC2: m = "vphaddbd"; vl = 0; break;
        case 0xC3: m = "vphaddbq"; vl = 0; break;
        case 0xC6: m = "vphaddwd"; vl = 0; break;
        case 0xC7: m = "vphaddwq"; vl = 0; break;
        case 0xCB: m = "vphadddq"; vl = 0; break;
        case 0xD1: m = "vphaddubw"; vl = 0; break;
        case 0xD2: m = "vphaddubd"; vl = 0; break;
        case 0xD3: m = "vphaddubq"; vl = 0; break;
        case 0xD6: m = "vphadduwd"; vl = 0; break;
        case 0xD7: m = "vphadduwq"; vl = 0; break;
        case 0xDB: m = "vphaddudq"; vl = 0; break;
        case 0xE1: m = "vphsubbw"; vl = 0; break;
        case 0xE2: m = "vphsubwd"; vl = 0; break;
        case 0xE3: m = "vphsubdq"; vl = 0; break;
        default: break;
        }

        char mn[20], dst[16], vsrc[16], rm[56];
        if (m) snprintf(mn, sizeof(mn), "%s", m);
        else snprintf(mn, sizeof(mn), "xop9_%02x", op);
        x86_set_mnem(s, out, mn);
        x86_xmm_name(dst, sizeof(dst), reg_v, vl);
        x86_fmt_rm_ex(s, rm, sizeof(rm), msz_ov ? msz_ov : x86_vec_bytes(vl), 1, 0, vl, 0, -1);
        if (kind == 1) {
            x86_xmm_name(vsrc, sizeof(vsrc), s->vex_v, vl);
            if (w) snprintf(out->ops, sizeof(out->ops), "%s, %s, %s", dst, vsrc, rm);
            else snprintf(out->ops, sizeof(out->ops), "%s, %s, %s", dst, rm, vsrc);
        } else {
            snprintf(out->ops, sizeof(out->ops), "%s, %s", dst, rm);
        }
        return true;
    }

    /* map == 10 (0x0A): ModRM + imm32 */
    uint32_t imm32;
    if (!x86_rd32(s, &imm32)) return false;
    x86_finish_rip(s, out);
    if (!s->want_text) return true;

    if (op == 0x10) {
        char rm[56];
        x86_set_mnem(s, out, "bextr");
        x86_fmt_rm(s, rm, sizeof(rm), gsz, 0, 0);
        snprintf(out->ops, sizeof(out->ops), "%s, %s, 0x%x", x86_reg_name(s, reg_g, gsz), rm, imm32);
        return true;
    }
    if (op == 0x12) {
        int g = (s->modrm >> 3) & 7;
        if (g == 0 || g == 1) {
            char rm[56];
            int vvvv = s->vex_v & ((s->bits == 64) ? 15 : 7);
            x86_set_mnem(s, out, g == 0 ? "lwpins" : "lwpval");
            x86_fmt_rm(s, rm, sizeof(rm), 4, 0, (s->modrm >> 6) != 3);
            snprintf(out->ops, sizeof(out->ops), "%s, %s, 0x%x", x86_reg_name(s, vvvv, gsz), rm, imm32);
            return true;
        }
    }
    char mn[20], rm[56];
    snprintf(mn, sizeof(mn), "xop10_%02x", op);
    x86_set_mnem(s, out, mn);
    x86_fmt_rm(s, rm, sizeof(rm), gsz, 0, 0);
    snprintf(out->ops, sizeof(out->ops), "%s, %s, 0x%x", x86_reg_name(s, reg_g, gsz), rm, imm32);
    return true;
}

int x86_decode(const uint8_t *code, size_t avail, uint64_t ip, int bits, int want_text, int upper, x86_ins *out) {
    memset(out, 0, sizeof(*out));
    out->ip = ip;
    if (!code || avail == 0) {
        out->len = 0;
        return 0;
    }

    x86_st s;
    memset(&s, 0, sizeof(s));
    s.code = code;
    s.avail = avail;
    s.ip = ip;
    s.bits = (bits == 32) ? 32 : 64;
    s.want_text = want_text;
    s.vex_v = 32;
    s.disp8_scale = 1;

    while (s.pos < avail && s.pos < 14) {
        uint8_t b = code[s.pos];
        if (b == 0xF0) { s.lock = 1; s.pos++; }
        else if (b == 0xF2 || b == 0xF3) { s.rep = b; s.pos++; }
        else if (b == 0x66) { s.osz = 1; s.pos++; }
        else if (b == 0x67) { s.asz = 1; s.pos++; }
        else if (b == 0x26) { s.seg = 1; s.pos++; }
        else if (b == 0x2E) { s.seg = 2; s.pos++; }
        else if (b == 0x36) { s.seg = 3; s.pos++; }
        else if (b == 0x3E) { s.seg = 4; s.pos++; }
        else if (b == 0x64) { s.seg = 5; s.pos++; }
        else if (b == 0x65) { s.seg = 6; s.pos++; }
        else break;
    }

    if (s.bits == 64 && s.pos < avail && (code[s.pos] & 0xF0) == 0x40) {
        s.rex = code[s.pos++];
        s.has_rex = 1;
    }

    uint8_t op;
    bool ok = false;
    if (x86_rd8(&s, &op)) {
        if (op == 0x0F) {
            ok = x86_decode_0f(&s, out);
        } else if (op == 0x62 && !s.has_rex &&
                   (s.bits == 64 || (s.pos + 2 < avail && (code[s.pos] & 0xC0) == 0xC0))) {
            ok = x86_decode_evex(&s, out);
        } else if ((op == 0xC4 || op == 0xC5) && !s.has_rex &&
                   (s.bits == 64 || (s.pos < avail && (code[s.pos] & 0xC0) == 0xC0))) {
            ok = x86_decode_vex(&s, op, out);
        } else if (op == 0x8F && !s.has_rex && !s.osz && !s.rep && !s.lock &&
                   s.pos < avail && ((code[s.pos] & 0x1F) >= 8 && (code[s.pos] & 0x1F) <= 10)) {
            ok = x86_decode_xop(&s, out);
        } else {
            ok = x86_decode_1b(&s, op, out);
        }
    }

    if (!ok || s.pos == 0) {
        out->len = 1;
        out->flow = X86_FLOW_NONE;
        out->has_target = 0;
        out->target_mem = 0;
        if (want_text) {
            snprintf(out->mnem, sizeof(out->mnem), "db");
            snprintf(out->ops, sizeof(out->ops), "0x%02x", code[0]);
        }
    } else {
        out->len = (uint8_t)s.pos;
    }

    if (want_text && upper) {
        for (char *p = out->mnem; *p; p++) *p = (char)toupper((unsigned char)*p);
    }
    return out->len;
}
