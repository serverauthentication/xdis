#include "arch.h"

#include <ctype.h>
#include <limits.h>
#include <stdbool.h>
#include <string.h>

typedef struct {
    uint8_t *buf;
    int      len;
    bool     err;
} asm_em;

typedef struct {
    int  idx;
    int  sz;
    bool is_hi8;
    bool need_rex;
} asm_reg;

typedef struct {
    int     sz;        /* 0 = unspecified, else 1, 2, 4, 8 */
    uint8_t seg;       /* 0 = none, else segment override opcode */
    int     addr_sz;   /* 0 = default, else 4 or 8 */
    bool    is_rip;
    bool    has_base;
    int     base;
    bool    has_index;
    int     index;
    int     scale;     /* 1, 2, 4, 8 */
    bool    has_disp;
    int64_t disp;
} asm_mem;

static void asm_u8(asm_em *e, uint8_t v) {
    if (e->err || e->len + 1 > 15) { e->err = true; return; }
    e->buf[e->len++] = v;
}

static void asm_u16(asm_em *e, uint16_t v) {
    if (e->err || e->len + 2 > 15) { e->err = true; return; }
    memcpy(e->buf + e->len, &v, 2);
    e->len += 2;
}

static void asm_u32(asm_em *e, uint32_t v) {
    if (e->err || e->len + 4 > 15) { e->err = true; return; }
    memcpy(e->buf + e->len, &v, 4);
    e->len += 4;
}

static void asm_u64(asm_em *e, uint64_t v) {
    if (e->err || e->len + 8 > 15) { e->err = true; return; }
    memcpy(e->buf + e->len, &v, 8);
    e->len += 8;
}

static int asm_done(const asm_em *e) {
    return e->err ? 0 : e->len;
}

static bool asm_emit_rex(asm_em *e, int is64, int w, int r, int x, int b,
                         bool force_rex, bool forbid_rex) {
    uint8_t v = (uint8_t)((w ? 8 : 0) | (r ? 4 : 0) | (x ? 2 : 0) | (b ? 1 : 0));
    bool need = (v != 0) || force_rex;
    if (need) {
        if (!is64 || forbid_rex) return false;
        asm_u8(e, (uint8_t)(0x40U | v));
    }
    return true;
}

static const char *asm_skip_ws(const char *p) {
    while (*p == ' ' || *p == '\t') p++;
    return p;
}

static bool asm_at_end(const char *p) {
    p = asm_skip_ws(p);
    return *p == 0 || *p == ';' || *p == '\r' || *p == '\n';
}

static bool asm_read_word(const char **pp, char *dst, size_t max) {
    const char *p = asm_skip_ws(*pp);
    size_t n = 0;
    while (isalnum((unsigned char)*p) || *p == '_') {
        if (n + 1 >= max) return false;
        dst[n++] = (char)tolower((unsigned char)*p);
        p++;
    }
    dst[n] = 0;
    *pp = p;
    return n > 0;
}

static bool asm_read_op(const char **pp, char *dst, size_t max) {
    const char *p = asm_skip_ws(*pp);
    size_t n = 0;
    while (*p && *p != ',' && *p != ';' && *p != '\r' && *p != '\n') {
        if (n + 1 >= max) return false;
        dst[n++] = *p++;
    }
    while (n > 0 && (dst[n - 1] == ' ' || dst[n - 1] == '\t')) n--;
    dst[n] = 0;
    *pp = p;
    return n > 0;
}

static bool asm_parse_reg(const char *s, int is64, asm_reg *out) {
    static const char *const r64[16] = {
        "rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi",
        "r8","r9","r10","r11","r12","r13","r14","r15"
    };
    static const char *const r32[16] = {
        "eax","ecx","edx","ebx","esp","ebp","esi","edi",
        "r8d","r9d","r10d","r11d","r12d","r13d","r14d","r15d"
    };
    static const char *const r16[16] = {
        "ax","cx","dx","bx","sp","bp","si","di",
        "r8w","r9w","r10w","r11w","r12w","r13w","r14w","r15w"
    };
    static const char *const r8[16] = {
        "al","cl","dl","bl","spl","bpl","sil","dil",
        "r8b","r9b","r10b","r11b","r12b","r13b","r14b","r15b"
    };
    static const char *const r8h[4] = { "ah","ch","dh","bh" };

    s = asm_skip_ws(s);
    char low[16];
    size_t n = 0;
    while (s[n] && s[n] != ' ' && s[n] != '\t') {
        if (n + 1 >= sizeof(low)) return false;
        low[n] = (char)tolower((unsigned char)s[n]);
        n++;
    }
    if (n == 0 || *asm_skip_ws(s + n) != 0) return false;
    low[n] = 0;

    memset(out, 0, sizeof(*out));
    for (int i = 0; i < 4; i++) {
        if (strcmp(low, r8h[i]) == 0) {
            out->idx = i + 4;
            out->sz = 1;
            out->is_hi8 = true;
            return true;
        }
    }
    for (int i = 0; i < 16; i++) {
        if (strcmp(low, r64[i]) == 0) {
            if (!is64) return false;
            out->idx = i;
            out->sz = 8;
            return true;
        }
        if (strcmp(low, r32[i]) == 0) {
            if (!is64 && i >= 8) return false;
            out->idx = i;
            out->sz = 4;
            return true;
        }
        if (strcmp(low, r16[i]) == 0) {
            if (!is64 && i >= 8) return false;
            out->idx = i;
            out->sz = 2;
            return true;
        }
        if (strcmp(low, r8[i]) == 0) {
            if (!is64 && i >= 4) return false;
            out->idx = i;
            out->sz = 1;
            out->need_rex = (i >= 4 && i <= 7);
            return true;
        }
    }
    return false;
}

static bool asm_parse_imm(const char *s, bool hex_hint, uint64_t *val, bool *is_neg) {
    s = asm_skip_ws(s);
    if (!*s) return false;

    bool neg = false;
    if (*s == '-') { neg = true; s++; }
    else if (*s == '+') { s++; }
    if (!*s) return false;

    size_t len = strlen(s);
    while (len > 0 && (s[len - 1] == ' ' || s[len - 1] == '\t')) len--;
    if (len == 0) return false;

    int base = 10;
    if (len > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        base = 16;
        s += 2;
        len -= 2;
    } else if (len > 1 && (s[len - 1] == 'h' || s[len - 1] == 'H')) {
        base = 16;
        len -= 1;
    } else if (hex_hint) {
        base = 16;
    }
    if (len == 0) return false;

    uint64_t v = 0;
    for (size_t i = 0; i < len; i++) {
        int d;
        char c = s[i];
        if (c >= '0' && c <= '9') d = c - '0';
        else if (base == 16 && c >= 'a' && c <= 'f') d = 10 + (c - 'a');
        else if (base == 16 && c >= 'A' && c <= 'F') d = 10 + (c - 'A');
        else return false;

        if (v > (UINT64_MAX - (uint64_t)d) / (uint64_t)base) return false;
        v = v * (uint64_t)base + (uint64_t)d;
    }

    if (neg) {
        if (v > (uint64_t)INT64_MAX + 1ULL) return false;
        v = ~v + 1ULL;
    }
    *val = v;
    if (is_neg) *is_neg = neg;
    return true;
}

static bool asm_imm8_ok(uint64_t u) {
    int64_t s = (int64_t)u;
    return s >= -128 && s <= 127;
}

static bool asm_imm_ok(uint64_t u, int sz, bool neg) {
    if (sz == 1) {
        if (neg) { int64_t s = (int64_t)u; return s >= -128 && s <= 0; }
        return u <= 0xFFULL;
    }
    if (sz == 2) {
        if (neg) { int64_t s = (int64_t)u; return s >= -32768 && s <= 0; }
        return u <= 0xFFFFULL;
    }
    if (sz == 4) {
        if (neg) { int64_t s = (int64_t)u; return s >= INT32_MIN && s <= 0; }
        return u <= UINT32_MAX;
    }
    if (sz == 8) {
        int64_t s = (int64_t)u;
        return s >= INT32_MIN && s <= INT32_MAX;
    }
    return false;
}

static bool asm_ieq(const char *a, const char *b) {
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) return false;
        a++;
        b++;
    }
    return *a == 0 && *b == 0;
}

static int asm_try_size_prefix(const char **pp, int is64, int *sz_out) {
    const char *p = asm_skip_ws(*pp);
    const char *q = p;
    char w[16];
    if (!asm_read_word(&q, w, sizeof(w))) return 0;

    int sz = 0;
    if (strcmp(w, "byte") == 0)       sz = 1;
    else if (strcmp(w, "word") == 0)  sz = 2;
    else if (strcmp(w, "dword") == 0) sz = 4;
    else if (strcmp(w, "qword") == 0) sz = 8;
    else return 0;

    if (sz == 8 && !is64) return -1;

    const char *after = asm_skip_ws(q);
    const char *q2 = after;
    char w2[16];
    if (asm_read_word(&q2, w2, sizeof(w2)) && strcmp(w2, "ptr") == 0) {
        after = asm_skip_ws(q2);
    }
    *sz_out = sz;
    *pp = after;
    return 1;
}

static bool asm_try_seg_prefix(const char **pp, uint8_t *seg_out) {
    const char *p = asm_skip_ws(*pp);
    if (!p[0] || !p[1]) return false;
    char c0 = (char)tolower((unsigned char)p[0]);
    char c1 = (char)tolower((unsigned char)p[1]);
    uint8_t seg = 0;
    if (c0 == 'e' && c1 == 's') seg = 0x26;
    else if (c0 == 'c' && c1 == 's') seg = 0x2E;
    else if (c0 == 's' && c1 == 's') seg = 0x36;
    else if (c0 == 'd' && c1 == 's') seg = 0x3E;
    else if (c0 == 'f' && c1 == 's') seg = 0x64;
    else if (c0 == 'g' && c1 == 's') seg = 0x65;
    else return false;

    const char *q = asm_skip_ws(p + 2);
    if (*q != ':') return false;
    *seg_out = seg;
    *pp = asm_skip_ws(q + 1);
    return true;
}

static bool asm_parse_scale(const char *s, int *sc_out) {
    uint64_t u = 0;
    bool neg = false;
    if (!asm_parse_imm(s, false, &u, &neg) || neg) return false;
    if (u == 1 || u == 2 || u == 4 || u == 8) {
        *sc_out = (int)u;
        return true;
    }
    return false;
}

static bool asm_parse_mem(const char *s, int is64, asm_mem *out) {
    memset(out, 0, sizeof(*out));
    out->scale = 1;

    const char *p = asm_skip_ws(s);
    int sr = asm_try_size_prefix(&p, is64, &out->sz);
    if (sr < 0) return false;

    if (asm_try_seg_prefix(&p, &out->seg)) {
        if (out->sz == 0) {
            sr = asm_try_size_prefix(&p, is64, &out->sz);
            if (sr < 0) return false;
        }
    }

    p = asm_skip_ws(p);
    if (*p != '[') return false;
    p++;
    p = asm_skip_ws(p);

    if (out->seg == 0) {
        asm_try_seg_prefix(&p, &out->seg);
    }

    bool first = true;
    while (*p && *p != ']') {
        int sign = 1;
        if (*p == '+') {
            sign = 1;
            p = asm_skip_ws(p + 1);
        } else if (*p == '-') {
            sign = -1;
            p = asm_skip_ws(p + 1);
        } else if (!first) {
            return false;
        }
        first = false;

        char term[64];
        size_t tn = 0;
        while (*p && *p != '+' && *p != '-' && *p != ']') {
            if (tn + 1 >= sizeof(term)) return false;
            term[tn++] = *p++;
        }
        while (tn > 0 && (term[tn - 1] == ' ' || term[tn - 1] == '\t')) tn--;
        term[tn] = 0;
        if (tn == 0) return false;

        char *star = strchr(term, '*');
        if (star) {
            if (sign < 0 || strchr(star + 1, '*') != NULL) return false;
            *star = 0;
            const char *lhs = asm_skip_ws(term);
            const char *rhs = asm_skip_ws(star + 1);
            if (!*lhs || !*rhs) return false;

            asm_reg r;
            int sc = 0;
            if (asm_parse_reg(lhs, is64, &r) && asm_parse_scale(rhs, &sc)) {
                /* reg * scale */
            } else if (asm_parse_scale(lhs, &sc) && asm_parse_reg(rhs, is64, &r)) {
                /* scale * reg */
            } else {
                return false;
            }
            if (out->is_rip || out->has_index) return false;
            if (r.sz != 4 && r.sz != 8) return false;
            if (!is64 && r.sz != 4) return false;
            if (out->addr_sz != 0 && out->addr_sz != r.sz) return false;
            if (r.idx == 4) return false; /* rsp/esp cannot be index */
            out->addr_sz = r.sz;
            out->has_index = true;
            out->index = r.idx;
            out->scale = sc;
        } else if (asm_ieq(term, "rip")) {
            if (!is64 || sign < 0 || out->is_rip || out->has_base || out->has_index || out->addr_sz != 0) {
                return false;
            }
            out->is_rip = true;
            out->addr_sz = 8;
        } else {
            asm_reg r;
            if (asm_parse_reg(term, is64, &r)) {
                if (sign < 0 || out->is_rip) return false;
                if (r.sz != 4 && r.sz != 8) return false;
                if (!is64 && r.sz != 4) return false;
                if (out->addr_sz != 0 && out->addr_sz != r.sz) return false;
                out->addr_sz = r.sz;
                if (!out->has_base) {
                    out->has_base = true;
                    out->base = r.idx;
                } else if (!out->has_index) {
                    if (r.idx == 4) {
                        if (out->base == 4) return false;
                        out->index = out->base;
                        out->base = 4;
                        out->has_index = true;
                        out->scale = 1;
                    } else {
                        out->has_index = true;
                        out->index = r.idx;
                        out->scale = 1;
                    }
                } else {
                    return false;
                }
            } else {
                uint64_t u = 0;
                bool neg = false;
                if (!asm_parse_imm(term, false, &u, &neg) || neg) return false;
                if (sign > 0) {
                    if (u > (uint64_t)UINT32_MAX) return false;
                    if (out->disp > INT64_MAX - (int64_t)u) return false;
                    out->disp += (int64_t)u;
                } else {
                    if (u > (uint64_t)INT32_MAX + 1ULL) return false;
                    if (out->disp < INT64_MIN + (int64_t)u) return false;
                    out->disp -= (int64_t)u;
                }
                out->has_disp = true;
            }
        }
    }

    if (*p != ']') return false;
    p = asm_skip_ws(p + 1);
    if (*p != 0) return false;

    if (!out->is_rip && !out->has_base && !out->has_index && !out->has_disp) return false;
    if (out->addr_sz == 0) out->addr_sz = is64 ? 8 : 4;

    if (is64 && out->addr_sz == 8) {
        if (out->disp < INT32_MIN || out->disp > INT32_MAX) return false;
    } else {
        if (out->disp < INT32_MIN || out->disp > (int64_t)UINT32_MAX) return false;
    }
    return true;
}

static int asm_mem_rex_x(const asm_mem *m) {
    return (m->has_index && m->index >= 8) ? 1 : 0;
}

static int asm_mem_rex_b(const asm_mem *m) {
    return (!m->is_rip && m->has_base && m->base >= 8) ? 1 : 0;
}

static bool asm_emit_mem_prefixes(asm_em *e, int is64, const asm_mem *m, int op_sz,
                                  int rex_w, int rex_r, bool force_rex, bool forbid_rex) {
    if (m->seg) asm_u8(e, m->seg);
    if (op_sz == 2) asm_u8(e, 0x66);
    if (is64 && m->addr_sz == 4) asm_u8(e, 0x67);
    return asm_emit_rex(e, is64, rex_w, rex_r, asm_mem_rex_x(m), asm_mem_rex_b(m),
                        force_rex, forbid_rex);
}

static void asm_emit_modrm_mem(asm_em *e, int is64, int reg_field, const asm_mem *m) {
    uint8_t rf = (uint8_t)((reg_field & 7) << 3);

    if (m->is_rip) {
        asm_u8(e, (uint8_t)(rf | 5U));
        asm_u32(e, (uint32_t)m->disp);
        return;
    }

    if (!m->has_base && !m->has_index) {
        if (is64) {
            asm_u8(e, (uint8_t)(rf | 4U));
            asm_u8(e, 0x25U);
            asm_u32(e, (uint32_t)m->disp);
        } else {
            asm_u8(e, (uint8_t)(rf | 5U));
            asm_u32(e, (uint32_t)m->disp);
        }
        return;
    }

    uint8_t ss = (m->scale == 8) ? 3U : (m->scale == 4) ? 2U : (m->scale == 2) ? 1U : 0U;

    if (!m->has_base && m->has_index) {
        asm_u8(e, (uint8_t)(rf | 4U));
        asm_u8(e, (uint8_t)((ss << 6) | ((uint8_t)(m->index & 7) << 3) | 5U));
        asm_u32(e, (uint32_t)m->disp);
        return;
    }

    uint8_t b7 = (uint8_t)(m->base & 7);
    uint8_t mod;
    if (m->disp == 0 && b7 != 5U) mod = 0U;
    else if (m->disp >= -128 && m->disp <= 127) mod = 1U;
    else mod = 2U;

    if (m->has_index) {
        asm_u8(e, (uint8_t)((mod << 6) | rf | 4U));
        asm_u8(e, (uint8_t)((ss << 6) | ((uint8_t)(m->index & 7) << 3) | b7));
    } else if (b7 == 4U) {
        asm_u8(e, (uint8_t)((mod << 6) | rf | 4U));
        asm_u8(e, 0x24U);
    } else {
        asm_u8(e, (uint8_t)((mod << 6) | rf | b7));
    }

    if (mod == 1U) asm_u8(e, (uint8_t)(int8_t)m->disp);
    else if (mod == 2U) asm_u32(e, (uint32_t)m->disp);
}

static int asm_alu_ext(const char *m) {
    if (strcmp(m, "add") == 0) return 0;
    if (strcmp(m, "or")  == 0) return 1;
    if (strcmp(m, "adc") == 0) return 2;
    if (strcmp(m, "sbb") == 0) return 3;
    if (strcmp(m, "and") == 0) return 4;
    if (strcmp(m, "sub") == 0) return 5;
    if (strcmp(m, "xor") == 0) return 6;
    if (strcmp(m, "cmp") == 0) return 7;
    return -1;
}

static int asm_shift_ext(const char *m) {
    if (strcmp(m, "rol") == 0) return 0;
    if (strcmp(m, "ror") == 0) return 1;
    if (strcmp(m, "rcl") == 0) return 2;
    if (strcmp(m, "rcr") == 0) return 3;
    if (strcmp(m, "shl") == 0 || strcmp(m, "sal") == 0) return 4;
    if (strcmp(m, "shr") == 0) return 5;
    if (strcmp(m, "sar") == 0) return 7;
    return -1;
}

static int asm_jcc_code(const char *m) {
    static const struct { const char *name; int cc; } tbl[] = {
        {"jo",0},   {"jno",1},
        {"jb",2},   {"jc",2},   {"jnae",2},
        {"jae",3},  {"jnb",3},  {"jnc",3},
        {"je",4},   {"jz",4},
        {"jne",5},  {"jnz",5},
        {"jbe",6},  {"jna",6},
        {"ja",7},   {"jnbe",7},
        {"js",8},   {"jns",9},
        {"jp",10},  {"jpe",10},
        {"jnp",11}, {"jpo",11},
        {"jl",12},  {"jnge",12},
        {"jge",13}, {"jnl",13},
        {"jle",14}, {"jng",14},
        {"jg",15},  {"jnle",15}
    };
    for (size_t i = 0; i < sizeof(tbl) / sizeof(tbl[0]); i++) {
        if (strcmp(m, tbl[i].name) == 0) return tbl[i].cc;
    }
    return -1;
}

static int asm_loop_op(const char *m, int is64, bool *need_67) {
    *need_67 = false;
    if (strcmp(m, "loopne") == 0 || strcmp(m, "loopnz") == 0) return 0xE0;
    if (strcmp(m, "loope") == 0  || strcmp(m, "loopz") == 0)  return 0xE1;
    if (strcmp(m, "loop") == 0)                               return 0xE2;
    if (strcmp(m, "jrcxz") == 0) return is64 ? 0xE3 : -1;
    if (strcmp(m, "jecxz") == 0) { *need_67 = (is64 != 0); return 0xE3; }
    return -1;
}

static int asm_enc_db(const char *p, asm_em *e) {
    while (!asm_at_end(p)) {
        p = asm_skip_ws(p);
        if (*p == ',') { p++; continue; }
        char tok[16];
        size_t n = 0;
        while (*p && *p != ',' && *p != ' ' && *p != '\t' && *p != ';' && *p != '\r' && *p != '\n') {
            if (n + 1 >= sizeof(tok)) return 0;
            tok[n++] = *p++;
        }
        tok[n] = 0;
        if (n == 0) return 0;

        const char *q = tok;
        if (n > 2 && q[0] == '0' && (q[1] == 'x' || q[1] == 'X')) q += 2;
        if (!*q) return 0;
        uint32_t v = 0;
        while (*q) {
            int d;
            if (*q >= '0' && *q <= '9') d = *q - '0';
            else if (*q >= 'a' && *q <= 'f') d = 10 + (*q - 'a');
            else if (*q >= 'A' && *q <= 'F') d = 10 + (*q - 'A');
            else return 0;
            v = (v << 4) | (uint32_t)d;
            if (v > 0xFFU) return 0;
            q++;
        }
        if (e->len >= 15) return 0;
        asm_u8(e, (uint8_t)v);
    }
    return asm_done(e);
}

static int asm_enc_rel(uint64_t ip, uint64_t va, int is64, int near_len,
                       bool allow_short, uint8_t op8, uint8_t op32_a, uint8_t op32_b, asm_em *e) {
    if (allow_short) {
        int64_t d8 = is64 ? (int64_t)(va - (ip + 2ULL))
                          : (int64_t)(int32_t)(uint32_t)(va - (ip + 2ULL));
        if (d8 >= -128 && d8 <= 127) {
            asm_u8(e, op8);
            asm_u8(e, (uint8_t)(int8_t)d8);
            return asm_done(e);
        }
    }

    int64_t d32 = is64 ? (int64_t)(va - (ip + (uint64_t)near_len))
                       : (int64_t)(int32_t)(uint32_t)(va - (ip + (uint64_t)near_len));
    if (d32 < INT32_MIN || d32 > INT32_MAX) return 0;

    if (op32_a) asm_u8(e, op32_a);
    asm_u8(e, op32_b);
    asm_u32(e, (uint32_t)(int32_t)d32);
    return asm_done(e);
}

static int asm_enc_zero(const char *m, const char *p, int is64, asm_em *e) {
    if (strcmp(m, "ret") == 0 && !asm_at_end(p)) {
        char op[64];
        if (!asm_read_op(&p, op, sizeof(op)) || !asm_at_end(p)) return 0;
        uint64_t u = 0;
        bool neg = false;
        if (!asm_parse_imm(op, false, &u, &neg) || neg || u > 0xFFFFU) return 0;
        asm_u8(e, 0xC2);
        asm_u16(e, (uint16_t)u);
        return asm_done(e);
    }
    if (strcmp(m, "int") == 0) {
        char op[64];
        if (!asm_read_op(&p, op, sizeof(op)) || !asm_at_end(p)) return 0;
        uint64_t u = 0;
        bool neg = false;
        if (!asm_parse_imm(op, false, &u, &neg) || neg || u > 0xFFU) return 0;
        if (u == 3) asm_u8(e, 0xCC);
        else { asm_u8(e, 0xCD); asm_u8(e, (uint8_t)u); }
        return asm_done(e);
    }
    if (!asm_at_end(p)) return 0;

    if (strcmp(m, "nop") == 0)     { asm_u8(e, 0x90); return asm_done(e); }
    if (strcmp(m, "ret") == 0)     { asm_u8(e, 0xC3); return asm_done(e); }
    if (strcmp(m, "int3") == 0)    { asm_u8(e, 0xCC); return asm_done(e); }
    if (strcmp(m, "hlt") == 0)     { asm_u8(e, 0xF4); return asm_done(e); }
    if (strcmp(m, "leave") == 0)   { asm_u8(e, 0xC9); return asm_done(e); }
    if (strcmp(m, "syscall") == 0) { asm_u8(e, 0x0F); asm_u8(e, 0x05); return asm_done(e); }
    if (strcmp(m, "pause") == 0)   { asm_u8(e, 0xF3); asm_u8(e, 0x90); return asm_done(e); }
    if (strcmp(m, "cdq") == 0)     { asm_u8(e, 0x99); return asm_done(e); }
    if (strcmp(m, "cqo") == 0) {
        if (!is64) return 0;
        asm_u8(e, 0x48);
        asm_u8(e, 0x99);
        return asm_done(e);
    }
    return -1;
}

static int asm_enc_push_pop(const char *m, const char *p, int is64, asm_em *e) {
    char op[96];
    if (!asm_read_op(&p, op, sizeof(op)) || !asm_at_end(p)) return 0;

    bool is_push = (strcmp(m, "push") == 0);
    int def_sz = is64 ? 8 : 4;

    asm_reg reg;
    if (asm_parse_reg(op, is64, &reg)) {
        if (reg.sz != 2 && reg.sz != def_sz) return 0;
        if (reg.sz == 2) asm_u8(e, 0x66);
        if (!asm_emit_rex(e, is64, 0, 0, 0, reg.idx >= 8, false, false)) return 0;
        asm_u8(e, (uint8_t)((is_push ? 0x50U : 0x58U) + (uint8_t)(reg.idx & 7)));
        return asm_done(e);
    }

    asm_mem mem;
    if (asm_parse_mem(op, is64, &mem)) {
        int sz = mem.sz ? mem.sz : def_sz;
        if (sz != 2 && sz != def_sz) return 0;
        if (!asm_emit_mem_prefixes(e, is64, &mem, sz == 2 ? 2 : 0, 0, 0, false, false)) return 0;
        asm_u8(e, is_push ? 0xFF : 0x8F);
        asm_emit_modrm_mem(e, is64, is_push ? 6 : 0, &mem);
        return asm_done(e);
    }

    if (!is_push) return 0;

    uint64_t u = 0;
    bool neg = false;
    if (!asm_parse_imm(op, false, &u, &neg)) return 0;
    if (asm_imm8_ok(u)) {
        asm_u8(e, 0x6A);
        asm_u8(e, (uint8_t)(int8_t)(int64_t)u);
        return asm_done(e);
    }
    if (asm_imm_ok(u, def_sz, neg)) {
        asm_u8(e, 0x68);
        asm_u32(e, (uint32_t)u);
        return asm_done(e);
    }
    return 0;
}

static int asm_enc_unary(const char *m, const char *p, int is64, asm_em *e) {
    char op[96];
    if (!asm_read_op(&p, op, sizeof(op)) || !asm_at_end(p)) return 0;

    uint8_t op8 = 0, opv = 0, ext = 0;
    if (strcmp(m, "inc") == 0)      { op8 = 0xFE; opv = 0xFF; ext = 0; }
    else if (strcmp(m, "dec") == 0) { op8 = 0xFE; opv = 0xFF; ext = 1; }
    else if (strcmp(m, "not") == 0) { op8 = 0xF6; opv = 0xF7; ext = 2; }
    else if (strcmp(m, "neg") == 0) { op8 = 0xF6; opv = 0xF7; ext = 3; }
    else return 0;

    asm_reg reg;
    if (asm_parse_reg(op, is64, &reg)) {
        if (reg.sz == 2) asm_u8(e, 0x66);
        if (!asm_emit_rex(e, is64, reg.sz == 8, 0, 0, reg.idx >= 8, reg.need_rex, reg.is_hi8)) return 0;
        asm_u8(e, reg.sz == 1 ? op8 : opv);
        asm_u8(e, (uint8_t)(0xC0U | (ext << 3) | (uint8_t)(reg.idx & 7)));
        return asm_done(e);
    }

    asm_mem mem;
    if (asm_parse_mem(op, is64, &mem)) {
        if (mem.sz == 0) return 0;
        if (!asm_emit_mem_prefixes(e, is64, &mem, mem.sz, mem.sz == 8, 0, false, false)) return 0;
        asm_u8(e, mem.sz == 1 ? op8 : opv);
        asm_emit_modrm_mem(e, is64, ext, &mem);
        return asm_done(e);
    }
    return 0;
}

static int asm_enc_mov(const char *p, int is64, bool force_abs, asm_em *e) {
    char op1[96], op2[96];
    if (!asm_read_op(&p, op1, sizeof(op1)) || *p != ',') return 0;
    p++;
    if (!asm_read_op(&p, op2, sizeof(op2)) || !asm_at_end(p)) return 0;

    asm_reg dst, src;
    asm_mem mem;

    if (asm_parse_reg(op1, is64, &dst)) {
        if (force_abs) {
            uint64_t u = 0;
            bool neg = false;
            if (!is64 || dst.sz != 8 || !asm_parse_imm(op2, false, &u, &neg)) return 0;
            if (!asm_emit_rex(e, is64, 1, 0, 0, dst.idx >= 8, false, false)) return 0;
            asm_u8(e, (uint8_t)(0xB8U + (uint8_t)(dst.idx & 7)));
            asm_u64(e, u);
            return asm_done(e);
        }

        if (asm_parse_reg(op2, is64, &src)) {
            if (dst.sz != src.sz) return 0;
            if (dst.sz == 2) asm_u8(e, 0x66);
            if (!asm_emit_rex(e, is64, dst.sz == 8, src.idx >= 8, 0, dst.idx >= 8,
                              dst.need_rex || src.need_rex, dst.is_hi8 || src.is_hi8)) {
                return 0;
            }
            asm_u8(e, dst.sz == 1 ? 0x88 : 0x89);
            asm_u8(e, (uint8_t)(0xC0U | ((src.idx & 7) << 3) | (dst.idx & 7)));
            return asm_done(e);
        }

        if (asm_parse_mem(op2, is64, &mem)) {
            if (mem.sz != 0 && mem.sz != dst.sz) return 0;
            if (!asm_emit_mem_prefixes(e, is64, &mem, dst.sz, dst.sz == 8, dst.idx >= 8,
                                       dst.need_rex, dst.is_hi8)) {
                return 0;
            }
            asm_u8(e, dst.sz == 1 ? 0x8A : 0x8B);
            asm_emit_modrm_mem(e, is64, dst.idx, &mem);
            return asm_done(e);
        }

        uint64_t u = 0;
        bool neg = false;
        if (!asm_parse_imm(op2, false, &u, &neg)) return 0;

        if (dst.sz == 1) {
            if (!asm_imm_ok(u, 1, neg)) return 0;
            if (!asm_emit_rex(e, is64, 0, 0, 0, dst.idx >= 8, dst.need_rex, dst.is_hi8)) return 0;
            asm_u8(e, (uint8_t)(0xB0U + (uint8_t)(dst.idx & 7)));
            asm_u8(e, (uint8_t)u);
            return asm_done(e);
        }
        if (dst.sz == 2) {
            if (!asm_imm_ok(u, 2, neg)) return 0;
            asm_u8(e, 0x66);
            if (!asm_emit_rex(e, is64, 0, 0, 0, dst.idx >= 8, false, false)) return 0;
            asm_u8(e, (uint8_t)(0xB8U + (uint8_t)(dst.idx & 7)));
            asm_u16(e, (uint16_t)u);
            return asm_done(e);
        }
        if (dst.sz == 4) {
            if (!asm_imm_ok(u, 4, neg)) return 0;
            if (!asm_emit_rex(e, is64, 0, 0, 0, dst.idx >= 8, false, false)) return 0;
            asm_u8(e, (uint8_t)(0xB8U + (uint8_t)(dst.idx & 7)));
            asm_u32(e, (uint32_t)u);
            return asm_done(e);
        }

        /* 64-bit reg: sign-extended imm32 avoids 10-byte movabs when valid */
        if (asm_imm_ok(u, 8, neg)) {
            if (!asm_emit_rex(e, is64, 1, 0, 0, dst.idx >= 8, false, false)) return 0;
            asm_u8(e, 0xC7);
            asm_u8(e, (uint8_t)(0xC0U | (dst.idx & 7)));
            asm_u32(e, (uint32_t)u);
            return asm_done(e);
        }
        if (!asm_emit_rex(e, is64, 1, 0, 0, dst.idx >= 8, false, false)) return 0;
        asm_u8(e, (uint8_t)(0xB8U + (uint8_t)(dst.idx & 7)));
        asm_u64(e, u);
        return asm_done(e);
    }

    if (force_abs || !asm_parse_mem(op1, is64, &mem)) return 0;

    if (asm_parse_reg(op2, is64, &src)) {
        if (mem.sz != 0 && mem.sz != src.sz) return 0;
        if (!asm_emit_mem_prefixes(e, is64, &mem, src.sz, src.sz == 8, src.idx >= 8,
                                   src.need_rex, src.is_hi8)) {
            return 0;
        }
        asm_u8(e, src.sz == 1 ? 0x88 : 0x89);
        asm_emit_modrm_mem(e, is64, src.idx, &mem);
        return asm_done(e);
    }

    uint64_t u = 0;
    bool neg = false;
    if (mem.sz == 0 || !asm_parse_imm(op2, false, &u, &neg)) return 0;
    if (!asm_imm_ok(u, mem.sz, neg)) return 0;
    if (!asm_emit_mem_prefixes(e, is64, &mem, mem.sz, mem.sz == 8, 0, false, false)) return 0;
    asm_u8(e, mem.sz == 1 ? 0xC6 : 0xC7);
    asm_emit_modrm_mem(e, is64, 0, &mem);
    if (mem.sz == 1) asm_u8(e, (uint8_t)u);
    else if (mem.sz == 2) asm_u16(e, (uint16_t)u);
    else asm_u32(e, (uint32_t)u);
    return asm_done(e);
}

static int asm_enc_xchg(const char *p, int is64, asm_em *e) {
    char op1[96], op2[96];
    if (!asm_read_op(&p, op1, sizeof(op1)) || *p != ',') return 0;
    p++;
    if (!asm_read_op(&p, op2, sizeof(op2)) || !asm_at_end(p)) return 0;

    asm_reg r1, r2;
    asm_mem mem;

    if (asm_parse_reg(op1, is64, &r1)) {
        if (asm_parse_reg(op2, is64, &r2)) {
            if (r1.sz != r2.sz) return 0;
            if (r1.sz == 2) asm_u8(e, 0x66);
            if (!asm_emit_rex(e, is64, r1.sz == 8, r2.idx >= 8, 0, r1.idx >= 8,
                              r1.need_rex || r2.need_rex, r1.is_hi8 || r2.is_hi8)) {
                return 0;
            }
            asm_u8(e, r1.sz == 1 ? 0x86 : 0x87);
            asm_u8(e, (uint8_t)(0xC0U | ((r2.idx & 7) << 3) | (r1.idx & 7)));
            return asm_done(e);
        }
        if (asm_parse_mem(op2, is64, &mem)) {
            if (mem.sz != 0 && mem.sz != r1.sz) return 0;
            if (!asm_emit_mem_prefixes(e, is64, &mem, r1.sz, r1.sz == 8, r1.idx >= 8,
                                       r1.need_rex, r1.is_hi8)) {
                return 0;
            }
            asm_u8(e, r1.sz == 1 ? 0x86 : 0x87);
            asm_emit_modrm_mem(e, is64, r1.idx, &mem);
            return asm_done(e);
        }
        return 0;
    }

    if (asm_parse_mem(op1, is64, &mem) && asm_parse_reg(op2, is64, &r2)) {
        if (mem.sz != 0 && mem.sz != r2.sz) return 0;
        if (!asm_emit_mem_prefixes(e, is64, &mem, r2.sz, r2.sz == 8, r2.idx >= 8,
                                   r2.need_rex, r2.is_hi8)) {
            return 0;
        }
        asm_u8(e, r2.sz == 1 ? 0x86 : 0x87);
        asm_emit_modrm_mem(e, is64, r2.idx, &mem);
        return asm_done(e);
    }
    return 0;
}

static int asm_enc_lea(const char *p, int is64, asm_em *e) {
    char op1[96], op2[96];
    if (!asm_read_op(&p, op1, sizeof(op1)) || *p != ',') return 0;
    p++;
    if (!asm_read_op(&p, op2, sizeof(op2)) || !asm_at_end(p)) return 0;

    asm_reg dst;
    asm_mem mem;
    if (!asm_parse_reg(op1, is64, &dst) || dst.sz == 1) return 0;
    if (!asm_parse_mem(op2, is64, &mem)) return 0;

    if (!asm_emit_mem_prefixes(e, is64, &mem, dst.sz, dst.sz == 8, dst.idx >= 8, false, false)) {
        return 0;
    }
    asm_u8(e, 0x8D);
    asm_emit_modrm_mem(e, is64, dst.idx, &mem);
    return asm_done(e);
}

static int asm_enc_movx(const char *m, const char *p, int is64, asm_em *e) {
    char op1[96], op2[96];
    if (!asm_read_op(&p, op1, sizeof(op1)) || *p != ',') return 0;
    p++;
    if (!asm_read_op(&p, op2, sizeof(op2)) || !asm_at_end(p)) return 0;

    asm_reg dst, src;
    asm_mem mem;
    if (!asm_parse_reg(op1, is64, &dst)) return 0;

    if (strcmp(m, "movsxd") == 0) {
        if (!is64 || dst.sz != 8) return 0;
        if (asm_parse_reg(op2, is64, &src)) {
            if (src.sz != 4) return 0;
            if (!asm_emit_rex(e, is64, 1, dst.idx >= 8, 0, src.idx >= 8, false, false)) return 0;
            asm_u8(e, 0x63);
            asm_u8(e, (uint8_t)(0xC0U | ((dst.idx & 7) << 3) | (src.idx & 7)));
            return asm_done(e);
        }
        if (asm_parse_mem(op2, is64, &mem)) {
            if (mem.sz != 0 && mem.sz != 4) return 0;
            if (!asm_emit_mem_prefixes(e, is64, &mem, 8, 1, dst.idx >= 8, false, false)) return 0;
            asm_u8(e, 0x63);
            asm_emit_modrm_mem(e, is64, dst.idx, &mem);
            return asm_done(e);
        }
        return 0;
    }

    bool is_zx = (strcmp(m, "movzx") == 0);
    if (dst.sz < 2) return 0;

    if (asm_parse_reg(op2, is64, &src)) {
        if (!is_zx && is64 && dst.sz == 8 && src.sz == 4) {
            if (!asm_emit_rex(e, is64, 1, dst.idx >= 8, 0, src.idx >= 8, false, false)) return 0;
            asm_u8(e, 0x63);
            asm_u8(e, (uint8_t)(0xC0U | ((dst.idx & 7) << 3) | (src.idx & 7)));
            return asm_done(e);
        }
        if ((src.sz != 1 && src.sz != 2) || dst.sz <= src.sz) return 0;
        if (dst.sz == 2) asm_u8(e, 0x66);
        if (!asm_emit_rex(e, is64, dst.sz == 8, dst.idx >= 8, 0, src.idx >= 8,
                          src.need_rex, src.is_hi8)) {
            return 0;
        }
        asm_u8(e, 0x0F);
        asm_u8(e, is_zx ? (src.sz == 1 ? 0xB6 : 0xB7) : (src.sz == 1 ? 0xBE : 0xBF));
        asm_u8(e, (uint8_t)(0xC0U | ((dst.idx & 7) << 3) | (src.idx & 7)));
        return asm_done(e);
    }

    if (asm_parse_mem(op2, is64, &mem)) {
        if (!is_zx && is64 && dst.sz == 8 && mem.sz == 4) {
            if (!asm_emit_mem_prefixes(e, is64, &mem, 8, 1, dst.idx >= 8, false, false)) return 0;
            asm_u8(e, 0x63);
            asm_emit_modrm_mem(e, is64, dst.idx, &mem);
            return asm_done(e);
        }
        if ((mem.sz != 1 && mem.sz != 2) || dst.sz <= mem.sz) return 0;
        if (!asm_emit_mem_prefixes(e, is64, &mem, dst.sz, dst.sz == 8, dst.idx >= 8, false, false)) {
            return 0;
        }
        asm_u8(e, 0x0F);
        asm_u8(e, is_zx ? (mem.sz == 1 ? 0xB6 : 0xB7) : (mem.sz == 1 ? 0xBE : 0xBF));
        asm_emit_modrm_mem(e, is64, dst.idx, &mem);
        return asm_done(e);
    }
    return 0;
}

static int asm_enc_alu(int ext, const char *p, int is64, asm_em *e) {
    char op1[96], op2[96];
    if (!asm_read_op(&p, op1, sizeof(op1)) || *p != ',') return 0;
    p++;
    if (!asm_read_op(&p, op2, sizeof(op2)) || !asm_at_end(p)) return 0;

    asm_reg dst, src;
    asm_mem mem;

    if (asm_parse_reg(op1, is64, &dst)) {
        if (asm_parse_reg(op2, is64, &src)) {
            if (dst.sz != src.sz) return 0;
            if (dst.sz == 2) asm_u8(e, 0x66);
            if (!asm_emit_rex(e, is64, dst.sz == 8, src.idx >= 8, 0, dst.idx >= 8,
                              dst.need_rex || src.need_rex, dst.is_hi8 || src.is_hi8)) {
                return 0;
            }
            asm_u8(e, (uint8_t)((ext << 3) | (dst.sz == 1 ? 0 : 1)));
            asm_u8(e, (uint8_t)(0xC0U | ((src.idx & 7) << 3) | (dst.idx & 7)));
            return asm_done(e);
        }

        if (asm_parse_mem(op2, is64, &mem)) {
            if (mem.sz != 0 && mem.sz != dst.sz) return 0;
            if (!asm_emit_mem_prefixes(e, is64, &mem, dst.sz, dst.sz == 8, dst.idx >= 8,
                                       dst.need_rex, dst.is_hi8)) {
                return 0;
            }
            asm_u8(e, (uint8_t)((ext << 3) | (dst.sz == 1 ? 2 : 3)));
            asm_emit_modrm_mem(e, is64, dst.idx, &mem);
            return asm_done(e);
        }

        uint64_t u = 0;
        bool neg = false;
        if (!asm_parse_imm(op2, false, &u, &neg)) return 0;

        if (dst.sz == 1) {
            if (!asm_imm_ok(u, 1, neg)) return 0;
            if (!asm_emit_rex(e, is64, 0, 0, 0, dst.idx >= 8, dst.need_rex, dst.is_hi8)) return 0;
            asm_u8(e, 0x80);
            asm_u8(e, (uint8_t)(0xC0U | (ext << 3) | (dst.idx & 7)));
            asm_u8(e, (uint8_t)u);
            return asm_done(e);
        }
        if (asm_imm8_ok(u)) {
            if (dst.sz == 2) asm_u8(e, 0x66);
            if (!asm_emit_rex(e, is64, dst.sz == 8, 0, 0, dst.idx >= 8, false, false)) return 0;
            asm_u8(e, 0x83);
            asm_u8(e, (uint8_t)(0xC0U | (ext << 3) | (dst.idx & 7)));
            asm_u8(e, (uint8_t)(int8_t)(int64_t)u);
            return asm_done(e);
        }
        if (asm_imm_ok(u, dst.sz, neg)) {
            if (dst.sz == 2) asm_u8(e, 0x66);
            if (!asm_emit_rex(e, is64, dst.sz == 8, 0, 0, dst.idx >= 8, false, false)) return 0;
            asm_u8(e, 0x81);
            asm_u8(e, (uint8_t)(0xC0U | (ext << 3) | (dst.idx & 7)));
            if (dst.sz == 2) asm_u16(e, (uint16_t)u);
            else asm_u32(e, (uint32_t)u);
            return asm_done(e);
        }
        return 0;
    }

    if (!asm_parse_mem(op1, is64, &mem)) return 0;

    if (asm_parse_reg(op2, is64, &src)) {
        if (mem.sz != 0 && mem.sz != src.sz) return 0;
        if (!asm_emit_mem_prefixes(e, is64, &mem, src.sz, src.sz == 8, src.idx >= 8,
                                   src.need_rex, src.is_hi8)) {
            return 0;
        }
        asm_u8(e, (uint8_t)((ext << 3) | (src.sz == 1 ? 0 : 1)));
        asm_emit_modrm_mem(e, is64, src.idx, &mem);
        return asm_done(e);
    }

    uint64_t u = 0;
    bool neg = false;
    if (mem.sz == 0 || !asm_parse_imm(op2, false, &u, &neg)) return 0;

    if (mem.sz == 1) {
        if (!asm_imm_ok(u, 1, neg)) return 0;
        if (!asm_emit_mem_prefixes(e, is64, &mem, 1, 0, 0, false, false)) return 0;
        asm_u8(e, 0x80);
        asm_emit_modrm_mem(e, is64, ext, &mem);
        asm_u8(e, (uint8_t)u);
        return asm_done(e);
    }
    if (asm_imm8_ok(u)) {
        if (!asm_emit_mem_prefixes(e, is64, &mem, mem.sz, mem.sz == 8, 0, false, false)) return 0;
        asm_u8(e, 0x83);
        asm_emit_modrm_mem(e, is64, ext, &mem);
        asm_u8(e, (uint8_t)(int8_t)(int64_t)u);
        return asm_done(e);
    }
    if (asm_imm_ok(u, mem.sz, neg)) {
        if (!asm_emit_mem_prefixes(e, is64, &mem, mem.sz, mem.sz == 8, 0, false, false)) return 0;
        asm_u8(e, 0x81);
        asm_emit_modrm_mem(e, is64, ext, &mem);
        if (mem.sz == 2) asm_u16(e, (uint16_t)u);
        else asm_u32(e, (uint32_t)u);
        return asm_done(e);
    }
    return 0;
}

static int asm_enc_test(const char *p, int is64, asm_em *e) {
    char op1[96], op2[96];
    if (!asm_read_op(&p, op1, sizeof(op1)) || *p != ',') return 0;
    p++;
    if (!asm_read_op(&p, op2, sizeof(op2)) || !asm_at_end(p)) return 0;

    asm_reg dst, src;
    asm_mem mem;

    if (asm_parse_reg(op1, is64, &dst)) {
        if (asm_parse_reg(op2, is64, &src)) {
            if (dst.sz != src.sz) return 0;
            if (dst.sz == 2) asm_u8(e, 0x66);
            if (!asm_emit_rex(e, is64, dst.sz == 8, src.idx >= 8, 0, dst.idx >= 8,
                              dst.need_rex || src.need_rex, dst.is_hi8 || src.is_hi8)) {
                return 0;
            }
            asm_u8(e, dst.sz == 1 ? 0x84 : 0x85);
            asm_u8(e, (uint8_t)(0xC0U | ((src.idx & 7) << 3) | (dst.idx & 7)));
            return asm_done(e);
        }

        if (asm_parse_mem(op2, is64, &mem)) {
            if (mem.sz != 0 && mem.sz != dst.sz) return 0;
            if (!asm_emit_mem_prefixes(e, is64, &mem, dst.sz, dst.sz == 8, dst.idx >= 8,
                                       dst.need_rex, dst.is_hi8)) {
                return 0;
            }
            asm_u8(e, dst.sz == 1 ? 0x84 : 0x85);
            asm_emit_modrm_mem(e, is64, dst.idx, &mem);
            return asm_done(e);
        }

        uint64_t u = 0;
        bool neg = false;
        if (!asm_parse_imm(op2, false, &u, &neg)) return 0;
        if (!asm_imm_ok(u, dst.sz, neg)) return 0;
        if (dst.sz == 2) asm_u8(e, 0x66);
        if (!asm_emit_rex(e, is64, dst.sz == 8, 0, 0, dst.idx >= 8, dst.need_rex, dst.is_hi8)) {
            return 0;
        }
        asm_u8(e, dst.sz == 1 ? 0xF6 : 0xF7);
        asm_u8(e, (uint8_t)(0xC0U | (dst.idx & 7)));
        if (dst.sz == 1) asm_u8(e, (uint8_t)u);
        else if (dst.sz == 2) asm_u16(e, (uint16_t)u);
        else asm_u32(e, (uint32_t)u);
        return asm_done(e);
    }

    if (!asm_parse_mem(op1, is64, &mem)) return 0;

    if (asm_parse_reg(op2, is64, &src)) {
        if (mem.sz != 0 && mem.sz != src.sz) return 0;
        if (!asm_emit_mem_prefixes(e, is64, &mem, src.sz, src.sz == 8, src.idx >= 8,
                                   src.need_rex, src.is_hi8)) {
            return 0;
        }
        asm_u8(e, src.sz == 1 ? 0x84 : 0x85);
        asm_emit_modrm_mem(e, is64, src.idx, &mem);
        return asm_done(e);
    }

    uint64_t u = 0;
    bool neg = false;
    if (mem.sz == 0 || !asm_parse_imm(op2, false, &u, &neg)) return 0;
    if (!asm_imm_ok(u, mem.sz, neg)) return 0;
    if (!asm_emit_mem_prefixes(e, is64, &mem, mem.sz, mem.sz == 8, 0, false, false)) return 0;
    asm_u8(e, mem.sz == 1 ? 0xF6 : 0xF7);
    asm_emit_modrm_mem(e, is64, 0, &mem);
    if (mem.sz == 1) asm_u8(e, (uint8_t)u);
    else if (mem.sz == 2) asm_u16(e, (uint16_t)u);
    else asm_u32(e, (uint32_t)u);
    return asm_done(e);
}

static int asm_enc_imul3_reg(const asm_reg *dst, const asm_reg *src, uint64_t u, bool neg,
                             int is64, asm_em *e) {
    if (asm_imm8_ok(u)) {
        if (dst->sz == 2) asm_u8(e, 0x66);
        if (!asm_emit_rex(e, is64, dst->sz == 8, dst->idx >= 8, 0, src->idx >= 8, false, false)) {
            return 0;
        }
        asm_u8(e, 0x6B);
        asm_u8(e, (uint8_t)(0xC0U | ((dst->idx & 7) << 3) | (src->idx & 7)));
        asm_u8(e, (uint8_t)(int8_t)(int64_t)u);
        return asm_done(e);
    }
    if (asm_imm_ok(u, dst->sz, neg)) {
        if (dst->sz == 2) asm_u8(e, 0x66);
        if (!asm_emit_rex(e, is64, dst->sz == 8, dst->idx >= 8, 0, src->idx >= 8, false, false)) {
            return 0;
        }
        asm_u8(e, 0x69);
        asm_u8(e, (uint8_t)(0xC0U | ((dst->idx & 7) << 3) | (src->idx & 7)));
        if (dst->sz == 2) asm_u16(e, (uint16_t)u);
        else asm_u32(e, (uint32_t)u);
        return asm_done(e);
    }
    return 0;
}

static int asm_enc_imul(const char *p, int is64, asm_em *e) {
    char op1[96], op2[96], op3[96];
    int nops = 0;
    if (!asm_read_op(&p, op1, sizeof(op1))) return 0;
    nops = 1;
    if (*p == ',') {
        p++;
        if (!asm_read_op(&p, op2, sizeof(op2))) return 0;
        nops = 2;
        if (*p == ',') {
            p++;
            if (!asm_read_op(&p, op3, sizeof(op3))) return 0;
            nops = 3;
        }
    }
    if (!asm_at_end(p)) return 0;

    asm_reg dst, src;
    asm_mem mem;

    if (nops == 1) {
        if (asm_parse_reg(op1, is64, &dst)) {
            if (dst.sz == 2) asm_u8(e, 0x66);
            if (!asm_emit_rex(e, is64, dst.sz == 8, 0, 0, dst.idx >= 8, dst.need_rex, dst.is_hi8)) {
                return 0;
            }
            asm_u8(e, dst.sz == 1 ? 0xF6 : 0xF7);
            asm_u8(e, (uint8_t)(0xC0U | (5U << 3) | (dst.idx & 7)));
            return asm_done(e);
        }
        if (asm_parse_mem(op1, is64, &mem)) {
            if (mem.sz == 0) return 0;
            if (!asm_emit_mem_prefixes(e, is64, &mem, mem.sz, mem.sz == 8, 0, false, false)) {
                return 0;
            }
            asm_u8(e, mem.sz == 1 ? 0xF6 : 0xF7);
            asm_emit_modrm_mem(e, is64, 5, &mem);
            return asm_done(e);
        }
        return 0;
    }

    if (!asm_parse_reg(op1, is64, &dst) || dst.sz < 2) return 0;

    if (nops == 2) {
        if (asm_parse_reg(op2, is64, &src)) {
            if (src.sz != dst.sz) return 0;
            if (dst.sz == 2) asm_u8(e, 0x66);
            if (!asm_emit_rex(e, is64, dst.sz == 8, dst.idx >= 8, 0, src.idx >= 8, false, false)) {
                return 0;
            }
            asm_u8(e, 0x0F);
            asm_u8(e, 0xAF);
            asm_u8(e, (uint8_t)(0xC0U | ((dst.idx & 7) << 3) | (src.idx & 7)));
            return asm_done(e);
        }
        if (asm_parse_mem(op2, is64, &mem)) {
            if (mem.sz != 0 && mem.sz != dst.sz) return 0;
            if (!asm_emit_mem_prefixes(e, is64, &mem, dst.sz, dst.sz == 8, dst.idx >= 8, false, false)) {
                return 0;
            }
            asm_u8(e, 0x0F);
            asm_u8(e, 0xAF);
            asm_emit_modrm_mem(e, is64, dst.idx, &mem);
            return asm_done(e);
        }
        uint64_t u = 0;
        bool neg = false;
        if (!asm_parse_imm(op2, false, &u, &neg)) return 0;
        return asm_enc_imul3_reg(&dst, &dst, u, neg, is64, e);
    }

    /* nops == 3 */
    uint64_t u = 0;
    bool neg = false;
    if (!asm_parse_imm(op3, false, &u, &neg)) return 0;

    if (asm_parse_reg(op2, is64, &src)) {
        if (src.sz != dst.sz) return 0;
        return asm_enc_imul3_reg(&dst, &src, u, neg, is64, e);
    }
    if (asm_parse_mem(op2, is64, &mem)) {
        if (mem.sz != 0 && mem.sz != dst.sz) return 0;
        if (asm_imm8_ok(u)) {
            if (!asm_emit_mem_prefixes(e, is64, &mem, dst.sz, dst.sz == 8, dst.idx >= 8, false, false)) {
                return 0;
            }
            asm_u8(e, 0x6B);
            asm_emit_modrm_mem(e, is64, dst.idx, &mem);
            asm_u8(e, (uint8_t)(int8_t)(int64_t)u);
            return asm_done(e);
        }
        if (asm_imm_ok(u, dst.sz, neg)) {
            if (!asm_emit_mem_prefixes(e, is64, &mem, dst.sz, dst.sz == 8, dst.idx >= 8, false, false)) {
                return 0;
            }
            asm_u8(e, 0x69);
            asm_emit_modrm_mem(e, is64, dst.idx, &mem);
            if (dst.sz == 2) asm_u16(e, (uint16_t)u);
            else asm_u32(e, (uint32_t)u);
            return asm_done(e);
        }
    }
    return 0;
}

static int asm_enc_shift(int ext, const char *p, int is64, asm_em *e) {
    char op1[96], op2[96];
    if (!asm_read_op(&p, op1, sizeof(op1)) || *p != ',') return 0;
    p++;
    if (!asm_read_op(&p, op2, sizeof(op2)) || !asm_at_end(p)) return 0;

    bool use_cl = false;
    uint64_t u = 0;
    bool neg = false;
    asm_reg cnt;
    if (asm_parse_reg(op2, is64, &cnt)) {
        if (cnt.idx != 1 || cnt.sz != 1 || cnt.is_hi8) return 0;
        use_cl = true;
    } else {
        if (!asm_parse_imm(op2, false, &u, &neg) || neg || u > 0xFFULL) return 0;
    }

    asm_reg dst;
    if (asm_parse_reg(op1, is64, &dst)) {
        if (dst.sz == 2) asm_u8(e, 0x66);
        if (!asm_emit_rex(e, is64, dst.sz == 8, 0, 0, dst.idx >= 8, dst.need_rex, dst.is_hi8)) {
            return 0;
        }
        uint8_t opc;
        if (use_cl) opc = (dst.sz == 1) ? 0xD2 : 0xD3;
        else if (u == 1) opc = (dst.sz == 1) ? 0xD0 : 0xD1;
        else opc = (dst.sz == 1) ? 0xC0 : 0xC1;
        asm_u8(e, opc);
        asm_u8(e, (uint8_t)(0xC0U | (ext << 3) | (dst.idx & 7)));
        if (!use_cl && u != 1) asm_u8(e, (uint8_t)u);
        return asm_done(e);
    }

    asm_mem mem;
    if (asm_parse_mem(op1, is64, &mem)) {
        if (mem.sz == 0) return 0;
        if (!asm_emit_mem_prefixes(e, is64, &mem, mem.sz, mem.sz == 8, 0, false, false)) {
            return 0;
        }
        uint8_t opc;
        if (use_cl) opc = (mem.sz == 1) ? 0xD2 : 0xD3;
        else if (u == 1) opc = (mem.sz == 1) ? 0xD0 : 0xD1;
        else opc = (mem.sz == 1) ? 0xC0 : 0xC1;
        asm_u8(e, opc);
        asm_emit_modrm_mem(e, is64, ext, &mem);
        if (!use_cl && u != 1) asm_u8(e, (uint8_t)u);
        return asm_done(e);
    }
    return 0;
}

static int asm_enc_branch(const char *m, const char *p, uint64_t ip, int is64, asm_em *e) {
    char op[96];
    if (!asm_read_op(&p, op, sizeof(op)) || !asm_at_end(p)) return 0;

    bool is_jmp  = (strcmp(m, "jmp") == 0);
    bool is_call = (strcmp(m, "call") == 0);
    int def_sz = is64 ? 8 : 4;

    if (is_jmp || is_call) {
        asm_reg reg;
        if (asm_parse_reg(op, is64, &reg)) {
            if (reg.sz != def_sz) return 0;
            if (!asm_emit_rex(e, is64, 0, 0, 0, reg.idx >= 8, false, false)) return 0;
            asm_u8(e, 0xFF);
            asm_u8(e, (uint8_t)(0xC0U | ((is_jmp ? 4U : 2U) << 3) | (uint8_t)(reg.idx & 7)));
            return asm_done(e);
        }
        asm_mem mem;
        if (asm_parse_mem(op, is64, &mem)) {
            int sz = mem.sz ? mem.sz : def_sz;
            if (sz != def_sz) return 0;
            if (!asm_emit_mem_prefixes(e, is64, &mem, 0, 0, 0, false, false)) return 0;
            asm_u8(e, 0xFF);
            asm_emit_modrm_mem(e, is64, is_jmp ? 4 : 2, &mem);
            return asm_done(e);
        }
        uint64_t va = 0;
        bool neg = false;
        if (!asm_parse_imm(op, true, &va, &neg)) return 0;
        if (neg) va = ip + va;
        else if (!is64 && va > UINT32_MAX) return 0;
        return asm_enc_rel(ip, va, is64, 5, is_jmp, 0xEB, 0, is_jmp ? 0xE9 : 0xE8, e);
    }

    asm_reg bad_reg;
    if (asm_parse_reg(op, is64, &bad_reg)) return 0;

    bool need_67 = false;
    int lop = asm_loop_op(m, is64, &need_67);
    if (lop >= 0) {
        uint64_t va = 0;
        bool neg = false;
        if (!asm_parse_imm(op, true, &va, &neg)) return 0;
        if (neg) va = ip + va;
        else if (!is64 && va > UINT32_MAX) return 0;
        uint64_t ilen = need_67 ? 3ULL : 2ULL;
        int64_t d8 = is64 ? (int64_t)(va - (ip + ilen))
                          : (int64_t)(int32_t)(uint32_t)(va - (ip + ilen));
        if (d8 < -128 || d8 > 127) return 0;
        if (need_67) asm_u8(e, 0x67);
        asm_u8(e, (uint8_t)lop);
        asm_u8(e, (uint8_t)(int8_t)d8);
        return asm_done(e);
    }

    int cc = asm_jcc_code(m);
    if (cc < 0) return 0;
    uint64_t va = 0;
    bool neg = false;
    if (!asm_parse_imm(op, true, &va, &neg)) return 0;
    if (neg) va = ip + va;
    else if (!is64 && va > UINT32_MAX) return 0;
    return asm_enc_rel(ip, va, is64, 6, true, (uint8_t)(0x70 + cc), 0x0F, (uint8_t)(0x80 + cc), e);
}

int asm_encode(const char *text, uint64_t ip, int bits, uint8_t out[16]) {
    if (!text || !out) return 0;
    int is64 = (bits != 32);

    const char *p = text;
    char m[24];
    if (!asm_read_word(&p, m, sizeof(m))) return 0;

    asm_em e = {out, 0, false};

    if (strcmp(m, "db") == 0) return asm_enc_db(p, &e);
    if (strcmp(m, "push") == 0 || strcmp(m, "pop") == 0) return asm_enc_push_pop(m, p, is64, &e);
    if (strcmp(m, "inc") == 0 || strcmp(m, "dec") == 0 ||
        strcmp(m, "neg") == 0 || strcmp(m, "not") == 0) {
        return asm_enc_unary(m, p, is64, &e);
    }
    if (strcmp(m, "mov") == 0)    return asm_enc_mov(p, is64, false, &e);
    if (strcmp(m, "movabs") == 0) return asm_enc_mov(p, is64, true, &e);
    if (strcmp(m, "xchg") == 0)   return asm_enc_xchg(p, is64, &e);
    if (strcmp(m, "lea") == 0)    return asm_enc_lea(p, is64, &e);
    if (strcmp(m, "movzx") == 0 || strcmp(m, "movsx") == 0 || strcmp(m, "movsxd") == 0) {
        return asm_enc_movx(m, p, is64, &e);
    }
    if (strcmp(m, "test") == 0) return asm_enc_test(p, is64, &e);
    if (strcmp(m, "imul") == 0) return asm_enc_imul(p, is64, &e);

    int ext = asm_alu_ext(m);
    if (ext >= 0) return asm_enc_alu(ext, p, is64, &e);

    int sext = asm_shift_ext(m);
    if (sext >= 0) return asm_enc_shift(sext, p, is64, &e);

    bool dummy_67 = false;
    if (strcmp(m, "jmp") == 0 || strcmp(m, "call") == 0 ||
        asm_jcc_code(m) >= 0 || asm_loop_op(m, is64, &dummy_67) >= 0) {
        return asm_enc_branch(m, p, ip, is64, &e);
    }

    int zr = asm_enc_zero(m, p, is64, &e);
    return zr > 0 ? zr : 0;
}
