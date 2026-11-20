#include "ana.h"
#include "../scan/scan.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
    CHDR_KIND_STRUCT  = 0,
    CHDR_KIND_ENUM    = 1,
    CHDR_KIND_TYPEDEF = 2
};

#define CHDR_MAX_MACROS  256
#define CHDR_MAX_EVALS   512
#define CHDR_MAX_ALIGNS  256
#define CHDR_PACK_DEPTH  16
#define CHDR_SIG_MAX     48

typedef struct {
    char    name[48];
    int64_t val;
} chdr_macro;

typedef struct {
    char name[40];
    int  align;
} chdr_align_ent;

typedef struct {
    typ_store     *store;
    chdr_macro     macros[CHDR_MAX_MACROS];
    int            nmacro;
    chdr_macro     evals[CHDR_MAX_EVALS];
    int            neval;
    chdr_align_ent aligns[CHDR_MAX_ALIGNS];
    int            nalign;
    int            pack_stack[CHDR_PACK_DEPTH];
    int            pack_top;
    int            cur_pack;
    int            types_added;
    int            defines;
} chdr_ctx;

typedef struct {
    const chdr_ctx *ctx;
    const char     *p;
    bool            ok;
    int             depth;
} chdr_expr;

static bool chdr_strieq(const char *a, const char *b) {
    if (!a || !b) return false;
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) return false;
        a++;
        b++;
    }
    return *a == 0 && *b == 0;
}

static bool chdr_is_id_start(char c) {
    return isalpha((unsigned char)c) || c == '_';
}

static bool chdr_is_id(char c) {
    return isalnum((unsigned char)c) || c == '_';
}

static const char *chdr_skip_ws(const char *p) {
    while (*p && isspace((unsigned char)*p)) p++;
    return p;
}

static const char *chdr_skip_hws(const char *p) {
    while (*p == ' ' || *p == '\t' || *p == '\r') p++;
    return p;
}

static const char *chdr_read_id(const char *p, char *dst, size_t max) {
    p = chdr_skip_ws(p);
    size_t k = 0;
    if (chdr_is_id_start(*p)) {
        while (chdr_is_id(*p)) {
            if (k + 1 < max) dst[k++] = *p;
            p++;
        }
    }
    if (max > 0) dst[k] = 0;
    return p;
}

static const char *chdr_skip_balanced(const char *p, char open_ch, char close_ch) {
    if (*p != open_ch) return p;
    int depth = 0;
    while (*p) {
        if (*p == '"' || *p == '\'') {
            char q = *p++;
            while (*p && *p != q) {
                if (*p == '\\' && p[1]) p++;
                p++;
            }
            if (*p == q) p++;
            continue;
        }
        if (*p == open_ch) depth++;
        else if (*p == close_ch) {
            depth--;
            p++;
            if (depth <= 0) return p;
            continue;
        }
        p++;
    }
    return p;
}

static const char *chdr_skip_attrs(const char *p) {
    for (;;) {
        p = chdr_skip_ws(p);
        if (!chdr_is_id_start(*p)) break;
        char w[32];
        const char *q = chdr_read_id(p, w, sizeof(w));
        if (strcmp(w, "__attribute__") == 0 || strcmp(w, "__declspec") == 0 ||
            strcmp(w, "_Alignas") == 0 || strcmp(w, "alignas") == 0) {
            q = chdr_skip_ws(q);
            if (*q == '(') q = chdr_skip_balanced(q, '(', ')');
            p = q;
            continue;
        }
        if (strcmp(w, "__unaligned") == 0 || strcmp(w, "__ptr32") == 0 ||
            strcmp(w, "__ptr64") == 0 || strcmp(w, "FAR") == 0 ||
            strcmp(w, "NEAR") == 0 || strcmp(w, "__extension__") == 0) {
            p = q;
            continue;
        }
        break;
    }
    return p;
}

static bool chdr_macro_find(const chdr_ctx *ctx, const char *name, int64_t *val) {
    for (int i = ctx->nmacro - 1; i >= 0; i--) {
        if (strcmp(ctx->macros[i].name, name) == 0) {
            *val = ctx->macros[i].val;
            return true;
        }
    }
    for (int i = ctx->neval - 1; i >= 0; i--) {
        if (strcmp(ctx->evals[i].name, name) == 0) {
            *val = ctx->evals[i].val;
            return true;
        }
    }
    return false;
}

static void chdr_macro_set(chdr_ctx *ctx, const char *name, int64_t val, int is_define) {
    if (!name || !name[0]) return;
    chdr_macro *arr = is_define ? ctx->macros : ctx->evals;
    int *cnt = is_define ? &ctx->nmacro : &ctx->neval;
    int cap = is_define ? CHDR_MAX_MACROS : CHDR_MAX_EVALS;

    for (int i = 0; i < *cnt; i++) {
        if (strcmp(arr[i].name, name) == 0) {
            arr[i].val = val;
            return;
        }
    }
    if (*cnt < cap) {
        snprintf(arr[*cnt].name, sizeof(arr[*cnt].name), "%s", name);
        arr[*cnt].val = val;
        (*cnt)++;
    }
}

static void chdr_macro_del(chdr_ctx *ctx, const char *name) {
    for (int i = 0; i < ctx->nmacro; i++) {
        if (strcmp(ctx->macros[i].name, name) == 0) {
            ctx->macros[i] = ctx->macros[ctx->nmacro - 1];
            ctx->nmacro--;
            return;
        }
    }
}

static void chdr_align_set(chdr_ctx *ctx, const char *name, int align) {
    if (!name || !name[0] || align < 1) return;
    for (int i = 0; i < ctx->nalign; i++) {
        if (strcmp(ctx->aligns[i].name, name) == 0) {
            ctx->aligns[i].align = align;
            return;
        }
    }
    if (ctx->nalign < CHDR_MAX_ALIGNS) {
        snprintf(ctx->aligns[ctx->nalign].name, sizeof(ctx->aligns[ctx->nalign].name), "%s", name);
        ctx->aligns[ctx->nalign].align = align;
        ctx->nalign++;
    }
}

static int chdr_align_get(const chdr_ctx *ctx, const char *name) {
    for (int i = 0; i < ctx->nalign; i++) {
        if (strcmp(ctx->aligns[i].name, name) == 0) return ctx->aligns[i].align;
    }
    return 0;
}

static bool chdr_upsert(chdr_ctx *ctx, const typ_def *def, int align) {
    if (!ctx || !ctx->store || !def->name[0]) return false;
    typ_store *s = ctx->store;
    if (align > 0) chdr_align_set(ctx, def->name, align);

    for (uint32_t i = 0; i < s->ndef; i++) {
        if (strcmp(s->defs[i].name, def->name) == 0) {
            s->defs[i] = *def;
            ctx->types_added++;
            return true;
        }
    }
    if (s->ndef == s->cap) {
        size_t nc_sz = s->cap ? (size_t)s->cap * 2U : 32U;
        if (nc_sz > (size_t)UINT32_MAX || nc_sz > SIZE_MAX / sizeof(typ_def)) return false;
        uint32_t nc = (uint32_t)nc_sz;
        typ_def *nd = (typ_def *)realloc(s->defs, nc_sz * sizeof(typ_def));
        if (!nd) return false;
        s->defs = nd;
        s->cap = nc;
    }
    s->defs[s->ndef++] = *def;
    ctx->types_added++;
    return true;
}

static int chdr_prim_size(const char *t) {
    if (strcmp(t, "char") == 0 || strcmp(t, "signed char") == 0 || strcmp(t, "unsigned char") == 0 ||
        strcmp(t, "int8_t") == 0 || strcmp(t, "uint8_t") == 0 || strcmp(t, "i8") == 0 || strcmp(t, "u8") == 0 ||
        strcmp(t, "bool") == 0 || strcmp(t, "_Bool") == 0 ||
        strcmp(t, "__int8") == 0 || strcmp(t, "signed __int8") == 0 || strcmp(t, "unsigned __int8") == 0) {
        return 1;
    }
    if (strcmp(t, "short") == 0 || strcmp(t, "short int") == 0 ||
        strcmp(t, "signed short") == 0 || strcmp(t, "signed short int") == 0 ||
        strcmp(t, "unsigned short") == 0 || strcmp(t, "unsigned short int") == 0 ||
        strcmp(t, "int16_t") == 0 || strcmp(t, "uint16_t") == 0 || strcmp(t, "i16") == 0 || strcmp(t, "u16") == 0 ||
        strcmp(t, "wchar_t") == 0 || strcmp(t, "char16_t") == 0 ||
        strcmp(t, "__int16") == 0 || strcmp(t, "signed __int16") == 0 || strcmp(t, "unsigned __int16") == 0) {
        return 2;
    }
    if (strcmp(t, "int") == 0 || strcmp(t, "signed") == 0 || strcmp(t, "signed int") == 0 ||
        strcmp(t, "unsigned") == 0 || strcmp(t, "unsigned int") == 0 ||
        strcmp(t, "long") == 0 || strcmp(t, "long int") == 0 ||
        strcmp(t, "signed long") == 0 || strcmp(t, "signed long int") == 0 ||
        strcmp(t, "unsigned long") == 0 || strcmp(t, "unsigned long int") == 0 ||
        strcmp(t, "int32_t") == 0 || strcmp(t, "uint32_t") == 0 || strcmp(t, "i32") == 0 || strcmp(t, "u32") == 0 ||
        strcmp(t, "float") == 0 || strcmp(t, "char32_t") == 0 ||
        strcmp(t, "__int32") == 0 || strcmp(t, "signed __int32") == 0 || strcmp(t, "unsigned __int32") == 0) {
        return 4;
    }
    if (strcmp(t, "long long") == 0 || strcmp(t, "long long int") == 0 ||
        strcmp(t, "signed long long") == 0 || strcmp(t, "signed long long int") == 0 ||
        strcmp(t, "unsigned long long") == 0 || strcmp(t, "unsigned long long int") == 0 ||
        strcmp(t, "int64_t") == 0 || strcmp(t, "uint64_t") == 0 || strcmp(t, "i64") == 0 || strcmp(t, "u64") == 0 ||
        strcmp(t, "double") == 0 || strcmp(t, "long double") == 0 ||
        strcmp(t, "size_t") == 0 || strcmp(t, "ssize_t") == 0 ||
        strcmp(t, "ptrdiff_t") == 0 || strcmp(t, "intptr_t") == 0 || strcmp(t, "uintptr_t") == 0 ||
        strcmp(t, "__int64") == 0 || strcmp(t, "signed __int64") == 0 || strcmp(t, "unsigned __int64") == 0) {
        return 8;
    }
    return 0;
}

static void chdr_clean_type_str(const char *raw, char *dst, size_t max) {
    char tmp[64];
    size_t k = 0;
    int prev_sp = 1;
    for (const char *p = raw; *p && k + 1 < sizeof(tmp); p++) {
        if (isspace((unsigned char)*p)) {
            if (!prev_sp) { tmp[k++] = ' '; prev_sp = 1; }
        } else {
            tmp[k++] = *p;
            prev_sp = 0;
        }
    }
    while (k > 0 && tmp[k - 1] == ' ') k--;
    tmp[k] = 0;

    const char *p = tmp;
    for (;;) {
        if (strncmp(p, "const ", 6) == 0) p += 6;
        else if (strncmp(p, "volatile ", 9) == 0) p += 9;
        else if (strncmp(p, "struct ", 7) == 0) p += 7;
        else if (strncmp(p, "union ", 6) == 0) p += 6;
        else if (strncmp(p, "enum ", 5) == 0) p += 5;
        else break;
    }
    snprintf(dst, max, "%s", p);
}

static int chdr_clamp_i32(int64_t v) {
    if (v <= 0) return 0;
    if (v > (int64_t)INT32_MAX) return INT32_MAX;
    return (int)v;
}

static int chdr_mul_i32(int a, int b) {
    if (a <= 0 || b <= 0) return 0;
    return chdr_clamp_i32((int64_t)a * (int64_t)b);
}

static int chdr_add_i32(int a, int b) {
    return chdr_clamp_i32((int64_t)a + (int64_t)b);
}

static int chdr_sizeof_depth(const chdr_ctx *ctx, const char *type_name, int depth) {
    if (!type_name || !type_name[0] || depth > 8) return 0;

    char clean[64];
    chdr_clean_type_str(type_name, clean, sizeof(clean));
    if (!clean[0]) return 0;

    char *colon = strchr(clean, ':');
    if (colon) *colon = 0;

    char *lb = strchr(clean, '[');
    if (lb) {
        *lb = 0;
        long long cnt = strtoll(lb + 1, NULL, 10);
        int esz = chdr_sizeof_depth(ctx, clean, depth + 1);
        if (cnt <= 0 || esz <= 0) return 0;
        int cnt32 = (cnt > (long long)INT32_MAX) ? INT32_MAX : (int)cnt;
        return chdr_mul_i32(esz, cnt32);
    }

    if (strchr(clean, '*') != NULL) return 8;

    int ps = chdr_prim_size(clean);
    if (ps > 0) return ps;

    const typ_def *d = ctx ? typ_find(ctx->store, clean) : NULL;
    if (d) {
        if (d->kind == CHDR_KIND_TYPEDEF && d->size == 0 && d->nmem > 0) {
            return chdr_sizeof_depth(ctx, d->mems[0].type, depth + 1);
        }
        return d->size < 0 ? 0 : d->size;
    }
    int tsz = ctx ? typ_sizeof(ctx->store, clean) : 0;
    return tsz < 0 ? 0 : tsz;
}

static int chdr_alignof_depth(const chdr_ctx *ctx, const char *type_name, int depth) {
    if (!type_name || !type_name[0] || depth > 8) return 1;

    char clean[64];
    chdr_clean_type_str(type_name, clean, sizeof(clean));
    if (!clean[0]) return 1;

    char *colon = strchr(clean, ':');
    if (colon) *colon = 0;
    char *lb = strchr(clean, '[');
    if (lb) *lb = 0;

    if (strchr(clean, '*') != NULL) return 8;

    int ps = chdr_prim_size(clean);
    if (ps > 0) return ps;

    if (ctx) {
        int cached = chdr_align_get(ctx, clean);
        if (cached > 0) return cached;
    }

    const typ_def *d = ctx ? typ_find(ctx->store, clean) : NULL;
    if (d) {
        if (d->kind == CHDR_KIND_ENUM) return 4;
        if (d->kind == CHDR_KIND_TYPEDEF && d->nmem > 0) {
            return chdr_alignof_depth(ctx, d->mems[0].type, depth + 1);
        }
        if (d->kind == CHDR_KIND_STRUCT) {
            int ma = 1;
            for (int i = 0; i < d->nmem; i++) {
                int a = chdr_alignof_depth(ctx, d->mems[i].type, depth + 1);
                if (a > ma) ma = a;
            }
            if (ma > 8) ma = 8;
            // clamp if type was previously packed
            while (ma > 1 && d->size > 0 && (d->size % ma) != 0) ma >>= 1;
            return ma;
        }
    }

    int ts = ctx ? typ_sizeof(ctx->store, clean) : 0;
    if (ts == 1 || ts == 2 || ts == 4 || ts == 8) return ts;
    return 4;
}

static int64_t chdr_eval_or(chdr_expr *e);

static int64_t chdr_eval_prim(chdr_expr *e) {
    if (!e->ok) return 0;
    e->p = chdr_skip_ws(e->p);
    if (*e->p == '(') {
        if (e->depth >= 64) { e->ok = false; return 0; }
        e->depth++;
        e->p++;
        int64_t v = chdr_eval_or(e);
        e->depth--;
        if (!e->ok) return 0;
        e->p = chdr_skip_ws(e->p);
        if (*e->p == ')') e->p++;
        else e->ok = false;
        return v;
    }
    if (*e->p == '\'') {
        e->p++;
        int64_t v = 0;
        if (*e->p == '\\' && e->p[1]) {
            e->p++;
            switch (*e->p) {
            case 'n': v = '\n'; break;
            case 'r': v = '\r'; break;
            case 't': v = '\t'; break;
            case '0': v = 0; break;
            default:  v = (unsigned char)*e->p; break;
            }
            e->p++;
        } else if (*e->p) {
            v = (unsigned char)*e->p++;
        }
        if (*e->p == '\'') e->p++;
        else e->ok = false;
        return v;
    }
    if (isdigit((unsigned char)*e->p)) {
        uint64_t u = 0;
        if (e->p[0] == '0' && (e->p[1] == 'x' || e->p[1] == 'X')) {
            e->p += 2;
            if (!isxdigit((unsigned char)*e->p)) { e->ok = false; return 0; }
            while (isxdigit((unsigned char)*e->p)) {
                char c = *e->p++;
                int d = (c >= '0' && c <= '9') ? (c - '0')
                      : (c >= 'a' && c <= 'f') ? (c - 'a' + 10)
                      : (c - 'A' + 10);
                u = (u << 4) | (uint64_t)d;
            }
        } else if (e->p[0] == '0' && (e->p[1] == 'b' || e->p[1] == 'B')) {
            e->p += 2;
            if (*e->p != '0' && *e->p != '1') { e->ok = false; return 0; }
            while (*e->p == '0' || *e->p == '1') {
                u = (u << 1) | (uint64_t)(*e->p++ - '0');
            }
        } else if (e->p[0] == '0' && e->p[1] >= '0' && e->p[1] <= '7') {
            while (*e->p >= '0' && *e->p <= '7') {
                u = (u << 3) | (uint64_t)(*e->p++ - '0');
            }
        } else {
            while (isdigit((unsigned char)*e->p)) {
                u = u * 10ULL + (uint64_t)(*e->p++ - '0');
            }
        }
        while (*e->p == 'u' || *e->p == 'U' || *e->p == 'l' || *e->p == 'L') e->p++;
        return (int64_t)u;
    }
    if (chdr_is_id_start(*e->p)) {
        char id[48];
        e->p = chdr_read_id(e->p, id, sizeof(id));
        if (strcmp(id, "sizeof") == 0) {
            e->p = chdr_skip_ws(e->p);
            if (*e->p == '(') {
                const char *s0 = e->p + 1;
                const char *s1 = chdr_skip_balanced(e->p, '(', ')');
                if (s1 > s0 && s1[-1] == ')') {
                    char tbuf[64];
                    size_t tl = (size_t)((s1 - 1) - s0);
                    if (tl >= sizeof(tbuf)) tl = sizeof(tbuf) - 1;
                    memcpy(tbuf, s0, tl);
                    tbuf[tl] = 0;
                    e->p = s1;
                    int sz = chdr_sizeof_depth(e->ctx, tbuf, 0);
                    if (sz > 0) return (int64_t)sz;
                }
            }
            e->ok = false;
            return 0;
        }
        int64_t v = 0;
        if (e->ctx && chdr_macro_find(e->ctx, id, &v)) return v;
        e->ok = false;
        return 0;
    }
    e->ok = false;
    return 0;
}

static int64_t chdr_eval_unary(chdr_expr *e) {
    if (!e->ok) return 0;
    e->p = chdr_skip_ws(e->p);
    if (*e->p == '+' || *e->p == '-' || *e->p == '~' || *e->p == '!') {
        if (e->depth >= 64) { e->ok = false; return 0; }
        char op = *e->p++;
        e->depth++;
        int64_t u = chdr_eval_unary(e);
        e->depth--;
        if (!e->ok) return 0;
        if (op == '+') return u;
        if (op == '-') return (int64_t)(0ULL - (uint64_t)u);
        if (op == '~') return (int64_t)(~(uint64_t)u);
        return u == 0 ? 1 : 0;
    }
    return chdr_eval_prim(e);
}

static int64_t chdr_eval_mul(chdr_expr *e) {
    int64_t v = chdr_eval_unary(e);
    for (;;) {
        e->p = chdr_skip_ws(e->p);
        char op = *e->p;
        if (op != '*' && op != '/' && op != '%') break;
        e->p++;
        int64_t r = chdr_eval_unary(e);
        if (op == '*') v = (int64_t)((uint64_t)v * (uint64_t)r);
        else if (r == 0 || (v == INT64_MIN && r == -1)) { e->ok = false; return 0; }
        else if (op == '/') v /= r;
        else v %= r;
    }
    return v;
}

static int64_t chdr_eval_add(chdr_expr *e) {
    int64_t v = chdr_eval_mul(e);
    for (;;) {
        e->p = chdr_skip_ws(e->p);
        char op = *e->p;
        if (op != '+' && op != '-') break;
        e->p++;
        int64_t r = chdr_eval_mul(e);
        if (op == '+') v = (int64_t)((uint64_t)v + (uint64_t)r);
        else v = (int64_t)((uint64_t)v - (uint64_t)r);
    }
    return v;
}

static int64_t chdr_eval_shift(chdr_expr *e) {
    int64_t v = chdr_eval_add(e);
    for (;;) {
        e->p = chdr_skip_ws(e->p);
        if (e->p[0] == '<' && e->p[1] == '<') {
            e->p += 2;
            int64_t r = chdr_eval_add(e);
            v = (r >= 0 && r < 64) ? (int64_t)((uint64_t)v << (unsigned)r) : 0;
        } else if (e->p[0] == '>' && e->p[1] == '>') {
            e->p += 2;
            int64_t r = chdr_eval_add(e);
            v = (r >= 0 && r < 64) ? (int64_t)((uint64_t)v >> (unsigned)r) : 0;
        } else {
            break;
        }
    }
    return v;
}

static int64_t chdr_eval_and(chdr_expr *e) {
    int64_t v = chdr_eval_shift(e);
    for (;;) {
        e->p = chdr_skip_ws(e->p);
        if (e->p[0] == '&' && e->p[1] != '&') {
            e->p++;
            int64_t r = chdr_eval_shift(e);
            v = (int64_t)((uint64_t)v & (uint64_t)r);
        } else {
            break;
        }
    }
    return v;
}

static int64_t chdr_eval_xor(chdr_expr *e) {
    int64_t v = chdr_eval_and(e);
    for (;;) {
        e->p = chdr_skip_ws(e->p);
        if (e->p[0] == '^') {
            e->p++;
            int64_t r = chdr_eval_and(e);
            v = (int64_t)((uint64_t)v ^ (uint64_t)r);
        } else {
            break;
        }
    }
    return v;
}

static int64_t chdr_eval_or(chdr_expr *e) {
    int64_t v = chdr_eval_xor(e);
    for (;;) {
        e->p = chdr_skip_ws(e->p);
        if (e->p[0] == '|' && e->p[1] != '|') {
            e->p++;
            int64_t r = chdr_eval_xor(e);
            v = (int64_t)((uint64_t)v | (uint64_t)r);
        } else {
            break;
        }
    }
    return v;
}

static bool chdr_eval_expr(const chdr_ctx *ctx, const char *p, const char **end_out, int64_t *val) {
    chdr_expr e;
    e.ctx = ctx;
    e.p = p;
    e.ok = true;
    e.depth = 0;
    int64_t v = chdr_eval_or(&e);
    if (end_out) *end_out = e.p;
    if (val) *val = v;
    return e.ok;
}

static char *chdr_strip_comments(const char *src) {
    size_t len = strlen(src);
    char *out = (char *)malloc(len + 2);
    if (!out) return NULL;

    size_t w = 0;
    const char *p = src;
    while (*p) {
        // join backslash line continuations
        if (p[0] == '\\' && p[1] == '\n') {
            p += 2;
            continue;
        }
        if (p[0] == '\\' && p[1] == '\r' && p[2] == '\n') {
            p += 3;
            continue;
        }
        if (*p == '"' || *p == '\'') {
            char q = *p;
            out[w++] = *p++;
            while (*p) {
                if (p[0] == '\\' && p[1] == '\n') { p += 2; continue; }
                if (p[0] == '\\' && p[1] == '\r' && p[2] == '\n') { p += 3; continue; }
                if (*p == '\\' && p[1]) {
                    out[w++] = *p++;
                    out[w++] = *p++;
                    continue;
                }
                char c = *p++;
                out[w++] = c;
                if (c == q) break;
            }
            continue;
        }
        if (p[0] == '/' && p[1] == '/') {
            p += 2;
            while (*p && *p != '\n') {
                if (p[0] == '\\' && p[1] == '\n') { p += 2; continue; }
                if (p[0] == '\\' && p[1] == '\r' && p[2] == '\n') { p += 3; continue; }
                p++;
            }
            continue;
        }
        if (p[0] == '/' && p[1] == '*') {
            p += 2;
            while (*p && !(p[0] == '*' && p[1] == '/')) p++;
            if (*p) p += 2;
            out[w++] = ' ';
            continue;
        }
        out[w++] = *p++;
    }
    out[w] = 0;
    return out;
}

static char *chdr_preprocess(chdr_ctx *ctx, const char *src) {
    char *flat = chdr_strip_comments(src);
    if (!flat) return NULL;

    size_t flen = strlen(flat);
    char *out = (char *)malloc(flen + 2);
    if (!out) {
        free(flat);
        return NULL;
    }

    size_t w = 0;
    const char *p = flat;
    while (*p) {
        const char *line = p;
        const char *nl = strchr(p, '\n');
        size_t llen = nl ? (size_t)(nl - line) : strlen(line);
        p = nl ? (nl + 1) : (line + llen);

        const char *t = chdr_skip_hws(line);
        if (t < line + llen && *t == '#') {
            t = chdr_skip_hws(t + 1);
            char dir[24];
            size_t dk = 0;
            while (t < line + llen && chdr_is_id(*t)) {
                if (dk + 1 < sizeof(dir)) dir[dk++] = *t;
                t++;
            }
            dir[dk] = 0;

            if (strcmp(dir, "define") == 0) {
                t = chdr_skip_hws(t);
                char mname[48];
                size_t mk = 0;
                if (t < line + llen && chdr_is_id_start(*t)) {
                    while (t < line + llen && chdr_is_id(*t)) {
                        if (mk + 1 < sizeof(mname)) mname[mk++] = *t;
                        t++;
                    }
                }
                mname[mk] = 0;
                // skip function-like macros
                if (mname[0] && !(t < line + llen && *t == '(')) {
                    t = chdr_skip_hws(t);
                    if (t < line + llen) {
                        char vbuf[256];
                        size_t vl = (size_t)((line + llen) - t);
                        if (vl >= sizeof(vbuf)) vl = sizeof(vbuf) - 1;
                        memcpy(vbuf, t, vl);
                        vbuf[vl] = 0;
                        const char *eend = NULL;
                        int64_t val = 0;
                        if (chdr_eval_expr(ctx, vbuf, &eend, &val)) {
                            eend = chdr_skip_ws(eend);
                            if (*eend == 0) {
                                chdr_macro_set(ctx, mname, val, 1);
                                ctx->defines++;
                            }
                        }
                    }
                }
                continue;
            }

            if (strcmp(dir, "undef") == 0) {
                t = chdr_skip_hws(t);
                char mname[48];
                size_t mk = 0;
                while (t < line + llen && chdr_is_id(*t)) {
                    if (mk + 1 < sizeof(mname)) mname[mk++] = *t;
                    t++;
                }
                mname[mk] = 0;
                if (mname[0]) chdr_macro_del(ctx, mname);
                continue;
            }

            if (strcmp(dir, "pragma") == 0) {
                t = chdr_skip_hws(t);
                char pw[24];
                size_t pk = 0;
                while (t < line + llen && chdr_is_id(*t)) {
                    if (pk + 1 < sizeof(pw)) pw[pk++] = *t;
                    t++;
                }
                pw[pk] = 0;
                // keep #pragma pack in stream so pack changes apply in order
                if (strcmp(pw, "pack") == 0) {
                    memcpy(out + w, line, llen);
                    w += llen;
                    out[w++] = '\n';
                }
                continue;
            }

            // skip include, ifdef, ifndef, if, else, elif, endif, etc.
            continue;
        }

        memcpy(out + w, line, llen);
        w += llen;
        out[w++] = '\n';
    }

    out[w] = 0;
    free(flat);
    return out;
}

static bool chdr_valid_pack(int n) {
    return n == 1 || n == 2 || n == 4 || n == 8 || n == 16;
}

static const char *chdr_handle_pragma(chdr_ctx *ctx, const char *p) {
    const char *nl = strchr(p, '\n');
    const char *next = nl ? (nl + 1) : (p + strlen(p));

    const char *lp = strchr(p, '(');
    if (!lp || lp >= next) return next;
    const char *rp = strchr(lp + 1, ')');
    if (!rp || rp >= next) return next;

    char args[128];
    size_t alen = (size_t)(rp - (lp + 1));
    if (alen >= sizeof(args)) alen = sizeof(args) - 1;
    memcpy(args, lp + 1, alen);
    args[alen] = 0;

    const char *q = chdr_skip_ws(args);
    if (*q == 0) {
        ctx->cur_pack = 8;
        return next;
    }

    char w[32];
    const char *after = chdr_read_id(q, w, sizeof(w));
    if (strcmp(w, "push") == 0) {
        if (ctx->pack_top < CHDR_PACK_DEPTH) {
            ctx->pack_stack[ctx->pack_top++] = ctx->cur_pack;
        }
        const char *c = strrchr(after, ',');
        if (c) {
            int64_t nv = 0;
            if (chdr_eval_expr(ctx, c + 1, NULL, &nv) && chdr_valid_pack((int)nv)) {
                ctx->cur_pack = (int)nv;
            }
        }
    } else if (strcmp(w, "pop") == 0) {
        if (ctx->pack_top > 0) ctx->cur_pack = ctx->pack_stack[--ctx->pack_top];
        else ctx->cur_pack = 8;
        const char *c = strrchr(after, ',');
        if (c) {
            int64_t nv = 0;
            if (chdr_eval_expr(ctx, c + 1, NULL, &nv) && chdr_valid_pack((int)nv)) {
                ctx->cur_pack = (int)nv;
            }
        }
    } else {
        int64_t nv = 0;
        if (chdr_eval_expr(ctx, q, NULL, &nv) && chdr_valid_pack((int)nv)) {
            ctx->cur_pack = (int)nv;
        }
    }
    return next;
}

static bool chdr_is_qual(const char *w) {
    return strcmp(w, "const") == 0 || strcmp(w, "volatile") == 0 ||
           strcmp(w, "restrict") == 0 || strcmp(w, "__restrict") == 0 ||
           strcmp(w, "__restrict__") == 0 || strcmp(w, "static") == 0 ||
           strcmp(w, "extern") == 0 || strcmp(w, "register") == 0 ||
           strcmp(w, "inline") == 0 || strcmp(w, "__inline") == 0 ||
           strcmp(w, "__forceinline") == 0 || strcmp(w, "_Atomic") == 0 ||
           strcmp(w, "mutable") == 0 || strcmp(w, "CONST") == 0;
}

static bool chdr_is_builtin(const char *w) {
    return strcmp(w, "void") == 0 || strcmp(w, "char") == 0 ||
           strcmp(w, "short") == 0 || strcmp(w, "int") == 0 ||
           strcmp(w, "long") == 0 || strcmp(w, "float") == 0 ||
           strcmp(w, "double") == 0 || strcmp(w, "signed") == 0 ||
           strcmp(w, "unsigned") == 0 || strcmp(w, "bool") == 0 ||
           strcmp(w, "_Bool") == 0 || strcmp(w, "__int8") == 0 ||
           strcmp(w, "__int16") == 0 || strcmp(w, "__int32") == 0 ||
           strcmp(w, "__int64") == 0 || strcmp(w, "wchar_t") == 0;
}

static bool chdr_is_callconv(const char *w) {
    return strcmp(w, "__cdecl") == 0 || strcmp(w, "__stdcall") == 0 ||
           strcmp(w, "__fastcall") == 0 || strcmp(w, "__thiscall") == 0 ||
           strcmp(w, "__vectorcall") == 0 || strcmp(w, "WINAPI") == 0 ||
           strcmp(w, "CALLBACK") == 0 || strcmp(w, "APIENTRY") == 0 ||
           strcmp(w, "NTAPI") == 0 || strcmp(w, "PASCAL") == 0;
}

static const char *chdr_parse_base_type(const char *p, char *base, size_t max) {
    base[0] = 0;
    size_t len = 0;
    int has_builtin = 0;
    int has_type = 0;

    for (;;) {
        p = chdr_skip_attrs(p);
        if (!chdr_is_id_start(*p)) break;

        char w[40];
        const char *q = chdr_read_id(p, w, sizeof(w));
        if (chdr_is_qual(w) || chdr_is_callconv(w)) {
            p = q;
            continue;
        }
        if (strcmp(w, "struct") == 0 || strcmp(w, "union") == 0 || strcmp(w, "enum") == 0) {
            if (has_builtin || has_type) break;
            p = chdr_skip_attrs(q);
            char tag[40];
            if (chdr_is_id_start(*p)) {
                p = chdr_read_id(p, tag, sizeof(tag));
                snprintf(base, max, "%s", tag);
            } else {
                snprintf(base, max, "%s", w);
            }
            has_type = 1;
            continue;
        }
        if (chdr_is_builtin(w)) {
            if (has_type) break;
            if (len > 0 && len + 1 < max) base[len++] = ' ';
            size_t wl = strlen(w);
            if (len + wl >= max) wl = (max > len + 1) ? (max - len - 1) : 0;
            memcpy(base + len, w, wl);
            len += wl;
            base[len] = 0;
            has_builtin = 1;
            p = q;
            continue;
        }
        if (has_builtin || has_type) break;
        snprintf(base, max, "%s", w);
        len = strlen(base);
        has_type = 1;
        p = q;
    }
    return p;
}

static const char *chdr_parse_arrays(const chdr_ctx *ctx, const char *p, int *arr_cnt) {
    int64_t total = 1;
    for (;;) {
        p = chdr_skip_ws(p);
        if (*p != '[') break;
        const char *s0 = p + 1;
        const char *s1 = chdr_skip_balanced(p, '[', ']');
        if (s1 <= s0 || s1[-1] != ']') break;
        char ebuf[128];
        size_t el = (size_t)((s1 - 1) - s0);
        if (el >= sizeof(ebuf)) el = sizeof(ebuf) - 1;
        memcpy(ebuf, s0, el);
        ebuf[el] = 0;
        int64_t nv = 0;
        if (chdr_eval_expr(ctx, ebuf, NULL, &nv) && nv > 0) {
            if (nv > 100000000LL / total) total = 100000000LL;
            else total *= nv;
        }
        p = s1;
    }
    *arr_cnt = (int)total;
    return p;
}

static const char *chdr_parse_decl(const chdr_ctx *ctx, const char *p, int *stars,
                                   char *name, size_t nmax, int *arr_cnt,
                                   int *bf_bits, int *is_fnptr) {
    *stars = 0;
    name[0] = 0;
    *arr_cnt = 1;
    *bf_bits = -1;
    *is_fnptr = 0;

    for (;;) {
        p = chdr_skip_attrs(p);
        if (*p == '*') {
            (*stars)++;
            p++;
            continue;
        }
        if (chdr_is_id_start(*p)) {
            char w[32];
            const char *q = chdr_read_id(p, w, sizeof(w));
            if (chdr_is_qual(w) || chdr_is_callconv(w)) {
                p = q;
                continue;
            }
        }
        break;
    }

    p = chdr_skip_attrs(p);
    if (*p == '(') {
        const char *inner = chdr_skip_attrs(p + 1);
        for (;;) {
            if (chdr_is_id_start(*inner)) {
                char cw[32];
                const char *cq = chdr_read_id(inner, cw, sizeof(cw));
                if (chdr_is_qual(cw) || chdr_is_callconv(cw)) {
                    inner = chdr_skip_attrs(cq);
                    continue;
                }
            }
            break;
        }
        if (*inner == '*') {
            *is_fnptr = 1;
            while (*inner == '*') {
                inner = chdr_skip_attrs(inner + 1);
                if (chdr_is_id_start(*inner)) {
                    char qw[32];
                    const char *qq = chdr_read_id(inner, qw, sizeof(qw));
                    if (chdr_is_qual(qw)) inner = chdr_skip_attrs(qq);
                }
            }
            if (chdr_is_id_start(*inner)) inner = chdr_read_id(inner, name, nmax);
            inner = chdr_parse_arrays(ctx, inner, arr_cnt);
            p = chdr_skip_balanced(p, '(', ')');
            p = chdr_skip_ws(p);
            if (*p == '(') p = chdr_skip_balanced(p, '(', ')');
            p = chdr_skip_attrs(p);
            return p;
        }
    }

    if (chdr_is_id_start(*p)) {
        p = chdr_read_id(p, name, nmax);
    }

    p = chdr_parse_arrays(ctx, p, arr_cnt);
    p = chdr_skip_ws(p);

    // skip trailing parameter list for non-pointer function typedefs
    if (*p == '(') {
        p = chdr_skip_balanced(p, '(', ')');
        p = chdr_skip_ws(p);
    }

    if (*p == ':') {
        p = chdr_skip_ws(p + 1);
        const char *eend = NULL;
        int64_t bv = 0;
        if (chdr_eval_expr(ctx, p, &eend, &bv) && bv >= 0 && bv <= 64) {
            *bf_bits = (int)bv;
            p = eend;
        }
    }

    return chdr_skip_attrs(p);
}

static void chdr_fmt_ptr_type(const char *base, int stars, int arr_cnt, char *dst, size_t max) {
    char tmp[48];
    size_t k = 0;
    for (size_t i = 0; base[i] && k + 1 < sizeof(tmp); i++) tmp[k++] = base[i];
    for (int i = 0; i < stars && k + 1 < sizeof(tmp); i++) tmp[k++] = '*';
    tmp[k] = 0;
    if (arr_cnt > 1) snprintf(dst, max, "%s[%d]", tmp, arr_cnt);
    else snprintf(dst, max, "%s", tmp);
}

static bool chdr_peek_inline_record(const char *p, int *is_union, const char **after_kw) {
    for (;;) {
        p = chdr_skip_attrs(p);
        if (!chdr_is_id_start(*p)) return false;
        char w[32];
        const char *q = chdr_read_id(p, w, sizeof(w));
        if (chdr_is_qual(w)) {
            p = q;
            continue;
        }
        if (strcmp(w, "struct") != 0 && strcmp(w, "union") != 0) return false;
        *is_union = (strcmp(w, "union") == 0);
        *after_kw = q;
        const char *pk = chdr_skip_attrs(q);
        char tag[40];
        if (chdr_is_id_start(*pk)) pk = chdr_read_id(pk, tag, sizeof(tag));
        pk = chdr_skip_attrs(pk);
        return *pk == '{';
    }
}

static bool chdr_peek_inline_enum(const char *p, const char **after_kw) {
    for (;;) {
        p = chdr_skip_attrs(p);
        if (!chdr_is_id_start(*p)) return false;
        char w[32];
        const char *q = chdr_read_id(p, w, sizeof(w));
        if (chdr_is_qual(w)) {
            p = q;
            continue;
        }
        if (strcmp(w, "enum") != 0) return false;
        *after_kw = q;
        const char *pk = chdr_skip_attrs(q);
        char tag[40];
        if (chdr_is_id_start(*pk)) pk = chdr_read_id(pk, tag, sizeof(tag));
        pk = chdr_skip_attrs(pk);
        return *pk == '{';
    }
}

static const char *chdr_parse_enum_body(chdr_ctx *ctx, const char *p, typ_def *def) {
    memset(def, 0, sizeof(*def));
    def->kind = CHDR_KIND_ENUM;
    def->size = 4;

    if (*p != '{') return p;
    p++;

    int64_t next_val = 0;
    while (*p) {
        p = chdr_skip_ws(p);
        if (!*p) break;
        if (*p == '}') { p++; break; }
        if (*p == ',') { p++; continue; }
        if (*p == '#') { p = chdr_handle_pragma(ctx, p); continue; }

        char ename[32];
        const char *q = chdr_read_id(p, ename, sizeof(ename));
        if (!ename[0]) { if (*p) p++; continue; }
        p = chdr_skip_ws(q);

        int64_t val = next_val;
        if (*p == '=') {
            p = chdr_skip_ws(p + 1);
            const char *vstart = p;
            int paren = 0;
            while (*p) {
                if (*p == '(') paren++;
                else if (*p == ')') { if (paren > 0) paren--; }
                else if (paren == 0 && (*p == ',' || *p == '}')) break;
                p++;
            }
            char ebuf[128];
            size_t el = (size_t)(p - vstart);
            if (el >= sizeof(ebuf)) el = sizeof(ebuf) - 1;
            memcpy(ebuf, vstart, el);
            ebuf[el] = 0;
            int64_t ev = 0;
            if (chdr_eval_expr(ctx, ebuf, NULL, &ev)) val = ev;
        }
        next_val = (int64_t)((uint64_t)val + 1ULL);
        chdr_macro_set(ctx, ename, val, 0);

        if (def->nmem < 32) {
            typ_member *m = &def->mems[def->nmem++];
            snprintf(m->name, sizeof(m->name), "%s", ename);
            snprintf(m->type, sizeof(m->type), "int");
            m->off = (int)val;
            m->size = 4;
        }
        p = chdr_skip_ws(p);
        if (*p == ',') p++;
    }
    return p;
}

typedef struct {
    typ_def *def;
    int      is_union;
    int      off;
    int      max_sz;
    int      max_al;
    int      bf_active;
    int      bf_unit_sz;
    int      bf_unit_off;
    int      bf_bits_used;
} chdr_rec_st;

static int chdr_rec_reserve(chdr_rec_st *rs, int cur_pack, int msz, int nat_al) {
    int fal = nat_al < cur_pack ? nat_al : cur_pack;
    if (fal < 1) fal = 1;
    int64_t off64 = rs->off < 0 ? 0 : (int64_t)rs->off;
    int64_t aligned = rs->is_union ? 0 : ((off64 + (int64_t)fal - 1) & ~((int64_t)fal - 1));
    int foff = chdr_clamp_i32(aligned);
    int csz = msz < 0 ? 0 : msz;
    if (rs->is_union) {
        if (csz > rs->max_sz) rs->max_sz = csz;
    } else {
        rs->off = chdr_clamp_i32((int64_t)foff + (int64_t)csz);
    }
    if (fal > rs->max_al) rs->max_al = fal;
    return foff;
}

static void chdr_rec_add_mem(typ_def *def, const char *name, const char *type, int off, int size) {
    if (!name || !name[0] || def->nmem >= 32) return;
    typ_member *m = &def->mems[def->nmem++];
    snprintf(m->name, sizeof(m->name), "%s", name);
    snprintf(m->type, sizeof(m->type), "%s", type);
    m->off = off;
    m->size = size;
}

static const char *chdr_parse_record_body(chdr_ctx *ctx, const char *p, int is_union,
                                          int depth, typ_def *def, int *out_align);

static const char *chdr_rec_inline_rec(chdr_ctx *ctx, chdr_rec_st *rs, const char *after_kw,
                                       int nested_union, int depth) {
    rs->bf_active = 0;
    const char *q = chdr_skip_attrs(after_kw);
    char ntag[40] = "";
    if (chdr_is_id_start(*q)) q = chdr_read_id(q, ntag, sizeof(ntag));
    q = chdr_skip_attrs(q);

    typ_def inner;
    int inner_al = 1;
    const char *p = chdr_parse_record_body(ctx, q, nested_union, depth + 1, &inner, &inner_al);
    if (ntag[0]) {
        snprintf(inner.name, sizeof(inner.name), "%s", ntag);
        chdr_upsert(ctx, &inner, inner_al);
    }

    p = chdr_skip_attrs(p);
    if (*p == ';') {
        p++;
        int foff = chdr_rec_reserve(rs, ctx->cur_pack, inner.size, inner_al);
        for (int i = 0; i < inner.nmem && rs->def->nmem < 32; i++) {
            typ_member *dst = &rs->def->mems[rs->def->nmem++];
            *dst = inner.mems[i];
            dst->off = chdr_add_i32(dst->off, foff);
        }
        return p;
    }

    for (;;) {
        int stars = 0, arr_cnt = 1, bf_bits = -1, is_fnptr = 0;
        char mname[32];
        p = chdr_parse_decl(ctx, p, &stars, mname, sizeof(mname), &arr_cnt, &bf_bits, &is_fnptr);

        int elem_sz = stars > 0 ? 8 : inner.size;
        int elem_al = stars > 0 ? 8 : inner_al;
        int msz = chdr_mul_i32(elem_sz, arr_cnt);
        int foff = chdr_rec_reserve(rs, ctx->cur_pack, msz, elem_al);

        if (stars == 0 && arr_cnt == 1 && inner.nmem > 0 && mname[0]) {
            for (int i = 0; i < inner.nmem && rs->def->nmem < 32; i++) {
                char fname[32];
                snprintf(fname, sizeof(fname), "%s.%s", mname, inner.mems[i].name);
                chdr_rec_add_mem(rs->def, fname, inner.mems[i].type, chdr_add_i32(foff, inner.mems[i].off), inner.mems[i].size);
            }
        } else if (mname[0]) {
            char mtype[32];
            const char *tbase = ntag[0] ? ntag : (nested_union ? "union" : "struct");
            chdr_fmt_ptr_type(tbase, stars, arr_cnt, mtype, sizeof(mtype));
            chdr_rec_add_mem(rs->def, mname, mtype, foff, msz);
        }

        p = chdr_skip_ws(p);
        if (*p == ',') { p++; continue; }
        if (*p == ';') p++;
        return p;
    }
}

static const char *chdr_rec_inline_enum(chdr_ctx *ctx, chdr_rec_st *rs, const char *after_kw) {
    rs->bf_active = 0;
    const char *q = chdr_skip_attrs(after_kw);
    char etag[40] = "";
    if (chdr_is_id_start(*q)) q = chdr_read_id(q, etag, sizeof(etag));
    q = chdr_skip_attrs(q);

    typ_def edef;
    const char *p = chdr_parse_enum_body(ctx, q, &edef);
    if (etag[0]) {
        snprintf(edef.name, sizeof(edef.name), "%s", etag);
        chdr_upsert(ctx, &edef, 4);
    }

    p = chdr_skip_ws(p);
    if (*p == ';') return p + 1;

    for (;;) {
        int stars = 0, arr_cnt = 1, bf_bits = -1, is_fnptr = 0;
        char mname[32];
        p = chdr_parse_decl(ctx, p, &stars, mname, sizeof(mname), &arr_cnt, &bf_bits, &is_fnptr);
        int elem_sz = stars > 0 ? 8 : 4;
        int msz = chdr_mul_i32(elem_sz, arr_cnt);
        int foff = chdr_rec_reserve(rs, ctx->cur_pack, msz, elem_sz);
        if (mname[0]) {
            char mtype[32];
            chdr_fmt_ptr_type(etag[0] ? etag : "int", stars, arr_cnt, mtype, sizeof(mtype));
            chdr_rec_add_mem(rs->def, mname, mtype, foff, msz);
        }
        p = chdr_skip_ws(p);
        if (*p == ',') { p++; continue; }
        if (*p == ';') p++;
        return p;
    }
}

static void chdr_rec_add_bitfield(const chdr_ctx *ctx, chdr_rec_st *rs, const char *base,
                                  const char *mname, int bf_bits) {
    int unit_sz = chdr_sizeof_depth(ctx, base, 0);
    int nat_al = chdr_alignof_depth(ctx, base, 0);
    if (unit_sz <= 0 || unit_sz > 8) { unit_sz = 4; nat_al = 4; }
    int fal = nat_al < ctx->cur_pack ? nat_al : ctx->cur_pack;
    if (fal < 1) fal = 1;

    if (bf_bits == 0) {
        rs->bf_active = 0;
        if (!rs->is_union) {
            int64_t off64 = rs->off < 0 ? 0 : (int64_t)rs->off;
            rs->off = chdr_clamp_i32((off64 + (int64_t)fal - 1) & ~((int64_t)fal - 1));
        }
        return;
    }

    int foff = 0;
    if (!rs->is_union && rs->bf_active && rs->bf_unit_sz == unit_sz &&
        rs->bf_bits_used + bf_bits <= unit_sz * 8) {
        foff = rs->bf_unit_off;
        rs->bf_bits_used += bf_bits;
    } else if (!rs->is_union) {
        foff = chdr_rec_reserve(rs, ctx->cur_pack, unit_sz, nat_al);
        rs->bf_unit_off = foff;
        rs->bf_unit_sz = unit_sz;
        rs->bf_bits_used = bf_bits;
        rs->bf_active = 1;
    } else {
        foff = chdr_rec_reserve(rs, ctx->cur_pack, unit_sz, nat_al);
    }

    if (mname[0]) {
        char mtype[32];
        snprintf(mtype, sizeof(mtype), "%s:%d", base, bf_bits);
        chdr_rec_add_mem(rs->def, mname, mtype, foff, unit_sz);
    }
}

static const char *chdr_rec_fields(const chdr_ctx *ctx, chdr_rec_st *rs, const char *p, const char *base) {
    for (;;) {
        int stars = 0, arr_cnt = 1, bf_bits = -1, is_fnptr = 0;
        char mname[32];
        const char *dp = p;
        p = chdr_parse_decl(ctx, p, &stars, mname, sizeof(mname), &arr_cnt, &bf_bits, &is_fnptr);
        if (p == dp && !mname[0] && bf_bits < 0) {
            while (*p && *p != ';' && *p != '}') p++;
            if (*p == ';') p++;
            return p;
        }

        if (is_fnptr) {
            rs->bf_active = 0;
            int msz = chdr_mul_i32(8, arr_cnt);
            int foff = chdr_rec_reserve(rs, ctx->cur_pack, msz, 8);
            char mtype[32];
            if (arr_cnt > 1) snprintf(mtype, sizeof(mtype), "fn_t *[%d]", arr_cnt);
            else snprintf(mtype, sizeof(mtype), "fn_t *");
            chdr_rec_add_mem(rs->def, mname, mtype, foff, msz);
        } else if (bf_bits >= 0) {
            chdr_rec_add_bitfield(ctx, rs, base, mname, bf_bits);
        } else {
            rs->bf_active = 0;
            int fsz = stars > 0 ? 8 : chdr_sizeof_depth(ctx, base, 0);
            int nat_al = stars > 0 ? 8 : chdr_alignof_depth(ctx, base, 0);
            if (fsz <= 0) { fsz = 8; nat_al = 8; }
            int msz = chdr_mul_i32(fsz, arr_cnt);
            int foff = chdr_rec_reserve(rs, ctx->cur_pack, msz, nat_al);
            char mtype[32];
            chdr_fmt_ptr_type(base, stars, arr_cnt, mtype, sizeof(mtype));
            chdr_rec_add_mem(rs->def, mname, mtype, foff, msz);
        }

        p = chdr_skip_ws(p);
        if (*p == ',') { p++; continue; }
        if (*p == ';') p++;
        return p;
    }
}

static const char *chdr_parse_record_body(chdr_ctx *ctx, const char *p, int is_union,
                                          int depth, typ_def *def, int *out_align) {
    memset(def, 0, sizeof(*def));
    def->kind = CHDR_KIND_STRUCT;
    *out_align = 1;
    if (*p != '{' || depth > 8) return p;
    p++;

    chdr_rec_st rs;
    memset(&rs, 0, sizeof(rs));
    rs.def = def;
    rs.is_union = is_union;
    rs.max_al = 1;

    while (*p) {
        p = chdr_skip_ws(p);
        if (!*p) break;
        if (*p == '}') { p++; break; }
        if (*p == ';') { p++; continue; }
        if (*p == '#') { p = chdr_handle_pragma(ctx, p); continue; }

        if (chdr_is_id_start(*p)) {
            char acc[16];
            const char *aq = chdr_read_id(p, acc, sizeof(acc));
            aq = chdr_skip_ws(aq);
            if (*aq == ':' && (strcmp(acc, "public") == 0 || strcmp(acc, "private") == 0 || strcmp(acc, "protected") == 0)) {
                p = aq + 1;
                continue;
            }
        }

        int nested_union = 0;
        const char *after_kw = NULL;
        if (chdr_peek_inline_record(p, &nested_union, &after_kw)) {
            p = chdr_rec_inline_rec(ctx, &rs, after_kw, nested_union, depth);
            continue;
        }
        if (chdr_peek_inline_enum(p, &after_kw)) {
            p = chdr_rec_inline_enum(ctx, &rs, after_kw);
            continue;
        }

        const char *start_p = p;
        char base[40];
        p = chdr_parse_base_type(p, base, sizeof(base));
        if (!base[0]) {
            while (*p && *p != ';' && *p != '}') p++;
            if (*p == ';') p++;
            if (p == start_p && *p) p++;
            continue;
        }
        p = chdr_rec_fields(ctx, &rs, p, base);
    }

    int rec_al = rs.max_al < ctx->cur_pack ? rs.max_al : ctx->cur_pack;
    if (rec_al < 1) rec_al = 1;
    int64_t raw_sz = is_union ? (int64_t)rs.max_sz : (int64_t)rs.off;
    if (raw_sz < 0) raw_sz = 0;
    def->size = chdr_clamp_i32((raw_sz + (int64_t)rec_al - 1) & ~((int64_t)rec_al - 1));
    *out_align = rec_al;
    return p;
}

static const char *chdr_register_aliases(chdr_ctx *ctx, const char *p, const typ_def *base_def,
                                         const char *tag, int rec_align, int is_typedef) {
    char primary[40] = "";
    int tag_done = 0;

    if (is_typedef) {
        for (;;) {
            p = chdr_skip_attrs(p);
            if (*p == ';' || *p == 0) break;

            int stars = 0, arr_cnt = 1, bf_bits = -1, is_fnptr = 0;
            char alias[40];
            const char *dp = p;
            p = chdr_parse_decl(ctx, p, &stars, alias, sizeof(alias), &arr_cnt, &bf_bits, &is_fnptr);
            if (p == dp && !alias[0]) break;

            if (alias[0]) {
                if (stars == 0 && arr_cnt == 1 && !is_fnptr) {
                    typ_def copy = *base_def;
                    snprintf(copy.name, sizeof(copy.name), "%s", alias);
                    chdr_upsert(ctx, &copy, rec_align);
                    if (!primary[0]) snprintf(primary, sizeof(primary), "%s", alias);
                    if (tag[0] && strcmp(tag, alias) == 0) tag_done = 1;
                } else {
                    typ_def pdef;
                    memset(&pdef, 0, sizeof(pdef));
                    pdef.kind = CHDR_KIND_TYPEDEF;
                    snprintf(pdef.name, sizeof(pdef.name), "%s", alias);
                    snprintf(pdef.mems[0].name, sizeof(pdef.mems[0].name), "alias");
                    const char *tref = primary[0] ? primary : (tag[0] ? tag : "void");
                    if (is_fnptr) {
                        snprintf(pdef.mems[0].type, sizeof(pdef.mems[0].type), "fn_t *");
                        pdef.size = 8;
                    } else {
                        chdr_fmt_ptr_type(tref, stars, arr_cnt, pdef.mems[0].type, sizeof(pdef.mems[0].type));
                        pdef.size = chdr_mul_i32(stars > 0 ? 8 : base_def->size, arr_cnt);
                    }
                    pdef.mems[0].size = pdef.size;
                    pdef.nmem = 1;
                    chdr_upsert(ctx, &pdef, stars > 0 || is_fnptr ? 8 : rec_align);
                }
            }

            p = chdr_skip_ws(p);
            if (*p == ',') { p++; continue; }
            break;
        }
    }

    if (tag[0] && !tag_done) {
        typ_def copy = *base_def;
        snprintf(copy.name, sizeof(copy.name), "%s", tag);
        chdr_upsert(ctx, &copy, rec_align);
    }

    while (*p && *p != ';') p++;
    if (*p == ';') p++;
    return p;
}

static const char *chdr_parse_record(chdr_ctx *ctx, const char *p, int is_union, int is_typedef) {
    char tag[40] = "";
    p = chdr_skip_attrs(p);
    if (chdr_is_id_start(*p)) p = chdr_read_id(p, tag, sizeof(tag));
    p = chdr_skip_attrs(p);
    if (*p != '{') {
        while (*p && *p != ';') p++;
        if (*p == ';') p++;
        return p;
    }

    typ_def def;
    int rec_align = 1;
    p = chdr_parse_record_body(ctx, p, is_union, 0, &def, &rec_align);
    return chdr_register_aliases(ctx, p, &def, tag, rec_align, is_typedef);
}

static const char *chdr_parse_enum(chdr_ctx *ctx, const char *p, int is_typedef) {
    char tag[40] = "";
    p = chdr_skip_attrs(p);
    if (chdr_is_id_start(*p)) p = chdr_read_id(p, tag, sizeof(tag));
    p = chdr_skip_attrs(p);
    if (*p != '{') {
        while (*p && *p != ';') p++;
        if (*p == ';') p++;
        return p;
    }

    typ_def def;
    p = chdr_parse_enum_body(ctx, p, &def);
    return chdr_register_aliases(ctx, p, &def, tag, 4, is_typedef);
}

static const char *chdr_parse_typedef(chdr_ctx *ctx, const char *p) {
    char base[40];
    p = chdr_parse_base_type(p, base, sizeof(base));
    if (!base[0]) {
        while (*p && *p != ';') p++;
        if (*p == ';') p++;
        return p;
    }

    for (;;) {
        p = chdr_skip_ws(p);
        if (*p == ';' || *p == 0) break;

        int stars = 0, arr_cnt = 1, bf_bits = -1, is_fnptr = 0;
        char alias[40];
        const char *dp = p;
        p = chdr_parse_decl(ctx, p, &stars, alias, sizeof(alias), &arr_cnt, &bf_bits, &is_fnptr);
        if (p == dp && !alias[0]) break;

        if (alias[0]) {
            // avoid clobbering struct/enum with self-alias
            if (!is_fnptr && stars == 0 && arr_cnt == 1 && strcmp(base, alias) == 0) {
                p = chdr_skip_ws(p);
                if (*p == ',') { p++; continue; }
                break;
            }
            typ_def def;
            memset(&def, 0, sizeof(def));
            def.kind = CHDR_KIND_TYPEDEF;
            snprintf(def.name, sizeof(def.name), "%s", alias);
            snprintf(def.mems[0].name, sizeof(def.mems[0].name), "alias");

            int al = 8;
            if (is_fnptr) {
                snprintf(def.mems[0].type, sizeof(def.mems[0].type), "fn_t *");
                def.size = chdr_mul_i32(8, arr_cnt);
                al = 8;
            } else {
                chdr_fmt_ptr_type(base, stars, arr_cnt, def.mems[0].type, sizeof(def.mems[0].type));
                int esz = stars > 0 ? 8 : chdr_sizeof_depth(ctx, base, 0);
                al = stars > 0 ? 8 : chdr_alignof_depth(ctx, base, 0);
                def.size = chdr_mul_i32(esz, arr_cnt);
            }
            def.mems[0].size = def.size;
            def.nmem = 1;
            chdr_upsert(ctx, &def, al);
        }

        p = chdr_skip_ws(p);
        if (*p == ',') { p++; continue; }
        break;
    }

    while (*p && *p != ';') p++;
    if (*p == ';') p++;
    return p;
}

bool chdr_parse(typ_store *s, const char *text, chdr_res *out) {
    if (out) memset(out, 0, sizeof(*out));
    if (!s || !text || !text[0]) {
        if (out) snprintf(out->err, sizeof(out->err), "empty input");
        return false;
    }

    chdr_ctx *ctx = (chdr_ctx *)calloc(1, sizeof(chdr_ctx));
    if (!ctx) {
        if (out) snprintf(out->err, sizeof(out->err), "out of memory");
        return false;
    }
    ctx->store = s;
    ctx->cur_pack = 8;

    char *clean = chdr_preprocess(ctx, text);
    if (!clean) {
        free(ctx);
        if (out) snprintf(out->err, sizeof(out->err), "out of memory");
        return false;
    }

    const char *p = clean;
    while (*p) {
        p = chdr_skip_ws(p);
        if (!*p) break;
        if (*p == ';' || *p == '}') { p++; continue; }
        if (*p == '#') { p = chdr_handle_pragma(ctx, p); continue; }

        const char *start_p = p;
        char kw[32];
        const char *q = chdr_read_id(p, kw, sizeof(kw));

        if (strcmp(kw, "extern") == 0) {
            q = chdr_skip_ws(q);
            if (*q == '"') {
                q++;
                while (*q && *q != '"') q++;
                if (*q == '"') q++;
                q = chdr_skip_ws(q);
                if (*q == '{') { p = q + 1; continue; }
            }
            while (*q && *q != ';' && *q != '{') q++;
            if (*q == '{') p = chdr_skip_balanced(q, '{', '}');
            else p = (*q == ';') ? q + 1 : q;
        } else if (strcmp(kw, "namespace") == 0) {
            q = chdr_skip_ws(q);
            char ns[32];
            if (chdr_is_id_start(*q)) q = chdr_read_id(q, ns, sizeof(ns));
            q = chdr_skip_ws(q);
            if (*q == '{') p = q + 1;
            else p = q;
        } else if (strcmp(kw, "struct") == 0 || strcmp(kw, "union") == 0) {
            p = chdr_parse_record(ctx, q, strcmp(kw, "union") == 0, 0);
        } else if (strcmp(kw, "enum") == 0) {
            p = chdr_parse_enum(ctx, q, 0);
        } else if (strcmp(kw, "typedef") == 0) {
            int is_u = 0;
            const char *akw = NULL;
            if (chdr_peek_inline_record(q, &is_u, &akw)) {
                p = chdr_parse_record(ctx, akw, is_u, 1);
            } else if (chdr_peek_inline_enum(q, &akw)) {
                p = chdr_parse_enum(ctx, akw, 1);
            } else {
                p = chdr_parse_typedef(ctx, q);
            }
        } else {
            while (*p && *p != ';' && *p != '{') p++;
            if (*p == '{') p = chdr_skip_balanced(p, '{', '}');
            else if (*p == ';') p++;
        }

        if (p == start_p && *p) p++;
    }

    int added = ctx->types_added;
    if (out) {
        out->types_added = added;
        out->defines = ctx->defines;
        if (added == 0) snprintf(out->err, sizeof(out->err), "no types parsed");
    }

    free(clean);
    free(ctx);
    return added > 0;
}

static const char *const chdr_xtil_win32 =
    "typedef uint8_t BYTE;\n"
    "typedef uint16_t WORD;\n"
    "typedef uint32_t DWORD;\n"
    "typedef uint64_t QWORD;\n"
    "typedef int32_t BOOL;\n"
    "typedef void *HANDLE;\n"
    "typedef void *HMODULE;\n"
    "typedef void *PVOID;\n"
    "typedef const char *LPCSTR;\n"
    "typedef const uint16_t *LPCWSTR;\n"
    "typedef struct _LIST_ENTRY {\n"
    "  struct _LIST_ENTRY *Flink;\n"
    "  struct _LIST_ENTRY *Blink;\n"
    "} LIST_ENTRY, *PLIST_ENTRY;\n"
    "typedef struct _UNICODE_STRING {\n"
    "  WORD Length;\n"
    "  WORD MaximumLength;\n"
    "  uint16_t *Buffer;\n"
    "} UNICODE_STRING, *PUNICODE_STRING;\n"
    "typedef struct _CLIENT_ID {\n"
    "  HANDLE UniqueProcess;\n"
    "  HANDLE UniqueThread;\n"
    "} CLIENT_ID, *PCLIENT_ID;\n"
    "typedef struct _PEB_LDR_DATA {\n"
    "  DWORD Length;\n"
    "  BYTE Initialized;\n"
    "  PVOID SsHandle;\n"
    "  LIST_ENTRY InLoadOrderModuleList;\n"
    "  LIST_ENTRY InMemoryOrderModuleList;\n"
    "  LIST_ENTRY InInitializationOrderModuleList;\n"
    "  PVOID EntryInProgress;\n"
    "  BYTE ShutdownInProgress;\n"
    "  PVOID ShutdownThreadId;\n"
    "} PEB_LDR_DATA, *PPEB_LDR_DATA;\n"
    "typedef struct _IMAGE_DOS_HEADER {\n"
    "  WORD e_magic;\n"
    "  WORD e_cblp;\n"
    "  WORD e_cp;\n"
    "  WORD e_crlc;\n"
    "  WORD e_cparhdr;\n"
    "  WORD e_minalloc;\n"
    "  WORD e_maxalloc;\n"
    "  WORD e_ss;\n"
    "  WORD e_sp;\n"
    "  WORD e_csum;\n"
    "  WORD e_ip;\n"
    "  WORD e_cs;\n"
    "  WORD e_lfarlc;\n"
    "  WORD e_ovno;\n"
    "  WORD e_res[4];\n"
    "  WORD e_oemid;\n"
    "  WORD e_oeminfo;\n"
    "  WORD e_res2[10];\n"
    "  int32_t e_lfanew;\n"
    "} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;\n"
    "typedef struct _IMAGE_FILE_HEADER {\n"
    "  WORD Machine;\n"
    "  WORD NumberOfSections;\n"
    "  DWORD TimeDateStamp;\n"
    "  DWORD PointerToSymbolTable;\n"
    "  DWORD NumberOfSymbols;\n"
    "  WORD SizeOfOptionalHeader;\n"
    "  WORD Characteristics;\n"
    "} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;\n"
    "typedef struct _IMAGE_SECTION_HEADER {\n"
    "  BYTE Name[8];\n"
    "  union {\n"
    "    DWORD PhysicalAddress;\n"
    "    DWORD VirtualSize;\n"
    "  };\n"
    "  DWORD VirtualAddress;\n"
    "  DWORD SizeOfRawData;\n"
    "  DWORD PointerToRawData;\n"
    "  DWORD PointerToRelocations;\n"
    "  DWORD PointerToLinenumbers;\n"
    "  WORD NumberOfRelocations;\n"
    "  WORD NumberOfLinenumbers;\n"
    "  DWORD Characteristics;\n"
    "} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;\n"
    "typedef struct _RTL_CRITICAL_SECTION {\n"
    "  PVOID DebugInfo;\n"
    "  int32_t LockCount;\n"
    "  int32_t RecursionCount;\n"
    "  HANDLE OwningThread;\n"
    "  HANDLE LockSemaphore;\n"
    "  QWORD SpinCount;\n"
    "} RTL_CRITICAL_SECTION, *PRTL_CRITICAL_SECTION;\n"
    "typedef struct _SOCKADDR_IN {\n"
    "  uint16_t sin_family;\n"
    "  uint16_t sin_port;\n"
    "  uint32_t sin_addr;\n"
    "  char sin_zero[8];\n"
    "} SOCKADDR_IN, *PSOCKADDR_IN;\n"
    "typedef struct _SYSTEMTIME {\n"
    "  WORD wYear;\n"
    "  WORD wMonth;\n"
    "  WORD wDayOfWeek;\n"
    "  WORD wDay;\n"
    "  WORD wHour;\n"
    "  WORD wMinute;\n"
    "  WORD wSecond;\n"
    "  WORD wMilliseconds;\n"
    "} SYSTEMTIME, *PSYSTEMTIME;\n"
    "typedef union _LARGE_INTEGER {\n"
    "  struct {\n"
    "    DWORD LowPart;\n"
    "    int32_t HighPart;\n"
    "  };\n"
    "  int64_t QuadPart;\n"
    "} LARGE_INTEGER, *PLARGE_INTEGER;\n";

static const char *const chdr_xtil_posix =
    "typedef int32_t pid_t;\n"
    "typedef uint32_t uid_t;\n"
    "typedef uint32_t gid_t;\n"
    "typedef int64_t off_t;\n"
    "typedef int64_t time_t;\n"
    "typedef struct timespec {\n"
    "  time_t tv_sec;\n"
    "  int64_t tv_nsec;\n"
    "} timespec;\n"
    "typedef struct iovec {\n"
    "  void *iov_base;\n"
    "  uint64_t iov_len;\n"
    "} iovec;\n"
    "typedef struct sockaddr_in {\n"
    "  uint16_t sin_family;\n"
    "  uint16_t sin_port;\n"
    "  uint32_t sin_addr;\n"
    "  uint8_t sin_zero[8];\n"
    "} sockaddr_in;\n"
    "typedef struct elf64_ehdr {\n"
    "  uint8_t e_ident[16];\n"
    "  uint16_t e_type;\n"
    "  uint16_t e_machine;\n"
    "  uint32_t e_version;\n"
    "  uint64_t e_entry;\n"
    "  uint64_t e_phoff;\n"
    "  uint64_t e_shoff;\n"
    "  uint32_t e_flags;\n"
    "  uint16_t e_ehsize;\n"
    "  uint16_t e_phentsize;\n"
    "  uint16_t e_phnum;\n"
    "  uint16_t e_shentsize;\n"
    "  uint16_t e_shnum;\n"
    "  uint16_t e_shstrndx;\n"
    "} elf64_ehdr;\n"
    "typedef struct elf64_phdr {\n"
    "  uint32_t p_type;\n"
    "  uint32_t p_flags;\n"
    "  uint64_t p_offset;\n"
    "  uint64_t p_vaddr;\n"
    "  uint64_t p_paddr;\n"
    "  uint64_t p_filesz;\n"
    "  uint64_t p_memsz;\n"
    "  uint64_t p_align;\n"
    "} elf64_phdr;\n"
    "typedef struct elf64_shdr {\n"
    "  uint32_t sh_name;\n"
    "  uint32_t sh_type;\n"
    "  uint64_t sh_flags;\n"
    "  uint64_t sh_addr;\n"
    "  uint64_t sh_offset;\n"
    "  uint64_t sh_size;\n"
    "  uint32_t sh_link;\n"
    "  uint32_t sh_info;\n"
    "  uint64_t sh_addralign;\n"
    "  uint64_t sh_entsize;\n"
    "} elf64_shdr;\n";

int chdr_load_stdlib(typ_store *s, const char *pack) {
    if (!s || !pack || !pack[0]) return 0;

    int total = 0;
    chdr_res r;
    if (chdr_strieq(pack, "win32") || chdr_strieq(pack, "all")) {
        if (chdr_parse(s, chdr_xtil_win32, &r)) total += r.types_added;
    }
    if (chdr_strieq(pack, "posix") || chdr_strieq(pack, "all")) {
        if (chdr_parse(s, chdr_xtil_posix, &r)) total += r.types_added;
    }
    return total;
}

static bool chdr_is_legacy_pfx(uint8_t b) {
    return b == 0xF0 || b == 0xF2 || b == 0xF3 || b == 0x66 || b == 0x67 ||
           b == 0x26 || b == 0x2E || b == 0x36 || b == 0x3E || b == 0x64 || b == 0x65;
}

static void chdr_mask_x86(const uint8_t *code, int bits, const x86_ins *ins, uint8_t *mask) {
    int n = (int)ins->len;
    memset(mask, 0xFF, (size_t)n);
    if (n <= 1) return;

    int pos = 0;
    while (pos < n - 1 && chdr_is_legacy_pfx(code[pos])) pos++;

    uint8_t rex = 0;
    if (bits == 64 && pos < n - 1 && (code[pos] & 0xF0) == 0x40) {
        rex = code[pos++];
    }

    uint8_t op = code[pos];

    // call/jmp rel32
    if ((op == 0xE8 || op == 0xE9) && pos + 5 <= n) {
        memset(mask + pos + 1, 0, 4);
        return;
    }
    if ((op == 0xE8 || op == 0xE9) && pos + 3 <= n) {
        memset(mask + pos + 1, 0, 2);
        return;
    }

    // jcc near rel32
    if (op == 0x0F && pos + 1 < n && (code[pos + 1] & 0xF0) == 0x80) {
        if (pos + 6 <= n) {
            memset(mask + pos + 2, 0, 4);
            return;
        }
        if (pos + 4 <= n) {
            memset(mask + pos + 2, 0, 2);
            return;
        }
    }

    // short jmp/jcc/loop rel8
    if ((op == 0xEB || (op >= 0x70 && op <= 0x7F) || (op >= 0xE0 && op <= 0xE3)) && pos + 2 <= n) {
        mask[pos + 1] = 0;
        return;
    }

    // movabs reg, imm64
    if (bits == 64 && (rex & 0x08) != 0 && op >= 0xB8 && op <= 0xBF && pos + 9 <= n) {
        memset(mask + pos + 1, 0, 8);
        return;
    }

    // rip-relative or moffs memory displacement
    if (ins->target_mem) {
        if (op >= 0xA0 && op <= 0xA3 && pos + 1 < n) {
            memset(mask + pos + 1, 0, (size_t)(n - pos - 1));
            return;
        }
        int mpos = -1;
        if (op == 0xC5 && pos + 3 < n) {
            mpos = pos + 3;
        } else if (op == 0xC4 && pos + 4 < n) {
            mpos = pos + 4;
        } else if (op == 0x62 && pos + 5 < n) {
            mpos = pos + 5;
        } else if (op == 0x0F && pos + 1 < n) {
            uint8_t op2 = code[pos + 1];
            mpos = (op2 == 0x38 || op2 == 0x3A) ? (pos + 3) : (pos + 2);
        } else {
            mpos = pos + 1;
        }

        if (mpos > 0 && mpos + 5 <= n && (code[mpos] & 0xC7) == 0x05) {
            memset(mask + mpos + 1, 0, 4);
            return;
        }
        if (n >= 5) {
            memset(mask + n - 4, 0, 4);
        }
    }
}

static void chdr_mask_arm64(const uint8_t *code, const x86_ins *ins, uint8_t *mask) {
    int n = (int)ins->len;
    memset(mask, 0xFF, (size_t)n);
    if (n != 4) return;

    uint32_t w = 0;
    memcpy(&w, code, 4);

    // b / bl: keep opcode top byte, wildcard imm26 lower 3 bytes
    if ((w & 0x7C000000U) == 0x14000000U) {
        mask[0] = 0;
        mask[1] = 0;
        mask[2] = 0;
        return;
    }

    // adrp / adr / conditional branches / pc-rel ldr: wildcard mid imm bytes
    if ((w & 0x1F000000U) == 0x10000000U ||
        (w & 0xFF000010U) == 0x54000000U ||
        (w & 0x7E000000U) == 0x34000000U ||
        (w & 0x7E000000U) == 0x36000000U ||
        (w & 0x3B000000U) == 0x18000000U) {
        mask[1] = 0;
        mask[2] = 0;
    }
}

static void chdr_build_pat(const uint8_t *bytes, const uint8_t *mask, size_t len, scan_pat *pat) {
    memset(pat, 0, sizeof(*pat));
    pat->len = len;
    pat->anchor = SCAN_PAT_MAX;

    size_t fallback = SCAN_PAT_MAX;
    for (size_t i = 0; i < len; i++) {
        pat->mask[i] = mask[i];
        pat->bytes[i] = mask[i] ? bytes[i] : 0;
        if (mask[i]) {
            if (fallback == SCAN_PAT_MAX) fallback = i;
            if (pat->anchor == SCAN_PAT_MAX &&
                bytes[i] != 0x00 && bytes[i] != 0x90 && bytes[i] != 0xCC && bytes[i] != 0x48) {
                pat->anchor = i;
            }
        }
    }
    if (pat->anchor == SCAN_PAT_MAX) pat->anchor = fallback;
}

static int chdr_count_hits(const uint8_t *buf, size_t len, const scan_pat *pat, int max_hits) {
    int hits = 0;
    size_t pos = 0;
    while (pos < len && hits < max_hits) {
        size_t h = scan_pat_find(buf, len, pos, pat);
        if (h >= len) break;
        hits++;
        pos = h + 1;
    }
    return hits;
}

bool chdr_make_sig(const ana_ctx *a, uint64_t va, chdr_sig_res *out) {
    if (out) memset(out, 0, sizeof(*out));
    if (!a || !out || !a->bin.map.data || a->bin.map.size == 0) return false;

    out->va = va;
    size_t avail = 0;
    const uint8_t *code = bin_ptr(&a->bin, va, &avail);
    if (!code || avail < 1) return false;

    size_t max_len = CHDR_SIG_MAX;
    if (avail < max_len) max_len = avail;
    if (max_len > (size_t)SCAN_PAT_MAX) max_len = (size_t)SCAN_PAT_MAX;
    if (max_len > sizeof(out->c_mask) - 1U) max_len = sizeof(out->c_mask) - 1U;
    uint8_t bytes[SCAN_PAT_MAX];
    uint8_t mask[SCAN_PAT_MAX];
    size_t total = 0;
    int hits = 0;

    const uint8_t *mbuf = a->bin.map.data;
    size_t mlen = (size_t)a->bin.map.size;

    while (total < max_len) {
        x86_ins ins;
        int ilen = arch_decode(a->bin.arch, code + total, avail - total, va + total, 0, 0, &ins);
        if (ilen <= 0) break;
        if (total + (size_t)ilen > max_len) {
            if (total > 0) break;
            ilen = (int)max_len;
            ins.len = (uint8_t)ilen;
        }

        memcpy(bytes + total, code + total, (size_t)ilen);
        if (a->bin.arch == BIN_ARCH_X64 || a->bin.arch == BIN_ARCH_X86) {
            chdr_mask_x86(code + total, a->bin.arch == BIN_ARCH_X86 ? 32 : 64, &ins, mask + total);
        } else if (a->bin.arch == BIN_ARCH_ARM64) {
            chdr_mask_arm64(code + total, &ins, mask + total);
        } else {
            memset(mask + total, 0xFF, (size_t)ilen);
        }
        total += (size_t)ilen;

        if (total >= 5) {
            scan_pat pat;
            chdr_build_pat(bytes, mask, total, &pat);
            if (pat.anchor >= pat.len) {
                mask[0] = 0xFF;
                chdr_build_pat(bytes, mask, total, &pat);
            }
            hits = chdr_count_hits(mbuf, mlen, &pat, 2);
            if (hits == 1) break;
        }
    }

    if (total == 0) return false;

    if (hits != 1) {
        scan_pat pat;
        chdr_build_pat(bytes, mask, total, &pat);
        if (pat.anchor >= pat.len) {
            mask[0] = 0xFF;
            chdr_build_pat(bytes, mask, total, &pat);
        }
        hits = chdr_count_hits(mbuf, mlen, &pat, 99);
    }

    size_t ipos = 0;
    size_t cpos = 0;
    size_t out_len = total;
    if (out_len >= sizeof(out->c_mask)) out_len = sizeof(out->c_mask) - 1U;
    for (size_t i = 0; i < out_len; i++) {
        if (i > 0 && ipos + 1 < sizeof(out->ida)) {
            out->ida[ipos++] = ' ';
            out->ida[ipos] = 0;
        }
        if (ipos + 1 < sizeof(out->ida)) {
            int iw = mask[i]
                ? snprintf(out->ida + ipos, sizeof(out->ida) - ipos, "%02X", bytes[i])
                : snprintf(out->ida + ipos, sizeof(out->ida) - ipos, "??");
            if (iw > 0) {
                size_t irem = sizeof(out->ida) - ipos - 1U;
                ipos += ((size_t)iw < irem) ? (size_t)iw : irem;
            }
        }
        if (cpos + 1 < sizeof(out->c_bytes)) {
            int cw = mask[i]
                ? snprintf(out->c_bytes + cpos, sizeof(out->c_bytes) - cpos, "\\x%02X", bytes[i])
                : snprintf(out->c_bytes + cpos, sizeof(out->c_bytes) - cpos, "\\x00");
            if (cw > 0) {
                size_t crem = sizeof(out->c_bytes) - cpos - 1U;
                cpos += ((size_t)cw < crem) ? (size_t)cw : crem;
            }
        }
        out->c_mask[i] = mask[i] ? 'x' : '?';
    }
    out->c_mask[out_len] = 0;
    out->len = (int)out_len;
    out->hits = hits;
    return out->len > 0;
}
