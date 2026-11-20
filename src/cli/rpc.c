#include "cli.h"
#include "../ana/ana.h"
#include "../dbg/dbg.h"
#include "../ext/ext.h"
#include "../opt/opt.h"
#include "../scan/scan.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RPC_INIT_LINE      65536u
#define RPC_MAX_LINE       (32u * 1024u * 1024u)
#define RPC_JSON_MAX_DEPTH 64

typedef struct {
    uint32_t id;
    uint64_t va;
    char     kind[12];
    char     val[192];
    char     reason[128];
    int      conf;
    int      status; // 0=pending 1=accepted 2=rejected
} rpc_sug;

typedef struct {
    ana_ctx   ana;
    ana_ctx   diff_ana;
    int       has_diff;
    typ_store types;
    dbg_ctx   dbg;
    gdb_ctx   gdb;
    dmp_ctx   dmp;
    opt_cfg   opt;
    ext_host  ext;
    uint64_t  cur_va;
    rpc_sug   sugs[128];
    int       nsug;
    uint32_t  next_sug_id;
    char      log_buf[4096];
    size_t    log_len;
} rpc_state;

static void rpc_jstr(const char *s) {
    putchar('"');
    if (s) {
        for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
            if (*p == '"') fputs("\\\"", stdout);
            else if (*p == '\\') fputs("\\\\", stdout);
            else if (*p == '\n') fputs("\\n", stdout);
            else if (*p == '\r') fputs("\\r", stdout);
            else if (*p == '\t') fputs("\\t", stdout);
            else if (*p < 0x20) printf("\\u%04x", *p);
            else putchar(*p);
        }
    }
    putchar('"');
}

static void rpc_log_cb(void *ud, const char *msg) {
    rpc_state *r = (rpc_state *)ud;
    if (!msg) return;
    size_t n = strlen(msg);
    if (r->log_len + n + 2 < sizeof(r->log_buf)) {
        if (r->log_len) r->log_buf[r->log_len++] = '\n';
        memcpy(r->log_buf + r->log_len, msg, n);
        r->log_len += n;
        r->log_buf[r->log_len] = 0;
    }
}

static uint64_t rpc_get_va(void *ud) { return ((rpc_state *)ud)->cur_va; }
static void rpc_set_va(void *ud, uint64_t va) { ((rpc_state *)ud)->cur_va = va; }

static void rpc_json_skip_ws(const char **pp) {
    const char *p = *pp;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    *pp = p;
}

static bool rpc_json_parse_hex4(const char *p, uint32_t *out) {
    uint32_t v = 0;
    for (int i = 0; i < 4; i++) {
        unsigned char c = (unsigned char)p[i];
        uint32_t d;
        if (c >= '0' && c <= '9') d = (uint32_t)(c - '0');
        else if (c >= 'a' && c <= 'f') d = (uint32_t)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') d = (uint32_t)(c - 'A' + 10);
        else return false;
        v = (v << 4) | d;
    }
    *out = v;
    return true;
}

static size_t rpc_json_utf8_encode(uint32_t cp, char u8[4]) {
    if (cp <= 0x7Fu) {
        u8[0] = (char)cp;
        return 1;
    }
    if (cp <= 0x7FFu) {
        u8[0] = (char)(0xC0u | (cp >> 6));
        u8[1] = (char)(0x80u | (cp & 0x3Fu));
        return 2;
    }
    if (cp <= 0xFFFFu) {
        u8[0] = (char)(0xE0u | (cp >> 12));
        u8[1] = (char)(0x80u | ((cp >> 6) & 0x3Fu));
        u8[2] = (char)(0x80u | (cp & 0x3Fu));
        return 3;
    }
    if (cp <= 0x10FFFFu) {
        u8[0] = (char)(0xF0u | (cp >> 18));
        u8[1] = (char)(0x80u | ((cp >> 12) & 0x3Fu));
        u8[2] = (char)(0x80u | ((cp >> 6) & 0x3Fu));
        u8[3] = (char)(0x80u | (cp & 0x3Fu));
        return 4;
    }
    u8[0] = (char)0xEFu;
    u8[1] = (char)0xBDu;
    u8[2] = (char)0xBDu;
    return 3;
}

static bool rpc_json_read_str_ex(const char **pp, char *dst, size_t max, bool allow_nul, bool *out_trunc) {
    const char *p = *pp;
    if (*p != '"') return false;
    p++;
    size_t k = 0;
    bool trunc = false;
    while (*p && *p != '"') {
        unsigned char uc = (unsigned char)*p;
        if (uc < 0x20u) return false;
        if (*p == '\\') {
            p++;
            if (!*p) return false;
            char esc = *p++;
            if (esc == 'u') {
                uint32_t cp = 0;
                if (!p[0] || !p[1] || !p[2] || !p[3] || !rpc_json_parse_hex4(p, &cp)) return false;
                p += 4;
                if (cp >= 0xD800u && cp <= 0xDBFFu) {
                    uint32_t lo = 0;
                    if (p[0] == '\\' && p[1] == 'u' && p[2] && p[3] && p[4] && p[5] &&
                        rpc_json_parse_hex4(p + 2, &lo) && lo >= 0xDC00u && lo <= 0xDFFFu) {
                        cp = 0x10000u + (((cp - 0xD800u) << 10) | (lo - 0xDC00u));
                        p += 6;
                    } else {
                        cp = 0xFFFDu;
                    }
                } else if (cp >= 0xDC00u && cp <= 0xDFFFu) {
                    cp = 0xFFFDu;
                }
                if (cp == 0 && !allow_nul) return false;
                char u8[4];
                size_t n8 = rpc_json_utf8_encode(cp, u8);
                if (!trunc && dst && max > 0) {
                    if (k + n8 < max) {
                        memcpy(dst + k, u8, n8);
                        k += n8;
                    } else {
                        trunc = true;
                    }
                }
            } else {
                char out_ch;
                switch (esc) {
                case '"':  out_ch = '"';  break;
                case '\\': out_ch = '\\'; break;
                case '/':  out_ch = '/';  break;
                case 'b':  out_ch = '\b'; break;
                case 'f':  out_ch = '\f'; break;
                case 'n':  out_ch = '\n'; break;
                case 'r':  out_ch = '\r'; break;
                case 't':  out_ch = '\t'; break;
                default:   return false;
                }
                if (!trunc && dst && max > 0) {
                    if (k + 1 < max) {
                        dst[k++] = out_ch;
                    } else {
                        trunc = true;
                    }
                }
            }
        } else {
            unsigned char lead = (unsigned char)*p;
            size_t seq = 1;
            if ((lead & 0xE0u) == 0xC0u && ((unsigned char)p[1] & 0xC0u) == 0x80u) {
                seq = 2;
            } else if ((lead & 0xF0u) == 0xE0u &&
                       ((unsigned char)p[1] & 0xC0u) == 0x80u &&
                       ((unsigned char)p[2] & 0xC0u) == 0x80u) {
                seq = 3;
            } else if ((lead & 0xF8u) == 0xF0u &&
                       ((unsigned char)p[1] & 0xC0u) == 0x80u &&
                       ((unsigned char)p[2] & 0xC0u) == 0x80u &&
                       ((unsigned char)p[3] & 0xC0u) == 0x80u) {
                seq = 4;
            }
            if (!trunc && dst && max > 0) {
                if (k + seq < max) {
                    memcpy(dst + k, p, seq);
                    k += seq;
                } else {
                    trunc = true;
                }
            }
            p += seq;
        }
    }
    if (*p != '"') return false;
    p++;
    if (dst && max > 0) dst[k] = '\0';
    if (out_trunc) *out_trunc = trunc;
    *pp = p;
    return true;
}

static bool rpc_json_skip_num(const char **pp) {
    const char *p = *pp;
    if (*p == '-') p++;
    if (*p == '0') {
        p++;
        if (isdigit((unsigned char)*p)) return false;
    } else if (*p >= '1' && *p <= '9') {
        while (isdigit((unsigned char)*p)) p++;
    } else {
        return false;
    }
    if (*p == '.') {
        p++;
        if (!isdigit((unsigned char)*p)) return false;
        while (isdigit((unsigned char)*p)) p++;
    }
    if (*p == 'e' || *p == 'E') {
        p++;
        if (*p == '+' || *p == '-') p++;
        if (!isdigit((unsigned char)*p)) return false;
        while (isdigit((unsigned char)*p)) p++;
    }
    *pp = p;
    return true;
}

static bool rpc_json_skip_val(const char **pp, int depth) {
    if (depth > RPC_JSON_MAX_DEPTH) return false;
    rpc_json_skip_ws(pp);
    const char *p = *pp;
    if (*p == '"') {
        return rpc_json_read_str_ex(pp, NULL, 0, true, NULL);
    }
    if (*p == '{') {
        p++;
        *pp = p;
        rpc_json_skip_ws(pp);
        if (**pp == '}') { (*pp)++; return true; }
        for (;;) {
            rpc_json_skip_ws(pp);
            if (**pp != '"') return false;
            if (!rpc_json_read_str_ex(pp, NULL, 0, true, NULL)) return false;
            rpc_json_skip_ws(pp);
            if (**pp != ':') return false;
            (*pp)++;
            if (!rpc_json_skip_val(pp, depth + 1)) return false;
            rpc_json_skip_ws(pp);
            if (**pp == ',') { (*pp)++; continue; }
            if (**pp == '}') { (*pp)++; return true; }
            return false;
        }
    }
    if (*p == '[') {
        p++;
        *pp = p;
        rpc_json_skip_ws(pp);
        if (**pp == ']') { (*pp)++; return true; }
        for (;;) {
            if (!rpc_json_skip_val(pp, depth + 1)) return false;
            rpc_json_skip_ws(pp);
            if (**pp == ',') { (*pp)++; continue; }
            if (**pp == ']') { (*pp)++; return true; }
            return false;
        }
    }
    if (strncmp(p, "true", 4) == 0) { *pp = p + 4; return true; }
    if (strncmp(p, "false", 5) == 0) { *pp = p + 5; return true; }
    if (strncmp(p, "null", 4) == 0) { *pp = p + 4; return true; }
    return rpc_json_skip_num(pp);
}

static bool rpc_json_validate_obj(const char *line) {
    if (!line) return false;
    const char *p = line;
    rpc_json_skip_ws(&p);
    if (*p != '{') return false;
    if (!rpc_json_skip_val(&p, 0)) return false;
    rpc_json_skip_ws(&p);
    return *p == '\0';
}

static const char *rpc_json_find_top(const char *line, const char *key) {
    if (!line || !key) return NULL;
    const char *p = line;
    rpc_json_skip_ws(&p);
    if (*p != '{') return NULL;
    p++;
    rpc_json_skip_ws(&p);
    if (*p == '}') return NULL;
    const char *found = NULL;
    for (;;) {
        rpc_json_skip_ws(&p);
        if (*p != '"') return NULL;
        char kbuf[128];
        bool ktrunc = false;
        if (!rpc_json_read_str_ex(&p, kbuf, sizeof(kbuf), false, &ktrunc)) return NULL;
        rpc_json_skip_ws(&p);
        if (*p != ':') return NULL;
        p++;
        rpc_json_skip_ws(&p);
        if (!ktrunc && strcmp(kbuf, key) == 0) found = p;
        if (!rpc_json_skip_val(&p, 1)) return NULL;
        rpc_json_skip_ws(&p);
        if (*p == ',') { p++; continue; }
        if (*p == '}') break;
        return NULL;
    }
    return found;
}

static bool rpc_jget_str(const char *line, const char *key, char *dst, size_t max) {
    if (!dst || max == 0) return false;
    const char *v = rpc_json_find_top(line, key);
    if (!v || *v != '"') return false;
    return rpc_json_read_str_ex(&v, dst, max, false, NULL);
}

static char *rpc_jget_str_alloc(const char *line, const char *key, size_t max_alloc) {
    const char *v = rpc_json_find_top(line, key);
    if (!v || *v != '"') return NULL;
    const char *scan = v;
    if (!rpc_json_read_str_ex(&scan, NULL, 0, false, NULL)) return NULL;
    size_t raw_len = (size_t)(scan - v);
    size_t cap = raw_len + 1;
    if (cap > max_alloc) cap = max_alloc;
    if (cap == 0) return NULL;
    char *out = (char *)malloc(cap);
    if (!out) return NULL;
    const char *p = v;
    if (!rpc_json_read_str_ex(&p, out, cap, false, NULL)) {
        free(out);
        return NULL;
    }
    return out;
}

static bool rpc_jparse_u64(const char *p, uint64_t *val) {
    if (!p || !val) return false;
    if (*p == '"') {
        char num[64];
        bool trunc = false;
        if (!rpc_json_read_str_ex(&p, num, sizeof(num), false, &trunc) || trunc) return false;
        if (!num[0]) return false;
        if (num[0] == '0' && (num[1] == 'x' || num[1] == 'X')) {
            const char *d = num + 2;
            if (!*d) return false;
            for (const char *q = d; *q; q++) {
                if (!isxdigit((unsigned char)*q)) return false;
            }
            errno = 0;
            char *end = NULL;
            unsigned long long v = strtoull(d, &end, 16);
            if (errno == ERANGE || !end || *end != '\0') return false;
            *val = (uint64_t)v;
            return true;
        }
        for (const char *q = num; *q; q++) {
            if (*q < '0' || *q > '9') return false;
        }
        errno = 0;
        char *end = NULL;
        unsigned long long v = strtoull(num, &end, 10);
        if (errno == ERANGE || !end || *end != '\0') return false;
        *val = (uint64_t)v;
        return true;
    }
    if (*p >= '0' && *p <= '9') {
        const char *q = p;
        while (*q >= '0' && *q <= '9') q++;
        if (*q == '.' || *q == 'e' || *q == 'E') return false;
        if (*q != '\0' && *q != ',' && *q != '}' && *q != ' ' && *q != '\t' && *q != '\r' && *q != '\n') {
            return false;
        }
        errno = 0;
        char *end = NULL;
        unsigned long long v = strtoull(p, &end, 10);
        if (errno == ERANGE || end != q) return false;
        *val = (uint64_t)v;
        return true;
    }
    return false;
}

static int rpc_jget_u64_opt(const char *line, const char *key, uint64_t *val) {
    const char *p = rpc_json_find_top(line, key);
    if (!p) return 0;
    return rpc_jparse_u64(p, val) ? 1 : -1;
}

static bool rpc_jget_u64(const char *line, const char *key, uint64_t *val) {
    return rpc_jget_u64_opt(line, key, val) > 0;
}

static int rpc_read_line(FILE *in, char **buf, size_t *cap, size_t *out_len, bool *has_nul) {
    *out_len = 0;
    *has_nul = false;
    if (!*buf) {
        *buf = (char *)malloc(RPC_INIT_LINE);
        if (!*buf) return -3;
        *cap = RPC_INIT_LINE;
    }
    size_t len = 0;
    int ch;
    while ((ch = fgetc(in)) != EOF) {
        if (ch == '\n') break;
        if (ch == '\0') {
            *has_nul = true;
            continue;
        }
        if (len + 1 >= *cap) {
            if (*cap >= RPC_MAX_LINE) {
                while ((ch = fgetc(in)) != EOF && ch != '\n') {}
                return -2;
            }
            size_t ncap = (*cap <= RPC_MAX_LINE / 2u) ? (*cap * 2u) : RPC_MAX_LINE;
            if (ncap <= len + 1) {
                while ((ch = fgetc(in)) != EOF && ch != '\n') {}
                return -2;
            }
            char *nb = (char *)realloc(*buf, ncap);
            if (!nb) {
                while ((ch = fgetc(in)) != EOF && ch != '\n') {}
                return -3;
            }
            *buf = nb;
            *cap = ncap;
        }
        (*buf)[len++] = (char)ch;
    }
    if (ch == EOF && len == 0 && !*has_nul) return 0;
    if (len > 0 && (*buf)[len - 1] == '\r') len--;
    (*buf)[len] = '\0';
    *out_len = len;
    return 1;
}

static bool rpc_has_bin(const rpc_state *r) {
    return r && r->ana.bin.map.data != NULL && r->ana.bin.path[0] != '\0';
}

static int rpc_hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static bool rpc_parse_hex_bytes(const char *hex, uint8_t *dst, size_t max, size_t *out_n) {
    if (!hex || !dst || !out_n) return false;
    size_t n = 0;
    const char *p = hex;
    while (*p) {
        while (*p == ' ' || *p == '\t' || *p == ',') p++;
        if (!*p) break;
        int hi = rpc_hex_nibble(*p);
        if (hi < 0) return false;
        p++;
        int lo = rpc_hex_nibble(*p);
        if (lo < 0) return false;
        p++;
        if (n >= max) return false;
        dst[n++] = (uint8_t)((hi << 4) | lo);
    }
    if (n == 0) return false;
    *out_n = n;
    return true;
}

static bool rpc_icontains(const char *hay, const char *ndl) {
    if (!ndl || !ndl[0]) return true;
    if (!hay) return false;
    size_t nl = strlen(ndl);
    for (const char *p = hay; *p; p++) {
        size_t i = 0;
        while (i < nl && p[i] && tolower((unsigned char)p[i]) == tolower((unsigned char)ndl[i])) i++;
        if (i == nl) return true;
    }
    return false;
}

static void rpc_emit_info(const rpc_state *r) {
    const ana_ctx *a = &r->ana;
    printf("{\"ok\":true,\"path\":");
    rpc_jstr(a->bin.path);
    printf(",\"fmt\":\"%s\",\"arch\":\"%s\",\"bits\":%d,\"size\":%llu,\"base\":\"0x%llx\",\"entry\":\"0x%llx\","
           "\"min_va\":\"0x%llx\",\"max_va\":\"0x%llx\",\"overlay\":%llu,\"nreloc\":%u,\"nrsrc\":%u,\"guard\":%u,\"pdb\":",
           bin_fmt_name(a->bin.fmt), bin_arch_name(a->bin.arch), a->bin.bits, (unsigned long long)a->bin.map.size,
           (unsigned long long)a->bin.base, (unsigned long long)a->bin.entry,
           (unsigned long long)a->bin.min_va, (unsigned long long)a->bin.max_va,
           (unsigned long long)a->bin.overlay_size, a->bin.nreloc, a->bin.nrsrc, a->bin.guard_flags);
    rpc_jstr(a->bin.pdb_path);
    printf(",\"tls\":[");
    for (uint32_t i = 0; i < a->bin.ntls; i++) {
        if (i) putchar(',');
        printf("\"0x%llx\"", (unsigned long long)a->bin.tls_cbs[i]);
    }
    printf("],\"has_clr\":%d,\"avx2\":%d,\"undo_n\":%u,\"redo_n\":%u,\"load_ms\":%.2f,\"ana_ms\":%.2f,"
           "\"nfunc\":%u,\"nsym\":%u,\"nstr\":%u,\"nxref\":%u,\"nmark\":%u,\"secs\":[",
           a->bin.has_clr, scan_has_avx2() ? 1 : 0, ana_undo_count(a), ana_redo_count(a),
           a->load_ms, a->ana_ms, a->nfunc, a->bin.nsym, a->nstr, a->nxref, a->nmark);
    for (uint32_t i = 0; i < a->bin.nsec; i++) {
        const bin_sec *s = &a->bin.secs[i];
        if (i) putchar(',');
        printf("{\"name\":");
        rpc_jstr(s->name);
        printf(",\"va\":\"0x%llx\",\"vsize\":%llu,\"fsize\":%llu,\"perm\":%u}",
               (unsigned long long)s->va, (unsigned long long)s->vsize,
               (unsigned long long)s->fsize, s->perm);
    }
    printf("]}\n");
}

static void rpc_emit_dis(const rpc_state *r, uint64_t va, int count) {
    const ana_ctx *a = &r->ana;
    if (count < 1) count = 40;
    if (count > 200) count = 200;

    printf("{\"ok\":true,\"rows\":[");
    uint64_t cur = va;
    x86_ins ins;
    int first = 1;

    for (int i = 0; i < count; i++) {
        const bin_sec *sec = bin_sec_at(&a->bin, cur);
        if (!sec) break;
        size_t avail = 0;
        const uint8_t *p = bin_ptr(&a->bin, cur, &avail);
        int ilen = 1;
        int is_code = (sec->perm & BIN_PERM_X) && p && avail > 0;
        if (is_code) {
            ilen = arch_decode(a->bin.arch, p, avail, cur, 1, r->opt.upper_mnem, &ins);
            if (ilen <= 0) ilen = 1;
        } else {
            memset(&ins, 0, sizeof(ins));
            ins.ip = cur;
            ins.len = 1;
            snprintf(ins.mnem, sizeof(ins.mnem), "db");
            uint8_t b = (p && avail > 0) ? p[0] : 0;
            snprintf(ins.ops, sizeof(ins.ops), "0x%02x", b);
        }

        char hex[48] = "";
        int hn = (p && avail > 0) ? (ilen < 12 ? ilen : 12) : 0;
        for (int k = 0; k < hn; k++) snprintf(hex + k * 3, sizeof(hex) - (size_t)(k * 3), "%02x ", p[k]);
        if (hn > 0) hex[hn * 3 - 1] = 0;

        const char *sym = ana_sym_at(a, cur);
        const char *cmt = ana_cmt_at(a, cur);
        const char *tsym = ins.has_target ? ana_sym_at(a, ins.target) : NULL;
        const ana_str *st = ins.has_target ? ana_str_at(a, ins.target) : NULL;
        char sbuf[80] = "";
        if (st) ana_read_str(a, st, sbuf, sizeof(sbuf));
        uint32_t xcnt = sym ? ana_xrefs_to(a, cur, NULL) : 0;

        if (!first) putchar(',');
        first = 0;
        printf("{\"va\":\"0x%llx\",\"len\":%d,\"flow\":%d,\"bytes\":",
               (unsigned long long)cur, ilen, ins.flow);
        rpc_jstr(hex);
        printf(",\"mnem\":");
        rpc_jstr(ins.mnem);
        printf(",\"ops\":");
        rpc_jstr(ins.ops);
        printf(",\"sec\":");
        rpc_jstr(sec->name);
        if (sym) { printf(",\"sym\":"); rpc_jstr(sym); printf(",\"xrefs\":%u", xcnt); }
        if (ins.has_target) {
            printf(",\"tgt\":\"0x%llx\",\"tmem\":%d", (unsigned long long)ins.target, ins.target_mem);
            if (tsym) { printf(",\"tsym\":"); rpc_jstr(tsym); }
            if (sbuf[0]) { printf(",\"tstr\":"); rpc_jstr(sbuf); }
        }
        if (cmt && cmt[0]) { printf(",\"cmt\":"); rpc_jstr(cmt); }
        putchar('}');

        uint64_t next = cur + (uint64_t)ilen;
        if (next >= sec->va + sec->vsize) next = ana_next_va(a, cur);
        if (next == cur) break;
        cur = next;
    }
    printf("],\"next\":\"0x%llx\"}\n", (unsigned long long)cur);
}

static void rpc_emit_cfg(const rpc_state *r, uint64_t va) {
    grp_cfg g = {0};
    if (!grp_build(&r->ana, va, r->opt.upper_mnem, &g)) {
        printf("{\"ok\":false,\"err\":\"no cfg\"}\n");
        return;
    }
    grp_layout(&g, 8, 20);
    const char *fn = ana_sym_at(&r->ana, g.func_va);

    printf("{\"ok\":true,\"func_va\":\"0x%llx\",\"name\":", (unsigned long long)g.func_va);
    rpc_jstr(fn ? fn : "");
    printf(",\"w\":%d,\"h\":%d,\"blks\":[", g.total_w, g.total_h);
    for (uint32_t i = 0; i < g.nblk; i++) {
        const grp_blk *b = &g.blks[i];
        if (i) putchar(',');
        const char *bs = ana_sym_at(&r->ana, b->start);
        printf("{\"start\":\"0x%llx\",\"end\":\"0x%llx\",\"x\":%d,\"y\":%d,\"w\":%d,\"h\":%d,\"sym\":",
               (unsigned long long)b->start, (unsigned long long)b->end, b->x, b->y, b->w, b->h);
        rpc_jstr(bs ? bs : "");
        printf(",\"ins\":[");
        for (uint32_t k = 0; k < b->ins_count; k++) {
            const x86_ins *in = &g.ins[b->ins_first + k];
            const char *ts = in->has_target ? ana_sym_at(&r->ana, in->target) : NULL;
            if (k) putchar(',');
            printf("{\"va\":\"0x%llx\",\"flow\":%d,\"mnem\":", (unsigned long long)in->ip, in->flow);
            rpc_jstr(in->mnem);
            printf(",\"ops\":");
            rpc_jstr(in->ops);
            if (in->has_target) {
                printf(",\"tgt\":\"0x%llx\",\"tmem\":%d", (unsigned long long)in->target, in->target_mem);
                if (ts) { printf(",\"tsym\":"); rpc_jstr(ts); }
            }
            putchar('}');
        }
        printf("]}");
    }
    printf("],\"edges\":[");
    for (uint32_t e = 0; e < g.nedge; e++) {
        if (e) putchar(',');
        printf("{\"from\":%u,\"to\":%u,\"kind\":%u,\"back\":%u}",
               g.edges[e].from, g.edges[e].to, g.edges[e].kind, g.edges[e].back);
    }
    putchar(']');
    if (g.truncated) {
        printf(",\"truncated\":true,\"orig_blks\":%u,\"orig_ins\":%u,"
               "\"warning\":\"CFG truncated at %u blocks / %u insns\"",
               g.orig_blks ? g.orig_blks : g.nblk,
               g.orig_ins ? g.orig_ins : g.nins,
               g.nblk, g.nins);
    }
    printf("}\n");
    grp_free(&g);
}

static void rpc_emit_dec(const rpc_state *r, uint64_t va) {
    dec_out d = {0};
    if (!dec_func_typed(&r->ana, &r->types, va, &d)) {
        printf("{\"ok\":false,\"err\":\"cannot decompile\"}\n");
        return;
    }
    const char *fn = ana_sym_at(&r->ana, d.func_va);
    printf("{\"ok\":true,\"func_va\":\"0x%llx\",\"name\":", (unsigned long long)d.func_va);
    rpc_jstr(fn ? fn : "");
    printf(",\"vars\":[");
    for (uint32_t i = 0; i < d.nvar; i++) {
        if (i) putchar(',');
        printf("{\"orig\":"); rpc_jstr(d.vars[i].orig);
        printf(",\"name\":"); rpc_jstr(d.vars[i].name);
        printf(",\"type\":"); rpc_jstr(d.vars[i].type);
        printf(",\"arg\":%d,\"bits\":%d,\"stack_off\":%lld}",
               d.vars[i].is_arg, d.vars[i].bits, (long long)d.vars[i].stack_off);
    }
    printf("],\"lines\":[");
    for (uint32_t i = 0; i < d.nline; i++) {
        if (i) putchar(',');
        printf("{\"va\":\"0x%llx\",\"text\":", (unsigned long long)d.lines[i].va);
        rpc_jstr(d.lines[i].text);
        putchar('}');
    }
    printf("]}\n");
    dec_free(&d);
}

static void rpc_emit_hex(const rpc_state *r, uint64_t va, int rows) {
    if (rows < 1) rows = 32;
    if (rows > 128) rows = 128;
    uint64_t base = va & ~15ULL;
    printf("{\"ok\":true,\"base\":\"0x%llx\",\"rows\":[", (unsigned long long)base);
    for (int i = 0; i < rows; i++) {
        uint64_t rva = base + (uint64_t)i * 16;
        uint8_t data[16];
        size_t got = bin_read(&r->ana.bin, rva, data, 16);
        char hex[48] = "";
        for (size_t k = 0; k < got; k++) snprintf(hex + k * 2, sizeof(hex) - k * 2, "%02x", data[k]);
        if (i) putchar(',');
        printf("{\"va\":\"0x%llx\",\"n\":%zu,\"hex\":\"%s\"}", (unsigned long long)rva, got, hex);
    }
    printf("]}\n");
}

static void rpc_emit_list(const rpc_state *r, const char *tab, const char *flt, uint32_t off, uint32_t lim) {
    if (lim == 0 || lim > 300) lim = 120;
    const ana_ctx *a = &r->ana;
    uint32_t matched = 0, sent = 0;
    printf("{\"ok\":true,\"items\":[");

    if (strcmp(tab, "funcs") == 0) {
        for (uint32_t i = 0; i < a->nfunc; i++) {
            const char *nm = ana_pool_str(a, a->funcs[i].name_off);
            if (!rpc_icontains(nm, flt)) continue;
            if (matched >= off && sent < lim) {
                if (sent) putchar(',');
                printf("{\"va\":\"0x%llx\",\"size\":%llu,\"name\":",
                       (unsigned long long)a->funcs[i].start,
                       (unsigned long long)(a->funcs[i].end - a->funcs[i].start));
                rpc_jstr(nm);
                putchar('}');
                sent++;
            }
            matched++;
        }
    } else if (strcmp(tab, "syms") == 0) {
        for (uint32_t i = 0; i < a->bin.nsym; i++) {
            const char *nm = bin_str(&a->bin, a->bin.syms[i].name_off);
            if (!rpc_icontains(nm, flt)) continue;
            if (matched >= off && sent < lim) {
                if (sent) putchar(',');
                printf("{\"va\":\"0x%llx\",\"kind\":%u,\"name\":",
                       (unsigned long long)a->bin.syms[i].va, a->bin.syms[i].kind);
                rpc_jstr(nm);
                putchar('}');
                sent++;
            }
            matched++;
        }
    } else if (strcmp(tab, "strs") == 0) {
        char sbuf[112];
        for (uint32_t i = 0; i < a->nstr; i++) {
            ana_read_str(a, &a->strs[i], sbuf, sizeof(sbuf));
            if (!rpc_icontains(sbuf, flt)) continue;
            if (matched >= off && sent < lim) {
                if (sent) putchar(',');
                printf("{\"va\":\"0x%llx\",\"wide\":%u,\"name\":",
                       (unsigned long long)a->strs[i].va, a->strs[i].wide);
                rpc_jstr(sbuf);
                putchar('}');
                sent++;
            }
            matched++;
        }
    } else if (strcmp(tab, "marks") == 0) {
        for (uint32_t i = 0; i < a->nmark; i++) {
            if (!rpc_icontains(a->marks[i].label, flt)) continue;
            if (matched >= off && sent < lim) {
                if (sent) putchar(',');
                printf("{\"va\":\"0x%llx\",\"name\":", (unsigned long long)a->marks[i].va);
                rpc_jstr(a->marks[i].label);
                putchar('}');
                sent++;
            }
            matched++;
        }
    }
    printf("],\"total\":%u}\n", matched);
}

static void rpc_emit_peek(const rpc_state *r, uint64_t va) {
    const ana_ctx *a = &r->ana;
    const bin_sec *s = bin_sec_at(&a->bin, va);
    if (!s) { printf("{\"ok\":false}\n"); return; }

    const ana_func *f = ana_func_at(a, va);
    const char *sym = ana_sym_at(a, va);
    const ana_str *st = ana_str_at(a, va);
    uint32_t xcnt = ana_xrefs_to(a, va, NULL);

    printf("{\"ok\":true,\"va\":\"0x%llx\",\"sec\":", (unsigned long long)va);
    rpc_jstr(s->name);
    printf(",\"sym\":");
    rpc_jstr(sym ? sym : (f ? ana_pool_str(a, f->name_off) : ""));
    printf(",\"fsize\":%llu,\"xrefs\":%u,\"exec\":%d",
           f ? (unsigned long long)(f->end - f->start) : 0ULL, xcnt, (s->perm & BIN_PERM_X) ? 1 : 0);

    if (st) {
        char sbuf[128];
        ana_read_str(a, st, sbuf, sizeof(sbuf));
        printf(",\"str\":");
        rpc_jstr(sbuf);
    }

    printf(",\"lines\":[");
    if (s->perm & BIN_PERM_X) {
        uint64_t cur = va;
        x86_ins ins;
        for (int i = 0; i < 10; i++) {
            size_t av = 0;
            const uint8_t *p = bin_ptr(&a->bin, cur, &av);
            if (!p || !av) break;
            int n = arch_decode(a->bin.arch, p, av, cur, 1, r->opt.upper_mnem, &ins);
            if (n <= 0) break;
            const char *ts = (ins.has_target && !ins.target_mem) ? ana_sym_at(a, ins.target) : NULL;
            if (i) putchar(',');
            printf("{\"va\":\"0x%llx\",\"flow\":%d,\"mnem\":", (unsigned long long)cur, ins.flow);
            rpc_jstr(ins.mnem);
            printf(",\"ops\":");
            rpc_jstr(ts ? ts : ins.ops);
            putchar('}');
            cur += (uint64_t)n;
            if (ins.flow == X86_FLOW_RET) break;
        }
    } else {
        uint8_t d[32];
        size_t got = bin_read(&a->bin, va, d, 32);
        char hex[96] = "";
        for (size_t i = 0; i < got; i++) snprintf(hex + i * 3, sizeof(hex) - i * 3, "%02x ", d[i]);
        printf("{\"va\":\"0x%llx\",\"flow\":0,\"mnem\":\"hex\",\"ops\":", (unsigned long long)va);
        rpc_jstr(hex);
        putchar('}');
    }
    printf("]}\n");
}

static void rpc_emit_xrefs(const rpc_state *r, uint64_t va) {
    uint32_t first = 0;
    uint32_t cnt = ana_xrefs_to(&r->ana, va, &first);
    printf("{\"ok\":true,\"va\":\"0x%llx\",\"total\":%u,\"items\":[", (unsigned long long)va, cnt);
    uint32_t lim = cnt < 200 ? cnt : 200;
    for (uint32_t i = 0; i < lim; i++) {
        const ana_xref *x = &r->ana.xrefs[first + i];
        const ana_func *f = ana_func_at(&r->ana, x->from);
        if (i) putchar(',');
        printf("{\"from\":\"0x%llx\",\"type\":%u,\"fn\":", (unsigned long long)x->from, x->type);
        rpc_jstr(f ? ana_pool_str(&r->ana, f->name_off) : "");
        putchar('}');
    }
    printf("]}\n");
}

static void rpc_emit_find(const rpc_state *r, const char *q) {
    size_t sz = (size_t)r->ana.bin.map.size;
    scan_pat pat;
    int is_pat = scan_pat_parse(&pat, q);
    printf("{\"ok\":true,\"hits\":[");
    size_t pos = 0, hits = 0;
    while (pos < sz && hits < 150) {
        size_t p = is_pat ? scan_pat_find(r->ana.bin.map.data, sz, pos, &pat)
                          : scan_text_find(r->ana.bin.map.data, sz, pos, q);
        if (p >= sz) break;
        uint64_t va = 0;
        int mapped = bin_off_to_va(&r->ana.bin, p, &va);
        const ana_func *f = mapped ? ana_func_at(&r->ana, va) : NULL;
        if (hits) putchar(',');
        printf("{\"va\":\"0x%llx\",\"off\":%zu,\"fn\":", (unsigned long long)(mapped ? va : 0), p);
        rpc_jstr(f ? ana_pool_str(&r->ana, f->name_off) : "");
        putchar('}');
        pos = p + 1;
        hits++;
    }
    printf("]}\n");
}

static void rpc_emit_inspect(const rpc_state *r, uint64_t va) {
    const ana_ctx *a = &r->ana;
    const bin_sec *s = bin_sec_at(&a->bin, va);
    if (!s) { printf("{\"ok\":false}\n"); return; }

    uint8_t raw[16] = {0};
    size_t got = bin_read(&a->bin, va, raw, 16);
    char hex[40] = "";
    for (size_t i = 0; i < got; i++) snprintf(hex + i * 2, sizeof(hex) - i * 2, "%02x", raw[i]);

    uint8_t ebuf[256];
    size_t en = bin_read(&a->bin, va, ebuf, sizeof(ebuf));
    double ent = ana_entropy(ebuf, en);

    const ana_func *f = ana_func_at(a, va);
    uint64_t foff = 0;
    int has_off = bin_va_to_off(&a->bin, va, &foff);
    uint32_t xcnt = ana_xrefs_to(a, va, NULL);

    printf("{\"ok\":true,\"va\":\"0x%llx\",\"off\":%llu,\"has_off\":%d,\"sec\":",
           (unsigned long long)va, (unsigned long long)foff, has_off);
    rpc_jstr(s->name);
    printf(",\"perm\":%u,\"n\":%zu,\"hex\":\"%s\",\"ent\":%.3f,\"xrefs\":%u,\"fn\":",
           s->perm, got, hex, ent, xcnt);
    rpc_jstr(f ? ana_pool_str(a, f->name_off) : "");
    printf(",\"fstart\":\"0x%llx\",\"fsize\":%llu}\n",
           f ? (unsigned long long)f->start : 0ULL,
           f ? (unsigned long long)(f->end - f->start) : 0ULL);
}

static void rpc_emit_callgraph(const rpc_state *r, uint64_t va) {
    const ana_ctx *a = &r->ana;
    const ana_func *fn = ana_func_at(a, va);
    uint64_t fva = fn ? fn->start : va;
    const char *fname = ana_sym_at(a, fva);

    printf("{\"ok\":true,\"va\":\"0x%llx\",\"name\":", (unsigned long long)fva);
    rpc_jstr(fname ? fname : "");
    printf(",\"callers\":[");

    uint64_t seen[64];
    int nseen = 0, first = 1;
    uint32_t xi = 0;
    uint32_t xcnt = ana_xrefs_to(a, fva, &xi);
    for (uint32_t i = 0; i < xcnt && nseen < 40; i++) {
        const ana_xref *x = &a->xrefs[xi + i];
        if (x->type != ANA_XREF_CALL && x->type != ANA_XREF_JMP) continue;
        const ana_func *cf = ana_func_at(a, x->from);
        uint64_t cva = cf ? cf->start : x->from;
        int dup = 0;
        for (int k = 0; k < nseen; k++) if (seen[k] == cva) dup = 1;
        if (dup) continue;
        seen[nseen++] = cva;
        if (!first) putchar(',');
        first = 0;
        const char *cn = cf ? ana_pool_str(a, cf->name_off) : ana_sym_at(a, cva);
        printf("{\"va\":\"0x%llx\",\"name\":", (unsigned long long)cva);
        rpc_jstr(cn ? cn : "");
        putchar('}');
    }

    printf("],\"callees\":[");
    nseen = 0; first = 1;
    grp_cfg g = {0};
    if (grp_build(a, fva, 0, &g)) {
        for (uint32_t i = 0; i < g.nins && nseen < 48; i++) {
            const x86_ins *in = &g.ins[i];
            if (in->flow != X86_FLOW_CALL || !in->has_target) continue;
            uint64_t tva = in->target;
            int dup = 0;
            for (int k = 0; k < nseen; k++) if (seen[k] == tva) dup = 1;
            if (dup) continue;
            seen[nseen++] = tva;
            if (!first) putchar(',');
            first = 0;
            const char *tn = ana_sym_at(a, tva);
            printf("{\"va\":\"0x%llx\",\"mem\":%d,\"name\":", (unsigned long long)tva, in->target_mem);
            rpc_jstr(tn ? tn : "");
            putchar('}');
        }
        grp_free(&g);
    }
    printf("]}\n");
}

static void rpc_emit_entropy_map(const rpc_state *r) {
    const ana_ctx *a = &r->ana;
    uint64_t sz = a->bin.map.size;
    printf("{\"ok\":true,\"bins\":[");
    int nb = 128;
    for (int i = 0; i < nb; i++) {
        uint64_t lo = (sz * (uint64_t)i) / (uint64_t)nb;
        uint64_t hi = (sz * (uint64_t)(i + 1)) / (uint64_t)nb;
        size_t span = (hi > lo) ? (size_t)(hi - lo) : 0;
        // cap bucket sample size
        if (span > 8192) span = 8192;
        double h = (span && a->bin.map.data) ? ana_entropy(a->bin.map.data + lo, span) : 0.0;
        if (i) putchar(',');
        printf("%.2f", h);
    }
    printf("],\"secs\":[");
    for (uint32_t i = 0; i < a->bin.nsec; i++) {
        const bin_sec *s = &a->bin.secs[i];
        size_t av = 0;
        const uint8_t *p = bin_ptr(&a->bin, s->va, &av);
        if (av > (2u << 20)) av = (2u << 20);
        double h = (p && av) ? ana_entropy(p, av) : 0.0;
        if (i) putchar(',');
        printf("{\"name\":");
        rpc_jstr(s->name);
        printf(",\"va\":\"0x%llx\",\"ent\":%.2f}", (unsigned long long)s->va, h);
    }
    printf("]}\n");
}

static void rpc_emit_patches(const rpc_state *r) {
    const ana_ctx *a = &r->ana;
    printf("{\"ok\":true,\"items\":[");
    for (uint32_t i = 0; i < a->npatch; i++) {
        if (i) putchar(',');
        printf("{\"va\":\"0x%llx\",\"orig\":%u,\"val\":%u}",
               (unsigned long long)a->patches[i].va, a->patches[i].orig, a->patches[i].val);
    }
    printf("]}\n");
}

static void rpc_emit_triage(const rpc_state *r) {
    tri_report *t = (tri_report *)calloc(1, sizeof(tri_report));
    if (!t) { printf("{\"ok\":false}\n"); return; }
    tri_analyze(&r->ana, t);
    printf("{\"ok\":true,\"verdict\":");
    rpc_jstr(t->verdict);
    printf(",\"packer\":");
    rpc_jstr(t->packer);
    printf(",\"compiler\":");
    rpc_jstr(t->compiler);
    printf(",\"pack_score\":%d,\"obf_score\":%d,\"max_ent\":%.2f,\"has_rwx\":%d,\"high_ent\":%d,\"ep_anom\":%d,\"sparse_imp\":%d,\"overlay\":%llu,\"notes\":[",
           t->pack_score, t->obf_score, t->max_ent, t->has_rwx, t->high_ent_exec, t->ep_anomaly, t->sparse_imp, (unsigned long long)t->overlay_size);
    for (int i = 0; i < t->nnote; i++) { if (i) putchar(','); rpc_jstr(t->notes[i]); }
    printf("],\"caps\":[");
    for (int i = 0; i < t->ncap; i++) {
        if (i) putchar(',');
        printf("{\"group\":");
        rpc_jstr(t->caps[i].group);
        printf(",\"items\":[");
        for (int k = 0; k < t->caps[i].count; k++) {
            if (k) putchar(',');
            printf("{\"name\":");
            rpc_jstr(t->caps[i].apis[k]);
            printf(",\"va\":\"0x%llx\"}", (unsigned long long)t->caps[i].vas[k]);
        }
        printf("]}");
    }
    printf("],\"spots\":[");
    for (int i = 0; i < t->nspot; i++) {
        if (i) putchar(',');
        printf("{\"va\":\"0x%llx\",\"kind\":", (unsigned long long)t->spots[i].va);
        rpc_jstr(t->spots[i].kind);
        printf(",\"name\":");
        rpc_jstr(t->spots[i].name);
        printf(",\"reason\":");
        rpc_jstr(t->spots[i].reason);
        printf(",\"score\":%d}", t->spots[i].score);
    }
    printf("]}\n");
    free(t);
}

static void rpc_emit_deobf(const rpc_state *r, uint64_t va) {
    dob_res *d = (dob_res *)calloc(1, sizeof(dob_res));
    if (!d) { printf("{\"ok\":false}\n"); return; }
    if (!dob_analyze(&r->ana, va, r->opt.upper_mnem, d)) {
        free(d);
        printf("{\"ok\":false}\n");
        return;
    }
    printf("{\"ok\":true,\"func_va\":\"0x%llx\",\"orig\":%d,\"clean\":%d,\"junk\":%d,\"opaque\":%d,\"folded\":%d,\"ind\":%d,\"strs\":[",
           (unsigned long long)d->func_va, d->orig_ins, d->clean_ins, d->junk_cut, d->opaque_cut, d->const_folded, d->ind_resolved);
    for (int i = 0; i < d->nstr; i++) {
        if (i) putchar(',');
        printf("{\"va\":\"0x%llx\",\"text\":", (unsigned long long)d->strs[i].va);
        rpc_jstr(d->strs[i].text);
        putchar('}');
    }
    printf("],\"rows\":[");
    for (int i = 0; i < d->nrow; i++) {
        if (i) putchar(',');
        printf("{\"va\":\"0x%llx\",\"flow\":%u,\"tag\":%u,\"mnem\":",
               (unsigned long long)d->rows[i].va, d->rows[i].flow, d->rows[i].tag);
        rpc_jstr(d->rows[i].mnem);
        printf(",\"ops\":");
        rpc_jstr(d->rows[i].ops);
        if (d->rows[i].note[0]) { printf(",\"note\":"); rpc_jstr(d->rows[i].note); }
        putchar('}');
    }
    printf("]}\n");
    free(d);
}

static void rpc_emit_emu(const rpc_state *r, uint64_t va, int steps) {
    emu_out *e = (emu_out *)calloc(1, sizeof(emu_out));
    if (!e) { printf("{\"ok\":false}\n"); return; }
    if (!emu_trace(&r->ana, va, steps, e)) {
        free(e);
        printf("{\"ok\":false}\n");
        return;
    }
    static const char *const rn[16] = {"rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi","r8","r9","r10","r11","r12","r13","r14","r15"};
    printf("{\"ok\":true,\"start\":\"0x%llx\",\"rip\":\"0x%llx\",\"zf\":%d,\"sf\":%d,\"cf\":%d,\"stop\":",
           (unsigned long long)e->start_va, (unsigned long long)e->rip, e->zf, e->sf, e->cf);
    rpc_jstr(e->stop_reason);
    printf(",\"stack_str\":");
    rpc_jstr(e->stack_ascii);
    printf(",\"regs\":{");
    for (int i = 0; i < 16; i++) {
        if (i) putchar(',');
        printf("\"%s\":\"0x%llx\"", rn[i], (unsigned long long)e->regs[i]);
    }
    printf("},\"steps\":[");
    for (int i = 0; i < e->nstep; i++) {
        if (i) putchar(',');
        printf("{\"va\":\"0x%llx\",\"text\":", (unsigned long long)e->steps[i].va);
        rpc_jstr(e->steps[i].text);
        printf(",\"eff\":");
        rpc_jstr(e->steps[i].effect);
        putchar('}');
    }
    printf("]}\n");
    free(e);
}

static void rpc_emit_ssa(const rpc_state *r, uint64_t va, const char *tier) {
    ssa_func f = {0};
    if (!ssa_build(&r->ana, va, &f)) { printf("{\"ok\":false}\n"); return; }
    int use_llir = (tier && strcmp(tier, "llir") == 0);
    const ssa_ins *arr = use_llir ? f.llir : f.mlir;
    uint32_t cnt = use_llir ? f.nllir : f.nmlir;
    printf("{\"ok\":true,\"func_va\":\"0x%llx\",\"tier\":\"%s\",\"proto\":",
           (unsigned long long)f.func_va, use_llir ? "llir" : "mlir");
    rpc_jstr(f.proto);
    printf(",\"nblk\":%u,\"nphi\":%d,\"nsccp\":%d,\"ngvn\":%d,\"ndce\":%d,\"blks\":[",
           f.nblk, f.nphi, f.nsccp, f.ngvn, f.ndce);
    for (uint32_t i = 0; i < f.nblk; i++) {
        if (i) putchar(',');
        printf("{\"start\":\"0x%llx\",\"end\":\"0x%llx\",\"idom\":%d}",
               (unsigned long long)f.blks[i].start, (unsigned long long)f.blks[i].end, f.blks[i].idom);
    }
    printf("],\"vars\":[");
    for (uint32_t i = 0; i < f.nvar && i < 128; i++) {
        if (i) putchar(',');
        printf("{\"name\":"); rpc_jstr(f.vars[i].name);
        printf(",\"type\":"); rpc_jstr(f.vars[i].type);
        printf(",\"arg\":%d,\"is_const\":%d,\"cval\":\"0x%llx\"}",
               f.vars[i].is_arg, f.vars[i].is_const, (unsigned long long)f.vars[i].cval);
    }
    printf("],\"ops\":[");
    uint32_t lim = cnt < 800 ? cnt : 800;
    for (uint32_t i = 0; i < lim; i++) {
        if (i) putchar(',');
        printf("{\"va\":\"0x%llx\",\"blk\":%u,\"phi\":%u,\"dead\":%u,\"dst\":",
               (unsigned long long)arr[i].va, arr[i].blk, arr[i].is_phi, arr[i].is_dead);
        rpc_jstr(arr[i].dst);
        printf(",\"type\":"); rpc_jstr(arr[i].type);
        printf(",\"text\":"); rpc_jstr(arr[i].text);
        putchar('}');
    }
    printf("]}\n");
    ssa_free(&f);
}

static void rpc_emit_lang(const rpc_state *r) {
    lang_info li = {0};
    lang_analyze(&r->ana, &li);
    printf("{\"ok\":true,\"runtime\":");
    rpc_jstr(li.runtime);
    printf(",\"classes\":[");
    uint32_t cl = li.nclass < 128 ? li.nclass : 128;
    for (uint32_t i = 0; i < cl; i++) {
        if (i) putchar(',');
        printf("{\"name\":"); rpc_jstr(li.classes[i].name);
        printf(",\"bases\":"); rpc_jstr(li.classes[i].bases);
        printf(",\"va\":\"0x%llx\",\"n\":%u,\"lang\":",
               (unsigned long long)li.classes[i].vtable_va, li.classes[i].nmethod);
        rpc_jstr(li.classes[i].lang);
        putchar('}');
    }
    printf("],\"go_funcs\":[");
    uint32_t gl = li.ngo_func < 200 ? li.ngo_func : 200;
    for (uint32_t i = 0; i < gl; i++) {
        if (i) putchar(',');
        printf("{\"va\":\"0x%llx\",\"name\":", (unsigned long long)li.go_funcs[i].va);
        rpc_jstr(li.go_funcs[i].name);
        putchar('}');
    }
    printf("],\"rust_srcs\":[");
    for (int i = 0; i < li.nrust_src; i++) {
        if (i) putchar(',');
        rpc_jstr(li.rust_srcs[i]);
    }
    printf("]}\n");
    lang_free(&li);
}

static void rpc_emit_cff(const rpc_state *r, uint64_t va) {
    cff_res *c = (cff_res *)calloc(1, sizeof(cff_res));
    if (!c || !cff_analyze(&r->ana, va, c)) { free(c); printf("{\"ok\":false}\n"); return; }
    printf("{\"ok\":true,\"func_va\":\"0x%llx\",\"detected\":%d,\"disp_va\":\"0x%llx\",\"state\":",
           (unsigned long long)c->func_va, c->detected, (unsigned long long)c->disp_va);
    rpc_jstr(c->state_var);
    printf(",\"orig_blks\":%d,\"real_blks\":%d,\"cut\":%d,\"edges\":[",
           c->orig_blks, c->real_blks, c->backbone_cut);
    for (int i = 0; i < c->nedge; i++) {
        if (i) putchar(',');
        printf("{\"from\":\"0x%llx\",\"to\":\"0x%llx\",\"state\":\"0x%llx\",\"kind\":%u}",
               (unsigned long long)c->edges[i].from_va, (unsigned long long)c->edges[i].to_va,
               (unsigned long long)c->edges[i].state_val, c->edges[i].kind);
    }
    printf("]}\n");
    free(c);
}

static void rpc_emit_mba_scan(const rpc_state *r, uint64_t va) {
    mba_res *m = (mba_res *)calloc(1, sizeof(mba_res));
    if (!m || !mba_scan_func(&r->ana, va, m)) { free(m); printf("{\"ok\":false}\n"); return; }
    printf("{\"ok\":true,\"func_va\":\"0x%llx\",\"hits\":[", (unsigned long long)m->func_va);
    for (int i = 0; i < m->nhit; i++) {
        if (i) putchar(',');
        printf("{\"va\":\"0x%llx\",\"orig\":", (unsigned long long)m->hits[i].va);
        rpc_jstr(m->hits[i].orig);
        printf(",\"simple\":");
        rpc_jstr(m->hits[i].simple);
        printf(",\"saved\":%d}", m->hits[i].ops_saved);
    }
    printf("]}\n");
    free(m);
}

static void rpc_emit_vm(const rpc_state *r, uint64_t va) {
    vm_res *v = (vm_res *)calloc(1, sizeof(vm_res));
    if (!v || !vm_analyze(&r->ana, va, v)) { free(v); printf("{\"ok\":false}\n"); return; }
    printf("{\"ok\":true,\"func_va\":\"0x%llx\",\"detected\":%d,\"disp_va\":\"0x%llx\",\"table_va\":\"0x%llx\",\"vip\":",
           (unsigned long long)v->func_va, v->detected, (unsigned long long)v->disp_va, (unsigned long long)v->table_va);
    rpc_jstr(v->vip_reg);
    printf(",\"vsp\":"); rpc_jstr(v->vsp_reg);
    printf(",\"style\":"); rpc_jstr(v->style);
    printf(",\"handlers\":[");
    for (int i = 0; i < v->nhandler; i++) {
        if (i) putchar(',');
        printf("{\"op\":%u,\"va\":\"0x%llx\",\"nins\":%d,\"kind\":",
               v->handlers[i].opcode, (unsigned long long)v->handlers[i].va, v->handlers[i].nins);
        rpc_jstr(v->handlers[i].kind);
        printf(",\"sem\":"); rpc_jstr(v->handlers[i].sem);
        putchar('}');
    }
    printf("],\"trace\":[");
    for (int i = 0; i < v->ntrace; i++) {
        if (i) putchar(',');
        printf("{\"va\":\"0x%llx\",\"op\":", (unsigned long long)v->trace[i].va);
        rpc_jstr(v->trace[i].op);
        printf(",\"detail\":"); rpc_jstr(v->trace[i].detail);
        putchar('}');
    }
    printf("]}\n");
    free(v);
}

static void rpc_emit_unp_hashes(rpc_state *r, int apply) {
    unp_hash_res *h = (unp_hash_res *)calloc(1, sizeof(unp_hash_res));
    if (!h) { printf("{\"ok\":false}\n"); return; }
    unp_resolve_hashes(&r->ana, apply, h);
    printf("{\"ok\":true,\"hits\":[");
    for (int i = 0; i < h->nhit; i++) {
        if (i) putchar(',');
        printf("{\"va\":\"0x%llx\",\"hash\":\"0x%08x\",\"algo\":",
               (unsigned long long)h->hits[i].va, h->hits[i].hash);
        rpc_jstr(h->hits[i].algo);
        printf(",\"api\":"); rpc_jstr(h->hits[i].api);
        putchar('}');
    }
    printf("]}\n");
    free(h);
}

static void rpc_emit_unp_strs(rpc_state *r, uint64_t va, int apply) {
    unp_str_res *s = (unp_str_res *)calloc(1, sizeof(unp_str_res));
    if (!s) { printf("{\"ok\":false}\n"); return; }
    unp_decrypt_strings(&r->ana, va, apply, s);
    printf("{\"ok\":true,\"hits\":[");
    for (int i = 0; i < s->nhit; i++) {
        if (i) putchar(',');
        printf("{\"va\":\"0x%llx\",\"key\":\"0x%x\",\"method\":",
               (unsigned long long)s->hits[i].va, s->hits[i].key);
        rpc_jstr(s->hits[i].method);
        printf(",\"text\":"); rpc_jstr(s->hits[i].text);
        putchar('}');
    }
    printf("]}\n");
    free(s);
}

static void rpc_emit_unp_rebuild(rpc_state *r, uint64_t base_va, uint64_t oep_va, const char *out_path) {
    unp_pe_res res = {0};
    uint8_t *img = NULL;
    size_t img_sz = 0;

    if (r->dbg.attached) {
        if (!base_va) {
            dbg_mod mods[8];
            if (dbg_list_mods(&r->dbg, mods, 8) > 0) base_va = mods[0].base;
        }
        uint8_t hdr[4096];
        size_t got = dbg_read_mem(&r->dbg, base_va, hdr, sizeof(hdr));
        if (got >= 0x200 && hdr[0] == 'M' && hdr[1] == 'Z') {
            uint32_t pe_off = 0;
            memcpy(&pe_off, hdr + 0x3C, 4);
            if (pe_off + 0x58 <= got && memcmp(hdr + pe_off, "PE\0\0", 4) == 0) {
                uint32_t soi = 0;
                memcpy(&soi, hdr + pe_off + 0x50, 4);
                if (soi >= 0x1000 && soi <= (64u << 20)) {
                    img = (uint8_t *)calloc(1, soi);
                    if (img) {
                        img_sz = soi;
                        // read page-by-page so unmapped guard holes do not abort dump
                        for (size_t off = 0; off < img_sz; off += 4096) {
                            size_t chunk = (img_sz - off < 4096) ? (img_sz - off) : 4096;
                            dbg_read_mem(&r->dbg, base_va + off, img + off, chunk);
                        }
                    }
                }
            }
        }
    } else if (r->ana.bin.map.data && r->ana.bin.map.size >= 0x200) {
        if (!base_va) base_va = r->ana.bin.base;
        if (!oep_va) oep_va = r->ana.bin.entry;
        uint64_t span = (r->ana.bin.max_va > base_va) ? (r->ana.bin.max_va - base_va) : 0;
        if (span >= 0x1000 && span <= (64u << 20)) {
            img = (uint8_t *)calloc(1, (size_t)span);
            if (img) {
                img_sz = (size_t)span;
                size_t hsz = r->ana.bin.map.size < 0x1000 ? (size_t)r->ana.bin.map.size : 0x1000;
                memcpy(img, r->ana.bin.map.data, hsz);
                for (uint32_t i = 0; i < r->ana.bin.nsec; i++) {
                    const bin_sec *s = &r->ana.bin.secs[i];
                    if (s->va < base_va) continue;
                    uint64_t rva = s->va - base_va;
                    if (rva >= img_sz) continue;
                    size_t avail = 0;
                    const uint8_t *p = bin_ptr(&r->ana.bin, s->va, &avail);
                    if (p && avail) {
                        if (rva + avail > img_sz) avail = img_sz - (size_t)rva;
                        memcpy(img + rva, p, avail);
                    }
                }
            }
        }
    }

    bool ok = img && unp_rebuild_pe_mem(img, img_sz, base_va, oep_va, out_path, &res);
    free(img);
    printf("{\"ok\":%s,\"nsec\":%u,\"nimp\":%u,\"size\":%llu,\"err\":",
           ok ? "true" : "false", res.nsec, res.nimp, (unsigned long long)res.out_size);
    rpc_jstr(ok ? "" : (res.err[0] ? res.err : "no pe image"));
    printf("}\n");
}

static void rpc_emit_ir(const rpc_state *r, uint64_t va) {
    ir_func *f = (ir_func *)calloc(1, sizeof(ir_func));
    if (!f || !ir_lift_func(&r->ana, va, f)) { free(f); printf("{\"ok\":false}\n"); return; }
    printf("{\"ok\":true,\"func_va\":\"0x%llx\",\"nconst\":%d,\"ndce\":%d,\"ops\":[",
           (unsigned long long)f->func_va, f->nconst, f->ndce);
    for (int i = 0; i < f->nop; i++) {
        if (i) putchar(',');
        printf("{\"va\":\"0x%llx\",\"text\":", (unsigned long long)f->ops[i].va);
        rpc_jstr(f->ops[i].text);
        putchar('}');
    }
    printf("],\"structs\":[");
    for (int s = 0; s < f->nstruct; s++) {
        if (s) putchar(',');
        printf("{\"name\":");
        rpc_jstr(f->structs[s].name);
        printf(",\"fields\":[");
        for (int k = 0; k < f->structs[s].nfield; k++) {
            if (k) putchar(',');
            printf("{\"off\":%d,\"size\":%d,\"name\":", f->structs[s].fields[k].off, f->structs[s].fields[k].size);
            rpc_jstr(f->structs[s].fields[k].name);
            printf(",\"type\":");
            rpc_jstr(f->structs[s].fields[k].type);
            putchar('}');
        }
        printf("]}");
    }
    printf("]}\n");
    free(f);
}

static void rpc_emit_vtables(const rpc_state *r) {
    ir_vtable vts[64];
    int n = ir_scan_vtables(&r->ana, vts, 64);
    printf("{\"ok\":true,\"items\":[");
    for (int i = 0; i < n; i++) {
        if (i) putchar(',');
        printf("{\"va\":\"0x%llx\",\"n\":%u,\"cls\":", (unsigned long long)vts[i].va, vts[i].nentry);
        rpc_jstr(vts[i].cls);
        putchar('}');
    }
    printf("]}\n");
}

static void rpc_emit_switches(const rpc_state *r, uint64_t va) {
    ir_switch sw[16];
    int n = ir_scan_switches(&r->ana, va, sw, 16);
    printf("{\"ok\":true,\"items\":[");
    for (int i = 0; i < n; i++) {
        if (i) putchar(',');
        printf("{\"va\":\"0x%llx\",\"table\":\"0x%llx\",\"cases\":%u}",
               (unsigned long long)sw[i].va, (unsigned long long)sw[i].table_va, sw[i].ncases);
    }
    printf("]}\n");
}

static void rpc_emit_crypto(const rpc_state *r) {
    sig_crypto out[64];
    int n = sig_find_crypto(&r->ana, out, 64);
    printf("{\"ok\":true,\"items\":[");
    for (int i = 0; i < n; i++) {
        if (i) putchar(',');
        printf("{\"va\":\"0x%llx\",\"algo\":", (unsigned long long)out[i].va);
        rpc_jstr(out[i].algo);
        printf(",\"detail\":");
        rpc_jstr(out[i].detail);
        putchar('}');
    }
    printf("]}\n");
}

static void rpc_emit_diff(rpc_state *r, const char *other) {
    ana_free(&r->diff_ana);
    ana_init(&r->diff_ana);
    r->has_diff = 0;
    if (!ana_open(&r->diff_ana, other, 0, 64)) {
        printf("{\"ok\":false,\"err\":\"failed to open second binary\"}\n");
        return;
    }
    ana_run(&r->diff_ana, r->opt.threads, r->opt.min_str, r->opt.max_ana_mb);
    r->has_diff = 1;

    dif_res res = {0};
    if (!dif_compare(&r->ana, &r->diff_ana, &res)) {
        printf("{\"ok\":false,\"err\":\"diff failed\"}\n");
        return;
    }
    printf("{\"ok\":true,\"same\":%u,\"mod\":%u,\"add\":%u,\"del\":%u,\"items\":[",
           res.same, res.mod, res.add, res.del);
    uint32_t lim = res.nitem < 300 ? res.nitem : 300;
    for (uint32_t i = 0; i < lim; i++) {
        const dif_item *it = &res.items[i];
        if (i) putchar(',');
        printf("{\"va_a\":\"0x%llx\",\"va_b\":\"0x%llx\",\"kind\":%u,\"sim\":%d,\"sa\":%u,\"sb\":%u,\"name\":",
               (unsigned long long)it->va_a, (unsigned long long)it->va_b,
               it->kind, it->sim, it->size_a, it->size_b);
        rpc_jstr(it->name);
        putchar('}');
    }
    printf("]}\n");
    dif_free(&res);
}

static void rpc_emit_path(const rpc_state *r, uint64_t a_va, uint64_t b_va) {
    pth_chain ch = {0};
    if (!pth_find(&r->ana, a_va, b_va, &ch)) {
        printf("{\"ok\":false,\"err\":\"no call path\"}\n");
        return;
    }
    printf("{\"ok\":true,\"steps\":[");
    for (int i = 0; i < ch.len; i++) {
        if (i) putchar(',');
        printf("{\"va\":\"0x%llx\",\"name\":", (unsigned long long)ch.vas[i]);
        rpc_jstr(ch.names[i]);
        putchar('}');
    }
    printf("]}\n");
}

static void rpc_emit_xgraph(const rpc_state *r, uint64_t va, int depth) {
    pth_xgraph *g = (pth_xgraph *)calloc(1, sizeof(pth_xgraph));
    if (!g || !pth_xgraph_build(&r->ana, va, depth, g)) { free(g); printf("{\"ok\":false}\n"); return; }
    printf("{\"ok\":true,\"nodes\":[");
    for (int i = 0; i < g->nnode; i++) {
        if (i) putchar(',');
        printf("{\"va\":\"0x%llx\",\"depth\":%d,\"name\":", (unsigned long long)g->nodes[i].va, g->nodes[i].depth);
        rpc_jstr(g->nodes[i].name);
        putchar('}');
    }
    printf("],\"edges\":[");
    for (int i = 0; i < g->nedge; i++) {
        if (i) putchar(',');
        printf("{\"from\":%d,\"to\":%d,\"type\":%d}", g->edges[i].from, g->edges[i].to, g->edges[i].type);
    }
    printf("]}\n");
    free(g);
}

static void rpc_emit_dotnet(const rpc_state *r) {
    bc_clr_info *ci = (bc_clr_info *)calloc(1, sizeof(bc_clr_info));
    if (!ci || !bc_inspect_dotnet(&r->ana.bin, ci)) { free(ci); printf("{\"ok\":false}\n"); return; }
    printf("{\"ok\":true,\"ver\":"); rpc_jstr(ci->runtime_ver);
    printf(",\"entry_token\":\"0x%08x\",\"types\":[", ci->entry_token);
    for (int i = 0; i < ci->ntype; i++) {
        if (i) putchar(',');
        printf("{\"ns\":"); rpc_jstr(ci->types[i].ns);
        printf(",\"name\":"); rpc_jstr(ci->types[i].name);
        printf(",\"flags\":%u}", ci->types[i].flags);
    }
    printf("],\"methods\":[");
    for (int i = 0; i < ci->nmethod; i++) {
        if (i) putchar(',');
        printf("{\"name\":"); rpc_jstr(ci->methods[i].name);
        printf(",\"va\":\"0x%llx\",\"rva\":\"0x%x\",\"flags\":%u}",
               (unsigned long long)ci->methods[i].va, ci->methods[i].rva, ci->methods[i].flags);
    }
    printf("],\"strings\":[");
    for (int i = 0; i < ci->nstr; i++) {
        if (i) putchar(',');
        rpc_jstr(ci->strings[i]);
    }
    printf("]}\n");
    free(ci);
}

static void rpc_emit_struct_apply(const rpc_state *r, const char *name, uint64_t va) {
    const typ_def *d = typ_find(&r->types, name);
    if (!d || d->size <= 0) { printf("{\"ok\":false,\"err\":\"unknown type\"}\n"); return; }
    size_t sz = (size_t)d->size;
    if (sz > 4096) sz = 4096;
    uint8_t *buf = (uint8_t *)calloc(1, sz);
    if (!buf) { printf("{\"ok\":false}\n"); return; }
    size_t got = r->dbg.attached ? dbg_read_mem(&r->dbg, va, buf, sz) : bin_read(&r->ana.bin, va, buf, sz);
    // allow inspecting PE/ELF headers at image base
    if (!r->dbg.attached && got == 0 && r->ana.bin.map.data && va >= r->ana.bin.base && va - r->ana.bin.base < r->ana.bin.map.size) {
        size_t off = (size_t)(va - r->ana.bin.base);
        size_t av = (size_t)r->ana.bin.map.size - off;
        got = sz < av ? sz : av;
        memcpy(buf, r->ana.bin.map.data + off, got);
    }
    printf("{\"ok\":true,\"name\":"); rpc_jstr(d->name);
    printf(",\"va\":\"0x%llx\",\"size\":%d,\"got\":%zu,\"live\":%d,\"fields\":[",
           (unsigned long long)va, d->size, got, r->dbg.attached);
    for (int k = 0; k < d->nmem; k++) {
        const typ_member *m = &d->mems[k];
        uint64_t uval = 0;
        char hex[36] = "", preview[64] = "";
        int msz = m->size;
        if (m->off >= 0 && (size_t)m->off < got) {
            size_t av = got - (size_t)m->off;
            size_t cn = (size_t)msz < av ? (size_t)msz : av;
            size_t hn = cn < 16 ? cn : 16;
            for (size_t i = 0; i < hn; i++) snprintf(hex + i * 2, sizeof(hex) - i * 2, "%02x", buf[m->off + i]);
            if (cn == 1) uval = buf[m->off];
            else if (cn == 2) { uint16_t v; memcpy(&v, buf + m->off, 2); uval = v; }
            else if (cn == 4) { uint32_t v; memcpy(&v, buf + m->off, 4); uval = v; }
            else if (cn >= 8) { memcpy(&uval, buf + m->off, 8); }
            if (strchr(m->type, '*') && uval >= 0x10000ULL) {
                uint8_t pb[48] = {0};
                size_t pn = r->dbg.attached ? dbg_read_mem(&r->dbg, uval, pb, 44) : bin_read(&r->ana.bin, uval, pb, 44);
                size_t pi = 0;
                while (pi < pn && pb[pi] >= 0x20 && pb[pi] <= 0x7E) { preview[pi] = (char)pb[pi]; pi++; }
                if (pi < 3) preview[0] = 0;
                else preview[pi] = 0;
            } else if (strstr(m->type, "char") && cn >= 2) {
                size_t pi = 0, lim = cn < 48 ? cn : 48;
                while (pi < lim && buf[m->off + pi] >= 0x20 && buf[m->off + pi] <= 0x7E) { preview[pi] = (char)buf[m->off + pi]; pi++; }
                preview[pi] = 0;
            }
        }
        if (k) putchar(',');
        printf("{\"off\":%d,\"size\":%d,\"name\":", m->off, m->size);
        rpc_jstr(m->name);
        printf(",\"type\":"); rpc_jstr(m->type);
        printf(",\"val\":\"0x%llx\",\"hex\":\"%s\",\"preview\":", (unsigned long long)uval, hex);
        rpc_jstr(preview);
        putchar('}');
    }
    printf("]}\n");
    free(buf);
}

static void rpc_emit_types(const rpc_state *r) {
    printf("{\"ok\":true,\"items\":[");
    for (uint32_t i = 0; i < r->types.ndef; i++) {
        const typ_def *d = &r->types.defs[i];
        if (i) putchar(',');
        printf("{\"name\":");
        rpc_jstr(d->name);
        printf(",\"kind\":%d,\"size\":%d,\"mems\":[", d->kind, d->size);
        for (int k = 0; k < d->nmem; k++) {
            if (k) putchar(',');
            printf("{\"off\":%d,\"size\":%d,\"name\":", d->mems[k].off, d->mems[k].size);
            rpc_jstr(d->mems[k].name);
            printf(",\"type\":");
            rpc_jstr(d->mems[k].type);
            putchar('}');
        }
        printf("]}");
    }
    printf("]}\n");
}

static void rpc_emit_dbg_state(const rpc_state *r, int snap_idx) {
    static const char *const rn[16] = {"rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi","r8","r9","r10","r11","r12","r13","r14","r15"};
    const dbg_snap *sn = dbg_get_snap(&r->dbg, snap_idx);
    printf("{\"ok\":true,\"attached\":%d,\"paused\":%d,\"pid\":%u,\"tid\":%u,\"nsnap\":%d,\"cur\":%d,\"nttd\":%d,\"ttd_cur\":%d,\"err\":",
           r->dbg.attached, r->dbg.paused, r->dbg.pid, r->dbg.tid, r->dbg.nsnap,
           snap_idx < 0 ? r->dbg.cur_snap : snap_idx, r->dbg.nttd, r->dbg.ttd_cur);
    rpc_jstr(r->dbg.last_err);
    printf(",\"bps\":[");
    for (int i = 0; i < r->dbg.nbp; i++) {
        if (i) putchar(',');
        printf("{\"va\":\"0x%llx\",\"active\":%d,\"cond\":", (unsigned long long)r->dbg.bps[i].va, r->dbg.bps[i].active);
        rpc_jstr(r->dbg.bps[i].cond);
        putchar('}');
    }
    printf("],\"hwbps\":[");
    for (int i = 0; i < DBG_MAX_HWBP; i++) {
        if (i) putchar(',');
        printf("{\"slot\":%d,\"va\":\"0x%llx\",\"kind\":%u,\"size\":%u,\"active\":%d}",
               i, (unsigned long long)r->dbg.hwbps[i].va, r->dbg.hwbps[i].kind, r->dbg.hwbps[i].size, r->dbg.hwbps[i].active);
    }
    printf("],\"membps\":[");
    for (int i = 0; i < r->dbg.nmembp; i++) {
        if (i) putchar(',');
        printf("{\"va\":\"0x%llx\",\"size\":%u,\"active\":%d}",
               (unsigned long long)r->dbg.membps[i].va, r->dbg.membps[i].size, r->dbg.membps[i].active);
    }
    printf("]");
    if (sn) {
        printf(",\"snap\":{\"rip\":\"0x%llx\",\"rflags\":\"0x%llx\",\"tid\":%u,\"event\":",
               (unsigned long long)sn->rip, (unsigned long long)sn->rflags, sn->tid);
        rpc_jstr(sn->event);
        printf(",\"regs\":{");
        for (int i = 0; i < 16; i++) {
            if (i) putchar(',');
            printf("\"%s\":\"0x%llx\"", rn[i], (unsigned long long)sn->regs[i]);
        }
        printf("},\"stack\":\"");
        for (int i = 0; i < 64; i++) printf("%02x", sn->stack[i]);
        printf("\"}");
    }
    printf("}\n");
}

static void rpc_emit_gdb_state(const rpc_state *r) {
    static const char *const rn[16] = {"rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi","r8","r9","r10","r11","r12","r13","r14","r15"};
    printf("{\"ok\":%s,\"connected\":%d,\"host\":", r->gdb.connected ? "true" : "false", r->gdb.connected);
    rpc_jstr(r->gdb.host);
    printf(",\"port\":%u,\"rip\":\"0x%llx\",\"rflags\":\"0x%llx\",\"stop\":",
           r->gdb.port, (unsigned long long)r->gdb.rip, (unsigned long long)r->gdb.rflags);
    rpc_jstr(r->gdb.stop_sig);
    printf(",\"err\":"); rpc_jstr(r->gdb.last_err);
    printf(",\"regs\":{");
    for (int i = 0; i < 16; i++) {
        if (i) putchar(',');
        printf("\"%s\":\"0x%llx\"", rn[i], (unsigned long long)r->gdb.regs[i]);
    }
    printf("}}\n");
}

static void rpc_emit_dmp_state(const rpc_state *r) {
    static const char *const rn[16] = {"rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi","r8","r9","r10","r11","r12","r13","r14","r15"};
    const dmp_ctx *m = &r->dmp;
    printf("{\"ok\":%s,\"loaded\":%d,\"path\":", m->loaded ? "true" : "false", m->loaded);
    rpc_jstr(m->path);
    printf(",\"arch\":%u,\"ncpu\":%u,\"os\":\"%u.%u.%u\",\"exc_tid\":%u,\"exc_code\":\"0x%08x\",\"exc_addr\":\"0x%llx\",\"err\":",
           m->arch, m->ncpu, m->os_major, m->os_minor, m->os_build, m->exc_tid, m->exc_code, (unsigned long long)m->exc_addr);
    rpc_jstr(m->last_err);
    printf(",\"mods\":[");
    uint32_t nm = m->nmod < 128 ? m->nmod : 128;
    for (uint32_t i = 0; i < nm; i++) {
        if (i) putchar(',');
        printf("{\"base\":\"0x%llx\",\"size\":%u,\"name\":", (unsigned long long)m->mods[i].base, m->mods[i].size);
        rpc_jstr(m->mods[i].name);
        putchar('}');
    }
    printf("],\"threads\":[");
    uint32_t nt = m->nthread < 32 ? m->nthread : 32;
    for (uint32_t i = 0; i < nt; i++) {
        if (i) putchar(',');
        printf("{\"tid\":%u,\"rip\":\"0x%llx\",\"rsp\":\"0x%llx\",\"rflags\":\"0x%llx\",\"regs\":{",
               m->threads[i].tid, (unsigned long long)m->threads[i].rip,
               (unsigned long long)m->threads[i].rsp, (unsigned long long)m->threads[i].rflags);
        for (int k = 0; k < 16; k++) {
            if (k) putchar(',');
            printf("\"%s\":\"0x%llx\"", rn[k], (unsigned long long)m->threads[i].regs[k]);
        }
        printf("}}");
    }
    printf("],\"nmem\":%u}\n", m->nmem);
}

static void rpc_emit_taint(const rpc_state *r, uint64_t va, int src_reg, uint32_t buf_len, int steps) {
    static const char *const rn[16] = {"rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi","r8","r9","r10","r11","r12","r13","r14","r15"};
    tnt_res *t = (tnt_res *)calloc(1, sizeof(tnt_res));
    if (!t || !tnt_run(&r->ana, va, src_reg, buf_len, steps, t)) { free(t); printf("{\"ok\":false}\n"); return; }
    printf("{\"ok\":true,\"start\":\"0x%llx\",\"nstep\":%d,\"taint_mask\":%u,\"taint_bytes\":%d,\"shims\":%d,\"stop\":",
           (unsigned long long)t->start_va, t->nstep, t->taint_regs, t->taint_bytes, t->shim_calls);
    rpc_jstr(t->stop_reason);
    printf(",\"tainted_regs\":[");
    int first = 1;
    for (int i = 0; i < 16; i++) {
        if (!(t->taint_regs & (1u << i))) continue;
        if (!first) putchar(',');
        first = 0;
        rpc_jstr(rn[i]);
    }
    printf("],\"regs\":{");
    for (int i = 0; i < 16; i++) {
        if (i) putchar(',');
        printf("\"%s\":\"0x%llx\"", rn[i], (unsigned long long)t->regs[i]);
    }
    printf("},\"events\":[");
    for (int i = 0; i < t->nevent; i++) {
        if (i) putchar(',');
        printf("{\"va\":\"0x%llx\",\"mask\":%u,\"kind\":", (unsigned long long)t->events[i].va, t->events[i].reg_mask);
        rpc_jstr(t->events[i].kind);
        printf(",\"detail\":"); rpc_jstr(t->events[i].detail);
        putchar('}');
    }
    printf("]}\n");
    free(t);
}

static void rpc_emit_sym_solve(const rpc_state *r, uint64_t start_va, uint64_t target_va) {
    tnt_solve_res *s = (tnt_solve_res *)calloc(1, sizeof(tnt_solve_res));
    if (!s || !tnt_solve_path(&r->ana, start_va, target_va, s)) { free(s); printf("{\"ok\":false}\n"); return; }
    printf("{\"ok\":true,\"reachable\":%d,\"summary\":", s->reachable);
    rpc_jstr(s->summary);
    printf(",\"path\":[");
    for (int i = 0; i < s->npath; i++) {
        if (i) putchar(',');
        printf("\"0x%llx\"", (unsigned long long)s->path[i]);
    }
    printf("],\"constraints\":[");
    for (int i = 0; i < s->ncons; i++) {
        if (i) putchar(',');
        rpc_jstr(s->constraints[i]);
    }
    printf("],\"witness\":[");
    for (int i = 0; i < s->nwitness; i++) {
        if (i) putchar(',');
        printf("{\"var\":"); rpc_jstr(s->witness[i].var);
        printf(",\"val\":\"0x%llx\",\"expr\":", (unsigned long long)s->witness[i].val);
        rpc_jstr(s->witness[i].expr);
        putchar('}');
    }
    printf("]}\n");
    free(s);
}

static int rpc_reg_index(const char *name) {
    static const char *const rn[16] = {"rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi","r8","r9","r10","r11","r12","r13","r14","r15"};
    if (!name || !name[0]) return -1;
    if ((name[0] == 'x' || name[0] == 'w') && isdigit((unsigned char)name[1])) {
        int idx = atoi(name + 1);
        return (idx >= 0 && idx < 16) ? idx : -1;
    }
    for (int i = 0; i < 16; i++) if (strcmp(name, rn[i]) == 0) return i;
    return -1;
}

static int rpc_patch_hex(ana_ctx *a, uint64_t va, const char *hex) {
    int cnt = 0;
    const char *p = hex;
    while (*p) {
        while (*p == ' ' || *p == '\t' || *p == ',') p++;
        if (!*p) break;
        unsigned int v = 0;
        int used = 0;
        if (sscanf(p, "%2x%n", &v, &used) != 1 || used == 0) break;
        if (!ana_patch_byte(a, va + (uint64_t)cnt, (uint8_t)v)) break;
        cnt++;
        p += used;
    }
    return cnt;
}

static void rpc_emit_yara(const rpc_state *r, const char *rules) {
    for_yara_res *yr = (for_yara_res *)calloc(1, sizeof(for_yara_res));
    if (!yr) { printf("{\"ok\":false,\"err\":\"oom\"}\n"); return; }
    const char *src = (rules && rules[0]) ? rules : for_yara_default_rules();
    bool ok = for_yara_scan(&r->ana, src, yr);
    printf("{\"ok\":%s,\"nrules\":%d,\"err\":", ok ? "true" : "false", yr->nrules);
    rpc_jstr(yr->err);
    printf(",\"hits\":[");
    for (int i = 0; i < yr->nhit; i++) {
        if (i) putchar(',');
        printf("{\"rule\":"); rpc_jstr(yr->hits[i].rule);
        printf(",\"desc\":"); rpc_jstr(yr->hits[i].desc);
        printf(",\"id\":"); rpc_jstr(yr->hits[i].match_id);
        printf(",\"va\":\"0x%llx\",\"off\":%llu,\"nmatch\":%d}",
               (unsigned long long)yr->hits[i].va, (unsigned long long)yr->hits[i].off, yr->hits[i].nmatch);
    }
    printf("]}\n");
    free(yr);
}

static void rpc_emit_carve(const rpc_state *r) {
    for_carve_res *cr = (for_carve_res *)calloc(1, sizeof(for_carve_res));
    if (!cr) { printf("{\"ok\":false}\n"); return; }
    for_carve(&r->ana, cr);
    printf("{\"ok\":true,\"items\":[");
    for (int i = 0; i < cr->nhit; i++) {
        if (i) putchar(',');
        printf("{\"kind\":"); rpc_jstr(cr->hits[i].kind);
        printf(",\"off\":%llu,\"va\":\"0x%llx\",\"size\":%llu,\"ent\":%.2f,\"detail\":",
               (unsigned long long)cr->hits[i].off, (unsigned long long)cr->hits[i].va,
               (unsigned long long)cr->hits[i].size, cr->hits[i].ent);
        rpc_jstr(cr->hits[i].detail);
        putchar('}');
    }
    printf("]}\n");
    free(cr);
}

static void rpc_emit_iocs(const rpc_state *r) {
    for_ioc_res *ir = (for_ioc_res *)calloc(1, sizeof(for_ioc_res));
    if (!ir) { printf("{\"ok\":false}\n"); return; }
    for_extract_iocs(&r->ana, ir);
    printf("{\"ok\":true,\"items\":[");
    for (int i = 0; i < ir->nhit; i++) {
        if (i) putchar(',');
        printf("{\"kind\":"); rpc_jstr(ir->hits[i].kind);
        printf(",\"va\":\"0x%llx\",\"value\":", (unsigned long long)ir->hits[i].va);
        rpc_jstr(ir->hits[i].value);
        putchar('}');
    }
    printf("]}\n");
    free(ir);
}

static void rpc_emit_vuln(const rpc_state *r) {
    vln_res *vr = (vln_res *)calloc(1, sizeof(vln_res));
    if (!vr) { printf("{\"ok\":false}\n"); return; }
    vln_scan(&r->ana, vr);
    printf("{\"ok\":true,\"nhigh\":%d,\"nmed\":%d,\"items\":[", vr->nhigh, vr->nmed);
    for (int i = 0; i < vr->nhit; i++) {
        if (i) putchar(',');
        printf("{\"va\":\"0x%llx\",\"sev\":", (unsigned long long)vr->hits[i].va);
        rpc_jstr(vr->hits[i].sev);
        printf(",\"kind\":"); rpc_jstr(vr->hits[i].kind);
        printf(",\"func\":"); rpc_jstr(vr->hits[i].func);
        printf(",\"sink\":"); rpc_jstr(vr->hits[i].sink);
        printf(",\"source\":"); rpc_jstr(vr->hits[i].source);
        printf(",\"hops\":%d,\"detail\":", vr->hits[i].hops);
        rpc_jstr(vr->hits[i].detail);
        putchar('}');
    }
    printf("]}\n");
    free(vr);
}

static void rpc_emit_pdiff(rpc_state *r, const char *other) {
    if (other && other[0]) {
        ana_free(&r->diff_ana);
        ana_init(&r->diff_ana);
        r->has_diff = 0;
        if (!ana_open(&r->diff_ana, other, 0, 64)) {
            printf("{\"ok\":false,\"err\":\"failed to open second binary\"}\n");
            return;
        }
        ana_run(&r->diff_ana, r->opt.threads, r->opt.min_str, r->opt.max_ana_mb);
        r->has_diff = 1;
    }
    if (!r->has_diff) {
        printf("{\"ok\":false,\"err\":\"no diff binary loaded\"}\n");
        return;
    }
    dif_res dres = {0};
    if (!dif_compare(&r->ana, &r->diff_ana, &dres)) {
        printf("{\"ok\":false,\"err\":\"diff failed\"}\n");
        return;
    }
    vln_pdiff_res *pr = (vln_pdiff_res *)calloc(1, sizeof(vln_pdiff_res));
    if (!pr) { dif_free(&dres); printf("{\"ok\":false}\n"); return; }
    vln_patch_triage(&r->ana, &r->diff_ana, &dres, pr);
    printf("{\"ok\":true,\"items\":[");
    for (int i = 0; i < pr->nitem; i++) {
        if (i) putchar(',');
        printf("{\"va_a\":\"0x%llx\",\"va_b\":\"0x%llx\",\"name\":",
               (unsigned long long)pr->items[i].va_a, (unsigned long long)pr->items[i].va_b);
        rpc_jstr(pr->items[i].name);
        printf(",\"score\":%d,\"delta_cmp\":%d,\"delta_jcc\":%d,\"reason\":",
               pr->items[i].score, pr->items[i].delta_cmp, pr->items[i].delta_jcc);
        rpc_jstr(pr->items[i].reason);
        putchar('}');
    }
    printf("]}\n");
    free(pr);
    dif_free(&dres);
}

static void rpc_emit_hilbert(const rpc_state *r, int order) {
    vln_hilbert_res *hr = (vln_hilbert_res *)calloc(1, sizeof(vln_hilbert_res));
    if (!hr || !vln_hilbert_map(&r->ana, order, hr)) {
        free(hr);
        printf("{\"ok\":false}\n");
        return;
    }
    printf("{\"ok\":true,\"side\":%d,\"ncell\":%d,\"cls\":[", hr->side, hr->ncell);
    for (int i = 0; i < hr->ncell; i++) { if (i) putchar(','); printf("%u", hr->cls[i]); }
    printf("],\"ent\":[");
    for (int i = 0; i < hr->ncell; i++) { if (i) putchar(','); printf("%u", hr->ent[i]); }
    printf("],\"offs\":[");
    for (int i = 0; i < hr->ncell; i++) { if (i) putchar(','); printf("%llu", (unsigned long long)hr->offs[i]); }
    printf("],\"vas\":[");
    for (int i = 0; i < hr->ncell; i++) { if (i) putchar(','); printf("\"0x%llx\"", (unsigned long long)hr->vas[i]); }
    printf("]}\n");
    free(hr);
}

static int rpc_sug_pending(const rpc_state *r) {
    int n = 0;
    for (int i = 0; i < r->nsug; i++) if (r->sugs[i].status == 0) n++;
    return n;
}

static void rpc_sug_apply_one(rpc_state *r, const rpc_sug *s) {
    if (strcmp(s->kind, "rename") == 0) {
        ana_set_name(&r->ana, s->va, s->val);
    } else if (strcmp(s->kind, "cmt") == 0) {
        ana_set_cmt(&r->ana, s->va, s->val);
    } else if (strcmp(s->kind, "type") == 0) {
        chdr_res cr = {0};
        if (!chdr_parse(&r->types, s->val, &cr)) typ_parse_c(&r->types, s->val);
    }
}

static void rpc_emit_sug_list(const rpc_state *r) {
    static const char *st_names[3] = { "pending", "accepted", "rejected" };
    printf("{\"ok\":true,\"pending\":%d,\"items\":[", rpc_sug_pending(r));
    for (int i = 0; i < r->nsug; i++) {
        const rpc_sug *s = &r->sugs[i];
        int si = (s->status >= 0 && s->status <= 2) ? s->status : 0;
        if (i) putchar(',');
        printf("{\"id\":%u,\"va\":\"0x%llx\",\"kind\":", s->id, (unsigned long long)s->va);
        rpc_jstr(s->kind);
        printf(",\"val\":"); rpc_jstr(s->val);
        printf(",\"reason\":"); rpc_jstr(s->reason);
        printf(",\"conf\":%d,\"status\":", s->conf);
        rpc_jstr(st_names[si]);
        putchar('}');
    }
    printf("]}\n");
}

int rpc_run(void) {
    setvbuf(stdout, NULL, _IOFBF, 65536);
    rpc_state st;
    memset(&st, 0, sizeof(st));
    opt_defaults(&st.opt);
    opt_load(&st.opt, "xdis.ini");
    ana_init(&st.ana);
    ana_init(&st.diff_ana);
    typ_init(&st.types);
    dbg_init(&st.dbg);
    gdb_init(&st.gdb);
    dmp_init(&st.dmp);
    ext_init(&st.ext, &st.ana, &st, rpc_log_cb, rpc_get_va, rpc_set_va);
    ext_load_dir_allow(&st.ext, "plugins", st.opt.plugins_allow);

    char *line = NULL;
    size_t line_cap = 0, line_len = 0;
    bool has_nul = false;
    int rstat = 0;
    while ((rstat = rpc_read_line(stdin, &line, &line_cap, &line_len, &has_nul)) != 0) {
        if (rstat == -2) {
            printf("{\"ok\":false,\"err\":\"line too long\"}\n");
            fflush(stdout);
            continue;
        }
        if (rstat < 0) {
            printf("{\"ok\":false,\"err\":\"oom\"}\n");
            fflush(stdout);
            continue;
        }
        if (line_len == 0 && !has_nul) continue;
        if (has_nul || !rpc_json_validate_obj(line)) {
            printf("{\"ok\":false,\"err\":\"invalid json\"}\n");
            fflush(stdout);
            continue;
        }
        char op[64] = "";
        if (!rpc_jget_str(line, "op", op, sizeof(op)) || !op[0]) {
            printf("{\"ok\":false,\"err\":\"missing op\"}\n");
            fflush(stdout);
            continue;
        }

        if (strcmp(op, "open") == 0) {
            char path[512] = "";
            if (!rpc_jget_str(line, "path", path, sizeof(path)) || !path[0]) {
                printf("{\"ok\":false,\"err\":\"missing path\"}\n");
            } else if (!ana_open(&st.ana, path, 0, 64)) {
                printf("{\"ok\":false,\"err\":\"open failed\"}\n");
            } else {
                ana_run(&st.ana, st.opt.threads, st.opt.min_str, st.opt.max_ana_mb);
                lang_apply_syms(&st.ana);
                char dbp[520];
                snprintf(dbp, sizeof(dbp), "%s.xdb", path);
                db_load(&st.ana, dbp);
                char typ_p[520];
                snprintf(typ_p, sizeof(typ_p), "%s.xtypes", path);
                typ_load_file(&st.types, typ_p);
                st.cur_va = st.ana.bin.entry;
                st.nsug = 0;
                rpc_emit_info(&st);
            }
        } else if (strcmp(op, "info") == 0) {
            rpc_emit_info(&st);
        } else if (strcmp(op, "dis") == 0) {
            uint64_t va = st.cur_va, n = 50;
            if (rpc_jget_u64_opt(line, "va", &va) < 0) printf("{\"ok\":false,\"err\":\"invalid va\"}\n");
            else if (rpc_jget_u64_opt(line, "n", &n) < 0) printf("{\"ok\":false,\"err\":\"invalid n\"}\n");
            else rpc_emit_dis(&st, va, (int)n);
        } else if (strcmp(op, "step") == 0) {
            uint64_t va = st.cur_va, d = 1;
            char dir[8] = "next";
            if (rpc_jget_u64_opt(line, "va", &va) < 0) printf("{\"ok\":false,\"err\":\"invalid va\"}\n");
            else if (rpc_jget_u64_opt(line, "n", &d) < 0) printf("{\"ok\":false,\"err\":\"invalid n\"}\n");
            else {
                rpc_jget_str(line, "dir", dir, sizeof(dir));
                for (uint64_t i = 0; i < d && i < 64; i++) {
                    va = (dir[0] == 'p') ? ana_prev_va(&st.ana, va) : ana_next_va(&st.ana, va);
                }
                printf("{\"ok\":true,\"va\":\"0x%llx\"}\n", (unsigned long long)va);
            }
        } else if (strcmp(op, "cfg") == 0) {
            uint64_t va = st.cur_va;
            if (rpc_jget_u64_opt(line, "va", &va) < 0) printf("{\"ok\":false,\"err\":\"invalid va\"}\n");
            else rpc_emit_cfg(&st, va);
        } else if (strcmp(op, "dec") == 0) {
            uint64_t va = st.cur_va;
            if (rpc_jget_u64_opt(line, "va", &va) < 0) printf("{\"ok\":false,\"err\":\"invalid va\"}\n");
            else rpc_emit_dec(&st, va);
        } else if (strcmp(op, "hex") == 0) {
            uint64_t va = st.cur_va, n = 32;
            if (rpc_jget_u64_opt(line, "va", &va) < 0) printf("{\"ok\":false,\"err\":\"invalid va\"}\n");
            else if (rpc_jget_u64_opt(line, "n", &n) < 0) printf("{\"ok\":false,\"err\":\"invalid n\"}\n");
            else rpc_emit_hex(&st, va, (int)n);
        } else if (strcmp(op, "list") == 0) {
            char tab[16] = "funcs", flt[64] = "";
            uint64_t off = 0, lim = 120;
            rpc_jget_str(line, "tab", tab, sizeof(tab));
            rpc_jget_str(line, "q", flt, sizeof(flt));
            if (rpc_jget_u64_opt(line, "off", &off) < 0) printf("{\"ok\":false,\"err\":\"invalid off\"}\n");
            else if (rpc_jget_u64_opt(line, "lim", &lim) < 0) printf("{\"ok\":false,\"err\":\"invalid lim\"}\n");
            else rpc_emit_list(&st, tab, flt, (uint32_t)off, (uint32_t)lim);
        } else if (strcmp(op, "peek") == 0) {
            uint64_t va = st.cur_va;
            if (rpc_jget_u64_opt(line, "va", &va) < 0) printf("{\"ok\":false,\"err\":\"invalid va\"}\n");
            else rpc_emit_peek(&st, va);
        } else if (strcmp(op, "xrefs") == 0) {
            uint64_t va = st.cur_va;
            if (rpc_jget_u64_opt(line, "va", &va) < 0) printf("{\"ok\":false,\"err\":\"invalid va\"}\n");
            else rpc_emit_xrefs(&st, va);
        } else if (strcmp(op, "find") == 0) {
            char q[128] = "";
            rpc_jget_str(line, "q", q, sizeof(q));
            rpc_emit_find(&st, q);
        } else if (strcmp(op, "resolve") == 0) {
            char q[128] = "";
            rpc_jget_str(line, "q", q, sizeof(q));
            uint64_t va = 0;
            if (ana_find_sym(&st.ana, q, &va)) {
                printf("{\"ok\":true,\"va\":\"0x%llx\"}\n", (unsigned long long)va);
            } else {
                const char *s = (q[0] == '0' && (q[1] == 'x' || q[1] == 'X')) ? q + 2 : q;
                char *end = NULL;
                errno = 0;
                va = strtoull(s, &end, 16);
                if (errno == 0 && end != s && *end == '\0' && bin_sec_at(&st.ana.bin, va)) {
                    printf("{\"ok\":true,\"va\":\"0x%llx\"}\n", (unsigned long long)va);
                } else {
                    printf("{\"ok\":false,\"err\":\"not found\"}\n");
                }
            }
        } else if (strcmp(op, "rename") == 0) {
            uint64_t va = st.cur_va;
            char name[96] = "";
            if (rpc_jget_u64_opt(line, "va", &va) < 0) {
                printf("{\"ok\":false,\"err\":\"invalid va\"}\n");
            } else {
                rpc_jget_str(line, "name", name, sizeof(name));
                ana_set_name(&st.ana, va, name);
                printf("{\"ok\":true}\n");
            }
        } else if (strcmp(op, "cmt") == 0) {
            uint64_t va = st.cur_va;
            char text[160] = "";
            if (rpc_jget_u64_opt(line, "va", &va) < 0) {
                printf("{\"ok\":false,\"err\":\"invalid va\"}\n");
            } else {
                rpc_jget_str(line, "text", text, sizeof(text));
                ana_set_cmt(&st.ana, va, text);
                printf("{\"ok\":true}\n");
            }
        } else if (strcmp(op, "mark") == 0) {
            uint64_t va = st.cur_va;
            char label[48] = "mark";
            if (rpc_jget_u64_opt(line, "va", &va) < 0) {
                printf("{\"ok\":false,\"err\":\"invalid va\"}\n");
            } else {
                rpc_jget_str(line, "label", label, sizeof(label));
                ana_add_mark(&st.ana, va, label);
                printf("{\"ok\":true}\n");
            }
        } else if (strcmp(op, "patch") == 0) {
            uint64_t va = st.cur_va, val = 0;
            if (rpc_jget_u64_opt(line, "va", &va) < 0) printf("{\"ok\":false,\"err\":\"invalid va\"}\n");
            else if (rpc_jget_u64_opt(line, "val", &val) < 0) printf("{\"ok\":false,\"err\":\"invalid val\"}\n");
            else {
                int ok = ana_patch_byte(&st.ana, va, (uint8_t)val);
                printf("{\"ok\":%s}\n", ok ? "true" : "false");
            }
        } else if (strcmp(op, "patch_bytes") == 0) {
            uint64_t va = st.cur_va;
            char hex[256] = "";
            if (rpc_jget_u64_opt(line, "va", &va) < 0) {
                printf("{\"ok\":false,\"err\":\"invalid va\"}\n");
            } else {
                rpc_jget_str(line, "hex", hex, sizeof(hex));
                int n = rpc_patch_hex(&st.ana, va, hex);
                printf("{\"ok\":%s,\"n\":%d}\n", n > 0 ? "true" : "false", n);
            }
        } else if (strcmp(op, "patches") == 0) {
            rpc_emit_patches(&st);
        } else if (strcmp(op, "unpatch") == 0) {
            uint64_t va = 0;
            if (rpc_jget_u64_opt(line, "va", &va) < 0) {
                printf("{\"ok\":false,\"err\":\"invalid va\"}\n");
            } else if (va == 0) {
                ana_unpatch_all(&st.ana);
                printf("{\"ok\":true}\n");
            } else {
                printf("{\"ok\":%s}\n", ana_unpatch_byte(&st.ana, va) ? "true" : "false");
            }
        } else if (strcmp(op, "export_bin") == 0) {
            char outp[512] = "";
            rpc_jget_str(line, "path", outp, sizeof(outp));
            printf("{\"ok\":%s}\n", ana_export_bin(&st.ana, outp) ? "true" : "false");
        } else if (strcmp(op, "lvar") == 0) {
            uint64_t fva = 0;
            char orig[24] = "", name[32] = "", type[32] = "";
            if (rpc_jget_u64_opt(line, "func_va", &fva) < 0) {
                printf("{\"ok\":false,\"err\":\"invalid func_va\"}\n");
            } else {
                rpc_jget_str(line, "orig", orig, sizeof(orig));
                rpc_jget_str(line, "name", name, sizeof(name));
                rpc_jget_str(line, "type", type, sizeof(type));
                int ok = ana_set_lvar(&st.ana, fva, orig, name, type);
                printf("{\"ok\":%s}\n", ok ? "true" : "false");
            }
        } else if (strcmp(op, "inspect") == 0) {
            uint64_t va = st.cur_va;
            if (rpc_jget_u64_opt(line, "va", &va) < 0) printf("{\"ok\":false,\"err\":\"invalid va\"}\n");
            else rpc_emit_inspect(&st, va);
        } else if (strcmp(op, "callgraph") == 0) {
            uint64_t va = st.cur_va;
            if (rpc_jget_u64_opt(line, "va", &va) < 0) printf("{\"ok\":false,\"err\":\"invalid va\"}\n");
            else rpc_emit_callgraph(&st, va);
        } else if (strcmp(op, "entropy_map") == 0) {
            rpc_emit_entropy_map(&st);
        } else if (strcmp(op, "triage") == 0) {
            rpc_emit_triage(&st);
        } else if (strcmp(op, "deobf") == 0) {
            uint64_t va = st.cur_va;
            if (rpc_jget_u64_opt(line, "va", &va) < 0) printf("{\"ok\":false,\"err\":\"invalid va\"}\n");
            else rpc_emit_deobf(&st, va);
        } else if (strcmp(op, "emu") == 0) {
            uint64_t va = st.cur_va, n = 48;
            if (rpc_jget_u64_opt(line, "va", &va) < 0) printf("{\"ok\":false,\"err\":\"invalid va\"}\n");
            else if (rpc_jget_u64_opt(line, "n", &n) < 0) printf("{\"ok\":false,\"err\":\"invalid n\"}\n");
            else rpc_emit_emu(&st, va, (int)n);
        } else if (strcmp(op, "ir") == 0) {
            uint64_t va = st.cur_va;
            if (rpc_jget_u64_opt(line, "va", &va) < 0) printf("{\"ok\":false,\"err\":\"invalid va\"}\n");
            else rpc_emit_ir(&st, va);
        } else if (strcmp(op, "ssa") == 0) {
            uint64_t va = st.cur_va;
            char tier[16] = "mlir";
            if (rpc_jget_u64_opt(line, "va", &va) < 0) {
                printf("{\"ok\":false,\"err\":\"invalid va\"}\n");
            } else {
                rpc_jget_str(line, "tier", tier, sizeof(tier));
                rpc_emit_ssa(&st, va, tier);
            }
        } else if (strcmp(op, "lang") == 0) {
            rpc_emit_lang(&st);
        } else if (strcmp(op, "cff") == 0) {
            uint64_t va = st.cur_va;
            if (rpc_jget_u64_opt(line, "va", &va) < 0) printf("{\"ok\":false,\"err\":\"invalid va\"}\n");
            else rpc_emit_cff(&st, va);
        } else if (strcmp(op, "mba_eval") == 0) {
            char expr[256] = "", out[256] = "";
            int saved = 0;
            const char *ev = rpc_json_find_top(line, "expr");
            bool trunc = false;
            if (!ev || *ev != '"' || !rpc_json_read_str_ex(&ev, expr, sizeof(expr), false, &trunc)) {
                printf("{\"ok\":false,\"err\":\"missing or invalid expr\",\"simple\":\"\",\"saved\":0}\n");
            } else if (trunc) {
                printf("{\"ok\":false,\"err\":\"expr too long\",\"simple\":\"\",\"saved\":0}\n");
            } else {
                bool ok = mba_simplify_expr(expr, out, sizeof(out), &saved);
                printf("{\"ok\":%s,\"simple\":", ok ? "true" : "false");
                rpc_jstr(ok ? out : expr);
                printf(",\"saved\":%d}\n", saved);
            }
        } else if (strcmp(op, "mba_scan") == 0) {
            uint64_t va = st.cur_va;
            if (rpc_jget_u64_opt(line, "va", &va) < 0) printf("{\"ok\":false,\"err\":\"invalid va\"}\n");
            else rpc_emit_mba_scan(&st, va);
        } else if (strcmp(op, "vm") == 0) {
            uint64_t va = st.cur_va;
            if (rpc_jget_u64_opt(line, "va", &va) < 0) printf("{\"ok\":false,\"err\":\"invalid va\"}\n");
            else rpc_emit_vm(&st, va);
        } else if (strcmp(op, "unp_hashes") == 0) {
            uint64_t apply = 0;
            if (rpc_jget_u64_opt(line, "apply", &apply) < 0) printf("{\"ok\":false,\"err\":\"invalid apply\"}\n");
            else rpc_emit_unp_hashes(&st, apply != 0);
        } else if (strcmp(op, "unp_strs") == 0) {
            uint64_t va = st.cur_va, apply = 0;
            if (rpc_jget_u64_opt(line, "va", &va) < 0) printf("{\"ok\":false,\"err\":\"invalid va\"}\n");
            else if (rpc_jget_u64_opt(line, "apply", &apply) < 0) printf("{\"ok\":false,\"err\":\"invalid apply\"}\n");
            else rpc_emit_unp_strs(&st, va, apply != 0);
        } else if (strcmp(op, "unp_rebuild") == 0) {
            uint64_t base = 0, oep = 0;
            char outp[512] = "";
            if (rpc_jget_u64_opt(line, "base", &base) < 0) printf("{\"ok\":false,\"err\":\"invalid base\"}\n");
            else if (rpc_jget_u64_opt(line, "oep", &oep) < 0) printf("{\"ok\":false,\"err\":\"invalid oep\"}\n");
            else {
                rpc_jget_str(line, "path", outp, sizeof(outp));
                rpc_emit_unp_rebuild(&st, base, oep, outp);
            }
        } else if (strcmp(op, "undo") == 0) {
            int ok = ana_undo(&st.ana);
            printf("{\"ok\":%s,\"undo_n\":%u,\"redo_n\":%u}\n", ok ? "true" : "false",
                   ana_undo_count(&st.ana), ana_redo_count(&st.ana));
        } else if (strcmp(op, "redo") == 0) {
            int ok = ana_redo(&st.ana);
            printf("{\"ok\":%s,\"undo_n\":%u,\"redo_n\":%u}\n", ok ? "true" : "false",
                   ana_undo_count(&st.ana), ana_redo_count(&st.ana));
        } else if (strcmp(op, "snap_save") == 0) {
            if (!rpc_has_bin(&st)) {
                printf("{\"ok\":false,\"err\":\"no binary open\"}\n");
            } else {
                char sn[48] = "snap", dbp[520];
                rpc_jget_str(line, "name", sn, sizeof(sn));
                snprintf(dbp, sizeof(dbp), "%s.xdb", st.ana.bin.path);
                printf("{\"ok\":%s}\n", db_snap_save(&st.ana, dbp, sn) ? "true" : "false");
            }
        } else if (strcmp(op, "snap_list") == 0) {
            if (!rpc_has_bin(&st)) {
                printf("{\"ok\":false,\"err\":\"no binary open\",\"items\":[]}\n");
            } else {
                char dbp[520];
                snprintf(dbp, sizeof(dbp), "%s.xdb", st.ana.bin.path);
                db_snap_meta ms[32];
                int n = db_snap_list(dbp, ms, 32);
                printf("{\"ok\":true,\"items\":[");
                for (int i = 0; i < n; i++) {
                    if (i) putchar(',');
                    printf("{\"name\":"); rpc_jstr(ms[i].name);
                    printf(",\"nsym\":%u,\"ncmt\":%u,\"npatch\":%u,\"nlvar\":%u}",
                           ms[i].nsym, ms[i].ncmt, ms[i].npatch, ms[i].nlvar);
                }
                printf("]}\n");
            }
        } else if (strcmp(op, "snap_load") == 0) {
            if (!rpc_has_bin(&st)) {
                printf("{\"ok\":false,\"err\":\"no binary open\"}\n");
            } else {
                char sn[48] = "", dbp[520];
                rpc_jget_str(line, "name", sn, sizeof(sn));
                snprintf(dbp, sizeof(dbp), "%s.xdb", st.ana.bin.path);
                printf("{\"ok\":%s}\n", db_snap_restore(&st.ana, dbp, sn) ? "true" : "false");
            }
        } else if (strcmp(op, "vtables") == 0) {
            rpc_emit_vtables(&st);
        } else if (strcmp(op, "switches") == 0) {
            uint64_t va = st.cur_va;
            if (rpc_jget_u64_opt(line, "va", &va) < 0) printf("{\"ok\":false,\"err\":\"invalid va\"}\n");
            else rpc_emit_switches(&st, va);
        } else if (strcmp(op, "crypto") == 0) {
            rpc_emit_crypto(&st);
        } else if (strcmp(op, "diff") == 0) {
            char other[512] = "";
            rpc_jget_str(line, "path", other, sizeof(other));
            rpc_emit_diff(&st, other);
        } else if (strcmp(op, "diff_dec") == 0) {
            uint64_t va_b = 0;
            if (rpc_jget_u64_opt(line, "va", &va_b) < 0) {
                printf("{\"ok\":false,\"err\":\"invalid va\"}\n");
            } else if (!st.has_diff) {
                printf("{\"ok\":false}\n");
            } else {
                dec_out d = {0};
                if (!dec_func_typed(&st.diff_ana, &st.types, va_b, &d)) printf("{\"ok\":false}\n");
                else {
                    printf("{\"ok\":true,\"lines\":[");
                    for (uint32_t i = 0; i < d.nline; i++) {
                        if (i) putchar(',');
                        rpc_jstr(d.lines[i].text);
                    }
                    printf("]}\n");
                    dec_free(&d);
                }
            }
        } else if (strcmp(op, "pathfind") == 0) {
            uint64_t a_va = st.cur_va, b_va = 0;
            if (rpc_jget_u64_opt(line, "from", &a_va) < 0) printf("{\"ok\":false,\"err\":\"invalid from\"}\n");
            else if (rpc_jget_u64_opt(line, "to", &b_va) < 0) printf("{\"ok\":false,\"err\":\"invalid to\"}\n");
            else rpc_emit_path(&st, a_va, b_va);
        } else if (strcmp(op, "xgraph") == 0) {
            uint64_t va = st.cur_va, depth = 2;
            if (rpc_jget_u64_opt(line, "va", &va) < 0) printf("{\"ok\":false,\"err\":\"invalid va\"}\n");
            else if (rpc_jget_u64_opt(line, "depth", &depth) < 0) printf("{\"ok\":false,\"err\":\"invalid depth\"}\n");
            else rpc_emit_xgraph(&st, va, (int)depth);
        } else if (strcmp(op, "sig_save") == 0) {
            char sp[512] = "";
            rpc_jget_str(line, "path", sp, sizeof(sp));
            printf("{\"ok\":%s}\n", sig_save(&st.ana, sp) ? "true" : "false");
        } else if (strcmp(op, "sig_apply") == 0) {
            char sp[512] = "";
            rpc_jget_str(line, "path", sp, sizeof(sp));
            uint32_t matched = sig_apply(&st.ana, sp);
            printf("{\"ok\":true,\"matched\":%u}\n", matched);
        } else if (strcmp(op, "asm") == 0) {
            if (!rpc_has_bin(&st) || st.ana.bin.nsec == 0) {
                printf("{\"ok\":false,\"err\":\"no binary open\"}\n");
            } else if (st.ana.bin.arch != BIN_ARCH_X64 && st.ana.bin.arch != BIN_ARCH_X86) {
                printf("{\"ok\":false,\"err\":\"asm only supported for x86/x64\"}\n");
            } else {
                uint64_t va = st.cur_va, apply = 1;
                char text[128] = "";
                if (rpc_jget_u64_opt(line, "va", &va) < 0) {
                    printf("{\"ok\":false,\"err\":\"invalid va\"}\n");
                } else if (rpc_jget_u64_opt(line, "apply", &apply) < 0) {
                    printf("{\"ok\":false,\"err\":\"invalid apply\"}\n");
                } else if (!rpc_jget_str(line, "text", text, sizeof(text)) || !text[0]) {
                    printf("{\"ok\":false,\"err\":\"missing text\"}\n");
                } else {
                    uint8_t bytes[16];
                    int n = asm_encode(text, va, st.ana.bin.bits, bytes);
                    if (n <= 0) { printf("{\"ok\":false,\"err\":\"bad asm\"}\n"); }
                    else {
                        if (apply) for (int i = 0; i < n; i++) ana_patch_byte(&st.ana, va + (uint64_t)i, bytes[i]);
                        printf("{\"ok\":true,\"n\":%d,\"hex\":\"", n);
                        for (int i = 0; i < n; i++) printf("%02x", bytes[i]);
                        printf("\"}\n");
                    }
                }
            }
        } else if (strcmp(op, "types") == 0) {
            rpc_emit_types(&st);
        } else if (strcmp(op, "type_add") == 0) {
            char *decl = rpc_jget_str_alloc(line, "decl", (4u << 20));
            if (!decl) {
                printf("{\"ok\":false,\"added\":0}\n");
            } else {
                chdr_res cr = {0};
                int ok = chdr_parse(&st.types, decl, &cr) || typ_parse_c(&st.types, decl);
                printf("{\"ok\":%s,\"added\":%d}\n", ok ? "true" : "false", cr.types_added ? cr.types_added : ok);
                free(decl);
            }
        } else if (strcmp(op, "chdr_parse") == 0) {
            char hdr_path[512] = "";
            char *text = NULL;
            chdr_res cr = {0};
            bool ok = false;
            if (rpc_jget_str(line, "path", hdr_path, sizeof(hdr_path)) && hdr_path[0]) {
                FILE *hf = fopen(hdr_path, "rb");
                if (hf) {
                    fseek(hf, 0, SEEK_END);
                    long fsz = ftell(hf);
                    fseek(hf, 0, SEEK_SET);
                    if (fsz > 0 && fsz < (2L << 20)) {
                        char *buf = (char *)calloc(1, (size_t)fsz + 1);
                        if (buf) {
                            fread(buf, 1, (size_t)fsz, hf);
                            ok = chdr_parse(&st.types, buf, &cr);
                            free(buf);
                        }
                    }
                    fclose(hf);
                }
            } else if ((text = rpc_jget_str_alloc(line, "text", (4u << 20))) != NULL) {
                ok = chdr_parse(&st.types, text, &cr);
                free(text);
            }
            printf("{\"ok\":%s,\"added\":%d,\"defines\":%d,\"err\":", ok ? "true" : "false", cr.types_added, cr.defines);
            rpc_jstr(cr.err);
            printf("}\n");
        } else if (strcmp(op, "chdr_stdlib") == 0) {
            char pack[32] = "win32";
            rpc_jget_str(line, "pack", pack, sizeof(pack));
            int n = chdr_load_stdlib(&st.types, pack);
            printf("{\"ok\":%s,\"added\":%d}\n", n > 0 ? "true" : "false", n);
        } else if (strcmp(op, "make_sig") == 0) {
            uint64_t va = st.cur_va;
            if (rpc_jget_u64_opt(line, "va", &va) < 0) {
                printf("{\"ok\":false,\"err\":\"invalid va\"}\n");
            } else {
                chdr_sig_res sr = {0};
                if (!chdr_make_sig(&st.ana, va, &sr)) { printf("{\"ok\":false}\n"); }
                else {
                    printf("{\"ok\":true,\"va\":\"0x%llx\",\"len\":%d,\"hits\":%d,\"ida\":",
                           (unsigned long long)sr.va, sr.len, sr.hits);
                    rpc_jstr(sr.ida);
                    printf(",\"c_bytes\":"); rpc_jstr(sr.c_bytes);
                    printf(",\"c_mask\":"); rpc_jstr(sr.c_mask);
                    printf("}\n");
                }
            }
        } else if (strcmp(op, "pdb_msf") == 0) {
            char pp[512] = "";
            rpc_jget_str(line, "path", pp, sizeof(pp));
            sym_dbg_stats ss = {0};
            bool ok = sym_load_pdb_msf(&st.ana, &st.types, pp, &ss);
            printf("{\"ok\":%s,\"syms\":%u,\"types\":%u,\"funcs\":%u,\"fmt\":",
                   ok ? "true" : "false", ss.syms_added, ss.types_added, ss.funcs_added);
            rpc_jstr(ss.format);
            printf(",\"err\":"); rpc_jstr(ss.err);
            printf("}\n");
        } else if (strcmp(op, "dwarf_load") == 0) {
            sym_dbg_stats ss = {0};
            bool ok = sym_load_dwarf(&st.ana, &st.types, &ss);
            printf("{\"ok\":%s,\"syms\":%u,\"types\":%u,\"funcs\":%u,\"fmt\":",
                   ok ? "true" : "false", ss.syms_added, ss.types_added, ss.funcs_added);
            rpc_jstr(ss.format);
            printf(",\"err\":"); rpc_jstr(ss.err);
            printf("}\n");
        } else if (strcmp(op, "dotnet") == 0) {
            rpc_emit_dotnet(&st);
        } else if (strcmp(op, "struct_apply") == 0) {
            char nm[64] = "";
            uint64_t va = st.cur_va;
            if (rpc_jget_u64_opt(line, "va", &va) < 0) {
                printf("{\"ok\":false,\"err\":\"invalid va\"}\n");
            } else {
                rpc_jget_str(line, "name", nm, sizeof(nm));
                rpc_emit_struct_apply(&st, nm, va);
            }
        } else if (strcmp(op, "demangle") == 0) {
            char in_s[256] = "", out_s[256] = "";
            rpc_jget_str(line, "name", in_s, sizeof(in_s));
            int ok = dem_name(in_s, out_s, sizeof(out_s));
            printf("{\"ok\":%s,\"name\":", ok ? "true" : "false");
            rpc_jstr(ok ? out_s : in_s);
            printf("}\n");
        } else if (strcmp(op, "pdb_load") == 0) {
            char pp[512] = "";
            rpc_jget_str(line, "path", pp, sizeof(pp));
            uint32_t added = pdb_load_file(&st.ana.bin, pp);
            for (uint32_t i = 0; i < st.ana.bin.nsym; i++) {
                ana_set_name(&st.ana, st.ana.bin.syms[i].va, bin_str(&st.ana.bin, st.ana.bin.syms[i].name_off));
            }
            printf("{\"ok\":true,\"added\":%u}\n", added);
        } else if (strcmp(op, "dbg_launch") == 0) {
            char dp[512] = "", da[256] = "";
            rpc_jget_str(line, "path", dp, sizeof(dp));
            rpc_jget_str(line, "args", da, sizeof(da));
            if (!dp[0] && !rpc_has_bin(&st)) {
                printf("{\"ok\":false,\"err\":\"no binary open\"}\n");
            } else {
                if (!dp[0]) snprintf(dp, sizeof(dp), "%s", st.ana.bin.path);
                int ok = dbg_launch(&st.dbg, dp, da);
                if (!ok) { printf("{\"ok\":false,\"err\":"); rpc_jstr(st.dbg.last_err); printf("}\n"); }
                else rpc_emit_dbg_state(&st, -1);
            }
        } else if (strcmp(op, "dbg_attach") == 0) {
            uint64_t pid = 0;
            if (rpc_jget_u64_opt(line, "pid", &pid) < 0) {
                printf("{\"ok\":false,\"err\":\"invalid pid\"}\n");
            } else {
                int ok = dbg_attach(&st.dbg, (uint32_t)pid);
                if (!ok) { printf("{\"ok\":false,\"err\":"); rpc_jstr(st.dbg.last_err); printf("}\n"); }
                else rpc_emit_dbg_state(&st, -1);
            }
        } else if (strcmp(op, "dbg_step") == 0) {
            dbg_step(&st.dbg);
            rpc_emit_dbg_state(&st, -1);
        } else if (strcmp(op, "dbg_step_over") == 0) {
            dbg_step_over(&st.dbg);
            rpc_emit_dbg_state(&st, -1);
        } else if (strcmp(op, "dbg_step_out") == 0) {
            dbg_step_out(&st.dbg);
            rpc_emit_dbg_state(&st, -1);
        } else if (strcmp(op, "dbg_run_to") == 0) {
            uint64_t va = st.cur_va;
            if (rpc_jget_u64_opt(line, "va", &va) < 0) printf("{\"ok\":false,\"err\":\"invalid va\"}\n");
            else { dbg_run_to(&st.dbg, va); rpc_emit_dbg_state(&st, -1); }
        } else if (strcmp(op, "dbg_cont") == 0) {
            uint64_t ms = 1500;
            if (rpc_jget_u64_opt(line, "ms", &ms) < 0) printf("{\"ok\":false,\"err\":\"invalid ms\"}\n");
            else { dbg_cont(&st.dbg, (uint32_t)ms); rpc_emit_dbg_state(&st, -1); }
        } else if (strcmp(op, "dbg_pause") == 0) {
            dbg_pause(&st.dbg);
            rpc_emit_dbg_state(&st, -1);
        } else if (strcmp(op, "dbg_set_reg") == 0) {
            char reg[16] = "";
            uint64_t val = 0;
            rpc_jget_str(line, "reg", reg, sizeof(reg));
            if (rpc_jget_u64_opt(line, "val", &val) < 0) {
                printf("{\"ok\":false,\"err\":\"invalid val\"}\n");
            } else {
                int ridx = rpc_reg_index(reg);
                if (ridx < 0) {
                    if (_stricmp(reg, "rip") == 0 || _stricmp(reg, "eip") == 0) ridx = 16;
                    else if (_stricmp(reg, "rflags") == 0 || _stricmp(reg, "eflags") == 0) ridx = 17;
                }
                if (ridx < 0 || !dbg_set_reg(&st.dbg, ridx, val)) {
                    printf("{\"ok\":false,\"err\":");
                    rpc_jstr(st.dbg.last_err[0] ? st.dbg.last_err : "invalid register");
                    printf("}\n");
                } else {
                    rpc_emit_dbg_state(&st, -1);
                }
            }
        } else if (strcmp(op, "dbg_bp") == 0) {
            uint64_t va = st.cur_va, del = 0;
            char cond[64] = "";
            if (rpc_jget_u64_opt(line, "va", &va) < 0) printf("{\"ok\":false,\"err\":\"invalid va\"}\n");
            else if (rpc_jget_u64_opt(line, "del", &del) < 0) printf("{\"ok\":false,\"err\":\"invalid del\"}\n");
            else {
                rpc_jget_str(line, "cond", cond, sizeof(cond));
                if (del) dbg_bp_del(&st.dbg, va);
                else if (cond[0]) dbg_bp_add_cond(&st.dbg, va, cond);
                else dbg_bp_add(&st.dbg, va);
                rpc_emit_dbg_state(&st, -1);
            }
        } else if (strcmp(op, "dbg_hwbp") == 0) {
            uint64_t va = st.cur_va, kind = 0, sz = 1, del = 0, slot = 0;
            int slot_rc = 0;
            if (rpc_jget_u64_opt(line, "va", &va) < 0) printf("{\"ok\":false,\"err\":\"invalid va\"}\n");
            else if (rpc_jget_u64_opt(line, "kind", &kind) < 0) printf("{\"ok\":false,\"err\":\"invalid kind\"}\n");
            else if (rpc_jget_u64_opt(line, "size", &sz) < 0) printf("{\"ok\":false,\"err\":\"invalid size\"}\n");
            else if (rpc_jget_u64_opt(line, "del", &del) < 0) printf("{\"ok\":false,\"err\":\"invalid del\"}\n");
            else if ((slot_rc = rpc_jget_u64_opt(line, "slot", &slot)) < 0) printf("{\"ok\":false,\"err\":\"invalid slot\"}\n");
            else {
                if (del) dbg_hwbp_del(&st.dbg, (int)slot);
                else if (slot_rc > 0) dbg_hwbp_add_slot(&st.dbg, (int)slot, va, (uint8_t)kind, (uint8_t)sz);
                else dbg_hwbp_add(&st.dbg, va, (uint8_t)kind, (uint8_t)sz);
                rpc_emit_dbg_state(&st, -1);
            }
        } else if (strcmp(op, "dbg_membp") == 0) {
            uint64_t va = st.cur_va, sz = 4096, del = 0;
            if (rpc_jget_u64_opt(line, "va", &va) < 0) printf("{\"ok\":false,\"err\":\"invalid va\"}\n");
            else if (rpc_jget_u64_opt(line, "size", &sz) < 0) printf("{\"ok\":false,\"err\":\"invalid size\"}\n");
            else if (rpc_jget_u64_opt(line, "del", &del) < 0) printf("{\"ok\":false,\"err\":\"invalid del\"}\n");
            else {
                if (del) dbg_membp_del(&st.dbg, va);
                else dbg_membp_add(&st.dbg, va, (uint32_t)sz);
                rpc_emit_dbg_state(&st, -1);
            }
        } else if (strcmp(op, "dbg_mmap") == 0) {
            dbg_mreg *regs = (dbg_mreg *)calloc(DBG_MAX_MMAP, sizeof(dbg_mreg));
            int n = regs ? dbg_mem_map(&st.dbg, regs, DBG_MAX_MMAP) : 0;
            printf("{\"ok\":true,\"items\":[");
            for (int i = 0; i < n; i++) {
                if (i) putchar(',');
                printf("{\"base\":\"0x%llx\",\"size\":%llu,\"perm\":%u,\"type\":",
                       (unsigned long long)regs[i].base, (unsigned long long)regs[i].size, regs[i].perm);
                rpc_jstr(regs[i].type);
                printf(",\"mod\":"); rpc_jstr(regs[i].mod);
                putchar('}');
            }
            printf("]}\n");
            free(regs);
        } else if (strcmp(op, "dbg_bt") == 0) {
            dbg_frame fr[DBG_MAX_BT];
            int n = dbg_backtrace(&st.dbg, fr, DBG_MAX_BT);
            printf("{\"ok\":true,\"items\":[");
            for (int i = 0; i < n; i++) {
                if (i) putchar(',');
                printf("{\"rip\":\"0x%llx\",\"sp\":\"0x%llx\",\"mod\":",
                       (unsigned long long)fr[i].rip, (unsigned long long)fr[i].sp);
                rpc_jstr(fr[i].mod);
                putchar('}');
            }
            printf("]}\n");
        } else if (strcmp(op, "dbg_ttd_rec") == 0) {
            uint64_t n = 128;
            if (rpc_jget_u64_opt(line, "n", &n) < 0) printf("{\"ok\":false,\"err\":\"invalid n\"}\n");
            else {
                int rec = dbg_ttd_record(&st.dbg, (int)n);
                printf("{\"ok\":%s,\"recorded\":%d,\"nttd\":%d,\"ttd_cur\":%d,\"nsnap\":%d}\n",
                       rec > 0 ? "true" : "false", rec, st.dbg.nttd, st.dbg.ttd_cur, st.dbg.nsnap);
            }
        } else if (strcmp(op, "dbg_ttd_back") == 0) {
            int ok = dbg_ttd_step_back(&st.dbg);
            printf("{\"ok\":%s,\"cur\":%d,\"nsnap\":%d,\"ttd_cur\":%d,\"nttd\":%d}\n",
                   ok ? "true" : "false", st.dbg.cur_snap, st.dbg.nsnap, st.dbg.ttd_cur, st.dbg.nttd);
        } else if (strcmp(op, "dbg_ttd_who") == 0) {
            uint64_t mva = 0, hrip = 0, ov = 0, nv = 0;
            char reg[16] = "";
            if (rpc_jget_u64_opt(line, "va", &mva) < 0) {
                printf("{\"ok\":false,\"err\":\"invalid va\"}\n");
            } else {
                rpc_jget_str(line, "reg", reg, sizeof(reg));
                int idx = dbg_ttd_who_wrote(&st.dbg, mva, rpc_reg_index(reg), &hrip, &ov, &nv);
                printf("{\"ok\":%s,\"idx\":%d,\"rip\":\"0x%llx\",\"old\":\"0x%llx\",\"new\":\"0x%llx\"}\n",
                       idx >= 0 ? "true" : "false", idx, (unsigned long long)hrip,
                       (unsigned long long)ov, (unsigned long long)nv);
            }
        } else if (strcmp(op, "gdb_connect") == 0) {
            char host[64] = "127.0.0.1";
            uint64_t port = 1234, ms = 2500;
            rpc_jget_str(line, "host", host, sizeof(host));
            if (rpc_jget_u64_opt(line, "port", &port) < 0) printf("{\"ok\":false,\"err\":\"invalid port\"}\n");
            else if (rpc_jget_u64_opt(line, "ms", &ms) < 0) printf("{\"ok\":false,\"err\":\"invalid ms\"}\n");
            else { gdb_connect(&st.gdb, host, (uint16_t)port, (uint32_t)ms); rpc_emit_gdb_state(&st); }
        } else if (strcmp(op, "gdb_step") == 0) {
            gdb_step(&st.gdb);
            rpc_emit_gdb_state(&st);
        } else if (strcmp(op, "gdb_cont") == 0) {
            uint64_t ms = 1500;
            if (rpc_jget_u64_opt(line, "ms", &ms) < 0) printf("{\"ok\":false,\"err\":\"invalid ms\"}\n");
            else { gdb_cont(&st.gdb, (uint32_t)ms); rpc_emit_gdb_state(&st); }
        } else if (strcmp(op, "gdb_bp") == 0) {
            uint64_t va = st.cur_va, del = 0, hw = 0;
            if (rpc_jget_u64_opt(line, "va", &va) < 0) printf("{\"ok\":false,\"err\":\"invalid va\"}\n");
            else if (rpc_jget_u64_opt(line, "del", &del) < 0) printf("{\"ok\":false,\"err\":\"invalid del\"}\n");
            else if (rpc_jget_u64_opt(line, "hw", &hw) < 0) printf("{\"ok\":false,\"err\":\"invalid hw\"}\n");
            else {
                int ok = del ? gdb_bp_del(&st.gdb, va, (int)hw) : gdb_bp_add(&st.gdb, va, (int)hw);
                printf("{\"ok\":%s}\n", ok ? "true" : "false");
            }
        } else if (strcmp(op, "gdb_mem") == 0) {
            uint64_t va = st.cur_va, n = 64;
            if (rpc_jget_u64_opt(line, "va", &va) < 0) printf("{\"ok\":false,\"err\":\"invalid va\"}\n");
            else if (rpc_jget_u64_opt(line, "n", &n) < 0) printf("{\"ok\":false,\"err\":\"invalid n\"}\n");
            else {
                if (n > 512) n = 512;
                uint8_t mb[512];
                size_t got = gdb_read_mem(&st.gdb, va, mb, (size_t)n);
                printf("{\"ok\":%s,\"n\":%zu,\"hex\":\"", got > 0 ? "true" : "false", got);
                for (size_t i = 0; i < got; i++) printf("%02x", mb[i]);
                printf("\"}\n");
            }
        } else if (strcmp(op, "gdb_disconnect") == 0) {
            gdb_disconnect(&st.gdb);
            rpc_emit_gdb_state(&st);
        } else if (strcmp(op, "dmp_open") == 0) {
            char dp[512] = "";
            rpc_jget_str(line, "path", dp, sizeof(dp));
            dmp_open(&st.dmp, dp);
            rpc_emit_dmp_state(&st);
        } else if (strcmp(op, "dmp_mem") == 0) {
            uint64_t va = 0, n = 64;
            if (rpc_jget_u64_opt(line, "va", &va) < 0) printf("{\"ok\":false,\"err\":\"invalid va\"}\n");
            else if (rpc_jget_u64_opt(line, "n", &n) < 0) printf("{\"ok\":false,\"err\":\"invalid n\"}\n");
            else {
                if (n > 512) n = 512;
                uint8_t mb[512];
                size_t got = dmp_read_mem(&st.dmp, va, mb, (size_t)n);
                printf("{\"ok\":%s,\"n\":%zu,\"hex\":\"", got > 0 ? "true" : "false", got);
                for (size_t i = 0; i < got; i++) printf("%02x", mb[i]);
                printf("\"}\n");
            }
        } else if (strcmp(op, "taint") == 0) {
            uint64_t va = st.cur_va, blen = 0, n = 128;
            char reg[16] = "rcx";
            if (rpc_jget_u64_opt(line, "va", &va) < 0) printf("{\"ok\":false,\"err\":\"invalid va\"}\n");
            else if (rpc_jget_u64_opt(line, "buf_len", &blen) < 0) printf("{\"ok\":false,\"err\":\"invalid buf_len\"}\n");
            else if (rpc_jget_u64_opt(line, "n", &n) < 0) printf("{\"ok\":false,\"err\":\"invalid n\"}\n");
            else {
                rpc_jget_str(line, "reg", reg, sizeof(reg));
                int ridx = rpc_reg_index(reg);
                if (ridx < 0) ridx = 1;
                rpc_emit_taint(&st, va, ridx, (uint32_t)blen, (int)n);
            }
        } else if (strcmp(op, "sym_solve") == 0) {
            uint64_t s_va = st.cur_va, t_va = 0;
            if (rpc_jget_u64_opt(line, "from", &s_va) < 0) printf("{\"ok\":false,\"err\":\"invalid from\"}\n");
            else if (rpc_jget_u64_opt(line, "to", &t_va) < 0) printf("{\"ok\":false,\"err\":\"invalid to\"}\n");
            else rpc_emit_sym_solve(&st, s_va, t_va);
        } else if (strcmp(op, "dbg_snap") == 0) {
            uint64_t idx = (uint64_t)(st.dbg.cur_snap >= 0 ? st.dbg.cur_snap : 0);
            int has = rpc_jget_u64_opt(line, "idx", &idx);
            if (has < 0) printf("{\"ok\":false,\"err\":\"invalid idx\"}\n");
            else rpc_emit_dbg_state(&st, has ? (int)idx : -1);
        } else if (strcmp(op, "dbg_mods") == 0) {
            dbg_mod mods[DBG_MAX_MOD];
            int n = dbg_list_mods(&st.dbg, mods, DBG_MAX_MOD);
            printf("{\"ok\":true,\"items\":[");
            for (int i = 0; i < n; i++) {
                if (i) putchar(',');
                printf("{\"base\":\"0x%llx\",\"size\":%u,\"name\":", (unsigned long long)mods[i].base, mods[i].size);
                rpc_jstr(mods[i].name);
                putchar('}');
            }
            printf("]}\n");
        } else if (strcmp(op, "dbg_threads") == 0) {
            dbg_th ths[DBG_MAX_TH];
            int n = dbg_list_threads(&st.dbg, ths, DBG_MAX_TH);
            printf("{\"ok\":true,\"items\":[");
            for (int i = 0; i < n; i++) {
                if (i) putchar(',');
                printf("{\"tid\":%u,\"start\":\"0x%llx\"}", ths[i].tid, (unsigned long long)ths[i].start_va);
            }
            printf("]}\n");
        } else if (strcmp(op, "dbg_mem") == 0) {
            uint64_t va = st.cur_va, n = 64;
            if (rpc_jget_u64_opt(line, "va", &va) < 0) printf("{\"ok\":false,\"err\":\"invalid va\"}\n");
            else if (rpc_jget_u64_opt(line, "n", &n) < 0) printf("{\"ok\":false,\"err\":\"invalid n\"}\n");
            else {
                if (n > 512) n = 512;
                uint8_t mb[512];
                size_t got = dbg_read_mem(&st.dbg, va, mb, (size_t)n);
                printf("{\"ok\":true,\"n\":%zu,\"hex\":\"", got);
                for (size_t i = 0; i < got; i++) printf("%02x", mb[i]);
                printf("\"}\n");
            }
        } else if (strcmp(op, "dbg_write_mem") == 0) {
            uint64_t va = 0;
            if (!st.dbg.attached || !st.dbg.hproc) {
                printf("{\"ok\":false,\"err\":\"debugger not attached\"}\n");
            } else if (!rpc_jget_u64(line, "va", &va)) {
                printf("{\"ok\":false,\"err\":\"missing or invalid va\"}\n");
            } else {
                char *hex = rpc_jget_str_alloc(line, "hex", 65536u);
                if (!hex) {
                    printf("{\"ok\":false,\"err\":\"missing hex\"}\n");
                } else {
                    uint8_t buf[4096];
                    size_t n = 0;
                    if (!rpc_parse_hex_bytes(hex, buf, sizeof(buf), &n)) {
                        printf("{\"ok\":false,\"err\":\"invalid hex bytes\"}\n");
                    } else if (!dbg_write_mem(&st.dbg, va, buf, n)) {
                        printf("{\"ok\":false,\"err\":\"write failed\"}\n");
                    } else {
                        printf("{\"ok\":true,\"written\":%zu}\n", n);
                    }
                    free(hex);
                }
            }
        } else if (strcmp(op, "dbg_detach") == 0) {
            dbg_detach(&st.dbg);
            rpc_emit_dbg_state(&st, -1);
        } else if (strcmp(op, "dbg_kill") == 0) {
            dbg_kill(&st.dbg);
            rpc_emit_dbg_state(&st, -1);
        } else if (strcmp(op, "read") == 0) {
            uint64_t va = st.cur_va, n = 64;
            if (rpc_jget_u64_opt(line, "va", &va) < 0) printf("{\"ok\":false,\"err\":\"invalid va\"}\n");
            else if (rpc_jget_u64_opt(line, "n", &n) < 0) printf("{\"ok\":false,\"err\":\"invalid n\"}\n");
            else {
                if (n > 2048) n = 2048;
                uint8_t buf[2048];
                size_t got = bin_read(&st.ana.bin, va, buf, (size_t)n);
                printf("{\"ok\":true,\"n\":%zu,\"hex\":\"", got);
                for (size_t i = 0; i < got; i++) printf("%02x", buf[i]);
                printf("\"}\n");
            }
        } else if (strcmp(op, "save") == 0) {
            if (!rpc_has_bin(&st)) {
                printf("{\"ok\":false,\"err\":\"no binary open\"}\n");
            } else {
                char dbp[520], typ_p[520];
                snprintf(dbp, sizeof(dbp), "%s.xdb", st.ana.bin.path);
                snprintf(typ_p, sizeof(typ_p), "%s.xtypes", st.ana.bin.path);
                int ok = db_save(&st.ana, dbp);
                if (st.types.ndef > 0) typ_save_file(&st.types, typ_p);
                printf("{\"ok\":%s}\n", ok ? "true" : "false");
            }
        } else if (strcmp(op, "opt") == 0) {
            uint64_t up = st.opt.upper_mnem;
            int has_up = rpc_jget_u64_opt(line, "upper", &up);
            if (has_up < 0) printf("{\"ok\":false,\"err\":\"invalid upper\"}\n");
            else {
                if (has_up > 0) st.opt.upper_mnem = (int)(up != 0);
                printf("{\"ok\":true,\"upper\":%d}\n", st.opt.upper_mnem);
            }
        } else if (strcmp(op, "cmd") == 0) {
            char name[48] = "", args[128] = "";
            rpc_jget_str(line, "name", name, sizeof(name));
            rpc_jget_str(line, "args", args, sizeof(args));
            st.log_len = 0;
            st.log_buf[0] = 0;
            int ok = ext_run(&st.ext, name, args);
            printf("{\"ok\":%s,\"out\":", ok ? "true" : "false");
            rpc_jstr(st.log_buf);
            printf("}\n");
        } else if (strcmp(op, "yara_defaults") == 0) {
            printf("{\"ok\":true,\"rules\":");
            rpc_jstr(for_yara_default_rules());
            printf("}\n");
        } else if (strcmp(op, "yara") == 0) {
            char *rules = rpc_jget_str_alloc(line, "rules", (4u << 20));
            rpc_emit_yara(&st, rules ? rules : "");
            free(rules);
        } else if (strcmp(op, "carve") == 0) {
            rpc_emit_carve(&st);
        } else if (strcmp(op, "carve_extract") == 0) {
            uint64_t off = 0, sz = 0;
            char outp[512] = "";
            if (rpc_jget_u64_opt(line, "off", &off) < 0) printf("{\"ok\":false,\"err\":\"invalid off\"}\n");
            else if (rpc_jget_u64_opt(line, "size", &sz) < 0) printf("{\"ok\":false,\"err\":\"invalid size\"}\n");
            else {
                rpc_jget_str(line, "path", outp, sizeof(outp));
                bool ok = for_extract(&st.ana, off, sz, outp);
                printf("{\"ok\":%s}\n", ok ? "true" : "false");
            }
        } else if (strcmp(op, "iocs") == 0) {
            rpc_emit_iocs(&st);
        } else if (strcmp(op, "vuln") == 0) {
            rpc_emit_vuln(&st);
        } else if (strcmp(op, "pdiff") == 0) {
            char other[512] = "";
            rpc_jget_str(line, "path", other, sizeof(other));
            rpc_emit_pdiff(&st, other);
        } else if (strcmp(op, "hilbert") == 0) {
            uint64_t order = 6;
            if (rpc_jget_u64_opt(line, "order", &order) < 0) printf("{\"ok\":false,\"err\":\"invalid order\"}\n");
            else rpc_emit_hilbert(&st, (int)order);
        } else if (strcmp(op, "sug_add") == 0) {
            uint64_t sva = st.cur_va, cf = 80;
            if (rpc_jget_u64_opt(line, "va", &sva) < 0) {
                printf("{\"ok\":false,\"err\":\"invalid va\"}\n");
            } else if (rpc_jget_u64_opt(line, "conf", &cf) < 0) {
                printf("{\"ok\":false,\"err\":\"invalid conf\"}\n");
            } else {
                if (st.nsug >= 128) {
                    memmove(&st.sugs[0], &st.sugs[1], 127 * sizeof(rpc_sug));
                    st.nsug = 127;
                }
                rpc_sug *s = &st.sugs[st.nsug];
                memset(s, 0, sizeof(*s));
                s->id = ++st.next_sug_id;
                s->va = sva;
                snprintf(s->kind, sizeof(s->kind), "rename");
                s->conf = (cf > 100) ? 100 : (int)cf;
                rpc_jget_str(line, "kind", s->kind, sizeof(s->kind));
                rpc_jget_str(line, "val", s->val, sizeof(s->val));
                rpc_jget_str(line, "reason", s->reason, sizeof(s->reason));
                if (!s->val[0]) {
                    printf("{\"ok\":false,\"err\":\"empty value\"}\n");
                } else {
                    st.nsug++;
                    printf("{\"ok\":true,\"id\":%u,\"pending\":%d}\n", s->id, rpc_sug_pending(&st));
                }
            }
        } else if (strcmp(op, "sug_list") == 0) {
            rpc_emit_sug_list(&st);
        } else if (strcmp(op, "sug_decide") == 0) {
            uint64_t id = 0, accept = 1, min_conf = 0;
            if (rpc_jget_u64_opt(line, "id", &id) < 0) printf("{\"ok\":false,\"err\":\"invalid id\"}\n");
            else if (rpc_jget_u64_opt(line, "accept", &accept) < 0) printf("{\"ok\":false,\"err\":\"invalid accept\"}\n");
            else if (rpc_jget_u64_opt(line, "min_conf", &min_conf) < 0) printf("{\"ok\":false,\"err\":\"invalid min_conf\"}\n");
            else {
                int applied = 0;
                for (int i = 0; i < st.nsug; i++) {
                    rpc_sug *s = &st.sugs[i];
                    if (s->status != 0) continue;
                    if (id > 0 && s->id != (uint32_t)id) continue;
                    if (id == 0 && (uint64_t)s->conf < min_conf) continue;
                    s->status = accept ? 1 : 2;
                    if (accept) rpc_sug_apply_one(&st, s);
                    applied++;
                }
                printf("{\"ok\":true,\"applied\":%d,\"pending\":%d}\n", applied, rpc_sug_pending(&st));
            }
        } else if (strcmp(op, "quit") == 0) {
            break;
        } else {
            printf("{\"ok\":false,\"err\":\"unknown op\"}\n");
        }
        fflush(stdout);
    }

    free(line);
    dmp_close(&st.dmp);
    gdb_disconnect(&st.gdb);
    dbg_close(&st.dbg);
    typ_free(&st.types);
    ext_free(&st.ext);
    ana_free(&st.diff_ana);
    ana_free(&st.ana);
    return 0;
}
