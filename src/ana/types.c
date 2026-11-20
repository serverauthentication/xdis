#include "ana.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
    TYP_STRUCT  = 0,
    TYP_ENUM    = 1,
    TYP_TYPEDEF = 2
};

void typ_init(typ_store *s) {
    if (!s) return;
    memset(s, 0, sizeof(*s));
}

void typ_free(typ_store *s) {
    if (!s) return;
    free(s->defs);
    memset(s, 0, sizeof(*s));
}

const typ_def *typ_find(const typ_store *s, const char *name) {
    if (!s || !name || !name[0]) return NULL;
    for (uint32_t i = 0; i < s->ndef; i++) {
        if (strcmp(s->defs[i].name, name) == 0) return &s->defs[i];
    }
    return NULL;
}

static void typ_clean_name(const char *raw, char *dst, size_t max) {
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
        else if (strncmp(p, "enum ", 5) == 0) p += 5;
        else if (strncmp(p, "union ", 6) == 0) p += 6;
        else break;
    }
    snprintf(dst, max, "%s", p);
}

static int typ_prim_size(const char *t) {
    if (strcmp(t, "char") == 0 || strcmp(t, "signed char") == 0 || strcmp(t, "unsigned char") == 0 ||
        strcmp(t, "int8_t") == 0 || strcmp(t, "uint8_t") == 0 || strcmp(t, "i8") == 0 || strcmp(t, "u8") == 0 ||
        strcmp(t, "bool") == 0 || strcmp(t, "_Bool") == 0 ||
        strcmp(t, "BYTE") == 0 || strcmp(t, "BOOLEAN") == 0 || strcmp(t, "CHAR") == 0 || strcmp(t, "UCHAR") == 0) {
        return 1;
    }
    if (strcmp(t, "short") == 0 || strcmp(t, "short int") == 0 || strcmp(t, "signed short") == 0 ||
        strcmp(t, "unsigned short") == 0 || strcmp(t, "unsigned short int") == 0 ||
        strcmp(t, "int16_t") == 0 || strcmp(t, "uint16_t") == 0 || strcmp(t, "i16") == 0 || strcmp(t, "u16") == 0 ||
        strcmp(t, "WORD") == 0 || strcmp(t, "SHORT") == 0 || strcmp(t, "USHORT") == 0 ||
        strcmp(t, "WCHAR") == 0 || strcmp(t, "wchar_t") == 0) {
        return 2;
    }
    if (strcmp(t, "int") == 0 || strcmp(t, "signed") == 0 || strcmp(t, "signed int") == 0 ||
        strcmp(t, "unsigned") == 0 || strcmp(t, "unsigned int") == 0 ||
        strcmp(t, "long") == 0 || strcmp(t, "signed long") == 0 || strcmp(t, "unsigned long") == 0 ||
        strcmp(t, "int32_t") == 0 || strcmp(t, "uint32_t") == 0 || strcmp(t, "i32") == 0 || strcmp(t, "u32") == 0 ||
        strcmp(t, "float") == 0 || strcmp(t, "DWORD") == 0 || strcmp(t, "BOOL") == 0 ||
        strcmp(t, "LONG") == 0 || strcmp(t, "ULONG") == 0 || strcmp(t, "UINT") == 0 ||
        strcmp(t, "INT") == 0 || strcmp(t, "HRESULT") == 0 || strcmp(t, "NTSTATUS") == 0) {
        return 4;
    }
    if (strcmp(t, "long long") == 0 || strcmp(t, "signed long long") == 0 || strcmp(t, "unsigned long long") == 0 ||
        strcmp(t, "int64_t") == 0 || strcmp(t, "uint64_t") == 0 || strcmp(t, "i64") == 0 || strcmp(t, "u64") == 0 ||
        strcmp(t, "double") == 0 || strcmp(t, "size_t") == 0 || strcmp(t, "ssize_t") == 0 ||
        strcmp(t, "ptrdiff_t") == 0 || strcmp(t, "intptr_t") == 0 || strcmp(t, "uintptr_t") == 0 ||
        strcmp(t, "HANDLE") == 0 || strcmp(t, "HWND") == 0 || strcmp(t, "HMODULE") == 0 ||
        strcmp(t, "HINSTANCE") == 0 || strcmp(t, "LPVOID") == 0 || strcmp(t, "PVOID") == 0 ||
        strcmp(t, "LPCSTR") == 0 || strcmp(t, "LPSTR") == 0 || strcmp(t, "LPCWSTR") == 0 ||
        strcmp(t, "LPWSTR") == 0 || strcmp(t, "QWORD") == 0 || strcmp(t, "SIZE_T") == 0 ||
        strcmp(t, "ULONG64") == 0 || strcmp(t, "UINT64") == 0 || strcmp(t, "INT64") == 0 ||
        strcmp(t, "LONGLONG") == 0 || strcmp(t, "ULONGLONG") == 0) {
        return 8;
    }
    return 0;
}

static int typ_sizeof_depth(const typ_store *s, const char *type_name, int depth) {
    if (!type_name || !type_name[0] || depth > 8) return 0;

    char clean[64];
    typ_clean_name(type_name, clean, sizeof(clean));
    if (!clean[0]) return 0;

    char *lb = strchr(clean, '[');
    if (lb) {
        *lb = 0;
        int cnt = atoi(lb + 1);
        int esz = typ_sizeof_depth(s, clean, depth + 1);
        return (cnt > 0 && esz > 0) ? esz * cnt : 0;
    }

    if (strchr(clean, '*') != NULL) return 8;

    int ps = typ_prim_size(clean);
    if (ps > 0) return ps;

    const typ_def *d = typ_find(s, clean);
    if (!d) return 0;
    if (d->kind == TYP_TYPEDEF && d->size == 0 && d->nmem > 0) {
        return typ_sizeof_depth(s, d->mems[0].type, depth + 1);
    }
    return d->size;
}

int typ_sizeof(const typ_store *s, const char *type_name) {
    return typ_sizeof_depth(s, type_name, 0);
}

static int typ_alignof_depth(const typ_store *s, const char *type_name, int depth) {
    if (!type_name || !type_name[0] || depth > 8) return 1;

    char clean[64];
    typ_clean_name(type_name, clean, sizeof(clean));
    char *lb = strchr(clean, '[');
    if (lb) *lb = 0;

    if (strchr(clean, '*') != NULL) return 8;
    int ps = typ_prim_size(clean);
    if (ps > 0) return ps;

    const typ_def *d = typ_find(s, clean);
    if (!d) return 4;
    if (d->kind == TYP_ENUM) return 4;
    if (d->kind == TYP_TYPEDEF && d->nmem > 0) return typ_alignof_depth(s, d->mems[0].type, depth + 1);
    if (d->kind == TYP_STRUCT) {
        int ma = 1;
        for (int i = 0; i < d->nmem; i++) {
            int a = typ_alignof_depth(s, d->mems[i].type, depth + 1);
            if (a > ma) ma = a;
        }
        return ma > 8 ? 8 : ma;
    }
    return 4;
}

static bool typ_upsert(typ_store *s, const typ_def *def) {
    if (!def->name[0]) return false;
    for (uint32_t i = 0; i < s->ndef; i++) {
        if (strcmp(s->defs[i].name, def->name) == 0) {
            s->defs[i] = *def;
            return true;
        }
    }
    if (s->ndef == s->cap) {
        uint32_t nc = s->cap ? s->cap * 2 : 32;
        typ_def *nd = (typ_def *)realloc(s->defs, (size_t)nc * sizeof(typ_def));
        if (!nd) return false;
        s->defs = nd;
        s->cap = nc;
    }
    s->defs[s->ndef++] = *def;
    return true;
}

static const char *typ_skip(const char *p) {
    for (;;) {
        while (*p && isspace((unsigned char)*p)) p++;
        if (p[0] == '/' && p[1] == '/') {
            p += 2;
            while (*p && *p != '\n') p++;
            continue;
        }
        if (p[0] == '/' && p[1] == '*') {
            p += 2;
            while (*p && !(p[0] == '*' && p[1] == '/')) p++;
            if (*p) p += 2;
            continue;
        }
        break;
    }
    return p;
}

static bool typ_is_ident_ch(char c) {
    return isalnum((unsigned char)c) || c == '_';
}

static const char *typ_read_ident(const char *p, char *dst, size_t max) {
    p = typ_skip(p);
    size_t k = 0;
    while (*p && typ_is_ident_ch(*p) && k + 1 < max) dst[k++] = *p++;
    dst[k] = 0;
    return p;
}

static const char *typ_parse_int(const char *p, int *val) {
    p = typ_skip(p);
    int neg = 0;
    if (*p == '-') { neg = 1; p++; p = typ_skip(p); }
    else if (*p == '+') { p++; p = typ_skip(p); }
    long long v = 0;
    char *end = NULL;
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) v = (long long)strtoull(p + 2, &end, 16);
    else v = strtoll(p, &end, 10);
    *val = neg ? (int)(-v) : (int)v;
    return end ? end : p;
}

static const char *typ_parse_struct(typ_store *s, const char *p, int is_typedef, bool *added) {
    char tag[40] = "";
    p = typ_skip(p);
    if (typ_is_ident_ch(*p)) p = typ_read_ident(p, tag, sizeof(tag));
    p = typ_skip(p);
    if (*p != '{') {
        while (*p && *p != ';') p++;
        if (*p == ';') p++;
        return p;
    }
    p++;

    typ_def def;
    memset(&def, 0, sizeof(def));
    def.kind = TYP_STRUCT;

    int off = 0, max_al = 1;
    while (*p) {
        p = typ_skip(p);
        if (*p == '}') { p++; break; }
        if (*p == ';') { p++; continue; }

        const char *stmt_end = strchr(p, ';');
        const char *brace_end = strchr(p, '}');
        if (!stmt_end || (brace_end && brace_end < stmt_end)) break;

        char line[128];
        size_t slen = (size_t)(stmt_end - p);
        if (slen >= sizeof(line)) slen = sizeof(line) - 1;
        memcpy(line, p, slen);
        line[slen] = 0;
        p = stmt_end + 1;

        // split optional [N] array suffix
        int arr_cnt = 1;
        char *lb = strchr(line, '[');
        if (lb) {
            int n = atoi(lb + 1);
            if (n > 0) arr_cnt = n;
            *lb = 0;
        }

        // peel member name from right end
        size_t n = strlen(line);
        while (n > 0 && isspace((unsigned char)line[n - 1])) line[--n] = 0;
        size_t nm_end = n;
        while (n > 0 && typ_is_ident_ch(line[n - 1])) n--;
        if (n == nm_end) continue;

        char mname[32];
        size_t mlen = nm_end - n;
        if (mlen >= sizeof(mname)) mlen = sizeof(mname) - 1;
        memcpy(mname, line + n, mlen);
        mname[mlen] = 0;
        line[n] = 0;

        char mtype[40];
        typ_clean_name(line, mtype, sizeof(mtype));
        if (!mtype[0]) continue;

        // compact spaces before pointer stars
        char tnorm[32];
        size_t tk = 0;
        for (size_t i = 0; mtype[i] && tk + 1 < sizeof(tnorm); i++) {
            if (mtype[i] == ' ' && mtype[i + 1] == '*') continue;
            tnorm[tk++] = mtype[i];
        }
        tnorm[tk] = 0;

        int fsz = typ_sizeof(s, tnorm);
        int fal = typ_alignof_depth(s, tnorm, 0);
        if (fsz <= 0) { fsz = 8; fal = 8; }
        if (fal < 1) fal = 1;
        if (fal > 8) fal = 8;

        off = (off + fal - 1) & ~(fal - 1);
        if (def.nmem < 32) {
            typ_member *m = &def.mems[def.nmem++];
            snprintf(m->name, sizeof(m->name), "%s", mname);
            if (arr_cnt > 1) snprintf(m->type, sizeof(m->type), "%s[%d]", tnorm, arr_cnt);
            else snprintf(m->type, sizeof(m->type), "%s", tnorm);
            m->off = off;
            m->size = fsz * arr_cnt;
        }
        off += fsz * arr_cnt;
        if (fal > max_al) max_al = fal;
    }

    def.size = (off + max_al - 1) & ~(max_al - 1);

    char alias[40] = "";
    p = typ_skip(p);
    if (is_typedef && typ_is_ident_ch(*p)) p = typ_read_ident(p, alias, sizeof(alias));
    p = typ_skip(p);
    if (*p == ';') p++;

    const char *final_name = alias[0] ? alias : tag;
    if (final_name[0]) {
        snprintf(def.name, sizeof(def.name), "%s", final_name);
        if (typ_upsert(s, &def)) *added = true;
        if (alias[0] && tag[0] && strcmp(alias, tag) != 0) {
            snprintf(def.name, sizeof(def.name), "%s", tag);
            typ_upsert(s, &def);
        }
    }
    return p;
}

static const char *typ_parse_enum(typ_store *s, const char *p, int is_typedef, bool *added) {
    char tag[40] = "";
    p = typ_skip(p);
    if (typ_is_ident_ch(*p)) p = typ_read_ident(p, tag, sizeof(tag));
    p = typ_skip(p);
    if (*p != '{') {
        while (*p && *p != ';') p++;
        if (*p == ';') p++;
        return p;
    }
    p++;

    typ_def def;
    memset(&def, 0, sizeof(def));
    def.kind = TYP_ENUM;
    def.size = 4;

    int next_val = 0;
    while (*p) {
        p = typ_skip(p);
        if (*p == '}') { p++; break; }
        if (*p == ',') { p++; continue; }

        char ename[32];
        p = typ_read_ident(p, ename, sizeof(ename));
        if (!ename[0]) { p++; continue; }

        p = typ_skip(p);
        int val = next_val;
        if (*p == '=') {
            p++;
            p = typ_parse_int(p, &val);
        }
        next_val = val + 1;

        if (def.nmem < 32) {
            typ_member *m = &def.mems[def.nmem++];
            snprintf(m->name, sizeof(m->name), "%s", ename);
            snprintf(m->type, sizeof(m->type), "int");
            m->off = val;
            m->size = 4;
        }
        p = typ_skip(p);
        if (*p == ',') p++;
    }

    char alias[40] = "";
    p = typ_skip(p);
    if (is_typedef && typ_is_ident_ch(*p)) p = typ_read_ident(p, alias, sizeof(alias));
    p = typ_skip(p);
    if (*p == ';') p++;

    const char *final_name = alias[0] ? alias : tag;
    if (final_name[0]) {
        snprintf(def.name, sizeof(def.name), "%s", final_name);
        if (typ_upsert(s, &def)) *added = true;
    }
    return p;
}

static const char *typ_parse_typedef(typ_store *s, const char *p, bool *added) {
    const char *semi = strchr(p, ';');
    if (!semi) return p + strlen(p);

    char buf[128];
    size_t len = (size_t)(semi - p);
    if (len >= sizeof(buf)) len = sizeof(buf) - 1;
    memcpy(buf, p, len);
    buf[len] = 0;

    size_t n = strlen(buf);
    while (n > 0 && isspace((unsigned char)buf[n - 1])) buf[--n] = 0;
    size_t end = n;
    while (n > 0 && typ_is_ident_ch(buf[n - 1])) n--;
    if (n < end && n > 0) {
        typ_def def;
        memset(&def, 0, sizeof(def));
        def.kind = TYP_TYPEDEF;
        size_t nlen = end - n;
        if (nlen >= sizeof(def.name)) nlen = sizeof(def.name) - 1;
        memcpy(def.name, buf + n, nlen);
        def.name[nlen] = 0;
        buf[n] = 0;

        char base[40];
        typ_clean_name(buf, base, sizeof(base));
        size_t tk = 0;
        for (size_t i = 0; base[i] && tk + 1 < sizeof(def.mems[0].type); i++) {
            if (base[i] == ' ' && base[i + 1] == '*') continue;
            def.mems[0].type[tk++] = base[i];
        }
        def.mems[0].type[tk] = 0;
        snprintf(def.mems[0].name, sizeof(def.mems[0].name), "alias");
        def.size = typ_sizeof(s, def.mems[0].type);
        def.mems[0].size = def.size;
        def.nmem = 1;
        if (def.mems[0].type[0] && typ_upsert(s, &def)) *added = true;
    }
    return semi + 1;
}

bool typ_parse_c(typ_store *s, const char *decl) {
    if (!s || !decl || !decl[0]) return false;

    bool added = false;
    const char *p = decl;
    while (*p) {
        p = typ_skip(p);
        if (!*p) break;
        if (*p == ';') { p++; continue; }

        char kw[32];
        const char *q = typ_read_ident(p, kw, sizeof(kw));
        if (strcmp(kw, "struct") == 0) {
            p = typ_parse_struct(s, q, 0, &added);
        } else if (strcmp(kw, "enum") == 0) {
            p = typ_parse_enum(s, q, 0, &added);
        } else if (strcmp(kw, "typedef") == 0) {
            char kw2[32];
            const char *q2 = typ_read_ident(q, kw2, sizeof(kw2));
            const char *peek = typ_skip(q2);
            if (strcmp(kw2, "struct") == 0 && (strchr(peek, '{') != NULL) &&
                (!strchr(peek, ';') || strchr(peek, '{') < strchr(peek, ';'))) {
                p = typ_parse_struct(s, q2, 1, &added);
            } else if (strcmp(kw2, "enum") == 0 && (strchr(peek, '{') != NULL) &&
                       (!strchr(peek, ';') || strchr(peek, '{') < strchr(peek, ';'))) {
                p = typ_parse_enum(s, q2, 1, &added);
            } else {
                p = typ_parse_typedef(s, q, &added);
            }
        } else {
            while (*p && *p != ';') p++;
            if (*p == ';') p++;
        }
    }

    return added;
}

static FILE *typ_fopen_utf8(const char *path, const wchar_t *mode) {
    if (!path || !path[0]) return NULL;
    UINT cp = CP_UTF8;
    DWORD flags = MB_ERR_INVALID_CHARS;
    int wn = MultiByteToWideChar(cp, flags, path, -1, NULL, 0);
    if (wn <= 0 && GetLastError() == ERROR_NO_UNICODE_TRANSLATION) {
        cp = CP_ACP;
        flags = 0;
        wn = MultiByteToWideChar(cp, flags, path, -1, NULL, 0);
    }
    if (wn <= 0) return NULL;
    wchar_t wstack[1024];
    wchar_t *wpath = ((size_t)wn <= 1024) ? wstack : (wchar_t *)malloc((size_t)wn * sizeof(wchar_t));
    if (!wpath) return NULL;
    FILE *f = NULL;
    if (MultiByteToWideChar(cp, flags, path, -1, wpath, wn) > 0) f = _wfopen(wpath, mode);
    if (wpath != wstack) free(wpath);
    return f;
}

bool typ_save_file(const typ_store *s, const char *path) {
    if (!s || !path || !path[0]) return false;

    FILE *f = typ_fopen_utf8(path, L"w");
    if (!f) return false;

    for (uint32_t i = 0; i < s->ndef; i++) {
        const typ_def *d = &s->defs[i];
        if (d->kind == TYP_TYPEDEF && d->nmem > 0) {
            fprintf(f, "typedef %s %s;\n\n", d->mems[0].type, d->name);
        } else if (d->kind == TYP_ENUM) {
            fprintf(f, "enum %s {\n", d->name);
            for (int k = 0; k < d->nmem; k++) {
                fprintf(f, "    %s = %d%s\n", d->mems[k].name, d->mems[k].off, (k + 1 < d->nmem) ? "," : "");
            }
            fprintf(f, "};\n\n");
        } else {
            fprintf(f, "struct %s {\n", d->name);
            for (int k = 0; k < d->nmem; k++) {
                const char *lb = strchr(d->mems[k].type, '[');
                if (lb) {
                    int blen = (int)(lb - d->mems[k].type);
                    fprintf(f, "    %.*s %s%s;\n", blen, d->mems[k].type, d->mems[k].name, lb);
                } else {
                    fprintf(f, "    %s %s;\n", d->mems[k].type, d->mems[k].name);
                }
            }
            fprintf(f, "};\n\n");
        }
    }

    bool ok = !ferror(f);
    fclose(f);
    return ok;
}

bool typ_load_file(typ_store *s, const char *path) {
    if (!s || !path || !path[0]) return false;

    FILE *f = typ_fopen_utf8(path, L"rb");
    if (!f) return false;

    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return false; }
    long fsz = ftell(f);
    if (fsz < 0 || fsz > 4 * 1024 * 1024) { fclose(f); return false; }
    rewind(f);

    char *buf = (char *)malloc((size_t)fsz + 1);
    if (!buf) { fclose(f); return false; }
    size_t rd = fsz > 0 ? fread(buf, 1, (size_t)fsz, f) : 0;
    buf[rd] = 0;
    fclose(f);

    bool ok = (rd == 0) ? true : typ_parse_c(s, buf);
    free(buf);
    return ok;
}
