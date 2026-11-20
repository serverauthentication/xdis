#include "bin.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    ULONG   SizeOfStruct;
    ULONG   TypeIndex;
    ULONG64 Reserved[2];
    ULONG   Index;
    ULONG   Size;
    ULONG64 ModBase;
    ULONG   Flags;
    ULONG64 Value;
    ULONG64 Address;
    ULONG   Register;
    ULONG   Scope;
    ULONG   Tag;
    ULONG   NameLen;
    ULONG   MaxNameLen;
    CHAR    Name[1];
} pdb_sym_info;

_Static_assert(sizeof(pdb_sym_info) == 88, "SYMBOL_INFO layout");

typedef BOOL    (CALLBACK *pdb_enum_fn)(pdb_sym_info *, ULONG, PVOID);
typedef DWORD   (WINAPI *pdb_set_opt_fn)(DWORD);
typedef BOOL    (WINAPI *pdb_init_fn)(HANDLE, PCSTR, BOOL);
typedef DWORD64 (WINAPI *pdb_load_mod_fn)(HANDLE, HANDLE, PCSTR, PCSTR, DWORD64, DWORD, PVOID, DWORD);
typedef BOOL    (WINAPI *pdb_enum_sym_fn)(HANDLE, ULONG64, PCSTR, pdb_enum_fn, PVOID);
typedef BOOL    (WINAPI *pdb_cleanup_fn)(HANDLE);

typedef struct {
    bin_img *b;
    uint32_t added;
} pdb_ctx;

static bool pdb_add_clean(bin_img *b, uint64_t va, const char *raw, uint8_t kind) {
    if (!raw || !raw[0] || !va) return false;
    char clean[256];
    const char *name = dem_name(raw, clean, sizeof(clean)) ? clean : raw;
    return bin_add_sym(b, va, name, kind);
}

static bool pdb_parse_hex(const char *s, uint64_t *out) {
    if (!s || !s[0]) return false;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s += 2;
    if (!s[0]) return false;

    uint64_t v = 0;
    int digs = 0;
    while (*s) {
        int d;
        if (*s >= '0' && *s <= '9') d = *s - '0';
        else if (*s >= 'a' && *s <= 'f') d = 10 + (*s - 'a');
        else if (*s >= 'A' && *s <= 'F') d = 10 + (*s - 'A');
        else return false;
        if (digs >= 16) return false;
        v = (v << 4) | (uint64_t)d;
        digs++;
        s++;
    }
    *out = v;
    return digs > 0;
}

static bool pdb_match_secoff(const char *p, const char **next) {
    int n1 = 0;
    while (isxdigit((unsigned char)*p) && n1 < 5) { p++; n1++; }
    if (n1 == 0 || n1 > 4 || *p != ':') return false;
    p++;
    int n2 = 0;
    while (isxdigit((unsigned char)*p) && n2 < 9) { p++; n2++; }
    if (n2 == 0 || n2 > 8) return false;
    if (*p != ' ' && *p != '\t') return false;
    while (*p == ' ' || *p == '\t') p++;
    *next = p;
    return true;
}

static size_t pdb_next_tok(const char **pp, char *dst, size_t max) {
    const char *p = *pp;
    while (*p == ' ' || *p == '\t') p++;
    size_t n = 0;
    while (*p && *p != ' ' && *p != '\t' && *p != '\r' && *p != '\n') {
        if (n + 1 < max) dst[n] = *p;
        n++;
        p++;
    }
    if (max) dst[n < max ? n : max - 1] = 0;
    *pp = p;
    return n;
}

static uint32_t pdb_load_map(bin_img *b, const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return 0;

    uint64_t pref_base = 0;
    uint32_t added = 0;
    char line[1024];

    while (fgets(line, sizeof(line), f)) {
        const char *p = line;
        while (*p == ' ' || *p == '\t') p++;

        if (strncmp(p, "Preferred load address is ", 26) == 0) {
            char tok[64];
            p += 26;
            if (pdb_next_tok(&p, tok, sizeof(tok)) > 0) pdb_parse_hex(tok, &pref_base);
            continue;
        }

        const char *rest = NULL;
        if (!pdb_match_secoff(p, &rest)) continue;

        char sym[512], vatok[64], flg[16];
        if (pdb_next_tok(&rest, sym, sizeof(sym)) == 0) continue;
        if (pdb_next_tok(&rest, vatok, sizeof(vatok)) == 0) continue;

        uint64_t va = 0;
        if (!pdb_parse_hex(vatok, &va) || va == 0) continue;

        if (pref_base && b->base && pref_base != b->base &&
            !bin_sec_at(b, va) && va >= pref_base) {
            va = b->base + (va - pref_base);
        }

        bool is_fn = false;
        if (pdb_next_tok(&rest, flg, sizeof(flg)) == 1 && flg[0] == 'f') is_fn = true;
        uint8_t kind = (is_fn || bin_is_exec(b, va)) ? BIN_SYM_FUNC : BIN_SYM_DATA;

        if (pdb_add_clean(b, va, sym, kind)) added++;
    }

    fclose(f);
    return added;
}

static BOOL CALLBACK pdb_enum_cb(pdb_sym_info *info, ULONG sym_size, PVOID user) {
    (void)sym_size;
    pdb_ctx *ctx = (pdb_ctx *)user;
    if (!info || !info->Address || !info->Name[0]) return TRUE;

    uint8_t kind = (info->Tag == 5 || info->Tag == 22 || bin_is_exec(ctx->b, info->Address))
                   ? BIN_SYM_FUNC : BIN_SYM_DATA;
    if (pdb_add_clean(ctx->b, info->Address, info->Name, kind)) ctx->added++;
    return TRUE;
}

static DWORD pdb_file_size32(const char *path) {
    WIN32_FILE_ATTRIBUTE_DATA fad;
    if (!GetFileAttributesExA(path, GetFileExInfoStandard, &fad)) return 0x10000000U;
    if (fad.nFileSizeHigh != 0 || fad.nFileSizeLow == 0) return 0x10000000U;
    return fad.nFileSizeLow;
}

static uint32_t pdb_load_dbghelp(bin_img *b, const char *path) {
    HMODULE mod = LoadLibraryA("dbghelp.dll");
    if (!mod) return 0;

    pdb_set_opt_fn  set_opt = (pdb_set_opt_fn)GetProcAddress(mod, "SymSetOptions");
    pdb_init_fn     init_fn = (pdb_init_fn)GetProcAddress(mod, "SymInitialize");
    pdb_load_mod_fn load_fn = (pdb_load_mod_fn)GetProcAddress(mod, "SymLoadModuleEx");
    pdb_enum_sym_fn enum_fn = (pdb_enum_sym_fn)GetProcAddress(mod, "SymEnumSymbols");
    pdb_cleanup_fn  clean_fn = (pdb_cleanup_fn)GetProcAddress(mod, "SymCleanup");

    if (!init_fn || !load_fn || !enum_fn || !clean_fn) {
        FreeLibrary(mod);
        return 0;
    }

    if (set_opt) set_opt(0x00080000U | 0x00000040U);

    // unique pseudo-handle avoids colliding with process sym session
    HANDLE hp = (HANDLE)(uintptr_t)b;
    if (!init_fn(hp, NULL, FALSE)) {
        FreeLibrary(mod);
        return 0;
    }

    uint64_t base = b->base ? b->base : 0x10000000ULL;
    DWORD dll_sz = 0;
    if (b->max_va > base && b->max_va - base <= 0x7FFFFFFFULL) {
        dll_sz = (DWORD)(b->max_va - base);
    } else {
        dll_sz = pdb_file_size32(path);
    }

    uint32_t added = 0;
    DWORD64 mb = load_fn(hp, NULL, path, NULL, base, dll_sz, NULL, 0);
    if (mb != 0) {
        pdb_ctx ctx = {b, 0};
        enum_fn(hp, mb, "*", pdb_enum_cb, &ctx);
        added = ctx.added;
    }

    clean_fn(hp);
    FreeLibrary(mod);
    return added;
}

static uint16_t pdb_u16(const uint8_t *d, size_t sz, size_t off) {
    if (off > sz || sz - off < 2) return 0;
    uint16_t v;
    memcpy(&v, d + off, 2);
    return v;
}

static uint32_t pdb_u32(const uint8_t *d, size_t sz, size_t off) {
    if (off > sz || sz - off < 4) return 0;
    uint32_t v;
    memcpy(&v, d + off, 4);
    return v;
}

static uint8_t *pdb_msf_gather(const uint8_t *d, uint64_t fsz, uint32_t blk_sz,
                               uint32_t num_blks, const uint8_t *blks, uint32_t nblk, uint32_t total) {
    if (total == 0 || total > 64U * 1024U * 1024U) return NULL;
    uint8_t *buf = (uint8_t *)malloc(total);
    if (!buf) return NULL;

    uint32_t done = 0;
    for (uint32_t i = 0; i < nblk && done < total; i++) {
        uint32_t bi = pdb_u32(blks, (size_t)nblk * 4, (size_t)i * 4);
        if (bi >= num_blks) { free(buf); return NULL; }
        uint64_t foff = (uint64_t)bi * blk_sz;
        uint32_t take = total - done;
        if (take > blk_sz) take = blk_sz;
        if (foff > fsz || fsz - foff < take) { free(buf); return NULL; }
        memcpy(buf + done, d + foff, take);
        done += take;
    }
    if (done != total) { free(buf); return NULL; }
    return buf;
}

static uint8_t *pdb_msf_stream(const uint8_t *d, uint64_t fsz, uint32_t blk_sz, uint32_t num_blks,
                               const uint8_t *dir, uint32_t dir_sz, uint32_t idx, uint32_t *out_sz) {
    uint32_t nstr = pdb_u32(dir, dir_sz, 0);
    if (idx >= nstr || nstr > 65536) return NULL;
    size_t sz_end = 4 + (size_t)nstr * 4;
    if (sz_end > dir_sz) return NULL;

    size_t blk_off = sz_end;
    for (uint32_t i = 0; i <= idx; i++) {
        uint32_t ssz = pdb_u32(dir, dir_sz, 4 + (size_t)i * 4);
        uint32_t nb = 0;
        if (ssz != 0xFFFFFFFFU && ssz != 0) {
            if (ssz > 64U * 1024U * 1024U) return NULL;
            nb = (ssz + blk_sz - 1) / blk_sz;
        }
        if (i == idx) {
            if (nb == 0) return NULL;
            if (blk_off > dir_sz || (dir_sz - blk_off) / 4 < nb) return NULL;
            uint8_t *res = pdb_msf_gather(d, fsz, blk_sz, num_blks, dir + blk_off, nb, ssz);
            if (res) *out_sz = ssz;
            return res;
        }
        if (blk_off > dir_sz || (dir_sz - blk_off) / 4 < nb) return NULL;
        blk_off += (size_t)nb * 4;
    }
    return NULL;
}

static uint32_t pdb_load_msf(bin_img *b, const char *path) {
    map_file mf;
    if (!map_open(&mf, path)) return 0;

    uint32_t added = 0;
    uint8_t *dir = NULL, *dbi = NULL, *syms = NULL;
    const uint8_t *d = mf.data;
    uint64_t fsz = mf.size;

    if (fsz < 56 || memcmp(d, "Microsoft C/C++ MSF 7.00", 24) != 0) goto done;

    uint32_t blk_sz   = pdb_u32(d, (size_t)(fsz > 64 ? 64 : fsz), 32);
    uint32_t num_blks = pdb_u32(d, (size_t)(fsz > 64 ? 64 : fsz), 40);
    uint32_t dir_sz   = pdb_u32(d, (size_t)(fsz > 64 ? 64 : fsz), 44);
    uint32_t map_blk  = pdb_u32(d, (size_t)(fsz > 64 ? 64 : fsz), 52);

    if (blk_sz != 512 && blk_sz != 1024 && blk_sz != 2048 && blk_sz != 4096) goto done;
    if (num_blks == 0 || dir_sz < 4 || dir_sz > 64U * 1024U * 1024U || map_blk >= num_blks) goto done;

    uint32_t dir_blks = (dir_sz + blk_sz - 1) / blk_sz;
    uint64_t map_off = (uint64_t)map_blk * blk_sz;
    if (map_off > fsz || fsz - map_off < (uint64_t)dir_blks * 4) goto done;

    dir = pdb_msf_gather(d, fsz, blk_sz, num_blks, d + map_off, dir_blks, dir_sz);
    if (!dir) goto done;

    uint32_t dbi_sz = 0;
    dbi = pdb_msf_stream(d, fsz, blk_sz, num_blks, dir, dir_sz, 3, &dbi_sz);
    if (!dbi || dbi_sz < 64) goto done;

    uint16_t sym_idx = pdb_u16(dbi, dbi_sz, 20);
    if (sym_idx == 0xFFFFU) goto done;

    uint32_t sym_sz = 0;
    syms = pdb_msf_stream(d, fsz, blk_sz, num_blks, dir, dir_sz, sym_idx, &sym_sz);
    if (!syms) goto done;

    size_t pos = 0;
    while (pos + 4 <= sym_sz) {
        uint16_t rlen  = pdb_u16(syms, sym_sz, pos);
        uint16_t rtype = pdb_u16(syms, sym_sz, pos + 2);
        if (rlen < 2 || (size_t)rlen + 2 > sym_sz - pos) break;

        if (rtype == 0x110EU && rlen >= 13) {
            uint32_t flags = pdb_u32(syms, sym_sz, pos + 4);
            uint32_t off   = pdb_u32(syms, sym_sz, pos + 8);
            uint16_t seg   = pdb_u16(syms, sym_sz, pos + 12);
            size_t nmax = (size_t)rlen - 12;
            char name[256];
            size_t n = 0;
            while (n < nmax && n + 1 < sizeof(name) && syms[pos + 14 + n] != 0) {
                name[n] = (char)syms[pos + 14 + n];
                n++;
            }
            name[n] = 0;

            uint64_t va = 0;
            if (seg >= 1 && seg <= b->nsec) va = b->secs[seg - 1].va + off;
            else if (seg == 1 && b->base) va = b->base + off;

            if (va && n > 0) {
                uint8_t kind = ((flags & 2U) || bin_is_exec(b, va)) ? BIN_SYM_FUNC : BIN_SYM_DATA;
                if (pdb_add_clean(b, va, name, kind)) added++;
            }
        }
        pos += (size_t)rlen + 2;
    }

done:
    free(syms);
    free(dbi);
    free(dir);
    map_close(&mf);
    return added;
}

static bool pdb_ends_pdb(const char *path) {
    size_t n = strlen(path);
    if (n < 4) return false;
    return tolower((unsigned char)path[n - 4]) == '.' &&
           tolower((unsigned char)path[n - 3]) == 'p' &&
           tolower((unsigned char)path[n - 2]) == 'd' &&
           tolower((unsigned char)path[n - 1]) == 'b';
}

uint32_t pdb_load_file(bin_img *b, const char *path) {
    if (!b || !path || !path[0]) return 0;

    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    char hdr[32];
    size_t nr = fread(hdr, 1, sizeof(hdr), f);
    fclose(f);

    if (nr >= 24 && memcmp(hdr, "Microsoft C/C++ MSF 7.00", 24) == 0) {
        uint32_t n = pdb_load_dbghelp(b, path);
        return n > 0 ? n : pdb_load_msf(b, path);
    }
    if (pdb_ends_pdb(path)) return pdb_load_dbghelp(b, path);
    return pdb_load_map(b, path);
}
