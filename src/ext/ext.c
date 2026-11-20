#include "ext.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>

typedef int (*ext_init_fn)(const xdis_api *api);

static void ext_api_log(void *ctx, const char *msg) {
    ext_host *h = (ext_host *)ctx;
    if (h->log_fn && msg) h->log_fn(h->ui_ud, msg);
}

static const char *ext_api_path(void *ctx) {
    ext_host *h = (ext_host *)ctx;
    return h->ana ? h->ana->bin.path : "";
}

static uint32_t ext_api_nsec(void *ctx) {
    ext_host *h = (ext_host *)ctx;
    return h->ana ? h->ana->bin.nsec : 0;
}

static int ext_api_sec(void *ctx, uint32_t idx, char *name, size_t nmax,
                       uint64_t *va, uint64_t *vsize, uint64_t *fsize, uint32_t *perm) {
    ext_host *h = (ext_host *)ctx;
    if (!h->ana || idx >= h->ana->bin.nsec) return 0;
    const bin_sec *s = &h->ana->bin.secs[idx];
    if (name && nmax) snprintf(name, nmax, "%s", s->name);
    if (va) *va = s->va;
    if (vsize) *vsize = s->vsize;
    if (fsize) *fsize = s->fsize;
    if (perm) *perm = s->perm;
    return 1;
}

static size_t ext_api_read(void *ctx, uint64_t va, uint8_t *dst, size_t len) {
    ext_host *h = (ext_host *)ctx;
    return h->ana ? bin_read(&h->ana->bin, va, dst, len) : 0;
}

static uint32_t ext_api_nfunc(void *ctx) {
    ext_host *h = (ext_host *)ctx;
    return h->ana ? h->ana->nfunc : 0;
}

static int ext_api_func(void *ctx, uint32_t idx, uint64_t *start, uint64_t *end, const char **name) {
    ext_host *h = (ext_host *)ctx;
    if (!h->ana || idx >= h->ana->nfunc) return 0;
    const ana_func *f = &h->ana->funcs[idx];
    if (start) *start = f->start;
    if (end) *end = f->end;
    if (name) *name = ana_pool_str(h->ana, f->name_off);
    return 1;
}

static const char *ext_api_sym(void *ctx, uint64_t va) {
    ext_host *h = (ext_host *)ctx;
    return h->ana ? ana_sym_at(h->ana, va) : NULL;
}

static void ext_api_set_name(void *ctx, uint64_t va, const char *name) {
    ext_host *h = (ext_host *)ctx;
    if (h->ana) ana_set_name(h->ana, va, name);
}

static void ext_api_set_cmt(void *ctx, uint64_t va, const char *text) {
    ext_host *h = (ext_host *)ctx;
    if (h->ana) ana_set_cmt(h->ana, va, text);
}

static uint64_t ext_api_cur_va(void *ctx) {
    ext_host *h = (ext_host *)ctx;
    return h->get_va_fn ? h->get_va_fn(h->ui_ud) : 0;
}

static void ext_api_goto_va(void *ctx, uint64_t va) {
    ext_host *h = (ext_host *)ctx;
    if (h->set_va_fn) h->set_va_fn(h->ui_ud, va);
}

static int ext_api_add_cmd(void *ctx, const char *name, xdis_cmd_fn fn, void *ud) {
    ext_host *h = (ext_host *)ctx;
    if (!name || !name[0] || !fn || h->ncmd >= 64) return 0;
    snprintf(h->cmds[h->ncmd].name, sizeof(h->cmds[h->ncmd].name), "%s", name);
    h->cmds[h->ncmd].fn = fn;
    h->cmds[h->ncmd].ud = ud;
    h->ncmd++;
    return 1;
}

void ext_init(ext_host *h, ana_ctx *a, void *ui_ud, ext_log_fn log_fn, ext_get_va_fn gva, ext_set_va_fn sva) {
    memset(h, 0, sizeof(*h));
    h->ana = a;
    h->ui_ud = ui_ud;
    h->log_fn = log_fn;
    h->get_va_fn = gva;
    h->set_va_fn = sva;

    h->api.version = XDIS_ABI_VER;
    h->api.ctx = h;
    h->api.log = ext_api_log;
    h->api.bin_path = ext_api_path;
    h->api.sec_count = ext_api_nsec;
    h->api.sec_info = ext_api_sec;
    h->api.read_va = ext_api_read;
    h->api.func_count = ext_api_nfunc;
    h->api.func_info = ext_api_func;
    h->api.sym_name = ext_api_sym;
    h->api.set_name = ext_api_set_name;
    h->api.set_cmt = ext_api_set_cmt;
    h->api.cur_va = ext_api_cur_va;
    h->api.goto_va = ext_api_goto_va;
    h->api.add_cmd = ext_api_add_cmd;
}

void ext_free(ext_host *h) {
    if (!h) return;
    for (uint32_t i = 0; i < h->nmod; i++) {
        if (h->mods[i]) FreeLibrary((HMODULE)h->mods[i]);
    }
    memset(h, 0, sizeof(*h));
}

static bool ext_valid_rel_dir(const char *dir) {
    if (!dir || !dir[0]) return false;
    if (dir[0] == '\\' || dir[0] == '/') return false;
    if (strstr(dir, "..") != NULL) return false;
    if (strchr(dir, ':') != NULL) return false;
    for (const unsigned char *p = (const unsigned char *)dir; *p; p++) {
        if (*p < 0x20 || *p == '*' || *p == '?' || *p == '"' || *p == '<' || *p == '>' || *p == '|')
            return false;
    }
    return true;
}

static bool ext_allowlist_has(const char *allow_csv, const char *filename) {
    if (!allow_csv || !allow_csv[0] || !filename || !filename[0]) return false;
    if (strchr(filename, '\\') || strchr(filename, '/') || strchr(filename, ':')) return false;
    size_t fn_len = strlen(filename);

    const char *p = allow_csv;
    while (*p) {
        const char *comma = strchr(p, ',');
        const char *end = comma ? comma : (p + strlen(p));
        const char *s = p;
        const char *e = end;

        while (s < e && isspace((unsigned char)*s)) s++;
        while (e > s && isspace((unsigned char)e[-1])) e--;

        size_t len = (size_t)(e - s);
        if (len > 0) {
            bool ok = true;
            if ((len == 1 && s[0] == '.') || (len == 2 && s[0] == '.' && s[1] == '.'))
                ok = false;
            for (size_t i = 0; i < len && ok; i++) {
                unsigned char c = (unsigned char)s[i];
                if (!(isalnum(c) || c == '.' || c == '_' || c == '-'))
                    ok = false;
                if (c == '.' && i + 1 < len && s[i + 1] == '.')
                    ok = false;
            }
            if (ok && len == fn_len && _strnicmp(s, filename, len) == 0)
                return true;
        }

        if (!comma) break;
        p = comma + 1;
    }
    return false;
}

uint32_t ext_load_dir_allow(ext_host *h, const char *dir, const char *allow_csv) {
    if (!h || !dir || !dir[0] || !allow_csv || !allow_csv[0]) return 0;
    if (!ext_valid_rel_dir(dir)) return 0;

    char clean_dir[MAX_PATH];
    int dn = snprintf(clean_dir, sizeof(clean_dir), "%s", dir);
    if (dn <= 0 || (size_t)dn >= sizeof(clean_dir)) return 0;
    while (dn > 0 && (clean_dir[dn - 1] == '\\' || clean_dir[dn - 1] == '/')) {
        clean_dir[--dn] = '\0';
    }
    if (dn == 0) return 0;

    char exe_path[MAX_PATH];
    DWORD exe_len = GetModuleFileNameA(NULL, exe_path, (DWORD)sizeof(exe_path));
    if (exe_len == 0 || exe_len >= (DWORD)sizeof(exe_path)) return 0;

    char *slash = strrchr(exe_path, '\\');
    char *fslash = strrchr(exe_path, '/');
    if (fslash && (!slash || fslash > slash)) slash = fslash;
    if (!slash) return 0;
    if (slash == exe_path + 2 && exe_path[1] == ':') slash[1] = '\0';
    else *slash = '\0';

    char canon_exe[MAX_PATH];
    DWORD canon_exe_len = GetFullPathNameA(exe_path, (DWORD)sizeof(canon_exe), canon_exe, NULL);
    if (canon_exe_len == 0 || canon_exe_len >= (DWORD)sizeof(canon_exe)) return 0;
    while (canon_exe_len > 0 && (canon_exe[canon_exe_len - 1] == '\\' || canon_exe[canon_exe_len - 1] == '/')) {
        if (canon_exe_len == 3 && canon_exe[1] == ':') break;
        canon_exe[--canon_exe_len] = '\0';
    }
    if (canon_exe_len == 0) return 0;

    bool exe_has_sep = (canon_exe[canon_exe_len - 1] == '\\');
    char raw_base[MAX_PATH * 2];
    int bn = snprintf(raw_base, sizeof(raw_base), "%s%s%s", canon_exe, exe_has_sep ? "" : "\\", clean_dir);
    if (bn <= 0 || (size_t)bn >= sizeof(raw_base)) return 0;

    char canon_base[MAX_PATH];
    DWORD base_len = GetFullPathNameA(raw_base, (DWORD)sizeof(canon_base), canon_base, NULL);
    if (base_len == 0 || base_len >= (DWORD)sizeof(canon_base)) return 0;
    while (base_len > 0 && (canon_base[base_len - 1] == '\\' || canon_base[base_len - 1] == '/')) {
        canon_base[--base_len] = '\0';
    }
    if (exe_has_sep) {
        if (base_len <= canon_exe_len || _strnicmp(canon_base, canon_exe, canon_exe_len) != 0)
            return 0;
    } else {
        if (base_len <= canon_exe_len + 1 ||
            _strnicmp(canon_base, canon_exe, canon_exe_len) != 0 ||
            canon_base[canon_exe_len] != '\\') {
            return 0;
        }
    }

    char pat[MAX_PATH + 16];
    int pn = snprintf(pat, sizeof(pat), "%s\\*.dll", canon_base);
    if (pn <= 0 || (size_t)pn >= sizeof(pat)) return 0;

    WIN32_FIND_DATAA fd;
    HANDLE ff = FindFirstFileA(pat, &fd);
    if (ff == INVALID_HANDLE_VALUE) return 0;

    uint32_t loaded = 0;
    do {
        if (h->nmod >= 32) break;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;

        if (!ext_allowlist_has(allow_csv, fd.cFileName)) {
            char msg[320];
            snprintf(msg, sizeof(msg), "[plugin] skipped (not allowlisted): %s", fd.cFileName);
            if (h->log_fn) h->log_fn(h->ui_ud, msg);
            continue;
        }

        char raw_full[MAX_PATH * 2];
        int fn = snprintf(raw_full, sizeof(raw_full), "%s\\%s", canon_base, fd.cFileName);
        if (fn <= 0 || (size_t)fn >= sizeof(raw_full)) continue;

        char canon_full[MAX_PATH];
        DWORD full_len = GetFullPathNameA(raw_full, (DWORD)sizeof(canon_full), canon_full, NULL);
        if (full_len == 0 || full_len >= (DWORD)sizeof(canon_full)) continue;
        if (full_len <= base_len + 1 ||
            _strnicmp(canon_full, canon_base, base_len) != 0 ||
            canon_full[base_len] != '\\' ||
            strchr(canon_full + base_len + 1, '\\') != NULL) {
            continue;
        }

        HMODULE mod = LoadLibraryExA(canon_full, NULL,
                                     LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (!mod) continue;

        ext_init_fn init = (ext_init_fn)GetProcAddress(mod, "xdis_plugin_init");
        if (!init || !init(&h->api)) {
            FreeLibrary(mod);
            continue;
        }
        h->mods[h->nmod++] = mod;
        loaded++;
    } while (FindNextFileA(ff, &fd));

    FindClose(ff);
    return loaded;
}

uint32_t ext_load_dir(ext_host *h, const char *dir) {
    return ext_load_dir_allow(h, dir, "entropy.dll");
}

bool ext_run(ext_host *h, const char *name, const char *args) {
    for (uint32_t i = 0; i < h->ncmd; i++) {
        if (_stricmp(h->cmds[i].name, name) == 0) {
            h->cmds[i].fn(args ? args : "", h->cmds[i].ud);
            return true;
        }
    }
    return false;
}
