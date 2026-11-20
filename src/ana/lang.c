#include "ana.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LANG_MAX_CLS   1024
#define LANG_MAX_GO    4096
#define LANG_MAX_VT    512
#define LANG_SCAN_CAP  (32ULL * 1024ULL * 1024ULL)

typedef struct {
    lang_cls *classes;
    uint32_t  nclass;
    uint32_t  class_cap;
    lang_sym *go_funcs;
    uint32_t  ngo_func;
    uint32_t  go_cap;
} lang_bld;

void lang_free(lang_info *li) {
    if (!li) return;
    free(li->classes);
    free(li->go_funcs);
    memset(li, 0, sizeof(*li));
}

static bool lang_is_code_ptr(const bin_img *b, uint64_t va) {
    if (va < b->min_va || va >= b->max_va) return false;
    if (!bin_is_exec(b, va)) return false;
    size_t av = 0;
    const uint8_t *p = bin_ptr(b, va, &av);
    return p != NULL && av >= 1 && p[0] != 0x00;
}

static uint32_t lang_count_vmethods(const bin_img *b, uint64_t vt_va, int psz) {
    uint32_t cnt = 0;
    for (uint32_t i = 0; i < 512; i++) {
        uint64_t ptr = 0;
        if (bin_read(b, vt_va + (uint64_t)i * (uint64_t)psz, (uint8_t *)&ptr, (size_t)psz) != (size_t)psz) break;
        if (!lang_is_code_ptr(b, ptr)) break;
        cnt++;
    }
    return cnt;
}

static void lang_add_class(lang_bld *b, const char *name, const char *bases,
                           uint64_t vt_va, uint32_t nmethod, const char *lang) {
    if (!name || !name[0]) return;
    for (uint32_t i = 0; i < b->nclass; i++) {
        lang_cls *c = &b->classes[i];
        if (vt_va && c->vtable_va == vt_va) {
            if (!c->bases[0] && bases && bases[0]) snprintf(c->bases, sizeof(c->bases), "%s", bases);
            if (nmethod > c->nmethod) c->nmethod = nmethod;
            return;
        }
        if (strcmp(c->name, name) == 0 && strcmp(c->lang, lang) == 0) {
            if (!c->vtable_va && vt_va) c->vtable_va = vt_va;
            if (nmethod > c->nmethod) c->nmethod = nmethod;
            if (!c->bases[0] && bases && bases[0]) snprintf(c->bases, sizeof(c->bases), "%s", bases);
            return;
        }
    }
    if (b->nclass >= LANG_MAX_CLS) return;
    if (b->nclass == b->class_cap) {
        uint32_t nc = b->class_cap ? b->class_cap * 2 : 32;
        if (nc > LANG_MAX_CLS) nc = LANG_MAX_CLS;
        lang_cls *p = (lang_cls *)realloc(b->classes, (size_t)nc * sizeof(lang_cls));
        if (!p) return;
        b->classes = p;
        b->class_cap = nc;
    }
    lang_cls *c = &b->classes[b->nclass++];
    memset(c, 0, sizeof(*c));
    snprintf(c->name, sizeof(c->name), "%s", name);
    if (bases && bases[0]) snprintf(c->bases, sizeof(c->bases), "%s", bases);
    c->vtable_va = vt_va;
    c->nmethod = nmethod;
    snprintf(c->lang, sizeof(c->lang), "%s", lang);
}

static void lang_add_go(lang_bld *b, uint64_t va, const char *name) {
    if (!name || !name[0] || b->ngo_func >= LANG_MAX_GO) return;
    if (b->ngo_func == b->go_cap) {
        uint32_t nc = b->go_cap ? b->go_cap * 2 : 128;
        if (nc > LANG_MAX_GO) nc = LANG_MAX_GO;
        lang_sym *p = (lang_sym *)realloc(b->go_funcs, (size_t)nc * sizeof(lang_sym));
        if (!p) return;
        b->go_funcs = p;
        b->go_cap = nc;
    }
    lang_sym *s = &b->go_funcs[b->ngo_func++];
    s->va = va;
    snprintf(s->name, sizeof(s->name), "%s", name);
}

static bool lang_demangle_msvc_td(const char *raw, char *out, size_t max) {
    if (!raw || raw[0] != '.' || raw[1] != '?' || raw[2] != 'A' || !raw[3] || !raw[4]) return false;

    // wrap .?AV... as ??_R0?AV... so dem_name handles it
    char wrapped[112];
    char dem[128];
    snprintf(wrapped, sizeof(wrapped), "??_R0%s", raw + 1);
    if (dem_name(wrapped, dem, sizeof(dem))) {
        const char *suf = "::RTTI Type Descriptor";
        char *hit = strstr(dem, suf);
        if (hit && hit > dem) {
            *hit = 0;
            snprintf(out, max, "%s", dem);
            return out[0] != 0;
        }
    }

    const char *p = raw + 4;
    const char *parts[8];
    size_t lens[8];
    int npart = 0;
    while (*p && npart < 8) {
        if (p[0] == '@' && p[1] == '@') break;
        const char *st = p;
        while (*p && *p != '@') {
            if ((unsigned char)*p < 0x20 || (unsigned char)*p > 0x7E) return false;
            p++;
        }
        if (p > st) {
            parts[npart] = st;
            lens[npart] = (size_t)(p - st);
            npart++;
        }
        if (*p == '@') p++;
    }
    if (npart == 0) return false;

    size_t n = 0;
    for (int i = npart - 1; i >= 0 && n + 1 < max; i--) {
        if (i < npart - 1) n += (size_t)snprintf(out + n, max - n, "::");
        size_t cp = lens[i];
        if (n + cp >= max) cp = max - 1 - n;
        memcpy(out + n, parts[i], cp);
        n += cp;
        out[n] = 0;
    }
    return n > 0;
}

static bool lang_read_msvc_td(const ana_ctx *a, uint64_t td_va, int psz, char *out, size_t max) {
    uint64_t name_off = (psz == 8) ? 16ULL : 8ULL;
    char raw[96];
    memset(raw, 0, sizeof(raw));
    if (bin_read(&a->bin, td_va + name_off, (uint8_t *)raw, sizeof(raw) - 1) < 6) return false;
    return lang_demangle_msvc_td(raw, out, max);
}

static bool lang_try_msvc_rtti(const ana_ctx *a, uint64_t vt_va, uint32_t nmethod, lang_bld *b) {
    int psz = (a->bin.bits == 32) ? 4 : 8;
    if (vt_va < (uint64_t)psz) return false;

    uint64_t col_va = 0;
    if (bin_read(&a->bin, vt_va - (uint64_t)psz, (uint8_t *)&col_va, (size_t)psz) != (size_t)psz) return false;
    if (!bin_sec_at(&a->bin, col_va)) return false;

    uint32_t col[6] = {0};
    size_t col_sz = (psz == 8) ? 24 : 20;
    if (bin_read(&a->bin, col_va, (uint8_t *)col, col_sz) != col_sz) return false;

    uint64_t base = a->bin.base;
    uint64_t td_va = 0, chd_va = 0;
    if (psz == 8) {
        if (col[0] != 1) return false;
        if (col[5] && col_va >= col[5]) base = col_va - col[5];
        td_va = base + col[3];
        chd_va = base + col[4];
    } else {
        if (col[0] != 0) return false;
        td_va = col[3];
        chd_va = col[4];
    }

    char cname[80] = "";
    if (!lang_read_msvc_td(a, td_va, psz, cname, sizeof(cname))) return false;

    char bases[160] = "";
    size_t bn = 0;
    uint32_t chd[4] = {0};
    if (bin_read(&a->bin, chd_va, (uint8_t *)chd, sizeof(chd)) == sizeof(chd) &&
        chd[0] == 0 && chd[2] >= 1 && chd[2] <= 64) {
        uint64_t bca_va = (psz == 8) ? (base + chd[3]) : (uint64_t)chd[3];
        for (uint32_t k = 0; k < chd[2]; k++) {
            uint32_t bcd_ref = 0;
            if (bin_read(&a->bin, bca_va + (uint64_t)k * 4, (uint8_t *)&bcd_ref, 4) != 4) break;
            if (!bcd_ref) continue;
            uint64_t bcd_va = (psz == 8) ? (base + bcd_ref) : (uint64_t)bcd_ref;
            uint32_t btd_ref = 0;
            if (bin_read(&a->bin, bcd_va, (uint8_t *)&btd_ref, 4) != 4 || !btd_ref) continue;
            uint64_t btd_va = (psz == 8) ? (base + btd_ref) : (uint64_t)btd_ref;

            char bname[80] = "";
            if (!lang_read_msvc_td(a, btd_va, psz, bname, sizeof(bname))) continue;
            if (strcmp(bname, cname) == 0) continue;
            if (bn > 0 && strstr(bases, bname) != NULL) continue;
            if (bn + strlen(bname) + 3 >= sizeof(bases)) break;
            if (bn > 0) bn += (size_t)snprintf(bases + bn, sizeof(bases) - bn, ", ");
            bn += (size_t)snprintf(bases + bn, sizeof(bases) - bn, "%s", bname);
        }
    }

    lang_add_class(b, cname, bases, vt_va, nmethod, "C++");
    return true;
}

static bool lang_demangle_it_ti(const char *raw, char *out, size_t max) {
    if (!raw || !raw[0]) return false;
    char wrapped[112], dem[128];
    snprintf(wrapped, sizeof(wrapped), "_ZTI%s", raw);
    if (dem_name(wrapped, dem, sizeof(dem))) {
        const char *pre = "typeinfo for ";
        if (strncmp(dem, pre, strlen(pre)) == 0 && dem[strlen(pre)]) {
            snprintf(out, max, "%s", dem + strlen(pre));
            return true;
        }
    }

    const char *p = raw;
    if (*p == 'N') p++;
    size_t n = 0;
    int seg = 0;
    while (isdigit((unsigned char)*p) && n + 1 < max) {
        int len = 0;
        while (isdigit((unsigned char)*p) && len < 256) { len = len * 10 + (*p - '0'); p++; }
        if (len <= 0 || len > 80) return false;
        if (seg++) n += (size_t)snprintf(out + n, max - n, "::");
        for (int i = 0; i < len && *p && n + 1 < max; i++, p++) {
            if ((unsigned char)*p < 0x20 || (unsigned char)*p > 0x7E) return false;
            out[n++] = *p;
        }
        out[n] = 0;
    }
    return n > 0;
}

static bool lang_read_it_ti(const ana_ctx *a, uint64_t ti_va, int psz, char *out, size_t max) {
    if (!bin_sec_at(&a->bin, ti_va)) return false;
    uint64_t nm_va = 0;
    if (bin_read(&a->bin, ti_va + (uint64_t)psz, (uint8_t *)&nm_va, (size_t)psz) != (size_t)psz) return false;
    if (!bin_sec_at(&a->bin, nm_va)) return false;
    char raw[96];
    memset(raw, 0, sizeof(raw));
    if (bin_read(&a->bin, nm_va, (uint8_t *)raw, sizeof(raw) - 1) < 2) return false;
    return lang_demangle_it_ti(raw, out, max);
}

static bool lang_try_itanium_rtti(const ana_ctx *a, uint64_t vt_va, uint32_t nmethod, lang_bld *b) {
    int psz = (a->bin.bits == 32) ? 4 : 8;
    if (vt_va < (uint64_t)psz) return false;

    uint64_t ti_va = 0;
    if (bin_read(&a->bin, vt_va - (uint64_t)psz, (uint8_t *)&ti_va, (size_t)psz) != (size_t)psz) return false;

    char cname[80] = "";
    if (!lang_read_it_ti(a, ti_va, psz, cname, sizeof(cname))) return false;

    // check __si_class_type_info single base pointer
    char bases[160] = "";
    uint64_t bti_va = 0;
    if (bin_read(&a->bin, ti_va + (uint64_t)psz * 2, (uint8_t *)&bti_va, (size_t)psz) == (size_t)psz &&
        bti_va != ti_va) {
        char bname[80] = "";
        if (lang_read_it_ti(a, bti_va, psz, bname, sizeof(bname)) && strcmp(bname, cname) != 0) {
            snprintf(bases, sizeof(bases), "%s", bname);
        }
    }

    lang_add_class(b, cname, bases, vt_va, nmethod, "C++");
    return true;
}

static void lang_scan_msvc_small_vtables(const ana_ctx *a, lang_bld *b) {
    const bin_img *bin = &a->bin;
    int psz = (bin->bits == 32) ? 4 : 8;
    for (uint32_t si = 0; si < bin->nsec && b->nclass < LANG_MAX_CLS; si++) {
        const bin_sec *s = &bin->secs[si];
        if (!(s->perm & BIN_PERM_R) || (s->perm & BIN_PERM_X)) continue;
        int is_ro = !(s->perm & BIN_PERM_W) || strstr(s->name, "rdata") != NULL;
        if (!is_ro || s->fsize < (uint64_t)psz * 2 || s->foff >= bin->map.size) continue;

        uint64_t sz = s->fsize;
        if (s->foff + sz > bin->map.size) sz = bin->map.size - s->foff;
        if (sz > LANG_SCAN_CAP) sz = LANG_SCAN_CAP;
        const uint8_t *d = bin->map.data + s->foff;

        for (uint64_t off = (uint64_t)psz; off + (uint64_t)psz <= sz; off += (uint64_t)psz) {
            uint64_t ptr = 0;
            memcpy(&ptr, d + off, (size_t)psz);
            if (!lang_is_code_ptr(bin, ptr)) continue;
            uint64_t vt_va = s->va + off;
            uint32_t nm = lang_count_vmethods(bin, vt_va, psz);
            if (nm >= 1 && lang_try_msvc_rtti(a, vt_va, nm, b)) {
                off += (uint64_t)(nm - 1) * (uint64_t)psz;
            }
        }
    }
}

static void lang_scan_itanium_syms(const ana_ctx *a, lang_bld *b) {
    int psz = (a->bin.bits == 32) ? 4 : 8;
    for (uint32_t i = 0; i < a->bin.nsym && b->nclass < LANG_MAX_CLS; i++) {
        const bin_sym *sy = &a->bin.syms[i];
        const char *raw = bin_str(&a->bin, sy->name_off);
        if (!raw) continue;

        int is_vt = (strncmp(raw, "_ZTV", 4) == 0 || strncmp(raw, "__ZTV", 5) == 0);
        int is_ti = (strncmp(raw, "_ZTI", 4) == 0 || strncmp(raw, "__ZTI", 5) == 0);
        if (!is_vt && !is_ti) continue;

        char dem[128] = "";
        if (!dem_name(raw, dem, sizeof(dem))) continue;

        const char *cname = dem;
        if (strncmp(cname, "vtable for ", 11) == 0) cname += 11;
        else if (strncmp(cname, "typeinfo for ", 13) == 0) cname += 13;
        if (!cname[0]) continue;

        uint64_t vt_va = 0;
        uint32_t nm = 0;
        if (is_vt && sy->va) {
            vt_va = sy->va + (uint64_t)psz * 2;
            nm = lang_count_vmethods(&a->bin, vt_va, psz);
            if (nm == 0) vt_va = sy->va;
        }
        lang_add_class(b, cname, "", vt_va, nm, "C++");
    }
}

static void lang_scan_cpp(const ana_ctx *a, lang_bld *b) {
    ir_vtable *vts = (ir_vtable *)calloc(LANG_MAX_VT, sizeof(ir_vtable));
    if (vts) {
        int nvt = ir_scan_vtables(a, vts, LANG_MAX_VT);
        for (int i = 0; i < nvt; i++) {
            if (!lang_try_msvc_rtti(a, vts[i].va, vts[i].nentry, b)) {
                lang_try_itanium_rtti(a, vts[i].va, vts[i].nentry, b);
            }
        }
        free(vts);
    }

    if (a->bin.fmt == BIN_PE64 || a->bin.fmt == BIN_PE32) {
        lang_scan_msvc_small_vtables(a, b);
    }
    lang_scan_itanium_syms(a, b);
}

static uint64_t lang_rd_u32(const uint8_t *d, size_t off) {
    uint32_t v = 0;
    memcpy(&v, d + off, 4);
    return (uint64_t)v;
}

static uint64_t lang_rd_ptr(const uint8_t *d, size_t off, int ps) {
    if (ps == 4) return lang_rd_u32(d, off);
    uint64_t v = 0;
    memcpy(&v, d + off, 8);
    return v;
}

static uint64_t lang_first_exec_va(const bin_img *bin) {
    for (uint32_t i = 0; i < bin->nsec; i++) {
        if (bin->secs[i].perm & BIN_PERM_X) return bin->secs[i].va;
    }
    return 0;
}

static bool lang_try_gopclntab(const ana_ctx *a, const uint8_t *d, size_t sz, lang_bld *b) {
    if (sz < 40) return false;
    uint32_t magic = (uint32_t)lang_rd_u32(d, 0);
    if (magic != 0xFFFFFFFAU && magic != 0xFFFFFFF0U && magic != 0xFFFFFFF1U) return false;
    if (d[4] != 0 || d[5] != 0) return false;
    uint8_t min_lc = d[6];
    uint8_t ps = d[7];
    if (min_lc != 1 && min_lc != 2 && min_lc != 4) return false;
    if (ps != 4 && ps != 8) return false;

    int is_116 = (magic == 0xFFFFFFFAU);
    size_t hdr_sz = 8 + (size_t)(is_116 ? 7 : 8) * (size_t)ps;
    if (sz < hdr_sz) return false;

    uint64_t nfunc = lang_rd_ptr(d, 8, ps);
    uint64_t text_start = 0;
    uint64_t fn_off = 0;
    uint64_t pcln_off = 0;

    if (is_116) {
        fn_off   = lang_rd_ptr(d, 8 + (size_t)ps * 2, ps);
        pcln_off = lang_rd_ptr(d, 8 + (size_t)ps * 6, ps);
    } else {
        text_start = lang_rd_ptr(d, 8 + (size_t)ps * 2, ps);
        fn_off     = lang_rd_ptr(d, 8 + (size_t)ps * 3, ps);
        pcln_off   = lang_rd_ptr(d, 8 + (size_t)ps * 7, ps);
    }

    if (nfunc == 0 || nfunc > 1000000ULL) return false;
    if (fn_off < hdr_sz || fn_off >= sz) return false;
    if (pcln_off < hdr_sz || pcln_off >= sz) return false;

    size_t ent_sz = is_116 ? ((size_t)ps * 2) : 8;
    size_t func_hdr_sz = is_116 ? ((size_t)ps + 4) : 8;
    if (nfunc > (uint64_t)(sz - (size_t)pcln_off) / ent_sz) return false;

    if (!is_116 && text_start == 0) text_start = lang_first_exec_va(&a->bin);

    uint32_t prev = b->ngo_func;
    uint32_t lim = (nfunc > LANG_MAX_GO) ? LANG_MAX_GO : (uint32_t)nfunc;

    for (uint32_t i = 0; i < lim; i++) {
        size_t fe = (size_t)pcln_off + (size_t)i * ent_sz;
        uint64_t entry = is_116 ? lang_rd_ptr(d, fe, ps) : lang_rd_u32(d, fe);
        uint64_t funcoff = is_116 ? lang_rd_ptr(d, fe + ps, ps) : lang_rd_u32(d, fe + 4);
        if (funcoff >= sz - (size_t)pcln_off) continue;
        if ((sz - (size_t)pcln_off) - (size_t)funcoff < func_hdr_sz) continue;

        size_t fpos = (size_t)pcln_off + (size_t)funcoff;
        int32_t nameoff = 0;
        memcpy(&nameoff, d + fpos + (is_116 ? (size_t)ps : 4), 4);
        if (nameoff < 0 || (uint64_t)nameoff >= (uint64_t)(sz - (size_t)fn_off)) continue;

        size_t npos = (size_t)fn_off + (size_t)nameoff;
        char nm[96];
        size_t k = 0;
        int ok = 1;
        while (npos + k < sz && d[npos + k] != 0) {
            uint8_t ch = d[npos + k];
            if (ch < 0x20 || ch > 0x7E) { ok = 0; break; }
            if (k + 1 < sizeof(nm)) nm[k] = (char)ch;
            k++;
            if (k > 256) { ok = 0; break; }
        }
        if (!ok || k == 0 || npos + k >= sz) continue;
        nm[k < sizeof(nm) ? k : sizeof(nm) - 1] = 0;

        uint64_t fva = is_116 ? entry : (text_start + entry);
        lang_add_go(b, fva, nm);
    }

    return b->ngo_func > prev;
}

static bool lang_scan_go(const ana_ctx *a, lang_bld *b) {
    const bin_img *bin = &a->bin;
    for (uint32_t si = 0; si < bin->nsec; si++) {
        const bin_sec *s = &bin->secs[si];
        if (!strstr(s->name, "gopclntab")) continue;
        if (s->fsize < 40 || s->foff >= bin->map.size) continue;
        uint64_t sz = s->fsize;
        if (s->foff + sz > bin->map.size) sz = bin->map.size - s->foff;
        if (lang_try_gopclntab(a, bin->map.data + s->foff, (size_t)sz, b)) return true;
    }

    for (uint32_t si = 0; si < bin->nsec; si++) {
        const bin_sec *s = &bin->secs[si];
        if (!(s->perm & BIN_PERM_R) || (s->perm & BIN_PERM_X)) continue;
        if (s->fsize < 40 || s->foff >= bin->map.size) continue;
        uint64_t sz = s->fsize;
        if (s->foff + sz > bin->map.size) sz = bin->map.size - s->foff;
        if (sz > LANG_SCAN_CAP) sz = LANG_SCAN_CAP;
        const uint8_t *d = bin->map.data + s->foff;

        for (uint64_t off = 0; off + 40 <= sz; off += 4) {
            uint8_t b0 = d[off];
            if ((b0 != 0xFA && b0 != 0xF0 && b0 != 0xF1) ||
                d[off + 1] != 0xFF || d[off + 2] != 0xFF || d[off + 3] != 0xFF) continue;
            if (d[off + 4] != 0 || d[off + 5] != 0) continue;
            if (lang_try_gopclntab(a, d + off, (size_t)(sz - off), b)) return true;
        }
    }
    return false;
}

static int lang_is_path_ch(char c) {
    return isalnum((unsigned char)c) || c == '_' || c == '-' || c == '.' || c == '/' || c == '\\' || c == ':';
}

static void lang_add_rust_src(lang_info *out, const char *path) {
    if (!path || !path[0] || out->nrust_src >= 32) return;
    size_t len = strlen(path);
    const char *src = (len > 95) ? (path + len - 95) : path;
    for (int i = 0; i < out->nrust_src; i++) {
        if (strcmp(out->rust_srcs[i], src) == 0) return;
    }
    snprintf(out->rust_srcs[out->nrust_src++], 96, "%s", src);
}

static bool lang_scan_rust(const ana_ctx *a, lang_info *out) {
    int strong = 0;
    for (uint32_t i = 0; i < a->bin.nsym; i++) {
        const char *nm = bin_str(&a->bin, a->bin.syms[i].name_off);
        if (!nm) continue;
        if (strstr(nm, "rust_begin_unwind") || strstr(nm, "core::panicking") || strstr(nm, "_ZN4core9panicking")) {
            strong = 1;
            break;
        }
    }

    char buf[256];
    for (uint32_t i = 0; i < a->nstr; i++) {
        size_t n = ana_read_str(a, &a->strs[i], buf, sizeof(buf));
        if (n < 5) continue;

        if (!strong && (strstr(buf, "core::panicking") || strstr(buf, "rust_begin_unwind") || strstr(buf, "std::panicking"))) {
            strong = 1;
        }

        const char *p = buf;
        while (out->nrust_src < 32) {
            const char *hit = strstr(p, ".rs");
            if (!hit) break;
            char after = hit[3];
            if (after == 0 || after == ':' || after == ' ' || after == ')' || after == ']' ||
                after == '"' || after == '\'' || after == ',' || after == '\r' || after == '\n') {
                const char *st = hit;
                while (st > buf && lang_is_path_ch(st[-1])) st--;
                size_t plen = (size_t)((hit + 3) - st);
                if (plen >= 5 && plen < 220) {
                    char path[224];
                    memcpy(path, st, plen);
                    path[plen] = 0;
                    if (strchr(path, '/') || strchr(path, '\\')) {
                        lang_add_rust_src(out, path);
                    }
                }
            }
            p = hit + 3;
        }
    }

    return (out->nrust_src >= 2 || strong != 0);
}

static bool lang_valid_objc_name(const char *s, size_t len) {
    if (len < 2 || len >= 80) return false;
    if (!(isalpha((unsigned char)s[0]) || s[0] == '_')) return false;
    for (size_t i = 1; i < len; i++) {
        if (!(isalnum((unsigned char)s[i]) || s[i] == '_' || s[i] == '$')) return false;
    }
    return true;
}

static bool lang_scan_objc(const ana_ctx *a, lang_bld *b) {
    if (a->bin.fmt != BIN_MACHO64) return false;
    const bin_img *bin = &a->bin;
    uint32_t prev = b->nclass;

    for (uint32_t si = 0; si < bin->nsec; si++) {
        const bin_sec *s = &bin->secs[si];
        if (!strstr(s->name, "__objc_classlist")) continue;
        if (s->fsize < 8 || s->foff >= bin->map.size) continue;
        uint64_t sz = s->fsize;
        if (s->foff + sz > bin->map.size) sz = bin->map.size - s->foff;
        uint64_t cnt = sz / 8;
        if (cnt > 512) cnt = 512;

        for (uint64_t i = 0; i < cnt; i++) {
            uint64_t cls_va = 0;
            memcpy(&cls_va, bin->map.data + s->foff + i * 8, 8);
            if (!bin_sec_at(bin, cls_va)) continue;
            uint64_t ro_va = 0;
            if (bin_read(bin, cls_va + 32, (uint8_t *)&ro_va, 8) != 8) continue;
            ro_va &= ~7ULL;
            if (!bin_sec_at(bin, ro_va)) continue;

            uint64_t nm_va = 0;
            if (bin_read(bin, ro_va + 24, (uint8_t *)&nm_va, 8) != 8) continue;
            char nm[80];
            memset(nm, 0, sizeof(nm));
            if (bin_read(bin, nm_va, (uint8_t *)nm, sizeof(nm) - 1) < 2) continue;
            size_t nl = strnlen(nm, sizeof(nm) - 1);
            if (!lang_valid_objc_name(nm, nl)) continue;

            uint32_t nmethod = 0;
            uint64_t ml_va = 0;
            if (bin_read(bin, ro_va + 32, (uint8_t *)&ml_va, 8) == 8 && bin_sec_at(bin, ml_va)) {
                uint32_t mc = 0;
                if (bin_read(bin, ml_va + 4, (uint8_t *)&mc, 4) == 4 && mc <= 4096) nmethod = mc;
            }
            lang_add_class(b, nm, "", cls_va, nmethod, "ObjC");
        }
    }

    for (uint32_t si = 0; si < bin->nsec; si++) {
        const bin_sec *s = &bin->secs[si];
        if (!strstr(s->name, "__objc_classname")) continue;
        if (s->fsize < 2 || s->foff >= bin->map.size) continue;
        uint64_t sz = s->fsize;
        if (s->foff + sz > bin->map.size) sz = bin->map.size - s->foff;
        if (sz > LANG_SCAN_CAP) sz = LANG_SCAN_CAP;
        const uint8_t *d = bin->map.data + s->foff;

        uint64_t off = 0;
        while (off < sz && b->nclass < LANG_MAX_CLS) {
            while (off < sz && d[off] == 0) off++;
            if (off >= sz) break;
            uint64_t st = off;
            while (off < sz && d[off] != 0) off++;
            size_t len = (size_t)(off - st);
            if (lang_valid_objc_name((const char *)(d + st), len)) {
                char nm[80];
                memcpy(nm, d + st, len);
                nm[len] = 0;
                lang_add_class(b, nm, "", s->va + st, 0, "ObjC");
            }
        }
    }

    return b->nclass > prev;
}

void lang_analyze(const ana_ctx *a, lang_info *out) {
    if (!out) return;
    memset(out, 0, sizeof(*out));
    if (!a) return;

    lang_bld b;
    memset(&b, 0, sizeof(b));

    bool is_go = lang_scan_go(a, &b);
    if (is_go) snprintf(out->runtime, sizeof(out->runtime), "Go");

    bool is_rust = lang_scan_rust(a, out);
    if (is_rust && !out->runtime[0]) snprintf(out->runtime, sizeof(out->runtime), "Rust");

    bool is_objc = lang_scan_objc(a, &b);
    if (is_objc && !out->runtime[0]) snprintf(out->runtime, sizeof(out->runtime), "ObjC");

    uint32_t pre_cpp = b.nclass;
    lang_scan_cpp(a, &b);
    if (b.nclass > pre_cpp && !out->runtime[0]) snprintf(out->runtime, sizeof(out->runtime), "C++");

    if (!out->runtime[0]) {
        snprintf(out->runtime, sizeof(out->runtime), "%s", a->bin.has_clr ? ".NET" : "C/Native");
    }

    out->classes = b.classes;
    out->nclass = b.nclass;
    out->go_funcs = b.go_funcs;
    out->ngo_func = b.ngo_func;
}

uint32_t lang_apply_syms(ana_ctx *a) {
    if (!a) return 0;
    lang_bld b;
    memset(&b, 0, sizeof(b));
    if (!lang_scan_go(a, &b)) {
        free(b.go_funcs);
        return 0;
    }

    uint32_t added = 0;
    for (uint32_t i = 0; i < b.ngo_func; i++) {
        uint64_t va = b.go_funcs[i].va;
        const char *nm = b.go_funcs[i].name;
        if (!va || !nm[0]) continue;

        const char *cur = ana_sym_at(a, va);
        if (cur && cur[0] &&
            strncmp(cur, "sub_", 4) != 0 &&
            strncmp(cur, "loc_", 4) != 0 &&
            strncmp(cur, "func_", 5) != 0) {
            continue;
        }
        ana_set_name(a, va, nm);
        added++;
    }
    free(b.go_funcs);
    return added;
}
