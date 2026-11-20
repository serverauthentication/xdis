#include "bin.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint16_t bc_u16(const uint8_t *d, uint64_t sz, uint64_t off) {
    if (off + 2 > sz) return 0;
    uint16_t v;
    memcpy(&v, d + off, 2);
    return v;
}

static uint32_t bc_u32(const uint8_t *d, uint64_t sz, uint64_t off) {
    if (off + 4 > sz) return 0;
    uint32_t v;
    memcpy(&v, d + off, 4);
    return v;
}

static uint64_t bc_u64(const uint8_t *d, uint64_t sz, uint64_t off) {
    if (off + 8 > sz) return 0;
    uint64_t v;
    memcpy(&v, d + off, 8);
    return v;
}

static bool bc_uleb(const uint8_t *d, uint64_t end, uint64_t *pos, uint32_t *out) {
    uint64_t v = 0;
    unsigned sh = 0;
    uint64_t p = *pos;
    for (int i = 0; i < 5 && p < end; i++) {
        uint8_t b = d[p++];
        v |= (uint64_t)(b & 0x7FU) << sh;
        if ((b & 0x80U) == 0) {
            *pos = p;
            *out = (uint32_t)v;
            return true;
        }
        sh += 7U;
    }
    return false;
}

static bool bc_wasm_name(const uint8_t *d, uint64_t end, uint64_t *pos, char *out, size_t max) {
    uint32_t len = 0;
    if (!bc_uleb(d, end, pos, &len)) return false;
    if (len > end - *pos) return false;
    if (out && max > 0) {
        size_t n = (size_t)len < max - 1 ? (size_t)len : max - 1;
        if (n > 0) memcpy(out, d + *pos, n);
        out[n] = 0;
    }
    *pos += len;
    return true;
}

static bool bc_wasm_skip_limits(const uint8_t *d, uint64_t end, uint64_t *pos) {
    if (*pos >= end) return false;
    uint8_t fl = d[(*pos)++];
    uint32_t v = 0;
    if (!bc_uleb(d, end, pos, &v)) return false;
    if ((fl & 1U) && !bc_uleb(d, end, pos, &v)) return false;
    return true;
}

typedef struct {
    uint32_t idx;
    char     name[64];
} wasm_exp;

static void bc_wasm_imports(bin_img *b, const uint8_t *d, uint64_t off, uint64_t end, uint32_t *n_imp_func) {
    uint64_t p = off;
    uint32_t cnt = 0;
    if (!bc_uleb(d, end, &p, &cnt)) return;
    if (cnt > 4096U) cnt = 4096U;

    for (uint32_t i = 0; i < cnt && p < end; i++) {
        char mod[48], field[64], full[120];
        if (!bc_wasm_name(d, end, &p, mod, sizeof(mod))) break;
        if (!bc_wasm_name(d, end, &p, field, sizeof(field))) break;
        if (p >= end) break;
        uint8_t kind = d[p++];
        uint32_t dummy = 0;
        if (kind == 0) {
            if (!bc_uleb(d, end, &p, &dummy)) break;
            (*n_imp_func)++;
            snprintf(full, sizeof(full), "%s!%s", mod, field);
            bin_add_sym(b, 0, full, BIN_SYM_IMPORT);
        } else if (kind == 1) {
            if (p >= end) break;
            p++;
            if (!bc_wasm_skip_limits(d, end, &p)) break;
        } else if (kind == 2) {
            if (!bc_wasm_skip_limits(d, end, &p)) break;
        } else if (kind == 3) {
            if (end - p < 2) break;
            p += 2;
        } else if (kind == 4) {
            if (p >= end) break;
            p++;
            if (!bc_uleb(d, end, &p, &dummy)) break;
        } else {
            break;
        }
    }
}

static void bc_wasm_exports(const uint8_t *d, uint64_t off, uint64_t end, wasm_exp **exps, uint32_t *nexp, uint32_t *cap) {
    uint64_t p = off;
    uint32_t cnt = 0;
    if (!bc_uleb(d, end, &p, &cnt)) return;
    if (cnt > 4096U) cnt = 4096U;

    for (uint32_t i = 0; i < cnt && p < end; i++) {
        char nm[64];
        if (!bc_wasm_name(d, end, &p, nm, sizeof(nm))) break;
        if (p >= end) break;
        uint8_t kind = d[p++];
        uint32_t idx = 0;
        if (!bc_uleb(d, end, &p, &idx)) break;
        if (kind != 0) continue;
        if (*nexp == *cap) {
            uint32_t ncap = *cap ? (*cap * 2U) : 64U;
            wasm_exp *ne = (wasm_exp *)realloc(*exps, (size_t)ncap * sizeof(wasm_exp));
            if (!ne) break;
            *exps = ne;
            *cap = ncap;
        }
        (*exps)[*nexp].idx = idx;
        snprintf((*exps)[*nexp].name, sizeof((*exps)[*nexp].name), "%s", nm);
        (*nexp)++;
    }
}

static void bc_wasm_code(bin_img *b, const uint8_t *d, uint64_t sec_off, uint64_t sec_size,
                         uint32_t n_imp_func, const wasm_exp *exps, uint32_t nexp) {
    if (sec_size == 0) return;
    bin_sec s;
    memset(&s, 0, sizeof(s));
    snprintf(s.name, sizeof(s.name), ".code");
    s.va = sec_off;
    s.foff = sec_off;
    s.vsize = sec_size;
    s.fsize = sec_size;
    s.perm = BIN_PERM_R | BIN_PERM_X;
    bin_add_sec(b, &s);

    uint64_t sec_end = sec_off + sec_size;
    uint64_t p = sec_off;
    uint32_t nfunc = 0;
    if (!bc_uleb(d, sec_end, &p, &nfunc)) return;
    if (nfunc > 65536U) nfunc = 65536U;

    int have_entry = 0;
    for (uint32_t fi = 0; fi < nfunc && p < sec_end; fi++) {
        uint32_t bsz = 0;
        if (!bc_uleb(d, sec_end, &p, &bsz) || bsz > sec_end - p) break;
        uint64_t body_end = p + bsz;

        uint32_t ngroups = 0;
        if (!bc_uleb(d, body_end, &p, &ngroups)) {
            p = body_end;
            continue;
        }
        for (uint32_t lg = 0; lg < ngroups && p < body_end; lg++) {
            uint32_t lcnt = 0;
            if (!bc_uleb(d, body_end, &p, &lcnt) || p >= body_end) {
                p = body_end;
                break;
            }
            p++;
        }

        uint64_t code_va = p;
        if (code_va < body_end) {
            bin_add_pdata(b, code_va, body_end);
            if (!have_entry) {
                b->entry = code_va;
                have_entry = 1;
            }
            uint32_t full_idx = n_imp_func + fi;
            int named = 0;
            for (uint32_t k = 0; k < nexp; k++) {
                if (exps[k].idx == full_idx) {
                    bin_add_sym(b, code_va, exps[k].name, BIN_SYM_EXPORT);
                    named = 1;
                }
            }
            if (!named) {
                char fn[32];
                snprintf(fn, sizeof(fn), "wasm_fn_%u", full_idx);
                bin_add_sym(b, code_va, fn, BIN_SYM_FUNC);
            }
        }
        p = body_end;
    }
}

bool bc_load_wasm(bin_img *b) {
    const uint8_t *d = b->map.data;
    uint64_t sz = b->map.size;
    if (sz < 8 || memcmp(d, "\0asm", 4) != 0 || bc_u32(d, sz, 4) != 1U) return false;

    b->fmt = BIN_WASM;
    b->arch = BIN_ARCH_WASM;
    b->bits = 32;
    b->base = 0;
    b->entry = 0;

    wasm_exp *exps = NULL;
    uint32_t nexp = 0, exp_cap = 0;
    uint32_t n_imp_func = 0;

    uint64_t pos = 8;
    while (pos < sz) {
        uint8_t id = d[pos++];
        uint32_t sec_sz = 0;
        if (!bc_uleb(d, sz, &pos, &sec_sz) || sec_sz > sz - pos) break;
        uint64_t sec_off = pos;
        uint64_t sec_end = pos + sec_sz;

        if (id == 2) {
            bc_wasm_imports(b, d, sec_off, sec_end, &n_imp_func);
        } else if (id == 7) {
            bc_wasm_exports(d, sec_off, sec_end, &exps, &nexp, &exp_cap);
        } else if (id == 10) {
            bc_wasm_code(b, d, sec_off, sec_sz, n_imp_func, exps, nexp);
        } else if (id == 11 && sec_sz > 0) {
            bin_sec s;
            memset(&s, 0, sizeof(s));
            snprintf(s.name, sizeof(s.name), ".data");
            s.va = sec_off;
            s.foff = sec_off;
            s.vsize = sec_sz;
            s.fsize = sec_sz;
            s.perm = BIN_PERM_R;
            bin_add_sec(b, &s);
        }
        pos = sec_end;
    }

    free(exps);

    if (b->nsec == 0) {
        bin_sec s;
        memset(&s, 0, sizeof(s));
        snprintf(s.name, sizeof(s.name), ".wasm");
        s.va = 0;
        s.foff = 0;
        s.vsize = sz;
        s.fsize = sz;
        s.perm = BIN_PERM_R;
        bin_add_sec(b, &s);
    }
    return true;
}

bool bc_load_dex(bin_img *b) {
    const uint8_t *d = b->map.data;
    uint64_t sz = b->map.size;
    if (sz < 112 || memcmp(d, "dex\n", 4) != 0) return false;

    b->fmt = BIN_DEX;
    b->arch = BIN_ARCH_X86;
    b->bits = 32;
    b->base = 0;
    b->entry = 0;

    bin_sec s;
    memset(&s, 0, sizeof(s));
    snprintf(s.name, sizeof(s.name), ".dex");
    s.va = 0;
    s.foff = 0;
    s.vsize = sz;
    s.fsize = sz;
    s.perm = BIN_PERM_R | BIN_PERM_X;
    bin_add_sec(b, &s);

    uint32_t str_cnt = bc_u32(d, sz, 0x38);
    uint32_t str_off = bc_u32(d, sz, 0x3C);
    uint32_t typ_cnt = bc_u32(d, sz, 0x40);
    uint32_t typ_off = bc_u32(d, sz, 0x44);
    uint32_t cls_cnt = bc_u32(d, sz, 0x60);
    uint32_t cls_off = bc_u32(d, sz, 0x64);

    if (cls_cnt == 0 || typ_cnt == 0 || str_cnt == 0) return true;
    if ((uint64_t)cls_off >= sz || (uint64_t)typ_off >= sz || (uint64_t)str_off >= sz) return true;

    uint32_t lim = cls_cnt < 512U ? cls_cnt : 512U;
    for (uint32_t i = 0; i < lim; i++) {
        uint64_t cpos = (uint64_t)cls_off + (uint64_t)i * 32ULL;
        if (cpos + 32ULL > sz) break;

        uint32_t class_idx = bc_u32(d, sz, cpos);
        uint32_t data_off = bc_u32(d, sz, cpos + 24ULL);
        if (class_idx >= typ_cnt) continue;
        uint64_t tpos = (uint64_t)typ_off + (uint64_t)class_idx * 4ULL;
        if (tpos + 4ULL > sz) continue;

        uint32_t desc_idx = bc_u32(d, sz, tpos);
        if (desc_idx >= str_cnt) continue;
        uint64_t spos = (uint64_t)str_off + (uint64_t)desc_idx * 4ULL;
        if (spos + 4ULL > sz) continue;

        uint32_t sdata_off = bc_u32(d, sz, spos);
        if ((uint64_t)sdata_off >= sz) continue;

        uint64_t sp = sdata_off;
        uint32_t u16_len = 0;
        if (!bc_uleb(d, sz, &sp, &u16_len)) continue;

        char name[128];
        size_t n = 0;
        while (sp + n < sz && n + 1 < sizeof(name) && d[sp + n] != 0) {
            name[n] = (char)d[sp + n];
            n++;
        }
        name[n] = 0;
        if (n == 0) continue;

        uint64_t sym_va = (data_off && (uint64_t)data_off < sz) ? (uint64_t)data_off : cpos;
        bin_add_sym(b, sym_va, name, BIN_SYM_FUNC);
    }

    return true;
}

typedef struct {
    uint64_t tbl_off, tbl_sz;
    uint64_t str_off, str_sz;
    uint64_t us_off,  us_sz;
    int      is_uncomp;
} clr_streams;

static uint32_t bc_tidx(uint32_t rows) {
    return (rows < 65536U) ? 2U : 4U;
}

static uint32_t bc_coded2(uint32_t a, uint32_t b, uint32_t c, uint32_t d) {
    uint32_t mx = a;
    if (b > mx) mx = b;
    if (c > mx) mx = c;
    if (d > mx) mx = d;
    return (mx < 16384U) ? 2U : 4U;
}

static void bc_md_str(const uint8_t *d, uint64_t sz, uint64_t base, uint64_t heap_sz, uint32_t idx, char *out, size_t max) {
    if (!max) return;
    out[0] = 0;
    if (!heap_sz || idx >= heap_sz) return;
    uint64_t off = base + idx;
    uint64_t lim = base + heap_sz;
    if (lim > sz) lim = sz;
    size_t n = 0;
    while (off + n < lim && n + 1 < max && d[off + n] != 0) {
        out[n] = (char)d[off + n];
        n++;
    }
    out[n] = 0;
}

static uint32_t bc_heap_idx(const uint8_t *d, uint64_t sz, uint64_t off, uint32_t width) {
    return (width == 4U) ? bc_u32(d, sz, off) : (uint32_t)bc_u16(d, sz, off);
}

static bool bc_clr_find_streams(const uint8_t *d, uint64_t sz, uint64_t md_off, uint64_t md_sz,
                                char *ver_out, size_t ver_max, clr_streams *st) {
    uint64_t md_end = md_off + md_sz;
    if (md_sz < 20 || bc_u32(d, sz, md_off) != 0x424A5342U) return false;

    uint32_t ver_len = bc_u32(d, sz, md_off + 12);
    if (ver_len > md_sz - 16) return false;
    size_t vn = 0;
    while (vn < ver_len && vn + 1 < ver_max && d[md_off + 16 + vn] != 0) {
        ver_out[vn] = (char)d[md_off + 16 + vn];
        vn++;
    }
    ver_out[vn] = 0;

    uint64_t sp = md_off + 16ULL + (((uint64_t)ver_len + 3ULL) & ~3ULL);
    if (sp + 4ULL > md_end) return false;
    uint16_t nstreams = bc_u16(d, sz, sp + 2ULL);
    sp += 4ULL;
    if (nstreams > 32U) nstreams = 32U;

    for (uint16_t i = 0; i < nstreams && sp + 8ULL < md_end; i++) {
        uint32_t soff = bc_u32(d, sz, sp);
        uint32_t ssz = bc_u32(d, sz, sp + 4ULL);
        uint64_t npos = sp + 8ULL;
        char nm[32];
        size_t nlen = 0;
        while (npos + nlen < md_end && nlen + 1 < sizeof(nm) && d[npos + nlen] != 0) {
            nm[nlen] = (char)d[npos + nlen];
            nlen++;
        }
        nm[nlen] = 0;
        while (npos + nlen < md_end && d[npos + nlen] != 0) nlen++;
        if (npos + nlen >= md_end) break;
        sp = npos + (((uint64_t)nlen + 4ULL) & ~3ULL);

        if ((uint64_t)soff > md_sz || (uint64_t)ssz > md_sz - soff) continue;
        if (strcmp(nm, "#~") == 0 || strcmp(nm, "#-") == 0) {
            st->tbl_off = md_off + soff;
            st->tbl_sz = ssz;
            st->is_uncomp = (nm[1] == '-');
        } else if (strcmp(nm, "#Strings") == 0) {
            st->str_off = md_off + soff;
            st->str_sz = ssz;
        } else if (strcmp(nm, "#US") == 0) {
            st->us_off = md_off + soff;
            st->us_sz = ssz;
        }
    }
    return true;
}

static void bc_clr_parse_tables(const bin_img *b, const clr_streams *st, bc_clr_info *out) {
    const uint8_t *d = b->map.data;
    uint64_t sz = b->map.size;
    if (st->tbl_sz < 24 || st->tbl_off + st->tbl_sz > sz) return;

    uint64_t tend = st->tbl_off + st->tbl_sz;
    uint8_t hsz = d[st->tbl_off + 6ULL];
    uint64_t valid = bc_u64(d, sz, st->tbl_off + 8ULL);

    uint32_t rows[64];
    memset(rows, 0, sizeof(rows));
    uint64_t cur = st->tbl_off + 24ULL;
    for (int t = 0; t < 64; t++) {
        if (!((valid >> t) & 1ULL)) continue;
        if (cur + 4ULL > tend) return;
        rows[t] = bc_u32(d, sz, cur);
        cur += 4ULL;
    }
    if (st->is_uncomp && (hsz & 0x40U)) cur += 4ULL;

    uint32_t str_i = (hsz & 1U) ? 4U : 2U;
    uint32_t guid_i = (hsz & 2U) ? 4U : 2U;
    uint32_t blob_i = (hsz & 4U) ? 4U : 2U;
    uint32_t res_i = bc_coded2(rows[0], rows[1], rows[26], rows[35]);
    uint32_t tdor_i = bc_coded2(rows[1], rows[2], rows[27], 0);
    uint32_t fld_l = bc_tidx(rows[3] ? rows[3] : rows[4]);
    uint32_t mth_l = bc_tidx(rows[5] ? rows[5] : rows[6]);
    uint32_t prm_l = bc_tidx(rows[7] ? rows[7] : rows[8]);

    uint32_t rsz[7];
    rsz[0] = 2U + str_i + 3U * guid_i;
    rsz[1] = res_i + 2U * str_i;
    rsz[2] = 4U + 2U * str_i + tdor_i + fld_l + mth_l;
    rsz[3] = bc_tidx(rows[4]);
    rsz[4] = 2U + str_i + blob_i;
    rsz[5] = bc_tidx(rows[6]);
    rsz[6] = 8U + str_i + blob_i + prm_l;

    for (int t = 0; t <= 6; t++) {
        uint64_t bytes = (uint64_t)rows[t] * (uint64_t)rsz[t];
        if (cur > tend || bytes > tend - cur) break;

        if (t == 2) {
            for (uint32_t i = 0; i < rows[2] && out->ntype < 128; i++) {
                uint64_t r = cur + (uint64_t)i * rsz[2];
                bc_clr_type *tp = &out->types[out->ntype++];
                tp->flags = bc_u32(d, sz, r);
                uint32_t nm_i = bc_heap_idx(d, sz, r + 4ULL, str_i);
                uint32_t ns_i = bc_heap_idx(d, sz, r + 4ULL + str_i, str_i);
                bc_md_str(d, sz, st->str_off, st->str_sz, nm_i, tp->name, sizeof(tp->name));
                bc_md_str(d, sz, st->str_off, st->str_sz, ns_i, tp->ns, sizeof(tp->ns));
            }
        } else if (t == 6) {
            for (uint32_t i = 0; i < rows[6] && out->nmethod < 192; i++) {
                uint64_t r = cur + (uint64_t)i * rsz[6];
                bc_clr_method *m = &out->methods[out->nmethod++];
                m->rva = bc_u32(d, sz, r);
                m->va = m->rva ? (b->base + m->rva) : 0;
                m->flags = bc_u16(d, sz, r + 6ULL);
                uint32_t nm_i = bc_heap_idx(d, sz, r + 8ULL, str_i);
                bc_md_str(d, sz, st->str_off, st->str_sz, nm_i, m->name, sizeof(m->name));
            }
        }
        cur += bytes;
    }
}

static void bc_clr_parse_us(const uint8_t *d, uint64_t sz, const clr_streams *st, bc_clr_info *out) {
    if (st->us_sz <= 1 || st->us_off + st->us_sz > sz) return;
    uint64_t p = st->us_off + 1ULL;
    uint64_t end = st->us_off + st->us_sz;

    while (p < end && out->nstr < 64) {
        uint8_t b0 = d[p];
        uint32_t blen = 0;
        if ((b0 & 0x80U) == 0) {
            blen = b0;
            p += 1ULL;
        } else if ((b0 & 0xC0U) == 0x80U) {
            if (end - p < 2ULL) break;
            blen = ((uint32_t)(b0 & 0x3FU) << 8) | d[p + 1ULL];
            p += 2ULL;
        } else if ((b0 & 0xE0U) == 0xC0U) {
            if (end - p < 4ULL) break;
            blen = ((uint32_t)(b0 & 0x1FU) << 24) | ((uint32_t)d[p + 1ULL] << 16)
                 | ((uint32_t)d[p + 2ULL] << 8) | d[p + 3ULL];
            p += 4ULL;
        } else {
            break;
        }
        if (blen == 0) continue;
        if (blen > end - p) break;

        uint32_t nch = (blen >= 2U) ? (blen - 1U) / 2U : 0U;
        char tmp[96];
        size_t o = 0;
        int ok_ch = 0;
        for (uint32_t k = 0; k < nch && o + 1 < sizeof(tmp); k++) {
            uint16_t ch = bc_u16(d, sz, p + (uint64_t)k * 2ULL);
            if (ch >= 0x20U && ch < 0x7FU) {
                tmp[o++] = (char)ch;
                if (ch > 0x20U) ok_ch++;
            } else if (ch == '\t' || ch == '\r' || ch == '\n') {
                tmp[o++] = ' ';
            }
        }
        tmp[o] = 0;
        if (ok_ch > 0 && o > 0) {
            snprintf(out->strings[out->nstr++], sizeof(out->strings[0]), "%s", tmp);
        }
        p += blen;
    }
}

bool bc_inspect_dotnet(const bin_img *b, bc_clr_info *out) {
    if (!b || !out) return false;
    memset(out, 0, sizeof(*out));
    if ((b->fmt != BIN_PE32 && b->fmt != BIN_PE64) || !b->has_clr) return false;

    const uint8_t *d = b->map.data;
    uint64_t sz = b->map.size;
    if (sz < 0x40 || d[0] != 'M' || d[1] != 'Z') return false;

    uint32_t pe_off = bc_u32(d, sz, 0x3C);
    if ((uint64_t)pe_off + 24ULL > sz || bc_u32(d, sz, pe_off) != 0x00004550U) return false;

    uint16_t opt_sz = bc_u16(d, sz, pe_off + 20ULL);
    uint64_t opt = (uint64_t)pe_off + 24ULL;
    if (opt + opt_sz > sz || opt_sz < 96U) return false;

    uint16_t magic = bc_u16(d, sz, opt);
    int is64 = (magic == 0x20BU);
    if (!is64 && magic != 0x10BU) return false;

    uint64_t dd_off = opt + (is64 ? 112ULL : 96ULL);
    uint32_t ndd = bc_u32(d, sz, dd_off - 4ULL);
    if (ndd <= 14U) return false;

    uint32_t clr_rva = bc_u32(d, sz, dd_off + 112ULL);
    uint32_t clr_sz = bc_u32(d, sz, dd_off + 116ULL);
    if (!clr_rva || clr_sz < 24U) return false;

    uint64_t clr_off = 0;
    if (!bin_va_to_off(b, b->base + clr_rva, &clr_off) || clr_off + 24ULL > sz) return false;

    uint32_t md_rva = bc_u32(d, sz, clr_off + 8ULL);
    uint32_t md_sz = bc_u32(d, sz, clr_off + 12ULL);
    out->entry_token = bc_u32(d, sz, clr_off + 20ULL);
    if (!md_rva || md_sz < 20U) return false;

    uint64_t md_off = 0;
    if (!bin_va_to_off(b, b->base + md_rva, &md_off)) return false;
    if (md_off >= sz) return false;
    if (md_sz > sz - md_off) md_sz = (uint32_t)(sz - md_off);

    clr_streams st;
    memset(&st, 0, sizeof(st));
    if (!bc_clr_find_streams(d, sz, md_off, md_sz, out->runtime_ver, sizeof(out->runtime_ver), &st)) {
        return false;
    }

    bc_clr_parse_tables(b, &st, out);
    bc_clr_parse_us(d, sz, &st, out);
    out->ok = 1;
    return true;
}
