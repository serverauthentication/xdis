#include "bin.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint16_t pe_u16(const uint8_t *d, uint64_t sz, uint64_t off) {
    if (off > sz || sz - off < 2ULL) return 0;
    uint16_t v;
    memcpy(&v, d + off, 2);
    return v;
}

static uint32_t pe_u32(const uint8_t *d, uint64_t sz, uint64_t off) {
    if (off > sz || sz - off < 4ULL) return 0;
    uint32_t v;
    memcpy(&v, d + off, 4);
    return v;
}

static uint64_t pe_u64(const uint8_t *d, uint64_t sz, uint64_t off) {
    if (off > sz || sz - off < 8ULL) return 0;
    uint64_t v;
    memcpy(&v, d + off, 8);
    return v;
}

static bool pe_rva_off(const bin_img *b, uint32_t rva, uint64_t *off) {
    if (!b || !off) return false;
    for (uint32_t i = 0; i < b->nsec; i++) {
        const bin_sec *s = &b->secs[i];
        if (s->va < b->base) continue;
        uint64_t sva = s->va - b->base;
        if ((uint64_t)rva >= sva && (uint64_t)rva - sva < s->vsize) {
            uint64_t rel = (uint64_t)rva - sva;
            if (rel >= s->fsize || s->foff >= b->map.size || rel >= b->map.size - s->foff) return false;
            *off = s->foff + rel;
            return true;
        }
    }
    return false;
}

static size_t pe_cstr(const uint8_t *d, uint64_t sz, uint64_t off, char *out, size_t max) {
    if (off >= sz || max == 0) {
        if (max) out[0] = 0;
        return 0;
    }
    size_t n = 0;
    while (n < max - 1U && (uint64_t)n < sz - off && d[off + n] != 0) {
        out[n] = (char)d[off + n];
        n++;
    }
    out[n] = 0;
    return n;
}

static void pe_exports(bin_img *b, uint32_t dir_rva, uint32_t dir_sz) {
    if (!dir_rva || dir_sz < 40U) return;
    uint64_t off;
    if (!pe_rva_off(b, dir_rva, &off)) return;

    const uint8_t *d = b->map.data;
    uint64_t sz = b->map.size;
    if (off > sz || sz - off < 40ULL) return;

    uint32_t nfunc = pe_u32(d, sz, off + 20ULL);
    uint32_t nname = pe_u32(d, sz, off + 24ULL);
    uint32_t f_rva = pe_u32(d, sz, off + 28ULL);
    uint32_t n_rva = pe_u32(d, sz, off + 32ULL);
    uint32_t o_rva = pe_u32(d, sz, off + 36ULL);

    uint64_t f_off, n_off, o_off;
    if (!pe_rva_off(b, f_rva, &f_off)) return;
    if (!pe_rva_off(b, n_rva, &n_off)) return;
    if (!pe_rva_off(b, o_rva, &o_off)) return;
    if (f_off > sz || n_off > sz || o_off > sz) return;

    if (nname > 65536U) nname = 65536U;
    char name[128];
    for (uint32_t i = 0; i < nname; i++) {
        uint64_t o_rel = (uint64_t)i * 2ULL;
        uint64_t n_rel = (uint64_t)i * 4ULL;
        if (o_rel > sz - o_off || sz - (o_off + o_rel) < 2ULL) break;
        if (n_rel > sz - n_off || sz - (n_off + n_rel) < 4ULL) break;

        uint16_t ord = pe_u16(d, sz, o_off + o_rel);
        if (ord >= nfunc) continue;
        uint64_t f_rel = (uint64_t)ord * 4ULL;
        if (f_rel > sz - f_off || sz - (f_off + f_rel) < 4ULL) continue;
        uint32_t fn_rva = pe_u32(d, sz, f_off + f_rel);

        uint32_t str_rva = pe_u32(d, sz, n_off + n_rel);
        uint64_t str_off;
        if (!pe_rva_off(b, str_rva, &str_off)) continue;
        if (pe_cstr(d, sz, str_off, name, sizeof(name)) == 0) continue;

        // forwarded exports point inside export directory
        if (fn_rva >= dir_rva && (uint64_t)(fn_rva - dir_rva) < (uint64_t)dir_sz) {
            uint64_t fwd_off = 0;
            if (!pe_rva_off(b, fn_rva, &fwd_off)) continue;
            char fwd[128];
            uint32_t rem_dir = dir_sz - (fn_rva - dir_rva);
            size_t fmax = ((size_t)rem_dir < sizeof(fwd) - 1U) ? ((size_t)rem_dir + 1U) : sizeof(fwd);
            if (pe_cstr(d, sz, fwd_off, fwd, fmax) == 0) continue;
            char dem[160];
            const char *lhs = name;
            if ((name[0] == '?' || (name[0] == '_' && (name[1] == 'Z' || (name[1] == '_' && name[2] == 'Z')))) &&
                dem_name(name, dem, sizeof(dem)) && dem[0]) {
                lhs = dem;
            }
            char full[296];
            snprintf(full, sizeof(full), "%s->%s", lhs, fwd);
            if (b->base > UINT64_MAX - (uint64_t)fn_rva) continue;
            if (!bin_add_sym(b, b->base + (uint64_t)fn_rva, full, BIN_SYM_EXPORT)) break;
            b->syms[b->nsym - 1U].flags |= BIN_SYM_F_NOFUNC;
            continue;
        }

        if (!fn_rva || b->base > UINT64_MAX - (uint64_t)fn_rva) continue;
        if (!bin_add_sym(b, b->base + (uint64_t)fn_rva, name, BIN_SYM_EXPORT)) break;
    }
}

#define PE_MAX_IMPORT_DESCS  4096U
#define PE_MAX_IMPORT_THUNKS 65536U

typedef struct {
    uint64_t start;
    uint64_t end;
} pe_imp_rng;

static void pe_imports(bin_img *b, uint32_t dir_rva, uint32_t dir_sz, int is64) {
    if (!dir_rva || dir_sz < 20) return;
    uint64_t off;
    if (!pe_rva_off(b, dir_rva, &off)) return;

    const uint8_t *d = b->map.data;
    uint64_t sz = b->map.size;
    if (off >= sz) return;
    uint32_t stride = is64 ? 8U : 4U;
    uint64_t ord_bit = is64 ? (1ULL << 63) : (1ULL << 31);

    pe_imp_rng *rngs = NULL;
    uint32_t nrng = 0, rng_cap = 0;
    uint32_t total_thunks = 0;
    bool stop_all = false;

    for (uint32_t desc = 0; desc < PE_MAX_IMPORT_DESCS && !stop_all; desc++) {
        uint64_t d_rel = (uint64_t)desc * 20ULL;
        if (d_rel > sz - off || sz - (off + d_rel) < 20ULL) break;
        uint64_t base = off + d_rel;
        uint32_t ilt_rva  = pe_u32(d, sz, base + 0);
        uint32_t name_rva = pe_u32(d, sz, base + 12);
        uint32_t iat_rva  = pe_u32(d, sz, base + 16);
        if (!ilt_rva && !name_rva && !iat_rva) break;

        uint64_t dll_off;
        char dll[64] = "imp";
        if (name_rva && pe_rva_off(b, name_rva, &dll_off)) pe_cstr(d, sz, dll_off, dll, sizeof(dll));

        uint32_t src_rva = ilt_rva ? ilt_rva : iat_rva;
        uint64_t t_off;
        if (!src_rva || !pe_rva_off(b, src_rva, &t_off) || t_off >= sz) continue;

        uint64_t stop_at = sz;
        uint32_t merge_idx = UINT32_MAX;
        bool skip_desc = false;
        for (uint32_t r = 0; r < nrng; r++) {
            if (t_off >= rngs[r].start && t_off < rngs[r].end) {
                skip_desc = true;
                break;
            }
            if (rngs[r].start > t_off && rngs[r].start < stop_at) {
                stop_at = rngs[r].start;
                merge_idx = r;
            }
        }
        if (skip_desc) continue;

        uint64_t end_pos = t_off;
        for (uint32_t j = 0; j < 65536U; j++) {
            if (total_thunks >= PE_MAX_IMPORT_THUNKS) { stop_all = true; break; }
            uint64_t j_rel = (uint64_t)j * (uint64_t)stride;
            if (j_rel > sz - t_off || sz - (t_off + j_rel) < (uint64_t)stride) break;
            uint64_t pos = t_off + j_rel;
            if (pos >= stop_at) break;
            uint64_t thunk = is64 ? pe_u64(d, sz, pos) : pe_u32(d, sz, pos);
            if (!thunk) break;
            end_pos = pos + (uint64_t)stride;

            char full[192];
            if (thunk & ord_bit) {
                snprintf(full, sizeof(full), "%s!#%u", dll, (unsigned)(thunk & 0xFFFFULL));
            } else {
                uint64_t hn_off = 0;
                char fn[120] = "ord";
                if (thunk <= (uint64_t)UINT32_MAX && pe_rva_off(b, (uint32_t)thunk, &hn_off) &&
                    hn_off < sz && sz - hn_off > 2ULL) {
                    pe_cstr(d, sz, hn_off + 2ULL, fn, sizeof(fn));
                }
                snprintf(full, sizeof(full), "%s!%s", dll, fn);
            }

            uint64_t iat_va = b->base + (uint64_t)iat_rva + j_rel;
            if (!bin_add_sym(b, iat_va, full, BIN_SYM_IMPORT)) {
                stop_all = true;
                break;
            }
            total_thunks++;
        }

        if (end_pos > t_off) {
            if (merge_idx != UINT32_MAX && end_pos >= rngs[merge_idx].start) {
                rngs[merge_idx].start = t_off;
                if (end_pos > rngs[merge_idx].end) rngs[merge_idx].end = end_pos;
            } else if (nrng < PE_MAX_IMPORT_DESCS) {
                if (nrng == rng_cap) {
                    uint32_t ncap = rng_cap ? rng_cap * 2U : 64U;
                    if (ncap > PE_MAX_IMPORT_DESCS) ncap = PE_MAX_IMPORT_DESCS;
                    pe_imp_rng *nr = (pe_imp_rng *)realloc(rngs, (size_t)ncap * sizeof(pe_imp_rng));
                    if (nr) { rngs = nr; rng_cap = ncap; }
                }
                if (nrng < rng_cap) {
                    rngs[nrng].start = t_off;
                    rngs[nrng].end = end_pos;
                    nrng++;
                }
            }
        }
    }
    free(rngs);
}

static bool pe_delay_to_rva(const bin_img *b, uint32_t gr_attrs, uint32_t raw, uint32_t *out_rva) {
    if (!out_rva) return false;
    if (!raw) {
        *out_rva = 0;
        return true;
    }
    if (gr_attrs & 1U) {
        *out_rva = raw;
        return true;
    }
    if ((uint64_t)raw < b->base) return false;
    uint64_t rva = (uint64_t)raw - b->base;
    if (rva > (uint64_t)UINT32_MAX) return false;
    *out_rva = (uint32_t)rva;
    return true;
}

static void pe_delay_imports(bin_img *b, uint32_t dir_rva, uint32_t dir_sz, int is64) {
    if (!dir_rva || dir_sz < 32U) return;
    uint64_t off;
    if (!pe_rva_off(b, dir_rva, &off)) return;

    const uint8_t *d = b->map.data;
    uint64_t sz = b->map.size;
    if (off >= sz) return;
    uint32_t stride = is64 ? 8U : 4U;
    uint64_t ord_bit = is64 ? (1ULL << 63) : (1ULL << 31);

    pe_imp_rng *rngs = NULL;
    uint32_t nrng = 0, rng_cap = 0;
    uint32_t total_thunks = 0;
    bool stop_all = false;

    for (uint32_t desc = 0; desc < PE_MAX_IMPORT_DESCS && !stop_all; desc++) {
        uint64_t d_rel = (uint64_t)desc * 32ULL;
        if (d_rel > (uint64_t)dir_sz || (uint64_t)dir_sz - d_rel < 32ULL) break;
        if (d_rel > sz - off || sz - (off + d_rel) < 32ULL) break;
        uint64_t dbase   = off + d_rel;
        uint32_t attrs   = pe_u32(d, sz, dbase + 0ULL);
        uint32_t dll_raw = pe_u32(d, sz, dbase + 4ULL);
        uint32_t iat_raw = pe_u32(d, sz, dbase + 12ULL);
        uint32_t int_raw = pe_u32(d, sz, dbase + 16ULL);
        if (!dll_raw && !iat_raw && !int_raw) break;

        uint32_t dll_rva = 0, iat_rva = 0, int_rva = 0;
        if (!pe_delay_to_rva(b, attrs, dll_raw, &dll_rva)) continue;
        if (!pe_delay_to_rva(b, attrs, iat_raw, &iat_rva)) continue;
        if (!pe_delay_to_rva(b, attrs, int_raw, &int_rva)) continue;
        if (!int_rva) continue;

        uint64_t dll_off;
        char dll[64] = "imp";
        if (dll_rva && pe_rva_off(b, dll_rva, &dll_off)) pe_cstr(d, sz, dll_off, dll, sizeof(dll));

        uint64_t t_off;
        if (!pe_rva_off(b, int_rva, &t_off) || t_off >= sz) continue;

        uint64_t stop_at = sz;
        uint32_t merge_idx = UINT32_MAX;
        bool skip_desc = false;
        for (uint32_t r = 0; r < nrng; r++) {
            if (t_off >= rngs[r].start && t_off < rngs[r].end) {
                skip_desc = true;
                break;
            }
            if (rngs[r].start > t_off && rngs[r].start < stop_at) {
                stop_at = rngs[r].start;
                merge_idx = r;
            }
        }
        if (skip_desc) continue;

        uint32_t sym_rva = iat_rva ? iat_rva : int_rva;
        if (b->base > UINT64_MAX - (uint64_t)sym_rva) continue;
        uint64_t sym_base = b->base + (uint64_t)sym_rva;

        uint64_t end_pos = t_off;
        for (uint32_t j = 0; j < 65536U; j++) {
            if (total_thunks >= PE_MAX_IMPORT_THUNKS) { stop_all = true; break; }
            uint64_t j_rel = (uint64_t)j * (uint64_t)stride;
            if (j_rel > sz - t_off || sz - (t_off + j_rel) < (uint64_t)stride) break;
            uint64_t pos = t_off + j_rel;
            if (pos >= stop_at) break;
            uint64_t thunk = is64 ? pe_u64(d, sz, pos) : pe_u32(d, sz, pos);
            if (!thunk) break;
            end_pos = pos + (uint64_t)stride;

            char full[192];
            if (thunk & ord_bit) {
                snprintf(full, sizeof(full), "%s!#%u", dll, (unsigned)(thunk & 0xFFFFULL));
            } else {
                uint64_t hn_off = 0;
                char fn[120] = "ord";
                uint32_t hn_rva = 0;
                bool hn_ok = false;
                if (attrs & 1U) {
                    if (thunk <= (uint64_t)UINT32_MAX) {
                        hn_rva = (uint32_t)thunk;
                        hn_ok = true;
                    }
                } else {
                    if (thunk >= b->base && thunk - b->base <= (uint64_t)UINT32_MAX) {
                        hn_rva = (uint32_t)(thunk - b->base);
                        hn_ok = true;
                    }
                }
                if (hn_ok && pe_rva_off(b, hn_rva, &hn_off) && hn_off < sz && sz - hn_off > 2ULL) {
                    pe_cstr(d, sz, hn_off + 2ULL, fn, sizeof(fn));
                }
                snprintf(full, sizeof(full), "%s!%s", dll, fn);
            }

            if (j_rel > UINT64_MAX - sym_base) break;
            uint64_t iat_va = sym_base + j_rel;
            if (!bin_add_sym(b, iat_va, full, BIN_SYM_IMPORT)) {
                stop_all = true;
                break;
            }
            total_thunks++;
        }

        if (end_pos > t_off) {
            if (merge_idx != UINT32_MAX && end_pos >= rngs[merge_idx].start) {
                rngs[merge_idx].start = t_off;
                if (end_pos > rngs[merge_idx].end) rngs[merge_idx].end = end_pos;
            } else if (nrng < PE_MAX_IMPORT_DESCS) {
                if (nrng == rng_cap) {
                    uint32_t ncap = rng_cap ? rng_cap * 2U : 64U;
                    if (ncap > PE_MAX_IMPORT_DESCS) ncap = PE_MAX_IMPORT_DESCS;
                    pe_imp_rng *nr = (pe_imp_rng *)realloc(rngs, (size_t)ncap * sizeof(pe_imp_rng));
                    if (nr) { rngs = nr; rng_cap = ncap; }
                }
                if (nrng < rng_cap) {
                    rngs[nrng].start = t_off;
                    rngs[nrng].end = end_pos;
                    nrng++;
                }
            }
        }
    }
    free(rngs);
}

typedef struct {
    uint32_t beg;
    uint32_t end;
    uint32_t root_beg;
} pe_chain_ent;

static int pe_rng_cmp(const void *a, const void *b) {
    const bin_range *ra = (const bin_range *)a;
    const bin_range *rb = (const bin_range *)b;
    if (ra->start != rb->start) return (ra->start > rb->start) - (ra->start < rb->start);
    return (ra->end > rb->end) - (ra->end < rb->end);
}

static int pe_chain_cmp(const void *a, const void *b) {
    const pe_chain_ent *ca = (const pe_chain_ent *)a;
    const pe_chain_ent *cb = (const pe_chain_ent *)b;
    if (ca->root_beg != cb->root_beg) return (ca->root_beg > cb->root_beg) - (ca->root_beg < cb->root_beg);
    if (ca->beg != cb->beg) return (ca->beg > cb->beg) - (ca->beg < cb->beg);
    return (ca->end > cb->end) - (ca->end < cb->end);
}

static bool pe_unwind_chain_root(const bin_img *b, const uint8_t *d, uint64_t sz,
                                 uint32_t beg, uint32_t unw_rva,
                                 bool *is_chained, uint32_t *root_beg) {
    *is_chained = false;
    *root_beg = beg;

    uint64_t uoff = 0;
    if (!unw_rva || !pe_rva_off(b, unw_rva, &uoff) || uoff >= sz || sz - uoff < 4ULL) {
        return true;
    }

    uint8_t vf = d[uoff];
    uint8_t ver = vf & 0x07U;
    uint8_t flg = (uint8_t)((vf >> 3) & 0x1FU);
    if ((ver != 1U && ver != 2U) || !(flg & 0x04U)) {
        return true;
    }

    *is_chained = true;
    uint64_t seen[64];
    uint32_t nseen = 0;
    uint32_t cur_beg = beg;
    uint64_t cur_uoff = uoff;

    for (uint32_t depth = 0; depth < 64U; depth++) {
        for (uint32_t k = 0; k < nseen; k++) {
            if (seen[k] == cur_uoff) return false;
        }
        seen[nseen++] = cur_uoff;

        if (cur_uoff >= sz || sz - cur_uoff < 4ULL) return false;
        uint8_t vf2 = d[cur_uoff];
        uint8_t ver2 = vf2 & 0x07U;
        uint8_t flg2 = (uint8_t)((vf2 >> 3) & 0x1FU);
        if (ver2 != 1U && ver2 != 2U) return false;
        if (!(flg2 & 0x04U)) {
            *root_beg = cur_beg;
            return true;
        }

        uint8_t cnt = d[cur_uoff + 2ULL];
        uint64_t padded = (uint64_t)cnt + ((uint64_t)cnt & 1ULL);
        uint64_t chain_rel = 4ULL + padded * 2ULL;
        if (chain_rel > sz - cur_uoff || sz - (cur_uoff + chain_rel) < 12ULL) return false;

        uint64_t cref = cur_uoff + chain_rel;
        uint32_t cbeg = pe_u32(d, sz, cref);
        uint32_t cend = pe_u32(d, sz, cref + 4ULL);
        uint32_t cunw = pe_u32(d, sz, cref + 8ULL);
        if (!cbeg || cend <= cbeg || !cunw) return false;

        uint64_t next_uoff = 0;
        if (!pe_rva_off(b, cunw, &next_uoff)) return false;
        cur_beg = cbeg;
        cur_uoff = next_uoff;
    }
    return false;
}

static void pe_pdata(bin_img *b, uint32_t dir_rva, uint32_t dir_sz) {
    if (!b || !dir_rva) return;

    const uint8_t *d = b->map.data;
    uint64_t sz = b->map.size;

    if (b->arch == BIN_ARCH_ARM64) {
        if (dir_sz < 8U) return;
        uint64_t off = 0;
        if (!pe_rva_off(b, dir_rva, &off) || off >= sz) return;
        uint32_t count = dir_sz / 8U;
        uint64_t avail = (sz - off) / 8ULL;
        if ((uint64_t)count > avail) count = (uint32_t)avail;

        for (uint32_t i = 0; i < count; i++) {
            uint64_t rec = off + (uint64_t)i * 8ULL;
            uint32_t beg = pe_u32(d, sz, rec);
            uint32_t unw = pe_u32(d, sz, rec + 4ULL);
            uint32_t flag = unw & 3U;
            uint32_t flen = 0;
            if (flag == 1U || flag == 2U) {
                flen = ((unw >> 2) & 0x7FFU) * 4U;
            } else if (flag == 0U && unw != 0U) {
                uint64_t xoff = 0;
                if (pe_rva_off(b, unw & ~3U, &xoff) && xoff < sz && sz - xoff >= 4ULL) {
                    uint32_t xhdr = pe_u32(d, sz, xoff);
                    if (((xhdr >> 18) & 3U) == 0U) flen = (xhdr & 0x3FFFFU) * 4U;
                }
            }
            if (!beg || !flen || flen > UINT32_MAX - beg) continue;
            uint32_t end = beg + flen;
            if (b->base > UINT64_MAX - (uint64_t)end) continue;
            bin_add_pdata(b, b->base + (uint64_t)beg, b->base + (uint64_t)end);
        }
        return;
    }

    if (b->arch != BIN_ARCH_X64) return;
    if (dir_sz < 12U) return;
    uint64_t off = 0;
    if (!pe_rva_off(b, dir_rva, &off) || off >= sz) return;

    uint32_t count = dir_sz / 12U;
    uint64_t avail = (sz - off) / 12ULL;
    if ((uint64_t)count > avail) count = (uint32_t)avail;

    pe_chain_ent *chains = NULL;
    uint32_t nchain = 0, chain_cap = 0;
    bool chains_oom = false;

    for (uint32_t i = 0; i < count; i++) {
        uint64_t rec = off + (uint64_t)i * 12ULL;
        uint32_t beg = pe_u32(d, sz, rec);
        uint32_t end = pe_u32(d, sz, rec + 4ULL);
        uint32_t unw = pe_u32(d, sz, rec + 8ULL);
        if (!beg || end <= beg || b->base > UINT64_MAX - (uint64_t)end) continue;

        bool is_chained = false;
        uint32_t root_beg = beg;
        bool chain_ok = pe_unwind_chain_root(b, d, sz, beg, unw, &is_chained, &root_beg);
        if (!is_chained) {
            bin_add_pdata(b, b->base + (uint64_t)beg, b->base + (uint64_t)end);
        } else if (chain_ok && !chains_oom && nchain < 1048576U) {
            if (nchain == chain_cap) {
                uint32_t ncap = chain_cap ? ((chain_cap > 524288U) ? 1048576U : (chain_cap * 2U)) : 64U;
                pe_chain_ent *nc = (pe_chain_ent *)realloc(chains, (size_t)ncap * sizeof(pe_chain_ent));
                if (!nc) {
                    chains_oom = true;
                    continue;
                }
                chains = nc;
                chain_cap = ncap;
            }
            chains[nchain].beg = beg;
            chains[nchain].end = end;
            chains[nchain].root_beg = root_beg;
            nchain++;
        }
    }

    if (nchain > 0U && b->npdata > 0U) {
        if (b->npdata > 1U) qsort(b->pdata, b->npdata, sizeof(bin_range), pe_rng_cmp);
        if (nchain > 1U) qsort(chains, nchain, sizeof(pe_chain_ent), pe_chain_cmp);
        for (uint32_t k = 0; k < nchain; k++) {
            if (b->base > UINT64_MAX - (uint64_t)chains[k].root_beg) continue;
            uint64_t target = b->base + (uint64_t)chains[k].root_beg;
            uint32_t lo = 0, hi = b->npdata;
            while (lo < hi) {
                uint32_t mid = lo + (hi - lo) / 2U;
                if (b->pdata[mid].start < target) lo = mid + 1U;
                else hi = mid;
            }
            if (lo < b->npdata && b->pdata[lo].start == target) {
                bin_range *r = &b->pdata[lo];
                uint64_t cb = b->base + (uint64_t)chains[k].beg;
                uint64_t ce = b->base + (uint64_t)chains[k].end;
                if (cb >= r->start && cb <= r->end && ce > r->end) {
                    r->end = ce;
                }
            }
        }
    }
    free(chains);
}

bool pe_load(bin_img *b) {
    const uint8_t *d = b->map.data;
    uint64_t sz = b->map.size;
    if (sz < 0x40ULL || d[0] != 'M' || d[1] != 'Z') return false;

    uint32_t pe_off = pe_u32(d, sz, 0x3C);
    if ((uint64_t)pe_off > sz - 24ULL) return false;
    if (pe_u32(d, sz, (uint64_t)pe_off) != 0x00004550U) return false;

    uint16_t mach   = pe_u16(d, sz, (uint64_t)pe_off + 4ULL);
    uint16_t nsec   = pe_u16(d, sz, (uint64_t)pe_off + 6ULL);
    uint16_t opt_sz = pe_u16(d, sz, (uint64_t)pe_off + 20ULL);
    uint64_t opt    = (uint64_t)pe_off + 24ULL;
    if (opt_sz < 96U || opt > sz || sz - opt < (uint64_t)opt_sz) return false;

    uint16_t magic = pe_u16(d, sz, opt);
    int is64 = (magic == 0x20B);
    if (!is64 && magic != 0x10B) return false;

    b->fmt = is64 ? BIN_PE64 : BIN_PE32;
    b->bits = is64 ? 64 : 32;
    if (mach == 0xAA64) {
        b->arch = BIN_ARCH_ARM64;
    } else if (mach == 0x01C0 || mach == 0x01C2 || mach == 0x01C4) {
        b->arch = BIN_ARCH_ARM32;
        b->bits = 32;
    } else {
        b->arch = is64 ? BIN_ARCH_X64 : BIN_ARCH_X86;
    }
    uint32_t ep_rva = pe_u32(d, sz, opt + 16ULL);
    b->base = is64 ? pe_u64(d, sz, opt + 24ULL) : pe_u32(d, sz, opt + 28ULL);
    b->entry = (ep_rva && b->base <= UINT64_MAX - (uint64_t)ep_rva) ? (b->base + (uint64_t)ep_rva) : 0ULL;

    uint32_t dd_hdr_sz = is64 ? 112U : 96U;
    uint64_t dd_off = opt + (uint64_t)dd_hdr_sz;
    uint32_t ndd = 0;
    if (opt_sz >= dd_hdr_sz) {
        ndd = pe_u32(d, sz, dd_off - 4ULL);
        uint32_t max_dd = (uint32_t)((opt_sz - dd_hdr_sz) / 8U);
        if (ndd > max_dd) ndd = max_dd;
        if (ndd > 16U) ndd = 16U;
    }

    uint64_t sh_off = opt + (uint64_t)opt_sz;
    if (nsec > 256U) nsec = 256U;
    for (uint16_t i = 0; i < nsec; i++) {
        uint64_t s_rel = (uint64_t)i * 40ULL;
        if (sh_off > sz || s_rel > sz - sh_off || sz - (sh_off + s_rel) < 40ULL) break;
        uint64_t s = sh_off + s_rel;

        bin_sec sec;
        memset(&sec, 0, sizeof(sec));
        memcpy(sec.name, d + s, 8);
        sec.name[8] = 0;

        uint32_t vsz  = pe_u32(d, sz, s + 8ULL);
        uint32_t rva  = pe_u32(d, sz, s + 12ULL);
        uint32_t rsz  = pe_u32(d, sz, s + 16ULL);
        uint32_t roff = pe_u32(d, sz, s + 20ULL);
        uint32_t ch   = pe_u32(d, sz, s + 36ULL);

        if (b->base > UINT64_MAX - (uint64_t)rva) continue;
        sec.va = b->base + (uint64_t)rva;
        sec.foff = roff;
        sec.fsize = rsz;
        if (sec.foff > sz) sec.fsize = 0;
        else if (sec.fsize > sz - sec.foff) sec.fsize = sz - sec.foff;
        sec.vsize = vsz ? vsz : sec.fsize;
        if (vsz > 0 && sec.fsize > sec.vsize) sec.fsize = sec.vsize;

        if (ch & 0x40000000U) sec.perm |= BIN_PERM_R;
        if (ch & 0x80000000U) sec.perm |= BIN_PERM_W;
        if (ch & 0x20000000U) sec.perm |= BIN_PERM_X;
        if (!sec.perm) sec.perm = BIN_PERM_R;

        if (sec.vsize > 0) bin_add_sec(b, &sec);
    }

    if (b->nsec == 0) return false;

    if (ndd > 0U) {
        uint32_t erva = pe_u32(d, sz, dd_off);
        uint32_t esz  = pe_u32(d, sz, dd_off + 4ULL);
        pe_exports(b, erva, esz);
    }
    if (ndd > 1U) {
        uint32_t irva = pe_u32(d, sz, dd_off + 8ULL);
        uint32_t isz  = pe_u32(d, sz, dd_off + 12ULL);
        pe_imports(b, irva, isz, is64);
    }
    if ((b->arch == BIN_ARCH_X64 || b->arch == BIN_ARCH_ARM64) && ndd > 3U) {
        uint32_t prva = pe_u32(d, sz, dd_off + 24ULL);
        uint32_t psz  = pe_u32(d, sz, dd_off + 28ULL);
        pe_pdata(b, prva, psz);
    }
    if (ndd > 2U) {
        uint32_t rrva = pe_u32(d, sz, dd_off + 16ULL);
        uint64_t roff = 0;
        if (rrva && pe_rva_off(b, rrva, &roff) && roff <= sz && sz - roff >= 16ULL) {
            b->nrsrc = (uint32_t)pe_u16(d, sz, roff + 12ULL) + (uint32_t)pe_u16(d, sz, roff + 14ULL);
        }
    }
    if (ndd > 5U) {
        uint32_t brva = pe_u32(d, sz, dd_off + 40ULL);
        uint32_t bsz  = pe_u32(d, sz, dd_off + 44ULL);
        uint64_t boff = 0;
        if (brva && bsz >= 8U && pe_rva_off(b, brva, &boff) && boff < sz) {
            uint64_t rem_file = sz - boff;
            uint64_t lim = ((uint64_t)bsz < rem_file) ? (uint64_t)bsz : rem_file;
            uint64_t pos = 0;
            while (pos <= lim && lim - pos >= 8ULL) {
                uint32_t blk = pe_u32(d, sz, boff + pos + 4ULL);
                if (blk < 8U || (uint64_t)blk > lim - pos) break;
                b->nreloc += (blk - 8U) / 2U;
                pos += (uint64_t)blk;
            }
        }
    }
    if (ndd > 6U) {
        uint32_t drva = pe_u32(d, sz, dd_off + 48ULL);
        uint32_t dsz  = pe_u32(d, sz, dd_off + 52ULL);
        uint64_t doff = 0;
        if (drva && dsz >= 28U && pe_rva_off(b, drva, &doff) && doff < sz) {
            uint32_t cnt = dsz / 28U;
            if (cnt > 16U) cnt = 16U;
            for (uint32_t i = 0; i < cnt; i++) {
                uint64_t e_rel = (uint64_t)i * 28ULL;
                if (e_rel > sz - doff || sz - (doff + e_rel) < 28ULL) break;
                uint64_t e = doff + e_rel;
                if (pe_u32(d, sz, e + 12ULL) != 2U) continue;
                uint32_t rawp = pe_u32(d, sz, e + 24ULL);
                uint32_t raws = pe_u32(d, sz, e + 16ULL);
                if (rawp && raws > 24U && (uint64_t)rawp < sz && sz - (uint64_t)rawp > 24ULL &&
                    memcmp(d + rawp, "RSDS", 4) == 0) {
                    pe_cstr(d, sz, (uint64_t)rawp + 24ULL, b->pdb_path, sizeof(b->pdb_path));
                    break;
                }
            }
        }
    }
    if (ndd > 9U) {
        uint32_t trva = pe_u32(d, sz, dd_off + 72ULL);
        uint64_t toff = 0;
        if (trva && pe_rva_off(b, trva, &toff) && toff < sz && sz - toff >= (is64 ? 32ULL : 16ULL)) {
            uint64_t cb_va = is64 ? pe_u64(d, sz, toff + 24ULL) : pe_u32(d, sz, toff + 12ULL);
            if (cb_va > b->base && cb_va - b->base <= (uint64_t)UINT32_MAX) {
                uint64_t cboff = 0;
                if (pe_rva_off(b, (uint32_t)(cb_va - b->base), &cboff) && cboff < sz) {
                    uint32_t stride = is64 ? 8U : 4U;
                    for (uint32_t i = 0; i < 32U; i++) {
                        uint64_t cb_rel = (uint64_t)i * (uint64_t)stride;
                        if (cb_rel > sz - cboff || sz - (cboff + cb_rel) < (uint64_t)stride) break;
                        uint64_t fn = is64 ? pe_u64(d, sz, cboff + cb_rel)
                                           : pe_u32(d, sz, cboff + cb_rel);
                        if (!fn) break;
                        b->tls_cbs[b->ntls++] = fn;
                        char nm[32];
                        snprintf(nm, sizeof(nm), "tls_callback_%u", i);
                        bin_add_sym(b, fn, nm, BIN_SYM_FUNC);
                    }
                }
            }
        }
    }
    if (ndd > 10U) {
        uint32_t lrva = pe_u32(d, sz, dd_off + 80ULL);
        uint64_t loff = 0;
        if (lrva && pe_rva_off(b, lrva, &loff) && loff < sz) {
            if (sz - loff >= (is64 ? 96ULL : 64ULL)) {
                b->sec_cookie = is64 ? pe_u64(d, sz, loff + 88ULL) : pe_u32(d, sz, loff + 60ULL);
            }
            if (sz - loff >= (is64 ? 148ULL : 92ULL)) {
                b->guard_flags = pe_u32(d, sz, is64 ? loff + 144ULL : loff + 88ULL);
            }
        }
    }
    if (ndd > 13U) {
        uint32_t drva = pe_u32(d, sz, dd_off + 104ULL);
        uint32_t dsz  = pe_u32(d, sz, dd_off + 108ULL);
        pe_delay_imports(b, drva, dsz, is64);
    }
    if (ndd > 14U && pe_u32(d, sz, dd_off + 112ULL) != 0U) b->has_clr = 1;

    uint64_t end_raw = 0;
    for (uint32_t i = 0; i < b->nsec; i++) {
        if (b->secs[i].foff <= sz && b->secs[i].fsize <= sz - b->secs[i].foff) {
            uint64_t e = b->secs[i].foff + b->secs[i].fsize;
            if (e > end_raw) end_raw = e;
        }
    }
    if (end_raw > 0 && end_raw < sz) {
        b->overlay_off = end_raw;
        b->overlay_size = sz - end_raw;
    }

    if (b->entry) bin_add_sym(b, b->entry, "_start", BIN_SYM_FUNC);
    return true;
}
