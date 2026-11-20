#include "bin.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BIN_MAX_POOL  (32U * 1024U * 1024U)
#define BIN_MAX_SYMS  262144U
#define BIN_MAX_SECS  65536U
#define BIN_MAX_PDATA 1048576U

static uint64_t bin_sat_add_u64(uint64_t a, uint64_t b) {
    return (b > UINT64_MAX - a) ? UINT64_MAX : (a + b);
}

static int bin_sec_cmp(const void *a, const void *b) {
    uint64_t va = ((const bin_sec *)a)->va;
    uint64_t vb = ((const bin_sec *)b)->va;
    return (va > vb) - (va < vb);
}

const char *bin_fmt_name(bin_fmt f) {
    switch (f) {
    case BIN_PE32:    return "PE32";
    case BIN_PE64:    return "PE32+";
    case BIN_ELF32:   return "ELF32";
    case BIN_ELF64:   return "ELF64";
    case BIN_MACHO64: return "Mach-O64";
    case BIN_WASM:    return "WASM";
    case BIN_DEX:     return "DEX";
    default:          return "RAW";
    }
}

const char *bin_arch_name(bin_arch a) {
    switch (a) {
    case BIN_ARCH_X86:     return "x86";
    case BIN_ARCH_ARM64:   return "arm64";
    case BIN_ARCH_ARM32:   return "arm32";
    case BIN_ARCH_RISCV64: return "riscv64";
    case BIN_ARCH_RISCV32: return "riscv32";
    case BIN_ARCH_MIPS32:  return "mips32";
    case BIN_ARCH_WASM:    return "wasm";
    case BIN_ARCH_CIL:     return "cil";
    default:               return "x86-64";
    }
}

const char *bin_str(const bin_img *b, uint32_t off) {
    if (!b || !b->pool || off >= b->pool_len) return "";
    return b->pool + off;
}

uint32_t bin_add_str(bin_img *b, const char *s) {
    if (!b) return 0;
    if (!s) s = "";
    size_t slen = strlen(s);
    if (slen >= (size_t)BIN_MAX_POOL) return 0;
    uint32_t n = (uint32_t)(slen + 1U);
    if (b->pool_len > BIN_MAX_POOL || n > BIN_MAX_POOL - b->pool_len) return 0;
    uint32_t need = b->pool_len + n;
    if (need > b->pool_cap) {
        uint32_t ncap = b->pool_cap ? b->pool_cap : 4096U;
        while (ncap < need) {
            if (ncap >= BIN_MAX_POOL) { ncap = BIN_MAX_POOL; break; }
            ncap = (ncap > BIN_MAX_POOL / 2U) ? BIN_MAX_POOL : (ncap * 2U);
        }
        char *np = (char *)realloc(b->pool, (size_t)ncap);
        if (!np) return 0;
        b->pool = np;
        b->pool_cap = ncap;
    }
    uint32_t off = b->pool_len;
    memcpy(b->pool + off, s, (size_t)n);
    b->pool_len = need;
    return off;
}

bool bin_add_sec(bin_img *b, const bin_sec *s) {
    if (!b || !s || b->nsec >= BIN_MAX_SECS) return false;
    if (b->nsec == b->sec_cap) {
        uint32_t ncap = b->sec_cap ? ((b->sec_cap > BIN_MAX_SECS / 2U) ? BIN_MAX_SECS : (b->sec_cap * 2U)) : 16U;
        if (ncap <= b->sec_cap || (size_t)ncap > SIZE_MAX / sizeof(bin_sec)) return false;
        bin_sec *ns = (bin_sec *)realloc(b->secs, (size_t)ncap * sizeof(bin_sec));
        if (!ns) return false;
        b->secs = ns;
        b->sec_cap = ncap;
    }
    b->secs[b->nsec++] = *s;
    return true;
}

bool bin_add_sym(bin_img *b, uint64_t va, const char *name, uint8_t kind) {
    if (!b || !name || !name[0]) return false;
    if (b->nsym >= BIN_MAX_SYMS) return false;
    char dem[160];
    if (!strstr(name, "->") &&
        (name[0] == '?' || (name[0] == '_' && (name[1] == 'Z' || (name[1] == '_' && name[2] == 'Z')))) &&
        dem_name(name, dem, sizeof(dem))) {
        if (dem[0]) name = dem;
    }
    if (b->pool_len == 0) {
        if (bin_add_str(b, "") == 0 && b->pool_len == 0) return false;
    }
    size_t slen = strlen(name);
    if (slen >= (size_t)BIN_MAX_POOL || slen + 1U > (size_t)(BIN_MAX_POOL - b->pool_len)) return false;
    if (b->nsym == b->sym_cap) {
        uint32_t ncap = b->sym_cap ? ((b->sym_cap > BIN_MAX_SYMS / 2U) ? BIN_MAX_SYMS : (b->sym_cap * 2U)) : 256U;
        if (ncap <= b->sym_cap || (size_t)ncap > SIZE_MAX / sizeof(bin_sym)) return false;
        bin_sym *ns = (bin_sym *)realloc(b->syms, (size_t)ncap * sizeof(bin_sym));
        if (!ns) return false;
        b->syms = ns;
        b->sym_cap = ncap;
    }
    uint32_t off = bin_add_str(b, name);
    if (off == 0) return false;
    bin_sym *sym = &b->syms[b->nsym];
    memset(sym, 0, sizeof(*sym));
    sym->va = va;
    sym->name_off = off;
    sym->kind = kind;
    sym->flags = 0;
    b->nsym++;
    return true;
}

bool bin_add_pdata(bin_img *b, uint64_t start, uint64_t end) {
    if (!b || end <= start || b->npdata >= BIN_MAX_PDATA) return false;
    if (b->npdata == b->pdata_cap) {
        uint32_t ncap = b->pdata_cap ? ((b->pdata_cap > BIN_MAX_PDATA / 2U) ? BIN_MAX_PDATA : (b->pdata_cap * 2U)) : 512U;
        if (ncap <= b->pdata_cap || (size_t)ncap > SIZE_MAX / sizeof(bin_range)) return false;
        bin_range *nr = (bin_range *)realloc(b->pdata, (size_t)ncap * sizeof(bin_range));
        if (!nr) return false;
        b->pdata = nr;
        b->pdata_cap = ncap;
    }
    b->pdata[b->npdata].start = start;
    b->pdata[b->npdata].end = end;
    b->npdata++;
    return true;
}

static bool bin_parse(bin_img *b, uint64_t raw_base, int raw_bits) {
    bin_add_str(b, "");

    bool ok = false;
    if (b->map.size >= 64 && b->map.data[0] == 'M' && b->map.data[1] == 'Z') {
        ok = pe_load(b);
    } else if (b->map.size >= 52 && memcmp(b->map.data, "\x7f" "ELF", 4) == 0) {
        ok = elf_load(b);
    } else if (b->map.size >= 8 && memcmp(b->map.data, "\0asm", 4) == 0) {
        ok = bc_load_wasm(b);
    } else if (b->map.size >= 112 && memcmp(b->map.data, "dex\n", 4) == 0) {
        ok = bc_load_dex(b);
    } else if (b->map.size >= 32) {
        uint32_t mg = 0;
        memcpy(&mg, b->map.data, 4);
        if (mg == 0xFEEDFACFU || mg == 0xBEBAFECAU || mg == 0xCAFEBABEU) ok = mo_load(b);
    }

    if (!ok) {
        b->fmt = BIN_RAW;
        b->bits = (raw_bits == 32) ? 32 : 64;
        b->arch = (b->bits == 32) ? BIN_ARCH_X86 : BIN_ARCH_X64;
        b->base = raw_base ? raw_base : 0x100000ULL;
        b->entry = b->base;
        bin_sec s;
        memset(&s, 0, sizeof(s));
        snprintf(s.name, sizeof(s.name), ".raw");
        s.va = b->base;
        s.vsize = b->map.size;
        s.foff = 0;
        s.fsize = b->map.size;
        s.perm = BIN_PERM_R | BIN_PERM_W | BIN_PERM_X;
        bin_add_sec(b, &s);
    }

    if (b->nsec > 1) qsort(b->secs, b->nsec, sizeof(bin_sec), bin_sec_cmp);
    if (b->nsec == 0) return false;

    b->min_va = b->secs[0].va;
    b->max_va = bin_sat_add_u64(b->secs[0].va, b->secs[0].vsize);
    for (uint32_t i = 1; i < b->nsec; i++) {
        uint64_t end = bin_sat_add_u64(b->secs[i].va, b->secs[i].vsize);
        if (end > b->max_va) b->max_va = end;
    }

    if (!bin_sec_at(b, b->entry)) {
        b->entry = b->min_va;
        for (uint32_t i = 0; i < b->nsec; i++) {
            if (b->secs[i].perm & BIN_PERM_X) {
                b->entry = b->secs[i].va;
                break;
            }
        }
    }

    return true;
}

bool bin_open(bin_img *b, const char *path, uint64_t raw_base, int raw_bits) {
    memset(b, 0, sizeof(*b));
    if (!map_open(&b->map, path)) return false;
    snprintf(b->path, sizeof(b->path), "%s", path);
    if (!bin_parse(b, raw_base, raw_bits)) {
        bin_close(b);
        return false;
    }
    return true;
}

bool bin_open_buf(bin_img *b, uint8_t *buf, uint64_t size, const char *label, uint64_t raw_base, int raw_bits) {
    memset(b, 0, sizeof(*b));
    if (!map_open_buf(&b->map, buf, size, 0)) return false;
    snprintf(b->path, sizeof(b->path), "%s", label ? label : "<mem>");
    if (!bin_parse(b, raw_base, raw_bits)) {
        bin_close(b);
        return false;
    }
    return true;
}

void bin_close(bin_img *b) {
    if (!b) return;
    free(b->secs);
    free(b->syms);
    free(b->pdata);
    free(b->pool);
    map_close(&b->map);
    memset(b, 0, sizeof(*b));
}

const bin_sec *bin_sec_at(const bin_img *b, uint64_t va) {
    if (!b || !b->secs) return NULL;
    uint32_t lo = 0, hi = b->nsec;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        const bin_sec *s = &b->secs[mid];
        if (va < s->va) {
            hi = mid;
        } else if (va - s->va >= s->vsize) {
            lo = mid + 1;
        } else {
            return s;
        }
    }
    return NULL;
}

bool bin_va_to_off(const bin_img *b, uint64_t va, uint64_t *off) {
    if (!b || !off) return false;
    const bin_sec *s = bin_sec_at(b, va);
    if (!s) return false;
    uint64_t rel = va - s->va;
    if (rel >= s->fsize || s->foff >= b->map.size || rel >= b->map.size - s->foff) return false;
    *off = s->foff + rel;
    return true;
}

bool bin_off_to_va(const bin_img *b, uint64_t off, uint64_t *va) {
    if (!b || !va || !b->secs || off >= b->map.size) return false;
    for (uint32_t i = 0; i < b->nsec; i++) {
        const bin_sec *s = &b->secs[i];
        if (s->foff >= b->map.size) continue;
        if (off >= s->foff && off - s->foff < s->fsize) {
            uint64_t rel = off - s->foff;
            if (rel >= b->map.size - s->foff || rel >= s->vsize || rel > UINT64_MAX - s->va) continue;
            *va = s->va + rel;
            return true;
        }
    }
    return false;
}

const uint8_t *bin_ptr(const bin_img *b, uint64_t va, size_t *avail) {
    if (!b || !b->map.data) {
        if (avail) *avail = 0;
        return NULL;
    }
    const bin_sec *s = bin_sec_at(b, va);
    if (!s) {
        if (avail) *avail = 0;
        return NULL;
    }
    uint64_t rel = va - s->va;
    if (rel >= s->fsize || s->foff >= b->map.size || rel >= b->map.size - s->foff) {
        if (avail) *avail = 0;
        return NULL;
    }
    uint64_t fpos = s->foff + rel;
    uint64_t rem = s->fsize - rel;
    uint64_t max_rem = b->map.size - fpos;
    if (rem > max_rem) rem = max_rem;
    #if SIZE_MAX < UINT64_MAX
    if (rem > (uint64_t)SIZE_MAX) rem = (uint64_t)SIZE_MAX;
    #endif
    if (avail) *avail = (size_t)rem;
    return b->map.data + fpos;
}

uint8_t *bin_ptr_rw(bin_img *b, uint64_t va, size_t *avail) {
    if (!b->map.writable) {
        if (avail) *avail = 0;
        return NULL;
    }
    return (uint8_t *)bin_ptr(b, va, avail);
}

size_t bin_read(const bin_img *b, uint64_t va, uint8_t *dst, size_t n) {
    size_t avail = 0;
    const uint8_t *p = bin_ptr(b, va, &avail);
    if (!p || avail == 0) return 0;
    if (n > avail) n = avail;
    memcpy(dst, p, n);
    return n;
}

bool bin_is_exec(const bin_img *b, uint64_t va) {
    const bin_sec *s = bin_sec_at(b, va);
    return s && (s->perm & BIN_PERM_X);
}
