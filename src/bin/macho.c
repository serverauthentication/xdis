#include "bin.h"

#include <stdio.h>
#include <string.h>

static uint32_t mo_u32(const uint8_t *d, uint64_t end, uint64_t off) {
    if (off > end || end - off < 4) return 0;
    uint32_t v;
    memcpy(&v, d + off, 4);
    return v;
}

static uint32_t mo_be32(const uint8_t *d, uint64_t end, uint64_t off) {
    if (off > end || end - off < 4) return 0;
    return ((uint32_t)d[off] << 24) |
           ((uint32_t)d[off + 1] << 16) |
           ((uint32_t)d[off + 2] << 8) |
           (uint32_t)d[off + 3];
}

static uint64_t mo_u64(const uint8_t *d, uint64_t end, uint64_t off) {
    if (off > end || end - off < 8) return 0;
    uint64_t v;
    memcpy(&v, d + off, 8);
    return v;
}

static void mo_fixstr(const uint8_t *d, uint64_t end, uint64_t off, char out[17]) {
    size_t n = 0;
    while (n < 16 && off + n < end && d[off + n] != 0) {
        out[n] = (char)d[off + n];
        n++;
    }
    out[n] = 0;
}

static size_t mo_cstr(const uint8_t *d, uint64_t end, uint64_t off, char *out, size_t max) {
    if (off >= end || max == 0) {
        if (max) out[0] = 0;
        return 0;
    }
    size_t n = 0;
    while (off + n < end && n + 1 < max && d[off + n] != 0) {
        out[n] = (char)d[off + n];
        n++;
    }
    out[n] = 0;
    return n;
}

static uint32_t mo_prot(uint32_t p) {
    uint32_t perm = 0;
    if (p & 1U) perm |= BIN_PERM_R;
    if (p & 2U) perm |= BIN_PERM_W;
    if (p & 4U) perm |= BIN_PERM_X;
    return perm;
}

static bool mo_va_exec(const bin_img *b, uint64_t va) {
    // secs not sorted yet
    for (uint32_t i = 0; i < b->nsec; i++) {
        const bin_sec *s = &b->secs[i];
        if (va >= s->va && va - s->va < s->vsize) {
            return (s->perm & BIN_PERM_X) != 0;
        }
    }
    return false;
}

static bool mo_off_va(const bin_img *b, uint64_t foff, uint64_t *va) {
    for (uint32_t i = 0; i < b->nsec; i++) {
        const bin_sec *s = &b->secs[i];
        if (foff >= s->foff && foff - s->foff < s->fsize) {
            *va = s->va + (foff - s->foff);
            return true;
        }
    }
    return false;
}

static bool mo_pick_slice(const uint8_t *d, uint64_t sz, uint64_t *off_out, uint64_t *sz_out) {
    if (sz < 32) return false;
    uint32_t mg = mo_u32(d, sz, 0);
    if (mg == 0xFEEDFACFU) {
        *off_out = 0;
        *sz_out = sz;
        return true;
    }

    bool be = (mg == 0xBEBAFECAU);
    if (!be && mg != 0xCAFEBABEU) return false;

    uint32_t nfat = be ? mo_be32(d, sz, 4) : mo_u32(d, sz, 4);
    if (nfat == 0 || nfat > 64) return false;

    bool found = false;
    uint64_t best_off = 0, best_sz = 0;
    for (uint32_t i = 0; i < nfat; i++) {
        uint64_t p = 8 + (uint64_t)i * 20;
        if (p + 20 > sz) break;
        uint32_t cpu  = be ? mo_be32(d, sz, p + 0)  : mo_u32(d, sz, p + 0);
        uint32_t soff = be ? mo_be32(d, sz, p + 8)  : mo_u32(d, sz, p + 8);
        uint32_t ssz  = be ? mo_be32(d, sz, p + 12) : mo_u32(d, sz, p + 12);
        if ((uint64_t)soff >= sz || ssz < 32 || (uint64_t)ssz > sz - soff) continue;
        if (mo_u32(d, sz, soff) != 0xFEEDFACFU) continue;

        if (cpu == 0x0100000CU) {
            *off_out = soff;
            *sz_out = ssz;
            return true;
        }
        if (cpu == 0x01000007U && !found) {
            best_off = soff;
            best_sz = ssz;
            found = true;
        }
    }
    if (!found) return false;
    *off_out = best_off;
    *sz_out = best_sz;
    return true;
}

static void mo_add_seg(bin_img *b, const uint8_t *d, uint64_t base_off, uint64_t slice_end,
                       uint64_t cmd_off, uint32_t cmdsize, uint64_t *text_base, bool *has_text) {
    if (cmdsize < 72) return;

    char seg[17];
    mo_fixstr(d, slice_end, cmd_off + 8, seg);
    if (strcmp(seg, "__PAGEZERO") == 0) return;

    uint64_t vmaddr   = mo_u64(d, slice_end, cmd_off + 24);
    uint64_t vmsize   = mo_u64(d, slice_end, cmd_off + 32);
    uint64_t fileoff  = mo_u64(d, slice_end, cmd_off + 40);
    uint64_t filesize = mo_u64(d, slice_end, cmd_off + 48);
    uint32_t initprot = mo_u32(d, slice_end, cmd_off + 60);
    uint32_t nsects   = mo_u32(d, slice_end, cmd_off + 64);

    if (strcmp(seg, "__TEXT") == 0 && vmsize > 0 && !*has_text) {
        *text_base = vmaddr;
        *has_text = true;
    }

    uint32_t perm = mo_prot(initprot);
    uint32_t max_sects = (cmdsize - 72) / 80;
    if (nsects > max_sects) nsects = max_sects;

    if (nsects == 0) {
        if (vmsize == 0 || perm == 0) return;
        bin_sec s;
        memset(&s, 0, sizeof(s));
        snprintf(s.name, sizeof(s.name), "%s", seg[0] ? seg : "__SEG");
        s.va = vmaddr;
        s.vsize = vmsize;
        if (fileoff < slice_end - base_off) {
            s.foff = base_off + fileoff;
            uint64_t rem = slice_end - s.foff;
            s.fsize = filesize <= rem ? filesize : rem;
        }
        s.perm = perm;
        bin_add_sec(b, &s);
        return;
    }

    for (uint32_t i = 0; i < nsects; i++) {
        uint64_t sp = cmd_off + 72 + (uint64_t)i * 80;
        char sect[17], sseg[17];
        mo_fixstr(d, slice_end, sp + 0, sect);
        mo_fixstr(d, slice_end, sp + 16, sseg);

        uint64_t addr  = mo_u64(d, slice_end, sp + 32);
        uint64_t ssz   = mo_u64(d, slice_end, sp + 40);
        uint32_t soff  = mo_u32(d, slice_end, sp + 48);
        uint32_t flags = mo_u32(d, slice_end, sp + 64);
        if (ssz == 0) continue;

        bin_sec s;
        memset(&s, 0, sizeof(s));
        const char *sn = sseg[0] ? sseg : seg;
        if (sn[0] && sect[0]) snprintf(s.name, sizeof(s.name), "%s,%s", sn, sect);
        else snprintf(s.name, sizeof(s.name), "%s", sect[0] ? sect : sn);
        s.va = addr;
        s.vsize = ssz;

        uint32_t stype = flags & 0xFFU;
        if (stype == 1U || stype == 0xCU || stype == 0x12U) {
            s.foff = 0;
            s.fsize = 0;
        } else if ((uint64_t)soff < slice_end - base_off) {
            s.foff = base_off + (uint64_t)soff;
            uint64_t rem = slice_end - s.foff;
            s.fsize = ssz <= rem ? ssz : rem;
        }
        s.perm = perm;
        bin_add_sec(b, &s);
    }
}

static void mo_load_syms(bin_img *b, const uint8_t *d, uint64_t base_off, uint64_t slice_end,
                         uint32_t symoff, uint32_t nsyms, uint32_t stroff, uint32_t strsize) {
    if (strsize == 0 || nsyms == 0) return;
    if ((uint64_t)symoff >= slice_end - base_off) return;
    if ((uint64_t)stroff >= slice_end - base_off) return;

    uint64_t sym_pos = base_off + (uint64_t)symoff;
    uint64_t str_pos = base_off + (uint64_t)stroff;
    uint64_t str_end = str_pos + (uint64_t)strsize;
    if (str_end > slice_end) str_end = slice_end;

    uint64_t max_n = (slice_end - sym_pos) / 16;
    if ((uint64_t)nsyms > max_n) nsyms = (uint32_t)max_n;
    if (nsyms > 200000) nsyms = 200000;

    char name[128];
    for (uint32_t i = 0; i < nsyms; i++) {
        uint64_t p = sym_pos + (uint64_t)i * 16;
        uint32_t strx  = mo_u32(d, slice_end, p);
        uint8_t  ntype = d[p + 4];
        uint64_t val   = mo_u64(d, slice_end, p + 8);
        if ((ntype & 0xE0U) != 0) continue;
        if ((ntype & 0x0EU) != 0x0EU || val == 0) continue;
        if (strx == 0 || (uint64_t)strx >= str_end - str_pos) continue;
        if (mo_cstr(d, str_end, str_pos + strx, name, sizeof(name)) == 0) continue;
        bin_add_sym(b, val, name, mo_va_exec(b, val) ? BIN_SYM_FUNC : BIN_SYM_DATA);
    }
}

bool mo_load(bin_img *b) {
    const uint8_t *d = b->map.data;
    uint64_t sz = b->map.size;
    uint64_t base_off = 0, slice_sz = 0;
    if (!mo_pick_slice(d, sz, &base_off, &slice_sz)) return false;

    uint64_t slice_end = base_off + slice_sz;
    uint32_t cputype    = mo_u32(d, slice_end, base_off + 4);
    uint32_t ncmds      = mo_u32(d, slice_end, base_off + 16);
    uint32_t sizeofcmds = mo_u32(d, slice_end, base_off + 20);

    b->fmt  = BIN_MACHO64;
    b->bits = 64;
    b->arch = (cputype == 0x0100000CU) ? BIN_ARCH_ARM64 : BIN_ARCH_X64;

    uint64_t cmd_off  = base_off + 32;
    uint64_t cmds_end = slice_end;
    if ((uint64_t)sizeofcmds < slice_end - cmd_off) cmds_end = cmd_off + (uint64_t)sizeofcmds;
    if (ncmds > 4096) ncmds = 4096;

    bool     has_text  = false;
    uint64_t text_base = 0;
    bool     has_main  = false;
    uint64_t entry_off = 0;
    bool     has_sym   = false;
    uint32_t symoff = 0, nsyms = 0, stroff = 0, strsize = 0;

    for (uint32_t i = 0; i < ncmds; i++) {
        if (cmd_off + 8 > cmds_end) break;
        uint32_t cmd     = mo_u32(d, cmds_end, cmd_off);
        uint32_t cmdsize = mo_u32(d, cmds_end, cmd_off + 4);
        if (cmdsize < 8 || (uint64_t)cmdsize > cmds_end - cmd_off) break;

        if (cmd == 0x19U) {
            mo_add_seg(b, d, base_off, slice_end, cmd_off, cmdsize, &text_base, &has_text);
        } else if (cmd == 0x80000028U && cmdsize >= 24) {
            entry_off = mo_u64(d, cmds_end, cmd_off + 8);
            has_main = true;
        } else if (cmd == 0x02U && cmdsize >= 24) {
            symoff  = mo_u32(d, cmds_end, cmd_off + 8);
            nsyms   = mo_u32(d, cmds_end, cmd_off + 12);
            stroff  = mo_u32(d, cmds_end, cmd_off + 16);
            strsize = mo_u32(d, cmds_end, cmd_off + 20);
            has_sym = true;
        }
        cmd_off += cmdsize;
    }

    if (b->nsec == 0) return false;
    b->base = has_text ? text_base : b->secs[0].va;

    if (has_main) {
        if (has_text) b->entry = text_base + entry_off;
        else if (!mo_off_va(b, base_off + entry_off, &b->entry)) b->entry = b->base + entry_off;
    }
    if (has_sym) {
        mo_load_syms(b, d, base_off, slice_end, symoff, nsyms, stroff, strsize);
    }
    if (b->entry) bin_add_sym(b, b->entry, "_start", BIN_SYM_FUNC);
    return true;
}
