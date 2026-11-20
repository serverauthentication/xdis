#pragma once

#include "../core/map.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum {
    BIN_RAW = 0,
    BIN_PE32,
    BIN_PE64,
    BIN_ELF32,
    BIN_ELF64,
    BIN_MACHO64,
    BIN_WASM,
    BIN_DEX
} bin_fmt;

typedef enum {
    BIN_ARCH_X64 = 0,
    BIN_ARCH_X86,
    BIN_ARCH_ARM64,
    BIN_ARCH_ARM32,
    BIN_ARCH_RISCV64,
    BIN_ARCH_RISCV32,
    BIN_ARCH_MIPS32,
    BIN_ARCH_WASM,
    BIN_ARCH_CIL
} bin_arch;

enum {
    BIN_PERM_R = 1,
    BIN_PERM_W = 2,
    BIN_PERM_X = 4
};

typedef enum {
    BIN_SYM_FUNC = 0,
    BIN_SYM_IMPORT,
    BIN_SYM_EXPORT,
    BIN_SYM_DATA,
    BIN_SYM_LABEL
} bin_sym_kind;

typedef struct {
    char     name[24];
    uint64_t va;
    uint64_t vsize;
    uint64_t foff;
    uint64_t fsize;
    uint32_t perm;
} bin_sec;

enum {
    BIN_SYM_F_NOFUNC = 1U
};

typedef struct {
    uint64_t va;
    uint32_t name_off;
    uint8_t  kind;
    uint8_t  flags;
} bin_sym;

_Static_assert(sizeof(bin_sym) == 16, "bin_sym size");

typedef struct {
    uint64_t start;
    uint64_t end;
} bin_range;

typedef struct {
    map_file   map;
    char       path[512];
    bin_fmt    fmt;
    bin_arch   arch;
    int        bits;
    uint64_t   base;
    uint64_t   entry;
    uint64_t   min_va;
    uint64_t   max_va;
    uint64_t   overlay_off;
    uint64_t   overlay_size;
    int        has_clr;
    char       pdb_path[260];
    uint64_t   tls_cbs[32];
    uint32_t   ntls;
    uint32_t   nreloc;
    uint32_t   nrsrc;
    uint64_t   sec_cookie;
    uint32_t   guard_flags;
    bin_sec   *secs;
    uint32_t   nsec;
    uint32_t   sec_cap;
    bin_sym   *syms;
    uint32_t   nsym;
    uint32_t   sym_cap;
    bin_range *pdata;
    uint32_t   npdata;
    uint32_t   pdata_cap;
    char      *pool;
    uint32_t   pool_len;
    uint32_t   pool_cap;
} bin_img;

bool        bin_open(bin_img *b, const char *path, uint64_t raw_base, int raw_bits);
bool        bin_open_buf(bin_img *b, uint8_t *buf, uint64_t size, const char *label, uint64_t raw_base, int raw_bits);
void        bin_close(bin_img *b);

const char *bin_fmt_name(bin_fmt f);
const char *bin_arch_name(bin_arch a);
const char *bin_str(const bin_img *b, uint32_t off);
uint32_t    bin_add_str(bin_img *b, const char *s);
bool        bin_add_sec(bin_img *b, const bin_sec *s);
bool        bin_add_sym(bin_img *b, uint64_t va, const char *name, uint8_t kind);
bool        bin_add_pdata(bin_img *b, uint64_t start, uint64_t end);

const bin_sec *bin_sec_at(const bin_img *b, uint64_t va);
bool        bin_va_to_off(const bin_img *b, uint64_t va, uint64_t *off);
bool        bin_off_to_va(const bin_img *b, uint64_t off, uint64_t *va);
const uint8_t *bin_ptr(const bin_img *b, uint64_t va, size_t *avail);
uint8_t    *bin_ptr_rw(bin_img *b, uint64_t va, size_t *avail);
size_t      bin_read(const bin_img *b, uint64_t va, uint8_t *dst, size_t n);
bool        bin_is_exec(const bin_img *b, uint64_t va);

bool        pe_load(bin_img *b);
bool        elf_load(bin_img *b);
bool        mo_load(bin_img *b);
bool        bc_load_wasm(bin_img *b);
bool        bc_load_dex(bin_img *b);
bool        dem_name(const char *mangled, char *out, size_t max);
uint32_t    pdb_load_file(bin_img *b, const char *path);

typedef struct {
    char     ns[64];
    char     name[64];
    uint32_t flags;
} bc_clr_type;

typedef struct {
    char     name[80];
    uint64_t va;
    uint32_t rva;
    uint32_t flags;
} bc_clr_method;

typedef struct {
    int           ok;
    char          runtime_ver[32];
    uint32_t      entry_token;
    bc_clr_type   types[128];
    int           ntype;
    bc_clr_method methods[192];
    int           nmethod;
    char          strings[64][96];
    int           nstr;
} bc_clr_info;

bool        bc_inspect_dotnet(const bin_img *b, bc_clr_info *out);
