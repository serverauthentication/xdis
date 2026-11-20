#include "ana.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TNT_STACK_BASE   0x7FFF0000ULL
#define TNT_STACK_SIZE   65536U
#define TNT_STACK_INIT   0x7FFF8000ULL
#define TNT_HEAP_BASE    0x20000000ULL
#define TNT_HEAP_SIZE    65536U
#define TNT_RET_SENTINEL 0xDEAD0000ULL
#define TNT_MAX_BUF      4096U
#define TNT_MAX_CFG_BLKS 256
#define TNT_MAX_PATH     64
#define TNT_MAX_SLOTS    32

typedef struct {
    uint8_t  stack[TNT_STACK_SIZE];
    uint8_t  stack_taint[TNT_STACK_SIZE];
    uint8_t  heap[TNT_HEAP_SIZE];
    uint8_t  heap_taint[TNT_HEAP_SIZE];
    uint32_t heap_top;
    uint64_t regs[16];
    uint64_t a64_hi[16];
    uint16_t reg_taint;
    uint16_t a64_hi_taint;
    uint64_t pc;
    int      zf;
    int      sf;
    int      cf;
    int      of;
    int      flag_taint;
    int      is_a64;
    int      is_32;
} tnt_vm;

static const char *const tnt_x86_r64[16] = {
    "rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi",
    "r8","r9","r10","r11","r12","r13","r14","r15"
};

static void tnt_trim(char *s) {
    char *p = s;
    while (*p == ' ' || *p == '\t') p++;
    if (p != s) memmove(s, p, strlen(p) + 1);
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\t')) s[--n] = 0;
}

static int tnt_split_ops(const char *ops, char out[4][76]) {
    for (int i = 0; i < 4; i++) out[i][0] = 0;
    if (!ops || !ops[0]) return 0;

    int cnt = 0;
    int depth = 0;
    const char *start = ops;
    for (const char *p = ops; ; p++) {
        if (*p == '[') depth++;
        else if (*p == ']' && depth > 0) depth--;
        if ((*p == ',' && depth == 0) || *p == 0) {
            if (cnt < 4) {
                size_t n = (size_t)(p - start);
                if (n >= 75) n = 75;
                memcpy(out[cnt], start, n);
                out[cnt][n] = 0;
                tnt_trim(out[cnt]);
                if (out[cnt][0] || *p == ',') cnt++;
            }
            if (*p == 0) break;
            start = p + 1;
        }
    }
    return cnt;
}

static bool tnt_parse_imm(const char *s, uint64_t *val) {
    if (!s || !s[0]) return false;
    const char *p = s;
    while (*p == ' ' || *p == '\t') p++;
    if (*p == '#') p++;
    int neg = 0;
    if (*p == '-') { neg = 1; p++; }
    else if (*p == '+') p++;
    if (!*p) return false;

    char *end = NULL;
    uint64_t v = 0;
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
        if (!isxdigit((unsigned char)p[2])) return false;
        v = strtoull(p + 2, &end, 16);
    } else if (isdigit((unsigned char)p[0])) {
        v = strtoull(p, &end, 10);
    } else {
        return false;
    }
    if (!end || *end != 0) return false;
    *val = neg ? ((uint64_t)0 - v) : v;
    return true;
}

static bool tnt_ieq(const char *a, const char *b) {
    if (!a || !b) return false;
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) return false;
        a++;
        b++;
    }
    return *a == 0 && *b == 0;
}

static uint64_t tnt_mask(uint64_t v, int bits) {
    if (bits == 8)  return v & 0xFFULL;
    if (bits == 16) return v & 0xFFFFULL;
    if (bits == 32) return v & 0xFFFFFFFFULL;
    return v;
}

static uint64_t tnt_sext(uint64_t v, int bits) {
    if (bits == 8)  return (uint64_t)(int64_t)(int8_t)(v & 0xFFULL);
    if (bits == 16) return (uint64_t)(int64_t)(int16_t)(v & 0xFFFFULL);
    if (bits == 32) return (uint64_t)(int64_t)(int32_t)(v & 0xFFFFFFFFULL);
    return v;
}

static int tnt_x86_reg(const char *s, int *bits, int *hi8) {
    static const char *const r32[16] = {"eax","ecx","edx","ebx","esp","ebp","esi","edi","r8d","r9d","r10d","r11d","r12d","r13d","r14d","r15d"};
    static const char *const r16[16] = {"ax","cx","dx","bx","sp","bp","si","di","r8w","r9w","r10w","r11w","r12w","r13w","r14w","r15w"};
    static const char *const r8[16]  = {"al","cl","dl","bl","spl","bpl","sil","dil","r8b","r9b","r10b","r11b","r12b","r13b","r14b","r15b"};
    static const char *const rh[4]   = {"ah","ch","dh","bh"};
    if (hi8) *hi8 = 0;
    if (!s || !s[0]) return -1;
    for (int i = 0; i < 16; i++) {
        if (strcmp(s, tnt_x86_r64[i]) == 0) { if (bits) *bits = 64; return i; }
        if (strcmp(s, r32[i]) == 0)         { if (bits) *bits = 32; return i; }
        if (strcmp(s, r16[i]) == 0)         { if (bits) *bits = 16; return i; }
        if (strcmp(s, r8[i]) == 0)          { if (bits) *bits = 8;  return i; }
    }
    for (int i = 0; i < 4; i++) {
        if (strcmp(s, rh[i]) == 0) {
            if (bits) *bits = 8;
            if (hi8) *hi8 = 1;
            return i;
        }
    }
    return -1;
}

static int tnt_a64_reg(const char *s, int *bits) {
    if (!s || !s[0]) return -1;
    if (strcmp(s, "xzr") == 0) { if (bits) *bits = 64; return -2; }
    if (strcmp(s, "wzr") == 0) { if (bits) *bits = 32; return -2; }
    if (strcmp(s, "sp") == 0)  { if (bits) *bits = 64; return 31; }
    if (strcmp(s, "wsp") == 0) { if (bits) *bits = 32; return 31; }
    if (strcmp(s, "fp") == 0)  { if (bits) *bits = 64; return 29; }
    if (strcmp(s, "lr") == 0)  { if (bits) *bits = 64; return 30; }
    if ((s[0] == 'x' || s[0] == 'w') && isdigit((unsigned char)s[1])) {
        char *end = NULL;
        unsigned long idx = strtoul(s + 1, &end, 10);
        if (end && *end == 0 && idx <= 30) {
            if (bits) *bits = (s[0] == 'x') ? 64 : 32;
            return (int)idx;
        }
    }
    return -1;
}

static bool tnt_is_sysv(const ana_ctx *a) {
    return a->bin.fmt == BIN_ELF32 || a->bin.fmt == BIN_ELF64 || a->bin.fmt == BIN_MACHO64;
}

static void tnt_arg_regs(const ana_ctx *a, int regs[4]) {
    if (a->bin.arch == BIN_ARCH_ARM64) {
        regs[0] = 0; regs[1] = 1; regs[2] = 2; regs[3] = 3;
    } else if (tnt_is_sysv(a)) {
        regs[0] = 7; regs[1] = 6; regs[2] = 2; regs[3] = 1;
    } else {
        regs[0] = 1; regs[1] = 2; regs[2] = 8; regs[3] = 9;
    }
}

static int tnt_eval_x86_cc(const char *cc, int zf, int sf, int cf, int of) {
    if (strcmp(cc, "e") == 0 || strcmp(cc, "z") == 0) return zf;
    if (strcmp(cc, "ne") == 0 || strcmp(cc, "nz") == 0) return !zf;
    if (strcmp(cc, "b") == 0 || strcmp(cc, "c") == 0 || strcmp(cc, "nae") == 0) return cf;
    if (strcmp(cc, "ae") == 0 || strcmp(cc, "nc") == 0 || strcmp(cc, "nb") == 0) return !cf;
    if (strcmp(cc, "be") == 0 || strcmp(cc, "na") == 0) return cf || zf;
    if (strcmp(cc, "a") == 0 || strcmp(cc, "nbe") == 0) return !cf && !zf;
    if (strcmp(cc, "s") == 0) return sf;
    if (strcmp(cc, "ns") == 0) return !sf;
    if (strcmp(cc, "o") == 0) return of;
    if (strcmp(cc, "no") == 0) return !of;
    if (strcmp(cc, "l") == 0 || strcmp(cc, "nge") == 0) return sf != of;
    if (strcmp(cc, "ge") == 0 || strcmp(cc, "nl") == 0) return sf == of;
    if (strcmp(cc, "le") == 0 || strcmp(cc, "ng") == 0) return zf || (sf != of);
    if (strcmp(cc, "g") == 0 || strcmp(cc, "nle") == 0) return !zf && (sf == of);
    if (strcmp(cc, "p") == 0 || strcmp(cc, "pe") == 0) return zf;
    if (strcmp(cc, "np") == 0 || strcmp(cc, "po") == 0) return !zf;
    return -1;
}

static int tnt_eval_a64_cc(const char *cc, int zf, int sf, int cf, int of) {
    // cf stores borrow (x86 convention), so ARM64 C flag is !cf
    if (strcmp(cc, "eq") == 0) return zf;
    if (strcmp(cc, "ne") == 0) return !zf;
    if (strcmp(cc, "cs") == 0 || strcmp(cc, "hs") == 0) return !cf;
    if (strcmp(cc, "cc") == 0 || strcmp(cc, "lo") == 0) return cf;
    if (strcmp(cc, "mi") == 0) return sf;
    if (strcmp(cc, "pl") == 0) return !sf;
    if (strcmp(cc, "vs") == 0) return of;
    if (strcmp(cc, "vc") == 0) return !of;
    if (strcmp(cc, "hi") == 0) return !cf && !zf;
    if (strcmp(cc, "ls") == 0) return cf || zf;
    if (strcmp(cc, "ge") == 0) return sf == of;
    if (strcmp(cc, "lt") == 0) return sf != of;
    if (strcmp(cc, "gt") == 0) return !zf && (sf == of);
    if (strcmp(cc, "le") == 0) return zf || (sf != of);
    if (strcmp(cc, "al") == 0) return 1;
    if (strcmp(cc, "nv") == 0) return 0;
    return -1;
}

static void tnt_add_event(tnt_res *out, uint64_t va, const char *kind, uint16_t mask, const char *detail) {
    if (!out || out->nevent >= 128) return;
    tnt_event *ev = &out->events[out->nevent++];
    ev->va = va;
    ev->reg_mask = mask;
    snprintf(ev->kind, sizeof(ev->kind), "%s", kind);
    snprintf(ev->detail, sizeof(ev->detail), "%s", detail);
}

static uint64_t tnt_vm_get_reg(const tnt_vm *vm, int r, int bits, int hi8) {
    if (r == -2 || r < 0 || r >= 32) return 0;
    uint64_t raw = (r < 16) ? vm->regs[r] : vm->a64_hi[r - 16];
    if (bits == 8 && hi8) return (raw >> 8) & 0xFFULL;
    return tnt_mask(raw, bits);
}

static void tnt_vm_set_reg(tnt_vm *vm, int r, int bits, int hi8, uint64_t val) {
    if (r == -2 || r < 0 || r >= 32) return;
    uint64_t *slot = (r < 16) ? &vm->regs[r] : &vm->a64_hi[r - 16];
    if (bits == 64) {
        *slot = val;
    } else if (bits == 32) {
        *slot = val & 0xFFFFFFFFULL;
    } else if (bits == 16) {
        *slot = (*slot & ~0xFFFFULL) | (val & 0xFFFFULL);
    } else if (bits == 8) {
        if (hi8) *slot = (*slot & ~0xFF00ULL) | ((val & 0xFFULL) << 8);
        else     *slot = (*slot & ~0xFFULL) | (val & 0xFFULL);
    }
}

static int tnt_vm_get_taint(const tnt_vm *vm, int r) {
    if (r == -2 || r < 0 || r >= 32) return 0;
    if (r < 16) return (vm->reg_taint & (uint16_t)(1u << r)) != 0;
    return (vm->a64_hi_taint & (uint16_t)(1u << (r - 16))) != 0;
}

static void tnt_vm_set_taint(tnt_vm *vm, int r, int t) {
    if (r == -2 || r < 0 || r >= 32) return;
    if (r < 16) {
        if (t) vm->reg_taint |= (uint16_t)(1u << r);
        else   vm->reg_taint &= (uint16_t)~(1u << r);
    } else {
        uint16_t bit = (uint16_t)(1u << (r - 16));
        if (t) vm->a64_hi_taint |= bit;
        else   vm->a64_hi_taint &= (uint16_t)~bit;
    }
}

static uint64_t tnt_heap_alloc(tnt_vm *vm, uint32_t size) {
    if (size == 0) size = 16;
    if (size > TNT_HEAP_SIZE) return 0;
    uint32_t aligned = (size + 15u) & ~15u;
    if (aligned < size || vm->heap_top > TNT_HEAP_SIZE - aligned) return 0;
    uint64_t addr = TNT_HEAP_BASE + (uint64_t)vm->heap_top;
    vm->heap_top += aligned;
    return addr;
}

static bool tnt_mem_read_u8(const ana_ctx *a, const tnt_vm *vm, uint64_t addr, uint8_t *val, int *taint) {
    if (addr >= TNT_STACK_BASE && (addr - TNT_STACK_BASE) < TNT_STACK_SIZE) {
        size_t off = (size_t)(addr - TNT_STACK_BASE);
        *val = vm->stack[off];
        *taint = vm->stack_taint[off] != 0;
        return true;
    }
    if (addr >= TNT_HEAP_BASE && (addr - TNT_HEAP_BASE) < TNT_HEAP_SIZE) {
        size_t off = (size_t)(addr - TNT_HEAP_BASE);
        *val = vm->heap[off];
        *taint = vm->heap_taint[off] != 0;
        return true;
    }
    uint8_t b = 0;
    if (bin_read(&a->bin, addr, &b, 1) == 1) {
        *val = b;
        *taint = 0;
        return true;
    }
    *val = 0;
    *taint = 0;
    return false;
}

static bool tnt_mem_write_u8(tnt_vm *vm, uint64_t addr, uint8_t val, int taint) {
    if (addr >= TNT_STACK_BASE && (addr - TNT_STACK_BASE) < TNT_STACK_SIZE) {
        size_t off = (size_t)(addr - TNT_STACK_BASE);
        vm->stack[off] = val;
        vm->stack_taint[off] = taint ? 1u : 0u;
        return true;
    }
    if (addr >= TNT_HEAP_BASE && (addr - TNT_HEAP_BASE) < TNT_HEAP_SIZE) {
        size_t off = (size_t)(addr - TNT_HEAP_BASE);
        vm->heap[off] = val;
        vm->heap_taint[off] = taint ? 1u : 0u;
        return true;
    }
    return false;
}

static bool tnt_mem_read(const ana_ctx *a, const tnt_vm *vm, uint64_t addr, int bits, uint64_t *val, int *taint) {
    int nb = bits / 8;
    if (nb < 1 || nb > 8) nb = 8;
    uint64_t acc = 0;
    int any_t = 0;
    int ok_any = 0;
    for (int i = 0; i < nb; i++) {
        uint8_t b = 0;
        int bt = 0;
        if (tnt_mem_read_u8(a, vm, addr + (uint64_t)i, &b, &bt)) ok_any = 1;
        acc |= ((uint64_t)b) << (i * 8);
        if (bt) any_t = 1;
    }
    *val = acc;
    *taint = any_t;
    return ok_any != 0;
}

static bool tnt_mem_write(tnt_vm *vm, uint64_t addr, int bits, uint64_t val, int taint) {
    int nb = bits / 8;
    if (nb < 1 || nb > 8) nb = 8;
    int ok = 0;
    for (int i = 0; i < nb; i++) {
        uint8_t b = (uint8_t)((val >> (i * 8)) & 0xFFULL);
        if (tnt_mem_write_u8(vm, addr + (uint64_t)i, b, taint)) ok = 1;
    }
    return ok != 0;
}

static bool tnt_buf_is_tainted(const tnt_vm *vm, uint64_t addr) {
    if (addr >= TNT_STACK_BASE && (addr - TNT_STACK_BASE) < TNT_STACK_SIZE) {
        size_t off = (size_t)(addr - TNT_STACK_BASE);
        for (size_t i = 0; i < 64 && off + i < TNT_STACK_SIZE; i++) {
            if (vm->stack_taint[off + i]) return true;
            if (i > 0 && vm->stack[off + i] == 0) break;
        }
    } else if (addr >= TNT_HEAP_BASE && (addr - TNT_HEAP_BASE) < TNT_HEAP_SIZE) {
        size_t off = (size_t)(addr - TNT_HEAP_BASE);
        for (size_t i = 0; i < 64 && off + i < TNT_HEAP_SIZE; i++) {
            if (vm->heap_taint[off + i]) return true;
            if (i > 0 && vm->heap[off + i] == 0) break;
        }
    }
    return false;
}

static void tnt_set_flags_sub(tnt_vm *vm, uint64_t a, uint64_t b, int bits, int taint) {
    uint64_t m = tnt_mask(~0ULL, bits);
    uint64_t sbit = 1ULL << (bits - 1);
    uint64_t la = a & m;
    uint64_t lb = b & m;
    uint64_t r = (la - lb) & m;
    vm->zf = (r == 0);
    vm->sf = ((r & sbit) != 0);
    vm->cf = (la < lb);
    vm->of = ((((la ^ lb) & (la ^ r)) & sbit) != 0);
    vm->flag_taint = taint ? 1 : 0;
}

static void tnt_set_flags_add(tnt_vm *vm, uint64_t a, uint64_t b, int bits, int taint) {
    uint64_t m = tnt_mask(~0ULL, bits);
    uint64_t sbit = 1ULL << (bits - 1);
    uint64_t la = a & m;
    uint64_t lb = b & m;
    uint64_t r = (la + lb) & m;
    vm->zf = (r == 0);
    vm->sf = ((r & sbit) != 0);
    vm->cf = (r < la);
    vm->of = ((((~(la ^ lb)) & (la ^ r)) & sbit) != 0);
    vm->flag_taint = taint ? 1 : 0;
}

static void tnt_set_flags_logic(tnt_vm *vm, uint64_t res, int bits, int taint) {
    uint64_t m = tnt_mask(~0ULL, bits);
    uint64_t sbit = 1ULL << (bits - 1);
    uint64_t r = res & m;
    vm->zf = (r == 0);
    vm->sf = ((r & sbit) != 0);
    vm->cf = 0;
    vm->of = 0;
    vm->flag_taint = taint ? 1 : 0;
}

static void tnt_clean_sym(const char *sym, char *out, size_t cap) {
    out[0] = 0;
    if (!sym || !sym[0]) return;
    const char *p = strrchr(sym, '!');
    p = p ? p + 1 : sym;
    if (strncmp(p, "__imp_", 6) == 0) p += 6;
    else if (strncmp(p, "_imp_", 5) == 0) p += 5;
    else if (strncmp(p, "imp.", 4) == 0) p += 4;
    else if (strncmp(p, "j_", 2) == 0) p += 2;
    if (p[0] == '_' && p[1] && p[1] != '_') p++;

    size_t n = 0;
    while (p[n] && p[n] != '@' && n + 1 < cap) {
        out[n] = p[n];
        n++;
    }
    out[n] = 0;
}

static bool tnt_is_sink_api(const char *name) {
    static const char *const sinks[] = {
        "memcpy","memmove","strcpy","strncpy","strcat","sprintf","snprintf",
        "system","WinExec","CreateProcessA","CreateProcessW","VirtualProtect",
        "WriteProcessMemory","send","URLDownloadToFileA","URLDownloadToFileW"
    };
    for (size_t i = 0; i < sizeof(sinks) / sizeof(sinks[0]); i++) {
        if (tnt_ieq(name, sinks[i])) return true;
    }
    return false;
}

static void tnt_get_call_arg(const ana_ctx *a, const tnt_vm *vm, int idx, uint64_t *val, int *taint) {
    *val = 0;
    *taint = 0;
    if (idx < 0 || idx >= 4) return;
    if (vm->is_32 && !vm->is_a64) {
        // cdecl/stdcall args sit at [esp + idx*4] before call return push
        uint64_t sv = 0;
        int st = 0;
        if (tnt_mem_read(a, vm, vm->regs[4] + (uint64_t)idx * 4ULL, 32, &sv, &st) && (sv != 0 || st != 0)) {
            *val = sv;
            *taint = st;
            return;
        }
    }
    int ar[4];
    tnt_arg_regs(a, ar);
    *val = vm->regs[ar[idx]];
    *taint = tnt_vm_get_taint(vm, ar[idx]);
}

static bool tnt_check_sink_args(const ana_ctx *a, const tnt_vm *vm, tnt_res *out, uint64_t call_va, const char *api) {
    int ar[4];
    tnt_arg_regs(a, ar);
    for (int i = 0; i < 4; i++) {
        int rt = tnt_vm_get_taint(vm, ar[i]);
        uint64_t rv = vm->regs[ar[i]];
        int bt = tnt_buf_is_tainted(vm, rv);
        if (vm->is_32 && !vm->is_a64) {
            uint64_t sv = 0;
            int st = 0;
            if (tnt_mem_read(a, vm, vm->regs[4] + (uint64_t)i * 4ULL, 32, &sv, &st)) {
                if (st) rt = 1;
                if (tnt_buf_is_tainted(vm, sv)) bt = 1;
            }
        }
        if (rt || bt) {
            char msg[96];
            snprintf(msg, sizeof(msg), "%s(arg%d %s)", api, i + 1, bt ? "tainted buf" : "tainted reg");
            tnt_add_event(out, call_va, "TAINT_SINK", vm->reg_taint, msg);
            return true;
        }
    }
    return false;
}

static bool tnt_exec_shim(const ana_ctx *a, tnt_vm *vm, tnt_res *out, uint64_t call_va, const char *raw_sym) {
    char name[64];
    tnt_clean_sym(raw_sym, name, sizeof(name));
    if (!name[0]) return false;

    uint64_t a0 = 0, a1 = 0, a2 = 0;
    int t0 = 0, t1 = 0, t2 = 0;
    tnt_get_call_arg(a, vm, 0, &a0, &t0);
    tnt_get_call_arg(a, vm, 1, &a1, &t1);
    tnt_get_call_arg(a, vm, 2, &a2, &t2);
    char msg[96];

    if (tnt_ieq(name, "malloc") || tnt_ieq(name, "calloc") ||
        tnt_ieq(name, "VirtualAlloc") || tnt_ieq(name, "HeapAlloc")) {
        uint64_t sz = a0;
        if (tnt_ieq(name, "calloc")) sz = a0 * a1;
        else if (tnt_ieq(name, "VirtualAlloc")) sz = a1;
        else if (tnt_ieq(name, "HeapAlloc")) sz = a2;
        if (sz == 0) sz = 64;
        if (sz > TNT_MAX_BUF) sz = TNT_MAX_BUF;
        uint64_t ptr = tnt_heap_alloc(vm, (uint32_t)sz);
        vm->regs[0] = ptr;
        tnt_vm_set_taint(vm, 0, 0);
        out->shim_calls++;
        snprintf(msg, sizeof(msg), "%s(0x%llx) -> 0x%llx", name, (unsigned long long)sz, (unsigned long long)ptr);
        tnt_add_event(out, call_va, "SHIM_CALL", vm->reg_taint, msg);
        return true;
    }

    if (tnt_ieq(name, "memcpy") || tnt_ieq(name, "memmove")) {
        uint32_t len = (a2 > TNT_MAX_BUF) ? TNT_MAX_BUF : (uint32_t)a2;
        uint8_t *tmp = len ? (uint8_t *)malloc(len) : NULL;
        uint8_t *tt  = len ? (uint8_t *)malloc(len) : NULL;
        int any_t = t1 || t2 || tnt_buf_is_tainted(vm, a1);
        if (tmp && tt) {
            int src_vmem = (a1 >= TNT_STACK_BASE && (a1 - TNT_STACK_BASE) < TNT_STACK_SIZE) ||
                           (a1 >= TNT_HEAP_BASE && (a1 - TNT_HEAP_BASE) < TNT_HEAP_SIZE);
            for (uint32_t i = 0; i < len; i++) {
                int bt = 0;
                bool ok = tnt_mem_read_u8(a, vm, a1 + (uint64_t)i, &tmp[i], &bt);
                if (!ok && !src_vmem && t1) bt = 1;
                tt[i] = bt ? 1u : 0u;
                if (bt) any_t = 1;
            }
            for (uint32_t i = 0; i < len; i++) {
                tnt_mem_write_u8(vm, a0 + (uint64_t)i, tmp[i], tt[i]);
            }
        }
        free(tmp);
        free(tt);
        vm->regs[0] = a0;
        tnt_vm_set_taint(vm, 0, t0);
        out->shim_calls++;
        snprintf(msg, sizeof(msg), "%s(0x%llx, 0x%llx, %u)", name, (unsigned long long)a0, (unsigned long long)a1, len);
        tnt_add_event(out, call_va, "SHIM_CALL", vm->reg_taint, msg);
        if (any_t) {
            snprintf(msg, sizeof(msg), "%s(src/len tainted, %u bytes)", name, len);
            tnt_add_event(out, call_va, "TAINT_SINK", vm->reg_taint, msg);
        }
        return true;
    }

    if (tnt_ieq(name, "strcpy") || tnt_ieq(name, "strncpy")) {
        uint32_t lim = tnt_ieq(name, "strncpy") ? ((a2 > TNT_MAX_BUF) ? TNT_MAX_BUF : (uint32_t)a2) : TNT_MAX_BUF;
        int any_t = t1 || (tnt_ieq(name, "strncpy") && t2) || tnt_buf_is_tainted(vm, a1);
        uint32_t copied = 0;
        for (uint32_t i = 0; i < lim; i++) {
            uint8_t b = 0;
            int bt = 0;
            if (!tnt_mem_read_u8(a, vm, a1 + (uint64_t)i, &b, &bt)) break;
            if (bt) any_t = 1;
            tnt_mem_write_u8(vm, a0 + (uint64_t)i, b, bt);
            copied++;
            if (b == 0) break;
        }
        vm->regs[0] = a0;
        tnt_vm_set_taint(vm, 0, t0);
        out->shim_calls++;
        snprintf(msg, sizeof(msg), "%s(0x%llx, 0x%llx, %uB)", name, (unsigned long long)a0, (unsigned long long)a1, copied);
        tnt_add_event(out, call_va, "SHIM_CALL", vm->reg_taint, msg);
        if (any_t) {
            snprintf(msg, sizeof(msg), "%s(src tainted, %u bytes)", name, copied);
            tnt_add_event(out, call_va, "TAINT_SINK", vm->reg_taint, msg);
        }
        return true;
    }

    if (tnt_ieq(name, "strcat")) {
        uint32_t dst_len = 0;
        while (dst_len < TNT_MAX_BUF) {
            uint8_t b = 0;
            int bt = 0;
            if (!tnt_mem_read_u8(a, vm, a0 + (uint64_t)dst_len, &b, &bt) || b == 0) break;
            dst_len++;
        }
        int any_t = t0 || t1 || tnt_buf_is_tainted(vm, a0) || tnt_buf_is_tainted(vm, a1);
        for (uint32_t i = 0; i + dst_len < TNT_MAX_BUF; i++) {
            uint8_t b = 0;
            int bt = 0;
            if (!tnt_mem_read_u8(a, vm, a1 + (uint64_t)i, &b, &bt)) break;
            if (bt) any_t = 1;
            tnt_mem_write_u8(vm, a0 + (uint64_t)dst_len + (uint64_t)i, b, bt);
            if (b == 0) break;
        }
        vm->regs[0] = a0;
        tnt_vm_set_taint(vm, 0, t0);
        out->shim_calls++;
        snprintf(msg, sizeof(msg), "%s(0x%llx, 0x%llx)", name, (unsigned long long)a0, (unsigned long long)a1);
        tnt_add_event(out, call_va, "SHIM_CALL", vm->reg_taint, msg);
        if (any_t) tnt_add_event(out, call_va, "TAINT_SINK", vm->reg_taint, "strcat(tainted input)");
        return true;
    }

    if (tnt_ieq(name, "memset")) {
        uint32_t len = (a2 > TNT_MAX_BUF) ? TNT_MAX_BUF : (uint32_t)a2;
        for (uint32_t i = 0; i < len; i++) {
            tnt_mem_write_u8(vm, a0 + (uint64_t)i, (uint8_t)(a1 & 0xFFULL), t1);
        }
        vm->regs[0] = a0;
        tnt_vm_set_taint(vm, 0, t0);
        out->shim_calls++;
        snprintf(msg, sizeof(msg), "memset(0x%llx, 0x%02x, %u)", (unsigned long long)a0, (unsigned)(a1 & 0xFFULL), len);
        tnt_add_event(out, call_va, "SHIM_CALL", vm->reg_taint, msg);
        return true;
    }

    if (tnt_ieq(name, "strlen")) {
        uint32_t len = 0;
        int any_t = 0;
        int mapped = 0;
        while (len < TNT_MAX_BUF) {
            uint8_t b = 0;
            int bt = 0;
            if (!tnt_mem_read_u8(a, vm, a0 + (uint64_t)len, &b, &bt)) break;
            mapped = 1;
            if (bt) any_t = 1;
            if (b == 0) break;
            len++;
        }
        if (!mapped && t0) any_t = 1;
        vm->regs[0] = len;
        tnt_vm_set_taint(vm, 0, any_t);
        out->shim_calls++;
        snprintf(msg, sizeof(msg), "strlen(0x%llx) -> %u", (unsigned long long)a0, len);
        tnt_add_event(out, call_va, "SHIM_CALL", vm->reg_taint, msg);
        return true;
    }

    if (tnt_ieq(name, "GetTickCount") || tnt_ieq(name, "GetTickCount64")) {
        vm->regs[0] = 0x1000ULL;
        tnt_vm_set_taint(vm, 0, 0);
        out->shim_calls++;
        snprintf(msg, sizeof(msg), "%s() -> 0x1000", name);
        tnt_add_event(out, call_va, "SHIM_CALL", vm->reg_taint, msg);
        return true;
    }

    if (tnt_ieq(name, "IsDebuggerPresent")) {
        vm->regs[0] = 0;
        tnt_vm_set_taint(vm, 0, 0);
        out->shim_calls++;
        tnt_add_event(out, call_va, "SHIM_CALL", vm->reg_taint, "IsDebuggerPresent() -> 0");
        return true;
    }

    if (tnt_is_sink_api(name)) {
        tnt_check_sink_args(a, vm, out, call_va, name);
        vm->regs[0] = (tnt_ieq(name, "VirtualProtect") || tnt_ieq(name, "WriteProcessMemory")) ? 1ULL : 0ULL;
        tnt_vm_set_taint(vm, 0, 0);
        out->shim_calls++;
        snprintf(msg, sizeof(msg), "%s()", name);
        tnt_add_event(out, call_va, "SHIM_CALL", vm->reg_taint, msg);
        return true;
    }

    return false;
}

static bool tnt_x86_eval_ea(const char *raw, const tnt_vm *vm, uint64_t *ea, int *bits, int *ea_taint) {
    const char *p = raw;
    *bits = 0;
    *ea_taint = 0;
    if (strncmp(p, "byte ptr ", 9) == 0)       { *bits = 8;  p += 9; }
    else if (strncmp(p, "word ptr ", 9) == 0)  { *bits = 16; p += 9; }
    else if (strncmp(p, "dword ptr ", 10) == 0){ *bits = 32; p += 10; }
    else if (strncmp(p, "qword ptr ", 10) == 0){ *bits = 64; p += 10; }
    if (p[0] && p[1] && p[2] == ':') p += 3;
    if (*p != '[') return false;

    char in[64];
    snprintf(in, sizeof(in), "%s", p + 1);
    char *rb = strchr(in, ']');
    if (rb) *rb = 0;

    uint64_t acc = 0;
    int sign = 1;
    char *c = in;
    while (*c) {
        if (*c == ' ' || *c == '\t') { c++; continue; }
        if (*c == '+') { sign = 1; c++; continue; }
        if (*c == '-') { sign = -1; c++; continue; }
        char tok[32];
        int k = 0;
        while (*c && *c != '+' && *c != '-' && k < 31) tok[k++] = *c++;
        tok[k] = 0;
        tnt_trim(tok);
        if (!tok[0]) continue;

        char *st = strchr(tok, '*');
        if (st) {
            *st = 0;
            int rb2 = 64, hi = 0;
            int r = tnt_x86_reg(tok, &rb2, &hi);
            uint64_t sc = (uint64_t)strtoull(st + 1, NULL, 10);
            if (r >= 0) {
                uint64_t term = tnt_vm_get_reg(vm, r, rb2, hi) * sc;
                acc = (sign > 0) ? (acc + term) : (acc - term);
                if (tnt_vm_get_taint(vm, r)) *ea_taint = 1;
            }
        } else {
            uint64_t imm = 0;
            int rb2 = 64, hi = 0;
            int r = tnt_x86_reg(tok, &rb2, &hi);
            if (r >= 0) {
                uint64_t term = tnt_vm_get_reg(vm, r, rb2, hi);
                acc = (sign > 0) ? (acc + term) : (acc - term);
                if (tnt_vm_get_taint(vm, r)) *ea_taint = 1;
            } else if (tnt_parse_imm(tok, &imm)) {
                acc = (sign > 0) ? (acc + imm) : (acc - imm);
            }
        }
    }
    *ea = vm->is_32 ? (acc & 0xFFFFFFFFULL) : acc;
    return true;
}

static bool tnt_x86_read_op(const ana_ctx *a, const tnt_vm *vm, const char *op, int def_bits, uint64_t *val, int *taint, int *out_bits) {
    int b = def_bits, hi = 0;
    int r = tnt_x86_reg(op, &b, &hi);
    if (r >= 0) {
        *val = tnt_vm_get_reg(vm, r, b, hi);
        *taint = tnt_vm_get_taint(vm, r);
        if (out_bits) *out_bits = b;
        return true;
    }
    uint64_t imm = 0;
    if (tnt_parse_imm(op, &imm)) {
        *val = imm;
        *taint = 0;
        if (out_bits) *out_bits = def_bits;
        return true;
    }
    uint64_t ea = 0;
    int mb = 0, ea_t = 0;
    if (tnt_x86_eval_ea(op, vm, &ea, &mb, &ea_t)) {
        int wb = mb ? mb : def_bits;
        tnt_mem_read(a, vm, ea, wb, val, taint);
        if (out_bits) *out_bits = wb;
        return true;
    }
    *val = 0;
    *taint = 0;
    if (out_bits) *out_bits = def_bits;
    return false;
}

static void tnt_x86_write_op(tnt_vm *vm, tnt_res *out, uint64_t ip, const char *op, int def_bits, uint64_t val, int taint) {
    int b = def_bits, hi = 0;
    int r = tnt_x86_reg(op, &b, &hi);
    if (r >= 0) {
        tnt_vm_set_reg(vm, r, b, hi, val);
        tnt_vm_set_taint(vm, r, taint);
        return;
    }
    uint64_t ea = 0;
    int mb = 0, ea_t = 0;
    if (tnt_x86_eval_ea(op, vm, &ea, &mb, &ea_t)) {
        int wb = mb ? mb : def_bits;
        tnt_mem_write(vm, ea, wb, val, taint);
        if (taint) {
            char msg[96];
            snprintf(msg, sizeof(msg), "[0x%llx] <- 0x%llx (%dB)", (unsigned long long)ea, (unsigned long long)tnt_mask(val, wb), wb / 8);
            tnt_add_event(out, ip, "TAINT_STORE", vm->reg_taint, msg);
        }
    }
}

static uint64_t tnt_sar(uint64_t v, uint64_t cnt, int bits) {
    uint64_t m = tnt_mask(~0ULL, bits);
    uint64_t sbit = 1ULL << (bits - 1);
    uint64_t uv = v & m;
    if (cnt == 0) return uv;
    if (cnt >= (uint64_t)bits) return (uv & sbit) ? m : 0;
    uint64_t res = uv >> cnt;
    if (uv & sbit) res |= (m << ((uint64_t)bits - cnt)) & m;
    return res;
}

static uint64_t tnt_step_x86(const ana_ctx *a, tnt_vm *vm, tnt_res *out, const x86_ins *ins) {
    uint64_t next_ip = ins->ip + (uint64_t)ins->len;
    const char *m = ins->mnem;
    if (strncmp(m, "lock ", 5) == 0) m += 5;

    char ops[4][76];
    int nops = tnt_split_ops(ins->ops, ops);
    int abits = vm->is_32 ? 32 : 64;
    int pbytes = vm->is_32 ? 4 : 8;
    int b0 = abits, hi0 = 0, b1 = abits, hi1 = 0;
    int r0 = (nops >= 1) ? tnt_x86_reg(ops[0], &b0, &hi0) : -1;
    int r1 = (nops >= 2) ? tnt_x86_reg(ops[1], &b1, &hi1) : -1;
    uint64_t imm1 = 0;
    bool has_imm1 = (nops >= 2) && tnt_parse_imm(ops[1], &imm1);

    if (strcmp(m, "nop") == 0 || strcmp(m, "pause") == 0 || strcmp(m, "endbr64") == 0 || strcmp(m, "endbr32") == 0) {
        return next_ip;
    }

    if (strcmp(m, "push") == 0 && nops >= 1) {
        uint64_t v = 0;
        int vt = 0, ob = abits;
        tnt_x86_read_op(a, vm, ops[0], abits, &v, &vt, &ob);
        vm->regs[4] -= (uint64_t)pbytes;
        tnt_mem_write(vm, vm->regs[4], abits, v, vt);
        if (vt) {
            char msg[96];
            snprintf(msg, sizeof(msg), "push [0x%llx] <- %s", (unsigned long long)vm->regs[4], ops[0]);
            tnt_add_event(out, ins->ip, "TAINT_STORE", vm->reg_taint, msg);
        }
        return next_ip;
    }

    if (strcmp(m, "pop") == 0 && nops >= 1) {
        uint64_t v = 0;
        int vt = 0;
        tnt_mem_read(a, vm, vm->regs[4], abits, &v, &vt);
        vm->regs[4] += (uint64_t)pbytes;
        tnt_x86_write_op(vm, out, ins->ip, ops[0], abits, v, vt);
        return next_ip;
    }

    if (strcmp(m, "leave") == 0) {
        vm->regs[4] = vm->regs[5];
        tnt_vm_set_taint(vm, 4, tnt_vm_get_taint(vm, 5));
        uint64_t v = 0;
        int vt = 0;
        tnt_mem_read(a, vm, vm->regs[4], abits, &v, &vt);
        vm->regs[4] += (uint64_t)pbytes;
        vm->regs[5] = v;
        tnt_vm_set_taint(vm, 5, vt);
        return next_ip;
    }

    if (strcmp(m, "mov") == 0 || strcmp(m, "movabs") == 0) {
        if (nops >= 2) {
            int wb = (r0 >= 0) ? b0 : ((r1 >= 0) ? b1 : abits);
            uint64_t rv = 0;
            int rt = 0, rb = wb;
            tnt_x86_read_op(a, vm, ops[1], wb, &rv, &rt, &rb);
            if (has_imm1) rt = 0;
            tnt_x86_write_op(vm, out, ins->ip, ops[0], wb, rv, rt);
        }
        return next_ip;
    }

    if (strcmp(m, "movzx") == 0 && nops >= 2 && r0 >= 0) {
        uint64_t rv = 0;
        int rt = 0, sb = 8;
        tnt_x86_read_op(a, vm, ops[1], 8, &rv, &rt, &sb);
        tnt_vm_set_reg(vm, r0, b0, hi0, tnt_mask(rv, sb));
        tnt_vm_set_taint(vm, r0, rt);
        return next_ip;
    }

    if ((strcmp(m, "movsx") == 0 || strcmp(m, "movsxd") == 0) && nops >= 2 && r0 >= 0) {
        int def_s = (strcmp(m, "movsxd") == 0) ? 32 : 8;
        uint64_t rv = 0;
        int rt = 0, sb = def_s;
        tnt_x86_read_op(a, vm, ops[1], def_s, &rv, &rt, &sb);
        tnt_vm_set_reg(vm, r0, b0, hi0, tnt_sext(rv, sb));
        tnt_vm_set_taint(vm, r0, rt);
        return next_ip;
    }

    if (strcmp(m, "lea") == 0 && nops >= 2 && r0 >= 0) {
        uint64_t ea = 0;
        int mb = 0, ea_t = 0;
        if (tnt_x86_eval_ea(ops[1], vm, &ea, &mb, &ea_t)) {
            tnt_vm_set_reg(vm, r0, b0, hi0, ea);
            tnt_vm_set_taint(vm, r0, ea_t);
        }
        return next_ip;
    }

    if (strcmp(m, "xchg") == 0 && nops >= 2) {
        int wb = (r0 >= 0) ? b0 : ((r1 >= 0) ? b1 : abits);
        uint64_t v0 = 0, v1 = 0;
        int t0 = 0, t1 = 0, ob0 = wb, ob1 = wb;
        tnt_x86_read_op(a, vm, ops[0], wb, &v0, &t0, &ob0);
        tnt_x86_read_op(a, vm, ops[1], wb, &v1, &t1, &ob1);
        tnt_x86_write_op(vm, out, ins->ip, ops[0], ob0, v1, t1);
        tnt_x86_write_op(vm, out, ins->ip, ops[1], ob1, v0, t0);
        return next_ip;
    }

    if (strcmp(m, "cdqe") == 0) { vm->regs[0] = tnt_sext(vm->regs[0], 32); return next_ip; }
    if (strcmp(m, "cwde") == 0) { vm->regs[0] = tnt_sext(vm->regs[0], 16) & 0xFFFFFFFFULL; return next_ip; }
    if (strcmp(m, "cbw") == 0)  { tnt_vm_set_reg(vm, 0, 16, 0, tnt_sext(vm->regs[0], 8)); return next_ip; }
    if (strcmp(m, "cdq") == 0)  { vm->regs[2] = (vm->regs[0] & 0x80000000ULL) ? 0xFFFFFFFFULL : 0ULL; tnt_vm_set_taint(vm, 2, tnt_vm_get_taint(vm, 0)); return next_ip; }
    if (strcmp(m, "cqo") == 0)  { vm->regs[2] = (vm->regs[0] & 0x8000000000000000ULL) ? ~0ULL : 0ULL; tnt_vm_set_taint(vm, 2, tnt_vm_get_taint(vm, 0)); return next_ip; }

    if (strcmp(m, "xor") == 0 || strcmp(m, "sub") == 0) {
        if (nops >= 2) {
            if (r0 >= 0 && r0 == r1 && b0 == b1 && hi0 == hi1) {
                tnt_vm_set_reg(vm, r0, b0, hi0, 0);
                tnt_vm_set_taint(vm, r0, 0);
                tnt_set_flags_logic(vm, 0, b0, 0);
                return next_ip;
            }
            int wb = (r0 >= 0) ? b0 : ((r1 >= 0) ? b1 : abits);
            uint64_t lv = 0, rv = 0;
            int lt = 0, rt = 0, lb = wb, rb = wb;
            tnt_x86_read_op(a, vm, ops[0], wb, &lv, &lt, &lb);
            tnt_x86_read_op(a, vm, ops[1], lb, &rv, &rt, &rb);
            int res_t = lt || rt;
            uint64_t res = (strcmp(m, "xor") == 0) ? (lv ^ rv) : (lv - rv);
            tnt_x86_write_op(vm, out, ins->ip, ops[0], lb, res, res_t);
            if (strcmp(m, "xor") == 0) tnt_set_flags_logic(vm, res, lb, res_t);
            else tnt_set_flags_sub(vm, lv, rv, lb, res_t);
        }
        return next_ip;
    }

    if (strcmp(m, "add") == 0 || strcmp(m, "adc") == 0 || strcmp(m, "sbb") == 0 ||
        strcmp(m, "and") == 0 || strcmp(m, "or") == 0) {
        if (nops >= 2) {
            int wb = (r0 >= 0) ? b0 : ((r1 >= 0) ? b1 : abits);
            uint64_t lv = 0, rv = 0;
            int lt = 0, rt = 0, lb = wb, rb = wb;
            tnt_x86_read_op(a, vm, ops[0], wb, &lv, &lt, &lb);
            tnt_x86_read_op(a, vm, ops[1], lb, &rv, &rt, &rb);
            int res_t = lt || rt;
            uint64_t res = lv;
            if (strcmp(m, "and") == 0) {
                res = lv & rv;
                if (has_imm1 && imm1 == 0) res_t = 0;
                tnt_x86_write_op(vm, out, ins->ip, ops[0], lb, res, res_t);
                tnt_set_flags_logic(vm, res, lb, res_t);
            } else if (strcmp(m, "or") == 0) {
                res = lv | rv;
                tnt_x86_write_op(vm, out, ins->ip, ops[0], lb, res, res_t);
                tnt_set_flags_logic(vm, res, lb, res_t);
            } else if (strcmp(m, "add") == 0 || strcmp(m, "adc") == 0) {
                uint64_t rhs = rv + (strcmp(m, "adc") == 0 ? (uint64_t)vm->cf : 0ULL);
                res = lv + rhs;
                tnt_x86_write_op(vm, out, ins->ip, ops[0], lb, res, res_t);
                tnt_set_flags_add(vm, lv, rhs, lb, res_t);
            } else {
                uint64_t rhs = rv + (uint64_t)vm->cf;
                res = lv - rhs;
                tnt_x86_write_op(vm, out, ins->ip, ops[0], lb, res, res_t);
                tnt_set_flags_sub(vm, lv, rhs, lb, res_t);
            }
        }
        return next_ip;
    }

    if (strcmp(m, "inc") == 0 || strcmp(m, "dec") == 0 || strcmp(m, "neg") == 0 || strcmp(m, "not") == 0) {
        if (nops >= 1) {
            uint64_t lv = 0;
            int lt = 0, lb = (r0 >= 0) ? b0 : abits;
            tnt_x86_read_op(a, vm, ops[0], lb, &lv, &lt, &lb);
            int old_cf = vm->cf;
            uint64_t res = lv;
            if (strcmp(m, "inc") == 0) {
                res = lv + 1ULL;
                tnt_set_flags_add(vm, lv, 1ULL, lb, lt);
                vm->cf = old_cf;
            } else if (strcmp(m, "dec") == 0) {
                res = lv - 1ULL;
                tnt_set_flags_sub(vm, lv, 1ULL, lb, lt);
                vm->cf = old_cf;
            } else if (strcmp(m, "neg") == 0) {
                res = (uint64_t)0 - lv;
                tnt_set_flags_sub(vm, 0, lv, lb, lt);
                vm->cf = (tnt_mask(lv, lb) != 0);
            } else {
                res = ~lv;
            }
            tnt_x86_write_op(vm, out, ins->ip, ops[0], lb, res, lt);
        }
        return next_ip;
    }

    if (strcmp(m, "shl") == 0 || strcmp(m, "sal") == 0 || strcmp(m, "shr") == 0 || strcmp(m, "sar") == 0) {
        if (nops >= 2) {
            uint64_t lv = 0, rv = 0;
            int lt = 0, rt = 0, lb = (r0 >= 0) ? b0 : abits, rb = 8;
            tnt_x86_read_op(a, vm, ops[0], lb, &lv, &lt, &lb);
            tnt_x86_read_op(a, vm, ops[1], 8, &rv, &rt, &rb);
            uint64_t cnt = rv & ((lb == 64) ? 63ULL : 31ULL);
            uint64_t res = tnt_mask(lv, lb);
            if (strcmp(m, "shl") == 0 || strcmp(m, "sal") == 0) res = tnt_mask(res << cnt, lb);
            else if (strcmp(m, "shr") == 0) res = res >> cnt;
            else res = tnt_sar(res, cnt, lb);
            int res_t = lt || rt;
            tnt_x86_write_op(vm, out, ins->ip, ops[0], lb, res, res_t);
            if (cnt != 0) tnt_set_flags_logic(vm, res, lb, res_t);
        }
        return next_ip;
    }

    if (strcmp(m, "imul") == 0) {
        if (nops == 3 && r0 >= 0) {
            uint64_t sv = 0, iv = 0;
            int st = 0, it = 0, sb = b0, ib = b0;
            tnt_x86_read_op(a, vm, ops[1], b0, &sv, &st, &sb);
            tnt_x86_read_op(a, vm, ops[2], b0, &iv, &it, &ib);
            int res_t = (iv == 0 && !it) ? 0 : (st || it);
            tnt_vm_set_reg(vm, r0, b0, hi0, (uint64_t)((int64_t)tnt_sext(sv, b0) * (int64_t)tnt_sext(iv, b0)));
            tnt_vm_set_taint(vm, r0, res_t);
        } else if (nops == 2 && r0 >= 0) {
            uint64_t lv = tnt_vm_get_reg(vm, r0, b0, hi0), rv = 0;
            int lt = tnt_vm_get_taint(vm, r0), rt = 0, rb = b0;
            tnt_x86_read_op(a, vm, ops[1], b0, &rv, &rt, &rb);
            int res_t = (has_imm1 && imm1 == 0) ? 0 : (lt || rt);
            tnt_vm_set_reg(vm, r0, b0, hi0, (uint64_t)((int64_t)tnt_sext(lv, b0) * (int64_t)tnt_sext(rv, b0)));
            tnt_vm_set_taint(vm, r0, res_t);
        } else if (nops == 1) {
            uint64_t sv = 0;
            int st = 0, sb = abits;
            tnt_x86_read_op(a, vm, ops[0], abits, &sv, &st, &sb);
            int res_t = tnt_vm_get_taint(vm, 0) || st;
            uint64_t lv = tnt_vm_get_reg(vm, 0, sb, 0);
            tnt_vm_set_reg(vm, 0, sb, 0, (uint64_t)((int64_t)tnt_sext(lv, sb) * (int64_t)tnt_sext(sv, sb)));
            tnt_vm_set_taint(vm, 0, res_t);
            tnt_vm_set_taint(vm, 2, res_t);
        }
        return next_ip;
    }

    if (strcmp(m, "cmp") == 0 || strcmp(m, "test") == 0) {
        if (nops >= 2) {
            int wb = (r0 >= 0) ? b0 : ((r1 >= 0) ? b1 : abits);
            uint64_t lv = 0, rv = 0;
            int lt = 0, rt = 0, lb = wb, rb = wb;
            tnt_x86_read_op(a, vm, ops[0], wb, &lv, &lt, &lb);
            tnt_x86_read_op(a, vm, ops[1], lb, &rv, &rt, &rb);
            if (strcmp(m, "cmp") == 0) {
                int ft = (r0 >= 0 && r0 == r1 && b0 == b1 && hi0 == hi1) ? 0 : (lt || rt);
                tnt_set_flags_sub(vm, lv, rv, lb, ft);
            } else {
                int ft = (has_imm1 && imm1 == 0) ? 0 : (lt || rt);
                tnt_set_flags_logic(vm, lv & rv, lb, ft);
            }
        }
        return next_ip;
    }

    if (strncmp(m, "set", 3) == 0 && nops >= 1) {
        int cond = tnt_eval_x86_cc(m + 3, vm->zf, vm->sf, vm->cf, vm->of);
        if (cond >= 0) {
            tnt_x86_write_op(vm, out, ins->ip, ops[0], 8, (uint64_t)(cond ? 1 : 0), vm->flag_taint);
        }
        return next_ip;
    }

    if (strncmp(m, "cmov", 4) == 0 && nops >= 2 && r0 >= 0) {
        int cond = tnt_eval_x86_cc(m + 4, vm->zf, vm->sf, vm->cf, vm->of);
        if (cond > 0) {
            uint64_t rv = 0;
            int rt = 0, rb = b0;
            tnt_x86_read_op(a, vm, ops[1], b0, &rv, &rt, &rb);
            tnt_vm_set_reg(vm, r0, b0, hi0, rv);
            tnt_vm_set_taint(vm, r0, rt || vm->flag_taint);
        } else if (cond == 0 && vm->flag_taint) {
            tnt_vm_set_taint(vm, r0, 1);
        }
        return next_ip;
    }

    if (ins->flow == X86_FLOW_JCC) {
        int taken = 0;
        int br_taint = vm->flag_taint;
        if (strcmp(m, "jrcxz") == 0 || strcmp(m, "jecxz") == 0) {
            taken = (tnt_vm_get_reg(vm, 1, abits, 0) == 0);
            br_taint = tnt_vm_get_taint(vm, 1);
        } else if (m[0] == 'j') {
            int c = tnt_eval_x86_cc(m + 1, vm->zf, vm->sf, vm->cf, vm->of);
            if (c >= 0) taken = c;
        }
        if (br_taint) {
            char msg[96];
            snprintf(msg, sizeof(msg), "%s 0x%llx (%s)", m, (unsigned long long)ins->target, taken ? "taken" : "not-taken");
            tnt_add_event(out, ins->ip, "TAINT_BRANCH", vm->reg_taint, msg);
        }
        if (taken && ins->has_target) return ins->target;
        return next_ip;
    }

    if (ins->flow == X86_FLOW_JMP) {
        if (ins->has_target && !ins->target_mem) return ins->target;
        uint64_t iat_ea = 0;
        int iat_mb = 0, iat_eat = 0;
        bool is_mem = (nops >= 1) && tnt_x86_eval_ea(ops[0], vm, &iat_ea, &iat_mb, &iat_eat);
        uint64_t sym_va = (ins->has_target && ins->target_mem) ? ins->target : ((is_mem && !iat_eat) ? iat_ea : 0);
        if (sym_va) {
            const char *sym = ana_sym_at(a, sym_va);
            if (sym && tnt_exec_shim(a, vm, out, ins->ip, sym)) {
                // IAT tail-call thunk: return to caller after running shim
                uint64_t rv = TNT_RET_SENTINEL;
                int rt = 0;
                tnt_mem_read(a, vm, vm->regs[4], abits, &rv, &rt);
                vm->regs[4] += (uint64_t)pbytes;
                return rv;
            }
        }
        uint64_t tgt = 0;
        int tt = 0, tb = abits;
        if (nops >= 1) tnt_x86_read_op(a, vm, ops[0], abits, &tgt, &tt, &tb);
        if (tt || (is_mem && iat_eat)) {
            char msg[96];
            snprintf(msg, sizeof(msg), "jmp %s -> 0x%llx", ops[0], (unsigned long long)tgt);
            tnt_add_event(out, ins->ip, "TAINT_IND", vm->reg_taint, msg);
        }
        return tgt;
    }

    if (ins->flow == X86_FLOW_CALL) {
        const char *sym = NULL;
        uint64_t tgt = 0;
        if (ins->has_target) {
            tgt = ins->target;
            sym = ana_sym_at(a, tgt);
        } else if (nops >= 1) {
            uint64_t ea = 0;
            int mb = 0, ea_t = 0;
            bool is_mem = tnt_x86_eval_ea(ops[0], vm, &ea, &mb, &ea_t);
            if (is_mem && !ea_t) sym = ana_sym_at(a, ea);
            int tt = 0, tb = abits;
            tnt_x86_read_op(a, vm, ops[0], abits, &tgt, &tt, &tb);
            if (tt || (is_mem && ea_t)) {
                char msg[96];
                snprintf(msg, sizeof(msg), "call %s -> 0x%llx", ops[0], (unsigned long long)tgt);
                tnt_add_event(out, ins->ip, "TAINT_IND", vm->reg_taint, msg);
            }
            if (!sym && tgt) sym = ana_sym_at(a, tgt);
        }
        if (sym && tnt_exec_shim(a, vm, out, ins->ip, sym)) return next_ip;
        if (ins->has_target && !ins->target_mem && bin_is_exec(&a->bin, tgt) &&
            vm->regs[4] > TNT_STACK_BASE + 256ULL) {
            vm->regs[4] -= (uint64_t)pbytes;
            tnt_mem_write(vm, vm->regs[4], abits, next_ip, 0);
            return tgt;
        }
        return next_ip;
    }

    if (ins->flow == X86_FLOW_RET) {
        uint64_t rv = TNT_RET_SENTINEL;
        int rt = 0;
        tnt_mem_read(a, vm, vm->regs[4], abits, &rv, &rt);
        vm->regs[4] += (uint64_t)pbytes;
        uint64_t pop_imm = 0;
        if (nops >= 1 && tnt_parse_imm(ops[0], &pop_imm)) vm->regs[4] += pop_imm;
        return rv;
    }

    return next_ip;
}

static bool tnt_a64_parse_mem(const char *op, const tnt_vm *vm, uint64_t *ea, int *base_reg, int *pre_idx, int64_t *off_out) {
    *ea = 0;
    *base_reg = -1;
    *pre_idx = 0;
    *off_out = 0;
    if (!op || op[0] != '[') return false;

    char buf[76];
    snprintf(buf, sizeof(buf), "%s", op + 1);
    size_t len = strlen(buf);
    if (len > 0 && buf[len - 1] == '!') {
        *pre_idx = 1;
        buf[--len] = 0;
    }
    char *rb = strchr(buf, ']');
    if (rb) *rb = 0;

    char *comma = strchr(buf, ',');
    uint64_t abs_addr = 0;
    if (!comma && tnt_parse_imm(buf, &abs_addr)) {
        *ea = abs_addr;
        return true;
    }

    char base_s[32];
    if (comma) {
        size_t n = (size_t)(comma - buf);
        if (n >= sizeof(base_s)) n = sizeof(base_s) - 1;
        memcpy(base_s, buf, n);
        base_s[n] = 0;
    } else {
        snprintf(base_s, sizeof(base_s), "%s", buf);
    }
    tnt_trim(base_s);

    int bb = 64;
    int br = tnt_a64_reg(base_s, &bb);
    if (br < 0) return false;
    *base_reg = br;

    int64_t off = 0;
    if (comma) {
        char off_s[32];
        snprintf(off_s, sizeof(off_s), "%s", comma + 1);
        tnt_trim(off_s);
        uint64_t ov = 0;
        int rb2 = 64;
        int ir = tnt_a64_reg(off_s, &rb2);
        if (ir >= 0) off = (int64_t)tnt_vm_get_reg(vm, ir, rb2, 0);
        else if (tnt_parse_imm(off_s, &ov)) off = (int64_t)ov;
    }
    *off_out = off;
    *ea = tnt_vm_get_reg(vm, br, 64, 0) + (uint64_t)off;
    return true;
}

static uint64_t tnt_step_a64(const ana_ctx *a, tnt_vm *vm, tnt_res *out, const x86_ins *ins) {
    uint64_t next_ip = ins->ip + (uint64_t)ins->len;
    const char *m = ins->mnem;
    char ops[4][76];
    int nops = tnt_split_ops(ins->ops, ops);

    if (strcmp(m, "nop") == 0 || strncmp(m, "pac", 3) == 0 || strncmp(m, "aut", 3) == 0) {
        return next_ip;
    }

    int b0 = 64, b1 = 64, b2 = 64;
    int r0 = (nops >= 1) ? tnt_a64_reg(ops[0], &b0) : -1;
    int r1 = (nops >= 2) ? tnt_a64_reg(ops[1], &b1) : -1;
    int r2 = (nops >= 3) ? tnt_a64_reg(ops[2], &b2) : -1;
    uint64_t imm1 = 0, imm2 = 0;
    bool has_imm1 = (nops >= 2) && tnt_parse_imm(ops[1], &imm1);
    bool has_imm2 = (nops >= 3) && tnt_parse_imm(ops[2], &imm2);

    if (strcmp(m, "mov") == 0 && nops >= 2 && r0 >= 0) {
        if (r1 == -2 || has_imm1) {
            tnt_vm_set_reg(vm, r0, b0, 0, has_imm1 ? imm1 : 0ULL);
            tnt_vm_set_taint(vm, r0, 0);
        } else if (r1 >= 0) {
            tnt_vm_set_reg(vm, r0, b0, 0, tnt_vm_get_reg(vm, r1, b1, 0));
            tnt_vm_set_taint(vm, r0, tnt_vm_get_taint(vm, r1));
        }
        return next_ip;
    }

    if ((strcmp(m, "movz") == 0 || strcmp(m, "movn") == 0 || strcmp(m, "movk") == 0) && nops >= 2 && r0 >= 0) {
        uint64_t sh = 0;
        if (nops >= 3 && strncmp(ops[2], "lsl ", 4) == 0) tnt_parse_imm(ops[2] + 4, &sh);
        uint64_t v = (imm1 & 0xFFFFULL) << (sh & 48ULL);
        if (strcmp(m, "movz") == 0) {
            tnt_vm_set_reg(vm, r0, b0, 0, v);
            tnt_vm_set_taint(vm, r0, 0);
        } else if (strcmp(m, "movn") == 0) {
            tnt_vm_set_reg(vm, r0, b0, 0, ~v);
            tnt_vm_set_taint(vm, r0, 0);
        } else {
            uint64_t cur = tnt_vm_get_reg(vm, r0, b0, 0);
            cur = (cur & ~(0xFFFFULL << (sh & 48ULL))) | v;
            tnt_vm_set_reg(vm, r0, b0, 0, cur);
        }
        return next_ip;
    }

    if ((strcmp(m, "adr") == 0 || strcmp(m, "adrp") == 0) && nops >= 2 && r0 >= 0) {
        tnt_vm_set_reg(vm, r0, 64, 0, ins->has_target ? ins->target : imm1);
        tnt_vm_set_taint(vm, r0, 0);
        return next_ip;
    }

    if (strcmp(m, "mvn") == 0 && nops >= 2 && r0 >= 0 && r1 >= 0) {
        tnt_vm_set_reg(vm, r0, b0, 0, ~tnt_vm_get_reg(vm, r1, b1, 0));
        tnt_vm_set_taint(vm, r0, tnt_vm_get_taint(vm, r1));
        return next_ip;
    }

    if ((strcmp(m, "add") == 0 || strcmp(m, "adds") == 0 ||
         strcmp(m, "sub") == 0 || strcmp(m, "subs") == 0 ||
         strcmp(m, "mul") == 0 || strcmp(m, "madd") == 0 ||
         strcmp(m, "and") == 0 || strcmp(m, "ands") == 0 ||
         strcmp(m, "orr") == 0 || strcmp(m, "eor") == 0 || strcmp(m, "bic") == 0 ||
         strcmp(m, "lsl") == 0 || strcmp(m, "lsr") == 0 || strcmp(m, "asr") == 0) && nops >= 3) {
        uint64_t lv = (r1 >= 0) ? tnt_vm_get_reg(vm, r1, b0, 0) : 0;
        int lt = (r1 >= 0) ? tnt_vm_get_taint(vm, r1) : 0;
        uint64_t rv = has_imm2 ? imm2 : ((r2 >= 0) ? tnt_vm_get_reg(vm, r2, b0, 0) : 0);
        int rt = has_imm2 ? 0 : ((r2 >= 0) ? tnt_vm_get_taint(vm, r2) : 0);
        int res_t = lt || rt;
        uint64_t res = 0;

        if ((strcmp(m, "eor") == 0 || strcmp(m, "sub") == 0 || strcmp(m, "subs") == 0) && r1 >= 0 && r1 == r2) {
            res = 0;
            res_t = 0;
        } else if (strcmp(m, "add") == 0 || strcmp(m, "adds") == 0) {
            res = lv + rv;
        } else if (strcmp(m, "sub") == 0 || strcmp(m, "subs") == 0) {
            res = lv - rv;
        } else if (strcmp(m, "mul") == 0) {
            res = lv * rv;
            if ((has_imm2 && imm2 == 0) || r2 == -2 || r1 == -2) res_t = 0;
        } else if (strcmp(m, "madd") == 0) {
            int b3 = b0, r3 = (nops >= 4) ? tnt_a64_reg(ops[3], &b3) : -1;
            uint64_t av = (r3 >= 0) ? tnt_vm_get_reg(vm, r3, b0, 0) : 0;
            int at = (r3 >= 0) ? tnt_vm_get_taint(vm, r3) : 0;
            res = av + lv * rv;
            res_t = res_t || at;
        } else if (strcmp(m, "and") == 0 || strcmp(m, "ands") == 0) {
            res = lv & rv;
            if ((has_imm2 && imm2 == 0) || r2 == -2 || r1 == -2) res_t = 0;
        } else if (strcmp(m, "orr") == 0) {
            res = lv | rv;
        } else if (strcmp(m, "eor") == 0) {
            res = lv ^ rv;
        } else if (strcmp(m, "bic") == 0) {
            res = lv & ~rv;
        } else if (strcmp(m, "lsl") == 0) {
            res = lv << (rv & (b0 == 64 ? 63ULL : 31ULL));
        } else if (strcmp(m, "lsr") == 0) {
            res = tnt_mask(lv, b0) >> (rv & (b0 == 64 ? 63ULL : 31ULL));
        } else {
            res = tnt_sar(lv, rv & (b0 == 64 ? 63ULL : 31ULL), b0);
        }

        if (r0 >= 0) {
            tnt_vm_set_reg(vm, r0, b0, 0, res);
            tnt_vm_set_taint(vm, r0, res_t);
        }
        if (strcmp(m, "adds") == 0) tnt_set_flags_add(vm, lv, rv, b0, res_t);
        else if (strcmp(m, "subs") == 0) tnt_set_flags_sub(vm, lv, rv, b0, res_t);
        else if (strcmp(m, "ands") == 0) tnt_set_flags_logic(vm, res, b0, res_t);
        return next_ip;
    }

    if ((strcmp(m, "cmp") == 0 || strcmp(m, "cmn") == 0 || strcmp(m, "tst") == 0) && nops >= 2) {
        uint64_t lv = (r0 >= 0) ? tnt_vm_get_reg(vm, r0, b0, 0) : 0;
        int lt = (r0 >= 0) ? tnt_vm_get_taint(vm, r0) : 0;
        uint64_t rv = has_imm1 ? imm1 : ((r1 >= 0) ? tnt_vm_get_reg(vm, r1, b0, 0) : 0);
        int rt = has_imm1 ? 0 : ((r1 >= 0) ? tnt_vm_get_taint(vm, r1) : 0);
        int ft = (strcmp(m, "cmp") == 0 && r0 >= 0 && r0 == r1) ? 0 : (lt || rt);
        if (strcmp(m, "cmp") == 0) tnt_set_flags_sub(vm, lv, rv, b0, ft);
        else if (strcmp(m, "cmn") == 0) tnt_set_flags_add(vm, lv, rv, b0, ft);
        else tnt_set_flags_logic(vm, lv & rv, b0, (has_imm1 && imm1 == 0) ? 0 : ft);
        return next_ip;
    }

    if (strcmp(m, "csel") == 0 && nops >= 4 && r0 >= 0) {
        int cond = tnt_eval_a64_cc(ops[3], vm->zf, vm->sf, vm->cf, vm->of);
        int src = (cond > 0) ? r1 : r2;
        uint64_t v = (src >= 0) ? tnt_vm_get_reg(vm, src, b0, 0) : 0;
        int vt = (src >= 0) ? tnt_vm_get_taint(vm, src) : 0;
        tnt_vm_set_reg(vm, r0, b0, 0, v);
        tnt_vm_set_taint(vm, r0, vt || vm->flag_taint);
        return next_ip;
    }

    if ((strcmp(m, "ldr") == 0 || strcmp(m, "ldrb") == 0 || strcmp(m, "ldrh") == 0) && nops >= 2 && r0 >= 0) {
        uint64_t ea = 0;
        int br = -1, pre = 0;
        int64_t off = 0;
        if (tnt_a64_parse_mem(ops[1], vm, &ea, &br, &pre, &off)) {
            int wb = (strcmp(m, "ldrb") == 0) ? 8 : (strcmp(m, "ldrh") == 0) ? 16 : b0;
            uint64_t val = 0;
            int vt = 0;
            tnt_mem_read(a, vm, ea, wb, &val, &vt);
            tnt_vm_set_reg(vm, r0, b0, 0, tnt_mask(val, wb));
            tnt_vm_set_taint(vm, r0, vt);
            if (pre && br >= 0) tnt_vm_set_reg(vm, br, 64, 0, ea);
            else if (nops >= 3 && br >= 0 && has_imm2) {
                tnt_vm_set_reg(vm, br, 64, 0, tnt_vm_get_reg(vm, br, 64, 0) + imm2);
            }
        }
        return next_ip;
    }

    if ((strcmp(m, "str") == 0 || strcmp(m, "strb") == 0 || strcmp(m, "strh") == 0) && nops >= 2) {
        uint64_t ea = 0;
        int br = -1, pre = 0;
        int64_t off = 0;
        if (tnt_a64_parse_mem(ops[1], vm, &ea, &br, &pre, &off)) {
            int wb = (strcmp(m, "strb") == 0) ? 8 : (strcmp(m, "strh") == 0) ? 16 : b0;
            uint64_t val = (r0 >= 0) ? tnt_vm_get_reg(vm, r0, wb, 0) : 0;
            int vt = (r0 >= 0) ? tnt_vm_get_taint(vm, r0) : 0;
            tnt_mem_write(vm, ea, wb, val, vt);
            if (vt) {
                char msg[96];
                snprintf(msg, sizeof(msg), "[0x%llx] <- %s (%dB)", (unsigned long long)ea, ops[0], wb / 8);
                tnt_add_event(out, ins->ip, "TAINT_STORE", vm->reg_taint, msg);
            }
            if (pre && br >= 0) tnt_vm_set_reg(vm, br, 64, 0, ea);
            else if (nops >= 3 && br >= 0 && has_imm2) {
                tnt_vm_set_reg(vm, br, 64, 0, tnt_vm_get_reg(vm, br, 64, 0) + imm2);
            }
        }
        return next_ip;
    }

    if ((strcmp(m, "stp") == 0 || strcmp(m, "ldp") == 0) && nops >= 3) {
        uint64_t ea = 0;
        int br = -1, pre = 0;
        int64_t off = 0;
        if (tnt_a64_parse_mem(ops[2], vm, &ea, &br, &pre, &off)) {
            int wb = (b0 == 32) ? 32 : 64;
            uint64_t esz = (uint64_t)(wb / 8);
            if (strcmp(m, "stp") == 0) {
                uint64_t v0 = (r0 >= 0) ? tnt_vm_get_reg(vm, r0, wb, 0) : 0;
                uint64_t v1 = (r1 >= 0) ? tnt_vm_get_reg(vm, r1, wb, 0) : 0;
                int t0 = (r0 >= 0) ? tnt_vm_get_taint(vm, r0) : 0;
                int t1 = (r1 >= 0) ? tnt_vm_get_taint(vm, r1) : 0;
                tnt_mem_write(vm, ea, wb, v0, t0);
                tnt_mem_write(vm, ea + esz, wb, v1, t1);
                if (t0 || t1) {
                    char msg[96];
                    snprintf(msg, sizeof(msg), "stp [0x%llx] <- %s,%s", (unsigned long long)ea, ops[0], ops[1]);
                    tnt_add_event(out, ins->ip, "TAINT_STORE", vm->reg_taint, msg);
                }
            } else {
                uint64_t v0 = 0, v1 = 0;
                int t0 = 0, t1 = 0;
                tnt_mem_read(a, vm, ea, wb, &v0, &t0);
                tnt_mem_read(a, vm, ea + esz, wb, &v1, &t1);
                if (r0 >= 0) { tnt_vm_set_reg(vm, r0, wb, 0, v0); tnt_vm_set_taint(vm, r0, t0); }
                if (r1 >= 0) { tnt_vm_set_reg(vm, r1, wb, 0, v1); tnt_vm_set_taint(vm, r1, t1); }
            }
            if (pre && br >= 0) {
                tnt_vm_set_reg(vm, br, 64, 0, ea);
            } else if (nops >= 4 && br >= 0) {
                uint64_t post = 0;
                if (tnt_parse_imm(ops[3], &post)) {
                    tnt_vm_set_reg(vm, br, 64, 0, tnt_vm_get_reg(vm, br, 64, 0) + post);
                }
            }
        }
        return next_ip;
    }

    if (strcmp(m, "cbz") == 0 || strcmp(m, "cbnz") == 0) {
        uint64_t v = (r0 >= 0) ? tnt_vm_get_reg(vm, r0, b0, 0) : 0;
        int vt = (r0 >= 0) ? tnt_vm_get_taint(vm, r0) : 0;
        int taken = (strcmp(m, "cbz") == 0) ? (v == 0) : (v != 0);
        if (vt) {
            char msg[96];
            snprintf(msg, sizeof(msg), "%s %s -> 0x%llx (%s)", m, ops[0], (unsigned long long)ins->target, taken ? "taken" : "not-taken");
            tnt_add_event(out, ins->ip, "TAINT_BRANCH", vm->reg_taint, msg);
        }
        return (taken && ins->has_target) ? ins->target : next_ip;
    }

    if (strcmp(m, "tbz") == 0 || strcmp(m, "tbnz") == 0) {
        uint64_t v = (r0 >= 0) ? tnt_vm_get_reg(vm, r0, 64, 0) : 0;
        int vt = (r0 >= 0) ? tnt_vm_get_taint(vm, r0) : 0;
        int bit = (int)(imm1 & 63ULL);
        int set = (int)((v >> bit) & 1ULL);
        int taken = (strcmp(m, "tbz") == 0) ? !set : set;
        if (vt) {
            char msg[96];
            snprintf(msg, sizeof(msg), "%s %s,#%d (%s)", m, ops[0], bit, taken ? "taken" : "not-taken");
            tnt_add_event(out, ins->ip, "TAINT_BRANCH", vm->reg_taint, msg);
        }
        return (taken && ins->has_target) ? ins->target : next_ip;
    }

    if (strncmp(m, "b.", 2) == 0) {
        int taken = tnt_eval_a64_cc(m + 2, vm->zf, vm->sf, vm->cf, vm->of);
        if (taken < 0) taken = 0;
        if (vm->flag_taint) {
            char msg[96];
            snprintf(msg, sizeof(msg), "%s 0x%llx (%s)", m, (unsigned long long)ins->target, taken ? "taken" : "not-taken");
            tnt_add_event(out, ins->ip, "TAINT_BRANCH", vm->reg_taint, msg);
        }
        return (taken && ins->has_target) ? ins->target : next_ip;
    }

    if (strcmp(m, "b") == 0 && ins->has_target) {
        const char *sym = ana_sym_at(a, ins->target);
        if (sym && tnt_exec_shim(a, vm, out, ins->ip, sym)) {
            return tnt_vm_get_reg(vm, 30, 64, 0);
        }
        return ins->target;
    }

    if (strcmp(m, "bl") == 0 && ins->has_target) {
        const char *sym = ana_sym_at(a, ins->target);
        if (sym && tnt_exec_shim(a, vm, out, ins->ip, sym)) return next_ip;
        if (bin_is_exec(&a->bin, ins->target)) {
            tnt_vm_set_reg(vm, 30, 64, 0, next_ip);
            tnt_vm_set_taint(vm, 30, 0);
            return ins->target;
        }
        return next_ip;
    }

    if (strcmp(m, "br") == 0 || strcmp(m, "blr") == 0) {
        uint64_t tgt = (r0 >= 0) ? tnt_vm_get_reg(vm, r0, 64, 0) : 0;
        int tt = (r0 >= 0) ? tnt_vm_get_taint(vm, r0) : 0;
        if (tt) {
            char msg[96];
            snprintf(msg, sizeof(msg), "%s %s -> 0x%llx", m, ops[0], (unsigned long long)tgt);
            tnt_add_event(out, ins->ip, "TAINT_IND", vm->reg_taint, msg);
        }
        const char *sym = tgt ? ana_sym_at(a, tgt) : NULL;
        if (sym && tnt_exec_shim(a, vm, out, ins->ip, sym)) {
            return (strcmp(m, "blr") == 0) ? next_ip : tnt_vm_get_reg(vm, 30, 64, 0);
        }
        if (strcmp(m, "blr") == 0) {
            if (bin_is_exec(&a->bin, tgt)) {
                tnt_vm_set_reg(vm, 30, 64, 0, next_ip);
                return tgt;
            }
            return next_ip;
        }
        return tgt;
    }

    if (strcmp(m, "ret") == 0) {
        int lr = (r0 >= 0) ? r0 : 30;
        return tnt_vm_get_reg(vm, lr, 64, 0);
    }

    return next_ip;
}

bool tnt_run(const ana_ctx *a, uint64_t start_va, int src_reg, uint32_t buf_len, int max_steps, tnt_res *out) {
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    if (!a || !bin_is_exec(&a->bin, start_va)) return false;

    if (max_steps <= 0) max_steps = 128;
    if (max_steps > 512) max_steps = 512;
    out->start_va = start_va;

    tnt_vm *vm = (tnt_vm *)calloc(1, sizeof(tnt_vm));
    if (!vm) return false;

    vm->is_a64 = (a->bin.arch == BIN_ARCH_ARM64);
    vm->is_32  = (a->bin.arch == BIN_ARCH_X86);
    vm->pc = start_va;

    if (vm->is_a64) {
        vm->a64_hi[15] = TNT_STACK_INIT; // sp
        vm->a64_hi[13] = TNT_STACK_INIT; // fp
        vm->a64_hi[14] = TNT_RET_SENTINEL; // lr
    } else {
        vm->regs[4] = TNT_STACK_INIT; // rsp
        vm->regs[5] = TNT_STACK_INIT; // rbp
        tnt_mem_write(vm, TNT_STACK_INIT, vm->is_32 ? 32 : 64, TNT_RET_SENTINEL, 0);
    }

    if (src_reg >= 0 && src_reg < 16) {
        vm->reg_taint |= (uint16_t)(1u << src_reg);
    }
    if (buf_len > 0) {
        if (buf_len > TNT_MAX_BUF) buf_len = TNT_MAX_BUF;
        uint64_t buf_va = tnt_heap_alloc(vm, buf_len + 1u);
        if (buf_va != 0) {
            size_t off = (size_t)(buf_va - TNT_HEAP_BASE);
            for (uint32_t i = 0; i < buf_len; i++) {
                vm->heap[off + i] = (uint8_t)'A';
                vm->heap_taint[off + i] = 1u;
            }
            vm->heap[off + buf_len] = 0;
            vm->heap_taint[off + buf_len] = 0;
            if (src_reg >= 0 && src_reg < 16) vm->regs[src_reg] = buf_va;
        }
    }

    x86_ins ins;
    for (int step = 0; step < max_steps; step++) {
        if (vm->pc == TNT_RET_SENTINEL) {
            snprintf(out->stop_reason, sizeof(out->stop_reason), "returned cleanly");
            break;
        }
        size_t av = 0;
        const uint8_t *p = bin_ptr(&a->bin, vm->pc, &av);
        if (!p || !av) {
            snprintf(out->stop_reason, sizeof(out->stop_reason), "unmapped pc 0x%llx", (unsigned long long)vm->pc);
            break;
        }
        int n = arch_decode(a->bin.arch, p, av, vm->pc, 1, 0, &ins);
        if (n <= 0) {
            snprintf(out->stop_reason, sizeof(out->stop_reason), "decode error");
            break;
        }
        out->nstep++;
        if (ins.flow == X86_FLOW_TRAP) {
            snprintf(out->stop_reason, sizeof(out->stop_reason), "trap (%s)", ins.mnem);
            break;
        }
        vm->pc = vm->is_a64 ? tnt_step_a64(a, vm, out, &ins) : tnt_step_x86(a, vm, out, &ins);
    }

    if (!out->stop_reason[0]) {
        snprintf(out->stop_reason, sizeof(out->stop_reason), "step limit (%d)", out->nstep);
    }

    int tb = 0;
    for (uint32_t i = 0; i < TNT_STACK_SIZE; i++) if (vm->stack_taint[i]) tb++;
    for (uint32_t i = 0; i < TNT_HEAP_SIZE; i++)  if (vm->heap_taint[i]) tb++;
    out->taint_bytes = tb;
    out->taint_regs = vm->reg_taint;
    memcpy(out->regs, vm->regs, sizeof(out->regs));

    free(vm);
    return true;
}

typedef enum {
    TNT_E_UNK = 0,
    TNT_E_CONST,
    TNT_E_SYM
} tnt_ekind;

typedef enum {
    TNT_OP_ID = 0,
    TNT_OP_ADD,
    TNT_OP_SUB,
    TNT_OP_XOR,
    TNT_OP_AND,
    TNT_OP_OR,
    TNT_OP_SHL,
    TNT_OP_SHR,
    TNT_OP_MUL,
    TNT_OP_RAW
} tnt_eop;

typedef enum {
    TNT_REL_NONE = 0,
    TNT_REL_EQ,
    TNT_REL_NE,
    TNT_REL_LT,
    TNT_REL_LE,
    TNT_REL_GT,
    TNT_REL_GE
} tnt_rel;

typedef struct {
    uint8_t  kind;
    uint8_t  var;
    uint8_t  op;
    uint64_t val;
    char     text[48];
} tnt_expr;

typedef struct {
    int      valid;
    tnt_expr lhs;
    tnt_expr rhs;
} tnt_cmp;

typedef struct {
    int      valid;
    int64_t  off;
    tnt_expr expr;
} tnt_slot;

typedef struct {
    tnt_expr regs[32];
    tnt_slot slots[TNT_MAX_SLOTS];
    int64_t  sp_off;
    tnt_cmp  cmp;
    int      is_a64;
} tnt_sym_st;

typedef struct {
    tnt_expr lhs;
    tnt_expr rhs;
    int      rel;
    int      is_signed;
    char     text[80];
} tnt_pcons;

static tnt_expr tnt_e_unk(void) {
    tnt_expr e;
    memset(&e, 0, sizeof(e));
    e.kind = TNT_E_UNK;
    return e;
}

static tnt_expr tnt_e_const(uint64_t v) {
    tnt_expr e;
    memset(&e, 0, sizeof(e));
    e.kind = TNT_E_CONST;
    e.val = v;
    return e;
}

static tnt_expr tnt_e_sym(uint8_t var) {
    tnt_expr e;
    memset(&e, 0, sizeof(e));
    e.kind = TNT_E_SYM;
    e.var = var;
    e.op = TNT_OP_ID;
    return e;
}

static void tnt_fmt_u64(uint64_t v, char *buf, size_t cap) {
    if (v < 10ULL) snprintf(buf, cap, "%llu", (unsigned long long)v);
    else snprintf(buf, cap, "0x%llx", (unsigned long long)v);
}

static void tnt_expr_fmt(const tnt_expr *e, char *buf, size_t cap) {
    if (e->kind == TNT_E_CONST) {
        tnt_fmt_u64(e->val, buf, cap);
        return;
    }
    if (e->kind != TNT_E_SYM) {
        snprintf(buf, cap, "?");
        return;
    }
    if (e->op == TNT_OP_RAW && e->text[0]) {
        snprintf(buf, cap, "%s", e->text);
        return;
    }
    if (e->op == TNT_OP_ID) {
        snprintf(buf, cap, "a%u", (unsigned)e->var + 1u);
        return;
    }
    static const char *const sym_op[] = {"","+","-","^","&","|","<<",">>","*"};
    char num[24];
    tnt_fmt_u64(e->val, num, sizeof(num));
    const char *os = (e->op <= TNT_OP_MUL) ? sym_op[e->op] : "?";
    snprintf(buf, cap, "(a%u %s %s)", (unsigned)e->var + 1u, os, num);
}

static tnt_expr tnt_expr_apply(tnt_expr e, uint8_t op, uint64_t k) {
    if (op == TNT_OP_ADD && (int64_t)k < 0 && (int64_t)k > -0x1000000LL) {
        op = TNT_OP_SUB;
        k = (uint64_t)0 - k;
    }
    if (e.kind == TNT_E_CONST) {
        if (op == TNT_OP_ADD) return tnt_e_const(e.val + k);
        if (op == TNT_OP_SUB) return tnt_e_const(e.val - k);
        if (op == TNT_OP_XOR) return tnt_e_const(e.val ^ k);
        if (op == TNT_OP_AND) return tnt_e_const(e.val & k);
        if (op == TNT_OP_OR)  return tnt_e_const(e.val | k);
        if (op == TNT_OP_SHL) return tnt_e_const(e.val << (k & 63ULL));
        if (op == TNT_OP_SHR) return tnt_e_const(e.val >> (k & 63ULL));
        if (op == TNT_OP_MUL) return tnt_e_const(e.val * k);
        return tnt_e_unk();
    }
    if (e.kind != TNT_E_SYM) return tnt_e_unk();

    if ((op == TNT_OP_AND || op == TNT_OP_MUL) && k == 0) return tnt_e_const(0);
    if ((op == TNT_OP_ADD || op == TNT_OP_SUB || op == TNT_OP_XOR ||
         op == TNT_OP_OR || op == TNT_OP_SHL || op == TNT_OP_SHR) && k == 0) return e;
    if (op == TNT_OP_MUL && k == 1) return e;

    if (e.op == TNT_OP_ID) {
        e.op = op;
        e.val = k;
        return e;
    }
    if (e.op == TNT_OP_ADD && op == TNT_OP_ADD) {
        e.val += k;
        if (e.val == 0) e.op = TNT_OP_ID;
        return e;
    }
    if (e.op == TNT_OP_SUB && op == TNT_OP_SUB) {
        e.val += k;
        if (e.val == 0) e.op = TNT_OP_ID;
        return e;
    }
    if ((e.op == TNT_OP_ADD && op == TNT_OP_SUB) || (e.op == TNT_OP_SUB && op == TNT_OP_ADD)) {
        int64_t cur = (e.op == TNT_OP_ADD) ? (int64_t)e.val : -(int64_t)e.val;
        int64_t del = (op == TNT_OP_ADD) ? (int64_t)k : -(int64_t)k;
        int64_t sum = cur + del;
        if (sum == 0) { e.op = TNT_OP_ID; e.val = 0; }
        else if (sum > 0) { e.op = TNT_OP_ADD; e.val = (uint64_t)sum; }
        else { e.op = TNT_OP_SUB; e.val = (uint64_t)(-sum); }
        return e;
    }
    if (e.op == TNT_OP_XOR && op == TNT_OP_XOR) {
        e.val ^= k;
        if (e.val == 0) e.op = TNT_OP_ID;
        return e;
    }
    if (e.op == TNT_OP_AND && op == TNT_OP_AND) {
        e.val &= k;
        if (e.val == 0) return tnt_e_const(0);
        return e;
    }
    if (e.op == TNT_OP_MUL && op == TNT_OP_MUL) {
        e.val *= k;
        return e;
    }

    static const char *const sym_op[] = {"","+","-","^","&","|","<<",">>","*"};
    char prev[48], num[24];
    tnt_expr_fmt(&e, prev, sizeof(prev));
    tnt_fmt_u64(k, num, sizeof(num));
    e.op = TNT_OP_RAW;
    snprintf(e.text, sizeof(e.text), "(%s %s %s)", prev, (op <= TNT_OP_MUL) ? sym_op[op] : "?", num);
    return e;
}

static bool tnt_sym_stack_off(const char *op, int is_a64, int64_t sp_off, int64_t *slot_off) {
    const char *p = op;
    if (!is_a64) {
        if (strncmp(p, "byte ptr ", 9) == 0) p += 9;
        else if (strncmp(p, "word ptr ", 9) == 0) p += 9;
        else if (strncmp(p, "dword ptr ", 10) == 0) p += 10;
        else if (strncmp(p, "qword ptr ", 10) == 0) p += 10;
    }
    if (*p != '[') return false;
    p++;
    int64_t base = 0;
    if (!is_a64) {
        if (strncmp(p, "rsp", 3) == 0 || strncmp(p, "esp", 3) == 0) { base = sp_off; p += 3; }
        else if (strncmp(p, "rbp", 3) == 0 || strncmp(p, "ebp", 3) == 0) { base = 0; p += 3; }
        else return false;
        int64_t disp = 0;
        if (*p == '+' || *p == '-') {
            int sign = (*p == '-') ? -1 : 1;
            p++;
            char num[24];
            int k = 0;
            while (*p && *p != ']' && k < 23) num[k++] = *p++;
            num[k] = 0;
            uint64_t v = 0;
            if (!tnt_parse_imm(num, &v)) return false;
            disp = sign * (int64_t)v;
        }
        if (*p != ']') return false;
        *slot_off = base + disp;
        return true;
    }
    if (strncmp(p, "sp", 2) == 0) { base = sp_off; p += 2; }
    else if (strncmp(p, "fp", 2) == 0) { base = 0; p += 2; }
    else return false;
    int64_t disp = 0;
    if (*p == ',') {
        p++;
        while (*p == ' ') p++;
        char num[24];
        int k = 0;
        while (*p && *p != ']' && k < 23) num[k++] = *p++;
        num[k] = 0;
        uint64_t v = 0;
        if (!tnt_parse_imm(num, &v)) return false;
        disp = (int64_t)v;
    }
    if (*p != ']') return false;
    *slot_off = base + disp;
    return true;
}

static tnt_expr tnt_sym_slot_get(const tnt_sym_st *st, int64_t off) {
    for (int i = 0; i < TNT_MAX_SLOTS; i++) {
        if (st->slots[i].valid && st->slots[i].off == off) return st->slots[i].expr;
    }
    return tnt_e_unk();
}

static void tnt_sym_slot_set(tnt_sym_st *st, int64_t off, tnt_expr e) {
    int free_i = -1;
    for (int i = 0; i < TNT_MAX_SLOTS; i++) {
        if (st->slots[i].valid && st->slots[i].off == off) {
            st->slots[i].expr = e;
            return;
        }
        if (!st->slots[i].valid && free_i < 0) free_i = i;
    }
    if (free_i >= 0) {
        st->slots[free_i].valid = 1;
        st->slots[free_i].off = off;
        st->slots[free_i].expr = e;
    }
}

static tnt_expr tnt_sym_eval_x86_op(const tnt_sym_st *st, const char *op) {
    int b = 64, hi = 0;
    int r = tnt_x86_reg(op, &b, &hi);
    if (r >= 0) return st->regs[r];
    uint64_t imm = 0;
    if (tnt_parse_imm(op, &imm)) return tnt_e_const(imm);
    int64_t soff = 0;
    if (tnt_sym_stack_off(op, 0, st->sp_off, &soff)) return tnt_sym_slot_get(st, soff);
    return tnt_e_unk();
}

static tnt_expr tnt_sym_eval_x86_lea(const tnt_sym_st *st, const char *op) {
    const char *lb = strchr(op, '[');
    if (!lb) return tnt_e_unk();
    char in[64];
    snprintf(in, sizeof(in), "%s", lb + 1);
    char *rb = strchr(in, ']');
    if (rb) *rb = 0;

    tnt_expr base = tnt_e_unk();
    int64_t disp = 0;
    int sign = 1;
    char *c = in;
    while (*c) {
        if (*c == ' ') { c++; continue; }
        if (*c == '+') { sign = 1; c++; continue; }
        if (*c == '-') { sign = -1; c++; continue; }
        char tok[32];
        int k = 0;
        while (*c && *c != '+' && *c != '-' && k < 31) tok[k++] = *c++;
        tok[k] = 0;
        tnt_trim(tok);
        if (!tok[0]) continue;
        char *star = strchr(tok, '*');
        if (star) {
            *star = 0;
            int b = 64, hi = 0;
            int r = tnt_x86_reg(tok, &b, &hi);
            uint64_t sc = (uint64_t)strtoull(star + 1, NULL, 10);
            if (r >= 0 && base.kind == TNT_E_UNK) base = tnt_expr_apply(st->regs[r], TNT_OP_MUL, sc);
        } else {
            int b = 64, hi = 0;
            int r = tnt_x86_reg(tok, &b, &hi);
            uint64_t imm = 0;
            if (r >= 0) {
                if (base.kind == TNT_E_UNK && sign > 0) base = st->regs[r];
                else if (base.kind == TNT_E_SYM && st->regs[r].kind == TNT_E_SYM && base.var == st->regs[r].var && base.op == TNT_OP_ID && st->regs[r].op == TNT_OP_ID && sign > 0) {
                    base = tnt_expr_apply(base, TNT_OP_MUL, 2);
                } else {
                    return tnt_e_unk();
                }
            } else if (tnt_parse_imm(tok, &imm)) {
                disp += sign * (int64_t)imm;
            }
        }
    }
    if (base.kind == TNT_E_UNK) return tnt_e_unk();
    if (disp > 0) return tnt_expr_apply(base, TNT_OP_ADD, (uint64_t)disp);
    if (disp < 0) return tnt_expr_apply(base, TNT_OP_SUB, (uint64_t)(-disp));
    return base;
}

static void tnt_sym_step_x86(tnt_sym_st *st, const x86_ins *ins) {
    const char *m = ins->mnem;
    if (strncmp(m, "lock ", 5) == 0) m += 5;
    char ops[4][76];
    int nops = tnt_split_ops(ins->ops, ops);
    int b0 = 64, hi0 = 0, b1 = 64, hi1 = 0;
    int r0 = (nops >= 1) ? tnt_x86_reg(ops[0], &b0, &hi0) : -1;
    int r1 = (nops >= 2) ? tnt_x86_reg(ops[1], &b1, &hi1) : -1;

    if (strcmp(m, "push") == 0) {
        st->sp_off -= 8;
        if (nops >= 1) tnt_sym_slot_set(st, st->sp_off, tnt_sym_eval_x86_op(st, ops[0]));
        return;
    }
    if (strcmp(m, "pop") == 0) {
        if (r0 >= 0) st->regs[r0] = tnt_sym_slot_get(st, st->sp_off);
        st->sp_off += 8;
        return;
    }
    if (strcmp(m, "mov") == 0 || strcmp(m, "movabs") == 0 || strcmp(m, "movsx") == 0 || strcmp(m, "movsxd") == 0) {
        if (nops >= 2) {
            tnt_expr rv = tnt_sym_eval_x86_op(st, ops[1]);
            int64_t soff = 0;
            if (r0 >= 0) st->regs[r0] = rv;
            else if (tnt_sym_stack_off(ops[0], 0, st->sp_off, &soff)) tnt_sym_slot_set(st, soff, rv);
        }
        return;
    }
    if (strcmp(m, "movzx") == 0 && nops >= 2 && r0 >= 0) {
        tnt_expr rv = tnt_sym_eval_x86_op(st, ops[1]);
        uint64_t mask = (strncmp(ops[1], "byte ptr ", 9) == 0 || (r1 >= 0 && b1 == 8)) ? 0xFFULL : 0xFFFFULL;
        st->regs[r0] = tnt_expr_apply(rv, TNT_OP_AND, mask);
        return;
    }
    if (strcmp(m, "lea") == 0 && nops >= 2 && r0 >= 0) {
        st->regs[r0] = tnt_sym_eval_x86_lea(st, ops[1]);
        return;
    }
    if (strcmp(m, "xchg") == 0 && nops >= 2 && r0 >= 0 && r1 >= 0) {
        tnt_expr tmp = st->regs[r0];
        st->regs[r0] = st->regs[r1];
        st->regs[r1] = tmp;
        return;
    }
    if (strcmp(m, "xor") == 0 && nops >= 2 && r0 >= 0 && r0 == r1) {
        st->regs[r0] = tnt_e_const(0);
        st->cmp.valid = 1; st->cmp.lhs = tnt_e_const(0); st->cmp.rhs = tnt_e_const(0);
        return;
    }
    if (strcmp(m, "sub") == 0 && nops >= 2 && r0 >= 0 && r0 == r1) {
        st->regs[r0] = tnt_e_const(0);
        st->cmp.valid = 1; st->cmp.lhs = tnt_e_const(0); st->cmp.rhs = tnt_e_const(0);
        return;
    }
    if (strcmp(m, "cmp") == 0 && nops >= 2) {
        st->cmp.valid = 1;
        st->cmp.lhs = tnt_sym_eval_x86_op(st, ops[0]);
        st->cmp.rhs = tnt_sym_eval_x86_op(st, ops[1]);
        return;
    }
    if (strcmp(m, "test") == 0 && nops >= 2) {
        tnt_expr lv = tnt_sym_eval_x86_op(st, ops[0]);
        tnt_expr rv = tnt_sym_eval_x86_op(st, ops[1]);
        st->cmp.valid = 1;
        if (r0 >= 0 && r0 == r1) {
            st->cmp.lhs = lv;
            st->cmp.rhs = tnt_e_const(0);
        } else if (rv.kind == TNT_E_CONST) {
            st->cmp.lhs = tnt_expr_apply(lv, TNT_OP_AND, rv.val);
            st->cmp.rhs = tnt_e_const(0);
        } else {
            st->cmp.lhs = lv;
            st->cmp.rhs = tnt_e_const(0);
        }
        return;
    }
    if ((strcmp(m, "inc") == 0 || strcmp(m, "dec") == 0) && r0 >= 0) {
        st->regs[r0] = tnt_expr_apply(st->regs[r0], strcmp(m, "inc") == 0 ? TNT_OP_ADD : TNT_OP_SUB, 1ULL);
        st->cmp.valid = 1; st->cmp.lhs = st->regs[r0]; st->cmp.rhs = tnt_e_const(0);
        return;
    }
    if (r0 == 4 && (strcmp(m, "sub") == 0 || strcmp(m, "add") == 0) && nops >= 2) {
        uint64_t imm = 0;
        if (tnt_parse_imm(ops[1], &imm)) {
            st->sp_off += (strcmp(m, "add") == 0) ? (int64_t)imm : -(int64_t)imm;
            return;
        }
    }
    if (r0 >= 0 && nops >= 2) {
        uint8_t op = 0;
        if (strcmp(m, "add") == 0) op = TNT_OP_ADD;
        else if (strcmp(m, "sub") == 0) op = TNT_OP_SUB;
        else if (strcmp(m, "xor") == 0) op = TNT_OP_XOR;
        else if (strcmp(m, "and") == 0) op = TNT_OP_AND;
        else if (strcmp(m, "or") == 0)  op = TNT_OP_OR;
        else if (strcmp(m, "shl") == 0 || strcmp(m, "sal") == 0) op = TNT_OP_SHL;
        else if (strcmp(m, "shr") == 0 || strcmp(m, "sar") == 0) op = TNT_OP_SHR;
        else if (strcmp(m, "imul") == 0) op = TNT_OP_MUL;
        if (op != 0) {
            if (op == TNT_OP_MUL && nops == 3) {
                tnt_expr sv = tnt_sym_eval_x86_op(st, ops[1]);
                tnt_expr iv = tnt_sym_eval_x86_op(st, ops[2]);
                st->regs[r0] = (iv.kind == TNT_E_CONST) ? tnt_expr_apply(sv, TNT_OP_MUL, iv.val) : tnt_e_unk();
            } else {
                tnt_expr rv = tnt_sym_eval_x86_op(st, ops[1]);
                if (rv.kind == TNT_E_CONST) st->regs[r0] = tnt_expr_apply(st->regs[r0], op, rv.val);
                else if (st->regs[r0].kind == TNT_E_CONST && rv.kind == TNT_E_SYM &&
                         (op == TNT_OP_ADD || op == TNT_OP_XOR || op == TNT_OP_AND || op == TNT_OP_OR || op == TNT_OP_MUL)) {
                    st->regs[r0] = tnt_expr_apply(rv, op, st->regs[r0].val);
                } else {
                    st->regs[r0] = tnt_e_unk();
                }
            }
            st->cmp.valid = 1;
            st->cmp.lhs = st->regs[r0];
            st->cmp.rhs = tnt_e_const(0);
            return;
        }
    }
    if (ins->flow == X86_FLOW_CALL) {
        st->regs[0] = tnt_e_unk();
    }
}

static tnt_expr tnt_sym_eval_a64_op(const tnt_sym_st *st, const char *op) {
    int b = 64;
    int r = tnt_a64_reg(op, &b);
    if (r == -2) return tnt_e_const(0);
    if (r >= 0) return st->regs[r];
    uint64_t imm = 0;
    if (tnt_parse_imm(op, &imm)) return tnt_e_const(imm);
    return tnt_e_unk();
}

static void tnt_sym_step_a64(tnt_sym_st *st, const x86_ins *ins) {
    const char *m = ins->mnem;
    char ops[4][76];
    int nops = tnt_split_ops(ins->ops, ops);
    int b0 = 64, b1 = 64, b2 = 64;
    int r0 = (nops >= 1) ? tnt_a64_reg(ops[0], &b0) : -1;
    int r1 = (nops >= 2) ? tnt_a64_reg(ops[1], &b1) : -1;
    int r2 = (nops >= 3) ? tnt_a64_reg(ops[2], &b2) : -1;

    if ((strcmp(m, "mov") == 0 || strcmp(m, "movz") == 0) && nops >= 2 && r0 >= 0) {
        st->regs[r0] = tnt_sym_eval_a64_op(st, ops[1]);
        return;
    }
    if ((strcmp(m, "str") == 0 || strcmp(m, "strb") == 0 || strcmp(m, "strh") == 0) && nops >= 2) {
        int64_t soff = 0;
        if (tnt_sym_stack_off(ops[1], 1, st->sp_off, &soff)) {
            tnt_sym_slot_set(st, soff, tnt_sym_eval_a64_op(st, ops[0]));
        }
        return;
    }
    if ((strcmp(m, "ldr") == 0 || strcmp(m, "ldrb") == 0 || strcmp(m, "ldrh") == 0) && nops >= 2 && r0 >= 0) {
        int64_t soff = 0;
        if (tnt_sym_stack_off(ops[1], 1, st->sp_off, &soff)) {
            st->regs[r0] = tnt_sym_slot_get(st, soff);
        } else {
            st->regs[r0] = tnt_e_unk();
        }
        return;
    }
    if (strcmp(m, "cmp") == 0 && nops >= 2) {
        st->cmp.valid = 1;
        st->cmp.lhs = tnt_sym_eval_a64_op(st, ops[0]);
        st->cmp.rhs = tnt_sym_eval_a64_op(st, ops[1]);
        return;
    }
    if (strcmp(m, "tst") == 0 && nops >= 2) {
        tnt_expr lv = tnt_sym_eval_a64_op(st, ops[0]);
        tnt_expr rv = tnt_sym_eval_a64_op(st, ops[1]);
        st->cmp.valid = 1;
        if (r0 >= 0 && r0 == r1) st->cmp.lhs = lv;
        else if (rv.kind == TNT_E_CONST) st->cmp.lhs = tnt_expr_apply(lv, TNT_OP_AND, rv.val);
        else st->cmp.lhs = lv;
        st->cmp.rhs = tnt_e_const(0);
        return;
    }
    if (nops >= 3 && r0 == 31 && (strcmp(m, "add") == 0 || strcmp(m, "sub") == 0)) {
        uint64_t imm = 0;
        if (tnt_parse_imm(ops[2], &imm)) {
            st->sp_off += (strcmp(m, "add") == 0) ? (int64_t)imm : -(int64_t)imm;
        }
        return;
    }
    if (nops >= 3 && r0 >= 0) {
        uint8_t op = 0;
        if (strcmp(m, "add") == 0 || strcmp(m, "adds") == 0) op = TNT_OP_ADD;
        else if (strcmp(m, "sub") == 0 || strcmp(m, "subs") == 0) op = TNT_OP_SUB;
        else if (strcmp(m, "eor") == 0) op = TNT_OP_XOR;
        else if (strcmp(m, "and") == 0 || strcmp(m, "ands") == 0) op = TNT_OP_AND;
        else if (strcmp(m, "orr") == 0) op = TNT_OP_OR;
        else if (strcmp(m, "lsl") == 0) op = TNT_OP_SHL;
        else if (strcmp(m, "lsr") == 0 || strcmp(m, "asr") == 0) op = TNT_OP_SHR;
        else if (strcmp(m, "mul") == 0) op = TNT_OP_MUL;
        if (op != 0) {
            if ((op == TNT_OP_XOR || op == TNT_OP_SUB) && r1 >= 0 && r1 == r2) {
                st->regs[r0] = tnt_e_const(0);
            } else {
                tnt_expr lv = tnt_sym_eval_a64_op(st, ops[1]);
                tnt_expr rv = tnt_sym_eval_a64_op(st, ops[2]);
                if (rv.kind == TNT_E_CONST) st->regs[r0] = tnt_expr_apply(lv, op, rv.val);
                else if (lv.kind == TNT_E_CONST && rv.kind == TNT_E_SYM &&
                         (op == TNT_OP_ADD || op == TNT_OP_XOR || op == TNT_OP_AND || op == TNT_OP_OR || op == TNT_OP_MUL)) {
                    st->regs[r0] = tnt_expr_apply(rv, op, lv.val);
                } else {
                    st->regs[r0] = tnt_e_unk();
                }
            }
            if (strcmp(m, "adds") == 0 || strcmp(m, "subs") == 0 || strcmp(m, "ands") == 0) {
                st->cmp.valid = 1;
                st->cmp.lhs = st->regs[r0];
                st->cmp.rhs = tnt_e_const(0);
            }
        }
    }
}

static int tnt_cc_to_rel(const char *cc, int is_a64, int *is_signed) {
    *is_signed = 0;
    if (!is_a64) {
        if (strcmp(cc, "e") == 0 || strcmp(cc, "z") == 0) return TNT_REL_EQ;
        if (strcmp(cc, "ne") == 0 || strcmp(cc, "nz") == 0) return TNT_REL_NE;
        if (strcmp(cc, "b") == 0 || strcmp(cc, "c") == 0 || strcmp(cc, "nae") == 0) return TNT_REL_LT;
        if (strcmp(cc, "be") == 0 || strcmp(cc, "na") == 0) return TNT_REL_LE;
        if (strcmp(cc, "a") == 0 || strcmp(cc, "nbe") == 0) return TNT_REL_GT;
        if (strcmp(cc, "ae") == 0 || strcmp(cc, "nb") == 0 || strcmp(cc, "nc") == 0) return TNT_REL_GE;
        if (strcmp(cc, "l") == 0 || strcmp(cc, "nge") == 0 || strcmp(cc, "s") == 0) { *is_signed = 1; return TNT_REL_LT; }
        if (strcmp(cc, "le") == 0 || strcmp(cc, "ng") == 0) { *is_signed = 1; return TNT_REL_LE; }
        if (strcmp(cc, "g") == 0 || strcmp(cc, "nle") == 0) { *is_signed = 1; return TNT_REL_GT; }
        if (strcmp(cc, "ge") == 0 || strcmp(cc, "nl") == 0 || strcmp(cc, "ns") == 0) { *is_signed = 1; return TNT_REL_GE; }
        return TNT_REL_NONE;
    }
    if (strcmp(cc, "eq") == 0) return TNT_REL_EQ;
    if (strcmp(cc, "ne") == 0) return TNT_REL_NE;
    if (strcmp(cc, "cc") == 0 || strcmp(cc, "lo") == 0) return TNT_REL_LT;
    if (strcmp(cc, "ls") == 0) return TNT_REL_LE;
    if (strcmp(cc, "hi") == 0) return TNT_REL_GT;
    if (strcmp(cc, "cs") == 0 || strcmp(cc, "hs") == 0) return TNT_REL_GE;
    if (strcmp(cc, "lt") == 0 || strcmp(cc, "mi") == 0) { *is_signed = 1; return TNT_REL_LT; }
    if (strcmp(cc, "le") == 0) { *is_signed = 1; return TNT_REL_LE; }
    if (strcmp(cc, "gt") == 0) { *is_signed = 1; return TNT_REL_GT; }
    if (strcmp(cc, "ge") == 0 || strcmp(cc, "pl") == 0) { *is_signed = 1; return TNT_REL_GE; }
    return TNT_REL_NONE;
}

static int tnt_inv_rel(int rel) {
    switch (rel) {
    case TNT_REL_EQ: return TNT_REL_NE;
    case TNT_REL_NE: return TNT_REL_EQ;
    case TNT_REL_LT: return TNT_REL_GE;
    case TNT_REL_GE: return TNT_REL_LT;
    case TNT_REL_LE: return TNT_REL_GT;
    case TNT_REL_GT: return TNT_REL_LE;
    default: return TNT_REL_NONE;
    }
}

static int tnt_flip_rel(int rel) {
    switch (rel) {
    case TNT_REL_LT: return TNT_REL_GT;
    case TNT_REL_GT: return TNT_REL_LT;
    case TNT_REL_LE: return TNT_REL_GE;
    case TNT_REL_GE: return TNT_REL_LE;
    default: return rel;
    }
}

static const char *tnt_rel_str(int rel) {
    switch (rel) {
    case TNT_REL_EQ: return "==";
    case TNT_REL_NE: return "!=";
    case TNT_REL_LT: return "<";
    case TNT_REL_LE: return "<=";
    case TNT_REL_GT: return ">";
    case TNT_REL_GE: return ">=";
    default: return "?";
    }
}

static void tnt_emit_branch_cons(const tnt_sym_st *st, const x86_ins *ins, uint8_t edge_kind,
                                 tnt_pcons *cons, int *ncons, tnt_solve_res *out) {
    if (ins->flow != X86_FLOW_JCC || *ncons >= 32) return;
    const char *m = ins->mnem;
    char ops[4][76];
    int nops = tnt_split_ops(ins->ops, ops);

    tnt_expr lhs = tnt_e_unk();
    tnt_expr rhs = tnt_e_const(0);
    int rel = TNT_REL_NONE;
    int is_signed = 0;

    if (st->is_a64 && (strcmp(m, "cbz") == 0 || strcmp(m, "cbnz") == 0) && nops >= 1) {
        lhs = tnt_sym_eval_a64_op(st, ops[0]);
        rhs = tnt_e_const(0);
        rel = (strcmp(m, "cbz") == 0) ? TNT_REL_EQ : TNT_REL_NE;
    } else if (st->is_a64 && (strcmp(m, "tbz") == 0 || strcmp(m, "tbnz") == 0) && nops >= 2) {
        uint64_t bit = 0;
        tnt_parse_imm(ops[1], &bit);
        lhs = tnt_expr_apply(tnt_sym_eval_a64_op(st, ops[0]), TNT_OP_AND, 1ULL << (bit & 63ULL));
        rhs = tnt_e_const(0);
        rel = (strcmp(m, "tbz") == 0) ? TNT_REL_EQ : TNT_REL_NE;
    } else if (!st->is_a64 && (strcmp(m, "jrcxz") == 0 || strcmp(m, "jecxz") == 0)) {
        lhs = st->regs[1];
        rhs = tnt_e_const(0);
        rel = TNT_REL_EQ;
    } else if (st->cmp.valid) {
        lhs = st->cmp.lhs;
        rhs = st->cmp.rhs;
        if (st->is_a64 && strncmp(m, "b.", 2) == 0) rel = tnt_cc_to_rel(m + 2, 1, &is_signed);
        else if (!st->is_a64 && m[0] == 'j') rel = tnt_cc_to_rel(m + 1, 0, &is_signed);
    }

    if (rel == TNT_REL_NONE) return;
    if (edge_kind == GRP_EDGE_FALSE) rel = tnt_inv_rel(rel);

    if (lhs.kind == TNT_E_CONST && rhs.kind == TNT_E_SYM) {
        tnt_expr tmp = lhs;
        lhs = rhs;
        rhs = tmp;
        rel = tnt_flip_rel(rel);
    }
    if (lhs.kind == TNT_E_UNK && rhs.kind == TNT_E_UNK) return;

    char ls[48], rs[48];
    tnt_expr_fmt(&lhs, ls, sizeof(ls));
    tnt_expr_fmt(&rhs, rs, sizeof(rs));

    tnt_pcons *pc = &cons[*ncons];
    pc->lhs = lhs;
    pc->rhs = rhs;
    pc->rel = rel;
    pc->is_signed = is_signed;
    snprintf(pc->text, sizeof(pc->text), "%s %s %s", ls, tnt_rel_str(rel), rs);
    snprintf(out->constraints[*ncons], sizeof(out->constraints[0]), "%s", pc->text);
    (*ncons)++;
    out->ncons = *ncons;
}

static bool tnt_eval_expr_concrete(const tnt_expr *e, uint64_t x, uint64_t *res) {
    if (e->kind != TNT_E_SYM) return false;
    switch (e->op) {
    case TNT_OP_ID:  *res = x; return true;
    case TNT_OP_ADD: *res = x + e->val; return true;
    case TNT_OP_SUB: *res = x - e->val; return true;
    case TNT_OP_XOR: *res = x ^ e->val; return true;
    case TNT_OP_AND: *res = x & e->val; return true;
    case TNT_OP_OR:  *res = x | e->val; return true;
    case TNT_OP_SHL: *res = x << (e->val & 63ULL); return true;
    case TNT_OP_SHR: *res = x >> (e->val & 63ULL); return true;
    case TNT_OP_MUL: *res = x * e->val; return true;
    default: return false;
    }
}

static bool tnt_check_rel(uint64_t a, uint64_t b, int rel, int is_signed) {
    if (rel == TNT_REL_EQ) return a == b;
    if (rel == TNT_REL_NE) return a != b;
    if (is_signed) {
        int64_t sa = (int64_t)a, sb = (int64_t)b;
        if (rel == TNT_REL_LT) return sa < sb;
        if (rel == TNT_REL_LE) return sa <= sb;
        if (rel == TNT_REL_GT) return sa > sb;
        if (rel == TNT_REL_GE) return sa >= sb;
    } else {
        if (rel == TNT_REL_LT) return a < b;
        if (rel == TNT_REL_LE) return a <= b;
        if (rel == TNT_REL_GT) return a > b;
        if (rel == TNT_REL_GE) return a >= b;
    }
    return false;
}

static bool tnt_solve_single(const tnt_pcons *c, uint64_t *sol) {
    if (c->lhs.kind != TNT_E_SYM || c->rhs.kind != TNT_E_CONST) return false;
    uint64_t rhs = c->rhs.val;
    uint64_t target = rhs;

    if (c->rel == TNT_REL_EQ) target = rhs;
    else if (c->rel == TNT_REL_NE) target = (rhs == 0) ? 1ULL : (rhs + 1ULL);
    else if (c->rel == TNT_REL_GT) target = rhs + 1ULL;
    else if (c->rel == TNT_REL_GE) target = rhs;
    else if (c->rel == TNT_REL_LT) target = (rhs > 0 || c->is_signed) ? (rhs - 1ULL) : 0ULL;
    else if (c->rel == TNT_REL_LE) target = rhs;
    else return false;

    uint64_t k = c->lhs.val;
    switch (c->lhs.op) {
    case TNT_OP_ID:  *sol = target; return true;
    case TNT_OP_ADD: *sol = target - k; return true;
    case TNT_OP_SUB: *sol = target + k; return true;
    case TNT_OP_XOR: *sol = target ^ k; return true;
    case TNT_OP_AND:
        if (c->rel == TNT_REL_NE && rhs == 0) { *sol = k; return k != 0; }
        if ((target & ~k) != 0) return false;
        *sol = target;
        return true;
    case TNT_OP_OR:
        if ((target & k) != k) return false;
        *sol = target;
        return true;
    case TNT_OP_SHL:
        if (k >= 64) return false;
        *sol = target >> k;
        return ((*sol << k) == target);
    case TNT_OP_SHR:
        if (k >= 64) return false;
        *sol = target << k;
        return ((*sol >> k) == target);
    case TNT_OP_MUL:
        if (k == 0 || (target % k) != 0) return false;
        *sol = target / k;
        return true;
    default:
        return false;
    }
}

static bool tnt_witness_ok(const tnt_pcons *cons, int ncons, uint8_t var, uint64_t cand) {
    for (int i = 0; i < ncons; i++) {
        if (cons[i].lhs.kind != TNT_E_SYM || cons[i].lhs.var != var || cons[i].rhs.kind != TNT_E_CONST) continue;
        uint64_t ev = 0;
        if (!tnt_eval_expr_concrete(&cons[i].lhs, cand, &ev)) continue;
        if (!tnt_check_rel(ev, cons[i].rhs.val, cons[i].rel, cons[i].is_signed)) return false;
    }
    return true;
}

static void tnt_solve_witnesses(const tnt_pcons *cons, int ncons, tnt_solve_res *out) {
    for (uint8_t v = 0; v < 4 && out->nwitness < 16; v++) {
        int has_var = 0;
        int best_idx = -1;
        uint64_t best_val = 0;
        int has_sol = 0;

        // prefer exact equality constraints first, then verify against all constraints on v
        for (int pass = 0; pass < 2 && !has_sol; pass++) {
            for (int i = 0; i < ncons; i++) {
                if (cons[i].lhs.kind != TNT_E_SYM || cons[i].lhs.var != v || cons[i].rhs.kind != TNT_E_CONST) continue;
                has_var = 1;
                if (pass == 0 && cons[i].rel != TNT_REL_EQ) continue;
                uint64_t cand = 0;
                if (tnt_solve_single(&cons[i], &cand) && tnt_witness_ok(cons, ncons, v, cand)) {
                    best_val = cand;
                    best_idx = i;
                    has_sol = 1;
                    break;
                }
            }
        }
        if (has_var && !has_sol) {
            for (int i = 0; i < ncons; i++) {
                if (cons[i].lhs.kind != TNT_E_SYM || cons[i].lhs.var != v || cons[i].rhs.kind != TNT_E_CONST) continue;
                uint64_t cand = 0;
                if (tnt_solve_single(&cons[i], &cand)) {
                    best_val = cand;
                    best_idx = i;
                    has_sol = 1;
                    break;
                }
            }
        }
        if (has_sol && best_idx >= 0) {
            tnt_bind *wb = &out->witness[out->nwitness++];
            snprintf(wb->var, sizeof(wb->var), "a%u", (unsigned)v + 1u);
            wb->val = best_val;
            snprintf(wb->expr, sizeof(wb->expr), "%s", cons[best_idx].text);
        }
    }
}

static int tnt_find_blk_for_va(const grp_cfg *g, uint64_t va) {
    for (uint32_t i = 0; i < g->nblk; i++) {
        if (va >= g->blks[i].start && va < g->blks[i].end) return (int)i;
    }
    return -1;
}

bool tnt_solve_path(const ana_ctx *a, uint64_t start_va, uint64_t target_va, tnt_solve_res *out) {
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    if (!a || !bin_is_exec(&a->bin, start_va)) {
        snprintf(out->summary, sizeof(out->summary), "invalid start address");
        return false;
    }

    grp_cfg g;
    memset(&g, 0, sizeof(g));
    if (!grp_build(a, start_va, 0, &g)) {
        snprintf(out->summary, sizeof(out->summary), "failed to build CFG");
        return false;
    }

    int b_start = tnt_find_blk_for_va(&g, start_va);
    if (b_start < 0) b_start = 0;
    int b_target = tnt_find_blk_for_va(&g, target_va);
    if (b_target < 0) {
        out->reachable = 0;
        snprintf(out->summary, sizeof(out->summary), "target not in function CFG");
        grp_free(&g);
        return true;
    }

    int q[TNT_MAX_CFG_BLKS];
    int parent[TNT_MAX_CFG_BLKS];
    uint8_t pedge[TNT_MAX_CFG_BLKS];
    uint8_t vis[TNT_MAX_CFG_BLKS];
    int depth[TNT_MAX_CFG_BLKS];
    memset(vis, 0, sizeof(vis));
    memset(pedge, 0, sizeof(pedge));
    for (int i = 0; i < TNT_MAX_CFG_BLKS; i++) { parent[i] = -1; depth[i] = 0; }

    int qh = 0, qt = 0;
    if (b_start < TNT_MAX_CFG_BLKS) {
        vis[b_start] = 1;
        q[qt++] = b_start;
    }
    while (qh < qt) {
        int u = q[qh++];
        if (u == b_target) break;
        if (depth[u] + 1 >= TNT_MAX_PATH) continue;
        for (uint32_t e = 0; e < g.nedge; e++) {
            if ((int)g.edges[e].from != u) continue;
            int v = (int)g.edges[e].to;
            if (v < 0 || v >= TNT_MAX_CFG_BLKS || vis[v]) continue;
            vis[v] = 1;
            parent[v] = u;
            pedge[v] = g.edges[e].kind;
            depth[v] = depth[u] + 1;
            if (qt < TNT_MAX_CFG_BLKS) q[qt++] = v;
        }
    }

    if (b_target >= TNT_MAX_CFG_BLKS || !vis[b_target]) {
        out->reachable = 0;
        snprintf(out->summary, sizeof(out->summary), "no path in CFG");
        grp_free(&g);
        return true;
    }

    int rev_blk[TNT_MAX_PATH];
    uint8_t rev_edge[TNT_MAX_PATH];
    int len = 0;
    for (int cur = b_target; cur >= 0 && len < TNT_MAX_PATH; cur = parent[cur]) {
        rev_blk[len] = cur;
        rev_edge[len] = pedge[cur];
        len++;
        if (cur == b_start) break;
    }

    int blk_seq[TNT_MAX_PATH];
    uint8_t edge_seq[TNT_MAX_PATH];
    for (int i = 0; i < len; i++) {
        blk_seq[i] = rev_blk[len - 1 - i];
        out->path[i] = g.blks[blk_seq[i]].start;
    }
    for (int i = 0; i + 1 < len; i++) {
        edge_seq[i] = rev_edge[len - 2 - i];
    }
    out->reachable = 1;
    out->npath = len;

    tnt_sym_st st;
    memset(&st, 0, sizeof(st));
    st.is_a64 = (a->bin.arch == BIN_ARCH_ARM64);
    int ar[4];
    tnt_arg_regs(a, ar);
    for (uint8_t i = 0; i < 4; i++) st.regs[ar[i]] = tnt_e_sym(i);

    tnt_pcons cons[32];
    int ncons = 0;

    for (int i = 0; i + 1 < len; i++) {
        const grp_blk *b = &g.blks[blk_seq[i]];
        for (uint32_t k = 0; k < b->ins_count; k++) {
            const x86_ins *ins = &g.ins[b->ins_first + k];
            if (i == 0 && ins->ip < start_va) continue;
            if (k + 1 == b->ins_count && ins->flow == X86_FLOW_JCC) {
                tnt_emit_branch_cons(&st, ins, edge_seq[i], cons, &ncons, out);
            } else if (st.is_a64) {
                tnt_sym_step_a64(&st, ins);
            } else {
                tnt_sym_step_x86(&st, ins);
            }
        }
    }

    tnt_solve_witnesses(cons, ncons, out);

    int w = snprintf(out->summary, sizeof(out->summary),
                     "Reachable in %d %s, %d %s",
                     out->npath, out->npath == 1 ? "block" : "blocks",
                     out->ncons, out->ncons == 1 ? "constraint" : "constraints");
    size_t pos = (w > 0) ? (size_t)w : 0;
    if (out->nwitness > 0 && pos + 4 < sizeof(out->summary)) {
        w = snprintf(out->summary + pos, sizeof(out->summary) - pos, " -> ");
        if (w > 0) pos += (size_t)w;
        for (int i = 0; i < out->nwitness && pos + 4 < sizeof(out->summary); i++) {
            w = snprintf(out->summary + pos, sizeof(out->summary) - pos, "%s%s=0x%llx",
                         i ? ", " : "", out->witness[i].var, (unsigned long long)out->witness[i].val);
            if (w <= 0) break;
            pos += (size_t)w;
        }
    }

    grp_free(&g);
    return true;
}
