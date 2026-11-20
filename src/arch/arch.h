#pragma once

#include "x86.h"
#include "../bin/bin.h"

int a64_decode(const uint8_t *code, size_t avail, uint64_t ip, int want_text, int upper, x86_ins *out);
int arm32_decode(const uint8_t *code, size_t avail, uint64_t ip, int want_text, int upper, x86_ins *out);
int thumb_decode(const uint8_t *code, size_t avail, uint64_t ip, int want_text, int upper, x86_ins *out);
int rv_decode(const uint8_t *code, size_t avail, uint64_t ip, int bits, int want_text, int upper, x86_ins *out);
int mips_decode(const uint8_t *code, size_t avail, uint64_t ip, int want_text, int upper, x86_ins *out);
int wasm_decode(const uint8_t *code, size_t avail, uint64_t ip, int want_text, int upper, x86_ins *out);
int cil_decode(const uint8_t *code, size_t avail, uint64_t ip, int want_text, int upper, x86_ins *out);
int asm_encode(const char *text, uint64_t ip, int bits, uint8_t out[16]);

static inline int arch_decode(bin_arch arch, const uint8_t *code, size_t avail, uint64_t ip, int want_text, int upper, x86_ins *out) {
    switch (arch) {
    case BIN_ARCH_ARM64:   return a64_decode(code, avail, ip, want_text, upper, out);
    case BIN_ARCH_ARM32:   return arm32_decode(code, avail, ip, want_text, upper, out);
    case BIN_ARCH_RISCV64: return rv_decode(code, avail, ip, 64, want_text, upper, out);
    case BIN_ARCH_RISCV32: return rv_decode(code, avail, ip, 32, want_text, upper, out);
    case BIN_ARCH_MIPS32:  return mips_decode(code, avail, ip, want_text, upper, out);
    case BIN_ARCH_WASM:    return wasm_decode(code, avail, ip, want_text, upper, out);
    case BIN_ARCH_CIL:     return cil_decode(code, avail, ip, want_text, upper, out);
    default:               return x86_decode(code, avail, ip, arch == BIN_ARCH_X86 ? 32 : 64, want_text, upper, out);
    }
}
