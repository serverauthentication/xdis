#pragma once

#include <stddef.h>
#include <stdint.h>

typedef enum {
    X86_FLOW_NONE = 0,
    X86_FLOW_JMP,
    X86_FLOW_JCC,
    X86_FLOW_CALL,
    X86_FLOW_RET,
    X86_FLOW_TRAP
} x86_flow;

typedef struct {
    uint64_t ip;
    uint64_t target;
    uint8_t  len;
    uint8_t  flow;
    uint8_t  has_target;
    uint8_t  target_mem;
    char     mnem[20];
    char     ops[76];
} x86_ins;

int x86_decode(const uint8_t *code, size_t avail, uint64_t ip, int bits, int want_text, int upper, x86_ins *out);
