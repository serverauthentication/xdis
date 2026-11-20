#include "ana.h"

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SSA_MAX_BLKS 256
#define SSA_MAX_REGS 32

enum {
    SSA_OP_NOP = 0,
    SSA_OP_MOV,
    SSA_OP_LOAD,
    SSA_OP_STORE,
    SSA_OP_LEA,
    SSA_OP_ADD,
    SSA_OP_SUB,
    SSA_OP_MUL,
    SSA_OP_DIV,
    SSA_OP_SHL,
    SSA_OP_SHR,
    SSA_OP_SAR,
    SSA_OP_ROL,
    SSA_OP_ROR,
    SSA_OP_AND,
    SSA_OP_OR,
    SSA_OP_XOR,
    SSA_OP_NOT,
    SSA_OP_NEG,
    SSA_OP_ZEXT,
    SSA_OP_SEXT,
    SSA_OP_CMP,
    SSA_OP_JCC,
    SSA_OP_JMP,
    SSA_OP_CALL,
    SSA_OP_RET,
    SSA_OP_FADD,
    SSA_OP_FSUB,
    SSA_OP_FMUL,
    SSA_OP_FDIV,
    SSA_OP_PHI,
    SSA_OP_SEL
};

enum {
    SSA_ARG_NONE = 0,
    SSA_ARG_REG,
    SSA_ARG_IMM,
    SSA_ARG_MEM,
    SSA_ARG_VA
};

enum {
    SSA_LAT_TOP = 0,
    SSA_LAT_CONST,
    SSA_LAT_BOT
};

enum {
    SSA_TY_UNK = 0,
    SSA_TY_I8,
    SSA_TY_U8,
    SSA_TY_I16,
    SSA_TY_U16,
    SSA_TY_I32,
    SSA_TY_U32,
    SSA_TY_I64,
    SSA_TY_U64,
    SSA_TY_SIZE_T,
    SSA_TY_BOOL,
    SSA_TY_FLOAT,
    SSA_TY_DOUBLE,
    SSA_TY_PTR,
    SSA_TY_STRUCT,
    SSA_TY_CSTR,
    SSA_TY_WSTR,
    SSA_TY_HANDLE,
    SSA_TY_HMODULE,
    SSA_TY_FARPROC,
    SSA_TY_HWND,
    SSA_TY_HKEY,
    SSA_TY_SOCKET,
    SSA_TY_FILE,
    SSA_TY_VOID
};

typedef struct {
    uint8_t  kind;
    int8_t   reg;
    int8_t   idx;
    uint8_t  scale;
    uint16_t bits;
    uint8_t  is_flt;
    uint8_t  folded;
    int64_t  disp;
    uint64_t imm;
    uint64_t fval;
    int      ver;
    int      idx_ver;
} ssa_arg;

typedef struct {
    uint16_t blk;
    int      ver;
} ssa_phi_in;

typedef struct {
    uint64_t va;
    uint16_t blk;
    uint16_t bits;
    uint8_t  op;
    uint8_t  src_bits;
    uint8_t  is_flt;
    uint8_t  is_phi;
    uint8_t  is_dead;
    uint8_t  is_signed;
    uint8_t  is_test;
    uint8_t  is_mulhi;
    uint8_t  call_narg;
    int8_t   dst_reg;
    int      dst_ver;
    ssa_arg  a0;
    ssa_arg  a1;
    ssa_arg  a2;
    int8_t   call_regs[8];
    int      call_vers[8];
    uint32_t phi_first;
    uint32_t phi_count;
    char     cc[8];
    char     sym[56];
} ssa_ir;

typedef struct {
    int8_t   reg;
    uint16_t bits;
    uint8_t  is_flt;
    uint8_t  is_arg;
    uint8_t  lat;
    uint8_t  ty;
    uint8_t  deref_cnt;
    uint8_t  deref_nz;
    int      idx;
    int      def_ins;
    int      alias;
    int      use_cnt;
    uint64_t cval;
} ssa_ver;

typedef struct {
    uint8_t  op;
    uint16_t bits;
    uint8_t  flags;
    uint8_t  k0_kind;
    uint8_t  k1_kind;
    int      k0_ver;
    int      k1_ver;
    uint64_t k0_imm;
    uint64_t k1_imm;
    int      idx_ver;
    uint8_t  scale;
    int      dst_ver;
} ssa_gvn_ent;

typedef struct {
    const char *name;
    uint8_t     ret_ty;
    uint8_t     narg;
    uint8_t     arg_ty[6];
} ssa_api_sig;

typedef struct {
    const ana_ctx *a;
    const grp_cfg *g;
    uint32_t       nblk;
    int            is_arm64;
    int            is_x86;
    int            ptr_bits;
    int            sp_reg;
    int            ret_reg;
    int            arg_regs[8];
    int            narg_abi;

    uint64_t       pred_bs[SSA_MAX_BLKS][4];
    uint64_t       succ_bs[SSA_MAX_BLKS][4];
    uint64_t       dom_bs[SSA_MAX_BLKS][4];
    uint64_t       df_bs[SSA_MAX_BLKS][4];
    uint8_t        reach[SSA_MAX_BLKS];
    int            idom[SSA_MAX_BLKS];
    int            dom_head[SSA_MAX_BLKS];
    int            dom_next[SSA_MAX_BLKS];

    ssa_ir        *llir;
    uint32_t       nllir;
    uint32_t       llir_cap;
    uint32_t       llir_first[SSA_MAX_BLKS];
    uint32_t       llir_count[SSA_MAX_BLKS];

    ssa_ir        *mlir;
    uint32_t       nmlir;
    uint32_t       mlir_cap;
    uint32_t       mlir_first[SSA_MAX_BLKS];
    uint32_t       mlir_count[SSA_MAX_BLKS];

    ssa_phi_in    *phi_pool;
    uint32_t       nphi_pool;
    uint32_t       phi_cap;

    ssa_ver       *vers;
    int            nver;
    int            ver_cap;
    int            entry_ver[SSA_MAX_REGS];
    int            reg_ver_cnt[SSA_MAX_REGS];

    int           *rstack[SSA_MAX_REGS];
    int            rstack_len[SSA_MAX_REGS];
    int            rstack_cap[SSA_MAX_REGS];
    int8_t        *push_log;
    int            push_len;
    int            push_cap;

    uint32_t       def_mask[SSA_MAX_BLKS];
    uint32_t       use_mask[SSA_MAX_BLKS];
    uint32_t       live_in[SSA_MAX_BLKS];
    uint32_t       live_out[SSA_MAX_BLKS];
    uint32_t       phi_mask[SSA_MAX_BLKS];

    ssa_gvn_ent   *gvn;
    int            gvn_len;
    int            gvn_cap;

    int            nphi;
    int            nsccp;
    int            ngvn;
    int            ndce;
} ssa_ctx;

static const char *const ssa_x64_regs[16] = {
    "rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi",
    "r8","r9","r10","r11","r12","r13","r14","r15"
};

static const char *const ssa_x86_regs[16] = {
    "eax","ecx","edx","ebx","esp","ebp","esi","edi",
    "r8d","r9d","r10d","r11d","r12d","r13d","r14d","r15d"
};

static const char *const ssa_a64_regs[32] = {
    "x0","x1","x2","x3","x4","x5","x6","x7",
    "x8","x9","x10","x11","x12","x13","x14","x15",
    "x16","x17","x18","x19","x20","x21","x22","x23",
    "x24","x25","x26","x27","x28","fp","lr","sp"
};

static const ssa_api_sig ssa_apis[] = {
    {"CreateFileA",          SSA_TY_HANDLE,  6, {SSA_TY_CSTR, SSA_TY_U32, SSA_TY_U32, SSA_TY_PTR, SSA_TY_U32, SSA_TY_U32}},
    {"CreateFileW",          SSA_TY_HANDLE,  6, {SSA_TY_WSTR, SSA_TY_U32, SSA_TY_U32, SSA_TY_PTR, SSA_TY_U32, SSA_TY_U32}},
    {"ReadFile",             SSA_TY_BOOL,    5, {SSA_TY_HANDLE, SSA_TY_PTR, SSA_TY_U32, SSA_TY_PTR, SSA_TY_PTR, 0}},
    {"WriteFile",            SSA_TY_BOOL,    5, {SSA_TY_HANDLE, SSA_TY_PTR, SSA_TY_U32, SSA_TY_PTR, SSA_TY_PTR, 0}},
    {"GetFileSizeEx",        SSA_TY_BOOL,    2, {SSA_TY_HANDLE, SSA_TY_PTR, 0, 0, 0, 0}},
    {"GetFileSize",          SSA_TY_U32,     2, {SSA_TY_HANDLE, SSA_TY_PTR, 0, 0, 0, 0}},
    {"SetFilePointer",       SSA_TY_U32,     4, {SSA_TY_HANDLE, SSA_TY_I32, SSA_TY_PTR, SSA_TY_U32, 0, 0}},
    {"SetFilePointerEx",     SSA_TY_BOOL,    4, {SSA_TY_HANDLE, SSA_TY_I64, SSA_TY_PTR, SSA_TY_U32, 0, 0}},
    {"CloseHandle",          SSA_TY_BOOL,    1, {SSA_TY_HANDLE, 0, 0, 0, 0, 0}},
    {"CreateFileMappingA",   SSA_TY_HANDLE,  6, {SSA_TY_HANDLE, SSA_TY_PTR, SSA_TY_U32, SSA_TY_U32, SSA_TY_U32, SSA_TY_CSTR}},
    {"CreateFileMappingW",   SSA_TY_HANDLE,  6, {SSA_TY_HANDLE, SSA_TY_PTR, SSA_TY_U32, SSA_TY_U32, SSA_TY_U32, SSA_TY_WSTR}},
    {"MapViewOfFile",        SSA_TY_PTR,     5, {SSA_TY_HANDLE, SSA_TY_U32, SSA_TY_U32, SSA_TY_U32, SSA_TY_SIZE_T, 0}},
    {"UnmapViewOfFile",      SSA_TY_BOOL,    1, {SSA_TY_PTR, 0, 0, 0, 0, 0}},
    {"FindFirstFileA",       SSA_TY_HANDLE,  2, {SSA_TY_CSTR, SSA_TY_PTR, 0, 0, 0, 0}},
    {"FindFirstFileW",       SSA_TY_HANDLE,  2, {SSA_TY_WSTR, SSA_TY_PTR, 0, 0, 0, 0}},
    {"FindNextFileA",        SSA_TY_BOOL,    2, {SSA_TY_HANDLE, SSA_TY_PTR, 0, 0, 0, 0}},
    {"FindNextFileW",        SSA_TY_BOOL,    2, {SSA_TY_HANDLE, SSA_TY_PTR, 0, 0, 0, 0}},
    {"FindClose",            SSA_TY_BOOL,    1, {SSA_TY_HANDLE, 0, 0, 0, 0, 0}},
    {"DeleteFileA",          SSA_TY_BOOL,    1, {SSA_TY_CSTR, 0, 0, 0, 0, 0}},
    {"DeleteFileW",          SSA_TY_BOOL,    1, {SSA_TY_WSTR, 0, 0, 0, 0, 0}},
    {"VirtualAlloc",         SSA_TY_PTR,     4, {SSA_TY_PTR, SSA_TY_SIZE_T, SSA_TY_U32, SSA_TY_U32, 0, 0}},
    {"VirtualAllocEx",       SSA_TY_PTR,     5, {SSA_TY_HANDLE, SSA_TY_PTR, SSA_TY_SIZE_T, SSA_TY_U32, SSA_TY_U32, 0}},
    {"VirtualProtect",       SSA_TY_BOOL,    4, {SSA_TY_PTR, SSA_TY_SIZE_T, SSA_TY_U32, SSA_TY_PTR, 0, 0}},
    {"VirtualProtectEx",     SSA_TY_BOOL,    5, {SSA_TY_HANDLE, SSA_TY_PTR, SSA_TY_SIZE_T, SSA_TY_U32, SSA_TY_PTR, 0}},
    {"VirtualFree",          SSA_TY_BOOL,    3, {SSA_TY_PTR, SSA_TY_SIZE_T, SSA_TY_U32, 0, 0, 0}},
    {"HeapAlloc",            SSA_TY_PTR,     3, {SSA_TY_HANDLE, SSA_TY_U32, SSA_TY_SIZE_T, 0, 0, 0}},
    {"HeapReAlloc",          SSA_TY_PTR,     4, {SSA_TY_HANDLE, SSA_TY_U32, SSA_TY_PTR, SSA_TY_SIZE_T, 0, 0}},
    {"HeapFree",             SSA_TY_BOOL,    3, {SSA_TY_HANDLE, SSA_TY_U32, SSA_TY_PTR, 0, 0, 0}},
    {"GetProcessHeap",       SSA_TY_HANDLE,  0, {0, 0, 0, 0, 0, 0}},
    {"LoadLibraryA",         SSA_TY_HMODULE, 1, {SSA_TY_CSTR, 0, 0, 0, 0, 0}},
    {"LoadLibraryW",         SSA_TY_HMODULE, 1, {SSA_TY_WSTR, 0, 0, 0, 0, 0}},
    {"LoadLibraryExA",       SSA_TY_HMODULE, 3, {SSA_TY_CSTR, SSA_TY_HANDLE, SSA_TY_U32, 0, 0, 0}},
    {"LoadLibraryExW",       SSA_TY_HMODULE, 3, {SSA_TY_WSTR, SSA_TY_HANDLE, SSA_TY_U32, 0, 0, 0}},
    {"GetModuleHandleA",     SSA_TY_HMODULE, 1, {SSA_TY_CSTR, 0, 0, 0, 0, 0}},
    {"GetModuleHandleW",     SSA_TY_HMODULE, 1, {SSA_TY_WSTR, 0, 0, 0, 0, 0}},
    {"GetProcAddress",       SSA_TY_FARPROC, 2, {SSA_TY_HMODULE, SSA_TY_CSTR, 0, 0, 0, 0}},
    {"FreeLibrary",          SSA_TY_BOOL,    1, {SSA_TY_HMODULE, 0, 0, 0, 0, 0}},
    {"OpenProcess",          SSA_TY_HANDLE,  3, {SSA_TY_U32, SSA_TY_BOOL, SSA_TY_U32, 0, 0, 0}},
    {"CreateProcessA",       SSA_TY_BOOL,    6, {SSA_TY_CSTR, SSA_TY_PTR, SSA_TY_PTR, SSA_TY_PTR, SSA_TY_BOOL, SSA_TY_U32}},
    {"CreateProcessW",       SSA_TY_BOOL,    6, {SSA_TY_WSTR, SSA_TY_PTR, SSA_TY_PTR, SSA_TY_PTR, SSA_TY_BOOL, SSA_TY_U32}},
    {"CreateThread",         SSA_TY_HANDLE,  6, {SSA_TY_PTR, SSA_TY_SIZE_T, SSA_TY_PTR, SSA_TY_PTR, SSA_TY_U32, SSA_TY_PTR}},
    {"CreateRemoteThread",   SSA_TY_HANDLE,  6, {SSA_TY_HANDLE, SSA_TY_PTR, SSA_TY_SIZE_T, SSA_TY_PTR, SSA_TY_PTR, SSA_TY_U32}},
    {"WaitForSingleObject",  SSA_TY_U32,     2, {SSA_TY_HANDLE, SSA_TY_U32, 0, 0, 0, 0}},
    {"GetCurrentProcess",    SSA_TY_HANDLE,  0, {0, 0, 0, 0, 0, 0}},
    {"GetCurrentProcessId",  SSA_TY_U32,     0, {0, 0, 0, 0, 0, 0}},
    {"GetCurrentThreadId",   SSA_TY_U32,     0, {0, 0, 0, 0, 0, 0}},
    {"GetLastError",         SSA_TY_U32,     0, {0, 0, 0, 0, 0, 0}},
    {"SetLastError",         SSA_TY_VOID,    1, {SSA_TY_U32, 0, 0, 0, 0, 0}},
    {"Sleep",                SSA_TY_VOID,    1, {SSA_TY_U32, 0, 0, 0, 0, 0}},
    {"ExitProcess",          SSA_TY_VOID,    1, {SSA_TY_U32, 0, 0, 0, 0, 0}},
    {"IsDebuggerPresent",    SSA_TY_BOOL,    0, {0, 0, 0, 0, 0, 0}},
    {"ReadProcessMemory",    SSA_TY_BOOL,    5, {SSA_TY_HANDLE, SSA_TY_PTR, SSA_TY_PTR, SSA_TY_SIZE_T, SSA_TY_PTR, 0}},
    {"WriteProcessMemory",   SSA_TY_BOOL,    5, {SSA_TY_HANDLE, SSA_TY_PTR, SSA_TY_PTR, SSA_TY_SIZE_T, SSA_TY_PTR, 0}},
    {"RegOpenKeyExA",        SSA_TY_I32,     5, {SSA_TY_HKEY, SSA_TY_CSTR, SSA_TY_U32, SSA_TY_U32, SSA_TY_PTR, 0}},
    {"RegOpenKeyExW",        SSA_TY_I32,     5, {SSA_TY_HKEY, SSA_TY_WSTR, SSA_TY_U32, SSA_TY_U32, SSA_TY_PTR, 0}},
    {"RegQueryValueExA",     SSA_TY_I32,     6, {SSA_TY_HKEY, SSA_TY_CSTR, SSA_TY_PTR, SSA_TY_PTR, SSA_TY_PTR, SSA_TY_PTR}},
    {"RegQueryValueExW",     SSA_TY_I32,     6, {SSA_TY_HKEY, SSA_TY_WSTR, SSA_TY_PTR, SSA_TY_PTR, SSA_TY_PTR, SSA_TY_PTR}},
    {"RegSetValueExA",       SSA_TY_I32,     6, {SSA_TY_HKEY, SSA_TY_CSTR, SSA_TY_U32, SSA_TY_U32, SSA_TY_PTR, SSA_TY_U32}},
    {"RegSetValueExW",       SSA_TY_I32,     6, {SSA_TY_HKEY, SSA_TY_WSTR, SSA_TY_U32, SSA_TY_U32, SSA_TY_PTR, SSA_TY_U32}},
    {"RegCloseKey",          SSA_TY_I32,     1, {SSA_TY_HKEY, 0, 0, 0, 0, 0}},
    {"MessageBoxA",          SSA_TY_I32,     4, {SSA_TY_HWND, SSA_TY_CSTR, SSA_TY_CSTR, SSA_TY_U32, 0, 0}},
    {"MessageBoxW",          SSA_TY_I32,     4, {SSA_TY_HWND, SSA_TY_WSTR, SSA_TY_WSTR, SSA_TY_U32, 0, 0}},
    {"SendMessageA",         SSA_TY_I64,     4, {SSA_TY_HWND, SSA_TY_U32, SSA_TY_U64, SSA_TY_I64, 0, 0}},
    {"SendMessageW",         SSA_TY_I64,     4, {SSA_TY_HWND, SSA_TY_U32, SSA_TY_U64, SSA_TY_I64, 0, 0}},
    {"GetWindowTextA",       SSA_TY_I32,     3, {SSA_TY_HWND, SSA_TY_PTR, SSA_TY_I32, 0, 0, 0}},
    {"GetWindowTextW",       SSA_TY_I32,     3, {SSA_TY_HWND, SSA_TY_PTR, SSA_TY_I32, 0, 0, 0}},
    {"socket",               SSA_TY_SOCKET,  3, {SSA_TY_I32, SSA_TY_I32, SSA_TY_I32, 0, 0, 0}},
    {"connect",              SSA_TY_I32,     3, {SSA_TY_SOCKET, SSA_TY_PTR, SSA_TY_I32, 0, 0, 0}},
    {"bind",                 SSA_TY_I32,     3, {SSA_TY_SOCKET, SSA_TY_PTR, SSA_TY_I32, 0, 0, 0}},
    {"send",                 SSA_TY_I32,     4, {SSA_TY_SOCKET, SSA_TY_PTR, SSA_TY_I32, SSA_TY_I32, 0, 0}},
    {"recv",                 SSA_TY_I32,     4, {SSA_TY_SOCKET, SSA_TY_PTR, SSA_TY_I32, SSA_TY_I32, 0, 0}},
    {"closesocket",          SSA_TY_I32,     1, {SSA_TY_SOCKET, 0, 0, 0, 0, 0}},
    {"malloc",               SSA_TY_PTR,     1, {SSA_TY_SIZE_T, 0, 0, 0, 0, 0}},
    {"calloc",               SSA_TY_PTR,     2, {SSA_TY_SIZE_T, SSA_TY_SIZE_T, 0, 0, 0, 0}},
    {"realloc",              SSA_TY_PTR,     2, {SSA_TY_PTR, SSA_TY_SIZE_T, 0, 0, 0, 0}},
    {"free",                 SSA_TY_VOID,    1, {SSA_TY_PTR, 0, 0, 0, 0, 0}},
    {"memcpy",               SSA_TY_PTR,     3, {SSA_TY_PTR, SSA_TY_PTR, SSA_TY_SIZE_T, 0, 0, 0}},
    {"memmove",              SSA_TY_PTR,     3, {SSA_TY_PTR, SSA_TY_PTR, SSA_TY_SIZE_T, 0, 0, 0}},
    {"memset",               SSA_TY_PTR,     3, {SSA_TY_PTR, SSA_TY_I32, SSA_TY_SIZE_T, 0, 0, 0}},
    {"memcmp",               SSA_TY_I32,     3, {SSA_TY_PTR, SSA_TY_PTR, SSA_TY_SIZE_T, 0, 0, 0}},
    {"strlen",               SSA_TY_SIZE_T,  1, {SSA_TY_CSTR, 0, 0, 0, 0, 0}},
    {"wcslen",               SSA_TY_SIZE_T,  1, {SSA_TY_WSTR, 0, 0, 0, 0, 0}},
    {"strcmp",               SSA_TY_I32,     2, {SSA_TY_CSTR, SSA_TY_CSTR, 0, 0, 0, 0}},
    {"strncmp",              SSA_TY_I32,     3, {SSA_TY_CSTR, SSA_TY_CSTR, SSA_TY_SIZE_T, 0, 0, 0}},
    {"stricmp",              SSA_TY_I32,     2, {SSA_TY_CSTR, SSA_TY_CSTR, 0, 0, 0, 0}},
    {"strcpy",               SSA_TY_PTR,     2, {SSA_TY_PTR, SSA_TY_CSTR, 0, 0, 0, 0}},
    {"strncpy",              SSA_TY_PTR,     3, {SSA_TY_PTR, SSA_TY_CSTR, SSA_TY_SIZE_T, 0, 0, 0}},
    {"strcat",               SSA_TY_PTR,     2, {SSA_TY_PTR, SSA_TY_CSTR, 0, 0, 0, 0}},
    {"strstr",               SSA_TY_CSTR,    2, {SSA_TY_CSTR, SSA_TY_CSTR, 0, 0, 0, 0}},
    {"strchr",               SSA_TY_CSTR,    2, {SSA_TY_CSTR, SSA_TY_I32, 0, 0, 0, 0}},
    {"strrchr",              SSA_TY_CSTR,    2, {SSA_TY_CSTR, SSA_TY_I32, 0, 0, 0, 0}},
    {"printf",               SSA_TY_I32,     1, {SSA_TY_CSTR, 0, 0, 0, 0, 0}},
    {"puts",                 SSA_TY_I32,     1, {SSA_TY_CSTR, 0, 0, 0, 0, 0}},
    {"sprintf",              SSA_TY_I32,     2, {SSA_TY_PTR, SSA_TY_CSTR, 0, 0, 0, 0}},
    {"snprintf",             SSA_TY_I32,     3, {SSA_TY_PTR, SSA_TY_SIZE_T, SSA_TY_CSTR, 0, 0, 0}},
    {"fopen",                SSA_TY_FILE,    2, {SSA_TY_CSTR, SSA_TY_CSTR, 0, 0, 0, 0}},
    {"fclose",               SSA_TY_I32,     1, {SSA_TY_FILE, 0, 0, 0, 0, 0}},
    {"fread",                SSA_TY_SIZE_T,  4, {SSA_TY_PTR, SSA_TY_SIZE_T, SSA_TY_SIZE_T, SSA_TY_FILE, 0, 0}},
    {"fwrite",               SSA_TY_SIZE_T,  4, {SSA_TY_PTR, SSA_TY_SIZE_T, SSA_TY_SIZE_T, SSA_TY_FILE, 0, 0}},
    {"fseek",                SSA_TY_I32,     3, {SSA_TY_FILE, SSA_TY_I64, SSA_TY_I32, 0, 0, 0}},
    {"ftell",                SSA_TY_I64,     1, {SSA_TY_FILE, 0, 0, 0, 0, 0}},
    {"open",                 SSA_TY_I32,     2, {SSA_TY_CSTR, SSA_TY_I32, 0, 0, 0, 0}},
    {"read",                 SSA_TY_I64,     3, {SSA_TY_I32, SSA_TY_PTR, SSA_TY_SIZE_T, 0, 0, 0}},
    {"write",                SSA_TY_I64,     3, {SSA_TY_I32, SSA_TY_PTR, SSA_TY_SIZE_T, 0, 0, 0}},
    {"close",                SSA_TY_I32,     1, {SSA_TY_I32, 0, 0, 0, 0, 0}},
    {"mmap",                 SSA_TY_PTR,     6, {SSA_TY_PTR, SSA_TY_SIZE_T, SSA_TY_I32, SSA_TY_I32, SSA_TY_I32, SSA_TY_I64}},
    {"munmap",               SSA_TY_I32,     2, {SSA_TY_PTR, SSA_TY_SIZE_T, 0, 0, 0, 0}},
    {"atoi",                 SSA_TY_I32,     1, {SSA_TY_CSTR, 0, 0, 0, 0, 0}},
    {"exit",                 SSA_TY_VOID,    1, {SSA_TY_I32, 0, 0, 0, 0, 0}},
    {"abort",                SSA_TY_VOID,    0, {0, 0, 0, 0, 0, 0}}
};

static inline void ssa_bs_set(uint64_t bs[4], uint32_t b) {
    bs[b >> 6] |= 1ULL << (b & 63);
}

static inline void ssa_bs_clr(uint64_t bs[4], uint32_t b) {
    bs[b >> 6] &= ~(1ULL << (b & 63));
}

static inline int ssa_bs_get(const uint64_t bs[4], uint32_t b) {
    return (bs[b >> 6] & (1ULL << (b & 63))) != 0;
}

static inline int ssa_bs_eq(const uint64_t a[4], const uint64_t b[4]) {
    return a[0] == b[0] && a[1] == b[1] && a[2] == b[2] && a[3] == b[3];
}

static void ssa_append(char *dst, size_t cap, size_t *pos, const char *fmt, ...) {
    if (*pos + 1 >= cap) return;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(dst + *pos, cap - *pos, fmt, ap);
    va_end(ap);
    if (n <= 0) return;
    size_t add = (size_t)n;
    if (*pos + add >= cap) *pos = cap - 1;
    else *pos += add;
}

static void ssa_trim(char *s) {
    char *p = s;
    while (*p == ' ' || *p == '\t') p++;
    if (p != s) memmove(s, p, strlen(p) + 1);
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\t')) s[--n] = 0;
}

static void ssa_clean_sym(const char *sym, char *dst, size_t cap) {
    const char *bang = strchr(sym, '!');
    const char *src = bang ? bang + 1 : sym;
    size_t k = 0;
    for (size_t i = 0; src[i] && k + 1 < cap; i++) {
        char ch = src[i];
        dst[k++] = (isalnum((unsigned char)ch) || ch == '_') ? ch : '_';
    }
    dst[k] = 0;
    if (!dst[0]) snprintf(dst, cap, "fn");
}

static const ssa_api_sig *ssa_api_find(const char *raw) {
    if (!raw || !raw[0]) return NULL;
    const char *s = raw;
    const char *bang = strchr(s, '!');
    if (bang) s = bang + 1;
    if (strncmp(s, "__imp_", 6) == 0) s += 6;
    else if (strncmp(s, "imp_", 4) == 0) s += 4;
    else if (strncmp(s, "j_", 2) == 0) s += 2;
    while (*s == '_') s++;

    size_t n = sizeof(ssa_apis) / sizeof(ssa_apis[0]);
    for (size_t i = 0; i < n; i++) {
        if (strcmp(s, ssa_apis[i].name) == 0) return &ssa_apis[i];
    }
    for (size_t i = 0; i < n; i++) {
        size_t len = strlen(ssa_apis[i].name);
        if (strncmp(s, ssa_apis[i].name, len) == 0 && (s[len] == '@' || s[len] == '_' || s[len] == 0)) {
            return &ssa_apis[i];
        }
    }
    return NULL;
}

static uint64_t ssa_mask(uint64_t v, int bits) {
    if (bits == 8) return v & 0xFFULL;
    if (bits == 16) return v & 0xFFFFULL;
    if (bits == 32) return v & 0xFFFFFFFFULL;
    return v;
}

static int64_t ssa_sext_val(uint64_t v, int bits) {
    if (bits == 8) return (int64_t)(int8_t)(v & 0xFFULL);
    if (bits == 16) return (int64_t)(int16_t)(v & 0xFFFFULL);
    if (bits == 32) return (int64_t)(int32_t)(v & 0xFFFFFFFFULL);
    return (int64_t)v;
}

static const char *ssa_reg_name(const ssa_ctx *c, int r, int bits) {
    static char xbuf[4][12];
    static int slot = 0;
    if (r < 0 || r >= SSA_MAX_REGS) return "r?";
    if (c->is_arm64) {
        if (bits == 32 && r < 31) {
            char *b = xbuf[slot++ & 3];
            snprintf(b, 12, "w%d", r);
            return b;
        }
        return ssa_a64_regs[r];
    }
    if (r >= 16) {
        char *b = xbuf[slot++ & 3];
        snprintf(b, 12, "xmm%d", r - 16);
        return b;
    }
    if (c->is_x86) return ssa_x86_regs[r];
    if (bits == 32) return ssa_x86_regs[r];
    return ssa_x64_regs[r];
}

static const char *ssa_canon_reg(const ssa_ctx *c, int r) {
    return ssa_reg_name(c, r, c->ptr_bits);
}

static void ssa_ver_name(const ssa_ctx *c, int ver, char *dst, size_t cap) {
    if (ver <= 0 || ver >= c->nver) {
        snprintf(dst, cap, "v?");
        return;
    }
    const ssa_ver *v = &c->vers[ver];
    snprintf(dst, cap, "%s_%d", ssa_canon_reg(c, v->reg), v->idx);
}

static void ssa_fmt_imm(uint64_t v, char *dst, size_t cap) {
    snprintf(dst, cap, "0x%llx", (unsigned long long)v);
}

static void ssa_build_cfg(ssa_ctx *c) {
    const grp_cfg *g = c->g;
    for (uint32_t e = 0; e < g->nedge; e++) {
        uint32_t u = g->edges[e].from;
        uint32_t v = g->edges[e].to;
        if (u >= c->nblk || v >= c->nblk) continue;
        ssa_bs_set(c->succ_bs[u], v);
        ssa_bs_set(c->pred_bs[v], u);
    }

    uint32_t q[SSA_MAX_BLKS];
    uint32_t qh = 0, qt = 0;
    c->reach[0] = 1;
    q[qt++] = 0;
    while (qh < qt) {
        uint32_t u = q[qh++];
        for (uint32_t v = 0; v < c->nblk; v++) {
            if (!c->reach[v] && ssa_bs_get(c->succ_bs[u], v)) {
                c->reach[v] = 1;
                q[qt++] = v;
            }
        }
    }
}

static void ssa_compute_doms(ssa_ctx *c) {
    uint64_t all_r[4] = {0, 0, 0, 0};
    for (uint32_t b = 0; b < c->nblk; b++) {
        c->idom[b] = -1;
        c->dom_head[b] = -1;
        c->dom_next[b] = -1;
        if (c->reach[b]) ssa_bs_set(all_r, b);
    }

    ssa_bs_set(c->dom_bs[0], 0);
    for (uint32_t b = 1; b < c->nblk; b++) {
        if (c->reach[b]) memcpy(c->dom_bs[b], all_r, sizeof(all_r));
    }

    int changed = 1;
    while (changed) {
        changed = 0;
        for (uint32_t b = 1; b < c->nblk; b++) {
            if (!c->reach[b]) continue;
            uint64_t nd[4];
            memcpy(nd, all_r, sizeof(nd));
            int has_p = 0;
            for (uint32_t p = 0; p < c->nblk; p++) {
                if (!c->reach[p] || !ssa_bs_get(c->pred_bs[b], p)) continue;
                for (int w = 0; w < 4; w++) nd[w] &= c->dom_bs[p][w];
                has_p = 1;
            }
            if (!has_p) memset(nd, 0, sizeof(nd));
            ssa_bs_set(nd, b);
            if (!ssa_bs_eq(nd, c->dom_bs[b])) {
                memcpy(c->dom_bs[b], nd, sizeof(nd));
                changed = 1;
            }
        }
    }

    for (uint32_t b = 1; b < c->nblk; b++) {
        if (!c->reach[b]) continue;
        uint64_t sdom[4];
        memcpy(sdom, c->dom_bs[b], sizeof(sdom));
        ssa_bs_clr(sdom, b);
        for (uint32_t d = 0; d < c->nblk; d++) {
            if (!ssa_bs_get(sdom, d)) continue;
            if (ssa_bs_eq(c->dom_bs[d], sdom)) {
                c->idom[b] = (int)d;
                break;
            }
        }
    }

    // append in reverse so head->next lists iterate in ascending block order
    for (int b = (int)c->nblk - 1; b >= 1; b--) {
        int id = c->idom[b];
        if (id >= 0) {
            c->dom_next[b] = c->dom_head[id];
            c->dom_head[id] = b;
        }
    }
}

static void ssa_compute_df(ssa_ctx *c) {
    for (uint32_t b = 0; b < c->nblk; b++) {
        if (!c->reach[b]) continue;
        int npred = 0;
        for (uint32_t p = 0; p < c->nblk; p++) {
            if (c->reach[p] && ssa_bs_get(c->pred_bs[b], p)) npred++;
        }
        if (npred < 2 && !(b == 0 && npred >= 1)) continue;
        for (uint32_t p = 0; p < c->nblk; p++) {
            if (!c->reach[p] || !ssa_bs_get(c->pred_bs[b], p)) continue;
            int runner = (int)p;
            while (runner >= 0 && runner != c->idom[b]) {
                ssa_bs_set(c->df_bs[runner], b);
                runner = c->idom[runner];
            }
        }
    }
}

static int ssa_split_ops(const char *ops, char out[4][76]) {
    for (int i = 0; i < 4; i++) out[i][0] = 0;
    if (!ops || !ops[0]) return 0;
    int cnt = 0, depth = 0;
    const char *start = ops;
    for (const char *p = ops; ; p++) {
        if (*p == '[') depth++;
        else if (*p == ']' && depth > 0) depth--;
        if ((*p == ',' && depth == 0) || *p == 0) {
            if (cnt < 4) {
                size_t len = (size_t)(p - start);
                if (len >= 75) len = 75;
                memcpy(out[cnt], start, len);
                out[cnt][len] = 0;
                ssa_trim(out[cnt]);
                if (out[cnt][0]) cnt++;
            }
            if (*p == 0) break;
            start = p + 1;
        }
    }
    return cnt;
}

static int ssa_parse_x86_reg(const char *s, int *bits, int *is_flt) {
    *bits = 64;
    *is_flt = 0;
    if ((s[0] == 'x' || s[0] == 'y' || s[0] == 'z') && s[1] == 'm' && s[2] == 'm' && isdigit((unsigned char)s[3])) {
        *bits = (s[0] == 'z') ? 512 : (s[0] == 'y') ? 256 : 128;
        *is_flt = 1;
        return 16 + (atoi(s + 3) & 15);
    }
    static const char *const r16[16] = {"ax","cx","dx","bx","sp","bp","si","di","r8w","r9w","r10w","r11w","r12w","r13w","r14w","r15w"};
    static const char *const r8a[16] = {"al","cl","dl","bl","spl","bpl","sil","dil","r8b","r9b","r10b","r11b","r12b","r13b","r14b","r15b"};
    static const char *const r8h[4]  = {"ah","ch","dh","bh"};
    for (int i = 0; i < 16; i++) {
        if (strcmp(s, ssa_x64_regs[i]) == 0) { *bits = 64; return i; }
        if (strcmp(s, ssa_x86_regs[i]) == 0) { *bits = 32; return i; }
        if (strcmp(s, r16[i]) == 0)          { *bits = 16; return i; }
        if (strcmp(s, r8a[i]) == 0)          { *bits = 8;  return i; }
    }
    for (int i = 0; i < 4; i++) {
        if (strcmp(s, r8h[i]) == 0) { *bits = 8; return i; }
    }
    return -1;
}

static int ssa_parse_a64_reg(const char *s, int *bits, int *is_zero, int *is_flt) {
    *bits = 64;
    *is_zero = 0;
    *is_flt = 0;
    if (strcmp(s, "xzr") == 0) { *bits = 64; *is_zero = 1; return -1; }
    if (strcmp(s, "wzr") == 0) { *bits = 32; *is_zero = 1; return -1; }
    if (strcmp(s, "sp") == 0)  { *bits = 64; return 31; }
    if (strcmp(s, "wsp") == 0) { *bits = 32; return 31; }
    if (strcmp(s, "fp") == 0)  { *bits = 64; return 29; }
    if (strcmp(s, "lr") == 0)  { *bits = 64; return 30; }
    if ((s[0] == 'x' || s[0] == 'w') && isdigit((unsigned char)s[1])) {
        char *end = NULL;
        long r = strtol(s + 1, &end, 10);
        if (end && *end == 0 && r >= 0 && r <= 30) {
            *bits = (s[0] == 'x') ? 64 : 32;
            return (int)r;
        }
    }
    if ((s[0] == 'd' || s[0] == 's') && isdigit((unsigned char)s[1])) {
        char *end = NULL;
        long r = strtol(s + 1, &end, 10);
        if (end && *end == 0 && r >= 0 && r <= 30) {
            *bits = (s[0] == 'd') ? 64 : 32;
            *is_flt = (s[0] == 'd') ? 2 : 1;
            return (int)r;
        }
    }
    return -1;
}

static int ssa_parse_int(const char *p, int64_t *out) {
    if (*p == '#') p++;
    int neg = 0;
    if (*p == '-') { neg = 1; p++; }
    else if (*p == '+') p++;
    if (!*p) return 0;
    char *end = NULL;
    uint64_t v = 0;
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) v = strtoull(p + 2, &end, 16);
    else if (isdigit((unsigned char)p[0])) v = strtoull(p, &end, 10);
    else return 0;
    if (!end || *end != 0) return 0;
    *out = neg ? (int64_t)(0ULL - v) : (int64_t)v;
    return 1;
}

static void ssa_parse_mem_x86(const char *in_raw, ssa_arg *op) {
    char in[64];
    snprintf(in, sizeof(in), "%s", in_raw);
    char *rb = strchr(in, ']');
    if (rb) *rb = 0;
    ssa_trim(in);

    if (strncmp(in, "0x", 2) == 0 && !strchr(in, '+') && !strchr(in, '-') && !strchr(in, '*')) {
        op->imm = strtoull(in + 2, NULL, 16);
        return;
    }

    char *cur = in;
    int sign = 1;
    while (*cur) {
        if (*cur == ' ') { cur++; continue; }
        if (*cur == '+') { sign = 1; cur++; continue; }
        if (*cur == '-') { sign = -1; cur++; continue; }
        char tok[32];
        int k = 0;
        while (*cur && *cur != '+' && *cur != '-' && k < 31) tok[k++] = *cur++;
        tok[k] = 0;
        ssa_trim(tok);
        char *star = strchr(tok, '*');
        if (star) {
            *star = 0;
            ssa_trim(tok);
            int b2, fl;
            int r = ssa_parse_x86_reg(tok, &b2, &fl);
            if (r >= 0 && !fl) {
                op->idx = (int8_t)r;
                op->scale = (uint8_t)atoi(star + 1);
            }
        } else {
            int64_t iv = 0;
            if (ssa_parse_int(tok, &iv)) {
                op->disp += sign * iv;
            } else {
                int b2, fl;
                int r = ssa_parse_x86_reg(tok, &b2, &fl);
                if (r >= 0 && !fl) {
                    if (op->reg < 0) op->reg = (int8_t)r;
                    else op->idx = (int8_t)r;
                }
            }
        }
    }
}

static void ssa_parse_mem_a64(const char *in_raw, ssa_arg *op) {
    char in[64];
    snprintf(in, sizeof(in), "%s", in_raw);
    char *rb = strchr(in, ']');
    if (rb) *rb = 0;
    ssa_trim(in);

    if (strncmp(in, "0x", 2) == 0 && !strchr(in, ',')) {
        op->imm = strtoull(in + 2, NULL, 16);
        return;
    }

    char *comma = strchr(in, ',');
    if (comma) *comma = 0;
    ssa_trim(in);
    int b2 = 64, zr = 0, fl = 0;
    int r = ssa_parse_a64_reg(in, &b2, &zr, &fl);
    if (r >= 0) op->reg = (int8_t)r;

    if (comma) {
        char *rhs = comma + 1;
        ssa_trim(rhs);
        int64_t iv = 0;
        if (ssa_parse_int(rhs, &iv)) {
            op->disp = iv;
        } else {
            int r2 = ssa_parse_a64_reg(rhs, &b2, &zr, &fl);
            if (r2 >= 0) op->idx = (int8_t)r2;
        }
    }
}

static void ssa_parse_opr(const ssa_ctx *c, const char *raw, ssa_arg *op) {
    memset(op, 0, sizeof(*op));
    op->reg = -1;
    op->idx = -1;
    op->scale = 1;
    if (!raw || !raw[0]) return;

    char buf[80];
    snprintf(buf, sizeof(buf), "%s", raw);
    ssa_trim(buf);

    const char *p = buf;
    if (!c->is_arm64) {
        if (strncmp(p, "byte ptr ", 9) == 0)         { op->bits = 8;   p += 9; }
        else if (strncmp(p, "word ptr ", 9) == 0)    { op->bits = 16;  p += 9; }
        else if (strncmp(p, "dword ptr ", 10) == 0)  { op->bits = 32;  p += 10; }
        else if (strncmp(p, "qword ptr ", 10) == 0)  { op->bits = 64;  p += 10; }
        else if (strncmp(p, "xmmword ptr ", 12) == 0) { op->bits = 128; p += 12; }
        else if (strncmp(p, "ymmword ptr ", 12) == 0) { op->bits = 256; p += 12; }
        if (p[0] && p[1] && p[2] == ':') p += 3;
    }

    if (*p == '[') {
        op->kind = SSA_ARG_MEM;
        if (c->is_arm64) ssa_parse_mem_a64(p + 1, op);
        else ssa_parse_mem_x86(p + 1, op);
        return;
    }

    int64_t iv = 0;
    if (ssa_parse_int(p, &iv)) {
        op->kind = SSA_ARG_IMM;
        op->imm = (uint64_t)iv;
        return;
    }

    int rb = c->ptr_bits, fl = 0, zr = 0;
    int r = c->is_arm64 ? ssa_parse_a64_reg(p, &rb, &zr, &fl) : ssa_parse_x86_reg(p, &rb, &fl);
    if (zr) {
        op->kind = SSA_ARG_IMM;
        op->imm = 0;
        op->bits = (uint16_t)rb;
        return;
    }
    if (r >= 0) {
        op->kind = SSA_ARG_REG;
        op->reg = (int8_t)r;
        op->bits = (uint16_t)rb;
        op->is_flt = (uint8_t)fl;
    }
}

static void ssa_norm_cc(const char *raw, char out[8]) {
    if (!raw || !raw[0]) { snprintf(out, 8, "cc"); return; }
    if (strcmp(raw, "e") == 0 || strcmp(raw, "z") == 0 || strcmp(raw, "eq") == 0) snprintf(out, 8, "eq");
    else if (strcmp(raw, "ne") == 0 || strcmp(raw, "nz") == 0) snprintf(out, 8, "ne");
    else if (strcmp(raw, "l") == 0 || strcmp(raw, "lt") == 0) snprintf(out, 8, "lt");
    else if (strcmp(raw, "le") == 0) snprintf(out, 8, "le");
    else if (strcmp(raw, "g") == 0 || strcmp(raw, "gt") == 0) snprintf(out, 8, "gt");
    else if (strcmp(raw, "ge") == 0) snprintf(out, 8, "ge");
    else if (strcmp(raw, "b") == 0 || strcmp(raw, "c") == 0 || strcmp(raw, "cc") == 0 || strcmp(raw, "lo") == 0) snprintf(out, 8, "ult");
    else if (strcmp(raw, "be") == 0 || strcmp(raw, "ls") == 0) snprintf(out, 8, "ule");
    else if (strcmp(raw, "a") == 0 || strcmp(raw, "hi") == 0) snprintf(out, 8, "ugt");
    else if (strcmp(raw, "ae") == 0 || strcmp(raw, "cs") == 0 || strcmp(raw, "hs") == 0) snprintf(out, 8, "uge");
    else if (strcmp(raw, "s") == 0 || strcmp(raw, "mi") == 0) snprintf(out, 8, "neg");
    else if (strcmp(raw, "ns") == 0 || strcmp(raw, "pl") == 0) snprintf(out, 8, "pos");
    else snprintf(out, 8, "%s", raw);
}

static ssa_ir *ssa_push_llir(ssa_ctx *c, uint64_t va, uint16_t blk, uint8_t op) {
    if (c->nllir == c->llir_cap) {
        uint32_t nc = c->llir_cap ? c->llir_cap * 2 : 256;
        ssa_ir *nl = (ssa_ir *)realloc(c->llir, (size_t)nc * sizeof(ssa_ir));
        if (!nl) return NULL;
        c->llir = nl;
        c->llir_cap = nc;
    }
    ssa_ir *ir = &c->llir[c->nllir++];
    memset(ir, 0, sizeof(*ir));
    ir->va = va;
    ir->blk = blk;
    ir->op = op;
    ir->dst_reg = -1;
    ir->a0.reg = ir->a0.idx = -1;
    ir->a1.reg = ir->a1.idx = -1;
    ir->a2.reg = ir->a2.idx = -1;
    return ir;
}

static void ssa_fill_call_sym(ssa_ctx *c, const x86_ins *in, const ssa_arg *o0, ssa_ir *ir) {
    if (in->has_target) {
        const char *sym = ana_sym_at(c->a, in->target);
        if (sym) ssa_clean_sym(sym, ir->sym, sizeof(ir->sym));
        else snprintf(ir->sym, sizeof(ir->sym), "sub_%llx", (unsigned long long)in->target);
        ir->a0.kind = SSA_ARG_VA;
        ir->a0.imm = in->target;
    } else if (o0->kind == SSA_ARG_REG || o0->kind == SSA_ARG_MEM) {
        ir->a0 = *o0;
    } else {
        snprintf(ir->sym, sizeof(ir->sym), "indirect");
    }
}

static int ssa_x86_flt_op(const char *m, uint8_t *op, uint8_t *flt_sz) {
    const char *s = (m[0] == 'v') ? (m + 1) : m;
    if (strncmp(s, "add", 3) == 0) *op = SSA_OP_FADD;
    else if (strncmp(s, "sub", 3) == 0) *op = SSA_OP_FSUB;
    else if (strncmp(s, "mul", 3) == 0) *op = SSA_OP_FMUL;
    else if (strncmp(s, "div", 3) == 0) *op = SSA_OP_FDIV;
    else return 0;

    const char *suf = s + 3;
    if (strcmp(suf, "ss") == 0 || strcmp(suf, "ps") == 0) { *flt_sz = 1; return 1; }
    if (strcmp(suf, "sd") == 0 || strcmp(suf, "pd") == 0) { *flt_sz = 2; return 1; }
    return 0;
}

static int ssa_x86_alu_op(const char *m, uint8_t *op, uint8_t *is_signed) {
    *is_signed = 0;
    if (strcmp(m, "add") == 0 || strcmp(m, "adc") == 0) { *op = SSA_OP_ADD; return 1; }
    if (strcmp(m, "sub") == 0 || strcmp(m, "sbb") == 0) { *op = SSA_OP_SUB; return 1; }
    if (strcmp(m, "and") == 0 || strcmp(m, "pand") == 0 || strcmp(m, "andps") == 0 || strcmp(m, "andpd") == 0) { *op = SSA_OP_AND; return 1; }
    if (strcmp(m, "or") == 0  || strcmp(m, "por") == 0  || strcmp(m, "orps") == 0  || strcmp(m, "orpd") == 0)  { *op = SSA_OP_OR;  return 1; }
    if (strcmp(m, "xor") == 0 || strcmp(m, "pxor") == 0 || strcmp(m, "xorps") == 0 || strcmp(m, "xorpd") == 0) { *op = SSA_OP_XOR; return 1; }
    if (strcmp(m, "shl") == 0 || strcmp(m, "sal") == 0) { *op = SSA_OP_SHL; return 1; }
    if (strcmp(m, "shr") == 0) { *op = SSA_OP_SHR; return 1; }
    if (strcmp(m, "sar") == 0) { *op = SSA_OP_SAR; *is_signed = 1; return 1; }
    if (strcmp(m, "rol") == 0 || strcmp(m, "rcl") == 0) { *op = SSA_OP_ROL; return 1; }
    if (strcmp(m, "ror") == 0 || strcmp(m, "rcr") == 0) { *op = SSA_OP_ROR; return 1; }
    if (strcmp(m, "imul") == 0) { *op = SSA_OP_MUL; *is_signed = 1; return 1; }
    return 0;
}

static void ssa_lift_x86(ssa_ctx *c, uint16_t blk, const x86_ins *in) {
    const char *m = in->mnem;
    if (strncmp(m, "lock ", 5) == 0) m += 5;
    if (strcmp(m, "nop") == 0 || strcmp(m, "fnop") == 0 || strcmp(m, "endbr64") == 0 ||
        strcmp(m, "endbr32") == 0 || strcmp(m, "int3") == 0 ||
        (strcmp(m, "add") == 0 && strcmp(in->ops, "byte ptr [rax], al") == 0)) {
        return;
    }

    char ops[4][76];
    int nops = ssa_split_ops(in->ops, ops);
    ssa_arg o0, o1, o2;
    ssa_parse_opr(c, ops[0], &o0);
    ssa_parse_opr(c, ops[1], &o1);
    ssa_parse_opr(c, ops[2], &o2);

    if (strcmp(m, "xchg") == 0 && o0.kind == SSA_ARG_REG && o1.kind == SSA_ARG_REG && o0.reg == o1.reg) {
        return;
    }

    if (in->flow == X86_FLOW_CALL) {
        ssa_ir *ir = ssa_push_llir(c, in->ip, blk, SSA_OP_CALL);
        if (!ir) return;
        ir->dst_reg = (int8_t)c->ret_reg;
        ir->bits = (uint8_t)c->ptr_bits;
        ssa_fill_call_sym(c, in, &o0, ir);
        return;
    }
    if (in->flow == X86_FLOW_RET) {
        ssa_ir *ir = ssa_push_llir(c, in->ip, blk, SSA_OP_RET);
        if (!ir) return;
        ir->bits = (uint8_t)c->ptr_bits;
        return;
    }
    if (in->flow == X86_FLOW_JCC) {
        ssa_ir *ir = ssa_push_llir(c, in->ip, blk, SSA_OP_JCC);
        if (!ir) return;
        ssa_norm_cc((m[0] == 'j' && m[1]) ? (m + 1) : m, ir->cc);
        ir->a0.kind = SSA_ARG_VA;
        ir->a0.imm = in->target;
        if (strcmp(m, "jrcxz") == 0 || strcmp(m, "jecxz") == 0) {
            ir->a1.kind = SSA_ARG_REG;
            ir->a1.reg = 1;
            ir->a1.bits = (uint16_t)c->ptr_bits;
        }
        return;
    }
    if (in->flow == X86_FLOW_JMP) {
        ssa_ir *ir = ssa_push_llir(c, in->ip, blk, SSA_OP_JMP);
        if (!ir) return;
        if (in->has_target && !in->target_mem) {
            ir->a0.kind = SSA_ARG_VA;
            ir->a0.imm = in->target;
        } else {
            ir->a0 = o0;
        }
        return;
    }

    if (strcmp(m, "cmp") == 0 || strcmp(m, "test") == 0 || strcmp(m, "bt") == 0 ||
        strcmp(m, "ucomiss") == 0 || strcmp(m, "ucomisd") == 0 ||
        strcmp(m, "comiss") == 0 || strcmp(m, "comisd") == 0) {
        ssa_ir *ir = ssa_push_llir(c, in->ip, blk, SSA_OP_CMP);
        if (!ir) return;
        ir->is_test = (strcmp(m, "test") == 0 || strcmp(m, "bt") == 0) ? 1 : 0;
        if (strstr(m, "ss")) { ir->is_flt = 1; ir->bits = 32; }
        else if (strstr(m, "sd")) { ir->is_flt = 2; ir->bits = 64; }
        else ir->bits = (uint8_t)(o0.bits ? o0.bits : (o1.bits ? o1.bits : c->ptr_bits));
        ir->a0 = o0;
        ir->a1 = o1;
        return;
    }

    if (strcmp(m, "lea") == 0 && o0.kind == SSA_ARG_REG && o1.kind == SSA_ARG_MEM) {
        ssa_ir *ir = ssa_push_llir(c, in->ip, blk, SSA_OP_LEA);
        if (!ir) return;
        ir->dst_reg = o0.reg;
        ir->bits = (uint8_t)(o0.bits ? o0.bits : c->ptr_bits);
        ir->a0 = o1;
        return;
    }

    if (strcmp(m, "push") == 0 && o0.kind != SSA_ARG_NONE) {
        ssa_ir *ir = ssa_push_llir(c, in->ip, blk, SSA_OP_STORE);
        if (!ir) return;
        ir->bits = (uint8_t)c->ptr_bits;
        ir->a0.kind = SSA_ARG_MEM;
        ir->a0.reg = (int8_t)c->sp_reg;
        ir->a0.idx = -1;
        ir->a0.scale = 1;
        ir->a0.bits = (uint16_t)c->ptr_bits;
        ir->a1 = o0;
        return;
    }

    if (strcmp(m, "pop") == 0 && o0.kind == SSA_ARG_REG) {
        ssa_ir *ir = ssa_push_llir(c, in->ip, blk, SSA_OP_LOAD);
        if (!ir) return;
        ir->dst_reg = o0.reg;
        ir->bits = (uint8_t)(o0.bits ? o0.bits : c->ptr_bits);
        ir->a0.kind = SSA_ARG_MEM;
        ir->a0.reg = (int8_t)c->sp_reg;
        ir->a0.idx = -1;
        ir->a0.scale = 1;
        ir->a0.bits = ir->bits;
        return;
    }

    if (strcmp(m, "movzx") == 0 || strcmp(m, "movsx") == 0 || strcmp(m, "movsxd") == 0) {
        if (o0.kind == SSA_ARG_REG) {
            uint8_t op = (strcmp(m, "movzx") == 0) ? SSA_OP_ZEXT : SSA_OP_SEXT;
            ssa_ir *ir = ssa_push_llir(c, in->ip, blk, op);
            if (!ir) return;
            ir->dst_reg = o0.reg;
            ir->bits = (uint8_t)(o0.bits ? o0.bits : 32);
            ir->src_bits = (uint8_t)(o1.bits ? o1.bits : (strcmp(m, "movsxd") == 0 ? 32 : 8));
            ir->is_signed = (op == SSA_OP_SEXT) ? 1 : 0;
            ir->a0 = o1;
        }
        return;
    }

    if (strcmp(m, "cdqe") == 0 || strcmp(m, "cwde") == 0 || strcmp(m, "cbw") == 0) {
        ssa_ir *ir = ssa_push_llir(c, in->ip, blk, SSA_OP_SEXT);
        if (!ir) return;
        ir->dst_reg = 0;
        ir->bits = (strcmp(m, "cdqe") == 0) ? 64 : (strcmp(m, "cwde") == 0 ? 32 : 16);
        ir->src_bits = (uint8_t)(ir->bits / 2);
        ir->is_signed = 1;
        ir->a0.kind = SSA_ARG_REG;
        ir->a0.reg = 0;
        ir->a0.bits = ir->src_bits;
        return;
    }
    if (strcmp(m, "cdq") == 0 || strcmp(m, "cqo") == 0) {
        ssa_ir *ir = ssa_push_llir(c, in->ip, blk, SSA_OP_SAR);
        if (!ir) return;
        ir->dst_reg = 2;
        ir->bits = (strcmp(m, "cqo") == 0) ? 64 : 32;
        ir->is_signed = 1;
        ir->a0.kind = SSA_ARG_REG;
        ir->a0.reg = 0;
        ir->a0.bits = ir->bits;
        ir->a1.kind = SSA_ARG_IMM;
        ir->a1.imm = (uint64_t)(ir->bits - 1);
        return;
    }

    if (strcmp(m, "mov") == 0 || strcmp(m, "movabs") == 0 || strcmp(m, "movss") == 0 ||
        strcmp(m, "movsd") == 0 || strcmp(m, "movaps") == 0 || strcmp(m, "movups") == 0 ||
        strcmp(m, "movapd") == 0 || strcmp(m, "movupd") == 0 || strcmp(m, "movdqa") == 0 ||
        strcmp(m, "movdqu") == 0 || strcmp(m, "movd") == 0 || strcmp(m, "movq") == 0 ||
        strcmp(m, "vmovss") == 0 || strcmp(m, "vmovsd") == 0 || strcmp(m, "vmovaps") == 0) {
        uint8_t fl = 0;
        if (strstr(m, "ss") || strstr(m, "ps")) fl = 1;
        else if (strstr(m, "sd") || strstr(m, "pd")) fl = 2;
        if (o0.kind == SSA_ARG_REG && o1.kind == SSA_ARG_MEM) {
            ssa_ir *ir = ssa_push_llir(c, in->ip, blk, SSA_OP_LOAD);
            if (!ir) return;
            ir->dst_reg = o0.reg;
            ir->is_flt = fl;
            ir->bits = fl ? (uint8_t)(fl == 2 ? 64 : 32) : (uint8_t)(o1.bits ? o1.bits : (o0.bits ? o0.bits : c->ptr_bits));
            ir->a0 = o1;
        } else if (o0.kind == SSA_ARG_MEM) {
            ssa_ir *ir = ssa_push_llir(c, in->ip, blk, SSA_OP_STORE);
            if (!ir) return;
            ir->is_flt = fl;
            ir->bits = fl ? (uint8_t)(fl == 2 ? 64 : 32) : (uint8_t)(o0.bits ? o0.bits : (o1.bits ? o1.bits : c->ptr_bits));
            ir->a0 = o0;
            ir->a1 = o1;
        } else if (o0.kind == SSA_ARG_REG) {
            ssa_ir *ir = ssa_push_llir(c, in->ip, blk, SSA_OP_MOV);
            if (!ir) return;
            ir->dst_reg = o0.reg;
            ir->is_flt = fl;
            ir->bits = fl ? (uint8_t)(fl == 2 ? 64 : 32) : (uint8_t)(o0.bits ? o0.bits : c->ptr_bits);
            ir->a0 = o1;
        }
        return;
    }

    if (strncmp(m, "cvt", 3) == 0 && o0.kind == SSA_ARG_REG) {
        ssa_ir *ir = ssa_push_llir(c, in->ip, blk, SSA_OP_MOV);
        if (!ir) return;
        ir->dst_reg = o0.reg;
        if (strstr(m, "2ss")) { ir->is_flt = 1; ir->bits = 32; }
        else if (strstr(m, "2sd")) { ir->is_flt = 2; ir->bits = 64; }
        else { ir->is_signed = 1; ir->bits = (uint8_t)(o0.bits ? o0.bits : 32); }
        ir->a0 = o1;
        return;
    }

    uint8_t fop = 0, flsz = 0;
    if (ssa_x86_flt_op(m, &fop, &flsz) && o0.kind == SSA_ARG_REG) {
        ssa_ir *ir = ssa_push_llir(c, in->ip, blk, fop);
        if (!ir) return;
        ir->dst_reg = o0.reg;
        ir->is_flt = flsz;
        ir->bits = (flsz == 2) ? 64 : 32;
        if (nops == 3) { ir->a0 = o1; ir->a1 = o2; }
        else { ir->a0 = o0; ir->a1 = o1; }
        return;
    }

    if ((strcmp(m, "mul") == 0 || strcmp(m, "imul") == 0) && nops == 1 && o0.kind != SSA_ARG_NONE) {
        int is_s = (m[0] == 'i');
        uint16_t bw = (uint16_t)(o0.bits ? o0.bits : c->ptr_bits);
        ssa_arg rax_a;
        memset(&rax_a, 0, sizeof(rax_a));
        rax_a.kind = SSA_ARG_REG;
        rax_a.reg = 0;
        rax_a.idx = -1;
        rax_a.bits = bw;
        ssa_ir *lo = ssa_push_llir(c, in->ip, blk, SSA_OP_MUL);
        if (lo) {
            lo->dst_reg = 0;
            lo->bits = bw;
            lo->is_signed = (uint8_t)is_s;
            lo->a0 = rax_a;
            lo->a1 = o0;
        }
        ssa_ir *hi = ssa_push_llir(c, in->ip, blk, SSA_OP_MUL);
        if (hi) {
            hi->dst_reg = 2;
            hi->bits = bw;
            hi->is_signed = (uint8_t)is_s;
            hi->is_mulhi = 1;
            hi->a0 = rax_a;
            hi->a1 = o0;
        }
        return;
    }

    if ((strcmp(m, "div") == 0 || strcmp(m, "idiv") == 0) && o0.kind != SSA_ARG_NONE) {
        ssa_ir *ir = ssa_push_llir(c, in->ip, blk, SSA_OP_DIV);
        if (!ir) return;
        ir->dst_reg = 0;
        ir->bits = (uint8_t)(o0.bits ? o0.bits : c->ptr_bits);
        ir->is_signed = (m[0] == 'i') ? 1 : 0;
        ir->a0.kind = SSA_ARG_REG;
        ir->a0.reg = 0;
        ir->a0.bits = ir->bits;
        ir->a1 = o0;
        return;
    }

    uint8_t aop = 0, asgn = 0;
    if (ssa_x86_alu_op(m, &aop, &asgn)) {
        uint8_t fl = (strstr(m, "ps") != NULL) ? 1 : (strstr(m, "pd") != NULL ? 2 : 0);
        if (o0.kind == SSA_ARG_REG) {
            ssa_ir *ir = ssa_push_llir(c, in->ip, blk, aop);
            if (!ir) return;
            ir->dst_reg = o0.reg;
            ir->is_flt = fl;
            ir->bits = fl ? (uint16_t)(fl == 2 ? 64 : 32) : (uint16_t)(o0.bits ? o0.bits : c->ptr_bits);
            ir->is_signed = asgn;
            if (nops == 3) { ir->a0 = o1; ir->a1 = o2; }
            else { ir->a0 = o0; ir->a1 = o1; }
        } else if (o0.kind == SSA_ARG_MEM) {
            ssa_ir *ir = ssa_push_llir(c, in->ip, blk, SSA_OP_STORE);
            if (!ir) return;
            ir->bits = (uint16_t)(o0.bits ? o0.bits : (o1.bits ? o1.bits : c->ptr_bits));
            ir->a0 = o0;
            ir->a1 = o1;
        }
        return;
    }

    if ((strcmp(m, "neg") == 0 || strcmp(m, "not") == 0 ||
         strcmp(m, "inc") == 0 || strcmp(m, "dec") == 0) && o0.kind == SSA_ARG_REG) {
        uint8_t op = SSA_OP_NEG;
        if (strcmp(m, "not") == 0) op = SSA_OP_NOT;
        else if (strcmp(m, "inc") == 0) op = SSA_OP_ADD;
        else if (strcmp(m, "dec") == 0) op = SSA_OP_SUB;
        ssa_ir *ir = ssa_push_llir(c, in->ip, blk, op);
        if (!ir) return;
        ir->dst_reg = o0.reg;
        ir->bits = (uint8_t)(o0.bits ? o0.bits : c->ptr_bits);
        ir->a0 = o0;
        if (op == SSA_OP_ADD || op == SSA_OP_SUB) {
            ir->a1.kind = SSA_ARG_IMM;
            ir->a1.imm = 1;
        }
        return;
    }

    if (strncmp(m, "cmov", 4) == 0 && o0.kind == SSA_ARG_REG) {
        ssa_ir *ir = ssa_push_llir(c, in->ip, blk, SSA_OP_SEL);
        if (!ir) return;
        ir->dst_reg = o0.reg;
        ir->bits = (uint8_t)(o0.bits ? o0.bits : c->ptr_bits);
        ssa_norm_cc(m + 4, ir->cc);
        ir->a0 = o1;
        ir->a1 = o0;
        return;
    }

    if (strncmp(m, "set", 3) == 0 && o0.kind == SSA_ARG_REG) {
        ssa_ir *ir = ssa_push_llir(c, in->ip, blk, SSA_OP_SEL);
        if (!ir) return;
        ir->dst_reg = o0.reg;
        ir->bits = 8;
        ssa_norm_cc(m + 3, ir->cc);
        ir->a0.kind = SSA_ARG_IMM;
        ir->a0.imm = 1;
        ir->a1.kind = SSA_ARG_IMM;
        ir->a1.imm = 0;
        return;
    }
}

static int ssa_a64_shift_amt(const char *s) {
    if (!s || !s[0]) return 0;
    const char *p = strchr(s, '#');
    if (!p) return 0;
    int64_t v = 0;
    return ssa_parse_int(p, &v) ? (int)v : 0;
}

static void ssa_lift_a64(ssa_ctx *c, uint16_t blk, const x86_ins *in) {
    const char *m = in->mnem;
    if (strcmp(m, "nop") == 0 || strcmp(m, "pacibsp") == 0 || strcmp(m, "autibsp") == 0 ||
        strcmp(m, "paciasp") == 0 || strcmp(m, "autiasp") == 0 || strcmp(m, "brk") == 0) {
        return;
    }

    char ops[4][76];
    int nops = ssa_split_ops(in->ops, ops);
    ssa_arg o0, o1, o2, o3;
    ssa_parse_opr(c, ops[0], &o0);
    ssa_parse_opr(c, ops[1], &o1);
    ssa_parse_opr(c, ops[2], &o2);
    ssa_parse_opr(c, ops[3], &o3);

    if (in->flow == X86_FLOW_CALL) {
        ssa_ir *ir = ssa_push_llir(c, in->ip, blk, SSA_OP_CALL);
        if (!ir) return;
        ir->dst_reg = 0;
        ir->bits = 64;
        ssa_fill_call_sym(c, in, &o0, ir);
        return;
    }
    if (in->flow == X86_FLOW_RET) {
        ssa_ir *ir = ssa_push_llir(c, in->ip, blk, SSA_OP_RET);
        if (ir) ir->bits = 64;
        return;
    }
    if (in->flow == X86_FLOW_JMP) {
        ssa_ir *ir = ssa_push_llir(c, in->ip, blk, SSA_OP_JMP);
        if (!ir) return;
        if (in->has_target && !in->target_mem) {
            ir->a0.kind = SSA_ARG_VA;
            ir->a0.imm = in->target;
        } else {
            ir->a0 = o0;
        }
        return;
    }
    if (in->flow == X86_FLOW_JCC) {
        if (strcmp(m, "cbz") == 0 || strcmp(m, "cbnz") == 0) {
            ssa_ir *cmp = ssa_push_llir(c, in->ip, blk, SSA_OP_CMP);
            if (cmp) {
                cmp->bits = (uint8_t)(o0.bits ? o0.bits : 64);
                cmp->a0 = o0;
                cmp->a1.kind = SSA_ARG_IMM;
                cmp->a1.imm = 0;
            }
            ssa_ir *jcc = ssa_push_llir(c, in->ip, blk, SSA_OP_JCC);
            if (jcc) {
                snprintf(jcc->cc, sizeof(jcc->cc), "%s", strcmp(m, "cbz") == 0 ? "eq" : "ne");
                jcc->a0.kind = SSA_ARG_VA;
                jcc->a0.imm = in->target;
            }
            return;
        }
        if (strcmp(m, "tbz") == 0 || strcmp(m, "tbnz") == 0) {
            ssa_ir *cmp = ssa_push_llir(c, in->ip, blk, SSA_OP_CMP);
            if (cmp) {
                cmp->is_test = 1;
                cmp->bits = (uint8_t)(o0.bits ? o0.bits : 64);
                cmp->a0 = o0;
                cmp->a1.kind = SSA_ARG_IMM;
                cmp->a1.imm = 1ULL << (o1.imm & 63U);
            }
            ssa_ir *jcc = ssa_push_llir(c, in->ip, blk, SSA_OP_JCC);
            if (jcc) {
                snprintf(jcc->cc, sizeof(jcc->cc), "%s", strcmp(m, "tbz") == 0 ? "eq" : "ne");
                jcc->a0.kind = SSA_ARG_VA;
                jcc->a0.imm = in->target;
            }
            return;
        }
        ssa_ir *ir = ssa_push_llir(c, in->ip, blk, SSA_OP_JCC);
        if (!ir) return;
        const char *dot = strchr(m, '.');
        ssa_norm_cc(dot ? (dot + 1) : m, ir->cc);
        ir->a0.kind = SSA_ARG_VA;
        ir->a0.imm = in->target;
        return;
    }

    if (strcmp(m, "cmp") == 0 || strcmp(m, "cmn") == 0 || strcmp(m, "tst") == 0) {
        ssa_ir *ir = ssa_push_llir(c, in->ip, blk, SSA_OP_CMP);
        if (!ir) return;
        ir->is_test = (strcmp(m, "tst") == 0) ? 1 : 0;
        ir->bits = (uint8_t)(o0.bits ? o0.bits : 64);
        ir->a0 = o0;
        ir->a1 = o1;
        return;
    }

    if ((strcmp(m, "adrp") == 0 || strcmp(m, "adr") == 0) && o0.kind == SSA_ARG_REG) {
        ssa_ir *ir = ssa_push_llir(c, in->ip, blk, SSA_OP_LEA);
        if (!ir) return;
        ir->dst_reg = o0.reg;
        ir->bits = 64;
        ir->a0.kind = SSA_ARG_MEM;
        ir->a0.reg = -1;
        ir->a0.idx = -1;
        ir->a0.imm = in->has_target ? in->target : o1.imm;
        return;
    }

    if ((strcmp(m, "movz") == 0 || strcmp(m, "movn") == 0 || strcmp(m, "movk") == 0) && o0.kind == SSA_ARG_REG) {
        int sh = (nops >= 3) ? ssa_a64_shift_amt(ops[2]) : 0;
        uint64_t val = (o1.imm & 0xFFFFULL) << (sh & 63);
        if (strcmp(m, "movn") == 0) val = ssa_mask(~val, o0.bits ? o0.bits : 64);
        if (strcmp(m, "movk") == 0) {
            ssa_ir *ir = ssa_push_llir(c, in->ip, blk, SSA_OP_OR);
            if (!ir) return;
            ir->dst_reg = o0.reg;
            ir->bits = (uint8_t)(o0.bits ? o0.bits : 64);
            ir->a0 = o0;
            ir->a1.kind = SSA_ARG_IMM;
            ir->a1.imm = val;
        } else {
            ssa_ir *ir = ssa_push_llir(c, in->ip, blk, SSA_OP_MOV);
            if (!ir) return;
            ir->dst_reg = o0.reg;
            ir->bits = (uint8_t)(o0.bits ? o0.bits : 64);
            ir->a0.kind = SSA_ARG_IMM;
            ir->a0.imm = val;
        }
        return;
    }

    if (strcmp(m, "mov") == 0 && o0.kind == SSA_ARG_REG) {
        ssa_ir *ir = ssa_push_llir(c, in->ip, blk, SSA_OP_MOV);
        if (!ir) return;
        ir->dst_reg = o0.reg;
        ir->bits = (uint8_t)(o0.bits ? o0.bits : 64);
        ir->a0 = o1;
        return;
    }

    if (strcmp(m, "mvn") == 0 && o0.kind == SSA_ARG_REG) {
        ssa_ir *ir = ssa_push_llir(c, in->ip, blk, SSA_OP_NOT);
        if (!ir) return;
        ir->dst_reg = o0.reg;
        ir->bits = (uint8_t)(o0.bits ? o0.bits : 64);
        ir->a0 = (nops >= 3) ? o2 : o1;
        return;
    }

    if (strcmp(m, "ldr") == 0 || strcmp(m, "ldrh") == 0 || strcmp(m, "ldrb") == 0) {
        if (o0.kind != SSA_ARG_REG) return;
        uint8_t bw = (strcmp(m, "ldrb") == 0) ? 8 : (strcmp(m, "ldrh") == 0 ? 16 : (uint8_t)(o0.bits ? o0.bits : 64));
        ssa_ir *ir = ssa_push_llir(c, in->ip, blk, SSA_OP_LOAD);
        if (!ir) return;
        ir->dst_reg = o0.reg;
        ir->bits = bw;
        ir->a0 = o1;
        ir->a0.bits = bw;
        return;
    }

    if (strcmp(m, "str") == 0 || strcmp(m, "strh") == 0 || strcmp(m, "strb") == 0) {
        uint8_t bw = (strcmp(m, "strb") == 0) ? 8 : (strcmp(m, "strh") == 0 ? 16 : (uint8_t)(o0.bits ? o0.bits : 64));
        ssa_ir *ir = ssa_push_llir(c, in->ip, blk, SSA_OP_STORE);
        if (!ir) return;
        ir->bits = bw;
        ir->a0 = o1;
        ir->a0.bits = bw;
        ir->a1 = o0;
        return;
    }

    if (strcmp(m, "ldp") == 0 || strcmp(m, "stp") == 0) {
        int is_ld = (m[0] == 'l');
        uint8_t bw = (uint8_t)(o0.bits ? o0.bits : 64);
        int64_t step = bw / 8;
        ssa_arg m0 = o2, m1 = o2;
        m0.bits = bw;
        m1.bits = bw;
        m1.disp += step;
        if (is_ld) {
            if (o0.kind == SSA_ARG_REG) {
                ssa_ir *a = ssa_push_llir(c, in->ip, blk, SSA_OP_LOAD);
                if (a) { a->dst_reg = o0.reg; a->bits = bw; a->a0 = m0; }
            }
            if (o1.kind == SSA_ARG_REG) {
                ssa_ir *b = ssa_push_llir(c, in->ip, blk, SSA_OP_LOAD);
                if (b) { b->dst_reg = o1.reg; b->bits = bw; b->a0 = m1; }
            }
        } else {
            ssa_ir *a = ssa_push_llir(c, in->ip, blk, SSA_OP_STORE);
            if (a) { a->bits = bw; a->a0 = m0; a->a1 = o0; }
            ssa_ir *b = ssa_push_llir(c, in->ip, blk, SSA_OP_STORE);
            if (b) { b->bits = bw; b->a0 = m1; b->a1 = o1; }
        }
        return;
    }

    if (strcmp(m, "csel") == 0 && o0.kind == SSA_ARG_REG) {
        ssa_ir *ir = ssa_push_llir(c, in->ip, blk, SSA_OP_SEL);
        if (!ir) return;
        ir->dst_reg = o0.reg;
        ir->bits = (uint8_t)(o0.bits ? o0.bits : 64);
        ssa_norm_cc(ops[3], ir->cc);
        ir->a0 = o1;
        ir->a1 = o2;
        return;
    }

    if ((strcmp(m, "mul") == 0 || strcmp(m, "madd") == 0) && o0.kind == SSA_ARG_REG) {
        ssa_ir *ir = ssa_push_llir(c, in->ip, blk, SSA_OP_MUL);
        if (!ir) return;
        ir->dst_reg = o0.reg;
        ir->bits = (uint8_t)(o0.bits ? o0.bits : 64);
        ir->a0 = o1;
        ir->a1 = o2;
        if (strcmp(m, "madd") == 0 && o3.kind == SSA_ARG_REG) {
            ssa_ir *add = ssa_push_llir(c, in->ip, blk, SSA_OP_ADD);
            if (add) {
                add->dst_reg = o0.reg;
                add->bits = ir->bits;
                add->a0 = o0;
                add->a1 = o3;
            }
        }
        return;
    }

    uint8_t op = SSA_OP_NOP;
    uint8_t sgn = 0;
    if (strcmp(m, "add") == 0 || strcmp(m, "adds") == 0) op = SSA_OP_ADD;
    else if (strcmp(m, "sub") == 0 || strcmp(m, "subs") == 0) op = SSA_OP_SUB;
    else if (strcmp(m, "and") == 0 || strcmp(m, "ands") == 0 || strcmp(m, "bic") == 0) op = SSA_OP_AND;
    else if (strcmp(m, "orr") == 0) op = SSA_OP_OR;
    else if (strcmp(m, "eor") == 0) op = SSA_OP_XOR;
    else if (strcmp(m, "lsl") == 0) op = SSA_OP_SHL;
    else if (strcmp(m, "lsr") == 0) op = SSA_OP_SHR;
    else if (strcmp(m, "asr") == 0) { op = SSA_OP_SAR; sgn = 1; }
    else if (strcmp(m, "ror") == 0) op = SSA_OP_ROR;
    else if (strcmp(m, "sdiv") == 0) { op = SSA_OP_DIV; sgn = 1; }
    else if (strcmp(m, "udiv") == 0) op = SSA_OP_DIV;
    else if (strcmp(m, "fadd") == 0) op = SSA_OP_FADD;
    else if (strcmp(m, "fsub") == 0) op = SSA_OP_FSUB;
    else if (strcmp(m, "fmul") == 0) op = SSA_OP_FMUL;
    else if (strcmp(m, "fdiv") == 0) op = SSA_OP_FDIV;

    if (op != SSA_OP_NOP && o0.kind == SSA_ARG_REG) {
        ssa_ir *ir = ssa_push_llir(c, in->ip, blk, op);
        if (!ir) return;
        ir->dst_reg = o0.reg;
        ir->bits = (uint8_t)(o0.bits ? o0.bits : 64);
        ir->is_signed = sgn;
        if (op == SSA_OP_FADD || op == SSA_OP_FSUB || op == SSA_OP_FMUL || op == SSA_OP_FDIV) {
            ir->is_flt = (ir->bits == 64) ? 2 : 1;
        }
        ir->a0 = o1;
        ir->a1 = o2;
    }
}

static void ssa_lift_all(ssa_ctx *c) {
    const grp_cfg *g = c->g;
    int ret_written = 0;
    int fp_ret_written = 0;

    for (uint32_t b = 0; b < c->nblk; b++) {
        c->llir_first[b] = c->nllir;
        const grp_blk *gb = &g->blks[b];
        for (uint32_t k = 0; k < gb->ins_count; k++) {
            const x86_ins *in = &g->ins[gb->ins_first + k];
            if (c->is_arm64) ssa_lift_a64(c, (uint16_t)b, in);
            else ssa_lift_x86(c, (uint16_t)b, in);
        }
        c->llir_count[b] = c->nllir - c->llir_first[b];

        // attach explicit ABI call args and return register use
        uint32_t written_args = 0;
        for (uint32_t i = c->llir_first[b]; i < c->llir_first[b] + c->llir_count[b]; i++) {
            ssa_ir *ir = &c->llir[i];
            if (ir->dst_reg == c->ret_reg) ret_written = 1;
            if (!c->is_arm64 && ir->dst_reg == 16 && ir->is_flt) fp_ret_written = 1;
            if (ir->op == SSA_OP_CALL) {
                const ssa_api_sig *api = ssa_api_find(ir->sym);
                int na = 0;
                if (api) {
                    na = (api->narg < c->narg_abi) ? api->narg : c->narg_abi;
                } else {
                    int max_idx = -1;
                    for (int k = 0; k < c->narg_abi; k++) {
                        if (written_args & (1u << k)) max_idx = k;
                    }
                    na = (max_idx >= 0) ? (max_idx + 1) : 0;
                }
                ir->call_narg = (uint8_t)na;
                for (int k = 0; k < na; k++) ir->call_regs[k] = (int8_t)c->arg_regs[k];
                written_args = 0;
            } else if (ir->dst_reg >= 0) {
                for (int k = 0; k < c->narg_abi; k++) {
                    if (c->arg_regs[k] == ir->dst_reg) written_args |= (1u << k);
                }
            }
        }
    }

    for (uint32_t i = 0; i < c->nllir; i++) {
        ssa_ir *ir = &c->llir[i];
        if (ir->op != SSA_OP_RET) continue;
        if (ret_written) {
            ir->a0.kind = SSA_ARG_REG;
            ir->a0.reg = (int8_t)c->ret_reg;
            ir->a0.bits = (uint16_t)c->ptr_bits;
        } else if (fp_ret_written) {
            ir->a0.kind = SSA_ARG_REG;
            ir->a0.reg = 16;
            ir->a0.bits = 64;
            ir->a0.is_flt = 2;
        }
    }
}

static const char *ssa_op_name(const ssa_ir *ir) {
    if (ir->op == SSA_OP_MUL && ir->is_mulhi) return "mulhi";
    if (ir->op == SSA_OP_CMP && ir->is_test) return "test";
    if (ir->op == SSA_OP_CMP && ir->is_flt) return "fcmp";
    switch (ir->op) {
    case SSA_OP_MOV:   return "mov";
    case SSA_OP_LOAD:  return "load";
    case SSA_OP_STORE: return "store";
    case SSA_OP_LEA:   return "lea";
    case SSA_OP_ADD:   return "add";
    case SSA_OP_SUB:   return "sub";
    case SSA_OP_MUL:   return "mul";
    case SSA_OP_DIV:   return "div";
    case SSA_OP_SHL:   return "shl";
    case SSA_OP_SHR:   return "shr";
    case SSA_OP_SAR:   return "sar";
    case SSA_OP_ROL:   return "rol";
    case SSA_OP_ROR:   return "ror";
    case SSA_OP_AND:   return "and";
    case SSA_OP_OR:    return "or";
    case SSA_OP_XOR:   return "xor";
    case SSA_OP_NOT:   return "not";
    case SSA_OP_NEG:   return "neg";
    case SSA_OP_ZEXT:  return "zext";
    case SSA_OP_SEXT:  return "sext";
    case SSA_OP_CMP:   return "cmp";
    case SSA_OP_JCC:   return "jcc";
    case SSA_OP_JMP:   return "jmp";
    case SSA_OP_CALL:  return "call";
    case SSA_OP_RET:   return "ret";
    case SSA_OP_FADD:  return "fadd";
    case SSA_OP_FSUB:  return "fsub";
    case SSA_OP_FMUL:  return "fmul";
    case SSA_OP_FDIV:  return "fdiv";
    case SSA_OP_PHI:   return "phi";
    case SSA_OP_SEL:   return "sel";
    default:           return "nop";
    }
}

static void ssa_width_tag(const ssa_ir *ir, char out[8]) {
    if (ir->is_flt == 1) { snprintf(out, 8, "f32"); return; }
    if (ir->is_flt == 2) { snprintf(out, 8, "f64"); return; }
    int b = ir->bits ? ir->bits : 64;
    snprintf(out, 8, "%c%d", ir->is_signed ? 'i' : 'u', b);
}

static void ssa_fmt_reg_ref(const ssa_ctx *c, int reg, int ver, int bits, int is_ssa, char *dst, size_t cap) {
    if (is_ssa && ver > 0) ssa_ver_name(c, ver, dst, cap);
    else snprintf(dst, cap, "%s", ssa_reg_name(c, reg, bits));
}

static void ssa_fmt_arg(const ssa_ctx *c, const ssa_arg *a, int is_ssa, char *dst, size_t cap) {
    if (a->kind == SSA_ARG_NONE) { snprintf(dst, cap, "0x0"); return; }
    if (a->folded) { ssa_fmt_imm(a->fval, dst, cap); return; }
    if (a->kind == SSA_ARG_IMM || a->kind == SSA_ARG_VA) {
        ssa_fmt_imm(a->imm, dst, cap);
        return;
    }
    if (a->kind == SSA_ARG_REG) {
        ssa_fmt_reg_ref(c, a->reg, a->ver, a->bits ? a->bits : c->ptr_bits, is_ssa, dst, cap);
        return;
    }
    if (a->kind == SSA_ARG_MEM) {
        if (a->reg < 0 && a->idx < 0) {
            const char *sym = a->imm ? ana_sym_at(c->a, a->imm) : NULL;
            if (sym) {
                char clean[48];
                ssa_clean_sym(sym, clean, sizeof(clean));
                snprintf(dst, cap, "[%s]", clean);
            } else {
                snprintf(dst, cap, "[0x%llx]", (unsigned long long)a->imm);
            }
            return;
        }
        char buf[96] = "";
        size_t pos = 0;
        ssa_append(buf, sizeof(buf), &pos, "[");
        int any = 0;
        if (a->reg >= 0) {
            char rn[24];
            ssa_fmt_reg_ref(c, a->reg, a->ver, c->ptr_bits, is_ssa, rn, sizeof(rn));
            ssa_append(buf, sizeof(buf), &pos, "%s", rn);
            any = 1;
        }
        if (a->idx >= 0) {
            char iname[24];
            ssa_fmt_reg_ref(c, a->idx, a->idx_ver, c->ptr_bits, is_ssa, iname, sizeof(iname));
            if (any) ssa_append(buf, sizeof(buf), &pos, " + ");
            if (a->scale > 1) ssa_append(buf, sizeof(buf), &pos, "%s*%u", iname, a->scale);
            else ssa_append(buf, sizeof(buf), &pos, "%s", iname);
            any = 1;
        }
        if (a->disp != 0) {
            if (!any) ssa_append(buf, sizeof(buf), &pos, "0x%llx", (unsigned long long)(uint64_t)a->disp);
            else if (a->disp < 0) ssa_append(buf, sizeof(buf), &pos, " - 0x%llx", (unsigned long long)(-a->disp));
            else ssa_append(buf, sizeof(buf), &pos, " + 0x%llx", (unsigned long long)a->disp);
        } else if (!any) {
            ssa_append(buf, sizeof(buf), &pos, "0x0");
        }
        ssa_append(buf, sizeof(buf), &pos, "]");
        snprintf(dst, cap, "%s", buf);
        return;
    }
    snprintf(dst, cap, "?");
}

static void ssa_fmt_ir_text(const ssa_ctx *c, const ssa_ir *ir, int is_ssa, char *dst, size_t cap) {
    char dname[24] = "";
    if (ir->dst_reg >= 0) {
        ssa_fmt_reg_ref(c, ir->dst_reg, ir->dst_ver, ir->bits ? ir->bits : c->ptr_bits, is_ssa, dname, sizeof(dname));
    }
    char wt[8];
    ssa_width_tag(ir, wt);

    if (ir->is_phi) {
        size_t pos = 0;
        dst[0] = 0;
        ssa_append(dst, cap, &pos, "%s = phi(", dname);
        for (uint32_t k = 0; k < ir->phi_count; k++) {
            const ssa_phi_in *pi = &c->phi_pool[ir->phi_first + k];
            char vn[24];
            ssa_ver_name(c, pi->ver, vn, sizeof(vn));
            if (k) ssa_append(dst, cap, &pos, ", ");
            if (pi->blk == 0xFFFF) ssa_append(dst, cap, &pos, "entry: %s", vn);
            else ssa_append(dst, cap, &pos, "B%u: %s", pi->blk, vn);
        }
        ssa_append(dst, cap, &pos, ")");
        return;
    }

    char s0[96] = "", s1[96] = "";
    ssa_fmt_arg(c, &ir->a0, is_ssa, s0, sizeof(s0));
    ssa_fmt_arg(c, &ir->a1, is_ssa, s1, sizeof(s1));

    if (ir->op == SSA_OP_CALL) {
        size_t pos = 0;
        dst[0] = 0;
        const char *tgt = ir->sym[0] ? ir->sym : s0;
        ssa_append(dst, cap, &pos, "%s = call %s(", dname, tgt);
        for (int k = 0; k < ir->call_narg; k++) {
            if (k) ssa_append(dst, cap, &pos, ", ");
            if (is_ssa && ir->call_vers[k] > 0 && c->vers[ir->call_vers[k]].lat == SSA_LAT_CONST) {
                char cv[24];
                ssa_fmt_imm(c->vers[ir->call_vers[k]].cval, cv, sizeof(cv));
                ssa_append(dst, cap, &pos, "%s", cv);
            } else {
                char an[24];
                ssa_fmt_reg_ref(c, ir->call_regs[k], ir->call_vers[k], c->ptr_bits, is_ssa, an, sizeof(an));
                ssa_append(dst, cap, &pos, "%s", an);
            }
        }
        ssa_append(dst, cap, &pos, ")");
        return;
    }
    if (ir->op == SSA_OP_RET) {
        if (ir->a0.kind != SSA_ARG_NONE) snprintf(dst, cap, "ret %s", s0);
        else snprintf(dst, cap, "ret");
        return;
    }
    if (ir->op == SSA_OP_JCC) {
        snprintf(dst, cap, "jcc.%s %s", ir->cc[0] ? ir->cc : "cc", s0);
        return;
    }
    if (ir->op == SSA_OP_JMP) {
        snprintf(dst, cap, "jmp %s", s0);
        return;
    }
    if (ir->op == SSA_OP_CMP) {
        snprintf(dst, cap, "flags = %s.%s %s, %s", ssa_op_name(ir), wt, s0, s1);
        return;
    }
    if (ir->op == SSA_OP_STORE) {
        snprintf(dst, cap, "store.%s %s, %s", wt, s0, s1);
        return;
    }
    if (ir->op == SSA_OP_LOAD || ir->op == SSA_OP_LEA || ir->op == SSA_OP_MOV ||
        ir->op == SSA_OP_NOT || ir->op == SSA_OP_NEG || ir->op == SSA_OP_ZEXT || ir->op == SSA_OP_SEXT) {
        snprintf(dst, cap, "%s = %s.%s %s", dname, ssa_op_name(ir), wt, s0);
        return;
    }
    if (ir->op == SSA_OP_SEL) {
        snprintf(dst, cap, "%s = sel.%s %s, %s", dname, ir->cc[0] ? ir->cc : "cc", s0, s1);
        return;
    }
    snprintf(dst, cap, "%s = %s.%s %s, %s", dname, ssa_op_name(ir), wt, s0, s1);
}

static void ssa_arg_use_bits(const ssa_arg *a, uint32_t *use_m, uint32_t def_m) {
    if (a->kind == SSA_ARG_REG && a->reg >= 0) {
        uint32_t bit = 1u << (unsigned)a->reg;
        if (!(def_m & bit)) *use_m |= bit;
    } else if (a->kind == SSA_ARG_MEM) {
        if (a->reg >= 0) {
            uint32_t bit = 1u << (unsigned)a->reg;
            if (!(def_m & bit)) *use_m |= bit;
        }
        if (a->idx >= 0) {
            uint32_t bit = 1u << (unsigned)a->idx;
            if (!(def_m & bit)) *use_m |= bit;
        }
    }
}

static void ssa_compute_liveness(ssa_ctx *c) {
    uint32_t sp_bit = 1u << (unsigned)c->sp_reg;
    for (uint32_t b = 0; b < c->nblk; b++) {
        uint32_t dm = 0, um = 0;
        for (uint32_t i = c->llir_first[b]; i < c->llir_first[b] + c->llir_count[b]; i++) {
            const ssa_ir *ir = &c->llir[i];
            int self_zero = (ir->op == SSA_OP_XOR || ir->op == SSA_OP_SUB) &&
                            ir->a0.kind == SSA_ARG_REG && ir->a1.kind == SSA_ARG_REG &&
                            ir->a0.reg == ir->a1.reg;
            if (!self_zero) {
                ssa_arg_use_bits(&ir->a0, &um, dm);
                ssa_arg_use_bits(&ir->a1, &um, dm);
                ssa_arg_use_bits(&ir->a2, &um, dm);
            }
            for (int k = 0; k < ir->call_narg; k++) {
                uint32_t bit = 1u << (unsigned)ir->call_regs[k];
                if (!(dm & bit)) um |= bit;
            }
            if (ir->dst_reg >= 0) dm |= (1u << (unsigned)ir->dst_reg);
        }
        c->def_mask[b] = dm & ~sp_bit;
        c->use_mask[b] = um & ~sp_bit;
        c->live_in[b] = c->use_mask[b];
        c->live_out[b] = 0;
    }

    int changed = 1;
    while (changed) {
        changed = 0;
        for (uint32_t b = 0; b < c->nblk; b++) {
            if (!c->reach[b]) continue;
            uint32_t lo = 0;
            for (uint32_t s = 0; s < c->nblk; s++) {
                if (ssa_bs_get(c->succ_bs[b], s)) lo |= c->live_in[s];
            }
            uint32_t li = c->use_mask[b] | (lo & ~c->def_mask[b]);
            if (lo != c->live_out[b] || li != c->live_in[b]) {
                c->live_out[b] = lo;
                c->live_in[b] = li;
                changed = 1;
            }
        }
    }
}

static void ssa_place_phis(ssa_ctx *c) {
    for (int r = 0; r < SSA_MAX_REGS; r++) {
        if (r == c->sp_reg) continue;
        uint32_t rbit = 1u << (unsigned)r;
        uint32_t wl[SSA_MAX_BLKS];
        uint32_t wh = 0, wt = 0;
        uint8_t in_wl[SSA_MAX_BLKS] = {0};
        uint8_t has_phi[SSA_MAX_BLKS] = {0};

        for (uint32_t b = 0; b < c->nblk; b++) {
            if (c->reach[b] && (c->def_mask[b] & rbit)) {
                wl[wt++] = b;
                in_wl[b] = 1;
            }
        }
        while (wh < wt) {
            uint32_t x = wl[wh++];
            for (uint32_t y = 0; y < c->nblk; y++) {
                if (!ssa_bs_get(c->df_bs[x], y)) continue;
                if (has_phi[y] || !(c->live_in[y] & rbit)) continue;
                has_phi[y] = 1;
                c->phi_mask[y] |= rbit;
                if (!in_wl[y] && wt < SSA_MAX_BLKS) {
                    in_wl[y] = 1;
                    wl[wt++] = y;
                }
            }
        }
    }
}

static ssa_ir *ssa_push_mlir(ssa_ctx *c) {
    if (c->nmlir == c->mlir_cap) {
        uint32_t nc = c->mlir_cap ? c->mlir_cap * 2 : 256;
        ssa_ir *nm = (ssa_ir *)realloc(c->mlir, (size_t)nc * sizeof(ssa_ir));
        if (!nm) return NULL;
        c->mlir = nm;
        c->mlir_cap = nc;
    }
    return &c->mlir[c->nmlir++];
}

static int ssa_new_ver(ssa_ctx *c, int reg, int def_ins, uint16_t bits, uint8_t is_flt) {
    if (c->nver == c->ver_cap) {
        int nc = c->ver_cap ? c->ver_cap * 2 : 256;
        ssa_ver *nv = (ssa_ver *)realloc(c->vers, (size_t)nc * sizeof(ssa_ver));
        if (!nv) return 0;
        c->vers = nv;
        c->ver_cap = nc;
    }
    int id = c->nver++;
    ssa_ver *v = &c->vers[id];
    memset(v, 0, sizeof(*v));
    v->reg = (int8_t)reg;
    v->bits = bits ? bits : (uint16_t)c->ptr_bits;
    v->is_flt = is_flt;
    v->def_ins = def_ins;
    v->idx = c->reg_ver_cnt[reg]++;
    return id;
}

static void ssa_rstack_push(ssa_ctx *c, int reg, int ver) {
    if (c->rstack_len[reg] == c->rstack_cap[reg]) {
        int nc = c->rstack_cap[reg] ? c->rstack_cap[reg] * 2 : 32;
        int *ns = (int *)realloc(c->rstack[reg], (size_t)nc * sizeof(int));
        if (!ns) return;
        c->rstack[reg] = ns;
        c->rstack_cap[reg] = nc;
    }
    c->rstack[reg][c->rstack_len[reg]++] = ver;

    if (c->push_len == c->push_cap) {
        int nc = c->push_cap ? c->push_cap * 2 : 256;
        int8_t *nl = (int8_t *)realloc(c->push_log, (size_t)nc * sizeof(int8_t));
        if (!nl) return;
        c->push_log = nl;
        c->push_cap = nc;
    }
    c->push_log[c->push_len++] = (int8_t)reg;
}

static int ssa_rstack_top(const ssa_ctx *c, int reg) {
    if (reg < 0 || reg >= SSA_MAX_REGS || c->rstack_len[reg] == 0) return 0;
    return c->rstack[reg][c->rstack_len[reg] - 1];
}

static void ssa_phi_add_in(ssa_ctx *c, ssa_ir *phi, uint16_t pblk, int ver) {
    if (c->nphi_pool == c->phi_cap) {
        uint32_t nc = c->phi_cap ? c->phi_cap * 2 : 128;
        ssa_phi_in *np = (ssa_phi_in *)realloc(c->phi_pool, (size_t)nc * sizeof(ssa_phi_in));
        if (!np) return;
        c->phi_pool = np;
        c->phi_cap = nc;
    }
    if (phi->phi_count == 0) phi->phi_first = c->nphi_pool;
    // keep each phi's entries contiguous by shifting only if needed
    uint32_t ins_at = phi->phi_first + phi->phi_count;
    if (ins_at < c->nphi_pool) {
        memmove(&c->phi_pool[ins_at + 1], &c->phi_pool[ins_at], (size_t)(c->nphi_pool - ins_at) * sizeof(ssa_phi_in));
        for (uint32_t i = 0; i < c->nmlir; i++) {
            if (c->mlir[i].is_phi && &c->mlir[i] != phi && c->mlir[i].phi_count > 0 && c->mlir[i].phi_first >= ins_at) {
                c->mlir[i].phi_first++;
            }
        }
    }
    c->phi_pool[ins_at].blk = pblk;
    c->phi_pool[ins_at].ver = ver;
    phi->phi_count++;
    c->nphi_pool++;
}

static void ssa_rename_arg(const ssa_ctx *c, ssa_arg *a) {
    if (a->kind == SSA_ARG_REG && a->reg >= 0) {
        a->ver = ssa_rstack_top(c, a->reg);
    } else if (a->kind == SSA_ARG_MEM) {
        if (a->reg >= 0) a->ver = ssa_rstack_top(c, a->reg);
        if (a->idx >= 0) a->idx_ver = ssa_rstack_top(c, a->idx);
    }
}

static void ssa_rename_blk(ssa_ctx *c, uint32_t b) {
    int mark = c->push_len;
    uint32_t end = c->mlir_first[b] + c->mlir_count[b];

    for (uint32_t i = c->mlir_first[b]; i < end; i++) {
        ssa_ir *ir = &c->mlir[i];
        if (!ir->is_phi) break;
        if (b == 0) ssa_phi_add_in(c, ir, 0xFFFF, ssa_rstack_top(c, ir->dst_reg));
        int v = ssa_new_ver(c, ir->dst_reg, (int)i, ir->bits, ir->is_flt);
        ir->dst_ver = v;
        ssa_rstack_push(c, ir->dst_reg, v);
    }

    for (uint32_t i = c->mlir_first[b]; i < end; i++) {
        ssa_ir *ir = &c->mlir[i];
        if (ir->is_phi) continue;
        // 1-op mul/imul reads pre-mul rax for the paired mulhi op
        int paired_hi = ir->is_mulhi && i > c->mlir_first[b] &&
                        c->mlir[i - 1].va == ir->va && c->mlir[i - 1].dst_reg == 0 &&
                        c->rstack_len[0] >= 2;
        int saved_rax = 0;
        if (paired_hi) {
            saved_rax = c->rstack[0][--c->rstack_len[0]];
        }
        ssa_rename_arg(c, &ir->a0);
        ssa_rename_arg(c, &ir->a1);
        ssa_rename_arg(c, &ir->a2);
        if (paired_hi) {
            c->rstack[0][c->rstack_len[0]++] = saved_rax;
        }
        for (int k = 0; k < ir->call_narg; k++) {
            ir->call_vers[k] = ssa_rstack_top(c, ir->call_regs[k]);
        }
        if (ir->dst_reg >= 0) {
            int v = ssa_new_ver(c, ir->dst_reg, (int)i, ir->bits, ir->is_flt);
            ir->dst_ver = v;
            ssa_rstack_push(c, ir->dst_reg, v);
        }
    }

    for (uint32_t s = 0; s < c->nblk; s++) {
        if (!ssa_bs_get(c->succ_bs[b], s)) continue;
        uint32_t send = c->mlir_first[s] + c->mlir_count[s];
        for (uint32_t i = c->mlir_first[s]; i < send; i++) {
            ssa_ir *phi = &c->mlir[i];
            if (!phi->is_phi) break;
            ssa_phi_add_in(c, phi, (uint16_t)b, ssa_rstack_top(c, phi->dst_reg));
        }
    }

    for (int ch = c->dom_head[b]; ch >= 0; ch = c->dom_next[ch]) {
        ssa_rename_blk(c, (uint32_t)ch);
    }

    while (c->push_len > mark) {
        int r = c->push_log[--c->push_len];
        if (c->rstack_len[r] > 1) c->rstack_len[r]--;
    }
}

static void ssa_build_mlir(ssa_ctx *c) {
    ssa_compute_liveness(c);
    ssa_place_phis(c);

    // reserve version 0 as sentinel
    ssa_new_ver(c, 0, -1, (uint16_t)c->ptr_bits, 0);
    c->reg_ver_cnt[0] = 0;

    for (int r = 0; r < SSA_MAX_REGS; r++) {
        uint8_t fl = (!c->is_arm64 && r >= 16) ? 1 : 0;
        int ev = ssa_new_ver(c, r, -1, (uint16_t)c->ptr_bits, fl);
        c->entry_ver[r] = ev;
        ssa_rstack_push(c, r, ev);
    }
    c->push_len = 0;

    for (uint32_t b = 0; b < c->nblk; b++) {
        c->mlir_first[b] = c->nmlir;
        if (c->reach[b]) {
            for (int r = 0; r < SSA_MAX_REGS; r++) {
                if (!(c->phi_mask[b] & (1u << (unsigned)r))) continue;
                ssa_ir *phi = ssa_push_mlir(c);
                if (!phi) continue;
                memset(phi, 0, sizeof(*phi));
                phi->va = c->g->blks[b].start;
                phi->blk = (uint16_t)b;
                phi->op = SSA_OP_PHI;
                phi->bits = (uint8_t)c->ptr_bits;
                phi->is_phi = 1;
                phi->dst_reg = (int8_t)r;
                phi->a0.reg = phi->a0.idx = -1;
                phi->a1.reg = phi->a1.idx = -1;
                phi->a2.reg = phi->a2.idx = -1;
                c->nphi++;
            }
        }
        for (uint32_t i = c->llir_first[b]; i < c->llir_first[b] + c->llir_count[b]; i++) {
            ssa_ir *dst = ssa_push_mlir(c);
            if (!dst) continue;
            *dst = c->llir[i];
            if (!c->reach[b]) dst->is_dead = 1;
        }
        c->mlir_count[b] = c->nmlir - c->mlir_first[b];
    }

    ssa_rename_blk(c, 0);
}

static uint64_t ssa_mulhi64(uint64_t a, uint64_t b, int is_signed) {
    uint64_t al = a & 0xFFFFFFFFULL, ah = a >> 32;
    uint64_t bl = b & 0xFFFFFFFFULL, bh = b >> 32;
    uint64_t p0 = al * bl;
    uint64_t p1 = al * bh;
    uint64_t p2 = ah * bl;
    uint64_t p3 = ah * bh;
    uint64_t cy = ((p0 >> 32) + (p1 & 0xFFFFFFFFULL) + (p2 & 0xFFFFFFFFULL)) >> 32;
    uint64_t hi = p3 + (p1 >> 32) + (p2 >> 32) + cy;
    if (is_signed) {
        if ((int64_t)a < 0) hi -= b;
        if ((int64_t)b < 0) hi -= a;
    }
    return hi;
}

static int ssa_arg_const(const ssa_ctx *c, const ssa_arg *a, uint64_t *val) {
    if (a->folded) { *val = a->fval; return 1; }
    if (a->kind == SSA_ARG_IMM || a->kind == SSA_ARG_VA) { *val = a->imm; return 1; }
    if (a->kind == SSA_ARG_REG && a->ver > 0 && c->vers[a->ver].lat == SSA_LAT_CONST) {
        *val = c->vers[a->ver].cval;
        return 1;
    }
    return 0;
}

static int ssa_eval_binop(const ssa_ir *ir, uint64_t x, uint64_t y, uint64_t *out) {
    int bits = ir->bits ? ir->bits : 64;
    uint32_t w = (bits == 8 || bits == 16 || bits == 32 || bits == 64) ? (uint32_t)bits : 64U;
    uint32_t sh = (uint32_t)(y & (w == 64 ? 63U : 31U));
    uint64_t mx = ssa_mask(x, (int)w);
    uint64_t my = ssa_mask(y, (int)w);
    uint64_t r = 0;

    switch (ir->op) {
    case SSA_OP_ADD: r = mx + my; break;
    case SSA_OP_SUB: r = mx - my; break;
    case SSA_OP_AND: r = mx & my; break;
    case SSA_OP_OR:  r = mx | my; break;
    case SSA_OP_XOR: r = mx ^ my; break;
    case SSA_OP_SHL: r = (sh < w) ? (mx << sh) : 0; break;
    case SSA_OP_SHR: r = (sh < w) ? (mx >> sh) : 0; break;
    case SSA_OP_SAR: {
        int64_t sx = ssa_sext_val(mx, (int)w);
        uint32_t ash = (sh < w) ? sh : (w - 1);
        r = (sx < 0 && ash > 0) ? (~(~(uint64_t)sx >> ash)) : ((uint64_t)sx >> ash);
        break;
    }
    case SSA_OP_ROL: {
        uint32_t s = (uint32_t)(y % w);
        r = s ? ((mx << s) | (mx >> (w - s))) : mx;
        break;
    }
    case SSA_OP_ROR: {
        uint32_t s = (uint32_t)(y % w);
        r = s ? ((mx >> s) | (mx << (w - s))) : mx;
        break;
    }
    case SSA_OP_MUL:
        if (ir->is_mulhi) {
            if (w <= 32) {
                if (ir->is_signed) {
                    int64_t p = ssa_sext_val(mx, (int)w) * ssa_sext_val(my, (int)w);
                    r = (uint64_t)p >> w;
                } else {
                    r = (mx * my) >> w;
                }
            } else {
                r = ssa_mulhi64(mx, my, ir->is_signed);
            }
        } else {
            r = mx * my;
        }
        break;
    case SSA_OP_DIV:
        if (my == 0) return 0;
        if (ir->is_signed) {
            int64_t sx = ssa_sext_val(mx, (int)w);
            int64_t sy = ssa_sext_val(my, (int)w);
            if (sy == 0 || (sx == (-9223372036854775807LL - 1) && sy == -1)) return 0;
            r = (uint64_t)(sx / sy);
        } else {
            r = mx / my;
        }
        break;
    default:
        return 0;
    }
    *out = ssa_mask(r, (int)w);
    return 1;
}

static int ssa_eval_unop(const ssa_ir *ir, uint64_t x, uint64_t *out) {
    int bits = ir->bits ? ir->bits : 64;
    if (ir->op == SSA_OP_NOT) { *out = ssa_mask(~x, bits); return 1; }
    if (ir->op == SSA_OP_NEG) { *out = ssa_mask(0ULL - x, bits); return 1; }
    if (ir->op == SSA_OP_ZEXT) {
        int sb = ir->src_bits ? ir->src_bits : 8;
        *out = ssa_mask(ssa_mask(x, sb), bits);
        return 1;
    }
    if (ir->op == SSA_OP_SEXT) {
        int sb = ir->src_bits ? ir->src_bits : 32;
        *out = ssa_mask((uint64_t)ssa_sext_val(x, sb), bits);
        return 1;
    }
    return 0;
}

static int ssa_match_magic_div(uint64_t m, int shift, int bits, int is_mulhi, uint64_t *divisor) {
    static const uint64_t divs[] = {3, 5, 6, 7, 9, 10, 12, 15, 100, 1000};
    if (bits == 64 && is_mulhi) {
        static const struct { uint64_t m; int s; uint64_t d; } m64[] = {
            {0x5555555555555556ULL, 0, 3},
            {0xAAAAAAAAAAAAAAABULL, 1, 3},
            {0x6666666666666667ULL, 1, 5},
            {0xCCCCCCCCCCCCCCCDULL, 2, 5},
            {0x2AAAAAAAAAAAAAABULL, 0, 6},
            {0x2492492492492493ULL, 0, 7},
            {0x4924924924924925ULL, 1, 7},
            {0x6666666666666667ULL, 2, 10},
            {0xCCCCCCCCCCCCCCCDULL, 3, 10},
            {0x51EB851EB851EB86ULL, 5, 100},
            {0xA3D70A3D70A3D70BULL, 6, 100}
        };
        for (size_t i = 0; i < sizeof(m64) / sizeof(m64[0]); i++) {
            if (m == m64[i].m && shift == m64[i].s) { *divisor = m64[i].d; return 1; }
        }
        return 0;
    }

    int total = is_mulhi ? (bits + shift) : shift;
    if (total < 32 || total > 62) return 0;
    uint64_t pow2 = 1ULL << (unsigned)total;
    for (size_t i = 0; i < sizeof(divs) / sizeof(divs[0]); i++) {
        uint64_t d = divs[i];
        uint64_t q = pow2 / d;
        uint64_t cm = (pow2 % d) ? (q + 1) : q;
        if (cm > 0xFFFFFFFFULL) continue;
        int match = (m == cm) || (is_mulhi && bits == 32 && (uint32_t)m == (uint32_t)cm) ||
                    ((uint64_t)(int64_t)(int32_t)(uint32_t)cm == m);
        if (match) {
            *divisor = d;
            return 1;
        }
    }
    return 0;
}

static int ssa_extract_mul_const(const ssa_ctx *c, const ssa_ir *mul, uint64_t *mval, ssa_arg *var_arg) {
    uint64_t c0 = 0, c1 = 0;
    int k0 = ssa_arg_const(c, &mul->a0, &c0);
    int k1 = ssa_arg_const(c, &mul->a1, &c1);
    if (k0 && !k1 && mul->a1.kind == SSA_ARG_REG) { *mval = c0; *var_arg = mul->a1; return 1; }
    if (k1 && !k0 && mul->a0.kind == SSA_ARG_REG) { *mval = c1; *var_arg = mul->a0; return 1; }
    return 0;
}

static void ssa_rewrite_magic_div(ssa_ctx *c) {
    if (c->nmlir == 0) return;
    uint8_t *used_hi = (uint8_t *)calloc(c->nmlir, 1);

    for (uint32_t i = 0; i < c->nmlir; i++) {
        ssa_ir *ir = &c->mlir[i];
        if (ir->is_dead || (ir->op != SSA_OP_SHR && ir->op != SSA_OP_SAR)) continue;
        if (ir->a0.kind != SSA_ARG_REG || ir->a0.ver <= 0) continue;
        uint64_t sh = 0;
        if (!ssa_arg_const(c, &ir->a1, &sh) || sh > 63) continue;
        int def_i = c->vers[ir->a0.ver].def_ins;
        if (def_i < 0) continue;
        const ssa_ir *def = &c->mlir[def_i];

        if (def->op == SSA_OP_MUL) {
            uint64_t mval = 0;
            ssa_arg var_a;
            uint64_t divisor = 0;
            if (ssa_extract_mul_const(c, def, &mval, &var_a) &&
                ssa_match_magic_div(mval, (int)sh, def->bits ? def->bits : 32, def->is_mulhi, &divisor)) {
                int was_sar = (ir->op == SSA_OP_SAR);
                ir->op = SSA_OP_DIV;
                ir->is_signed = (was_sar || def->is_signed) ? 1 : 0;
                ir->a0 = var_a;
                memset(&ir->a1, 0, sizeof(ir->a1));
                ir->a1.kind = SSA_ARG_IMM;
                ir->a1.reg = ir->a1.idx = -1;
                ir->a1.imm = divisor;
                if (used_hi) used_hi[def_i] = 1;
                c->nsccp++;
                continue;
            }
        }

        // signed /7 fixup: mulhi(x, 0x92492493) + add(hi, x) + sar 2
        if (def->op == SSA_OP_ADD && sh == 2) {
            const ssa_arg *mref = NULL, *xref = NULL;
            if (def->a0.kind == SSA_ARG_REG && def->a0.ver > 0 && c->vers[def->a0.ver].def_ins >= 0 &&
                c->mlir[c->vers[def->a0.ver].def_ins].op == SSA_OP_MUL) {
                mref = &def->a0;
                xref = &def->a1;
            } else if (def->a1.kind == SSA_ARG_REG && def->a1.ver > 0 && c->vers[def->a1.ver].def_ins >= 0 &&
                       c->mlir[c->vers[def->a1.ver].def_ins].op == SSA_OP_MUL) {
                mref = &def->a1;
                xref = &def->a0;
            }
            if (mref && xref && xref->kind == SSA_ARG_REG) {
                int mul_i = c->vers[mref->ver].def_ins;
                const ssa_ir *mul = &c->mlir[mul_i];
                uint64_t mval = 0;
                ssa_arg var_a;
                if (mul->is_mulhi && ssa_extract_mul_const(c, mul, &mval, &var_a) &&
                    var_a.ver == xref->ver &&
                    ((uint32_t)mval == 0x92492493U || mval == 0x9249249249249249ULL)) {
                    ir->op = SSA_OP_DIV;
                    ir->is_signed = 1;
                    ir->a0 = var_a;
                    memset(&ir->a1, 0, sizeof(ir->a1));
                    ir->a1.kind = SSA_ARG_IMM;
                    ir->a1.reg = ir->a1.idx = -1;
                    ir->a1.imm = 7;
                    if (used_hi) used_hi[mul_i] = 1;
                    c->nsccp++;
                }
            }
        }
    }

    for (uint32_t i = 0; i < c->nmlir; i++) {
        ssa_ir *ir = &c->mlir[i];
        if (ir->is_dead || (used_hi && used_hi[i])) continue;
        if (ir->op != SSA_OP_MUL || !ir->is_mulhi || !ir->is_signed) continue;
        uint64_t mval = 0;
        ssa_arg var_a;
        uint64_t divisor = 0;
        if (ssa_extract_mul_const(c, ir, &mval, &var_a) &&
            ssa_match_magic_div(mval, 0, ir->bits ? ir->bits : 32, 1, &divisor)) {
            ir->op = SSA_OP_DIV;
            ir->is_mulhi = 0;
            ir->a0 = var_a;
            memset(&ir->a1, 0, sizeof(ir->a1));
            ir->a1.kind = SSA_ARG_IMM;
            ir->a1.reg = ir->a1.idx = -1;
            ir->a1.imm = divisor;
            c->nsccp++;
        }
    }

    free(used_hi);
}

static void ssa_lat_meet(ssa_ver *dst, uint8_t lat, uint64_t val, int *changed) {
    if (lat == SSA_LAT_TOP) return;
    if (dst->lat == SSA_LAT_TOP) {
        dst->lat = lat;
        dst->cval = val;
        *changed = 1;
    } else if (dst->lat == SSA_LAT_CONST) {
        if (lat == SSA_LAT_BOT || dst->cval != val) {
            dst->lat = SSA_LAT_BOT;
            *changed = 1;
        }
    }
}

static void ssa_sccp_sub_arg(ssa_ctx *c, ssa_arg *a) {
    if (a->kind == SSA_ARG_REG && !a->folded && a->ver > 0 && c->vers[a->ver].lat == SSA_LAT_CONST) {
        a->folded = 1;
        a->fval = c->vers[a->ver].cval;
        c->nsccp++;
    }
}

static void ssa_run_sccp(ssa_ctx *c) {
    for (int v = 1; v < c->nver; v++) {
        c->vers[v].lat = (c->vers[v].def_ins < 0) ? SSA_LAT_BOT : SSA_LAT_TOP;
    }

    int changed = 1;
    for (int iter = 0; iter < 16 && changed; iter++) {
        changed = 0;
        for (uint32_t i = 0; i < c->nmlir; i++) {
            const ssa_ir *ir = &c->mlir[i];
            if (ir->is_dead || ir->dst_ver <= 0) continue;
            ssa_ver *dv = &c->vers[ir->dst_ver];
            if (dv->lat == SSA_LAT_BOT) continue;

            if (ir->is_phi) {
                uint8_t ml = SSA_LAT_TOP;
                uint64_t mv = 0;
                for (uint32_t k = 0; k < ir->phi_count; k++) {
                    int pv = c->phi_pool[ir->phi_first + k].ver;
                    if (pv <= 0 || pv == ir->dst_ver) continue;
                    const ssa_ver *in_v = &c->vers[pv];
                    if (in_v->lat == SSA_LAT_TOP) continue;
                    if (in_v->lat == SSA_LAT_BOT) { ml = SSA_LAT_BOT; break; }
                    if (ml == SSA_LAT_TOP) { ml = SSA_LAT_CONST; mv = in_v->cval; }
                    else if (mv != in_v->cval) { ml = SSA_LAT_BOT; break; }
                }
                ssa_lat_meet(dv, ml, mv, &changed);
                continue;
            }

            if ((ir->op == SSA_OP_XOR || ir->op == SSA_OP_SUB) &&
                ir->a0.kind == SSA_ARG_REG && ir->a1.kind == SSA_ARG_REG && ir->a0.ver == ir->a1.ver) {
                ssa_lat_meet(dv, SSA_LAT_CONST, 0, &changed);
                continue;
            }
            if ((ir->op == SSA_OP_AND || ir->op == SSA_OP_MUL) && !ir->is_mulhi) {
                uint64_t cv = 0;
                if ((ssa_arg_const(c, &ir->a0, &cv) && cv == 0) ||
                    (ssa_arg_const(c, &ir->a1, &cv) && cv == 0)) {
                    ssa_lat_meet(dv, SSA_LAT_CONST, 0, &changed);
                    continue;
                }
            }
            if (ir->op == SSA_OP_MOV) {
                uint64_t cv = 0;
                if (ssa_arg_const(c, &ir->a0, &cv)) {
                    ssa_lat_meet(dv, SSA_LAT_CONST, ssa_mask(cv, ir->bits ? ir->bits : 64), &changed);
                } else if (ir->a0.kind != SSA_ARG_REG || ir->a0.ver <= 0 || c->vers[ir->a0.ver].lat == SSA_LAT_BOT) {
                    ssa_lat_meet(dv, SSA_LAT_BOT, 0, &changed);
                }
                continue;
            }
            if (ir->op == SSA_OP_LEA && ir->a0.kind == SSA_ARG_MEM) {
                if (ir->a0.reg < 0 && ir->a0.idx < 0 && ir->a0.imm != 0) {
                    ssa_lat_meet(dv, SSA_LAT_CONST, ir->a0.imm, &changed);
                } else if (ir->a0.reg >= 0 && ir->a0.ver > 0 && c->vers[ir->a0.ver].lat == SSA_LAT_CONST &&
                           (ir->a0.idx < 0 || (ir->a0.idx_ver > 0 && c->vers[ir->a0.idx_ver].lat == SSA_LAT_CONST))) {
                    uint64_t base = c->vers[ir->a0.ver].cval;
                    uint64_t iv = (ir->a0.idx >= 0) ? c->vers[ir->a0.idx_ver].cval * ir->a0.scale : 0;
                    ssa_lat_meet(dv, SSA_LAT_CONST, base + iv + (uint64_t)ir->a0.disp, &changed);
                } else {
                    ssa_lat_meet(dv, SSA_LAT_BOT, 0, &changed);
                }
                continue;
            }
            if (ir->op == SSA_OP_NOT || ir->op == SSA_OP_NEG || ir->op == SSA_OP_ZEXT || ir->op == SSA_OP_SEXT) {
                uint64_t x = 0, r = 0;
                if (ssa_arg_const(c, &ir->a0, &x) && ssa_eval_unop(ir, x, &r)) {
                    ssa_lat_meet(dv, SSA_LAT_CONST, r, &changed);
                } else if (ir->a0.kind != SSA_ARG_REG || ir->a0.ver <= 0 || c->vers[ir->a0.ver].lat == SSA_LAT_BOT) {
                    ssa_lat_meet(dv, SSA_LAT_BOT, 0, &changed);
                }
                continue;
            }
            if (ir->op >= SSA_OP_ADD && ir->op <= SSA_OP_XOR) {
                uint64_t x = 0, y = 0, r = 0;
                int kx = ssa_arg_const(c, &ir->a0, &x);
                int ky = ssa_arg_const(c, &ir->a1, &y);
                if (kx && ky && ssa_eval_binop(ir, x, y, &r)) {
                    ssa_lat_meet(dv, SSA_LAT_CONST, r, &changed);
                } else {
                    int bx = (!kx && (ir->a0.kind != SSA_ARG_REG || ir->a0.ver <= 0 || c->vers[ir->a0.ver].lat == SSA_LAT_BOT));
                    int by = (!ky && (ir->a1.kind != SSA_ARG_REG || ir->a1.ver <= 0 || c->vers[ir->a1.ver].lat == SSA_LAT_BOT));
                    if (bx || by) ssa_lat_meet(dv, SSA_LAT_BOT, 0, &changed);
                }
                continue;
            }
            ssa_lat_meet(dv, SSA_LAT_BOT, 0, &changed);
        }
    }

    ssa_rewrite_magic_div(c);

    for (uint32_t i = 0; i < c->nmlir; i++) {
        ssa_ir *ir = &c->mlir[i];
        if (ir->is_dead || ir->is_phi) continue;
        if (ir->dst_ver > 0 && c->vers[ir->dst_ver].lat == SSA_LAT_CONST) {
            if (ir->op != SSA_OP_MOV || ir->a0.kind != SSA_ARG_IMM) {
                ir->op = SSA_OP_MOV;
                ir->is_mulhi = 0;
                memset(&ir->a0, 0, sizeof(ir->a0));
                memset(&ir->a1, 0, sizeof(ir->a1));
                ir->a0.kind = SSA_ARG_IMM;
                ir->a0.reg = ir->a0.idx = -1;
                ir->a0.imm = c->vers[ir->dst_ver].cval;
                ir->a1.reg = ir->a1.idx = -1;
                c->nsccp++;
            }
            continue;
        }

        // algebraic identities before substituting constants
        uint64_t y = 0;
        if (ir->a0.kind == SSA_ARG_REG && ssa_arg_const(c, &ir->a1, &y)) {
            int ident = ((ir->op == SSA_OP_ADD || ir->op == SSA_OP_SUB || ir->op == SSA_OP_OR ||
                          ir->op == SSA_OP_XOR || ir->op == SSA_OP_SHL || ir->op == SSA_OP_SHR ||
                          ir->op == SSA_OP_SAR) && y == 0) ||
                        (ir->op == SSA_OP_MUL && !ir->is_mulhi && y == 1) ||
                        (ir->op == SSA_OP_DIV && y == 1);
            if (ident) {
                ir->op = SSA_OP_MOV;
                memset(&ir->a1, 0, sizeof(ir->a1));
                ir->a1.reg = ir->a1.idx = -1;
                c->nsccp++;
                continue;
            }
        }

        ssa_sccp_sub_arg(c, &ir->a0);
        ssa_sccp_sub_arg(c, &ir->a1);
        ssa_sccp_sub_arg(c, &ir->a2);
        for (int k = 0; k < ir->call_narg; k++) {
            int cv = ir->call_vers[k];
            if (cv > 0 && c->vers[cv].lat == SSA_LAT_CONST) c->nsccp++;
        }
    }
}

static int ssa_resolve_ver(const ssa_ctx *c, int v) {
    int lim = 0;
    while (v > 0 && v < c->nver && c->vers[v].alias > 0 && lim < 32) {
        v = c->vers[v].alias;
        lim++;
    }
    return v;
}

static void ssa_apply_alias_arg(const ssa_ctx *c, ssa_arg *a) {
    if (a->folded) return;
    if (a->kind == SSA_ARG_REG && a->ver > 0) a->ver = ssa_resolve_ver(c, a->ver);
    else if (a->kind == SSA_ARG_MEM) {
        if (a->ver > 0) a->ver = ssa_resolve_ver(c, a->ver);
        if (a->idx_ver > 0) a->idx_ver = ssa_resolve_ver(c, a->idx_ver);
    }
}

static int ssa_is_gvn_pure(uint8_t op) {
    return (op >= SSA_OP_LEA && op <= SSA_OP_SEXT) ||
           (op >= SSA_OP_FADD && op <= SSA_OP_FDIV) || op == SSA_OP_SEL;
}

static int ssa_is_comm(uint8_t op) {
    return op == SSA_OP_ADD || op == SSA_OP_MUL || op == SSA_OP_AND ||
           op == SSA_OP_OR || op == SSA_OP_XOR || op == SSA_OP_FADD || op == SSA_OP_FMUL;
}

static int ssa_gvn_make(const ssa_ctx *c, const ssa_ir *ir, ssa_gvn_ent *e) {
    if (!ssa_is_gvn_pure(ir->op) || ir->dst_ver <= 0) return 0;
    memset(e, 0, sizeof(*e));
    e->op = ir->op;
    e->bits = ir->bits;
    e->flags = (uint8_t)((ir->is_flt << 2) | (ir->is_signed << 1) | ir->is_mulhi);
    e->dst_ver = ir->dst_ver;

    if (ir->op == SSA_OP_LEA) {
        e->k0_kind = ir->a0.kind;
        e->k0_ver = (ir->a0.reg >= 0) ? ssa_resolve_ver(c, ir->a0.ver) : -1;
        e->idx_ver = (ir->a0.idx >= 0) ? ssa_resolve_ver(c, ir->a0.idx_ver) : -1;
        e->scale = ir->a0.scale;
        e->k0_imm = (ir->a0.reg < 0 && ir->a0.idx < 0) ? ir->a0.imm : (uint64_t)ir->a0.disp;
        return 1;
    }

    if (ir->a0.kind == SSA_ARG_MEM || ir->a1.kind == SSA_ARG_MEM) return 0;
    if (ir->a0.folded || ir->a0.kind == SSA_ARG_IMM) {
        e->k0_kind = SSA_ARG_IMM;
        e->k0_imm = ir->a0.folded ? ir->a0.fval : ir->a0.imm;
    } else if (ir->a0.kind == SSA_ARG_REG) {
        e->k0_kind = SSA_ARG_REG;
        e->k0_ver = ssa_resolve_ver(c, ir->a0.ver);
    }
    if (ir->a1.folded || ir->a1.kind == SSA_ARG_IMM) {
        e->k1_kind = SSA_ARG_IMM;
        e->k1_imm = ir->a1.folded ? ir->a1.fval : ir->a1.imm;
    } else if (ir->a1.kind == SSA_ARG_REG) {
        e->k1_kind = SSA_ARG_REG;
        e->k1_ver = ssa_resolve_ver(c, ir->a1.ver);
    }

    if (ssa_is_comm(ir->op)) {
        int swap = (e->k0_kind > e->k1_kind) ||
                   (e->k0_kind == e->k1_kind && (e->k0_ver > e->k1_ver ||
                    (e->k0_ver == e->k1_ver && e->k0_imm > e->k1_imm)));
        if (swap) {
            uint8_t tk = e->k0_kind; e->k0_kind = e->k1_kind; e->k1_kind = tk;
            int tv = e->k0_ver; e->k0_ver = e->k1_ver; e->k1_ver = tv;
            uint64_t ti = e->k0_imm; e->k0_imm = e->k1_imm; e->k1_imm = ti;
        }
    }
    return 1;
}

static int ssa_gvn_eq(const ssa_gvn_ent *a, const ssa_gvn_ent *b) {
    return a->op == b->op && a->bits == b->bits && a->flags == b->flags &&
           a->k0_kind == b->k0_kind && a->k1_kind == b->k1_kind &&
           a->k0_ver == b->k0_ver && a->k1_ver == b->k1_ver &&
           a->k0_imm == b->k0_imm && a->k1_imm == b->k1_imm &&
           a->idx_ver == b->idx_ver && a->scale == b->scale;
}

static void ssa_gvn_blk(ssa_ctx *c, uint32_t b) {
    int mark = c->gvn_len;
    uint32_t end = c->mlir_first[b] + c->mlir_count[b];

    for (uint32_t i = c->mlir_first[b]; i < end; i++) {
        ssa_ir *ir = &c->mlir[i];
        if (ir->is_dead) continue;
        if (ir->is_phi) continue;

        ssa_apply_alias_arg(c, &ir->a0);
        ssa_apply_alias_arg(c, &ir->a1);
        ssa_apply_alias_arg(c, &ir->a2);
        for (int k = 0; k < ir->call_narg; k++) {
            ir->call_vers[k] = ssa_resolve_ver(c, ir->call_vers[k]);
        }

        if (ir->op == SSA_OP_MOV && ir->dst_ver > 0 && ir->a0.kind == SSA_ARG_REG &&
            !ir->a0.folded && ir->a0.ver > 0 && ir->bits == c->vers[ir->a0.ver].bits &&
            ir->is_flt == c->vers[ir->a0.ver].is_flt &&
            (c->is_arm64 || (ir->dst_reg < 16) == (c->vers[ir->a0.ver].reg < 16))) {
            c->vers[ir->dst_ver].alias = ssa_resolve_ver(c, ir->a0.ver);
            continue;
        }

        ssa_gvn_ent key;
        if (!ssa_gvn_make(c, ir, &key)) continue;

        int found = 0;
        for (int g = c->gvn_len - 1; g >= 0; g--) {
            if (ssa_gvn_eq(&c->gvn[g], &key)) {
                found = c->gvn[g].dst_ver;
                break;
            }
        }
        if (found > 0) {
            c->vers[ir->dst_ver].alias = found;
            ir->op = SSA_OP_MOV;
            ir->is_mulhi = 0;
            memset(&ir->a0, 0, sizeof(ir->a0));
            memset(&ir->a1, 0, sizeof(ir->a1));
            ir->a0.kind = SSA_ARG_REG;
            ir->a0.reg = c->vers[found].reg;
            ir->a0.idx = -1;
            ir->a0.bits = c->vers[found].bits;
            ir->a0.ver = found;
            ir->a1.reg = ir->a1.idx = -1;
            c->ngvn++;
        } else {
            if (c->gvn_len == c->gvn_cap) {
                int nc = c->gvn_cap ? c->gvn_cap * 2 : 128;
                ssa_gvn_ent *ng = (ssa_gvn_ent *)realloc(c->gvn, (size_t)nc * sizeof(ssa_gvn_ent));
                if (!ng) continue;
                c->gvn = ng;
                c->gvn_cap = nc;
            }
            c->gvn[c->gvn_len++] = key;
        }
    }

    for (int ch = c->dom_head[b]; ch >= 0; ch = c->dom_next[ch]) {
        ssa_gvn_blk(c, (uint32_t)ch);
    }
    c->gvn_len = mark;
}

static void ssa_run_gvn(ssa_ctx *c) {
    ssa_gvn_blk(c, 0);
    for (uint32_t i = 0; i < c->nmlir; i++) {
        ssa_ir *ir = &c->mlir[i];
        if (!ir->is_phi) continue;
        for (uint32_t k = 0; k < ir->phi_count; k++) {
            ssa_phi_in *pi = &c->phi_pool[ir->phi_first + k];
            pi->ver = ssa_resolve_ver(c, pi->ver);
        }
    }
}

static int ssa_is_essential(uint8_t op) {
    return op == SSA_OP_STORE || op == SSA_OP_CALL || op == SSA_OP_RET ||
           op == SSA_OP_JCC || op == SSA_OP_JMP || op == SSA_OP_CMP;
}

static void ssa_dce_push_ver(const ssa_ctx *c, int ver, uint8_t *live, uint32_t *wl, uint32_t *wt) {
    if (ver <= 0 || ver >= c->nver) return;
    int di = c->vers[ver].def_ins;
    if (di >= 0 && !live[di] && !c->mlir[di].is_dead) {
        live[di] = 1;
        wl[(*wt)++] = (uint32_t)di;
    }
}

static void ssa_dce_mark_arg(const ssa_ctx *c, const ssa_arg *a, uint8_t *live, uint32_t *wl, uint32_t *wt) {
    if (a->folded) return;
    if (a->kind == SSA_ARG_REG) ssa_dce_push_ver(c, a->ver, live, wl, wt);
    else if (a->kind == SSA_ARG_MEM) {
        if (a->reg >= 0) ssa_dce_push_ver(c, a->ver, live, wl, wt);
        if (a->idx >= 0) ssa_dce_push_ver(c, a->idx_ver, live, wl, wt);
    }
}

static void ssa_run_dce(ssa_ctx *c) {
    if (c->nmlir == 0) return;
    uint8_t *live = (uint8_t *)calloc(c->nmlir, 1);
    uint32_t *wl = (uint32_t *)malloc((size_t)c->nmlir * sizeof(uint32_t));
    if (!live || !wl) { free(live); free(wl); return; }

    uint32_t wh = 0, wt = 0;
    int last_ret_def = -1;
    for (uint32_t i = 0; i < c->nmlir; i++) {
        if (c->mlir[i].is_dead) continue;
        if (c->mlir[i].dst_reg == c->ret_reg) last_ret_def = (int)i;
        if (ssa_is_essential(c->mlir[i].op)) {
            live[i] = 1;
            wl[wt++] = i;
        }
    }
    if (wt == 0 && last_ret_def >= 0) {
        live[last_ret_def] = 1;
        wl[wt++] = (uint32_t)last_ret_def;
    }

    while (wh < wt) {
        const ssa_ir *ir = &c->mlir[wl[wh++]];
        if (ir->is_phi) {
            for (uint32_t k = 0; k < ir->phi_count; k++) {
                ssa_dce_push_ver(c, c->phi_pool[ir->phi_first + k].ver, live, wl, &wt);
            }
            continue;
        }
        ssa_dce_mark_arg(c, &ir->a0, live, wl, &wt);
        ssa_dce_mark_arg(c, &ir->a1, live, wl, &wt);
        ssa_dce_mark_arg(c, &ir->a2, live, wl, &wt);
        for (int k = 0; k < ir->call_narg; k++) {
            int cv = ir->call_vers[k];
            if (cv > 0 && c->vers[cv].lat != SSA_LAT_CONST) ssa_dce_push_ver(c, cv, live, wl, &wt);
        }
    }

    for (int v = 0; v < c->nver; v++) c->vers[v].use_cnt = 0;
    for (uint32_t i = 0; i < c->nmlir; i++) {
        ssa_ir *ir = &c->mlir[i];
        if (ir->is_dead) continue;
        if (!live[i]) {
            ir->is_dead = 1;
            c->ndce++;
            continue;
        }
        if (ir->is_phi) {
            for (uint32_t k = 0; k < ir->phi_count; k++) {
                int pv = c->phi_pool[ir->phi_first + k].ver;
                if (pv > 0 && pv < c->nver) c->vers[pv].use_cnt++;
            }
            continue;
        }
        const ssa_arg *as[3] = {&ir->a0, &ir->a1, &ir->a2};
        for (int k = 0; k < 3; k++) {
            if (as[k]->folded) continue;
            if (as[k]->kind == SSA_ARG_REG && as[k]->ver > 0) c->vers[as[k]->ver].use_cnt++;
            else if (as[k]->kind == SSA_ARG_MEM) {
                if (as[k]->reg >= 0 && as[k]->ver > 0) c->vers[as[k]->ver].use_cnt++;
                if (as[k]->idx >= 0 && as[k]->idx_ver > 0) c->vers[as[k]->idx_ver].use_cnt++;
            }
        }
        for (int k = 0; k < ir->call_narg; k++) {
            int cv = ir->call_vers[k];
            if (cv > 0 && cv < c->nver) c->vers[cv].use_cnt++;
        }
    }

    free(live);
    free(wl);
}

static int ssa_ty_rank(uint8_t t) {
    if (t == SSA_TY_UNK) return 0;
    if (t >= SSA_TY_I8 && t <= SSA_TY_U64) return 1;
    if (t == SSA_TY_SIZE_T || t == SSA_TY_BOOL || t == SSA_TY_FLOAT || t == SSA_TY_DOUBLE) return 2;
    if (t == SSA_TY_PTR) return 3;
    if (t == SSA_TY_STRUCT) return 4;
    return 5;
}

static const char *ssa_ty_name(uint8_t t) {
    switch (t) {
    case SSA_TY_I8:      return "int8_t";
    case SSA_TY_U8:      return "uint8_t";
    case SSA_TY_I16:     return "int16_t";
    case SSA_TY_U16:     return "uint16_t";
    case SSA_TY_I32:     return "int32_t";
    case SSA_TY_U32:     return "uint32_t";
    case SSA_TY_I64:     return "int64_t";
    case SSA_TY_U64:     return "uint64_t";
    case SSA_TY_SIZE_T:  return "size_t";
    case SSA_TY_BOOL:    return "BOOL";
    case SSA_TY_FLOAT:   return "float";
    case SSA_TY_DOUBLE:  return "double";
    case SSA_TY_PTR:     return "void *";
    case SSA_TY_STRUCT:  return "struct *";
    case SSA_TY_CSTR:    return "const char *";
    case SSA_TY_WSTR:    return "const wchar_t *";
    case SSA_TY_HANDLE:  return "HANDLE";
    case SSA_TY_HMODULE: return "HMODULE";
    case SSA_TY_FARPROC: return "FARPROC";
    case SSA_TY_HWND:    return "HWND";
    case SSA_TY_HKEY:    return "HKEY";
    case SSA_TY_SOCKET:  return "SOCKET";
    case SSA_TY_FILE:    return "FILE *";
    case SSA_TY_VOID:    return "void";
    default:             return "uint64_t";
    }
}

static uint8_t ssa_ty_int(int bits, int is_signed) {
    if (bits == 8) return is_signed ? SSA_TY_I8 : SSA_TY_U8;
    if (bits == 16) return is_signed ? SSA_TY_I16 : SSA_TY_U16;
    if (bits == 32) return is_signed ? SSA_TY_I32 : SSA_TY_U32;
    return is_signed ? SSA_TY_I64 : SSA_TY_U64;
}

static int ssa_ty_constrain(ssa_ctx *c, int ver, uint8_t ty) {
    if (ver <= 0 || ver >= c->nver || ty == SSA_TY_UNK || ty == SSA_TY_VOID) return 0;
    ssa_ver *v = &c->vers[ver];
    int r_old = ssa_ty_rank(v->ty);
    int r_new = ssa_ty_rank(ty);
    if (r_new > r_old) {
        v->ty = ty;
        return 1;
    }
    if (r_new == 1 && r_old == 1 && v->ty != ty) {
        // prefer signed when explicitly constrained by sar/sext/signed-cmp
        int new_s = (ty == SSA_TY_I8 || ty == SSA_TY_I16 || ty == SSA_TY_I32 || ty == SSA_TY_I64);
        int old_s = (v->ty == SSA_TY_I8 || v->ty == SSA_TY_I16 || v->ty == SSA_TY_I32 || v->ty == SSA_TY_I64);
        if (new_s && !old_s) {
            v->ty = ty;
            return 1;
        }
    }
    return 0;
}

static void ssa_ty_note_mem(ssa_ctx *c, const ssa_arg *m) {
    if (m->kind != SSA_ARG_MEM) return;
    if (m->reg >= 0 && m->reg != c->sp_reg && m->ver > 0 && m->ver < c->nver) {
        ssa_ver *v = &c->vers[m->ver];
        if (v->deref_cnt < 255) v->deref_cnt++;
        if (m->disp > 0 && m->disp < 0x10000) v->deref_nz = 1;
        ssa_ty_constrain(c, m->ver, (v->deref_nz && v->deref_cnt >= 2) ? SSA_TY_STRUCT : SSA_TY_PTR);
    }
    if (m->idx >= 0 && m->idx_ver > 0) {
        ssa_ty_constrain(c, m->idx_ver, SSA_TY_SIZE_T);
    }
}

static void ssa_solve_types(ssa_ctx *c) {
    for (uint32_t i = 0; i < c->nmlir; i++) {
        const ssa_ir *ir = &c->mlir[i];
        if (ir->is_dead) continue;

        if (ir->op == SSA_OP_CALL) {
            const ssa_api_sig *api = ssa_api_find(ir->sym);
            if (api) {
                if (api->ret_ty != SSA_TY_VOID) ssa_ty_constrain(c, ir->dst_ver, api->ret_ty);
                for (int k = 0; k < ir->call_narg && k < api->narg; k++) {
                    ssa_ty_constrain(c, ir->call_vers[k], api->arg_ty[k]);
                }
            }
            continue;
        }

        if (ir->op == SSA_OP_LOAD || ir->op == SSA_OP_STORE) {
            ssa_ty_note_mem(c, &ir->a0);
            if (ir->op == SSA_OP_LOAD) {
                if (ir->is_flt) ssa_ty_constrain(c, ir->dst_ver, ir->is_flt == 2 ? SSA_TY_DOUBLE : SSA_TY_FLOAT);
                else ssa_ty_constrain(c, ir->dst_ver, ssa_ty_int(ir->bits, 0));
            }
            continue;
        }

        if (ir->op == SSA_OP_LEA) {
            if (ir->a0.reg < 0 && ir->a0.idx < 0 && ir->a0.imm) {
                const ana_str *st = ana_str_at(c->a, ir->a0.imm);
                if (st) ssa_ty_constrain(c, ir->dst_ver, st->wide ? SSA_TY_WSTR : SSA_TY_CSTR);
                else ssa_ty_constrain(c, ir->dst_ver, SSA_TY_PTR);
            } else {
                ssa_ty_constrain(c, ir->dst_ver, SSA_TY_PTR);
            }
            continue;
        }

        if (ir->op == SSA_OP_MOV && ir->a0.kind == SSA_ARG_IMM && ir->a0.imm > 0x10000) {
            const ana_str *st = ana_str_at(c->a, ir->a0.imm);
            if (st) ssa_ty_constrain(c, ir->dst_ver, st->wide ? SSA_TY_WSTR : SSA_TY_CSTR);
            else if (bin_sec_at(&c->a->bin, ir->a0.imm)) ssa_ty_constrain(c, ir->dst_ver, SSA_TY_PTR);
        }

        if (ir->op == SSA_OP_ZEXT) {
            ssa_ty_constrain(c, ir->a0.ver, ssa_ty_int(ir->src_bits ? ir->src_bits : 8, 0));
            ssa_ty_constrain(c, ir->dst_ver, ssa_ty_int(ir->bits, 0));
            continue;
        }
        if (ir->op == SSA_OP_SEXT) {
            ssa_ty_constrain(c, ir->a0.ver, ssa_ty_int(ir->src_bits ? ir->src_bits : 32, 1));
            ssa_ty_constrain(c, ir->dst_ver, ssa_ty_int(ir->bits, 1));
            continue;
        }
        if (ir->op == SSA_OP_SAR || (ir->op == SSA_OP_DIV && ir->is_signed)) {
            uint8_t st = ssa_ty_int(ir->bits, 1);
            ssa_ty_constrain(c, ir->dst_ver, st);
            ssa_ty_constrain(c, ir->a0.ver, st);
            continue;
        }
        if (ir->op == SSA_OP_SHR || (ir->op == SSA_OP_DIV && !ir->is_signed)) {
            uint8_t ut = ssa_ty_int(ir->bits, 0);
            ssa_ty_constrain(c, ir->dst_ver, ut);
            ssa_ty_constrain(c, ir->a0.ver, ut);
            continue;
        }
        if (ir->is_flt) {
            uint8_t ft = (ir->is_flt == 2) ? SSA_TY_DOUBLE : SSA_TY_FLOAT;
            ssa_ty_constrain(c, ir->dst_ver, ft);
            ssa_ty_constrain(c, ir->a0.ver, ft);
            ssa_ty_constrain(c, ir->a1.ver, ft);
            continue;
        }
        if (ir->op == SSA_OP_SEL && ir->bits == 8) {
            ssa_ty_constrain(c, ir->dst_ver, SSA_TY_BOOL);
            continue;
        }
        if (ir->op == SSA_OP_CMP) {
            for (uint32_t j = i + 1; j < c->nmlir && c->mlir[j].blk == ir->blk; j++) {
                uint8_t nop = c->mlir[j].op;
                if (nop == SSA_OP_CMP || nop == SSA_OP_CALL) break;
                if (nop != SSA_OP_JCC) continue;
                const char *cc = c->mlir[j].cc;
                int is_s = (strcmp(cc, "lt") == 0 || strcmp(cc, "le") == 0 || strcmp(cc, "gt") == 0 || strcmp(cc, "ge") == 0);
                int is_u = (strcmp(cc, "ult") == 0 || strcmp(cc, "ule") == 0 || strcmp(cc, "ugt") == 0 || strcmp(cc, "uge") == 0);
                if (is_s || is_u) {
                    uint8_t ct = ssa_ty_int(ir->bits, is_s);
                    ssa_ty_constrain(c, ir->a0.ver, ct);
                    ssa_ty_constrain(c, ir->a1.ver, ct);
                }
                break;
            }
        }
    }

    // bidirectional fixed-point propagation through mov/phi/sel
    int changed = 1;
    for (int iter = 0; iter < 8 && changed; iter++) {
        changed = 0;
        for (uint32_t i = 0; i < c->nmlir; i++) {
            const ssa_ir *ir = &c->mlir[i];
            if (ir->is_dead || ir->dst_ver <= 0) continue;
            uint8_t dt = c->vers[ir->dst_ver].ty;

            if (ir->is_phi) {
                uint16_t common_bits = 0;
                int same_bits = 1;
                for (uint32_t k = 0; k < ir->phi_count; k++) {
                    int pv = c->phi_pool[ir->phi_first + k].ver;
                    if (pv <= 0 || pv == ir->dst_ver) continue;
                    changed |= ssa_ty_constrain(c, ir->dst_ver, c->vers[pv].ty);
                    changed |= ssa_ty_constrain(c, pv, c->vers[ir->dst_ver].ty);
                    if (common_bits == 0) common_bits = c->vers[pv].bits;
                    else if (common_bits != c->vers[pv].bits) same_bits = 0;
                }
                if (same_bits && common_bits && c->vers[ir->dst_ver].bits != common_bits) {
                    c->vers[ir->dst_ver].bits = common_bits;
                }
            } else if (ir->op == SSA_OP_MOV && ir->a0.kind == SSA_ARG_REG && !ir->a0.folded && ir->a0.ver > 0 &&
                       ir->is_flt == c->vers[ir->a0.ver].is_flt &&
                       (c->is_arm64 || (ir->dst_reg < 16) == (c->vers[ir->a0.ver].reg < 16))) {
                changed |= ssa_ty_constrain(c, ir->dst_ver, c->vers[ir->a0.ver].ty);
                changed |= ssa_ty_constrain(c, ir->a0.ver, dt);
            } else if (ir->op == SSA_OP_SEL) {
                if (ir->a0.kind == SSA_ARG_REG && ir->a0.ver > 0) {
                    changed |= ssa_ty_constrain(c, ir->dst_ver, c->vers[ir->a0.ver].ty);
                    changed |= ssa_ty_constrain(c, ir->a0.ver, c->vers[ir->dst_ver].ty);
                }
                if (ir->a1.kind == SSA_ARG_REG && ir->a1.ver > 0) {
                    changed |= ssa_ty_constrain(c, ir->dst_ver, c->vers[ir->a1.ver].ty);
                    changed |= ssa_ty_constrain(c, ir->a1.ver, c->vers[ir->dst_ver].ty);
                }
            } else if ((ir->op == SSA_OP_ADD || ir->op == SSA_OP_SUB) && ir->a0.kind == SSA_ARG_REG && ir->a0.ver > 0) {
                uint8_t bt = c->vers[ir->a0.ver].ty;
                if (bt == SSA_TY_PTR || bt == SSA_TY_STRUCT || bt == SSA_TY_CSTR || bt == SSA_TY_WSTR) {
                    changed |= ssa_ty_constrain(c, ir->dst_ver, SSA_TY_PTR);
                }
            }
        }
    }

    for (int v = 1; v < c->nver; v++) {
        if (c->vers[v].ty != SSA_TY_UNK) continue;
        if (c->vers[v].is_flt) c->vers[v].ty = (c->vers[v].is_flt == 2) ? SSA_TY_DOUBLE : SSA_TY_FLOAT;
        else c->vers[v].ty = ssa_ty_int(c->vers[v].bits, 0);
    }
}

static void ssa_fmt_typed_name(const char *ty, const char *name, char *dst, size_t cap) {
    size_t n = strlen(ty);
    if (n > 0 && ty[n - 1] == '*') snprintf(dst, cap, "%s%s", ty, name);
    else snprintf(dst, cap, "%s %s", ty, name);
}

static void ssa_build_proto(ssa_ctx *c, ssa_func *out) {
    uint8_t ret_ty = SSA_TY_VOID;
    int has_ret = 0;
    for (uint32_t i = 0; i < c->nmlir; i++) {
        const ssa_ir *ir = &c->mlir[i];
        if (ir->is_dead || ir->op != SSA_OP_RET) continue;
        if (ir->a0.kind == SSA_ARG_REG && ir->a0.ver > 0) {
            has_ret = 1;
            uint8_t vt = c->vers[ir->a0.ver].ty;
            if (ret_ty == SSA_TY_VOID || ssa_ty_rank(vt) > ssa_ty_rank(ret_ty)) ret_ty = vt;
        }
    }
    if (!has_ret) ret_ty = SSA_TY_VOID;

    int max_arg = -1;
    int arg_vers[8];
    for (int k = 0; k < c->narg_abi; k++) {
        int ev = c->entry_ver[c->arg_regs[k]];
        int fv = (!c->is_arm64 && k < 4) ? c->entry_ver[16 + k] : 0;
        if (ev > 0 && c->vers[ev].use_cnt > 0) {
            c->vers[ev].is_arg = 1;
            arg_vers[k] = ev;
            max_arg = k;
        } else if (fv > 0 && c->vers[fv].use_cnt > 0) {
            c->vers[fv].is_arg = 1;
            arg_vers[k] = fv;
            max_arg = k;
        } else {
            arg_vers[k] = ev;
        }
    }

    char fname[64];
    const char *sym = ana_sym_at(c->a, c->g->func_va);
    if (sym) ssa_clean_sym(sym, fname, sizeof(fname));
    else snprintf(fname, sizeof(fname), "sub_%llx", (unsigned long long)c->g->func_va);

    char head[96];
    ssa_fmt_typed_name(ssa_ty_name(ret_ty), fname, head, sizeof(head));

    size_t pos = 0;
    out->proto[0] = 0;
    ssa_append(out->proto, sizeof(out->proto), &pos, "%s(", head);
    if (max_arg < 0) {
        ssa_append(out->proto, sizeof(out->proto), &pos, "void");
    } else {
        for (int k = 0; k <= max_arg; k++) {
            if (k) ssa_append(out->proto, sizeof(out->proto), &pos, ", ");
            char an[12], param[48];
            snprintf(an, sizeof(an), "a%d", k + 1);
            const char *pt = (arg_vers[k] > 0) ? ssa_ty_name(c->vers[arg_vers[k]].ty) : "uint64_t";
            ssa_fmt_typed_name(pt, an, param, sizeof(param));
            ssa_append(out->proto, sizeof(out->proto), &pos, "%s", param);
        }
    }
    ssa_append(out->proto, sizeof(out->proto), &pos, ")");
}

static bool ssa_emit_outputs(ssa_ctx *c, ssa_func *out) {
    out->func_va = c->g->func_va;
    out->nblk = c->nblk;
    out->nphi = c->nphi;
    out->nsccp = c->nsccp;
    out->ngvn = c->ngvn;
    out->ndce = c->ndce;

    out->blks = (ssa_blk *)calloc(c->nblk, sizeof(ssa_blk));
    if (!out->blks) return false;
    for (uint32_t b = 0; b < c->nblk; b++) {
        out->blks[b].start = c->g->blks[b].start;
        out->blks[b].end = c->g->blks[b].end;
        out->blks[b].idom = c->idom[b];
        out->blks[b].first = c->mlir_first[b];
        out->blks[b].count = c->mlir_count[b];
    }

    if (c->nllir > 0) {
        out->llir = (ssa_ins *)calloc(c->nllir, sizeof(ssa_ins));
        if (!out->llir) return false;
        out->nllir = c->nllir;
        for (uint32_t i = 0; i < c->nllir; i++) {
            const ssa_ir *ir = &c->llir[i];
            ssa_ins *dst = &out->llir[i];
            dst->va = ir->va;
            dst->blk = ir->blk;
            dst->op = ir->op;
            if (ir->dst_reg >= 0) {
                snprintf(dst->dst, sizeof(dst->dst), "%s", ssa_reg_name(c, ir->dst_reg, ir->bits ? ir->bits : c->ptr_bits));
                ssa_width_tag(ir, dst->type);
            } else if (ir->op == SSA_OP_CMP) {
                snprintf(dst->dst, sizeof(dst->dst), "flags");
            }
            ssa_fmt_ir_text(c, ir, 0, dst->text, sizeof(dst->text));
        }
    }

    if (c->nmlir > 0) {
        out->mlir = (ssa_ins *)calloc(c->nmlir, sizeof(ssa_ins));
        if (!out->mlir) return false;
        out->nmlir = c->nmlir;
        for (uint32_t i = 0; i < c->nmlir; i++) {
            const ssa_ir *ir = &c->mlir[i];
            ssa_ins *dst = &out->mlir[i];
            dst->va = ir->va;
            dst->blk = ir->blk;
            dst->op = ir->op;
            dst->is_phi = ir->is_phi;
            dst->is_dead = ir->is_dead;
            if (ir->dst_ver > 0) {
                ssa_ver_name(c, ir->dst_ver, dst->dst, sizeof(dst->dst));
                snprintf(dst->type, sizeof(dst->type), "%s", ssa_ty_name(c->vers[ir->dst_ver].ty));
            } else if (ir->op == SSA_OP_CMP) {
                snprintf(dst->dst, sizeof(dst->dst), "flags");
            }
            ssa_fmt_ir_text(c, ir, 1, dst->text, sizeof(dst->text));
        }
    }

    uint32_t vcap = 0;
    for (int v = 1; v < c->nver; v++) {
        const ssa_ver *sv = &c->vers[v];
        if (sv->is_arg || (sv->def_ins >= 0 && !c->mlir[sv->def_ins].is_dead)) vcap++;
    }
    if (vcap > 256) vcap = 256;
    if (vcap > 0) {
        out->vars = (ssa_var *)calloc(vcap, sizeof(ssa_var));
        if (!out->vars) return false;
        for (int pass = 0; pass < 2; pass++) {
            for (int v = 1; v < c->nver && out->nvar < vcap; v++) {
                const ssa_ver *sv = &c->vers[v];
                int want = (pass == 0) ? (sv->is_arg != 0) : (!sv->is_arg && sv->def_ins >= 0 && !c->mlir[sv->def_ins].is_dead);
                if (!want) continue;
                ssa_var *ov = &out->vars[out->nvar++];
                ssa_ver_name(c, v, ov->name, sizeof(ov->name));
                snprintf(ov->type, sizeof(ov->type), "%s", ssa_ty_name(sv->ty));
                ov->is_arg = sv->is_arg;
                ov->is_const = (sv->lat == SSA_LAT_CONST) ? 1 : 0;
                ov->cval = ov->is_const ? sv->cval : 0;
            }
        }
    }

    return true;
}

static void ssa_ctx_free(ssa_ctx *c) {
    if (!c) return;
    free(c->llir);
    free(c->mlir);
    free(c->phi_pool);
    free(c->vers);
    free(c->push_log);
    free(c->gvn);
    for (int r = 0; r < SSA_MAX_REGS; r++) free(c->rstack[r]);
    free(c);
}

void ssa_free(ssa_func *f) {
    if (!f) return;
    free(f->blks);
    free(f->llir);
    free(f->mlir);
    free(f->vars);
    memset(f, 0, sizeof(*f));
}

bool ssa_build(const ana_ctx *a, uint64_t va, ssa_func *out) {
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    if (!a) return false;

    grp_cfg g = {0};
    if (!grp_build(a, va, 0, &g)) return false;

    uint32_t nblk = (g.nblk > SSA_MAX_BLKS) ? SSA_MAX_BLKS : g.nblk;
    if (nblk == 0) {
        grp_free(&g);
        return false;
    }

    ssa_ctx *c = (ssa_ctx *)calloc(1, sizeof(ssa_ctx));
    if (!c) {
        grp_free(&g);
        return false;
    }

    c->a = a;
    c->g = &g;
    c->nblk = nblk;
    c->is_arm64 = (a->bin.arch == BIN_ARCH_ARM64);
    c->is_x86 = (a->bin.arch == BIN_ARCH_X86);
    c->ptr_bits = c->is_x86 ? 32 : 64;

    if (c->is_arm64) {
        c->sp_reg = 31;
        c->ret_reg = 0;
        c->narg_abi = 8;
        for (int k = 0; k < 8; k++) c->arg_regs[k] = k;
    } else if (c->is_x86) {
        c->sp_reg = 4;
        c->ret_reg = 0;
        c->narg_abi = 2;
        c->arg_regs[0] = 1;
        c->arg_regs[1] = 2;
    } else if (a->bin.fmt == BIN_PE64 || a->bin.fmt == BIN_RAW) {
        c->sp_reg = 4;
        c->ret_reg = 0;
        c->narg_abi = 4;
        c->arg_regs[0] = 1;
        c->arg_regs[1] = 2;
        c->arg_regs[2] = 8;
        c->arg_regs[3] = 9;
    } else {
        c->sp_reg = 4;
        c->ret_reg = 0;
        c->narg_abi = 6;
        c->arg_regs[0] = 7;
        c->arg_regs[1] = 6;
        c->arg_regs[2] = 2;
        c->arg_regs[3] = 1;
        c->arg_regs[4] = 8;
        c->arg_regs[5] = 9;
    }

    ssa_build_cfg(c);
    ssa_compute_doms(c);
    ssa_compute_df(c);
    ssa_lift_all(c);
    ssa_build_mlir(c);
    ssa_run_sccp(c);
    ssa_run_gvn(c);
    ssa_run_dce(c);
    ssa_solve_types(c);
    ssa_build_proto(c, out);

    bool ok = ssa_emit_outputs(c, out);
    if (!ok) ssa_free(out);

    ssa_ctx_free(c);
    grp_free(&g);
    return ok;
}
