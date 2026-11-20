#pragma once

#include "ana.h"
#include <stdbool.h>
#include <stdint.h>

#define HL_MAX_BLKS     2048
#define HL_MAX_REGS     32
#define HL_MAX_SW       32
#define HL_MAX_CALL_ARG 10

typedef enum {
    HL_TY_UNK = 0,
    HL_TY_VOID,
    HL_TY_BOOL,
    HL_TY_I8,
    HL_TY_U8,
    HL_TY_CHAR,
    HL_TY_I16,
    HL_TY_U16,
    HL_TY_WCHAR,
    HL_TY_I32,
    HL_TY_U32,
    HL_TY_I64,
    HL_TY_U64,
    HL_TY_SIZE_T,
    HL_TY_F32,
    HL_TY_F64,
    HL_TY_PTR,
    HL_TY_STRUCT,
    HL_TY_HANDLE,
    HL_TY_HMODULE,
    HL_TY_HWND,
    HL_TY_HKEY,
    HL_TY_SOCKET,
    HL_TY_FILE
} hl_ty_kind;

typedef struct {
    uint8_t kind;
    uint8_t ptr_depth;
    uint8_t is_const;
    uint8_t bits;
    char    name[40];
} hl_type;

typedef struct {
    int      id;
    char     orig[24];
    char     name[32];
    hl_type  ty;
    int      bits;
    int      is_arg;
    int      arg_idx;
    int      is_stack;
    int64_t  stack_off;
    int      is_flt;
    int      is_loop_idx;
    int      is_dead;
    int      is_canary;
    int      reg_hint;
    int      use_cnt;
    int      def_cnt;
    int      ssa_ver;
    int      coal_to;
} hl_var;

typedef enum {
    HLE_NONE = 0,
    HLE_INT,
    HLE_FLT,
    HLE_STR,
    HLE_SYM,
    HLE_VAR,
    HLE_ADDR,
    HLE_DEREF,
    HLE_FIELD,
    HLE_INDEX,
    HLE_UNOP,
    HLE_BINOP,
    HLE_TERNARY,
    HLE_CALL,
    HLE_BITSET
} hl_expr_kind;

typedef enum {
    HLU_NEG = 1,
    HLU_BITNOT,
    HLU_LOGNOT,
    HLU_ZEXT,
    HLU_SEXT,
    HLU_CAST,
    HLU_FNEG,
    HLU_FABS,
    HLU_I2F,
    HLU_F2I,
    HLU_BSWAP,
    HLU_POPCNT,
    HLU_CLZ,
    HLU_CTZ,
    HLU_ABS
} hl_unop;

typedef enum {
    HLB_ADD = 1,
    HLB_SUB,
    HLB_MUL,
    HLB_SDIV,
    HLB_UDIV,
    HLB_SMOD,
    HLB_UMOD,
    HLB_AND,
    HLB_OR,
    HLB_XOR,
    HLB_SHL,
    HLB_SHR,
    HLB_SAR,
    HLB_ROL,
    HLB_ROR,
    HLB_EQ,
    HLB_NE,
    HLB_SLT,
    HLB_SLE,
    HLB_SGT,
    HLB_SGE,
    HLB_ULT,
    HLB_ULE,
    HLB_UGT,
    HLB_UGE,
    HLB_LAND,
    HLB_LOR,
    HLB_MIN,
    HLB_MAX,
    HLB_FADD,
    HLB_FSUB,
    HLB_FMUL,
    HLB_FDIV
} hl_binop;

typedef struct {
    uint8_t  kind;
    uint8_t  op;
    uint8_t  bits;
    uint8_t  is_signed;
    uint8_t  is_flt;
    uint8_t  is_wide;
    uint8_t  is_dot;
    uint8_t  narg;
    int      var_id;
    int      sub0;
    int      sub1;
    int      sub2;
    int      args[HL_MAX_CALL_ARG];
    int64_t  disp;
    uint64_t uval;
    double   fval;
    uint64_t va;
    int      scale;
    char     sym[64];
    char     field[40];
    hl_type  ty;
} hl_expr;

typedef enum {
    HLS_NOP = 0,
    HLS_ASSIGN,
    HLS_STORE,
    HLS_CALL,
    HLS_RET,
    HLS_MEMCPY,
    HLS_MEMSET,
    HLS_PHI
} hl_stmt_kind;

typedef struct {
    uint64_t va;
    uint8_t  kind;
    uint8_t  dead;
    uint8_t  nphi;
    int      dst_var;
    int      lhs_expr;
    int      rhs_expr;
    int      len_expr;
    int      phi_vars[8];
    int      phi_blks[8];
} hl_stmt;

typedef struct {
    uint64_t start;
    uint64_t end;
    int     *stmts;
    int      nstmt;
    int      stmt_cap;
    int      cond_expr;
    uint64_t cond_va;
    int      sw_expr;
    int      sw_idx;
    int      out_t;
    int      out_f;
    int      out_u;
    int      in_deg;
    int      idom;
    int      ipdom;
    uint8_t  is_loop_hdr;
    uint8_t  is_exit;
} hl_blk;

typedef struct {
    uint64_t va;
    int      narg;
    uint8_t  flt_mask;
    int      has_ret;
    hl_type  ret_ty;
    hl_type  arg_ty[HL_MAX_CALL_ARG];
    int      is_vararg;
    int      fmt_arg;
} hl_callee_sig;

typedef struct {
    const ana_ctx   *a;
    const typ_store *types;
    const grp_cfg   *g;
    int              is_a64;
    int              is_win64;
    int              is_x86_32;
    int              ptr_bits;
    int              arg_regs[8];
    int              narg_abi;
    int              ret_reg;
    int              sp_reg;
    int              bp_reg;
    int              saved_mask;
    int              has_ret_val;
    int              has_canary;
    int64_t          canary_off;
    hl_type          ret_ty;

    hl_blk          *blks;
    int              nblk;

    hl_stmt         *stmts;
    int              nstmt;
    int              stmt_cap;

    hl_expr         *exprs;
    int              nexpr;
    int              expr_cap;

    hl_var          *vars;
    int              nvar;
    int              var_cap;

    ir_switch        sws[HL_MAX_SW];
    int              nsw;
} hl_fn;

void        hl_fn_free(hl_fn *fn);
int         hl_expr_new(hl_fn *fn, uint8_t kind);
int         hl_expr_int(hl_fn *fn, uint64_t v, int bits, int is_signed);
int         hl_expr_flt(hl_fn *fn, double v, int bits);
int         hl_expr_var(hl_fn *fn, int var_id);
int         hl_expr_unop(hl_fn *fn, uint8_t op, int sub, int bits);
int         hl_expr_binop(hl_fn *fn, uint8_t op, int a, int b, int bits);
int         hl_expr_clone(hl_fn *fn, int eid);
int         hl_expr_invert(hl_fn *fn, int eid);
int         hl_var_canon(const hl_fn *fn, int vid);
int         hl_stmt_new(hl_fn *fn, int bi, uint64_t va, uint8_t kind);

bool        hl_lift_cfg(const ana_ctx *a, const typ_store *types, const grp_cfg *g, hl_fn *fn);
void        hl_optimize(hl_fn *fn);

bool        hl_lookup_callee(const ana_ctx *a, const typ_store *types, uint64_t va, const char *sym, hl_callee_sig *out);
int         hl_count_fmt_args(const char *fmt);
void        hl_type_fmt(const hl_type *t, char *dst, size_t cap);
bool        hl_type_parse(const typ_store *types, const char *decl, hl_type *out);
void        hl_infer_types(hl_fn *fn);

bool        hl_structure_and_emit(hl_fn *fn, dec_out *out);
