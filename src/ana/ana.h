#pragma once

#include "../arch/arch.h"
#include "../bin/bin.h"
#include "../core/tbl.h"
#include <stdbool.h>
#include <stdint.h>

typedef enum {
    ANA_XREF_CALL = 1,
    ANA_XREF_JMP  = 2,
    ANA_XREF_DATA = 3
} ana_xref_type;

typedef struct {
    uint64_t start;
    uint64_t end;
    uint32_t name_off;
    uint8_t  flags;
} ana_func;

typedef struct {
    uint64_t from;
    uint64_t to;
    uint8_t  type;
} ana_xref;

typedef struct {
    uint64_t va;
    uint32_t len;
    uint8_t  wide;
} ana_str;

typedef struct {
    uint64_t va;
    char     label[48];
} ana_mark;

typedef struct {
    uint64_t va;
    uint8_t  orig;
    uint8_t  val;
} ana_patch;

typedef struct {
    uint64_t func_va;
    char     orig[24];
    char     name[32];
    char     type[32];
} ana_lvar;

typedef enum {
    ANA_HIST_NAME = 1,
    ANA_HIST_CMT,
    ANA_HIST_PATCH,
    ANA_HIST_LVAR,
    ANA_HIST_MARK
} ana_hist_kind;

typedef struct {
    uint8_t  kind;
    uint64_t va;
    uint64_t aux_va;
    uint8_t  old_byte;
    uint8_t  new_byte;
    uint8_t  had_old;
    char     old_a[96];
    char     new_a[96];
    char     old_b[48];
    char     new_b[48];
} ana_hist;

typedef struct {
    bin_img    bin;
    ana_func  *funcs;
    uint32_t   nfunc;
    uint32_t   func_cap;
    ana_xref  *xrefs;
    uint32_t   nxref;
    uint32_t   xref_cap;
    ana_str   *strs;
    uint32_t   nstr;
    uint32_t   str_cap;
    ana_mark  *marks;
    uint32_t   nmark;
    uint32_t   mark_cap;
    ana_patch *patches;
    uint32_t   npatch;
    uint32_t   patch_cap;
    ana_lvar  *lvars;
    uint32_t   nlvar;
    uint32_t   lvar_cap;
    ana_hist  *hist;
    uint32_t   hist_len;
    uint32_t   hist_pos;
    uint32_t   hist_cap;
    int        hist_mute;

    tbl_u64    func_map;
    tbl_u64    sym_map;
    tbl_u64    cmt_map;
    tbl_u64    str_map;
    char      *pool;
    uint32_t   pool_len;
    uint32_t   pool_cap;

    double     load_ms;
    double     ana_ms;
    volatile long busy;
    volatile long cancel;
    volatile long pct;
} ana_ctx;

typedef enum {
    GRP_EDGE_UNCOND = 0,
    GRP_EDGE_TRUE   = 1,
    GRP_EDGE_FALSE  = 2
} grp_edge_kind;

typedef struct {
    uint32_t from;
    uint32_t to;
    uint8_t  kind;
    uint8_t  back;
} grp_edge;

typedef struct {
    uint64_t start;
    uint64_t end;
    uint32_t ins_first;
    uint32_t ins_count;
    int      layer;
    int      order;
    int      x, y, w, h;
} grp_blk;

typedef struct {
    uint64_t  func_va;
    grp_blk  *blks;
    uint32_t  nblk;
    grp_edge *edges;
    uint32_t  nedge;
    x86_ins  *ins;
    uint32_t  nins;
    int       total_w;
    int       total_h;
    bool      truncated;
    uint32_t  orig_blks;
    uint32_t  orig_ins;
    uint8_t   trunc_reason;
} grp_cfg;

void        ana_init(ana_ctx *a);
void        ana_free(ana_ctx *a);
bool        ana_open(ana_ctx *a, const char *path, uint64_t raw_base, int raw_bits);
bool        ana_open_buf(ana_ctx *a, uint8_t *buf, uint64_t size, const char *label, uint64_t raw_base, int raw_bits);
void        ana_run(ana_ctx *a, int threads, int min_str, int max_ana_mb);

const char *ana_pool_str(const ana_ctx *a, uint32_t off);
uint32_t    ana_pool_add(ana_ctx *a, const char *s);
const char *ana_sym_at(const ana_ctx *a, uint64_t va);
void        ana_set_name(ana_ctx *a, uint64_t va, const char *name);
const char *ana_cmt_at(const ana_ctx *a, uint64_t va);
void        ana_set_cmt(ana_ctx *a, uint64_t va, const char *text);
const ana_func *ana_func_at(const ana_ctx *a, uint64_t va);
const ana_str  *ana_str_at(const ana_ctx *a, uint64_t va);
size_t      ana_read_str(const ana_ctx *a, const ana_str *s, char *dst, size_t max);
uint32_t    ana_xrefs_to(const ana_ctx *a, uint64_t va, uint32_t *first_idx);
bool        ana_find_sym(const ana_ctx *a, const char *name, uint64_t *va);
bool        ana_add_mark(ana_ctx *a, uint64_t va, const char *label);
bool        ana_patch_byte(ana_ctx *a, uint64_t va, uint8_t val);
bool        ana_unpatch_byte(ana_ctx *a, uint64_t va);
void        ana_unpatch_all(ana_ctx *a);
bool        ana_export_bin(const ana_ctx *a, const char *path);
bool        ana_set_lvar(ana_ctx *a, uint64_t func_va, const char *orig, const char *name, const char *type);
bool        ana_undo(ana_ctx *a);
bool        ana_redo(ana_ctx *a);
uint32_t    ana_undo_count(const ana_ctx *a);
uint32_t    ana_redo_count(const ana_ctx *a);
double      ana_entropy(const uint8_t *buf, size_t n);
uint64_t    ana_prev_va(const ana_ctx *a, uint64_t va);
uint64_t    ana_next_va(const ana_ctx *a, uint64_t va);

void        grp_free(grp_cfg *g);
bool        grp_build(const ana_ctx *a, uint64_t va, int upper, grp_cfg *g);
void        grp_layout(grp_cfg *g, int char_w, int line_h);

typedef struct {
    char     name[48];
    uint32_t nsym;
    uint32_t ncmt;
    uint32_t npatch;
    uint32_t nlvar;
} db_snap_meta;

bool        db_save(const ana_ctx *a, const char *path);
bool        db_load(ana_ctx *a, const char *path);
bool        db_snap_save(const ana_ctx *a, const char *db_path, const char *snap_name);
int         db_snap_list(const char *db_path, db_snap_meta *out, int max_out);
bool        db_snap_restore(ana_ctx *a, const char *db_path, const char *snap_name);

typedef struct {
    uint64_t va;
    char     text[200];
} dec_line;

typedef struct {
    char    orig[24];
    char    name[32];
    char    type[48];
    int     is_arg;
    int     bits;
    int64_t stack_off;
} dec_var_info;

typedef struct {
    uint64_t      func_va;
    dec_line     *lines;
    uint32_t      nline;
    uint32_t      cap;
    dec_var_info *vars;
    uint32_t      nvar;
} dec_out;

struct typ_store_s;

void        dec_free(dec_out *d);
bool        dec_func(const ana_ctx *a, uint64_t va, dec_out *d);
bool        dec_func_typed(const ana_ctx *a, const struct typ_store_s *types, uint64_t va, dec_out *d);

typedef struct {
    uint64_t va;
    char     kind[20];
    char     name[64];
    char     reason[112];
    int      score;
} tri_spot;

typedef struct {
    char     group[24];
    char     apis[16][48];
    uint64_t vas[16];
    int      count;
} tri_cap;

typedef struct {
    char     verdict[48];
    char     packer[64];
    char     compiler[48];
    int      pack_score;
    int      obf_score;
    int      has_rwx;
    int      high_ent_exec;
    int      ep_anomaly;
    int      sparse_imp;
    double   max_ent;
    uint64_t overlay_size;
    char     notes[8][128];
    int      nnote;
    tri_cap  caps[7];
    int      ncap;
    tri_spot spots[48];
    int      nspot;
} tri_report;

void        tri_analyze(const ana_ctx *a, tri_report *r);

typedef struct {
    uint64_t va;
    char     mnem[20];
    char     ops[76];
    char     note[72];
    uint8_t  flow;
    uint8_t  tag;
} dob_row;

typedef struct {
    uint64_t va;
    char     text[80];
} dob_str;

typedef struct {
    uint64_t func_va;
    int      orig_ins;
    int      clean_ins;
    int      junk_cut;
    int      opaque_cut;
    int      const_folded;
    int      ind_resolved;
    dob_row  rows[512];
    int      nrow;
    dob_str  strs[32];
    int      nstr;
} dob_res;

bool        dob_analyze(const ana_ctx *a, uint64_t va, int upper, dob_res *out);

typedef struct {
    uint64_t va;
    char     text[88];
    char     effect[80];
} emu_step;

typedef struct {
    uint64_t start_va;
    uint64_t regs[16];
    uint64_t rip;
    int      zf, sf, cf;
    int      nstep;
    int      halted;
    char     stop_reason[48];
    emu_step steps[256];
    char     stack_ascii[256];
} emu_out;

bool        emu_trace(const ana_ctx *a, uint64_t start_va, int max_steps, emu_out *out);

typedef struct {
    uint64_t va;
    uint8_t  op;
    char     text[128];
} ir_op;

typedef struct {
    int  off;
    int  size;
    char name[24];
    char type[24];
} ir_field;

typedef struct {
    char     name[32];
    int      base_reg;
    int      nfield;
    ir_field fields[32];
} ir_struct;

typedef struct {
    uint64_t  func_va;
    int       nop;
    int       nconst;
    int       ndce;
    int       nstruct;
    ir_op     ops[512];
    ir_struct structs[8];
} ir_func;

typedef struct {
    uint64_t va;
    uint32_t nentry;
    char     cls[80];
} ir_vtable;

typedef struct {
    uint64_t va;
    uint64_t table_va;
    uint32_t ncases;
} ir_switch;

bool        ir_lift_func(const ana_ctx *a, uint64_t va, ir_func *out);
int         ir_scan_vtables(const ana_ctx *a, ir_vtable *out, int max_out);
int         ir_scan_switches(const ana_ctx *a, uint64_t func_va, ir_switch *out, int max_out);
int         ir_scan_switches_cfg(const ana_ctx *a, const grp_cfg *g, ir_switch *out, int max_out);
uint32_t    ir_read_switch_targets(const ana_ctx *a, const ir_switch *sw, uint64_t *tgts, uint32_t max_tgts);

typedef struct {
    uint64_t hash;
    uint32_t nins;
    uint32_t nblk;
    uint32_t ncall;
    char     name[64];
} sig_ent;

typedef struct {
    uint64_t va;
    char     algo[32];
    char     detail[64];
} sig_crypto;

uint64_t    sig_dna(const ana_ctx *a, uint64_t func_va, uint32_t *nins, uint32_t *nblk, uint32_t *ncall);
bool        sig_save(const ana_ctx *a, const char *path);
uint32_t    sig_apply(ana_ctx *a, const char *path);
int         sig_find_crypto(const ana_ctx *a, sig_crypto *out, int max_out);

typedef enum {
    DIF_SAME = 0,
    DIF_MOD,
    DIF_ADD,
    DIF_DEL
} dif_kind;

typedef struct {
    uint64_t va_a;
    uint64_t va_b;
    char     name[64];
    uint8_t  kind;
    int      sim;
    uint32_t size_a;
    uint32_t size_b;
} dif_item;

typedef struct {
    dif_item *items;
    uint32_t  nitem;
    uint32_t  same;
    uint32_t  mod;
    uint32_t  add;
    uint32_t  del;
} dif_res;

void        dif_free(dif_res *d);
bool        dif_compare(const ana_ctx *a, const ana_ctx *b, dif_res *out);

typedef struct {
    uint64_t vas[64];
    char     names[64][64];
    int      len;
} pth_chain;

typedef struct {
    uint64_t va;
    char     name[64];
    int      depth;
} pth_node;

typedef struct {
    int from;
    int to;
    int type;
} pth_edge;

typedef struct {
    pth_node nodes[96];
    int      nnode;
    pth_edge edges[192];
    int      nedge;
} pth_xgraph;

bool        pth_find(const ana_ctx *a, uint64_t from_va, uint64_t to_va, pth_chain *out);
bool        pth_xgraph_build(const ana_ctx *a, uint64_t center_va, int max_depth, pth_xgraph *out);

typedef struct {
    char name[32];
    char type[32];
    int  off;
    int  size;
} typ_member;

typedef struct {
    char       name[40];
    int        kind;
    int        size;
    int        nmem;
    typ_member mems[32];
} typ_def;

typedef struct typ_store_s {
    typ_def *defs;
    uint32_t ndef;
    uint32_t cap;
} typ_store;

void        typ_init(typ_store *s);
void        typ_free(typ_store *s);
bool        typ_parse_c(typ_store *s, const char *decl);
const typ_def *typ_find(const typ_store *s, const char *name);
int         typ_sizeof(const typ_store *s, const char *type_name);
bool        typ_save_file(const typ_store *s, const char *path);
bool        typ_load_file(typ_store *s, const char *path);

typedef struct {
    uint64_t va;
    uint16_t blk;
    uint8_t  op;
    uint8_t  is_phi;
    uint8_t  is_dead;
    char     dst[24];
    char     type[24];
    char     text[144];
} ssa_ins;

typedef struct {
    uint64_t start;
    uint64_t end;
    int      idom;
    uint32_t first;
    uint32_t count;
} ssa_blk;

typedef struct {
    char     name[24];
    char     type[32];
    int      is_arg;
    int      is_const;
    uint64_t cval;
} ssa_var;

typedef struct {
    uint64_t  func_va;
    char      proto[192];
    ssa_blk  *blks;
    uint32_t  nblk;
    ssa_ins  *llir;
    uint32_t  nllir;
    ssa_ins  *mlir;
    uint32_t  nmlir;
    ssa_var  *vars;
    uint32_t  nvar;
    int       nphi;
    int       nsccp;
    int       ngvn;
    int       ndce;
} ssa_func;

void        ssa_free(ssa_func *f);
bool        ssa_build(const ana_ctx *a, uint64_t va, ssa_func *out);

typedef struct {
    char     name[80];
    char     bases[160];
    uint64_t vtable_va;
    uint32_t nmethod;
    char     lang[16];
} lang_cls;

typedef struct {
    uint64_t va;
    char     name[96];
} lang_sym;

typedef struct {
    char      runtime[32];
    lang_cls *classes;
    uint32_t  nclass;
    lang_sym *go_funcs;
    uint32_t  ngo_func;
    char      rust_srcs[32][96];
    int       nrust_src;
} lang_info;

void        lang_free(lang_info *li);
void        lang_analyze(const ana_ctx *a, lang_info *out);
uint32_t    lang_apply_syms(ana_ctx *a);

typedef struct {
    uint64_t from_va;
    uint64_t to_va;
    uint64_t state_val;
    uint8_t  kind;
} cff_edge;

typedef struct {
    uint64_t func_va;
    int      detected;
    uint64_t disp_va;
    char     state_var[32];
    int      orig_blks;
    int      real_blks;
    int      backbone_cut;
    cff_edge edges[256];
    int      nedge;
} cff_res;

typedef struct {
    uint64_t va;
    char     orig[128];
    char     simple[96];
    int      ops_saved;
} mba_hit;

typedef struct {
    uint64_t func_va;
    mba_hit  hits[64];
    int      nhit;
} mba_res;

bool        cff_analyze(const ana_ctx *a, uint64_t va, cff_res *out);
bool        mba_simplify_expr(const char *expr, char *out, size_t max, int *ops_saved);
bool        mba_scan_func(const ana_ctx *a, uint64_t va, mba_res *out);

typedef struct {
    uint32_t opcode;
    uint64_t va;
    char     kind[20];
    char     sem[96];
    int      nins;
} vm_handler;

typedef struct {
    uint64_t va;
    char     op[24];
    char     detail[80];
} vm_step;

typedef struct {
    uint64_t   func_va;
    int        detected;
    uint64_t   disp_va;
    uint64_t   table_va;
    char       vip_reg[16];
    char       vsp_reg[16];
    char       style[24];
    vm_handler handlers[64];
    int        nhandler;
    vm_step    trace[128];
    int        ntrace;
} vm_res;

bool        vm_analyze(const ana_ctx *a, uint64_t va, vm_res *out);

typedef struct {
    uint64_t va;
    uint32_t hash;
    char     algo[16];
    char     api[64];
} unp_hash_hit;

typedef struct {
    unp_hash_hit hits[128];
    int          nhit;
} unp_hash_res;

typedef struct {
    uint64_t va;
    char     method[24];
    uint32_t key;
    char     text[96];
} unp_str_hit;

typedef struct {
    unp_str_hit hits[128];
    int         nhit;
} unp_str_res;

typedef struct {
    int      ok;
    uint32_t nsec;
    uint32_t nimp;
    uint64_t out_size;
    char     err[96];
} unp_pe_res;

int         unp_resolve_hashes(ana_ctx *a, int apply, unp_hash_res *out);
int         unp_decrypt_strings(ana_ctx *a, uint64_t focus_va, int apply, unp_str_res *out);
bool        unp_rebuild_pe_mem(const uint8_t *img, size_t img_size, uint64_t base_va, uint64_t oep_va, const char *out_path, unp_pe_res *out);

typedef struct {
    uint64_t va;
    char     kind[20];
    char     detail[96];
    uint16_t reg_mask;
} tnt_event;

typedef struct {
    uint64_t  start_va;
    int       nstep;
    uint64_t  regs[16];
    uint16_t  taint_regs;
    int       taint_bytes;
    int       shim_calls;
    char      stop_reason[48];
    tnt_event events[128];
    int       nevent;
} tnt_res;

typedef struct {
    char     var[24];
    uint64_t val;
    char     expr[64];
} tnt_bind;

typedef struct {
    int      reachable;
    int      npath;
    uint64_t path[64];
    char     constraints[32][80];
    int      ncons;
    tnt_bind witness[16];
    int      nwitness;
    char     summary[128];
} tnt_solve_res;

bool        tnt_run(const ana_ctx *a, uint64_t start_va, int src_reg, uint32_t buf_len, int max_steps, tnt_res *out);
bool        tnt_solve_path(const ana_ctx *a, uint64_t start_va, uint64_t target_va, tnt_solve_res *out);

typedef struct {
    uint32_t syms_added;
    uint32_t types_added;
    uint32_t funcs_added;
    char     format[24];
    char     err[96];
} sym_dbg_stats;

bool        sym_load_pdb_msf(ana_ctx *a, typ_store *types, const char *path, sym_dbg_stats *out);
bool        sym_load_dwarf(ana_ctx *a, typ_store *types, sym_dbg_stats *out);

typedef struct {
    int  types_added;
    int  defines;
    char err[96];
} chdr_res;

typedef struct {
    char     ida[256];
    char     c_bytes[256];
    char     c_mask[64];
    int      len;
    int      hits;
    uint64_t va;
} chdr_sig_res;

bool        chdr_parse(typ_store *s, const char *text, chdr_res *out);
int         chdr_load_stdlib(typ_store *s, const char *pack);
bool        chdr_make_sig(const ana_ctx *a, uint64_t va, chdr_sig_res *out);

typedef struct {
    char     rule[64];
    char     desc[96];
    char     match_id[24];
    uint64_t va;
    uint64_t off;
    int      nmatch;
} for_yara_hit;

typedef struct {
    for_yara_hit hits[128];
    int          nhit;
    int          nrules;
    char         err[96];
} for_yara_res;

typedef struct {
    char     kind[20];
    uint64_t off;
    uint64_t va;
    uint64_t size;
    double   ent;
    char     detail[64];
} for_carve_hit;

typedef struct {
    for_carve_hit hits[128];
    int           nhit;
} for_carve_res;

typedef struct {
    char     kind[16];
    uint64_t va;
    char     value[128];
} for_ioc_hit;

typedef struct {
    for_ioc_hit hits[256];
    int         nhit;
} for_ioc_res;

const char *for_yara_default_rules(void);
bool        for_yara_scan(const ana_ctx *a, const char *rules_text, for_yara_res *out);
int         for_carve(const ana_ctx *a, for_carve_res *out);
bool        for_extract(const ana_ctx *a, uint64_t off, uint64_t size, const char *out_path);
int         for_extract_iocs(const ana_ctx *a, for_ioc_res *out);

typedef struct {
    uint64_t va;
    char     sev[8];
    char     kind[24];
    char     func[64];
    char     sink[48];
    char     source[48];
    int      hops;
    char     detail[112];
} vln_hit;

typedef struct {
    vln_hit hits[128];
    int     nhit;
    int     nhigh;
    int     nmed;
} vln_res;

typedef struct {
    uint64_t va_a;
    uint64_t va_b;
    char     name[64];
    int      score;
    int      delta_cmp;
    int      delta_jcc;
    char     reason[112];
} vln_pdiff_item;

typedef struct {
    vln_pdiff_item items[128];
    int            nitem;
} vln_pdiff_res;

typedef struct {
    int      side;
    int      ncell;
    uint8_t  cls[4096];
    uint8_t  ent[4096];
    uint64_t offs[4096];
    uint64_t vas[4096];
} vln_hilbert_res;

int         vln_scan(const ana_ctx *a, vln_res *out);
int         vln_patch_triage(const ana_ctx *a, const ana_ctx *b, const dif_res *dif, vln_pdiff_res *out);
bool        vln_hilbert_map(const ana_ctx *a, int order, vln_hilbert_res *out);
