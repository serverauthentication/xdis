#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define DBG_MAX_BP    64
#define DBG_MAX_HWBP  4
#define DBG_MAX_MEMBP 16
#define DBG_MAX_SNAP  256
#define DBG_MAX_TTD   4096
#define DBG_MAX_MOD   128
#define DBG_MAX_TH    64
#define DBG_MAX_MMAP  256
#define DBG_MAX_BT    32

typedef struct {
    uint64_t va;
    uint8_t  orig;
    int      active;
    char     cond[64];
} dbg_bp;

typedef struct {
    uint64_t va;
    uint8_t  kind;
    uint8_t  size;
    int      active;
} dbg_hwbp;

typedef struct {
    uint64_t va;
    uint32_t size;
    uint32_t orig_prot;
    int      active;
} dbg_membp;

typedef struct {
    uint64_t base;
    uint64_t size;
    uint8_t  perm;
    char     type[8];
    char     mod[48];
} dbg_mreg;

typedef struct {
    uint64_t rip;
    uint64_t sp;
    char     mod[48];
} dbg_frame;

typedef struct {
    uint64_t rip;
    uint64_t rflags;
    uint64_t regs[16];
    uint16_t chg_mask;
    uint64_t mem_va;
    uint64_t mem_val;
    uint8_t  mem_sz;
} dbg_ttd_ent;

typedef struct {
    uint64_t rip;
    uint64_t rflags;
    uint64_t regs[16];
    uint8_t  stack[64];
    uint32_t tid;
    char     event[48];
} dbg_snap;

typedef struct {
    uint64_t base;
    uint32_t size;
    char     name[64];
} dbg_mod;

typedef struct {
    uint32_t tid;
    uint64_t start_va;
} dbg_th;

typedef struct {
    int          attached;
    int          paused;
    bool         launched;
    uint32_t     pid;
    uint32_t     tid;
    void        *hproc;
    void        *hthread;
    dbg_bp       bps[DBG_MAX_BP];
    int          nbp;
    dbg_hwbp     hwbps[DBG_MAX_HWBP];
    dbg_membp    membps[DBG_MAX_MEMBP];
    int          nmembp;
    dbg_snap     snaps[DBG_MAX_SNAP];
    int          nsnap;
    int          cur_snap;
    dbg_ttd_ent *ttd;
    int          nttd;
    int          ttd_cur;
    char         last_err[96];
} dbg_ctx;

void dbg_init(dbg_ctx *d);
void dbg_close(dbg_ctx *d);
bool dbg_launch(dbg_ctx *d, const char *path, const char *args);
bool dbg_attach(dbg_ctx *d, uint32_t pid);
bool dbg_detach(dbg_ctx *d);
bool dbg_kill(dbg_ctx *d);
bool dbg_step(dbg_ctx *d);
bool dbg_step_over(dbg_ctx *d);
bool dbg_step_out(dbg_ctx *d);
bool dbg_run_to(dbg_ctx *d, uint64_t va);
bool dbg_cont(dbg_ctx *d, uint32_t timeout_ms);
bool dbg_pause(dbg_ctx *d);
bool dbg_set_reg(dbg_ctx *d, int reg_idx, uint64_t val);
bool dbg_bp_add(dbg_ctx *d, uint64_t va);
bool dbg_bp_add_cond(dbg_ctx *d, uint64_t va, const char *cond);
bool dbg_bp_del(dbg_ctx *d, uint64_t va);
bool dbg_hwbp_add(dbg_ctx *d, uint64_t va, uint8_t kind, uint8_t size);
bool dbg_hwbp_add_slot(dbg_ctx *d, int req_slot, uint64_t va, uint8_t kind, uint8_t size);
bool dbg_hwbp_del(dbg_ctx *d, int slot);
bool dbg_membp_add(dbg_ctx *d, uint64_t va, uint32_t size);
bool dbg_membp_del(dbg_ctx *d, uint64_t va);
size_t dbg_read_mem(const dbg_ctx *d, uint64_t va, uint8_t *dst, size_t n);
bool dbg_write_mem(dbg_ctx *d, uint64_t va, const uint8_t *src, size_t n);
int  dbg_list_mods(const dbg_ctx *d, dbg_mod *out, int max_out);
int  dbg_list_threads(const dbg_ctx *d, dbg_th *out, int max_out);
int  dbg_mem_map(const dbg_ctx *d, dbg_mreg *out, int max_out);
int  dbg_backtrace(const dbg_ctx *d, dbg_frame *out, int max_out);
const dbg_snap *dbg_get_snap(const dbg_ctx *d, int idx);
int  dbg_ttd_record(dbg_ctx *d, int max_steps);
bool dbg_ttd_step_back(dbg_ctx *d);
int  dbg_ttd_who_wrote(const dbg_ctx *d, uint64_t mem_va, int reg_idx, uint64_t *hit_rip, uint64_t *old_v, uint64_t *new_v);

typedef struct {
    int      connected;
    int      no_ack;
    uint64_t sock;
    char     host[64];
    uint16_t port;
    uint64_t rip;
    uint64_t rflags;
    uint64_t regs[16];
    char     stop_sig[32];
    char     last_err[96];
} gdb_ctx;

void   gdb_init(gdb_ctx *g);
bool   gdb_connect(gdb_ctx *g, const char *host, uint16_t port, uint32_t timeout_ms);
void   gdb_disconnect(gdb_ctx *g);
bool   gdb_read_regs(gdb_ctx *g);
bool   gdb_step(gdb_ctx *g);
bool   gdb_cont(gdb_ctx *g, uint32_t timeout_ms);
bool   gdb_bp_add(gdb_ctx *g, uint64_t va, int hw);
bool   gdb_bp_del(gdb_ctx *g, uint64_t va, int hw);
size_t gdb_read_mem(gdb_ctx *g, uint64_t va, uint8_t *dst, size_t n);
bool   gdb_write_mem(gdb_ctx *g, uint64_t va, const uint8_t *src, size_t n);

typedef struct {
    uint64_t va;
    uint64_t size;
    uint64_t file_off;
} dmp_mem_rng;

typedef struct {
    uint32_t tid;
    uint64_t rip;
    uint64_t rsp;
    uint64_t rflags;
    uint64_t regs[16];
} dmp_thread;

typedef struct {
    int          loaded;
    char         path[260];
    uint16_t     arch;
    uint32_t     ncpu;
    uint32_t     os_major;
    uint32_t     os_minor;
    uint32_t     os_build;
    uint32_t     exc_tid;
    uint32_t     exc_code;
    uint64_t     exc_addr;
    dbg_mod     *mods;
    uint32_t     nmod;
    dmp_thread  *threads;
    uint32_t     nthread;
    dmp_mem_rng *mems;
    uint32_t     nmem;
    uint8_t     *raw;
    size_t       raw_size;
    char         last_err[96];
} dmp_ctx;

void   dmp_init(dmp_ctx *m);
void   dmp_close(dmp_ctx *m);
bool   dmp_open(dmp_ctx *m, const char *path);
size_t dmp_read_mem(const dmp_ctx *m, uint64_t va, uint8_t *dst, size_t n);
