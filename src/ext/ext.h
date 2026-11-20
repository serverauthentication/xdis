#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define XDIS_ABI_VER 1

typedef void (*xdis_cmd_fn)(const char *args, void *ud);

typedef struct {
    uint32_t version;
    void       *ctx;
    void        (*log)(void *ctx, const char *msg);
    const char *(*bin_path)(void *ctx);
    uint32_t    (*sec_count)(void *ctx);
    int         (*sec_info)(void *ctx, uint32_t idx, char *name, size_t nmax,
                            uint64_t *va, uint64_t *vsize, uint64_t *fsize, uint32_t *perm);
    size_t      (*read_va)(void *ctx, uint64_t va, uint8_t *dst, size_t len);
    uint32_t    (*func_count)(void *ctx);
    int         (*func_info)(void *ctx, uint32_t idx, uint64_t *start, uint64_t *end, const char **name);
    const char *(*sym_name)(void *ctx, uint64_t va);
    void        (*set_name)(void *ctx, uint64_t va, const char *name);
    void        (*set_cmt)(void *ctx, uint64_t va, const char *text);
    uint64_t    (*cur_va)(void *ctx);
    void        (*goto_va)(void *ctx, uint64_t va);
    int         (*add_cmd)(void *ctx, const char *name, xdis_cmd_fn fn, void *ud);
} xdis_api;

#ifndef XDIS_PLUGIN_ONLY

#include "../ana/ana.h"

typedef void     (*ext_log_fn)(void *ud, const char *msg);
typedef uint64_t (*ext_get_va_fn)(void *ud);
typedef void     (*ext_set_va_fn)(void *ud, uint64_t va);

typedef struct {
    char        name[32];
    xdis_cmd_fn fn;
    void       *ud;
} ext_cmd;

typedef struct {
    ana_ctx      *ana;
    void         *ui_ud;
    ext_log_fn    log_fn;
    ext_get_va_fn get_va_fn;
    ext_set_va_fn set_va_fn;
    void         *mods[32];
    uint32_t      nmod;
    ext_cmd       cmds[64];
    uint32_t      ncmd;
    xdis_api      api;
} ext_host;

void     ext_init(ext_host *h, ana_ctx *a, void *ui_ud, ext_log_fn log_fn, ext_get_va_fn gva, ext_set_va_fn sva);
void     ext_free(ext_host *h);
uint32_t ext_load_dir(ext_host *h, const char *dir);
uint32_t ext_load_dir_allow(ext_host *h, const char *dir, const char *allow_csv);
bool     ext_run(ext_host *h, const char *name, const char *args);

#endif
