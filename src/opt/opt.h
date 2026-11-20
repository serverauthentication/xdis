#pragma once

#include <stdbool.h>
#include <stdint.h>

typedef struct {
    char     name[24];
    uint32_t bg;
    uint32_t bg_alt;
    uint32_t bg_panel;
    uint32_t bg_sel;
    uint32_t bg_cur;
    uint32_t border;
    uint32_t fg;
    uint32_t fg_dim;
    uint32_t addr;
    uint32_t bytes;
    uint32_t mnem;
    uint32_t reg;
    uint32_t num;
    uint32_t str;
    uint32_t sym;
    uint32_t call;
    uint32_t jmp;
    uint32_t ret;
    uint32_t cmt;
    uint32_t edge_t;
    uint32_t edge_f;
    uint32_t edge_u;
} opt_theme;

typedef struct {
    char      path[260];
    char      font[64];
    int       font_size;
    int       show_bytes;
    int       bytes_cols;
    int       upper_mnem;
    int       threads;
    int       min_str;
    int       max_ana_mb;
    int       theme_idx;
    char      plugins_allow[256];
    opt_theme th;
} opt_cfg;

void opt_defaults(opt_cfg *o);
void opt_set_theme(opt_cfg *o, const char *name);
void opt_next_theme(opt_cfg *o);
bool opt_load(opt_cfg *o, const char *path);
bool opt_write_default(const char *path);
