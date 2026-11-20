#pragma once

#include "../ana/ana.h"
#include "../ext/ext.h"
#include "../opt/opt.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

typedef enum {
    UI_MODE_LINEAR = 0,
    UI_MODE_GRAPH,
    UI_MODE_HEX
} ui_mode;

typedef enum {
    UI_TAB_FUNCS = 0,
    UI_TAB_SYMS,
    UI_TAB_STRS,
    UI_TAB_MARKS
} ui_tab;

typedef enum {
    UI_PROMPT_NONE = 0,
    UI_PROMPT_CMD,
    UI_PROMPT_GOTO,
    UI_PROMPT_RENAME,
    UI_PROMPT_CMT,
    UI_PROMPT_FIND,
    UI_PROMPT_MARK,
    UI_PROMPT_PATCH,
    UI_PROMPT_FILTER
} ui_prompt;

#define UI_MAX_ROWS 128
#define UI_MAX_LOG  128
#define UI_MAX_HIST 256
#define UI_WM_ANA_DONE (WM_APP + 1)

typedef struct {
    HWND      hwnd;
    HFONT     font;
    HFONT     font_bold;
    int       cw;
    int       lh;
    int       win_w;
    int       win_h;
    int       side_w;
    int       log_h;

    opt_cfg   opt;
    ana_ctx   ana;
    ext_host  ext;
    grp_cfg   cfg;
    uint64_t  cfg_func_va;

    ui_mode   mode;
    ui_tab    tab;
    uint64_t  top_va;
    uint64_t  cur_va;
    uint64_t  row_vas[UI_MAX_ROWS];
    uint64_t  row_tgts[UI_MAX_ROWS];
    int       row_cnt;

    uint64_t  hist[UI_MAX_HIST];
    int       hist_pos;
    int       hist_len;

    double    gx, gy, gz;
    int       drag_graph;
    int       drag_split;
    int       drag_x, drag_y;

    char      filter[64];
    uint32_t *list_idx;
    uint32_t  list_cnt;
    uint32_t  list_cap;
    int       list_scroll;

    ui_prompt prompt;
    char      in_buf[256];
    int       in_len;

    int       show_xrefs;
    uint64_t  xref_va;
    uint32_t  xref_first;
    uint32_t  xref_cnt;
    int       xref_sel;

    char      last_find[128];
    uint64_t  last_find_off;

    char      logs[UI_MAX_LOG][160];
    int       log_head;
    int       log_cnt;
    HANDLE    ana_th;
} ui_app;

int  ui_run(const char *init_path);
void ui_log(ui_app *u, const char *msg);
void ui_goto(ui_app *u, uint64_t va, int push_hist);
void ui_rebuild_list(ui_app *u);
void ui_ensure_cfg(ui_app *u);
void ui_draw_ops(HDC dc, const ui_app *u, int x, int y, const char *ops);

void ui_draw_linear(HDC dc, ui_app *u, RECT rc);
void ui_draw_hex(HDC dc, ui_app *u, RECT rc);
void ui_draw_graph(HDC dc, ui_app *u, RECT rc);
bool ui_graph_hit(const ui_app *u, RECT rc, int mx, int my, uint64_t *va, uint64_t *tgt);
void ui_draw_sidebar(HDC dc, ui_app *u, RECT rc);
void ui_draw_nav(HDC dc, const ui_app *u, RECT rc);
