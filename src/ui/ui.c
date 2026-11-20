#include "ui.h"
#include "../scan/scan.h"

#include <commdlg.h>
#include <ctype.h>
#include <dwmapi.h>
#include <process.h>
#include <shellapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define UI_BAR_H 28
#define UI_NAV_H 14
#define UI_IN_H  24

static ui_app *g_ui;

static void ui_apply_titlebar(ui_app *u) {
    if (!u->hwnd) return;
    BOOL dark = (u->opt.theme_idx != 1);
    DwmSetWindowAttribute(u->hwnd, 20, &dark, sizeof(dark));
}

static void ui_load_fonts(ui_app *u) {
    if (u->font) DeleteObject(u->font);
    if (u->font_bold) DeleteObject(u->font_bold);
    u->font = CreateFontA(-u->opt.font_size, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                          DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                          CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, u->opt.font);
    u->font_bold = CreateFontA(-u->opt.font_size, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
                               DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                               CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, u->opt.font);

    HDC dc = GetDC(u->hwnd);
    HFONT old = (HFONT)SelectObject(dc, u->font);
    TEXTMETRICA tm;
    GetTextMetricsA(dc, &tm);
    u->cw = tm.tmAveCharWidth;
    u->lh = tm.tmHeight + 3;
    SelectObject(dc, old);
    ReleaseDC(u->hwnd, dc);
}

void ui_log(ui_app *u, const char *msg) {
    if (!msg) return;
    int idx = (u->log_head + u->log_cnt) % UI_MAX_LOG;
    if (u->log_cnt == UI_MAX_LOG) u->log_head = (u->log_head + 1) % UI_MAX_LOG;
    else u->log_cnt++;
    snprintf(u->logs[idx], sizeof(u->logs[idx]), "%s", msg);
}

static void ui_ext_log(void *ud, const char *msg) {
    ui_log((ui_app *)ud, msg);
}

static uint64_t ui_ext_get_va(void *ud) {
    return ((ui_app *)ud)->cur_va;
}

static void ui_ext_set_va(void *ud, uint64_t va) {
    ui_goto((ui_app *)ud, va, 1);
}

static bool ui_icontains(const char *hay, const char *needle) {
    if (!needle || !needle[0]) return true;
    if (!hay) return false;
    size_t nl = strlen(needle);
    for (const char *p = hay; *p; p++) {
        size_t i = 0;
        while (i < nl && p[i] && tolower((unsigned char)p[i]) == tolower((unsigned char)needle[i])) i++;
        if (i == nl) return true;
    }
    return false;
}

void ui_rebuild_list(ui_app *u) {
    u->list_cnt = 0;
    u->list_scroll = 0;
    uint32_t total = 0;
    if (u->tab == UI_TAB_FUNCS) total = u->ana.nfunc;
    else if (u->tab == UI_TAB_SYMS) total = u->ana.bin.nsym;
    else if (u->tab == UI_TAB_STRS) total = u->ana.nstr;
    else if (u->tab == UI_TAB_MARKS) total = u->ana.nmark;

    if (total > u->list_cap) {
        uint32_t *nl = (uint32_t *)realloc(u->list_idx, (size_t)total * sizeof(uint32_t));
        if (!nl) return;
        u->list_idx = nl;
        u->list_cap = total;
    }

    char sbuf[96];
    for (uint32_t i = 0; i < total; i++) {
        const char *text = NULL;
        if (u->tab == UI_TAB_FUNCS) text = ana_pool_str(&u->ana, u->ana.funcs[i].name_off);
        else if (u->tab == UI_TAB_SYMS) text = bin_str(&u->ana.bin, u->ana.bin.syms[i].name_off);
        else if (u->tab == UI_TAB_STRS) {
            ana_read_str(&u->ana, &u->ana.strs[i], sbuf, sizeof(sbuf));
            text = sbuf;
        } else if (u->tab == UI_TAB_MARKS) text = u->ana.marks[i].label;

        if (ui_icontains(text, u->filter)) u->list_idx[u->list_cnt++] = i;
    }
}

void ui_ensure_cfg(ui_app *u) {
    const ana_func *f = ana_func_at(&u->ana, u->cur_va);
    uint64_t fva = f ? f->start : u->cur_va;
    if (u->cfg.nblk > 0 && u->cfg_func_va == fva) return;

    u->cfg_func_va = fva;
    if (grp_build(&u->ana, u->cur_va, u->opt.upper_mnem, &u->cfg)) {
        grp_layout(&u->cfg, u->cw, u->lh);
        u->gx = 24.0;
        u->gy = 16.0;
        u->gz = 1.0;
    }
}

void ui_goto(ui_app *u, uint64_t va, int push_hist) {
    if (!bin_sec_at(&u->ana.bin, va)) return;
    if (push_hist && u->cur_va && u->cur_va != va) {
        if (u->hist_pos < UI_MAX_HIST) u->hist[u->hist_pos++] = u->cur_va;
        else {
            memmove(u->hist, u->hist + 1, (UI_MAX_HIST - 1) * sizeof(uint64_t));
            u->hist[UI_MAX_HIST - 1] = u->cur_va;
        }
        u->hist_len = u->hist_pos;
    }
    u->cur_va = va;
    u->top_va = va;
    if (u->mode == UI_MODE_GRAPH) u->cfg_func_va = 0;
}

static unsigned __stdcall ui_ana_thread(void *arg) {
    ui_app *u = (ui_app *)arg;
    ana_run(&u->ana, u->opt.threads, u->opt.min_str, u->opt.max_ana_mb);
    PostMessageA(u->hwnd, UI_WM_ANA_DONE, 0, 0);
    return 0;
}

static void ui_stop_ana(ui_app *u) {
    if (!u->ana_th) return;
    InterlockedExchange(&u->ana.cancel, 1);
    WaitForSingleObject(u->ana_th, INFINITE);
    CloseHandle(u->ana_th);
    u->ana_th = NULL;
}

static void ui_open_file(ui_app *u, const char *path) {
    ui_stop_ana(u);
    grp_free(&u->cfg);
    u->cfg_func_va = 0;
    u->hist_pos = 0;
    u->hist_len = 0;
    u->show_xrefs = 0;

    if (!ana_open(&u->ana, path, 0, 64)) {
        char msg[320];
        snprintf(msg, sizeof(msg), "failed to open: %s", path);
        ui_log(u, msg);
        return;
    }

    u->cur_va = u->ana.bin.entry;
    u->top_va = u->ana.bin.entry;

    char dbpath[520];
    snprintf(dbpath, sizeof(dbpath), "%s.xdb", path);
    if (db_load(&u->ana, dbpath)) ui_log(u, "loaded existing .xdb database");

    char msg[256];
    snprintf(msg, sizeof(msg), "opened %s (%s %d-bit, %.2f MB in %.1f ms) - analyzing...",
             path, bin_fmt_name(u->ana.bin.fmt), u->ana.bin.bits,
             (double)u->ana.bin.map.size / (1024.0 * 1024.0), u->ana.load_ms);
    ui_log(u, msg);

    char title[300];
    snprintf(title, sizeof(title), "xdis - %s", path);
    SetWindowTextA(u->hwnd, title);

    ui_rebuild_list(u);
    u->ana_th = (HANDLE)_beginthreadex(NULL, 0, ui_ana_thread, u, 0, NULL);
    InvalidateRect(u->hwnd, NULL, FALSE);
}

static void ui_open_dialog(ui_app *u) {
    char file[512] = "";
    OPENFILENAMEA ofn;
    memset(&ofn, 0, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = u->hwnd;
    ofn.lpstrFilter = "Binaries (*.exe;*.dll;*.sys;*.elf;*.so;*.bin)\0*.exe;*.dll;*.sys;*.elf;*.so;*.bin\0All Files\0*.*\0";
    ofn.lpstrFile = file;
    ofn.nMaxFile = sizeof(file);
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    if (GetOpenFileNameA(&ofn)) ui_open_file(u, file);
}

static void ui_find_next(ui_app *u, const char *query, int reset) {
    if (!query || !query[0] || u->ana.bin.map.size == 0) return;
    if (reset) {
        snprintf(u->last_find, sizeof(u->last_find), "%s", query);
        u->last_find_off = 0;
    }

    size_t sz = (size_t)u->ana.bin.map.size;
    size_t pos = sz;
    scan_pat pat;
    if (scan_pat_parse(&pat, u->last_find)) {
        pos = scan_pat_find(u->ana.bin.map.data, sz, (size_t)u->last_find_off, &pat);
    }
    if (pos >= sz) {
        pos = scan_text_find(u->ana.bin.map.data, sz, (size_t)u->last_find_off, u->last_find);
    }

    if (pos < sz) {
        u->last_find_off = pos + 1;
        uint64_t va = 0;
        if (bin_off_to_va(&u->ana.bin, pos, &va)) {
            ui_goto(u, va, 1);
            char msg[128];
            snprintf(msg, sizeof(msg), "match at 0x%llx (off 0x%zx)", (unsigned long long)va, pos);
            ui_log(u, msg);
        } else {
            char msg[128];
            snprintf(msg, sizeof(msg), "match at raw offset 0x%zx (unmapped)", pos);
            ui_log(u, msg);
        }
    } else {
        u->last_find_off = 0;
        ui_log(u, "no match found");
    }
}

static bool ui_parse_addr(const ui_app *u, const char *s, uint64_t *va) {
    if (!s || !s[0]) return false;
    if (ana_find_sym(&u->ana, s, va)) return true;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s += 2;
    char *end = NULL;
    uint64_t v = strtoull(s, &end, 16);
    if (end == s) return false;
    *va = v;
    return true;
}

static void ui_exec_cmd(ui_app *u, const char *raw) {
    char cmd[48] = "";
    const char *p = raw;
    while (*p == ' ' || *p == ':') p++;
    size_t i = 0;
    while (*p && *p != ' ' && i + 1 < sizeof(cmd)) cmd[i++] = *p++;
    cmd[i] = 0;
    while (*p == ' ') p++;
    if (!cmd[0]) return;

    if (_stricmp(cmd, "goto") == 0 || _stricmp(cmd, "g") == 0) {
        uint64_t va;
        if (ui_parse_addr(u, p, &va)) ui_goto(u, va, 1);
        else ui_log(u, "bad address or symbol");
    } else if (_stricmp(cmd, "rename") == 0 || _stricmp(cmd, "n") == 0) {
        if (*p) {
            ana_set_name(&u->ana, u->cur_va, p);
            ui_rebuild_list(u);
            ui_log(u, "symbol updated");
        }
    } else if (_stricmp(cmd, "cmt") == 0) {
        ana_set_cmt(&u->ana, u->cur_va, p);
    } else if (_stricmp(cmd, "mark") == 0 || _stricmp(cmd, "bm") == 0) {
        ana_add_mark(&u->ana, u->cur_va, *p ? p : "bookmark");
        if (u->tab == UI_TAB_MARKS) ui_rebuild_list(u);
        ui_log(u, "bookmark added");
    } else if (_stricmp(cmd, "find") == 0 || _stricmp(cmd, "f") == 0) {
        ui_find_next(u, p, 1);
    } else if (_stricmp(cmd, "patch") == 0) {
        unsigned int bv = 0;
        if (sscanf(p, "%x", &bv) == 1 && ana_patch_byte(&u->ana, u->cur_va, (uint8_t)bv)) {
            u->cfg_func_va = 0;
            ui_log(u, "patched byte (copy-on-write)");
        } else {
            ui_log(u, "patch failed (unmapped or read-only)");
        }
    } else if (_stricmp(cmd, "theme") == 0) {
        if (*p) opt_set_theme(&u->opt, p);
        else opt_next_theme(&u->opt);
        ui_apply_titlebar(u);
        ui_log(u, u->opt.th.name);
    } else if (_stricmp(cmd, "reload") == 0) {
        opt_load(&u->opt, u->opt.path);
        ui_load_fonts(u);
        ui_apply_titlebar(u);
        ui_log(u, "reloaded xdis.ini");
    } else if (_stricmp(cmd, "bytes") == 0) {
        u->opt.show_bytes = !u->opt.show_bytes;
    } else if (_stricmp(cmd, "upper") == 0) {
        u->opt.upper_mnem = !u->opt.upper_mnem;
        u->cfg_func_va = 0;
    } else if (_stricmp(cmd, "save") == 0) {
        char dbp[520];
        snprintf(dbp, sizeof(dbp), "%s.xdb", u->ana.bin.path);
        ui_log(u, db_save(&u->ana, dbp) ? "saved .xdb database" : "save failed");
    } else if (_stricmp(cmd, "open") == 0 && *p) {
        ui_open_file(u, p);
    } else if (_stricmp(cmd, "help") == 0) {
        ui_log(u, "cmds: goto rename cmt mark find patch theme reload bytes upper save open | plugins: entropy");
        ui_log(u, "keys: Space=Graph H=Hex G=Goto N=Rename ;=Cmt X=Xrefs M=Mark /=Filter Ctrl+F=Find Ctrl+T=Theme Esc=Back");
    } else if (!ext_run(&u->ext, cmd, p)) {
        char msg[96];
        snprintf(msg, sizeof(msg), "unknown command: %s (try :help)", cmd);
        ui_log(u, msg);
    }
}

static void ui_submit_prompt(ui_app *u) {
    ui_prompt pr = u->prompt;
    u->prompt = UI_PROMPT_NONE;

    if (pr == UI_PROMPT_CMD) ui_exec_cmd(u, u->in_buf);
    else if (pr == UI_PROMPT_GOTO) {
        uint64_t va;
        if (ui_parse_addr(u, u->in_buf, &va)) ui_goto(u, va, 1);
        else ui_log(u, "symbol/address not found");
    } else if (pr == UI_PROMPT_RENAME && u->in_buf[0]) {
        ana_set_name(&u->ana, u->cur_va, u->in_buf);
        ui_rebuild_list(u);
    } else if (pr == UI_PROMPT_CMT) {
        ana_set_cmt(&u->ana, u->cur_va, u->in_buf);
    } else if (pr == UI_PROMPT_FIND) {
        ui_find_next(u, u->in_buf, 1);
    } else if (pr == UI_PROMPT_MARK) {
        ana_add_mark(&u->ana, u->cur_va, u->in_buf[0] ? u->in_buf : "mark");
        if (u->tab == UI_TAB_MARKS) ui_rebuild_list(u);
    } else if (pr == UI_PROMPT_PATCH) {
        unsigned int bv = 0;
        if (sscanf(u->in_buf, "%x", &bv) == 1 && ana_patch_byte(&u->ana, u->cur_va, (uint8_t)bv)) {
            u->cfg_func_va = 0;
            ui_log(u, "byte patched");
        }
    } else if (pr == UI_PROMPT_FILTER) {
        snprintf(u->filter, sizeof(u->filter), "%s", u->in_buf);
        ui_rebuild_list(u);
    }
}

static void ui_start_prompt(ui_app *u, ui_prompt p, const char *prefill) {
    u->prompt = p;
    snprintf(u->in_buf, sizeof(u->in_buf), "%s", prefill ? prefill : "");
    u->in_len = (int)strlen(u->in_buf);
    InvalidateRect(u->hwnd, NULL, FALSE);
}

static void ui_draw_bar(HDC dc, const ui_app *u, RECT rc) {
    const opt_theme *t = &u->opt.th;
    HBRUSH bg = CreateSolidBrush(t->bg_panel);
    FillRect(dc, &rc, bg);
    DeleteObject(bg);

    static const char *const modes[3] = { "Linear", "Graph", "Hex" };
    int x = rc.left + 8;
    for (int i = 0; i < 3; i++) {
        RECT br = { x, rc.top + 4, x + 64, rc.bottom - 4 };
        HBRUSH bb = CreateSolidBrush((int)u->mode == i ? t->bg_sel : t->bg_alt);
        FillRect(dc, &br, bb);
        DeleteObject(bb);
        SetTextColor(dc, (int)u->mode == i ? t->fg : t->fg_dim);
        TextOutA(dc, br.left + 10, br.top + 2, modes[i], (int)strlen(modes[i]));
        x += 70;
    }

    char stat[220];
    if (u->ana.bin.nsec == 0) {
        snprintf(stat, sizeof(stat), "xdis | theme: %s | Ctrl+O open | :help", u->opt.th.name);
    } else if (u->ana.busy) {
        snprintf(stat, sizeof(stat), "%s %d-bit | analyzing %ld%%... | theme: %s",
                 bin_fmt_name(u->ana.bin.fmt), u->ana.bin.bits, u->ana.pct, u->opt.th.name);
    } else {
        snprintf(stat, sizeof(stat), "%s %d-bit | %.1f ms | %u funcs | %u xrefs | %u strs | %s",
                 bin_fmt_name(u->ana.bin.fmt), u->ana.bin.bits, u->ana.ana_ms,
                 u->ana.nfunc, u->ana.nxref, u->ana.nstr, u->opt.th.name);
    }
    SetTextColor(dc, t->fg_dim);
    TextOutA(dc, x + 12, rc.top + 6, stat, (int)strlen(stat));
}

static void ui_draw_bottom(HDC dc, const ui_app *u, RECT rc) {
    const opt_theme *t = &u->opt.th;
    RECT log_rc = { rc.left, rc.top, rc.right, rc.bottom - UI_IN_H };
    RECT in_rc  = { rc.left, rc.bottom - UI_IN_H, rc.right, rc.bottom };

    HBRUSH lb = CreateSolidBrush(t->bg_panel);
    FillRect(dc, &log_rc, lb);
    DeleteObject(lb);

    HPEN bp = CreatePen(PS_SOLID, 1, t->border);
    HPEN op = (HPEN)SelectObject(dc, bp);
    MoveToEx(dc, rc.left, rc.top, NULL);
    LineTo(dc, rc.right, rc.top);
    SelectObject(dc, op);
    DeleteObject(bp);

    int vis = (log_rc.bottom - log_rc.top - 4) / u->lh;
    int start = u->log_cnt > vis ? u->log_cnt - vis : 0;
    int y = log_rc.top + 3;
    SetTextColor(dc, t->fg_dim);
    for (int i = start; i < u->log_cnt; i++) {
        int idx = (u->log_head + i) % UI_MAX_LOG;
        TextOutA(dc, log_rc.left + 8, y, u->logs[idx], (int)strlen(u->logs[idx]));
        y += u->lh;
    }

    HBRUSH ib = CreateSolidBrush(u->prompt ? t->bg_cur : t->bg_alt);
    FillRect(dc, &in_rc, ib);
    DeleteObject(ib);

    const char *pfx = "";
    switch (u->prompt) {
    case UI_PROMPT_CMD:    pfx = ": "; break;
    case UI_PROMPT_GOTO:   pfx = "goto (va/sym)> "; break;
    case UI_PROMPT_RENAME: pfx = "rename> "; break;
    case UI_PROMPT_CMT:    pfx = "comment> "; break;
    case UI_PROMPT_FIND:   pfx = "find (hex/str)> "; break;
    case UI_PROMPT_MARK:   pfx = "bookmark> "; break;
    case UI_PROMPT_PATCH:  pfx = "patch byte (hex)> "; break;
    case UI_PROMPT_FILTER: pfx = "filter> "; break;
    default:               pfx = ""; break;
    }

    char bar[320];
    if (u->prompt) {
        snprintf(bar, sizeof(bar), "%s%s_", pfx, u->in_buf);
        SetTextColor(dc, t->fg);
    } else {
        const bin_sec *s = bin_sec_at(&u->ana.bin, u->cur_va);
        const ana_func *f = ana_func_at(&u->ana, u->cur_va);
        snprintf(bar, sizeof(bar), "va=0x%016llx  sec=%s  fn=%s  | : cmd  Space graph  G goto  X xrefs  N rename  ; cmt",
                 (unsigned long long)u->cur_va,
                 s ? s->name : "-",
                 f ? ana_pool_str(&u->ana, f->name_off) : "-");
        SetTextColor(dc, t->fg_dim);
    }
    TextOutA(dc, in_rc.left + 8, in_rc.top + 4, bar, (int)strlen(bar));
}

static void ui_draw_xrefs_box(HDC dc, const ui_app *u, RECT main_rc) {
    if (!u->show_xrefs) return;
    const opt_theme *t = &u->opt.th;
    int bw = 460, bh = 280;
    int x = main_rc.left + ((main_rc.right - main_rc.left) - bw) / 2;
    int y = main_rc.top + ((main_rc.bottom - main_rc.top) - bh) / 2;
    RECT r = { x, y, x + bw, y + bh };

    HBRUSH bg = CreateSolidBrush(t->bg_panel);
    FillRect(dc, &r, bg);
    DeleteObject(bg);

    HPEN pen = CreatePen(PS_SOLID, 2, t->sym);
    HPEN op = (HPEN)SelectObject(dc, pen);
    HBRUSH ob = (HBRUSH)SelectObject(dc, GetStockObject(NULL_BRUSH));
    Rectangle(dc, r.left, r.top, r.right, r.bottom);
    SelectObject(dc, ob);
    SelectObject(dc, op);
    DeleteObject(pen);

    char hdr[128];
    snprintf(hdr, sizeof(hdr), "Xrefs to 0x%llx (%u)  [Enter=Jump, Esc=Close]",
             (unsigned long long)u->xref_va, u->xref_cnt);
    SelectObject(dc, u->font_bold);
    SetTextColor(dc, t->sym);
    TextOutA(dc, r.left + 10, r.top + 8, hdr, (int)strlen(hdr));
    SelectObject(dc, u->font);

    int max_vis = (bh - 36) / u->lh;
    int start = (u->xref_sel >= max_vis) ? (u->xref_sel - max_vis + 1) : 0;
    int ry = r.top + 30;
    for (int i = 0; i < max_vis && (uint32_t)(start + i) < u->xref_cnt; i++) {
        uint32_t idx = u->xref_first + (uint32_t)(start + i);
        const ana_xref *xr = &u->ana.xrefs[idx];
        if (start + i == u->xref_sel) {
            RECT sr = { r.left + 4, ry, r.right - 4, ry + u->lh };
            HBRUSH sb = CreateSolidBrush(t->bg_sel);
            FillRect(dc, &sr, sb);
            DeleteObject(sb);
        }
        const ana_func *fn = ana_func_at(&u->ana, xr->from);
        const char *k = (xr->type == ANA_XREF_CALL) ? "CALL" : (xr->type == ANA_XREF_JMP) ? "JMP " : "DATA";
        char line[128];
        snprintf(line, sizeof(line), "%s  0x%016llx  (%s)", k, (unsigned long long)xr->from,
                 fn ? ana_pool_str(&u->ana, fn->name_off) : "-");
        SetTextColor(dc, xr->type == ANA_XREF_CALL ? t->call : t->fg);
        TextOutA(dc, r.left + 12, ry + 1, line, (int)strlen(line));
        ry += u->lh;
    }
}

static void ui_paint(ui_app *u) {
    PAINTSTRUCT ps;
    HDC hdc = BeginPaint(u->hwnd, &ps);
    RECT cr;
    GetClientRect(u->hwnd, &cr);
    int w = cr.right - cr.left;
    int h = cr.bottom - cr.top;
    if (w <= 0 || h <= 0) { EndPaint(u->hwnd, &ps); return; }

    HDC mem = CreateCompatibleDC(hdc);
    HBITMAP bmp = CreateCompatibleBitmap(hdc, w, h);
    HBITMAP oldb = (HBITMAP)SelectObject(mem, bmp);
    HFONT oldf = (HFONT)SelectObject(mem, u->font);
    SetBkMode(mem, TRANSPARENT);

    RECT bar_rc  = { 0, 0, w, UI_BAR_H };
    RECT nav_rc  = { 0, UI_BAR_H, w, UI_BAR_H + UI_NAV_H };
    int body_top = UI_BAR_H + UI_NAV_H;
    int body_bot = h - u->log_h;
    if (body_bot < body_top + 60) body_bot = body_top + 60;

    RECT side_rc = { 0, body_top, u->side_w, body_bot };
    RECT main_rc = { u->side_w, body_top, w, body_bot };
    RECT bot_rc  = { 0, body_bot, w, h };

    ui_draw_bar(mem, u, bar_rc);
    ui_draw_nav(mem, u, nav_rc);
    ui_draw_sidebar(mem, u, side_rc);

    if (u->mode == UI_MODE_LINEAR) ui_draw_linear(mem, u, main_rc);
    else if (u->mode == UI_MODE_GRAPH) ui_draw_graph(mem, u, main_rc);
    else ui_draw_hex(mem, u, main_rc);

    ui_draw_xrefs_box(mem, u, main_rc);
    ui_draw_bottom(mem, u, bot_rc);

    BitBlt(hdc, 0, 0, w, h, mem, 0, 0, SRCCOPY);
    SelectObject(mem, oldf);
    SelectObject(mem, oldb);
    DeleteObject(bmp);
    DeleteDC(mem);
    EndPaint(u->hwnd, &ps);
}

static void ui_follow_cur(ui_app *u) {
    size_t avail = 0;
    const uint8_t *p = bin_ptr(&u->ana.bin, u->cur_va, &avail);
    if (!p || avail == 0) return;
    x86_ins ins;
    if (arch_decode(u->ana.bin.arch, p, avail, u->cur_va, 0, 0, &ins) > 0 && ins.has_target) {
        ui_goto(u, ins.target, 1);
    }
}

static void ui_scroll_lines(ui_app *u, int delta) {
    if (u->ana.bin.nsec == 0) return;
    if (u->mode == UI_MODE_HEX) {
        int64_t step = (int64_t)delta * 16;
        uint64_t nv = (step < 0 && u->top_va < (uint64_t)(-step)) ? u->ana.bin.min_va : u->top_va + (uint64_t)step;
        if (bin_sec_at(&u->ana.bin, nv)) u->top_va = nv;
        return;
    }
    int steps = delta < 0 ? -delta : delta;
    for (int i = 0; i < steps; i++) {
        u->top_va = (delta > 0) ? ana_next_va(&u->ana, u->top_va) : ana_prev_va(&u->ana, u->top_va);
    }
}

static void ui_on_click(ui_app *u, int x, int y, int dbl) {
    int body_top = UI_BAR_H + UI_NAV_H;
    int body_bot = u->win_h - u->log_h;

    if (y < UI_BAR_H) {
        if (x >= 8 && x < 72) u->mode = UI_MODE_LINEAR;
        else if (x >= 78 && x < 142) u->mode = UI_MODE_GRAPH;
        else if (x >= 148 && x < 212) u->mode = UI_MODE_HEX;
        InvalidateRect(u->hwnd, NULL, FALSE);
        return;
    }

    if (y < body_top && u->ana.bin.max_va > u->ana.bin.min_va) {
        double frac = (double)x / (double)(u->win_w > 1 ? u->win_w : 1);
        uint64_t va = u->ana.bin.min_va + (uint64_t)(frac * (double)(u->ana.bin.max_va - u->ana.bin.min_va));
        const bin_sec *s = bin_sec_at(&u->ana.bin, va);
        if (s) ui_goto(u, va, 1);
        InvalidateRect(u->hwnd, NULL, FALSE);
        return;
    }

    if (abs(x - u->side_w) <= 5 && y >= body_top && y < body_bot) {
        u->drag_split = 1;
        SetCapture(u->hwnd);
        return;
    }

    if (x < u->side_w && y >= body_top && y < body_bot) {
        int ly = y - body_top;
        if (ly < 24) {
            int tw = u->side_w / 4;
            int nt = x / (tw > 1 ? tw : 1);
            if (nt >= 0 && nt < 4) {
                u->tab = (ui_tab)nt;
                ui_rebuild_list(u);
            }
        } else if (ly < 52) {
            ui_start_prompt(u, UI_PROMPT_FILTER, u->filter);
        } else {
            int row = (ly - 56) / u->lh + u->list_scroll;
            if (row >= 0 && (uint32_t)row < u->list_cnt) {
                uint32_t idx = u->list_idx[row];
                uint64_t va = 0;
                if (u->tab == UI_TAB_FUNCS && idx < u->ana.nfunc) va = u->ana.funcs[idx].start;
                else if (u->tab == UI_TAB_SYMS && idx < u->ana.bin.nsym) va = u->ana.bin.syms[idx].va;
                else if (u->tab == UI_TAB_STRS && idx < u->ana.nstr) va = u->ana.strs[idx].va;
                else if (u->tab == UI_TAB_MARKS && idx < u->ana.nmark) va = u->ana.marks[idx].va;
                if (va) ui_goto(u, va, 1);
            }
        }
        InvalidateRect(u->hwnd, NULL, FALSE);
        return;
    }

    if (y >= body_top && y < body_bot) {
        RECT main_rc = { u->side_w, body_top, u->win_w, body_bot };
        if (u->mode == UI_MODE_GRAPH) {
            uint64_t va = 0, tgt = 0;
            if (ui_graph_hit(u, main_rc, x, y, &va, &tgt)) {
                u->cur_va = va;
                if (dbl && tgt) ui_goto(u, tgt, 1);
            } else {
                u->drag_graph = 1;
                u->drag_x = x;
                u->drag_y = y;
                SetCapture(u->hwnd);
            }
        } else {
            int row = (y - body_top - 2) / u->lh;
            if (row >= 0 && row < u->row_cnt) {
                u->cur_va = u->row_vas[row];
                if (dbl && u->row_tgts[row]) ui_goto(u, u->row_tgts[row], 1);
            }
        }
        InvalidateRect(u->hwnd, NULL, FALSE);
    }
}

static void ui_on_key(ui_app *u, WPARAM vk) {
    int ctrl = (GetKeyState(VK_CONTROL) & 0x8000) != 0;

    if (u->prompt) {
        if (vk == VK_ESCAPE) u->prompt = UI_PROMPT_NONE;
        else if (vk == VK_RETURN) ui_submit_prompt(u);
        else if (vk == VK_BACK && u->in_len > 0) u->in_buf[--u->in_len] = 0;
        InvalidateRect(u->hwnd, NULL, FALSE);
        return;
    }

    if (u->show_xrefs) {
        if (vk == VK_ESCAPE) u->show_xrefs = 0;
        else if (vk == VK_UP && u->xref_sel > 0) u->xref_sel--;
        else if (vk == VK_DOWN && (uint32_t)(u->xref_sel + 1) < u->xref_cnt) u->xref_sel++;
        else if (vk == VK_RETURN && u->xref_cnt > 0) {
            uint64_t from = u->ana.xrefs[u->xref_first + (uint32_t)u->xref_sel].from;
            u->show_xrefs = 0;
            ui_goto(u, from, 1);
        }
        InvalidateRect(u->hwnd, NULL, FALSE);
        return;
    }

    if (ctrl) {
        if (vk == 'O') ui_open_dialog(u);
        else if (vk == 'F') ui_start_prompt(u, UI_PROMPT_FIND, u->last_find);
        else if (vk == 'T') { opt_next_theme(&u->opt); ui_apply_titlebar(u); ui_log(u, u->opt.th.name); }
        else if (vk == 'R') { opt_load(&u->opt, u->opt.path); ui_load_fonts(u); ui_apply_titlebar(u); ui_log(u, "reloaded xdis.ini"); }
        else if (vk == 'S' && u->ana.bin.path[0]) {
            char dbp[520];
            snprintf(dbp, sizeof(dbp), "%s.xdb", u->ana.bin.path);
            ui_log(u, db_save(&u->ana, dbp) ? "saved .xdb database" : "save failed");
        } else if (vk == 'E') ui_start_prompt(u, UI_PROMPT_PATCH, "");
        InvalidateRect(u->hwnd, NULL, FALSE);
        return;
    }

    switch (vk) {
    case VK_SPACE:
        u->mode = (u->mode == UI_MODE_GRAPH) ? UI_MODE_LINEAR : UI_MODE_GRAPH;
        if (u->mode == UI_MODE_GRAPH) u->cfg_func_va = 0;
        break;
    case 'H':
        u->mode = (u->mode == UI_MODE_HEX) ? UI_MODE_LINEAR : UI_MODE_HEX;
        break;
    case 'G':
        ui_start_prompt(u, UI_PROMPT_GOTO, "");
        return;
    case 'N':
        ui_start_prompt(u, UI_PROMPT_RENAME, ana_sym_at(&u->ana, u->cur_va));
        return;
    case 'M':
        ui_start_prompt(u, UI_PROMPT_MARK, "");
        return;
    case 'X':
        u->xref_va = u->cur_va;
        u->xref_cnt = ana_xrefs_to(&u->ana, u->cur_va, &u->xref_first);
        u->xref_sel = 0;
        u->show_xrefs = 1;
        break;
    case VK_F3:
        if (u->last_find[0]) ui_find_next(u, u->last_find, 0);
        break;
    case VK_RETURN:
        ui_follow_cur(u);
        break;
    case VK_ESCAPE:
        if (u->hist_pos > 0) ui_goto(u, u->hist[--u->hist_pos], 0);
        break;
    case VK_DOWN:
        u->cur_va = ana_next_va(&u->ana, u->cur_va);
        if (u->row_cnt > 0 && u->cur_va > u->row_vas[u->row_cnt - 1]) ui_scroll_lines(u, 1);
        break;
    case VK_UP:
        u->cur_va = ana_prev_va(&u->ana, u->cur_va);
        if (u->cur_va < u->top_va) u->top_va = u->cur_va;
        break;
    case VK_NEXT:
        ui_scroll_lines(u, 20);
        u->cur_va = u->top_va;
        break;
    case VK_PRIOR:
        ui_scroll_lines(u, -20);
        u->cur_va = u->top_va;
        break;
    default:
        return;
    }
    InvalidateRect(u->hwnd, NULL, FALSE);
}

static LRESULT CALLBACK ui_wndproc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    ui_app *u = g_ui;
    if (!u) return DefWindowProcA(hwnd, msg, wp, lp);

    switch (msg) {
    case WM_SIZE:
        u->win_w = LOWORD(lp);
        u->win_h = HIWORD(lp);
        InvalidateRect(hwnd, NULL, FALSE);
        return 0;

    case WM_PAINT:
        ui_paint(u);
        return 0;

    case WM_ERASEBKGND:
        return 1;

    case WM_LBUTTONDOWN:
        ui_on_click(u, (short)LOWORD(lp), (short)HIWORD(lp), 0);
        return 0;

    case WM_LBUTTONDBLCLK:
        ui_on_click(u, (short)LOWORD(lp), (short)HIWORD(lp), 1);
        return 0;

    case WM_MOUSEMOVE: {
        int mx = (short)LOWORD(lp), my = (short)HIWORD(lp);
        if (u->drag_split) {
            u->side_w = mx;
            if (u->side_w < 140) u->side_w = 140;
            if (u->side_w > u->win_w - 240) u->side_w = u->win_w - 240;
            InvalidateRect(hwnd, NULL, FALSE);
        } else if (u->drag_graph) {
            u->gx += (double)(mx - u->drag_x) / u->gz;
            u->gy += (double)(my - u->drag_y) / u->gz;
            u->drag_x = mx;
            u->drag_y = my;
            InvalidateRect(hwnd, NULL, FALSE);
        }
        return 0;
    }

    case WM_LBUTTONUP:
        if (u->drag_graph || u->drag_split) {
            u->drag_graph = 0;
            u->drag_split = 0;
            ReleaseCapture();
        }
        return 0;

    case WM_MOUSEWHEEL: {
        POINT pt = { (short)LOWORD(lp), (short)HIWORD(lp) };
        ScreenToClient(hwnd, &pt);
        int z = GET_WHEEL_DELTA_WPARAM(wp);
        if (pt.x < u->side_w) {
            u->list_scroll += (z > 0 ? -4 : 4);
            if (u->list_scroll < 0) u->list_scroll = 0;
        } else if (u->mode == UI_MODE_GRAPH) {
            u->gz *= (z > 0) ? 1.12 : 0.89;
            if (u->gz < 0.25) u->gz = 0.25;
            if (u->gz > 2.5) u->gz = 2.5;
        } else {
            ui_scroll_lines(u, z > 0 ? -4 : 4);
        }
        InvalidateRect(hwnd, NULL, FALSE);
        return 0;
    }

    case WM_KEYDOWN:
        ui_on_key(u, wp);
        return 0;

    case WM_CHAR: {
        char ch = (char)wp;
        if (u->prompt) {
            if (ch >= 0x20 && ch <= 0x7E && u->in_len + 1 < (int)sizeof(u->in_buf)) {
                u->in_buf[u->in_len++] = ch;
                u->in_buf[u->in_len] = 0;
                InvalidateRect(hwnd, NULL, FALSE);
            }
            return 0;
        }
        if (ch == ':') ui_start_prompt(u, UI_PROMPT_CMD, "");
        else if (ch == ';') ui_start_prompt(u, UI_PROMPT_CMT, ana_cmt_at(&u->ana, u->cur_va));
        else if (ch == '/') ui_start_prompt(u, UI_PROMPT_FILTER, u->filter);
        return 0;
    }

    case WM_DROPFILES: {
        char path[512];
        if (DragQueryFileA((HDROP)wp, 0, path, sizeof(path))) ui_open_file(u, path);
        DragFinish((HDROP)wp);
        return 0;
    }

    case WM_TIMER:
        if (u->ana.busy) InvalidateRect(hwnd, NULL, FALSE);
        return 0;

    case UI_WM_ANA_DONE: {
        char buf[160];
        snprintf(buf, sizeof(buf), "analysis done in %.1f ms: %u funcs, %u xrefs, %u strings",
                 u->ana.ana_ms, u->ana.nfunc, u->ana.nxref, u->ana.nstr);
        ui_log(u, buf);
        ui_rebuild_list(u);
        u->cfg_func_va = 0;
        InvalidateRect(hwnd, NULL, FALSE);
        return 0;
    }

    case WM_DESTROY:
        ui_stop_ana(u);
        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProcA(hwnd, msg, wp, lp);
}

int ui_run(const char *init_path) {
    ui_app app;
    memset(&app, 0, sizeof(app));
    g_ui = &app;

    opt_defaults(&app.opt);
    if (!opt_load(&app.opt, "xdis.ini")) opt_write_default("xdis.ini");

    ana_init(&app.ana);
    ext_init(&app.ext, &app.ana, &app, ui_ext_log, ui_ext_get_va, ui_ext_set_va);
    app.side_w = 270;
    app.log_h = 112;
    app.gz = 1.0;

    WNDCLASSA wc;
    memset(&wc, 0, sizeof(wc));
    wc.style = CS_DBLCLKS | CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = ui_wndproc;
    wc.hInstance = GetModuleHandleA(NULL);
    wc.hCursor = LoadCursorA(NULL, IDC_ARROW);
    wc.lpszClassName = "xdis_wnd";
    RegisterClassA(&wc);

    app.hwnd = CreateWindowExA(WS_EX_ACCEPTFILES, "xdis_wnd", "xdis",
                               WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                               CW_USEDEFAULT, CW_USEDEFAULT, 1360, 860,
                               NULL, NULL, wc.hInstance, NULL);
    if (!app.hwnd) return 1;

    ui_apply_titlebar(&app);
    ui_load_fonts(&app);
    SetTimer(app.hwnd, 1, 120, NULL);

    uint32_t np = ext_load_dir_allow(&app.ext, "plugins", app.opt.plugins_allow);
    if (np == 0) ui_log(&app, "xdis ready (press :help for commands)");
    if (init_path && init_path[0]) ui_open_file(&app, init_path);

    MSG m;
    while (GetMessageA(&m, NULL, 0, 0) > 0) {
        TranslateMessage(&m);
        DispatchMessageA(&m);
    }

    ext_free(&app.ext);
    grp_free(&app.cfg);
    ana_free(&app.ana);
    free(app.list_idx);
    if (app.font) DeleteObject(app.font);
    if (app.font_bold) DeleteObject(app.font_bold);
    g_ui = NULL;
    return 0;
}
