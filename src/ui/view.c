#include "ui.h"

#include <ctype.h>
#include <math.h>
#include <stdio.h>
#include <string.h>

static int ui_gx(const ui_app *u, RECT rc, int x) {
    return rc.left + (int)((x + u->gx) * u->gz);
}

static int ui_gy(const ui_app *u, RECT rc, int y) {
    return rc.top + (int)((y + u->gy) * u->gz);
}

static void ui_draw_arrow(HDC dc, int x1, int y1, int x2, int y2, uint32_t col, int dashed) {
    HPEN pen = CreatePen(dashed ? PS_DOT : PS_SOLID, dashed ? 1 : 2, col);
    HPEN old = (HPEN)SelectObject(dc, pen);
    int mid_y = (y1 + y2) / 2;

    if (y2 >= y1) {
        POINT pts[4] = { {x1, y1}, {x1, mid_y}, {x2, mid_y}, {x2, y2} };
        Polyline(dc, pts, 4);
    } else {
        // avoid overlapping block body
        int side_x = (x1 > x2 ? x1 : x2) + 28;
        POINT pts[6] = {
            {x1, y1}, {x1, y1 + 12}, {side_x, y1 + 12},
            {side_x, y2 - 14}, {x2, y2 - 14}, {x2, y2}
        };
        Polyline(dc, pts, 6);
    }

    POINT head[3] = { {x2, y2}, {x2 - 4, y2 - 7}, {x2 + 4, y2 - 7} };
    HBRUSH br = CreateSolidBrush(col);
    HBRUSH ob = (HBRUSH)SelectObject(dc, br);
    Polygon(dc, head, 3);
    SelectObject(dc, ob);
    DeleteObject(br);
    SelectObject(dc, old);
    DeleteObject(pen);
}

void ui_draw_graph(HDC dc, ui_app *u, RECT rc) {
    const opt_theme *t = &u->opt.th;
    HBRUSH bg = CreateSolidBrush(t->bg);
    FillRect(dc, &rc, bg);
    DeleteObject(bg);

    ui_ensure_cfg(u);
    const grp_cfg *g = &u->cfg;
    if (g->nblk == 0) {
        SetTextColor(dc, t->fg_dim);
        const char *m = "No executable CFG at current address (Space -> Linear)";
        TextOutA(dc, rc.left + 20, rc.top + 20, m, (int)strlen(m));
        return;
    }

    HRGN clip = CreateRectRgn(rc.left, rc.top, rc.right, rc.bottom);
    SelectClipRgn(dc, clip);

    for (uint32_t e = 0; e < g->nedge; e++) {
        const grp_edge *ed = &g->edges[e];
        const grp_blk *a = &g->blks[ed->from];
        const grp_blk *b = &g->blks[ed->to];
        int sx_off = (ed->kind == GRP_EDGE_TRUE) ? (a->w * 2 / 3) : (ed->kind == GRP_EDGE_FALSE) ? (a->w / 3) : (a->w / 2);
        int x1 = ui_gx(u, rc, a->x + sx_off);
        int y1 = ui_gy(u, rc, a->y + a->h);
        int x2 = ui_gx(u, rc, b->x + b->w / 2);
        int y2 = ui_gy(u, rc, b->y);
        uint32_t col = (ed->kind == GRP_EDGE_TRUE) ? t->edge_t
                     : (ed->kind == GRP_EDGE_FALSE) ? t->edge_f : t->edge_u;
        ui_draw_arrow(dc, x1, y1, x2, y2, col, ed->back);
    }

    int show_text = (u->gz >= 0.55);
    HBRUSH card_bg = CreateSolidBrush(t->bg_panel);
    HBRUSH hdr_bg  = CreateSolidBrush(t->bg_alt);
    HBRUSH sel_bg  = CreateSolidBrush(t->bg_sel);

    for (uint32_t i = 0; i < g->nblk; i++) {
        const grp_blk *b = &g->blks[i];
        int x1 = ui_gx(u, rc, b->x);
        int y1 = ui_gy(u, rc, b->y);
        int x2 = ui_gx(u, rc, b->x + b->w);
        int y2 = ui_gy(u, rc, b->y + b->h);
        if (x2 < rc.left || x1 > rc.right || y2 < rc.top || y1 > rc.bottom) continue;

        int active = (u->cur_va >= b->start && u->cur_va < b->end);
        RECT br = { x1, y1, x2, y2 };
        FillRect(dc, &br, card_bg);

        int hh = (int)((u->lh + 4) * u->gz);
        RECT hr = { x1, y1, x2, y1 + hh };
        FillRect(dc, &hr, hdr_bg);

        HPEN pen = CreatePen(PS_SOLID, active ? 2 : 1, active ? t->sym : t->border);
        HPEN op = (HPEN)SelectObject(dc, pen);
        HBRUSH ob = (HBRUSH)SelectObject(dc, GetStockObject(NULL_BRUSH));
        Rectangle(dc, x1, y1, x2, y2);
        SelectObject(dc, ob);
        SelectObject(dc, op);
        DeleteObject(pen);

        if (!show_text) continue;

        const char *sym = ana_sym_at(&u->ana, b->start);
        char title[64];
        if (sym) snprintf(title, sizeof(title), "%s", sym);
        else snprintf(title, sizeof(title), "loc_%llx", (unsigned long long)b->start);
        SelectObject(dc, u->font_bold);
        SetTextColor(dc, t->sym);
        TextOutA(dc, x1 + 8, y1 + 3, title, (int)strlen(title));
        SelectObject(dc, u->font);

        int lh = (int)(u->lh * u->gz);
        if (lh < 10) lh = 10;
        for (uint32_t k = 0; k < b->ins_count; k++) {
            const x86_ins *in = &g->ins[b->ins_first + k];
            int iy = y1 + hh + 3 + (int)k * lh;
            if (iy + lh > y2) break;
            if (in->ip == u->cur_va) {
                RECT sr = { x1 + 2, iy, x2 - 2, iy + lh };
                FillRect(dc, &sr, sel_bg);
            }
            char line[96];
            const char *ts = (in->has_target && !in->target_mem) ? ana_sym_at(&u->ana, in->target) : NULL;
            snprintf(line, sizeof(line), "%08x  %-8s %s", (uint32_t)in->ip, in->mnem, ts ? ts : in->ops);
            uint32_t col = (in->flow == X86_FLOW_CALL) ? t->call
                         : (in->flow == X86_FLOW_JMP || in->flow == X86_FLOW_JCC) ? t->jmp
                         : (in->flow == X86_FLOW_RET) ? t->ret : t->fg;
            SetTextColor(dc, col);
            ExtTextOutA(dc, x1 + 8, iy, ETO_CLIPPED, &br, line, (int)strlen(line), NULL);
        }
    }

    DeleteObject(card_bg);
    DeleteObject(hdr_bg);
    DeleteObject(sel_bg);
    SelectClipRgn(dc, NULL);
    DeleteObject(clip);
}

bool ui_graph_hit(const ui_app *u, RECT rc, int mx, int my, uint64_t *va, uint64_t *tgt) {
    const grp_cfg *g = &u->cfg;
    for (uint32_t i = 0; i < g->nblk; i++) {
        const grp_blk *b = &g->blks[i];
        int x1 = ui_gx(u, rc, b->x);
        int y1 = ui_gy(u, rc, b->y);
        int x2 = ui_gx(u, rc, b->x + b->w);
        int y2 = ui_gy(u, rc, b->y + b->h);
        if (mx < x1 || mx > x2 || my < y1 || my > y2) continue;

        int hh = (int)((u->lh + 4) * u->gz);
        int lh = (int)(u->lh * u->gz);
        if (lh < 10) lh = 10;
        int idx = (my - (y1 + hh + 3)) / lh;
        if (idx < 0) idx = 0;
        if ((uint32_t)idx >= b->ins_count) idx = (int)b->ins_count - 1;
        if (idx >= 0) {
            const x86_ins *in = &g->ins[b->ins_first + idx];
            *va = in->ip;
            *tgt = in->has_target ? in->target : 0;
            return true;
        }
        *va = b->start;
        *tgt = 0;
        return true;
    }
    return false;
}

void ui_draw_sidebar(HDC dc, ui_app *u, RECT rc) {
    const opt_theme *t = &u->opt.th;
    HBRUSH bg = CreateSolidBrush(t->bg_panel);
    FillRect(dc, &rc, bg);
    DeleteObject(bg);

    static const char *const tabs[4] = { "Funcs", "Syms", "Strs", "Marks" };
    int tw = (rc.right - rc.left) / 4;
    for (int i = 0; i < 4; i++) {
        RECT tr = { rc.left + i * tw, rc.top, rc.left + (i + 1) * tw, rc.top + 24 };
        HBRUSH tb = CreateSolidBrush((int)u->tab == i ? t->bg_sel : t->bg_alt);
        FillRect(dc, &tr, tb);
        DeleteObject(tb);
        SetTextColor(dc, (int)u->tab == i ? t->fg : t->fg_dim);
        TextOutA(dc, tr.left + 8, tr.top + 4, tabs[i], (int)strlen(tabs[i]));
    }

    RECT fr = { rc.left + 6, rc.top + 28, rc.right - 6, rc.top + 50 };
    HBRUSH fb = CreateSolidBrush(u->prompt == UI_PROMPT_FILTER ? t->bg_cur : t->bg);
    FillRect(dc, &fr, fb);
    DeleteObject(fb);

    char ftxt[80];
    if (u->filter[0]) snprintf(ftxt, sizeof(ftxt), "/ %s (%u)", u->filter, u->list_cnt);
    else snprintf(ftxt, sizeof(ftxt), "Filter (/) [%u]", u->list_cnt);
    SetTextColor(dc, u->filter[0] ? t->fg : t->fg_dim);
    ExtTextOutA(dc, fr.left + 6, fr.top + 3, ETO_CLIPPED, &fr, ftxt, (int)strlen(ftxt), NULL);

    int y = rc.top + 56;
    int vis = (rc.bottom - y) / u->lh;
    if (u->list_scroll < 0) u->list_scroll = 0;
    if (u->list_cnt > 0 && u->list_scroll >= (int)u->list_cnt) u->list_scroll = (int)u->list_cnt - 1;

    char line[128];
    for (int i = 0; i < vis && (uint32_t)(u->list_scroll + i) < u->list_cnt; i++) {
        uint32_t idx = u->list_idx[u->list_scroll + i];
        uint64_t va = 0;
        uint32_t col = t->fg;

        if (u->tab == UI_TAB_FUNCS && idx < u->ana.nfunc) {
            va = u->ana.funcs[idx].start;
            snprintf(line, sizeof(line), "%s", ana_pool_str(&u->ana, u->ana.funcs[idx].name_off));
            col = t->sym;
        } else if (u->tab == UI_TAB_SYMS && idx < u->ana.bin.nsym) {
            va = u->ana.bin.syms[idx].va;
            snprintf(line, sizeof(line), "%s", bin_str(&u->ana.bin, u->ana.bin.syms[idx].name_off));
            col = (u->ana.bin.syms[idx].kind == BIN_SYM_IMPORT) ? t->call : t->sym;
        } else if (u->tab == UI_TAB_STRS && idx < u->ana.nstr) {
            va = u->ana.strs[idx].va;
            char sbuf[96];
            ana_read_str(&u->ana, &u->ana.strs[idx], sbuf, sizeof(sbuf));
            snprintf(line, sizeof(line), "\"%s\"", sbuf);
            col = t->str;
        } else if (u->tab == UI_TAB_MARKS && idx < u->ana.nmark) {
            va = u->ana.marks[idx].va;
            snprintf(line, sizeof(line), "%llx %s", (unsigned long long)va, u->ana.marks[idx].label);
            col = t->jmp;
        } else {
            continue;
        }

        RECT ir = { rc.left + 2, y, rc.right - 2, y + u->lh };
        if (va == u->cur_va) {
            HBRUSH sb = CreateSolidBrush(t->bg_sel);
            FillRect(dc, &ir, sb);
            DeleteObject(sb);
        }
        SetTextColor(dc, col);
        ExtTextOutA(dc, ir.left + 6, y + 1, ETO_CLIPPED, &ir, line, (int)strlen(line), NULL);
        y += u->lh;
    }

    HPEN bp = CreatePen(PS_SOLID, 1, t->border);
    HPEN op = (HPEN)SelectObject(dc, bp);
    MoveToEx(dc, rc.right - 1, rc.top, NULL);
    LineTo(dc, rc.right - 1, rc.bottom);
    SelectObject(dc, op);
    DeleteObject(bp);
}

void ui_draw_nav(HDC dc, const ui_app *u, RECT rc) {
    const opt_theme *t = &u->opt.th;
    HBRUSH bg = CreateSolidBrush(t->bg_alt);
    FillRect(dc, &rc, bg);
    DeleteObject(bg);

    if (u->ana.bin.nsec == 0 || u->ana.bin.max_va <= u->ana.bin.min_va) return;
    double span = (double)(u->ana.bin.max_va - u->ana.bin.min_va);
    int w = rc.right - rc.left;

    for (uint32_t i = 0; i < u->ana.bin.nsec; i++) {
        const bin_sec *s = &u->ana.bin.secs[i];
        int x1 = rc.left + (int)(((double)(s->va - u->ana.bin.min_va) / span) * w);
        int x2 = rc.left + (int)(((double)(s->va + s->vsize - u->ana.bin.min_va) / span) * w);
        if (x2 <= x1) x2 = x1 + 2;
        uint32_t c = (s->perm & BIN_PERM_X) ? t->call : (s->perm & BIN_PERM_W) ? t->jmp : t->str;
        RECT sr = { x1, rc.top + 2, x2, rc.bottom - 2 };
        HBRUSH sb = CreateSolidBrush(c);
        FillRect(dc, &sr, sb);
        DeleteObject(sb);
    }

    if (u->cur_va >= u->ana.bin.min_va && u->cur_va <= u->ana.bin.max_va) {
        int cx = rc.left + (int)(((double)(u->cur_va - u->ana.bin.min_va) / span) * w);
        RECT cr = { cx - 2, rc.top, cx + 2, rc.bottom };
        HBRUSH cb = CreateSolidBrush(t->fg);
        FillRect(dc, &cr, cb);
        DeleteObject(cb);
    }
}
