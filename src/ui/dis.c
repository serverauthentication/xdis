#include "ui.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

static bool ui_is_reg(const char *s, size_t n) {
    if (n < 2 || n > 5) return false;
    char b[8];
    for (size_t i = 0; i < n; i++) b[i] = (char)tolower((unsigned char)s[i]);
    b[n] = 0;
    static const char *const regs[] = {
        "rax","rbx","rcx","rdx","rsi","rdi","rbp","rsp","rip",
        "eax","ebx","ecx","edx","esi","edi","ebp","esp","eip",
        "ax","bx","cx","dx","si","di","bp","sp",
        "al","bl","cl","dl","ah","bh","ch","dh","sil","dil","bpl","spl",
        "r8","r9","r10","r11","r12","r13","r14","r15",
        "r8d","r9d","r10d","r11d","r12d","r13d","r14d","r15d",
        "r8w","r9w","r10w","r11w","r12w","r13w","r14w","r15w",
        "r8b","r9b","r10b","r11b","r12b","r13b","r14b","r15b",
        "cs","ds","es","fs","gs","ss"
    };
    if ((b[0] == 'x' || b[0] == 'y') && b[1] == 'm' && b[2] == 'm') return true;
    for (size_t i = 0; i < sizeof(regs) / sizeof(regs[0]); i++) {
        if (strcmp(b, regs[i]) == 0) return true;
    }
    return false;
}

void ui_draw_ops(HDC dc, const ui_app *u, int x, int y, const char *ops) {
    const opt_theme *t = &u->opt.th;
    const char *p = ops;
    while (*p) {
        if (isalnum((unsigned char)*p) || *p == '_') {
            const char *s = p;
            while (isalnum((unsigned char)*p) || *p == '_') p++;
            size_t n = (size_t)(p - s);
            uint32_t col = t->fg;
            if (n >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) col = t->num;
            else if (isdigit((unsigned char)s[0])) col = t->num;
            else if (ui_is_reg(s, n)) col = t->reg;
            else if (n >= 3 && (memcmp(s, "ptr", 3) == 0 || memcmp(s, "byte", 4) == 0 ||
                     memcmp(s, "word", 4) == 0 || memcmp(s, "dword", 5) == 0 || memcmp(s, "qword", 5) == 0)) col = t->fg_dim;
            SetTextColor(dc, col);
            TextOutA(dc, x, y, s, (int)n);
            x += (int)n * u->cw;
        } else {
            SetTextColor(dc, (*p == '[' || *p == ']') ? t->addr : t->fg_dim);
            TextOutA(dc, x, y, p, 1);
            x += u->cw;
            p++;
        }
    }
}

static uint32_t ui_mnem_color(const opt_theme *t, uint8_t flow) {
    switch (flow) {
    case X86_FLOW_CALL: return t->call;
    case X86_FLOW_JMP:
    case X86_FLOW_JCC:  return t->jmp;
    case X86_FLOW_RET:
    case X86_FLOW_TRAP: return t->ret;
    default:            return t->mnem;
    }
}

void ui_draw_linear(HDC dc, ui_app *u, RECT rc) {
    const opt_theme *t = &u->opt.th;
    HBRUSH bg = CreateSolidBrush(t->bg);
    FillRect(dc, &rc, bg);
    DeleteObject(bg);

    u->row_cnt = 0;
    if (u->ana.bin.nsec == 0) {
        SetTextColor(dc, t->fg_dim);
        const char *msg = "Drop a PE/ELF/RAW binary here or press Ctrl+O";
        TextOutA(dc, rc.left + 24, rc.top + 24, msg, (int)strlen(msg));
        return;
    }

    int max_rows = (rc.bottom - rc.top) / u->lh;
    if (max_rows > UI_MAX_ROWS) max_rows = UI_MAX_ROWS;
    if (max_rows <= 0) return;

    uint64_t va = u->top_va;
    int y = rc.top + 2;
    int bytes_w = u->opt.show_bytes ? (u->opt.bytes_cols * 3 + 2) * u->cw : 0;
    int x_addr = rc.left + 10;
    int x_bytes = x_addr + 18 * u->cw;
    int x_mnem = x_bytes + bytes_w;
    int x_ops = x_mnem + 11 * u->cw;
    int x_cmt = x_ops + 30 * u->cw;

    x86_ins ins;
    for (int row = 0; row < max_rows; ) {
        const bin_sec *sec = bin_sec_at(&u->ana.bin, va);
        if (!sec) break;

        const char *sym = ana_sym_at(&u->ana, va);
        if (sym && row < max_rows) {
            RECT hr = { rc.left, y, rc.right, y + u->lh };
            HBRUSH hb = CreateSolidBrush(t->bg_alt);
            FillRect(dc, &hr, hb);
            DeleteObject(hb);

            uint32_t xcnt = ana_xrefs_to(&u->ana, va, NULL);
            char hdr[160];
            if (xcnt) snprintf(hdr, sizeof(hdr), "%s:  ; %s  xrefs=%u", sym, sec->name, xcnt);
            else snprintf(hdr, sizeof(hdr), "%s:  ; %s", sym, sec->name);

            SelectObject(dc, u->font_bold);
            SetTextColor(dc, t->sym);
            TextOutA(dc, x_addr, y + 1, hdr, (int)strlen(hdr));
            SelectObject(dc, u->font);

            u->row_vas[row] = va;
            u->row_tgts[row] = 0;
            u->row_cnt = ++row;
            y += u->lh;
            if (row >= max_rows) break;
        }

        size_t avail = 0;
        const uint8_t *p = bin_ptr(&u->ana.bin, va, &avail);
        int ilen = 1;
        uint64_t tgt = 0;
        int is_code = (sec->perm & BIN_PERM_X) && p && avail > 0;

        if (is_code) {
            ilen = arch_decode(u->ana.bin.arch, p, avail, va, 1, u->opt.upper_mnem, &ins);
            if (ilen <= 0) ilen = 1;
            if (ins.has_target) tgt = ins.target;
        } else {
            memset(&ins, 0, sizeof(ins));
            ins.ip = va;
            ins.len = 1;
            snprintf(ins.mnem, sizeof(ins.mnem), "db");
            uint8_t b = (p && avail > 0) ? p[0] : 0;
            if (b >= 0x20 && b <= 0x7E) snprintf(ins.ops, sizeof(ins.ops), "0x%02x  '%c'", b, (char)b);
            else snprintf(ins.ops, sizeof(ins.ops), "0x%02x", b);
        }

        if (va == u->cur_va) {
            RECT sr = { rc.left, y, rc.right, y + u->lh };
            HBRUSH sb = CreateSolidBrush(t->bg_sel);
            FillRect(dc, &sr, sb);
            DeleteObject(sb);
        }

        char abuf[24];
        snprintf(abuf, sizeof(abuf), "%016llx", (unsigned long long)va);
        SetTextColor(dc, t->addr);
        TextOutA(dc, x_addr, y + 1, abuf, 16);

        if (u->opt.show_bytes && p && avail > 0) {
            char bbuf[64] = "";
            int cols = u->opt.bytes_cols;
            int n = ilen < cols ? ilen : cols;
            for (int k = 0; k < n; k++) snprintf(bbuf + k * 3, sizeof(bbuf) - k * 3, "%02x ", p[k]);
            SetTextColor(dc, t->bytes);
            TextOutA(dc, x_bytes, y + 1, bbuf, (int)strlen(bbuf));
        }

        SetTextColor(dc, ui_mnem_color(t, ins.flow));
        TextOutA(dc, x_mnem, y + 1, ins.mnem, (int)strlen(ins.mnem));

        if (ins.has_target && !ins.target_mem) {
            const char *ts = ana_sym_at(&u->ana, ins.target);
            if (ts) {
                SetTextColor(dc, t->sym);
                TextOutA(dc, x_ops, y + 1, ts, (int)strlen(ts));
            } else {
                ui_draw_ops(dc, u, x_ops, y + 1, ins.ops);
            }
        } else {
            ui_draw_ops(dc, u, x_ops, y + 1, ins.ops);
        }

        char cbuf[160] = "";
        const char *ucmt = ana_cmt_at(&u->ana, va);
        const char *tsym = ins.has_target ? ana_sym_at(&u->ana, ins.target) : NULL;
        const ana_str *st = ins.has_target ? ana_str_at(&u->ana, ins.target) : NULL;
        if (ucmt && ucmt[0]) {
            snprintf(cbuf, sizeof(cbuf), "; %s", ucmt);
            SetTextColor(dc, t->cmt);
        } else if (st) {
            char sraw[72];
            ana_read_str(&u->ana, st, sraw, sizeof(sraw));
            snprintf(cbuf, sizeof(cbuf), "; \"%s\"", sraw);
            SetTextColor(dc, t->str);
        } else if (tsym && ins.target_mem) {
            snprintf(cbuf, sizeof(cbuf), "; %s", tsym);
            SetTextColor(dc, t->sym);
        }
        if (cbuf[0] && x_cmt < rc.right - 20) {
            TextOutA(dc, x_cmt, y + 1, cbuf, (int)strlen(cbuf));
        }

        u->row_vas[row] = va;
        u->row_tgts[row] = tgt;
        u->row_cnt = ++row;
        y += u->lh;

        uint64_t next = va + (uint64_t)ilen;
        if (next >= sec->va + sec->vsize) next = ana_next_va(&u->ana, va);
        if (next == va) break;
        va = next;
    }
}

void ui_draw_hex(HDC dc, ui_app *u, RECT rc) {
    const opt_theme *t = &u->opt.th;
    HBRUSH bg = CreateSolidBrush(t->bg);
    FillRect(dc, &rc, bg);
    DeleteObject(bg);

    u->row_cnt = 0;
    if (u->ana.bin.nsec == 0) return;

    int max_rows = (rc.bottom - rc.top) / u->lh;
    if (max_rows > UI_MAX_ROWS) max_rows = UI_MAX_ROWS;
    uint64_t base = u->top_va & ~15ULL;
    int y = rc.top + 4;
    int x_addr = rc.left + 10;
    int x_hex = x_addr + 18 * u->cw;
    int x_asc = x_hex + 50 * u->cw;

    for (int row = 0; row < max_rows; row++) {
        uint64_t rva = base + (uint64_t)row * 16;
        uint8_t data[16];
        size_t got = bin_read(&u->ana.bin, rva, data, 16);

        if (u->cur_va >= rva && u->cur_va < rva + 16) {
            RECT sr = { rc.left, y, rc.right, y + u->lh };
            HBRUSH sb = CreateSolidBrush(t->bg_alt);
            FillRect(dc, &sr, sb);
            DeleteObject(sb);
        }

        char abuf[24];
        snprintf(abuf, sizeof(abuf), "%016llx", (unsigned long long)rva);
        SetTextColor(dc, t->addr);
        TextOutA(dc, x_addr, y + 1, abuf, 16);

        char asc[17];
        for (int i = 0; i < 16; i++) {
            int bx = x_hex + (i * 3 + (i >= 8 ? 1 : 0)) * u->cw;
            if (rva + (uint64_t)i == u->cur_va) {
                RECT cr = { bx - 1, y, bx + 2 * u->cw + 1, y + u->lh };
                HBRUSH cb = CreateSolidBrush(t->bg_sel);
                FillRect(dc, &cr, cb);
                DeleteObject(cb);
            }
            if ((size_t)i < got) {
                char hb[4];
                snprintf(hb, sizeof(hb), "%02x", data[i]);
                SetTextColor(dc, data[i] ? t->fg : t->fg_dim);
                TextOutA(dc, bx, y + 1, hb, 2);
                asc[i] = (data[i] >= 0x20 && data[i] <= 0x7E) ? (char)data[i] : '.';
            } else {
                SetTextColor(dc, t->fg_dim);
                TextOutA(dc, bx, y + 1, "--", 2);
                asc[i] = ' ';
            }
        }
        asc[16] = 0;
        SetTextColor(dc, t->str);
        TextOutA(dc, x_asc, y + 1, asc, 16);

        u->row_vas[row] = rva;
        u->row_tgts[row] = 0;
        u->row_cnt = row + 1;
        y += u->lh;
    }
}
