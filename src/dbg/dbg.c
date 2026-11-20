#include "dbg.h"
#include "../arch/arch.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
    DBG_STEP_ERR = 0,
    DBG_STEP_OK,
    DBG_STEP_STOP,
    DBG_STEP_EXIT
};

enum {
    DBG_EXC_PASS = 0,
    DBG_EXC_STOP,
    DBG_EXC_COND_SKIP
};

enum {
    DBG_COND_BUDGET = 256
};

typedef LONG (WINAPI *dbg_ntqit_fn)(HANDLE, ULONG, PVOID, ULONG, PULONG);

static void dbg_err(dbg_ctx *d, const char *msg, DWORD code) {
    if (!d) return;
    if (code)
        snprintf(d->last_err, sizeof(d->last_err), "%s (err %lu)", msg, (unsigned long)code);
    else
        snprintf(d->last_err, sizeof(d->last_err), "%s", msg);
}

static void dbg_drop_handles(dbg_ctx *d) {
    if (d->hthread) {
        CloseHandle((HANDLE)d->hthread);
        d->hthread = NULL;
    }
    if (d->hproc) {
        CloseHandle((HANDLE)d->hproc);
        d->hproc = NULL;
    }
}

static bool dbg_set_thread(dbg_ctx *d, uint32_t tid) {
    if (d->hthread && d->tid == tid) return true;
    if (d->hthread) {
        CloseHandle((HANDLE)d->hthread);
        d->hthread = NULL;
    }
    d->tid = tid;
    d->hthread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT |
                            THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION, FALSE, tid);
    return d->hthread != NULL;
}

static void dbg_ctx_to_regs(const CONTEXT *c, uint64_t regs[16]) {
    regs[0]  = c->Rax;
    regs[1]  = c->Rcx;
    regs[2]  = c->Rdx;
    regs[3]  = c->Rbx;
    regs[4]  = c->Rsp;
    regs[5]  = c->Rbp;
    regs[6]  = c->Rsi;
    regs[7]  = c->Rdi;
    regs[8]  = c->R8;
    regs[9]  = c->R9;
    regs[10] = c->R10;
    regs[11] = c->R11;
    regs[12] = c->R12;
    regs[13] = c->R13;
    regs[14] = c->R14;
    regs[15] = c->R15;
}

static bool dbg_patch_byte(const dbg_ctx *d, uint64_t va, uint8_t b) {
    if (!d || !d->hproc) return false;
    HANDLE hp = (HANDLE)d->hproc;
    void *addr = (void *)(uintptr_t)va;
    DWORD oldp = 0;
    BOOL vp = VirtualProtectEx(hp, addr, 1, PAGE_EXECUTE_READWRITE, &oldp);
    SIZE_T wr = 0;
    BOOL ok = WriteProcessMemory(hp, addr, &b, 1, &wr) && wr == 1;
    DWORD err = ok ? 0 : GetLastError();
    if (vp) VirtualProtectEx(hp, addr, 1, oldp, &oldp);
    if (ok) FlushInstructionCache(hp, addr, 1);
    else SetLastError(err);
    return ok != 0;
}

static dbg_bp *dbg_bp_find(dbg_ctx *d, uint64_t va) {
    for (int i = 0; i < d->nbp; i++) {
        if (d->bps[i].active && d->bps[i].va == va) return &d->bps[i];
    }
    return NULL;
}

static dbg_bp *dbg_bp_find_any(dbg_ctx *d, uint64_t va) {
    for (int i = 0; i < d->nbp; i++) {
        if (d->bps[i].va == va) return &d->bps[i];
    }
    return NULL;
}

static void dbg_bp_restore_all(dbg_ctx *d) {
    for (int i = 0; i < d->nbp; i++) {
        if (d->bps[i].active) {
            dbg_patch_byte(d, d->bps[i].va, d->bps[i].orig);
            d->bps[i].active = 0;
        }
    }
    d->nbp = 0;
}

static bool dbg_hwbp_any(const dbg_ctx *d) {
    for (int i = 0; i < DBG_MAX_HWBP; i++) {
        if (d->hwbps[i].active) return true;
    }
    return false;
}

static bool dbg_hwbp_at_exec(const dbg_ctx *d, uint64_t rip) {
    for (int i = 0; i < DBG_MAX_HWBP; i++) {
        if (d->hwbps[i].active && d->hwbps[i].kind == 0 && d->hwbps[i].va == rip)
            return true;
    }
    return false;
}

static bool dbg_apply_hwbp_thread(const dbg_ctx *d, HANDLE hthr) {
    if (!d || !hthr) return false;
    CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(hthr, &ctx)) return false;

    DWORD64 dr7 = 0;
    for (int i = 0; i < DBG_MAX_HWBP; i++) {
        DWORD64 addr = d->hwbps[i].active ? (DWORD64)d->hwbps[i].va : 0;
        if (i == 0) ctx.Dr0 = addr;
        else if (i == 1) ctx.Dr1 = addr;
        else if (i == 2) ctx.Dr2 = addr;
        else ctx.Dr3 = addr;

        if (d->hwbps[i].active) {
            DWORD64 rw = (DWORD64)(d->hwbps[i].kind & 3u);
            DWORD64 len = 0;
            if (rw != 0) {
                if (d->hwbps[i].size == 2) len = 1;
                else if (d->hwbps[i].size == 4) len = 3;
                else if (d->hwbps[i].size == 8) len = 2;
            }
            dr7 |= (1ULL << (i * 2));
            dr7 |= (rw << (16 + i * 4));
            dr7 |= (len << (18 + i * 4));
        }
    }
    ctx.Dr6 = 0;
    ctx.Dr7 = dr7;
    return SetThreadContext(hthr, &ctx) != 0;
}

static bool dbg_apply_hwbp_all(dbg_ctx *d) {
    if (!d || (!d->pid && !d->hthread)) return false;

    bool applied_any = false;
    bool applied_cur = false;
    DWORD last_err = 0;

    if (d->pid) {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snap != INVALID_HANDLE_VALUE) {
            THREADENTRY32 te;
            te.dwSize = sizeof(te);
            if (Thread32First(snap, &te)) {
                do {
                    if (te.th32OwnerProcessID != d->pid) continue;
                    bool is_cur = (d->paused && te.th32ThreadID == d->tid);
                    HANDLE ht = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT |
                                           THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                    bool own_handle = (ht != NULL);
                    if (!ht && te.th32ThreadID == d->tid && d->hthread)
                        ht = (HANDLE)d->hthread;
                    if (!ht) {
                        last_err = GetLastError();
                        continue;
                    }

                    bool suspended = false;
                    if (!is_cur) {
                        DWORD prev = SuspendThread(ht);
                        if (prev != (DWORD)-1) suspended = true;
                    }

                    if (dbg_apply_hwbp_thread(d, ht)) {
                        applied_any = true;
                        if (te.th32ThreadID == d->tid) applied_cur = true;
                    } else {
                        last_err = GetLastError();
                    }

                    if (suspended) ResumeThread(ht);
                    if (own_handle) CloseHandle(ht);
                } while (Thread32Next(snap, &te));
            }
            CloseHandle(snap);
        } else {
            last_err = GetLastError();
        }
    }

    if (!applied_cur && d->hthread) {
        bool suspended = false;
        if (!d->paused) {
            DWORD prev = SuspendThread((HANDLE)d->hthread);
            if (prev != (DWORD)-1) suspended = true;
        }
        if (dbg_apply_hwbp_thread(d, (HANDLE)d->hthread)) {
            applied_any = true;
        } else if (!last_err) {
            last_err = GetLastError();
        }
        if (suspended) ResumeThread((HANDLE)d->hthread);
    }

    if (!applied_any) {
        dbg_err(d, "SetThreadContext failed", last_err);
        return false;
    }
    return true;
}

static int dbg_hwbp_check_clear(const dbg_ctx *d) {
    if (!d || !d->hthread || !dbg_hwbp_any(d)) return -1;
    CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext((HANDLE)d->hthread, &ctx)) return -1;

    DWORD64 hits = ctx.Dr6 & 0xFULL;
    if (!hits) return -1;

    int slot = -1;
    for (int i = 0; i < DBG_MAX_HWBP; i++) {
        if ((hits & (1ULL << i)) && d->hwbps[i].active) {
            slot = i;
            break;
        }
    }
    ctx.Dr6 = 0;
    SetThreadContext((HANDLE)d->hthread, &ctx);
    return slot;
}

static void dbg_hwbp_clear_all(dbg_ctx *d) {
    bool had = dbg_hwbp_any(d);
    memset(d->hwbps, 0, sizeof(d->hwbps));
    if (had && (d->pid || d->hthread)) dbg_apply_hwbp_all(d);
}

static dbg_membp *dbg_membp_find_hit(dbg_ctx *d, uint64_t addr) {
    uint64_t pg = addr & ~0xFFFULL;
    for (int i = 0; i < d->nmembp; i++) {
        if (!d->membps[i].active) continue;
        uint64_t lo = d->membps[i].va & ~0xFFFULL;
        uint64_t hi = (d->membps[i].va + (uint64_t)d->membps[i].size + 0xFFFULL) & ~0xFFFULL;
        if (pg >= lo && pg < hi) return &d->membps[i];
    }
    return NULL;
}

static void dbg_membp_rearm_all(const dbg_ctx *d) {
    if (!d || !d->hproc) return;
    for (int i = 0; i < d->nmembp; i++) {
        if (!d->membps[i].active) continue;
        DWORD oldp = 0;
        VirtualProtectEx((HANDLE)d->hproc, (LPVOID)(uintptr_t)d->membps[i].va,
                         (SIZE_T)d->membps[i].size, d->membps[i].orig_prot | PAGE_GUARD, &oldp);
    }
}

static void dbg_membp_clear_all(dbg_ctx *d) {
    for (int i = 0; i < d->nmembp; i++) {
        if (d->membps[i].active && d->hproc) {
            DWORD oldp = 0;
            VirtualProtectEx((HANDLE)d->hproc, (LPVOID)(uintptr_t)d->membps[i].va,
                             (SIZE_T)d->membps[i].size, d->membps[i].orig_prot, &oldp);
        }
    }
    d->nmembp = 0;
    memset(d->membps, 0, sizeof(d->membps));
}

static bool dbg_get_rip(const dbg_ctx *d, uint64_t *rip) {
    if (!d->hthread || !rip) return false;
    CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_CONTROL;
    if (!GetThreadContext((HANDLE)d->hthread, &ctx)) return false;
    *rip = ctx.Rip;
    return true;
}

static bool dbg_set_rip(dbg_ctx *d, uint64_t rip) {
    if (!d->hthread) return false;
    CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_CONTROL;
    if (!GetThreadContext((HANDLE)d->hthread, &ctx)) return false;
    ctx.Rip = rip;
    return SetThreadContext((HANDLE)d->hthread, &ctx) != 0;
}

static bool dbg_set_eflags(dbg_ctx *d, DWORD set_bits, DWORD clr_bits) {
    if (!d->hthread) return false;
    CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_CONTROL;
    if (!GetThreadContext((HANDLE)d->hthread, &ctx)) {
        dbg_err(d, "GetThreadContext failed", GetLastError());
        return false;
    }
    ctx.EFlags = (ctx.EFlags | set_bits) & ~clr_bits;
    if (!SetThreadContext((HANDLE)d->hthread, &ctx)) {
        dbg_err(d, "SetThreadContext failed", GetLastError());
        return false;
    }
    return true;
}

static bool dbg_last_event_is(const dbg_ctx *d, const char *prefix) {
    if (!d || d->nsnap <= 0) return false;
    const char *ev = d->snaps[d->nsnap - 1].event;
    return strncmp(ev, prefix, strlen(prefix)) == 0;
}

static DWORD dbg_cont_status(const dbg_ctx *d) {
    if (dbg_last_event_is(d, "access_violation") || dbg_last_event_is(d, "exc_"))
        return DBG_EXCEPTION_NOT_HANDLED;
    return DBG_CONTINUE;
}

static bool dbg_reg_val(const uint64_t regs[16], uint64_t rip, uint64_t rflags,
                        const char *name, size_t len, uint64_t *out) {
    static const char *const r64[16] = {
        "rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi",
        "r8","r9","r10","r11","r12","r13","r14","r15"
    };
    static const char *const r32[16] = {
        "eax","ecx","edx","ebx","esp","ebp","esi","edi",
        "r8d","r9d","r10d","r11d","r12d","r13d","r14d","r15d"
    };
    if (len == 0 || len >= 16) return false;
    char lo[16];
    for (size_t i = 0; i < len; i++) lo[i] = (char)tolower((unsigned char)name[i]);
    lo[len] = '\0';

    for (int i = 0; i < 16; i++) {
        if (strcmp(lo, r64[i]) == 0) { *out = regs[i]; return true; }
        if (strcmp(lo, r32[i]) == 0) { *out = regs[i] & 0xFFFFFFFFULL; return true; }
    }
    if (strcmp(lo, "rip") == 0) { *out = rip; return true; }
    if (strcmp(lo, "eip") == 0) { *out = rip & 0xFFFFFFFFULL; return true; }
    if (strcmp(lo, "rflags") == 0 || strcmp(lo, "eflags") == 0) { *out = rflags; return true; }
    return false;
}

static bool dbg_parse_u64(const char *p, uint64_t *val, const char **after) {
    if (!isdigit((unsigned char)*p)) return false;
    char *end = NULL;
    uint64_t v = 0;
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
        v = strtoull(p + 2, &end, 16);
        if (end == p + 2) return false;
    } else {
        v = strtoull(p, &end, 10);
        if (end == p) return false;
    }
    *val = v;
    *after = end;
    return true;
}

static bool dbg_eval_ea(const uint64_t regs[16], uint64_t rip, uint64_t rflags,
                        const char *expr, uint64_t *out) {
    const char *p = expr;
    while (*p && isspace((unsigned char)*p)) p++;
    if (!*p) return false;

    uint64_t total = 0;
    int sign = 1;
    bool have = false;

    while (*p) {
        while (*p && isspace((unsigned char)*p)) p++;
        if (!*p) break;

        if (have) {
            if (*p == '+') { sign = 1; p++; }
            else if (*p == '-') { sign = -1; p++; }
            else return false;
        } else if (*p == '+' || *p == '-') {
            sign = (*p == '-') ? -1 : 1;
            p++;
        }
        while (*p && isspace((unsigned char)*p)) p++;
        if (!*p) return false;

        uint64_t term = 0;
        if (isalpha((unsigned char)*p)) {
            const char *st = p;
            while (isalnum((unsigned char)*p)) p++;
            if (!dbg_reg_val(regs, rip, rflags, st, (size_t)(p - st), &term))
                return false;
            while (*p && isspace((unsigned char)*p)) p++;
            if (*p == '*') {
                p++;
                while (*p && isspace((unsigned char)*p)) p++;
                uint64_t sc = 0;
                if (!dbg_parse_u64(p, &sc, &p)) return false;
                term *= sc;
            }
        } else if (!dbg_parse_u64(p, &term, &p)) {
            return false;
        }

        total = (sign > 0) ? (total + term) : (total - term);
        have = true;
    }

    if (!have) return false;
    *out = total;
    return true;
}

static bool dbg_eval_atom(const dbg_ctx *d, const uint64_t regs[16], uint64_t rip,
                          uint64_t rflags, const char *s, size_t len, uint64_t *out) {
    while (len > 0 && isspace((unsigned char)*s)) { s++; len--; }
    while (len > 0 && isspace((unsigned char)s[len - 1])) len--;
    if (len == 0 || len >= 64) return false;

    char buf[64];
    memcpy(buf, s, len);
    buf[len] = '\0';

    const char *lb = strchr(buf, '[');
    if (lb && buf[len - 1] == ']') {
        size_t sz = 8;
        if (lb > buf) {
            char pfx[24];
            size_t pl = (size_t)(lb - buf);
            if (pl >= sizeof(pfx)) return false;
            for (size_t i = 0; i < pl; i++) pfx[i] = (char)tolower((unsigned char)buf[i]);
            pfx[pl] = '\0';
            if (strstr(pfx, "byte")) sz = 1;
            else if (strstr(pfx, "qword")) sz = 8;
            else if (strstr(pfx, "dword")) sz = 4;
            else if (strstr(pfx, "word")) sz = 2;
            else return false;
        }
        buf[len - 1] = '\0';
        uint64_t ea = 0;
        if (!dbg_eval_ea(regs, rip, rflags, lb + 1, &ea)) return false;
        uint8_t raw[8] = {0};
        if (dbg_read_mem(d, ea, raw, sz) != sz) return false;
        uint64_t v = 0;
        memcpy(&v, raw, sz);
        *out = v;
        return true;
    }
    return dbg_eval_ea(regs, rip, rflags, buf, out);
}

static bool dbg_eval_cond(const dbg_ctx *d, const CONTEXT *c, const char *cond) {
    if (!cond || !cond[0] || !c) return true;
    uint64_t regs[16];
    dbg_ctx_to_regs(c, regs);
    uint64_t rip = c->Rip;
    uint64_t rflags = (uint64_t)c->EFlags;

    const char *op = NULL;
    size_t op_len = 0;
    int depth = 0;
    for (const char *p = cond; *p; p++) {
        if (*p == '[') { depth++; continue; }
        if (*p == ']' && depth > 0) { depth--; continue; }
        if (depth != 0) continue;
        if ((p[0] == '=' && p[1] == '=') || (p[0] == '!' && p[1] == '=') ||
            (p[0] == '<' && p[1] == '=') || (p[0] == '>' && p[1] == '=')) {
            op = p;
            op_len = 2;
            break;
        }
        if (p[0] == '<' || p[0] == '>' || p[0] == '&') {
            op = p;
            op_len = 1;
            break;
        }
    }

    if (!op) {
        uint64_t v = 0;
        return dbg_eval_atom(d, regs, rip, rflags, cond, strlen(cond), &v) ? (v != 0) : true;
    }

    uint64_t lhs = 0, rhs = 0;
    if (!dbg_eval_atom(d, regs, rip, rflags, cond, (size_t)(op - cond), &lhs)) return false;
    if (!dbg_eval_atom(d, regs, rip, rflags, op + op_len, strlen(op + op_len), &rhs)) return false;

    if (op_len == 2) {
        if (op[0] == '=') return lhs == rhs;
        if (op[0] == '!') return lhs != rhs;
        if (op[0] == '<') return lhs <= rhs;
        return lhs >= rhs;
    }
    if (op[0] == '<') return lhs < rhs;
    if (op[0] == '>') return lhs > rhs;
    return (lhs & rhs) != 0;
}

static void dbg_capture_snap(dbg_ctx *d, const char *event) {
    if (d->nsnap >= DBG_MAX_SNAP) {
        // keep timeline chronological on wrap
        memmove(&d->snaps[0], &d->snaps[1], (DBG_MAX_SNAP - 1) * sizeof(dbg_snap));
        d->nsnap = DBG_MAX_SNAP - 1;
    }
    int idx = d->nsnap++;
    d->cur_snap = idx;
    dbg_snap *s = &d->snaps[idx];
    memset(s, 0, sizeof(*s));
    s->tid = d->tid;
    snprintf(s->event, sizeof(s->event), "%s", event ? event : "");

    if (!d->hthread) return;
    CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext((HANDLE)d->hthread, &ctx)) return;

    s->rip    = ctx.Rip;
    s->rflags = (uint64_t)ctx.EFlags;
    dbg_ctx_to_regs(&ctx, s->regs);
    dbg_read_mem(d, ctx.Rsp, s->stack, sizeof(s->stack));
}

static void dbg_handle_misc(dbg_ctx *d, const DEBUG_EVENT *ev) {
    if (ev->dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT) {
        if (ev->dwProcessId == d->pid && !d->hproc && ev->u.CreateProcessInfo.hProcess) {
            HANDLE dup = NULL;
            if (DuplicateHandle(GetCurrentProcess(), ev->u.CreateProcessInfo.hProcess,
                                GetCurrentProcess(), &dup, 0, FALSE, DUPLICATE_SAME_ACCESS))
                d->hproc = dup;
        }
        if (ev->u.CreateProcessInfo.hFile)
            CloseHandle(ev->u.CreateProcessInfo.hFile);
    } else if (ev->dwDebugEventCode == CREATE_THREAD_DEBUG_EVENT) {
        if (ev->dwProcessId == d->pid && ev->u.CreateThread.hThread && dbg_hwbp_any(d)) {
            dbg_apply_hwbp_thread(d, ev->u.CreateThread.hThread);
        }
    } else if (ev->dwDebugEventCode == LOAD_DLL_DEBUG_EVENT) {
        if (ev->u.LoadDll.hFile)
            CloseHandle(ev->u.LoadDll.hFile);
    }
    ContinueDebugEvent(ev->dwProcessId, ev->dwThreadId, DBG_CONTINUE);
}

static void dbg_handle_exit(dbg_ctx *d, const DEBUG_EVENT *ev) {
    char tag[48];
    snprintf(tag, sizeof(tag), "exit_%lu", (unsigned long)ev->u.ExitProcess.dwExitCode);
    dbg_set_thread(d, ev->dwThreadId);
    dbg_capture_snap(d, tag);
    ContinueDebugEvent(ev->dwProcessId, ev->dwThreadId, DBG_CONTINUE);
    dbg_drop_handles(d);
    d->attached = 0;
    d->paused = 0;
    d->launched = false;
    d->pid = 0;
    d->tid = 0;
    d->nbp = 0;
    d->nmembp = 0;
    memset(d->hwbps, 0, sizeof(d->hwbps));
}

static int dbg_handle_exc(dbg_ctx *d, const DEBUG_EVENT *ev) {
    const EXCEPTION_RECORD *er = &ev->u.Exception.ExceptionRecord;
    DWORD code = er->ExceptionCode;

    if (code == EXCEPTION_BREAKPOINT || code == 0x4000001Fu) {
        dbg_set_thread(d, ev->dwThreadId);
        uint64_t addr = (uint64_t)(uintptr_t)er->ExceptionAddress;
        dbg_bp *bp = dbg_bp_find(d, addr);
        if (!bp) {
            uint64_t rip = 0;
            if (dbg_get_rip(d, &rip) && rip > 0) bp = dbg_bp_find(d, rip - 1);
        }
        if (bp) {
            dbg_patch_byte(d, bp->va, bp->orig);
            dbg_set_rip(d, bp->va);
            if (bp->cond[0] && d->hthread) {
                CONTEXT ctx;
                memset(&ctx, 0, sizeof(ctx));
                ctx.ContextFlags = CONTEXT_FULL;
                if (GetThreadContext((HANDLE)d->hthread, &ctx) && !dbg_eval_cond(d, &ctx, bp->cond))
                    return DBG_EXC_COND_SKIP;
            }
            d->paused = 1;
            dbg_capture_snap(d, "bp");
            return DBG_EXC_STOP;
        }
        d->paused = 1;
        dbg_capture_snap(d, "breakpoint");
        return DBG_EXC_STOP;
    }
    if (code == EXCEPTION_SINGLE_STEP || code == 0x4000001Eu) {
        dbg_set_thread(d, ev->dwThreadId);
        int hw = dbg_hwbp_check_clear(d);
        d->paused = 1;
        if (hw >= 0) {
            char tag[48];
            snprintf(tag, sizeof(tag), "hwbp_%d", hw);
            dbg_capture_snap(d, tag);
        } else {
            dbg_capture_snap(d, "single_step");
        }
        return DBG_EXC_STOP;
    }
    if (code == (DWORD)STATUS_GUARD_PAGE_VIOLATION && d->nmembp > 0) {
        uint64_t addr = (er->NumberParameters >= 2)
                      ? (uint64_t)er->ExceptionInformation[1]
                      : (uint64_t)(uintptr_t)er->ExceptionAddress;
        if (dbg_membp_find_hit(d, addr)) {
            dbg_set_thread(d, ev->dwThreadId);
            d->paused = 1;
            dbg_capture_snap(d, "membp");
            return DBG_EXC_STOP;
        }
    }
    if (code == EXCEPTION_ACCESS_VIOLATION) {
        dbg_set_thread(d, ev->dwThreadId);
        d->paused = 1;
        dbg_capture_snap(d, "access_violation");
        return DBG_EXC_STOP;
    }
    if (!ev->u.Exception.dwFirstChance) {
        char tag[48];
        snprintf(tag, sizeof(tag), "exc_0x%08lx", (unsigned long)code);
        dbg_set_thread(d, ev->dwThreadId);
        d->paused = 1;
        dbg_capture_snap(d, tag);
        return DBG_EXC_STOP;
    }
    return DBG_EXC_PASS;
}

static bool dbg_wait_initial(dbg_ctx *d, const char *snap_ev) {
    ULONGLONG deadline = GetTickCount64() + 5000u;
    for (;;) {
        ULONGLONG now = GetTickCount64();
        DWORD rem = (now < deadline) ? (DWORD)(deadline - now) : 0;
        DEBUG_EVENT ev;
        if (!WaitForDebugEvent(&ev, rem)) {
            dbg_err(d, "initial debug wait failed", GetLastError());
            return false;
        }
        if (ev.dwProcessId != d->pid) {
            dbg_handle_misc(d, &ev);
            continue;
        }
        if (ev.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
            DWORD code = ev.u.Exception.ExceptionRecord.ExceptionCode;
            if (code == EXCEPTION_BREAKPOINT || code == 0x4000001Fu) {
                dbg_set_thread(d, ev.dwThreadId);
                d->paused = 1;
                dbg_capture_snap(d, snap_ev);
                return true;
            }
            ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_EXCEPTION_NOT_HANDLED);
            continue;
        }
        if (ev.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
            ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE);
            dbg_err(d, "target exited before break", 0);
            return false;
        }
        dbg_handle_misc(d, &ev);
    }
}

static int dbg_step_once(dbg_ctx *d, bool capture, DWORD cont_st) {
    uint64_t rip = 0;
    bool have_rip = dbg_get_rip(d, &rip);
    dbg_bp *bp = have_rip ? dbg_bp_find(d, rip) : NULL;
    if (bp) dbg_patch_byte(d, bp->va, bp->orig);

    // set RF past exec hwbp
    DWORD fl = 0x100u | ((have_rip && dbg_hwbp_at_exec(d, rip)) ? 0x10000u : 0u);
    if (!dbg_set_eflags(d, fl, 0u)) {
        if (bp && bp->active) dbg_patch_byte(d, bp->va, 0xCC);
        return DBG_STEP_ERR;
    }

    uint32_t step_tid = d->tid;
    if (!ContinueDebugEvent(d->pid, d->tid, cont_st)) {
        dbg_err(d, "ContinueDebugEvent failed", GetLastError());
        if (bp && bp->active) dbg_patch_byte(d, bp->va, 0xCC);
        return DBG_STEP_ERR;
    }
    d->paused = 0;

    ULONGLONG deadline = GetTickCount64() + 5000u;
    for (;;) {
        ULONGLONG now = GetTickCount64();
        DWORD rem = (now < deadline) ? (DWORD)(deadline - now) : 0;
        DEBUG_EVENT ev;
        if (!WaitForDebugEvent(&ev, rem)) {
            DWORD err = GetLastError();
            if (bp && bp->active) dbg_patch_byte(d, bp->va, 0xCC);
            dbg_err(d, err == ERROR_SEM_TIMEOUT ? "step timeout" : "WaitForDebugEvent failed",
                    err == ERROR_SEM_TIMEOUT ? 0 : err);
            return DBG_STEP_ERR;
        }
        if (ev.dwProcessId != d->pid) {
            dbg_handle_misc(d, &ev);
            continue;
        }
        if (ev.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
            dbg_handle_exit(d, &ev);
            return DBG_STEP_EXIT;
        }
        if (ev.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
            DWORD code = ev.u.Exception.ExceptionRecord.ExceptionCode;
            if ((code == EXCEPTION_SINGLE_STEP || code == 0x4000001Eu) && ev.dwThreadId == step_tid) {
                if (bp && bp->active) dbg_patch_byte(d, bp->va, 0xCC);
                if (d->nmembp > 0) dbg_membp_rearm_all(d);
                dbg_set_thread(d, ev.dwThreadId);
                int hw = dbg_hwbp_check_clear(d);
                d->paused = 1;
                if (!capture && hw >= 0) {
                    char tag[48];
                    snprintf(tag, sizeof(tag), "hwbp_%d", hw);
                    dbg_capture_snap(d, tag);
                    return DBG_STEP_STOP;
                }
                if (capture) dbg_capture_snap(d, "step");
                return DBG_STEP_OK;
            }
            int exc = dbg_handle_exc(d, &ev);
            if (exc != DBG_EXC_PASS) {
                if (ev.dwThreadId == step_tid)
                    dbg_set_eflags(d, 0u, 0x100u);
                if (exc == DBG_EXC_COND_SKIP) {
                    d->paused = 1;
                    dbg_capture_snap(d, "bp");
                }
                if (bp && bp->active) {
                    uint64_t cur = 0;
                    if (!dbg_get_rip(d, &cur) || cur != bp->va)
                        dbg_patch_byte(d, bp->va, 0xCC);
                }
                if (d->nmembp > 0 && !dbg_last_event_is(d, "membp"))
                    dbg_membp_rearm_all(d);
                return DBG_STEP_STOP;
            }
            ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_EXCEPTION_NOT_HANDLED);
            continue;
        }
        dbg_handle_misc(d, &ev);
    }
}

static bool dbg_wait_loop(dbg_ctx *d, uint32_t timeout_ms) {
    ULONGLONG deadline = (timeout_ms == INFINITE) ? 0 : GetTickCount64() + (ULONGLONG)timeout_ms;
    int cond_skips = 0;

    for (;;) {
        DWORD rem = INFINITE;
        if (timeout_ms != INFINITE) {
            ULONGLONG now = GetTickCount64();
            rem = (now < deadline) ? (DWORD)(deadline - now) : 0;
        }
        DEBUG_EVENT ev;
        if (!WaitForDebugEvent(&ev, rem)) {
            DWORD err = GetLastError();
            if (err == ERROR_SEM_TIMEOUT) {
                dbg_err(d, "timeout (running)", 0);
                return false;
            }
            dbg_err(d, "WaitForDebugEvent failed", err);
            return false;
        }
        if (ev.dwProcessId != d->pid) {
            dbg_handle_misc(d, &ev);
            continue;
        }
        if (ev.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
            dbg_handle_exit(d, &ev);
            return true;
        }
        if (ev.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
            int exc = dbg_handle_exc(d, &ev);
            if (exc == DBG_EXC_STOP) return true;
            if (exc == DBG_EXC_COND_SKIP) {
                bool within_time = (timeout_ms == INFINITE) || (GetTickCount64() < deadline);
                if (cond_skips < DBG_COND_BUDGET && within_time) {
                    int rc = dbg_step_once(d, false, DBG_CONTINUE);
                    if (rc == DBG_STEP_ERR) return false;
                    if (rc == DBG_STEP_STOP || rc == DBG_STEP_EXIT) return true;
                    cond_skips++;
                    if (!ContinueDebugEvent(d->pid, d->tid, DBG_CONTINUE)) {
                        dbg_err(d, "ContinueDebugEvent failed", GetLastError());
                        return false;
                    }
                    d->paused = 0;
                    continue;
                }
                d->paused = 1;
                dbg_capture_snap(d, "bp");
                return true;
            }
            ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_EXCEPTION_NOT_HANDLED);
            continue;
        }
        dbg_handle_misc(d, &ev);
    }
}

static uint64_t dbg_thread_start(DWORD tid) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return 0;
    dbg_ntqit_fn fn = (dbg_ntqit_fn)GetProcAddress(ntdll, "NtQueryInformationThread");
    if (!fn) return 0;
    HANDLE ht = OpenThread(THREAD_QUERY_INFORMATION, FALSE, tid);
    if (!ht) ht = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, tid);
    if (!ht) return 0;
    void *start = NULL;
    ULONG len = 0;
    // query win32 start address
    LONG st = fn(ht, 9u, &start, (ULONG)sizeof(start), &len);
    CloseHandle(ht);
    return st >= 0 ? (uint64_t)(uintptr_t)start : 0;
}

static uint8_t dbg_prot_to_perm(DWORD prot) {
    switch (prot & 0xFFu) {
    case PAGE_READONLY:          return 1;
    case PAGE_READWRITE:         return 3;
    case PAGE_WRITECOPY:         return 3;
    case PAGE_EXECUTE:           return 4;
    case PAGE_EXECUTE_READ:      return 5;
    case PAGE_EXECUTE_READWRITE: return 7;
    case PAGE_EXECUTE_WRITECOPY: return 7;
    default:                     return 0;
    }
}

static const char *dbg_mod_for_va(const dbg_mod *mods, int nmod, uint64_t va) {
    for (int i = 0; i < nmod; i++) {
        if (va >= mods[i].base && va < mods[i].base + (uint64_t)mods[i].size)
            return mods[i].name;
    }
    return "";
}

static bool dbg_is_exec_va(const dbg_ctx *d, uint64_t va) {
    if (!d || !d->hproc || va < 0x10000u) return false;
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQueryEx((HANDLE)d->hproc, (LPCVOID)(uintptr_t)va, &mbi, sizeof(mbi)))
        return false;
    return mbi.State == MEM_COMMIT && (dbg_prot_to_perm(mbi.Protect) & 4u) != 0;
}

static bool dbg_run_temp_bp(dbg_ctx *d, uint64_t target_va, const char *label, uint32_t timeout_ms) {
    if (!d || !d->attached) {
        dbg_err(d, "not attached", 0);
        return false;
    }
    if (!target_va) {
        dbg_err(d, "invalid target", 0);
        return false;
    }
    bool temp = (dbg_bp_find(d, target_va) == NULL);
    if (temp && !dbg_bp_add(d, target_va)) return false;

    bool ok = dbg_cont(d, timeout_ms);
    char saved_err[96];
    snprintf(saved_err, sizeof(saved_err), "%s", d->last_err);

    if (temp && d->attached) dbg_bp_del(d, target_va);
    if (!ok) {
        snprintf(d->last_err, sizeof(d->last_err), "%s", saved_err);
        return false;
    }
    if (d->paused && d->nsnap > 0) {
        dbg_snap *sn = &d->snaps[d->nsnap - 1];
        if (sn->rip == target_va && strcmp(sn->event, "bp") == 0)
            snprintf(sn->event, sizeof(sn->event), "%s", label);
    }
    d->last_err[0] = '\0';
    return true;
}

static bool dbg_ptr_before(const char *ops, const char *lb, const char *pat) {
    const char *p = strstr(ops, pat);
    return p != NULL && p < lb;
}

static bool dbg_probe_mem_write(const uint8_t *code, size_t n, uint64_t rip,
                                const uint64_t regs[16], uint64_t rflags,
                                uint64_t *out_va, uint8_t *out_sz) {
    if (!code || n == 0) return false;
    x86_ins ins;
    int len = x86_decode(code, n, rip, 64, 1, 0, &ins);
    if (len <= 0) return false;

    const char *m = ins.mnem;
    if (strncmp(m, "lock ", 5) == 0) m += 5;
    if (strncmp(m, "rep ", 4) == 0) m += 4;
    else if (strncmp(m, "repne ", 6) == 0) m += 6;

    if (ins.flow == X86_FLOW_CALL || strcmp(m, "push") == 0) {
        *out_va = regs[4] - 8u;
        *out_sz = 8;
        return true;
    }
    if ((strncmp(m, "stos", 4) == 0 || strncmp(m, "movs", 4) == 0) &&
        m[4] && m[5] == '\0' && ins.ops[0] == '\0') {
        uint8_t sz = (m[4] == 'b') ? 1 : (m[4] == 'w') ? 2 : (m[4] == 'd') ? 4 : (m[4] == 'q') ? 8 : 0;
        if (sz) {
            *out_va = regs[7];
            *out_sz = sz;
            return true;
        }
    }

    const char *ops = ins.ops;
    const char *comma = strchr(ops, ',');
    const char *lb = strchr(ops, '[');
    if (!lb || (comma && lb > comma)) return false;
    const char *rb = strchr(lb + 1, ']');
    if (!rb || (comma && rb > comma)) return false;

    for (const char *p = ops; p < lb; p++) {
        if (*p == ':') return false;
    }
    if (strcmp(m, "cmp") == 0 || strcmp(m, "test") == 0 || strcmp(m, "bt") == 0 ||
        strcmp(m, "jmp") == 0 || strcmp(m, "fld") == 0 || strcmp(m, "fild") == 0 ||
        strcmp(m, "fcom") == 0 || strcmp(m, "fcomp") == 0 || strcmp(m, "ptest") == 0 ||
        strcmp(m, "comiss") == 0 || strcmp(m, "comisd") == 0 ||
        strcmp(m, "ucomiss") == 0 || strcmp(m, "ucomisd") == 0)
        return false;

    uint8_t sz = 8;
    if (dbg_ptr_before(ops, lb, "byte ptr ")) sz = 1;
    else if (dbg_ptr_before(ops, lb, "qword ptr ")) sz = 8;
    else if (dbg_ptr_before(ops, lb, "dword ptr ")) sz = 4;
    else if (dbg_ptr_before(ops, lb, "xmmword ptr ") || dbg_ptr_before(ops, lb, "ymmword ptr ")) sz = 8;
    else if (dbg_ptr_before(ops, lb, "word ptr ")) sz = 2;

    size_t elen = (size_t)(rb - (lb + 1));
    if (elen == 0 || elen >= 64) return false;
    char expr[64];
    memcpy(expr, lb + 1, elen);
    expr[elen] = '\0';

    uint64_t ea = 0;
    if (!dbg_eval_ea(regs, rip + (uint64_t)len, rflags, expr, &ea)) return false;
    *out_va = ea;
    *out_sz = sz;
    return true;
}

static void dbg_ttd_push(dbg_ctx *d, const dbg_ttd_ent *ent) {
    if (d->nttd >= DBG_MAX_TTD) {
        memmove(&d->ttd[0], &d->ttd[1], (DBG_MAX_TTD - 1) * sizeof(dbg_ttd_ent));
        d->nttd = DBG_MAX_TTD - 1;
    }
    d->ttd[d->nttd++] = *ent;
    d->ttd_cur = d->nttd - 1;
}

static bool dbg_read_live_ent(const dbg_ctx *d, dbg_ttd_ent *ent) {
    if (!d || !d->hthread) return false;
    CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
    if (!GetThreadContext((HANDLE)d->hthread, &ctx)) return false;
    memset(ent, 0, sizeof(*ent));
    ent->rip = ctx.Rip;
    ent->rflags = (uint64_t)ctx.EFlags;
    dbg_ctx_to_regs(&ctx, ent->regs);
    return true;
}

static bool dbg_terminate_process(dbg_ctx *d, UINT exit_code) {
    d->nbp = 0;
    d->nmembp = 0;
    memset(d->hwbps, 0, sizeof(d->hwbps));

    if (!d->hproc && d->pid) {
        d->hproc = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, d->pid);
    }
    BOOL ok = d->hproc ? TerminateProcess((HANDLE)d->hproc, exit_code) : FALSE;
    DWORD err = ok ? 0 : GetLastError();
    if (!ok && d->hproc && WaitForSingleObject((HANDLE)d->hproc, 0) == WAIT_OBJECT_0) {
        ok = TRUE;
        err = 0;
    }

    if (d->paused && d->pid) {
        ContinueDebugEvent(d->pid, d->tid, DBG_CONTINUE);
        d->paused = 0;
    }

    // keep debug queue clean
    if (d->pid) {
        ULONGLONG deadline = GetTickCount64() + 200u;
        for (;;) {
            ULONGLONG now = GetTickCount64();
            DWORD rem = (now < deadline) ? (DWORD)(deadline - now) : 0;
            DEBUG_EVENT ev;
            if (!WaitForDebugEvent(&ev, rem)) break;
            if (ev.dwProcessId == d->pid && ev.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
                ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE);
                break;
            }
            if (ev.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT && ev.u.CreateProcessInfo.hFile)
                CloseHandle(ev.u.CreateProcessInfo.hFile);
            else if (ev.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT && ev.u.LoadDll.hFile)
                CloseHandle(ev.u.LoadDll.hFile);
            ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE);
        }
        DebugActiveProcessStop(d->pid);
    }

    if (d->hproc) WaitForSingleObject((HANDLE)d->hproc, 1000u);

    dbg_drop_handles(d);
    d->attached = 0;
    d->paused = 0;
    d->launched = false;
    d->pid = 0;
    d->tid = 0;
    if (!ok) {
        dbg_err(d, "TerminateProcess failed", err);
        return false;
    }
    d->last_err[0] = '\0';
    return true;
}

void dbg_init(dbg_ctx *d) {
    if (!d) return;
    memset(d, 0, sizeof(*d));
    d->cur_snap = -1;
    d->ttd_cur = -1;
}

void dbg_close(dbg_ctx *d) {
    if (!d) return;
    if (d->attached && d->pid) {
        if (d->launched)
            dbg_terminate_process(d, 0);
        else
            dbg_detach(d);
    } else if (d->attached) {
        dbg_detach(d);
    }
    dbg_drop_handles(d);
    free(d->ttd);
    memset(d, 0, sizeof(*d));
    d->cur_snap = -1;
    d->ttd_cur = -1;
}

bool dbg_launch(dbg_ctx *d, const char *path, const char *args) {
    if (!d || !path || !path[0]) {
        dbg_err(d, "invalid path", 0);
        return false;
    }
    if (d->attached || d->hproc || d->hthread || d->ttd) dbg_close(d);
    dbg_init(d);

    char cmd[1536];
    if (args && args[0])
        snprintf(cmd, sizeof(cmd), "\"%s\" %s", path, args);
    else
        snprintf(cmd, sizeof(cmd), "\"%s\"", path);

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    memset(&pi, 0, sizeof(pi));
    si.cb = sizeof(si);

    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE,
                        DEBUG_ONLY_THIS_PROCESS | CREATE_NO_WINDOW,
                        NULL, NULL, &si, &pi)) {
        dbg_err(d, "CreateProcessA failed", GetLastError());
        return false;
    }

    d->hproc = pi.hProcess;
    d->hthread = pi.hThread;
    d->pid = pi.dwProcessId;
    d->tid = pi.dwThreadId;
    d->attached = 1;
    d->launched = true;
    DebugSetProcessKillOnExit(TRUE);

    if (!dbg_wait_initial(d, "entry_bp")) {
        char saved_err[96];
        snprintf(saved_err, sizeof(saved_err), "%s", d->last_err);
        dbg_terminate_process(d, 1);
        snprintf(d->last_err, sizeof(d->last_err), "%s", saved_err);
        return false;
    }
    return true;
}

bool dbg_attach(dbg_ctx *d, uint32_t pid) {
    if (!d || !pid) {
        dbg_err(d, "invalid pid", 0);
        return false;
    }
    if (d->attached || d->hproc || d->hthread || d->ttd) dbg_close(d);
    dbg_init(d);

    if (!DebugActiveProcess(pid)) {
        dbg_err(d, "DebugActiveProcess failed", GetLastError());
        return false;
    }
    DebugSetProcessKillOnExit(FALSE);

    d->pid = pid;
    d->attached = 1;
    d->launched = false;
    d->hproc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!d->hproc) {
        d->hproc = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
                               PROCESS_QUERY_INFORMATION | PROCESS_TERMINATE | SYNCHRONIZE,
                               FALSE, pid);
    }

    if (!dbg_wait_initial(d, "attached")) {
        DebugSetProcessKillOnExit(FALSE);
        DebugActiveProcessStop(pid);
        dbg_drop_handles(d);
        d->attached = 0;
        d->paused = 0;
        d->launched = false;
        d->pid = 0;
        d->tid = 0;
        return false;
    }
    return true;
}

bool dbg_detach(dbg_ctx *d) {
    if (!d || !d->attached) {
        dbg_err(d, "not attached", 0);
        return false;
    }
    DebugSetProcessKillOnExit(FALSE);
    dbg_bp_restore_all(d);
    dbg_hwbp_clear_all(d);
    dbg_membp_clear_all(d);
    if (d->paused) {
        // avoid unhandled bp crash
        ContinueDebugEvent(d->pid, d->tid, dbg_cont_status(d));
    }
    BOOL ok = DebugActiveProcessStop(d->pid);
    DWORD err = ok ? 0 : GetLastError();
    dbg_drop_handles(d);
    d->attached = 0;
    d->paused = 0;
    d->launched = false;
    d->pid = 0;
    d->tid = 0;
    if (!ok) {
        dbg_err(d, "DebugActiveProcessStop failed", err);
        return false;
    }
    d->last_err[0] = '\0';
    return true;
}

bool dbg_kill(dbg_ctx *d) {
    if (!d || !d->attached) {
        dbg_err(d, "not attached", 0);
        return false;
    }
    return dbg_terminate_process(d, 1);
}

bool dbg_step(dbg_ctx *d) {
    if (!d || !d->attached) {
        dbg_err(d, "not attached", 0);
        return false;
    }
    if (!d->paused) {
        dbg_err(d, "not paused", 0);
        return false;
    }
    d->last_err[0] = '\0';
    return dbg_step_once(d, true, dbg_cont_status(d)) != DBG_STEP_ERR;
}

bool dbg_step_over(dbg_ctx *d) {
    if (!d || !d->attached) {
        dbg_err(d, "not attached", 0);
        return false;
    }
    if (!d->paused) {
        dbg_err(d, "not paused", 0);
        return false;
    }
    uint64_t rip = 0;
    if (!dbg_get_rip(d, &rip)) {
        dbg_err(d, "GetThreadContext failed", GetLastError());
        return false;
    }
    uint8_t code[16];
    size_t got = dbg_read_mem(d, rip, code, sizeof(code));
    if (got > 0) {
        dbg_bp *bp = dbg_bp_find(d, rip);
        if (bp) code[0] = bp->orig;
        x86_ins ins;
        int len = x86_decode(code, got, rip, 64, 1, 0, &ins);
        if (len > 0 && (ins.flow == X86_FLOW_CALL ||
                        strncmp(ins.mnem, "rep ", 4) == 0 ||
                        strncmp(ins.mnem, "repne ", 6) == 0)) {
            return dbg_run_temp_bp(d, rip + (uint64_t)len, "step_over", 2500);
        }
    }
    return dbg_step(d);
}

bool dbg_step_out(dbg_ctx *d) {
    if (!d || !d->attached) {
        dbg_err(d, "not attached", 0);
        return false;
    }
    if (!d->paused || !d->hthread) {
        dbg_err(d, "not paused", 0);
        return false;
    }
    CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
    if (!GetThreadContext((HANDLE)d->hthread, &ctx)) {
        dbg_err(d, "GetThreadContext failed", GetLastError());
        return false;
    }

    uint64_t ret_va = 0;
    uint64_t cand = 0;
    if (dbg_read_mem(d, ctx.Rsp, (uint8_t *)&cand, sizeof(cand)) == sizeof(cand) &&
        dbg_is_exec_va(d, cand)) {
        ret_va = cand;
    } else if (ctx.Rbp >= ctx.Rsp && (ctx.Rbp - ctx.Rsp) <= 0x100000u &&
               ctx.Rbp <= UINT64_MAX - 8u &&
               dbg_read_mem(d, ctx.Rbp + 8u, (uint8_t *)&cand, sizeof(cand)) == sizeof(cand) &&
               dbg_is_exec_va(d, cand)) {
        ret_va = cand;
    }

    if (ret_va) {
        bool temp = (dbg_bp_find(d, ret_va) == NULL);
        if (temp && !dbg_bp_add(d, ret_va)) return false;

        bool ok = dbg_cont(d, 3000u);
        char saved_err[96];
        snprintf(saved_err, sizeof(saved_err), "%s", d->last_err);

        if (temp && d->attached) dbg_bp_del(d, ret_va);
        if (!ok) {
            snprintf(d->last_err, sizeof(d->last_err), "%s", saved_err);
            return false;
        }

        uint64_t cur_rip = 0;
        if (!d->attached || !d->paused || !dbg_get_rip(d, &cur_rip) || cur_rip != ret_va) {
            if (!d->last_err[0]) dbg_err(d, "step_out stopped before return", 0);
            return false;
        }
        if (d->nsnap > 0) {
            dbg_snap *sn = &d->snaps[d->nsnap - 1];
            if (sn->rip == ret_va && strcmp(sn->event, "bp") == 0)
                snprintf(sn->event, sizeof(sn->event), "step_out");
        }
        d->last_err[0] = '\0';
        return true;
    }

    int depth = 0;
    for (int i = 0; i < 512; i++) {
        uint64_t rip = 0;
        if (!dbg_get_rip(d, &rip)) {
            dbg_err(d, "GetThreadContext failed", GetLastError());
            return false;
        }
        uint8_t code[16];
        size_t got = dbg_read_mem(d, rip, code, sizeof(code));
        bool is_call = false;
        bool is_ret = false;
        if (got > 0) {
            dbg_bp *bp = dbg_bp_find(d, rip);
            if (bp) code[0] = bp->orig;
            x86_ins ins;
            int len = x86_decode(code, got, rip, 64, 0, 0, &ins);
            if (len > 0) {
                is_call = (ins.flow == X86_FLOW_CALL);
                is_ret = (ins.flow == X86_FLOW_RET);
            }
        }
        int rc = dbg_step_once(d, false, dbg_cont_status(d));
        if (rc == DBG_STEP_ERR) return false;
        if (rc == DBG_STEP_STOP || rc == DBG_STEP_EXIT) return false;
        if (is_call) {
            depth++;
        } else if (is_ret) {
            if (depth == 0) {
                dbg_capture_snap(d, "step_out");
                d->last_err[0] = '\0';
                return true;
            }
            depth--;
        }
    }
    dbg_capture_snap(d, "step");
    dbg_err(d, "step_out step limit reached", 0);
    return false;
}

bool dbg_run_to(dbg_ctx *d, uint64_t va) {
    return dbg_run_temp_bp(d, va, "run_to", 3000);
}

bool dbg_cont(dbg_ctx *d, uint32_t timeout_ms) {
    if (!d || !d->attached) {
        dbg_err(d, "not attached", 0);
        return false;
    }
    d->last_err[0] = '\0';
    if (d->paused) {
        DWORD status = dbg_cont_status(d);
        uint64_t rip = 0;
        bool have_rip = dbg_get_rip(d, &rip);
        bool at_bp = have_rip && dbg_bp_find(d, rip) != NULL;
        bool rearm_mem = d->nmembp > 0 && dbg_last_event_is(d, "membp");

        if (at_bp || rearm_mem) {
            int rc = dbg_step_once(d, false, status);
            if (rc == DBG_STEP_ERR) return false;
            if (rc == DBG_STEP_STOP || rc == DBG_STEP_EXIT) return true;
            status = DBG_CONTINUE;
            have_rip = dbg_get_rip(d, &rip);
        }
        if (have_rip && dbg_hwbp_at_exec(d, rip))
            dbg_set_eflags(d, 0x10000u, 0u);

        if (!ContinueDebugEvent(d->pid, d->tid, status)) {
            dbg_err(d, "ContinueDebugEvent failed", GetLastError());
            return false;
        }
        d->paused = 0;
    }
    return dbg_wait_loop(d, timeout_ms);
}

bool dbg_pause(dbg_ctx *d) {
    if (!d || !d->attached || !d->hproc) {
        dbg_err(d, "not attached", 0);
        return false;
    }
    if (d->paused) {
        dbg_capture_snap(d, "paused");
        d->last_err[0] = '\0';
        return true;
    }
    if (!DebugBreakProcess((HANDLE)d->hproc)) {
        dbg_err(d, "DebugBreakProcess failed", GetLastError());
        return false;
    }

    ULONGLONG deadline = GetTickCount64() + 2000u;
    for (;;) {
        ULONGLONG now = GetTickCount64();
        if (now >= deadline) {
            dbg_err(d, "pause timeout", 0);
            return false;
        }
        DWORD rem = (DWORD)(deadline - now);
        DEBUG_EVENT ev;
        if (!WaitForDebugEvent(&ev, rem)) {
            DWORD err = GetLastError();
            dbg_err(d, err == ERROR_SEM_TIMEOUT ? "pause timeout" : "WaitForDebugEvent failed",
                    err == ERROR_SEM_TIMEOUT ? 0 : err);
            return false;
        }
        if (ev.dwProcessId != d->pid) {
            dbg_handle_misc(d, &ev);
            continue;
        }
        if (ev.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
            dbg_handle_exit(d, &ev);
            dbg_err(d, "target exited", 0);
            return false;
        }
        if (ev.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
            const EXCEPTION_RECORD *er = &ev.u.Exception.ExceptionRecord;
            DWORD code = er->ExceptionCode;
            if (code == EXCEPTION_BREAKPOINT || code == 0x4000001Fu) {
                dbg_set_thread(d, ev.dwThreadId);
                uint64_t addr = (uint64_t)(uintptr_t)er->ExceptionAddress;
                dbg_bp *bp = dbg_bp_find(d, addr);
                if (!bp) {
                    uint64_t rip = 0;
                    if (dbg_get_rip(d, &rip) && rip > 0) bp = dbg_bp_find(d, rip - 1);
                }
                if (bp) {
                    dbg_patch_byte(d, bp->va, bp->orig);
                    dbg_set_rip(d, bp->va);
                }
                d->paused = 1;
                dbg_capture_snap(d, "paused");
                d->last_err[0] = '\0';
                return true;
            }
            int exc = dbg_handle_exc(d, &ev);
            if (exc == DBG_EXC_STOP) {
                d->last_err[0] = '\0';
                return true;
            }
            if (exc == DBG_EXC_COND_SKIP) {
                d->paused = 1;
                dbg_capture_snap(d, "paused");
                d->last_err[0] = '\0';
                return true;
            }
            ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_EXCEPTION_NOT_HANDLED);
            continue;
        }
        dbg_handle_misc(d, &ev);
    }
}

bool dbg_set_reg(dbg_ctx *d, int reg_idx, uint64_t val) {
    if (!d || !d->attached) {
        dbg_err(d, "not attached", 0);
        return false;
    }
    if (!d->paused || !d->hthread) {
        dbg_err(d, "not paused", 0);
        return false;
    }
    if (reg_idx < 0 || reg_idx > 17) {
        dbg_err(d, "invalid register", 0);
        return false;
    }

    CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
    if (!GetThreadContext((HANDLE)d->hthread, &ctx)) {
        dbg_err(d, "GetThreadContext failed", GetLastError());
        return false;
    }

    switch (reg_idx) {
    case 0:  ctx.Rax = val; break;
    case 1:  ctx.Rcx = val; break;
    case 2:  ctx.Rdx = val; break;
    case 3:  ctx.Rbx = val; break;
    case 4:  ctx.Rsp = val; break;
    case 5:  ctx.Rbp = val; break;
    case 6:  ctx.Rsi = val; break;
    case 7:  ctx.Rdi = val; break;
    case 8:  ctx.R8  = val; break;
    case 9:  ctx.R9  = val; break;
    case 10: ctx.R10 = val; break;
    case 11: ctx.R11 = val; break;
    case 12: ctx.R12 = val; break;
    case 13: ctx.R13 = val; break;
    case 14: ctx.R14 = val; break;
    case 15: ctx.R15 = val; break;
    case 16: ctx.Rip = val; break;
    case 17: ctx.EFlags = (DWORD)val; break;
    default: break;
    }

    if (!SetThreadContext((HANDLE)d->hthread, &ctx)) {
        dbg_err(d, "SetThreadContext failed", GetLastError());
        return false;
    }

    CONTEXT live;
    memset(&live, 0, sizeof(live));
    live.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
    const CONTEXT *src = GetThreadContext((HANDLE)d->hthread, &live) ? &live : &ctx;

    if (d->nsnap > 0) {
        dbg_snap *s = &d->snaps[d->nsnap - 1];
        d->cur_snap = d->nsnap - 1;
        s->tid = d->tid;
        s->rip = src->Rip;
        s->rflags = (uint64_t)src->EFlags;
        dbg_ctx_to_regs(src, s->regs);
        if (reg_idx == 4) {
            memset(s->stack, 0, sizeof(s->stack));
            dbg_read_mem(d, src->Rsp, s->stack, sizeof(s->stack));
        }
    } else {
        dbg_capture_snap(d, "set_reg");
    }

    d->last_err[0] = '\0';
    return true;
}

bool dbg_bp_add_cond(dbg_ctx *d, uint64_t va, const char *cond) {
    if (!d || !d->attached || !d->hproc) {
        dbg_err(d, "not attached", 0);
        return false;
    }
    dbg_bp *ex = dbg_bp_find_any(d, va);
    if (ex) {
        if (!ex->active) {
            uint8_t cur_orig = 0;
            if (dbg_read_mem(d, va, &cur_orig, 1) != 1) {
                dbg_err(d, "bp read failed", GetLastError());
                return false;
            }
            if (!dbg_patch_byte(d, va, 0xCC)) {
                dbg_err(d, "bp write failed", GetLastError());
                return false;
            }
            ex->orig = cur_orig;
        }
        ex->active = 1;
        if (cond && cond[0]) snprintf(ex->cond, sizeof(ex->cond), "%s", cond);
        else ex->cond[0] = '\0';
        d->last_err[0] = '\0';
        return true;
    }
    if (d->nbp >= DBG_MAX_BP) {
        dbg_err(d, "bp limit reached", 0);
        return false;
    }
    uint8_t orig = 0;
    if (dbg_read_mem(d, va, &orig, 1) != 1) {
        dbg_err(d, "bp read failed", GetLastError());
        return false;
    }
    if (!dbg_patch_byte(d, va, 0xCC)) {
        dbg_err(d, "bp write failed", GetLastError());
        return false;
    }
    dbg_bp *bp = &d->bps[d->nbp++];
    memset(bp, 0, sizeof(*bp));
    bp->va = va;
    bp->orig = orig;
    bp->active = 1;
    if (cond && cond[0]) snprintf(bp->cond, sizeof(bp->cond), "%s", cond);
    d->last_err[0] = '\0';
    return true;
}

bool dbg_bp_add(dbg_ctx *d, uint64_t va) {
    return dbg_bp_add_cond(d, va, NULL);
}

bool dbg_bp_del(dbg_ctx *d, uint64_t va) {
    if (!d || !d->attached) {
        dbg_err(d, "not attached", 0);
        return false;
    }
    int idx = -1;
    for (int i = 0; i < d->nbp; i++) {
        if (d->bps[i].va == va) {
            idx = i;
            break;
        }
    }
    if (idx < 0) {
        dbg_err(d, "bp not found", 0);
        return false;
    }
    if (d->bps[idx].active)
        dbg_patch_byte(d, va, d->bps[idx].orig);
    if (idx + 1 < d->nbp)
        memmove(&d->bps[idx], &d->bps[idx + 1], (size_t)(d->nbp - idx - 1) * sizeof(dbg_bp));
    d->nbp--;
    d->last_err[0] = '\0';
    return true;
}

bool dbg_hwbp_add_slot(dbg_ctx *d, int req_slot, uint64_t va, uint8_t kind, uint8_t size) {
    if (!d || !d->attached || (!d->pid && !d->hthread)) {
        dbg_err(d, "not attached", 0);
        return false;
    }
    if (kind != 0 && kind != 1 && kind != 3) {
        dbg_err(d, "invalid hwbp kind", 0);
        return false;
    }
    if (kind == 0) size = 1;
    else if (size == 0) size = 1;
    else if (size != 1 && size != 2 && size != 4 && size != 8) {
        dbg_err(d, "invalid hwbp size", 0);
        return false;
    }
    if (req_slot >= DBG_MAX_HWBP) {
        dbg_err(d, "invalid hwbp slot", 0);
        return false;
    }

    int slot = -1;
    if (req_slot > 0) {
        slot = req_slot;
    } else if (req_slot == 0 && !d->hwbps[0].active) {
        slot = 0;
    }
    if (slot < 0) {
        for (int i = 0; i < DBG_MAX_HWBP; i++) {
            if (d->hwbps[i].active && d->hwbps[i].va == va &&
                d->hwbps[i].kind == kind && d->hwbps[i].size == size) {
                if (!dbg_apply_hwbp_all(d)) return false;
                d->last_err[0] = '\0';
                return true;
            }
            if (!d->hwbps[i].active && slot < 0) slot = i;
        }
    }
    if (slot < 0) {
        dbg_err(d, "hwbp slots full", 0);
        return false;
    }

    dbg_hwbp prev = d->hwbps[slot];
    d->hwbps[slot].va = va;
    d->hwbps[slot].kind = kind;
    d->hwbps[slot].size = size;
    d->hwbps[slot].active = 1;
    if (!dbg_apply_hwbp_all(d)) {
        d->hwbps[slot] = prev;
        return false;
    }
    d->last_err[0] = '\0';
    return true;
}

bool dbg_hwbp_add(dbg_ctx *d, uint64_t va, uint8_t kind, uint8_t size) {
    return dbg_hwbp_add_slot(d, -1, va, kind, size);
}

bool dbg_hwbp_del(dbg_ctx *d, int slot) {
    if (!d || !d->attached) {
        dbg_err(d, "not attached", 0);
        return false;
    }
    if (slot < 0 || slot >= DBG_MAX_HWBP) {
        dbg_err(d, "invalid hwbp slot", 0);
        return false;
    }
    memset(&d->hwbps[slot], 0, sizeof(dbg_hwbp));
    if ((d->pid || d->hthread) && !dbg_apply_hwbp_all(d)) return false;
    d->last_err[0] = '\0';
    return true;
}

bool dbg_membp_add(dbg_ctx *d, uint64_t va, uint32_t size) {
    if (!d || !d->attached || !d->hproc) {
        dbg_err(d, "not attached", 0);
        return false;
    }
    if (size == 0) size = 4096;

    for (int i = 0; i < d->nmembp; i++) {
        if (d->membps[i].va == va) {
            DWORD oldp = 0;
            if (!VirtualProtectEx((HANDLE)d->hproc, (LPVOID)(uintptr_t)va, (SIZE_T)size,
                                  d->membps[i].orig_prot | PAGE_GUARD, &oldp)) {
                dbg_err(d, "VirtualProtectEx failed", GetLastError());
                return false;
            }
            d->membps[i].size = size;
            d->membps[i].active = 1;
            d->last_err[0] = '\0';
            return true;
        }
    }
    if (d->nmembp >= DBG_MAX_MEMBP) {
        dbg_err(d, "membp limit reached", 0);
        return false;
    }

    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQueryEx((HANDLE)d->hproc, (LPCVOID)(uintptr_t)va, &mbi, sizeof(mbi)) ||
        mbi.State != MEM_COMMIT) {
        dbg_err(d, "membp query failed", GetLastError());
        return false;
    }
    DWORD base_prot = mbi.Protect & ~(DWORD)PAGE_GUARD;
    DWORD oldp = 0;
    if (!VirtualProtectEx((HANDLE)d->hproc, (LPVOID)(uintptr_t)va, (SIZE_T)size,
                          base_prot | PAGE_GUARD, &oldp)) {
        dbg_err(d, "VirtualProtectEx failed", GetLastError());
        return false;
    }

    dbg_membp *m = &d->membps[d->nmembp++];
    m->va = va;
    m->size = size;
    m->orig_prot = oldp & ~(DWORD)PAGE_GUARD;
    m->active = 1;
    d->last_err[0] = '\0';
    return true;
}

bool dbg_membp_del(dbg_ctx *d, uint64_t va) {
    if (!d || !d->attached || !d->hproc) {
        dbg_err(d, "not attached", 0);
        return false;
    }
    int idx = -1;
    for (int i = 0; i < d->nmembp; i++) {
        if (d->membps[i].va == va) {
            idx = i;
            break;
        }
    }
    if (idx < 0) {
        for (int i = 0; i < d->nmembp; i++) {
            uint64_t lo = d->membps[i].va & ~0xFFFULL;
            uint64_t hi = (d->membps[i].va + (uint64_t)d->membps[i].size + 0xFFFULL) & ~0xFFFULL;
            if (va >= lo && va < hi) {
                idx = i;
                break;
            }
        }
    }
    if (idx < 0) {
        dbg_err(d, "membp not found", 0);
        return false;
    }
    if (d->membps[idx].active) {
        DWORD oldp = 0;
        VirtualProtectEx((HANDLE)d->hproc, (LPVOID)(uintptr_t)d->membps[idx].va,
                         (SIZE_T)d->membps[idx].size, d->membps[idx].orig_prot, &oldp);
    }
    if (idx + 1 < d->nmembp)
        memmove(&d->membps[idx], &d->membps[idx + 1], (size_t)(d->nmembp - idx - 1) * sizeof(dbg_membp));
    d->nmembp--;
    d->last_err[0] = '\0';
    return true;
}

static bool dbg_write_raw_range(HANDLE hp, uint64_t va, const uint8_t *buf, size_t n) {
    SIZE_T wr = 0;
    void *addr = (void *)(uintptr_t)va;
    if (WriteProcessMemory(hp, addr, buf, n, &wr) && wr == n) {
        FlushInstructionCache(hp, addr, n);
        return true;
    }

    size_t off = 0;
    while (off < n) {
        uint64_t cur_va = va + (uint64_t)off;
        size_t chunk = n - off;
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(hp, (LPCVOID)(uintptr_t)cur_va, &mbi, sizeof(mbi))) {
            uint64_t reg_end = (uint64_t)(uintptr_t)mbi.BaseAddress + (uint64_t)mbi.RegionSize;
            if (reg_end > cur_va && (reg_end - cur_va) < (uint64_t)chunk)
                chunk = (size_t)(reg_end - cur_va);
        }
        void *caddr = (void *)(uintptr_t)cur_va;
        DWORD oldp = 0;
        BOOL vp = VirtualProtectEx(hp, caddr, chunk, PAGE_EXECUTE_READWRITE, &oldp);
        wr = 0;
        BOOL ok = WriteProcessMemory(hp, caddr, buf + off, chunk, &wr) && wr == chunk;
        DWORD err = ok ? 0 : GetLastError();
        if (vp) VirtualProtectEx(hp, caddr, chunk, oldp, &oldp);
        if (!ok) {
            SetLastError(err);
            return false;
        }
        FlushInstructionCache(hp, caddr, chunk);
        off += chunk;
    }
    return true;
}

size_t dbg_read_mem(const dbg_ctx *d, uint64_t va, uint8_t *dst, size_t n) {
    if (!d || !d->hproc || !dst || n == 0) return 0;
    SIZE_T got = 0;
    if (!ReadProcessMemory((HANDLE)d->hproc, (LPCVOID)(uintptr_t)va, dst, n, &got)) {
        size_t rem = (size_t)(0x1000u - (va & 0xFFFu));
        if (rem >= n || !ReadProcessMemory((HANDLE)d->hproc, (LPCVOID)(uintptr_t)va, dst, rem, &got))
            return 0;
    }
    size_t ret = (size_t)got;
    for (int i = 0; i < d->nbp; i++) {
        const dbg_bp *bp = &d->bps[i];
        if (bp->active && bp->va >= va && (bp->va - va) < (uint64_t)ret) {
            dst[(size_t)(bp->va - va)] = bp->orig;
        }
    }
    return ret;
}

bool dbg_write_mem(dbg_ctx *d, uint64_t va, const uint8_t *src, size_t n) {
    if (!d || !d->hproc || !src || n == 0) return false;

    bool has_bp = false;
    for (int i = 0; i < d->nbp; i++) {
        if (d->bps[i].active && d->bps[i].va >= va && (d->bps[i].va - va) < (uint64_t)n) {
            has_bp = true;
            break;
        }
    }

    uint8_t stack_buf[256];
    uint8_t *heap_buf = NULL;
    const uint8_t *wbuf = src;
    if (has_bp) {
        uint8_t *tmp = stack_buf;
        if (n > sizeof(stack_buf)) {
            heap_buf = (uint8_t *)malloc(n);
            if (!heap_buf) {
                dbg_err(d, "write_mem alloc failed", 0);
                return false;
            }
            tmp = heap_buf;
        }
        memcpy(tmp, src, n);
        for (int i = 0; i < d->nbp; i++) {
            if (d->bps[i].active && d->bps[i].va >= va && (d->bps[i].va - va) < (uint64_t)n) {
                tmp[(size_t)(d->bps[i].va - va)] = 0xCC;
            }
        }
        wbuf = tmp;
    }

    bool ok = dbg_write_raw_range((HANDLE)d->hproc, va, wbuf, n);
    free(heap_buf);

    if (ok && has_bp) {
        for (int i = 0; i < d->nbp; i++) {
            if (d->bps[i].active && d->bps[i].va >= va && (d->bps[i].va - va) < (uint64_t)n) {
                d->bps[i].orig = src[(size_t)(d->bps[i].va - va)];
            }
        }
    }
    return ok;
}

int dbg_list_mods(const dbg_ctx *d, dbg_mod *out, int max_out) {
    if (!d || !d->attached || !d->pid || !out || max_out <= 0) return 0;
    HANDLE snap = INVALID_HANDLE_VALUE;
    for (int tries = 0; tries < 5; tries++) {
        snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, d->pid);
        if (snap != INVALID_HANDLE_VALUE) break;
        if (GetLastError() != ERROR_BAD_LENGTH) break;
    }
    if (snap == INVALID_HANDLE_VALUE)
        snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, d->pid);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    MODULEENTRY32 me;
    me.dwSize = sizeof(me);
    int n = 0;
    if (Module32First(snap, &me)) {
        do {
            if (n >= max_out) break;
            out[n].base = (uint64_t)(uintptr_t)me.modBaseAddr;
            out[n].size = (uint32_t)me.modBaseSize;
            snprintf(out[n].name, sizeof(out[n].name), "%s", me.szModule);
            n++;
        } while (Module32Next(snap, &me));
    }
    CloseHandle(snap);
    return n;
}

int dbg_list_threads(const dbg_ctx *d, dbg_th *out, int max_out) {
    if (!d || !d->attached || !d->pid || !out || max_out <= 0) return 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    int n = 0;
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != d->pid) continue;
            if (n >= max_out) break;
            out[n].tid = (uint32_t)te.th32ThreadID;
            out[n].start_va = dbg_thread_start(te.th32ThreadID);
            n++;
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return n;
}

int dbg_mem_map(const dbg_ctx *d, dbg_mreg *out, int max_out) {
    if (!d || !d->attached || !d->hproc || !out || max_out <= 0) return 0;
    dbg_mod mods[DBG_MAX_MOD];
    int nmod = dbg_list_mods(d, mods, DBG_MAX_MOD);

    SYSTEM_INFO si;
    GetSystemInfo(&si);
    uint64_t max_va = (uint64_t)(uintptr_t)si.lpMaximumApplicationAddress;
    uint64_t addr = 0;
    int n = 0;

    while (addr < max_va && n < max_out) {
        MEMORY_BASIC_INFORMATION mbi;
        if (!VirtualQueryEx((HANDLE)d->hproc, (LPCVOID)(uintptr_t)addr, &mbi, sizeof(mbi)))
            break;
        uint64_t base = (uint64_t)(uintptr_t)mbi.BaseAddress;
        uint64_t rsz = (uint64_t)mbi.RegionSize;
        if (rsz == 0) break;

        if (mbi.State == MEM_COMMIT) {
            dbg_mreg *r = &out[n++];
            memset(r, 0, sizeof(*r));
            r->base = base;
            r->size = rsz;
            r->perm = dbg_prot_to_perm(mbi.Protect);
            const char *tp = (mbi.Type == MEM_IMAGE) ? "IMG"
                           : (mbi.Type == MEM_MAPPED) ? "MAP" : "PRV";
            snprintf(r->type, sizeof(r->type), "%s", tp);
            const char *mn = dbg_mod_for_va(mods, nmod, base);
            if (mn[0]) snprintf(r->mod, sizeof(r->mod), "%s", mn);
        }
        if (base > UINT64_MAX - rsz) break;
        uint64_t next = base + rsz;
        if (next <= addr) break;
        addr = next;
    }
    return n;
}

int dbg_backtrace(const dbg_ctx *d, dbg_frame *out, int max_out) {
    if (!d || !d->attached || !d->hthread || !out || max_out <= 0) return 0;
    CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
    if (!GetThreadContext((HANDLE)d->hthread, &ctx)) return 0;

    dbg_mod mods[DBG_MAX_MOD];
    int nmod = dbg_list_mods(d, mods, DBG_MAX_MOD);
    int n = 0;

    memset(&out[n], 0, sizeof(out[n]));
    out[n].rip = ctx.Rip;
    out[n].sp = ctx.Rsp;
    snprintf(out[n].mod, sizeof(out[n].mod), "%s", dbg_mod_for_va(mods, nmod, ctx.Rip));
    n++;

    uint64_t rsp = ctx.Rsp;
    uint64_t lim = rsp + 0x10000u;
    uint64_t fp = ctx.Rbp;
    while (n < max_out && fp >= rsp && fp <= lim && (fp & 7u) == 0) {
        uint64_t pair[2] = {0, 0};
        if (dbg_read_mem(d, fp, (uint8_t *)pair, sizeof(pair)) != sizeof(pair)) break;
        if (!pair[1] || !dbg_is_exec_va(d, pair[1])) break;
        memset(&out[n], 0, sizeof(out[n]));
        out[n].rip = pair[1];
        out[n].sp = fp + 16u;
        snprintf(out[n].mod, sizeof(out[n].mod), "%s", dbg_mod_for_va(mods, nmod, pair[1]));
        n++;
        if (pair[0] <= fp || pair[0] > lim || (pair[0] & 7u) != 0) break;
        fp = pair[0];
    }

    if (n <= 1 && n < max_out) {
        // win64 often omits rbp frames
        uint64_t stk[32];
        size_t got = dbg_read_mem(d, rsp, (uint8_t *)stk, sizeof(stk));
        size_t nq = got / sizeof(uint64_t);
        for (size_t i = 0; i < nq && n < max_out; i++) {
            const char *mn = dbg_mod_for_va(mods, nmod, stk[i]);
            if (!mn[0] || !dbg_is_exec_va(d, stk[i])) continue;
            memset(&out[n], 0, sizeof(out[n]));
            out[n].rip = stk[i];
            out[n].sp = rsp + (uint64_t)(i * sizeof(uint64_t));
            snprintf(out[n].mod, sizeof(out[n].mod), "%s", mn);
            n++;
        }
    }
    return n;
}

const dbg_snap *dbg_get_snap(const dbg_ctx *d, int idx) {
    if (!d || d->nsnap <= 0) return NULL;
    if (idx < 0) idx = d->cur_snap;
    if (idx < 0 || idx >= d->nsnap) return NULL;
    return &d->snaps[idx];
}

int dbg_ttd_record(dbg_ctx *d, int max_steps) {
    if (!d || !d->attached || !d->paused) return 0;
    if (max_steps < 1) max_steps = 1;
    if (max_steps > 512) max_steps = 512;

    if (!d->ttd) {
        d->ttd = (dbg_ttd_ent *)calloc(DBG_MAX_TTD, sizeof(dbg_ttd_ent));
        if (!d->ttd) {
            dbg_err(d, "ttd alloc failed", 0);
            return 0;
        }
        d->nttd = 0;
        d->ttd_cur = -1;
    }

    dbg_ttd_ent base;
    if (!dbg_read_live_ent(d, &base)) return 0;
    if (d->nttd == 0 || d->ttd[d->nttd - 1].rip != base.rip)
        dbg_ttd_push(d, &base);

    int rec = 0;
    for (int s = 0; s < max_steps; s++) {
        dbg_ttd_ent prev = d->ttd[d->nttd - 1];
        uint64_t w_va = 0;
        uint8_t w_sz = 0;
        uint8_t code[16];
        size_t got = dbg_read_mem(d, prev.rip, code, sizeof(code));
        if (got > 0) {
            dbg_bp *bp = dbg_bp_find(d, prev.rip);
            if (bp) code[0] = bp->orig;
            dbg_probe_mem_write(code, got, prev.rip, prev.regs, prev.rflags, &w_va, &w_sz);
        }

        if (!dbg_step(d)) break;
        if (!d->attached || !d->paused || d->nsnap <= 0) break;

        const dbg_snap *sn = &d->snaps[d->nsnap - 1];
        dbg_ttd_ent ent;
        memset(&ent, 0, sizeof(ent));
        ent.rip = sn->rip;
        ent.rflags = sn->rflags;
        memcpy(ent.regs, sn->regs, sizeof(ent.regs));

        uint16_t mask = 0;
        for (int r = 0; r < 16; r++) {
            if (ent.regs[r] != prev.regs[r]) mask |= (uint16_t)(1u << r);
        }
        ent.chg_mask = mask;

        if (w_sz > 0 && w_va != 0) {
            uint8_t raw[8] = {0};
            if (dbg_read_mem(d, w_va, raw, w_sz) == w_sz) {
                uint64_t val = 0;
                memcpy(&val, raw, w_sz);
                ent.mem_va = w_va;
                ent.mem_val = val;
                ent.mem_sz = w_sz;
            }
        }

        dbg_ttd_push(d, &ent);
        rec++;
        if (dbg_last_event_is(d, "access_violation") || dbg_last_event_is(d, "exc_"))
            break;
    }
    return rec;
}

bool dbg_ttd_step_back(dbg_ctx *d) {
    if (!d) return false;
    bool moved = false;
    if (d->cur_snap > 0) {
        d->cur_snap--;
        moved = true;
    }
    if (d->ttd_cur > 0) {
        d->ttd_cur--;
        moved = true;
    }
    return moved;
}

int dbg_ttd_who_wrote(const dbg_ctx *d, uint64_t mem_va, int reg_idx,
                      uint64_t *hit_rip, uint64_t *old_v, uint64_t *new_v) {
    if (!d) return -1;

    if (d->ttd && d->nttd > 1) {
        int start = d->ttd_cur;
        if (start < 0 || start >= d->nttd) start = d->nttd - 1;

        if (reg_idx >= 0 && reg_idx < 16) {
            for (int i = start; i >= 1; i--) {
                uint64_t prev = d->ttd[i - 1].regs[reg_idx];
                uint64_t cur = d->ttd[i].regs[reg_idx];
                if (cur != prev) {
                    if (hit_rip) *hit_rip = d->ttd[i - 1].rip;
                    if (old_v) *old_v = prev;
                    if (new_v) *new_v = cur;
                    return i;
                }
            }
            return -1;
        }
        if (mem_va != 0) {
            for (int i = start; i >= 1; i--) {
                const dbg_ttd_ent *e = &d->ttd[i];
                if (e->mem_sz > 0 && mem_va >= e->mem_va &&
                    mem_va < e->mem_va + (uint64_t)e->mem_sz) {
                    if (hit_rip) *hit_rip = d->ttd[i - 1].rip;
                    if (old_v) *old_v = 0;
                    if (new_v) *new_v = e->mem_val;
                    return i;
                }
            }
        }
        return -1;
    }

    if (d->nsnap > 1 && reg_idx >= 0 && reg_idx < 16) {
        int start = d->cur_snap;
        if (start < 0 || start >= d->nsnap) start = d->nsnap - 1;
        for (int i = start; i >= 1; i--) {
            uint64_t prev = d->snaps[i - 1].regs[reg_idx];
            uint64_t cur = d->snaps[i].regs[reg_idx];
            if (cur != prev) {
                if (hit_rip) *hit_rip = d->snaps[i - 1].rip;
                if (old_v) *old_v = prev;
                if (new_v) *new_v = cur;
                return i;
            }
        }
    }
    return -1;
}
