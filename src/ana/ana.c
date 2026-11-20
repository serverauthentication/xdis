#include "ana.h"
#include "../scan/scan.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <math.h>
#include <process.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static double ana_now_ms(void) {
    static LARGE_INTEGER freq;
    if (!freq.QuadPart) QueryPerformanceFrequency(&freq);
    LARGE_INTEGER t;
    QueryPerformanceCounter(&t);
    return (double)t.QuadPart * 1000.0 / (double)freq.QuadPart;
}

void ana_init(ana_ctx *a) {
    memset(a, 0, sizeof(*a));
    tbl_init(&a->func_map);
    tbl_init(&a->sym_map);
    tbl_init(&a->cmt_map);
    tbl_init(&a->str_map);
}

void ana_free(ana_ctx *a) {
    if (!a) return;
    bin_close(&a->bin);
    free(a->funcs);
    free(a->xrefs);
    free(a->strs);
    free(a->marks);
    free(a->patches);
    free(a->lvars);
    free(a->hist);
    free(a->pool);
    tbl_free(&a->func_map);
    tbl_free(&a->sym_map);
    tbl_free(&a->cmt_map);
    tbl_free(&a->str_map);
    memset(a, 0, sizeof(*a));
}

const char *ana_pool_str(const ana_ctx *a, uint32_t off) {
    if (!a->pool || off >= a->pool_len) return NULL;
    return a->pool + off;
}

uint32_t ana_pool_add(ana_ctx *a, const char *s) {
    if (!a) return 0;
    if (!s) s = "";
    size_t slen = strlen(s);
    if (slen > (size_t)UINT32_MAX - 1U) return 0;
    uint32_t n = (uint32_t)(slen + 1U);
    if (n > UINT32_MAX - a->pool_len) return 0;
    uint32_t need = a->pool_len + n;
    if (need > a->pool_cap) {
        size_t ncap = a->pool_cap ? (size_t)a->pool_cap : 8192U;
        while (ncap < (size_t)need) {
            if (ncap > (size_t)UINT32_MAX / 2U) {
                ncap = (size_t)need;
                break;
            }
            ncap *= 2U;
        }
        char *np = (char *)realloc(a->pool, ncap);
        if (!np) return 0;
        a->pool = np;
        a->pool_cap = (uint32_t)ncap;
    }
    uint32_t off = a->pool_len;
    memcpy(a->pool + off, s, (size_t)n);
    a->pool_len = need;
    return off;
}

static void ana_seed_syms(ana_ctx *a) {
    ana_pool_add(a, "");
    for (uint32_t i = 0; i < a->bin.nsym; i++) {
        const bin_sym *s = &a->bin.syms[i];
        const char *name = bin_str(&a->bin, s->name_off);
        if (!name || !name[0]) continue;
        uint32_t off = ana_pool_add(a, name);
        if (off != 0) tbl_put(&a->sym_map, s->va, off);
    }
}

bool ana_open(ana_ctx *a, const char *path, uint64_t raw_base, int raw_bits) {
    if (!a) return false;
    double t0 = ana_now_ms();
    bin_img tmp_bin;
    if (!bin_open(&tmp_bin, path, raw_base, raw_bits)) return false;
    ana_free(a);
    ana_init(a);
    a->bin = tmp_bin;
    ana_seed_syms(a);
    a->load_ms = ana_now_ms() - t0;
    return true;
}

bool ana_open_buf(ana_ctx *a, uint8_t *buf, uint64_t size, const char *label, uint64_t raw_base, int raw_bits) {
    if (!a) return false;
    double t0 = ana_now_ms();
    bin_img tmp_bin;
    if (!bin_open_buf(&tmp_bin, buf, size, label, raw_base, raw_bits)) return false;
    ana_free(a);
    ana_init(a);
    a->bin = tmp_bin;
    ana_seed_syms(a);
    a->load_ms = ana_now_ms() - t0;
    return true;
}

typedef struct {
    const ana_ctx *a;
    uint32_t       tid;
    uint32_t       nt;
    uint64_t       max_bytes;
    int            min_str;
    uint64_t      *call_targets;
    uint32_t       ncall;
    uint32_t       call_cap;
    ana_xref      *xrefs;
    uint32_t       nxref;
    uint32_t       xref_cap;
    ana_str       *strs;
    uint32_t       nstr;
    uint32_t       str_cap;
} ana_job;

static void ana_job_push_call(ana_job *j, uint64_t va) {
    if (j->ncall == j->call_cap) {
        size_t nc_sz = j->call_cap ? (size_t)j->call_cap * 2U : 1024U;
        if (nc_sz > (size_t)UINT32_MAX || nc_sz > SIZE_MAX / sizeof(uint64_t)) return;
        uint32_t nc = (uint32_t)nc_sz;
        uint64_t *p = (uint64_t *)realloc(j->call_targets, nc_sz * sizeof(uint64_t));
        if (!p) return;
        j->call_targets = p;
        j->call_cap = nc;
    }
    j->call_targets[j->ncall++] = va;
}

static void ana_job_push_xref(ana_job *j, uint64_t from, uint64_t to, uint8_t type) {
    if (j->nxref == j->xref_cap) {
        size_t nc_sz = j->xref_cap ? (size_t)j->xref_cap * 2U : 2048U;
        if (nc_sz > (size_t)UINT32_MAX || nc_sz > SIZE_MAX / sizeof(ana_xref)) return;
        uint32_t nc = (uint32_t)nc_sz;
        ana_xref *p = (ana_xref *)realloc(j->xrefs, nc_sz * sizeof(ana_xref));
        if (!p) return;
        j->xrefs = p;
        j->xref_cap = nc;
    }
    j->xrefs[j->nxref].from = from;
    j->xrefs[j->nxref].to = to;
    j->xrefs[j->nxref].type = type;
    j->nxref++;
}

static void ana_job_push_str(ana_job *j, uint64_t va, uint32_t len, uint8_t wide) {
    if (j->nstr == j->str_cap) {
        size_t nc_sz = j->str_cap ? (size_t)j->str_cap * 2U : 512U;
        if (nc_sz > (size_t)UINT32_MAX || nc_sz > SIZE_MAX / sizeof(ana_str)) return;
        uint32_t nc = (uint32_t)nc_sz;
        ana_str *p = (ana_str *)realloc(j->strs, nc_sz * sizeof(ana_str));
        if (!p) return;
        j->strs = p;
        j->str_cap = nc;
    }
    j->strs[j->nstr].va = va;
    j->strs[j->nstr].len = len;
    j->strs[j->nstr].wide = wide;
    j->nstr++;
}

static void ana_scan_strings_chunk(ana_job *j, const uint8_t *d, size_t len, uint64_t base_va) {
    size_t min_len = (size_t)(j->min_str > 3 ? j->min_str : 4);
    size_t pos = 0;

    while (pos + min_len <= len) {
        if (j->a->cancel) return;
        size_t s = scan_ascii_next_x64(d, len, pos);
        if (s + min_len > len) break;
        size_t run = scan_ascii_run_x64(d + s, len - s);
        if (run >= min_len && run <= 512) {
            // drop unterminated code noise
            uint8_t endb = (s + run < len) ? d[s + run] : 0;
            if (endb == 0 || endb == '\n' || endb == '\r') {
                ana_job_push_str(j, base_va + s, (uint32_t)run, 0);
            }
        }
        pos = s + (run ? run : 1);
    }

    size_t i = 0;
    while (i + min_len * 2 <= len) {
        if (j->a->cancel) return;
        if (d[i] >= 0x20 && d[i] <= 0x7E && d[i + 1] == 0) {
            size_t cnt = 0;
            while (i + cnt * 2 + 1 < len && cnt < 256 &&
                   d[i + cnt * 2] >= 0x20 && d[i + cnt * 2] <= 0x7E &&
                   d[i + cnt * 2 + 1] == 0) {
                cnt++;
            }
            if (cnt >= min_len) {
                int term = (i + cnt * 2 + 1 < len && d[i + cnt * 2] == 0 && d[i + cnt * 2 + 1] == 0);
                if (term) ana_job_push_str(j, base_va + i, (uint32_t)cnt, 1);
            }
            i += cnt * 2 + 2;
        } else {
            i += 2;
        }
    }
}

static void ana_scan_exec_chunk(ana_job *j, const uint8_t *d, size_t len, uint64_t base_va) {
    const bin_img *b = &j->a->bin;
    uint32_t hits[4096];
    size_t off = 0;

    while (off + 5 <= len) {
        if (j->a->cancel) return;
        size_t span = len - off;
        if (span > (1u << 20)) span = (1u << 20);
        size_t n = scan_calls_fast(d + off, span, hits, 4096);
        for (size_t i = 0; i < n; i++) {
            size_t pos = off + hits[i];
            if (pos + 5 > len) continue;
            int32_t rel;
            memcpy(&rel, d + pos + 1, 4);
            uint64_t from = base_va + pos;
            uint64_t tgt  = from + 5 + (uint64_t)(int64_t)rel;
            if (!bin_is_exec(b, tgt)) continue;

            // drop e8 inside immediates
            size_t ta = 0;
            const uint8_t *tp = bin_ptr(b, tgt, &ta);
            if (!tp || ta < 2) continue;
            if (tp[0] == 0x00 || tp[0] == 0xCC || (tp[0] == 0xFF && tp[1] == 0xFF)) continue;

            ana_job_push_call(j, tgt);
            ana_job_push_xref(j, from, tgt, ANA_XREF_CALL);
        }
        if (n < 4096) off += span;
        else off += hits[n - 1] + 1;
    }

    size_t lim = len;
    if (lim > j->max_bytes) lim = (size_t)j->max_bytes;
    x86_ins ins;
    size_t pos = 0;
    while (pos < lim) {
        if (j->a->cancel) return;
        uint8_t b0 = d[pos];
        if (b0 == 0xCC || b0 == 0x00) {
            pos++;
            continue;
        }
        int ilen = arch_decode(b->arch, d + pos, len - pos, base_va + pos, 0, 0, &ins);
        if (ilen <= 0) { pos++; continue; }
        if (ins.has_target) {
            if (ins.target_mem) {
                if (bin_sec_at(b, ins.target)) {
                    uint8_t kind = (ins.flow == X86_FLOW_CALL) ? ANA_XREF_CALL
                                 : (ins.flow == X86_FLOW_JMP)  ? ANA_XREF_JMP
                                                               : ANA_XREF_DATA;
                    ana_job_push_xref(j, ins.ip, ins.target, kind);
                }
            } else if (ins.flow == X86_FLOW_JMP || ins.flow == X86_FLOW_JCC) {
                if (bin_is_exec(b, ins.target)) {
                    ana_job_push_xref(j, ins.ip, ins.target, ANA_XREF_JMP);
                }
            }
        }
        pos += (size_t)ilen;
    }
}

static unsigned __stdcall ana_worker(void *arg) {
    ana_job *j = (ana_job *)arg;
    const bin_img *b = &j->a->bin;
    uint64_t code_budget = j->max_bytes;

    for (uint32_t i = 0; i < b->nsec; i++) {
        if (j->a->cancel) break;
        const bin_sec *s = &b->secs[i];
        if (s->fsize == 0 || s->foff >= b->map.size) continue;
        uint64_t sz = s->fsize;
        if (sz > b->map.size - s->foff) sz = b->map.size - s->foff;

        uint64_t chunk = (sz - 1ULL) / j->nt + 1ULL;
        if (j->tid != 0 && chunk > (sz - 1ULL) / j->tid) continue;
        uint64_t lo = chunk * j->tid;
        if (lo >= sz) continue;
        uint64_t hi = (sz - lo < chunk) ? sz : (lo + chunk);
        if (hi - lo > (uint64_t)SIZE_MAX) hi = lo + (uint64_t)SIZE_MAX;

        const uint8_t *ptr = b->map.data + s->foff + lo;
        size_t len = (size_t)(hi - lo);

        if (s->perm & BIN_PERM_X) {
            j->max_bytes = code_budget;
            ana_scan_exec_chunk(j, ptr, len, s->va + lo);
        } else if (s->perm & BIN_PERM_R) {
            ana_scan_strings_chunk(j, ptr, len, s->va + lo);
        }
    }
    return 0;
}

static int ana_u64_cmp(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

static int ana_func_cmp(const void *a, const void *b) {
    uint64_t x = ((const ana_func *)a)->start;
    uint64_t y = ((const ana_func *)b)->start;
    return (x > y) - (x < y);
}

static int ana_xref_cmp(const void *a, const void *b) {
    const ana_xref *x = (const ana_xref *)a;
    const ana_xref *y = (const ana_xref *)b;
    if (x->to != y->to) return (x->to > y->to) - (x->to < y->to);
    if (x->from != y->from) return (x->from > y->from) - (x->from < y->from);
    return (int)x->type - (int)y->type;
}

static int ana_str_cmp(const void *a, const void *b) {
    uint64_t x = ((const ana_str *)a)->va;
    uint64_t y = ((const ana_str *)b)->va;
    return (x > y) - (x < y);
}

static void ana_add_func_raw(ana_ctx *a, uint64_t start, uint64_t end) {
    if (!bin_is_exec(&a->bin, start)) return;
    if (tbl_get(&a->func_map, start) != TBL_NONE) return;
    if (a->nfunc == a->func_cap) {
        size_t nc_sz = a->func_cap ? (size_t)a->func_cap * 2U : 512U;
        if (nc_sz > (size_t)UINT32_MAX || nc_sz > SIZE_MAX / sizeof(ana_func)) return;
        uint32_t nc = (uint32_t)nc_sz;
        ana_func *nf = (ana_func *)realloc(a->funcs, nc_sz * sizeof(ana_func));
        if (!nf) return;
        a->funcs = nf;
        a->func_cap = nc;
    }

    uint32_t idx = a->nfunc++;
    a->funcs[idx].start = start;
    a->funcs[idx].end = end;
    a->funcs[idx].flags = 0;

    uint32_t sym = tbl_get(&a->sym_map, start);
    if (sym != TBL_NONE) {
        a->funcs[idx].name_off = sym;
    } else {
        char buf[32];
        snprintf(buf, sizeof(buf), "sub_%llx", (unsigned long long)start);
        uint32_t off = ana_pool_add(a, buf);
        a->funcs[idx].name_off = off;
        if (off != 0) tbl_put(&a->sym_map, start, off);
    }
    tbl_put(&a->func_map, start, idx);
}

void ana_run(ana_ctx *a, int threads, int min_str, int max_ana_mb) {
    if (!a || a->bin.nsec == 0) return;
    double t0 = ana_now_ms();
    int prev_mute = a->hist_mute;
    a->hist_mute = 1;
    // cache cpuid before spawning workers
    (void)scan_has_avx2();
    InterlockedExchange(&a->busy, 1);
    InterlockedExchange(&a->cancel, 0);
    InterlockedExchange(&a->pct, 5);

    free(a->funcs); a->funcs = NULL; a->nfunc = 0; a->func_cap = 0;
    free(a->xrefs); a->xrefs = NULL; a->nxref = 0; a->xref_cap = 0;
    free(a->strs);  a->strs = NULL;  a->nstr = 0;  a->str_cap = 0;
    tbl_clear(&a->func_map);
    tbl_clear(&a->str_map);

    if (a->bin.entry) ana_add_func_raw(a, a->bin.entry, 0);
    for (uint32_t i = 0; i < a->bin.npdata; i++) {
        ana_add_func_raw(a, a->bin.pdata[i].start, a->bin.pdata[i].end);
    }
    for (uint32_t i = 0; i < a->bin.nsym; i++) {
        const bin_sym *s = &a->bin.syms[i];
        if (s->flags & BIN_SYM_F_NOFUNC) continue;
        uint8_t k = s->kind;
        if (k == BIN_SYM_FUNC || k == BIN_SYM_EXPORT) {
            ana_add_func_raw(a, s->va, 0);
        }
    }

    SYSTEM_INFO si;
    GetSystemInfo(&si);
    int nt = threads > 0 ? threads : (int)si.dwNumberOfProcessors;
    if (nt < 1) nt = 1;
    if (nt > 8) nt = 8;
    if (a->bin.map.size < (1u << 20)) nt = 1;

    uint64_t budget = (uint64_t)(max_ana_mb > 0 ? max_ana_mb : 256) * 1024ULL * 1024ULL;
    ana_job jobs[8];
    HANDLE ths[8];
    memset(jobs, 0, sizeof(jobs));
    memset(ths, 0, sizeof(ths));

    for (int i = 0; i < nt; i++) {
        jobs[i].a = a;
        jobs[i].tid = (uint32_t)i;
        jobs[i].nt = (uint32_t)nt;
        jobs[i].max_bytes = budget / (uint64_t)nt;
        jobs[i].min_str = min_str > 0 ? min_str : 4;
    }

    InterlockedExchange(&a->pct, 25);
    if (nt == 1) {
        ana_worker(&jobs[0]);
    } else {
        for (int i = 0; i < nt; i++) {
            ths[i] = (HANDLE)_beginthreadex(NULL, 0, ana_worker, &jobs[i], 0, NULL);
        }
        WaitForMultipleObjects((DWORD)nt, ths, TRUE, INFINITE);
        for (int i = 0; i < nt; i++) {
            if (ths[i]) CloseHandle(ths[i]);
        }
    }

    InterlockedExchange(&a->pct, 75);

    uint64_t tot_c64 = 0, tot_x64 = 0, tot_s64 = 0;
    for (int i = 0; i < nt; i++) {
        tot_c64 += jobs[i].ncall;
        tot_x64 += jobs[i].nxref;
        tot_s64 += jobs[i].nstr;
    }

    if (tot_c64 > 0 && tot_c64 <= (uint64_t)(SIZE_MAX / sizeof(uint64_t))) {
        size_t tot_c = (size_t)tot_c64;
        uint64_t *all_c = (uint64_t *)malloc(tot_c * sizeof(uint64_t));
        if (all_c) {
            size_t k = 0;
            for (int i = 0; i < nt && k < tot_c; i++) {
                if (jobs[i].ncall) {
                    size_t take = ((size_t)jobs[i].ncall <= tot_c - k) ? (size_t)jobs[i].ncall : (tot_c - k);
                    memcpy(all_c + k, jobs[i].call_targets, take * sizeof(uint64_t));
                    k += take;
                }
            }
            qsort(all_c, k, sizeof(uint64_t), ana_u64_cmp);
            for (size_t i = 0; i < k; i++) {
                if (i == 0 || all_c[i] != all_c[i - 1]) ana_add_func_raw(a, all_c[i], 0);
            }
            free(all_c);
        }
    }

    if (a->nfunc > 1) qsort(a->funcs, a->nfunc, sizeof(ana_func), ana_func_cmp);
    tbl_clear(&a->func_map);
    for (uint32_t i = 0; i < a->nfunc; i++) {
        tbl_put(&a->func_map, a->funcs[i].start, i);
        if (a->funcs[i].end <= a->funcs[i].start) {
            const bin_sec *s = bin_sec_at(&a->bin, a->funcs[i].start);
            uint64_t sec_end = s ? ((s->vsize > UINT64_MAX - s->va) ? UINT64_MAX : (s->va + s->vsize))
                                 : ((a->funcs[i].start > UINT64_MAX - 64ULL) ? UINT64_MAX : (a->funcs[i].start + 64ULL));
            uint64_t next_f = (i + 1 < a->nfunc && a->funcs[i + 1].start < sec_end)
                            ? a->funcs[i + 1].start : sec_end;
            if (next_f > a->funcs[i].start && next_f - a->funcs[i].start > 0x40000ULL) {
                next_f = a->funcs[i].start + 0x40000ULL;
            }
            a->funcs[i].end = next_f;
        }
    }

    uint32_t tot_x = (tot_x64 > (uint64_t)UINT32_MAX) ? UINT32_MAX : (uint32_t)tot_x64;
    if (tot_x > 0 && (size_t)tot_x <= SIZE_MAX / sizeof(ana_xref)) {
        a->xrefs = (ana_xref *)malloc((size_t)tot_x * sizeof(ana_xref));
        if (a->xrefs) {
            uint32_t k = 0;
            for (int i = 0; i < nt && k < tot_x; i++) {
                if (jobs[i].nxref) {
                    uint32_t take = (jobs[i].nxref <= tot_x - k) ? jobs[i].nxref : (tot_x - k);
                    memcpy(a->xrefs + k, jobs[i].xrefs, (size_t)take * sizeof(ana_xref));
                    k += take;
                }
            }
            qsort(a->xrefs, k, sizeof(ana_xref), ana_xref_cmp);
            uint32_t out = 0;
            for (uint32_t i = 0; i < k; i++) {
                if (out > 0 && a->xrefs[i].to == a->xrefs[out - 1].to &&
                    a->xrefs[i].from == a->xrefs[out - 1].from &&
                    a->xrefs[i].type == a->xrefs[out - 1].type) continue;
                a->xrefs[out++] = a->xrefs[i];
            }
            a->nxref = out;
            a->xref_cap = tot_x;
        }
    }

    uint32_t tot_s = (tot_s64 > (uint64_t)UINT32_MAX) ? UINT32_MAX : (uint32_t)tot_s64;
    if (tot_s > 0 && (size_t)tot_s <= SIZE_MAX / sizeof(ana_str)) {
        a->strs = (ana_str *)malloc((size_t)tot_s * sizeof(ana_str));
        if (a->strs) {
            uint32_t k = 0;
            for (int i = 0; i < nt && k < tot_s; i++) {
                if (jobs[i].nstr) {
                    uint32_t take = (jobs[i].nstr <= tot_s - k) ? jobs[i].nstr : (tot_s - k);
                    memcpy(a->strs + k, jobs[i].strs, (size_t)take * sizeof(ana_str));
                    k += take;
                }
            }
            qsort(a->strs, k, sizeof(ana_str), ana_str_cmp);
            a->nstr = k;
            a->str_cap = tot_s;
            for (uint32_t i = 0; i < k; i++) tbl_put(&a->str_map, a->strs[i].va, i);
        }
    }

    for (int i = 0; i < nt; i++) {
        free(jobs[i].call_targets);
        free(jobs[i].xrefs);
        free(jobs[i].strs);
    }

    a->hist_mute = prev_mute;
    a->ana_ms = ana_now_ms() - t0;
    InterlockedExchange(&a->pct, 100);
    InterlockedExchange(&a->busy, 0);
}

#define ANA_HIST_MAX 2048

static void ana_hist_push(ana_ctx *a, const ana_hist *h) {
    if (!a || !h || a->hist_mute) return;
    a->hist_len = a->hist_pos;
    if (a->hist_len >= ANA_HIST_MAX) {
        memmove(a->hist, a->hist + 1, (size_t)(ANA_HIST_MAX - 1) * sizeof(ana_hist));
        a->hist_len = ANA_HIST_MAX - 1;
        a->hist_pos = a->hist_len;
    }
    if (a->hist_len == a->hist_cap) {
        uint32_t nc = a->hist_cap ? a->hist_cap * 2 : 64;
        if (nc > ANA_HIST_MAX) nc = ANA_HIST_MAX;
        ana_hist *nh = (ana_hist *)realloc(a->hist, (size_t)nc * sizeof(ana_hist));
        if (!nh) return;
        a->hist = nh;
        a->hist_cap = nc;
    }
    a->hist[a->hist_len++] = *h;
    a->hist_pos = a->hist_len;
}

static uint32_t ana_pool_empty(ana_ctx *a) {
    if (a->pool && a->pool_len > 0 && a->pool[0] == 0) return 0;
    return ana_pool_add(a, "");
}

static void ana_set_name_raw(ana_ctx *a, uint64_t va, const char *name) {
    uint32_t off = (name && name[0]) ? ana_pool_add(a, name) : ana_pool_empty(a);
    tbl_put(&a->sym_map, va, off);
    uint32_t fi = tbl_get(&a->func_map, va);
    if (fi != TBL_NONE && fi < a->nfunc) a->funcs[fi].name_off = off;
}

const char *ana_sym_at(const ana_ctx *a, uint64_t va) {
    uint32_t off = tbl_get(&a->sym_map, va);
    if (off == TBL_NONE) return NULL;
    const char *s = ana_pool_str(a, off);
    return (s && s[0]) ? s : NULL;
}

void ana_set_name(ana_ctx *a, uint64_t va, const char *name) {
    if (!a || !name || !name[0]) return;
    ana_hist h = {0};
    if (!a->hist_mute) {
        const char *old = ana_sym_at(a, va);
        if (old && strcmp(old, name) == 0) return;
        h.kind = ANA_HIST_NAME;
        h.va = va;
        if (old) {
            h.had_old = 1;
            snprintf(h.old_a, sizeof(h.old_a), "%s", old);
        }
        snprintf(h.new_a, sizeof(h.new_a), "%s", name);
    }
    ana_set_name_raw(a, va, name);
    ana_hist_push(a, &h);
}

const char *ana_cmt_at(const ana_ctx *a, uint64_t va) {
    uint32_t off = tbl_get(&a->cmt_map, va);
    if (off == TBL_NONE) return NULL;
    const char *s = ana_pool_str(a, off);
    return (s && s[0]) ? s : NULL;
}

void ana_set_cmt(ana_ctx *a, uint64_t va, const char *text) {
    if (!a) return;
    if (!text) text = "";
    ana_hist h = {0};
    if (!a->hist_mute) {
        const char *old = ana_cmt_at(a, va);
        if (!old && !text[0]) return;
        if (old && strcmp(old, text) == 0) return;
        h.kind = ANA_HIST_CMT;
        h.va = va;
        if (old) {
            h.had_old = 1;
            snprintf(h.old_a, sizeof(h.old_a), "%s", old);
        }
        snprintf(h.new_a, sizeof(h.new_a), "%s", text);
    }
    uint32_t off = text[0] ? ana_pool_add(a, text) : ana_pool_empty(a);
    tbl_put(&a->cmt_map, va, off);
    ana_hist_push(a, &h);
}

const ana_func *ana_func_at(const ana_ctx *a, uint64_t va) {
    if (a->nfunc == 0) return NULL;
    uint32_t lo = 0, hi = a->nfunc;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        if (a->funcs[mid].start <= va) lo = mid + 1;
        else hi = mid;
    }
    if (lo == 0) return NULL;
    const ana_func *f = &a->funcs[lo - 1];
    return (va >= f->start && va < f->end) ? f : NULL;
}

const ana_str *ana_str_at(const ana_ctx *a, uint64_t va) {
    uint32_t idx = tbl_get(&a->str_map, va);
    if (idx == TBL_NONE || idx >= a->nstr) return NULL;
    return &a->strs[idx];
}

size_t ana_read_str(const ana_ctx *a, const ana_str *s, char *dst, size_t max) {
    if (!s || max == 0) {
        if (max) dst[0] = 0;
        return 0;
    }
    size_t avail = 0;
    const uint8_t *p = bin_ptr(&a->bin, s->va, &avail);
    if (!p) { dst[0] = 0; return 0; }
    size_t n = 0;
    size_t lim = s->len;
    if (lim >= max) lim = max - 1;
    if (s->wide) {
        for (size_t i = 0; i < lim && i * 2 < avail; i++) dst[n++] = (char)p[i * 2];
    } else {
        for (size_t i = 0; i < lim && i < avail; i++) dst[n++] = (char)p[i];
    }
    dst[n] = 0;
    return n;
}

uint32_t ana_xrefs_to(const ana_ctx *a, uint64_t va, uint32_t *first_idx) {
    uint32_t lo = 0, hi = a->nxref;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        if (a->xrefs[mid].to < va) lo = mid + 1;
        else hi = mid;
    }
    if (first_idx) *first_idx = lo;
    uint32_t cnt = 0;
    while (lo + cnt < a->nxref && a->xrefs[lo + cnt].to == va) cnt++;
    return cnt;
}

bool ana_find_sym(const ana_ctx *a, const char *name, uint64_t *va) {
    if (!name || !name[0]) return false;
    for (uint32_t i = 0; i < a->sym_map.cap; i++) {
        if (a->sym_map.slots[i].val == TBL_NONE) continue;
        const char *s = ana_pool_str(a, a->sym_map.slots[i].val);
        if (s && _stricmp(s, name) == 0) {
            *va = a->sym_map.slots[i].key;
            return true;
        }
    }
    return false;
}

bool ana_add_mark(ana_ctx *a, uint64_t va, const char *label) {
    if (!a) return false;
    for (uint32_t i = 0; i < a->nmark; i++) {
        if (a->marks[i].va == va) {
            const char *nl = label ? label : "";
            ana_hist h = {0};
            if (!a->hist_mute) {
                h.kind = ANA_HIST_MARK;
                h.va = va;
                h.had_old = 1;
                snprintf(h.old_a, sizeof(h.old_a), "%s", a->marks[i].label);
                snprintf(h.new_a, sizeof(h.new_a), "%s", nl);
            }
            snprintf(a->marks[i].label, sizeof(a->marks[i].label), "%s", nl);
            ana_hist_push(a, &h);
            return true;
        }
    }
    if (a->nmark == a->mark_cap) {
        size_t nc_sz = a->mark_cap ? (size_t)a->mark_cap * 2U : 32U;
        if (nc_sz > (size_t)UINT32_MAX || nc_sz > SIZE_MAX / sizeof(ana_mark)) return false;
        uint32_t nc = (uint32_t)nc_sz;
        ana_mark *nm = (ana_mark *)realloc(a->marks, nc_sz * sizeof(ana_mark));
        if (!nm) return false;
        a->marks = nm;
        a->mark_cap = nc;
    }
    const char *nl = label ? label : "mark";
    a->marks[a->nmark].va = va;
    snprintf(a->marks[a->nmark].label, sizeof(a->marks[a->nmark].label), "%s", nl);
    a->nmark++;
    if (!a->hist_mute) {
        ana_hist h = {0};
        h.kind = ANA_HIST_MARK;
        h.va = va;
        snprintf(h.new_a, sizeof(h.new_a), "%s", a->marks[a->nmark - 1].label);
        ana_hist_push(a, &h);
    }
    return true;
}

bool ana_patch_byte(ana_ctx *a, uint64_t va, uint8_t val) {
    if (!a) return false;
    size_t avail = 0;
    uint8_t *p = bin_ptr_rw(&a->bin, va, &avail);
    if (!p || avail == 0) return false;
    uint8_t orig = *p;
    *p = val;

    for (uint32_t i = 0; i < a->npatch; i++) {
        if (a->patches[i].va == va) {
            a->patches[i].val = val;
            if (!a->hist_mute) {
                ana_hist h = {0};
                h.kind = ANA_HIST_PATCH;
                h.va = va;
                h.old_byte = orig;
                h.new_byte = val;
                h.had_old = 1;
                ana_hist_push(a, &h);
            }
            return true;
        }
    }
    if (a->npatch == a->patch_cap) {
        size_t nc_sz = a->patch_cap ? (size_t)a->patch_cap * 2U : 32U;
        if (nc_sz > (size_t)UINT32_MAX || nc_sz > SIZE_MAX / sizeof(ana_patch)) return true;
        uint32_t nc = (uint32_t)nc_sz;
        ana_patch *np = (ana_patch *)realloc(a->patches, nc_sz * sizeof(ana_patch));
        if (!np) return true;
        a->patches = np;
        a->patch_cap = nc;
    }
    a->patches[a->npatch].va = va;
    a->patches[a->npatch].orig = orig;
    a->patches[a->npatch].val = val;
    a->npatch++;
    if (!a->hist_mute) {
        ana_hist h = {0};
        h.kind = ANA_HIST_PATCH;
        h.va = va;
        h.old_byte = orig;
        h.new_byte = val;
        ana_hist_push(a, &h);
    }
    return true;
}

bool ana_unpatch_byte(ana_ctx *a, uint64_t va) {
    for (uint32_t i = 0; i < a->npatch; i++) {
        if (a->patches[i].va != va) continue;
        size_t avail = 0;
        uint8_t *p = bin_ptr_rw(&a->bin, va, &avail);
        if (p && avail > 0) *p = a->patches[i].orig;
        a->patches[i] = a->patches[--a->npatch];
        return true;
    }
    return false;
}

void ana_unpatch_all(ana_ctx *a) {
    for (uint32_t i = 0; i < a->npatch; i++) {
        size_t avail = 0;
        uint8_t *p = bin_ptr_rw(&a->bin, a->patches[i].va, &avail);
        if (p && avail > 0) *p = a->patches[i].orig;
    }
    a->npatch = 0;
}

bool ana_export_bin(const ana_ctx *a, const char *path) {
    if (!a || !a->bin.map.data || !a->bin.map.size || !path || !path[0]) return false;
    UINT cp = CP_UTF8;
    DWORD flags = MB_ERR_INVALID_CHARS;
    int wn = MultiByteToWideChar(cp, flags, path, -1, NULL, 0);
    if (wn <= 0 && GetLastError() == ERROR_NO_UNICODE_TRANSLATION) {
        cp = CP_ACP;
        flags = 0;
        wn = MultiByteToWideChar(cp, flags, path, -1, NULL, 0);
    }
    if (wn <= 0) return false;
    wchar_t wstack[1024];
    wchar_t *wpath = ((size_t)wn <= 1024) ? wstack : (wchar_t *)malloc((size_t)wn * sizeof(wchar_t));
    if (!wpath) return false;
    FILE *f = NULL;
    if (MultiByteToWideChar(cp, flags, path, -1, wpath, wn) > 0) f = _wfopen(wpath, L"wb");
    if (wpath != wstack) free(wpath);
    if (!f) return false;
    size_t chunk = 1 << 20;
    uint64_t off = 0;
    while (off < a->bin.map.size) {
        size_t n = (a->bin.map.size - off > chunk) ? chunk : (size_t)(a->bin.map.size - off);
        if (fwrite(a->bin.map.data + off, 1, n, f) != n) { fclose(f); return false; }
        off += n;
    }
    fclose(f);
    return true;
}

bool ana_set_lvar(ana_ctx *a, uint64_t func_va, const char *orig, const char *name, const char *type) {
    if (!a || !orig || !orig[0]) return false;
    for (uint32_t i = 0; i < a->nlvar; i++) {
        if (a->lvars[i].func_va == func_va && strcmp(a->lvars[i].orig, orig) == 0) {
            ana_hist h = {0};
            if (!a->hist_mute) {
                h.kind = ANA_HIST_LVAR;
                h.va = func_va;
                h.had_old = 1;
                snprintf(h.old_a, 24, "%s", a->lvars[i].orig);
                snprintf(h.old_a + 24, 32, "%s", a->lvars[i].name);
                snprintf(h.old_b, 32, "%s", a->lvars[i].type);
            }
            if (name && name[0]) snprintf(a->lvars[i].name, sizeof(a->lvars[i].name), "%s", name);
            if (type && type[0]) snprintf(a->lvars[i].type, sizeof(a->lvars[i].type), "%s", type);
            if (!a->hist_mute) {
                snprintf(h.new_a, 32, "%s", a->lvars[i].name);
                snprintf(h.new_b, 32, "%s", a->lvars[i].type);
                ana_hist_push(a, &h);
            }
            return true;
        }
    }
    if (a->nlvar == a->lvar_cap) {
        size_t nc_sz = a->lvar_cap ? (size_t)a->lvar_cap * 2U : 32U;
        if (nc_sz > (size_t)UINT32_MAX || nc_sz > SIZE_MAX / sizeof(ana_lvar)) return false;
        uint32_t nc = (uint32_t)nc_sz;
        ana_lvar *nl = (ana_lvar *)realloc(a->lvars, nc_sz * sizeof(ana_lvar));
        if (!nl) return false;
        a->lvars = nl;
        a->lvar_cap = nc;
    }
    ana_lvar *lv = &a->lvars[a->nlvar++];
    memset(lv, 0, sizeof(*lv));
    lv->func_va = func_va;
    snprintf(lv->orig, sizeof(lv->orig), "%s", orig);
    if (name && name[0]) snprintf(lv->name, sizeof(lv->name), "%s", name);
    if (type && type[0]) snprintf(lv->type, sizeof(lv->type), "%s", type);
    if (!a->hist_mute) {
        ana_hist h = {0};
        h.kind = ANA_HIST_LVAR;
        h.va = func_va;
        snprintf(h.old_a, 24, "%s", lv->orig);
        snprintf(h.new_a, 32, "%s", lv->name);
        snprintf(h.new_b, 32, "%s", lv->type);
        ana_hist_push(a, &h);
    }
    return true;
}

static void ana_lvar_restore(ana_ctx *a, uint64_t func_va, const char *orig, const char *name, const char *type) {
    for (uint32_t i = 0; i < a->nlvar; i++) {
        if (a->lvars[i].func_va == func_va && strcmp(a->lvars[i].orig, orig) == 0) {
            snprintf(a->lvars[i].name, sizeof(a->lvars[i].name), "%s", name ? name : "");
            snprintf(a->lvars[i].type, sizeof(a->lvars[i].type), "%s", type ? type : "");
            return;
        }
    }
    ana_set_lvar(a, func_va, orig, name, type);
}

static void ana_lvar_remove(ana_ctx *a, uint64_t func_va, const char *orig) {
    for (uint32_t i = 0; i < a->nlvar; i++) {
        if (a->lvars[i].func_va == func_va && strcmp(a->lvars[i].orig, orig) == 0) {
            a->lvars[i] = a->lvars[--a->nlvar];
            return;
        }
    }
}

static void ana_mark_remove(ana_ctx *a, uint64_t va) {
    for (uint32_t i = 0; i < a->nmark; i++) {
        if (a->marks[i].va == va) {
            if (i + 1 < a->nmark) {
                memmove(&a->marks[i], &a->marks[i + 1], (size_t)(a->nmark - i - 1) * sizeof(ana_mark));
            }
            a->nmark--;
            return;
        }
    }
}

bool ana_undo(ana_ctx *a) {
    if (!a || a->hist_pos == 0) return false;
    const ana_hist *h = &a->hist[--a->hist_pos];
    int prev_mute = a->hist_mute;
    a->hist_mute = 1;

    switch (h->kind) {
    case ANA_HIST_NAME:
        ana_set_name_raw(a, h->va, h->had_old ? h->old_a : "");
        break;
    case ANA_HIST_CMT:
        ana_set_cmt(a, h->va, h->had_old ? h->old_a : "");
        break;
    case ANA_HIST_PATCH:
        if (!h->had_old) {
            if (!ana_unpatch_byte(a, h->va)) {
                size_t avail = 0;
                uint8_t *p = bin_ptr_rw(&a->bin, h->va, &avail);
                if (p && avail > 0) *p = h->old_byte;
            }
        } else {
            ana_patch_byte(a, h->va, h->old_byte);
        }
        break;
    case ANA_HIST_LVAR:
        if (h->had_old) ana_lvar_restore(a, h->va, h->old_a, h->old_a + 24, h->old_b);
        else ana_lvar_remove(a, h->va, h->old_a);
        break;
    case ANA_HIST_MARK:
        if (h->had_old) ana_add_mark(a, h->va, h->old_a);
        else ana_mark_remove(a, h->va);
        break;
    default:
        break;
    }

    a->hist_mute = prev_mute;
    return true;
}

bool ana_redo(ana_ctx *a) {
    if (!a || a->hist_pos >= a->hist_len) return false;
    const ana_hist *h = &a->hist[a->hist_pos++];
    int prev_mute = a->hist_mute;
    a->hist_mute = 1;

    switch (h->kind) {
    case ANA_HIST_NAME:
        ana_set_name_raw(a, h->va, h->new_a);
        break;
    case ANA_HIST_CMT:
        ana_set_cmt(a, h->va, h->new_a);
        break;
    case ANA_HIST_PATCH:
        ana_patch_byte(a, h->va, h->new_byte);
        break;
    case ANA_HIST_LVAR:
        ana_lvar_restore(a, h->va, h->old_a, h->new_a, h->new_b);
        break;
    case ANA_HIST_MARK:
        ana_add_mark(a, h->va, h->new_a);
        break;
    default:
        break;
    }

    a->hist_mute = prev_mute;
    return true;
}

uint32_t ana_undo_count(const ana_ctx *a) {
    return a ? a->hist_pos : 0;
}

uint32_t ana_redo_count(const ana_ctx *a) {
    if (!a || a->hist_pos >= a->hist_len) return 0;
    return a->hist_len - a->hist_pos;
}

double ana_entropy(const uint8_t *buf, size_t n) {
    if (!buf || n == 0) return 0.0;
    uint32_t hist[256] = {0};
    for (size_t i = 0; i < n; i++) hist[buf[i]]++;
    double h = 0.0, inv = 1.0 / (double)n;
    for (int i = 0; i < 256; i++) {
        if (!hist[i]) continue;
        double p = (double)hist[i] * inv;
        h -= p * log2(p);
    }
    return h;
}

uint64_t ana_next_va(const ana_ctx *a, uint64_t va) {
    if (!a) return va;
    const bin_sec *s = bin_sec_at(&a->bin, va);
    if (!s) return (va < UINT64_MAX) ? (va + 1ULL) : va;
    if (!(s->perm & BIN_PERM_X)) {
        if (va < UINT64_MAX) {
            uint64_t nv = va + 1ULL;
            if (nv - s->va < s->vsize) return nv;
        }
    } else {
        size_t avail = 0;
        const uint8_t *p = bin_ptr(&a->bin, va, &avail);
        if (p && avail > 0) {
            x86_ins ins;
            int n = arch_decode(a->bin.arch, p, avail, va, 0, 0, &ins);
            if (n > 0 && (uint64_t)n <= UINT64_MAX - va) {
                uint64_t nv = va + (uint64_t)n;
                if (nv - s->va < s->vsize) return nv;
            }
        }
    }
    for (uint32_t i = 0; i + 1 < a->bin.nsec; i++) {
        if (&a->bin.secs[i] == s) return a->bin.secs[i + 1].va;
    }
    return va;
}

uint64_t ana_prev_va(const ana_ctx *a, uint64_t va) {
    if (!a) return va;
    const bin_sec *s = bin_sec_at(&a->bin, va);
    if (!s) return (va > 0 && va > a->bin.min_va) ? (va - 1ULL) : va;
    if (va <= s->va) {
        for (uint32_t i = 1; i < a->bin.nsec; i++) {
            if (&a->bin.secs[i] == s) {
                const bin_sec *prev = &a->bin.secs[i - 1];
                uint64_t off = prev->vsize ? (prev->vsize - 1ULL) : 0ULL;
                return (off > UINT64_MAX - prev->va) ? UINT64_MAX : (prev->va + off);
            }
        }
        return va;
    }
    if (!(s->perm & BIN_PERM_X)) return va - 1ULL;

    uint64_t anchor = (va - s->va > 64) ? (va - 64) : s->va;
    const ana_func *f = ana_func_at(a, va - 1ULL);
    if (f && f->start < va && va - f->start <= 4096) anchor = f->start;

    uint64_t cur = anchor;
    uint64_t prev = anchor;
    x86_ins ins;
    while (cur < va) {
        size_t avail = 0;
        const uint8_t *p = bin_ptr(&a->bin, cur, &avail);
        if (!p || avail == 0) break;
        int n = arch_decode(a->bin.arch, p, avail, cur, 0, 0, &ins);
        if (n <= 0) n = 1;
        prev = cur;
        if ((uint64_t)n > UINT64_MAX - cur) break;
        cur += (uint64_t)n;
    }
    return (cur == va) ? prev : (va - 1ULL);
}
