#include "ana.h"

#include <ctype.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define VLN_MAX_HITS      128
#define VLN_MAX_PDIFF     128
#define VLN_SCAN_MAX_INS  4096
#define VLN_DIFF_MAX_INS  1024
#define VLN_BFS_MAX_DEPTH 4
#define VLN_BFS_MAX_QUEUE 256
#define VLN_HILB_SAMPLE   4096

static const char *const vln_unsafe_sinks[] = {
    "strcpy", "strcat", "gets", "sprintf", "vsprintf",
    "scanf", "sscanf", "wcscpy", "wcscat",
    "lstrcpy", "lstrcpyA", "lstrcpyW",
    "lstrcat", "lstrcatA", "lstrcatW",
    "system", "popen", "WinExec", "ShellExecuteA", "ShellExecuteW",
    NULL
};

static const char *const vln_bounded_copies[] = {
    "memcpy", "memmove", "strncpy", "RtlCopyMemory", "CopyMemory",
    NULL
};

static const char *const vln_sources[] = {
    "recv", "recvfrom", "WSARecv", "read", "fread", "fgets",
    "ReadFile", "InternetReadFile", "WinHttpReadData",
    "GetCommandLineA", "GetCommandLineW", "getenv",
    "GetEnvironmentVariableA", "GetEnvironmentVariableW",
    "RegQueryValueExA", "RegQueryValueExW", "DeviceIoControl",
    NULL
};

static const char *const vln_safe_apis[] = {
    "strncpy", "strcpy_s", "strncat", "strcat_s",
    "snprintf", "vsnprintf", "sprintf_s", "vsprintf_s",
    "memcpy_s", "memmove_s", "wcsncpy", "wcscpy_s", "wcsncat", "wcscat_s",
    "scanf_s", "sscanf_s", "strlcpy", "strlcat",
    "StringCchCopyA", "StringCchCopyW", "StringCbCopyA", "StringCbCopyW",
    "StringCchPrintfA", "StringCchPrintfW",
    "RtlStringCchCopyA", "RtlStringCchCopyW",
    NULL
};

static const char *const vln_int_helpers[] = {
    "ULongAdd", "ULongSub", "ULongMult",
    "UIntAdd", "UIntSub", "UIntMult",
    "ULongLongAdd", "ULongLongMult",
    "SizeTAdd", "SizeTSub", "SizeTMult",
    "IntAdd", "IntSub", "IntMult",
    "RtlULongAdd", "RtlULongSub", "RtlULongMult",
    "RtlSizeTAdd", "RtlSizeTMult",
    "RtlIntAdd", "RtlIntSub", "RtlIntMult",
    NULL
};

static const char *const vln_cookie_apis[] = {
    "__security_check_cookie", "__stack_chk_fail",
    "__report_gsfailure", "__report_rangecheckfailure",
    NULL
};

static int vln_clamp(int v, int lo, int hi) {
    if (v < lo) return lo;
    if (v > hi) return hi;
    return v;
}

static bool vln_ieq(const char *a, const char *b) {
    if (!a || !b) return false;
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) return false;
        a++;
        b++;
    }
    return *a == 0 && *b == 0;
}

static bool vln_istarts(const char *s, const char *pfx) {
    if (!s || !pfx) return false;
    while (*pfx) {
        if (tolower((unsigned char)*s) != tolower((unsigned char)*pfx)) return false;
        s++;
        pfx++;
    }
    return true;
}

static bool vln_ihas(const char *hay, const char *ndl) {
    if (!hay || !ndl || !ndl[0]) return false;
    size_t nl = strlen(ndl);
    for (const char *p = hay; *p; p++) {
        size_t i = 0;
        while (i < nl && p[i] && tolower((unsigned char)p[i]) == tolower((unsigned char)ndl[i])) i++;
        if (i == nl) return true;
    }
    return false;
}

static void vln_trim(char *s) {
    char *p = s;
    while (*p == ' ' || *p == '\t') p++;
    if (p != s) memmove(s, p, strlen(p) + 1);
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\t')) s[--n] = 0;
}

static int vln_split_ops(const char *ops, char out[3][76]) {
    for (int i = 0; i < 3; i++) out[i][0] = 0;
    if (!ops || !ops[0]) return 0;

    int cnt = 0, depth = 0;
    const char *start = ops;
    for (const char *p = ops; ; p++) {
        if (*p == '[') depth++;
        else if (*p == ']' && depth > 0) depth--;
        if ((*p == ',' && depth == 0) || *p == 0) {
            if (cnt < 3) {
                size_t n = (size_t)(p - start);
                if (n >= 75) n = 75;
                memcpy(out[cnt], start, n);
                out[cnt][n] = 0;
                vln_trim(out[cnt]);
                if (out[cnt][0] || *p == ',') cnt++;
            }
            if (*p == 0) break;
            start = p + 1;
        }
    }
    return cnt;
}

static bool vln_parse_imm(const char *s, uint64_t *val) {
    if (!s || !s[0]) return false;
    const char *p = s;
    while (*p == ' ' || *p == '\t') p++;
    if (*p == '#') p++;
    int neg = 0;
    if (*p == '-') { neg = 1; p++; }
    else if (*p == '+') p++;
    if (!*p) return false;

    char *end = NULL;
    uint64_t v = 0;
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
        if (!isxdigit((unsigned char)p[2])) return false;
        v = strtoull(p + 2, &end, 16);
    } else if (isdigit((unsigned char)p[0])) {
        v = strtoull(p, &end, 10);
    } else {
        return false;
    }
    if (!end || *end != 0) return false;
    if (val) *val = neg ? ((uint64_t)0 - v) : v;
    return true;
}

static bool vln_parse_abs_mem(const char *ops, uint64_t *addr) {
    if (!ops) return false;
    const char *lb = strchr(ops, '[');
    const char *rb = lb ? strchr(lb + 1, ']') : NULL;
    if (!lb || !rb || rb <= lb + 1) return false;
    char inner[48];
    size_t n = (size_t)(rb - (lb + 1));
    if (n >= sizeof(inner)) return false;
    memcpy(inner, lb + 1, n);
    inner[n] = 0;
    vln_trim(inner);
    return vln_parse_imm(inner, addr);
}

static void vln_norm_sym(const char *sym, char *raw_out, size_t raw_cap, char *api_out, size_t api_cap) {
    raw_out[0] = 0;
    api_out[0] = 0;
    if (!sym || !sym[0]) return;

    const char *p = sym;
    const char *bang = strrchr(p, '!');
    if (bang && bang[1]) p = bang + 1;

    for (;;) {
        if (vln_istarts(p, "__imp_")) p += 6;
        else if (vln_istarts(p, "_imp_")) p += 5;
        else if (vln_istarts(p, "imp_")) p += 4;
        else if (strncmp(p, "j_", 2) == 0) p += 2;
        else break;
    }

    size_t n = 0;
    while (p[n] && p[n] != '@' && p[n] != '(' && n + 1 < raw_cap) {
        raw_out[n] = p[n];
        n++;
    }
    raw_out[n] = 0;
    vln_trim(raw_out);

    const char *q = raw_out;
    if (strncmp(q, "__isoc99_", 9) == 0) q += 9;
    else if (strncmp(q, "_o_", 3) == 0) q += 3;
    while (*q == '_') q++;
    snprintf(api_out, api_cap, "%s", q);
}

static int vln_list_match(const char *const *list, const char *name) {
    if (!name || !name[0]) return -1;
    for (int i = 0; list[i]; i++) {
        if (vln_ieq(list[i], name)) return i;
    }
    return -1;
}

static const char *vln_call_sym(const ana_ctx *a, const x86_ins *ins) {
    if (!a || !ins) return NULL;
    uint64_t tgt = 0;
    bool has = false;
    if (ins->has_target) {
        tgt = ins->target;
        has = true;
    } else if (ins->flow == X86_FLOW_CALL || ins->flow == X86_FLOW_JMP) {
        // 32-bit indirect iat call dword ptr [0x...] has no rip flag
        has = vln_parse_abs_mem(ins->ops, &tgt);
    }
    if (!has) return NULL;

    const char *sym = ana_sym_at(a, tgt);
    if (sym && strncmp(sym, "sub_", 4) != 0 && strncmp(sym, "loc_", 4) != 0) return sym;

    if (ins->target_mem) return sym;

    // follow 1-hop plt/iat jump thunk
    size_t av = 0;
    const uint8_t *p = bin_ptr(&a->bin, tgt, &av);
    if (!p || av == 0) return sym;

    size_t pos = 0;
    x86_ins st;
    for (int step = 0; step < 2 && pos < av; step++) {
        int n = arch_decode(a->bin.arch, p + pos, av - pos, tgt + pos, 1, 0, &st);
        if (n <= 0) break;
        if (strcmp(st.mnem, "endbr64") == 0 || strcmp(st.mnem, "endbr32") == 0 || strcmp(st.mnem, "nop") == 0) {
            pos += (size_t)n;
            continue;
        }
        if (st.flow == X86_FLOW_JMP) {
            uint64_t jt = 0;
            bool jhas = st.has_target;
            if (jhas) jt = st.target;
            else jhas = vln_parse_abs_mem(st.ops, &jt);
            if (jhas) {
                const char *js = ana_sym_at(a, jt);
                if (js && js[0]) return js;
            }
        }
        break;
    }
    return sym;
}

static int vln_fmt_arg_index(const char *api) {
    if (vln_ieq(api, "printf") || vln_ieq(api, "vprintf") || vln_ieq(api, "wprintf")) return 0;
    if (vln_ieq(api, "fprintf") || vln_ieq(api, "sprintf") || vln_ieq(api, "syslog")) return 1;
    if (vln_ieq(api, "snprintf")) return 2;
    return -1;
}

static int vln_alloc_size_arg(const char *sym, const char *api, const char **canon_out) {
    if (vln_ieq(api, "malloc")) { *canon_out = "malloc"; return 0; }
    if (vln_ieq(api, "calloc")) { *canon_out = "calloc"; return -2; }
    if (vln_ieq(api, "realloc")) { *canon_out = "realloc"; return 1; }
    if (vln_ieq(api, "VirtualAlloc")) { *canon_out = "VirtualAlloc"; return 1; }
    if (vln_ieq(api, "HeapAlloc")) { *canon_out = "HeapAlloc"; return 2; }
    if (vln_ieq(api, "LocalAlloc")) { *canon_out = "LocalAlloc"; return 1; }
    if (vln_ieq(api, "GlobalAlloc")) { *canon_out = "GlobalAlloc"; return 1; }
    if (vln_ieq(api, "ExAllocatePool") || vln_ieq(api, "ExAllocatePoolWithTag") || vln_ieq(api, "ExAllocatePool2")) {
        *canon_out = "ExAllocatePool";
        return 1;
    }
    if (vln_ihas(sym, "operator new") || vln_ieq(api, "Znwm") || vln_ieq(api, "Znwj") || vln_ieq(api, "Znam") ||
        strncmp(sym, "??2@", 4) == 0 || strncmp(sym, "??_U@", 5) == 0) {
        *canon_out = "operator new";
        return 0;
    }
    return -1;
}

static int vln_match_source(const char *sym) {
    if (!sym || !sym[0]) return -1;
    char raw[96], api[96];
    vln_norm_sym(sym, raw, sizeof(raw), api, sizeof(api));
    return vln_list_match(vln_sources, api);
}

static bool vln_is_arg_reg(const ana_ctx *a, int arg_idx, const char *reg) {
    if (!reg || !reg[0]) return false;
    bool is_win = (a->bin.fmt == BIN_PE64 || a->bin.fmt == BIN_PE32);
    bool is_sysv = (a->bin.fmt == BIN_ELF64 || a->bin.fmt == BIN_ELF32 || a->bin.fmt == BIN_MACHO64);
    bool is_raw = !is_win && !is_sysv;

    if (a->bin.arch == BIN_ARCH_ARM64) {
        if (arg_idx == 0) return vln_ieq(reg, "x0") || vln_ieq(reg, "w0");
        if (arg_idx == 1) return vln_ieq(reg, "x1") || vln_ieq(reg, "w1");
        if (arg_idx == 2) return vln_ieq(reg, "x2") || vln_ieq(reg, "w2");
        return false;
    }

    if (arg_idx == 0) {
        if ((is_win || is_raw) && (vln_ieq(reg, "rcx") || vln_ieq(reg, "ecx"))) return true;
        if ((is_sysv || is_raw) && (vln_ieq(reg, "rdi") || vln_ieq(reg, "edi"))) return true;
    } else if (arg_idx == 1) {
        if ((is_win || is_raw) && (vln_ieq(reg, "rdx") || vln_ieq(reg, "edx"))) return true;
        if ((is_sysv || is_raw) && (vln_ieq(reg, "rsi") || vln_ieq(reg, "esi"))) return true;
    } else if (arg_idx == 2) {
        if ((is_win || is_raw) && (vln_ieq(reg, "r8") || vln_ieq(reg, "r8d"))) return true;
        if ((is_sysv || is_raw) && (vln_ieq(reg, "rdx") || vln_ieq(reg, "edx"))) return true;
    }
    return false;
}

static bool vln_is_plain_reg(const char *op) {
    if (!op || !op[0]) return false;
    if (strchr(op, '[') || strchr(op, ' ')) return false;
    if (isdigit((unsigned char)op[0])) return false;
    for (const char *p = op; *p; p++) {
        if (!isalnum((unsigned char)*p)) return false;
    }
    return true;
}

static bool vln_is_reg_const(const ana_ctx *a, const x86_ins *ins_buf, int from_idx, int min_idx, const char *reg) {
    for (int j = from_idx; j >= min_idx; j--) {
        const x86_ins *p = &ins_buf[j];
        if (p->flow == X86_FLOW_CALL || p->flow == X86_FLOW_RET) break;
        char ops[3][76];
        int nop = vln_split_ops(p->ops, ops);
        if (nop < 2 || !vln_ieq(ops[0], reg)) continue;

        if (strcmp(p->mnem, "lea") == 0) return (p->has_target && p->target_mem) ? true : false;
        if (strcmp(p->mnem, "mov") == 0 || strcmp(p->mnem, "movabs") == 0) {
            if (vln_parse_imm(ops[1], NULL)) return true;
            if (p->has_target && p->target_mem && ana_str_at(a, p->target)) return true;
            return false;
        }
        return false;
    }
    return false;
}

static bool vln_check_fmt_nonconst(const ana_ctx *a, const x86_ins *ins_buf, int call_idx, int arg_idx, char *why, size_t why_cap) {
    int min_idx = call_idx - 6;
    if (min_idx < 0) min_idx = 0;

    if (a->bin.arch == BIN_ARCH_X86) {
        int pushed = 0;
        for (int j = call_idx - 1; j >= min_idx; j--) {
            const x86_ins *p = &ins_buf[j];
            if (p->flow == X86_FLOW_CALL || p->flow == X86_FLOW_RET) break;
            if (strcmp(p->mnem, "push") != 0) continue;
            if (pushed == arg_idx) {
                if (vln_parse_imm(p->ops, NULL)) return false;
                snprintf(why, why_cap, "non-constant format arg pushed (%s %s)", p->mnem, p->ops);
                return true;
            }
            pushed++;
        }
        return false;
    }

    for (int j = call_idx - 1; j >= min_idx; j--) {
        const x86_ins *p = &ins_buf[j];
        if (p->flow == X86_FLOW_CALL || p->flow == X86_FLOW_RET) break;
        char ops[3][76];
        int nop = vln_split_ops(p->ops, ops);
        if (nop < 2 || !vln_is_arg_reg(a, arg_idx, ops[0])) continue;

        if (strcmp(p->mnem, "lea") == 0) {
            if (p->has_target && p->target_mem) return false;
            snprintf(why, why_cap, "non-constant format buffer (%s %s)", p->mnem, p->ops);
            return true;
        }
        if (strcmp(p->mnem, "mov") == 0 || strcmp(p->mnem, "movabs") == 0 ||
            strcmp(p->mnem, "movzx") == 0 || strcmp(p->mnem, "movsxd") == 0) {
            if (vln_parse_imm(ops[1], NULL)) return false;
            if (p->has_target && p->target_mem) return false;
            if (vln_is_plain_reg(ops[1]) && vln_is_reg_const(a, ins_buf, j - 1, min_idx, ops[1])) return false;
            snprintf(why, why_cap, "non-constant format arg (%s %s)", p->mnem, p->ops);
            return true;
        }
        if (strcmp(p->mnem, "xor") == 0 && vln_ieq(ops[0], ops[1])) return false;
        break;
    }
    return false;
}

static bool vln_is_ovf_jcc(const char *m) {
    return strcmp(m, "jo") == 0 || strcmp(m, "jno") == 0 ||
           strcmp(m, "jc") == 0 || strcmp(m, "jnc") == 0 ||
           strcmp(m, "jb") == 0 || strcmp(m, "jnb") == 0 ||
           strcmp(m, "jae") == 0 || strcmp(m, "ja") == 0 || strcmp(m, "jbe") == 0 ||
           strcmp(m, "b.hi") == 0 || strcmp(m, "b.hs") == 0 ||
           strcmp(m, "b.lo") == 0 || strcmp(m, "b.ls") == 0 ||
           strcmp(m, "b.vs") == 0 || strcmp(m, "b.vc") == 0;
}

static bool vln_is_ovf_guard(const x86_ins *p) {
    if (p->flow == X86_FLOW_JCC && vln_is_ovf_jcc(p->mnem)) return true;
    if (strcmp(p->mnem, "cmovo") == 0 || strcmp(p->mnem, "cmovb") == 0 ||
        strcmp(p->mnem, "cmovc") == 0 || strcmp(p->mnem, "cmovae") == 0 ||
        strcmp(p->mnem, "seto") == 0 || strcmp(p->mnem, "setb") == 0 || strcmp(p->mnem, "setc") == 0) {
        return true;
    }
    if (strcmp(p->mnem, "cmp") == 0) {
        char ops[3][76];
        int nop = vln_split_ops(p->ops, ops);
        if (nop >= 2) {
            uint64_t imm = 0;
            // comparing against zero is a null check, not an overflow bound
            if (vln_parse_imm(ops[1], &imm) && imm == 0) return false;
            return true;
        }
    }
    return false;
}

static int vln_check_int_ovf_alloc(const ana_ctx *a, const x86_ins *ins_buf, int call_idx, int size_arg, const char **op_out) {
    int min_idx = call_idx - 12;
    if (min_idx < 0) min_idx = 0;

    bool has_guard = false;
    bool size_const = false;
    bool c0 = false, c1 = false;
    bool found_shl = false;
    const char *shl_mnem = NULL;

    for (int j = call_idx - 1; j >= min_idx; j--) {
        const x86_ins *p = &ins_buf[j];
        if (p->flow == X86_FLOW_RET) break;

        if (vln_is_ovf_guard(p)) {
            has_guard = true;
            continue;
        }

        if (strcmp(p->mnem, "mov") == 0 || strcmp(p->mnem, "movabs") == 0) {
            char ops[3][76];
            int nop = vln_split_ops(p->ops, ops);
            if (nop >= 2 && vln_parse_imm(ops[1], NULL)) {
                if (size_arg == -2) {
                    if (vln_is_arg_reg(a, 0, ops[0])) c0 = true;
                    if (vln_is_arg_reg(a, 1, ops[0])) c1 = true;
                    if (c0 && c1) size_const = true;
                } else if (vln_is_arg_reg(a, size_arg, ops[0])) {
                    size_const = true;
                }
            }
        }

        if (has_guard || size_const) continue;

        if (strcmp(p->mnem, "imul") == 0 || strcmp(p->mnem, "mul") == 0 || strcmp(p->mnem, "mulx") == 0) {
            *op_out = p->mnem;
            return 2;
        }
        if (!found_shl && (strcmp(p->mnem, "shl") == 0 || strcmp(p->mnem, "sal") == 0 || strcmp(p->mnem, "shlx") == 0)) {
            found_shl = true;
            shl_mnem = p->mnem;
        }
    }

    if (found_shl) {
        *op_out = shl_mnem;
        return 1;
    }
    return 0;
}

static void vln_build_src_map(const ana_ctx *a, tbl_u64 *src_map) {
    if (!a->sym_map.slots || a->sym_map.cap == 0 || a->nxref == 0) return;

    for (uint32_t i = 0; i < a->sym_map.cap; i++) {
        uint32_t val = a->sym_map.slots[i].val;
        if (val == TBL_NONE) continue;
        const char *sym = ana_pool_str(a, val);
        int sid = vln_match_source(sym);
        if (sid < 0) continue;

        uint64_t sva = a->sym_map.slots[i].key;
        uint32_t first = 0;
        uint32_t cnt = ana_xrefs_to(a, sva, &first);
        for (uint32_t k = 0; k < cnt; k++) {
            const ana_xref *x = &a->xrefs[first + k];
            if (x->type == ANA_XREF_DATA) continue;
            const ana_func *cf = ana_func_at(a, x->from);
            if (!cf) continue;
            if (tbl_get(src_map, cf->start) == TBL_NONE) tbl_put(src_map, cf->start, (uint32_t)sid);

            // propagate across 1-hop plt/iat jmp thunks
            if (x->type == ANA_XREF_JMP && cf->end > cf->start && (cf->end - cf->start) <= 16) {
                uint32_t tf = 0;
                uint32_t tc = ana_xrefs_to(a, cf->start, &tf);
                for (uint32_t j = 0; j < tc; j++) {
                    const ana_xref *tx = &a->xrefs[tf + j];
                    if (tx->type == ANA_XREF_DATA) continue;
                    const ana_func *tcf = ana_func_at(a, tx->from);
                    if (tcf && tbl_get(src_map, tcf->start) == TBL_NONE) {
                        tbl_put(src_map, tcf->start, (uint32_t)sid);
                    }
                }
            }
        }
    }
}

typedef struct {
    uint64_t va;
    int      hops;
} vln_bfs_node;

static bool vln_find_source(const ana_ctx *a, uint64_t func_va, int local_sid,
                            const tbl_u64 *src_map, tbl_u64 *vis,
                            const char **src_out, int *hops_out) {
    if (local_sid >= 0) {
        *src_out = vln_sources[local_sid];
        *hops_out = 0;
        return true;
    }
    uint32_t s0 = tbl_get(src_map, func_va);
    if (s0 != TBL_NONE) {
        *src_out = vln_sources[s0];
        *hops_out = 0;
        return true;
    }
    if (a->nxref == 0 || a->nfunc == 0) return false;

    vln_bfs_node q[VLN_BFS_MAX_QUEUE];
    int qh = 0, qt = 0;
    tbl_clear(vis);
    tbl_put(vis, func_va, 1);
    q[qt].va = func_va;
    q[qt].hops = 0;
    qt++;

    while (qh < qt) {
        vln_bfs_node cur = q[qh++];
        if (cur.hops >= VLN_BFS_MAX_DEPTH) continue;

        uint32_t first = 0;
        uint32_t cnt = ana_xrefs_to(a, cur.va, &first);
        for (uint32_t k = 0; k < cnt; k++) {
            const ana_xref *x = &a->xrefs[first + k];
            if (x->type == ANA_XREF_DATA) continue;
            const ana_func *cf = ana_func_at(a, x->from);
            if (!cf || cf->start == cur.va) continue;
            if (tbl_get(vis, cf->start) != TBL_NONE) continue;

            uint32_t sid = tbl_get(src_map, cf->start);
            if (sid != TBL_NONE) {
                *src_out = vln_sources[sid];
                *hops_out = cur.hops + 1;
                return true;
            }
            if (qt < VLN_BFS_MAX_QUEUE) {
                tbl_put(vis, cf->start, 1);
                q[qt].va = cf->start;
                q[qt].hops = cur.hops + 1;
                qt++;
            }
        }
    }
    return false;
}

static int vln_hit_prio(const vln_hit *h) {
    int p = (strcmp(h->sev, "HIGH") == 0) ? 10 : 0;
    if (h->source[0]) p += 5 - vln_clamp(h->hops, 0, 4);
    return p;
}

static void vln_push_hit(vln_res *out, uint64_t va, const char *sev, const char *kind,
                         const char *func, const char *sink, const char *source, int hops,
                         const char *detail) {
    for (int i = 0; i < out->nhit; i++) {
        if (out->hits[i].va == va && strcmp(out->hits[i].kind, kind) == 0) return;
    }

    vln_hit h;
    memset(&h, 0, sizeof(h));
    h.va = va;
    snprintf(h.sev, sizeof(h.sev), "%s", sev);
    snprintf(h.kind, sizeof(h.kind), "%s", kind);
    snprintf(h.func, sizeof(h.func), "%s", func ? func : "");
    snprintf(h.sink, sizeof(h.sink), "%s", sink ? sink : "");
    if (source && source[0]) {
        snprintf(h.source, sizeof(h.source), "%s", source);
        h.hops = hops;
    }
    snprintf(h.detail, sizeof(h.detail), "%s", detail ? detail : "");

    if (out->nhit < VLN_MAX_HITS) {
        out->hits[out->nhit++] = h;
        return;
    }

    // evict lowest-priority entry so high-severity hits are never dropped
    int worst = -1;
    int worst_p = vln_hit_prio(&h);
    for (int i = 0; i < out->nhit; i++) {
        int pi = vln_hit_prio(&out->hits[i]);
        if (pi < worst_p) {
            worst_p = pi;
            worst = i;
        }
    }
    if (worst >= 0) out->hits[worst] = h;
}

static int vln_hit_cmp(const void *a, const void *b) {
    const vln_hit *x = (const vln_hit *)a;
    const vln_hit *y = (const vln_hit *)b;
    int hx = (strcmp(x->sev, "HIGH") == 0) ? 0 : 1;
    int hy = (strcmp(y->sev, "HIGH") == 0) ? 0 : 1;
    if (hx != hy) return hx - hy;
    int sx = x->source[0] ? 0 : 1;
    int sy = y->source[0] ? 0 : 1;
    if (sx != sy) return sx - sy;
    if (x->source[0] && x->hops != y->hops) return x->hops - y->hops;
    if (x->va != y->va) return (x->va > y->va) - (x->va < y->va);
    return strcmp(x->kind, y->kind);
}

static int vln_decode_range(const ana_ctx *a, uint64_t start, uint64_t end, int max_ins, x86_ins *buf) {
    if (end <= start) return 0;
    size_t av = 0;
    const uint8_t *p = bin_ptr(&a->bin, start, &av);
    if (!p || av == 0) return 0;
    uint64_t span = end - start;
    if (span < av) av = (size_t)span;

    int nins = 0;
    size_t pos = 0;
    while (pos < av && nins < max_ins) {
        int n = arch_decode(a->bin.arch, p + pos, av - pos, start + pos, 1, 0, &buf[nins]);
        if (n <= 0) { pos++; continue; }
        nins++;
        pos += (size_t)n;
    }
    return nins;
}

static void vln_scan_func(const ana_ctx *a, uint64_t fstart, uint64_t fend, const char *fname,
                          x86_ins *ins_buf, const tbl_u64 *src_map, tbl_u64 *vis, vln_res *out) {
    int nins = vln_decode_range(a, fstart, fend, VLN_SCAN_MAX_INS, ins_buf);
    if (nins == 0) return;

    int local_sid = -1;
    for (int i = 0; i < nins; i++) {
        const x86_ins *ins = &ins_buf[i];
        if (ins->flow != X86_FLOW_CALL && !(ins->flow == X86_FLOW_JMP && nins >= 3)) continue;
        const char *sym = vln_call_sym(a, ins);
        if (!sym) continue;
        int sid = vln_match_source(sym);
        if (sid >= 0) { local_sid = sid; break; }
    }

    int src_checked = 0;
    const char *src_name = NULL;
    int src_hops = 0;
    bool has_src = false;

    for (int i = 0; i < nins; i++) {
        const x86_ins *ins = &ins_buf[i];
        // skip 1-2 instruction plt/iat thunks themselves
        if (ins->flow != X86_FLOW_CALL && !(ins->flow == X86_FLOW_JMP && nins >= 3)) continue;
        const char *sym = vln_call_sym(a, ins);
        if (!sym || !sym[0]) continue;

        char raw[96], api[96];
        vln_norm_sym(sym, raw, sizeof(raw), api, sizeof(api));
        if (!api[0] && !raw[0]) continue;

        int unsafe_idx = vln_list_match(vln_unsafe_sinks, api);
        int fmt_arg = vln_fmt_arg_index(api);
        const char *alloc_canon = NULL;
        int alloc_arg = vln_alloc_size_arg(sym, api, &alloc_canon);
        int bcopy_idx = vln_list_match(vln_bounded_copies, api);

        if (unsafe_idx < 0 && fmt_arg < 0 && alloc_arg == -1 && bcopy_idx < 0) continue;

        if (!src_checked) {
            has_src = vln_find_source(a, fstart, local_sid, src_map, vis, &src_name, &src_hops);
            src_checked = 1;
        }

        if (unsafe_idx >= 0) {
            char det[112];
            if (has_src) {
                snprintf(det, sizeof(det), "unsafe sink %s reachable from %s (%d hops)",
                         vln_unsafe_sinks[unsafe_idx], src_name, src_hops);
            } else {
                snprintf(det, sizeof(det), "call to unbounded/unsafe sink %s", vln_unsafe_sinks[unsafe_idx]);
            }
            vln_push_hit(out, ins->ip, "HIGH", "UNSAFE_SINK", fname, vln_unsafe_sinks[unsafe_idx],
                         has_src ? src_name : NULL, src_hops, det);
        }

        if (fmt_arg >= 0) {
            char why[112];
            if (vln_check_fmt_nonconst(a, ins_buf, i, fmt_arg, why, sizeof(why))) {
                vln_push_hit(out, ins->ip, "HIGH", "FMT_STRING", fname, api,
                             has_src ? src_name : NULL, src_hops, why);
            }
        }

        if (alloc_arg != -1) {
            const char *opm = NULL;
            int ovf = vln_check_int_ovf_alloc(a, ins_buf, i, alloc_arg, &opm);
            if (ovf > 0) {
                const char *sev = (ovf == 2 || has_src) ? "HIGH" : "MED";
                char det[112];
                snprintf(det, sizeof(det), "unchecked %s size calculation before %s", opm, alloc_canon);
                vln_push_hit(out, ins->ip, sev, "INT_OVERFLOW_ALLOC", fname, alloc_canon,
                             has_src ? src_name : NULL, src_hops, det);
            }
        }

        if (bcopy_idx >= 0 && has_src) {
            const char *sev = (src_hops == 0) ? "HIGH" : "MED";
            char det[112];
            snprintf(det, sizeof(det), "bounded copy %s reachable from %s (%d hops) - audit length",
                     vln_bounded_copies[bcopy_idx], src_name, src_hops);
            vln_push_hit(out, ins->ip, sev, "BOUNDED_COPY_AUDIT", fname, vln_bounded_copies[bcopy_idx],
                         src_name, src_hops, det);
        }
    }
}

int vln_scan(const ana_ctx *a, vln_res *out) {
    if (!out) return 0;
    memset(out, 0, sizeof(*out));
    if (!a) return 0;

    x86_ins *ins_buf = (x86_ins *)malloc((size_t)VLN_SCAN_MAX_INS * sizeof(x86_ins));
    if (!ins_buf) return 0;

    tbl_u64 src_map, vis;
    tbl_init(&src_map);
    tbl_init(&vis);
    vln_build_src_map(a, &src_map);

    if (a->nfunc > 0) {
        for (uint32_t i = 0; i < a->nfunc; i++) {
            const ana_func *f = &a->funcs[i];
            if (f->end <= f->start) continue;
            char fnbuf[64];
            const char *fn = ana_pool_str(a, f->name_off);
            if (!fn || !fn[0]) fn = ana_sym_at(a, f->start);
            if (!fn || !fn[0]) {
                snprintf(fnbuf, sizeof(fnbuf), "sub_%llx", (unsigned long long)f->start);
                fn = fnbuf;
            }
            vln_scan_func(a, f->start, f->end, fn, ins_buf, &src_map, &vis, out);
        }
    } else if (a->bin.nsec > 0) {
        // fallback synthetic function for raw unanalyzed buffers
        const bin_sec *s = bin_sec_at(&a->bin, a->bin.entry);
        if (!s || !(s->perm & BIN_PERM_X)) {
            s = NULL;
            for (uint32_t i = 0; i < a->bin.nsec; i++) {
                if (a->bin.secs[i].perm & BIN_PERM_X) { s = &a->bin.secs[i]; break; }
            }
            if (!s) s = &a->bin.secs[0];
        }
        uint64_t start = (a->bin.entry >= s->va && a->bin.entry < s->va + s->vsize) ? a->bin.entry : s->va;
        uint64_t span = s->fsize ? s->fsize : s->vsize;
        uint64_t end = s->va + span;
        if (end > start + 65536ULL) end = start + 65536ULL;
        char fnbuf[64];
        const char *fn = ana_sym_at(a, start);
        if (!fn || !fn[0]) {
            snprintf(fnbuf, sizeof(fnbuf), "sub_%llx", (unsigned long long)start);
            fn = fnbuf;
        }
        vln_scan_func(a, start, end, fn, ins_buf, &src_map, &vis, out);
    }

    if (out->nhit > 1) qsort(out->hits, (size_t)out->nhit, sizeof(vln_hit), vln_hit_cmp);
    for (int i = 0; i < out->nhit; i++) {
        if (strcmp(out->hits[i].sev, "HIGH") == 0) out->nhigh++;
        else out->nmed++;
    }

    tbl_free(&vis);
    tbl_free(&src_map);
    free(ins_buf);
    return out->nhit;
}

typedef struct {
    int ncmp;
    int njcc;
    int nbounds_jcc;
    int nnull_chk;
    int ncookie;
    int nunsafe;
    int nrawcopy;
    int nsafe_api;
    int nint_helper;
} vln_fn_stats;

static bool vln_is_null_test(const x86_ins *prev, const x86_ins *cur) {
    if (cur->flow != X86_FLOW_JCC) return false;
    bool is_eq = (strcmp(cur->mnem, "je") == 0 || strcmp(cur->mnem, "jz") == 0 ||
                  strcmp(cur->mnem, "jne") == 0 || strcmp(cur->mnem, "jnz") == 0);
    if (strcmp(cur->mnem, "cbz") == 0 || strcmp(cur->mnem, "cbnz") == 0) return true;
    if (!is_eq) return false;

    if (strcmp(prev->mnem, "test") == 0) {
        char ops[3][76];
        if (vln_split_ops(prev->ops, ops) >= 2 && vln_is_plain_reg(ops[0]) && vln_ieq(ops[0], ops[1])) {
            return true;
        }
    }
    if (strcmp(prev->mnem, "cmp") == 0) {
        char ops[3][76];
        uint64_t imm = 1;
        if (vln_split_ops(prev->ops, ops) >= 2 && vln_parse_imm(ops[1], &imm) && imm == 0) {
            return true;
        }
    }
    return false;
}

static void vln_collect_stats(const ana_ctx *ctx, uint64_t va, uint32_t hint_sz, vln_fn_stats *st) {
    memset(st, 0, sizeof(*st));
    if (!ctx || va == 0) return;

    uint64_t sz = hint_sz;
    const ana_func *f = ana_func_at(ctx, va);
    if (f && f->start == va && f->end > f->start) sz = f->end - f->start;
    if (sz == 0) return;
    if (sz > 65536ULL) sz = 65536ULL;

    size_t av = 0;
    const uint8_t *p = bin_ptr(&ctx->bin, va, &av);
    if (!p || av == 0) return;
    if (sz < av) av = (size_t)sz;

    x86_ins ins, prev;
    memset(&prev, 0, sizeof(prev));
    size_t pos = 0;
    int nins = 0;

    while (pos < av && nins < VLN_DIFF_MAX_INS) {
        int n = arch_decode(ctx->bin.arch, p + pos, av - pos, va + pos, 1, 0, &ins);
        if (n <= 0) { pos++; continue; }
        nins++;

        if (strcmp(ins.mnem, "cmp") == 0 || strcmp(ins.mnem, "test") == 0 ||
            strcmp(ins.mnem, "cmn") == 0 || strcmp(ins.mnem, "tst") == 0) {
            st->ncmp++;
        }
        if (ins.flow == X86_FLOW_JCC) {
            st->njcc++;
            if (vln_is_ovf_jcc(ins.mnem)) st->nbounds_jcc++;
            if (nins > 1 && vln_is_null_test(&prev, &ins)) st->nnull_chk++;
        }

        if (ins.flow == X86_FLOW_CALL || (ins.flow == X86_FLOW_JMP && ins.has_target)) {
            const char *sym = vln_call_sym(ctx, &ins);
            if (sym && sym[0]) {
                char raw[96], api[96];
                vln_norm_sym(sym, raw, sizeof(raw), api, sizeof(api));
                if (vln_list_match(vln_cookie_apis, raw) >= 0) st->ncookie++;
                if (vln_list_match(vln_unsafe_sinks, api) >= 0) st->nunsafe++;
                if (vln_list_match(vln_bounded_copies, api) >= 0) st->nrawcopy++;
                if (vln_list_match(vln_safe_apis, api) >= 0) st->nsafe_api++;
                if (vln_list_match(vln_int_helpers, api) >= 0 || vln_ihas(sym, "SafeInt")) st->nint_helper++;
            }
        }

        prev = ins;
        pos += (size_t)n;
    }
}

static void vln_append_part(char *dst, size_t cap, size_t *len, const char *sep, const char *part) {
    if (!part || !part[0]) return;
    size_t slen = (*len > 0) ? strlen(sep) : 0;
    size_t plen = strlen(part);
    if (*len + slen + plen >= cap) return;
    if (slen) {
        memcpy(dst + *len, sep, slen);
        *len += slen;
    }
    memcpy(dst + *len, part, plen);
    *len += plen;
    dst[*len] = 0;
}

static int vln_pdiff_cmp(const void *a, const void *b) {
    const vln_pdiff_item *x = (const vln_pdiff_item *)a;
    const vln_pdiff_item *y = (const vln_pdiff_item *)b;
    if (x->score != y->score) return y->score - x->score;
    int dx = x->delta_cmp + x->delta_jcc;
    int dy = y->delta_cmp + y->delta_jcc;
    if (dx != dy) return dy - dx;
    return (x->va_a > y->va_a) - (x->va_a < y->va_a);
}

int vln_patch_triage(const ana_ctx *a, const ana_ctx *b, const dif_res *dif, vln_pdiff_res *out) {
    if (!out) return 0;
    memset(out, 0, sizeof(*out));
    if (!a || !b || !dif || !dif->items || dif->nitem == 0) return 0;

    for (uint32_t i = 0; i < dif->nitem; i++) {
        const dif_item *it = &dif->items[i];
        if (it->kind != DIF_MOD) continue;

        vln_fn_stats sa, sb;
        vln_collect_stats(a, it->va_a, it->size_a, &sa);
        vln_collect_stats(b, it->va_b, it->size_b, &sb);

        int d_cmp = sb.ncmp - sa.ncmp;
        int d_jcc = sb.njcc - sa.njcc;
        int d_bnd = sb.nbounds_jcc - sa.nbounds_jcc;
        int d_nul = sb.nnull_chk - sa.nnull_chk;
        bool cookie_added = (sb.ncookie > sa.ncookie);
        bool int_added = (sb.nint_helper > sa.nint_helper);
        bool sink_removed = (sa.nunsafe > sb.nunsafe);
        bool safe_added = (sb.nsafe_api > sa.nsafe_api);
        bool copy_replaced = (sa.nrawcopy > sb.nrawcopy && safe_added);
        bool surgical = (it->sim >= 40 && it->sim <= 98);

        int score = 0;
        if (surgical) score += 15;
        score += 12 * vln_clamp(d_cmp, 0, 3);
        score += 10 * vln_clamp(d_jcc, 0, 3);
        if (d_bnd > 0) score += 15;
        if (sink_removed || safe_added || cookie_added || int_added) score += 25;
        if (d_nul > 0) score += 8;
        score = vln_clamp(score, 0, 100);

        vln_pdiff_item pi;
        memset(&pi, 0, sizeof(pi));
        pi.va_a = it->va_a;
        pi.va_b = it->va_b;
        pi.score = score;
        pi.delta_cmp = d_cmp;
        pi.delta_jcc = d_jcc;
        if (it->name[0]) snprintf(pi.name, sizeof(pi.name), "%s", it->name);
        else snprintf(pi.name, sizeof(pi.name), "sub_%llx", (unsigned long long)(it->va_b ? it->va_b : it->va_a));

        size_t rlen = 0;
        char seg[64];
        if ((sink_removed && safe_added) || copy_replaced) {
            vln_append_part(pi.reason, sizeof(pi.reason), &rlen, " + ", "replaced unsafe sink");
        } else if (sink_removed) {
            vln_append_part(pi.reason, sizeof(pi.reason), &rlen, " + ", "removed unsafe sink");
        } else if (safe_added) {
            vln_append_part(pi.reason, sizeof(pi.reason), &rlen, " + ", "added safe API");
        }
        if (int_added) vln_append_part(pi.reason, sizeof(pi.reason), &rlen, " + ", rlen ? "overflow helper" : "added overflow helper");
        if (cookie_added) vln_append_part(pi.reason, sizeof(pi.reason), &rlen, " + ", rlen ? "stack cookie" : "added stack cookie");
        if (d_cmp > 0) {
            snprintf(seg, sizeof(seg), rlen ? "%d cmp" : "added %d cmp", d_cmp);
            vln_append_part(pi.reason, sizeof(pi.reason), &rlen, " + ", seg);
        }
        if (d_bnd > 0) {
            snprintf(seg, sizeof(seg), rlen ? "%d bounds jcc" : "added %d bounds jcc", d_bnd);
            vln_append_part(pi.reason, sizeof(pi.reason), &rlen, " + ", seg);
        } else if (d_jcc > 0) {
            snprintf(seg, sizeof(seg), rlen ? "%d jcc" : "added %d jcc", d_jcc);
            vln_append_part(pi.reason, sizeof(pi.reason), &rlen, " + ", seg);
        }
        if (d_nul > 0) {
            snprintf(seg, sizeof(seg), rlen ? "%d null chk" : "added %d null check", d_nul);
            vln_append_part(pi.reason, sizeof(pi.reason), &rlen, " + ", seg);
        }
        if (surgical) {
            snprintf(seg, sizeof(seg), "surgical patch (sim %d%%)", it->sim);
            vln_append_part(pi.reason, sizeof(pi.reason), &rlen, "; ", seg);
        } else if (rlen == 0) {
            snprintf(pi.reason, sizeof(pi.reason), "modified function (sim %d%%)", it->sim);
        }

        if (out->nitem < VLN_MAX_PDIFF) {
            out->items[out->nitem++] = pi;
        } else {
            int worst = -1;
            int min_sc = pi.score;
            for (int j = 0; j < out->nitem; j++) {
                if (out->items[j].score < min_sc) {
                    min_sc = out->items[j].score;
                    worst = j;
                }
            }
            if (worst >= 0) out->items[worst] = pi;
        }
    }

    if (out->nitem > 1) qsort(out->items, (size_t)out->nitem, sizeof(vln_pdiff_item), vln_pdiff_cmp);
    return out->nitem;
}

static void vln_hilbert_rot(int n, int *x, int *y, int rx, int ry) {
    if (ry != 0) return;
    if (rx == 1) {
        *x = n - 1 - *x;
        *y = n - 1 - *y;
    }
    int t = *x;
    *x = *y;
    *y = t;
}

static void vln_hilbert_d2xy(int n, int d, int *ox, int *oy) {
    int x = 0, y = 0;
    int t = d;
    for (int s = 1; s < n; s <<= 1) {
        int rx = 1 & (t >> 1);
        int ry = 1 & (t ^ rx);
        vln_hilbert_rot(s, &x, &y, rx, ry);
        x += s * rx;
        y += s * ry;
        t >>= 2;
    }
    *ox = x;
    *oy = y;
}

bool vln_hilbert_map(const ana_ctx *a, int order, vln_hilbert_res *out) {
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    if (!a || !a->bin.map.data || a->bin.map.size == 0) return false;

    order = vln_clamp(order, 4, 6);
    int side = 1 << order;
    int ncell = side * side;
    const uint8_t *data = a->bin.map.data;
    uint64_t fsz = a->bin.map.size;

    for (int d = 0; d < ncell; d++) {
        int x = 0, y = 0;
        vln_hilbert_d2xy(side, d, &x, &y);
        int idx = y * side + x;

        uint64_t off = ((uint64_t)d * fsz) / (uint64_t)ncell;
        uint64_t end = ((uint64_t)(d + 1) * fsz) / (uint64_t)ncell;
        uint64_t len = (end > off) ? (end - off) : 1ULL;
        if (off + len > fsz) len = fsz - off;
        size_t slen = (len > VLN_HILB_SAMPLE) ? VLN_HILB_SAMPLE : (size_t)len;

        const uint8_t *p = data + off;
        uint32_t hist[256] = {0};
        size_t zeros = 0, print = 0;
        for (size_t i = 0; i < slen; i++) {
            uint8_t b = p[i];
            hist[b]++;
            if (b == 0) zeros++;
            if ((b >= 0x20 && b <= 0x7E) || b == '\t' || b == '\n' || b == '\r') print++;
        }

        double h = 0.0;
        double inv = 1.0 / (double)slen;
        for (int i = 0; i < 256; i++) {
            if (!hist[i]) continue;
            double pr = (double)hist[i] * inv;
            h -= pr * log2(pr);
        }

        int ei = (int)(h * 10.0 + 0.5);
        out->ent[idx] = (uint8_t)vln_clamp(ei, 0, 80);

        uint64_t va = 0;
        bool mapped = bin_off_to_va(&a->bin, off, &va);
        out->offs[idx] = off;
        out->vas[idx] = mapped ? va : 0;

        bool is_exec = false;
        if (mapped) {
            const bin_sec *sec = bin_sec_at(&a->bin, va);
            if (sec && (sec->perm & BIN_PERM_X)) is_exec = true;
        }

        uint8_t cls = 2;
        if (zeros * 100 >= slen * 90 || h < 0.35) cls = 0;
        else if (h >= 6.8) cls = 4;
        else if (is_exec) cls = 1;
        else if (print * 100 >= slen * 72 && h < 6.0) cls = 3;
        out->cls[idx] = cls;
    }

    out->side = side;
    out->ncell = ncell;
    return true;
}
