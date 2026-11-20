#include "ana.h"
#include "../scan/scan.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool tri_ihas(const char *hay, const char *ndl) {
    if (!hay || !ndl || !ndl[0]) return false;
    size_t nl = strlen(ndl);
    for (const char *p = hay; *p; p++) {
        size_t i = 0;
        while (i < nl && p[i] && tolower((unsigned char)p[i]) == tolower((unsigned char)ndl[i])) i++;
        if (i == nl) return true;
    }
    return false;
}

static void tri_note(tri_report *r, const char *msg) {
    if (r->nnote < 8) snprintf(r->notes[r->nnote++], 128, "%s", msg);
}

static void tri_spot_add(tri_report *r, uint64_t va, const char *kind, const char *name, const char *reason, int score) {
    if (r->nspot >= 48) return;
    tri_spot *s = &r->spots[r->nspot++];
    s->va = va;
    s->score = score;
    snprintf(s->kind, sizeof(s->kind), "%s", kind);
    snprintf(s->name, sizeof(s->name), "%s", name ? name : "");
    snprintf(s->reason, sizeof(s->reason), "%s", reason);
}

static int tri_spot_cmp(const void *a, const void *b) {
    return ((const tri_spot *)b)->score - ((const tri_spot *)a)->score;
}

static void tri_add_cap(tri_report *r, int idx, const char *api, uint64_t va) {
    tri_cap *c = &r->caps[idx];
    for (int i = 0; i < c->count; i++) {
        if (_stricmp(c->apis[i], api) == 0) return;
    }
    if (c->count < 16) {
        snprintf(c->apis[c->count], sizeof(c->apis[0]), "%s", api);
        c->vas[c->count] = va;
        c->count++;
    }
}

static void tri_classify_imports(const ana_ctx *a, tri_report *r) {
    static const char *const grp_names[7] = {
        "Anti-Debug", "Memory/Unpack", "Process/Exec", "Network", "Filesystem", "Registry", "Crypto"
    };
    r->ncap = 7;
    for (int i = 0; i < 7; i++) snprintf(r->caps[i].group, sizeof(r->caps[i].group), "%s", grp_names[i]);

    static const char *const k_dbg[] = {"IsDebuggerPresent","CheckRemoteDebugger","NtQueryInformationProcess","OutputDebugString","SetUnhandledExceptionFilter","QueryPerformanceCounter","GetTickCount","NtSetInformationThread", NULL};
    static const char *const k_mem[] = {"VirtualAlloc","VirtualProtect","WriteProcessMemory","ReadProcessMemory","NtUnmapViewOfSection","LoadLibrary","GetProcAddress","LdrLoadDll","RtlAllocateHeap", NULL};
    static const char *const k_prc[] = {"CreateProcess","ShellExecute","CreateThread","CreateRemoteThread","OpenProcess","WinExec","ResumeThread","QueueUserAPC", NULL};
    static const char *const k_net[] = {"WSAStartup","WSAConnect","WSASend","WSARecv","InternetOpen","InternetConnect","HttpSendRequest","WinHttpOpen","URLDownload","getaddrinfo","socket", NULL};
    static const char *const k_fs[]  = {"CreateFile","ReadFile","WriteFile","DeleteFile","MoveFile","FindFirstFile","CopyFile","SetFilePointer", NULL};
    static const char *const k_reg[] = {"RegOpenKey","RegSetValue","RegCreateKey","RegQueryValue","CreateService","StartService", NULL};
    static const char *const k_cry[] = {"CryptEncrypt","CryptDecrypt","BCryptEncrypt","BCryptDecrypt","CryptAcquireContext","CryptHashData","CryptGenRandom", NULL};
    static const char *const *const tables[7] = {k_dbg, k_mem, k_prc, k_net, k_fs, k_reg, k_cry};

    int nimp = 0, has_ll = 0, has_gpa = 0, has_vp = 0;
    for (uint32_t i = 0; i < a->bin.nsym; i++) {
        if (a->bin.syms[i].kind != BIN_SYM_IMPORT) continue;
        nimp++;
        const char *full = bin_str(&a->bin, a->bin.syms[i].name_off);
        const char *bang = strchr(full, '!');
        const char *fn = bang ? bang + 1 : full;
        if (tri_ihas(fn, "LoadLibrary")) has_ll = 1;
        if (tri_ihas(fn, "GetProcAddress")) has_gpa = 1;
        if (tri_ihas(fn, "VirtualProtect") || tri_ihas(fn, "VirtualAlloc")) has_vp = 1;

        for (int g = 0; g < 7; g++) {
            for (int k = 0; tables[g][k]; k++) {
                if (tri_ihas(fn, tables[g][k])) {
                    tri_add_cap(r, g, fn, a->bin.syms[i].va);
                    break;
                }
            }
        }
    }

    if (nimp > 0 && nimp <= 14 && has_ll && has_gpa) {
        r->sparse_imp = 1;
        r->pack_score += has_vp ? 32 : 20;
        tri_note(r, "Sparse import table with LoadLibrary/GetProcAddress (dynamic API resolution or unpacker stub)");
    }
}

static void tri_detect_signatures(const ana_ctx *a, tri_report *r) {
    const bin_img *b = &a->bin;
    snprintf(r->packer, sizeof(r->packer), "None detected");
    snprintf(r->compiler, sizeof(r->compiler), "Unknown");

    if (b->has_clr) snprintf(r->compiler, sizeof(r->compiler), ".NET / CLR");

    for (uint32_t i = 0; i < b->nsec; i++) {
        const bin_sec *s = &b->secs[i];
        size_t av = 0;
        const uint8_t *p = bin_ptr(b, s->va, &av);
        if (av > (2u << 20)) av = (2u << 20);
        double h = (p && av) ? ana_entropy(p, av) : 0.0;
        if (h > r->max_ent) r->max_ent = h;

        if ((s->perm & BIN_PERM_W) && (s->perm & BIN_PERM_X)) {
            r->has_rwx = 1;
            r->pack_score += 24;
            char msg[128];
            snprintf(msg, sizeof(msg), "Section %s is RWX (writable + executable; common in self-modifying unpackers)", s->name);
            tri_note(r, msg);
            tri_spot_add(r, s->va, "RWX_SEC", s->name, "writable and executable section", 85);
        }
        if ((s->perm & BIN_PERM_X) && h >= 7.0) {
            r->high_ent_exec = 1;
            r->pack_score += 34;
            char msg[128];
            snprintf(msg, sizeof(msg), "Executable section %s has high entropy H=%.2f (likely compressed or encrypted)", s->name, h);
            tri_note(r, msg);
            tri_spot_add(r, s->va, "PACKED", s->name, "high-entropy executable section", 92);
        }

        if (tri_ihas(s->name, "UPX")) { snprintf(r->packer, sizeof(r->packer), "UPX Packer"); r->pack_score += 45; }
        else if (tri_ihas(s->name, "vmp")) { snprintf(r->packer, sizeof(r->packer), "VMProtect"); r->pack_score += 45; r->obf_score += 45; }
        else if (tri_ihas(s->name, "themida") || tri_ihas(s->name, "winlice")) { snprintf(r->packer, sizeof(r->packer), "Themida / WinLicense"); r->pack_score += 45; r->obf_score += 45; }
        else if (tri_ihas(s->name, "enigma")) { snprintf(r->packer, sizeof(r->packer), "Enigma Protector"); r->pack_score += 40; }
        else if (tri_ihas(s->name, "aspack") || tri_ihas(s->name, "adata")) { snprintf(r->packer, sizeof(r->packer), "ASPack"); r->pack_score += 40; }
        else if (tri_ihas(s->name, "mpress")) { snprintf(r->packer, sizeof(r->packer), "MPRESS"); r->pack_score += 40; }
        else if (tri_ihas(s->name, "gopclntab")) snprintf(r->compiler, sizeof(r->compiler), "Go");
    }

    const bin_sec *ep = bin_sec_at(b, b->entry);
    if (ep && _stricmp(ep->name, ".text") != 0 && _stricmp(ep->name, "CODE") != 0 &&
        _stricmp(ep->name, ".raw") != 0 && strncmp(ep->name, "LOAD", 4) != 0) {
        r->ep_anomaly = 1;
        r->pack_score += 18;
        char msg[128];
        snprintf(msg, sizeof(msg), "Entry point lies in section %s instead of .text (possible unpacker stub)", ep->name);
        tri_note(r, msg);
        tri_spot_add(r, b->entry, "EP_STUB", ep->name, "entry point outside standard .text", 80);
    }

    r->overlay_size = b->overlay_size;
    if (b->overlay_size > 4096) {
        char msg[128];
        snprintf(msg, sizeof(msg), "Appended overlay detected: %llu bytes after last section", (unsigned long long)b->overlay_size);
        tri_note(r, msg);
    }

    // cap scan for huge binaries
    size_t scan_lim = (b->map.size > (4u << 20)) ? (4u << 20) : (size_t)b->map.size;
    if (strcmp(r->compiler, "Unknown") == 0 && b->map.data && scan_lim > 64) {
        if (scan_text_find(b->map.data, scan_lim, 0, "rustc") < scan_lim) snprintf(r->compiler, sizeof(r->compiler), "Rust");
        else if (scan_text_find(b->map.data, scan_lim, 0, "Go build") < scan_lim) snprintf(r->compiler, sizeof(r->compiler), "Go");
        else if (scan_text_find(b->map.data, scan_lim, 0, "MEI\x0c") < scan_lim) snprintf(r->packer, sizeof(r->packer), "PyInstaller");
        else if (scan_text_find(b->map.data, scan_lim, 0, "GCC:") < scan_lim) snprintf(r->compiler, sizeof(r->compiler), "GCC / MinGW");
        else if (scan_text_find(b->map.data, scan_lim, 0, "clang") < scan_lim) snprintf(r->compiler, sizeof(r->compiler), "Clang / LLVM");
        else if (b->fmt == BIN_PE64 || b->fmt == BIN_PE32) snprintf(r->compiler, sizeof(r->compiler), "MSVC / Win32");
    }
}

static void tri_scan_obfuscation(const ana_ctx *a, tri_report *r) {
    uint32_t lim = a->nfunc < 600 ? a->nfunc : 600;
    uint32_t stride = (a->nfunc > lim) ? (a->nfunc / lim) : 1;
    x86_ins ins, prev;

    for (uint32_t idx = 0; idx < a->nfunc && r->nspot < 46; idx += stride) {
        const ana_func *f = &a->funcs[idx];
        uint64_t fsz = (f->end > f->start) ? (f->end - f->start) : 0;
        if (fsz < 12) continue;
        if (fsz > 8192) fsz = 8192;

        size_t av = 0;
        const uint8_t *p = bin_ptr(&a->bin, f->start, &av);
        if (!p || av < 12) continue;
        if (av > fsz) av = (size_t)fsz;

        int nins = 0, ind_jmp = 0, jcc = 0, pushf = 0, opaque = 0, trick = 0, math_ops = 0;
        memset(&prev, 0, sizeof(prev));
        size_t pos = 0;
        while (pos < av && nins < 400) {
            int n = arch_decode(a->bin.arch, p + pos, av - pos, f->start + pos, 1, 0, &ins);
            if (n <= 0) break;
            nins++;

            if (ins.flow == X86_FLOW_JMP && !ins.has_target) ind_jmp++;
            if (ins.flow == X86_FLOW_JCC) {
                jcc++;
                // self-xor before jcc is opaque
                if (strcmp(prev.mnem, "xor") == 0) {
                    const char *cm = strchr(prev.ops, ',');
                    if (cm && strncmp(prev.ops, cm + 2, (size_t)(cm - prev.ops)) == 0) opaque++;
                }
            }
            if (strcmp(ins.mnem, "pushfq") == 0 || strcmp(ins.mnem, "pushfd") == 0) pushf++;
            if (strcmp(ins.mnem, "rdtsc") == 0 || strcmp(ins.mnem, "rdtscp") == 0 ||
                strcmp(ins.mnem, "cpuid") == 0 || strcmp(ins.mnem, "int1") == 0) trick++;
            if (ins.flow == X86_FLOW_CALL && ins.has_target && ins.target == ins.ip + (uint64_t)n) trick++;
            if (strcmp(ins.mnem, "xor") == 0 || strcmp(ins.mnem, "rol") == 0 ||
                strcmp(ins.mnem, "ror") == 0 || strcmp(ins.mnem, "not") == 0) math_ops++;

            prev = ins;
            pos += (size_t)n;
        }

        const char *nm = ana_pool_str(a, f->name_off);
        if ((ind_jmp >= 2 && pushf >= 2) || ind_jmp >= 8) {
            char msg[112];
            snprintf(msg, sizeof(msg), "%d indirect jumps, %d flag saves (%d insns) — possible VM dispatcher", ind_jmp, pushf, nins);
            tri_spot_add(r, f->start, "VM_DISPATCH", nm, msg, 75 + ind_jmp * 4 + pushf * 5);
            r->obf_score += 24;
        } else if (opaque >= 2) {
            char msg[112];
            snprintf(msg, sizeof(msg), "%d opaque predicate candidates detected", opaque);
            tri_spot_add(r, f->start, "OPAQUE", nm, msg, 70);
            r->obf_score += 16;
        } else if (trick >= 2) {
            char msg[112];
            snprintf(msg, sizeof(msg), "timing/anti-debug/call-pop trick (%d hits)", trick);
            tri_spot_add(r, f->start, "ANTI_RE", nm, msg, 64);
            r->obf_score += 10;
        } else if (jcc >= 35 && nins >= 120) {
            char msg[112];
            snprintf(msg, sizeof(msg), "%d branches in %d insns — large switch or flattened CFG", jcc, nins);
            tri_spot_add(r, f->start, "COMPLEX_CFG", nm, msg, 50 + (jcc > 60 ? 20 : jcc / 3));
        } else if (math_ops >= 32 && nins <= 120) {
            char msg[112];
            snprintf(msg, sizeof(msg), "%d bitwise/rotate ops — crypto routine or MBA math", math_ops);
            tri_spot_add(r, f->start, "CRYPTO_MBA", nm, msg, 56);
        }
    }
}

void tri_analyze(const ana_ctx *a, tri_report *r) {
    memset(r, 0, sizeof(*r));
    if (!a || a->bin.nsec == 0) return;

    tri_detect_signatures(a, r);
    tri_classify_imports(a, r);
    tri_scan_obfuscation(a, r);

    if (r->pack_score > 100) r->pack_score = 100;
    if (r->obf_score > 100) r->obf_score = 100;

    if (r->nspot > 1) qsort(r->spots, (size_t)r->nspot, sizeof(tri_spot), tri_spot_cmp);

    if (r->pack_score >= 55) snprintf(r->verdict, sizeof(r->verdict), "Heavily Packed / Protected");
    else if (r->pack_score >= 25 || r->obf_score >= 45) snprintf(r->verdict, sizeof(r->verdict), "Moderately Obfuscated / Packed");
    else snprintf(r->verdict, sizeof(r->verdict), "Standard Unpacked Binary");

    if (r->nnote == 0) {
        tri_note(r, "Sections, imports, and entry point look normal — start at _start or inspect Functions.");
    }
}
