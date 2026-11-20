#include "cli.h"
#include "../ana/ana.h"
#include "../dbg/dbg.h"
#include "../ext/ext.h"
#include "../opt/opt.h"
#include "../scan/scan.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void cli_log_cb(void *ud, const char *msg) {
    (void)ud;
    printf("%s\n", msg);
}

static uint64_t cli_parse_u64(const char *s) {
    if (!s) return 0;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) return strtoull(s + 2, NULL, 16);
    return strtoull(s, NULL, 16);
}

static double cli_ms(void) {
    static LARGE_INTEGER f;
    if (!f.QuadPart) QueryPerformanceFrequency(&f);
    LARGE_INTEGER t;
    QueryPerformanceCounter(&t);
    return (double)t.QuadPart * 1000.0 / (double)f.QuadPart;
}

static int cli_test_scan(void) {
    uint8_t buf[4097];
    for (size_t i = 0; i < sizeof(buf); i++) buf[i] = (uint8_t)((i * 73 + 19) & 0xFF);
    buf[0] = 0xE8;
    buf[15] = 0xE8;
    buf[16] = 0xE8;
    buf[17] = 0xE8;
    buf[4090] = 0xE8;
    buf[4095] = 0xE8;

    size_t lens[] = {0, 1, 7, 15, 16, 17, 31, 32, 33, 4097};
    for (size_t li = 0; li < sizeof(lens) / sizeof(lens[0]); li++) {
        size_t n = lens[li];
        size_t got = scan_byte_x64(buf, n, 0xAB);
        size_t ref = n;
        for (size_t i = 0; i < n; i++) {
            if (buf[i] == 0xAB) { ref = i; break; }
        }
        if (got != ref) { printf("FAIL scan_byte len=%zu got=%zu ref=%zu\n", n, got, ref); return 1; }
    }

    uint32_t out[4096];
    size_t nc = scan_calls_x64(buf, sizeof(buf), out, 4096);
    size_t ref_c = 0;
    for (size_t i = 0; i + 5 <= sizeof(buf); i++) {
        if (buf[i] == 0xE8) {
            if (ref_c >= nc || out[ref_c] != (uint32_t)i) {
                printf("FAIL scan_calls mismatch at %zu\n", i);
                return 1;
            }
            ref_c++;
        }
    }
    if (nc != ref_c) { printf("FAIL scan_calls count %zu != %zu\n", nc, ref_c); return 1; }

    uint8_t sbuf[128];
    memset(sbuf, 0, sizeof(sbuf));
    memcpy(sbuf + 19, "Hello_XDis_1234567890!", 22);
    size_t p = scan_ascii_next_x64(sbuf, sizeof(sbuf), 0);
    if (p != 19) { printf("FAIL scan_ascii_next got=%zu\n", p); return 1; }
    size_t r = scan_ascii_run_x64(sbuf + p, sizeof(sbuf) - p);
    if (r != 22) { printf("FAIL scan_ascii_run got=%zu\n", r); return 1; }

    scan_pat pat;
    if (!scan_pat_parse(&pat, "48 89 ?? 24 08")) { printf("FAIL pat parse\n"); return 1; }
    uint8_t pbuf[64] = {0};
    pbuf[21] = 0x48; pbuf[22] = 0x89; pbuf[23] = 0x5C; pbuf[24] = 0x24; pbuf[25] = 0x08;
    if (scan_pat_find(pbuf, sizeof(pbuf), 0, &pat) != 21) { printf("FAIL pat find\n"); return 1; }
    return 0;
}

static int cli_test_x86(void) {
    struct { const uint8_t b[16]; size_t n; uint64_t ip; int bits; const char *m; int flow; uint64_t tgt; } cases[] = {
        { {0x48,0x89,0x5C,0x24,0x08}, 5, 0x1000, 64, "mov", X86_FLOW_NONE, 0 },
        { {0x48,0x8D,0x05,0x10,0x00,0x00,0x00}, 7, 0x1000, 64, "lea", X86_FLOW_NONE, 0x1017 },
        { {0xE8,0xFB,0x00,0x00,0x00}, 5, 0x1000, 64, "call", X86_FLOW_CALL, 0x1100 },
        { {0x0F,0x84,0x20,0x00,0x00,0x00}, 6, 0x1000, 64, "je", X86_FLOW_JCC, 0x1026 },
        { {0xFF,0x15,0x00,0x20,0x00,0x00}, 6, 0x1000, 64, "call", X86_FLOW_CALL, 0x3006 },
        { {0xC3}, 1, 0x1000, 64, "ret", X86_FLOW_RET, 0 },
        { {0xF3,0x0F,0x1E,0xFA}, 4, 0x1000, 64, "endbr64", X86_FLOW_NONE, 0 },
        { {0x80,0x3D,0x10,0x00,0x00,0x00,0x01}, 7, 0x1000, 64, "cmp", X86_FLOW_NONE, 0x1017 },
        { {0x48,0xB8,0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11}, 10, 0x1000, 64, "movabs", X86_FLOW_NONE, 0 },
        { {0xC5,0xF8,0x77}, 3, 0x1000, 64, "vzeroupper", X86_FLOW_NONE, 0 },
        { {0x66,0x0F,0xEF,0xC0}, 4, 0x1000, 64, "pxor", X86_FLOW_NONE, 0 },
        { {0x0F,0x1F,0x44,0x00,0x00}, 5, 0x1000, 64, "nop", X86_FLOW_NONE, 0 },
        { {0xD9,0xEE}, 2, 0x1000, 64, "fldz", X86_FLOW_NONE, 0 },
        { {0x66,0x0F,0x38,0xDC,0xC1}, 5, 0x1000, 64, "aesenc", X86_FLOW_NONE, 0 },
        { {0x0F,0x20,0xC0}, 3, 0x1000, 64, "mov", X86_FLOW_NONE, 0 },
        { {0xF1}, 1, 0x1000, 64, "int1", X86_FLOW_TRAP, 0 },
        { {0x62,0xF1,0x7C,0x48,0x28,0xC1}, 6, 0x1000, 64, "vmovaps", X86_FLOW_NONE, 0 },
        { {0x3D,0x11,0x11,0x00,0x00}, 5, 0x1000, 64, "cmp", X86_FLOW_NONE, 0 },
        { {0x3C,0x41}, 2, 0x1000, 64, "cmp", X86_FLOW_NONE, 0 }
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        x86_ins ins;
        int len = x86_decode(cases[i].b, cases[i].n, cases[i].ip, cases[i].bits, 1, 0, &ins);
        if (len != (int)cases[i].n || strcmp(ins.mnem, cases[i].m) != 0 || ins.flow != cases[i].flow) {
            printf("FAIL x86 case %zu: len=%d/%zu mnem=%s/%s flow=%d/%d\n",
                   i, len, cases[i].n, ins.mnem, cases[i].m, ins.flow, cases[i].flow);
            return 1;
        }
        if (cases[i].tgt && (!ins.has_target || ins.target != cases[i].tgt)) {
            printf("FAIL x86 case %zu target=0x%llx want=0x%llx\n",
                   i, (unsigned long long)ins.target, (unsigned long long)cases[i].tgt);
            return 1;
        }
    }

    const uint8_t a64_code[12] = {
        0x1F,0x20,0x03,0xD5,
        0x04,0x00,0x00,0x94,
        0xC0,0x03,0x5F,0xD6
    };
    x86_ins ai;
    if (arch_decode(BIN_ARCH_ARM64, a64_code, 12, 0x4000, 1, 0, &ai) != 4 || strcmp(ai.mnem, "nop") != 0) {
        printf("FAIL arm64 nop\n"); return 1;
    }
    if (arch_decode(BIN_ARCH_ARM64, a64_code + 4, 8, 0x4004, 1, 0, &ai) != 4 ||
        strcmp(ai.mnem, "bl") != 0 || ai.target != 0x4014) {
        printf("FAIL arm64 bl\n"); return 1;
    }
    if (arch_decode(BIN_ARCH_ARM64, a64_code + 8, 4, 0x4008, 1, 0, &ai) != 4 ||
        strcmp(ai.mnem, "ret") != 0 || ai.flow != X86_FLOW_RET) {
        printf("FAIL arm64 ret\n"); return 1;
    }
    return 0;
}

static int cli_test_deobf_emu(void) {
    uint8_t obf[] = {
        0x90,
        0x31, 0xC0,
        0x74, 0x02,
        0x90, 0x90,
        0xC7, 0x44, 0x24, 0x20, 'X', 'D', 'I', 'S',
        0xB8, 0x10, 0x00, 0x00, 0x00,
        0x83, 0xF0, 0x05,
        0xC3
    };
    ana_ctx a;
    ana_init(&a);
    ana_open_buf(&a, obf, sizeof(obf), "obf.bin", 0x100000, 64);
    ana_run(&a, 1, 4, 16);

    dob_res *d = (dob_res *)calloc(1, sizeof(dob_res));
    emu_out *e = (emu_out *)calloc(1, sizeof(emu_out));
    int ok = dob_analyze(&a, 0x100000, 0, d) &&
             d->junk_cut >= 3 && d->opaque_cut >= 1 && d->const_folded >= 2 &&
             d->nstr == 1 && strcmp(d->strs[0].text, "XDIS") == 0 &&
             emu_trace(&a, 0x100000, 32, e) &&
             e->regs[0] == 0x15 && strstr(e->stack_ascii, "XDIS") != NULL;
    free(d);
    free(e);
    ana_free(&a);
    if (!ok) { printf("FAIL deobf/emu\n"); return 1; }
    return 0;
}

static int cli_test_cfg_and_db(void) {
    uint8_t code[] = {
        0x48, 0x85, 0xC9,
        0x74, 0x07,
        0xB8, 0x01, 0x00, 0x00, 0x00,
        0xEB, 0x05,
        0xB8, 0x02, 0x00, 0x00, 0x00,
        0xC3
    };

    ana_ctx a;
    ana_init(&a);
    if (!ana_open_buf(&a, code, sizeof(code), "test.bin", 0x100000, 64)) {
        printf("FAIL ana_open_buf\n");
        return 1;
    }
    ana_run(&a, 1, 4, 16);

    grp_cfg g = {0};
    if (!grp_build(&a, 0x100000, 0, &g) || g.nblk != 4 || g.nedge != 4) {
        printf("FAIL grp_build blks=%u edges=%u\n", g.nblk, g.nedge);
        grp_free(&g);
        ana_free(&a);
        return 1;
    }
    grp_layout(&g, 8, 18);
    if (g.total_w <= 0 || g.total_h <= 0) { printf("FAIL grp_layout\n"); return 1; }
    grp_free(&g);

    dec_out dec = {0};
    if (!dec_func(&a, 0x100000, &dec) || dec.nline < 4) {
        printf("FAIL dec_func lines=%u\n", dec.nline);
        dec_free(&dec);
        ana_free(&a);
        return 1;
    }
    dec_free(&dec);

    ana_set_name(&a, 0x100000, "diamond_fn");
    ana_set_cmt(&a, 0x100003, "branch check");
    ana_add_mark(&a, 0x10000C, "else_arm");
    ana_set_lvar(&a, 0x100000, "a1", "flag", "uint32_t");
    ana_patch_byte(&a, 0x100006, 0x09);

    const char *tmp = "xdis_test.xdb";
    if (!db_save(&a, tmp)) { printf("FAIL db_save\n"); return 1; }
    if (!ana_unpatch_byte(&a, 0x100006) || code[6] != 0x01) { printf("FAIL unpatch\n"); return 1; }
    ana_free(&a);

    ana_init(&a);
    code[6] = 0x01;
    ana_open_buf(&a, code, sizeof(code), "test.bin", 0x100000, 64);
    if (!db_load(&a, tmp)) { printf("FAIL db_load\n"); return 1; }
    DeleteFileA(tmp);

    const char *nm = ana_sym_at(&a, 0x100000);
    const char *cm = ana_cmt_at(&a, 0x100003);
    if (!nm || strcmp(nm, "diamond_fn") != 0 || !cm || strcmp(cm, "branch check") != 0 ||
        a.nmark != 1 || a.nlvar != 1 || code[6] != 0x09) {
        printf("FAIL db roundtrip\n");
        ana_free(&a);
        return 1;
    }
    dec_out dec2 = {0};
    if (!dec_func(&a, 0x100000, &dec2) || !strstr(dec2.lines[0].text, "uint32_t flag")) {
        printf("FAIL lvar apply\n");
        dec_free(&dec2);
        ana_free(&a);
        return 1;
    }
    dec_free(&dec2);
    ana_free(&a);
    return 0;
}

static int cli_test_elf(void) {
    uint8_t elf[256];
    memset(elf, 0, sizeof(elf));
    memcpy(elf, "\x7f" "ELF", 4);
    elf[4] = 2; elf[5] = 1; elf[6] = 1;
    uint64_t entry = 0x401000, phoff = 64;
    uint16_t phent = 56, phnum = 1;
    memcpy(elf + 24, &entry, 8);
    memcpy(elf + 32, &phoff, 8);
    memcpy(elf + 54, &phent, 2);
    memcpy(elf + 56, &phnum, 2);

    uint32_t ptype = 1, pflg = 5;
    uint64_t pfoff = 128, pvaddr = 0x401000, pfsz = 64, pmsz = 64;
    memcpy(elf + 64, &ptype, 4);
    memcpy(elf + 68, &pflg, 4);
    memcpy(elf + 72, &pfoff, 8);
    memcpy(elf + 80, &pvaddr, 8);
    memcpy(elf + 96, &pfsz, 8);
    memcpy(elf + 104, &pmsz, 8);
    elf[128] = 0x55; elf[129] = 0x48; elf[130] = 0x89; elf[131] = 0xE5; elf[132] = 0xC3;

    bin_img b;
    if (!bin_open_buf(&b, elf, sizeof(elf), "mini.elf", 0, 64)) {
        printf("FAIL elf load\n");
        return 1;
    }
    int ok = (b.fmt == BIN_ELF64 && b.entry == 0x401000 && b.nsec == 1);
    bin_close(&b);
    if (!ok) { printf("FAIL elf fields\n"); return 1; }
    return 0;
}

static int cli_test_pro(void) {
    char d[128];
    if (!dem_name("_ZN3Foo3barEi", d, sizeof(d)) || !strstr(d, "Foo::bar")) {
        printf("FAIL demangle itanium: %s\n", d); return 1;
    }
    if (!dem_name("?bar@Foo@@QEAAHXZ", d, sizeof(d)) || !strstr(d, "Foo::bar")) {
        printf("FAIL demangle msvc: %s\n", d); return 1;
    }

    uint8_t ab[16];
    x86_ins ins;
    int n = asm_encode("mov eax, 1", 0x1000, 64, ab);
    if (n <= 0 || x86_decode(ab, (size_t)n, 0x1000, 64, 1, 0, &ins) != n || strcmp(ins.mnem, "mov") != 0) {
        printf("FAIL asm mov eax, 1 (n=%d)\n", n); return 1;
    }
    n = asm_encode("xor eax, eax", 0x1000, 64, ab);
    if (n <= 0 || x86_decode(ab, (size_t)n, 0x1000, 64, 1, 0, &ins) != n || strcmp(ins.mnem, "xor") != 0) {
        printf("FAIL asm xor\n"); return 1;
    }
    n = asm_encode("call 0x1020", 0x1000, 64, ab);
    if (n <= 0 || x86_decode(ab, (size_t)n, 0x1000, 64, 1, 0, &ins) != n || ins.target != 0x1020) {
        printf("FAIL asm call target\n"); return 1;
    }

    // minimal Mach-O 64 header + LC_SEGMENT_64 (__TEXT) + LC_MAIN
    uint8_t mo[256];
    memset(mo, 0, sizeof(mo));
    uint32_t m_magic = 0xFEEDFACFu, m_cpu = 0x01000007u, m_ncmds = 2, m_szcmds = 72 + 24;
    memcpy(mo + 0, &m_magic, 4);
    memcpy(mo + 4, &m_cpu, 4);
    memcpy(mo + 16, &m_ncmds, 4);
    memcpy(mo + 20, &m_szcmds, 4);
    uint32_t lc_seg = 0x19u, lc_segsz = 72u, initprot = 5u;
    uint64_t vmaddr = 0x100000000ULL, vmsz = 128, foff = 128, fsz = 128;
    memcpy(mo + 32, &lc_seg, 4);
    memcpy(mo + 36, &lc_segsz, 4);
    memcpy(mo + 40, "__TEXT", 6);
    memcpy(mo + 56, &vmaddr, 8);
    memcpy(mo + 64, &vmsz, 8);
    memcpy(mo + 72, &foff, 8);
    memcpy(mo + 80, &fsz, 8);
    memcpy(mo + 92, &initprot, 4);
    uint32_t lc_main = 0x80000028u, lc_msz = 24u;
    uint64_t ep_off = 128;
    memcpy(mo + 104, &lc_main, 4);
    memcpy(mo + 108, &lc_msz, 4);
    memcpy(mo + 112, &ep_off, 8);
    mo[128] = 0xC3;
    bin_img mb;
    if (!bin_open_buf(&mb, mo, sizeof(mo), "mini.macho", 0, 64) || mb.fmt != BIN_MACHO64) {
        printf("FAIL macho64 load\n"); return 1;
    }
    bin_close(&mb);

    // call chain A(0x100000) -> B(0x100020) -> C(0x100040) + struct accesses + AES S-Box
    uint8_t chain[160];
    memset(chain, 0x90, sizeof(chain));
    // A: mov eax,[rcx+8]; mov edx,[rcx+16]; call B; ret
    uint8_t fnA[] = { 0x8B,0x41,0x08, 0x8B,0x51,0x10, 0xE8,0x15,0x00,0x00,0x00, 0xC3 };
    memcpy(chain + 0x00, fnA, sizeof(fnA));
    // B: call C; ret
    uint8_t fnB[] = { 0xE8,0x1B,0x00,0x00,0x00, 0xC3 };
    memcpy(chain + 0x20, fnB, sizeof(fnB));
    // C: mov eax, 42; ret
    uint8_t fnC[] = { 0xB8,0x2A,0x00,0x00,0x00, 0xC3 };
    memcpy(chain + 0x40, fnC, sizeof(fnC));
    // AES S-box prefix at +0x60
    const uint8_t aes_sb[16] = { 0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76 };
    memcpy(chain + 0x60, aes_sb, 16);

    ana_ctx a1, a2;
    ana_init(&a1); ana_init(&a2);
    ana_open_buf(&a1, chain, sizeof(chain), "chain1.bin", 0x100000, 64);
    ana_run(&a1, 1, 4, 16);

    ir_func *irf = (ir_func *)calloc(1, sizeof(ir_func));
    int ir_ok = irf && ir_lift_func(&a1, 0x100000, irf) && irf->nop > 0 && irf->nstruct >= 1;
    free(irf);
    if (!ir_ok) { printf("FAIL ir_lift_func\n"); ana_free(&a1); return 1; }

    sig_crypto cr[8];
    if (sig_find_crypto(&a1, cr, 8) < 1) { printf("FAIL sig_find_crypto\n"); ana_free(&a1); return 1; }

    pth_chain ch = {0};
    if (!pth_find(&a1, 0x100000, 0x100040, &ch) || ch.len != 3) {
        printf("FAIL pth_find len=%d\n", ch.len); ana_free(&a1); return 1;
    }
    pth_xgraph *xg = (pth_xgraph *)calloc(1, sizeof(pth_xgraph));
    int xg_ok = xg && pth_xgraph_build(&a1, 0x100020, 1, xg) && xg->nnode >= 2;
    free(xg);
    if (!xg_ok) { printf("FAIL pth_xgraph\n"); ana_free(&a1); return 1; }

    chain[0x41] = 0x99;
    ana_open_buf(&a2, chain, sizeof(chain), "chain2.bin", 0x100000, 64);
    ana_run(&a2, 1, 4, 16);
    dif_res dr = {0};
    int dif_ok = dif_compare(&a1, &a2, &dr) && dr.nitem >= 1;
    dif_free(&dr);
    ana_free(&a2);
    ana_free(&a1);
    if (!dif_ok) { printf("FAIL dif_compare\n"); return 1; }

    typ_store ts;
    typ_init(&ts);
    int tok = typ_parse_c(&ts, "struct Packet { uint32_t magic; uint64_t len; };") &&
              typ_sizeof(&ts, "Packet") == 16;
    typ_free(&ts);
    if (!tok) { printf("FAIL typ_parse_c/sizeof\n"); return 1; }

    return 0;
}

static int cli_test_wave_a(void) {
    // 1. AVX2 vs SSE2 byte & call scan parity
    if (scan_has_avx2()) {
        uint8_t buf[4097];
        for (size_t i = 0; i < sizeof(buf); i++) buf[i] = (uint8_t)((i * 37 + 11) & 0xFF);
        buf[0] = 0xE8; buf[31] = 0xE8; buf[32] = 0xE8; buf[33] = 0xE8; buf[4091] = 0xE8;
        size_t lens[] = {0, 1, 15, 16, 31, 32, 33, 63, 64, 65, 4097};
        for (size_t li = 0; li < sizeof(lens) / sizeof(lens[0]); li++) {
            size_t n = lens[li];
            if (scan_byte_avx2(buf, n, 0xAB) != scan_byte_x64(buf, n, 0xAB)) {
                printf("FAIL avx2 byte parity len=%zu\n", n); return 1;
            }
        }
        uint32_t o1[4096], o2[4096];
        size_t c1 = scan_calls_x64(buf, sizeof(buf), o1, 4096);
        size_t c2 = scan_calls_avx2(buf, sizeof(buf), o2, 4096);
        if (c1 != c2 || memcmp(o1, o2, c1 * sizeof(uint32_t)) != 0) {
            printf("FAIL avx2 calls parity %zu != %zu\n", c1, c2); return 1;
        }
    }

    // 2. Diamond CFG -> SSA Phi + SCCP + Undo/Redo + XDB v3 Snapshots
    uint8_t dia[] = {
        0x48, 0x85, 0xC9,                   // test rcx, rcx
        0x74, 0x07,                         // je +7
        0xB8, 0x01, 0x00, 0x00, 0x00,       // mov eax, 1
        0xEB, 0x05,                         // jmp +5
        0xB8, 0x02, 0x00, 0x00, 0x00,       // mov eax, 2
        0x83, 0xC0, 0x0A,                   // add eax, 10
        0xC3                                // ret
    };
    ana_ctx a;
    ana_init(&a);
    ana_open_buf(&a, dia, sizeof(dia), "wavea.bin", 0x100000, 64);
    ana_run(&a, 1, 4, 16);

    ssa_func sf = {0};
    if (!ssa_build(&a, 0x100000, &sf) || sf.nblk != 4 || sf.nllir == 0 || sf.nmlir == 0 || sf.nphi < 1 || !sf.proto[0]) {
        printf("FAIL ssa_build nblk=%u nllir=%u nmlir=%u nphi=%d\n", sf.nblk, sf.nllir, sf.nmlir, sf.nphi);
        ssa_free(&sf); ana_free(&a); return 1;
    }
    ssa_free(&sf);

    // Undo/Redo test on rename, comment, patch
    ana_set_name(&a, 0x100000, "fn_v1");
    ana_set_cmt(&a, 0x100003, "check zero");
    ana_patch_byte(&a, 0x100006, 0x77);
    if (ana_undo_count(&a) < 3 || dia[6] != 0x77) { printf("FAIL hist record\n"); ana_free(&a); return 1; }
    if (!ana_undo(&a) || dia[6] != 0x01) { printf("FAIL undo patch\n"); ana_free(&a); return 1; }
    if (!ana_undo(&a) || ana_cmt_at(&a, 0x100003) != NULL) { printf("FAIL undo cmt\n"); ana_free(&a); return 1; }
    if (!ana_redo(&a) || !ana_cmt_at(&a, 0x100003)) { printf("FAIL redo cmt\n"); ana_free(&a); return 1; }
    if (!ana_redo(&a) || dia[6] != 0x77) { printf("FAIL redo patch\n"); ana_free(&a); return 1; }

    // XDB v3 Snapshot save/list/restore
    const char *sdb = "xdis_wavea.xdb";
    if (!db_snap_save(&a, sdb, "snap_a")) { printf("FAIL snap_save a\n"); ana_free(&a); return 1; }
    ana_set_name(&a, 0x100000, "fn_v2");
    ana_patch_byte(&a, 0x100006, 0x99);
    if (!db_snap_save(&a, sdb, "snap_b")) { printf("FAIL snap_save b\n"); DeleteFileA(sdb); ana_free(&a); return 1; }
    db_snap_meta ms[8];
    int nsn = db_snap_list(sdb, ms, 8);
    if (nsn != 2) { printf("FAIL snap_list n=%d\n", nsn); DeleteFileA(sdb); ana_free(&a); return 1; }
    if (!db_snap_restore(&a, sdb, "snap_a") || dia[6] != 0x77 || strcmp(ana_sym_at(&a, 0x100000), "fn_v1") != 0) {
        printf("FAIL snap_restore\n"); DeleteFileA(sdb); ana_free(&a); return 1;
    }
    DeleteFileA(sdb);
    ana_free(&a);

    // 3. ARM64 decompiler test (add x0, x0, x1; ret)
    uint8_t a64_fn[] = { 0x00, 0x00, 0x01, 0x8B, 0xC0, 0x03, 0x5F, 0xD6 };
    ana_ctx aa;
    ana_init(&aa);
    ana_open_buf(&aa, a64_fn, sizeof(a64_fn), "a64.bin", 0x400000, 64);
    aa.bin.arch = BIN_ARCH_ARM64;
    ana_run(&aa, 1, 4, 16);
    dec_out ad = {0};
    int a64_ok = dec_func(&aa, 0x400000, &ad) && ad.nline >= 3;
    dec_free(&ad);
    ana_free(&aa);
    if (!a64_ok) { printf("FAIL arm64 decompile\n"); return 1; }

    return 0;
}

static uint32_t cli_fnv1a(const char *s) {
    uint32_t h = 0x811C9DC5u;
    for (; *s; s++) { h ^= (uint8_t)*s; h *= 0x01000193u; }
    return h;
}

static int cli_test_wave_b(void) {
    // 1. MBA expression simplifier
    char out[96];
    int saved = 0;
    if (!mba_simplify_expr("(x ^ y) + 2 * (x & y)", out, sizeof(out), &saved) ||
        (strcmp(out, "x + y") != 0 && strcmp(out, "y + x") != 0)) {
        printf("FAIL mba add: got '%s'\n", out); return 1;
    }
    if (!mba_simplify_expr("(x | y) - (x & y)", out, sizeof(out), &saved) ||
        (strcmp(out, "x ^ y") != 0 && strcmp(out, "y ^ x") != 0)) {
        printf("FAIL mba xor: got '%s'\n", out); return 1;
    }
    if (!mba_simplify_expr("~(~x | ~y)", out, sizeof(out), &saved) ||
        (strcmp(out, "x & y") != 0 && strcmp(out, "y & x") != 0)) {
        printf("FAIL mba and: got '%s'\n", out); return 1;
    }

    // 2. Synthetic CFF flattened 3-state loop
    // 0x00: mov eax, 0x1111 (5)
    // 0x05 (disp): cmp eax, 0x1111 (5); je +0x11 (2 -> 0x1D)
    // 0x0C: cmp eax, 0x2222 (5); je +0x13 (2 -> 0x26)
    // 0x13: cmp eax, 0x3333 (5); je +0x15 (2 -> 0x2F)
    // 0x1A: xor eax, eax (2); ret (1)
    // 0x1D (B1): inc ecx (2); mov eax, 0x2222 (5); jmp -0x21 (2 -> 0x05)
    // 0x26 (B2): add ecx, 5 (3); mov eax, 0x3333 (5); jmp -0x2B (2 -> 0x05)
    // 0x30 (B3): mov eax, ecx (2); ret (1)
    uint8_t cff_code[] = {
        0xB8, 0x11, 0x11, 0x00, 0x00,
        0x3D, 0x11, 0x11, 0x00, 0x00, 0x74, 0x11,
        0x3D, 0x22, 0x22, 0x00, 0x00, 0x74, 0x13,
        0x3D, 0x33, 0x33, 0x00, 0x00, 0x74, 0x16,
        0x31, 0xC0, 0xC3,
        0xFF, 0xC1, 0xB8, 0x22, 0x22, 0x00, 0x00, 0xEB, 0xDF,
        0x83, 0xC1, 0x05, 0xB8, 0x33, 0x33, 0x00, 0x00, 0xEB, 0xD5,
        0x89, 0xC8, 0xC3
    };
    ana_ctx ca;
    ana_init(&ca);
    ana_open_buf(&ca, cff_code, sizeof(cff_code), "cff.bin", 0x100000, 64);
    ana_run(&ca, 1, 4, 16);
    cff_res *cr = (cff_res *)calloc(1, sizeof(cff_res));
    int cff_ok = cr && cff_analyze(&ca, 0x100000, cr) && cr->detected && cr->nedge >= 2;
    free(cr);
    ana_free(&ca);
    if (!cff_ok) { printf("FAIL cff_analyze\n"); return 1; }

    // 3. API hash resolver (FNV-1a of VirtualAlloc in mov ecx, imm32) + XOR string decryptor
    uint32_t h_va = cli_fnv1a("VirtualAlloc");
    uint8_t ubuf[128];
    memset(ubuf, 0x90, sizeof(ubuf));
    ubuf[0] = 0xB9; // mov ecx, h_va
    memcpy(ubuf + 1, &h_va, 4);
    // XOR loop over 0x100040 (len 12, key 0x5A): lea rdi,[rip+0x34]; xor ecx,ecx; L: xor byte ptr [rdi+rcx],0x5A; inc rcx; cmp rcx,12; jb L; ret
    uint8_t dec_loop[] = {
        0x48, 0x8D, 0x3D, 0x34, 0x00, 0x00, 0x00,
        0x31, 0xC9,
        0x80, 0x34, 0x0F, 0x5A,
        0x48, 0xFF, 0xC1,
        0x48, 0x83, 0xF9, 0x0C,
        0x72, 0xF3,
        0xC3
    };
    memcpy(ubuf + 5, dec_loop, sizeof(dec_loop));
    const char *secret = "XDIS_DECRYPT";
    for (int i = 0; i < 12; i++) ubuf[0x40 + i] = (uint8_t)(secret[i] ^ 0x5A);
    ubuf[0x4C] = 0;

    ana_ctx ua;
    ana_init(&ua);
    ana_open_buf(&ua, ubuf, sizeof(ubuf), "unp.bin", 0x100000, 64);
    ana_run(&ua, 1, 4, 16);
    unp_hash_res *hr = (unp_hash_res *)calloc(1, sizeof(unp_hash_res));
    int h_found = hr ? unp_resolve_hashes(&ua, 0, hr) : 0;
    int h_ok = 0;
    for (int i = 0; hr && i < hr->nhit; i++) {
        if (strcmp(hr->hits[i].api, "VirtualAlloc") == 0) h_ok = 1;
    }
    free(hr);
    unp_str_res *sr = (unp_str_res *)calloc(1, sizeof(unp_str_res));
    int s_found = sr ? unp_decrypt_strings(&ua, 0x100000, 0, sr) : 0;
    int s_ok = 0;
    for (int i = 0; sr && i < sr->nhit; i++) {
        if (strstr(sr->hits[i].text, "XDIS_DECRYPT")) s_ok = 1;
    }
    free(sr);
    ana_free(&ua);
    if (!h_found || !h_ok) { printf("FAIL unp_resolve_hashes\n"); return 1; }
    if (!s_found || !s_ok) { printf("FAIL unp_decrypt_strings\n"); return 1; }

    return 0;
}

static int cli_test_wave_c(void) {
    // 1. Taint propagation + symbolic path solver on branching function:
    // 0x00: mov rax, rcx (3) -> rax tainted from rcx
    // 0x03: add rax, 5 (4) -> rax still tainted
    // 0x07: cmp eax, 0x2a (3) -> tainted branch!
    // 0x0A: jne +5 (2 -> 0x11)
    // 0x0C: mov eax, 1 (5) [target 0x10000C]
    // 0x11: ret (1)
    uint8_t tc[] = {
        0x48, 0x89, 0xC8,
        0x48, 0x83, 0xC0, 0x05,
        0x83, 0xF8, 0x2A,
        0x75, 0x05,
        0xB8, 0x01, 0x00, 0x00, 0x00,
        0xC3
    };
    ana_ctx a;
    ana_init(&a);
    ana_open_buf(&a, tc, sizeof(tc), "taint.bin", 0x100000, 64);
    ana_run(&a, 1, 4, 16);

    tnt_res *tr = (tnt_res *)calloc(1, sizeof(tnt_res));
    int tok = tr && tnt_run(&a, 0x100000, 1, 0, 32, tr) && (tr->taint_regs & 1u) && tr->nevent >= 1;
    free(tr);
    if (!tok) { printf("FAIL tnt_run\n"); ana_free(&a); return 1; }

    tnt_solve_res *sr = (tnt_solve_res *)calloc(1, sizeof(tnt_solve_res));
    int sok = sr && tnt_solve_path(&a, 0x100000, 0x10000C, sr) && sr->reachable && sr->ncons >= 1;
    free(sr);
    ana_free(&a);
    if (!sok) { printf("FAIL tnt_solve_path\n"); return 1; }

    // 2. Minimal synthetic Windows MDMP (SystemInfo + Exception + MemoryList)
    uint8_t dmp[512];
    memset(dmp, 0, sizeof(dmp));
    memcpy(dmp, "MDMP", 4);
    uint16_t ver = 0xA793; memcpy(dmp + 4, &ver, 2);
    uint32_t nstr = 3, dir_rva = 32;
    memcpy(dmp + 8, &nstr, 4);
    memcpy(dmp + 12, &dir_rva, 4);
    // Dir[0]: SystemInfoStream (7), size 56, rva 80
    uint32_t d0[3] = {7, 56, 80}; memcpy(dmp + 32, d0, 12);
    uint16_t arch = 9; memcpy(dmp + 80, &arch, 2); dmp[86] = 8;
    uint32_t os_maj = 10, os_bld = 26100; memcpy(dmp + 88, &os_maj, 4); memcpy(dmp + 96, &os_bld, 4);
    // Dir[1]: ExceptionStream (6), size 168, rva 144
    uint32_t d1[3] = {6, 168, 144}; memcpy(dmp + 44, d1, 12);
    uint32_t etid = 4242, ecode = 0xC0000005u; uint64_t eaddr = 0x140001234ULL;
    memcpy(dmp + 144, &etid, 4); memcpy(dmp + 152, &ecode, 4); memcpy(dmp + 168, &eaddr, 8);
    // Dir[2]: MemoryListStream (5), size 20, rva 320 -> 1 range @ 0x140001234 len 8 at file off 352
    uint32_t d2[3] = {5, 20, 320}; memcpy(dmp + 56, d2, 12);
    uint32_t nm = 1; memcpy(dmp + 320, &nm, 4);
    memcpy(dmp + 324, &eaddr, 8);
    uint32_t msz = 8, mrva = 352; memcpy(dmp + 332, &msz, 4); memcpy(dmp + 336, &mrva, 4);
    memcpy(dmp + 352, "XDISDMP!", 8);

    const char *df = "xdis_test.dmp";
    FILE *fp = fopen(df, "wb");
    if (!fp) return 1;
    fwrite(dmp, 1, sizeof(dmp), fp);
    fclose(fp);

    dmp_ctx mc;
    dmp_init(&mc);
    uint8_t mb[8] = {0};
    int dok = dmp_open(&mc, df) && mc.loaded && mc.exc_code == 0xC0000005u && mc.exc_addr == eaddr &&
              dmp_read_mem(&mc, eaddr, mb, 8) == 8 && memcmp(mb, "XDISDMP!", 8) == 0;
    dmp_close(&mc);
    DeleteFileA(df);
    if (!dok) { printf("FAIL dmp_open/read\n"); return 1; }
    return 0;
}

static int cli_test_wave_d(void) {
    x86_ins ins;
    // 1. ARM32: bx lr (0xE12FFF1E), add r0, r1, r2 (0xE0810002)
    uint8_t arm32_b[8] = { 0x1E,0xFF,0x2F,0xE1, 0x02,0x00,0x81,0xE0 };
    if (arch_decode(BIN_ARCH_ARM32, arm32_b, 8, 0x1000, 1, 0, &ins) != 4 || ins.flow != X86_FLOW_RET) {
        printf("FAIL arm32 bx lr (%s)\n", ins.mnem); return 1;
    }
    if (arch_decode(BIN_ARCH_ARM32, arm32_b + 4, 4, 0x1004, 1, 0, &ins) != 4 || strncmp(ins.mnem, "add", 3) != 0) {
        printf("FAIL arm32 add (%s)\n", ins.mnem); return 1;
    }

    // 2. RISC-V 64: addi sp, sp, -16 (0xFF010113), ret (0x00008067), c.nop (0x0001)
    uint8_t rv_b[10] = { 0x13,0x01,0x01,0xFF, 0x67,0x80,0x00,0x00, 0x01,0x00 };
    if (arch_decode(BIN_ARCH_RISCV64, rv_b, 10, 0x2000, 1, 0, &ins) != 4 || strcmp(ins.mnem, "addi") != 0) {
        printf("FAIL riscv addi (%s)\n", ins.mnem); return 1;
    }
    if (arch_decode(BIN_ARCH_RISCV64, rv_b + 4, 6, 0x2004, 1, 0, &ins) != 4 || ins.flow != X86_FLOW_RET) {
        printf("FAIL riscv ret (%s)\n", ins.mnem); return 1;
    }
    if (arch_decode(BIN_ARCH_RISCV64, rv_b + 8, 2, 0x2008, 1, 0, &ins) != 2) {
        printf("FAIL riscv rvc len\n"); return 1;
    }

    // 3. MIPS32: jr $ra (0x03E00008), addiu $sp, $sp, -16 (0x27BDFFF0)
    uint8_t mips_b[8] = { 0x08,0x00,0xE0,0x03, 0xF0,0xFF,0xBD,0x27 };
    if (arch_decode(BIN_ARCH_MIPS32, mips_b, 8, 0x3000, 1, 0, &ins) != 4 || ins.flow != X86_FLOW_RET) {
        printf("FAIL mips jr $ra (%s)\n", ins.mnem); return 1;
    }
    if (arch_decode(BIN_ARCH_MIPS32, mips_b + 4, 4, 0x3004, 1, 0, &ins) != 4 || strcmp(ins.mnem, "addiu") != 0) {
        printf("FAIL mips addiu (%s)\n", ins.mnem); return 1;
    }

    // 4. WASM + CIL bytecode decoders
    uint8_t wasm_op[4] = { 0x41, 0x2A, 0x6A, 0x0F };
    if (arch_decode(BIN_ARCH_WASM, wasm_op, 4, 0x10, 1, 0, &ins) != 2 || strcmp(ins.mnem, "i32.const") != 0) {
        printf("FAIL wasm i32.const (%s)\n", ins.mnem); return 1;
    }
    if (arch_decode(BIN_ARCH_WASM, wasm_op + 3, 1, 0x13, 1, 0, &ins) != 1 || ins.flow != X86_FLOW_RET) {
        printf("FAIL wasm return\n"); return 1;
    }
    uint8_t cil_op[3] = { 0x02, 0x58, 0x2A };
    if (arch_decode(BIN_ARCH_CIL, cil_op, 3, 0x10, 1, 0, &ins) != 1 || strcmp(ins.mnem, "ldarg.0") != 0) {
        printf("FAIL cil ldarg.0 (%s)\n", ins.mnem); return 1;
    }
    if (arch_decode(BIN_ARCH_CIL, cil_op + 2, 1, 0x12, 1, 0, &ins) != 1 || ins.flow != X86_FLOW_RET) {
        printf("FAIL cil ret\n"); return 1;
    }

    // 5. Minimal WASM module loader (export "add")
    uint8_t wasm_mod[] = {
        0x00,0x61,0x73,0x6D, 0x01,0x00,0x00,0x00,
        0x01,0x07, 0x01, 0x60,0x02,0x7F,0x7F,0x01,0x7F,
        0x03,0x02, 0x01, 0x00,
        0x07,0x07, 0x01, 0x03,'a','d','d', 0x00,0x00,
        0x0A,0x09, 0x01, 0x07, 0x00, 0x20,0x00, 0x20,0x01, 0x6A, 0x0B
    };
    bin_img wb;
    if (!bin_open_buf(&wb, wasm_mod, sizeof(wasm_mod), "mini.wasm", 0, 32) ||
        wb.fmt != BIN_WASM || wb.arch != BIN_ARCH_WASM || wb.nsym < 1) {
        printf("FAIL wasm loader fmt=%d arch=%d nsym=%u\n", wb.fmt, wb.arch, wb.nsym);
        bin_close(&wb); return 1;
    }
    bin_close(&wb);

    // 6. C Header parser (#define, #pragma pack, typedef struct) + Win32 .xtil
    typ_store ts;
    typ_init(&ts);
    chdr_res cr = {0};
    const char *hdr =
        "#define HDR_LEN 12\n"
        "#pragma pack(push, 1)\n"
        "typedef struct NetHdr {\n"
        "  uint16_t magic;\n"
        "  uint32_t seq;\n"
        "  char tag[HDR_LEN];\n"
        "} NetHdr;\n"
        "#pragma pack(pop)\n";
    int hok = chdr_parse(&ts, hdr, &cr) && typ_sizeof(&ts, "NetHdr") == 18 &&
              chdr_load_stdlib(&ts, "win32") >= 5 && typ_find(&ts, "IMAGE_DOS_HEADER") != NULL;
    typ_free(&ts);
    if (!hok) { printf("FAIL chdr_parse/stdlib\n"); return 1; }

    // 7. Auto-Sig unique pattern generator (wildcards call rel32)
    uint8_t sbuf[64];
    memset(sbuf, 0x90, sizeof(sbuf));
    uint8_t f0[] = { 0x55, 0x48, 0x89, 0xE5, 0xE8, 0x10, 0x00, 0x00, 0x00, 0xB8, 0x77, 0x00, 0x00, 0x00, 0x5D, 0xC3 };
    memcpy(sbuf + 0, f0, sizeof(f0));
    ana_ctx sa;
    ana_init(&sa);
    ana_open_buf(&sa, sbuf, sizeof(sbuf), "sig.bin", 0x100000, 64);
    ana_run(&sa, 1, 4, 16);
    chdr_sig_res sr = {0};
    int sok = chdr_make_sig(&sa, 0x100000, &sr) && sr.hits == 1 && sr.len >= 4;
    ana_free(&sa);
    if (!sok) { printf("FAIL chdr_make_sig hits=%d len=%d ida='%s'\n", sr.hits, sr.len, sr.ida); return 1; }

    return 0;
}

static int cli_test_wave_e(void) {
    // 1. Forensics buffer: x64 code + embedded ZIP + embedded PE + IOC strings
    uint8_t buf[2048];
    memset(buf, 0, sizeof(buf));
    // Function at 0x100000: mov [rsp+8], rcx; imul eax, ecx; call +0x1A (malloc @ 0x100028); call +0x25 (strcpy @ 0x100038); ret
    uint8_t code[] = {
        0x48, 0x89, 0x4C, 0x24, 0x08, // 0x00: mov [rsp+8], rcx
        0x0F, 0xAF, 0xC1,             // 0x05: imul eax, ecx
        0xE8, 0x1B, 0x00, 0x00, 0x00, // 0x08: call 0x28 (malloc)
        0xE8, 0x26, 0x00, 0x00, 0x00, // 0x0D: call 0x38 (strcpy)
        0xC3                          // 0x12: ret
    };
    memcpy(buf, code, sizeof(code));
    buf[0x28] = 0xC3;
    buf[0x38] = 0xC3;

    // IOC strings at 0x100
    const char *s1 = "https://telemetry.example.com/v1";
    const char *s2 = "198.51.100.42";
    const char *s3 = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run";
    memcpy(buf + 0x100, s1, strlen(s1) + 1);
    memcpy(buf + 0x140, s2, strlen(s2) + 1);
    memcpy(buf + 0x180, s3, strlen(s3) + 1);

    // Embedded ZIP at 0x240 (PK\x03\x04 + local header + EOCD PK\x05\x06)
    uint8_t zip_hdr[30] = { 'P','K',0x03,0x04, 0x14,0x00, 0,0, 0,0, 0,0,0,0, 0,0,0,0, 4,0,0,0, 4,0,0,0, 4,0, 0,0 };
    memcpy(buf + 0x240, zip_hdr, sizeof(zip_hdr));
    memcpy(buf + 0x240 + 30, "a.txTEST", 8);
    uint8_t zip_eocd[22] = { 'P','K',0x05,0x06, 0 };
    memcpy(buf + 0x240 + 40, zip_eocd, sizeof(zip_eocd));

    // Embedded PE at 0x300 (MZ ... e_lfanew=0x40 -> PE\0\0 + COFF)
    buf[0x300] = 'M'; buf[0x301] = 'Z';
    uint32_t lfanew = 0x40;
    memcpy(buf + 0x33C, &lfanew, 4);
    memcpy(buf + 0x340, "PE\0\0", 4);
    uint16_t mach = 0x8664;
    memcpy(buf + 0x344, &mach, 2);

    ana_ctx a;
    ana_init(&a);
    ana_open_buf(&a, buf, sizeof(buf), "wave_e.bin", 0x100000, 64);
    ana_run(&a, 1, 4, 16);
    ana_set_name(&a, 0x100028, "malloc");
    ana_set_name(&a, 0x100038, "strcpy");

    // YARA test
    const char *rules =
        "rule TestCombo {\n"
        "  meta:\n"
        "    description = \"matches code and url\"\n"
        "  strings:\n"
        "    $a = \"telemetry.example.com\" ascii\n"
        "    $b = { 48 89 ?? 24 08 }\n"
        "  condition:\n"
        "    $a and $b\n"
        "}\n"
        "rule TestMiss {\n"
        "  strings:\n"
        "    $z = \"NEVER_PRESENT_XYZ\"\n"
        "  condition:\n"
        "    $z\n"
        "}\n";
    for_yara_res *yr = (for_yara_res *)calloc(1, sizeof(for_yara_res));
    int yok = yr && for_yara_scan(&a, rules, yr) && yr->nrules == 2 && yr->nhit == 1 && strcmp(yr->hits[0].rule, "TestCombo") == 0;
    free(yr);
    if (!yok) { printf("FAIL for_yara_scan\n"); ana_free(&a); return 1; }

    // Carver test
    for_carve_res *cr = (for_carve_res *)calloc(1, sizeof(for_carve_res));
    int has_zip = 0, has_pe = 0;
    if (cr && for_carve(&a, cr) >= 2) {
        for (int i = 0; i < cr->nhit; i++) {
            if (strcmp(cr->hits[i].kind, "ZIP") == 0) has_zip = 1;
            if (strcmp(cr->hits[i].kind, "PE") == 0) has_pe = 1;
        }
    }
    free(cr);
    if (!has_zip || !has_pe) { printf("FAIL for_carve zip=%d pe=%d\n", has_zip, has_pe); ana_free(&a); return 1; }

    // IOC test
    for_ioc_res *ir = (for_ioc_res *)calloc(1, sizeof(for_ioc_res));
    int has_url = 0, has_ip = 0, has_reg = 0;
    if (ir && for_extract_iocs(&a, ir) >= 3) {
        for (int i = 0; i < ir->nhit; i++) {
            if (strcmp(ir->hits[i].kind, "URL") == 0) has_url = 1;
            if (strcmp(ir->hits[i].kind, "IPV4") == 0) has_ip = 1;
            if (strcmp(ir->hits[i].kind, "REG") == 0) has_reg = 1;
        }
    }
    free(ir);
    if (!has_url || !has_ip || !has_reg) { printf("FAIL for_extract_iocs url=%d ip=%d reg=%d\n", has_url, has_ip, has_reg); ana_free(&a); return 1; }

    // Vuln slicer test
    vln_res *vr = (vln_res *)calloc(1, sizeof(vln_res));
    int vok = vr && vln_scan(&a, vr) >= 1 && vr->nhigh >= 1;
    free(vr);
    if (!vok) { printf("FAIL vln_scan\n"); ana_free(&a); return 1; }

    // Hilbert map test
    vln_hilbert_res *hr = (vln_hilbert_res *)calloc(1, sizeof(vln_hilbert_res));
    int hok = hr && vln_hilbert_map(&a, 5, hr) && hr->side == 32 && hr->ncell == 1024;
    free(hr);
    ana_free(&a);
    if (!hok) { printf("FAIL vln_hilbert_map\n"); return 1; }

    return 0;
}

static int cli_dec_contains(const dec_out *d, const char *ndl) {
    for (uint32_t i = 0; i < d->nline; i++) {
        if (strstr(d->lines[i].text, ndl)) return 1;
    }
    return 0;
}

static int cli_test_dec_v2(void) {
    // 1. Live-in params (2 args only), callee-saved push/pop strip, typ_store struct field (IMAGE_DOS_HEADER->e_lfanew)
    // push rbx; mov rbx, rcx; mov eax, [rbx+0x3c]; add eax, edx; pop rbx; ret
    uint8_t fn1[] = {
        0x53,
        0x48, 0x89, 0xCB,
        0x8B, 0x43, 0x3C,
        0x01, 0xD0,
        0x5B,
        0xC3
    };
    ana_ctx a;
    ana_init(&a);
    ana_open_buf(&a, fn1, sizeof(fn1), "dec1.bin", 0x100000, 64);
    ana_run(&a, 1, 4, 16);
    ana_set_lvar(&a, 0x100000, "a1", "dos", "IMAGE_DOS_HEADER *");

    typ_store ts;
    typ_init(&ts);
    chdr_load_stdlib(&ts, "win32");

    dec_out d = {0};
    int ok1 = dec_func_typed(&a, &ts, 0x100000, &d) &&
              cli_dec_contains(&d, "IMAGE_DOS_HEADER *dos") &&
              cli_dec_contains(&d, "dos->e_lfanew") &&
              !cli_dec_contains(&d, "a3") &&
              !cli_dec_contains(&d, "rbx") &&
              d.nvar >= 2;
    dec_free(&d);
    typ_free(&ts);
    ana_free(&a);
    if (!ok1) { printf("FAIL dec_v2 struct_field/live_in\n"); return 1; }

    // 2. XMM 16-byte zero-store coalescing -> memset(a1, 0, 0x40) + bt bitmask ('\t', ' ', ',')
    // xorps xmm0, xmm0; movups [rcx], xmm0; movups [rcx+0x10], xmm0; movups [rcx+0x20], xmm0; movups [rcx+0x30], xmm0;
    // mov r11, 0x100100000200; movzx eax, dl; bt r11, rax; jb +5; xor eax, eax; ret; mov eax, 1; ret
    uint8_t fn2[] = {
        0x0F, 0x57, 0xC0,
        0x0F, 0x11, 0x01,
        0x0F, 0x11, 0x41, 0x10,
        0x0F, 0x11, 0x41, 0x20,
        0x0F, 0x11, 0x41, 0x30,
        0x49, 0xBB, 0x00, 0x02, 0x00, 0x00, 0x01, 0x10, 0x00, 0x00,
        0x0F, 0xB6, 0xC2,
        0x49, 0x0F, 0xA3, 0xC3,
        0x72, 0x03,
        0x31, 0xC0,
        0xC3,
        0xB8, 0x01, 0x00, 0x00, 0x00,
        0xC3
    };
    ana_init(&a);
    ana_open_buf(&a, fn2, sizeof(fn2), "dec2.bin", 0x100000, 64);
    ana_run(&a, 1, 4, 16);
    int ok2 = dec_func(&a, 0x100000, &d) &&
              cli_dec_contains(&d, "memset(") &&
              cli_dec_contains(&d, "'\\t'") &&
              cli_dec_contains(&d, "' '") &&
              cli_dec_contains(&d, "','") &&
              !cli_dec_contains(&d, "r11");
    dec_free(&d);
    ana_free(&a);
    if (!ok2) { printf("FAIL dec_v2 memset/bitset\n"); return 1; }

    // 3. 32-bit unsigned magic division (x / 10): mov eax, 0xCCCCCCCD; mul ecx; shr edx, 3; mov eax, edx; ret
    uint8_t fn3[] = {
        0xB8, 0xCD, 0xCC, 0xCC, 0xCC,
        0xF7, 0xE1,
        0xC1, 0xEA, 0x03,
        0x89, 0xD0,
        0xC3
    };
    ana_init(&a);
    ana_open_buf(&a, fn3, sizeof(fn3), "dec3.bin", 0x100000, 64);
    ana_run(&a, 1, 4, 16);
    int ok3 = dec_func(&a, 0x100000, &d) && cli_dec_contains(&d, "/ 10");
    dec_free(&d);
    ana_free(&a);
    if (!ok3) { printf("FAIL dec_v2 magic_div10\n"); return 1; }

    // 4. Scaled struct array indexing: lea rax, [rdx+rdx]; mov eax, [rcx+rax*8+8]; ret -> a1[a2].f_08
    uint8_t fn4[] = {
        0x48, 0x8D, 0x04, 0x12,
        0x8B, 0x44, 0xC1, 0x08,
        0xC3
    };
    ana_init(&a);
    ana_open_buf(&a, fn4, sizeof(fn4), "dec4.bin", 0x100000, 64);
    ana_run(&a, 1, 4, 16);
    int ok4 = dec_func(&a, 0x100000, &d) && cli_dec_contains(&d, "[a2].f_08");
    dec_free(&d);
    ana_free(&a);
    if (!ok4) { printf("FAIL dec_v2 struct_array\n"); return 1; }

    return 0;
}

static int cli_test_hardening(void) {
    x86_ins ins;

    // 1. x87 0xDC/0xDE fsub<->fsubr & fdiv<->fdivr swap + BMI2 + AVX-512 EVEX + x86-32 0x67
    const uint8_t dc_e3[] = {0xDC, 0xE3};
    const uint8_t dc_eb[] = {0xDC, 0xEB};
    const uint8_t de_e1[] = {0xDE, 0xE1};
    const uint8_t de_e9[] = {0xDE, 0xE9};
    const uint8_t mulx[]  = {0xC4, 0x42, 0xB3, 0xF6, 0xC2};
    const uint8_t rorx[]  = {0xC4, 0x43, 0xFB, 0xF0, 0xDC, 0x07};
    const uint8_t pext[]  = {0xC4, 0xE2, 0xE2, 0xF5, 0xC1};
    const uint8_t evex1[] = {0x62, 0xE1, 0x7C, 0xC9, 0x28, 0x40, 0x01};
    const uint8_t evex2[] = {0x62, 0x01, 0x0C, 0xC3, 0x58, 0xFD};
    const uint8_t evex3[] = {0x62, 0x61, 0x0C, 0xD3, 0x58, 0x78, 0x01};
    const uint8_t x32_p[] = {0x60};
    const uint8_t x32_a[] = {0x63, 0xD0};
    const uint8_t x32_m[] = {0x67, 0x8B, 0x00};

    if (x86_decode(dc_e3, sizeof(dc_e3), 0x1000, 64, 1, 0, &ins) != 2 || strcmp(ins.mnem, "fsubr") != 0 || strcmp(ins.ops, "st(3), st(0)") != 0) { printf("FAIL x87 DC E3\n"); return 1; }
    if (x86_decode(dc_eb, sizeof(dc_eb), 0x1000, 64, 1, 0, &ins) != 2 || strcmp(ins.mnem, "fsub") != 0 || strcmp(ins.ops, "st(3), st(0)") != 0) { printf("FAIL x87 DC EB\n"); return 1; }
    if (x86_decode(de_e1, sizeof(de_e1), 0x1000, 64, 1, 0, &ins) != 2 || strcmp(ins.mnem, "fsubrp") != 0) { printf("FAIL x87 DE E1\n"); return 1; }
    if (x86_decode(de_e9, sizeof(de_e9), 0x1000, 64, 1, 0, &ins) != 2 || strcmp(ins.mnem, "fsubp") != 0) { printf("FAIL x87 DE E9\n"); return 1; }
    if (x86_decode(mulx, sizeof(mulx), 0x1000, 64, 1, 0, &ins) != 5 || strcmp(ins.mnem, "mulx") != 0 || strcmp(ins.ops, "r8, r9, r10") != 0) { printf("FAIL BMI2 mulx\n"); return 1; }
    if (x86_decode(rorx, sizeof(rorx), 0x1000, 64, 1, 0, &ins) != 6 || strcmp(ins.mnem, "rorx") != 0 || strcmp(ins.ops, "r11, r12, 0x7") != 0) { printf("FAIL BMI2 rorx\n"); return 1; }
    if (x86_decode(pext, sizeof(pext), 0x1000, 64, 1, 0, &ins) != 5 || strcmp(ins.mnem, "pext") != 0 || strcmp(ins.ops, "rax, rbx, rcx") != 0) { printf("FAIL BMI2 pext\n"); return 1; }
    if (x86_decode(evex1, sizeof(evex1), 0x1000, 64, 1, 0, &ins) != 7 || strcmp(ins.mnem, "vmovaps") != 0 || strcmp(ins.ops, "zmm16{k1}{z}, [rax+0x40]") != 0) { printf("FAIL EVEX disp8*64: %s %s\n", ins.mnem, ins.ops); return 1; }
    if (x86_decode(evex2, sizeof(evex2), 0x1000, 64, 1, 0, &ins) != 6 || strcmp(ins.mnem, "vaddps") != 0 || strcmp(ins.ops, "zmm31{k3}{z}, zmm30, zmm29") != 0) { printf("FAIL EVEX zmm31\n"); return 1; }
    if (x86_decode(evex3, sizeof(evex3), 0x1000, 64, 1, 0, &ins) != 7 || strcmp(ins.mnem, "vaddps") != 0 || !strstr(ins.ops, "{1to16}")) { printf("FAIL EVEX broadcast\n"); return 1; }
    if (x86_decode(x32_p, sizeof(x32_p), 0x1000, 32, 1, 0, &ins) != 1 || strcmp(ins.mnem, "pushad") != 0) { printf("FAIL x86-32 pushad\n"); return 1; }
    if (x86_decode(x32_a, sizeof(x32_a), 0x1000, 32, 1, 0, &ins) != 2 || strcmp(ins.mnem, "arpl") != 0) { printf("FAIL x86-32 arpl\n"); return 1; }
    if (x86_decode(x32_m, sizeof(x32_m), 0x1000, 32, 1, 0, &ins) != 3 || !strstr(ins.ops, "[bx+si]")) { printf("FAIL x86-32 0x67 16-bit modrm: %s\n", ins.ops); return 1; }

    // 2. ARM64 128-bit SIMD + Thumb-1/Thumb-2 + odd-VA interworking
    const uint32_t a64_ldrq = 0x3DC00800U;
    const uint32_t a64_stpq = 0xADBF07E0U;
    const uint32_t a64_ld1  = 0x4C407000U;
    const uint32_t a64_madd = 0x9B020C20U;
    if (a64_decode((const uint8_t *)&a64_ldrq, 4, 0x1000, 1, 0, &ins) != 4 || strcmp(ins.mnem, "ldr") != 0 || strcmp(ins.ops, "q0, [x0, #0x20]") != 0) { printf("FAIL A64 ldr q0: %s %s\n", ins.mnem, ins.ops); return 1; }
    if (a64_decode((const uint8_t *)&a64_stpq, 4, 0x1000, 1, 0, &ins) != 4 || strcmp(ins.mnem, "stp") != 0 || strcmp(ins.ops, "q0, q1, [sp, #-32]!") != 0) { printf("FAIL A64 stp q0,q1\n"); return 1; }
    if (a64_decode((const uint8_t *)&a64_ld1, 4, 0x1000, 1, 0, &ins) != 4 || strcmp(ins.mnem, "ld1") != 0 || strcmp(ins.ops, "{v0.16b}, [x0]") != 0) { printf("FAIL A64 ld1\n"); return 1; }
    if (a64_decode((const uint8_t *)&a64_madd, 4, 0x1000, 1, 0, &ins) != 4 || strcmp(ins.mnem, "madd") != 0) { printf("FAIL A64 madd\n"); return 1; }

    const uint16_t th_push = 0xB510U;
    const uint16_t th_pop  = 0xBD10U;
    const uint16_t th_movw[2] = {0xF241U, 0x2034U};
    if (thumb_decode((const uint8_t *)&th_push, 2, 0x2001, 1, 0, &ins) != 2 || strcmp(ins.mnem, "push") != 0) { printf("FAIL Thumb16 push\n"); return 1; }
    if (arm32_decode((const uint8_t *)&th_pop, 2, 0x2003, 1, 0, &ins) != 2 || ins.flow != X86_FLOW_RET) { printf("FAIL ARM32/Thumb odd-VA interworking\n"); return 1; }
    if (thumb_decode((const uint8_t *)th_movw, 4, 0x3000, 1, 0, &ins) != 4 || strcmp(ins.mnem, "movw") != 0 || strcmp(ins.ops, "r0, #0x1234") != 0) { printf("FAIL Thumb32 movw\n"); return 1; }

    // 3. Decompiler v2 precision: double return after GPR scratch + byte-pointer array vs struct
    ana_ctx a;
    dec_out d;
    memset(&d, 0, sizeof(d));
    // mov eax, 1; addsd xmm0, xmm1; ret
    uint8_t fn_dbl[] = {
        0xB8, 0x01, 0x00, 0x00, 0x00,
        0xF2, 0x0F, 0x58, 0xC1,
        0xC3
    };
    ana_init(&a);
    ana_open_buf(&a, fn_dbl, sizeof(fn_dbl), "dbl.bin", 0x100000, 64);
    ana_run(&a, 1, 4, 16);
    int ok_dbl = dec_func(&a, 0x100000, &d) &&
                 d.nline > 0 && strncmp(d.lines[0].text, "double ", 7) == 0 &&
                 cli_dec_contains(&d, "return ");
    dec_free(&d);
    ana_free(&a);
    if (!ok_dbl) { printf("FAIL dec_v2 double_ret\n"); return 1; }

    // byte-pointer string check: movzx eax, byte ptr [rcx]; cmp al, 0; je +6; movzx edx, byte ptr [rcx+1]; add eax, edx; ret
    uint8_t fn_str[] = {
        0x0F, 0xB6, 0x01,
        0x3C, 0x00,
        0x74, 0x06,
        0x0F, 0xB6, 0x51, 0x01,
        0x01, 0xD0,
        0xC3
    };
    ana_init(&a);
    ana_open_buf(&a, fn_str, sizeof(fn_str), "str.bin", 0x100000, 64);
    ana_run(&a, 1, 4, 16);
    int ok_str = dec_func(&a, 0x100000, &d) &&
                 !cli_dec_contains(&d, "->f_00") &&
                 !cli_dec_contains(&d, "->f_01");
    dec_free(&d);
    ana_free(&a);
    if (!ok_str) { printf("FAIL dec_v2 array_vs_struct\n"); return 1; }

    // 4. Plugin allowlist & path-traversal security
    ana_init(&a);
    ext_host ext;
    ext_init(&ext, &a, NULL, NULL, NULL, NULL);
    if (ext_load_dir_allow(&ext, "..\\plugins", "entropy.dll") != 0) { printf("FAIL ext traversal reject\n"); ext_free(&ext); ana_free(&a); return 1; }
    if (ext_load_dir_allow(&ext, "plugins", "") != 0) { printf("FAIL ext empty allowlist\n"); ext_free(&ext); ana_free(&a); return 1; }
    if (ext_load_dir_allow(&ext, "plugins", "nonexistent.dll") != 0) { printf("FAIL ext non-allowlisted reject\n"); ext_free(&ext); ana_free(&a); return 1; }
    if (ext_load_dir_allow(&ext, "plugins", "entropy.dll") != 1) { printf("FAIL ext allowlisted load\n"); ext_free(&ext); ana_free(&a); return 1; }
    ext_free(&ext);
    ana_free(&a);

    return 0;
}

static int cli_bench_big(size_t mb) {
    size_t sz = mb * 1024ULL * 1024ULL;
    uint8_t *buf = (uint8_t *)malloc(sz);
    if (!buf) { printf("FAIL alloc %zu MB\n", mb); return 1; }

    memset(buf, 0x90, sz);
    const uint8_t fn_tmpl[32] = {
        0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x20,
        0xE8, 0x13, 0x00, 0x00, 0x00, 0x48, 0x85, 0xC0,
        0x74, 0x05, 0xB8, 0x01, 0x00, 0x00, 0x00, 0x48,
        0x83, 0xC4, 0x20, 0x5D, 0xC3, 0xCC, 0xCC, 0xCC
    };
    for (size_t off = 0; off + 32 <= sz; off += 32) {
        memcpy(buf + off, fn_tmpl, 32);
    }

    ana_ctx a;
    ana_init(&a);
    ana_open_buf(&a, buf, sz, "bench.raw", 0x140000000ULL, 64);
    ana_run(&a, 0, 4, (int)mb);

    double t0 = cli_ms();
    scan_pat pat;
    scan_pat_parse(&pat, "48 83 EC 20 E8 ?? ?? 00 00");
    size_t pos = scan_pat_find(buf, sz, sz - 64, &pat);
    double pat_ms = cli_ms() - t0;

    double mbps = a.ana_ms > 0.0 ? ((double)mb / (a.ana_ms / 1000.0)) : 0.0;
    printf("BENCH %zu MB: ana=%.1f ms (%.1f MB/s) funcs=%u xrefs=%u pat_tail=%.2f ms hit=%zu\n",
           mb, a.ana_ms, mbps, a.nfunc, a.nxref, pat_ms, pos);

    ana_free(&a);
    free(buf);
    return 0;
}

static void cli_print_dis(const ana_ctx *a, uint64_t va, int count, int upper) {
    uint64_t cur = va;
    x86_ins ins;
    for (int i = 0; i < count; i++) {
        size_t avail = 0;
        const uint8_t *p = bin_ptr(&a->bin, cur, &avail);
        if (!p || avail == 0) break;
        const char *sym = ana_sym_at(a, cur);
        if (sym) printf("\n%s:\n", sym);
        int n = arch_decode(a->bin.arch, p, avail, cur, 1, upper, &ins);
        if (n <= 0) break;

        char hex[32] = "";
        int hn = n < 8 ? n : 8;
        for (int k = 0; k < hn; k++) snprintf(hex + k * 3, sizeof(hex) - k * 3, "%02x ", p[k]);

        const char *tsym = ins.has_target ? ana_sym_at(a, ins.target) : NULL;
        const ana_str *st = ins.has_target ? ana_str_at(a, ins.target) : NULL;
        char sbuf[48] = "";
        if (st) ana_read_str(a, st, sbuf, sizeof(sbuf));

        printf("  %016llx  %-24s %-10s %-28s", (unsigned long long)cur, hex, ins.mnem, ins.ops);
        if (tsym) printf(" ; %s", tsym);
        else if (sbuf[0]) printf(" ; \"%s\"", sbuf);
        printf("\n");
        cur += (uint64_t)n;
    }
}

int cli_run(int argc, char **argv) {
    if (argc >= 2 && strcmp(argv[1], "--rpc") == 0) return rpc_run();
    if (argc >= 2 && strcmp(argv[1], "--test") == 0) {
        if (cli_test_scan() || cli_test_x86() || cli_test_deobf_emu() || cli_test_cfg_and_db() || cli_test_elf() || cli_test_pro() || cli_test_wave_a() || cli_test_wave_b() || cli_test_wave_c() || cli_test_wave_d() || cli_test_wave_e() || cli_test_dec_v2() || cli_test_hardening()) return 1;
        printf("ALL TESTS PASSED\n");
        return 0;
    }
    if (argc >= 2 && strcmp(argv[1], "--bench") == 0) {
        size_t mb = (argc >= 3) ? (size_t)atoi(argv[2]) : 64;
        if (mb < 1) mb = 1;
        if (mb > 512) mb = 512;
        return cli_bench_big(mb);
    }

    const char *path = NULL;
    int do_info = 0, do_funcs = 0, do_strings = 0, do_dis = 0, do_cfg = 0, do_dec = 0, do_xrefs = 0;
    uint64_t target_va = 0;
    int dis_cnt = 32;
    const char *find_pat = NULL;
    const char *run_cmd = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--info") == 0) do_info = 1;
        else if (strcmp(argv[i], "--funcs") == 0) do_funcs = 1;
        else if (strcmp(argv[i], "--strings") == 0) do_strings = 1;
        else if (strcmp(argv[i], "--dis") == 0) {
            do_dis = 1;
            if (i + 1 < argc && argv[i + 1][0] != '-') target_va = cli_parse_u64(argv[++i]);
            if (i + 1 < argc && argv[i + 1][0] != '-') dis_cnt = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--cfg") == 0) {
            do_cfg = 1;
            if (i + 1 < argc && argv[i + 1][0] != '-') target_va = cli_parse_u64(argv[++i]);
        } else if (strcmp(argv[i], "--dec") == 0) {
            do_dec = 1;
            if (i + 1 < argc && argv[i + 1][0] != '-') target_va = cli_parse_u64(argv[++i]);
        } else if (strcmp(argv[i], "--xrefs") == 0 && i + 1 < argc) {
            do_xrefs = 1;
            target_va = cli_parse_u64(argv[++i]);
        } else if (strcmp(argv[i], "--find") == 0 && i + 1 < argc) {
            find_pat = argv[++i];
        } else if (strcmp(argv[i], "--cmd") == 0 && i + 1 < argc) {
            run_cmd = argv[++i];
        } else if (argv[i][0] != '-' && !path) {
            path = argv[i];
        }
    }

    if (!path) {
        printf("usage: xdis <file> [--info|--funcs|--strings|--dis [va] [n]|--cfg [va]|--xrefs va|--find \"hex\"|--cmd name]\n");
        printf("       xdis --test | --bench [MB]\n");
        return 1;
    }

    opt_cfg opt;
    opt_defaults(&opt);
    opt_load(&opt, "xdis.ini");

    ana_ctx a;
    ana_init(&a);
    if (!ana_open(&a, path, 0, 64)) {
        printf("error: failed to open %s\n", path);
        return 1;
    }
    ana_run(&a, opt.threads, opt.min_str, opt.max_ana_mb);

    ext_host ext;
    ext_init(&ext, &a, NULL, cli_log_cb, NULL, NULL);
    ext_load_dir_allow(&ext, "plugins", opt.plugins_allow);

    if (do_info || (!do_funcs && !do_strings && !do_dis && !do_cfg && !do_dec && !do_xrefs && !find_pat && !run_cmd)) {
        printf("file: %s (%s %d-bit, %llu bytes)\n", a.bin.path, bin_fmt_name(a.bin.fmt), a.bin.bits, (unsigned long long)a.bin.map.size);
        printf("base=0x%llx entry=0x%llx secs=%u syms=%u pdata=%u\n",
               (unsigned long long)a.bin.base, (unsigned long long)a.bin.entry, a.bin.nsec, a.bin.nsym, a.bin.npdata);
        printf("analysis: load=%.2f ms ana=%.2f ms funcs=%u xrefs=%u strings=%u\n",
               a.load_ms, a.ana_ms, a.nfunc, a.nxref, a.nstr);
        for (uint32_t i = 0; i < a.bin.nsec; i++) {
            const bin_sec *s = &a.bin.secs[i];
            printf("  %-10s va=0x%016llx vsz=0x%llx fsz=0x%llx %c%c%c\n",
                   s->name, (unsigned long long)s->va, (unsigned long long)s->vsize, (unsigned long long)s->fsize,
                   (s->perm & BIN_PERM_R) ? 'r' : '-', (s->perm & BIN_PERM_W) ? 'w' : '-', (s->perm & BIN_PERM_X) ? 'x' : '-');
        }
    }

    if (do_funcs) {
        uint32_t lim = a.nfunc < 40 ? a.nfunc : 40;
        for (uint32_t i = 0; i < lim; i++) {
            printf("  0x%016llx  len=%-6llu %s\n",
                   (unsigned long long)a.funcs[i].start,
                   (unsigned long long)(a.funcs[i].end - a.funcs[i].start),
                   ana_pool_str(&a, a.funcs[i].name_off));
        }
        if (a.nfunc > lim) printf("  ... (%u total)\n", a.nfunc);
    }

    if (do_strings) {
        uint32_t lim = a.nstr < 30 ? a.nstr : 30;
        char buf[80];
        for (uint32_t i = 0; i < lim; i++) {
            ana_read_str(&a, &a.strs[i], buf, sizeof(buf));
            printf("  0x%016llx  %s\"%s\"\n", (unsigned long long)a.strs[i].va, a.strs[i].wide ? "L" : "", buf);
        }
        if (a.nstr > lim) printf("  ... (%u total)\n", a.nstr);
    }

    if (do_dis) {
        cli_print_dis(&a, target_va ? target_va : a.bin.entry, dis_cnt, opt.upper_mnem);
    }

    if (do_cfg) {
        grp_cfg g = {0};
        uint64_t va = target_va ? target_va : a.bin.entry;
        if (grp_build(&a, va, opt.upper_mnem, &g)) {
            grp_layout(&g, 8, 18);
            printf("CFG 0x%llx: %u blocks, %u edges, %u ins (%dx%d)\n",
                   (unsigned long long)g.func_va, g.nblk, g.nedge, g.nins, g.total_w, g.total_h);
            for (uint32_t i = 0; i < g.nblk && i < 16; i++) {
                printf("  B%u [0x%llx..0x%llx] ins=%u layer=%d pos=(%d,%d)\n",
                       i, (unsigned long long)g.blks[i].start, (unsigned long long)g.blks[i].end,
                       g.blks[i].ins_count, g.blks[i].layer, g.blks[i].x, g.blks[i].y);
            }
            grp_free(&g);
        }
    }

    if (do_dec) {
        dec_out d = {0};
        uint64_t va = target_va ? target_va : a.bin.entry;
        if (dec_func(&a, va, &d)) {
            for (uint32_t i = 0; i < d.nline; i++) printf("%s\n", d.lines[i].text);
            dec_free(&d);
        }
    }

    if (do_xrefs) {
        uint32_t first = 0;
        uint32_t cnt = ana_xrefs_to(&a, target_va, &first);
        printf("xrefs to 0x%llx: %u\n", (unsigned long long)target_va, cnt);
        for (uint32_t i = 0; i < cnt && i < 32; i++) {
            const ana_xref *x = &a.xrefs[first + i];
            const char *t = (x->type == ANA_XREF_CALL) ? "call" : (x->type == ANA_XREF_JMP) ? "jmp" : "data";
            printf("  %s from 0x%016llx\n", t, (unsigned long long)x->from);
        }
    }

    if (find_pat) {
        scan_pat p;
        if (scan_pat_parse(&p, find_pat)) {
            size_t pos = 0, hits = 0;
            while (hits < 20) {
                pos = scan_pat_find(a.bin.map.data, (size_t)a.bin.map.size, pos, &p);
                if (pos >= (size_t)a.bin.map.size) break;
                uint64_t va = 0;
                if (bin_off_to_va(&a.bin, pos, &va)) printf("  hit va=0x%016llx (off=0x%zx)\n", (unsigned long long)va, pos);
                else printf("  hit off=0x%zx\n", pos);
                pos++;
                hits++;
            }
        }
    }

    if (run_cmd) {
        if (!ext_run(&ext, run_cmd, "")) printf("unknown plugin cmd: %s\n", run_cmd);
    }

    ext_free(&ext);
    ana_free(&a);
    return 0;
}
