#include "ana.h"
#include "../scan/scan.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SIG_FNV_OFF 14695981039346656037ULL
#define SIG_FNV_PRM 1099511628211ULL

static uint64_t sig_fnv_b(uint64_t h, uint8_t b) {
    return (h ^ (uint64_t)b) * SIG_FNV_PRM;
}

static uint64_t sig_fnv_u32(uint64_t h, uint32_t v) {
    h = sig_fnv_b(h, (uint8_t)(v & 0xFF));
    h = sig_fnv_b(h, (uint8_t)((v >> 8) & 0xFF));
    h = sig_fnv_b(h, (uint8_t)((v >> 16) & 0xFF));
    return sig_fnv_b(h, (uint8_t)((v >> 24) & 0xFF));
}

static uint64_t sig_fnv_str(uint64_t h, const char *s) {
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        h = sig_fnv_b(h, *p);
    }
    return sig_fnv_b(h, 0);
}

static char sig_op_kind(const char *raw) {
    if (!raw) return 0;
    const char *p = raw;
    while (*p == ' ' || *p == '\t') p++;
    if (!*p) return 0;
    if (strncmp(p, "byte ptr ", 9) == 0) p += 9;
    else if (strncmp(p, "word ptr ", 9) == 0) p += 9;
    else if (strncmp(p, "dword ptr ", 10) == 0) p += 10;
    else if (strncmp(p, "qword ptr ", 10) == 0) p += 10;
    else if (strncmp(p, "xmmword ptr ", 12) == 0) p += 12;
    else if (strncmp(p, "ymmword ptr ", 12) == 0) p += 12;
    if (p[0] && p[1] && p[2] == ':') p += 3;
    if (*p == '[') return 'M';
    if (strncmp(p, "0x", 2) == 0 || isdigit((unsigned char)*p)) return 'I';
    return 'R';
}

static bool sig_is_self_xor(const x86_ins *in) {
    if (strcmp(in->mnem, "xor") != 0) return false;
    const char *c = strchr(in->ops, ',');
    if (!c) return false;
    const char *a = in->ops;
    while (*a == ' ' || *a == '\t') a++;
    const char *ae = c;
    while (ae > a && (ae[-1] == ' ' || ae[-1] == '\t')) ae--;
    const char *b = c + 1;
    while (*b == ' ' || *b == '\t') b++;
    size_t la = (size_t)(ae - a);
    size_t lb = strlen(b);
    while (lb > 0 && (b[lb - 1] == ' ' || b[lb - 1] == '\t')) lb--;
    return la > 0 && la == lb && memcmp(a, b, la) == 0 && sig_op_kind(a) == 'R';
}

static bool sig_is_auto_name(const char *s) {
    if (!s || !s[0]) return true;
    return strncmp(s, "sub_", 4) == 0 || strncmp(s, "loc_", 4) == 0;
}

uint64_t sig_dna(const ana_ctx *a, uint64_t func_va, uint32_t *nins, uint32_t *nblk, uint32_t *ncall) {
    if (nins) *nins = 0;
    if (nblk) *nblk = 0;
    if (ncall) *ncall = 0;
    if (!a) return 0;

    grp_cfg g = {0};
    if (!grp_build(a, func_va, 0, &g)) return 0;

    uint64_t h = SIG_FNV_OFF;
    h = sig_fnv_u32(h, g.nblk);
    h = sig_fnv_u32(h, g.nedge);
    for (uint32_t e = 0; e < g.nedge; e++) {
        h = sig_fnv_u32(h, g.edges[e].from);
        h = sig_fnv_u32(h, g.edges[e].to);
        h = sig_fnv_b(h, g.edges[e].kind);
    }

    uint32_t ic = 0, cc = 0;
    for (uint32_t bi = 0; bi < g.nblk; bi++) {
        const grp_blk *b = &g.blks[bi];
        h = sig_fnv_b(h, 0xFE);
        for (uint32_t k = 0; k < b->ins_count; k++) {
            const x86_ins *in = &g.ins[b->ins_first + k];
            const char *m = in->mnem;
            if (strncmp(m, "lock ", 5) == 0) m += 5;
            if (strcmp(m, "nop") == 0 || strcmp(m, "int3") == 0 ||
                strcmp(m, "endbr64") == 0 || strcmp(m, "endbr32") == 0 ||
                (strcmp(m, "add") == 0 && strcmp(in->ops, "byte ptr [rax], al") == 0)) {
                continue;
            }
            ic++;
            if (sig_is_self_xor(in)) {
                h = sig_fnv_str(h, "zreg");
                continue;
            }
            h = sig_fnv_str(h, m);

            if (in->flow == X86_FLOW_CALL) {
                cc++;
                if (in->has_target) {
                    const char *sym = ana_sym_at(a, in->target);
                    if (!sig_is_auto_name(sym)) {
                        const char *bang = strchr(sym, '!');
                        h = sig_fnv_str(h, bang ? bang + 1 : sym);
                    }
                }
            } else if (in->flow != X86_FLOW_JMP && in->flow != X86_FLOW_JCC) {
                const char *c1 = strchr(in->ops, ',');
                char k0 = sig_op_kind(in->ops);
                char k1 = c1 ? sig_op_kind(c1 + 1) : 0;
                h = sig_fnv_b(h, (uint8_t)k0);
                h = sig_fnv_b(h, (uint8_t)k1);
            }
        }
    }

    h = sig_fnv_u32(h, ic);
    h = sig_fnv_u32(h, cc);
    if (ic > 0 && h == 0) h = 1;

    if (nins) *nins = ic;
    if (nblk) *nblk = g.nblk;
    if (ncall) *ncall = cc;
    grp_free(&g);
    return ic > 0 ? h : 0;
}

static int sig_ent_cmp(const void *a, const void *b) {
    const sig_ent *x = (const sig_ent *)a;
    const sig_ent *y = (const sig_ent *)b;
    if (x->hash != y->hash) return (x->hash > y->hash) - (x->hash < y->hash);
    if (x->nblk != y->nblk) return (x->nblk > y->nblk) - (x->nblk < y->nblk);
    if (x->ncall != y->ncall) return (x->ncall > y->ncall) - (x->ncall < y->ncall);
    return (x->nins > y->nins) - (x->nins < y->nins);
}

bool sig_save(const ana_ctx *a, const char *path) {
    if (!a || !path || !path[0]) return false;

    uint32_t cap = 256, cnt = 0;
    sig_ent *ents = (sig_ent *)malloc((size_t)cap * sizeof(sig_ent));
    if (!ents) return false;

    for (uint32_t i = 0; i < a->nfunc; i++) {
        const char *nm = ana_pool_str(a, a->funcs[i].name_off);
        if (sig_is_auto_name(nm)) nm = ana_sym_at(a, a->funcs[i].start);
        if (sig_is_auto_name(nm)) continue;

        uint32_t ni = 0, nb = 0, nc = 0;
        uint64_t h = sig_dna(a, a->funcs[i].start, &ni, &nb, &nc);
        if (h == 0 || ni == 0) continue;

        if (cnt == cap) {
            uint32_t ncap = cap * 2;
            sig_ent *ne = (sig_ent *)realloc(ents, (size_t)ncap * sizeof(sig_ent));
            if (!ne) { free(ents); return false; }
            ents = ne;
            cap = ncap;
        }
        sig_ent *e = &ents[cnt++];
        memset(e, 0, sizeof(*e));
        e->hash = h;
        e->nins = ni;
        e->nblk = nb;
        e->ncall = nc;
        snprintf(e->name, sizeof(e->name), "%s", nm);
    }

    FILE *f = fopen(path, "wb");
    if (!f) { free(ents); return false; }
    bool ok = fwrite("XSIG", 1, 4, f) == 4 &&
              fwrite(&cnt, 4, 1, f) == 1 &&
              (cnt == 0 || fwrite(ents, sizeof(sig_ent), cnt, f) == cnt);
    fclose(f);
    free(ents);
    return ok;
}

uint32_t sig_apply(ana_ctx *a, const char *path) {
    if (!a || !path || !path[0]) return 0;

    FILE *f = fopen(path, "rb");
    if (!f) return 0;

    char mag[4];
    uint32_t cnt = 0;
    if (fread(mag, 1, 4, f) != 4 || memcmp(mag, "XSIG", 4) != 0 ||
        fread(&cnt, 4, 1, f) != 1 || cnt == 0 || cnt > 500000) {
        fclose(f);
        return 0;
    }

    sig_ent *ents = (sig_ent *)malloc((size_t)cnt * sizeof(sig_ent));
    if (!ents) { fclose(f); return 0; }
    if (fread(ents, sizeof(sig_ent), cnt, f) != cnt) {
        free(ents);
        fclose(f);
        return 0;
    }
    fclose(f);

    qsort(ents, cnt, sizeof(sig_ent), sig_ent_cmp);

    uint32_t matched = 0;
    for (uint32_t i = 0; i < a->nfunc; i++) {
        const char *nm = ana_pool_str(a, a->funcs[i].name_off);
        if (!sig_is_auto_name(nm)) continue;

        uint32_t ni = 0, nb = 0, nc = 0;
        uint64_t h = sig_dna(a, a->funcs[i].start, &ni, &nb, &nc);
        if (h == 0 || ni < 6) continue;

        uint32_t lo = 0, hi = cnt;
        while (lo < hi) {
            uint32_t mid = lo + (hi - lo) / 2;
            if (ents[mid].hash < h) lo = mid + 1;
            else hi = mid;
        }

        const sig_ent *best = NULL;
        for (uint32_t k = lo; k < cnt && ents[k].hash == h; k++) {
            if (ents[k].nins < 6 || ents[k].nblk != nb || ents[k].ncall != nc) continue;
            if (!best || ents[k].nins == ni) {
                best = &ents[k];
                if (ents[k].nins == ni) break;
            }
        }
        if (best) {
            char name[64];
            memcpy(name, best->name, 63);
            name[63] = 0;
            if (name[0]) {
                ana_set_name(a, a->funcs[i].start, name);
                matched++;
            }
        }
    }

    free(ents);
    return matched;
}

static bool sig_has_va(const sig_crypto *out, int n, uint64_t va) {
    for (int i = 0; i < n; i++) {
        if (out[i].va == va) return true;
    }
    return false;
}

int sig_find_crypto(const ana_ctx *a, sig_crypto *out, int max_out) {
    if (!a || !out || max_out <= 0 || !a->bin.map.data || a->bin.map.size == 0) return 0;

    static const struct {
        const char *pat;
        const char *algo;
        const char *detail;
        int         is_text;
    } rules[] = {
        { "63 7c 77 7b f2 6b 6f c5", "AES",          "S-Box",                  0 },
        { "52 09 6a d5 30 36 a5 38", "AES",          "Inverse S-Box",          0 },
        { "a5 63 63 c6 84 7c 7c f8", "Rijndael/AES", "Te0 T-table (LE)",       0 },
        { "c6 63 63 a5 f8 7c 7c 84", "Rijndael/AES", "Te0 T-table (BE)",       0 },
        { "50 a7 f4 51 53 65 41 7e", "Rijndael/AES", "Td0 T-table (LE)",       0 },
        { "98 2f 8a 42 91 44 37 71", "SHA-256",      "Round constants K (LE)", 0 },
        { "42 8a 2f 98 71 37 44 91", "SHA-256",      "Round constants K (BE)", 0 },
        { "67 e6 09 6a 85 ae 67 bb", "SHA-256",      "Initial hash H0 (LE)",   0 },
        { "6a 09 e6 67 bb 67 ae 85", "SHA-256",      "Initial hash H0 (BE)",   0 },
        { "22 ae 28 d7 98 2f 8a 42", "SHA-512",      "Round constants K (LE)", 0 },
        { "expand 32-byte k",        "ChaCha20",     "Sigma constant 256-bit", 1 },
        { "expand 16-byte k",        "ChaCha20",     "Tau constant 128-bit",   1 },
        { "01 23 45 67 89 ab cd ef", "MD5/SHA-1",    "Initial vector IV (LE)", 0 },
        { "67 45 23 01 ef cd ab 89", "MD5/SHA-1",    "Initial vector IV (BE)", 0 },
        { "78 a4 6a d7 56 b7 c7 e8", "MD5",          "Sine table T (LE)",      0 },
        { "00 00 00 00 96 30 07 77", "CRC32",        "IEEE 802.3 table",       0 },
        { "00 00 00 00 03 83 6b f2", "CRC32C",       "Castagnoli table",       0 },
        { "a3 78 59 13 ca 4d eb 75", "Curve25519",   "Ed25519 constant d",     0 },
        { "ed ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff", "Curve25519", "Prime 2^255-19", 0 },
        { "ff ff ff 0f fc ff ff 0f", "Poly1305",     "Clamp mask",             0 },
        { "88 6a 3f 24 d3 08 a3 85", "Blowfish",     "Initial P-array (LE)",   0 }
    };

    const uint8_t *buf = a->bin.map.data;
    size_t len = (size_t)a->bin.map.size;
    int found = 0;

    for (size_t r = 0; r < sizeof(rules) / sizeof(rules[0]) && found < max_out; r++) {
        scan_pat pat;
        size_t step = 0;
        if (!rules[r].is_text) {
            if (!scan_pat_parse(&pat, rules[r].pat)) continue;
            step = pat.len;
        } else {
            step = strlen(rules[r].pat);
        }

        size_t pos = 0;
        int per_rule = 0;
        while (pos < len && found < max_out && per_rule < 8) {
            size_t hit = rules[r].is_text
                       ? scan_text_find(buf, len, pos, rules[r].pat)
                       : scan_pat_find(buf, len, pos, &pat);
            if (hit >= len) break;

            uint64_t va = 0;
            if (bin_off_to_va(&a->bin, (uint64_t)hit, &va) && !sig_has_va(out, found, va)) {
                sig_crypto *c = &out[found++];
                c->va = va;
                snprintf(c->algo, sizeof(c->algo), "%s", rules[r].algo);
                snprintf(c->detail, sizeof(c->detail), "%s", rules[r].detail);
                per_rule++;
            }
            pos = hit + (step ? step : 1);
        }
    }

    return found;
}
