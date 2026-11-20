#include "ana.h"
#include "../scan/scan.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint16_t for_rd16_le(const uint8_t *p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t for_rd32_le(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t for_rd64_le(const uint8_t *p) {
    return (uint64_t)for_rd32_le(p) | ((uint64_t)for_rd32_le(p + 4) << 32);
}

static uint16_t for_rd16_be(const uint8_t *p) {
    return ((uint16_t)p[0] << 8) | (uint16_t)p[1];
}

static uint32_t for_rd32_be(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static int for_hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

const char *for_yara_default_rules(void) {
    static const char rules[] =
        "rule PE_Process_Injection {\n"
        "  meta:\n"
        "    description = \"Win32 remote process injection API cluster\"\n"
        "  strings:\n"
        "    $a = \"VirtualAllocEx\" ascii\n"
        "    $b = \"WriteProcessMemory\" ascii\n"
        "    $c = \"CreateRemoteThread\" ascii\n"
        "    $d = \"NtUnmapViewOfSection\" ascii\n"
        "    $e = \"QueueUserAPC\" ascii\n"
        "  condition:\n"
        "    2 of them\n"
        "}\n\n"
        "rule AntiDebug_Checks {\n"
        "  meta:\n"
        "    description = \"Anti-debugging APIs or direct PEB BeingDebugged read\"\n"
        "  strings:\n"
        "    $api1 = \"IsDebuggerPresent\" ascii\n"
        "    $api2 = \"CheckRemoteDebuggerPresent\" ascii\n"
        "    $api3 = \"NtQueryInformationProcess\" ascii\n"
        "    $peb64 = { 65 48 8B 04 25 60 00 00 00 }\n"
        "    $peb32 = { 64 A1 30 00 00 00 }\n"
        "  condition:\n"
        "    any of them\n"
        "}\n\n"
        "rule Embedded_PE_Header {\n"
        "  meta:\n"
        "    description = \"Multiple PE DOS stubs or embedded PE64 headers\"\n"
        "  strings:\n"
        "    $stub = \"This program cannot be run in DOS mode\" ascii\n"
        "    $pe64 = { 50 45 00 00 64 86 }\n"
        "  condition:\n"
        "    #stub > 1 or (#pe64 > 1 and filesize < 50MB)\n"
        "}\n\n"
        "rule Embedded_ZIP_Archive {\n"
        "  meta:\n"
        "    description = \"Embedded PKZIP local header and end-of-central-directory\"\n"
        "  strings:\n"
        "    $lh = { 50 4B 03 04 }\n"
        "    $eocd = { 50 4B 05 06 }\n"
        "  condition:\n"
        "    $lh and $eocd\n"
        "}\n\n"
        "rule UPX_Packer {\n"
        "  meta:\n"
        "    description = \"UPX packer section markers or header signature\"\n"
        "  strings:\n"
        "    $s0 = \"UPX0\" ascii\n"
        "    $s1 = \"UPX1\" ascii\n"
        "    $s2 = \"UPX!\" ascii\n"
        "  condition:\n"
        "    2 of ($s*)\n"
        "}\n\n"
        "rule Crypto_AES_Constants {\n"
        "  meta:\n"
        "    description = \"AES Rijndael S-Box or inverse S-Box table\"\n"
        "  strings:\n"
        "    $sbox = { 63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76 }\n"
        "    $inv = { 52 09 6A D5 30 36 A5 38 BF 40 A3 9E 81 F3 D7 FB }\n"
        "  condition:\n"
        "    any of them\n"
        "}\n\n"
        "rule Suspicious_Shell_Exec {\n"
        "  meta:\n"
        "    description = \"Command shell or PowerShell execution indicators\"\n"
        "  strings:\n"
        "    $a = \"cmd.exe\" ascii wide nocase\n"
        "    $b = \"powershell\" ascii wide nocase\n"
        "    $c = \"ShellExecute\" ascii\n"
        "    $d = \"WinExec\" ascii\n"
        "    $e = \"/bin/sh\" ascii\n"
        "  condition:\n"
        "    any of them\n"
        "}\n\n"
        "rule Persistence_RunKey {\n"
        "  meta:\n"
        "    description = \"Windows Run / RunOnce registry persistence key\"\n"
        "  strings:\n"
        "    $a = \"Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\" ascii wide nocase\n"
        "    $b = \"CurrentVersion\\\\RunOnce\" ascii wide nocase\n"
        "  condition:\n"
        "    any of them\n"
        "}\n\n"
        "rule Ransomware_ShadowCopy {\n"
        "  meta:\n"
        "    description = \"Shadow copy deletion or recovery inhibition commands\"\n"
        "  strings:\n"
        "    $a = \"vssadmin\" ascii wide nocase\n"
        "    $b = \"delete shadows\" ascii wide nocase\n"
        "    $c = \"wbadmin\" ascii wide nocase\n"
        "    $d = \"bcdedit\" ascii wide nocase\n"
        "  condition:\n"
        "    2 of them or ($a and $b)\n"
        "}\n\n"
        "rule Networking_WinHTTP_WinINet {\n"
        "  meta:\n"
        "    description = \"WinHTTP, WinINet, or Winsock network client APIs\"\n"
        "  strings:\n"
        "    $a = \"InternetOpen\" ascii\n"
        "    $b = \"HttpSendRequest\" ascii\n"
        "    $c = \"WinHttpOpen\" ascii\n"
        "    $d = \"URLDownloadToFile\" ascii\n"
        "    $e = \"WSAStartup\" ascii\n"
        "  condition:\n"
        "    2 of them\n"
        "}\n";
    return rules;
}

#define YR_MAX_STRS  32
#define YR_MAX_SEGS  8
#define YR_SEG_MAX   SCAN_PAT_MAX
#define YR_TXT_MAX   128
#define YR_MAX_MATCH 32
#define YR_MAX_DEPTH 64

enum {
    YR_MOD_ASCII    = 1u << 0,
    YR_MOD_WIDE     = 1u << 1,
    YR_MOD_NOCASE   = 1u << 2,
    YR_MOD_FULLWORD = 1u << 3
};

typedef struct {
    uint8_t  bytes[YR_SEG_MAX];
    uint8_t  mask[YR_SEG_MAX];
    size_t   len;
    size_t   jmin;
    size_t   jmax;
    int      has_nibble;
    scan_pat fast;
    int      use_fast;
} yr_seg;

typedef struct {
    char     id[24];
    int      is_hex;
    uint32_t mods;
    uint8_t  txt[YR_TXT_MAX];
    size_t   txt_len;
    yr_seg   segs[YR_MAX_SEGS];
    int      nseg;
    int      count;
    uint64_t first_off;
} yr_str;

typedef struct {
    char   name[64];
    char   desc[96];
    yr_str strs[YR_MAX_STRS];
    int    nstr;
} yr_rule;

typedef struct {
    const char *src;
    size_t      pos;
    char        err[96];
} yr_lex;

typedef struct {
    yr_lex        *lx;
    const yr_rule *rule;
    const uint8_t *buf;
    size_t         sz;
    int            depth;
} yr_cond;

static void yr_set_err(yr_lex *lx, const char *msg) {
    if (!lx->err[0]) snprintf(lx->err, sizeof(lx->err), "%s", msg);
}

static bool yr_is_id_start(char c) {
    return isalpha((unsigned char)c) || c == '_';
}

static bool yr_is_id(char c) {
    return isalnum((unsigned char)c) || c == '_';
}

static void yr_skip_ws(yr_lex *lx) {
    for (;;) {
        char c = lx->src[lx->pos];
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
            lx->pos++;
            continue;
        }
        if (c == '/' && lx->src[lx->pos + 1] == '/') {
            lx->pos += 2;
            while (lx->src[lx->pos] && lx->src[lx->pos] != '\n') lx->pos++;
            continue;
        }
        if (c == '/' && lx->src[lx->pos + 1] == '*') {
            lx->pos += 2;
            while (lx->src[lx->pos] && !(lx->src[lx->pos] == '*' && lx->src[lx->pos + 1] == '/')) {
                lx->pos++;
            }
            if (lx->src[lx->pos]) lx->pos += 2;
            else { yr_set_err(lx, "unterminated block comment"); break; }
            continue;
        }
        break;
    }
}

static bool yr_peek_kw(yr_lex *lx, const char *kw) {
    yr_skip_ws(lx);
    size_t n = strlen(kw);
    if (strncmp(lx->src + lx->pos, kw, n) != 0) return false;
    return !yr_is_id(lx->src[lx->pos + n]);
}

static bool yr_eat_kw(yr_lex *lx, const char *kw) {
    if (!yr_peek_kw(lx, kw)) return false;
    lx->pos += strlen(kw);
    return true;
}

static bool yr_eat_ch(yr_lex *lx, char ch) {
    yr_skip_ws(lx);
    if (lx->src[lx->pos] != ch) return false;
    lx->pos++;
    return true;
}

static bool yr_peek_section(yr_lex *lx, const char *kw) {
    yr_skip_ws(lx);
    size_t save = lx->pos;
    if (!yr_eat_kw(lx, kw)) return false;
    bool ok = yr_eat_ch(lx, ':');
    lx->pos = save;
    return ok;
}

static bool yr_read_ident(yr_lex *lx, char *dst, size_t max) {
    yr_skip_ws(lx);
    if (!yr_is_id_start(lx->src[lx->pos])) return false;
    size_t k = 0;
    while (yr_is_id(lx->src[lx->pos])) {
        if (k + 1 < max) dst[k++] = lx->src[lx->pos];
        lx->pos++;
    }
    dst[k] = 0;
    return k > 0;
}

static bool yr_parse_quoted(yr_lex *lx, uint8_t *dst, size_t max, size_t *out_len) {
    yr_skip_ws(lx);
    if (lx->src[lx->pos] != '"') { yr_set_err(lx, "expected quoted string"); return false; }
    lx->pos++;
    size_t n = 0;
    while (lx->src[lx->pos] && lx->src[lx->pos] != '"') {
        char c = lx->src[lx->pos++];
        uint8_t val = (uint8_t)c;
        if (c == '\\') {
            char e = lx->src[lx->pos];
            if (!e) { yr_set_err(lx, "unterminated escape"); return false; }
            lx->pos++;
            if (e == 'n') val = '\n';
            else if (e == 'r') val = '\r';
            else if (e == 't') val = '\t';
            else if (e == '\\') val = '\\';
            else if (e == '"') val = '"';
            else if (e == 'x') {
                int hi = for_hex_val(lx->src[lx->pos]);
                int lo = (hi >= 0) ? for_hex_val(lx->src[lx->pos + 1]) : -1;
                if (hi < 0 || lo < 0) { yr_set_err(lx, "invalid \\x hex escape"); return false; }
                val = (uint8_t)((hi << 4) | lo);
                lx->pos += 2;
            } else {
                val = (uint8_t)e;
            }
        }
        if (n < max) dst[n++] = val;
    }
    if (lx->src[lx->pos] != '"') { yr_set_err(lx, "unterminated string literal"); return false; }
    lx->pos++;
    *out_len = n;
    return true;
}

static void yr_seg_compile_fast(yr_seg *seg) {
    seg->use_fast = 0;
    if (seg->len == 0 || seg->has_nibble || seg->len > SCAN_PAT_MAX) return;
    char txt[SCAN_PAT_MAX * 3 + 4];
    size_t off = 0;
    for (size_t i = 0; i < seg->len; i++) {
        if (i) txt[off++] = ' ';
        if (seg->mask[i] == 0) {
            txt[off++] = '?';
            txt[off++] = '?';
        } else {
            static const char hx[] = "0123456789ABCDEF";
            txt[off++] = hx[(seg->bytes[i] >> 4) & 0xF];
            txt[off++] = hx[seg->bytes[i] & 0xF];
        }
    }
    txt[off] = 0;
    if (scan_pat_parse(&seg->fast, txt)) seg->use_fast = 1;
}

static bool yr_parse_hex_jump(yr_lex *lx, size_t *jmin, size_t *jmax) {
    lx->pos++;
    yr_skip_ws(lx);
    size_t lo = 0, hi = 256;
    int has_lo = 0, has_dash = 0, has_hi = 0;
    if (isdigit((unsigned char)lx->src[lx->pos])) {
        has_lo = 1;
        while (isdigit((unsigned char)lx->src[lx->pos])) {
            lo = lo * 10 + (size_t)(lx->src[lx->pos++] - '0');
            if (lo > 256) lo = 256;
        }
    }
    yr_skip_ws(lx);
    if (lx->src[lx->pos] == '-') {
        has_dash = 1;
        lx->pos++;
        yr_skip_ws(lx);
        if (isdigit((unsigned char)lx->src[lx->pos])) {
            has_hi = 1;
            hi = 0;
            while (isdigit((unsigned char)lx->src[lx->pos])) {
                hi = hi * 10 + (size_t)(lx->src[lx->pos++] - '0');
                if (hi > 256) hi = 256;
            }
        }
    }
    if (!yr_eat_ch(lx, ']')) { yr_set_err(lx, "expected ']' in hex jump"); return false; }
    if (!has_dash) {
        if (!has_lo) { yr_set_err(lx, "empty hex jump"); return false; }
        hi = lo;
    } else if (!has_hi) {
        hi = (lo + 64 < 256) ? (lo + 64) : 256;
    }
    if (hi < lo) { yr_set_err(lx, "invalid hex jump range"); return false; }
    *jmin = lo;
    *jmax = hi;
    return true;
}

static bool yr_parse_hex(yr_lex *lx, yr_str *st) {
    if (!yr_eat_ch(lx, '{')) { yr_set_err(lx, "expected '{' in hex pattern"); return false; }
    st->is_hex = 1;
    st->nseg = 1;
    yr_seg *cur = &st->segs[0];

    for (;;) {
        yr_skip_ws(lx);
        if (lx->err[0]) return false;
        char c = lx->src[lx->pos];
        if (!c) { yr_set_err(lx, "unterminated hex string"); return false; }
        if (c == '}') { lx->pos++; break; }

        if (c == '[') {
            size_t jmin = 0, jmax = 0;
            if (!yr_parse_hex_jump(lx, &jmin, &jmax)) return false;
            // expand small fixed jump into wildcards so scan_pat_find handles it in one pass
            if (jmin == jmax && jmin <= 16 && cur->len + jmin <= YR_SEG_MAX) {
                for (size_t k = 0; k < jmin; k++) {
                    cur->bytes[cur->len] = 0;
                    cur->mask[cur->len] = 0;
                    cur->len++;
                }
            } else if (cur->len > 0 && st->nseg < YR_MAX_SEGS) {
                cur = &st->segs[st->nseg++];
                cur->jmin = jmin;
                cur->jmax = jmax;
            }
            continue;
        }

        char c0 = lx->src[lx->pos];
        char c1 = lx->src[lx->pos + 1];
        if (c0 == '?' && (c1 == ' ' || c1 == '\t' || c1 == '\r' || c1 == '\n' || c1 == '}' || c1 == '[')) {
            if (cur->len < YR_SEG_MAX) {
                cur->bytes[cur->len] = 0;
                cur->mask[cur->len] = 0;
                cur->len++;
            }
            lx->pos++;
            continue;
        }

        int hi = (c0 == '?') ? -2 : for_hex_val(c0);
        int lo = (c1 == '?') ? -2 : for_hex_val(c1);
        if (hi == -1 || lo == -1) { yr_set_err(lx, "invalid hex token"); return false; }

        uint8_t b = 0, m = 0;
        if (hi >= 0) { b |= (uint8_t)(hi << 4); m |= 0xF0; }
        if (lo >= 0) { b |= (uint8_t)lo;        m |= 0x0F; }
        if (m == 0xF0 || m == 0x0F) cur->has_nibble = 1;

        if (cur->len == YR_SEG_MAX && st->nseg < YR_MAX_SEGS) {
            cur = &st->segs[st->nseg++];
        }
        if (cur->len < YR_SEG_MAX) {
            cur->bytes[cur->len] = b;
            cur->mask[cur->len] = m;
            cur->len++;
        }
        lx->pos += 2;
    }

    while (st->nseg > 0 && st->segs[st->nseg - 1].len == 0) st->nseg--;
    if (st->nseg == 0 || st->segs[0].len == 0) {
        yr_set_err(lx, "empty hex pattern");
        return false;
    }
    for (int i = 0; i < st->nseg; i++) yr_seg_compile_fast(&st->segs[i]);
    return true;
}

static bool yr_seg_at(const uint8_t *p, const yr_seg *seg) {
    for (size_t i = 0; i < seg->len; i++) {
        uint8_t m = seg->mask[i];
        if (m && (p[i] & m) != seg->bytes[i]) return false;
    }
    return true;
}

static size_t yr_find_seg_nibble(const uint8_t *buf, size_t sz, size_t start, const yr_seg *seg) {
    if (seg->len == 0 || start + seg->len > sz) return sz;
    size_t anchor = seg->len;
    for (size_t i = 0; i < seg->len; i++) {
        if (seg->mask[i] == 0xFF) { anchor = i; break; }
    }
    size_t limit = sz - seg->len;
    if (anchor < seg->len) {
        size_t pos = start;
        uint8_t needle = seg->bytes[anchor];
        while (pos <= limit) {
            size_t span = (limit - pos) + 1;
            size_t rel = scan_byte_fast(buf + pos + anchor, span, needle);
            if (rel >= span) return sz;
            size_t cand = pos + rel;
            if (yr_seg_at(buf + cand, seg)) return cand;
            pos = cand + 1;
        }
        return sz;
    }
    for (size_t pos = start; pos <= limit; pos++) {
        if (yr_seg_at(buf + pos, seg)) return pos;
    }
    return sz;
}

static bool yr_match_tail(const uint8_t *buf, size_t sz, size_t off, const yr_str *st, int si) {
    if (si >= st->nseg) return true;
    const yr_seg *seg = &st->segs[si];
    for (size_t d = seg->jmin; d <= seg->jmax; d++) {
        if (off + d + seg->len > sz) break;
        if (yr_seg_at(buf + off + d, seg) && yr_match_tail(buf, sz, off + d + seg->len, st, si + 1)) {
            return true;
        }
    }
    return false;
}

static void yr_record_hit(yr_str *st, size_t off) {
    if (st->count == 0 || (uint64_t)off < st->first_off) st->first_off = (uint64_t)off;
    if (st->count < YR_MAX_MATCH) st->count++;
}

static void yr_scan_hex(const uint8_t *buf, size_t sz, yr_str *st) {
    const yr_seg *s0 = &st->segs[0];
    size_t pos = 0;
    while (pos < sz && st->count < YR_MAX_MATCH) {
        size_t cand = s0->use_fast
                    ? scan_pat_find(buf, sz, pos, &s0->fast)
                    : yr_find_seg_nibble(buf, sz, pos, s0);
        if (cand >= sz) break;
        if (st->nseg == 1 || yr_match_tail(buf, sz, cand + s0->len, st, 1)) {
            yr_record_hit(st, cand);
        }
        pos = cand + 1;
    }
}

static bool yr_fullword_ascii(const uint8_t *buf, size_t sz, size_t off, size_t len) {
    if (off > 0 && isalnum(buf[off - 1])) return false;
    if (off + len < sz && isalnum(buf[off + len])) return false;
    return true;
}

static bool yr_fullword_wide(const uint8_t *buf, size_t sz, size_t off, size_t wlen) {
    if (off >= 2 && buf[off - 1] == 0 && isalnum(buf[off - 2])) return false;
    if (off + wlen + 2 <= sz && buf[off + wlen + 1] == 0 && isalnum(buf[off + wlen])) return false;
    return true;
}

static bool yr_eq_ascii_ci(const uint8_t *p, const uint8_t *pat, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (tolower(p[i]) != tolower(pat[i])) return false;
    }
    return true;
}

static bool yr_eq_wide(const uint8_t *p, const uint8_t *pat, size_t len, int ci) {
    for (size_t i = 0; i < len; i++) {
        if (p[i * 2 + 1] != 0) return false;
        uint8_t b = p[i * 2];
        if (ci ? (tolower(b) != tolower(pat[i])) : (b != pat[i])) return false;
    }
    return true;
}

static void yr_scan_text_ascii(const uint8_t *buf, size_t sz, yr_str *st) {
    size_t len = st->txt_len;
    if (len == 0 || len > sz) return;
    int ci = (st->mods & YR_MOD_NOCASE) != 0;
    int fw = (st->mods & YR_MOD_FULLWORD) != 0;
    size_t limit = sz - len;

    size_t anchor = len;
    if (!ci) {
        anchor = 0;
    } else {
        for (size_t i = 0; i < len; i++) {
            if (!isalpha(st->txt[i])) { anchor = i; break; }
        }
    }

    if (anchor < len) {
        uint8_t needle = st->txt[anchor];
        size_t pos = 0;
        while (pos <= limit && st->count < YR_MAX_MATCH) {
            size_t span = (limit - pos) + 1;
            size_t rel = scan_byte_fast(buf + pos + anchor, span, needle);
            if (rel >= span) break;
            size_t cand = pos + rel;
            bool ok = ci ? yr_eq_ascii_ci(buf + cand, st->txt, len)
                         : (memcmp(buf + cand, st->txt, len) == 0);
            if (ok && (!fw || yr_fullword_ascii(buf, sz, cand, len))) {
                yr_record_hit(st, cand);
            }
            pos = cand + 1;
        }
        return;
    }

    uint8_t lo0 = (uint8_t)tolower(st->txt[0]);
    for (size_t pos = 0; pos <= limit && st->count < YR_MAX_MATCH; pos++) {
        if ((uint8_t)(buf[pos] | 0x20u) != lo0) continue;
        if (yr_eq_ascii_ci(buf + pos, st->txt, len) && (!fw || yr_fullword_ascii(buf, sz, pos, len))) {
            yr_record_hit(st, pos);
        }
    }
}

static void yr_scan_text_wide(const uint8_t *buf, size_t sz, yr_str *st) {
    size_t len = st->txt_len;
    size_t wlen = len * 2;
    if (len == 0 || wlen > sz) return;
    int ci = (st->mods & YR_MOD_NOCASE) != 0;
    int fw = (st->mods & YR_MOD_FULLWORD) != 0;
    size_t limit = sz - wlen;
    int cap_only_earlier = (st->count >= YR_MAX_MATCH);
    if (cap_only_earlier && st->first_off < limit) limit = (size_t)st->first_off;

    size_t anchor = len;
    if (!ci) {
        anchor = 0;
    } else {
        for (size_t i = 0; i < len; i++) {
            if (!isalpha(st->txt[i])) { anchor = i; break; }
        }
    }

    if (anchor < len) {
        uint8_t needle = st->txt[anchor];
        size_t aoff = anchor * 2;
        size_t pos = 0;
        while (pos <= limit && (cap_only_earlier ? (pos < (size_t)st->first_off) : (st->count < YR_MAX_MATCH))) {
            size_t span = (limit - pos) + 1;
            size_t rel = scan_byte_fast(buf + pos + aoff, span, needle);
            if (rel >= span) break;
            size_t cand = pos + rel;
            if (yr_eq_wide(buf + cand, st->txt, len, ci) && (!fw || yr_fullword_wide(buf, sz, cand, wlen))) {
                yr_record_hit(st, cand);
                if (cap_only_earlier) break;
            }
            pos = cand + 1;
        }
        return;
    }

    uint8_t lo0 = (uint8_t)tolower(st->txt[0]);
    for (size_t pos = 0; pos <= limit; pos++) {
        if (cap_only_earlier ? (pos >= (size_t)st->first_off) : (st->count >= YR_MAX_MATCH)) break;
        if ((uint8_t)(buf[pos] | 0x20u) != lo0 || buf[pos + 1] != 0) continue;
        if (yr_eq_wide(buf + pos, st->txt, len, 1) && (!fw || yr_fullword_wide(buf, sz, pos, wlen))) {
            yr_record_hit(st, pos);
            if (cap_only_earlier) break;
        }
    }
}

static void yr_scan_rule_strs(const uint8_t *buf, size_t sz, yr_rule *r) {
    for (int i = 0; i < r->nstr; i++) {
        yr_str *st = &r->strs[i];
        st->count = 0;
        st->first_off = 0;
        if (st->is_hex) {
            yr_scan_hex(buf, sz, st);
        } else {
            if (st->mods & YR_MOD_ASCII) yr_scan_text_ascii(buf, sz, st);
            if (st->mods & YR_MOD_WIDE) yr_scan_text_wide(buf, sz, st);
        }
    }
}

static const yr_str *yr_find_str(const yr_rule *r, const char *id) {
    for (int i = 0; i < r->nstr; i++) {
        if (strcmp(r->strs[i].id, id) == 0) return &r->strs[i];
    }
    return NULL;
}

static int64_t yr_read_mem_int(const uint8_t *buf, size_t sz, int64_t off, int width, int is_signed, int be) {
    if (off < 0 || (uint64_t)off >= (uint64_t)sz || (uint64_t)width > (uint64_t)sz - (uint64_t)off) {
        return 0;
    }
    const uint8_t *p = buf + (size_t)off;
    uint64_t v = 0;
    if (be) {
        for (int i = 0; i < width; i++) v = (v << 8) | p[i];
    } else {
        for (int i = 0; i < width; i++) v |= ((uint64_t)p[i] << (i * 8));
    }
    if (is_signed) {
        if (width == 1) return (int8_t)v;
        if (width == 2) return (int16_t)v;
        if (width == 4) return (int32_t)v;
    }
    return (int64_t)v;
}

static int64_t yr_parse_or(yr_cond *c);

static int64_t yr_parse_of(yr_cond *c, int mode, int64_t req_cnt) {
    yr_lex *lx = c->lx;
    uint32_t mask = 0;

    if (yr_eat_kw(lx, "them")) {
        for (int i = 0; i < c->rule->nstr; i++) mask |= (1u << i);
    } else if (yr_eat_ch(lx, '(')) {
        for (;;) {
            yr_skip_ws(lx);
            if (lx->src[lx->pos] != '$') { yr_set_err(lx, "expected $id in string set"); return 0; }
            char pat[24];
            size_t k = 0;
            pat[k++] = lx->src[lx->pos++];
            while (yr_is_id(lx->src[lx->pos])) {
                if (k + 1 < sizeof(pat)) pat[k++] = lx->src[lx->pos];
                lx->pos++;
            }
            pat[k] = 0;
            int wild = 0;
            if (lx->src[lx->pos] == '*') { wild = 1; lx->pos++; }

            int found = 0;
            for (int i = 0; i < c->rule->nstr; i++) {
                bool match = wild ? (strncmp(c->rule->strs[i].id, pat, k) == 0)
                                  : (strcmp(c->rule->strs[i].id, pat) == 0);
                if (match) { mask |= (1u << i); found = 1; }
            }
            if (!wild && !found) { yr_set_err(lx, "unknown string id in set"); return 0; }
            if (yr_eat_ch(lx, ',')) continue;
            if (!yr_eat_ch(lx, ')')) { yr_set_err(lx, "expected ')' after string set"); return 0; }
            break;
        }
    } else {
        yr_set_err(lx, "expected 'them' or '(...)' after 'of'");
        return 0;
    }

    int total = 0, matched = 0;
    for (int i = 0; i < c->rule->nstr; i++) {
        if (!(mask & (1u << i))) continue;
        total++;
        if (c->rule->strs[i].count > 0) matched++;
    }

    if (mode == 0) return matched >= 1 ? 1 : 0;
    if (mode == 1) return (total > 0 && matched == total) ? 1 : 0;
    if (mode == 2) return matched == 0 ? 1 : 0;
    return matched >= req_cnt ? 1 : 0;
}

static bool yr_parse_int_lit(yr_lex *lx, int64_t *out) {
    yr_skip_ws(lx);
    const char *p = lx->src + lx->pos;
    if (!isdigit((unsigned char)p[0])) return false;

    uint64_t v = 0;
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
        lx->pos += 2;
        int any = 0;
        while (for_hex_val(lx->src[lx->pos]) >= 0) {
            v = (v << 4) | (uint64_t)for_hex_val(lx->src[lx->pos++]);
            any = 1;
        }
        if (!any) { yr_set_err(lx, "invalid hex integer"); return false; }
        *out = (int64_t)v;
        return true;
    }

    while (isdigit((unsigned char)lx->src[lx->pos])) {
        v = v * 10 + (uint64_t)(lx->src[lx->pos++] - '0');
    }
    const char *s = lx->src + lx->pos;
    if ((s[0] == 'K' || s[0] == 'k') && (s[1] == 'B' || s[1] == 'b') && !yr_is_id(s[2])) {
        v *= 1024ULL;
        lx->pos += 2;
    } else if ((s[0] == 'M' || s[0] == 'm') && (s[1] == 'B' || s[1] == 'b') && !yr_is_id(s[2])) {
        v *= 1024ULL * 1024ULL;
        lx->pos += 2;
    } else if ((s[0] == 'G' || s[0] == 'g') && (s[1] == 'B' || s[1] == 'b') && !yr_is_id(s[2])) {
        v *= 1024ULL * 1024ULL * 1024ULL;
        lx->pos += 2;
    }
    *out = (int64_t)v;
    return true;
}

static bool yr_try_mem_fn(yr_cond *c, int64_t *out) {
    static const struct { const char *name; int w; int sgn; int be; } fns[] = {
        { "uint8",    1, 0, 0 },
        { "uint16",   2, 0, 0 },
        { "uint32",   4, 0, 0 },
        { "uint64",   8, 0, 0 },
        { "uint16be", 2, 0, 1 },
        { "uint32be", 4, 0, 1 },
        { "int8",     1, 1, 0 },
        { "int16",    2, 1, 0 },
        { "int32",    4, 1, 0 }
    };
    for (size_t i = 0; i < sizeof(fns) / sizeof(fns[0]); i++) {
        if (!yr_eat_kw(c->lx, fns[i].name)) continue;
        if (!yr_eat_ch(c->lx, '(')) { yr_set_err(c->lx, "expected '(' after integer reader"); return true; }
        int64_t off = yr_parse_or(c);
        if (!yr_eat_ch(c->lx, ')')) { yr_set_err(c->lx, "expected ')' after offset"); return true; }
        *out = yr_read_mem_int(c->buf, c->sz, off, fns[i].w, fns[i].sgn, fns[i].be);
        return true;
    }
    return false;
}

static int64_t yr_parse_primary(yr_cond *c) {
    yr_lex *lx = c->lx;
    if (lx->err[0]) return 0;
    if (++c->depth > YR_MAX_DEPTH) { yr_set_err(lx, "condition nesting too deep"); return 0; }
    yr_skip_ws(lx);

    int64_t res = 0;
    if (yr_eat_ch(lx, '(')) {
        res = yr_parse_or(c);
        if (!yr_eat_ch(lx, ')')) yr_set_err(lx, "expected ')'");
        c->depth--;
        return res;
    }
    if (yr_eat_kw(lx, "true"))     { c->depth--; return 1; }
    if (yr_eat_kw(lx, "false"))    { c->depth--; return 0; }
    if (yr_eat_kw(lx, "filesize")) { c->depth--; return (int64_t)c->sz; }
    if (yr_eat_kw(lx, "any")) {
        if (!yr_eat_kw(lx, "of")) { yr_set_err(lx, "expected 'of' after 'any'"); c->depth--; return 0; }
        res = yr_parse_of(c, 0, 0);
        c->depth--;
        return res;
    }
    if (yr_eat_kw(lx, "all")) {
        if (!yr_eat_kw(lx, "of")) { yr_set_err(lx, "expected 'of' after 'all'"); c->depth--; return 0; }
        res = yr_parse_of(c, 1, 0);
        c->depth--;
        return res;
    }
    if (yr_eat_kw(lx, "none")) {
        if (!yr_eat_kw(lx, "of")) { yr_set_err(lx, "expected 'of' after 'none'"); c->depth--; return 0; }
        res = yr_parse_of(c, 2, 0);
        c->depth--;
        return res;
    }
    if (yr_try_mem_fn(c, &res)) { c->depth--; return res; }

    char ch = lx->src[lx->pos];
    if (ch == '$' || ch == '#' || ch == '@') {
        lx->pos++;
        char id[24];
        size_t k = 0;
        id[k++] = '$';
        while (yr_is_id(lx->src[lx->pos])) {
            if (k + 1 < sizeof(id)) id[k++] = lx->src[lx->pos];
            lx->pos++;
        }
        id[k] = 0;
        const yr_str *st = yr_find_str(c->rule, id);
        if (!st) { yr_set_err(lx, "undefined string identifier"); c->depth--; return 0; }
        if (ch == '$') res = (st->count > 0) ? 1 : 0;
        else if (ch == '#') res = (int64_t)st->count;
        else res = (st->count > 0) ? (int64_t)st->first_off : 0;
        c->depth--;
        return res;
    }

    if (yr_parse_int_lit(lx, &res)) {
        if (yr_eat_kw(lx, "of")) res = yr_parse_of(c, 3, res);
        c->depth--;
        return res;
    }

    yr_set_err(lx, "unexpected token in condition");
    c->depth--;
    return 0;
}

static int64_t yr_parse_unary(yr_cond *c) {
    yr_skip_ws(c->lx);
    if (c->lx->src[c->lx->pos] == '-') {
        c->lx->pos++;
        return -yr_parse_unary(c);
    }
    return yr_parse_primary(c);
}

static int64_t yr_parse_mul(yr_cond *c) {
    int64_t lhs = yr_parse_unary(c);
    while (!c->lx->err[0]) {
        yr_skip_ws(c->lx);
        char op = c->lx->src[c->lx->pos];
        if (op != '*' && op != '/' && op != '%') break;
        c->lx->pos++;
        int64_t rhs = yr_parse_unary(c);
        if (op == '*') lhs *= rhs;
        else if (op == '/') lhs = (rhs != 0) ? (lhs / rhs) : 0;
        else lhs = (rhs != 0) ? (lhs % rhs) : 0;
    }
    return lhs;
}

static int64_t yr_parse_add(yr_cond *c) {
    int64_t lhs = yr_parse_mul(c);
    while (!c->lx->err[0]) {
        yr_skip_ws(c->lx);
        char op = c->lx->src[c->lx->pos];
        if (op != '+' && op != '-') break;
        c->lx->pos++;
        int64_t rhs = yr_parse_mul(c);
        lhs = (op == '+') ? (lhs + rhs) : (lhs - rhs);
    }
    return lhs;
}

static int64_t yr_parse_cmp(yr_cond *c) {
    int64_t lhs = yr_parse_add(c);
    if (c->lx->err[0]) return 0;
    yr_skip_ws(c->lx);
    const char *p = c->lx->src + c->lx->pos;
    int op = 0;
    if (p[0] == '=' && p[1] == '=') { op = 1; c->lx->pos += 2; }
    else if (p[0] == '!' && p[1] == '=') { op = 2; c->lx->pos += 2; }
    else if (p[0] == '<' && p[1] == '=') { op = 3; c->lx->pos += 2; }
    else if (p[0] == '>' && p[1] == '=') { op = 4; c->lx->pos += 2; }
    else if (p[0] == '<') { op = 5; c->lx->pos += 1; }
    else if (p[0] == '>') { op = 6; c->lx->pos += 1; }
    if (!op) return lhs;

    int64_t rhs = yr_parse_add(c);
    switch (op) {
    case 1: return lhs == rhs ? 1 : 0;
    case 2: return lhs != rhs ? 1 : 0;
    case 3: return lhs <= rhs ? 1 : 0;
    case 4: return lhs >= rhs ? 1 : 0;
    case 5: return lhs < rhs ? 1 : 0;
    case 6: return lhs > rhs ? 1 : 0;
    default: return 0;
    }
}

static int64_t yr_parse_not(yr_cond *c) {
    if (yr_eat_kw(c->lx, "not")) {
        return yr_parse_not(c) == 0 ? 1 : 0;
    }
    return yr_parse_cmp(c);
}

static int64_t yr_parse_and(yr_cond *c) {
    int64_t lhs = yr_parse_not(c);
    // always parse rhs so syntax errors and rule boundaries stay accurate
    while (!c->lx->err[0] && yr_eat_kw(c->lx, "and")) {
        int64_t rhs = yr_parse_not(c);
        lhs = (lhs != 0 && rhs != 0) ? 1 : 0;
    }
    return lhs;
}

static int64_t yr_parse_or(yr_cond *c) {
    int64_t lhs = yr_parse_and(c);
    while (!c->lx->err[0] && yr_eat_kw(c->lx, "or")) {
        int64_t rhs = yr_parse_and(c);
        lhs = (lhs != 0 || rhs != 0) ? 1 : 0;
    }
    return lhs;
}

static bool yr_parse_meta_sec(yr_lex *lx, yr_rule *r) {
    for (;;) {
        yr_skip_ws(lx);
        if (lx->err[0]) return false;
        if (lx->src[lx->pos] == '}' || yr_peek_section(lx, "strings") || yr_peek_section(lx, "condition")) {
            return true;
        }
        char key[32];
        if (!yr_read_ident(lx, key, sizeof(key))) { yr_set_err(lx, "expected meta key"); return false; }
        if (!yr_eat_ch(lx, '=')) { yr_set_err(lx, "expected '=' in meta"); return false; }
        yr_skip_ws(lx);
        if (lx->src[lx->pos] == '"') {
            uint8_t val[96];
            size_t vlen = 0;
            if (!yr_parse_quoted(lx, val, sizeof(val) - 1, &vlen)) return false;
            val[vlen] = 0;
            if (_stricmp(key, "description") == 0 || (_stricmp(key, "desc") == 0 && !r->desc[0])) {
                snprintf(r->desc, sizeof(r->desc), "%s", (const char *)val);
            }
        } else if (yr_eat_kw(lx, "true") || yr_eat_kw(lx, "false")) {
            continue;
        } else {
            int64_t iv = 0;
            if (lx->src[lx->pos] == '-') lx->pos++;
            if (!yr_parse_int_lit(lx, &iv)) { yr_set_err(lx, "invalid meta value"); return false; }
        }
    }
}

static bool yr_parse_strings_sec(yr_lex *lx, yr_rule *r) {
    for (;;) {
        yr_skip_ws(lx);
        if (lx->err[0]) return false;
        if (lx->src[lx->pos] != '$') return true;

        char id[24];
        size_t k = 0;
        id[k++] = lx->src[lx->pos++];
        while (yr_is_id(lx->src[lx->pos])) {
            if (k + 1 < sizeof(id)) id[k++] = lx->src[lx->pos];
            lx->pos++;
        }
        id[k] = 0;
        if (k == 1) snprintf(id, sizeof(id), "$anon%d", r->nstr);

        if (!yr_eat_ch(lx, '=')) { yr_set_err(lx, "expected '=' in string def"); return false; }

        yr_str tmp;
        memset(&tmp, 0, sizeof(tmp));
        snprintf(tmp.id, sizeof(tmp.id), "%s", id);

        yr_skip_ws(lx);
        if (lx->src[lx->pos] == '"') {
            if (!yr_parse_quoted(lx, tmp.txt, YR_TXT_MAX, &tmp.txt_len)) return false;
            if (tmp.txt_len == 0) { yr_set_err(lx, "empty string pattern"); return false; }
            int enc_set = 0;
            for (;;) {
                if (yr_eat_kw(lx, "ascii"))         { tmp.mods |= YR_MOD_ASCII; enc_set = 1; }
                else if (yr_eat_kw(lx, "wide"))     { tmp.mods |= YR_MOD_WIDE;  enc_set = 1; }
                else if (yr_eat_kw(lx, "nocase"))   { tmp.mods |= YR_MOD_NOCASE; }
                else if (yr_eat_kw(lx, "fullword")) { tmp.mods |= YR_MOD_FULLWORD; }
                else break;
            }
            if (!enc_set) tmp.mods |= YR_MOD_ASCII;
        } else if (lx->src[lx->pos] == '{') {
            if (!yr_parse_hex(lx, &tmp)) return false;
        } else {
            yr_set_err(lx, "expected quoted string or hex '{...}'");
            return false;
        }

        if (r->nstr < YR_MAX_STRS) r->strs[r->nstr++] = tmp;
    }
}

static bool yr_parse_and_run_rule(yr_lex *lx, const ana_ctx *a, yr_rule *r, for_yara_res *out) {
    memset(r, 0, sizeof(*r));
    while (yr_eat_kw(lx, "private") || yr_eat_kw(lx, "global")) { }
    if (!yr_eat_kw(lx, "rule")) { yr_set_err(lx, "expected 'rule'"); return false; }
    if (!yr_read_ident(lx, r->name, sizeof(r->name))) { yr_set_err(lx, "expected rule name"); return false; }

    if (yr_eat_ch(lx, ':')) {
        char tag[32];
        while (yr_read_ident(lx, tag, sizeof(tag))) { }
    }
    if (!yr_eat_ch(lx, '{')) { yr_set_err(lx, "expected '{' after rule name"); return false; }

    int has_cond = 0;
    int64_t cond_val = 0;
    for (;;) {
        yr_skip_ws(lx);
        if (lx->err[0]) return false;
        if (yr_eat_ch(lx, '}')) break;

        if (yr_peek_section(lx, "meta")) {
            yr_eat_kw(lx, "meta");
            yr_eat_ch(lx, ':');
            if (!yr_parse_meta_sec(lx, r)) return false;
        } else if (yr_peek_section(lx, "strings")) {
            yr_eat_kw(lx, "strings");
            yr_eat_ch(lx, ':');
            if (!yr_parse_strings_sec(lx, r)) return false;
        } else if (yr_peek_section(lx, "condition")) {
            if (has_cond) { yr_set_err(lx, "duplicate condition section"); return false; }
            yr_eat_kw(lx, "condition");
            yr_eat_ch(lx, ':');
            yr_scan_rule_strs(a->bin.map.data, (size_t)a->bin.map.size, r);
            yr_cond cp = { lx, r, a->bin.map.data, (size_t)a->bin.map.size, 0 };
            cond_val = yr_parse_or(&cp);
            if (lx->err[0]) return false;
            has_cond = 1;
        } else {
            yr_set_err(lx, "unexpected token in rule body");
            return false;
        }
    }

    if (!has_cond) { yr_set_err(lx, "missing condition section"); return false; }
    out->nrules++;

    if (cond_val != 0 && out->nhit < 128) {
        for_yara_hit *h = &out->hits[out->nhit++];
        memset(h, 0, sizeof(*h));
        snprintf(h->rule, sizeof(h->rule), "%s", r->name);
        snprintf(h->desc, sizeof(h->desc), "%s", r->desc);

        int total = 0;
        const yr_str *first = NULL;
        for (int i = 0; i < r->nstr; i++) {
            if (r->strs[i].count <= 0) continue;
            if (!first) first = &r->strs[i];
            total += r->strs[i].count;
        }
        if (first) {
            snprintf(h->match_id, sizeof(h->match_id), "%s", first->id);
            h->off = first->first_off;
            h->nmatch = total;
        } else {
            snprintf(h->match_id, sizeof(h->match_id), "cond");
            h->off = 0;
            h->nmatch = 1;
        }
        uint64_t va = 0;
        h->va = bin_off_to_va(&a->bin, h->off, &va) ? va : h->off;
    }
    return true;
}

bool for_yara_scan(const ana_ctx *a, const char *rules_text, for_yara_res *out) {
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    if (!a || !a->bin.map.data || a->bin.map.size == 0) {
        snprintf(out->err, sizeof(out->err), "no binary loaded");
        return false;
    }
    if (!rules_text || !rules_text[0]) {
        snprintf(out->err, sizeof(out->err), "empty rules");
        return false;
    }

    yr_rule *r = (yr_rule *)calloc(1, sizeof(yr_rule));
    if (!r) {
        snprintf(out->err, sizeof(out->err), "out of memory");
        return false;
    }

    yr_lex lx = { rules_text, 0, "" };
    for (;;) {
        yr_skip_ws(&lx);
        if (lx.err[0]) break;
        if (!lx.src[lx.pos]) break;
        if (!yr_parse_and_run_rule(&lx, a, r, out)) break;
    }

    free(r);
    if (lx.err[0]) {
        snprintf(out->err, sizeof(out->err), "%s", lx.err);
        return false;
    }
    if (out->nrules == 0) {
        snprintf(out->err, sizeof(out->err), "no rules found");
        return false;
    }
    return true;
}

static void crv_add(const ana_ctx *a, for_carve_res *out, const char *kind,
                    uint64_t off, uint64_t size, const char *detail) {
    if (out->nhit >= 128) return;
    for_carve_hit *h = &out->hits[out->nhit++];
    memset(h, 0, sizeof(*h));
    snprintf(h->kind, sizeof(h->kind), "%s", kind);
    h->off = off;
    uint64_t va = 0;
    h->va = bin_off_to_va(&a->bin, off, &va) ? va : 0;
    h->size = size;
    size_t esz = (size > 16384) ? 16384 : (size_t)size;
    if (off + esz > a->bin.map.size) esz = (size_t)(a->bin.map.size - off);
    h->ent = ana_entropy(a->bin.map.data + off, esz);
    snprintf(h->detail, sizeof(h->detail), "%s", detail ? detail : "");
}

static bool crv_try_pe(const ana_ctx *a, size_t off, for_carve_res *out) {
    const uint8_t *d = a->bin.map.data;
    size_t sz = (size_t)a->bin.map.size;
    if (off == 0 || off + 0x46 > sz) return false;
    if (d[off] != 'M' || d[off + 1] != 'Z') return false;

    uint32_t lfanew = for_rd32_le(d + off + 0x3C);
    if (lfanew < 0x40 || lfanew > 0x400) return false;
    if (off + (size_t)lfanew + 24 > sz) return false;
    if (memcmp(d + off + lfanew, "PE\0\0", 4) != 0) return false;

    uint16_t mach = for_rd16_le(d + off + lfanew + 4);
    const char *arch = NULL;
    if (mach == 0x8664) arch = "PE64";
    else if (mach == 0x014C) arch = "PE32";
    else if (mach == 0xAA64) arch = "PE-ARM64";
    else return false;

    uint16_t nsec = for_rd16_le(d + off + lfanew + 6);
    uint16_t opt_sz = for_rd16_le(d + off + lfanew + 20);
    uint64_t remain = (uint64_t)(sz - off);
    uint64_t max_end = 0;

    if (nsec > 0 && nsec <= 96 && opt_sz <= 0x400) {
        size_t sec_base = off + (size_t)lfanew + 24 + (size_t)opt_sz;
        for (uint16_t i = 0; i < nsec; i++) {
            size_t sp = sec_base + (size_t)i * 40;
            if (sp + 40 > sz) break;
            uint64_t rsz = for_rd32_le(d + sp + 16);
            uint64_t rptr = for_rd32_le(d + sp + 20);
            if (rptr + rsz > max_end && rptr + rsz <= remain) max_end = rptr + rsz;
        }
    }

    uint64_t est = max_end ? max_end : (remain < 4096 ? remain : 4096);
    char det[64];
    if (nsec > 0 && nsec <= 96) snprintf(det, sizeof(det), "%s (%u secs)", arch, nsec);
    else snprintf(det, sizeof(det), "%s", arch);
    crv_add(a, out, "PE", (uint64_t)off, est, det);
    return true;
}

static bool crv_try_elf(const ana_ctx *a, size_t off, for_carve_res *out) {
    const uint8_t *d = a->bin.map.data;
    size_t sz = (size_t)a->bin.map.size;
    if (off == 0 || off + 52 > sz) return false;
    if (memcmp(d + off, "\x7F" "ELF", 4) != 0) return false;
    uint8_t cls = d[off + 4];
    uint8_t enc = d[off + 5];
    if ((cls != 1 && cls != 2) || (enc != 1 && enc != 2)) return false;

    uint64_t remain = (uint64_t)(sz - off);
    uint64_t est = 0;
    if (enc == 1) {
        if (cls == 2 && off + 64 <= sz) {
            uint64_t shoff = for_rd64_le(d + off + 40);
            uint16_t shent = for_rd16_le(d + off + 58);
            uint16_t shnum = for_rd16_le(d + off + 60);
            if (shoff > 0 && shent > 0 && shnum > 0 && shoff < remain) {
                uint64_t span = (uint64_t)shent * (uint64_t)shnum;
                if (span <= remain - shoff) est = shoff + span;
            }
        } else if (cls == 1) {
            uint64_t shoff = for_rd32_le(d + off + 32);
            uint16_t shent = for_rd16_le(d + off + 46);
            uint16_t shnum = for_rd16_le(d + off + 48);
            if (shoff > 0 && shent > 0 && shnum > 0 && shoff < remain) {
                uint64_t span = (uint64_t)shent * (uint64_t)shnum;
                if (span <= remain - shoff) est = shoff + span;
            }
        }
    }
    if (est == 0) est = remain < 4096 ? remain : 4096;

    char det[64];
    snprintf(det, sizeof(det), "ELF%d %s", cls == 2 ? 64 : 32, enc == 1 ? "LE" : "BE");
    crv_add(a, out, "ELF", (uint64_t)off, est, det);
    return true;
}

static bool crv_try_zip(const ana_ctx *a, size_t off, size_t *last_zip_end, for_carve_res *out) {
    const uint8_t *d = a->bin.map.data;
    size_t sz = (size_t)a->bin.map.size;
    if (off < *last_zip_end || off + 30 > sz) return false;
    if (memcmp(d + off, "PK\x03\x04", 4) != 0) return false;

    uint16_t ver = for_rd16_le(d + off + 4);
    uint16_t meth = for_rd16_le(d + off + 8);
    uint16_t nlen = for_rd16_le(d + off + 26);
    if (ver < 10 || ver > 100) return false;
    if (meth > 20 && meth != 98 && meth != 99) return false;
    if (nlen == 0 || nlen > 260 || off + 30 + nlen > sz) return false;
    for (uint16_t i = 0; i < nlen; i++) {
        uint8_t c = d[off + 30 + i];
        if (c < 0x20 || c > 0x7E) return false;
    }

    char fname[48];
    size_t fl = nlen < sizeof(fname) - 1 ? (size_t)nlen : sizeof(fname) - 1;
    memcpy(fname, d + off + 30, fl);
    fname[fl] = 0;

    size_t lim = sz;
    if (lim - off > (4u << 20)) lim = off + (4u << 20);
    uint64_t est = 0;
    size_t p = off + 30 + nlen;
    while (p + 22 <= lim) {
        size_t rel = scan_byte_fast(d + p, lim - p - 21, 'P');
        if (rel >= lim - p - 21) break;
        size_t cand = p + rel;
        if (d[cand + 1] == 'K' && d[cand + 2] == 0x05 && d[cand + 3] == 0x06) {
            uint16_t clen = for_rd16_le(d + cand + 20);
            uint64_t end = (uint64_t)(cand - off) + 22ULL + (uint64_t)clen;
            if (end > (uint64_t)(sz - off)) end = (uint64_t)(sz - off);
            est = end;
            break;
        }
        p = cand + 1;
    }
    if (est == 0) {
        uint64_t remain = (uint64_t)(sz - off);
        est = remain < 4096 ? remain : 4096;
    }

    *last_zip_end = off + (size_t)est;
    char det[64];
    snprintf(det, sizeof(det), "entry: %s", fname);
    crv_add(a, out, "ZIP", (uint64_t)off, est, det);
    return true;
}

static bool crv_try_gzip(const ana_ctx *a, size_t off, for_carve_res *out) {
    const uint8_t *d = a->bin.map.data;
    size_t sz = (size_t)a->bin.map.size;
    if (off + 18 > sz) return false;
    if (d[off] != 0x1F || d[off + 1] != 0x8B || d[off + 2] != 0x08) return false;
    uint8_t flg = d[off + 3];
    if ((flg & 0xE0u) != 0) return false;
    uint8_t xfl = d[off + 8];
    uint8_t os = d[off + 9];
    if (xfl != 0 && xfl != 2 && xfl != 4) return false;
    if (os > 13 && os != 255) return false;

    char det[64] = "deflate stream";
    if (flg & 0x08u) {
        size_t p = off + 10;
        if ((flg & 0x04u) && p + 2 <= sz) p += 2 + for_rd16_le(d + p);
        size_t k = 0;
        char fn[48];
        while (p + k < sz && k + 1 < sizeof(fn) && d[p + k] >= 0x20 && d[p + k] <= 0x7E) {
            fn[k] = (char)d[p + k];
            k++;
        }
        if (k > 0 && p + k < sz && d[p + k] == 0) {
            fn[k] = 0;
            snprintf(det, sizeof(det), "name: %s", fn);
        }
    }

    uint64_t remain = (uint64_t)(sz - off);
    crv_add(a, out, "GZIP", (uint64_t)off, remain < 4096 ? remain : 4096, det);
    return true;
}

static bool crv_try_png(const ana_ctx *a, size_t off, for_carve_res *out) {
    const uint8_t *d = a->bin.map.data;
    size_t sz = (size_t)a->bin.map.size;
    static const uint8_t sig[8] = { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A };
    if (off + 33 > sz || memcmp(d + off, sig, 8) != 0) return false;

    uint32_t w = 0, h = 0;
    size_t p = off + 8;
    bool got_end = false;
    for (int ci = 0; ci < 4096 && p + 12 <= sz; ci++) {
        uint32_t clen = for_rd32_be(d + p);
        const uint8_t *ct = d + p + 4;
        if (!isalpha(ct[0]) || !isalpha(ct[1]) || !isalpha(ct[2]) || !isalpha(ct[3])) break;
        if ((uint64_t)clen > (uint64_t)(sz - p - 12)) break;
        if (ci == 0 && memcmp(ct, "IHDR", 4) == 0 && clen >= 8) {
            w = for_rd32_be(d + p + 8);
            h = for_rd32_be(d + p + 12);
        }
        p += 12 + (size_t)clen;
        if (memcmp(ct, "IEND", 4) == 0) { got_end = true; break; }
    }

    uint64_t est = got_end ? (uint64_t)(p - off)
                           : ((sz - off < 4096) ? (uint64_t)(sz - off) : 4096ULL);
    char det[64];
    if (w && h) snprintf(det, sizeof(det), "%ux%u%s", w, h, got_end ? "" : " (truncated)");
    else snprintf(det, sizeof(det), "%s", got_end ? "PNG image" : "PNG (truncated)");
    crv_add(a, out, "PNG", (uint64_t)off, est, det);
    return true;
}

static bool crv_try_jpeg(const ana_ctx *a, size_t off, for_carve_res *out) {
    const uint8_t *d = a->bin.map.data;
    size_t sz = (size_t)a->bin.map.size;
    if (off + 16 > sz) return false;
    if (d[off] != 0xFF || d[off + 1] != 0xD8 || d[off + 2] != 0xFF) return false;
    uint8_t m = d[off + 3];
    if (m != 0xE0 && m != 0xE1 && m != 0xDB && m != 0xEE) return false;

    size_t lim = sz;
    if (lim - off > (2u << 20)) lim = off + (2u << 20);
    size_t p = off + 4;
    uint64_t est = 0;
    while (p + 2 <= lim) {
        size_t rel = scan_byte_fast(d + p, lim - p - 1, 0xFF);
        if (rel >= lim - p - 1) break;
        size_t cand = p + rel;
        if (d[cand + 1] == 0xD9) {
            est = (uint64_t)(cand + 2 - off);
            break;
        }
        p = cand + 1;
    }
    if (est == 0) return false;

    const char *det = (m == 0xE0) ? "JFIF" : (m == 0xE1) ? "EXIF" : "JPEG image";
    crv_add(a, out, "JPEG", (uint64_t)off, est, det);
    return true;
}

static bool crv_try_x509(const ana_ctx *a, size_t off, for_carve_res *out) {
    const uint8_t *d = a->bin.map.data;
    size_t sz = (size_t)a->bin.map.size;
    if (off + 16 > sz) return false;
    if (d[off] != 0x30 || d[off + 1] != 0x82) return false;
    uint32_t outer = for_rd16_be(d + off + 2);
    uint64_t total = 4ULL + (uint64_t)outer;
    if (outer < 128 || total > (uint64_t)(sz - off)) return false;
    if (d[off + 4] != 0x30 || d[off + 5] != 0x82) return false;
    uint32_t inner = for_rd16_be(d + off + 6);
    if (inner < 64 || inner >= outer) return false;

    crv_add(a, out, "X509", (uint64_t)off, total, "ASN.1 DER certificate");
    return true;
}

int for_carve(const ana_ctx *a, for_carve_res *out) {
    if (!out) return 0;
    memset(out, 0, sizeof(*out));
    if (!a || !a->bin.map.data || a->bin.map.size == 0) return 0;

    static const uint8_t magic_lut[256] = {
        ['M']  = 1,
        [0x7F] = 1,
        ['P']  = 1,
        [0x1F] = 1,
        [0x89] = 1,
        [0xFF] = 1,
        [0x30] = 1
    };

    const uint8_t *d = a->bin.map.data;
    size_t sz = (size_t)a->bin.map.size;
    size_t last_zip_end = 0;

    // leave 1 slot reserved for PE overlay if present
    for (size_t off = 0; off < sz && out->nhit < 127; off++) {
        uint8_t b = d[off];
        if (!magic_lut[b]) continue;

        if (b == 'M')         crv_try_pe(a, off, out);
        else if (b == 0x7F)   crv_try_elf(a, off, out);
        else if (b == 'P')    crv_try_zip(a, off, &last_zip_end, out);
        else if (b == 0x1F)   crv_try_gzip(a, off, out);
        else if (b == 0x89)   crv_try_png(a, off, out);
        else if (b == 0xFF)   crv_try_jpeg(a, off, out);
        else if (b == 0x30)   crv_try_x509(a, off, out);
    }

    if ((a->bin.fmt == BIN_PE32 || a->bin.fmt == BIN_PE64) && out->nhit < 128) {
        uint64_t pe_end = 0;
        for (uint32_t i = 0; i < a->bin.nsec; i++) {
            uint64_t end = a->bin.secs[i].foff + a->bin.secs[i].fsize;
            if (end > pe_end) pe_end = end;
        }
        if (pe_end > 0 && a->bin.map.size > pe_end && (a->bin.map.size - pe_end) >= 256) {
            crv_add(a, out, "OVERLAY", pe_end, a->bin.map.size - pe_end, "appended data after last PE section");
        }
    }

    return out->nhit;
}

bool for_extract(const ana_ctx *a, uint64_t off, uint64_t size, const char *out_path) {
    if (!a || !a->bin.map.data || !out_path || !out_path[0]) return false;
    if (off >= a->bin.map.size || size == 0 || size > a->bin.map.size - off) return false;

    FILE *f = fopen(out_path, "wb");
    if (!f) return false;

    const size_t chunk = 1u << 20;
    uint64_t done = 0;
    while (done < size) {
        size_t n = (size - done > chunk) ? chunk : (size_t)(size - done);
        if (fwrite(a->bin.map.data + off + done, 1, n, f) != n) {
            fclose(f);
            return false;
        }
        done += n;
    }
    return fclose(f) == 0;
}

static bool ioc_istarts(const char *s, const char *pfx) {
    while (*pfx) {
        if (!*s || tolower((unsigned char)*s) != tolower((unsigned char)*pfx)) return false;
        s++;
        pfx++;
    }
    return true;
}

static void ioc_add(for_ioc_res *out, const char *kind, uint64_t va, const char *s, size_t len) {
    if (out->nhit >= 256 || !s || len == 0) return;

    while (len > 0 && isspace((unsigned char)s[0])) { s++; len--; }
    while (len > 0) {
        char c = s[len - 1];
        if (isspace((unsigned char)c) || c == ',' || c == ';' || c == ')' ||
            c == ']' || c == '>' || c == '\'' || c == '"') {
            len--;
        } else if (c == '.' && (strcmp(kind, "URL") == 0 || strcmp(kind, "EMAIL") == 0)) {
            len--;
        } else {
            break;
        }
    }
    if (len == 0) return;
    if (len >= sizeof(out->hits[0].value)) len = sizeof(out->hits[0].value) - 1;

    char val[128];
    memcpy(val, s, len);
    val[len] = 0;

    for (int i = 0; i < out->nhit; i++) {
        if (strcmp(out->hits[i].kind, kind) == 0 && _stricmp(out->hits[i].value, val) == 0) {
            return;
        }
    }

    for_ioc_hit *h = &out->hits[out->nhit++];
    snprintf(h->kind, sizeof(h->kind), "%s", kind);
    h->va = va;
    snprintf(h->value, sizeof(h->value), "%s", val);
}

static void ioc_scan_urls(const char *s, uint64_t va, for_ioc_res *out) {
    static const char *const schemes[] = { "https://", "http://", "ftp://", "wss://", "ws://", NULL };
    for (const char *p = s; *p && out->nhit < 256; p++) {
        for (int i = 0; schemes[i]; i++) {
            if (!ioc_istarts(p, schemes[i])) continue;
            size_t slen = strlen(schemes[i]);
            size_t len = slen;
            int has_sep = 0;
            while (p[len] && (unsigned char)p[len] > 0x20 && (unsigned char)p[len] < 0x7F &&
                   p[len] != '"' && p[len] != '\'' && p[len] != '<' && p[len] != '>' && p[len] != '`') {
                if (p[len] == '.' || p[len] == ':' || p[len] == '/') has_sep = 1;
                len++;
            }
            if (len >= slen + 4 && has_sep) {
                ioc_add(out, "URL", va, p, len);
                p += len - 1;
            }
            break;
        }
    }
}

static void ioc_scan_reg(const char *s, uint64_t va, for_ioc_res *out) {
    static const char *const pfxs[] = {
        "HKEY_LOCAL_MACHINE\\",
        "HKEY_CURRENT_USER\\",
        "HKEY_CLASSES_ROOT\\",
        "HKEY_USERS\\",
        "HKLM\\",
        "HKCU\\",
        "HKCR\\",
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\",
        "SYSTEM\\CurrentControlSet\\",
        NULL
    };
    for (const char *p = s; *p && out->nhit < 256; p++) {
        if (p > s && (isalnum((unsigned char)p[-1]) || p[-1] == '\\')) continue;
        for (int i = 0; pfxs[i]; i++) {
            if (!ioc_istarts(p, pfxs[i])) continue;
            size_t plen = strlen(pfxs[i]);
            size_t len = plen;
            while (p[len] && (unsigned char)p[len] >= 0x20 && (unsigned char)p[len] < 0x7F &&
                   p[len] != '"' && p[len] != '\'' && p[len] != '<' && p[len] != '>') {
                len++;
            }
            if (len > plen) {
                ioc_add(out, "REG", va, p, len);
                p += len - 1;
            }
            break;
        }
    }
}

static void ioc_scan_paths(const char *s, uint64_t va, for_ioc_res *out) {
    static const char *const win_pfxs[] = {
        "C:\\Windows\\", "C:\\Users\\", "C:\\ProgramData\\",
        "%APPDATA%", "%LOCALAPPDATA%", "%TEMP%", "%TMP%", "%SYSTEMROOT%", "%USERPROFILE%",
        "\\\\.\\", "\\\\?\\", NULL
    };
    static const char *const nix_pfxs[] = {
        "/etc/passwd", "/etc/shadow", "/etc/hosts", "/tmp/", "/var/tmp/", "/dev/shm/", NULL
    };

    for (const char *p = s; *p && out->nhit < 256; p++) {
        int matched = 0;
        for (int i = 0; win_pfxs[i]; i++) {
            if (!ioc_istarts(p, win_pfxs[i])) continue;
            size_t plen = strlen(win_pfxs[i]);
            if (p > s && isalnum((unsigned char)p[-1])) continue;
            size_t len = plen;
            while (p[len] && (unsigned char)p[len] >= 0x20 && (unsigned char)p[len] < 0x7F &&
                   p[len] != '"' && p[len] != '\'' && p[len] != '<' && p[len] != '>') {
                len++;
            }
            bool is_dev = (win_pfxs[i][0] == '\\');
            if ((is_dev && len >= plen + 2) || (!is_dev && len >= plen)) {
                ioc_add(out, "PATH", va, p, len);
                p += len - 1;
                matched = 1;
            }
            break;
        }
        if (matched) continue;

        if (*p == '/' && (p == s || (!isalnum((unsigned char)p[-1]) && p[-1] != '/' && p[-1] != ':'))) {
            for (int i = 0; nix_pfxs[i]; i++) {
                if (strncmp(p, nix_pfxs[i], strlen(nix_pfxs[i])) != 0) continue;
                size_t len = strlen(nix_pfxs[i]);
                while (p[len] && (unsigned char)p[len] > 0x20 && (unsigned char)p[len] < 0x7F &&
                       p[len] != '"' && p[len] != '\'' && p[len] != '<' && p[len] != '>') {
                    len++;
                }
                ioc_add(out, "PATH", va, p, len);
                p += len - 1;
                break;
            }
        }
    }
}

static void ioc_scan_ipv4(const char *s, uint64_t va, for_ioc_res *out) {
    for (const char *p = s; *p && out->nhit < 256; p++) {
        if (!isdigit((unsigned char)*p)) continue;
        if (p > s && (isdigit((unsigned char)p[-1]) || p[-1] == '.')) continue;

        const char *q = p;
        unsigned int oct[4] = {0};
        int ok = 1;
        for (int k = 0; k < 4; k++) {
            if (!isdigit((unsigned char)*q)) { ok = 0; break; }
            if (q[0] == '0' && isdigit((unsigned char)q[1])) { ok = 0; break; }
            unsigned int v = 0;
            int nd = 0;
            while (isdigit((unsigned char)*q) && nd < 4) {
                v = v * 10u + (unsigned int)(*q++ - '0');
                nd++;
            }
            if (nd == 0 || nd > 3 || v > 255u) { ok = 0; break; }
            oct[k] = v;
            if (k < 3) {
                if (*q != '.') { ok = 0; break; }
                q++;
            }
        }
        if (!ok || *q == '.' || isdigit((unsigned char)*q)) continue;

        // drop placeholder, broadcast, loopback, and obvious X.0.0.0 version numbers
        if (oct[0] == 0) continue;
        if (oct[0] == 255 && oct[1] == 255 && oct[2] == 255 && oct[3] == 255) continue;
        if (oct[0] == 127 && oct[1] == 0 && oct[2] == 0 && (oct[3] == 0 || oct[3] == 1)) continue;
        if (oct[1] == 0 && oct[2] == 0 && oct[3] == 0) continue;

        ioc_add(out, "IPV4", va, p, (size_t)(q - p));
        p = q - 1;
    }
}

static void ioc_scan_mutex(const char *s, uint64_t va, for_ioc_res *out) {
    static const char *const pfxs[] = { "Global\\", "Local\\", NULL };
    for (const char *p = s; *p && out->nhit < 256; p++) {
        if (p > s && (isalnum((unsigned char)p[-1]) || p[-1] == '\\')) continue;
        for (int i = 0; pfxs[i]; i++) {
            size_t plen = strlen(pfxs[i]);
            if (strncmp(p, pfxs[i], plen) != 0) continue;
            size_t len = plen;
            while (p[len] && (isalnum((unsigned char)p[len]) || p[len] == '_' || p[len] == '-' ||
                              p[len] == '.' || p[len] == '{' || p[len] == '}')) {
                len++;
            }
            if (len >= plen + 3) {
                ioc_add(out, "MUTEX", va, p, len);
                p += len - 1;
            }
            break;
        }
    }
}

static bool ioc_bad_tld(const char *tld, size_t n) {
    static const char *const skip[] = { "dll", "exe", "sys", "obj", "pdb", "lib", "bin", NULL };
    for (int i = 0; skip[i]; i++) {
        if (strlen(skip[i]) == n && _strnicmp(tld, skip[i], n) == 0) return true;
    }
    return false;
}

static void ioc_scan_email(const char *s, uint64_t va, for_ioc_res *out) {
    for (const char *at = strchr(s, '@'); at && out->nhit < 256; at = strchr(at + 1, '@')) {
        if (at == s || at[1] == '@') continue;
        const char *ls = at;
        while (ls > s && (isalnum((unsigned char)ls[-1]) || ls[-1] == '.' ||
                          ls[-1] == '_' || ls[-1] == '%' || ls[-1] == '+' || ls[-1] == '-')) {
            ls--;
        }
        if (ls > s && (ls[-1] == '?' || ls[-1] == '@')) continue;
        size_t llen = (size_t)(at - ls);
        if (llen < 1 || llen > 64 || !isalnum((unsigned char)ls[0]) || !isalnum((unsigned char)at[-1])) continue;

        const char *ds = at + 1;
        const char *de = ds;
        const char *last_dot = NULL;
        int bad_dom = 0;
        while (*de && (isalnum((unsigned char)*de) || *de == '.' || *de == '-')) {
            if (*de == '.') {
                if (de == ds || de[-1] == '.') { bad_dom = 1; break; }
                last_dot = de;
            }
            de++;
        }
        if (bad_dom || !last_dot || *de == '@' || (size_t)(de - ds) > 64) continue;
        size_t tlen = (size_t)(de - (last_dot + 1));
        if (tlen < 2 || tlen > 10) continue;
        int alpha_tld = 1;
        for (size_t i = 0; i < tlen; i++) {
            if (!isalpha((unsigned char)last_dot[1 + i])) { alpha_tld = 0; break; }
        }
        if (!alpha_tld || ioc_bad_tld(last_dot + 1, tlen)) continue;

        ioc_add(out, "EMAIL", va, ls, (size_t)(de - ls));
    }
}

static bool ioc_is_b58(char c) {
    if (c == '0' || c == 'O' || c == 'I' || c == 'l') return false;
    return isalnum((unsigned char)c) != 0;
}

static bool ioc_is_bech32(char c) {
    return (c >= 'a' && c <= 'z' && c != 'b' && c != 'i' && c != 'o') ||
           (c >= '0' && c <= '9' && c != '1');
}

static void ioc_scan_btc(const char *s, uint64_t va, for_ioc_res *out) {
    for (const char *p = s; *p && out->nhit < 256; p++) {
        if (p > s && (isalnum((unsigned char)p[-1]) || p[-1] == '_' || p[-1] == '\\' || p[-1] == '/')) continue;

        if (strncmp(p, "bc1q", 4) == 0 || strncmp(p, "bc1p", 4) == 0) {
            size_t len = 4;
            while (p[len] && ioc_is_bech32(p[len])) len++;
            if ((len == 42 || len == 62) && !isalnum((unsigned char)p[len])) {
                ioc_add(out, "BTC", va, p, len);
                p += len - 1;
            }
            continue;
        }

        if (*p == '1' || *p == '3') {
            size_t len = 0;
            int has_up = 0, has_lo = 0, has_dg = 0;
            while (p[len] && ioc_is_b58(p[len]) && len <= 36) {
                if (isupper((unsigned char)p[len])) has_up = 1;
                else if (islower((unsigned char)p[len])) has_lo = 1;
                else if (isdigit((unsigned char)p[len])) has_dg = 1;
                len++;
            }
            if (len >= 26 && len <= 35 && has_up && has_lo && has_dg && !isalnum((unsigned char)p[len])) {
                ioc_add(out, "BTC", va, p, len);
                p += len - 1;
            }
        }
    }
}

static void ioc_inspect_str(const char *s, uint64_t va, for_ioc_res *out) {
    if (!s || !s[0] || out->nhit >= 256) return;
    ioc_scan_urls(s, va, out);
    ioc_scan_reg(s, va, out);
    ioc_scan_paths(s, va, out);
    ioc_scan_mutex(s, va, out);
    ioc_scan_ipv4(s, va, out);
    ioc_scan_email(s, va, out);
    ioc_scan_btc(s, va, out);
}

static void ioc_fallback_raw(const ana_ctx *a, for_ioc_res *out) {
    const uint8_t *d = a->bin.map.data;
    size_t sz = (size_t)a->bin.map.size;
    if (sz > (32u << 20)) sz = (32u << 20);

    char buf[256];
    size_t pos = 0;
    while (pos + 5 <= sz && out->nhit < 256) {
        size_t s = scan_ascii_next_x64(d, sz, pos);
        if (s + 5 > sz) break;
        size_t run = scan_ascii_run_x64(d + s, sz - s);
        if (run >= 5) {
            size_t cp = run < sizeof(buf) - 1 ? run : sizeof(buf) - 1;
            memcpy(buf, d + s, cp);
            buf[cp] = 0;
            uint64_t va = 0;
            if (!bin_off_to_va(&a->bin, s, &va)) va = (uint64_t)s;
            ioc_inspect_str(buf, va, out);
        }
        pos = s + (run ? run : 1);
    }

    size_t i = 0;
    while (i + 10 <= sz && out->nhit < 256) {
        if (d[i] >= 0x20 && d[i] <= 0x7E && d[i + 1] == 0) {
            size_t cnt = 0;
            while (i + cnt * 2 + 1 < sz && cnt < sizeof(buf) - 1 &&
                   d[i + cnt * 2] >= 0x20 && d[i + cnt * 2] <= 0x7E &&
                   d[i + cnt * 2 + 1] == 0) {
                buf[cnt] = (char)d[i + cnt * 2];
                cnt++;
            }
            if (cnt >= 5) {
                buf[cnt] = 0;
                uint64_t va = 0;
                if (!bin_off_to_va(&a->bin, i, &va)) va = (uint64_t)i;
                ioc_inspect_str(buf, va, out);
            }
            i += cnt * 2 + 2;
        } else {
            i += 2;
        }
    }
}

int for_extract_iocs(const ana_ctx *a, for_ioc_res *out) {
    if (!out) return 0;
    memset(out, 0, sizeof(*out));
    if (!a || !a->bin.map.data || a->bin.map.size == 0) return 0;

    if (a->nstr > 0) {
        char buf[256];
        for (uint32_t i = 0; i < a->nstr && out->nhit < 256; i++) {
            size_t n = ana_read_str(a, &a->strs[i], buf, sizeof(buf));
            if (n >= 5) ioc_inspect_str(buf, a->strs[i].va, out);
        }
    } else {
        ioc_fallback_raw(a, out);
    }

    return out->nhit;
}
