#include "ana.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DB_MAX_SNAPS 32
#define DB_MAX_FILE  (256u * 1024u * 1024u)

static const char db_magic_v3[4] = {'X', 'D', 'B', '3'};

typedef struct {
    uint8_t *data;
    size_t   len;
    size_t   cap;
} db_buf;

typedef struct {
    const uint8_t *data;
    size_t         len;
    size_t         pos;
} db_rdr;

typedef struct {
    char     name[48];
    uint8_t *data;
    uint32_t size;
} db_snap_ent;

typedef struct {
    db_snap_ent items[DB_MAX_SNAPS];
    uint32_t    count;
} db_snap_vec;

static void db_buf_free(db_buf *b) {
    free(b->data);
    b->data = NULL;
    b->len = 0;
    b->cap = 0;
}

static bool db_buf_put(db_buf *b, const void *src, size_t n) {
    if (n == 0) return true;
    if (b->len + n > b->cap) {
        size_t nc = b->cap ? b->cap * 2 : 4096;
        while (nc < b->len + n) nc *= 2;
        uint8_t *nd = (uint8_t *)realloc(b->data, nc);
        if (!nd) return false;
        b->data = nd;
        b->cap = nc;
    }
    memcpy(b->data + b->len, src, n);
    b->len += n;
    return true;
}

static bool db_buf_u32(db_buf *b, uint32_t v) {
    return db_buf_put(b, &v, 4);
}

static bool db_buf_u64(db_buf *b, uint64_t v) {
    return db_buf_put(b, &v, 8);
}

static bool db_buf_str(db_buf *b, const char *s) {
    size_t slen = s ? strlen(s) : 0;
    if (slen > 0xFFFFu) slen = 0xFFFFu;
    uint16_t n = (uint16_t)slen;
    if (!db_buf_put(b, &n, 2)) return false;
    return n ? db_buf_put(b, s, n) : true;
}

static bool db_rd_bytes(db_rdr *r, void *dst, size_t n) {
    if (n > r->len - r->pos) return false;
    if (dst && n) memcpy(dst, r->data + r->pos, n);
    r->pos += n;
    return true;
}

static bool db_rd_u32(db_rdr *r, uint32_t *out) {
    return db_rd_bytes(r, out, 4);
}

static bool db_rd_u64(db_rdr *r, uint64_t *out) {
    return db_rd_bytes(r, out, 8);
}

static bool db_rd_str(db_rdr *r, char *buf, size_t max) {
    uint16_t n = 0;
    if (!db_rd_bytes(r, &n, 2)) return false;
    if (n > r->len - r->pos) return false;
    if (buf) {
        if ((size_t)n >= max) return false;
        if (n) memcpy(buf, r->data + r->pos, n);
        buf[n] = 0;
    }
    r->pos += n;
    return true;
}

static bool db_pack_state(const ana_ctx *a, db_buf *out) {
    memset(out, 0, sizeof(*out));

    uint32_t nsym = 0;
    for (uint32_t i = 0; i < a->sym_map.cap; i++) {
        if (a->sym_map.slots[i].val == TBL_NONE) continue;
        const char *s = ana_pool_str(a, a->sym_map.slots[i].val);
        if (s && s[0]) nsym++;
    }
    if (!db_buf_u32(out, nsym)) goto fail;
    for (uint32_t i = 0; i < a->sym_map.cap; i++) {
        if (a->sym_map.slots[i].val == TBL_NONE) continue;
        const char *s = ana_pool_str(a, a->sym_map.slots[i].val);
        if (!s || !s[0]) continue;
        if (!db_buf_u64(out, a->sym_map.slots[i].key) || !db_buf_str(out, s)) goto fail;
    }

    uint32_t ncmt = 0;
    for (uint32_t i = 0; i < a->cmt_map.cap; i++) {
        if (a->cmt_map.slots[i].val == TBL_NONE) continue;
        const char *s = ana_pool_str(a, a->cmt_map.slots[i].val);
        if (s && s[0]) ncmt++;
    }
    if (!db_buf_u32(out, ncmt)) goto fail;
    for (uint32_t i = 0; i < a->cmt_map.cap; i++) {
        if (a->cmt_map.slots[i].val == TBL_NONE) continue;
        const char *s = ana_pool_str(a, a->cmt_map.slots[i].val);
        if (!s || !s[0]) continue;
        if (!db_buf_u64(out, a->cmt_map.slots[i].key) || !db_buf_str(out, s)) goto fail;
    }

    if (!db_buf_u32(out, a->nmark)) goto fail;
    for (uint32_t i = 0; i < a->nmark; i++) {
        if (!db_buf_u64(out, a->marks[i].va) || !db_buf_str(out, a->marks[i].label)) goto fail;
    }

    if (!db_buf_u32(out, a->npatch)) goto fail;
    for (uint32_t i = 0; i < a->npatch; i++) {
        if (!db_buf_u64(out, a->patches[i].va) || !db_buf_put(out, &a->patches[i].val, 1)) goto fail;
    }

    if (!db_buf_u32(out, a->nlvar)) goto fail;
    for (uint32_t i = 0; i < a->nlvar; i++) {
        if (!db_buf_u64(out, a->lvars[i].func_va) ||
            !db_buf_str(out, a->lvars[i].orig) ||
            !db_buf_str(out, a->lvars[i].name) ||
            !db_buf_str(out, a->lvars[i].type)) goto fail;
    }

    return true;

fail:
    db_buf_free(out);
    return false;
}

static bool db_skip_payload(db_rdr *r, int ver, db_snap_meta *meta) {
    uint32_t cnt = 0;

    if (!db_rd_u32(r, &cnt)) return false;
    if (meta) meta->nsym = cnt;
    for (uint32_t i = 0; i < cnt; i++) {
        if (!db_rd_bytes(r, NULL, 8) || !db_rd_str(r, NULL, 0)) return false;
    }

    if (!db_rd_u32(r, &cnt)) return false;
    if (meta) meta->ncmt = cnt;
    for (uint32_t i = 0; i < cnt; i++) {
        if (!db_rd_bytes(r, NULL, 8) || !db_rd_str(r, NULL, 0)) return false;
    }

    if (!db_rd_u32(r, &cnt)) return false;
    for (uint32_t i = 0; i < cnt; i++) {
        if (!db_rd_bytes(r, NULL, 8) || !db_rd_str(r, NULL, 0)) return false;
    }

    if (!db_rd_u32(r, &cnt)) return false;
    if (meta) meta->npatch = cnt;
    for (uint32_t i = 0; i < cnt; i++) {
        if (!db_rd_bytes(r, NULL, 9)) return false;
    }

    if (meta) meta->nlvar = 0;
    if (ver >= 2) {
        if (!db_rd_u32(r, &cnt)) return false;
        if (meta) meta->nlvar = cnt;
        for (uint32_t i = 0; i < cnt; i++) {
            if (!db_rd_bytes(r, NULL, 8) ||
                !db_rd_str(r, NULL, 0) ||
                !db_rd_str(r, NULL, 0) ||
                !db_rd_str(r, NULL, 0)) return false;
        }
    }

    return true;
}

static bool db_apply_payload(ana_ctx *a, db_rdr *r, int ver) {
    char buf[1024];
    uint32_t cnt = 0;

    if (!db_rd_u32(r, &cnt)) return false;
    for (uint32_t i = 0; i < cnt; i++) {
        uint64_t va = 0;
        if (!db_rd_u64(r, &va) || !db_rd_str(r, buf, sizeof(buf))) return false;
        ana_set_name(a, va, buf);
    }

    if (!db_rd_u32(r, &cnt)) return false;
    for (uint32_t i = 0; i < cnt; i++) {
        uint64_t va = 0;
        if (!db_rd_u64(r, &va) || !db_rd_str(r, buf, sizeof(buf))) return false;
        ana_set_cmt(a, va, buf);
    }

    if (!db_rd_u32(r, &cnt)) return false;
    for (uint32_t i = 0; i < cnt; i++) {
        uint64_t va = 0;
        if (!db_rd_u64(r, &va) || !db_rd_str(r, buf, sizeof(buf))) return false;
        ana_add_mark(a, va, buf);
    }

    if (!db_rd_u32(r, &cnt)) return false;
    for (uint32_t i = 0; i < cnt; i++) {
        uint64_t va = 0;
        uint8_t val = 0;
        if (!db_rd_u64(r, &va) || !db_rd_bytes(r, &val, 1)) return false;
        ana_patch_byte(a, va, val);
    }

    if (ver >= 2 && r->pos < r->len) {
        if (!db_rd_u32(r, &cnt)) return false;
        char orig[64], name[64], type[64];
        for (uint32_t i = 0; i < cnt; i++) {
            uint64_t fva = 0;
            if (!db_rd_u64(r, &fva) ||
                !db_rd_str(r, orig, sizeof(orig)) ||
                !db_rd_str(r, name, sizeof(name)) ||
                !db_rd_str(r, type, sizeof(type))) return false;
            ana_set_lvar(a, fva, orig, name, type);
        }
    }

    return true;
}

static wchar_t *db_utf8_to_wide(const char *path, wchar_t *stack_buf, size_t stack_cap) {
    if (!path || !path[0]) return NULL;
    UINT cp = CP_UTF8;
    DWORD flags = MB_ERR_INVALID_CHARS;
    int n = MultiByteToWideChar(cp, flags, path, -1, NULL, 0);
    if (n <= 0) {
        if (GetLastError() != ERROR_NO_UNICODE_TRANSLATION) return NULL;
        cp = CP_ACP;
        flags = 0;
        n = MultiByteToWideChar(cp, flags, path, -1, NULL, 0);
        if (n <= 0) return NULL;
    }
    wchar_t *wbuf = ((size_t)n <= stack_cap) ? stack_buf : (wchar_t *)malloc((size_t)n * sizeof(wchar_t));
    if (!wbuf) return NULL;
    if (MultiByteToWideChar(cp, flags, path, -1, wbuf, n) <= 0) {
        if (wbuf != stack_buf) free(wbuf);
        return NULL;
    }
    return wbuf;
}

static FILE *db_fopen_utf8(const char *path, const wchar_t *mode) {
    wchar_t wstack[1024];
    wchar_t *wpath = db_utf8_to_wide(path, wstack, 1024);
    if (!wpath) return NULL;
    FILE *f = _wfopen(wpath, mode);
    if (wpath != wstack) free(wpath);
    return f;
}

static bool db_read_file(const char *path, uint8_t **out_data, size_t *out_len) {
    *out_data = NULL;
    *out_len = 0;
    if (!path || !path[0]) return false;

    FILE *f = db_fopen_utf8(path, L"rb");
    if (!f) return false;
    if (_fseeki64(f, 0, SEEK_END) != 0) { fclose(f); return false; }
    __int64 sz = _ftelli64(f);
    if (sz < 0 || (uint64_t)sz > DB_MAX_FILE) { fclose(f); return false; }
    if (_fseeki64(f, 0, SEEK_SET) != 0) { fclose(f); return false; }

    size_t len = (size_t)sz;
    uint8_t *buf = (uint8_t *)malloc(len ? len : 1);
    if (!buf) { fclose(f); return false; }
    if (len && fread(buf, 1, len, f) != len) {
        free(buf);
        fclose(f);
        return false;
    }
    fclose(f);
    *out_data = buf;
    *out_len = len;
    return true;
}

static void db_snap_vec_free(db_snap_vec *v) {
    for (uint32_t i = 0; i < v->count; i++) free(v->items[i].data);
    memset(v, 0, sizeof(*v));
}

static void db_load_snaps(const char *path, db_snap_vec *v) {
    memset(v, 0, sizeof(*v));
    uint8_t *raw = NULL;
    size_t len = 0;
    if (!db_read_file(path, &raw, &len)) return;
    if (len < 4 || memcmp(raw, db_magic_v3, 4) != 0) {
        free(raw);
        return;
    }

    db_rdr r = {raw, len, 4};
    uint32_t nsnap = 0;
    if (!db_skip_payload(&r, 3, NULL) || !db_rd_u32(&r, &nsnap)) {
        free(raw);
        return;
    }

    for (uint32_t i = 0; i < nsnap && v->count < DB_MAX_SNAPS; i++) {
        char name[48];
        uint32_t sz = 0;
        if (!db_rd_bytes(&r, name, 48) || !db_rd_u32(&r, &sz)) break;
        if (sz > r.len - r.pos) break;
        name[47] = 0;

        uint8_t *copy = (uint8_t *)malloc(sz ? sz : 1);
        if (!copy) break;
        if (sz) memcpy(copy, r.data + r.pos, sz);
        r.pos += sz;

        db_snap_ent *e = &v->items[v->count++];
        memset(e->name, 0, sizeof(e->name));
        snprintf(e->name, sizeof(e->name), "%s", name);
        e->data = copy;
        e->size = sz;
    }

    free(raw);
}

static bool db_write_xdb3(const char *path, const db_buf *main_buf, const db_snap_vec *snaps) {
    size_t plen = strlen(path);
    char *tmp = (char *)malloc(plen + 5);
    if (!tmp) return false;
    memcpy(tmp, path, plen);
    memcpy(tmp + plen, ".tmp", 5);

    FILE *f = db_fopen_utf8(tmp, L"wb");
    if (!f) {
        free(tmp);
        return false;
    }

    bool ok = true;
    if (fwrite(db_magic_v3, 1, 4, f) != 4) ok = false;
    if (ok && main_buf->len && fwrite(main_buf->data, 1, main_buf->len, f) != main_buf->len) ok = false;

    uint32_t nsnap = snaps ? snaps->count : 0;
    if (ok && fwrite(&nsnap, 4, 1, f) != 1) ok = false;
    for (uint32_t i = 0; ok && i < nsnap; i++) {
        const db_snap_ent *e = &snaps->items[i];
        if (fwrite(e->name, 1, 48, f) != 48 ||
            fwrite(&e->size, 4, 1, f) != 1 ||
            (e->size && fwrite(e->data, 1, e->size, f) != e->size)) {
            ok = false;
        }
    }

    if (fflush(f) != 0) ok = false;
    if (fclose(f) != 0) ok = false;

    // atomic replace on target path
    wchar_t wt_stack[1024], wp_stack[1024];
    wchar_t *wtmp = db_utf8_to_wide(tmp, wt_stack, 1024);
    wchar_t *wdst = db_utf8_to_wide(path, wp_stack, 1024);
    if (ok) {
        if (!wtmp || !wdst || !MoveFileExW(wtmp, wdst, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) ok = false;
    }
    if (!ok && wtmp) DeleteFileW(wtmp);
    if (wtmp && wtmp != wt_stack) free(wtmp);
    if (wdst && wdst != wp_stack) free(wdst);
    free(tmp);
    return ok;
}

bool db_save(const ana_ctx *a, const char *path) {
    if (!a || !path || !path[0]) return false;

    db_buf main_buf = {0};
    if (!db_pack_state(a, &main_buf)) return false;

    db_snap_vec snaps;
    db_load_snaps(path, &snaps);

    bool ok = db_write_xdb3(path, &main_buf, &snaps);
    db_snap_vec_free(&snaps);
    db_buf_free(&main_buf);
    return ok;
}

bool db_load(ana_ctx *a, const char *path) {
    if (!a || !path || !path[0]) return false;

    uint8_t *raw = NULL;
    size_t len = 0;
    if (!db_read_file(path, &raw, &len)) return false;
    if (len < 4 || memcmp(raw, "XDB", 3) != 0 || (raw[3] != '1' && raw[3] != '2' && raw[3] != '3')) {
        free(raw);
        return false;
    }

    int ver = raw[3] - '0';
    db_rdr r = {raw, len, 4};

    int prev_mute = a->hist_mute;
    a->hist_mute = 1;
    bool ok = db_apply_payload(a, &r, ver);
    a->hist_mute = prev_mute;

    free(raw);
    return ok;
}

bool db_snap_save(const ana_ctx *a, const char *db_path, const char *snap_name) {
    if (!a || !db_path || !db_path[0] || !snap_name || !snap_name[0]) return false;

    db_buf payload = {0};
    if (!db_pack_state(a, &payload)) return false;
    if (payload.len > UINT32_MAX) {
        db_buf_free(&payload);
        return false;
    }

    db_snap_vec snaps;
    db_load_snaps(db_path, &snaps);

    char cname[48] = {0};
    snprintf(cname, sizeof(cname), "%s", snap_name);

    int slot = -1;
    for (uint32_t i = 0; i < snaps.count; i++) {
        if (strcmp(snaps.items[i].name, cname) == 0) {
            slot = (int)i;
            break;
        }
    }
    if (slot < 0) {
        if (snaps.count >= DB_MAX_SNAPS) {
            db_snap_vec_free(&snaps);
            db_buf_free(&payload);
            return false;
        }
        slot = (int)snaps.count++;
    }

    uint8_t *copy = (uint8_t *)malloc(payload.len ? payload.len : 1);
    if (!copy) {
        db_snap_vec_free(&snaps);
        db_buf_free(&payload);
        return false;
    }
    if (payload.len) memcpy(copy, payload.data, payload.len);

    free(snaps.items[slot].data);
    memcpy(snaps.items[slot].name, cname, 48);
    snaps.items[slot].data = copy;
    snaps.items[slot].size = (uint32_t)payload.len;

    bool ok = db_write_xdb3(db_path, &payload, &snaps);
    db_snap_vec_free(&snaps);
    db_buf_free(&payload);
    return ok;
}

int db_snap_list(const char *db_path, db_snap_meta *out, int max_out) {
    if (!db_path || !db_path[0] || !out || max_out <= 0) return 0;

    uint8_t *raw = NULL;
    size_t len = 0;
    if (!db_read_file(db_path, &raw, &len)) return 0;
    if (len < 4 || memcmp(raw, db_magic_v3, 4) != 0) {
        free(raw);
        return 0;
    }

    db_rdr r = {raw, len, 4};
    uint32_t nsnap = 0;
    if (!db_skip_payload(&r, 3, NULL) || !db_rd_u32(&r, &nsnap)) {
        free(raw);
        return 0;
    }

    int found = 0;
    for (uint32_t i = 0; i < nsnap && found < max_out; i++) {
        char name[48];
        uint32_t sz = 0;
        if (!db_rd_bytes(&r, name, 48) || !db_rd_u32(&r, &sz)) break;
        if (sz > r.len - r.pos) break;
        name[47] = 0;

        db_rdr sr = {r.data + r.pos, sz, 0};
        r.pos += sz;

        db_snap_meta m = {0};
        memcpy(m.name, name, 48);
        if (db_skip_payload(&sr, 3, &m)) out[found++] = m;
    }

    free(raw);
    return found;
}

bool db_snap_restore(ana_ctx *a, const char *db_path, const char *snap_name) {
    if (!a || !db_path || !db_path[0] || !snap_name || !snap_name[0]) return false;

    uint8_t *raw = NULL;
    size_t len = 0;
    if (!db_read_file(db_path, &raw, &len)) return false;
    if (len < 4 || memcmp(raw, db_magic_v3, 4) != 0) {
        free(raw);
        return false;
    }

    db_rdr r = {raw, len, 4};
    uint32_t nsnap = 0;
    if (!db_skip_payload(&r, 3, NULL) || !db_rd_u32(&r, &nsnap)) {
        free(raw);
        return false;
    }

    char cname[48] = {0};
    snprintf(cname, sizeof(cname), "%s", snap_name);

    bool ok = false;
    for (uint32_t i = 0; i < nsnap; i++) {
        char name[48];
        uint32_t sz = 0;
        if (!db_rd_bytes(&r, name, 48) || !db_rd_u32(&r, &sz)) break;
        if (sz > r.len - r.pos) break;
        name[47] = 0;

        const uint8_t *pdata = r.data + r.pos;
        r.pos += sz;
        if (strcmp(name, cname) != 0) continue;

        // validate snapshot before mutating state
        db_rdr chk = {pdata, sz, 0};
        if (!db_skip_payload(&chk, 3, NULL)) break;

        int prev_mute = a->hist_mute;
        a->hist_mute = 1;
        ana_unpatch_all(a);
        a->nmark = 0;
        a->nlvar = 0;
        tbl_clear(&a->cmt_map);
        tbl_clear(&a->sym_map);

        db_rdr sr = {pdata, sz, 0};
        ok = db_apply_payload(a, &sr, 3);
        a->hist_mute = prev_mute;
        break;
    }

    free(raw);
    return ok;
}
