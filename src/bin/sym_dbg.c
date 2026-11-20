#include "../ana/ana.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SYM_MAX_PDB_BYTES  (128ULL * 1024ULL * 1024ULL)
#define SYM_MAX_STRM_BYTES (64U * 1024U * 1024U)
#define SYM_MAX_STREAMS    65536U
#define SYM_MAX_TYPES      512U
#define SYM_MAX_TPI_RECS   2000000U
#define SYM_MAX_MEMS       32
#define SYM_MAX_DW_DEPTH   128
#define SYM_MAX_DW_DIES    2000000U
#define SYM_MAX_FL_VISITED 256U
#define SYM_MAX_FL_STEPS   512U
#define SYM_MAX_FL_ITEMS   4096U
#define SYM_MAX_TPI_WORK   1000000U

enum {
    SYM_AGG_STRUCT = 0,
    SYM_AGG_UNION  = 1,
    SYM_AGG_ENUM   = 2
};

enum {
    SYM_CV_LF_MODIFIER   = 0x1001U,
    SYM_CV_LF_POINTER    = 0x1002U,
    SYM_CV_LF_PROCEDURE  = 0x1008U,
    SYM_CV_LF_MFUNCTION  = 0x1009U,
    SYM_CV_LF_FIELDLIST  = 0x1203U,
    SYM_CV_LF_BITFIELD   = 0x1205U,
    SYM_CV_LF_BCLASS     = 0x1400U,
    SYM_CV_LF_VBCLASS    = 0x1401U,
    SYM_CV_LF_IVBCLASS   = 0x1402U,
    SYM_CV_LF_INDEX      = 0x1404U,
    SYM_CV_LF_VFUNCTAB   = 0x1409U,
    SYM_CV_LF_FRIENDCLS  = 0x140AU,
    SYM_CV_LF_VFUNCOFF   = 0x140CU,
    SYM_CV_LF_ENUMERATE  = 0x1502U,
    SYM_CV_LF_ARRAY      = 0x1503U,
    SYM_CV_LF_CLASS      = 0x1504U,
    SYM_CV_LF_STRUCTURE  = 0x1505U,
    SYM_CV_LF_UNION      = 0x1506U,
    SYM_CV_LF_ENUM       = 0x1507U,
    SYM_CV_LF_FRIENDFCN  = 0x150CU,
    SYM_CV_LF_MEMBER     = 0x150DU,
    SYM_CV_LF_STMEMBER   = 0x150EU,
    SYM_CV_LF_METHOD     = 0x150FU,
    SYM_CV_LF_NESTTYPE   = 0x1510U,
    SYM_CV_LF_ONEMETHOD  = 0x1511U,
    SYM_CV_LF_NESTTYPEEX = 0x1512U,
    SYM_CV_LF_CHAR       = 0x8000U,
    SYM_CV_LF_SHORT      = 0x8001U,
    SYM_CV_LF_USHORT     = 0x8002U,
    SYM_CV_LF_LONG       = 0x8003U,
    SYM_CV_LF_ULONG      = 0x8004U,
    SYM_CV_LF_REAL32     = 0x8005U,
    SYM_CV_LF_REAL64     = 0x8006U,
    SYM_CV_LF_REAL80     = 0x8007U,
    SYM_CV_LF_REAL128    = 0x8008U,
    SYM_CV_LF_QUAD       = 0x8009U,
    SYM_CV_LF_UQUAD      = 0x800AU,
    SYM_CV_LF_VARSTR     = 0x8010U,
    SYM_CV_S_LDATA32     = 0x110CU,
    SYM_CV_S_GDATA32     = 0x110DU,
    SYM_CV_S_PUB32       = 0x110EU,
    SYM_CV_S_LPROC32     = 0x110FU,
    SYM_CV_S_GPROC32     = 0x1110U,
    SYM_CV_S_LPROC32_ID  = 0x1146U,
    SYM_CV_S_GPROC32_ID  = 0x1147U
};

typedef struct {
    char    name[32];
    char    type[32];
    int     arr_cnt;
    int     off;
    int64_t eval;
    bool    has_off;
} sym_mem;

typedef struct {
    char    name[40];
    int     kind;
    int     byte_size;
    int     nmem;
    sym_mem mems[SYM_MAX_MEMS];
} sym_agg;

static uint16_t sym_u16(const uint8_t *d, size_t sz, size_t off) {
    if (off > sz || sz - off < 2) return 0;
    uint16_t v;
    memcpy(&v, d + off, 2);
    return v;
}

static uint32_t sym_u32(const uint8_t *d, size_t sz, size_t off) {
    if (off > sz || sz - off < 4) return 0;
    uint32_t v;
    memcpy(&v, d + off, 4);
    return v;
}

static uint64_t sym_u64(const uint8_t *d, size_t sz, size_t off) {
    if (off > sz || sz - off < 8) return 0;
    uint64_t v;
    memcpy(&v, d + off, 8);
    return v;
}

static size_t sym_cstr(const uint8_t *d, size_t sz, size_t off, char *out, size_t max) {
    if (off >= sz || max == 0) {
        if (max) out[0] = 0;
        return 0;
    }
    size_t n = 0;
    while (off + n < sz && d[off + n] != 0) {
        if (n + 1 < max) out[n] = (char)d[off + n];
        n++;
    }
    out[n < max ? n : max - 1] = 0;
    return n;
}

static bool sym_skip_cstr(const uint8_t *d, size_t sz, size_t *pos, char *out, size_t max) {
    if (*pos >= sz) {
        if (max) out[0] = 0;
        return false;
    }
    size_t n = 0;
    while (*pos + n < sz && d[*pos + n] != 0) {
        if (out && n + 1 < max) out[n] = (char)d[*pos + n];
        n++;
    }
    if (out && max) out[n < max ? n : max - 1] = 0;
    if (*pos + n >= sz) return false;
    *pos += n + 1;
    return true;
}

static bool sym_sanitize_ident(const char *raw, char *out, size_t max) {
    if (!raw || !raw[0] || max < 2) return false;
    if (raw[0] == '<' || strchr(raw, '<') != NULL) return false;

    size_t k = 0;
    for (const char *p = raw; *p && k + 1 < max; p++) {
        unsigned char c = (unsigned char)*p;
        if (isalnum(c) || c == '_') {
            out[k++] = (char)c;
        } else if (c == ':' || c == '.' || c == '$') {
            if (k > 0 && out[k - 1] != '_') out[k++] = '_';
        } else {
            break;
        }
    }
    if (k == 0 || isdigit((unsigned char)out[0])) return false;
    out[k] = 0;
    return true;
}

static void sym_apply_sym(ana_ctx *a, uint64_t va, const char *raw, bool is_func, sym_dbg_stats *out) {
    if (!va || !raw || !raw[0]) return;
    char dem[256];
    const char *name = dem_name(raw, dem, sizeof(dem)) ? dem : raw;
    if (!name[0]) return;
    ana_set_name(a, va, name);
    out->syms_added++;
    if (is_func) out->funcs_added++;
}

static bool sym_register_agg(typ_store *types, const sym_agg *agg, sym_dbg_stats *out) {
    if (!types || !agg || !agg->name[0]) return false;
    if (out->types_added >= SYM_MAX_TYPES) return false;

    const typ_def *ex = typ_find(types, agg->name);
    if (ex && (ex->nmem > 0 || agg->nmem == 0)) return false;

    char decl[4096];
    int wr = snprintf(decl, sizeof(decl), "%s %s { ",
                      agg->kind == SYM_AGG_ENUM ? "enum" : "struct", agg->name);
    if (wr < 0 || (size_t)wr >= sizeof(decl)) return false;
    size_t pos = (size_t)wr;

    for (int i = 0; i < agg->nmem; i++) {
        const sym_mem *m = &agg->mems[i];
        if (!m->name[0]) continue;
        if (agg->kind == SYM_AGG_ENUM) {
            wr = snprintf(decl + pos, sizeof(decl) - pos, "%s = %lld%s",
                          m->name, (long long)m->eval, (i + 1 < agg->nmem) ? ", " : " ");
        } else if (m->arr_cnt > 1) {
            wr = snprintf(decl + pos, sizeof(decl) - pos, "%s %s[%d]; ",
                          m->type[0] ? m->type : "uint32_t", m->name, m->arr_cnt);
        } else {
            wr = snprintf(decl + pos, sizeof(decl) - pos, "%s %s; ",
                          m->type[0] ? m->type : "uint32_t", m->name);
        }
        if (wr < 0 || pos + (size_t)wr + 8 >= sizeof(decl)) break;
        pos += (size_t)wr;
    }

    if (pos + 4 >= sizeof(decl)) return false;
    memcpy(decl + pos, "};", 3);
    if (!typ_parse_c(types, decl)) return false;

    // preserve exact debug layout offsets
    for (uint32_t i = 0; i < types->ndef; i++) {
        if (strcmp(types->defs[i].name, agg->name) != 0) continue;
        typ_def *td = &types->defs[i];
        if (agg->kind == SYM_AGG_UNION) {
            int max_sz = agg->byte_size;
            for (int k = 0; k < td->nmem; k++) {
                td->mems[k].off = 0;
                if (td->mems[k].size > max_sz) max_sz = td->mems[k].size;
            }
            if (max_sz > 0) td->size = max_sz;
        } else if (agg->kind == SYM_AGG_STRUCT) {
            for (int k = 0; k < td->nmem && k < agg->nmem; k++) {
                if (agg->mems[k].has_off && strcmp(td->mems[k].name, agg->mems[k].name) == 0) {
                    td->mems[k].off = agg->mems[k].off;
                }
            }
            if (agg->byte_size > 0) td->size = agg->byte_size;
        }
        break;
    }

    if (!ex) out->types_added++;
    return true;
}

static const uint8_t sym_msf7_magic[32] = {
    'M','i','c','r','o','s','o','f','t',' ','C','/','C','+','+',' ',
    'M','S','F',' ','7','.','0','0','\r','\n',0x1A,'D','S',0,0,0
};

typedef struct {
    const uint8_t *data;
    size_t         size;
    uint32_t       block_size;
    uint32_t       num_blocks;
    uint8_t       *dir;
    uint32_t       dir_size;
    uint32_t       num_streams;
    uint32_t      *stream_sizes;
    uint32_t      *stream_blk_off;
} sym_msf;

static bool sym_msf_valid_blk_sz(uint32_t bs) {
    return bs == 512U || bs == 1024U || bs == 2048U || bs == 4096U ||
           bs == 8192U || bs == 16384U || bs == 32768U;
}

static uint8_t *sym_msf_gather(const uint8_t *data, size_t fsz, uint32_t blk_sz, uint32_t num_blks,
                               const uint8_t *blk_list, size_t blk_list_sz, uint32_t nblk, uint32_t total) {
    if (total == 0 || total > SYM_MAX_STRM_BYTES) return NULL;
    if ((size_t)nblk > blk_list_sz / 4U) return NULL;

    uint8_t *buf = (uint8_t *)malloc(total);
    if (!buf) return NULL;

    uint32_t done = 0;
    for (uint32_t i = 0; i < nblk && done < total; i++) {
        uint32_t bi = sym_u32(blk_list, blk_list_sz, (size_t)i * 4U);
        if (bi >= num_blks) { free(buf); return NULL; }
        uint64_t foff = (uint64_t)bi * (uint64_t)blk_sz;
        uint32_t take = total - done;
        if (take > blk_sz) take = blk_sz;
        if (foff > (uint64_t)fsz || (uint64_t)fsz - foff < (uint64_t)take) {
            free(buf);
            return NULL;
        }
        memcpy(buf + done, data + (size_t)foff, take);
        done += take;
    }
    if (done != total) { free(buf); return NULL; }
    return buf;
}

static void sym_msf_close(sym_msf *m) {
    if (!m) return;
    free(m->dir);
    free(m->stream_sizes);
    free(m->stream_blk_off);
    memset(m, 0, sizeof(*m));
}

static bool sym_msf_open(sym_msf *m, const uint8_t *data, size_t fsz, char *err, size_t err_max) {
    memset(m, 0, sizeof(*m));
    if (fsz < 56 || memcmp(data, sym_msf7_magic, 32) != 0) {
        snprintf(err, err_max, "not an MSF 7.00 PDB file");
        return false;
    }

    uint32_t blk_sz   = sym_u32(data, fsz, 32);
    uint32_t num_blks = sym_u32(data, fsz, 40);
    uint32_t dir_sz   = sym_u32(data, fsz, 44);
    uint32_t map_blk  = sym_u32(data, fsz, 52);

    if (!sym_msf_valid_blk_sz(blk_sz)) {
        snprintf(err, err_max, "invalid MSF block size %u", blk_sz);
        return false;
    }
    if (num_blks == 0 || dir_sz < 4 || dir_sz > SYM_MAX_STRM_BYTES || map_blk >= num_blks) {
        snprintf(err, err_max, "corrupt MSF superblock");
        return false;
    }

    uint32_t dir_blks = (uint32_t)(((uint64_t)dir_sz + blk_sz - 1U) / blk_sz);
    uint64_t map_off = (uint64_t)map_blk * (uint64_t)blk_sz;
    if (dir_blks > blk_sz / 4U || map_off > (uint64_t)fsz ||
        (uint64_t)fsz - map_off < (uint64_t)dir_blks * 4U) {
        snprintf(err, err_max, "corrupt MSF block map");
        return false;
    }

    uint8_t *dir = sym_msf_gather(data, fsz, blk_sz, num_blks,
                                  data + (size_t)map_off, (size_t)dir_blks * 4U, dir_blks, dir_sz);
    if (!dir) {
        snprintf(err, err_max, "failed to read MSF directory");
        return false;
    }

    uint32_t nstr = sym_u32(dir, dir_sz, 0);
    if (nstr == 0 || nstr > SYM_MAX_STREAMS || 4U + (uint64_t)nstr * 4U > (uint64_t)dir_sz) {
        free(dir);
        snprintf(err, err_max, "corrupt MSF stream directory");
        return false;
    }

    uint32_t *ssz = (uint32_t *)malloc((size_t)nstr * sizeof(uint32_t));
    uint32_t *bof = (uint32_t *)malloc((size_t)nstr * sizeof(uint32_t));
    if (!ssz || !bof) {
        free(dir); free(ssz); free(bof);
        snprintf(err, err_max, "out of memory");
        return false;
    }

    uint64_t cur = 4U + (uint64_t)nstr * 4U;
    for (uint32_t i = 0; i < nstr; i++) {
        uint32_t sz = sym_u32(dir, dir_sz, 4U + (size_t)i * 4U);
        ssz[i] = sz;
        bof[i] = (uint32_t)cur;
        if (sz != 0 && sz != 0xFFFFFFFFU) {
            uint64_t nb = ((uint64_t)sz + blk_sz - 1U) / blk_sz;
            if (nb > ((uint64_t)dir_sz - cur) / 4U) {
                free(dir); free(ssz); free(bof);
                snprintf(err, err_max, "truncated MSF block list");
                return false;
            }
            cur += nb * 4U;
        }
    }

    m->data = data;
    m->size = fsz;
    m->block_size = blk_sz;
    m->num_blocks = num_blks;
    m->dir = dir;
    m->dir_size = dir_sz;
    m->num_streams = nstr;
    m->stream_sizes = ssz;
    m->stream_blk_off = bof;
    return true;
}

static uint8_t *sym_msf_read_stream(const sym_msf *m, uint32_t idx, uint32_t *out_sz) {
    *out_sz = 0;
    if (!m || idx >= m->num_streams) return NULL;
    uint32_t sz = m->stream_sizes[idx];
    if (sz == 0 || sz == 0xFFFFFFFFU || sz > SYM_MAX_STRM_BYTES) return NULL;

    uint32_t nb = (uint32_t)(((uint64_t)sz + m->block_size - 1U) / m->block_size);
    uint32_t boff = m->stream_blk_off[idx];
    if (boff > m->dir_size || (m->dir_size - boff) / 4U < nb) return NULL;

    uint8_t *buf = sym_msf_gather(m->data, m->size, m->block_size, m->num_blocks,
                                  m->dir + boff, m->dir_size - boff, nb, sz);
    if (buf) *out_sz = sz;
    return buf;
}

static bool sym_cv_num(const uint8_t *p, size_t len, size_t *pos, int64_t *val) {
    if (*pos > len || len - *pos < 2) return false;
    uint16_t leaf = sym_u16(p, len, *pos);
    *pos += 2;
    if (leaf < 0x8000U) {
        *val = (int64_t)leaf;
        return true;
    }
    switch (leaf) {
    case SYM_CV_LF_CHAR:
        if (len - *pos < 1) return false;
        *val = (int8_t)p[(*pos)++];
        return true;
    case SYM_CV_LF_SHORT:
        if (len - *pos < 2) return false;
        *val = (int16_t)sym_u16(p, len, *pos);
        *pos += 2;
        return true;
    case SYM_CV_LF_USHORT:
        if (len - *pos < 2) return false;
        *val = (int64_t)sym_u16(p, len, *pos);
        *pos += 2;
        return true;
    case SYM_CV_LF_LONG:
        if (len - *pos < 4) return false;
        *val = (int32_t)sym_u32(p, len, *pos);
        *pos += 4;
        return true;
    case SYM_CV_LF_ULONG:
        if (len - *pos < 4) return false;
        *val = (int64_t)sym_u32(p, len, *pos);
        *pos += 4;
        return true;
    case SYM_CV_LF_REAL32:
        if (len - *pos < 4) return false;
        *val = 0; *pos += 4; return true;
    case SYM_CV_LF_REAL64:
        if (len - *pos < 8) return false;
        *val = 0; *pos += 8; return true;
    case SYM_CV_LF_REAL80:
        if (len - *pos < 10) return false;
        *val = 0; *pos += 10; return true;
    case SYM_CV_LF_REAL128:
        if (len - *pos < 16) return false;
        *val = 0; *pos += 16; return true;
    case SYM_CV_LF_QUAD:
    case SYM_CV_LF_UQUAD:
        if (len - *pos < 8) return false;
        *val = (int64_t)sym_u64(p, len, *pos);
        *pos += 8;
        return true;
    case SYM_CV_LF_VARSTR: {
        if (len - *pos < 2) return false;
        uint16_t slen = sym_u16(p, len, *pos);
        *pos += 2;
        if (len - *pos < slen) return false;
        *pos += slen;
        *val = 0;
        return true;
    }
    default:
        return false;
    }
}

typedef struct {
    uint32_t off;
    uint16_t len;
    uint16_t kind;
} sym_tpi_rec;

typedef struct {
    const uint8_t *buf;
    uint32_t       buf_sz;
    uint32_t       ti_begin;
    uint32_t       count;
    sym_tpi_rec   *recs;
} sym_tpi_ctx;

static const char *sym_cv_prim_base(uint32_t base, int *elem_sz) {
    switch (base) {
    case 0x00U: case 0x03U: if (elem_sz) *elem_sz = 0; return "void";
    case 0x10U: case 0x70U: case 0x7CU: if (elem_sz) *elem_sz = 1; return "char";
    case 0x68U: if (elem_sz) *elem_sz = 1; return "int8_t";
    case 0x20U: case 0x69U: if (elem_sz) *elem_sz = 1; return "uint8_t";
    case 0x30U: if (elem_sz) *elem_sz = 1; return "bool";
    case 0x11U: case 0x72U: if (elem_sz) *elem_sz = 2; return "int16_t";
    case 0x21U: case 0x31U: case 0x73U: case 0x7AU: if (elem_sz) *elem_sz = 2; return "uint16_t";
    case 0x71U: if (elem_sz) *elem_sz = 2; return "wchar_t";
    case 0x12U: case 0x32U: case 0x74U: if (elem_sz) *elem_sz = 4; return "int32_t";
    case 0x22U: case 0x75U: case 0x7BU: if (elem_sz) *elem_sz = 4; return "uint32_t";
    case 0x13U: case 0x76U: if (elem_sz) *elem_sz = 8; return "int64_t";
    case 0x23U: case 0x33U: case 0x77U: if (elem_sz) *elem_sz = 8; return "uint64_t";
    case 0x40U: if (elem_sz) *elem_sz = 4; return "float";
    case 0x41U: case 0x42U: if (elem_sz) *elem_sz = 8; return "double";
    default:    if (elem_sz) *elem_sz = 4; return NULL;
    }
}

static void sym_tpi_type_name(const sym_tpi_ctx *ctx, uint32_t ti, int depth,
                              char *out, size_t max, int *arr_cnt, int *elem_sz) {
    if (arr_cnt) *arr_cnt = 1;
    if (elem_sz) *elem_sz = 0;
    if (depth > 8) { snprintf(out, max, "void *"); return; }

    if (ti < 0x1000U) {
        uint32_t mode = (ti >> 8) & 0x0FU;
        uint32_t base = ti & 0xFFU;
        int bsz = 0;
        const char *bn = sym_cv_prim_base(base, &bsz);
        if (mode != 0) {
            if (elem_sz) *elem_sz = (mode == 0x04U || mode == 0x05U) ? 4 : 8;
            snprintf(out, max, "%s", (base == 0x10U || base == 0x70U) ? "char *" : "void *");
            return;
        }
        if (elem_sz) *elem_sz = bsz;
        snprintf(out, max, "%s", bn ? bn : "uint32_t");
        return;
    }

    if (ti < ctx->ti_begin || ti - ctx->ti_begin >= ctx->count) {
        snprintf(out, max, "uint64_t");
        return;
    }

    const sym_tpi_rec *r = &ctx->recs[ti - ctx->ti_begin];
    const uint8_t *p = ctx->buf + r->off;
    size_t len = r->len;

    if (r->kind == SYM_CV_LF_MODIFIER && len >= 4) {
        sym_tpi_type_name(ctx, sym_u32(p, len, 0), depth + 1, out, max, arr_cnt, elem_sz);
        return;
    }
    if (r->kind == SYM_CV_LF_POINTER && len >= 4) {
        char inner[32];
        sym_tpi_type_name(ctx, sym_u32(p, len, 0), depth + 1, inner, sizeof(inner), NULL, NULL);
        if (elem_sz) *elem_sz = 8;
        if (strcmp(inner, "char") == 0) snprintf(out, max, "char *");
        else if (strcmp(inner, "void") == 0 || strchr(inner, '*') != NULL || strlen(inner) > 22)
            snprintf(out, max, "void *");
        else snprintf(out, max, "%s *", inner);
        return;
    }
    if (r->kind == SYM_CV_LF_BITFIELD && len >= 4) {
        sym_tpi_type_name(ctx, sym_u32(p, len, 0), depth + 1, out, max, NULL, elem_sz);
        return;
    }
    if (r->kind == SYM_CV_LF_ARRAY && len >= 10) {
        size_t pos = 8;
        int64_t bsz = 0;
        int esz = 0;
        sym_tpi_type_name(ctx, sym_u32(p, len, 0), depth + 1, out, max, NULL, &esz);
        if (sym_cv_num(p, len, &pos, &bsz) && bsz > 0 && esz > 0 && (bsz % esz) == 0) {
            int64_t cnt = bsz / esz;
            if (arr_cnt && cnt > 1 && cnt <= 65536) *arr_cnt = (int)cnt;
        }
        return;
    }
    if (r->kind == SYM_CV_LF_CLASS || r->kind == SYM_CV_LF_STRUCTURE ||
        r->kind == SYM_CV_LF_UNION || r->kind == SYM_CV_LF_ENUM) {
        size_t pos = (r->kind == SYM_CV_LF_ENUM) ? 12U : (r->kind == SYM_CV_LF_UNION ? 8U : 16U);
        int64_t szv = 0;
        if (r->kind != SYM_CV_LF_ENUM && !sym_cv_num(p, len, &pos, &szv)) {
            snprintf(out, max, "uint64_t");
            return;
        }
        char raw[64], clean[32];
        sym_cstr(p, len, pos, raw, sizeof(raw));
        if (sym_sanitize_ident(raw, clean, sizeof(clean))) {
            snprintf(out, max, "%s", clean);
            if (elem_sz && szv > 0 && szv < 65536) *elem_sz = (int)szv;
            return;
        }
    }
    if (r->kind == SYM_CV_LF_PROCEDURE || r->kind == SYM_CV_LF_MFUNCTION) {
        snprintf(out, max, "void *");
        if (elem_sz) *elem_sz = 8;
        return;
    }
    snprintf(out, max, "uint64_t");
}

typedef struct {
    uint32_t  visited[SYM_MAX_FL_VISITED];
    uint32_t  nvis;
    uint32_t  steps;
    uint32_t  items;
    uint32_t *global_work;
} sym_fl_walk;

static void sym_tpi_walk_fieldlist(const sym_tpi_ctx *ctx, uint32_t fl_ti, sym_agg *agg,
                                   int depth, sym_fl_walk *w) {
    if (!w || depth > 16 || agg->nmem >= SYM_MAX_MEMS) return;
    if (w->steps >= SYM_MAX_FL_STEPS || w->items >= SYM_MAX_FL_ITEMS) return;
    if (w->global_work && *w->global_work >= SYM_MAX_TPI_WORK) return;
    if (fl_ti < ctx->ti_begin || fl_ti - ctx->ti_begin >= ctx->count) return;
    const sym_tpi_rec *r = &ctx->recs[fl_ti - ctx->ti_begin];
    if (r->kind != SYM_CV_LF_FIELDLIST) return;
    for (uint32_t i = 0; i < w->nvis; i++) {
        if (w->visited[i] == fl_ti) return;
    }
    if (w->nvis >= SYM_MAX_FL_VISITED) return;
    w->visited[w->nvis++] = fl_ti;

    const uint8_t *p = ctx->buf + r->off;
    size_t len = r->len;
    size_t pos = 0;

    while (pos + 2 <= len && agg->nmem < SYM_MAX_MEMS) {
        if (w->items >= SYM_MAX_FL_ITEMS) break;
        if (w->global_work && *w->global_work >= SYM_MAX_TPI_WORK) break;
        w->items++;
        if (w->global_work) (*w->global_work)++;

        if (p[pos] >= 0xF0U) {
            uint8_t pad = (uint8_t)(p[pos] & 0x0FU);
            size_t step = pad ? pad : 1U;
            if (step > len - pos) break;
            pos += step;
            continue;
        }
        uint16_t leaf = sym_u16(p, len, pos);
        pos += 2;

        if (leaf == SYM_CV_LF_MEMBER) {
            if (len - pos < 8) break;
            uint32_t mti = sym_u32(p, len, pos + 2);
            pos += 6;
            int64_t moff = 0;
            if (!sym_cv_num(p, len, &pos, &moff)) break;
            char raw[64], clean[32];
            if (!sym_skip_cstr(p, len, &pos, raw, sizeof(raw))) break;
            if (agg->kind != SYM_AGG_ENUM && sym_sanitize_ident(raw, clean, sizeof(clean))) {
                sym_mem *m = &agg->mems[agg->nmem++];
                memset(m, 0, sizeof(*m));
                snprintf(m->name, sizeof(m->name), "%s", clean);
                sym_tpi_type_name(ctx, mti, 0, m->type, sizeof(m->type), &m->arr_cnt, NULL);
                m->off = (moff >= 0 && moff <= 0x7FFFFFFF) ? (int)moff : 0;
                m->has_off = true;
            }
        } else if (leaf == SYM_CV_LF_ENUMERATE) {
            if (len - pos < 4) break;
            pos += 2;
            int64_t eval = 0;
            if (!sym_cv_num(p, len, &pos, &eval)) break;
            char raw[64], clean[32];
            if (!sym_skip_cstr(p, len, &pos, raw, sizeof(raw))) break;
            if (agg->kind == SYM_AGG_ENUM && sym_sanitize_ident(raw, clean, sizeof(clean))) {
                sym_mem *m = &agg->mems[agg->nmem++];
                memset(m, 0, sizeof(*m));
                snprintf(m->name, sizeof(m->name), "%s", clean);
                m->eval = eval;
            }
        } else if (leaf == SYM_CV_LF_INDEX) {
            if (len - pos < 6) break;
            uint32_t next_ti = sym_u32(p, len, pos + 2);
            pos += 6;
            if (w->steps >= SYM_MAX_FL_STEPS) break;
            w->steps++;
            sym_tpi_walk_fieldlist(ctx, next_ti, agg, depth + 1, w);
        } else if (leaf == SYM_CV_LF_BCLASS) {
            if (len - pos < 8) break;
            pos += 6;
            int64_t dummy = 0;
            if (!sym_cv_num(p, len, &pos, &dummy)) break;
        } else if (leaf == SYM_CV_LF_VBCLASS || leaf == SYM_CV_LF_IVBCLASS) {
            if (len - pos < 12) break;
            pos += 10;
            int64_t d1 = 0, d2 = 0;
            if (!sym_cv_num(p, len, &pos, &d1) || !sym_cv_num(p, len, &pos, &d2)) break;
        } else if (leaf == SYM_CV_LF_VFUNCTAB || leaf == SYM_CV_LF_FRIENDCLS) {
            if (len - pos < 6) break;
            pos += 6;
        } else if (leaf == SYM_CV_LF_VFUNCOFF) {
            if (len - pos < 10) break;
            pos += 10;
        } else if (leaf == SYM_CV_LF_STMEMBER || leaf == SYM_CV_LF_METHOD ||
                   leaf == SYM_CV_LF_NESTTYPE || leaf == SYM_CV_LF_NESTTYPEEX ||
                   leaf == SYM_CV_LF_FRIENDFCN) {
            if (len - pos < 7) break;
            pos += 6;
            if (!sym_skip_cstr(p, len, &pos, NULL, 0)) break;
        } else if (leaf == SYM_CV_LF_ONEMETHOD) {
            if (len - pos < 7) break;
            uint16_t mprop = (uint16_t)((sym_u16(p, len, pos) >> 2) & 7U);
            size_t skip = (mprop == 4U || mprop == 6U) ? 10U : 6U;
            if (len - pos < skip + 1U) break;
            pos += skip;
            if (!sym_skip_cstr(p, len, &pos, NULL, 0)) break;
        } else {
            break;
        }
    }
}

static bool sym_tpi_parse(const sym_msf *msf, typ_store *types, sym_dbg_stats *out) {
    uint32_t tpi_sz = 0;
    uint8_t *tpi = sym_msf_read_stream(msf, 2, &tpi_sz);
    if (!tpi || tpi_sz < 56) { free(tpi); return false; }

    uint32_t ver       = sym_u32(tpi, tpi_sz, 0);
    uint32_t hdr_sz    = sym_u32(tpi, tpi_sz, 4);
    uint32_t ti_begin  = sym_u32(tpi, tpi_sz, 8);
    uint32_t ti_end    = sym_u32(tpi, tpi_sz, 12);
    uint32_t rec_bytes = sym_u32(tpi, tpi_sz, 16);

    if (ver != 20040203U || hdr_sz < 56 || hdr_sz > tpi_sz || ti_end < ti_begin) {
        free(tpi);
        return false;
    }

    uint32_t max_cnt = ti_end - ti_begin;
    if (max_cnt > SYM_MAX_TPI_RECS) max_cnt = SYM_MAX_TPI_RECS;
    if (rec_bytes > tpi_sz - hdr_sz) rec_bytes = tpi_sz - hdr_sz;

    if (!types || max_cnt == 0 || rec_bytes < 4) { free(tpi); return true; }

    sym_tpi_rec *recs = (sym_tpi_rec *)calloc(max_cnt, sizeof(sym_tpi_rec));
    if (!recs) { free(tpi); return false; }

    size_t pos = hdr_sz;
    size_t end = (size_t)hdr_sz + rec_bytes;
    uint32_t nrec = 0;
    while (pos + 4 <= end && nrec < max_cnt) {
        uint16_t rlen = sym_u16(tpi, end, pos);
        uint16_t kind = sym_u16(tpi, end, pos + 2);
        if (rlen < 2 || (size_t)rlen + 2U > end - pos) break;
        recs[nrec].off  = (uint32_t)(pos + 4U);
        recs[nrec].len  = (uint16_t)(rlen - 2U);
        recs[nrec].kind = kind;
        nrec++;
        pos += (size_t)rlen + 2U;
    }

    sym_tpi_ctx ctx = {tpi, tpi_sz, ti_begin, nrec, recs};
    uint32_t total_work = 0;
    for (uint32_t i = 0; i < nrec && out->types_added < SYM_MAX_TYPES && total_work < SYM_MAX_TPI_WORK; i++) {
        uint16_t k = recs[i].kind;
        if (k != SYM_CV_LF_CLASS && k != SYM_CV_LF_STRUCTURE &&
            k != SYM_CV_LF_UNION && k != SYM_CV_LF_ENUM) continue;

        const uint8_t *p = tpi + recs[i].off;
        size_t len = recs[i].len;
        if (len < 10 || (sym_u16(p, len, 2) & 0x0080U)) continue;

        sym_agg agg;
        memset(&agg, 0, sizeof(agg));
        uint32_t field_ti = 0;
        size_t npos = 0;
        int64_t bsz = 0;

        if (k == SYM_CV_LF_ENUM) {
            if (len < 13) continue;
            agg.kind = SYM_AGG_ENUM;
            field_ti = sym_u32(p, len, 8);
            npos = 12;
        } else if (k == SYM_CV_LF_UNION) {
            agg.kind = SYM_AGG_UNION;
            field_ti = sym_u32(p, len, 4);
            npos = 8;
            if (!sym_cv_num(p, len, &npos, &bsz)) continue;
        } else {
            if (len < 18) continue;
            agg.kind = SYM_AGG_STRUCT;
            field_ti = sym_u32(p, len, 4);
            npos = 16;
            if (!sym_cv_num(p, len, &npos, &bsz)) continue;
        }

        char raw[96];
        sym_cstr(p, len, npos, raw, sizeof(raw));
        if (!sym_sanitize_ident(raw, agg.name, sizeof(agg.name))) continue;
        if (bsz > 0 && bsz <= 0x7FFFFFFF) agg.byte_size = (int)bsz;

        const typ_def *ex = typ_find(types, agg.name);
        if (ex && ex->nmem > 0) continue;

        if (field_ti != 0) {
            sym_fl_walk w;
            memset(&w, 0, sizeof(w));
            w.global_work = &total_work;
            sym_tpi_walk_fieldlist(&ctx, field_ti, &agg, 0, &w);
        }
        if (agg.nmem == 0 && agg.byte_size == 0) continue;
        sym_register_agg(types, &agg, out);
    }

    free(recs);
    free(tpi);
    return true;
}

static bool sym_pdb_parse_syms(ana_ctx *a, const sym_msf *msf, sym_dbg_stats *out) {
    uint32_t dbi_sz = 0;
    uint8_t *dbi = sym_msf_read_stream(msf, 3, &dbi_sz);
    if (!dbi || dbi_sz < 22) { free(dbi); return false; }

    uint16_t sym_strm = sym_u16(dbi, dbi_sz, 20);
    free(dbi);
    if (sym_strm == 0xFFFFU || sym_strm >= msf->num_streams) return false;

    uint32_t sym_sz = 0;
    uint8_t *syms = sym_msf_read_stream(msf, sym_strm, &sym_sz);
    if (!syms) return false;

    int prev_mute = a->hist_mute;
    a->hist_mute = 1;

    size_t pos = 0;
    while (pos + 4 <= sym_sz) {
        uint16_t rlen = sym_u16(syms, sym_sz, pos);
        uint16_t kind = sym_u16(syms, sym_sz, pos + 2);
        if (rlen < 2 || (size_t)rlen + 2U > sym_sz - pos) break;

        const uint8_t *pay = syms + pos + 4;
        size_t plen = (size_t)rlen - 2U;
        uint32_t off = 0;
        uint16_t seg = 0;
        char raw[256];
        raw[0] = 0;
        bool is_func = false;
        bool matched = false;

        if (kind == SYM_CV_S_PUB32 && plen >= 11) {
            uint32_t flags = sym_u32(pay, plen, 0);
            off = sym_u32(pay, plen, 4);
            seg = sym_u16(pay, plen, 8);
            sym_cstr(pay, plen, 10, raw, sizeof(raw));
            is_func = (flags & 3U) != 0;
            matched = true;
        } else if ((kind == SYM_CV_S_LPROC32 || kind == SYM_CV_S_GPROC32 ||
                    kind == SYM_CV_S_LPROC32_ID || kind == SYM_CV_S_GPROC32_ID) && plen >= 36) {
            off = sym_u32(pay, plen, 28);
            seg = sym_u16(pay, plen, 32);
            sym_cstr(pay, plen, 35, raw, sizeof(raw));
            is_func = true;
            matched = true;
        } else if ((kind == SYM_CV_S_LDATA32 || kind == SYM_CV_S_GDATA32) && plen >= 11) {
            off = sym_u32(pay, plen, 4);
            seg = sym_u16(pay, plen, 8);
            sym_cstr(pay, plen, 10, raw, sizeof(raw));
            matched = true;
        }

        if (matched && raw[0] && seg >= 1 && seg <= a->bin.nsec) {
            uint64_t va = a->bin.secs[seg - 1].va + (uint64_t)off;
            if (va) {
                if (!is_func && kind == SYM_CV_S_PUB32 && bin_is_exec(&a->bin, va)) is_func = true;
                sym_apply_sym(a, va, raw, is_func, out);
            }
        }
        pos += (size_t)rlen + 2U;
    }

    a->hist_mute = prev_mute;
    free(syms);
    return true;
}

static uint8_t *sym_read_pdb_file(const char *path, size_t *out_sz, char *err, size_t err_max) {
    FILE *f = fopen(path, "rb");
    if (!f) { snprintf(err, err_max, "cannot open PDB file"); return NULL; }
    if (_fseeki64(f, 0, SEEK_END) != 0) {
        fclose(f); snprintf(err, err_max, "cannot seek PDB file"); return NULL;
    }
    int64_t fsz = _ftelli64(f);
    if (fsz <= 0) {
        fclose(f); snprintf(err, err_max, "empty or unreadable PDB file"); return NULL;
    }
    if ((uint64_t)fsz > SYM_MAX_PDB_BYTES) {
        fclose(f); snprintf(err, err_max, "PDB exceeds 128 MB limit"); return NULL;
    }
    if (_fseeki64(f, 0, SEEK_SET) != 0) {
        fclose(f); snprintf(err, err_max, "cannot rewind PDB file"); return NULL;
    }
    uint8_t *buf = (uint8_t *)malloc((size_t)fsz);
    if (!buf) { fclose(f); snprintf(err, err_max, "out of memory"); return NULL; }
    size_t got = fread(buf, 1, (size_t)fsz, f);
    fclose(f);
    if (got != (size_t)fsz) {
        free(buf); snprintf(err, err_max, "short PDB read"); return NULL;
    }
    *out_sz = (size_t)fsz;
    return buf;
}

bool sym_load_pdb_msf(ana_ctx *a, typ_store *types, const char *path, sym_dbg_stats *out) {
    sym_dbg_stats local;
    if (!out) out = &local;
    memset(out, 0, sizeof(*out));
    if (!a || !path || !path[0]) {
        snprintf(out->err, sizeof(out->err), "invalid arguments");
        return false;
    }

    size_t fsz = 0;
    uint8_t *buf = sym_read_pdb_file(path, &fsz, out->err, sizeof(out->err));
    if (!buf) return false;

    sym_msf msf;
    if (!sym_msf_open(&msf, buf, fsz, out->err, sizeof(out->err))) {
        free(buf);
        return false;
    }

    snprintf(out->format, sizeof(out->format), "PDB/MSF7");
    bool tpi_ok = sym_tpi_parse(&msf, types, out);
    bool dbi_ok = sym_pdb_parse_syms(a, &msf, out);
    sym_msf_close(&msf);
    free(buf);

    if (!tpi_ok && !dbi_ok) {
        snprintf(out->err, sizeof(out->err), "no readable TPI or DBI streams");
        return false;
    }
    return true;
}

typedef struct {
    const uint8_t *data;
    size_t         size;
} sym_slice;

static bool sym_dw_sec_match(const char *sec_name, const char *want) {
    if (strcmp(sec_name, want) == 0) return true;
    const char *tail = (want[0] == '.') ? want + 1 : want;
    size_t slen = strlen(sec_name);
    size_t tlen = strlen(tail);
    if (slen > tlen && strcmp(sec_name + slen - tlen, tail) == 0) {
        char prev = sec_name[slen - tlen - 1];
        if (prev == '.' || prev == '_') return true;
    }
    return false;
}

static bool sym_dw_find_elf_sec(const bin_img *b, const char *want, sym_slice *out) {
    const uint8_t *d = b->map.data;
    size_t sz = (size_t)b->map.size;
    if (!d || sz < 52 || memcmp(d, "\x7f" "ELF", 4) != 0 || d[5] != 1) return false;

    int is64 = (d[4] == 2);
    if (!is64 && d[4] != 1) return false;
    if (is64 && sz < 64) return false;

    uint64_t shoff = is64 ? sym_u64(d, sz, 40) : sym_u32(d, sz, 32);
    uint16_t shent = sym_u16(d, sz, is64 ? 58U : 46U);
    uint16_t shnum = sym_u16(d, sz, is64 ? 60U : 48U);
    uint16_t shstr = sym_u16(d, sz, is64 ? 62U : 50U);
    uint16_t min_ent = is64 ? 64U : 40U;
    if (!shoff || shoff >= sz || !shnum || shstr >= shnum || shent < min_ent) return false;
    if (shnum > 4096U) shnum = 4096U;

    uint64_t st_sh = shoff + (uint64_t)shstr * shent;
    if (st_sh > sz || sz - (size_t)st_sh < shent) return false;
    uint64_t str_off = is64 ? sym_u64(d, sz, (size_t)st_sh + 24) : sym_u32(d, sz, (size_t)st_sh + 16);
    uint64_t str_sz  = is64 ? sym_u64(d, sz, (size_t)st_sh + 32) : sym_u32(d, sz, (size_t)st_sh + 20);
    if (str_off >= sz) return false;
    if (str_sz > (uint64_t)sz - str_off) str_sz = (uint64_t)sz - str_off;

    for (uint16_t i = 0; i < shnum; i++) {
        uint64_t s = shoff + (uint64_t)i * shent;
        if (s > sz || sz - (size_t)s < shent) break;
        uint32_t noff = sym_u32(d, sz, (size_t)s);
        uint32_t type = sym_u32(d, sz, (size_t)s + 4);
        if (type == 8U || noff >= str_sz) continue;

        char nm[48];
        sym_cstr(d, (size_t)(str_off + str_sz), (size_t)(str_off + noff), nm, sizeof(nm));
        if (strcmp(nm, want) != 0) continue;

        uint64_t foff = is64 ? sym_u64(d, sz, (size_t)s + 24) : sym_u32(d, sz, (size_t)s + 16);
        uint64_t ssz  = is64 ? sym_u64(d, sz, (size_t)s + 32) : sym_u32(d, sz, (size_t)s + 20);
        if (foff >= sz || ssz == 0) return false;
        if (ssz > (uint64_t)sz - foff) ssz = (uint64_t)sz - foff;
        out->data = d + (size_t)foff;
        out->size = (size_t)ssz;
        return true;
    }
    return false;
}

static bool sym_dw_find_pe_sec(const bin_img *b, const char *want, sym_slice *out) {
    if (!b || !want || !out) return false;
    const uint8_t *d = b->map.data;
    uint64_t sz64 = b->map.size;
    if (!d || sz64 < 0x40ULL || d[0] != 'M' || d[1] != 'Z') return false;
#if SIZE_MAX < UINT64_MAX
    if (sz64 > (uint64_t)SIZE_MAX) return false;
#endif
    size_t sz = (size_t)sz64;

    uint32_t pe_off = sym_u32(d, sz, 0x3C);
    if ((uint64_t)pe_off > sz64 - 24ULL || sym_u32(d, sz, (size_t)pe_off) != 0x00004550U) return false;

    uint16_t nsec    = sym_u16(d, sz, (size_t)pe_off + 6U);
    uint32_t sym_off = sym_u32(d, sz, (size_t)pe_off + 12U);
    uint32_t nsym    = sym_u32(d, sz, (size_t)pe_off + 16U);
    uint16_t opt_sz  = sym_u16(d, sz, (size_t)pe_off + 20U);
    if (!sym_off) return false;

    uint64_t sym_bytes = (uint64_t)nsym * 18ULL;
    if ((uint64_t)sym_off > sz64 || sym_bytes > sz64 - (uint64_t)sym_off) return false;
    uint64_t strtab = (uint64_t)sym_off + sym_bytes;
    if (sz64 - strtab < 4ULL) return false;

    uint32_t str_sz = sym_u32(d, sz, (size_t)strtab);
    if (str_sz < 4U) return false;
    uint64_t str_lim = ((uint64_t)str_sz <= sz64 - strtab) ? (uint64_t)str_sz : (sz64 - strtab);

    uint64_t sh_off = (uint64_t)pe_off + 24ULL + (uint64_t)opt_sz;
    if (sh_off > sz64 || sz64 - sh_off < 40ULL) return false;
    if (nsec > 256U) nsec = 256U;

    for (uint16_t i = 0; i < nsec; i++) {
        uint64_t s_rel = (uint64_t)i * 40ULL;
        if (s_rel > sz64 - sh_off || sz64 - (sh_off + s_rel) < 40ULL) break;
        uint64_t s = sh_off + s_rel;
        if (d[s] != '/') continue;

        uint64_t soff = 0;
        bool valid_digits = (d[s + 1] >= '0' && d[s + 1] <= '9');
        for (uint32_t k = 1; k < 8U && valid_digits; k++) {
            uint8_t c = d[s + k];
            if (c == 0) break;
            if (c < '0' || c > '9') {
                valid_digits = false;
                break;
            }
            soff = soff * 10ULL + (uint64_t)(c - '0');
        }
        if (!valid_digits || soff < 4ULL || soff >= str_lim) continue;

        char nm[48];
        sym_cstr(d, (size_t)(strtab + str_lim), (size_t)(strtab + soff), nm, sizeof(nm));
        if (strcmp(nm, want) != 0) continue;

        uint32_t vsz  = sym_u32(d, sz, (size_t)s + 8U);
        uint32_t rsz  = sym_u32(d, sz, (size_t)s + 16U);
        uint32_t roff = sym_u32(d, sz, (size_t)s + 20U);
        uint32_t use_sz = (vsz > 0 && vsz < rsz) ? vsz : rsz;
        if ((uint64_t)roff >= sz64 || use_sz == 0) return false;
        if ((uint64_t)use_sz > sz64 - (uint64_t)roff) use_sz = (uint32_t)(sz64 - (uint64_t)roff);
        out->data = d + (size_t)roff;
        out->size = (size_t)use_sz;
        return true;
    }
    return false;
}

static bool sym_dw_find_sec(const bin_img *b, const char *want, sym_slice *out) {
    out->data = NULL;
    out->size = 0;
    if (!b || !b->map.data || b->map.size == 0) return false;

    for (uint32_t i = 0; i < b->nsec; i++) {
        const bin_sec *s = &b->secs[i];
        if (!sym_dw_sec_match(s->name, want)) continue;
        if (s->foff >= b->map.size || s->fsize == 0) continue;
        uint64_t avail = b->map.size - s->foff;
        uint64_t take = s->fsize < avail ? s->fsize : avail;
        out->data = b->map.data + (size_t)s->foff;
        out->size = (size_t)take;
        return true;
    }
    // elf_load omits non-alloc debug sections
    if (sym_dw_find_elf_sec(b, want, out)) return true;
    if (sym_dw_find_pe_sec(b, want, out)) return true;
    return false;
}

static bool sym_uleb(const uint8_t *d, size_t sz, size_t *pos, uint64_t *val) {
    uint64_t res = 0;
    unsigned shift = 0;
    while (*pos < sz) {
        uint8_t b = d[(*pos)++];
        if (shift < 64) res |= (uint64_t)(b & 0x7FU) << shift;
        if ((b & 0x80U) == 0) { *val = res; return true; }
        shift += 7;
        if (shift > 70) return false;
    }
    return false;
}

static bool sym_sleb(const uint8_t *d, size_t sz, size_t *pos, int64_t *val) {
    uint64_t res = 0;
    unsigned shift = 0;
    while (*pos < sz) {
        uint8_t b = d[(*pos)++];
        if (shift < 64) res |= (uint64_t)(b & 0x7FU) << shift;
        shift += 7;
        if ((b & 0x80U) == 0) {
            if (shift < 64 && (b & 0x40U)) res |= (~0ULL << shift);
            *val = (int64_t)res;
            return true;
        }
        if (shift > 70) return false;
    }
    return false;
}

enum {
    SYM_DW_TAG_ARRAY   = 0x01,
    SYM_DW_TAG_CLASS   = 0x02,
    SYM_DW_TAG_ENUM    = 0x04,
    SYM_DW_TAG_MEMBER  = 0x0D,
    SYM_DW_TAG_PTR     = 0x0F,
    SYM_DW_TAG_CU      = 0x11,
    SYM_DW_TAG_STRUCT  = 0x13,
    SYM_DW_TAG_TYPEDEF = 0x16,
    SYM_DW_TAG_UNION   = 0x17,
    SYM_DW_TAG_BASE    = 0x24,
    SYM_DW_TAG_CONST   = 0x26,
    SYM_DW_TAG_ENUMER  = 0x28,
    SYM_DW_TAG_SUBPROG = 0x2E,
    SYM_DW_TAG_VOL     = 0x35
};

enum {
    SYM_DW_AT_NAME          = 0x03,
    SYM_DW_AT_BYTE_SIZE     = 0x0B,
    SYM_DW_AT_LOW_PC        = 0x11,
    SYM_DW_AT_CONST_VAL     = 0x1C,
    SYM_DW_AT_MEM_LOC       = 0x38,
    SYM_DW_AT_DECL          = 0x3C,
    SYM_DW_AT_ENCODING      = 0x3E,
    SYM_DW_AT_TYPE          = 0x49,
    SYM_DW_AT_LINKAGE_NAME  = 0x6E,
    SYM_DW_AT_STR_OFF_BASE  = 0x72,
    SYM_DW_AT_ADDR_BASE     = 0x73,
    SYM_DW_AT_MIPS_LINKNAME = 0x2007
};

enum {
    SYM_DW_FORM_ADDR      = 0x01,
    SYM_DW_FORM_BLOCK2    = 0x03,
    SYM_DW_FORM_BLOCK4    = 0x04,
    SYM_DW_FORM_DATA2     = 0x05,
    SYM_DW_FORM_DATA4     = 0x06,
    SYM_DW_FORM_DATA8     = 0x07,
    SYM_DW_FORM_STRING    = 0x08,
    SYM_DW_FORM_BLOCK     = 0x09,
    SYM_DW_FORM_BLOCK1    = 0x0A,
    SYM_DW_FORM_DATA1     = 0x0B,
    SYM_DW_FORM_FLAG      = 0x0C,
    SYM_DW_FORM_SDATA     = 0x0D,
    SYM_DW_FORM_STRP      = 0x0E,
    SYM_DW_FORM_UDATA     = 0x0F,
    SYM_DW_FORM_REF_ADDR  = 0x10,
    SYM_DW_FORM_REF1      = 0x11,
    SYM_DW_FORM_REF2      = 0x12,
    SYM_DW_FORM_REF4      = 0x13,
    SYM_DW_FORM_REF8      = 0x14,
    SYM_DW_FORM_REF_UDATA = 0x15,
    SYM_DW_FORM_INDIRECT  = 0x16,
    SYM_DW_FORM_SEC_OFF   = 0x17,
    SYM_DW_FORM_EXPRLOC   = 0x18,
    SYM_DW_FORM_FLAG_PRES = 0x19,
    SYM_DW_FORM_STRX      = 0x1A,
    SYM_DW_FORM_ADDRX     = 0x1B,
    SYM_DW_FORM_REF_SUP4  = 0x1C,
    SYM_DW_FORM_STRP_SUP  = 0x1D,
    SYM_DW_FORM_DATA16    = 0x1E,
    SYM_DW_FORM_LINE_STRP = 0x1F,
    SYM_DW_FORM_REF_SIG8  = 0x20,
    SYM_DW_FORM_IMP_CONST = 0x21,
    SYM_DW_FORM_LOCLISTX  = 0x22,
    SYM_DW_FORM_RNGLISTX  = 0x23,
    SYM_DW_FORM_REF_SUP8  = 0x24,
    SYM_DW_FORM_STRX1     = 0x25,
    SYM_DW_FORM_STRX2     = 0x26,
    SYM_DW_FORM_STRX3     = 0x27,
    SYM_DW_FORM_STRX4     = 0x28,
    SYM_DW_FORM_ADDRX1    = 0x29,
    SYM_DW_FORM_ADDRX2    = 0x2A,
    SYM_DW_FORM_ADDRX3    = 0x2B,
    SYM_DW_FORM_ADDRX4    = 0x2C
};

typedef struct {
    uint32_t name;
    uint32_t form;
    int64_t  imp_val;
} sym_dw_aspec;

typedef struct {
    uint64_t code;
    uint32_t tag;
    uint8_t  has_children;
    uint32_t first;
    uint32_t count;
} sym_dw_abbrev;

typedef struct {
    sym_dw_abbrev *ents;
    uint32_t       nent;
    uint32_t       ent_cap;
    sym_dw_aspec  *attrs;
    uint32_t       nattr;
    uint32_t       attr_cap;
    tbl_u64        code_map;
} sym_dw_atbl;

static void sym_dw_atbl_free(sym_dw_atbl *t) {
    free(t->ents);
    free(t->attrs);
    tbl_free(&t->code_map);
    memset(t, 0, sizeof(*t));
}

static bool sym_dw_atbl_parse(sym_dw_atbl *t, sym_slice abbrev, size_t off) {
    t->nent = 0;
    t->nattr = 0;
    tbl_clear(&t->code_map);
    if (off >= abbrev.size) return false;

    size_t pos = off;
    while (pos < abbrev.size && t->nent < 65536U) {
        uint64_t code = 0, tag = 0;
        if (!sym_uleb(abbrev.data, abbrev.size, &pos, &code)) return false;
        if (code == 0) return true;
        if (!sym_uleb(abbrev.data, abbrev.size, &pos, &tag) || pos >= abbrev.size) return false;
        if (tag > 0xFFFFFFFFULL) return false;
        uint8_t children = abbrev.data[pos++];

        if (t->nent == t->ent_cap) {
            uint32_t nc = t->ent_cap ? t->ent_cap * 2U : 64U;
            sym_dw_abbrev *ne = (sym_dw_abbrev *)realloc(t->ents, (size_t)nc * sizeof(sym_dw_abbrev));
            if (!ne) return false;
            t->ents = ne;
            t->ent_cap = nc;
        }

        uint32_t first = t->nattr;
        for (;;) {
            uint64_t an = 0, af = 0;
            if (!sym_uleb(abbrev.data, abbrev.size, &pos, &an) ||
                !sym_uleb(abbrev.data, abbrev.size, &pos, &af)) return false;
            if (an == 0 && af == 0) break;
            if (an > 0xFFFFFFFFULL || af > 0xFFFFFFFFULL) return false;

            int64_t imp = 0;
            if (af == SYM_DW_FORM_IMP_CONST && !sym_sleb(abbrev.data, abbrev.size, &pos, &imp)) {
                return false;
            }
            if (t->nattr >= 524288U) return false;
            if (t->nattr == t->attr_cap) {
                uint32_t nc = t->attr_cap ? t->attr_cap * 2U : 256U;
                sym_dw_aspec *na = (sym_dw_aspec *)realloc(t->attrs, (size_t)nc * sizeof(sym_dw_aspec));
                if (!na) return false;
                t->attrs = na;
                t->attr_cap = nc;
            }
            t->attrs[t->nattr].name = (uint32_t)an;
            t->attrs[t->nattr].form = (uint32_t)af;
            t->attrs[t->nattr].imp_val = imp;
            t->nattr++;
        }

        uint32_t idx = t->nent;
        if (tbl_get(&t->code_map, code) == TBL_NONE) {
            if (!tbl_put(&t->code_map, code, idx)) return false;
        }
        sym_dw_abbrev *e = &t->ents[t->nent++];
        e->code = code;
        e->tag = (uint32_t)tag;
        e->has_children = children;
        e->first = first;
        e->count = t->nattr - first;
    }
    return true;
}

static const sym_dw_abbrev *sym_dw_atbl_find(const sym_dw_atbl *t, uint64_t code) {
    if (code >= 1 && code <= t->nent && t->ents[code - 1].code == code) {
        return &t->ents[code - 1];
    }
    uint32_t idx = tbl_get(&t->code_map, code);
    if (idx < t->nent) return &t->ents[idx];
    return NULL;
}

#define SYM_DW_ACACHE_CAP   16U
#define SYM_DW_ACACHE_BYTES (32ULL * 1024ULL * 1024ULL)

typedef struct {
    size_t      abbrev_off;
    uint64_t    last_use;
    bool        valid;
    bool        ok;
    sym_dw_atbl tbl;
} sym_dw_acache_ent;

typedef struct {
    sym_dw_acache_ent ents[SYM_DW_ACACHE_CAP];
    uint64_t          tick;
} sym_dw_acache;

static void sym_dw_acache_free(sym_dw_acache *c) {
    if (!c) return;
    for (uint32_t i = 0; i < SYM_DW_ACACHE_CAP; i++) {
        sym_dw_atbl_free(&c->ents[i].tbl);
    }
    memset(c, 0, sizeof(*c));
}

static uint64_t sym_dw_acache_bytes(const sym_dw_acache *c) {
    uint64_t tot = 0;
    for (uint32_t i = 0; i < SYM_DW_ACACHE_CAP; i++) {
        const sym_dw_acache_ent *e = &c->ents[i];
        if (!e->valid) continue;
        tot += (uint64_t)e->tbl.ent_cap * sizeof(sym_dw_abbrev);
        tot += (uint64_t)e->tbl.attr_cap * sizeof(sym_dw_aspec);
        tot += (uint64_t)e->tbl.code_map.cap * sizeof(tbl_slot);
    }
    return tot;
}

static const sym_dw_atbl *sym_dw_acache_get(sym_dw_acache *c, sym_slice abbrev, size_t off) {
    if (!c) return NULL;
    for (uint32_t i = 0; i < SYM_DW_ACACHE_CAP; i++) {
        sym_dw_acache_ent *e = &c->ents[i];
        if (e->valid && e->abbrev_off == off) {
            e->last_use = ++c->tick;
            return e->ok ? &e->tbl : NULL;
        }
    }

    uint32_t vi = 0;
    uint64_t min_use = UINT64_MAX;
    for (uint32_t i = 0; i < SYM_DW_ACACHE_CAP; i++) {
        if (!c->ents[i].valid) {
            vi = i;
            break;
        }
        if (c->ents[i].last_use < min_use) {
            min_use = c->ents[i].last_use;
            vi = i;
        }
    }

    sym_dw_acache_ent *dst = &c->ents[vi];
    dst->abbrev_off = off;
    dst->last_use = ++c->tick;
    dst->valid = true;
    dst->ok = sym_dw_atbl_parse(&dst->tbl, abbrev, off);
    if (!dst->ok) {
        sym_dw_atbl_free(&dst->tbl);
    }

    while (sym_dw_acache_bytes(c) > SYM_DW_ACACHE_BYTES) {
        uint32_t evict_i = UINT32_MAX;
        uint64_t evict_use = UINT64_MAX;
        for (uint32_t j = 0; j < SYM_DW_ACACHE_CAP; j++) {
            if (j == vi || !c->ents[j].valid) continue;
            if (c->ents[j].last_use <= evict_use) {
                evict_use = c->ents[j].last_use;
                evict_i = j;
            }
        }
        if (evict_i == UINT32_MAX) break;
        sym_dw_atbl_free(&c->ents[evict_i].tbl);
        c->ents[evict_i].valid = false;
        c->ents[evict_i].ok = false;
    }

    return dst->ok ? &dst->tbl : NULL;
}

typedef enum {
    SYM_DWV_NONE = 0,
    SYM_DWV_UINT,
    SYM_DWV_SINT,
    SYM_DWV_STR,
    SYM_DWV_REF,
    SYM_DWV_BLOCK
} sym_dw_vkind;

typedef struct {
    sym_dw_vkind   kind;
    uint64_t       uval;
    int64_t        sval;
    const uint8_t *ptr;
    size_t         len;
    char           str[256];
} sym_dw_val;

typedef struct {
    sym_slice info;
    sym_slice abbrev;
    sym_slice str;
    sym_slice line_str;
    sym_slice str_offs;
    sym_slice addr;
} sym_dw_secs;

typedef struct {
    size_t   cu_start;
    size_t   cu_end;
    uint16_t version;
    uint8_t  addr_size;
    uint64_t str_off_base;
    uint64_t addr_base;
} sym_dw_cu;

static bool sym_dw_read_form(const sym_dw_secs *secs, const sym_dw_cu *cu,
                             uint32_t form, int64_t imp_val, size_t *pos, sym_dw_val *v, int depth) {
    memset(v, 0, sizeof(*v));
    if (depth > 4) return false;
    const uint8_t *d = secs->info.data;
    size_t end = cu->cu_end;

    switch (form) {
    case SYM_DW_FORM_ADDR:
        if (end - *pos < cu->addr_size) return false;
        v->kind = SYM_DWV_UINT;
        v->uval = (cu->addr_size == 8) ? sym_u64(d, end, *pos) : (uint64_t)sym_u32(d, end, *pos);
        v->sval = (int64_t)v->uval;
        *pos += cu->addr_size;
        return true;
    case SYM_DW_FORM_DATA1:
        if (end - *pos < 1) return false;
        v->kind = SYM_DWV_UINT;
        v->uval = d[*pos];
        v->sval = (int8_t)d[(*pos)++];
        return true;
    case SYM_DW_FORM_DATA2:
        if (end - *pos < 2) return false;
        v->kind = SYM_DWV_UINT;
        v->uval = sym_u16(d, end, *pos);
        v->sval = (int16_t)v->uval;
        *pos += 2;
        return true;
    case SYM_DW_FORM_DATA4:
        if (end - *pos < 4) return false;
        v->kind = SYM_DWV_UINT;
        v->uval = sym_u32(d, end, *pos);
        v->sval = (int32_t)v->uval;
        *pos += 4;
        return true;
    case SYM_DW_FORM_DATA8:
        if (end - *pos < 8) return false;
        v->kind = SYM_DWV_UINT;
        v->uval = sym_u64(d, end, *pos);
        v->sval = (int64_t)v->uval;
        *pos += 8;
        return true;
    case SYM_DW_FORM_DATA16:
        if (end - *pos < 16) return false;
        v->kind = SYM_DWV_BLOCK;
        v->ptr = d + *pos;
        v->len = 16;
        *pos += 16;
        return true;
    case SYM_DW_FORM_UDATA:
    case SYM_DW_FORM_LOCLISTX:
    case SYM_DW_FORM_RNGLISTX:
        if (!sym_uleb(d, end, pos, &v->uval)) return false;
        v->kind = SYM_DWV_UINT;
        v->sval = (int64_t)v->uval;
        return true;
    case SYM_DW_FORM_SDATA:
        if (!sym_sleb(d, end, pos, &v->sval)) return false;
        v->kind = SYM_DWV_SINT;
        v->uval = (uint64_t)v->sval;
        return true;
    case SYM_DW_FORM_IMP_CONST:
        v->kind = SYM_DWV_SINT;
        v->sval = imp_val;
        v->uval = (uint64_t)imp_val;
        return true;
    case SYM_DW_FORM_FLAG:
        if (end - *pos < 1) return false;
        v->kind = SYM_DWV_UINT;
        v->uval = d[(*pos)++] ? 1ULL : 0ULL;
        return true;
    case SYM_DW_FORM_FLAG_PRES:
        v->kind = SYM_DWV_UINT;
        v->uval = 1;
        return true;
    case SYM_DW_FORM_STRING:
        if (!sym_skip_cstr(d, end, pos, v->str, sizeof(v->str))) return false;
        v->kind = SYM_DWV_STR;
        return true;
    case SYM_DW_FORM_STRP:
    case SYM_DW_FORM_LINE_STRP: {
        if (end - *pos < 4) return false;
        uint32_t soff = sym_u32(d, end, *pos);
        *pos += 4;
        v->kind = SYM_DWV_STR;
        sym_slice tab = (form == SYM_DW_FORM_STRP) ? secs->str : secs->line_str;
        if (tab.data && soff < tab.size) sym_cstr(tab.data, tab.size, soff, v->str, sizeof(v->str));
        return true;
    }
    case SYM_DW_FORM_STRP_SUP:
    case SYM_DW_FORM_REF_SUP4:
        if (end - *pos < 4) return false;
        *pos += 4;
        return true;
    case SYM_DW_FORM_REF_SIG8:
    case SYM_DW_FORM_REF_SUP8:
        if (end - *pos < 8) return false;
        *pos += 8;
        return true;
    case SYM_DW_FORM_SEC_OFF:
        if (end - *pos < 4) return false;
        v->kind = SYM_DWV_UINT;
        v->uval = sym_u32(d, end, *pos);
        *pos += 4;
        return true;
    case SYM_DW_FORM_REF1:
        if (end - *pos < 1) return false;
        v->kind = SYM_DWV_REF;
        v->uval = (uint64_t)cu->cu_start + d[(*pos)++];
        return true;
    case SYM_DW_FORM_REF2:
        if (end - *pos < 2) return false;
        v->kind = SYM_DWV_REF;
        v->uval = (uint64_t)cu->cu_start + sym_u16(d, end, *pos);
        *pos += 2;
        return true;
    case SYM_DW_FORM_REF4:
        if (end - *pos < 4) return false;
        v->kind = SYM_DWV_REF;
        v->uval = (uint64_t)cu->cu_start + sym_u32(d, end, *pos);
        *pos += 4;
        return true;
    case SYM_DW_FORM_REF8:
        if (end - *pos < 8) return false;
        v->kind = SYM_DWV_REF;
        v->uval = (uint64_t)cu->cu_start + sym_u64(d, end, *pos);
        *pos += 8;
        return true;
    case SYM_DW_FORM_REF_UDATA: {
        uint64_t rel = 0;
        if (!sym_uleb(d, end, pos, &rel)) return false;
        v->kind = SYM_DWV_REF;
        v->uval = (uint64_t)cu->cu_start + rel;
        return true;
    }
    case SYM_DW_FORM_REF_ADDR: {
        size_t n = (cu->version == 2) ? (size_t)cu->addr_size : 4U;
        if (end - *pos < n) return false;
        v->kind = SYM_DWV_REF;
        v->uval = (n == 8) ? sym_u64(d, end, *pos) : (uint64_t)sym_u32(d, end, *pos);
        *pos += n;
        return true;
    }
    case SYM_DW_FORM_BLOCK1:
    case SYM_DW_FORM_BLOCK2:
    case SYM_DW_FORM_BLOCK4:
    case SYM_DW_FORM_BLOCK:
    case SYM_DW_FORM_EXPRLOC: {
        uint64_t blen = 0;
        if (form == SYM_DW_FORM_BLOCK1) {
            if (end - *pos < 1) return false;
            blen = d[(*pos)++];
        } else if (form == SYM_DW_FORM_BLOCK2) {
            if (end - *pos < 2) return false;
            blen = sym_u16(d, end, *pos); *pos += 2;
        } else if (form == SYM_DW_FORM_BLOCK4) {
            if (end - *pos < 4) return false;
            blen = sym_u32(d, end, *pos); *pos += 4;
        } else if (!sym_uleb(d, end, pos, &blen)) {
            return false;
        }
        if (blen > end - *pos) return false;
        v->kind = SYM_DWV_BLOCK;
        v->ptr = d + *pos;
        v->len = (size_t)blen;
        *pos += (size_t)blen;
        return true;
    }
    case SYM_DW_FORM_INDIRECT: {
        uint64_t rf = 0;
        if (!sym_uleb(d, end, pos, &rf)) return false;
        if (rf > 0xFFFFFFFFULL) return false;
        return sym_dw_read_form(secs, cu, (uint32_t)rf, 0, pos, v, depth + 1);
    }
    case SYM_DW_FORM_STRX:
    case SYM_DW_FORM_STRX1:
    case SYM_DW_FORM_STRX2:
    case SYM_DW_FORM_STRX3:
    case SYM_DW_FORM_STRX4: {
        uint64_t idx = 0;
        if (form == SYM_DW_FORM_STRX) {
            if (!sym_uleb(d, end, pos, &idx)) return false;
        } else {
            size_t nb = (size_t)(form - SYM_DW_FORM_STRX1 + 1);
            if (end - *pos < nb) return false;
            for (size_t k = 0; k < nb; k++) idx |= (uint64_t)d[*pos + k] << (k * 8U);
            *pos += nb;
        }
        v->kind = SYM_DWV_STR;
        if (secs->str_offs.data && secs->str.data &&
            cu->str_off_base <= secs->str_offs.size &&
            secs->str_offs.size - (size_t)cu->str_off_base >= 4U &&
            idx <= (secs->str_offs.size - (size_t)cu->str_off_base - 4U) / 4U) {
            size_t slot = (size_t)cu->str_off_base + (size_t)idx * 4U;
            uint32_t soff = sym_u32(secs->str_offs.data, secs->str_offs.size, slot);
            if (soff < secs->str.size) sym_cstr(secs->str.data, secs->str.size, soff, v->str, sizeof(v->str));
        }
        return true;
    }
    case SYM_DW_FORM_ADDRX:
    case SYM_DW_FORM_ADDRX1:
    case SYM_DW_FORM_ADDRX2:
    case SYM_DW_FORM_ADDRX3:
    case SYM_DW_FORM_ADDRX4: {
        uint64_t idx = 0;
        if (form == SYM_DW_FORM_ADDRX) {
            if (!sym_uleb(d, end, pos, &idx)) return false;
        } else {
            size_t nb = (size_t)(form - SYM_DW_FORM_ADDRX1 + 1);
            if (end - *pos < nb) return false;
            for (size_t k = 0; k < nb; k++) idx |= (uint64_t)d[*pos + k] << (k * 8U);
            *pos += nb;
        }
        v->kind = SYM_DWV_UINT;
        if (secs->addr.data && cu->addr_size > 0 &&
            cu->addr_base <= secs->addr.size &&
            secs->addr.size - (size_t)cu->addr_base >= (size_t)cu->addr_size &&
            idx <= (secs->addr.size - (size_t)cu->addr_base - (size_t)cu->addr_size) / (size_t)cu->addr_size) {
            size_t slot = (size_t)cu->addr_base + (size_t)idx * (size_t)cu->addr_size;
            v->uval = (cu->addr_size == 8)
                      ? sym_u64(secs->addr.data, secs->addr.size, slot)
                      : (uint64_t)sym_u32(secs->addr.data, secs->addr.size, slot);
        }
        return true;
    }
    default:
        return false;
    }
}

static bool sym_dw_member_loc(const sym_dw_val *v, int *out_off) {
    if (v->kind == SYM_DWV_UINT || v->kind == SYM_DWV_SINT) {
        if (v->uval <= 0x7FFFFFFFULL) { *out_off = (int)v->uval; return true; }
        return false;
    }
    if (v->kind == SYM_DWV_BLOCK && v->ptr && v->len >= 1) {
        if (v->ptr[0] == 0x23U && v->len >= 2) {
            size_t p = 1;
            uint64_t u = 0;
            if (sym_uleb(v->ptr, v->len, &p, &u) && u <= 0x7FFFFFFFULL) {
                *out_off = (int)u;
                return true;
            }
        } else if (v->ptr[0] >= 0x30U && v->ptr[0] <= 0x4FU) {
            *out_off = (int)(v->ptr[0] - 0x30U);
            return true;
        }
    }
    return false;
}

typedef struct {
    uint64_t die_off;
    uint32_t tag;
    uint32_t byte_size;
    uint8_t  encoding;
    uint8_t  has_ref;
    uint64_t ref_off;
    char     name[40];
} sym_dw_type;

typedef struct {
    sym_agg  agg;
    uint64_t type_refs[SYM_MAX_MEMS];
    uint8_t  has_type[SYM_MAX_MEMS];
    int      parent_depth;
} sym_dw_pending;

typedef struct {
    sym_dw_type    *types;
    uint32_t        ntype;
    uint32_t        type_cap;
    sym_dw_pending *aggs;
    uint32_t        nagg;
    uint32_t        agg_cap;
} sym_dw_cu_data;

typedef struct {
    char     name[256];
    char     link_name[256];
    uint64_t low_pc;
    uint64_t byte_size;
    uint64_t type_ref;
    int64_t  const_val;
    int      mem_off;
    uint8_t  encoding;
    bool     has_type;
    bool     has_mem_off;
    bool     is_decl;
} sym_dw_die;

static void sym_dw_cu_data_free(sym_dw_cu_data *cd) {
    free(cd->types);
    free(cd->aggs);
    memset(cd, 0, sizeof(*cd));
}

static void sym_dw_add_type(sym_dw_cu_data *cd, const sym_dw_type *dt) {
    if (cd->ntype >= 131072U) return;
    if (cd->ntype == cd->type_cap) {
        uint32_t nc = cd->type_cap ? cd->type_cap * 2U : 128U;
        sym_dw_type *nt = (sym_dw_type *)realloc(cd->types, (size_t)nc * sizeof(sym_dw_type));
        if (!nt) return;
        cd->types = nt;
        cd->type_cap = nc;
    }
    cd->types[cd->ntype++] = *dt;
}

static void sym_dw_add_agg(sym_dw_cu_data *cd, const sym_dw_pending *p) {
    if (cd->nagg >= SYM_MAX_TYPES) return;
    if (cd->nagg == cd->agg_cap) {
        uint32_t nc = cd->agg_cap ? cd->agg_cap * 2U : 32U;
        sym_dw_pending *na = (sym_dw_pending *)realloc(cd->aggs, (size_t)nc * sizeof(sym_dw_pending));
        if (!na) return;
        cd->aggs = na;
        cd->agg_cap = nc;
    }
    cd->aggs[cd->nagg++] = *p;
}

static const sym_dw_type *sym_dw_find_type(const sym_dw_cu_data *cd, uint64_t die_off) {
    uint32_t lo = 0, hi = cd->ntype;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2U;
        if (cd->types[mid].die_off < die_off) lo = mid + 1U;
        else if (cd->types[mid].die_off > die_off) hi = mid;
        else return &cd->types[mid];
    }
    return NULL;
}

static void sym_dw_resolve_type(const sym_dw_cu_data *cd, uint64_t ref_off, int depth,
                                char *out, size_t max) {
    if (depth > 8) { snprintf(out, max, "void *"); return; }
    const sym_dw_type *dt = sym_dw_find_type(cd, ref_off);
    if (!dt) { snprintf(out, max, "uint64_t"); return; }

    if (dt->tag == SYM_DW_TAG_CONST || dt->tag == SYM_DW_TAG_VOL || dt->tag == SYM_DW_TAG_ARRAY) {
        if (dt->has_ref) sym_dw_resolve_type(cd, dt->ref_off, depth + 1, out, max);
        else snprintf(out, max, "uint64_t");
        return;
    }
    if (dt->tag == SYM_DW_TAG_TYPEDEF) {
        if (dt->has_ref) sym_dw_resolve_type(cd, dt->ref_off, depth + 1, out, max);
        else snprintf(out, max, "%s", dt->name[0] ? dt->name : "uint64_t");
        return;
    }
    if (dt->tag == SYM_DW_TAG_PTR) {
        if (!dt->has_ref) { snprintf(out, max, "void *"); return; }
        char inner[32];
        sym_dw_resolve_type(cd, dt->ref_off, depth + 1, inner, sizeof(inner));
        if (strcmp(inner, "char") == 0) snprintf(out, max, "char *");
        else if (strcmp(inner, "void") == 0 || strchr(inner, '*') != NULL || strlen(inner) > 22)
            snprintf(out, max, "void *");
        else snprintf(out, max, "%s *", inner);
        return;
    }
    if (dt->tag == SYM_DW_TAG_BASE) {
        if (dt->encoding == 2) snprintf(out, max, "bool");
        else if (dt->encoding == 4) snprintf(out, max, "%s", dt->byte_size == 4 ? "float" : "double");
        else if (dt->encoding == 6) snprintf(out, max, "char");
        else if (dt->encoding == 8) snprintf(out, max, "uint8_t");
        else if (dt->encoding == 1) snprintf(out, max, "void *");
        else if (dt->encoding == 5) {
            snprintf(out, max, "%s", dt->byte_size == 1 ? "int8_t" :
                     dt->byte_size == 2 ? "int16_t" : dt->byte_size == 4 ? "int32_t" : "int64_t");
        } else {
            snprintf(out, max, "%s", dt->byte_size == 1 ? "uint8_t" :
                     dt->byte_size == 2 ? "uint16_t" : dt->byte_size == 4 ? "uint32_t" : "uint64_t");
        }
        return;
    }
    snprintf(out, max, "%s", dt->name[0] ? dt->name : "uint64_t");
}

static void sym_dw_flush_aggs(const sym_dw_cu_data *cd, uint8_t addr_size,
                              typ_store *types, sym_dbg_stats *out) {
    if (!types) return;
    for (uint32_t i = 0; i < cd->nagg && out->types_added < SYM_MAX_TYPES; i++) {
        sym_agg agg = cd->aggs[i].agg;
        if (agg.kind != SYM_AGG_ENUM) {
            for (int k = 0; k < agg.nmem; k++) {
                if (cd->aggs[i].has_type[k]) {
                    sym_dw_resolve_type(cd, cd->aggs[i].type_refs[k], 0,
                                        agg.mems[k].type, sizeof(agg.mems[k].type));
                } else {
                    int span = 0;
                    if (agg.mems[k].has_off && k + 1 < agg.nmem && agg.mems[k + 1].has_off) {
                        span = agg.mems[k + 1].off - agg.mems[k].off;
                    } else if (agg.mems[k].has_off && agg.byte_size > agg.mems[k].off) {
                        span = agg.byte_size - agg.mems[k].off;
                    }
                    snprintf(agg.mems[k].type, sizeof(agg.mems[k].type), "%s",
                             span == 1 ? "uint8_t" : span == 2 ? "uint16_t" :
                             span == 4 ? "uint32_t" : span == 8 ? "uint64_t" :
                             (addr_size == 4 ? "uint32_t" : "uint64_t"));
                }
            }
        }
        if (agg.nmem == 0 && agg.byte_size == 0) continue;
        sym_register_agg(types, &agg, out);
    }
}

static bool sym_dw_read_die(const sym_dw_secs *secs, sym_dw_cu *cu, const sym_dw_atbl *atbl,
                            const sym_dw_abbrev *ab, size_t *pos, sym_dw_die *die) {
    memset(die, 0, sizeof(*die));
    for (uint32_t i = 0; i < ab->count; i++) {
        const sym_dw_aspec *sp_attr = &atbl->attrs[ab->first + i];
        sym_dw_val v;
        if (!sym_dw_read_form(secs, cu, sp_attr->form, sp_attr->imp_val, pos, &v, 0)) return false;

        switch (sp_attr->name) {
        case SYM_DW_AT_NAME:
            if (v.kind == SYM_DWV_STR && v.str[0]) snprintf(die->name, sizeof(die->name), "%s", v.str);
            break;
        case SYM_DW_AT_LINKAGE_NAME:
        case SYM_DW_AT_MIPS_LINKNAME:
            if (v.kind == SYM_DWV_STR && v.str[0]) snprintf(die->link_name, sizeof(die->link_name), "%s", v.str);
            break;
        case SYM_DW_AT_LOW_PC:
            if (v.kind == SYM_DWV_UINT) die->low_pc = v.uval;
            break;
        case SYM_DW_AT_BYTE_SIZE:
            if (v.kind == SYM_DWV_UINT || v.kind == SYM_DWV_SINT) die->byte_size = v.uval;
            break;
        case SYM_DW_AT_TYPE:
            if (v.kind == SYM_DWV_REF) { die->type_ref = v.uval; die->has_type = true; }
            break;
        case SYM_DW_AT_CONST_VAL:
            if (v.kind == SYM_DWV_UINT || v.kind == SYM_DWV_SINT) die->const_val = v.sval;
            break;
        case SYM_DW_AT_MEM_LOC:
            if (sym_dw_member_loc(&v, &die->mem_off)) die->has_mem_off = true;
            break;
        case SYM_DW_AT_DECL:
            if (v.kind == SYM_DWV_UINT && v.uval != 0) die->is_decl = true;
            break;
        case SYM_DW_AT_ENCODING:
            if (v.kind == SYM_DWV_UINT) die->encoding = (uint8_t)v.uval;
            break;
        case SYM_DW_AT_STR_OFF_BASE:
            if (ab->tag == SYM_DW_TAG_CU && v.kind == SYM_DWV_UINT) cu->str_off_base = v.uval;
            break;
        case SYM_DW_AT_ADDR_BASE:
            if (ab->tag == SYM_DW_TAG_CU && v.kind == SYM_DWV_UINT) cu->addr_base = v.uval;
            break;
        default:
            break;
        }
    }
    return true;
}

static bool sym_dw_parse_hdr(const sym_dw_secs *secs, size_t *cu_pos, sym_dw_cu *cu,
                             size_t *die_pos, uint32_t *abbrev_off, bool *skip_cu) {
    *skip_cu = false;
    size_t start = *cu_pos;
    if (secs->info.size - start < 4) return false;

    uint32_t ulen = sym_u32(secs->info.data, secs->info.size, start);
    if (ulen == 0) return false;
    if (ulen == 0xFFFFFFFFU) {
        if (secs->info.size - start < 12) return false;
        uint64_t len64 = sym_u64(secs->info.data, secs->info.size, start + 4);
        if (len64 > secs->info.size - start - 12) return false;
        *cu_pos = start + 12U + (size_t)len64;
        *skip_cu = true;
        return true;
    }
    if (ulen >= 0xFFFFFFF0U || (size_t)ulen > secs->info.size - start - 4U) return false;

    size_t cu_end = start + 4U + (size_t)ulen;
    *cu_pos = cu_end;
    size_t pos = start + 4U;
    if (cu_end - pos < 7) { *skip_cu = true; return true; }

    uint16_t ver = sym_u16(secs->info.data, cu_end, pos);
    pos += 2;
    if (ver < 2 || ver > 5) { *skip_cu = true; return true; }

    uint8_t addr_size = 0;
    uint32_t aoff = 0;
    if (ver == 5) {
        if (cu_end - pos < 6) { *skip_cu = true; return true; }
        uint8_t utype = secs->info.data[pos++];
        addr_size = secs->info.data[pos++];
        aoff = sym_u32(secs->info.data, cu_end, pos);
        pos += 4;
        size_t extra = (utype == 2 || utype == 6) ? 12U : ((utype == 4 || utype == 5) ? 8U : 0U);
        if (cu_end - pos < extra) { *skip_cu = true; return true; }
        pos += extra;
    } else {
        if (cu_end - pos < 5) { *skip_cu = true; return true; }
        aoff = sym_u32(secs->info.data, cu_end, pos);
        pos += 4;
        addr_size = secs->info.data[pos++];
    }

    if ((addr_size != 4 && addr_size != 8) || aoff >= secs->abbrev.size) {
        *skip_cu = true;
        return true;
    }

    memset(cu, 0, sizeof(*cu));
    cu->cu_start = start;
    cu->cu_end = cu_end;
    cu->version = ver;
    cu->addr_size = addr_size;
    *die_pos = pos;
    *abbrev_off = aoff;
    return true;
}

static bool sym_dw_parse_cu(ana_ctx *a, typ_store *types, const sym_dw_secs *secs,
                            sym_dw_acache *acache, size_t *cu_pos, sym_dbg_stats *out) {
    sym_dw_cu cu;
    size_t pos = 0;
    uint32_t abbrev_off = 0;
    bool skip_cu = false;
    if (!sym_dw_parse_hdr(secs, cu_pos, &cu, &pos, &abbrev_off, &skip_cu)) return false;
    if (skip_cu) return true;
    const sym_dw_atbl *atbl = sym_dw_acache_get(acache, secs->abbrev, abbrev_off);
    if (!atbl) return true;

    sym_dw_cu_data cd;
    memset(&cd, 0, sizeof(cd));
    sym_dw_pending stack[16];
    int sp = 0, depth = 0;
    uint32_t dies = 0;

    while (pos < cu.cu_end && dies < SYM_MAX_DW_DIES) {
        size_t die_off = pos;
        uint64_t code = 0;
        if (!sym_uleb(secs->info.data, cu.cu_end, &pos, &code)) break;

        if (code == 0) {
            if (depth == 0) break;
            if (sp > 0 && stack[sp - 1].parent_depth == depth - 1) sym_dw_add_agg(&cd, &stack[--sp]);
            depth--;
            continue;
        }

        const sym_dw_abbrev *ab = sym_dw_atbl_find(atbl, code);
        if (!ab) break;
        dies++;

        sym_dw_die die;
        if (!sym_dw_read_die(secs, &cu, atbl, ab, &pos, &die)) break;

        uint32_t tag = ab->tag;
        if (tag == SYM_DW_TAG_SUBPROG && die.low_pc != 0) {
            const char *raw = die.link_name[0] ? die.link_name : die.name;
            if (raw[0]) sym_apply_sym(a, die.low_pc, raw, true, out);
        } else if (tag == SYM_DW_TAG_BASE || tag == SYM_DW_TAG_PTR || tag == SYM_DW_TAG_TYPEDEF ||
                   tag == SYM_DW_TAG_CONST || tag == SYM_DW_TAG_VOL || tag == SYM_DW_TAG_ARRAY ||
                   tag == SYM_DW_TAG_STRUCT || tag == SYM_DW_TAG_CLASS ||
                   tag == SYM_DW_TAG_UNION || tag == SYM_DW_TAG_ENUM) {
            sym_dw_type dt;
            memset(&dt, 0, sizeof(dt));
            dt.die_off = (uint64_t)die_off;
            dt.tag = tag;
            dt.byte_size = (die.byte_size <= 0xFFFFFFFFULL) ? (uint32_t)die.byte_size : 0;
            dt.encoding = die.encoding;
            dt.has_ref = die.has_type ? 1 : 0;
            dt.ref_off = die.type_ref;
            if (die.name[0]) sym_sanitize_ident(die.name, dt.name, sizeof(dt.name));
            sym_dw_add_type(&cd, &dt);

            if ((tag == SYM_DW_TAG_STRUCT || tag == SYM_DW_TAG_CLASS ||
                 tag == SYM_DW_TAG_UNION || tag == SYM_DW_TAG_ENUM) &&
                !die.is_decl && dt.name[0]) {
                sym_dw_pending pend;
                memset(&pend, 0, sizeof(pend));
                snprintf(pend.agg.name, sizeof(pend.agg.name), "%s", dt.name);
                pend.agg.kind = (tag == SYM_DW_TAG_ENUM) ? SYM_AGG_ENUM
                              : (tag == SYM_DW_TAG_UNION ? SYM_AGG_UNION : SYM_AGG_STRUCT);
                if (die.byte_size > 0 && die.byte_size <= 0x7FFFFFFFULL) {
                    pend.agg.byte_size = (int)die.byte_size;
                }
                pend.parent_depth = depth;
                if (ab->has_children) {
                    if (sp < 16) stack[sp++] = pend;
                } else if (pend.agg.byte_size > 0) {
                    sym_dw_add_agg(&cd, &pend);
                }
            }
        } else if (tag == SYM_DW_TAG_MEMBER && sp > 0 && stack[sp - 1].parent_depth == depth - 1) {
            sym_dw_pending *top = &stack[sp - 1];
            char clean[32];
            if (top->agg.kind != SYM_AGG_ENUM && top->agg.nmem < SYM_MAX_MEMS &&
                sym_sanitize_ident(die.name, clean, sizeof(clean))) {
                int idx = top->agg.nmem++;
                sym_mem *m = &top->agg.mems[idx];
                memset(m, 0, sizeof(*m));
                snprintf(m->name, sizeof(m->name), "%s", clean);
                m->off = die.mem_off;
                m->has_off = die.has_mem_off;
                top->has_type[idx] = die.has_type ? 1 : 0;
                top->type_refs[idx] = die.type_ref;
            }
        } else if (tag == SYM_DW_TAG_ENUMER && sp > 0 && stack[sp - 1].parent_depth == depth - 1) {
            sym_dw_pending *top = &stack[sp - 1];
            char clean[32];
            if (top->agg.kind == SYM_AGG_ENUM && top->agg.nmem < SYM_MAX_MEMS &&
                sym_sanitize_ident(die.name, clean, sizeof(clean))) {
                sym_mem *m = &top->agg.mems[top->agg.nmem++];
                memset(m, 0, sizeof(*m));
                snprintf(m->name, sizeof(m->name), "%s", clean);
                m->eval = die.const_val;
            }
        }

        if (ab->has_children) {
            if (depth >= SYM_MAX_DW_DEPTH) break;
            depth++;
        }
    }

    while (sp > 0) sym_dw_add_agg(&cd, &stack[--sp]);
    sym_dw_flush_aggs(&cd, cu.addr_size, types, out);
    sym_dw_cu_data_free(&cd);
    return true;
}

bool sym_load_dwarf(ana_ctx *a, typ_store *types, sym_dbg_stats *out) {
    sym_dbg_stats local;
    if (!out) out = &local;
    memset(out, 0, sizeof(*out));
    if (!a) {
        snprintf(out->err, sizeof(out->err), "invalid arguments");
        return false;
    }

    sym_dw_secs secs;
    memset(&secs, 0, sizeof(secs));
    if (!sym_dw_find_sec(&a->bin, ".debug_info", &secs.info) ||
        !sym_dw_find_sec(&a->bin, ".debug_abbrev", &secs.abbrev)) {
        snprintf(out->err, sizeof(out->err), "no DWARF debug sections");
        return false;
    }
    (void)sym_dw_find_sec(&a->bin, ".debug_str", &secs.str);
    (void)sym_dw_find_sec(&a->bin, ".debug_line_str", &secs.line_str);
    (void)sym_dw_find_sec(&a->bin, ".debug_str_offsets", &secs.str_offs);
    (void)sym_dw_find_sec(&a->bin, ".debug_addr", &secs.addr);

    sym_dw_acache acache;
    memset(&acache, 0, sizeof(acache));
    int prev_mute = a->hist_mute;
    a->hist_mute = 1;

    size_t cu_pos = 0;
    uint32_t ncu = 0;
    while (cu_pos < secs.info.size && ncu < 65536U) {
        size_t before = cu_pos;
        if (!sym_dw_parse_cu(a, types, &secs, &acache, &cu_pos, out)) break;
        if (cu_pos <= before) break;
        ncu++;
    }

    a->hist_mute = prev_mute;
    sym_dw_acache_free(&acache);

    if (ncu == 0) {
        snprintf(out->err, sizeof(out->err), "no valid DWARF compilation units");
        return false;
    }
    snprintf(out->format, sizeof(out->format), "DWARF");
    return true;
}
