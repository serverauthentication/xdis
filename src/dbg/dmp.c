#include "dbg.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
    DMP_SIG            = 0x504D444Du,
    DMP_HDR_SIZE       = 32,
    DMP_DIR_SIZE       = 12,
    DMP_MOD_SIZE       = 108,
    DMP_TH_SIZE        = 48,
    DMP_MEM_SIZE       = 16,
    DMP_STREAM_THREADS = 3,
    DMP_STREAM_MODS    = 4,
    DMP_STREAM_MEM     = 5,
    DMP_STREAM_EXC     = 6,
    DMP_STREAM_SYSINFO = 7,
    DMP_STREAM_MEM64   = 9
};

static const size_t DMP_MAX_FILE = 256u * 1024u * 1024u;

static void dmp_err(dmp_ctx *m, const char *msg) {
    if (!m) return;
    snprintf(m->last_err, sizeof(m->last_err), "%s", msg);
}

static uint16_t dmp_rd16(const uint8_t *p) {
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t dmp_rd32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t dmp_rd64(const uint8_t *p) {
    return (uint64_t)dmp_rd32(p) | ((uint64_t)dmp_rd32(p + 4) << 32);
}

static bool dmp_in_bounds(const dmp_ctx *m, uint64_t off, uint64_t len) {
    if (off > (uint64_t)m->raw_size) return false;
    return len <= (uint64_t)m->raw_size - off;
}

static size_t dmp_utf8_put(char *dst, size_t pos, size_t cap, uint32_t cp) {
    if (cp < 0x80u) {
        if (pos + 1 >= cap) return pos;
        dst[pos++] = (char)cp;
    } else if (cp < 0x800u) {
        if (pos + 2 >= cap) return pos;
        dst[pos++] = (char)(0xC0u | (cp >> 6));
        dst[pos++] = (char)(0x80u | (cp & 0x3Fu));
    } else if (cp < 0x10000u) {
        if (pos + 3 >= cap) return pos;
        dst[pos++] = (char)(0xE0u | (cp >> 12));
        dst[pos++] = (char)(0x80u | ((cp >> 6) & 0x3Fu));
        dst[pos++] = (char)(0x80u | (cp & 0x3Fu));
    } else if (cp <= 0x10FFFFu) {
        if (pos + 4 >= cap) return pos;
        dst[pos++] = (char)(0xF0u | (cp >> 18));
        dst[pos++] = (char)(0x80u | ((cp >> 12) & 0x3Fu));
        dst[pos++] = (char)(0x80u | ((cp >> 6) & 0x3Fu));
        dst[pos++] = (char)(0x80u | (cp & 0x3Fu));
    }
    return pos;
}

static void dmp_read_mod_name(const dmp_ctx *m, uint32_t rva, char *dst, size_t cap) {
    if (!dst || cap == 0) return;
    dst[0] = 0;
    if (!dmp_in_bounds(m, rva, 4)) return;

    uint32_t blen = dmp_rd32(m->raw + rva);
    if (!dmp_in_bounds(m, (uint64_t)rva + 4, blen)) return;

    const uint8_t *s = m->raw + rva + 4;
    size_t nch = (size_t)(blen / 2);
    size_t end = 0;
    size_t start = 0;
    for (size_t i = 0; i < nch; i++) {
        uint16_t ch = dmp_rd16(s + i * 2);
        if (ch == 0) break;
        if (ch == '\\' || ch == '/') start = i + 1;
        end = i + 1;
    }

    size_t pos = 0;
    for (size_t i = start; i < end; i++) {
        uint32_t cp = dmp_rd16(s + i * 2);
        if (cp >= 0xD800u && cp <= 0xDBFFu && i + 1 < end) {
            uint32_t lo = dmp_rd16(s + (i + 1) * 2);
            if (lo >= 0xDC00u && lo <= 0xDFFFu) {
                cp = 0x10000u + (((cp - 0xD800u) << 10) | (lo - 0xDC00u));
                i++;
            }
        }
        size_t next = dmp_utf8_put(dst, pos, cap, cp);
        if (next == pos) break;
        pos = next;
    }
    dst[pos] = 0;
}

static bool dmp_grow_mems(dmp_ctx *m, uint32_t add) {
    if (add == 0) return true;
    if (add > UINT32_MAX - m->nmem) return false;
    uint32_t total = m->nmem + add;
    if ((size_t)total > SIZE_MAX / sizeof(dmp_mem_rng)) return false;
    dmp_mem_rng *nr = (dmp_mem_rng *)realloc(m->mems, (size_t)total * sizeof(dmp_mem_rng));
    if (!nr) return false;
    m->mems = nr;
    return true;
}

static void dmp_parse_sysinfo(dmp_ctx *m, const uint8_t *p, uint32_t sz) {
    if (sz < 20) return;
    m->arch     = dmp_rd16(p + 0);
    m->ncpu     = (uint32_t)p[6];
    m->os_major = dmp_rd32(p + 8);
    m->os_minor = dmp_rd32(p + 12);
    m->os_build = dmp_rd32(p + 16);
}

static void dmp_parse_exc(dmp_ctx *m, const uint8_t *p, uint32_t sz) {
    if (sz < 32) return;
    m->exc_tid  = dmp_rd32(p + 0);
    m->exc_code = dmp_rd32(p + 8);
    m->exc_addr = dmp_rd64(p + 24);
}

static bool dmp_parse_mods(dmp_ctx *m, const uint8_t *p, uint32_t sz) {
    if (sz < 4) return true;
    uint32_t cnt = dmp_rd32(p + 0);
    uint32_t max_cnt = (sz - 4) / DMP_MOD_SIZE;
    if (cnt > max_cnt) cnt = max_cnt;

    free(m->mods);
    m->mods = NULL;
    m->nmod = 0;
    if (cnt == 0) return true;

    m->mods = (dbg_mod *)calloc(cnt, sizeof(dbg_mod));
    if (!m->mods) {
        dmp_err(m, "out of memory for modules");
        return false;
    }
    m->nmod = cnt;

    for (uint32_t i = 0; i < cnt; i++) {
        const uint8_t *e = p + 4 + (size_t)i * DMP_MOD_SIZE;
        m->mods[i].base = dmp_rd64(e + 0);
        m->mods[i].size = dmp_rd32(e + 8);
        // ModuleNameRva sits at +20 under pshpack4
        uint32_t name_rva = dmp_rd32(e + 20);
        dmp_read_mod_name(m, name_rva, m->mods[i].name, sizeof(m->mods[i].name));
    }
    return true;
}

static void dmp_parse_thread_ctx(const dmp_ctx *m, dmp_thread *t, uint32_t rva, uint32_t sz) {
    if (!dmp_in_bounds(m, rva, sz)) return;
    const uint8_t *cp = m->raw + rva;

    if (m->arch == 0 && sz == 0x2CCu && (dmp_rd32(cp) & 0x00010000u) != 0) {
        t->regs[7] = dmp_rd32(cp + 0x9C);
        t->regs[6] = dmp_rd32(cp + 0xA0);
        t->regs[3] = dmp_rd32(cp + 0xA4);
        t->regs[2] = dmp_rd32(cp + 0xA8);
        t->regs[1] = dmp_rd32(cp + 0xAC);
        t->regs[0] = dmp_rd32(cp + 0xB0);
        t->regs[5] = dmp_rd32(cp + 0xB4);
        t->rip     = dmp_rd32(cp + 0xB8);
        t->rflags  = dmp_rd32(cp + 0xC0);
        t->regs[4] = dmp_rd32(cp + 0xC4);
        t->rsp     = t->regs[4];
        return;
    }

    if (sz < 0x100u) return;
    t->rflags = (uint64_t)dmp_rd32(cp + 0x44);
    for (int k = 0; k < 16; k++)
        t->regs[k] = dmp_rd64(cp + 0x78 + (size_t)k * 8);
    t->rsp = t->regs[4];
    t->rip = dmp_rd64(cp + 0xF8);
}

static bool dmp_parse_threads(dmp_ctx *m, const uint8_t *p, uint32_t sz) {
    if (sz < 4) return true;
    uint32_t cnt = dmp_rd32(p + 0);
    uint32_t max_cnt = (sz - 4) / DMP_TH_SIZE;
    if (cnt > max_cnt) cnt = max_cnt;

    free(m->threads);
    m->threads = NULL;
    m->nthread = 0;
    if (cnt == 0) return true;

    m->threads = (dmp_thread *)calloc(cnt, sizeof(dmp_thread));
    if (!m->threads) {
        dmp_err(m, "out of memory for threads");
        return false;
    }
    m->nthread = cnt;

    for (uint32_t i = 0; i < cnt; i++) {
        const uint8_t *e = p + 4 + (size_t)i * DMP_TH_SIZE;
        dmp_thread *t = &m->threads[i];
        t->tid = dmp_rd32(e + 0);
        uint32_t ctx_sz = dmp_rd32(e + 40);
        uint32_t ctx_rva = dmp_rd32(e + 44);
        dmp_parse_thread_ctx(m, t, ctx_rva, ctx_sz);
    }
    return true;
}

static bool dmp_parse_mem(dmp_ctx *m, const uint8_t *p, uint32_t sz) {
    if (sz < 4) return true;
    uint32_t cnt = dmp_rd32(p + 0);
    uint32_t max_cnt = (sz - 4) / DMP_MEM_SIZE;
    if (cnt > max_cnt) cnt = max_cnt;
    if (cnt == 0) return true;

    if (!dmp_grow_mems(m, cnt)) {
        dmp_err(m, "out of memory for memory list");
        return false;
    }

    for (uint32_t i = 0; i < cnt; i++) {
        const uint8_t *e = p + 4 + (size_t)i * DMP_MEM_SIZE;
        uint64_t va = dmp_rd64(e + 0);
        uint32_t dsz = dmp_rd32(e + 8);
        uint32_t drva = dmp_rd32(e + 12);
        if (dsz == 0 || !dmp_in_bounds(m, drva, dsz)) continue;
        dmp_mem_rng *r = &m->mems[m->nmem++];
        r->va = va;
        r->size = (uint64_t)dsz;
        r->file_off = (uint64_t)drva;
    }
    return true;
}

static bool dmp_parse_mem64(dmp_ctx *m, const uint8_t *p, uint32_t sz) {
    if (sz < 16) return true;
    uint64_t cnt64 = dmp_rd64(p + 0);
    uint64_t foff = dmp_rd64(p + 8);
    uint64_t max_cnt = (uint64_t)(sz - 16) / DMP_MEM_SIZE;
    if (cnt64 > max_cnt) cnt64 = max_cnt;
    uint32_t cnt = (uint32_t)cnt64;
    if (cnt == 0) return true;

    if (!dmp_grow_mems(m, cnt)) {
        dmp_err(m, "out of memory for memory64 list");
        return false;
    }

    for (uint32_t i = 0; i < cnt; i++) {
        const uint8_t *e = p + 16 + (size_t)i * DMP_MEM_SIZE;
        uint64_t va = dmp_rd64(e + 0);
        uint64_t dsz = dmp_rd64(e + 8);
        if (dsz > 0 && dmp_in_bounds(m, foff, dsz)) {
            dmp_mem_rng *r = &m->mems[m->nmem++];
            r->va = va;
            r->size = dsz;
            r->file_off = foff;
        }
        uint64_t next = foff + dsz;
        if (next < foff || next > (uint64_t)m->raw_size) break;
        foff = next;
    }
    return true;
}

static bool dmp_read_file(dmp_ctx *m, const char *path) {
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        dmp_err(m, "cannot open minidump file");
        return false;
    }

#ifdef _MSC_VER
    if (_fseeki64(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        dmp_err(m, "seek failed");
        return false;
    }
    long long fsz = _ftelli64(fp);
    if (fsz < 0 || _fseeki64(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        dmp_err(m, "tell failed");
        return false;
    }
#else
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        dmp_err(m, "seek failed");
        return false;
    }
    long fsz = ftell(fp);
    if (fsz < 0 || fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        dmp_err(m, "tell failed");
        return false;
    }
#endif

    if ((uint64_t)fsz < DMP_HDR_SIZE) {
        fclose(fp);
        dmp_err(m, "file too small for minidump");
        return false;
    }
    if ((uint64_t)fsz > (uint64_t)DMP_MAX_FILE) {
        fclose(fp);
        dmp_err(m, "minidump exceeds 256 MB cap");
        return false;
    }

    size_t sz = (size_t)fsz;
    uint8_t *buf = (uint8_t *)malloc(sz);
    if (!buf) {
        fclose(fp);
        dmp_err(m, "out of memory reading dump");
        return false;
    }
    size_t got = fread(buf, 1, sz, fp);
    fclose(fp);
    if (got != sz) {
        free(buf);
        dmp_err(m, "short read on minidump");
        return false;
    }

    m->raw = buf;
    m->raw_size = sz;
    return true;
}

static void dmp_fail(dmp_ctx *m) {
    char saved[96];
    snprintf(saved, sizeof(saved), "%s", m->last_err);
    dmp_close(m);
    snprintf(m->last_err, sizeof(m->last_err), "%s", saved);
}

void dmp_init(dmp_ctx *m) {
    if (!m) return;
    memset(m, 0, sizeof(*m));
}

void dmp_close(dmp_ctx *m) {
    if (!m) return;
    free(m->mods);
    free(m->threads);
    free(m->mems);
    free(m->raw);
    memset(m, 0, sizeof(*m));
}

bool dmp_open(dmp_ctx *m, const char *path) {
    if (!m) return false;
    if (!path || !path[0]) {
        dmp_err(m, "empty dump path");
        return false;
    }

    dmp_close(m);
    snprintf(m->path, sizeof(m->path), "%s", path);
    if (!dmp_read_file(m, path)) {
        dmp_fail(m);
        return false;
    }

    if (dmp_rd32(m->raw + 0) != DMP_SIG) {
        dmp_err(m, "invalid MDMP signature");
        dmp_fail(m);
        return false;
    }

    uint32_t nstream = dmp_rd32(m->raw + 8);
    uint32_t dir_rva = dmp_rd32(m->raw + 12);
    if (nstream > 65536u || !dmp_in_bounds(m, dir_rva, (uint64_t)nstream * DMP_DIR_SIZE)) {
        dmp_err(m, "invalid stream directory");
        dmp_fail(m);
        return false;
    }

    const uint8_t *dir = m->raw + dir_rva;
    // parse system info first so thread contexts know arch
    for (uint32_t i = 0; i < nstream; i++) {
        const uint8_t *ent = dir + (size_t)i * DMP_DIR_SIZE;
        if (dmp_rd32(ent + 0) != DMP_STREAM_SYSINFO) continue;
        uint32_t ssz = dmp_rd32(ent + 4);
        uint32_t srva = dmp_rd32(ent + 8);
        if (ssz > 0 && dmp_in_bounds(m, srva, ssz))
            dmp_parse_sysinfo(m, m->raw + srva, ssz);
        break;
    }

    for (uint32_t i = 0; i < nstream; i++) {
        const uint8_t *ent = dir + (size_t)i * DMP_DIR_SIZE;
        uint32_t stype = dmp_rd32(ent + 0);
        uint32_t ssz = dmp_rd32(ent + 4);
        uint32_t srva = dmp_rd32(ent + 8);
        if (ssz == 0 || !dmp_in_bounds(m, srva, ssz)) continue;

        const uint8_t *sp = m->raw + srva;
        bool ok = true;
        if (stype == DMP_STREAM_EXC)
            dmp_parse_exc(m, sp, ssz);
        else if (stype == DMP_STREAM_MODS)
            ok = dmp_parse_mods(m, sp, ssz);
        else if (stype == DMP_STREAM_THREADS)
            ok = dmp_parse_threads(m, sp, ssz);
        else if (stype == DMP_STREAM_MEM)
            ok = dmp_parse_mem(m, sp, ssz);
        else if (stype == DMP_STREAM_MEM64)
            ok = dmp_parse_mem64(m, sp, ssz);

        if (!ok) {
            dmp_fail(m);
            return false;
        }
    }

    m->loaded = 1;
    m->last_err[0] = 0;
    return true;
}

size_t dmp_read_mem(const dmp_ctx *m, uint64_t va, uint8_t *dst, size_t n) {
    if (!m || !m->loaded || !m->raw || !dst || n == 0) return 0;

    size_t done = 0;
    while (done < n) {
        uint64_t cur = va + (uint64_t)done;
        if (cur < va) break;

        const dmp_mem_rng *hit = NULL;
        for (uint32_t i = 0; i < m->nmem; i++) {
            const dmp_mem_rng *r = &m->mems[i];
            if (cur >= r->va && (cur - r->va) < r->size) {
                hit = r;
                break;
            }
        }
        if (!hit) break;

        uint64_t roff = cur - hit->va;
        uint64_t ravail = hit->size - roff;
        uint64_t foff = hit->file_off + roff;
        if (foff < hit->file_off || foff >= (uint64_t)m->raw_size) break;

        uint64_t favail = (uint64_t)m->raw_size - foff;
        if (ravail > favail) ravail = favail;

        size_t take = n - done;
        if ((uint64_t)take > ravail) take = (size_t)ravail;
        if (take == 0) break;

        memcpy(dst + done, m->raw + (size_t)foff, take);
        done += take;
    }
    return done;
}
