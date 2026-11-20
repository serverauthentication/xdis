#define XDIS_PLUGIN_ONLY
#include "../src/ext/ext.h"

#include <math.h>
#include <stdio.h>
#include <string.h>

static const xdis_api *g_api;

static double ent_calc(uint64_t va, uint64_t fsize) {
    uint64_t hist[256] = {0};
    uint8_t buf[16384];
    uint64_t done = 0;
    uint64_t total = 0;
    // cap keeps huge sections fast
    uint64_t lim = fsize > (16ULL << 20) ? (16ULL << 20) : fsize;

    while (done < lim) {
        size_t want = (size_t)(lim - done);
        if (want > sizeof(buf)) want = sizeof(buf);
        size_t n = g_api->read_va(g_api->ctx, va + done, buf, want);
        if (n == 0) break;
        for (size_t i = 0; i < n; i++) hist[buf[i]]++;
        done += n;
        total += n;
    }

    if (total == 0) return 0.0;
    double e = 0.0;
    double inv = 1.0 / (double)total;
    for (int i = 0; i < 256; i++) {
        if (!hist[i]) continue;
        double p = (double)hist[i] * inv;
        e -= p * log2(p);
    }
    return e;
}

static void ent_cmd(const char *args, void *ud) {
    (void)args;
    (void)ud;
    uint32_t nsec = g_api->sec_count(g_api->ctx);
    char line[160];
    snprintf(line, sizeof(line), "[entropy] scanning %u sections", nsec);
    g_api->log(g_api->ctx, line);

    for (uint32_t i = 0; i < nsec; i++) {
        char name[32];
        uint64_t va = 0, vsz = 0, fsz = 0;
        uint32_t perm = 0;
        if (!g_api->sec_info(g_api->ctx, i, name, sizeof(name), &va, &vsz, &fsz, &perm)) continue;
        double h = ent_calc(va, fsz);
        const char *tag = (h >= 7.2) ? "packed/encrypted" : (h >= 6.0) ? "code/dense" : "normal";
        snprintf(line, sizeof(line), "  %-10s va=0x%llx size=%llu H=%.3f (%s)",
                 name, (unsigned long long)va, (unsigned long long)fsz, h, tag);
        g_api->log(g_api->ctx, line);
        if (h >= 7.2) {
            char cmt[64];
            snprintf(cmt, sizeof(cmt), "high entropy %.2f", h);
            g_api->set_cmt(g_api->ctx, va, cmt);
        }
    }
}

__declspec(dllexport) int xdis_plugin_init(const xdis_api *api) {
    if (!api || api->version != XDIS_ABI_VER) return 0;
    g_api = api;
    api->add_cmd(api->ctx, "entropy", ent_cmd, NULL);
    api->log(api->ctx, "[plugin] entropy loaded (:entropy)");
    return 1;
}
