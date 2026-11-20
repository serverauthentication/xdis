#include "dec_ir.h"

#include <stdlib.h>
#include <string.h>

void dec_free(dec_out *d) {
    if (!d) return;
    free(d->lines);
    free(d->vars);
    memset(d, 0, sizeof(*d));
}

bool dec_func_typed(const ana_ctx *a, const typ_store *types, uint64_t va, dec_out *out) {
    if (!a || !out) return false;
    dec_free(out);

    grp_cfg g = {0};
    if (!grp_build(a, va, 0, &g)) return false;

    hl_fn *fn = (hl_fn *)calloc(1, sizeof(hl_fn));
    if (!fn) {
        grp_free(&g);
        return false;
    }

    bool ok = false;
    if (hl_lift_cfg(a, types, &g, fn)) {
        hl_optimize(fn);
        hl_infer_types(fn);
        ok = hl_structure_and_emit(fn, out);
    }

    hl_fn_free(fn);
    free(fn);
    grp_free(&g);
    return ok && out->nline > 0;
}

bool dec_func(const ana_ctx *a, uint64_t va, dec_out *out) {
    return dec_func_typed(a, NULL, va, out);
}
