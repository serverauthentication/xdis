#include "opt.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// gdi uses bgr order
static uint32_t opt_rgb(uint32_t hex) {
    uint32_t r = (hex >> 16) & 0xFF;
    uint32_t g = (hex >> 8) & 0xFF;
    uint32_t b = hex & 0xFF;
    return r | (g << 8) | (b << 16);
}

static const opt_theme opt_presets[4] = {
    {
        "obsidian",
        0x161311, 0x1E1A17, 0x221D1A, 0x423026, 0x2E241E, 0x3A312C,
        0xE4DDD8, 0x8F847D, 0xA89278, 0x7A7068, 0xF0C070, 0xD89CE0,
        0x8CE0B0, 0x88E2A8, 0x80D8FF, 0x78C8FF, 0x90E890, 0x8888FF,
        0x8A988A, 0x78E078, 0x7878F0, 0xF0B870
    },
    {
        "ida",
        0xFFFFFF, 0xF5F5F5, 0xECECEC, 0xFFD8B0, 0xFFE8C8, 0xC8C8C8,
        0x1A1A1A, 0x6E6E6E, 0x606060, 0x888888, 0x800000, 0x702070,
        0x007800, 0x007000, 0xB00000, 0xC02000, 0x0060A0, 0x0000B0,
        0x904000, 0x008800, 0x0000C8, 0xB05000
    },
    {
        "nord",
        0x40342E, 0x483B35, 0x52423B, 0x6A5448, 0x5A483F, 0x6A564C,
        0xF4ECE8, 0xA89A90, 0xC0A488, 0x928478, 0xD0C088, 0xB088B8,
        0x88CEB0, 0x8CBE9A, 0xE2C88E, 0xD8B480, 0x8CBE9A, 0x6E60BF,
        0x9C8A7C, 0x8CBE9A, 0x6E60BF, 0xD8B480
    },
    {
        "solar",
        0x362B00, 0x423607, 0x3D3104, 0x584812, 0x4B3D0A, 0x685820,
        0xB0A490, 0x807464, 0x969483, 0x756E58, 0x0089B5, 0xC4716C,
        0x98A12A, 0x98A12A, 0xD28B26, 0xD28B26, 0x009985, 0x2F32DC,
        0x756E58, 0x009985, 0x2F32DC, 0xD28B26
    }
};

void opt_defaults(opt_cfg *o) {
    memset(o, 0, sizeof(*o));
    snprintf(o->path, sizeof(o->path), "xdis.ini");
    snprintf(o->font, sizeof(o->font), "Consolas");
    o->font_size = 15;
    o->show_bytes = 1;
    o->bytes_cols = 8;
    o->upper_mnem = 0;
    o->threads = 0;
    o->min_str = 4;
    o->max_ana_mb = 256;
    o->theme_idx = 0;
    snprintf(o->plugins_allow, sizeof(o->plugins_allow), "entropy.dll");
    o->th = opt_presets[0];
}

void opt_set_theme(opt_cfg *o, const char *name) {
    if (!name) return;
    for (int i = 0; i < 4; i++) {
        if (_stricmp(opt_presets[i].name, name) == 0) {
            o->theme_idx = i;
            o->th = opt_presets[i];
            return;
        }
    }
}

void opt_next_theme(opt_cfg *o) {
    o->theme_idx = (o->theme_idx + 1) & 3;
    o->th = opt_presets[o->theme_idx];
}

static char *opt_trim(char *s) {
    while (*s && isspace((unsigned char)*s)) s++;
    size_t n = strlen(s);
    while (n > 0 && isspace((unsigned char)s[n - 1])) s[--n] = 0;
    return s;
}

static bool opt_parse_hex(const char *val, uint32_t *out) {
    if (*val == '#') val++;
    else if (val[0] == '0' && (val[1] == 'x' || val[1] == 'X')) val += 2;
    char *end = NULL;
    unsigned long v = strtoul(val, &end, 16);
    if (end == val) return false;
    *out = opt_rgb((uint32_t)v);
    return true;
}

static void opt_apply_color(opt_theme *t, const char *k, const char *v) {
    uint32_t c;
    if (!opt_parse_hex(v, &c)) return;
    if (strcmp(k, "bg") == 0) t->bg = c;
    else if (strcmp(k, "bg_alt") == 0) t->bg_alt = c;
    else if (strcmp(k, "bg_panel") == 0) t->bg_panel = c;
    else if (strcmp(k, "bg_sel") == 0) t->bg_sel = c;
    else if (strcmp(k, "bg_cur") == 0) t->bg_cur = c;
    else if (strcmp(k, "border") == 0) t->border = c;
    else if (strcmp(k, "fg") == 0) t->fg = c;
    else if (strcmp(k, "fg_dim") == 0) t->fg_dim = c;
    else if (strcmp(k, "addr") == 0) t->addr = c;
    else if (strcmp(k, "bytes") == 0) t->bytes = c;
    else if (strcmp(k, "mnem") == 0) t->mnem = c;
    else if (strcmp(k, "reg") == 0) t->reg = c;
    else if (strcmp(k, "num") == 0) t->num = c;
    else if (strcmp(k, "str") == 0) t->str = c;
    else if (strcmp(k, "sym") == 0) t->sym = c;
    else if (strcmp(k, "call") == 0) t->call = c;
    else if (strcmp(k, "jmp") == 0) t->jmp = c;
    else if (strcmp(k, "ret") == 0) t->ret = c;
    else if (strcmp(k, "cmt") == 0) t->cmt = c;
    else if (strcmp(k, "edge_t") == 0) t->edge_t = c;
    else if (strcmp(k, "edge_f") == 0) t->edge_f = c;
    else if (strcmp(k, "edge_u") == 0) t->edge_u = c;
}

bool opt_load(opt_cfg *o, const char *path) {
    if (path && path[0]) snprintf(o->path, sizeof(o->path), "%s", path);
    FILE *f = fopen(o->path, "rb");
    if (!f) return false;

    char sec[32] = "";
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        char *s = opt_trim(line);
        if (!*s || *s == '#' || *s == ';') continue;
        if (*s == '[') {
            char *e = strchr(s, ']');
            if (e) {
                *e = 0;
                snprintf(sec, sizeof(sec), "%s", opt_trim(s + 1));
            }
            continue;
        }
        char *eq = strchr(s, '=');
        if (!eq) continue;
        *eq = 0;
        char *k = opt_trim(s);
        char *v = opt_trim(eq + 1);

        if (_stricmp(sec, "colors") == 0) {
            opt_apply_color(&o->th, k, v);
            continue;
        }

        if (strcmp(k, "theme") == 0) opt_set_theme(o, v);
        else if (strcmp(k, "font") == 0) snprintf(o->font, sizeof(o->font), "%s", v);
        else if (strcmp(k, "font_size") == 0) {
            int n = atoi(v);
            if (n >= 10 && n <= 32) o->font_size = n;
        } else if (strcmp(k, "show_bytes") == 0) o->show_bytes = atoi(v) != 0;
        else if (strcmp(k, "bytes_cols") == 0) {
            int n = atoi(v);
            if (n >= 0 && n <= 16) o->bytes_cols = n;
        } else if (strcmp(k, "upper_mnem") == 0) o->upper_mnem = atoi(v) != 0;
        else if (strcmp(k, "threads") == 0) {
            int n = atoi(v);
            if (n >= 0 && n <= 32) o->threads = n;
        } else if (strcmp(k, "min_str") == 0) {
            int n = atoi(v);
            if (n >= 3 && n <= 64) o->min_str = n;
        } else if (strcmp(k, "max_ana_mb") == 0) {
            int n = atoi(v);
            if (n >= 1 && n <= 4096) o->max_ana_mb = n;
        } else if (strcmp(k, "plugins_allow") == 0) {
            snprintf(o->plugins_allow, sizeof(o->plugins_allow), "%s", v);
        }
    }

    fclose(f);
    return true;
}

bool opt_write_default(const char *path) {
    FILE *f = fopen(path, "wb");
    if (!f) return false;
    fputs(
        "[ui]\n"
        "theme = obsidian\n"
        "font = Consolas\n"
        "font_size = 15\n"
        "show_bytes = 1\n"
        "bytes_cols = 8\n"
        "upper_mnem = 0\n"
        "\n"
        "[analysis]\n"
        "threads = 0\n"
        "min_str = 4\n"
        "max_ana_mb = 256\n"
        "\n"
        "[colors]\n"
        "; uncomment hex overrides (RRGGBB)\n"
        "; bg = 111316\n"
        "; mnem = 70C0F0\n"
        "; call = FFC878\n",
        f);
    fclose(f);
    return true;
}
