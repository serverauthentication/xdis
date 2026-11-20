#include "bin.h"

#include <ctype.h>
#include <string.h>

typedef struct {
    char  *p;
    size_t len;
    size_t cap;
} dem_buf;

typedef struct {
    const char *s;
    size_t      n;
} dem_str;

static void dem_putc(dem_buf *o, char c) {
    if (o->len + 1 >= o->cap) return;
    o->p[o->len++] = c;
    o->p[o->len] = 0;
}

static void dem_putn(dem_buf *o, const char *s, size_t n) {
    if (o->len + 1 >= o->cap) return;
    size_t avail = o->cap - 1 - o->len;
    if (n > avail) n = avail;
    memcpy(o->p + o->len, s, n);
    o->len += n;
    o->p[o->len] = 0;
}

static void dem_puts(dem_buf *o, const char *s) {
    dem_putn(o, s, strlen(s));
}

static const char *dem_msvc_op(char c) {
    switch (c) {
    case '2': return "operator new";
    case '3': return "operator delete";
    case '4': return "operator=";
    case '5': return "operator>>";
    case '6': return "operator<<";
    case '7': return "operator!";
    case '8': return "operator==";
    case '9': return "operator!=";
    case 'A': return "operator[]";
    case 'B': return "operator cast";
    case 'C': return "operator->";
    case 'D': return "operator*";
    case 'E': return "operator++";
    case 'F': return "operator--";
    case 'G': return "operator-";
    case 'H': return "operator+";
    case 'I': return "operator&";
    case 'J': return "operator->*";
    case 'K': return "operator/";
    case 'L': return "operator%";
    case 'M': return "operator<";
    case 'N': return "operator<=";
    case 'O': return "operator>";
    case 'P': return "operator>=";
    case 'Q': return "operator,";
    case 'R': return "operator()";
    case 'S': return "operator~";
    case 'T': return "operator^";
    case 'U': return "operator|";
    case 'V': return "operator&&";
    case 'W': return "operator||";
    case 'X': return "operator*=";
    case 'Y': return "operator+=";
    case 'Z': return "operator-=";
    default:  return NULL;
    }
}

static const char *dem_msvc_ext(char c) {
    switch (c) {
    case '0': return "operator/=";
    case '1': return "operator%=";
    case '2': return "operator>>=";
    case '3': return "operator<<=";
    case '4': return "operator&=";
    case '5': return "operator|=";
    case '6': return "operator^=";
    case '7': return "vftable";
    case '8': return "vbtable";
    case '9': return "vcall";
    case 'E': return "vector deleting destructor";
    case 'G': return "scalar deleting destructor";
    case 'U': return "operator new[]";
    case 'V': return "operator delete[]";
    default:  return NULL;
    }
}

static void dem_msvc_skip_tpl(const char **pp) {
    const char *p = *pp;
    int depth = 1;
    while (*p && depth > 0) {
        if (p[0] == '?' && p[1] == '$') {
            depth++;
            p += 2;
            while (*p && *p != '@') p++;
            if (*p == '@') p++;
            continue;
        }
        if (*p == '@') {
            p++;
            if (*p == '@') {
                depth--;
                p++;
            } else {
                depth--;
            }
            continue;
        }
        p++;
    }
    *pp = p;
}

static bool dem_msvc(const char *s, dem_buf *o) {
    if (s[0] != '?') return false;
    const char *p = s + 1;

    enum { K_NORM = 0, K_CTOR, K_DTOR, K_SPEC } kind = K_NORM;
    dem_str base = {NULL, 0};
    const char *spec = NULL;
    dem_str brefs[10];
    int nbref = 0;

    if (*p == '?') {
        p++;
        if (*p == '0') {
            kind = K_CTOR;
            p++;
        } else if (*p == '1') {
            kind = K_DTOR;
            p++;
        } else if (*p == '_') {
            p++;
            if (*p == 'R') {
                p++;
                char r = *p;
                if (r) p++;
                kind = K_SPEC;
                switch (r) {
                case '0':
                    spec = "RTTI Type Descriptor";
                    // skip ?AV/?AU/?AT/?AW4 type tag
                    if (p[0] == '?' && p[1] && p[2]) {
                        p += 2;
                        if (*p == 'W' && p[1]) p += 2;
                        else if (*p) p++;
                    }
                    break;
                case '1': spec = "RTTI Base Class Descriptor"; break;
                case '2': spec = "RTTI Base Class Array"; break;
                case '3': spec = "RTTI Class Hierarchy Descriptor"; break;
                case '4': spec = "RTTI Complete Object Locator"; break;
                default:  spec = "RTTI"; break;
                }
            } else {
                spec = dem_msvc_ext(*p);
                if (!spec) return false;
                kind = K_SPEC;
                p++;
            }
        } else if (*p == '$') {
            p++;
            const char *st = p;
            while (*p && *p != '@') p++;
            if (p == st || *p != '@') return false;
            base.s = st;
            base.n = (size_t)(p - st);
            if (nbref < 10) brefs[nbref++] = base;
            p++;
            dem_msvc_skip_tpl(&p);
        } else {
            spec = dem_msvc_op(*p);
            if (!spec) return false;
            kind = K_SPEC;
            p++;
        }
    } else if (*p == '$') {
        p++;
        const char *st = p;
        while (*p && *p != '@') p++;
        if (p == st || *p != '@') return false;
        base.s = st;
        base.n = (size_t)(p - st);
        if (nbref < 10) brefs[nbref++] = base;
        p++;
        dem_msvc_skip_tpl(&p);
    } else {
        const char *st = p;
        while (*p && *p != '@') p++;
        if (p == st || *p != '@') return false;
        base.s = st;
        base.n = (size_t)(p - st);
        if (nbref < 10) brefs[nbref++] = base;
        p++;
    }

    dem_str scopes[16];
    int nscope = 0;
    while (*p && *p != '@' && nscope < 16) {
        if (*p >= '0' && *p <= '9') {
            int idx = *p - '0';
            p++;
            if (idx < nbref) scopes[nscope++] = brefs[idx];
        } else if (p[0] == '?' && p[1] == '$') {
            p += 2;
            const char *st = p;
            while (*p && *p != '@') p++;
            if (p == st || *p != '@') break;
            dem_str tn = {st, (size_t)(p - st)};
            if (nbref < 10) brefs[nbref++] = tn;
            scopes[nscope++] = tn;
            p++;
            dem_msvc_skip_tpl(&p);
        } else if (*p == '?') {
            p++;
            while (*p && *p != '@') p++;
            if (*p == '@') p++;
        } else {
            const char *st = p;
            while (*p && *p != '@') p++;
            if (p == st || *p != '@') return false;
            dem_str sc = {st, (size_t)(p - st)};
            if (nbref < 10) brefs[nbref++] = sc;
            scopes[nscope++] = sc;
            p++;
        }
    }
    if (*p != '@' && nscope < 16) return false;

    for (int i = nscope - 1; i >= 0; i--) {
        dem_putn(o, scopes[i].s, scopes[i].n);
        dem_puts(o, "::");
    }

    if (kind == K_NORM) {
        dem_putn(o, base.s, base.n);
    } else if (kind == K_CTOR) {
        if (nscope == 0) return false;
        dem_putn(o, scopes[0].s, scopes[0].n);
    } else if (kind == K_DTOR) {
        if (nscope == 0) return false;
        dem_putc(o, '~');
        dem_putn(o, scopes[0].s, scopes[0].n);
    } else {
        dem_puts(o, spec);
    }
    return o->len > 0;
}

static bool dem_it_len(const char **pp, dem_str *out) {
    const char *p = *pp;
    if (!isdigit((unsigned char)*p)) return false;
    size_t n = 0;
    while (isdigit((unsigned char)*p)) {
        n = n * 10 + (size_t)(*p - '0');
        if (n > 4096) return false;
        p++;
    }
    if (n == 0) return false;
    for (size_t i = 0; i < n; i++) {
        if (p[i] == 0) return false;
    }
    out->s = p;
    out->n = n;
    *pp = p + n;
    return true;
}

static void dem_it_skip_tpl(const char **pp) {
    const char *p = *pp;
    if (*p != 'I') return;
    p++;
    int depth = 1;
    while (*p && depth > 0) {
        if (isdigit((unsigned char)*p)) {
            dem_str tmp;
            if (!dem_it_len(&p, &tmp)) break;
            continue;
        }
        if (*p == 'I' || *p == 'N') depth++;
        else if (*p == 'E') depth--;
        p++;
    }
    *pp = p;
}

static const char *dem_it_op(const char *p) {
    if (!p[0] || !p[1]) return NULL;
    static const struct { char a, b; const char *name; } ops[] = {
        {'n','w',"operator new"},    {'n','a',"operator new[]"},
        {'d','l',"operator delete"}, {'d','a',"operator delete[]"},
        {'p','l',"operator+"},       {'m','i',"operator-"},
        {'m','l',"operator*"},       {'d','v',"operator/"},
        {'r','m',"operator%"},       {'a','S',"operator="},
        {'e','q',"operator=="},      {'n','e',"operator!="},
        {'l','t',"operator<"},       {'g','t',"operator>"},
        {'l','e',"operator<="},      {'g','e',"operator>="},
        {'i','x',"operator[]"},      {'c','l',"operator()"},
        {'p','t',"operator->"},      {'p','p',"operator++"},
        {'m','m',"operator--"},      {'l','s',"operator<<"},
        {'r','s',"operator>>"}
    };
    for (size_t i = 0; i < sizeof(ops) / sizeof(ops[0]); i++) {
        if (p[0] == ops[i].a && p[1] == ops[i].b) return ops[i].name;
    }
    return NULL;
}

static const char *dem_it_stdsub(char c) {
    switch (c) {
    case 't': return "std";
    case 'a': return "std::allocator";
    case 'b': return "std::basic_string";
    case 's': return "std::string";
    case 'i': return "std::istream";
    case 'o': return "std::ostream";
    case 'd': return "std::iostream";
    default:  return NULL;
    }
}

static bool dem_it_nested(const char **pp, dem_buf *o) {
    const char *p = *pp;
    if (*p != 'N') return false;
    p++;
    while (*p == 'r' || *p == 'V' || *p == 'K' || *p == 'R' || *p == 'O') p++;

    int comp = 0;
    dem_str last = {NULL, 0};
    while (*p && *p != 'E') {
        if (*p == 'B') {
            p++;
            dem_str tag;
            if (!dem_it_len(&p, &tag)) return false;
            continue;
        }
        if (*p == 'I') {
            dem_it_skip_tpl(&p);
            continue;
        }

        if (comp > 0) dem_puts(o, "::");
        if (isdigit((unsigned char)*p)) {
            dem_str nm;
            if (!dem_it_len(&p, &nm)) return false;
            dem_putn(o, nm.s, nm.n);
            last = nm;
            comp++;
        } else if (p[0] == 'C' && (p[1] == '1' || p[1] == '2' || p[1] == '3')) {
            if (!last.s) return false;
            dem_putn(o, last.s, last.n);
            p += 2;
            comp++;
        } else if (p[0] == 'D' && (p[1] == '0' || p[1] == '1' || p[1] == '2')) {
            if (!last.s) return false;
            dem_putc(o, '~');
            dem_putn(o, last.s, last.n);
            p += 2;
            comp++;
        } else if (p[0] == 'S') {
            const char *sub = dem_it_stdsub(p[1]);
            if (!sub) return false;
            dem_puts(o, sub);
            last.s = sub;
            last.n = strlen(sub);
            p += 2;
            comp++;
        } else {
            const char *op = dem_it_op(p);
            if (!op) return false;
            dem_puts(o, op);
            p += 2;
            comp++;
        }
    }
    if (*p != 'E' || comp == 0) return false;
    *pp = p + 1;
    return true;
}

static const char *dem_it_prim(char c) {
    switch (c) {
    case 'v': return "void";
    case 'b': return "bool";
    case 'c': return "char";
    case 'a': return "signed char";
    case 'h': return "unsigned char";
    case 's': return "short";
    case 't': return "unsigned short";
    case 'i': return "int";
    case 'j': return "unsigned int";
    case 'l': return "long";
    case 'm': return "unsigned long";
    case 'x': return "long long";
    case 'y': return "unsigned long long";
    case 'f': return "float";
    case 'd': return "double";
    case 'e': return "long double";
    case 'w': return "wchar_t";
    case 'z': return "...";
    default:  return NULL;
    }
}

static bool dem_it_type(const char **pp, dem_buf *o) {
    const char *p = *pp;
    int ptr = 0, ref = 0, is_const = 0;
    for (int i = 0; i < 8 && *p; i++) {
        if (*p == 'P') { ptr++; p++; }
        else if (*p == 'R') { ref = 1; p++; }
        else if (*p == 'O') { ref = 2; p++; }
        else if (*p == 'K') { is_const = 1; p++; }
        else if (*p == 'V' || *p == 'r') { p++; }
        else break;
    }
    if (!*p) return false;

    if (is_const) dem_puts(o, "const ");
    const char *prim = dem_it_prim(*p);
    if (prim) {
        dem_puts(o, prim);
        p++;
    } else if (isdigit((unsigned char)*p)) {
        dem_str nm;
        if (!dem_it_len(&p, &nm)) return false;
        dem_putn(o, nm.s, nm.n);
        if (*p == 'I') dem_it_skip_tpl(&p);
    } else if (*p == 'N') {
        if (!dem_it_nested(&p, o)) return false;
    } else if (p[0] == 'S') {
        const char *sub = dem_it_stdsub(p[1]);
        if (sub) {
            dem_puts(o, sub);
            p += 2;
        } else {
            p++;
            while (*p && *p != '_') p++;
            if (*p != '_') return false;
            p++;
            dem_puts(o, "...");
        }
    } else {
        return false;
    }

    for (int i = 0; i < ptr; i++) dem_putc(o, '*');
    if (ref == 1) dem_putc(o, '&');
    else if (ref == 2) dem_puts(o, "&&");
    *pp = p;
    return true;
}

static bool dem_itanium(const char *s, dem_buf *o) {
    const char *p = s;
    if (p[0] == '_' && p[1] == '_' && p[2] == 'Z') p += 3;
    else if (p[0] == '_' && p[1] == 'Z') p += 2;
    else return false;

    if (*p == 'L') p++;
    if (!*p) return false;

    bool is_spec = false;
    if (p[0] == 'T' && (p[1] == 'V' || p[1] == 'I' || p[1] == 'S' || p[1] == 'T')) {
        if (p[1] == 'V') dem_puts(o, "vtable for ");
        else if (p[1] == 'I') dem_puts(o, "typeinfo for ");
        else if (p[1] == 'S') dem_puts(o, "typeinfo name for ");
        else dem_puts(o, "VTT for ");
        p += 2;
        is_spec = true;
    }

    if (*p == 'N') {
        if (!dem_it_nested(&p, o)) return false;
    } else if (p[0] == 'S' && p[1] == 't') {
        dem_puts(o, "std::");
        p += 2;
        if (isdigit((unsigned char)*p)) {
            dem_str nm;
            if (!dem_it_len(&p, &nm)) return false;
            dem_putn(o, nm.s, nm.n);
            if (*p == 'I') dem_it_skip_tpl(&p);
        } else {
            const char *op = dem_it_op(p);
            if (!op) return false;
            dem_puts(o, op);
            p += 2;
        }
    } else if (isdigit((unsigned char)*p)) {
        dem_str nm;
        if (!dem_it_len(&p, &nm)) return false;
        dem_putn(o, nm.s, nm.n);
        if (*p == 'B') {
            p++;
            dem_str tag;
            if (!dem_it_len(&p, &tag)) return false;
        }
        if (*p == 'I') dem_it_skip_tpl(&p);
    } else {
        const char *op = dem_it_op(p);
        if (!op) return false;
        dem_puts(o, op);
        p += 2;
    }

    if (!is_spec && *p && *p != '.') {
        if (p[0] == 'v' && (p[1] == 0 || p[1] == '.')) {
            dem_puts(o, "()");
        } else {
            dem_putc(o, '(');
            int narg = 0;
            while (*p && *p != '.' && narg < 16) {
                size_t mark = o->len;
                if (narg > 0) dem_puts(o, ", ");
                if (!dem_it_type(&p, o)) {
                    o->len = mark;
                    o->p[mark] = 0;
                    break;
                }
                narg++;
            }
            dem_putc(o, ')');
        }
    }
    return o->len > 0;
}

bool dem_name(const char *mangled, char *out, size_t max) {
    if (!mangled || !out || max < 2) return false;
    out[0] = 0;
    dem_buf o = {out, 0, max};

    bool ok = false;
    if (mangled[0] == '?') {
        ok = dem_msvc(mangled, &o);
    } else if ((mangled[0] == '_' && mangled[1] == 'Z') ||
               (mangled[0] == '_' && mangled[1] == '_' && mangled[2] == 'Z')) {
        ok = dem_itanium(mangled, &o);
    }

    if (!ok || o.len == 0 || strcmp(out, mangled) == 0) {
        out[0] = 0;
        return false;
    }
    return true;
}
