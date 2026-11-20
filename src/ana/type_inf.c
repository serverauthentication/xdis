#include "dec_ir.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TI_CALLEE_CACHE_SZ 512
#define TI_VTABLE_CACHE_MAX 64
#define TI_MAX_OFFS 16

enum {
    T_NONE = 0,
    T_VOID,
    T_BOOL,
    T_I8,
    T_U8,
    T_CHAR,
    T_I16,
    T_U16,
    T_WCHAR,
    T_I32,
    T_U32,
    T_I64,
    T_U64,
    T_SZ,
    T_F32,
    T_F64,
    T_VP,
    T_CVP,
    T_VPP,
    T_STR,
    T_CSTR,
    T_STRP,
    T_WSTR,
    T_CWSTR,
    T_U8P,
    T_CU8P,
    T_U32P,
    T_I32P,
    T_U64P,
    T_I64P,
    T_SZP,
    T_F64P,
    T_HND,
    T_HNDP,
    T_HMOD,
    T_HMODP,
    T_HWND,
    T_HKEY,
    T_HKEYP,
    T_SOCK,
    T_FILEP
};

typedef struct {
    const char *name;
    uint8_t     ret;
    uint8_t     narg;
    uint8_t     vararg;
    int8_t      fmt;
    uint8_t     a[HL_MAX_CALL_ARG];
} ti_api_ent;

typedef struct {
    const uint8_t *map_data;
    uint64_t       map_size;
    uint64_t       entry;
    uint64_t       va;
    uint8_t        used;
    uint8_t        ok;
    hl_callee_sig  sig;
} ti_callee_cache_ent;

static ti_callee_cache_ent ti_callee_cache[TI_CALLEE_CACHE_SZ];
static int ti_callee_cache_used = 0;

typedef struct {
    const uint8_t *map_data;
    uint64_t       map_size;
    uint64_t       entry;
    int            nvt;
    ir_vtable      vts[TI_VTABLE_CACHE_MAX];
} ti_vt_cache_t;

static ti_vt_cache_t ti_vt_cache;

int hl_count_fmt_args(const char *fmt) {
    if (!fmt) return 0;
    int cnt = 0;
    const char *p = fmt;
    while (*p && cnt < HL_MAX_CALL_ARG) {
        if (*p != '%') {
            p++;
            continue;
        }
        p++;
        if (*p == '%') {
            p++;
            continue;
        }
        if (!*p) break;

        // optional positional arg index like %1$d
        const char *q = p;
        while (isdigit((unsigned char)*q)) q++;
        if (q > p && *q == '$') p = q + 1;

        while (*p && strchr("-#0 +'", *p) != NULL) p++;

        int extra = 0;
        if (*p == '*') {
            extra++;
            p++;
            q = p;
            while (isdigit((unsigned char)*q)) q++;
            if (q > p && *q == '$') p = q + 1;
        } else {
            while (isdigit((unsigned char)*p)) p++;
        }

        if (*p == '.') {
            p++;
            if (*p == '*') {
                extra++;
                p++;
                q = p;
                while (isdigit((unsigned char)*q)) q++;
                if (q > p && *q == '$') p = q + 1;
            } else {
                while (isdigit((unsigned char)*p)) p++;
            }
        }

        if (p[0] == 'h' && p[1] == 'h') p += 2;
        else if (p[0] == 'l' && p[1] == 'l') p += 2;
        else if (p[0] == 'I' && p[1] == '6' && p[2] == '4') p += 3;
        else if (p[0] == 'I' && p[1] == '3' && p[2] == '2') p += 3;
        else if (*p && strchr("hlLztjqIw", *p) != NULL) p++;

        if (!*p) break;
        if (strchr("diuoxXfFeEgGaAcspnSC", *p) != NULL) {
            cnt += extra + 1;
            p++;
        } else if (*p == '[') {
            p++;
            if (*p == '^') p++;
            if (*p == ']') p++;
            while (*p && *p != ']') p++;
            if (*p == ']') p++;
            cnt += extra + 1;
        }
    }
    return cnt > HL_MAX_CALL_ARG ? HL_MAX_CALL_ARG : cnt;
}

static hl_type ti_make_ty(uint8_t kind, uint8_t ptr_depth, uint8_t is_const, uint8_t bits) {
    hl_type t;
    memset(&t, 0, sizeof(t));
    t.kind = kind;
    t.ptr_depth = ptr_depth;
    t.is_const = is_const;
    t.bits = bits;
    return t;
}

static hl_type ti_tcode_to_type(uint8_t code) {
    switch (code) {
    case T_VOID:  return ti_make_ty(HL_TY_VOID, 0, 0, 0);
    case T_BOOL:  return ti_make_ty(HL_TY_BOOL, 0, 0, 32);
    case T_I8:    return ti_make_ty(HL_TY_I8, 0, 0, 8);
    case T_U8:    return ti_make_ty(HL_TY_U8, 0, 0, 8);
    case T_CHAR:  return ti_make_ty(HL_TY_CHAR, 0, 0, 8);
    case T_I16:   return ti_make_ty(HL_TY_I16, 0, 0, 16);
    case T_U16:   return ti_make_ty(HL_TY_U16, 0, 0, 16);
    case T_WCHAR: return ti_make_ty(HL_TY_WCHAR, 0, 0, 16);
    case T_I32:   return ti_make_ty(HL_TY_I32, 0, 0, 32);
    case T_U32:   return ti_make_ty(HL_TY_U32, 0, 0, 32);
    case T_I64:   return ti_make_ty(HL_TY_I64, 0, 0, 64);
    case T_U64:   return ti_make_ty(HL_TY_U64, 0, 0, 64);
    case T_SZ:    return ti_make_ty(HL_TY_SIZE_T, 0, 0, 64);
    case T_F32:   return ti_make_ty(HL_TY_F32, 0, 0, 32);
    case T_F64:   return ti_make_ty(HL_TY_F64, 0, 0, 64);
    case T_VP:    return ti_make_ty(HL_TY_VOID, 1, 0, 0);
    case T_CVP:   return ti_make_ty(HL_TY_VOID, 1, 1, 0);
    case T_VPP:   return ti_make_ty(HL_TY_VOID, 2, 0, 0);
    case T_STR:   return ti_make_ty(HL_TY_CHAR, 1, 0, 8);
    case T_CSTR:  return ti_make_ty(HL_TY_CHAR, 1, 1, 8);
    case T_STRP:  return ti_make_ty(HL_TY_CHAR, 2, 0, 8);
    case T_WSTR:  return ti_make_ty(HL_TY_WCHAR, 1, 0, 16);
    case T_CWSTR: return ti_make_ty(HL_TY_WCHAR, 1, 1, 16);
    case T_U8P:   return ti_make_ty(HL_TY_U8, 1, 0, 8);
    case T_CU8P:  return ti_make_ty(HL_TY_U8, 1, 1, 8);
    case T_U32P:  return ti_make_ty(HL_TY_U32, 1, 0, 32);
    case T_I32P:  return ti_make_ty(HL_TY_I32, 1, 0, 32);
    case T_U64P:  return ti_make_ty(HL_TY_U64, 1, 0, 64);
    case T_I64P:  return ti_make_ty(HL_TY_I64, 1, 0, 64);
    case T_SZP:   return ti_make_ty(HL_TY_SIZE_T, 1, 0, 64);
    case T_F64P:  return ti_make_ty(HL_TY_F64, 1, 0, 64);
    case T_HND:   return ti_make_ty(HL_TY_HANDLE, 0, 0, 64);
    case T_HNDP:  return ti_make_ty(HL_TY_HANDLE, 1, 0, 64);
    case T_HMOD:  return ti_make_ty(HL_TY_HMODULE, 0, 0, 64);
    case T_HMODP: return ti_make_ty(HL_TY_HMODULE, 1, 0, 64);
    case T_HWND:  return ti_make_ty(HL_TY_HWND, 0, 0, 64);
    case T_HKEY:  return ti_make_ty(HL_TY_HKEY, 0, 0, 64);
    case T_HKEYP: return ti_make_ty(HL_TY_HKEY, 1, 0, 64);
    case T_SOCK:  return ti_make_ty(HL_TY_SOCKET, 0, 0, 64);
    case T_FILEP: return ti_make_ty(HL_TY_FILE, 1, 0, 0);
    default:      return ti_make_ty(HL_TY_UNK, 0, 0, 0);
    }
}

void hl_type_fmt(const hl_type *t, char *dst, size_t cap) {
    if (!dst || cap == 0) return;
    if (!t) {
        snprintf(dst, cap, "int64_t");
        return;
    }

    const char *base = "int64_t";
    int stars = (int)t->ptr_depth;

    switch (t->kind) {
    case HL_TY_VOID:    base = "void"; break;
    case HL_TY_BOOL:    base = "bool"; break;
    case HL_TY_I8:      base = "int8_t"; break;
    case HL_TY_U8:      base = "uint8_t"; break;
    case HL_TY_CHAR:    base = "char"; break;
    case HL_TY_I16:     base = "int16_t"; break;
    case HL_TY_U16:     base = "uint16_t"; break;
    case HL_TY_WCHAR:   base = "wchar_t"; break;
    case HL_TY_I32:     base = "int32_t"; break;
    case HL_TY_U32:     base = "uint32_t"; break;
    case HL_TY_I64:     base = "int64_t"; break;
    case HL_TY_U64:     base = "uint64_t"; break;
    case HL_TY_SIZE_T:  base = "size_t"; break;
    case HL_TY_F32:     base = "float"; break;
    case HL_TY_F64:     base = "double"; break;
    case HL_TY_PTR:
        base = "void";
        if (stars == 0) stars = 1;
        break;
    case HL_TY_STRUCT:  base = t->name[0] ? t->name : "void"; break;
    case HL_TY_HANDLE:  base = "HANDLE"; break;
    case HL_TY_HMODULE: base = "HMODULE"; break;
    case HL_TY_HWND:    base = "HWND"; break;
    case HL_TY_HKEY:    base = "HKEY"; break;
    case HL_TY_SOCKET:  base = "SOCKET"; break;
    case HL_TY_FILE:    base = "FILE"; break;
    default:
        if (t->bits == 8) base = "uint8_t";
        else if (t->bits == 16) base = "uint16_t";
        else if (t->bits == 32) base = "int32_t";
        else base = "int64_t";
        break;
    }

    if (stars > 4) stars = 4;
    char sbuf[8];
    for (int i = 0; i < stars; i++) sbuf[i] = '*';
    sbuf[stars] = 0;

    if (t->is_const && stars > 0) snprintf(dst, cap, "const %s %s", base, sbuf);
    else if (t->is_const) snprintf(dst, cap, "const %s", base);
    else if (stars > 0) snprintf(dst, cap, "%s %s", base, sbuf);
    else snprintf(dst, cap, "%s", base);
}

static bool ti_is_valid_ident(const char *s) {
    if (!s || (!isalpha((unsigned char)s[0]) && s[0] != '_')) return false;
    for (const char *p = s + 1; *p; p++) {
        if (!isalnum((unsigned char)*p) && *p != '_') return false;
    }
    return true;
}

static void ti_strip_trailing_kw(char *s, size_t *len, const char *kw) {
    size_t kl = strlen(kw);
    if (*len >= kl && strcmp(s + *len - kl, kw) == 0) {
        if (*len == kl || (!isalnum((unsigned char)s[*len - kl - 1]) && s[*len - kl - 1] != '_')) {
            *len -= kl;
            while (*len > 0 && isspace((unsigned char)s[*len - 1])) (*len)--;
            s[*len] = 0;
        }
    }
}

static bool ti_type_parse_depth(const typ_store *types, const char *decl, hl_type *out, int depth) {
    if (!decl || !out || depth > 6) return false;
    memset(out, 0, sizeof(*out));

    char buf[128];
    size_t k = 0;
    const char *p = decl;
    while (*p && isspace((unsigned char)*p)) p++;
    while (*p && k + 1 < sizeof(buf)) buf[k++] = *p++;
    while (k > 0 && isspace((unsigned char)buf[k - 1])) k--;
    buf[k] = 0;
    if (k == 0) return false;

    int is_const = 0;
    int ptr_depth = 0;

    // peel trailing array suffix like char[16]
    char *lb = strchr(buf, '[');
    if (lb) {
        *lb = 0;
        k = strlen(buf);
        while (k > 0 && isspace((unsigned char)buf[k - 1])) buf[--k] = 0;
        ptr_depth++;
    }

    for (;;) {
        while (k > 0 && isspace((unsigned char)buf[k - 1])) buf[--k] = 0;
        size_t prev = k;
        if (k > 0 && buf[k - 1] == '*') {
            ptr_depth++;
            buf[--k] = 0;
            continue;
        }
        size_t before_const = k;
        ti_strip_trailing_kw(buf, &k, "const");
        if (k != before_const) {
            if (strchr(buf, '*') == NULL) is_const = 1;
            continue;
        }
        ti_strip_trailing_kw(buf, &k, "volatile");
        ti_strip_trailing_kw(buf, &k, "restrict");
        ti_strip_trailing_kw(buf, &k, "__restrict");
        ti_strip_trailing_kw(buf, &k, "__ptr64");
        ti_strip_trailing_kw(buf, &k, "__unaligned");
        ti_strip_trailing_kw(buf, &k, "FAR");
        ti_strip_trailing_kw(buf, &k, "NEAR");
        if (k == prev) break;
    }

    // collapse inner whitespace and strip leading qualifiers
    char norm[128];
    size_t nk = 0;
    int prev_sp = 1;
    for (size_t i = 0; i < k && nk + 1 < sizeof(norm); i++) {
        if (isspace((unsigned char)buf[i])) {
            if (!prev_sp) { norm[nk++] = ' '; prev_sp = 1; }
        } else {
            norm[nk++] = buf[i];
            prev_sp = 0;
        }
    }
    while (nk > 0 && norm[nk - 1] == ' ') nk--;
    norm[nk] = 0;

    const char *b = norm;
    for (;;) {
        if (strncmp(b, "const ", 6) == 0) { is_const = 1; b += 6; }
        else if (strncmp(b, "volatile ", 9) == 0) b += 9;
        else if (strncmp(b, "struct ", 7) == 0) b += 7;
        else if (strncmp(b, "union ", 6) == 0) b += 6;
        else if (strncmp(b, "enum ", 5) == 0) b += 5;
        else if (strncmp(b, "class ", 6) == 0) b += 6;
        else if (strncmp(b, "FAR ", 4) == 0) b += 4;
        else if (strncmp(b, "NEAR ", 5) == 0) b += 5;
        else break;
    }
    if (!b[0]) return false;

    if (strcmp(b, "LPCSTR") == 0 || strcmp(b, "PCSTR") == 0 || strcmp(b, "LPCCH") == 0 ||
        strcmp(b, "PCCH") == 0 || strcmp(b, "LPCTSTR") == 0 || strcmp(b, "PCTSTR") == 0) {
        *out = ti_make_ty(HL_TY_CHAR, (uint8_t)(ptr_depth + 1), 1, 8);
        return true;
    }
    if (strcmp(b, "LPSTR") == 0 || strcmp(b, "PSTR") == 0 || strcmp(b, "PCHAR") == 0 ||
        strcmp(b, "LPCH") == 0 || strcmp(b, "PCH") == 0 || strcmp(b, "LPTSTR") == 0 || strcmp(b, "PTSTR") == 0) {
        *out = ti_make_ty(HL_TY_CHAR, (uint8_t)(ptr_depth + 1), (uint8_t)is_const, 8);
        return true;
    }
    if (strcmp(b, "LPCWSTR") == 0 || strcmp(b, "PCWSTR") == 0 || strcmp(b, "LPCWCH") == 0 || strcmp(b, "PCWCH") == 0) {
        *out = ti_make_ty(HL_TY_WCHAR, (uint8_t)(ptr_depth + 1), 1, 16);
        return true;
    }
    if (strcmp(b, "LPWSTR") == 0 || strcmp(b, "PWSTR") == 0 || strcmp(b, "PWCHAR") == 0 ||
        strcmp(b, "LPWCH") == 0 || strcmp(b, "PWCH") == 0) {
        *out = ti_make_ty(HL_TY_WCHAR, (uint8_t)(ptr_depth + 1), (uint8_t)is_const, 16);
        return true;
    }
    if (strcmp(b, "LPCVOID") == 0 || strcmp(b, "PCVOID") == 0) {
        *out = ti_make_ty(HL_TY_VOID, (uint8_t)(ptr_depth + 1), 1, 0);
        return true;
    }
    if (strcmp(b, "LPVOID") == 0 || strcmp(b, "PVOID") == 0 || strcmp(b, "FARPROC") == 0 ||
        strcmp(b, "PROC") == 0 || strcmp(b, "WNDPROC") == 0 || strcmp(b, "DLGPROC") == 0 ||
        strcmp(b, "LPTHREAD_START_ROUTINE") == 0) {
        *out = ti_make_ty(HL_TY_VOID, (uint8_t)(ptr_depth + 1), (uint8_t)is_const, 0);
        return true;
    }
    if (strcmp(b, "LPBYTE") == 0 || strcmp(b, "PBYTE") == 0 || strcmp(b, "PUCHAR") == 0) {
        *out = ti_make_ty(HL_TY_U8, (uint8_t)(ptr_depth + 1), (uint8_t)is_const, 8);
        return true;
    }
    if (strcmp(b, "LPWORD") == 0 || strcmp(b, "PWORD") == 0 || strcmp(b, "PUSHORT") == 0) {
        *out = ti_make_ty(HL_TY_U16, (uint8_t)(ptr_depth + 1), (uint8_t)is_const, 16);
        return true;
    }
    if (strcmp(b, "LPDWORD") == 0 || strcmp(b, "PDWORD") == 0 || strcmp(b, "PULONG") == 0 || strcmp(b, "PUINT") == 0) {
        *out = ti_make_ty(HL_TY_U32, (uint8_t)(ptr_depth + 1), (uint8_t)is_const, 32);
        return true;
    }
    if (strcmp(b, "LPLONG") == 0 || strcmp(b, "PLONG") == 0 || strcmp(b, "PINT") == 0) {
        *out = ti_make_ty(HL_TY_I32, (uint8_t)(ptr_depth + 1), (uint8_t)is_const, 32);
        return true;
    }
    if (strcmp(b, "LPBOOL") == 0 || strcmp(b, "PBOOL") == 0) {
        *out = ti_make_ty(HL_TY_BOOL, (uint8_t)(ptr_depth + 1), (uint8_t)is_const, 32);
        return true;
    }
    if (strcmp(b, "PHANDLE") == 0 || strcmp(b, "LPHANDLE") == 0) {
        *out = ti_make_ty(HL_TY_HANDLE, (uint8_t)(ptr_depth + 1), (uint8_t)is_const, 64);
        return true;
    }
    if (strcmp(b, "PHKEY") == 0) {
        *out = ti_make_ty(HL_TY_HKEY, (uint8_t)(ptr_depth + 1), (uint8_t)is_const, 64);
        return true;
    }
    if (strcmp(b, "PSIZE_T") == 0) {
        *out = ti_make_ty(HL_TY_SIZE_T, (uint8_t)(ptr_depth + 1), (uint8_t)is_const, 64);
        return true;
    }
    if (strcmp(b, "PULONG64") == 0 || strcmp(b, "PUINT64") == 0 || strcmp(b, "PDWORD64") == 0 ||
        strcmp(b, "PULONGLONG") == 0 || strcmp(b, "PULONG_PTR") == 0 || strcmp(b, "PUINT_PTR") == 0) {
        *out = ti_make_ty(HL_TY_U64, (uint8_t)(ptr_depth + 1), (uint8_t)is_const, 64);
        return true;
    }
    if (strcmp(b, "PINT64") == 0 || strcmp(b, "PLONGLONG") == 0 || strcmp(b, "PINT_PTR") == 0 || strcmp(b, "PLONG_PTR") == 0) {
        *out = ti_make_ty(HL_TY_I64, (uint8_t)(ptr_depth + 1), (uint8_t)is_const, 64);
        return true;
    }

    uint8_t kind = HL_TY_UNK;
    uint8_t bits = 0;

    if (strcmp(b, "void") == 0 || strcmp(b, "VOID") == 0) {
        kind = HL_TY_VOID; bits = 0;
    } else if (strcmp(b, "bool") == 0 || strcmp(b, "_Bool") == 0 || strcmp(b, "BOOLEAN") == 0) {
        kind = HL_TY_BOOL; bits = 8;
    } else if (strcmp(b, "BOOL") == 0) {
        kind = HL_TY_BOOL; bits = 32;
    } else if (strcmp(b, "char") == 0 || strcmp(b, "CHAR") == 0 || strcmp(b, "TCHAR") == 0) {
        kind = HL_TY_CHAR; bits = 8;
    } else if (strcmp(b, "int8_t") == 0 || strcmp(b, "signed char") == 0 || strcmp(b, "i8") == 0 ||
               strcmp(b, "__int8") == 0 || strcmp(b, "INT8") == 0 || strcmp(b, "SBYTE") == 0) {
        kind = HL_TY_I8; bits = 8;
    } else if (strcmp(b, "uint8_t") == 0 || strcmp(b, "unsigned char") == 0 || strcmp(b, "u8") == 0 ||
               strcmp(b, "unsigned __int8") == 0 || strcmp(b, "BYTE") == 0 || strcmp(b, "UCHAR") == 0 || strcmp(b, "UINT8") == 0) {
        kind = HL_TY_U8; bits = 8;
    } else if (strcmp(b, "wchar_t") == 0 || strcmp(b, "WCHAR") == 0 || strcmp(b, "OLECHAR") == 0 || strcmp(b, "char16_t") == 0) {
        kind = HL_TY_WCHAR; bits = 16;
    } else if (strcmp(b, "int16_t") == 0 || strcmp(b, "short") == 0 || strcmp(b, "short int") == 0 ||
               strcmp(b, "signed short") == 0 || strcmp(b, "signed short int") == 0 || strcmp(b, "i16") == 0 ||
               strcmp(b, "__int16") == 0 || strcmp(b, "SHORT") == 0 || strcmp(b, "INT16") == 0) {
        kind = HL_TY_I16; bits = 16;
    } else if (strcmp(b, "uint16_t") == 0 || strcmp(b, "unsigned short") == 0 || strcmp(b, "unsigned short int") == 0 ||
               strcmp(b, "u16") == 0 || strcmp(b, "unsigned __int16") == 0 || strcmp(b, "WORD") == 0 ||
               strcmp(b, "USHORT") == 0 || strcmp(b, "UINT16") == 0 || strcmp(b, "ATOM") == 0) {
        kind = HL_TY_U16; bits = 16;
    } else if (strcmp(b, "int32_t") == 0 || strcmp(b, "int") == 0 || strcmp(b, "signed") == 0 ||
               strcmp(b, "signed int") == 0 || strcmp(b, "long") == 0 || strcmp(b, "long int") == 0 ||
               strcmp(b, "signed long") == 0 || strcmp(b, "signed long int") == 0 || strcmp(b, "i32") == 0 ||
               strcmp(b, "__int32") == 0 || strcmp(b, "INT") == 0 || strcmp(b, "INT32") == 0 ||
               strcmp(b, "LONG") == 0 || strcmp(b, "LONG32") == 0 || strcmp(b, "HRESULT") == 0 ||
               strcmp(b, "NTSTATUS") == 0 || strcmp(b, "LSTATUS") == 0 || strcmp(b, "errno_t") == 0) {
        kind = HL_TY_I32; bits = 32;
    } else if (strcmp(b, "uint32_t") == 0 || strcmp(b, "unsigned") == 0 || strcmp(b, "unsigned int") == 0 ||
               strcmp(b, "unsigned long") == 0 || strcmp(b, "unsigned long int") == 0 || strcmp(b, "u32") == 0 ||
               strcmp(b, "unsigned __int32") == 0 || strcmp(b, "DWORD") == 0 || strcmp(b, "ULONG") == 0 ||
               strcmp(b, "ULONG32") == 0 || strcmp(b, "UINT") == 0 || strcmp(b, "UINT32") == 0 ||
               strcmp(b, "DWORD32") == 0 || strcmp(b, "COLORREF") == 0 || strcmp(b, "ACCESS_MASK") == 0 ||
               strcmp(b, "LCID") == 0 || strcmp(b, "REGSAM") == 0) {
        kind = HL_TY_U32; bits = 32;
    } else if (strcmp(b, "int64_t") == 0 || strcmp(b, "long long") == 0 || strcmp(b, "long long int") == 0 ||
               strcmp(b, "signed long long") == 0 || strcmp(b, "signed long long int") == 0 || strcmp(b, "i64") == 0 ||
               strcmp(b, "__int64") == 0 || strcmp(b, "INT64") == 0 || strcmp(b, "LONGLONG") == 0 ||
               strcmp(b, "LONG64") == 0 || strcmp(b, "intptr_t") == 0 || strcmp(b, "ptrdiff_t") == 0 ||
               strcmp(b, "ssize_t") == 0 || strcmp(b, "SSIZE_T") == 0 || strcmp(b, "INT_PTR") == 0 ||
               strcmp(b, "LONG_PTR") == 0 || strcmp(b, "LPARAM") == 0 || strcmp(b, "LRESULT") == 0 ||
               strcmp(b, "time_t") == 0 || strcmp(b, "__time64_t") == 0 || strcmp(b, "off_t") == 0) {
        kind = HL_TY_I64; bits = 64;
    } else if (strcmp(b, "uint64_t") == 0 || strcmp(b, "unsigned long long") == 0 ||
               strcmp(b, "unsigned long long int") == 0 || strcmp(b, "u64") == 0 || strcmp(b, "unsigned __int64") == 0 ||
               strcmp(b, "QWORD") == 0 || strcmp(b, "UINT64") == 0 || strcmp(b, "ULONG64") == 0 ||
               strcmp(b, "ULONGLONG") == 0 || strcmp(b, "DWORD64") == 0 || strcmp(b, "DWORDLONG") == 0 ||
               strcmp(b, "uintptr_t") == 0 || strcmp(b, "UINT_PTR") == 0 || strcmp(b, "ULONG_PTR") == 0 ||
               strcmp(b, "DWORD_PTR") == 0 || strcmp(b, "WPARAM") == 0) {
        kind = HL_TY_U64; bits = 64;
    } else if (strcmp(b, "size_t") == 0 || strcmp(b, "SIZE_T") == 0) {
        kind = HL_TY_SIZE_T; bits = 64;
    } else if (strcmp(b, "float") == 0 || strcmp(b, "FLOAT") == 0) {
        kind = HL_TY_F32; bits = 32;
    } else if (strcmp(b, "double") == 0 || strcmp(b, "long double") == 0 || strcmp(b, "DOUBLE") == 0) {
        kind = HL_TY_F64; bits = 64;
    } else if (strcmp(b, "HANDLE") == 0 || strcmp(b, "HFILE") == 0 || strcmp(b, "SC_HANDLE") == 0 ||
               strcmp(b, "HINTERNET") == 0 || strcmp(b, "HCRYPTPROV") == 0 || strcmp(b, "HCRYPTHASH") == 0 ||
               strcmp(b, "HCRYPTKEY") == 0 || strcmp(b, "BCRYPT_ALG_HANDLE") == 0 || strcmp(b, "BCRYPT_KEY_HANDLE") == 0 ||
               strcmp(b, "BCRYPT_HASH_HANDLE") == 0 || strcmp(b, "HGLOBAL") == 0 || strcmp(b, "HLOCAL") == 0 ||
               strcmp(b, "HRSRC") == 0 || strcmp(b, "HMENU") == 0 || strcmp(b, "HDC") == 0 || strcmp(b, "HGDIOBJ") == 0 ||
               strcmp(b, "HBRUSH") == 0 || strcmp(b, "HPEN") == 0 || strcmp(b, "HFONT") == 0 || strcmp(b, "HBITMAP") == 0 ||
               strcmp(b, "HICON") == 0 || strcmp(b, "HCURSOR") == 0 || strcmp(b, "HHOOK") == 0) {
        kind = HL_TY_HANDLE; bits = 64;
    } else if (strcmp(b, "HMODULE") == 0 || strcmp(b, "HINSTANCE") == 0) {
        kind = HL_TY_HMODULE; bits = 64;
    } else if (strcmp(b, "HWND") == 0) {
        kind = HL_TY_HWND; bits = 64;
    } else if (strcmp(b, "HKEY") == 0) {
        kind = HL_TY_HKEY; bits = 64;
    } else if (strcmp(b, "SOCKET") == 0) {
        kind = HL_TY_SOCKET; bits = 64;
    } else if (strcmp(b, "FILE") == 0) {
        kind = HL_TY_FILE; bits = 0;
    }

    if (kind != HL_TY_UNK) {
        if (ptr_depth > 4) ptr_depth = 4;
        *out = ti_make_ty(kind, (uint8_t)ptr_depth, (uint8_t)is_const, bits);
        return true;
    }

    if (types) {
        const typ_def *td = typ_find(types, b);
        if (!td && b[0] == 'P' && b[1] && isupper((unsigned char)b[1])) {
            td = typ_find(types, b + 1);
            if (td) ptr_depth++;
        } else if (!td && b[0] == 'L' && b[1] == 'P' && b[2] && isupper((unsigned char)b[2])) {
            td = typ_find(types, b + 2);
            if (td) ptr_depth++;
        }
        if (td) {
            if (td->kind == 2 && td->nmem > 0 && td->mems[0].type[0]) {
                hl_type sub;
                if (ti_type_parse_depth(types, td->mems[0].type, &sub, depth + 1)) {
                    int pd = (int)sub.ptr_depth + ptr_depth;
                    if (pd > 4) pd = 4;
                    sub.ptr_depth = (uint8_t)pd;
                    if (is_const) sub.is_const = 1;
                    *out = sub;
                    return true;
                }
            }
            out->kind = HL_TY_STRUCT;
            out->ptr_depth = (uint8_t)(ptr_depth > 4 ? 4 : ptr_depth);
            out->is_const = (uint8_t)is_const;
            out->bits = (td->kind == 1) ? 32 : (uint8_t)(td->size > 0 && td->size <= 8 ? td->size * 8 : 0);
            snprintf(out->name, sizeof(out->name), "%s", td->name);
            return true;
        }
    }

    // allow forward-declared struct names before typ_store defines them
    if (ti_is_valid_ident(b)) {
        out->kind = HL_TY_STRUCT;
        out->ptr_depth = (uint8_t)(ptr_depth > 4 ? 4 : ptr_depth);
        out->is_const = (uint8_t)is_const;
        snprintf(out->name, sizeof(out->name), "%s", b);
        return true;
    }

    return false;
}

bool hl_type_parse(const typ_store *types, const char *decl, hl_type *out) {
    return ti_type_parse_depth(types, decl, out, 0);
}

static const ti_api_ent ti_apis[] = {
    // Win32 File & Pipe I/O
    {"CreateFileA", T_HND, 7, 0, -1, {T_CSTR, T_U32, T_U32, T_VP, T_U32, T_U32, T_HND}},
    {"CreateFileW", T_HND, 7, 0, -1, {T_CWSTR, T_U32, T_U32, T_VP, T_U32, T_U32, T_HND}},
    {"ReadFile", T_BOOL, 5, 0, -1, {T_HND, T_VP, T_U32, T_U32P, T_VP}},
    {"WriteFile", T_BOOL, 5, 0, -1, {T_HND, T_CVP, T_U32, T_U32P, T_VP}},
    {"CloseHandle", T_BOOL, 1, 0, -1, {T_HND}},
    {"DuplicateHandle", T_BOOL, 7, 0, -1, {T_HND, T_HND, T_HND, T_HNDP, T_U32, T_BOOL, T_U32}},
    {"GetFileSize", T_U32, 2, 0, -1, {T_HND, T_U32P}},
    {"GetFileSizeEx", T_BOOL, 2, 0, -1, {T_HND, T_I64P}},
    {"SetFilePointer", T_U32, 4, 0, -1, {T_HND, T_I32, T_I32P, T_U32}},
    {"SetFilePointerEx", T_BOOL, 4, 0, -1, {T_HND, T_I64, T_I64P, T_U32}},
    {"SetEndOfFile", T_BOOL, 1, 0, -1, {T_HND}},
    {"FlushFileBuffers", T_BOOL, 1, 0, -1, {T_HND}},
    {"DeleteFileA", T_BOOL, 1, 0, -1, {T_CSTR}},
    {"DeleteFileW", T_BOOL, 1, 0, -1, {T_CWSTR}},
    {"MoveFileA", T_BOOL, 2, 0, -1, {T_CSTR, T_CSTR}},
    {"MoveFileW", T_BOOL, 2, 0, -1, {T_CWSTR, T_CWSTR}},
    {"MoveFileExA", T_BOOL, 3, 0, -1, {T_CSTR, T_CSTR, T_U32}},
    {"MoveFileExW", T_BOOL, 3, 0, -1, {T_CWSTR, T_CWSTR, T_U32}},
    {"CopyFileA", T_BOOL, 3, 0, -1, {T_CSTR, T_CSTR, T_BOOL}},
    {"CopyFileW", T_BOOL, 3, 0, -1, {T_CWSTR, T_CWSTR, T_BOOL}},
    {"CreateFileMappingA", T_HND, 6, 0, -1, {T_HND, T_VP, T_U32, T_U32, T_U32, T_CSTR}},
    {"CreateFileMappingW", T_HND, 6, 0, -1, {T_HND, T_VP, T_U32, T_U32, T_U32, T_CWSTR}},
    {"OpenFileMappingA", T_HND, 3, 0, -1, {T_U32, T_BOOL, T_CSTR}},
    {"OpenFileMappingW", T_HND, 3, 0, -1, {T_U32, T_BOOL, T_CWSTR}},
    {"MapViewOfFile", T_VP, 5, 0, -1, {T_HND, T_U32, T_U32, T_U32, T_SZ}},
    {"MapViewOfFileEx", T_VP, 6, 0, -1, {T_HND, T_U32, T_U32, T_U32, T_SZ, T_VP}},
    {"UnmapViewOfFile", T_BOOL, 1, 0, -1, {T_CVP}},
    {"FlushViewOfFile", T_BOOL, 2, 0, -1, {T_CVP, T_SZ}},
    {"FindFirstFileA", T_HND, 2, 0, -1, {T_CSTR, T_VP}},
    {"FindFirstFileW", T_HND, 2, 0, -1, {T_CWSTR, T_VP}},
    {"FindNextFileA", T_BOOL, 2, 0, -1, {T_HND, T_VP}},
    {"FindNextFileW", T_BOOL, 2, 0, -1, {T_HND, T_VP}},
    {"FindClose", T_BOOL, 1, 0, -1, {T_HND}},
    {"GetFileAttributesA", T_U32, 1, 0, -1, {T_CSTR}},
    {"GetFileAttributesW", T_U32, 1, 0, -1, {T_CWSTR}},
    {"SetFileAttributesA", T_BOOL, 2, 0, -1, {T_CSTR, T_U32}},
    {"SetFileAttributesW", T_BOOL, 2, 0, -1, {T_CWSTR, T_U32}},
    {"GetFileType", T_U32, 1, 0, -1, {T_HND}},
    {"GetStdHandle", T_HND, 1, 0, -1, {T_U32}},
    {"SetStdHandle", T_BOOL, 2, 0, -1, {T_U32, T_HND}},
    {"CreateDirectoryA", T_BOOL, 2, 0, -1, {T_CSTR, T_VP}},
    {"CreateDirectoryW", T_BOOL, 2, 0, -1, {T_CWSTR, T_VP}},
    {"RemoveDirectoryA", T_BOOL, 1, 0, -1, {T_CSTR}},
    {"RemoveDirectoryW", T_BOOL, 1, 0, -1, {T_CWSTR}},
    {"GetTempPathA", T_U32, 2, 0, -1, {T_U32, T_STR}},
    {"GetTempPathW", T_U32, 2, 0, -1, {T_U32, T_WSTR}},
    {"GetTempFileNameA", T_U32, 4, 0, -1, {T_CSTR, T_CSTR, T_U32, T_STR}},
    {"GetTempFileNameW", T_U32, 4, 0, -1, {T_CWSTR, T_CWSTR, T_U32, T_WSTR}},
    {"GetFullPathNameA", T_U32, 4, 0, -1, {T_CSTR, T_U32, T_STR, T_STRP}},
    {"GetFullPathNameW", T_U32, 4, 0, -1, {T_CWSTR, T_U32, T_WSTR, T_VPP}},
    {"GetCurrentDirectoryA", T_U32, 2, 0, -1, {T_U32, T_STR}},
    {"GetCurrentDirectoryW", T_U32, 2, 0, -1, {T_U32, T_WSTR}},
    {"SetCurrentDirectoryA", T_BOOL, 1, 0, -1, {T_CSTR}},
    {"SetCurrentDirectoryW", T_BOOL, 1, 0, -1, {T_CWSTR}},
    {"DeviceIoControl", T_BOOL, 8, 0, -1, {T_HND, T_U32, T_VP, T_U32, T_VP, T_U32, T_U32P, T_VP}},
    {"CreatePipe", T_BOOL, 4, 0, -1, {T_HNDP, T_HNDP, T_VP, T_U32}},
    {"PeekNamedPipe", T_BOOL, 6, 0, -1, {T_HND, T_VP, T_U32, T_U32P, T_U32P, T_U32P}},
    {"CreateNamedPipeA", T_HND, 8, 0, -1, {T_CSTR, T_U32, T_U32, T_U32, T_U32, T_U32, T_U32, T_VP}},
    {"CreateNamedPipeW", T_HND, 8, 0, -1, {T_CWSTR, T_U32, T_U32, T_U32, T_U32, T_U32, T_U32, T_VP}},
    {"ConnectNamedPipe", T_BOOL, 2, 0, -1, {T_HND, T_VP}},

    // Win32 Console, Command Line & Environment
    {"GetConsoleProcessList", T_U32, 2, 0, -1, {T_U32P, T_U32}},
    {"FreeConsole", T_BOOL, 0, 0, -1, {0}},
    {"AllocConsole", T_BOOL, 0, 0, -1, {0}},
    {"AttachConsole", T_BOOL, 1, 0, -1, {T_U32}},
    {"GetConsoleWindow", T_HWND, 0, 0, -1, {0}},
    {"GetConsoleMode", T_BOOL, 2, 0, -1, {T_HND, T_U32P}},
    {"SetConsoleMode", T_BOOL, 2, 0, -1, {T_HND, T_U32}},
    {"WriteConsoleA", T_BOOL, 5, 0, -1, {T_HND, T_CVP, T_U32, T_U32P, T_VP}},
    {"WriteConsoleW", T_BOOL, 5, 0, -1, {T_HND, T_CVP, T_U32, T_U32P, T_VP}},
    {"ReadConsoleA", T_BOOL, 5, 0, -1, {T_HND, T_VP, T_U32, T_U32P, T_VP}},
    {"ReadConsoleW", T_BOOL, 5, 0, -1, {T_HND, T_VP, T_U32, T_U32P, T_VP}},
    {"SetConsoleTitleA", T_BOOL, 1, 0, -1, {T_CSTR}},
    {"SetConsoleTitleW", T_BOOL, 1, 0, -1, {T_CWSTR}},
    {"GetCommandLineA", T_STR, 0, 0, -1, {0}},
    {"GetCommandLineW", T_WSTR, 0, 0, -1, {0}},
    {"CommandLineToArgvW", T_VPP, 2, 0, -1, {T_CWSTR, T_I32P}},
    {"GetEnvironmentVariableA", T_U32, 3, 0, -1, {T_CSTR, T_STR, T_U32}},
    {"GetEnvironmentVariableW", T_U32, 3, 0, -1, {T_CWSTR, T_WSTR, T_U32}},
    {"SetEnvironmentVariableA", T_BOOL, 2, 0, -1, {T_CSTR, T_CSTR}},
    {"SetEnvironmentVariableW", T_BOOL, 2, 0, -1, {T_CWSTR, T_CWSTR}},
    {"ExpandEnvironmentStringsA", T_U32, 3, 0, -1, {T_CSTR, T_STR, T_U32}},
    {"ExpandEnvironmentStringsW", T_U32, 3, 0, -1, {T_CWSTR, T_WSTR, T_U32}},

    // Win32 Virtual Memory & Heap
    {"VirtualAlloc", T_VP, 4, 0, -1, {T_VP, T_SZ, T_U32, T_U32}},
    {"VirtualAllocEx", T_VP, 5, 0, -1, {T_HND, T_VP, T_SZ, T_U32, T_U32}},
    {"VirtualProtect", T_BOOL, 4, 0, -1, {T_VP, T_SZ, T_U32, T_U32P}},
    {"VirtualProtectEx", T_BOOL, 5, 0, -1, {T_HND, T_VP, T_SZ, T_U32, T_U32P}},
    {"VirtualFree", T_BOOL, 3, 0, -1, {T_VP, T_SZ, T_U32}},
    {"VirtualFreeEx", T_BOOL, 4, 0, -1, {T_HND, T_VP, T_SZ, T_U32}},
    {"VirtualQuery", T_SZ, 3, 0, -1, {T_CVP, T_VP, T_SZ}},
    {"VirtualQueryEx", T_SZ, 4, 0, -1, {T_HND, T_CVP, T_VP, T_SZ}},
    {"GetProcessHeap", T_HND, 0, 0, -1, {0}},
    {"HeapCreate", T_HND, 3, 0, -1, {T_U32, T_SZ, T_SZ}},
    {"HeapDestroy", T_BOOL, 1, 0, -1, {T_HND}},
    {"HeapAlloc", T_VP, 3, 0, -1, {T_HND, T_U32, T_SZ}},
    {"HeapReAlloc", T_VP, 4, 0, -1, {T_HND, T_U32, T_VP, T_SZ}},
    {"HeapFree", T_BOOL, 3, 0, -1, {T_HND, T_U32, T_VP}},
    {"HeapSize", T_SZ, 3, 0, -1, {T_HND, T_U32, T_CVP}},
    {"LocalAlloc", T_VP, 2, 0, -1, {T_U32, T_SZ}},
    {"LocalReAlloc", T_VP, 3, 0, -1, {T_VP, T_SZ, T_U32}},
    {"LocalFree", T_VP, 1, 0, -1, {T_VP}},
    {"GlobalAlloc", T_VP, 2, 0, -1, {T_U32, T_SZ}},
    {"GlobalReAlloc", T_VP, 3, 0, -1, {T_VP, T_SZ, T_U32}},
    {"GlobalFree", T_VP, 1, 0, -1, {T_VP}},
    {"GlobalLock", T_VP, 1, 0, -1, {T_HND}},
    {"GlobalUnlock", T_BOOL, 1, 0, -1, {T_HND}},

    // Win32 Module, Library, System Info & Time
    {"LoadLibraryA", T_HMOD, 1, 0, -1, {T_CSTR}},
    {"LoadLibraryW", T_HMOD, 1, 0, -1, {T_CWSTR}},
    {"LoadLibraryExA", T_HMOD, 3, 0, -1, {T_CSTR, T_HND, T_U32}},
    {"LoadLibraryExW", T_HMOD, 3, 0, -1, {T_CWSTR, T_HND, T_U32}},
    {"GetModuleHandleA", T_HMOD, 1, 0, -1, {T_CSTR}},
    {"GetModuleHandleW", T_HMOD, 1, 0, -1, {T_CWSTR}},
    {"GetModuleHandleExA", T_BOOL, 3, 0, -1, {T_U32, T_CSTR, T_HMODP}},
    {"GetModuleHandleExW", T_BOOL, 3, 0, -1, {T_U32, T_CWSTR, T_HMODP}},
    {"GetModuleFileNameA", T_U32, 3, 0, -1, {T_HMOD, T_STR, T_U32}},
    {"GetModuleFileNameW", T_U32, 3, 0, -1, {T_HMOD, T_WSTR, T_U32}},
    {"FreeLibrary", T_BOOL, 1, 0, -1, {T_HMOD}},
    {"GetProcAddress", T_VP, 2, 0, -1, {T_HMOD, T_CSTR}},
    {"GetSystemInfo", T_VOID, 1, 0, -1, {T_VP}},
    {"GetNativeSystemInfo", T_VOID, 1, 0, -1, {T_VP}},
    {"GetSystemDirectoryA", T_U32, 2, 0, -1, {T_STR, T_U32}},
    {"GetSystemDirectoryW", T_U32, 2, 0, -1, {T_WSTR, T_U32}},
    {"GetWindowsDirectoryA", T_U32, 2, 0, -1, {T_STR, T_U32}},
    {"GetWindowsDirectoryW", T_U32, 2, 0, -1, {T_WSTR, T_U32}},
    {"GetComputerNameA", T_BOOL, 2, 0, -1, {T_STR, T_U32P}},
    {"GetComputerNameW", T_BOOL, 2, 0, -1, {T_WSTR, T_U32P}},
    {"GetUserNameA", T_BOOL, 2, 0, -1, {T_STR, T_U32P}},
    {"GetUserNameW", T_BOOL, 2, 0, -1, {T_WSTR, T_U32P}},
    {"GetVersion", T_U32, 0, 0, -1, {0}},
    {"GetVersionExA", T_BOOL, 1, 0, -1, {T_VP}},
    {"GetVersionExW", T_BOOL, 1, 0, -1, {T_VP}},
    {"GetSystemTime", T_VOID, 1, 0, -1, {T_VP}},
    {"GetLocalTime", T_VOID, 1, 0, -1, {T_VP}},
    {"GetSystemTimeAsFileTime", T_VOID, 1, 0, -1, {T_VP}},
    {"GetTickCount", T_U32, 0, 0, -1, {0}},
    {"GetTickCount64", T_U64, 0, 0, -1, {0}},
    {"QueryPerformanceCounter", T_BOOL, 1, 0, -1, {T_I64P}},
    {"QueryPerformanceFrequency", T_BOOL, 1, 0, -1, {T_I64P}},

    // Win32 Process, Thread, Debug & Error
    {"CreateProcessA", T_BOOL, 10, 0, -1, {T_CSTR, T_STR, T_VP, T_VP, T_BOOL, T_U32, T_VP, T_CSTR, T_VP, T_VP}},
    {"CreateProcessW", T_BOOL, 10, 0, -1, {T_CWSTR, T_WSTR, T_VP, T_VP, T_BOOL, T_U32, T_VP, T_CWSTR, T_VP, T_VP}},
    {"OpenProcess", T_HND, 3, 0, -1, {T_U32, T_BOOL, T_U32}},
    {"GetCurrentProcess", T_HND, 0, 0, -1, {0}},
    {"GetCurrentProcessId", T_U32, 0, 0, -1, {0}},
    {"TerminateProcess", T_BOOL, 2, 0, -1, {T_HND, T_U32}},
    {"ExitProcess", T_VOID, 1, 0, -1, {T_U32}},
    {"GetExitCodeProcess", T_BOOL, 2, 0, -1, {T_HND, T_U32P}},
    {"CreateThread", T_HND, 6, 0, -1, {T_VP, T_SZ, T_VP, T_VP, T_U32, T_U32P}},
    {"CreateRemoteThread", T_HND, 7, 0, -1, {T_HND, T_VP, T_SZ, T_VP, T_VP, T_U32, T_U32P}},
    {"OpenThread", T_HND, 3, 0, -1, {T_U32, T_BOOL, T_U32}},
    {"GetCurrentThread", T_HND, 0, 0, -1, {0}},
    {"GetCurrentThreadId", T_U32, 0, 0, -1, {0}},
    {"SuspendThread", T_U32, 1, 0, -1, {T_HND}},
    {"ResumeThread", T_U32, 1, 0, -1, {T_HND}},
    {"TerminateThread", T_BOOL, 2, 0, -1, {T_HND, T_U32}},
    {"ExitThread", T_VOID, 1, 0, -1, {T_U32}},
    {"GetExitCodeThread", T_BOOL, 2, 0, -1, {T_HND, T_U32P}},
    {"GetThreadContext", T_BOOL, 2, 0, -1, {T_HND, T_VP}},
    {"SetThreadContext", T_BOOL, 2, 0, -1, {T_HND, T_CVP}},
    {"ReadProcessMemory", T_BOOL, 5, 0, -1, {T_HND, T_CVP, T_VP, T_SZ, T_SZP}},
    {"WriteProcessMemory", T_BOOL, 5, 0, -1, {T_HND, T_VP, T_CVP, T_SZ, T_SZP}},
    {"FlushInstructionCache", T_BOOL, 3, 0, -1, {T_HND, T_CVP, T_SZ}},
    {"Sleep", T_VOID, 1, 0, -1, {T_U32}},
    {"SleepEx", T_U32, 2, 0, -1, {T_U32, T_BOOL}},
    {"GetLastError", T_U32, 0, 0, -1, {0}},
    {"SetLastError", T_VOID, 1, 0, -1, {T_U32}},
    {"FormatMessageA", T_U32, 7, 0, -1, {T_U32, T_CVP, T_U32, T_U32, T_STR, T_U32, T_VP}},
    {"FormatMessageW", T_U32, 7, 0, -1, {T_U32, T_CVP, T_U32, T_U32, T_WSTR, T_U32, T_VP}},
    {"IsDebuggerPresent", T_BOOL, 0, 0, -1, {0}},
    {"CheckRemoteDebuggerPresent", T_BOOL, 2, 0, -1, {T_HND, T_I32P}},
    {"OutputDebugStringA", T_VOID, 1, 0, -1, {T_CSTR}},
    {"OutputDebugStringW", T_VOID, 1, 0, -1, {T_CWSTR}},
    {"RaiseException", T_VOID, 4, 0, -1, {T_U32, T_U32, T_U32, T_U64P}},
    {"SetUnhandledExceptionFilter", T_VP, 1, 0, -1, {T_VP}},
    {"AddVectoredExceptionHandler", T_VP, 2, 0, -1, {T_U32, T_VP}},
    {"CreateToolhelp32Snapshot", T_HND, 2, 0, -1, {T_U32, T_U32}},
    {"Process32First", T_BOOL, 2, 0, -1, {T_HND, T_VP}},
    {"Process32Next", T_BOOL, 2, 0, -1, {T_HND, T_VP}},
    {"Process32FirstW", T_BOOL, 2, 0, -1, {T_HND, T_VP}},
    {"Process32NextW", T_BOOL, 2, 0, -1, {T_HND, T_VP}},
    {"Module32First", T_BOOL, 2, 0, -1, {T_HND, T_VP}},
    {"Module32Next", T_BOOL, 2, 0, -1, {T_HND, T_VP}},
    {"ShellExecuteA", T_HMOD, 6, 0, -1, {T_HWND, T_CSTR, T_CSTR, T_CSTR, T_CSTR, T_I32}},
    {"ShellExecuteW", T_HMOD, 6, 0, -1, {T_HWND, T_CWSTR, T_CWSTR, T_CWSTR, T_CWSTR, T_I32}},
    {"WinExec", T_U32, 2, 0, -1, {T_CSTR, T_U32}},
    {"_beginthreadex", T_HND, 6, 0, -1, {T_VP, T_U32, T_VP, T_VP, T_U32, T_U32P}},
    {"_endthreadex", T_VOID, 1, 0, -1, {T_U32}},

    // Win32 Synchronization & TLS
    {"WaitForSingleObject", T_U32, 2, 0, -1, {T_HND, T_U32}},
    {"WaitForSingleObjectEx", T_U32, 3, 0, -1, {T_HND, T_U32, T_BOOL}},
    {"WaitForMultipleObjects", T_U32, 4, 0, -1, {T_U32, T_HNDP, T_BOOL, T_U32}},
    {"WaitForMultipleObjectsEx", T_U32, 5, 0, -1, {T_U32, T_HNDP, T_BOOL, T_U32, T_BOOL}},
    {"InitializeCriticalSection", T_VOID, 1, 0, -1, {T_VP}},
    {"InitializeCriticalSectionAndSpinCount", T_BOOL, 2, 0, -1, {T_VP, T_U32}},
    {"EnterCriticalSection", T_VOID, 1, 0, -1, {T_VP}},
    {"TryEnterCriticalSection", T_BOOL, 1, 0, -1, {T_VP}},
    {"LeaveCriticalSection", T_VOID, 1, 0, -1, {T_VP}},
    {"DeleteCriticalSection", T_VOID, 1, 0, -1, {T_VP}},
    {"InitializeSRWLock", T_VOID, 1, 0, -1, {T_VP}},
    {"AcquireSRWLockExclusive", T_VOID, 1, 0, -1, {T_VP}},
    {"ReleaseSRWLockExclusive", T_VOID, 1, 0, -1, {T_VP}},
    {"AcquireSRWLockShared", T_VOID, 1, 0, -1, {T_VP}},
    {"ReleaseSRWLockShared", T_VOID, 1, 0, -1, {T_VP}},
    {"CreateEventA", T_HND, 4, 0, -1, {T_VP, T_BOOL, T_BOOL, T_CSTR}},
    {"CreateEventW", T_HND, 4, 0, -1, {T_VP, T_BOOL, T_BOOL, T_CWSTR}},
    {"OpenEventA", T_HND, 3, 0, -1, {T_U32, T_BOOL, T_CSTR}},
    {"OpenEventW", T_HND, 3, 0, -1, {T_U32, T_BOOL, T_CWSTR}},
    {"SetEvent", T_BOOL, 1, 0, -1, {T_HND}},
    {"ResetEvent", T_BOOL, 1, 0, -1, {T_HND}},
    {"CreateMutexA", T_HND, 3, 0, -1, {T_VP, T_BOOL, T_CSTR}},
    {"CreateMutexW", T_HND, 3, 0, -1, {T_VP, T_BOOL, T_CWSTR}},
    {"OpenMutexA", T_HND, 3, 0, -1, {T_U32, T_BOOL, T_CSTR}},
    {"OpenMutexW", T_HND, 3, 0, -1, {T_U32, T_BOOL, T_CWSTR}},
    {"ReleaseMutex", T_BOOL, 1, 0, -1, {T_HND}},
    {"CreateSemaphoreA", T_HND, 4, 0, -1, {T_VP, T_I32, T_I32, T_CSTR}},
    {"CreateSemaphoreW", T_HND, 4, 0, -1, {T_VP, T_I32, T_I32, T_CWSTR}},
    {"ReleaseSemaphore", T_BOOL, 3, 0, -1, {T_HND, T_I32, T_I32P}},
    {"TlsAlloc", T_U32, 0, 0, -1, {0}},
    {"TlsGetValue", T_VP, 1, 0, -1, {T_U32}},
    {"TlsSetValue", T_BOOL, 2, 0, -1, {T_U32, T_VP}},
    {"TlsFree", T_BOOL, 1, 0, -1, {T_U32}},
    {"InitOnceExecuteOnce", T_BOOL, 4, 0, -1, {T_VP, T_VP, T_VP, T_VPP}},

    // Win32 Registry, Services & Security
    {"RegOpenKeyExA", T_I32, 5, 0, -1, {T_HKEY, T_CSTR, T_U32, T_U32, T_HKEYP}},
    {"RegOpenKeyExW", T_I32, 5, 0, -1, {T_HKEY, T_CWSTR, T_U32, T_U32, T_HKEYP}},
    {"RegCreateKeyExA", T_I32, 9, 0, -1, {T_HKEY, T_CSTR, T_U32, T_STR, T_U32, T_U32, T_VP, T_HKEYP, T_U32P}},
    {"RegCreateKeyExW", T_I32, 9, 0, -1, {T_HKEY, T_CWSTR, T_U32, T_WSTR, T_U32, T_U32, T_VP, T_HKEYP, T_U32P}},
    {"RegQueryValueExA", T_I32, 6, 0, -1, {T_HKEY, T_CSTR, T_U32P, T_U32P, T_U8P, T_U32P}},
    {"RegQueryValueExW", T_I32, 6, 0, -1, {T_HKEY, T_CWSTR, T_U32P, T_U32P, T_U8P, T_U32P}},
    {"RegSetValueExA", T_I32, 6, 0, -1, {T_HKEY, T_CSTR, T_U32, T_U32, T_CU8P, T_U32}},
    {"RegSetValueExW", T_I32, 6, 0, -1, {T_HKEY, T_CWSTR, T_U32, T_U32, T_CU8P, T_U32}},
    {"RegDeleteValueA", T_I32, 2, 0, -1, {T_HKEY, T_CSTR}},
    {"RegDeleteValueW", T_I32, 2, 0, -1, {T_HKEY, T_CWSTR}},
    {"RegDeleteKeyA", T_I32, 2, 0, -1, {T_HKEY, T_CSTR}},
    {"RegDeleteKeyW", T_I32, 2, 0, -1, {T_HKEY, T_CWSTR}},
    {"RegEnumKeyExA", T_I32, 8, 0, -1, {T_HKEY, T_U32, T_STR, T_U32P, T_U32P, T_STR, T_U32P, T_VP}},
    {"RegEnumKeyExW", T_I32, 8, 0, -1, {T_HKEY, T_U32, T_WSTR, T_U32P, T_U32P, T_WSTR, T_U32P, T_VP}},
    {"RegEnumValueA", T_I32, 8, 0, -1, {T_HKEY, T_U32, T_STR, T_U32P, T_U32P, T_U32P, T_U8P, T_U32P}},
    {"RegEnumValueW", T_I32, 8, 0, -1, {T_HKEY, T_U32, T_WSTR, T_U32P, T_U32P, T_U32P, T_U8P, T_U32P}},
    {"RegCloseKey", T_I32, 1, 0, -1, {T_HKEY}},
    {"OpenSCManagerA", T_HND, 3, 0, -1, {T_CSTR, T_CSTR, T_U32}},
    {"OpenSCManagerW", T_HND, 3, 0, -1, {T_CWSTR, T_CWSTR, T_U32}},
    {"OpenServiceA", T_HND, 3, 0, -1, {T_HND, T_CSTR, T_U32}},
    {"OpenServiceW", T_HND, 3, 0, -1, {T_HND, T_CWSTR, T_U32}},
    {"CreateServiceA", T_HND, 10, 0, -1, {T_HND, T_CSTR, T_CSTR, T_U32, T_U32, T_U32, T_U32, T_CSTR, T_CSTR, T_U32P}},
    {"CreateServiceW", T_HND, 10, 0, -1, {T_HND, T_CWSTR, T_CWSTR, T_U32, T_U32, T_U32, T_U32, T_CWSTR, T_CWSTR, T_U32P}},
    {"StartServiceA", T_BOOL, 3, 0, -1, {T_HND, T_U32, T_STRP}},
    {"StartServiceW", T_BOOL, 3, 0, -1, {T_HND, T_U32, T_VPP}},
    {"CloseServiceHandle", T_BOOL, 1, 0, -1, {T_HND}},
    {"OpenProcessToken", T_BOOL, 3, 0, -1, {T_HND, T_U32, T_HNDP}},
    {"AdjustTokenPrivileges", T_BOOL, 6, 0, -1, {T_HND, T_BOOL, T_VP, T_U32, T_VP, T_U32P}},
    {"LookupPrivilegeValueA", T_BOOL, 3, 0, -1, {T_CSTR, T_CSTR, T_VP}},
    {"LookupPrivilegeValueW", T_BOOL, 3, 0, -1, {T_CWSTR, T_CWSTR, T_VP}},
    {"GetTokenInformation", T_BOOL, 5, 0, -1, {T_HND, T_I32, T_VP, T_U32, T_U32P}},

    // Win32 GUI / User32 / GDI
    {"MessageBoxA", T_I32, 4, 0, -1, {T_HWND, T_CSTR, T_CSTR, T_U32}},
    {"MessageBoxW", T_I32, 4, 0, -1, {T_HWND, T_CWSTR, T_CWSTR, T_U32}},
    {"CreateWindowExA", T_HWND, 10, 0, -1, {T_U32, T_CSTR, T_CSTR, T_U32, T_I32, T_I32, T_I32, T_I32, T_HWND, T_HND}},
    {"CreateWindowExW", T_HWND, 10, 0, -1, {T_U32, T_CWSTR, T_CWSTR, T_U32, T_I32, T_I32, T_I32, T_I32, T_HWND, T_HND}},
    {"DestroyWindow", T_BOOL, 1, 0, -1, {T_HWND}},
    {"ShowWindow", T_BOOL, 2, 0, -1, {T_HWND, T_I32}},
    {"UpdateWindow", T_BOOL, 1, 0, -1, {T_HWND}},
    {"FindWindowA", T_HWND, 2, 0, -1, {T_CSTR, T_CSTR}},
    {"FindWindowW", T_HWND, 2, 0, -1, {T_CWSTR, T_CWSTR}},
    {"GetWindowTextA", T_I32, 3, 0, -1, {T_HWND, T_STR, T_I32}},
    {"GetWindowTextW", T_I32, 3, 0, -1, {T_HWND, T_WSTR, T_I32}},
    {"SetWindowTextA", T_BOOL, 2, 0, -1, {T_HWND, T_CSTR}},
    {"SetWindowTextW", T_BOOL, 2, 0, -1, {T_HWND, T_CWSTR}},
    {"GetWindowLongPtrA", T_I64, 2, 0, -1, {T_HWND, T_I32}},
    {"GetWindowLongPtrW", T_I64, 2, 0, -1, {T_HWND, T_I32}},
    {"SetWindowLongPtrA", T_I64, 3, 0, -1, {T_HWND, T_I32, T_I64}},
    {"SetWindowLongPtrW", T_I64, 3, 0, -1, {T_HWND, T_I32, T_I64}},
    {"SendMessageA", T_I64, 4, 0, -1, {T_HWND, T_U32, T_U64, T_I64}},
    {"SendMessageW", T_I64, 4, 0, -1, {T_HWND, T_U32, T_U64, T_I64}},
    {"PostMessageA", T_BOOL, 4, 0, -1, {T_HWND, T_U32, T_U64, T_I64}},
    {"PostMessageW", T_BOOL, 4, 0, -1, {T_HWND, T_U32, T_U64, T_I64}},
    {"PostQuitMessage", T_VOID, 1, 0, -1, {T_I32}},
    {"GetMessageA", T_BOOL, 4, 0, -1, {T_VP, T_HWND, T_U32, T_U32}},
    {"GetMessageW", T_BOOL, 4, 0, -1, {T_VP, T_HWND, T_U32, T_U32}},
    {"PeekMessageA", T_BOOL, 5, 0, -1, {T_VP, T_HWND, T_U32, T_U32, T_U32}},
    {"PeekMessageW", T_BOOL, 5, 0, -1, {T_VP, T_HWND, T_U32, T_U32, T_U32}},
    {"TranslateMessage", T_BOOL, 1, 0, -1, {T_CVP}},
    {"DispatchMessageA", T_I64, 1, 0, -1, {T_CVP}},
    {"DispatchMessageW", T_I64, 1, 0, -1, {T_CVP}},
    {"DefWindowProcA", T_I64, 4, 0, -1, {T_HWND, T_U32, T_U64, T_I64}},
    {"DefWindowProcW", T_I64, 4, 0, -1, {T_HWND, T_U32, T_U64, T_I64}},
    {"RegisterClassExA", T_U16, 1, 0, -1, {T_CVP}},
    {"RegisterClassExW", T_U16, 1, 0, -1, {T_CVP}},
    {"GetDC", T_HND, 1, 0, -1, {T_HWND}},
    {"ReleaseDC", T_I32, 2, 0, -1, {T_HWND, T_HND}},
    {"BeginPaint", T_HND, 2, 0, -1, {T_HWND, T_VP}},
    {"EndPaint", T_BOOL, 2, 0, -1, {T_HWND, T_CVP}},
    {"InvalidateRect", T_BOOL, 3, 0, -1, {T_HWND, T_CVP, T_BOOL}},
    {"GetClientRect", T_BOOL, 2, 0, -1, {T_HWND, T_VP}},
    {"GetWindowRect", T_BOOL, 2, 0, -1, {T_HWND, T_VP}},
    {"SetTimer", T_U64, 4, 0, -1, {T_HWND, T_U64, T_U32, T_VP}},
    {"KillTimer", T_BOOL, 2, 0, -1, {T_HWND, T_U64}},
    {"GetAsyncKeyState", T_I16, 1, 0, -1, {T_I32}},
    {"GetKeyState", T_I16, 1, 0, -1, {T_I32}},
    {"SetWindowsHookExA", T_HND, 4, 0, -1, {T_I32, T_VP, T_HMOD, T_U32}},
    {"SetWindowsHookExW", T_HND, 4, 0, -1, {T_I32, T_VP, T_HMOD, T_U32}},
    {"UnhookWindowsHookEx", T_BOOL, 1, 0, -1, {T_HND}},
    {"CallNextHookEx", T_I64, 4, 0, -1, {T_HND, T_I32, T_U64, T_I64}},
    {"wsprintfA", T_I32, 2, 1, 1, {T_STR, T_CSTR}},
    {"wsprintfW", T_I32, 2, 1, 1, {T_WSTR, T_CWSTR}},

    // NTAPI / ntdll (Zw* aliases map automatically to Nt*)
    {"NtAllocateVirtualMemory", T_I32, 6, 0, -1, {T_HND, T_VPP, T_U64, T_SZP, T_U32, T_U32}},
    {"NtFreeVirtualMemory", T_I32, 4, 0, -1, {T_HND, T_VPP, T_SZP, T_U32}},
    {"NtProtectVirtualMemory", T_I32, 5, 0, -1, {T_HND, T_VPP, T_SZP, T_U32, T_U32P}},
    {"NtReadVirtualMemory", T_I32, 5, 0, -1, {T_HND, T_CVP, T_VP, T_SZ, T_SZP}},
    {"NtWriteVirtualMemory", T_I32, 5, 0, -1, {T_HND, T_VP, T_CVP, T_SZ, T_SZP}},
    {"NtQueryVirtualMemory", T_I32, 6, 0, -1, {T_HND, T_CVP, T_I32, T_VP, T_SZ, T_SZP}},
    {"NtQuerySystemInformation", T_I32, 4, 0, -1, {T_I32, T_VP, T_U32, T_U32P}},
    {"NtQueryInformationProcess", T_I32, 5, 0, -1, {T_HND, T_I32, T_VP, T_U32, T_U32P}},
    {"NtQueryInformationThread", T_I32, 5, 0, -1, {T_HND, T_I32, T_VP, T_U32, T_U32P}},
    {"NtSetInformationThread", T_I32, 4, 0, -1, {T_HND, T_I32, T_CVP, T_U32}},
    {"NtOpenProcess", T_I32, 4, 0, -1, {T_HNDP, T_U32, T_VP, T_VP}},
    {"NtCreateThreadEx", T_I32, 10, 0, -1, {T_HNDP, T_U32, T_VP, T_HND, T_VP, T_VP, T_U32, T_SZ, T_SZ, T_SZ}},
    {"NtResumeThread", T_I32, 2, 0, -1, {T_HND, T_U32P}},
    {"NtSuspendThread", T_I32, 2, 0, -1, {T_HND, T_U32P}},
    {"NtTerminateProcess", T_I32, 2, 0, -1, {T_HND, T_I32}},
    {"NtClose", T_I32, 1, 0, -1, {T_HND}},
    {"NtDelayExecution", T_I32, 2, 0, -1, {T_BOOL, T_I64P}},
    {"NtWaitForSingleObject", T_I32, 3, 0, -1, {T_HND, T_BOOL, T_I64P}},
    {"NtCreateFile", T_I32, 10, 0, -1, {T_HNDP, T_U32, T_VP, T_VP, T_I64P, T_U32, T_U32, T_U32, T_U32, T_VP}},
    {"NtOpenFile", T_I32, 6, 0, -1, {T_HNDP, T_U32, T_VP, T_VP, T_U32, T_U32}},
    {"NtReadFile", T_I32, 9, 0, -1, {T_HND, T_HND, T_VP, T_VP, T_VP, T_VP, T_U32, T_I64P, T_U32P}},
    {"NtWriteFile", T_I32, 9, 0, -1, {T_HND, T_HND, T_VP, T_VP, T_VP, T_CVP, T_U32, T_I64P, T_U32P}},
    {"NtCreateSection", T_I32, 7, 0, -1, {T_HNDP, T_U32, T_VP, T_I64P, T_U32, T_U32, T_HND}},
    {"NtMapViewOfSection", T_I32, 10, 0, -1, {T_HND, T_HND, T_VPP, T_U64, T_SZ, T_I64P, T_SZP, T_I32, T_U32, T_U32}},
    {"NtUnmapViewOfSection", T_I32, 2, 0, -1, {T_HND, T_VP}},
    {"NtOpenKey", T_I32, 3, 0, -1, {T_HNDP, T_U32, T_VP}},
    {"NtQueryValueKey", T_I32, 6, 0, -1, {T_HND, T_VP, T_I32, T_VP, T_U32, T_U32P}},
    {"RtlCopyMemory", T_VOID, 3, 0, -1, {T_VP, T_CVP, T_SZ}},
    {"RtlMoveMemory", T_VOID, 3, 0, -1, {T_VP, T_CVP, T_SZ}},
    {"RtlZeroMemory", T_VOID, 2, 0, -1, {T_VP, T_SZ}},
    {"RtlFillMemory", T_VOID, 3, 0, -1, {T_VP, T_SZ, T_U8}},
    {"RtlCompareMemory", T_SZ, 3, 0, -1, {T_CVP, T_CVP, T_SZ}},
    {"RtlInitUnicodeString", T_VOID, 2, 0, -1, {T_VP, T_CWSTR}},
    {"RtlInitAnsiString", T_VOID, 2, 0, -1, {T_VP, T_CSTR}},
    {"RtlAnsiStringToUnicodeString", T_I32, 3, 0, -1, {T_VP, T_CVP, T_BOOL}},
    {"RtlFreeUnicodeString", T_VOID, 1, 0, -1, {T_VP}},
    {"RtlGetVersion", T_I32, 1, 0, -1, {T_VP}},
    {"RtlNtStatusToDosError", T_U32, 1, 0, -1, {T_I32}},
    {"RtlAddVectoredExceptionHandler", T_VP, 2, 0, -1, {T_U32, T_VP}},
    {"LdrLoadDll", T_I32, 4, 0, -1, {T_CWSTR, T_U32P, T_VP, T_HMODP}},
    {"LdrGetProcedureAddress", T_I32, 4, 0, -1, {T_HMOD, T_VP, T_U32, T_VPP}},

    // WinSock, WinHTTP & WinINet
    {"WSAStartup", T_I32, 2, 0, -1, {T_U16, T_VP}},
    {"WSACleanup", T_I32, 0, 0, -1, {0}},
    {"WSAGetLastError", T_I32, 0, 0, -1, {0}},
    {"WSASocketA", T_SOCK, 6, 0, -1, {T_I32, T_I32, T_I32, T_VP, T_U32, T_U32}},
    {"WSASocketW", T_SOCK, 6, 0, -1, {T_I32, T_I32, T_I32, T_VP, T_U32, T_U32}},
    {"socket", T_SOCK, 3, 0, -1, {T_I32, T_I32, T_I32}},
    {"connect", T_I32, 3, 0, -1, {T_SOCK, T_CVP, T_I32}},
    {"bind", T_I32, 3, 0, -1, {T_SOCK, T_CVP, T_I32}},
    {"listen", T_I32, 2, 0, -1, {T_SOCK, T_I32}},
    {"accept", T_SOCK, 3, 0, -1, {T_SOCK, T_VP, T_I32P}},
    {"send", T_I32, 4, 0, -1, {T_SOCK, T_CVP, T_I32, T_I32}},
    {"recv", T_I32, 4, 0, -1, {T_SOCK, T_VP, T_I32, T_I32}},
    {"sendto", T_I32, 6, 0, -1, {T_SOCK, T_CVP, T_I32, T_I32, T_CVP, T_I32}},
    {"recvfrom", T_I32, 6, 0, -1, {T_SOCK, T_VP, T_I32, T_I32, T_VP, T_I32P}},
    {"shutdown", T_I32, 2, 0, -1, {T_SOCK, T_I32}},
    {"closesocket", T_I32, 1, 0, -1, {T_SOCK}},
    {"setsockopt", T_I32, 5, 0, -1, {T_SOCK, T_I32, T_I32, T_CVP, T_I32}},
    {"getsockopt", T_I32, 5, 0, -1, {T_SOCK, T_I32, T_I32, T_VP, T_I32P}},
    {"select", T_I32, 5, 0, -1, {T_I32, T_VP, T_VP, T_VP, T_VP}},
    {"ioctlsocket", T_I32, 3, 0, -1, {T_SOCK, T_I32, T_U32P}},
    {"htons", T_U16, 1, 0, -1, {T_U16}},
    {"htonl", T_U32, 1, 0, -1, {T_U32}},
    {"ntohs", T_U16, 1, 0, -1, {T_U16}},
    {"ntohl", T_U32, 1, 0, -1, {T_U32}},
    {"inet_addr", T_U32, 1, 0, -1, {T_CSTR}},
    {"inet_ntoa", T_STR, 1, 0, -1, {T_U32}},
    {"inet_pton", T_I32, 3, 0, -1, {T_I32, T_CSTR, T_VP}},
    {"inet_ntop", T_CSTR, 4, 0, -1, {T_I32, T_CVP, T_STR, T_SZ}},
    {"gethostbyname", T_VP, 1, 0, -1, {T_CSTR}},
    {"getaddrinfo", T_I32, 4, 0, -1, {T_CSTR, T_CSTR, T_CVP, T_VPP}},
    {"freeaddrinfo", T_VOID, 1, 0, -1, {T_VP}},
    {"WinHttpOpen", T_HND, 5, 0, -1, {T_CWSTR, T_U32, T_CWSTR, T_CWSTR, T_U32}},
    {"WinHttpConnect", T_HND, 4, 0, -1, {T_HND, T_CWSTR, T_U16, T_U32}},
    {"WinHttpOpenRequest", T_HND, 7, 0, -1, {T_HND, T_CWSTR, T_CWSTR, T_CWSTR, T_CWSTR, T_VPP, T_U32}},
    {"WinHttpSendRequest", T_BOOL, 7, 0, -1, {T_HND, T_CWSTR, T_U32, T_VP, T_U32, T_U32, T_U64}},
    {"WinHttpReceiveResponse", T_BOOL, 2, 0, -1, {T_HND, T_VP}},
    {"WinHttpReadData", T_BOOL, 4, 0, -1, {T_HND, T_VP, T_U32, T_U32P}},
    {"WinHttpWriteData", T_BOOL, 4, 0, -1, {T_HND, T_CVP, T_U32, T_U32P}},
    {"WinHttpQueryHeaders", T_BOOL, 6, 0, -1, {T_HND, T_U32, T_CWSTR, T_VP, T_U32P, T_U32P}},
    {"WinHttpQueryDataAvailable", T_BOOL, 2, 0, -1, {T_HND, T_U32P}},
    {"WinHttpCloseHandle", T_BOOL, 1, 0, -1, {T_HND}},
    {"WinHttpSetOption", T_BOOL, 4, 0, -1, {T_HND, T_U32, T_VP, T_U32}},
    {"WinHttpAddRequestHeaders", T_BOOL, 4, 0, -1, {T_HND, T_CWSTR, T_U32, T_U32}},
    {"InternetOpenA", T_HND, 5, 0, -1, {T_CSTR, T_U32, T_CSTR, T_CSTR, T_U32}},
    {"InternetOpenW", T_HND, 5, 0, -1, {T_CWSTR, T_U32, T_CWSTR, T_CWSTR, T_U32}},
    {"InternetOpenUrlA", T_HND, 6, 0, -1, {T_HND, T_CSTR, T_CSTR, T_U32, T_U32, T_U64}},
    {"InternetOpenUrlW", T_HND, 6, 0, -1, {T_HND, T_CWSTR, T_CWSTR, T_U32, T_U32, T_U64}},
    {"InternetConnectA", T_HND, 8, 0, -1, {T_HND, T_CSTR, T_U16, T_CSTR, T_CSTR, T_U32, T_U32, T_U64}},
    {"InternetConnectW", T_HND, 8, 0, -1, {T_HND, T_CWSTR, T_U16, T_CWSTR, T_CWSTR, T_U32, T_U32, T_U64}},
    {"HttpOpenRequestA", T_HND, 8, 0, -1, {T_HND, T_CSTR, T_CSTR, T_CSTR, T_CSTR, T_STRP, T_U32, T_U64}},
    {"HttpOpenRequestW", T_HND, 8, 0, -1, {T_HND, T_CWSTR, T_CWSTR, T_CWSTR, T_CWSTR, T_VPP, T_U32, T_U64}},
    {"HttpSendRequestA", T_BOOL, 5, 0, -1, {T_HND, T_CSTR, T_U32, T_VP, T_U32}},
    {"HttpSendRequestW", T_BOOL, 5, 0, -1, {T_HND, T_CWSTR, T_U32, T_VP, T_U32}},
    {"InternetReadFile", T_BOOL, 4, 0, -1, {T_HND, T_VP, T_U32, T_U32P}},
    {"InternetWriteFile", T_BOOL, 4, 0, -1, {T_HND, T_CVP, T_U32, T_U32P}},
    {"InternetCloseHandle", T_BOOL, 1, 0, -1, {T_HND}},
    {"URLDownloadToFileA", T_I32, 5, 0, -1, {T_VP, T_CSTR, T_CSTR, T_U32, T_VP}},
    {"URLDownloadToFileW", T_I32, 5, 0, -1, {T_VP, T_CWSTR, T_CWSTR, T_U32, T_VP}},

    // CryptoAPI & CNG / BCrypt
    {"CryptAcquireContextA", T_BOOL, 5, 0, -1, {T_HNDP, T_CSTR, T_CSTR, T_U32, T_U32}},
    {"CryptAcquireContextW", T_BOOL, 5, 0, -1, {T_HNDP, T_CWSTR, T_CWSTR, T_U32, T_U32}},
    {"CryptReleaseContext", T_BOOL, 2, 0, -1, {T_HND, T_U32}},
    {"CryptCreateHash", T_BOOL, 5, 0, -1, {T_HND, T_U32, T_HND, T_U32, T_HNDP}},
    {"CryptHashData", T_BOOL, 4, 0, -1, {T_HND, T_CU8P, T_U32, T_U32}},
    {"CryptGetHashParam", T_BOOL, 5, 0, -1, {T_HND, T_U32, T_U8P, T_U32P, T_U32}},
    {"CryptDestroyHash", T_BOOL, 1, 0, -1, {T_HND}},
    {"CryptDeriveKey", T_BOOL, 5, 0, -1, {T_HND, T_U32, T_HND, T_U32, T_HNDP}},
    {"CryptImportKey", T_BOOL, 6, 0, -1, {T_HND, T_CU8P, T_U32, T_HND, T_U32, T_HNDP}},
    {"CryptEncrypt", T_BOOL, 7, 0, -1, {T_HND, T_HND, T_BOOL, T_U32, T_U8P, T_U32P, T_U32}},
    {"CryptDecrypt", T_BOOL, 6, 0, -1, {T_HND, T_HND, T_BOOL, T_U32, T_U8P, T_U32P}},
    {"CryptDestroyKey", T_BOOL, 1, 0, -1, {T_HND}},
    {"CryptGenRandom", T_BOOL, 3, 0, -1, {T_HND, T_U32, T_U8P}},
    {"CryptBinaryToStringA", T_BOOL, 5, 0, -1, {T_CU8P, T_U32, T_U32, T_STR, T_U32P}},
    {"CryptStringToBinaryA", T_BOOL, 7, 0, -1, {T_CSTR, T_U32, T_U32, T_U8P, T_U32P, T_U32P, T_U32P}},
    {"CryptProtectData", T_BOOL, 7, 0, -1, {T_VP, T_CWSTR, T_VP, T_VP, T_VP, T_U32, T_VP}},
    {"CryptUnprotectData", T_BOOL, 7, 0, -1, {T_VP, T_VPP, T_VP, T_VP, T_VP, T_U32, T_VP}},
    {"BCryptOpenAlgorithmProvider", T_I32, 4, 0, -1, {T_HNDP, T_CWSTR, T_CWSTR, T_U32}},
    {"BCryptCloseAlgorithmProvider", T_I32, 2, 0, -1, {T_HND, T_U32}},
    {"BCryptCreateHash", T_I32, 7, 0, -1, {T_HND, T_HNDP, T_U8P, T_U32, T_U8P, T_U32, T_U32}},
    {"BCryptHashData", T_I32, 4, 0, -1, {T_HND, T_U8P, T_U32, T_U32}},
    {"BCryptFinishHash", T_I32, 4, 0, -1, {T_HND, T_U8P, T_U32, T_U32}},
    {"BCryptDestroyHash", T_I32, 1, 0, -1, {T_HND}},
    {"BCryptGenerateSymmetricKey", T_I32, 7, 0, -1, {T_HND, T_HNDP, T_U8P, T_U32, T_U8P, T_U32, T_U32}},
    {"BCryptEncrypt", T_I32, 10, 0, -1, {T_HND, T_U8P, T_U32, T_VP, T_U8P, T_U32, T_U8P, T_U32, T_U32P, T_U32}},
    {"BCryptDecrypt", T_I32, 10, 0, -1, {T_HND, T_U8P, T_U32, T_VP, T_U8P, T_U32, T_U8P, T_U32, T_U32P, T_U32}},
    {"BCryptDestroyKey", T_I32, 1, 0, -1, {T_HND}},
    {"BCryptGenRandom", T_I32, 4, 0, -1, {T_HND, T_U8P, T_U32, T_U32}},

    // CRT Memory, Strings & Character Class
    {"malloc", T_VP, 1, 0, -1, {T_SZ}},
    {"calloc", T_VP, 2, 0, -1, {T_SZ, T_SZ}},
    {"realloc", T_VP, 2, 0, -1, {T_VP, T_SZ}},
    {"free", T_VOID, 1, 0, -1, {T_VP}},
    {"_aligned_malloc", T_VP, 2, 0, -1, {T_SZ, T_SZ}},
    {"_aligned_free", T_VOID, 1, 0, -1, {T_VP}},
    {"memcpy", T_VP, 3, 0, -1, {T_VP, T_CVP, T_SZ}},
    {"memcpy_s", T_I32, 4, 0, -1, {T_VP, T_SZ, T_CVP, T_SZ}},
    {"memmove", T_VP, 3, 0, -1, {T_VP, T_CVP, T_SZ}},
    {"memmove_s", T_I32, 4, 0, -1, {T_VP, T_SZ, T_CVP, T_SZ}},
    {"memset", T_VP, 3, 0, -1, {T_VP, T_I32, T_SZ}},
    {"memcmp", T_I32, 3, 0, -1, {T_CVP, T_CVP, T_SZ}},
    {"memchr", T_VP, 3, 0, -1, {T_CVP, T_I32, T_SZ}},
    {"strlen", T_SZ, 1, 0, -1, {T_CSTR}},
    {"strnlen", T_SZ, 2, 0, -1, {T_CSTR, T_SZ}},
    {"wcslen", T_SZ, 1, 0, -1, {T_CWSTR}},
    {"wcsnlen", T_SZ, 2, 0, -1, {T_CWSTR, T_SZ}},
    {"lstrlenA", T_I32, 1, 0, -1, {T_CSTR}},
    {"lstrlenW", T_I32, 1, 0, -1, {T_CWSTR}},
    {"strcmp", T_I32, 2, 0, -1, {T_CSTR, T_CSTR}},
    {"strncmp", T_I32, 3, 0, -1, {T_CSTR, T_CSTR, T_SZ}},
    {"stricmp", T_I32, 2, 0, -1, {T_CSTR, T_CSTR}},
    {"_stricmp", T_I32, 2, 0, -1, {T_CSTR, T_CSTR}},
    {"_strnicmp", T_I32, 3, 0, -1, {T_CSTR, T_CSTR, T_SZ}},
    {"strcasecmp", T_I32, 2, 0, -1, {T_CSTR, T_CSTR}},
    {"strncasecmp", T_I32, 3, 0, -1, {T_CSTR, T_CSTR, T_SZ}},
    {"wcscmp", T_I32, 2, 0, -1, {T_CWSTR, T_CWSTR}},
    {"wcsncmp", T_I32, 3, 0, -1, {T_CWSTR, T_CWSTR, T_SZ}},
    {"_wcsicmp", T_I32, 2, 0, -1, {T_CWSTR, T_CWSTR}},
    {"lstrcmpA", T_I32, 2, 0, -1, {T_CSTR, T_CSTR}},
    {"lstrcmpW", T_I32, 2, 0, -1, {T_CWSTR, T_CWSTR}},
    {"lstrcmpiA", T_I32, 2, 0, -1, {T_CSTR, T_CSTR}},
    {"lstrcmpiW", T_I32, 2, 0, -1, {T_CWSTR, T_CWSTR}},
    {"strcpy", T_STR, 2, 0, -1, {T_STR, T_CSTR}},
    {"strcpy_s", T_I32, 3, 0, -1, {T_STR, T_SZ, T_CSTR}},
    {"strncpy", T_STR, 3, 0, -1, {T_STR, T_CSTR, T_SZ}},
    {"strcat", T_STR, 2, 0, -1, {T_STR, T_CSTR}},
    {"strcat_s", T_I32, 3, 0, -1, {T_STR, T_SZ, T_CSTR}},
    {"strncat", T_STR, 3, 0, -1, {T_STR, T_CSTR, T_SZ}},
    {"wcscpy", T_WSTR, 2, 0, -1, {T_WSTR, T_CWSTR}},
    {"wcsncpy", T_WSTR, 3, 0, -1, {T_WSTR, T_CWSTR, T_SZ}},
    {"wcscat", T_WSTR, 2, 0, -1, {T_WSTR, T_CWSTR}},
    {"lstrcpyA", T_STR, 2, 0, -1, {T_STR, T_CSTR}},
    {"lstrcpyW", T_WSTR, 2, 0, -1, {T_WSTR, T_CWSTR}},
    {"lstrcatA", T_STR, 2, 0, -1, {T_STR, T_CSTR}},
    {"lstrcatW", T_WSTR, 2, 0, -1, {T_WSTR, T_CWSTR}},
    {"strchr", T_STR, 2, 0, -1, {T_CSTR, T_I32}},
    {"strrchr", T_STR, 2, 0, -1, {T_CSTR, T_I32}},
    {"strstr", T_STR, 2, 0, -1, {T_CSTR, T_CSTR}},
    {"strpbrk", T_STR, 2, 0, -1, {T_CSTR, T_CSTR}},
    {"strspn", T_SZ, 2, 0, -1, {T_CSTR, T_CSTR}},
    {"strcspn", T_SZ, 2, 0, -1, {T_CSTR, T_CSTR}},
    {"strtok", T_STR, 2, 0, -1, {T_STR, T_CSTR}},
    {"strtok_s", T_STR, 3, 0, -1, {T_STR, T_CSTR, T_STRP}},
    {"strdup", T_STR, 1, 0, -1, {T_CSTR}},
    {"_strdup", T_STR, 1, 0, -1, {T_CSTR}},
    {"wcschr", T_WSTR, 2, 0, -1, {T_CWSTR, T_WCHAR}},
    {"wcsrchr", T_WSTR, 2, 0, -1, {T_CWSTR, T_WCHAR}},
    {"wcsstr", T_WSTR, 2, 0, -1, {T_CWSTR, T_CWSTR}},
    {"_wcsdup", T_WSTR, 1, 0, -1, {T_CWSTR}},
    {"MultiByteToWideChar", T_I32, 6, 0, -1, {T_U32, T_U32, T_CSTR, T_I32, T_WSTR, T_I32}},
    {"WideCharToMultiByte", T_I32, 8, 0, -1, {T_U32, T_U32, T_CWSTR, T_I32, T_STR, T_I32, T_CSTR, T_I32P}},
    {"tolower", T_I32, 1, 0, -1, {T_I32}},
    {"toupper", T_I32, 1, 0, -1, {T_I32}},
    {"isalpha", T_I32, 1, 0, -1, {T_I32}},
    {"isdigit", T_I32, 1, 0, -1, {T_I32}},
    {"isalnum", T_I32, 1, 0, -1, {T_I32}},
    {"isspace", T_I32, 1, 0, -1, {T_I32}},
    {"isxdigit", T_I32, 1, 0, -1, {T_I32}},
    {"isprint", T_I32, 1, 0, -1, {T_I32}},

    // CRT Stdio, Formatting, Conversion & Utility
    {"printf", T_I32, 1, 1, 0, {T_CSTR}},
    {"printf_s", T_I32, 1, 1, 0, {T_CSTR}},
    {"fprintf", T_I32, 2, 1, 1, {T_FILEP, T_CSTR}},
    {"fprintf_s", T_I32, 2, 1, 1, {T_FILEP, T_CSTR}},
    {"sprintf", T_I32, 2, 1, 1, {T_STR, T_CSTR}},
    {"snprintf", T_I32, 3, 1, 2, {T_STR, T_SZ, T_CSTR}},
    {"_snprintf", T_I32, 3, 1, 2, {T_STR, T_SZ, T_CSTR}},
    {"sprintf_s", T_I32, 3, 1, 2, {T_STR, T_SZ, T_CSTR}},
    {"snprintf_s", T_I32, 3, 1, 2, {T_STR, T_SZ, T_CSTR}},
    {"_snprintf_s", T_I32, 4, 1, 3, {T_STR, T_SZ, T_SZ, T_CSTR}},
    {"__printf_chk", T_I32, 2, 1, 1, {T_I32, T_CSTR}},
    {"__fprintf_chk", T_I32, 3, 1, 2, {T_FILEP, T_I32, T_CSTR}},
    {"__sprintf_chk", T_I32, 4, 1, 3, {T_STR, T_I32, T_SZ, T_CSTR}},
    {"__snprintf_chk", T_I32, 5, 1, 4, {T_STR, T_SZ, T_I32, T_SZ, T_CSTR}},
    {"vprintf", T_I32, 2, 0, 0, {T_CSTR, T_VP}},
    {"vfprintf", T_I32, 3, 0, 1, {T_FILEP, T_CSTR, T_VP}},
    {"vsprintf", T_I32, 3, 0, 1, {T_STR, T_CSTR, T_VP}},
    {"vsnprintf", T_I32, 4, 0, 2, {T_STR, T_SZ, T_CSTR, T_VP}},
    {"_vsnprintf", T_I32, 4, 0, 2, {T_STR, T_SZ, T_CSTR, T_VP}},
    {"wprintf", T_I32, 1, 1, 0, {T_CWSTR}},
    {"wprintf_s", T_I32, 1, 1, 0, {T_CWSTR}},
    {"fwprintf", T_I32, 2, 1, 1, {T_FILEP, T_CWSTR}},
    {"fwprintf_s", T_I32, 2, 1, 1, {T_FILEP, T_CWSTR}},
    {"swprintf", T_I32, 3, 1, 2, {T_WSTR, T_SZ, T_CWSTR}},
    {"swprintf_s", T_I32, 3, 1, 2, {T_WSTR, T_SZ, T_CWSTR}},
    {"_snwprintf", T_I32, 3, 1, 2, {T_WSTR, T_SZ, T_CWSTR}},
    {"_snwprintf_s", T_I32, 4, 1, 3, {T_WSTR, T_SZ, T_SZ, T_CWSTR}},
    {"vswprintf", T_I32, 4, 0, 2, {T_WSTR, T_SZ, T_CWSTR, T_VP}},
    {"scanf", T_I32, 1, 1, 0, {T_CSTR}},
    {"scanf_s", T_I32, 1, 1, 0, {T_CSTR}},
    {"fscanf", T_I32, 2, 1, 1, {T_FILEP, T_CSTR}},
    {"fscanf_s", T_I32, 2, 1, 1, {T_FILEP, T_CSTR}},
    {"sscanf", T_I32, 2, 1, 1, {T_CSTR, T_CSTR}},
    {"sscanf_s", T_I32, 2, 1, 1, {T_CSTR, T_CSTR}},
    {"wscanf", T_I32, 1, 1, 0, {T_CWSTR}},
    {"swscanf", T_I32, 2, 1, 1, {T_CWSTR, T_CWSTR}},
    {"asprintf", T_I32, 2, 1, 1, {T_STRP, T_CSTR}},
    {"dprintf", T_I32, 2, 1, 1, {T_I32, T_CSTR}},
    {"syslog", T_VOID, 2, 1, 1, {T_I32, T_CSTR}},
    {"__stdio_common_vfprintf", T_I32, 5, 0, 2, {T_U64, T_FILEP, T_CSTR, T_VP, T_VP}},
    {"__stdio_common_vsprintf", T_I32, 6, 0, 3, {T_U64, T_STR, T_SZ, T_CSTR, T_VP, T_VP}},
    {"__stdio_common_vsprintf_s", T_I32, 6, 0, 3, {T_U64, T_STR, T_SZ, T_CSTR, T_VP, T_VP}},
    {"__stdio_common_vsnprintf_s", T_I32, 7, 0, 4, {T_U64, T_STR, T_SZ, T_SZ, T_CSTR, T_VP, T_VP}},
    {"__stdio_common_vswprintf", T_I32, 6, 0, 3, {T_U64, T_WSTR, T_SZ, T_CWSTR, T_VP, T_VP}},
    {"__stdio_common_vsscanf", T_I32, 6, 0, 3, {T_U64, T_CSTR, T_SZ, T_CSTR, T_VP, T_VP}},
    {"__acrt_iob_func", T_FILEP, 1, 0, -1, {T_U32}},
    {"puts", T_I32, 1, 0, -1, {T_CSTR}},
    {"fputs", T_I32, 2, 0, -1, {T_CSTR, T_FILEP}},
    {"putchar", T_I32, 1, 0, -1, {T_I32}},
    {"fputc", T_I32, 2, 0, -1, {T_I32, T_FILEP}},
    {"putc", T_I32, 2, 0, -1, {T_I32, T_FILEP}},
    {"getchar", T_I32, 0, 0, -1, {0}},
    {"fgetc", T_I32, 1, 0, -1, {T_FILEP}},
    {"getc", T_I32, 1, 0, -1, {T_FILEP}},
    {"ungetc", T_I32, 2, 0, -1, {T_I32, T_FILEP}},
    {"fgets", T_STR, 3, 0, -1, {T_STR, T_I32, T_FILEP}},
    {"fopen", T_FILEP, 2, 0, -1, {T_CSTR, T_CSTR}},
    {"fopen_s", T_I32, 3, 0, -1, {T_VPP, T_CSTR, T_CSTR}},
    {"_wfopen", T_FILEP, 2, 0, -1, {T_CWSTR, T_CWSTR}},
    {"freopen", T_FILEP, 3, 0, -1, {T_CSTR, T_CSTR, T_FILEP}},
    {"fdopen", T_FILEP, 2, 0, -1, {T_I32, T_CSTR}},
    {"fread", T_SZ, 4, 0, -1, {T_VP, T_SZ, T_SZ, T_FILEP}},
    {"fwrite", T_SZ, 4, 0, -1, {T_CVP, T_SZ, T_SZ, T_FILEP}},
    {"fclose", T_I32, 1, 0, -1, {T_FILEP}},
    {"fseek", T_I32, 3, 0, -1, {T_FILEP, T_I32, T_I32}},
    {"_fseeki64", T_I32, 3, 0, -1, {T_FILEP, T_I64, T_I32}},
    {"ftell", T_I32, 1, 0, -1, {T_FILEP}},
    {"_ftelli64", T_I64, 1, 0, -1, {T_FILEP}},
    {"rewind", T_VOID, 1, 0, -1, {T_FILEP}},
    {"fflush", T_I32, 1, 0, -1, {T_FILEP}},
    {"feof", T_I32, 1, 0, -1, {T_FILEP}},
    {"ferror", T_I32, 1, 0, -1, {T_FILEP}},
    {"clearerr", T_VOID, 1, 0, -1, {T_FILEP}},
    {"fileno", T_I32, 1, 0, -1, {T_FILEP}},
    {"remove", T_I32, 1, 0, -1, {T_CSTR}},
    {"rename", T_I32, 2, 0, -1, {T_CSTR, T_CSTR}},
    {"perror", T_VOID, 1, 0, -1, {T_CSTR}},
    {"atoi", T_I32, 1, 0, -1, {T_CSTR}},
    {"atol", T_I32, 1, 0, -1, {T_CSTR}},
    {"atoll", T_I64, 1, 0, -1, {T_CSTR}},
    {"atof", T_F64, 1, 0, -1, {T_CSTR}},
    {"strtol", T_I32, 3, 0, -1, {T_CSTR, T_STRP, T_I32}},
    {"strtoul", T_U32, 3, 0, -1, {T_CSTR, T_STRP, T_I32}},
    {"strtoll", T_I64, 3, 0, -1, {T_CSTR, T_STRP, T_I32}},
    {"strtoull", T_U64, 3, 0, -1, {T_CSTR, T_STRP, T_I32}},
    {"strtod", T_F64, 2, 0, -1, {T_CSTR, T_STRP}},
    {"strtof", T_F32, 2, 0, -1, {T_CSTR, T_STRP}},
    {"_wtoi", T_I32, 1, 0, -1, {T_CWSTR}},
    {"wcstol", T_I32, 3, 0, -1, {T_CWSTR, T_VPP, T_I32}},
    {"wcstoul", T_U32, 3, 0, -1, {T_CWSTR, T_VPP, T_I32}},
    {"qsort", T_VOID, 4, 0, -1, {T_VP, T_SZ, T_SZ, T_VP}},
    {"bsearch", T_VP, 5, 0, -1, {T_CVP, T_CVP, T_SZ, T_SZ, T_VP}},
    {"rand", T_I32, 0, 0, -1, {0}},
    {"srand", T_VOID, 1, 0, -1, {T_U32}},
    {"exit", T_VOID, 1, 0, -1, {T_I32}},
    {"_exit", T_VOID, 1, 0, -1, {T_I32}},
    {"abort", T_VOID, 0, 0, -1, {0}},
    {"atexit", T_I32, 1, 0, -1, {T_VP}},
    {"getenv", T_STR, 1, 0, -1, {T_CSTR}},
    {"system", T_I32, 1, 0, -1, {T_CSTR}},
    {"time", T_I64, 1, 0, -1, {T_I64P}},
    {"_time64", T_I64, 1, 0, -1, {T_I64P}},
    {"localtime", T_VP, 1, 0, -1, {T_I64P}},
    {"gmtime", T_VP, 1, 0, -1, {T_I64P}},
    {"strftime", T_SZ, 4, 0, -1, {T_STR, T_SZ, T_CSTR, T_CVP}},
    {"clock", T_I32, 0, 0, -1, {0}},
    {"difftime", T_F64, 2, 0, -1, {T_I64, T_I64}},

    // CRT Math
    {"sin", T_F64, 1, 0, -1, {T_F64}},
    {"cos", T_F64, 1, 0, -1, {T_F64}},
    {"tan", T_F64, 1, 0, -1, {T_F64}},
    {"asin", T_F64, 1, 0, -1, {T_F64}},
    {"acos", T_F64, 1, 0, -1, {T_F64}},
    {"atan", T_F64, 1, 0, -1, {T_F64}},
    {"atan2", T_F64, 2, 0, -1, {T_F64, T_F64}},
    {"sinh", T_F64, 1, 0, -1, {T_F64}},
    {"cosh", T_F64, 1, 0, -1, {T_F64}},
    {"tanh", T_F64, 1, 0, -1, {T_F64}},
    {"exp", T_F64, 1, 0, -1, {T_F64}},
    {"log", T_F64, 1, 0, -1, {T_F64}},
    {"log10", T_F64, 1, 0, -1, {T_F64}},
    {"log2", T_F64, 1, 0, -1, {T_F64}},
    {"pow", T_F64, 2, 0, -1, {T_F64, T_F64}},
    {"sqrt", T_F64, 1, 0, -1, {T_F64}},
    {"cbrt", T_F64, 1, 0, -1, {T_F64}},
    {"ceil", T_F64, 1, 0, -1, {T_F64}},
    {"floor", T_F64, 1, 0, -1, {T_F64}},
    {"round", T_F64, 1, 0, -1, {T_F64}},
    {"trunc", T_F64, 1, 0, -1, {T_F64}},
    {"fabs", T_F64, 1, 0, -1, {T_F64}},
    {"fmod", T_F64, 2, 0, -1, {T_F64, T_F64}},
    {"ldexp", T_F64, 2, 0, -1, {T_F64, T_I32}},
    {"frexp", T_F64, 2, 0, -1, {T_F64, T_I32P}},
    {"hypot", T_F64, 2, 0, -1, {T_F64, T_F64}},
    {"sinf", T_F32, 1, 0, -1, {T_F32}},
    {"cosf", T_F32, 1, 0, -1, {T_F32}},
    {"tanf", T_F32, 1, 0, -1, {T_F32}},
    {"expf", T_F32, 1, 0, -1, {T_F32}},
    {"logf", T_F32, 1, 0, -1, {T_F32}},
    {"powf", T_F32, 2, 0, -1, {T_F32, T_F32}},
    {"sqrtf", T_F32, 1, 0, -1, {T_F32}},
    {"ceilf", T_F32, 1, 0, -1, {T_F32}},
    {"floorf", T_F32, 1, 0, -1, {T_F32}},
    {"fabsf", T_F32, 1, 0, -1, {T_F32}},
    {"fmodf", T_F32, 2, 0, -1, {T_F32, T_F32}},

    // POSIX / Linux / macOS
    {"open", T_I32, 2, 1, -1, {T_CSTR, T_I32}},
    {"openat", T_I32, 3, 1, -1, {T_I32, T_CSTR, T_I32}},
    {"creat", T_I32, 2, 0, -1, {T_CSTR, T_U32}},
    {"read", T_I64, 3, 0, -1, {T_I32, T_VP, T_SZ}},
    {"write", T_I64, 3, 0, -1, {T_I32, T_CVP, T_SZ}},
    {"pread", T_I64, 4, 0, -1, {T_I32, T_VP, T_SZ, T_I64}},
    {"pwrite", T_I64, 4, 0, -1, {T_I32, T_CVP, T_SZ, T_I64}},
    {"close", T_I32, 1, 0, -1, {T_I32}},
    {"lseek", T_I64, 3, 0, -1, {T_I32, T_I64, T_I32}},
    {"stat", T_I32, 2, 0, -1, {T_CSTR, T_VP}},
    {"fstat", T_I32, 2, 0, -1, {T_I32, T_VP}},
    {"lstat", T_I32, 2, 0, -1, {T_CSTR, T_VP}},
    {"ioctl", T_I32, 2, 1, -1, {T_I32, T_U64}},
    {"fcntl", T_I32, 2, 1, -1, {T_I32, T_I32}},
    {"dup", T_I32, 1, 0, -1, {T_I32}},
    {"dup2", T_I32, 2, 0, -1, {T_I32, T_I32}},
    {"pipe", T_I32, 1, 0, -1, {T_I32P}},
    {"poll", T_I32, 3, 0, -1, {T_VP, T_U64, T_I32}},
    {"epoll_create1", T_I32, 1, 0, -1, {T_I32}},
    {"epoll_ctl", T_I32, 4, 0, -1, {T_I32, T_I32, T_I32, T_VP}},
    {"epoll_wait", T_I32, 4, 0, -1, {T_I32, T_VP, T_I32, T_I32}},
    {"mmap", T_VP, 6, 0, -1, {T_VP, T_SZ, T_I32, T_I32, T_I32, T_I64}},
    {"munmap", T_I32, 2, 0, -1, {T_VP, T_SZ}},
    {"mprotect", T_I32, 3, 0, -1, {T_VP, T_SZ, T_I32}},
    {"dlopen", T_VP, 2, 0, -1, {T_CSTR, T_I32}},
    {"dlsym", T_VP, 2, 0, -1, {T_VP, T_CSTR}},
    {"dlclose", T_I32, 1, 0, -1, {T_VP}},
    {"fork", T_I32, 0, 0, -1, {0}},
    {"execve", T_I32, 3, 0, -1, {T_CSTR, T_STRP, T_STRP}},
    {"execvp", T_I32, 2, 0, -1, {T_CSTR, T_STRP}},
    {"waitpid", T_I32, 3, 0, -1, {T_I32, T_I32P, T_I32}},
    {"kill", T_I32, 2, 0, -1, {T_I32, T_I32}},
    {"getpid", T_I32, 0, 0, -1, {0}},
    {"getppid", T_I32, 0, 0, -1, {0}},
    {"getuid", T_U32, 0, 0, -1, {0}},
    {"geteuid", T_U32, 0, 0, -1, {0}},
    {"setuid", T_I32, 1, 0, -1, {T_U32}},
    {"prctl", T_I32, 5, 0, -1, {T_I32, T_U64, T_U64, T_U64, T_U64}},
    {"ptrace", T_I64, 4, 0, -1, {T_I32, T_I32, T_VP, T_VP}},
    {"signal", T_VP, 2, 0, -1, {T_I32, T_VP}},
    {"sigaction", T_I32, 3, 0, -1, {T_I32, T_CVP, T_VP}},
    {"sleep", T_U32, 1, 0, -1, {T_U32}},
    {"usleep", T_I32, 1, 0, -1, {T_U32}},
    {"nanosleep", T_I32, 2, 0, -1, {T_CVP, T_VP}},
    {"pthread_create", T_I32, 4, 0, -1, {T_U64P, T_CVP, T_VP, T_VP}},
    {"pthread_join", T_I32, 2, 0, -1, {T_U64, T_VPP}},
    {"pthread_detach", T_I32, 1, 0, -1, {T_U64}},
    {"pthread_self", T_U64, 0, 0, -1, {0}},
    {"pthread_mutex_init", T_I32, 2, 0, -1, {T_VP, T_CVP}},
    {"pthread_mutex_lock", T_I32, 1, 0, -1, {T_VP}},
    {"pthread_mutex_unlock", T_I32, 1, 0, -1, {T_VP}},
    {"pthread_mutex_destroy", T_I32, 1, 0, -1, {T_VP}},

    // Runtime & Compiler Helpers
    {"__security_check_cookie", T_VOID, 1, 0, -1, {T_U64}},
    {"__stack_chk_fail", T_VOID, 0, 0, -1, {0}},
    {"__chkstk", T_VOID, 0, 0, -1, {0}},
    {"_chkstk", T_VOID, 0, 0, -1, {0}},
    {"_purecall", T_VOID, 0, 0, -1, {0}},
    {"__cxa_allocate_exception", T_VP, 1, 0, -1, {T_SZ}},
    {"__cxa_throw", T_VOID, 3, 0, -1, {T_VP, T_VP, T_VP}},
    {"__C_specific_handler", T_I32, 4, 0, -1, {T_VP, T_VP, T_VP, T_VP}}
};

static void ti_strip_sym(const char *sym, char *dst, size_t cap) {
    if (!sym || !sym[0]) {
        if (cap > 0) dst[0] = 0;
        return;
    }
    const char *p = sym;
    const char *bang = strchr(p, '!');
    if (bang) p = bang + 1;

    for (;;) {
        if (strncmp(p, "__imp_", 6) == 0) p += 6;
        else if (strncmp(p, "_imp_", 5) == 0) p += 5;
        else if (strncmp(p, "imp_", 4) == 0) p += 4;
        else if (strncmp(p, "j_", 2) == 0) p += 2;
        else if (strncmp(p, "__isoc99_", 9) == 0) p += 9;
        else if (strncmp(p, "__isoc23_", 9) == 0) p += 9;
        else if (strncmp(p, "_o_", 3) == 0) p += 3;
        else if (strncmp(p, "__wrap_", 7) == 0) p += 7;
        else if (strncmp(p, "__libc_", 7) == 0) p += 7;
        else break;
    }

    snprintf(dst, cap, "%s", p);
    char *at = strchr(dst, '@');
    if (at) *at = 0;
    char *dot = strstr(dst, ".plt");
    if (dot && dot[4] == 0) *dot = 0;
}

static const ti_api_ent *ti_find_api(const char *sym) {
    char clean[96];
    ti_strip_sym(sym, clean, sizeof(clean));
    if (!clean[0]) return NULL;

    size_t n = sizeof(ti_apis) / sizeof(ti_apis[0]);
    for (size_t i = 0; i < n; i++) {
        if (clean[0] == ti_apis[i].name[0] && strcmp(clean, ti_apis[i].name) == 0) return &ti_apis[i];
    }
    if (clean[0] == '_' && clean[1]) {
        for (size_t i = 0; i < n; i++) {
            if (clean[1] == ti_apis[i].name[0] && strcmp(clean + 1, ti_apis[i].name) == 0) return &ti_apis[i];
        }
    }
    if (clean[0] == 'Z' && clean[1] == 'w' && isupper((unsigned char)clean[2])) {
        clean[0] = 'N';
        clean[1] = 't';
        for (size_t i = 0; i < n; i++) {
            if (clean[0] == ti_apis[i].name[0] && strcmp(clean, ti_apis[i].name) == 0) return &ti_apis[i];
        }
    }
    return NULL;
}

static void ti_set_struct_arg(const typ_store *types, hl_callee_sig *sig, int idx, const char *sname) {
    if (!types || idx < 0 || idx >= HL_MAX_CALL_ARG) return;
    const typ_def *td = typ_find(types, sname);
    if (!td) return;
    memset(&sig->arg_ty[idx], 0, sizeof(sig->arg_ty[idx]));
    sig->arg_ty[idx].kind = HL_TY_STRUCT;
    sig->arg_ty[idx].ptr_depth = 1;
    snprintf(sig->arg_ty[idx].name, sizeof(sig->arg_ty[idx].name), "%s", td->name);
}

static void ti_fill_api_sig(const typ_store *types, const ti_api_ent *ent, uint64_t va, hl_callee_sig *out) {
    memset(out, 0, sizeof(*out));
    out->va = va;
    out->narg = (int)ent->narg;
    out->is_vararg = (int)ent->vararg;
    out->fmt_arg = (int)ent->fmt;
    out->ret_ty = ti_tcode_to_type(ent->ret);
    out->has_ret = (ent->ret != T_VOID) ? 1 : 0;

    int lim = out->narg < HL_MAX_CALL_ARG ? out->narg : HL_MAX_CALL_ARG;
    for (int i = 0; i < lim; i++) {
        out->arg_ty[i] = ti_tcode_to_type(ent->a[i]);
        if (ent->a[i] == T_F32 || ent->a[i] == T_F64) {
            if (i < 8) out->flt_mask |= (uint8_t)(1u << i);
        }
    }

    if (!types || types->ndef == 0) return;

    if (strcmp(ent->name, "InitializeCriticalSection") == 0 ||
        strcmp(ent->name, "InitializeCriticalSectionAndSpinCount") == 0 ||
        strcmp(ent->name, "EnterCriticalSection") == 0 ||
        strcmp(ent->name, "TryEnterCriticalSection") == 0 ||
        strcmp(ent->name, "LeaveCriticalSection") == 0 ||
        strcmp(ent->name, "DeleteCriticalSection") == 0) {
        ti_set_struct_arg(types, out, 0, "RTL_CRITICAL_SECTION");
    } else if (strcmp(ent->name, "GetSystemTime") == 0 || strcmp(ent->name, "GetLocalTime") == 0) {
        ti_set_struct_arg(types, out, 0, "SYSTEMTIME");
    } else if (strcmp(ent->name, "QueryPerformanceCounter") == 0 || strcmp(ent->name, "QueryPerformanceFrequency") == 0) {
        ti_set_struct_arg(types, out, 0, "LARGE_INTEGER");
    } else if (strcmp(ent->name, "GetFileSizeEx") == 0) {
        ti_set_struct_arg(types, out, 1, "LARGE_INTEGER");
    } else if (strcmp(ent->name, "RtlInitUnicodeString") == 0 || strcmp(ent->name, "RtlFreeUnicodeString") == 0) {
        ti_set_struct_arg(types, out, 0, "UNICODE_STRING");
    } else if (strcmp(ent->name, "nanosleep") == 0) {
        ti_set_struct_arg(types, out, 0, "timespec");
        ti_set_struct_arg(types, out, 1, "timespec");
    }
}

static void ti_trim(char *s) {
    char *p = s;
    while (*p == ' ' || *p == '\t') p++;
    if (p != s) memmove(s, p, strlen(p) + 1);
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\t')) s[--n] = 0;
}

static int ti_split_ops(const char *ops, char out[][76], int max_ops) {
    for (int i = 0; i < max_ops; i++) out[i][0] = 0;
    if (!ops || !ops[0]) return 0;

    int cnt = 0;
    int depth = 0;
    const char *start = ops;
    for (const char *p = ops; ; p++) {
        if (*p == '[') depth++;
        else if (*p == ']' && depth > 0) depth--;
        if ((*p == ',' && depth == 0) || *p == 0) {
            if (cnt < max_ops) {
                size_t len = (size_t)(p - start);
                if (len >= 75) len = 75;
                memcpy(out[cnt], start, len);
                out[cnt][len] = 0;
                ti_trim(out[cnt]);
                cnt++;
            }
            if (*p == 0) break;
            start = p + 1;
        }
    }
    return cnt;
}

static int ti_parse_x86_reg(const char *s, int *bits, int *is_xmm) {
    *bits = 64;
    *is_xmm = 0;
    if (!s || !s[0]) return -1;
    if ((s[0] == 'x' || s[0] == 'y' || s[0] == 'z') && s[1] == 'm' && s[2] == 'm' && isdigit((unsigned char)s[3])) {
        char *end = NULL;
        long idx = strtol(s + 3, &end, 10);
        if (end && *end == 0 && idx >= 0 && idx < 32) {
            *is_xmm = 1;
            *bits = (s[0] == 'z') ? 512 : (s[0] == 'y') ? 256 : 128;
            return (int)idx;
        }
    }
    static const char *const r64[16] = {"rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi","r8","r9","r10","r11","r12","r13","r14","r15"};
    static const char *const r32[16] = {"eax","ecx","edx","ebx","esp","ebp","esi","edi","r8d","r9d","r10d","r11d","r12d","r13d","r14d","r15d"};
    static const char *const r16[16] = {"ax","cx","dx","bx","sp","bp","si","di","r8w","r9w","r10w","r11w","r12w","r13w","r14w","r15w"};
    static const char *const r8a[16] = {"al","cl","dl","bl","spl","bpl","sil","dil","r8b","r9b","r10b","r11b","r12b","r13b","r14b","r15b"};
    static const char *const r8h[4]  = {"ah","ch","dh","bh"};
    for (int i = 0; i < 16; i++) {
        if (strcmp(s, r64[i]) == 0) { *bits = 64; return i; }
        if (strcmp(s, r32[i]) == 0) { *bits = 32; return i; }
        if (strcmp(s, r16[i]) == 0) { *bits = 16; return i; }
        if (strcmp(s, r8a[i]) == 0) { *bits = 8; return i; }
    }
    for (int i = 0; i < 4; i++) {
        if (strcmp(s, r8h[i]) == 0) { *bits = 8; return i; }
    }
    return -1;
}

static int ti_parse_a64_reg(const char *s, int *bits, int *is_flt, int *is_zr) {
    *bits = 64;
    *is_flt = 0;
    *is_zr = 0;
    if (!s || !s[0]) return -1;
    if (strcmp(s, "sp") == 0)  { *bits = 64; return 31; }
    if (strcmp(s, "wsp") == 0) { *bits = 32; return 31; }
    if (strcmp(s, "xzr") == 0) { *bits = 64; *is_zr = 1; return 31; }
    if (strcmp(s, "wzr") == 0) { *bits = 32; *is_zr = 1; return 31; }
    if (strcmp(s, "fp") == 0)  { *bits = 64; return 29; }
    if (strcmp(s, "lr") == 0)  { *bits = 64; return 30; }
    if ((s[0] == 'x' || s[0] == 'w') && isdigit((unsigned char)s[1])) {
        char *end = NULL;
        long r = strtol(s + 1, &end, 10);
        if (end && *end == 0 && r >= 0 && r <= 30) {
            *bits = (s[0] == 'x') ? 64 : 32;
            return (int)r;
        }
    }
    if ((s[0] == 'v' || s[0] == 'd' || s[0] == 's' || s[0] == 'q') && isdigit((unsigned char)s[1])) {
        char *end = NULL;
        long r = strtol(s + 1, &end, 10);
        if (end && *end == 0 && r >= 0 && r <= 31) {
            *is_flt = 1;
            *bits = (s[0] == 's') ? 32 : (s[0] == 'd') ? 64 : 128;
            return (int)r;
        }
    }
    return -1;
}

static void ti_scan_x86_mem_regs(const char *raw, uint32_t *gpr_reads, int *ebp_arg_max) {
    const char *lb = strchr(raw, '[');
    if (!lb) return;
    char in[64];
    snprintf(in, sizeof(in), "%s", lb + 1);
    char *rb = strchr(in, ']');
    if (rb) *rb = 0;

    int has_ebp = 0;
    int64_t disp = 0;
    int sign = 1;
    char *cur = in;
    while (*cur) {
        if (*cur == '+') { sign = 1; cur++; continue; }
        if (*cur == '-') { sign = -1; cur++; continue; }
        if (*cur == ' ' || *cur == '\t') { cur++; continue; }
        char tok[32];
        int k = 0;
        while (*cur && *cur != '+' && *cur != '-' && k < 31) tok[k++] = *cur++;
        tok[k] = 0;
        ti_trim(tok);
        char *star = strchr(tok, '*');
        if (star) *star = 0;
        ti_trim(tok);
        if (strncmp(tok, "0x", 2) == 0 || isdigit((unsigned char)tok[0])) {
            uint64_t v = (strncmp(tok, "0x", 2) == 0) ? strtoull(tok + 2, NULL, 16) : strtoull(tok, NULL, 10);
            disp += sign * (int64_t)v;
        } else {
            int b = 0, xm = 0;
            int r = ti_parse_x86_reg(tok, &b, &xm);
            if (r >= 0 && !xm) {
                *gpr_reads |= (1u << r);
                if (r == 5 && !star) has_ebp = 1;
            }
        }
    }
    if (ebp_arg_max && has_ebp && disp >= 8 && disp < 0x38 && (disp & 3) == 0) {
        int idx = (int)((disp - 8) / 4);
        if (idx > *ebp_arg_max) *ebp_arg_max = idx;
    }
}

typedef struct {
    uint64_t va;
    uint32_t gpr_def;
    uint32_t xmm_def;
    int      ret_gpr;
    int      ret_flt;
    int      last_ret_kind; /* 0 = none, 1 = gpr, 2 = flt */
    int      last_ret_bits;
    int      unk_call_ret;
} ti_scan_blk;

static bool ti_is_x86_scalar_fp_write(const char *m, int *out_bits) {
    if (!m || !m[0]) return false;
    const char *s = (m[0] == 'v') ? (m + 1) : m;
    if (strcmp(s, "movss") == 0 || strcmp(s, "addss") == 0 || strcmp(s, "subss") == 0 ||
        strcmp(s, "mulss") == 0 || strcmp(s, "divss") == 0 || strcmp(s, "sqrtss") == 0 ||
        strcmp(s, "minss") == 0 || strcmp(s, "maxss") == 0 || strcmp(s, "rcpss") == 0 ||
        strcmp(s, "rsqrtss") == 0 || strcmp(s, "roundss") == 0 ||
        strcmp(s, "cvtsi2ss") == 0 || strcmp(s, "cvtsd2ss") == 0) {
        if (out_bits) *out_bits = 32;
        return true;
    }
    if (strcmp(s, "movsd") == 0 || strcmp(s, "addsd") == 0 || strcmp(s, "subsd") == 0 ||
        strcmp(s, "mulsd") == 0 || strcmp(s, "divsd") == 0 || strcmp(s, "sqrtsd") == 0 ||
        strcmp(s, "minsd") == 0 || strcmp(s, "maxsd") == 0 || strcmp(s, "roundsd") == 0 ||
        strcmp(s, "cvtsi2sd") == 0 || strcmp(s, "cvtss2sd") == 0) {
        if (out_bits) *out_bits = 64;
        return true;
    }
    if (strncmp(s, "fmadd", 5) == 0 || strncmp(s, "fmsub", 5) == 0 ||
        strncmp(s, "fnmadd", 6) == 0 || strncmp(s, "fnmsub", 6) == 0) {
        size_t len = strlen(s);
        if (len >= 7 && s[len - 2] == 's' && s[len - 1] == 's') {
            if (out_bits) *out_bits = 32;
            return true;
        }
        if (len >= 7 && s[len - 2] == 's' && s[len - 1] == 'd') {
            if (out_bits) *out_bits = 64;
            return true;
        }
    }
    return false;
}

static bool ti_is_x86_vec_store_mnem(const char *m) {
    if (!m || !m[0]) return false;
    const char *s = (m[0] == 'v') ? (m + 1) : m;
    return strcmp(s, "movups") == 0 || strcmp(s, "movaps") == 0 ||
           strcmp(s, "movupd") == 0 || strcmp(s, "movapd") == 0 ||
           strcmp(s, "movdqu") == 0 || strcmp(s, "movdqa") == 0;
}

static bool ti_is_x86_pure_write(const char *m) {
    if (strcmp(m, "mov") == 0 || strcmp(m, "movzx") == 0 || strcmp(m, "movsx") == 0 ||
        strcmp(m, "movsxd") == 0 || strcmp(m, "lea") == 0 || strcmp(m, "pop") == 0 ||
        strcmp(m, "movaps") == 0 || strcmp(m, "movups") == 0 || strcmp(m, "movdqa") == 0 ||
        strcmp(m, "movdqu") == 0 || strcmp(m, "movss") == 0 || strcmp(m, "movsd") == 0 ||
        strcmp(m, "movd") == 0 || strcmp(m, "movq") == 0 || strcmp(m, "movabs") == 0 ||
        strcmp(m, "cvtsi2sd") == 0 || strcmp(m, "cvtsi2ss") == 0 ||
        strcmp(m, "cvtsd2si") == 0 || strcmp(m, "cvtss2si") == 0 ||
        strcmp(m, "cvttsd2si") == 0 || strcmp(m, "cvttss2si") == 0 ||
        strcmp(m, "cvtsd2ss") == 0 || strcmp(m, "cvtss2sd") == 0 ||
        strcmp(m, "popcnt") == 0 || strcmp(m, "lzcnt") == 0 || strcmp(m, "tzcnt") == 0 ||
        strcmp(m, "bsf") == 0 || strcmp(m, "bsr") == 0) {
        return true;
    }
    if (strncmp(m, "set", 3) == 0 || strncmp(m, "vmov", 4) == 0 || strncmp(m, "vcvt", 4) == 0) return true;
    return false;
}

static bool ti_is_x86_readonly(const char *m) {
    if (strcmp(m, "cmp") == 0 || strcmp(m, "test") == 0 || strcmp(m, "push") == 0 ||
        strcmp(m, "bt") == 0 || strcmp(m, "ucomiss") == 0 || strcmp(m, "ucomisd") == 0 ||
        strcmp(m, "comiss") == 0 || strcmp(m, "comisd") == 0 ||
        strcmp(m, "vucomiss") == 0 || strcmp(m, "vucomisd") == 0) {
        return true;
    }
    return false;
}

static bool ti_is_xmm0_vec_store_soon(const ana_ctx *a, bin_arch arch, uint64_t next_ip) {
    uint64_t cur = next_ip;
    for (int step = 0; step < 3; step++) {
        size_t nav = 0;
        const uint8_t *np = bin_ptr(&a->bin, cur, &nav);
        if (!np || nav < 1) break;
        x86_ins nxt;
        int nlen = arch_decode(arch, np, nav, cur, 1, 0, &nxt);
        if (nlen <= 0 || nxt.flow != X86_FLOW_NONE) break;
        char nops_s[4][76];
        int nn = ti_split_ops(nxt.ops, nops_s, 4);
        if (nn >= 2 && ti_is_x86_vec_store_mnem(nxt.mnem) && strchr(nops_s[0], '[') != NULL) {
            int b = 0, xm = 0;
            int r = ti_parse_x86_reg(nops_s[1], &b, &xm);
            if (xm && r == 0) return true;
        }
        if (nn >= 1 && strchr(nops_s[0], '[') == NULL && !ti_is_x86_readonly(nxt.mnem)) {
            int b = 0, xm = 0;
            int r = ti_parse_x86_reg(nops_s[0], &b, &xm);
            if (xm && r == 0) break;
        }
        cur += (uint64_t)nlen;
    }
    return false;
}

static bool ti_is_x86_self_zero(const char *m, int nops, const char ops[][76]) {
    if (nops == 2 && strcmp(ops[0], ops[1]) == 0) {
        if (strcmp(m, "xor") == 0 || strcmp(m, "sub") == 0 || strcmp(m, "pxor") == 0 ||
            strcmp(m, "xorps") == 0 || strcmp(m, "xorpd") == 0) {
            return true;
        }
    }
    if (nops == 3 && strcmp(ops[1], ops[2]) == 0) {
        if (strcmp(m, "vpxor") == 0 || strcmp(m, "vxorps") == 0 || strcmp(m, "vxorpd") == 0) return true;
    }
    return false;
}

static bool ti_analyze_callee_a64(const ana_ctx *a, uint64_t start_va, hl_callee_sig *out) {
    uint32_t gpr_live = 0, flt_live = 0;
    int ret_gpr_max = 0, ret_flt_max = 0;
    int ret_last_gpr = 0, ret_last_flt = 0;
    int saw_ret = 0, unk_call_ret_seen = 0;

    ti_scan_blk work[2];
    memset(work, 0, sizeof(work));
    work[0].va = start_va;
    int nwork = 1;
    int budget = 48;

    for (int wi = 0; wi < nwork && budget > 0; wi++) {
        uint64_t ip = work[wi].va;
        uint32_t gpr_def = work[wi].gpr_def;
        uint32_t flt_def = work[wi].xmm_def;
        int ret_gpr = work[wi].ret_gpr;
        int ret_flt = work[wi].ret_flt;
        int last_ret_kind = work[wi].last_ret_kind;
        int last_ret_bits = work[wi].last_ret_bits;
        int unk_call_ret = work[wi].unk_call_ret;

        while (budget > ((wi == 0 && nwork == 2) ? 12 : 0)) {
            size_t avail = 0;
            const uint8_t *code = bin_ptr(&a->bin, ip, &avail);
            if (!code || avail < 4) break;
            x86_ins ins;
            int len = arch_decode(a->bin.arch, code, avail, ip, 1, 0, &ins);
            if (len <= 0) break;
            budget--;

            char ops[4][76];
            int nops = ti_split_ops(ins.ops, ops, 4);

            if (ins.flow == X86_FLOW_RET) {
                saw_ret = 1;
                if (ret_gpr > ret_gpr_max) ret_gpr_max = ret_gpr;
                if (ret_flt > ret_flt_max) ret_flt_max = ret_flt;
                if (last_ret_kind == 2 && last_ret_bits > ret_last_flt) ret_last_flt = last_ret_bits;
                else if (last_ret_kind == 1 && last_ret_bits > ret_last_gpr) ret_last_gpr = last_ret_bits;
                if (unk_call_ret) unk_call_ret_seen = 1;
                break;
            }
            if (ins.flow == X86_FLOW_TRAP) break;

            if (ins.flow == X86_FLOW_JCC) {
                if ((strcmp(ins.mnem, "cbz") == 0 || strcmp(ins.mnem, "cbnz") == 0 ||
                     strcmp(ins.mnem, "tbz") == 0 || strcmp(ins.mnem, "tbnz") == 0) && nops >= 1) {
                    int b = 0, fl = 0, zr = 0;
                    int r = ti_parse_a64_reg(ops[0], &b, &fl, &zr);
                    if (r >= 0 && !zr && !fl && !(gpr_def & (1u << r))) gpr_live |= (1u << r);
                }
                if (nwork < 2 && ins.has_target && ins.target > start_va && ins.target < start_va + 0x1000 &&
                    bin_is_exec(&a->bin, ins.target)) {
                    work[1].va = ins.target;
                    work[1].gpr_def = gpr_def;
                    work[1].xmm_def = flt_def;
                    work[1].ret_gpr = ret_gpr;
                    work[1].ret_flt = ret_flt;
                    work[1].last_ret_kind = last_ret_kind;
                    work[1].last_ret_bits = last_ret_bits;
                    work[1].unk_call_ret = unk_call_ret;
                    nwork = 2;
                }
                ip += (uint64_t)len;
                continue;
            }

            if (ins.flow == X86_FLOW_JMP) {
                if (ins.has_target && !ins.target_mem && ins.target > ip && ins.target < start_va + 0x1000 &&
                    bin_is_exec(&a->bin, ins.target)) {
                    ip = ins.target;
                    continue;
                }
                break;
            }

            if (ins.flow == X86_FLOW_CALL) {
                if (nops >= 1 && !ins.has_target) {
                    int b = 0, fl = 0, zr = 0;
                    int r = ti_parse_a64_reg(ops[0], &b, &fl, &zr);
                    if (r >= 0 && !zr && !fl && !(gpr_def & (1u << r))) gpr_live |= (1u << r);
                }
                const ti_api_ent *api = (ins.has_target && ana_sym_at(a, ins.target)) ? ti_find_api(ana_sym_at(a, ins.target)) : NULL;
                if (api) {
                    int lim = api->narg < 8 ? api->narg : 8;
                    int gi = 0, fi = 0;
                    for (int k = 0; k < lim; k++) {
                        if (api->a[k] == T_F32 || api->a[k] == T_F64) {
                            if (fi < 8 && !(flt_def & (1u << fi))) flt_live |= (1u << fi);
                            fi++;
                        } else {
                            if (gi < 8 && !(gpr_def & (1u << gi))) gpr_live |= (1u << gi);
                            gi++;
                        }
                    }
                    if (api->ret == T_F32) { ret_flt = 32; last_ret_kind = 2; last_ret_bits = 32; unk_call_ret = 0; }
                    else if (api->ret == T_F64) { ret_flt = 64; last_ret_kind = 2; last_ret_bits = 64; unk_call_ret = 0; }
                    else if (api->ret != T_VOID) { ret_gpr = 64; last_ret_kind = 1; last_ret_bits = 64; unk_call_ret = 0; }
                    else { last_ret_kind = 0; last_ret_bits = 0; unk_call_ret = 0; }
                } else {
                    last_ret_kind = 0;
                    last_ret_bits = 0;
                    unk_call_ret = 1;
                }
                // caller-saved x0..x18 and v0..v7
                gpr_def |= 0x0007FFFFu;
                flt_def |= 0x000000FFu;
                ip += (uint64_t)len;
                continue;
            }

            int is_store = (strncmp(ins.mnem, "str", 3) == 0 || strcmp(ins.mnem, "stp") == 0);
            int is_ro = (strcmp(ins.mnem, "cmp") == 0 || strcmp(ins.mnem, "cmn") == 0 ||
                         strcmp(ins.mnem, "tst") == 0 || strcmp(ins.mnem, "fcmp") == 0);
            int is_ldp = (strcmp(ins.mnem, "ldp") == 0);
            int is_movk = (strcmp(ins.mnem, "movk") == 0);

            int read_start = (is_store || is_ro || is_movk) ? 0 : (is_ldp ? 2 : 1);
            for (int k = read_start; k < nops; k++) {
                if (ops[k][0] == '[') {
                    char in[64];
                    snprintf(in, sizeof(in), "%s", ops[k] + 1);
                    char *rb = strchr(in, ']');
                    if (rb) *rb = 0;
                    char mops[3][76];
                    int nm = ti_split_ops(in, mops, 3);
                    for (int mi = 0; mi < nm; mi++) {
                        int b = 0, fl = 0, zr = 0;
                        int r = ti_parse_a64_reg(mops[mi], &b, &fl, &zr);
                        if (r >= 0 && !zr && !fl && !(gpr_def & (1u << r))) gpr_live |= (1u << r);
                    }
                } else {
                    int b = 0, fl = 0, zr = 0;
                    int r = ti_parse_a64_reg(ops[k], &b, &fl, &zr);
                    if (r >= 0 && !zr) {
                        if (fl) { if (!(flt_def & (1u << r))) flt_live |= (1u << r); }
                        else { if (!(gpr_def & (1u << r))) gpr_live |= (1u << r); }
                    }
                }
            }

            if (!is_store && !is_ro && nops >= 1) {
                int ndef = is_ldp ? 2 : 1;
                for (int d = 0; d < ndef && d < nops; d++) {
                    int b = 0, fl = 0, zr = 0;
                    int r = ti_parse_a64_reg(ops[d], &b, &fl, &zr);
                    if (r >= 0 && !zr) {
                        if (fl) {
                            flt_def |= (1u << r);
                            if (r == 0) {
                                int fb = (b == 32) ? 32 : 64;
                                ret_flt = fb;
                                last_ret_kind = 2;
                                last_ret_bits = fb;
                                unk_call_ret = 0;
                            }
                        } else {
                            gpr_def |= (1u << r);
                            if (r == 0) {
                                ret_gpr = b;
                                last_ret_kind = 1;
                                last_ret_bits = b;
                                unk_call_ret = 0;
                            }
                        }
                    }
                }
            }

            ip += (uint64_t)len;
        }
    }

    int max_int = -1, max_flt = -1;
    for (int i = 0; i < 8; i++) {
        if (gpr_live & (1u << i)) max_int = i;
        if (flt_live & (1u << i)) max_flt = i;
    }

    int narg = (max_int + 1);
    if (max_flt + 1 > narg) narg = max_flt + 1;
    if (narg > HL_MAX_CALL_ARG) narg = HL_MAX_CALL_ARG;
    out->narg = narg;
    for (int i = 0; i < 8 && i < narg; i++) {
        if ((flt_live & (1u << i)) && !(gpr_live & (1u << i))) {
            out->flt_mask |= (uint8_t)(1u << i);
            out->arg_ty[i] = ti_make_ty(HL_TY_F64, 0, 0, 64);
        }
    }

    if (!saw_ret || unk_call_ret_seen) {
        out->has_ret = 1;
        out->ret_ty = ti_make_ty(HL_TY_I64, 0, 0, 64);
    } else if (ret_last_flt > 0) {
        out->has_ret = 1;
        out->ret_ty = ti_make_ty(ret_last_flt == 32 ? HL_TY_F32 : HL_TY_F64, 0, 0, (uint8_t)ret_last_flt);
    } else if (ret_last_gpr > 0) {
        out->has_ret = 1;
        out->ret_ty = ti_make_ty(ret_last_gpr == 32 ? HL_TY_I32 : HL_TY_I64, 0, 0, (uint8_t)ret_last_gpr);
    } else if (ret_flt_max > 0) {
        out->has_ret = 1;
        out->ret_ty = ti_make_ty(ret_flt_max == 32 ? HL_TY_F32 : HL_TY_F64, 0, 0, (uint8_t)ret_flt_max);
    } else if (ret_gpr_max > 0) {
        out->has_ret = 1;
        out->ret_ty = ti_make_ty(ret_gpr_max == 32 ? HL_TY_I32 : HL_TY_I64, 0, 0, (uint8_t)ret_gpr_max);
    } else {
        out->has_ret = 0;
        out->ret_ty = ti_make_ty(HL_TY_VOID, 0, 0, 0);
    }
    return true;
}

static int ti_parse_rsp_disp(const char *op, int64_t *out_disp) {
    if (!op || !out_disp) return 0;
    const char *lb = strchr(op, '[');
    const char *rb = lb ? strchr(lb, ']') : NULL;
    if (!lb || !rb) return 0;
    const char *p = lb + 1;
    while (p < rb && (*p == ' ' || *p == '\t')) p++;
    if ((size_t)(rb - p) < 3 || strncmp(p, "rsp", 3) != 0) return 0;
    p += 3;
    while (p < rb && (*p == ' ' || *p == '\t')) p++;
    if (p == rb) {
        *out_disp = 0;
        return 1;
    }
    int sign = 1;
    if (*p == '+') { sign = 1; p++; }
    else if (*p == '-') { sign = -1; p++; }
    else return 0;
    while (p < rb && (*p == ' ' || *p == '\t')) p++;
    if (p >= rb || !isxdigit((unsigned char)*p)) return 0;
    char *endp = NULL;
    uint64_t v = (p + 1 < rb && p[0] == '0' && (p[1] == 'x' || p[1] == 'X'))
                 ? strtoull(p + 2, &endp, 16)
                 : strtoull(p, &endp, 10);
    if (!endp || endp == p) return 0;
    while (endp < rb && (*endp == ' ' || *endp == '\t')) endp++;
    if (endp != rb) return 0;
    *out_disp = sign * (int64_t)v;
    return 1;
}

static bool ti_analyze_callee(const ana_ctx *a, const typ_store *types, uint64_t va, hl_callee_sig *out) {
    if (!a || !va || !bin_is_exec(&a->bin, va)) return false;

    bin_arch arch = a->bin.arch;
    if (arch != BIN_ARCH_X64 && arch != BIN_ARCH_X86 && arch != BIN_ARCH_ARM64) return false;

    // follow up to 2 direct jmp thunks (incremental link / plt / iat stubs)
    uint64_t cur_va = va;
    for (int hop = 0; hop < 2; hop++) {
        size_t avail = 0;
        const uint8_t *code = bin_ptr(&a->bin, cur_va, &avail);
        if (!code || avail < 1) return false;
        x86_ins ins;
        int len = arch_decode(arch, code, avail, cur_va, 1, 0, &ins);
        if (len <= 0) return false;
        if (ins.flow == X86_FLOW_JMP && ins.has_target) {
            const char *tsym = ana_sym_at(a, ins.target);
            if (tsym) {
                const ti_api_ent *api = ti_find_api(tsym);
                if (api) {
                    ti_fill_api_sig(types, api, va, out);
                    return true;
                }
            }
            if (!ins.target_mem && bin_is_exec(&a->bin, ins.target) && ins.target != cur_va) {
                cur_va = ins.target;
                continue;
            }
            if (ins.target_mem) return false;
        }
        break;
    }

    if (arch == BIN_ARCH_ARM64) return ti_analyze_callee_a64(a, cur_va, out);

    int is_x86_32 = (arch == BIN_ARCH_X86 || a->bin.bits == 32);
    int is_win64 = (!is_x86_32 && (a->bin.fmt == BIN_PE64 || a->bin.fmt == BIN_RAW));
    static const int win64_args[4] = {1, 2, 8, 9};
    static const int sysv_args[6]  = {7, 6, 2, 1, 8, 9};
    const int *abi_args = is_win64 ? win64_args : sysv_args;
    int nabi = is_x86_32 ? 0 : (is_win64 ? 4 : 6);
    uint32_t caller_saved_gpr = is_x86_32 ? 0x0007u : (is_win64 ? 0x0F07u : 0x0FC7u);
    uint32_t caller_saved_xmm = is_x86_32 ? 0x00FFu : (is_win64 ? 0x003Fu : 0x00FFu);

    uint32_t gpr_live = 0, xmm_live = 0;
    uint8_t  xmm_f32 = 0;
    int ret_gpr_max = 0, ret_flt_max = 0;
    int ret_last_gpr = 0, ret_last_flt = 0;
    int saw_ret = 0, unk_call_ret_seen = 0;
    int stdcall_narg = -1;
    int ebp_arg_max = -1;
    uint8_t win64_home_mask = 0;
    int win64_va_start_idx = -1;

    ti_scan_blk work[2];
    memset(work, 0, sizeof(work));
    work[0].va = cur_va;
    int nwork = 1;
    int budget = 48;

    for (int wi = 0; wi < nwork && budget > 0; wi++) {
        uint64_t ip = work[wi].va;
        uint32_t gpr_def = work[wi].gpr_def;
        uint32_t xmm_def = work[wi].xmm_def;
        int ret_gpr = work[wi].ret_gpr;
        int ret_flt = work[wi].ret_flt;
        int last_ret_kind = work[wi].last_ret_kind;
        int last_ret_bits = work[wi].last_ret_bits;
        int unk_call_ret = work[wi].unk_call_ret;
        int64_t sp_off = 0;

        while (budget > ((wi == 0 && nwork == 2) ? 12 : 0)) {
            size_t avail = 0;
            const uint8_t *code = bin_ptr(&a->bin, ip, &avail);
            if (!code || avail < 1) break;
            x86_ins ins;
            int len = arch_decode(arch, code, avail, ip, 1, 0, &ins);
            if (len <= 0) break;
            budget--;

            if (ins.flow == X86_FLOW_RET) {
                saw_ret = 1;
                if (ret_gpr > ret_gpr_max) ret_gpr_max = ret_gpr;
                if (ret_flt > ret_flt_max) ret_flt_max = ret_flt;
                if (last_ret_kind == 2 && last_ret_bits > ret_last_flt) ret_last_flt = last_ret_bits;
                else if (last_ret_kind == 1 && last_ret_bits > ret_last_gpr) ret_last_gpr = last_ret_bits;
                if (unk_call_ret) unk_call_ret_seen = 1;
                if (is_x86_32 && ins.ops[0]) {
                    uint64_t imm = (strncmp(ins.ops, "0x", 2) == 0) ? strtoull(ins.ops + 2, NULL, 16) : strtoull(ins.ops, NULL, 10);
                    if (imm > 0 && imm <= 40 && (imm & 3) == 0) stdcall_narg = (int)(imm / 4);
                }
                break;
            }
            if (ins.flow == X86_FLOW_TRAP) break;

            if (ins.flow == X86_FLOW_JCC) {
                if (nwork < 2 && ins.has_target && ins.target > cur_va && ins.target < cur_va + 0x1000 &&
                    bin_is_exec(&a->bin, ins.target)) {
                    work[1].va = ins.target;
                    work[1].gpr_def = gpr_def;
                    work[1].xmm_def = xmm_def;
                    work[1].ret_gpr = ret_gpr;
                    work[1].ret_flt = ret_flt;
                    work[1].last_ret_kind = last_ret_kind;
                    work[1].last_ret_bits = last_ret_bits;
                    work[1].unk_call_ret = unk_call_ret;
                    nwork = 2;
                }
                ip += (uint64_t)len;
                continue;
            }

            if (ins.flow == X86_FLOW_JMP) {
                if (ins.has_target && !ins.target_mem && ins.target > ip && ins.target < cur_va + 0x1000 &&
                    bin_is_exec(&a->bin, ins.target)) {
                    ip = ins.target;
                    continue;
                }
                // tail call to known API
                if (ins.has_target) {
                    const char *tsym = ana_sym_at(a, ins.target);
                    const ti_api_ent *api = tsym ? ti_find_api(tsym) : NULL;
                    if (api) {
                        int lim = api->narg < nabi ? api->narg : nabi;
                        for (int k = 0; k < lim; k++) {
                            if (api->a[k] == T_F32 || api->a[k] == T_F64) {
                                if (!(xmm_def & (1u << k))) xmm_live |= (1u << k);
                            } else {
                                int ar = abi_args[k];
                                if (!(gpr_def & (1u << ar))) gpr_live |= (1u << ar);
                            }
                        }
                        saw_ret = 1;
                        if (api->ret == T_F32) {
                            if (ret_flt_max < 32) ret_flt_max = 32;
                            if (ret_last_flt < 32) ret_last_flt = 32;
                        } else if (api->ret == T_F64) {
                            ret_flt_max = 64;
                            ret_last_flt = 64;
                        } else if (api->ret != T_VOID) {
                            int gb = is_x86_32 ? 32 : 64;
                            if (ret_gpr_max < gb) ret_gpr_max = gb;
                            if (ret_last_gpr < gb) ret_last_gpr = gb;
                        }
                    }
                }
                break;
            }

            char ops[4][76];
            int nops = ti_split_ops(ins.ops, ops, 4);

            if (ins.flow == X86_FLOW_CALL) {
                // MSVC __chkstk probe: call followed immediately by sub rsp, rax (preserves all ABI arg regs)
                int is_chkstk = 0;
                if (ins.has_target && !ins.target_mem) {
                    size_t nav = 0;
                    const uint8_t *np = bin_ptr(&a->bin, ip + (uint64_t)len, &nav);
                    if (np && nav >= 2) {
                        x86_ins nxt;
                        if (arch_decode(a->bin.arch, np, nav, ip + (uint64_t)len, 1, 0, &nxt) > 0 &&
                            strcmp(nxt.mnem, "sub") == 0 &&
                            (strstr(nxt.ops, "rsp, rax") != NULL || strstr(nxt.ops, "esp, eax") != NULL)) {
                            is_chkstk = 1;
                        }
                    }
                }
                if (is_chkstk) {
                    ip += (uint64_t)len;
                    continue;
                }
                if (nops >= 1 && (!ins.has_target || ins.target_mem)) {
                    uint32_t mreads = 0;
                    if (strchr(ops[0], '[')) {
                        ti_scan_x86_mem_regs(ops[0], &mreads, is_x86_32 ? &ebp_arg_max : NULL);
                    } else {
                        int b = 0, xm = 0;
                        int r = ti_parse_x86_reg(ops[0], &b, &xm);
                        if (r >= 0 && !xm) mreads |= (1u << r);
                    }
                    gpr_live |= (mreads & ~gpr_def);
                }
                const char *tsym = ins.has_target ? ana_sym_at(a, ins.target) : NULL;
                const ti_api_ent *api = tsym ? ti_find_api(tsym) : NULL;
                if (api) {
                    int lim = api->narg < nabi ? api->narg : nabi;
                    for (int k = 0; k < lim; k++) {
                        if (api->a[k] == T_F32 || api->a[k] == T_F64) {
                            if (!(xmm_def & (1u << k))) xmm_live |= (1u << k);
                        } else {
                            int ar = abi_args[k];
                            if (!(gpr_def & (1u << ar))) gpr_live |= (1u << ar);
                        }
                    }
                    if (api->ret == T_F32) { ret_flt = 32; last_ret_kind = 2; last_ret_bits = 32; unk_call_ret = 0; }
                    else if (api->ret == T_F64) { ret_flt = 64; last_ret_kind = 2; last_ret_bits = 64; unk_call_ret = 0; }
                    else if (api->ret != T_VOID) {
                        int gb = is_x86_32 ? 32 : 64;
                        ret_gpr = gb;
                        last_ret_kind = 1;
                        last_ret_bits = gb;
                        unk_call_ret = 0;
                    } else {
                        last_ret_kind = 0;
                        last_ret_bits = 0;
                        unk_call_ret = 0;
                    }
                } else {
                    last_ret_kind = 0;
                    last_ret_bits = 0;
                    unk_call_ret = 1;
                }
                gpr_def |= caller_saved_gpr;
                xmm_def |= caller_saved_xmm;
                ip += (uint64_t)len;
                continue;
            }

            const char *m = ins.mnem;
            if (strcmp(m, "nop") == 0 || strcmp(m, "endbr64") == 0 || strcmp(m, "endbr32") == 0 ||
                strncmp(m, "prefetch", 8) == 0) {
                ip += (uint64_t)len;
                continue;
            }

            if (is_win64 && wi == 0) {
                if (strcmp(m, "push") == 0) {
                    sp_off += 8;
                } else if (strcmp(m, "pop") == 0) {
                    sp_off -= 8;
                } else if ((strcmp(m, "sub") == 0 || strcmp(m, "add") == 0) && nops >= 2 &&
                           strcmp(ops[0], "rsp") == 0) {
                    const char *im = ops[1];
                    if (isxdigit((unsigned char)im[0])) {
                        uint64_t v = (strncmp(im, "0x", 2) == 0 || strncmp(im, "0X", 2) == 0)
                                     ? strtoull(im + 2, NULL, 16) : strtoull(im, NULL, 10);
                        if (v < 0x100000ULL) sp_off += (m[0] == 's') ? (int64_t)v : -(int64_t)v;
                    }
                } else if (strcmp(m, "mov") == 0 && nops >= 2) {
                    int64_t disp = 0;
                    int sb = 0, sxm = 0;
                    int sr = ti_parse_x86_reg(ops[1], &sb, &sxm);
                    if (!sxm && sr >= 0 && ti_parse_rsp_disp(ops[0], &disp)) {
                        int64_t rel = disp - sp_off;
                        for (int hk = 0; hk < 4; hk++) {
                            if (sr == win64_args[hk] && rel == (int64_t)(8 + hk * 8)) {
                                win64_home_mask |= (uint8_t)(1u << hk);
                            }
                        }
                    }
                } else if (strcmp(m, "lea") == 0 && nops >= 2 && win64_va_start_idx < 0) {
                    int64_t disp = 0;
                    if (ti_parse_rsp_disp(ops[1], &disp)) {
                        int64_t rel = disp - sp_off;
                        if (rel == 0x10 || rel == 0x18 || rel == 0x20) {
                            int idx = (int)((rel - 8) / 8);
                            uint8_t need = (uint8_t)(((1u << 4) - 1u) & ~((1u << idx) - 1u));
                            if ((win64_home_mask & need) == need) {
                                win64_va_start_idx = idx;
                            }
                        }
                    }
                }
            }

            if (strcmp(m, "cdqe") == 0 || strcmp(m, "cwde") == 0) {
                if (!(gpr_def & 1u)) gpr_live |= 1u;
                gpr_def |= 1u;
                ret_gpr = (strcmp(m, "cdqe") == 0) ? 64 : 32;
                last_ret_kind = 1;
                last_ret_bits = ret_gpr;
                unk_call_ret = 0;
                ip += (uint64_t)len;
                continue;
            }
            if (strcmp(m, "cdq") == 0 || strcmp(m, "cqo") == 0) {
                if (!(gpr_def & 1u)) gpr_live |= 1u;
                gpr_def |= (1u << 2);
                ip += (uint64_t)len;
                continue;
            }
            if (nops == 1 && (strcmp(m, "div") == 0 || strcmp(m, "idiv") == 0 ||
                              strcmp(m, "mul") == 0 || strcmp(m, "imul") == 0)) {
                uint32_t mreads = 1u;
                if (m[0] == 'd' || (m[0] == 'i' && m[1] == 'd')) mreads |= (1u << 2);
                int b = is_x86_32 ? 32 : 64;
                if (strchr(ops[0], '[') != NULL) {
                    ti_scan_x86_mem_regs(ops[0], &mreads, is_x86_32 ? &ebp_arg_max : NULL);
                } else {
                    int xm = 0;
                    int r = ti_parse_x86_reg(ops[0], &b, &xm);
                    if (r >= 0 && !xm) mreads |= (1u << r);
                }
                gpr_live |= (mreads & ~gpr_def);
                gpr_def |= 1u | (1u << 2);
                ret_gpr = b;
                last_ret_kind = 1;
                last_ret_bits = b;
                unk_call_ret = 0;
                ip += (uint64_t)len;
                continue;
            }

            // self-zero idiom (xor eax, eax / xorps xmm0, xmm0) defines without reading
            if (ti_is_x86_self_zero(m, nops, ops)) {
                int b = 0, xm = 0;
                int r = ti_parse_x86_reg(ops[0], &b, &xm);
                if (r >= 0) {
                    if (xm) {
                        xmm_def |= (1u << (r & 15));
                        if (r == 0 && (strstr(m, "ps") != NULL || strstr(m, "pd") != NULL) &&
                            !ti_is_xmm0_vec_store_soon(a, arch, ip + (uint64_t)len)) {
                            int fb = (strstr(m, "ps") != NULL) ? 32 : 64;
                            ret_flt = fb;
                            last_ret_kind = 2;
                            last_ret_bits = fb;
                            unk_call_ret = 0;
                        }
                    } else {
                        gpr_def |= (1u << r);
                        if (r == 0) {
                            ret_gpr = b;
                            last_ret_kind = 1;
                            last_ret_bits = b;
                            unk_call_ret = 0;
                        }
                    }
                }
                ip += (uint64_t)len;
                continue;
            }

            int op0_is_mem = (nops >= 1 && strchr(ops[0], '[') != NULL);
            int op0_pure_write = (!op0_is_mem && ti_is_x86_pure_write(m));
            int is_ro = ti_is_x86_readonly(m);
            if (!op0_is_mem && strcmp(m, "imul") == 0 && nops == 3) op0_pure_write = 1;
            if (!op0_is_mem && m[0] == 'v' && nops >= 3) op0_pure_write = 1;

            int is_ss = (strstr(m, "ss") != NULL);

            uint32_t gpr_r = 0, xmm_r = 0;
            for (int k = 0; k < nops; k++) {
                if (k == 0 && op0_pure_write) continue;
                if (strchr(ops[k], '[') != NULL) {
                    ti_scan_x86_mem_regs(ops[k], &gpr_r, is_x86_32 ? &ebp_arg_max : NULL);
                } else {
                    int b = 0, xm = 0;
                    int r = ti_parse_x86_reg(ops[k], &b, &xm);
                    if (r >= 0) {
                        if (xm) {
                            xmm_r |= (1u << (r & 15));
                            if (is_ss && r < 8) xmm_f32 |= (uint8_t)(1u << r);
                        } else {
                            gpr_r |= (1u << r);
                        }
                    }
                }
            }
            gpr_live |= (gpr_r & ~gpr_def);
            xmm_live |= (xmm_r & ~xmm_def);

            if (!is_ro && !op0_is_mem && nops >= 1) {
                int b = 0, xm = 0;
                int r = ti_parse_x86_reg(ops[0], &b, &xm);
                if (r >= 0) {
                    if (xm) {
                        xmm_def |= (1u << (r & 15));
                        if (r == 0) {
                            int fb = 0;
                            if (ti_is_x86_scalar_fp_write(m, &fb)) {
                                ret_flt = fb;
                                last_ret_kind = 2;
                                last_ret_bits = fb;
                                unk_call_ret = 0;
                            } else if ((strcmp(m, "movaps") == 0 || strcmp(m, "movapd") == 0 ||
                                        strcmp(m, "vmovaps") == 0 || strcmp(m, "vmovapd") == 0) &&
                                       nops >= 2 && strchr(ops[1], '[') == NULL &&
                                       !ti_is_xmm0_vec_store_soon(a, arch, ip + (uint64_t)len)) {
                                int b1 = 0, xm1 = 0;
                                int r1 = ti_parse_x86_reg(ops[1], &b1, &xm1);
                                if (xm1 && r1 >= 0) {
                                    if (strstr(m, "pd") != NULL) fb = 64;
                                    else if (r1 < 8 && (xmm_f32 & (1u << r1))) fb = 32;
                                    else if (ret_flt > 0) fb = ret_flt;
                                    else fb = 64;
                                    ret_flt = fb;
                                    last_ret_kind = 2;
                                    last_ret_bits = fb;
                                    unk_call_ret = 0;
                                }
                            } else if ((strcmp(m, "xorps") == 0 || strcmp(m, "xorpd") == 0 ||
                                        strcmp(m, "vxorps") == 0 || strcmp(m, "vxorpd") == 0 ||
                                        strcmp(m, "andps") == 0 || strcmp(m, "andpd") == 0 ||
                                        strcmp(m, "vandps") == 0 || strcmp(m, "vandpd") == 0) &&
                                       !ti_is_xmm0_vec_store_soon(a, arch, ip + (uint64_t)len)) {
                                if (strstr(m, "pd") != NULL) fb = 64;
                                else if (last_ret_kind == 2 && last_ret_bits == 64) fb = 64;
                                else fb = 32;
                                ret_flt = fb;
                                last_ret_kind = 2;
                                last_ret_bits = fb;
                                unk_call_ret = 0;
                            }
                        }
                    } else {
                        gpr_def |= (1u << r);
                        if (r == 0) {
                            ret_gpr = b;
                            last_ret_kind = 1;
                            last_ret_bits = b;
                            unk_call_ret = 0;
                        }
                    }
                }
            }

            ip += (uint64_t)len;
        }
    }

    if (is_x86_32) {
        if (stdcall_narg >= 0) {
            out->narg = stdcall_narg;
        } else if (ebp_arg_max >= 0) {
            out->narg = ebp_arg_max + 1;
        } else {
            int fc = 0;
            if (gpr_live & (1u << 1)) fc = 1;
            if (gpr_live & (1u << 2)) fc = 2;
            out->narg = fc;
        }
        if (out->narg > HL_MAX_CALL_ARG) out->narg = HL_MAX_CALL_ARG;
    } else if (is_win64) {
        if (win64_va_start_idx > 0 && win64_va_start_idx <= 3) {
            out->is_vararg = 1;
            out->narg = win64_va_start_idx;
            out->fmt_arg = win64_va_start_idx - 1;
        } else {
            int max_idx = -1;
            for (int i = 0; i < 4; i++) {
                int ig = (gpr_live & (1u << win64_args[i])) != 0;
                int xf = (xmm_live & (1u << i)) != 0;
                if (ig || xf) max_idx = i;
                if (xf && !ig) {
                    out->flt_mask |= (uint8_t)(1u << i);
                    int fb = (xmm_f32 & (1u << i)) ? 32 : 64;
                    out->arg_ty[i] = ti_make_ty(fb == 32 ? HL_TY_F32 : HL_TY_F64, 0, 0, (uint8_t)fb);
                }
            }
            out->narg = max_idx + 1;
        }
    } else {
        int max_int = -1, max_flt = -1;
        for (int i = 0; i < 6; i++) {
            if (gpr_live & (1u << sysv_args[i])) max_int = i;
        }
        for (int i = 0; i < 8; i++) {
            if (xmm_live & (1u << i)) max_flt = i;
        }
        int nint = max_int + 1;
        int nflt = max_flt + 1;
        int total = nint + nflt;
        if (total > HL_MAX_CALL_ARG) total = HL_MAX_CALL_ARG;
        out->narg = total;
        for (int i = 0; i < nflt && (nint + i) < 8; i++) {
            int pos = nint + i;
            out->flt_mask |= (uint8_t)(1u << pos);
            int fb = (xmm_f32 & (1u << i)) ? 32 : 64;
            out->arg_ty[pos] = ti_make_ty(fb == 32 ? HL_TY_F32 : HL_TY_F64, 0, 0, (uint8_t)fb);
        }
    }

    if (!saw_ret || unk_call_ret_seen) {
        out->has_ret = 1;
        out->ret_ty = ti_make_ty(is_x86_32 ? HL_TY_I32 : HL_TY_I64, 0, 0, is_x86_32 ? 32 : 64);
    } else if (ret_last_flt > 0) {
        out->has_ret = 1;
        out->ret_ty = ti_make_ty(ret_last_flt == 32 ? HL_TY_F32 : HL_TY_F64, 0, 0, (uint8_t)ret_last_flt);
    } else if (ret_last_gpr > 0) {
        out->has_ret = 1;
        if (ret_last_gpr == 8) out->ret_ty = ti_make_ty(HL_TY_U8, 0, 0, 8);
        else if (ret_last_gpr == 16) out->ret_ty = ti_make_ty(HL_TY_U16, 0, 0, 16);
        else if (ret_last_gpr == 32 || is_x86_32) out->ret_ty = ti_make_ty(HL_TY_I32, 0, 0, 32);
        else out->ret_ty = ti_make_ty(HL_TY_I64, 0, 0, 64);
    } else if (ret_flt_max > 0) {
        out->has_ret = 1;
        out->ret_ty = ti_make_ty(ret_flt_max == 32 ? HL_TY_F32 : HL_TY_F64, 0, 0, (uint8_t)ret_flt_max);
    } else if (ret_gpr_max > 0) {
        out->has_ret = 1;
        if (ret_gpr_max == 8) out->ret_ty = ti_make_ty(HL_TY_U8, 0, 0, 8);
        else if (ret_gpr_max == 16) out->ret_ty = ti_make_ty(HL_TY_U16, 0, 0, 16);
        else if (ret_gpr_max == 32 || is_x86_32) out->ret_ty = ti_make_ty(HL_TY_I32, 0, 0, 32);
        else out->ret_ty = ti_make_ty(HL_TY_I64, 0, 0, 64);
    } else {
        out->has_ret = 0;
        out->ret_ty = ti_make_ty(HL_TY_VOID, 0, 0, 0);
    }
    return true;
}

static uint32_t ti_callee_hash(const uint8_t *data, uint64_t size, uint64_t va) {
    uint64_t h = va ^ (va >> 12) ^ (size << 3) ^ ((uint64_t)(uintptr_t)data >> 4);
    h ^= h >> 17;
    h *= 0xbf58476d1ce4e5b9ULL;
    h ^= h >> 31;
    return (uint32_t)(h & (TI_CALLEE_CACHE_SZ - 1));
}

bool hl_lookup_callee(const ana_ctx *a, const typ_store *types, uint64_t va, const char *sym, hl_callee_sig *out) {
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    out->va = va;
    out->narg = -1;
    out->fmt_arg = -1;

    const char *eff_sym = (sym && sym[0]) ? sym : ((a && va) ? ana_sym_at(a, va) : NULL);
    if (eff_sym && eff_sym[0]) {
        const ti_api_ent *api = ti_find_api(eff_sym);
        if (api) {
            ti_fill_api_sig(types, api, va, out);
            return true;
        }
    }

    if (!a || !va || !a->bin.map.data || !bin_is_exec(&a->bin, va)) return false;

    const uint8_t *mdata = a->bin.map.data;
    uint64_t msize = a->bin.map.size;
    uint64_t entry = a->bin.entry;

    uint32_t slot = ti_callee_hash(mdata, msize, va);
    for (uint32_t probe = 0; probe < 32; probe++) {
        ti_callee_cache_ent *ce = &ti_callee_cache[(slot + probe) & (TI_CALLEE_CACHE_SZ - 1)];
        if (!ce->used) break;
        if (ce->va == va && ce->map_data == mdata && ce->map_size == msize && ce->entry == entry) {
            *out = ce->sig;
            out->va = va;
            return ce->ok != 0;
        }
    }

    hl_callee_sig res;
    memset(&res, 0, sizeof(res));
    res.va = va;
    res.narg = -1;
    res.fmt_arg = -1;
    bool ok = ti_analyze_callee(a, types, va, &res);

    if (ti_callee_cache_used >= (TI_CALLEE_CACHE_SZ * 3) / 4) {
        memset(ti_callee_cache, 0, sizeof(ti_callee_cache));
        ti_callee_cache_used = 0;
    }
    uint32_t dst_slot = slot;
    for (uint32_t probe = 0; probe < 32; probe++) {
        uint32_t idx = (slot + probe) & (TI_CALLEE_CACHE_SZ - 1);
        if (!ti_callee_cache[idx].used) {
            dst_slot = idx;
            ti_callee_cache_used++;
            break;
        }
        if (ti_callee_cache[idx].va == va && ti_callee_cache[idx].map_data == mdata &&
            ti_callee_cache[idx].map_size == msize && ti_callee_cache[idx].entry == entry) {
            dst_slot = idx;
            break;
        }
    }
    ti_callee_cache_ent *ce = &ti_callee_cache[dst_slot];
    ce->map_data = mdata;
    ce->map_size = msize;
    ce->entry = entry;
    ce->va = va;
    ce->used = 1;
    ce->ok = ok ? 1 : 0;
    ce->sig = res;

    if (ok) *out = res;
    return ok;
}

static int ti_var_canon(const hl_fn *fn, int vid) {
    if (!fn || vid < 0 || vid >= fn->nvar) return -1;
    int c = hl_var_canon(fn, vid);
    if (c < 0 || c >= fn->nvar) return vid;
    return c;
}

static int ti_type_rank(const hl_type *t) {
    if (!t || t->kind == HL_TY_UNK) return 0;
    if (t->kind == HL_TY_STRUCT) return (t->ptr_depth > 0) ? 9 : 8;
    if (t->kind == HL_TY_HANDLE || t->kind == HL_TY_HMODULE || t->kind == HL_TY_HWND ||
        t->kind == HL_TY_HKEY || t->kind == HL_TY_SOCKET || t->kind == HL_TY_FILE) {
        return (t->ptr_depth > 0) ? 7 : 6;
    }
    if (t->kind == HL_TY_PTR) return 5;
    if (t->kind == HL_TY_VOID) return (t->ptr_depth > 0) ? 5 : 1;
    if (t->ptr_depth > 0) return 7;
    if (t->kind == HL_TY_BOOL || t->kind == HL_TY_CHAR || t->kind == HL_TY_WCHAR ||
        t->kind == HL_TY_SIZE_T || t->kind == HL_TY_F32 || t->kind == HL_TY_F64) {
        return 4;
    }
    if (t->kind == HL_TY_I8 || t->kind == HL_TY_U8 || t->kind == HL_TY_I16 || t->kind == HL_TY_U16) {
        return 3;
    }
    return 2;
}

static int ti_type_eq(const hl_type *a, const hl_type *b) {
    return a->kind == b->kind && a->ptr_depth == b->ptr_depth &&
           a->is_const == b->is_const && strcmp(a->name, b->name) == 0;
}

static int ti_type_merge(hl_type *dst, const hl_type *src, int dst_pinned) {
    if (dst_pinned || !dst || !src || src->kind == HL_TY_UNK) return 0;
    if (src->kind == HL_TY_VOID && src->ptr_depth == 0) return 0;
    if (dst->kind == HL_TY_UNK) {
        *dst = *src;
        return 1;
    }
    if (ti_type_eq(dst, src)) return 0;
    int rd = ti_type_rank(dst);
    int rs = ti_type_rank(src);
    if (rs > rd) {
        *dst = *src;
        return 1;
    }
    return 0;
}

static hl_type ti_scalar_from_bits(int bits, int is_flt, int is_signed) {
    if (is_flt) return ti_make_ty(bits == 32 ? HL_TY_F32 : HL_TY_F64, 0, 0, bits == 32 ? 32 : 64);
    if (bits == 8) return ti_make_ty(is_signed ? HL_TY_I8 : HL_TY_U8, 0, 0, 8);
    if (bits == 16) return ti_make_ty(is_signed ? HL_TY_I16 : HL_TY_U16, 0, 0, 16);
    if (bits == 32) return ti_make_ty(HL_TY_I32, 0, 0, 32);
    return ti_make_ty(HL_TY_I64, 0, 0, 64);
}

static bool ti_is_printable_ascii(uint64_t v) {
    return v == 0 || v == '\t' || v == '\n' || v == '\r' || (v >= 0x20 && v <= 0x7E);
}

static bool ti_is_char_like(const hl_fn *fn, const hl_expr *e) {
    if (!e || e->ty.ptr_depth > 0) return false;
    if (e->ty.kind == HL_TY_CHAR || e->ty.kind == HL_TY_U8 || e->ty.kind == HL_TY_I8 || e->ty.kind == HL_TY_WCHAR) {
        return true;
    }
    if (e->bits == 8 && e->kind != HLE_INT) return true;
    if (fn && e->kind == HLE_UNOP && (e->op == HLU_ZEXT || e->op == HLU_SEXT) &&
        e->sub0 >= 0 && e->sub0 < fn->nexpr) {
        const hl_expr *s = &fn->exprs[e->sub0];
        if (s->ty.ptr_depth == 0 &&
            (s->ty.kind == HL_TY_CHAR || s->ty.kind == HL_TY_U8 || s->ty.kind == HL_TY_I8 ||
             s->ty.kind == HL_TY_WCHAR || (s->bits == 8 && s->kind != HLE_INT))) {
            return true;
        }
    }
    return false;
}

static void ti_backprop_type(hl_fn *fn, int eid, const hl_type *ty, const uint8_t *pinned, int *changed) {
    if (!fn || !ty || ty->kind == HL_TY_UNK || eid < 0 || eid >= fn->nexpr) return;
    hl_expr *e = &fn->exprs[eid];

    if (e->kind == HLE_VAR) {
        int cid = ti_var_canon(fn, e->var_id);
        if (cid >= 0) {
            if (ti_type_merge(&fn->vars[cid].ty, ty, pinned[cid])) *changed = 1;
            if (ti_type_merge(&e->ty, &fn->vars[cid].ty, 0)) *changed = 1;
        }
    } else if (e->kind == HLE_ADDR && e->sub0 >= 0 && e->sub0 < fn->nexpr) {
        hl_expr *sub = &fn->exprs[e->sub0];
        if (sub->kind == HLE_VAR && ty->ptr_depth >= 1 && ty->kind != HL_TY_VOID && ty->kind != HL_TY_PTR) {
            hl_type pt = *ty;
            pt.ptr_depth--;
            pt.is_const = 0;
            int cid = ti_var_canon(fn, sub->var_id);
            if (cid >= 0 && ti_type_merge(&fn->vars[cid].ty, &pt, pinned[cid])) *changed = 1;
        }
    } else if (e->kind == HLE_BINOP && e->op == HLB_ADD &&
               ty->ptr_depth >= 1 && (ty->kind == HL_TY_CHAR || ty->kind == HL_TY_WCHAR || ty->kind == HL_TY_STRUCT)) {
        if (e->sub0 >= 0 && e->sub0 < fn->nexpr && fn->exprs[e->sub0].kind == HLE_VAR &&
            e->sub1 >= 0 && e->sub1 < fn->nexpr && fn->exprs[e->sub1].kind == HLE_INT) {
            int cid = ti_var_canon(fn, fn->exprs[e->sub0].var_id);
            if (cid >= 0 && ti_type_merge(&fn->vars[cid].ty, ty, pinned[cid])) *changed = 1;
        }
    }
}

static void ti_hint_ptr_var(hl_fn *fn, int eid, const uint8_t *pinned, int *changed) {
    if (!fn || eid < 0 || eid >= fn->nexpr) return;
    hl_expr *e = &fn->exprs[eid];
    hl_type vp = ti_make_ty(HL_TY_VOID, 1, 0, 0);

    if (e->kind == HLE_VAR) {
        int cid = ti_var_canon(fn, e->var_id);
        if (cid >= 0 && fn->vars[cid].ty.ptr_depth == 0 && ti_type_rank(&fn->vars[cid].ty) <= 2) {
            if (ti_type_merge(&fn->vars[cid].ty, &vp, pinned[cid])) *changed = 1;
        }
    } else if (e->kind == HLE_BINOP && (e->op == HLB_ADD || e->op == HLB_SUB)) {
        if (e->sub0 >= 0 && e->sub0 < fn->nexpr && fn->exprs[e->sub0].kind == HLE_VAR &&
            e->sub1 >= 0 && e->sub1 < fn->nexpr && fn->exprs[e->sub1].kind == HLE_INT) {
            int cid = ti_var_canon(fn, fn->exprs[e->sub0].var_id);
            if (cid >= 0 && fn->vars[cid].ty.ptr_depth == 0 && ti_type_rank(&fn->vars[cid].ty) <= 2) {
                if (ti_type_merge(&fn->vars[cid].ty, &vp, pinned[cid])) *changed = 1;
            }
        }
    }
}

static bool ti_read_fmt_str(const hl_fn *fn, int eid, char *out, size_t cap) {
    if (!fn || !out || cap < 2 || eid < 0 || eid >= fn->nexpr) return false;
    const hl_expr *e = &fn->exprs[eid];
    if (e->kind == HLE_STR && e->va == 0 && e->sym[0]) {
        snprintf(out, cap, "%s", e->sym);
        return true;
    }
    uint64_t va = 0;
    int prefer_wide = 0;
    if (e->kind == HLE_STR) { va = e->va; prefer_wide = e->is_wide ? 1 : 0; }
    else if (e->kind == HLE_SYM) va = e->va;
    else if (e->kind == HLE_INT) va = e->uval;
    else return false;

    if (!fn->a || !va) return false;
    const ana_str *st = ana_str_at(fn->a, va);
    if (st) prefer_wide = st->wide ? 1 : 0;
    const bin_sec *sec = bin_sec_at(&fn->a->bin, va);
    if (!sec || (sec->perm & BIN_PERM_X)) return false;

    uint8_t raw[256];
    size_t got = bin_read(&fn->a->bin, va, raw, sizeof(raw));
    if (got < 2) return false;

    if (prefer_wide || (got >= 4 && raw[1] == 0 && raw[0] >= 0x20 && raw[0] <= 0x7E)) {
        size_t k = 0;
        for (size_t i = 0; i * 2 + 1 < got && k + 1 < cap; i++) {
            uint8_t lo = raw[i * 2], hi = raw[i * 2 + 1];
            if (lo == 0 && hi == 0) {
                out[k] = 0;
                return k > 0;
            }
            if (hi == 0 && ((lo >= 0x20 && lo <= 0x7E) || lo == '\t' || lo == '\r' || lo == '\n')) {
                out[k++] = (char)lo;
            } else if (prefer_wide) {
                out[k++] = '?';
            } else {
                break;
            }
        }
        if (prefer_wide && k > 0) { out[k] = 0; return true; }
    }

    size_t len = 0;
    while (len < got && raw[len] != 0 && len + 1 < cap) {
        uint8_t c = raw[len];
        if (!((c >= 0x20 && c <= 0x7E) || c == '\t' || c == '\r' || c == '\n')) break;
        out[len] = (char)c;
        len++;
    }
    if (len > 0 && ((len < got && raw[len] == 0) || st != NULL)) {
        out[len] = 0;
        return true;
    }
    return false;
}

static int ti_parse_fmt_arg_types(const char *fmt, int is_scanf, hl_type *out_ty, int max_args) {
    if (!fmt || !out_ty || max_args <= 0) return 0;
    int cnt = 0;
    const char *p = fmt;
    while (*p && cnt < max_args) {
        if (*p != '%') { p++; continue; }
        p++;
        if (*p == '%') { p++; continue; }
        if (!*p) break;

        const char *q = p;
        while (isdigit((unsigned char)*q)) q++;
        if (q > p && *q == '$') p = q + 1;

        while (*p && strchr("-#0 +'", *p) != NULL) p++;

        int suppressed = 0;
        if (*p == '*') {
            if (is_scanf) {
                suppressed = 1;
            } else if (cnt < max_args) {
                out_ty[cnt++] = ti_make_ty(HL_TY_I32, 0, 0, 32);
            }
            p++;
            q = p;
            while (isdigit((unsigned char)*q)) q++;
            if (q > p && *q == '$') p = q + 1;
        } else {
            while (isdigit((unsigned char)*p)) p++;
        }

        if (*p == '.') {
            p++;
            if (*p == '*') {
                if (!is_scanf && cnt < max_args) {
                    out_ty[cnt++] = ti_make_ty(HL_TY_I32, 0, 0, 32);
                }
                p++;
                q = p;
                while (isdigit((unsigned char)*q)) q++;
                if (q > p && *q == '$') p = q + 1;
            } else {
                while (isdigit((unsigned char)*p)) p++;
            }
        }

        int is_long = 0, is_ll = 0;
        if (p[0] == 'h' && p[1] == 'h') p += 2;
        else if (p[0] == 'l' && p[1] == 'l') { is_ll = 1; p += 2; }
        else if (p[0] == 'I' && p[1] == '6' && p[2] == '4') { is_ll = 1; p += 3; }
        else if (p[0] == 'I' && p[1] == '3' && p[2] == '2') p += 3;
        else if (*p && strchr("hlLztjqIw", *p) != NULL) {
            if (*p == 'l') is_long = 1;
            else if (*p == 'z' || *p == 't' || *p == 'j' || *p == 'q' || *p == 'I') is_ll = 1;
            p++;
        }

        if (!*p) break;
        char sp = *p;
        if (sp == '[') {
            p++;
            if (*p == '^') p++;
            if (*p == ']') p++;
            while (*p && *p != ']') p++;
            if (*p == ']') p++;
            if (!suppressed && cnt < max_args) {
                out_ty[cnt++] = ti_make_ty(HL_TY_CHAR, 1, 0, 8);
            }
            continue;
        }
        if (strchr("diuoxXfFeEgGaAcspnSC", sp) == NULL) continue;
        p++;
        if (suppressed || cnt >= max_args) continue;

        if (is_scanf) {
            if (sp == 's') out_ty[cnt++] = ti_make_ty(is_long ? HL_TY_WCHAR : HL_TY_CHAR, 1, 0, is_long ? 16 : 8);
            else if (sp == 'S') out_ty[cnt++] = ti_make_ty(HL_TY_WCHAR, 1, 0, 16);
            else if (sp == 'c') out_ty[cnt++] = ti_make_ty(HL_TY_CHAR, 1, 0, 8);
            else if (strchr("fFeEgGaA", sp)) out_ty[cnt++] = ti_make_ty(is_long ? HL_TY_F64 : HL_TY_F32, 1, 0, is_long ? 64 : 32);
            else if (sp == 'd' || sp == 'i') out_ty[cnt++] = ti_make_ty(is_ll ? HL_TY_I64 : HL_TY_I32, 1, 0, is_ll ? 64 : 32);
            else if (sp == 'u' || sp == 'o' || sp == 'x' || sp == 'X') out_ty[cnt++] = ti_make_ty(is_ll ? HL_TY_U64 : HL_TY_U32, 1, 0, is_ll ? 64 : 32);
            else out_ty[cnt++] = ti_make_ty(HL_TY_VOID, 1, 0, 0);
        } else {
            if (sp == 's') out_ty[cnt++] = ti_make_ty(is_long ? HL_TY_WCHAR : HL_TY_CHAR, 1, 1, is_long ? 16 : 8);
            else if (sp == 'S') out_ty[cnt++] = ti_make_ty(HL_TY_WCHAR, 1, 1, 16);
            else if (sp == 'p') out_ty[cnt++] = ti_make_ty(HL_TY_VOID, 1, 1, 0);
            else if (strchr("fFeEgGaA", sp)) out_ty[cnt++] = ti_make_ty(HL_TY_F64, 0, 0, 64);
            else if (sp == 'd' || sp == 'i') out_ty[cnt++] = ti_make_ty(is_ll ? HL_TY_I64 : HL_TY_I32, 0, 0, is_ll ? 64 : 32);
            else if (sp == 'u' || sp == 'o' || sp == 'x' || sp == 'X') out_ty[cnt++] = ti_make_ty(is_ll ? HL_TY_U64 : HL_TY_U32, 0, 0, is_ll ? 64 : 32);
            else if (sp == 'c') out_ty[cnt++] = ti_make_ty(HL_TY_CHAR, 0, 0, 8);
            else out_ty[cnt++] = ti_make_ty(HL_TY_UNK, 0, 0, 0);
        }
    }
    return cnt;
}

static void ti_infer_expr(hl_fn *fn, int eid, const uint8_t *pinned, int *changed, int depth) {
    if (!fn || eid < 0 || eid >= fn->nexpr || depth > 48) return;
    hl_expr *e = &fn->exprs[eid];

    switch (e->kind) {
    case HLE_STR: {
        hl_type st = ti_make_ty(e->is_wide ? HL_TY_WCHAR : HL_TY_CHAR, 1, 1, e->is_wide ? 16 : 8);
        if (ti_type_merge(&e->ty, &st, 0)) *changed = 1;
        break;
    }
    case HLE_FLT: {
        hl_type ft = ti_make_ty(e->bits == 32 ? HL_TY_F32 : HL_TY_F64, 0, 0, e->bits == 32 ? 32 : 64);
        if (ti_type_merge(&e->ty, &ft, 0)) *changed = 1;
        break;
    }
    case HLE_INT: {
        if (e->ty.kind == HL_TY_UNK) {
            e->ty = ti_scalar_from_bits(e->bits ? (int)e->bits : 32, 0, e->is_signed);
            *changed = 1;
        }
        break;
    }
    case HLE_SYM: {
        if (e->ty.kind == HL_TY_UNK && fn->a && e->va) {
            const ana_str *st = ana_str_at(fn->a, e->va);
            if (st) {
                e->ty = ti_make_ty(st->wide ? HL_TY_WCHAR : HL_TY_CHAR, 1, 1, st->wide ? 16 : 8);
                *changed = 1;
            }
        }
        if (e->ty.kind == HL_TY_UNK) {
            e->ty = ti_scalar_from_bits(e->bits ? (int)e->bits : fn->ptr_bits, e->is_flt, e->is_signed);
            *changed = 1;
        }
        break;
    }
    case HLE_VAR: {
        int cid = ti_var_canon(fn, e->var_id);
        if (cid >= 0) {
            if (ti_type_merge(&e->ty, &fn->vars[cid].ty, 0)) *changed = 1;
            if (ti_type_merge(&fn->vars[cid].ty, &e->ty, pinned[cid])) *changed = 1;
        }
        break;
    }
    case HLE_ADDR: {
        ti_infer_expr(fn, e->sub0, pinned, changed, depth + 1);
        if (e->sub0 >= 0 && e->sub0 < fn->nexpr) {
            hl_type st = fn->exprs[e->sub0].ty;
            if (st.kind != HL_TY_UNK) {
                if (st.ptr_depth < 4) st.ptr_depth++;
                if (ti_type_merge(&e->ty, &st, 0)) *changed = 1;
            } else {
                hl_type vp = ti_make_ty(HL_TY_VOID, 1, 0, 0);
                if (ti_type_merge(&e->ty, &vp, 0)) *changed = 1;
            }
        }
        break;
    }
    case HLE_DEREF: {
        ti_infer_expr(fn, e->sub0, pinned, changed, depth + 1);
        ti_hint_ptr_var(fn, e->sub0, pinned, changed);
        if (e->sub0 >= 0 && e->sub0 < fn->nexpr) {
            const hl_type *pt = &fn->exprs[e->sub0].ty;
            if (pt->ptr_depth >= 1 && pt->kind != HL_TY_UNK && pt->kind != HL_TY_VOID && pt->kind != HL_TY_PTR &&
                !(pt->kind == HL_TY_STRUCT && pt->ptr_depth == 1)) {
                hl_type deref_t = *pt;
                deref_t.ptr_depth--;
                if (deref_t.ptr_depth == 0) deref_t.is_const = 0;
                if (ti_type_merge(&e->ty, &deref_t, 0)) *changed = 1;
            }
        }
        if (e->ty.kind == HL_TY_UNK) {
            hl_type sc = ti_scalar_from_bits(e->bits ? (int)e->bits : fn->ptr_bits, e->is_flt, e->is_signed);
            if (ti_type_merge(&e->ty, &sc, 0)) *changed = 1;
        }
        break;
    }
    case HLE_FIELD: {
        ti_infer_expr(fn, e->sub0, pinned, changed, depth + 1);
        if (e->ty.kind == HL_TY_UNK) {
            hl_type sc = ti_scalar_from_bits(e->bits ? (int)e->bits : fn->ptr_bits, e->is_flt, e->is_signed);
            if (ti_type_merge(&e->ty, &sc, 0)) *changed = 1;
        }
        break;
    }
    case HLE_INDEX: {
        ti_infer_expr(fn, e->sub0, pinned, changed, depth + 1);
        ti_infer_expr(fn, e->sub1, pinned, changed, depth + 1);
        if (e->sub0 >= 0 && e->sub0 < fn->nexpr) {
            const hl_type *pt = &fn->exprs[e->sub0].ty;
            if (pt->ptr_depth >= 1 && pt->kind != HL_TY_UNK && pt->kind != HL_TY_VOID && pt->kind != HL_TY_PTR &&
                !(pt->kind == HL_TY_STRUCT && pt->ptr_depth == 1)) {
                hl_type elem_t = *pt;
                elem_t.ptr_depth--;
                if (elem_t.ptr_depth == 0) elem_t.is_const = 0;
                if (ti_type_merge(&e->ty, &elem_t, 0)) *changed = 1;
            }
        }
        if (e->ty.kind == HL_TY_UNK) {
            hl_type sc = ti_scalar_from_bits(e->bits ? (int)e->bits : fn->ptr_bits, e->is_flt, e->is_signed);
            if (ti_type_merge(&e->ty, &sc, 0)) *changed = 1;
        }
        break;
    }
    case HLE_UNOP: {
        ti_infer_expr(fn, e->sub0, pinned, changed, depth + 1);
        hl_type ut = ti_make_ty(HL_TY_UNK, 0, 0, 0);
        if (e->op == HLU_LOGNOT) {
            ut = ti_make_ty(HL_TY_BOOL, 0, 0, 8);
        } else if (e->op == HLU_FNEG || e->op == HLU_FABS || e->op == HLU_I2F) {
            ut = ti_make_ty(e->bits == 32 ? HL_TY_F32 : HL_TY_F64, 0, 0, e->bits == 32 ? 32 : 64);
            if (e->op == HLU_FNEG || e->op == HLU_FABS) ti_backprop_type(fn, e->sub0, &ut, pinned, changed);
        } else if (e->op == HLU_F2I) {
            ut = ti_make_ty(e->bits == 32 ? HL_TY_I32 : HL_TY_I64, 0, 0, e->bits == 32 ? 32 : 64);
        } else if (e->op == HLU_ZEXT) {
            ut = ti_make_ty(e->bits == 8 ? HL_TY_U8 : e->bits == 16 ? HL_TY_U16 : e->bits == 32 ? HL_TY_U32 : HL_TY_U64,
                            0, 0, e->bits ? e->bits : 64);
        } else if (e->op == HLU_SEXT) {
            ut = ti_make_ty(e->bits == 8 ? HL_TY_I8 : e->bits == 16 ? HL_TY_I16 : e->bits == 32 ? HL_TY_I32 : HL_TY_I64,
                            0, 0, e->bits ? e->bits : 64);
        } else if (e->op != HLU_CAST) {
            ut = ti_scalar_from_bits(e->bits ? (int)e->bits : fn->ptr_bits, e->is_flt, e->is_signed);
        }
        if (ut.kind != HL_TY_UNK && ti_type_merge(&e->ty, &ut, 0)) *changed = 1;
        break;
    }
    case HLE_BITSET: {
        ti_infer_expr(fn, e->sub0, pinned, changed, depth + 1);
        ti_infer_expr(fn, e->sub1, pinned, changed, depth + 1);
        hl_type bt = ti_make_ty(HL_TY_BOOL, 0, 0, 8);
        if (ti_type_merge(&e->ty, &bt, 0)) *changed = 1;
        break;
    }
    case HLE_BINOP: {
        ti_infer_expr(fn, e->sub0, pinned, changed, depth + 1);
        ti_infer_expr(fn, e->sub1, pinned, changed, depth + 1);
        hl_expr *l = (e->sub0 >= 0 && e->sub0 < fn->nexpr) ? &fn->exprs[e->sub0] : NULL;
        hl_expr *r = (e->sub1 >= 0 && e->sub1 < fn->nexpr) ? &fn->exprs[e->sub1] : NULL;

        if ((e->op >= HLB_EQ && e->op <= HLB_LOR)) {
            hl_type bt = ti_make_ty(HL_TY_BOOL, 0, 0, 8);
            if (ti_type_merge(&e->ty, &bt, 0)) *changed = 1;

            if (e->op >= HLB_EQ && e->op <= HLB_UGE && l && r) {
                hl_type ct = ti_make_ty(HL_TY_CHAR, 0, 0, 8);
                int eq_cmp = (e->op == HLB_EQ || e->op == HLB_NE);
                if (ti_is_char_like(fn, l) && r->kind == HLE_INT &&
                    (eq_cmp ? ti_is_printable_ascii(r->uval) : (r->uval >= 0x20 && r->uval <= 0x7E))) {
                    if (ti_type_merge(&r->ty, &ct, 0)) *changed = 1;
                } else if (ti_is_char_like(fn, r) && l->kind == HLE_INT &&
                           (eq_cmp ? ti_is_printable_ascii(l->uval) : (l->uval >= 0x20 && l->uval <= 0x7E))) {
                    if (ti_type_merge(&l->ty, &ct, 0)) *changed = 1;
                }
                if (e->op >= HLB_SLT && e->op <= HLB_UGE && l->kind == HLE_BINOP && l->op == HLB_SUB &&
                    l->sub0 >= 0 && l->sub1 >= 0 && ti_is_char_like(fn, &fn->exprs[l->sub0]) &&
                    fn->exprs[l->sub1].kind == HLE_INT &&
                    fn->exprs[l->sub1].uval >= 0x20 && fn->exprs[l->sub1].uval <= 0x7E) {
                    if (ti_type_merge(&fn->exprs[l->sub1].ty, &ct, 0)) *changed = 1;
                }
                if ((e->op == HLB_EQ || e->op == HLB_NE) && l->kind == HLE_VAR && r->kind == HLE_VAR) {
                    if (ti_type_rank(&l->ty) >= 6) ti_backprop_type(fn, e->sub1, &l->ty, pinned, changed);
                    else if (ti_type_rank(&r->ty) >= 6) ti_backprop_type(fn, e->sub0, &r->ty, pinned, changed);
                }
            }
        } else if (e->op >= HLB_FADD && e->op <= HLB_FDIV) {
            hl_type ft = ti_make_ty(e->bits == 32 ? HL_TY_F32 : HL_TY_F64, 0, 0, e->bits == 32 ? 32 : 64);
            if (ti_type_merge(&e->ty, &ft, 0)) *changed = 1;
            ti_backprop_type(fn, e->sub0, &ft, pinned, changed);
            ti_backprop_type(fn, e->sub1, &ft, pinned, changed);
        } else if (e->op == HLB_ADD || e->op == HLB_SUB) {
            if (l && r && l->ty.ptr_depth > 0 && r->ty.ptr_depth == 0) {
                if (ti_type_merge(&e->ty, &l->ty, 0)) *changed = 1;
            } else if (e->op == HLB_ADD && l && r && r->ty.ptr_depth > 0 && l->ty.ptr_depth == 0) {
                if (ti_type_merge(&e->ty, &r->ty, 0)) *changed = 1;
            } else {
                hl_type sc = ti_scalar_from_bits(e->bits ? (int)e->bits : fn->ptr_bits, 0, e->is_signed);
                if (ti_type_merge(&e->ty, &sc, 0)) *changed = 1;
            }
        } else {
            int uns = (e->op == HLB_UDIV || e->op == HLB_UMOD || e->op == HLB_SHR);
            hl_type sc = uns ? ti_make_ty(e->bits == 32 ? HL_TY_U32 : HL_TY_U64, 0, 0, e->bits == 32 ? 32 : 64)
                             : ti_scalar_from_bits(e->bits ? (int)e->bits : fn->ptr_bits, e->is_flt, e->is_signed);
            if (ti_type_merge(&e->ty, &sc, 0)) *changed = 1;
        }
        break;
    }
    case HLE_TERNARY: {
        ti_infer_expr(fn, e->sub0, pinned, changed, depth + 1);
        ti_infer_expr(fn, e->sub1, pinned, changed, depth + 1);
        ti_infer_expr(fn, e->sub2, pinned, changed, depth + 1);
        if (e->sub1 >= 0 && e->sub1 < fn->nexpr && ti_type_merge(&e->ty, &fn->exprs[e->sub1].ty, 0)) *changed = 1;
        if (e->sub2 >= 0 && e->sub2 < fn->nexpr && ti_type_merge(&e->ty, &fn->exprs[e->sub2].ty, 0)) *changed = 1;
        break;
    }
    case HLE_CALL: {
        if (e->sub0 >= 0) ti_infer_expr(fn, e->sub0, pinned, changed, depth + 1);
        int nargs = e->narg < HL_MAX_CALL_ARG ? (int)e->narg : HL_MAX_CALL_ARG;
        for (int i = 0; i < nargs; i++) {
            ti_infer_expr(fn, e->args[i], pinned, changed, depth + 1);
        }
        hl_callee_sig csig;
        if (hl_lookup_callee(fn->a, fn->types, e->va, e->sym, &csig)) {
            if (csig.has_ret && csig.ret_ty.kind != HL_TY_UNK) {
                if (ti_type_merge(&e->ty, &csig.ret_ty, 0)) *changed = 1;
            } else if (!csig.has_ret && e->ty.kind == HL_TY_UNK) {
                e->ty = ti_make_ty(HL_TY_VOID, 0, 0, 0);
                *changed = 1;
            }
            for (int i = 0; i < nargs; i++) {
                if (csig.arg_ty[i].kind != HL_TY_UNK) {
                    ti_backprop_type(fn, e->args[i], &csig.arg_ty[i], pinned, changed);
                }
            }
            if (csig.is_vararg && csig.fmt_arg >= 0 && csig.fmt_arg < nargs) {
                char fbuf[256];
                if (ti_read_fmt_str(fn, e->args[csig.fmt_arg], fbuf, sizeof(fbuf))) {
                    int is_scanf = (strstr(e->sym, "scanf") != NULL);
                    hl_type vty[HL_MAX_CALL_ARG];
                    int nv = ti_parse_fmt_arg_types(fbuf, is_scanf, vty, HL_MAX_CALL_ARG);
                    int base = csig.fmt_arg + 1;
                    for (int j = 0; j < nv && (base + j) < nargs; j++) {
                        if (vty[j].kind != HL_TY_UNK) {
                            ti_backprop_type(fn, e->args[base + j], &vty[j], pinned, changed);
                        }
                    }
                }
            }
        }
        break;
    }
    default:
        break;
    }
}

static void ti_propagate_pass(hl_fn *fn, const uint8_t *pinned, int *changed) {
    hl_type vp = ti_make_ty(HL_TY_VOID, 1, 0, 0);
    hl_type szt = ti_make_ty(HL_TY_SIZE_T, 0, 0, 64);

    for (int bi = 0; bi < fn->nblk; bi++) {
        hl_blk *b = &fn->blks[bi];
        for (int si = 0; si < b->nstmt; si++) {
            int sid = b->stmts[si];
            if (sid < 0 || sid >= fn->nstmt) continue;
            hl_stmt *st = &fn->stmts[sid];
            if (st->dead || st->kind == HLS_NOP) continue;

            if (st->kind == HLS_ASSIGN) {
                ti_infer_expr(fn, st->rhs_expr, pinned, changed, 0);
                int cid = ti_var_canon(fn, st->dst_var);
                if (cid >= 0 && st->rhs_expr >= 0 && st->rhs_expr < fn->nexpr) {
                    if (ti_type_merge(&fn->vars[cid].ty, &fn->exprs[st->rhs_expr].ty, pinned[cid])) *changed = 1;
                    ti_backprop_type(fn, st->rhs_expr, &fn->vars[cid].ty, pinned, changed);
                }
            } else if (st->kind == HLS_PHI) {
                int cid = ti_var_canon(fn, st->dst_var);
                if (cid >= 0) {
                    int np = st->nphi < 8 ? (int)st->nphi : 8;
                    for (int k = 0; k < np; k++) {
                        int pid = ti_var_canon(fn, st->phi_vars[k]);
                        if (pid >= 0) {
                            if (ti_type_merge(&fn->vars[cid].ty, &fn->vars[pid].ty, pinned[cid])) *changed = 1;
                            if (ti_type_merge(&fn->vars[pid].ty, &fn->vars[cid].ty, pinned[pid])) *changed = 1;
                        }
                    }
                }
            } else if (st->kind == HLS_STORE) {
                ti_infer_expr(fn, st->lhs_expr, pinned, changed, 0);
                ti_infer_expr(fn, st->rhs_expr, pinned, changed, 0);
                if (st->lhs_expr >= 0 && st->lhs_expr < fn->nexpr &&
                    st->rhs_expr >= 0 && st->rhs_expr < fn->nexpr) {
                    hl_expr *lhs = &fn->exprs[st->lhs_expr];
                    hl_expr *rhs = &fn->exprs[st->rhs_expr];
                    if (ti_type_rank(&rhs->ty) >= 4 && ti_type_merge(&lhs->ty, &rhs->ty, 0)) *changed = 1;
                    if (ti_type_rank(&lhs->ty) >= 4) ti_backprop_type(fn, st->rhs_expr, &lhs->ty, pinned, changed);
                }
            } else if (st->kind == HLS_CALL) {
                ti_infer_expr(fn, st->rhs_expr, pinned, changed, 0);
            } else if (st->kind == HLS_RET) {
                if (st->rhs_expr >= 0 && st->rhs_expr < fn->nexpr) {
                    ti_infer_expr(fn, st->rhs_expr, pinned, changed, 0);
                    if (ti_type_merge(&fn->ret_ty, &fn->exprs[st->rhs_expr].ty, 0)) *changed = 1;
                    if (fn->ret_ty.kind != HL_TY_UNK && fn->ret_ty.kind != HL_TY_VOID) {
                        ti_backprop_type(fn, st->rhs_expr, &fn->ret_ty, pinned, changed);
                    }
                }
            } else if (st->kind == HLS_MEMCPY) {
                ti_infer_expr(fn, st->lhs_expr, pinned, changed, 0);
                ti_infer_expr(fn, st->rhs_expr, pinned, changed, 0);
                ti_infer_expr(fn, st->len_expr, pinned, changed, 0);
                ti_backprop_type(fn, st->lhs_expr, &vp, pinned, changed);
                ti_backprop_type(fn, st->rhs_expr, &vp, pinned, changed);
                ti_backprop_type(fn, st->len_expr, &szt, pinned, changed);
            } else if (st->kind == HLS_MEMSET) {
                ti_infer_expr(fn, st->lhs_expr, pinned, changed, 0);
                ti_infer_expr(fn, st->rhs_expr, pinned, changed, 0);
                ti_infer_expr(fn, st->len_expr, pinned, changed, 0);
                ti_backprop_type(fn, st->lhs_expr, &vp, pinned, changed);
                ti_backprop_type(fn, st->len_expr, &szt, pinned, changed);
            }
        }
        if (b->cond_expr >= 0) ti_infer_expr(fn, b->cond_expr, pinned, changed, 0);
        if (b->sw_expr >= 0) ti_infer_expr(fn, b->sw_expr, pinned, changed, 0);
    }
}

typedef struct {
    int     base_eid;
    int     idx_eid;
    int     scale;
    int64_t disp;
} ti_addr;

typedef struct {
    int eid;
    int coeff;
    int is_scaled;
} ti_term;

static bool ti_same_atom(const hl_fn *fn, int a, int b) {
    if (a == b) return true;
    if (a < 0 || a >= fn->nexpr || b < 0 || b >= fn->nexpr) return false;
    const hl_expr *ea = &fn->exprs[a];
    const hl_expr *eb = &fn->exprs[b];
    if (ea->kind == HLE_VAR && eb->kind == HLE_VAR) {
        return ti_var_canon(fn, ea->var_id) == ti_var_canon(fn, eb->var_id);
    }
    return false;
}

static int ti_unwrap_ext(const hl_fn *fn, int eid) {
    for (int k = 0; k < 4 && eid >= 0 && eid < fn->nexpr; k++) {
        const hl_expr *e = &fn->exprs[eid];
        if (e->kind == HLE_UNOP && !e->is_flt &&
            (e->op == HLU_SEXT || e->op == HLU_ZEXT ||
             (e->op == HLU_CAST && (e->ty.kind == HL_TY_UNK || e->ty.kind == HL_TY_I64 ||
                                    e->ty.kind == HL_TY_U64 || e->ty.kind == HL_TY_PTR ||
                                    (e->ty.kind == HL_TY_VOID && e->ty.ptr_depth > 0))))) {
            eid = e->sub0;
        } else {
            break;
        }
    }
    return eid;
}

static bool ti_extract_scaled(const hl_fn *fn, int eid, int *out_var, int *out_scale, int depth) {
    if (depth > 8 || eid < 0 || eid >= fn->nexpr) return false;
    eid = ti_unwrap_ext(fn, eid);
    if (eid < 0 || eid >= fn->nexpr) return false;
    const hl_expr *e = &fn->exprs[eid];

    if (e->kind == HLE_BINOP && e->op == HLB_MUL) {
        if (e->sub1 >= 0 && e->sub1 < fn->nexpr && fn->exprs[e->sub1].kind == HLE_INT) {
            int64_t c = (int64_t)fn->exprs[e->sub1].uval;
            if (c > 0 && c <= 4096) {
                int v = -1, s = 0;
                if (ti_extract_scaled(fn, e->sub0, &v, &s, depth + 1) && s * c <= 4096) {
                    *out_var = v;
                    *out_scale = (int)(s * c);
                    return true;
                }
            }
        }
        if (e->sub0 >= 0 && e->sub0 < fn->nexpr && fn->exprs[e->sub0].kind == HLE_INT) {
            int64_t c = (int64_t)fn->exprs[e->sub0].uval;
            if (c > 0 && c <= 4096) {
                int v = -1, s = 0;
                if (ti_extract_scaled(fn, e->sub1, &v, &s, depth + 1) && s * c <= 4096) {
                    *out_var = v;
                    *out_scale = (int)(s * c);
                    return true;
                }
            }
        }
        return false;
    }

    if (e->kind == HLE_BINOP && e->op == HLB_SHL) {
        if (e->sub1 >= 0 && e->sub1 < fn->nexpr && fn->exprs[e->sub1].kind == HLE_INT) {
            uint64_t sh = fn->exprs[e->sub1].uval;
            if (sh <= 12) {
                int v = -1, s = 0;
                if (ti_extract_scaled(fn, e->sub0, &v, &s, depth + 1) && (s << sh) <= 4096) {
                    *out_var = v;
                    *out_scale = s << (int)sh;
                    return true;
                }
            }
        }
        return false;
    }

    if (e->kind == HLE_BINOP && (e->op == HLB_ADD || e->op == HLB_SUB)) {
        int va = -1, sa = 0, vb = -1, sb = 0;
        if (ti_extract_scaled(fn, e->sub0, &va, &sa, depth + 1) &&
            ti_extract_scaled(fn, e->sub1, &vb, &sb, depth + 1) &&
            ti_same_atom(fn, va, vb)) {
            int ns = (e->op == HLB_ADD) ? (sa + sb) : (sa - sb);
            if (ns > 0 && ns <= 4096) {
                *out_var = va;
                *out_scale = ns;
                return true;
            }
        }
        return false;
    }

    if (e->kind == HLE_INT) return false;
    *out_var = eid;
    *out_scale = 1;
    return true;
}

static bool ti_flatten_addr(const hl_fn *fn, int eid, int sign, ti_term *terms, int *nterm, int64_t *disp, int depth) {
    if (depth > 12 || eid < 0 || eid >= fn->nexpr) return false;
    const hl_expr *e = &fn->exprs[eid];

    if (e->kind == HLE_INT) {
        *disp += (int64_t)sign * (int64_t)e->uval;
        return true;
    }
    if (e->kind == HLE_UNOP && e->op == HLU_CAST && !e->is_flt &&
        (e->ty.kind == HL_TY_UNK || e->ty.kind == HL_TY_I64 || e->ty.kind == HL_TY_U64 ||
         e->ty.kind == HL_TY_PTR || (e->ty.kind == HL_TY_VOID && e->ty.ptr_depth > 0))) {
        return ti_flatten_addr(fn, e->sub0, sign, terms, nterm, disp, depth + 1);
    }
    if (e->kind == HLE_BINOP && (e->op == HLB_ADD || e->op == HLB_SUB)) {
        if (!ti_flatten_addr(fn, e->sub0, sign, terms, nterm, disp, depth + 1)) return false;
        return ti_flatten_addr(fn, e->sub1, (e->op == HLB_ADD) ? sign : -sign, terms, nterm, disp, depth + 1);
    }

    int v = eid, s = 1;
    int scaled = 0;
    if (ti_extract_scaled(fn, eid, &v, &s, 0) && s > 1) {
        scaled = 1;
    } else {
        v = eid;
        s = 1;
    }

    for (int i = 0; i < *nterm; i++) {
        if (ti_same_atom(fn, terms[i].eid, v)) {
            terms[i].coeff += sign * s;
            if (terms[i].coeff > 1 || terms[i].coeff < -1) terms[i].is_scaled = 1;
            return true;
        }
    }
    if (*nterm >= 8) return false;
    terms[*nterm].eid = v;
    terms[*nterm].coeff = sign * s;
    terms[*nterm].is_scaled = scaled;
    (*nterm)++;
    return true;
}

static int ti_base_score(const hl_fn *fn, int eid) {
    if (eid < 0 || eid >= fn->nexpr) return 0;
    const hl_expr *e = &fn->exprs[eid];
    int sc = 0;
    if (e->ty.ptr_depth > 0 || e->ty.kind == HL_TY_PTR) sc += 100;
    if (e->kind == HLE_ADDR || e->kind == HLE_SYM || e->kind == HLE_DEREF || e->kind == HLE_FIELD) sc += 60;
    if (e->kind == HLE_VAR) {
        int cid = ti_var_canon(fn, e->var_id);
        if (cid >= 0) {
            if (fn->vars[cid].ty.ptr_depth > 0 || fn->vars[cid].ty.kind == HL_TY_PTR) sc += 100;
            if (fn->vars[cid].is_loop_idx) sc -= 80;
            if (fn->vars[cid].bits >= 64) sc += 10;
            if (fn->vars[cid].is_arg) sc += 15;
        }
    }
    return sc;
}

static bool ti_decompose_addr(const hl_fn *fn, int addr_eid, ti_addr *out) {
    out->base_eid = -1;
    out->idx_eid = -1;
    out->scale = 1;
    out->disp = 0;

    ti_term raw[8];
    int nraw = 0;
    if (!ti_flatten_addr(fn, addr_eid, 1, raw, &nraw, &out->disp, 0)) return false;

    ti_term terms[8];
    int nterm = 0;
    for (int i = 0; i < nraw; i++) {
        if (raw[i].coeff != 0) terms[nterm++] = raw[i];
    }

    if (nterm == 1) {
        if (terms[0].coeff == 1 && !terms[0].is_scaled) {
            out->base_eid = terms[0].eid;
            return true;
        }
        return false;
    }

    if (nterm == 2) {
        if (terms[0].coeff == 1 && !terms[0].is_scaled && terms[1].coeff > 1) {
            out->base_eid = terms[0].eid;
            out->idx_eid = terms[1].eid;
            out->scale = terms[1].coeff;
            return true;
        }
        if (terms[1].coeff == 1 && !terms[1].is_scaled && terms[0].coeff > 1) {
            out->base_eid = terms[1].eid;
            out->idx_eid = terms[0].eid;
            out->scale = terms[0].coeff;
            return true;
        }
        if (terms[0].coeff == 1 && terms[1].coeff == 1) {
            int s0 = ti_base_score(fn, terms[0].eid);
            int s1 = ti_base_score(fn, terms[1].eid);
            if (s1 > s0) {
                out->base_eid = terms[1].eid;
                out->idx_eid = terms[0].eid;
            } else {
                out->base_eid = terms[0].eid;
                out->idx_eid = terms[1].eid;
            }
            out->scale = 1;
            return true;
        }
    }

    return false;
}

#define TI_MAX_INC_STEPS 8

typedef struct {
    int64_t offs[TI_MAX_OFFS];
    int     noff;
    int64_t max_off;
    int     min_bits;
    int     max_bits;
    int     has_flt_acc;
    int     has_write;
    int     has_read;
    int     is_incremented;
    int64_t inc_steps[TI_MAX_INC_STEPS];
    int     ninc_steps;
    int     char_cmp_cnt;
    int     has_idx_acc;
    int     idx_scale;
    int     classified;     /* 0 = struct/default, 1 = char/u8 array, 2 = typed uniform array */
    int     arr_elem_bytes; /* 1, 2, 4, 8 */
} ti_var_offs;

static void ti_record_var_off(ti_var_offs *vo, int64_t off) {
    if (off < 0 || off >= 0x4000) return;
    if (off > vo->max_off) vo->max_off = off;
    for (int i = 0; i < vo->noff; i++) {
        if (vo->offs[i] == off) return;
    }
    if (vo->noff < TI_MAX_OFFS) vo->offs[vo->noff++] = off;
}

static void ti_record_inc_step(ti_var_offs *vo, int64_t step) {
    vo->is_incremented = 1;
    if (step < 0) step = -step;
    if (step <= 0 || step > 4096) return;
    for (int i = 0; i < vo->ninc_steps; i++) {
        if (vo->inc_steps[i] == step) return;
    }
    if (vo->ninc_steps < TI_MAX_INC_STEPS) vo->inc_steps[vo->ninc_steps++] = step;
}

static void ti_count_offs_expr(const hl_fn *fn, int eid, uint8_t *vis, int nexpr,
                               ti_var_offs *voffs, int is_store_lhs, int depth) {
    if (depth > 48 || eid < 0 || eid >= nexpr || vis[eid]) return;
    vis[eid] = 1;
    const hl_expr *e = &fn->exprs[eid];

    if (e->sub0 >= 0) ti_count_offs_expr(fn, e->sub0, vis, nexpr, voffs, 0, depth + 1);
    if (e->sub1 >= 0) ti_count_offs_expr(fn, e->sub1, vis, nexpr, voffs, 0, depth + 1);
    if (e->sub2 >= 0) ti_count_offs_expr(fn, e->sub2, vis, nexpr, voffs, 0, depth + 1);
    if (e->kind == HLE_CALL) {
        int na = e->narg < HL_MAX_CALL_ARG ? (int)e->narg : HL_MAX_CALL_ARG;
        for (int i = 0; i < na; i++) ti_count_offs_expr(fn, e->args[i], vis, nexpr, voffs, 0, depth + 1);
    }

    if (e->kind == HLE_DEREF && e->sub0 >= 0) {
        ti_addr ad;
        if (ti_decompose_addr(fn, e->sub0, &ad) && ad.base_eid >= 0 && ad.base_eid < fn->nexpr) {
            const hl_expr *be = &fn->exprs[ad.base_eid];
            if (be->kind == HLE_VAR) {
                int cid = ti_var_canon(fn, be->var_id);
                if (cid >= 0 && cid < fn->nvar) {
                    ti_var_offs *vo = &voffs[cid];
                    int abits = e->bits ? (int)e->bits : fn->ptr_bits;
                    if (abits > 0) {
                        if (vo->min_bits == 0 || abits < vo->min_bits) vo->min_bits = abits;
                        if (abits > vo->max_bits) vo->max_bits = abits;
                    }
                    if (e->is_flt || e->ty.kind == HL_TY_F32 || e->ty.kind == HL_TY_F64) {
                        vo->has_flt_acc = 1;
                    }
                    if (is_store_lhs) vo->has_write = 1;
                    else vo->has_read = 1;

                    if (ad.idx_eid < 0) {
                        ti_record_var_off(vo, ad.disp);
                    } else {
                        vo->has_idx_acc = 1;
                        if (vo->idx_scale == 0) vo->idx_scale = ad.scale;
                        else if (vo->idx_scale != ad.scale) vo->idx_scale = -1;
                        if (ad.disp > 0 && ad.disp < 0x4000 && ad.disp > vo->max_off) {
                            vo->max_off = ad.disp;
                        }
                    }
                }
            }
        }
    }
}

static int ti_expr_byte_load_base(const hl_fn *fn, int eid, const int *loaded_from) {
    eid = ti_unwrap_ext(fn, eid);
    if (eid < 0 || eid >= fn->nexpr) return -1;
    const hl_expr *e = &fn->exprs[eid];
    if (e->kind == HLE_DEREF && e->bits == 8 && e->sub0 >= 0) {
        ti_addr ad;
        if (ti_decompose_addr(fn, e->sub0, &ad) && ad.base_eid >= 0 && ad.base_eid < fn->nexpr) {
            const hl_expr *be = &fn->exprs[ad.base_eid];
            if (be->kind == HLE_VAR) return ti_var_canon(fn, be->var_id);
        }
    }
    if (e->kind == HLE_VAR && loaded_from) {
        int cid = ti_var_canon(fn, e->var_id);
        if (cid >= 0 && cid < fn->nvar) return loaded_from[cid];
    }
    return -1;
}

static void ti_count_char_cmps_expr(const hl_fn *fn, int eid, uint8_t *vis, int nexpr,
                                    const int *loaded_from, ti_var_offs *voffs, int depth) {
    if (depth > 48 || eid < 0 || eid >= nexpr || vis[eid]) return;
    vis[eid] = 1;
    const hl_expr *e = &fn->exprs[eid];

    if (e->sub0 >= 0) ti_count_char_cmps_expr(fn, e->sub0, vis, nexpr, loaded_from, voffs, depth + 1);
    if (e->sub1 >= 0) ti_count_char_cmps_expr(fn, e->sub1, vis, nexpr, loaded_from, voffs, depth + 1);
    if (e->sub2 >= 0) ti_count_char_cmps_expr(fn, e->sub2, vis, nexpr, loaded_from, voffs, depth + 1);
    if (e->kind == HLE_CALL) {
        int na = e->narg < HL_MAX_CALL_ARG ? (int)e->narg : HL_MAX_CALL_ARG;
        for (int i = 0; i < na; i++) {
            ti_count_char_cmps_expr(fn, e->args[i], vis, nexpr, loaded_from, voffs, depth + 1);
        }
    }

    if (e->kind == HLE_BITSET && e->sub0 >= 0) {
        int sub = e->sub0;
        int b = ti_expr_byte_load_base(fn, sub, loaded_from);
        if (b < 0 && sub < fn->nexpr && fn->exprs[sub].kind == HLE_BINOP &&
            fn->exprs[sub].op == HLB_SUB && fn->exprs[sub].sub0 >= 0) {
            b = ti_expr_byte_load_base(fn, fn->exprs[sub].sub0, loaded_from);
        }
        if (b >= 0 && b < fn->nvar) voffs[b].char_cmp_cnt++;
        return;
    }

    if (e->kind == HLE_BINOP && e->op >= HLB_EQ && e->op <= HLB_UGE &&
        e->sub0 >= 0 && e->sub0 < fn->nexpr && e->sub1 >= 0 && e->sub1 < fn->nexpr) {
        const hl_expr *l = &fn->exprs[e->sub0];
        const hl_expr *r = &fn->exprs[e->sub1];
        int eq_cmp = (e->op == HLB_EQ || e->op == HLB_NE);

        int lb = ti_expr_byte_load_base(fn, e->sub0, loaded_from);
        if (lb >= 0 && lb < fn->nvar && r->kind == HLE_INT &&
            (eq_cmp ? ti_is_printable_ascii(r->uval) : (r->uval >= 0x20 && r->uval <= 0x7E))) {
            voffs[lb].char_cmp_cnt++;
        }
        int rb = ti_expr_byte_load_base(fn, e->sub1, loaded_from);
        if (rb >= 0 && rb < fn->nvar && l->kind == HLE_INT &&
            (eq_cmp ? ti_is_printable_ascii(l->uval) : (l->uval >= 0x20 && l->uval <= 0x7E))) {
            voffs[rb].char_cmp_cnt++;
        }
        if (e->op >= HLB_SLT && e->op <= HLB_UGE && l->kind == HLE_BINOP && l->op == HLB_SUB &&
            l->sub0 >= 0 && l->sub1 >= 0 && l->sub1 < fn->nexpr &&
            fn->exprs[l->sub1].kind == HLE_INT &&
            fn->exprs[l->sub1].uval >= 0x20 && fn->exprs[l->sub1].uval <= 0x7E) {
            int sb = ti_expr_byte_load_base(fn, l->sub0, loaded_from);
            if (sb >= 0 && sb < fn->nvar) voffs[sb].char_cmp_cnt++;
        }
    }
}

static void ti_collect_var_profiles(const hl_fn *fn, int init_nexpr, ti_var_offs *voffs, uint8_t *vis) {
    for (int bi = 0; bi < fn->nblk; bi++) {
        const hl_blk *b = &fn->blks[bi];
        for (int si = 0; si < b->nstmt; si++) {
            int sid = b->stmts[si];
            if (sid < 0 || sid >= fn->nstmt) continue;
            const hl_stmt *st = &fn->stmts[sid];
            if (st->dead || st->kind == HLS_NOP) continue;
            if (st->lhs_expr >= 0) {
                ti_count_offs_expr(fn, st->lhs_expr, vis, init_nexpr, voffs, st->kind == HLS_STORE ? 1 : 0, 0);
            }
            if (st->rhs_expr >= 0) ti_count_offs_expr(fn, st->rhs_expr, vis, init_nexpr, voffs, 0, 0);
            if (st->len_expr >= 0) ti_count_offs_expr(fn, st->len_expr, vis, init_nexpr, voffs, 0, 0);

            if ((st->kind == HLS_MEMSET || st->kind == HLS_MEMCPY) && st->lhs_expr >= 0 && st->lhs_expr < fn->nexpr) {
                ti_addr ad;
                if (ti_decompose_addr(fn, st->lhs_expr, &ad) && ad.base_eid >= 0 && ad.base_eid < fn->nexpr &&
                    fn->exprs[ad.base_eid].kind == HLE_VAR) {
                    int cid = ti_var_canon(fn, fn->exprs[ad.base_eid].var_id);
                    if (cid >= 0 && cid < fn->nvar) voffs[cid].has_write = 1;
                }
            }
        }
        if (b->cond_expr >= 0) ti_count_offs_expr(fn, b->cond_expr, vis, init_nexpr, voffs, 0, 0);
        if (b->sw_expr >= 0) ti_count_offs_expr(fn, b->sw_expr, vis, init_nexpr, voffs, 0, 0);
    }

    int *loaded_from = (int *)malloc((size_t)(fn->nvar + 1) * sizeof(int));
    if (loaded_from) {
        for (int i = 0; i <= fn->nvar; i++) loaded_from[i] = -1;
    }

    // Detect pointer stepping (var = var +/- k) and byte-load temp variables
    for (int bi = 0; bi < fn->nblk; bi++) {
        const hl_blk *b = &fn->blks[bi];
        for (int si = 0; si < b->nstmt; si++) {
            int sid = b->stmts[si];
            if (sid < 0 || sid >= fn->nstmt) continue;
            const hl_stmt *st = &fn->stmts[sid];
            if (st->dead || st->kind != HLS_ASSIGN || st->dst_var < 0 ||
                st->rhs_expr < 0 || st->rhs_expr >= fn->nexpr) {
                continue;
            }
            int dst_c = ti_var_canon(fn, st->dst_var);
            if (dst_c < 0 || dst_c >= fn->nvar) continue;
            const hl_expr *rhs = &fn->exprs[st->rhs_expr];

            if (rhs->kind == HLE_BINOP && (rhs->op == HLB_ADD || rhs->op == HLB_SUB) &&
                rhs->sub0 >= 0 && rhs->sub0 < fn->nexpr && rhs->sub1 >= 0 && rhs->sub1 < fn->nexpr) {
                const hl_expr *l = &fn->exprs[rhs->sub0];
                const hl_expr *r = &fn->exprs[rhs->sub1];
                if (l->kind == HLE_VAR && ti_var_canon(fn, l->var_id) == dst_c) {
                    if (r->kind == HLE_INT) {
                        int64_t step = (int64_t)r->uval;
                        if (r->bits == 32) step = (int64_t)(int32_t)r->uval;
                        else if (r->bits == 8) step = (int64_t)(int8_t)r->uval;
                        ti_record_inc_step(&voffs[dst_c], step);
                    } else {
                        voffs[dst_c].is_incremented = 1;
                    }
                } else if (rhs->op == HLB_ADD && r->kind == HLE_VAR && ti_var_canon(fn, r->var_id) == dst_c) {
                    if (l->kind == HLE_INT) {
                        int64_t step = (int64_t)l->uval;
                        if (l->bits == 32) step = (int64_t)(int32_t)l->uval;
                        else if (l->bits == 8) step = (int64_t)(int8_t)l->uval;
                        ti_record_inc_step(&voffs[dst_c], step);
                    } else {
                        voffs[dst_c].is_incremented = 1;
                    }
                }
            }

            if (loaded_from) {
                int src_base = ti_expr_byte_load_base(fn, st->rhs_expr, NULL);
                if (src_base >= 0) loaded_from[dst_c] = src_base;
            }
        }
    }

    // One-hop copy propagation for loaded_from (e.g. c2 = (int)c1)
    if (loaded_from) {
        for (int bi = 0; bi < fn->nblk; bi++) {
            const hl_blk *b = &fn->blks[bi];
            for (int si = 0; si < b->nstmt; si++) {
                int sid = b->stmts[si];
                if (sid < 0 || sid >= fn->nstmt) continue;
                const hl_stmt *st = &fn->stmts[sid];
                if (st->dead || st->kind != HLS_ASSIGN || st->dst_var < 0 || st->rhs_expr < 0) continue;
                int dst_c = ti_var_canon(fn, st->dst_var);
                if (dst_c < 0 || dst_c >= fn->nvar || loaded_from[dst_c] >= 0) continue;
                int u = ti_unwrap_ext(fn, st->rhs_expr);
                if (u >= 0 && u < fn->nexpr && fn->exprs[u].kind == HLE_VAR) {
                    int sc = ti_var_canon(fn, fn->exprs[u].var_id);
                    if (sc >= 0 && sc < fn->nvar && loaded_from[sc] >= 0) {
                        loaded_from[dst_c] = loaded_from[sc];
                    }
                }
            }
        }

        memset(vis, 0, (size_t)init_nexpr);
        for (int bi = 0; bi < fn->nblk; bi++) {
            const hl_blk *b = &fn->blks[bi];
            for (int si = 0; si < b->nstmt; si++) {
                int sid = b->stmts[si];
                if (sid < 0 || sid >= fn->nstmt) continue;
                const hl_stmt *st = &fn->stmts[sid];
                if (st->dead || st->kind == HLS_NOP) continue;
                if (st->lhs_expr >= 0) ti_count_char_cmps_expr(fn, st->lhs_expr, vis, init_nexpr, loaded_from, voffs, 0);
                if (st->rhs_expr >= 0) ti_count_char_cmps_expr(fn, st->rhs_expr, vis, init_nexpr, loaded_from, voffs, 0);
                if (st->len_expr >= 0) ti_count_char_cmps_expr(fn, st->len_expr, vis, init_nexpr, loaded_from, voffs, 0);
            }
            if (b->cond_expr >= 0) ti_count_char_cmps_expr(fn, b->cond_expr, vis, init_nexpr, loaded_from, voffs, 0);
            if (b->sw_expr >= 0) ti_count_char_cmps_expr(fn, b->sw_expr, vis, init_nexpr, loaded_from, voffs, 0);
        }
        free(loaded_from);
    }
}

static bool ti_is_untyped_ptr_var(const hl_type *t) {
    if (!t) return true;
    if (t->kind == HL_TY_UNK) return true;
    if (t->kind == HL_TY_PTR && t->ptr_depth <= 1) return true;
    if (t->kind == HL_TY_VOID && t->ptr_depth == 1) return true;
    if (t->ptr_depth == 0 && (t->kind == HL_TY_I64 || t->kind == HL_TY_U64 ||
                              t->kind == HL_TY_I32 || t->kind == HL_TY_U32)) {
        return true;
    }
    return false;
}

static void ti_classify_array_vars(hl_fn *fn, const uint8_t *pinned, ti_var_offs *voffs) {
    for (int cid = 0; cid < fn->nvar; cid++) {
        if (ti_var_canon(fn, cid) != cid) continue;
        ti_var_offs *vo = &voffs[cid];
        if (vo->min_bits == 0 || vo->max_bits == 0) continue;

        const hl_type *t = &fn->vars[cid].ty;
        // Never override known struct pointers or opaque handle types
        if (t->kind == HL_TY_STRUCT || t->ptr_depth >= 2 ||
            t->kind == HL_TY_HANDLE || t->kind == HL_TY_HMODULE || t->kind == HL_TY_HWND ||
            t->kind == HL_TY_HKEY || t->kind == HL_TY_SOCKET || t->kind == HL_TY_FILE) {
            continue;
        }

        // Preserve already-known char* / uint8_t* / int8_t* as byte arrays for indexing
        if (t->ptr_depth == 1 && (t->kind == HL_TY_CHAR || t->kind == HL_TY_U8 || t->kind == HL_TY_I8) &&
            vo->min_bits == 8 && vo->max_bits == 8 && (!vo->has_idx_acc || vo->idx_scale == 1)) {
            vo->classified = 1;
            vo->arr_elem_bytes = 1;
            continue;
        }

        if (pinned[cid] || !ti_is_untyped_ptr_var(t)) continue;

        // Case (a): All accesses are 8-bit AND (incremented OR char comparisons OR max_off <= 8)
        if (vo->min_bits == 8 && vo->max_bits == 8 && !vo->has_flt_acc &&
            (!vo->has_idx_acc || vo->idx_scale == 1) &&
            (vo->is_incremented || vo->char_cmp_cnt > 0 || vo->max_off <= 8)) {
            if (!vo->has_write) {
                fn->vars[cid].ty = ti_make_ty(HL_TY_CHAR, 1, 1, 8);
            } else {
                fn->vars[cid].ty = ti_make_ty(HL_TY_U8, 1, 0, 8);
            }
            vo->classified = 1;
            vo->arr_elem_bytes = 1;
            continue;
        }

        // Case (b): Uniform element width W (16/32/64) AND incremented with step k*(W/8) AND max_off <= 4*(W/8)
        if (vo->min_bits == vo->max_bits &&
            (vo->min_bits == 16 || vo->min_bits == 32 || vo->min_bits == 64) &&
            vo->is_incremented && vo->ninc_steps > 0) {
            int W = vo->min_bits;
            int eb = W / 8;
            if ((!vo->has_idx_acc || vo->idx_scale == eb) && vo->max_off <= (int64_t)(4 * eb)) {
                int steps_ok = 1;
                for (int i = 0; i < vo->ninc_steps; i++) {
                    int64_t stp = vo->inc_steps[i];
                    if (stp < eb || (stp % eb) != 0 || stp > (int64_t)(4 * eb)) {
                        steps_ok = 0;
                        break;
                    }
                }
                int offs_ok = 1;
                for (int i = 0; i < vo->noff; i++) {
                    if ((vo->offs[i] % eb) != 0) {
                        offs_ok = 0;
                        break;
                    }
                }
                if (steps_ok && offs_ok) {
                    if (vo->has_flt_acc) {
                        fn->vars[cid].ty = ti_make_ty(W == 32 ? HL_TY_F32 : HL_TY_F64, 1, 0, (uint8_t)W);
                    } else if (W == 16) {
                        fn->vars[cid].ty = ti_make_ty(HL_TY_U16, 1, 0, 16);
                    } else if (W == 32) {
                        fn->vars[cid].ty = ti_make_ty(HL_TY_I32, 1, 0, 32);
                    } else {
                        fn->vars[cid].ty = ti_make_ty(HL_TY_I64, 1, 0, 64);
                    }
                    vo->classified = 2;
                    vo->arr_elem_bytes = eb;
                }
            }
        }
    }

    for (int i = 0; i < fn->nvar; i++) {
        int cid = ti_var_canon(fn, i);
        if (cid >= 0 && cid != i && !pinned[i] && voffs[cid].classified != 0) {
            fn->vars[i].ty = fn->vars[cid].ty;
        }
    }
}

static const typ_def *ti_expr_struct_def(const hl_fn *fn, int eid, int *out_base_eid, int *out_is_dot) {
    if (!fn || !fn->types || eid < 0 || eid >= fn->nexpr) return NULL;
    const hl_expr *e = &fn->exprs[eid];

    // &struct_val -> dot access on struct_val
    if (e->kind == HLE_ADDR && e->sub0 >= 0 && e->sub0 < fn->nexpr) {
        const hl_expr *inner = &fn->exprs[e->sub0];
        const hl_type *it = &inner->ty;
        if (inner->kind == HLE_VAR) {
            int cid = ti_var_canon(fn, inner->var_id);
            if (cid >= 0) it = &fn->vars[cid].ty;
        }
        if (it->kind == HL_TY_STRUCT && it->ptr_depth == 0 && it->name[0]) {
            const typ_def *td = typ_find(fn->types, it->name);
            if (td && td->kind == 0) {
                *out_base_eid = e->sub0;
                *out_is_dot = 1;
                return td;
            }
        }
    }

    const hl_type *t = &e->ty;
    if (e->kind == HLE_VAR) {
        int cid = ti_var_canon(fn, e->var_id);
        if (cid >= 0) t = &fn->vars[cid].ty;
    }
    if (t->kind == HL_TY_STRUCT && t->ptr_depth >= 1 && t->name[0]) {
        const typ_def *td = typ_find(fn->types, t->name);
        if (td && td->kind == 0) {
            *out_base_eid = eid;
            *out_is_dot = 0;
            return td;
        }
    }
    return NULL;
}

static const typ_member *ti_find_member(const typ_def *td, int64_t disp, int acc_bytes, int *exact) {
    *exact = 0;
    if (!td || disp < 0) return NULL;
    const typ_member *best = NULL;
    for (int i = 0; i < td->nmem; i++) {
        const typ_member *m = &td->mems[i];
        if ((int64_t)m->off == disp) {
            *exact = 1;
            if (acc_bytes > 0 && m->size == acc_bytes) return m;
            if (!best) best = m;
        }
    }
    if (best) return best;
    for (int i = 0; i < td->nmem; i++) {
        const typ_member *m = &td->mems[i];
        if (disp > (int64_t)m->off && disp < (int64_t)m->off + (int64_t)m->size) return m;
    }
    return NULL;
}

static bool ti_rewrite_struct_field(hl_fn *fn, int eid, int base_eid, int is_dot,
                                    const typ_def *td, int64_t disp, int acc_bytes, int depth) {
    if (depth > 4) return false;
    int exact = 0;
    const typ_member *m = ti_find_member(td, disp, acc_bytes, &exact);
    if (!m) return false;

    hl_type mty;
    bool has_mty = hl_type_parse(fn->types, m->type, &mty);

    if (exact) {
        // if offset 0 of an embedded nested struct and access is smaller, drill into nested member
        if (has_mty && mty.kind == HL_TY_STRUCT && mty.ptr_depth == 0 && acc_bytes > 0 && acc_bytes < m->size) {
            const typ_def *sub_td = typ_find(fn->types, mty.name);
            int sub_exact = 0;
            if (sub_td && sub_td->kind == 0 && ti_find_member(sub_td, 0, acc_bytes, &sub_exact)) {
                int mid = hl_expr_new(fn, HLE_FIELD);
                if (mid >= 0) {
                    fn->exprs[mid].sub0 = base_eid;
                    fn->exprs[mid].disp = m->off;
                    fn->exprs[mid].is_dot = (uint8_t)is_dot;
                    fn->exprs[mid].ty = mty;
                    snprintf(fn->exprs[mid].field, sizeof(fn->exprs[mid].field), "%s", m->name);
                    if (ti_rewrite_struct_field(fn, eid, mid, 1, sub_td, 0, acc_bytes, depth + 1)) return true;
                }
            }
        }
        hl_expr *e = &fn->exprs[eid];
        e->kind = HLE_FIELD;
        e->sub0 = base_eid;
        e->sub1 = -1;
        e->sub2 = -1;
        e->disp = disp;
        e->is_dot = (uint8_t)is_dot;
        e->scale = 0;
        snprintf(e->field, sizeof(e->field), "%s", m->name);
        if (has_mty) e->ty = mty;
        return true;
    }

    // nested struct member inside m
    int64_t rel = disp - (int64_t)m->off;
    if (has_mty && mty.kind == HL_TY_STRUCT && mty.ptr_depth == 0) {
        const typ_def *sub_td = typ_find(fn->types, mty.name);
        if (sub_td && sub_td->kind == 0) {
            int mid = hl_expr_new(fn, HLE_FIELD);
            if (mid < 0) return false;
            fn->exprs[mid].sub0 = base_eid;
            fn->exprs[mid].disp = m->off;
            fn->exprs[mid].is_dot = (uint8_t)is_dot;
            fn->exprs[mid].ty = mty;
            snprintf(fn->exprs[mid].field, sizeof(fn->exprs[mid].field), "%s", m->name);
            return ti_rewrite_struct_field(fn, eid, mid, 1, sub_td, rel, acc_bytes, depth + 1);
        }
    }

    // embedded array member like uint16_t e_res[4]
    const char *lb = strchr(m->type, '[');
    if (lb) {
        char elem_decl[32];
        size_t el = (size_t)(lb - m->type);
        if (el >= sizeof(elem_decl)) el = sizeof(elem_decl) - 1;
        memcpy(elem_decl, m->type, el);
        elem_decl[el] = 0;
        int esz = typ_sizeof(fn->types, elem_decl);
        if (esz > 0 && (rel % esz) == 0) {
            int mid = hl_expr_new(fn, HLE_FIELD);
            int idx = hl_expr_int(fn, (uint64_t)(rel / esz), 32, 0);
            if (mid >= 0 && idx >= 0) {
                fn->exprs[mid].sub0 = base_eid;
                fn->exprs[mid].disp = m->off;
                fn->exprs[mid].is_dot = (uint8_t)is_dot;
                if (has_mty) fn->exprs[mid].ty = mty;
                snprintf(fn->exprs[mid].field, sizeof(fn->exprs[mid].field), "%s", m->name);

                hl_expr *e = &fn->exprs[eid];
                e->kind = HLE_INDEX;
                e->sub0 = mid;
                e->sub1 = idx;
                e->sub2 = -1;
                e->disp = 0;
                e->scale = esz;
                e->is_dot = 0;
                e->field[0] = 0;
                hl_type ety;
                if (hl_type_parse(fn->types, elem_decl, &ety)) e->ty = ety;
                return true;
            }
        }
    }

    return false;
}

static void ti_ensure_vtable_cache(const ana_ctx *a) {
    if (!a || !a->bin.map.data) return;
    if (ti_vt_cache.map_data == a->bin.map.data && ti_vt_cache.map_size == a->bin.map.size &&
        ti_vt_cache.entry == a->bin.entry) {
        return;
    }
    memset(&ti_vt_cache, 0, sizeof(ti_vt_cache));
    ti_vt_cache.map_data = a->bin.map.data;
    ti_vt_cache.map_size = a->bin.map.size;
    ti_vt_cache.entry = a->bin.entry;
    ti_vt_cache.nvt = ir_scan_vtables(a, ti_vt_cache.vts, TI_VTABLE_CACHE_MAX);
}

static bool ti_is_deref_zero(const hl_fn *fn, int eid, int *out_this_eid) {
    if (eid < 0 || eid >= fn->nexpr) return false;
    const hl_expr *e = &fn->exprs[eid];
    if (e->kind == HLE_DEREF && e->sub0 >= 0) {
        *out_this_eid = e->sub0;
        return true;
    }
    if (e->kind == HLE_FIELD && e->disp == 0 && e->is_dot == 0 && e->sub0 >= 0) {
        *out_this_eid = e->sub0;
        return true;
    }
    return false;
}

static int ti_find_var_def_rhs(const hl_fn *fn, int vid) {
    int cid = ti_var_canon(fn, vid);
    if (cid < 0) return -1;
    int rhs = -1;
    int cnt = 0;
    for (int bi = 0; bi < fn->nblk; bi++) {
        const hl_blk *b = &fn->blks[bi];
        for (int si = 0; si < b->nstmt; si++) {
            int sid = b->stmts[si];
            if (sid < 0 || sid >= fn->nstmt) continue;
            const hl_stmt *st = &fn->stmts[sid];
            if (st->dead || st->kind != HLS_ASSIGN) continue;
            if (ti_var_canon(fn, st->dst_var) == cid) {
                rhs = st->rhs_expr;
                cnt++;
            }
        }
    }
    return (cnt == 1) ? rhs : -1;
}

static bool ti_match_vtable_callee(const hl_fn *fn, int sub0, int *out_this_eid, int64_t *out_voff, int *out_fld_eid) {
    *out_this_eid = -1;
    *out_voff = 0;
    *out_fld_eid = -1;
    if (sub0 < 0 || sub0 >= fn->nexpr) return false;

    // unwrap single-def variable holding function pointer
    if (fn->exprs[sub0].kind == HLE_VAR) {
        int rhs = ti_find_var_def_rhs(fn, fn->exprs[sub0].var_id);
        if (rhs >= 0) sub0 = rhs;
    }
    if (sub0 < 0 || sub0 >= fn->nexpr) return false;
    const hl_expr *e = &fn->exprs[sub0];

    int vtbl_eid = -1;
    int64_t voff = 0;

    if (e->kind == HLE_FIELD && !e->is_dot && e->sub0 >= 0) {
        vtbl_eid = e->sub0;
        voff = e->disp;
        *out_fld_eid = sub0;
    } else if (e->kind == HLE_DEREF && e->sub0 >= 0) {
        ti_addr ad;
        if (!ti_decompose_addr(fn, e->sub0, &ad) || ad.idx_eid >= 0 || ad.base_eid < 0) return false;
        vtbl_eid = ad.base_eid;
        voff = ad.disp;
    } else {
        return false;
    }

    if (voff < 0 || voff >= 0x800) return false;

    if (ti_is_deref_zero(fn, vtbl_eid, out_this_eid)) {
        *out_voff = voff;
        return true;
    }
    if (vtbl_eid >= 0 && vtbl_eid < fn->nexpr && fn->exprs[vtbl_eid].kind == HLE_VAR) {
        int rhs = ti_find_var_def_rhs(fn, fn->exprs[vtbl_eid].var_id);
        if (rhs >= 0 && ti_is_deref_zero(fn, rhs, out_this_eid)) {
            *out_voff = voff;
            return true;
        }
    }
    return false;
}

static void ti_resolve_vtable_call(hl_fn *fn, int eid) {
    hl_expr *e = &fn->exprs[eid];
    if (e->kind != HLE_CALL || e->sym[0] != 0 || e->sub0 < 0) return;

    int this_eid = -1;
    int fld_eid = -1;
    int64_t voff = 0;
    if (!ti_match_vtable_callee(fn, e->sub0, &this_eid, &voff, &fld_eid)) return;

    int ptr_bytes = (fn->ptr_bits == 32) ? 4 : 8;
    unsigned slot = (unsigned)(voff / ptr_bytes);

    // check if this_eid has a known class name matching a scanned vtable
    const char *cls_name = NULL;
    if (this_eid >= 0 && this_eid < fn->nexpr) {
        const hl_expr *te = &fn->exprs[this_eid];
        const hl_type *tt = &te->ty;
        if (te->kind == HLE_VAR) {
            int cid = ti_var_canon(fn, te->var_id);
            if (cid >= 0) tt = &fn->vars[cid].ty;
        }
        if (tt->kind == HL_TY_STRUCT && tt->name[0]) cls_name = tt->name;
    }

    if (cls_name && fn->a) {
        ti_ensure_vtable_cache(fn->a);
        for (int i = 0; i < ti_vt_cache.nvt; i++) {
            const ir_vtable *vt = &ti_vt_cache.vts[i];
            if (slot >= vt->nentry) continue;
            if (strcmp(vt->cls, cls_name) == 0 || strstr(vt->cls, cls_name) != NULL) {
                uint64_t mva = 0;
                if (bin_read(&fn->a->bin, vt->va + (uint64_t)slot * (uint64_t)ptr_bytes,
                             (uint8_t *)&mva, (size_t)ptr_bytes) == (size_t)ptr_bytes) {
                    const char *msym = ana_sym_at(fn->a, mva);
                    if (msym && msym[0]) {
                        snprintf(e->sym, sizeof(e->sym), "%s", msym);
                        e->va = mva;
                    } else {
                        snprintf(e->sym, sizeof(e->sym), "%s::vtable_slot_%02x", cls_name, slot);
                        e->va = mva;
                    }
                    if (fld_eid >= 0 && fld_eid < fn->nexpr) {
                        snprintf(fn->exprs[fld_eid].field, sizeof(fn->exprs[fld_eid].field), "vtable_slot_%02x", slot);
                    }
                    return;
                }
            }
        }
    }

    snprintf(e->sym, sizeof(e->sym), "vtable_slot_%02x", slot);
    if (fld_eid >= 0 && fld_eid < fn->nexpr) {
        snprintf(fn->exprs[fld_eid].field, sizeof(fn->exprs[fld_eid].field), "vtable_slot_%02x", slot);
    }
}

static void ti_rewrite_expr(hl_fn *fn, int eid, uint8_t *vis, int init_nexpr, const ti_var_offs *voffs, int depth) {
    if (depth > 48 || eid < 0 || eid >= init_nexpr || vis[eid]) return;
    vis[eid] = 1;

    // copy child indices before recursion so realloc in hl_expr_new cannot invalidate pointers
    int sub0 = fn->exprs[eid].sub0;
    int sub1 = fn->exprs[eid].sub1;
    int sub2 = fn->exprs[eid].sub2;
    int is_call = (fn->exprs[eid].kind == HLE_CALL);
    int narg = is_call ? (fn->exprs[eid].narg < HL_MAX_CALL_ARG ? (int)fn->exprs[eid].narg : HL_MAX_CALL_ARG) : 0;
    int cargs[HL_MAX_CALL_ARG];
    for (int i = 0; i < narg; i++) cargs[i] = fn->exprs[eid].args[i];

    if (sub0 >= 0) ti_rewrite_expr(fn, sub0, vis, init_nexpr, voffs, depth + 1);
    if (sub1 >= 0) ti_rewrite_expr(fn, sub1, vis, init_nexpr, voffs, depth + 1);
    if (sub2 >= 0) ti_rewrite_expr(fn, sub2, vis, init_nexpr, voffs, depth + 1);
    for (int i = 0; i < narg; i++) ti_rewrite_expr(fn, cargs[i], vis, init_nexpr, voffs, depth + 1);

    if (fn->exprs[eid].kind == HLE_CALL) {
        ti_resolve_vtable_call(fn, eid);
        return;
    }

    if (fn->exprs[eid].kind != HLE_DEREF) return;

    int addr_eid = fn->exprs[eid].sub0;
    if (addr_eid < 0 || addr_eid >= fn->nexpr) return;

    ti_addr ad;
    if (!ti_decompose_addr(fn, addr_eid, &ad) || ad.base_eid < 0 || ad.base_eid >= fn->nexpr) return;

    int elem_bits = fn->exprs[eid].bits ? (int)fn->exprs[eid].bits : fn->ptr_bits;
    int elem_bytes = elem_bits / 8;
    if (elem_bytes <= 0) elem_bytes = 1;

    int sbase = -1, sdot = 0;
    const typ_def *td = ti_expr_struct_def(fn, ad.base_eid, &sbase, &sdot);
    if (td) {
        if (ad.idx_eid < 0 && ad.disp >= 0) {
            if (ti_rewrite_struct_field(fn, eid, sbase, sdot, td, ad.disp, elem_bytes, 0)) return;
        } else if (ad.idx_eid >= 0 && !sdot && td->size > 0 && ad.scale == td->size && ad.disp >= 0) {
            int exact = 0;
            if (ti_find_member(td, ad.disp, elem_bytes, &exact)) {
                int idx_node = hl_expr_new(fn, HLE_INDEX);
                if (idx_node >= 0) {
                    fn->exprs[idx_node].sub0 = sbase;
                    fn->exprs[idx_node].sub1 = ad.idx_eid;
                    fn->exprs[idx_node].sub2 = -1;
                    fn->exprs[idx_node].scale = ad.scale;
                    fn->exprs[idx_node].ty.kind = HL_TY_STRUCT;
                    fn->exprs[idx_node].ty.ptr_depth = 0;
                    snprintf(fn->exprs[idx_node].ty.name, sizeof(fn->exprs[idx_node].ty.name), "%s", td->name);
                    if (ti_rewrite_struct_field(fn, eid, idx_node, 1, td, ad.disp, elem_bytes, 0)) return;
                }
            }
        } else if (ad.idx_eid >= 0 && ad.disp >= 0) {
            // indexed access into an embedded array field of td: s->arr[i]
            int exact = 0;
            const typ_member *m = ti_find_member(td, ad.disp, 0, &exact);
            if (m && exact) {
                const char *lb = strchr(m->type, '[');
                if (lb) {
                    char edecl[32];
                    size_t el = (size_t)(lb - m->type);
                    if (el >= sizeof(edecl)) el = sizeof(edecl) - 1;
                    memcpy(edecl, m->type, el);
                    edecl[el] = 0;
                    int esz = typ_sizeof(fn->types, edecl);
                    if (esz > 0 && ad.scale == esz) {
                        int mid = hl_expr_new(fn, HLE_FIELD);
                        if (mid >= 0) {
                            fn->exprs[mid].sub0 = sbase;
                            fn->exprs[mid].disp = ad.disp;
                            fn->exprs[mid].is_dot = (uint8_t)sdot;
                            snprintf(fn->exprs[mid].field, sizeof(fn->exprs[mid].field), "%s", m->name);
                            hl_type fty;
                            if (hl_type_parse(fn->types, m->type, &fty)) fn->exprs[mid].ty = fty;

                            hl_expr *e = &fn->exprs[eid];
                            e->kind = HLE_INDEX;
                            e->sub0 = mid;
                            e->sub1 = ad.idx_eid;
                            e->sub2 = -1;
                            e->disp = 0;
                            e->scale = ad.scale;
                            e->is_dot = 0;
                            e->field[0] = 0;
                            hl_type ety;
                            if (hl_type_parse(fn->types, edecl, &ety)) e->ty = ety;
                            return;
                        }
                    }
                }
            }
        }
    }

    if (ad.idx_eid >= 0) {
        if (ad.disp == 0 && (ad.scale == 1 || ad.scale == 2 || ad.scale == 4 || ad.scale == 8) &&
            (ad.scale == elem_bytes || (ad.scale == 1 && elem_bits == 8))) {
            hl_expr *e = &fn->exprs[eid];
            e->kind = HLE_INDEX;
            e->sub0 = ad.base_eid;
            e->sub1 = ad.idx_eid;
            e->sub2 = -1;
            e->disp = 0;
            e->scale = ad.scale;
            e->is_dot = 0;
            e->field[0] = 0;
            return;
        }
        if (ad.disp < 0 && (-ad.disp) % ad.scale == 0 && (-ad.disp) / ad.scale <= 16 &&
            (ad.scale == 1 || ad.scale == 2 || ad.scale == 4 || ad.scale == 8) && ad.scale == elem_bytes) {
            int sub_k = hl_expr_int(fn, (uint64_t)((-ad.disp) / ad.scale), 32, 0);
            int adj_idx = (sub_k >= 0) ? hl_expr_binop(fn, HLB_SUB, ad.idx_eid, sub_k, 64) : -1;
            if (adj_idx >= 0) {
                hl_expr *e = &fn->exprs[eid];
                e->kind = HLE_INDEX;
                e->sub0 = ad.base_eid;
                e->sub1 = adj_idx;
                e->sub2 = -1;
                e->disp = 0;
                e->scale = ad.scale;
                e->is_dot = 0;
                e->field[0] = 0;
                return;
            }
        }
        if (ad.scale >= 8 && ad.disp >= 0 && ad.disp < 0x1000 && (ad.disp != 0 || ad.scale > elem_bytes)) {
            int idx_node = hl_expr_new(fn, HLE_INDEX);
            if (idx_node >= 0) {
                fn->exprs[idx_node].sub0 = ad.base_eid;
                fn->exprs[idx_node].sub1 = ad.idx_eid;
                fn->exprs[idx_node].sub2 = -1;
                fn->exprs[idx_node].scale = ad.scale;
                fn->exprs[idx_node].bits = (uint8_t)fn->ptr_bits;

                hl_expr *e = &fn->exprs[eid];
                e->kind = HLE_FIELD;
                e->sub0 = idx_node;
                e->sub1 = -1;
                e->sub2 = -1;
                e->disp = ad.disp;
                e->is_dot = 1;
                e->scale = 0;
                snprintf(e->field, sizeof(e->field), "f_%02llx", (unsigned long long)ad.disp);
                return;
            }
        }
        return;
    }

    const hl_expr *be = &fn->exprs[ad.base_eid];
    if (be->kind == HLE_ADDR || be->kind == HLE_SYM) return;

    if (be->kind == HLE_VAR) {
        int cid = ti_var_canon(fn, be->var_id);
        int noff = (cid >= 0 && cid < fn->nvar) ? voffs[cid].noff : 0;

        // Case (a)/(b): classified string/byte or uniform typed array pointer -> *base / base[k]
        if (cid >= 0 && cid < fn->nvar && ad.disp >= 0) {
            const ti_var_offs *vo = &voffs[cid];
            if (vo->classified == 1 && elem_bits == 8 && ad.disp < 64) {
                hl_type ety = fn->vars[cid].ty;
                ety.ptr_depth = 0;
                ety.is_const = 0;
                fn->exprs[ad.base_eid].ty = fn->vars[cid].ty;
                if (ad.disp == 0) {
                    fn->exprs[eid].sub0 = ad.base_eid;
                    fn->exprs[eid].disp = 0;
                    fn->exprs[eid].ty = ety;
                    return;
                }
                int cidx = hl_expr_int(fn, (uint64_t)ad.disp, 32, 0);
                if (cidx >= 0) {
                    hl_expr *e = &fn->exprs[eid];
                    e->kind = HLE_INDEX;
                    e->sub0 = ad.base_eid;
                    e->sub1 = cidx;
                    e->sub2 = -1;
                    e->disp = 0;
                    e->scale = 1;
                    e->is_dot = 0;
                    e->field[0] = 0;
                    e->ty = ety;
                    return;
                }
            }
            if (vo->classified == 2 && vo->arr_elem_bytes > 0 && vo->arr_elem_bytes == elem_bytes &&
                ad.disp <= (int64_t)(4 * vo->arr_elem_bytes) && (ad.disp % vo->arr_elem_bytes) == 0) {
                hl_type ety = fn->vars[cid].ty;
                ety.ptr_depth = 0;
                ety.is_const = 0;
                fn->exprs[ad.base_eid].ty = fn->vars[cid].ty;
                if (ad.disp == 0) {
                    fn->exprs[eid].sub0 = ad.base_eid;
                    fn->exprs[eid].disp = 0;
                    fn->exprs[eid].ty = ety;
                    return;
                }
                int cidx = hl_expr_int(fn, (uint64_t)(ad.disp / vo->arr_elem_bytes), 32, 0);
                if (cidx >= 0) {
                    hl_expr *e = &fn->exprs[eid];
                    e->kind = HLE_INDEX;
                    e->sub0 = ad.base_eid;
                    e->sub1 = cidx;
                    e->sub2 = -1;
                    e->disp = 0;
                    e->scale = vo->arr_elem_bytes;
                    e->is_dot = 0;
                    e->field[0] = 0;
                    e->ty = ety;
                    return;
                }
            }
        }

        // keep *str clean when only offset 0 is ever accessed
        if (ad.disp == 0 && noff < 2) {
            fn->exprs[eid].sub0 = ad.base_eid;
            if (cid >= 0 && cid < fn->nvar) fn->exprs[ad.base_eid].ty = fn->vars[cid].ty;
            return;
        }

        // char * / wchar_t * deref or constant indexing (never str->f_00 / str->f_01)
        if (cid >= 0 && ad.disp >= 0 && ad.disp < 64) {
            const hl_type *bt = &fn->vars[cid].ty;
            if (bt->ptr_depth == 1 && bt->kind == HL_TY_CHAR && elem_bits == 8) {
                fn->exprs[ad.base_eid].ty = *bt;
                if (ad.disp == 0) {
                    fn->exprs[eid].sub0 = ad.base_eid;
                    fn->exprs[eid].ty = ti_make_ty(HL_TY_CHAR, 0, 0, 8);
                    return;
                }
                int cidx = hl_expr_int(fn, (uint64_t)ad.disp, 32, 0);
                if (cidx >= 0) {
                    hl_expr *e = &fn->exprs[eid];
                    e->kind = HLE_INDEX;
                    e->sub0 = ad.base_eid;
                    e->sub1 = cidx;
                    e->sub2 = -1;
                    e->disp = 0;
                    e->scale = 1;
                    e->is_dot = 0;
                    e->field[0] = 0;
                    e->ty = ti_make_ty(HL_TY_CHAR, 0, 0, 8);
                    return;
                }
            }
            if (bt->ptr_depth == 1 && bt->kind == HL_TY_WCHAR && elem_bits == 16 && (ad.disp & 1) == 0) {
                fn->exprs[ad.base_eid].ty = *bt;
                if (ad.disp == 0) {
                    fn->exprs[eid].sub0 = ad.base_eid;
                    fn->exprs[eid].ty = ti_make_ty(HL_TY_WCHAR, 0, 0, 16);
                    return;
                }
                int cidx = hl_expr_int(fn, (uint64_t)(ad.disp / 2), 32, 0);
                if (cidx >= 0) {
                    hl_expr *e = &fn->exprs[eid];
                    e->kind = HLE_INDEX;
                    e->sub0 = ad.base_eid;
                    e->sub1 = cidx;
                    e->sub2 = -1;
                    e->disp = 0;
                    e->scale = 2;
                    e->is_dot = 0;
                    e->field[0] = 0;
                    e->ty = ti_make_ty(HL_TY_WCHAR, 0, 0, 16);
                    return;
                }
            }
        }

        if (ad.disp >= 0 && ad.disp < 0x1000 && (ad.disp > 0 || noff >= 2)) {
            hl_expr *e = &fn->exprs[eid];
            e->kind = HLE_FIELD;
            e->sub0 = ad.base_eid;
            e->sub1 = -1;
            e->sub2 = -1;
            e->disp = ad.disp;
            e->is_dot = 0;
            e->scale = 0;
            snprintf(e->field, sizeof(e->field), "f_%02llx", (unsigned long long)ad.disp);
            return;
        }
    } else if ((be->kind == HLE_DEREF || be->kind == HLE_FIELD || be->kind == HLE_INDEX) &&
               ad.disp > 0 && ad.disp < 0x1000) {
        hl_expr *e = &fn->exprs[eid];
        e->kind = HLE_FIELD;
        e->sub0 = ad.base_eid;
        e->sub1 = -1;
        e->sub2 = -1;
        e->disp = ad.disp;
        e->is_dot = 0;
        e->scale = 0;
        snprintf(e->field, sizeof(e->field), "f_%02llx", (unsigned long long)ad.disp);
    }
}

void hl_infer_types(hl_fn *fn) {
    if (!fn) return;

    uint8_t *pinned = (uint8_t *)calloc((size_t)(fn->nvar + 1), sizeof(uint8_t));
    if (!pinned) return;

    for (int i = 0; i < fn->nvar; i++) {
        hl_var *v = &fn->vars[i];
        if (v->ty.kind == HL_TY_UNK && v->is_flt) {
            int fb = (v->bits == 32) ? 32 : 64;
            v->ty = ti_make_ty(fb == 32 ? HL_TY_F32 : HL_TY_F64, 0, 0, (uint8_t)fb);
        }
    }

    if (fn->a && fn->g && fn->a->lvars && fn->a->nlvar > 0) {
        uint64_t fva = fn->g->func_va;
        for (uint32_t li = 0; li < fn->a->nlvar; li++) {
            const ana_lvar *lv = &fn->a->lvars[li];
            if (lv->func_va != fva || !lv->orig[0]) continue;
            for (int vi = 0; vi < fn->nvar; vi++) {
                hl_var *v = &fn->vars[vi];
                if (strcmp(v->orig, lv->orig) != 0 && strcmp(v->name, lv->orig) != 0) continue;
                int cid = ti_var_canon(fn, vi);
                if (lv->name[0]) {
                    snprintf(v->name, sizeof(v->name), "%s", lv->name);
                    if (cid >= 0 && cid != vi) snprintf(fn->vars[cid].name, sizeof(fn->vars[cid].name), "%s", lv->name);
                }
                if (lv->type[0]) {
                    hl_type parsed;
                    if (hl_type_parse(fn->types, lv->type, &parsed)) {
                        v->ty = parsed;
                        pinned[vi] = 1;
                        if (cid >= 0 && cid != vi) {
                            fn->vars[cid].ty = parsed;
                            pinned[cid] = 1;
                        }
                    }
                }
            }
        }
    }

    for (int iter = 0; iter < 4; iter++) {
        int changed = 0;
        ti_propagate_pass(fn, pinned, &changed);
        if (!changed) break;
    }

    for (int i = 0; i < fn->nvar; i++) {
        int cid = ti_var_canon(fn, i);
        if (cid >= 0 && cid != i && !pinned[i]) fn->vars[i].ty = fn->vars[cid].ty;
    }

    int init_nexpr = fn->nexpr;
    if (init_nexpr > 0) {
        ti_var_offs *voffs = (ti_var_offs *)calloc((size_t)(fn->nvar + 1), sizeof(ti_var_offs));
        uint8_t *vis = (uint8_t *)calloc((size_t)init_nexpr, sizeof(uint8_t));
        if (voffs && vis) {
            ti_collect_var_profiles(fn, init_nexpr, voffs, vis);
            ti_classify_array_vars(fn, pinned, voffs);

            memset(vis, 0, (size_t)init_nexpr);
            for (int bi = 0; bi < fn->nblk; bi++) {
                const hl_blk *b = &fn->blks[bi];
                for (int si = 0; si < b->nstmt; si++) {
                    int sid = b->stmts[si];
                    if (sid < 0 || sid >= fn->nstmt) continue;
                    const hl_stmt *st = &fn->stmts[sid];
                    if (st->dead || st->kind == HLS_NOP) continue;
                    if (st->lhs_expr >= 0) ti_rewrite_expr(fn, st->lhs_expr, vis, init_nexpr, voffs, 0);
                    if (st->rhs_expr >= 0) ti_rewrite_expr(fn, st->rhs_expr, vis, init_nexpr, voffs, 0);
                    if (st->len_expr >= 0) ti_rewrite_expr(fn, st->len_expr, vis, init_nexpr, voffs, 0);
                }
                if (b->cond_expr >= 0) ti_rewrite_expr(fn, b->cond_expr, vis, init_nexpr, voffs, 0);
                if (b->sw_expr >= 0) ti_rewrite_expr(fn, b->sw_expr, vis, init_nexpr, voffs, 0);
            }
        }
        free(vis);
        free(voffs);
    }

    // propagate newly recovered struct member and array/string element types to vars and return type
    for (int iter = 0; iter < 2; iter++) {
        int changed = 0;
        ti_propagate_pass(fn, pinned, &changed);
        if (!changed) break;
    }

    if (fn->ret_ty.kind == HL_TY_UNK) {
        if (!fn->has_ret_val) {
            fn->ret_ty = ti_make_ty(HL_TY_VOID, 0, 0, 0);
        } else {
            fn->ret_ty = ti_make_ty(fn->is_x86_32 ? HL_TY_I32 : HL_TY_I64, 0, 0, fn->is_x86_32 ? 32 : 64);
        }
    }

    for (int i = 0; i < fn->nvar; i++) {
        int cid = ti_var_canon(fn, i);
        if (cid >= 0 && cid != i && !pinned[i]) fn->vars[i].ty = fn->vars[cid].ty;
        hl_var *v = &fn->vars[i];
        if (v->ty.kind == HL_TY_UNK) {
            if (v->is_flt) {
                int fb = (v->bits == 32) ? 32 : 64;
                v->ty = ti_make_ty(fb == 32 ? HL_TY_F32 : HL_TY_F64, 0, 0, (uint8_t)fb);
            } else if (v->bits == 8) {
                v->ty = ti_make_ty(HL_TY_U8, 0, 0, 8);
            } else if (v->bits == 16) {
                v->ty = ti_make_ty(HL_TY_U16, 0, 0, 16);
            } else if (v->bits == 32) {
                v->ty = ti_make_ty(HL_TY_I32, 0, 0, 32);
            } else {
                v->ty = ti_make_ty(fn->is_x86_32 ? HL_TY_I32 : HL_TY_I64, 0, 0, fn->is_x86_32 ? 32 : 64);
            }
        }
    }

    free(pinned);
}
