#include "map.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdlib.h>
#include <string.h>

static wchar_t *map_utf8_to_wide(const char *path, wchar_t *stack_buf, size_t stack_cap) {
    int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, NULL, 0);
    UINT cp = CP_UTF8;
    DWORD flags = MB_ERR_INVALID_CHARS;
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

bool map_open(map_file *m, const char *path) {
    memset(m, 0, sizeof(*m));
    if (!path || !path[0]) return false;

    wchar_t wstack[1024];
    wchar_t *wpath = map_utf8_to_wide(path, wstack, 1024);
    if (!wpath) return false;

    HANDLE fh = CreateFileW(wpath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (wpath != wstack) free(wpath);
    if (fh == INVALID_HANDLE_VALUE) return false;

    LARGE_INTEGER sz;
    if (!GetFileSizeEx(fh, &sz) || sz.QuadPart <= 0) {
        CloseHandle(fh);
        return false;
    }

    // cow keeps disk file untouched
    HANDLE mh = CreateFileMappingW(fh, NULL, PAGE_WRITECOPY, 0, 0, NULL);
    int writable = 1;
    DWORD access = FILE_MAP_COPY;
    if (!mh) {
        mh = CreateFileMappingW(fh, NULL, PAGE_READONLY, 0, 0, NULL);
        writable = 0;
        access = FILE_MAP_READ;
    }
    if (!mh) {
        CloseHandle(fh);
        return false;
    }

    void *view = MapViewOfFile(mh, access, 0, 0, 0);
    if (!view) {
        CloseHandle(mh);
        CloseHandle(fh);
        return false;
    }

    m->data = (uint8_t *)view;
    m->size = (uint64_t)sz.QuadPart;
    m->fh = fh;
    m->mh = mh;
    m->writable = writable;
    return true;
}

bool map_open_buf(map_file *m, uint8_t *buf, uint64_t size, int take_owner) {
    memset(m, 0, sizeof(*m));
    if (!buf || size == 0) return false;
    m->data = buf;
    m->size = size;
    m->writable = 1;
    m->owned = take_owner;
    return true;
}

void map_close(map_file *m) {
    if (!m) return;
    if (m->mh) {
        if (m->data) UnmapViewOfFile(m->data);
        CloseHandle((HANDLE)m->mh);
        CloseHandle((HANDLE)m->fh);
    } else if (m->owned && m->data) {
        free(m->data);
    }
    memset(m, 0, sizeof(*m));
}
