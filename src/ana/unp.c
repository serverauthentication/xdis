#include "ana.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define UNP_HT_CAP         8192u
#define UNP_HT_MASK        (UNP_HT_CAP - 1u)
#define UNP_MAX_HASH_INSNS 65536
#define UNP_MAX_FUNC_INSNS 512

typedef struct {
    uint32_t    hash;
    const char *algo;
    const char *api;
} unp_ht_ent;

typedef struct {
    const char *dll;
    const char *fn;
    const char *label;
} unp_msf_ent;

enum {
    UNP_REG_NONE = 0,
    UNP_REG_IMM  = 1,
    UNP_REG_ADDR = 2
};

enum {
    UNP_OP_NONE = 0,
    UNP_OP_XOR  = 1,
    UNP_OP_ADD  = 2,
    UNP_OP_SUB  = 3,
    UNP_OP_ROL  = 4,
    UNP_OP_ROR  = 5
};

static const char *const unp_api_names[] = {
    "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
    "GetProcAddress", "FreeLibrary", "FreeLibraryAndExitThread",
    "GetModuleHandleA", "GetModuleHandleW", "GetModuleHandleExA", "GetModuleHandleExW",
    "GetModuleFileNameA", "GetModuleFileNameW", "GetModuleFileNameExA", "GetModuleFileNameExW",
    "LdrLoadDll", "LdrGetProcedureAddress", "LdrGetDllHandle", "LdrUnloadDll",
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
    "VirtualFree", "VirtualFreeEx", "VirtualQuery", "VirtualQueryEx",
    "HeapAlloc", "HeapReAlloc", "HeapFree", "HeapCreate", "HeapDestroy", "GetProcessHeap",
    "GlobalAlloc", "GlobalReAlloc", "GlobalFree", "GlobalLock", "GlobalUnlock",
    "LocalAlloc", "LocalReAlloc", "LocalFree",
    "MapViewOfFile", "MapViewOfFileEx", "UnmapViewOfFile",
    "CreateFileMappingA", "CreateFileMappingW", "OpenFileMappingA", "OpenFileMappingW",
    "RtlMoveMemory", "RtlCopyMemory", "RtlZeroMemory", "RtlFillMemory",
    "RtlAllocateHeap", "RtlFreeHeap", "RtlReAllocateHeap",
    "RtlDecompressBuffer", "RtlDecompressBufferEx", "RtlCompressBuffer", "RtlGetCompressionWorkSpaceSize",
    "NtAllocateVirtualMemory", "NtProtectVirtualMemory", "NtFreeVirtualMemory",
    "NtWriteVirtualMemory", "NtReadVirtualMemory", "NtQueryVirtualMemory",
    "NtUnmapViewOfSection", "NtMapViewOfSection", "NtCreateSection", "NtOpenSection",
    "ZwAllocateVirtualMemory", "ZwProtectVirtualMemory", "ZwWriteVirtualMemory",
    "ZwReadVirtualMemory", "ZwUnmapViewOfSection", "ZwMapViewOfSection",
    "CreateFileA", "CreateFileW", "ReadFile", "WriteFile", "CloseHandle",
    "DeleteFileA", "DeleteFileW", "CopyFileA", "CopyFileW",
    "MoveFileA", "MoveFileW", "MoveFileExA", "MoveFileExW",
    "GetFileSize", "GetFileSizeEx", "SetFilePointer", "SetFilePointerEx",
    "GetFileAttributesA", "GetFileAttributesW", "SetFileAttributesA", "SetFileAttributesW",
    "FindFirstFileA", "FindFirstFileW", "FindNextFileA", "FindNextFileW", "FindClose",
    "CreateDirectoryA", "CreateDirectoryW", "RemoveDirectoryA", "RemoveDirectoryW",
    "GetTempPathA", "GetTempPathW", "GetTempFileNameA", "GetTempFileNameW",
    "GetSystemDirectoryA", "GetSystemDirectoryW", "GetWindowsDirectoryA", "GetWindowsDirectoryW",
    "GetCurrentDirectoryA", "GetCurrentDirectoryW", "SetCurrentDirectoryA", "SetCurrentDirectoryW",
    "ExpandEnvironmentStringsA", "ExpandEnvironmentStringsW", "FlushFileBuffers", "SetEndOfFile",
    "CreatePipe", "PeekNamedPipe", "DeviceIoControl",
    "NtCreateFile", "NtOpenFile", "NtReadFile", "NtWriteFile", "NtClose", "NtDeleteFile",
    "CreateProcessA", "CreateProcessW", "CreateProcessInternalW",
    "CreateProcessAsUserA", "CreateProcessAsUserW", "CreateProcessWithLogonW", "CreateProcessWithTokenW",
    "OpenProcess", "TerminateProcess", "ExitProcess", "GetCurrentProcess", "GetCurrentProcessId",
    "CreateThread", "CreateRemoteThread", "CreateRemoteThreadEx",
    "OpenThread", "TerminateThread", "ExitThread", "GetCurrentThread", "GetCurrentThreadId",
    "ResumeThread", "SuspendThread", "GetThreadContext", "SetThreadContext", "QueueUserAPC",
    "WriteProcessMemory", "ReadProcessMemory",
    "WaitForSingleObject", "WaitForMultipleObjects", "GetExitCodeProcess", "GetExitCodeThread",
    "DuplicateHandle", "CreateToolhelp32Snapshot",
    "Process32First", "Process32FirstW", "Process32Next", "Process32NextW",
    "Module32First", "Module32FirstW", "Module32Next", "Module32NextW",
    "Thread32First", "Thread32Next", "EnumProcesses", "EnumProcessModules",
    "GetModuleBaseNameA", "GetModuleBaseNameW",
    "NtCreateThreadEx", "NtOpenProcess", "NtTerminateProcess",
    "NtResumeThread", "NtSuspendThread", "NtGetContextThread", "NtSetContextThread",
    "NtQueueApcThread", "NtQueryInformationProcess", "NtSetInformationProcess",
    "NtQueryInformationThread", "NtSetInformationThread", "NtQuerySystemInformation",
    "NtDelayExecution", "RtlCreateUserThread", "RtlExitUserThread", "RtlExitUserProcess",
    "ZwCreateThreadEx", "ZwQuerySystemInformation", "ZwQueryInformationProcess",
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "OutputDebugStringA", "OutputDebugStringW",
    "SetUnhandledExceptionFilter", "AddVectoredExceptionHandler", "RemoveVectoredExceptionHandler",
    "GetTickCount", "GetTickCount64", "QueryPerformanceCounter", "QueryPerformanceFrequency",
    "GetSystemTime", "GetLocalTime", "GetSystemTimeAsFileTime", "Sleep", "SleepEx",
    "GetSystemInfo", "GetNativeSystemInfo", "GlobalMemoryStatusEx",
    "GetVersionExA", "GetVersionExW", "GetComputerNameA", "GetComputerNameW",
    "GetUserNameA", "GetUserNameW", "GetCommandLineA", "GetCommandLineW",
    "GetEnvironmentVariableA", "GetEnvironmentVariableW", "GetLastError", "SetLastError",
    "CreateMutexA", "CreateMutexW", "OpenMutexA", "OpenMutexW", "ReleaseMutex",
    "CreateEventA", "CreateEventW", "OpenEventA", "SetEvent", "ResetEvent",
    "InitializeCriticalSection", "EnterCriticalSection", "LeaveCriticalSection",
    "FlsAlloc", "TlsAlloc", "TlsGetValue", "TlsSetValue", "GetStartupInfoA", "GetStartupInfoW",
    "WinExec", "ShellExecuteA", "ShellExecuteW", "ShellExecuteExA", "ShellExecuteExW",
    "URLDownloadToFileA", "URLDownloadToFileW", "URLDownloadToCacheFileA", "URLDownloadToCacheFileW",
    "InternetOpenA", "InternetOpenW", "InternetOpenUrlA", "InternetOpenUrlW",
    "InternetConnectA", "InternetConnectW", "InternetReadFile", "InternetWriteFile",
    "InternetCloseHandle", "InternetSetOptionA", "InternetSetOptionW",
    "InternetQueryOptionA", "InternetQueryDataAvailable", "InternetCrackUrlA",
    "HttpOpenRequestA", "HttpOpenRequestW", "HttpSendRequestA", "HttpSendRequestW",
    "HttpSendRequestExA", "HttpQueryInfoA", "HttpQueryInfoW",
    "HttpAddRequestHeadersA", "HttpAddRequestHeadersW",
    "WinHttpOpen", "WinHttpConnect", "WinHttpOpenRequest", "WinHttpSendRequest",
    "WinHttpReceiveResponse", "WinHttpReadData", "WinHttpWriteData",
    "WinHttpQueryHeaders", "WinHttpQueryDataAvailable", "WinHttpSetOption",
    "WinHttpCloseHandle", "WinHttpCrackUrl",
    "WSAStartup", "WSACleanup", "WSASocketA", "WSASocketW", "WSAConnect",
    "WSASend", "WSARecv", "WSAGetLastError",
    "socket", "connect", "bind", "listen", "accept", "send", "recv",
    "sendto", "recvfrom", "closesocket", "shutdown", "setsockopt", "getsockopt",
    "select", "ioctlsocket", "htons", "htonl", "ntohs", "ntohl",
    "inet_addr", "inet_ntoa", "inet_pton", "gethostbyname", "getaddrinfo", "freeaddrinfo",
    "DnsQuery_A", "DnsQuery_W", "GetAdaptersInfo", "GetAdaptersAddresses",
    "RegOpenKeyA", "RegOpenKeyW", "RegOpenKeyExA", "RegOpenKeyExW",
    "RegCreateKeyA", "RegCreateKeyW", "RegCreateKeyExA", "RegCreateKeyExW",
    "RegSetValueA", "RegSetValueExA", "RegSetValueExW",
    "RegQueryValueA", "RegQueryValueExA", "RegQueryValueExW",
    "RegDeleteKeyA", "RegDeleteKeyW", "RegDeleteValueA", "RegDeleteValueW",
    "RegEnumKeyExA", "RegEnumKeyExW", "RegEnumValueA", "RegEnumValueW", "RegCloseKey",
    "CryptAcquireContextA", "CryptAcquireContextW", "CryptReleaseContext",
    "CryptCreateHash", "CryptDestroyHash", "CryptHashData", "CryptGetHashParam",
    "CryptDeriveKey", "CryptImportKey", "CryptExportKey", "CryptDestroyKey",
    "CryptGenKey", "CryptGenRandom", "CryptEncrypt", "CryptDecrypt",
    "CryptProtectData", "CryptUnprotectData",
    "CryptStringToBinaryA", "CryptStringToBinaryW", "CryptBinaryToStringA",
    "BCryptOpenAlgorithmProvider", "BCryptCloseAlgorithmProvider",
    "BCryptGenerateSymmetricKey", "BCryptImportKey", "BCryptDestroyKey",
    "BCryptEncrypt", "BCryptDecrypt", "BCryptCreateHash", "BCryptHashData",
    "BCryptFinishHash", "BCryptGenRandom",
    "OpenProcessToken", "OpenThreadToken", "AdjustTokenPrivileges",
    "LookupPrivilegeValueA", "LookupPrivilegeValueW", "GetTokenInformation",
    "DuplicateTokenEx", "ImpersonateLoggedOnUser", "RevertToSelf",
    "LogonUserA", "LogonUserW", "LsaEnumerateLogonSessions",
    "OpenSCManagerA", "OpenSCManagerW", "CreateServiceA", "CreateServiceW",
    "OpenServiceA", "OpenServiceW", "StartServiceA", "StartServiceW",
    "ControlService", "DeleteService", "CloseServiceHandle",
    "QueryServiceStatus", "ChangeServiceConfigA", "ChangeServiceConfigW",
    "MessageBoxA", "MessageBoxW", "FindWindowA", "FindWindowW",
    "GetForegroundWindow", "GetWindowTextA", "GetWindowTextW", "GetWindowThreadProcessId",
    "ShowWindow", "EnumWindows", "SetWindowsHookExA", "SetWindowsHookExW",
    "UnhookWindowsHookEx", "CallNextHookEx",
    "GetAsyncKeyState", "GetKeyState", "GetKeyboardState", "GetMessageA", "DispatchMessageA",
    "GetDC", "ReleaseDC", "CreateCompatibleDC", "CreateCompatibleBitmap",
    "SelectObject", "BitBlt", "GetDIBits", "DeleteObject", "DeleteDC",
    "OpenClipboard", "GetClipboardData", "SetClipboardData", "CloseClipboard",
    "CoInitialize", "CoInitializeEx", "CoCreateInstance", "CoUninitialize",
    "SHGetFolderPathA", "SHGetFolderPathW", "SHGetSpecialFolderPathA",
    "SetFileTime", "GetFileTime", "CreateNamedPipeA", "ConnectNamedPipe"
};

static const unp_msf_ent unp_msf_apis[] = {
    {"kernel32.dll", "LoadLibraryA",              "kernel32!LoadLibraryA"},
    {"kernel32.dll", "LoadLibraryW",              "kernel32!LoadLibraryW"},
    {"kernel32.dll", "LoadLibraryExA",            "kernel32!LoadLibraryExA"},
    {"kernel32.dll", "GetProcAddress",            "kernel32!GetProcAddress"},
    {"kernel32.dll", "VirtualAlloc",              "kernel32!VirtualAlloc"},
    {"kernel32.dll", "VirtualAllocEx",            "kernel32!VirtualAllocEx"},
    {"kernel32.dll", "VirtualProtect",            "kernel32!VirtualProtect"},
    {"kernel32.dll", "VirtualProtectEx",          "kernel32!VirtualProtectEx"},
    {"kernel32.dll", "VirtualFree",               "kernel32!VirtualFree"},
    {"kernel32.dll", "CreateProcessA",            "kernel32!CreateProcessA"},
    {"kernel32.dll", "CreateProcessW",            "kernel32!CreateProcessW"},
    {"kernel32.dll", "CreateThread",              "kernel32!CreateThread"},
    {"kernel32.dll", "CreateRemoteThread",        "kernel32!CreateRemoteThread"},
    {"kernel32.dll", "OpenProcess",               "kernel32!OpenProcess"},
    {"kernel32.dll", "WriteProcessMemory",        "kernel32!WriteProcessMemory"},
    {"kernel32.dll", "ReadProcessMemory",         "kernel32!ReadProcessMemory"},
    {"kernel32.dll", "WaitForSingleObject",       "kernel32!WaitForSingleObject"},
    {"kernel32.dll", "Sleep",                     "kernel32!Sleep"},
    {"kernel32.dll", "WinExec",                   "kernel32!WinExec"},
    {"kernel32.dll", "ExitProcess",               "kernel32!ExitProcess"},
    {"kernel32.dll", "ExitThread",                "kernel32!ExitThread"},
    {"kernel32.dll", "CreateFileA",               "kernel32!CreateFileA"},
    {"kernel32.dll", "WriteFile",                 "kernel32!WriteFile"},
    {"kernel32.dll", "ReadFile",                  "kernel32!ReadFile"},
    {"kernel32.dll", "CloseHandle",               "kernel32!CloseHandle"},
    {"kernel32.dll", "GetTempPathA",              "kernel32!GetTempPathA"},
    {"kernel32.dll", "GetModuleHandleA",          "kernel32!GetModuleHandleA"},
    {"kernel32.dll", "IsDebuggerPresent",         "kernel32!IsDebuggerPresent"},
    {"ntdll.dll",    "RtlExitUserThread",         "ntdll!RtlExitUserThread"},
    {"ntdll.dll",    "NtAllocateVirtualMemory",   "ntdll!NtAllocateVirtualMemory"},
    {"ntdll.dll",    "NtProtectVirtualMemory",    "ntdll!NtProtectVirtualMemory"},
    {"ntdll.dll",    "NtWriteVirtualMemory",      "ntdll!NtWriteVirtualMemory"},
    {"ntdll.dll",    "NtCreateThreadEx",          "ntdll!NtCreateThreadEx"},
    {"ntdll.dll",    "NtUnmapViewOfSection",      "ntdll!NtUnmapViewOfSection"},
    {"ntdll.dll",    "NtQueryInformationProcess", "ntdll!NtQueryInformationProcess"},
    {"ntdll.dll",    "NtQuerySystemInformation",  "ntdll!NtQuerySystemInformation"},
    {"ntdll.dll",    "LdrLoadDll",                "ntdll!LdrLoadDll"},
    {"ntdll.dll",    "RtlMoveMemory",             "ntdll!RtlMoveMemory"},
    {"ntdll.dll",    "RtlDecompressBuffer",       "ntdll!RtlDecompressBuffer"},
    {"wininet.dll",  "InternetOpenA",             "wininet!InternetOpenA"},
    {"wininet.dll",  "InternetConnectA",          "wininet!InternetConnectA"},
    {"wininet.dll",  "InternetOpenUrlA",          "wininet!InternetOpenUrlA"},
    {"wininet.dll",  "HttpOpenRequestA",          "wininet!HttpOpenRequestA"},
    {"wininet.dll",  "HttpSendRequestA",          "wininet!HttpSendRequestA"},
    {"wininet.dll",  "InternetReadFile",          "wininet!InternetReadFile"},
    {"wininet.dll",  "InternetCloseHandle",       "wininet!InternetCloseHandle"},
    {"ws2_32.dll",   "WSAStartup",                "ws2_32!WSAStartup"},
    {"ws2_32.dll",   "WSASocketA",                "ws2_32!WSASocketA"},
    {"ws2_32.dll",   "connect",                   "ws2_32!connect"},
    {"ws2_32.dll",   "send",                      "ws2_32!send"},
    {"ws2_32.dll",   "recv",                      "ws2_32!recv"},
    {"ws2_32.dll",   "closesocket",               "ws2_32!closesocket"},
    {"urlmon.dll",   "URLDownloadToFileA",        "urlmon!URLDownloadToFileA"},
    {"winhttp.dll",  "WinHttpOpen",               "winhttp!WinHttpOpen"},
    {"winhttp.dll",  "WinHttpConnect",            "winhttp!WinHttpConnect"},
    {"winhttp.dll",  "WinHttpOpenRequest",        "winhttp!WinHttpOpenRequest"},
    {"winhttp.dll",  "WinHttpSendRequest",        "winhttp!WinHttpSendRequest"}
};

static unp_ht_ent unp_ht[UNP_HT_CAP];
static int unp_ht_ready = 0;

static uint32_t unp_ror32(uint32_t v, unsigned r) {
    r &= 31u;
    if (r == 0u) return v;
    return (v >> r) | (v << (32u - r));
}

static uint32_t unp_rol32(uint32_t v, unsigned r) {
    r &= 31u;
    if (r == 0u) return v;
    return (v << r) | (v >> (32u - r));
}

static uint8_t unp_ror8(uint8_t v, unsigned r) {
    r &= 7u;
    if (r == 0u) return v;
    return (uint8_t)((v >> r) | (uint8_t)(v << (8u - r)));
}

static uint8_t unp_rol8(uint8_t v, unsigned r) {
    r &= 7u;
    if (r == 0u) return v;
    return (uint8_t)((uint8_t)(v << r) | (v >> (8u - r)));
}

static uint32_t unp_h_fnv1a(const char *s) {
    uint32_t h = 0x811C9DC5u;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        h ^= (uint32_t)*p;
        h *= 0x01000193u;
    }
    return h;
}

static uint32_t unp_h_djb2(const char *s) {
    uint32_t h = 5381u;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        h = h * 33u + (uint32_t)*p;
    }
    return h;
}

static uint32_t unp_h_ror13(const char *s) {
    uint32_t h = 0u;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        h = unp_ror32(h, 13u) + (uint32_t)*p;
    }
    return h;
}

static uint32_t unp_h_crc32(const char *s) {
    uint32_t h = 0xFFFFFFFFu;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        h ^= (uint32_t)*p;
        for (int i = 0; i < 8; i++) {
            h = (h >> 1) ^ ((h & 1u) ? 0xEDB88320u : 0u);
        }
    }
    return ~h;
}

static uint32_t unp_h_sdbm(const char *s) {
    uint32_t h = 0u;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        h = (uint32_t)*p + (h << 6) + (h << 16) - h;
    }
    return h;
}

static uint32_t unp_h_msf(const char *dll, const char *fn) {
    uint32_t mh = 0u;
    for (const unsigned char *p = (const unsigned char *)dll; ; p++) {
        uint32_t lo = (uint32_t)(unsigned char)toupper(*p);
        mh = unp_ror32(mh, 13u) + lo;
        mh = unp_ror32(mh, 13u);
        if (*p == 0) break;
    }
    uint32_t fh = 0u;
    for (const unsigned char *p = (const unsigned char *)fn; ; p++) {
        fh = unp_ror32(fh, 13u) + (uint32_t)*p;
        if (*p == 0) break;
    }
    return mh + fh;
}

static void unp_ht_insert(uint32_t hash, const char *algo, const char *api) {
    uint32_t idx = (hash * 2654435761u) & UNP_HT_MASK;
    for (uint32_t n = 0; n < UNP_HT_CAP; n++) {
        if (!unp_ht[idx].api) {
            unp_ht[idx].hash = hash;
            unp_ht[idx].algo = algo;
            unp_ht[idx].api = api;
            return;
        }
        if (unp_ht[idx].hash == hash) return;
        idx = (idx + 1u) & UNP_HT_MASK;
    }
}

static void unp_ht_init(void) {
    if (unp_ht_ready) return;
    memset(unp_ht, 0, sizeof(unp_ht));

    size_t n_msf = sizeof(unp_msf_apis) / sizeof(unp_msf_apis[0]);
    for (size_t i = 0; i < n_msf; i++) {
        uint32_t h = unp_h_msf(unp_msf_apis[i].dll, unp_msf_apis[i].fn);
        unp_ht_insert(h, "MSF-ROR13", unp_msf_apis[i].label);
    }

    size_t n_api = sizeof(unp_api_names) / sizeof(unp_api_names[0]);
    for (size_t i = 0; i < n_api; i++) {
        const char *nm = unp_api_names[i];
        unp_ht_insert(unp_h_ror13(nm), "ROR13", nm);
        unp_ht_insert(unp_h_fnv1a(nm), "FNV1a", nm);
        unp_ht_insert(unp_h_djb2(nm),  "DJB2",  nm);
        unp_ht_insert(unp_h_crc32(nm), "CRC32", nm);
        unp_ht_insert(unp_h_sdbm(nm),  "SDBM",  nm);
    }
    unp_ht_ready = 1;
}

static const unp_ht_ent *unp_ht_lookup(uint32_t hash) {
    uint32_t idx = (hash * 2654435761u) & UNP_HT_MASK;
    for (uint32_t n = 0; n < UNP_HT_CAP; n++) {
        if (!unp_ht[idx].api) return NULL;
        if (unp_ht[idx].hash == hash) return &unp_ht[idx];
        idx = (idx + 1u) & UNP_HT_MASK;
    }
    return NULL;
}

static void unp_trim(char *s) {
    char *p = s;
    while (*p == ' ' || *p == '\t') p++;
    if (p != s) memmove(s, p, strlen(p) + 1);
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\t')) s[--n] = 0;
}

static int unp_split_ops(const char *ops, char a[76], char b[76]) {
    a[0] = 0;
    b[0] = 0;
    if (!ops || !ops[0]) return 0;
    const char *c = strchr(ops, ',');
    if (!c) {
        snprintf(a, 76, "%s", ops);
        unp_trim(a);
        return 1;
    }
    size_t n = (size_t)(c - ops);
    if (n >= 75) n = 75;
    memcpy(a, ops, n);
    a[n] = 0;
    unp_trim(a);
    snprintf(b, 76, "%s", c + 1);
    unp_trim(b);
    return 2;
}

static bool unp_parse_hex(const char *s, uint64_t *val) {
    if (!s || s[0] != '0' || (s[1] != 'x' && s[1] != 'X')) return false;
    char *e = NULL;
    uint64_t v = strtoull(s + 2, &e, 16);
    if (e == s + 2 || *e != 0) return false;
    *val = v;
    return true;
}

static bool unp_is_ascii4(uint32_t v) {
    for (int i = 0; i < 4; i++) {
        uint8_t b = (uint8_t)((v >> (i * 8)) & 0xFFu);
        if (b < 0x20 || b > 0x7E) return false;
    }
    return true;
}

static bool unp_extract_imm32(const x86_ins *ins, uint32_t *out_imm) {
    const char *m = ins->mnem;
    int is_push = (strcmp(m, "push") == 0);
    if (!is_push &&
        strcmp(m, "mov") != 0 && strcmp(m, "movabs") != 0 &&
        strcmp(m, "cmp") != 0 && strcmp(m, "xor") != 0 &&
        strcmp(m, "add") != 0 && strcmp(m, "sub") != 0) {
        return false;
    }

    char s0[76], s1[76];
    int nops = unp_split_ops(ins->ops, s0, s1);
    const char *tok = is_push ? (nops >= 1 ? s0 : NULL) : (nops >= 2 ? s1 : NULL);
    if (!tok || tok[0] == '[') return false;

    uint64_t v = 0;
    if (!unp_parse_hex(tok, &v)) return false;
    // accept zero- or sign-extended 32-bit immediates
    uint32_t hi = (uint32_t)(v >> 32);
    if (hi != 0u && hi != 0xFFFFFFFFu) return false;

    uint32_t h = (uint32_t)v;
    if (h < 0x00100000u || h >= 0xFFF00000u) return false;
    if (unp_is_ascii4(h)) return false;

    *out_imm = h;
    return true;
}

static void unp_hash_add(unp_hash_res *out, uint64_t va, uint32_t hash, const unp_ht_ent *e) {
    if (out->nhit >= 128) return;
    for (int i = 0; i < out->nhit; i++) {
        if (out->hits[i].va == va) return;
    }
    unp_hash_hit *h = &out->hits[out->nhit++];
    h->va = va;
    h->hash = hash;
    snprintf(h->algo, sizeof(h->algo), "%s", e->algo);
    snprintf(h->api, sizeof(h->api), "%s", e->api);
}

static void unp_scan_hash_range(const ana_ctx *a, uint64_t start, uint64_t end, int *budget, unp_hash_res *out) {
    if (start >= end || *budget <= 0 || out->nhit >= 128) return;
    size_t av = 0;
    const uint8_t *p = bin_ptr(&a->bin, start, &av);
    if (!p || !av) return;

    uint64_t span = end - start;
    if (av > span) av = (size_t)span;

    x86_ins ins;
    size_t pos = 0;
    while (pos < av && *budget > 0 && out->nhit < 128) {
        if (a->bin.arch != BIN_ARCH_ARM64 && (p[pos] == 0xCC || p[pos] == 0x00)) {
            pos++;
            continue;
        }
        int n = arch_decode(a->bin.arch, p + pos, av - pos, start + pos, 1, 0, &ins);
        if (n <= 0) {
            pos++;
            continue;
        }
        (*budget)--;

        uint32_t imm = 0;
        if (unp_extract_imm32(&ins, &imm)) {
            const unp_ht_ent *e = unp_ht_lookup(imm);
            if (e) unp_hash_add(out, ins.ip, imm, e);
        }
        pos += (size_t)n;
    }
}

int unp_resolve_hashes(ana_ctx *a, int apply, unp_hash_res *out) {
    if (!out) return 0;
    memset(out, 0, sizeof(*out));
    if (!a || a->bin.nsec == 0) return 0;

    unp_ht_init();

    int budget = UNP_MAX_HASH_INSNS;
    if (a->bin.entry && bin_is_exec(&a->bin, a->bin.entry)) {
        const ana_func *ef = ana_func_at(a, a->bin.entry);
        const bin_sec *es = bin_sec_at(&a->bin, a->bin.entry);
        uint64_t es_end = ef ? ef->end : (es ? es->va + es->vsize : a->bin.entry);
        if (es_end > a->bin.entry + 16384) es_end = a->bin.entry + 16384;
        unp_scan_hash_range(a, ef ? ef->start : a->bin.entry, es_end, &budget, out);
    }

    int func_budget = (budget > 48000) ? 48000 : budget;
    int saved_rem = budget - func_budget;
    for (uint32_t i = 0; i < a->nfunc && func_budget > 0 && out->nhit < 128; i++) {
        const ana_func *f = &a->funcs[i];
        if (f->end <= f->start) continue;
        uint64_t fend = f->end;
        if (fend - f->start > 16384) fend = f->start + 16384;
        unp_scan_hash_range(a, f->start, fend, &func_budget, out);
    }
    budget = func_budget + saved_rem;

    for (uint32_t i = 0; i < a->bin.nsec && budget > 0 && out->nhit < 128; i++) {
        const bin_sec *s = &a->bin.secs[i];
        if (!(s->perm & BIN_PERM_X) || s->fsize == 0) continue;
        unp_scan_hash_range(a, s->va, s->va + s->fsize, &budget, out);
    }

    if (apply) {
        for (int i = 0; i < out->nhit; i++) {
            char cmt[112];
            snprintf(cmt, sizeof(cmt), "api_hash: %s -> %s", out->hits[i].algo, out->hits[i].api);
            ana_set_cmt(a, out->hits[i].va, cmt);
        }
    }
    return out->nhit;
}

static int unp_reg_id(const char *s, int *bits) {
    static const char *const r64[16] = {"rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi","r8","r9","r10","r11","r12","r13","r14","r15"};
    static const char *const r32[16] = {"eax","ecx","edx","ebx","esp","ebp","esi","edi","r8d","r9d","r10d","r11d","r12d","r13d","r14d","r15d"};
    static const char *const r16[16] = {"ax","cx","dx","bx","sp","bp","si","di","r8w","r9w","r10w","r11w","r12w","r13w","r14w","r15w"};
    static const char *const r8[16]  = {"al","cl","dl","bl","spl","bpl","sil","dil","r8b","r9b","r10b","r11b","r12b","r13b","r14b","r15b"};
    for (int i = 0; i < 16; i++) {
        if (strcmp(s, r64[i]) == 0) { if (bits) *bits = 64; return i; }
        if (strcmp(s, r32[i]) == 0) { if (bits) *bits = 32; return i; }
        if (strcmp(s, r16[i]) == 0) { if (bits) *bits = 16; return i; }
        if (strcmp(s, r8[i])  == 0) { if (bits) *bits = 8;  return i; }
    }
    return -1;
}

static bool unp_clean_text(const uint8_t *buf, size_t len, char out[96]) {
    while (len > 0 && buf[len - 1] == 0) len--;
    if (len < 4) return false;
    if (len > 95) len = 95;

    size_t pr = 0, alnum = 0;
    uint8_t seen[128] = {0};
    int distinct = 0;
    size_t k = 0;

    for (size_t i = 0; i < len; i++) {
        uint8_t c = buf[i];
        if (c >= 0x20 && c <= 0x7E) {
            pr++;
            if (isalnum(c) || c == '/' || c == '\\' || c == '.' || c == '_' || c == ':') alnum++;
            if (!seen[c]) { seen[c] = 1; distinct++; }
            out[k++] = (char)c;
        } else if (c == '\t' || c == '\r' || c == '\n') {
            out[k++] = ' ';
        } else if (len < 8) {
            return false;
        }
    }
    out[k] = 0;

    if (pr < 4 || k < 4) return false;
    if (pr * 100u < len * 85u) return false;
    // reject constant-byte noise from zeroed buffers
    if (distinct < 2 || alnum < 2) return false;
    return true;
}

static void unp_str_add(unp_str_res *out, uint64_t va, const char *method, uint32_t key, const char *text) {
    if (out->nhit >= 128 || !text || !text[0]) return;
    for (int i = 0; i < out->nhit; i++) {
        if (out->hits[i].va == va && strcmp(out->hits[i].text, text) == 0) return;
    }
    unp_str_hit *h = &out->hits[out->nhit++];
    h->va = va;
    h->key = key;
    snprintf(h->method, sizeof(h->method), "%s", method);
    snprintf(h->text, sizeof(h->text), "%s", text);
}

static int unp_op_kind(const char *m) {
    if (strcmp(m, "xor") == 0) return UNP_OP_XOR;
    if (strcmp(m, "add") == 0) return UNP_OP_ADD;
    if (strcmp(m, "sub") == 0) return UNP_OP_SUB;
    if (strcmp(m, "rol") == 0) return UNP_OP_ROL;
    if (strcmp(m, "ror") == 0) return UNP_OP_ROR;
    return UNP_OP_NONE;
}

static const char *unp_op_name(int op) {
    switch (op) {
    case UNP_OP_XOR: return "XOR-loop";
    case UNP_OP_ADD: return "ADD-loop";
    case UNP_OP_SUB: return "SUB-loop";
    case UNP_OP_ROL: return "ROL-loop";
    case UNP_OP_ROR: return "ROR-loop";
    default:         return "decrypt";
    }
}

static bool unp_parse_mem_op(const char *op, const x86_ins *ins, int *bits,
                             int *base_reg, int *idx_reg, int *scale, int64_t *disp, int *has_rip) {
    *bits = 0;
    *base_reg = -1;
    *idx_reg = -1;
    *scale = 1;
    *disp = 0;
    *has_rip = 0;

    const char *p = op;
    if (strncmp(p, "byte ptr ", 9) == 0)       { *bits = 8;  p += 9; }
    else if (strncmp(p, "word ptr ", 9) == 0)  { *bits = 16; p += 9; }
    else if (strncmp(p, "dword ptr ", 10) == 0){ *bits = 32; p += 10; }
    else if (strncmp(p, "qword ptr ", 10) == 0){ *bits = 64; p += 10; }

    if (p[0] && p[1] && p[2] == ':') p += 3;
    if (*p != '[') return false;

    if (ins->has_target && ins->target_mem) {
        *has_rip = 1;
        *disp = (int64_t)ins->target;
        return true;
    }

    char in[64];
    snprintf(in, sizeof(in), "%s", p + 1);
    char *rb = strchr(in, ']');
    if (!rb) return false;
    *rb = 0;

    int sign = 1;
    char *c = in;
    while (*c) {
        if (*c == '+') { sign = 1; c++; continue; }
        if (*c == '-') { sign = -1; c++; continue; }
        char tok[32];
        int k = 0;
        while (*c && *c != '+' && *c != '-' && k < 31) tok[k++] = *c++;
        tok[k] = 0;

        char *st = strchr(tok, '*');
        if (st) {
            *st = 0;
            int r = unp_reg_id(tok, NULL);
            int sc = atoi(st + 1);
            if (r >= 0) {
                *idx_reg = r;
                *scale = (sc == 2 || sc == 4 || sc == 8) ? sc : 1;
            }
        } else if (tok[0] == '0' && (tok[1] == 'x' || tok[1] == 'X')) {
            uint64_t dv = strtoull(tok + 2, NULL, 16);
            *disp += (sign > 0) ? (int64_t)dv : -(int64_t)dv;
        } else {
            int r = unp_reg_id(tok, NULL);
            if (r >= 0) {
                if (*base_reg < 0) *base_reg = r;
                else if (*idx_reg < 0) *idx_reg = r;
            }
        }
    }
    return true;
}

static bool unp_resolve_data_va(const ana_ctx *a, const uint64_t reg_val[16], const uint8_t reg_kind[16],
                                int base_reg, int idx_reg, int64_t disp, int has_rip, uint64_t *out_va) {
    if (has_rip) {
        uint64_t va = (uint64_t)disp;
        if (bin_sec_at(&a->bin, va)) { *out_va = va; return true; }
        return false;
    }
    // ignore stack frames handled by dob/emu pass
    if (base_reg == 4 || base_reg == 5) return false;

    if (base_reg >= 0 && reg_kind[base_reg] == UNP_REG_ADDR) {
        uint64_t va = reg_val[base_reg] + (uint64_t)disp;
        if (bin_sec_at(&a->bin, va)) { *out_va = va; return true; }
    }
    if (idx_reg >= 0 && reg_kind[idx_reg] == UNP_REG_ADDR) {
        uint64_t va = reg_val[idx_reg] + (uint64_t)disp;
        if (bin_sec_at(&a->bin, va)) { *out_va = va; return true; }
    }
    if (disp > 0 && bin_sec_at(&a->bin, (uint64_t)disp)) {
        *out_va = (uint64_t)disp;
        return true;
    }
    return false;
}

static void unp_track_reg(const ana_ctx *a, const x86_ins *ins, uint64_t reg_val[16], uint8_t reg_kind[16]) {
    const char *m = ins->mnem;
    char s0[76], s1[76];
    int nops = unp_split_ops(ins->ops, s0, s1);
    int b0 = 64, b1 = 64;
    int r0 = (nops >= 1) ? unp_reg_id(s0, &b0) : -1;
    int r1 = (nops >= 2) ? unp_reg_id(s1, &b1) : -1;
    uint64_t imm = 0;
    bool has_imm = (nops >= 2) && unp_parse_hex(s1, &imm);

    if (ins->flow == X86_FLOW_CALL) {
        static const int vol[7] = {0, 1, 2, 8, 9, 10, 11};
        for (int i = 0; i < 7; i++) reg_kind[vol[i]] = UNP_REG_NONE;
        return;
    }
    if (r0 < 0 || r0 == 4) return;

    if (strcmp(m, "lea") == 0) {
        if (ins->has_target && bin_sec_at(&a->bin, ins->target)) {
            reg_val[r0] = ins->target;
            reg_kind[r0] = UNP_REG_ADDR;
        } else {
            reg_kind[r0] = UNP_REG_NONE;
        }
    } else if (strcmp(m, "mov") == 0 || strcmp(m, "movabs") == 0) {
        if (has_imm) {
            reg_val[r0] = imm;
            reg_kind[r0] = (imm >= 0x1000u && bin_sec_at(&a->bin, imm)) ? UNP_REG_ADDR : UNP_REG_IMM;
        } else if (r1 >= 0 && reg_kind[r1] != UNP_REG_NONE) {
            reg_val[r0] = reg_val[r1];
            reg_kind[r0] = reg_kind[r1];
        } else {
            reg_kind[r0] = UNP_REG_NONE;
        }
    } else if (strcmp(m, "xor") == 0 && r0 == r1) {
        reg_val[r0] = 0;
        reg_kind[r0] = UNP_REG_IMM;
    } else if (strcmp(m, "cmp") != 0 && strcmp(m, "test") != 0 && strcmp(m, "push") != 0) {
        reg_kind[r0] = UNP_REG_NONE;
    }
}

static void unp_apply_cipher(const uint8_t *raw, uint8_t *dec, size_t len, int op, uint32_t key, int width) {
    if (width == 4) {
        size_t n4 = len & ~3u;
        for (size_t i = 0; i < n4; i += 4) {
            uint32_t w = 0;
            memcpy(&w, raw + i, 4);
            if (op == UNP_OP_XOR)      w ^= key;
            else if (op == UNP_OP_ADD) w += key;
            else if (op == UNP_OP_SUB) w -= key;
            else if (op == UNP_OP_ROL) w = unp_rol32(w, key & 31u);
            else if (op == UNP_OP_ROR) w = unp_ror32(w, key & 31u);
            memcpy(dec + i, &w, 4);
        }
        for (size_t i = n4; i < len; i++) dec[i] = raw[i];
        return;
    }

    uint8_t k8 = (uint8_t)(key & 0xFFu);
    for (size_t i = 0; i < len; i++) {
        uint8_t b = raw[i];
        if (op == UNP_OP_XOR)      dec[i] = (uint8_t)(b ^ k8);
        else if (op == UNP_OP_ADD) dec[i] = (uint8_t)(b + k8);
        else if (op == UNP_OP_SUB) dec[i] = (uint8_t)(b - k8);
        else if (op == UNP_OP_ROL) dec[i] = unp_rol8(b, k8 & 7u);
        else if (op == UNP_OP_ROR) dec[i] = unp_ror8(b, k8 & 7u);
        else                       dec[i] = b;
    }
}

static void unp_try_decrypt_buf(const ana_ctx *a, uint64_t data_va, int op, uint32_t key,
                                int width, size_t bound, int nul_mode, unp_str_res *out) {
    if (op == UNP_OP_NONE || out->nhit >= 128) return;
    if (width == 1) {
        uint8_t k8 = (uint8_t)(key & 0xFFu);
        if (op == UNP_OP_ROL || op == UNP_OP_ROR) { if ((k8 & 7u) == 0u) return; }
        else if (k8 == 0u) return;
        key = k8;
    } else {
        if (op == UNP_OP_ROL || op == UNP_OP_ROR) { if ((key & 31u) == 0u) return; }
        else if (key == 0u) return;
    }

    size_t req = bound;
    if (req == 0 || req > 128) req = 128;

    uint8_t raw[128], dec[128];
    size_t got = bin_read(&a->bin, data_va, raw, req);
    if (got < 4) return;

    size_t eff = got;
    if (bound == 0 && nul_mode == 1) {
        size_t z = 0;
        while (z < got && raw[z] != 0) z++;
        if (z >= 4) eff = z;
    }

    unp_apply_cipher(raw, dec, eff, op, key, width);

    // stop at decrypted nul when no fixed bound was recovered
    if (bound == 0) {
        size_t z = 0;
        while (z < eff && dec[z] != 0) z++;
        if (z >= 4) eff = z;
        else if (nul_mode == 0) return;
    } else {
        size_t z = 0;
        while (z < eff && dec[z] != 0) z++;
        if (z >= 4 && z < eff) eff = z;
    }

    char text[96];
    if (!unp_clean_text(dec, eff, text)) return;
    unp_str_add(out, data_va, unp_op_name(op), key, text);
}

static void unp_analyze_loop(const ana_ctx *a, const x86_ins *insns, int ti, int bi,
                             const uint64_t reg_val[16], const uint8_t reg_kind[16], unp_str_res *out) {
    int op = UNP_OP_NONE;
    uint32_t key = 0;
    int width = 1;
    int scale = 1;
    uint64_t data_va = 0;
    int has_va = 0;
    int op_idx = -1;

    int load_reg = -1;
    int load_width = 1;
    int load_scale = 1;
    uint64_t load_va = 0;

    size_t bound = 0;
    int nul_mode = 0;
    int nul_idx = -1;
    int ptr_step = 1;

    for (int i = ti; i <= bi; i++) {
        const x86_ins *ins = &insns[i];
        const char *m = ins->mnem;
        char s0[76], s1[76];
        int nops = unp_split_ops(ins->ops, s0, s1);
        int b0 = 64, b1 = 64;
        int r0 = (nops >= 1) ? unp_reg_id(s0, &b0) : -1;
        int r1 = (nops >= 2) ? unp_reg_id(s1, &b1) : -1;
        uint64_t imm = 0;
        bool has_imm = (nops >= 2) && unp_parse_hex(s1, &imm);

        // track memory load into temp reg
        if (nops == 2 && r0 >= 0 &&
            (strcmp(m, "mov") == 0 || strcmp(m, "movzx") == 0 || strcmp(m, "movsx") == 0)) {
            int mb = 0, br = -1, ir = -1, sc = 1, hr = 0;
            int64_t disp = 0;
            if (unp_parse_mem_op(s1, ins, &mb, &br, &ir, &sc, &disp, &hr)) {
                uint64_t va = 0;
                if (unp_resolve_data_va(a, reg_val, reg_kind, br, ir, disp, hr, &va)) {
                    load_reg = r0;
                    load_va = va;
                    load_scale = sc;
                    load_width = (mb == 32 || (mb == 0 && b0 == 32 && strcmp(m, "mov") == 0)) ? 4 : 1;
                }
            }
        }

        // detect decrypt arithmetic/bitwise op
        int k = unp_op_kind(m);
        if (k != UNP_OP_NONE && nops == 2 && op == UNP_OP_NONE) {
            uint64_t kv = 0;
            bool got_key = false;
            if (has_imm) { kv = imm; got_key = true; }
            else if (r1 >= 0 && r1 != r0 && reg_kind[r1] == UNP_REG_IMM) { kv = reg_val[r1]; got_key = true; }

            if (got_key) {
                int mb = 0, br = -1, ir = -1, sc = 1, hr = 0;
                int64_t disp = 0;
                if (r0 < 0 && unp_parse_mem_op(s0, ins, &mb, &br, &ir, &sc, &disp, &hr)) {
                    uint64_t va = 0;
                    if (unp_resolve_data_va(a, reg_val, reg_kind, br, ir, disp, hr, &va)) {
                        op = k;
                        key = (uint32_t)kv;
                        width = (mb == 32) ? 4 : 1;
                        scale = sc;
                        data_va = va;
                        has_va = 1;
                        op_idx = i;
                    }
                } else if (r0 >= 0 && r0 == load_reg && load_va != 0) {
                    op = k;
                    key = (uint32_t)kv;
                    width = load_width;
                    scale = load_scale;
                    data_va = load_va;
                    has_va = 1;
                    op_idx = i;
                }
            }
        }

        // detect loop bound or nul terminator
        if (strcmp(m, "cmp") == 0 && nops == 2 && has_imm) {
            if (imm >= 4 && imm <= 128 && bound == 0) {
                bound = (size_t)imm;
            } else if (imm == 0) {
                nul_idx = i;
            }
        } else if (strcmp(m, "test") == 0 && nops == 2 && r0 >= 0 && r0 == r1 && r0 == load_reg) {
            nul_idx = i;
        } else if (strcmp(m, "dec") == 0 && r0 >= 0 && reg_kind[r0] == UNP_REG_IMM) {
            if (reg_val[r0] >= 4 && reg_val[r0] <= 128 && bound == 0) bound = (size_t)reg_val[r0];
        } else if (strcmp(m, "sub") == 0 && r0 >= 0 && has_imm && imm == 1 && reg_kind[r0] == UNP_REG_IMM) {
            if (reg_val[r0] >= 4 && reg_val[r0] <= 128 && bound == 0) bound = (size_t)reg_val[r0];
        } else if (strcmp(m, "add") == 0 && r0 >= 0 && has_imm && imm == 0xFFFFFFFFFFFFFFFFULL && reg_kind[r0] == UNP_REG_IMM) {
            if (reg_val[r0] >= 4 && reg_val[r0] <= 128 && bound == 0) bound = (size_t)reg_val[r0];
        } else if ((strcmp(m, "loop") == 0 || strcmp(m, "loopne") == 0 || strcmp(m, "loope") == 0) &&
                   reg_kind[1] == UNP_REG_IMM && reg_val[1] >= 4 && reg_val[1] <= 128 && bound == 0) {
            bound = (size_t)reg_val[1];
        } else if (strcmp(m, "add") == 0 && r0 >= 0 && reg_kind[r0] == UNP_REG_ADDR && has_imm && imm == 4) {
            ptr_step = 4;
        }
    }

    if (!has_va || op == UNP_OP_NONE) return;

    if (bound > 0) {
        size_t mult = (scale == 4) ? 4u : ((width == 4 && ptr_step == 4) ? 4u : 1u);
        bound *= mult;
        if (bound > 128) bound = 128;
    } else if (nul_idx >= 0) {
        nul_mode = (nul_idx < op_idx) ? 1 : 2;
    }

    unp_try_decrypt_buf(a, data_va, op, key, width, bound, nul_mode, out);
}

static void unp_scan_func_loops(const ana_ctx *a, uint64_t func_va, x86_ins *insns, unp_str_res *out) {
    const bin_sec *sec = bin_sec_at(&a->bin, func_va);
    if (!sec || !(sec->perm & BIN_PERM_X)) return;

    const ana_func *f = ana_func_at(a, func_va);
    uint64_t fstart = f ? f->start : func_va;
    uint64_t fend = f ? f->end : (sec->va + sec->vsize);
    if (fend <= fstart) return;
    if (fend - fstart > 8192) fend = fstart + 8192;

    size_t av = 0;
    const uint8_t *p = bin_ptr(&a->bin, fstart, &av);
    if (!p || !av) return;
    if (av > (size_t)(fend - fstart)) av = (size_t)(fend - fstart);

    int nins = 0;
    size_t pos = 0;
    while (pos < av && nins < UNP_MAX_FUNC_INSNS) {
        int n = arch_decode(a->bin.arch, p + pos, av - pos, fstart + pos, 1, 0, &insns[nins]);
        if (n <= 0) break;
        nins++;
        pos += (size_t)n;
    }
    if (nins < 3) return;

    uint64_t reg_val[16] = {0};
    uint8_t reg_kind[16] = {0};
    for (int bi = 1; bi < nins && out->nhit < 128; bi++) {
        const x86_ins *br = &insns[bi];
        if ((br->flow == X86_FLOW_JCC || br->flow == X86_FLOW_JMP) &&
            br->has_target && !br->target_mem && br->target < br->ip) {
            int ti = -1;
            int lo = (bi > 32) ? (bi - 32) : 0;
            for (int j = bi - 1; j >= lo; j--) {
                if (insns[j].ip == br->target) { ti = j; break; }
            }
            if (ti < 0) continue;

            memset(reg_val, 0, sizeof(reg_val));
            memset(reg_kind, 0, sizeof(reg_kind));
            int start_tr = (ti > 64) ? (ti - 64) : 0;
            for (int j = start_tr; j < ti; j++) {
                unp_track_reg(a, &insns[j], reg_val, reg_kind);
            }
            unp_analyze_loop(a, insns, ti, bi, reg_val, reg_kind, out);
        }
    }
}

static void unp_push_va(uint64_t *vas, int *cnt, int max_vas, uint64_t va) {
    if (*cnt >= max_vas || va == 0) return;
    for (int i = 0; i < *cnt; i++) {
        if (vas[i] == va) return;
    }
    vas[(*cnt)++] = va;
}

static int unp_collect_funcs(const ana_ctx *a, uint64_t focus_va, uint64_t *vas, int max_vas) {
    int cnt = 0;
    if (focus_va && bin_is_exec(&a->bin, focus_va)) {
        const ana_func *ff = ana_func_at(a, focus_va);
        unp_push_va(vas, &cnt, max_vas, ff ? ff->start : focus_va);
    }
    if (a->bin.entry && bin_is_exec(&a->bin, a->bin.entry)) {
        const ana_func *ef = ana_func_at(a, a->bin.entry);
        unp_push_va(vas, &cnt, max_vas, ef ? ef->start : a->bin.entry);
    }
    for (uint32_t i = 0; i < a->bin.ntls && cnt < max_vas; i++) {
        if (bin_is_exec(&a->bin, a->bin.tls_cbs[i])) {
            unp_push_va(vas, &cnt, max_vas, a->bin.tls_cbs[i]);
        }
    }
    if (a->nfunc > 0) {
        uint32_t stride = (a->nfunc > (uint32_t)max_vas) ? (a->nfunc / (uint32_t)max_vas) : 1u;
        for (uint32_t i = 0; i < a->nfunc && cnt < max_vas; i += stride) {
            uint64_t fsz = (a->funcs[i].end > a->funcs[i].start) ? (a->funcs[i].end - a->funcs[i].start) : 0;
            if (fsz >= 12) unp_push_va(vas, &cnt, max_vas, a->funcs[i].start);
        }
        for (uint32_t i = 0; i < a->nfunc && cnt < max_vas; i++) {
            unp_push_va(vas, &cnt, max_vas, a->funcs[i].start);
        }
    }
    if (cnt == 0) {
        for (uint32_t i = 0; i < a->bin.nsec && cnt < max_vas; i++) {
            if ((a->bin.secs[i].perm & BIN_PERM_X) && a->bin.secs[i].fsize > 0) {
                unp_push_va(vas, &cnt, max_vas, a->bin.secs[i].va);
            }
        }
    }
    return cnt;
}

static void unp_harvest_emu_ascii(uint64_t va, const char *ascii, unp_str_res *out) {
    if (!ascii || !ascii[0]) return;
    size_t len = strlen(ascii);
    size_t pos = 0;
    while (pos < len && out->nhit < 128) {
        while (pos < len && ascii[pos] == ' ') pos++;
        if (pos >= len) break;

        size_t rem = len - pos;
        size_t take = (rem <= 95) ? rem : 95;
        if (rem > 95) {
            size_t sp = take;
            while (sp > 4 && ascii[pos + sp] != ' ') sp--;
            if (sp > 4) take = sp;
        }
        while (take > 0 && ascii[pos + take - 1] == ' ') take--;

        char text[96];
        if (take >= 4 && unp_clean_text((const uint8_t *)(ascii + pos), take, text)) {
            unp_str_add(out, va, "emu-stack", 0u, text);
        }
        pos += (take > 0) ? take : 1;
    }
}

int unp_decrypt_strings(ana_ctx *a, uint64_t focus_va, int apply, unp_str_res *out) {
    if (!out) return 0;
    memset(out, 0, sizeof(*out));
    if (!a || a->bin.nsec == 0) return 0;

    uint64_t func_vas[65];
    int nfunc = unp_collect_funcs(a, focus_va, func_vas, 65);

    x86_ins *insns = (x86_ins *)malloc(UNP_MAX_FUNC_INSNS * sizeof(x86_ins));
    if (insns) {
        for (int i = 0; i < nfunc && out->nhit < 128; i++) {
            unp_scan_func_loops(a, func_vas[i], insns, out);
        }
        free(insns);
    }

    dob_res *dob = (dob_res *)malloc(sizeof(dob_res));
    if (dob) {
        int dob_lim = (nfunc < 16) ? nfunc : 16;
        for (int i = 0; i < dob_lim && out->nhit < 128; i++) {
            if (!dob_analyze(a, func_vas[i], 0, dob)) continue;
            for (int k = 0; k < dob->nstr && out->nhit < 128; k++) {
                char text[96];
                size_t slen = strlen(dob->strs[k].text);
                if (unp_clean_text((const uint8_t *)dob->strs[k].text, slen, text)) {
                    unp_str_add(out, dob->strs[k].va, "stack-str", 0u, text);
                }
            }
        }
        free(dob);
    }

    uint64_t emu_va = (focus_va && bin_is_exec(&a->bin, focus_va)) ? focus_va
                    : (a->bin.entry && bin_is_exec(&a->bin, a->bin.entry)) ? a->bin.entry
                    : (nfunc > 0 ? func_vas[0] : 0);
    if (emu_va && out->nhit < 128) {
        emu_out *emu = (emu_out *)malloc(sizeof(emu_out));
        if (emu) {
            if (emu_trace(a, emu_va, 128, emu) && emu->stack_ascii[0]) {
                unp_harvest_emu_ascii(emu->start_va, emu->stack_ascii, out);
            }
            free(emu);
        }
    }

    if (apply) {
        for (int i = 0; i < out->nhit; i++) {
            char cmt[128];
            snprintf(cmt, sizeof(cmt), "decrypted: \"%s\"", out->hits[i].text);
            ana_set_cmt(a, out->hits[i].va, cmt);
        }
    }
    return out->nhit;
}

static uint16_t unp_u16(const uint8_t *d, size_t sz, size_t off) {
    if (off + 2 > sz) return 0;
    uint16_t v = 0;
    memcpy(&v, d + off, 2);
    return v;
}

static uint32_t unp_u32(const uint8_t *d, size_t sz, size_t off) {
    if (off + 4 > sz) return 0;
    uint32_t v = 0;
    memcpy(&v, d + off, 4);
    return v;
}

static uint64_t unp_u64(const uint8_t *d, size_t sz, size_t off) {
    if (off + 8 > sz) return 0;
    uint64_t v = 0;
    memcpy(&v, d + off, 8);
    return v;
}

static void unp_w32(uint8_t *d, size_t off, uint32_t v) {
    memcpy(d + off, &v, 4);
}

static void unp_w64(uint8_t *d, size_t off, uint64_t v) {
    memcpy(d + off, &v, 8);
}

static bool unp_pe_fail(unp_pe_res *out, const char *msg) {
    if (out) snprintf(out->err, sizeof(out->err), "%s", msg);
    return false;
}

static uint32_t unp_count_pe_imports(const uint8_t *buf, size_t sz, size_t dd_off,
                                     uint32_t ndd, size_t opt_end, int is64) {
    if (ndd <= 1u || dd_off + 16u > opt_end || dd_off + 16u > sz) return 0;
    uint32_t imp_rva = unp_u32(buf, sz, dd_off + 8u);
    if (imp_rva == 0u || (size_t)imp_rva + 20u > sz) return 0;

    size_t stride = is64 ? 8u : 4u;
    uint32_t total = 0;
    for (uint32_t d = 0; d < 1024u && total < 65536u; d++) {
        size_t base = (size_t)imp_rva + (size_t)d * 20u;
        if (base + 20u > sz) break;
        uint32_t ilt_rva  = unp_u32(buf, sz, base + 0u);
        uint32_t name_rva = unp_u32(buf, sz, base + 12u);
        uint32_t iat_rva  = unp_u32(buf, sz, base + 16u);
        if (!ilt_rva && !name_rva && !iat_rva) break;

        uint32_t src_rva = (ilt_rva != 0u && (size_t)ilt_rva + stride <= sz) ? ilt_rva : iat_rva;
        uint32_t cnt = 0;
        if (src_rva != 0u && (size_t)src_rva + stride <= sz) {
            for (uint32_t j = 0; j < 4096u && total + cnt < 65536u; j++) {
                size_t pos = (size_t)src_rva + (size_t)j * stride;
                if (pos + stride > sz) break;
                uint64_t th = is64 ? unp_u64(buf, sz, pos) : (uint64_t)unp_u32(buf, sz, pos);
                if (th == 0u) break;
                cnt++;
            }
        }
        if (cnt > 0u) {
            total += cnt;
        } else if (name_rva != 0u && (size_t)name_rva < sz &&
                   buf[name_rva] >= 0x20 && buf[name_rva] <= 0x7E) {
            total++;
        }
    }
    return total;
}

static bool unp_write_atomic(const char *out_path, const uint8_t *buf, size_t sz, unp_pe_res *out) {
    size_t plen = strlen(out_path);
    char *tmp_path = (char *)malloc(plen + 8u);
    if (!tmp_path) return unp_pe_fail(out, "out of memory");
    snprintf(tmp_path, plen + 8u, "%s.tmp", out_path);

    FILE *fp = fopen(tmp_path, "wb");
    if (!fp) {
        free(tmp_path);
        return unp_pe_fail(out, "failed to open output temp file");
    }

    size_t wr = fwrite(buf, 1, sz, fp);
    int fl_err = fflush(fp);
    int cl_err = fclose(fp);
    if (wr != sz || fl_err != 0 || cl_err != 0) {
        remove(tmp_path);
        free(tmp_path);
        return unp_pe_fail(out, "failed to write rebuilt PE");
    }

    if (!MoveFileExA(tmp_path, out_path, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        remove(tmp_path);
        free(tmp_path);
        return unp_pe_fail(out, "failed to replace output PE");
    }

    free(tmp_path);
    return true;
}

bool unp_rebuild_pe_mem(const uint8_t *img, size_t img_size, uint64_t base_va, uint64_t oep_va,
                        const char *out_path, unp_pe_res *out) {
    if (out) memset(out, 0, sizeof(*out));
    if (!img || img_size < 0x200u) return unp_pe_fail(out, "image buffer too small");
    if (!out_path || !out_path[0]) return unp_pe_fail(out, "missing output path");

    if (unp_u16(img, img_size, 0u) != 0x5A4Du) return unp_pe_fail(out, "invalid MZ magic");

    uint32_t pe_off = unp_u32(img, img_size, 0x3Cu);
    if (pe_off < 0x40u || (size_t)pe_off > img_size || img_size - (size_t)pe_off < 24u) {
        return unp_pe_fail(out, "e_lfanew out of bounds");
    }
    if (unp_u32(img, img_size, (size_t)pe_off) != 0x00004550u) {
        return unp_pe_fail(out, "invalid PE signature");
    }

    uint16_t nsec   = unp_u16(img, img_size, (size_t)pe_off + 6u);
    uint16_t opt_sz = unp_u16(img, img_size, (size_t)pe_off + 20u);
    if (nsec < 1u || nsec > 96u) return unp_pe_fail(out, "invalid section count");

    size_t opt = (size_t)pe_off + 24u;
    if (opt_sz < 96u || (size_t)opt_sz > img_size - opt) {
        return unp_pe_fail(out, "optional header out of bounds");
    }

    uint16_t magic = unp_u16(img, img_size, opt);
    int is64 = (magic == 0x20Bu);
    if (!is64 && magic != 0x10Bu) return unp_pe_fail(out, "unsupported optional header magic");
    if (opt_sz < (is64 ? 112u : 96u)) return unp_pe_fail(out, "optional header truncated");

    size_t sh_off = opt + (size_t)opt_sz;
    size_t sh_sz  = (size_t)nsec * 40u;
    if (sh_off > img_size || img_size - sh_off < sh_sz) {
        return unp_pe_fail(out, "section headers out of bounds");
    }

    uint8_t *buf = (uint8_t *)malloc(img_size);
    if (!buf) return unp_pe_fail(out, "out of memory");
    memcpy(buf, img, img_size);

    if (oep_va != 0u && oep_va > base_va && (oep_va - base_va) < (uint64_t)img_size) {
        unp_w32(buf, opt + 16u, (uint32_t)(oep_va - base_va));
    }
    if (base_va != 0u) {
        if (is64) unp_w64(buf, opt + 24u, base_va);
        else if (base_va <= 0xFFFFFFFFULL) unp_w32(buf, opt + 28u, (uint32_t)base_va);
    }

    uint32_t sec_align = unp_u32(buf, img_size, opt + 32u);
    if (sec_align != 0u) unp_w32(buf, opt + 36u, sec_align);
    unp_w32(buf, opt + 64u, 0u);

    size_t dd_off = opt + (is64 ? 112u : 96u);
    uint32_t ndd = unp_u32(buf, img_size, dd_off - 4u);
    if (ndd > 16u) ndd = 16u;
    // zero authenticode directory invalidated by memory dump
    if (ndd > 4u && dd_off + 40u <= sh_off && dd_off + 40u <= img_size) {
        unp_w32(buf, dd_off + 32u, 0u);
        unp_w32(buf, dd_off + 36u, 0u);
    }

    for (uint16_t i = 0; i < nsec; i++) {
        size_t s = sh_off + (size_t)i * 40u;
        uint32_t vsz = unp_u32(buf, img_size, s + 8u);
        uint32_t rva = unp_u32(buf, img_size, s + 12u);
        uint32_t rsz = unp_u32(buf, img_size, s + 16u);
        if ((size_t)rva >= img_size) {
            unp_w32(buf, s + 16u, 0u);
            unp_w32(buf, s + 20u, 0u);
            continue;
        }
        uint64_t avail = (uint64_t)img_size - (uint64_t)rva;
        uint64_t raw_sz = vsz ? (uint64_t)vsz : (uint64_t)rsz;
        if (raw_sz == 0u) {
            if (i + 1u < nsec) {
                uint32_t next_rva = unp_u32(buf, img_size, sh_off + (size_t)(i + 1u) * 40u + 12u);
                if (next_rva > rva) raw_sz = (uint64_t)(next_rva - rva);
            }
            if (raw_sz == 0u) raw_sz = avail;
        }
        if (raw_sz > avail) raw_sz = avail;
        if (vsz == 0u) unp_w32(buf, s + 8u, (uint32_t)raw_sz);
        unp_w32(buf, s + 16u, (uint32_t)raw_sz);
        unp_w32(buf, s + 20u, rva);
    }

    uint32_t nimp = unp_count_pe_imports(buf, img_size, dd_off, ndd, sh_off, is64);

    if (!unp_write_atomic(out_path, buf, img_size, out)) {
        free(buf);
        return false;
    }

    free(buf);
    if (out) {
        out->ok = 1;
        out->nsec = nsec;
        out->nimp = nimp;
        out->out_size = (uint64_t)img_size;
        out->err[0] = 0;
    }
    return true;
}
