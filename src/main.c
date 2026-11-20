#include "cli/cli.h"
#include "ui/ui.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#include <stdlib.h>
#include <string.h>

static int main_is_cli(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-') return 1;
    }
    return 0;
}

int main(int argc, char **argv) {
    int uargc = argc;
    char **uargv = argv;
    char **alloc_argv = NULL;

    int wargc = 0;
    LPWSTR *wargv = CommandLineToArgvW(GetCommandLineW(), &wargc);
    if (wargv && wargc > 0) {
        alloc_argv = (char **)calloc((size_t)wargc + 1u, sizeof(char *));
        if (alloc_argv) {
            int ok = 1;
            for (int i = 0; i < wargc; i++) {
                int n = WideCharToMultiByte(CP_UTF8, 0, wargv[i], -1, NULL, 0, NULL, NULL);
                if (n <= 0) { ok = 0; break; }
                alloc_argv[i] = (char *)malloc((size_t)n);
                if (!alloc_argv[i] || WideCharToMultiByte(CP_UTF8, 0, wargv[i], -1, alloc_argv[i], n, NULL, NULL) <= 0) {
                    ok = 0;
                    break;
                }
            }
            if (ok) {
                uargc = wargc;
                uargv = alloc_argv;
            } else {
                for (int i = 0; i < wargc; i++) free(alloc_argv[i]);
                free(alloc_argv);
                alloc_argv = NULL;
            }
        }
        LocalFree(wargv);
    }

    int rc = 0;
    if (main_is_cli(uargc, uargv)) {
        rc = cli_run(uargc, uargv);
    } else {
        // avoid orphan console window
        DWORD pids[2];
        if (GetConsoleProcessList(pids, 2) <= 1) FreeConsole();
        rc = ui_run(uargc >= 2 ? uargv[1] : NULL);
    }

    if (alloc_argv) {
        for (int i = 0; i < uargc; i++) free(alloc_argv[i]);
        free(alloc_argv);
    }
    return rc;
}
