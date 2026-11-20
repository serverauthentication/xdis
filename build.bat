@echo off
setlocal
if not defined VSCMD_VER (
    for %%p in (
        "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat"
        "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
        "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
    ) do if exist %%p (
        call %%p >nul
        goto :env_ok
    )
)
:env_ok
if not exist build mkdir build

ml64 /nologo /c /Fo build\scan_x64.obj src\scan\scan_x64.asm
if errorlevel 1 exit /b 1
ml64 /nologo /c /Fo build\scan_avx2.obj src\scan\scan_avx2.asm
if errorlevel 1 exit /b 1

cl /nologo /std:c11 /O2 /W4 /D_CRT_SECURE_NO_WARNINGS /Fo:build\ /Fe:xdis.exe ^
    src\main.c ^
    src\core\map.c ^
    src\scan\scan.c ^
    src\bin\bin.c ^
    src\bin\pe.c ^
    src\bin\elf.c ^
    src\bin\macho.c ^
    src\bin\demangle.c ^
    src\bin\pdb.c ^
    src\bin\bc.c ^
    src\bin\sym_dbg.c ^
    src\arch\x86.c ^
    src\arch\arm64.c ^
    src\arch\multi.c ^
    src\arch\asm.c ^
    src\ana\ana.c ^
    src\ana\graph.c ^
    src\ana\hlir.c ^
    src\ana\type_inf.c ^
    src\ana\struct_cfg.c ^
    src\ana\dec.c ^
    src\ana\triage.c ^
    src\ana\deobf.c ^
    src\ana\ir.c ^
    src\ana\ssa.c ^
    src\ana\lang.c ^
    src\ana\obf_cff.c ^
    src\ana\vm.c ^
    src\ana\unp.c ^
    src\ana\taint.c ^
    src\ana\chdr.c ^
    src\ana\forensics.c ^
    src\ana\vuln.c ^
    src\ana\sig.c ^
    src\ana\diff.c ^
    src\ana\path.c ^
    src\ana\types.c ^
    src\ana\db.c ^
    src\dbg\dbg.c ^
    src\dbg\gdb.c ^
    src\dbg\dmp.c ^
    src\opt\opt.c ^
    src\ext\ext.c ^
    src\cli\cli.c ^
    src\cli\rpc.c ^
    src\ui\ui.c ^
    src\ui\dis.c ^
    src\ui\view.c ^
    build\scan_x64.obj build\scan_avx2.obj ^
    user32.lib gdi32.lib comdlg32.lib shell32.lib dwmapi.lib ws2_32.lib
if errorlevel 1 exit /b 1

cl /nologo /std:c11 /O2 /W4 /LD /D_CRT_SECURE_NO_WARNINGS /Fo:build\ /Fe:plugins\entropy.dll plugins\entropy.c /link /IMPLIB:build\entropy.lib
if errorlevel 1 exit /b 1

echo build ok: xdis.exe + plugins\entropy.dll
