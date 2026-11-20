@echo off
setlocal
cd /d "%~dp0"
if not exist xdis.exe call build.bat
if "%~1"=="" (
    app\node_modules\.bin\electron.cmd app
) else (
    app\node_modules\.bin\electron.cmd app "%~f1"
)
