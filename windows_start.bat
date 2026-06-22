@echo off
REM ============================================================
REM  PM3 webUI launcher for Windows  (PM3 yi jian gong ju webUI)
REM  No GUI library needed, only Python 3.
REM ============================================================
chcp 65001 >nul
cd /d "%~dp0"

echo ===============================================
echo    PM3 webUI
echo ===============================================

set "PY="
where py >nul 2>nul && set "PY=py -3"
if not defined PY (
    where python >nul 2>nul && set "PY=python"
)
if not defined PY (
    echo [ERROR] Python not found.
    echo         Install from https://www.python.org/downloads/windows/
    echo         and tick "Add python.exe to PATH" during setup.
    pause
    exit /b 1
)

echo [*] Using: %PY%
echo [*] Starting local server and opening the browser...
echo     (Close this window to stop the server.)
echo.
echo     Note: on Windows the proxmark3 client is proxmark3.exe and you must
echo     pick the COM port (e.g. COM3) in the page. Windows backend is
echo     experimental (output is shown per-command, not live-streamed).
echo.

%PY% "%~dp0pm3_web.py"

echo.
pause
