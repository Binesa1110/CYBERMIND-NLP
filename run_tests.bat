@echo off
setlocal EnableExtensions
cd /d "%~dp0"

set "PYTHONUTF8=1"

set "PYTHON="
if exist "..\.venv\Scripts\python.exe" set "PYTHON=..\.venv\Scripts\python.exe"
if not defined PYTHON if exist ".venv\Scripts\python.exe" set "PYTHON=.venv\Scripts\python.exe"
if not defined PYTHON set "PYTHON=python"

echo ==========================================================
echo   CYBERMIND - backend test suite
echo ==========================================================
echo.

"%PYTHON%" -m unittest discover -s tests -t . -v

echo.
echo ==========================================================
echo   Optional browser end-to-end test
echo ==========================================================
echo   Install the test tools first:
echo       "%PYTHON%" -m pip install -r requirements-dev.txt
echo   Run the E2E suite ^(uses installed Microsoft Edge^):
echo       "%PYTHON%" -m tests.browser_e2e
echo.

pause
endlocal
