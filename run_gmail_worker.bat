@echo off
setlocal EnableExtensions
cd /d "%~dp0"
set "PYTHONUTF8=1"

set "PYTHON="
if exist "..\.venv\Scripts\python.exe" set "PYTHON=..\.venv\Scripts\python.exe"
if not defined PYTHON if exist ".venv\Scripts\python.exe" set "PYTHON=.venv\Scripts\python.exe"
if not defined PYTHON set "PYTHON=python"

"%PYTHON%" -c "import google.cloud.pubsub_v1, googleapiclient, cryptography, dotenv" >nul 2>&1
if errorlevel 1 (
    echo.
    echo [ERROR] Gmail worker dependencies are missing.
    echo Install them with:
    echo     "%PYTHON%" -m pip install -r requirements.txt
    echo.
    pause
    exit /b 1
)

echo Starting the Gmail Pub/Sub worker.
echo Leave this terminal open while monitoring is enabled.
echo Press Ctrl+C to stop the worker.
echo.
"%PYTHON%" -m src.gmail_security.worker

echo.
echo The Gmail worker has stopped.
pause
endlocal
