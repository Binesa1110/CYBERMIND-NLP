@echo off
setlocal EnableExtensions
cd /d "%~dp0"

set "HOST=0.0.0.0"
set "PORT=8000"
set "PYTHONUTF8=1"

rem ---------------------------------------------------------
rem  Find a Python interpreter (prefer the project venv).
rem  The venv in this workspace lives one folder above the
rem  project root, so check both locations.
rem ---------------------------------------------------------
set "PYTHON="
if exist "..\.venv\Scripts\python.exe" set "PYTHON=..\.venv\Scripts\python.exe"
if not defined PYTHON if exist ".venv\Scripts\python.exe" set "PYTHON=.venv\Scripts\python.exe"
if not defined PYTHON set "PYTHON=python"

"%PYTHON%" -c "import fastapi, uvicorn, sklearn, nltk, joblib, googleapiclient, google_auth_oauthlib, google.cloud.pubsub_v1, cryptography, dotenv" >nul 2>&1
if errorlevel 1 (
    echo.
    echo [ERROR] Python dependencies are missing or incomplete.
    echo.
    echo Install them with:
    echo     "%PYTHON%" -m pip install -r requirements.txt
    echo.
    pause
    exit /b 1
)

if not exist "models\cybermind_threat_classifier.joblib" (
    echo.
    echo [ERROR] The trained model file is missing:
    echo     models\cybermind_threat_classifier.joblib
    echo.
    echo Restore it from your backup before starting the server.
    echo.
    pause
    exit /b 1
)

"%PYTHON%" -c "from src.preprocessing import TextPreprocessor; from src.sentiment import SentimentAnalyzer; TextPreprocessor().process('preflight check'); SentimentAnalyzer().analyze('preflight check')" >nul 2>&1
if errorlevel 1 (
    echo.
    echo [ERROR] Required NLTK data is missing.
    echo.
    echo Download it with:
    echo     "%PYTHON%" -m nltk.downloader stopwords punkt punkt_tab wordnet omw-1.4 averaged_perceptron_tagger averaged_perceptron_tagger_eng maxent_ne_chunker maxent_ne_chunker_tab words vader_lexicon
    echo.
    pause
    exit /b 1
)

echo ==========================================================
echo   CYBERMIND - AI-Powered Cyber Threat Detection
echo ==========================================================
echo   Local website : http://localhost:%PORT%/ui/
echo   API docs      : http://127.0.0.1:%PORT%/docs
echo   Health check  : http://127.0.0.1:%PORT%/health
echo.
echo   Starting the server. Your browser will open shortly.
echo   Press Ctrl+C in this window to stop the server.
echo ==========================================================
echo.

rem Open the browser a few seconds after the server starts.
rem Set CYBERMIND_NO_BROWSER=1 to skip this (useful for automated checks).
if not defined CYBERMIND_NO_BROWSER (
    start "" /min powershell -NoProfile -WindowStyle Hidden -Command "Start-Sleep -Seconds 4; Start-Process 'http://localhost:%PORT%/ui/'"
)

"%PYTHON%" -m uvicorn api:app --host %HOST% --port %PORT%

echo.
echo The CYBERMIND server has stopped.
pause
endlocal
