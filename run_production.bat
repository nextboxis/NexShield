@REM ═══════════════════════════════════════════════════════════════
@REM  NexShield Production Startup Script (Windows)
@REM ═══════════════════════════════════════════════════════════════
@REM
@REM  This script starts NexShield using Gunicorn (production WSGI server)
@REM  Ensure you have a .env file with proper configuration before running
@REM

@echo off
setlocal enabledelayedexpansion

echo.
echo ═══════════════════════════════════════════════════════════════
echo   NexShield — Production Server Startup
echo ═══════════════════════════════════════════════════════════════
echo.

REM Check if virtual environment is activated
if not defined VIRTUAL_ENV (
    echo [!] Virtual environment not activated
    echo Starting virtual environment...
    if exist .venv\Scripts\activate.bat (
        call .venv\Scripts\activate.bat
        echo [+] Virtual environment activated
    ) else (
        echo [ERROR] Virtual environment not found. Run: python -m venv .venv
        exit /b 1
    )
)

REM Install/update requirements
echo [*] Checking dependencies...
pip install --quiet -r requirements.txt
if errorlevel 1 (
    echo [ERROR] Failed to install dependencies
    exit /b 1
)
echo [+] Dependencies ready

REM Start Gunicorn with SocketIO support
echo.
echo [*] Starting NexShield production server...
echo     URL: http://0.0.0.0:5000
echo     Press Ctrl+C to stop
echo.

REM Use 4 worker processes by default (adjust based on CPU cores)
REM Timeout set to 120 seconds for long-running scans
REM Binding to all interfaces (0.0.0.0)
gunicorn -w 4 -b 0.0.0.0:5000 --timeout 120 ^
    --access-logfile - --error-logfile - ^
    --log-level info ^
    wsgi:app

if errorlevel 1 (
    echo [ERROR] Gunicorn failed. Try installing gunicorn: pip install gunicorn
    echo.
    echo Fallback: Running with Flask development server...
    python app.py
)
