@REM ═══════════════════════════════════════════════════════════════
@REM  NexShield Development Startup Script (Windows)
@REM ═══════════════════════════════════════════════════════════════
@REM
@REM  This script starts NexShield in development mode with hot-reload
@REM  Only use for local development, NOT for production
@REM

@echo off
setlocal enabledelayedexpansion

echo.
echo ═══════════════════════════════════════════════════════════════
echo   NexShield — Development Server
echo ═══════════════════════════════════════════════════════════════
echo.
echo [!] WARNING: This is the DEVELOPMENT server
echo     Use run_production.bat for production deployments
echo.

REM Activate virtual environment if not already active
if not defined VIRTUAL_ENV (
    echo [*] Activating virtual environment...
    if exist .venv\Scripts\activate.bat (
        call .venv\Scripts\activate.bat
    ) else (
        echo [ERROR] Virtual environment not found at .venv
        echo Run: python -m venv .venv
        pause
        exit /b 1
    )
)

REM Install requirements
echo [*] Installing dependencies...
pip install -q -r requirements.txt
if errorlevel 1 (
    echo [ERROR] Failed to install dependencies
    pause
    exit /b 1
)

REM Set development mode
set FLASK_ENV=development
set FLASK_DEBUG=true

echo [+] Environment: Development (Debug Mode ON)
echo [+] Dashboard: http://127.0.0.1:5000
echo.
echo [*] Starting Flask development server...
echo     Press Ctrl+C to stop
echo.

python app.py

pause
