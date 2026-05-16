@REM ═══════════════════════════════════════════════════════════════
@REM  NexShield Development Startup Script (Windows)
@REM ═══════════════════════════════════════════════════════════════
@REM
@REM  Starts NexShield in development mode.
@REM  Preferred: just run "python run.py" instead.
@REM

@echo off
setlocal enabledelayedexpansion

echo.
echo ═══════════════════════════════════════════════════════════════
echo   NexShield — Development Server
echo ═══════════════════════════════════════════════════════════════
echo.

REM Activate virtual environment if not already active
if not defined VIRTUAL_ENV (
    echo [*] Activating virtual environment...
    if exist .venv\Scripts\activate.bat (
        call .venv\Scripts\activate.bat
    ) else (
        echo [!] Virtual environment not found. Run install.bat first.
        echo     Or: python -m venv .venv
        pause
        exit /b 1
    )
)

REM Start using the unified launcher
echo [*] Starting NexShield in development mode...
echo.
python run.py --debug

pause
