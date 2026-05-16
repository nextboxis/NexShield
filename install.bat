@echo off
echo.
echo ========================================================
echo   NexShield v5 - Windows Setup
echo ========================================================
echo.

REM ── Check Python ────────────────────────────────────────────
echo [*] Checking for Python...
python --version >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    echo.
    echo [!] Python is NOT installed or not in PATH.
    echo     Download Python 3.9+: https://www.python.org/downloads/
    echo     IMPORTANT: Check "Add Python to PATH" during install!
    echo.
    pause
    exit /b 1
)

FOR /F "tokens=2" %%G IN ('python --version 2^>^&1') DO SET PYVER=%%G
echo [+] Python %PYVER% detected

REM ── Create Virtual Environment ──────────────────────────────
echo.
echo [*] Creating virtual environment (.venv)...
IF EXIST .venv (
    echo [+] Virtual environment already exists, reusing it.
) ELSE (
    python -m venv .venv
    IF %ERRORLEVEL% NEQ 0 (
        echo [!] Failed to create virtual environment.
        echo     Try: python -m pip install --upgrade pip virtualenv
        pause
        exit /b 1
    )
)

REM ── Activate ────────────────────────────────────────────────
echo [*] Activating virtual environment...
call .venv\Scripts\activate.bat

REM ── Upgrade pip ─────────────────────────────────────────────
echo [*] Upgrading pip...
python -m pip install --upgrade pip -q

REM ── Install Dependencies ────────────────────────────────────
echo [*] Installing dependencies...
pip install -r requirements.txt -q
IF %ERRORLEVEL% NEQ 0 (
    echo.
    echo [!] Some packages failed to install.
    echo     Trying individual installs...
    pip install flask tinydb flask-socketio flask-cors python-dotenv requests python-nmap -q
)

REM ── Create .env ─────────────────────────────────────────────
IF NOT EXIST .env (
    IF EXIST .env.example (
        copy .env.example .env >nul
        echo [+] Created .env from template
    )
)

REM ── Done ────────────────────────────────────────────────────
echo.
echo ========================================================
echo   Setup Complete!
echo ========================================================
echo.
echo   To start NexShield, run:
echo.
echo       python run.py
echo.
echo   That's it! No database setup needed.
echo   Dashboard will open at: http://127.0.0.1:5000
echo.
echo   Optional: Install nmap for network scanning:
echo       https://nmap.org/download.html
echo.
pause
