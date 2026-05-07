@echo off
echo ========================================================
echo   NexShield v5 - Automated Windows Setup
echo ========================================================

echo.
echo [*] Checking for Python...
python --version >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    echo [!] Python is not installed or not in PATH. Please install Python 3.10+ and try again.
    pause
    exit /b 1
)

echo [*] Creating virtual environment (.venv)...
python -m venv .venv

echo [*] Activating virtual environment...
call .venv\Scripts\activate.bat

echo [*] Installing dependencies from requirements.txt...
python -m pip install --upgrade pip
pip install -r requirements.txt

echo.
echo ========================================================
echo   Setup Complete!
echo ========================================================
echo To start NexShield:
echo.
echo   1. Ensure MongoDB is running locally
echo   2. Activate the environment: call .venv\Scripts\activate.bat
echo   3. Start the server:        python app.py
echo.
pause
