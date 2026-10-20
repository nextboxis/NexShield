@echo off
setlocal
cd /d "%~dp0"
echo.
echo ========================================================
echo   NexShield v6.1 - Pure Rust Setup (Zero Python Needed)
echo ========================================================
echo.
cargo --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [!] Rust/Cargo was not found in PATH.
    echo     Please install Rust from: https://rustup.rs/
    pause
    exit /b 1
)
echo [*] Compiling optimized release binaries (target\release\)...
cargo build --release --offline
if %ERRORLEVEL% NEQ 0 (
    cargo build --release
)
echo.
echo [✓] Build Complete! Run NexShield via:
echo       run.bat              (Starts Web Dashboard on http://127.0.0.1:5000)
echo       .\target\release\nexshield-cli.exe check
echo       .\target\release\nexshield-cli.exe self-test
echo       python run.py        (Transparent wrapper)
echo.
pause
