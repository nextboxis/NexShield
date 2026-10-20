@echo off
cd /d "%~dp0\.."
echo.
echo ========================================================
echo   NexShield v6.1 - Windows Setup (Pure Rust Engine)
echo ========================================================
echo.

REM ── Check Cargo / Rust ──────────────────────────────────────
if exist "%USERPROFILE%\.cargo\bin\cargo.exe" (
    set "PATH=%USERPROFILE%\.cargo\bin;%PATH%"
)
echo [*] Checking for Cargo & Rust toolchain...
cargo --version >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    echo.
    echo [!] Rust / Cargo is NOT installed or not in PATH.
    echo     Download Rust installer: https://rustup.rs/
    echo     IMPORTANT: Restart your terminal after installing!
    echo.
    pause
    exit /b 1
)

FOR /F "tokens=2" %%G IN ('cargo --version 2^>^&1') DO SET RUSTVER=%%G
echo [+] Cargo %RUSTVER% detected

REM ── Compile Release Binaries ─────────────────────────────────
echo.
echo [*] Compiling optimized release binaries (zero external dependencies)...
cargo build --release --offline
IF %ERRORLEVEL% NEQ 0 (
    cargo build --release
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
echo       run.bat
echo          OR
echo       .\target\release\nexshield-cli.exe run
echo.
echo   Dashboard will open at: http://127.0.0.1:5000
echo.
pause
