@echo off
cd /d "%~dp0\.."
setlocal enabledelayedexpansion

echo.
echo ========================================================
echo   NexShield v6.1 - Development Runner
echo ========================================================
echo.

if exist "%USERPROFILE%\.cargo\bin\cargo.exe" (
    set "PATH=%USERPROFILE%\.cargo\bin;%PATH%"
)

if exist target\release\nexshield-cli.exe (
    target\release\nexshield-cli.exe run 5000 127.0.0.1
) else (
    echo [*] Binary not found. Building with cargo...
    cargo run --release -p nexshield-cli -- run 5000 127.0.0.1
)

pause
