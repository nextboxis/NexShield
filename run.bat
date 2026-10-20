@echo off
setlocal
cd /d "%~dp0"
if exist "%USERPROFILE%\.cargo\bin\cargo.exe" (
    set "PATH=%USERPROFILE%\.cargo\bin;%PATH%"
)
if exist "target\release\nexshield-cli.exe" (
    target\release\nexshield-cli.exe run %*
) else if exist "target\debug\nexshield-cli.exe" (
    target\debug\nexshield-cli.exe run %*
) else (
    cargo run --release -p nexshield-cli -- run %*
)
