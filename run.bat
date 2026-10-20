@echo off
setlocal
cd /d "%~dp0"
if exist "target\release\nexshield-cli.exe" (
    target\release\nexshield-cli.exe run %*
) else (
    cargo run --release -p nexshield-cli -- run %*
)
