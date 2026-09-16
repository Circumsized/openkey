@echo off
setlocal
title AutoClaw Token Extractor (1-Second Instant Decrypt)

echo ================================================================
echo AutoClaw Desktop Token Extractor
echo Method: Windows DPAPI + AES-256-GCM (Chromium safeStorage)
echo ================================================================
echo.

set "PATH=D:\tools\go\bin;%PATH%"
cd /d "%~dp0"

if exist "decryptor.go" (
    echo [INFO] Running Go Decryptor (zero dependency)...
    go run decryptor.go
) else (
    echo [INFO] Running Python Decryptor...
    python decryptor.py
)

echo.
echo ================================================================
echo Press any key to close this window...
pause >nul
