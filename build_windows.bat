@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"
title DORM - Build

:: ============================================================
::  Banner
:: ============================================================
echo.
echo   ____   ___  ____  __  __
echo  ^|  _ \ / _ \^|  _ \^|  \/  ^|
echo  ^| ^| ^| ^| ^| ^| ^| ^|_) ^| ^|\/^| ^|
echo  ^| ^|_^| ^| ^|_^| ^|  _ ^<^| ^|  ^| ^|
echo  ^|____/ \___/^|_^| \_\_^|  ^|_^|
echo.
echo  Next-Gen Vulnerability Scanner - Windows Builder
echo  --------------------------------------------------
echo.

:: ============================================================
::  STEP 1 - Verify Go is installed and available in PATH
:: ============================================================
echo [*] Checking Go installation...
where go >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo [!] Go not found. Install Go 1.21+ from: https://go.dev/dl/
    echo.
    pause & exit /b 1
)

:: Parse version string: "go version go1.25.5 windows/amd64" → "1.25.5"
for /f "tokens=3" %%v in ('go version 2^>^&1') do set GO_RAW=%%v
set GO_VER=%GO_RAW:go=%
echo [+] Go version: %GO_VER%

:: Enforce Go 1.21 minimum.
for /f "tokens=1,2 delims=." %%a in ("%GO_VER%") do ( set MAJOR=%%a & set MINOR=%%b )
if !MAJOR! equ 1 if !MINOR! lss 21 (
    echo [!] Go 1.21+ required. Found %GO_VER%. Update from: https://go.dev/dl/
    pause & exit /b 1
)
echo [+] Version check passed.
echo.

:: ============================================================
::  STEP 2 - Download module dependencies
:: ============================================================
echo [*] Downloading dependencies...
go mod download
if %errorlevel% neq 0 (
    echo [!] go mod download failed.
    pause & exit /b 1
)
echo [+] Dependencies ready.
echo.

:: ============================================================
::  STEP 3 - Compile DORM.exe
:: ============================================================
echo [*] Compiling DORM.exe...
go build -o DORM.exe .
if %errorlevel% neq 0 (
    echo [!] Build failed. See output above.
    pause & exit /b 1
)

echo.
echo  --------------------------------------------------
echo   [+] DORM.exe compiled successfully!
echo.
echo   Double-click DORM.exe to launch.
echo  --------------------------------------------------
echo.
pause
endlocal
