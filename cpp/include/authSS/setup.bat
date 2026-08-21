@echo off
REM =============================================================================
REM SANTET SENTINEL — Download json.hpp (nlohmann/json v3.11.3)
REM =============================================================================
REM This downloads the single-header JSON library needed by authSS.
REM License: MIT — https://github.com/nlohmann/json
REM =============================================================================

if exist json.hpp (
    echo [SKIP] json.hpp already exists.
    exit /b 0
)

echo [*] Downloading json.hpp (nlohmann/json v3.11.3)...

powershell -Command "Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/nlohmann/json/v3.11.3/single_include/nlohmann/json.hpp' -OutFile 'json.hpp'"

if %ERRORLEVEL% equ 0 (
    echo [OK] json.hpp downloaded successfully.
) else (
    echo [FAIL] Failed to download json.hpp.
    echo        Please download manually from:
    echo        https://github.com/nlohmann/json/releases/tag/v3.11.3
    exit /b 1
)
