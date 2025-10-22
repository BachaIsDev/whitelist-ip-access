@echo off
net session >nul 2>&1
if %errorLevel% NEQ 0 (
    powershell -Command "Start-Process '%~0' -Verb RunAs" >nul 2>&1
    exit /b
)

title IP Monitor - Admin Mode
color 0a
cd /d "%~dp0"

echo.
echo Запуск скрипта с правами администратора...
powershell.exe -ExecutionPolicy Bypass -NoLogo -File "monitor_whitelist_ips.ps1"

echo.
echo Скрипт завершил работу.
pause