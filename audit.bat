@echo off
echo.
echo  Windows Endpoint Security Audit
echo  ================================
echo.
powershell -ExecutionPolicy Bypass -File "%~dp0scripts\full-audit.ps1"
echo.
pause
