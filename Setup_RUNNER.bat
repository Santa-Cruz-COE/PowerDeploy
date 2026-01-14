@echo off
REM start "PowerDeploy - Setup" /MAX Powershell.exe -executionpolicy bypass -File "%~dp0Setup.ps1"

Powershell.exe -executionpolicy bypass -File "%~dp0Setup.ps1"

Pause