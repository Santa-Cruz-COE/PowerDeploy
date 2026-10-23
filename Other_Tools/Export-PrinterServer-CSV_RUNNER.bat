@echo off
echo !!! UNTESTED TOOL - not validated end to end. Review all output by hand. !!!
Powershell.exe -executionpolicy bypass -File "%~dp0Export-PrinterServer-CSV.ps1"
Pause