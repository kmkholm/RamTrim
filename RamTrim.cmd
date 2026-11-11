@echo off
rem Runs RamTrim from source. The single-file build is RamTrim.exe (see build.cmd).
start "" powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "%~dp0src\RamTrim.ps1"
