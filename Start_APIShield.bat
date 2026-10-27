@echo off
setlocal
title APIShield Sentinel - Start
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo APIShield's Python environment is missing.
  echo Run these commands in this folder first:
  echo   python -m venv .venv
  echo   .venv\Scripts\python.exe -m pip install -r requirements-lock.txt
  pause
  exit /b 1
)
echo Starting APIShield Sentinel...
".venv\Scripts\python.exe" scripts\environment.py start --open-browser
if errorlevel 1 (
  echo.
  echo Startup did not complete. Check the message above and runtime logs.
  echo Dependencies: .venv\Scripts\python.exe -m pip install -r requirements-lock.txt
  pause
  exit /b 1
)
endlocal
exit /b 0
