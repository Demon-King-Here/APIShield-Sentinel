@echo off
setlocal
title APIShield Sentinel - Stop
cd /d "%~dp0"
".venv\Scripts\python.exe" scripts\environment.py stop
if errorlevel 1 (
  echo Could not stop the owned APIShield environment. See the error above.
  pause
  exit /b 1
)
echo The owned APIShield process has been stopped.
pause
endlocal
exit /b 0
