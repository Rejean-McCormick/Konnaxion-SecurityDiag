@echo off
setlocal
cd /d "%~dp0"
where pyw >nul 2>nul
if %errorlevel%==0 (
  start "" pyw -3 "%~dp0RecoveryDrillAssistant.pyw"
  exit /b 0
)
where pythonw >nul 2>nul
if %errorlevel%==0 (
  start "" pythonw "%~dp0RecoveryDrillAssistant.pyw"
  exit /b 0
)
echo ERROR: Python 3 / pythonw not found in PATH.
pause
exit /b 1
