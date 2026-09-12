@echo off
setlocal
cd /d "%~dp0"

where pyw >nul 2>&1
if %errorlevel%==0 (
  pyw -3 tools\SSH_HARDENING_ASSISTANT.pyw
  exit /b %errorlevel%
)

where pythonw >nul 2>&1
if %errorlevel%==0 (
  pythonw tools\SSH_HARDENING_ASSISTANT.pyw
  exit /b %errorlevel%
)

where python >nul 2>&1
if %errorlevel%==0 (
  python tools\SSH_HARDENING_ASSISTANT.pyw
  exit /b %errorlevel%
)

echo Python 3 was not found in PATH.
pause
exit /b 1
