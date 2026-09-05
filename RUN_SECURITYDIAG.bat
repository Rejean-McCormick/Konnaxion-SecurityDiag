@echo off
setlocal
set CAMPAIGN=%1
if "%CAMPAIGN%"=="" set CAMPAIGN=repo
python "%~dp0securitydiag.py" run %CAMPAIGN%
exit /b %ERRORLEVEL%
