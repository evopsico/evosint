@echo off
setlocal
cd /d "%~dp0"
where node >nul 2>nul
if errorlevel 1 (
  echo Node.js is not installed or not on PATH.
  echo Install Node.js 18+ from https://nodejs.org/ then re-run.
  pause
  exit /b 1
)
node launch-evosint.js
pause
