@echo off
setlocal
cd /d "%~dp0"
set "ERA_REQUEST=%~1"
if not defined ERA_REQUEST set "ERA_REQUEST=examples\dispersion.json"
set "ERA_RESULT=result-%RANDOM%-%RANDOM%.json"
if exist "%ERA_RESULT%" (
  echo Output name collision. Please run again.
  exit /b 1
)
"%~dp0era-engine.exe" dispersion "%ERA_REQUEST%" > "%ERA_RESULT%"
if errorlevel 1 (
  echo Calculation failed. Do not use the output file.
  pause
  exit /b 1
)
echo Experimental calculation saved to %ERA_RESULT%
echo Read README-WINDOWS.txt for supported inputs and limitations.
pause
