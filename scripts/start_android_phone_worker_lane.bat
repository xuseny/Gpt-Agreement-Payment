@echo off
setlocal EnableExtensions EnableDelayedExpansion

cd /d "%~dp0\.."

if not defined LANE_ID set "LANE_ID=lane"
if not defined CONFIG (
  echo [%LANE_ID%] CONFIG is not set.
  pause
  exit /b 1
)
if not defined PHONE_WORKER_ADB_SERIAL set "PHONE_WORKER_ADB_SERIAL=auto"
if not defined PHONE_WORKER_ADB_CONNECT_SERIALS set "PHONE_WORKER_ADB_CONNECT_SERIALS=%PHONE_WORKER_ADB_SERIAL%"
if not defined PHONE_WORKER_APPIUM_PORT set "PHONE_WORKER_APPIUM_PORT=4723"
if not defined WORKER set "WORKER=CTF-pay\android_phone_worker.py"

set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8"

echo [%LANE_ID%] Project: %CD%
echo [%LANE_ID%] Config: %CONFIG%
echo [%LANE_ID%] ADB serial: %PHONE_WORKER_ADB_SERIAL%
echo [%LANE_ID%] Appium port: %PHONE_WORKER_APPIUM_PORT%

if not exist "%CONFIG%" (
  echo [%LANE_ID%] Missing %CONFIG%
  echo [%LANE_ID%] Generate it with scripts\new_android_gopay_lane.ps1 first.
  pause
  exit /b 1
)

if not exist "%WORKER%" (
  echo [%LANE_ID%] Missing %WORKER%
  pause
  exit /b 1
)

where python >nul 2>nul
if errorlevel 1 (
  echo [%LANE_ID%] python is not in PATH.
  pause
  exit /b 1
)

if defined PHONE_WORKER_ADB_PATH if exist "%PHONE_WORKER_ADB_PATH%" set "ADB_EXE=%PHONE_WORKER_ADB_PATH%"

for /f "delims=" %%I in ('where adb 2^>nul') do (
  if not defined ADB_EXE set "ADB_EXE=%%I"
)

if not defined ADB_EXE if exist "C:\Program Files\Netease\MuMu Player 12\shell\adb.exe" set "ADB_EXE=C:\Program Files\Netease\MuMu Player 12\shell\adb.exe"
if not defined ADB_EXE if exist "C:\Program Files (x86)\Netease\MuMu Player 12\shell\adb.exe" set "ADB_EXE=C:\Program Files (x86)\Netease\MuMu Player 12\shell\adb.exe"
if not defined ADB_EXE if exist "C:\Program Files\Netease\MuMuPlayer-12.0\shell\adb.exe" set "ADB_EXE=C:\Program Files\Netease\MuMuPlayer-12.0\shell\adb.exe"

if not defined ADB_EXE (
  echo [%LANE_ID%] adb is not in PATH and MuMu adb.exe was not found.
  echo [%LANE_ID%] Install Android platform-tools, add adb.exe to PATH, or set PHONE_WORKER_ADB_PATH.
  pause
  exit /b 1
)

set "PHONE_WORKER_ADB_PATH=%ADB_EXE%"

for %%I in ("%ADB_EXE%\..") do set "PLATFORM_TOOLS=%%~fI"
for %%I in ("%PLATFORM_TOOLS%\..") do set "SDK_ROOT=%%~fI"

set "ANDROID_HOME=%SDK_ROOT%"
set "ANDROID_SDK_ROOT=%SDK_ROOT%"

echo [%LANE_ID%] adb: %ADB_EXE%
echo [%LANE_ID%] ANDROID_HOME: %ANDROID_HOME%
echo [%LANE_ID%] ADB connect candidates: %PHONE_WORKER_ADB_CONNECT_SERIALS%

set "ADB_CONNECT_LIST=%PHONE_WORKER_ADB_CONNECT_SERIALS:,= %"
set "ADB_CONNECT_LIST=%ADB_CONNECT_LIST:;= %"
for %%S in (%ADB_CONNECT_LIST%) do (
  echo [%LANE_ID%] adb connect %%S
  "%ADB_EXE%" connect %%S >nul 2>nul
)

echo [%LANE_ID%] Connected Android devices:
"%ADB_EXE%" devices

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$port = [int]$env:PHONE_WORKER_APPIUM_PORT; $ok = Test-NetConnection 127.0.0.1 -Port $port -InformationLevel Quiet -WarningAction SilentlyContinue; if (-not $ok) { exit 1 }"
if errorlevel 1 (
  echo.
  echo [%LANE_ID%] Appium is not listening on 127.0.0.1:%PHONE_WORKER_APPIUM_PORT%.
  echo [%LANE_ID%] Trying to start Appium for this lane ...

  set "APPIUM_EXE="
  for /f "delims=" %%I in ('where appium.cmd 2^>nul') do (
    if not defined APPIUM_EXE set "APPIUM_EXE=%%I"
  )
  if not defined APPIUM_EXE (
    for /f "delims=" %%I in ('where appium 2^>nul') do (
      if not defined APPIUM_EXE set "APPIUM_EXE=%%I"
    )
  )

  if not defined APPIUM_EXE (
    echo [%LANE_ID%] appium is not in PATH.
    echo [%LANE_ID%] OTP worker can still run in adb notification mode.
    echo [%LANE_ID%] Install Appium or add appium.cmd to PATH for auto unlink.
  ) else (
    if not exist "output\%LANE_ID%" mkdir "output\%LANE_ID%"
    echo [%LANE_ID%] Starting Appium: !APPIUM_EXE! --base-path / --port %PHONE_WORKER_APPIUM_PORT%
    powershell -NoProfile -ExecutionPolicy Bypass -Command ^
      "$appium = $env:APPIUM_EXE; $lane = $env:LANE_ID; $port = [int]$env:PHONE_WORKER_APPIUM_PORT; $out = Join-Path (Get-Location) ('output\' + $lane + '\appium.out.log'); $err = Join-Path (Get-Location) ('output\' + $lane + '\appium.err.log'); Start-Process -FilePath $appium -ArgumentList '--base-path','/','--port',([string]$port) -WorkingDirectory (Get-Location) -WindowStyle Hidden -RedirectStandardOutput $out -RedirectStandardError $err | Out-Null; $deadline = (Get-Date).AddSeconds(25); do { Start-Sleep -Milliseconds 500; $ok = Test-NetConnection 127.0.0.1 -Port $port -InformationLevel Quiet -WarningAction SilentlyContinue } until ($ok -or (Get-Date) -gt $deadline); if (-not $ok) { exit 1 }"
    if errorlevel 1 (
      echo [%LANE_ID%] Appium was started but 127.0.0.1:%PHONE_WORKER_APPIUM_PORT% did not become ready.
      echo [%LANE_ID%] Check output\%LANE_ID%\appium.err.log and output\%LANE_ID%\appium.out.log.
      echo [%LANE_ID%] OTP worker can still run in adb notification mode.
    ) else (
      echo [%LANE_ID%] Appium is listening on 127.0.0.1:%PHONE_WORKER_APPIUM_PORT%.
    )
  )
) else (
  echo [%LANE_ID%] Appium already listening on 127.0.0.1:%PHONE_WORKER_APPIUM_PORT%.
)

echo.
echo [%LANE_ID%] Starting worker with %CONFIG%
echo [%LANE_ID%] Press Ctrl+C to stop.
echo.

python "%WORKER%" --config "%CONFIG%"

echo.
echo [%LANE_ID%] Worker exited with code %ERRORLEVEL%.
pause
exit /b %ERRORLEVEL%
