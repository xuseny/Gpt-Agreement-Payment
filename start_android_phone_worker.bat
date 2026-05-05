@echo off
setlocal EnableExtensions EnableDelayedExpansion

cd /d "%~dp0"

set "CONFIG=CTF-pay\config.android-gopay.local.json"
set "WORKER=CTF-pay\android_phone_worker.py"
set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8"

echo [android-phone-worker] Project: %CD%

if not exist "%CONFIG%" (
  echo [android-phone-worker] Missing %CONFIG%
  echo [android-phone-worker] Create it from CTF-pay\config.android-gopay.example.json and fill phone_worker.server_base_url / relay_token.
  pause
  exit /b 1
)

if not exist "%WORKER%" (
  echo [android-phone-worker] Missing %WORKER%
  pause
  exit /b 1
)

where python >nul 2>nul
if errorlevel 1 (
  echo [android-phone-worker] python is not in PATH.
  pause
  exit /b 1
)

where adb >nul 2>nul
if errorlevel 1 (
  echo [android-phone-worker] adb is not in PATH.
  echo [android-phone-worker] Install Android platform-tools or add adb.exe to PATH.
  pause
  exit /b 1
)

for /f "delims=" %%I in ('where adb 2^>nul') do (
  if not defined ADB_EXE set "ADB_EXE=%%I"
)

for %%I in ("%ADB_EXE%\..") do set "PLATFORM_TOOLS=%%~fI"
for %%I in ("%PLATFORM_TOOLS%\..") do set "SDK_ROOT=%%~fI"

set "ANDROID_HOME=%SDK_ROOT%"
set "ANDROID_SDK_ROOT=%SDK_ROOT%"

echo [android-phone-worker] adb: %ADB_EXE%
echo [android-phone-worker] ANDROID_HOME: %ANDROID_HOME%

echo [android-phone-worker] Connected Android devices:
adb devices

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$ok = Test-NetConnection 127.0.0.1 -Port 4723 -InformationLevel Quiet -WarningAction SilentlyContinue; if (-not $ok) { exit 1 }"
if errorlevel 1 (
  echo.
  echo [android-phone-worker] Appium is not listening on 127.0.0.1:4723.
  echo [android-phone-worker] Trying to start Appium for inspect/unlink UI automation ...

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
    echo [android-phone-worker] appium is not in PATH.
    echo [android-phone-worker] OTP worker can still run in adb notification mode.
    echo [android-phone-worker] Install Appium or add appium.cmd to PATH for auto unlink.
  ) else (
    if not exist "output" mkdir "output"
    echo [android-phone-worker] Starting Appium: !APPIUM_EXE! --base-path /
    powershell -NoProfile -ExecutionPolicy Bypass -Command ^
      "$appium = $env:APPIUM_EXE; $out = Join-Path (Get-Location) 'output\appium-worker.out.log'; $err = Join-Path (Get-Location) 'output\appium-worker.err.log'; Start-Process -FilePath $appium -ArgumentList '--base-path','/' -WorkingDirectory (Get-Location) -WindowStyle Hidden -RedirectStandardOutput $out -RedirectStandardError $err | Out-Null; $deadline = (Get-Date).AddSeconds(25); do { Start-Sleep -Milliseconds 500; $ok = Test-NetConnection 127.0.0.1 -Port 4723 -InformationLevel Quiet -WarningAction SilentlyContinue } until ($ok -or (Get-Date) -gt $deadline); if (-not $ok) { exit 1 }"
    if errorlevel 1 (
      echo [android-phone-worker] Appium was started but 127.0.0.1:4723 did not become ready.
      echo [android-phone-worker] Check output\appium-worker.err.log and output\appium-worker.out.log.
      echo [android-phone-worker] OTP worker can still run in adb notification mode.
    ) else (
      echo [android-phone-worker] Appium is listening on 127.0.0.1:4723.
    )
  )
) else (
  echo [android-phone-worker] Appium already listening on 127.0.0.1:4723.
)

echo.
echo [android-phone-worker] Starting worker with %CONFIG%
echo [android-phone-worker] Press Ctrl+C to stop.
echo.

python "%WORKER%" --config "%CONFIG%"

echo.
echo [android-phone-worker] Worker exited with code %ERRORLEVEL%.
pause
exit /b %ERRORLEVEL%
