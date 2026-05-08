@echo off
setlocal EnableExtensions

set "LANE_ID=lane-02"
set "CONFIG=CTF-pay\config.android-gopay.lane-02.local.json"
set "PHONE_WORKER_ADB_SERIAL=127.0.0.1:16448"
set "PHONE_WORKER_ADB_CONNECT_SERIALS=127.0.0.1:16448"
set "PHONE_WORKER_APPIUM_PORT=4724"

call "%~dp0scripts\start_android_phone_worker_lane.bat"
exit /b %ERRORLEVEL%
