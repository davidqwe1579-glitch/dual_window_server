@echo off
setlocal enabledelayedexpansion
title ASTER Worker Global Setup (All Users)

:: Check Admin
echo [*] Checking Admin...
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [!] Please run as Administrator.
    pause
    exit /b
)

echo.
echo [*] Killing existing worker...
taskkill /f /im dual_window.exe >nul 2>&1
timeout /t 2 >nul

echo [*] Resetting port registry...
if exist "C:\Users\Public\worker_ports.txt" del /f /q "C:\Users\Public\worker_ports.txt"

echo.
echo [*] Updating executable...
if exist "%~dp0dual_window.exe" (
    copy /y "%~dp0dual_window.exe" "C:\Users\Public\dual_window.exe"
)

if %errorlevel% neq 0 (
    echo [!] Copy failed. Retrying...
    taskkill /f /fi "IMAGENAME eq dual_window.exe" /t >nul 2>&1
    copy /y "%~dp0dual_window.exe" "C:\Users\Public\dual_window.exe"
)

:: Get current username
for /f "tokens=*" %%u in ('whoami') do set "current_full_user=%%u"
set "curr_user=%current_full_user%"
echo %current_full_user% | find "\" >nul && (
    for /f "tokens=2 delims=\" %%u in ("%current_full_user%") do set "curr_user=%%u"
)

echo.
echo [*] Registering Global Task for All Users on Logon...
set "TASK_NAME=DualWindowWorker_Logon"
set "EXE_PATH=C:\Users\Public\dual_window.exe"

:: 1. Delete old tasks if exists
schtasks /delete /tn "DualWindowWorker_Global" /f >nul 2>&1
schtasks /delete /tn "%TASK_NAME%" /f >nul 2>&1

:: 2. Create individual OnLogon tasks for EACH user profile
echo [*] Scanning user profiles and creating individual tasks...
for /d %%d in (C:\Users\*) do (
    set "U_NAME=%%~nxd"
    if /I "!U_NAME!" neq "Public" (
        if /I "!U_NAME!" neq "Default" (
            if /I "!U_NAME!" neq "Default User" (
                :: Always delete old task if exists for a clean state
                schtasks /delete /tn "DualWindowWorker_!U_NAME!" /f >nul 2>&1
                
                :: Only register task for users that are NOT the current main user
                if /I "!U_NAME!" neq "%curr_user%" (
                    echo  - Registering task for user: !U_NAME!
                    schtasks /create /tn "DualWindowWorker_!U_NAME!" /tr "\"%EXE_PATH%\" --worker --no-elevate" /sc onlogon /ru "!U_NAME!" /rl highest /f >nul 2>&1
                ) else (
                    echo  - Skipping worker registration for main user: !U_NAME!
                )
            )
        )
    )
)

:: 3. Remove old HKLM Run registry key to prevent duplicate execution
echo [*] Cleaning up old registry entries...
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "AsterDualWorker" /f >nul 2>&1

echo [V] Global registration successful.

echo.
echo [*] Logging off other users...
for /f "skip=1 tokens=1,2,3" %%a in ('query user') do (
    set "first_token=%%a"
    if "!first_token:~0,1!"==">" (
        echo [*] Skipping current session: %%a
    ) else (
        set "uname=%%a"
        set "sid=%%b"
        set "is_numeric=1"
        for /f "delims=0123456789" %%i in ("!sid!") do set "is_numeric=0"
        if "!is_numeric!"=="0" (
            set "sid=%%c"
        )
        if "!sid!" neq "" (
            echo [!] Logging off: !uname! (Session ID: !sid!)
            logoff !sid! >nul 2>&1
        )
    )
)

echo.
echo [V] Setup Complete.
echo Other users (except current) will run the worker on login with automatic elevation.
pause