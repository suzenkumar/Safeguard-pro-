@echo off
rem ==============================================================
rem  Safeguard Pro+ - AI Security Toolkit
rem  Launcher for Windows
rem  Made by Er-Suzen Kumar Mohanty - IBM Cyber Security Project
rem ==============================================================
rem
rem  Starts the combined dashboard at http://127.0.0.1:5000
rem  The network assessment workspace is available at /network/
rem --------------------------------------------------------------

setlocal
cd /d "%~dp0"

set "PYEXE=py -3"
if exist "venv\Scripts\python.exe" set "PYEXE=venv\Scripts\python.exe"

%PYEXE% -c "import flask, sklearn, psutil, docx, reportlab" >nul 2>&1
if errorlevel 1 (
    echo Installing Safeguard Pro+ dependencies...
    %PYEXE% -m pip install --upgrade pip
    %PYEXE% -m pip install -r requirements.txt
    if errorlevel 1 (
        echo [error] Dependency installation failed.
        pause
        exit /b 1
    )
)

if not exist "models\url_model.joblib" (
    echo Training URL model...
    %PYEXE% train_model.py
)
if not exist "models\email_model.joblib" (
    echo Training email model...
    %PYEXE% train_model.py
)

echo Starting Safeguard Pro+ - open http://127.0.0.1:5000
echo Network assessment: http://127.0.0.1:5000/network/
echo Press Ctrl + C to stop.
echo.
%PYEXE% SUZENKUMARMOHANTYPHISHINGGUARD.py
pause
