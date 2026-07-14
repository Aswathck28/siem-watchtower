@echo off
setlocal enabledelayedexpansion
echo =========================================
echo   SIEM-Watchtower ML Service Launcher
echo =========================================

:: Check if virtual environment exists
if not exist "%~dp0venv\Scripts\activate.bat" (
    echo [SETUP] Creating virtual environment...
    python -m venv "%~dp0venv"
    if !errorlevel! neq 0 (
        echo [ERROR] Failed to create venv. Make sure Python 3.8+ is installed.
        pause
        exit /b 1
    )
)

:: Activate venv
call "%~dp0venv\Scripts\activate.bat"

:: Install requirements
echo [SETUP] Installing/verifying dependencies...
pip install -r "%~dp0requirements.txt" --quiet

:: Check if models exist
if not exist "%~dp0isolation_forest.pkl" (
    echo [TRAIN] Model files not found. Training now (takes ~30 seconds)...
    python "%~dp0train.py"
    if !errorlevel! neq 0 (
        echo [ERROR] Training failed. Check Python environment.
        pause
        exit /b 1
    )
) else (
    echo [INFO] Model files found. Skipping training.
)

:: Start Flask service
echo [START] Launching ML service on port 5001...
python "%~dp0app.py"

pause
