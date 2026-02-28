@echo off
title SafeClick - Phishing Detection
cd /d "%~dp0"

echo =============================================
echo  SafeClick - Intelligent Phishing Detection
echo =============================================
echo.

:: Check if Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python not found. Please install Python 3.10+
    echo Download from: https://www.python.org/downloads/
    pause
    exit /b 1
)

:: Install dependencies if needed
echo Checking dependencies...
python -m pip install -q scikit-learn pandas numpy pyperclip plyer 2>nul

echo Starting SafeClick...
python main.py
pause
