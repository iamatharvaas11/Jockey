@echo off
echo ============================================
echo    JOCKY Forensic Investigation Framework
echo ============================================
echo.

REM Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH.
    echo Please install Python 3.10+ from https://python.org
    pause
    exit /b 1
)

echo [*] Python found.
echo.

REM Create virtual environment if it doesn't exist
if not exist "venv" (
    echo [*] Creating virtual environment...
    python -m venv venv
    echo [+] Virtual environment created.
) else (
    echo [*] Virtual environment already exists.
)

echo [*] Activating virtual environment...
call venv\Scripts\activate.bat

echo [*] Installing dependencies...
pip install -e . --quiet

echo.
echo [+] Setup complete!
echo.
echo ============================================
echo    Starting JOCKY Server...
echo    Dashboard: http://localhost:8000
echo    API Docs:  http://localhost:8000/docs
echo ============================================
echo.

python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
