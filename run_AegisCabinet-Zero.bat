@echo off
setlocal
cd /d "%~dp0"
set "PYTHON_CMD=python"
where py >nul 2>nul
if not errorlevel 1 set "PYTHON_CMD=py -3"

%PYTHON_CMD% -c "import streamlit" >nul 2>nul
if errorlevel 1 (
    echo [AegisCabinet-Zero] Installing missing dependencies...
    %PYTHON_CMD% -m pip install -r requirements.txt
)

netstat -ano | findstr ":8501" >nul 2>nul
if not errorlevel 1 (
    echo [AegisCabinet-Zero] Port 8501 is already in use. Streamlit will handle the session.
)

%PYTHON_CMD% -m streamlit run app.py --server.address=127.0.0.1 --server.port=8501
pause
