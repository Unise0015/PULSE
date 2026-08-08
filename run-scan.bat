@echo off
rem Batch script to run the PULSE Security Scanner CLI within the virtual environment
if exist "%~dp0venv\Scripts\pulse.exe" (
    "%~dp0venv\Scripts\pulse.exe" %*
) else (
    echo Error: Virtual environment or pulse executable not found.
    echo Please run python -m venv venv and pip install -e .
    exit /b 1
)
