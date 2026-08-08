@echo off
rem Batch script to run the pytest suite within the virtual environment
if exist "%~dp0venv\Scripts\pytest.exe" (
    "%~dp0venv\Scripts\pytest.exe" %*
) else (
    echo Error: Virtual environment or pytest executable not found.
    echo Please run python -m venv venv and pip install -e .[dev]
    exit /b 1
)
