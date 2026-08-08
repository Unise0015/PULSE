# PowerShell script to run the PULSE Security Scanner CLI within the virtual environment
if (Test-Path ".\venv\Scripts\pulse.exe") {
    & ".\venv\Scripts\pulse.exe" @args
} else {
    Write-Error "Virtual environment or pulse executable not found. Please run python -m venv venv and pip install -e ."
}
