# PowerShell script to run the pytest suite within the virtual environment
if (Test-Path ".\venv\Scripts\pytest.exe") {
    & ".\venv\Scripts\pytest.exe" @args
} else {
    Write-Error "Virtual environment or pytest executable not found. Please run python -m venv venv and pip install -e .[dev]"
}
