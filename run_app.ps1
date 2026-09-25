$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

if (-not (Test-Path ".\.venv\Scripts\python.exe")) {
    Write-Error "No existe .venv. Crea/activa el entorno primero."
}

& ".\.venv\Scripts\python.exe" -m uvicorn app.api:app --host 0.0.0.0 --port 8000
