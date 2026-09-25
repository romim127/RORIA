$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

param(
    [switch]$StartApp
)

if ($StartApp) {
    Start-Process powershell -ArgumentList '-NoExit','-ExecutionPolicy','Bypass','-File','.\run_app.ps1' -WorkingDirectory $PSScriptRoot | Out-Null
    Start-Sleep -Seconds 3
}

Write-Host "Creando tunel publico para http://localhost:8000 ..." -ForegroundColor Cyan
npx localtunnel --port 8000
