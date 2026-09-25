$ErrorActionPreference = "Stop"

$port = if ($env:RED_OPERATIVA_PORT) { [int]$env:RED_OPERATIVA_PORT } else { 8770 }
$env:SKYEYE_RELATIONAL_STANDALONE = "1"
$env:SKYEYE_DATA_DIR = Join-Path $PSScriptRoot "datos_locales"

Write-Host "============================================================"
Write-Host "RED OPERATIVA RELACIONAL - APP INDEPENDIENTE"
Write-Host "URL local: http://127.0.0.1:$port/red-operativa"
Write-Host "Datos locales: $env:SKYEYE_DATA_DIR"
Write-Host "Cierra esta terminal para detener el servicio local."
Write-Host "============================================================"

Start-Process "http://127.0.0.1:$port/red-operativa"
python -m uvicorn red_operativa_app:app --host 127.0.0.1 --port $port
