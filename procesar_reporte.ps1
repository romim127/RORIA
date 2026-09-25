$python = "c:/Sistema_Inhibidor_SkyEye/.venv/Scripts/python.exe"
$script = "src/utils/operacion_diaria.py"

if (-not (Test-Path $python)) {
    Write-Error "No se encontro el entorno Python en $python"
    exit 1
}

& $python $script @args
