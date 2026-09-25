# RORIA

Red Operativa Relacional para investigacion y analisis forense de vinculos operativos, entidades, IMSI/IMEI, histories, evidencia, escenarios y colaboracion controlada entre analistas autorizados, con apoyo de IA.

Aplicacion local independiente para trabajar hojas relacionales operativas: canvas, entidades, vinculos, histories, evidencias, ficha tecnica y exportaciones.

## Arranque local

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
.\run_red_operativa.ps1
```

URL local:

```text
http://127.0.0.1:8770/red-operativa
```

Si el puerto esta ocupado:

```powershell
$env:RED_OPERATIVA_PORT=8771
.\run_red_operativa.ps1
```

## Entrada de la app

- Backend: `red_operativa_app.py`
- Frontend: `app/frontend/red_operativa.html`
- Launcher Windows: `run_red_operativa.ps1`
- Launcher ejecutable: `scripts/red_operativa_relacional_launcher.py`

## Datos locales

Los datos locales se guardan fuera del codigo, por defecto en:

```text
datos_locales/
```

Esa carpeta esta ignorada por Git para no subir bases, uploads ni evidencia operativa.

## Deploy

`render.yaml` apunta a:

```text
uvicorn red_operativa_app:app --host 0.0.0.0 --port $PORT
```

La variable `SKYEYE_RELATIONAL_STANDALONE=1` debe estar activa para permitir el acceso standalone de Red Operativa.
