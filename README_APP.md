# SkyEye Ops App (MVP)

## Que incluye
- API: FastAPI (`app/api.py`)
- Base de datos: SQLite (`app_data/skyeye_app.db`)
- Frontend: HTML/JS (`app/frontend/index.html`)
- Flujo end-to-end:
  - Detection Report -> `reporte_detecciones.html`
  - Pipeline georef -> KML trayectorias + KML ultimas posiciones + TXT
  - Caso M3T -> `busqueda_M3T_perdido.kml`

## Donde colocar reportes diarios
Copiar los CSV diarios en:

`reportes_diarios_entrada/`

El sistema detecta automaticamente:
- Detection Report (obligatorio)
- CSV de trayectoria tipo PRUEBA1 (opcional, recomendado)

## Ejecutar
1. Instalar dependencias:
   - `pip install -r requirements.txt`
2. Levantar app:
   - `powershell -ExecutionPolicy Bypass -File .\run_app.ps1`
3. Abrir en navegador:
   - `http://localhost:8000`

## Compartir por link publico (sin localhost)
1. Deja la app corriendo en puerto 8000 (`run_app.ps1`).
2. En otra terminal ejecuta:
   - `powershell -ExecutionPolicy Bypass -File .\\compartir_link_publico.ps1`
3. Copia la URL `https://....loca.lt` y compartela.

Atajo para levantar app + tunel:
- `powershell -ExecutionPolicy Bypass -File .\\compartir_link_publico.ps1 -StartApp`

Nota:
- El link publico vive mientras la terminal del tunel siga abierta.

## Deploy permanente en Render
Este repo ya incluye `render.yaml` listo para deploy.

1. En Render: `New +` -> `Blueprint`.
2. Conecta este repo de GitHub.
3. Render detecta `render.yaml` y crea el servicio `skyeye-ops`.
4. Al finalizar, abre la URL de Render (ej: `https://skyeye-ops.onrender.com`).

Notas:
- Usa disco persistente montado en `/var/data` para corridas y CSV.
- Ya puedes subir CSV desde la propia web (no hace falta acceso al servidor).

## Login inicial
- No documentar usuarios ni claves en el repositorio.
- El alta inicial de usuarios administradores debe realizarse en un entorno controlado.
- Roles visibles en pantalla (centro): `OPERADOR`, `ANALISTA`, `ADMIN`
- La primera pantalla es solo ingreso de usuario.
- Luego del login se habilitan: flujo completo, cierre de sesion, cambio de clave y gestion de usuarios (si rol admin).

## Endpoints API
- `GET /api/health`
- `POST /api/auth/login`
- `POST /api/auth/logout`
- `GET /api/auth/me`
- `POST /api/auth/change-password`
- `GET /api/config`
- `POST /api/runs/process-latest`
- `GET /api/runs`
- `GET /api/runs/{id}`
- `GET /api/users` (admin)
- `POST /api/users` (admin)

## Salidas de cada corrida
Se guardan en:

`app_outputs/run_YYYYMMDD_HHMMSS/`

Con archivos:
- `reporte_detecciones.html`
- `georef/trayectorias_drones.kml`
- `georef/ultimas_posiciones_drones.kml`
- `georef/reporte_georeferenciacion.txt`
- `busqueda_M3T_perdido.kml`
