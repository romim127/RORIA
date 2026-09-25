RED OPERATIVA RELACIONAL - APP SEPARADA PARA VSCODE

Esta carpeta contiene una app local separada para trabajar Red Operativa Relacional sin tocar la plataforma principal.
La entrada propia es red_operativa_app.py y la pantalla propia es app/frontend/red_operativa.html.
No incluye base de datos productiva, datos operativos, uploads, reportes, outputs, build, dist ni .git.

Arranque:
1. Abrir esta carpeta en VSCode.
2. Activar el entorno virtual.
3. Ejecutar:
   .\run_red_operativa.ps1

URL:
http://127.0.0.1:8770/red-operativa

Si el puerto 8770 esta ocupado:
$env:RED_OPERATIVA_PORT=8771
.\run_red_operativa.ps1

Cuando una mejora quede estable, se reintegra quirurgicamente en la plataforma principal.

Ultimo commit fuente copiado: c0e93d6 Refine relational network workspace panels
