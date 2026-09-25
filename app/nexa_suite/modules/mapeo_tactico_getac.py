# -*- coding: utf-8 -*-
"""
Entrada compatible para el mapeo tactico GETAC integrado en NEXA.

La plataforma ejecuta este motor en modo controlado mediante
`mapeo_tactico_guardian.generar_mapeo_tactico`.
"""

from __future__ import annotations

from pathlib import Path

try:
    from app.nexa_suite.modules.mapeo_tactico_guardian import generar_mapeo_tactico
except ModuleNotFoundError:
    from mapeo_tactico_guardian import generar_mapeo_tactico


def main() -> None:
    base = Path("C:/bandas_2")
    csv_files = sorted(p for p in base.glob("*.csv") if p.is_file())
    if not csv_files:
        print(f"[-] No se encontraron archivos .csv en la ruta: {base}")
        return
    result = generar_mapeo_tactico(csv_files[0], base, orientation="ABC_IZQUIERDA", antennas="DIRECCIONALES")
    print(f"[+] Archivo de consulta generado: {Path(result['txt_path']).name}")
    print(f"[+] HTML generado: {Path(result['html_path']).name}")


if __name__ == "__main__":
    main()
