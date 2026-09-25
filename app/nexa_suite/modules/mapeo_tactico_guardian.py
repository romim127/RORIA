# -*- coding: utf-8 -*-
"""
NEXA - Mapeo tactico Guardian / GETAC.

Adaptacion web-safe del motor GETAC:
- no usa input() interactivo;
- no mueve ni altera el CSV fuente;
- conserva la logica operativa de operador dominante y acoplamiento fisico;
- genera TXT/HTML auditables dentro de la corrida NEXA.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Tuple
import html

import pandas as pd


OPERADORES_LOCALES = ["CLARO", "PERSONAL", "MOVISTAR"]


def _html_page(title: str, body: str) -> str:
    return f"""<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <title>{html.escape(title)}</title>
  <style>
    body {{ font-family: Segoe UI, Arial, sans-serif; margin: 28px; color: #071527; }}
    h1 {{ color: #003b69; }}
    h2 {{ color: #005180; margin-top: 24px; }}
    .card {{ border: 1px solid #cfd8e3; border-radius: 8px; padding: 14px; margin: 12px 0; }}
    .line {{ font-family: Consolas, monospace; white-space: pre-wrap; background: #07111f; color: #eaf9ff; padding: 16px; border-radius: 8px; }}
    .grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; }}
    .metric {{ border: 1px solid #cfd8e3; border-radius: 8px; padding: 10px; background: #f7fbff; }}
    .label {{ color: #5c6b7a; font-size: 12px; text-transform: uppercase; }}
    .value {{ font-size: 20px; font-weight: 800; color: #003b69; }}
    ul {{ line-height: 1.55; }}
  </style>
</head>
<body>{body}</body>
</html>"""


def obtener_acoplamiento_completo(operador: str, tipo_antena: str, lado: str) -> Tuple[str, List[str]]:
    """
    Combina el tipo de antena, el operador dominante y la matriz de conectores
    fisicos de la caja Guardian.
    """
    operador = str(operador or "").strip().upper()
    if tipo_antena == "1":
        modo_str = "OMNIDIRECCIONAL (Cobertura Radial 360°)"
        if operador == "PERSONAL":
            return modo_str, [
                "Fila 1 [ 850/1900 (G/U/L) ]: Conectar Antena Omni Principal (Base Radial)",
                "Fila 2 [ 700 (L)/1900 (U/L) ]: Conectar Antena Omni de Capacidad LTE",
                "Fila 3 [ 1700 (U/L) ]: Conectar Antena Omni AWS",
            ]
        if operador == "CLARO":
            return modo_str, [
                "Fila 1 [ 850/1900 (G/U/L) ]: Conectar Antena Omni Principal (Base Radial)",
                "Fila 2 [ 700 (L)/1700 (U/L) ]: Conectar Antena Omni LTE/AWS",
                "Fila 4 [ 900 (U/L) ]: Conectar Antena Omni GSM/UMTS",
            ]
        return modo_str, [
            "Fila 1 [ 850/1900 (G/U/L) ]: Conectar Antena Omni Principal (Base Radial)",
            "Fila 3 [ 2600 (L) ]: Conectar Antena Omni Capacidad",
            "Fila 4 [ 2600 TX ]: Conectar Antena Omni Anclaje (Tx)",
        ]

    lado_str = "IZQUIERDO (SECTOR A)" if lado == "1" else "DERECHO (SECTOR B)"
    modo_str = f"DIRECCIONAL ({lado_str} - Alta Ganancia Azimutal)"
    if operador == "PERSONAL":
        return modo_str, [
            f"Fila 1 [ 850/1900 (G/U/L) ]: Antena Direccional Principal (Captura) -> {lado_str}",
            f"Fila 2 [ 700 (L)/1900 (U/L) ]: Antena Direccional de Seguimiento -> {lado_str}",
            f"Fila 3 [ 1700 (U/L) ]: Antena Direccional AWS -> {lado_str}",
        ]
    if operador == "CLARO":
        return modo_str, [
            f"Fila 1 [ 850/1900 (G/U/L) ]: Antena Direccional Principal (Captura) -> {lado_str}",
            f"Fila 2 [ 700 (L)/1700 (U/L) ]: Antena Direccional LTE/AWS -> {lado_str}",
            f"Fila 4 [ 900 (U/L) ]: Antena Direccional GSM/UMTS -> {lado_str}",
        ]
    return modo_str, [
        f"Fila 1 [ 850/1900 (G/U/L) ]: Antena Direccional Principal (Captura) -> {lado_str}",
        f"Fila 3 [ 2600 (L) ]: Antena Direccional de Capacidad -> {lado_str}",
        f"Fila 4 [ 2600 TX ]: Antena Direccional de Anclaje (Tx) -> {lado_str}",
    ]


def _resolve_antena_options(orientation: str, antennas: str = "") -> Tuple[str, str, str]:
    orientation = str(orientation or "").strip().upper()
    antennas = str(antennas or "").strip().upper()
    if "OMNI" in antennas or orientation in {"OMNI", "OMNIDIRECCIONAL"}:
        return "1", "1", "Omnidireccional"
    if orientation == "DEF_DERECHA":
        return "2", "2", "Direccional derecha"
    if orientation == "ABC_IZQUIERDA":
        return "2", "1", "Direccional izquierda"
    if "DIREC" in antennas:
        return "2", "1", "Direccional izquierda por defecto"
    return "1", "1", "Omnidireccional por defecto"


def analizar_networkcfg(csv_path: Path) -> Dict[str, object]:
    df = pd.read_csv(csv_path, encoding="utf-8-sig")
    df.columns = df.columns.str.strip()
    required = ["Network Name", "Rx Level"]
    missing = [col for col in required if col not in df.columns]
    if missing:
        raise ValueError(f"El CSV no contiene las columnas esperadas: {missing}")

    df_real = df[df["Network Name"].astype(str).str.strip().str.upper().isin(OPERADORES_LOCALES)].copy()
    df_real["Network Name"] = df_real["Network Name"].astype(str).str.strip().str.upper()
    df_real["Rx Level_num"] = pd.to_numeric(df_real["Rx Level"], errors="coerce")
    df_real = df_real.dropna(subset=["Rx Level_num"])
    if df_real.empty:
        raise ValueError("El archivo no contiene registros validos de Claro, Personal o Movistar.")

    celda_dominante = df_real.loc[df_real["Rx Level_num"].idxmax()]
    return {
        "operador_dominante": str(celda_dominante.get("Network Name", "")).strip().upper(),
        "potencia_dominante": str(celda_dominante.get("Rx Level", "")),
        "tecnologia_dominante": str(celda_dominante.get("Net Type", "N/A")),
        "canal_dominante": str(celda_dominante.get("ARFCN", "N/A")),
        "lac": str(celda_dominante.get("LAC", "")) if "LAC" in df.columns else "",
        "cell_id": str(celda_dominante.get("Cell ID", "")) if "Cell ID" in df.columns else "",
        "total_celdas_validas": int(len(df_real)),
    }


def generar_reporte_texto(csv_path: Path, orientation: str, antennas: str = "") -> Tuple[str, Dict[str, object]]:
    analisis = analizar_networkcfg(csv_path)
    operador = str(analisis["operador_dominante"])
    tipo_antena, lado_opcion, seleccion = _resolve_antena_options(orientation, antennas)
    modo_descripcion, config_puertos = obtener_acoplamiento_completo(operador, tipo_antena, lado_opcion)

    reporte = [
        "=" * 75,
        f"        INFORME TACTICO UNIFICADO - ARCHIVO: {csv_path.name}",
        "=" * 75,
        f"OPERADOR DETECTADO (MAS FUERTE): {operador}",
        f"DETALLE: Canal {analisis['canal_dominante']} | Tipo: {analisis['tecnologia_dominante']} | Nivel: {analisis['potencia_dominante']}",
        f"SELECCION OPERATIVA: {seleccion}",
        f"MODO DE ARREGLO: {modo_descripcion}",
        "-" * 75,
        "1. ACOPLAMIENTO DE CONECTORES FISICOS (CAJA GUARDIAN):",
        "-" * 75,
    ]
    for puerto in config_puertos:
        reporte.append(f"[+] {puerto}")

    reporte.extend([
        "-" * 75,
        "2. CRITERIOS DE INGENIERIA PARA LA SELECCION:",
        "   - OMNIDIRECCIONAL: usar en fases iniciales de barrido ciego o captura general donde la posicion del objetivo es incierta.",
        "   - DIRECCIONAL: usar en fase de honing o rastreo preciso una vez acotado el sector, aprovechando la directividad del lobulo para maximizar RSSI y SNR.",
        "=" * 75,
    ])

    analisis.update({
        "tipo_antena": tipo_antena,
        "lado_opcion": lado_opcion,
        "seleccion_operativa": seleccion,
        "modo_descripcion": modo_descripcion,
        "config_puertos": config_puertos,
    })
    return "\n".join(reporte), analisis


def generar_mapeo_tactico(csv_path: Path, out_dir: Path, orientation: str, antennas: str = "") -> Dict[str, object]:
    out_dir.mkdir(parents=True, exist_ok=True)
    texto, analisis = generar_reporte_texto(csv_path, orientation, antennas)

    txt_path = out_dir / f"machete_{csv_path.stem}.txt"
    txt_path.write_text(texto + "\n", encoding="utf-8")

    puertos_html = "".join(f"<li>{html.escape(str(puerto))}</li>" for puerto in analisis["config_puertos"])
    body = f"""
<h1>NEXA - Mapeo tactico Guardian / GETAC</h1>
<div class="grid">
  <div class="metric"><div class="label">Prestadora dominante</div><div class="value">{html.escape(str(analisis['operador_dominante']))}</div></div>
  <div class="metric"><div class="label">Canal / ARFCN</div><div class="value">{html.escape(str(analisis['canal_dominante']))}</div></div>
  <div class="metric"><div class="label">Tecnologia</div><div class="value">{html.escape(str(analisis['tecnologia_dominante']))}</div></div>
  <div class="metric"><div class="label">Rx Level</div><div class="value">{html.escape(str(analisis['potencia_dominante']))}</div></div>
</div>
<div class="card">
  <strong>Archivo:</strong> {html.escape(csv_path.name)}<br>
  <strong>LAC:</strong> {html.escape(str(analisis.get('lac') or '-'))}<br>
  <strong>Cell ID:</strong> {html.escape(str(analisis.get('cell_id') or '-'))}<br>
  <strong>Seleccion operativa:</strong> {html.escape(str(analisis['seleccion_operativa']))}<br>
  <strong>Modo de arreglo:</strong> {html.escape(str(analisis['modo_descripcion']))}<br>
  <strong>Celdas validas leidas:</strong> {html.escape(str(analisis['total_celdas_validas']))}
</div>
<h2>Acoplamiento de conectores fisicos</h2>
<div class="card"><ul>{puertos_html}</ul></div>
<h2>Reporte canonico</h2>
<div class="line">{html.escape(texto)}</div>
"""
    html_path = out_dir / f"mapeo_tactico_{csv_path.stem}.html"
    html_path.write_text(_html_page("NEXA - Mapeo tactico Guardian / GETAC", body), encoding="utf-8")

    return {
        "txt_path": txt_path,
        "html_path": html_path,
        "analysis": analisis,
    }
