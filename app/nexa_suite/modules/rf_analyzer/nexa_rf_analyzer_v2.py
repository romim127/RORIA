#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NEXA RF ANALYZER v2 - Informe técnico RF Guardian/Septier

Corrección principal v2:
- El archivo history.csv se procesa usando el campo "Home Network" para la
  distribución real de operadores detectados.
- El valor "Clear Channel" del networkcfg.csv NO se interpreta como operador.
  Se informa por separado como canales libres/registros de configuración/escaneo.

Salida:
- Informe DOCX
- Informe PDF si LibreOffice está instalado
- Gráficos PNG
- Tablas CSV procesadas

Uso:
python nexa_rf_analyzer_v2.py --networkcfg networkcfg.csv --history history.csv --out salida_rf_uncuyo --firma "Romina S. Mercau" --cargo "Programmer | Digital Forensic Examiner"
"""

import argparse
import shutil
import subprocess
from datetime import datetime
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd
from docx import Document
from docx.enum.section import WD_ORIENT
from docx.enum.table import WD_CELL_VERTICAL_ALIGNMENT, WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Inches, Pt, RGBColor

NET_TYPE_MAP = {2: "2G / GSM", 3: "3G / UMTS", 4: "4G / LTE"}
CHANNEL_LABEL = {"2G / GSM": "ARFCN", "3G / UMTS": "UARFCN", "4G / LTE": "EARFCN"}
NATIONAL_OPERATORS = {"CLARO", "MOVISTAR", "PERSONAL"}


def read_csv_safely(path: Path) -> pd.DataFrame:
    for enc in ("utf-8-sig", "utf-8", "latin-1"):
        try:
            return pd.read_csv(path, encoding=enc)
        except UnicodeDecodeError:
            continue
    return pd.read_csv(path)


def clean_number(x):
    if pd.isna(x):
        return None
    try:
        f = float(x)
        if f.is_integer():
            return int(f)
        return round(f, 2)
    except Exception:
        return x


def normalize_op(value):
    if pd.isna(value):
        return "SIN_DATO"
    s = str(value).strip().upper()
    if not s or s in ("NAN", "NONE", "NULL"):
        return "SIN_DATO"
    return s


def normalize_networkcfg(path: Path) -> pd.DataFrame:
    df = read_csv_safely(path)
    required = ["Network Name", "ARFCN", "LAC", "Cell ID", "Rx Level", "Priority", "Net Type"]
    missing = [c for c in required if c not in df.columns]
    if missing:
        raise ValueError(f"El archivo networkcfg no contiene columnas requeridas: {missing}")
    out = df.copy()
    out["Operador_raw"] = out["Network Name"].apply(normalize_op)
    out["Es_Clear_Channel"] = out["Operador_raw"].eq("CLEAR CHANNEL")
    out["Operador"] = out["Operador_raw"].where(~out["Es_Clear_Channel"], "CANAL_LIBRE_CONFIG")
    out["Net Type Num"] = pd.to_numeric(out["Net Type"], errors="coerce")
    out["Tecnologia"] = out["Net Type Num"].map(NET_TYPE_MAP).fillna("SIN_DATO")
    out["Tipo Canal"] = out["Tecnologia"].map(CHANNEL_LABEL).fillna("CANAL")
    out["Canal"] = pd.to_numeric(out["ARFCN"], errors="coerce").apply(clean_number)
    for col in ["Rx Level", "Priority", "LAC", "Cell ID"]:
        if col in out.columns:
            out[col] = pd.to_numeric(out[col], errors="coerce").apply(clean_number)
    return out


def normalize_history(path: Path | None) -> pd.DataFrame | None:
    if not path:
        return None
    df = read_csv_safely(path)
    if "Event Time" in df.columns:
        df["Event Time Parsed"] = pd.to_datetime(df["Event Time"], errors="coerce")
    if "Home Network" not in df.columns:
        raise ValueError('El archivo history no contiene la columna requerida "Home Network"')
    df["Operador"] = df["Home Network"].apply(normalize_op)
    if "Network Type" in df.columns:
        df["Tecnologia"] = df["Network Type"].fillna("SIN_DATO").astype(str).str.upper().str.strip()
    else:
        df["Tecnologia"] = "SIN_DATO"
    if "Status" in df.columns:
        df["Estado"] = df["Status"].fillna("SIN_DATO").astype(str).str.strip()
    else:
        df["Estado"] = "SIN_DATO"
    return df


def count_table(df, cols, base_col=None):
    t = df.groupby(cols, dropna=False).size().reset_index(name="Registros")
    total = len(df) if base_col is None else df[base_col].sum()
    if total == 0:
        t["Porcentaje"] = 0.0
    else:
        t["Porcentaje"] = (t["Registros"] / total * 100).round(2)
    return t.sort_values("Registros", ascending=False)


def history_operator_summary(hist: pd.DataFrame) -> pd.DataFrame:
    if hist is None:
        return pd.DataFrame()
    unique_col = "IMSI" if "IMSI" in hist.columns else None
    if unique_col:
        t = hist.groupby("Operador", dropna=False).agg(Eventos=("Operador", "size"), IMSI_unicos=(unique_col, "nunique")).reset_index()
    else:
        t = hist.groupby("Operador", dropna=False).agg(Eventos=("Operador", "size")).reset_index()
        t["IMSI_unicos"] = ""
    total = t["Eventos"].sum()
    t["Porcentaje"] = (t["Eventos"] / total * 100).round(2)
    t["Tipo"] = t["Operador"].apply(lambda x: "Nacional" if x in NATIONAL_OPERATORS else ("Sin dato" if x == "SIN_DATO" else "Roaming / externo"))
    return t.sort_values("Eventos", ascending=False)


def history_technology_summary(hist: pd.DataFrame) -> pd.DataFrame:
    if hist is None:
        return pd.DataFrame()
    t = hist.groupby("Tecnologia", dropna=False).agg(Eventos=("Tecnologia", "size")) .reset_index()
    total = t["Eventos"].sum()
    t["Porcentaje"] = (t["Eventos"] / total * 100).round(2)
    return t.sort_values("Eventos", ascending=False)


def history_status_summary(hist: pd.DataFrame) -> pd.DataFrame:
    if hist is None:
        return pd.DataFrame()
    t = hist.groupby("Estado", dropna=False).agg(Eventos=("Estado", "size")).reset_index()
    total = t["Eventos"].sum()
    t["Porcentaje"] = (t["Eventos"] / total * 100).round(2)
    return t.sort_values("Eventos", ascending=False)


def channel_summary(net: pd.DataFrame) -> pd.DataFrame:
    carriers = net[~net["Es_Clear_Channel"]].copy()
    cols = ["Operador_raw", "Tecnologia", "Tipo Canal", "Canal"]
    t = carriers.groupby(cols, dropna=False).size().reset_index(name="Registros")
    t = t.rename(columns={"Operador_raw": "Operador"})
    total = len(carriers)
    t["Porcentaje"] = (t["Registros"] / total * 100).round(2) if total else 0
    return t.sort_values(["Operador", "Tecnologia", "Canal"])


def cells_summary(net: pd.DataFrame) -> pd.DataFrame:
    carriers = net[~net["Es_Clear_Channel"]].copy()
    cols = ["Operador_raw", "Tecnologia", "Tipo Canal", "Canal", "LAC", "Cell ID"]
    stats = carriers.groupby(cols, dropna=False).agg(
        Registros=("Canal", "size"),
        Rx_promedio=("Rx Level", "mean"),
        Rx_maximo=("Rx Level", "max"),
        Rx_minimo=("Rx Level", "min"),
    ).reset_index().rename(columns={"Operador_raw": "Operador"})
    for c in ["Rx_promedio", "Rx_maximo", "Rx_minimo"]:
        stats[c] = stats[c].round(2)
    return stats.sort_values(["Operador", "Tecnologia", "Canal", "Cell ID"])


def clear_channel_summary(net: pd.DataFrame) -> pd.DataFrame:
    cc = net[net["Es_Clear_Channel"]].copy()
    if cc.empty:
        return pd.DataFrame(columns=["Tecnologia", "Tipo Canal", "Canal_min", "Canal_max", "Registros"])
    return cc.groupby(["Tecnologia", "Tipo Canal"], dropna=False).agg(
        Canal_min=("Canal", "min"), Canal_max=("Canal", "max"), Registros=("Canal", "size")
    ).reset_index().sort_values("Registros", ascending=False)


def set_cell_shading(cell, fill):
    tcPr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:fill"), fill)
    tcPr.append(shd)


def set_repeat_table_header(row):
    trPr = row._tr.get_or_add_trPr()
    tblHeader = OxmlElement("w:tblHeader")
    tblHeader.set(qn("w:val"), "true")
    trPr.append(tblHeader)


def add_df_table(doc, df, max_rows=None, font_size=8):
    if df is None or df.empty:
        doc.add_paragraph("Sin registros disponibles.")
        return None
    shown = df.copy() if max_rows is None else df.head(max_rows).copy()
    table = doc.add_table(rows=1, cols=len(shown.columns))
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    table.style = "Table Grid"
    hdr = table.rows[0]
    set_repeat_table_header(hdr)
    for i, col in enumerate(shown.columns):
        hdr.cells[i].text = str(col)
        set_cell_shading(hdr.cells[i], "D9EAF7")
    for _, row in shown.iterrows():
        cells = table.add_row().cells
        for i, col in enumerate(shown.columns):
            val = row[col]
            if pd.isna(val):
                val = ""
            cells[i].text = str(val)
            cells[i].vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.CENTER
    for row in table.rows:
        for cell in row.cells:
            for p in cell.paragraphs:
                for run in p.runs:
                    run.font.name = "Arial"
                    run.font.size = Pt(font_size)
    if max_rows is not None and len(df) > max_rows:
        p = doc.add_paragraph(f"Nota: se muestran {max_rows} registros de {len(df)}. La tabla completa se exporta en CSV dentro de la carpeta de salida.")
        p.runs[0].italic = True
    return table


def add_para(doc, text, italic=False):
    p = doc.add_paragraph()
    r = p.add_run(text)
    r.italic = italic
    return p


def add_bullet(doc, text):
    return doc.add_paragraph(text, style="List Bullet")


def make_bar_chart(series, title, out_path, ylabel="Registros"):
    if series is None or len(series) == 0:
        return
    plt.figure(figsize=(8, 4.5))
    series.plot(kind="bar")
    plt.title(title)
    plt.ylabel(ylabel)
    plt.xticks(rotation=35, ha="right")
    plt.tight_layout()
    plt.savefig(out_path, dpi=180)
    plt.close()


def configure_doc(doc):
    sec = doc.sections[0]
    sec.top_margin = Inches(0.7)
    sec.bottom_margin = Inches(0.7)
    sec.left_margin = Inches(0.75)
    sec.right_margin = Inches(0.75)
    styles = doc.styles
    styles["Normal"].font.name = "Arial"
    styles["Normal"].font.size = Pt(10)
    for style_name in ["Heading 1", "Heading 2", "Heading 3"]:
        styles[style_name].font.name = "Arial"
        styles[style_name].font.color.rgb = RGBColor(31, 78, 121)


def generate_report(networkcfg_path, history_path, out_dir, firma, cargo, firma_img=None, lugar="UNCUYO - BACT II", nota="____/26"):
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    charts_dir = out_dir / "graficos"
    tables_dir = out_dir / "tablas_procesadas"
    charts_dir.mkdir(exist_ok=True)
    tables_dir.mkdir(exist_ok=True)

    net = normalize_networkcfg(Path(networkcfg_path))
    hist = normalize_history(Path(history_path)) if history_path else None

    hist_ops = history_operator_summary(hist)
    hist_tech = history_technology_summary(hist)
    hist_status = history_status_summary(hist)
    hist_op_tech = pd.crosstab(hist["Operador"], hist["Tecnologia"]).reset_index() if hist is not None else pd.DataFrame()
    hist_op_status = pd.crosstab(hist["Operador"], hist["Estado"]).reset_index() if hist is not None else pd.DataFrame()

    carrier_net = net[~net["Es_Clear_Channel"]].copy()
    net_ops = count_table(carrier_net, ["Operador_raw"]).rename(columns={"Operador_raw": "Operador"}) if not carrier_net.empty else pd.DataFrame()
    net_tech = count_table(carrier_net, ["Tecnologia"]) if not carrier_net.empty else pd.DataFrame()
    net_op_tec = count_table(carrier_net, ["Operador_raw", "Tecnologia"]).rename(columns={"Operador_raw": "Operador"}) if not carrier_net.empty else pd.DataFrame()
    channels = channel_summary(net)
    cells = cells_summary(net)
    clear_channels = clear_channel_summary(net)

    # Export processed data
    hist_ops.to_csv(tables_dir / "01_history_operadores_home_network.csv", index=False, encoding="utf-8-sig")
    hist_tech.to_csv(tables_dir / "02_history_tecnologias.csv", index=False, encoding="utf-8-sig")
    hist_status.to_csv(tables_dir / "03_history_estados.csv", index=False, encoding="utf-8-sig")
    hist_op_tech.to_csv(tables_dir / "04_history_operador_tecnologia.csv", index=False, encoding="utf-8-sig")
    hist_op_status.to_csv(tables_dir / "05_history_operador_estado.csv", index=False, encoding="utf-8-sig")
    net_ops.to_csv(tables_dir / "06_networkcfg_operadores_sin_clear_channel.csv", index=False, encoding="utf-8-sig")
    net_tech.to_csv(tables_dir / "07_networkcfg_tecnologias.csv", index=False, encoding="utf-8-sig")
    channels.to_csv(tables_dir / "08_networkcfg_canales_arfcn_uarfcn_earfcn.csv", index=False, encoding="utf-8-sig")
    cells.to_csv(tables_dir / "09_networkcfg_celdas_identificadas.csv", index=False, encoding="utf-8-sig")
    clear_channels.to_csv(tables_dir / "10_networkcfg_clear_channel_informativo.csv", index=False, encoding="utf-8-sig")

    # Charts
    if not hist_ops.empty:
        make_bar_chart(hist_ops.set_index("Operador")["Eventos"].head(10), "Eventos por operador - fuente: history / Home Network", charts_dir / "eventos_por_operador.png", "Eventos")
    if not hist_tech.empty:
        make_bar_chart(hist_tech.set_index("Tecnologia")["Eventos"], "Eventos por tecnologia - fuente: history", charts_dir / "eventos_por_tecnologia.png", "Eventos")
    if not hist_status.empty:
        make_bar_chart(hist_status.set_index("Estado")["Eventos"], "Estados operativos registrados - fuente: history", charts_dir / "eventos_por_estado.png", "Eventos")
    if not channels.empty:
        top = channels.copy()
        top["Etiqueta"] = top["Operador"] + " - " + top["Tipo Canal"] + " " + top["Canal"].astype(str)
        make_bar_chart(top.sort_values("Registros", ascending=False).head(12).set_index("Etiqueta")["Registros"], "Canales ARFCN/UARFCN/EARFCN detectados", charts_dir / "canales_detectados.png")

    # Key values
    total_history = len(hist) if hist is not None else 0
    total_networkcfg = len(net)
    clear_count = int(net["Es_Clear_Channel"].sum())
    carrier_count = int((~net["Es_Clear_Channel"]).sum())
    unique_imsi = int(hist["IMSI"].nunique()) if hist is not None and "IMSI" in hist.columns else 0
    t_min = hist["Event Time Parsed"].min() if hist is not None and "Event Time Parsed" in hist.columns else None
    t_max = hist["Event Time Parsed"].max() if hist is not None and "Event Time Parsed" in hist.columns else None
    national_events = int(hist_ops.loc[hist_ops["Operador"].isin(NATIONAL_OPERATORS), "Eventos"].sum()) if not hist_ops.empty else 0
    roaming_events = int(hist_ops.loc[hist_ops["Tipo"].eq("Roaming / externo"), "Eventos"].sum()) if not hist_ops.empty else 0

    doc = Document()
    configure_doc(doc)

    title = doc.add_paragraph()
    title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = title.add_run("INFORME TECNICO DE RELEVAMIENTO RADIOELECTRICO")
    r.bold = True
    r.font.size = Pt(14)

    sub = doc.add_paragraph()
    sub.alignment = WD_ALIGN_PARAGRAPH.CENTER
    s = sub.add_run(f"Establecimiento: {lugar}\nSistema: GUARDIAN / antenas direccionales / modo BLOCK\nNota Nro.: {nota}")
    s.bold = True

    doc.add_heading("1. Objeto", 1)
    add_para(doc, f"Atento a lo solicitado, se deja constancia del resultado de la inspeccion ocular y tecnica efectuada en el establecimiento perteneciente a la Universidad Nacional de Cuyo, sector {lugar}, mediante la utilizacion del sistema GUARDIAN, con antenas direccionales y configuracion operativa en modo BLOCK.")
    add_para(doc, "El objeto del presente es informar las detecciones surgidas durante el relevamiento, describiendo operadores, tecnologias, estados operativos y canales radioelectricos ARFCN/UARFCN/EARFCN observados por el sistema durante la ventana temporal analizada.")
    add_para(doc, "El informe se limita a los registros exportados por el propio sistema y no incorpora inferencias no respaldadas por los archivos fuente.")

    doc.add_heading("2. Fuente de datos y criterio de procesamiento", 1)
    add_para(doc, f"Se procesaron dos fuentes exportadas por el sistema: archivo history, con {total_history} eventos operativos, y archivo networkcfg, con {total_networkcfg} registros de configuracion de red.")
    add_para(doc, "Para la distribucion de operadores detectados se utilizo exclusivamente el campo Home Network del archivo history. Este criterio corrige la interpretacion previa que podia confundir registros Clear Channel del archivo networkcfg con operadores de red.")
    add_para(doc, "El valor Clear Channel se informa de manera separada como dato propio de configuracion/escaneo del sistema y no como prestadora telefonica detectada.", italic=True)
    add_para(doc, "La nomenclatura de canales se mantiene conforme a cada tecnologia: ARFCN para GSM/2G, UARFCN para UMTS/3G y EARFCN para LTE/4G.")

    doc.add_heading("3. Resumen ejecutivo", 1)
    add_bullet(doc, f"Eventos operativos registrados en history: {total_history}")
    add_bullet(doc, f"IMSI unicos observados: {unique_imsi}")
    if pd.notna(t_min) and pd.notna(t_max):
        add_bullet(doc, f"Ventana temporal: {t_min.strftime('%d/%m/%Y %H:%M:%S')} a {t_max.strftime('%d/%m/%Y %H:%M:%S')}")
    add_bullet(doc, f"Eventos asociados a prestadoras nacionales (Claro, Movistar y Personal): {national_events}")
    add_bullet(doc, f"Eventos asociados a operadores externos/roaming: {roaming_events}")
    add_bullet(doc, f"Registros networkcfg de operadores celulares identificados: {carrier_count}")
    add_bullet(doc, f"Registros Clear Channel en networkcfg informados por separado: {clear_count}")

    doc.add_heading("4. Resultado del archivo history - Operadores detectados", 1)
    add_para(doc, "Del procesamiento del archivo history se determino que la mayor cantidad de eventos registrados corresponde a las prestadoras nacionales Claro, Movistar y Personal. La identificacion se realizo mediante el campo Home Network, por ser el campo que referencia la red de origen asociada al abonado detectado.")
    add_df_table(doc, hist_ops, max_rows=15, font_size=8)
    if (charts_dir / "eventos_por_operador.png").exists():
        doc.add_picture(str(charts_dir / "eventos_por_operador.png"), width=Inches(6.4))

    doc.add_heading("5. Tecnologias y estados operativos registrados", 1)
    add_para(doc, "La actividad registrada en history se concentro principalmente en tecnologia 4G/LTE, observandose tambien eventos 3G/UMTS y 2G/GSM. Asimismo, se registraron estados operativos propios del sistema, tales como Camped, Blocked y Released.")
    add_df_table(doc, hist_tech, font_size=8)
    doc.add_paragraph()
    add_df_table(doc, hist_status, font_size=8)
    if (charts_dir / "eventos_por_tecnologia.png").exists():
        doc.add_picture(str(charts_dir / "eventos_por_tecnologia.png"), width=Inches(6.4))
    if (charts_dir / "eventos_por_estado.png").exists():
        doc.add_picture(str(charts_dir / "eventos_por_estado.png"), width=Inches(6.4))

    doc.add_heading("6. Resultado del archivo networkcfg - Canales ARFCN/UARFCN/EARFCN", 1)
    add_para(doc, "El archivo networkcfg fue utilizado para identificar configuracion de celdas, canales radioelectricos, LAC, Cell ID, niveles de recepcion y tecnologia asociada. En esta seccion se excluyen los registros Clear Channel de la distribucion por prestadora, manteniendolos como informacion tecnica independiente.")
    add_df_table(doc, channels, max_rows=60, font_size=7)
    if (charts_dir / "canales_detectados.png").exists():
        doc.add_picture(str(charts_dir / "canales_detectados.png"), width=Inches(6.4))

    doc.add_heading("7. Registros Clear Channel", 1)
    add_para(doc, "Se deja expresa constancia de que los registros Clear Channel observados en networkcfg no fueron considerados operadores telefonicos ni eventos de abonados. Su inclusion corresponde a informacion de configuracion/escaneo propia del sistema y se documenta por separado a efectos de trazabilidad.")
    add_df_table(doc, clear_channels, font_size=8)

    doc.add_heading("8. Analisis tecnico", 1)
    add_para(doc, "Durante el relevamiento se verifico la presencia simultanea de redes pertenecientes a Claro, Movistar y Personal, con predominio de eventos registrados sobre tecnologia 4G/LTE. La coexistencia de tecnologias GSM, UMTS y LTE evidencia un entorno radioelectrico de alta ocupacion, compatible con una zona urbana e institucional con multiples celdas y portadoras activas.")
    add_para(doc, "La discriminacion entre history y networkcfg resulta esencial para evitar errores de interpretacion: history permite describir eventos y redes de origen de abonados mediante Home Network, mientras que networkcfg permite documentar configuraciones de red, canales ARFCN/UARFCN/EARFCN, LAC, Cell ID y niveles Rx.")
    if not cells.empty and "Rx_promedio" in cells.columns:
        rx_mean = pd.to_numeric(carrier_net["Rx Level"], errors="coerce").mean()
        rx_max = pd.to_numeric(carrier_net["Rx Level"], errors="coerce").max()
        rx_min = pd.to_numeric(carrier_net["Rx Level"], errors="coerce").min()
        if pd.notna(rx_mean):
            add_para(doc, f"Respecto de los registros de operadores identificados en networkcfg, los niveles de recepcion presentan un promedio de {rx_mean:.2f} dBm, con maximo de {rx_max:.2f} dBm y minimo de {rx_min:.2f} dBm, conforme a los registros exportados por el sistema.")

    doc.add_heading("9. Conclusion", 1)
    add_para(doc, "En funcion de los datos analizados, se deja constancia de que durante la inspeccion ocular y tecnica del establecimiento se registraron eventos asociados principalmente a las prestadoras Claro, Movistar y Personal, conforme surge del campo Home Network del archivo history.")
    add_para(doc, "Asimismo, del archivo networkcfg se identificaron canales radioelectricos ARFCN/UARFCN/EARFCN, tecnologias y parametros de celdas correspondientes al entorno celular relevado. Los registros Clear Channel fueron tratados como informacion tecnica de configuracion/escaneo y no como operador detectado.")
    add_para(doc, "La densidad de eventos, la presencia de multiples tecnologias y la diversidad de canales observados permiten caracterizar el sector relevado como un entorno radioelectrico complejo, circunstancia que debe ser considerada para cualquier planificacion tecnica vinculada a deteccion, localizacion, emulacion o bloqueo dentro del area de operacion.")
    add_para(doc, "Los resultados detallados se respaldan en los archivos exportados directamente por el sistema GUARDIAN, preservando la trazabilidad de la evidencia tecnica obtenida en campo.")

    doc.add_page_break()
    doc.add_heading("ANEXO I - Procesamiento tecnico de registros", 1)
    add_para(doc, "El presente anexo contiene las tablas procesadas a partir de los archivos history y networkcfg exportados por el sistema. Se excluye la publicacion de identificadores sensibles completos en el cuerpo del informe, manteniendo el analisis en nivel estadistico y tecnico.")

    doc.add_heading("I.1 History - Operadores detectados por Home Network", 2)
    add_df_table(doc, hist_ops, max_rows=30, font_size=7)
    doc.add_heading("I.2 History - Operador por tecnologia", 2)
    add_df_table(doc, hist_op_tech, max_rows=30, font_size=7)
    doc.add_heading("I.3 History - Operador por estado operativo", 2)
    add_df_table(doc, hist_op_status, max_rows=30, font_size=7)
    doc.add_heading("I.4 Networkcfg - Canales detectados", 2)
    add_df_table(doc, channels, max_rows=80, font_size=6)
    doc.add_heading("I.5 Networkcfg - Celdas identificadas", 2)
    add_df_table(doc, cells, max_rows=80, font_size=6)
    doc.add_heading("I.6 Networkcfg - Clear Channel documentado por separado", 2)
    add_df_table(doc, clear_channels, font_size=7)

    doc.add_paragraph()
    p = doc.add_paragraph("Es cuanto se informa.\n")
    p.alignment = WD_ALIGN_PARAGRAPH.LEFT
    if firma_img and Path(firma_img).exists():
        doc.add_picture(str(firma_img), width=Inches(1.8))
    sig = doc.add_paragraph()
    sig.add_run(f"{firma}\n").bold = True
    sig.add_run(f"{cargo}\n")
    sig.add_run(f"Fecha de generacion: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")

    docx_path = out_dir / "Informe_Tecnico_Relevamiento_RF_NEXA.docx"
    doc.save(docx_path)

    pdf_path = None
    soffice = shutil.which("soffice") or shutil.which("libreoffice")
    if soffice:
        subprocess.run([soffice, "--headless", "--convert-to", "pdf", "--outdir", str(out_dir), str(docx_path)], check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        candidate = out_dir / (docx_path.stem + ".pdf")
        if candidate.exists():
            pdf_path = candidate
    return docx_path, pdf_path, tables_dir, charts_dir


def main():
    parser = argparse.ArgumentParser(description="Genera informe tecnico RF desde CSV de Guardian/Septier")
    parser.add_argument("--networkcfg", required=True, help="Ruta al CSV networkcfg exportado por el sistema")
    parser.add_argument("--history", required=True, help="Ruta al CSV history exportado por el sistema")
    parser.add_argument("--out", default="./salida_informe_rf", help="Carpeta de salida")
    parser.add_argument("--firma", default="Romina S. Mercau", help="Nombre de firma")
    parser.add_argument("--cargo", default="Programmer | Digital Forensic Examiner", help="Cargo o leyenda profesional")
    parser.add_argument("--firma-img", default=None, help="Imagen de firma opcional PNG/JPG")
    parser.add_argument("--lugar", default="UNCUYO - BACT II", help="Lugar relevado")
    parser.add_argument("--nota", default="____/26", help="Numero de nota")
    args = parser.parse_args()

    docx, pdf, tables, charts = generate_report(
        networkcfg_path=args.networkcfg,
        history_path=args.history,
        out_dir=args.out,
        firma=args.firma,
        cargo=args.cargo,
        firma_img=args.firma_img,
        lugar=args.lugar,
        nota=args.nota,
    )
    print("OK - informe generado")
    print(f"DOCX: {docx}")
    if pdf:
        print(f"PDF:  {pdf}")
    else:
        print("PDF:  no generado automaticamente. Instala LibreOffice o abre el DOCX y exporta a PDF.")
    print(f"Tablas: {tables}")
    print(f"Graficos: {charts}")


if __name__ == "__main__":
    main()
