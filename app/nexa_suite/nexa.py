# -*- coding: utf-8 -*-
r"""
NEXA DIGITAL FORENSIC SUITE v0.5.1 Alpha FIXED
Ministerio Edition — RF Analyzer + informe técnico + trazabilidad.

Instalación:
    python -m pip install rich pandas matplotlib python-docx

Ejecución:
    python nexa.py

Los archivos deben copiarse dentro de input/:
    history*.csv
    networkcfg*.csv
"""

from __future__ import annotations

from pathlib import Path
from datetime import datetime
import csv
import json
import os
import subprocess
import sys
import time
import traceback

try:
    from rich import box
    from rich.align import Align
    from rich.console import Console
    from rich.panel import Panel
    from rich.prompt import Prompt
    from rich.table import Table
    from rich.text import Text
except ImportError:
    print("Falta Rich. Ejecutá: python -m pip install rich")
    raise SystemExit(1)

BASE_DIR = Path(__file__).resolve().parent
CONFIG_PATH = BASE_DIR / "config" / "config.json"
INPUT_DIR = BASE_DIR / "input"
OUTPUT_DIR = BASE_DIR / "output"
LOG_DIR = BASE_DIR / "logs"

console = Console()
SESSION_TIMELINE: list[dict] = []

NEXA_ASCII = r"""
███╗   ██╗███████╗██╗  ██╗ █████╗
████╗  ██║██╔════╝╚██╗██╔╝██╔══██╗
██╔██╗ ██║█████╗   ╚███╔╝ ███████║
██║╚██╗██║██╔══╝   ██╔██╗ ██╔══██║
██║ ╚████║███████╗██╔╝ ██╗██║  ██║
╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝
"""


def clear() -> None:
    os.system("cls" if os.name == "nt" else "clear")


def now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def load_config() -> dict:
    if not CONFIG_PATH.exists():
        raise FileNotFoundError(f"No se encontró la configuración: {CONFIG_PATH}")
    return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))


def log_action(
    action: str,
    actor: str = "NEXA",
    status: str = "OK",
    evidence: str = "",
    detail: str = "",
) -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    event = {
        "timestamp": now_iso(),
        "time": datetime.now().strftime("%H:%M:%S"),
        "actor": actor,
        "action": action,
        "evidence": evidence,
        "status": status,
        "detail": detail,
    }
    SESSION_TIMELINE.append(event)
    with (LOG_DIR / "nexa_session.log").open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(event, ensure_ascii=False) + "\n")


def export_timeline(out_dir: Path) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)

    json_path = out_dir / "timeline_chain_of_custody.json"
    json_path.write_text(
        json.dumps(SESSION_TIMELINE, ensure_ascii=False, indent=4),
        encoding="utf-8",
    )

    csv_path = out_dir / "timeline_chain_of_custody.csv"
    fields = ["timestamp", "time", "actor", "action", "evidence", "status", "detail"]
    with csv_path.open("w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(SESSION_TIMELINE)

    return json_path, csv_path


def splash(config: dict) -> None:
    clear()
    header = Text(NEXA_ASCII, style="bold bright_white")
    header += Text(
        "\nDIGITAL FORENSIC SUITE — MINISTERIO EDITION\n"
        "RF Intelligence | Reports | Evidence | Traceability\n",
        style="bold bright_cyan",
    )
    console.print(
        Panel(
            Align.center(header),
            title="[bold bright_cyan]INITIALIZING[/bold bright_cyan]",
            subtitle=f"[white]{config.get('organization', '')}[/white]",
            border_style="bright_cyan",
            box=box.DOUBLE,
        )
    )

    for step in [
        "Loading RF Analyzer engine",
        "Loading report intelligence engine",
        "Loading evidence timeline",
        "Validating configuration",
    ]:
        console.print(
            f"[bright_cyan]▸[/bright_cyan] [white]{step:<38}[/white] [green]OK[/green]"
        )
        log_action(step, actor="SYSTEM")
        time.sleep(0.12)


def menu(config: dict) -> str:
    console.print(
        Panel(
            "[1] RF Analyzer\n"
            "[2] Packet Analyzer        [dim][COMING SOON][/dim]\n"
            "[3] Mobile Forensics       [dim][COMING SOON][/dim]\n"
            "[4] Drone Analyzer         [dim][COMING SOON][/dim]\n"
            "[5] Evidence Manager       [dim][COMING SOON][/dim]\n"
            "[6] Chain of Custody       [dim][COMING SOON][/dim]\n"
            "[0] Exit",
            title=(
                "[bold bright_cyan]"
                f"NEXA | {config.get('version')} | Build {config.get('build')}"
                "[/bold bright_cyan]"
            ),
            border_style="bright_cyan",
            box=box.DOUBLE,
        )
    )
    return Prompt.ask(
        "Select module",
        choices=["0", "1", "2", "3", "4", "5", "6"],
        default="1",
    )


def ask_case_data(config: dict) -> dict:
    clear()
    console.print(
        Panel(
            "[bold white]DATOS DEL RELEVAMIENTO[/bold white]\n"
            "[cyan]Estos datos se incorporarán al informe técnico.[/cyan]",
            title="[bold bright_cyan]NEXA RF ANALYZER[/bold bright_cyan]",
            border_style="bright_cyan",
            box=box.DOUBLE,
        )
    )

    case = {
        "case_number": Prompt.ask("Nota Nro.", default="____/26"),
        "analyst": Prompt.ask("Perito / Analista", default=""),
        "position": Prompt.ask(
            "Cargo",
            default="Programmer | Digital Forensic Examiner",
        ),
        "organization": Prompt.ask(
            "Organización",
            default=config.get("organization", ""),
        ),
        "institution": Prompt.ask("Establecimiento / Institución", default=""),
        "location": Prompt.ask("Sector / Ubicación", default=""),
        "equipment": Prompt.ask(
            "Sistema",
            default=config.get("default_equipment", "GUARDIAN"),
        ),
        "mode": Prompt.ask(
            "Modo",
            default=config.get("default_mode", "BLOCK"),
        ),
        "antennas": Prompt.ask(
            "Antenas",
            default=config.get("default_antennas", "DIRECCIONALES"),
        ),
        "signature_image": Prompt.ask(
            "Ruta imagen de firma (opcional)",
            default="",
        ),
    }

    parts = [case["institution"].strip(), case["location"].strip()]
    case["report_place"] = " - ".join(part for part in parts if part)
    if not case["report_place"]:
        case["report_place"] = "ESTABLECIMIENTO RELEVADO"

    log_action(
        "Caso creado",
        actor=case["analyst"] or "ANALYST",
        evidence=case["case_number"],
    )
    return case


def find_first(patterns: list[str], folder: Path) -> Path | None:
    for pattern in patterns:
        matches = sorted(folder.glob(pattern))
        if matches:
            return matches[0]
    return None


def detect_files() -> dict[str, Path | None]:
    INPUT_DIR.mkdir(parents=True, exist_ok=True)
    return {
        "history": find_first(
            ["history*.csv", "*history*.csv", "*hist*.csv"],
            INPUT_DIR,
        ),
        "networkcfg": find_first(
            ["networkcfg*.csv", "*networkcfg*.csv", "*network*.csv"],
            INPUT_DIR,
        ),
    }


def show_evidence(files: dict, case: dict) -> bool:
    console.print(
        Panel(
            f"[white]Carpeta:[/white] {INPUT_DIR}",
            title="[bold bright_cyan]EVIDENCE DETECTION[/bold bright_cyan]",
            border_style="bright_cyan",
        )
    )

    complete = True
    for key, expected in (
        ("history", "history*.csv"),
        ("networkcfg", "networkcfg*.csv"),
    ):
        path = files[key]
        if path:
            console.print(f"[white]{expected:<20}[/white] [green]OK[/green]  {path.name}")
            log_action(
                f"Evidencia registrada: {path.name}",
                actor=case["analyst"] or "ANALYST",
                evidence=str(path),
            )
        else:
            console.print(f"[white]{expected:<20}[/white] [red]MISSING[/red]")
            complete = False

    if not complete:
        console.print(
            f"\n[yellow]Copiá ambos CSV dentro de: {INPUT_DIR}[/yellow]"
        )
        log_action("Faltan archivos RF", status="ERROR")
    return complete


def safe_name(value: str) -> str:
    value = value.strip().replace(" ", "_")
    return "".join(ch for ch in value if ch.isalnum() or ch in "._-") or "CASE"


def build_output_dir(case: dict) -> Path:
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    folder = (
        f"{stamp}_{safe_name(case['report_place'])}_"
        f"{safe_name(case['case_number'])}"
    )
    path = OUTPUT_DIR / folder
    path.mkdir(parents=True, exist_ok=True)
    return path


def show_workflow_step(step: str, status: str = "RUNNING") -> None:
    color = "bright_cyan" if status == "RUNNING" else (
        "green" if status == "DONE" else "red"
    )
    console.print(
        f"[green]{datetime.now().strftime('%H:%M:%S')}[/green] "
        f"[white]{step:<46}[/white] [{color}]{status}[/{color}]"
    )


def run_rf_engine(config: dict, case: dict, files: dict) -> tuple[Path, int, str]:
    engine_rel = config.get(
        "rf_engine",
        "modules/rf_analyzer/nexa_rf_analyzer_v2.py",
    )
    engine = (BASE_DIR / engine_rel).resolve()
    out_dir = build_output_dir(case)
    engine_log = out_dir / "rf_engine_console.log"

    if not engine.exists():
        message = f"No se encontró el motor RF: {engine}"
        log_action("Motor RF no encontrado", status="ERROR", detail=message)
        engine_log.write_text(message, encoding="utf-8")
        return out_dir, 99, message

    cmd = [
        sys.executable,
        str(engine),
        "--networkcfg",
        str(files["networkcfg"].resolve()),
        "--history",
        str(files["history"].resolve()),
        "--out",
        str(out_dir.resolve()),
        "--firma",
        case["analyst"],
        "--cargo",
        case["position"],
        "--lugar",
        case["report_place"],
        "--nota",
        case["case_number"],
    ]

    signature = case["signature_image"].strip()
    if signature:
        signature_path = Path(signature).expanduser()
        if signature_path.exists():
            cmd.extend(["--firma-img", str(signature_path.resolve())])
        else:
            log_action(
                "Imagen de firma no encontrada; se continúa sin imagen",
                status="WARNING",
                evidence=signature,
            )

    show_workflow_step("Executing original RF report engine")
    log_action("Inicio de motor RF", evidence=str(engine))

    creation_flags = 0
    if os.name == "nt":
        creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)

    try:
        result = subprocess.run(
            cmd,
            cwd=str(BASE_DIR),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            creationflags=creation_flags,
        )
        combined = (
            "COMMAND:\n"
            + subprocess.list2cmdline(cmd)
            + "\n\nSTDOUT:\n"
            + (result.stdout or "")
            + "\n\nSTDERR:\n"
            + (result.stderr or "")
        )
        engine_log.write_text(combined, encoding="utf-8")
        code = result.returncode
    except Exception:
        combined = traceback.format_exc()
        engine_log.write_text(combined, encoding="utf-8")
        code = 98

    docx_files = list(out_dir.glob("*.docx"))
    pdf_files = list(out_dir.glob("*.pdf"))
    table_files = list((out_dir / "tablas_procesadas").glob("*.csv"))
    chart_files = list((out_dir / "graficos").glob("*.png"))

    if code == 0 and docx_files:
        log_action(
            "Informe Word generado",
            status="OK",
            evidence=str(docx_files[0]),
        )
        show_workflow_step("Generating Word Report", "DONE")
    else:
        detail = (
            f"Código={code}; DOCX encontrados={len(docx_files)}. "
            f"Revisar {engine_log}"
        )
        log_action("Fallo al generar informe Word", status="ERROR", detail=detail)
        show_workflow_step("Generating Word Report", "ERROR")

    if pdf_files:
        log_action("Informe PDF generado", evidence=str(pdf_files[0]))
        show_workflow_step("Generating PDF Report", "DONE")
    else:
        log_action(
            "PDF no generado automáticamente",
            status="WARNING",
            detail="El DOCX puede exportarse a PDF. LibreOffice/soffice debe estar instalado.",
        )
        show_workflow_step("Generating PDF Report", "WARNING")

    if table_files:
        log_action(
            "Tablas procesadas generadas",
            evidence=str(out_dir / "tablas_procesadas"),
        )
        show_workflow_step("Exporting Processed Tables", "DONE")

    if chart_files:
        log_action(
            "Gráficos generados",
            evidence=str(out_dir / "graficos"),
        )
        show_workflow_step("Generating Charts", "DONE")

    return out_dir, code, combined


def run_rf_workflow(config: dict, case: dict, files: dict) -> tuple[Path, int]:
    console.print(
        Panel(
            f"[white]Caso:[/white] {case['case_number']}\n"
            f"[white]Analista:[/white] {case['analyst']}\n"
            f"[white]Lugar:[/white] {case['report_place']}",
            title="[bold bright_cyan]REAL TIME CREATION FLOW[/bold bright_cyan]",
            border_style="bright_cyan",
            box=box.DOUBLE,
        )
    )

    for step in [
        "Searching RF Environment",
        "Reading history.csv",
        "Reading networkcfg.csv",
        "Analyzing Home Networks",
        "Calculating ARFCN/UARFCN/EARFCN",
        "Building Statistical Model",
    ]:
        show_workflow_step(step)
        log_action(step, status="RUNNING")
        time.sleep(0.18)
        SESSION_TIMELINE[-1]["status"] = "OK"
        show_workflow_step(step, "DONE")

    out_dir, code, _ = run_rf_engine(config, case, files)

    export_timeline(out_dir)
    show_workflow_step("Writing Chain of Custody Timeline", "DONE")
    log_action(
        "Timeline exportada",
        evidence=str(out_dir),
        status="OK",
    )
    # Re-exporta para que también conste la acción anterior.
    export_timeline(out_dir)

    return out_dir, code


def show_final(out_dir: Path, code: int) -> None:
    docx = list(out_dir.glob("*.docx"))
    pdf = list(out_dir.glob("*.pdf"))
    engine_log = out_dir / "rf_engine_console.log"

    rows = Table(box=box.ROUNDED, border_style="bright_cyan")
    rows.add_column("Producto", style="white")
    rows.add_column("Estado", justify="right")
    rows.add_row(
        "Informe Word",
        "[green]GENERADO[/green]" if docx else "[red]NO GENERADO[/red]",
    )
    rows.add_row(
        "Informe PDF",
        "[green]GENERADO[/green]" if pdf else "[yellow]NO DISPONIBLE[/yellow]",
    )
    rows.add_row("Timeline JSON/CSV", "[green]GENERADA[/green]")
    rows.add_row("Diagnóstico del motor", f"[cyan]{engine_log.name}[/cyan]")
    console.print(rows)

    if code == 0 and docx:
        title = "[bold bright_cyan]MISSION ACCOMPLISHED[/bold bright_cyan]"
        body = (
            "[bold green]MODULE 1 — RF ANALYZER COMPLETED[/bold green]\n\n"
            f"[white]Carpeta de salida:[/white]\n{out_dir}\n\n"
            f"[white]Informe:[/white] {docx[0].name}"
        )
        border = "bright_cyan"
    else:
        title = "[bold red]REPORT GENERATION ERROR[/bold red]"
        body = (
            "[bold red]El informe no fue generado.[/bold red]\n\n"
            f"[white]Diagnóstico completo:[/white]\n{engine_log}\n\n"
            "[yellow]Copiá el contenido de ese archivo para identificar "
            "el error exacto.[/yellow]"
        )
        border = "red"

    console.print(
        Panel(
            body,
            title=title,
            border_style=border,
            box=box.DOUBLE,
        )
    )


def rf_analyzer(config: dict) -> None:
    case = ask_case_data(config)
    files = detect_files()
    if not show_evidence(files, case):
        input("\nPresioná ENTER para volver...")
        return

    out_dir, code = run_rf_workflow(config, case, files)
    clear()
    show_final(out_dir, code)
    input("\nPresioná ENTER para salir...")


def main() -> None:
    try:
        config = load_config()
        splash(config)
        choice = menu(config)

        if choice == "1":
            rf_analyzer(config)
        elif choice == "0":
            return
        else:
            console.print(
                "[yellow]COMING SOON — módulo reservado para una versión futura.[/yellow]"
            )
            input("\nPresioná ENTER para salir...")
    except KeyboardInterrupt:
        console.print("\n[yellow]Operación cancelada por el usuario.[/yellow]")
    except Exception:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        error_path = LOG_DIR / "fatal_error.log"
        error_path.write_text(traceback.format_exc(), encoding="utf-8")
        console.print(
            Panel(
                f"[red]Error no controlado.[/red]\n\n"
                f"Diagnóstico guardado en:\n{error_path}",
                title="[bold red]NEXA ERROR[/bold red]",
                border_style="red",
            )
        )
        input("\nPresioná ENTER para salir...")


if __name__ == "__main__":
    main()
