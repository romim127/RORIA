import datetime as dt
import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import pandas as pd

try:
    from src.utils.detection_report import generar_reporte_html
    from src.utils.projections import ProjectionEngine
    from src.utils.skyeye_geo_pipeline import run_pipeline
except ModuleNotFoundError:
    from detection_report import generar_reporte_html
    from projections import ProjectionEngine
    from skyeye_geo_pipeline import run_pipeline


def _resolve_data_dir() -> Path:
    configured = os.getenv("SKYEYE_DATA_DIR", ".")
    candidate = Path(configured).resolve()
    try:
        candidate.mkdir(parents=True, exist_ok=True)
        probe = candidate / ".skyeye_write_test"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink(missing_ok=True)
        return candidate
    except Exception:
        fallback = Path("/tmp/skyeye_data")
        fallback.mkdir(parents=True, exist_ok=True)
        return fallback.resolve()


DATA_DIR = _resolve_data_dir()
REPORTS_DIR = DATA_DIR / "reportes_diarios_entrada"
OUTPUTS_DIR = DATA_DIR / "app_outputs"


def clean_columns(df: pd.DataFrame) -> pd.DataFrame:
    df.columns = [re.sub(r"^[\W_]+", "", str(c)).strip() for c in df.columns]
    return df


def parse_latlon(value: object) -> Optional[Tuple[float, float]]:
    nums = re.findall(r"[-+]?\d+(?:\.\d+)?", str(value).strip())
    if len(nums) < 2:
        return None
    lat, lon = float(nums[0]), float(nums[1])
    if not (-90 <= lat <= 90 and -180 <= lon <= 180):
        return None
    return round(lat, 6), round(lon, 6)


def _maps_url(lat: float, lon: float) -> str:
    return f"https://maps.google.com/?q={lat},{lon}"


def _earth_url(lat: float, lon: float) -> str:
    return f"https://earth.google.com/web/search/{lat},{lon}"


def build_drones_commands_file(
    detection_csv: Path,
    trajectory_csv: Optional[Path],
    output_file: Path,
) -> Path:
    rows = []

    det = pd.read_csv(detection_csv, sep=None, engine="python", encoding="latin-1")
    det = clean_columns(det)
    for _, r in det.iterrows():
        coord = parse_latlon(r.get("Last Detected Location (Lat Lng)", "")) or parse_latlon(
            r.get("Nearest Location [Lat Lng]", "")
        )
        lat = coord[0] if coord else None
        lon = coord[1] if coord else None
        rows.append(
            {
                "origen": "detection_report",
                "timestamp": str(r.get("Detect Time", "")).strip(),
                "device_id": str(r.get("Device ID", "")).strip(),
                "model": str(r.get("Model", "")).strip(),
                "source": str(r.get("Source", "")).strip(),
                "comando": str(r.get("Method", "")).strip() or str(r.get("tag", "")).strip(),
                "direccion": str(r.get("Direction", "")).strip(),
                "frecuencia": str(r.get("Frequency", "")).strip(),
                "altura_m": str(r.get("Max Drone Height (m)", "")).strip(),
                "lat": lat,
                "lon": lon,
                "google_maps": _maps_url(lat, lon) if coord else "",
                "google_earth": _earth_url(lat, lon) if coord else "",
            }
        )

    if trajectory_csv and trajectory_csv.exists():
        tr = pd.read_csv(trajectory_csv, sep=None, engine="python", encoding="latin-1")
        tr = clean_columns(tr)
        for _, r in tr.iterrows():
            coord = parse_latlon(r.get("Location", ""))
            lat = coord[0] if coord else None
            lon = coord[1] if coord else None
            rows.append(
                {
                    "origen": "detection_trajectories",
                    "timestamp": str(r.get("Timestamp", "")).strip(),
                    "device_id": str(r.get("Device ID", "")).strip(),
                    "model": str(r.get("Model", "")).strip(),
                    "source": str(r.get("Source", "")).strip(),
                    "comando": str(r.get("Method", "")).strip(),
                    "direccion": str(r.get("Direction", "")).strip(),
                    "frecuencia": str(r.get("Frequency", "")).strip(),
                    "altura_m": str(r.get("Drone Height (m)", "")).strip(),
                    "lat": lat,
                    "lon": lon,
                    "google_maps": _maps_url(lat, lon) if coord else "",
                    "google_earth": _earth_url(lat, lon) if coord else "",
                }
            )

    df_out = pd.DataFrame(rows)
    if not df_out.empty:
        df_out["ts"] = pd.to_datetime(df_out["timestamp"], format="%Y.%m.%d %H:%M:%S", errors="coerce")
        df_out = df_out.sort_values("ts", ascending=False).drop(columns=["ts"])

    output_file.parent.mkdir(parents=True, exist_ok=True)
    df_out.to_csv(output_file, index=False, encoding="utf-8")
    return output_file


def find_latest_csv(directory: Path) -> Path:
    csvs = [p for p in directory.glob("*.csv") if p.is_file()]
    if not csvs:
        raise FileNotFoundError(
            f"No hay CSV en {directory.resolve()}. Copia ahi el Detection Report diario."
        )
    return max(csvs, key=lambda p: p.stat().st_mtime)


def csv_kind(path: Path) -> str:
    df = pd.read_csv(path, sep=None, engine="python", encoding="latin-1")
    df = clean_columns(df)
    cols = set(df.columns)
    if "Source" in cols and "Last Detected Location (Lat Lng)" in cols:
        return "detection"
    if "Location" in cols and "Timestamp" in cols:
        return "trajectory"
    return "unknown"


def find_detection_and_trajectory(directory: Path) -> Tuple[Path, Optional[Path]]:
    detection = None
    trajectory = None

    for csv_path in sorted(directory.glob("*.csv"), key=lambda p: p.stat().st_mtime, reverse=True):
        kind = csv_kind(csv_path)
        if kind == "detection" and detection is None:
            detection = csv_path
        elif kind == "trajectory" and trajectory is None:
            trajectory = csv_path

    if detection is None:
        raise FileNotFoundError(
            "No encontre un Detection Report valido en reportes_diarios_entrada/."
        )

    return detection, trajectory


def build_m3t_kml(detection_csv: Path, trajectory_csv: Optional[Path], output_file: Path) -> Dict[str, object]:
    dr = pd.read_csv(detection_csv, sep=None, engine="python", encoding="latin-1")
    dr = clean_columns(dr)

    if "Model" not in dr.columns:
        raise ValueError("Detection Report sin columna Model")

    dr["Source"] = dr.get("Source", "").fillna("").astype(str).str.strip().str.lower()
    dr["Model_clean"] = (
        dr["Model"]
        .astype(str)
        .str.replace(r"[^\x20-\x7E]+", "", regex=True)
        .str.strip()
    )

    m3t = dr[dr["Model_clean"].str.upper().str.contains("M3T", na=False)].copy()
    if m3t.empty:
        raise ValueError("No hay registros M3T en el Detection Report")

    m3t["dt"] = pd.to_datetime(m3t.get("Detect Time", ""), format="%Y.%m.%d %H:%M:%S", errors="coerce")
    m3t = m3t.sort_values("dt")
    row = m3t.iloc[-1]

    last_det = parse_latlon(row.get("Last Detected Location (Lat Lng)", ""))
    nearest = parse_latlon(row.get("Nearest Location [Lat Lng]", ""))
    home_pt = parse_latlon(row.get("Home Location (Lat Lng)", ""))
    rc_pt = parse_latlon(row.get("RC Location (Lat Lng)", ""))

    traj = []
    target_device = str(row.get("Device ID", "")).strip()
    target_model = str(row.get("Model_clean", "")).strip().upper()
    if trajectory_csv and trajectory_csv.exists():
        p1 = pd.read_csv(trajectory_csv, sep=None, engine="python", encoding="latin-1")
        p1 = clean_columns(p1)

        if "Device ID" in p1.columns:
            p1["Device ID"] = p1["Device ID"].fillna("").astype(str).str.strip()
        else:
            p1["Device ID"] = ""

        if "Model" in p1.columns:
            p1["Model_clean"] = (
                p1["Model"]
                .fillna("")
                .astype(str)
                .str.replace(r"[^\x20-\x7E]+", "", regex=True)
                .str.strip()
                .str.upper()
            )
        else:
            p1["Model_clean"] = ""

        if target_device:
            filtered_p1 = p1[p1["Device ID"] == target_device].copy()
        else:
            filtered_p1 = p1[p1["Model_clean"].str.contains("M3T", na=False)].copy()

        if filtered_p1.empty:
            filtered_p1 = p1[p1["Model_clean"].str.contains(target_model or "M3T", na=False)].copy()

        filtered_p1["ts"] = pd.to_datetime(
            filtered_p1.get("Timestamp", ""),
            format="%Y.%m.%d %H:%M:%S",
            errors="coerce",
        )
        filtered_p1 = filtered_p1.sort_values("ts")

        if "Location" in filtered_p1.columns:
            proj = ProjectionEngine()
            for _, r in filtered_p1.iterrows():
                text = str(r.get("Location", "")).strip()
                nums = re.findall(r"[-+]?\d+(?:\.\d+)?", text)
                if len(nums) >= 2:
                    lat = float(nums[0])
                    lon = float(nums[1])
                    if -90 <= lat <= 90 and -180 <= lon <= 180:
                        traj.append((round(lat, 6), round(lon, 6), str(r.get("Timestamp", "")).strip()))
                        continue
                if len(nums) < 1:
                    continue
                offset = float(nums[0])
                lat, lon = proj.calcular_coordenada_absoluta(offset)
                traj.append((lat, lon, str(r.get("Timestamp", "")).strip()))

    if not traj and last_det:
        detect_time = str(row.get("Detect Time", "")).strip()
        traj = [(last_det[0], last_det[1], detect_time)]

    if not traj:
        raise ValueError("No pude construir trayectoria M3T (sin PRUEBA de trayectoria ni last_det)")

    inicio = traj[0]
    fin = traj[-1]

    def esc(v: object) -> str:
        return str(v).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<kml xmlns="http://www.opengis.net/kml/2.2">',
        '<Document><name>Busqueda DJI M3T Perdido</name>',
        '<Style id="inicio"><IconStyle><color>ff00ff00</color><scale>1.4</scale></IconStyle></Style>',
        '<Style id="fin"><IconStyle><color>ff0000ff</color><scale>1.4</scale></IconStyle></Style>',
        '<Style id="home"><IconStyle><color>ff00ffff</color><scale>1.4</scale></IconStyle></Style>',
        '<Style id="rc"><IconStyle><color>ff00ff80</color><scale>1.2</scale></IconStyle></Style>',
        '<Style id="lastdet"><IconStyle><color>ff0080ff</color><scale>1.4</scale></IconStyle></Style>',
        '<Style id="tray"><LineStyle><color>ff1f77b4</color><width>3</width></LineStyle></Style>',
    ]

    detect_t = str(row.get("Detect Time", "")).strip()

    if home_pt:
        lines += [
            '<Placemark><name>HOME (Despegue)</name><styleUrl>#home</styleUrl>',
            f'<description><![CDATA[<b>Modelo:</b> {esc(row.get("Model", ""))}<br/><b>Device ID:</b> {esc(row.get("Device ID", ""))}<br/>Punto de despegue estimado<br/>Deteccion: {esc(detect_t)}<br/>Coordenadas: {home_pt[0]}, {home_pt[1]}]]></description>',
            f'<Point><coordinates>{home_pt[1]},{home_pt[0]},0</coordinates></Point></Placemark>',
        ]

    if rc_pt:
        lines += [
            '<Placemark><name>OPERADOR RC</name><styleUrl>#rc</styleUrl>',
            f'<description><![CDATA[<b>Modelo:</b> {esc(row.get("Model", ""))}<br/><b>Device ID:</b> {esc(row.get("Device ID", ""))}<br/>Posicion del operador con control remoto<br/>Deteccion: {esc(detect_t)}<br/>Coordenadas: {rc_pt[0]}, {rc_pt[1]}]]></description>',
            f'<Point><coordinates>{rc_pt[1]},{rc_pt[0]},0</coordinates></Point></Placemark>',
        ]

    lines += [
        '<Placemark><name>INICIO trayectoria</name><styleUrl>#inicio</styleUrl>',
        f'<description><![CDATA[<b>Modelo:</b> {esc(row.get("Model", ""))}<br/><b>Device ID:</b> {esc(row.get("Device ID", ""))}<br/>Primera posicion registrada<br/>Hora: {esc(inicio[2])}<br/>Coordenadas: {inicio[0]}, {inicio[1]}]]></description>',
        f'<Point><coordinates>{inicio[1]},{inicio[0]},0</coordinates></Point></Placemark>',
    ]

    lines.append('<Placemark><name>Recorrido M3T</name><styleUrl>#tray</styleUrl>')
    lines.append('<LineString><tessellate>1</tessellate><coordinates>')
    for lat, lon, _ in traj:
        lines.append(f"{lon},{lat},0")
    lines.append('</coordinates></LineString></Placemark>')

    lines += [
        '<Placemark><name>FIN trayectoria</name><styleUrl>#fin</styleUrl>',
        f'<description><![CDATA[<b>Modelo:</b> {esc(row.get("Model", ""))}<br/><b>Device ID:</b> {esc(row.get("Device ID", ""))}<br/>Ultima posicion trayectoria<br/>Hora: {esc(fin[2])}<br/>Altura maxima: {esc(row.get("Max Drone Height (m)", ""))} m<br/>Coordenadas: {fin[0]}, {fin[1]}]]></description>',
        f'<Point><coordinates>{fin[1]},{fin[0]},0</coordinates></Point></Placemark>',
    ]

    if last_det:
        lines += [
            '<Placemark><name>ULTIMA DETECCION SENSOR</name><styleUrl>#lastdet</styleUrl>',
            f'<description><![CDATA[<b>Modelo:</b> {esc(row.get("Model", ""))}<br/><b>Device ID:</b> {esc(row.get("Device ID", ""))}<br/>Ultimo punto registrado por sensor SkyEye<br/>Hora: {esc(detect_t)}<br/>Coordenadas: {last_det[0]}, {last_det[1]}]]></description>',
            f'<Point><coordinates>{last_det[1]},{last_det[0]},0</coordinates></Point></Placemark>',
        ]

    lines += ['</Document></kml>']

    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text("\n".join(lines), encoding="utf-8")

    summary = {
        "device_id": str(row.get("Device ID", "")).strip(),
        "model": str(row.get("Model", "")).strip(),
        "detect_time": detect_t,
        "home": {"lat": home_pt[0], "lon": home_pt[1]} if home_pt else None,
        "rc": {"lat": rc_pt[0], "lon": rc_pt[1]} if rc_pt else None,
        "sensor_last": {"lat": last_det[0], "lon": last_det[1]} if last_det else None,
        "sensor_nearest": {"lat": nearest[0], "lon": nearest[1]} if nearest else None,
        "trajectory_start": {"lat": inicio[0], "lon": inicio[1], "time": inicio[2]},
        "trajectory_end": {"lat": fin[0], "lon": fin[1], "time": fin[2]},
        "trajectory_points": len(traj),
    }
    return summary


def _read_skyeye_csv(path: Path) -> pd.DataFrame:
    try:
        df = pd.read_csv(path, sep=None, engine="python", encoding="utf-8-sig", dtype=str)
    except Exception:
        df = pd.read_csv(path, sep=None, engine="python", encoding="latin-1", dtype=str)
    return clean_columns(df).fillna("")


def _parse_trajectory_location(value: object) -> Optional[Tuple[float, float]]:
    coord = parse_latlon(value)
    if coord:
        return coord
    nums = re.findall(r"[-+]?\d+(?:\.\d+)?", str(value).strip())
    if len(nums) != 1:
        return None
    try:
        return ProjectionEngine().calcular_coordenada_absoluta(float(nums[0]))
    except Exception:
        return None


def build_device_trajectory_kml(
    detection_csv: Path,
    trajectory_csv: Optional[Path],
    output_file: Path,
    device_id: Optional[str] = None,
) -> Dict[str, object]:
    """Build a focused KML for one SkyEye Device ID.

    Detection Trajectories can contain either a single drone path or many devices.
    If device_id is omitted, the function only auto-selects when the trajectory or
    detection file contains one clear Device ID.
    """
    det = _read_skyeye_csv(detection_csv)
    target_device = str(device_id or "").strip()

    if "Device ID" not in det.columns:
        raise ValueError("Detection Report sin columna Device ID")

    det["Device ID"] = det["Device ID"].fillna("").astype(str).str.strip()
    if target_device:
        det_target = det[det["Device ID"] == target_device].copy()
    else:
        det_target = det.copy()

    if det_target.empty and target_device:
        raise ValueError(f"No hay detecciones para Device ID {target_device}")

    traj_rows = []
    trajectory_devices: List[str] = []
    if trajectory_csv and trajectory_csv.exists():
        tr = _read_skyeye_csv(trajectory_csv)
        if "Device ID" in tr.columns:
            tr["Device ID"] = tr["Device ID"].fillna("").astype(str).str.strip()
            trajectory_devices = [d for d in tr["Device ID"].dropna().astype(str).str.strip().unique().tolist() if d]
        else:
            tr["Device ID"] = ""

        if not target_device:
            if len(trajectory_devices) == 1:
                target_device = trajectory_devices[0]
            else:
                det_devices = [d for d in det["Device ID"].dropna().astype(str).str.strip().unique().tolist() if d]
                if len(det_devices) == 1:
                    target_device = det_devices[0]

        if target_device:
            tr = tr[tr["Device ID"] == target_device].copy()
            det_target = det[det["Device ID"] == target_device].copy()
        elif len(trajectory_devices) > 1:
            raise ValueError("La trayectoria contiene varios Device ID. Selecciona uno para generar KML individual.")

        if "Timestamp" in tr.columns:
            tr["_ts"] = pd.to_datetime(tr["Timestamp"], format="%Y.%m.%d %H:%M:%S", errors="coerce")
            tr = tr.sort_values("_ts").drop(columns=["_ts"])

        for _, row in tr.iterrows():
            coord = _parse_trajectory_location(row.get("Location", ""))
            if not coord:
                continue
            traj_rows.append({
                "lat": coord[0],
                "lon": coord[1],
                "time": str(row.get("Timestamp", "")).strip(),
                "model": str(row.get("Model", "")).strip(),
                "source": str(row.get("Source", "")).strip(),
                "height": str(row.get("Drone Height (m)", "")).strip(),
            })

    if det_target.empty and target_device:
        det_target = det[det["Device ID"] == target_device].copy()
    if det_target.empty:
        raise ValueError("No hay detecciones SkyEye para construir la trayectoria.")

    if "Detect Time" in det_target.columns:
        det_target["_dt"] = pd.to_datetime(det_target["Detect Time"], format="%Y.%m.%d %H:%M:%S", errors="coerce")
        det_target = det_target.sort_values("_dt").drop(columns=["_dt"])

    selected = det_target.iloc[-1]
    if not target_device:
        target_device = str(selected.get("Device ID", "")).strip()
    if not target_device:
        raise ValueError("No se pudo determinar Device ID para generar KML individual.")

    last_det = parse_latlon(selected.get("Last Detected Location (Lat Lng)", ""))
    nearest = parse_latlon(selected.get("Nearest Location [Lat Lng]", ""))
    home_pt = parse_latlon(selected.get("Home Location (Lat Lng)", ""))
    rc_pt = parse_latlon(selected.get("RC Location (Lat Lng)", ""))
    detect_t = str(selected.get("Detect Time", "")).strip()

    if not traj_rows:
        fallback = last_det or nearest
        if not fallback:
            raise ValueError("No hay trayectoria ni ultima coordenada valida para generar KML.")
        traj_rows = [{
            "lat": fallback[0],
            "lon": fallback[1],
            "time": detect_t,
            "model": str(selected.get("Model", "")).strip(),
            "source": str(selected.get("Source", "")).strip(),
            "height": str(selected.get("Max Drone Height (m)", "")).strip(),
        }]

    inicio = traj_rows[0]
    fin = traj_rows[-1]

    def esc(v: object) -> str:
        return str(v).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    model = str(selected.get("Model", "")).strip() or str(fin.get("model", "")).strip()
    output_file.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<kml xmlns="http://www.opengis.net/kml/2.2">',
        f'<Document><name>Trayectoria Device ID {esc(target_device)}</name>',
        '<Style id="inicio"><IconStyle><color>ff00ff00</color><scale>1.4</scale></IconStyle></Style>',
        '<Style id="fin"><IconStyle><color>ff0000ff</color><scale>1.4</scale></IconStyle></Style>',
        '<Style id="home"><IconStyle><color>ff00ffff</color><scale>1.4</scale></IconStyle></Style>',
        '<Style id="rc"><IconStyle><color>ff00ff80</color><scale>1.2</scale></IconStyle></Style>',
        '<Style id="lastdet"><IconStyle><color>ff0080ff</color><scale>1.4</scale></IconStyle></Style>',
        '<Style id="tray"><LineStyle><color>ff1f77b4</color><width>3</width></LineStyle></Style>',
    ]

    if home_pt:
        lines += [
            '<Placemark><name>HOME (Despegue)</name><styleUrl>#home</styleUrl>',
            f'<description><![CDATA[<b>Modelo:</b> {esc(model)}<br/><b>Device ID:</b> {esc(target_device)}<br/>Punto de despegue estimado<br/>Deteccion: {esc(detect_t)}<br/>Coordenadas: {home_pt[0]}, {home_pt[1]}]]></description>',
            f'<Point><coordinates>{home_pt[1]},{home_pt[0]},0</coordinates></Point></Placemark>',
        ]

    if rc_pt:
        lines += [
            '<Placemark><name>OPERADOR RC</name><styleUrl>#rc</styleUrl>',
            f'<description><![CDATA[<b>Modelo:</b> {esc(model)}<br/><b>Device ID:</b> {esc(target_device)}<br/>Posicion del operador con control remoto<br/>Deteccion: {esc(detect_t)}<br/>Coordenadas: {rc_pt[0]}, {rc_pt[1]}]]></description>',
            f'<Point><coordinates>{rc_pt[1]},{rc_pt[0]},0</coordinates></Point></Placemark>',
        ]

    lines += [
        '<Placemark><name>INICIO trayectoria</name><styleUrl>#inicio</styleUrl>',
        f'<description><![CDATA[<b>Modelo:</b> {esc(model)}<br/><b>Device ID:</b> {esc(target_device)}<br/>Primera posicion registrada<br/>Hora: {esc(inicio.get("time", ""))}<br/>Coordenadas: {inicio["lat"]}, {inicio["lon"]}]]></description>',
        f'<Point><coordinates>{inicio["lon"]},{inicio["lat"]},0</coordinates></Point></Placemark>',
        '<Placemark><name>Recorrido del Device ID</name><styleUrl>#tray</styleUrl>',
        '<LineString><tessellate>1</tessellate><coordinates>',
    ]
    for point in traj_rows:
        lines.append(f'{point["lon"]},{point["lat"]},0')
    lines += [
        '</coordinates></LineString></Placemark>',
        '<Placemark><name>FIN trayectoria</name><styleUrl>#fin</styleUrl>',
        f'<description><![CDATA[<b>Modelo:</b> {esc(model)}<br/><b>Device ID:</b> {esc(target_device)}<br/>Ultima posicion trayectoria<br/>Hora: {esc(fin.get("time", ""))}<br/>Altura: {esc(fin.get("height", ""))} m<br/>Coordenadas: {fin["lat"]}, {fin["lon"]}]]></description>',
        f'<Point><coordinates>{fin["lon"]},{fin["lat"]},0</coordinates></Point></Placemark>',
    ]

    if last_det:
        lines += [
            '<Placemark><name>ULTIMA DETECCION SENSOR</name><styleUrl>#lastdet</styleUrl>',
            f'<description><![CDATA[<b>Modelo:</b> {esc(model)}<br/><b>Device ID:</b> {esc(target_device)}<br/>Ultimo punto registrado por sensor SkyEye<br/>Hora: {esc(detect_t)}<br/>Coordenadas: {last_det[0]}, {last_det[1]}]]></description>',
            f'<Point><coordinates>{last_det[1]},{last_det[0]},0</coordinates></Point></Placemark>',
        ]

    lines += ['</Document></kml>']
    output_file.write_text("\n".join(lines), encoding="utf-8")

    return {
        "device_id": target_device,
        "model": model,
        "detect_time": detect_t,
        "home": {"lat": home_pt[0], "lon": home_pt[1]} if home_pt else None,
        "rc": {"lat": rc_pt[0], "lon": rc_pt[1]} if rc_pt else None,
        "sensor_last": {"lat": last_det[0], "lon": last_det[1]} if last_det else None,
        "sensor_nearest": {"lat": nearest[0], "lon": nearest[1]} if nearest else None,
        "trajectory_start": {"lat": inicio["lat"], "lon": inicio["lon"], "time": inicio.get("time", "")},
        "trajectory_end": {"lat": fin["lat"], "lon": fin["lon"], "time": fin.get("time", "")},
        "trajectory_points": len(traj_rows),
        "kml_path": str(output_file),
    }


def _merge_detection_csvs(directory: Path, run_dir: Path) -> Path:
    """Merge all detection CSVs in directory into one combined file for reporting."""
    all_detection = []
    for p in sorted(directory.glob("*.csv"), key=lambda x: x.stat().st_mtime):
        try:
            if csv_kind(p) == "detection":
                df = pd.read_csv(p, sep=None, engine="python", encoding="latin-1")
                df = clean_columns(df)
                all_detection.append(df)
        except Exception:
            pass

    if not all_detection:
        raise FileNotFoundError("No hay detection CSVs en el inbox.")

    merged = pd.concat(all_detection, ignore_index=True)

    # Deduplicate by Record ID if available
    if "Record ID" in merged.columns:
        merged = merged.drop_duplicates(subset=["Record ID"], keep="last")

    # Sort by Detect Time descending
    if "Detect Time" in merged.columns:
        merged["_dt"] = pd.to_datetime(merged["Detect Time"], format="%Y.%m.%d %H:%M:%S", errors="coerce")
        merged = merged.sort_values("_dt", ascending=False).drop(columns=["_dt"])

    merged_path = run_dir / "detection_merged.csv"
    merged.to_csv(merged_path, index=False, encoding="utf-8")
    return merged_path


def _extract_detections_for_db(merged_csv: Path, run_id: int) -> List[Dict]:
    """Extract detection rows for DB storage (heatmap persistence)."""
    try:
        df = pd.read_csv(merged_csv, sep=None, engine="python", encoding="latin-1")
        df = clean_columns(df)
    except Exception:
        return []

    rows = []
    for _, r in df.iterrows():
        coord = parse_latlon(r.get("Last Detected Location (Lat Lng)", "")) or parse_latlon(r.get("Nearest Location [Lat Lng]", ""))
        if not coord:
            continue

        raw_time = str(r.get("Detect Time", "")).strip()
        detect_date = ""
        if raw_time:
            try:
                detect_date = dt.datetime.strptime(raw_time, "%Y.%m.%d %H:%M:%S").strftime("%Y-%m-%d")
            except Exception:
                pass

        rows.append({
            "run_id": run_id,
            "detect_date": detect_date,
            "detect_time": raw_time,
            "lat": coord[0],
            "lon": coord[1],
            "model": str(r.get("Model", "")).strip(),
            "sensor": str(r.get("Sensor", "")).strip(),
            "location": str(r.get("Detection Engine", "")).strip(),
            "tag": str(r.get("tag", "")).strip(),
            "source": str(r.get("Source", "")).strip(),
            "frequency": str(r.get("Frequency", "")).strip(),
            "height_m": str(r.get("Max Drone Height (m)", "")).strip(),
        })
    return rows


def run_end_to_end_for_latest() -> Dict[str, object]:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)

    detection_csv, trajectory_csv = find_detection_and_trajectory(REPORTS_DIR)

    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = OUTPUTS_DIR / f"run_{stamp}"
    georef_dir = run_dir / "georef"
    run_dir.mkdir(parents=True, exist_ok=True)

    # Merge all detection CSVs for the report and georef pipeline
    merged_detection_csv = _merge_detection_csvs(REPORTS_DIR, run_dir)

    html_report = run_dir / "reporte_detecciones.html"
    generar_reporte_html(str(merged_detection_csv), str(html_report))

    run_pipeline(
        input_csv=str(merged_detection_csv),
        output_dir=str(georef_dir),
        source="drone",
        model_filter=None,
        device_filter=None,
        date_filter=None,
    )

    # M3T analysis is useful, but it must not block the base SkyEye reading.
    m3t_kml = run_dir / "busqueda_M3T_perdido.kml"
    try:
        m3t_summary = build_m3t_kml(detection_csv, trajectory_csv, m3t_kml)
        m3t_kml_value = str(m3t_kml)
    except Exception as exc:
        m3t_summary = {
            "status": "sin_m3t",
            "message": str(exc),
            "trajectory_end": None,
            "points": 0,
        }
        m3t_kml_value = None
    drones_commands_file = build_drones_commands_file(
        detection_csv=merged_detection_csv,
        trajectory_csv=trajectory_csv,
        output_file=run_dir / "drones_y_comandos.csv",
    )

    return {
        "created_at": dt.datetime.now().isoformat(timespec="seconds"),
        "input_detection_csv": str(merged_detection_csv),
        "input_trajectory_csv": str(trajectory_csv) if trajectory_csv else None,
        "output_dir": str(run_dir),
        "html_report": str(html_report),
        "tracks_kml": str(georef_dir / "trayectorias_drones.kml"),
        "last_seen_kml": str(georef_dir / "ultimas_posiciones_drones.kml"),
        "geo_txt_report": str(georef_dir / "reporte_georeferenciacion.txt"),
        "m3t_kml": m3t_kml_value,
        "drones_commands_file": str(drones_commands_file),
        "status": "ok",
        "message": "Pipeline completado",
        "m3t_summary": m3t_summary,
    }
