import json
import os
import sqlite3
import hashlib
import datetime as dt
import re
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
except Exception:  # pragma: no cover
    psycopg2 = None
    RealDictCursor = None


def _resolve_db_path() -> Path:
    """Store the DB in the same persistent data dir as the CSVs."""
    data_dir = os.getenv("SKYEYE_DATA_DIR", "")
    if data_dir:
        candidate = Path(data_dir).resolve()
        try:
            candidate.mkdir(parents=True, exist_ok=True)
            probe = candidate / ".db_write_test"
            probe.write_text("ok", encoding="utf-8")
            probe.unlink(missing_ok=True)
            return candidate / "skyeye_app.db"
        except Exception:
            pass
    # fallback: /tmp on Render or local app_data/
    fallback = Path("/tmp/skyeye_data")
    try:
        fallback.mkdir(parents=True, exist_ok=True)
        return fallback / "skyeye_app.db"
    except Exception:
        return Path("app_data/skyeye_app.db")


DB_PATH = _resolve_db_path()

DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
USE_POSTGRES = bool(DATABASE_URL)
if USE_POSTGRES:
    DB_PATH = DATABASE_URL


def _identity_keys(value: object) -> set:
    raw = str(value or "").strip()
    if not raw:
        return set()
    if raw.endswith(".0"):
        raw = raw[:-2]
    if "/" in raw:
        left_side = raw.split("/", 1)[0].strip()
        left_digits = re.sub(r"\D+", "", left_side)
        if re.fullmatch(r"[\d\s.,+\-]+", left_side) and len(left_digits) == 15:
            return {left_digits}
    digits = re.sub(r"\D+", "", raw)
    if digits:
        return {digits} if len(digits) == 15 else set()
    keys = {raw, raw.lower()}
    return {k for k in keys if k}


def _is_whitelisted_identity(imsi: object, imei: object, whitelist_keys: set) -> bool:
    return bool((_identity_keys(imsi) | _identity_keys(imei)) & whitelist_keys)


def _clean_whitelist_device_id(value: object, device_type: object = "") -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    if raw.endswith(".0"):
        raw = raw[:-2]
    if str(device_type or "").strip().lower() in {"mac", "macaddress"}:
        return raw
    if "/" in raw:
        left_side = raw.split("/", 1)[0].strip()
        left_digits = re.sub(r"\D+", "", left_side)
        return left_digits if re.fullmatch(r"[\d\s.,+\-]+", left_side) and len(left_digits) == 15 else ""
    digits = re.sub(r"\D+", "", raw)
    if digits:
        numeric_like = bool(re.fullmatch(r"[\d\s.,+\-]+", raw))
        if numeric_like:
            return digits if len(digits) == 15 else ""
        return raw
    return raw

TOKEN_TTL_HOURS = int(os.getenv("SKYEYE_TOKEN_TTL_HOURS", "8"))
SECURITY_FAILURE_WINDOW_MINUTES = int(os.getenv("SKYEYE_SECURITY_FAILURE_WINDOW_MINUTES", "10"))
SECURITY_BLOCK_MINUTES = int(os.getenv("SKYEYE_SECURITY_BLOCK_MINUTES", "15"))
SECURITY_MAX_USER_FAILURES = int(os.getenv("SKYEYE_SECURITY_MAX_USER_FAILURES", "5"))
SECURITY_MAX_IP_FAILURES = int(os.getenv("SKYEYE_SECURITY_MAX_IP_FAILURES", "12"))
SECURITY_SUPER_ADMIN_USERNAME = os.getenv("SKYEYE_SUPER_ADMIN_USERNAME", "rmercau.spp").strip().lower()
SECURITY_SUPER_ADMIN_MAX_IP_FAILURES = int(os.getenv("SKYEYE_SECURITY_SUPER_ADMIN_MAX_IP_FAILURES", "3"))


def _norm_sql(query: str) -> str:
    if USE_POSTGRES:
        return query.replace("?", "%s")
    return query


def _connect():
    if USE_POSTGRES:
        if psycopg2 is None:
            raise RuntimeError("DATABASE_URL definido pero psycopg2 no esta disponible")
        return psycopg2.connect(DATABASE_URL)

    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


@contextmanager
def _cursor():
    conn = _connect()
    try:
        if USE_POSTGRES:
            cur = conn.cursor(cursor_factory=RealDictCursor)
        else:
            cur = conn.cursor()
        try:
            yield conn, cur
            conn.commit()
        finally:
            cur.close()
    finally:
        conn.close()


def _fetchone(query: str, params: tuple = ()) -> Optional[Dict[str, Any]]:
    with _cursor() as (_, cur):
        cur.execute(_norm_sql(query), params)
        row = cur.fetchone()
    if row is None:
        return None
    return dict(row)


def _fetchall(query: str, params: tuple = ()) -> List[Dict[str, Any]]:
    with _cursor() as (_, cur):
        cur.execute(_norm_sql(query), params)
        rows = cur.fetchall()
    return [dict(r) for r in rows]


def _ensure_column(conn: sqlite3.Connection, table: str, column: str, ddl: str) -> None:
    if USE_POSTGRES:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT 1
                FROM information_schema.columns
                WHERE table_name = %s AND column_name = %s
                """,
                (table, column),
            )
            exists = cur.fetchone() is not None
            if not exists:
                cur.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")
        return

    cols = conn.execute(f"PRAGMA table_info({table})").fetchall()
    names = {row[1] for row in cols}
    if column not in names:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")


def _ensure_septier_postgis_support() -> None:
    """Prepare real PostGIS geometries without breaking plain PostgreSQL/SQLite installs."""
    if not USE_POSTGRES:
        return
    conn = None
    try:
        conn = _connect()
        with conn.cursor() as cur:
            cur.execute("CREATE EXTENSION IF NOT EXISTS postgis")
            cur.execute("SELECT PostGIS_Version()")
            cur.fetchone()
            cur.execute("ALTER TABLE septier_detections ADD COLUMN IF NOT EXISTS system_geom geometry(Point, 4326)")
            cur.execute("ALTER TABLE septier_detections ADD COLUMN IF NOT EXISTS target_geom geometry(Point, 4326)")
            cur.execute("ALTER TABLE septier_detections ADD COLUMN IF NOT EXISTS multipolygon_geom geometry(MultiPolygon, 4326)")
            cur.execute(
                """
                COMMENT ON COLUMN septier_detections.system_geom IS
                'PostGIS point from longitud/latitud: operative system position.'
                """
            )
            cur.execute(
                """
                COMMENT ON COLUMN septier_detections.target_geom IS
                'PostGIS point from target_longitude/target_latitude: estimated device/target position.'
                """
            )
            cur.execute(
                """
                COMMENT ON COLUMN septier_detections.multipolygon_geom IS
                'PostGIS MultiPolygon parsed from Septier multipolygon WKT.'
                """
            )
            cur.execute("CREATE INDEX IF NOT EXISTS idx_septier_detections_system_geom ON septier_detections USING GIST (system_geom)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_septier_detections_target_geom ON septier_detections USING GIST (target_geom)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_septier_detections_multipolygon_geom ON septier_detections USING GIST (multipolygon_geom)")
        conn.commit()
    except Exception as exc:
        if conn is not None:
            conn.rollback()
        print(f"PostGIS no disponible o no inicializado; se mantiene geometria legacy: {exc}")
        return
    finally:
        if conn is not None:
            conn.close()


def _sync_septier_postgis_geometries(
    *,
    files: Optional[List[str]] = None,
    hashes: Optional[List[str]] = None,
    max_multipolygons: int = 500,
) -> None:
    """Populate PostGIS geometry columns from the existing Septier scalar/WKT fields."""
    if not USE_POSTGRES:
        return
    file_values = sorted({str(item or "").strip() for item in (files or []) if str(item or "").strip()})
    hash_values = sorted({str(item or "").strip() for item in (hashes or []) if str(item or "").strip()})
    scope_clauses: List[str] = []
    scope_params: List[Any] = []
    if file_values:
        scope_clauses.append("archivo_origen = ANY(%s)")
        scope_params.append(file_values)
    if hash_values:
        scope_clauses.append("hash_sha256 = ANY(%s)")
        scope_params.append(hash_values)
    if not scope_clauses:
        return
    scope_sql = " AND (" + " OR ".join(scope_clauses) + ")"
    conn = None
    try:
        conn = _connect()
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT 1
                FROM information_schema.columns
                WHERE table_name = 'septier_detections'
                  AND column_name = 'multipolygon_geom'
                """
            )
            if cur.fetchone() is None:
                conn.rollback()
                return
            cur.execute(
                f"""
                UPDATE septier_detections
                SET system_geom = ST_SetSRID(ST_MakePoint(longitud, latitud), 4326)
                WHERE latitud BETWEEN -90 AND 90
                  AND longitud BETWEEN -180 AND 180
                  {scope_sql}
                  AND (
                    system_geom IS NULL
                    OR NOT ST_Equals(system_geom, ST_SetSRID(ST_MakePoint(longitud, latitud), 4326))
                  )
                """,
                tuple(scope_params),
            )
            cur.execute(
                f"""
                UPDATE septier_detections
                SET target_geom = ST_SetSRID(ST_MakePoint(target_longitude, target_latitude), 4326)
                WHERE target_latitude BETWEEN -90 AND 90
                  AND target_longitude BETWEEN -180 AND 180
                  {scope_sql}
                  AND (
                    target_geom IS NULL
                    OR NOT ST_Equals(target_geom, ST_SetSRID(ST_MakePoint(target_longitude, target_latitude), 4326))
                  )
                """,
                tuple(scope_params),
            )
            cur.execute(
                f"""
                SELECT id, multipolygon
                FROM septier_detections
                WHERE multipolygon IS NOT NULL
                  AND BTRIM(multipolygon) <> ''
                  AND multipolygon_geom IS NULL
                  {scope_sql}
                ORDER BY id ASC
                LIMIT %s
                """,
                tuple(scope_params + [max(1, int(max_multipolygons or 500))]),
            )
            rows = cur.fetchall()
            if rows:
                try:
                    from shapely import wkt as shapely_wkt  # type: ignore
                    from shapely.geometry import MultiPolygon  # type: ignore
                except Exception as exc:
                    print(f"Shapely no disponible para convertir Multipolygon a PostGIS: {exc}")
                    rows = []
                for row in rows:
                    if isinstance(row, dict):
                        row_id = row.get("id")
                        multipolygon = row.get("multipolygon")
                    else:
                        row_id, multipolygon = row
                    try:
                        geom = shapely_wkt.loads(str(multipolygon or ""))
                        if geom.is_empty:
                            continue
                        if geom.geom_type == "Polygon":
                            geom = MultiPolygon([geom])
                        elif geom.geom_type != "MultiPolygon":
                            continue
                        if not geom.is_valid:
                            repaired = geom.buffer(0)
                            if repaired.is_empty:
                                continue
                            if repaired.geom_type == "Polygon":
                                geom = MultiPolygon([repaired])
                            elif repaired.geom_type == "MultiPolygon":
                                geom = repaired
                            else:
                                continue
                        cur.execute(
                            """
                            UPDATE septier_detections
                            SET multipolygon_geom = ST_Multi(ST_SetSRID(ST_GeomFromText(%s), 4326))
                            WHERE id = %s
                            """,
                            (geom.wkt, row_id),
                        )
                    except Exception:
                        continue
        conn.commit()
    except Exception as exc:
        if conn is not None:
            conn.rollback()
        print(f"No se pudieron sincronizar geometrias PostGIS Septier: {exc}")
    finally:
        if conn is not None:
            conn.close()


def init_db() -> None:
    with _cursor() as (conn, cur):
        if USE_POSTGRES:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS runs (
                    id BIGSERIAL PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    input_detection_csv TEXT NOT NULL,
                    input_trajectory_csv TEXT,
                    output_dir TEXT NOT NULL,
                    html_report TEXT,
                    tracks_kml TEXT,
                    last_seen_kml TEXT,
                    geo_txt_report TEXT,
                    m3t_kml TEXT,
                    drones_commands_file TEXT,
                    status TEXT NOT NULL,
                    message TEXT,
                    m3t_summary_json TEXT
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id BIGSERIAL PRIMARY KEY,
                    username TEXT NOT NULL UNIQUE,
                    full_name TEXT NOT NULL DEFAULT '',
                    password_hash TEXT NOT NULL,
                    roles_json TEXT NOT NULL,
                    is_active BOOLEAN NOT NULL DEFAULT TRUE,
                    must_change_password BOOLEAN NOT NULL DEFAULT FALSE,
                    mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
                    mfa_secret TEXT NOT NULL DEFAULT '',
                    mfa_confirmed_at TIMESTAMPTZ,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            _ensure_column(conn, "users", "must_change_password", "BOOLEAN NOT NULL DEFAULT FALSE")
            _ensure_column(conn, "users", "mfa_enabled", "BOOLEAN NOT NULL DEFAULT FALSE")
            _ensure_column(conn, "users", "mfa_secret", "TEXT NOT NULL DEFAULT ''")
            _ensure_column(conn, "users", "mfa_confirmed_at", "TIMESTAMPTZ")
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS tokens (
                    token TEXT PRIMARY KEY,
                    user_json TEXT NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS mfa_login_tickets (
                    ticket TEXT PRIMARY KEY,
                    username TEXT NOT NULL,
                    source_ip TEXT,
                    user_agent TEXT,
                    expires_at TIMESTAMPTZ NOT NULL,
                    consumed_at TIMESTAMPTZ,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS detections (
                    id BIGSERIAL PRIMARY KEY,
                    run_id BIGINT,
                    detect_date TEXT,
                    detect_time TEXT,
                    lat DOUBLE PRECISION,
                    lon DOUBLE PRECISION,
                    model TEXT,
                    sensor TEXT,
                    location TEXT,
                    tag TEXT,
                    source TEXT,
                    frequency TEXT,
                    height_m TEXT
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS login_events (
                    id BIGSERIAL PRIMARY KEY,
                    username TEXT NOT NULL,
                    full_name TEXT NOT NULL,
                    role TEXT NOT NULL,
                    source_ip TEXT,
                    user_agent TEXT,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS login_attempts (
                    id BIGSERIAL PRIMARY KEY,
                    username TEXT NOT NULL DEFAULT '',
                    success BOOLEAN NOT NULL DEFAULT FALSE,
                    reason TEXT NOT NULL DEFAULT '',
                    source_ip TEXT,
                    user_agent TEXT,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS security_blocks (
                    id BIGSERIAL PRIMARY KEY,
                    kind TEXT NOT NULL,
                    value TEXT NOT NULL,
                    reason TEXT NOT NULL DEFAULT '',
                    blocked_until TIMESTAMPTZ NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    lifted_at TIMESTAMPTZ,
                    lifted_by TEXT
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS security_events (
                    id BIGSERIAL PRIMARY KEY,
                    event_type TEXT NOT NULL,
                    severity TEXT NOT NULL DEFAULT 'info',
                    username TEXT NOT NULL DEFAULT '',
                    source_ip TEXT,
                    user_agent TEXT,
                    detail TEXT NOT NULL DEFAULT '',
                    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            _ensure_column(conn, "users", "full_name", "TEXT NOT NULL DEFAULT ''")
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS septier_detections (
                    id BIGSERIAL PRIMARY KEY,
                    latitud DOUBLE PRECISION,
                    longitud DOUBLE PRECISION,
                    imsi_mac TEXT,
                    imei TEXT,
                    model TEXT,
                    operation TEXT,
                    orig_lac TEXT,
                    cell_id TEXT,
                    multipolygon TEXT,
                    last_update TIMESTAMPTZ,
                    event_type TEXT,
                    source TEXT,
                    archivo_origen TEXT,
                    hash_sha256 TEXT,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            _ensure_column(conn, "septier_detections", "location", "TEXT DEFAULT ''")
            _ensure_column(conn, "septier_detections", "orig_lac", "TEXT")
            _ensure_column(conn, "septier_detections", "cell_id", "TEXT")
            _ensure_column(conn, "septier_detections", "distance", "REAL")
            _ensure_column(conn, "septier_detections", "target_latitude", "REAL")
            _ensure_column(conn, "septier_detections", "target_longitude", "REAL")
            _ensure_column(conn, "septier_detections", "minor_radius_a", "REAL")
            _ensure_column(conn, "septier_detections", "major_radius_a", "REAL")
            _ensure_column(conn, "septier_detections", "minor_radius_b", "REAL")
            _ensure_column(conn, "septier_detections", "major_radius_b", "REAL")
            _ensure_column(conn, "septier_detections", "start_angle", "REAL")
            _ensure_column(conn, "septier_detections", "stop_angle", "REAL")
            _ensure_column(conn, "septier_detections", "orientation", "REAL")
            _ensure_column(conn, "septier_detections", "distance", "DOUBLE PRECISION")
            _ensure_column(conn, "septier_detections", "target_latitude", "DOUBLE PRECISION")
            _ensure_column(conn, "septier_detections", "target_longitude", "DOUBLE PRECISION")
            _ensure_column(conn, "septier_detections", "minor_radius_a", "DOUBLE PRECISION")
            _ensure_column(conn, "septier_detections", "major_radius_a", "DOUBLE PRECISION")
            _ensure_column(conn, "septier_detections", "minor_radius_b", "DOUBLE PRECISION")
            _ensure_column(conn, "septier_detections", "major_radius_b", "DOUBLE PRECISION")
            _ensure_column(conn, "septier_detections", "start_angle", "DOUBLE PRECISION")
            _ensure_column(conn, "septier_detections", "stop_angle", "DOUBLE PRECISION")
            _ensure_column(conn, "septier_detections", "orientation", "DOUBLE PRECISION")
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS septier_history_metadata (
                    id BIGSERIAL PRIMARY KEY,
                    source TEXT NOT NULL,
                    archivo_origen TEXT NOT NULL,
                    lugar_operativo TEXT NOT NULL DEFAULT '',
                    complejo TEXT NOT NULL DEFAULT '',
                    modulo TEXT NOT NULL DEFAULT '',
                    ala TEXT NOT NULL DEFAULT '',
                    ubicacion TEXT NOT NULL DEFAULT '',
                    coordenadas TEXT NOT NULL DEFAULT '',
                    observacion TEXT NOT NULL DEFAULT '',
                    updated_by TEXT NOT NULL DEFAULT '',
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(source, archivo_origen)
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS septier_history_schema (
                    field TEXT PRIMARY KEY,
                    title TEXT NOT NULL DEFAULT '',
                    position INTEGER NOT NULL DEFAULT 0,
                    selected BOOLEAN NOT NULL DEFAULT FALSE,
                    source_filename TEXT NOT NULL DEFAULT '',
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS septier_network_refs (
                    id BIGSERIAL PRIMARY KEY,
                    mcc TEXT NOT NULL,
                    mnc TEXT NOT NULL,
                    network_name TEXT NOT NULL DEFAULT '',
                    source_type TEXT NOT NULL DEFAULT '',
                    source_filename TEXT NOT NULL DEFAULT '',
                    external_id TEXT NOT NULL DEFAULT '',
                    session_id TEXT NOT NULL DEFAULT '',
                    when_created TEXT NOT NULL DEFAULT '',
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(mcc, mnc, source_type)
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS septier_rf_bands (
                    id BIGSERIAL PRIMARY KEY,
                    rx_type TEXT NOT NULL,
                    band TEXT NOT NULL,
                    label TEXT NOT NULL DEFAULT '',
                    frequency TEXT NOT NULL DEFAULT '',
                    command TEXT NOT NULL DEFAULT '',
                    source_filename TEXT NOT NULL DEFAULT '',
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(rx_type, band)
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS whitelist_devices (
                    id BIGSERIAL PRIMARY KEY,
                    device_id TEXT NOT NULL UNIQUE,
                    device_type TEXT,
                    description TEXT,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS whitelist_uploads (
                    id BIGSERIAL PRIMARY KEY,
                    original_filename TEXT NOT NULL,
                    stored_filename TEXT NOT NULL,
                    stored_path TEXT NOT NULL,
                    uploaded_by TEXT,
                    replace_mode BOOLEAN NOT NULL DEFAULT FALSE,
                    rows_count INTEGER NOT NULL DEFAULT 0,
                    unique_count INTEGER NOT NULL DEFAULT 0,
                    inserted_count INTEGER NOT NULL DEFAULT 0,
                    deleted_at TIMESTAMPTZ,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS whitelist_upload_items (
                    id BIGSERIAL PRIMARY KEY,
                    upload_id BIGINT NOT NULL,
                    device_id TEXT NOT NULL,
                    existed_before BOOLEAN NOT NULL DEFAULT FALSE
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS external_identity_uploads (
                    id BIGSERIAL PRIMARY KEY,
                    original_filename TEXT NOT NULL,
                    stored_filename TEXT NOT NULL,
                    stored_path TEXT NOT NULL,
                    uploaded_by TEXT,
                    hash_sha256 TEXT NOT NULL DEFAULT '',
                    rows_count INTEGER NOT NULL DEFAULT 0,
                    unique_imsi_count INTEGER NOT NULL DEFAULT 0,
                    unique_imei_count INTEGER NOT NULL DEFAULT 0,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS external_identity_data (
                    id BIGSERIAL PRIMARY KEY,
                    upload_id BIGINT NOT NULL,
                    imsi TEXT NOT NULL DEFAULT '',
                    imei TEXT NOT NULL DEFAULT '',
                    prestataria TEXT NOT NULL DEFAULT '',
                    estado TEXT NOT NULL DEFAULT '',
                    modelo TEXT NOT NULL DEFAULT '',
                    source_filename TEXT NOT NULL DEFAULT '',
                    hash_sha256 TEXT NOT NULL DEFAULT '',
                    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS tower_catalog (
                    id BIGSERIAL PRIMARY KEY,
                    provider TEXT NOT NULL DEFAULT '',
                    mcc TEXT NOT NULL DEFAULT '',
                    mnc TEXT NOT NULL DEFAULT '',
                    lac TEXT NOT NULL,
                    cell_id TEXT NOT NULL,
                    lat DOUBLE PRECISION,
                    lon DOUBLE PRECISION,
                    source TEXT NOT NULL DEFAULT '',
                    notes TEXT NOT NULL DEFAULT '',
                    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(provider, lac, cell_id)
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS septier_objectives (
                    id BIGSERIAL PRIMARY KEY,
                    request_type TEXT NOT NULL DEFAULT '',
                    case_number TEXT NOT NULL DEFAULT '',
                    requester TEXT NOT NULL DEFAULT '',
                    person_name TEXT NOT NULL DEFAULT '',
                    dni TEXT NOT NULL DEFAULT '',
                    phone TEXT NOT NULL DEFAULT '',
                    imsi TEXT NOT NULL DEFAULT '',
                    imei TEXT NOT NULL DEFAULT '',
                    geomatrix_lat TEXT NOT NULL DEFAULT '',
                    geomatrix_lon TEXT NOT NULL DEFAULT '',
                    geomatrix_ref TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'pendiente',
                    notes TEXT NOT NULL DEFAULT '',
                    field_staff TEXT NOT NULL DEFAULT '',
                    technologies_used TEXT NOT NULL DEFAULT '',
                    methodology TEXT NOT NULL DEFAULT '',
                    created_by TEXT NOT NULL DEFAULT '',
                    updated_by TEXT NOT NULL DEFAULT '',
                    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS septier_objective_reports (
                    id BIGSERIAL PRIMARY KEY,
                    objective_id BIGINT NOT NULL,
                    html_path TEXT NOT NULL DEFAULT '',
                    word_path TEXT NOT NULL DEFAULT '',
                    sha256 TEXT NOT NULL DEFAULT '',
                    generated_by TEXT NOT NULL DEFAULT '',
                    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS septier_objective_history_uploads (
                    id BIGSERIAL PRIMARY KEY,
                    objective_id BIGINT NOT NULL,
                    original_filename TEXT NOT NULL DEFAULT '',
                    stored_filename TEXT NOT NULL DEFAULT '',
                    stored_path TEXT NOT NULL DEFAULT '',
                    rows_count INTEGER NOT NULL DEFAULT 0,
                    hash_sha256 TEXT NOT NULL DEFAULT '',
                    uploaded_by TEXT NOT NULL DEFAULT '',
                    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS septier_objective_history_rows (
                    id BIGSERIAL PRIMARY KEY,
                    objective_id BIGINT NOT NULL,
                    upload_id BIGINT NOT NULL,
                    imsi_mac TEXT NOT NULL DEFAULT '',
                    imei TEXT NOT NULL DEFAULT '',
                    model TEXT NOT NULL DEFAULT '',
                    operation TEXT NOT NULL DEFAULT '',
                    orig_lac TEXT NOT NULL DEFAULT '',
                    cell_id TEXT NOT NULL DEFAULT '',
                    last_update TEXT NOT NULL DEFAULT '',
                    event_type TEXT NOT NULL DEFAULT '',
                    source TEXT NOT NULL DEFAULT 'objetivo',
                    archivo_origen TEXT NOT NULL DEFAULT '',
                    hash_sha256 TEXT NOT NULL DEFAULT '',
                    location TEXT NOT NULL DEFAULT '',
                    lat_text TEXT NOT NULL DEFAULT '',
                    lon_text TEXT NOT NULL DEFAULT '',
                    gps_text TEXT NOT NULL DEFAULT '',
                    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS septier_objective_images (
                    id BIGSERIAL PRIMARY KEY,
                    objective_id BIGINT NOT NULL,
                    image_type TEXT NOT NULL DEFAULT '',
                    original_filename TEXT NOT NULL DEFAULT '',
                    stored_filename TEXT NOT NULL DEFAULT '',
                    stored_path TEXT NOT NULL DEFAULT '',
                    content_type TEXT NOT NULL DEFAULT '',
                    hash_sha256 TEXT NOT NULL DEFAULT '',
                    uploaded_by TEXT NOT NULL DEFAULT '',
                    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS septier_objective_csv_attachments (
                    id BIGSERIAL PRIMARY KEY,
                    objective_id BIGINT NOT NULL,
                    original_filename TEXT NOT NULL DEFAULT '',
                    stored_filename TEXT NOT NULL DEFAULT '',
                    stored_path TEXT NOT NULL DEFAULT '',
                    rows_count INTEGER NOT NULL DEFAULT 0,
                    columns_json TEXT NOT NULL DEFAULT '[]',
                    hash_sha256 TEXT NOT NULL DEFAULT '',
                    uploaded_by TEXT NOT NULL DEFAULT '',
                    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            _ensure_column(conn, "septier_objectives", "field_staff", "TEXT NOT NULL DEFAULT ''")
            _ensure_column(conn, "septier_objectives", "technologies_used", "TEXT NOT NULL DEFAULT ''")
            _ensure_column(conn, "septier_objectives", "methodology", "TEXT NOT NULL DEFAULT ''")
            _ensure_column(conn, "septier_objective_history_rows", "lat_text", "TEXT NOT NULL DEFAULT ''")
            _ensure_column(conn, "septier_objective_history_rows", "lon_text", "TEXT NOT NULL DEFAULT ''")
            _ensure_column(conn, "septier_objective_history_rows", "gps_text", "TEXT NOT NULL DEFAULT ''")
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS historial_informes (
                    id BIGSERIAL PRIMARY KEY,
                    imsi TEXT,
                    imei TEXT,
                    archivo_origen TEXT,
                    numero_informe TEXT,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS informes_generados (
                    id BIGSERIAL PRIMARY KEY,
                    numero_nota INTEGER NOT NULL,
                    anio INTEGER NOT NULL,
                    numero_informe TEXT NOT NULL,
                    tipo TEXT,
                    usuario TEXT,
                    archivos_json TEXT NOT NULL DEFAULT '[]',
                    objetivos_count INTEGER NOT NULL DEFAULT 0,
                    download_url TEXT,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS phone_queries (
                    id BIGSERIAL PRIMARY KEY,
                    reference TEXT NOT NULL DEFAULT '',
                    phone TEXT NOT NULL DEFAULT '',
                    area_label TEXT NOT NULL DEFAULT '',
                    area_lat DOUBLE PRECISION,
                    area_lon DOUBLE PRECISION,
                    radius_m INTEGER NOT NULL DEFAULT 50000,
                    status TEXT NOT NULL DEFAULT '',
                    provider_summary_json TEXT NOT NULL DEFAULT '{}',
                    html_path TEXT NOT NULL DEFAULT '',
                    word_path TEXT NOT NULL DEFAULT '',
                    sha256 TEXT NOT NULL DEFAULT '',
                    created_by TEXT NOT NULL DEFAULT '',
                    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
        else:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    input_detection_csv TEXT NOT NULL,
                    input_trajectory_csv TEXT,
                    output_dir TEXT NOT NULL,
                    html_report TEXT,
                    tracks_kml TEXT,
                    last_seen_kml TEXT,
                    geo_txt_report TEXT,
                    m3t_kml TEXT,
                    drones_commands_file TEXT,
                    status TEXT NOT NULL,
                    message TEXT,
                    m3t_summary_json TEXT
                )
                """
            )
            _ensure_column(conn, "runs", "drones_commands_file", "TEXT")
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    full_name TEXT NOT NULL DEFAULT '',
                    password_hash TEXT NOT NULL,
                    roles_json TEXT NOT NULL,
                    is_active INTEGER NOT NULL DEFAULT 1,
                    must_change_password INTEGER NOT NULL DEFAULT 0,
                    mfa_enabled INTEGER NOT NULL DEFAULT 0,
                    mfa_secret TEXT NOT NULL DEFAULT '',
                    mfa_confirmed_at TEXT,
                    created_at TEXT NOT NULL
                )
                """
            )
            _ensure_column(conn, "users", "full_name", "TEXT NOT NULL DEFAULT ''")
            _ensure_column(conn, "users", "must_change_password", "INTEGER NOT NULL DEFAULT 0")
            _ensure_column(conn, "users", "mfa_enabled", "INTEGER NOT NULL DEFAULT 0")
            _ensure_column(conn, "users", "mfa_secret", "TEXT NOT NULL DEFAULT ''")
            _ensure_column(conn, "users", "mfa_confirmed_at", "TEXT")
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS tokens (
                    token TEXT PRIMARY KEY,
                    user_json TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS mfa_login_tickets (
                    ticket TEXT PRIMARY KEY,
                    username TEXT NOT NULL,
                    source_ip TEXT,
                    user_agent TEXT,
                    expires_at TEXT NOT NULL,
                    consumed_at TEXT,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS login_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    full_name TEXT NOT NULL,
                    role TEXT NOT NULL,
                    source_ip TEXT,
                    user_agent TEXT,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS login_attempts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL DEFAULT '',
                    success INTEGER NOT NULL DEFAULT 0,
                    reason TEXT NOT NULL DEFAULT '',
                    source_ip TEXT,
                    user_agent TEXT,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS security_blocks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    kind TEXT NOT NULL,
                    value TEXT NOT NULL,
                    reason TEXT NOT NULL DEFAULT '',
                    blocked_until TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    lifted_at TEXT,
                    lifted_by TEXT
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS security_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    severity TEXT NOT NULL DEFAULT 'info',
                    username TEXT NOT NULL DEFAULT '',
                    source_ip TEXT,
                    user_agent TEXT,
                    detail TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS detections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id INTEGER,
                    detect_date TEXT,
                    detect_time TEXT,
                    lat REAL,
                    lon REAL,
                    model TEXT,
                    sensor TEXT,
                    location TEXT,
                    tag TEXT,
                    source TEXT,
                    frequency TEXT,
                    height_m TEXT
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS septier_detections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    latitud REAL,
                    longitud REAL,
                    imsi_mac TEXT,
                    imei TEXT,
                    model TEXT,
                    operation TEXT,
                    orig_lac TEXT,
                    cell_id TEXT,
                    multipolygon TEXT,
                    last_update TEXT,
                    event_type TEXT,
                    source TEXT,
                    archivo_origen TEXT,
                    hash_sha256 TEXT,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            _ensure_column(conn, "septier_detections", "location", "TEXT DEFAULT ''")
            _ensure_column(conn, "septier_detections", "orig_lac", "TEXT")
            _ensure_column(conn, "septier_detections", "cell_id", "TEXT")
            _ensure_column(conn, "septier_detections", "distance", "REAL")
            _ensure_column(conn, "septier_detections", "target_latitude", "REAL")
            _ensure_column(conn, "septier_detections", "target_longitude", "REAL")
            _ensure_column(conn, "septier_detections", "minor_radius_a", "REAL")
            _ensure_column(conn, "septier_detections", "major_radius_a", "REAL")
            _ensure_column(conn, "septier_detections", "minor_radius_b", "REAL")
            _ensure_column(conn, "septier_detections", "major_radius_b", "REAL")
            _ensure_column(conn, "septier_detections", "start_angle", "REAL")
            _ensure_column(conn, "septier_detections", "stop_angle", "REAL")
            _ensure_column(conn, "septier_detections", "orientation", "REAL")
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS septier_history_metadata (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source TEXT NOT NULL,
                    archivo_origen TEXT NOT NULL,
                    lugar_operativo TEXT NOT NULL DEFAULT '',
                    complejo TEXT NOT NULL DEFAULT '',
                    modulo TEXT NOT NULL DEFAULT '',
                    ala TEXT NOT NULL DEFAULT '',
                    ubicacion TEXT NOT NULL DEFAULT '',
                    coordenadas TEXT NOT NULL DEFAULT '',
                    observacion TEXT NOT NULL DEFAULT '',
                    updated_by TEXT NOT NULL DEFAULT '',
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(source, archivo_origen)
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS septier_history_schema (
                    field TEXT PRIMARY KEY,
                    title TEXT NOT NULL DEFAULT '',
                    position INTEGER NOT NULL DEFAULT 0,
                    selected INTEGER NOT NULL DEFAULT 0,
                    source_filename TEXT NOT NULL DEFAULT '',
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS septier_network_refs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    mcc TEXT NOT NULL,
                    mnc TEXT NOT NULL,
                    network_name TEXT NOT NULL DEFAULT '',
                    source_type TEXT NOT NULL DEFAULT '',
                    source_filename TEXT NOT NULL DEFAULT '',
                    external_id TEXT NOT NULL DEFAULT '',
                    session_id TEXT NOT NULL DEFAULT '',
                    when_created TEXT NOT NULL DEFAULT '',
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(mcc, mnc, source_type)
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS septier_rf_bands (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    rx_type TEXT NOT NULL,
                    band TEXT NOT NULL,
                    label TEXT NOT NULL DEFAULT '',
                    frequency TEXT NOT NULL DEFAULT '',
                    command TEXT NOT NULL DEFAULT '',
                    source_filename TEXT NOT NULL DEFAULT '',
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(rx_type, band)
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS whitelist_devices (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id TEXT NOT NULL UNIQUE,
                    device_type TEXT,
                    description TEXT,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS whitelist_uploads (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    original_filename TEXT NOT NULL,
                    stored_filename TEXT NOT NULL,
                    stored_path TEXT NOT NULL,
                    uploaded_by TEXT,
                    replace_mode INTEGER NOT NULL DEFAULT 0,
                    rows_count INTEGER NOT NULL DEFAULT 0,
                    unique_count INTEGER NOT NULL DEFAULT 0,
                    inserted_count INTEGER NOT NULL DEFAULT 0,
                    deleted_at TEXT,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS whitelist_upload_items (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    upload_id INTEGER NOT NULL,
                    device_id TEXT NOT NULL,
                    existed_before INTEGER NOT NULL DEFAULT 0
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS external_identity_uploads (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    original_filename TEXT NOT NULL,
                    stored_filename TEXT NOT NULL,
                    stored_path TEXT NOT NULL,
                    uploaded_by TEXT,
                    hash_sha256 TEXT NOT NULL DEFAULT '',
                    rows_count INTEGER NOT NULL DEFAULT 0,
                    unique_imsi_count INTEGER NOT NULL DEFAULT 0,
                    unique_imei_count INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS external_identity_data (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    upload_id INTEGER NOT NULL,
                    imsi TEXT NOT NULL DEFAULT '',
                    imei TEXT NOT NULL DEFAULT '',
                    prestataria TEXT NOT NULL DEFAULT '',
                    estado TEXT NOT NULL DEFAULT '',
                    modelo TEXT NOT NULL DEFAULT '',
                    source_filename TEXT NOT NULL DEFAULT '',
                    hash_sha256 TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS tower_catalog (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    provider TEXT NOT NULL DEFAULT '',
                    mcc TEXT NOT NULL DEFAULT '',
                    mnc TEXT NOT NULL DEFAULT '',
                    lac TEXT NOT NULL,
                    cell_id TEXT NOT NULL,
                    lat REAL,
                    lon REAL,
                    source TEXT NOT NULL DEFAULT '',
                    notes TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(provider, lac, cell_id)
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS septier_objectives (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    request_type TEXT NOT NULL DEFAULT '',
                    case_number TEXT NOT NULL DEFAULT '',
                    requester TEXT NOT NULL DEFAULT '',
                    person_name TEXT NOT NULL DEFAULT '',
                    dni TEXT NOT NULL DEFAULT '',
                    phone TEXT NOT NULL DEFAULT '',
                    imsi TEXT NOT NULL DEFAULT '',
                    imei TEXT NOT NULL DEFAULT '',
                    geomatrix_lat TEXT NOT NULL DEFAULT '',
                    geomatrix_lon TEXT NOT NULL DEFAULT '',
                    geomatrix_ref TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'pendiente',
                    notes TEXT NOT NULL DEFAULT '',
                    field_staff TEXT NOT NULL DEFAULT '',
                    technologies_used TEXT NOT NULL DEFAULT '',
                    methodology TEXT NOT NULL DEFAULT '',
                    created_by TEXT NOT NULL DEFAULT '',
                    updated_by TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS septier_objective_reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    objective_id INTEGER NOT NULL,
                    html_path TEXT NOT NULL DEFAULT '',
                    word_path TEXT NOT NULL DEFAULT '',
                    sha256 TEXT NOT NULL DEFAULT '',
                    generated_by TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS septier_objective_history_uploads (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    objective_id INTEGER NOT NULL,
                    original_filename TEXT NOT NULL DEFAULT '',
                    stored_filename TEXT NOT NULL DEFAULT '',
                    stored_path TEXT NOT NULL DEFAULT '',
                    rows_count INTEGER NOT NULL DEFAULT 0,
                    hash_sha256 TEXT NOT NULL DEFAULT '',
                    uploaded_by TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS septier_objective_history_rows (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    objective_id INTEGER NOT NULL,
                    upload_id INTEGER NOT NULL,
                    imsi_mac TEXT NOT NULL DEFAULT '',
                    imei TEXT NOT NULL DEFAULT '',
                    model TEXT NOT NULL DEFAULT '',
                    operation TEXT NOT NULL DEFAULT '',
                    orig_lac TEXT NOT NULL DEFAULT '',
                    cell_id TEXT NOT NULL DEFAULT '',
                    last_update TEXT NOT NULL DEFAULT '',
                    event_type TEXT NOT NULL DEFAULT '',
                    source TEXT NOT NULL DEFAULT 'objetivo',
                    archivo_origen TEXT NOT NULL DEFAULT '',
                    hash_sha256 TEXT NOT NULL DEFAULT '',
                    location TEXT NOT NULL DEFAULT '',
                    lat_text TEXT NOT NULL DEFAULT '',
                    lon_text TEXT NOT NULL DEFAULT '',
                    gps_text TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS septier_objective_images (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    objective_id INTEGER NOT NULL,
                    image_type TEXT NOT NULL DEFAULT '',
                    original_filename TEXT NOT NULL DEFAULT '',
                    stored_filename TEXT NOT NULL DEFAULT '',
                    stored_path TEXT NOT NULL DEFAULT '',
                    content_type TEXT NOT NULL DEFAULT '',
                    hash_sha256 TEXT NOT NULL DEFAULT '',
                    uploaded_by TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS septier_objective_csv_attachments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    objective_id INTEGER NOT NULL,
                    original_filename TEXT NOT NULL DEFAULT '',
                    stored_filename TEXT NOT NULL DEFAULT '',
                    stored_path TEXT NOT NULL DEFAULT '',
                    rows_count INTEGER NOT NULL DEFAULT 0,
                    columns_json TEXT NOT NULL DEFAULT '[]',
                    hash_sha256 TEXT NOT NULL DEFAULT '',
                    uploaded_by TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            _ensure_column(conn, "septier_objectives", "field_staff", "TEXT NOT NULL DEFAULT ''")
            _ensure_column(conn, "septier_objectives", "technologies_used", "TEXT NOT NULL DEFAULT ''")
            _ensure_column(conn, "septier_objectives", "methodology", "TEXT NOT NULL DEFAULT ''")
            _ensure_column(conn, "septier_objective_history_rows", "lat_text", "TEXT NOT NULL DEFAULT ''")
            _ensure_column(conn, "septier_objective_history_rows", "lon_text", "TEXT NOT NULL DEFAULT ''")
            _ensure_column(conn, "septier_objective_history_rows", "gps_text", "TEXT NOT NULL DEFAULT ''")
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS historial_informes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    imsi TEXT,
                    imei TEXT,
                    archivo_origen TEXT,
                    numero_informe TEXT,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS informes_generados (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    numero_nota INTEGER NOT NULL,
                    anio INTEGER NOT NULL,
                    numero_informe TEXT NOT NULL,
                    tipo TEXT,
                    usuario TEXT,
                    archivos_json TEXT NOT NULL DEFAULT '[]',
                    objetivos_count INTEGER NOT NULL DEFAULT 0,
                    download_url TEXT,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS phone_queries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    reference TEXT NOT NULL DEFAULT '',
                    phone TEXT NOT NULL DEFAULT '',
                    area_label TEXT NOT NULL DEFAULT '',
                    area_lat REAL,
                    area_lon REAL,
                    radius_m INTEGER NOT NULL DEFAULT 50000,
                    status TEXT NOT NULL DEFAULT '',
                    provider_summary_json TEXT NOT NULL DEFAULT '{}',
                    html_path TEXT NOT NULL DEFAULT '',
                    word_path TEXT NOT NULL DEFAULT '',
                    sha256 TEXT NOT NULL DEFAULT '',
                    created_by TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )


    if USE_POSTGRES:
        _ensure_septier_postgis_support()


def store_token(token: str, user: Dict[str, Any]) -> None:
    payload = json.dumps(user, ensure_ascii=False)
    with _cursor() as (_, cur):
        if USE_POSTGRES:
            cur.execute(
                """
                INSERT INTO tokens (token, user_json)
                VALUES (?, ?)
                ON CONFLICT (token) DO UPDATE SET user_json = EXCLUDED.user_json
                """,
                (token, payload),
            )
        else:
            cur.execute(
                _norm_sql("INSERT OR REPLACE INTO tokens (token, user_json) VALUES (?, ?)"),
                (token, payload),
            )


def get_token_user(token: str) -> Optional[Dict[str, Any]]:
    row = _fetchone("SELECT user_json, created_at FROM tokens WHERE token = ?", (token,))
    if row is None:
        return None
    if TOKEN_TTL_HOURS > 0:
        created_at = row.get("created_at")
        if isinstance(created_at, str):
            try:
                created_at = dt.datetime.fromisoformat(created_at.replace("Z", "+00:00"))
            except Exception:
                created_at = None
        if isinstance(created_at, dt.datetime):
            if created_at.tzinfo is not None:
                now = dt.datetime.now(dt.timezone.utc)
            else:
                now = dt.datetime.now()
            if now - created_at > dt.timedelta(hours=TOKEN_TTL_HOURS):
                delete_token(token)
                return None
    return json.loads(row["user_json"])


def delete_token(token: str) -> None:
    with _cursor() as (_, cur):
        cur.execute(_norm_sql("DELETE FROM tokens WHERE token = ?"), (token,))


def _hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def ensure_default_user() -> None:
    with _cursor() as (_, cur):
        # Migrar por seguridad el usuario 'ministerio' a 'rmercau.spp' si existe
        cur.execute(_norm_sql("UPDATE users SET username = 'rmercau.spp' WHERE username = 'ministerio'"))
        cur.execute(
            _norm_sql(
                """
                UPDATE users
                SET is_active = ?
                WHERE username IN ('analista', 'visita')
                  AND full_name IN ('USUARIO ANALISTA', 'USUARIO VISITA')
                """
            ),
            (False if USE_POSTGRES else 0,),
        )
        
    seed_users = [
        {
            "username": "rmercau.spp",
            "full_name": "ROMINA SILVANA MERCAU",
            "password": os.getenv("DEFAULT_ADMIN_PASS", "Antena"),
            "roles": ["admin"],
        },
    ]
    with _cursor() as (_, cur):
        for item in seed_users:
            cur.execute(_norm_sql("SELECT id FROM users WHERE username = ?"), (item["username"],))
            row = cur.fetchone()
            if row is None:
                cur.execute(
                    _norm_sql(
                        """
                        INSERT INTO users (username, full_name, password_hash, roles_json, is_active, created_at)
                        VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                        """
                    ),
                    (
                        item["username"],
                        item["full_name"],
                        _hash_password(item["password"]),
                        json.dumps(item["roles"], ensure_ascii=False),
                        True if USE_POSTGRES else 1,
                    ),
                )
            else:
                cur.execute(
                    _norm_sql("UPDATE users SET full_name = ? WHERE username = ?"),
                    (item["full_name"], item["username"]),
                )


def authenticate_user(username: str, password: str) -> Optional[Dict[str, Any]]:
    active_clause = "is_active = TRUE" if USE_POSTGRES else "is_active = 1"
    row = _fetchone(
        f"SELECT * FROM users WHERE username = ? AND {active_clause}",
        (username,),
    )
    if row is None:
        return None

    user = row
    if user["password_hash"] != _hash_password(password):
        return None

    return {
        "id": user["id"],
        "username": user["username"],
        "full_name": user.get("full_name", ""),
        "roles": json.loads(user["roles_json"] or "[]"),
        "must_change_password": bool(user.get("must_change_password", False)),
        "mfa_enabled": bool(user.get("mfa_enabled", False)),
    }


def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    active_clause = "is_active = TRUE" if USE_POSTGRES else "is_active = 1"
    row = _fetchone(
        f"SELECT * FROM users WHERE username = ? AND {active_clause}",
        (username,),
    )
    if row is None:
        return None

    user = row
    return {
        "id": user["id"],
        "username": user["username"],
        "full_name": user.get("full_name", ""),
        "roles": json.loads(user["roles_json"] or "[]"),
        "password_hash": user["password_hash"],
        "must_change_password": bool(user.get("must_change_password", False)),
        "mfa_enabled": bool(user.get("mfa_enabled", False)),
        "mfa_secret": user.get("mfa_secret", ""),
        "mfa_confirmed_at": user.get("mfa_confirmed_at"),
    }


def change_password(username: str, current_password: str, new_password: str) -> bool:
    user = get_user_by_username(username)
    if user is None:
        return False
    if user["password_hash"] != _hash_password(current_password):
        return False

    with _cursor() as (_, cur):
        cur.execute(
            _norm_sql("UPDATE users SET password_hash = ?, must_change_password = ? WHERE username = ?"),
            (_hash_password(new_password), False if USE_POSTGRES else 0, username),
        )
    return True


def set_user_mfa_secret(username: str, secret: str) -> bool:
    with _cursor() as (_, cur):
        cur.execute(
            _norm_sql(
                """
                UPDATE users
                SET mfa_secret = ?, mfa_enabled = ?, mfa_confirmed_at = NULL
                WHERE username = ?
                """
            ),
            (secret.strip(), False if USE_POSTGRES else 0, username.strip()),
        )
        return bool(cur.rowcount)


def confirm_user_mfa(username: str) -> bool:
    with _cursor() as (_, cur):
        cur.execute(
            _norm_sql(
                """
                UPDATE users
                SET mfa_enabled = ?, mfa_confirmed_at = CURRENT_TIMESTAMP
                WHERE username = ? AND COALESCE(mfa_secret, '') <> ''
                """
            ),
            (True if USE_POSTGRES else 1, username.strip()),
        )
        return bool(cur.rowcount)


def cleanup_mfa_login_tickets() -> None:
    with _cursor() as (_, cur):
        cur.execute(
            _norm_sql(
                """
                DELETE FROM mfa_login_tickets
                WHERE expires_at <= CURRENT_TIMESTAMP OR consumed_at IS NOT NULL
                """
            )
        )


def create_mfa_login_ticket(
    ticket: str,
    username: str,
    source_ip: str = "",
    user_agent: str = "",
    ttl_seconds: int = 300,
) -> None:
    cleanup_mfa_login_tickets()
    expires_at = (dt.datetime.utcnow() + dt.timedelta(seconds=max(1, int(ttl_seconds)))).strftime("%Y-%m-%d %H:%M:%S")
    with _cursor() as (_, cur):
        cur.execute(
            _norm_sql(
                """
                INSERT INTO mfa_login_tickets
                    (ticket, username, source_ip, user_agent, expires_at)
                VALUES (?, ?, ?, ?, ?)
                """
            ),
            (ticket.strip(), username.strip(), source_ip.strip(), user_agent.strip(), expires_at),
        )


def get_mfa_login_ticket(ticket: str) -> Optional[Dict[str, Any]]:
    cleanup_mfa_login_tickets()
    return _fetchone(
        """
        SELECT ticket, username, source_ip, user_agent, expires_at, created_at
        FROM mfa_login_tickets
        WHERE ticket = ? AND consumed_at IS NULL AND expires_at > CURRENT_TIMESTAMP
        """,
        (ticket.strip(),),
    )


def consume_mfa_login_ticket(ticket: str) -> bool:
    with _cursor() as (_, cur):
        cur.execute(
            _norm_sql(
                """
                UPDATE mfa_login_tickets
                SET consumed_at = CURRENT_TIMESTAMP
                WHERE ticket = ? AND consumed_at IS NULL AND expires_at > CURRENT_TIMESTAMP
                """
            ),
            (ticket.strip(),),
        )
        return bool(cur.rowcount)


def create_user(
    username: str,
    password: str,
    roles: List[str],
    full_name: str = "",
    must_change_password: bool = False,
) -> Dict[str, Any]:
    clean_roles = sorted({r.strip().lower() for r in roles if r and r.strip()})
    if not clean_roles:
        clean_roles = ["visita"]

    with _cursor() as (_, cur):
        if USE_POSTGRES:
            cur.execute(
                _norm_sql(
                    """
                    INSERT INTO users (username, full_name, password_hash, roles_json, is_active, must_change_password, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                    RETURNING id
                    """
                ),
                (
                    username.strip(),
                    full_name.strip(),
                    _hash_password(password),
                    json.dumps(clean_roles, ensure_ascii=False),
                    True,
                    bool(must_change_password),
                ),
            )
            user_id = int(cur.fetchone()["id"])
        else:
            cur.execute(
                _norm_sql(
                    """
                    INSERT INTO users (username, full_name, password_hash, roles_json, is_active, must_change_password, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                    """
                ),
                (
                    username.strip(),
                    full_name.strip(),
                    _hash_password(password),
                    json.dumps(clean_roles, ensure_ascii=False),
                    1,
                    1 if must_change_password else 0,
                ),
            )
            user_id = int(cur.lastrowid)

    return {
        "id": user_id,
        "username": username.strip(),
        "full_name": full_name.strip(),
        "roles": clean_roles,
        "must_change_password": bool(must_change_password),
        "mfa_enabled": False,
    }


def get_user_by_id(user_id: int) -> Optional[Dict[str, Any]]:
    row = _fetchone(
        "SELECT id, username, full_name, roles_json, is_active, must_change_password, mfa_enabled, created_at FROM users WHERE id = ?",
        (user_id,),
    )
    if row is None:
        return None
    return {
        "id": row["id"],
        "username": row["username"],
        "full_name": row.get("full_name", ""),
        "roles": json.loads(row["roles_json"] or "[]"),
        "is_active": bool(row["is_active"]),
        "must_change_password": bool(row.get("must_change_password", False)),
        "mfa_enabled": bool(row.get("mfa_enabled", False)),
        "created_at": row["created_at"],
    }


def update_user(
    user_id: int,
    username: str,
    full_name: str,
    roles: List[str],
    password: str = "",
    is_active: Optional[bool] = None,
) -> Optional[Dict[str, Any]]:
    clean_roles = sorted({r.strip().lower() for r in roles if r and r.strip()})
    if not clean_roles:
        clean_roles = ["visita"]

    sets = ["username = ?", "full_name = ?", "roles_json = ?"]
    params: List[Any] = [username.strip(), full_name.strip(), json.dumps(clean_roles, ensure_ascii=False)]
    if password.strip():
        sets.append("password_hash = ?")
        params.append(_hash_password(password))
        sets.append("must_change_password = ?")
        params.append(True if USE_POSTGRES else 1)
    if is_active is not None:
        sets.append("is_active = ?")
        params.append(bool(is_active) if USE_POSTGRES else (1 if is_active else 0))
    params.append(user_id)

    with _cursor() as (_, cur):
        cur.execute(
            _norm_sql(f"UPDATE users SET {', '.join(sets)} WHERE id = ?"),
            tuple(params),
        )
    return get_user_by_id(user_id)


def set_user_active(user_id: int, is_active: bool) -> Optional[Dict[str, Any]]:
    with _cursor() as (_, cur):
        cur.execute(
            _norm_sql("UPDATE users SET is_active = ? WHERE id = ?"),
            (bool(is_active) if USE_POSTGRES else (1 if is_active else 0), user_id),
        )
    return get_user_by_id(user_id)


def delete_user_by_id(user_id: int) -> None:
    with _cursor() as (_, cur):
        cur.execute(_norm_sql("DELETE FROM users WHERE id = ?"), (user_id,))


def list_users() -> List[Dict[str, Any]]:
    rows = _fetchall(
        "SELECT id, username, full_name, roles_json, is_active, must_change_password, mfa_enabled, created_at FROM users ORDER BY id ASC"
    )

    users: List[Dict[str, Any]] = []
    for row in rows:
        item = row
        users.append(
            {
                "id": item["id"],
                "username": item["username"],
                "full_name": item.get("full_name", ""),
                "roles": json.loads(item["roles_json"] or "[]"),
                "is_active": bool(item["is_active"]),
                "must_change_password": bool(item.get("must_change_password", False)),
                "mfa_enabled": bool(item.get("mfa_enabled", False)),
                "created_at": item["created_at"],
            }
        )
    return users


def list_login_events(
    limit: int = 200,
    username: str = "",
    role: str = "",
    date_from: str = "",
    date_to: str = "",
) -> List[Dict[str, Any]]:
    safe_limit = max(1, min(int(limit), 1000))
    like_op = "ILIKE" if USE_POSTGRES else "LIKE"
    clauses: List[str] = []
    params: List[Any] = []

    if username:
        clauses.append(f"username {like_op} ?")
        params.append(f"%{username.strip()}%")
    if role:
        clauses.append("LOWER(role) = ?")
        params.append(role.strip().lower())
    if date_from:
        clauses.append("DATE(created_at) >= ?")
        params.append(date_from.strip())
    if date_to:
        clauses.append("DATE(created_at) <= ?")
        params.append(date_to.strip())

    where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    params.append(safe_limit)

    rows = _fetchall(
        _norm_sql(
            f"""
            SELECT id, username, full_name, role, source_ip, user_agent, created_at
            FROM login_events
            {where_sql}
            ORDER BY id DESC
            LIMIT ?
            """
        ),
        tuple(params),
    )
    return rows


def record_login_event(user: Dict[str, Any], source_ip: str = "", user_agent: str = "") -> None:
    roles = [str(r).strip().lower() for r in user.get("roles", []) if str(r).strip()]
    role = roles[0] if roles else "visita"
    with _cursor() as (_, cur):
        cur.execute(
            _norm_sql(
                """
                INSERT INTO login_events (username, full_name, role, source_ip, user_agent, created_at)
                VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                """
            ),
            (
                str(user.get("username", "")).strip(),
                str(user.get("full_name", "")).strip(),
                role,
                source_ip.strip(),
                user_agent.strip(),
            ),
        )


def _security_block_value(kind: str, value: str) -> str:
    clean = str(value or "").strip()
    if kind == "username":
        return clean.lower()
    return clean


def _security_block_until(minutes: int = SECURITY_BLOCK_MINUTES) -> str:
    until = dt.datetime.utcnow() + dt.timedelta(minutes=max(1, int(minutes)))
    return until.strftime("%Y-%m-%d %H:%M:%S")


def is_super_admin_username(username: str) -> bool:
    return bool(SECURITY_SUPER_ADMIN_USERNAME) and str(username or "").strip().lower() == SECURITY_SUPER_ADMIN_USERNAME


def record_login_attempt(
    username: str,
    success: bool,
    reason: str = "",
    source_ip: str = "",
    user_agent: str = "",
) -> None:
    with _cursor() as (_, cur):
        cur.execute(
            _norm_sql(
                """
                INSERT INTO login_attempts (username, success, reason, source_ip, user_agent, created_at)
                VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                """
            ),
            (
                str(username or "").strip(),
                bool(success) if USE_POSTGRES else (1 if success else 0),
                str(reason or "").strip(),
                str(source_ip or "").strip(),
                str(user_agent or "").strip(),
            ),
        )


def list_login_attempts(
    limit: int = 200,
    username: str = "",
    success: Optional[bool] = None,
    date_from: str = "",
    date_to: str = "",
) -> List[Dict[str, Any]]:
    safe_limit = max(1, min(int(limit), 1000))
    like_op = "ILIKE" if USE_POSTGRES else "LIKE"
    clauses: List[str] = []
    params: List[Any] = []

    if username:
        clauses.append(f"username {like_op} ?")
        params.append(f"%{username.strip()}%")
    if success is not None:
        clauses.append("success = ?")
        params.append(bool(success) if USE_POSTGRES else (1 if success else 0))
    if date_from:
        clauses.append("DATE(created_at) >= ?")
        params.append(date_from.strip())
    if date_to:
        clauses.append("DATE(created_at) <= ?")
        params.append(date_to.strip())

    where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    params.append(safe_limit)
    rows = _fetchall(
        _norm_sql(
            f"""
            SELECT id, username, success, reason, source_ip, user_agent, created_at
            FROM login_attempts
            {where_sql}
            ORDER BY id DESC
            LIMIT ?
            """
        ),
        tuple(params),
    )
    for row in rows:
        row["success"] = bool(row.get("success"))
    return rows


def get_active_security_block(username: str = "", source_ip: str = "") -> Optional[Dict[str, Any]]:
    checks: List[tuple] = []
    if username:
        checks.append(("username", _security_block_value("username", username)))
    if source_ip:
        checks.append(("ip", _security_block_value("ip", source_ip)))
    if not checks:
        return None

    clauses = []
    params: List[Any] = []
    for kind, value in checks:
        clauses.append("(kind = ? AND value = ?)")
        params.extend([kind, value])

    row = _fetchone(
        _norm_sql(
            f"""
            SELECT id, kind, value, reason, blocked_until, created_at, lifted_at, lifted_by
            FROM security_blocks
            WHERE lifted_at IS NULL
              AND blocked_until > CURRENT_TIMESTAMP
              AND ({' OR '.join(clauses)})
            ORDER BY id DESC
            LIMIT 1
            """
        ),
        tuple(params),
    )
    return row


def create_security_block(kind: str, value: str, reason: str, minutes: int = SECURITY_BLOCK_MINUTES) -> Dict[str, Any]:
    clean_kind = "ip" if str(kind).strip().lower() == "ip" else "username"
    clean_value = _security_block_value(clean_kind, value)
    existing = get_active_security_block(
        username=clean_value if clean_kind == "username" else "",
        source_ip=clean_value if clean_kind == "ip" else "",
    )
    if existing and existing.get("kind") == clean_kind and existing.get("value") == clean_value:
        return existing

    blocked_until = _security_block_until(minutes)
    with _cursor() as (_, cur):
        if USE_POSTGRES:
            cur.execute(
                _norm_sql(
                    """
                    INSERT INTO security_blocks (kind, value, reason, blocked_until, created_at)
                    VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
                    RETURNING id
                    """
                ),
                (clean_kind, clean_value, str(reason or "").strip(), blocked_until),
            )
            block_id = int(cur.fetchone()["id"])
        else:
            cur.execute(
                _norm_sql(
                    """
                    INSERT INTO security_blocks (kind, value, reason, blocked_until, created_at)
                    VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
                    """
                ),
                (clean_kind, clean_value, str(reason or "").strip(), blocked_until),
            )
            block_id = int(cur.lastrowid)
    return {
        "id": block_id,
        "kind": clean_kind,
        "value": clean_value,
        "reason": str(reason or "").strip(),
        "blocked_until": blocked_until,
    }


def _count_recent_failed_attempts(kind: str, value: str, window_minutes: int = SECURITY_FAILURE_WINDOW_MINUTES) -> int:
    clean_kind = "ip" if str(kind).strip().lower() == "ip" else "username"
    clean_value = _security_block_value(clean_kind, value)
    if not clean_value:
        return 0

    if USE_POSTGRES:
        field_sql = "LOWER(username)" if clean_kind == "username" else "source_ip"
        query = f"""
            SELECT COUNT(*) AS total
            FROM login_attempts
            WHERE success = FALSE
              AND {field_sql} = ?
              AND created_at >= (CURRENT_TIMESTAMP - (? * INTERVAL '1 minute'))
        """
        row = _fetchone(_norm_sql(query), (clean_value, int(window_minutes)))
    else:
        field_sql = "LOWER(username)" if clean_kind == "username" else "source_ip"
        query = f"""
            SELECT COUNT(*) AS total
            FROM login_attempts
            WHERE success = 0
              AND {field_sql} = ?
              AND created_at >= datetime('now', '-' || ? || ' minutes')
        """
        row = _fetchone(query, (clean_value, int(window_minutes)))
    return int((row or {}).get("total") or 0)


def register_failed_login_attempt(username: str, source_ip: str = "", user_agent: str = "") -> List[Dict[str, Any]]:
    clean_username = str(username or "").strip()
    clean_ip = str(source_ip or "").strip()
    record_login_attempt(clean_username, False, "invalid_credentials", clean_ip, user_agent)

    created: List[Dict[str, Any]] = []
    user_failures = _count_recent_failed_attempts("username", clean_username)
    super_admin_attempt = is_super_admin_username(clean_username)
    if clean_username and not super_admin_attempt and user_failures >= SECURITY_MAX_USER_FAILURES:
        created.append(
            create_security_block(
                "username",
                clean_username,
                f"{user_failures} fallos en {SECURITY_FAILURE_WINDOW_MINUTES} minutos",
            )
        )

    ip_failures = _count_recent_failed_attempts("ip", clean_ip)
    ip_threshold = SECURITY_SUPER_ADMIN_MAX_IP_FAILURES if super_admin_attempt else SECURITY_MAX_IP_FAILURES
    if clean_ip and ip_failures >= ip_threshold:
        created.append(
            create_security_block(
                "ip",
                clean_ip,
                f"{ip_failures} fallos en {SECURITY_FAILURE_WINDOW_MINUTES} minutos",
            )
        )
    return created


def record_security_event(
    event_type: str,
    severity: str = "info",
    username: str = "",
    source_ip: str = "",
    user_agent: str = "",
    detail: str = "",
) -> None:
    with _cursor() as (_, cur):
        cur.execute(
            _norm_sql(
                """
                INSERT INTO security_events (event_type, severity, username, source_ip, user_agent, detail, created_at)
                VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                """
            ),
            (
                str(event_type or "").strip(),
                str(severity or "info").strip().lower(),
                str(username or "").strip(),
                str(source_ip or "").strip(),
                str(user_agent or "").strip(),
                str(detail or "").strip(),
            ),
        )


def list_security_events(
    limit: int = 100,
    severity: str = "",
    username: str = "",
    date_from: str = "",
    date_to: str = "",
) -> List[Dict[str, Any]]:
    safe_limit = max(1, min(int(limit), 1000))
    like_op = "ILIKE" if USE_POSTGRES else "LIKE"
    clauses: List[str] = []
    params: List[Any] = []

    if severity:
        clauses.append("LOWER(severity) = ?")
        params.append(severity.strip().lower())
    if username:
        clauses.append(f"username {like_op} ?")
        params.append(f"%{username.strip()}%")
    if date_from:
        clauses.append("DATE(created_at) >= ?")
        params.append(date_from.strip())
    if date_to:
        clauses.append("DATE(created_at) <= ?")
        params.append(date_to.strip())

    where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    params.append(safe_limit)
    return _fetchall(
        _norm_sql(
            f"""
            SELECT id, event_type, severity, username, source_ip, user_agent, detail, created_at
            FROM security_events
            {where_sql}
            ORDER BY id DESC
            LIMIT ?
            """
        ),
        tuple(params),
    )


def list_security_blocks(active_only: bool = True, limit: int = 200) -> List[Dict[str, Any]]:
    safe_limit = max(1, min(int(limit), 1000))
    where_sql = "WHERE lifted_at IS NULL AND blocked_until > CURRENT_TIMESTAMP" if active_only else ""
    rows = _fetchall(
        _norm_sql(
            f"""
            SELECT id, kind, value, reason, blocked_until, created_at, lifted_at, lifted_by
            FROM security_blocks
            {where_sql}
            ORDER BY id DESC
            LIMIT ?
            """
        ),
        (safe_limit,),
    )
    return rows


def lift_security_block(block_id: int, lifted_by: str = "") -> bool:
    with _cursor() as (_, cur):
        cur.execute(
            _norm_sql(
                """
                UPDATE security_blocks
                SET lifted_at = CURRENT_TIMESTAMP, lifted_by = ?
                WHERE id = ? AND lifted_at IS NULL
                """
            ),
            (str(lifted_by or "").strip(), int(block_id)),
        )
        return bool(cur.rowcount)


def insert_detections(run_id: int, rows: List[Dict[str, Any]]) -> None:
    """Bulk-insert detection points for heatmap persistence."""
    if not rows:
        return
    values = [
        (
            run_id,
            r.get("detect_date", ""),
            r.get("detect_time", ""),
            r.get("lat"),
            r.get("lon"),
            r.get("model", ""),
            r.get("sensor", ""),
            r.get("location", ""),
            r.get("tag", ""),
            r.get("source", ""),
            r.get("frequency", ""),
            r.get("height_m", ""),
        )
        for r in rows
    ]
    with _cursor() as (_, cur):
        cur.executemany(
            _norm_sql(
                """
                INSERT INTO detections
                    (run_id, detect_date, detect_time, lat, lon, model, sensor, location, tag, source, frequency, height_m)
                VALUES
                    (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """
            ),
            values,
        )


def delete_skyeye_run_data_by_input(filename: str, folder: str = "") -> int:
    """Delete heatmap detections and runs associated with a SkyEye input file."""
    filename = Path(filename).name
    folder = Path(folder).name if folder else ""
    if not filename:
        return 0

    if folder:
        pattern = f"%/{folder}/{filename}"
        alt_pattern = f"%\\{folder}\\{filename}"
        params = (pattern, alt_pattern)
        where = "input_detection_csv LIKE ? OR input_detection_csv LIKE ?"
    else:
        pattern = f"%/{filename}"
        alt_pattern = f"%\\{filename}"
        params = (pattern, alt_pattern)
        where = "input_detection_csv LIKE ? OR input_detection_csv LIKE ?"

    with _cursor() as (_, cur):
        cur.execute(_norm_sql(f"SELECT id FROM runs WHERE {where}"), params)
        rows = cur.fetchall()
        run_ids = [int(r["id"] if isinstance(r, dict) else r[0]) for r in rows]
        if not run_ids:
            return 0
        placeholders = ", ".join(["?"] * len(run_ids))
        cur.execute(_norm_sql(f"DELETE FROM detections WHERE run_id IN ({placeholders})"), tuple(run_ids))
        cur.execute(_norm_sql(f"DELETE FROM runs WHERE id IN ({placeholders})"), tuple(run_ids))
        return len(run_ids)


def clear_skyeye_run_data() -> None:
    """Clear SkyEye run history and heatmap detections."""
    with _cursor() as (_, cur):
        cur.execute("DELETE FROM detections")
        cur.execute("DELETE FROM runs")


def insert_septier_detections(rows: List[Dict[str, Any]]) -> None:
    """Bulk-insert Septier detection points."""
    if not rows:
        return
    values = [
        (
            r.get("latitud"),
            r.get("longitud"),
            r.get("imsi_mac", ""),
            r.get("imei", ""),
            r.get("model", ""),
            r.get("operation", ""),
            r.get("orig_lac", ""),
            r.get("cell_id", ""),
            r.get("multipolygon", ""),
            r.get("last_update", ""),
            r.get("event_type", ""),
            r.get("source", ""),
            r.get("archivo_origen", ""),
            r.get("hash_sha256", ""),
            r.get("location", ""),
            r.get("distance"),
            r.get("target_latitude"),
            r.get("target_longitude"),
            r.get("minor_radius_a"),
            r.get("major_radius_a"),
            r.get("minor_radius_b"),
            r.get("major_radius_b"),
            r.get("start_angle"),
            r.get("stop_angle"),
            r.get("orientation"),
        )
        for r in rows
    ]
    with _cursor() as (_, cur):
        cur.executemany(
            _norm_sql(
                """
                INSERT INTO septier_detections
                    (latitud, longitud, imsi_mac, imei, model, operation, orig_lac, cell_id, multipolygon, last_update, event_type, source, archivo_origen, hash_sha256, location, distance, target_latitude, target_longitude, minor_radius_a, major_radius_a, minor_radius_b, major_radius_b, start_angle, stop_angle, orientation)
                VALUES
                    (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """
            ),
            values,
        )
    if USE_POSTGRES:
        _sync_septier_postgis_geometries(
            files=[str(r.get("archivo_origen") or "").strip() for r in rows],
            hashes=[str(r.get("hash_sha256") or "").strip() for r in rows],
            max_multipolygons=max(500, min(len(rows), 2000)),
        )


def upsert_septier_history_metadata(item: Dict[str, Any]) -> Dict[str, Any]:
    source = str(item.get("source") or item.get("system") or "").strip().lower()
    archivo = str(item.get("archivo_origen") or item.get("file") or "").strip()
    if not source or not archivo:
        return {}
    payload = {
        "source": source,
        "archivo_origen": archivo,
        "lugar_operativo": str(item.get("lugar_operativo") or item.get("lugar") or "").strip(),
        "complejo": str(item.get("complejo") or "").strip(),
        "modulo": str(item.get("modulo") or "").strip(),
        "ala": str(item.get("ala") or "").strip(),
        "ubicacion": str(item.get("ubicacion") or "").strip(),
        "coordenadas": str(item.get("coordenadas") or "").strip(),
        "observacion": str(item.get("observacion") or "").strip(),
        "updated_by": str(item.get("updated_by") or "").strip(),
    }
    if USE_POSTGRES:
        sql = """
            INSERT INTO septier_history_metadata
                (source, archivo_origen, lugar_operativo, complejo, modulo, ala, ubicacion, coordenadas, observacion, updated_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (source, archivo_origen) DO UPDATE SET
                lugar_operativo = EXCLUDED.lugar_operativo,
                complejo = EXCLUDED.complejo,
                modulo = EXCLUDED.modulo,
                ala = EXCLUDED.ala,
                ubicacion = EXCLUDED.ubicacion,
                coordenadas = EXCLUDED.coordenadas,
                observacion = EXCLUDED.observacion,
                updated_by = EXCLUDED.updated_by,
                updated_at = CURRENT_TIMESTAMP
        """
    else:
        sql = """
            INSERT INTO septier_history_metadata
                (source, archivo_origen, lugar_operativo, complejo, modulo, ala, ubicacion, coordenadas, observacion, updated_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(source, archivo_origen) DO UPDATE SET
                lugar_operativo = excluded.lugar_operativo,
                complejo = excluded.complejo,
                modulo = excluded.modulo,
                ala = excluded.ala,
                ubicacion = excluded.ubicacion,
                coordenadas = excluded.coordenadas,
                observacion = excluded.observacion,
                updated_by = excluded.updated_by,
                updated_at = CURRENT_TIMESTAMP
        """
    values = (
        payload["source"],
        payload["archivo_origen"],
        payload["lugar_operativo"],
        payload["complejo"],
        payload["modulo"],
        payload["ala"],
        payload["ubicacion"],
        payload["coordenadas"],
        payload["observacion"],
        payload["updated_by"],
    )
    with _cursor() as (_, cur):
        cur.execute(_norm_sql(sql), values)
    return get_septier_history_metadata(source, archivo) or payload


def get_septier_history_metadata(source: str, archivo_origen: str) -> Optional[Dict[str, Any]]:
    return _fetchone(
        """
        SELECT source, archivo_origen, lugar_operativo, complejo, modulo, ala, ubicacion, coordenadas, observacion, updated_by, updated_at
        FROM septier_history_metadata
        WHERE source = ? AND archivo_origen = ?
        """,
        (str(source or "").strip().lower(), str(archivo_origen or "").strip()),
    )


def get_septier_history_metadata_map(files: List[Dict[str, str]]) -> Dict[str, Dict[str, Any]]:
    if not files:
        return {}
    conditions = []
    params: List[str] = []
    for item in files:
        source = str(item.get("system") or item.get("source") or "").strip().lower()
        archivo = str(item.get("file") or item.get("archivo_origen") or "").strip()
        if not source or not archivo:
            continue
        conditions.append("(source = ? AND archivo_origen = ?)")
        params.extend([source, archivo])
    if not conditions:
        return {}
    rows = _fetchall(
        f"""
        SELECT source, archivo_origen, lugar_operativo, complejo, modulo, ala, ubicacion, coordenadas, observacion, updated_by, updated_at
        FROM septier_history_metadata
        WHERE {' OR '.join(conditions)}
        """,
        tuple(params),
    )
    return {f"{str(r.get('source') or '').lower()}|{str(r.get('archivo_origen') or '')}": dict(r) for r in rows}


def delete_septier_history_metadata(source: str, archivo_origen: str) -> None:
    with _cursor() as (_, cur):
        cur.execute(
            _norm_sql("DELETE FROM septier_history_metadata WHERE source = ? AND archivo_origen = ?"),
            (str(source or "").strip().lower(), str(archivo_origen or "").strip()),
        )


def list_septier_history_schema() -> List[Dict[str, Any]]:
    rows = _fetchall(
        """
        SELECT field, title, position, selected, source_filename, updated_at
        FROM septier_history_schema
        ORDER BY position ASC, field ASC
        """
    )
    return [
        {
            "field": str(r.get("field") or ""),
            "title": str(r.get("title") or ""),
            "position": int(r.get("position") or 0),
            "selected": bool(r.get("selected")),
            "source_filename": str(r.get("source_filename") or ""),
            "updated_at": r.get("updated_at"),
        }
        for r in rows
    ]


def replace_septier_history_schema(items: List[Dict[str, Any]], source_filename: str = "") -> int:
    selected_fields = {
        str(r.get("field") or "").strip()
        for r in _fetchall("SELECT field FROM septier_history_schema WHERE selected = ?", (True if USE_POSTGRES else 1,))
        if str(r.get("field") or "").strip()
    }
    values = []
    seen = set()
    for idx, item in enumerate(items, start=1):
        field = str(item.get("field") or "").strip()
        if not field or field in seen:
            continue
        seen.add(field)
        values.append((
            field,
            str(item.get("title") or field).strip(),
            int(item.get("position") or idx),
            (field in selected_fields) if USE_POSTGRES else (1 if field in selected_fields else 0),
            source_filename.strip(),
        ))
    with _cursor() as (_, cur):
        cur.execute("DELETE FROM septier_history_schema")
        if values:
            cur.executemany(
                _norm_sql(
                    """
                    INSERT INTO septier_history_schema
                        (field, title, position, selected, source_filename, updated_at)
                    VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                    """
                ),
                values,
            )
    return len(values)


def update_septier_history_schema_selection(fields: List[str]) -> int:
    selected = {str(f).strip() for f in fields if str(f).strip()}
    with _cursor() as (_, cur):
        cur.execute(
            _norm_sql("UPDATE septier_history_schema SET selected = ?, updated_at = CURRENT_TIMESTAMP"),
            (False if USE_POSTGRES else 0,),
        )
        if selected:
            placeholders = ", ".join(["?"] * len(selected))
            cur.execute(
                _norm_sql(
                    f"""
                    UPDATE septier_history_schema
                    SET selected = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE field IN ({placeholders})
                    """
                ),
                (True if USE_POSTGRES else 1, *tuple(selected)),
            )
    return len(selected)


def _norm_network_code(value: Any, width: int = 0) -> str:
    text = str(value or "").strip()
    if text.endswith(".0"):
        text = text[:-2]
    text = text.replace(" ", "")
    if text.isdigit() and width:
        return text.zfill(width)
    return text


def replace_septier_network_refs(items: List[Dict[str, Any]], source_type: str, source_filename: str = "") -> int:
    clean_source_type = str(source_type or "").strip() or "manual"
    values = []
    seen = set()
    for item in items:
        mcc = _norm_network_code(item.get("mcc"), 3)
        mnc = _norm_network_code(item.get("mnc"))
        if not mcc or not mnc:
            continue
        key = (mcc, mnc, clean_source_type)
        if key in seen:
            continue
        seen.add(key)
        values.append(
            (
                mcc,
                mnc,
                str(item.get("network_name") or item.get("name") or "").strip(),
                clean_source_type,
                str(source_filename or item.get("source_filename") or "").strip(),
                str(item.get("external_id") or item.get("id") or "").strip(),
                str(item.get("session_id") or "").strip(),
                str(item.get("when_created") or "").strip(),
            )
        )
    with _cursor() as (_, cur):
        cur.execute(_norm_sql("DELETE FROM septier_network_refs WHERE source_type = ?"), (clean_source_type,))
        if values:
            cur.executemany(
                _norm_sql(
                    """
                    INSERT INTO septier_network_refs
                        (mcc, mnc, network_name, source_type, source_filename, external_id, session_id, when_created, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                    """
                ),
                values,
            )
    return len(values)


def list_septier_network_refs(
    q: str = "",
    mcc: str = "",
    mnc: str = "",
    source_type: str = "",
    limit: int = 500,
) -> List[Dict[str, Any]]:
    safe_limit = max(1, min(int(limit), 5000))
    like_op = "ILIKE" if USE_POSTGRES else "LIKE"
    clauses: List[str] = []
    params: List[Any] = []
    if q:
        clauses.append(f"(network_name {like_op} ? OR mcc {like_op} ? OR mnc {like_op} ?)")
        needle = f"%{q.strip()}%"
        params.extend([needle, needle, needle])
    if mcc:
        clauses.append("mcc = ?")
        params.append(_norm_network_code(mcc, 3))
    if mnc:
        clauses.append("mnc = ?")
        params.append(_norm_network_code(mnc))
    if source_type:
        clauses.append("source_type = ?")
        params.append(source_type.strip())
    where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    params.append(safe_limit)
    return _fetchall(
        _norm_sql(
            f"""
            SELECT id, mcc, mnc, network_name, source_type, source_filename, external_id, session_id, when_created, updated_at
            FROM septier_network_refs
            {where_sql}
            ORDER BY mcc ASC, mnc ASC, source_type ASC
            LIMIT ?
            """
        ),
        tuple(params),
    )


def replace_septier_rf_bands(items: List[Dict[str, Any]], source_filename: str = "") -> int:
    values = []
    seen = set()
    for item in items:
        rx_type = str(item.get("rx_type") or "").strip().upper()
        band = str(item.get("band") or "").strip()
        if rx_type not in {"RX_M", "RX_S"} or not band:
            continue
        key = (rx_type, band)
        if key in seen:
            continue
        seen.add(key)
        values.append(
            (
                rx_type,
                band,
                str(item.get("label") or "").strip(),
                str(item.get("frequency") or "").strip(),
                str(item.get("command") or "").strip(),
                str(source_filename or item.get("source_filename") or "").strip(),
            )
        )
    with _cursor() as (_, cur):
        cur.execute("DELETE FROM septier_rf_bands")
        if values:
            cur.executemany(
                _norm_sql(
                    """
                    INSERT INTO septier_rf_bands
                        (rx_type, band, label, frequency, command, source_filename, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                    """
                ),
                values,
            )
    return len(values)


def list_septier_rf_bands(limit: int = 500) -> List[Dict[str, Any]]:
    safe_limit = max(1, min(int(limit), 1000))
    return _fetchall(
        _norm_sql(
            """
            SELECT id, rx_type, band, label, frequency, command, source_filename, updated_at
            FROM septier_rf_bands
            ORDER BY band ASC, rx_type ASC
            LIMIT ?
            """
        ),
        (safe_limit,),
    )


def query_heatmap(
    date_from: str = "",
    date_to: str = "",
    sensor: str = "",
    model: str = "",
    location: str = "",
    source: str = "",
) -> List[Dict[str, Any]]:
    clauses = ["lat IS NOT NULL", "lon IS NOT NULL", "lat != 0", "lon != 0"]
    params: List[Any] = []
    if date_from:
        clauses.append("detect_date >= ?")
        params.append(date_from)
    if date_to:
        clauses.append("detect_date <= ?")
        params.append(date_to)
    like_op = "ILIKE" if USE_POSTGRES else "LIKE"
    if sensor:
        clauses.append(f"sensor {like_op} ?")
        params.append(f"%{sensor}%")
    if model:
        clauses.append(f"model {like_op} ?")
        params.append(f"%{model}%")
    if location:
        clauses.append(f"location {like_op} ?")
        params.append(f"%{location}%")
    if source:
        clauses.append(f"source {like_op} ?")
        params.append(f"%{source}%")

    where = " AND ".join(clauses)
    rows = _fetchall(
        f"SELECT lat, lon, model, sensor, location, tag, source, detect_date FROM detections WHERE {where} ORDER BY detect_date DESC",
        tuple(params),
    )
    return rows


def query_septier_heatmap(
    date_from: str = "",
    date_to: str = "",
    source: str = "",
    model: str = "",
    location: str = "",
) -> List[Dict[str, Any]]:
    """Devuelve centroides de Multipolygon para el mapa Septier.

    En Septier, latitud/longitud representan el punto operativo del equipo.
    Para detecciones en mapa se usa Multipolygon y se calcula centroide; si no hay
    Multipolygon valido, la fila no se muestra como deteccion del dispositivo.
    """
    clauses = ["multipolygon IS NOT NULL", "multipolygon != ''"]
    params: List[Any] = []
    if date_from:
        clauses.append("DATE(last_update) >= ?")
        params.append(date_from)
    if date_to:
        clauses.append("DATE(last_update) <= ?")
        params.append(date_to)
    if source:
        clauses.append("source = ?")
        params.append(source.lower())
    like_op = "ILIKE" if USE_POSTGRES else "LIKE"
    if location:
        clauses.append(f"location {like_op} ?")
        params.append(f"%{location}%")
    if model:
        clauses.append(f"model {like_op} ?")
        params.append(f"%{model}%")

    where = " AND ".join(clauses)
    sql = f"""
        SELECT * FROM (
            SELECT *,
                COALESCE(imsi_mac, imei, '') as unique_id,
                DATE(last_update) as day,
                ROW_NUMBER() OVER (
                    PARTITION BY COALESCE(imsi_mac, imei, ''), DATE(last_update)
                    ORDER BY last_update ASC, id ASC
                ) as rn
            FROM septier_detections
            WHERE {where}
        ) t
        WHERE rn = 1
        ORDER BY last_update DESC
    """
    rows = _fetchall(sql, tuple(params))
    
    wl_rows = _fetchall("SELECT device_id FROM whitelist_devices")
    whitelist = set()
    for item in wl_rows:
        whitelist.update(_identity_keys(item.get("device_id")))
    
    out: List[Dict[str, Any]] = []
    for r in rows:
        area_lat, area_lon = "", ""
        try:
            from shapely import wkt as _shapely_wkt  # type: ignore
            geom = _shapely_wkt.loads(str(r.get("multipolygon") or ""))
            centroid = geom.centroid
            area_lat = round(float(centroid.y), 6)
            area_lon = round(float(centroid.x), 6)
        except Exception:
            area_lat, area_lon = "", ""
        if area_lat == "" or area_lon == "":
            continue
        out.append(
            {
                "lat": area_lat,
                "lon": area_lon,
                "model": r.get("model", ""),
                "source": r.get("source", "septier"),
                "operation": r.get("operation", ""),
                "orig_lac": r.get("orig_lac", ""),
                "cell_id": r.get("cell_id", ""),
                "imsi_mac": r.get("imsi_mac", ""),
                "imei": r.get("imei", ""),
                "last_update": r.get("last_update", ""),
                "distance": r.get("distance", ""),
                "target_latitude": r.get("target_latitude", ""),
                "target_longitude": r.get("target_longitude", ""),
                "minor_radius_a": r.get("minor_radius_a", ""),
                "major_radius_a": r.get("major_radius_a", ""),
                "minor_radius_b": r.get("minor_radius_b", ""),
                "major_radius_b": r.get("major_radius_b", ""),
                "start_angle": r.get("start_angle", ""),
                "stop_angle": r.get("stop_angle", ""),
                "orientation": r.get("orientation", ""),
                "location": r.get("location", ""),
                "geometry_source": "multipolygon_centroid",
                "multipolygon": r.get("multipolygon", ""),
                "operator_lat": r.get("latitud", ""),
                "operator_lon": r.get("longitud", ""),
                "is_whitelisted": _is_whitelisted_identity(r.get("imsi_mac", ""), r.get("imei", ""), whitelist),
            }
        )
    return out


def search_septier_detections(query: str, limit: int = 100) -> List[Dict[str, Any]]:
    if not query.strip():
        return []
    
    like_op = "ILIKE" if USE_POSTGRES else "LIKE"
    search_term = f"%{query.strip()}%"
    
    sql = f"""
        SELECT latitud as lat, longitud as lon, imsi_mac, imei, model, operation, orig_lac, cell_id, last_update, event_type, source, archivo_origen, hash_sha256
        FROM septier_detections
        WHERE imsi_mac {like_op} ? 
           OR imei {like_op} ? 
           OR model {like_op} ? 
           OR operation {like_op} ?
           OR orig_lac {like_op} ?
           OR cell_id {like_op} ?
        ORDER BY last_update DESC
        LIMIT ?
    """
    rows = _fetchall(sql, (search_term, search_term, search_term, search_term, search_term, search_term, limit))
    return [dict(r) for r in rows]


def get_septier_file_stats(filename: str, source: str) -> Dict[str, Any]:
    sql = """
        SELECT latitud as lat, longitud as lon, imsi_mac, imei, model, operation, orig_lac, cell_id, last_update, event_type, source, archivo_origen, hash_sha256
        FROM septier_detections
        WHERE archivo_origen = ? AND source = ?
        ORDER BY last_update DESC
    """
    rows = _fetchall(sql, (filename, source))
    
    wl_rows = _fetchall("SELECT device_id FROM whitelist_devices")
    whitelist = set()
    for item in wl_rows:
        whitelist.update(_identity_keys(item.get("device_id")))
    
    unique_imsi = set()
    unique_imei = set()
    whitelisted_devices = set()
    for r in rows:
        imsi = str(r.get("imsi_mac") or "").strip()
        imei = str(r.get("imei") or "").strip()
        if imsi: unique_imsi.add(imsi)
        if imei: unique_imei.add(imei)
        
        is_wl = _is_whitelisted_identity(imsi, imei, whitelist)
        r["is_whitelisted"] = is_wl
        
        dev_id = imsi if imsi else imei
        if dev_id and is_wl:
            whitelisted_devices.add(dev_id)

    return {
        "total": len(rows),
        "unique_imsi": len(unique_imsi),
        "unique_imei": len(unique_imei),
        "whitelisted_imsi": len([imsi for imsi in unique_imsi if _identity_keys(imsi) & whitelist]),
        "whitelisted_imei": len([imei for imei in unique_imei if _identity_keys(imei) & whitelist]),
        "whitelisted_devices": len(whitelisted_devices),
        "rows": rows
    }


def get_septier_detections_by_files(files: List[Dict[str, str]]) -> List[Dict[str, Any]]:
    if not files:
        return []
    conditions = []
    params = []
    for f in files:
        conditions.append("(source = ? AND archivo_origen = ?)")
        params.extend([str(f.get("system", "")).lower(), str(f.get("file", ""))])
    
    where_sql = " OR ".join(conditions)
    sql = f"""
        SELECT latitud as lat, longitud as lon, imsi_mac, imei, model, operation, orig_lac, cell_id, last_update, event_type, source, archivo_origen
        FROM septier_detections
        WHERE {where_sql}
        ORDER BY last_update DESC
    """
    return _fetchall(sql, tuple(params))


def get_septier_forensic_rows_by_files(files: List[Dict[str, str]]) -> List[Dict[str, Any]]:
    if not files:
        return []
    conditions = []
    params = []
    for f in files:
        conditions.append("(source = ? AND archivo_origen = ?)")
        params.extend([str(f.get("system", "")).lower(), str(f.get("file", ""))])

    where_sql = " OR ".join(conditions)
    sql = f"""
        SELECT latitud, longitud, imsi_mac, imei, model, operation, orig_lac, cell_id, multipolygon, last_update, event_type, source, archivo_origen, hash_sha256
        FROM septier_detections
        WHERE {where_sql}
        ORDER BY last_update ASC
    """
    return _fetchall(sql, tuple(params))


def list_septier_uploaded_files_from_db() -> List[Dict[str, Any]]:
    sql = """
        SELECT
            LOWER(source) AS source,
            archivo_origen,
            COUNT(*) AS filas_leidas,
            MIN(last_update) AS primera_deteccion,
            MAX(last_update) AS ultima_deteccion,
            MAX(hash_sha256) AS hash_sha256
        FROM septier_detections
        WHERE LOWER(source) IN ('guardian', 'backpack')
          AND archivo_origen IS NOT NULL
          AND archivo_origen != ''
        GROUP BY LOWER(source), archivo_origen
        ORDER BY MAX(last_update) DESC, archivo_origen DESC
    """
    return _fetchall(sql)


def get_septier_identity_history() -> List[Dict[str, Any]]:
    sql = """
        SELECT imsi_mac, imei, last_update, source, archivo_origen
        FROM septier_detections
        WHERE (imsi_mac IS NOT NULL AND imsi_mac != '')
           OR (imei IS NOT NULL AND imei != '')
        ORDER BY last_update ASC
    """
    return _fetchall(sql)


def query_heatmap_filters() -> Dict[str, List[str]]:
    sensors = [
        r["sensor"]
        for r in _fetchall(
            "SELECT DISTINCT sensor FROM detections WHERE sensor IS NOT NULL AND sensor != '' ORDER BY sensor"
        )
    ]
    models = [
        r["model"]
        for r in _fetchall(
            "SELECT DISTINCT model FROM detections WHERE model IS NOT NULL AND model != '' ORDER BY model"
        )
    ]
    locations = [
        r["location"]
        for r in _fetchall(
            "SELECT DISTINCT location FROM detections WHERE location IS NOT NULL AND location != '' ORDER BY location"
        )
    ]
    sources = [
        r["source"]
        for r in _fetchall(
            "SELECT DISTINCT source FROM detections WHERE source IS NOT NULL AND source != '' ORDER BY source"
        )
    ]
    return {"sensors": sensors, "models": models, "locations": locations, "sources": sources}


def insert_run(payload: Dict[str, Any]) -> int:
    params = (
        payload["created_at"],
        payload["input_detection_csv"],
        payload.get("input_trajectory_csv"),
        payload["output_dir"],
        payload.get("html_report"),
        payload.get("tracks_kml"),
        payload.get("last_seen_kml"),
        payload.get("geo_txt_report"),
        payload.get("m3t_kml"),
        payload.get("drones_commands_file"),
        payload["status"],
        payload.get("message"),
        json.dumps(payload.get("m3t_summary", {}), ensure_ascii=False),
    )
    with _cursor() as (_, cur):
        if USE_POSTGRES:
            cur.execute(
                _norm_sql(
                    """
                    INSERT INTO runs (
                        created_at,
                        input_detection_csv,
                        input_trajectory_csv,
                        output_dir,
                        html_report,
                        tracks_kml,
                        last_seen_kml,
                        geo_txt_report,
                        m3t_kml,
                        drones_commands_file,
                        status,
                        message,
                        m3t_summary_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    RETURNING id
                    """
                ),
                params,
            )
            return int(cur.fetchone()["id"])

        cur.execute(
            _norm_sql(
                """
                INSERT INTO runs (
                    created_at,
                    input_detection_csv,
                    input_trajectory_csv,
                    output_dir,
                    html_report,
                    tracks_kml,
                    last_seen_kml,
                    geo_txt_report,
                    m3t_kml,
                    drones_commands_file,
                    status,
                    message,
                    m3t_summary_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """
            ),
            params,
        )
        return int(cur.lastrowid)


def list_runs() -> List[Dict[str, Any]]:
    rows = _fetchall("SELECT * FROM runs ORDER BY id DESC")
    return [_row_to_dict(row) for row in rows]


def get_run(run_id: int) -> Optional[Dict[str, Any]]:
    row = _fetchone("SELECT * FROM runs WHERE id = ?", (run_id,))
    if row is None:
        return None
    return _row_to_dict(row)


def _row_to_dict(row: Dict[str, Any]) -> Dict[str, Any]:
    item = dict(row)
    item["m3t_summary"] = json.loads(item["m3t_summary_json"] or "{}")
    item.pop("m3t_summary_json", None)
    return item


def cleanup_whitelist_identifiers() -> Dict[str, int]:
    normalized = 0
    removed = 0
    with _cursor() as (_, cur):
        cur.execute(_norm_sql("SELECT device_id, device_type, description FROM whitelist_devices"))
        rows = [dict(r) for r in cur.fetchall()]
        for row in rows:
            current = str(row.get("device_id") or "").strip()
            cleaned = _clean_whitelist_device_id(current, row.get("device_type"))
            if cleaned == current:
                continue
            if not cleaned:
                cur.execute(_norm_sql("DELETE FROM whitelist_devices WHERE device_id = ?"), (current,))
                cur.execute(_norm_sql("DELETE FROM whitelist_upload_items WHERE device_id = ?"), (current,))
                removed += 1
                continue
            description = str(row.get("description") or "").strip()
            if current not in description:
                description = (description + " - " if description else "") + f"ID original informado {current}"
            if USE_POSTGRES:
                cur.execute(
                    _norm_sql(
                        """
                        INSERT INTO whitelist_devices (device_id, device_type, description)
                        VALUES (?, ?, ?)
                        ON CONFLICT (device_id) DO UPDATE SET description = EXCLUDED.description
                        """
                    ),
                    (cleaned, str(row.get("device_type") or "").strip(), description),
                )
            else:
                cur.execute(
                    _norm_sql(
                        """
                        INSERT OR REPLACE INTO whitelist_devices (device_id, device_type, description)
                        VALUES (?, ?, ?)
                        """
                    ),
                    (cleaned, str(row.get("device_type") or "").strip(), description),
                )
            cur.execute(_norm_sql("UPDATE whitelist_upload_items SET device_id = ? WHERE device_id = ?"), (cleaned, current))
            cur.execute(_norm_sql("DELETE FROM whitelist_devices WHERE device_id = ?"), (current,))
            normalized += 1
    return {"normalized": normalized, "removed": removed}


def list_whitelist() -> List[Dict[str, Any]]:
    cleanup_whitelist_identifiers()
    return _fetchall("SELECT * FROM whitelist_devices ORDER BY created_at DESC")


def insert_whitelist_items(items: List[Dict[str, str]]) -> None:
    if not items:
        return
    with _cursor() as (_, cur):
        for item in items:
            device_type = str(item.get("device_type", "")).strip()
            device_id = _clean_whitelist_device_id(item.get("device_id", ""), device_type)
            description = str(item.get("description", "")).strip()
            if not device_id:
                continue
            if USE_POSTGRES:
                cur.execute(
                    _norm_sql("INSERT INTO whitelist_devices (device_id, device_type, description) VALUES (?, ?, ?) ON CONFLICT (device_id) DO UPDATE SET description = EXCLUDED.description"),
                    (device_id, device_type, description)
                )
            else:
                cur.execute(
                    _norm_sql("INSERT OR REPLACE INTO whitelist_devices (device_id, device_type, description) VALUES (?, ?, ?)"),
                    (device_id, device_type, description)
                )


def clear_whitelist() -> None:
    with _cursor() as (_, cur):
        cur.execute("DELETE FROM whitelist_devices")


def whitelist_existing_ids(device_ids: List[str]) -> set:
    ids = [str(d).strip() for d in device_ids if str(d).strip()]
    if not ids:
        return set()
    out = set()
    chunk_size = 500
    with _cursor() as (_, cur):
        for i in range(0, len(ids), chunk_size):
            chunk = ids[i:i + chunk_size]
            placeholders = ", ".join(["?"] * len(chunk))
            cur.execute(_norm_sql(f"SELECT device_id FROM whitelist_devices WHERE device_id IN ({placeholders})"), tuple(chunk))
            out.update(str(r["device_id"]).strip() for r in cur.fetchall())
    return out


def whitelist_matches_for_ids(device_ids: List[str]) -> List[Dict[str, Any]]:
    ids = sorted({str(d).strip() for d in device_ids if str(d).strip()})
    if not ids:
        return []
    rows: List[Dict[str, Any]] = []
    chunk_size = 500
    with _cursor() as (_, cur):
        for i in range(0, len(ids), chunk_size):
            chunk = ids[i:i + chunk_size]
            placeholders = ", ".join(["?"] * len(chunk))
            cur.execute(
                _norm_sql(
                    f"""
                    SELECT
                        wd.device_id,
                        wd.device_type,
                        wd.description,
                        wu.id AS upload_id,
                        wu.original_filename,
                        wi.existed_before
                    FROM whitelist_devices wd
                    LEFT JOIN whitelist_upload_items wi ON wi.device_id = wd.device_id
                    LEFT JOIN whitelist_uploads wu ON wu.id = wi.upload_id AND wu.deleted_at IS NULL
                    WHERE wd.device_id IN ({placeholders})
                    ORDER BY CASE WHEN wu.id IS NULL THEN 1 ELSE 0 END, wu.id DESC, wd.device_id
                    """
                ),
                tuple(chunk),
            )
            rows.extend(dict(r) for r in cur.fetchall())
    return rows


def insert_whitelist_upload(
    original_filename: str,
    stored_filename: str,
    stored_path: str,
    uploaded_by: str,
    replace_mode: bool,
    rows_count: int,
    device_ids: List[str],
    existed_before: set,
) -> int:
    unique_ids = sorted({str(d).strip() for d in device_ids if str(d).strip()})
    with _cursor() as (_, cur):
        if USE_POSTGRES:
            cur.execute(
                _norm_sql(
                    """
                    INSERT INTO whitelist_uploads
                        (original_filename, stored_filename, stored_path, uploaded_by, replace_mode, rows_count, unique_count, inserted_count)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    RETURNING id
                    """
                ),
                (
                    original_filename,
                    stored_filename,
                    stored_path,
                    uploaded_by,
                    replace_mode,
                    rows_count,
                    len(unique_ids),
                    len([d for d in unique_ids if d not in existed_before]),
                ),
            )
            upload_id = int(cur.fetchone()["id"])
        else:
            cur.execute(
                _norm_sql(
                    """
                    INSERT INTO whitelist_uploads
                        (original_filename, stored_filename, stored_path, uploaded_by, replace_mode, rows_count, unique_count, inserted_count)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """
                ),
                (
                    original_filename,
                    stored_filename,
                    stored_path,
                    uploaded_by,
                    1 if replace_mode else 0,
                    rows_count,
                    len(unique_ids),
                    len([d for d in unique_ids if d not in existed_before]),
                ),
            )
            upload_id = int(cur.lastrowid)

        cur.executemany(
            _norm_sql(
                """
                INSERT INTO whitelist_upload_items (upload_id, device_id, existed_before)
                VALUES (?, ?, ?)
                """
            ),
            [(upload_id, device_id, device_id in existed_before) for device_id in unique_ids],
        )
        return upload_id


def list_whitelist_uploads(limit: int = 100) -> List[Dict[str, Any]]:
    return _fetchall(
        """
        SELECT id, original_filename, stored_filename, uploaded_by, replace_mode, rows_count,
               unique_count, inserted_count, deleted_at, created_at
        FROM whitelist_uploads
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,),
    )


def get_whitelist_upload(upload_id: int) -> Optional[Dict[str, Any]]:
    return _fetchone("SELECT * FROM whitelist_uploads WHERE id = ?", (upload_id,))


def delete_whitelist_upload(upload_id: int) -> Dict[str, int]:
    with _cursor() as (_, cur):
        cur.execute(_norm_sql("SELECT device_id, existed_before FROM whitelist_upload_items WHERE upload_id = ?"), (upload_id,))
        rows = cur.fetchall()
        device_ids = [str(r["device_id"]).strip() for r in rows if str(r["device_id"]).strip()]
        removable = [str(r["device_id"]).strip() for r in rows if str(r["device_id"]).strip() and not bool(r["existed_before"])]

        removed = 0
        if removable:
            placeholders = ", ".join(["?"] * len(removable))
            cur.execute(
                _norm_sql(
                    f"""
                    SELECT DISTINCT device_id
                    FROM whitelist_upload_items wi
                    JOIN whitelist_uploads wu ON wu.id = wi.upload_id
                    WHERE wi.upload_id != ?
                      AND wu.deleted_at IS NULL
                      AND wi.device_id IN ({placeholders})
                    """
                ),
                tuple([upload_id, *removable]),
            )
            protected = {str(r["device_id"]).strip() for r in cur.fetchall()}
            final_remove = [d for d in removable if d not in protected]
            if final_remove:
                placeholders = ", ".join(["?"] * len(final_remove))
                cur.execute(_norm_sql(f"DELETE FROM whitelist_devices WHERE device_id IN ({placeholders})"), tuple(final_remove))
                removed = len(final_remove)

        cur.execute(_norm_sql("UPDATE whitelist_uploads SET deleted_at = CURRENT_TIMESTAMP WHERE id = ?"), (upload_id,))
        return {"items": len(device_ids), "removed": removed}


def delete_whitelist_item(device_id: str) -> None:
    with _cursor() as (_, cur):
        cur.execute(_norm_sql("DELETE FROM whitelist_devices WHERE device_id = ?"), (device_id,))


def insert_external_identity_upload(
    original_filename: str,
    stored_filename: str,
    stored_path: str,
    uploaded_by: str,
    hash_sha256: str,
    rows: List[Dict[str, str]],
) -> int:
    clean_rows = []
    for row in rows:
        imsi = str(row.get("imsi") or "").strip()
        imei = str(row.get("imei") or "").strip()
        if not imsi and not imei:
            continue
        clean_rows.append({
            "imsi": imsi,
            "imei": imei,
            "prestataria": str(row.get("prestataria") or "").strip().upper(),
            "estado": str(row.get("estado") or "").strip().upper(),
            "modelo": str(row.get("modelo") or "").strip(),
        })
    unique_imsi = {r["imsi"] for r in clean_rows if r["imsi"]}
    unique_imei = {r["imei"] for r in clean_rows if r["imei"]}
    with _cursor() as (_, cur):
        if USE_POSTGRES:
            cur.execute(
                _norm_sql(
                    """
                    INSERT INTO external_identity_uploads
                        (original_filename, stored_filename, stored_path, uploaded_by, hash_sha256, rows_count, unique_imsi_count, unique_imei_count)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    RETURNING id
                    """
                ),
                (original_filename, stored_filename, stored_path, uploaded_by, hash_sha256, len(clean_rows), len(unique_imsi), len(unique_imei)),
            )
            upload_id = int(cur.fetchone()["id"])
        else:
            cur.execute(
                _norm_sql(
                    """
                    INSERT INTO external_identity_uploads
                        (original_filename, stored_filename, stored_path, uploaded_by, hash_sha256, rows_count, unique_imsi_count, unique_imei_count)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """
                ),
                (original_filename, stored_filename, stored_path, uploaded_by, hash_sha256, len(clean_rows), len(unique_imsi), len(unique_imei)),
            )
            upload_id = int(cur.lastrowid)
        cur.executemany(
            _norm_sql(
                """
                INSERT INTO external_identity_data
                    (upload_id, imsi, imei, prestataria, estado, modelo, source_filename, hash_sha256)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """
            ),
            [
                (
                    upload_id,
                    row["imsi"],
                    row["imei"],
                    row["prestataria"],
                    row["estado"],
                    row["modelo"],
                    original_filename,
                    hash_sha256,
                )
                for row in clean_rows
            ],
        )
        return upload_id


def list_external_identity_uploads(limit: int = 100) -> List[Dict[str, Any]]:
    return _fetchall(
        """
        SELECT id, original_filename, stored_filename, uploaded_by, hash_sha256,
               rows_count, unique_imsi_count, unique_imei_count, created_at
        FROM external_identity_uploads
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,),
    )


def list_external_identity_data(limit: int = 100, q: str = "", upload_ids: Optional[List[int]] = None) -> List[Dict[str, Any]]:
    params: List[Any] = []
    clauses: List[str] = []
    if q.strip():
        like_op = "ILIKE" if USE_POSTGRES else "LIKE"
        clauses.append(f"(imsi {like_op} ? OR imei {like_op} ? OR prestataria {like_op} ? OR modelo {like_op} ?)")
        needle = f"%{q.strip()}%"
        params.extend([needle, needle, needle, needle])
    clean_upload_ids = [int(upload_id) for upload_id in (upload_ids or []) if str(upload_id).strip().isdigit()]
    if clean_upload_ids:
        placeholders = ", ".join(["?"] * len(clean_upload_ids))
        clauses.append(f"upload_id IN ({placeholders})")
        params.extend(clean_upload_ids)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    params.append(limit)
    return _fetchall(
        f"""
        SELECT id, upload_id, imsi, imei, prestataria, estado, modelo, source_filename, hash_sha256, created_at
        FROM external_identity_data
        {where}
        ORDER BY id DESC
        LIMIT ?
        """,
        tuple(params),
    )


def external_identity_lookup(imsi: object, imei: object, upload_ids: Optional[List[int]] = None) -> List[Dict[str, Any]]:
    imsi_digits = re.sub(r"\D+", "", str(imsi or ""))
    imei_digits = re.sub(r"\D+", "", str(imei or ""))
    clauses = []
    params: List[Any] = []
    if len(imsi_digits) == 15:
        clauses.append("imsi = ?")
        params.append(imsi_digits)
    if len(imei_digits) == 15:
        clauses.append("imei = ?")
        params.append(imei_digits)
    if not clauses:
        return []
    clean_upload_ids = [int(upload_id) for upload_id in (upload_ids or []) if str(upload_id).strip().isdigit()]
    upload_clause = ""
    if clean_upload_ids:
        placeholders = ", ".join(["?"] * len(clean_upload_ids))
        upload_clause = f" AND upload_id IN ({placeholders})"
        params.extend(clean_upload_ids)
    return _fetchall(
        f"""
        SELECT id, upload_id, imsi, imei, prestataria, estado, modelo, source_filename, hash_sha256, created_at
        FROM external_identity_data
        WHERE ({" OR ".join(clauses)}){upload_clause}
        ORDER BY id DESC
        LIMIT 20
        """,
        tuple(params),
    )


def delete_external_identity_upload(upload_id: int) -> Dict[str, Any]:
    with _cursor() as (_, cur):
        cur.execute(_norm_sql("SELECT stored_path FROM external_identity_uploads WHERE id = ?"), (upload_id,))
        row = cur.fetchone()
        if not row:
            return {"deleted": False, "rows": 0, "stored_path": ""}
        stored_path = row["stored_path"] if isinstance(row, dict) else row[0]
        cur.execute(_norm_sql("DELETE FROM external_identity_data WHERE upload_id = ?"), (upload_id,))
        rows_deleted = cur.rowcount if cur.rowcount is not None else 0
        cur.execute(_norm_sql("DELETE FROM external_identity_uploads WHERE id = ?"), (upload_id,))
        return {"deleted": True, "rows": rows_deleted, "stored_path": stored_path or ""}


def list_tower_catalog(
    provider: str = "",
    lac: str = "",
    cell_id: str = "",
    limit: int = 500,
    with_coords_only: bool = False,
) -> List[Dict[str, Any]]:
    clauses = []
    params: List[Any] = []
    like_op = "ILIKE" if USE_POSTGRES else "LIKE"
    if provider:
        clauses.append(f"provider {like_op} ?")
        params.append(f"%{provider.strip()}%")
    if lac:
        clauses.append("lac = ?")
        params.append(str(lac).strip())
    if cell_id:
        clauses.append("cell_id = ?")
        params.append(str(cell_id).strip())
    if with_coords_only:
        clauses.extend(["lat IS NOT NULL", "lon IS NOT NULL"])
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    params.append(max(1, min(int(limit or 500), 5000)))
    return _fetchall(
        f"""
        SELECT id, provider, mcc, mnc, lac, cell_id, lat, lon, source, notes, created_at
        FROM tower_catalog
        {where}
        ORDER BY provider, lac, cell_id
        LIMIT ?
        """,
        tuple(params),
    )


def upsert_tower_catalog(items: List[Dict[str, Any]]) -> int:
    if not items:
        return 0
    inserted = 0
    with _cursor() as (_, cur):
        for item in items:
            provider = str(item.get("provider") or "").strip()
            lac = str(item.get("lac") or "").strip()
            cell_id = str(item.get("cell_id") or "").strip()
            if not lac or not cell_id:
                continue
            values = (
                provider,
                str(item.get("mcc") or "").strip(),
                str(item.get("mnc") or "").strip(),
                lac,
                cell_id,
                item.get("lat"),
                item.get("lon"),
                str(item.get("source") or "").strip(),
                str(item.get("notes") or "").strip(),
            )
            if USE_POSTGRES:
                cur.execute(
                    _norm_sql(
                        """
                        INSERT INTO tower_catalog
                            (provider, mcc, mnc, lac, cell_id, lat, lon, source, notes)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT (provider, lac, cell_id) DO UPDATE SET
                            mcc = EXCLUDED.mcc,
                            mnc = EXCLUDED.mnc,
                            lat = EXCLUDED.lat,
                            lon = EXCLUDED.lon,
                            source = EXCLUDED.source,
                            notes = EXCLUDED.notes
                        """
                    ),
                    values,
                )
            else:
                cur.execute(
                    _norm_sql(
                        """
                        INSERT OR REPLACE INTO tower_catalog
                            (provider, mcc, mnc, lac, cell_id, lat, lon, source, notes)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """
                    ),
                    values,
                )
            inserted += 1
    return inserted


def delete_tower_catalog_item(item_id: int) -> None:
    with _cursor() as (_, cur):
        cur.execute(_norm_sql("DELETE FROM tower_catalog WHERE id = ?"), (item_id,))


def clear_tower_catalog() -> None:
    with _cursor() as (_, cur):
        cur.execute("DELETE FROM tower_catalog")


OBJECTIVE_STATUSES = {"pendiente", "en_analisis", "localizado", "informado", "cerrado"}


def _clean_objective_status(value: Any) -> str:
    status = str(value or "pendiente").strip().lower().replace(" ", "_")
    return status if status in OBJECTIVE_STATUSES else "pendiente"


def create_septier_objective(item: Dict[str, Any], username: str = "") -> Dict[str, Any]:
    ordered_keys = [
        "request_type", "case_number", "requester", "person_name", "dni", "phone", "imsi", "imei",
        "geomatrix_lat", "geomatrix_lon", "geomatrix_ref", "status", "notes",
        "field_staff", "technologies_used", "methodology", "created_by", "updated_by",
    ]
    values = {
        "request_type": str(item.get("request_type") or "").strip(),
        "case_number": str(item.get("case_number") or "").strip(),
        "requester": str(item.get("requester") or "").strip(),
        "person_name": str(item.get("person_name") or "").strip(),
        "dni": str(item.get("dni") or "").strip(),
        "phone": str(item.get("phone") or "").strip(),
        "imsi": str(item.get("imsi") or "").strip(),
        "imei": str(item.get("imei") or "").strip(),
        "geomatrix_lat": str(item.get("geomatrix_lat") or "").strip(),
        "geomatrix_lon": str(item.get("geomatrix_lon") or "").strip(),
        "geomatrix_ref": str(item.get("geomatrix_ref") or "").strip(),
        "status": _clean_objective_status(item.get("status")),
        "notes": str(item.get("notes") or "").strip(),
        "field_staff": str(item.get("field_staff") or "").strip(),
        "technologies_used": str(item.get("technologies_used") or "").strip(),
        "methodology": str(item.get("methodology") or "").strip(),
        "created_by": str(username or "").strip(),
        "updated_by": str(username or "").strip(),
    }
    with _cursor() as (_, cur):
        if USE_POSTGRES:
            cur.execute(
                _norm_sql(
                    """
                    INSERT INTO septier_objectives
                        (request_type, case_number, requester, person_name, dni, phone, imsi, imei,
                         geomatrix_lat, geomatrix_lon, geomatrix_ref, status, notes,
                         field_staff, technologies_used, methodology, created_by, updated_by)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    RETURNING id
                    """
                ),
                tuple(values[k] for k in ordered_keys),
            )
            row = cur.fetchone()
            new_id = int(row["id"] if isinstance(row, dict) else row[0])
        else:
            cur.execute(
                _norm_sql(
                    """
                    INSERT INTO septier_objectives
                        (request_type, case_number, requester, person_name, dni, phone, imsi, imei,
                         geomatrix_lat, geomatrix_lon, geomatrix_ref, status, notes,
                         field_staff, technologies_used, methodology, created_by, updated_by)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """
                ),
                tuple(values[k] for k in ordered_keys),
            )
            new_id = int(cur.lastrowid)
    return get_septier_objective(new_id) or {"id": new_id, **values}


def get_septier_objective(objective_id: int) -> Optional[Dict[str, Any]]:
    return _fetchone(
        """
        SELECT id, request_type, case_number, requester, person_name, dni, phone, imsi, imei,
               geomatrix_lat, geomatrix_lon, geomatrix_ref, status, notes,
               field_staff, technologies_used, methodology, created_by, updated_by, created_at, updated_at
        FROM septier_objectives
        WHERE id = ?
        """,
        (objective_id,),
    )


def list_septier_objectives(q: str = "", status: str = "", limit: int = 200) -> List[Dict[str, Any]]:
    safe_limit = max(1, min(int(limit), 1000))
    like_op = "ILIKE" if USE_POSTGRES else "LIKE"
    clauses: List[str] = []
    params: List[Any] = []
    if q:
        needle = f"%{q.strip()}%"
        clauses.append(
            f"(person_name {like_op} ? OR case_number {like_op} ? OR requester {like_op} ? OR phone {like_op} ? OR imsi {like_op} ? OR imei {like_op} ? OR dni {like_op} ?)"
        )
        params.extend([needle, needle, needle, needle, needle, needle, needle])
    if status:
        clauses.append("status = ?")
        params.append(_clean_objective_status(status))
    where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    params.append(safe_limit)
    return _fetchall(
        _norm_sql(
            f"""
            SELECT id, request_type, case_number, requester, person_name, dni, phone, imsi, imei,
                   geomatrix_lat, geomatrix_lon, geomatrix_ref, status, notes,
                   field_staff, technologies_used, methodology, created_by, updated_by, created_at, updated_at
            FROM septier_objectives
            {where_sql}
            ORDER BY id DESC
            LIMIT ?
            """
        ),
        tuple(params),
    )


def update_septier_objective_status(objective_id: int, status: str, username: str = "") -> Optional[Dict[str, Any]]:
    with _cursor() as (_, cur):
        cur.execute(
            _norm_sql(
                """
                UPDATE septier_objectives
                SET status = ?, updated_by = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """
            ),
            (_clean_objective_status(status), str(username or "").strip(), objective_id),
        )
    return get_septier_objective(objective_id)


def delete_septier_objective(objective_id: int) -> None:
    with _cursor() as (_, cur):
        cur.execute(_norm_sql("DELETE FROM septier_objective_history_rows WHERE objective_id = ?"), (objective_id,))
        cur.execute(_norm_sql("DELETE FROM septier_objective_history_uploads WHERE objective_id = ?"), (objective_id,))
        cur.execute(_norm_sql("DELETE FROM septier_objective_images WHERE objective_id = ?"), (objective_id,))
        cur.execute(_norm_sql("DELETE FROM septier_objective_csv_attachments WHERE objective_id = ?"), (objective_id,))
        cur.execute(_norm_sql("DELETE FROM septier_objectives WHERE id = ?"), (objective_id,))


def insert_septier_objective_report(item: Dict[str, Any]) -> Dict[str, Any]:
    values = (
        int(item.get("objective_id") or 0),
        str(item.get("html_path") or "").strip(),
        str(item.get("word_path") or "").strip(),
        str(item.get("sha256") or "").strip(),
        str(item.get("generated_by") or "").strip(),
    )
    with _cursor() as (_, cur):
        if USE_POSTGRES:
            cur.execute(
                _norm_sql(
                    """
                    INSERT INTO septier_objective_reports
                        (objective_id, html_path, word_path, sha256, generated_by)
                    VALUES (?, ?, ?, ?, ?)
                    RETURNING id
                    """
                ),
                values,
            )
            row = cur.fetchone()
            report_id = int(row["id"] if isinstance(row, dict) else row[0])
        else:
            cur.execute(
                _norm_sql(
                    """
                    INSERT INTO septier_objective_reports
                        (objective_id, html_path, word_path, sha256, generated_by)
                    VALUES (?, ?, ?, ?, ?)
                    """
                ),
                values,
            )
            report_id = int(cur.lastrowid)
    row = _fetchone(
        """
        SELECT id, objective_id, html_path, word_path, sha256, generated_by, created_at
        FROM septier_objective_reports
        WHERE id = ?
        """,
        (report_id,),
    )
    return row or {"id": report_id, **item}


def list_septier_objective_reports(objective_id: int = 0, limit: int = 100) -> List[Dict[str, Any]]:
    safe_limit = max(1, min(int(limit), 500))
    clauses: List[str] = []
    params: List[Any] = []
    if objective_id:
        clauses.append("objective_id = ?")
        params.append(int(objective_id))
    where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    params.append(safe_limit)
    return _fetchall(
        _norm_sql(
            f"""
            SELECT id, objective_id, html_path, word_path, sha256, generated_by, created_at
            FROM septier_objective_reports
            {where_sql}
            ORDER BY id DESC
            LIMIT ?
            """
        ),
        tuple(params),
    )


def insert_septier_objective_history_upload(item: Dict[str, Any]) -> Dict[str, Any]:
    values = (
        int(item.get("objective_id") or 0),
        str(item.get("original_filename") or "").strip(),
        str(item.get("stored_filename") or "").strip(),
        str(item.get("stored_path") or "").strip(),
        int(item.get("rows_count") or 0),
        str(item.get("hash_sha256") or "").strip(),
        str(item.get("uploaded_by") or "").strip(),
    )
    with _cursor() as (_, cur):
        if USE_POSTGRES:
            cur.execute(
                _norm_sql(
                    """
                    INSERT INTO septier_objective_history_uploads
                        (objective_id, original_filename, stored_filename, stored_path, rows_count, hash_sha256, uploaded_by)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    RETURNING id
                    """
                ),
                values,
            )
            row = cur.fetchone()
            upload_id = int(row["id"] if isinstance(row, dict) else row[0])
        else:
            cur.execute(
                _norm_sql(
                    """
                    INSERT INTO septier_objective_history_uploads
                        (objective_id, original_filename, stored_filename, stored_path, rows_count, hash_sha256, uploaded_by)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """
                ),
                values,
            )
            upload_id = int(cur.lastrowid)
    row = _fetchone(
        """
        SELECT id, objective_id, original_filename, stored_filename, stored_path, rows_count, hash_sha256, uploaded_by, created_at
        FROM septier_objective_history_uploads
        WHERE id = ?
        """,
        (upload_id,),
    )
    return row or {"id": upload_id, **item}


def update_septier_objective_history_upload_rows(upload_id: int, rows_count: int) -> None:
    with _cursor() as (_, cur):
        cur.execute(
            _norm_sql("UPDATE septier_objective_history_uploads SET rows_count = ? WHERE id = ?"),
            (int(rows_count or 0), int(upload_id)),
        )


def insert_septier_objective_history_rows(rows: List[Dict[str, Any]]) -> None:
    if not rows:
        return
    values = [
        (
            int(r.get("objective_id") or 0),
            int(r.get("upload_id") or 0),
            str(r.get("imsi_mac") or "").strip(),
            str(r.get("imei") or "").strip(),
            str(r.get("model") or "").strip(),
            str(r.get("operation") or "").strip(),
            str(r.get("orig_lac") or "").strip(),
            str(r.get("cell_id") or "").strip(),
            str(r.get("last_update") or "").strip(),
            str(r.get("event_type") or "").strip(),
            str(r.get("source") or "objetivo").strip() or "objetivo",
            str(r.get("archivo_origen") or "").strip(),
            str(r.get("hash_sha256") or "").strip(),
            str(r.get("location") or "").strip(),
            str(r.get("lat_text") or "").strip(),
            str(r.get("lon_text") or "").strip(),
            str(r.get("gps_text") or "").strip(),
        )
        for r in rows
    ]
    with _cursor() as (_, cur):
        cur.executemany(
            _norm_sql(
                """
                INSERT INTO septier_objective_history_rows
                    (objective_id, upload_id, imsi_mac, imei, model, operation, orig_lac, cell_id,
                     last_update, event_type, source, archivo_origen, hash_sha256, location, lat_text, lon_text, gps_text)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """
            ),
            values,
        )

def list_septier_objective_history_uploads(objective_id: int, limit: int = 100) -> List[Dict[str, Any]]:
    safe_limit = max(1, min(int(limit), 500))
    return _fetchall(
        _norm_sql(
            """
            SELECT id, objective_id, original_filename, stored_filename, stored_path, rows_count, hash_sha256, uploaded_by, created_at
            FROM septier_objective_history_uploads
            WHERE objective_id = ?
            ORDER BY id DESC
            LIMIT ?
            """
        ),
        (int(objective_id), safe_limit),
    )


def list_septier_objective_history_rows(objective_id: int, limit: int = 5000) -> List[Dict[str, Any]]:
    safe_limit = max(1, min(int(limit), 20000))
    return _fetchall(
        _norm_sql(
            """
            SELECT id, objective_id, upload_id, imsi_mac, imei, model, operation, orig_lac, cell_id,
                   last_update, event_type, source, archivo_origen, hash_sha256, location, lat_text, lon_text, gps_text, created_at
            FROM septier_objective_history_rows
            WHERE objective_id = ?
            ORDER BY id DESC
            LIMIT ?
            """
        ),
        (int(objective_id), safe_limit),
    )


def insert_septier_objective_image(item: Dict[str, Any]) -> Dict[str, Any]:
    values = (
        int(item.get("objective_id") or 0),
        str(item.get("image_type") or "").strip(),
        str(item.get("original_filename") or "").strip(),
        str(item.get("stored_filename") or "").strip(),
        str(item.get("stored_path") or "").strip(),
        str(item.get("content_type") or "").strip(),
        str(item.get("hash_sha256") or "").strip(),
        str(item.get("uploaded_by") or "").strip(),
    )
    with _cursor() as (_, cur):
        if USE_POSTGRES:
            cur.execute(
                _norm_sql(
                    """
                    INSERT INTO septier_objective_images
                        (objective_id, image_type, original_filename, stored_filename, stored_path, content_type, hash_sha256, uploaded_by)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    RETURNING id
                    """
                ),
                values,
            )
            row = cur.fetchone()
            image_id = int(row["id"] if isinstance(row, dict) else row[0])
        else:
            cur.execute(
                _norm_sql(
                    """
                    INSERT INTO septier_objective_images
                        (objective_id, image_type, original_filename, stored_filename, stored_path, content_type, hash_sha256, uploaded_by)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """
                ),
                values,
            )
            image_id = int(cur.lastrowid)
    row = _fetchone(
        """
        SELECT id, objective_id, image_type, original_filename, stored_filename, stored_path, content_type, hash_sha256, uploaded_by, created_at
        FROM septier_objective_images
        WHERE id = ?
        """,
        (image_id,),
    )
    return row or {"id": image_id, **item}


def list_septier_objective_images(objective_id: int, limit: int = 100) -> List[Dict[str, Any]]:
    safe_limit = max(1, min(int(limit), 500))
    return _fetchall(
        _norm_sql(
            """
            SELECT id, objective_id, image_type, original_filename, stored_filename, stored_path, content_type, hash_sha256, uploaded_by, created_at
            FROM septier_objective_images
            WHERE objective_id = ?
            ORDER BY id DESC
            LIMIT ?
            """
        ),
        (int(objective_id), safe_limit),
    )


def insert_septier_objective_csv_attachment(item: Dict[str, Any]) -> Dict[str, Any]:
    values = (
        int(item.get("objective_id") or 0),
        str(item.get("original_filename") or "").strip(),
        str(item.get("stored_filename") or "").strip(),
        str(item.get("stored_path") or "").strip(),
        int(item.get("rows_count") or 0),
        str(item.get("columns_json") or "[]").strip() or "[]",
        str(item.get("hash_sha256") or "").strip(),
        str(item.get("uploaded_by") or "").strip(),
    )
    with _cursor() as (_, cur):
        if USE_POSTGRES:
            cur.execute(
                _norm_sql(
                    """
                    INSERT INTO septier_objective_csv_attachments
                        (objective_id, original_filename, stored_filename, stored_path, rows_count, columns_json, hash_sha256, uploaded_by)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    RETURNING id
                    """
                ),
                values,
            )
            row = cur.fetchone()
            attachment_id = int(row["id"] if isinstance(row, dict) else row[0])
        else:
            cur.execute(
                _norm_sql(
                    """
                    INSERT INTO septier_objective_csv_attachments
                        (objective_id, original_filename, stored_filename, stored_path, rows_count, columns_json, hash_sha256, uploaded_by)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """
                ),
                values,
            )
            attachment_id = int(cur.lastrowid)
    row = _fetchone(
        """
        SELECT id, objective_id, original_filename, stored_filename, stored_path, rows_count, columns_json, hash_sha256, uploaded_by, created_at
        FROM septier_objective_csv_attachments
        WHERE id = ?
        """,
        (attachment_id,),
    )
    return row or {"id": attachment_id, **item}


def list_septier_objective_csv_attachments(objective_id: int, limit: int = 100) -> List[Dict[str, Any]]:
    safe_limit = max(1, min(int(limit), 500))
    return _fetchall(
        _norm_sql(
            """
            SELECT id, objective_id, original_filename, stored_filename, stored_path, rows_count, columns_json, hash_sha256, uploaded_by, created_at
            FROM septier_objective_csv_attachments
            WHERE objective_id = ?
            ORDER BY id DESC
            LIMIT ?
            """
        ),
        (int(objective_id), safe_limit),
    )


def get_historial_informes() -> List[Dict[str, Any]]:
    """Devuelve todo el historial de IMSIs/IMEIs ya reportados."""
    return _fetchall("SELECT imsi, imei, archivo_origen, numero_informe, created_at FROM historial_informes")


def insert_historial_informes(items: List[Dict[str, str]], numero_informe: str) -> None:
    """Sella los objetivos reportados en la memoria del sistema."""
    if not items:
        return
    values = [(str(i.get("imsi", "")).strip(), str(i.get("imei", "")).strip(), str(i.get("archivo_origen", "")).strip(), str(numero_informe).strip()) for i in items]
    with _cursor() as (_, cur):
        cur.executemany(
            _norm_sql("INSERT INTO historial_informes (imsi, imei, archivo_origen, numero_informe) VALUES (?, ?, ?, ?)"),
            values
        )


def next_numero_nota(anio: int) -> int:
    row = _fetchone("SELECT COALESCE(MAX(numero_nota), 0) + 1 AS next_num FROM informes_generados WHERE anio = ?", (anio,))
    if not row:
        return 1
    return int(row.get("next_num") or 1)


def insert_informe_generado(item: Dict[str, Any]) -> None:
    archivos = item.get("archivos", [])
    with _cursor() as (_, cur):
        cur.execute(
            _norm_sql(
                """
                INSERT INTO informes_generados
                    (numero_nota, anio, numero_informe, tipo, usuario, archivos_json, objetivos_count, download_url)
                VALUES
                    (?, ?, ?, ?, ?, ?, ?, ?)
                """
            ),
            (
                int(item.get("numero_nota") or 0),
                int(item.get("anio") or 0),
                str(item.get("numero_informe", "")).strip(),
                str(item.get("tipo", "")).strip(),
                str(item.get("usuario", "")).strip(),
                json.dumps(archivos, ensure_ascii=False),
                int(item.get("objetivos_count") or 0),
                str(item.get("download_url", "")).strip(),
            ),
        )


def list_informes_generados(limit: int = 100) -> List[Dict[str, Any]]:
    rows = _fetchall("SELECT * FROM informes_generados ORDER BY id DESC LIMIT ?", (limit,))
    out: List[Dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        try:
            item["archivos"] = json.loads(item.get("archivos_json") or "[]")
        except Exception:
            item["archivos"] = []
        item.pop("archivos_json", None)
        out.append(item)
    return out


def insert_phone_query(item: Dict[str, Any]) -> Dict[str, Any]:
    provider_summary = item.get("provider_summary", item.get("provider_summary_json", {}))
    if not isinstance(provider_summary, str):
        provider_summary = json.dumps(provider_summary, ensure_ascii=False)
    with _cursor() as (_, cur):
        if USE_POSTGRES:
            cur.execute(
                _norm_sql(
                    """
                    INSERT INTO phone_queries
                        (reference, phone, area_label, area_lat, area_lon, radius_m, status, provider_summary_json, created_by)
                    VALUES
                        (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    RETURNING *
                    """
                ),
                (
                    str(item.get("reference", "")).strip(),
                    str(item.get("phone", "")).strip(),
                    str(item.get("area_label", "")).strip(),
                    item.get("area_lat"),
                    item.get("area_lon"),
                    int(item.get("radius_m") or 50000),
                    str(item.get("status", "")).strip(),
                    str(provider_summary),
                    str(item.get("created_by", "")).strip(),
                ),
            )
            row = cur.fetchone()
            return dict(row) if row else {}
        cur.execute(
            _norm_sql(
                """
                INSERT INTO phone_queries
                    (reference, phone, area_label, area_lat, area_lon, radius_m, status, provider_summary_json, created_by)
                VALUES
                    (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """
            ),
            (
                str(item.get("reference", "")).strip(),
                str(item.get("phone", "")).strip(),
                str(item.get("area_label", "")).strip(),
                item.get("area_lat"),
                item.get("area_lon"),
                int(item.get("radius_m") or 50000),
                str(item.get("status", "")).strip(),
                str(provider_summary),
                str(item.get("created_by", "")).strip(),
            ),
        )
        query_id = int(cur.lastrowid)
    row = _fetchone("SELECT * FROM phone_queries WHERE id = ?", (query_id,))
    return dict(row) if row else {}


def update_phone_query_report(query_id: int, html_path: str, word_path: str, sha256: str) -> Dict[str, Any]:
    with _cursor() as (_, cur):
        cur.execute(
            _norm_sql(
                """
                UPDATE phone_queries
                SET html_path = ?, word_path = ?, sha256 = ?
                WHERE id = ?
                """
            ),
            (str(html_path), str(word_path), str(sha256), int(query_id)),
        )
    row = _fetchone("SELECT * FROM phone_queries WHERE id = ?", (int(query_id),))
    return dict(row) if row else {}


def list_phone_queries(limit: int = 100) -> List[Dict[str, Any]]:
    rows = _fetchall("SELECT * FROM phone_queries ORDER BY id DESC LIMIT ?", (int(limit),))
    out: List[Dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        try:
            item["provider_summary"] = json.loads(item.get("provider_summary_json") or "{}")
        except Exception:
            item["provider_summary"] = {}
        item.pop("provider_summary_json", None)
        out.append(item)
    return out
