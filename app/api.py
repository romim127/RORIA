from pathlib import Path
import csv
import base64
from collections import Counter, defaultdict
import datetime as dt
import hashlib
import hmac
import html as html_lib
import json
import math
import os
import re
import secrets
import shutil
import socket
import struct
import subprocess
import sys
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile
from typing import Any, Dict, List, Optional, Tuple

from docxtpl import DocxTemplate  # type: ignore
from fastapi import (
    Body,
    Depends,
    FastAPI,
    File,
    Form,
    Header,
    HTTPException,
    Request,
    Response,
    UploadFile,
    status,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from app.db import (
    authenticate_user,
    change_password,
    create_user,
    delete_user_by_id,
    delete_token,
    clear_skyeye_run_data,
    delete_septier_history_metadata,
    ensure_default_user,
    get_user_by_id,
    get_user_by_username,
    get_run,
    get_token_user,
    init_db,
    delete_skyeye_run_data_by_input,
    insert_detections,
    insert_septier_detections,
    list_septier_history_schema,
    list_septier_network_refs,
    list_septier_rf_bands,
    replace_septier_history_schema,
    replace_septier_network_refs,
    replace_septier_rf_bands,
    update_septier_history_schema_selection,
    insert_run,
    list_runs,
    list_login_events,
    list_login_attempts,
    list_security_events,
    list_security_blocks,
    list_users,
    query_heatmap,
    query_heatmap_filters,
    query_septier_heatmap,
    search_septier_detections,
    get_septier_file_stats,
    get_septier_detections_by_files,
    get_septier_forensic_rows_by_files,
    get_septier_history_metadata_map,
    list_septier_uploaded_files_from_db,
    get_septier_identity_history,
    get_historial_informes,
    insert_informe_generado,
    insert_historial_informes,
    insert_phone_query,
    record_login_event,
    record_login_attempt,
    record_security_event,
    register_failed_login_attempt,
    set_user_active,
    set_user_mfa_secret,
    confirm_user_mfa,
    cleanup_mfa_login_tickets,
    consume_mfa_login_ticket,
    create_mfa_login_ticket,
    get_mfa_login_ticket,
    get_active_security_block,
    create_security_block,
    is_super_admin_username,
    lift_security_block,
    list_informes_generados,
    list_phone_queries,
    list_whitelist,
    list_whitelist_uploads,
    whitelist_matches_for_ids,
    clear_whitelist,
    delete_whitelist_upload,
    delete_external_identity_upload,
    get_whitelist_upload,
    external_identity_lookup,
    insert_external_identity_upload,
    insert_whitelist_items,
    insert_whitelist_upload,
    list_external_identity_data,
    list_external_identity_uploads,
    delete_whitelist_item,
    list_tower_catalog,
    upsert_tower_catalog,
    delete_tower_catalog_item,
    clear_tower_catalog,
    create_septier_objective,
    delete_septier_objective,
    get_septier_objective,
    insert_septier_objective_csv_attachment,
    insert_septier_objective_history_rows,
    insert_septier_objective_history_upload,
    insert_septier_objective_image,
    insert_septier_objective_report,
    list_septier_objective_history_rows,
    list_septier_objective_history_uploads,
    list_septier_objective_csv_attachments,
    list_septier_objective_images,
    list_septier_objective_reports,
    list_septier_objectives,
    update_septier_objective_history_upload_rows,
    update_septier_objective_status,
    upsert_septier_history_metadata,
    store_token,
    TOKEN_TTL_HOURS,
    next_numero_nota,
    update_phone_query_report,
    whitelist_existing_ids,
    update_user,
)
from app.processing import (
    OUTPUTS_DIR,
    REPORTS_DIR,
    build_device_trajectory_kml,
    build_drones_commands_file,
    generar_reporte_html,
    run_end_to_end_for_latest,
)
from app.processing import csv_kind, _extract_detections_for_db, clean_columns
from app.processing import parse_latlon


app = FastAPI(title="SkyEye Ops API", version="0.1.0")
REPO_ROOT = Path(__file__).resolve().parent.parent
NEXA_SUITE_DIR = REPO_ROOT / "app" / "nexa_suite"
NEXA_RF_ENGINE = NEXA_SUITE_DIR / "modules" / "rf_analyzer" / "nexa_rf_analyzer_v2.py"
SAMPLE_INPUT_FILES = ("Detection Report.csv", "PRUEBA1.csv")
PROCESSED_DIR = REPORTS_DIR / "procesados"
SKYEYE_GENERAL_DIR = REPORTS_DIR.parent / "skyeye_general"
SEPTIER_DIR = REPORTS_DIR / "septier_detecciones"
GUARDIAN_DIR = SEPTIER_DIR / "guardian"
BACKPACK_DIR = SEPTIER_DIR / "backpack"
OBJECTIVE_HISTORY_DIR = SEPTIER_DIR / "objetivos"
WHITELIST_UPLOADS_DIR = REPORTS_DIR.parent / "whitelist_uploads"
EXTERNAL_IDENTITY_DIR = REPORTS_DIR.parent / "external_identity_data"
NEXA_DIR = REPORTS_DIR.parent / "nexa"
NEXA_INPUT_DIR = NEXA_DIR / "input"
NEXA_LOG_DIR = NEXA_DIR / "logs"
NEXA_MANUALS_DIR = NEXA_DIR / "manuals"
NEXA_RUNS_DIR = OUTPUTS_DIR / "nexa" / "runs"
TELEGRAM_BOT_TOKEN = re.sub(r"\s+", "", os.getenv("SKYEYE_TELEGRAM_BOT_TOKEN", ""))
TELEGRAM_CHAT_ID = os.getenv("SKYEYE_TELEGRAM_CHAT_ID", "").strip()
TELEGRAM_NOTIFY_LOGINS = os.getenv("SKYEYE_TELEGRAM_NOTIFY_LOGINS", "false").strip().lower() in {"1", "true", "yes", "on"}
MFA_LOGIN_TICKET_TTL_SECONDS = 300
SESSION_COOKIE_NAME = "skyeye_session"
SESSION_COOKIE_SECURE = os.getenv("SKYEYE_SESSION_COOKIE_SECURE", "false").strip().lower() in {"1", "true", "yes", "on"}
SECURITY_REQUEST_GUARD_ENABLED = os.getenv("SKYEYE_SECURITY_REQUEST_GUARD", "true").strip().lower() not in {"0", "false", "no", "off"}
SECURITY_STRICT_LOGIN_BLOCK_ENABLED = os.getenv("SKYEYE_SECURITY_STRICT_LOGIN_BLOCK", "true").strip().lower() not in {"0", "false", "no", "off"}
SECURITY_STRICT_BLOCK_MINUTES = int(os.getenv("SKYEYE_SECURITY_STRICT_BLOCK_MINUTES", "1440"))
RELATIONAL_STANDALONE_ENABLED = os.getenv("SKYEYE_RELATIONAL_STANDALONE", "false").strip().lower() in {"1", "true", "yes", "on"}
CLAMAV_ENABLED = os.getenv("CLAMAV_ENABLED", "false").strip().lower() in {"1", "true", "yes", "on"}
CLAMAV_HOST = os.getenv("CLAMAV_HOST", "127.0.0.1").strip()
CLAMAV_PORT = int(os.getenv("CLAMAV_PORT", "3310"))
CLAMAV_TIMEOUT_SECONDS = float(os.getenv("CLAMAV_TIMEOUT_SECONDS", "12"))
CLAMAV_FAIL_CLOSED = os.getenv("CLAMAV_FAIL_CLOSED", "false").strip().lower() not in {"0", "false", "no", "off"}
CLAMAV_MAX_SCAN_BYTES = int(os.getenv("CLAMAV_MAX_SCAN_BYTES", str(80 * 1024 * 1024)))
OPENAI_API_KEY = (os.getenv("OPENAI_API_KEY", "") or os.getenv("SIGMA_OPENAI_API_KEY", "")).strip()
SIGMA_OPENAI_MODEL = os.getenv("SIGMA_OPENAI_MODEL", "gpt-4.1-mini").strip()
SIGMA_MAX_CONTEXT_CHARS = int(os.getenv("SIGMA_MAX_CONTEXT_CHARS", "18000"))
PHONE_QUERY_OPEN_GATEWAY_TOKEN = os.getenv("PHONE_QUERY_OPEN_GATEWAY_TOKEN", "").strip()
PHONE_QUERY_SIM_SWAP_URL = os.getenv("PHONE_QUERY_SIM_SWAP_URL", "").strip()
PHONE_QUERY_DEVICE_LOCATION_VERIFY_URL = os.getenv("PHONE_QUERY_DEVICE_LOCATION_VERIFY_URL", "").strip()
PHONE_QUERY_IPQS_API_KEY = os.getenv("PHONE_QUERY_IPQS_API_KEY", "").strip()
PHONE_QUERY_IPQS_URL_TEMPLATE = os.getenv("PHONE_QUERY_IPQS_URL_TEMPLATE", "https://www.ipqualityscore.com/api/json/phone/{key}/{phone}").strip()
PHONE_QUERY_MAXMIND_ACCOUNT_ID = os.getenv("PHONE_QUERY_MAXMIND_ACCOUNT_ID", "").strip()
PHONE_QUERY_MAXMIND_LICENSE_KEY = os.getenv("PHONE_QUERY_MAXMIND_LICENSE_KEY", "").strip()
PHONE_QUERY_MAXMIND_URL = os.getenv("PHONE_QUERY_MAXMIND_URL", "").strip()
PHONE_QUERY_ENV_VARS = [
    "PHONE_QUERY_OPEN_GATEWAY_TOKEN",
    "PHONE_QUERY_SIM_SWAP_URL",
    "PHONE_QUERY_DEVICE_LOCATION_VERIFY_URL",
    "PHONE_QUERY_IPQS_API_KEY",
    "PHONE_QUERY_IPQS_URL_TEMPLATE",
    "PHONE_QUERY_MAXMIND_ACCOUNT_ID",
    "PHONE_QUERY_MAXMIND_LICENSE_KEY",
    "PHONE_QUERY_MAXMIND_URL",
]

SECURITY_GUARD_PATTERNS: List[Tuple[str, re.Pattern[str]]] = [
    ("sqlmap_user_agent", re.compile(r"\bsqlmap\b", re.IGNORECASE)),
    ("sql_injection_union", re.compile(r"\bunion\s+(?:all\s+)?select\b", re.IGNORECASE)),
    ("sql_injection_boolean", re.compile(r"(?:\bor\b|\band\b)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+", re.IGNORECASE)),
    ("sql_injection_comment", re.compile(r"(--|/\*|\*/)\s*(?:$|[\w-])", re.IGNORECASE)),
    ("sql_injection_metadata", re.compile(r"\b(information_schema|pg_catalog|sqlite_master|sysobjects)\b", re.IGNORECASE)),
    ("sql_injection_time", re.compile(r"\b(sleep|benchmark|pg_sleep|waitfor\s+delay)\s*\(", re.IGNORECASE)),
    ("sql_destructive_statement", re.compile(r"\b(drop|truncate|alter)\s+(table|database|schema)\b", re.IGNORECASE)),
    ("command_execution", re.compile(r"\b(cmd\.exe|powershell|bash\s+-c|/bin/sh|xp_cmdshell|whoami|net\s+user)\b", re.IGNORECASE)),
    ("path_traversal", re.compile(r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e%5c)", re.IGNORECASE)),
    ("sensitive_file_probe", re.compile(r"(/etc/passwd|/proc/self/environ|win\.ini|web\.config)", re.IGNORECASE)),
]


def _security_guard_probe_text(request: Request, body: bytes = b"") -> str:
    parts = [
        request.url.path,
        request.url.query,
    ]
    user_agent = request.headers.get("user-agent", "")
    if re.search(r"\bsqlmap\b", user_agent, re.IGNORECASE):
        parts.append(user_agent)
    content_type = request.headers.get("content-type", "").lower()
    if body and len(body) <= 8192 and "multipart/" not in content_type:
        parts.append(body.decode("utf-8", errors="ignore"))
    return urllib.parse.unquote_plus("\n".join(parts))[:12000]


def _security_guard_match(probe: str) -> Optional[str]:
    for label, pattern in SECURITY_GUARD_PATTERNS:
        if pattern.search(probe):
            return label
    return None


def _request_source_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",", 1)[0].strip()
    return request.client.host if request.client else ""


def _is_local_request(request: Request) -> bool:
    host = (request.client.host if request.client else "") or ""
    forwarded = request.headers.get("x-forwarded-for", "").strip()
    if forwarded:
        host = forwarded.split(",", 1)[0].strip()
    return host in {"127.0.0.1", "::1", "localhost"}


def _standalone_network_user() -> Dict[str, object]:
    return {
        "id": 0,
        "username": "red.operativa.local",
        "full_name": "Red Operativa Relacional",
        "roles": ["analista"],
        "must_change_password": False,
        "mfa_enabled": False,
    }


def _strict_block_actor(username: str, source_ip: str, reason: str) -> List[Dict[str, object]]:
    blocks: List[Dict[str, object]] = []
    clean_username = str(username or "").strip()
    clean_ip = str(source_ip or "").strip()
    try:
        if clean_username and not is_super_admin_username(clean_username):
            blocks.append(create_security_block("username", clean_username, reason, minutes=SECURITY_STRICT_BLOCK_MINUTES))
    except Exception:
        pass
    try:
        if clean_ip:
            blocks.append(create_security_block("ip", clean_ip, reason, minutes=SECURITY_STRICT_BLOCK_MINUTES))
    except Exception:
        pass
    return blocks


def _security_canary_response(
    event_type: str,
    rule: str,
    username: str,
    source_ip: str,
    path: str,
    user_agent: str,
) -> Response:
    token = secrets.token_urlsafe(18)
    now = dt.datetime.now(dt.timezone(dt.timedelta(hours=-3))).strftime("%Y-%m-%d %H:%M:%S UTC-3")
    detail = f"canary={token}; regla={rule}; path={path}; ip={source_ip or '-'}"
    try:
        record_security_event(
            event_type="security_canary_issued",
            severity="critical",
            username=username,
            source_ip=source_ip,
            user_agent=user_agent,
            detail=detail,
        )
    except Exception:
        pass
    text = "\n".join(
        [
            "DETECTION OF SIGNALS - AVISO DE SEGURIDAD",
            "",
            "Intentaste ingresar o descargar un recurso sin permiso.",
            "El evento fue registrado y el acceso queda bloqueado por politica operativa.",
            "",
            f"Token canary: {token}",
            f"Regla: {rule}",
            f"Ruta: {path}",
            f"IP registrada: {source_ip or '-'}",
            f"Usuario: {username or '-'}",
            f"Fecha: {now}",
            "",
            "Comunicarse con el administrador de la plataforma.",
        ]
    )
    filename = f"AVISO_SEGURIDAD_{token[:10]}.txt"
    return Response(
        content=text,
        status_code=403,
        media_type="text/plain; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Security-Canary": token,
        },
    )


def _clamav_scan_bytes(raw: bytes) -> Tuple[bool, str]:
    if not CLAMAV_ENABLED:
        return True, "disabled"
    if len(raw or b"") > CLAMAV_MAX_SCAN_BYTES:
        if CLAMAV_FAIL_CLOSED:
            return False, f"archivo supera limite de escaneo ClamAV ({CLAMAV_MAX_SCAN_BYTES} bytes)"
        return True, "skipped_size_limit"
    try:
        with socket.create_connection((CLAMAV_HOST, CLAMAV_PORT), timeout=CLAMAV_TIMEOUT_SECONDS) as sock:
            sock.settimeout(CLAMAV_TIMEOUT_SECONDS)
            sock.sendall(b"zINSTREAM\0")
            chunk_size = 1024 * 1024
            for idx in range(0, len(raw), chunk_size):
                chunk = raw[idx: idx + chunk_size]
                sock.sendall(struct.pack(">I", len(chunk)))
                sock.sendall(chunk)
            sock.sendall(struct.pack(">I", 0))
            response = sock.recv(4096).decode("utf-8", errors="replace").strip()
    except Exception as exc:
        if CLAMAV_FAIL_CLOSED:
            return False, f"ClamAV no disponible: {exc}"
        return True, f"clamav_unavailable_fail_open: {exc}"
    if "FOUND" in response.upper():
        return False, response
    if response.upper().endswith("OK"):
        return True, response
    if CLAMAV_FAIL_CLOSED:
        return False, f"Respuesta ClamAV no reconocida: {response}"
    return True, f"clamav_unknown_fail_open: {response}"


def _scan_uploaded_bytes(raw: bytes, filename: str, context: str, user: Optional[Dict[str, object]] = None) -> None:
    ok, result = _clamav_scan_bytes(raw)
    username = str((user or {}).get("username") or (user or {}).get("full_name") or "")
    clean_name = Path(filename or "archivo").name
    if ok:
        if CLAMAV_ENABLED:
            try:
                record_security_event(
                    event_type="clamav_scan_ok",
                    severity="info",
                    username=username,
                    detail=f"context={context}; file={clean_name}; result={result}",
                )
            except Exception:
                pass
        return

    try:
        record_security_event(
            event_type="clamav_scan_blocked",
            severity="critical",
            username=username,
            detail=f"context={context}; file={clean_name}; result={result}",
        )
    except Exception:
        pass
    raise HTTPException(
        status_code=422,
        detail=f"Archivo rechazado por inspeccion antivirus: {clean_name}. Resultado: {result}",
    )


@app.middleware("http")
async def security_request_guard(request: Request, call_next):
    if not SECURITY_REQUEST_GUARD_ENABLED:
        return await call_next(request)

    path = request.url.path or ""
    if path.startswith(("/assets/", "/ui/")):
        return await call_next(request)

    body = b""
    content_type = request.headers.get("content-type", "").lower()
    content_length = int(request.headers.get("content-length") or 0)
    if request.method in {"POST", "PUT", "PATCH"} and content_length <= 8192 and "multipart/" not in content_type:
        try:
            body = await request.body()
        except Exception:
            body = b""

    probe = _security_guard_probe_text(request, body)
    match = _security_guard_match(probe)
    if not match:
        return await call_next(request)

    token = ""
    authorization = request.headers.get("authorization", "")
    if authorization.startswith("Bearer "):
        token = authorization.replace("Bearer ", "", 1).strip()
    elif request.cookies.get(SESSION_COOKIE_NAME):
        token = request.cookies.get(SESSION_COOKIE_NAME, "").strip()
    user = get_token_user(token) if token else None
    username = str((user or {}).get("username", "")) if user else ""
    source_ip = _request_source_ip(request)
    user_agent = request.headers.get("user-agent", "")
    detail = f"Bloqueo guard={match}; metodo={request.method}; path={path}; query={request.url.query[:500]}"
    _strict_block_actor(username, source_ip, f"Guard request bloqueado: {match}")

    try:
        record_security_event(
            event_type="request_guard_blocked",
            severity="critical",
            username=username,
            source_ip=source_ip,
            user_agent=user_agent,
            detail=detail,
        )
    except Exception:
        pass

    try:
        _send_security_telegram_alert(
            "\n".join(
                [
                    "ALERTA DE SEGURIDAD - Detection of Signals",
                    f"Evento: request_guard_blocked",
                    f"Regla: {match}",
                    f"Usuario: {username or '-'}",
                    f"IP: {source_ip or '-'}",
                    f"Ruta: {request.method} {path}",
                    f"Fecha Argentina: {_security_local_time_text()}",
                ]
            )
        )
    except Exception:
        pass

    return _security_canary_response(
        event_type="request_guard_blocked",
        rule=match,
        username=username,
        source_ip=source_ip,
        path=path,
        user_agent=user_agent,
    )


class LoginRequest(BaseModel):
    username: str
    password: str


class MfaLoginVerifyRequest(BaseModel):
    ticket: str
    code: str


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


class MfaConfirmRequest(BaseModel):
    code: str


class CreateUserRequest(BaseModel):
    username: str
    password: str
    roles: List[str]
    full_name: str = ""


class UpdateUserRequest(BaseModel):
    username: str
    roles: List[str]
    full_name: str = ""
    password: str = ""
    is_active: bool = True


class NetworkAccessSessionRequest(BaseModel):
    scenario: str = "Escenario 1"
    user_id: int
    status: str = "pendiente"
    permissions: Dict[str, bool] = Field(default_factory=dict)
    note: str = ""


class NetworkAccessStatusRequest(BaseModel):
    status: str


class FileItem(BaseModel):
    system: str
    file: str


class AuditReportRequest(BaseModel):
    files: List[FileItem]
    ignore_memory: bool = False


class ForensicMasterRequest(BaseModel):
    files: List[FileItem]


class SeptierTechnicalCsvRequest(BaseModel):
    files: List[FileItem]
    fields: List[str] = Field(default_factory=list)
    exclude_whitelist: bool = False


class SeptierSearchReportRequest(BaseModel):
    q: str


class SeptierExternalCleanReportRequest(BaseModel):
    files: List[FileItem] = Field(default_factory=list)
    upload_ids: List[int] = Field(default_factory=list)


class SeptierExternalUploadSelection(BaseModel):
    upload_ids: List[int] = Field(default_factory=list)


class SeptierHistoryProviderAuditRequest(BaseModel):
    files: List[FileItem] = Field(default_factory=list)


class SeptierNetworkReportRequest(BaseModel):
    source: str = ""
    place: str = ""
    q: str = ""
    limit: int = 80
    include_whitelist: bool = True
    show_whitelist_nodes: bool = True
    include_mutations: bool = True
    only_unauthorized: bool = False
    only_multi_place: bool = False
    only_memory: bool = False
    only_first_seen: bool = False
    files: List[FileItem] = Field(default_factory=list)
    show_imsi: bool = True
    show_imei: bool = True
    show_description: bool = True
    show_source: bool = True
    nodes: List[Dict[str, Any]] = Field(default_factory=list)
    edges: List[Dict[str, Any]] = Field(default_factory=list)
    summary: Dict[str, Any] = Field(default_factory=dict)
    filters: Dict[str, Any] = Field(default_factory=dict)
    view_options: Dict[str, Any] = Field(default_factory=dict)
    selected_files: List[FileItem] = Field(default_factory=list)
    layout: Dict[str, Any] = Field(default_factory=dict)
    annotations: List[Dict[str, Any]] = Field(default_factory=list)
    canvas_theme: str = "app"
    audit_log: List[Dict[str, Any]] = Field(default_factory=list)


class SeptierNetworkCaseRequest(BaseModel):
    title: str = ""
    description: str = ""
    nodes: List[Dict[str, Any]] = Field(default_factory=list)
    edges: List[Dict[str, Any]] = Field(default_factory=list)
    summary: Dict[str, Any] = Field(default_factory=dict)
    filters: Dict[str, Any] = Field(default_factory=dict)
    view_options: Dict[str, Any] = Field(default_factory=dict)
    selected_files: List[FileItem] = Field(default_factory=list)
    layout: Dict[str, Any] = Field(default_factory=dict)
    annotations: List[Dict[str, Any]] = Field(default_factory=list)
    canvas_theme: str = "app"
    audit_log: List[Dict[str, Any]] = Field(default_factory=list)


class SeptierNetworkCaseShareRequest(BaseModel):
    usernames: List[str] = Field(default_factory=list)
    permission: str = "comment"
    message: str = ""


class SeptierNetworkCaseCommentRequest(BaseModel):
    message: str = ""


class SeptierNetworkTaskStatusRequest(BaseModel):
    status: str = "en_curso"


class SeptierObjectiveRequest(BaseModel):
    request_type: str = ""
    case_number: str = ""
    requester: str = ""
    person_name: str = ""
    dni: str = ""
    phone: str = ""
    imsi: str = ""
    imei: str = ""
    geomatrix_lat: str = ""
    geomatrix_lon: str = ""
    geomatrix_ref: str = ""
    status: str = "pendiente"
    notes: str = ""
    field_staff: str = ""
    technologies_used: str = ""
    methodology: str = ""


class SeptierObjectiveStatusRequest(BaseModel):
    status: str


class SigmaChatRequest(BaseModel):
    message: str
    objective_id: Optional[int] = None


class TargetItem(BaseModel):
    imsi: str
    imei: str
    archivo: str


class ReportStaffItem(BaseModel):
    nombre: str
    titulo: str


class ReportLocationItem(BaseModel):
    nombre: str = ""
    mes: str = ""
    lugar_escaneo: str = ""
    ubicacion_escaneo: str = ""
    coordenadas: str = ""
    modulos: str = ""
    ala: str = ""


class GenerateReportRequest(BaseModel):
    tipo: str
    files: List[FileItem]
    targets: List[TargetItem]
    personal: List[ReportStaffItem] = Field(default_factory=list)
    lugar: ReportLocationItem = Field(default_factory=ReportLocationItem)


class SeptierHistoryMetaItem(BaseModel):
    system: str
    file: str
    bloque: str = ""
    complejo: str = ""
    lugar: str = ""
    modulo: str = ""
    ala: str = ""
    ubicacion: str = ""
    coordenadas: str = ""
    observacion: str = ""


class SeptierHistoryMetadataUpdate(BaseModel):
    lugar_operativo: str = ""
    complejo: str = ""
    modulo: str = ""
    ala: str = ""
    ubicacion: str = ""
    coordenadas: str = ""
    observacion: str = ""


class SeptierConsolidatedBlockItem(BaseModel):
    ui_index: int = 0
    nombre: str = ""
    complejo: str = ""
    lugar: str = ""
    modulo: str = ""
    ala: str = ""
    ubicacion: str = ""
    coordenadas: str = ""
    observacion: str = ""
    files: List[FileItem] = Field(default_factory=list)


class SeptierConsolidatedReportRequest(BaseModel):
    files: List[FileItem]
    histories: List[SeptierHistoryMetaItem] = Field(default_factory=list)
    bloques: List[SeptierConsolidatedBlockItem] = Field(default_factory=list)
    personal: List[ReportStaffItem] = Field(default_factory=list)
    lugar: ReportLocationItem = Field(default_factory=ReportLocationItem)


def _effective_consolidated_files(payload: SeptierConsolidatedReportRequest) -> List[FileItem]:
    seen = set()
    result: List[FileItem] = []
    block_files = [file_item for block in payload.bloques for file_item in block.files]
    source = block_files if block_files else payload.files
    for file_item in source:
        key = (str(file_item.system or "").lower(), str(file_item.file or ""))
        if not key[0] or not key[1] or key in seen:
            continue
        seen.add(key)
        result.append(file_item)
    return result


class SkyEyeReportRequest(BaseModel):
    run_id: Optional[int] = None
    observaciones: str = ""
    area: str = ""
    folder: str = ""
    filename: str = ""
    device_id: str = ""
    generate_kml: bool = False


class PhoneQueryRequest(BaseModel):
    reference: str = ""
    phone: str
    area_label: str = ""
    area_lat: Optional[float] = None
    area_lon: Optional[float] = None
    radius_m: int = Field(default=50000, ge=100, le=500000)
    notes: str = ""


class NexaSourceFile(BaseModel):
    source: str
    file: str
    system: str = ""
    folder: str = ""


class NexaPrepareRunRequest(BaseModel):
    module: str = "rf_analyzer"
    case_name: str = ""
    case_number: str = ""
    analyst: str = ""
    position: str = ""
    organization: str = ""
    institution: str = ""
    location: str = ""
    equipment: str = "GUARDIAN"
    mode: str = "BLOCK"
    antennas: str = "DIRECCIONALES"
    orientation: str = ""
    notes: str = ""
    files: List[NexaSourceFile] = Field(default_factory=list)


class NexaManualSearchRequest(BaseModel):
    q: str
    limit: int = Field(default=5, ge=1, le=10)


class SeptierHistorySchemaSelectionRequest(BaseModel):
    fields: List[str] = Field(default_factory=list)


class WhitelistItemRequest(BaseModel):
    device_id: str
    device_type: str = "manual"
    description: str = ""


class TowerCatalogItemRequest(BaseModel):
    provider: str = ""
    mcc: str = ""
    mnc: str = ""
    lac: str
    cell_id: str
    lat: Optional[float] = None
    lon: Optional[float] = None
    source: str = ""
    notes: str = ""

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def _no_cache_frontend(request: Request, call_next):
    response = await call_next(request)
    if request.url.path == "/" or request.url.path.startswith("/ui"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
    return response


def _bootstrap_sample_inputs() -> None:
    if any(REPORTS_DIR.glob("*.csv")):
        return

    for name in SAMPLE_INPUT_FILES:
        source = REPO_ROOT / name
        if source.exists():
            shutil.copy2(source, REPORTS_DIR / name)


def _bootstrap_initial_run() -> None:
    if os.getenv("SKYEYE_BOOTSTRAP_SAMPLE", "").strip() != "1":
        return

    if list_runs():
        return

    _bootstrap_sample_inputs()
    if not any(REPORTS_DIR.glob("*.csv")):
        return

    try:
        payload = run_end_to_end_for_latest()
        insert_run(payload)
    except Exception:
        pass


def _detect_csv_kind(path: Path) -> str:
    try:
        kind = csv_kind(path)
        return kind if kind in {"detection", "trajectory"} else "unknown"
    except Exception:
        return "unknown"


def _build_upload_target(kind: str, original_name: str) -> Path:
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    stem = re.sub(r"[^A-Za-z0-9._-]+", "_", Path(original_name).stem).strip("._") or "archivo"
    prefix = {
        "detection": "report",
        "trajectory": "trajectories",
    }.get(kind, "csv")

    base_name = f"{prefix}_{stamp}_{stem}.csv"
    target = REPORTS_DIR / base_name
    i = 1
    while target.exists():
        target = REPORTS_DIR / f"{prefix}_{stamp}_{stem}_{i}.csv"
        i += 1
    return target


def _build_skyeye_general_target(kind: str, original_name: str) -> Path:
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    stem = re.sub(r"[^A-Za-z0-9._-]+", "_", Path(original_name).stem).strip("._") or "archivo"
    prefix = {
        "detection": "general_detection",
        "trajectory": "general_trajectory",
    }.get(kind, "general_csv")

    target = SKYEYE_GENERAL_DIR / f"{prefix}_{stamp}_{stem}.csv"
    i = 1
    while target.exists():
        target = SKYEYE_GENERAL_DIR / f"{prefix}_{stamp}_{stem}_{i}.csv"
        i += 1
    return target


def _archive_processed_inputs(detection_csv: Path, trajectory_csv: Optional[Path]) -> Dict[str, object]:
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    archive_dir = PROCESSED_DIR / stamp
    archive_dir.mkdir(parents=True, exist_ok=True)

    def _move(src: Optional[Path]) -> Optional[str]:
        if src is None or not src.exists():
            return None
        dest = archive_dir / src.name
        i = 1
        while dest.exists():
            dest = archive_dir / f"{src.stem}_{i}{src.suffix}"
            i += 1
        shutil.move(str(src), str(dest))
        return str(dest)

    return {
        "archive_dir": str(archive_dir),
        "detection": _move(detection_csv),
        "trajectory": _move(trajectory_csv),
    }


def _septier_target_dir(system_name: str) -> Path:
    key = system_name.strip().lower()
    if key == "guardian":
        return GUARDIAN_DIR
    if key == "backpack":
        return BACKPACK_DIR
    raise HTTPException(status_code=400, detail="Sistema invalido. Usa guardian o backpack")


def _norm_col(name: object) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(name or "").strip().lower())


def _first_col(columns: Dict[str, str], candidates: List[str]) -> str:
    for c in candidates:
        col = columns.get(_norm_col(c), "")
        if col:
            return col
    return ""


def _septier_place_bucket(value: object) -> str:
    text = unicodedata.normalize("NFD", str(value or ""))
    text = "".join(ch for ch in text if unicodedata.category(ch) != "Mn")
    text = re.sub(r"\s+", " ", text.upper()).strip()
    if "SAN FELIPE" in text:
        return "SAN FELIPE"
    if re.search(r"BOULOGNE\s+SUR\s+MER|BOULOGNE", text):
        return "BOULOGNE SUR MER"
    if re.search(r"ALMA\s*FUERTE\s*II|ALMAFUERTE\s*II", text):
        return "ALMAFUERTE II"
    if re.search(r"ALMA\s*FUERTE|ALMAFUERTE", text):
        return "ALMAFUERTE I"
    if "SAN RAFAEL" in text:
        return "SAN RAFAEL"
    if re.search(r"REQUER|PCN|FISCAL|PERSONA PERDIDA", text):
        return "REQUERIMIENTOS"
    return "OTROS"


def _septier_is_penitentiary_bucket(bucket: str) -> bool:
    return bucket in {"SAN FELIPE", "BOULOGNE SUR MER", "ALMAFUERTE I", "ALMAFUERTE II", "SAN RAFAEL"}


def _safe_num(value: object) -> Optional[float]:
    if value is None:
        return None
    text = str(value).strip().replace(",", ".")
    if not text:
        return None
    try:
        return float(text)
    except Exception:
        return None


def _parse_datetime_fields(raw_dt: object, raw_date: object, raw_time: object) -> Tuple[str, str]:
    import pandas as pd

    if raw_dt is not None and str(raw_dt).strip():
        dt_obj = pd.to_datetime(raw_dt, errors="coerce")
        if not pd.isna(dt_obj):
            return dt_obj.strftime("%Y-%m-%d"), dt_obj.strftime("%H:%M:%S")

    date_str = str(raw_date or "").strip()
    time_str = str(raw_time or "").strip()

    if date_str:
        dt_obj = pd.to_datetime(date_str, errors="coerce")
        if not pd.isna(dt_obj):
            date_str = dt_obj.strftime("%Y-%m-%d")
    return date_str, time_str


def _digits_only(value: object) -> str:
    text = str(value or "").strip()
    if text.endswith(".0"):
        text = text[:-2]
    return re.sub(r"\D+", "", text)


def _id15(value: object) -> str:
    raw = str(value or "").strip()
    if raw.endswith(".0"):
        raw = raw[:-2]
    if "/" in raw:
        left_side = raw.split("/", 1)[0].strip()
        left_digits = re.sub(r"\D+", "", left_side)
        if re.fullmatch(r"[\d\s.,+\-]+", left_side) and len(left_digits) == 15:
            return left_digits
    digits = _digits_only(raw)
    return digits if len(digits) == 15 else ""


def _identity_keys(value: object) -> set:
    raw = str(value or "").strip()
    if not raw:
        return set()
    if raw.endswith(".0"):
        raw = raw[:-2]
    identifier = _id15(raw)
    if identifier:
        return {identifier}
    if "/" in raw:
        return set()
    digits = _digits_only(raw)
    numeric_like = bool(re.fullmatch(r"[\d\s.,+\-]+", raw))
    if numeric_like and digits:
        return {digits} if len(digits) == 15 else set()
    keys = {raw, raw.lower()}
    return {k for k in keys if k}


def _primary_identity_key(value: object) -> str:
    digits = _id15(value)
    if len(digits) == 15:
        return digits
    raw = str(value or "").strip()
    if raw.endswith(".0"):
        raw = raw[:-2]
    return raw.lower()


def _whitelist_base_identity_set() -> set:
    keys = set()
    for item in list_whitelist():
        keys.update(_identity_keys(item.get("device_id")))
    return keys


def _whitelist_identity_set() -> set:
    return _whitelist_base_identity_set()


def _is_whitelisted_identity(imsi: object, imei: object, whitelist_keys: Optional[set] = None) -> bool:
    return bool(_whitelist_decision(imsi, imei, whitelist_keys=whitelist_keys).get("is_whitelisted"))


def _septier_identity_sets(rows: List[Dict[str, object]]) -> Dict[str, set]:
    imsis = set()
    imeis = set()
    identities = set()
    for row in rows:
        imsi = _id15(row.get("imsi_mac"))
        imei = _id15(row.get("imei"))
        if len(imsi) == 15:
            imsis.add(imsi)
        if len(imei) == 15:
            imeis.add(imei)
        key = _operational_identity_key(imsi, imei)
        if key and not (key.startswith("raw:") and key == "raw:|"):
            identities.add(key)
    return {"imsi": imsis, "imei": imeis, "identities": identities}


def _septier_whitelist_metrics(
    source_rows: List[Dict[str, object]],
    net_rows: List[Dict[str, object]],
    whitelist_rows: List[Dict[str, object]],
) -> Dict[str, int]:
    source_sets = _septier_identity_sets(source_rows)
    net_sets = _septier_identity_sets(net_rows)
    whitelist_sets = _septier_identity_sets(whitelist_rows)
    return {
        "detecciones_brutas": len(source_rows),
        "detecciones_sin_duplicar": len(source_sets["identities"]),
        "coincidencias_lista_blanca": len(whitelist_sets["identities"]),
        "filas_lista_blanca": len(whitelist_rows),
        "detecciones_finales": len(net_rows),
        "identidades_finales": len(net_sets["identities"]),
        "no_coincidentes": len(net_sets["identities"]),
        "imsi_leidos": len(source_sets["imsi"]),
        "imsi_excluidos_lb": len(whitelist_sets["imsi"]),
        "imsi_netos": len(net_sets["imsi"]),
        "imei_leidos": len(source_sets["imei"]),
        "imei_excluidos_lb": len(whitelist_sets["imei"]),
        "imei_netos": len(net_sets["imei"]),
    }


def _whitelist_decision(
    imsi: object,
    imei: object,
    whitelist_keys: Optional[set] = None,
) -> Dict[str, object]:
    keys = whitelist_keys if whitelist_keys is not None else _whitelist_base_identity_set()
    imsi_keys = _identity_keys(imsi)
    imei_keys = _identity_keys(imei)
    imsi_hit = bool(imsi_keys & keys)
    imei_hit = bool(imei_keys & keys)
    match_by = []
    if imsi_hit:
        match_by.append("IMSI directo")
    if imei_hit:
        match_by.append("IMEI directo")
    matched_keys = sorted((imsi_keys | imei_keys) & keys)
    return {
        "is_whitelisted": bool(match_by),
        "match_by": " + ".join(match_by),
        "matched_keys": matched_keys,
    }


def _operational_identity_key(imsi: object, imei: object) -> str:
    imsi_key = _primary_identity_key(imsi)
    imei_key = _primary_identity_key(imei)
    if len(_digits_only(imsi_key)) == 15:
        return f"imsi:{imsi_key}"
    if len(_digits_only(imei_key)) == 15:
        return f"imei:{imei_key}"
    return f"raw:{imsi_key}|{imei_key}"


def _whitelist_match_details(imsi: object, imei: object) -> List[Dict[str, object]]:
    lookup_ids = sorted(_identity_keys(imsi) | _identity_keys(imei))
    matches = whitelist_matches_for_ids(lookup_ids) if lookup_ids else []
    imsi_keys = _identity_keys(imsi)
    imei_keys = _identity_keys(imei)
    out: List[Dict[str, object]] = []
    for match in matches:
        device_id = str(match.get("device_id") or "").strip()
        device_keys = _identity_keys(device_id)
        match_by = []
        if device_keys & imsi_keys:
            match_by.append("IMSI")
        if device_keys & imei_keys:
            match_by.append("IMEI")
        out.append({
            **match,
            "match_by": " + ".join(match_by) or "identidad",
            "source_label": str(match.get("original_filename") or "Lista Blanca manual").strip(),
        })
    return out


def _whitelist_match_reason(matches: List[Dict[str, object]]) -> str:
    descriptions = sorted({
        str(match.get("description") or "").strip()
        for match in matches
        if str(match.get("description") or "").strip()
    })
    if descriptions:
        return " | ".join(descriptions)
    sources = sorted({
        str(match.get("source_label") or match.get("original_filename") or "").strip()
        for match in matches
        if str(match.get("source_label") or match.get("original_filename") or "").strip()
    })
    if sources:
        return "Coincide con Lista Blanca actual: " + " | ".join(sources)
    return "Coincide con Lista Blanca actual"


def _whitelist_match_trace(matches: List[Dict[str, object]]) -> str:
    rows = []
    seen = set()
    for match in matches:
        source = str(match.get("source_label") or match.get("original_filename") or "Lista Blanca manual").strip()
        description = str(match.get("description") or "").strip()
        match_by = str(match.get("match_by") or "identidad").strip()
        device_id = str(match.get("device_id") or "").strip()
        parts = [source]
        if description:
            parts.append(description)
        if device_id:
            parts.append(f"{match_by}: {device_id}")
        text = " | ".join(parts)
        if text and text not in seen:
            seen.add(text)
            rows.append(text)
    return " || ".join(rows) or _whitelist_match_reason(matches)


def _counter_known_values(counter: Optional[Counter[str]], exclude: str = "") -> str:
    if not counter:
        return "-"
    values = []
    seen = set()
    for value, _count in counter.most_common():
        key = _id15(value)
        if len(key) != 15 or key == exclude or key in seen:
            continue
        seen.add(key)
        values.append(key)
    return " | ".join(values) or "-"


def _identity_text_values(text: str, exclude: str = "") -> List[str]:
    values: List[str] = []
    seen = set()
    for part in str(text or "").split("|"):
        key = _id15(part.strip())
        if len(key) != 15 or key == exclude or key in seen:
            continue
        seen.add(key)
        values.append(key)
    return values


def _merge_identity_value_text(*texts: str, exclude: str = "") -> str:
    values: List[str] = []
    seen = set()
    for text in texts:
        for key in _identity_text_values(text, exclude=exclude):
            if key in seen:
                continue
            seen.add(key)
            values.append(key)
    return " | ".join(values) or "-"


def _dedupe_memory_rows(rows: List[Dict[str, object]]) -> List[Dict[str, object]]:
    deduped: List[Dict[str, object]] = []
    seen = set()
    for row in rows:
        key = (
            str(row.get("numero_informe") or ""),
            str(row.get("archivo_origen") or ""),
            _id15(row.get("imsi") or row.get("imsi_mac")),
            _id15(row.get("imei")),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(row)
    return deduped


def _septier_mutation_context(
    imsi: object,
    imei: object,
    current_seen_at: object,
    mem_imsi_rows: Dict[str, List[Dict[str, object]]],
    mem_imei_rows: Dict[str, List[Dict[str, object]]],
    imei_counts_by_imsi: Dict[str, Counter[str]],
    imsi_counts_by_imei: Dict[str, Counter[str]],
    det_rows_by_imsi: Dict[str, List[Dict[str, object]]],
    det_rows_by_imei: Dict[str, List[Dict[str, object]]],
) -> Optional[Dict[str, object]]:
    imsi_key = _id15(imsi)
    imei_key = _id15(imei)
    if len(imsi_key) != 15 or len(imei_key) != 15:
        return None

    current_dt = _parse_dt_value(current_seen_at)

    def was_seen_before(row: Dict[str, object]) -> bool:
        if not current_dt:
            return True
        row_dt = _parse_dt_value(row.get("last_update") or row.get("created_at"))
        return not row_dt or row_dt < current_dt

    previous_imei_rows = [
        row for row in [*mem_imsi_rows.get(imsi_key, []), *det_rows_by_imsi.get(imsi_key, [])]
        if was_seen_before(row) and _id15(row.get("imei")) and _id15(row.get("imei")) != imei_key
    ]
    previous_imsi_rows = [
        row for row in [*mem_imei_rows.get(imei_key, []), *det_rows_by_imei.get(imei_key, [])]
        if was_seen_before(row) and _id15(row.get("imsi") or row.get("imsi_mac")) and _id15(row.get("imsi") or row.get("imsi_mac")) != imsi_key
    ]
    previous_imeis = _merge_identity_value_text(
        _memory_known_values(previous_imei_rows, "imei"),
        "-" if current_dt else _counter_known_values(imei_counts_by_imsi.get(imsi_key), exclude=imei_key),
        exclude=imei_key,
    )
    previous_imsis = _merge_identity_value_text(
        _memory_known_values(previous_imsi_rows, "imsi"),
        "-" if current_dt else _counter_known_values(imsi_counts_by_imei.get(imei_key), exclude=imsi_key),
        exclude=imsi_key,
    )

    has_previous_imeis = previous_imeis != "-"
    has_previous_imsis = previous_imsis != "-"
    if not has_previous_imeis and not has_previous_imsis:
        return None

    if has_previous_imeis and has_previous_imsis:
        reason = "Mutacion IMSI/IMEI cruzada"
        previous_value = f"IMEI anterior: {previous_imeis} | IMSI anterior: {previous_imsis}"
    elif has_previous_imeis:
        reason = "Nuevo IMEI para IMSI conocido"
        previous_value = f"IMEI anterior: {previous_imeis}"
    else:
        reason = "Nuevo IMSI para IMEI conocido"
        previous_value = f"IMSI anterior: {previous_imsis}"

    return {
        "reason": reason,
        "previous_identity_value": previous_value,
        "memory_rows": _dedupe_memory_rows([*previous_imei_rows, *previous_imsi_rows]),
        "previous_imeis": previous_imeis,
        "previous_imsis": previous_imsis,
    }


def _network_text_category(text: object) -> str:
    value = str(text or "").lower()
    if any(token in value for token in ("penitenci", "penal", "almafuerte", "san felipe", "san rafael", "complejo")):
        return "penitentiary"
    if any(token in value for token in ("polic", "ministerio", "dpto", "departamento", "movilidad policial")):
        return "police"
    if any(token in value for token in ("empresa", "clisa", "fonther", "fronther", "ltn", "proveedor", "contrat")):
        return "company"
    return "general"


def _network_whitelist_info(matches: List[Dict[str, object]]) -> Dict[str, object]:
    text = " ".join(
        str(match.get(key) or "")
        for match in matches
        for key in ("description", "source_label", "original_filename", "device_type")
    )
    category = _network_text_category(text)
    match_types = sorted({
        part.strip()
        for match in matches
        for part in str(match.get("match_by") or "").split("+")
        if part.strip()
    })
    sources = sorted({
        str(match.get("source_label") or match.get("original_filename") or "Lista Blanca manual").strip()
        for match in matches
        if str(match.get("source_label") or match.get("original_filename") or "Lista Blanca manual").strip()
    })
    descriptions = sorted({
        str(match.get("description") or "").strip()
        for match in matches
        if str(match.get("description") or "").strip()
    })
    return {
        "category": category,
        "icon_hint": "shield" if category == "police" else "tower" if category == "penitentiary" else "person",
        "match_types": match_types,
        "sources": sources,
        "descriptions": descriptions,
        "source_count": len(sources),
        "description": " | ".join(descriptions[:3]) or "Coincide con Lista Blanca actual",
        "source_label": " | ".join(sources[:3]) or "Lista Blanca actual",
    }


def _historial_memory_maps() -> Tuple[Dict[str, set], set, Dict[str, List[Dict[str, object]]], Dict[str, List[Dict[str, object]]]]:
    mem_imsi: Dict[str, set] = {}
    mem_imei = set()
    mem_imsi_rows: Dict[str, List[Dict[str, object]]] = defaultdict(list)
    mem_imei_rows: Dict[str, List[Dict[str, object]]] = defaultdict(list)
    for r in get_historial_informes():
        imsi = _primary_identity_key(r.get("imsi"))
        imei = _primary_identity_key(r.get("imei"))
        if imsi:
            mem_imsi.setdefault(imsi, set())
            mem_imsi_rows[imsi].append(r)
            if imei:
                mem_imsi[imsi].add(imei)
        if imei:
            mem_imei.add(imei)
            mem_imei_rows[imei].append(r)
    return mem_imsi, mem_imei, mem_imsi_rows, mem_imei_rows


def _memory_source_text(rows: List[Dict[str, object]]) -> str:
    return " | ".join(
        sorted({
            f"{m.get('numero_informe') or '-'} / {m.get('archivo_origen') or '-'}"
            for m in rows
        })
    ) or "Memoria Sellada"


def _memory_history_source_text(rows: List[Dict[str, object]]) -> str:
    histories = sorted({
        str(m.get("archivo_origen") or "").strip()
        for m in rows
        if str(m.get("archivo_origen") or "").strip()
    })
    return " | ".join(histories) or "-"


def _memory_known_values(rows: List[Dict[str, object]], field: str) -> str:
    if field == "imsi":
        fields = ("imsi", "imsi_mac")
    elif field == "imei":
        fields = ("imei",)
    else:
        fields = (field,)
    values = sorted({
        _primary_identity_key(next((row.get(name) for name in fields if row.get(name)), ""))
        for row in rows
        if _primary_identity_key(next((row.get(name) for name in fields if row.get(name)), ""))
    })
    return " | ".join(values) or "-"


def _build_septier_audit_result(files: List[Dict[str, str]], ignore_memory: bool = False) -> Dict[str, List[Dict[str, object]]]:
    source_rows = get_septier_detections_by_files(files)
    identity_memory = _septier_identity_memory()
    rows = [_with_resolved_septier_identity(r, identity_memory) for r in source_rows]

    whitelist = _whitelist_identity_set()
    mem_imsi, mem_imei, mem_imsi_rows, mem_imei_rows = _historial_memory_maps()
    imei_counts_by_imsi, imsi_counts_by_imei = _septier_identity_memory()
    det_rows_by_imsi, det_rows_by_imei = _septier_identity_source_maps()

    nuevos: List[Dict[str, object]] = []
    mutaciones: List[Dict[str, object]] = []
    descartados: List[Dict[str, object]] = []
    coincidencias_data_externa: List[Dict[str, object]] = []
    seen_this_batch = set()

    for r in rows:
        imsi = str(r.get("imsi_mac") or "").strip()
        imei = str(r.get("imei") or "").strip()
        imsi_key = _primary_identity_key(imsi)
        imei_key = _primary_identity_key(imei)

        if not imsi and not imei:
            continue

        batch_key = _operational_identity_key(imsi, imei)
        if batch_key in seen_this_batch:
            continue
        seen_this_batch.add(batch_key)

        if not ignore_memory:
            mutation_context = _septier_mutation_context(
                imsi,
                imei,
                r.get("last_update"),
                mem_imsi_rows,
                mem_imei_rows,
                imei_counts_by_imsi,
                imsi_counts_by_imei,
                det_rows_by_imsi,
                det_rows_by_imei,
            )
            if mutation_context:
                matches = _whitelist_match_details(imsi, imei)
                r["reason"] = mutation_context["reason"]
                r["memory_matches"] = mutation_context["memory_rows"]
                r["memory_source"] = _memory_history_source_text(r["memory_matches"])
                r["previous_identity_value"] = mutation_context["previous_identity_value"]
                r["whitelist_matches"] = matches
                r["whitelist_source"] = " | ".join(
                    sorted({str(m.get("source_label") or "") for m in matches if m.get("source_label")})
                ) or ""
                r["whitelist_match_by"] = " | ".join(
                    sorted({str(m.get("match_by") or "") for m in matches if m.get("match_by")})
                ) or ""
                mutaciones.append(r)
                continue

        if _is_whitelisted_identity(imsi, imei, whitelist):
            matches = _whitelist_match_details(imsi, imei)
            r["whitelist_matches"] = matches
            r["reason"] = _whitelist_match_reason(matches)
            r["whitelist_source"] = " | ".join(
                sorted({str(m.get("source_label") or "") for m in matches if m.get("source_label")})
            ) or "Lista Blanca actual"
            r["whitelist_match_by"] = " | ".join(
                sorted({str(m.get("match_by") or "") for m in matches if m.get("match_by")})
            ) or "identidad"
            descartados.append(r)
            continue

        external_matches = external_identity_lookup(imsi, imei)
        if external_matches:
            imsi_key_digits = _id15(imsi)
            imei_key_digits = _id15(imei)
            enriched_matches = []
            for match in external_matches:
                match_imsi = _id15(match.get("imsi"))
                match_imei = _id15(match.get("imei"))
                match_kind = []
                if imsi_key_digits and match_imsi and imsi_key_digits == match_imsi:
                    match_kind.append("IMSI")
                if imei_key_digits and match_imei and imei_key_digits == match_imei:
                    match_kind.append("IMEI")
                enriched_matches.append({**match, "match_kind": " + ".join(match_kind) or "identidad"})
            r["reason"] = "Coincide con Data Externa Postgres - requiere revision operativa"
            r["external_matches"] = enriched_matches
            r["external_match_kind"] = ", ".join(sorted({m.get("match_kind", "") for m in enriched_matches if m.get("match_kind")})) or "identidad"
            first_match = enriched_matches[0]
            r["external_prestataria"] = first_match.get("prestataria") or "DESCONOCIDA"
            r["external_estado"] = first_match.get("estado") or "-"
            r["external_modelo"] = first_match.get("modelo") or "-"
            coincidencias_data_externa.append(r)
            continue

        if ignore_memory:
            nuevos.append(r)
            continue

        is_imsi_known = imsi_key in mem_imsi
        is_imei_known = imei_key in mem_imei

        if not is_imsi_known and not is_imei_known:
            nuevos.append(r)
        elif is_imsi_known or is_imei_known:
            r["reason"] = "Ya informado"
            r["memory_matches"] = [*mem_imsi_rows.get(imsi_key, []), *mem_imei_rows.get(imei_key, [])]
            r["memory_source"] = _memory_history_source_text(r["memory_matches"])
            descartados.append(r)
        else:
            r["reason"] = "Ya informado"
            descartados.append(r)

    return {
        "nuevos": nuevos,
        "mutaciones": mutaciones,
        "descartados": descartados,
        "coincidencias_data_externa": coincidencias_data_externa,
    }


def _septier_row_matches_operational_key(row: Dict[str, object], operational_key: str) -> bool:
    kind, _, value = operational_key.partition(":")
    if kind == "imsi":
        return _primary_identity_key(row.get("imsi_mac")) == value
    if kind == "imei":
        return _primary_identity_key(row.get("imei")) == value
    return _operational_identity_key(row.get("imsi_mac"), row.get("imei")) == operational_key


def _parse_dt_value(value: object) -> Optional[dt.datetime]:
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00")[:19])
        return parsed.replace(tzinfo=None)
    except Exception:
        pass
    for fmt in ("%Y-%m-%d %H:%M:%S", "%d/%m/%Y %H:%M:%S", "%d-%m-%Y %H:%M:%S", "%Y-%m-%d"):
        try:
            return dt.datetime.strptime(text[:19], fmt).replace(tzinfo=None)
        except Exception:
            continue
    return None


def _format_forensic_dt(value: object) -> str:
    parsed = _parse_dt_value(value)
    if parsed:
        return parsed.strftime("%Y-%m-%d %H:%M:%S")
    return str(value or "").strip() or "--- S/D ---"


def _carrier_from_imsi_value(imsi_value: str) -> str:
    imsi = _id15(imsi_value)
    if imsi.startswith(("72231", "72232", "72233")):
        return "CLARO"
    if imsi.startswith(("72201", "72207")):
        return "MOVISTAR"
    if imsi.startswith(("72234", "72203", "72235")):
        return "PERSONAL"
    return "OTRO"


def _centroid_from_wkt(multipolygon: object) -> Tuple[str, str]:
    text = str(multipolygon or "").strip()
    if not text:
        return "--- S/D ---", "--- S/D ---"
    try:
        import shapely.wkt

        geom = shapely.wkt.loads(text)
        centroid = geom.centroid
        return f"{centroid.y:.6f}", f"{centroid.x:.6f}"
    except Exception:
        return "--- S/D ---", "--- S/D ---"


def _extract_septier_rows(csv_path: Path, source_name: str, location: str = "", file_hash: str = "") -> List[Dict[str, object]]:
    import pandas as pd
    import shapely.wkt

    df = pd.read_csv(csv_path, sep=None, engine="python", encoding="latin-1")
    df = clean_columns(df)
    if df.shape[1] > 1 and _norm_col(str(df.columns[0])) == "eventtime":
        non_empty_after_first = df.iloc[:, 1:].fillna("").astype(str).apply(
            lambda col: col.str.strip().ne("").any()
        ).any()
        first_values = df.iloc[:, 0].fillna("").astype(str)
        encapsulated_rows = first_values.str.contains(",", regex=False).sum()
        if not non_empty_after_first and encapsulated_rows:
            repaired_rows: List[Dict[str, object]] = []
            header = [str(c) for c in df.columns]
            for value in first_values:
                raw = str(value).strip()
                if not raw:
                    continue
                parsed = next(csv.reader([raw]))
                if len(parsed) < len(header):
                    parsed += [""] * (len(header) - len(parsed))
                repaired_rows.append(dict(zip(header, parsed[:len(header)])))
            df = clean_columns(pd.DataFrame(repaired_rows, columns=header))
    cols = {_norm_col(c): c for c in df.columns}

    def get_col(names, default=None):
        if isinstance(names, str):
            names = [names]
        for n in names:
            col = cols.get(_norm_col(n))
            if col is not None and col in df.columns:
                return col
        return default

    def clean_id(val: object) -> str:
        if pd.isna(val):
            return ""
        s = str(val).strip()
        if s.endswith(".0"):
            return s[:-2]
        return s if s.lower() != "nan" else ""

    def clean_text(val: object) -> str:
        if pd.isna(val):
            return ""
        s = str(val).strip()
        return "" if s.lower() == "nan" else s

    out: List[Dict[str, object]] = []
    for _, r in df.iterrows():
        lat = _safe_num(r.get(get_col(["latitud", "latitude", "lat"])))
        lon = _safe_num(r.get(get_col(["longitud", "longitude", "lon", "lng"])))
        multipolygon = str(r.get(get_col(["multipolygon", "poligono"]), "")).strip()

        # Si no hay lat/lon pero hay multipolygon, calcular centroide
        if (lat is None or lon is None) and multipolygon:
            try:
                geom = shapely.wkt.loads(multipolygon)
                centroid = geom.centroid
                lat, lon = centroid.y, centroid.x
            except Exception:
                lat, lon = None, None

        has_valid_coords = lat is not None and lon is not None and -90 <= lat <= 90 and -180 <= lon <= 180
        if not has_valid_coords:
            lat, lon = None, None

        # last_update puede ser timestamp o texto
        last_update = r.get(get_col(["last_update", "event time", "timestamp", "fecha", "time"]), "")
        if last_update:
            try:
                last_update = pd.to_datetime(last_update, errors="coerce")
                if pd.isna(last_update):
                    last_update = ""
                else:
                    last_update = last_update.isoformat()
            except Exception:
                last_update = str(last_update)

        imsi_mac = clean_id(r.get(get_col(["imsi", "mac", "imsi_mac", "imsi / mac", "imsi mac"])))
        imei = clean_id(r.get(get_col(["imei", "device_id", "device id"])))
        model = clean_text(r.get(get_col(["model", "modelo", "imei name", "device model"])))
        operation = clean_text(r.get(get_col(["operation", "operacion", "op / evento", "evento", "event"])))
        orig_lac = clean_text(r.get(get_col(["orig_lac", "orig lac", "original_lac", "lac", "lac_origen", "original lac"])))
        cell_id = clean_id(r.get(get_col(["cell_id", "cell id", "cid", "cell", "id celda", "id_de_celda", "eci", "enb"])))
        event_type = clean_text(r.get(get_col(["event_type", "event type", "evento", "event"])))
        distance = _safe_num(r.get(get_col(["distance", "distancia", "distance_m", "distancia_m"])))
        target_latitude = _safe_num(r.get(get_col(["target latitude", "target_latitude", "latitud objetivo", "target lat"])))
        target_longitude = _safe_num(r.get(get_col(["target longitude", "target_longitude", "longitud objetivo", "target lon", "target lng"])))
        minor_radius_a = _safe_num(r.get(get_col(["minor radius a", "minor_radius_a"])))
        major_radius_a = _safe_num(r.get(get_col(["major radius a", "major_radius_a"])))
        minor_radius_b = _safe_num(r.get(get_col(["minor radius b", "minor_radius_b"])))
        major_radius_b = _safe_num(r.get(get_col(["major radius b", "major_radius_b"])))
        start_angle = _safe_num(r.get(get_col(["start angle", "start_angle"])))
        stop_angle = _safe_num(r.get(get_col(["stop angle", "stop_angle"])))
        orientation = _safe_num(r.get(get_col(["orientation", "orientacion"])))
        if not any([imsi_mac, imei, model, operation, orig_lac, cell_id, multipolygon, last_update, event_type]):
            continue

        out.append({
            "latitud": round(float(lat), 6) if lat is not None else None,
            "longitud": round(float(lon), 6) if lon is not None else None,
            "imsi_mac": imsi_mac,
            "imei": imei,
            "model": model,
            "operation": operation,
            "orig_lac": orig_lac,
            "cell_id": cell_id,
            "multipolygon": multipolygon,
            "last_update": last_update,
            "event_type": event_type,
            "source": source_name.lower(),
            "archivo_origen": str(csv_path.name),
            "hash_sha256": file_hash,
            "location": location.strip(),
            "distance": distance,
            "target_latitude": target_latitude,
            "target_longitude": target_longitude,
            "minor_radius_a": minor_radius_a,
            "major_radius_a": major_radius_a,
            "minor_radius_b": minor_radius_b,
            "major_radius_b": major_radius_b,
            "start_angle": start_angle,
            "stop_angle": stop_angle,
            "orientation": orientation,
        })
    return out


def _load_nexa_multipolygon_dataframe(content: bytes, filename: str):
    import io
    import pandas as pd
    try:
        from shapely import from_wkt  # type: ignore
    except ImportError:
        from_wkt = None
        import shapely.wkt as shapely_wkt

    suffix = Path(filename or "").suffix.lower()
    if suffix in {".xlsx", ".xls"}:
        raw = pd.read_excel(io.BytesIO(content), header=None)
        if raw.shape[1] == 1:
            csv_rows = list(csv.reader(raw.iloc[:, 0].fillna("").astype(str).tolist()))
            df = pd.DataFrame(csv_rows[1:], columns=csv_rows[0]) if csv_rows else pd.DataFrame()
        else:
            df = pd.read_excel(io.BytesIO(content), dtype=str)
    else:
        text = content.decode("utf-8-sig", errors="ignore")
        if not text.strip():
            text = content.decode("latin-1", errors="ignore")
        df = pd.read_csv(io.StringIO(text), sep=None, engine="python", dtype=str)
    df = clean_columns(df.fillna(""))
    cols = {_norm_col(c): c for c in df.columns}

    def col(name: str) -> str:
        return cols.get(_norm_col(name), "")

    event_col = col("Event Type")
    if event_col:
        df = df[df[event_col].astype(str).str.upper().eq("LUPD")].copy()

    multipolygon_col = col("Multipolygon")
    if not multipolygon_col:
        raise HTTPException(status_code=400, detail="El archivo no contiene columna Multipolygon")

    for numeric_name in [
        "Target Latitude", "Target Longitude",
        "Latitude", "Longitude", "Distance",
        "Minor Radius A", "Major Radius A",
        "Minor Radius B", "Major Radius B",
        "Start Angle", "Stop Angle", "Orientation",
    ]:
        c = col(numeric_name)
        if c:
            df[c] = pd.to_numeric(df[c].astype(str).str.replace(",", ".", regex=False), errors="coerce")

    def parse_wkt_geometry(value: object):
        text = str(value or "").strip()
        if not text:
            return None
        try:
            if from_wkt is not None:
                return from_wkt(text, on_invalid="fix")
            return shapely_wkt.loads(text)
        except TypeError:
            return from_wkt(text) if from_wkt is not None else shapely_wkt.loads(text)
        except Exception:
            return None

    df["geometry_wgs84"] = df[multipolygon_col].map(parse_wkt_geometry)
    return df[df["geometry_wgs84"].notna()].copy(), cols


def _nexa_build_overlap_grid(df, cols: Dict[str, str], imsi: str = "", resolution_m: float = 5.0, weighted: bool = False) -> Dict[str, object]:
    import numpy as np
    from shapely import contains_xy
    from shapely.ops import transform
    from pyproj import Transformer

    imsi_col = cols.get(_norm_col("IMSI"), "")
    if imsi and imsi_col:
        work = df[df[imsi_col].astype(str).eq(str(imsi))].copy()
    else:
        work = df.copy()
    if work.empty:
        raise HTTPException(status_code=400, detail=f"No hay eventos LUPD con Multipolygon para IMSI {imsi or 'seleccionado'}")

    resolution_m = max(2.0, min(float(resolution_m or 5.0), 50.0))
    project_to_utm = Transformer.from_crs("EPSG:4326", "EPSG:32719", always_xy=True).transform
    project_to_wgs84 = Transformer.from_crs("EPSG:32719", "EPSG:4326", always_xy=True).transform
    geoms = [transform(project_to_utm, geom) for geom in work["geometry_wgs84"]]

    minx = min(p.bounds[0] for p in geoms)
    miny = min(p.bounds[1] for p in geoms)
    maxx = max(p.bounds[2] for p in geoms)
    maxy = max(p.bounds[3] for p in geoms)

    xs = np.arange(minx, maxx + resolution_m, resolution_m)
    ys = np.arange(miny, maxy + resolution_m, resolution_m)
    xx, yy = np.meshgrid(xs, ys)
    heat = np.zeros(xx.shape, dtype=float)

    if weighted:
        areas = np.array([max(float(p.area), 0.0001) for p in geoms], dtype=float)
        weights = np.median(areas) / areas
    else:
        weights = np.ones(len(geoms))

    for geom, weight in zip(geoms, weights):
        heat += contains_xy(geom, xx, yy).astype(float) * weight

    max_heat = float(heat.max()) if heat.size else 0.0
    heat_norm = heat / max_heat if max_heat else heat
    cells: List[Dict[str, object]] = []
    max_cells = 8000
    for y_idx in range(max(0, len(ys) - 1)):
        for x_idx in range(max(0, len(xs) - 1)):
            value = float(heat[y_idx, x_idx])
            if value <= 0:
                continue
            corners_utm = [
                (xs[x_idx], ys[y_idx]),
                (xs[x_idx + 1], ys[y_idx]),
                (xs[x_idx + 1], ys[y_idx + 1]),
                (xs[x_idx], ys[y_idx + 1]),
            ]
            corners = []
            for x, y in corners_utm:
                lon, lat = project_to_wgs84(x, y)
                corners.append({"lat": round(float(lat), 7), "lon": round(float(lon), 7)})
            cells.append({
                "corners": corners,
                "heat": value,
                "heat_norm": round(float(heat_norm[y_idx, x_idx]), 4) if max_heat else 0,
            })
    if len(cells) > max_cells:
        cells = sorted(cells, key=lambda c: (float(c["heat_norm"]), float(c["heat"])), reverse=True)[:max_cells]

    imsis = []
    if imsi_col:
        imsis = sorted({str(v).strip() for v in work[imsi_col].fillna("").tolist() if str(v).strip()})

    return {
        "imsi": str(imsi or ""),
        "imsis": imsis[:200],
        "imsi_total": len(imsis),
        "events": int(len(work)),
        "resolution_m": resolution_m,
        "weighted": bool(weighted),
        "max_overlap": max_heat,
        "cells": cells,
        "cell_count": len(cells),
        "interpretation": "H(x,y)=sum_i I[(x,y) pertenece a Polygon_i]. H no es probabilidad; indica superposicion de areas de estimacion del sistema.",
    }


@app.on_event("startup")
def startup() -> None:
    OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    SKYEYE_GENERAL_DIR.mkdir(parents=True, exist_ok=True)
    SEPTIER_DIR.mkdir(parents=True, exist_ok=True)
    GUARDIAN_DIR.mkdir(parents=True, exist_ok=True)
    BACKPACK_DIR.mkdir(parents=True, exist_ok=True)
    OBJECTIVE_HISTORY_DIR.mkdir(parents=True, exist_ok=True)
    WHITELIST_UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
    (REPO_ROOT / "app/templates").mkdir(parents=True, exist_ok=True)
    init_db()
    ensure_default_user()
    _bootstrap_initial_run()


def _require_auth(request: Request, authorization: str = Header(default="")) -> Dict[str, object]:
    if RELATIONAL_STANDALONE_ENABLED and _is_local_request(request):
        cookie_token = request.cookies.get(SESSION_COOKIE_NAME, "").strip()
        if cookie_token:
            user = get_token_user(cookie_token)
            if user:
                return user
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Falta token Bearer")
    token = authorization.replace("Bearer ", "", 1).strip()
    user = get_token_user(token)
    if not user:
        raise HTTPException(status_code=401, detail="Token invalido o expirado")
    return user


def _require_admin(user: Dict[str, object] = Depends(_require_auth)) -> Dict[str, object]:
    roles = [str(r).lower() for r in user.get("roles", [])]
    if "admin" not in roles:
        raise HTTPException(status_code=403, detail="Solo admin puede realizar esta accion")
    return user


def _require_edit(user: Dict[str, object] = Depends(_require_auth)) -> Dict[str, object]:
    roles = [str(r).lower() for r in user.get("roles", [])]
    if "admin" not in roles and "analista" not in roles:
        raise HTTPException(status_code=403, detail="Permisos insuficientes para modificar datos")
    return user


@app.post("/api/septier/nexa/multipolygon-heatmap")
async def api_nexa_multipolygon_heatmap(
    file: UploadFile = File(...),
    imsi: str = Form(""),
    resolution_m: float = Form(5.0),
    weighted: bool = Form(False),
    user=Depends(_require_auth),
):
    if not file.filename:
        raise HTTPException(status_code=400, detail="Sube un archivo history para calcular concentracion Multipolygon")
    content = await file.read()
    _scan_uploaded_bytes(content, file.filename or "archivo", "nexa_multipolygon_heatmap", user)
    if not content:
        raise HTTPException(status_code=400, detail="El archivo esta vacio")
    try:
        df, cols = _load_nexa_multipolygon_dataframe(content, file.filename)
        result = _nexa_build_overlap_grid(df, cols, imsi=imsi.strip(), resolution_m=resolution_m, weighted=weighted)
    except HTTPException:
        raise
    except ImportError as exc:
        raise HTTPException(status_code=500, detail=f"Falta dependencia NEXA Multipolygon: {exc}")
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"No se pudo calcular heatmap Multipolygon: {exc}")
    result.update({"filename": Path(file.filename).name})
    return result


app.mount("/assets", StaticFiles(directory="app/frontend/assets", check_dir=False), name="assets")
app.mount("/ui", StaticFiles(directory="app/frontend", html=True), name="ui")


def _auth_token_from_request(request: Request) -> str:
    authorization = request.headers.get("authorization", "")
    if authorization.startswith("Bearer "):
        return authorization.replace("Bearer ", "", 1).strip()
    return request.cookies.get(SESSION_COOKIE_NAME, "").strip()


def _require_output_auth(request: Request) -> Dict[str, object]:
    token = _auth_token_from_request(request)
    user = get_token_user(token) if token else None
    if not user:
        raise HTTPException(status_code=401, detail="Sesion requerida para acceder a salidas protegidas")
    return user


async def honeypot_probe(request: Request):
    token = _auth_token_from_request(request)
    user = get_token_user(token) if token else None
    username = str((user or {}).get("username", "")) if user else ""
    source_ip = _request_source_ip(request)
    user_agent = request.headers.get("user-agent", "")
    path = request.url.path
    _strict_block_actor(username, source_ip, f"Honeypot solicitado: {path}")
    try:
        record_security_event(
            event_type="honeypot_probe",
            severity="critical",
            username=username,
            source_ip=source_ip,
            user_agent=user_agent,
            detail=f"Ruta trampa solicitada: {request.method} {path}",
        )
    except Exception:
        pass
    try:
        _send_security_telegram_alert(
            "\n".join(
                [
                    "ALERTA DE SEGURIDAD - Honeypot",
                    f"Ruta: {request.method} {path}",
                    f"Usuario: {username or '-'}",
                    f"IP: {source_ip or '-'}",
                    f"Fecha Argentina: {_security_local_time_text()}",
                ]
            )
        )
    except Exception:
        pass
    return _security_canary_response(
        event_type="honeypot_probe",
        rule="honeypot_probe",
        username=username,
        source_ip=source_ip,
        path=path,
        user_agent=user_agent,
    )


for _honeypot_path in (
    "/adminer.php",
    "/phpmyadmin",
    "/phpmyadmin/",
    "/wp-admin",
    "/wp-login.php",
    "/backup.zip",
    "/backup.sql",
    "/db.sql",
    "/database.sql",
    "/dump.sql",
    "/.env",
    "/config.php",
):
    app.add_api_route(
        _honeypot_path,
        honeypot_probe,
        methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
        include_in_schema=False,
    )


@app.get("/outputs/{relative_path:path}")
def protected_output_file(relative_path: str, request: Request):
    _require_output_auth(request)
    file_path = (OUTPUTS_DIR / relative_path).resolve()
    try:
        file_path.relative_to(OUTPUTS_DIR.resolve())
    except Exception:
        raise HTTPException(status_code=400, detail="Ruta invalida")
    if not file_path.exists() or not file_path.is_file():
        raise HTTPException(status_code=404, detail="Archivo no encontrado")
    inline_extensions = {".html", ".htm", ".svg", ".txt", ".json", ".xml", ".kml", ".pdf"}
    if file_path.suffix.lower() in inline_extensions:
        response = FileResponse(file_path)
        response.headers["Content-Disposition"] = f'inline; filename="{file_path.name}"'
        return response
    return FileResponse(file_path, filename=file_path.name)


@app.get("/")
def root():
    response = FileResponse("app/frontend/red_operativa.html")
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    return response


@app.get("/red-operativa")
def red_operativa_root():
    response = FileResponse("app/frontend/red_operativa.html")
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    return response


@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "app_version": "red-operativa-relacional-v1",
    }


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",", 1)[0].strip()
    return request.client.host if request.client else ""


def _localize_security_times(items: List[Dict[str, object]]) -> List[Dict[str, object]]:
    tz_ar = dt.timezone(dt.timedelta(hours=-3))
    for item in items:
        for key in ("created_at", "blocked_until", "lifted_at"):
            raw_dt = item.get(key)
            if isinstance(raw_dt, dt.datetime):
                item[key] = raw_dt.astimezone(tz_ar).strftime("%Y-%m-%d %H:%M:%S")
            elif isinstance(raw_dt, str):
                try:
                    parsed = dt.datetime.strptime(raw_dt, "%Y-%m-%d %H:%M:%S").replace(tzinfo=dt.timezone.utc)
                    item[key] = parsed.astimezone(tz_ar).strftime("%Y-%m-%d %H:%M:%S")
                except Exception:
                    pass
    return items


def _send_security_telegram_alert(text: str) -> Tuple[bool, str]:
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return False, "Variables Telegram incompletas"
    try:
        payload = urllib.parse.urlencode(
            {
                "chat_id": TELEGRAM_CHAT_ID,
                "text": text[:3500],
                "disable_web_page_preview": "true",
            }
        ).encode("utf-8")
        req = urllib.request.Request(
            f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
            data=payload,
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        with urllib.request.urlopen(req, timeout=8) as response:
            body = response.read(500).decode("utf-8", errors="replace")
            return 200 <= int(response.status) < 300, body
    except Exception as exc:
        return False, str(exc)


def _security_local_time_text() -> str:
    tz_ar = dt.timezone(dt.timedelta(hours=-3))
    return dt.datetime.now(tz_ar).strftime("%Y-%m-%d %H:%M:%S UTC-3")


def _record_super_admin_security_event(
    event_type: str,
    username: str,
    source_ip: str,
    user_agent: str,
    detail: str,
) -> None:
    try:
        record_security_event(
            event_type=event_type,
            severity="critical",
            username=username,
            source_ip=source_ip,
            user_agent=user_agent,
            detail=detail,
        )
    except Exception:
        pass
    sent, send_detail = _send_security_telegram_alert(
        "\n".join(
            [
                "ALERTA CRITICA - Detection of Signals",
                f"Evento: {event_type}",
                f"Usuario: {username}",
                f"IP: {source_ip or '-'}",
                f"Detalle: {detail or '-'}",
                f"Fecha Argentina: {_security_local_time_text()}",
            ]
        )
    )
    if not sent:
        try:
            record_security_event(
                event_type="telegram_alert_failed",
                severity="warning",
                username=username,
                source_ip=source_ip,
                user_agent=user_agent,
                detail=send_detail[:500],
            )
        except Exception:
            pass


def _notify_successful_login(user: Dict[str, object], source_ip: str, user_agent: str) -> None:
    if not TELEGRAM_NOTIFY_LOGINS:
        return
    try:
        roles = ", ".join([str(r).upper() for r in user.get("roles", [])]) or "-"
        sent, detail = _send_security_telegram_alert(
            "\n".join(
                [
                    "INICIO DE SESION - Detection of Signals",
                    f"Usuario: {user.get('username', '-')}",
                    f"Nombre: {user.get('full_name', '-') or '-'}",
                    f"Rol(es): {roles}",
                    f"IP: {source_ip or '-'}",
                    f"Fecha Argentina: {_security_local_time_text()}",
                ]
            )
        )
        if not sent:
            record_security_event(
                event_type="telegram_login_alert_failed",
                severity="warning",
                username=str(user.get("username", "")),
                source_ip=source_ip,
                user_agent=user_agent,
                detail=detail[:500],
            )
    except Exception:
        pass


def _record_security_event_safe(event_type: str, username: str, detail: str, severity: str = "info") -> None:
    try:
        record_security_event(
            event_type=event_type,
            severity=severity,
            username=username,
            detail=detail,
        )
    except Exception:
        pass


def _new_mfa_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _mfa_otpauth_uri(username: str, secret: str) -> str:
    label = urllib.parse.quote(f"Detection of Signals:{username}")
    issuer = urllib.parse.quote("Detection of Signals")
    return f"otpauth://totp/{label}?secret={secret}&issuer={issuer}&digits=6&period=30"


def _totp_code(secret: str, counter: int) -> str:
    padded = secret.strip().replace(" ", "").upper()
    padded += "=" * ((8 - len(padded) % 8) % 8)
    key = base64.b32decode(padded, casefold=True)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, "sha1").digest()
    offset = digest[-1] & 0x0F
    code_int = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code_int % 1000000).zfill(6)


def _verify_totp(secret: str, code: str, window: int = 1) -> bool:
    clean_code = re.sub(r"\D+", "", code or "")
    if len(clean_code) != 6 or not secret:
        return False
    current = int(time.time() // 30)
    for drift in range(-window, window + 1):
        try:
            if hmac.compare_digest(_totp_code(secret, current + drift), clean_code):
                return True
        except Exception:
            return False
    return False


def _cleanup_mfa_login_tickets() -> None:
    cleanup_mfa_login_tickets()


def _create_mfa_login_ticket(user: Dict[str, object], source_ip: str, user_agent: str) -> str:
    _cleanup_mfa_login_tickets()
    ticket = secrets.token_urlsafe(32)
    create_mfa_login_ticket(
        ticket=ticket,
        username=str(user.get("username", "")),
        source_ip=source_ip,
        user_agent=user_agent,
        ttl_seconds=MFA_LOGIN_TICKET_TTL_SECONDS,
    )
    return ticket


def _set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=token,
        max_age=TOKEN_TTL_HOURS * 3600,
        httponly=True,
        secure=SESSION_COOKIE_SECURE,
        samesite="strict",
        path="/",
    )


def _clear_session_cookie(response: Response) -> None:
    response.delete_cookie(key=SESSION_COOKIE_NAME, path="/")


def _issue_login_token(
    user: Dict[str, object],
    source_ip: str,
    user_agent: str,
    response: Optional[Response] = None,
) -> Dict[str, object]:
    token = secrets.token_urlsafe(32)
    store_token(token, user)
    if response is not None:
        _set_session_cookie(response, token)
    try:
        record_login_attempt(str(user.get("username", "")), True, "ok", source_ip, user_agent)
        record_login_event(user, source_ip=source_ip, user_agent=user_agent)
    except Exception:
        pass
    _notify_successful_login(user, source_ip, user_agent)
    return {"token": token, "user": user}


@app.post("/api/auth/login")
def login(payload: LoginRequest, request: Request, response: Response):
    username = payload.username.strip()
    source_ip = _client_ip(request)
    user_agent = request.headers.get("user-agent", "")
    is_super_admin = is_super_admin_username(username)
    active_block = get_active_security_block(username="" if is_super_admin else username, source_ip=source_ip)
    user = authenticate_user(username, payload.password) if is_super_admin else None

    if active_block and not (is_super_admin and user):
        try:
            record_login_attempt(username, False, f"blocked_{active_block.get('kind')}", source_ip, user_agent)
        except Exception:
            pass
        if is_super_admin:
            _record_super_admin_security_event(
                "super_admin_blocked_attempt",
                username,
                source_ip,
                user_agent,
                f"Intento contra super admin desde origen bloqueado ({active_block.get('kind')})",
            )
        raise HTTPException(status_code=423, detail="Acceso bloqueado temporalmente. Contacta a un administrador.")

    if user and active_block:
        _record_super_admin_security_event(
            "super_admin_login_from_blocked_ip",
            username,
            source_ip,
            user_agent,
            f"Clave correcta desde IP con bloqueo activo ({active_block.get('kind')}); acceso permitido por regla super admin",
        )

    if not is_super_admin:
        user = authenticate_user(username, payload.password)
    if not user:
        try:
            created_blocks = register_failed_login_attempt(username, source_ip=source_ip, user_agent=user_agent)
            if SECURITY_STRICT_LOGIN_BLOCK_ENABLED:
                strict_blocks = _strict_block_actor(username, source_ip, "Login fallido en modo estricto")
                created_blocks.extend(strict_blocks)
                record_security_event(
                    event_type="strict_login_block",
                    severity="critical",
                    username=username,
                    source_ip=source_ip,
                    user_agent=user_agent,
                    detail="Primer intento de login fallido bloqueado por politica estricta",
                )
            if is_super_admin:
                block_text = ", ".join([f"{b.get('kind')}:{b.get('value')}" for b in created_blocks]) or "sin bloqueo nuevo"
                _record_super_admin_security_event(
                    "super_admin_password_failed",
                    username,
                    source_ip,
                    user_agent,
                    f"Credenciales invalidas contra super admin; accion: {block_text}",
                )
        except Exception:
            pass
        raise HTTPException(status_code=423, detail="Acceso bloqueado. Comunicate con el administrador.")

    db_user = get_user_by_username(username) or {}
    if db_user.get("mfa_enabled"):
        ticket = _create_mfa_login_ticket(user, source_ip, user_agent)
        return {"mfa_required": True, "ticket": ticket, "username": username}

    return _issue_login_token(user, source_ip, user_agent, response=response)


@app.post("/api/auth/mfa/login/verify")
def login_mfa_verify(payload: MfaLoginVerifyRequest, response: Response):
    _cleanup_mfa_login_tickets()
    raw_ticket = payload.ticket.strip()
    ticket = get_mfa_login_ticket(raw_ticket)
    if not ticket:
        raise HTTPException(status_code=401, detail="El desafio MFA expiro. Volve a ingresar usuario y clave.")
    username = str(ticket.get("username", "")).strip()
    db_user = get_user_by_username(username)
    if not db_user or not db_user.get("mfa_enabled"):
        raise HTTPException(status_code=401, detail="MFA no disponible para este usuario")
    if not _verify_totp(str(db_user.get("mfa_secret", "") or ""), payload.code):
        _record_security_event_safe("mfa_login_failed", username, "Codigo MFA incorrecto", severity="warning")
        raise HTTPException(status_code=401, detail="Codigo MFA invalido")
    if not consume_mfa_login_ticket(raw_ticket):
        raise HTTPException(status_code=401, detail="El desafio MFA expiro. Volve a ingresar usuario y clave.")
    user = {
        "id": db_user.get("id"),
        "username": db_user.get("username"),
        "full_name": db_user.get("full_name", ""),
        "roles": db_user.get("roles", []),
        "must_change_password": bool(db_user.get("must_change_password", False)),
        "mfa_enabled": True,
    }
    _record_security_event_safe("mfa_login_success", username, "Login MFA confirmado")
    return _issue_login_token(user, str(ticket.get("source_ip", "")), str(ticket.get("user_agent", "")), response=response)


@app.post("/api/auth/standalone-network")
def standalone_network_login(request: Request, response: Response):
    if not RELATIONAL_STANDALONE_ENABLED or not _is_local_request(request):
        raise HTTPException(status_code=404, detail="Modo standalone no disponible")
    return _issue_login_token(
        _standalone_network_user(),
        _client_ip(request),
        request.headers.get("user-agent", ""),
        response=response,
    )


@app.get("/api/auth/me")
def me(user=Depends(_require_auth)):
    return {"user": user}


@app.post("/api/auth/logout")
def logout(response: Response, authorization: str = Header(default=""), user=Depends(_require_auth)):
    token = authorization.replace("Bearer ", "", 1).strip()
    delete_token(token)
    _clear_session_cookie(response)
    return {"ok": True}


@app.post("/api/auth/change-password")
def auth_change_password(payload: ChangePasswordRequest, user=Depends(_require_auth)):
    if len(payload.new_password.strip()) < 6:
        raise HTTPException(status_code=400, detail="La nueva clave debe tener al menos 6 caracteres")

    ok = change_password(
        username=str(user.get("username", "")),
        current_password=payload.current_password,
        new_password=payload.new_password,
    )
    if not ok:
        raise HTTPException(status_code=400, detail="Clave actual incorrecta")
    _record_security_event_safe(
        "password_changed_by_user",
        str(user.get("username", "")),
        "El usuario cambio su propia clave",
    )
    return {"ok": True, "must_change_password": False}


@app.get("/api/auth/mfa/status")
def auth_mfa_status(user=Depends(_require_auth)):
    db_user = get_user_by_username(str(user.get("username", "")))
    if not db_user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    return {
        "enabled": bool(db_user.get("mfa_enabled")),
        "configured": bool(db_user.get("mfa_secret")),
        "confirmed_at": db_user.get("mfa_confirmed_at"),
    }


@app.post("/api/auth/mfa/setup")
def auth_mfa_setup(user=Depends(_require_auth)):
    username = str(user.get("username", "")).strip()
    if not username:
        raise HTTPException(status_code=401, detail="Usuario invalido")
    secret = _new_mfa_secret()
    if not set_user_mfa_secret(username, secret):
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    _record_security_event_safe("mfa_setup_started", username, "El usuario inicio configuracion MFA")
    return {
        "secret": secret,
        "otpauth_uri": _mfa_otpauth_uri(username, secret),
        "enabled": False,
    }


@app.post("/api/auth/mfa/confirm")
def auth_mfa_confirm(payload: MfaConfirmRequest, user=Depends(_require_auth)):
    username = str(user.get("username", "")).strip()
    db_user = get_user_by_username(username)
    if not db_user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    secret = str(db_user.get("mfa_secret", "") or "")
    if not _verify_totp(secret, payload.code):
        _record_security_event_safe("mfa_confirm_failed", username, "Codigo MFA incorrecto", severity="warning")
        raise HTTPException(status_code=400, detail="Codigo MFA invalido")
    if not confirm_user_mfa(username):
        raise HTTPException(status_code=400, detail="No se pudo confirmar MFA")
    _record_security_event_safe("mfa_confirmed", username, "MFA confirmado correctamente")
    updated = get_user_by_username(username) or {}
    return {
        "ok": True,
        "enabled": True,
        "user": {
            "id": updated.get("id", user.get("id")),
            "username": updated.get("username", user.get("username")),
            "full_name": updated.get("full_name", user.get("full_name", "")),
            "roles": updated.get("roles", user.get("roles", [])),
            "must_change_password": bool(updated.get("must_change_password", False)),
            "mfa_enabled": True,
        },
    }


@app.get("/api/users")
def users(admin=Depends(_require_admin)):
    return {"items": list_users()}


def _validate_user_payload(username: str, roles: List[str], password: str = "", require_password: bool = False) -> List[str]:
    if len(username.strip()) < 3:
        raise HTTPException(status_code=400, detail="El usuario debe tener al menos 3 caracteres")
    if require_password and len(password.strip()) < 6:
        raise HTTPException(status_code=400, detail="La clave debe tener al menos 6 caracteres")
    if password.strip() and len(password.strip()) < 6:
        raise HTTPException(status_code=400, detail="La clave debe tener al menos 6 caracteres")
    allowed_roles = {"admin", "analista", "visita"}
    clean_roles = [r.strip().lower() for r in roles if str(r).strip()]
    invalid = [r for r in clean_roles if r not in allowed_roles]
    if invalid:
        raise HTTPException(status_code=400, detail=f"Roles invalidos: {invalid}")
    return clean_roles or ["visita"]


def _active_admin_count(exclude_user_id: Optional[int] = None) -> int:
    total = 0
    for item in list_users():
        if exclude_user_id is not None and int(item.get("id") or 0) == exclude_user_id:
            continue
        roles = [str(r).lower() for r in item.get("roles", [])]
        if item.get("is_active") and "admin" in roles:
            total += 1
    return total


NETWORK_ACCESS_ALLOWED_STATUSES = {"pendiente", "aceptado", "rechazado", "revocado"}
NETWORK_ACCESS_ALLOWED_PERMS = {"ver", "comentar", "editar", "exportar", "administrar"}


def _network_access_path() -> Path:
    return OUTPUTS_DIR / "red_operativa" / "trabajo_en_red_autorizaciones.json"


def _read_network_access_sessions() -> List[Dict[str, Any]]:
    path = _network_access_path()
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []
    if isinstance(data, dict):
        items = data.get("items", [])
    else:
        items = data
    return items if isinstance(items, list) else []


def _write_network_access_sessions(items: List[Dict[str, Any]]) -> None:
    path = _network_access_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({"items": items}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def _clean_network_access_status(value: str) -> str:
    status_value = (value or "pendiente").strip().lower()
    if status_value not in NETWORK_ACCESS_ALLOWED_STATUSES:
        raise HTTPException(status_code=400, detail="Estado de trabajo en red invalido")
    return status_value


def _clean_network_access_permissions(raw: Dict[str, bool]) -> Dict[str, bool]:
    source = raw or {}
    return {key: bool(source.get(key, False)) for key in NETWORK_ACCESS_ALLOWED_PERMS}


def _network_access_public_item(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": str(item.get("id") or ""),
        "scenario": str(item.get("scenario") or "Escenario 1"),
        "user_id": int(item.get("user_id") or 0),
        "username": str(item.get("username") or ""),
        "full_name": str(item.get("full_name") or ""),
        "roles": item.get("roles") if isinstance(item.get("roles"), list) else [],
        "status": str(item.get("status") or "pendiente"),
        "permissions": _clean_network_access_permissions(item.get("permissions") or {}),
        "note": str(item.get("note") or ""),
        "invited_by": str(item.get("invited_by") or ""),
        "invited_at": str(item.get("invited_at") or ""),
        "updated_by": str(item.get("updated_by") or ""),
        "updated_at": str(item.get("updated_at") or ""),
    }


@app.get("/api/network-access/sessions")
def network_access_sessions(admin=Depends(_require_admin)):
    items = [_network_access_public_item(item) for item in _read_network_access_sessions()]
    items.sort(key=lambda x: (x.get("scenario", ""), x.get("status", ""), x.get("username", "")))
    return {"items": items}


@app.post("/api/network-access/sessions")
def network_access_upsert(payload: NetworkAccessSessionRequest, admin=Depends(_require_admin)):
    scenario = (payload.scenario or "Escenario 1").strip() or "Escenario 1"
    target = get_user_by_id(payload.user_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    if not target.get("is_active"):
        raise HTTPException(status_code=400, detail="El usuario esta inactivo")

    status_value = _clean_network_access_status(payload.status)
    permissions = _clean_network_access_permissions(payload.permissions)
    if not any(permissions.values()):
        permissions["ver"] = True

    now = dt.datetime.now(dt.timezone.utc).isoformat()
    admin_user = str(admin.get("username") or "")
    items = _read_network_access_sessions()
    found = None
    for item in items:
        if str(item.get("scenario") or "").strip().lower() == scenario.lower() and int(item.get("user_id") or 0) == int(payload.user_id):
            found = item
            break

    if found is None:
        found = {
            "id": uuid.uuid4().hex[:12],
            "scenario": scenario,
            "user_id": int(payload.user_id),
            "invited_by": admin_user,
            "invited_at": now,
        }
        items.append(found)

    found.update(
        {
            "scenario": scenario,
            "username": str(target.get("username") or ""),
            "full_name": str(target.get("full_name") or ""),
            "roles": target.get("roles") if isinstance(target.get("roles"), list) else [],
            "status": status_value,
            "permissions": permissions,
            "note": (payload.note or "").strip(),
            "updated_by": admin_user,
            "updated_at": now,
        }
    )
    _write_network_access_sessions(items)
    _record_security_event_safe(
        "network_access_authorization_saved",
        str(target.get("username") or ""),
        f"Trabajo en red {scenario} guardado por admin {admin_user} con estado {status_value}",
    )
    return {"ok": True, "item": _network_access_public_item(found)}


@app.patch("/api/network-access/sessions/{session_id}/status")
def network_access_status_update(session_id: str, payload: NetworkAccessStatusRequest, admin=Depends(_require_admin)):
    status_value = _clean_network_access_status(payload.status)
    items = _read_network_access_sessions()
    for item in items:
        if str(item.get("id") or "") == session_id:
            item["status"] = status_value
            item["updated_by"] = str(admin.get("username") or "")
            item["updated_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
            _write_network_access_sessions(items)
            _record_security_event_safe(
                "network_access_status_changed",
                str(item.get("username") or ""),
                f"Trabajo en red {item.get('scenario', '')} actualizado a {status_value}",
            )
            return {"ok": True, "item": _network_access_public_item(item)}
    raise HTTPException(status_code=404, detail="Autorizacion de trabajo en red no encontrada")


@app.get("/api/audit/logins")
def audit_logins(
    limit: int = 200,
    username: str = "",
    role: str = "",
    date_from: str = "",
    date_to: str = "",
    admin=Depends(_require_admin),
):
    events = list_login_events(
        limit=limit,
        username=username,
        role=role,
        date_from=date_from,
        date_to=date_to,
    )
    
    # Convertir horario UTC de la base de datos a UTC-3 (Argentina/Mendoza)
    tz_ar = dt.timezone(dt.timedelta(hours=-3))
    for ev in events:
        raw_dt = ev.get("created_at")
        if isinstance(raw_dt, dt.datetime):
            # Si PostgreSQL devuelve un objeto datetime
            ev["created_at"] = raw_dt.astimezone(tz_ar).strftime("%Y-%m-%d %H:%M:%S")
        elif isinstance(raw_dt, str):
            try:
                # Si SQLite devuelve un string 'YYYY-MM-DD HH:MM:SS' en UTC
                utc_dt = dt.datetime.strptime(raw_dt, "%Y-%m-%d %H:%M:%S").replace(tzinfo=dt.timezone.utc)
                ev["created_at"] = utc_dt.astimezone(tz_ar).strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                pass

    return {"items": events}


@app.get("/api/security/login-attempts")
def security_login_attempts(
    limit: int = 200,
    username: str = "",
    success: str = "",
    date_from: str = "",
    date_to: str = "",
    admin=Depends(_require_admin),
):
    success_value: Optional[bool] = None
    if success.strip().lower() in {"1", "true", "ok", "success"}:
        success_value = True
    elif success.strip().lower() in {"0", "false", "fail", "failed"}:
        success_value = False
    attempts = list_login_attempts(
        limit=limit,
        username=username,
        success=success_value,
        date_from=date_from,
        date_to=date_to,
    )
    return {"items": _localize_security_times(attempts)}


@app.get("/api/security/blocks")
def security_blocks(active_only: bool = True, limit: int = 200, admin=Depends(_require_admin)):
    blocks = list_security_blocks(active_only=active_only, limit=limit)
    return {"items": _localize_security_times(blocks)}


@app.get("/api/security/events")
def security_events(
    limit: int = 100,
    severity: str = "",
    username: str = "",
    date_from: str = "",
    date_to: str = "",
    admin=Depends(_require_admin),
):
    events = list_security_events(
        limit=limit,
        severity=severity,
        username=username,
        date_from=date_from,
        date_to=date_to,
    )
    return {"items": _localize_security_times(events)}


@app.post("/api/security/telegram/test")
def security_telegram_test(request: Request, admin=Depends(_require_admin)):
    source_ip = _client_ip(request)
    user_agent = request.headers.get("user-agent", "")
    username = str(admin.get("username", ""))
    sent, detail = _send_security_telegram_alert(
        "\n".join(
            [
                "PRUEBA TELEGRAM - Detection of Signals",
                f"Usuario admin: {username}",
                f"IP: {source_ip or '-'}",
                f"Fecha Argentina: {_security_local_time_text()}",
            ]
        )
    )
    try:
        record_security_event(
            event_type="telegram_test",
            severity="info" if sent else "warning",
            username=username,
            source_ip=source_ip,
            user_agent=user_agent,
            detail=("envio_ok" if sent else detail[:500]),
        )
    except Exception:
        pass
    return {
        "ok": sent,
        "configured": bool(TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID),
        "chat_id_configured": bool(TELEGRAM_CHAT_ID),
        "token_configured": bool(TELEGRAM_BOT_TOKEN),
        "detail": "Mensaje enviado" if sent else detail,
    }


@app.post("/api/security/blocks/{block_id}/lift")
def security_block_lift(block_id: int, admin=Depends(_require_admin)):
    lifted = lift_security_block(block_id, lifted_by=str(admin.get("username", "")))
    if not lifted:
        raise HTTPException(status_code=404, detail="Bloqueo no encontrado o ya levantado")
    return {"ok": True}


@app.post("/api/users")
def users_create(payload: CreateUserRequest, admin=Depends(_require_admin)):
    username = payload.username.strip()
    roles = _validate_user_payload(username, payload.roles, payload.password, require_password=True)

    try:
        user = create_user(
            username=username,
            password=payload.password,
            roles=roles,
            full_name=payload.full_name,
            must_change_password=True,
        )
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=f"No se pudo crear usuario: {exc}")

    _record_security_event_safe(
        "user_created_with_initial_password",
        username,
        f"Usuario creado por admin {admin.get('username', '')}",
    )
    return {"ok": True, "user": user}


@app.put("/api/users/{user_id}")
def users_update(user_id: int, payload: UpdateUserRequest, admin=Depends(_require_admin)):
    target = get_user_by_id(user_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")

    username = payload.username.strip()
    roles = _validate_user_payload(username, payload.roles, payload.password)
    admin_id = int(admin.get("id") or 0)
    target_roles = [str(r).lower() for r in target.get("roles", [])]
    removing_last_admin = target.get("is_active") and "admin" in target_roles and (
        not payload.is_active or "admin" not in roles
    )
    if removing_last_admin and _active_admin_count(exclude_user_id=user_id) == 0:
        raise HTTPException(status_code=400, detail="No se puede dejar el sistema sin admin activo")
    if user_id == admin_id and (not payload.is_active or "admin" not in roles):
        raise HTTPException(status_code=400, detail="No podes quitarte tu propio rol admin ni desactivarte")

    try:
        user = update_user(
            user_id=user_id,
            username=username,
            full_name=payload.full_name,
            roles=roles,
            password=payload.password,
            is_active=payload.is_active,
        )
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=f"No se pudo actualizar usuario: {exc}")

    if payload.password.strip():
        _record_security_event_safe(
            "password_reset_by_admin",
            username,
            f"Clave actualizada por admin {admin.get('username', '')}",
        )
    return {"ok": True, "user": user}


@app.patch("/api/users/{user_id}/active")
def users_set_active(user_id: int, is_active: bool, admin=Depends(_require_admin)):
    target = get_user_by_id(user_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    if user_id == int(admin.get("id") or 0) and not is_active:
        raise HTTPException(status_code=400, detail="No podes desactivar tu propio usuario")
    roles = [str(r).lower() for r in target.get("roles", [])]
    if target.get("is_active") and not is_active and "admin" in roles and _active_admin_count(exclude_user_id=user_id) == 0:
        raise HTTPException(status_code=400, detail="No se puede dejar el sistema sin admin activo")
    user = set_user_active(user_id, is_active)
    return {"ok": True, "user": user}


@app.delete("/api/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def users_delete(user_id: int, admin=Depends(_require_admin)):
    target = get_user_by_id(user_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    if user_id == int(admin.get("id") or 0):
        raise HTTPException(status_code=400, detail="No podes borrar tu propio usuario")
    roles = [str(r).lower() for r in target.get("roles", [])]
    if target.get("is_active") and "admin" in roles and _active_admin_count(exclude_user_id=user_id) == 0:
        raise HTTPException(status_code=400, detail="No se puede borrar el ultimo admin activo")
    delete_user_by_id(user_id)
    return


@app.get("/api/config")
def config(user=Depends(_require_auth)):
    return {
        "reports_inbox": str(REPORTS_DIR.resolve()),
        "septier_inbox": str(SEPTIER_DIR.resolve()),
        "guardian_inbox": str(GUARDIAN_DIR.resolve()),
        "backpack_inbox": str(BACKPACK_DIR.resolve()),
        "how_to_use": "Sube aqui Detection Report.csv y Detection Trajectories.csv, luego ejecuta 'Procesar ultimo reporte'.",
    }


@app.get("/api/septier/config")
def septier_config(user=Depends(_require_auth)):
    GUARDIAN_DIR.mkdir(parents=True, exist_ok=True)
    BACKPACK_DIR.mkdir(parents=True, exist_ok=True)
    return {
        "base_dir": str(SEPTIER_DIR.resolve()),
        "guardian_dir": str(GUARDIAN_DIR.resolve()),
        "backpack_dir": str(BACKPACK_DIR.resolve()),
    }


@app.get("/api/septier/files")
def septier_files(user=Depends(_require_auth)):
    GUARDIAN_DIR.mkdir(parents=True, exist_ok=True)
    BACKPACK_DIR.mkdir(parents=True, exist_ok=True)
    disk_files = [
        *[{"system": "guardian", "file": p.name} for p in GUARDIAN_DIR.glob("*.csv")],
        *[{"system": "backpack", "file": p.name} for p in BACKPACK_DIR.glob("*.csv")],
    ]
    db_file_rows = list_septier_uploaded_files_from_db()
    db_files = [
        {
            "system": str(row.get("source") or "").lower(),
            "file": str(row.get("archivo_origen") or ""),
        }
        for row in db_file_rows
        if str(row.get("source") or "").lower() in {"guardian", "backpack"} and row.get("archivo_origen")
    ]
    all_files_map: Dict[str, Dict[str, str]] = {}
    for item in [*db_files, *disk_files]:
        key = f"{item['system']}|{item['file']}"
        all_files_map[key] = item
    all_files = list(all_files_map.values())
    metadata_map = get_septier_history_metadata_map(all_files)
    stats_map: Dict[str, Dict[str, object]] = {}
    for row in db_file_rows:
        key = f"{str(row.get('source') or '').lower()}|{row.get('archivo_origen') or ''}"
        stats_map[key] = {
            "rows": int(row.get("filas_leidas") or 0),
            "first": _parse_dt_value(row.get("primera_deteccion")),
            "last": _parse_dt_value(row.get("ultima_deteccion")),
            "hash_sha256": row.get("hash_sha256") or "",
        }

    def _list_csvs(base: Path, system_name: str) -> List[Dict[str, object]]:
        out: List[Dict[str, object]] = []
        names = {
            item["file"]
            for item in all_files
            if item.get("system") == system_name and str(item.get("file") or "").lower().endswith(".csv")
        }
        ordered_names = sorted(
            names,
            key=lambda name: (
                stats_map.get(f"{system_name}|{name}", {}).get("last") or dt.datetime.min,
                name,
            ),
            reverse=True,
        )
        for name in ordered_names:
            p = base / name
            file_exists = p.exists() and p.is_file()
            stats = stats_map.get(f"{system_name}|{name}") or {}
            file_hash = _nexa_hash_file(p) if file_exists else str(stats.get("hash_sha256") or "")
            meta = metadata_map.get(f"{system_name}|{name}") or {}
            first_seen = stats.get("first")
            last_seen = stats.get("last")
            modified_at = (
                dt.datetime.fromtimestamp(p.stat().st_mtime).isoformat(timespec="seconds")
                if file_exists
                else last_seen.isoformat(timespec="seconds") if isinstance(last_seen, dt.datetime)
                else ""
            )
            out.append(
                {
                    "name": name,
                    "size": p.stat().st_size if file_exists else 0,
                    "modified_at": modified_at,
                    "fecha_operativo": first_seen.strftime("%Y-%m-%d") if isinstance(first_seen, dt.datetime) else "",
                    "primera_deteccion": first_seen.isoformat(timespec="seconds") if isinstance(first_seen, dt.datetime) else "",
                    "ultima_deteccion": last_seen.isoformat(timespec="seconds") if isinstance(last_seen, dt.datetime) else "",
                    "filas_leidas": int(stats.get("rows") or 0),
                    "sha256": file_hash,
                    "hash_sha256": file_hash,
                    "db_only": not file_exists,
                    "metadata": meta,
                    "lugar_operativo": meta.get("lugar_operativo") or "",
                    "complejo": meta.get("complejo") or "",
                    "modulo": meta.get("modulo") or "",
                    "ala": meta.get("ala") or "",
                    "ubicacion": meta.get("ubicacion") or "",
                    "coordenadas": meta.get("coordenadas") or "",
                    "observacion": meta.get("observacion") or "",
                }
            )
        return out

    return {
        "guardian": _list_csvs(GUARDIAN_DIR, "guardian"),
        "backpack": _list_csvs(BACKPACK_DIR, "backpack"),
    }


def _septier_operational_network_data(
    source: str = "",
    place: str = "",
    q: str = "",
    limit: int = 80,
    include_whitelist: bool = True,
    show_whitelist_nodes: bool = True,
    include_mutations: bool = True,
    only_unauthorized: bool = False,
    only_multi_place: bool = False,
    only_memory: bool = False,
    only_first_seen: bool = False,
    files: Optional[List[FileItem]] = None,
):
    GUARDIAN_DIR.mkdir(parents=True, exist_ok=True)
    BACKPACK_DIR.mkdir(parents=True, exist_ok=True)
    source_norm = source.strip().lower()
    if source_norm not in {"", "guardian", "backpack"}:
        raise HTTPException(status_code=400, detail="Fuente no valida")
    limit = max(20, min(int(limit or 80), 180))
    selected_files = []
    for item in files or []:
        system = str(item.system or "").strip().lower()
        filename = Path(str(item.file or "")).name
        if system not in {"guardian", "backpack"} or not filename.lower().endswith(".csv"):
            continue
        path = _septier_target_dir(system) / filename
        if path.exists() and path.is_file():
            selected_files.append({"system": system, "file": filename})

    if selected_files:
        files_payload = selected_files
    else:
        files_payload = []
        if source_norm in {"", "guardian"}:
            files_payload.extend({"system": "guardian", "file": p.name} for p in GUARDIAN_DIR.glob("*.csv"))
        if source_norm in {"", "backpack"}:
            files_payload.extend({"system": "backpack", "file": p.name} for p in BACKPACK_DIR.glob("*.csv"))

    metadata = get_septier_history_metadata_map(files_payload) if files_payload else {}
    place_filter = place.strip().upper()
    if place_filter and metadata:
        scoped_files = []
        for item in files_payload:
            history_key = f"{str(item.get('system') or '').lower()}|{Path(str(item.get('file') or '')).name}"
            meta = metadata.get(history_key) or {}
            raw_place = str(meta.get("lugar_operativo") or meta.get("complejo") or "").strip()
            if _septier_place_bucket(raw_place) == place_filter:
                scoped_files.append(item)
        if scoped_files:
            files_payload = scoped_files
            metadata = get_septier_history_metadata_map(files_payload)
    identity_memory = _septier_identity_memory()
    rows = [_with_resolved_septier_identity(r, identity_memory) for r in get_septier_forensic_rows_by_files(files_payload)] if files_payload else []
    query = q.strip().lower()
    if query in {"imsi", "imei", "imsi/mac", "mac", "history", "histories", "archivo", "archivos"}:
        query = ""
    whitelist = _whitelist_identity_set() if include_whitelist else set()
    _, _, mem_imsi_rows, mem_imei_rows = _historial_memory_maps()
    whitelist_node_cache: Dict[str, Optional[Tuple[str, str, Dict[str, object]]]] = {}

    nodes: Dict[str, Dict[str, object]] = {}
    edges: Dict[Tuple[str, str, str], Dict[str, object]] = {}
    imsi_to_imeis: Dict[str, set] = defaultdict(set)
    imei_to_imsis: Dict[str, set] = defaultdict(set)
    identity_count: Counter[str] = Counter()
    identity_places: Dict[str, set] = defaultdict(set)
    identity_histories: Dict[str, set] = defaultdict(set)
    identity_first_seen: Dict[str, dt.datetime] = {}
    identity_whitelisted: Dict[str, bool] = {}
    identity_memory_refs: Dict[str, List[Dict[str, object]]] = defaultdict(list)

    def memory_matches(imsi: str, imei: str) -> List[Dict[str, object]]:
        refs: List[Dict[str, object]] = []
        imsi_key = _primary_identity_key(imsi)
        imei_key = _primary_identity_key(imei)
        if imsi_key:
            refs.extend(mem_imsi_rows.get(imsi_key, []))
        if imei_key:
            refs.extend(mem_imei_rows.get(imei_key, []))
        seen = set()
        unique_refs = []
        for ref in refs:
            key = (
                str(ref.get("numero_informe") or ""),
                str(ref.get("archivo_origen") or ""),
                str(ref.get("imsi") or ""),
                str(ref.get("imei") or ""),
            )
            if key in seen:
                continue
            seen.add(key)
            unique_refs.append(ref)
        return unique_refs

    def add_node(node_id: str, node_type: str, label: str, subtitle: str = "", **extra: object) -> None:
        if not node_id:
            return
        if node_id not in nodes:
            nodes[node_id] = {"id": node_id, "type": node_type, "label": label, "subtitle": subtitle, **extra}
        elif subtitle and not nodes[node_id].get("subtitle"):
            nodes[node_id]["subtitle"] = subtitle
        if node_id in nodes:
            for key, value in extra.items():
                if value not in ("", None, [], {}) and not nodes[node_id].get(key):
                    nodes[node_id][key] = value

    def add_edge(from_id: str, to_id: str, kind: str, label: str) -> None:
        if not from_id or not to_id or from_id == to_id:
            return
        key = (from_id, to_id, kind)
        if key not in edges:
            edges[key] = {
                "from": from_id,
                "to": to_id,
                "kind": kind,
                "label": label,
                "from_label": nodes.get(from_id, {}).get("label", from_id),
                "to_label": nodes.get(to_id, {}).get("label", to_id),
            }

    for row in rows:
        system = str(row.get("source") or "").lower()
        filename = str(row.get("archivo_origen") or "")
        history_key = f"{system}|{filename}"
        meta = metadata.get(history_key) or {}
        raw_place = str(meta.get("lugar_operativo") or meta.get("complejo") or row.get("location") or "").strip()
        bucket = _septier_place_bucket(raw_place)
        if place_filter and bucket != place_filter:
            continue
        haystack = " ".join([
            str(row.get("imsi_mac") or ""),
            str(row.get("imei") or ""),
            filename,
            raw_place,
            str(row.get("model") or ""),
            str(row.get("operator_event") or ""),
        ]).lower()
        if query and query not in haystack:
            continue
        imsi = _id15(row.get("imsi_mac"))
        imei = _id15(row.get("imei"))
        identity_key = _operational_identity_key(imsi, imei)
        if not identity_key:
            continue
        identity_count[identity_key] += 1
        if bucket:
            identity_places[identity_key].add(bucket)
        if filename:
            identity_histories[identity_key].add(f"{system.upper()}: {filename}")
        seen_at = _parse_dt_value(row.get("last_update"))
        if seen_at and (identity_key not in identity_first_seen or seen_at < identity_first_seen[identity_key]):
            identity_first_seen[identity_key] = seen_at
        if include_whitelist:
            identity_whitelisted[identity_key] = identity_whitelisted.get(identity_key, False) or _is_whitelisted_identity(imsi, imei, whitelist)
        refs = memory_matches(imsi, imei)
        if refs:
            identity_memory_refs[identity_key].extend(refs)
        if len(imsi) == 15 and len(imei) == 15:
            imsi_to_imeis[imsi].add(imei)
            imei_to_imsis[imei].add(imsi)

    for key, refs in list(identity_memory_refs.items()):
        seen_refs = set()
        deduped_refs = []
        for ref in refs:
            ref_key = (
                str(ref.get("numero_informe") or ""),
                str(ref.get("archivo_origen") or ""),
                str(ref.get("imsi") or ""),
                str(ref.get("imei") or ""),
            )
            if ref_key in seen_refs:
                continue
            seen_refs.add(ref_key)
            deduped_refs.append(ref)
        identity_memory_refs[key] = deduped_refs

    def identity_allowed(key: str) -> bool:
        if only_unauthorized and identity_whitelisted.get(key, False):
            return False
        if only_multi_place and len(identity_places.get(key, set())) < 2 and len(identity_histories.get(key, set())) < 2:
            return False
        if only_memory and not identity_memory_refs.get(key):
            return False
        if only_first_seen and identity_memory_refs.get(key):
            return False
        return True

    selected_identity_keys = [key for key, _ in identity_count.most_common() if identity_allowed(key)][:limit]
    selected = set(selected_identity_keys)

    for row in rows:
        system = str(row.get("source") or "").lower()
        filename = str(row.get("archivo_origen") or "")
        history_key = f"{system}|{filename}"
        meta = metadata.get(history_key) or {}
        raw_place = str(meta.get("lugar_operativo") or meta.get("complejo") or row.get("location") or "").strip()
        bucket = _septier_place_bucket(raw_place)
        if place_filter and bucket != place_filter:
            continue
        haystack = " ".join([
            str(row.get("imsi_mac") or ""),
            str(row.get("imei") or ""),
            filename,
            raw_place,
            str(row.get("model") or ""),
            str(row.get("operator_event") or ""),
        ]).lower()
        if query and query not in haystack:
            continue
        imsi = _id15(row.get("imsi_mac"))
        imei = _id15(row.get("imei"))
        identity_key = _operational_identity_key(imsi, imei)
        if identity_key not in selected:
            continue
        first_seen = identity_first_seen.get(identity_key)
        status_tags = []
        if identity_whitelisted.get(identity_key, False):
            status_tags.append("Coincide con Lista Blanca")
        else:
            status_tags.append("No coincidente con Lista Blanca")
        if len(identity_places.get(identity_key, set())) > 1:
            status_tags.append("Visto en varios lugares")
        if len(identity_histories.get(identity_key, set())) > 1:
            status_tags.append("Visto en varios histories")
        if identity_memory_refs.get(identity_key):
            status_tags.append("Memoria forense")
        else:
            status_tags.append("Primera vez en seleccion")

        history_id = f"history:{system}:{filename}"
        place_id = f"place:{bucket or 'SIN LUGAR'}"
        if len(imsi) == 15:
            imsi_id = f"imsi:{imsi}"
            related_imeis = sorted(imsi_to_imeis.get(imsi, set()))
            add_node(
                imsi_id,
                "IMSI",
                imsi,
                f"{identity_count[identity_key]} deteccion(es)",
                primary_imsi=imsi,
                related_imeis=related_imeis[:8],
                description=str(row.get("model") or row.get("operator_event") or raw_place or "").strip(),
                places_seen=sorted(identity_places.get(identity_key, set()))[:8],
                histories_seen=sorted(identity_histories.get(identity_key, set()))[:8],
                first_seen=first_seen.strftime("%Y-%m-%d %H:%M:%S") if first_seen else "",
                memory_source=_memory_source_text(identity_memory_refs.get(identity_key, [])) if identity_memory_refs.get(identity_key) else "",
                status_tags=status_tags,
            )
            history_subtitle = " | ".join(
                part for part in [system.upper(), raw_place, str(meta.get("fecha_operativo") or "")] if part
            )
            add_node(
                history_id,
                "History",
                filename,
                history_subtitle or system.upper(),
                source_system=system.upper(),
                description=raw_place or str(meta.get("observacion") or "").strip(),
            )
            add_edge(imsi_id, history_id, "seen_in", "IMSI visto en history")
            if bucket:
                add_node(
                    place_id,
                    "place",
                    bucket,
                    raw_place or "Lugar operativo",
                    category=_network_text_category(raw_place or bucket),
                    description=raw_place,
                    coordinates=str(meta.get("coordenadas") or "").strip(),
                )
                add_edge(history_id, place_id, "place", "History asignado a lugar")
        if len(imei) == 15:
            imei_id = f"imei:{imei}"
            related_imsis = sorted(imei_to_imsis.get(imei, set()))
            add_node(
                imei_id,
                "IMEI",
                imei,
                str(row.get("model") or "Dispositivo"),
                primary_imei=imei,
                related_imsis=related_imsis[:8],
                description=str(row.get("model") or row.get("operator_event") or raw_place or "").strip(),
                places_seen=sorted(identity_places.get(identity_key, set()))[:8],
                histories_seen=sorted(identity_histories.get(identity_key, set()))[:8],
                first_seen=first_seen.strftime("%Y-%m-%d %H:%M:%S") if first_seen else "",
                memory_source=_memory_source_text(identity_memory_refs.get(identity_key, [])) if identity_memory_refs.get(identity_key) else "",
                status_tags=status_tags,
            )
            history_subtitle = " | ".join(
                part for part in [system.upper(), raw_place, str(meta.get("fecha_operativo") or "")] if part
            )
            add_node(
                history_id,
                "History",
                filename,
                history_subtitle or system.upper(),
                source_system=system.upper(),
                description=raw_place or str(meta.get("observacion") or "").strip(),
            )
            add_edge(imei_id, history_id, "seen_in", "IMEI visto en history")
            if len(imsi) == 15:
                add_edge(f"imsi:{imsi}", imei_id, "association", "IMSI asociado a IMEI")

        if include_whitelist and show_whitelist_nodes and identity_whitelisted.get(identity_key, False):
            if identity_key not in whitelist_node_cache:
                matches = _whitelist_match_details(imsi, imei)
                if matches:
                    label = _whitelist_match_reason(matches)
                    info = _network_whitelist_info(matches)
                    wl_key = f"{info.get('category') or 'general'}|{info.get('source_label') or label}"
                    wl_id = f"whitelist:{hashlib.sha1(wl_key.encode('utf-8', errors='ignore')).hexdigest()[:10]}"
                    whitelist_node_cache[identity_key] = (wl_id, label, info)
                else:
                    whitelist_node_cache[identity_key] = None
            cached_whitelist = whitelist_node_cache.get(identity_key)
            if not cached_whitelist:
                continue
            wl_id, label, info = cached_whitelist
            add_node(
                wl_id,
                "whitelist",
                "Lista Blanca",
                label[:72],
                category=info.get("category") or "general",
                icon_hint=info.get("icon_hint") or "",
                source_label=info.get("source_label") or "",
                source_count=info.get("source_count") or 0,
                match_types=info.get("match_types") or [],
                description=info.get("description") or "",
            )
            target_id = f"imsi:{imsi}" if len(imsi) == 15 else f"imei:{imei}" if len(imei) == 15 else ""
            add_edge(target_id, wl_id, "whitelist", "Coincide con Lista Blanca")

    if include_mutations:
        for imsi, imeis in imsi_to_imeis.items():
            if len(imeis) < 2:
                continue
            imsi_id = f"imsi:{imsi}"
            if imsi_id not in nodes:
                continue
            mut_id = f"mutation:imsi:{imsi}"
            add_node(mut_id, "mutation", "Mutacion IMSI", f"{len(imeis)} IMEI asociados")
            add_edge(imsi_id, mut_id, "mutation", "Nuevo IMEI para IMSI conocido")
            for imei in sorted(imeis)[:4]:
                imei_id = f"imei:{imei}"
                if imei_id in nodes:
                    add_edge(mut_id, imei_id, "mutation", "IMEI asociado en mutacion")
        for imei, imsis in imei_to_imsis.items():
            if len(imsis) < 2:
                continue
            imei_id = f"imei:{imei}"
            if imei_id not in nodes:
                continue
            mut_id = f"mutation:imei:{imei}"
            add_node(mut_id, "mutation", "Mutacion IMEI", f"{len(imsis)} IMSI asociados")
            add_edge(imei_id, mut_id, "mutation", "Nuevo IMSI sobre IMEI conocido")
            for imsi in sorted(imsis)[:4]:
                imsi_id = f"imsi:{imsi}"
                if imsi_id in nodes:
                    add_edge(mut_id, imsi_id, "mutation", "IMSI asociado en mutacion")

    node_list = list(nodes.values())[: max(limit + 40, 60)]
    visible = {str(n["id"]) for n in node_list}
    edge_list = [edge for edge in edges.values() if edge.get("from") in visible and edge.get("to") in visible]
    return {
        "nodes": node_list,
        "edges": edge_list,
        "summary": {
            "nodes": len(node_list),
            "edges": len(edge_list),
            "mutations": sum(1 for n in node_list if str(n.get("type") or "").lower() == "mutation"),
            "whitelist": sum(1 for e in edge_list if e.get("kind") == "whitelist"),
            "histories": sum(1 for n in node_list if str(n.get("type") or "").lower() == "history"),
            "selected_files": len(selected_files),
            "filters": {
                "cross_whitelist": include_whitelist,
                "show_whitelist_nodes": show_whitelist_nodes,
                "only_unauthorized": only_unauthorized,
                "only_multi_place": only_multi_place,
                "only_memory": only_memory,
                "only_first_seen": only_first_seen,
            },
        },
    }


@app.get("/api/septier/network")
def septier_operational_network(
    source: str = "",
    place: str = "",
    q: str = "",
    limit: int = 80,
    include_whitelist: bool = True,
    show_whitelist_nodes: bool = True,
    include_mutations: bool = True,
    only_unauthorized: bool = False,
    only_multi_place: bool = False,
    only_memory: bool = False,
    only_first_seen: bool = False,
    user=Depends(_require_auth),
):
    return _septier_operational_network_data(
        source=source,
        place=place,
        q=q,
        limit=limit,
        include_whitelist=include_whitelist,
        show_whitelist_nodes=show_whitelist_nodes,
        include_mutations=include_mutations,
        only_unauthorized=only_unauthorized,
        only_multi_place=only_multi_place,
        only_memory=only_memory,
        only_first_seen=only_first_seen,
    )


@app.post("/api/septier/network/build")
def septier_operational_network_build(payload: SeptierNetworkReportRequest, user=Depends(_require_auth)):
    return _septier_operational_network_data(
        source=payload.source,
        place=payload.place,
        q=payload.q,
        limit=payload.limit,
        include_whitelist=payload.include_whitelist,
        show_whitelist_nodes=payload.show_whitelist_nodes,
        include_mutations=payload.include_mutations,
        only_unauthorized=payload.only_unauthorized,
        only_multi_place=payload.only_multi_place,
        only_memory=payload.only_memory,
        only_first_seen=payload.only_first_seen,
        files=payload.files,
    )


@app.post("/api/septier/network/report")
def septier_operational_network_report(payload: SeptierNetworkReportRequest, user=Depends(_require_auth)):
    if payload.nodes:
        nodes = [item for item in payload.nodes if isinstance(item, dict)]
        edges = [item for item in payload.edges if isinstance(item, dict)]
        summary = dict(payload.summary or {})
        summary.setdefault("nodes", len(nodes))
        summary.setdefault("edges", len(edges))
        summary.setdefault("mutations", sum(1 for item in nodes if "mutacion" in " ".join(str(tag).lower() for tag in (item.get("status_tags") or []))))
        summary.setdefault("whitelist", sum(1 for item in nodes if str(item.get("type") or "").lower() == "whitelist" or "lista blanca" in " ".join(str(tag).lower() for tag in (item.get("status_tags") or []))))
    else:
        data = _septier_operational_network_data(
            source=payload.source,
            place=payload.place,
            q=payload.q,
            limit=payload.limit,
            include_whitelist=payload.include_whitelist,
            show_whitelist_nodes=payload.show_whitelist_nodes,
            include_mutations=payload.include_mutations,
            only_unauthorized=payload.only_unauthorized,
            only_multi_place=payload.only_multi_place,
            only_memory=payload.only_memory,
            only_first_seen=payload.only_first_seen,
            files=payload.files,
        )
        nodes = list(data.get("nodes") or [])
        edges = list(data.get("edges") or [])
        summary = dict(data.get("summary") or {})
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = OUTPUTS_DIR / "red_operativa"
    out_dir.mkdir(parents=True, exist_ok=True)
    base_name = f"informe_red_operativa_{stamp}"
    html_path = out_dir / f"{base_name}.html"
    word_path = out_dir / f"{base_name}.docx"
    svg_path = out_dir / f"{base_name}.svg"

    def e(value: object) -> str:
        return html_lib.escape(str(value or ""))

    def _join_values(value: object) -> str:
        if isinstance(value, list):
            return " | ".join(str(item) for item in value if str(item or "").strip())
        return str(value or "")

    def _audit_rows(items: List[Dict[str, object]]) -> str:
        rows = []
        for item in items[-120:]:
            rows.append(
                "<tr>"
                f"<td>{e(item.get('at') or '')}</td>"
                f"<td>{e(item.get('user') or '')}</td>"
                f"<td>{e(item.get('action') or '')}</td>"
                f"<td>{e(item.get('detail') or '')}</td>"
                "</tr>"
            )
        return "".join(rows) or "<tr><td colspan='4'>Sin eventos de bitacora incorporados.</td></tr>"

    layout_payload = dict(payload.layout or {})
    raw_annotations = payload.annotations or layout_payload.get("annotations") or []
    annotations = [item for item in raw_annotations if isinstance(item, dict)][-350:] if isinstance(raw_annotations, list) else []

    def _annotation_rows() -> str:
        rows = []
        for item in annotations:
            rows.append(
                "<tr>"
                f"<td>{e(item.get('created_at') or item.get('at') or '')}</td>"
                f"<td>{e(item.get('user') or item.get('username') or '')}</td>"
                f"<td>{e(item.get('tool') or '')}</td>"
                f"<td>{e(item.get('text') or '')}</td>"
                f"<td>{e(item.get('color') or '')}</td>"
                "</tr>"
            )
        return "".join(rows) or "<tr><td colspan='5'>Sin marcas visuales incorporadas.</td></tr>"

    def _event_time_value(value: object) -> float:
        raw = str(value or "").strip()
        if not raw:
            return 0.0
        try:
            return dt.datetime.fromisoformat(raw.replace("Z", "+00:00").replace(" ", "T")).timestamp()
        except Exception:
            return 0.0

    def _timeline_rows() -> str:
        rows: List[Tuple[float, str, str, str]] = []
        node_by_id = {str(item.get("id") or ""): item for item in nodes}
        for item in nodes:
            when = str(item.get("first_seen") or item.get("last_seen") or item.get("created_at") or item.get("uploaded_at") or "").strip()
            if when:
                rows.append((_event_time_value(when), when, str(item.get("label") or item.get("id") or ""), f"{item.get('type') or 'nodo'} | {item.get('subtitle') or item.get('source_label') or ''}"))
        for item in edges:
            when = str(item.get("first_seen") or item.get("time") or item.get("created_at") or "").strip()
            if not when:
                src = node_by_id.get(str(item.get("from") or ""), {})
                dst = node_by_id.get(str(item.get("to") or ""), {})
                when = str(src.get("first_seen") or dst.get("first_seen") or "").strip()
            if when:
                rows.append((_event_time_value(when), when, str(item.get("label") or item.get("kind") or "Relacion"), f"{item.get('from_label') or item.get('from') or '-'} -> {item.get('to_label') or item.get('to') or '-'}"))
        rows.sort(key=lambda item: (item[0], item[1], item[2]))
        return "".join(f"<tr><td>{e(when)}</td><td>{e(title)}</td><td>{e(detail)}</td></tr>" for _, when, title, detail in rows[:220]) or "<tr><td colspan='3'>Sin marcas temporales suficientes.</td></tr>"

    node_columns: List[Tuple[str, str]] = [("Tipo", "type"), ("Identificador", "label")]
    if payload.show_imsi:
        node_columns.append(("IMSI", "imsi_display"))
    if payload.show_imei:
        node_columns.append(("IMEI", "imei_display"))
    if payload.show_description:
        node_columns.append(("Descripcion", "description_display"))
    if payload.show_source:
        node_columns.append(("Fuente", "source_display"))
    node_columns.extend([
        ("Estado", "status_display"),
        ("Primera vez", "first_seen"),
        ("Lugares", "places_display"),
        ("Memoria", "memory_source"),
    ])
    node_columns.append(("Categoria", "category"))

    def _node_cell(item: Dict[str, object], key: str) -> str:
        node_type = str(item.get("type") or "").lower()
        if key == "imsi_display":
            return str(item.get("primary_imsi") or (item.get("label") if node_type == "imsi" else "") or _join_values(item.get("related_imsis")) or "")
        if key == "imei_display":
            return str(item.get("primary_imei") or (item.get("label") if node_type == "imei" else "") or _join_values(item.get("related_imeis")) or "")
        if key == "description_display":
            return str(item.get("description") or item.get("subtitle") or "")
        if key == "source_display":
            return str(item.get("source_label") or item.get("source_system") or "")
        if key == "status_display":
            return _join_values(item.get("status_tags"))
        if key == "places_display":
            return _join_values(item.get("places_seen"))
        return str(item.get(key) or "")

    node_head = "".join(f"<th>{e(label)}</th>" for label, _ in node_columns)
    node_rows = "".join(
        "<tr>" + "".join(f"<td>{e(_node_cell(item, key))}</td>" for _, key in node_columns) + "</tr>"
        for item in nodes
    ) or f"<tr><td colspan='{len(node_columns)}'>Sin nodos.</td></tr>"
    edge_rows = "".join(
        f"<tr><td>{e(item.get('label') or item.get('kind'))}</td><td>{e(item.get('from_label') or item.get('from'))}</td><td>{e(item.get('to_label') or item.get('to'))}</td></tr>"
        for item in edges
    ) or "<tr><td colspan='3'>Sin relaciones.</td></tr>"

    visual_nodes = nodes[:160]
    node_index = {str(item.get("id") or item.get("label") or idx): item for idx, item in enumerate(visual_nodes)}
    visual_edges = [
        item for item in edges[:420]
        if str(item.get("from") or "") in node_index and str(item.get("to") or "") in node_index
    ]

    def _node_position(idx: int, total: int) -> Tuple[float, float]:
        if total <= 1:
            return 600.0, 330.0
        angle = (2 * math.pi * idx) / max(total, 1)
        radius = 210 + (idx % 4) * 26
        return 600 + math.cos(angle) * radius, 330 + math.sin(angle) * radius

    def _node_colors(item: Dict[str, object]) -> Tuple[str, str]:
        node_type = str(item.get("type") or "").lower()
        tags = " ".join(str(tag) for tag in (item.get("status_tags") or [])).lower()
        if node_type == "place":
            return "#f59e0b", "#251b0a"
        if node_type == "history":
            return "#38bdf8", "#071824"
        if node_type == "whitelist" or "lista blanca" in tags:
            return "#22c55e", "#062312"
        if "mutacion" in tags or "mutation" in tags:
            return "#f97316", "#281005"
        if "no coincidente" in tags or "sin lista blanca" in tags:
            return "#ef4444", "#260909"
        return "#22d3ee", "#061923"

    positions = {
        str(item.get("id") or item.get("label") or idx): _node_position(idx, len(visual_nodes))
        for idx, item in enumerate(visual_nodes)
    }
    grid_lines = "\n".join(
        [f"<line x1='{x}' y1='0' x2='{x}' y2='660' class='grid'/>" for x in range(0, 1201, 80)] +
        [f"<line x1='0' y1='{y}' x2='1200' y2='{y}' class='grid'/>" for y in range(0, 661, 60)]
    )
    svg_edges = []
    for edge in visual_edges:
        src = str(edge.get("from") or "")
        dst = str(edge.get("to") or "")
        if src not in positions or dst not in positions:
            continue
        x1, y1 = positions[src]
        x2, y2 = positions[dst]
        svg_edges.append(
            f"<line x1='{x1:.1f}' y1='{y1:.1f}' x2='{x2:.1f}' y2='{y2:.1f}' class='edge'><title>{e(edge.get('label') or edge.get('kind') or 'Relacion')}</title></line>"
        )
    svg_nodes = []
    for idx, item in enumerate(visual_nodes):
        node_id = str(item.get("id") or item.get("label") or idx)
        x, y = positions[node_id]
        stroke, fill = _node_colors(item)
        label = re.sub(r"\s+", " ", str(item.get("label") or item.get("title") or node_id).strip()) or node_id
        subtitle = re.sub(r"\s+", " ", str(item.get("subtitle") or item.get("source_label") or item.get("type") or "").strip())
        svg_nodes.append(
            f"<g class='node'><rect x='{x-72:.1f}' y='{y-25:.1f}' width='144' height='50' rx='9' fill='{fill}' stroke='{stroke}'/>"
            f"<text x='{x-62:.1f}' y='{y-5:.1f}' class='label'>{e(label[:22])}</text>"
            f"<text x='{x-62:.1f}' y='{y+13:.1f}' class='sub'>{e(subtitle[:24])}</text>"
            f"<title>{e(label)} | {e(subtitle)}</title></g>"
        )

    def _annotation_svg(item: Dict[str, object]) -> str:
        tool = str(item.get("tool") or "").lower()
        color = e(item.get("color") or "#12d8ff")
        try:
            x1 = float(item.get("x1") or 0)
            y1 = float(item.get("y1") or 0)
            x2 = float(item.get("x2") or x1)
            y2 = float(item.get("y2") or y1)
            stroke_width = max(1.0, min(float(item.get("width") or 4), 12.0))
        except Exception:
            return ""
        if tool == "text":
            return f'<text x="{x1:.1f}" y="{y1:.1f}" fill="{color}" font-size="18" font-weight="800">{e(item.get("text") or "")}</text>'
        if tool == "circle":
            cx = (x1 + x2) / 2
            cy = (y1 + y2) / 2
            rx = abs(x2 - x1) / 2
            ry = abs(y2 - y1) / 2
            return f'<ellipse cx="{cx:.1f}" cy="{cy:.1f}" rx="{rx:.1f}" ry="{ry:.1f}" fill="none" stroke="{color}" stroke-width="{stroke_width:.1f}" opacity="0.92"/>'
        if tool in {"rect", "highlight"}:
            x = min(x1, x2)
            y = min(y1, y2)
            width = abs(x2 - x1)
            height = abs(y2 - y1)
            fill = color if tool == "highlight" else "none"
            fill_opacity = "0.18" if tool == "highlight" else "0"
            opacity = "0.30" if tool == "highlight" else "0.92"
            return f'<rect x="{x:.1f}" y="{y:.1f}" width="{width:.1f}" height="{height:.1f}" rx="8" fill="{fill}" fill-opacity="{fill_opacity}" stroke="{color}" stroke-width="{stroke_width:.1f}" opacity="{opacity}"/>'
        if tool == "arrow":
            return f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" stroke="{color}" stroke-width="{stroke_width:.1f}" opacity="0.92" marker-end="url(#annotArrow)"/>'
        return ""

    annotation_layer = "".join(_annotation_svg(item) for item in annotations)
    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="660" viewBox="0 0 1200 660">
<style>
.bg{{fill:#04101a}}.grid{{stroke:#0b3546;stroke-width:1;opacity:.45}}.edge{{stroke:#7dd3fc;stroke-width:1.3;opacity:.48}}
.node text{{font-family:Arial,sans-serif;pointer-events:none}}.label{{fill:#f8fafc;font-size:12px;font-weight:700}}.sub{{fill:#9fb6c7;font-size:10px}}
marker{{overflow:visible}}
</style><defs><marker id="annotArrow" markerWidth="10" markerHeight="10" refX="9" refY="3" orient="auto" markerUnits="strokeWidth"><path d="M0,0 L0,6 L9,3 z" fill="#12d8ff"/></marker></defs><rect class="bg" width="1200" height="660"/>{grid_lines}<g>{''.join(svg_edges)}</g><g>{''.join(svg_nodes)}</g><g>{annotation_layer}</g></svg>"""
    svg_path.write_text(svg, encoding="utf-8")

    filter_text = " | ".join([
        f"Fuente: {payload.source or 'Guardian y Backpack'}",
        f"Lugar: {payload.place or 'Todos'}",
        f"Filtro: {payload.q or '-'}",
        f"Limite: {payload.limit}",
        f"Cruzar Lista Blanca: {'si' if payload.include_whitelist else 'no'}",
        f"Mostrar Lista Blanca: {'si' if payload.show_whitelist_nodes else 'no'}",
        f"Mutaciones: {'si' if payload.include_mutations else 'no'}",
        f"Histories seleccionados: {len(payload.files or [])}",
        "Filtros entidad: " + (", ".join(
            label for label, enabled in [
                ("no coincidentes", payload.only_unauthorized),
                ("varios lugares/histories", payload.only_multi_place),
                ("memoria forense", payload.only_memory),
                ("primera vez en seleccion", payload.only_first_seen),
            ] if enabled
        ) or "sin filtro extra"),
        "Tarjeta: " + ", ".join(
            label for label, enabled in [
                ("IMSI", payload.show_imsi),
                ("IMEI", payload.show_imei),
                ("Descripcion", payload.show_description),
                ("Fuente", payload.show_source),
            ] if enabled
        ),
    ])
    selected_files_rows = "".join(
        f"<tr><td>{e(item.system)}</td><td>{e(item.file)}</td></tr>" for item in (payload.selected_files or payload.files or [])
    ) or "<tr><td colspan='2'>Sin histories declarados en el informe.</td></tr>"
    audit_rows = _audit_rows([item for item in (payload.audit_log or []) if isinstance(item, dict)])
    annotation_rows = _annotation_rows()
    timeline_rows = _timeline_rows()
    html = f"""<!doctype html>
<html lang="es"><head><meta charset="utf-8"><title>Informe Red Operativa</title>
<style>
body{{font-family:Arial,sans-serif;margin:24px;color:#001b33}}h1{{color:#00446f}}h2{{color:#005f91;margin-top:22px}}
.meta,.rule{{border:1px solid #c8d7e6;border-radius:6px;padding:10px;margin:12px 0}}
.grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin:16px 0}}
.metric{{border:1px solid #c8d7e6;border-radius:6px;padding:10px;background:#f6f9fc}}.metric strong{{display:block;color:#00446f;font-size:24px}}
table{{border-collapse:collapse;width:100%;margin:12px 0;font-size:13px}}th,td{{border:1px solid #c8d7e6;padding:7px;text-align:left;vertical-align:top}}th{{background:#e9f2fb}}
.network-visual{{border:1px solid #c8d7e6;border-radius:6px;padding:8px;margin:12px 0;background:#f6f9fc}}.network-visual img{{width:100%;height:auto;display:block}}
</style></head><body>
<h1>Informe Red Operativa</h1>
<div class="meta"><strong>DEPARTAMENTO DE TECNOLOGIAS ESPECIALES Y DESPLIEGUE TACTICO</strong><br>
SUBSECRETARIA DE TECNOLOGIA APLICADA A LA SEGURIDAD<br>MINISTERIO DE SEGURIDAD Y JUSTICIA</div>
<div class="meta"><strong>Generado:</strong> {e(dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}<br>
<strong>Usuario:</strong> {e(user.get('full_name') or user.get('username') or '-')}<br>
<strong>Filtros:</strong> {e(filter_text)}</div>
<div class="rule"><strong>Regla:</strong> se informan solo nodos y relaciones derivados de histories, metadata, Lista Blanca y memoria operativa existentes en la plataforma. No se infieren identidades ni vínculos fuera de la evidencia cargada.</div>
<div class="grid">
<div class="metric"><strong>{e(summary.get('nodes'))}</strong>Nodos</div>
<div class="metric"><strong>{e(summary.get('edges'))}</strong>Relaciones</div>
<div class="metric"><strong>{e(summary.get('mutations'))}</strong>Mutaciones</div>
<div class="metric"><strong>{e(summary.get('whitelist'))}</strong>Coincidencias Lista Blanca</div>
</div>
<h2>Plano relacional</h2><div class="network-visual"><img src="{e(svg_path.name)}" alt="Plano relacional Red Operativa"></div>
<h2>Histories / evidencias seleccionadas</h2><table><thead><tr><th>Sistema</th><th>Archivo</th></tr></thead><tbody>{selected_files_rows}</tbody></table>
<h2>Línea temporal del subconjunto</h2><table><thead><tr><th>Fecha / hora</th><th>Entidad o vínculo</th><th>Detalle</th></tr></thead><tbody>{timeline_rows}</tbody></table>
<h2>Nodos</h2><table><thead><tr>{node_head}</tr></thead><tbody>{node_rows}</tbody></table>
<h2>Relaciones</h2><table><thead><tr><th>Relacion</th><th>Origen</th><th>Destino</th></tr></thead><tbody>{edge_rows}</tbody></table>
<h2>Marcas visuales del canvas</h2><table><thead><tr><th>Fecha / hora</th><th>Usuario</th><th>Herramienta</th><th>Texto</th><th>Color</th></tr></thead><tbody>{annotation_rows}</tbody></table>
<h2>Bitácora automática del análisis</h2><table><thead><tr><th>Fecha / hora</th><th>Usuario</th><th>Acción</th><th>Detalle</th></tr></thead><tbody>{audit_rows}</tbody></table>
</body></html>"""
    html_path.write_text(html, encoding="utf-8")

    try:
        from docx import Document
        from docx.enum.section import WD_ORIENT
        from docx.shared import Cm, Pt, RGBColor
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Falta dependencia python-docx para generar Word: {exc}")

    doc = Document()
    section = doc.sections[0]
    section.orientation = WD_ORIENT.LANDSCAPE
    section.page_width, section.page_height = section.page_height, section.page_width
    section.top_margin = Cm(1.2)
    section.bottom_margin = Cm(1.2)
    section.left_margin = Cm(1.2)
    section.right_margin = Cm(1.2)
    title = doc.add_heading("Informe Red Operativa", level=1)
    title.runs[0].font.color.rgb = RGBColor(0, 68, 111)
    doc.add_paragraph("DEPARTAMENTO DE TECNOLOGIAS ESPECIALES Y DESPLIEGUE TACTICO")
    doc.add_paragraph("SUBSECRETARIA DE TECNOLOGIA APLICADA A LA SEGURIDAD")
    doc.add_paragraph("MINISTERIO DE SEGURIDAD Y JUSTICIA")
    doc.add_paragraph(f"Generado: {dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    doc.add_paragraph(f"Usuario: {user.get('full_name') or user.get('username') or '-'}")
    doc.add_paragraph(f"Filtros: {filter_text}")
    doc.add_paragraph("Regla: se informan solo nodos y relaciones derivados de evidencia cargada. No se infieren identidades ni vínculos fuera del sistema.")
    doc.add_heading("Plano relacional", level=2)
    doc.add_paragraph("La visual tecnica del informe queda incorporada en el HTML y como archivo SVG auditado junto al reporte.")
    doc.add_paragraph(f"Archivo visual: {svg_path.name}")
    metrics = doc.add_table(rows=2, cols=4)
    metrics.style = "Table Grid"
    labels = ["Nodos", "Relaciones", "Mutaciones", "Coincidencias Lista Blanca"]
    values = [summary.get("nodes", 0), summary.get("edges", 0), summary.get("mutations", 0), summary.get("whitelist", 0)]
    for idx, label in enumerate(labels):
        metrics.cell(0, idx).text = label
        metrics.cell(1, idx).text = str(values[idx])
    doc.add_heading("Histories / evidencias seleccionadas", level=2)
    files_table = doc.add_table(rows=1, cols=2)
    files_table.style = "Table Grid"
    files_table.rows[0].cells[0].text = "Sistema"
    files_table.rows[0].cells[1].text = "Archivo"
    for item in (payload.selected_files or payload.files or [])[:120]:
        cells = files_table.add_row().cells
        cells[0].text = str(item.system or "")
        cells[1].text = str(item.file or "")
    doc.add_heading("Linea temporal del subconjunto", level=2)
    timeline_table = doc.add_table(rows=1, cols=3)
    timeline_table.style = "Table Grid"
    for idx, label in enumerate(["Fecha / hora", "Entidad o vinculo", "Detalle"]):
        timeline_table.rows[0].cells[idx].text = label
    timeline_items = re.findall(r"<tr><td>(.*?)</td><td>(.*?)</td><td>(.*?)</td></tr>", timeline_rows)
    for when, title_text, detail_text in timeline_items[:140]:
        cells = timeline_table.add_row().cells
        cells[0].text = html_lib.unescape(when)
        cells[1].text = html_lib.unescape(title_text)
        cells[2].text = html_lib.unescape(detail_text)
    doc.add_heading("Nodos", level=2)
    node_table = doc.add_table(rows=1, cols=len(node_columns))
    node_table.style = "Table Grid"
    for idx, (label, _) in enumerate(node_columns):
        node_table.rows[0].cells[idx].text = label
    for item in nodes[:220]:
        cells = node_table.add_row().cells
        for idx, (_, key) in enumerate(node_columns):
            cells[idx].text = _node_cell(item, key)
    doc.add_heading("Relaciones", level=2)
    edge_table = doc.add_table(rows=1, cols=3)
    edge_table.style = "Table Grid"
    for idx, label in enumerate(["Relacion", "Origen", "Destino"]):
        edge_table.rows[0].cells[idx].text = label
    for item in edges[:260]:
        cells = edge_table.add_row().cells
        cells[0].text = str(item.get("label") or item.get("kind") or "")
        cells[1].text = str(item.get("from_label") or item.get("from") or "")
        cells[2].text = str(item.get("to_label") or item.get("to") or "")
    doc.add_heading("Marcas visuales del canvas", level=2)
    annotation_table = doc.add_table(rows=1, cols=5)
    annotation_table.style = "Table Grid"
    for idx, label in enumerate(["Fecha / hora", "Usuario", "Herramienta", "Texto", "Color"]):
        annotation_table.rows[0].cells[idx].text = label
    if annotations:
        for item in annotations[:220]:
            cells = annotation_table.add_row().cells
            cells[0].text = str(item.get("created_at") or item.get("at") or "")
            cells[1].text = str(item.get("user") or item.get("username") or "")
            cells[2].text = str(item.get("tool") or "")
            cells[3].text = str(item.get("text") or "")
            cells[4].text = str(item.get("color") or "")
    else:
        cells = annotation_table.add_row().cells
        cells[0].text = "Sin marcas visuales incorporadas."
    doc.add_heading("Bitacora automatica del analisis", level=2)
    audit_table = doc.add_table(rows=1, cols=4)
    audit_table.style = "Table Grid"
    for idx, label in enumerate(["Fecha / hora", "Usuario", "Accion", "Detalle"]):
        audit_table.rows[0].cells[idx].text = label
    for item in [row for row in (payload.audit_log or []) if isinstance(row, dict)][-120:]:
        cells = audit_table.add_row().cells
        cells[0].text = str(item.get("at") or "")
        cells[1].text = str(item.get("user") or "")
        cells[2].text = str(item.get("action") or "")
        cells[3].text = str(item.get("detail") or "")
    for paragraph in doc.paragraphs:
        for run in paragraph.runs:
            run.font.size = Pt(9)
    doc.save(word_path)
    digest = _nexa_hash_file(word_path)
    return {
        "ok": True,
        "summary": summary,
        "html_url": _skyeye_output_url(html_path),
        "word_url": _skyeye_output_url(word_path),
        "svg_url": _skyeye_output_url(svg_path),
        "sha256": digest,
    }


@app.post("/api/septier/network/case")
def septier_operational_network_case(payload: SeptierNetworkCaseRequest, user=Depends(_require_auth)):
    nodes = [item for item in (payload.nodes or []) if isinstance(item, dict)]
    edges = [item for item in (payload.edges or []) if isinstance(item, dict)]
    if not nodes:
        raise HTTPException(status_code=400, detail="La red no tiene nodos para guardar")

    def e(value: object) -> str:
        return html_lib.escape(str(value or ""))

    def clean_text_value(value: object, fallback: str = "") -> str:
        text = re.sub(r"\s+", " ", str(value or "").strip())
        return text or fallback

    title = clean_text_value(payload.title, "Red Operativa")
    description = clean_text_value(payload.description)
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    case_id = f"red_{stamp}_{uuid.uuid4().hex[:8]}"
    out_dir = OUTPUTS_DIR / "red_operativa" / "casos" / case_id
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / f"{case_id}.json"
    html_path = out_dir / f"{case_id}.html"
    word_path = out_dir / f"{case_id}.docx"
    svg_path = out_dir / f"{case_id}.svg"
    generated_at = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    layout_payload = dict(payload.layout or {})
    raw_annotations = payload.annotations or layout_payload.get("annotations") or []
    annotations = [item for item in raw_annotations if isinstance(item, dict)][-350:] if isinstance(raw_annotations, list) else []
    canvas_theme = str(payload.canvas_theme or layout_payload.get("canvas_theme") or "app").strip().lower()

    case_payload = {
        "case_id": case_id,
        "title": title,
        "description": description,
        "generated_at": generated_at,
        "user": user.get("full_name") or user.get("username") or "",
        "username": user.get("username") or "",
        "owner_username": user.get("username") or "",
        "owner_full_name": user.get("full_name") or user.get("username") or "",
        "visibility": "privado",
        "shared_with": [],
        "comments": [],
        "activity": [
            {
                "type": "created",
                "username": user.get("username") or "",
                "full_name": user.get("full_name") or user.get("username") or "",
                "message": "Caso Red Operativa creado",
                "created_at": generated_at,
            }
        ],
        "summary": dict(payload.summary or {}),
        "filters": dict(payload.filters or {}),
        "view_options": dict(payload.view_options or {}),
        "selected_files": [item.dict() for item in (payload.selected_files or [])],
        "layout": layout_payload,
        "annotations": annotations,
        "canvas_theme": canvas_theme if canvas_theme in {"app", "light"} else "app",
        "audit_log": [item for item in (payload.audit_log or []) if isinstance(item, dict)][-250:],
        "nodes": nodes,
        "edges": edges,
    }
    json_path.write_text(json.dumps(case_payload, ensure_ascii=False, indent=2), encoding="utf-8")
    payload_hash = _nexa_hash_file(json_path)
    case_payload["sha256"] = payload_hash
    json_path.write_text(json.dumps(case_payload, ensure_ascii=False, indent=2), encoding="utf-8")

    def node_value(item: Dict[str, object], key: str) -> str:
        node_type = str(item.get("type") or "").lower()
        if key == "imsi":
            return str(item.get("primary_imsi") or (item.get("label") if node_type == "imsi" else "") or "")
        if key == "imei":
            return str(item.get("primary_imei") or (item.get("label") if node_type == "imei" else "") or "")
        if key == "description":
            return str(item.get("description") or item.get("subtitle") or "")
        if key == "status":
            tags = item.get("status_tags")
            return " | ".join(str(tag) for tag in tags if str(tag or "").strip()) if isinstance(tags, list) else str(tags or "")
        if key == "places":
            places = item.get("places_seen")
            return " | ".join(str(place) for place in places if str(place or "").strip()) if isinstance(places, list) else str(places or "")
        if key == "files":
            files = item.get("manual_files")
            if not isinstance(files, list):
                return ""
            labels = []
            for file in files:
                if not isinstance(file, dict):
                    continue
                name = str(file.get("name") or "").strip()
                if not name:
                    continue
                digest = str(file.get("sha256") or "").strip()
                url = str(file.get("url") or "").strip()
                labels.append(" | ".join(part for part in [name, f"SHA-256 {digest}" if digest else "", url] if part))
            return " || ".join(labels)
        return str(item.get(key) or "")

    node_columns = [
        ("Tipo", "type"),
        ("Identificador", "label"),
        ("IMSI", "imsi"),
        ("IMEI", "imei"),
        ("Descripcion", "description"),
        ("Rol / funcion", "role"),
        ("Estado operativo", "operational_status"),
        ("Coordenadas", "coordinates"),
        ("Estado", "status"),
        ("Lugares", "places"),
        ("Fuente", "source_label"),
        ("Adjuntos declarados", "files"),
    ]
    node_head = "".join(f"<th>{e(label)}</th>" for label, _ in node_columns)
    node_rows = "".join(
        "<tr>" + "".join(f"<td>{e(node_value(item, key))}</td>" for _, key in node_columns) + "</tr>"
        for item in nodes
    )
    edge_rows = "".join(
        f"<tr><td>{e(item.get('label') or item.get('kind'))}</td><td>{e(item.get('from_label') or item.get('from'))}</td><td>{e(item.get('to_label') or item.get('to'))}</td><td>{e(item.get('note'))}</td></tr>"
        for item in edges
    ) or "<tr><td colspan='4'>Sin relaciones registradas.</td></tr>"
    summary = dict(payload.summary or {})
    summary_values = [
        ("Nodos", summary.get("nodes", len(nodes))),
        ("Relaciones", summary.get("edges", len(edges))),
        ("Mutaciones", summary.get("mutations", 0)),
        ("Lista Blanca", summary.get("whitelist", 0)),
    ]
    metrics_html = "".join(
        f"<div class='metric'><strong>{e(value)}</strong>{e(label)}</div>" for label, value in summary_values
    )
    case_audit_rows = "".join(
        "<tr>"
        f"<td>{e(item.get('at') or item.get('created_at') or '')}</td>"
        f"<td>{e(item.get('user') or item.get('full_name') or item.get('username') or '')}</td>"
        f"<td>{e(item.get('action') or item.get('type') or '')}</td>"
        f"<td>{e(item.get('detail') or item.get('message') or '')}</td>"
        "</tr>"
        for item in (case_payload.get("audit_log") or case_payload.get("activity") or [])
        if isinstance(item, dict)
    ) or "<tr><td colspan='4'>Sin eventos de bitacora incorporados.</td></tr>"
    annotation_rows = "".join(
        "<tr>"
        f"<td>{e(item.get('created_at') or item.get('at') or '')}</td>"
        f"<td>{e(item.get('user') or item.get('username') or '')}</td>"
        f"<td>{e(item.get('tool') or '')}</td>"
        f"<td>{e(item.get('text') or '')}</td>"
        f"<td>{e(item.get('color') or '')}</td>"
        "</tr>"
        for item in annotations
    ) or "<tr><td colspan='5'>Sin marcas visuales incorporadas.</td></tr>"

    def node_position(item: Dict[str, object], idx: int, total: int) -> Tuple[int, int]:
        pos = item.get("canvas_position")
        if isinstance(pos, dict):
            try:
                x = float(pos.get("x", 0))
                y = float(pos.get("y", 0))
                if x > 0 and y > 0:
                    return int(round(x)), int(round(y))
            except Exception:
                pass
        angle = (2 * 3.141592653589793 * idx / max(total, 1)) - (3.141592653589793 / 2)
        return int(round(550 + math.cos(angle) * 360)), int(round(340 + math.sin(angle) * 210))

    def node_visual_color(item: Dict[str, object]) -> Tuple[str, str]:
        node_type = str(item.get("type") or "").lower()
        status = " ".join(str(tag or "").lower() for tag in item.get("status_tags", []) if isinstance(item.get("status_tags"), list))
        if node_type == "mutation" or "mutacion" in status or "mutation" in status:
            return "#fbbf24", "rgba(245,158,11,0.10)"
        if node_type == "whitelist" or "whitelist" in status or "lista blanca" in status:
            return "#56d364", "rgba(86,211,100,0.10)"
        if node_type == "place":
            return "#f472b6", "rgba(244,114,182,0.09)"
        if node_type == "history":
            return "#8fa3b6", "rgba(148,163,184,0.08)"
        if node_type == "imei":
            return "#6ea8fe", "rgba(110,168,254,0.09)"
        return "#12d8ff", "rgba(18,216,255,0.09)"

    def svg_text_lines(value: object, max_chars: int = 24, max_lines: int = 2) -> List[str]:
        raw = re.sub(r"\s+", " ", str(value or "-")).strip()
        if len(raw) <= max_chars:
            return [raw]
        words = raw.split(" ")
        lines: List[str] = []
        line = ""
        for word in words:
            candidate = f"{line} {word}".strip()
            if len(candidate) > max_chars and line:
                lines.append(line)
                line = word
            else:
                line = candidate
        if line:
            lines.append(line)
        out = lines[:max_lines]
        if len(lines) > max_lines and out:
            out[-1] = out[-1][: max(3, max_chars - 3)] + "..."
        return out

    visual_nodes = nodes[:160]
    positions = {str(item.get("id") or item.get("label") or idx): node_position(item, idx, len(visual_nodes)) for idx, item in enumerate(visual_nodes)}
    svg_edges = []
    for item in edges[:450]:
        from_id = str(item.get("from") or "")
        to_id = str(item.get("to") or "")
        if from_id not in positions or to_id not in positions:
            continue
        ax, ay = positions[from_id]
        bx, by = positions[to_id]
        kind = str(item.get("kind") or "").lower()
        is_mutation = "mutation" in kind or "mutacion" in kind
        is_whitelist = "whitelist" in kind
        stroke = "#fbbf24" if is_mutation else "#56d364" if is_whitelist else "#8edaff"
        dash = ' stroke-dasharray="9 7"' if is_mutation else ""
        width = "2.3" if is_whitelist else "1.5"
        svg_edges.append(f'<line x1="{ax}" y1="{ay}" x2="{bx}" y2="{by}" stroke="{stroke}" stroke-opacity="0.58" stroke-width="{width}"{dash}/>')
    svg_nodes = []
    for idx, item in enumerate(visual_nodes):
        node_id = str(item.get("id") or item.get("label") or idx)
        x, y = positions[node_id]
        left = x - 86
        top = y - 48
        stroke, fill = node_visual_color(item)
        title_lines = svg_text_lines(item.get("label") or item.get("id"), 22, 2)
        detail_lines = svg_text_lines(item.get("description") or item.get("subtitle") or item.get("source_label") or item.get("type"), 28, 2)
        title_svg = "".join(f'<text x="{left + 12}" y="{top + 19 + line_idx * 13}" fill="#e8f8ff" font-size="12" font-weight="800">{e(line)}</text>' for line_idx, line in enumerate(title_lines))
        detail_svg = "".join(f'<text x="{left + 12}" y="{top + 62 + line_idx * 11}" fill="#9fb0c1" font-size="9">{e(line)}</text>' for line_idx, line in enumerate(detail_lines))
        node_type = e(str(item.get("type") or "nodo").upper())
        svg_nodes.append(f"""<g filter="url(#softGlow)">
<rect x="{left}" y="{top}" width="172" height="98" rx="9" fill="#06101a" stroke="{stroke}" stroke-opacity="0.82" stroke-width="1.2"/>
<rect x="{left}" y="{top}" width="172" height="98" rx="9" fill="{fill}"/>
{title_svg}<text x="{left + 12}" y="{top + 49}" fill="#8fb8c7" font-size="9" font-weight="700">{node_type}</text>{detail_svg}
</g>""")

    def annotation_svg(item: Dict[str, object]) -> str:
        tool = str(item.get("tool") or "").lower()
        color = e(item.get("color") or "#12d8ff")
        try:
            x1 = float(item.get("x1") or 0)
            y1 = float(item.get("y1") or 0)
            x2 = float(item.get("x2") or x1)
            y2 = float(item.get("y2") or y1)
            stroke_width = max(1.0, min(float(item.get("width") or 4), 12.0))
        except Exception:
            return ""
        if tool == "text":
            return f'<text x="{x1:.1f}" y="{y1:.1f}" fill="{color}" font-size="18" font-weight="800">{e(item.get("text") or "")}</text>'
        if tool == "circle":
            cx = (x1 + x2) / 2
            cy = (y1 + y2) / 2
            rx = abs(x2 - x1) / 2
            ry = abs(y2 - y1) / 2
            return f'<ellipse cx="{cx:.1f}" cy="{cy:.1f}" rx="{rx:.1f}" ry="{ry:.1f}" fill="none" stroke="{color}" stroke-width="{stroke_width:.1f}" opacity="0.92"/>'
        if tool in {"rect", "highlight"}:
            x = min(x1, x2)
            y = min(y1, y2)
            width = abs(x2 - x1)
            height = abs(y2 - y1)
            fill = color if tool == "highlight" else "none"
            fill_opacity = "0.18" if tool == "highlight" else "0"
            opacity = "0.30" if tool == "highlight" else "0.92"
            return f'<rect x="{x:.1f}" y="{y:.1f}" width="{width:.1f}" height="{height:.1f}" rx="8" fill="{fill}" fill-opacity="{fill_opacity}" stroke="{color}" stroke-width="{stroke_width:.1f}" opacity="{opacity}"/>'
        if tool == "arrow":
            return f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" stroke="{color}" stroke-width="{stroke_width:.1f}" opacity="0.92" marker-end="url(#annotArrow)"/>'
        return ""

    annotation_layer = "".join(annotation_svg(item) for item in annotations)
    grid_lines = []
    for x in range(0, 1101, 64):
        grid_lines.append(f'<line x1="{x}" y1="0" x2="{x}" y2="720" stroke="rgba(18,216,255,0.07)" stroke-width="1"/>')
    for y in range(0, 721, 64):
        grid_lines.append(f'<line x1="0" y1="{y}" x2="1100" y2="{y}" stroke="rgba(18,216,255,0.07)" stroke-width="1"/>')
    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="1100" height="720" viewBox="0 0 1100 720">
<defs><filter id="softGlow" x="-30%" y="-30%" width="160%" height="160%"><feDropShadow dx="0" dy="0" stdDeviation="3" flood-color="#12d8ff" flood-opacity="0.18"/></filter>
<marker id="annotArrow" markerWidth="10" markerHeight="10" refX="9" refY="3" orient="auto" markerUnits="strokeWidth"><path d="M0,0 L0,6 L9,3 z" fill="#12d8ff"/></marker>
<linearGradient id="bg" x1="0" x2="1" y1="0" y2="1"><stop offset="0" stop-color="#061826"/><stop offset="1" stop-color="#02070d"/></linearGradient></defs>
<rect width="100%" height="100%" fill="url(#bg)"/><g>{''.join(grid_lines)}</g>
<text x="28" y="38" fill="#e8f8ff" font-family="Arial, sans-serif" font-size="24" font-weight="900" letter-spacing="2">{e(title)}</text>
<text x="28" y="62" fill="#8fb8c7" font-family="Arial, sans-serif" font-size="11" font-weight="700">RED OPERATIVA | {e(generated_at)} | Nodos: {len(nodes)} | Relaciones: {len(edges)}</text>
<g font-family="Arial, sans-serif">{''.join(svg_edges)}{''.join(svg_nodes)}</g><g font-family="Arial, sans-serif">{annotation_layer}</g></svg>"""
    svg_path.write_text(svg, encoding="utf-8")

    html = f"""<!doctype html>
<html lang="es"><head><meta charset="utf-8"><title>{e(title)}</title>
<style>
@page{{size:landscape;margin:1.1cm}}body{{font-family:Arial,sans-serif;margin:24px;color:#001b33}}h1{{color:#00446f;margin-bottom:8px}}h2{{color:#005f91;margin-top:22px}}
.meta,.rule{{border:1px solid #c8d7e6;border-radius:6px;padding:10px;margin:12px 0}}.grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin:16px 0}}
.metric{{border:1px solid #c8d7e6;border-radius:6px;padding:10px;background:#f6f9fc}}.metric strong{{display:block;color:#00446f;font-size:24px}}
table{{border-collapse:collapse;width:100%;margin:12px 0;font-size:12px}}th,td{{border:1px solid #c8d7e6;padding:6px;text-align:left;vertical-align:top}}th{{background:#e9f2fb}}
.mono{{font-family:Consolas,monospace;font-size:11px;word-break:break-all}}
.network-visual{{border:1px solid #c8d7e6;border-radius:8px;padding:10px;background:#06101a;margin:14px 0}}.network-visual img{{width:100%;max-height:720px;object-fit:contain;display:block}}
</style></head><body>
<h1>{e(title)}</h1>
<div class="meta"><strong>DEPARTAMENTO DE TECNOLOGIAS ESPECIALES Y DESPLIEGUE TACTICO</strong><br>
SUBSECRETARIA DE TECNOLOGIA APLICADA A LA SEGURIDAD<br>MINISTERIO DE SEGURIDAD Y JUSTICIA</div>
<div class="meta"><strong>Caso:</strong> {e(case_id)}<br><strong>Generado:</strong> {e(generated_at)}<br><strong>Usuario:</strong> {e(case_payload["user"])}<br><strong>Hash SHA-256:</strong> <span class="mono">{e(payload_hash)}</span></div>
<div class="rule"><strong>Descripcion:</strong> {e(description or "Sin descripcion agregada.")}<br><strong>Regla:</strong> se conserva la red armada por el analista con nodos, relaciones y adjuntos declarados. No se crean identidades ni vinculos fuera de la evidencia visible al momento del guardado.</div>
<div class="grid">{metrics_html}</div>
<h2>Plano relacional</h2><div class="network-visual"><img src="{e(svg_path.name)}" alt="Plano relacional Red Operativa"></div>
<h2>Entidades del caso</h2><table><thead><tr>{node_head}</tr></thead><tbody>{node_rows}</tbody></table>
<h2>Relaciones del caso</h2><table><thead><tr><th>Relacion</th><th>Origen</th><th>Destino</th><th>Observacion</th></tr></thead><tbody>{edge_rows}</tbody></table>
<h2>Marcas visuales del canvas</h2><table><thead><tr><th>Fecha / hora</th><th>Usuario</th><th>Herramienta</th><th>Texto</th><th>Color</th></tr></thead><tbody>{annotation_rows}</tbody></table>
<h2>Bitácora automática del análisis</h2><table><thead><tr><th>Fecha / hora</th><th>Usuario</th><th>Acción</th><th>Detalle</th></tr></thead><tbody>{case_audit_rows}</tbody></table>
</body></html>"""
    html_path.write_text(html, encoding="utf-8")

    try:
        from docx import Document
        from docx.enum.section import WD_ORIENT
        from docx.shared import Cm, Pt, RGBColor
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Falta dependencia python-docx para generar Word: {exc}")

    doc = Document()
    section = doc.sections[0]
    section.orientation = WD_ORIENT.LANDSCAPE
    section.page_width, section.page_height = section.page_height, section.page_width
    section.top_margin = Cm(1.1)
    section.bottom_margin = Cm(1.1)
    section.left_margin = Cm(1.1)
    section.right_margin = Cm(1.1)
    heading = doc.add_heading(title, level=1)
    if heading.runs:
        heading.runs[0].font.color.rgb = RGBColor(0, 68, 111)
    doc.add_paragraph("DEPARTAMENTO DE TECNOLOGIAS ESPECIALES Y DESPLIEGUE TACTICO")
    doc.add_paragraph("SUBSECRETARIA DE TECNOLOGIA APLICADA A LA SEGURIDAD")
    doc.add_paragraph("MINISTERIO DE SEGURIDAD Y JUSTICIA")
    doc.add_paragraph(f"Caso: {case_id}")
    doc.add_paragraph(f"Generado: {generated_at}")
    doc.add_paragraph(f"Usuario: {case_payload['user']}")
    doc.add_paragraph(f"Hash SHA-256: {payload_hash}")
    doc.add_paragraph(f"Descripcion: {description or 'Sin descripcion agregada.'}")
    doc.add_heading("Plano relacional", level=2)
    doc.add_paragraph("La visual tecnica del caso queda incorporada en el HTML y como archivo SVG auditado junto al caso.")
    doc.add_paragraph(f"Archivo visual: {svg_path.name}")
    metric_table = doc.add_table(rows=2, cols=4)
    metric_table.style = "Table Grid"
    for idx, (label, value) in enumerate(summary_values):
        metric_table.cell(0, idx).text = str(label)
        metric_table.cell(1, idx).text = str(value)
    doc.add_heading("Entidades del caso", level=2)
    node_table = doc.add_table(rows=1, cols=len(node_columns))
    node_table.style = "Table Grid"
    for idx, (label, _) in enumerate(node_columns):
        node_table.rows[0].cells[idx].text = label
    for item in nodes[:350]:
        cells = node_table.add_row().cells
        for idx, (_, key) in enumerate(node_columns):
            cells[idx].text = node_value(item, key)
    doc.add_heading("Relaciones del caso", level=2)
    edge_table = doc.add_table(rows=1, cols=4)
    edge_table.style = "Table Grid"
    for idx, label in enumerate(["Relacion", "Origen", "Destino", "Observacion"]):
        edge_table.rows[0].cells[idx].text = label
    for item in edges[:450]:
        cells = edge_table.add_row().cells
        cells[0].text = str(item.get("label") or item.get("kind") or "")
        cells[1].text = str(item.get("from_label") or item.get("from") or "")
        cells[2].text = str(item.get("to_label") or item.get("to") or "")
        cells[3].text = str(item.get("note") or "")
    doc.add_heading("Marcas visuales del canvas", level=2)
    annotation_table = doc.add_table(rows=1, cols=5)
    annotation_table.style = "Table Grid"
    for idx, label in enumerate(["Fecha / hora", "Usuario", "Herramienta", "Texto", "Color"]):
        annotation_table.rows[0].cells[idx].text = label
    if annotations:
        for item in annotations[:220]:
            cells = annotation_table.add_row().cells
            cells[0].text = str(item.get("created_at") or item.get("at") or "")
            cells[1].text = str(item.get("user") or item.get("username") or "")
            cells[2].text = str(item.get("tool") or "")
            cells[3].text = str(item.get("text") or "")
            cells[4].text = str(item.get("color") or "")
    else:
        cells = annotation_table.add_row().cells
        cells[0].text = "Sin marcas visuales incorporadas."
    doc.add_heading("Bitacora automatica del analisis", level=2)
    audit_table = doc.add_table(rows=1, cols=4)
    audit_table.style = "Table Grid"
    for idx, label in enumerate(["Fecha / hora", "Usuario", "Accion", "Detalle"]):
        audit_table.rows[0].cells[idx].text = label
    for item in [row for row in (case_payload.get("audit_log") or case_payload.get("activity") or []) if isinstance(row, dict)][-160:]:
        cells = audit_table.add_row().cells
        cells[0].text = str(item.get("at") or item.get("created_at") or "")
        cells[1].text = str(item.get("user") or item.get("full_name") or item.get("username") or "")
        cells[2].text = str(item.get("action") or item.get("type") or "")
        cells[3].text = str(item.get("detail") or item.get("message") or "")
    for paragraph in doc.paragraphs:
        for run in paragraph.runs:
            run.font.size = Pt(8)
    for table in doc.tables:
        for row in table.rows:
            for cell in row.cells:
                for paragraph in cell.paragraphs:
                    for run in paragraph.runs:
                        run.font.size = Pt(7)
    doc.save(word_path)

    return {
        "ok": True,
        "case_id": case_id,
        "summary": summary_values,
        "json_url": _skyeye_output_url(json_path),
        "html_url": _skyeye_output_url(html_path),
        "word_url": _skyeye_output_url(word_path),
        "svg_url": _skyeye_output_url(svg_path),
        "sha256": payload_hash,
    }


def _septier_network_cases_root() -> Path:
    path = OUTPUTS_DIR / "red_operativa" / "casos"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _septier_network_case_paths(case_id: str) -> Tuple[Path, Path, Path]:
    safe_id = re.sub(r"[^A-Za-z0-9._-]+", "", str(case_id or "").strip())
    if not safe_id or safe_id != case_id:
        raise HTTPException(status_code=400, detail="Identificador de caso invalido")
    root = _septier_network_cases_root().resolve()
    case_dir = (root / safe_id).resolve()
    try:
        case_dir.relative_to(root)
    except ValueError:
        raise HTTPException(status_code=400, detail="Caso fuera de ruta permitida")
    return case_dir / f"{safe_id}.json", case_dir / f"{safe_id}.html", case_dir / f"{safe_id}.docx"


def _network_user_label(user: Dict[str, object]) -> str:
    return str(user.get("full_name") or user.get("username") or "").strip()


def _network_user_roles(user: Dict[str, object]) -> List[str]:
    return [str(role or "").strip().lower() for role in (user.get("roles") or [])]


def _network_is_admin(user: Dict[str, object]) -> bool:
    return "admin" in _network_user_roles(user)


def _network_case_read(case_id: str) -> Tuple[Dict[str, object], Path, Path, Path]:
    json_path, html_path, word_path = _septier_network_case_paths(case_id)
    if not json_path.exists():
        raise HTTPException(status_code=404, detail="Caso Red Operativa no encontrado")
    try:
        data = json.loads(json_path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"No se pudo leer el caso: {exc}")
    if not isinstance(data, dict):
        raise HTTPException(status_code=500, detail="Caso Red Operativa invalido")
    return data, json_path, html_path, word_path


def _network_case_write(data: Dict[str, object], json_path: Path) -> None:
    data["collaboration_updated_at"] = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    json_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def _network_case_access(data: Dict[str, object], user: Dict[str, object], write: bool = False) -> bool:
    if _network_is_admin(user):
        return True
    username = str(user.get("username") or "").strip().lower()
    owner = str(data.get("owner_username") or "").strip().lower()
    if username and owner and username == owner:
        return True
    shared = data.get("shared_with") if isinstance(data.get("shared_with"), list) else []
    for item in shared:
        if not isinstance(item, dict):
            continue
        if str(item.get("username") or "").strip().lower() != username:
            continue
        if not write:
            return True
        permission = str(item.get("permission") or "view").strip().lower()
        return permission in {"comment", "edit", "owner"}
    return False


def _network_case_owner_access(data: Dict[str, object], user: Dict[str, object]) -> bool:
    if _network_is_admin(user):
        return True
    username = str(user.get("username") or "").strip().lower()
    owner = str(data.get("owner_username") or data.get("username") or "").strip().lower()
    return bool(username and owner and username == owner)


def _network_case_permissions(data: Dict[str, object], user: Dict[str, object]) -> Dict[str, bool]:
    can_owner = _network_case_owner_access(data, user)
    return {
        "can_view": _network_case_access(data, user, write=False),
        "can_comment": _network_case_access(data, user, write=True),
        "can_share": can_owner,
        "can_delete": can_owner,
    }


def _network_case_public(data: Dict[str, object], html_path: Path, word_path: Path, json_path: Path) -> Dict[str, object]:
    case_id = str(data.get("case_id") or json_path.stem)
    svg_path = html_path.with_suffix(".svg")
    data = dict(data)
    data["html_url"] = _skyeye_output_url(html_path) if html_path.exists() else ""
    data["word_url"] = _skyeye_output_url(word_path) if word_path.exists() else ""
    data["svg_url"] = _skyeye_output_url(svg_path) if svg_path.exists() else ""
    data["json_url"] = _skyeye_output_url(json_path)
    data["case_id"] = case_id
    return data


def _septier_network_case_summary(json_path: Path) -> Optional[Dict[str, object]]:
    try:
        data = json.loads(json_path.read_text(encoding="utf-8"))
    except Exception:
        return None
    case_id = str(data.get("case_id") or json_path.stem)
    _, html_path, word_path = _septier_network_case_paths(case_id)
    svg_path = html_path.with_suffix(".svg")
    nodes = data.get("nodes") if isinstance(data.get("nodes"), list) else []
    edges = data.get("edges") if isinstance(data.get("edges"), list) else []
    shared = data.get("shared_with") if isinstance(data.get("shared_with"), list) else []
    comments = data.get("comments") if isinstance(data.get("comments"), list) else []
    return {
        "case_id": case_id,
        "title": data.get("title") or "Red Operativa",
        "description": data.get("description") or "",
        "generated_at": data.get("generated_at") or "",
        "user": data.get("user") or "",
        "owner_username": data.get("owner_username") or "",
        "visibility": data.get("visibility") or "privado",
        "shared_count": len(shared),
        "comment_count": len(comments),
        "sha256": data.get("sha256") or "",
        "nodes": len(nodes),
        "edges": len(edges),
        "html_url": _skyeye_output_url(html_path) if html_path.exists() else "",
        "word_url": _skyeye_output_url(word_path) if word_path.exists() else "",
        "svg_url": _skyeye_output_url(svg_path) if svg_path.exists() else "",
        "json_url": _skyeye_output_url(json_path),
    }


@app.get("/api/septier/network/cases")
def septier_operational_network_cases(limit: int = 80, user=Depends(_require_auth)):
    root = _septier_network_cases_root()
    items: List[Dict[str, object]] = []
    for json_path in sorted(root.glob("*/red_*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
        try:
            raw = json.loads(json_path.read_text(encoding="utf-8"))
        except Exception:
            raw = {}
        if isinstance(raw, dict) and not _network_case_access(raw, user, write=False):
            continue
        item = _septier_network_case_summary(json_path)
        if item:
            permissions = _network_case_permissions(raw, user) if isinstance(raw, dict) else {}
            item["permissions"] = permissions
            item["can_share"] = permissions.get("can_share", False)
            item["can_delete"] = permissions.get("can_delete", False)
            items.append(item)
        if len(items) >= max(1, min(limit, 200)):
            break
    return {"ok": True, "items": items}


@app.get("/api/septier/network/cases/{case_id}")
def septier_operational_network_case_get(case_id: str, user=Depends(_require_auth)):
    data, json_path, html_path, word_path = _network_case_read(case_id)
    if not _network_case_access(data, user, write=False):
        raise HTTPException(status_code=403, detail="Caso no compartido con este usuario")
    public = _network_case_public(data, html_path, word_path, json_path)
    public["permissions"] = _network_case_permissions(data, user)
    return {"ok": True, "case": public}


@app.get("/api/septier/network/users")
def septier_operational_network_users(user=Depends(_require_auth)):
    current = str(user.get("username") or "").strip().lower()
    items = []
    for item in list_users():
        if not item.get("is_active"):
            continue
        username = str(item.get("username") or "").strip()
        if not username or username.lower() == current:
            continue
        items.append({
            "username": username,
            "full_name": item.get("full_name") or username,
            "roles": item.get("roles") or [],
        })
    return {"ok": True, "items": items}


@app.get("/api/septier/network/tasks")
def septier_operational_network_tasks(user=Depends(_require_auth)):
    username = str(user.get("username") or "").strip().lower()
    root = _septier_network_cases_root()
    items: List[Dict[str, object]] = []
    for json_path in sorted(root.glob("*/red_*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
        data, _, html_path, word_path = _network_case_read(json_path.stem)
        shared = data.get("shared_with") if isinstance(data.get("shared_with"), list) else []
        matches = [
            item for item in shared
            if isinstance(item, dict) and str(item.get("username") or "").strip().lower() == username
        ]
        if not matches and not _network_is_admin(user):
            continue
        public = _network_case_public(data, html_path, word_path, json_path)
        public["permissions"] = _network_case_permissions(data, user)
        public["can_share"] = public["permissions"].get("can_share", False)
        public["can_delete"] = public["permissions"].get("can_delete", False)
        public["share"] = matches[-1] if matches else {}
        items.append(public)
    return {"ok": True, "items": items[:100]}


@app.get("/api/septier/network/cases/{case_id}/collaboration")
def septier_operational_network_case_collaboration(case_id: str, user=Depends(_require_auth)):
    data, json_path, html_path, word_path = _network_case_read(case_id)
    if not _network_case_access(data, user, write=False):
        raise HTTPException(status_code=403, detail="Caso no compartido con este usuario")
    public = _network_case_public(data, html_path, word_path, json_path)
    public["permissions"] = _network_case_permissions(data, user)
    return {
        "ok": True,
        "case": public,
        "shared_with": data.get("shared_with") if isinstance(data.get("shared_with"), list) else [],
        "comments": data.get("comments") if isinstance(data.get("comments"), list) else [],
        "activity": data.get("activity") if isinstance(data.get("activity"), list) else [],
    }


@app.post("/api/septier/network/cases/{case_id}/share")
def septier_operational_network_case_share(case_id: str, payload: SeptierNetworkCaseShareRequest, user=Depends(_require_auth)):
    data, json_path, html_path, word_path = _network_case_read(case_id)
    if not _network_case_owner_access(data, user):
        raise HTTPException(status_code=403, detail="Solo propietario/admin puede compartir este caso")
    valid_users = {str(item.get("username") or "").strip().lower(): item for item in list_users() if item.get("is_active")}
    permission = str(payload.permission or "comment").strip().lower()
    if permission not in {"view", "comment", "edit"}:
        permission = "comment"
    now = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    shared = data.get("shared_with") if isinstance(data.get("shared_with"), list) else []
    shared_by_username = {
        str(item.get("username") or "").strip().lower(): dict(item)
        for item in shared if isinstance(item, dict) and str(item.get("username") or "").strip()
    }
    added: List[Dict[str, object]] = []
    for raw_username in payload.usernames:
        key = str(raw_username or "").strip().lower()
        if not key or key not in valid_users:
            continue
        target = valid_users[key]
        item = {
            "username": target.get("username") or key,
            "full_name": target.get("full_name") or target.get("username") or key,
            "permission": permission,
            "message": re.sub(r"\s+", " ", str(payload.message or "").strip()),
            "shared_by": user.get("username") or "",
            "shared_by_name": _network_user_label(user),
            "shared_at": now,
            "status": "pendiente",
        }
        shared_by_username[key] = item
        added.append(item)
    data["shared_with"] = list(shared_by_username.values())
    activity = data.get("activity") if isinstance(data.get("activity"), list) else []
    if added:
        activity.append({
            "type": "shared",
            "username": user.get("username") or "",
            "full_name": _network_user_label(user),
            "message": f"Caso compartido con {len(added)} usuario(s)",
            "created_at": now,
        })
    data["activity"] = activity
    data["visibility"] = "compartido" if data["shared_with"] else "privado"
    _network_case_write(data, json_path)
    public = _network_case_public(data, html_path, word_path, json_path)
    public["permissions"] = _network_case_permissions(data, user)
    return {"ok": True, "case": public, "shared_with": data["shared_with"]}


@app.post("/api/septier/network/cases/{case_id}/comments")
def septier_operational_network_case_comment(case_id: str, payload: SeptierNetworkCaseCommentRequest, user=Depends(_require_auth)):
    data, json_path, html_path, word_path = _network_case_read(case_id)
    if not _network_case_access(data, user, write=True):
        raise HTTPException(status_code=403, detail="Sin permisos para comentar este caso")
    message = re.sub(r"\s+", " ", str(payload.message or "").strip())
    if not message:
        raise HTTPException(status_code=400, detail="El comentario no puede estar vacio")
    now = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    comments = data.get("comments") if isinstance(data.get("comments"), list) else []
    comment = {
        "id": uuid.uuid4().hex[:12],
        "username": user.get("username") or "",
        "full_name": _network_user_label(user),
        "message": message,
        "created_at": now,
    }
    comments.append(comment)
    data["comments"] = comments
    activity = data.get("activity") if isinstance(data.get("activity"), list) else []
    activity.append({
        "type": "comment",
        "username": user.get("username") or "",
        "full_name": _network_user_label(user),
        "message": message[:120],
        "created_at": now,
    })
    data["activity"] = activity
    _network_case_write(data, json_path)
    return {"ok": True, "comment": comment, "case": _network_case_public(data, html_path, word_path, json_path)}


@app.post("/api/septier/network/cases/{case_id}/task-status")
def septier_operational_network_case_task_status(case_id: str, payload: SeptierNetworkTaskStatusRequest, user=Depends(_require_auth)):
    data, json_path, html_path, word_path = _network_case_read(case_id)
    username = str(user.get("username") or "").strip().lower()
    shared = data.get("shared_with") if isinstance(data.get("shared_with"), list) else []
    allowed_status = {"pendiente", "en_curso", "revisada", "cerrada"}
    next_status = str(payload.status or "en_curso").strip().lower()
    if next_status not in allowed_status:
        next_status = "en_curso"
    updated = False
    for item in shared:
        if not isinstance(item, dict):
            continue
        if str(item.get("username") or "").strip().lower() == username:
            item["status"] = next_status
            item["status_updated_at"] = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            updated = True
            break
    if not updated:
        raise HTTPException(status_code=403, detail="No hay tarea compartida para este usuario en el caso")
    data["shared_with"] = shared
    activity = data.get("activity") if isinstance(data.get("activity"), list) else []
    activity.append({
        "type": "task_status",
        "username": user.get("username") or "",
        "full_name": _network_user_label(user),
        "message": f"Tarea marcada como {next_status}",
        "created_at": dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    })
    data["activity"] = activity
    _network_case_write(data, json_path)
    return {
        "ok": True,
        "status": next_status,
        "case": _network_case_public(data, html_path, word_path, json_path),
        "shared_with": shared,
    }


@app.delete("/api/septier/network/cases/{case_id}")
def septier_operational_network_case_delete(case_id: str, user=Depends(_require_auth)):
    data, json_path, _html_path, _word_path = _network_case_read(case_id)
    if not _network_case_owner_access(data, user):
        raise HTTPException(status_code=403, detail="Solo propietario/admin puede retirar este caso")
    case_dir = json_path.parent
    if not case_dir.exists() or not json_path.exists():
        raise HTTPException(status_code=404, detail="Caso Red Operativa no encontrado")
    root = _septier_network_cases_root().resolve()
    resolved_dir = case_dir.resolve()
    try:
        resolved_dir.relative_to(root)
    except ValueError:
        raise HTTPException(status_code=400, detail="Caso fuera de ruta permitida")
    shutil.rmtree(resolved_dir)
    return {"ok": True, "case_id": case_id, "detail": "Caso Red Operativa retirado"}


NETWORK_ATTACHMENT_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".webp", ".gif",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx",
    ".csv", ".tsv", ".txt", ".json", ".kml",
}


def _septier_network_attachment_dir() -> Path:
    path = OUTPUTS_DIR / "red_operativa" / "adjuntos"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _septier_network_import_dir() -> Path:
    path = OUTPUTS_DIR / "red_operativa" / "imports"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _network_import_read_rows(raw: bytes, suffix: str, filename: str) -> Tuple[List[str], List[Dict[str, str]], str]:
    suffix = str(suffix or "").lower()
    if suffix in {".csv", ".tsv", ".txt"}:
        from io import BytesIO
        import pandas as pd

        last_error = ""
        encodings = ("utf-8-sig", "utf-16", "latin-1")
        separators = [None, "\t", ";", ",", "|"]
        for encoding in encodings:
            decoded_text = ""
            try:
                decoded_text = raw.decode(encoding, errors="replace")
            except Exception:
                decoded_text = ""
            for separator in separators:
                try:
                    if suffix == ".tsv":
                        separator = "\t"
                    df = pd.read_csv(
                        BytesIO(raw),
                        sep=separator,
                        engine="python",
                        encoding=encoding,
                        dtype=str,
                    ).fillna("")
                    df = df.dropna(axis=1, how="all")
                    columns = [str(c).strip() for c in df.columns]
                    data_columns = [c for c in columns if c and not c.lower().startswith("unnamed:")]
                    if len(data_columns) >= 2 or suffix in {".csv", ".tsv"}:
                        return columns, df.astype(str).head(1200).to_dict(orient="records"), "tsv" if separator == "\t" else "csv"
                except Exception as exc:
                    last_error = str(exc)
                    continue
            if suffix == ".txt" and decoded_text:
                lines = [line.rstrip() for line in decoded_text.splitlines() if line.strip()]
                if lines:
                    sample = lines[:20]
                    delimiter_scores = {
                        "\t": sum(line.count("\t") for line in sample),
                        ";": sum(line.count(";") for line in sample),
                        ",": sum(line.count(",") for line in sample),
                        "|": sum(line.count("|") for line in sample),
                    }
                    delimiter, score = max(delimiter_scores.items(), key=lambda item: item[1])
                    if score:
                        try:
                            df = pd.read_csv(BytesIO(raw), sep=delimiter, engine="python", encoding=encoding, dtype=str).fillna("")
                            columns = [str(c).strip() for c in df.columns]
                            if len([c for c in columns if c]) >= 2:
                                return columns, df.astype(str).head(1200).to_dict(orient="records"), "txt_tabular"
                        except Exception as exc:
                            last_error = str(exc)
                    rows = [{"linea": str(i + 1), "texto": line.strip()} for i, line in enumerate(lines[:1200])]
                    return ["linea", "texto"], rows, "txt"
        raise HTTPException(status_code=400, detail=f"No se pudo leer {filename} como tabla CSV/TXT/TSV: {last_error or 'formato no reconocido'}")
    if suffix in {".xls", ".xlsx"}:
        from io import BytesIO
        import pandas as pd

        try:
            sheets = pd.read_excel(BytesIO(raw), sheet_name=None, dtype=str).items()
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"No se pudo leer {filename} como Excel: {exc}")
        best_sheet = ""
        best_df = pd.DataFrame()
        best_score = -1
        for sheet_name, sheet_df in sheets:
            df = sheet_df.fillna("").dropna(axis=1, how="all")
            columns = [str(c).strip() for c in df.columns]
            meaningful_columns = [c for c in columns if c and not c.lower().startswith("unnamed:")]
            non_empty_rows = int((df.astype(str).apply(lambda row: any(str(v).strip() for v in row), axis=1)).sum()) if not df.empty else 0
            score = (len(meaningful_columns) * 1000) + non_empty_rows
            if score > best_score:
                best_sheet = str(sheet_name)
                best_df = df
                best_score = score
        if best_df.empty or best_score <= 0:
            raise HTTPException(status_code=400, detail=f"El Excel {filename} no contiene hojas tabulares con datos")
        rows = best_df.astype(str).head(1200).to_dict(orient="records")
        columns = [str(c) for c in best_df.columns]
        return columns, rows, f"excel:{best_sheet}"
    if suffix == ".json":
        try:
            parsed = json.loads(raw.decode("utf-8-sig", errors="replace"))
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"No se pudo leer JSON: {exc}")
        if isinstance(parsed, list):
            rows = [item if isinstance(item, dict) else {"valor": item} for item in parsed[:1200]]
        elif isinstance(parsed, dict):
            data = parsed.get("items") or parsed.get("rows") or parsed.get("data")
            if isinstance(data, list):
                rows = [item if isinstance(item, dict) else {"valor": item} for item in data[:1200]]
            else:
                rows = [parsed]
        else:
            rows = [{"valor": parsed}]
        columns = sorted({str(k) for row in rows for k in (row.keys() if isinstance(row, dict) else [])})
        return columns, [{str(k): str(v) for k, v in row.items()} for row in rows], "json"
    return [], [], "archivo"


def _network_import_col(columns: List[str], *names: str) -> str:
    index = {_norm_col(c): c for c in columns}
    for name in names:
        found = index.get(_norm_col(name))
        if found:
            return found
    return ""


def _network_import_identity(value: object, *, exact_15: bool = True) -> str:
    text = str(value or "").strip()
    if exact_15:
        match = re.fullmatch(r"\D*(\d{15})\D*", text)
        return match.group(1) if match else ""
    digits = re.sub(r"\D+", "", text)
    return digits if digits else text


def _network_import_node(
    nodes: Dict[str, Dict[str, object]],
    node_id: str,
    node_type: str,
    label: str,
    **extra: object,
) -> Dict[str, object]:
    if node_id in nodes:
        node = nodes[node_id]
        node["detections"] = int(node.get("detections") or 0) + int(extra.pop("detections", 1) or 1)
        places = set(node.get("places_seen") if isinstance(node.get("places_seen"), list) else [])
        if extra.get("place"):
            places.add(str(extra["place"]))
        if places:
            node["places_seen"] = sorted(places)
        if extra.get("first_seen") and not node.get("first_seen"):
            node["first_seen"] = extra["first_seen"]
        return node
    node = {
        "id": node_id,
        "type": node_type,
        "label": label,
        "subtitle": extra.pop("subtitle", ""),
        "description": extra.pop("description", ""),
        "role": extra.pop("role", ""),
        "operational_status": extra.pop("operational_status", "interpretado"),
        "source_label": extra.pop("source_label", "Importador relacional"),
        "coordinates": extra.pop("coordinates", ""),
        "status_tags": extra.pop("status_tags", ["importado", node_type]),
        "category": extra.pop("category", ""),
        "primary_imsi": label if node_type == "imsi" else extra.pop("primary_imsi", ""),
        "primary_imei": label if node_type == "imei" else extra.pop("primary_imei", ""),
        "primary_phone": label if node_type == "phone" else extra.pop("primary_phone", ""),
        "manual_note": extra.pop("manual_note", ""),
        "manual_files": extra.pop("manual_files", []),
        "detections": int(extra.pop("detections", 1) or 1),
        **extra,
    }
    if node.get("place"):
        node["places_seen"] = [node["place"]]
    nodes[node_id] = node
    return node


def _network_import_edge(edges: Dict[str, Dict[str, object]], from_id: str, to_id: str, kind: str, label: str, note: str = "") -> None:
    if not from_id or not to_id or from_id == to_id:
        return
    edge_id = re.sub(r"[^a-zA-Z0-9:_\-.]+", "_", f"import:{from_id}:{kind}:{to_id}")[:220]
    if edge_id in edges:
        return
    edges[edge_id] = {
        "id": edge_id,
        "from": from_id,
        "to": to_id,
        "kind": kind,
        "label": label,
        "note": note,
        "source_label": "Importador relacional",
    }


def _network_import_analyze(raw: bytes, filename: str, evidence_type: str, saved_file: Dict[str, object]) -> Dict[str, object]:
    suffix = Path(filename).suffix.lower()
    digest = str(saved_file.get("sha256") or hashlib.sha256(raw).hexdigest())
    columns, rows, parsed_as = _network_import_read_rows(raw, suffix, filename)
    source_prefix = f"import:{digest[:16]}"
    nodes: Dict[str, Dict[str, object]] = {}
    edges: Dict[str, Dict[str, object]] = {}
    file_node_id = f"{source_prefix}:file"
    _network_import_node(
        nodes,
        file_node_id,
        "history" if evidence_type == "history" else "evidence",
        filename,
        subtitle=f"Archivo interpretado como {parsed_as}",
        description=f"Columnas leidas: {len(columns)} | Filas muestreadas: {len(rows)}",
        role="Fuente documental",
        source_label="Carga guiada relacional",
        status_tags=["importado", evidence_type or parsed_as, "staging_seguro"],
        manual_note="Archivo interpretado para proponer entidades y relaciones. No modifica motores finales.",
        manual_files=[saved_file],
        detections=0,
    )
    imsi_col = _network_import_col(columns, "IMSI", "IMSI / MAC", "IMSI/MAC", "imsi_mac", "imsi mac")
    imei_col = _network_import_col(columns, "IMEI", "device_id", "device id", "imei_1", "imei_2")
    phone_col = _network_import_col(columns, "telefono", "teléfono", "phone", "msisdn", "celular")
    entity_col = _network_import_col(columns, "identificador", "id", "id entidad", "entidad", "alias", "target", "objetivo id", "referencia")
    person_col = _network_import_col(columns, "nombre", "persona", "apellido y nombre", "apellidoynombre", "objetivo")
    place_col = _network_import_col(columns, "lugar", "lugar operativo", "complejo", "operacion", "op / evento", "op", "zona")
    model_col = _network_import_col(columns, "modelo", "model")
    time_col = _network_import_col(columns, "event time", "time", "fecha", "visto", "timestamp")
    lat_col = _network_import_col(columns, "lat", "latitude", "latitud")
    lon_col = _network_import_col(columns, "lon", "lng", "longitude", "longitud")
    role_map = {
        "imsi": imsi_col,
        "imei": imei_col,
        "phone": phone_col,
        "entity": entity_col,
        "person": person_col,
        "place": place_col,
        "model": model_col,
        "time": time_col,
        "lat": lat_col,
        "lon": lon_col,
    }
    for row in rows:
        imsi = _network_import_identity(row.get(imsi_col), exact_15=True) if imsi_col else ""
        imei = _network_import_identity(row.get(imei_col), exact_15=True) if imei_col else ""
        phone = _network_import_identity(row.get(phone_col), exact_15=False) if phone_col else ""
        entity = str(row.get(entity_col) or "").strip() if entity_col else ""
        person = str(row.get(person_col) or "").strip() if person_col else ""
        place_raw = str(row.get(place_col) or "").strip() if place_col else ""
        place = _septier_place_bucket(place_raw) if place_raw else ""
        model = str(row.get(model_col) or "").strip() if model_col else ""
        first_seen = str(row.get(time_col) or "").strip() if time_col else ""
        coords = ""
        if lat_col and lon_col and str(row.get(lat_col) or "").strip() and str(row.get(lon_col) or "").strip():
            coords = f"{str(row.get(lat_col)).strip()}, {str(row.get(lon_col)).strip()}"
        place_node_id = ""
        if place:
            place_node_id = f"{source_prefix}:place:{_norm_col(place)}"
            _network_import_node(
                nodes,
                place_node_id,
                "place",
                place,
                subtitle=place_raw or place,
                category="place",
                source_label=filename,
                detections=1,
            )
            _network_import_edge(edges, file_node_id, place_node_id, "contiene_lugar", "History pertenece a lugar operativo")
        if imsi:
            imsi_id = f"{source_prefix}:imsi:{imsi}"
            _network_import_node(
                nodes,
                imsi_id,
                "imsi",
                imsi,
                subtitle=model or "IMSI detectado",
                description=place_raw,
                source_label=filename,
                coordinates=coords,
                status_tags=["importado", "imsi", "propuesto"],
                place=place,
                first_seen=first_seen,
                detections=1,
            )
            _network_import_edge(edges, file_node_id, imsi_id, "detectado_en_archivo", "Entidad detectada en archivo")
            if place_node_id:
                _network_import_edge(edges, imsi_id, place_node_id, "detectado_en", "IMSI detectado en lugar", first_seen)
        if imei:
            imei_id = f"{source_prefix}:imei:{imei}"
            _network_import_node(
                nodes,
                imei_id,
                "imei",
                imei,
                subtitle=model or "IMEI detectado",
                description=place_raw,
                source_label=filename,
                coordinates=coords,
                status_tags=["importado", "imei", "propuesto"],
                place=place,
                first_seen=first_seen,
                detections=1,
            )
            _network_import_edge(edges, file_node_id, imei_id, "detectado_en_archivo", "Entidad detectada en archivo")
            if imsi:
                _network_import_edge(edges, f"{source_prefix}:imsi:{imsi}", imei_id, "imei_imsi", "IMSI asociado a IMEI", model)
            if place_node_id:
                _network_import_edge(edges, imei_id, place_node_id, "visto_en", "IMEI visto en lugar", first_seen)
        if entity:
            entity_id = f"{source_prefix}:entity:{_norm_col(entity)[:80]}"
            _network_import_node(
                nodes,
                entity_id,
                "evidence",
                entity,
                subtitle="Entidad creada desde columna",
                description=place_raw or model,
                category="evidence",
                source_label=filename,
                coordinates=coords,
                status_tags=["importado", "entidad", "propuesto"],
                place=place,
                first_seen=first_seen,
                detections=1,
            )
            _network_import_edge(edges, file_node_id, entity_id, "detectado_en_archivo", "Entidad creada desde columna")
            if place_node_id:
                _network_import_edge(edges, entity_id, place_node_id, "asociado_a_lugar", "Entidad asociada a lugar", first_seen)
        if phone:
            phone_id = f"{source_prefix}:phone:{_norm_col(phone)[:40]}"
            _network_import_node(nodes, phone_id, "phone", phone, subtitle="Telefono / MSISDN", source_label=filename, detections=1)
            _network_import_edge(edges, file_node_id, phone_id, "detectado_en_archivo", "Telefono declarado en archivo")
            if imsi:
                _network_import_edge(edges, phone_id, f"{source_prefix}:imsi:{imsi}", "telefono_imsi", "Telefono asociado a IMSI")
        if person:
            person_id = f"{source_prefix}:person:{_norm_col(person)[:60]}"
            _network_import_node(nodes, person_id, "person", person, subtitle="Persona / alias", source_label=filename, detections=1)
            _network_import_edge(edges, file_node_id, person_id, "evidencia", "Persona declarada en archivo")
            if phone:
                _network_import_edge(edges, person_id, f"{source_prefix}:phone:{_norm_col(phone)[:40]}", "persona_dispositivo", "Persona vinculada a telefono")
            if imsi:
                _network_import_edge(edges, person_id, f"{source_prefix}:imsi:{imsi}", "persona_dispositivo", "Persona vinculada a IMSI")
    sample_rows = [{str(k): str(v) for k, v in row.items()} for row in rows[:8]]
    return {
        "columns": columns,
        "column_roles": {k: v for k, v in role_map.items() if v},
        "sample_rows": sample_rows,
        "nodes": list(nodes.values())[:600],
        "edges": list(edges.values())[:1200],
        "summary": {
            "filename": filename,
            "sha256": digest,
            "parsed_as": parsed_as,
            "columns": len(columns),
            "sampled_rows": len(rows),
            "nodes": len(nodes),
            "edges": len(edges),
            "imsi": sum(1 for n in nodes.values() if n.get("type") == "imsi"),
            "imei": sum(1 for n in nodes.values() if n.get("type") == "imei"),
            "places": sum(1 for n in nodes.values() if n.get("type") == "place"),
        },
    }


@app.post("/api/septier/network/attachments")
async def septier_operational_network_attachments(
    node_id: str = Form(""),
    files: List[UploadFile] = File(...),
    user=Depends(_require_auth),
):
    safe_node = re.sub(r"[^A-Za-z0-9._-]+", "_", str(node_id or "red_operativa").strip()).strip("._") or "red_operativa"
    target_dir = _septier_network_attachment_dir() / safe_node[:80]
    target_dir.mkdir(parents=True, exist_ok=True)
    saved = []
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    for up in files:
        if not up.filename:
            continue
        original = Path(up.filename).name
        suffix = Path(original).suffix.lower()
        if suffix not in NETWORK_ATTACHMENT_EXTENSIONS:
            raise HTTPException(status_code=400, detail=f"Extension no permitida para adjunto: {suffix or original}")
        raw = await up.read()
        _scan_uploaded_bytes(raw, up.filename or "archivo", "upload", user)
        if not raw:
            continue
        digest = hashlib.sha256(raw).hexdigest()
        stem = re.sub(r"[^A-Za-z0-9._-]+", "_", Path(original).stem).strip("._") or "adjunto"
        target = target_dir / f"{stamp}_{stem[:90]}{suffix}"
        i = 1
        while target.exists():
            target = target_dir / f"{stamp}_{stem[:82]}_{i}{suffix}"
            i += 1
        target.write_bytes(raw)
        saved.append({
            "name": original,
            "stored_name": target.name,
            "size": len(raw),
            "type": up.content_type or "application/octet-stream",
            "sha256": digest,
            "url": _skyeye_output_url(target),
            "uploaded_by": user.get("username") or user.get("full_name") or "",
            "uploaded_at": dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        })
    if not saved:
        raise HTTPException(status_code=400, detail="No se recibieron adjuntos validos")
    return {"ok": True, "saved": saved}


@app.post("/api/septier/network/import/interpret")
async def septier_operational_network_import_interpret(
    evidence_type: str = Form("evidence"),
    file: UploadFile = File(...),
    user=Depends(_require_auth),
):
    if not file.filename:
        raise HTTPException(status_code=400, detail="Sube un archivo para interpretar")
    original = Path(file.filename).name
    suffix = Path(original).suffix.lower()
    if suffix not in NETWORK_ATTACHMENT_EXTENSIONS:
        raise HTTPException(status_code=400, detail=f"Extension no permitida para Red Operativa: {suffix or original}")
    raw = await file.read()
    _scan_uploaded_bytes(raw, file.filename or "archivo", "upload", user)
    if not raw:
        raise HTTPException(status_code=400, detail="El archivo esta vacio")
    digest = hashlib.sha256(raw).hexdigest()
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    stem = re.sub(r"[^A-Za-z0-9._-]+", "_", Path(original).stem).strip("._") or "evidencia"
    target_dir = _septier_network_import_dir()
    target = target_dir / f"{stamp}_{stem[:90]}{suffix}"
    i = 1
    while target.exists():
        target = target_dir / f"{stamp}_{stem[:82]}_{i}{suffix}"
        i += 1
    target.write_bytes(raw)
    saved_file = {
        "name": original,
        "stored_name": target.name,
        "size": len(raw),
        "type": file.content_type or "application/octet-stream",
        "sha256": digest,
        "url": _skyeye_output_url(target),
        "uploaded_by": user.get("username") or user.get("full_name") or "",
        "uploaded_at": dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    analysis = _network_import_analyze(raw, original, evidence_type, saved_file)
    return {"ok": True, "file": saved_file, **analysis}


@app.put("/api/septier/files/{system_name}/{filename}/metadata")
def septier_file_metadata_update(
    system_name: str,
    filename: str,
    payload: SeptierHistoryMetadataUpdate,
    user=Depends(_require_edit),
):
    system = system_name.lower()
    file_path = _septier_target_dir(system) / Path(filename).name
    if not file_path.exists() or not file_path.is_file():
        raise HTTPException(status_code=404, detail="Archivo Septier no encontrado")
    updated = upsert_septier_history_metadata({
        "source": system,
        "archivo_origen": file_path.name,
        "lugar_operativo": payload.lugar_operativo,
        "complejo": payload.complejo,
        "modulo": payload.modulo,
        "ala": payload.ala,
        "ubicacion": payload.ubicacion,
        "coordenadas": payload.coordenadas,
        "observacion": payload.observacion,
        "updated_by": user.get("username") or user.get("full_name") or "",
    })
    return {"ok": True, "metadata": updated}


def _nexa_ensure_dirs() -> None:
    NEXA_INPUT_DIR.mkdir(parents=True, exist_ok=True)
    NEXA_LOG_DIR.mkdir(parents=True, exist_ok=True)
    NEXA_MANUALS_DIR.mkdir(parents=True, exist_ok=True)
    NEXA_RUNS_DIR.mkdir(parents=True, exist_ok=True)


def _nexa_manuals_index_path() -> Path:
    _nexa_ensure_dirs()
    return NEXA_MANUALS_DIR / "manuals_index.json"


def _nexa_load_manuals_index() -> List[Dict[str, object]]:
    path = _nexa_manuals_index_path()
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except Exception:
        return []


def _nexa_save_manuals_index(items: List[Dict[str, object]]) -> None:
    _nexa_manuals_index_path().write_text(json.dumps(items, ensure_ascii=False, indent=2), encoding="utf-8")


def _nexa_manual_item(manual_id: str) -> Dict[str, object]:
    safe_id = re.sub(r"[^A-Za-z0-9._-]+", "_", str(manual_id or "").strip())
    for item in _nexa_load_manuals_index():
        if str(item.get("id") or "") == safe_id:
            return item
    raise HTTPException(status_code=404, detail="Manual NEXA no encontrado")


def _nexa_extract_pdf_text(pdf_path: Path) -> Tuple[str, List[Dict[str, object]]]:
    try:
        from pypdf import PdfReader
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Falta dependencia pypdf para leer manuales PDF: {exc}")
    reader = PdfReader(str(pdf_path))
    pages: List[Dict[str, object]] = []
    parts: List[str] = []
    for idx, page in enumerate(reader.pages, start=1):
        text = page.extract_text() or ""
        clean = re.sub(r"\s+", " ", text).strip()
        pages.append({"page": idx, "text": clean})
        if clean:
            parts.append(f"[PAGINA {idx}]\n{clean}")
    return "\n\n".join(parts), pages


def _nexa_manual_url(manual_id: str) -> str:
    return f"/api/nexa/manuals/{urllib.parse.quote(manual_id)}/download"


def _nexa_search_manuals(query: str, limit: int = 5) -> List[Dict[str, object]]:
    query = str(query or "").strip()
    if not query:
        return []
    terms = [t for t in re.findall(r"[a-zA-Z0-9_áéíóúñÁÉÍÓÚÑ]+", query.lower()) if len(t) > 2]
    if not terms:
        return []
    matches: List[Dict[str, object]] = []
    for item in _nexa_load_manuals_index():
        text_path = Path(str(item.get("text_path") or ""))
        if not text_path.exists():
            continue
        text = text_path.read_text(encoding="utf-8", errors="replace")
        for block in re.split(r"\n\n(?=\[PAGINA \d+\])", text):
            lower = block.lower()
            score = sum(lower.count(term) for term in terms)
            if score <= 0:
                continue
            page_match = re.search(r"\[PAGINA (\d+)\]", block)
            page = int(page_match.group(1)) if page_match else 0
            snippet = re.sub(r"\s+", " ", re.sub(r"^\[PAGINA \d+\]\s*", "", block)).strip()
            matches.append({
                "manual_id": item.get("id"),
                "title": item.get("title") or item.get("original_filename"),
                "page": page,
                "score": score,
                "snippet": snippet[:900],
                "sha256": item.get("sha256"),
            })
    matches.sort(key=lambda x: int(x.get("score") or 0), reverse=True)
    return matches[:limit]


def _nexa_file_info(path: Path, source: str, system: str = "", folder: str = "") -> Dict[str, object]:
    return {
        "source": source,
        "system": system,
        "folder": folder,
        "name": path.name,
        "size": path.stat().st_size,
        "modified_at": dt.datetime.fromtimestamp(path.stat().st_mtime).isoformat(timespec="seconds"),
    }


def _nexa_hash_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _nexa_safe_input_name(original_name: str) -> str:
    name = Path(original_name).name
    stem = re.sub(r"[^A-Za-z0-9._-]+", "_", Path(name).stem).strip("._") or "nexa_input"
    suffix = Path(name).suffix.lower()
    if suffix not in {".csv", ".txt", ".json"}:
        raise HTTPException(status_code=400, detail="NEXA acepta CSV, TXT o JSON como evidencia de entrada")
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"nexa_{stamp}_{stem}{suffix}"


def _nexa_source_path(ref: NexaSourceFile) -> Path:
    source = str(ref.source or "").strip().lower()
    system = str(ref.system or "").strip().lower()
    filename = Path(str(ref.file or "")).name
    folder = re.sub(r"[^A-Za-z0-9._-]+", "_", str(ref.folder or "").strip())
    if not filename:
        raise HTTPException(status_code=400, detail="Archivo NEXA invalido")
    if source == "septier":
        return _septier_target_dir(system) / filename
    if source == "skyeye_inbox":
        return REPORTS_DIR / filename
    if source == "skyeye_processed":
        if not folder:
            raise HTTPException(status_code=400, detail="Falta carpeta procesada SkyEye")
        return PROCESSED_DIR / folder / filename
    if source == "nexa_input":
        return NEXA_INPUT_DIR / filename
    raise HTTPException(status_code=400, detail="Fuente NEXA invalida")


def _nexa_list_runs(limit: int = 50) -> List[Dict[str, object]]:
    _nexa_ensure_dirs()
    items: List[Dict[str, object]] = []
    for p in sorted(NEXA_RUNS_DIR.glob("*/manifest.json"), key=lambda x: x.stat().st_mtime, reverse=True)[:limit]:
        try:
            manifest = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            manifest = {"run_id": p.parent.name, "status": "manifest_invalido"}
        log_path = p.parent / "nexa_run.log"
        manifest["manifest_url"] = _skyeye_output_url(p)
        manifest["log_url"] = _skyeye_output_url(log_path) if log_path.exists() else ""
        items.append(manifest)
    return items


def _nexa_run_dir(run_id: str) -> Path:
    safe_id = re.sub(r"[^A-Za-z0-9._-]+", "_", str(run_id or "").strip())
    if not safe_id:
        raise HTTPException(status_code=400, detail="Run NEXA invalido")
    path = (NEXA_RUNS_DIR / safe_id).resolve()
    try:
        path.relative_to(NEXA_RUNS_DIR.resolve())
    except Exception:
        raise HTTPException(status_code=400, detail="Run NEXA fuera de ruta permitida")
    if not path.exists() or not path.is_dir():
        raise HTTPException(status_code=404, detail="Run NEXA no encontrado")
    return path


def _nexa_load_manifest(run_dir: Path) -> Dict[str, object]:
    manifest_path = run_dir / "manifest.json"
    if not manifest_path.exists():
        raise HTTPException(status_code=404, detail="Manifest NEXA no encontrado")
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return data
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Manifest NEXA invalido: {exc}")
    raise HTTPException(status_code=500, detail="Manifest NEXA invalido")


def _nexa_save_manifest(run_dir: Path, manifest: Dict[str, object]) -> None:
    (run_dir / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")


def _nexa_log(run_dir: Path, message: str) -> None:
    log_path = run_dir / "nexa_run.log"
    stamp = dt.datetime.now().isoformat(timespec="seconds")
    with log_path.open("a", encoding="utf-8") as fh:
        fh.write(f"[{stamp}] {message}\n")


def _nexa_snapshot_files(run_dir: Path) -> List[Path]:
    evidence_dir = run_dir / "input_snapshot"
    if not evidence_dir.exists():
        return []
    return sorted([p for p in evidence_dir.iterdir() if p.is_file()], key=lambda x: x.name.lower())


def _nexa_read_csv(path: Path):
    import pandas as pd

    last_error: Optional[Exception] = None
    for encoding in ("utf-8-sig", "utf-8", "latin-1"):
        try:
            return pd.read_csv(path, sep=None, engine="python", encoding=encoding, dtype=str).fillna("")
        except Exception as exc:
            last_error = exc
    raise HTTPException(status_code=400, detail=f"NEXA no pudo leer CSV {path.name}: {last_error}")


def _nexa_column_map(columns: List[object]) -> Dict[str, str]:
    return {_norm_col(c): str(c) for c in columns}


def _nexa_detect_role(path: Path) -> Tuple[str, object]:
    df = _nexa_read_csv(path)
    cols = _nexa_column_map(list(df.columns))
    has_networkcfg = all(_norm_col(c) in cols for c in ["Network Name", "ARFCN", "LAC", "Cell ID"])
    has_history = any(_norm_col(c) in cols for c in ["Home Network", "IMSI / MAC", "IMSI", "IMEI", "Event Time"])
    if has_networkcfg:
        return "networkcfg", df
    if has_history:
        return "history", df
    return "csv", df


def _nexa_html_page(title: str, body: str) -> str:
    return f"""<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <title>{html_lib.escape(title)}</title>
  <style>
    body {{ font-family: Segoe UI, Arial, sans-serif; color:#0b1f36; margin:28px; }}
    h1, h2 {{ color:#003b69; }}
    .meta, .card {{ border:1px solid #cfd8e3; border-radius:8px; padding:12px; margin:12px 0; }}
    .grid {{ display:grid; grid-template-columns:repeat(3,1fr); gap:10px; }}
    .kpi {{ font-size:28px; font-weight:800; color:#003b69; }}
    table {{ width:100%; border-collapse:collapse; margin:10px 0; }}
    th, td {{ border:1px solid #cfd8e3; padding:7px; text-align:left; font-size:13px; }}
    th {{ background:#eaf2fb; }}
    .muted {{ color:#5c6b7a; }}
  </style>
</head>
<body>
{body}
</body>
</html>"""


def _nexa_table(headers: List[str], rows: List[List[object]]) -> str:
    th = "".join(f"<th>{html_lib.escape(str(h))}</th>" for h in headers)
    trs = []
    for row in rows:
        tds = "".join(f"<td>{html_lib.escape(str(v))}</td>" for v in row)
        trs.append(f"<tr>{tds}</tr>")
    return f"<table><thead><tr>{th}</tr></thead><tbody>{''.join(trs) or '<tr><td colspan=\"99\">Sin datos</td></tr>'}</tbody></table>"


def _nexa_execute_rf_analyzer(run_dir: Path, manifest: Dict[str, object]) -> List[Dict[str, object]]:
    snapshots = _nexa_snapshot_files(run_dir)
    if not snapshots:
        raise HTTPException(status_code=400, detail="NEXA no tiene archivos snapshot para analizar")
    history_path: Optional[Path] = None
    networkcfg_path: Optional[Path] = None
    for path in snapshots:
        if path.suffix.lower() != ".csv":
            continue
        role, _df = _nexa_detect_role(path)
        if role == "history" and history_path is None:
            history_path = path
        elif role == "networkcfg" and networkcfg_path is None:
            networkcfg_path = path

    if history_path is None or networkcfg_path is None:
        raise HTTPException(status_code=400, detail="NEXA RF Analyzer requiere un history.csv y un networkcfg.csv reconocibles")
    if not NEXA_RF_ENGINE.exists():
        raise HTTPException(status_code=500, detail=f"No se encontro el motor RF NEXA: {NEXA_RF_ENGINE}")

    engine_out = run_dir / "rf_engine_v0_5_1"
    engine_out.mkdir(parents=True, exist_ok=True)
    engine_log = run_dir / "rf_engine_console.log"
    case_name = str(manifest.get("case_name") or "NEXA").strip() or "NEXA"
    analyst = str(manifest.get("analyst") or manifest.get("created_by") or "NEXA").strip() or "NEXA"
    position = str(manifest.get("position") or "NEXA Digital Forensic Suite").strip() or "NEXA Digital Forensic Suite"
    institution = str(manifest.get("institution") or "").strip()
    location = str(manifest.get("location") or "").strip()
    report_place = " - ".join([p for p in [institution, location] if p]) or case_name
    case_number = str(manifest.get("case_number") or case_name or "____/26").strip()
    cmd = [
        sys.executable,
        str(NEXA_RF_ENGINE),
        "--networkcfg",
        str(networkcfg_path.resolve()),
        "--history",
        str(history_path.resolve()),
        "--out",
        str(engine_out.resolve()),
        "--firma",
        analyst,
        "--cargo",
        position,
        "--lugar",
        report_place,
        "--nota",
        case_number,
    ]

    _nexa_log(run_dir, f"rf_engine_original_v0_5_1 iniciado history={history_path.name} networkcfg={networkcfg_path.name}")
    creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
    try:
        result = subprocess.run(
            cmd,
            cwd=str(NEXA_SUITE_DIR),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            creationflags=creation_flags,
            timeout=180,
        )
    except subprocess.TimeoutExpired as exc:
        engine_log.write_text(f"TIMEOUT ejecutando NEXA RF v0.5.1\n{exc}", encoding="utf-8")
        raise HTTPException(status_code=504, detail="NEXA RF Analyzer excedio el tiempo maximo")

    engine_log.write_text(
        "COMMAND:\n"
        + subprocess.list2cmdline(cmd)
        + "\n\nSTDOUT:\n"
        + (result.stdout or "")
        + "\n\nSTDERR:\n"
        + (result.stderr or ""),
        encoding="utf-8",
    )
    if result.returncode != 0:
        raise HTTPException(status_code=500, detail=f"NEXA RF Analyzer finalizo con codigo {result.returncode}. Revisar rf_engine_console.log")

    outputs: List[Dict[str, object]] = [{"label": "Log motor RF v0.5.1", "path": str(engine_log), "url": _skyeye_output_url(engine_log), "sha256": _nexa_hash_file(engine_log)}]
    suffix_labels = {
        ".docx": "Informe Word NEXA v0.5.1",
        ".pdf": "Informe PDF NEXA v0.5.1",
        ".csv": "Tabla procesada NEXA",
        ".png": "Grafico NEXA",
    }
    for p in sorted(engine_out.rglob("*")):
        if not p.is_file() or p.suffix.lower() not in suffix_labels:
            continue
        outputs.append({
            "label": suffix_labels[p.suffix.lower()],
            "path": str(p),
            "url": _skyeye_output_url(p),
            "sha256": _nexa_hash_file(p),
        })
    if not any(str(o.get("path", "")).lower().endswith(".docx") for o in outputs):
        raise HTTPException(status_code=500, detail="NEXA RF v0.5.1 no genero DOCX. Revisar log del motor.")
    _nexa_log(run_dir, f"rf_engine_original_v0_5_1 finalizado outputs={len(outputs)}")
    return outputs


def _nexa_execute_mapeo_tactico(run_dir: Path, manifest: Dict[str, object]) -> List[Dict[str, object]]:
    from app.nexa_suite.modules.mapeo_tactico_guardian import generar_mapeo_tactico

    network_candidates: List[Tuple[Path, object]] = []
    for path in _nexa_snapshot_files(run_dir):
        if path.suffix.lower() != ".csv":
            continue
        role, df = _nexa_detect_role(path)
        if role == "networkcfg":
            network_candidates.append((path, df))
    if not network_candidates:
        raise HTTPException(status_code=400, detail="Mapeo tactico requiere un CSV networkcfg con Network Name, ARFCN, LAC y Cell ID")

    source_path, df = network_candidates[0]
    orientation = str(manifest.get("orientation") or "").strip() or "NO_INFORMADA"
    antennas = str(manifest.get("antennas") or "").strip()
    try:
        result = generar_mapeo_tactico(source_path, run_dir, orientation, antennas)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"NEXA mapeo tactico fallo: {exc}")

    txt_path = Path(str(result["txt_path"]))
    html_path = Path(str(result["html_path"]))
    _nexa_log(run_dir, f"mapeo_tactico_getac generado archivo={source_path.name} orientacion={orientation} antenas={antennas}")
    return [
        {"label": "Mapeo tactico GETAC TXT", "path": str(txt_path), "url": _skyeye_output_url(txt_path), "sha256": _nexa_hash_file(txt_path)},
        {"label": "Mapeo tactico GETAC HTML", "path": str(html_path), "url": _skyeye_output_url(html_path), "sha256": _nexa_hash_file(html_path)},
    ]


def _nexa_restore_suite_input(suite_input: Path, backup_dir: Path, staged_paths: List[Path]) -> None:
    for staged in staged_paths:
        try:
            if staged.exists() and staged.is_file():
                staged.unlink()
        except Exception:
            pass
    if not backup_dir.exists():
        return
    for saved in sorted(backup_dir.iterdir(), key=lambda x: x.name.lower()):
        if not saved.is_file():
            continue
        target = suite_input / saved.name
        i = 1
        while target.exists():
            target = suite_input / f"{saved.stem}_restore_{i}{saved.suffix}"
            i += 1
        shutil.move(str(saved), str(target))


def _nexa_collect_original_outputs(run_dir: Path, generated_root: Optional[Path], console_log: Path) -> List[Dict[str, object]]:
    outputs: List[Dict[str, object]] = [
        {
            "label": "Consola original NEXA v0.5.1",
            "path": str(console_log),
            "url": _skyeye_output_url(console_log),
            "sha256": _nexa_hash_file(console_log),
        }
    ]
    if generated_root is None or not generated_root.exists():
        return outputs

    copied_root = run_dir / "suite_original_output_v0_5_1"
    if copied_root.exists():
        shutil.rmtree(copied_root)
    shutil.copytree(generated_root, copied_root)

    suffix_labels = {
        ".docx": "Informe Word NEXA v0.5.1",
        ".pdf": "Informe PDF NEXA v0.5.1",
        ".csv": "Tabla procesada NEXA",
        ".png": "Grafico NEXA",
        ".json": "Timeline NEXA",
        ".log": "Log NEXA",
    }
    for p in sorted(copied_root.rglob("*")):
        if not p.is_file():
            continue
        label = suffix_labels.get(p.suffix.lower(), "Salida NEXA original")
        outputs.append({
            "label": label,
            "path": str(p),
            "url": _skyeye_output_url(p),
            "sha256": _nexa_hash_file(p),
        })
    return outputs


def _nexa_execute_original_suite(run_dir: Path, manifest: Dict[str, object]) -> Tuple[List[Dict[str, object]], str]:
    snapshots = _nexa_snapshot_files(run_dir)
    if not snapshots:
        raise HTTPException(status_code=400, detail="NEXA no tiene archivos snapshot para analizar")

    has_history = False
    has_networkcfg = False
    for path in snapshots:
        if path.suffix.lower() != ".csv":
            continue
        role, _df = _nexa_detect_role(path)
        has_history = has_history or role == "history"
        has_networkcfg = has_networkcfg or role == "networkcfg"
    if not has_history or not has_networkcfg:
        raise HTTPException(status_code=400, detail="NEXA Suite original requiere un history.csv y un networkcfg.csv reconocibles")

    nexa_py = NEXA_SUITE_DIR / "nexa.py"
    if not nexa_py.exists():
        raise HTTPException(status_code=500, detail=f"No se encontro nexa.py: {nexa_py}")

    suite_input = NEXA_SUITE_DIR / "input"
    suite_output = NEXA_SUITE_DIR / "output"
    suite_input.mkdir(parents=True, exist_ok=True)
    suite_output.mkdir(parents=True, exist_ok=True)
    backup_dir = run_dir / "suite_input_backup"
    backup_dir.mkdir(parents=True, exist_ok=True)
    staged_paths: List[Path] = []
    for existing in sorted(suite_input.iterdir(), key=lambda x: x.name.lower()):
        if existing.is_file():
            shutil.move(str(existing), str(backup_dir / existing.name))

    before_outputs = {p.resolve(): p.stat().st_mtime for p in suite_output.iterdir() if p.is_dir()}
    try:
        for source in snapshots:
            if not source.is_file():
                continue
            safe_name = re.sub(r"[^A-Za-z0-9._-]+", "_", source.name).strip("._") or source.name
            dest = suite_input / safe_name
            i = 1
            while dest.exists():
                dest = suite_input / f"{Path(safe_name).stem}_{i}{Path(safe_name).suffix}"
                i += 1
            shutil.copy2(source, dest)
            staged_paths.append(dest)

        stdin_lines = [
            "1",
            str(manifest.get("case_number") or "____/26"),
            str(manifest.get("analyst") or manifest.get("created_by") or ""),
            str(manifest.get("position") or "Programmer | Digital Forensic Examiner"),
            str(manifest.get("organization") or "DEPARTAMENTO DE TECNOLOGIAS ESPECIALES Y DESPLIEGUE TACTICO"),
            str(manifest.get("institution") or ""),
            str(manifest.get("location") or ""),
            str(manifest.get("equipment") or "GUARDIAN"),
            str(manifest.get("mode") or "BLOCK"),
            str(manifest.get("antennas") or "DIRECCIONALES"),
            "",
            "",
        ]
        stdin_text = "\n".join(stdin_lines) + "\n"
        console_log = run_dir / "nexa_original_console.log"
        _nexa_log(run_dir, "suite_original_v0_5_1 iniciada via python nexa.py")
        creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
        try:
            result = subprocess.run(
                [sys.executable, str(nexa_py)],
                cwd=str(NEXA_SUITE_DIR),
                input=stdin_text,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
                creationflags=creation_flags,
                timeout=240,
            )
        except subprocess.TimeoutExpired as exc:
            console_log.write_text(f"TIMEOUT ejecutando NEXA Suite original\n{exc}", encoding="utf-8")
            raise HTTPException(status_code=504, detail="NEXA Suite original excedio el tiempo maximo")

        raw_console = (
            "COMMAND:\n"
            + subprocess.list2cmdline([sys.executable, str(nexa_py)])
            + "\n\nSTDOUT:\n"
            + (result.stdout or "")
            + "\n\nSTDERR:\n"
            + (result.stderr or "")
        )
        clean_console = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", raw_console)
        console_log.write_text(clean_console, encoding="utf-8")

        after_outputs = [
            p for p in suite_output.iterdir()
            if p.is_dir() and (
                p.resolve() not in before_outputs
                or p.stat().st_mtime > float(before_outputs.get(p.resolve(), 0)) + 0.01
            )
        ]
        generated_root = max(after_outputs, key=lambda p: p.stat().st_mtime) if after_outputs else None
        outputs = _nexa_collect_original_outputs(run_dir, generated_root, console_log)
        if result.returncode != 0:
            raise HTTPException(status_code=500, detail=f"NEXA Suite original finalizo con codigo {result.returncode}. Revisar consola original.")
        if not any(str(o.get("path", "")).lower().endswith(".docx") for o in outputs):
            raise HTTPException(status_code=500, detail="NEXA Suite original no genero DOCX. Revisar consola original.")
        _nexa_log(run_dir, f"suite_original_v0_5_1 finalizada outputs={len(outputs)}")
        return outputs, clean_console
    finally:
        _nexa_restore_suite_input(suite_input, backup_dir, staged_paths)


def _nexa_execute_run(run_dir: Path, manifest: Dict[str, object]) -> List[Dict[str, object]]:
    module = str(manifest.get("module") or "").strip().lower()
    if module == "rf_analyzer":
        return _nexa_execute_rf_analyzer(run_dir, manifest)
    if module == "mapeo_tactico":
        return _nexa_execute_mapeo_tactico(run_dir, manifest)
    raise HTTPException(status_code=400, detail="Modulo NEXA no ejecutable")


@app.get("/api/nexa/config")
def api_nexa_config(user=Depends(_require_auth)):
    _nexa_ensure_dirs()
    return {
        "base_dir": str(NEXA_DIR.resolve()),
        "input_dir": str(NEXA_INPUT_DIR.resolve()),
        "runs_dir": str(NEXA_RUNS_DIR.resolve()),
        "logs_dir": str(NEXA_LOG_DIR.resolve()),
        "mode": "suite_forense_controlada",
        "execution": "preparada_sin_ejecucion_libre",
    }


@app.get("/api/nexa/files")
def api_nexa_files(user=Depends(_require_auth)):
    _nexa_ensure_dirs()
    skyeye_inbox = [_nexa_file_info(p, "skyeye_inbox") for p in sorted(REPORTS_DIR.glob("*.csv"), key=lambda x: x.stat().st_mtime, reverse=True)]
    skyeye_processed: List[Dict[str, object]] = []
    for p in sorted(PROCESSED_DIR.rglob("*.csv"), key=lambda x: x.stat().st_mtime, reverse=True):
        skyeye_processed.append(_nexa_file_info(p, "skyeye_processed", folder=p.parent.name))
    guardian = [_nexa_file_info(p, "septier", "guardian") for p in sorted(GUARDIAN_DIR.glob("*.csv"), key=lambda x: x.stat().st_mtime, reverse=True)]
    backpack = [_nexa_file_info(p, "septier", "backpack") for p in sorted(BACKPACK_DIR.glob("*.csv"), key=lambda x: x.stat().st_mtime, reverse=True)]
    nexa_inputs = [_nexa_file_info(p, "nexa_input") for p in sorted(NEXA_INPUT_DIR.glob("*"), key=lambda x: x.stat().st_mtime, reverse=True) if p.is_file()]
    return {
        "skyeye_inbox": skyeye_inbox,
        "skyeye_processed": skyeye_processed,
        "guardian": guardian,
        "backpack": backpack,
        "nexa_inputs": nexa_inputs,
    }


@app.post("/api/nexa/upload")
async def api_nexa_upload(files: List[UploadFile] = File(...), user=Depends(_require_edit)):
    _nexa_ensure_dirs()
    saved = []
    for up in files:
        if not up.filename:
            continue
        raw = await up.read()
        _scan_uploaded_bytes(raw, up.filename or "archivo", "upload", user)
        if not raw:
            continue
        target = NEXA_INPUT_DIR / _nexa_safe_input_name(up.filename)
        i = 1
        while target.exists():
            target = target.with_name(f"{target.stem}_{i}{target.suffix}")
            i += 1
        target.write_bytes(raw)
        saved.append({
            "original": Path(up.filename).name,
            "saved_as": target.name,
            "size": target.stat().st_size,
            "sha256": hashlib.sha256(raw).hexdigest(),
        })
    return {"ok": True, "saved": saved}


@app.post("/api/nexa/runs/prepare")
def api_nexa_prepare_run(payload: NexaPrepareRunRequest, user=Depends(_require_edit)):
    _nexa_ensure_dirs()
    module = re.sub(r"[^a-z0-9_]+", "_", str(payload.module or "").strip().lower()).strip("_")
    allowed_modules = {
        "rf_analyzer": "RF Analyzer Septier",
        "mapeo_tactico": "Mapeo tactico Guardian / GETAC",
    }
    if module not in allowed_modules:
        raise HTTPException(status_code=400, detail="Modulo NEXA no permitido")
    if not payload.files:
        raise HTTPException(status_code=400, detail="Selecciona al menos un archivo para NEXA")

    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    run_id = f"nexa_{stamp}_{secrets.token_hex(3)}"
    run_dir = NEXA_RUNS_DIR / run_id
    evidence_dir = run_dir / "input_snapshot"
    evidence_dir.mkdir(parents=True, exist_ok=True)

    evidence_files = []
    for ref in payload.files:
        source_path = _nexa_source_path(ref).resolve()
        if not source_path.exists() or not source_path.is_file():
            raise HTTPException(status_code=404, detail=f"Archivo no encontrado para NEXA: {ref.file}")
        safe_copy = re.sub(r"[^A-Za-z0-9._-]+", "_", source_path.name).strip("._") or "evidencia.csv"
        dest = evidence_dir / safe_copy
        i = 1
        while dest.exists():
            dest = evidence_dir / f"{Path(safe_copy).stem}_{i}{Path(safe_copy).suffix}"
            i += 1
        shutil.copy2(source_path, dest)
        evidence_files.append({
            "source": ref.source,
            "system": ref.system,
            "folder": ref.folder,
            "original_name": source_path.name,
            "snapshot_name": dest.name,
            "size": dest.stat().st_size,
            "sha256": _nexa_hash_file(dest),
        })

    manifest = {
        "run_id": run_id,
        "status": "preparado",
        "module": module,
        "module_label": allowed_modules[module],
        "case_name": str(payload.case_name or "").strip(),
        "case_number": str(payload.case_number or "").strip(),
        "analyst": str(payload.analyst or "").strip(),
        "position": str(payload.position or "").strip(),
        "organization": str(payload.organization or "").strip(),
        "institution": str(payload.institution or "").strip(),
        "location": str(payload.location or "").strip(),
        "equipment": str(payload.equipment or "").strip(),
        "mode": str(payload.mode or "").strip(),
        "antennas": str(payload.antennas or "").strip(),
        "orientation": str(payload.orientation or "").strip(),
        "notes": str(payload.notes or "").strip(),
        "created_at": dt.datetime.now().isoformat(timespec="seconds"),
        "created_by": str(user.get("username") or ""),
        "files": evidence_files,
        "next_step": "Ejecucion controlada pendiente de conectar al motor NEXA. No se ejecuto terminal libre.",
    }
    manifest_path = run_dir / "manifest.json"
    log_path = run_dir / "nexa_run.log"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    log_path.write_text(
        "\n".join([
            f"[{manifest['created_at']}] NEXA run preparado",
            f"usuario={manifest['created_by']}",
            f"modulo={manifest['module_label']}",
            f"archivos={len(evidence_files)}",
            "estado=preparado_sin_ejecucion_libre",
        ]) + "\n",
        encoding="utf-8",
    )
    return {
        "ok": True,
        "item": {
            **manifest,
            "manifest_url": _skyeye_output_url(manifest_path),
            "log_url": _skyeye_output_url(log_path),
        },
    }


@app.post("/api/nexa/runs/original")
def api_nexa_original_run(payload: NexaPrepareRunRequest, user=Depends(_require_edit)):
    _nexa_ensure_dirs()
    if str(payload.module or "rf_analyzer").strip().lower() != "rf_analyzer":
        raise HTTPException(status_code=400, detail="La suite original NEXA v0.5.1 esta habilitada para RF Analyzer")
    if not payload.files:
        raise HTTPException(status_code=400, detail="Selecciona al menos un archivo para NEXA")

    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    run_id = f"nexa_original_{stamp}_{secrets.token_hex(3)}"
    run_dir = NEXA_RUNS_DIR / run_id
    evidence_dir = run_dir / "input_snapshot"
    evidence_dir.mkdir(parents=True, exist_ok=True)

    evidence_files = []
    for ref in payload.files:
        source_path = _nexa_source_path(ref).resolve()
        if not source_path.exists() or not source_path.is_file():
            raise HTTPException(status_code=404, detail=f"Archivo no encontrado para NEXA: {ref.file}")
        safe_copy = re.sub(r"[^A-Za-z0-9._-]+", "_", source_path.name).strip("._") or "evidencia.csv"
        dest = evidence_dir / safe_copy
        i = 1
        while dest.exists():
            dest = evidence_dir / f"{Path(safe_copy).stem}_{i}{Path(safe_copy).suffix}"
            i += 1
        shutil.copy2(source_path, dest)
        evidence_files.append({
            "source": ref.source,
            "system": ref.system,
            "folder": ref.folder,
            "original_name": source_path.name,
            "snapshot_name": dest.name,
            "size": dest.stat().st_size,
            "sha256": _nexa_hash_file(dest),
        })

    manifest = {
        "run_id": run_id,
        "status": "ejecutando",
        "module": "rf_analyzer",
        "module_label": "NEXA Suite original v0.5.1 - RF Analyzer",
        "case_name": str(payload.case_name or "").strip(),
        "case_number": str(payload.case_number or "").strip(),
        "analyst": str(payload.analyst or "").strip(),
        "position": str(payload.position or "").strip(),
        "organization": str(payload.organization or "").strip(),
        "institution": str(payload.institution or "").strip(),
        "location": str(payload.location or "").strip(),
        "equipment": str(payload.equipment or "").strip(),
        "mode": str(payload.mode or "").strip(),
        "antennas": str(payload.antennas or "").strip(),
        "orientation": str(payload.orientation or "").strip(),
        "notes": str(payload.notes or "").strip(),
        "created_at": dt.datetime.now().isoformat(timespec="seconds"),
        "created_by": str(user.get("username") or ""),
        "executed_by": str(user.get("username") or ""),
        "started_at": dt.datetime.now().isoformat(timespec="seconds"),
        "files": evidence_files,
        "execution_mode": "nexa_py_original_controlado",
    }
    _nexa_save_manifest(run_dir, manifest)
    _nexa_log(run_dir, f"suite_original_preparada usuario={manifest['created_by']} archivos={len(evidence_files)}")
    try:
        outputs, console_text = _nexa_execute_original_suite(run_dir, manifest)
        manifest["status"] = "ejecutado"
        manifest["finished_at"] = dt.datetime.now().isoformat(timespec="seconds")
        manifest["outputs"] = outputs
        manifest["next_step"] = "Revisar consola original, informe Word y salidas NEXA v0.5.1 con trazabilidad."
        _nexa_save_manifest(run_dir, manifest)
        return {
            "ok": True,
            "console_text": console_text,
            "item": {
                **manifest,
                "manifest_url": _skyeye_output_url(run_dir / "manifest.json"),
                "log_url": _skyeye_output_url(run_dir / "nexa_run.log"),
            },
        }
    except HTTPException as exc:
        manifest["status"] = "error"
        manifest["finished_at"] = dt.datetime.now().isoformat(timespec="seconds")
        manifest["error"] = str(exc.detail)
        _nexa_save_manifest(run_dir, manifest)
        _nexa_log(run_dir, f"suite_original_error {exc.detail}")
        raise
    except Exception as exc:
        manifest["status"] = "error"
        manifest["finished_at"] = dt.datetime.now().isoformat(timespec="seconds")
        manifest["error"] = str(exc)
        _nexa_save_manifest(run_dir, manifest)
        _nexa_log(run_dir, f"suite_original_error {exc}")
        raise HTTPException(status_code=500, detail=f"NEXA Suite original fallo: {exc}")


@app.get("/api/nexa/runs")
def api_nexa_runs(limit: int = 50, user=Depends(_require_auth)):
    return {"items": _nexa_list_runs(limit=limit)}


@app.get("/api/nexa/manuals")
def api_nexa_manuals(user=Depends(_require_auth)):
    items = []
    for item in _nexa_load_manuals_index():
        pdf_path = Path(str(item.get("pdf_path") or ""))
        text_path = Path(str(item.get("text_path") or ""))
        items.append({
            **item,
            "exists": bool(pdf_path.exists()),
            "text_exists": bool(text_path.exists()),
            "download_url": _nexa_manual_url(str(item.get("id") or "")),
        })
    return {"items": items}


@app.post("/api/nexa/manuals/upload")
async def api_nexa_manual_upload(file: UploadFile = File(...), admin=Depends(_require_admin)):
    _nexa_ensure_dirs()
    if not file.filename or not file.filename.lower().endswith(".pdf"):
        raise HTTPException(status_code=400, detail="Sube un manual PDF")
    raw = await file.read()
    _scan_uploaded_bytes(raw, file.filename or "archivo", "nexa_manual", admin)
    if not raw:
        raise HTTPException(status_code=400, detail="PDF vacio")
    manual_id = f"manual_{dt.datetime.now().strftime('%Y%m%d_%H%M%S')}_{secrets.token_hex(3)}"
    safe_stem = re.sub(r"[^A-Za-z0-9._-]+", "_", Path(file.filename).stem).strip("._") or "manual"
    pdf_path = NEXA_MANUALS_DIR / f"{manual_id}_{safe_stem}.pdf"
    text_path = NEXA_MANUALS_DIR / f"{manual_id}_{safe_stem}.txt"
    pdf_path.write_bytes(raw)
    sha256 = hashlib.sha256(raw).hexdigest()
    extracted_text, pages = _nexa_extract_pdf_text(pdf_path)
    text_path.write_text(extracted_text, encoding="utf-8")
    item = {
        "id": manual_id,
        "title": Path(file.filename).stem,
        "original_filename": Path(file.filename).name,
        "pdf_path": str(pdf_path),
        "text_path": str(text_path),
        "sha256": sha256,
        "pages": len(pages),
        "uploaded_by": str(admin.get("username") or ""),
        "uploaded_at": dt.datetime.now().isoformat(timespec="seconds"),
        "source": "manual_operativo_autorizado",
    }
    items = [x for x in _nexa_load_manuals_index() if str(x.get("sha256") or "") != sha256]
    items.insert(0, item)
    _nexa_save_manuals_index(items)
    return {"ok": True, "item": {**item, "download_url": _nexa_manual_url(manual_id)}}


@app.get("/api/nexa/manuals/{manual_id}/download")
def api_nexa_manual_download(manual_id: str, user=Depends(_require_auth)):
    item = _nexa_manual_item(manual_id)
    path = Path(str(item.get("pdf_path") or ""))
    if not path.exists() or not path.is_file():
        raise HTTPException(status_code=404, detail="PDF no encontrado")
    return FileResponse(path, filename=str(item.get("original_filename") or path.name), media_type="application/pdf")


@app.post("/api/nexa/manuals/search")
def api_nexa_manual_search(payload: NexaManualSearchRequest, user=Depends(_require_auth)):
    return {
        "items": _nexa_search_manuals(payload.q, limit=payload.limit),
        "rule": "SIGMA/NEXA responde solo con manuales cargados y auditados. Si no hay coincidencias, debe declarar faltante.",
    }


@app.post("/api/nexa/runs/{run_id}/execute")
def api_nexa_execute_run(run_id: str, user=Depends(_require_edit)):
    run_dir = _nexa_run_dir(run_id)
    manifest = _nexa_load_manifest(run_dir)
    if str(manifest.get("status") or "") == "ejecutando":
        raise HTTPException(status_code=409, detail="La corrida NEXA ya esta ejecutandose")
    manifest["status"] = "ejecutando"
    manifest["executed_by"] = str(user.get("username") or "")
    manifest["started_at"] = dt.datetime.now().isoformat(timespec="seconds")
    _nexa_save_manifest(run_dir, manifest)
    _nexa_log(run_dir, f"ejecucion_iniciada usuario={manifest['executed_by']} modulo={manifest.get('module')}")
    try:
        outputs = _nexa_execute_run(run_dir, manifest)
        manifest["status"] = "ejecutado"
        manifest["finished_at"] = dt.datetime.now().isoformat(timespec="seconds")
        manifest["outputs"] = outputs
        manifest["next_step"] = "Revisar salidas NEXA, manifest y log TXT. SIGMA puede observar estos resultados con trazabilidad."
        _nexa_save_manifest(run_dir, manifest)
        _nexa_log(run_dir, f"ejecucion_finalizada outputs={len(outputs)}")
        return {"ok": True, "item": {**manifest, "manifest_url": _skyeye_output_url(run_dir / "manifest.json"), "log_url": _skyeye_output_url(run_dir / "nexa_run.log")}}
    except HTTPException as exc:
        manifest["status"] = "error"
        manifest["finished_at"] = dt.datetime.now().isoformat(timespec="seconds")
        manifest["error"] = str(exc.detail)
        _nexa_save_manifest(run_dir, manifest)
        _nexa_log(run_dir, f"ejecucion_error {exc.detail}")
        raise
    except Exception as exc:
        manifest["status"] = "error"
        manifest["finished_at"] = dt.datetime.now().isoformat(timespec="seconds")
        manifest["error"] = str(exc)
        _nexa_save_manifest(run_dir, manifest)
        _nexa_log(run_dir, f"ejecucion_error {exc}")
        raise HTTPException(status_code=500, detail=f"NEXA fallo al ejecutar: {exc}")


def _parse_septier_history_schema_bytes(raw: bytes) -> List[Dict[str, object]]:
    import json

    text = raw.decode("utf-8-sig", errors="replace").strip()
    try:
        parsed = json.loads(text)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"No se pudo leer el esquema history: {exc}")
    if not isinstance(parsed, list):
        raise HTTPException(status_code=400, detail="El esquema history debe ser una lista JSON")

    items: List[Dict[str, object]] = []
    for idx, item in enumerate(parsed, start=1):
        if not isinstance(item, dict):
            continue
        field = str(item.get("field") or "").strip()
        title = str(item.get("title") or field).strip()
        if not field:
            continue
        items.append({"field": field, "title": title, "position": idx})
    if not items:
        raise HTTPException(status_code=400, detail="No se encontraron columnas validas en el esquema history")
    return items


def _csv_text(raw: bytes) -> str:
    for encoding in ("utf-8-sig", "latin-1"):
        try:
            return raw.decode(encoding)
        except Exception:
            continue
    return raw.decode("utf-8-sig", errors="replace")


def _clean_code_text(value: object, width: int = 0) -> str:
    text = str(value or "").strip().strip('"')
    if text.endswith(".0"):
        text = text[:-2]
    text = re.sub(r"\s+", "", text)
    if width and text.isdigit():
        return text.zfill(width)
    return text


def _parse_septier_network_reference_bytes(raw: bytes, filename: str) -> Tuple[str, List[Dict[str, object]]]:
    text = _csv_text(raw)
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    lower_name = filename.lower()
    items: List[Dict[str, object]] = []

    if lower_name.endswith(".csv") and ("gsm" in lower_name or (lines and "\t" in lines[0])):
        source_type = "gsm_networks"
        reader = csv.reader(text.splitlines(), delimiter="\t", quotechar='"')
        for idx, parts in enumerate(reader):
            if len(parts) == 1 and "\t" in parts[0]:
                parts = parts[0].split("\t")
            parts = [part.strip().strip('"') for part in parts]
            if idx == 0 and parts and _norm_col(parts[0]) == "mcc":
                continue
            if len(parts) < 2:
                continue
            mcc, mnc = parts[0], parts[1]
            name = parts[2] if len(parts) >= 3 else ""
            items.append({"mcc": _clean_code_text(mcc, 3), "mnc": _clean_code_text(mnc), "network_name": str(name).strip()})
        return source_type, items

    reader = csv.DictReader(text.splitlines())
    field_map = {_norm_col(f): f for f in (reader.fieldnames or [])}

    def pick(row: Dict[str, object], *names: str) -> str:
        for name in names:
            field = field_map.get(_norm_col(name))
            if field:
                return str(row.get(field) or "").strip()
        return ""

    source_type = "network_info"
    for row in reader:
        items.append(
            {
                "mcc": _clean_code_text(pick(row, "mcc"), 3),
                "mnc": _clean_code_text(pick(row, "mnc")),
                "network_name": pick(row, "name", "network_name", "network name"),
                "when_created": pick(row, "when_created"),
                "external_id": pick(row, "id"),
                "session_id": pick(row, "session_id"),
            }
        )
    return source_type, items


def _parse_rf_bands_python_bytes(raw: bytes, filename: str) -> List[Dict[str, object]]:
    text = _csv_text(raw)
    command_vars: Dict[str, str] = {}
    for match in re.finditer(r"^(RX_[MS]_\d+)\s*=\s*['\"]([^'\"]+)['\"]", text, flags=re.MULTILINE):
        command_vars[match.group(1)] = match.group(2).strip()

    labels: Dict[Tuple[str, str], str] = {}
    for match in re.finditer(r"push_band(\d+)([ms])\.setText\([^,]+,\s*['\"]([^'\"]+)['\"]\)", text):
        band = match.group(1)
        rx_type = "RX_M" if match.group(2).lower() == "m" else "RX_S"
        labels[(rx_type, band)] = match.group(3).strip()

    items: List[Dict[str, object]] = []
    for var_name, command in command_vars.items():
        rx_type, band = var_name.rsplit("_", 1)
        label = labels.get((rx_type, band), "")
        freq_match = re.search(r"-(\d+(?:[.,]\d+)?)", label)
        items.append(
            {
                "rx_type": rx_type,
                "band": band,
                "label": label or f"{rx_type} BAND{band}",
                "frequency": freq_match.group(1).replace(",", ".") if freq_match else "",
                "command": command,
                "source_filename": filename,
            }
        )
    if not items:
        raise HTTPException(status_code=400, detail="No se encontraron bandas RX_M/RX_S en el archivo Python")
    return items


def _parse_external_identity_data_bytes(raw: bytes) -> List[Dict[str, str]]:
    text = _csv_text(raw)
    lines = text.splitlines()
    first_line = lines[0] if lines else ""
    delimiter = ";" if ";" in first_line and "," not in first_line else ","
    reader = csv.DictReader(lines, delimiter=delimiter)
    aliases = {
        "imsi": {"imsi", "imsi_mac", "imsi/mac"},
        "imei": {"imei", "imei_15"},
        "prestataria": {"prestataria", "prestadora", "operador", "carrier", "provider"},
        "estado": {"estado", "state", "status"},
        "modelo": {"modelo", "model", "marca"},
    }
    rows: List[Dict[str, str]] = []
    for raw_row in reader:
        normalized = {str(k or "").strip().lower(): "" if v is None else str(v).strip() for k, v in raw_row.items()}
        row: Dict[str, str] = {}
        for canonical, keys in aliases.items():
            row[canonical] = ""
            for key in keys:
                if key in normalized:
                    row[canonical] = normalized[key]
                    break
        imsi = _id15(row.get("imsi"))
        imei = _id15(row.get("imei"))
        if len(imsi) != 15 and len(imei) != 15:
            continue
        rows.append({
            "imsi": imsi,
            "imei": imei,
            "prestataria": (row.get("prestataria") or "DESCONOCIDA").strip().upper(),
            "estado": (row.get("estado") or "SIN ESTADO").strip().upper(),
            "modelo": (row.get("modelo") or "").strip(),
        })
    return rows


def _septier_uploaded_file_path(item: FileItem) -> Path:
    base = _septier_target_dir(item.system)
    filename = Path(str(item.file or "")).name
    if not filename.lower().endswith(".csv"):
        raise HTTPException(status_code=400, detail=f"Archivo Septier invalido: {item.file}")
    path = (base / filename).resolve()
    try:
        path.relative_to(base.resolve())
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Ruta Septier invalida: {item.file}")
    if not path.exists() or not path.is_file():
        raise HTTPException(status_code=404, detail=f"No se encontro {item.system}/{filename}")
    return path


def _read_septier_csv_dataframe(path: Path):
    import pandas as pd

    last_exc: Optional[Exception] = None
    for encoding in ("utf-8-sig", "latin-1"):
        try:
            df = pd.read_csv(path, sep=None, engine="python", encoding=encoding, dtype=str)
            return clean_columns(df).fillna("")
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
    raise HTTPException(status_code=400, detail=f"No se pudo leer {path.name}: {last_exc}")


def _history_schema_column_candidates(item: Dict[str, object]) -> List[str]:
    field = str(item.get("field") or "").strip()
    title = str(item.get("title") or "").strip()
    variants = [
        field,
        title,
        field.replace("_", " "),
        field.replace("_", "/"),
        field.replace("_", "-"),
    ]
    out: List[str] = []
    seen = set()
    for value in variants:
        key = _norm_col(value)
        if value and key not in seen:
            seen.add(key)
            out.append(value)
    return out


@app.get("/api/septier/reference/history-schema")
def api_get_septier_history_schema(user=Depends(_require_auth)):
    items = list_septier_history_schema()
    return {
        "items": items,
        "total": len(items),
        "selected_count": sum(1 for item in items if item.get("selected")),
    }


@app.post("/api/septier/reference/history-schema/upload")
async def api_upload_septier_history_schema(file: UploadFile = File(...), user=Depends(_require_admin)):
    if not file.filename:
        raise HTTPException(status_code=400, detail="Sube el archivo history_export.txt")
    raw = await file.read()
    _scan_uploaded_bytes(raw, file.filename or "archivo", "upload", user)
    items = _parse_septier_history_schema_bytes(raw)
    inserted = replace_septier_history_schema(items, source_filename=file.filename)
    return {
        "ok": True,
        "inserted": inserted,
        "items": list_septier_history_schema(),
    }


@app.post("/api/septier/reference/history-schema/selection")
def api_save_septier_history_schema_selection(payload: SeptierHistorySchemaSelectionRequest, user=Depends(_require_admin)):
    saved = update_septier_history_schema_selection(payload.fields)
    items = list_septier_history_schema()
    return {
        "ok": True,
        "saved": saved,
        "selected_count": sum(1 for item in items if item.get("selected")),
        "items": items,
    }


@app.get("/api/septier/reference/networks")
def api_get_septier_network_refs(
    q: str = "",
    mcc: str = "",
    mnc: str = "",
    source_type: str = "",
    limit: int = 500,
    user=Depends(_require_auth),
):
    items = list_septier_network_refs(q=q, mcc=mcc, mnc=mnc, source_type=source_type, limit=limit)
    sources: Dict[str, int] = {}
    for item in list_septier_network_refs(limit=5000):
        key = str(item.get("source_type") or "sin_fuente")
        sources[key] = sources.get(key, 0) + 1
    return {"items": items, "total": len(items), "sources": sources}


@app.post("/api/septier/reference/networks/upload")
async def api_upload_septier_network_refs(file: UploadFile = File(...), user=Depends(_require_admin)):
    if not file.filename or not file.filename.lower().endswith(".csv"):
        raise HTTPException(status_code=400, detail="Sube gsm-networks-list.csv o network_info.csv")
    raw = await file.read()
    _scan_uploaded_bytes(raw, file.filename or "archivo", "upload", user)
    source_type, items = _parse_septier_network_reference_bytes(raw, file.filename)
    inserted = replace_septier_network_refs(items, source_type=source_type, source_filename=file.filename)
    return {
        "ok": True,
        "source_type": source_type,
        "inserted": inserted,
        "sources": api_get_septier_network_refs(user=user).get("sources", {}),
    }


@app.get("/api/septier/reference/rf-bands")
def api_get_septier_rf_bands(limit: int = 500, user=Depends(_require_auth)):
    items = list_septier_rf_bands(limit=limit)
    return {"items": items, "total": len(items)}


@app.post("/api/septier/reference/rf-bands/upload")
async def api_upload_septier_rf_bands(file: UploadFile = File(...), user=Depends(_require_admin)):
    if not file.filename or not file.filename.lower().endswith(".py"):
        raise HTTPException(status_code=400, detail="Sube el archivo Python de bandas RF")
    raw = await file.read()
    _scan_uploaded_bytes(raw, file.filename or "archivo", "upload", user)
    items = _parse_rf_bands_python_bytes(raw, file.filename)
    inserted = replace_septier_rf_bands(items, source_filename=file.filename)
    return {"ok": True, "inserted": inserted, "items": list_septier_rf_bands()}


def _parse_external_upload_ids(raw: object) -> List[int]:
    if isinstance(raw, list):
        values = raw
    else:
        values = re.split(r"[,;\s]+", str(raw or ""))
    ids: List[int] = []
    for value in values:
        text = str(value or "").strip()
        if not text.isdigit():
            continue
        upload_id = int(text)
        if upload_id > 0 and upload_id not in ids:
            ids.append(upload_id)
    return ids


@app.get("/api/septier/reference/external-data")
def api_get_septier_external_data(q: str = "", limit: int = 50, upload_ids: str = "", user=Depends(_require_auth)):
    uploads = list_external_identity_uploads(limit=50)
    selected_upload_ids = _parse_external_upload_ids(upload_ids)
    items = list_external_identity_data(q=q, limit=limit, upload_ids=selected_upload_ids)
    return {"uploads": uploads, "items": items, "selected_upload_ids": selected_upload_ids}


@app.post("/api/septier/reference/external-data/upload")
async def api_upload_septier_external_data(file: UploadFile = File(...), user=Depends(_require_admin)):
    raw = await file.read()
    _scan_uploaded_bytes(raw, file.filename or "archivo", "upload", user)
    if not raw:
        raise HTTPException(status_code=400, detail="Archivo Data Externa vacio")
    original_name = Path(file.filename or "data_externa.csv").name
    if not original_name.lower().endswith(".csv"):
        raise HTTPException(status_code=400, detail="Sube un CSV data-xxxx.csv")
    rows = _parse_external_identity_data_bytes(raw)
    if not rows:
        raise HTTPException(status_code=400, detail="No se detectaron columnas IMSI/IMEI validas en Data Externa")
    EXTERNAL_IDENTITY_DIR.mkdir(parents=True, exist_ok=True)
    stem = re.sub(r"[^A-Za-z0-9._-]+", "_", Path(original_name).stem).strip("._") or "data_externa"
    stored_name = f"data_{dt.datetime.now().strftime('%Y%m%d_%H%M%S')}_{secrets.token_hex(4)}_{stem}.csv"
    stored_path = EXTERNAL_IDENTITY_DIR / stored_name
    stored_path.write_bytes(raw)
    sha256 = hashlib.sha256(raw).hexdigest()
    upload_id = insert_external_identity_upload(
        original_filename=original_name,
        stored_filename=stored_name,
        stored_path=str(stored_path),
        uploaded_by=str(user.get("full_name") or user.get("username") or ""),
        hash_sha256=sha256,
        rows=rows,
    )
    return {
        "ok": True,
        "upload_id": upload_id,
        "inserted": len(rows),
        "unique_imsi": len({r["imsi"] for r in rows if r.get("imsi")}),
        "unique_imei": len({r["imei"] for r in rows if r.get("imei")}),
        "sha256": sha256,
    }


@app.delete("/api/septier/reference/external-data/uploads/{upload_id}")
def api_delete_septier_external_data_upload(upload_id: int, user=Depends(_require_admin)):
    result = delete_external_identity_upload(upload_id)
    if not result.get("deleted"):
        raise HTTPException(status_code=404, detail="Carga Data Externa no encontrada")
    stored_path = str(result.get("stored_path") or "")
    if stored_path:
        try:
            path = Path(stored_path)
            if path.exists() and EXTERNAL_IDENTITY_DIR.resolve() in path.resolve().parents:
                path.unlink()
        except Exception:
            pass
    return {"ok": True, "upload_id": upload_id, "rows_deleted": result.get("rows", 0)}


def _external_data_whitelist_matches(limit: int = 200000, upload_ids: Optional[List[int]] = None) -> List[Dict[str, object]]:
    whitelist = _whitelist_identity_set()
    matches: List[Dict[str, object]] = []
    for row in list_external_identity_data(limit=limit, upload_ids=upload_ids):
        imsi = str(row.get("imsi") or "").strip()
        imei = str(row.get("imei") or "").strip()
        imsi_hit = bool(_identity_keys(imsi) & whitelist)
        imei_hit = bool(_identity_keys(imei) & whitelist)
        if not imsi_hit and not imei_hit:
            continue
        match_kind = "IMSI + IMEI" if imsi_hit and imei_hit else ("IMSI" if imsi_hit else "IMEI")
        matches.append({
            **row,
            "match_kind": match_kind,
            "motivo": "Coincide con Lista Blanca actual",
        })
    return matches


@app.get("/api/septier/reference/external-data/whitelist-cross")
def api_external_data_whitelist_cross(upload_ids: str = "", user=Depends(_require_auth)):
    selected_upload_ids = _parse_external_upload_ids(upload_ids)
    matches = _external_data_whitelist_matches(upload_ids=selected_upload_ids)
    by_kind = Counter(str(item.get("match_kind") or "identidad") for item in matches)
    by_provider = Counter(str(item.get("prestataria") or "DESCONOCIDA") for item in matches)
    return {
        "items": matches[:500],
        "total": len(matches),
        "by_kind": dict(by_kind),
        "by_provider": dict(by_provider),
        "selected_upload_ids": selected_upload_ids,
        "rule": "Estas coincidencias se excluyen del informe final y quedan auditadas como Lista Blanca actual.",
    }


@app.post("/api/septier/reference/external-data/whitelist-report")
def api_external_data_whitelist_report(payload: Optional[SeptierExternalUploadSelection] = Body(default=None), user=Depends(_require_auth)):
    selected_upload_ids = _parse_external_upload_ids(payload.upload_ids if payload else [])
    matches = _external_data_whitelist_matches(upload_ids=selected_upload_ids)
    stamp = dt.datetime.now(dt.timezone(dt.timedelta(hours=-3))).strftime("%Y%m%d_%H%M%S")
    base_name = f"data_externa_vs_lista_blanca_{stamp}"
    OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)
    csv_path = OUTPUTS_DIR / f"{base_name}.csv"
    html_path = OUTPUTS_DIR / f"{base_name}.html"
    word_path = OUTPUTS_DIR / f"{base_name}.docx"
    fields = ["match_kind", "imsi", "imei", "prestataria", "estado", "modelo", "source_filename", "motivo", "hash_sha256"]
    with csv_path.open("w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields, delimiter=";")
        writer.writeheader()
        writer.writerows([{field: item.get(field, "") for field in fields} for item in matches])

    by_kind = Counter(str(item.get("match_kind") or "identidad") for item in matches)
    by_provider = Counter(str(item.get("prestataria") or "DESCONOCIDA") for item in matches)
    rows_html = "\n".join(
        "<tr>"
        f"<td>{html_lib.escape(str(item.get('match_kind') or '-'))}</td>"
        f"<td>{html_lib.escape(str(item.get('imsi') or '-'))}</td>"
        f"<td>{html_lib.escape(str(item.get('imei') or '-'))}</td>"
        f"<td>{html_lib.escape(str(item.get('prestataria') or 'DESCONOCIDA'))}</td>"
        f"<td>{html_lib.escape(str(item.get('estado') or '-'))}</td>"
        f"<td>{html_lib.escape(str(item.get('modelo') or '-'))}</td>"
        "</tr>"
        for item in matches
    )
    html_doc = f"""<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <title>Data Externa vs Lista Blanca</title>
  <style>
    body {{ font-family: Arial, sans-serif; color: #061327; margin: 28px; }}
    h1 {{ color: #003b68; }}
    .box {{ border: 1px solid #c8d4e3; border-radius: 8px; padding: 12px; margin: 12px 0; }}
    table {{ border-collapse: collapse; width: 100%; font-size: 12px; }}
    th, td {{ border: 1px solid #d4deeb; padding: 7px; text-align: left; }}
    th {{ background: #eaf2fb; }}
  </style>
</head>
<body>
  <h1>Informe de Contraste Externo Septier</h1>
  <div class="box">
    <strong>Fuente:</strong> Data Externa Postgres vs Lista Blanca actual<br>
    <strong>Cargas utilizadas:</strong> {html_lib.escape(', '.join(map(str, selected_upload_ids)) or 'Todas')}<br>
    <strong>Generado:</strong> {dt.datetime.now(dt.timezone(dt.timedelta(hours=-3))).strftime('%Y-%m-%d %H:%M:%S')}<br>
    <strong>Usuario:</strong> {html_lib.escape(str(user.get('full_name') or user.get('username') or '-'))}<br>
    <strong>Total coincidencias excluidas del informe final:</strong> {len(matches)}
  </div>
  <div class="box">
    <strong>Coincidencias por tipo:</strong> {html_lib.escape(json.dumps(dict(by_kind), ensure_ascii=False))}<br>
    <strong>Coincidencias por prestataria:</strong> {html_lib.escape(json.dumps(dict(by_provider), ensure_ascii=False))}
  </div>
  <table>
    <thead><tr><th>Cruce</th><th>IMSI</th><th>IMEI</th><th>Prestataria</th><th>Estado</th><th>Modelo</th></tr></thead>
    <tbody>{rows_html or '<tr><td colspan="6">Sin coincidencias con Lista Blanca actual.</td></tr>'}</tbody>
  </table>
</body>
</html>"""
    html_path.write_text(html_doc, encoding="utf-8")

    try:
        from docx import Document
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Falta dependencia python-docx para generar Word: {exc}")
    doc = Document()
    doc.add_heading("Informe de Contraste Externo Septier", level=1)
    doc.add_paragraph("Fuente: Data Externa Postgres vs Lista Blanca actual")
    doc.add_paragraph(f"Cargas utilizadas: {', '.join(map(str, selected_upload_ids)) or 'Todas'}")
    doc.add_paragraph(f"Generado: {dt.datetime.now(dt.timezone(dt.timedelta(hours=-3))).strftime('%Y-%m-%d %H:%M:%S')}")
    doc.add_paragraph(f"Usuario: {user.get('full_name') or user.get('username') or '-'}")
    doc.add_paragraph(f"Total coincidencias excluidas del informe final: {len(matches)}")
    doc.add_paragraph(f"Coincidencias por tipo: {json.dumps(dict(by_kind), ensure_ascii=False)}")
    doc.add_paragraph(f"Coincidencias por prestataria: {json.dumps(dict(by_provider), ensure_ascii=False)}")
    table = doc.add_table(rows=1, cols=6)
    hdr = table.rows[0].cells
    for idx, label in enumerate(["Cruce", "IMSI", "IMEI", "Prestataria", "Estado", "Modelo"]):
        hdr[idx].text = label
    for item in matches:
        cells = table.add_row().cells
        values = [item.get("match_kind"), item.get("imsi"), item.get("imei"), item.get("prestataria"), item.get("estado"), item.get("modelo")]
        for idx, value in enumerate(values):
            cells[idx].text = str(value or "-")
    doc.save(word_path)
    return {
        "ok": True,
        "total": len(matches),
        "by_kind": dict(by_kind),
        "by_provider": dict(by_provider),
        "selected_upload_ids": selected_upload_ids,
        "csv_url": f"/outputs/{csv_path.name}",
        "html_url": f"/outputs/{html_path.name}",
        "word_url": f"/outputs/{word_path.name}",
    }


def _external_provider_bucket(value: object) -> str:
    text = str(value or "").strip().upper()
    if text in {"CLARO", "MOVISTAR", "PERSONAL"}:
        return text
    if not text or text in {"DESCONOCIDA", "DESCONOCIDO", "SIN_DATO", "S/D"}:
        return "DESCONOCIDA"
    return "OTROS"


def _external_match_kind(base_imsi: object, base_imei: object, ext_imsi: object, ext_imei: object) -> str:
    base_imsi_key = _id15(base_imsi)
    base_imei_key = _id15(base_imei)
    ext_imsi_key = _id15(ext_imsi)
    ext_imei_key = _id15(ext_imei)
    parts = []
    if base_imsi_key and ext_imsi_key and base_imsi_key == ext_imsi_key:
        parts.append("IMSI")
    if base_imei_key and ext_imei_key and base_imei_key == ext_imei_key:
        parts.append("IMEI")
    return " + ".join(parts) or "IDENTIDAD"


def _external_clean_rows(files: List[FileItem], upload_ids: Optional[List[int]] = None) -> Tuple[List[Dict[str, object]], Dict[str, object]]:
    whitelist = _whitelist_identity_set()
    rows: List[Dict[str, object]] = []
    seen = set()
    files_dict = [{"system": f.system, "file": f.file} for f in files if f.system and f.file]
    selected_upload_ids = _parse_external_upload_ids(upload_ids or [])
    source_mode = "data_externa"

    if files_dict:
        source_mode = "data_externa_con_history"
        identity_memory = _septier_identity_memory()
        history_rows = [
            _with_resolved_septier_identity(history, identity_memory)
            for history in get_septier_detections_by_files(files_dict)
        ]
        for history in history_rows:
            hist_imsi = str(history.get("imsi_mac") or "").strip()
            hist_imei = str(history.get("imei") or "").strip()
            if _is_whitelisted_identity(hist_imsi, hist_imei, whitelist):
                continue
            for ext in external_identity_lookup(hist_imsi, hist_imei, upload_ids=selected_upload_ids):
                ext_imsi = str(ext.get("imsi") or "").strip()
                ext_imei = str(ext.get("imei") or "").strip()
                if _is_whitelisted_identity(ext_imsi, ext_imei, whitelist):
                    continue
                key = "|".join([
                    ext_imsi,
                    ext_imei,
                    str(history.get("source") or ""),
                    str(history.get("archivo_origen") or ""),
                ])
                if key in seen:
                    continue
                seen.add(key)
                rows.append({
                    "prestataria": _external_provider_bucket(ext.get("prestataria")),
                    "imsi": ext_imsi or hist_imsi,
                    "imei": ext_imei or hist_imei,
                    "estado": ext.get("estado") or "-",
                    "modelo": ext.get("modelo") or "-",
                    "match_kind": _external_match_kind(hist_imsi, hist_imei, ext_imsi, ext_imei),
                    "history_system": str(history.get("source") or "").upper(),
                    "history_file": str(history.get("archivo_origen") or ""),
                    "history_model": str(history.get("model") or ""),
                    "history_seen_at": _format_forensic_dt(history.get("last_update")),
                    "source_filename": ext.get("source_filename") or "",
                    "hash_sha256": ext.get("hash_sha256") or "",
                    "motivo": "Data Externa depurada sin coincidencia con Lista Blanca actual",
                })
    else:
        for ext in list_external_identity_data(limit=200000, upload_ids=selected_upload_ids):
            ext_imsi = str(ext.get("imsi") or "").strip()
            ext_imei = str(ext.get("imei") or "").strip()
            if _is_whitelisted_identity(ext_imsi, ext_imei, whitelist):
                continue
            key = f"{ext_imsi}|{ext_imei}|{ext.get('source_filename') or ''}"
            if key in seen:
                continue
            seen.add(key)
            rows.append({
                "prestataria": _external_provider_bucket(ext.get("prestataria")),
                "imsi": ext_imsi,
                "imei": ext_imei,
                "estado": ext.get("estado") or "-",
                "modelo": ext.get("modelo") or "-",
                "match_kind": "DATA EXTERNA",
                "history_system": "",
                "history_file": "",
                "history_model": "",
                "history_seen_at": "",
                "source_filename": ext.get("source_filename") or "",
                "hash_sha256": ext.get("hash_sha256") or "",
                "motivo": "Data Externa depurada sin coincidencia con Lista Blanca actual",
            })

    order = {"CLARO": 0, "MOVISTAR": 1, "PERSONAL": 2, "DESCONOCIDA": 3, "OTROS": 4}
    rows.sort(key=lambda r: (order.get(str(r.get("prestataria")), 9), str(r.get("imsi") or ""), str(r.get("imei") or "")))
    summary = {
        "source_mode": source_mode,
        "total": len(rows),
        "by_provider": dict(Counter(str(r.get("prestataria") or "DESCONOCIDA") for r in rows)),
        "with_history": bool(files_dict),
        "files": files_dict,
        "upload_ids": selected_upload_ids,
    }
    return rows, summary


def _whitelist_source_summary() -> Dict[str, object]:
    uploads = list_whitelist_uploads(limit=1000)
    active_uploads = [u for u in uploads if not u.get("deleted_at")]
    devices = list_whitelist()
    by_type = Counter(str(item.get("type") or "sin_tipo").lower() for item in devices)
    return {
        "devices_active": len(devices),
        "uploads_active": len(active_uploads),
        "uploads_total": len(uploads),
        "uploads": [
            {
                "id": u.get("id"),
                "filename": u.get("original_filename") or u.get("stored_filename") or "-",
                "inserted_count": u.get("inserted_count") or u.get("rows_count") or 0,
            }
            for u in active_uploads
        ],
        "by_type": dict(by_type),
        "external_query_sources": [
            "planta_peni.device_id",
            "planta_peni2.device_id",
            "planta_penitenciaria.imei_oficial",
            "personal_tecnicas.imsi",
            "personal_tecnicas.imei_1",
            "personal_tecnicas.imei_2",
            "planta_cadetes.imei",
            "planta_cadetes.imei_2",
        ],
    }


def _history_provider_audit_rows(files: List[FileItem]) -> Tuple[List[Dict[str, object]], Dict[str, object]]:
    files_dict = [{"system": f.system, "file": f.file} for f in files if f.system and f.file]
    if not files_dict:
        raise HTTPException(status_code=400, detail="Selecciona al menos un history Guardian o Backpack para auditar.")

    selected_rows = get_septier_forensic_rows_by_files(files_dict)
    if not selected_rows:
        raise HTTPException(status_code=404, detail="No hay detecciones cargadas para los histories seleccionados.")

    whitelist = _whitelist_identity_set()
    whitelist_base = _whitelist_base_identity_set()
    history_rows = get_septier_identity_history()
    first_seen_by_key: Dict[str, dt.datetime] = {}
    imei_counts_by_imsi: Dict[str, Counter[str]] = {}
    imsi_counts_by_imei: Dict[str, Counter[str]] = {}
    provider_counts_by_imsi: Dict[str, Counter[str]] = {}

    for row in history_rows:
        imsi_key = _id15(row.get("imsi_mac"))
        imei_key = _id15(row.get("imei"))
        seen_at = _parse_dt_value(row.get("last_update"))
        for key in [k for k in (imsi_key, imei_key) if len(k) >= 14]:
            if seen_at and (key not in first_seen_by_key or seen_at < first_seen_by_key[key]):
                first_seen_by_key[key] = seen_at
        if len(imsi_key) == 15:
            provider = _external_provider_bucket(_carrier_from_imsi_value(imsi_key))
            provider_counts_by_imsi.setdefault(imsi_key, Counter())[provider] += 1
            if len(imei_key) == 15:
                imei_counts_by_imsi.setdefault(imsi_key, Counter())[imei_key] += 1
                imsi_counts_by_imei.setdefault(imei_key, Counter())[imsi_key] += 1

    selected_groups: Dict[str, Dict[str, object]] = {}
    raw_rows = 0
    excluded_whitelist_keys: set[str] = set()
    raw_imsi_seen: set[str] = set()
    raw_imei_seen: set[str] = set()
    for row in selected_rows:
        imsi = _id15(row.get("imsi_mac"))
        imei = _id15(row.get("imei"))
        if len(imsi) != 15 and len(imei) != 15:
            continue
        raw_rows += 1
        if len(imsi) == 15:
            raw_imsi_seen.add(imsi)
        if len(imei) == 15:
            raw_imei_seen.add(imei)

        if len(imsi) == 15 and len(imei) != 15:
            imei_counter = imei_counts_by_imsi.get(imsi)
            if imei_counter:
                imei = imei_counter.most_common(1)[0][0]
        if len(imei) == 15 and len(imsi) != 15:
            imsi_counter = imsi_counts_by_imei.get(imei)
            if imsi_counter:
                imsi = imsi_counter.most_common(1)[0][0]

        key = imsi if len(imsi) == 15 else imei
        seen_at = _parse_dt_value(row.get("last_update")) or dt.datetime.max
        current = selected_groups.get(key)
        current_seen_at = current.get("selected_seen_at_dt") if current else None
        current_seen_dt = current_seen_at if isinstance(current_seen_at, dt.datetime) else dt.datetime.max
        if current is None or seen_at < current_seen_dt:
            selected_groups[key] = {
                "imsi": imsi,
                "imei": imei,
                "modelo": str(row.get("model") or "").strip() or "-",
                "prestataria": _external_provider_bucket(_carrier_from_imsi_value(imsi)),
                "estado": "DESCONOCIDO / EXTERNO",
                "primera_vez_visto": _format_forensic_dt(row.get("last_update")),
                "selected_seen_at_dt": seen_at,
                "history_system": str(row.get("source") or "").upper(),
                "history_file": str(row.get("archivo_origen") or ""),
                "hash_sha256": str(row.get("hash_sha256") or ""),
                "motivo": "History depurado contra Lista Blanca actual",
            }

    rows: List[Dict[str, object]] = []
    excluded_whitelist_rows: List[Dict[str, object]] = []
    for key, group in selected_groups.items():
        imsi = str(group.get("imsi") or "")
        imei = str(group.get("imei") or "")
        if len(imsi) == 15:
            imei_counter = imei_counts_by_imsi.get(imsi)
            provider_counter = provider_counts_by_imsi.get(imsi)
            if len(imei) != 15 and imei_counter:
                imei = imei_counter.most_common(1)[0][0]
            if provider_counter:
                group["prestataria"] = provider_counter.most_common(1)[0][0]
        first_seen = first_seen_by_key.get(imsi) if len(imsi) == 15 else first_seen_by_key.get(key)
        if first_seen:
            group["primera_vez_visto"] = first_seen.strftime("%Y-%m-%d %H:%M:%S")
        group["imsi"] = imsi or "-"
        group["imei"] = imei or "-"
        if _is_whitelisted_identity(group["imsi"], group["imei"], whitelist):
            excluded_key = _operational_identity_key(group["imsi"], group["imei"])
            excluded_whitelist_keys.add(excluded_key)
            direct_parts = []
            if _identity_keys(group["imsi"]) & whitelist_base:
                direct_parts.append("IMSI directo")
            if _identity_keys(group["imei"]) & whitelist_base:
                direct_parts.append("IMEI directo")
            if not direct_parts:
                direct_parts.append("Asociacion historica IMSI/IMEI")
            direct_keys = sorted((_identity_keys(group["imsi"]) | _identity_keys(group["imei"])) & whitelist_base)
            direct_matches = whitelist_matches_for_ids(direct_keys) if direct_keys else []
            source_names = sorted({
                str(match.get("original_filename") or "").strip()
                for match in direct_matches
                if str(match.get("original_filename") or "").strip()
            })
            excluded_whitelist_rows.append({
                **{k: v for k, v in group.items() if k != "selected_seen_at_dt"},
                "motivo": " + ".join(direct_parts),
                "lista_blanca_fuente": ", ".join(source_names) or "Lista Blanca por asociacion historica",
            })
            continue
        rows.append({k: v for k, v in group.items() if k != "selected_seen_at_dt"})

    order = {"CLARO": 0, "MOVISTAR": 1, "PERSONAL": 2, "DESCONOCIDA": 3, "OTROS": 4}
    rows.sort(key=lambda r: (order.get(str(r.get("prestataria")), 9), str(r.get("primera_vez_visto") or ""), str(r.get("imsi") or "")))
    excluded_whitelist_rows.sort(key=lambda r: (str(r.get("motivo") or ""), str(r.get("imsi") or ""), str(r.get("imei") or "")))
    net_imsi_seen = {str(r.get("imsi") or "") for r in rows if len(_id15(r.get("imsi"))) == 15}
    net_imei_seen = {str(r.get("imei") or "") for r in rows if len(_id15(r.get("imei"))) == 15}
    pre_whitelist_rows = list(selected_groups.values())
    pre_whitelist_imsi_seen = {str(r.get("imsi") or "") for r in pre_whitelist_rows if len(_id15(r.get("imsi"))) == 15}
    pre_whitelist_imei_seen = {str(r.get("imei") or "") for r in pre_whitelist_rows if len(_id15(r.get("imei"))) == 15}
    whitelist_sources = _whitelist_source_summary()
    summary = {
        "source_mode": "history_con_prestatarias",
        "total": len(rows),
        "pre_whitelist_total": len(pre_whitelist_rows),
        "pre_whitelist_imsi": len(pre_whitelist_imsi_seen),
        "pre_whitelist_imei": len(pre_whitelist_imei_seen),
        "raw_rows": raw_rows,
        "excluded_whitelist": len(excluded_whitelist_keys),
        "excluded_whitelist_rows": excluded_whitelist_rows,
        "unique_imsi_selected": len(net_imsi_seen),
        "unique_imei_selected": len(net_imei_seen),
        "unique_imsi_raw": len(raw_imsi_seen),
        "unique_imei_raw": len(raw_imei_seen),
        "by_provider": dict(Counter(str(r.get("prestataria") or "DESCONOCIDA") for r in rows)),
        "files": files_dict,
        "whitelist": whitelist_sources,
    }
    return rows, summary


def _septier_identity_memory() -> Tuple[Dict[str, Counter[str]], Dict[str, Counter[str]]]:
    imei_counts_by_imsi: Dict[str, Counter[str]] = {}
    imsi_counts_by_imei: Dict[str, Counter[str]] = {}
    for row in get_septier_identity_history():
        imsi_key = _id15(row.get("imsi_mac"))
        imei_key = _id15(row.get("imei"))
        if len(imsi_key) == 15 and len(imei_key) == 15:
            imei_counts_by_imsi.setdefault(imsi_key, Counter())[imei_key] += 1
            imsi_counts_by_imei.setdefault(imei_key, Counter())[imsi_key] += 1
    return imei_counts_by_imsi, imsi_counts_by_imei


def _septier_identity_source_maps() -> Tuple[Dict[str, List[Dict[str, object]]], Dict[str, List[Dict[str, object]]]]:
    rows_by_imsi: Dict[str, List[Dict[str, object]]] = {}
    rows_by_imei: Dict[str, List[Dict[str, object]]] = {}
    for row in get_septier_identity_history():
        imsi_key = _id15(row.get("imsi_mac"))
        imei_key = _id15(row.get("imei"))
        if len(imsi_key) == 15:
            rows_by_imsi.setdefault(imsi_key, []).append(row)
        if len(imei_key) == 15:
            rows_by_imei.setdefault(imei_key, []).append(row)
    return rows_by_imsi, rows_by_imei


def _resolve_septier_identity_values(
    imsi_value: object,
    imei_value: object,
    memory: Optional[Tuple[Dict[str, Counter[str]], Dict[str, Counter[str]]]] = None,
) -> Tuple[str, str]:
    imsi = _id15(imsi_value)
    imei = _id15(imei_value)
    imei_counts_by_imsi, imsi_counts_by_imei = memory or _septier_identity_memory()
    if len(imsi) == 15 and len(imei) != 15:
        imei_counter = imei_counts_by_imsi.get(imsi)
        if imei_counter:
            imei = imei_counter.most_common(1)[0][0]
    if len(imei) == 15 and len(imsi) != 15:
        imsi_counter = imsi_counts_by_imei.get(imei)
        if imsi_counter:
            imsi = imsi_counter.most_common(1)[0][0]
    return imsi, imei


def _with_resolved_septier_identity(
    row: Dict[str, object],
    memory: Optional[Tuple[Dict[str, Counter[str]], Dict[str, Counter[str]]]] = None,
) -> Dict[str, object]:
    imsi, imei = _resolve_septier_identity_values(row.get("imsi_mac"), row.get("imei"), memory)
    out = dict(row)
    if len(imsi) == 15:
        out["imsi_mac"] = imsi
    if len(imei) == 15:
        out["imei"] = imei
    return out


def _split_pipe_values(value: object) -> List[str]:
    seen: set[str] = set()
    out: List[str] = []
    for part in str(value or "").split(" | "):
        clean = part.strip()
        if not clean or clean == "-":
            continue
        key = clean.casefold()
        if key not in seen:
            seen.add(key)
            out.append(clean)
    return out


def _merge_pipe_text(*values: object) -> str:
    merged: List[str] = []
    seen: set[str] = set()
    for value in values:
        for clean in _split_pipe_values(value):
            key = clean.casefold()
            if key not in seen:
                seen.add(key)
                merged.append(clean)
    return " | ".join(merged) or "-"


def _merge_previous_identity_text(*values: object) -> str:
    buckets: Dict[str, List[str]] = {"IMEI anterior": [], "IMSI anterior": []}
    seen: Dict[str, set[str]] = {label: set() for label in buckets}
    for value in values:
        text = str(value or "").strip()
        if not text or text == "-":
            continue
        for label in buckets:
            pattern = rf"{re.escape(label)}:\s*(.*?)(?=\s*\|\s*(?:IMEI anterior|IMSI anterior):|$)"
            for match in re.finditer(pattern, text):
                raw_values = re.split(r"\s*\|\s*|\s*,\s*", match.group(1))
                for raw in raw_values:
                    clean = raw.strip()
                    if not clean or clean == "-":
                        continue
                    key = clean.casefold()
                    if key not in seen[label]:
                        seen[label].add(key)
                        buckets[label].append(clean)
    parts = [f"{label}: {', '.join(items)}" for label, items in buckets.items() if items]
    if parts:
        return " | ".join(parts)
    return _merge_pipe_text(*values)


def _septier_mutation_case_key(imsi: str, imei: str, reason: str) -> str:
    reason_value = reason.casefold()
    if "nuevo imei" in reason_value and len(imsi) == 15:
        return f"swap:imsi:{imsi}"
    if "nuevo imsi" in reason_value and len(imei) == 15:
        return f"swap:imei:{imei}"
    if len(imsi) == 15 and len(imei) == 15:
        return f"swap:pair:{imsi}:{imei}"
    return f"swap:{reason_value}:{imsi}:{imei}"


def _septier_history_base_name(value: object) -> str:
    text = str(value or "").strip()
    match = re.search(r"history\.\d+", text, flags=re.I)
    if match:
        return match.group(0).lower()
    if text:
        return Path(text).name.lower()
    return "-"


def _septier_swap_row_seen_key(row: Dict[str, object]) -> Tuple[str, str, str, str, str]:
    imsi = _id15(row.get("imsi_mac"))
    imei = _id15(row.get("imei"))
    seen_at = str(row.get("last_update") or "").replace("T", " ").strip()[:19]
    return (
        str(row.get("source") or "").strip().lower(),
        _septier_history_base_name(row.get("archivo_origen")),
        imsi,
        imei,
        seen_at,
    )


def _is_septier_swap_placeholder_identity(value: object) -> bool:
    digits = _id15(value)
    if len(digits) != 15:
        return False
    subscriber_tail = digits[5:]
    return subscriber_tail in {"0" * 10, "1" * 10, "9" * 10} or len(set(digits[-8:])) == 1


def _dedupe_septier_rows_for_swap(
    rows: List[Dict[str, object]],
    identity_memory: Tuple[Dict[str, Counter], Dict[str, Counter]],
) -> List[Dict[str, object]]:
    deduped: List[Dict[str, object]] = []
    seen: set[Tuple[str, str, str, str, str]] = set()
    for source_row in rows:
        row = _with_resolved_septier_identity(source_row, identity_memory)
        key = _septier_swap_row_seen_key(row)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(row)
    return deduped


def _septier_swap_identity_memory_and_sources() -> Tuple[
    Dict[str, Counter],
    Dict[str, Counter],
    Dict[str, List[Dict[str, object]]],
    Dict[str, List[Dict[str, object]]],
]:
    imei_counts_by_imsi: Dict[str, Counter] = {}
    imsi_counts_by_imei: Dict[str, Counter] = {}
    rows_by_imsi: Dict[str, List[Dict[str, object]]] = {}
    rows_by_imei: Dict[str, List[Dict[str, object]]] = {}
    seen: set[Tuple[str, str, str, str, str]] = set()
    for row in get_septier_identity_history():
        key = _septier_swap_row_seen_key(row)
        if key in seen:
            continue
        seen.add(key)
        imsi_key = _id15(row.get("imsi_mac"))
        imei_key = _id15(row.get("imei"))
        if _is_septier_swap_placeholder_identity(imsi_key) or _is_septier_swap_placeholder_identity(imei_key):
            continue
        if len(imsi_key) == 15 and len(imei_key) == 15:
            imei_counts_by_imsi.setdefault(imsi_key, Counter())[imei_key] += 1
            imsi_counts_by_imei.setdefault(imei_key, Counter())[imsi_key] += 1
        if len(imsi_key) == 15:
            rows_by_imsi.setdefault(imsi_key, []).append(row)
        if len(imei_key) == 15:
            rows_by_imei.setdefault(imei_key, []).append(row)
    return imei_counts_by_imsi, imsi_counts_by_imei, rows_by_imsi, rows_by_imei


def _septier_swap_memory_source_text(rows: List[Dict[str, object]]) -> str:
    if not rows:
        return "-"
    values: List[str] = []
    seen: set[Tuple[str, str]] = set()
    for row in rows:
        source = str(row.get("source") or "").strip().upper()
        history = str(row.get("archivo_origen") or "").strip()
        base = _septier_history_base_name(history)
        key = (source.casefold(), base)
        if key in seen:
            continue
        seen.add(key)
        if source and history:
            values.append(f"{source}: {history}")
        elif history:
            values.append(history)
    return " | ".join(values) if values else "-"


def _septier_mutation_case_count(alerts: List[Dict[str, object]]) -> int:
    parent: Dict[str, str] = {}

    def find(node: str) -> str:
        parent.setdefault(node, node)
        if parent[node] != node:
            parent[node] = find(parent[node])
        return parent[node]

    def union(left: str, right: str) -> None:
        root_left = find(left)
        root_right = find(right)
        if root_left != root_right:
            parent[root_right] = root_left

    for alert in alerts:
        imsi = _id15(alert.get("imsi"))
        imei = _id15(alert.get("imei"))
        if len(imsi) == 15 and len(imei) == 15:
            union(f"imsi:{imsi}", f"imei:{imei}")
            continue
        case_key = str(alert.get("case_key") or "").strip()
        if case_key:
            find(case_key)
    return len({find(node) for node in parent})


def _septier_mutation_alerts_from_rows(rows: List[Dict[str, object]], limit: int = 80) -> List[Dict[str, object]]:
    mem_imsi, mem_imei, mem_imsi_rows, mem_imei_rows = _historial_memory_maps()
    imei_counts_by_imsi, imsi_counts_by_imei, det_rows_by_imsi, det_rows_by_imei = _septier_swap_identity_memory_and_sources()
    identity_memory = (imei_counts_by_imsi, imsi_counts_by_imei)
    alerts: List[Dict[str, object]] = []
    alert_index: Dict[Tuple[str, str, str], int] = {}
    for row in _dedupe_septier_rows_for_swap(rows, identity_memory):
        imsi = _id15(row.get("imsi_mac"))
        imei = _id15(row.get("imei"))
        if len(imsi) != 15 or len(imei) != 15:
            continue
        if _is_septier_swap_placeholder_identity(imsi) or _is_septier_swap_placeholder_identity(imei):
            continue
        mutation_context = _septier_mutation_context(
            imsi,
            imei,
            row.get("last_update"),
            mem_imsi_rows,
            mem_imei_rows,
            imei_counts_by_imsi,
            imsi_counts_by_imei,
            det_rows_by_imsi,
            det_rows_by_imei,
        )
        if not mutation_context:
            continue
        reason = str(mutation_context["reason"])
        memory_rows = list(mutation_context["memory_rows"])
        previous_value = str(mutation_context["previous_identity_value"])
        case_key = _septier_mutation_case_key(imsi, imei, reason)
        key = (imsi, imei, reason)
        history_name = str(row.get("archivo_origen") or "-")
        source_name = str(row.get("source") or "").upper()
        seen_at = str(row.get("last_update") or "").replace("T", " ")
        if key in alert_index:
            existing = alerts[alert_index[key]]
            memory_text = _septier_swap_memory_source_text(memory_rows)
            existing["history"] = _merge_pipe_text(existing.get("history"), history_name)
            existing["source"] = _merge_pipe_text(existing.get("source"), source_name)
            existing["memory_source"] = _merge_pipe_text(existing.get("memory_source"), memory_text)
            existing["previous_identity_value"] = _merge_previous_identity_text(
                existing.get("previous_identity_value"),
                previous_value,
            )
            existing["history_count"] = len(_split_pipe_values(existing.get("history")))
            if seen_at and seen_at != "-":
                first_seen = str(existing.get("seen_at") or "")
                if not first_seen or seen_at < first_seen:
                    existing["seen_at"] = seen_at
            continue
        matches = _whitelist_match_details(imsi, imei)
        alert_index[key] = len(alerts)
        alerts.append({
            "imsi": imsi,
            "imei": imei,
            "reason": reason,
            "case_key": case_key,
            "previous_identity_value": previous_value,
            "memory_source": _septier_swap_memory_source_text(memory_rows),
            "source": source_name or "-",
            "history": history_name,
            "history_count": 1 if history_name and history_name != "-" else 0,
            "operation": row.get("operation") or "-",
            "model": row.get("model") or "-",
            "seen_at": seen_at,
            "whitelist_status": "AUTORIZADO" if matches else "NO AUTORIZADO",
            "whitelist_source": " | ".join(sorted({str(m.get("source_label") or "") for m in matches if m.get("source_label")})) or "",
            "whitelist_reason": _whitelist_match_reason(matches) if matches else "",
            "whitelist_trace": _whitelist_match_trace(matches) if matches else "",
            "whitelist_matches": matches,
        })
        if limit and len(alerts) >= limit:
            break
    return alerts


def _septier_mutation_summary_from_rows(rows: List[Dict[str, object]]) -> Dict[str, int]:
    _, _, mem_imsi_rows, mem_imei_rows = _historial_memory_maps()
    imei_counts_by_imsi, imsi_counts_by_imei, det_rows_by_imsi, det_rows_by_imei = _septier_swap_identity_memory_and_sources()
    identity_memory = (imei_counts_by_imsi, imsi_counts_by_imei)
    whitelist = _whitelist_identity_set()
    parent: Dict[str, str] = {}
    alert_keys: set[Tuple[str, str, str]] = set()
    unauthorized_case_keys: set[str] = set()

    def find(node: str) -> str:
        parent.setdefault(node, node)
        if parent[node] != node:
            parent[node] = find(parent[node])
        return parent[node]

    def union(left: str, right: str) -> None:
        root_left = find(left)
        root_right = find(right)
        if root_left != root_right:
            parent[root_right] = root_left

    for row in _dedupe_septier_rows_for_swap(rows, identity_memory):
        imsi = _id15(row.get("imsi_mac"))
        imei = _id15(row.get("imei"))
        if len(imsi) != 15 or len(imei) != 15:
            continue
        if _is_septier_swap_placeholder_identity(imsi) or _is_septier_swap_placeholder_identity(imei):
            continue
        mutation_context = _septier_mutation_context(
            imsi,
            imei,
            row.get("last_update"),
            mem_imsi_rows,
            mem_imei_rows,
            imei_counts_by_imsi,
            imsi_counts_by_imei,
            det_rows_by_imsi,
            det_rows_by_imei,
        )
        if not mutation_context:
            continue
        reason = str(mutation_context["reason"])
        alert_keys.add((imsi, imei, reason))
        if len(imsi) == 15 and len(imei) == 15:
            union(f"imsi:{imsi}", f"imei:{imei}")
        else:
            find(_septier_mutation_case_key(imsi, imei, reason))
        if not _is_whitelisted_identity(imsi, imei, whitelist):
            unauthorized_case_keys.add(find(f"imsi:{imsi}"))

    case_roots = {find(node) for node in parent}
    unauthorized_roots = {find(node) for node in unauthorized_case_keys}
    return {
        "alerts_total": len(alert_keys),
        "cases_total": len(case_roots),
        "unauthorized_cases": len(unauthorized_roots),
    }


def _blocking_operator_from_imsi(imsi: object) -> str:
    carrier = _carrier_from_imsi_value(str(imsi or ""))
    if carrier == "CLARO":
        return "Claro"
    if carrier == "MOVISTAR":
        return "Movistar"
    if carrier == "PERSONAL":
        return "Personal"
    return "Internacional"


def _iso_utc_from_operational_dt(value: object) -> str:
    parsed = _parse_dt_value(value)
    if not parsed:
        return ""
    local = parsed.replace(tzinfo=dt.timezone(dt.timedelta(hours=-3)))
    return local.astimezone(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _septier_blocking_csv_rows(files: List[FileItem]) -> Tuple[Dict[str, List[Dict[str, object]]], Dict[str, List[Dict[str, object]]], Dict[str, object]]:
    files_payload = [{"system": f.system, "file": f.file} for f in files if f.system and f.file]
    if not files_payload:
        raise HTTPException(status_code=400, detail="Selecciona al menos un history Guardian o Backpack.")
    source_rows = get_septier_forensic_rows_by_files(files_payload)
    if not source_rows:
        raise HTTPException(status_code=404, detail="No hay detecciones cargadas para los histories seleccionados.")

    whitelist = _whitelist_identity_set()
    if not whitelist:
        raise HTTPException(status_code=400, detail="CSV Bloqueo requiere Lista Blanca activa para excluir autorizados.")

    identity_memory = _septier_identity_memory()
    candidate_imsi_groups: Dict[str, Dict[str, object]] = {}
    candidate_imei_groups: Dict[str, Dict[str, object]] = {}
    selected_imeis_by_imsi: Dict[str, set] = defaultdict(set)
    invalid_rows = 0

    for source_row in source_rows:
        resolved_row = _with_resolved_septier_identity(source_row, identity_memory)
        imsi = _id15(resolved_row.get("imsi_mac"))
        imei = _id15(resolved_row.get("imei"))
        if len(imsi) != 15 and len(imei) != 15:
            invalid_rows += 1
            continue
        seen_utc = _iso_utc_from_operational_dt(resolved_row.get("last_update"))
        operator = _blocking_operator_from_imsi(imsi)

        if len(imsi) == 15:
            group = candidate_imsi_groups.setdefault(imsi, {
                "imsi": imsi, "operator": operator, "recurrencia": 0,
                "first_seen_utc": "", "last_seen_utc": "", "_imeis": set(),
            })
            group["recurrencia"] = int(group.get("recurrencia") or 0) + 1
            if len(imei) == 15:
                group["_imeis"].add(imei)
            if seen_utc and (not group.get("first_seen_utc") or seen_utc < str(group.get("first_seen_utc") or "")):
                group["first_seen_utc"] = seen_utc
            if seen_utc and (not group.get("last_seen_utc") or seen_utc > str(group.get("last_seen_utc") or "")):
                group["last_seen_utc"] = seen_utc

        if len(imsi) == 15 and len(imei) == 15:
            selected_imeis_by_imsi[imsi].add(imei)

        if len(imei) == 15:
            group = candidate_imei_groups.setdefault(imei, {
                "imei": imei, "operator": operator, "first_seen_utc": "",
                "last_seen_utc": "", "_imsis": set(),
            })
            if len(imsi) == 15:
                group["_imsis"].add(imsi)
            if seen_utc and (not group.get("first_seen_utc") or seen_utc < str(group.get("first_seen_utc") or "")):
                group["first_seen_utc"] = seen_utc
            if seen_utc and (not group.get("last_seen_utc") or seen_utc > str(group.get("last_seen_utc") or "")):
                group["last_seen_utc"] = seen_utc

    for imsi, imei_counter in identity_memory[0].items():
        if len(imsi) == 15:
            selected_imeis_by_imsi[imsi].update(k for k in imei_counter.keys() if len(k) == 15)
            if imsi in candidate_imsi_groups:
                candidate_imsi_groups[imsi]["_imeis"].update(k for k in imei_counter.keys() if len(k) == 15)

    batch_id = str(uuid.uuid4())
    imsi_by_operator: Dict[str, List[Dict[str, object]]] = defaultdict(list)
    imei_by_operator: Dict[str, List[Dict[str, object]]] = defaultdict(list)
    excluded_whitelist_identity_keys = set()
    excluded_whitelist_imsi = 0
    excluded_whitelist_imei = 0

    for group in candidate_imsi_groups.values():
        imsi = str(group.get("imsi") or "")
        imeis = {str(v) for v in (group.get("_imeis") or set()) if len(str(v)) == 15}
        if _is_whitelisted_identity(imsi, "", whitelist) or any(_is_whitelisted_identity("", imei, whitelist) for imei in imeis):
            excluded_whitelist_identity_keys.add(f"imsi:{imsi}")
            excluded_whitelist_imsi += 1
            continue
        imsi_by_operator[str(group["operator"])].append({
            "imsi": group["imsi"],
            "operator": group["operator"],
            "recurrencia": int(group.get("recurrencia") or 0),
            "first_seen_utc": group.get("first_seen_utc") or "",
            "last_seen_utc": group.get("last_seen_utc") or "",
            "batch_id": batch_id,
        })
    for group in candidate_imei_groups.values():
        imei = str(group.get("imei") or "")
        imsis = {str(v) for v in (group.get("_imsis") or set()) if str(v)}
        if _is_whitelisted_identity("", imei, whitelist) or any(_is_whitelisted_identity(imsi, "", whitelist) for imsi in imsis):
            excluded_whitelist_identity_keys.add(f"imei:{imei}")
            excluded_whitelist_imei += 1
            continue
        imsis = {str(v) for v in (group.get("_imsis") or set()) if str(v)}
        observable_clone = any(len(selected_imeis_by_imsi.get(imsi, set())) > 1 for imsi in imsis)
        imei_by_operator[str(group["operator"])].append({
            "imei": group["imei"],
            "imei_observable_clon": "true" if observable_clone else "false",
            "operator": group["operator"],
            "first_seen_utc": group.get("first_seen_utc") or "",
            "last_seen_utc": group.get("last_seen_utc") or "",
            "batch_id": batch_id,
        })

    for rows in imsi_by_operator.values():
        rows.sort(key=lambda r: (str(r.get("imsi") or ""), str(r.get("first_seen_utc") or "")))
    for rows in imei_by_operator.values():
        rows.sort(key=lambda r: (str(r.get("imei") or ""), str(r.get("first_seen_utc") or "")))

    summary = {
        "batch_id": batch_id,
        "files": files_payload,
        "raw_rows": len(source_rows),
        "net_rows": sum(len(rows) for rows in imsi_by_operator.values()),
        "invalid_rows": invalid_rows,
        "unique_identities_read": len(
            {f"imsi:{key}" for key in candidate_imsi_groups.keys()}
            | {f"imei:{key}" for key in candidate_imei_groups.keys()}
        ),
        "imsi_unique_read": len(candidate_imsi_groups),
        "imei_unique_read": len(candidate_imei_groups),
        "excluded_whitelist": len(excluded_whitelist_identity_keys),
        "excluded_whitelist_imsi": excluded_whitelist_imsi,
        "excluded_whitelist_imei": excluded_whitelist_imei,
        "imsi_total": sum(len(rows) for rows in imsi_by_operator.values()),
        "imei_total": sum(len(rows) for rows in imei_by_operator.values()),
        "operators": sorted(set(imsi_by_operator.keys()) | set(imei_by_operator.keys())),
    }
    return imsi_by_operator, imei_by_operator, summary


@app.post("/api/septier/blocking-csv/generate")
def septier_blocking_csv_generate(payload: ForensicMasterRequest, user=Depends(_require_auth)):
    imsi_by_operator, imei_by_operator, summary = _septier_blocking_csv_rows(payload.files)
    stamp_dt = dt.datetime.now(dt.timezone(dt.timedelta(hours=-3)))
    date_tag = stamp_dt.strftime("%Y%m%d")
    stamp = stamp_dt.strftime("%Y%m%d_%H%M%S")
    out_dir = OUTPUTS_DIR / "csv_bloqueo_imsi_imei" / f"bloqueo_{stamp}"
    out_dir.mkdir(parents=True, exist_ok=True)
    csv_outputs: List[Dict[str, object]] = []

    def write_csv(filename: str, fieldnames: List[str], rows: List[Dict[str, object]]) -> None:
        path = out_dir / filename
        with path.open("w", newline="", encoding="utf-8-sig") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
        csv_outputs.append({"filename": filename, "rows": len(rows), "sha256": _nexa_hash_file(path), "url": _skyeye_output_url(path)})

    for operator, rows in sorted(imsi_by_operator.items()):
        write_csv(f"Imsi_{operator}_{date_tag}.csv", ["imsi", "operator", "recurrencia", "first_seen_utc", "last_seen_utc", "batch_id"], rows)
    for operator, rows in sorted(imei_by_operator.items()):
        write_csv(f"imei_{operator}_{date_tag}.csv", ["imei", "imei_observable_clon", "operator", "first_seen_utc", "last_seen_utc", "batch_id"], rows)

    zip_path = out_dir / f"CSV_Bloqueo_IMSI_IMEI_{date_tag}_{summary['batch_id']}.zip"
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for output in csv_outputs:
            z.write(out_dir / str(output["filename"]), arcname=str(output["filename"]))

    def e(value: object) -> str:
        return html_lib.escape(str(value if value is not None else ""))

    file_rows_html = "".join(f"<tr><td>{e(f.get('system'))}</td><td>{e(f.get('file'))}</td></tr>" for f in summary["files"])
    csv_rows_html = "".join(
        f"<tr><td>{e(o.get('filename'))}</td><td>{e(o.get('rows'))}</td><td><span class='hash'>{e(o.get('sha256'))}</span></td><td><a href='{e(o.get('url'))}'>Descargar</a></td></tr>"
        for o in csv_outputs
    )
    html = f"""<!doctype html><html lang="es"><head><meta charset="utf-8"><title>CSV Bloqueo IMSI IMEI</title>
<style>body{{font-family:Arial,sans-serif;margin:24px;color:#001b33}}h1{{color:#00446f}}h2{{color:#005f91;margin-top:22px}}.meta,.rule{{border:1px solid #c8d7e6;border-radius:6px;padding:10px;margin:12px 0}}.grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin:16px 0}}.metric{{border:1px solid #c8d7e6;border-radius:6px;padding:10px;background:#f6f9fc}}.metric strong{{display:block;color:#00446f;font-size:24px}}table{{border-collapse:collapse;width:100%;margin:12px 0;font-size:13px}}th,td{{border:1px solid #c8d7e6;padding:7px;text-align:left;vertical-align:top}}th{{background:#e9f2fb}}.hash{{font-size:11px;word-break:break-all}}</style></head><body>
<h1>CSV Bloqueo IMSI / IMEI</h1>
<div class="meta"><strong>Resolucion:</strong> 2026-336-APN-MSG del 14/04/2026<br><strong>Batch ID:</strong> {e(summary['batch_id'])}<br><strong>Generado:</strong> {e(stamp_dt.strftime('%Y-%m-%d %H:%M:%S %z'))}<br><strong>Usuario:</strong> {e(user.get('full_name') or user.get('username'))}</div>
<div class="rule"><strong>Regla aplicada:</strong> se excluye Lista Blanca actual por IMSI o IMEI usando solo identificadores numericos validos de 15 digitos. Data Externa no excluye. Los horarios se exportan en ISO 8601 UTC.</div>
<div class="grid"><div class="metric"><strong>{e(summary['raw_rows'])}</strong>Detecciones brutas leidas</div><div class="metric"><strong>{e(summary['unique_identities_read'])}</strong>Identidades leidas sin duplicar</div><div class="metric"><strong>{e(summary['excluded_whitelist'])}</strong>Coincidencias Lista Blanca</div><div class="metric"><strong>{e(summary['imsi_unique_read'])}</strong>IMSI unicos leidos</div><div class="metric"><strong>{e(summary['imsi_total'])}</strong>IMSI para bloqueo</div><div class="metric"><strong>{e(summary['imei_unique_read'])}</strong>IMEI unicos leidos</div><div class="metric"><strong>{e(summary['imei_total'])}</strong>IMEI para bloqueo</div></div>
<h2>Histories utilizados</h2><table><thead><tr><th>Sistema</th><th>History</th></tr></thead><tbody>{file_rows_html}</tbody></table>
<h2>Archivos CSV generados</h2><table><thead><tr><th>Archivo</th><th>Filas</th><th>SHA-256</th><th>Link</th></tr></thead><tbody>{csv_rows_html or '<tr><td colspan="4">Sin CSV generados.</td></tr>'}</tbody></table>
</body></html>"""
    html_path = out_dir / f"auditoria_csv_bloqueo_{date_tag}_{stamp}.html"
    html_path.write_text(html, encoding="utf-8")

    try:
        from docx import Document
        from docx.enum.section import WD_ORIENT
        from docx.shared import Cm, Pt, RGBColor
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Falta dependencia python-docx para generar Word: {exc}")

    word_path = out_dir / f"auditoria_csv_bloqueo_{date_tag}_{stamp}.docx"
    doc = Document()
    section = doc.sections[0]
    section.orientation = WD_ORIENT.LANDSCAPE
    section.page_width, section.page_height = section.page_height, section.page_width
    for sec in doc.sections:
        sec.top_margin = Cm(1.2); sec.bottom_margin = Cm(1.2); sec.left_margin = Cm(1.2); sec.right_margin = Cm(1.2)
    title = doc.add_heading("CSV Bloqueo IMSI / IMEI", 0)
    title.runs[0].font.color.rgb = RGBColor(0, 68, 111)
    doc.add_paragraph("Resolucion: 2026-336-APN-MSG del 14/04/2026")
    doc.add_paragraph(f"Batch ID: {summary['batch_id']}")
    doc.add_paragraph(f"Generado: {stamp_dt.strftime('%Y-%m-%d %H:%M:%S %z')}")
    doc.add_paragraph(f"Usuario: {user.get('full_name') or user.get('username')}")
    doc.add_paragraph("Regla aplicada: se excluye Lista Blanca actual por IMSI o IMEI usando solo identificadores numericos validos de 15 digitos. Data Externa no excluye. Los horarios se exportan en ISO 8601 UTC.")
    metrics = doc.add_table(rows=2, cols=7)
    labels = [
        "Detecciones brutas leidas",
        "Identidades leidas sin duplicar",
        "Coincidencias Lista Blanca",
        "IMSI unicos leidos",
        "IMSI para bloqueo",
        "IMEI unicos leidos",
        "IMEI para bloqueo",
    ]
    values = [
        summary["raw_rows"],
        summary["unique_identities_read"],
        summary["excluded_whitelist"],
        summary["imsi_unique_read"],
        summary["imsi_total"],
        summary["imei_unique_read"],
        summary["imei_total"],
    ]
    for i, label in enumerate(labels):
        metrics.cell(0, i).text = str(values[i]); metrics.cell(1, i).text = label
    doc.add_heading("Histories utilizados", level=1)
    table = doc.add_table(rows=1, cols=2)
    table.rows[0].cells[0].text = "Sistema"; table.rows[0].cells[1].text = "History"
    for f in summary["files"]:
        cells = table.add_row().cells; cells[0].text = str(f.get("system") or ""); cells[1].text = str(f.get("file") or "")
    doc.add_heading("Archivos CSV generados", level=1)
    table = doc.add_table(rows=1, cols=3)
    for i, h in enumerate(["Archivo", "Filas", "SHA-256"]):
        table.rows[0].cells[i].text = h
    for output in csv_outputs:
        cells = table.add_row().cells
        cells[0].text = str(output.get("filename") or ""); cells[1].text = str(output.get("rows") or 0); cells[2].text = str(output.get("sha256") or "")
    for paragraph in doc.paragraphs:
        for run in paragraph.runs:
            run.font.size = Pt(9)
    doc.save(word_path)

    return {
        "ok": True,
        "batch_id": summary["batch_id"],
        "summary": summary,
        "csv_outputs": csv_outputs,
        "zip_url": _skyeye_output_url(zip_path),
        "zip_sha256": _nexa_hash_file(zip_path),
        "html_url": _skyeye_output_url(html_path),
        "word_url": _skyeye_output_url(word_path),
    }


@app.post("/api/septier/reference/external-data/history-provider-audit")
def api_history_provider_audit(payload: SeptierHistoryProviderAuditRequest, user=Depends(_require_auth)):
    rows, summary = _history_provider_audit_rows(payload.files)
    stamp_dt = dt.datetime.now(dt.timezone(dt.timedelta(hours=-3)))
    stamp = stamp_dt.strftime("%Y%m%d_%H%M%S")
    base_name = f"auditoria_history_prestatarias_{stamp}"
    OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)
    csv_path = OUTPUTS_DIR / f"{base_name}.csv"
    html_path = OUTPUTS_DIR / f"{base_name}.html"
    word_path = OUTPUTS_DIR / f"{base_name}.docx"
    fields = [
        "prestataria", "imsi", "imei", "estado", "modelo", "primera_vez_visto",
        "history_system", "history_file", "motivo", "hash_sha256",
    ]
    with csv_path.open("w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields, delimiter=";")
        writer.writeheader()
        writer.writerows([{field: row.get(field, "") for field in fields} for row in rows])

    whitelist_summary = summary.get("whitelist", {})
    external_sources = whitelist_summary.get("external_query_sources", [])
    upload_names = ", ".join(
        f"#{u.get('id')} {u.get('filename')}"
        for u in whitelist_summary.get("uploads", [])
    ) or "Sin archivos activos informados"
    files_text = ", ".join(f"{f.get('system', '').upper()}: {f.get('file', '')}" for f in summary.get("files", []))

    def _table_for(provider: str) -> str:
        subset = [r for r in rows if str(r.get("prestataria") or "") == provider]
        if not subset:
            return "<p>Sin registros.</p>"
        body = "\n".join(
            "<tr>"
            f"<td>{html_lib.escape(str(r.get('imsi') or '-'))}</td>"
            f"<td>{html_lib.escape(str(r.get('imei') or '-'))}</td>"
            f"<td>{html_lib.escape(str(r.get('estado') or '-'))}</td>"
            f"<td>{html_lib.escape(str(r.get('modelo') or '-'))}</td>"
            f"<td>{html_lib.escape(str(r.get('primera_vez_visto') or '-'))}</td>"
            f"<td>{html_lib.escape(str(r.get('history_system') or '-'))}</td>"
            f"<td>{html_lib.escape(str(r.get('history_file') or '-'))}</td>"
            "</tr>"
            for r in subset
        )
        return f"<table><thead><tr><th>IMSI</th><th>IMEI</th><th>Estado</th><th>Modelo</th><th>Primera vez visto</th><th>Sistema</th><th>History</th></tr></thead><tbody>{body}</tbody></table>"

    def _excluded_table() -> str:
        subset = list(summary.get("excluded_whitelist_rows") or [])
        if not subset:
            return "<p>Sin exclusiones por Lista Blanca.</p>"
        body = "\n".join(
            "<tr>"
            f"<td>{html_lib.escape(str(r.get('imsi') or '-'))}</td>"
            f"<td>{html_lib.escape(str(r.get('imei') or '-'))}</td>"
            f"<td>{html_lib.escape(str(r.get('motivo') or '-'))}</td>"
            f"<td>{html_lib.escape(str(r.get('lista_blanca_fuente') or '-'))}</td>"
            f"<td>{html_lib.escape(str(r.get('primera_vez_visto') or '-'))}</td>"
            f"<td>{html_lib.escape(str(r.get('history_file') or '-'))}</td>"
            "</tr>"
            for r in subset
        )
        return f"<table><thead><tr><th>IMSI</th><th>IMEI</th><th>Motivo exclusion</th><th>Fuente Lista Blanca</th><th>Primera vez visto</th><th>History</th></tr></thead><tbody>{body}</tbody></table>"

    provider_sections = "\n".join(
        f"<h2>{provider}</h2>{_table_for(provider)}"
        for provider in ["CLARO", "MOVISTAR", "PERSONAL", "DESCONOCIDA", "OTROS"]
    )
    html_path.write_text(f"""<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <title>AUDITORIA HISTORY CON PRESTATARIAS</title>
  <style>
    body {{ font-family: Arial, sans-serif; color: #061327; margin: 28px; }}
    .letterhead {{ border: 1px solid #c8d4e3; border-radius: 8px; padding: 12px 14px; margin-bottom: 18px; background: #f8fbff; color: #003b68; font-weight: 700; line-height: 1.45; text-transform: uppercase; }}
    .letterhead .ministry {{ color: #005b8f; }}
    h1 {{ color: #003b68; text-transform: uppercase; }}
    h2 {{ color: #005b8f; margin-top: 24px; }}
    .grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin: 18px 0; }}
    .card {{ border: 1px solid #c8d4e3; border-radius: 8px; padding: 12px; background: #f8fbff; }}
    .card strong {{ display: block; font-size: 24px; color: #003b68; }}
    .note {{ border: 1px solid #c8d4e3; border-radius: 8px; padding: 12px; background: #fff; margin: 14px 0; }}
    table {{ border-collapse: collapse; width: 100%; font-size: 12px; margin-bottom: 16px; }}
    th, td {{ border: 1px solid #d4deeb; padding: 7px; text-align: left; vertical-align: top; }}
    th {{ background: #eaf2fb; }}
  </style>
</head>
<body>
  <div class="letterhead">
    <div>DEPARTAMENTO DE TECNOLOGIAS ESPECIALES Y DESPLIEGUE TACTICO</div>
    <div>SUBSECRETARIA DE TECNOLOGIA APLICADA A LA SEGURIDAD</div>
    <div class="ministry">MINISTERIO DE SEGURIDAD Y JUSTICIA</div>
  </div>
  <h1>AUDITORIA HISTORY CON PRESTATARIAS</h1>
  <p><strong>Regla:</strong> se reconstruye cada IMSI desde history, se recupera IMEI frecuente cuando falta y se excluye solo si coincide con Lista Blanca actual por IMSI o IMEI.</p>
  <p><strong>Generado:</strong> {stamp_dt.strftime('%Y-%m-%d %H:%M:%S')} | <strong>Usuario:</strong> {html_lib.escape(str(user.get('full_name') or user.get('username') or '-'))}</p>
  <p><strong>Histories auditados:</strong> {html_lib.escape(files_text)}</p>
  <div class="grid">
    <div class="card"><strong>{summary['raw_rows']}</strong>Detecciones brutas leidas</div>
    <div class="card"><strong>{summary['pre_whitelist_total']}</strong>Detecciones netas antes de Lista Blanca</div>
    <div class="card"><strong>{summary['pre_whitelist_imsi']}</strong>IMSI unicos antes de Lista Blanca</div>
    <div class="card"><strong>{summary['pre_whitelist_imei']}</strong>IMEI unicos antes de Lista Blanca</div>
  </div>
  <div class="grid">
    <div class="card"><strong>{summary['excluded_whitelist']}</strong>Excluidos Lista Blanca</div>
    <div class="card"><strong>{summary['total']}</strong>Total general depurado</div>
    <div class="card"><strong>{summary['unique_imsi_selected']}</strong>IMSI unicos finales</div>
    <div class="card"><strong>{summary['unique_imei_selected']}</strong>IMEI unicos finales</div>
  </div>
  <div class="grid">
    <div class="card"><strong>{summary['by_provider'].get('CLARO', 0)}</strong>Claro</div>
    <div class="card"><strong>{summary['by_provider'].get('MOVISTAR', 0)}</strong>Movistar</div>
    <div class="card"><strong>{summary['by_provider'].get('PERSONAL', 0)}</strong>Personal</div>
    <div class="card"><strong>{summary['by_provider'].get('DESCONOCIDA', 0) + summary['by_provider'].get('OTROS', 0)}</strong>Desconocida / Otros</div>
  </div>
  <div class="note">
    <strong>Comparacion de Lista Blanca:</strong><br>
    Query externa de referencia: 5 fuentes/tablas y {len(external_sources)} campos de identidad ({html_lib.escape(', '.join(external_sources))}).<br>
    Base SkyEye actual: {whitelist_summary.get('uploads_active', 0)} archivo(s) activo(s) de Lista Blanca, {whitelist_summary.get('uploads_total', 0)} archivo(s) registrado(s), {whitelist_summary.get('devices_active', 0)} identidad(es) activas.<br>
    Archivos activos: {html_lib.escape(upload_names)}.
  </div>
  <h2>Trazabilidad de excluidos por Lista Blanca</h2>
  {_excluded_table()}
  {provider_sections}
</body>
</html>""", encoding="utf-8")

    try:
        from docx import Document
        from docx.enum.section import WD_ORIENT
        from docx.enum.table import WD_TABLE_ALIGNMENT
        from docx.shared import Cm, Pt, RGBColor
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Falta dependencia python-docx para generar Word: {exc}")

    doc = Document()
    section = doc.sections[0]
    section.orientation = WD_ORIENT.LANDSCAPE
    section.page_width, section.page_height = section.page_height, section.page_width
    section.top_margin = Cm(1.0)
    section.bottom_margin = Cm(1.0)
    section.left_margin = Cm(1.0)
    section.right_margin = Cm(1.0)
    title = doc.add_paragraph()
    run = title.add_run("AUDITORIA HISTORY CON PRESTATARIAS")
    run.bold = True
    run.font.size = Pt(18)
    run.font.color.rgb = RGBColor(0, 59, 104)
    for line in [
        "DEPARTAMENTO DE TECNOLOGIAS ESPECIALES Y DESPLIEGUE TACTICO",
        "SUBSECRETARIA DE TECNOLOGIA APLICADA A LA SEGURIDAD",
        "MINISTERIO DE SEGURIDAD Y JUSTICIA",
    ]:
        p = doc.add_paragraph()
        r = p.add_run(line)
        r.bold = True
        r.font.size = Pt(9)
        r.font.color.rgb = RGBColor(0, 59, 104)
    doc.add_paragraph(f"Generado: {stamp_dt.strftime('%Y-%m-%d %H:%M:%S')} | Usuario: {user.get('full_name') or user.get('username') or '-'}")
    doc.add_paragraph("Regla: se reconstruye cada IMSI desde history, se recupera IMEI frecuente cuando falta y se excluye solo si coincide con Lista Blanca actual por IMSI o IMEI.")
    doc.add_paragraph(f"Histories auditados: {files_text}")
    doc.add_paragraph(
        f"Lista Blanca actual: {whitelist_summary.get('uploads_active', 0)} archivo(s) activo(s), "
        f"{whitelist_summary.get('devices_active', 0)} identidad(es) activas. "
        f"Query externa: 5 fuentes / {len(external_sources)} campos de identidad."
    )
    doc.add_paragraph(
        f"Metricas: brutas {summary['raw_rows']} | netas antes de Lista Blanca {summary['pre_whitelist_total']} | "
        f"IMSI antes de Lista Blanca {summary['pre_whitelist_imsi']} | IMEI antes de Lista Blanca {summary['pre_whitelist_imei']} | "
        f"excluidos Lista Blanca {summary['excluded_whitelist']} | total general depurado {summary['total']} | "
        f"IMSI finales {summary['unique_imsi_selected']} | IMEI finales {summary['unique_imei_selected']}"
    )
    excluded_subset = list(summary.get("excluded_whitelist_rows") or [])
    if excluded_subset:
        heading = doc.add_paragraph()
        hr = heading.add_run(f"Trazabilidad de excluidos por Lista Blanca ({len(excluded_subset)})")
        hr.bold = True
        hr.font.size = Pt(13)
        hr.font.color.rgb = RGBColor(0, 91, 143)
        table = doc.add_table(rows=1, cols=6)
        table.alignment = WD_TABLE_ALIGNMENT.LEFT
        table.autofit = True
        headers = ["IMSI", "IMEI", "Motivo", "Fuente Lista Blanca", "Primera vez", "History"]
        for idx, label in enumerate(headers):
            cell = table.rows[0].cells[idx]
            cell.text = label
            for paragraph in cell.paragraphs:
                for run in paragraph.runs:
                    run.bold = True
                    run.font.size = Pt(7)
        for item in excluded_subset:
            cells = table.add_row().cells
            values = [
                item.get("imsi", "-"),
                item.get("imei", "-"),
                item.get("motivo", "-"),
                item.get("lista_blanca_fuente", "-"),
                item.get("primera_vez_visto", "-"),
                item.get("history_file", "-"),
            ]
            for idx, value in enumerate(values):
                cells[idx].text = str(value or "-")
                for paragraph in cells[idx].paragraphs:
                    for run in paragraph.runs:
                        run.font.size = Pt(6)
    for provider in ["CLARO", "MOVISTAR", "PERSONAL", "DESCONOCIDA", "OTROS"]:
        subset = [r for r in rows if str(r.get("prestataria") or "") == provider]
        if not subset:
            continue
        heading = doc.add_paragraph()
        hr = heading.add_run(f"{provider} ({len(subset)})")
        hr.bold = True
        hr.font.size = Pt(13)
        hr.font.color.rgb = RGBColor(0, 91, 143)
        table = doc.add_table(rows=1, cols=7)
        table.alignment = WD_TABLE_ALIGNMENT.LEFT
        table.autofit = True
        headers = ["IMSI", "IMEI", "Estado", "Modelo", "Primera vez", "Sistema", "History"]
        for idx, label in enumerate(headers):
            cell = table.rows[0].cells[idx]
            cell.text = label
            for paragraph in cell.paragraphs:
                for r in paragraph.runs:
                    r.bold = True
                    r.font.size = Pt(7)
        for item in subset[:500]:
            cells = table.add_row().cells
            values = [item.get("imsi"), item.get("imei"), item.get("estado"), item.get("modelo"), item.get("primera_vez_visto"), item.get("history_system"), item.get("history_file")]
            for idx, value in enumerate(values):
                cells[idx].text = str(value or "-")
                for paragraph in cells[idx].paragraphs:
                    for r in paragraph.runs:
                        r.font.size = Pt(7)
    doc.save(word_path)
    return {
        "ok": True,
        "total": summary["total"],
        "pre_whitelist_total": summary["pre_whitelist_total"],
        "raw_rows": summary["raw_rows"],
        "excluded_whitelist": summary["excluded_whitelist"],
        "excluded_whitelist_rows": len(summary.get("excluded_whitelist_rows") or []),
        "unique_imsi_before_whitelist": summary["pre_whitelist_imsi"],
        "unique_imei_before_whitelist": summary["pre_whitelist_imei"],
        "unique_imsi_net": summary["unique_imsi_selected"],
        "unique_imei_net": summary["unique_imei_selected"],
        "unique_imsi_raw": summary["unique_imsi_raw"],
        "unique_imei_raw": summary["unique_imei_raw"],
        "by_provider": summary["by_provider"],
        "whitelist": whitelist_summary,
        "csv_url": f"/outputs/{csv_path.name}",
        "html_url": f"/outputs/{html_path.name}",
        "word_url": f"/outputs/{word_path.name}",
    }


@app.post("/api/septier/reference/external-data/clean-report")
def api_external_data_clean_report(payload: SeptierExternalCleanReportRequest, user=Depends(_require_auth)):
    rows, summary = _external_clean_rows(payload.files, upload_ids=payload.upload_ids)
    stamp_dt = dt.datetime.now(dt.timezone(dt.timedelta(hours=-3)))
    stamp = stamp_dt.strftime("%Y%m%d_%H%M%S")
    base_name = f"data_externa_depurada_{stamp}"
    OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)
    csv_path = OUTPUTS_DIR / f"{base_name}.csv"
    html_path = OUTPUTS_DIR / f"{base_name}.html"
    word_path = OUTPUTS_DIR / f"{base_name}.docx"
    fields = [
        "prestataria", "imsi", "imei", "estado", "modelo", "match_kind",
        "history_system", "history_file", "history_model", "history_seen_at",
        "source_filename", "motivo", "hash_sha256",
    ]
    with csv_path.open("w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields, delimiter=";")
        writer.writeheader()
        writer.writerows([{field: row.get(field, "") for field in fields} for row in rows])

    def _table_for(provider: str) -> str:
        subset = [r for r in rows if str(r.get("prestataria") or "") == provider]
        if not subset:
            return "<p>Sin registros.</p>"
        body = "\n".join(
            "<tr>"
            f"<td>{html_lib.escape(str(r.get('imsi') or '-'))}</td>"
            f"<td>{html_lib.escape(str(r.get('imei') or '-'))}</td>"
            f"<td>{html_lib.escape(str(r.get('estado') or '-'))}</td>"
            f"<td>{html_lib.escape(str(r.get('modelo') or '-'))}</td>"
            f"<td>{html_lib.escape(str(r.get('match_kind') or '-'))}</td>"
            f"<td>{html_lib.escape(str(r.get('history_file') or '-'))}</td>"
            "</tr>"
            for r in subset
        )
        return f"<table><thead><tr><th>IMSI</th><th>IMEI</th><th>Estado</th><th>Modelo</th><th>Cruce</th><th>History</th></tr></thead><tbody>{body}</tbody></table>"

    provider_sections = "\n".join(
        f"<h2>{provider}</h2>{_table_for(provider)}"
        for provider in ["CLARO", "MOVISTAR", "PERSONAL", "DESCONOCIDA", "OTROS"]
    )
    files_text = ", ".join(f"{f.get('system', '').upper()}: {f.get('file', '')}" for f in summary.get("files", [])) or "Sin history seleccionado"
    html_path.write_text(f"""<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <title>AUDITORIA PRESTATARIAS</title>
  <style>
    body {{ font-family: Arial, sans-serif; color: #061327; margin: 28px; }}
    .letterhead {{ border: 1px solid #c8d4e3; border-radius: 8px; padding: 12px 14px; margin-bottom: 18px; background: #f8fbff; color: #003b68; font-weight: 700; line-height: 1.45; text-transform: uppercase; }}
    .letterhead .ministry {{ color: #005b8f; }}
    h1 {{ color: #003b68; text-transform: uppercase; }}
    h2 {{ color: #005b8f; margin-top: 24px; }}
    .grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin: 18px 0; }}
    .card {{ border: 1px solid #c8d4e3; border-radius: 8px; padding: 12px; background: #f8fbff; }}
    .card strong {{ display: block; font-size: 24px; color: #003b68; }}
    table {{ border-collapse: collapse; width: 100%; font-size: 12px; margin-bottom: 16px; }}
    th, td {{ border: 1px solid #d4deeb; padding: 7px; text-align: left; }}
    th {{ background: #eaf2fb; }}
  </style>
</head>
<body>
  <div class="letterhead">
    <div>DEPARTAMENTO DE TECNOLOGIAS ESPECIALES Y DESPLIEGUE TACTICO</div>
    <div>SUBSECRETARIA DE TECNOLOGIA APLICADA A LA SEGURIDAD</div>
    <div class="ministry">MINISTERIO DE SEGURIDAD Y JUSTICIA</div>
  </div>
  <h1>AUDITORIA PRESTATARIAS</h1>
  <p><strong>Regla:</strong> se excluyen coincidencias con Lista Blanca actual. La prestataria DESCONOCIDA se conserva como categoria propia.</p>
  <p><strong>Generado:</strong> {stamp_dt.strftime('%Y-%m-%d %H:%M:%S')} | <strong>Usuario:</strong> {html_lib.escape(str(user.get('full_name') or user.get('username') or '-'))}</p>
  <p><strong>History utilizado:</strong> {html_lib.escape(files_text)}</p>
  <p><strong>Cargas Data utilizadas:</strong> {html_lib.escape(', '.join(map(str, summary.get('upload_ids', []))) or 'Todas')}</p>
  <div class="grid">
    <div class="card"><strong>{summary['total']}</strong>Total depurado</div>
    <div class="card"><strong>{summary['by_provider'].get('CLARO', 0)}</strong>Claro</div>
    <div class="card"><strong>{summary['by_provider'].get('MOVISTAR', 0)}</strong>Movistar</div>
    <div class="card"><strong>{summary['by_provider'].get('PERSONAL', 0)}</strong>Personal</div>
  </div>
  <div class="grid">
    <div class="card"><strong>{summary['by_provider'].get('DESCONOCIDA', 0)}</strong>Desconocida</div>
    <div class="card"><strong>{summary['by_provider'].get('OTROS', 0)}</strong>Otros</div>
  </div>
  {provider_sections}
</body>
</html>""", encoding="utf-8")

    try:
        from docx import Document
        from docx.enum.section import WD_ORIENT
        from docx.enum.table import WD_TABLE_ALIGNMENT, WD_CELL_VERTICAL_ALIGNMENT
        from docx.oxml import OxmlElement
        from docx.oxml.ns import qn
        from docx.shared import Cm, Pt, RGBColor
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Falta dependencia python-docx para generar Word: {exc}")

    def _set_cell(cell, text: object, bold: bool = False, color: Optional[RGBColor] = None, size: int = 8):
        cell.text = ""
        paragraph = cell.paragraphs[0]
        paragraph.paragraph_format.space_after = Pt(0)
        run = paragraph.add_run(str(text or "-"))
        run.bold = bold
        run.font.size = Pt(size)
        if color:
            run.font.color.rgb = color
        cell.vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.CENTER

    def _shade_cell(cell, fill: str):
        tc_pr = cell._tc.get_or_add_tcPr()
        shd = OxmlElement("w:shd")
        shd.set(qn("w:fill"), fill)
        tc_pr.append(shd)

    def _set_table_widths(table, widths_cm: List[float]):
        table.autofit = False
        for row in table.rows:
            for idx, width in enumerate(widths_cm):
                if idx < len(row.cells):
                    row.cells[idx].width = Cm(width)

    doc = Document()
    section = doc.sections[0]
    section.orientation = WD_ORIENT.LANDSCAPE
    section.page_width, section.page_height = section.page_height, section.page_width
    section.top_margin = Cm(1.2)
    section.bottom_margin = Cm(1.2)
    section.left_margin = Cm(1.2)
    section.right_margin = Cm(1.2)

    letterhead_lines = [
        "DEPARTAMENTO DE TECNOLOGIAS ESPECIALES Y DESPLIEGUE TACTICO",
        "SUBSECRETARIA DE TECNOLOGIA APLICADA A LA SEGURIDAD",
        "MINISTERIO DE SEGURIDAD Y JUSTICIA",
    ]
    letterhead = doc.add_table(rows=1, cols=1)
    letterhead.alignment = WD_TABLE_ALIGNMENT.LEFT
    letterhead.autofit = False
    head_cell = letterhead.rows[0].cells[0]
    head_cell.width = Cm(25.5)
    _shade_cell(head_cell, "F8FBFF")
    head_cell.text = ""
    for idx, line in enumerate(letterhead_lines):
        p = head_cell.paragraphs[0] if idx == 0 else head_cell.add_paragraph()
        p.paragraph_format.space_after = Pt(0)
        run = p.add_run(line)
        run.bold = True
        run.font.size = Pt(10)
        run.font.color.rgb = RGBColor(0, 91, 143 if idx == 2 else 104)
    doc.add_paragraph()

    title = doc.add_paragraph()
    title.paragraph_format.space_after = Pt(10)
    title_run = title.add_run("AUDITORIA PRESTATARIAS")
    title_run.bold = True
    title_run.font.size = Pt(22)
    title_run.font.color.rgb = RGBColor(0, 59, 104)

    meta = doc.add_paragraph()
    meta.paragraph_format.space_after = Pt(6)
    r = meta.add_run("Regla: ")
    r.bold = True
    meta.add_run("se excluyen coincidencias con Lista Blanca actual. La prestataria DESCONOCIDA se conserva como categoria propia.")

    gen = doc.add_paragraph()
    gen.paragraph_format.space_after = Pt(6)
    r = gen.add_run("Generado: ")
    r.bold = True
    gen.add_run(stamp_dt.strftime("%Y-%m-%d %H:%M:%S"))
    gen.add_run(" | ")
    r = gen.add_run("Usuario: ")
    r.bold = True
    gen.add_run(str(user.get("full_name") or user.get("username") or "-"))

    hist = doc.add_paragraph()
    hist.paragraph_format.space_after = Pt(12)
    r = hist.add_run("History utilizado: ")
    r.bold = True
    hist.add_run(files_text)
    data_uploads = doc.add_paragraph()
    data_uploads.paragraph_format.space_after = Pt(12)
    r = data_uploads.add_run("Cargas Data utilizadas: ")
    r.bold = True
    data_uploads.add_run(", ".join(map(str, summary.get("upload_ids", []))) or "Todas")

    card_values = [
        ("Total depurado", summary["total"]),
        ("Claro", summary["by_provider"].get("CLARO", 0)),
        ("Movistar", summary["by_provider"].get("MOVISTAR", 0)),
        ("Personal", summary["by_provider"].get("PERSONAL", 0)),
        ("Desconocida", summary["by_provider"].get("DESCONOCIDA", 0)),
        ("Otros", summary["by_provider"].get("OTROS", 0)),
    ]
    cards = doc.add_table(rows=2, cols=3)
    cards.alignment = WD_TABLE_ALIGNMENT.LEFT
    cards.autofit = False
    for row in cards.rows:
        for cell in row.cells:
            cell.width = Cm(8.3)
            _shade_cell(cell, "F8FBFF")
    for idx, (label, value) in enumerate(card_values):
        cell = cards.rows[idx // 3].cells[idx % 3]
        cell.text = ""
        p = cell.paragraphs[0]
        p.paragraph_format.space_after = Pt(1)
        n = p.add_run(str(value))
        n.bold = True
        n.font.size = Pt(18)
        n.font.color.rgb = RGBColor(0, 59, 104)
        p.add_run("\n")
        t = p.add_run(label)
        t.font.size = Pt(10)
    doc.add_paragraph()

    for provider in ["CLARO", "MOVISTAR", "PERSONAL", "DESCONOCIDA", "OTROS"]:
        subset = [r for r in rows if str(r.get("prestataria") or "") == provider]
        heading = doc.add_paragraph()
        heading.paragraph_format.space_before = Pt(8)
        heading.paragraph_format.space_after = Pt(6)
        run = heading.add_run(provider)
        run.bold = True
        run.font.size = Pt(16)
        run.font.color.rgb = RGBColor(0, 91, 143)
        if not subset:
            doc.add_paragraph("Sin registros.")
            continue
        table = doc.add_table(rows=1, cols=6)
        table.alignment = WD_TABLE_ALIGNMENT.LEFT
        table.style = "Table Grid"
        widths = [Cm(3.2), Cm(3.2), Cm(4.6), Cm(8.6), Cm(3.0), Cm(4.0)]
        for idx, label in enumerate(["IMSI", "IMEI", "Estado", "Modelo", "Cruce", "History"]):
            cell = table.rows[0].cells[idx]
            _shade_cell(cell, "EAF2FB")
            cell.width = widths[idx]
            _set_cell(cell, label, bold=True, size=8)
        for r in subset:
            cells = table.add_row().cells
            values = [r.get("imsi"), r.get("imei"), r.get("estado"), r.get("modelo"), r.get("match_kind"), r.get("history_file")]
            for idx, value in enumerate(values):
                cells[idx].width = widths[idx]
                _set_cell(cells[idx], value, size=8)
        _set_table_widths(table, [3.2, 3.2, 4.6, 8.6, 3.0, 4.0])
    doc.save(word_path)

    return {
        "ok": True,
        "total": summary["total"],
        "by_provider": summary["by_provider"],
        "with_history": summary["with_history"],
        "selected_upload_ids": summary.get("upload_ids", []),
        "csv_url": f"/outputs/{csv_path.name}",
        "html_url": f"/outputs/{html_path.name}",
        "word_url": f"/outputs/{word_path.name}",
    }


@app.post("/api/septier/reference/history-schema/export")
def api_export_septier_technical_csv(payload: SeptierTechnicalCsvRequest, user=Depends(_require_auth)):
    import pandas as pd

    if not payload.files:
        raise HTTPException(status_code=400, detail="Selecciona al menos un history Guardian o Backpack")

    all_schema = list_septier_history_schema()
    requested_fields = {str(field or "").strip() for field in payload.fields if str(field or "").strip()}
    selected_schema = [item for item in all_schema if str(item.get("field") or "").strip() in requested_fields] if requested_fields else [item for item in all_schema if item.get("selected")]
    if not selected_schema:
        raise HTTPException(status_code=400, detail="No hay columnas seleccionadas en Referencias tecnicas Septier")

    output_columns = [str(item.get("field") or "").strip() for item in selected_schema if str(item.get("field") or "").strip()]
    frames = []
    missing_by_file: List[Dict[str, object]] = []
    excluded_whitelist = 0
    whitelist_keys = _whitelist_identity_set() if payload.exclude_whitelist else set()
    identity_memory = _septier_identity_memory() if payload.exclude_whitelist else None

    for file_item in payload.files:
        path = _septier_uploaded_file_path(file_item)
        df = _read_septier_csv_dataframe(path)
        column_index = {_norm_col(col): str(col) for col in df.columns}
        if payload.exclude_whitelist and not df.empty:
            imsi_col = _first_col(column_index, ["imsi / mac", "imsi_mac", "imsi", "mac", "imsi mac"])
            imei_col = _first_col(column_index, ["imei", "device_id", "device id"])
            if imsi_col or imei_col:
                keep_mask = []
                for _, row in df.iterrows():
                    resolved_imsi, resolved_imei = _resolve_septier_identity_values(
                        row.get(imsi_col, "") if imsi_col else "",
                        row.get(imei_col, "") if imei_col else "",
                        identity_memory,
                    )
                    is_whitelisted = _is_whitelisted_identity(
                        resolved_imsi,
                        resolved_imei,
                        whitelist_keys,
                    )
                    keep_mask.append(not is_whitelisted)
                    if is_whitelisted:
                        excluded_whitelist += 1
                df = df[keep_mask]
        out_data: Dict[str, object] = {}
        missing_fields: List[str] = []

        for schema_item in selected_schema:
            field = str(schema_item.get("field") or "").strip()
            if not field:
                continue
            source_col = _first_col(column_index, _history_schema_column_candidates(schema_item))
            if source_col:
                out_data[field] = df[source_col].astype(str)
            else:
                out_data[field] = [""] * len(df)
                missing_fields.append(field)

        frames.append(pd.DataFrame(out_data, columns=output_columns))
        if missing_fields:
            missing_by_file.append(
                {
                    "system": file_item.system,
                    "file": path.name,
                    "missing_fields": missing_fields,
                }
            )

    merged = pd.concat(frames, ignore_index=True) if frames else pd.DataFrame(columns=output_columns)
    OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)
    out_name = f"septier_csv_tecnico_{dt.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    out_path = OUTPUTS_DIR / out_name
    merged.to_csv(out_path, index=False, encoding="utf-8-sig")
    return {
        "ok": True,
        "total_rows": int(len(merged)),
        "columns": output_columns,
        "missing": missing_by_file,
        "excluded_whitelist": excluded_whitelist,
        "file": out_name,
        "download_url": _skyeye_output_url(out_path),
    }


def _septier_search_items(q: str) -> List[Dict[str, object]]:
    if not q.strip():
        return []
    results = search_septier_detections(q)
    history_rows = get_septier_identity_history()
    imei_counts_by_imsi: Dict[str, Counter[str]] = {}
    imsi_counts_by_imei: Dict[str, Counter[str]] = {}
    for row in history_rows:
        imsi_key = _id15(row.get("imsi_mac"))
        imei_key = _id15(row.get("imei"))
        if len(imsi_key) == 15 and len(imei_key) == 15:
            imei_counts_by_imsi.setdefault(imsi_key, Counter())[imei_key] += 1
            imsi_counts_by_imei.setdefault(imei_key, Counter())[imsi_key] += 1

    lookup_ids = set()
    enriched_base: List[Dict[str, object]] = []
    for result in results:
        item = dict(result)
        imsi_key = _id15(item.get("imsi_mac"))
        imei_key = _id15(item.get("imei"))
        associated_imei = ""
        associated_imsi = ""
        associated_imeis = []
        associated_imsis = []
        if len(imsi_key) == 15 and imei_counts_by_imsi.get(imsi_key):
            associated_imei = imei_counts_by_imsi[imsi_key].most_common(1)[0][0]
            associated_imeis = [value for value, _count in imei_counts_by_imsi[imsi_key].most_common()]
        if len(imei_key) == 15 and imsi_counts_by_imei.get(imei_key):
            associated_imsi = imsi_counts_by_imei[imei_key].most_common(1)[0][0]
            associated_imsis = [value for value, _count in imsi_counts_by_imei[imei_key].most_common()]
        item["associated_imei_by_history"] = associated_imei
        item["associated_imsi_by_history"] = associated_imsi
        item["associated_imeis_by_history"] = associated_imeis
        item["associated_imsis_by_history"] = associated_imsis
        mutation_notes = []
        if len(imsi_key) == 15 and imei_key and associated_imeis and imei_key not in associated_imeis:
            mutation_notes.append(f"Nuevo IMEI para IMSI conocido. IMEI previos: {', '.join(associated_imeis)}")
        if len(imei_key) == 15 and imsi_key and associated_imsis and imsi_key not in associated_imsis:
            mutation_notes.append(f"Nuevo IMSI para IMEI conocido. IMSI previos: {', '.join(associated_imsis)}")
        if len(associated_imeis) > 1:
            mutation_notes.append(f"IMSI con multiples IMEI historicos: {', '.join(associated_imeis)}")
        if len(associated_imsis) > 1:
            mutation_notes.append(f"IMEI con multiples IMSI historicos: {', '.join(associated_imsis)}")
        item["mutation_notes"] = mutation_notes
        candidate_sources = [
            ("IMSI", item.get("imsi_mac")),
            ("IMEI", item.get("imei")),
            ("IMEI asociado por historico", associated_imei),
            ("IMSI asociado por historico", associated_imsi),
        ]
        candidate_keys = set()
        source_keys = []
        for source, value in candidate_sources:
            keys = _identity_keys(value)
            if not keys:
                continue
            candidate_keys.update(keys)
            source_keys.append((source, keys))
        item["_whitelist_candidate_keys"] = sorted(candidate_keys)
        item["_whitelist_source_keys"] = source_keys
        lookup_ids.update(candidate_keys)
        enriched_base.append(item)

    whitelist_rows = whitelist_matches_for_ids(sorted(lookup_ids))
    whitelist_items = list_whitelist()
    normalized_whitelist_matches: Dict[str, List[Dict[str, object]]] = defaultdict(list)
    normalized_device_ids = set()
    if lookup_ids:
        for whitelist_item in whitelist_items:
            device_id = str(whitelist_item.get("device_id") or "").strip()
            if not device_id:
                continue
            wl_keys = _identity_keys(device_id)
            if wl_keys & lookup_ids:
                normalized_device_ids.add(device_id)
                normalized_whitelist_matches[device_id].append(whitelist_item)
    if normalized_device_ids:
        whitelist_rows.extend(whitelist_matches_for_ids(sorted(normalized_device_ids)))

    matches_by_device: Dict[str, List[Dict[str, object]]] = defaultdict(list)
    for match in whitelist_rows:
        device_id = str(match.get("device_id") or "").strip()
        if device_id:
            matches_by_device[device_id].append(match)
    for device_id, normalized_rows in normalized_whitelist_matches.items():
        if matches_by_device.get(device_id):
            continue
        matches_by_device[device_id].extend(normalized_rows)

    enriched_items = []
    for item in enriched_base:
        keys = item.pop("_whitelist_candidate_keys", [])
        source_keys = item.pop("_whitelist_source_keys", [])
        matches = []
        candidate_key_set = set(keys)
        for device_id, rows in matches_by_device.items():
            device_keys = _identity_keys(device_id)
            if not (device_keys & candidate_key_set):
                continue
            source = "IDENTIDAD"
            for source_name, source_key_set in source_keys:
                if device_keys & source_key_set:
                    source = source_name
                    break
            for match in rows:
                matches.append({
                    "device_id": match.get("device_id"),
                    "device_type": match.get("device_type") or "",
                    "description": match.get("description") or "",
                    "upload_id": match.get("upload_id"),
                    "original_filename": match.get("original_filename") or "Carga manual / sin archivo",
                    "match_by": source,
                    "excludable": True,
                })
        deduped = []
        seen = set()
        for match in matches:
            sig = (match.get("device_id"), match.get("upload_id"), match.get("match_by"))
            if sig in seen:
                continue
            seen.add(sig)
            deduped.append(match)
        item["whitelist_status"] = "AUTORIZADO" if deduped else "NO AUTORIZADO"
        item["whitelist_matches"] = deduped
        enriched_items.append(item)

    return enriched_items


@app.get("/api/septier/search")
def septier_search(q: str = "", user=Depends(_require_auth)):
    enriched_items = _septier_search_items(q)
    return {"items": enriched_items}


@app.post("/api/septier/search/report")
def septier_search_report(payload: SeptierSearchReportRequest, user=Depends(_require_auth)):
    query = payload.q.strip()
    if not query:
        raise HTTPException(status_code=400, detail="Indica IMSI, IMEI, MAC, modelo u operacion para exportar.")
    items = _septier_search_items(query)
    if not items:
        raise HTTPException(status_code=404, detail="No hay resultados para exportar.")

    stamp_dt = dt.datetime.now()
    stamp = stamp_dt.strftime("%Y%m%d_%H%M%S")
    safe_query = re.sub(r"[^A-Za-z0-9_.-]+", "_", query).strip("_")[:60] or "busqueda"
    out_dir = OUTPUTS_DIR / "busquedas_dispositivos"
    out_dir.mkdir(parents=True, exist_ok=True)
    base_name = f"busqueda_dispositivo_{safe_query}_{stamp}"
    html_path = out_dir / f"{base_name}.html"
    word_path = out_dir / f"{base_name}.docx"

    def e(value: object) -> str:
        return html_lib.escape(str(value if value is not None else ""))

    authorized = sum(1 for item in items if str(item.get("whitelist_status") or "") == "AUTORIZADO")
    not_authorized = len(items) - authorized
    unique_imsi = sorted({_id15(item.get("imsi_mac")) for item in items if _id15(item.get("imsi_mac"))})
    unique_imei = sorted({_id15(item.get("imei")) for item in items if _id15(item.get("imei"))})
    source_counts = Counter(str(item.get("source") or "desconocido").upper() for item in items)
    source_text = " | ".join(f"{k}: {v}" for k, v in sorted(source_counts.items())) or "-"

    rows_html = []
    for item in items:
        matches = item.get("whitelist_matches") or []
        if matches:
            match_text = "<br>".join(
                f"{e(match.get('match_by') or 'IDENTIDAD')}: {e(match.get('device_id') or '-')} | {e(match.get('original_filename') or 'Carga manual / sin archivo')}"
                + (f" | {e(match.get('description'))}" if match.get("description") else "")
                for match in matches if isinstance(match, dict)
            )
        else:
            match_text = "Sin coincidencia con Lista Blanca actual por IMSI/IMEI."
        mutation_text = "<br>".join(e(note) for note in (item.get("mutation_notes") or [])) or "-"
        rows_html.append(
            "<tr>"
            f"<td>{e(item.get('source') or '-').upper()}</td>"
            f"<td>{e(item.get('imsi_mac') or '-')}</td>"
            f"<td>{e(item.get('imei') or '-')}</td>"
            f"<td>{e(item.get('associated_imei_by_history') or '-')}</td>"
            f"<td>{e(item.get('associated_imsi_by_history') or '-')}</td>"
            f"<td>{mutation_text}</td>"
            f"<td>{e(item.get('whitelist_status') or 'NO AUTORIZADO')}</td>"
            f"<td>{match_text}</td>"
            f"<td>{e(item.get('model') or '-')}</td>"
            f"<td>{e(item.get('operation') or '-')}</td>"
            f"<td>{e(str(item.get('last_update') or '-').replace('T', ' '))}</td>"
            f"<td>{e(item.get('archivo_origen') or '-')}</td>"
            f"<td>{e(item.get('lat') or '-')} / {e(item.get('lon') or '-')}</td>"
            "</tr>"
        )

    html = f"""<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <title>Busqueda de dispositivo Septier</title>
  <style>
    body {{ font-family: Arial, sans-serif; color: #001b33; margin: 24px; }}
    h1, h2 {{ color: #00416b; }}
    .card {{ border: 1px solid #c9d8e8; border-radius: 6px; padding: 12px; margin: 12px 0; }}
    .grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin: 16px 0; }}
    .metric {{ border: 1px solid #c9d8e8; border-radius: 6px; padding: 12px; background: #f6f9fc; }}
    .metric strong {{ display: block; color: #00416b; font-size: 26px; }}
    table {{ border-collapse: collapse; width: 100%; font-size: 12px; }}
    th, td {{ border: 1px solid #c9d8e8; padding: 6px; vertical-align: top; }}
    th {{ background: #e7f0f8; text-align: left; }}
    .rule {{ background: #f6f9fc; border-left: 4px solid #0078d4; padding: 10px 12px; }}
  </style>
</head>
<body>
  <div class="card"><strong>DEPARTAMENTO DE TECNOLOGIAS ESPECIALES Y DESPLIEGUE TACTICO</strong><br>
  SUBSECRETARIA DE TECNOLOGIA APLICADA A LA SEGURIDAD<br>
  MINISTERIO DE SEGURIDAD Y JUSTICIA</div>
  <h1>Busqueda de Dispositivo Septier</h1>
  <p><strong>Consulta:</strong> {e(query)} | <strong>Generado:</strong> {stamp_dt.strftime('%Y-%m-%d %H:%M:%S')} | <strong>Usuario:</strong> {e(user.get('full_name') or user.get('username') or '-')}</p>
  <div class="rule"><strong>Regla aplicada:</strong> el resultado se cruza con Lista Blanca actual por IMSI e IMEI. Si falta IMEI/IMSI en la fila, se informa la asociacion frecuente encontrada en el historico para sostener el cruce. Data Externa no autoriza ni excluye.</div>
  <div class="grid">
    <div class="metric"><strong>{len(items)}</strong>Resultados</div>
    <div class="metric"><strong>{len(unique_imsi)}</strong>IMSI unicos</div>
    <div class="metric"><strong>{len(unique_imei)}</strong>IMEI unicos</div>
    <div class="metric"><strong>{authorized}</strong>Coinciden Lista Blanca</div>
    <div class="metric"><strong>{not_authorized}</strong>No coinciden</div>
    <div class="metric"><strong>{e(source_text)}</strong>Fuente</div>
  </div>
  <h2>Detalle de resultados</h2>
  <table>
    <thead><tr><th>Sistema</th><th>IMSI / MAC</th><th>IMEI</th><th>IMEI asociado</th><th>IMSI asociado</th><th>Mutacion / memoria</th><th>Lista Blanca</th><th>Fuente / coincidencia</th><th>Modelo</th><th>Operacion</th><th>Visto</th><th>Archivo</th><th>GPS</th></tr></thead>
    <tbody>{''.join(rows_html)}</tbody>
  </table>
</body>
</html>"""
    html_path.write_text(html, encoding="utf-8")

    try:
        from docx import Document
        from docx.enum.section import WD_ORIENT
        from docx.shared import Cm, Pt, RGBColor
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Falta dependencia python-docx para generar Word: {exc}")

    doc = Document()
    section = doc.sections[0]
    section.orientation = WD_ORIENT.LANDSCAPE
    section.page_width, section.page_height = section.page_height, section.page_width
    section.left_margin = Cm(0.9)
    section.right_margin = Cm(0.9)
    section.top_margin = Cm(0.9)
    section.bottom_margin = Cm(0.9)
    styles = doc.styles
    styles["Normal"].font.name = "Arial"
    styles["Normal"].font.size = Pt(8)
    title = doc.add_heading("Busqueda de Dispositivo Septier", level=1)
    title.runs[0].font.color.rgb = RGBColor(0, 65, 107)
    doc.add_paragraph("DEPARTAMENTO DE TECNOLOGIAS ESPECIALES Y DESPLIEGUE TACTICO\nSUBSECRETARIA DE TECNOLOGIA APLICADA A LA SEGURIDAD\nMINISTERIO DE SEGURIDAD Y JUSTICIA")
    doc.add_paragraph(f"Consulta: {query} | Generado: {stamp_dt.strftime('%Y-%m-%d %H:%M:%S')} | Usuario: {user.get('full_name') or user.get('username') or '-'}")
    doc.add_paragraph("Regla aplicada: el resultado se cruza con Lista Blanca actual por IMSI e IMEI. Si falta IMEI/IMSI en la fila, se informa la asociacion frecuente encontrada en el historico para sostener el cruce. Data Externa no autoriza ni excluye.")
    metrics = doc.add_table(rows=2, cols=6)
    labels = ["Resultados", "IMSI unicos", "IMEI unicos", "Coinciden Lista Blanca", "No coinciden", "Fuente"]
    values = [len(items), len(unique_imsi), len(unique_imei), authorized, not_authorized, source_text]
    for idx, label in enumerate(labels):
        metrics.cell(0, idx).text = str(values[idx])
        metrics.cell(1, idx).text = label
    doc.add_heading("Detalle de resultados", level=2)
    headers = ["Sistema", "IMSI/MAC", "IMEI", "IMEI asociado", "IMSI asociado", "Mutacion / memoria", "Lista Blanca", "Coincidencia / fuente", "Modelo", "Operacion", "Visto", "Archivo", "GPS"]
    table = doc.add_table(rows=1, cols=len(headers))
    table.style = "Table Grid"
    for idx, header in enumerate(headers):
        table.rows[0].cells[idx].text = header
    for item in items[:500]:
        cells = table.add_row().cells
        matches = item.get("whitelist_matches") or []
        match_texts = []
        for match in matches:
            if not isinstance(match, dict):
                continue
            text = f"{match.get('match_by') or 'IDENTIDAD'}: {match.get('device_id') or '-'} | {match.get('original_filename') or 'Carga manual / sin archivo'}"
            if match.get("description"):
                text += f" | {match.get('description')}"
            match_texts.append(text)
        values = [
            str(item.get("source") or "-").upper(),
            item.get("imsi_mac") or "-",
            item.get("imei") or "-",
            item.get("associated_imei_by_history") or "-",
            item.get("associated_imsi_by_history") or "-",
            "\n".join(str(note) for note in (item.get("mutation_notes") or [])) or "-",
            item.get("whitelist_status") or "NO AUTORIZADO",
            "\n".join(match_texts) if match_texts else "Sin coincidencia con Lista Blanca actual por IMSI/IMEI.",
            item.get("model") or "-",
            item.get("operation") or "-",
            str(item.get("last_update") or "-").replace("T", " "),
            item.get("archivo_origen") or "-",
            f"{item.get('lat') or '-'} / {item.get('lon') or '-'}",
        ]
        for idx, value in enumerate(values):
            cells[idx].text = str(value)
    if len(items) > 500:
        doc.add_paragraph(f"Nota: el Word incluye los primeros 500 resultados para mantener legibilidad. El HTML conserva el detalle completo de {len(items)} resultado(s).")
    doc.save(word_path)
    digest = hashlib.sha256(word_path.read_bytes()).hexdigest()
    return {
        "ok": True,
        "total": len(items),
        "authorized": authorized,
        "not_authorized": not_authorized,
        "unique_imsi": len(unique_imsi),
        "unique_imei": len(unique_imei),
        "html_url": _skyeye_output_url(html_path),
        "word_url": _skyeye_output_url(word_path),
        "sha256": digest,
    }


@app.get("/api/septier/objectives")
def api_list_septier_objectives(
    q: str = "",
    status_filter: str = "",
    limit: int = 200,
    user=Depends(_require_auth),
):
    return {"items": list_septier_objectives(q=q, status=status_filter, limit=limit)}


@app.post("/api/septier/objectives")
def api_create_septier_objective(payload: SeptierObjectiveRequest, user=Depends(_require_edit)):
    if not any([payload.person_name.strip(), payload.phone.strip(), payload.imsi.strip(), payload.imei.strip()]):
        raise HTTPException(status_code=400, detail="Carga al menos nombre, telefono, IMSI o IMEI")
    item = create_septier_objective(payload.dict(), username=str(user.get("username", "")))
    return {"ok": True, "item": item}


@app.patch("/api/septier/objectives/{objective_id}/status")
def api_update_septier_objective_status(
    objective_id: int,
    payload: SeptierObjectiveStatusRequest,
    user=Depends(_require_edit),
):
    item = update_septier_objective_status(objective_id, payload.status, username=str(user.get("username", "")))
    if item is None:
        raise HTTPException(status_code=404, detail="Objetivo no encontrado")
    return {"ok": True, "item": item}


@app.delete("/api/septier/objectives/{objective_id}", status_code=status.HTTP_204_NO_CONTENT)
def api_delete_septier_objective(objective_id: int, user=Depends(_require_edit)):
    delete_septier_objective(objective_id)
    return


def _clean_history_text(value: object) -> str:
    text = str(value or "").strip()
    if text.lower() in {"nan", "none", "nat"}:
        return ""
    if text.endswith(".0") and re.fullmatch(r"\d+\.0", text):
        text = text[:-2]
    return text


def _read_history_dataframe_from_bytes(raw: bytes):
    import pandas as pd
    from io import BytesIO

    last_error: Optional[Exception] = None
    for encoding in ("utf-8-sig", "latin-1"):
        try:
            df = pd.read_csv(BytesIO(raw), sep=None, engine="python", encoding=encoding, dtype=str)
            return clean_columns(df).fillna("")
        except Exception as exc:
            last_error = exc
    raise HTTPException(status_code=400, detail=f"No se pudo leer el CSV history: {last_error}")


def _parse_objective_history_rows(
    raw: bytes,
    objective_id: int,
    upload_id: int,
    filename: str,
    file_hash: str,
    location: str = "",
) -> List[Dict[str, object]]:
    df = _read_history_dataframe_from_bytes(raw)
    cols = {_norm_col(c): c for c in df.columns}

    def col(names: List[str]) -> str:
        return _first_col(cols, names)

    imsi_col = col(["imsi / mac", "imsi_mac", "imsi", "mac", "imsi mac"])
    imei_col = col(["imei", "device_id", "device id"])
    model_col = col(["modelo", "model", "imei name", "device model"])
    operation_col = col(["op / evento", "operation", "operacion", "evento", "event"])
    lac_col = col(["orig lac", "orig_lac", "original lac", "lac", "lac_origen"])
    cell_col = col(["cell id", "cell_id", "cid", "cell", "id celda", "id_de_celda", "eci", "enb"])
    last_col = col(["hora", "last_update", "last update", "event time", "timestamp", "fecha", "time", "datetime"])
    event_col = col(["event_type", "event type", "tipo evento", "evento"])
    lat_col = col(["lat", "latitude", "latitud", "y", "gps lat", "gps latitude"])
    lon_col = col(["lon", "lng", "long", "longitude", "longitud", "x", "gps lon", "gps longitude"])
    gps_col = col(["gps", "coordenadas", "coordinates", "coord", "location", "ubicacion"])

    rows: List[Dict[str, object]] = []
    for _, r in df.iterrows():
        imsi = _clean_history_text(r.get(imsi_col, "")) if imsi_col else ""
        imei = _clean_history_text(r.get(imei_col, "")) if imei_col else ""
        lac = _clean_history_text(r.get(lac_col, "")) if lac_col else ""
        cell_id = _clean_history_text(r.get(cell_col, "")) if cell_col else ""
        if not any([imsi, imei, lac, cell_id]):
            continue
        rows.append({
            "objective_id": objective_id,
            "upload_id": upload_id,
            "imsi_mac": imsi,
            "imei": imei,
            "model": _clean_history_text(r.get(model_col, "")) if model_col else "",
            "operation": _clean_history_text(r.get(operation_col, "")) if operation_col else "",
            "orig_lac": lac,
            "cell_id": cell_id,
            "last_update": _clean_history_text(r.get(last_col, "")) if last_col else "",
            "event_type": _clean_history_text(r.get(event_col, "")) if event_col else "",
            "source": "objetivo",
            "archivo_origen": filename,
            "hash_sha256": file_hash,
            "location": location.strip(),
            "lat_text": _clean_history_text(r.get(lat_col, "")) if lat_col else "",
            "lon_text": _clean_history_text(r.get(lon_col, "")) if lon_col else "",
            "gps_text": _clean_history_text(r.get(gps_col, "")) if gps_col else "",
        })
    return rows


def _objective_history_dir(objective_id: int) -> Path:
    path = OBJECTIVE_HISTORY_DIR / f"objetivo_{int(objective_id)}"
    path.mkdir(parents=True, exist_ok=True)
    return path


OBJECTIVE_IMAGE_TYPES = {
    "foto_1": "Foto 1",
    "foto_2": "Foto 2",
    "captura_geomatrix": "Captura Geomatrix",
    "evidencia_operativa": "Evidencia operativa",
}


def _clean_objective_image_type(value: object) -> str:
    key = re.sub(r"[^a-z0-9_]+", "_", str(value or "").strip().lower()).strip("_")
    return key if key in OBJECTIVE_IMAGE_TYPES else "evidencia_operativa"


def _objective_evidence_dir(objective_id: int) -> Path:
    path = OUTPUTS_DIR / "objective_evidence" / f"objetivo_{int(objective_id)}"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _objective_csv_attachment_dir(objective_id: int) -> Path:
    path = OUTPUTS_DIR / "objective_csv_attachments" / f"objetivo_{int(objective_id)}"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _objective_image_url(item: Dict[str, Any]) -> str:
    return _skyeye_output_url(item.get("stored_path"))


def _objective_csv_attachment_url(item: Dict[str, Any]) -> str:
    return _skyeye_output_url(item.get("stored_path"))


def _read_objective_csv_attachment_dataframe(raw: bytes):
    import pandas as pd
    from io import BytesIO

    last_error: Optional[Exception] = None
    for encoding in ("utf-8-sig", "latin-1"):
        try:
            return pd.read_csv(BytesIO(raw), sep=None, engine="python", encoding=encoding, dtype=str).fillna("")
        except Exception as exc:
            last_error = exc
    raise HTTPException(status_code=400, detail=f"No se pudo leer el CSV tecnico del objetivo: {last_error}")


def _objective_csv_columns(item: Dict[str, Any]) -> List[str]:
    try:
        parsed = json.loads(str(item.get("columns_json") or "[]"))
        if isinstance(parsed, list):
            return [str(col) for col in parsed]
    except Exception:
        return []
    return []


def _serialize_objective_csv_attachment(item: Dict[str, Any]) -> Dict[str, Any]:
    path = Path(str(item.get("stored_path") or ""))
    return {
        **item,
        "columns": _objective_csv_columns(item),
        "url": _objective_csv_attachment_url(item),
        "exists": bool(path.exists() and path.is_file()),
    }


def _objective_image_data_uri(item: Dict[str, Any]) -> str:
    path = Path(str(item.get("stored_path") or ""))
    if not path.exists() or not path.is_file():
        return ""
    content_type = str(item.get("content_type") or "").strip() or "image/jpeg"
    try:
        return f"data:{content_type};base64,{base64.b64encode(path.read_bytes()).decode('ascii')}"
    except Exception:
        return ""


def _objective_identity_match(row: Dict[str, Any], objective: Dict[str, Any]) -> bool:
    objective_imsi = _id15(objective.get("imsi"))
    row_imsi = _id15(row.get("imsi_mac"))
    return bool(objective_imsi and row_imsi and objective_imsi == row_imsi)


def _network_candidates_from_imsi(imsi_value: object) -> List[Dict[str, object]]:
    imsi = _digits_only(imsi_value)
    if len(imsi) < 5:
        return []
    mcc = imsi[:3]
    mncs = []
    if len(imsi) >= 5:
        mncs.append(imsi[3:5])
    if len(imsi) >= 6:
        mncs.append(imsi[3:6])
    mncs.extend([m.lstrip("0") for m in list(mncs) if m.lstrip("0")])
    out: List[Dict[str, object]] = []
    seen = set()
    for mnc in mncs:
        for item in list_septier_network_refs(mcc=mcc, mnc=mnc, limit=20):
            key = (item.get("mcc"), item.get("mnc"), item.get("network_name"), item.get("source_type"))
            if key in seen:
                continue
            seen.add(key)
            out.append(item)
    return out


def _objective_cross_summary(objective: Dict[str, Any]) -> Dict[str, object]:
    objective_id = int(objective.get("id") or 0)
    rows = list_septier_objective_history_rows(objective_id, limit=20000)
    uploads = list_septier_objective_history_uploads(objective_id, limit=100)

    identity_counter: Counter = Counter()
    identity_rows: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
    lac_cell_counter: Counter = Counter()
    times = []
    target_times = []
    files = set()
    target_count = 0

    for row in rows:
        imsi = str(row.get("imsi_mac") or "").strip()
        imei = str(row.get("imei") or "").strip()
        key = (imsi or "-", imei or "-")
        identity_counter[key] += 1
        identity_rows[key].append(row)
        if _objective_identity_match(row, objective):
            target_count += 1
            target_when = str(row.get("last_update") or "").strip()
            if target_when:
                target_times.append(target_when)
        lac = str(row.get("orig_lac") or "").strip()
        cell = str(row.get("cell_id") or "").strip()
        if lac or cell:
            lac_cell_counter[(lac or "-", cell or "-")] += 1
        when = str(row.get("last_update") or "").strip()
        if when:
            times.append(when)
        source_file = str(row.get("archivo_origen") or "").strip()
        if source_file:
            files.add(source_file)

    ranking = []
    for (imsi, imei), total in identity_counter.most_common(20):
        related = identity_rows[(imsi, imei)]
        related_times = sorted([str(r.get("last_update") or "").strip() for r in related if str(r.get("last_update") or "").strip()])
        ranking.append({
            "imsi": "" if imsi == "-" else imsi,
            "imei": "" if imei == "-" else imei,
            "total": total,
            "first_detection": related_times[0] if related_times else "",
            "last_detection": related_times[-1] if related_times else "",
            "files": sorted({str(r.get("archivo_origen") or "").strip() for r in related if str(r.get("archivo_origen") or "").strip()}),
            "is_objective": any(_objective_identity_match(r, objective) for r in related),
        })

    lac_cell_ranking = []
    for (lac, cell_id), total in lac_cell_counter.most_common(20):
        tower_matches = []
        if lac != "-" and cell_id != "-":
            tower_matches = list_tower_catalog(lac=lac, cell_id=cell_id, limit=5)
        elif lac != "-":
            tower_matches = list_tower_catalog(lac=lac, limit=5)
        lac_cell_ranking.append({
            "lac": "" if lac == "-" else lac,
            "cell_id": "" if cell_id == "-" else cell_id,
            "total": total,
            "tower_matches": tower_matches,
        })

    networks = []
    network_seen = set()
    imsi_values = [objective.get("imsi")]
    imsi_values.extend([row.get("imsi_mac") for row in rows[:500]])
    for imsi in imsi_values:
        for ref in _network_candidates_from_imsi(imsi):
            key = (ref.get("mcc"), ref.get("mnc"), ref.get("network_name"), ref.get("source_type"))
            if key in network_seen:
                continue
            network_seen.add(key)
            networks.append(ref)

    sorted_times = sorted(times)
    sorted_target_times = sorted(target_times)
    notes = []
    objective_imsi = _id15(objective.get("imsi"))
    if not rows:
        notes.append("No hay history especifico cargado para este objetivo.")
    elif not objective_imsi:
        notes.append("El objetivo no tiene IMSI valido de 15 digitos cargado; no se puede ejecutar el cruce principal.")
    elif target_count == 0:
        notes.append(f"No se encontro el IMSI objetivo {objective_imsi} en la columna IMSI/MAC del history asociado.")
    return {
        "objective_id": objective_id,
        "objective_imsi": objective_imsi,
        "uploads": uploads,
        "total_rows": len(rows),
        "target_rows": target_count,
        "first_detection": sorted_target_times[0] if sorted_target_times else "",
        "last_detection": sorted_target_times[-1] if sorted_target_times else "",
        "history_first_detection": sorted_times[0] if sorted_times else "",
        "history_last_detection": sorted_times[-1] if sorted_times else "",
        "files": sorted(files),
        "ranking": ranking,
        "lac_cell_ranking": lac_cell_ranking,
        "networks": networks[:20],
        "notes": notes,
    }


@app.post("/api/septier/objectives/{objective_id}/history/upload")
async def api_upload_septier_objective_history(
    objective_id: int,
    location: str = Form(""),
    files: List[UploadFile] = File(...),
    user=Depends(_require_edit),
):
    objective = get_septier_objective(objective_id)
    if objective is None:
        raise HTTPException(status_code=404, detail="Objetivo no encontrado")

    saved = []
    inserted_total = 0
    target_dir = _objective_history_dir(objective_id)
    for up in files:
        if not up.filename:
            continue
        safe_name = Path(up.filename).name
        if not safe_name.lower().endswith(".csv"):
            continue
        raw = await up.read()
        _scan_uploaded_bytes(raw, up.filename or "archivo", "upload", user)
        file_hash = hashlib.sha256(raw).hexdigest()
        stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
        stem = re.sub(r"[^A-Za-z0-9._-]+", "_", Path(safe_name).stem).strip("._") or "history"
        final_target = target_dir / f"objetivo_{objective_id}_{stamp}_{stem}.csv"
        i = 1
        while final_target.exists():
            final_target = target_dir / f"objetivo_{objective_id}_{stamp}_{stem}_{i}.csv"
            i += 1
        final_target.write_bytes(raw)

        upload = insert_septier_objective_history_upload({
            "objective_id": objective_id,
            "original_filename": safe_name,
            "stored_filename": final_target.name,
            "stored_path": str(final_target),
            "rows_count": 0,
            "hash_sha256": file_hash,
            "uploaded_by": str(user.get("username") or ""),
        })
        rows = _parse_objective_history_rows(raw, objective_id, int(upload.get("id") or 0), final_target.name, file_hash, location=location)
        insert_septier_objective_history_rows(rows)
        update_septier_objective_history_upload_rows(int(upload.get("id") or 0), len(rows))
        inserted_total += len(rows)
        saved.append({"original": safe_name, "saved_as": final_target.name, "inserted": len(rows), "sha256": file_hash})

    if not saved:
        raise HTTPException(status_code=400, detail="No se subieron CSV history validos")
    return {"ok": True, "objective_id": objective_id, "saved": saved, "inserted_total": inserted_total}


@app.get("/api/septier/objectives/{objective_id}/cross")
def api_cross_septier_objective(objective_id: int, user=Depends(_require_auth)):
    objective = get_septier_objective(objective_id)
    if objective is None:
        raise HTTPException(status_code=404, detail="Objetivo no encontrado")
    return _objective_cross_summary(objective)


@app.post("/api/septier/objectives/{objective_id}/images/upload")
async def api_upload_septier_objective_images(
    objective_id: int,
    image_type: str = Form("evidencia_operativa"),
    files: List[UploadFile] = File(...),
    user=Depends(_require_edit),
):
    objective = get_septier_objective(objective_id)
    if objective is None:
        raise HTTPException(status_code=404, detail="Objetivo no encontrado")

    clean_type = _clean_objective_image_type(image_type)
    target_dir = _objective_evidence_dir(objective_id)
    saved = []
    for up in files:
        if not up.filename:
            continue
        safe_name = Path(up.filename).name
        content_type = str(up.content_type or "").strip().lower()
        suffix = Path(safe_name).suffix.lower()
        if not (content_type.startswith("image/") or suffix in {".jpg", ".jpeg", ".png", ".webp"}):
            continue
        raw = await up.read()
        _scan_uploaded_bytes(raw, up.filename or "archivo", "upload", user)
        if not raw:
            continue
        file_hash = hashlib.sha256(raw).hexdigest()
        stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
        stem = re.sub(r"[^A-Za-z0-9._-]+", "_", Path(safe_name).stem).strip("._") or clean_type
        final_target = target_dir / f"{clean_type}_{stamp}_{stem}{suffix or '.jpg'}"
        i = 1
        while final_target.exists():
            final_target = target_dir / f"{clean_type}_{stamp}_{stem}_{i}{suffix or '.jpg'}"
            i += 1
        final_target.write_bytes(raw)
        row = insert_septier_objective_image({
            "objective_id": objective_id,
            "image_type": clean_type,
            "original_filename": safe_name,
            "stored_filename": final_target.name,
            "stored_path": str(final_target),
            "content_type": content_type or "image/jpeg",
            "hash_sha256": file_hash,
            "uploaded_by": str(user.get("username") or ""),
        })
        saved.append({**row, "url": _objective_image_url(row), "type_label": OBJECTIVE_IMAGE_TYPES.get(clean_type, clean_type)})

    if not saved:
        raise HTTPException(status_code=400, detail="No se subieron imagenes validas")
    return {"ok": True, "objective_id": objective_id, "saved": saved, "count": len(saved)}


@app.get("/api/septier/objectives/{objective_id}/images")
def api_list_septier_objective_images(objective_id: int, user=Depends(_require_auth)):
    objective = get_septier_objective(objective_id)
    if objective is None:
        raise HTTPException(status_code=404, detail="Objetivo no encontrado")
    items = []
    for item in list_septier_objective_images(objective_id, limit=100):
        image_type = str(item.get("image_type") or "")
        items.append({
            **item,
            "url": _objective_image_url(item),
            "exists": bool(item.get("stored_path") and Path(str(item.get("stored_path"))).exists()),
            "type_label": OBJECTIVE_IMAGE_TYPES.get(image_type, image_type or "Imagen"),
        })
    return {"items": items, "types": OBJECTIVE_IMAGE_TYPES}


@app.post("/api/septier/objectives/{objective_id}/csv-attachments/upload")
async def api_upload_septier_objective_csv_attachment(
    objective_id: int,
    files: List[UploadFile] = File(...),
    user=Depends(_require_edit),
):
    objective = get_septier_objective(objective_id)
    if objective is None:
        raise HTTPException(status_code=404, detail="Objetivo no encontrado")

    target_dir = _objective_csv_attachment_dir(objective_id)
    saved = []
    for up in files:
        if not up.filename:
            continue
        safe_name = Path(up.filename).name
        if not safe_name.lower().endswith(".csv"):
            continue
        raw = await up.read()
        _scan_uploaded_bytes(raw, up.filename or "archivo", "upload", user)
        if not raw:
            continue
        df = _read_objective_csv_attachment_dataframe(raw)
        columns = [str(col) for col in df.columns]
        file_hash = hashlib.sha256(raw).hexdigest()
        stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
        stem = re.sub(r"[^A-Za-z0-9._-]+", "_", Path(safe_name).stem).strip("._") or "csv_tecnico"
        final_target = target_dir / f"objetivo_{objective_id}_{stamp}_{stem}.csv"
        i = 1
        while final_target.exists():
            final_target = target_dir / f"objetivo_{objective_id}_{stamp}_{stem}_{i}.csv"
            i += 1
        final_target.write_bytes(raw)
        row = insert_septier_objective_csv_attachment({
            "objective_id": objective_id,
            "original_filename": safe_name,
            "stored_filename": final_target.name,
            "stored_path": str(final_target),
            "rows_count": int(len(df)),
            "columns_json": json.dumps(columns, ensure_ascii=False),
            "hash_sha256": file_hash,
            "uploaded_by": str(user.get("username") or ""),
        })
        saved.append(_serialize_objective_csv_attachment(row))

    if not saved:
        raise HTTPException(status_code=400, detail="No se subieron CSV tecnicos validos")
    return {"ok": True, "objective_id": objective_id, "saved": saved, "count": len(saved)}


@app.get("/api/septier/objectives/{objective_id}/csv-attachments")
def api_list_septier_objective_csv_attachments(objective_id: int, user=Depends(_require_auth)):
    objective = get_septier_objective(objective_id)
    if objective is None:
        raise HTTPException(status_code=404, detail="Objetivo no encontrado")
    items = [
        _serialize_objective_csv_attachment(item)
        for item in list_septier_objective_csv_attachments(objective_id, limit=100)
    ]
    return {"items": items}


def _objective_missing(value: object, label: str) -> str:
    text = str(value or "").strip()
    return text if text else f"SIN {label} INFORMADO"


def _objective_related_rows(objective: Dict[str, Any], limit: int = 20) -> List[List[str]]:
    seen = set()
    rows: List[List[str]] = []
    objective_id = int(objective.get("id") or 0)
    if objective_id:
        for match in list_septier_objective_history_rows(objective_id, limit=20000):
            if not _objective_identity_match(match, objective):
                continue
            key = (
                str(match.get("archivo_origen") or ""),
                str(match.get("imsi_mac") or ""),
                str(match.get("imei") or ""),
                str(match.get("last_update") or ""),
            )
            if key in seen:
                continue
            seen.add(key)
            rows.append([
                html_lib.escape(str(match.get("archivo_origen") or "-")),
                html_lib.escape(str(match.get("last_update") or "-")),
                html_lib.escape(str(match.get("imsi_mac") or "-")),
                html_lib.escape(str(match.get("imei") or "-")),
                html_lib.escape(str(match.get("model") or "-")),
                html_lib.escape(str(match.get("orig_lac") or "-")),
                html_lib.escape(str(match.get("cell_id") or "-")),
            ])
            if len(rows) >= limit:
                return rows
    if rows:
        return rows
    queries = [objective.get("imsi")]
    for query in [str(q or "").strip() for q in queries if str(q or "").strip()]:
        try:
            matches = search_septier_detections(query)
        except Exception:
            matches = []
        for match in matches:
            if not _objective_identity_match(match, objective):
                continue
            key = (
                str(match.get("archivo_origen") or ""),
                str(match.get("imsi_mac") or ""),
                str(match.get("imei") or ""),
                str(match.get("last_update") or ""),
            )
            if key in seen:
                continue
            seen.add(key)
            rows.append([
                html_lib.escape(str(match.get("archivo_origen") or "-")),
                html_lib.escape(str(match.get("last_update") or "-")),
                html_lib.escape(str(match.get("imsi_mac") or "-")),
                html_lib.escape(str(match.get("imei") or "-")),
                html_lib.escape(str(match.get("model") or "-")),
                html_lib.escape(str(match.get("orig_lac") or "-")),
                html_lib.escape(str(match.get("cell_id") or "-")),
            ])
            if len(rows) >= limit:
                return rows
    return rows


def _objective_coord_text(row: Dict[str, Any]) -> str:
    gps = str(row.get("gps_text") or "").strip()
    lat = str(row.get("lat_text") or "").strip()
    lon = str(row.get("lon_text") or "").strip()
    if lat or lon:
        return ", ".join([v for v in (lat, lon) if v])
    return gps


def _objective_detection_summary(objective: Dict[str, Any]) -> Dict[str, object]:
    objective_id = int(objective.get("id") or 0)
    rows = list_septier_objective_history_rows(objective_id, limit=20000)
    target_rows = [row for row in rows if _objective_identity_match(row, objective)]
    target_rows.sort(key=lambda r: _parse_dt_value(r.get("last_update")) or dt.datetime.max)

    imsis = sorted({
        _id15(row.get("imsi_mac"))
        for row in target_rows
        if _id15(row.get("imsi_mac"))
    })
    imeis = sorted({
        _id15(row.get("imei"))
        for row in target_rows
        if _id15(row.get("imei"))
    })
    files = sorted({
        str(row.get("archivo_origen") or "").strip()
        for row in target_rows
        if str(row.get("archivo_origen") or "").strip()
    })
    points = [
        {
            "when": _format_forensic_dt(row.get("last_update")),
            "imsi": _id15(row.get("imsi_mac")) or str(row.get("imsi_mac") or "-").strip() or "-",
            "imei": _id15(row.get("imei")) or str(row.get("imei") or "-").strip() or "-",
            "model": str(row.get("model") or "-").strip() or "-",
            "operation": str(row.get("operation") or row.get("event_type") or "-").strip() or "-",
            "lac": str(row.get("orig_lac") or "-").strip() or "-",
            "cell_id": str(row.get("cell_id") or "-").strip() or "-",
            "coord": _objective_coord_text(row) or "-",
            "file": str(row.get("archivo_origen") or "-").strip() or "-",
        }
        for row in target_rows
    ]
    first = target_rows[0] if target_rows else {}
    last = target_rows[-1] if target_rows else {}
    by_file = Counter(str(row.get("archivo_origen") or "-").strip() or "-" for row in target_rows)
    return {
        "pings": len(target_rows),
        "first_detection": _format_forensic_dt(first.get("last_update")) if first else "-",
        "last_detection": _format_forensic_dt(last.get("last_update")) if last else "-",
        "first_coord": _objective_coord_text(first) if first else "",
        "last_coord": _objective_coord_text(last) if last else "",
        "imsi_observed": imsis,
        "imei_observed": imeis,
        "files": files,
        "by_file": [{"file": file, "total": total} for file, total in by_file.most_common()],
        "points": points,
        "total_history_rows": len(rows),
    }


def _objective_report_html(
    objective: Dict[str, Any],
    related_rows: List[List[str]],
    cross_summary: Dict[str, object],
    detection_summary: Dict[str, object],
    images: List[Dict[str, Any]],
    csv_attachments: List[Dict[str, Any]],
    generated_at: str,
    user: Dict[str, object],
    word_mode: bool = False,
) -> str:
    def e(value: object) -> str:
        return html_lib.escape(str(value or ""))

    imsi = _objective_missing(objective.get("imsi"), "IMSI")
    imei = _objective_missing(objective.get("imei"), "IMEI")
    phone = _objective_missing(objective.get("phone"), "TELEFONO")
    geo = ", ".join([v for v in [str(objective.get("geomatrix_lat") or "").strip(), str(objective.get("geomatrix_lon") or "").strip()] if v])
    geo = geo or "SIN COORDENADAS INFORMADAS"
    field_staff = str(objective.get("field_staff") or "").strip() or "No informado"
    technologies_used = str(objective.get("technologies_used") or "").strip() or "Sistema Septier Guardian/Backpack, Geomatrix si corresponde, referencias de antenas/redes y analisis de history asociado."
    methodology = str(objective.get("methodology") or "").strip() or (
        "Se carga el requerimiento, se asocia el IMSI informado y se incorpora el history del operativo. "
        "La coincidencia principal del objetivo se verifica por IMSI exacto contra la columna IMSI/MAC del history. "
        "Cuando el history contiene coordenadas, se documentan primera y ultima deteccion, cantidad de pings y trazabilidad por archivo."
    )
    related_table = _skyeye_html_table(
        ["Archivo", "Fecha/Hora", "IMSI/MAC", "IMEI", "Modelo", "LAC", "CELL ID"],
        related_rows,
    )
    ranking_rows = [
        [
            e(item.get("imsi") or "-"),
            e(item.get("imei") or "-"),
            e(item.get("total") or 0),
            e(item.get("first_detection") or "-"),
            e(item.get("last_detection") or "-"),
            e(", ".join(item.get("files") or []) or "-"),
            "Objetivo" if item.get("is_objective") else "Relacionado",
        ]
        for item in list(cross_summary.get("ranking") or [])[:10]
    ]
    lac_cell_rows = []
    for item in list(cross_summary.get("lac_cell_ranking") or [])[:10]:
        towers = item.get("tower_matches") or []
        tower_text = "Sin cruce de antena cargado"
        if towers:
            tower_text = " | ".join(
                f"{t.get('provider') or '-'} {t.get('lac') or '-'}/{t.get('cell_id') or '-'} {t.get('lat') or ''}{', ' + str(t.get('lon')) if t.get('lon') else ''}"
                for t in towers
            )
        lac_cell_rows.append([e(item.get("lac") or "-"), e(item.get("cell_id") or "-"), e(item.get("total") or 0), e(tower_text)])
    network_rows = [
        [e(item.get("mcc") or "-"), e(item.get("mnc") or "-"), e(item.get("network_name") or "-"), e(item.get("source_type") or "-")]
        for item in list(cross_summary.get("networks") or [])[:10]
    ]
    ranking_table = _skyeye_html_table(["IMSI/MAC", "IMEI", "Total", "Primera", "Ultima", "Archivos", "Tipo"], ranking_rows)
    lac_cell_table = _skyeye_html_table(["LAC", "CELL ID", "Total", "Cruce antena"], lac_cell_rows)
    network_table = _skyeye_html_table(["MCC", "MNC", "Red", "Fuente"], network_rows)
    detection_rows = [
        [
            e(item.get("when")),
            e(item.get("imsi")),
            e(item.get("imei")),
            e(item.get("model")),
            e(item.get("operation")),
            e(item.get("lac")),
            e(item.get("cell_id")),
            e(item.get("coord")),
            e(item.get("file")),
        ]
        for item in list(detection_summary.get("points") or [])[:80]
    ]
    detection_table = _skyeye_html_table(
        ["Fecha/Hora", "IMSI", "IMEI", "Modelo", "Op/Evento", "LAC", "CELL ID", "GPS / Lat, Lon", "Archivo"],
        detection_rows,
    )
    by_file_rows = [
        [e(item.get("file")), e(item.get("total"))]
        for item in list(detection_summary.get("by_file") or [])
    ]
    by_file_table = _skyeye_html_table(["History asociado", "Pings"], by_file_rows)
    csv_attachment_rows = []
    for item in csv_attachments:
        columns = _objective_csv_columns(item)
        url = _objective_csv_attachment_url(item)
        link = f"<a href='{e(url)}'>Descargar CSV</a>" if url and not word_mode else e(item.get("stored_filename") or "-")
        csv_attachment_rows.append([
            e(item.get("original_filename") or item.get("stored_filename") or "-"),
            e(item.get("rows_count") or 0),
            e(", ".join(columns) or "-"),
            e(str(item.get("hash_sha256") or "")[:18] or "-") + "...",
            link,
        ])
    csv_attachment_section = ""
    if csv_attachment_rows:
        csv_attachment_section = (
            "<h2>Anexo CSV Tecnico Asociado</h2>"
            "<p class='muted'>Archivo tecnico adjunto al objetivo por el analista. "
            "Se listan columnas detectadas, cantidad de filas y hash para auditoria.</p>"
            + _skyeye_html_table(["Archivo", "Filas", "Columnas", "Hash SHA-256", "Acceso"], csv_attachment_rows)
        )

    by_type: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for item in images:
        by_type[str(item.get("image_type") or "evidencia_operativa")].append(item)
    photo_boxes = []
    for key, label in OBJECTIVE_IMAGE_TYPES.items():
        item = by_type.get(key, [None])[0]
        if item:
            src = _objective_image_data_uri(item)
            if src:
                photo_boxes.append(
                    f"<div class='photo-box has-image'><strong>{e(label)}</strong><br>"
                    f"<img src='{src}' alt='{e(label)}' />"
                    f"<div class='muted'>Archivo: {e(item.get('original_filename'))}<br>SHA-256: {e(str(item.get('hash_sha256') or '')[:16])}...</div></div>"
                )
                continue
        photo_boxes.append(f"<div class='photo-box'><strong>{e(label)}</strong><br><span>Adjuntar imagen si se obtiene</span></div>")
    extra_images = [item for key, values in by_type.items() for item in values[1:]]
    for item in extra_images:
        src = _objective_image_data_uri(item)
        if src:
            label = OBJECTIVE_IMAGE_TYPES.get(str(item.get("image_type") or ""), "Evidencia adicional")
            photo_boxes.append(
                f"<div class='photo-box has-image'><strong>{e(label)} adicional</strong><br>"
                f"<img src='{src}' alt='{e(label)}' />"
                f"<div class='muted'>Archivo: {e(item.get('original_filename'))}</div></div>"
            )
    photo_boxes_html = "".join(photo_boxes)
    title_suffix = " - WORD" if word_mode else ""
    return f"""<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="utf-8" />
  <title>Informe Objetivo Identificado #{e(objective.get('id'))}{title_suffix}</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 28px; color: #172033; }}
    .letterhead {{ font-weight: 700; color: #0f3b66; line-height: 1.35; }}
    h1, h2 {{ color: #0f3b66; }}
    .meta, .card {{ border: 1px solid #d8dee8; border-radius: 8px; padding: 12px; margin: 12px 0; }}
    .grid {{ display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; }}
    .grid-3 {{ display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 12px; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 8px; font-size: 13px; }}
    th, td {{ border: 1px solid #d8dee8; padding: 7px; text-align: left; vertical-align: top; }}
    th {{ background: #eef4fb; }}
    .muted {{ color: #667085; }}
    .kpi {{ font-size: 20px; font-weight: 700; color: #0f3b66; word-break: break-word; }}
    .photo-grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; }}
    .photo-box {{ min-height: 150px; border: 1px dashed #9aa8bb; border-radius: 8px; padding: 12px; color: #667085; background: #f8fafc; }}
    .photo-box img {{ display: block; width: 100%; max-height: 260px; object-fit: contain; margin: 8px 0; border: 1px solid #d8dee8; }}
    .has-image {{ border-style: solid; color: #172033; }}
    @media print {{ a {{ color: #172033; }} .grid, .grid-3, .photo-grid {{ grid-template-columns: 1fr 1fr; }} }}
  </style>
</head>
<body>
  <div class="letterhead">
    DEPARTAMENTO DE TECNOLOGIAS ESPECIALES Y DESPLIEGUE TACTICO<br>
    SUBSECRETARIA DE TECNOLOGIA APLICADA A LA SEGURIDAD<br>
    MINISTERIO DE SEGURIDAD Y JUSTICIA
  </div>
  <h1>Informe Resultado Objetivo Identificado</h1>
  <div class="meta">
    <strong>Objetivo:</strong> #{e(objective.get('id'))} | <strong>Generado:</strong> {e(generated_at)} | <strong>Usuario:</strong> {e(user.get('username'))}<br>
    <strong>Oficio / expediente:</strong> {e(objective.get('case_number') or '-')} | <strong>Solicitante:</strong> {e(objective.get('requester') or '-')} | <strong>Estado:</strong> {e(objective.get('status') or '-')}
  </div>

  <div class="grid">
    <div class="card"><div class="kpi">{e(objective.get('person_name') or 'OBJETIVO SIN NOMBRE')}</div><div>Persona / objetivo</div></div>
    <div class="card"><div class="kpi">{e(phone)}</div><div>Telefono</div></div>
    <div class="card"><div class="kpi">{e(imsi)}</div><div>IMSI</div></div>
    <div class="card"><div class="kpi">{e(imei)}</div><div>IMEI</div></div>
  </div>

  <h2>1. Objetivo del Procedimiento</h2>
  <div class="card">
    Detectar, verificar y documentar la informacion disponible del objetivo identificado en el requerimiento operativo.
    Los identificadores informados son: telefono <strong>{e(phone)}</strong>, IMSI <strong>{e(imsi)}</strong> e IMEI <strong>{e(imei)}</strong>.
  </div>

  <h2>2. Datos del Requerimiento</h2>
  <table>
    <tbody>
      <tr><th>Tipo</th><td>{e(objective.get('request_type') or '-')}</td></tr>
      <tr><th>DNI</th><td>{e(_objective_missing(objective.get('dni'), 'DNI'))}</td></tr>
      <tr><th>Referencia Geomatrix</th><td>{e(geo)} {e(objective.get('geomatrix_ref') or '')}</td></tr>
      <tr><th>Operarios intervinientes / trabajo de campo</th><td>{e(field_staff)}</td></tr>
      <tr><th>Tecnologias utilizadas</th><td>{e(technologies_used)}</td></tr>
      <tr><th>Metodologia aplicada</th><td>{e(methodology)}</td></tr>
      <tr><th>Observaciones</th><td>{e(objective.get('notes') or 'Sin observaciones cargadas.')}</td></tr>
    </tbody>
  </table>

  <h2>3. Resultados y Coincidencias</h2>
  <div class="grid-3">
    <div class="card"><div class="kpi">{e(cross_summary.get('total_rows') or 0)}</div><div>Filas history objetivo</div></div>
    <div class="card"><div class="kpi">{e(cross_summary.get('target_rows') or 0)}</div><div>Coincidencias con objetivo</div></div>
    <div class="card"><div class="kpi">{e(len(cross_summary.get('files') or []))}</div><div>Archivos involucrados</div></div>
  </div>
  <div class="grid-3">
    <div class="card"><div class="kpi">{e(detection_summary.get('pings') or 0)}</div><div>Ping(s) del objetivo</div></div>
    <div class="card"><div class="kpi">{e(', '.join(detection_summary.get('imsi_observed') or []) or '-')}</div><div>IMSI observado</div></div>
    <div class="card"><div class="kpi">{e(', '.join(detection_summary.get('imei_observed') or []) or '-')}</div><div>IMEI observado</div></div>
  </div>
  <table>
    <tbody>
      <tr><th>Primera deteccion del objetivo</th><td>{e(detection_summary.get('first_detection') or '-')} {e(detection_summary.get('first_coord') or '')}</td></tr>
      <tr><th>Ultima deteccion del objetivo</th><td>{e(detection_summary.get('last_detection') or '-')} {e(detection_summary.get('last_coord') or '')}</td></tr>
      <tr><th>Archivos donde aparece</th><td>{e(', '.join(detection_summary.get('files') or []) or '-')}</td></tr>
    </tbody>
  </table>
  <h3>Histories asociados al objetivo</h3>
  {by_file_table}
  <h3>Detalle temporal del objetivo</h3>
  {detection_table}
  <h3>Vista resumida de coincidencias</h3>
  {related_table}

  <h2>4. Analisis Tecnico</h2>
  <h3>Ranking de apariciones</h3>
  {ranking_table}
  <h3>LAC / CELL ID y cruce con Antenas</h3>
  {lac_cell_table}
  <h3>Cruce con Redes y Telefonia</h3>
  {network_table}

  {csv_attachment_section}

  <h2>5. Registro Fotografico / Evidencia Visual</h2>
  <p class="muted">Espacios reservados para adjuntar imagen si se obtiene durante el procedimiento.</p>
  <div class="photo-grid">{photo_boxes_html}</div>

  <h2>6. Conclusion Operativa</h2>
  <div class="card">
    El presente informe consolida la informacion disponible del objetivo cargado en el sistema. La interpretacion final queda sujeta a la validacion operativa del analista interviniente y a las coordenadas o registros complementarios que se incorporen.
  </div>
</body>
</html>"""


def _write_objective_docx(
    objective: Dict[str, Any],
    cross_summary: Dict[str, object],
    detection_summary: Dict[str, object],
    images: List[Dict[str, Any]],
    csv_attachments: List[Dict[str, Any]],
    generated_at: str,
    user: Dict[str, object],
    word_path: Path,
) -> None:
    try:
        from docx import Document
        from docx.enum.section import WD_ORIENT
        from docx.enum.table import WD_TABLE_ALIGNMENT, WD_CELL_VERTICAL_ALIGNMENT
        from docx.oxml import OxmlElement
        from docx.oxml.ns import qn
        from docx.shared import Cm, Pt, RGBColor
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Falta dependencia python-docx para generar Word: {exc}")

    def text(value: object, fallback: str = "-") -> str:
        clean = str(value or "").strip()
        return clean if clean else fallback

    def add_kv_table(title: str, rows: List[Tuple[str, object]]) -> None:
        doc.add_heading(title, level=1)
        table = doc.add_table(rows=0, cols=2)
        table.style = "Table Grid"
        table.autofit = False
        for label, value in rows:
            cells = table.add_row().cells
            cells[0].width = Cm(5.0)
            cells[1].width = Cm(22.0)
            cells[0].text = str(label)
            cells[1].text = text(value, "No informado")
            _shade_cell(cells[0], "EAF3FB")
            for cell in cells:
                cell.vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.TOP
                for paragraph in cell.paragraphs:
                    paragraph.paragraph_format.space_after = Pt(0)
                    for run in paragraph.runs:
                        run.font.size = Pt(8)
            for run in cells[0].paragraphs[0].runs:
                run.bold = True

    def add_table(title: str, headers: List[str], rows: List[List[object]], widths: Optional[List[float]] = None, max_rows: int = 120) -> None:
        doc.add_heading(title, level=1)
        if not rows:
            doc.add_paragraph("Sin datos verificables.")
            return
        table = doc.add_table(rows=1, cols=len(headers))
        table.style = "Table Grid"
        table.alignment = WD_TABLE_ALIGNMENT.LEFT
        table.autofit = False
        header_cells = table.rows[0].cells
        for idx, header in enumerate(headers):
            header_cells[idx].text = header
            _shade_cell(header_cells[idx], "EAF3FB")
            for run in header_cells[idx].paragraphs[0].runs:
                run.bold = True
                run.font.size = Pt(7)
        for row in rows[:max_rows]:
            cells = table.add_row().cells
            for idx, value in enumerate(row):
                cells[idx].text = text(value)
        if widths:
            for row in table.rows:
                for idx, width in enumerate(widths):
                    if idx < len(row.cells):
                        row.cells[idx].width = Cm(width)
        for row in table.rows:
            for cell in row.cells:
                cell.vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.TOP
                for paragraph in cell.paragraphs:
                    paragraph.paragraph_format.space_after = Pt(0)
                    for run in paragraph.runs:
                        run.font.size = Pt(7)
        if len(rows) > max_rows:
            doc.add_paragraph(f"Tabla truncada para Word: se muestran {max_rows} de {len(rows)} registros. El HTML conserva la vista ampliada.")

    def _shade_cell(cell, fill: str) -> None:
        tc_pr = cell._tc.get_or_add_tcPr()
        shd = OxmlElement("w:shd")
        shd.set(qn("w:fill"), fill)
        tc_pr.append(shd)

    doc = Document()
    section = doc.sections[0]
    section.orientation = WD_ORIENT.LANDSCAPE
    section.page_width, section.page_height = section.page_height, section.page_width
    section.top_margin = Cm(1.0)
    section.bottom_margin = Cm(1.0)
    section.left_margin = Cm(1.0)
    section.right_margin = Cm(1.0)

    head = doc.add_paragraph()
    head.paragraph_format.space_after = Pt(4)
    for idx, line in enumerate([
        "DEPARTAMENTO DE TECNOLOGIAS ESPECIALES Y DESPLIEGUE TACTICO",
        "SUBSECRETARIA DE TECNOLOGIA APLICADA A LA SEGURIDAD",
        "MINISTERIO DE SEGURIDAD Y JUSTICIA",
    ]):
        run = head.add_run(line)
        run.bold = True
        run.font.size = Pt(9)
        run.font.color.rgb = RGBColor(0, 59, 104)
        if idx < 2:
            head.add_run("\n")

    title = doc.add_paragraph()
    title.paragraph_format.space_after = Pt(8)
    title_run = title.add_run("Informe Resultado Objetivo Identificado")
    title_run.bold = True
    title_run.font.size = Pt(20)
    title_run.font.color.rgb = RGBColor(0, 68, 111)

    geo = ", ".join([v for v in [str(objective.get("geomatrix_lat") or "").strip(), str(objective.get("geomatrix_lon") or "").strip()] if v])
    geo = geo or "Sin coordenadas informadas"
    meta_rows = [
        ("Objetivo", f"#{objective.get('id') or '-'} - {text(objective.get('person_name'), 'Objetivo sin nombre')}"),
        ("Generado", generated_at),
        ("Usuario", user.get("full_name") or user.get("username") or "-"),
        ("Oficio / expediente", objective.get("case_number") or "-"),
        ("Solicitante", objective.get("requester") or "-"),
        ("Estado", objective.get("status") or "-"),
    ]
    add_kv_table("Datos principales", meta_rows)
    add_kv_table("Identificadores y referencia", [
        ("Telefono", _objective_missing(objective.get("phone"), "TELEFONO")),
        ("IMSI informado", _objective_missing(objective.get("imsi"), "IMSI")),
        ("IMEI informado", _objective_missing(objective.get("imei"), "IMEI")),
        ("DNI", _objective_missing(objective.get("dni"), "DNI")),
        ("Referencia Geomatrix", f"{geo} {objective.get('geomatrix_ref') or ''}".strip()),
    ])
    add_kv_table("Personal, tecnologias y metodologia", [
        ("Operarios intervinientes / trabajo de campo", objective.get("field_staff") or "No informado"),
        ("Tecnologias utilizadas", objective.get("technologies_used") or "Sistema Septier Guardian/Backpack, Geomatrix si corresponde, referencias de antenas/redes y analisis de history asociado."),
        ("Metodologia aplicada", objective.get("methodology") or "Se carga el requerimiento, se asocia el IMSI informado y se incorpora el history del operativo. La coincidencia principal del objetivo se verifica por IMSI exacto contra la columna IMSI/MAC del history."),
        ("Observaciones", objective.get("notes") or "Sin observaciones cargadas."),
    ])

    metrics = [
        ("Filas history objetivo", cross_summary.get("total_rows") or 0),
        ("Coincidencias con objetivo", cross_summary.get("target_rows") or 0),
        ("Pings del objetivo", detection_summary.get("pings") or 0),
        ("Archivos involucrados", len(detection_summary.get("files") or [])),
        ("IMSI observado", ", ".join(detection_summary.get("imsi_observed") or []) or "-"),
        ("IMEI observado", ", ".join(detection_summary.get("imei_observed") or []) or "-"),
        ("Primera deteccion", detection_summary.get("first_detection") or "-"),
        ("Ultima deteccion", detection_summary.get("last_detection") or "-"),
    ]
    add_kv_table("Resultado tecnico del objetivo", metrics)

    by_file_rows = [
        [item.get("file"), item.get("total")]
        for item in list(detection_summary.get("by_file") or [])
    ]
    add_table("Histories asociados al objetivo", ["History", "Pings"], by_file_rows, widths=[22.0, 3.0])

    point_rows = [
        [
            item.get("when"),
            item.get("imsi"),
            item.get("imei"),
            item.get("model"),
            item.get("operation"),
            item.get("lac"),
            item.get("cell_id"),
            item.get("coord"),
            item.get("file"),
        ]
        for item in list(detection_summary.get("points") or [])
    ]
    add_table(
        "Detalle temporal del objetivo",
        ["Fecha/Hora", "IMSI", "IMEI", "Modelo", "Op/Evento", "LAC", "CELL ID", "GPS / Lat, Lon", "Archivo"],
        point_rows,
        widths=[3.0, 3.2, 3.2, 3.6, 3.8, 1.7, 1.7, 3.0, 4.5],
        max_rows=80,
    )

    csv_rows = [
        [
            item.get("original_filename") or item.get("stored_filename") or "-",
            item.get("rows_count") or 0,
            ", ".join(_objective_csv_columns(item)) or "-",
            str(item.get("hash_sha256") or "")[:24],
        ]
        for item in csv_attachments
    ]
    add_table("Anexo CSV Tecnico Asociado", ["Archivo", "Filas", "Columnas", "Hash SHA-256"], csv_rows, widths=[6.0, 2.0, 15.0, 4.0], max_rows=40)

    image_rows = [
        [
            OBJECTIVE_IMAGE_TYPES.get(str(item.get("image_type") or ""), str(item.get("image_type") or "Imagen")),
            item.get("original_filename") or "-",
            str(item.get("hash_sha256") or "")[:24],
        ]
        for item in images
    ]
    add_table("Registro fotografico / evidencia visual", ["Tipo", "Archivo", "Hash SHA-256"], image_rows, widths=[5.0, 15.0, 5.0], max_rows=40)

    doc.add_heading("Conclusion Operativa", level=1)
    doc.add_paragraph(
        "El presente informe consolida la informacion disponible del objetivo cargado en el sistema. "
        "La interpretacion final queda sujeta a la validacion operativa del analista interviniente y a los registros complementarios que se incorporen."
    )
    for paragraph in doc.paragraphs:
        for run in paragraph.runs:
            if run.font.size is None:
                run.font.size = Pt(9)
    doc.save(word_path)


def _write_objective_report_files(objective: Dict[str, Any], user: Dict[str, object]) -> Dict[str, object]:
    generated_at = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_id = re.sub(r"[^a-zA-Z0-9_-]+", "_", str(objective.get("id") or "objetivo"))
    out_dir = OUTPUTS_DIR / "informes_objetivos" / f"objetivo_{safe_id}"
    out_dir.mkdir(parents=True, exist_ok=True)
    related_rows = _objective_related_rows(objective)
    cross_summary = _objective_cross_summary(objective)
    detection_summary = _objective_detection_summary(objective)
    images = list_septier_objective_images(int(objective.get("id") or 0), limit=100)
    csv_attachments = list_septier_objective_csv_attachments(int(objective.get("id") or 0), limit=100)
    html = _objective_report_html(objective, related_rows, cross_summary, detection_summary, images, csv_attachments, generated_at, user)
    html_path = out_dir / f"informe_objetivo_{safe_id}_{stamp}.html"
    word_path = out_dir / f"informe_objetivo_{safe_id}_{stamp}.docx"
    html_path.write_text(html, encoding="utf-8")
    _write_objective_docx(objective, cross_summary, detection_summary, images, csv_attachments, generated_at, user, word_path)
    sha256 = hashlib.sha256(word_path.read_bytes()).hexdigest()
    audit = insert_septier_objective_report({
        "objective_id": int(objective.get("id") or 0),
        "html_path": str(html_path),
        "word_path": str(word_path),
        "sha256": sha256,
        "generated_by": str(user.get("username") or ""),
    })
    return {
        "audit": audit,
        "html_path": html_path,
        "word_path": word_path,
        "sha256": sha256,
        "related_count": len(related_rows),
        "images_count": len(images),
        "csv_attachments_count": len(csv_attachments),
    }


@app.post("/api/septier/objectives/{objective_id}/report")
def api_generate_septier_objective_report(objective_id: int, user=Depends(_require_auth)):
    objective = get_septier_objective(objective_id)
    if objective is None:
        raise HTTPException(status_code=404, detail="Objetivo no encontrado")
    result = _write_objective_report_files(objective, user)
    return {
        "ok": True,
        "objective_id": objective_id,
        "html_url": _skyeye_output_url(result["html_path"]),
        "word_url": _skyeye_output_url(result["word_path"]),
        "sha256": result["sha256"],
        "related_count": result["related_count"],
        "images_count": result["images_count"],
        "csv_attachments_count": result["csv_attachments_count"],
        "audit": result["audit"],
    }


@app.get("/api/septier/objectives/{objective_id}/reports")
def api_list_septier_objective_reports(objective_id: int, user=Depends(_require_auth)):
    items = []
    for row in list_septier_objective_reports(objective_id=objective_id):
        html_path = row.get("html_path")
        word_path = row.get("word_path")
        items.append({
            **row,
            "html_url": _skyeye_output_url(html_path),
            "word_url": _skyeye_output_url(word_path),
            "html_exists": bool(html_path and Path(str(html_path)).exists()),
            "word_exists": bool(word_path and Path(str(word_path)).exists()),
        })
    return {"items": items}


def _phone_query_http_json(url: str, *, method: str = "GET", headers: Optional[Dict[str, str]] = None, payload: Optional[Dict[str, object]] = None, timeout: int = 10) -> Dict[str, object]:
    data = None
    request_headers = dict(headers or {})
    if payload is not None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        request_headers.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=data, method=method.upper(), headers=request_headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            text = raw.decode("utf-8", errors="replace")
            try:
                body = json.loads(text) if text.strip() else {}
            except Exception:
                body = {"raw_text": text[:2000]}
            return {"ok": True, "status_code": int(getattr(resp, "status", 200)), "body": body}
    except urllib.error.HTTPError as exc:
        raw = exc.read() if hasattr(exc, "read") else b""
        text = raw.decode("utf-8", errors="replace")
        try:
            body = json.loads(text) if text.strip() else {}
        except Exception:
            body = {"raw_text": text[:2000]}
        return {"ok": False, "status_code": int(exc.code), "body": body, "error": str(exc)}
    except Exception as exc:
        return {"ok": False, "status_code": 0, "body": {}, "error": str(exc)}


def _phone_provider_result(name: str, status_value: str, detail: str, raw: Optional[Dict[str, object]] = None) -> Dict[str, object]:
    return {
        "provider": name,
        "status": status_value,
        "detail": detail,
        "raw": raw or {},
    }


def _phone_query_env_status() -> Dict[str, bool]:
    return {
        "open_gateway_token": bool(PHONE_QUERY_OPEN_GATEWAY_TOKEN),
        "sim_swap_url": bool(PHONE_QUERY_SIM_SWAP_URL),
        "device_location_verify_url": bool(PHONE_QUERY_DEVICE_LOCATION_VERIFY_URL),
        "ipqs": bool(PHONE_QUERY_IPQS_API_KEY),
        "maxmind": bool(PHONE_QUERY_MAXMIND_ACCOUNT_ID and PHONE_QUERY_MAXMIND_LICENSE_KEY and PHONE_QUERY_MAXMIND_URL),
    }


def _summarize_ipqs(body: Dict[str, object]) -> str:
    parts = []
    for key, label in [
        ("carrier", "carrier"),
        ("line_type", "linea"),
        ("country", "pais"),
        ("city", "ciudad"),
        ("fraud_score", "fraud_score"),
        ("active", "activo"),
        ("valid", "valido"),
    ]:
        if key in body and body.get(key) not in (None, ""):
            parts.append(f"{label}: {body.get(key)}")
    return " | ".join(parts) or "Respuesta recibida sin campos operativos normalizados."


def _run_phone_query_providers(payload: PhoneQueryRequest, user: Dict[str, object]) -> Dict[str, object]:
    phone = payload.phone.strip()
    results: List[Dict[str, object]] = []
    env_status = _phone_query_env_status()

    results.append(_phone_provider_result(
        "Regla de evidencia",
        "ACTIVA",
        "La consulta no infiere IMSI ni ubicacion exacta. Solo se informa lo devuelto por proveedores configurados.",
        {"created_by": str(user.get("username") or "")},
    ))

    if PHONE_QUERY_IPQS_API_KEY and PHONE_QUERY_IPQS_URL_TEMPLATE:
        url = PHONE_QUERY_IPQS_URL_TEMPLATE.replace("{key}", urllib.parse.quote(PHONE_QUERY_IPQS_API_KEY)).replace("{phone}", urllib.parse.quote(phone))
        response = _phone_query_http_json(url, timeout=10)
        body = response.get("body") if isinstance(response.get("body"), dict) else {}
        status_value = "OK" if response.get("ok") else "ERROR"
        results.append(_phone_provider_result("IPQualityScore Phone Validation", status_value, _summarize_ipqs(body), response))
    else:
        results.append(_phone_provider_result("IPQualityScore Phone Validation", "NO_CONFIGURADO", "Falta PHONE_QUERY_IPQS_API_KEY para consultar estado tecnico del numero."))

    if PHONE_QUERY_MAXMIND_ACCOUNT_ID and PHONE_QUERY_MAXMIND_LICENSE_KEY and PHONE_QUERY_MAXMIND_URL:
        token_raw = f"{PHONE_QUERY_MAXMIND_ACCOUNT_ID}:{PHONE_QUERY_MAXMIND_LICENSE_KEY}".encode("utf-8")
        headers = {"Authorization": "Basic " + base64.b64encode(token_raw).decode("ascii")}
        response = _phone_query_http_json(PHONE_QUERY_MAXMIND_URL, method="POST", headers=headers, payload={"phone_number": phone}, timeout=10)
        status_value = "OK" if response.get("ok") else "ERROR"
        results.append(_phone_provider_result("MaxMind minFraud / Phone", status_value, "Respuesta recibida para evaluacion antifraude si el producto contratado lo soporta.", response))
    else:
        results.append(_phone_provider_result("MaxMind minFraud / Phone", "NO_CONFIGURADO", "Faltan credenciales/endpoint MaxMind para consulta antifraude."))

    if PHONE_QUERY_OPEN_GATEWAY_TOKEN and PHONE_QUERY_SIM_SWAP_URL:
        headers = {
            "Authorization": f"Bearer {PHONE_QUERY_OPEN_GATEWAY_TOKEN}",
            "x-correlator": secrets.token_hex(16),
        }
        response = _phone_query_http_json(PHONE_QUERY_SIM_SWAP_URL, method="POST", headers=headers, payload={"phoneNumber": phone, "maxAge": 24}, timeout=10)
        body = response.get("body") if isinstance(response.get("body"), dict) else {}
        swapped = body.get("swapped")
        detail = f"SIM swap informado: {swapped}" if swapped is not None else "Respuesta recibida; revisar cuerpo normalizado del proveedor."
        results.append(_phone_provider_result("GSMA Open Gateway SIM Swap", "OK" if response.get("ok") else "ERROR", detail, response))
    else:
        results.append(_phone_provider_result("GSMA Open Gateway SIM Swap", "NO_CONFIGURADO", "Falta PHONE_QUERY_OPEN_GATEWAY_TOKEN y/o PHONE_QUERY_SIM_SWAP_URL."))

    has_area = payload.area_lat is not None and payload.area_lon is not None
    if PHONE_QUERY_OPEN_GATEWAY_TOKEN and PHONE_QUERY_DEVICE_LOCATION_VERIFY_URL and has_area:
        headers = {
            "Authorization": f"Bearer {PHONE_QUERY_OPEN_GATEWAY_TOKEN}",
            "x-correlator": secrets.token_hex(16),
        }
        body = {
            "device": {"phoneNumber": phone},
            "area": {
                "areaType": "CIRCLE",
                "center": {"latitude": payload.area_lat, "longitude": payload.area_lon},
                "radius": int(payload.radius_m or 50000),
            },
        }
        response = _phone_query_http_json(PHONE_QUERY_DEVICE_LOCATION_VERIFY_URL, method="POST", headers=headers, payload=body, timeout=10)
        resp_body = response.get("body") if isinstance(response.get("body"), dict) else {}
        verification = resp_body.get("verificationResult") or resp_body.get("result") or resp_body.get("match")
        detail = f"Resultado de verificacion de area: {verification}" if verification is not None else "Respuesta recibida; revisar match/radio devuelto por proveedor."
        results.append(_phone_provider_result("GSMA Open Gateway Device Location Verification", "OK" if response.get("ok") else "ERROR", detail, response))
    elif PHONE_QUERY_OPEN_GATEWAY_TOKEN and PHONE_QUERY_DEVICE_LOCATION_VERIFY_URL:
        results.append(_phone_provider_result("GSMA Open Gateway Device Location Verification", "PENDIENTE_DATOS", "Para verificar area se requieren latitud y longitud operativas."))
    else:
        results.append(_phone_provider_result("GSMA Open Gateway Device Location Verification", "NO_CONFIGURADO", "Falta token y/o endpoint de verificacion de ubicacion."))

    configured_external = [r for r in results if r.get("provider") != "Regla de evidencia" and r.get("status") not in {"NO_CONFIGURADO", "PENDIENTE_DATOS"}]
    if not configured_external:
        overall = "SIN_FUENTES_CONFIGURADAS"
    elif any(r.get("status") == "ERROR" for r in configured_external):
        overall = "CON_OBSERVACIONES"
    else:
        overall = "CONSULTA_REGISTRADA"

    return {
        "status": overall,
        "phone": phone,
        "reference": payload.reference.strip(),
        "area": {
            "label": payload.area_label.strip(),
            "lat": payload.area_lat,
            "lon": payload.area_lon,
            "radius_m": int(payload.radius_m or 50000),
        },
        "notes": payload.notes.strip(),
        "env_status": env_status,
        "providers": results,
        "imsi": "No informado por fuente consultada",
        "exact_location": "No disponible salvo contrato/API que lo entregue expresamente",
    }


def _phone_query_report_html(record: Dict[str, object], summary: Dict[str, object], generated_at: str, user: Dict[str, object], word_mode: bool = False) -> str:
    e = lambda v: html_lib.escape(str(v if v is not None else ""))
    providers = summary.get("providers") if isinstance(summary.get("providers"), list) else []
    area = summary.get("area") if isinstance(summary.get("area"), dict) else {}
    provider_rows = ""
    for provider in providers:
        raw = provider.get("raw") if isinstance(provider.get("raw"), dict) else {}
        raw_preview = json.dumps(raw.get("body", raw), ensure_ascii=False)[:1200]
        provider_rows += (
            "<tr>"
            f"<td>{e(provider.get('provider'))}</td>"
            f"<td>{e(provider.get('status'))}</td>"
            f"<td>{e(provider.get('detail'))}</td>"
            f"<td class='small'>{e(raw_preview or '-')}</td>"
            "</tr>"
        )
    env_rows = "".join(
        f"<tr><td>{e(name)}</td><td>{'Configurada' if bool(value) else 'Pendiente'}</td></tr>"
        for name, value in (summary.get("env_status") if isinstance(summary.get("env_status"), dict) else {}).items()
    )
    return f"""<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <title>Consulta Operativa Telefonica</title>
  <style>
    body {{ font-family: Arial, sans-serif; color: #06152b; margin: 28px; }}
    h1, h2 {{ color: #073b6d; }}
    .muted {{ color: #52606f; }}
    .grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin: 14px 0; }}
    .card {{ border: 1px solid #cfd9e6; border-radius: 8px; padding: 12px; }}
    .kpi {{ font-size: 24px; font-weight: 800; color: #073b6d; }}
    table {{ width: 100%; border-collapse: collapse; margin: 12px 0 20px; }}
    th, td {{ border: 1px solid #cfd9e6; padding: 8px; text-align: left; vertical-align: top; }}
    th {{ background: #eaf1f8; }}
    .small {{ font-size: 11px; color: #394758; word-break: break-word; }}
    .warning {{ border-left: 4px solid #d58512; background: #fff8e8; padding: 12px; }}
  </style>
</head>
<body>
  <h1>Consulta Operativa Telefonica</h1>
  <p><b>Generado:</b> {e(generated_at)} | <b>Usuario:</b> {e(user.get('username'))} | <b>ID:</b> {e(record.get('id'))}</p>
  <div class="grid">
    <div class="card"><div class="kpi">{e(summary.get('status'))}</div><div>Estado de consulta</div></div>
    <div class="card"><div class="kpi">{e(summary.get('phone'))}</div><div>Numero consultado</div></div>
    <div class="card"><div class="kpi">{e(summary.get('imsi'))}</div><div>IMSI</div></div>
  </div>
  <h2>Datos de requerimiento</h2>
  <table>
    <tbody>
      <tr><th>Referencia</th><td>{e(summary.get('reference') or record.get('reference') or '-')}</td></tr>
      <tr><th>Area</th><td>{e(area.get('label') or record.get('area_label') or '-')}</td></tr>
      <tr><th>Coordenadas / radio</th><td>{e(area.get('lat'))}, {e(area.get('lon'))} / {e(area.get('radius_m'))} m</td></tr>
      <tr><th>Observaciones</th><td>{e(summary.get('notes') or '-')}</td></tr>
    </tbody>
  </table>
  <h2>Fuentes consultadas</h2>
  <table>
    <thead><tr><th>Fuente</th><th>Estado</th><th>Detalle</th><th>Respuesta tecnica</th></tr></thead>
    <tbody>{provider_rows}</tbody>
  </table>
  <h2>Variables / credenciales</h2>
  <table><tbody>{env_rows}</tbody></table>
  <h2>Limitaciones tecnicas</h2>
  <div class="warning">
    Este modulo no inventa IMSI, coordenadas ni ubicacion exacta. SIM Swap informa eventos sobre la SIM/MSISDN si el proveedor contratado lo devuelve. Device Location Verification valida presencia en un area solicitada cuando existe endpoint, token, scope y autorizacion legal; no equivale por si mismo a obtener ubicacion exacta.
  </div>
</body>
</html>"""


def _phone_query_public_item(row: Dict[str, object]) -> Dict[str, object]:
    item = dict(row)
    summary = item.get("provider_summary")
    if summary is None:
        try:
            summary = json.loads(str(item.get("provider_summary_json") or "{}"))
        except Exception:
            summary = {}
    item["provider_summary"] = summary
    item.pop("provider_summary_json", None)
    item["html_url"] = _skyeye_output_url(item.get("html_path"))
    item["word_url"] = _skyeye_output_url(item.get("word_path"))
    item["html_exists"] = bool(item.get("html_path") and Path(str(item.get("html_path"))).exists())
    item["word_exists"] = bool(item.get("word_path") and Path(str(item.get("word_path"))).exists())
    return item


def _write_phone_query_report(record: Dict[str, object], user: Dict[str, object]) -> Dict[str, object]:
    summary = record.get("provider_summary")
    if summary is None:
        try:
            summary = json.loads(str(record.get("provider_summary_json") or "{}"))
        except Exception:
            summary = {}
    generated_at = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_id = re.sub(r"[^a-zA-Z0-9_-]+", "_", str(record.get("id") or "consulta"))
    out_dir = OUTPUTS_DIR / "consultas_telefono" / f"consulta_{safe_id}"
    out_dir.mkdir(parents=True, exist_ok=True)
    html_path = out_dir / f"consulta_telefono_{safe_id}_{stamp}.html"
    word_path = out_dir / f"consulta_telefono_{safe_id}_{stamp}.doc"
    html_path.write_text(_phone_query_report_html(record, summary, generated_at, user), encoding="utf-8")
    word_path.write_text(_phone_query_report_html(record, summary, generated_at, user, word_mode=True), encoding="utf-8")
    sha256 = hashlib.sha256(word_path.read_bytes()).hexdigest()
    updated = update_phone_query_report(int(record.get("id") or 0), str(html_path), str(word_path), sha256)
    return {"record": updated, "html_path": html_path, "word_path": word_path, "sha256": sha256}


@app.post("/api/phone-query")
def api_create_phone_query(payload: PhoneQueryRequest, user=Depends(_require_edit)):
    phone = re.sub(r"[\s().-]+", "", payload.phone.strip())
    if phone.startswith("00"):
        phone = "+" + phone[2:]
    if not re.fullmatch(r"\+[1-9]\d{7,14}", phone):
        raise HTTPException(status_code=400, detail="El numero debe estar en formato internacional E.164. Ejemplo: +5492610000000")
    payload.phone = phone
    summary = _run_phone_query_providers(payload, user)
    record = insert_phone_query({
        "reference": payload.reference,
        "phone": phone,
        "area_label": payload.area_label,
        "area_lat": payload.area_lat,
        "area_lon": payload.area_lon,
        "radius_m": payload.radius_m,
        "status": summary.get("status", ""),
        "provider_summary": summary,
        "created_by": str(user.get("username") or ""),
    })
    result = _write_phone_query_report(record, user)
    return {
        "ok": True,
        "item": _phone_query_public_item(result["record"]),
        "html_url": _skyeye_output_url(result["html_path"]),
        "word_url": _skyeye_output_url(result["word_path"]),
        "sha256": result["sha256"],
        "env_required": PHONE_QUERY_ENV_VARS,
    }


@app.get("/api/phone-query")
def api_list_phone_query(limit: int = 100, user=Depends(_require_auth)):
    safe_limit = max(1, min(int(limit or 100), 300))
    return {"items": [_phone_query_public_item(row) for row in list_phone_queries(limit=safe_limit)], "env_status": _phone_query_env_status(), "env_required": PHONE_QUERY_ENV_VARS}


@app.get("/api/sigma/objectives")
def api_sigma_objectives(user=Depends(_require_auth)):
    return _sigma_objectives_payload()


@app.get("/api/sigma/status")
def api_sigma_status(user=Depends(_require_auth)):
    return {
        "ok": True,
        "configured": bool(OPENAI_API_KEY),
        "model": SIGMA_OPENAI_MODEL,
        "mode": "evidence_chat",
        "scope": [
            "SkyEye",
            "Septier",
            "objetivos",
            "informes",
            "antenas",
            "redes/telefonia",
            "evidencias",
            "hashes",
            "lista blanca",
            "seguridad",
        ],
    }


def _sigma_objectives_payload() -> Dict[str, object]:
    objectives = list_septier_objectives(limit=500)
    items = []
    counts = {
        "total": len(objectives),
        "pending": 0,
        "missing_imsi_imei": 0,
        "with_matches": 0,
        "ready_for_report": 0,
        "with_report": 0,
        "without_history": 0,
    }
    for objective in objectives:
        objective_id = int(objective.get("id") or 0)
        status_value = str(objective.get("status") or "").strip()
        if status_value in {"pendiente", "en_analisis"}:
            counts["pending"] += 1
        if not str(objective.get("imsi") or "").strip() and not str(objective.get("imei") or "").strip():
            counts["missing_imsi_imei"] += 1

        cross = _objective_cross_summary(objective)
        reports = list_septier_objective_reports(objective_id=objective_id, limit=10)
        images = list_septier_objective_images(objective_id, limit=100)
        latest_report = reports[0] if reports else {}
        has_report = bool(reports)
        has_history = bool(cross.get("total_rows"))
        has_match = bool(cross.get("target_rows"))
        ready_for_report = has_match and status_value not in {"cerrado"}
        if not has_history:
            counts["without_history"] += 1
        if has_match:
            counts["with_matches"] += 1
        if ready_for_report:
            counts["ready_for_report"] += 1
        if has_report:
            counts["with_report"] += 1
        items.append({
            "id": objective_id,
            "person_name": objective.get("person_name") or "",
            "case_number": objective.get("case_number") or "",
            "status": status_value,
            "phone": objective.get("phone") or "",
            "imsi": objective.get("imsi") or "",
            "imei": objective.get("imei") or "",
            "total_rows": cross.get("total_rows") or 0,
            "target_rows": cross.get("target_rows") or 0,
            "first_detection": cross.get("first_detection") or "",
            "last_detection": cross.get("last_detection") or "",
            "files_count": len(cross.get("files") or []),
            "images_count": len(images),
            "reports_count": len(reports),
            "ready_for_report": ready_for_report,
            "latest_report_hash": latest_report.get("sha256") or "",
            "latest_report_at": latest_report.get("created_at") or "",
            "latest_report_by": latest_report.get("generated_by") or "",
            "html_exists": bool(latest_report.get("html_path") and Path(str(latest_report.get("html_path"))).exists()),
            "word_exists": bool(latest_report.get("word_path") and Path(str(latest_report.get("word_path"))).exists()),
        })

    return {
        "counts": counts,
        "items": items,
        "source": "septier_objectives + objective_history + objective_reports",
    }


def _sigma_external_data_payload() -> Dict[str, object]:
    uploads = list_external_identity_uploads(limit=20)
    sample = list_external_identity_data(limit=500)
    matches = _external_data_whitelist_matches()
    latest_upload = uploads[0] if uploads else {}
    by_provider = Counter(_external_provider_bucket(row.get("prestataria")) for row in sample)
    by_match_kind = Counter(str(item.get("match_kind") or "identidad") for item in matches)
    return {
        "source": "external_identity_data + whitelist_actual",
        "rule": "Data Externa Postgres es segunda capa de contraste. No autoriza ni excluye IMSI/IMEI del informe final; las coincidencias se documentan para revision operativa.",
        "uploads_count": len(uploads),
        "latest_upload": {
            "original_filename": latest_upload.get("original_filename") or "",
            "stored_filename": latest_upload.get("stored_filename") or "",
            "uploaded_by": latest_upload.get("uploaded_by") or "",
            "created_at": latest_upload.get("created_at") or "",
            "rows_count": latest_upload.get("rows_count") or 0,
            "unique_imsi_count": latest_upload.get("unique_imsi_count") or 0,
            "unique_imei_count": latest_upload.get("unique_imei_count") or 0,
            "hash_sha256": latest_upload.get("hash_sha256") or "",
        },
        "visible_sample_count": len(sample),
        "sample_by_provider": dict(by_provider),
        "whitelist_matches_count": len(matches),
        "whitelist_matches_by_kind": dict(by_match_kind),
        "available_reports": [
            "informe_contraste_data_externa_vs_lista_blanca",
            "informe_data_externa_depurada_sin_history",
            "informe_data_externa_depurada_con_histories_seleccionados",
        ],
        "hard_limit": "Nunca tratar Data Externa como autorizado final ni usarla para excluir registros. Solo Lista Blanca actual puede excluir; Data Externa se informa como contraste/depuracion.",
    }


SIGMA_ALLOWED_TERMS = {
    "sigma", "objetivo", "objetivos", "requerimiento", "requerimientos", "persona", "perdida",
    "septier", "guardian", "backpack", "history", "histories", "imsi", "imei", "telefono",
    "celular", "deteccion", "detecciones", "informe", "informes", "hash", "sha", "evidencia",
    "imagen", "imagenes", "geomatrix", "coordenada", "coordenadas", "antena", "antenas",
    "lac", "cell", "cid", "red", "redes", "telefonia", "mcc", "mnc", "skyeye", "drone",
    "drones", "run", "corrida", "corridas", "lista", "blanca", "autorizado", "autorizados",
    "seguridad", "mfa", "usuario", "usuarios", "login", "acceso", "bloqueo", "telegram",
    "ingenieria", "radio", "rf", "banda", "bandas", "frecuencia", "frecuencias",
    "nexa", "suite", "forense", "mapeo", "tactico", "getac", "timeline", "log", "logs",
    "manual", "manuales", "documentacion", "documental", "operativo", "operativa", "procedimiento",
    "data", "externa", "postgres", "depurada", "contraste", "prestataria", "prestatarias",
    "desconocida", "externo", "externos", "filtro", "filtrar", "depurar",
}


def _sigma_is_authorized_question(message: str) -> bool:
    tokens = set(re.findall(r"[a-zA-Z0-9_áéíóúñÁÉÍÓÚÑ]+", message.lower()))
    if tokens & SIGMA_ALLOWED_TERMS:
        return True
    digits = _digits_only(message)
    return len(digits) >= 5


def _sigma_compact_context(objective_id: Optional[int] = None, sigma_query: str = "") -> Dict[str, object]:
    objectives_payload = _sigma_objectives_payload()
    external_data_payload = _sigma_external_data_payload()
    selected_objective: Dict[str, object] = {}
    if objective_id:
        objective = get_septier_objective(objective_id)
        if objective:
            cross = _objective_cross_summary(objective)
            reports = api_list_septier_objective_reports(objective_id, user={"username": "sigma_context"}).get("items", [])
            images = api_list_septier_objective_images(objective_id, user={"username": "sigma_context"}).get("items", [])
            selected_objective = {
                "objective": objective,
                "cross": cross,
                "reports": reports,
                "images": images,
            }
    recent_runs = list_runs()[:5]
    latest_reports = list_informes_generados(limit=10)
    network_refs = list_septier_network_refs(limit=40)
    tower_refs = list_tower_catalog(limit=40)
    whitelist_items = list_whitelist()
    nexa_runs = _nexa_list_runs(limit=10)
    manual_matches = _nexa_search_manuals(sigma_query, limit=5)
    context = {
        "allowed_scope": [
            "SkyEye", "Septier Guardian/Backpack", "objetivos/requerimientos", "IMSI", "IMEI",
            "telefono", "LAC", "CELL ID", "antenas", "redes y telefonia", "Geomatrix",
            "informes", "hashes", "evidencias", "lista blanca", "seguridad de acceso",
            "NEXA Suite Forense", "RF Analyzer", "mapeo tactico Guardian/GETAC",
            "Manual operativo Septier/NEXA cargado y auditado",
            "Data Externa Postgres como segunda capa de filtro Septier",
        ],
        "current_app_data": {
            "objectives": objectives_payload,
            "external_data_postgres": external_data_payload,
            "selected_objective": selected_objective,
            "recent_skyeye_runs": recent_runs,
            "recent_septier_reports": latest_reports,
            "network_refs_sample": network_refs,
            "tower_catalog_sample": tower_refs,
            "whitelist_count": len(whitelist_items),
            "nexa_recent_runs": nexa_runs,
            "nexa_manual_matches": manual_matches,
        },
        "hard_limits": [
            "No responder fuera del alcance autorizado.",
            "No inventar datos no presentes en current_app_data.",
            "Si falta informacion, declararlo como faltante.",
            "Para Data Externa Postgres: listar solo cargas, conteos y coincidencias verificables del contexto.",
            "Las coincidencias de Data Externa son referencia de contraste; no excluyen registros del informe final.",
            "Si la consulta depende de un manual, responder solo con nexa_manual_matches y citar manual/pagina/hash.",
            "Separar verificado, observacion, faltante y siguiente paso.",
            "No dar instrucciones ofensivas, evasivas, intrusivas o externas al sistema.",
        ],
    }
    text = json.dumps(context, ensure_ascii=False, default=str)
    if len(text) > SIGMA_MAX_CONTEXT_CHARS:
        text = text[:SIGMA_MAX_CONTEXT_CHARS] + "\n...CONTEXTO RECORTADO POR LIMITE..."
    return {"json": text, "truncated": len(json.dumps(context, ensure_ascii=False, default=str)) > SIGMA_MAX_CONTEXT_CHARS}


def _extract_openai_output_text(payload: Dict[str, object]) -> str:
    direct = str(payload.get("output_text") or "").strip()
    if direct:
        return direct
    chunks: List[str] = []
    for item in payload.get("output", []) or []:
        if not isinstance(item, dict):
            continue
        for content in item.get("content", []) or []:
            if isinstance(content, dict):
                text = str(content.get("text") or "").strip()
                if text:
                    chunks.append(text)
    return "\n".join(chunks).strip()


def _call_openai_responses(instructions: str, user_input: str) -> Tuple[str, Dict[str, object]]:
    if not OPENAI_API_KEY:
        raise HTTPException(status_code=503, detail="SIGMA no tiene OPENAI_API_KEY configurada en Render")
    body = {
        "model": SIGMA_OPENAI_MODEL,
        "instructions": instructions,
        "input": user_input,
    }
    request = urllib.request.Request(
        "https://api.openai.com/v1/responses",
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {OPENAI_API_KEY}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=45) as response:
            raw = response.read().decode("utf-8", errors="replace")
            payload = json.loads(raw)
            text = _extract_openai_output_text(payload)
            return text or "SIGMA no obtuvo texto de respuesta del proveedor IA.", payload
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:1000]
        raise HTTPException(status_code=502, detail=f"OpenAI rechazo la consulta: {detail}")
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"No se pudo contactar OpenAI: {exc}")


def _sigma_norm_text(value: object) -> str:
    text = str(value or "").lower()
    replacements = str.maketrans("áéíóúüñ", "aeiouun")
    return text.translate(replacements)


def _sigma_local_response(answer: str, mode: str, source: str = "") -> Dict[str, object]:
    return {
        "ok": True,
        "configured": bool(OPENAI_API_KEY),
        "model": SIGMA_OPENAI_MODEL,
        "answer": answer,
        "mode": mode,
        "source": source,
        "context_truncated": False,
    }


def _sigma_local_septier_answer(user: Dict[str, object]) -> Dict[str, object]:
    try:
        metrics = operations_metrics(user=user).get("septier", {})
    except Exception:
        metrics = {}
    guardian_count = len(list(GUARDIAN_DIR.glob("*.csv")))
    backpack_count = len(list(BACKPACK_DIR.glob("*.csv")))
    total_histories = guardian_count + backpack_count
    answer = "\n".join([
        "Verificado: SIGMA lee Septier con datos internos actuales.",
        f"Guardian: {guardian_count} history(s) cargado(s).",
        f"Backpack: {backpack_count} history(s) cargado(s).",
        f"Operativos / histories totales: {total_histories}.",
        f"Detecciones leidas: {metrics.get('detecciones_brutas', 0)}.",
        f"Coincidencias con Lista Blanca actual: {metrics.get('coincidentes_lista_blanca', metrics.get('excluidos_lista_blanca', 0))}.",
        f"No coincidentes para revision: {metrics.get('no_coincidentes', metrics.get('detecciones_netas', 0))}.",
        f"IMSI no coincidentes: {metrics.get('imsi_unicos_netos', 0)}.",
        f"IMEI no coincidentes: {metrics.get('imei_unicos_netos', 0)}.",
        "Observacion: estos conteos usan Lista Blanca actual por IMSI/IMEI y consolidan duplicados por identidad tecnica.",
        "Siguiente paso: si vas a consolidar, asigna lugar operativo a los histories y selecciona los bloques correspondientes.",
    ])
    return _sigma_local_response(answer, "local_evidence_septier", "operations_metrics + septier_directories")


def _latest_septier_history_file() -> Optional[Dict[str, object]]:
    candidates: List[Dict[str, object]] = []
    for system_name, base_dir in [("guardian", GUARDIAN_DIR), ("backpack", BACKPACK_DIR)]:
        base_dir.mkdir(parents=True, exist_ok=True)
        for path in base_dir.glob("*.csv"):
            if not path.is_file():
                continue
            candidates.append({
                "system": system_name,
                "file": path.name,
                "path": path,
                "modified_at": dt.datetime.fromtimestamp(path.stat().st_mtime).isoformat(timespec="seconds"),
                "mtime": path.stat().st_mtime,
                "size": path.stat().st_size,
                "sha256": _nexa_hash_file(path),
            })
    if not candidates:
        return None
    return sorted(candidates, key=lambda item: float(item.get("mtime") or 0), reverse=True)[0]


def _sigma_local_latest_septier_history_answer(user: Dict[str, object]) -> Dict[str, object]:
    latest = _latest_septier_history_file()
    if not latest:
        return _sigma_local_response(
            "No hay histories Guardian/Backpack cargados para auditar.",
            "local_evidence_latest_septier_history",
            "septier_directories",
        )

    file_payload = [{"system": str(latest["system"]), "file": str(latest["file"])}]
    rows = get_septier_forensic_rows_by_files(file_payload)
    identity_memory = _septier_identity_memory()
    resolved_rows = [_with_resolved_septier_identity(row, identity_memory) for row in rows]
    whitelist = _whitelist_identity_set()
    net_rows = [
        row for row in resolved_rows
        if not _is_whitelisted_identity(row.get("imsi_mac"), row.get("imei"), whitelist)
    ]
    raw_imsi = {_id15(row.get("imsi_mac")) for row in resolved_rows if len(_id15(row.get("imsi_mac"))) == 15}
    raw_imei = {_id15(row.get("imei")) for row in resolved_rows if len(_id15(row.get("imei"))) == 15}
    net_imsi = {_id15(row.get("imsi_mac")) for row in net_rows if len(_id15(row.get("imsi_mac"))) == 15}
    net_imei = {_id15(row.get("imei")) for row in net_rows if len(_id15(row.get("imei"))) == 15}
    whitelisted_count = max(len(resolved_rows) - len(net_rows), 0)
    answer = "\n".join([
        "SIGMA IA | ultimo_history_septier | evidencia local verificada",
        f"Ultimo history detectado: {latest['system'].upper()} - {latest['file']}.",
        f"Modificado/subido: {latest.get('modified_at')}.",
        f"SHA-256: {latest.get('sha256')}.",
        f"Detecciones brutas del archivo: {len(resolved_rows)}.",
        f"IMSI unicos leidos: {len(raw_imsi)}.",
        f"IMEI unicos leidos: {len(raw_imei)}.",
        f"Excluidos por Lista Blanca actual: {whitelisted_count}.",
        f"Detecciones netas: {len(net_rows)}.",
        f"IMSI unicos netos: {len(net_imsi)}.",
        f"IMEI unicos netos: {len(net_imei)}.",
        "Observacion: esta respuesta corresponde solo al ultimo history cargado, no al acumulado general de Septier.",
    ])
    return _sigma_local_response(answer, "local_evidence_latest_septier_history", "septier_latest_history + whitelist_actual")


def _sigma_local_skyeye_answer(user: Dict[str, object]) -> Dict[str, object]:
    try:
        metrics = operations_metrics(user=user).get("skyeye", {})
    except Exception:
        metrics = {}
    answer = "\n".join([
        "Verificado: SIGMA lee SkyEye con datos internos actuales.",
        f"Operativos / corridas: {metrics.get('operativos', 0)}.",
        f"Detecciones: {metrics.get('detecciones', 0)}.",
        f"Device ID unicos: {metrics.get('device_ids', 0)}.",
        f"Modelos detectados: {metrics.get('modelos', 0)}.",
        f"Sensores informados: {metrics.get('sensores', 0)}.",
        f"Dias operativos indexados: {metrics.get('dias_operativos', 0)}.",
        f"Dias con actividad en ultima corrida: {metrics.get('dias_actividad_ultima_corrida', metrics.get('dias_actividad', 0))}.",
        "Observacion: si se necesita trayectoria individual, el informe debe generarse sobre el archivo o seleccion especifica del Device ID.",
    ])
    return _sigma_local_response(answer, "local_evidence_skyeye", "operations_metrics")


def _sigma_local_objectives_answer() -> Dict[str, object]:
    payload = _sigma_objectives_payload()
    counts = payload.get("counts", {}) if isinstance(payload, dict) else {}
    items = payload.get("items", []) if isinstance(payload, dict) else []
    ready = [item for item in items if isinstance(item, dict) and item.get("ready_for_report")]
    missing = [
        item for item in items
        if isinstance(item, dict) and not str(item.get("imsi") or "").strip() and not str(item.get("imei") or "").strip()
    ]
    reported = [item for item in items if isinstance(item, dict) and int(item.get("reports_count") or 0) > 0]

    def _objective_label(item: Dict[str, object]) -> str:
        name = str(item.get("person_name") or item.get("case_number") or "").strip() or "Sin nombre/caso"
        return f"#{item.get('id', '')} {name}".strip()

    ready_lines = [_objective_label(item) for item in ready[:10]]
    missing_lines = [_objective_label(item) for item in missing[:10]]
    report_lines = [
        f"{_objective_label(item)} | informes: {item.get('reports_count', 0)} | hash: {item.get('latest_report_hash') or 'sin hash'}"
        for item in reported[:8]
    ]
    answer_lines = [
        "Verificado: SIGMA lee objetivos desde septier_objectives, objective_history y objective_reports.",
        f"Objetivos totales: {counts.get('total', 0)}.",
        f"Pendientes / en analisis: {counts.get('pending', 0)}.",
        f"Sin IMSI/IMEI: {counts.get('missing_imsi_imei', 0)}.",
        f"Sin history especifico: {counts.get('without_history', 0)}.",
        f"Con coincidencias: {counts.get('with_matches', 0)}.",
        f"Listos para informe: {counts.get('ready_for_report', 0)}.",
        f"Con informe generado: {counts.get('with_report', 0)}.",
    ]
    if ready_lines:
        answer_lines.extend(["", "Objetivos listos para informe:"] + [f"- {line}" for line in ready_lines])
    else:
        answer_lines.extend(["", "Objetivos listos para informe: no hay objetivos listos con coincidencias verificables."])
    if missing_lines:
        answer_lines.extend(["", "Faltantes criticos: objetivos sin IMSI/IMEI:"] + [f"- {line}" for line in missing_lines])
    if report_lines:
        answer_lines.extend(["", "Informes con hash registrados:"] + [f"- {line}" for line in report_lines])
    answer_lines.append("Siguiente paso: completar IMSI/IMEI o asociar histories antes de generar el informe cuando falten datos.")
    return _sigma_local_response("\n".join(answer_lines), "local_evidence_objectives", str(payload.get("source") or "objectives"))


def _sigma_local_external_data_answer() -> Dict[str, object]:
    payload = _sigma_external_data_payload()
    latest = payload.get("latest_upload", {}) if isinstance(payload, dict) else {}
    answer = "\n".join([
        "Verificado: SIGMA lee Data Externa Postgres como segunda capa de contraste.",
        str(payload.get("rule") or ""),
        f"Cargas registradas: {payload.get('uploads_count', 0)}.",
        f"Ultima carga: {latest.get('original_filename') or 'sin carga registrada'}.",
        f"Filas ultima carga: {latest.get('rows_count', 0)}.",
        f"IMSI unicos ultima carga: {latest.get('unique_imsi_count', 0)}.",
        f"IMEI unicos ultima carga: {latest.get('unique_imei_count', 0)}.",
        f"Coincidencias contra Lista Blanca actual: {payload.get('whitelist_matches_count', 0)}.",
        f"Por tipo: {payload.get('whitelist_matches_by_kind', {})}.",
        "Limite operativo: Data Externa no autoriza ni excluye por si sola en informes Septier; solo documenta contraste/depuracion.",
    ])
    return _sigma_local_response(answer, "local_evidence_data_externa", "external_identity_data + whitelist_actual")


def _sigma_local_case_answer(user: Dict[str, object]) -> Dict[str, object]:
    try:
        status_payload = case_status(user=user)
        metrics_payload = operations_metrics(user=user)
    except Exception:
        status_payload = {}
        metrics_payload = {}
    septier_status = status_payload.get("septier", {}) if isinstance(status_payload, dict) else {}
    whitelist_status = status_payload.get("whitelist", {}) if isinstance(status_payload, dict) else {}
    reports_status = status_payload.get("reports", {}) if isinstance(status_payload, dict) else {}
    septier_metrics = metrics_payload.get("septier", {}) if isinstance(metrics_payload, dict) else {}
    skyeye_metrics = metrics_payload.get("skyeye", {}) if isinstance(metrics_payload, dict) else {}
    answer = "\n".join([
        "Verificado: estado operativo general del sistema.",
        f"Septier histories: {septier_status.get('total_histories', 0)} | Guardian: {septier_status.get('guardian_csv', 0)} | Backpack: {septier_status.get('backpack_csv', 0)}.",
        f"Septier no coincidentes: {septier_metrics.get('no_coincidentes', 0)} | IMSI no coincidentes: {septier_metrics.get('imsi_unicos_netos', 0)} | IMEI no coincidentes: {septier_metrics.get('imei_unicos_netos', 0)}.",
        f"SkyEye corridas: {skyeye_metrics.get('operativos', 0)} | detecciones: {skyeye_metrics.get('detecciones', 0)} | Device ID: {skyeye_metrics.get('device_ids', 0)}.",
        f"Lista Blanca activa: {whitelist_status.get('devices', 0)} dispositivos/identidades registradas.",
        f"Informes recientes registrados: {reports_status.get('latest_count', 0)}.",
        "Siguiente paso: indicame si queres profundizar en Septier, SkyEye, objetivos, Data Externa o informes con hash.",
    ])
    return _sigma_local_response(answer, "local_evidence_case_status", "case_status + operations_metrics")


def _sigma_local_answer(message: str, user: Dict[str, object]) -> Optional[Dict[str, object]]:
    norm = _sigma_norm_text(message)
    if any(term in norm for term in ["objetivo", "objetivos", "requerimiento", "requerimientos", "listos para informe"]):
        return _sigma_local_objectives_answer()
    if any(term in norm for term in ["data externa", "postgres", "data depurada", "prestataria", "prestatarias"]):
        return _sigma_local_external_data_answer()
    if any(term in norm for term in ["skyeye", "drone", "drones", "device id", "corrida"]):
        return _sigma_local_skyeye_answer(user)
    if any(term in norm for term in ["ultimo history", "ultimo archivo", "recien subi", "recien subido", "acabo de subir", "ultima carga"]):
        if any(term in norm for term in ["septier", "guardian", "backpack", "history", "imsi", "imei"]):
            return _sigma_local_latest_septier_history_answer(user)
    if any(term in norm for term in ["septier", "guardian", "backpack", "history", "histories", "imsi", "imei"]):
        return _sigma_local_septier_answer(user)
    if any(term in norm for term in ["estado", "actualmente", "que hay", "hay cargado", "disponible", "disponibles"]):
        return _sigma_local_case_answer(user)
    return None


@app.post("/api/sigma/chat")
def api_sigma_chat(payload: SigmaChatRequest, user=Depends(_require_auth)):
    try:
        message = str(payload.message or "").strip()
        if not message:
            raise HTTPException(status_code=400, detail="Escribe una consulta para SIGMA")
        if not _sigma_is_authorized_question(message):
            return {
                "ok": True,
                "configured": bool(OPENAI_API_KEY),
                "model": SIGMA_OPENAI_MODEL,
                "answer": "No tengo permitido responder esa consulta. Solo puedo hablar sobre datos autorizados del sistema: SkyEye, Septier, objetivos, informes, antenas, redes/telefonia, evidencias, hashes, lista blanca y seguridad de acceso.",
                "mode": "blocked_by_scope",
            }

        local_answer = _sigma_local_answer(message, user)
        if local_answer:
            _record_security_event_safe(
                "sigma_chat_local",
                str(user.get("username") or ""),
                f"consulta_sigma_local mode={local_answer.get('mode')} chars={len(message)}",
                severity="info",
            )
            return local_answer

        context = _sigma_compact_context(payload.objective_id, sigma_query=message)
        instructions = (
            "Sos SIGMA IA, asistente operativo interno de Detection of Signals. "
            "Reglas obligatorias: responde solo con el CONTEXTO AUTORIZADO provisto por el sistema; "
            "nunca inventes datos, coordenadas, identidades, hashes, fechas, redes o conclusiones. "
            "Si la consulta pide algo fuera del alcance autorizado, responde exactamente que no tenes permitido responder esa consulta. "
            "Si el dato no existe en el contexto, deci 'No hay dato verificable cargado'. "
            "No uses conocimiento externo salvo para explicar conceptos tecnicos generales de redes/telefonia/radiofrecuencia cuando no agreguen hechos del caso. "
            "No modifiques datos ni indiques que ejecutaste acciones. "
            "Formato preferido: Verificado, Observacion, Faltante, Siguiente paso. "
            "Tono: profesional, claro, prudente, en espanol."
        )
        user_input = (
            "CONTEXTO AUTORIZADO DEL SISTEMA:\n"
            f"{context['json']}\n\n"
            "CONSULTA DEL USUARIO:\n"
            f"{message}"
        )
        answer, raw_payload = _call_openai_responses(instructions, user_input)
        _record_security_event_safe(
            "sigma_chat",
            str(user.get("username") or ""),
            f"consulta_sigma model={SIGMA_OPENAI_MODEL} chars={len(message)} truncated={context.get('truncated')}",
            severity="info",
        )
        return {
            "ok": True,
            "configured": True,
            "model": SIGMA_OPENAI_MODEL,
            "answer": answer,
            "mode": "evidence_chat",
            "context_truncated": bool(context.get("truncated")),
            "response_id": raw_payload.get("id") if isinstance(raw_payload, dict) else "",
        }
    except HTTPException as exc:
        try:
            local_answer = _sigma_local_answer(str(payload.message or ""), user)
            if local_answer:
                local_answer["provider_warning"] = str(exc.detail)[:300]
                local_answer["answer"] = (
                    str(local_answer.get("answer") or "")
                    + "\n\nObservacion: el motor generativo no respondio; SIGMA emitio esta lectura con datos internos verificables."
                )
                return local_answer
        except Exception:
            pass
        raise
    except Exception as exc:
        return {
            "ok": False,
            "configured": bool(OPENAI_API_KEY),
            "model": SIGMA_OPENAI_MODEL,
            "answer": f"SIGMA no pudo completar la consulta con datos verificables. Detalle tecnico: {exc}",
            "mode": "error",
            "context_truncated": False,
        }


@app.get("/api/septier/reports")
def septier_reports(limit: int = 100, user=Depends(_require_auth)):
    return {"items": list_informes_generados(limit=limit)}


@app.get("/api/case/status")
def case_status(user=Depends(_require_auth)):
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    SKYEYE_GENERAL_DIR.mkdir(parents=True, exist_ok=True)
    GUARDIAN_DIR.mkdir(parents=True, exist_ok=True)
    BACKPACK_DIR.mkdir(parents=True, exist_ok=True)
    OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)

    def _count_csvs(base: Path) -> int:
        return len(list(base.glob("*.csv")))

    def _latest_file(base: Path, pattern: str) -> Optional[Dict[str, object]]:
        files = sorted(base.glob(pattern), key=lambda x: x.stat().st_mtime, reverse=True)
        if not files:
            return None
        p = files[0]
        return {
            "name": p.name,
            "size": p.stat().st_size,
            "modified_at": dt.datetime.fromtimestamp(p.stat().st_mtime).isoformat(timespec="seconds"),
        }

    whitelist_rows = list_whitelist()
    whitelist_by_type: Dict[str, int] = {}
    for row in whitelist_rows:
        device_type = str(row.get("device_type") or "sin_tipo").strip().lower() or "sin_tipo"
        whitelist_by_type[device_type] = whitelist_by_type.get(device_type, 0) + 1

    uploads = list_whitelist_uploads(limit=500)
    active_uploads = [u for u in uploads if not u.get("deleted_at")]
    reports = list_informes_generados(limit=10)
    latest_report = reports[0] if reports else None

    forensic_csvs = sorted(
        OUTPUTS_DIR.glob("consulta_maestra_forense_*.csv"),
        key=lambda x: x.stat().st_mtime,
        reverse=True,
    )

    return {
        "skyeye": {
            "inbox_csv": _count_csvs(REPORTS_DIR),
            "processed_csv": len(list(PROCESSED_DIR.rglob("*.csv"))),
            "general_csv": _count_csvs(SKYEYE_GENERAL_DIR),
            "latest_inbox": _latest_file(REPORTS_DIR, "*.csv"),
        },
        "septier": {
            "guardian_csv": _count_csvs(GUARDIAN_DIR),
            "backpack_csv": _count_csvs(BACKPACK_DIR),
            "total_histories": _count_csvs(GUARDIAN_DIR) + _count_csvs(BACKPACK_DIR),
        },
        "whitelist": {
            "devices": len(whitelist_rows),
            "by_type": whitelist_by_type,
            "uploads_active": len(active_uploads),
            "uploads_total": len(uploads),
        },
        "forensic_master": {
            "csv_count": len(forensic_csvs),
            "latest_csv": _latest_file(OUTPUTS_DIR, "consulta_maestra_forense_*.csv"),
        },
        "reports": {
            "latest_count": len(reports),
            "latest": latest_report,
        },
    }


@app.get("/api/operations/metrics")
def operations_metrics(user=Depends(_require_auth)):
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    GUARDIAN_DIR.mkdir(parents=True, exist_ok=True)
    BACKPACK_DIR.mkdir(parents=True, exist_ok=True)

    septier_files_by_key: Dict[str, Dict[str, str]] = {}
    for p in GUARDIAN_DIR.glob("*.csv"):
        septier_files_by_key[f"guardian|{p.name}"] = {"system": "guardian", "file": p.name}
    for p in BACKPACK_DIR.glob("*.csv"):
        septier_files_by_key[f"backpack|{p.name}"] = {"system": "backpack", "file": p.name}
    for item in list_septier_uploaded_files_from_db():
        system_name = str(item.get("source") or item.get("system") or "").strip().lower()
        filename = str(item.get("archivo_origen") or item.get("file") or "").strip()
        if system_name in {"guardian", "backpack"} and filename:
            septier_files_by_key.setdefault(f"{system_name}|{filename}", {"system": system_name, "file": filename})
    septier_files = list(septier_files_by_key.values())
    septier_metadata = get_septier_history_metadata_map(septier_files) if septier_files else {}
    whitelist = _whitelist_identity_set()
    septier_rows = get_septier_forensic_rows_by_files(septier_files) if septier_files else []
    identity_memory = _septier_identity_memory()
    septier_rows_resolved = [_with_resolved_septier_identity(row, identity_memory) for row in septier_rows]
    septier_net_rows: List[Dict[str, Any]] = []
    septier_raw_by_day: Counter[str] = Counter()
    septier_net_by_day: Counter[str] = Counter()
    septier_hourly: Counter[str] = Counter()
    septier_by_history: Dict[str, Dict[str, Any]] = {}
    septier_whitelisted_keys = set()
    septier_net_keys = set()
    septier_all_imsi = set()
    septier_all_imei = set()
    septier_imsi = set()
    septier_imei = set()
    septier_net_identity_profiles: Dict[str, Dict[str, str]] = {}
    septier_penitentiary: Dict[str, Dict[str, Any]] = {}
    septier_day_place: Dict[str, Dict[str, Any]] = {}

    for row in septier_rows_resolved:
        seen_at = _parse_dt_value(row.get("last_update"))
        day_key = seen_at.strftime("%Y-%m-%d") if seen_at else "Sin fecha"
        hour_key = seen_at.strftime("%H:00") if seen_at else "Sin hora"
        history_key = f"{str(row.get('source') or '').lower()}|{row.get('archivo_origen') or ''}"
        meta = septier_metadata.get(history_key) or {}
        place_text = meta.get("lugar_operativo") or meta.get("complejo") or row.get("location") or ""
        place_bucket = _septier_place_bucket(place_text)
        place_entry = septier_penitentiary.setdefault(
            place_bucket,
            {
                "lugar": place_bucket,
                "operativos": set(),
                "detecciones_brutas": 0,
                "identidades_netas": set(),
                "imsi_unicos_netos": set(),
                "imei_unicos_netos": set(),
                "lista_blanca": set(),
            },
        )
        history_entry = septier_by_history.setdefault(
            history_key,
            {
                "source": str(row.get("source") or "").lower(),
                "file": row.get("archivo_origen") or "",
                "fecha_operativo": day_key,
                "detecciones_brutas": 0,
                "detecciones_netas": 0,
                "imsi_unicos_netos": 0,
                "imei_unicos_netos": 0,
                "excluidos_lista_blanca": 0,
                "_net_keys": set(),
                "_wl_keys": set(),
                "_imsi": set(),
                "_imei": set(),
            },
        )
        if seen_at and history_entry.get("fecha_operativo") in ("Sin fecha", day_key):
            history_entry["fecha_operativo"] = day_key

        septier_raw_by_day[day_key] += 1
        history_entry["detecciones_brutas"] = int(history_entry["detecciones_brutas"]) + 1
        if _septier_is_penitentiary_bucket(place_bucket):
            place_entry["operativos"].add(history_key)
            place_entry["detecciones_brutas"] = int(place_entry["detecciones_brutas"]) + 1

        identity_key = _operational_identity_key(row.get("imsi_mac"), row.get("imei"))
        has_identity = identity_key != "raw:|"
        if not has_identity:
            continue

        raw_imsi_key = _id15(row.get("imsi_mac"))
        raw_imei_key = _id15(row.get("imei"))
        if len(raw_imsi_key) == 15:
            septier_all_imsi.add(raw_imsi_key)
        if len(raw_imei_key) == 15:
            septier_all_imei.add(raw_imei_key)

        if _is_whitelisted_identity(row.get("imsi_mac"), row.get("imei"), whitelist):
            septier_whitelisted_keys.add(identity_key)
            history_entry["_wl_keys"].add(identity_key)
            if _septier_is_penitentiary_bucket(place_bucket):
                place_entry["lista_blanca"].add(identity_key)
            continue

        septier_net_rows.append(row)
        septier_net_keys.add(identity_key)
        history_entry["_net_keys"].add(identity_key)
        septier_net_by_day[day_key] += 1
        septier_hourly[hour_key] += 1
        if identity_key not in septier_net_identity_profiles:
            septier_net_identity_profiles[identity_key] = {
                "prestataria": _external_provider_bucket(_carrier_from_imsi_value(raw_imsi_key)),
                "modelo": str(row.get("model") or "").strip() or "SIN MODELO",
            }
        if _septier_is_penitentiary_bucket(place_bucket):
            place_entry["identidades_netas"].add(identity_key)
            day_place_key = f"{day_key}|{place_bucket}"
            day_place_entry = septier_day_place.setdefault(
                day_place_key,
                {
                    "fecha_operativo": day_key,
                    "lugar": place_bucket,
                    "operativos": set(),
                    "identidades_netas": set(),
                    "imsi_unicos_netos": set(),
                    "imei_unicos_netos": set(),
                },
            )
            day_place_entry["operativos"].add(history_key)
            day_place_entry["identidades_netas"].add(identity_key)

        imsi_key = raw_imsi_key
        imei_key = raw_imei_key
        if len(imsi_key) == 15:
            septier_imsi.add(imsi_key)
            history_entry["_imsi"].add(imsi_key)
            if _septier_is_penitentiary_bucket(place_bucket):
                place_entry["imsi_unicos_netos"].add(imsi_key)
                day_place_entry["imsi_unicos_netos"].add(imsi_key)
        if len(imei_key) == 15:
            septier_imei.add(imei_key)
            history_entry["_imei"].add(imei_key)
            if _septier_is_penitentiary_bucket(place_bucket):
                place_entry["imei_unicos_netos"].add(imei_key)
                day_place_entry["imei_unicos_netos"].add(imei_key)

    septier_history_series = []
    for item in septier_by_history.values():
        item["detecciones_netas"] = len(item.pop("_net_keys"))
        item["excluidos_lista_blanca"] = len(item.pop("_wl_keys"))
        item["imsi_unicos_netos"] = len(item.pop("_imsi"))
        item["imei_unicos_netos"] = len(item.pop("_imei"))
        septier_history_series.append(item)
    septier_history_series.sort(key=lambda x: (str(x.get("fecha_operativo") or ""), str(x.get("source") or ""), str(x.get("file") or "")))
    penitentiary_order = ["SAN FELIPE", "BOULOGNE SUR MER", "ALMAFUERTE I", "ALMAFUERTE II", "SAN RAFAEL"]
    septier_penitentiary_series = []
    for label in penitentiary_order:
        item = septier_penitentiary.get(label)
        if not item:
            continue
        septier_penitentiary_series.append({
            "lugar": label,
            "operativos": len(item["operativos"]),
            "detecciones_brutas": int(item["detecciones_brutas"]),
            "identidades_netas": len(item["identidades_netas"]),
            "imsi_unicos_netos": len(item["imsi_unicos_netos"]),
            "imei_unicos_netos": len(item["imei_unicos_netos"]),
            "lista_blanca": len(item["lista_blanca"]),
        })
    septier_penitentiary_chart = {
        item["lugar"]: item["identidades_netas"]
        for item in septier_penitentiary_series
        if int(item["identidades_netas"]) > 0
    }
    septier_day_place_series = []
    for item in septier_day_place.values():
        septier_day_place_series.append({
            "fecha_operativo": item["fecha_operativo"],
            "lugar": item["lugar"],
            "operativos": len(item["operativos"]),
            "identidades_netas": len(item["identidades_netas"]),
            "imsi_unicos_netos": len(item["imsi_unicos_netos"]),
            "imei_unicos_netos": len(item["imei_unicos_netos"]),
        })
    septier_day_place_series.sort(key=lambda x: (str(x.get("fecha_operativo") or ""), str(x.get("lugar") or "")))
    septier_day_place_chart = {
        f"{item['fecha_operativo']} | {item['lugar']}": item["identidades_netas"]
        for item in septier_day_place_series
        if int(item["identidades_netas"]) > 0
    }
    septier_provider_chart = dict(Counter(
        str(profile.get("prestataria") or "DESCONOCIDA")
        for profile in septier_net_identity_profiles.values()
    ))
    septier_model_chart = dict(Counter(
        str(profile.get("modelo") or "SIN MODELO")
        for profile in septier_net_identity_profiles.values()
    ).most_common(12))
    septier_mutation_cases_total = 0
    septier_mutation_alerts_total = 0
    septier_mutation_unauthorized = 0
    if os.getenv("SKYEYE_METRICS_INCLUDE_SWAP_SUMMARY", "").strip().lower() in {"1", "true", "yes"}:
        try:
            septier_mutation_summary = _septier_mutation_summary_from_rows(septier_rows)
            septier_mutation_cases_total = int(septier_mutation_summary.get("cases_total") or 0)
            septier_mutation_alerts_total = int(septier_mutation_summary.get("alerts_total") or 0)
            septier_mutation_unauthorized = int(septier_mutation_summary.get("unauthorized_cases") or 0)
        except Exception as exc:
            print(f"No se pudo calcular resumen swap en metricas operativas: {exc}")

    skyeye_runs = list_runs()
    latest_skyeye_run = skyeye_runs[0] if skyeye_runs else None
    skyeye_total_detections = 0
    skyeye_drone_models = set()
    skyeye_device_ids = set()
    skyeye_sensors = set()
    skyeye_activity_days = set()
    skyeye_operational_days = set()
    skyeye_enemy = 0
    for run in skyeye_runs:
        try:
            run_df = _skyeye_read_csv(run.get("input_detection_csv"))
            if "Detect Time" not in run_df.columns:
                continue
            for value in run_df["Detect Time"].fillna("").astype(str).str.strip():
                if not value:
                    continue
                try:
                    parsed = dt.datetime.fromisoformat(value.replace(".", "-"))
                    skyeye_operational_days.add(parsed.strftime("%Y-%m-%d"))
                except Exception:
                    continue
        except Exception:
            continue
    if latest_skyeye_run:
        try:
            df = _skyeye_read_csv(latest_skyeye_run.get("input_detection_csv"))
            if "Source" in df.columns:
                source_series = df["Source"].fillna("").astype(str).str.strip().str.lower()
            else:
                source_series = None
            skyeye_total_detections = len(df)
            if "Model" in df.columns:
                if source_series is not None:
                    models = df.loc[source_series == "drone", "Model"]
                else:
                    models = df["Model"]
                skyeye_drone_models = {str(v).strip() for v in models.dropna().tolist() if str(v).strip()}
            if "Device ID" in df.columns:
                skyeye_device_ids = {str(v).strip() for v in df["Device ID"].dropna().tolist() if str(v).strip()}
            if "Sensor" in df.columns:
                skyeye_sensors = {str(v).strip() for v in df["Sensor"].dropna().tolist() if str(v).strip()}
            if "Detect Time" in df.columns:
                times = df["Detect Time"].fillna("").astype(str).str.strip()
                for value in times:
                    if not value:
                        continue
                    try:
                        parsed = dt.datetime.fromisoformat(value.replace(".", "-"))
                        skyeye_activity_days.add(parsed.strftime("%Y-%m-%d"))
                    except Exception:
                        continue
            if "tag" in df.columns:
                skyeye_enemy = int((df["tag"].fillna("").astype(str).str.strip().str.lower() == "enemy").sum())
        except Exception:
            pass

    return {
        "septier": {
            "operativos": len(septier_files),
            "detecciones_brutas": len(septier_rows),
            "imsi_unicos": len(septier_imsi),
            "imei_unicos": len(septier_imei),
            "coincidentes_lista_blanca": len(septier_whitelisted_keys),
            "no_coincidentes": len(septier_net_keys),
            "detecciones_sin_lista_blanca": len(septier_net_rows),
            "detecciones_netas": len(septier_net_keys),
            "imsi_unicos_netos": len(septier_imsi),
            "imei_unicos_netos": len(septier_imei),
            "excluidos_lista_blanca": len(septier_whitelisted_keys),
            "por_dia_brutas": dict(sorted(septier_raw_by_day.items())),
            "por_dia_netas": dict(sorted(septier_net_by_day.items())),
            "por_hora_netas": dict(sorted(septier_hourly.items())),
            "por_history": septier_history_series,
            "por_lugar_penitenciario": septier_penitentiary_series,
            "por_lugar_penitenciario_netas": septier_penitentiary_chart,
            "por_dia_lugar_penitenciario": septier_day_place_series,
            "por_dia_lugar_penitenciario_netas": septier_day_place_chart,
            "por_prestadora_no_coincidente": septier_provider_chart,
            "por_modelo_no_coincidente": septier_model_chart,
            "criticos_sin_lista_blanca": len(septier_net_keys),
            "mutaciones": septier_mutation_alerts_total,
            "mutaciones_unicas_total": septier_mutation_cases_total,
            "mutaciones_detalle_total": septier_mutation_alerts_total,
            "mutaciones_no_autorizadas": septier_mutation_unauthorized,
            "mutaciones_detalle": [],
            "swaps_memoria_total": septier_mutation_cases_total,
            "swaps_memoria_detalle": septier_mutation_alerts_total,
            "swaps_memoria_muestra": 0,
            "swaps_memoria_muestra_limit": 0,
        },
        "skyeye": {
            "operativos": len(skyeye_runs),
            "detecciones": skyeye_total_detections,
            "detecciones_ultima_corrida": skyeye_total_detections,
            "device_ids": len(skyeye_device_ids),
            "modelos": len(skyeye_drone_models),
            "sensores": len(skyeye_sensors),
            "dias_actividad": len(skyeye_activity_days),
            "dias_actividad_ultima_corrida": len(skyeye_activity_days),
            "dias_operativos": len(skyeye_operational_days),
            "enemigos": skyeye_enemy,
        },
    }


@app.get("/api/operations/metrics/septier-swaps")
def operations_metrics_septier_swaps(user=Depends(_require_auth)):
    GUARDIAN_DIR.mkdir(parents=True, exist_ok=True)
    BACKPACK_DIR.mkdir(parents=True, exist_ok=True)

    septier_files_by_key: Dict[str, Dict[str, str]] = {}
    for p in GUARDIAN_DIR.glob("*.csv"):
        septier_files_by_key[f"guardian|{p.name}"] = {"system": "guardian", "file": p.name}
    for p in BACKPACK_DIR.glob("*.csv"):
        septier_files_by_key[f"backpack|{p.name}"] = {"system": "backpack", "file": p.name}
    for item in list_septier_uploaded_files_from_db():
        system_name = str(item.get("source") or item.get("system") or "").strip().lower()
        filename = str(item.get("archivo_origen") or item.get("file") or "").strip()
        if system_name in {"guardian", "backpack"} and filename:
            septier_files_by_key.setdefault(f"{system_name}|{filename}", {"system": system_name, "file": filename})

    septier_files = list(septier_files_by_key.values())
    septier_rows = get_septier_forensic_rows_by_files(septier_files) if septier_files else []
    summary = _septier_mutation_summary_from_rows(septier_rows)
    alerts = _septier_mutation_alerts_from_rows(septier_rows, limit=0)
    return {
        "ok": True,
        "total_cases": int(summary.get("cases_total") or 0),
        "total_details": int(summary.get("alerts_total") or len(alerts)),
        "unauthorized_cases": int(summary.get("unauthorized_cases") or 0),
        "items": alerts,
    }


@app.get("/api/septier/file/{system_name}/{filename}")
def septier_file_details(system_name: str, filename: str, user=Depends(_require_auth)):
    return get_septier_file_stats(filename, system_name.lower())


@app.post("/api/septier/audit")
def septier_audit(payload: AuditReportRequest, user=Depends(_require_auth)):
    files = [{"system": f.system, "file": f.file} for f in payload.files]
    return _build_septier_audit_result(files, ignore_memory=payload.ignore_memory)


@app.post("/api/septier/forensic-master")
def septier_forensic_master(payload: ForensicMasterRequest, user=Depends(_require_auth)):
    files = [{"system": f.system, "file": f.file} for f in payload.files]
    if not files:
        raise HTTPException(status_code=400, detail="Selecciona al menos un archivo Septier.")

    source_rows = get_septier_forensic_rows_by_files(files)
    if not source_rows:
        raise HTTPException(status_code=404, detail="No hay detecciones cargadas para los archivos seleccionados.")
    identity_memory = _septier_identity_memory()
    selected_rows = [_with_resolved_septier_identity(row, identity_memory) for row in source_rows]

    whitelist_norm = _whitelist_identity_set()

    history_rows = get_septier_identity_history()
    first_seen_by_key: Dict[str, dt.datetime] = {}
    imei_counts_by_imsi: Dict[str, Dict[str, int]] = {}
    for row in history_rows:
        imsi_key = _id15(row.get("imsi_mac"))
        imei_key = _id15(row.get("imei"))
        seen_at = _parse_dt_value(row.get("last_update"))
        keys = [k for k in (imsi_key, imei_key) if len(k) == 15]
        for key in keys:
            if seen_at and (key not in first_seen_by_key or seen_at < first_seen_by_key[key]):
                first_seen_by_key[key] = seen_at
        if len(imsi_key) == 15 and len(imei_key) == 15:
            counts = imei_counts_by_imsi.setdefault(imsi_key, {})
            counts[imei_key] = counts.get(imei_key, 0) + 1

    selected_dates = [_parse_dt_value(r.get("last_update")) for r in selected_rows]
    selected_dates = [d for d in selected_dates if d is not None]
    operation_floor = min(selected_dates).replace(hour=0, minute=0, second=0, microsecond=0) if selected_dates else None

    groups: Dict[str, Dict[str, object]] = {}
    excluded = 0
    raw_count = 0
    for row in selected_rows:
        imsi = _id15(row.get("imsi_mac"))
        imei = _id15(row.get("imei"))
        if len(imsi) != 15 and len(imei) != 15:
            continue
        raw_count += 1

        is_whitelisted = _is_whitelisted_identity(imsi, imei, whitelist_norm)
        if is_whitelisted:
            excluded += 1
            continue

        key = imsi if len(imsi) == 15 else imei
        seen_at = _parse_dt_value(row.get("last_update")) or dt.datetime.min
        current = groups.setdefault(
            key,
            {
                "imsi": imsi if len(imsi) == 15 else "--- S/D ---",
                "imei": imei if len(imei) == 15 else "",
                "model": "",
                "orig_lac": "",
                "multipolygon": "",
                "pings": 0,
                "latest_at": dt.datetime.min,
                "latest_raw_at": "",
            },
        )
        current["pings"] = int(current.get("pings") or 0) + 1
        if seen_at >= current.get("latest_at", dt.datetime.min):
            current["latest_at"] = seen_at
            current["latest_raw_at"] = row.get("last_update") or ""
            current["model"] = str(row.get("model") or "").strip()
            current["orig_lac"] = str(row.get("orig_lac") or "").strip()
            current["multipolygon"] = str(row.get("multipolygon") or "").strip()
            if len(imei) == 15:
                current["imei"] = imei

    csv_rows = []
    for key, group in groups.items():
        imsi = str(group.get("imsi") or "--- S/D ---")
        imei = str(group.get("imei") or "").strip()
        if not imei and imsi != "--- S/D ---":
            counts = imei_counts_by_imsi.get(imsi, {})
            if counts:
                imei = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]
        imei = imei or "--- S/D ---"

        first_seen = first_seen_by_key.get(imsi) if imsi != "--- S/D ---" else None
        if first_seen is None:
            first_seen = first_seen_by_key.get(key)
        latest_raw = group.get("latest_raw_at") or ""
        condition = "NUEVO"
        if operation_floor and first_seen and first_seen < operation_floor:
            condition = "REINCIDENTE HISTORICO"

        latitud, longitud = _centroid_from_wkt(group.get("multipolygon"))
        csv_rows.append({
            "prestataria": _carrier_from_imsi_value(imsi),
            "imsi": imsi,
            "imei": imei,
            "modelo": str(group.get("model") or "").strip() or "Generico",
            "condicion_objetivo": condition,
            "pings": int(group.get("pings") or 0),
            "orig_lac": str(group.get("orig_lac") or "").strip() or "--- S/D ---",
            "primer_avistamiento_historico": first_seen.strftime("%Y-%m-%d %H:%M:%S") if first_seen else "--- S/D ---",
            "ultimo_avistamiento_archivo": _format_forensic_dt(latest_raw),
            "latitud": latitud,
            "longitud": longitud,
            "multipolygon": str(group.get("multipolygon") or "").strip() or "--- S/D ---",
        })

    csv_rows.sort(key=lambda r: (str(r["prestataria"]), -int(r["pings"]), str(r["imsi"])))

    fields = [
        "prestataria",
        "imsi",
        "imei",
        "modelo",
        "condicion_objetivo",
        "pings",
        "orig_lac",
        "primer_avistamiento_historico",
        "ultimo_avistamiento_archivo",
        "latitud",
        "longitud",
        "multipolygon",
    ]
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    out_name = f"consulta_maestra_forense_{stamp}.csv"
    out_path = OUTPUTS_DIR / out_name
    OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields, delimiter=";")
        writer.writeheader()
        writer.writerows(csv_rows)
        writer.writerow({
            "prestataria": ">> CONTROL",
            "imsi": ">> TOTAL NETO DISPOSITIVOS EXTERNOS ENCONTRADOS",
            "imei": len(csv_rows),
            "modelo": "----------------",
            "condicion_objetivo": "----------------",
            "pings": sum(int(r["pings"]) for r in csv_rows),
            "orig_lac": "----------------",
            "primer_avistamiento_historico": "----------------",
            "ultimo_avistamiento_archivo": "----------------",
            "latitud": "----------------",
            "longitud": "----------------",
            "multipolygon": "----------------",
        })

    return {
        "ok": True,
        "download_url": f"/outputs/{out_name}",
        "total": len(csv_rows),
        "pings": sum(int(r["pings"]) for r in csv_rows),
        "raw_rows": raw_count,
        "excluded_whitelist": excluded,
        "files": files,
    }


def _septier_monthly_report_generate(payload: GenerateReportRequest, user: Dict[str, object]) -> Dict[str, object]:
    files_payload = [{"system": f.system, "file": f.file} for f in payload.files]
    audit_result = _build_septier_audit_result(files_payload, ignore_memory=False)
    audit_whitelist_discards = [
        r for r in audit_result.get("descartados", [])
        if r.get("whitelist_matches") or r.get("whitelist_source") or r.get("whitelist_match_by")
    ]
    audit_memory_discards = [
        r for r in audit_result.get("descartados", [])
        if str(r.get("reason") or "") == "Ya informado"
    ]
    audit_mutations = list(audit_result.get("mutaciones", []))

    source_rows = get_septier_forensic_rows_by_files([{"system": f.system, "file": f.file} for f in payload.files])
    if not source_rows:
        raise HTTPException(status_code=400, detail="No hay detecciones Septier para los operativos seleccionados")

    whitelist = _whitelist_identity_set()
    if not whitelist:
        raise HTTPException(
            status_code=400,
            detail="Informe operativo requiere Lista Blanca activa para depurar IMSI/IMEI antes de generar.",
        )
    identity_memory = _septier_identity_memory()
    excluded_whitelist_rows: List[Dict[str, object]] = []
    rows: List[Dict[str, object]] = []
    resolved_source_rows: List[Dict[str, object]] = []
    for source_row in source_rows:
        resolved_row = _with_resolved_septier_identity(source_row, identity_memory)
        resolved_source_rows.append(resolved_row)
        if _is_whitelisted_identity(resolved_row.get("imsi_mac"), resolved_row.get("imei"), whitelist):
            excluded_whitelist_rows.append(resolved_row)
        else:
            rows.append(resolved_row)

    def e(value: object) -> str:
        return html_lib.escape(str(value if value is not None else ""))

    def carrier_from_imsi(imsi_value: str) -> str:
        digits = _digits_only(imsi_value)
        if digits.startswith(("72231", "72232", "72233")):
            return "CLARO"
        if digits.startswith(("72201", "72207")):
            return "MOVISTAR"
        if digits.startswith(("72234", "72203", "72235")):
            return "PERSONAL"
        return "DESCONOCIDA"

    def fmt_dt(value: object) -> str:
        if not value:
            return "-"
        text = str(value)
        try:
            parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00")[:19])
            return parsed.strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return text[:19]

    lugar_nombre = payload.lugar.nombre.strip() or "Complejo no informado"
    mes_informe_raw = payload.lugar.mes.strip()
    lugar_escaneo = payload.lugar.lugar_escaneo.strip() or "Sector no informado"
    ubicacion_escaneo = payload.lugar.ubicacion_escaneo.strip() or "Ubicacion no informada"
    coordenadas = payload.lugar.coordenadas.strip() or "No informadas"
    modulos = payload.lugar.modulos.strip() or "Modulo no informado"
    ala = payload.lugar.ala.strip() or "Ala / sector no informado"
    personal = [p for p in payload.personal if p.nombre.strip()]
    personal_text = " | ".join(
        f"{p.nombre.strip()} - {p.titulo.strip()}" if p.titulo.strip() else p.nombre.strip()
        for p in personal
    ) or str(user.get("full_name") or user.get("username") or "-")

    def fmt_month(value: str) -> str:
        value = str(value or "").strip()
        if not value:
            return "Mes no informado"
        months = [
            "ENERO", "FEBRERO", "MARZO", "ABRIL", "MAYO", "JUNIO",
            "JULIO", "AGOSTO", "SEPTIEMBRE", "OCTUBRE", "NOVIEMBRE", "DICIEMBRE",
        ]
        try:
            year, month = value.split("-", 1)
            idx = int(month[:2])
            if 1 <= idx <= 12:
                return f"{months[idx - 1]} {year}"
        except Exception:
            pass
        return value.upper()

    file_hashes: Dict[str, str] = {}
    for f in files_payload:
        file_key = str(f.get("file") or "")
        source_hash = ""
        try:
            path = _septier_uploaded_file_path(FileItem(system=str(f.get("system") or ""), file=file_key))
            if path.exists() and path.is_file():
                source_hash = _nexa_hash_file(path)
        except Exception:
            source_hash = ""
        file_hashes[file_key] = source_hash
    stats_by_file: List[Dict[str, object]] = []
    rows_by_file: Dict[str, List[Dict[str, object]]] = defaultdict(list)
    for row in resolved_source_rows:
        rows_by_file[str(row.get("archivo_origen") or "-")].append(row)
        row_hash = str(row.get("hash_sha256") or "").strip()
        row_file = str(row.get("archivo_origen") or "").strip()
        if row_hash and row_file and not file_hashes.get(row_file):
            file_hashes[row_file] = row_hash
    filtered_rows_by_file: Dict[str, List[Dict[str, object]]] = defaultdict(list)
    for row in rows:
        filtered_rows_by_file[str(row.get("archivo_origen") or "-")].append(row)
    excluded_rows_by_file: Dict[str, List[Dict[str, object]]] = defaultdict(list)
    for row in excluded_whitelist_rows:
        excluded_rows_by_file[str(row.get("archivo_origen") or "-")].append(row)
    audit_whitelist_by_file: Dict[str, List[Dict[str, object]]] = defaultdict(list)
    for row in audit_whitelist_discards:
        audit_whitelist_by_file[str(row.get("archivo_origen") or "-")].append(row)

    monthly_metrics = _septier_whitelist_metrics(resolved_source_rows, rows, excluded_whitelist_rows)
    raw_total_scans = monthly_metrics["detecciones_brutas"]
    excluded_whitelist_rows_count = monthly_metrics["filas_lista_blanca"]
    excluded_whitelist_count = monthly_metrics["coincidencias_lista_blanca"]
    carriers = Counter(carrier_from_imsi(str(r.get("imsi_mac") or "")) for r in rows)
    lac_cell = Counter(
        f"{str(r.get('orig_lac') or '-').strip()} / {str(r.get('cell_id') or '-').strip()}"
        for r in rows
        if str(r.get("orig_lac") or "").strip() or str(r.get("cell_id") or "").strip()
    )
    first_dt = fmt_dt(min((str(r.get("last_update") or "") for r in rows if r.get("last_update")), default=""))
    last_dt = fmt_dt(max((str(r.get("last_update") or "") for r in rows if r.get("last_update")), default=""))

    def unique_identity_count(row_list: List[Dict[str, object]]) -> int:
        keys = set()
        for row in row_list:
            key = _operational_identity_key(row.get("imsi_mac"), row.get("imei"))
            if not (key.startswith("raw:") and key == "raw:|"):
                keys.add(key)
        return len(keys)

    for f in files_payload:
        file_rows = filtered_rows_by_file.get(str(f.get("file") or ""), [])
        file_excluded = excluded_rows_by_file.get(str(f.get("file") or ""), [])
        file_source_rows = rows_by_file.get(str(f.get("file") or ""), [])
        file_carriers = Counter(carrier_from_imsi(str(r.get("imsi_mac") or "")) for r in file_rows)
        file_metrics = _septier_whitelist_metrics(file_source_rows, file_rows, file_excluded)
        stats_by_file.append({
            "system": str(f.get("system") or "").upper(),
            "file": str(f.get("file") or ""),
            "raw_rows": file_metrics["detecciones_brutas"],
            "unique_detections": file_metrics["detecciones_sin_duplicar"],
            "excluded_whitelist": file_metrics["coincidencias_lista_blanca"],
            "excluded_whitelist_rows": file_metrics["filas_lista_blanca"],
            "imsi_read": file_metrics["imsi_leidos"],
            "imsi_excluded": file_metrics["imsi_excluidos_lb"],
            "unique_imsi": file_metrics["imsi_netos"],
            "imei_read": file_metrics["imei_leidos"],
            "imei_excluded": file_metrics["imei_excluidos_lb"],
            "unique_imei": file_metrics["imei_netos"],
            "first": fmt_dt(min((str(r.get("last_update") or "") for r in file_rows if r.get("last_update")), default="")),
            "last": fmt_dt(max((str(r.get("last_update") or "") for r in file_rows if r.get("last_update")), default="")),
            "carriers": dict(file_carriers),
            "hash_sha256": file_hashes.get(str(f.get("file") or ""), ""),
        })

    device_groups: Dict[Tuple[str, str, str, str], Dict[str, object]] = {}
    for r in rows:
        imsi_value = str(r.get("imsi_mac") or "").strip() or "-"
        imei_value = str(r.get("imei") or "").strip() or "-"
        model_value = str(r.get("model") or "").strip() or "-"
        carrier = carrier_from_imsi(imsi_value)
        key = (carrier, imsi_value, imei_value, model_value)
        item = device_groups.setdefault(key, {
            "carrier": carrier,
            "imsi": imsi_value,
            "imei": imei_value,
            "model": model_value,
            "scans": 0,
            "histories": set(),
            "first_raw": "",
            "last_raw": "",
            "lac_cell": Counter(),
        })
        item["scans"] = int(item.get("scans") or 0) + 1
        history_name = str(r.get("archivo_origen") or "").strip()
        if history_name:
            item["histories"].add(history_name)
        raw_dt = str(r.get("last_update") or "").strip()
        if raw_dt:
            if not item.get("first_raw") or raw_dt < str(item.get("first_raw") or ""):
                item["first_raw"] = raw_dt
            if not item.get("last_raw") or raw_dt > str(item.get("last_raw") or ""):
                item["last_raw"] = raw_dt
        lac = str(r.get("orig_lac") or "").strip()
        cell = str(r.get("cell_id") or "").strip()
        if lac or cell:
            item["lac_cell"][f"{lac or '-'} / {cell or '-'}"] += 1

    carrier_order = {"CLARO": 1, "MOVISTAR": 2, "PERSONAL": 3, "DESCONOCIDA": 4, "OTROS": 5}
    devices_by_carrier: Dict[str, List[Dict[str, object]]] = defaultdict(list)
    for item in device_groups.values():
        devices_by_carrier[str(item.get("carrier") or "DESCONOCIDA")].append(item)
    for carrier, devices in devices_by_carrier.items():
        devices.sort(key=lambda d: (-int(d.get("scans") or 0), str(d.get("imsi") or ""), str(d.get("imei") or "")))

    carrier_rows = "".join(
        f"<tr><td>{e(k)}</td><td>{v}</td><td>{len(devices_by_carrier.get(k, []))}</td></tr>"
        for k, v in sorted(carriers.items(), key=lambda item: (-item[1], item[0]))
    ) or "<tr><td colspan='3'>Sin prestataria inferible</td></tr>"
    lac_rows = "".join(
        f"<tr><td>{e(k)}</td><td>{v}</td></tr>"
        for k, v in lac_cell.most_common(30)
    ) or "<tr><td colspan='2'>El history no informa LAC/CELL ID verificable</td></tr>"
    file_rows_html = "".join(
        "<tr>"
        f"<td>{e(item['system'])}</td><td>{e(item['file'])}<br><span class='hash'>SHA-256: {e(str(item.get('hash_sha256') or '-')[:64])}</span></td><td>{e(item.get('raw_rows') or 0)}</td>"
        f"<td>{e(item.get('unique_detections') or 0)}</td>"
        f"<td>{e(item.get('excluded_whitelist') or 0)}</td>"
        f"<td>{e(item.get('imsi_read') or 0)}</td><td>{e(item['unique_imsi'])}</td>"
        f"<td>{e(item.get('imei_read') or 0)}</td><td>{e(item['unique_imei'])}</td>"
        f"<td>{e(item['first'])}</td><td>{e(item['last'])}</td>"
        f"<td>{e(', '.join(f'{k}: {v}' for k, v in item['carriers'].items()) or '-')}</td>"
        "</tr>"
        for item in stats_by_file
    )

    def audit_identity_rows_html(items: List[Dict[str, object]], source_kind: str) -> str:
        rows_html = []
        for item in items:
            if source_kind == "whitelist":
                source = str(item.get("whitelist_source") or "Lista Blanca actual")
                match_by = str(item.get("whitelist_match_by") or "identidad")
            elif source_kind == "memory":
                source = str(item.get("memory_source") or "Memoria Sellada")
                match_by = "Memoria Forense"
            else:
                source = str(item.get("memory_source") or "-")
                match_by = "Mutacion"
            if source_kind == "mutation":
                rows_html.append(
                    "<tr>"
                    f"<td>{e(item.get('imsi_mac') or '-')}</td>"
                    f"<td>{e(item.get('imei') or '-')}</td>"
                    f"<td>{e(item.get('reason') or '-')}</td>"
                    f"<td>{e(match_by)}</td>"
                    f"<td>{e(item.get('previous_identity_value') or '-')}</td>"
                    f"<td>{e(source)}</td>"
                    f"<td>{e(item.get('model') or '-')}</td>"
                    f"<td>{e(item.get('archivo_origen') or '-')}</td>"
                    "</tr>"
                )
            else:
                rows_html.append(
                    "<tr>"
                    f"<td>{e(item.get('imsi_mac') or '-')}</td>"
                    f"<td>{e(item.get('imei') or '-')}</td>"
                    f"<td>{e(item.get('reason') or '-')}</td>"
                    f"<td>{e(match_by)}</td>"
                    f"<td>{e(source)}</td>"
                    f"<td>{e(item.get('model') or '-')}</td>"
                    f"<td>{e(item.get('archivo_origen') or '-')}</td>"
                    "</tr>"
                )
        colspan = 8 if source_kind == "mutation" else 7
        return "".join(rows_html) or f"<tr><td colspan='{colspan}'>Sin registros para este criterio.</td></tr>"

    whitelist_detail_html = audit_identity_rows_html(audit_whitelist_discards, "whitelist")
    memory_detail_html = audit_identity_rows_html(audit_memory_discards, "memory")
    mutation_detail_html = audit_identity_rows_html(audit_mutations, "mutation")
    carrier_sections_parts: List[str] = []
    for carrier in sorted(devices_by_carrier.keys(), key=lambda c: (carrier_order.get(c, 99), c)):
        devices = devices_by_carrier[carrier]
        scans_count = int(carriers.get(carrier, 0))
        device_rows = "".join(
            "<tr>"
            f"<td>{e(d.get('imsi') or '-')}</td>"
            f"<td>{e(d.get('imei') or '-')}</td>"
            f"<td>{e(d.get('model') or '-')}</td>"
            f"<td>{e(d.get('scans') or 0)}</td>"
            f"<td>{e(fmt_dt(d.get('first_raw')))}</td>"
            f"<td>{e(fmt_dt(d.get('last_raw')))}</td>"
            f"<td>{e(', '.join(sorted(d.get('histories') or [])) or '-')}</td>"
            f"<td>{e(', '.join(f'{k}: {v}' for k, v in (d.get('lac_cell') or Counter()).most_common(8)) or '-')}</td>"
            "</tr>"
            for d in devices
        ) or "<tr><td colspan='8'>Sin dispositivos para esta prestataria</td></tr>"
        carrier_sections_parts.append(
            f"""
<section class="carrier-section">
  <h2>{e(carrier)} - Dispositivos detectados</h2>
  <div class="carrier-total">
    <strong>Total {e(carrier)}:</strong> {len(devices)} dispositivo(s) unico(s) | {scans_count} deteccion(es) | History(s) vinculados: {len(set().union(*(d.get('histories') or set() for d in devices))) if devices else 0}
  </div>
  <table>
    <thead><tr><th>IMSI / MAC</th><th>IMEI</th><th>Modelo</th><th>Pings</th><th>Primera deteccion</th><th>Ultima deteccion</th><th>History(s)</th><th>LAC / CELL ID</th></tr></thead>
    <tbody>{device_rows}</tbody>
  </table>
</section>"""
        )
    carrier_sections = "".join(carrier_sections_parts) or "<div class='card'>Sin dispositivos agrupables por prestadora.</div>"
    unique_detections_total = monthly_metrics["identidades_finales"]

    ahora = dt.datetime.now(dt.timezone(dt.timedelta(hours=-3)))
    stamp = ahora.strftime("%Y%m%d_%H%M%S")
    num_informe = f"INF-OPERATIVO-{stamp}"
    numero_nota = next_numero_nota(ahora.year)
    out_dir = OUTPUTS_DIR / "informes_septier_mensuales"
    out_dir.mkdir(parents=True, exist_ok=True)
    base_name = f"informe_operativo_septier_{numero_nota:02d}_{stamp}"
    html_path = out_dir / f"{base_name}.html"
    word_path = out_dir / f"{base_name}.doc"

    html = f"""<!doctype html>
<html lang="es"><head><meta charset="utf-8">
<title>Informe Operativo Septier</title>
<style>
body {{ font-family: Arial, sans-serif; color:#061827; margin:24px; }}
h1, h2 {{ color:#003e68; }} h1 {{ font-size:30px; margin-bottom:4px; }}
.sub {{ color:#334155; font-weight:700; margin:2px 0; }}
.meta, .card {{ border:1px solid #c9d7e8; border-radius:8px; padding:12px; margin:12px 0; }}
.grid {{ display:grid; grid-template-columns:repeat(auto-fit, minmax(180px, 1fr)); gap:12px; margin:14px 0; }}
.metric {{ border:1px solid #c9d7e8; border-radius:8px; padding:12px; background:#f7fbff; }}
.metric strong {{ display:block; color:#003e68; font-size:26px; }}
table {{ border-collapse:collapse; width:100%; margin:12px 0; font-size:12px; }}
th, td {{ border:1px solid #c9d7e8; padding:7px; text-align:left; vertical-align:top; }}
th {{ background:#eaf2fb; color:#001b35; }}
.rule {{ background:#f6f9fc; border-left:4px solid #0077b6; padding:10px 12px; }}
.hash {{ color:#475569; font-family:Consolas, monospace; font-size:10px; word-break:break-all; }}
.carrier-section {{ page-break-inside:auto; margin-top:22px; }}
.carrier-total {{ border:1px solid #c9d7e8; border-left:4px solid #003e68; border-radius:8px; padding:10px 12px; background:#f7fbff; color:#061827; }}
@media print {{ .grid {{ grid-template-columns:repeat(2, 1fr); }} }}
</style></head><body>
<h1>Informe Operativo Septier</h1>
<div class="sub">DEPARTAMENTO DE TECNOLOGIAS ESPECIALES Y DESPLIEGUE TACTICO</div>
<div class="sub">SUBSECRETARIA DE TECNOLOGIA APLICADA A LA SEGURIDAD</div>
<div class="sub">MINISTERIO DE SEGURIDAD Y JUSTICIA</div>
<div class="meta">
<strong>Mes informado:</strong> {e(fmt_month(mes_informe_raw))}<br>
<strong>Nota:</strong> {numero_nota:02d}/{ahora.year} | <strong>Informe:</strong> {e(num_informe)} | <strong>Generado:</strong> {e(ahora.strftime('%Y-%m-%d %H:%M:%S'))}<br>
<strong>Usuario:</strong> {e(user.get('full_name') or user.get('username'))} | <strong>Personal:</strong> {e(personal_text)}
</div>
<h2>Marco Tecnologico Utilizado</h2>
<div class="rule">
El sistema Septier permite capturar y registrar eventos radioelectricos asociados a dispositivos celulares observados durante un relevamiento operativo.
Cada archivo history representa una fuente documental del sistema, Guardian o Backpack, y sus filas constituyen detecciones registradas por el equipamiento.
El presente informe consolida exclusivamente datos contenidos en los histories seleccionados y cruces disponibles en la plataforma. No se infieren titulares,
ubicaciones ni identidades no presentes en la evidencia cargada.
</div>
<h2>Datos del Relevamiento</h2>
<table><tbody>
<tr><th>Mes</th><td>{e(fmt_month(mes_informe_raw))}</td><th>Complejo</th><td>{e(lugar_nombre)}</td></tr>
<tr><th>Modulo(s)</th><td>{e(modulos)}</td><th>Ala / sector</th><td>{e(ala)}</td></tr>
<tr><th>Lugar de escaneo</th><td>{e(lugar_escaneo)}</td><th>Ubicacion</th><td>{e(ubicacion_escaneo)}</td></tr>
<tr><th>Coordenadas</th><td>{e(coordenadas)}</td><th>Periodo detectado</th><td>{e(first_dt)} a {e(last_dt)}</td></tr>
</tbody></table>
<div class="grid">
<div class="metric"><strong>{raw_total_scans}</strong>Detecciones brutas</div>
<div class="metric"><strong>{monthly_metrics["detecciones_sin_duplicar"]}</strong>Identidades leidas sin duplicar</div>
<div class="metric"><strong>{monthly_metrics["no_coincidentes"]}</strong>No coincidentes</div>
<div class="metric"><strong>{excluded_whitelist_count}</strong>Coincidencias Lista Blanca</div>
<div class="metric"><strong>{monthly_metrics["imsi_leidos"]}</strong>IMSI leidos</div>
<div class="metric"><strong>{monthly_metrics["imsi_netos"]}</strong>IMSI no coincidentes</div>
<div class="metric"><strong>{monthly_metrics["imei_leidos"]}</strong>IMEI leidos</div>
<div class="metric"><strong>{monthly_metrics["imei_netos"]}</strong>IMEI no coincidentes</div>
<div class="metric"><strong>{len(stats_by_file)}</strong>History(s) consolidados</div>
</div>
<h2>Resumen por History / Modulo</h2>
<table><thead><tr><th>Sistema</th><th>History / Hash SHA-256</th><th>Detecciones brutas</th><th>Identidades leidas sin duplicar</th><th>Coincidencias LB</th><th>IMSI leidos</th><th>IMSI no coincidentes</th><th>IMEI leidos</th><th>IMEI no coincidentes</th><th>Primera deteccion</th><th>Ultima deteccion</th><th>Prestatarias no coincidentes</th></tr></thead><tbody>{file_rows_html}</tbody></table>
<h2>Identidades excluidas por Lista Blanca</h2>
<div class="card">Se listan identidades unicas descartadas por coincidencia exacta con Lista Blanca actual. Las filas repetidas del history quedan depuradas, pero aqui se informa la identidad y la fuente de Lista Blanca correspondiente.</div>
<table><thead><tr><th>IMSI / MAC</th><th>IMEI</th><th>Razon</th><th>Coincidencia</th><th>Lista Blanca / Fuente</th><th>Modelo</th><th>History actual</th></tr></thead><tbody>{whitelist_detail_html}</tbody></table>
<h2>Identidades ya informadas</h2>
<div class="card">Registros descartados por Memoria Sellada. La columna de referencia indica el informe y/o history donde ya constaba la identidad.</div>
<table><thead><tr><th>IMSI / MAC</th><th>IMEI</th><th>Razon</th><th>Criterio</th><th>Referencia anterior</th><th>Modelo</th><th>History actual</th></tr></thead><tbody>{memory_detail_html}</tbody></table>
<h2>Mutaciones detectadas</h2>
<div class="card">Cambios operativos relevantes, como nuevo IMEI para IMSI conocido o nuevo IMSI sobre IMEI conocido. No se eliminan automaticamente: quedan visibles para revision.</div>
<table><thead><tr><th>IMSI / MAC</th><th>IMEI</th><th>Razon</th><th>Criterio</th><th>Valor anterior conocido</th><th>Referencia anterior</th><th>Modelo</th><th>History actual</th></tr></thead><tbody>{mutation_detail_html}</tbody></table>
<h2>Resumen por Prestataria</h2>
<table><thead><tr><th>Prestataria</th><th>Detecciones</th><th>Dispositivos unicos</th></tr></thead><tbody>{carrier_rows}</tbody></table>
<h2>Resumen LAC / CELL ID</h2>
<table><thead><tr><th>LAC / CELL ID</th><th>Detecciones</th></tr></thead><tbody>{lac_rows}</tbody></table>
<h2>Detalle por Prestataria</h2>
{carrier_sections}
<h2>Observaciones Operativas</h2>
<div class="card">Control obligatorio aplicado: antes de consolidar el informe se excluyeron coincidencias con Lista Blanca actual por IMSI o IMEI. Las detecciones brutas son las filas leidas del CSV. Las identidades leidas sin duplicar agrupan por IMSI cuando existe; si no existe IMSI, agrupan por IMEI. No coincidentes es el universo que queda para revision operativa despues del cruce con Lista Blanca. Control de coincidencias con Lista Blanca: {excluded_whitelist_rows_count} fila(s) del history.</div>
</body></html>"""
    html_path.write_text(html, encoding="utf-8")
    word_css = """
@page Section1 { size: 841.95pt 595.35pt; margin: 22pt 22pt 24pt 22pt; }
div.Section1 { page: Section1; }
body { margin: 8px; font-size: 10px; }
h1 { font-size: 22px; margin-bottom: 2px; }
h2 { font-size: 15px; margin: 12px 0 6px; page-break-after: avoid; }
.sub { font-size: 10px; }
.meta, .card, .rule { padding: 8px; margin: 8px 0; }
.grid { display: block; }
.metric { display: inline-block; width: 22%; min-height: 42px; margin: 0 4px 6px 0; padding: 7px; vertical-align: top; }
.metric strong { font-size: 18px; }
table { font-size: 8px; table-layout: fixed; width: 100%; margin: 7px 0; }
th, td { padding: 3px; word-break: break-word; overflow-wrap: anywhere; }
.hash { font-size: 7px; }
.carrier-section { page-break-inside: auto; }
.carrier-total { padding: 6px 8px; margin-bottom: 4px; }
"""
    word_html = html.replace("</style>", f"{word_css}\n</style>", 1)
    word_html = word_html.replace("<body>", "<body><div class=\"Section1\">", 1).replace("</body>", "</div></body>", 1)
    word_path.write_text(word_html, encoding="utf-8")
    digest = hashlib.sha256(html.encode("utf-8")).hexdigest()

    insert_informe_generado({
        "numero_nota": numero_nota,
        "anio": ahora.year,
        "numero_informe": num_informe,
        "tipo": "mensual",
        "usuario": user.get("full_name") or user.get("username"),
        "archivos": [{"system": f.system, "file": f.file} for f in payload.files],
        "objetivos_count": unique_detections_total,
        "download_url": _skyeye_output_url(word_path),
    })
    return {
        "ok": True,
        "download_url": _skyeye_output_url(word_path),
        "html_url": _skyeye_output_url(html_path),
        "numero_nota": numero_nota,
        "numero_informe": num_informe,
        "hash_sha256": digest,
        "total_escaneos": unique_detections_total,
        "total_bruto": raw_total_scans,
        "excluidos_lista_blanca": excluded_whitelist_count,
    }


@app.post("/api/septier/report/consolidated/preview")
def septier_consolidated_report_preview(payload: SeptierConsolidatedReportRequest, user=Depends(_require_auth)):
    effective_files = _effective_consolidated_files(payload)
    files_payload = [{"system": f.system, "file": f.file} for f in effective_files]
    source_rows = get_septier_forensic_rows_by_files(files_payload) if files_payload else []
    whitelist = _whitelist_identity_set()
    identity_memory = _septier_identity_memory()
    rows_by_file: Dict[Tuple[str, str], List[Dict[str, object]]] = defaultdict(list)
    for row in source_rows:
        rows_by_file[(str(row.get("source") or "").lower(), str(row.get("archivo_origen") or ""))].append(row)

    blocks = payload.bloques or [SeptierConsolidatedBlockItem(nombre="Bloque 01", files=effective_files)]
    block_payload = []
    summary = {
        "histories": 0,
        "raw_count": 0,
        "excluded": 0,
        "excluded_whitelist": 0,
        "net_count": 0,
        "raw_imsi": 0,
        "raw_imei": 0,
        "net_imsi": set(),
        "net_imei": set(),
        "devices": set(),
    }

    for idx, block in enumerate(blocks, start=1):
        block_files = block.files or []
        if not block_files:
            continue
        block_source_rows: List[Dict[str, object]] = []
        block_net_rows: List[Dict[str, object]] = []
        block_whitelist_rows: List[Dict[str, object]] = []
        for file_item in block_files:
            file_key = (str(file_item.system or "").lower(), str(file_item.file or ""))
            for row in rows_by_file.get(file_key, []):
                resolved_row = _with_resolved_septier_identity(row, identity_memory)
                block_source_rows.append(resolved_row)
                if whitelist and _is_whitelisted_identity(resolved_row.get("imsi_mac"), resolved_row.get("imei"), whitelist):
                    block_whitelist_rows.append(resolved_row)
                    continue
                block_net_rows.append(resolved_row)
        block_metrics = _septier_whitelist_metrics(block_source_rows, block_net_rows, block_whitelist_rows)

        summary["histories"] += len(block_files)
        summary["raw_count"] += block_metrics["detecciones_brutas"]
        summary["excluded"] += block_metrics["filas_lista_blanca"]
        summary["excluded_whitelist"] += block_metrics["coincidencias_lista_blanca"]
        summary["net_count"] += block_metrics["detecciones_finales"]
        summary["raw_imsi"] += block_metrics["imsi_leidos"]
        summary["raw_imei"] += block_metrics["imei_leidos"]
        summary["net_imsi"].update(_septier_identity_sets(block_net_rows)["imsi"])
        summary["net_imei"].update(_septier_identity_sets(block_net_rows)["imei"])
        summary["devices"].update(_septier_identity_sets(block_net_rows)["identities"])
        block_payload.append({
            "index": idx,
            "ui_index": block.ui_index,
            "nombre": block.nombre.strip() or f"Bloque {idx:02d}",
            "histories": len(block_files),
            "raw_count": block_metrics["detecciones_brutas"],
            "unique_count": block_metrics["detecciones_sin_duplicar"],
            "excluded": block_metrics["filas_lista_blanca"],
            "excluded_whitelist": block_metrics["coincidencias_lista_blanca"],
            "net_count": block_metrics["detecciones_finales"],
            "raw_imsi": block_metrics["imsi_leidos"],
            "excluded_imsi": block_metrics["imsi_excluidos_lb"],
            "raw_imei": block_metrics["imei_leidos"],
            "excluded_imei": block_metrics["imei_excluidos_lb"],
            "net_imsi": block_metrics["imsi_netos"],
            "net_imei": block_metrics["imei_netos"],
            "devices": block_metrics["identidades_finales"],
        })

    return {
        "ok": True,
        "whitelist_active": bool(whitelist),
        "summary": {
            "histories": summary["histories"],
            "raw_count": summary["raw_count"],
            "unique_count": len(summary["devices"]) + summary["excluded_whitelist"],
            "excluded": summary["excluded"],
            "excluded_whitelist": summary["excluded_whitelist"],
            "net_count": summary["net_count"],
            "raw_imsi": summary["raw_imsi"],
            "raw_imei": summary["raw_imei"],
            "net_imsi": len(summary["net_imsi"]),
            "net_imei": len(summary["net_imei"]),
            "devices": len(summary["devices"]),
        },
        "blocks": block_payload,
    }


@app.post("/api/septier/report/consolidated")
def septier_consolidated_report_generate(payload: SeptierConsolidatedReportRequest, user=Depends(_require_auth)):
    effective_files = _effective_consolidated_files(payload)
    files_payload = [{"system": f.system, "file": f.file} for f in effective_files]
    source_rows = get_septier_forensic_rows_by_files(files_payload)
    if not source_rows:
        raise HTTPException(status_code=400, detail="No hay detecciones Septier para los operativos seleccionados")

    whitelist = _whitelist_identity_set()
    if not whitelist:
        raise HTTPException(status_code=400, detail="El informe consolidado requiere Lista Blanca activa.")
    identity_memory = _septier_identity_memory()

    def e(value: object) -> str:
        return html_lib.escape(str(value if value is not None else ""))

    def carrier_from_imsi(imsi_value: object) -> str:
        digits = _digits_only(imsi_value)
        if digits.startswith(("72231", "72232", "72233")):
            return "CLARO"
        if digits.startswith(("72201", "72207")):
            return "MOVISTAR"
        if digits.startswith(("72234", "72203", "72235")):
            return "PERSONAL"
        return "DESCONOCIDA"

    def fmt_dt(value: object) -> str:
        parsed = _parse_dt_value(value)
        return parsed.strftime("%Y-%m-%d %H:%M:%S") if parsed else (str(value or "-")[:19] or "-")

    def system_short(value: object) -> str:
        system = str(value or "").strip().lower()
        if system == "guardian":
            return "G"
        if system == "backpack":
            return "BP"
        return system.upper() or "-"

    meta_by_key = {
        (str(m.system or "").lower(), str(m.file or "")): m
        for m in payload.histories
    }
    for idx, block in enumerate(payload.bloques, start=1):
        block_name = block.nombre.strip() or f"Bloque {idx:02d}"
        for file_item in block.files:
            key = (str(file_item.system or "").lower(), str(file_item.file or ""))
            meta_by_key[key] = SeptierHistoryMetaItem(
                system=file_item.system,
                file=file_item.file,
                bloque=block_name,
                complejo=block.complejo,
                lugar=block.lugar,
                modulo=block.modulo,
                ala=block.ala,
                ubicacion=block.ubicacion,
                coordenadas=block.coordenadas,
                observacion=block.observacion,
            )
    rows_by_file: Dict[Tuple[str, str], List[Dict[str, object]]] = defaultdict(list)
    for row in source_rows:
        rows_by_file[(str(row.get("source") or "").lower(), str(row.get("archivo_origen") or ""))].append(row)

    history_word_blocks: List[Dict[str, object]] = []
    place_groups: Dict[str, Dict[str, object]] = {}
    global_groups: Dict[str, Dict[str, object]] = {}
    global_source_rows: List[Dict[str, object]] = []
    global_whitelist_rows: List[Dict[str, object]] = []
    global_net_rows: List[Dict[str, object]] = []

    def place_values(meta: SeptierHistoryMetaItem) -> Dict[str, str]:
        return {
            "bloque": meta.bloque or "",
            "complejo": meta.complejo or payload.lugar.nombre or "No informado",
            "lugar": meta.lugar or payload.lugar.lugar_escaneo or "No informado",
            "modulo": meta.modulo or payload.lugar.modulos or "No informado",
            "ala": meta.ala or payload.lugar.ala or "No informado",
            "ubicacion": meta.ubicacion or payload.lugar.ubicacion_escaneo or "No informada",
            "coordenadas": meta.coordenadas or payload.lugar.coordenadas or "No informadas",
        }

    def place_key_from(values: Dict[str, str]) -> str:
        return "|".join(
            re.sub(r"\s+", " ", str(values.get(field) or "").strip().lower())
            for field in ("bloque", "complejo", "lugar", "modulo", "ala", "ubicacion", "coordenadas")
        )

    def place_title(values: Dict[str, str]) -> str:
        parts = [values.get("bloque"), values.get("complejo"), values.get("lugar"), values.get("modulo"), values.get("ala")]
        return " - ".join(str(p).strip() for p in parts if str(p or "").strip() and str(p).strip() != "No informado") or "Lugar no informado"

    for f in effective_files:
        file_key = (str(f.system or "").lower(), str(f.file or ""))
        meta = meta_by_key.get(file_key) or SeptierHistoryMetaItem(system=f.system, file=f.file)
        place_info = place_values(meta)
        place_key = place_key_from(place_info)
        place_group = place_groups.setdefault(place_key, {
            "title": place_title(place_info),
            "meta": place_info,
            "histories": [],
            "groups": {},
            "source_rows": [],
            "whitelist_rows": [],
            "net_rows": [],
        })
        file_rows_raw = rows_by_file.get(file_key, [])
        file_rows = []
        file_source_resolved: List[Dict[str, object]] = []
        file_whitelist_rows: List[Dict[str, object]] = []
        for row in file_rows_raw:
            resolved_row = _with_resolved_septier_identity(row, identity_memory)
            file_source_resolved.append(resolved_row)
            if _is_whitelisted_identity(resolved_row.get("imsi_mac"), resolved_row.get("imei"), whitelist):
                file_whitelist_rows.append(resolved_row)
                continue
            file_rows.append(resolved_row)
        file_metrics = _septier_whitelist_metrics(file_source_resolved, file_rows, file_whitelist_rows)
        place_group["source_rows"].extend(file_source_resolved)
        place_group["whitelist_rows"].extend(file_whitelist_rows)
        place_group["net_rows"].extend(file_rows)
        global_source_rows.extend(file_source_resolved)
        global_whitelist_rows.extend(file_whitelist_rows)
        global_net_rows.extend(file_rows)

        file_groups: Dict[str, Dict[str, object]] = {}
        for row in file_rows:
            key = _operational_identity_key(row.get("imsi_mac"), row.get("imei"))
            if key.startswith("raw:") and key == "raw:|":
                continue
            for groups in (file_groups, place_group["groups"], global_groups):
                item = groups.setdefault(key, {
                    "imsi": _id15(row.get("imsi_mac")) if len(_id15(row.get("imsi_mac"))) == 15 else "",
                    "imei": "",
                    "imeis": Counter(),
                    "model": "",
                    "carrier": carrier_from_imsi(row.get("imsi_mac")),
                    "pings": 0,
                    "histories": set(),
                    "lac_cell": Counter(),
                    "first_raw": "",
                    "last_raw": "",
                })
                row_imsi = _id15(row.get("imsi_mac"))
                row_imei = _id15(row.get("imei"))
                if len(row_imsi) == 15 and not item.get("imsi"):
                    item["imsi"] = row_imsi
                    item["carrier"] = carrier_from_imsi(row_imsi)
                if len(row_imei) == 15:
                    item["imeis"][row_imei] += 1
                model = str(row.get("model") or "").strip()
                if model:
                    item["model"] = model
                item["pings"] = int(item.get("pings") or 0) + 1
                history_name = str(row.get("archivo_origen") or "").strip()
                if history_name:
                    item["histories"].add(history_name)
                lac = str(row.get("orig_lac") or "").strip()
                cell = str(row.get("cell_id") or "").strip()
                if lac or cell:
                    item["lac_cell"][f"{lac or '-'} / {cell or '-'}"] += 1
                raw_dt = str(row.get("last_update") or "").strip()
                if raw_dt:
                    if not item.get("first_raw") or raw_dt < str(item.get("first_raw") or ""):
                        item["first_raw"] = raw_dt
                    if not item.get("last_raw") or raw_dt > str(item.get("last_raw") or ""):
                        item["last_raw"] = raw_dt

        for groups in (file_groups,):
            for item in groups.values():
                if not item.get("imei") and item.get("imeis"):
                    item["imei"] = sorted(item["imeis"].items(), key=lambda kv: (-kv[1], kv[0]))[0][0]

        devices = sorted(file_groups.values(), key=lambda d: (str(d.get("carrier")), -int(d.get("pings") or 0), str(d.get("imsi") or ""), str(d.get("imei") or "")))
        raw_hash = ""
        try:
            file_path = _septier_uploaded_file_path(FileItem(system=f.system, file=f.file))
            raw_hash = _nexa_hash_file(file_path) if file_path.exists() else ""
        except Exception:
            raw_hash = ""
        history_word_blocks.append({
            "system": system_short(f.system),
            "file": str(f.file or ""),
            "meta": meta,
            "place_key": place_key,
            "hash": raw_hash,
            "raw_count": file_metrics["detecciones_brutas"],
            "unique_count": file_metrics["detecciones_sin_duplicar"],
            "excluded": file_metrics["coincidencias_lista_blanca"],
            "net_count": file_metrics["detecciones_finales"],
            "raw_imsi": file_metrics["imsi_leidos"],
            "excluded_imsi": file_metrics["imsi_excluidos_lb"],
            "net_imsi": file_metrics["imsi_netos"],
            "raw_imei": file_metrics["imei_leidos"],
            "excluded_imei": file_metrics["imei_excluidos_lb"],
            "net_imei": file_metrics["imei_netos"],
            "devices_count": len(file_groups),
            "devices": devices,
        })
        place_group["histories"].append(history_word_blocks[-1])

    for place_group in place_groups.values():
        for item in (place_group.get("groups") or {}).values():
            if not item.get("imei") and item.get("imeis"):
                item["imei"] = sorted(item["imeis"].items(), key=lambda kv: (-kv[1], kv[0]))[0][0]
    for item in global_groups.values():
        if not item.get("imei") and item.get("imeis"):
            item["imei"] = sorted(item["imeis"].items(), key=lambda kv: (-kv[1], kv[0]))[0][0]
    total_net_imsi = len({str(item.get("imsi") or "") for item in global_groups.values() if str(item.get("imsi") or "")})
    total_net_imei = len({str(item.get("imei") or "") for item in global_groups.values() if str(item.get("imei") or "") and str(item.get("imei") or "") != "S/I"})
    global_metrics = _septier_whitelist_metrics(global_source_rows, global_net_rows, global_whitelist_rows)
    carrier_order = {"CLARO": 1, "MOVISTAR": 2, "PERSONAL": 3, "DESCONOCIDA": 4}
    place_sections = []
    for place_group in place_groups.values():
        place_metrics = _septier_whitelist_metrics(
            list(place_group.get("source_rows") or []),
            list(place_group.get("net_rows") or []),
            list(place_group.get("whitelist_rows") or []),
        )
        groups = place_group.get("groups") or {}
        place_by_carrier: Dict[str, List[Dict[str, object]]] = defaultdict(list)
        for item in groups.values():
            place_by_carrier[str(item.get("carrier") or "DESCONOCIDA")].append(item)
        for devices in place_by_carrier.values():
            devices.sort(key=lambda d: (-int(d.get("pings") or 0), str(d.get("imsi") or ""), str(d.get("imei") or "")))
        histories_html = "".join(
            "<tr>"
            f"<td>{e(block.get('system') or '-')}</td><td>{e(block.get('file') or '-')}</td>"
            f"<td>{e(block.get('raw_count') or 0)}</td><td>{e(block.get('unique_count') or 0)}</td>"
            f"<td>{e(block.get('excluded') or 0)}</td><td>{e(block.get('raw_imsi') or 0)}</td>"
            f"<td>{e(block.get('net_imsi') or 0)}</td>"
            f"<td>{e(block.get('raw_imei') or 0)}</td>"
            f"<td>{e(block.get('net_imei') or 0)}</td>"
            f"<td><span class='hash'>{e(block.get('hash') or '-')}</span></td>"
            "</tr>"
            for block in place_group.get("histories", [])
        ) or "<tr><td colspan='10'>Sin histories asociados.</td></tr>"
        carrier_html = []
        for carrier in sorted(place_by_carrier, key=lambda c: (carrier_order.get(c, 99), c)):
            rows_html = "".join(
                "<tr>"
                f"<td>{e(d.get('imsi') or '-')}</td><td>{e(d.get('imei') or 'S/I')}</td><td>{e(d.get('model') or 'S/I')}</td>"
                f"<td>{e(d.get('pings') or 0)}</td><td>{e(fmt_dt(d.get('first_raw')))}</td><td>{e(fmt_dt(d.get('last_raw')))}</td>"
                f"<td>{e(', '.join(sorted(d.get('histories') or [])) or '-')}</td>"
                f"<td>{e(', '.join(f'{k}: {v}' for k, v in (d.get('lac_cell') or Counter()).most_common(8)) or '-')}</td>"
                "</tr>"
                for d in place_by_carrier[carrier]
            ) or f"<tr><td colspan='8'>Sin dispositivos netos para {e(carrier)}.</td></tr>"
            carrier_html.append(f"""
  <h3>{e(carrier)} - Detalle del lugar</h3>
  <div class="carrier-total">{len(place_by_carrier[carrier])} dispositivo(s) unico(s) | {sum(int(d.get('pings') or 0) for d in place_by_carrier[carrier])} deteccion(es)</div>
  <table><thead><tr><th>IMSI / MAC</th><th>IMEI</th><th>Modelo</th><th>Pings</th><th>Primera</th><th>Ultima</th><th>Histories</th><th>LAC / CELL ID</th></tr></thead><tbody>{rows_html}</tbody></table>""")
        meta = place_group.get("meta") or {}
        place_sections.append(f"""
<section class="place-block">
  <h2>{e(place_group.get('title') or 'Lugar no informado')}</h2>
  <div class="meta">
    <strong>Bloque:</strong> {e(meta.get('bloque') or '-')}<br>
    <strong>Complejo:</strong> {e(meta.get('complejo') or 'No informado')} |
    <strong>Lugar:</strong> {e(meta.get('lugar') or 'No informado')} |
    <strong>Modulo:</strong> {e(meta.get('modulo') or 'No informado')} |
    <strong>Ala/Sector:</strong> {e(meta.get('ala') or 'No informado')}<br>
    <strong>Ubicacion:</strong> {e(meta.get('ubicacion') or 'No informada')} |
    <strong>Coordenadas:</strong> {e(meta.get('coordenadas') or 'No informadas')}
  </div>
  <div class="grid">
    <div class="metric"><strong>{place_metrics["detecciones_brutas"]}</strong>Detecciones brutas del lugar</div>
    <div class="metric"><strong>{place_metrics["detecciones_sin_duplicar"]}</strong>Identidades leidas sin duplicar</div>
    <div class="metric"><strong>{place_metrics["no_coincidentes"]}</strong>No coincidentes</div>
    <div class="metric"><strong>{place_metrics["coincidencias_lista_blanca"]}</strong>Coincidencias Lista Blanca</div>
    <div class="metric"><strong>{place_metrics["imsi_leidos"]}</strong>IMSI leidos</div>
    <div class="metric"><strong>{place_metrics["imsi_netos"]}</strong>IMSI no coincidentes</div>
    <div class="metric"><strong>{place_metrics["imei_leidos"]}</strong>IMEI leidos</div>
    <div class="metric"><strong>{place_metrics["imei_netos"]}</strong>IMEI no coincidentes</div>
    <div class="metric"><strong>{len(place_group.get('histories') or [])}</strong>Operativo(s) asociados</div>
  </div>
  <h3>Operativos correspondientes</h3>
  <table><thead><tr><th>Sistema</th><th>Operativo / History</th><th>Brutas</th><th>Identidades sin duplicar</th><th>Coincidencias LB</th><th>IMSI leidos</th><th>IMSI no coincidentes</th><th>IMEI leidos</th><th>IMEI no coincidentes</th><th>Hash SHA-256</th></tr></thead><tbody>{histories_html}</tbody></table>
  {''.join(carrier_html) or "<div class='card'>Sin dispositivos netos para este lugar.</div>"}
</section>""")

    global_by_carrier: Dict[str, List[Dict[str, object]]] = defaultdict(list)
    for item in global_groups.values():
        global_by_carrier[str(item.get("carrier") or "DESCONOCIDA")].append(item)
    for devices in global_by_carrier.values():
        devices.sort(key=lambda d: (-int(d.get("pings") or 0), str(d.get("imsi") or ""), str(d.get("imei") or "")))

    carrier_sections = []
    for carrier in sorted(global_by_carrier, key=lambda c: (carrier_order.get(c, 99), c)):
        rows_html = "".join(
            "<tr>"
            f"<td>{e(d.get('imsi') or '-')}</td><td>{e(d.get('imei') or 'S/I')}</td><td>{e(d.get('model') or 'S/I')}</td>"
            f"<td>{e(d.get('pings') or 0)}</td><td>{e(fmt_dt(d.get('first_raw')))}</td><td>{e(fmt_dt(d.get('last_raw')))}</td>"
            f"<td>{e(', '.join(sorted(d.get('histories') or [])) or '-')}</td>"
            f"<td>{e(', '.join(f'{k}: {v}' for k, v in (d.get('lac_cell') or Counter()).most_common(8)) or '-')}</td>"
            "</tr>"
            for d in global_by_carrier[carrier]
        )
        carrier_sections.append(f"""
<section class="carrier-section">
  <h2>{e(carrier)} - Consolidado final</h2>
  <div class="carrier-total">{len(global_by_carrier[carrier])} dispositivo(s) unico(s) | {sum(int(d.get('pings') or 0) for d in global_by_carrier[carrier])} deteccion(es)</div>
  <table><thead><tr><th>IMSI / MAC</th><th>IMEI</th><th>Modelo</th><th>Pings</th><th>Primera</th><th>Ultima</th><th>Histories</th><th>LAC / CELL ID</th></tr></thead><tbody>{rows_html}</tbody></table>
</section>""")

    ahora = dt.datetime.now(dt.timezone(dt.timedelta(hours=-3)))
    stamp = ahora.strftime("%Y%m%d_%H%M%S")
    numero_nota = next_numero_nota(ahora.year)
    num_informe = f"INF-CONSOLIDADO-{stamp}"
    personal_text = " | ".join(
        f"{p.nombre.strip()} - {p.titulo.strip()}" if p.titulo.strip() else p.nombre.strip()
        for p in payload.personal if p.nombre.strip()
    ) or str(user.get("full_name") or user.get("username") or "-")

    out_dir = OUTPUTS_DIR / "informes_septier_consolidados"
    out_dir.mkdir(parents=True, exist_ok=True)
    base_name = f"informe_operativo_consolidado_septier_{numero_nota:02d}_{stamp}"
    html_path = out_dir / f"{base_name}.html"
    word_path = out_dir / f"{base_name}.doc"
    html = f"""<!doctype html>
<html lang="es"><head><meta charset="utf-8"><title>Informe Operativo Consolidado Septier</title>
<style>
@page WordSection1 {{ size:841.95pt 595.35pt; margin:26pt 20pt 26pt 20pt; mso-page-orientation:landscape; }}
div.WordSection1 {{ page:WordSection1; }}
body {{ font-family: Arial, sans-serif; color:#061827; margin:18px; font-size:11px; line-height:1.25; }}
h1,h2 {{ color:#003e68; }} h1 {{ font-size:24px; margin:0 0 12px; }} h2 {{ font-size:18px; margin:18px 0 10px; }} h3 {{ font-size:13px; margin:12px 0 8px; }}
.sub {{ color:#334155; font-weight:700; margin:2px 0; font-size:12px; }}
.meta,.card {{ border:1px solid #c9d7e8; border-radius:8px; padding:9px; margin:9px 0; }}
.grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(145px,1fr)); gap:8px; margin:10px 0; }}
.metric {{ border:1px solid #c9d7e8; border-radius:8px; padding:8px; background:#f7fbff; min-height:42px; }}
.metric strong {{ display:block; color:#003e68; font-size:20px; line-height:1; }}
table {{ border-collapse:collapse; width:100%; margin:8px 0; font-size:8.5px; table-layout:fixed; mso-table-layout-alt:fixed; }}
th,td {{ border:1px solid #c9d7e8; padding:4px; text-align:left; vertical-align:top; overflow-wrap:anywhere; word-break:break-word; }}
th {{ background:#eaf2fb; color:#001b35; }}
.hash {{ color:#475569; font-family:Consolas, monospace; font-size:7px; word-break:break-all; overflow-wrap:anywhere; }}
.place-block,.history-block,.carrier-section {{ margin-top:16px; page-break-inside:auto; }}
.carrier-total {{ border:1px solid #c9d7e8; border-left:4px solid #003e68; border-radius:8px; padding:8px 10px; background:#f7fbff; }}
</style></head><body><div class="WordSection1">
<h1>Informe Operativo Consolidado Septier</h1>
<div class="sub">DEPARTAMENTO DE TECNOLOGIAS ESPECIALES Y DESPLIEGUE TACTICO</div>
<div class="sub">SUBSECRETARIA DE TECNOLOGIA APLICADA A LA SEGURIDAD</div>
<div class="sub">MINISTERIO DE SEGURIDAD Y JUSTICIA</div>
<div class="meta"><strong>Nota:</strong> {numero_nota}/{ahora.year} | <strong>Informe:</strong> {e(num_informe)} | <strong>Generado:</strong> {e(ahora.strftime('%Y-%m-%d %H:%M:%S'))}<br>
<strong>Usuario:</strong> {e(user.get('full_name') or user.get('username'))} | <strong>Personal:</strong> {e(personal_text)}</div>
<div class="card">Regla de depuracion: cada history seleccionado se cruza contra Lista Blanca actual por IMSI e IMEI. Solo las coincidencias autorizadas en Lista Blanca se excluyen antes del consolidado final. Los repetidos se consolidan por IMSI cuando existe; si no existe IMSI, se consolidan por IMEI.</div>
<div class="grid">
<div class="metric"><strong>{global_metrics["detecciones_brutas"]}</strong>Detecciones brutas</div>
<div class="metric"><strong>{global_metrics["detecciones_sin_duplicar"]}</strong>Identidades leidas sin duplicar</div>
<div class="metric"><strong>{global_metrics["no_coincidentes"]}</strong>No coincidentes</div>
<div class="metric"><strong>{global_metrics["coincidencias_lista_blanca"]}</strong>Coincidencias Lista Blanca</div>
<div class="metric"><strong>{global_metrics["imsi_leidos"]}</strong>IMSI leidos</div>
<div class="metric"><strong>{global_metrics["imsi_netos"]}</strong>IMSI no coincidentes</div>
<div class="metric"><strong>{global_metrics["imei_leidos"]}</strong>IMEI leidos</div>
<div class="metric"><strong>{global_metrics["imei_netos"]}</strong>IMEI no coincidentes</div>
<div class="metric"><strong>{len(effective_files)}</strong>Operativo(s)</div>
</div>
<h2>Detalle por Lugar de Alojamiento</h2>
{''.join(place_sections) or "<div class='card'>Sin lugares operativos consolidados.</div>"}
<h2>Consolidado Final Depurado</h2>
{''.join(carrier_sections) or "<div class='card'>Sin dispositivos netos consolidados.</div>"}
</div></body></html>"""
    html_path.write_text(html, encoding="utf-8")
    word_path.write_text(html, encoding="utf-8")
    digest = hashlib.sha256(word_path.read_bytes()).hexdigest()
    insert_informe_generado({
        "numero_nota": numero_nota,
        "anio": ahora.year,
        "numero_informe": num_informe,
        "tipo": "consolidado",
        "usuario": user.get("full_name") or user.get("username"),
        "archivos": [{"system": f.system, "file": f.file} for f in effective_files],
        "objetivos_count": len(global_groups),
        "download_url": _skyeye_output_url(word_path),
    })
    return {
        "ok": True,
        "download_url": _skyeye_output_url(word_path),
        "html_url": _skyeye_output_url(html_path),
        "numero_nota": numero_nota,
        "numero_informe": num_informe,
        "hash_sha256": digest,
        "total_bruto": global_metrics["detecciones_brutas"],
        "detecciones_sin_duplicar": global_metrics["detecciones_sin_duplicar"],
        "excluidos_lista_blanca": global_metrics["coincidencias_lista_blanca"],
        "imsi_brutos": global_metrics["imsi_leidos"],
        "imsi_excluidos_lb": global_metrics["imsi_excluidos_lb"],
        "imsi_unicos_netos": global_metrics["imsi_netos"],
        "imei_brutos": global_metrics["imei_leidos"],
        "imei_excluidos_lb": global_metrics["imei_excluidos_lb"],
        "imei_unicos_netos": global_metrics["imei_netos"],
        "objetivos_netos": len(global_groups),
    }


@app.post("/api/septier/report/generate")
def septier_report_generate(payload: GenerateReportRequest, user=Depends(_require_auth)):
    report_type = str(payload.tipo or "").strip().lower()
    if report_type == "mensual":
        return _septier_monthly_report_generate(payload, user)

    template_path = REPO_ROOT / f"app/templates/informe_{payload.tipo}.docx"
    if not template_path.exists():
        raise HTTPException(status_code=404, detail=f"Plantilla no encontrada: {template_path.name}")

    # 1. Obtener detalles de la DB para los targets aprobados
    files_dict = [{"system": f.system, "file": f.file} for f in payload.files]
    db_rows = get_septier_detections_by_files(files_dict)
    identity_memory = _septier_identity_memory()
    db_rows_resolved = [_with_resolved_septier_identity(r, identity_memory) for r in db_rows]
    row_map = {
        f"{str(r.get('imsi_mac') or '').strip()}|{str(r.get('imei') or '').strip()}|{str(r.get('archivo_origen') or '').strip()}": r
        for r in db_rows_resolved
    }
    fallback_row_map = {
        f"{str(r.get('imsi_mac') or '').strip()}|{str(r.get('imei') or '').strip()}": r
        for r in db_rows_resolved
    }
    whitelist = _whitelist_identity_set()
    approved_targets = []
    for t in payload.targets:
        target_imsi, target_imei = _resolve_septier_identity_values(t.imsi, t.imei, identity_memory)
        lookup_key = _operational_identity_key(target_imsi or t.imsi, target_imei or t.imei)
        target_file = t.archivo.strip()
        k = f"{target_imsi}|{target_imei}|{target_file}"
        fallback_k = f"{target_imsi}|{target_imei}"
        target_row = row_map.get(k) or fallback_row_map.get(fallback_k, {})
        if not target_row and lookup_key:
            target_row = next(
                (
                    r for r in db_rows_resolved
                    if str(r.get("archivo_origen") or "").strip() == target_file
                    and _septier_row_matches_operational_key(r, lookup_key)
                ),
                {},
            ) or next(
                (r for r in db_rows_resolved if _septier_row_matches_operational_key(r, lookup_key)),
                {},
            )
        if target_row:
            row_imsi = _id15(target_row.get("imsi_mac"))
            row_imei = _id15(target_row.get("imei"))
            if len(row_imsi) == 15:
                target_imsi = row_imsi
            if len(row_imei) == 15:
                target_imei = row_imei
        if not _is_whitelisted_identity(target_imsi, target_imei, whitelist):
            approved_targets.append({
                "imsi": target_imsi,
                "imei": target_imei,
                "archivo": target_file,
                "target_row": target_row,
            })
    if payload.targets and not approved_targets:
        raise HTTPException(status_code=400, detail="Todos los objetivos seleccionados coinciden con Lista Blanca actual.")

    consolidated_targets: Dict[str, Dict[str, object]] = {}
    for t in approved_targets:
        target_imsi = str(t.get("imsi") or "").strip()
        target_imei = str(t.get("imei") or "").strip()
        target_file = str(t.get("archivo") or "").strip()
        key = _operational_identity_key(target_imsi, target_imei)
        target_row = t.get("target_row") or {}
        related_rows = [
            r for r in db_rows_resolved
            if _septier_row_matches_operational_key(r, key)
            and not _is_whitelisted_identity(r.get("imsi_mac"), r.get("imei"), whitelist)
        ]
        if not related_rows and target_row:
            related_rows = [target_row]

        current = consolidated_targets.setdefault(key, {
            "imsi": _id15(target_imsi) if len(_id15(target_imsi)) == 15 else "",
            "imei": _id15(target_imei) if len(_id15(target_imei)) == 15 else "",
            "archivo": target_file,
            "archivos": set(),
            "detecciones": 0,
            "row": target_row,
            "imeis": Counter(),
        })
        if target_file:
            current["archivos"].add(target_file)
        if len(_id15(target_imsi)) == 15 and not current.get("imsi"):
            current["imsi"] = _id15(target_imsi)
        if len(_id15(target_imei)) == 15:
            current["imeis"][_id15(target_imei)] += 1
            if not current.get("imei"):
                current["imei"] = _id15(target_imei)

        for r in related_rows:
            row_imsi = _id15(r.get("imsi_mac"))
            row_imei = _id15(r.get("imei"))
            if len(row_imsi) == 15 and not current.get("imsi"):
                current["imsi"] = row_imsi
            if len(row_imei) == 15:
                current["imeis"][row_imei] += 1
            row_file = str(r.get("archivo_origen") or "").strip()
            if row_file:
                current["archivos"].add(row_file)
            row_dt = _parse_dt_value(r.get("last_update")) or dt.datetime.min
            current_dt = _parse_dt_value((current.get("row") or {}).get("last_update")) if current.get("row") else None
            if not current.get("row") or row_dt >= (current_dt or dt.datetime.min):
                current["row"] = r

        current["detecciones"] = max(int(current.get("detecciones") or 0), len(related_rows) or 1)

    approved_targets_netos = list(consolidated_targets.values())
    for item in approved_targets_netos:
        if not item.get("imei") and item.get("imeis"):
            item["imei"] = sorted(item["imeis"].items(), key=lambda kv: (-kv[1], kv[0]))[0][0]
        if item.get("archivos"):
            item["archivo"] = ", ".join(sorted(item["archivos"]))

    def _format_report_date(raw_value: object) -> str:
        if not raw_value:
            return "-"
        try:
            dt_obj = dt.datetime.fromisoformat(str(raw_value).replace("Z", "+00:00")[:19])
            return dt_obj.strftime("%d-%m-%Y")
        except Exception:
            return str(raw_value)[:10]

    def _carrier_from_imsi(imsi_value: str) -> str:
        if imsi_value.startswith(("72231", "72232", "72233")):
            return "CLARO"
        if imsi_value.startswith(("72201", "72207")):
            return "MOVISTAR"
        if imsi_value.startswith(("72234", "72203", "72235")):
            return "PERSONAL"
        return "OTRO"

    lista_claro, lista_movistar, lista_personal, lista_otros = [], [], [], []
    
    for t in approved_targets_netos:
        r = t.get("row") or {}
        imsi = str(t.get("imsi") or "").strip()
        imei = str(t.get("imei") or "").strip() or "S/I"
        marca = str(r.get("model", "")).strip() or "S/I"
        operativo = _carrier_from_imsi(imsi)
        obj = {
            "imsi": imsi,
            "operativo": operativo,
            "imei_15": imei,
            "marca": marca,
            "archivo": str(t.get("archivo") or "").strip() or str(r.get("archivo_origen", "")).strip(),
            "fecha": _format_report_date(r.get("last_update")),
            "fuente": str(r.get("source", "")).strip().upper(),
            "detecciones": int(t.get("detecciones") or 0),
        }
            
        # Clasificacion inteligente por Codigo MNC de Argentina
        if operativo == "CLARO":
            lista_claro.append(obj)
        elif operativo == "MOVISTAR":
            lista_movistar.append(obj)
        elif operativo == "PERSONAL":
            lista_personal.append(obj)
        else:
            lista_otros.append(obj)

    mem_imsi, mem_imei, mem_imsi_rows, mem_imei_rows = _historial_memory_maps()
    imei_counts_by_imsi, imsi_counts_by_imei = _septier_identity_memory()
    det_rows_by_imsi, det_rows_by_imei = _septier_identity_source_maps()

    selected_by_file: Dict[str, int] = {}
    for target in approved_targets_netos:
        archivos = target.get("archivos") or set()
        if not archivos and target.get("archivo"):
            archivos = {str(target.get("archivo") or "").strip()}
        for archivo in archivos:
            if archivo:
                selected_by_file[archivo] = selected_by_file.get(archivo, 0) + 1

    audit_counts_by_file: Dict[str, Dict[str, int]] = {}
    seen_this_batch = set()
    for r in db_rows_resolved:
        imsi = str(r.get("imsi_mac") or "").strip()
        imei = str(r.get("imei") or "").strip()
        imsi_key = _primary_identity_key(imsi)
        imei_key = _primary_identity_key(imei)
        archivo = str(r.get("archivo_origen") or "").strip()
        if not imsi and not imei:
            continue

        batch_key = f"{archivo}|{_operational_identity_key(imsi, imei)}"
        if batch_key in seen_this_batch:
            continue
        seen_this_batch.add(batch_key)

        counts = audit_counts_by_file.setdefault(
            archivo,
            {"descartados_personal_autorizado": 0, "descartados_ya_informados": 0, "mutaciones": 0},
        )
        mutation_context = _septier_mutation_context(
            imsi,
            imei,
            r.get("last_update"),
            mem_imsi_rows,
            mem_imei_rows,
            imei_counts_by_imsi,
            imsi_counts_by_imei,
            det_rows_by_imsi,
            det_rows_by_imei,
        )
        if mutation_context:
            counts["mutaciones"] += 1
            continue

        if _is_whitelisted_identity(imsi, imei, whitelist):
            counts["descartados_personal_autorizado"] += 1
            continue

        is_imsi_known = imsi_key in mem_imsi
        is_imei_known = imei_key in mem_imei
        if is_imsi_known or is_imei_known:
            counts["descartados_ya_informados"] += 1

    # 2. Resumen Estadistico Operativo por Archivo
    lista_archivos = []
    total_brutas = 0
    total_descartados = 0
    total_descartados_ya_informados = 0
    total_mutaciones = 0
    report_source_rows: List[Dict[str, object]] = []
    report_net_rows: List[Dict[str, object]] = []
    report_whitelist_rows: List[Dict[str, object]] = []

    for f in payload.files:
        stats = get_septier_file_stats(f.file, f.system.lower())
        file_source_rows = [
            r for r in db_rows_resolved
            if str(r.get("archivo_origen") or "").strip() == f.file.strip()
        ]
        file_whitelist_rows = [
            r for r in file_source_rows
            if _is_whitelisted_identity(r.get("imsi_mac"), r.get("imei"), whitelist)
        ]
        file_net_rows = [
            r for r in file_source_rows
            if not _is_whitelisted_identity(r.get("imsi_mac"), r.get("imei"), whitelist)
        ]
        file_metrics = _septier_whitelist_metrics(file_source_rows, file_net_rows, file_whitelist_rows)
        report_source_rows.extend(file_source_rows)
        report_net_rows.extend(file_net_rows)
        report_whitelist_rows.extend(file_whitelist_rows)
        sospechosos_netos = selected_by_file.get(f.file.strip(), 0)
        audit_counts = audit_counts_by_file.get(
            f.file.strip(),
            {"descartados_personal_autorizado": 0, "descartados_ya_informados": 0, "mutaciones": 0},
        )
        descartados_auth = audit_counts["descartados_personal_autorizado"]
        descartados_ya_informados = audit_counts["descartados_ya_informados"]
        mutaciones = audit_counts["mutaciones"]
        
        fecha_arch = "-"
        if stats.get("rows"):
            raw_d = stats["rows"][0].get("last_update")
            fecha_arch = _format_report_date(raw_d)

        lista_archivos.append({
            "nombre": f.file, 
            "fecha": fecha_arch,
            "fuente": f.system.upper(),
            "brutas": file_metrics["detecciones_brutas"],
            "sin_duplicar": file_metrics["detecciones_sin_duplicar"],
            "imsi_leidos": file_metrics["imsi_leidos"],
            "imsi_excluidos_lb": file_metrics["imsi_excluidos_lb"],
            "imsi_netos": file_metrics["imsi_netos"],
            "imei_leidos": file_metrics["imei_leidos"],
            "imei_excluidos_lb": file_metrics["imei_excluidos_lb"],
            "imei_netos": file_metrics["imei_netos"],
            "descartados_personal_autorizado": descartados_auth,
            "descartados_ya_informados": descartados_ya_informados,
            "mutaciones": mutaciones,
            "sospechosos": sospechosos_netos,
            "objetivos_netos": sospechosos_netos,
        })
        total_descartados += descartados_auth
        total_descartados_ya_informados += descartados_ya_informados
        total_mutaciones += mutaciones

    report_metrics = _septier_whitelist_metrics(report_source_rows, report_net_rows, report_whitelist_rows)
    total_brutas = report_metrics["detecciones_brutas"]
    total_imsi = report_metrics["imsi_netos"]
    total_imei = report_metrics["imei_netos"]
    total_descartados = report_metrics["coincidencias_lista_blanca"]

    neto_imsi_total = len(approved_targets_netos)
    neto_imei_total = len([t for t in approved_targets_netos if str(t.get("imei") or "").strip()])
    neto_sin_imei = neto_imsi_total - neto_imei_total

    claro_con_imei = len([t for t in lista_claro if t["imei_15"] != "S/I"])
    movistar_con_imei = len([t for t in lista_movistar if t["imei_15"] != "S/I"])
    personal_con_imei = len([t for t in lista_personal if t["imei_15"] != "S/I"])
    otros_con_imei = len([t for t in lista_otros if t["imei_15"] != "S/I"])

    meses = ["Enero", "Febrero", "Marzo", "Abril", "Mayo", "Junio", "Julio", "Agosto", "Septiembre", "Octubre", "Noviembre", "Diciembre"]
    ahora = dt.datetime.now(dt.timezone(dt.timedelta(hours=-3)))
    fecha_informe_str = f"{ahora.day} de {meses[ahora.month - 1]} de {ahora.year}"
    num_informe = f"INF-{ahora.strftime('%Y%m%d-%H%M%S')}"
    numero_nota = next_numero_nota(ahora.year)

    personal_informe = [
        {"nombre": p.nombre.strip(), "titulo": p.titulo.strip()}
        for p in payload.personal
        if p.nombre.strip()
    ]
    if not personal_informe:
        personal_informe = [
            {
                "nombre": "Romina MERCAU",
                "titulo": "ADJUTOR S.C.S - Gestora de Base de datos, Perito Informatico Forense",
            }
        ]

    personal_con_titulo = "\n".join(
        f"{p['nombre']} - {p['titulo']}" if p["titulo"] else p["nombre"]
        for p in personal_informe
    )

    lugar_nombre = payload.lugar.nombre.strip() or "Complejo Penitenciario Almafuerte N° 01"
    lugar_escaneo = payload.lugar.lugar_escaneo.strip() or "TORRE VIGIA Nª5"
    ubicacion_escaneo = payload.lugar.ubicacion_escaneo.strip() or "Cerco Perimetral"
    coordenadas = payload.lugar.coordenadas.strip() or "-33.09422, -69.04616"
    modulos = payload.lugar.modulos.strip() or "MODULOS 3 y 4"
    ala = payload.lugar.ala.strip() or "Ala 1, 3 y 4"

    # 3. Renderizar Plantilla
    context = {
        "numero_informe": num_informe, 
        "fecha_procesamiento": ahora.strftime('%Y-%m-%d %H:%M:%S'),
        "usuario": user.get("full_name") or user.get("username"), 

        "Nro_nota": f"{numero_nota:02d}", 
        "anio": str(ahora.year),
        "fecha_informe": fecha_informe_str,
        "destinatario_nombre": "ING. LEANDRO BISKUPOVICH",
        "nombre_perito": personal_con_titulo,
        "jerarquia_perito": "",
        "especialidad_perito": "",
        "personal_informe": personal_informe,
        "personal_informe_texto": personal_con_titulo,
        
        "modulos_analizados": modulos,
        "modulo_analizado": modulos,
        "nombre_ala": ala,
        "nombre_complejo": lugar_nombre,
        "nombre_centro_alojamiento": lugar_nombre,
        "nombre_lugar_escaneo": lugar_escaneo,
        "nombre_ubicacion_escaneo": ubicacion_escaneo,
        "ubicacion_coordenadas": coordenadas,
        "links_mymaps": "https://www.google.com/maps/d/viewer?mid=...",
        
        "neto_imsi_total": neto_imsi_total, "neto_imei_total": neto_imei_total, "neto_sin_imei": neto_sin_imei,
        "neto_objetivos_final": neto_imsi_total, "neto_con_imei": neto_imei_total, "neto_descartados_total": total_descartados,
        "total_brutas": total_brutas, "total_imsi": total_imsi, "total_imei": total_imei,
        "total_descartados_personal_autorizado": total_descartados, "total_sospechosos": neto_imsi_total,
        "total_descartados_ya_informados": total_descartados_ya_informados,
        "total_mutaciones": total_mutaciones,
        "total_data_externa_revision": 0,

        "imsi_totales_brutos": total_brutas,
        "imsi_totales_netos": total_imsi,
        "imei_totales_netos": total_imei,
        "objetivos_netos": neto_imsi_total,

        "lista_archivos": lista_archivos,
        "arch": lista_archivos[0] if lista_archivos else {
            "nombre": "-",
            "fecha": "-",
            "fuente": "-",
            "brutas": 0,
            "imsi_netos": 0,
            "imei_netos": 0,
            "descartados_personal_autorizado": 0,
            "descartados_ya_informados": 0,
            "mutaciones": 0,
            "sospechosos": 0,
            "objetivos_netos": 0,
        },

        "claro_netos": len(lista_claro), "claro_con_imei": claro_con_imei, "claro_sin_imei": len(lista_claro) - claro_con_imei, "lista_claro": lista_claro,
        "movistar_netos": len(lista_movistar), "movistar_con_imei": movistar_con_imei, "movistar_sin_imei": len(lista_movistar) - movistar_con_imei, "lista_movistar": lista_movistar,
        "personal_netos": len(lista_personal), "personal_con_imei": personal_con_imei, "personal_sin_imei": len(lista_personal) - personal_con_imei, "lista_personal": lista_personal,
        "otros_netos": len(lista_otros), "otros_con_imei": otros_con_imei, "otros_sin_imei": len(lista_otros) - otros_con_imei, "lista_otros": lista_otros,

        "personal_penitenciaria": 0,
        "flota_movilidad": 0,
        "flota_movilidad_policial": 0,
        "monitoreo_camaras": 0,
        "dispositivos_provistos": 0,
        "dpto_tecnica": 0,
        "dispositivos_con_escuchas": 0,
        "autorizados_mujeres": 0,
        "provistos_ministerio": 0,
    }
    
    try:
        doc = DocxTemplate(template_path)
        doc.render(context)
        out_name = f"Reporte_{payload.tipo.capitalize()}_Nota_{numero_nota:02d}_{num_informe}.docx"
        doc.save(OUTPUTS_DIR / out_name)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al procesar plantilla DOCX: {str(e)}")

    # 4. Sellar la Memoria Forense y devolver el link
    insert_historial_informes([
        {
            "imsi": str(t.get("imsi") or ""),
            "imei": str(t.get("imei") or ""),
            "archivo_origen": str(t.get("archivo") or ""),
        }
        for t in approved_targets_netos
    ], num_informe)
    download_url = f"/outputs/{out_name}"
    insert_informe_generado({
        "numero_nota": numero_nota,
        "anio": ahora.year,
        "numero_informe": num_informe,
        "tipo": payload.tipo,
        "usuario": user.get("full_name") or user.get("username"),
        "archivos": [{"system": f.system, "file": f.file} for f in payload.files],
        "objetivos_count": len(approved_targets_netos),
        "download_url": download_url,
    })
    return {"ok": True, "download_url": download_url, "numero_nota": numero_nota, "numero_informe": num_informe}


@app.post("/api/septier/upload/{system_name}")
async def septier_upload(
    system_name: str,
    location: str = Form(""),
    files: List[UploadFile] = File(...),
    user=Depends(_require_edit)
):
    target_dir = _septier_target_dir(system_name)
    target_dir.mkdir(parents=True, exist_ok=True)

    saved = []
    mutation_source_rows: List[Dict[str, object]] = []
    inserted_total = 0
    ignored_total = 0
    geocoded_total = 0

    for up in files:
        if not up.filename:
            continue
        safe_name = Path(up.filename).name
        if not safe_name.lower().endswith(".csv"):
            continue

        data = await up.read()
        _scan_uploaded_bytes(data, up.filename or "archivo", "upload", user)
        file_hash = hashlib.sha256(data).hexdigest()
        stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
        stem = re.sub(r"[^A-Za-z0-9._-]+", "_", Path(safe_name).stem).strip("._") or "csv"
        final_target = target_dir / f"{system_name.lower()}_{stamp}_{stem}.csv"
        i = 1
        while final_target.exists():
            final_target = target_dir / f"{system_name.lower()}_{stamp}_{stem}_{i}.csv"
            i += 1

        final_target.write_bytes(data)

        rows = _extract_septier_rows(final_target, source_name=system_name, location=location, file_hash=file_hash)
        insert_septier_detections(rows)
        mutation_source_rows.extend(rows)
        upsert_septier_history_metadata({
            "source": system_name,
            "archivo_origen": final_target.name,
            "lugar_operativo": location,
            "complejo": location,
            "updated_by": user.get("username") or user.get("full_name") or "",
        })
        geocoded = sum(1 for row in rows if row.get("latitud") is not None and row.get("longitud") is not None)
        inserted_total += len(rows)
        geocoded_total += geocoded
        ignored_total += max(0, (len(data.splitlines()) - 1) - len(rows))
        saved.append({
            "original": safe_name,
            "saved_as": final_target.name,
            "inserted": len(rows),
            "geocoded": geocoded,
            "without_coords": max(0, len(rows) - geocoded),
            "sha256": file_hash,
            "hash_sha256": file_hash,
        })

    if not saved:
        raise HTTPException(status_code=400, detail="No se subieron CSV validos")

    mutation_alerts: List[Dict[str, object]] = []
    mutation_cases_count = 0
    if os.getenv("SKYEYE_UPLOAD_INCLUDE_SWAP_ALERTS", "").strip().lower() in {"1", "true", "yes"}:
        try:
            mutation_alerts = _septier_mutation_alerts_from_rows(mutation_source_rows, limit=50)
            mutation_cases_count = _septier_mutation_case_count(mutation_alerts)
        except Exception as exc:
            print(f"No se pudieron calcular swaps durante la subida Septier: {exc}")

    return {
        "ok": True,
        "system": system_name.lower(),
        "saved": saved,
        "inserted_total": inserted_total,
        "geocoded_total": geocoded_total,
        "without_coords_total": max(0, inserted_total - geocoded_total),
        "ignored_total": ignored_total,
        "mutation_alerts": mutation_alerts,
        "mutation_alerts_count": len(mutation_alerts),
        "swap_cases_count": mutation_cases_count,
        "swap_detail_count": len(mutation_alerts),
    }


def _read_uploaded_csv_df(upload: UploadFile, raw: bytes):
    import pandas as pd
    from io import BytesIO

    last_error = None
    for encoding in ("utf-8-sig", "latin-1"):
        try:
            return pd.read_csv(BytesIO(raw), sep=None, engine="python", encoding=encoding, dtype=str).fillna("")
        except Exception as exc:
            last_error = exc
    raise HTTPException(status_code=400, detail=f"No se pudo leer CSV {Path(upload.filename or 'archivo').name}: {last_error}")


def _forensic_num(value: object) -> float:
    text = str(value or "").strip().replace(",", ".")
    if not text:
        return 0.0
    try:
        return float(text)
    except Exception:
        return 0.0


def _forensic_int(value: object) -> int:
    return int(round(_forensic_num(value)))


def _forensic_col(row: Dict[str, object], *names: str) -> str:
    folded = {str(k).strip().casefold(): v for k, v in row.items()}
    for name in names:
        value = folded.get(name.casefold())
        if value is not None:
            return str(value or "").strip()
    return ""


def _forensic_presence_score(row: Dict[str, object]) -> int:
    registrations = int(row.get("max_registrations") or row.get("registrations") or 0)
    pings = int(row.get("events") or 0)
    days = int(_forensic_num(row.get("stationary_days") or 0))
    day_hours = int(_forensic_num(row.get("maximum_day_hours") or 0))
    night_hours = int(_forensic_num(row.get("maximum_night_hours") or 0))
    probability = int(_forensic_num(row.get("stationary_probability") or 0))
    swap_bonus = 25 if "swap" in str(row.get("forensic_note") or "").lower() else 0
    whitelist_penalty = 15 if "coincide" in str(row.get("whitelist_status") or "").lower() else 0
    distance = _forensic_num(row.get("distance_min") or 0)
    proximity_bonus = 0
    if distance > 0:
        proximity_bonus = max(0, 20 - min(20, int(distance // 25)))
    return max(0, registrations * 5 + pings * 3 + days * 8 + day_hours * 2 + night_hours * 2 + probability + swap_bonus + proximity_bonus - whitelist_penalty)


def _whitelist_context_text(imsi: object, imei: object) -> Tuple[str, str]:
    matches = _whitelist_match_details(imsi, imei)
    if not matches:
        return "NO COINCIDENTE LB", "-"
    status_text = "AUTORIZADO EN LISTA BLANCA"
    detail = _whitelist_match_trace(matches) or _whitelist_match_reason(matches) or "Coincidencia Lista Blanca"
    return status_text, detail


def _forensic_package_report_html(title: str, summary: Dict[str, object], identities: List[Dict[str, object]], swaps: List[Dict[str, object]]) -> str:
    generated_at = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    carrier_order = {"CLARO": 1, "MOVISTAR": 2, "PERSONAL": 3, "DESCONOCIDA": 4, "OTRO": 5, "OTROS": 6}
    identities_by_carrier: Dict[str, List[Dict[str, object]]] = defaultdict(list)
    for row in identities:
        identities_by_carrier[str(row.get("carrier") or "DESCONOCIDA")].append(row)
    carrier_rows = "\n".join(
        f"<tr><td>{html_lib.escape(str(carrier))}</td><td>{len(rows)}</td><td>{sum(int(r.get('events') or 0) for r in rows)}</td><td>{sum(int(r.get('registrations') or 0) for r in rows)}</td></tr>"
        for carrier, rows in sorted(identities_by_carrier.items(), key=lambda item: (carrier_order.get(item[0], 99), item[0]))
    ) or '<tr><td colspan="4">Sin prestadora inferible.</td></tr>'
    rows_html = "\n".join(
        f"<tr><td>{html_lib.escape(str(r.get('forensic_score') or '0'))}</td><td>{html_lib.escape(str(r.get('carrier') or '-'))}</td><td>{html_lib.escape(str(r.get('imsi') or '-'))}</td><td>{html_lib.escape(str(r.get('imei') or '-'))}</td>"
        f"<td>{html_lib.escape(str(r.get('model') or '-'))}</td><td>{html_lib.escape(str(r.get('registrations') or '0'))}</td>"
        f"<td>{html_lib.escape(str(r.get('events') or '0'))}</td><td>{html_lib.escape(str(r.get('stationary_probability') or '-'))}</td>"
        f"<td>{html_lib.escape(str(r.get('stationary_days') or '-'))}</td><td>{html_lib.escape(str(r.get('average_day_hours') or '-'))}</td>"
        f"<td>{html_lib.escape(str(r.get('maximum_day_hours') or '-'))}</td><td>{html_lib.escape(str(r.get('average_night_hours') or '-'))}</td>"
        f"<td>{html_lib.escape(str(r.get('maximum_night_hours') or '-'))}</td><td>{html_lib.escape(str(r.get('stationary_list') or '-'))}</td><td>{html_lib.escape(str(r.get('distance_min') or '-'))}</td>"
        f"<td>{html_lib.escape(str(r.get('distance_max') or '-'))}</td><td>{html_lib.escape(str(r.get('first_seen') or '-'))}</td>"
        f"<td>{html_lib.escape(str(r.get('last_seen') or '-'))}</td><td>{html_lib.escape(str(r.get('whitelist_status') or '-'))}</td>"
        f"<td>{html_lib.escape(str(r.get('forensic_note') or '-'))}</td></tr>"
        for r in identities[:2000]
    )
    carrier_sections = "\n".join(
        f"""<section class="carrier-section"><h2>{html_lib.escape(str(carrier))} - Identidades detectadas / dispositivos asociados</h2>
<div class="carrier-total">{len(rows)} identidad(es) IMSI | {sum(int(r.get('events') or 0) for r in rows)} ping(s) history | {sum(int(r.get('registrations') or 0) for r in rows)} registracion(es) stationary</div>
<table><thead><tr><th>Score</th><th>IMSI</th><th>IMEI</th><th>Modelo</th><th>Pings</th><th>Maximum Registrations</th><th>Probability</th><th>Days</th><th>Maximum Day Hours</th><th>Maximum Night Hours</th><th>Lista Blanca</th></tr></thead><tbody>{''.join(
            f"<tr><td>{html_lib.escape(str(r.get('forensic_score') or 0))}</td><td>{html_lib.escape(str(r.get('imsi') or '-'))}</td><td>{html_lib.escape(str(r.get('imei') or '-'))}</td><td>{html_lib.escape(str(r.get('model') or '-'))}</td><td>{html_lib.escape(str(r.get('events') or 0))}</td><td>{html_lib.escape(str(r.get('max_registrations') or r.get('registrations') or 0))}</td><td>{html_lib.escape(str(r.get('stationary_probability') or '-'))}</td><td>{html_lib.escape(str(r.get('stationary_days') or '-'))}</td><td>{html_lib.escape(str(r.get('maximum_day_hours') or '-'))}</td><td>{html_lib.escape(str(r.get('maximum_night_hours') or '-'))}</td><td>{html_lib.escape(str(r.get('whitelist_status') or '-'))}</td></tr>"
            for r in rows[:600]
        )}</tbody></table></section>"""
        for carrier, rows in sorted(identities_by_carrier.items(), key=lambda item: (carrier_order.get(item[0], 99), item[0]))
    ) or '<div class="box">Sin detalle por prestadora.</div>'
    swap_html = "\n".join(
        f"<tr><td>{html_lib.escape(str(s.get('type') or '-'))}</td><td>{html_lib.escape(str(s.get('imsi') or '-'))}</td>"
        f"<td>{html_lib.escape(str(s.get('imei') or '-'))}</td><td>{html_lib.escape(str(s.get('associated_count') or '-'))}</td>"
        f"<td>{html_lib.escape(str(s.get('probability') or '-'))}</td><td>{html_lib.escape(str(s.get('associated_identities') or '-'))}</td>"
        f"<td>{html_lib.escape(str(s.get('evidence') or '-'))}</td><td>{html_lib.escape(str(s.get('whitelist_status') or '-'))}</td></tr>"
        for s in swaps
    )
    no_swap = "" if swaps else f"<p class=\"notice\">En el operativo {html_lib.escape(str(summary.get('operation') or '-'))}, fecha {html_lib.escape(str(summary.get('date') or '-'))}, no se hallaron swaps asociados a las identidades o dispositivos detectados.</p>"
    return f"""<!doctype html>
<html lang="es"><head><meta charset="utf-8"><title>{html_lib.escape(title)}</title>
<style>
body{{font-family:Arial,sans-serif;margin:24px;color:#102030}} h1{{color:#003b63}} .box{{border:1px solid #b8d7ea;border-radius:8px;padding:12px;margin:12px 0;background:#f8fcff}}
.grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:8px}} .metric{{border:1px solid #c9ddeb;border-radius:6px;padding:10px;background:#fff}} .metric strong{{display:block;font-size:22px;color:#00639b}}
table{{width:100%;border-collapse:collapse;font-size:11px;table-layout:fixed}} th,td{{border:1px solid #c8d8e8;padding:6px;text-align:left;vertical-align:top;word-break:break-word}} th{{background:#e8f2fb}}
.notice{{border-left:4px solid #0a84ff;background:#eef7ff;padding:10px}} .warn{{color:#a34900;font-weight:bold}} .carrier-section{{margin-top:20px;page-break-inside:auto}} .carrier-total{{border:1px solid #c9ddeb;border-left:4px solid #00639b;border-radius:6px;padding:9px;background:#f8fcff;margin-bottom:8px}}
</style></head><body>
<h1>{html_lib.escape(title)}</h1>
<div class="box"><strong>Generado:</strong> {html_lib.escape(generated_at)}<br><strong>Operativo:</strong> {html_lib.escape(str(summary.get('operation') or '-'))}<br><strong>Rango:</strong> {html_lib.escape(str(summary.get('first_seen') or '-'))} a {html_lib.escape(str(summary.get('last_seen') or '-'))}</div>
<div class="grid">
<div class="metric"><strong>{summary.get('history_events', 0)}</strong>Eventos history</div>
<div class="metric"><strong>{summary.get('unique_imsi', 0)}</strong>IMSI unicos</div>
<div class="metric"><strong>{summary.get('unique_imei', 0)}</strong>IMEI unicos</div>
<div class="metric"><strong>{summary.get('swap_count', 0)}</strong>Swaps Septier</div>
</div>
<h2>Resumen por prestadora</h2>
<table><thead><tr><th>Prestadora</th><th>Identidades IMSI</th><th>Pings history</th><th>Registraciones stationary</th></tr></thead><tbody>{carrier_rows}</tbody></table>
{no_swap}
<h2>Swaps reportados por Septier</h2>
<table><thead><tr><th>Tipo</th><th>IMSI</th><th>IMEI</th><th>Cantidad asociada</th><th>Probabilidad</th><th>Identidades asociadas</th><th>Evidencia</th><th>Lista Blanca</th></tr></thead><tbody>{swap_html or '<tr><td colspan="8">Sin swaps reportados en el paquete.</td></tr>'}</tbody></table>
<h2>Detalle por prestadora</h2>
{carrier_sections}
<h2>Identidades detectadas / dispositivos asociados</h2>
<table><thead><tr><th>Score</th><th>Prestadora</th><th>IMSI</th><th>IMEI</th><th>Modelo</th><th>Maximum Registrations</th><th>Pings</th><th>Probability</th><th>Days</th><th>Average Day Hours</th><th>Maximum Day Hours</th><th>Average Night Hours</th><th>Maximum Night Hours</th><th>List</th><th>Dist. min</th><th>Dist. max</th><th>Primera vez</th><th>Ultima vez</th><th>Lista Blanca</th><th>Nota forense</th></tr></thead><tbody>{rows_html}</tbody></table>
</body></html>"""


async def _uploaded_csv_payload(upload: Optional[UploadFile], user: Optional[Dict[str, object]] = None, context: str = "forensic_package") -> Tuple[str, bytes, Any]:
    if upload is None or not upload.filename:
        return "", b"", None
    raw = await upload.read()
    _scan_uploaded_bytes(raw, upload.filename or "archivo", context, user)
    return Path(upload.filename).name, raw, _read_uploaded_csv_df(upload, raw)


@app.post("/api/septier/forensic-package")
async def septier_forensic_package(
    operation_label: str = Form(""),
    history_file: UploadFile = File(...),
    stationary_imsi_file: Optional[UploadFile] = File(None),
    stationary_imei_file: Optional[UploadFile] = File(None),
    imei_swap_file: Optional[UploadFile] = File(None),
    imsi_swap_file: Optional[UploadFile] = File(None),
    user=Depends(_require_edit),
):
    history_name, history_raw, history_df = await _uploaded_csv_payload(history_file, user, "forensic_package_history")
    st_imsi_name, st_imsi_raw, st_imsi_df = await _uploaded_csv_payload(stationary_imsi_file, user, "forensic_package_stationary_imsi")
    st_imei_name, st_imei_raw, st_imei_df = await _uploaded_csv_payload(stationary_imei_file, user, "forensic_package_stationary_imei")
    imei_swap_name, imei_swap_raw, imei_swap_df = await _uploaded_csv_payload(imei_swap_file, user, "forensic_package_imei_swap")
    imsi_swap_name, imsi_swap_raw, imsi_swap_df = await _uploaded_csv_payload(imsi_swap_file, user, "forensic_package_imsi_swap")
    if history_df is None:
        raise HTTPException(status_code=400, detail="El paquete requiere el history crudo.")

    history_records = history_df.to_dict(orient="records")
    identities: Dict[str, Dict[str, object]] = {}

    def ensure_identity(imsi: str = "", imei: str = "") -> Dict[str, object]:
        imsi = _id15(imsi)
        imei = _id15(imei)
        key = f"imsi:{imsi}" if imsi else f"imei:{imei}" if imei else ""
        if not key:
            key = f"raw:{len(identities) + 1}"
        item = identities.setdefault(key, {
            "imsi": imsi or "-",
            "imei": imei or "-",
            "model": "-",
            "registrations": 0,
            "avg_registrations": 0,
            "max_registrations": 0,
            "stationary_days": "",
            "stationary_day_hours": "",
            "stationary_night_hours": "",
            "average_day_hours": "",
            "maximum_day_hours": "",
            "average_night_hours": "",
            "maximum_night_hours": "",
            "stationary_probability": "",
            "stationary_list": "",
            "events": 0,
            "distance_values": [],
            "first_seen": "",
            "last_seen": "",
            "sources": set(),
            "carrier": _carrier_from_imsi_value(imsi) if imsi else "DESCONOCIDA",
        })
        if imsi and item.get("imsi") == "-":
            item["imsi"] = imsi
        if imsi:
            item["carrier"] = _carrier_from_imsi_value(imsi)
        if imei and item.get("imei") == "-":
            item["imei"] = imei
        return item

    def identities_for_imei(imei: str) -> List[Dict[str, object]]:
        imei = _id15(imei)
        if not imei:
            return []
        return [
            item
            for item in identities.values()
            if _id15(str(item.get("imei") or "")) == imei and _id15(str(item.get("imsi") or ""))
        ]

    times: List[str] = []
    operations = Counter()
    for row in history_records:
        imsi = _id15(_forensic_col(row, "IMSI"))
        imei = _id15(_forensic_col(row, "IMEI"))
        if not imsi and not imei:
            continue
        item = ensure_identity(imsi, imei)
        item["events"] = int(item.get("events") or 0) + 1
        item["sources"].add("history")
        model = _forensic_col(row, "Model", "IMEI Name")
        if model and model.lower() != "unknown":
            item["model"] = model
        dist = _forensic_col(row, "Distance")
        if dist != "":
            item["distance_values"].append(_forensic_num(dist))
        event_time = _forensic_col(row, "Event Time")
        if event_time:
            times.append(event_time)
            if not item.get("first_seen") or event_time < str(item.get("first_seen")):
                item["first_seen"] = event_time
            if not item.get("last_seen") or event_time > str(item.get("last_seen")):
                item["last_seen"] = event_time
        op = _forensic_col(row, "Operation")
        if op:
            operations[op] += 1

    if st_imsi_df is not None:
        for row in st_imsi_df.to_dict(orient="records"):
            imsi = _id15(_forensic_col(row, "IMSI"))
            imei = _id15(_forensic_col(row, "IMEI"))
            if not imsi and not imei:
                continue
            item = ensure_identity(imsi, imei)
            avg_regs = _forensic_int(_forensic_col(row, "Average Registrations"))
            max_regs = _forensic_int(_forensic_col(row, "Maximum Registrations", "Average Registrations"))
            item["avg_registrations"] = max(int(item.get("avg_registrations") or 0), avg_regs)
            item["max_registrations"] = max(int(item.get("max_registrations") or 0), max_regs)
            item["registrations"] = max(int(item.get("registrations") or 0), max_regs or avg_regs)
            model = _forensic_col(row, "Model")
            if model:
                item["model"] = model
            item["stationary_probability"] = _forensic_col(row, "Probability")
            item["stationary_days"] = _forensic_col(row, "Days")
            item["stationary_day_hours"] = _forensic_col(row, "Maximum Day Hours", "Average Day Hours")
            item["stationary_night_hours"] = _forensic_col(row, "Maximum Night Hours", "Average Night Hours")
            item["average_day_hours"] = _forensic_col(row, "Average Day Hours")
            item["maximum_day_hours"] = _forensic_col(row, "Maximum Day Hours")
            item["average_night_hours"] = _forensic_col(row, "Average Night Hours")
            item["maximum_night_hours"] = _forensic_col(row, "Maximum Night Hours")
            item["stationary_list"] = _forensic_col(row, "List")
            item["sources"].add("rpt_stationary_ms_imsi")

    if st_imei_df is not None:
        for row in st_imei_df.to_dict(orient="records"):
            imei = _id15(_forensic_col(row, "IMEI"))
            if not imei:
                continue
            matched_items = identities_for_imei(imei)
            if matched_items:
                target_items = matched_items
            else:
                target_items = [ensure_identity("", imei)]
            imei_avg_registrations = _forensic_int(_forensic_col(row, "Average Registrations"))
            imei_registrations = _forensic_int(_forensic_col(row, "Maximum Registrations", "Average Registrations"))
            model = _forensic_col(row, "Model")
            for item in target_items:
                if not matched_items:
                    item["registrations"] = max(int(item.get("registrations") or 0), imei_registrations)
                    item["avg_registrations"] = max(int(item.get("avg_registrations") or 0), imei_avg_registrations)
                    item["max_registrations"] = max(int(item.get("max_registrations") or 0), imei_registrations)
                else:
                    item["stationary_imei_registrations"] = max(int(item.get("stationary_imei_registrations") or 0), imei_registrations)
                if model:
                    item["model"] = model
                item["stationary_probability"] = _forensic_col(row, "Probability")
                if not item.get("stationary_days"):
                    item["stationary_days"] = _forensic_col(row, "Days")
                if not item.get("stationary_day_hours"):
                    item["stationary_day_hours"] = _forensic_col(row, "Maximum Day Hours", "Average Day Hours")
                if not item.get("stationary_night_hours"):
                    item["stationary_night_hours"] = _forensic_col(row, "Maximum Night Hours", "Average Night Hours")
                if not item.get("average_day_hours"):
                    item["average_day_hours"] = _forensic_col(row, "Average Day Hours")
                if not item.get("maximum_day_hours"):
                    item["maximum_day_hours"] = _forensic_col(row, "Maximum Day Hours")
                if not item.get("average_night_hours"):
                    item["average_night_hours"] = _forensic_col(row, "Average Night Hours")
                if not item.get("maximum_night_hours"):
                    item["maximum_night_hours"] = _forensic_col(row, "Maximum Night Hours")
                if not item.get("stationary_list"):
                    item["stationary_list"] = _forensic_col(row, "List")
                item["sources"].add("rpt_stationary_ms_imei")

    swaps: List[Dict[str, object]] = []
    if imei_swap_df is not None:
        for row in imei_swap_df.to_dict(orient="records"):
            imei = _id15(_forensic_col(row, "IMEI"))
            if not imei:
                continue
            associated = sorted({
                _id15(str(r.get("IMSI") or ""))
                for r in (st_imsi_df.to_dict(orient="records") if st_imsi_df is not None else [])
                if _id15(str(r.get("IMEI") or "")) == imei and _id15(str(r.get("IMSI") or ""))
            })
            status, wl_detail = _whitelist_context_text("", imei)
            swaps.append({
                "type": "IMEI con multiples IMSI",
                "imsi": " | ".join(associated) or "-",
                "imei": imei,
                "associated_count": _forensic_col(row, "IMSI Count"),
                "probability": _forensic_col(row, "Probability"),
                "associated_identities": " | ".join(associated) or "No listado en stationary IMSI",
                "evidence": f"{imei_swap_name} + {st_imsi_name or 'stationary IMSI no adjunto'} + {history_name}",
                "whitelist_status": status,
                "whitelist_detail": wl_detail,
            })

    if imsi_swap_df is not None:
        for row in imsi_swap_df.to_dict(orient="records"):
            imsi = _id15(_forensic_col(row, "IMSI"))
            if not imsi:
                continue
            associated = sorted({
                _id15(str(r.get("IMEI") or ""))
                for r in (st_imsi_df.to_dict(orient="records") if st_imsi_df is not None else [])
                if _id15(str(r.get("IMSI") or "")) == imsi and _id15(str(r.get("IMEI") or ""))
            })
            status, wl_detail = _whitelist_context_text(imsi, "")
            swaps.append({
                "type": "IMSI con multiples IMEI",
                "imsi": imsi,
                "imei": " | ".join(associated) or "-",
                "associated_count": _forensic_col(row, "IMEI Count"),
                "probability": _forensic_col(row, "Probability"),
                "associated_identities": " | ".join(associated) or "No listado en stationary",
                "evidence": f"{imsi_swap_name} + {st_imsi_name or 'stationary IMSI no adjunto'} + {history_name}",
                "whitelist_status": status,
                "whitelist_detail": wl_detail,
            })

    identity_rows: List[Dict[str, object]] = []
    for item in identities.values():
        imsi = str(item.get("imsi") or "-")
        imei = str(item.get("imei") or "-")
        status, wl_detail = _whitelist_context_text(imsi, imei)
        distances = [float(v) for v in item.get("distance_values", []) if isinstance(v, (int, float))]
        sources = sorted(str(v) for v in item.get("sources", set()))
        note_parts = []
        if int(item.get("registrations") or 0) > 0:
            note_parts.append("Persistencia agregada Septier")
        if int(item.get("stationary_imei_registrations") or 0) > 0:
            note_parts.append("Agregado IMEI Septier asociado")
        if any(imsi in str(s.get("imsi") or "") or imei in str(s.get("imei") or "") for s in swaps):
            note_parts.append("Asociado a reporte swap Septier")
        identity_rows.append({
            "carrier": item.get("carrier") or "DESCONOCIDA",
            "imsi": imsi,
            "imei": imei,
            "model": item.get("model") or "-",
            "registrations": int(item.get("registrations") or item.get("events") or 0),
            "avg_registrations": int(item.get("avg_registrations") or 0),
            "max_registrations": int(item.get("max_registrations") or item.get("registrations") or 0),
            "stationary_probability": item.get("stationary_probability") or "-",
            "stationary_days": item.get("stationary_days") or "-",
            "stationary_day_hours": item.get("stationary_day_hours") or "-",
            "stationary_night_hours": item.get("stationary_night_hours") or "-",
            "average_day_hours": item.get("average_day_hours") or "-",
            "maximum_day_hours": item.get("maximum_day_hours") or "-",
            "average_night_hours": item.get("average_night_hours") or "-",
            "maximum_night_hours": item.get("maximum_night_hours") or "-",
            "stationary_list": item.get("stationary_list") or "-",
            "events": int(item.get("events") or 0),
            "distance_min": min(distances) if distances else "-",
            "distance_max": max(distances) if distances else "-",
            "first_seen": item.get("first_seen") or "-",
            "last_seen": item.get("last_seen") or "-",
            "whitelist_status": status,
            "whitelist_detail": wl_detail,
            "sources": " | ".join(sources),
            "forensic_note": " + ".join(note_parts) or "Identidad detectada en history",
        })
        identity_rows[-1]["forensic_score"] = _forensic_presence_score(identity_rows[-1])
    carrier_order = {"CLARO": 1, "MOVISTAR": 2, "PERSONAL": 3, "DESCONOCIDA": 4, "OTRO": 5, "OTROS": 6}
    identity_rows.sort(key=lambda r: (-int(r.get("forensic_score") or 0), carrier_order.get(str(r.get("carrier") or ""), 99), -int(r.get("max_registrations") or r.get("registrations") or 0), -int(r.get("events") or 0), str(r.get("imsi") or ""), str(r.get("imei") or "")))

    operation = operation_label.strip() or (operations.most_common(1)[0][0] if operations else Path(history_name).stem)
    by_carrier = {
        carrier: {
            "identities": len(rows),
            "pings": sum(int(r.get("events") or 0) for r in rows),
            "registrations": sum(int(r.get("registrations") or 0) for r in rows),
        }
        for carrier, rows in sorted(
            {
                carrier: [row for row in identity_rows if str(row.get("carrier") or "DESCONOCIDA") == carrier]
                for carrier in {str(row.get("carrier") or "DESCONOCIDA") for row in identity_rows}
            }.items(),
            key=lambda item: (carrier_order.get(item[0], 99), item[0]),
        )
    }
    summary = {
        "operation": operation,
        "date": (min(times)[:10] if times else "-"),
        "first_seen": min(times) if times else "-",
        "last_seen": max(times) if times else "-",
        "history_events": len(history_records),
        "unique_imsi": len({_id15(str(r.get("IMSI") or "")) for r in history_records if _id15(str(r.get("IMSI") or ""))}),
        "unique_imei": len({_id15(str(r.get("IMEI") or "")) for r in history_records if _id15(str(r.get("IMEI") or ""))}),
        "swap_count": len(swaps),
        "by_carrier": by_carrier,
    }

    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = OUTPUTS_DIR / "paquete_forense_septier" / f"paquete_{stamp}"
    out_dir.mkdir(parents=True, exist_ok=True)
    title = f"Paquete Forense Septier - {operation}"
    html_text = _forensic_package_report_html(title, summary, identity_rows, swaps)
    html_path = out_dir / "paquete_forense_septier.html"
    csv_path = out_dir / "paquete_forense_septier.csv"
    word_path = out_dir / "paquete_forense_septier.docx"
    html_path.write_text(html_text, encoding="utf-8")
    with csv_path.open("w", newline="", encoding="utf-8-sig") as fh:
        fields = [
            "forensic_score", "carrier", "imsi", "imei", "model", "events", "registrations", "avg_registrations", "max_registrations",
            "stationary_probability", "stationary_days", "average_day_hours", "maximum_day_hours", "average_night_hours", "maximum_night_hours", "stationary_list",
            "distance_min", "distance_max", "first_seen", "last_seen", "whitelist_status", "whitelist_detail", "sources", "forensic_note",
        ]
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows([{field: row.get(field, "") for field in fields} for row in identity_rows])
    try:
        from docx import Document
        from docx.enum.section import WD_ORIENT
        from docx.shared import Inches, Pt

        def doc_text(value: object) -> str:
            return str(value if value is not None else "-")

        def add_docx_table(headers: List[str], rows: List[List[object]], *, max_rows: int = 250):
            table = doc.add_table(rows=1, cols=len(headers))
            table.style = "Table Grid"
            for idx, header in enumerate(headers):
                cell = table.rows[0].cells[idx]
                cell.text = header
                for paragraph in cell.paragraphs:
                    for run in paragraph.runs:
                        run.bold = True
                        run.font.size = Pt(8)
            for values in rows[:max_rows]:
                cells = table.add_row().cells
                for idx, value in enumerate(values):
                    cells[idx].text = doc_text(value)
                    for paragraph in cells[idx].paragraphs:
                        for run in paragraph.runs:
                            run.font.size = Pt(7)
            if len(rows) > max_rows:
                doc.add_paragraph(f"Listado limitado en Word a {max_rows} filas. CSV/HTML conservan el paquete completo.")
            return table

        doc = Document()
        section = doc.sections[0]
        section.orientation = WD_ORIENT.LANDSCAPE
        section.page_width, section.page_height = section.page_height, section.page_width
        section.top_margin = Inches(0.35)
        section.bottom_margin = Inches(0.35)
        section.left_margin = Inches(0.35)
        section.right_margin = Inches(0.35)
        doc.add_heading(title, 0)
        doc.add_paragraph(f"Operativo: {operation}")
        doc.add_paragraph(f"Rango: {summary['first_seen']} a {summary['last_seen']}")
        add_docx_table(
            ["Eventos history", "IMSI unicos", "IMEI unicos", "Swaps Septier"],
            [[summary["history_events"], summary["unique_imsi"], summary["unique_imei"], summary["swap_count"]]],
            max_rows=1,
        )
        doc.add_heading("Resumen por prestadora", level=1)
        add_docx_table(
            ["Prestadora", "Identidades IMSI", "Pings history", "Registraciones stationary"],
            [[
                carrier,
                values.get("identities"),
                values.get("pings"),
                values.get("registrations"),
            ] for carrier, values in (summary.get("by_carrier") or {}).items()],
            max_rows=20,
        )
        if not swaps:
            doc.add_paragraph(f"En el operativo {operation}, fecha {summary['date']}, no se hallaron swaps asociados a las identidades o dispositivos detectados.")
        else:
            doc.add_heading("Swaps reportados por Septier", level=1)
            add_docx_table(
                ["Tipo", "IMSI", "IMEI", "Cantidad asociada", "Probabilidad", "Identidades asociadas", "Evidencia", "Lista Blanca"],
                [[
                    swap.get("type"),
                    swap.get("imsi"),
                    swap.get("imei"),
                    swap.get("associated_count"),
                    swap.get("probability"),
                    swap.get("associated_identities"),
                    swap.get("evidence"),
                    swap.get("whitelist_status"),
                ] for swap in swaps],
                max_rows=250,
            )
        doc.add_heading("Identidades detectadas / dispositivos asociados", level=1)
        add_docx_table(
            ["Score", "Prestadora", "IMSI", "IMEI", "Modelo", "Pings", "Max Reg.", "Avg Reg.", "Prob.", "Days", "Avg Day", "Max Day", "Avg Night", "Max Night", "List", "Dist. min", "Dist. max", "Lista Blanca", "Nota forense"],
            [[
                row.get("forensic_score"),
                row.get("carrier"),
                row.get("imsi"),
                row.get("imei"),
                row.get("model"),
                row.get("events"),
                row.get("registrations"),
                row.get("avg_registrations"),
                row.get("stationary_probability"),
                row.get("stationary_days"),
                row.get("average_day_hours"),
                row.get("maximum_day_hours"),
                row.get("average_night_hours"),
                row.get("maximum_night_hours"),
                row.get("stationary_list"),
                row.get("distance_min"),
                row.get("distance_max"),
                row.get("whitelist_status"),
                row.get("forensic_note"),
            ] for row in identity_rows],
            max_rows=250,
        )
        doc.save(word_path)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"No se pudo generar Word del paquete forense: {exc}")
    sha256 = hashlib.sha256(html_path.read_bytes() + csv_path.read_bytes() + word_path.read_bytes()).hexdigest()
    return {
        "ok": True,
        "summary": summary,
        "items_count": len(identity_rows),
        "swap_count": len(swaps),
        "sha256": sha256,
        "html_url": _skyeye_output_url(html_path),
        "word_url": _skyeye_output_url(word_path),
        "csv_url": _skyeye_output_url(csv_path),
    }


@app.delete("/api/septier/delete/{system_name}/{filename}", status_code=status.HTTP_204_NO_CONTENT)
def septier_delete_file(system_name: str, filename: str, user=Depends(_require_edit)):
    target_dir = _septier_target_dir(system_name)
    file_path = target_dir / Path(filename).name
    if not file_path.exists() or not file_path.is_file():
        raise HTTPException(status_code=404, detail="Archivo no encontrado")
    try:
        file_path.unlink()
        delete_septier_history_metadata(system_name.lower(), file_path.name)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"No se pudo borrar: {exc}")
    return


@app.delete("/api/files/delete/{filename}", status_code=status.HTTP_204_NO_CONTENT)
def delete_inbox_file(filename: str, user=Depends(_require_edit)):
    file_path = REPORTS_DIR / Path(filename).name
    if file_path.suffix.lower() != ".csv":
        raise HTTPException(status_code=400, detail="Solo se pueden borrar archivos CSV")
    if not file_path.exists() or not file_path.is_file():
        raise HTTPException(status_code=404, detail="Archivo no encontrado")
    try:
        file_path.unlink()
        delete_skyeye_run_data_by_input(file_path.name)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"No se pudo borrar: {exc}")
    return


@app.delete("/api/files/general/{filename}", status_code=status.HTTP_204_NO_CONTENT)
def delete_skyeye_general_file(filename: str, user=Depends(_require_edit)):
    file_path = SKYEYE_GENERAL_DIR / Path(filename).name
    if file_path.suffix.lower() != ".csv":
        raise HTTPException(status_code=400, detail="Solo se pueden borrar archivos CSV")
    try:
        file_path.resolve().relative_to(SKYEYE_GENERAL_DIR.resolve())
    except Exception:
        raise HTTPException(status_code=400, detail="Ruta invalida")
    if not file_path.exists() or not file_path.is_file():
        raise HTTPException(status_code=404, detail="Archivo no encontrado")
    try:
        file_path.unlink()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"No se pudo borrar: {exc}")
    return


@app.delete("/api/files/processed/{folder}/{filename}", status_code=status.HTTP_204_NO_CONTENT)
def delete_processed_file(folder: str, filename: str, user=Depends(_require_edit)):
    safe_folder = Path(folder).name
    file_path = PROCESSED_DIR / safe_folder / Path(filename).name
    if file_path.suffix.lower() != ".csv":
        raise HTTPException(status_code=400, detail="Solo se pueden borrar archivos CSV")
    try:
        file_path.resolve().relative_to(PROCESSED_DIR.resolve())
    except Exception:
        raise HTTPException(status_code=400, detail="Ruta invalida")
    if not file_path.exists() or not file_path.is_file():
        raise HTTPException(status_code=404, detail="Archivo no encontrado")
    try:
        file_path.unlink()
        delete_skyeye_run_data_by_input(file_path.name, safe_folder)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"No se pudo borrar: {exc}")
    return


@app.delete("/api/files/clear-skyeye", status_code=status.HTTP_204_NO_CONTENT)
def clear_skyeye_files(user=Depends(_require_edit)):
    deleted = 0
    try:
        for p in REPORTS_DIR.glob("*.csv"):
            if p.is_file():
                p.unlink()
                deleted += 1
        for p in PROCESSED_DIR.rglob("*.csv"):
            if p.is_file():
                p.unlink()
                deleted += 1
        clear_skyeye_run_data()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"No se pudo vaciar SkyEye: {exc}")
    return


@app.get("/api/whitelist")
def api_get_whitelist(user=Depends(_require_auth)):
    return {"items": list_whitelist()}


@app.get("/api/whitelist/uploads")
def api_get_whitelist_uploads(limit: int = 100, admin=Depends(_require_admin)):
    return {"items": list_whitelist_uploads(limit=limit)}


@app.get("/api/whitelist/uploads/{upload_id}/download")
def api_download_whitelist_upload(upload_id: int, admin=Depends(_require_admin)):
    item = get_whitelist_upload(upload_id)
    if not item:
        raise HTTPException(status_code=404, detail="Upload no encontrado")
    file_path = Path(str(item.get("stored_path", ""))).resolve()
    try:
        file_path.relative_to(WHITELIST_UPLOADS_DIR.resolve())
    except Exception:
        raise HTTPException(status_code=400, detail="Ruta invalida")
    if not file_path.exists() or not file_path.is_file():
        raise HTTPException(status_code=404, detail="Archivo no encontrado")
    return FileResponse(file_path, filename=str(item.get("original_filename") or file_path.name))


@app.delete("/api/whitelist/uploads/{upload_id}", status_code=status.HTTP_204_NO_CONTENT)
def api_delete_whitelist_upload(upload_id: int, admin=Depends(_require_admin)):
    item = get_whitelist_upload(upload_id)
    if not item:
        raise HTTPException(status_code=404, detail="Upload no encontrado")
    result = delete_whitelist_upload(upload_id)
    file_path = Path(str(item.get("stored_path", ""))).resolve()
    try:
        file_path.relative_to(WHITELIST_UPLOADS_DIR.resolve())
        if file_path.exists() and file_path.is_file():
            file_path.unlink()
    except Exception:
        pass
    return


@app.post("/api/whitelist")
def api_upsert_whitelist_item(payload: WhitelistItemRequest, user=Depends(_require_edit)):
    device_id = re.sub(r"\s+", "", payload.device_id.strip())
    if not device_id:
        raise HTTPException(status_code=400, detail="Falta IMSI/IMEI/MAC o ID")
    insert_whitelist_items([{
        "device_id": device_id,
        "device_type": payload.device_type.strip() or "manual",
        "description": payload.description.strip(),
    }])
    return {"ok": True, "device_id": device_id}


@app.put("/api/whitelist/{device_id}")
def api_update_whitelist_item(device_id: str, payload: WhitelistItemRequest, user=Depends(_require_edit)):
    current_id = re.sub(r"\s+", "", device_id.strip())
    new_id = re.sub(r"\s+", "", payload.device_id.strip())
    if not current_id or not new_id:
        raise HTTPException(status_code=400, detail="Falta IMSI/IMEI/MAC o ID")
    if current_id != new_id:
        delete_whitelist_item(current_id)
    insert_whitelist_items([{
        "device_id": new_id,
        "device_type": payload.device_type.strip() or "manual",
        "description": payload.description.strip(),
    }])
    return {"ok": True, "device_id": new_id}


@app.delete("/api/whitelist/{device_id}", status_code=status.HTTP_204_NO_CONTENT)
def api_delete_whitelist(device_id: str, user=Depends(_require_edit)):
    delete_whitelist_item(device_id)
    return


@app.delete("/api/whitelist", status_code=status.HTTP_204_NO_CONTENT)
def api_clear_whitelist(user=Depends(_require_edit)):
    clear_whitelist()
    return


@app.get("/api/tower-catalog")
def api_get_tower_catalog(
    provider: str = "",
    lac: str = "",
    cell_id: str = "",
    limit: int = 500,
    with_coords_only: bool = False,
    user=Depends(_require_auth),
):
    return {
        "items": list_tower_catalog(
            provider=provider,
            lac=lac,
            cell_id=cell_id,
            limit=limit,
            with_coords_only=with_coords_only,
        )
    }


@app.post("/api/tower-catalog")
def api_upsert_tower_catalog_item(payload: TowerCatalogItemRequest, user=Depends(_require_edit)):
    inserted = upsert_tower_catalog([payload.dict()])
    return {"ok": True, "inserted": inserted}


@app.post("/api/tower-catalog/upload")
async def api_upload_tower_catalog(file: UploadFile = File(...), user=Depends(_require_edit)):
    import pandas as pd

    if not file.filename or not file.filename.lower().endswith(".csv"):
        raise HTTPException(status_code=400, detail="Sube un archivo CSV")
    raw = await file.read()
    _scan_uploaded_bytes(raw, file.filename or "archivo", "upload", user)
    try:
        from io import BytesIO

        df = pd.read_csv(BytesIO(raw), sep=None, engine="python", encoding="utf-8-sig", dtype=str)
    except Exception:
        from io import BytesIO

        df = pd.read_csv(BytesIO(raw), sep=None, engine="python", encoding="latin-1", dtype=str)
    df = clean_columns(df)
    cols = {_norm_col(c): c for c in df.columns}

    def col(*names):
        for name in names:
            found = cols.get(_norm_col(name))
            if found is not None:
                return found
        return None

    def txt(value: object) -> str:
        if pd.isna(value):
            return ""
        text = str(value).strip()
        if text.endswith(".0"):
            text = text[:-2]
        return "" if text.lower() == "nan" else text

    def num(value: object) -> Optional[float]:
        text = txt(value).replace(",", ".")
        if not text:
            return None
        try:
            return float(text)
        except Exception:
            return None

    provider_col = col("provider", "proveedor", "operador", "carrier", "network", "nombre", "empresa")
    mcc_col = col("mcc")
    mnc_col = col("mnc", "net")
    lac_col = col("lac", "tac", "area", "orig_lac", "orig lac")
    cell_col = col("cell_id", "cell id", "cid", "cell", "id celda", "id_de_celda", "eci", "enb", "identifica", "fid")
    lat_col = col("lat", "latitud", "latitude")
    lon_col = col("lon", "lng", "longitud", "longitude")
    source_col = col("source", "fuente")
    notes_col = col("notes", "nota", "observacion", "observaciones", "descripcion")
    address_cols = [c for c in [col("direccion"), col("calle"), col("numero"), col("expediente"), col("altura")] if c]

    if not cell_col:
        raise HTTPException(status_code=400, detail="El CSV debe tener CELL ID, ID de celda, CID, identifica o FID")

    rows = []
    for _, r in df.iterrows():
        lac = txt(r.get(lac_col)) if lac_col else "SIN_LAC"
        cell_id = txt(r.get(cell_col))
        if not lac or not cell_id:
            continue
        lat = num(r.get(lat_col)) if lat_col else None
        lon = num(r.get(lon_col)) if lon_col else None
        if lat is not None and lon is not None and (
            (abs(lat) > 90 and abs(lon) <= 90)
            or (-75 <= lat <= -50 and -55 <= lon <= -20)
        ):
            lat, lon = lon, lat
        notes = txt(r.get(notes_col)) if notes_col else ""
        extra_notes = []
        for c in address_cols:
            val = txt(r.get(c))
            if val:
                extra_notes.append(f"{c}: {val}")
        if not lac_col:
            extra_notes.append("sin LAC/CELL real: punto GIS de antena fisica")
        if extra_notes:
            notes = " | ".join([n for n in [notes, *extra_notes] if n])
        rows.append({
            "provider": txt(r.get(provider_col)) if provider_col else "",
            "mcc": txt(r.get(mcc_col)) if mcc_col else "",
            "mnc": txt(r.get(mnc_col)) if mnc_col else "",
            "lac": lac,
            "cell_id": cell_id,
            "lat": lat,
            "lon": lon,
            "source": txt(r.get(source_col)) if source_col else Path(file.filename).name,
            "notes": notes,
        })
    inserted = upsert_tower_catalog(rows)
    return {"ok": True, "rows": len(rows), "inserted": inserted}


@app.delete("/api/tower-catalog/{item_id}", status_code=status.HTTP_204_NO_CONTENT)
def api_delete_tower_catalog_item(item_id: int, user=Depends(_require_edit)):
    delete_tower_catalog_item(item_id)
    return


@app.delete("/api/tower-catalog", status_code=status.HTTP_204_NO_CONTENT)
def api_clear_tower_catalog(user=Depends(_require_edit)):
    clear_tower_catalog()
    return


@app.post("/api/whitelist/upload")
async def api_upload_whitelist(
    file: UploadFile = File(...),
    replace: bool = Form(False),
    user=Depends(_require_edit),
):
    content = await file.read()
    _scan_uploaded_bytes(content, file.filename or "archivo", "whitelist_upload", user)
    WHITELIST_UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
    original_name = Path(file.filename or "lista_blanca.csv").name
    stem = re.sub(r"[^A-Za-z0-9._-]+", "_", Path(original_name).stem).strip("._") or "lista_blanca"
    suffix = Path(original_name).suffix.lower() or ".csv"
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    stored_path = WHITELIST_UPLOADS_DIR / f"whitelist_{stamp}_{secrets.token_hex(4)}_{stem}{suffix}"
    stored_path.write_bytes(content)

    import csv
    import io

    rows_iter: List[Dict[str, object]] = []
    if suffix in {".xlsx", ".xls"}:
        try:
            import pandas as pd
            from io import BytesIO

            sheets = pd.read_excel(BytesIO(content), sheet_name=None, dtype=str)
        except ImportError as exc:
            raise HTTPException(status_code=500, detail=f"Falta dependencia para leer Excel de Lista Blanca: {exc}")
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"No se pudo leer Excel de Lista Blanca: {exc}")
        for sheet_name, df in sheets.items():
            df = df.fillna("")
            for row in df.to_dict(orient="records"):
                item = {str(k or "").strip(): v for k, v in row.items() if str(k or "").strip()}
                if item:
                    item["_hoja"] = sheet_name
                    rows_iter.append(item)
    else:
        try:
            text = content.decode("utf-8-sig")
        except UnicodeDecodeError:
            text = content.decode("latin-1", errors="ignore")
        delimiter = ";"
        first_line = text.split("\n", 1)[0]
        if first_line.count(",") >= first_line.count(";"):
            delimiter = ","
        rows_iter = list(csv.DictReader(io.StringIO(text), delimiter=delimiter))

    rows_to_insert = []

    def _whitelist_col_key(value: object) -> str:
        return re.sub(r"[^a-z0-9]+", "", str(value or "").lower())

    def _whitelist_device_type(col_key: str) -> str:
        if col_key == "identificador":
            return "csv_import"
        if col_key in {"imei", "imei1", "imei2"}:
            return "imei"
        if col_key in {"imsi", "imsi1", "imsi2"}:
            return "imsi"
        if col_key in {"mac", "macaddress"}:
            return "mac"
        return "csv_import"

    def _whitelist_identifier_from_value(value: object, col_key: str) -> str:
        raw = str(value or "").strip()
        if not raw or raw.lower() == "nan":
            return ""
        if raw.endswith(".0"):
            raw = raw[:-2]
        if col_key in {"mac", "macaddress"}:
            return raw
        left_side = raw.split("/", 1)[0].strip()
        left_digits = re.sub(r"\D+", "", left_side)
        if re.fullmatch(r"[\d\s.,+\-]+", left_side) and len(left_digits) == 15:
            return left_digits
        digits = re.sub(r"\D+", "", raw)
        return digits if len(digits) == 15 else ""

    def _is_whitelist_device_column(col_key: str) -> bool:
        ignored = {
            "imeisufijooriginal",
            "imsisufijooriginal",
            "sufijooriginal",
            "sufijo",
            "imeioriginal",
            "imsioriginal",
            "observaciones",
            "descripcion",
            "description",
            "detalle",
            "observacion",
        }
        if col_key in ignored:
            return False
        return col_key in {
            "identificador",
            "imsi",
            "imsi1",
            "imsi2",
            "imei",
            "imei1",
            "imei2",
            "mac",
            "macaddress",
            "deviceid",
            "dispositivo",
            "id",
        }

    def _whitelist_description(row: Dict[str, object]) -> str:
        preferred = [
            "descripcion",
            "description",
            "nombre",
            "apellido",
            "apellidoynombre",
            "nombreyapellido",
            "persona",
            "personal",
            "funcion",
            "cargo",
            "empresa",
            "dependencia",
            "departamento",
            "unidad",
            "modelo",
            "marca",
            "observaciones",
            "observacion",
            "detalle",
        ]
        normalized = {_whitelist_col_key(k): v for k, v in row.items() if k}
        parts = []
        used = set()
        for key in preferred:
            value = str(normalized.get(key) or "").strip()
            if value and value.lower() != "nan":
                label = key.replace("apellidoynombre", "apellido/nombre").replace("nombreyapellido", "nombre/apellido")
                parts.append(f"{label}: {value}")
                used.add(key)
        if not parts:
            for raw_key, raw_value in row.items():
                col_key = _whitelist_col_key(raw_key)
                if col_key in used or col_key.startswith("_") or _is_whitelist_device_column(col_key):
                    continue
                value = str(raw_value or "").strip()
                if value and value.lower() != "nan":
                    parts.append(f"{raw_key}: {value}")
                if len(parts) >= 8:
                    break
        sheet = str(row.get("_hoja") or "").strip()
        if sheet:
            parts.append(f"hoja: {sheet}")
        return " | ".join(parts)[:900]
    
    for row in rows_iter:
        normalized = {_whitelist_col_key(k): v for k, v in row.items() if k}
        desc = _whitelist_description(row)
        inserted_in_row = False
        for k, v in row.items():
            col_key = _whitelist_col_key(k)
            is_device_col = _is_whitelist_device_column(col_key)
            if not is_device_col or not v:
                continue
            device_id = _whitelist_identifier_from_value(v, col_key)
            if not device_id:
                continue
            rows_to_insert.append({
                "device_id": device_id,
                "device_type": _whitelist_device_type(col_key),
                "description": str(desc).strip(),
            })
            inserted_in_row = True
        if not inserted_in_row and row:
            first_value = str(list(row.values())[0] or "").strip()
            device_id = _whitelist_identifier_from_value(first_value, "identificador")
            if device_id:
                rows_to_insert.append({"device_id": device_id, "device_type": "csv_import", "description": str(desc).strip()})
            
    device_ids = [str(r.get("device_id", "")).strip() for r in rows_to_insert if str(r.get("device_id", "")).strip()]
    existed_before = set() if replace else whitelist_existing_ids(device_ids)
    if rows_to_insert:
        if replace:
            clear_whitelist()
        insert_whitelist_items(rows_to_insert)
    elif replace:
        clear_whitelist()
    upload_id = insert_whitelist_upload(
        original_filename=original_name,
        stored_filename=stored_path.name,
        stored_path=str(stored_path),
        uploaded_by=str(user.get("full_name") or user.get("username") or ""),
        replace_mode=replace,
        rows_count=len(rows_to_insert),
        device_ids=device_ids,
        existed_before=existed_before,
    )
    return {"ok": True, "inserted": len(rows_to_insert), "replaced": replace, "upload_id": upload_id}


def _csv_date_range(path: Path) -> dict:
    """Return the min/max Detect Time from a detection CSV."""
    try:
        import pandas as pd
        df = pd.read_csv(path, sep=None, engine="python", encoding="latin-1")
        df = clean_columns(df)
        if "Detect Time" not in df.columns:
            return {}
        dates = pd.to_datetime(df["Detect Time"], format="%Y.%m.%d %H:%M:%S", errors="coerce").dropna()
        if dates.empty:
            return {}
        return {
            "data_date_from": dates.min().strftime("%Y-%m-%d"),
            "data_date_to": dates.max().strftime("%Y-%m-%d"),
        }
    except Exception:
        return {}


@app.get("/api/files")
def list_inbox_files(user=Depends(_require_auth)):
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    SKYEYE_GENERAL_DIR.mkdir(parents=True, exist_ok=True)

    items = []
    for p in sorted(REPORTS_DIR.glob("*.csv"), key=lambda x: x.stat().st_mtime, reverse=True):
        kind = _detect_csv_kind(p)
        item = {
            "name": p.name,
            "size": p.stat().st_size,
            "kind": kind,
            "modified_at": dt.datetime.fromtimestamp(p.stat().st_mtime).isoformat(timespec="seconds"),
        }
        if kind == "detection":
            item.update(_csv_date_range(p))
        items.append(item)

    processed_items = []
    for p in sorted(PROCESSED_DIR.rglob("*.csv"), key=lambda x: x.stat().st_mtime, reverse=True):
        kind = _detect_csv_kind(p)
        item = {
            "name": p.name,
            "size": p.stat().st_size,
            "kind": kind,
            "modified_at": dt.datetime.fromtimestamp(p.stat().st_mtime).isoformat(timespec="seconds"),
            "folder": p.parent.name,
        }
        if kind == "detection":
            item.update(_csv_date_range(p))
        processed_items.append(item)

    general_items = []
    for p in sorted(SKYEYE_GENERAL_DIR.glob("*.csv"), key=lambda x: x.stat().st_mtime, reverse=True):
        kind = _detect_csv_kind(p)
        item = {
            "name": p.name,
            "size": p.stat().st_size,
            "kind": kind,
            "modified_at": dt.datetime.fromtimestamp(p.stat().st_mtime).isoformat(timespec="seconds"),
            "scope": "general",
        }
        if kind == "detection":
            item.update(_csv_date_range(p))
        general_items.append(item)

    return {
        "items": items,
        "processed_items": processed_items,
        "general_items": general_items,
        "processed_dir": str(PROCESSED_DIR.resolve()),
    }


def _safe_rel(base: Path, target: Path) -> str:
    return target.resolve().relative_to(base.resolve()).as_posix()


@app.get("/api/outputs/explorer")
def outputs_explorer(user=Depends(_require_auth)):
    OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)

    runs = []
    for run_dir in sorted([p for p in OUTPUTS_DIR.iterdir() if p.is_dir()], key=lambda x: x.stat().st_mtime, reverse=True):
        files = []
        for p in sorted(run_dir.rglob("*")):
            if not p.is_file():
                continue
            if p.suffix.lower() not in {".kml", ".html", ".csv", ".txt"}:
                continue
            files.append(
                {
                    "name": p.name,
                    "relative": _safe_rel(OUTPUTS_DIR, p),
                    "section": _safe_rel(OUTPUTS_DIR, p.parent),
                }
            )
        runs.append(
            {
                "name": run_dir.name,
                "path": _safe_rel(OUTPUTS_DIR, run_dir),
                "files": files,
            }
        )

    root_files = []
    for p in sorted(OUTPUTS_DIR.glob("*")):
        if p.is_file() and p.suffix.lower() in {".kml", ".html", ".csv", ".txt"}:
            root_files.append({"name": p.name, "relative": _safe_rel(OUTPUTS_DIR, p)})

    return {
        "base": str(OUTPUTS_DIR.resolve()),
        "runs": runs,
        "root_files": root_files,
    }


def _output_path_from_rel(relative_path: str) -> Path:
    candidate = (OUTPUTS_DIR / relative_path).resolve()
    try:
        candidate.relative_to(OUTPUTS_DIR.resolve())
    except Exception:
        raise HTTPException(status_code=400, detail="Ruta invalida")
    return candidate


@app.delete("/api/outputs/file/{relative_path:path}", status_code=status.HTTP_204_NO_CONTENT)
def delete_output_file(relative_path: str, user=Depends(_require_edit)):
    file_path = _output_path_from_rel(relative_path)
    if not file_path.exists() or not file_path.is_file():
        raise HTTPException(status_code=404, detail="Archivo no encontrado")
    try:
        file_path.unlink()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"No se pudo borrar archivo: {exc}")
    return


@app.delete("/api/outputs/run/{relative_path:path}", status_code=status.HTTP_204_NO_CONTENT)
def delete_output_run(relative_path: str, user=Depends(_require_edit)):
    run_path = _output_path_from_rel(relative_path)
    if run_path == OUTPUTS_DIR.resolve():
        raise HTTPException(status_code=400, detail="No se puede borrar la carpeta base de salidas")
    if not run_path.exists() or not run_path.is_dir():
        raise HTTPException(status_code=404, detail="Carpeta no encontrada")
    try:
        shutil.rmtree(run_path)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"No se pudo borrar carpeta: {exc}")
    return


@app.post("/api/files/upload")
async def upload_files(files: List[UploadFile] = File(...), user=Depends(_require_edit)):
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    saved = []
    for up in files:
        if not up.filename:
            continue
        safe_name = Path(up.filename).name
        if not safe_name.lower().endswith(".csv"):
            continue

        data = await up.read()
        _scan_uploaded_bytes(data, up.filename or "archivo", "upload", user)
        temp_target = REPORTS_DIR / f"upload_tmp_{secrets.token_hex(6)}.csv"
        temp_target.write_bytes(data)

        kind = _detect_csv_kind(temp_target)
        final_target = _build_upload_target(kind, safe_name)
        temp_target.replace(final_target)

        saved.append(
            {
                "original": safe_name,
                "saved_as": final_target.name,
                "kind": kind,
            }
        )

    if not saved:
        raise HTTPException(status_code=400, detail="No se subieron CSV validos")

    return {"ok": True, "saved": saved}


@app.post("/api/files/upload-general")
async def upload_skyeye_general_files(files: List[UploadFile] = File(...), user=Depends(_require_edit)):
    SKYEYE_GENERAL_DIR.mkdir(parents=True, exist_ok=True)

    saved = []
    for up in files:
        if not up.filename:
            continue
        safe_name = Path(up.filename).name
        if not safe_name.lower().endswith(".csv"):
            continue

        data = await up.read()
        _scan_uploaded_bytes(data, up.filename or "archivo", "upload", user)
        temp_target = SKYEYE_GENERAL_DIR / f"upload_tmp_{secrets.token_hex(6)}.csv"
        temp_target.write_bytes(data)

        kind = _detect_csv_kind(temp_target)
        final_target = _build_skyeye_general_target(kind, safe_name)
        temp_target.replace(final_target)

        saved.append(
            {
                "original": safe_name,
                "saved_as": final_target.name,
                "kind": kind,
                "scope": "general",
                "counts_impact": False,
            }
        )

    if not saved:
        raise HTTPException(status_code=400, detail="No se subieron CSV generales validos")

    return {"ok": True, "saved": saved, "scope": "general", "counts_impact": False}


@app.post("/api/runs/process-latest")
def process_latest(user=Depends(_require_edit)):
    try:
        payload = run_end_to_end_for_latest()

        detection_csv = Path(str(payload.get("input_detection_csv", "")))
        trajectory_raw = payload.get("input_trajectory_csv")
        trajectory_csv = Path(str(trajectory_raw)) if trajectory_raw else None
        archived = _archive_processed_inputs(detection_csv, trajectory_csv)

        if archived.get("detection"):
            payload["input_detection_csv"] = str(archived["detection"])
        if archived.get("trajectory"):
            payload["input_trajectory_csv"] = str(archived["trajectory"])

        run_id = insert_run(payload)

        # persist detection points for heatmap
        try:
            final_detection_csv = Path(str(payload["input_detection_csv"])) if payload.get("input_detection_csv") else detection_csv
            det_rows = _extract_detections_for_db(final_detection_csv, run_id)
            insert_detections(run_id, det_rows)
        except Exception:
            pass

        result = get_run(run_id)
        return {"ok": True, "run": result}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc)}


def _skyeye_detection_files_for_index() -> List[Path]:
    candidates: List[Path] = []
    for base in (REPORTS_DIR, PROCESSED_DIR):
        if not base.exists():
            continue
        iterator = base.rglob("*.csv") if base == PROCESSED_DIR else base.glob("*.csv")
        for path in iterator:
            if not path.is_file():
                continue
            try:
                if _detect_csv_kind(path) == "detection":
                    candidates.append(path)
            except Exception:
                continue
    return sorted(candidates, key=lambda p: (str(p.parent), p.name))


@app.post("/api/runs/index-existing")
def index_existing_skyeye_runs(user=Depends(_require_edit)):
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)

    files = _skyeye_detection_files_for_index()
    indexed: List[Dict[str, object]] = []
    skipped: List[Dict[str, object]] = []
    errors: List[Dict[str, object]] = []

    for detection_csv in files:
        if _skyeye_find_run_for_file(detection_csv):
            skipped.append({"file": detection_csv.name, "reason": "ya indexado"})
            continue

        safe_stem = re.sub(r"[^A-Za-z0-9._-]+", "_", detection_csv.stem).strip("._") or "skyeye"
        run_dir = OUTPUTS_DIR / "skyeye_indexado" / f"{safe_stem}_{dt.datetime.now().strftime('%Y%m%d_%H%M%S_%f')}"
        run_dir.mkdir(parents=True, exist_ok=True)
        trajectory_csv = _skyeye_find_trajectory_for_file(detection_csv)
        html_report_path: Optional[Path] = run_dir / "reporte_detecciones.html"
        drones_commands_path: Optional[Path] = run_dir / "drones_y_comandos.csv"

        try:
            try:
                generar_reporte_html(str(detection_csv), str(html_report_path))
            except Exception:
                html_report_path = None
            try:
                build_drones_commands_file(detection_csv, trajectory_csv, drones_commands_path)
            except Exception:
                drones_commands_path = None

            payload = {
                "created_at": dt.datetime.now().isoformat(timespec="seconds"),
                "input_detection_csv": str(detection_csv),
                "input_trajectory_csv": str(trajectory_csv) if trajectory_csv else None,
                "output_dir": str(run_dir),
                "html_report": str(html_report_path) if html_report_path and html_report_path.exists() else "",
                "tracks_kml": "",
                "last_seen_kml": "",
                "geo_txt_report": "",
                "m3t_kml": "",
                "drones_commands_file": str(drones_commands_path) if drones_commands_path and drones_commands_path.exists() else "",
                "status": "ok",
                "message": "SkyEye indexado desde archivo existente",
                "m3t_summary": {"status": "bajo_demanda"},
            }
            run_id = insert_run(payload)
            det_rows = _extract_detections_for_db(detection_csv, run_id)
            insert_detections(run_id, det_rows)
            indexed.append({
                "run_id": run_id,
                "file": detection_csv.name,
                "points": len(det_rows),
                **_csv_date_range(detection_csv),
            })
        except Exception as exc:
            errors.append({"file": detection_csv.name, "error": str(exc)})

    return {
        "ok": not errors,
        "found": len(files),
        "indexed": indexed,
        "indexed_count": len(indexed),
        "skipped": skipped,
        "skipped_count": len(skipped),
        "errors": errors,
        "errors_count": len(errors),
    }


@app.get("/api/runs")
def runs(user=Depends(_require_auth)):
    return {"items": list_runs()}


@app.get("/api/runs/{run_id}")
def run_detail(run_id: int, user=Depends(_require_auth)):
    run = get_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run no encontrado")
    return run


def _skyeye_output_url(path_value: object) -> str:
    if not path_value:
        return ""
    try:
        p = Path(str(path_value)).resolve()
        rel = p.relative_to(OUTPUTS_DIR.resolve()).as_posix()
        return f"/outputs/{rel}"
    except Exception:
        return ""


def _skyeye_find_run_for_file(file_path: Path) -> Optional[Dict[str, object]]:
    try:
        target = file_path.resolve()
    except Exception:
        target = file_path
    for run in list_runs():
        try:
            if Path(str(run.get("input_detection_csv") or "")).resolve() == target:
                return run
        except Exception:
            continue
    return None


def _skyeye_find_trajectory_for_file(file_path: Path) -> Optional[Path]:
    try:
        base = file_path.resolve()
    except Exception:
        base = file_path
    candidates: List[Path] = []
    search_dirs = [base.parent, REPORTS_DIR, PROCESSED_DIR]
    seen_dirs = set()
    for directory in search_dirs:
        try:
            resolved = directory.resolve()
        except Exception:
            resolved = directory
        if str(resolved) in seen_dirs or not resolved.exists():
            continue
        seen_dirs.add(str(resolved))
        iterator = resolved.rglob("*.csv") if resolved == PROCESSED_DIR.resolve() else resolved.glob("*.csv")
        for p in iterator:
            if p.resolve() == base:
                continue
            try:
                if _detect_csv_kind(p) == "trajectory":
                    candidates.append(p)
            except Exception:
                continue
    if not candidates:
        return None
    return sorted(candidates, key=lambda p: (0 if p.parent.resolve() == base.parent.resolve() else 1, abs(p.stat().st_mtime - base.stat().st_mtime)))[0]


def _skyeye_file_from_payload(payload: SkyEyeReportRequest) -> Optional[Path]:
    filename = Path(payload.filename.strip()).name
    if not filename:
        return None

    area = payload.area.strip().lower() or "inbox"
    if area == "processed":
        folder = Path(payload.folder.strip()).name
        if not folder:
            raise HTTPException(status_code=400, detail="Lote procesado no informado")
        candidate = (PROCESSED_DIR / folder / filename).resolve()
        try:
            candidate.relative_to(PROCESSED_DIR.resolve())
        except Exception:
            raise HTTPException(status_code=400, detail="Archivo SkyEye invalido")
    elif area == "general":
        candidate = (SKYEYE_GENERAL_DIR / filename).resolve()
        try:
            candidate.relative_to(SKYEYE_GENERAL_DIR.resolve())
        except Exception:
            raise HTTPException(status_code=400, detail="Archivo SkyEye invalido")
    else:
        candidate = (REPORTS_DIR / filename).resolve()
        try:
            candidate.relative_to(REPORTS_DIR.resolve())
        except Exception:
            raise HTTPException(status_code=400, detail="Archivo SkyEye invalido")

    if not candidate.exists() or not candidate.is_file():
        raise HTTPException(status_code=404, detail="Archivo SkyEye no encontrado")
    if _detect_csv_kind(candidate) != "detection":
        raise HTTPException(status_code=400, detail="El informe SkyEye se genera sobre Detection Report")
    return candidate


def _skyeye_read_csv(path_value: object):
    import pandas as pd

    p = Path(str(path_value or ""))
    if not p.exists() or not p.is_file():
        raise HTTPException(status_code=404, detail=f"Archivo SkyEye no encontrado: {p.name or path_value}")
    try:
        df = pd.read_csv(p, sep=None, engine="python", encoding="utf-8-sig", dtype=str)
    except Exception:
        df = pd.read_csv(p, sep=None, engine="python", encoding="latin-1", dtype=str)
    return clean_columns(df).fillna("")


def _skyeye_counts(records: List[Dict[str, object]], field: str, limit: int = 10) -> List[Tuple[str, int]]:
    counts: Dict[str, int] = {}
    for row in records:
        value = str(row.get(field) or "").strip()
        if not value:
            continue
        counts[value] = counts.get(value, 0) + 1
    return sorted(counts.items(), key=lambda x: (-x[1], x[0]))[:limit]


def _skyeye_time_range(records: List[Dict[str, object]], field: str) -> Tuple[str, str]:
    import pandas as pd

    values = [str(row.get(field) or "").strip() for row in records if str(row.get(field) or "").strip()]
    if not values:
        return "", ""
    parsed = pd.to_datetime(values, format="%Y.%m.%d %H:%M:%S", errors="coerce").dropna()
    if parsed.empty:
        return min(values), max(values)
    return parsed.min().strftime("%Y-%m-%d %H:%M:%S"), parsed.max().strftime("%Y-%m-%d %H:%M:%S")


def _skyeye_detection_points(records: List[Dict[str, object]], limit: int = 12) -> List[Dict[str, str]]:
    points: List[Dict[str, str]] = []
    for row in records:
        coord = parse_latlon(row.get("Last Detected Location (Lat Lng)", "")) or parse_latlon(row.get("Nearest Location [Lat Lng]", ""))
        if not coord:
            continue
        lat, lon = coord
        points.append({
            "time": str(row.get("Detect Time") or "").strip(),
            "model": str(row.get("Model") or "").strip(),
            "device_id": str(row.get("Device ID") or "").strip(),
            "sensor": str(row.get("Sensor") or "").strip(),
            "lat": str(lat),
            "lon": str(lon),
            "maps": f"https://maps.google.com/?q={lat},{lon}",
            "earth": f"https://earth.google.com/web/search/{lat},{lon}",
        })
    return points[:limit]


def _skyeye_trajectory_summaries(commands_path: object, fallback_records: List[Dict[str, object]], limit: int = 12) -> List[Dict[str, str]]:
    groups: Dict[str, Dict[str, object]] = {}
    if commands_path and Path(str(commands_path)).exists():
        try:
            df = _skyeye_read_csv(commands_path)
            rows = df.to_dict(orient="records")
        except Exception:
            rows = []
    else:
        rows = []

    if not rows:
        rows = [{
            "timestamp": r.get("Detect Time", ""),
            "device_id": r.get("Device ID", ""),
            "model": r.get("Model", ""),
            "source": r.get("Source", ""),
            "lat": (parse_latlon(r.get("Last Detected Location (Lat Lng)", "")) or ("", ""))[0],
            "lon": (parse_latlon(r.get("Last Detected Location (Lat Lng)", "")) or ("", ""))[1],
            "google_maps": "",
            "google_earth": "",
        } for r in fallback_records]

    for row in rows:
        device = str(row.get("device_id") or row.get("Device ID") or "").strip() or "SIN_DEVICE_ID"
        model = str(row.get("model") or row.get("Model") or "").strip()
        key = f"{device}|{model}"
        ts = str(row.get("timestamp") or row.get("Timestamp") or "").strip()
        item = groups.setdefault(key, {
            "device_id": device,
            "model": model,
            "count": 0,
            "first": ts,
            "last": ts,
            "maps": str(row.get("google_maps") or "").strip(),
            "earth": str(row.get("google_earth") or "").strip(),
        })
        item["count"] = int(item["count"]) + 1
        if ts and (not item["first"] or ts < str(item["first"])):
            item["first"] = ts
        if ts and (not item["last"] or ts > str(item["last"])):
            item["last"] = ts
            item["maps"] = str(row.get("google_maps") or "").strip()
            item["earth"] = str(row.get("google_earth") or "").strip()

    return sorted(groups.values(), key=lambda x: (-int(x["count"]), str(x["device_id"])))[:limit]


def _skyeye_clean_device_id(value: object) -> str:
    text = str(value or "").strip()
    match = re.fullmatch(r'=T\("([^"]+)"\)', text)
    if match:
        return match.group(1).strip()
    return text


def _skyeye_near_probability(value: object) -> Tuple[str, Optional[float]]:
    text = str(value or "").strip()
    match = re.search(r"([A-Za-z]+)\s*-\s*(\d+(?:\.\d+)?)%", text)
    if match:
        return match.group(1).strip(), float(match.group(2))
    match = re.search(r"(\d+(?:\.\d+)?)%", text)
    if match:
        return "", float(match.group(1))
    return "", None


def _skyeye_duration_seconds(value: object) -> int:
    text = str(value or "").strip().lower()
    match = re.fullmatch(r"(\d+)s", text)
    if match:
        return int(match.group(1))
    match = re.fullmatch(r"(\d+):(\d+)", text)
    if match:
        return int(match.group(1)) * 60 + int(match.group(2))
    return 0


def _skyeye_device_proximity_patterns(records: List[Dict[str, object]], limit: int = 25) -> List[Dict[str, object]]:
    groups: Dict[str, Dict[str, object]] = {}
    for row in records:
        device_id = _skyeye_clean_device_id(row.get("Device ID")) or "SIN_DEVICE_ID"
        item = groups.setdefault(device_id, {
            "device_id": device_id,
            "events": 0,
            "detection_count": 0,
            "days": set(),
            "first": "",
            "last": "",
            "models": Counter(),
            "frequencies": Counter(),
            "sources": Counter(),
            "tags": Counter(),
            "near_values": [],
            "near_labels": Counter(),
            "geo_rows": 0,
            "location_rows": 0,
            "duration_seconds": 0,
        })
        item["events"] = int(item["events"]) + 1
        ts = str(row.get("Detect Time") or "").strip()
        if ts:
            if not item["first"] or ts < str(item["first"]):
                item["first"] = ts
            if not item["last"] or ts > str(item["last"]):
                item["last"] = ts
            item["days"].add(ts[:10])
        model = str(row.get("Model") or "").strip()
        if model:
            item["models"][model] += 1
        frequency = str(row.get("Frequency") or "").strip()
        if frequency:
            item["frequencies"][frequency] += 1
        source = str(row.get("Source") or "").strip()
        if source:
            item["sources"][source] += 1
        tag = str(row.get("tag") or "").strip()
        if tag:
            item["tags"][tag] += 1
        label, near_value = _skyeye_near_probability(row.get("Max Near Probability"))
        if label:
            item["near_labels"][label] += 1
        if near_value is not None:
            item["near_values"].append(near_value)
        if str(row.get("Report Type") or "").strip().lower() == "geo location":
            item["geo_rows"] = int(item["geo_rows"]) + 1
        if str(row.get("Nearest Location [Lat Lng]") or "").strip() or str(row.get("Last Detected Location (Lat Lng)") or "").strip():
            item["location_rows"] = int(item["location_rows"]) + 1
        item["duration_seconds"] = int(item["duration_seconds"]) + _skyeye_duration_seconds(row.get("Stay Duration"))
        try:
            item["detection_count"] = int(item["detection_count"]) + int(float(str(row.get("Detection Count") or "0").strip() or 0))
        except Exception:
            pass

    patterns: List[Dict[str, object]] = []
    for item in groups.values():
        near_values = list(item.get("near_values") or [])
        near_total = len(near_values)
        near_ge90 = sum(1 for value in near_values if float(value) >= 90)
        near_ge70 = sum(1 for value in near_values if float(value) >= 70)
        near_ge50 = sum(1 for value in near_values if float(value) >= 50)
        near_high_pct = round((near_ge90 / near_total) * 100, 1) if near_total else 0.0
        near_avg = round(sum(float(v) for v in near_values) / near_total, 1) if near_total else None
        near_max = max(near_values) if near_values else None
        tags = item.get("tags") or Counter()
        events = int(item.get("events") or 0)
        days = len(item.get("days") or [])
        if near_total and near_high_pct >= 70 and events >= 5 and any(str(t).lower() in {"suspicious", "enemy"} for t in tags):
            priority = "ALTA"
        elif near_total and (near_ge70 >= 5 or events >= 15):
            priority = "MEDIA"
        else:
            priority = "REVISION"
        patterns.append({
            "device_id": item["device_id"],
            "events": events,
            "detection_count": int(item.get("detection_count") or 0),
            "days": days,
            "first": item.get("first") or "",
            "last": item.get("last") or "",
            "model": (item.get("models") or Counter()).most_common(1)[0][0] if item.get("models") else "",
            "frequency": (item.get("frequencies") or Counter()).most_common(1)[0][0] if item.get("frequencies") else "",
            "source": (item.get("sources") or Counter()).most_common(1)[0][0] if item.get("sources") else "",
            "tag": (item.get("tags") or Counter()).most_common(1)[0][0] if item.get("tags") else "",
            "near_total": near_total,
            "near_ge50": near_ge50,
            "near_ge70": near_ge70,
            "near_ge90": near_ge90,
            "near_high_pct": near_high_pct,
            "near_avg": near_avg,
            "near_max": near_max,
            "geo_rows": int(item.get("geo_rows") or 0),
            "location_rows": int(item.get("location_rows") or 0),
            "duration_seconds": int(item.get("duration_seconds") or 0),
            "priority": priority,
        })
    return sorted(
        patterns,
        key=lambda x: (
            {"ALTA": 3, "MEDIA": 2, "REVISION": 1}.get(str(x.get("priority")), 0),
            int(x.get("near_ge90") or 0),
            int(x.get("events") or 0),
            int(x.get("days") or 0),
        ),
        reverse=True,
    )[:limit]


def _skyeye_defense_summary(records: List[Dict[str, object]], limit: int = 20) -> List[Dict[str, str]]:
    defense_columns = {
        "method": "Defense Method",
        "trigger": "Defense Trigger",
        "attempt": "Defense Attempt",
        "duration": "Defense Duration (min:sec)",
        "time": "Defense Time",
    }
    if not any(any(key.lower() == str(col).lower() for col in (records[0].keys() if records else [])) for key in defense_columns.values()):
        return []
    rows: List[Dict[str, str]] = []
    for row in records:
        if not any(str(row.get(col) or "").strip() for col in defense_columns.values()):
            continue
        rows.append({
            "device_id": _skyeye_clean_device_id(row.get("Device ID")),
            "model": str(row.get("Model") or "").strip(),
            "frequency": str(row.get("Frequency") or "").strip(),
            "time": str(row.get(defense_columns["time"]) or row.get("Detect Time") or "").strip(),
            "trigger": str(row.get(defense_columns["trigger"]) or "").strip(),
            "method": str(row.get(defense_columns["method"]) or "").strip(),
            "duration": str(row.get(defense_columns["duration"]) or "").strip(),
            "attempt": str(row.get(defense_columns["attempt"]) or "").strip(),
            "sensor": str(row.get("Sensor") or "").strip(),
        })
    return rows[:limit]


def _skyeye_html_table(headers: List[str], rows: List[List[str]]) -> str:
    if not rows:
        return "<p class='muted'>Sin datos verificables.</p>"
    head = "".join(f"<th>{html_lib.escape(h)}</th>" for h in headers)
    body = "".join(
        "<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>"
        for row in rows
    )
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def _generate_skyeye_report_html(run: Dict[str, object], observaciones: str, user: Dict[str, object], device_id: str = "") -> Path:
    detection_df = _skyeye_read_csv(run.get("input_detection_csv"))
    selected_device = device_id.strip()
    if selected_device and "Device ID" in detection_df.columns:
        detection_df = detection_df[detection_df["Device ID"].fillna("").astype(str).str.strip() == selected_device].copy()
        if detection_df.empty:
            raise HTTPException(status_code=404, detail=f"No hay detecciones SkyEye para Device ID {selected_device}")
    records = detection_df.to_dict(orient="records")
    run_dir = Path(str(run.get("output_dir") or "")).resolve()
    try:
        run_dir.relative_to(OUTPUTS_DIR.resolve())
    except Exception:
        run_dir = OUTPUTS_DIR / f"run_{run.get('id', 'skyeye')}"
    if not run_dir.exists():
        run_dir = OUTPUTS_DIR / f"run_{run.get('id', 'skyeye')}"
        run_dir.mkdir(parents=True, exist_ok=True)

    total = len(records)
    models = _skyeye_counts(records, "Model")
    devices = _skyeye_counts(records, "Device ID", limit=20)
    sensors = _skyeye_counts(records, "Sensor")
    locations = _skyeye_counts(records, "Detection Engine")
    report_days = {
        str(value).strip()[:10]
        for value in (str(row.get("Detect Time") or "").strip() for row in records)
        if value
    }
    start_time, end_time = _skyeye_time_range(records, "Detect Time")
    points = _skyeye_detection_points(records)
    trajectories = _skyeye_trajectory_summaries(run.get("drones_commands_file"), records)
    proximity_patterns = _skyeye_device_proximity_patterns(records)
    defense_events = _skyeye_defense_summary(records)
    tz_ar = dt.timezone(dt.timedelta(hours=-3))
    generated_at = dt.datetime.now(tz_ar).strftime("%Y-%m-%d %H:%M:%S UTC-3")
    report_name = f"informe_skyeye_run_{run.get('id')}_{dt.datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    out_path = run_dir / report_name

    def e(value: object) -> str:
        return html_lib.escape(str(value or ""))

    model_rows = [[e(k), e(v)] for k, v in models]
    device_rows = [[e(k), e(v)] for k, v in devices]
    sensor_rows = [[e(k), e(v)] for k, v in sensors]
    location_rows = [[e(k), e(v)] for k, v in locations]
    point_rows = [[
        e(p["time"]), e(p["model"]), e(p["device_id"]), e(p["sensor"]),
        e(f'{p["lat"]}, {p["lon"]}'),
        f'<a href="{e(p["maps"])}" target="_blank" rel="noopener">Mapa</a> | <a href="{e(p["earth"])}" target="_blank" rel="noopener">Earth</a>',
    ] for p in points]
    trajectory_rows = [[
        e(t["device_id"]), e(t["model"]), e(t["count"]), e(t["first"]), e(t["last"]),
        (f'<a href="{e(t["maps"])}" target="_blank" rel="noopener">Mapa</a>' if t.get("maps") else "-"),
    ] for t in trajectories]
    proximity_rows = [[
        e(p["priority"]),
        e(p["device_id"]),
        e(p["model"]),
        e(p["source"]),
        e(p["tag"]),
        e(p["frequency"]),
        e(p["events"]),
        e(p["detection_count"]),
        e(p["days"]),
        e(p["first"]),
        e(p["last"]),
        e(p["near_total"]),
        e(p["near_ge90"]),
        e(f'{p["near_high_pct"]}%'),
        e(p["near_avg"] if p["near_avg"] is not None else "-"),
        e(p["near_max"] if p["near_max"] is not None else "-"),
        e("si" if int(p["location_rows"] or 0) else "no"),
    ] for p in proximity_patterns]
    defense_rows = [[
        e(d["time"]), e(d["device_id"]), e(d["model"]), e(d["frequency"]),
        e(d["trigger"]), e(d["method"]), e(d["duration"]), e(d["attempt"]), e(d["sensor"]),
    ] for d in defense_events]

    links = []
    for label, key in [
        ("Reporte HTML procesado", "html_report"),
        ("Trayectorias KML", "tracks_kml"),
        ("Ultimas posiciones KML", "last_seen_kml"),
        ("Reporte georreferenciacion TXT", "geo_txt_report"),
        ("KML M3T", "m3t_kml"),
        ("KML trayectoria Device ID", "device_trajectory_kml"),
        ("Drones y comandos CSV", "drones_commands_file"),
    ]:
        url = _skyeye_output_url(run.get(key))
        if url:
            links.append(f'<li><a href="{e(url)}" target="_blank" rel="noopener">{e(label)}</a></li>')

    obs = e(observaciones.strip()) if observaciones.strip() else "Sin observaciones operativas cargadas."
    html = f"""<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="utf-8" />
  <title>Informe SkyEye Run {e(run.get('id'))}</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 28px; color: #172033; }}
    h1, h2 {{ color: #0f3b66; }}
    .meta, .card {{ border: 1px solid #d8dee8; border-radius: 8px; padding: 12px; margin: 12px 0; }}
    .grid {{ display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; }}
    .note {{ background: #f7fbff; border-left: 4px solid #2b7de9; padding: 10px 12px; margin: 12px 0; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 8px; font-size: 13px; }}
    th, td {{ border: 1px solid #d8dee8; padding: 7px; text-align: left; vertical-align: top; }}
    th {{ background: #eef4fb; }}
    .muted {{ color: #667085; }}
    .kpi {{ font-size: 22px; font-weight: 700; color: #0f3b66; }}
    @media print {{ a {{ color: #172033; }} .grid {{ grid-template-columns: 1fr 1fr; }} }}
  </style>
</head>
<body>
  <h1>Informe Operativo SkyEye</h1>
  <div class="meta">
    <strong>Run:</strong> #{e(run.get('id'))} | <strong>Procesado:</strong> {e(run.get('created_at'))} | <strong>Generado:</strong> {e(generated_at)}<br>
    <strong>Usuario:</strong> {e(user.get('username'))} | <strong>Periodo detectado (hora CSV):</strong> {e(start_time or '-')} a {e(end_time or '-')}
    {f'<br><strong>Device ID filtrado:</strong> {e(selected_device)}' if selected_device else ''}
  </div>
  <div class="grid">
    <div class="card"><div class="kpi">{total}</div><div>Total de detecciones</div></div>
    <div class="card"><div class="kpi">{len(models)}</div><div>Drones/modelos detectados</div></div>
    <div class="card"><div class="kpi">{len(devices)}</div><div>Device ID unicos</div></div>
    <div class="card"><div class="kpi">{len(report_days)}</div><div>Dias detectados en este reporte</div></div>
  </div>
  <h2>Drones / modelos detectados</h2>
  {_skyeye_html_table(["Modelo", "Detecciones"], model_rows)}
  <h2>Device ID</h2>
  {_skyeye_html_table(["Device ID", "Detecciones"], device_rows)}
  <h2>Patrones de recurrencia y proximidad por Device ID</h2>
  <div class="note">
    <strong>Geovalla operativa:</strong> 1300 metros. En este reporte, <strong>Max Near Probability</strong> se interpreta como cercania estimada por SkyEye, no como distancia metrica.
    Para calcular metros reales dentro/fuera de geovalla se requiere coordenada fija del sensor o distancia exportada por el sistema.
  </div>
  {_skyeye_html_table(["Prioridad", "Device ID", "Modelo", "Source", "Tag", "Frecuencia", "Eventos", "Detection Count", "Dias", "Primera", "Ultima", "Con cercania", "Near >= 90%", "% cercania alta", "Near promedio", "Near max", "Coordenadas"], proximity_rows)}
  <h2>Sensores</h2>
  {_skyeye_html_table(["Sensor", "Detecciones"], sensor_rows)}
  <h2>Horarios</h2>
  <div class="card">Primera deteccion verificable: <strong>{e(start_time or '-')}</strong><br>Ultima deteccion verificable: <strong>{e(end_time or '-')}</strong></div>
  <h2>Ubicaciones / coordenadas</h2>
  {_skyeye_html_table(["Hora", "Modelo", "Device ID", "Sensor", "Coordenadas", "Referencia geografica"], point_rows)}
  <h2>Ubicaciones por motor de deteccion</h2>
  {_skyeye_html_table(["Ubicacion / motor", "Detecciones"], location_rows)}
  <h2>Trayectorias importantes</h2>
  {_skyeye_html_table(["Device ID", "Modelo", "Puntos", "Primera marca", "Ultima marca", "Referencia"], trajectory_rows)}
  <h2>Activacion / defensa del sistema</h2>
  <div class="note">
    Esta seccion se completa cuando el CSV contiene columnas Defense. Si no hay datos, el archivo analizado corresponde a detecciones/geolocalizacion y no acredita activacion de defensa.
  </div>
  {_skyeye_html_table(["Hora", "Device ID", "Modelo", "Frecuencia", "Trigger", "Metodo", "Duracion", "Resultado", "Sensor"], defense_rows)}
  <h2>Mapa / referencias geograficas existentes</h2>
  <ul>{''.join(links) if links else '<li class="muted">Sin referencias geograficas asociadas al run.</li>'}</ul>
  <h2>Observaciones operativas</h2>
  <div class="card">{obs}</div>
</body>
</html>"""
    out_path.write_text(html, encoding="utf-8")
    return out_path


@app.post("/api/skyeye/report/generate")
def skyeye_report_generate(payload: SkyEyeReportRequest, user=Depends(_require_auth)):
    runs_available = list_runs()
    selected_file = _skyeye_file_from_payload(payload)
    requested_device = payload.device_id.strip()
    run = get_run(payload.run_id) if payload.run_id else None
    if selected_file is not None:
        safe_id = re.sub(r"[^a-zA-Z0-9_-]+", "_", selected_file.stem)[:80] or "archivo"
        if requested_device:
            safe_device = re.sub(r"[^a-zA-Z0-9_-]+", "_", requested_device)[:50]
            safe_id = f"{safe_id}_{safe_device}"
        run_dir = OUTPUTS_DIR / "informes_skyeye_archivos" / safe_id
        run_dir.mkdir(parents=True, exist_ok=True)
        trajectory_csv = _skyeye_find_trajectory_for_file(selected_file)
        run = {
            "id": safe_id,
            "created_at": dt.datetime.now(dt.timezone(dt.timedelta(hours=-3))).strftime("%Y-%m-%d %H:%M:%S UTC-3"),
            "status": "file_report",
            "input_detection_csv": str(selected_file),
            "input_trajectory_csv": str(trajectory_csv) if trajectory_csv else "",
            "output_dir": str(run_dir),
            "html_report": "",
            "tracks_kml": "",
            "last_seen_kml": "",
            "geo_txt_report": "",
            "m3t_kml": "",
            "device_trajectory_kml": "",
            "drones_commands_file": "",
            "m3t_summary": {},
        }
    if run is None:
        run = runs_available[0] if runs_available else None
    if run is None:
        raise HTTPException(status_code=404, detail="No hay corridas SkyEye para generar informe")
    kml_summary: Dict[str, object] = {}
    if payload.generate_kml:
        detection_path = Path(str(run.get("input_detection_csv") or ""))
        trajectory_raw = str(run.get("input_trajectory_csv") or "").strip()
        trajectory_path = Path(trajectory_raw) if trajectory_raw else _skyeye_find_trajectory_for_file(detection_path)
        safe_device = re.sub(r"[^a-zA-Z0-9_-]+", "_", requested_device or "auto")[:50] or "auto"
        out_dir = Path(str(run.get("output_dir") or OUTPUTS_DIR / "informes_skyeye_archivos")).resolve()
        out_dir.mkdir(parents=True, exist_ok=True)
        kml_path = out_dir / f"trayectoria_device_{safe_device}_{dt.datetime.now().strftime('%Y%m%d_%H%M%S')}.kml"
        try:
            kml_summary = build_device_trajectory_kml(
                detection_csv=detection_path,
                trajectory_csv=trajectory_path if trajectory_path and trajectory_path.exists() else None,
                output_file=kml_path,
                device_id=requested_device or None,
            )
            run["device_trajectory_kml"] = str(kml_path)
            if not requested_device:
                requested_device = str(kml_summary.get("device_id") or "").strip()
        except Exception as exc:
            if requested_device:
                raise HTTPException(status_code=400, detail=f"No se pudo generar KML de trayectoria: {exc}")
            kml_summary = {"error": str(exc)}
    out_path = _generate_skyeye_report_html(run, payload.observaciones, user, device_id=requested_device)
    return {
        "ok": True,
        "run_id": run.get("id"),
        "report_name": out_path.name,
        "report_url": _skyeye_output_url(out_path),
        "device_id": requested_device,
        "kml_url": _skyeye_output_url(run.get("device_trajectory_kml")),
        "kml_summary": kml_summary,
    }


@app.get("/api/skyeye/reports")
def skyeye_reports(limit: int = 100, user=Depends(_require_auth)):
    OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)
    items = []
    for p in sorted(OUTPUTS_DIR.rglob("informe_skyeye_run_*.html"), key=lambda x: x.stat().st_mtime, reverse=True)[:limit]:
        items.append({
            "name": p.name,
            "relative": p.resolve().relative_to(OUTPUTS_DIR.resolve()).as_posix(),
            "url": _skyeye_output_url(p),
            "modified_at": dt.datetime.fromtimestamp(p.stat().st_mtime).isoformat(timespec="seconds"),
            "size": p.stat().st_size,
        })
    return {"items": items}


@app.get("/api/skyeye/summary")
def skyeye_summary(run_id: Optional[int] = None, user=Depends(_require_auth)):
    runs_available = list_runs()
    run = get_run(run_id) if run_id else (runs_available[0] if runs_available else None)
    if run is None:
        raise HTTPException(status_code=404, detail="No hay corridas SkyEye para leer")

    detection_df = _skyeye_read_csv(run.get("input_detection_csv"))
    records = detection_df.to_dict(orient="records")
    start_time, end_time = _skyeye_time_range(records, "Detect Time")
    related = []
    for label, key in [
        ("CSV detecciones", "input_detection_csv"),
        ("CSV trayectorias", "input_trajectory_csv"),
        ("Reporte HTML procesado", "html_report"),
        ("Trayectorias KML", "tracks_kml"),
        ("Ultimas posiciones KML", "last_seen_kml"),
        ("Reporte georreferenciacion TXT", "geo_txt_report"),
        ("KML M3T", "m3t_kml"),
        ("Drones y comandos CSV", "drones_commands_file"),
    ]:
        value = run.get(key)
        exists = bool(value and Path(str(value)).exists())
        related.append({
            "label": label,
            "key": key,
            "exists": exists,
            "url": _skyeye_output_url(value) if exists else "",
            "name": Path(str(value)).name if value else "",
        })

    return {
        "run": {
            "id": run.get("id"),
            "created_at": run.get("created_at"),
            "status": run.get("status"),
            "message": run.get("message"),
        },
        "summary": {
            "total_detections": len(records),
            "models": [{"value": k, "count": v} for k, v in _skyeye_counts(records, "Model", limit=12)],
            "device_ids": [{"value": k, "count": v} for k, v in _skyeye_counts(records, "Device ID", limit=12)],
            "sensors": [{"value": k, "count": v} for k, v in _skyeye_counts(records, "Sensor", limit=12)],
            "locations": [{"value": k, "count": v} for k, v in _skyeye_counts(records, "Detection Engine", limit=8)],
            "time_from": start_time,
            "time_to": end_time,
            "points": _skyeye_detection_points(records, limit=8),
            "trajectories": _skyeye_trajectory_summaries(run.get("drones_commands_file"), records, limit=8),
            "m3t_summary": run.get("m3t_summary") or {},
        },
        "evidence": {
            "endpoint": "/api/skyeye/summary",
            "source": "runs + CSV SkyEye procesado",
            "run_id": run.get("id"),
            "detection_csv": Path(str(run.get("input_detection_csv") or "")).name,
            "related_files": related,
        },
    }


# ── Heatmap ──────────────────────────────────────────────────────────────────

@app.get("/api/heatmap")
def heatmap(
    date_from: str = "",
    date_to: str = "",
    sensor: str = "",
    model: str = "",
    location: str = "",
    source: str = "",
    user=Depends(_require_auth),
):
    rows = query_heatmap(date_from=date_from, date_to=date_to, sensor=sensor, model=model, location=location, source=source)
    filters = query_heatmap_filters()

    points = [[r["lat"], r["lon"], 1.0] for r in rows]

    # stats from DB rows
    from collections import Counter
    by_model = dict(Counter(r["model"] for r in rows if r.get("model")).most_common(20))
    by_sensor = dict(Counter(r["sensor"] for r in rows if r.get("sensor")).most_common(20))
    by_location = dict(Counter(r["location"] for r in rows if r.get("location")).most_common(20))
    by_source = dict(Counter(r["source"] for r in rows if r.get("source")).most_common(20))
    by_date: dict = {}
    for r in rows:
        d = r.get("detect_date", "")
        if d:
            by_date[d] = by_date.get(d, 0) + 1
    by_date = dict(sorted(by_date.items()))

    return {
        "points": points,
        "total": len(rows),
        "stats": {
            "by_model": by_model,
            "by_sensor": by_sensor,
            "by_location": by_location,
            "by_source": by_source,
            "by_date": by_date,
        },
        "filters": filters,
    }


@app.get("/api/heatmap/combined")
def heatmap_combined(
    date_from: str = "",
    date_to: str = "",
    sensor: str = "",
    model: str = "",
    location: str = "",
    show_skyeye: bool = True,
    show_guardian: bool = True,
    show_backpack: bool = True,
    cross_whitelist: bool = True,
    show_whitelist: bool = False,
    user=Depends(_require_auth),
):
    points: List[Dict[str, object]] = []

    whitelist = _whitelist_identity_set() if cross_whitelist else set()

    def septier_whitelist_payload(row: Dict[str, object]) -> Dict[str, object]:
        if not cross_whitelist:
            return {
                "is_whitelisted": False,
                "whitelist_status": "SIN CRUCE LB",
                "whitelist_trace": "",
                "whitelist_matches": [],
            }
        imsi = row.get("imsi_mac", "")
        imei = row.get("imei", "")
        matches = _whitelist_match_details(imsi, imei)
        is_whitelisted = bool(matches) or _is_whitelisted_identity(imsi, imei, whitelist)
        return {
            "is_whitelisted": is_whitelisted,
            "whitelist_status": "AUTORIZADO EN LISTA BLANCA" if is_whitelisted else "NO COINCIDENTE LB",
            "whitelist_trace": _whitelist_match_trace(matches) if matches else "",
            "whitelist_matches": matches,
        }

    if show_skyeye:
        skyeye_rows = query_heatmap(
            date_from=date_from,
            date_to=date_to,
            sensor=sensor,
            model=model,
            location=location,
            source="",
        )
        for r in skyeye_rows:
            src = str(r.get("source", "")).strip().lower()
            if src in {"guardian", "backpack"}:
                continue
            points.append(
                {
                    "lat": r["lat"],
                    "lon": r["lon"],
                    "color": "#ff8c00",
                    "source": "skyeye",
                    "model": r.get("model", ""),
                    "label": r.get("tag", ""),
                        "date": r.get("detect_date", ""),
                    "location": r.get("location", ""),
                        "imsi_mac": "",
                        "imei": "",
                }
            )

    if show_guardian:
        guardian_rows = query_septier_heatmap(
            date_from=date_from,
            date_to=date_to,
            source="guardian",
            location=location,
            model=model,
        )
        for r in guardian_rows:
            wl = septier_whitelist_payload(r)
            is_wl = bool(wl.get("is_whitelisted"))
            if cross_whitelist and is_wl and not show_whitelist:
                continue
            points.append(
                {
                    "lat": r["lat"],
                    "lon": r["lon"],
                    "color": "#56d364" if is_wl else "#ff0000",
                    "source": "guardian",
                    "model": r.get("model", ""),
                    "label": f"{r.get('operation', '')} | Centroide Multipolygon" + (" [LISTA BLANCA]" if is_wl else ""),
                    "date": r.get("last_update", ""),
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
                    "imsi_mac": r.get("imsi_mac", ""),
                    "imei": r.get("imei", ""),
                    "orig_lac": r.get("orig_lac", ""),
                    "cell_id": r.get("cell_id", ""),
                    "geometry_source": r.get("geometry_source", ""),
                    "multipolygon": r.get("multipolygon", ""),
                    "operator_lat": r.get("operator_lat", ""),
                    "operator_lon": r.get("operator_lon", ""),
                    **wl,
                }
            )

    if show_backpack:
        backpack_rows = query_septier_heatmap(
            date_from=date_from,
            date_to=date_to,
            source="backpack",
            location=location,
            model=model,
        )
        for r in backpack_rows:
            wl = septier_whitelist_payload(r)
            is_wl = bool(wl.get("is_whitelisted"))
            if cross_whitelist and is_wl and not show_whitelist:
                continue
            points.append(
                {
                    "lat": r["lat"],
                    "lon": r["lon"],
                    "color": "#56d364" if is_wl else "#ff0000",
                    "source": "backpack",
                    "model": r.get("model", ""),
                    "label": f"{r.get('operation', '')} | Centroide Multipolygon" + (" [LISTA BLANCA]" if is_wl else ""),
                    "date": r.get("last_update", ""),
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
                    "imsi_mac": r.get("imsi_mac", ""),
                    "imei": r.get("imei", ""),
                    "orig_lac": r.get("orig_lac", ""),
                    "cell_id": r.get("cell_id", ""),
                    "geometry_source": r.get("geometry_source", ""),
                    "multipolygon": r.get("multipolygon", ""),
                    "operator_lat": r.get("operator_lat", ""),
                    "operator_lon": r.get("operator_lon", ""),
                    **wl,
                }
            )

    by_source: Dict[str, int] = {}
    for p in points:
        src = str(p.get("source", "")).strip().lower() or "desconocido"
        by_source[src] = by_source.get(src, 0) + 1

    return {"points": points, "total": len(points), "by_source": by_source}


