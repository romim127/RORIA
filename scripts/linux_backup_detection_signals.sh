#!/usr/bin/env bash
set -euo pipefail

DATA_DIR="${SKYEYE_DATA_DIR:-/var/lib/detection-signals}"
BACKUP_DIR="${BACKUP_DIR:-/var/backups/detection-signals}"
SERVICE_NAME="${SERVICE_NAME:-detection-signals}"
RETENTION_DAYS="${RETENTION_DAYS:-30}"
STOP_SERVICE=0
ALLOW_LIVE=0

usage() {
  cat <<'USAGE'
Detection of Signals - Linux data backup

Usage:
  sudo bash scripts/linux_backup_detection_signals.sh --stop-service

Options:
  --data-dir PATH       Data directory to back up. Default: $SKYEYE_DATA_DIR or /var/lib/detection-signals
  --backup-dir PATH     Destination directory. Default: /var/backups/detection-signals
  --service NAME        systemd service name. Default: detection-signals
  --retention-days N    Delete local backups older than N days. Default: 30
  --stop-service        Stop the app during backup and start it again afterwards.
  --live                Allow backup while service is running. Not recommended for SQLite.
  -h, --help            Show this help.

Notes:
  - Backups stay local by default. Do not write sensitive evidence to shared folders.
  - The script creates a .tar.gz archive and a .sha256 audit file.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --data-dir)
      DATA_DIR="${2:-}"
      shift 2
      ;;
    --backup-dir)
      BACKUP_DIR="${2:-}"
      shift 2
      ;;
    --service)
      SERVICE_NAME="${2:-}"
      shift 2
      ;;
    --retention-days)
      RETENTION_DAYS="${2:-}"
      shift 2
      ;;
    --stop-service)
      STOP_SERVICE=1
      shift
      ;;
    --live)
      ALLOW_LIVE=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      exit 2
      ;;
  esac
done

if [[ ! -d "$DATA_DIR" ]]; then
  echo "Data directory does not exist: $DATA_DIR" >&2
  exit 1
fi

service_active=0
service_was_active=0
if command -v systemctl >/dev/null 2>&1; then
  if systemctl is-active --quiet "$SERVICE_NAME"; then
    service_active=1
    service_was_active=1
  fi
fi

if [[ "$service_active" -eq 1 && "$STOP_SERVICE" -ne 1 && "$ALLOW_LIVE" -ne 1 ]]; then
  echo "Service '$SERVICE_NAME' is running." >&2
  echo "For a consistent SQLite backup, run again with --stop-service." >&2
  echo "Use --live only if you understand the risk of an inconsistent database snapshot." >&2
  exit 1
fi

mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"

timestamp="$(date +%Y%m%d_%H%M%S)"
hostname="$(hostname 2>/dev/null || echo unknown-host)"
archive_name="detection_signals_data_${hostname}_${timestamp}.tar.gz"
archive_path="$BACKUP_DIR/$archive_name"
manifest_path="$BACKUP_DIR/detection_signals_manifest_${hostname}_${timestamp}.txt"

cleanup() {
  if [[ "$STOP_SERVICE" -eq 1 && "$service_was_active" -eq 1 ]]; then
    systemctl start "$SERVICE_NAME" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

if [[ "$STOP_SERVICE" -eq 1 && "$service_was_active" -eq 1 ]]; then
  echo "Stopping service: $SERVICE_NAME"
  systemctl stop "$SERVICE_NAME"
fi

cat > "$manifest_path" <<EOF
Detection of Signals backup manifest
created_at=$(date --iso-8601=seconds)
hostname=$hostname
data_dir=$DATA_DIR
backup_dir=$BACKUP_DIR
service_name=$SERVICE_NAME
service_was_active=$service_was_active
live_backup=$ALLOW_LIVE
retention_days=$RETENTION_DAYS
EOF

echo "Creating backup: $archive_path"
tar \
  --exclude='*/__pycache__' \
  --exclude='*/.DS_Store' \
  -czf "$archive_path" \
  -C "$(dirname "$DATA_DIR")" \
  "$(basename "$DATA_DIR")"

sha256sum "$archive_path" > "$archive_path.sha256"
chmod 600 "$archive_path" "$archive_path.sha256" "$manifest_path"

if [[ "$STOP_SERVICE" -eq 1 && "$service_was_active" -eq 1 ]]; then
  echo "Starting service: $SERVICE_NAME"
  systemctl start "$SERVICE_NAME"
fi

if [[ "$RETENTION_DAYS" =~ ^[0-9]+$ && "$RETENTION_DAYS" -gt 0 ]]; then
  find "$BACKUP_DIR" -type f -name 'detection_signals_data_*.tar.gz' -mtime +"$RETENTION_DAYS" -print -delete
  find "$BACKUP_DIR" -type f -name 'detection_signals_data_*.tar.gz.sha256' -mtime +"$RETENTION_DAYS" -print -delete
  find "$BACKUP_DIR" -type f -name 'detection_signals_manifest_*.txt' -mtime +"$RETENTION_DAYS" -print -delete
fi

echo "Backup completed."
echo "Archive: $archive_path"
echo "SHA-256:"
cat "$archive_path.sha256"
