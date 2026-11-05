#!/bin/sh
set -eu

umask 077

ensure_writable_dir() {
  dir="$1"
  if [ -z "$dir" ]; then
    return
  fi
  mkdir -p "$dir"
  chown -R app:app "$dir"
}

work_dir="${WORK_DIR:-./data}"
mkdir -p "$work_dir"
work_dir_resolved="$(cd "$work_dir" && pwd -P)"
if [ "$work_dir_resolved" = "/" ]; then
  echo "WORK_DIR must not resolve to /" >&2
  exit 1
fi
work_dir="$work_dir_resolved"
ensure_writable_dir "$work_dir"

case "${BACKUP_ENABLED:-true}" in
  false|FALSE|False|0)
    ;;
  *)
    ensure_writable_dir "$work_dir/backups"
    ;;
esac

case "${LOG_FILE_ENABLED:-true}" in
  false|FALSE|False|0)
    ;;
  *)
    ensure_writable_dir "$work_dir/logs"
    ;;
esac

exec su-exec app "$@"
