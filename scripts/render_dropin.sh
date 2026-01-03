#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'USAGE'
usage: render_dropin.sh <service-name> [options]

Notes:
  - <service-name> may be given with or without the .service suffix.
  - Map file defaults to services/<name>.conf (suffix stripped).

Options:
  --map-file PATH   Map file to read (default: services/<service>.conf)
  --cred-dir PATH   Base directory for .cred files (default: credstore)
  --out-dir PATH    Output directory for drop-in (default: units/<service>.d)
  --no-env          Do not emit Environment= lines
  --apply           Copy drop-in to /etc/systemd/system/<service>.d and reload
USAGE
}

if [ $# -lt 1 ]; then
  usage
  exit 1
fi

SERVICE="$1"
shift

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UNIT_NAME="$SERVICE"
MAP_NAME="$SERVICE"
if [[ "$SERVICE" != *.service ]]; then
  UNIT_NAME="$SERVICE.service"
else
  MAP_NAME="${SERVICE%.service}"
fi

MAP_FILE="$BASE_DIR/services/$MAP_NAME.conf"
CRED_DIR="$BASE_DIR/credstore"
OUT_DIR="$BASE_DIR/units/$UNIT_NAME.d"
NO_ENV=0
APPLY=0

while [ $# -gt 0 ]; do
  case "$1" in
    --map-file)
      MAP_FILE="$2"
      shift 2
      ;;
    --cred-dir)
      CRED_DIR="$2"
      shift 2
      ;;
    --out-dir)
      OUT_DIR="$2"
      shift 2
      ;;
    --no-env)
      NO_ENV=1
      shift
      ;;
    --apply)
      APPLY=1
      shift
      ;;
    *)
      usage
      exit 1
      ;;
  esac
done

if [ ! -f "$MAP_FILE" ]; then
  echo "map file not found: $MAP_FILE" >&2
  exit 1
fi

mkdir -p "$OUT_DIR"
OUT_FILE="$OUT_DIR/credentials.conf"

{
  echo "[Service]"
  while IFS= read -r line || [ -n "$line" ]; do
    line="${line%%#*}"
    if [ -z "${line//[[:space:]]/}" ]; then
      continue
    fi
    set -- $line
    raw="$1"
    env_var="${2:-}"

    if [[ "$raw" == *:* ]]; then
      name="${raw%%:*}"
      cred_path="${raw#*:}"
    else
      name="$raw"
      cred_path="$CRED_DIR/$name.cred"
    fi

    echo "LoadCredentialEncrypted=$name:$cred_path"
    if [ $NO_ENV -eq 0 ] && [ -n "$env_var" ]; then
      echo "Environment=$env_var=/run/credentials/%N/$name"
    fi
  done < "$MAP_FILE"
} > "$OUT_FILE"

echo "Wrote $OUT_FILE"

if [ $APPLY -eq 1 ]; then
  target_dir="/etc/systemd/system/$UNIT_NAME.d"
  target_file="$target_dir/credentials.conf"
  mkdir -p "$target_dir"
  cp "$OUT_FILE" "$target_file"
  if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
  fi
  echo "Installed $target_file"
fi
