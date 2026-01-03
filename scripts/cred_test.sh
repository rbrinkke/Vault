#!/usr/bin/env bash
set -euo pipefail

NAME="${1:-db_password}"
CRED_DIR="${SYSTEMD_CREDENTIALS_DIRECTORY:-}"

if [ -z "$CRED_DIR" ]; then
  echo "SYSTEMD_CREDENTIALS_DIRECTORY not set." >&2
  echo "Run via systemd with LoadCredentialEncrypted." >&2
  exit 1
fi

cred_file="$CRED_DIR/$NAME"
if [ ! -f "$cred_file" ]; then
  echo "credential not found: $cred_file" >&2
  if [ -d "$CRED_DIR" ]; then
    ls -l "$CRED_DIR" >&2 || true
  fi
  exit 1
fi

bytes="$(stat -c %s "$cred_file")"
echo "loaded credential $NAME ($bytes bytes)"
