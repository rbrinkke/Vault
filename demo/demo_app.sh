#!/usr/bin/env bash
set -euo pipefail

require_file() {
  local label="$1"
  local file_var="$2"
  local path="${!file_var:-}"

  if [ -z "$path" ]; then
    echo "$label: env $file_var is not set" >&2
    exit 1
  fi
  if [ ! -f "$path" ]; then
    echo "$label: file not found: $path" >&2
    exit 1
  fi

  local bytes
  bytes="$(stat -c %s "$path")"
  echo "$label loaded ($bytes bytes)"
}

require_file "db_password" DB_PASSWORD_FILE
require_file "api_token" API_TOKEN_FILE
