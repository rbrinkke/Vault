#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'USAGE'
usage: service-smoke.sh --unit NAME --binary PATH [options]

Options:
  --unit NAME           systemd transient unit name
  --binary PATH         binary to execute under systemd-run
  --arg VALUE           argument passed to the binary (repeatable)
  --secret KEY=VALUE    create an encrypted credential and inject it (repeatable)
  --env KEY=VALUE       extra plain environment variable (repeatable)
  --with-key TYPE       host|tpm2|host+tpm2 (default: host)
  --app-env VALUE       APP_ENV value (default: production)
  --no-validate-only    do not inject VALIDATE_CONFIG_ONLY=1
USAGE
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing command: $1" >&2
    exit 10
  }
}

UNIT=""
BINARY=""
WITH_KEY="host"
APP_ENV="production"
NO_VALIDATE_ONLY=0
ARGS=()
SECRETS=()
ENVS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --unit)
      UNIT="${2:-}"
      shift 2
      ;;
    --binary)
      BINARY="${2:-}"
      shift 2
      ;;
    --arg)
      ARGS+=("${2:-}")
      shift 2
      ;;
    --secret)
      SECRETS+=("${2:-}")
      shift 2
      ;;
    --env)
      ENVS+=("${2:-}")
      shift 2
      ;;
    --with-key)
      WITH_KEY="${2:-}"
      shift 2
      ;;
    --app-env)
      APP_ENV="${2:-}"
      shift 2
      ;;
    --no-validate-only)
      NO_VALIDATE_ONLY=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown arg: $1" >&2
      usage
      exit 1
      ;;
  esac
done

[[ -n "$UNIT" ]] || { echo "--unit is required" >&2; exit 1; }
[[ -n "$BINARY" ]] || { echo "--binary is required" >&2; exit 1; }
[[ -x "$BINARY" ]] || { echo "binary not executable: $BINARY" >&2; exit 1; }

require_cmd systemd-run
require_cmd systemctl
require_cmd journalctl
require_cmd systemd-creds

tmp_root="$(mktemp -d)"
cred_dir="$tmp_root/credstore"
mkdir -p "$cred_dir"
chmod 700 "$cred_dir"

cleanup() {
  systemctl stop "$UNIT" >/dev/null 2>&1 || true
  systemctl reset-failed "$UNIT" >/dev/null 2>&1 || true
  rm -rf "$tmp_root"
}
trap cleanup EXIT

props=(
  "-p" "Type=exec"
  "-p" "Environment=APP_ENV=$APP_ENV"
)

if [[ "$NO_VALIDATE_ONLY" -eq 0 ]]; then
  props+=("-p" "Environment=VALIDATE_CONFIG_ONLY=1")
fi

for env_kv in "${ENVS[@]}"; do
  props+=("-p" "Environment=$env_kv")
done

secret_values=()
for secret_kv in "${SECRETS[@]}"; do
  key="${secret_kv%%=*}"
  value="${secret_kv#*=}"
  [[ -n "$key" ]] || { echo "invalid --secret: $secret_kv" >&2; exit 1; }

  plain_file="$cred_dir/.${key}.plain"
  cred_file="$cred_dir/${key}.cred"
  printf '%s' "$value" > "$plain_file"
  chmod 600 "$plain_file"
  systemd-creds encrypt --with-key="$WITH_KEY" --name="$key" "$plain_file" "$cred_file" >/dev/null
  rm -f "$plain_file"

  props+=("-p" "LoadCredentialEncrypted=${key}:${cred_file}")
  secret_values+=("$value")
done

cmd=(systemd-run --wait --collect --unit "$UNIT")
cmd+=("${props[@]}")
cmd+=("$BINARY")
cmd+=("${ARGS[@]}")

"${cmd[@]}"

journal="$(journalctl -u "$UNIT" --no-pager 2>&1 || true)"
for value in "${secret_values[@]}"; do
  if [[ "$journal" == *"$value"* ]]; then
    echo "secret leaked into journald for unit $UNIT" >&2
    exit 40
  fi
done

echo "service smoke passed: $UNIT"
