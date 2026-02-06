#!/usr/bin/env bash
set -euo pipefail

if [ $# -lt 1 ]; then
  echo "usage: create_cred.sh <name> [--with-key=host|tpm2|host+tpm2]" >&2
  exit 1
fi

NAME="$1"
shift

WITH_KEY="host"
if [ $# -gt 0 ]; then
  case "$1" in
    --with-key=*)
      WITH_KEY="${1#--with-key=}"
      ;;
    *)
      echo "unknown arg: $1" >&2
      exit 1
      ;;
  esac
fi

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CRED_DIR="$BASE_DIR/credstore"
mkdir -p "$CRED_DIR"

umask 077
# Avoid writing secrets to /tmp; keep them under the (0700) credstore directory.
tmp_file="$(mktemp -p "$CRED_DIR" ".secret-$NAME-XXXXXX")"
cleanup() { rm -f "$tmp_file"; }
trap cleanup EXIT

read -r -s -p "Secret for $NAME: " secret
printf '\n'

printf '%s' "$secret" > "$tmp_file"

systemd-creds encrypt --with-key="$WITH_KEY" --name="$NAME" \
  "$tmp_file" "$CRED_DIR/$NAME.cred"

echo "Wrote $CRED_DIR/$NAME.cred"
