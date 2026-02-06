#!/bin/bash
# smoke-check.sh - production-safe smoke checks for goamet-vault.
#
# Default behavior is read-only checks against a real vault root.
# Optional leak-check uses a transient systemd unit with an isolated /tmp vault root.
#
# Usage:
#   sudo /opt/services/vault/scripts/smoke-check.sh --root /var/lib/goamet-vault
#   sudo /opt/services/vault/scripts/smoke-check.sh --root /var/lib/goamet-vault --with-leak

set -euo pipefail

VAULT_BIN="/usr/local/bin/goamet-vault"
ROOT=""
WITH_LEAK="0"

die() { echo "ERROR: $*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --root)
      ROOT="${2:-}"; shift 2;;
    --with-leak)
      WITH_LEAK="1"; shift 1;;
    -h|--help)
      sed -n '1,80p' "$0"; exit 0;;
    *)
      die "unknown arg: $1";;
  esac
done

[[ -n "${ROOT}" ]] || die "--root is required"
[[ -x "${VAULT_BIN}" ]] || die "missing vault binary: ${VAULT_BIN}"

echo "== goamet-vault smoke check =="
echo "vault_bin: ${VAULT_BIN}"
echo "vault_root: ${ROOT}"
echo

echo "-- doctor (read-only) --"
sudo -n "${VAULT_BIN}" --root "${ROOT}" doctor --path
echo

echo "-- health (read-only) --"
sudo -n "${VAULT_BIN}" --root "${ROOT}" health
echo

echo "-- audit verify (read-only) --"
sudo -n "${VAULT_BIN}" --root "${ROOT}" audit verify
echo

if [[ "${WITH_LEAK}" == "1" ]]; then
  echo "-- transient leak check (isolated /tmp root; does not touch prod data) --"
  sudo -n "${VAULT_BIN}" test run --runtime-sec 4
  echo
fi

echo "OK"

