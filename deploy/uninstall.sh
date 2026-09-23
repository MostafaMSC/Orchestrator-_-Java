#!/usr/bin/env bash
#
# Removes the TwoKeyOk MiddleWare Orchestrator.
#
#   sudo ./deploy/uninstall.sh              # keeps configuration, logs and the service account
#   sudo ./deploy/uninstall.sh --purge      # also deletes /etc/twokeyok/orchestrator and the logs
#
set -euo pipefail

APP_NAME="twokeyok-orchestrator"
APP_USER="twokeyok"
INSTALL_DIR="/opt/twokeyok/orchestrator"
CONFIG_DIR="/etc/twokeyok/orchestrator"
LOG_DIR="/var/log/${APP_NAME}"

PURGE=0
[[ "${1:-}" == "--purge" ]] && PURGE=1

log() { printf '\033[0;32m[ok]\033[0m %s\n' "$*"; }
die() { printf '\033[0;31m[!!]\033[0m %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "Run this as root (sudo $0)."

if systemctl list-unit-files | grep -q "^${APP_NAME}.service"; then
  systemctl stop "${APP_NAME}" 2>/dev/null || true
  systemctl disable "${APP_NAME}" 2>/dev/null || true
  rm -f "/etc/systemd/system/${APP_NAME}.service"
  systemctl daemon-reload
  log "Service removed"
fi

rm -rf "${INSTALL_DIR}"
rm -f "/etc/logrotate.d/${APP_NAME}"
log "Application files removed"

if [[ "${PURGE}" -eq 1 ]]; then
  # The audit trail is signing evidence, so say plainly what is being deleted.
  printf 'This deletes %s (including TLS material and the signing audit trail in %s).\n' "${CONFIG_DIR}" "${LOG_DIR}"
  read -r -p 'Type PURGE to confirm: ' answer
  [[ "${answer}" == "PURGE" ]] || die "Aborted; nothing else was removed."
  rm -rf "${CONFIG_DIR}" "${LOG_DIR}"
  userdel "${APP_USER}" 2>/dev/null || true
  log "Configuration, logs and the service account removed"
else
  log "Kept ${CONFIG_DIR} and ${LOG_DIR} (use --purge to remove them)"
fi
