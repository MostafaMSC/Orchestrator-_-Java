#!/usr/bin/env bash
#
# TwoKeyOk MiddleWare Orchestrator — Linux installer
#
#   sudo ./deploy/install.sh [--jar path/to/twokeyok-orchestrator.jar]
#
# Idempotent: re-running upgrades the jar and the unit file but never overwrites
# an existing configuration. Tested on RHEL/Rocky 8-9, Ubuntu 20.04-24.04 and
# Debian 11-12 with systemd.
#
set -euo pipefail

APP_NAME="twokeyok-orchestrator"
APP_USER="twokeyok"
APP_GROUP="twokeyok"
INSTALL_DIR="/opt/twokeyok/orchestrator"
CONFIG_DIR="/etc/twokeyok/orchestrator"
LOG_DIR="/var/log/${APP_NAME}"
UNIT_FILE="/etc/systemd/system/${APP_NAME}.service"
MIN_JAVA_MAJOR=17

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
JAR_PATH="${PROJECT_DIR}/target/${APP_NAME}.jar"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --jar) JAR_PATH="$2"; shift 2 ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done

log()  { printf '\033[0;32m[ok]\033[0m %s\n' "$*"; }
warn() { printf '\033[0;33m[..]\033[0m %s\n' "$*"; }
die()  { printf '\033[0;31m[!!]\033[0m %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------- checks ----
[[ $EUID -eq 0 ]] || die "Run this installer as root (sudo $0)."
command -v systemctl >/dev/null 2>&1 || die "systemd is required."
[[ -f "${JAR_PATH}" ]] || die "Application jar not found at ${JAR_PATH}. Build it first with 'mvn -B clean package', or pass --jar."

command -v java >/dev/null 2>&1 || die "Java ${MIN_JAVA_MAJOR}+ is required but 'java' is not on PATH."
JAVA_MAJOR="$(java -version 2>&1 | head -n1 | sed -E 's/.*"([0-9]+)(\.|").*/\1/')"
[[ "${JAVA_MAJOR}" =~ ^[0-9]+$ ]] || die "Cannot determine the Java version."
(( JAVA_MAJOR >= MIN_JAVA_MAJOR )) || die "Java ${MIN_JAVA_MAJOR}+ is required, found ${JAVA_MAJOR}."
log "Java ${JAVA_MAJOR} detected"

# ----------------------------------------------------------- service user ---
if ! getent group "${APP_GROUP}" >/dev/null; then
  groupadd --system "${APP_GROUP}"
  log "Created group ${APP_GROUP}"
fi
if ! getent passwd "${APP_USER}" >/dev/null; then
  useradd --system --gid "${APP_GROUP}" --home-dir "${INSTALL_DIR}" \
          --shell /usr/sbin/nologin --comment "TwoKeyOk Orchestrator" "${APP_USER}"
  log "Created service account ${APP_USER}"
fi

# ---------------------------------------------------------------- layout ----
install -d -o root        -g "${APP_GROUP}" -m 0755 "${INSTALL_DIR}"
install -d -o root        -g "${APP_GROUP}" -m 0750 "${CONFIG_DIR}"
install -d -o root        -g "${APP_GROUP}" -m 0750 "${CONFIG_DIR}/appearances"
install -d -o root        -g "${APP_GROUP}" -m 0750 "${CONFIG_DIR}/tls"
install -d -o "${APP_USER}" -g "${APP_GROUP}" -m 0750 "${LOG_DIR}"
log "Directory layout ready"

# ------------------------------------------------------------------- jar ----
if systemctl is-active --quiet "${APP_NAME}"; then
  warn "Stopping the running service for the upgrade"
  systemctl stop "${APP_NAME}"
  RESTART_AFTER=1
fi
install -o root -g "${APP_GROUP}" -m 0640 "${JAR_PATH}" "${INSTALL_DIR}/${APP_NAME}.jar"
log "Installed ${INSTALL_DIR}/${APP_NAME}.jar"

# ---------------------------------------------------------------- config ----
# Never clobber a live configuration: new files are installed, existing ones are
# left alone and the packaged version is dropped next to them as .new.
install_config() {
  local src="$1" dst="$2" mode="$3"
  if [[ -f "${dst}" ]]; then
    if ! cmp -s "${src}" "${dst}"; then
      install -o root -g "${APP_GROUP}" -m "${mode}" "${src}" "${dst}.new"
      warn "Kept existing ${dst} (packaged version saved as ${dst}.new)"
    fi
  else
    install -o root -g "${APP_GROUP}" -m "${mode}" "${src}" "${dst}"
    log "Installed ${dst}"
  fi
}

install_config "${PROJECT_DIR}/config/orchestrator.yml" "${CONFIG_DIR}/orchestrator.yml" 0640
# Shipped as .example so a real env file is never committed to source control.
install_config "${PROJECT_DIR}/deploy/env/orchestrator.env.example" "${CONFIG_DIR}/orchestrator.env" 0640
for template in "${PROJECT_DIR}"/config/appearances/*.json; do
  [[ -e "${template}" ]] || continue
  install_config "${template}" "${CONFIG_DIR}/appearances/$(basename "${template}")" 0640
done

# ------------------------------------------------------------- logrotate ----
if [[ -d /etc/logrotate.d ]]; then
  install -o root -g root -m 0644 "${PROJECT_DIR}/deploy/logrotate/${APP_NAME}" "/etc/logrotate.d/${APP_NAME}"
  log "Installed /etc/logrotate.d/${APP_NAME}"
fi

# ---------------------------------------------------------------- systemd ---
install -o root -g root -m 0644 "${PROJECT_DIR}/deploy/systemd/${APP_NAME}.service" "${UNIT_FILE}"
systemctl daemon-reload
systemctl enable "${APP_NAME}" >/dev/null
log "Installed and enabled ${UNIT_FILE}"

# ------------------------------------------------------------------ SELinux --
if command -v getenforce >/dev/null 2>&1 && [[ "$(getenforce)" == "Enforcing" ]]; then
  warn "SELinux is enforcing. If the service cannot read ${CONFIG_DIR}, run:"
  warn "  semanage fcontext -a -t etc_t '${CONFIG_DIR}(/.*)?' && restorecon -R ${CONFIG_DIR}"
fi

# --------------------------------------------------------------- finish -----
cat <<EOF

  Installation complete.

  1. Edit the configuration:
       ${CONFIG_DIR}/orchestrator.yml      (ADSS endpoints, clients, signers)
       ${CONFIG_DIR}/orchestrator.env      (secrets, TLS keystore, port)

  2. Hash each client secret and paste it into orchestrator.env:
       java -jar ${INSTALL_DIR}/${APP_NAME}.jar --hash-secret '<secret>'

  3. Put the TLS material in ${CONFIG_DIR}/tls and chown it to ${APP_USER}:
       chown ${APP_USER}:${APP_GROUP} ${CONFIG_DIR}/tls/* && chmod 0640 ${CONFIG_DIR}/tls/*

  4. Start the service:
       systemctl start ${APP_NAME}
       systemctl status ${APP_NAME}
       journalctl -u ${APP_NAME} -f

  5. Check it answers:
       curl -sk https://localhost:\${ORCHESTRATOR_PORT:-443}/orchestrator/actuator/health

EOF

if [[ "${RESTART_AFTER:-0}" == "1" ]]; then
  systemctl start "${APP_NAME}"
  log "Service restarted after upgrade"
fi
