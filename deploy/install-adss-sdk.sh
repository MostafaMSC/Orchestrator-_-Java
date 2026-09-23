#!/usr/bin/env bash
#
# The ADSS Client SDK is licensed software and is not published to Maven
# Central, so it has to be installed into the local Maven repository once
# before the orchestrator can be built.
#
#   ./deploy/install-adss-sdk.sh [path]
#
# "path" may be any of:
#   * a JAVAsdk directory            (…/API/lib/adss_client_api.jar)
#   * a deployed ADSS Orchestrator   (…/lib/adss_client_api.jar)
#   * a directory containing the jar
#   * the jar itself
#
# With no argument the usual locations are searched, including the deployed
# Ascertia installations under /appdata/ascertia.
#
# The version is taken from adss-clientsdk.version when present, otherwise from
# the jar's own MANIFEST (Implementation-Version) — the deployed installations
# ship no version file.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

GROUP_ID="com.ascertia"
ARTIFACT_ID="adss-client-api"
JAR_NAME="adss_client_api.jar"

log()  { printf '\033[0;32m[ok]\033[0m %s\n' "$*"; }
warn() { printf '\033[0;33m[..]\033[0m %s\n' "$*"; }
die()  { printf '\033[0;31m[!!]\033[0m %s\n' "$*" >&2; exit 1; }

command -v mvn >/dev/null 2>&1 || die "Maven 3.9+ is required but 'mvn' is not on PATH."

# ------------------------------------------------------------------ locate ---
JAR=""
resolve_jar() {
  local candidate="$1"
  [[ -z "${candidate}" ]] && return 1
  if [[ -f "${candidate}" ]]; then JAR="${candidate}"; return 0; fi
  for sub in "API/lib/${JAR_NAME}" "lib/${JAR_NAME}" "${JAR_NAME}"; do
    if [[ -f "${candidate}/${sub}" ]]; then JAR="${candidate}/${sub}"; return 0; fi
  done
  return 1
}

if [[ $# -ge 1 ]]; then
  resolve_jar "$1" || die "Cannot find ${JAR_NAME} at or under '$1'."
else
  warn "No path given; searching the usual locations…"
  for candidate in \
      "$(cd "${PROJECT_DIR}/.." && pwd)" \
      "${HOME}/JAVAsdk" \
      /appdata/ascertia/orchestrator \
      /usr/local/ascertia/orchestrator; do
    resolve_jar "${candidate}" && break
  done
  if [[ -z "${JAR}" ]]; then
    # Last resort: any deployed Ascertia installation on this host.
    JAR="$(find /appdata/ascertia /usr/local/ascertia -name "${JAR_NAME}" 2>/dev/null | head -n1 || true)"
  fi
  [[ -n "${JAR}" ]] || die "Cannot find ${JAR_NAME}. Pass its path explicitly."
fi
log "Using SDK jar: ${JAR}"

# ----------------------------------------------------------------- version ---
VERSION=""

# 1. The SDK distribution ships a version file next to API/.
SDK_ROOT="$(cd "$(dirname "${JAR}")/../.." 2>/dev/null && pwd || true)"
VERSION_FILE="${SDK_ROOT}/adss-clientsdk.version"
if [[ -f "${VERSION_FILE}" ]]; then
  MAJOR="$(grep -E '^ADSS_CLIENTSDK_MAJOR_VERSION=' "${VERSION_FILE}" | cut -d= -f2 | tr -d '\r')"
  MINOR="$(grep -E '^ADSS_CLIENTSDK_MINOR_VERSION=' "${VERSION_FILE}" | cut -d= -f2 | tr -d '\r')"
  PATCH="$(grep -E '^ADSS_CLIENTSDK_PATCH_LEVEL='   "${VERSION_FILE}" | cut -d= -f2 | tr -d '\r')"
  [[ -n "${MAJOR}" ]] && VERSION="${MAJOR}.${MINOR}.${PATCH}"
fi

# 2. A deployed installation has no version file, but the jar manifest does.
if [[ -z "${VERSION}" ]] && command -v unzip >/dev/null 2>&1; then
  VERSION="$(unzip -p "${JAR}" META-INF/MANIFEST.MF 2>/dev/null \
             | tr -d '\r' | grep -E '^Implementation-Version:' | head -n1 \
             | cut -d: -f2 | tr -d ' ' || true)"
fi

[[ -n "${VERSION}" ]] || die "Cannot determine the SDK version. Install it manually:
  mvn install:install-file -Dfile='${JAR}' \\
    -DgroupId=${GROUP_ID} -DartifactId=${ARTIFACT_ID} \\
    -Dversion=<version> -Dpackaging=jar"
log "Detected SDK version: ${VERSION}"

# Verify the shipped checksum when the SDK distribution provides one.
if [[ -f "${JAR}.SHA-256" ]] && command -v sha256sum >/dev/null 2>&1; then
  EXPECTED="$(tr -d '[:space:]' < "${JAR}.SHA-256")"
  ACTUAL="$(sha256sum "${JAR}" | cut -d' ' -f1)"
  [[ "${EXPECTED,,}" == "${ACTUAL,,}" ]] || die "Checksum mismatch for ${JAR}. Do not install this jar."
  log "Checksum verified"
fi

# ----------------------------------------------------------------- install ---
mvn -B org.apache.maven.plugins:maven-install-plugin:3.1.2:install-file \
  -Dfile="${JAR}" \
  -DgroupId="${GROUP_ID}" \
  -DartifactId="${ARTIFACT_ID}" \
  -Dversion="${VERSION}" \
  -Dpackaging=jar

log "Installed ${GROUP_ID}:${ARTIFACT_ID}:${VERSION}"

# --------------------------------------------------------------- next step ---
# A mismatch is not an error: the pom's version is a property, so the build can
# simply be pointed at whichever SDK this host actually has.
POM_VERSION="$(grep -oP '(?<=<adss\.sdk\.version>)[^<]+' "${PROJECT_DIR}/pom.xml" | head -n1 || true)"
if [[ -n "${POM_VERSION}" && "${POM_VERSION}" != "${VERSION}" ]]; then
  warn "pom.xml defaults to SDK ${POM_VERSION}, this host has ${VERSION}."
  warn "Build with:  mvn -B -Dadss.sdk.version=${VERSION} clean package"
  warn "Or make it permanent by editing <adss.sdk.version> in pom.xml."
else
  log "Now run:  cd ${PROJECT_DIR} && mvn -B clean package"
fi
