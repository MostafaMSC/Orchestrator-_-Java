#!/usr/bin/env bash
#
# The ADSS Client SDK is licensed software and is not published to Maven Central,
# so it has to be installed into the local Maven repository once before the
# orchestrator can be built.
#
#   ./deploy/install-adss-sdk.sh [/path/to/JAVAsdk]
#
# The default path assumes this project sits inside the SDK directory, i.e.
#   JAVAsdk/
#     API/lib/adss_client_api.jar
#     twokeyok-orchestrator/          <- this project
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
SDK_DIR="${1:-$(cd "${PROJECT_DIR}/.." && pwd)}"

GROUP_ID="com.ascertia"
ARTIFACT_ID="adss-client-api"

log() { printf '\033[0;32m[ok]\033[0m %s\n' "$*"; }
die() { printf '\033[0;31m[!!]\033[0m %s\n' "$*" >&2; exit 1; }

command -v mvn >/dev/null 2>&1 || die "Maven 3.9+ is required but 'mvn' is not on PATH."

JAR="${SDK_DIR}/API/lib/adss_client_api.jar"
VERSION_FILE="${SDK_DIR}/adss-clientsdk.version"

[[ -f "${JAR}" ]] || die "Cannot find ${JAR}. Pass the SDK directory as the first argument."

# Derive the version from the SDK's own version file so the pom and the jar
# never drift apart.
if [[ -f "${VERSION_FILE}" ]]; then
  MAJOR="$(grep -E '^ADSS_CLIENTSDK_MAJOR_VERSION=' "${VERSION_FILE}" | cut -d= -f2 | tr -d '\r')"
  MINOR="$(grep -E '^ADSS_CLIENTSDK_MINOR_VERSION=' "${VERSION_FILE}" | cut -d= -f2 | tr -d '\r')"
  PATCH="$(grep -E '^ADSS_CLIENTSDK_PATCH_LEVEL='   "${VERSION_FILE}" | cut -d= -f2 | tr -d '\r')"
  VERSION="${MAJOR}.${MINOR}.${PATCH}"
else
  VERSION="8.3.7"
fi

POM_VERSION="$(grep -oP '(?<=<adss\.sdk\.version>)[^<]+' "${PROJECT_DIR}/pom.xml" || true)"
if [[ -n "${POM_VERSION}" && "${POM_VERSION}" != "${VERSION}" ]]; then
  die "SDK version mismatch: the jar is ${VERSION} but pom.xml expects ${POM_VERSION}. Update <adss.sdk.version> in pom.xml."
fi

# Verify the shipped checksum when the SDK provides one.
if [[ -f "${JAR}.SHA-256" ]] && command -v sha256sum >/dev/null 2>&1; then
  EXPECTED="$(tr -d '[:space:]' < "${JAR}.SHA-256")"
  ACTUAL="$(sha256sum "${JAR}" | cut -d' ' -f1)"
  [[ "${EXPECTED,,}" == "${ACTUAL,,}" ]] || die "Checksum mismatch for ${JAR}. Do not install this jar."
  log "Checksum verified"
fi

mvn -B org.apache.maven.plugins:maven-install-plugin:3.1.2:install-file \
  -Dfile="${JAR}" \
  -DgroupId="${GROUP_ID}" \
  -DartifactId="${ARTIFACT_ID}" \
  -Dversion="${VERSION}" \
  -Dpackaging=jar

log "Installed ${GROUP_ID}:${ARTIFACT_ID}:${VERSION} into the local Maven repository"
log "Now run:  cd ${PROJECT_DIR} && mvn -B clean package"
