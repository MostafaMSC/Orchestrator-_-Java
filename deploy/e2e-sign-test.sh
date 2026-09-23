#!/usr/bin/env bash
#
# End-to-end signing test against the real ADSS environment.
#
#   Test PDF -> Orchestrator -> ADSS -> signed PDF -> signature verified
#
# Run this ON the orchestrator/ADSS host, inside the network.
#
#   export ORCH_CLIENT_ID=hr_portal
#   read -rs ORCH_CLIENT_SECRET && export ORCH_CLIENT_SECRET
#   ./deploy/e2e-sign-test.sh --signer ministry_eseal
#
# The secret is read from the environment, passed to curl through a mode-0600
# config file (never on the command line, so it stays out of `ps`), and is never
# echoed. Nothing here rotates or changes any credential.
#
set -uo pipefail

JAR="${JAR:-/opt/twokeyok/orchestrator/twokeyok-orchestrator.jar}"
BASE_URL="${BASE_URL:-https://localhost/orchestrator}"
OUT_DIR="${OUT_DIR:-./e2e-out}"
SIGNER_ID=""
PIN=""
INSECURE=""
CONTAINER="NONE"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --signer)     SIGNER_ID="$2"; shift 2 ;;
    --pin)        PIN="$2"; shift 2 ;;
    --base-url)   BASE_URL="$2"; shift 2 ;;
    --jar)        JAR="$2"; shift 2 ;;
    --out)        OUT_DIR="$2"; shift 2 ;;
    --container)  CONTAINER="$2"; shift 2 ;;
    # Self-signed listener certificate on a staging box.
    --insecure|-k) INSECURE="-k"; shift ;;
    -h|--help)    sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done

# ---------------------------------------------------------------- output ----
BOLD=$'\033[1m'; RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[0;33m'; OFF=$'\033[0m'
step() { printf '\n%s==> %s%s\n' "$BOLD" "$*" "$OFF"; }
ok()   { printf '%s  PASS%s  %s\n' "$GREEN" "$OFF" "$*"; }
bad()  { printf '%s  FAIL%s  %s\n' "$RED" "$OFF" "$*"; }
warn() { printf '%s  WARN%s  %s\n' "$YELLOW" "$OFF" "$*"; }

# Scorecard. Every stage starts unknown and is set as it runs.
R_PRECHECK="NOT RUN"; R_ORCH="NOT RUN"; R_ADSS="NOT RUN"; R_AUTH="NOT RUN"
R_CRED="NOT RUN"; R_SIGN="NOT RUN"; R_VALIDATE="NOT RUN"
FAILED_STAGE=""

finish() {
  printf '\n%s================ RESULT ================%s\n' "$BOLD" "$OFF"
  printf '  PRECHECK             : %s\n' "$R_PRECHECK"
  printf '  ORCHESTRATOR         : %s\n' "$R_ORCH"
  printf '  ADSS CONNECTION      : %s\n' "$R_ADSS"
  printf '  AUTHENTICATION       : %s\n' "$R_AUTH"
  printf '  CREDENTIAL           : %s\n' "$R_CRED"
  printf '  SIGNING              : %s\n' "$R_SIGN"
  printf '  SIGNATURE VALIDATION : %s\n' "$R_VALIDATE"
  printf '%s=======================================%s\n' "$BOLD" "$OFF"
  if [[ -n "$FAILED_STAGE" ]]; then
    printf '\n  Failed at stage: %s\n' "$FAILED_STAGE"
    printf '  Diagnostics collected in: %s\n' "$OUT_DIR"
    printf '  Recent orchestrator log lines:\n'
    tail -n 40 /var/log/twokeyok-orchestrator/orchestrator.log 2>/dev/null \
      | sed 's/^/    /' || echo "    (log not readable from this user)"
  fi
  exit "${1:-0}"
}

# ---------------------------------------------------------------- inputs ----
[[ -f "$JAR" ]] || { bad "jar not found: $JAR"; FAILED_STAGE="setup"; finish 1; }
: "${ORCH_CLIENT_ID:?Set ORCH_CLIENT_ID to a registered client id}"
: "${ORCH_CLIENT_SECRET:?Set ORCH_CLIENT_SECRET (it is never printed)}"

mkdir -p "$OUT_DIR"
CURL_CFG="$(mktemp)"
chmod 600 "$CURL_CFG"
# Keeping credentials in a config file keeps them off the process list.
printf 'user = "%s:%s"\n' "$ORCH_CLIENT_ID" "$ORCH_CLIENT_SECRET" > "$CURL_CFG"
trap 'rm -f "$CURL_CFG"' EXIT

CURL=(curl --silent --show-error --config "$CURL_CFG")
[[ -n "$INSECURE" ]] && CURL+=("$INSECURE")

# ====================================================================
step "1/6  Preflight — ADSS endpoints, key material, effective profile"
# ====================================================================
if java -jar "$JAR" --check-adss | tee "$OUT_DIR/preflight.txt"; then
  R_PRECHECK="PASS"; R_ADSS="PASS"; ok "preflight"
else
  R_PRECHECK="FAIL"; R_ADSS="FAIL"
  bad "preflight — a required ADSS endpoint is unreachable"
  FAILED_STAGE="preflight / ADSS connectivity"
  finish 1
fi

# ====================================================================
step "2/6  Orchestrator health"
# ====================================================================
HEALTH_CODE=$("${CURL[@]}" -o "$OUT_DIR/health.json" -w '%{http_code}' \
  "$BASE_URL/actuator/health" || echo "000")
if [[ "$HEALTH_CODE" == "200" ]]; then
  R_ORCH="PASS"; ok "health endpoint returned 200"; cat "$OUT_DIR/health.json"; echo
else
  R_ORCH="FAIL"
  bad "health endpoint returned $HEALTH_CODE — is the service running?"
  echo "    systemctl status twokeyok-orchestrator"
  FAILED_STAGE="orchestrator not reachable at $BASE_URL"
  finish 1
fi

# ====================================================================
step "3/6  Authentication — list signature appearances"
# ====================================================================
APPEAR_CODE=$("${CURL[@]}" -o "$OUT_DIR/appearances.json" -w '%{http_code}' \
  "$BASE_URL/service/signing/appearances/list" || echo "000")
case "$APPEAR_CODE" in
  200) R_AUTH="PASS"; ok "authenticated as client '$ORCH_CLIENT_ID'" ;;
  401) R_AUTH="FAIL"; bad "401 — client id or secret rejected"
       cat "$OUT_DIR/appearances.json"; echo
       FAILED_STAGE="authentication"; finish 1 ;;
  *)   R_AUTH="FAIL"; bad "unexpected HTTP $APPEAR_CODE"
       cat "$OUT_DIR/appearances.json"; echo
       FAILED_STAGE="authentication"; finish 1 ;;
esac

# ====================================================================
step "4/6  Generate the unsigned test document"
# ====================================================================
java -jar "$JAR" --make-test-pdf "$OUT_DIR/test-unsigned.pdf" || {
  bad "could not generate the test PDF"; FAILED_STAGE="test document"; finish 1; }
ok "unsigned test document ready"

# ====================================================================
step "5/6  Sign — Test PDF -> Orchestrator -> ADSS"
# ====================================================================
SIGN_ARGS=(-F "input_files=@$OUT_DIR/test-unsigned.pdf" -F "container_type=$CONTAINER")
[[ -n "$SIGNER_ID" ]] && SIGN_ARGS+=(-F "signer_id=$SIGNER_ID")
# The PIN is only needed for a natural person; it is never echoed.
[[ -n "$PIN" ]] && SIGN_ARGS+=(-F "pin=$PIN")

SIGN_CODE=$("${CURL[@]}" -o "$OUT_DIR/test-signed.pdf" -w '%{http_code}' \
  -D "$OUT_DIR/sign-headers.txt" \
  -X POST "${SIGN_ARGS[@]}" "$BASE_URL/service/sign" || echo "000")

if [[ "$SIGN_CODE" == "200" ]]; then
  R_SIGN="PASS"; R_CRED="PASS"
  ok "HTTP 200, $(stat -c%s "$OUT_DIR/test-signed.pdf" 2>/dev/null || echo '?') bytes returned"
else
  R_SIGN="FAIL"
  bad "HTTP $SIGN_CODE"
  echo "  --- response headers ---"; sed 's/^/    /' "$OUT_DIR/sign-headers.txt"
  echo "  --- response body ---";    sed 's/^/    /' "$OUT_DIR/test-signed.pdf"; echo

  # Map the orchestrator error code onto the stage that failed, so the next
  # step is obvious without reading the source.
  ERR=$(grep -o '"error_code"[[:space:]]*:[[:space:]]*[0-9]*' "$OUT_DIR/test-signed.pdf" \
        | grep -o '[0-9]*$' || true)
  case "$ERR" in
    1002|1104|1102|1103) R_CRED="FAIL"; FAILED_STAGE="signer selection (error $ERR)" ;;
    1029|1122|1031|1105) R_CRED="FAIL"; FAILED_STAGE="credential selection (error $ERR)" ;;
    1106|1107|1108|1121) R_CRED="PASS"; FAILED_STAGE="signature appearance (error $ERR)" ;;
    1111|1120)           R_CRED="PASS"; FAILED_STAGE="signing profile configuration (error $ERR)" ;;
    1114)                R_ADSS="FAIL"; FAILED_STAGE="ADSS connection (error $ERR)" ;;
    1115)                R_CRED="PASS"; FAILED_STAGE="ADSS rejected the signing request (error $ERR) — see the message above for the ADSS code" ;;
    1112|1113)           R_CRED="PASS"; FAILED_STAGE="remote authorisation by the signer (error $ERR)" ;;
    *)                   FAILED_STAGE="signing (HTTP $SIGN_CODE, error ${ERR:-none})" ;;
  esac
  finish 1
fi

# ====================================================================
step "6/6  Verify the output is genuinely signed"
# ====================================================================
if [[ "$CONTAINER" != "NONE" ]]; then
  warn "container_type=$CONTAINER, so the response is an archive — skipping PDF verification"
  R_VALIDATE="SKIPPED"
  finish 0
fi

if java -jar "$JAR" --verify-pdf "$OUT_DIR/test-signed.pdf" | tee "$OUT_DIR/verification.txt"; then
  R_VALIDATE="PASS"; ok "signature verifies over the document bytes"
else
  R_VALIDATE="FAIL"
  bad "the returned file is not a validly signed PDF"
  FAILED_STAGE="signature validation"
  finish 1
fi

printf '\n  Signed output: %s\n' "$OUT_DIR/test-signed.pdf"
finish 0
