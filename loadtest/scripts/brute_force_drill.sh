#!/usr/bin/env bash
# Live staging drill: login rate limiter (account + IP dimensions).
#
# Policy (staging defaults): 10 attempts / 300s per account, 30 / 300s per IP.
# Throttled logins return HTTP 200 with an HTML error page (not 429) and may set Retry-After.
#
# Usage:
#   export BASE_URL="http://af-stg....elb.amazonaws.com"
#   ./loadtest/scripts/brute_force_drill.sh account   # 12 wrong-password tries, one real account
#   # wait >= 300s so the IP counter from phase 1 expires, then:
#   ./loadtest/scripts/brute_force_drill.sh ip        # 31 tries across fake accounts, one source IP
#
# Environment:
#   BASE_URL                 (required) staging ALB origin, no trailing slash
#   DRILL_EMAIL              account-phase identifier (default: loadtest@authforge.test)
#   DRILL_WRONG_PASSWORD     deliberate bad password (default: WrongPasswordForDrill1!)
#   DRILL_ACCOUNT_ATTEMPTS   default 12
#   DRILL_IP_ATTEMPTS        default 31
#   DRILL_IP_PREFIX          fake username prefix for IP phase (default: nouser-drill)
#   DRILL_SLEEP_MS           pause between attempts in ms (default: 50)
#
# Run phases separately: both dimensions share the per-IP counter. If you run `account` first,
# wait at least AUTHFORGE_LOGIN_RATE_LIMIT_WINDOW_SECONDS (300s) before `ip`, or the IP phase
# will trip earlier than attempt 31.

set -euo pipefail

PHASE="${1:-}"
if [[ "$PHASE" != "account" && "$PHASE" != "ip" ]]; then
  echo "usage: $0 account|ip" >&2
  exit 1
fi

BASE_URL="${BASE_URL:?set BASE_URL to the staging ALB origin (no trailing slash)}"
BASE_URL="${BASE_URL%/}"

DRILL_EMAIL="${DRILL_EMAIL:-loadtest@authforge.test}"
DRILL_WRONG_PASSWORD="${DRILL_WRONG_PASSWORD:-WrongPasswordForDrill1!}"
DRILL_ACCOUNT_ATTEMPTS="${DRILL_ACCOUNT_ATTEMPTS:-12}"
DRILL_IP_ATTEMPTS="${DRILL_IP_ATTEMPTS:-31}"
DRILL_IP_PREFIX="${DRILL_IP_PREFIX:-nouser-drill}"
DRILL_SLEEP_MS="${DRILL_SLEEP_MS:-50}"

FLOW_COOKIE_VALUE=""

DRILL_START_ISO="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
echo "=== login rate-limit drill: phase=${PHASE} ==="
echo "base_url=${BASE_URL}"
echo "started_utc=${DRILL_START_ISO}"
echo ""

extract_csrf() {
  sed -n 's/.*name="csrf_token" value="\([^"]*\)".*/\1/p' | head -1
}

# Staging ALB is HTTP while auth cookies are Secure; curl drops them unless we copy manually
# (same workaround as loadtest/k6/token_exchange.js storeCookies).
capture_flow_cookie() {
  local headers_file="$1"
  local line
  while IFS= read -r line; do
    line="${line//$'\r'/}"
    case "$line" in
      [Ss]et-[Cc]ookie:*authforge_flow=*)
        FLOW_COOKIE_VALUE="$(sed -n 's/^[Ss]et-[Cc]ookie:[[:space:]]*authforge_flow=\([^;]*\).*/\1/p' <<<"$line")"
        ;;
    esac
  done <"$headers_file"
}

cookie_header() {
  if [[ -n "$FLOW_COOKIE_VALUE" ]]; then
    printf 'authforge_flow=%s' "$FLOW_COOKIE_VALUE"
  fi
}

classify_body() {
  local body="$1"
  if grep -q "Too many sign-in attempts" <<<"$body"; then
    echo "rate_limited"
  elif grep -q "That email or password is not correct" <<<"$body"; then
    echo "invalid_credentials"
  elif grep -q "temporarily locked" <<<"$body"; then
    echo "account_locked"
  elif grep -q "has been disabled" <<<"$body"; then
    echo "account_disabled"
  elif grep -q "form has expired" <<<"$body"; then
    echo "csrf_error"
  else
    echo "other"
  fi
}

login_attempt() {
  local attempt="$1"
  local identifier="$2"

  local page csrf http_code body headers retry_after classification cookie
  headers="$(mktemp)"
  page="$(curl -sS -D "$headers" "${BASE_URL}/login")"
  capture_flow_cookie "$headers"
  csrf="$(printf '%s' "$page" | extract_csrf)"
  if [[ -z "$csrf" ]]; then
    echo "attempt=${attempt} identifier=${identifier} ERROR=could not parse csrf_token from GET /login" >&2
    rm -f "$headers"
    return 1
  fi
  cookie="$(cookie_header)"
  if [[ -z "$cookie" ]]; then
    echo "attempt=${attempt} identifier=${identifier} ERROR=authforge_flow cookie missing from GET /login" >&2
    rm -f "$headers"
    return 1
  fi

  body="$(mktemp)"
  http_code="$(
    curl -sS -o "$body" -D "$headers" -w "%{http_code}" \
      -X POST "${BASE_URL}/login" \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -H "Cookie: ${cookie}" \
      --data-urlencode "identifier=${identifier}" \
      --data-urlencode "password=${DRILL_WRONG_PASSWORD}" \
      --data-urlencode "csrf_token=${csrf}" \
      --data-urlencode "next="
  )"
  retry_after="$(sed -n 's/^[Rr]etry-[Aa]fter:[[:space:]]*\([0-9]*\).*/\1/p' "$headers" | tr -d '\r' | head -1)"
  classification="$(classify_body "$(cat "$body")")"
  rm -f "$body" "$headers"

  printf 'attempt=%02d http=%s class=%s retry_after=%s identifier=%s\n' \
    "$attempt" "$http_code" "$classification" "${retry_after:-}" "$identifier"

  if [[ "$DRILL_SLEEP_MS" -gt 0 ]]; then
    # Portable sub-second sleep where available (Git Bash sleep accepts decimals).
    sleep "$(awk "BEGIN {printf \"%.3f\", ${DRILL_SLEEP_MS}/1000}")"
  fi
}

run_account_phase() {
  echo "target_account=${DRILL_EMAIL}"
  echo "attempts=${DRILL_ACCOUNT_ATTEMPTS} (expect invalid_credentials on 1-10, rate_limited on 11+)"
  echo ""
  local i
  for ((i = 1; i <= DRILL_ACCOUNT_ATTEMPTS; i++)); do
    login_attempt "$i" "$DRILL_EMAIL"
  done
}

run_ip_phase() {
  echo "fake_accounts=${DRILL_IP_PREFIX}-NN@example.test"
  echo "attempts=${DRILL_IP_ATTEMPTS} (expect invalid_credentials on 1-30, rate_limited on 31+)"
  echo ""
  local i
  for ((i = 1; i <= DRILL_IP_ATTEMPTS; i++)); do
    login_attempt "$i" "${DRILL_IP_PREFIX}-$(printf '%02d' "$i")@example.test"
  done
}

case "$PHASE" in
  account) run_account_phase ;;
  ip) run_ip_phase ;;
esac

DRILL_END_ISO="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
echo ""
echo "finished_utc=${DRILL_END_ISO}"
echo ""
cat <<EOF
--- CloudWatch verification (/ecs/authforge-staging) ---

Use Logs Insights with a window covering:
  ${DRILL_START_ISO}  ->  ${DRILL_END_ISO}  (add ~1 minute slack on each side)

1) Account phase — login_failure events should climb (10 allowed failures before throttle):
   fields @timestamp, event, outcome, detail, request_id
   | filter message = "security event"
   | filter event = "login_failure"
   | filter @timestamp >= "${DRILL_START_ISO}"
   | sort @timestamp asc

   Expect ~10 rows (attempts 1-10). Attempts 11+ do not emit login_failure because the
   rate limiter short-circuits before credential verification.

2) Account phase — account throttle (attempt 11 or 12):
   fields @timestamp, event, outcome, detail, request_id
   | filter message = "security event"
   | filter event = "rate_limit_exceeded"
   | filter detail.scope = "login"
   | filter @timestamp >= "${DRILL_START_ISO}"
   | sort @timestamp asc

   Expect >= 1 row. detail.retry_after_seconds should be present.
   Correlate with the script line class=rate_limited (HTTP 200, not 429).

   Optional corroboration from the limiter itself:
   fields @timestamp, message, limit_scope, limit, window_seconds
   | filter message = "rate limit exceeded"
   | filter limit_scope = "login_account"
   | filter @timestamp >= "${DRILL_START_ISO}"
   | sort @timestamp asc

3) IP phase — login_failure on many distinct fake accounts:
   fields @timestamp, event, outcome, detail, request_id
   | filter message = "security event"
   | filter event = "login_failure"
   | filter @timestamp >= "${DRILL_START_ISO}"
   | sort @timestamp asc

   Expect ~30 rows (one per fake username through attempt 30).

4) IP phase — IP throttle (attempt 31):
   fields @timestamp, event, outcome, detail, request_id
   | filter message = "security event"
   | filter event = "rate_limit_exceeded"
   | filter detail.scope = "login"
   | filter @timestamp >= "${DRILL_START_ISO}"
   | sort @timestamp asc

   Expect >= 1 row on the IP phase run. Script attempt 31 should show class=rate_limited.

   Optional corroboration:
   fields @timestamp, message, limit_scope, limit, window_seconds
   | filter message = "rate limit exceeded"
   | filter limit_scope = "login_ip"
   | filter @timestamp >= "${DRILL_START_ISO}"
   | sort @timestamp asc

5) Account phase only — durable lockout audit (Postgres lockout fires on the 10th failure
   even though the UI still shows the generic wrong-password message):
   fields @timestamp, event, outcome, detail, request_id
   | filter message = "security event"
   | filter event = "account_locked"
   | filter @timestamp >= "${DRILL_START_ISO}"
   | sort @timestamp asc

   Expect 1 row near the 10th failed attempt.

CLI one-liner (replace START/END):
  aws logs start-query --log-group-name /ecs/authforge-staging \\
    --start-time \$(date -u -d 'START' +%s) --end-time \$(date -u -d 'END' +%s) \\
    --query-string 'fields @timestamp, event, message, detail, limit_scope | filter message in ["security event", "rate limit exceeded"] | sort @timestamp asc'

After the account drill, the load-test user may have failed_login_count elevated. A successful
login or \`authforge-admin\` user unlock clears Redis counters; wait 300s before the IP phase
if both are run from the same workstation.
EOF
