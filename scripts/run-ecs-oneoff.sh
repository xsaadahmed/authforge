#!/usr/bin/env bash
# Run a one-off Fargate task using the env's existing task definition, private
# subnets, and ecs-sg — same network path as the long-running service.
#
# Usage:
#   ./scripts/run-ecs-oneoff.sh [TF_DIR] -- <command> [args...]
#   TF_DIR=infra/envs/staging ./scripts/run-ecs-oneoff.sh -- alembic upgrade head
#
# Values are read from `terraform output` (never hardcoded).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TF_DIR="${TF_DIR:-${ROOT}/infra/envs/staging}"

if [[ "${1:-}" != "--" && -d "${1:-}" ]]; then
  TF_DIR="$1"
  shift
fi

if [[ "${1:-}" != "--" ]]; then
  echo "usage: $0 [TF_DIR] -- <command> [args...]" >&2
  echo "example: $0 -- alembic upgrade head" >&2
  exit 2
fi
shift

if [[ "$#" -lt 1 ]]; then
  echo "error: no command provided after --" >&2
  exit 2
fi

if ! command -v terraform >/dev/null 2>&1; then
  echo "error: terraform is required" >&2
  exit 1
fi
if ! command -v aws >/dev/null 2>&1; then
  echo "error: aws CLI is required" >&2
  exit 1
fi
resolve_python() {
  # Prefer a real interpreter. On Windows, `python3` is often only the Microsoft
  # Store App Execution Alias stub (WindowsApps), which prints a Store advert and
  # exits 49 — while `python` points at the actual install.
  local candidate
  for candidate in python python3; do
    if ! command -v "${candidate}" >/dev/null 2>&1; then
      continue
    fi
    candidate="$(command -v "${candidate}")"
    case "${candidate}" in
      *WindowsApps*) continue ;;
    esac
    if "${candidate}" -c "import sys" >/dev/null 2>&1; then
      echo "${candidate}"
      return 0
    fi
  done
  # Windows Python launcher as a last resort (expands to a real install).
  if command -v py >/dev/null 2>&1; then
    candidate="$(py -3 -c "import sys; print(sys.executable)" 2>/dev/null || true)"
    if [[ -n "${candidate}" && -x "${candidate}" ]]; then
      echo "${candidate}"
      return 0
    fi
  fi
  return 1
}

if ! PYTHON="$(resolve_python)"; then
  echo "error: a working Python interpreter is required to build the run-task override JSON" >&2
  echo "hint: on Windows, disable App Installer python.exe / python3.exe under" >&2
  echo "      Settings > Apps > Advanced app settings > App execution aliases" >&2
  exit 1
fi


tf_out() {
  terraform -chdir="${TF_DIR}" output -raw "$1"
}

tf_json() {
  terraform -chdir="${TF_DIR}" output -json "$1"
}

echo "==> reading terraform outputs from ${TF_DIR}"
REGION="$(tf_out aws_region)"
CLUSTER="$(tf_out ecs_cluster_name)"
TASK_DEF="$(tf_out ecs_task_definition_arn)"
CONTAINER="$(tf_out ecs_container_name)"
LOG_GROUP="$(tf_out ecs_log_group_name)"
SG="$(tf_out ecs_security_group_id)"
SUBNETS_JSON="$(tf_json private_subnet_ids)"

SUBNET_CSV="$("${PYTHON}" -c 'import json,sys; print(",".join(json.load(sys.stdin)))' <<<"${SUBNETS_JSON}")"
OVERRIDES="$("${PYTHON}" -c '
import json, sys
container = sys.argv[1]
command = sys.argv[2:]
# Source lives in WORKDIR and is not installed into the venv; console scripts need this.
print(json.dumps({
    "containerOverrides": [{
        "name": container,
        "command": command,
        "environment": [{"name": "PYTHONPATH", "value": "/srv/authforge"}],
    }]
}))
' "${CONTAINER}" "$@")"

echo "==> run-task cluster=${CLUSTER} taskDefinition=${TASK_DEF}"
echo "==> command: $*"

RUN_JSON="$(aws ecs run-task \
  --region "${REGION}" \
  --cluster "${CLUSTER}" \
  --task-definition "${TASK_DEF}" \
  --launch-type FARGATE \
  --platform-version LATEST \
  --count 1 \
  --started-by "authforge-oneoff" \
  --network-configuration "awsvpcConfiguration={subnets=[${SUBNET_CSV}],securityGroups=[${SG}],assignPublicIp=DISABLED}" \
  --overrides "${OVERRIDES}" \
  --output json)"

TASK_ARN="$("${PYTHON}" -c 'import json,sys; d=json.load(sys.stdin); tasks=d.get("tasks") or []; fails=d.get("failures") or [];
assert tasks, f"run-task failed: {fails or d}"; print(tasks[0]["taskArn"])' <<<"${RUN_JSON}")"
TASK_ID="${TASK_ARN##*/}"

echo "==> started task ${TASK_ARN}"
echo "==> waiting for task to stop..."
aws ecs wait tasks-stopped --region "${REGION}" --cluster "${CLUSTER}" --tasks "${TASK_ARN}"

DESC="$(aws ecs describe-tasks \
  --region "${REGION}" \
  --cluster "${CLUSTER}" \
  --tasks "${TASK_ARN}" \
  --output json)"

EXIT_CODE="$("${PYTHON}" -c '
import json, sys
task = json.load(sys.stdin)["tasks"][0]
containers = task.get("containers") or []
code = None
for c in containers:
    if c.get("exitCode") is not None:
        code = c["exitCode"]
        break
if code is None:
    code = 1 if task.get("stopCode") else 0
print(code)
print(task.get("stoppedReason") or "", file=sys.stderr)
print(task.get("stopCode") or "", file=sys.stderr)
' <<<"${DESC}")"

echo "==> container exit code: ${EXIT_CODE}"

STREAM="ecs/${CONTAINER}/${TASK_ID}"
echo "==> CloudWatch logs: logGroup=${LOG_GROUP} stream=${STREAM}"
for _ in 1 2 3 4 5 6; do
  if aws logs get-log-events \
    --region "${REGION}" \
    --log-group-name "${LOG_GROUP}" \
    --log-stream-name "${STREAM}" \
    --start-from-head \
    --output text \
    --query 'events[*].message' 2>/dev/null; then
    break
  fi
  sleep 2
done

exit "${EXIT_CODE}"
