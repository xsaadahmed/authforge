#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "==> terraform fmt"
terraform -chdir="${ROOT}/infra" fmt -recursive

validate_env() {
  local env_dir="$1"
  echo "==> validating ${env_dir}"
  terraform -chdir="${env_dir}" init -backend=false -input=false
  terraform -chdir="${env_dir}" validate
}

for module_dir in "${ROOT}/infra/modules"/*; do
  if [[ -f "${module_dir}/main.tf" ]]; then
    echo "==> validating module ${module_dir##*/}"
    terraform -chdir="${module_dir}" init -backend=false -input=false
    terraform -chdir="${module_dir}" validate
  fi
done

validate_env "${ROOT}/infra/bootstrap"
validate_env "${ROOT}/infra/envs/staging"
validate_env "${ROOT}/infra/envs/prod"

echo "All Terraform configurations are valid."
