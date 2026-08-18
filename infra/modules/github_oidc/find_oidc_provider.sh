#!/usr/bin/env bash
set -euo pipefail

# Returns whether a GitHub OIDC provider already exists in the account.
if ! command -v aws >/dev/null 2>&1; then
  echo '{"arn":""}'
  exit 0
fi

arn="$(aws iam list-open-id-connect-providers --output json \
  | python3 -c 'import json,sys; arns=json.load(sys.stdin).get("OpenIDConnectProviderList",[]); matches=[a["Arn"] for a in arns if "token.actions.githubusercontent.com" in a["Arn"]]; print(matches[0] if matches else "")')"

printf '{"arn":"%s"}\n' "${arn}"
