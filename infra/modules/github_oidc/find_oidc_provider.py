#!/usr/bin/env python3
"""Return whether a GitHub OIDC provider already exists in the AWS account."""

import json
import shutil
import subprocess


def main() -> None:
    if shutil.which("aws") is None:
        print(json.dumps({"arn": ""}))
        return

    try:
        result = subprocess.run(
            # aws is resolved via PATH after shutil.which confirms it is installed.
            ["aws", "iam", "list-open-id-connect-providers", "--output", "json"],  # noqa: S607
            capture_output=True,
            text=True,
            check=True,
        )
        payload = json.loads(result.stdout)
        matches = [
            item["Arn"]
            for item in payload.get("OpenIDConnectProviderList", [])
            if "token.actions.githubusercontent.com" in item["Arn"]
        ]
        print(json.dumps({"arn": matches[0] if matches else ""}))
    except (subprocess.CalledProcessError, json.JSONDecodeError, KeyError):
        print(json.dumps({"arn": ""}))


if __name__ == "__main__":
    main()
