"""Read-only DeepSeek account/model checks; never persist authentication data."""
from __future__ import annotations

import datetime as dt
import http.client
import json
import os
from pathlib import Path

from .budget import ChatCompletionsConnector


def inspect_deepseek(output: Path, key_env="STUDY_MODEL_API_KEY"):
    credential = os.environ.get(key_env)
    if not credential:
        raise ValueError("credential_environment_variable_missing")
    report = {"timestamp_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
              "host": "api.deepseek.com", "generative_requests": 0, "checks": {}}
    for endpoint in ("/models", "/user/balance"):
        conn = http.client.HTTPSConnection("api.deepseek.com", timeout=30)
        try:
            conn.request("GET", endpoint, headers={"Authorization": "Bearer " + credential})
            response = conn.getresponse()
            raw = response.read(1048577)
            item = {"status": response.status}
            if len(raw) > 1048576 or credential.encode() in raw:
                item["error"] = "unsafe_or_oversize_response"
            elif response.status == 200:
                value = json.loads(raw)
                if ChatCompletionsConnector._contains_sensitive_data(value, credential):
                    item["error"] = "sensitive_response_rejected"
                elif endpoint == "/models":
                    item["model_ids"] = [m["id"] for m in value.get("data", []) if isinstance(m.get("id"), str)]
                else:
                    item["is_available"] = value.get("is_available")
                    item["balances"] = [{"currency": b.get("currency"), "total_balance": b.get("total_balance")}
                                        for b in value.get("balance_infos", [])]
            report["checks"][endpoint] = item
        except Exception as exc:
            report["checks"][endpoint] = {"error": type(exc).__name__}
        finally:
            conn.close()
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return report


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output already exists")
    print(json.dumps(inspect_deepseek(args.output), ensure_ascii=False))
