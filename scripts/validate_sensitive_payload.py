"""Run local sensitive detection with advisory syntax/checksum/date annotations.

Input JSON contains exactly payload and policy. Default is zero-model rules;
--with-local-agent adds only the pinned loopback Qwen detector. No raw values
are copied into annotations, and invalid candidates are not released.
"""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def run(input_path, output_path, *, with_local_agent=False, detector_config=None):
    from memory_migration_study.value_validation import detect_sensitive
    input_path, output_path = Path(input_path), Path(output_path)
    if input_path.resolve() == output_path.resolve() or output_path.exists():
        raise ValueError("output_must_be_new_and_distinct")
    try:
        content = json.loads(input_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeError):
        raise ValueError("invalid_input_json") from None
    if not isinstance(content, dict) or set(content) != {"payload", "policy"}:
        raise ValueError("input_requires_exact_payload_and_policy")
    agent = None
    if with_local_agent:
        from memory_migration_study.local_detector import LocalSensitivityAgent
        config = json.loads(Path(detector_config or "configs/local_privacy_detector.json").read_text(encoding="utf-8"))
        agent = LocalSensitivityAgent(config)
    result = detect_sensitive(content["payload"], content["policy"], mode="combined" if with_local_agent else "rules", agent=agent)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(result, ensure_ascii=False, indent=2)+"\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--with-local-agent", action="store_true")
    parser.add_argument("--detector-config", type=Path, default=Path("configs/local_privacy_detector.json"))
    args = parser.parse_args()
    def audit(event, values):
        if event == "socket.connect":
            address = values[1]
            if not isinstance(address, tuple) or address[0] not in {"127.0.0.1", "::1"}:
                raise RuntimeError("external_network_disabled")
    sys.addaudithook(audit)
    result = run(args.input, args.output, with_local_agent=args.with_local_agent, detector_config=args.detector_config)
    print(json.dumps({"status": result["status"], "candidates": len(result.get("findings", [])),
                      "annotations": len(result["validation_annotations"]), "local_calls": result.get("local_calls", 0),
                      "scope": result["value_validation_scope"]}))
