"""Standard-library, rules-only demo with synthetic text and a simulated answer."""
import argparse
import json
from pathlib import Path
import re
import sys
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from memory_migration_study.privacy import detect_sensitive, prepare_private_payload, restore_answer
from memory_migration_study.privacy_egress import validate_outbound


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    policy = {"version": "authored-demo-v3", "protected_categories": ["CUSTOMER", "PROJECT", "AMOUNT"]}
    source = {"query": "What customer belongs to project Cedar-R8?", "memories": [
        {"source_id": "synthetic-memory-1", "text": "Customer: Violet Harbor Cooperative; Project: Cedar-R8; Budget: 319,000 USD."}]}
    # Identity and authority come from this trusted local program, never the text.
    def authorize(sid, actor, version):
        return sid == "synthetic-memory-1" and actor == "owner" and version == policy["version"]
    detection = detect_sensitive(source, policy, mode="rules")
    request = str(uuid.uuid4())
    prepared = prepare_private_payload(source, detection, actor_id="owner", request_id=request,
        policy_version=policy["version"], sensitivity_policy=policy, authorizer=authorize)
    check = validate_outbound(source, prepared, detection, policy)
    if check["status"] != "ok":
        raise RuntimeError("demo_outbound_blocked")
    # Select a known category solely to exercise restoration. No model is called.
    simulated = re.search(r"\[PVT_[A-F0-9]{24}_CUSTOMER_\d+\]", prepared["payload"]["memories"][0]["text"]).group()
    restored = restore_answer(simulated, prepared["mapping"], actor_id="owner", request_id=request,
        policy_version=policy["version"], sensitivity_policy=policy, authorizer=authorize)
    outsider = restore_answer(simulated, prepared["mapping"], actor_id="outsider", request_id=request,
        policy_version=policy["version"], sensitivity_policy=policy, authorizer=authorize)
    result = {"synthetic": True, "detector": "rules_only", "cloud_calls": 0,
              "original": source, "prepared_for_cloud_but_not_sent": prepared["payload"],
              "simulated_cloud_answer": simulated, "authorized_restore": restored,
              "cross_actor_restore": outsider, "task_quality": None}
    prepared["mapping"] = None
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("x", encoding="utf-8") as stream:
            json.dump(result, stream, ensure_ascii=False, indent=2)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
