"""v3 fixes the documented Transformers 5.5.4 loading-info container contract.

v1 and v2 remain immutable. No change to pair texts, weights, labels, argmax,
forward limits, file exceptions, or missing/mismatched/unexpected-key criteria.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SELF = Path(__file__).resolve()
V2 = "scripts/qualify_mdeberta_nli_runtime_v2.py"
V2_SHA = "a6d90133dda53f96f2495d230b926ef8b05bba481ba6e861518b377bfe41cdf0"
VERSION = "mdeberta_nli_runtime_qualification_v3"


def normalize_loading_info(info):
    if not isinstance(info, dict):
        raise ValueError("loading_info_invalid")
    result = dict(info)
    types = {}
    for name in ("missing_keys", "unexpected_keys", "mismatched_keys"):
        value = info.get(name)
        if type(value) not in (list, set, frozenset):
            raise ValueError("loading_info_container_invalid")
        types[name] = type(value).__name__
        if name != "mismatched_keys":
            if any(type(k) is not str for k in value) or len(value) != len(set(value)):
                raise ValueError("loading_info_key_invalid")
            result[name] = sorted(value)
        else:
            # The unchanged validator rejects every nonempty mismatch; no
            # shape coercion or key filtering is permitted here.
            result[name] = list(value)
    if type(info.get("error_msgs")) is not list:
        raise ValueError("loading_error_container_invalid")
    types["error_msgs"] = "list"
    return result, types


def load_qualifier():
    if hashlib.sha256((ROOT / V2).read_bytes()).hexdigest() != V2_SHA:
        raise ValueError("frozen_v2_changed")
    spec = importlib.util.spec_from_file_location("frozen_nli_v2_for_v3", ROOT / V2)
    v2 = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(v2)
    validate = v2.validate_loading
    def loading(model, info):
        normalized, types = normalize_loading_info(info)
        result = validate(model, normalized)
        return {**result, "source_container_types": types,
                "container_normalization_only": True}
    v2.SELF = SELF
    v2.VERSION = VERSION
    v2.validate_loading = loading
    q = v2.load_qualifier()
    q.RUNTIME_SOURCES = (*q.RUNTIME_SOURCES, "transformers/modeling_utils.py", "transformers/utils/loading_report.py")
    old_build, old_plan, old_approved, OldGuard = q.build_plan, q.plan_only, q.approved_plan, q.WorkerGuard
    def build(output):
        plan = old_build(output)
        q.require(q.sha(ROOT / V2) == V2_SHA, "frozen_v2_changed")
        plan["implementation_sha256"][V2] = V2_SHA
        plan["v3_loading_info_contract"] = {
            "accepted_key_container_types": ["list", "set", "frozenset"],
            "error_msgs_container": "list", "nonempty_missing_mismatch_errors_rejected": True,
            "unrecognized_or_duplicate_unexpected_keys_rejected": True,
            "only_container_normalization": True}
        return plan
    def plan_only(output):
        plan = old_plan(output)
        target = ROOT / plan["output"] / "frozen_source" / V2
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as stream:
            stream.write((ROOT / V2).read_bytes())
        return plan
    def approved(path):
        result = old_approved(path)
        q.require(q.sha(Path(path).parent / "frozen_source" / V2) == V2_SHA, "frozen_v2_snapshot_changed")
        return result
    class Guard(OldGuard):
        def __init__(self, common, job, output):
            super().__init__(common, job, output)
            self.read_files.update({(ROOT / V2).resolve(), (output / "frozen_source" / V2).resolve()})
    q.build_plan, q.plan_only, q.approved_plan, q.WorkerGuard = build, plan_only, approved, Guard
    return q


if __name__ == "__main__":
    try:
        raise SystemExit(load_qualifier().main())
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(json.dumps({"status": "qualification_failed", "error_type": type(error).__name__,
                          "code": "v3_plan_or_worker_protocol_failed"}))
        raise SystemExit(1) from None
