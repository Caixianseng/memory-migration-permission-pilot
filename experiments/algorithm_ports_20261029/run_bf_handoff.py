"""Controlled B/F decisions through the project's current/read/transfer gates.

No model calls. Trusted test declarations supply the lineage; equal text does
not establish independent sources. The graph selects candidates, never grants
permission or changes the underlying authority.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import time

from experiments.algorithm_ports_20261029.bf_port import (
    BfMaterialization, FullRecomputeBaseline, GroundRule, DeliveryKey,
    delivery_projection,
)
from experiments.algorithm_ports_20261029.dual_gate import HandoffSession, RECEIVER


def run(output: Path):
    output.mkdir(parents=True, exist_ok=False)
    # Two independently declared fixture roots support the SAME exact value.
    # Two copies below A are expressly declared to share ancestor A.
    value = "VCONTROLLEDSOURCE"
    text = f"Station SHANDOFF has customer code {value}."
    case = {"story_id": "bf_handoff", "split": "integration",
        "query": "What is the customer code for station SHANDOFF?",
        "records": [{"source_id": sid, "text": text, "protected_value": value,
            "recipient_read": True, "export_allowed": True, "copy_allowed": True}
            for sid in ("trusted-root-A", "trusted-root-B")]}
    host = HandoffSession(case, output / "host_state")
    rules = [GroundRule("copy1", ("rootA",)), GroundRule("copy2", ("rootA",)),
        GroundRule("joint", ("copy1", "rootB")),
        GroundRule("alternative", ("copy1",)), GroundRule("alternative", ("rootB",))]
    # The final projection additionally requires the exact operation grant.
    targets = {DeliveryKey(RECEIVER[0], RECEIVER[1], "transfer", name, "target"):
        {name, "grant-transfer"} for name in ("copy1", "copy2", "joint", "alternative")}
    candidate = BfMaterialization({"rootA", "rootB", "grant-transfer"}, rules)
    baseline = FullRecomputeBaseline({"rootA", "rootB", "grant-transfer"}, rules)
    observations = []

    def record(stage, delete=(), insert=(), forbidden=()):
        begin = time.perf_counter_ns()
        cr = candidate.update(delete=delete, insert=insert)
        cp = delivery_projection(cr.materialized, targets, globally_forbidden=forbidden)
        candidate_total = time.perf_counter_ns() - begin
        begin = time.perf_counter_ns()
        br = baseline.update(delete=delete, insert=insert)
        bp = delivery_projection(br.materialized, targets, globally_forbidden=forbidden)
        baseline_total = time.perf_counter_ns() - begin
        assert cr.materialized == br.materialized and cp == bp, stage
        row = {"stage": stage, "engine_agreement": True,
            "graph_delivery_resources": sorted(k.resource_id for k in cp),
            "candidate_update_projection_ns": candidate_total,
            "baseline_update_projection_ns": baseline_total}
        observations.append(row)
        return row

    def placeholder(request):
        return request["prepared"]["payload"]["memories"][0]["text"].split("customer code ")[1].rstrip(".")

    initial = record("initial")
    assert initial["graph_delivery_resources"] == ["alternative", "copy1", "copy2", "joint"]
    request = host.prepare(host.eligible()[0], "bf-before-revoke")
    assert host.restore(placeholder(request), request)["answer"] == value
    initial["host_restore"] = "ok"

    host.revoke("trusted-root-A")
    after_a = record("revoke_A", delete={"rootA"})
    assert after_a["graph_delivery_resources"] == ["alternative"]
    try:
        host.restore(placeholder(request), request)
    except (ValueError, PermissionError):
        after_a["stale_packet_blocked"] = True
    else:
        raise AssertionError("old packet unexpectedly accepted")
    remaining = host.eligible()[0]
    assert len(remaining) == 1 and remaining[0]["source"]["source_id"] == "trusted-root-B"
    fresh = host.prepare(remaining, "bf-independent-B")
    assert host.restore(placeholder(fresh), fresh)["answer"] == value
    after_a["fresh_independent_host_restore"] = "ok"

    no_grant = record("remove_transfer_grant", delete={"grant-transfer"})
    assert no_grant["graph_delivery_resources"] == []
    returned = record("restore_declared_graph_grant", insert={"grant-transfer"})
    assert returned["graph_delivery_resources"] == ["alternative"]
    forbidden = record("global_obligation", forbidden=set(targets))
    assert forbidden["graph_delivery_resources"] == []

    host.revoke("trusted-root-B")
    after_b = record("revoke_B", delete={"rootB"})
    assert not after_b["graph_delivery_resources"] and not host.eligible()[0]
    # Deliberately stale/untrusted graph input cannot override live host policy.
    stale = record("untrusted_stale_graph_root", insert={"rootB"})
    assert stale["graph_delivery_resources"] == ["alternative"]
    try:
        bad_request = host.prepare([host.by_source["trusted-root-B"]], "bf-stale-authority")
        result = host.restore(placeholder(bad_request), bad_request)
        assert result["status"] != "ok"
    except (ValueError, PermissionError):
        pass
    stale["host_still_denies"] = True
    result = {"status": "passed", "stages": observations, "model_calls": 0,
        "scope": "controlled trusted lineage through existing host interfaces; not native product IAM",
        "independence": "Declared by fixture; equal content never supplies lineage or authorization.",
        "novelty_claim": False}
    (output / "integration.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": result["status"], "stages": len(observations), "model_calls": 0}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    run(parser.parse_args().output)
