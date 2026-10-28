"""Bounded development probe: source labels versus the same two-detector union.

Only source annotation performs new inference. References remain opaque until
every response, signed record, preparation and position footprint is closed.
"""
from __future__ import annotations

from copy import deepcopy
import argparse
import http.client
import json
from pathlib import Path
import secrets
import shutil
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import run_prospective_context_probe as previous
from memory_migration_study.memory_labels import MemoryLabelAuthority, prepare_labeled_transfer
from memory_migration_study.deadline_http import Deadline, DeadlineExceeded, exchange_http
from memory_migration_study.occurrence_qwen import OccurrenceQwenAgent
from memory_migration_study.privacy_payload_eval import masking_intervals
from memory_migration_study.source_annotation import annotate_and_build_records

base, scoring = previous.base, previous.scoring
save, sha, require = base.save, base.sha, base.require
VERSION = "source_annotation_development_probe_v1"
PREREG = "docs/源端上下文标注_开发对照预注册_2026-10-28.md"
OLD = ROOT / "results/prospective_context_20261027_run_01"
PINNED = {
    "predictions.json": "1dd4ab18afff76b0091f1a56f53ee470cf2b4abf3763499c10c3b4eb572a1226",
    "plan.json": "dc333d148dfc1cfb34cd779dcab9c1de102130b06641682c1f8ca557a957239c",
    "prediction_phase_closed.json": "0878349785d3cfbe72df9d83ea567d590888d809f89b899e09c318ad3158e17e",
}
ARMS = ("receiver_only", "source_label_transfer", "receiver_union")
ACTOR, SOURCE_AGENT, TARGET_AGENT = "probe_user", "probe_source", "probe_target"
PRINCIPALS = [{"user_id": ACTOR, "agent_id": TARGET_AGENT}]
LIMITS = {"texts": 24, "rows": 72, "source_generation_posts": 48,
          "source_posts_per_text": 2, "target_generation_posts": 0,
          "wall_seconds": 1800, "cloud_calls": 0, "native_writes": 0,
          "concurrent_requests": 1}


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def frozen_inputs():
    # Check all three trusted roots before parsing a historical prediction.
    require(all(sha(OLD / name) == digest for name, digest in PINNED.items()),
            "historical_roots_changed")
    plan, closed = read_json(OLD / "plan.json"), read_json(OLD / "prediction_phase_closed.json")
    require(closed["plan_sha256"] == PINNED["plan.json"]
            and closed["predictions_sha256"] == PINNED["predictions.json"]
            and closed["reference_parsed"] is False and closed["rows"] == 48,
            "historical_closure_invalid")
    require(sha(OLD / "runtime.json") == plan["runtime_sha256"]
            and sha(OLD / "evaluation.opaque.json") == plan["reference_sha256"],
            "historical_material_changed")
    texts = previous.read_runtime(OLD / "runtime.json")
    predictions = read_json(OLD / "predictions.json")
    require(isinstance(predictions, list) and len(predictions) == 48,
            "historical_prediction_grid_invalid")
    selected = {}
    for row in predictions:
        cell = row.get("cell", {})
        if cell.get("arm") != "conditional":
            continue
        i = cell.get("text_index")
        require(type(i) is int and 0 <= i < 24 and i not in selected
                and cell.get("profile") == base.PROFILE and isinstance(row.get("response"), dict),
                "historical_receiver_invalid")
        # Do not reuse the old preparation, scoring, reference or classification.
        selected[i] = deepcopy(row["response"])
    require(set(selected) == set(range(24)), "historical_receiver_incomplete")
    files = {name: sha(OLD / name) for name in (*PINNED, "runtime.json", "evaluation.opaque.json")}
    return texts, [selected[i] for i in range(24)], deepcopy(plan["policy"]), files


def manifest():
    # Freeze transitive local Python dependencies, including this bounded client.
    paths = list((ROOT / "memory_migration_study").glob("*.py"))
    paths += list((ROOT / "scripts").glob("*.py"))
    paths += [ROOT / "tests/test_source_annotation_probe.py", ROOT / PREREG]
    return {p.relative_to(ROOT).as_posix(): sha(p) for p in sorted(paths)}


def freeze(output):
    require(output.is_relative_to(ROOT / "results") and not output.exists(), "output_scope_or_exists")
    texts, receivers, policy, inputs = frozen_inputs()
    sources = manifest()
    output.mkdir(parents=True)
    for name in sources:
        destination = output / "implementation" / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, destination)
    for name in inputs:
        destination = output / "historical" / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(OLD / name, destination)
    save(output / "receiver_responses.json", receivers)
    save(output / "plan.json", {
        "version": VERSION, "limits": LIMITS, "options": base.OPTIONS,
        "model": base.MODEL, "digest": base.DIGEST, "ollama": base.OLLAMA_VERSION,
        "inputs": inputs, "sources": sources, "policy": policy,
        "receiver_responses_sha256": sha(output / "receiver_responses.json"),
        "reference_parsed": False, "arms": list(ARMS), "principals": PRINCIPALS,
        "source_agent": SOURCE_AGENT, "target_agent": TARGET_AGENT,
        "memory_method": "one exact full-source copy per text; not model-generated summary",
        "scope": "24 already exposed development texts; not independent 64-case acceptance; no downstream task/refusal metric",
        "comparison": "source labels and receiver union use identical observations; extra detection is not migration novelty",
        "stop_rule": "at most two source posts per text, 48 total; no added retries or tuning batch",
    })
    return {"status": "frozen", "plan_sha256": sha(output / "plan.json"), "new_model_calls": 0}


def verify(output, expected):
    require(isinstance(expected, str) and sha(output / "plan.json") == expected, "plan_changed")
    plan = read_json(output / "plan.json")
    texts, receivers, policy, inputs = frozen_inputs()
    require(plan["version"] == VERSION and plan["sources"] == manifest()
            and plan["inputs"] == inputs and plan["policy"] == policy
            and plan["limits"] == LIMITS and plan["options"] == base.OPTIONS
            and plan["arms"] == list(ARMS) and plan["principals"] == PRINCIPALS
            and plan["model"] == base.MODEL and plan["digest"] == base.DIGEST
            and plan["ollama"] == base.OLLAMA_VERSION, "frozen_contract_changed")
    for name, digest in plan["sources"].items():
        require(sha(output / "implementation" / name) == digest, "archive_changed")
    for name, digest in inputs.items():
        require(sha(output / "historical" / name) == digest, "copied_material_changed")
    require(sha(output / "receiver_responses.json") == plan["receiver_responses_sha256"]
            and read_json(output / "receiver_responses.json") == receivers, "receiver_response_changed")
    return plan, texts, receivers


class BoundedClient(previous.BoundedClient):
    """Reuse the captured fixed-loopback client; also enforce each text's bound."""

    def __init__(self, output, *, exchange=None):
        super().__init__(output, exchange=exchange)
        self.deadline = Deadline(self.started + LIMITS["wall_seconds"], clock=lambda: time.monotonic())
        self.active_text = None
        self.per_text_posts = {}

    def _exchange(self, method, path, body):
        event = self.events[-1]
        encoded = json.dumps(body, ensure_ascii=False).encode("utf-8") if body is not None else None
        raw = exchange_http(method, path, encoded, host="127.0.0.1", port=11435,
            deadline=self.deadline, event=event, connection_factory=http.client.HTTPConnection)
        require(event["http_status"] == 200 and len(raw) <= 1048576, "local_http_failure")
        return raw.decode("utf-8")

    def begin_text(self, index):
        require(type(index) is int and 0 <= index < 24 and index not in self.per_text_posts,
                "source_text_repeated_or_invalid")
        self.active_text = index
        self.per_text_posts[index] = 0

    def __call__(self, method, path, body=None):
        self.deadline.check()
        if method == "POST":
            require(self.active_text is not None
                    and self.per_text_posts[self.active_text] < LIMITS["source_posts_per_text"]
                    and self.posts < LIMITS["source_generation_posts"], "source_generation_budget")
            self.per_text_posts[self.active_text] += 1
        # Keep the inherited route, identity, count and capture contract while
        # checking injected exchanges as well as physical HTTP before return.
        def checked_exchange(method, path, body):
            raw = exchange(method, path, body)
            self.events[-1]["raw_response"] = raw
            self.deadline.check()
            return raw
        exchange = self.exchange
        self.exchange = checked_exchange
        try:
            result = super().__call__(method, path, body)
            self.deadline.check()
            return result
        finally:
            self.exchange = exchange


def install_network_guard(network):
    def guard(event, args):
        if event == "socket.connect":
            if not isinstance(args[1], tuple) or args[1][:2] != ("127.0.0.1", 11435):
                network["blocked_connects"] += 1
                raise RuntimeError("external_network_forbidden")
            network["loopback_connects"] += 1
    sys.addaudithook(guard)


def exact_findings(text, findings):
    require(isinstance(findings, list), "invalid_exact_findings")
    result = set()
    for item in findings:
        a, b = item.get("start"), item.get("end")
        require(type(a) is int and type(b) is int and 0 <= a < b <= len(text)
                and item.get("category") == "CUSTOMER"
                and item.get("quote", text[a:b]) == text[a:b], "invalid_exact_finding")
        result.add((a, b, "CUSTOMER"))
    return [{"start": a, "end": b, "category": c, "quote": text[a:b]}
            for a, b, c in sorted(result)]


def union_response(text, first, second):
    errors = sorted(set(first.get("errors", []) + second.get("errors", [])))
    ready = first.get("status") == second.get("status") == "ok" and not errors
    return {"status": "ok" if ready else "needs_review",
            "findings": exact_findings(text, first.get("findings", []) + second.get("findings", [])),
            "errors": errors if ready or errors else ["source_or_receiver_requires_review"],
            "local_calls": 0, "local_calls_complete": True, "elapsed_seconds": 0.0}


def blocked_preparation(error):
    return {"status": "blocked", "error": error, "payload": None,
            "actual_mask_intervals": [], "acl_negative_controls": [], "new_target_posts": 0}


def prepare_record(text, record, policy, response, *, authority, mode, request_id):
    """Exercise real labels after JSON roundtrip; export only safe evidence."""
    records = json.loads(json.dumps([record], ensure_ascii=False, allow_nan=False))
    replay = scoring.ReplayDetector(text, records[0]["record_id"], policy, response)
    kwargs = {"authority": authority, "actor_id": ACTOR, "agent_id": TARGET_AGENT,
              "request_id": request_id, "mode": mode, "agent": replay}
    prepared = prepare_labeled_transfer(records, "", policy, **kwargs)
    require(prepared.get("local_calls", 0) == 0, "target_inference_forbidden")
    controls, intervals = [], []
    if prepared["status"] == "ok":
        raw = text
        masked = prepared["payload"]["memories"][0]["text"]
        intervals = [list(pair) for pair in masking_intervals(raw, masked, prepared["mapping"]._entries)]
        for user, agent in (("probe_wrong_user", TARGET_AGENT), (ACTOR, "probe_wrong_agent")):
            denied = prepare_labeled_transfer(records, "", policy,
                **{**kwargs, "actor_id": user, "agent_id": agent})
            require(denied["status"] == "blocked" and denied.get("payload") is None
                    and denied.get("error") == "principal_not_authorized", "acl_negative_control_failed")
            controls.append({"actor_id": user, "agent_id": agent, "status": "rejected",
                             "error": denied["error"], "payload_is_none": True})
    # No mapping, private entries, authority key or restoration capability escapes.
    return {"status": prepared["status"], "error": prepared.get("error"),
            "payload": deepcopy(prepared.get("payload")), "metadata": deepcopy(prepared.get("metadata", {})),
            "checks": deepcopy(prepared.get("checks", [])), "detection": deepcopy(prepared.get("detection")),
            "replay_binding": deepcopy(replay.binding), "actual_mask_intervals": intervals,
            "acl_negative_controls": controls, "new_target_posts": 0}


def observe_case(index, text, policy, receiver, *, agent, authority):
    source = {"source_id": "source_%02d" % index, "text": text}
    facts = [{"text": text, "source_start": 0, "source_end": len(text), "findings": []}]
    trusted = {"authority": authority, "owner_id": ACTOR, "agent_id": SOURCE_AGENT,
               "allowed_principals": PRINCIPALS, "builder_version": VERSION,
               "detector_version": "occurrence_qwen_source_v1"}
    annotated = annotate_and_build_records(source, facts, policy, agent=agent, **trusted)
    empty = None
    if text.strip():
        empty = authority.build_record(source, facts[0], policy,
            **{key: value for key, value in trusted.items() if key != "authority"})
    rows = []
    source_ok = annotated["status"] == "ok" and len(annotated["records"]) == 1
    for arm in ARMS:
        record, response = empty, deepcopy(receiver)
        mode, error = "migration", None
        if empty is None:
            error = "empty_source"
        elif arm != "receiver_only" and not source_ok:
            error = "source_annotation_requires_review"
        elif arm == "source_label_transfer":
            record, mode = annotated["records"][0], "two_stage"
        elif arm == "receiver_union":
            response = union_response(text, annotated["source_response"], receiver)
        exact = exact_findings(text, response.get("findings", [])) if text else []
        if arm == "source_label_transfer" and source_ok:
            exact = exact_findings(text, exact + record["label"]["findings"])
        preparation = blocked_preparation(error) if error else prepare_record(
            text, record, policy, response, authority=authority, mode=mode,
            request_id="source-probe-%02d-%s" % (index, arm))
        source_response = annotated.get("source_response") or {}
        receiver_uncertain = (receiver.get("status") == "needs_review"
                              and receiver.get("errors") == ["semantic_uncertainty"])
        source_uncertain = (arm != "receiver_only" and annotated["local_calls_complete"] is True
                            and source_response.get("status") == "needs_review"
                            and source_response.get("errors") == ["semantic_uncertainty"])
        reasons = set()
        if preparation["status"] != "ok":
            reasons.update(receiver.get("errors", []))
            reasons.update((preparation.get("detection") or {}).get("errors", []))
            if preparation.get("error"):
                reasons.add(preparation["error"])
            if arm != "receiver_only" and not source_ok:
                reasons.update(annotated["errors"])
                reasons.update(source_response.get("errors", []))
        rows.append({"cell": {"text_index": index, "profile": base.PROFILE, "arm": arm},
                     "status": preparation["status"], "source_status": annotated["status"],
                     "response": response, "record": deepcopy(record) if not error else None,
                     "exact_protective_findings": exact, "preparation": preparation,
                     "semantic_review_evidence": {"receiver": receiver_uncertain, "source": source_uncertain},
                     "block_reasons": sorted(reasons),
                     "baseline_empty_labels": arm != "source_label_transfer",
                     "new_target_posts": 0})
    return annotated, rows


def span_score(text, row, truth, fact):
    ready = row["preparation"]["status"] == "ok"
    predicted = {(f["start"], f["end"], f["category"]) for f in exact_findings(text, row["exact_protective_findings"])}
    gold = scoring._spans(truth["spans"], text, reference=True)
    known = truth["decision"] != "needs_review"
    intervals = row["preparation"]["actual_mask_intervals"]
    require(isinstance(intervals, list) and all(isinstance(v, list) and len(v) == 2
            and all(type(x) is int for x in v) and 0 <= v[0] < v[1] <= len(text) for v in intervals)
            and (ready or not intervals), "invalid_mask_footprint")
    masked = {p for a, b in intervals for p in range(a, b)}
    protected = {p for a, b, _ in gold for p in range(a, b)}
    unprotected_masked = len(masked - protected) if known and ready else 0
    full = partial = absent = 0
    for a, b, _ in gold:
        hit = len(masked.intersection(range(a, b)))
        full += int(ready and hit == b-a)
        partial += int(ready and 0 < hit < b-a)
        absent += int(ready and hit == 0)
    retained = ready and not masked.intersection(range(fact["start"], fact["end"]))
    semantic_review = not ready and any(row["semantic_review_evidence"].values())
    return {"total": 1, "known": int(known), "unknown": int(not known),
            "prepared": int(ready), "known_prepared": int(known and ready), "blocked": int(not ready),
            "known_exact": int(known and ready and predicted == gold),
            "unknown_blocked": int(not known and not ready),
            "semantic_unknown_review": int(not known and semantic_review),
            "unknown_blocked_without_semantic_uncertainty": int(not known and not ready and not semantic_review),
            "unknown_prepared": int(not known and ready),
            "raw_predicted_protective_tp": len(predicted & gold) if known else 0,
            "raw_predicted_protective_fp": len(predicted - gold) if known else 0,
            "raw_predicted_protective_fn": len(gold - predicted) if known else 0,
            "reference_spans": len(gold), "fully_masked_spans": full,
            "partially_masked_spans": partial, "unmasked_spans": absent,
            "prepared_incomplete_spans": partial + absent,
            "actual_masked_unprotected_chars": unprotected_masked,
            "known_prepared_with_unprotected_masking": int(unprotected_masked > 0),
            "blocked_reference_spans": len(gold) if not ready else 0,
            "allowed_fact_retained": int(retained), "allowed_fact_total": 1}


def comparison_signature(row):
    # Random record IDs and token names are not algorithmic differences.
    return {"status": row["status"], "error": row["preparation"]["error"],
            "findings": row["exact_protective_findings"],
            "footprint": row["preparation"]["actual_mask_intervals"]}


def score_rows(rows, reference, texts):
    expected = {(i, arm) for i in range(24) for arm in ARMS}
    require(len(texts) == 24 and len(rows) == 72 and
            {(r["cell"]["text_index"], r["cell"]["arm"]) for r in rows} == expected,
            "prediction_grid_incomplete")
    refs = scoring._validate_reference(reference, texts)
    groups, scored, paired = {}, [], {}
    for row in deepcopy(rows):
        i, arm = row["cell"]["text_index"], row["cell"]["arm"]
        values = span_score(texts[i], row, refs[i]["expected"][base.PROFILE], refs[i]["allowed_fact"])
        row["score"] = values
        scored.append(row)
        group = groups.setdefault(arm, {**dict.fromkeys(values, 0), "statuses": {}, "block_reasons": {}})
        for key, value in values.items():
            group[key] += value
        group["statuses"][row["status"]] = group["statuses"].get(row["status"], 0) + 1
        for reason in row["block_reasons"]:
            group["block_reasons"][reason] = group["block_reasons"].get(reason, 0) + 1
        paired[(i, arm)] = row
    for group in groups.values():
        tp, fp, fn = (group["raw_predicted_protective_" + key] for key in ("tp", "fp", "fn"))
        group["raw_predicted_protective_precision"] = tp / (tp + fp) if tp + fp else None
        group["raw_predicted_protective_recall"] = tp / (tp + fn) if tp + fn else None
    differences = [i for i in range(24) if comparison_signature(paired[(i, ARMS[1])]) != comparison_signature(paired[(i, ARMS[2])])]
    a, b = groups[ARMS[0]], groups[ARMS[1]]
    gate = (b["known_prepared"] >= a["known_prepared"] and b["semantic_unknown_review"] == b["unknown"]
            and b["prepared_incomplete_spans"] == 0)
    return {"rows": scored, "by_arm": groups, "development_gate_passed": gate,
            "metric_definitions": {"raw_predicted_protective_tp_fp_fn": "Raw original protective positions, including blocked rows; not actual emitted protection.",
                "semantic_unknown_review": "Blocked reference-unknown case with an original detector response explicitly reporting semantic_uncertainty.",
                "unknown_blocked": "Any blocked reference-unknown case, including engineering or format failures; not semantic correctness.",
                "actual_masked_unprotected_chars": "Known prepared cases only: actual masked character positions outside the reference sensitive-position union, including same-word expansion.",
                "masking": "Actual original-position footprints from ephemeral restoration entries; blocked rows have no emitted payload."},
            "union_comparison": {"equivalent": not differences, "different_text_indices": differences,
                                 "comparison": "exact findings, readiness and actual position footprints"},
            "case22": {arm: paired[(22, arm)] for arm in ARMS}}


def close_prediction_phase(output, expected, rows, annotations, client, network):
    client.deadline.check()
    require(len(rows) == 72 and len(annotations) == 24, "prediction_grid_incomplete")
    require(client.closed and network["blocked_connects"] == 0, "prediction_phase_not_closed")
    save(output / "predictions.json", rows)
    save(output / "source_annotations.json", annotations)
    captures = {p.name: sha(p) for p in sorted(output.glob("transport_*.json"))}
    closure = {"plan_sha256": expected, "reference_parsed": False, "rows": len(rows),
               "source_generation_posts": client.posts, "new_target_posts": 0,
               "per_text_posts": client.per_text_posts, "network": deepcopy(network),
               "capture_sha256": captures, "predictions_sha256": sha(output / "predictions.json"),
               "source_annotations_sha256": sha(output / "source_annotations.json")}
    client.deadline.check()
    save(output / "prediction_phase_closed.json", closure)
    return closure


def load_closed_reference(output, expected):
    # This is the only reference parse in the driver, including mocked runs.
    closure = read_json(output / "prediction_phase_closed.json")
    require(closure["plan_sha256"] == expected and closure["reference_parsed"] is False
            and closure["rows"] == 72, "prediction_closure_invalid")
    for name, key in (("predictions.json", "predictions_sha256"),
                      ("source_annotations.json", "source_annotations_sha256")):
        require(sha(output / name) == closure[key], "closed_prediction_changed")
    require(all(sha(output / name) == digest for name, digest in closure["capture_sha256"].items()),
            "closed_capture_changed")
    return read_json(output / "historical/evaluation.opaque.json")


def execute(output, expected):
    plan, texts, receivers = verify(output, expected)
    save(output / "execution_started.json", {"plan_sha256": expected, "reference_parsed": False})
    client = BoundedClient(output)
    network = {"loopback_connects": 0, "blocked_connects": 0}
    install_network_guard(network)
    rows, annotations = [], []
    state = {"status": "started", "reference_parsed": False}
    authority = MemoryLabelAuthority(secrets.token_bytes(32))
    agent = OccurrenceQwenAgent(transport=client)
    try:
        # Health failures are left to the source adapter and remain in denominators.
        for i, text in enumerate(texts):
            require(time.monotonic() - client.started < LIMITS["wall_seconds"], "wall_budget_exceeded")
            verify(output, expected)
            client.begin_text(i)
            before = client.posts
            annotation, case_rows = observe_case(i, text, plan["policy"], receivers[i], agent=agent, authority=authority)
            # The adapter can convert transport failure into an incomplete
            # observation; report an expired deadline before checking its counts.
            client.deadline.check()
            require(annotation["local_calls_complete"] is True and
                    annotation["local_calls"] == client.posts-before <= 2, "source_cost_accounting")
            annotations.append(annotation)
            rows.extend(case_rows)
            save(output / ("source_%02d.json" % i), annotation)
            for row in case_rows:
                save(output / ("row_%02d_%s.json" % (i, row["cell"]["arm"])), row)
            print(json.dumps({"texts_completed": i+1, "rows": len(rows), "source_posts": client.posts}), flush=True)
        client.closed = True
        verify(output, expected)
        client.deadline.check()
        closure = close_prediction_phase(output, expected, rows, annotations, client, network)
        client.deadline.check()
        reference = load_closed_reference(output, expected)
        state["reference_parsed"] = True
        results = score_rows(rows, reference, texts)
        require(all(g["known"] == 20 and g["unknown"] == 4 for g in results["by_arm"].values()),
                "registered_reference_inventory_changed")
        save(output / "scored_rows.json", results["rows"])
        verify(output, expected)
        report = {key: value for key, value in results.items() if key != "rows"}
        report.update(version=VERSION, status="complete", source_generation_posts=client.posts,
                      source_elapsed_seconds=sum(a["agent_elapsed_seconds"] for a in annotations),
                      new_target_posts=0, cloud_calls=0, native_writes=0,
                      network=network, unique_development_texts=24, rows=72,
                      source_cost_complete=all(a["local_calls_complete"] for a in annotations),
                      plan_sha256=expected, closure_sha256=sha(output / "prediction_phase_closed.json"),
                      scope=plan["scope"], comparison=plan["comparison"],
                      interpretation="Fixed receiver positives cannot be removed by a protective union; no refusal or independent-acceptance claim.")
        client.deadline.check()
        save(output / "report.json", report)
        try:
            client.deadline.check()
        except DeadlineExceeded:
            (output / "report.json").unlink()
            raise
        state["status"] = "complete"
        return report
    except KeyboardInterrupt as error:
        state.update(status="interrupted", error_type=type(error).__name__, error=str(error))
        raise
    except Exception as error:
        state.update(status="stopped", error_type=type(error).__name__, error=str(error))
        raise
    finally:
        client.closed = True
        state.update(rows=len(rows), source_generation_posts=client.posts, new_target_posts=0,
                     network=network, wall_seconds=time.monotonic()-client.started)
        save(output / "execution_final.json", state)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--expected-plan-sha")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--plan-only", action="store_true")
    mode.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    output = args.output.resolve()
    require(output.is_relative_to(ROOT / "results"), "output_scope")
    result = freeze(output) if args.plan_only else execute(output, args.expected_plan_sha)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
