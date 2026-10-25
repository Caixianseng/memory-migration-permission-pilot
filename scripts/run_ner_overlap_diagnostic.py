"""Source-only development probe of confidence-flat versus overlap coverage.

Two real encoder API calls per story; a longest-span view is derived without
another model call. No generation, permissions or task-answer claims are made.
The complete fixed source set is processed before reading scoring material.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from memory_migration_study.ner_detector import CjkAwareSplitter, LABELS, LocalNerRuntime

VERSION = "source_ner_overlap_development_v1"
THRESHOLD = 0.5


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2)+"\n", encoding="utf-8")


def positions(text, output):
    if not isinstance(output, dict) or set(output) != {"entities"}:
        raise ValueError("invalid_encoder_output")
    spans = []
    for label, entities in output["entities"].items():
        for item in entities:
            start, end = item["start"], item["end"]
            if (type(start) is not int or type(end) is not int or not 0 <= start < end <= len(text)
                    or text[start:end] != item["text"] or not THRESHOLD <= item["confidence"] <= 1):
                raise ValueError("invalid_encoder_span")
            spans.append({"start": start, "end": end, "label": label,
                          "quote": item["text"], "confidence": item["confidence"]})
    return spans


def longest(spans):
    # No new span or category is invented; discard strict contained duplicates.
    return [s for s in spans if not any(o["label"] == s["label"]
        and o["start"] <= s["start"] < s["end"] <= o["end"]
        and (o["start"], o["end"]) != (s["start"], s["end"]) for o in spans)]


def run(output):
    output.mkdir(parents=True, exist_ok=False)
    corpus = ROOT/"examples/privacy_semantics_v1/development"
    runtime_bytes = (corpus/"runtime.json").read_bytes()
    evaluation_bytes = (corpus/"evaluation.json").read_bytes()
    runtime = json.loads(runtime_bytes)
    if len(runtime) != 8:
        raise ValueError("registered_eight_story_development_required")
    frozen = {str(p.relative_to(ROOT)): sha(p.read_bytes()) for p in
        (Path(__file__), ROOT/"memory_migration_study/ner_detector.py")}
    save(output/"plan.json", {"version": VERSION, "source_stories": 8, "encoder_call_cap": 16,
        "threshold": THRESHOLD, "splitter": "cjk_aware", "conditions": ["default_flat", "allow", "allow_longest_view"],
        "runtime_sha256": sha(runtime_bytes), "evaluation_sha256": sha(evaluation_bytes),
        "implementation_sha256": frozen, "scoring": "after_all_encoder_calls",
        "scope": "Exposed synthetic source-only development; not end-to-end privacy, authorized utility or novelty."})
    encoder = LocalNerRuntime(ROOT/".runtime/github_ner")
    save(output/"runtime_identity.json", encoder.identity)
    rows, calls = [], 0
    for story in runtime:
        text = story["source"]["text"]
        labels = {LABELS[c][0]: LABELS[c][1] for c in story["policy"]["protected_categories"]}
        started = time.monotonic()
        calls += 1
        default = encoder.infer(text, labels, splitter="cjk_aware", threshold=THRESHOLD)
        default_seconds = time.monotonic()-started
        with encoder.lock:
            encoder.model.processor.word_splitter = CjkAwareSplitter()
            schema = encoder.model.create_schema().entities(labels)
            transformed = encoder.model.processor.transform_record(text, schema, max_len=None)
            if len(transformed.input_ids) > 512:
                raise ValueError("input_budget_exceeded")
            started = time.monotonic()
            calls += 1
            allowed = encoder.model.extract_entities(text, labels, threshold=THRESHOLD,
                include_confidence=True, include_spans=True, overlap_policy="allow")
            allow_seconds = time.monotonic()-started
        d, a = positions(text, default), positions(text, allowed)
        rows.append({"story_id": story["story_id"], "source_sha256": sha(text.encode()),
            "source_id": story["source"]["source_id"], "text": text,
            "conditions": {"default_flat": d, "allow": a, "allow_longest_view": longest(deepcopy(a))},
            "encoder_calls": 2, "seconds": {"default_flat": default_seconds, "allow": allow_seconds},
            "raw": {"default_flat": default, "allow": allowed}})
        save(output/"rows.json", rows)
    if calls != 16:
        raise ValueError("encoder_call_accounting")
    # No model operations below this point; scoring data was not parsed above.
    evaluation = json.loads(evaluation_bytes)
    totals = {name: {"source_spans": 0, "fully_covered": 0, "partially_covered": 0,
                    "uncovered": 0, "extra_covered_characters": 0, "candidate_spans": 0}
              for name in ("default_flat", "allow", "allow_longest_view")}
    for row in rows:
        truth = evaluation[row["story_id"]]["sensitive_spans"]
        protected = set().union(*(set(range(s["start"], s["end"])) for s in truth)) if truth else set()
        row["coverage"] = {}
        for name, spans in row["conditions"].items():
            covered = set().union(*(set(range(s["start"], s["end"])) for s in spans)) if spans else set()
            full = sum(set(range(s["start"], s["end"])) <= covered for s in truth)
            partial = sum(bool(set(range(s["start"], s["end"])) & covered)
                          and not set(range(s["start"], s["end"])) <= covered for s in truth)
            stats = {"source_spans": len(truth), "fully_covered": full, "partially_covered": partial,
                "uncovered": len(truth)-full-partial, "extra_covered_characters": len(covered-protected),
                "candidate_spans": len(spans)}
            row["coverage"][name] = stats
            for key, value in stats.items():
                totals[name][key] += value
    if frozen != {name: sha((ROOT/name).read_bytes()) for name in frozen}:
        raise ValueError("implementation_changed_during_probe")
    report = {"version": VERSION, "rows": len(rows), "actual_encoder_api_calls": calls,
        "generation_calls": 0, "cloud_calls": 0, "new_api_cost_cny": 0,
        "totals": totals, "scoring_after_model_phase": True,
        "limits": ["Coverage unions are a proposal diagnostic, not sensitive-label precision or final egress.",
                   "All eight sources are exposed development data; the longest view uses the same encoder output."]}
    save(output/"rows.json", rows)
    save(output/"report.json", report)
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    target = args.output.resolve()
    if target.exists() or not target.is_relative_to(ROOT/"results"):
        raise ValueError("new_project_result_required")
    network = {"connections_blocked": 0}
    def no_network(event, values):
        if event == "socket.connect":
            network["connections_blocked"] += 1
            raise RuntimeError("all_network_disabled")
    sys.addaudithook(no_network)
    try:
        print(json.dumps(run(target), ensure_ascii=False), flush=True)
    finally:
        if target.exists():
            save(target/"network_audit.json", network)
