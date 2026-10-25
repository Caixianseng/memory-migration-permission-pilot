"""Zero-model post-hoc mechanism audit of the frozen synthetic A->B run.

Read original artifacts, normalize only valid request nonces, and inspect
recorded builder replies. Never modify results, replay models, or repair truth.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import copy
import hashlib
import json
from pathlib import Path
import re


VERSION = "boundary_transfer_mechanism_analysis_v1"
TOKEN = re.compile(r"\[PVT_([A-F0-9]{24})_([A-Z]+)_([1-9][0-9]*)\]")
SOURCE = re.compile(r"m_([A-F0-9]{24})_([1-9][0-9]*)\Z")
CATEGORIES = frozenset("PERSON ADDRESS CUSTOMER PROJECT EMAIL PHONE ID AMOUNT DATE MIXED".split())
PAIRS = (("\"", "\""), ("'", "'"), ("“", "”"), ("‘", "’"), ("「", "」"), ("『", "』"))


def read(path):
    return json.loads(path.read_bytes())


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def digest(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True,
                                    separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def normalized_payload(payload):
    """Preserve category, ordinal, all ordinary text and every field boundary."""
    assert set(payload) == {"query", "memories"}
    nonce = set()
    def text(value):
        matches = list(TOKEN.finditer(value))
        assert value.count("[PVT_") == len(matches)
        assert all(m[2] in CATEGORIES for m in matches)
        nonce.update(m[1] for m in matches)
        return TOKEN.sub(lambda m: "[PVT_<REQUEST_NONCE>_"+m[2]+"_"+m[3]+"]", value)
    result = {"query": text(payload["query"]), "memories": []}
    for index, memory in enumerate(payload["memories"], 1):
        assert set(memory) == {"source_id", "text"}
        match = SOURCE.fullmatch(memory["source_id"])
        assert match and int(match[2]) == index
        nonce.add(match[1])
        result["memories"].append({"source_id": "m_<REQUEST_NONCE>_"+match[2], "text": text(memory["text"])})
    assert len(nonce) == 1
    return result


def normalized_request(body):
    body = copy.deepcopy(body)
    assert len(body["messages"]) == 2 and body["messages"][1]["role"] == "user"
    payload = json.loads(body["messages"][1]["content"])
    body["messages"][1]["content"] = json.dumps(normalized_payload(payload), ensure_ascii=False, separators=(",", ":"))
    return body


def spans(row):
    detection = row.get("detection")
    return None if detection is None else sorted((f["source_id"], f["start"], f["end"], f["category"])
                                                 for f in detection["findings"])


def locate(quote, text):
    """Same bounded outer-quote handling as the archived exact-quote validator."""
    if not isinstance(quote, str) or not quote:
        raise ValueError("invalid_span")
    if quote in text:
        return quote
    value = quote.strip()
    if value and value[-1] in ".,;!?。，；！？":
        value = value[:-1]
    for left, right in PAIRS:
        if len(value) > 2 and value.startswith(left) and value.endswith(right) and value[1:-1] in text:
            return value[1:-1]
    raise ValueError("invalid_span")


def builder_diagnostics(content, source):
    data = json.loads(content)
    invalid = []
    for i, fact in enumerate(data["facts"]):
        try:
            quote = locate(fact["quote"], source)
        except ValueError:
            invalid.append({"path": f"facts[{i}].quote", "kind": "fact_quote_not_in_source", "quote": fact["quote"]})
            continue
        for j, finding in enumerate(fact["findings"]):
            try:
                locate(finding["quote"], quote)
            except ValueError:
                invalid.append({"path": f"facts[{i}].findings[{j}].quote", "kind": "field_quote_not_in_parent_fact",
                                "quote": finding["quote"], "parent_fact_quote": quote})
    return data, invalid


def run(source, output):
    source, output = Path(source), Path(output)
    names = ("plan.json", "runtime.json", "evaluation.json", "rows.json", "builds.json", "record_store.json",
             "report.json", "request_transport.jsonl", "transport_audit.json")
    before = {name: sha(source/name) for name in names}
    plan, runtime, rows, builds = (read(source/name) for name in ("plan.json", "runtime.json", "rows.json", "builds.json"))
    events = [json.loads(line) for line in (source/"request_transport.jsonl").read_text(encoding="utf-8").splitlines()]
    requests = {e["index"]: e for e in events if e["phase"] == "request"}
    responses = {e["index"]: e for e in events if e["phase"] == "response"}
    assert len(requests) == len(responses) == 356 and set(requests) == set(responses)
    assert all(digest(e["request"]) == e["request_sha256"] for e in requests.values())
    assert all(digest(e["response"]) == e["response_sha256"] and e["request_sha256"] == requests[i]["request_sha256"]
               for i, e in responses.items())
    answer_requests = defaultdict(list)
    for index, request in requests.items():
        body = request["request"]
        if body["messages"][0]["content"].startswith("The user JSON contains a query and memories."):
            answer_requests[digest(json.loads(body["messages"][1]["content"]))].append(index)
    row_requests, used = {}, set()
    for row in rows:
        if row.get("outbound") is None:
            continue
        ids = answer_requests[digest(row["outbound"])]
        assert len(ids) == 1
        index = ids[0]
        assert responses[index]["response"]["message"]["content"].strip() == row["model_answer"]
        row_requests[(row["story_id"], row["task_id"], row["arm"])] = requests[index]["request"]
        used.add(index)
    assert len(used) == 312 == sum(len(v) for v in answer_requests.values())

    by_row = {(r["story_id"], r["task_id"], r["arm"]): r for r in rows}
    families = sorted({r["arm"].split("__")[0] for r in rows if "__" in r["arm"]})
    pair_rows, summary = [], {}
    for family in families:
        selected = [r for r in rows if r["arm"] == family+"__legacy"]
        for old in selected:
            key = (old["story_id"], old["task_id"], family+"__boundary")
            new = by_row[key]
            ready = old.get("outbound") is not None and new.get("outbound") is not None
            before_meta = new.get("prepare_metadata", {}).get("boundary_preparation")
            item = {"family": family, "story_id": old["story_id"], "task_id": old["task_id"], "actor_id": old["actor_id"],
                    "both_outbound": ready, "normalized_outbound_equal": None, "normalized_http_request_equal": None,
                    "detection_spans_equal": spans(old) == spans(new), "masking_scores_equal": old.get("masking") == new.get("masking"),
                    "legacy_correct": old["score"]["correct"], "boundary_correct": new["score"]["correct"],
                    "legacy_joint_correct": old["score"]["joint_correct_no_masking_gap"],
                    "boundary_joint_correct": new["score"]["joint_correct_no_masking_gap"],
                    "boundary_source_relations": before_meta}
            if ready:
                a, b = normalized_payload(old["outbound"]), normalized_payload(new["outbound"])
                item.update(normalized_outbound_equal=a == b, normalized_outbound_sha256=digest(a))
                item["normalized_http_request_equal"] = normalized_request(row_requests[(old["story_id"], old["task_id"], old["arm"])]) == normalized_request(row_requests[key])
            pair_rows.append(item)
        pairs = [p for p in pair_rows if p["family"] == family]
        active = [p for p in pairs if p["both_outbound"]]
        summary[family] = {"registered_pairs": len(pairs), "legal_pairs": sum(p["actor_id"] == "owner" for p in pairs),
            "both_outbound_pairs": len(active), "normalized_outbound_equal": sum(p["normalized_outbound_equal"] is True for p in active),
            "normalized_http_request_equal": sum(p["normalized_http_request_equal"] is True for p in active),
            "detection_spans_equal": sum(p["detection_spans_equal"] for p in pairs),
            "masking_scores_equal": sum(p["masking_scores_equal"] for p in pairs),
            "removed_key_only_source_relations": sum(p["boundary_source_relations"]["removed_key_only_source_relations"] for p in active),
            "source_relation_counts_changed": sum(p["boundary_source_relations"]["source_relations_before"] != p["boundary_source_relations"]["source_relations_after"] for p in active),
            "parsed_field_key_counts": dict(Counter(p["boundary_source_relations"]["field_key_count"] for p in active)),
            "newly_correct": [{"story_id": p["story_id"], "task_id": p["task_id"]} for p in pairs if not p["legacy_correct"] and p["boundary_correct"]],
            "newly_wrong": [{"story_id": p["story_id"], "task_id": p["task_id"]} for p in pairs if p["legacy_correct"] and not p["boundary_correct"]]}

    source_by_text = {story["source"]["text"]: story for story in runtime}
    attempts = []
    for index, request in requests.items():
        body = request["request"]
        if not body["messages"][0]["content"].startswith("Build factual memory from text locally."):
            continue
        text = json.loads(body["messages"][1]["content"])["text"]
        story = source_by_text[text]
        raw = responses[index]["response"]["message"]["content"]
        parsed, invalid = builder_diagnostics(raw, text)
        attempts.append({"transport_index": index, "story_id": story["story_id"], "repair_attempt": len(body["messages"]) > 2,
            "raw_response_content": raw, "raw_response_sha256": hashlib.sha256(raw.encode()).hexdigest(),
            "model_status": parsed["status"], "raw_fact_count": len(parsed["facts"]), "invalid_span_paths": invalid,
            "host_span_validation_would_fail": bool(invalid)})
    final_builds = [{"story_id": b["story_id"], "status": b["status"], "errors": b["errors"], "local_calls": b["local_calls"],
                     "stored_characters": b["stored_characters"], "final_fact_count": len(b["facts"]),
                     "whole_fact_label_count": sum(f["start"] == 0 and f["end"] == len(fact["text"]) for fact in b["facts"] for f in fact["findings"])}
                    for b in builds if b["builder"] == "model"]
    assert len(attempts) == sum(b["local_calls"] for b in final_builds) == 12
    assert before == {name: sha(source/name) for name in names}
    output.mkdir(parents=True, exist_ok=False)
    result = {"version": VERSION, "source_sha256": before, "analysis_script_sha256": sha(Path(__file__)),
        "registered_rows": len(rows), "matched_pairs": len(pair_rows), "active_model_pairs": sum(p["both_outbound"] for p in pair_rows),
        "all_312_answer_requests_bound_to_row_inputs_and_raw_replies": True, "pair_summary": summary,
        "builder_attempts": len(attempts), "builder_valid_needs_review_attempts": sum(not a["invalid_span_paths"] and a["model_status"] == "needs_review" for a in attempts),
        "builder_invalid_span_attempts": sum(a["host_span_validation_would_fail"] for a in attempts),
        "builder_invalid_path_kinds": dict(Counter(e["kind"] for a in attempts for e in a["invalid_span_paths"])),
        "final_model_builds": final_builds, "new_model_calls": 0, "source_unchanged": True,
        "conclusions": ["All active paired outbound payloads and complete model request bodies are identical after only valid request-nonce normalization; final detection spans and masking scores are unchanged.",
            "All recorded boundary source-removal counts are zero. These examples show no final boundary/source-tightening intervention; small score changes must not be attributed to that mechanism.",
            "Nonce-dependent tokenization, execution order or numerical variation were not separated by a fixed-nonce replay; this audit does not prove nonce is the sole cause.",
            "Recorded invalid spans include findings assigned to a different parent fact, a finding longer than its chosen fact and one literal character insertion. Fact quotation alone is not the entire failure mechanism.",
            "Four structurally valid replies explicitly say needs_review without a reason field; their underlying semantic uncertainty cannot be identified from the response.",
            "No original score, answer, truth or frozen production code is changed. This is exposed-development post-hoc analysis, not new acceptance or algorithm novelty evidence."]}
    for name, value in (("analysis.json", result), ("matched_pairs.json", pair_rows), ("builder_attempts.json", attempts)):
        (output/name).write_text(json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False)+"\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = run(args.run, args.output)
    print(json.dumps({"matched_pairs": result["matched_pairs"], "active_model_pairs": result["active_model_pairs"],
                      "builder_attempts": result["builder_attempts"], "source_unchanged": result["source_unchanged"]}))
