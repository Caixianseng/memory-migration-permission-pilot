"""Independently align unchanged literals to audit actual masked payloads.

No recovery map, detector spans, production scorer, model, or signing key is
used. Ambiguous coverage is an explicit verification failure, not a guessed
alignment. This verifies registered character exposure, not semantic privacy.
"""
from __future__ import annotations
import argparse
from functools import lru_cache
import hashlib
import json
from pathlib import Path
import re

TOKEN = re.compile(r"\[PVT_[A-F0-9]{24}_(?:PERSON|ADDRESS|CUSTOMER|PROJECT|EMAIL|PHONE|ID|AMOUNT|DATE|MIXED)_[1-9][0-9]*\]")
HINT_SEPARATOR = ".\nMasked question / 脱敏问题: "
HINT_PREFIXES = frozenset("Requested answer field / 请求字段: " + description + HINT_SEPARATOR
    for description in (
        "email address / 电子邮箱地址", "telephone number / 联系电话号码",
        "identity-document number / 身份证件或护照号码", "person's name / 人员姓名",
        "postal or street address / 邮寄或街道地址", "customer organization's complete name / 客户组织的完整名称",
        "project name or identifier / 项目名称或标识", "monetary amount including currency / 包含币种的金额",
        "calendar or business date / 日历日期或业务日期", "business or processing status / 业务或处理状态"))


def coverage_from_literals(original, masked):
    """All valid nonempty token expansions must give the same covered offsets."""
    if not isinstance(original, str) or not isinstance(masked, str) or len(original) > 6000:
        raise ValueError("invalid_alignment_input")
    literals = TOKEN.split(masked)
    token_count = len(literals)-1
    if token_count == 0:
        if original != masked:
            raise ValueError("unexplained_plaintext_change")
        return frozenset()
    if token_count > 32 or not original.startswith(literals[0]):
        raise ValueError("invalid_alignment_layout")
    work = 0

    @lru_cache(None)
    def walk(index, cursor):
        nonlocal work
        work += 1
        if work > 10000:
            raise ValueError("alignment_budget_exceeded")
        literal = literals[index+1]
        last = index == token_count-1
        if last:
            positions = [len(original)-len(literal)] if original.endswith(literal) else []
        elif literal:
            positions = []
            start = original.find(literal, cursor+1)
            while start >= 0:
                positions.append(start)
                start = original.find(literal, start+1)
        else:
            positions = range(cursor+1, len(original)+1)
        solutions = set()
        for position in positions:
            if position <= cursor:
                continue
            covered = frozenset(range(cursor, position))
            after = position+len(literal)
            if last:
                if after == len(original):
                    solutions.add(covered)
            else:
                solutions.update(covered | tail for tail in walk(index+1, after))
            if len(solutions) > 64:
                raise ValueError("ambiguous_mask_coverage")
        return frozenset(solutions)

    possible = walk(0, len(literals[0]))
    if len(possible) != 1:
        raise ValueError("ambiguous_mask_coverage" if possible else "no_valid_mask_alignment")
    return next(iter(possible))


def independent_masking(story, task, labels, records, outbound, intent_applied):
    source = story["source"]["text"]
    if len(records) != len(outbound["memories"]):
        raise ValueError("memory_count_changed")
    covered = set()
    retained = set()
    for index, (record, memory) in enumerate(zip(records, outbound["memories"])):
        a, b = record["source_start"], record["source_end"]
        if source[a:b] != record["text"]:
            raise ValueError("source_location_changed")
        retained.update(range(a, b))
        covered.update((index, p) for p in coverage_from_literals(record["text"], memory["text"]))
    query = outbound["query"]
    if intent_applied:
        prefixes = [prefix for prefix in HINT_PREFIXES if query.startswith(prefix)]
        if len(prefixes) != 1:
            raise ValueError("unregistered_query_prefix")
        query = query[len(prefixes[0]):]
    covered.update(("query", p) for p in coverage_from_literals(task["query"], query))
    spans = []
    original_spans = [set(range(item["start"], item["end"])) for item in labels["sensitive_spans"]]
    source_gold = set().union(*original_spans) if original_spans else set()
    for gold in labels["sensitive_spans"]:
        for index, record in enumerate(records):
            a, b = max(gold["start"], record["source_start"]), min(gold["end"], record["source_end"])
            if a < b:
                positions = frozenset((index, p-record["source_start"]) for p in range(a, b))
                spans.append((positions, a != gold["start"] or b != gold["end"]))
        value = source[gold["start"]:gold["end"]]
        for match in re.finditer(re.escape(value), task["query"], re.I):
            item = (frozenset(("query", p) for p in range(match.start(), match.end())), False)
            if item not in spans:
                spans.append(item)
    complete = partial = unmasked = 0
    sensitive = set()
    for positions, truncated in spans:
        sensitive.update(positions)
        if positions <= covered and not truncated:
            complete += 1
        elif positions & covered:
            partial += 1
        else:
            unmasked += 1
    return {"source_sensitive_characters": len(source_gold),
            "retained_sensitive_characters": len(source_gold & retained),
            "missing_extraction_sensitive_characters": len(source_gold-retained), "ready": True,
            "fully_retained_source_spans": sum(p <= retained for p in original_spans),
            "partially_retained_source_spans": sum(bool(p & retained) and not p <= retained for p in original_spans),
            "missing_source_spans": sum(not p & retained for p in original_spans),
            "retained_gold_spans": len(spans), "complete": complete, "partial": partial,
            "unmasked": unmasked, "extra_masked_characters": len(covered-sensitive)}


def verify(directory):
    directory = Path(directory)
    read = lambda name: json.loads((directory/name).read_bytes())
    runtime, evaluation, rows, stores, plan = (read(n) for n in
        ("runtime.json", "evaluation.json", "rows.json", "record_store.json", "plan.json"))
    stories = {s["story_id"]: s for s in runtime}
    record_index = {(s["story_id"], s["builder"]): s["records"] for s in stores}
    checked, failures, counts = 0, [], {}
    for row in rows:
        if row["mode"] == "raw" or row["prepare_status"] != "ok":
            continue
        sid, arm, tid = row["story_id"], row["arm"], row["task_id"]
        story = stories[sid]
        task = next(t for t in story["tasks"] if t["task_id"] == tid)
        try:
            measured = independent_masking(story, task, evaluation[sid],
                record_index[(sid, plan["arms"][arm][0])], row["outbound"], row["intent_applied"])
            if measured != row["masking"]:
                failures.append({"story_id": sid, "task_id": tid, "arm": arm, "error": "masking_measurement_mismatch",
                                 "different_fields": sorted(k for k in measured if measured[k] != row["masking"].get(k))})
                continue
            checked += 1
            cell = counts.setdefault(arm, {"checked_requests": 0, "requests_with_gaps": 0})
            cell["checked_requests"] += 1
            cell["requests_with_gaps"] += bool(measured["partial"] or measured["unmasked"])
        except (ValueError, TypeError, KeyError) as exc:
            failures.append({"story_id": sid, "task_id": tid, "arm": arm, "error": str(exc)})
    expected = sum(r["mode"] != "raw" and r["prepare_status"] == "ok" for r in rows)
    return {"version": "independent_literal_alignment_v2_strict_hint",
            "status": "passed" if checked == expected and not failures and expected > 0 else "failed",
            "expected_ready_masked_requests": expected, "independently_checked_requests": checked,
            "arms": counts, "failures": failures, "no_recovery_map_or_detector_findings_used": True,
            "actual_model_calls": 0,
            "implementation_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "evidence_sha256": {n: hashlib.sha256((directory/n).read_bytes()).hexdigest() for n in
                ("runtime.json", "evaluation.json", "rows.json", "record_store.json", "plan.json")},
            "scope": "Independent literal alignment of actual recorded payloads verifies registered character masking and extraction loss only. Not semantic privacy or authenticated restoration replay."}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    result = verify(args.directory)
    destination = args.directory/"independent_mask_alignment_v2.json"
    if destination.exists():
        raise ValueError("audit_output_exists")
    destination.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False))
    raise SystemExit(0 if result["status"] == "passed" else 1)
