"""Authored bilingual privacy examples and local-only detector evaluation.

Gold spans are a separate file and are never arguments to the detector.  This
small template-held-out corpus is instrumentation, not a population sample.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import inspect
from pathlib import Path
import time
from typing import Any, Callable


CATEGORIES = ("EMAIL", "PHONE", "ID", "PERSON", "ADDRESS", "CUSTOMER", "PROJECT", "AMOUNT", "DATE")
FAMILIES = (
    ("contact_card", "dev"), ("identity_registry", "dev"),
    ("delivery_label", "dev"), ("customer_handover", "dev"),
    ("funding_memo", "dev"), ("schedule_brief", "dev"),
    ("directory_entry", "dev"), ("policy_pair", "dev"),
    ("contract_narrative", "heldout"), ("visit_narrative", "heldout"),
    ("identity_correction", "heldout"), ("publication_notice", "heldout"),
)


def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True,
                                    separators=(",", ":")).encode("utf-8")).hexdigest()


def _read(path: Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _write(path: Path, value: dict) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    temporary.replace(path)


def _fictional_id(index: int) -> str:
    # A checksum-valid shape with an explicitly fictitious region prefix.
    first = "99000019900101" + f"{index % 1000:03d}"
    checksum = "10X98765432"[sum(int(c) * w for c, w in zip(
        first, (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2))) % 11]
    return first + checksum


def _values(language: str, index: int) -> dict[str, str]:
    if language == "zh":
        return dict(PERSON=("沈星禾", "林沐川", "陈映澜", "周若岚", "许知遥")[index % 5],
                    EMAIL=f"fixture{index}@example.test", PHONE=f"+86-1390000{index:04d}",
                    ID=_fictional_id(index), ADDRESS=f"虚构市青杉路{index}号",
                    CUSTOMER=f"青杉实验社{index}", PROJECT=f"枫叶-{index}",
                    AMOUNT=f"{200 + index},000 USD", DATE=f"2027年6月{index % 27 + 1}日")
    return dict(PERSON=("Mara Linden", "Evan Brook", "Nora Vale", "Iris Reed", "Theo Ash")[index % 5],
                EMAIL=f"fixture{index}@example.test", PHONE=f"+1-202-555-{100 + index % 100:04d}",
                ID=_fictional_id(index), ADDRESS=f"{index} Fictional Cedar Lane",
                CUSTOMER=f"Granite Fern Cooperative {index}", PROJECT=f"Maple-{index}",
                AMOUNT=f"{200 + index},000 USD", DATE=f"June {index % 27 + 1}, 2027")


def _render(family: str, language: str, values: dict) -> tuple[str, list[dict]]:
    """Render authored segments and calculate code-point offsets before labels split."""
    v = lambda name: (values[name], name)
    zh = language == "zh"
    templates = {
        "contact_card": (["姓名：", v("PERSON"), "；邮箱：", v("EMAIL"), "；电话：", v("PHONE"), "。"] if zh else
                         ["Name: ", v("PERSON"), "; Email: ", v("EMAIL"), "; Phone: ", v("PHONE"), "."]),
        "identity_registry": (["登记人：", v("PERSON"), "；身份证号：", v("ID"), "。"] if zh else
                              ["Registered person: ", v("PERSON"), "; Identity number: ", v("ID"), "."]),
        "delivery_label": (["收件人：", v("PERSON"), "；地址：", v("ADDRESS"), "；电话：", v("PHONE"), "。"] if zh else
                           ["Recipient: ", v("PERSON"), "; Address: ", v("ADDRESS"), "; Phone: ", v("PHONE"), "."]),
        "customer_handover": (["客户：", v("CUSTOMER"), "；项目：", v("PROJECT"), "。"] if zh else
                              ["Customer: ", v("CUSTOMER"), "; Project: ", v("PROJECT"), "."]),
        "funding_memo": (["客户：", v("CUSTOMER"), "；预算：", v("AMOUNT"), "。"] if zh else
                         ["Customer: ", v("CUSTOMER"), "; Budget: ", v("AMOUNT"), "."]),
        "schedule_brief": (["项目：", v("PROJECT"), "；会议日期：", v("DATE"), "。"] if zh else
                            ["Project: ", v("PROJECT"), "; Meeting date: ", v("DATE"), "."]),
        "directory_entry": (["目录条目——姓名：", v("PERSON"), "，邮箱：", v("EMAIL"), "，地址：", v("ADDRESS"), "。"] if zh else
                            ["Directory entry — Name: ", v("PERSON"), "; Email: ", v("EMAIL"), "; Address: ", v("ADDRESS"), "."]),
        "policy_pair": (["客户：", v("CUSTOMER"), "；项目：", v("PROJECT"), "；预算：", v("AMOUNT"), "；日期：", v("DATE"), "。"] if zh else
                        ["Customer: ", v("CUSTOMER"), "; Project: ", v("PROJECT"), "; Budget: ", v("AMOUNT"), "; Date: ", v("DATE"), "."]),
        "contract_narrative": (["合同写明", v("PROJECT"), "的客户是", v("CUSTOMER"), "，可使用", v("AMOUNT"), "完成交付。"] if zh else
                               ["For project ", v("PROJECT"), ", the contract names ", v("CUSTOMER"), " as customer and allocates ", v("AMOUNT"), " for delivery."]),
        "visit_narrative": ([v("PERSON"), "将于", v("DATE"), "到访", v("ADDRESS"), "；需要联系时拨打", v("PHONE"), "。"] if zh else
                            [v("PERSON"), " will visit ", v("ADDRESS"), " on ", v("DATE"), "; call ", v("PHONE"), " to coordinate."]),
        "identity_correction": (["请把编号", v("ID"), "对应的登记姓名核对为", v("PERSON"), "，回执应发送至", v("EMAIL"), "。"] if zh else
                                ["The record identified by ", v("ID"), " should name ", v("PERSON"), "; direct the receipt to ", v("EMAIL"), "."]),
        "publication_notice": (["通告提到", v("CUSTOMER"), "在", v("DATE"), "启动", v("PROJECT"), "，计划金额为", v("AMOUNT"), "。"] if zh else
                               ["The notice says ", v("CUSTOMER"), " starts ", v("PROJECT"), " on ", v("DATE"), " with ", v("AMOUNT"), " allocated."]),
    }
    text = ""
    spans = []
    for piece in templates[family]:
        if isinstance(piece, tuple):
            value, category = piece
            spans.append({"start": len(text), "end": len(text) + len(value), "category": category})
            text += value
        else:
            text += piece
    return text, spans


def build_corpus() -> tuple[dict, dict]:
    runtime = {"schema_version": 1, "kind": "synthetic_privacy_detection_runtime",
               "authorship": "programmatically rendered, AI-authored synthetic templates; no human review",
               "identity_note": "Fictional examples; .test emails, fictional ID region 990000. No real records collected.",
               "split_unit": "template_family; paired policies stay in the same story and split",
               "cases": []}
    evaluation = {"schema_version": 1, "kind": "synthetic_privacy_detection_gold",
                  "annotation_method": "authored segment offsets filtered by independently supplied policy categories",
                  "human_review": None, "cases": []}
    for family_index, (family, split) in enumerate(FAMILIES):
        for language in ("zh", "en"):
            for j in range(5):
                # Policy twins deliberately have byte-identical content and different policies.
                value_index = family_index * 10 + (0 if family in {"policy_pair", "publication_notice"} and j == 1 else j) + 100
                values = _values(language, value_index)
                text, spans = _render(family, language, values)
                present = sorted({span["category"] for span in spans})
                protected = present if j in (0, 4) else present[:max(1, len(present) // 2)] if j == 2 else []
                case_id = f"{family}-{language}-{j:02d}"
                source_id = f"memory-{case_id}"
                story_j = 0 if family in {"policy_pair", "publication_notice"} and j == 1 else j
                runtime["cases"].append({"case_id": case_id, "language": language,
                    "story_id": f"{family}-{language}-story-{story_j}", "template_family": family, "split": split,
                    "payload": {"query": "", "memories": [{"source_id": source_id, "text": text}]},
                    "sensitivity_policy": {"version": f"synthetic-policy-v1-{j}", "protected_categories": protected}})
                evaluation["cases"].append({"case_id": case_id, "findings": [dict(source_id=source_id, **span)
                    for span in spans if span["category"] in protected]})
    evaluation["runtime_sha256"] = _digest(runtime)
    validate_corpus(runtime, evaluation)
    return runtime, evaluation


def validate_corpus(runtime: dict, evaluation: dict) -> None:
    cases = runtime["cases"]
    ids = [case["case_id"] for case in cases]
    if len(ids) != len(set(ids)) or not cases:
        raise ValueError("duplicate_or_empty_cases")
    if evaluation.get("runtime_sha256") != _digest(runtime):
        raise ValueError("gold_runtime_hash_mismatch")
    gold_ids = [row["case_id"] for row in evaluation["cases"]]
    if len(gold_ids) != len(set(gold_ids)) or set(gold_ids) != set(ids):
        raise ValueError("gold_case_coverage_mismatch")
    for field in ("template_family", "story_id"):
        memberships: dict[str, set] = {}
        for case in cases:
            memberships.setdefault(case[field], set()).add(case["split"])
        if any(len(splits) != 1 for splits in memberships.values()):
            raise ValueError(f"{field}_crosses_split")
    by_id = {case["case_id"]: case for case in cases}
    for gold in evaluation["cases"]:
        case = by_id[gold["case_id"]]
        texts = {memory["source_id"]: memory["text"] for memory in case["payload"]["memories"]}
        texts["__query__"] = case["payload"]["query"]
        seen = set()
        for span in gold["findings"]:
            key = _span_key(span)
            if key in seen or key[0] not in texts or not (0 <= key[1] < key[2] <= len(texts[key[0]])):
                raise ValueError("invalid_gold_span")
            if key[3] not in case["sensitivity_policy"]["protected_categories"]:
                raise ValueError("gold_outside_policy")
            seen.add(key)


def write_corpus(output_dir: Path) -> dict:
    output_dir = Path(output_dir)
    runtime_path, evaluation_path = output_dir / "runtime.json", output_dir / "evaluation.json"
    if runtime_path.exists() or evaluation_path.exists():
        raise FileExistsError("corpus_destination_already_exists")
    runtime, evaluation = build_corpus()
    _write(runtime_path, runtime)
    _write(evaluation_path, evaluation)
    return {"runtime": str(runtime_path), "evaluation": str(evaluation_path), "case_count": len(runtime["cases"])}


def _span_key(span: dict) -> tuple:
    return span["source_id"], span["start"], span["end"], span["category"]


def _validated_predictions(result: dict, payload: dict) -> tuple[set, list[str]]:
    texts = {memory["source_id"]: memory["text"] for memory in payload["memories"]}
    texts["__query__"] = payload["query"]
    predictions, errors = set(), []
    for finding in result.get("findings", []):
        try:
            source, start, end, category = _span_key(finding)
            if source not in texts or type(start) is not int or type(end) is not int:
                raise ValueError()
            if not 0 <= start < end <= len(texts[source]) or category not in CATEGORIES:
                raise ValueError()
            predictions.add((source, start, end, category))
        except (ValueError, TypeError, KeyError):
            errors.append("invalid_predicted_span")
    return predictions, errors


def _characters(spans: set) -> set:
    return {(source, offset) for source, start, end, _ in spans for offset in range(start, end)}


def _aggregate(rows: list[dict]) -> dict:
    tp, fp, fn = (sum(row[name] for row in rows) for name in ("tp", "fp", "fn"))
    char_tp, char_fp, char_fn = (sum(row[name] for row in rows) for name in ("char_tp", "char_fp", "char_fn"))
    return {"cases": len(rows), "tp": tp, "fp": fp, "fn": fn,
            "precision": tp / (tp + fp) if tp + fp else None,
            "recall": tp / (tp + fn) if tp + fn else None,
            "character_precision": char_tp / (char_tp + char_fp) if char_tp + char_fp else None,
            "character_recall": char_tp / (char_tp + char_fn) if char_tp + char_fn else None,
            "needs_review": sum(row["status"] == "needs_review" for row in rows),
            "needs_review_rate": sum(row["status"] == "needs_review" for row in rows) / len(rows) if rows else None,
            "error_cases": sum(bool(row["errors"]) for row in rows),
            "elapsed_seconds_original_detection": sum(row["elapsed_seconds"] for row in rows),
            "cached_cases": sum(row["cache_hit"] for row in rows)}


def evaluate_corpus(runtime_path: Path, evaluation_path: Path, *, agent: Any = None,
                    modes: tuple[str, ...] = ("rules", "agent", "combined"),
                    cache_path: Path | None = None, detector_provenance: dict | None = None,
                    output_path: Path | None = None, detector: Callable | None = None,
                    progress: Callable | None = None, expected_heldout_cases: int = 40) -> dict:
    """Evaluate locally; gold is held by scorer, never passed into detector/agent.

    Persistent cache stores complete detector outputs (including failures), keyed
    by runtime, policy, detector implementation, mode and caller-supplied model
    and prompt provenance. Agent and combined execute separately unless the
    supplied agent itself provides an explicitly reported response cache.
    """
    from .privacy import detect_sensitive
    if type(expected_heldout_cases) is not int or expected_heldout_cases <= 0:
        raise ValueError("positive_preregistered_heldout_count_required")
    detector = detector or detect_sensitive
    runtime, evaluation = _read(Path(runtime_path)), _read(Path(evaluation_path))
    validate_corpus(runtime, evaluation)
    if not modes or len(set(modes)) != len(modes) or set(modes) - {"rules", "agent", "combined"}:
        raise ValueError("invalid_modes")
    provenance = copy.deepcopy(detector_provenance or {})
    if cache_path and agent is not None and set(modes) & {"agent", "combined"}:
        if not provenance.get("model_digest") or not provenance.get("prompt_sha256"):
            raise ValueError("agent_cache_requires_model_and_prompt_hash")
    implementation = Path(inspect.getsourcefile(detector) or str(Path(__file__).with_name("privacy.py")))
    basis = {"schema_version": 1, "runtime_sha256": _digest(runtime),
             "detector_sha256": hashlib.sha256(implementation.read_bytes()).hexdigest(),
             "detector_source_file": str(implementation.resolve()),
             "evaluator_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
             "local_agent_sha256": hashlib.sha256(implementation.with_name("local_detector.py").read_bytes()).hexdigest()
                 if implementation.with_name("local_detector.py").is_file() else None,
             "provenance": provenance, "agent_available": agent is not None}
    basis_hash = _digest(basis)
    cache = {"schema_version": 1, "basis": basis, "basis_sha256": basis_hash, "entries": {}}
    if cache_path and Path(cache_path).exists():
        cache = _read(Path(cache_path))
        if cache.get("basis_sha256") != basis_hash or cache.get("basis") != basis:
            raise ValueError("stale_detection_cache")
    gold = {row["case_id"]: row["findings"] for row in evaluation["cases"]}
    rows = []
    for case in runtime["cases"]:
        for mode in modes:
            key = _digest({"case_id": case["case_id"], "payload": case["payload"],
                           "policy": case["sensitivity_policy"], "mode": mode})
            hit = key in cache["entries"]
            if hit:
                entry = cache["entries"][key]
            else:
                start = time.perf_counter()
                try:
                    result = detector(copy.deepcopy(case["payload"]), copy.deepcopy(case["sensitivity_policy"]),
                                      agent=agent, mode=mode)
                    if not isinstance(result, dict) or result.get("status") not in {"ok", "needs_review"}:
                        raise ValueError("invalid_detector_output")
                except Exception as exc:
                    # Do not log exception messages: a model/parser could echo raw content.
                    result = {"status": "needs_review", "findings": [], "errors": [f"detector_error:{type(exc).__name__}"]}
                entry = {"result": result, "elapsed_seconds": time.perf_counter() - start}
                cache["entries"][key] = entry
                if cache_path:
                    _write(Path(cache_path), cache)
            result = entry["result"]
            predicted, validation_errors = _validated_predictions(result, case["payload"])
            expected = {_span_key(span) for span in gold[case["case_id"]]}
            predicted_chars, expected_chars = _characters(predicted), _characters(expected)
            row = {field: case[field] for field in ("case_id", "language", "split", "story_id", "template_family")}
            row.update(mode=mode, status="needs_review" if validation_errors else result["status"],
                tp=len(predicted & expected), fp=len(predicted - expected), fn=len(expected - predicted),
                char_tp=len(predicted_chars & expected_chars), char_fp=len(predicted_chars - expected_chars),
                char_fn=len(expected_chars - predicted_chars), findings=result.get("findings", []),
                errors=list(result.get("errors", [])) + validation_errors,
                elapsed_seconds=entry["elapsed_seconds"], cache_hit=hit,
                local_calls=result.get("local_calls"),
                agent_observations=result.get("agent_observations", []))
            rows.append(row)
            if progress:
                progress({"case_id": case["case_id"], "mode": mode, "status": row["status"],
                          "completed": len(rows), "total": len(runtime["cases"]) * len(modes)})
    summaries = []
    for mode in modes:
        for split in ("all", "dev", "heldout"):
            for language in ("all", "zh", "en"):
                selected = [row for row in rows if row["mode"] == mode and
                            (split == "all" or row["split"] == split) and
                            (language == "all" or row["language"] == language)]
                summaries.append(dict(mode=mode, split=split, language=language, **_aggregate(selected)))
    heldout = next((row for row in summaries if row["mode"] == "combined" and
                    row["split"] == "heldout" and row["language"] == "all"), None)
    gate = None if heldout is None else bool(heldout["cases"] == expected_heldout_cases and
        heldout["recall"] is not None and heldout["recall"] >= .95 and
        heldout["precision"] is not None and heldout["precision"] >= .90 and
        heldout["needs_review"] == 0 and heldout["error_cases"] == 0)
    report = {"schema_version": 1, "kind": "local_privacy_detection_evaluation", "basis": basis,
        "evaluation_sha256": _digest(evaluation), "case_count": len(runtime["cases"]),
        "independent_story_count": len({case["story_id"] for case in runtime["cases"]}),
        "modes": list(modes), "remote_model_calls": 0,
        "detector_execution": "serial; agent and combined are separate detector executions",
        "cache_note": "Per-mode result cache includes failures; cached elapsed times describe the original detection, not this replay.",
        "metric_definition": "Micro exact (source,start,end,category) span matching; duplicates collapse. Character coverage ignores type. Invalid spans count as errors; failed/pending cases retain gold denominators.",
        "heldout_gate": {"passed": gate, "minimum_recall": .95, "minimum_precision": .90,
                         "required_heldout_cases": expected_heldout_cases,
                         "requires_all_expected_cases_and_no_review_or_errors": True},
        "limitations": ["Synthetic, AI-authored templates; gold is derived from authored segments, not independent human annotation.",
                        "Template-family split prevents shared-template leakage; this is a small engineering gate, not a real-world safety claim.",
                        "No lower-bound confidence claim; not tuned again on heldout failures."],
        "summaries": summaries, "rows": rows}
    if output_path:
        _write(Path(output_path), report)
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("create")
    create.add_argument("--output", type=Path, required=True)
    evaluate = sub.add_parser("evaluate-rules")
    evaluate.add_argument("--runtime", type=Path, required=True)
    evaluate.add_argument("--evaluation", type=Path, required=True)
    evaluate.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "create":
        print(json.dumps(write_corpus(args.output), ensure_ascii=False))
    else:
        if args.output.exists():
            raise FileExistsError("report_destination_already_exists")
        report = evaluate_corpus(args.runtime, args.evaluation, modes=("rules",), output_path=args.output)
        print(json.dumps({"cases": report["case_count"], "remote_model_calls": 0}, ensure_ascii=False))


if __name__ == "__main__":
    main()
