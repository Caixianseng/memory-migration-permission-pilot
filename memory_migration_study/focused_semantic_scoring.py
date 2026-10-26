"""Post-prediction scoring for the four-cell development diagnostic.

This module performs no IO and imports no runtime materials. Callers close and
hash model outputs before loading the independent reference. Native eligibility,
policy controls and boundary checks remain separate from semantic correctness.
"""
from __future__ import annotations

from collections import Counter
from itertools import combinations
import re

CONDITIONS = ("S0", "S1", "T0", "T1")
SEMANTIC_OUTCOMES = ("correct", "legal_unknown", "wrong_fact", "missing_hallucination", "execution_failure")
_ANSWER = re.compile(r"F[1-4]\Z")
_WIRE_HASH = re.compile(r"[0-9a-f]{64}\Z")


def _reference_rows(reference):
    rows = reference.get("rows") if isinstance(reference, dict) else reference
    if not isinstance(rows, list) or len(rows) != 12:
        raise ValueError("reference_requires_twelve_questions")
    result = {}
    by_story = {}
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"story_id", "question_id", "expected_id", "kind"}:
            raise ValueError("reference_schema_invalid")
        key = (row["story_id"], row["question_id"])
        if not all(isinstance(k, str) and k for k in key) or key in result:
            raise ValueError("reference_question_identity_invalid")
        kind, expected = row["kind"], row["expected_id"]
        if kind not in {"legal", "missing"} or not isinstance(expected, str):
            raise ValueError("reference_kind_invalid")
        if (kind == "missing" and expected != "UNKNOWN") or (kind == "legal" and not _ANSWER.fullmatch(expected)):
            raise ValueError("reference_answer_kind_mismatch")
        result[key] = dict(row)
        by_story.setdefault(key[0], Counter())[kind] += 1
    if len(by_story) != 4 or any(count != Counter(legal=2, missing=1) for count in by_story.values()):
        raise ValueError("reference_requires_four_two_legal_one_missing_stories")
    return result


def score(predictions, reference):
    """Score flat predictions without dropping missing, blocked or failed rows.

    Each prediction has story_id, question_id, condition, status and answer_id.
    Actual final wire hashes are accepted as request_sha256 or request_hash.
    Only status == 'ok' can be semantically correct. A pre-model policy denial
    is never scored as a model UNKNOWN, including on missing-information items.
    Unknown question identities, duplicate outputs and old condition names fail
    closed instead of being silently included or relabelled.
    """
    refs = _reference_rows(reference)
    if not isinstance(predictions, list):
        raise ValueError("predictions_must_be_list")
    observed = {}
    for prediction in predictions:
        if not isinstance(prediction, dict):
            raise ValueError("prediction_schema_invalid")
        condition = prediction.get("condition")
        key = (prediction.get("story_id"), prediction.get("question_id"))
        if condition not in CONDITIONS:
            raise ValueError("prediction_condition_invalid")
        if key not in refs:
            raise ValueError("prediction_question_not_registered")
        identity = (*key, condition)
        if identity in observed:
            raise ValueError("duplicate_prediction")
        observed[identity] = prediction

    rows = []
    indexed = {}
    failures = Counter()
    for key, reference_row in refs.items():
        for condition in CONDITIONS:
            prediction = observed.get((*key, condition))
            answer = prediction.get("answer_id") if prediction else None
            status = prediction.get("status", "invalid_prediction") if prediction else "missing_prediction"
            failure_class = prediction.get("failure_class") if prediction else "missing_prediction"
            valid_answer = isinstance(answer, str) and (answer == "UNKNOWN" or bool(_ANSWER.fullmatch(answer)))
            if status == "ok" and not valid_answer:
                status = "invalid_answer_id"
                failure_class = "invalid_answer_id"
            if status != "ok":
                failure_class = failure_class or status
                failures[str(failure_class)] += 1
            wire_hash = prediction.get("request_sha256", prediction.get("request_hash")) if prediction else None
            correct = status == "ok" and answer == reference_row["expected_id"]
            semantic_outcome = (
                "execution_failure" if status != "ok" else
                "correct" if correct else
                "missing_hallucination" if reference_row["kind"] == "missing" else
                "legal_unknown" if answer == "UNKNOWN" else "wrong_fact")
            row = dict(reference_row, condition=condition, answer_id=answer, status=status,
                       correct=correct, semantic_outcome=semantic_outcome,
                       failure_class=failure_class if status != "ok" else None,
                       request_sha256=wire_hash)
            rows.append(row)
            indexed[(*key, condition)] = row

    conditions = {}
    for condition in CONDITIONS:
        group = [r for r in rows if r["condition"] == condition]
        legal = [r for r in group if r["kind"] == "legal"]
        missing = [r for r in group if r["kind"] == "missing"]
        conditions[condition] = {
            "planned": 12, "observed": sum((*key, condition) in observed for key in refs),
            "legal": 8, "legal_correct": sum(r["correct"] for r in legal),
            "legal_accuracy": sum(r["correct"] for r in legal) / 8,
            "missing": 4, "missing_correct": sum(r["correct"] for r in missing),
            "missing_accuracy": sum(r["correct"] for r in missing) / 4,
            "ok": sum(r["status"] == "ok" for r in group),
            "failed_or_blocked": sum(r["status"] != "ok" for r in group),
            "semantic_outcomes": {name: sum(r["semantic_outcome"] == name for r in group)
                                  for name in SEMANTIC_OUTCOMES},
        }

    accuracy = {c: conditions[c]["legal_accuracy"] for c in CONDITIONS}
    effects = {
        "migration_raw": accuracy["T0"] - accuracy["S0"],
        "migration_pseudonymized": accuracy["T1"] - accuracy["S1"],
        "privacy_source": accuracy["S1"] - accuracy["S0"],
        "privacy_target": accuracy["T1"] - accuracy["T0"],
        "interaction": (accuracy["T1"] - accuracy["T0"]) - (accuracy["S1"] - accuracy["S0"]),
    }
    comparisons = {}
    for left, right in combinations(CONDITIONS, 2):
        pairs = []
        for key, ref in refs.items():
            if ref["kind"] != "legal":
                continue
            a, b = indexed[(*key, left)], indexed[(*key, right)]
            both_ok = a["status"] == b["status"] == "ok"
            same_wire = (isinstance(a["request_sha256"], str)
                         and bool(_WIRE_HASH.fullmatch(a["request_sha256"]))
                         and a["request_sha256"] == b["request_sha256"])
            answer_disagreement = both_ok and a["answer_id"] != b["answer_id"]
            pairs.append({
                "story_id": key[0], "question_id": key[1], "left": left, "right": right,
                "left_answer_id": a["answer_id"], "right_answer_id": b["answer_id"],
                "left_correct": a["correct"], "right_correct": b["correct"],
                "both_ok": both_ok, "answer_disagreement": answer_disagreement,
                "correctness_disagreement": a["correct"] != b["correct"],
                "same_actual_request": same_wire,
                "attribution": "runtime_variation" if same_wire and answer_disagreement else
                    ("input_difference" if answer_disagreement else ("incomplete_pair" if not both_ok else "none")),
            })
        comparisons[f"{left}:{right}"] = {
            "planned_legal_pairs": 8, "complete_pairs": sum(r["both_ok"] for r in pairs),
            "answer_disagreements": sum(r["answer_disagreement"] for r in pairs),
            "correctness_disagreements": sum(r["correctness_disagreement"] for r in pairs),
            "runtime_variations": sum(r["attribution"] == "runtime_variation" for r in pairs),
            "rows": pairs,
        }
    return {
        "version": "focused_semantic_four_cell_score_v1",
        "scope": "four_new_development_stories_only",
        "conditions": conditions, "effects": effects, "paired_comparisons": comparisons,
        "failure_classes": dict(sorted(failures.items())), "rows": rows,
        "semantic_outcomes": {name: sum(r["semantic_outcome"] == name for r in rows)
                              for name in SEMANTIC_OUTCOMES},
        "planned_predictions": 48, "observed_predictions": len(observed),
        "missing_predictions": 48 - len(observed),
    }
