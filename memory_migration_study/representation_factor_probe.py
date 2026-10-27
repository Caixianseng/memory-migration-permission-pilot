"""Exposed-development representation diagnostic; no authorization changes.

Entity types are manual oracle metadata. All four candidate statements survive
each reversible transform. Request construction has no scoring-reference IO.
The short/long contrast changes nonce format, readability and tokenization; it
does not identify pure character-length causation. Natural renaming is a
compound control, not an isolated lexical-name effect or an algorithm.
"""
from __future__ import annotations

from collections import Counter
from copy import deepcopy
import re
import time

from .focused_semantic_reader import (OPTIONS, SCHEMA, SYSTEM, candidates,
    canonical, digest, parse_selection, require)
from .focused_semantic_scoring import _reference_rows
from .local_detector import MODEL
from .private_request_boundary import (PrivateRequestBoundary, LoopbackJSONSender,
                                      _strings, _known_value_forms)

REPRESENTATIONS = ("raw", "short_customer", "long_customer", "short_typed", "long_typed", "natural")
PROMPTS = ("original", "evidence")
CONDITIONS = tuple(r + ":" + p for r in REPRESENTATIONS for p in PROMPTS)
EVIDENCE_ADDITION = (
    " A card is eligible only when its statement provides evidence for the requested relationship, "
    "with matching entity, time and negation. Shared entities alone do not establish the requested "
    "relationship. Do not substitute a merely associated relationship. If none of the supplied "
    "statements supports the relationship, relevant time and polarity asked about, return UNKNOWN.")
SYSTEMS = {"original": SYSTEM, "evidence": SYSTEM + EVIDENCE_ADDITION}
TYPE_LABELS = {"PROJECT": "PROJECT_", "PERSON": "PERSON__", "ORG": "ORG_____"}


def validate_entities(material, registry):
    require(set(registry) == {"version", "provenance", "stories"}, "entity_registry_fields")
    require(set(registry["stories"]) == {s["id"] for s in material["stories"]}, "entity_story_inventory")
    for story in material["stories"]:
        rows = registry["stories"][story["id"]]
        require(isinstance(rows, list) and len(rows) == len(story["sensitive_values"]), "entity_count")
        require(all(set(e) == {"value", "type", "pseudonym"} for e in rows), "entity_fields")
        require([e["value"] for e in rows] == story["sensitive_values"], "stable_entity_order")
        require(all(e["type"] in TYPE_LABELS for e in rows), "oracle_entity_type")
        values, names = [e["value"] for e in rows], [e["pseudonym"] for e in rows]
        require(all(isinstance(n, str) and n and n not in values for n in names)
                and len(set(names)) == len(names), "natural_name_bijection")
        require(not any(a in b for a in names for b in names if a != b), "natural_name_overlap")
        require(not any(a in b or b in a for a in values for b in names), "natural_original_overlap")
        # Fixed synthetic names retain character length, word count and UTF-8
        # length where possible; tokenizer identity/semantics still change.
        require(all(len(v) == len(n) and len(v.encode()) == len(n.encode())
                    and len(v.split()) == len(n.split()) for v, n in zip(values, names)), "natural_name_shape")


def entity_map(rows, representation, nonce):
    require(representation in REPRESENTATIONS and re.fullmatch(r"[A-F0-9]{24}", nonce), "representation_or_nonce")
    if representation == "raw":
        return {e["value"]: e["value"] for e in rows}
    if representation == "natural":
        result = {e["value"]: e["pseudonym"] for e in rows}
    else:
        visible_nonce = nonce[:4] if representation.startswith("short_") else nonce
        result = {e["value"]: "[PVT_" + visible_nonce + "_" +
                  (TYPE_LABELS[e["type"]] if representation.endswith("typed") else "CUSTOMER") +
                  "_" + str(index) + "]" for index, e in enumerate(rows, 1)}
    require(len(result) == len(rows) == len(set(result.values())), "entity_alias_bijection")
    return result


def substitute(text, mapping):
    pattern = re.compile("|".join(re.escape(v) for v in sorted(mapping, key=len, reverse=True)))
    return pattern.sub(lambda match: mapping[match.group()], text)


def model_body(story, question, entity_rows, representation, prompt, nonce):
    require(prompt in PROMPTS, "prompt_not_registered")
    raw = candidates(story, {o["key"]: o["text"] for o in story["objects"]})
    mapping = entity_map(entity_rows, representation, nonce)
    inverse = {v: k for k, v in mapping.items()}
    texts = [question["text"], *[f["text"] for f in raw]]
    converted = [substitute(text, mapping) for text in texts]
    require(all(substitute(after, inverse) == before for before, after in zip(texts, converted)), "lossless_roundtrip")
    if representation != "raw":
        require(not any(value in text for value in story["sensitive_values"] for text in converted), "original_value_in_representation")
    user = {"query": converted[0], "fact_cards": [
        {"answer_id": fact["id"], "statement": text} for fact, text in zip(raw, converted[1:])]}
    return {"model": MODEL, "messages": [{"role": "system", "content": SYSTEMS[prompt]},
            {"role": "user", "content": canonical(user).decode()}], "stream": False,
            "options": dict(OPTIONS), "format": deepcopy(SCHEMA)}


def call_order(question_index):
    require(type(question_index) is int and 0 <= question_index < 12, "question_index")
    # Every condition occupies every serial position exactly once across 12 questions.
    return list(CONDITIONS[question_index:] + CONDITIONS[:question_index])


class ModelBudget:
    def __init__(self, cap=144):
        require(type(cap) is int and 0 <= cap <= 144, "invalid_model_cap")
        self.cap, self.attempted = cap, 0

    def reserve(self):
        require(self.attempted < self.cap, "model_budget_exhausted")
        self.attempted += 1


def call_model(row, body, registered_values, budget, *, sender=None):
    """One exact-byte attempt; injectable sender is offline-test-only.

    The production driver supplies its fixed LoopbackJSONSender capture wrapper.
    It never supplies a model response and has no retry/resume path.
    """
    result_row = dict(row, status="not_run", answer_id=None, model_calls=0, failure_class=None,
                      request_sha256=digest(body), request_bytes=len(canonical(body)))
    start = time.monotonic()
    try:
        require(len(canonical(body)) <= OPTIONS["num_ctx"] - OPTIONS["num_predict"], "conservative_input_budget_exceeded")
        require(budget.attempted < budget.cap, "model_budget_exhausted")
        boundary = PrivateRequestBoundary(body["messages"], registered_values, MODEL, 1, expected_format=SCHEMA)
        def transport(raw):
            budget.reserve()
            result_row["model_calls"] = 1
            return (sender or LoopbackJSONSender(timeout=120))(raw)
        result = boundary.send(body, transport)
        result_row["request_boundary"] = result.receipt
        require(result.receipt["status"] == "sent", result.receipt["code"] or "request_not_sent")
        response = result.response
        result_row["response_sha256"] = digest(response)
        known = {form for value in registered_values for form in _known_value_forms(value)}
        response_clear = not any(value in form for text in _strings(response)
                                 for form in _known_value_forms(text) for value in known)
        result_row["response_registered_value_scan"] = {"registered": len(registered_values), "clear": response_clear}
        require(response_clear, "response_registered_value_present")
        result_row["usage"] = {k: response.get(k) for k in ("prompt_eval_count", "eval_count", "total_duration", "load_duration")}
        require(type(response.get("prompt_eval_count")) is int and 0 < response["prompt_eval_count"] <= 4032
                and type(response.get("eval_count")) is int and 0 <= response["eval_count"] <= 64,
                "observed_token_budget_unverified")
        require(response.get("done") is True and response.get("model") == MODEL, "model_response_envelope")
        result_row["raw_answer"] = response.get("message", {}).get("content")
        selected = parse_selection(result_row["raw_answer"])
        result_row.update(status="ok", answer_id=selected)
    except Exception as error:
        result_row.update(status="error", failure_class=str(error) if isinstance(error, ValueError) else type(error).__name__)
    result_row["elapsed_seconds"] = time.monotonic() - start
    return result_row


def score(predictions, reference):
    """Only called after predictions close; retain the entire 144-cell denominator."""
    refs = _reference_rows(reference)
    observed = {}
    for row in predictions:
        key = (row.get("story_id"), row.get("question_id"), row.get("condition"))
        require(key[:2] in refs and key[2] in CONDITIONS and key not in observed, "prediction_identity_invalid")
        observed[key] = row
    rows, indexed = [], {}
    for key, ref in refs.items():
        for condition in CONDITIONS:
            prediction = observed.get((*key, condition), {})
            status, answer = prediction.get("status", "not_run"), prediction.get("answer_id")
            if status == "ok" and answer not in {"F1", "F2", "F3", "F4", "UNKNOWN"}:
                status = "invalid_answer_id"
            correct = status == "ok" and answer == ref["expected_id"]
            outcome = ("execution_failure" if status != "ok" else "correct" if correct else
                       "missing_hallucination" if ref["kind"] == "missing" else
                       "legal_unknown" if answer == "UNKNOWN" else "wrong_fact")
            row = dict(ref, condition=condition, status=status, answer_id=answer, correct=correct,
                       semantic_outcome=outcome, failure_class=prediction.get("failure_class"),
                       request_sha256=prediction.get("request_sha256"))
            rows.append(row); indexed[(*key, condition)] = row
    conditions = {}
    for condition in CONDITIONS:
        group = [r for r in rows if r["condition"] == condition]
        actual = [observed[(*key, condition)] for key in refs if (*key, condition) in observed]
        conditions[condition] = {"planned": 12, "observed": len(actual),
            "legal_correct": sum(r["correct"] for r in group if r["kind"] == "legal"), "legal": 8,
            "missing_correct": sum(r["correct"] for r in group if r["kind"] == "missing"), "missing": 4,
            "correct": sum(r["correct"] for r in group),
            "semantic_outcomes": dict(Counter(r["semantic_outcome"] for r in group)),
            "prompt_tokens": sum(r.get("usage", {}).get("prompt_eval_count") or 0 for r in actual),
            "output_tokens": sum(r.get("usage", {}).get("eval_count") or 0 for r in actual),
            "elapsed_seconds": sum(r.get("elapsed_seconds", 0) for r in actual)}
    contrasts = [(r + ":original", r + ":evidence", "prompt") for r in REPRESENTATIONS]
    for prompt in PROMPTS:
        contrasts += [(a + ":" + prompt, b + ":" + prompt, factor) for a, b, factor in (
            ("short_customer", "long_customer", "nonce_format_coarse"),
            ("short_typed", "long_typed", "nonce_format_typed"),
            ("short_customer", "short_typed", "oracle_type_short"),
            ("long_customer", "long_typed", "oracle_type_long"),
            ("raw", "natural", "compound_natural_renaming"),
            ("raw", "long_customer", "compound_legacy_format"),
            ("raw", "short_customer", "compound_short_coarse_format"),
            ("raw", "short_typed", "compound_short_oracle_typed_format"),
            ("raw", "long_typed", "compound_long_oracle_typed_format"))]
    paired = []
    for left, right, factor in contrasts:
        flips = []
        for key, ref in refs.items():
            a, b = indexed[(*key, left)], indexed[(*key, right)]
            flips.append({"story_id": key[0], "question_id": key[1], "kind": ref["kind"],
                "left_answer_id": a["answer_id"], "right_answer_id": b["answer_id"],
                "both_ok": a["status"] == b["status"] == "ok", "left_correct": a["correct"],
                "right_correct": b["correct"], "answer_changed": a["answer_id"] != b["answer_id"],
                "gain": not a["correct"] and b["correct"], "loss": a["correct"] and not b["correct"]})
        paired.append({"left": left, "right": right, "factor": factor, "planned_pairs": 12,
            "gain": sum(f["gain"] for f in flips), "loss": sum(f["loss"] for f in flips), "rows": flips})
    return {"version": "representation_factor_development_score_v1", "scope": "four_exposed_development_stories",
        "planned_predictions": 144, "observed_predictions": len(observed), "missing_predictions": 144-len(observed),
        "conditions": conditions, "paired_contrasts": paired, "rows": rows}
