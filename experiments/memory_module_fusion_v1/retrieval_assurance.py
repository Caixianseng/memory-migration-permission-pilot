"""Authorized progressive retrieval with an optional REAL local CPU reranker.

Four registered comparisons: fixed BM25, fixed rerank, adaptive BM25, adaptive
rerank. Every question starts with two WHOLE source IDs, widening to 4/8 and
finally all lawful raw sources if the quality signal remains low. Ranking
windows are features only. Scores/lexical coverage neither prove support nor
grant permission. This is an independent CRAG-inspired control-flow adaptation,
not copied CRAG code or a claim to reproduce its trained T5 evaluator.
"""
from __future__ import annotations
import hashlib
import json
import math
import time

from experiments.revocation_grouping_v1.retrieval_baseline import score_sources, tokenize

METHODS = ("bm25", "fixed_rerank", "adaptive_bm25", "adaptive_rerank")
DEFAULT_CONFIG = {"method": "adaptive_rerank", "stages": [2, 4, 8], "candidate_k": 20,
                  "score_threshold": .5, "min_relevant_sources": 2,
                  "require_distinct_parents": 1,
                  "lexical_coverage_threshold": .65,
                  "threshold_provenance": "a_priori_default_NOT_calibrated"}
_FORBIDDEN = {"answer", "answers", "reference_answer", "expected_answer", "supporting_facts",
              "support_sets", "support_source_ids", "required_fact_source_ids", "evaluation",
              "gold", "gold_sources", "future_events", "events", "test_trace", "level", "type"}


class AuthorityChanged(RuntimeError):
    pass


def _no_labels(value):
    if isinstance(value, dict):
        if _FORBIDDEN.intersection(value):
            raise ValueError("evaluation_or_future_labels_not_allowed_in_retrieval")
        for child in value.values():
            _no_labels(child)
    elif isinstance(value, (list, tuple)):
        for child in value:
            _no_labels(child)


def _sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def _validate_rank_result(result, records):
    if not isinstance(result, dict) or result.get("status") != "ok":
        raise ValueError("ranker_did_not_complete")
    scores = result.get("source_scores")
    if not isinstance(scores, dict) or set(scores) != set(records):
        raise ValueError("ranker_score_ids_not_exactly_authorized_candidate_pool")
    for score in scores.values():
        if isinstance(score, bool) or not isinstance(score, (int, float)) or not math.isfinite(score) or not 0 <= score <= 1:
            raise ValueError("ranker_quality_score_must_be_finite_probability_like_value")
    windows = result.get("windows")
    if not isinstance(windows, list):
        raise ValueError("ranker_window_audit_required")
    tokens = {sid: [] for sid in records}
    for window in windows:
        sid = window.get("source_id")
        if sid not in records:
            raise ValueError("ranker_window_not_in_authorized_pool")
        start, end = window.get("start"), window.get("end")
        if type(start) is not int or type(end) is not int or not 0 <= start < end <= len(records[sid]["text"]):
            raise ValueError("ranker_window_invalid_original_offsets")
        if _sha(records[sid]["text"][start:end]) != window.get("text_sha256"):
            raise ValueError("ranker_window_original_hash_mismatch")
        if (window.get("truncated") is not False or type(window.get("pair_tokens")) is not int
                or not 0 < window["pair_tokens"] <= 512):
            raise ValueError("ranker_pair_truncated_or_exceeds_512_tokens")
        a, b, total = window.get("source_token_start"), window.get("source_token_end"), window.get("source_total_tokens")
        if any(type(value) is not int for value in (a, b, total)) or not 0 <= a < b <= total:
            raise ValueError("invalid_ranker_token_coverage_audit")
        tokens[sid].append((a, b, total))
    for intervals in tokens.values():
        cursor, previous_total = 0, None
        for a, b, total in sorted(intervals):
            if a != cursor or (previous_total is not None and total != previous_total):
                raise ValueError("ranker_silently_omitted_or_overlapped_source_feature_tokens")
            cursor, previous_total = b, total
        if previous_total is None or cursor != previous_total:
            raise ValueError("ranker_feature_windows_do_not_cover_entire_source_token_sequence")
    return scores


def prepare_retrieval(allowed_sources, questions, ranker=None, config=None, authorize=None, get_epoch=None):
    """Return complete selected source IDs, trace, local timing and gate decisions.

    authorize(ids, purpose) must raise or return False on denial; returning None
    is supported for trusted host APIs. get_epoch() must change on any relevant
    permission/source-version change. All phases recheck the SAME epoch before
    and after reading/scoring and immediately before returning the union. A
    changed epoch fails closed; this function never retries a generation call.

    Questions are strings or {question_id,question} only. The controller cannot
    consume support/gold labels. Fixed and adaptive rerank use the same BM25
    candidate pool; repeated widening reuses this call's validated pair scores.
    Final payload rendering must recover WHOLE originals from the trusted host.
    """
    wall_started, cpu_started = time.perf_counter(), time.process_time()
    if not callable(authorize) or not callable(get_epoch):
        raise ValueError("trusted_authorize_and_epoch_callbacks_required")
    _no_labels(config or {})
    if config is not None and (not isinstance(config, dict) or set(config) - DEFAULT_CONFIG.keys()):
        raise ValueError("unknown_retrieval_assurance_config")
    cfg = {**DEFAULT_CONFIG, **(config or {})}
    method = cfg["method"]
    if method not in METHODS:
        raise ValueError("unknown_retrieval_assurance_method")
    stages = cfg["stages"]
    if not isinstance(stages, (list, tuple)) or list(stages) != [2, 4, 8]:
        raise ValueError("registered_stages_must_be_2_4_8")
    if type(cfg["candidate_k"]) is not int or cfg["candidate_k"] < 8:
        raise ValueError("candidate_pool_must_support_all_registered_stages")
    if type(cfg["min_relevant_sources"]) is not int or cfg["min_relevant_sources"] < 1:
        raise ValueError("positive_min_relevant_sources_required")
    if type(cfg["require_distinct_parents"]) is not int or cfg["require_distinct_parents"] < 1:
        raise ValueError("positive_distinct_parent_requirement_required")
    for key in ("score_threshold", "lexical_coverage_threshold"):
        value = cfg[key]
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not 0 <= value <= 1:
            raise ValueError("invalid_" + key)
    if not isinstance(allowed_sources, (list, tuple)):
        raise ValueError("already_authorized_source_list_required")
    records = {}
    for source in allowed_sources:
        if not isinstance(source, dict):
            raise ValueError("source_object_required")
        sid, text = source.get("source_id"), source.get("text")
        if (not isinstance(sid, str) or not sid or sid in records or not isinstance(text, str)
                or not text.strip()):
            raise ValueError("invalid_or_duplicate_source_record")
        if source.get("allow", True) is not True or source.get("allowed", True) is not True:
            raise ValueError("explicitly_forbidden_source_received")
        records[sid] = source
    _no_labels(questions)
    if not isinstance(questions, (list, tuple)) or not questions:
        raise ValueError("nonempty_current_question_list_required")
    parsed, seen = [], set()
    for index, question in enumerate(questions):
        if isinstance(question, str):
            qid, text = f"Q{index + 1}", question
        elif isinstance(question, dict) and set(question) <= {"question_id", "question"}:
            qid, text = question.get("question_id", f"Q{index + 1}"), question.get("question")
        else:
            raise ValueError("question_requires_only_id_and_text")
        if not isinstance(qid, str) or not qid or qid in seen or not isinstance(text, str) or not text.strip():
            raise ValueError("invalid_or_duplicate_current_question")
        seen.add(qid)
        parsed.append((qid, text))
    epoch = _canonical(get_epoch())
    if epoch == "null":
        raise ValueError("host_epoch_required")
    trace, gate_decisions, per_question = [], [], []

    def check(ids, purpose):
        if _canonical(get_epoch()) != epoch:
            raise AuthorityChanged("authority_epoch_changed_before_" + purpose)
        if authorize(list(ids), purpose) is False:
            raise PermissionError("host_denied_" + purpose)
        if _canonical(get_epoch()) != epoch:
            raise AuthorityChanged("authority_epoch_changed_during_" + purpose)
        trace.append({"phase": "host_authorized", "purpose": purpose, "source_ids": list(ids)})

    check(records, "assurance_input_view")
    owned_ranker, model_cpu, model_wall, rank_calls = None, 0.0, 0.0, 0
    cpu_complete = True
    selected_union = set()
    try:
        for qid, question in parsed:
            check(records, "bm25_before_" + qid)
            lexical = score_sources(list(records.values()), [question]) if records else []
            check(records, "bm25_after_" + qid)
            ordered = [row["source_id"] for row in lexical]
            scores, rank_audit, rank_error = None, None, None
            rank_started, rank_elapsed_counted = None, False
            if "rerank" in method and ordered:
                pool = ordered[:cfg["candidate_k"]]
                check(pool, "rank_before_" + qid)
                try:
                    if ranker is None:
                        from .reranker_runtime import TinyBERTReranker
                        owned_ranker = TinyBERTReranker()
                        ranker = owned_ranker
                    rank_calls += 1
                    rank_started = time.perf_counter()
                    result = ranker.score_sources(question, [{"source_id": sid, "text": records[sid]["text"]}
                                                             for sid in pool])
                    model_wall += (time.perf_counter() - rank_started) * 1000
                    rank_elapsed_counted = True
                    check(pool, "rank_after_" + qid)
                    elapsed_cpu = result.get("cpu_ms", 0)
                    if isinstance(elapsed_cpu, bool) or not isinstance(elapsed_cpu, (float, int)) or not math.isfinite(elapsed_cpu) or elapsed_cpu < 0:
                        raise ValueError("invalid_ranker_cpu_accounting")
                    model_cpu += elapsed_cpu
                    scores = _validate_rank_result(result, {sid: records[sid] for sid in pool})
                    ordered = sorted(pool, key=lambda sid: (-scores[sid], sid))
                    rank_audit = {"source_scores": scores, "windows": result["windows"],
                                  "feature_pool_source_ids": pool,
                                  "model_revision": getattr(ranker, "metadata", {}).get("model_revision")}
                except (AuthorityChanged, PermissionError):
                    raise
                except Exception as exc:
                    cpu_complete = False
                    if rank_started is not None and not rank_elapsed_counted:
                        model_wall += (time.perf_counter() - rank_started) * 1000
                    check(records, "rank_failure_full_raw_" + qid)
                    rank_error = type(exc).__name__
            trace.append({"phase": "ranking", "question_id": qid, "method": method,
                          "ranker_audit": rank_audit, "ranker_error": rank_error})
            chosen, accepted = [], False
            if rank_error:
                chosen = list(records)
                gate_decisions.append({"question_id": qid, "decision": "ranker_error_full_raw",
                                       "quality_or_support_guarantee": False})
            elif not records:
                gate_decisions.append({"question_id": qid, "decision": "empty_authorized_view",
                                       "quality_or_support_guarantee": False})
            else:
                actual_stages = [2] if method in {"bm25", "fixed_rerank"} else stages
                attempted_sizes = set()
                for k in actual_stages:
                    chosen = ordered[:min(k, len(ordered))]
                    if len(chosen) in attempted_sizes:
                        continue
                    attempted_sizes.add(len(chosen))
                    check(chosen, "stage_before_" + qid + "_" + str(k))
                    query_terms = set(tokenize(question))
                    available_terms = set(token for sid in chosen for token in tokenize(records[sid]["text"]))
                    coverage = len(query_terms & available_terms) / len(query_terms) if query_terms else 0.0
                    high_count = sum(scores[sid] >= cfg["score_threshold"] for sid in chosen) if scores is not None else None
                    parents = {_canonical(records[sid].get("origin", {}).get("parent_index", sid))
                               for sid in chosen}
                    quality_ok = (high_count >= cfg["min_relevant_sources"] if scores is not None
                                  else coverage >= cfg["lexical_coverage_threshold"])
                    quality_ok = quality_ok and len(parents) >= cfg["require_distinct_parents"]
                    check(chosen, "stage_after_" + qid + "_" + str(k))
                    accepted = method in {"bm25", "fixed_rerank"} or quality_ok
                    decision = {"question_id": qid, "requested_k": k, "selected_source_ids": list(chosen),
                                "decision": "fixed_budget" if method in {"bm25", "fixed_rerank"}
                                else "accept_quality_signal" if quality_ok else "widen_for_more_lawful_evidence",
                                "lexical_query_coverage": coverage, "above_threshold_source_count": high_count,
                                "distinct_parent_count": len(parents),
                                "quality_or_support_guarantee": False}
                    gate_decisions.append(decision)
                    if accepted:
                        break
                if not accepted:
                    check(records, "full_raw_fallback_" + qid)
                    chosen = list(records)
                    gate_decisions.append({"question_id": qid, "decision": "full_raw_fallback",
                                           "selected_source_ids": chosen,
                                           "quality_or_support_guarantee": False})
            check(chosen, "question_final_" + qid)
            per_question.append({"question_id": qid, "selected_source_ids": list(chosen)})
            selected_union.update(chosen)
        selected = [sid for sid in records if sid in selected_union]
        check(selected, "assurance_final_union")
        return {"selected_source_ids": selected, "per_question": per_question,
                "trace": trace, "gate_decisions": gate_decisions,
                "cpu_ms": (time.process_time() - cpu_started) * 1000 + model_cpu,
                "local_wall_ms": (time.perf_counter() - wall_started) * 1000,
                "ranker_cpu_ms": model_cpu, "ranker_wall_ms": model_wall,
                "ranker_call_count": rank_calls,
                "ranker_cpu_accounting_complete": cpu_complete,
                "ranker_metadata": getattr(ranker, "metadata", None),
                "threshold_config": cfg, "source_payload_untouched": True,
                "source_bindings": {sid: {"text_sha256": _sha(records[sid]["text"]),
                                           "version": records[sid].get("version", 1)} for sid in selected},
                "authority_epoch_sha256": _sha(epoch),
                "full_raw_fallback_and_prior_stage_costs_must_all_be_charged": True,
                "quality_scores_do_not_prove_support_or_authorize_access": True,
                "no_generation_model_api_calls": True}
    finally:
        if owned_ranker is not None:
            owned_ranker.close()
