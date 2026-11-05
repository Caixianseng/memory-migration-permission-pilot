"""Fair, plain BM25 retrieval baseline over sources that are ALREADY authorized.

Scope and honesty notes
-----------------------
* This module is a *baseline*, not a contribution claim.  It exists so the D1
  grouping candidate can be compared against ordinary retrieval applied after
  authorization (see docs/新算法优势停滞原因与七天验证计划_2026-11-04.md, section 4,
  row "合法原文＋普通检索").
* ``select`` receives only sources the host has already authorized.  It never
  reads the host, the filesystem, the experiment workload, or any reference
  answer, and it cannot reach a source that was not passed in.  Records that
  explicitly declare themselves forbidden are rejected instead of being ranked.
* Retrieval never truncates, rewrites, summarizes, pads or deduplicates text.
  The returned list contains the exact objects that were passed in, only
  reordered.  The "full original text" arm therefore keeps its full capacity and
  remains an independent baseline: this module must not shrink it.
* If no source matches the questions the result is still exactly ``top_k``
  sources ordered by ``source_id``.  There is no silent fallback to returning
  every source, and ``top_k`` is never silently widened.
* Ranking is deterministic: BM25 score descending, then ``source_id`` ascending.
  Parameters are fixed a priori (standard BM25 defaults); nothing here is tuned
  on evaluation results, and no per-question weighting is learned.

Tokenization (deterministic, no model): lowercased English alphanumeric words
with a small fixed stop-word list, plus overlapping bigrams of every run of Han
characters (a single-character run contributes that character).
"""
from __future__ import annotations

import math
import re
from collections import Counter

K1 = 1.5
B = 0.75
AGGREGATIONS = ("sum", "max")

_WORD = re.compile(r"[a-z0-9]+(?:[._-][a-z0-9]+)*")
_CJK_RUN = re.compile(r"[\u3400-\u4dbf\u4e00-\u9fff]+")
_STOP = frozenset("a an and are as at be by for from in is it of on or that the this to was were will with you your".split())


def tokenize(text):
    """Return BM25 term tokens for ``text``; raises on non-string input."""
    if not isinstance(text, str):
        raise ValueError("text_must_be_string")
    tokens = ["w:" + word for word in _WORD.findall(text.lower()) if word not in _STOP]
    for run in _CJK_RUN.findall(text):
        if len(run) == 1:
            tokens.append("c:" + run)
        else:
            tokens.extend("c:" + run[i:i + 2] for i in range(len(run) - 1))
    return tokens


def _records(sources):
    """Validate the incoming authorization view and index it by source_id."""
    if sources is None:
        return {}
    if not isinstance(sources, (list, tuple)):
        raise ValueError("source_list_required")
    indexed = {}
    for record in sources:
        if not isinstance(record, dict):
            raise ValueError("source_object_required")
        source_id = record.get("source_id")
        if not isinstance(source_id, str) or not source_id.strip():
            raise ValueError("invalid_source_id")
        if source_id in indexed:
            raise ValueError("duplicate_source_id")
        if not isinstance(record.get("text"), str):
            raise ValueError("source_text_required")
        if record.get("allow") is False or record.get("allowed") is False:
            raise ValueError("retrieval_received_forbidden_source")
        indexed[source_id] = record
    return indexed


def _questions(questions):
    if not isinstance(questions, (list, tuple)) or not all(isinstance(q, str) for q in questions):
        raise ValueError("questions_must_be_string_list")
    if not questions:
        raise ValueError("questions_required")
    return list(questions)


def _check_params(aggregation, k1, b):
    if aggregation not in AGGREGATIONS:
        raise ValueError("unknown_score_aggregation")
    for value, name in ((k1, "k1"), (b, "b")):
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
            raise ValueError("invalid_" + name)
    if k1 < 0 or not 0.0 <= b <= 1.0:
        raise ValueError("invalid_bm25_parameters")


def score_sources(sources, questions, *, aggregation="sum", k1=K1, b=B):
    """Diagnostics only: ``[{"source_id", "score"}]`` in ranking order, no texts.

    Same arithmetic as :func:`select`; returns no source objects so it cannot be
    mistaken for a delivery path.
    """
    _check_params(aggregation, k1, b)
    indexed = _records(sources)
    query_tokens = [tokenize(q) for q in _questions(questions)]
    doc_tokens = {sid: tokenize(record["text"]) for sid, record in indexed.items()}
    total = len(doc_tokens)
    if not total:
        return []
    lengths = {sid: len(tokens) for sid, tokens in doc_tokens.items()}
    average_length = sum(lengths.values()) / total
    document_frequency = Counter()
    for tokens in doc_tokens.values():
        document_frequency.update(set(tokens))
    scored = []
    for sid in sorted(doc_tokens):
        frequencies = Counter(doc_tokens[sid])
        normalizer = k1 * (1.0 - b + b * (lengths[sid] / average_length if average_length else 0.0))
        per_question = []
        for query in query_tokens:
            question_score = 0.0
            for term in dict.fromkeys(query):
                frequency = frequencies.get(term, 0)
                if not frequency:
                    continue
                df = document_frequency[term]
                idf = math.log(1.0 + (total - df + 0.5) / (df + 0.5))
                question_score += idf * (frequency * (k1 + 1.0)) / (frequency + normalizer)
            per_question.append(question_score)
        aggregated = sum(per_question) if aggregation == "sum" else max(per_question)
        scored.append({"source_id": sid, "score": aggregated})
    scored.sort(key=lambda item: (-item["score"], item["source_id"]))
    return scored


def select(sources, questions, top_k=4, *, aggregation="sum", k1=K1, b=B):
    """Return the ``top_k`` most relevant of the ALREADY-AUTHORIZED ``sources``.

    ``sources``: list of dicts, each with ``source_id`` and ``text`` (``version``
    and any other fields are carried through untouched).  Only these sources can
    be returned; the function has no other way to obtain data.

    ``questions``: non-empty list of question strings.  Scores of the individual
    questions are summed (default) or maximized, then sources are ordered by
    score descending and ``source_id`` ascending for exact ties.

    ``top_k``: positive integer.  When it exceeds ``len(sources)`` every source
    is returned; it is not padded and never widened behind the caller's back.

    Returned items are the original objects, unmodified: no truncation, no
    rewriting, no summarization, no added keys.  No sources at all -> ``[]``.
    """
    if isinstance(top_k, bool) or not isinstance(top_k, int):
        raise ValueError("invalid_top_k")
    if top_k < 1:
        raise ValueError("invalid_top_k")
    _check_params(aggregation, k1, b)
    indexed = _records(sources)
    query_tokens = [tokenize(q) for q in _questions(questions)]
    if not indexed:
        return []
    ranking = score_sources(list(indexed.values()), questions, aggregation=aggregation, k1=k1, b=b)
    return [indexed[item["source_id"]] for item in ranking[:top_k]]


__all__ = ["select", "score_sources", "tokenize", "AGGREGATIONS", "K1", "B"]
