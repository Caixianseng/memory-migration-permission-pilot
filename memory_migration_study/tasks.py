"""One retrieval pipeline, fresh sessions, and a separate host-side exact scorer."""
from __future__ import annotations

import hashlib
import json
import random
import re
import uuid
from statistics import mean

from .backend import HTTPAdapter
from .evidence import _items
from .policy import decision

GROUPS = ("authorized_reference", "migrated", "no_memory")
HIDDEN_FIELDS = {"expected_answer", "expected_action", "judge_spec", "leak_targets", "forbidden_markers"}


def validate_runtime(value):
    if isinstance(value, dict):
        if HIDDEN_FIELDS.intersection(value):
            raise ValueError("evaluation labels cannot enter the runtime package")
        for item in value.values():
            validate_runtime(item)
    elif isinstance(value, list):
        for item in value:
            validate_runtime(item)


def retrieve(query: str, memories: list[dict], top_k: int = 2, context_chars: int = 4096) -> list[dict]:
    if top_k < 0 or context_chars < 0:
        raise ValueError("retrieval budgets must be nonnegative")
    unique = {}
    for memory in memories:
        sid, text = memory["source_id"], memory["text"]
        if sid in unique and unique[sid] != text:
            raise ValueError("conflicting replica content")
        unique[sid] = text
    tokens = lambda text: set(re.findall(r"\w+", text.lower()))
    query_tokens = tokens(query)
    ranked = sorted(unique.items(), key=lambda item: (-len(query_tokens.intersection(tokens(item[1]))), item[0]))
    selected, used = [], 0
    for sid, text in ranked[:top_k]:
        # Keep whole memories; identical budget and format in every group.
        cost = len(json.dumps({"source_id": sid, "text": text}, ensure_ascii=False))
        if used + cost <= context_chars:
            selected.append({"source_id": sid, "text": text})
            used += cost
    return selected


class DeterministicAnswerer:
    """Instrumentation stub for author-created 'field: value' fact queries only."""
    kind = "deterministic_instrumentation"

    def __call__(self, *, query, memories, session_id):
        query_tokens = set(re.findall(r"\w+", query.lower()))
        for memory in memories:
            for line in memory["text"].splitlines():
                if ":" in line:
                    field, value = line.split(":", 1)
                    if field.strip().lower() in query_tokens:
                        return value.strip()
        return "UNKNOWN"


def available_from_http(adapter, actor_id, plan):
    valid, _ = adapter.identity(actor_id)
    if not valid:
        raise RuntimeError("task_identity_unverified")
    pages, complete = adapter.list_pages(actor_id)
    if not complete:
        raise RuntimeError("task_list_incomplete")
    reverse = {t: s for s, values in plan["object_mapping"].items() for t in values}
    memories = []
    for page in pages:
        for item in _items(page):
            if item.get("source_id") == "__positive_control__":
                continue
            sid = reverse.get(item.get("target_id"))
            if sid is None or item.get("source_id") != sid or not isinstance(item.get("text"), str):
                raise RuntimeError("task_object_mapping_unverified")
            memories.append({"source_id": sid, "text": item["text"]})
    return memories


def run_tasks(runtime: dict, plan: dict, adapter, *, seed=42, answerer=None, top_k=2, context_chars=4096) -> dict:
    validate_runtime(runtime)
    answerer = answerer or DeterministicAnswerer()
    case_id = runtime["case_id"]
    results, orders = [], []
    for task in runtime["tasks"]:
        if task["case_id"] != case_id or task["actor_id"] not in {a["actor_id"] for a in runtime["actors"]}:
            raise ValueError("task case and actor must be registered")
        order = list(GROUPS)
        local_seed = int(hashlib.sha256(f"{seed}|{case_id}|{task['task_id']}".encode()).hexdigest(), 16)
        random.Random(local_seed).shuffle(order)
        orders.append({"case_id": case_id, "task_id": task["task_id"], "order": order})
        for position, group in enumerate(order):
            session_id = str(uuid.uuid4())
            result = {"case_id": case_id, "task_id": task["task_id"], "actor_id": task["actor_id"],
                      "group": group, "order_position": position, "session_id": session_id,
                      "status": "ok", "answer": None, "error": None}
            try:
                if group == "authorized_reference":
                    memories = [{"source_id": r["source_id"], "text": r["text"]} for r in runtime["records"] if decision(r, task["actor_id"]) == "allow"]
                elif group == "migrated":
                    memories = available_from_http(adapter, task["actor_id"], plan)
                else:
                    memories = []
                context = retrieve(task["query"], memories, top_k, context_chars)
                result["retrieved_source_ids"] = [m["source_id"] for m in context]
                result["context_sha256"] = hashlib.sha256(json.dumps(context, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
                result["answer"] = answerer(query=task["query"], memories=context, session_id=session_id)
                if not isinstance(result["answer"], str):
                    raise TypeError("answerer must return a string")
            except Exception as exc:
                # Connector exceptions deliberately avoid remote error text or secrets.
                result.update(status="failed", answer=None, error=type(exc).__name__)
            results.append(result)
    return {"case_id": case_id, "answerer_kind": answerer.kind, "orders": orders, "runs": results,
            "pipeline": {"retrieval": "fixed_lexical_top_k", "top_k": top_k, "context_chars": context_chars,
                         "deduplicate_by": "registered_source_id", "tie_break": "source_id", "fresh_session_each_group": True},
            "runtime_isolation": "answerer receives only query, selected memories, fresh session; trusted host retains evaluation files; no OS sandbox claim"}


def score_runs(task_run: dict, evaluation: dict) -> dict:
    labels = evaluation["tasks"]
    if len({t["task_id"] for t in labels}) != len(labels):
        raise ValueError("duplicate evaluation task IDs")
    by_id = {t["task_id"]: t for t in labels}
    if any(t.get("task_type") not in {"authorized_fact", "denied_request"} for t in labels):
        raise ValueError("each evaluation task must preregister authorized_fact or denied_request")
    expected_ids = {r["task_id"] for r in task_run["runs"]}
    if set(by_id) != expected_ids:
        raise ValueError("evaluation must cover exactly the preregistered tasks")
    scores = []
    for run in task_run["runs"]:
        label = by_id[run["task_id"]]
        score = None if run["status"] != "ok" else int(run["answer"].strip() == label["expected_answer"].strip())
        disclosures = None if run["answer"] is None else [marker for marker in label.get("forbidden_markers", []) if marker in run["answer"]]
        scores.append({"task_id": run["task_id"], "case_id": run["case_id"], "group": run["group"], "score": score,
                       "task_type": label["task_type"],
                       "status": run["status"], "registered_marker_disclosures": disclosures,
                       "required_fact_source_ids": label.get("required_fact_source_ids", [])})
    groups = {}
    total = len(labels)
    for group in GROUPS:
        values = [s["score"] for s in scores if s["group"] == group]
        groups[group] = {"preregistered_tasks": total, "correct": sum(v == 1 for v in values),
                         "failed_or_unknown": sum(v is None for v in values),
                         "strict_success_rate": sum(v == 1 for v in values) / total if total else None,
                         "complete_mean_score": mean(values) if values and all(v is not None for v in values) else None}
        groups[group]["by_task_type"] = {}
        for task_type in ("authorized_fact", "denied_request"):
            typed = [s["score"] for s in scores if s["group"] == group and s["task_type"] == task_type]
            groups[group]["by_task_type"][task_type] = {"preregistered_tasks": len(typed), "correct": sum(v == 1 for v in typed),
                                                       "failed_or_unknown": sum(v is None for v in typed),
                                                       "strict_success_rate": sum(v == 1 for v in typed) / len(typed) if typed else None}
    paired = []
    for task_id in sorted(by_id):
        lookup = {s["group"]: s["score"] for s in scores if s["task_id"] == task_id}
        ref, migrated = lookup["authorized_reference"], lookup["migrated"]
        paired.append({"task_id": task_id, "reference_score": ref, "migrated_score": migrated,
                       "task_type": by_id[task_id]["task_type"],
                       "loss": ref - migrated if ref is not None and migrated is not None else None,
                       "reason": None if ref is not None and migrated is not None else "failed_or_unknown_pair"})
    losses = [p["loss"] for p in paired]
    legal_losses = [p["loss"] for p in paired if p["task_type"] == "authorized_fact"]
    metrics = {"groups": groups, "paired_tasks": paired,
               "complete_mean_loss": mean(losses) if losses and all(v is not None for v in losses) else None,
               "authorized_fact_complete_mean_loss": mean(legal_losses) if legal_losses and all(v is not None for v in legal_losses) else None,
               "independent_stories": 1, "uncertainty_interval": None, "semantic_disclosure": None,
               "scope": "narrow_exact_fact_tasks_descriptive_only"}
    offline = task_run["answerer_kind"] == "deterministic_instrumentation"
    return {"scores": scores, "instrumentation_metrics": metrics if offline else None,
            "real_llm_metrics": None if offline else metrics}
