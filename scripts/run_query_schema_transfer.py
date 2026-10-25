"""Two fixed query schemas over common authentic A facts and union labels.

Exposed development comparison, not a production default or novelty claim.
"""
from __future__ import annotations
import argparse
import copy
from collections import Counter
import hashlib
import html
import json
from pathlib import Path
import random
import secrets
import shutil
import sys
import time
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from memory_migration_study import privacy
from memory_migration_study.answer_serialization import canonicalize_answer
from memory_migration_study.detection_cache import detector_revision
from memory_migration_study.local_detector import LocalSensitivityAgent
from memory_migration_study.memory_generation_experiment import LocalFactAnswerer, score_masking
from memory_migration_study.memory_labels import prepare_labeled_transfer, restore_labeled_answer
from memory_migration_study.ner_detector import GlinerEntityAgent, LocalNerRuntime, LABELS
from memory_migration_study.privacy import QUERY_SOURCE, _digest, _policy
from memory_migration_study.reference_memory import ReferenceMemoryBuilder
from memory_migration_study.reuse_benchmark import save
from memory_migration_study.union_detector import IndependentUnionDetector
from scripts.run_customer_schema_probe import POLICY, schemas, _infer
from scripts.run_generation_union_transfer import AnnotationNerRecorder, _volume
from scripts.run_policy_semantic_study import AuditedAuthority, event
from scripts.run_reference_memory_study import TypedCountingDetector, file_sha
from scripts.run_span_answer_transfer import AnswerTransport, _construct, _tasks, _current_access, _score, CONTROL_ID, CONTROL_QUERIES

VERSION = "query_schema_transfer_development_v1"
ARMS = ("A", "B")
SEED, GENERATION_CAP = 2026102519, 224


class QueryTransport(AnswerTransport):
    def __init__(self, output, original):
        super().__init__(output, original)
        self.maximum = GENERATION_CAP


class SchemaRuntimeProxy:
    """Serial local schema substitution; translate labels, never entity text."""
    def __init__(self, runtime, arm, events):
        if arm not in ARMS:
            raise ValueError("invalid_query_schema_arm")
        self.runtime, self.arm, self.events, self.context = runtime, arm, events, {}
        self.schema = copy.deepcopy(schemas()[arm])
        self.identity = {"original_runtime": copy.deepcopy(runtime.identity), "query_schema_arm": arm,
            "actual_schema": self.schema, "schema_sha256": _digest(self.schema),
            "approved_policy_sha256": _digest(_policy(POLICY)), "splitter": "cjk_aware", "threshold": .5,
            "max_encoded_tokens": 512, "proxy_source_sha256": file_sha(Path(__file__))}

    def infer(self, text, labels, *, splitter, threshold):
        expected = {LABELS["CUSTOMER"][0]: LABELS["CUSTOMER"][1]}
        if labels != expected or splitter != "cjk_aware" or threshold != .5:
            raise ValueError("query_schema_input_contract_invalid")
        actual = {self.schema["CUSTOMER"][0]: self.schema["CUSTOMER"][1]}
        observed = _infer(self.runtime, text, actual)
        translated = None
        raw = observed["raw_result"]
        if observed["status"] == "ok":
            if not isinstance(raw, dict) or set(raw) != {"entities"} or not isinstance(raw["entities"], dict) or set(raw["entities"])-set(actual):
                observed.update(status="needs_review", error="query_schema_unrecognized_model_label")
            else:
                translated = {"entities": {LABELS["CUSTOMER"][0]: copy.deepcopy(raw["entities"].get(self.schema["CUSTOMER"][0], []))}}
        self.events.append({"event_index": len(self.events), **copy.deepcopy(self.context),
            "text": text, "text_sha256": hashlib.sha256(text.encode()).hexdigest(), "arm": self.arm,
            "requested_labels": copy.deepcopy(labels), "actual_labels": actual,
            "full_schema_sha256": _digest(self.schema), "label_translation": {self.schema["CUSTOMER"][0]: LABELS["CUSTOMER"][0]},
            "translated_result": translated, **observed})
        if observed["status"] != "ok":
            raise ValueError(observed["error"])
        return translated


class QuerySchemaAgent:
    max_local_calls = 1
    def __init__(self, runtime, arm, events):
        self.proxy = SchemaRuntimeProxy(runtime, arm, events)
        self.query = GlinerEntityAgent(self.proxy, approved_policies=[POLICY])
        self.fallback = GlinerEntityAgent(runtime, approved_policies=[POLICY])
        self.events, self.context = events, {}

    def cache_identity(self):
        return {"query": self.query.cache_identity(), "fallback": self.fallback.cache_identity(),
            "approved_policy": _policy(POLICY), "source_sha256": file_sha(Path(__file__)),
            "scope": "query-only schema; invalid-label memory fallback keeps original production labels"}

    def __call__(self, *, text, source_id, policy, rule_findings):
        if _digest(_policy(policy)) != _digest(_policy(POLICY)):
            return {"status": "needs_review", "findings": [], "errors": ["query_schema_policy_not_approved"],
                "local_calls": 0, "local_calls_complete": True, "elapsed_seconds": 0,
                "inference_kind": "local_encoder", "diagnostics": []}
        if source_id != QUERY_SOURCE:
            return self.fallback(text=text, source_id=source_id, policy=policy, rule_findings=rule_findings)
        before = len(self.events)
        self.proxy.context = {**self.context, "source_id": source_id, "policy_sha256": _digest(_policy(policy))}
        result = self.query(text=text, source_id=source_id, policy=policy, rule_findings=rule_findings)
        observed = self.events[before:]
        physical = sum(r["extract_entities_calls"] for r in observed)
        if len(observed) > 1 or physical not in {0, 1}:
            raise ValueError("query_schema_physical_call_accounting_invalid")
        return {**result, "local_calls": physical, "local_calls_complete": True}


def _aggregate(rows):
    report = {}
    for arm in ARMS:
        report[arm] = {}
        for kind in ("legal", "missing", "outsider"):
            selected = [r for r in rows if r["arm"] == arm and r["task_class"] == kind]
            report[arm][kind] = {"registered_tasks": len(selected),
                **{key: sum(r["score"][key] for r in selected) for key in ("correct", "joint_correct_no_masking_gap",
                    "model_chose_unknown", "unknown_with_required_fact", "secondary_correct", "secondary_joint_correct_no_masking_gap", "outsider_blocked", "unauthorized_output", "restoration_failure")},
                "answer_calls": sum(r["answer_calls"] for r in selected),
                "prepare_blocked": sum(r["prepare_status"] != "ok" for r in selected),
                "label_set_unavailable": sum(r["union_label_set_status"] != "ok" for r in selected),
                "by_language": {lang: {"tasks": sum(r["language"] == lang for r in selected),
                    "correct": sum(r["language"] == lang and r["score"]["correct"] for r in selected)} for lang in ("en", "zh")}}
    return report


def render(output, report):
    text = '<!doctype html><meta charset="utf-8"><title>查询schema A→B对照</title><h1>固定查询schema：完整A→B开发对照</h1><p>共同真实构建及Union生成标签；只有查询模型的CUSTOMER schema不同。每题配对序列化随机性，独立核权与恢复。不是默认改动、盲测或创新证明。</p><table border="1"><tr><th>arm</th><th>合法/32</th><th>安全联合/32</th><th>缺失UNKNOWN/8</th><th>越权阻断/8</th></tr>'
    for arm, cell in report["arms"].items():
        text += '<tr><td>'+html.escape(arm)+'</td>'+''.join('<td>'+str(x)+'</td>' for x in (cell["legal"]["correct"], cell["legal"]["joint_correct_no_masking_gap"], cell["missing"]["correct"], cell["outsider"]["outsider_blocked"]))+'</tr>'
    text += '</table><p><a href="rows.json">逐题原始输入/回答/主次成绩</a> · <a href="query_encoder_events.json">实际schema与原始编码响应</a> · <a href="plan.json">预注册</a></p>'
    (output/"index.html").write_text(text, encoding="utf-8")


def run(corpus, output, model_root, config, observer, *, progress=None):
    corpus, output = Path(corpus), Path(output)
    runtime_bytes = (corpus/"development/runtime.json").read_bytes()
    evaluation_bytes = (corpus/"development/evaluation.json").read_bytes()
    runtime = json.loads(runtime_bytes)
    original_labels = _digest(LABELS)
    if (len(runtime) != 8 or len({s["story_id"] for s in runtime}) != 8 or Counter(s["language"] for s in runtime) != {"en": 4, "zh": 4}
            or sum(len(s["tasks"]) for s in runtime) != 40 or sum(t["actor_id"] == "owner" for s in runtime for t in s["tasks"]) != 32
            or any("@" in s["source"]["text"] or CONTROL_ID in {t["task_id"] for t in s["tasks"]} for s in runtime)
            or any(_digest(_policy(s["policy"])) != _digest(_policy(POLICY)) for s in runtime)):
        raise ValueError("registered_customer_scope_8_source_48_task_protocol_required")
    output.mkdir(parents=True, exist_ok=False)
    files = list((ROOT/"memory_migration_study").glob("*.py"))+[Path(__file__)]+[ROOT/"scripts"/n for n in
        ("run_span_answer_transfer.py", "run_customer_schema_probe.py", "run_generation_union_transfer.py", "run_policy_semantic_study.py", "run_reference_memory_study.py", "run_boundary_transfer_diagnostic.py")]
    hashes = {str(p.relative_to(ROOT)): file_sha(p) for p in files}
    for path in files:
        target = output/"implementation"/path.relative_to(ROOT)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)
    plan = {"version": VERSION, "score_schema_version": "query_schema_final_answer_v1", "arms": list(ARMS),
        "source_stories": 8, "registered_tasks": 48, "expected_rows": 96, "legal_per_arm": 32, "missing_per_arm": 8, "outsider_per_arm": 8,
        "runtime_sha256": hashlib.sha256(runtime_bytes).hexdigest(), "evaluation_sha256": hashlib.sha256(evaluation_bytes).hexdigest(),
        "implementation_sha256": hashes, "config_sha256": _digest(config), "ordering_seed": SEED,
        "schemas": schemas(), "schema_sha256": {a: _digest(s) for a, s in schemas().items()}, "approved_policy": _policy(POLICY),
        "threshold": .5, "splitter": "cjk_aware", "max_encoded_tokens": 512,
        "prepare_mode": "generation", "privacy_pipeline": "legacy", "source_annotation": "unchanged default NER plus independent local Qwen union per fact",
        "generation_limits": {"total": 224, "build": 16, "write_annotation": 128, "answer": 80},
        "serialization_control": "counterfactual paired randomness: one genuine token_hex(12) per task; each privacy-only scoped secrets binding permits exactly one n=12 call. No global secrets mutation. Independent maps/ACL/restoration per arm.",
        "missing_control": {"queries": CONTROL_QUERIES, "expected_answer": "UNKNOWN", "source_assertion": "no source contact email; @ absent before model, no gold-based selection"},
        "evaluation_timing": "after_all_model_processing_and_model_phase_closed",
        "secondary_serialization": "same model output exact current-token outer brackets then original full restoration",
        "scope": "Fixed customer-policy exposed development, A-to-B signed JSON local host; no production default, native backend, generalization or novelty claim."}
    for name, value in (("plan.json", plan), ("runtime.json", runtime), ("config.json", config),
        ("controls.json", [{"story_id": s["story_id"], "language": s["language"], **_tasks(s)[-1], "expected_answer": "UNKNOWN"} for s in runtime])):
        save(output/name, value)
    ner = LocalNerRuntime(model_root)
    recorder = AnnotationNerRecorder(GlinerEntityAgent(ner, approved_policies=[POLICY]))
    base = TypedCountingDetector(recorder)
    local = LocalSensitivityAgent(config)
    health = local.health()
    union = TypedCountingDetector(IndependentUnionDetector(recorder, local, member_kinds=("local_encoder", "local_generation")))
    revision = detector_revision(union)
    query_events = []
    query_agents = {arm: QuerySchemaAgent(ner, arm, query_events) for arm in ARMS}
    detectors = {arm: TypedCountingDetector(query_agents[arm]) for arm in ARMS}
    builder, answerer = ReferenceMemoryBuilder(mode="select", detector=base, config=config), LocalFactAnswerer(config)
    save(output/"runtime_identity.json", {"ner": ner.identity, "local_generation": health, "union": union.cache_identity(),
        "union_detector_revision": revision, "query_detectors": {a: d.cache_identity() for a, d in detectors.items()}, "ner_initialization_seconds": ner.initialization_seconds})
    rows, builds, stores, annotations, pools, pending, journal, paired = [], [], [], [], [], [], [], []
    for story in runtime:
        sid, policy = story["story_id"], story["policy"]
        authority = AuditedAuthority(secrets.token_bytes(32), journal)
        before = dict(base.counts)
        built, pool, labeled, records, group_status = _construct(story, authority, builder, union, recorder, observer, revision)
        built.update(inference_counts=base.delta(before), **_volume(records, story["source"]))
        builds.append(built)
        pools.append({"story_id": sid, "pool": pool})
        annotations.extend(labeled)
        stores.append({"story_id": sid, "builder": "union", "records": records, "union_label_set_status": group_status})
        for task in _tasks(story):
            actor, request_id, nonce = task["actor_id"], secrets.token_hex(16), secrets.token_hex(12)
            context_id = sid+":"+task["task_id"]
            pair = {"context_id": context_id, "story_id": sid, "task_id": task["task_id"], "task_class": task["task_class"], "actor_id": actor,
                "request_sha256": hashlib.sha256(request_id.encode()).hexdigest(), "paired_nonce_sha256": hashlib.sha256(nonce.encode()).hexdigest(), "records_sha256": _digest(records)}
            paired.append(pair)
            order = list(ARMS)
            random.Random(f"{SEED}:{context_id}").shuffle(order)
            for arm in order:
                authority.operation = context_id+":"+arm
                detector = detectors[arm]
                query_agents[arm].context = {"context_id": context_id, "story_id": sid, "task_id": task["task_id"], "operation": authority.operation}
                event(journal, "prepare_start", operation=authority.operation, agent_id="target-agent", record_ids=[r["record_id"] for r in records], **pair)
                observer.stage("prepare", arm, sid, task["task_id"])
                before, posts, event_start, nonce_calls = dict(detector.counts), observer.attempts, len(query_events), []
                def paired_token_hex(n):
                    if type(n) is not int or n != 12 or nonce_calls:
                        raise ValueError("paired_serialization_nonce_contract_invalid")
                    nonce_calls.append(12)
                    return nonce
                with patch.object(privacy, "secrets", SimpleNamespace(token_hex=paired_token_hex)):
                    prepared = prepare_labeled_transfer(records, task["query"], policy, authority=authority, actor_id=actor,
                        agent_id="target-agent", request_id=request_id, mode="generation", agent=detector,
                        label_requirements={"expected_builder_version": built["builder_version"], "expected_detector_version": revision}) if records else None
                ready = prepared is not None and prepared["status"] == "ok"
                if ready and nonce_calls != [12] or actor != "owner" and nonce_calls:
                    raise ValueError("paired_serialization_call_count_invalid")
                row = {**pair, "language": story["language"], "template_family": story["template_family"], "arm": arm, "mode": "generation",
                    "common_build_status": built["status"], "union_label_set_status": group_status, "serialization_nonce_calls": len(nonce_calls),
                    "prepare_status": prepared["status"] if prepared else "blocked", "prepare_error": prepared.get("error") if prepared else "label_set_unavailable",
                    "outbound": prepared["payload"] if ready else None, "actual_payload_sha256": _digest(prepared["payload"]) if ready else None,
                    "detection": prepared.get("detection") if prepared else None, "checks": prepared.get("checks") if prepared else [],
                    "prepare_metadata": prepared.get("metadata") if prepared else {}, "egress": prepared.get("egress") if prepared else None,
                    "inference_counts": detector.delta(before), "prepare_generation_calls_observed": observer.attempts-posts,
                    "query_encoder_event_indices": list(range(event_start, len(query_events))),
                    "answer_status": "not_run", "answer_calls": 0, "model_answer": None, "raw_model_answer": None,
                    "final_answer": None, "restoration_status": None, "secondary_serialization_registered": True}
                if ready:
                    reason = _current_access(authority, records, actor_id=actor, agent_id="target-agent", policy=policy)
                    if reason:
                        row.update(answer_status="blocked", answer_error=reason)
                    else:
                        observer.stage("answer", arm, sid, task["task_id"])
                        posts = observer.attempts
                        response = answerer(prepared["payload"])
                        row.update(answer_status=response["status"], answer_error=response.get("error"), answer_calls=response["local_calls"],
                            model_answer=response.get("answer"), answer_request_indices=list(range(posts+1, observer.attempts+1)))
                        if row["answer_calls"] != observer.attempts-posts or row["answer_calls"] > 1:
                            raise ValueError("single_answer_call_accounting_mismatch")
                        terminal = observer.terminals.get(observer.attempts) if row["answer_calls"] else None
                        if terminal and terminal["phase"] == "response":
                            row["raw_model_answer"] = terminal["response"].get("message", {}).get("content")
                        if response["status"] == "ok":
                            restored = restore_labeled_answer(response["answer"], prepared, records, policy, authority=authority,
                                actor_id=actor, agent_id="target-agent", request_id=request_id)
                            row.update(final_answer=restored.get("answer"), restoration_status=restored["status"], restoration_error=restored.get("error"))
                            canonical = canonicalize_answer(response["answer"], prepared["payload"])
                            secondary = restore_labeled_answer(canonical["answer"], prepared, records, policy, authority=authority,
                                actor_id=actor, agent_id="target-agent", request_id=request_id)
                            row["secondary_serialization"] = {"decision": canonical["decision"], "canonical_answer": canonical["answer"], "final_answer": secondary.get("answer"),
                                "restoration_status": secondary["status"], "restoration_error": secondary.get("error")}
                rows.append(row)
                pending.append((row, story, task, records, prepared))
                event(journal, "task_processing_end", operation=authority.operation, prepare_status=row["prepare_status"], answer_calls=row["answer_calls"])
                if progress:
                    progress({"completed": len(rows), "expected": 96, "story": sid, "arm": arm, "scored": False})
            for name, value in (("rows.json", rows), ("paired_contexts.json", paired), ("query_encoder_events.json", query_events), ("auth_events.json", journal),
                ("builds.json", builds), ("record_store.json", stores), ("annotations.json", annotations), ("pools.json", pools)):
                save(output/name, value)
    if (len(rows) != 96 or _digest(LABELS) != original_labels or file_sha(corpus/"development/runtime.json") != plan["runtime_sha256"]
            or file_sha(corpus/"development/evaluation.json") != plan["evaluation_sha256"]):
        raise ValueError("matrix_labels_or_source_changed")
    observer.model_phase_closed = True
    event(journal, "model_phase_closed", actual_generation_attempts=observer.attempts)
    evaluation = json.loads(evaluation_bytes)
    if set(evaluation) != {s["story_id"] for s in runtime}:
        raise ValueError("evaluation_story_mismatch")
    for row, story, task, records, prepared in pending:
        gold = evaluation[story["story_id"]]
        expected = "UNKNOWN" if task["task_class"] == "missing" else gold["answers"].get(task["task_id"], "")
        row["required_fact_retained"] = bool(task["task_class"] == "legal" and expected and any(expected in r["text"] for r in records))
        row["masking"] = score_masking(story, gold, records, prepared or {"status": "blocked"})
        row["score"] = _score(row, expected)
        if prepared:
            prepared["mapping"] = None
    pending.clear()
    for name, value in (("rows.json", rows), ("evaluation.json", evaluation), ("auth_events.json", journal)):
        save(output/name, value)
    if hashes != {str(p.relative_to(ROOT)): file_sha(p) for p in files} or _digest(LABELS) != original_labels:
        raise ValueError("implementation_or_default_labels_changed")
    events = [json.loads(line) for line in (output/"request_transport.jsonl").read_text(encoding="utf-8").splitlines()]
    posts = [e for e in events if e["phase"] == "request"]
    report = {"version": VERSION, "registered_rows": 96, "recorded_rows": len(rows), "source_stories": 8,
        "registered_tasks": 48, "common_build_failures": sum(b["status"] != "ok" for b in builds),
        "union_label_set_failures": sum(s["union_label_set_status"] != "ok" for s in stores), "arms": _aggregate(rows),
        "generation_calls_observed": observer.attempts, **{field: sum(e["stage"] == stage for e in posts) for field, stage in
            (("builder_generations", "build"), ("write_annotation_generations", "write_annotation"), ("answer_generations", "answer"))},
        "build_encoder_calls": base.counts["local_encoder"], "write_annotation_encoder_calls": union.counts["local_encoder"],
        "query_prepare_encoder_calls": {a: d.counts["local_encoder"] for a, d in detectors.items()},
        "query_model_extract_entities_calls": sum(e["extract_entities_calls"] for e in query_events),
        "total_encoder_calls": base.counts["local_encoder"]+union.counts["local_encoder"]+sum(d.counts["local_encoder"] for d in detectors.values()),
        "detector_call_accounting_complete": base.complete and union.complete and all(d.complete for d in detectors.values()),
        "implementation_unchanged": True, "default_labels_unchanged": True, "closed_phase_attempts": observer.closed_phase_attempts,
        "cloud_calls": 0, "new_api_cost_cny": 0, "scope": plan["scope"]}
    save(output/"report.json", report)
    render(output, report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists() or not output.is_relative_to(ROOT/"results"):
        raise ValueError("new_project_results_directory_required")
    network = {"loopback_connections": 0, "external_attempts_blocked": 0}
    def guard(name, values):
        if name == "socket.connect":
            address = values[1]
            if not isinstance(address, tuple) or address[0] not in {"127.0.0.1", "::1"}:
                network["external_attempts_blocked"] += 1
                raise RuntimeError("external_network_disabled")
            network["loopback_connections"] += 1
    sys.addaudithook(guard)
    config = json.loads((ROOT/"configs/local_privacy_detector.json").read_bytes())
    observer, completed, started = QueryTransport(output, LocalSensitivityAgent._transport), False, time.monotonic()
    try:
        with observer.installed():
            run(ROOT/"examples/privacy_semantics_v1", output, ROOT/".runtime/github_ner", config, observer,
                progress=lambda value: print(json.dumps(value), flush=True))
        completed = True
    finally:
        if output.exists():
            summary = dict(observer.summary(), completed=completed, elapsed_seconds=time.monotonic()-started,
                network=network, registered_protocol=VERSION, closed_phase_attempts=observer.closed_phase_attempts,
                python_executable=sys.executable, python_version=sys.version)
            save(output/"transport_audit.json", summary)
            save(output/"network_audit.json", network)
            print(json.dumps({"output": str(output), "audit": summary}, ensure_ascii=False), flush=True)


if __name__ == "__main__":
    main()
