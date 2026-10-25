"""Registered three-answerer A->B mechanism comparison, with missing controls.

Every task shares one authenticated G-mode preparation and one complete token
view. Span selection is exact input-position selection, not a trained PtrNet.
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
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from memory_migration_study.answer_serialization import canonicalize_answer
from memory_migration_study.detection_cache import detector_revision
from memory_migration_study.local_detector import LocalSensitivityAgent
from memory_migration_study.memory_generation_experiment import score_masking
from memory_migration_study.memory_labels import prepare_labeled_transfer, restore_labeled_answer
from memory_migration_study.ner_detector import GlinerEntityAgent, LocalNerRuntime
from memory_migration_study.privacy import _digest, _policy, detect_sensitive
from memory_migration_study.reference_memory import ReferenceMemoryBuilder, propose_fact_pool
from memory_migration_study.reuse_benchmark import save
from memory_migration_study.span_answer_evidence import build_span_evidence, resolve_span_evidence
from memory_migration_study.span_answerer import LocalSpanFactAnswerer
from memory_migration_study.union_detector import IndependentUnionDetector
from scripts.run_generation_union_transfer import AnnotationNerRecorder, _fact_identity, _volume
from scripts.run_policy_semantic_study import AuditedAuthority, SemanticTransport, event
from scripts.run_reference_memory_study import TypedCountingDetector, file_sha

VERSION = "span_answer_transfer_development_v1"
ARMS = ("free", "free_indexed", "span_pointer")
SEED, GENERATION_CAP = 2026102517, 264
CONTROL_ID = "missing_contact_email_control"
CONTROL_QUERIES = {"en": "What is the contact email address?", "zh": "联系人的电子邮箱地址是什么？"}


class AnswerTransport(SemanticTransport):
    def __init__(self, output, original):
        super().__init__(output, original)
        self.maximum, self.terminals = GENERATION_CAP, {}

    def append(self, record):
        if record["phase"] in {"response", "failure"}:
            self.terminals[record["index"]] = copy.deepcopy({**record, **self.context})
        super().append(record)


def _tasks(story):
    return [{**t, "task_class": "legal" if t["actor_id"] == "owner" else "outsider"} for t in story["tasks"]]+[
        {"task_id": CONTROL_ID, "actor_id": "owner", "query": CONTROL_QUERIES[story["language"]], "task_class": "missing"}]


def _current_access(authority, records, *, actor_id, agent_id, policy):
    for record in records:
        reason = authority.validate_access(record, actor_id=actor_id, agent_id=agent_id, policy_version=policy["version"])
        if reason:
            return reason
    return None


def _pointer_authorizer(prepared, records, authority, *, actor_id, agent_id, policy):
    original = prepared["original_payload"]["memories"]
    current = prepared["payload"]["memories"]
    if (len(original) != len(current) or len(current) != len(records)
            or any(m["source_id"] != r["record_id"] or m["text"] != r["text"] for m, r in zip(original, records))):
        return lambda *_: False
    aliases = {m["source_id"] for m in current}
    def authorize(source_id, actor, version):
        return (source_id in aliases and actor == actor_id and version == policy["version"]
                and _current_access(authority, records, actor_id=actor, agent_id=agent_id, policy=policy) is None)
    return authorize


def _score(row, expected):
    authorized = row["actor_id"] == "owner"
    final = row.get("final_answer")
    exact = authorized and isinstance(final, str) and final.strip().casefold() == expected.casefold()
    pointer = row["arm"] == "span_pointer"
    chose_unknown = (row.get("pointer_decision") == "UNKNOWN" if pointer else
        row.get("answer_status") == "ok" and (row.get("model_answer") or "").strip() == "UNKNOWN")
    correct = bool(exact and (row["task_class"] != "missing" or chose_unknown))
    mask = row["masking"]
    no_gap = mask.get("ready") is True and mask.get("partial") == mask.get("unmasked") == 0
    secondary = (row.get("secondary_serialization") or {}).get("final_answer")
    secondary_correct = authorized and isinstance(secondary, str) and secondary.strip().casefold() == expected.casefold()
    return {"authorized": authorized, "correct": correct,
        "joint_correct_no_masking_gap": bool(correct and no_gap), "model_chose_unknown": bool(chose_unknown),
        "unknown_with_required_fact": row["task_class"] == "legal" and row["required_fact_retained"] and bool(chose_unknown),
        "secondary_correct": bool(secondary_correct) if not pointer else None,
        "secondary_joint_correct_no_masking_gap": bool(secondary_correct and no_gap) if not pointer else None,
        "outsider_blocked": row["task_class"] == "outsider" and row.get("prepare_error") == "principal_not_authorized" and row["answer_calls"] == 0,
        "unauthorized_output": not authorized and (row["answer_calls"] > 0 or bool(final)),
        "restoration_failure": row.get("restoration_status") == "blocked"}


def _aggregate(rows):
    report = {}
    for arm in ARMS:
        selected = [r for r in rows if r["arm"] == arm]
        cells = {}
        for kind in ("legal", "missing", "outsider"):
            group = [r for r in selected if r["task_class"] == kind]
            cells[kind] = {"registered_tasks": len(group), "correct": sum(r["score"]["correct"] for r in group),
                "joint_correct_no_masking_gap": sum(r["score"]["joint_correct_no_masking_gap"] for r in group),
                "model_chose_unknown": sum(r["score"]["model_chose_unknown"] for r in group),
                "unknown_with_required_fact": sum(r["score"]["unknown_with_required_fact"] for r in group),
                "secondary_correct": None if arm == "span_pointer" else sum(r["score"]["secondary_correct"] for r in group),
                "outsider_blocked": sum(r["score"]["outsider_blocked"] for r in group),
                "unauthorized_output": sum(r["score"]["unauthorized_output"] for r in group),
                "answer_calls": sum(r["answer_calls"] for r in group),
                "label_set_unavailable": sum(r["union_label_set_status"] != "ok" for r in group),
                "prepare_blocked": sum(r["prepare_status"] != "ok" for r in group),
                "view_blocked": sum(r["prepare_status"] == "ok" and r["view_status"] != "ok" and arm != "free" for r in group),
                "resolver_blocked": sum(r.get("resolver_status") == "blocked" for r in group),
                "restoration_failure": sum(r["score"]["restoration_failure"] for r in group),
                "by_language": {lang: {"tasks": sum(r["language"] == lang for r in group),
                    "correct": sum(r["language"] == lang and r["score"]["correct"] for r in group)} for lang in ("en", "zh")}}
        report[arm] = cells
    return report


def _construct(story, authority, builder, detector, recorder, observer, revision):
    sid, source, policy = story["story_id"], story["source"], story["policy"]
    pool = propose_fact_pool(source["text"], source["source_id"])
    observer.stage("build", "common", sid)
    posts = observer.attempts
    built = builder(text=source["text"], source_id=source["source_id"], policy=policy, pool=pool)
    built = dict(built, story_id=sid, generation_calls_observed=observer.attempts-posts)
    annotations, candidates, records = [], [], []
    if built["status"] == "ok":
        if not 0 < len(built["facts"]) <= 8:
            raise ValueError("common_fact_count_contract_invalid")
        for index, fact in enumerate(built["facts"]):
            identity, fact_key = _fact_identity(source, fact)
            fid = fact["fid"]
            annotation_source = "write_"+fact_key[:32]
            payload = {"query": "", "memories": [{"source_id": annotation_source, "text": fact["text"]}]}
            observer.stage("write_annotation", "union_labels", sid)
            observer.context.update(fact_index=index, fid=fid, fact_key=fact_key)
            before, posts = dict(detector.counts), observer.attempts
            recorder.capture = []
            try:
                detection = detect_sensitive(payload, policy, mode="combined", agent=detector)
                members = copy.deepcopy(recorder.capture)
            finally:
                recorder.capture = None
            okay = (detection["status"] == "ok" and detection["local_calls_complete"] is True and detector.complete
                and detection.get("payload_sha256") == _digest(payload) and detection.get("policy_sha256") == _digest(_policy(policy)))
            findings = []
            if okay:
                for f in detection["findings"]:
                    if f["source_id"] != annotation_source:
                        raise ValueError("annotation_source_changed")
                    findings.append({k: f[k] for k in ("start", "end", "category")})
            candidates.append({**fact, "findings": findings, "status": "ok" if okay else "needs_review"})
            annotations.append({"story_id": sid, "fact_index": index, "fid": fid, "fact_key": fact_key, **identity,
                "annotation_source_id": annotation_source, "input_payload": payload, "detection": detection,
                "status": "ok" if okay else "needs_review", "member_raw_outputs": members,
                "generation_calls_observed": observer.attempts-posts, "request_indices": list(range(posts+1, observer.attempts+1)),
                "inference_counts": detector.delta(before)})
        if all(a["status"] == "ok" for a in annotations):
            records = [authority.build_record(source, fact, policy, owner_id="owner", readers=["owner"], agent_id="source-agent",
                allowed_agent_ids=["target-agent"], builder_version=built["builder_version"], detector_version=revision) for fact in candidates]
            records = json.loads(json.dumps(records, ensure_ascii=False))
    group_status = "ok" if records else "needs_review" if built["status"] == "ok" else "not_run"
    for item in annotations:
        item.update(group_status=group_status, eligible_for_store=bool(records))
    return built, pool, annotations, records, group_status


def render(output, report):
    text = ('<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>同输入回答机制对照</title>'
        '<style>body{font:16px/1.7 system-ui;margin:32px}td,th{border:1px solid #aaa;padding:8px}table{border-collapse:collapse}</style>'
        '<h1>共同授权输入：自由回答、索引自由回答、严格跨度指针</h1><p>每题一次G模式准备和同一完整token view。'
        '32道合法题、8道缺失邮箱控制、8道越权题分别计分。指针只是选择输入位置，不是PtrNet训练或创新证明。'
        '原始JSON、解析后字面值、最终核权恢复分别保存；指针无修复、猜测或补全。</p><table><tr><th>条件</th><th>合法正确/32</th>'
        '<th>合法安全联合/32</th><th>缺失UNKNOWN/8</th><th>越权阻断/8</th></tr>')
    for arm, cell in report["arms"].items():
        text += '<tr><td>'+html.escape(arm)+'</td>'+''.join('<td>'+str(n)+'</td>' for n in
            (cell["legal"]["correct"], cell["legal"]["joint_correct_no_masking_gap"], cell["missing"]["correct"], cell["outsider"]["outsider_blocked"]))+'</tr>'
    text += '</table><p><a href="plan.json">预注册</a> · <a href="rows.json">逐题</a> · <a href="shared_contexts.json">共享脱敏输入与公开视图</a> · <a href="report.json">汇总</a></p></html>'
    (output/"index.html").write_text(text, encoding="utf-8")


def run(corpus, output, model_root, config, observer, *, progress=None):
    corpus, output = Path(corpus), Path(output)
    runtime_bytes = (corpus/"development/runtime.json").read_bytes()
    evaluation_bytes = (corpus/"development/evaluation.json").read_bytes()
    runtime = json.loads(runtime_bytes)
    if (len(runtime) != 8 or len({s["story_id"] for s in runtime}) != 8
            or Counter(s["language"] for s in runtime) != {"en": 4, "zh": 4}
            or sum(len(s["tasks"]) for s in runtime) != 40
            or sum(t["actor_id"] == "owner" for s in runtime for t in s["tasks"]) != 32
            or any("@" in s["source"]["text"] or CONTROL_ID in {t["task_id"] for t in s["tasks"]} for s in runtime)):
        raise ValueError("registered_8_source_32_legal_8_outsider_and_missing_email_fixture_required")
    output.mkdir(parents=True, exist_ok=False)
    dependencies = [Path(__file__), ROOT/"scripts/run_generation_union_transfer.py", ROOT/"scripts/run_policy_semantic_study.py",
                    ROOT/"scripts/run_reference_memory_study.py", ROOT/"scripts/run_boundary_transfer_diagnostic.py"]
    files = list((ROOT/"memory_migration_study").glob("*.py"))+dependencies
    hashes = {str(p.relative_to(ROOT)): file_sha(p) for p in files}
    import shutil
    for path in files:
        target = output/"implementation"/path.relative_to(ROOT)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)
    plan = {"version": VERSION, "score_schema_version": "span_answer_final_answer_v1", "arms": list(ARMS),
        "source_stories": 8, "registered_tasks": 48, "expected_rows": 144,
        "legal_per_arm": 32, "missing_per_arm": 8, "outsider_per_arm": 8, "ordering_seed": SEED,
        "runtime_sha256": hashlib.sha256(runtime_bytes).hexdigest(), "evaluation_sha256": hashlib.sha256(evaluation_bytes).hexdigest(),
        "implementation_sha256": hashes, "config_sha256": _digest(config),
        "generation_limits": {"total": 264, "build": 16, "write_annotation": 128, "answer": 120},
        "prepare_mode": "generation", "privacy_pipeline": "legacy", "query_intent": False,
        "shared": "one fresh A fact construction and union label set per story; one prepare/request/table/view per task across three answerers",
        "missing_control": {"task_id": CONTROL_ID, "queries": CONTROL_QUERIES, "expected_answer": "UNKNOWN",
            "fixture_assertion": "All registered sources contain no contact email; absence of @ is asserted before any model. No gold-based task selection.",
            "pointer_correctness": "final UNKNOWN and accepted decision UNKNOWN; SPAN choosing literal UNKNOWN is not abstention"},
        "evaluation_timing": "after_all_model_processing_and_model_phase_closed",
        "secondary_serialization": "free/free_indexed only; same-output exact outer-brackets canonicalization then original restoration",
        "scope": "Exposed synthetic development; local signed JSON transfer and existing G-mode controls. Position selection, not trained PtrNet, downstream generalization, native portability or novelty evidence."}
    controls = [{"story_id": s["story_id"], "language": s["language"], **_tasks(s)[-1], "expected_answer": "UNKNOWN"} for s in runtime]
    for name, value in (("plan.json", plan), ("runtime.json", runtime), ("config.json", config), ("controls.json", controls)):
        save(output/name, value)
    ner = LocalNerRuntime(model_root)
    recorder = AnnotationNerRecorder(GlinerEntityAgent(ner, approved_policies=[s["policy"] for s in runtime]))
    base = TypedCountingDetector(recorder)
    local = LocalSensitivityAgent(config)
    health = local.health()
    union = TypedCountingDetector(IndependentUnionDetector(recorder, local, member_kinds=("local_encoder", "local_generation")))
    revision = detector_revision(union)
    builder = ReferenceMemoryBuilder(mode="select", detector=base, config=config)
    answerers = {arm: LocalSpanFactAnswerer(config, mode=arm) for arm in ARMS}
    save(output/"runtime_identity.json", {"ner": ner.identity, "local_generation": health, "union": union.cache_identity(),
        "union_detector_revision": revision, "base_detector": base.cache_identity(), "ner_initialization_seconds": ner.initialization_seconds})
    rows, builds, stores, annotations, pools, contexts, pending, journal = [], [], [], [], [], [], [], []
    prepare_invocations = 0
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
        for name, value in (("builds.json", builds), ("record_store.json", stores), ("annotations.json", annotations), ("pools.json", pools)):
            save(output/name, value)
        for task in _tasks(story):
            actor, request_id = task["actor_id"], secrets.token_hex(16)
            context_id = sid+":"+task["task_id"]
            authority.operation = context_id+":shared_prepare"
            event(journal, "prepare_start", operation=authority.operation, story_id=sid, task_id=task["task_id"], actor_id=actor,
                agent_id="target-agent", record_ids=[r["record_id"] for r in records], record_set_sha256=_digest(records),
                request_sha256=hashlib.sha256(request_id.encode()).hexdigest())
            observer.stage("prepare", "shared", sid, task["task_id"])
            before, posts_before = dict(base.counts), observer.attempts
            prepared = None
            if records:
                prepare_invocations += 1
                prepared = prepare_labeled_transfer(records, task["query"], policy, authority=authority, actor_id=actor,
                    agent_id="target-agent", request_id=request_id, mode="generation", agent=base,
                    label_requirements={"expected_builder_version": built["builder_version"], "expected_detector_version": revision})
            ready = prepared is not None and prepared["status"] == "ok"
            evidence = build_span_evidence(prepared["payload"], actor_id=actor, agent_id="target-agent", request_id=request_id,
                policy=policy) if ready else {"status": "not_built", "error": "transfer_not_ready", "view": None, "response_schema": None, "metadata": {}, "table": None}
            context = {"context_id": context_id, "story_id": sid, "task_id": task["task_id"], "task_class": task["task_class"],
                "actor_id": actor, "request_sha256": hashlib.sha256(request_id.encode()).hexdigest(),
                "prepare_status": prepared["status"] if prepared else "blocked", "prepare_error": prepared.get("error") if prepared else "label_set_unavailable",
                "payload": prepared["payload"] if ready else None,
                "payload_sha256": _digest(prepared["payload"]) if ready else None,
                "detection": prepared.get("detection") if prepared else None, "checks": prepared.get("checks") if prepared else [],
                "prepare_metadata": prepared.get("metadata") if prepared else {}, "egress": prepared.get("egress") if prepared else None,
                "prepare_inference_counts": base.delta(before), "prepare_generation_calls_observed": observer.attempts-posts_before,
                "view_status": evidence["status"], "view_error": evidence["error"], "view": evidence["view"],
                "response_schema": evidence["response_schema"], "view_metadata": evidence["metadata"]}
            context["context_sha256"] = _digest(context)
            contexts.append(context)
            current_auth = _pointer_authorizer(prepared, records, authority, actor_id=actor, agent_id="target-agent", policy=policy) if ready else None
            order = list(ARMS)
            random.Random(f"{SEED}:{context_id}").shuffle(order)
            task_rows = []
            for arm in order:
                authority.operation = context_id+":"+arm
                row = {"story_id": sid, "task_id": task["task_id"], "task_class": task["task_class"], "actor_id": actor,
                    "language": story["language"], "template_family": story["template_family"], "arm": arm,
                    "context_id": context_id, "context_sha256": context["context_sha256"], "mode": "generation",
                    "common_build_status": built["status"], "union_label_set_status": group_status,
                    "prepare_status": context["prepare_status"], "prepare_error": context["prepare_error"], "view_status": evidence["status"],
                    "answer_status": "not_run", "answer_calls": 0, "model_answer": None, "raw_model_answer": None,
                    "answer_for_restore": None, "pointer_decision": None, "resolver_status": "not_run", "source_span": None,
                    "final_answer": None, "restoration_status": None,
                    "secondary_serialization_registered": arm != "span_pointer"}
                if ready:
                    reason = _current_access(authority, records, actor_id=actor, agent_id="target-agent", policy=policy)
                    if reason:
                        row.update(answer_error=reason, answer_status="blocked")
                    elif arm != "free" and evidence["status"] != "ok":
                        row.update(answer_error="span_view_unavailable", answer_status="blocked")
                    else:
                        observer.stage("answer", arm, sid, task["task_id"])
                        before_post = observer.attempts
                        response = answerers[arm](prepared["payload"], view=evidence["view"],
                            response_schema=evidence["response_schema"], evidence_table=evidence["table"])
                        row.update(answer_status=response["status"], answer_error=response.get("error"), answer_calls=response["local_calls"],
                            model_answer=response.get("answer"), answer_metadata=response.get("metadata"),
                            answer_request_indices=list(range(before_post+1, observer.attempts+1)),
                            prepared_payload_sha256=context["payload_sha256"])
                        if row["answer_calls"] != observer.attempts-before_post or row["answer_calls"] > 1:
                            raise ValueError("single_answer_call_accounting_mismatch")
                        terminal = observer.terminals.get(observer.attempts) if row["answer_calls"] else None
                        if terminal and terminal["phase"] == "response":
                            row["raw_model_answer"] = terminal["response"].get("message", {}).get("content")
                        if response["status"] == "ok":
                            answer = response["answer"]
                            if arm == "span_pointer":
                                reason = _current_access(authority, records, actor_id=actor, agent_id="target-agent", policy=policy)
                                resolved = ({"status": "blocked", "answer": None, "source_span": None, "error": reason} if reason else
                                    resolve_span_evidence(answer, evidence["table"], prepared["payload"], actor_id=actor, agent_id="target-agent",
                                        request_id=request_id, policy=policy, authorizer=current_auth))
                                row.update(resolver_status=resolved["status"], resolver_error=resolved.get("error"), source_span=resolved.get("source_span"))
                                answer = resolved.get("answer") if resolved["status"] == "ok" else None
                                if resolved["status"] == "ok":
                                    row["pointer_decision"] = "UNKNOWN" if resolved["source_span"] is None else "SPAN"
                            row["answer_for_restore"] = answer
                            if answer is not None:
                                restored = restore_labeled_answer(answer, prepared, records, policy, authority=authority,
                                    actor_id=actor, agent_id="target-agent", request_id=request_id)
                                row.update(final_answer=restored.get("answer"), restoration_status=restored["status"], restoration_error=restored.get("error"))
                            if arm != "span_pointer":
                                canonical = canonicalize_answer(response["answer"], prepared["payload"])
                                secondary = restore_labeled_answer(canonical["answer"], prepared, records, policy, authority=authority,
                                    actor_id=actor, agent_id="target-agent", request_id=request_id)
                                row["secondary_serialization"] = {"decision": canonical["decision"], "canonical_answer": canonical["answer"],
                                    "final_answer": secondary.get("answer"), "restoration_status": secondary["status"], "restoration_error": secondary.get("error")}
                rows.append(row)
                task_rows.append(row)
                event(journal, "arm_processing_end", operation=authority.operation, answer_calls=row["answer_calls"],
                    answer_status=row["answer_status"], resolver_status=row["resolver_status"])
                if progress:
                    progress({"completed": len(rows), "expected": 144, "story": sid, "arm": arm, "scored": False})
            pending.append((task_rows, story, task, records, prepared))
            evidence["table"] = None
            for name, value in (("shared_contexts.json", contexts), ("rows.json", rows), ("auth_events.json", journal)):
                save(output/name, value)
    if (len(rows) != 144 or file_sha(corpus/"development/runtime.json") != plan["runtime_sha256"]
            or file_sha(corpus/"development/evaluation.json") != plan["evaluation_sha256"]):
        raise ValueError("study_matrix_or_source_changed")
    observer.model_phase_closed = True
    event(journal, "model_phase_closed", actual_generation_attempts=observer.attempts)
    evaluation = json.loads(evaluation_bytes)
    if set(evaluation) != {s["story_id"] for s in runtime}:
        raise ValueError("evaluation_story_mismatch")
    for group, story, task, records, prepared in pending:
        gold = evaluation[story["story_id"]]
        expected = "UNKNOWN" if task["task_class"] == "missing" else gold["answers"].get(task["task_id"], "")
        mask = score_masking(story, gold, records, prepared or {"status": "blocked"})
        for row in group:
            row["required_fact_retained"] = bool(task["task_class"] == "legal" and expected and any(expected in r["text"] for r in records))
            row["masking"] = mask
            row["score"] = _score(row, expected)
        if prepared:
            prepared["mapping"] = None
    pending.clear()
    for name, value in (("rows.json", rows), ("evaluation.json", evaluation), ("auth_events.json", journal)):
        save(output/name, value)
    if hashes != {str(p.relative_to(ROOT)): file_sha(p) for p in files}:
        raise ValueError("implementation_changed_during_study")
    events = [json.loads(line) for line in (output/"request_transport.jsonl").read_text(encoding="utf-8").splitlines()]
    posts = [e for e in events if e["phase"] == "request"]
    report = {"version": VERSION, "registered_rows": 144, "recorded_rows": len(rows), "registered_tasks": 48,
        "source_stories": 8, "common_build_failures": sum(b["status"] != "ok" for b in builds),
        "union_label_set_failures": sum(s["union_label_set_status"] != "ok" for s in stores),
        "shared_prepare_invocations": prepare_invocations, "shared_contexts": len(contexts), "arms": _aggregate(rows),
        "generation_calls_observed": observer.attempts,
        **{field: sum(e["stage"] == stage for e in posts) for field, stage in
            (("builder_generations", "build"), ("write_annotation_generations", "write_annotation"), ("answer_generations", "answer"))},
        "build_encoder_calls": sum(b["inference_counts"]["local_encoder"] for b in builds),
        "write_annotation_encoder_calls": sum(a["inference_counts"]["local_encoder"] for a in annotations),
        "shared_prepare_encoder_calls": sum(c["prepare_inference_counts"]["local_encoder"] for c in contexts),
        "total_encoder_calls": base.counts["local_encoder"]+union.counts["local_encoder"],
        "detector_call_accounting_complete": base.complete and union.complete,
        "implementation_unchanged": True, "closed_phase_attempts": observer.closed_phase_attempts,
        "cloud_calls": 0, "new_api_cost_cny": 0, "scope": plan["scope"]}
    save(output/"report.json", report)
    render(output, report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
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
    observer, completed, started = AnswerTransport(output, LocalSensitivityAgent._transport), False, time.monotonic()
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
