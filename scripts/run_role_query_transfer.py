"""Plan-first exposed development comparison: free / lexical join / query-role join.

The method never reads evaluation labels. Exact-source construction and Union
labels are shared; authorization, canonical formatting and old restoration stay
mandatory. This is an engineering comparison, not independent acceptance.
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

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from memory_migration_study.answer_serialization import canonicalize_answer
from memory_migration_study.detection_cache import detector_revision
from memory_migration_study.local_detector import LocalSensitivityAgent
from memory_migration_study.memory_generation_experiment import LocalFactAnswerer, score_masking
from memory_migration_study.memory_labels import prepare_labeled_transfer, restore_labeled_answer
from memory_migration_study.ner_detector import GlinerEntityAgent, LocalNerRuntime, LABELS
from memory_migration_study.privacy import _digest, _policy
from memory_migration_study.reference_memory import ReferenceMemoryBuilder
from memory_migration_study.reuse_benchmark import save
from memory_migration_study.union_detector import IndependentUnionDetector
from memory_migration_study import role_query
from scripts.run_customer_schema_probe import POLICY
from scripts.run_generation_union_transfer import AnnotationNerRecorder, _volume
from scripts.run_policy_semantic_study import AuditedAuthority, event
from scripts.run_query_schema_transfer import QuerySchemaAgent
from scripts.run_reference_memory_study import TypedCountingDetector, file_sha
from scripts.run_span_answer_transfer import AnswerTransport, _construct, _tasks, _current_access, _pointer_authorizer, CONTROL_ID, CONTROL_QUERIES

VERSION = "source_role_query_join_development_v1"
ARMS = ("F", "Q0", "Q1")
SEED = 2026102601
LIMITS = {"build": 16, "write_annotation": 128, "answer": 80}
MAX_CALLS = sum(LIMITS.values())


class RoleQueryTransport(AnswerTransport):
    def __init__(self, output, original):
        super().__init__(output, original)
        self.maximum = MAX_CALLS
        self.stage_counts = Counter()

    def call(self, client, method, path, body):
        if method == "POST":
            stage = self.context["stage"]
            if stage not in LIMITS or self.stage_counts[stage] >= LIMITS[stage]:
                raise ValueError("registered_stage_cap_reached")
            if stage == "answer" and self.context["arm"] not in {"F", "Q1"}:
                raise ValueError("non_model_arm_attempted_generation")
        return super().call(client, method, path, body)

    def append(self, record):
        if record["phase"] == "request":
            self.stage_counts[self.context["stage"]] += 1
        super().append(record)


def implementation_files():
    names = ("run_span_answer_transfer.py", "run_customer_schema_probe.py", "run_generation_union_transfer.py",
             "run_policy_semantic_study.py", "run_reference_memory_study.py", "run_boundary_transfer_diagnostic.py",
             "run_query_schema_transfer.py", "verify_role_query_transfer.py")
    return sorted(set(list((ROOT/"memory_migration_study").glob("*.py")) + [Path(__file__)] +
                      [ROOT/"scripts"/name for name in names]))


def protocol(corpus, config):
    corpus = Path(corpus)
    raw = (corpus/"development/runtime.json").read_bytes()
    evaluation = (corpus/"development/evaluation.json").read_bytes()
    runtime = json.loads(raw)
    if (len(runtime) != 8 or Counter(s["language"] for s in runtime) != {"en": 4, "zh": 4}
            or len({s["story_id"] for s in runtime}) != 8
            or sum(len(s["tasks"]) for s in runtime) != 40
            or sum(t["actor_id"] == "owner" for s in runtime for t in s["tasks"]) != 32
            or any("@" in s["source"]["text"] or CONTROL_ID in {t["task_id"] for t in s["tasks"]} for s in runtime)
            or any(_digest(_policy(s["policy"])) != _digest(_policy(POLICY)) for s in runtime)):
        raise ValueError("registered_8_story_48_task_customer_scope_required")
    hashes = {p.relative_to(ROOT).as_posix(): file_sha(p) for p in implementation_files()}
    return {"version": VERSION, "arms": list(ARMS), "source_stories": 8, "registered_tasks": 48,
        "expected_rows": 144, "legal_per_arm": 32, "missing_per_arm": 8, "outsider_per_arm": 8,
        "runtime_sha256": hashlib.sha256(raw).hexdigest(), "evaluation_sha256": hashlib.sha256(evaluation).hexdigest(),
        "config_sha256": _digest(config), "implementation_sha256": hashes, "ordering_seed": SEED,
        "approved_policy": _policy(POLICY), "source_annotation": "shared original Union per exact fact",
        "query_detector": "unchanged A/default customer schema; one preparation per task shared by all arms",
        "prepare_mode": "generation", "privacy_pipeline": "legacy", "threshold": .5,
        "splitter": "cjk_aware", "max_encoded_tokens": 512, "generation_limits": {"total": MAX_CALLS, **LIMITS},
        "roles": list(role_query.ROLES), "source_aliases": dict(role_query.ALIASES),
        "query_aliases": dict(role_query.QUERY_ALIASES), "role_schema": copy.deepcopy(role_query.ROLE_SCHEMA),
        "classifier_identity": role_query.LocalQueryRoleClassifier(config).cache_identity(),
        "role_projection": "complete PVT organization candidates plus explicit status values from authorized masked memory only; same-memory anchor and support; zero inference",
        "role_scope_binding": "actor+agent+request+full policy+masked payload+sha256 of complete exact records; current original authority callback mandatory",
        "F": "one original local answer, then pre-registered exact-current-token canonicalization and original full restoration",
        "Q0": "frozen lexical role classifier; exact unique role-value join; zero model calls",
        "Q1": "one local role-enum classifier sees neutralized masked query only, no memories/values/cards/gold; exact same join as Q0",
        "missing_control": {"queries": CONTROL_QUERIES, "expected_answer": "UNKNOWN", "source_precondition": "@ absent from every source"},
        "primary_output": "all branches apply same existing conservative canonicalization then original restore_labeled_answer; raw F strict restoration separately retained",
        "evaluation_timing": "hash evaluation bytes before run; parse labels only after model_phase_closed",
        "scope": "Existing exposed eight synthetic development stories, same-host signed JSON A-to-B. No fresh acceptance, native backend, semantic privacy or novelty claim."}, runtime, evaluation


def score(row, expected):
    authorized = row["actor_id"] == "owner"
    final = row.get("final_answer")
    exact = authorized and isinstance(final, str) and final.strip().casefold() == expected.casefold()
    mask = row["masking"]
    gap_free = mask.get("ready") is True and mask.get("partial") == mask.get("unmasked") == 0
    unknown = final == "UNKNOWN"
    model_unknown = (row["arm"] == "F" and row.get("answer_status") == "ok"
        and (row.get("raw_model_answer") or "").strip() == "UNKNOWN"
        or row["arm"] == "Q1" and (row.get("classification") or {}).get("status") == "ok"
        and (row.get("classification") or {}).get("role") == "UNKNOWN")
    strict = row.get("strict_final_answer")
    return {"authorized": authorized, "correct": bool(exact), "joint_correct_no_masking_gap": bool(exact and gap_free),
        "model_chose_unknown": bool(model_unknown), "host_join_unknown": row["arm"] != "F" and row.get("resolved_answer") == "UNKNOWN",
        "unknown_with_required_fact": row["task_class"] == "legal" and row["required_fact_retained"] and unknown,
        "strict_F_correct": bool(row["arm"] == "F" and isinstance(strict, str) and strict.strip().casefold() == expected.casefold()),
        "outsider_blocked": row["task_class"] == "outsider" and row.get("prepare_error") == "principal_not_authorized" and row["answer_calls"] == 0,
        "unauthorized_output": not authorized and (row["answer_calls"] > 0 or bool(final)),
        "restoration_failure": row.get("restoration_status") == "blocked"}


def aggregate(rows):
    keys = ("correct", "joint_correct_no_masking_gap", "model_chose_unknown", "host_join_unknown",
            "unknown_with_required_fact", "strict_F_correct", "outsider_blocked", "unauthorized_output", "restoration_failure")
    return {arm: {kind: {"registered_tasks": len(group), **{k: sum(r["score"][k] for r in group) for k in keys},
                        "answer_calls": sum(r["answer_calls"] for r in group),
                        "prepare_blocked": sum(r["prepare_status"] != "ok" for r in group)}
                  for kind in ("legal", "missing", "outsider")
                  for group in [[r for r in rows if r["arm"] == arm and r["task_class"] == kind]]} for arm in ARMS}


def render(output, report):
    page = '<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>角色解析与精确证据连接</title><style>body{font:16px/1.7 system-ui;margin:32px}td,th{border:1px solid #abc;padding:8px}table{border-collapse:collapse}</style><h1>自由回答、词典角色连接、仅问题模型角色连接</h1><p>共同构建、Union标签与一次授权准备；旧8故事开发诊断。原恢复门控保留；格式兼容预先纳入三组主流程。不是新盲测或创新证明。</p><table><tr><th>条件</th><th>合法正确/32</th><th>联合/32</th><th>缺失UNKNOWN/8</th><th>越权阻断/8</th><th>回答生成</th></tr>'
    for arm, cell in report["arms"].items():
        nums = (cell["legal"]["correct"], cell["legal"]["joint_correct_no_masking_gap"], cell["missing"]["correct"],
                cell["outsider"]["outsider_blocked"], cell["legal"]["answer_calls"]+cell["missing"]["answer_calls"])
        page += '<tr><td>'+html.escape(arm)+'</td>'+''.join('<td>'+str(v)+'</td>' for v in nums)+'</tr>'
    page += '</table><p>Q0/Q1只连接当前记忆中的唯一证据；UNKNOWN与处理失败分开，缺失与越权不计入合法32题。</p><p><a href="rows.json">逐题结果</a> · <a href="shared_contexts.json">共享准备与角色证据</a> · <a href="plan.json">冻结协议</a></p></html>'
    (output/"index.html").write_text(page, encoding="utf-8")


def run(corpus, output, model_root, config, observer, approved, *, progress=None):
    corpus, output = Path(corpus), Path(output)
    plan, runtime, evaluation_bytes = protocol(corpus, config)
    if _digest(plan) != _digest(approved):
        raise ValueError("approved_protocol_or_source_changed")
    output.mkdir(parents=True, exist_ok=False)
    for name in plan["implementation_sha256"]:
        dest = output/"implementation"/name
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT/name, dest)
    for name, value in (("plan.json", plan), ("runtime.json", runtime), ("config.json", config)):
        save(output/name, value)
    ner = LocalNerRuntime(model_root)
    recorder = AnnotationNerRecorder(GlinerEntityAgent(ner, approved_policies=[POLICY]))
    base = TypedCountingDetector(recorder)
    local = LocalSensitivityAgent(config)
    health = local.health()
    union = TypedCountingDetector(IndependentUnionDetector(recorder, local, member_kinds=("local_encoder", "local_generation")))
    revision = detector_revision(union)
    query_events = []
    query_agent = QuerySchemaAgent(ner, "A", query_events)
    detector = TypedCountingDetector(query_agent)
    builder = ReferenceMemoryBuilder(mode="select", detector=base, config=config)
    free, classifier = LocalFactAnswerer(config), role_query.LocalQueryRoleClassifier(config)
    save(output/"runtime_identity.json", {"ner": ner.identity, "local_generation": health,
        "union": union.cache_identity(), "union_detector_revision": revision, "classifier": classifier.cache_identity()})
    rows, contexts, builds, stores, annotations, pools, pending, journal = [], [], [], [], [], [], [], []
    for story in runtime:
        sid, policy = story["story_id"], story["policy"]
        authority = AuditedAuthority(secrets.token_bytes(32), journal)
        before = dict(base.counts)
        built, pool, labels, records, group_status = _construct(story, authority, builder, union, recorder, observer, revision)
        built.update(inference_counts=base.delta(before), **_volume(records, story["source"]))
        builds.append(built)
        pools.append({"story_id": sid, "pool": pool})
        annotations.extend(labels)
        stores.append({"story_id": sid, "builder": "union", "records": records, "union_label_set_status": group_status})
        for task in _tasks(story):
            actor, request_id = task["actor_id"], secrets.token_hex(16)
            context_id = sid+":"+task["task_id"]
            authority.operation = context_id+":shared"
            query_agent.context = {"context_id": context_id, "story_id": sid, "task_id": task["task_id"], "operation": authority.operation}
            event(journal, "prepare_start", operation=authority.operation, context_id=context_id, actor_id=actor,
                  agent_id="target-agent", record_ids=[r["record_id"] for r in records])
            observer.stage("prepare", "shared", sid, task["task_id"])
            before, posts, qstart = dict(detector.counts), observer.attempts, len(query_events)
            prepared = prepare_labeled_transfer(records, task["query"], policy, authority=authority, actor_id=actor,
                agent_id="target-agent", request_id=request_id, mode="generation", agent=detector,
                label_requirements={"expected_builder_version": built["builder_version"], "expected_detector_version": revision}) if records else None
            ready = prepared is not None and prepared["status"] == "ok"
            record_scope = _digest(records)
            scope = {"actor_id": actor, "agent_id": "target-agent", "request_id": request_id,
                     "policy": policy, "record_scope_sha256": record_scope}
            evidence = role_query.build_role_evidence(prepared["payload"], **scope) if ready else None
            context = {"context_id": context_id, "story_id": sid, "task_id": task["task_id"], "actor_id": actor,
                "agent_id": "target-agent", "request_id": request_id, "original_query": task["query"], "policy": policy,
                "record_scope_sha256": record_scope, "prepare_status": prepared["status"] if prepared else "blocked",
                "prepare_error": prepared.get("error") if prepared else "label_set_unavailable",
                "outbound": copy.deepcopy(prepared["payload"]) if ready else None,
                "actual_payload_sha256": _digest(prepared["payload"]) if ready else None,
                "detection": prepared.get("detection") if prepared else None, "checks": prepared.get("checks") if prepared else [],
                "prepare_metadata": prepared.get("metadata") if prepared else {}, "egress": prepared.get("egress") if prepared else None,
                "inference_counts": detector.delta(before), "prepare_generation_calls_observed": observer.attempts-posts,
                "query_encoder_event_indices": list(range(qstart, len(query_events))),
                "role_evidence_status": evidence["status"] if evidence else "not_run",
                "role_evidence_error": evidence.get("error") if evidence else None,
                "role_cards": copy.deepcopy(evidence.get("cards", [])) if evidence else [],
                "role_evidence_metadata": evidence.get("metadata", {}) if evidence else {}}
            context["role_cards_sha256"] = _digest(context["role_cards"])
            contexts.append(context)
            event(journal, "prepare_end", operation=authority.operation, context_id=context_id, prepare_status=context["prepare_status"])
            order = list(ARMS)
            random.Random(SEED+int(hashlib.sha256(context_id.encode()).hexdigest()[:8], 16)).shuffle(order)
            for arm in order:
                authority.operation = context_id+":"+arm
                row = {"context_id": context_id, "story_id": sid, "task_id": task["task_id"], "actor_id": actor,
                    "request_id": request_id, "language": story["language"], "template_family": story["template_family"],
                    "task_class": task["task_class"], "arm": arm, "common_build_status": built["status"],
                    "union_label_set_status": group_status, "prepare_status": context["prepare_status"],
                    "prepare_error": context["prepare_error"], "actual_payload_sha256": context["actual_payload_sha256"],
                    "role_cards_sha256": context["role_cards_sha256"], "record_scope_sha256": record_scope,
                    "answer_status": "not_run", "answer_calls": 0, "answer_request_indices": [],
                    "raw_model_answer": None, "classification": None, "resolved_answer": None,
                    "final_answer": None, "restoration_status": None, "strict_final_answer": None}
                if ready:
                    reason = _current_access(authority, records, actor_id=actor, agent_id="target-agent", policy=policy)
                    if reason:
                        row.update(answer_status="blocked", answer_error=reason)
                    elif arm != "F" and evidence["status"] != "ok":
                        row.update(answer_status="blocked", answer_error=evidence.get("error"))
                    else:
                        observer.stage("answer", arm, sid, task["task_id"])
                        posts = observer.attempts
                        if arm == "F":
                            response = free(prepared["payload"])
                            candidate = response.get("answer")
                        else:
                            response = role_query.classify_role_lexical(prepared["payload"]["query"]) if arm == "Q0" else classifier(prepared["payload"]["query"])
                            row["classification"] = copy.deepcopy(response)
                            resolution = role_query.resolve_role_answer(response["role"], evidence["table"], prepared["payload"],
                                **scope, authorizer=_pointer_authorizer(prepared, records, authority, actor_id=actor, agent_id="target-agent", policy=policy)) if response["status"] == "ok" else None
                            row["resolution"] = resolution
                            candidate = resolution.get("answer") if resolution and resolution["status"] == "ok" else None
                            if resolution and resolution["status"] != "ok":
                                response = {**response, "status": "blocked", "error": resolution.get("error")}
                        row.update(answer_status=response["status"], answer_error=response.get("error"),
                            answer_calls=response["local_calls"], answer_request_indices=list(range(posts+1, observer.attempts+1)),
                            resolved_answer=candidate)
                        if row["answer_calls"] != observer.attempts-posts or row["answer_calls"] > 1:
                            raise ValueError("single_task_call_accounting_invalid")
                        terminal = observer.terminals.get(observer.attempts) if row["answer_calls"] else None
                        if terminal and terminal["phase"] == "response":
                            row["raw_model_answer"] = terminal["response"].get("message", {}).get("content")
                        if response["status"] == "ok" and candidate is not None:
                            if arm == "F":
                                strict = restore_labeled_answer(candidate, prepared, records, policy, authority=authority,
                                    actor_id=actor, agent_id="target-agent", request_id=request_id)
                                row["strict_restoration"] = strict
                                row["strict_final_answer"] = strict.get("answer")
                            canonical = canonicalize_answer(candidate, prepared["payload"])
                            row["canonicalization"] = canonical
                            restored = restore_labeled_answer(canonical["answer"], prepared, records, policy, authority=authority,
                                actor_id=actor, agent_id="target-agent", request_id=request_id)
                            row.update(final_answer=restored.get("answer"), restoration_status=restored["status"], restoration_error=restored.get("error"))
                rows.append(row)
                pending.append((row, story, task, records, prepared))
                event(journal, "task_processing_end", operation=authority.operation, context_id=context_id, arm=arm,
                      prepare_status=row["prepare_status"], answer_calls=row["answer_calls"])
                if progress:
                    progress({"completed": len(rows), "expected": 144, "story": sid, "arm": arm, "scored": False})
            for name, value in (("rows.json", rows), ("shared_contexts.json", contexts), ("query_encoder_events.json", query_events),
                                ("auth_events.json", journal), ("builds.json", builds), ("record_store.json", stores),
                                ("annotations.json", annotations), ("pools.json", pools)):
                save(output/name, value)
    if len(rows) != 144 or len(contexts) != 48 or protocol(corpus, config)[0] != plan:
        raise ValueError("matrix_or_frozen_source_changed")
    observer.model_phase_closed = True
    event(journal, "model_phase_closed", actual_generation_attempts=observer.attempts)
    evaluation = json.loads(evaluation_bytes)
    event(journal, "evaluation_loaded", evaluation_sha256=plan["evaluation_sha256"])
    for row, story, task, records, prepared in pending:
        gold = evaluation[story["story_id"]]
        expected = "UNKNOWN" if task["task_class"] == "missing" else gold["answers"].get(task["task_id"], "")
        row["required_fact_retained"] = bool(task["task_class"] == "legal" and expected and any(expected in r["text"] for r in records))
        row["masking"] = score_masking(story, gold, records, prepared or {"status": "blocked"})
        row["score"] = score(row, expected)
    for _, _, _, _, prepared in pending:
        if prepared:
            prepared["mapping"] = None
    pending.clear()
    for name, value in (("rows.json", rows), ("evaluation.json", evaluation), ("auth_events.json", journal)):
        save(output/name, value)
    events = [json.loads(line) for line in (output/"request_transport.jsonl").read_text(encoding="utf-8").splitlines()]
    posts = [e for e in events if e["phase"] == "request"]
    report = {"version": VERSION, "registered_rows": 144, "recorded_rows": len(rows), "source_stories": 8,
        "shared_contexts": len(contexts), "registered_tasks": 48, "arms": aggregate(rows),
        "common_build_failures": sum(b["status"] != "ok" for b in builds),
        "union_label_set_failures": sum(s["union_label_set_status"] != "ok" for s in stores),
        "generation_calls_observed": observer.attempts,
        "generation_calls_by_stage": dict(observer.stage_counts),
        "generation_calls_by_arm": {a: sum(e["stage"] == "answer" and e["arm"] == a for e in posts) for a in ARMS},
        "build_encoder_calls": base.counts["local_encoder"], "write_annotation_encoder_calls": union.counts["local_encoder"],
        "query_prepare_encoder_calls": detector.counts["local_encoder"],
        "total_encoder_calls": base.counts["local_encoder"]+union.counts["local_encoder"]+detector.counts["local_encoder"],
        "detector_call_accounting_complete": base.complete and union.complete and detector.complete,
        "implementation_unchanged": protocol(corpus, config)[0] == plan,
        "closed_phase_attempts": observer.closed_phase_attempts, "cloud_calls": 0, "new_api_cost_cny": 0,
        "scope": plan["scope"]}
    save(output/"report.json", report)
    render(output, report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--plan-only", action="store_true")
    parser.add_argument("--approved-plan", type=Path)
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists() or not output.is_relative_to(ROOT/"results"):
        raise ValueError("new_project_results_directory_required")
    corpus = ROOT/"examples/privacy_semantics_v1"
    config = json.loads((ROOT/"configs/local_privacy_detector.json").read_bytes())
    if args.plan_only:
        plan = protocol(corpus, config)[0]
        output.mkdir(parents=True)
        save(output/"plan.json", plan)
        print(json.dumps({"plan": str(output/"plan.json"), "sha256": file_sha(output/"plan.json"), "model_calls": 0}))
        return
    if args.approved_plan is None:
        raise ValueError("approved_plan_required_before_inference")
    approved = json.loads(args.approved_plan.read_bytes())
    network = {"loopback_connections": 0, "external_attempts_blocked": 0}
    def guard(name, values):
        if name == "socket.connect":
            address = values[1]
            if not isinstance(address, tuple) or address[0] not in {"127.0.0.1", "::1"}:
                network["external_attempts_blocked"] += 1
                raise RuntimeError("external_network_disabled")
            network["loopback_connections"] += 1
    sys.addaudithook(guard)
    observer, completed, started = RoleQueryTransport(output, LocalSensitivityAgent._transport), False, time.monotonic()
    try:
        with observer.installed():
            run(corpus, output, ROOT/".runtime/github_ner", config, observer, approved,
                progress=lambda value: print(json.dumps(value), flush=True))
        completed = True
    finally:
        if output.exists():
            save(output/"transport_audit.json", dict(observer.summary(), completed=completed, network=network,
                elapsed_seconds=time.monotonic()-started, closed_phase_attempts=observer.closed_phase_attempts,
                generation_calls_by_stage=dict(observer.stage_counts), python_executable=sys.executable, python_version=sys.version))
            save(output/"network_audit.json", network)
            print(json.dumps({"output": str(output), "completed": completed, "generation_attempts": observer.attempts}, ensure_ascii=False), flush=True)


if __name__ == "__main__":
    main()
