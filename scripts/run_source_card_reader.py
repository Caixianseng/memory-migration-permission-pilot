"""Plan-first exposed development: canonical F / Flat-ID / Source-ID.

Real model execution requires a separate --execute and an approved frozen plan.
No fresh acceptance material is opened. This is a structured-reader baseline.
"""
from __future__ import annotations

import argparse
import ast
from collections import Counter
from copy import deepcopy
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
from memory_migration_study.memory_generation_experiment import LocalFactAnswerer, score_masking
from memory_migration_study.memory_labels import prepare_labeled_transfer, restore_labeled_answer
from memory_migration_study.ner_detector import GlinerEntityAgent, LocalNerRuntime
from memory_migration_study.privacy import _digest, _policy
from memory_migration_study.reference_memory import ReferenceMemoryBuilder
from memory_migration_study.request_projection import project_fact_cards, resolve_fact_card_answer
from memory_migration_study.reuse_benchmark import save
from memory_migration_study.source_card_reader import LocalSourceCardReader
from memory_migration_study.source_fact_cards import build_source_fact_cards, GRAMMAR_SHA256
from memory_migration_study.union_detector import IndependentUnionDetector
from scripts.run_customer_schema_probe import POLICY
from scripts.run_generation_union_transfer import AnnotationNerRecorder, _volume
from scripts.run_policy_semantic_study import AuditedAuthority, event
from scripts.run_query_schema_transfer import QuerySchemaAgent
from scripts.run_reference_memory_study import TypedCountingDetector, file_sha
from scripts.run_span_answer_transfer import AnswerTransport, _construct, _tasks, _current_access, CONTROL_ID, CONTROL_QUERIES

VERSION = "full_context_source_fact_reader_development_v1"
ARMS = ("F", "Flat-ID", "Source-ID")
SEED = 2026102604
LIMITS = {"build": 16, "write_annotation": 128, "answer": 120}
MAX_CALLS = sum(LIMITS.values())
REGISTERED_DEPENDENCIES = (
    "memory_migration_study/__init__.py",
    "memory_migration_study/amount_candidates.py",
    "memory_migration_study/answer_evidence.py",
    "memory_migration_study/answer_serialization.py",
    "memory_migration_study/backend.py",
    "memory_migration_study/boundary_detector.py",
    "memory_migration_study/boundary_preparation.py",
    "memory_migration_study/boundary_reconciliation.py",
    "memory_migration_study/budget.py",
    "memory_migration_study/candidate_adjudicator.py",
    "memory_migration_study/candidate_proposals.py",
    "memory_migration_study/coverage_memory.py",
    "memory_migration_study/detection_cache.py",
    "memory_migration_study/evidence.py",
    "memory_migration_study/local_detector.py",
    "memory_migration_study/memory_builder.py",
    "memory_migration_study/memory_generation_experiment.py",
    "memory_migration_study/memory_labels.py",
    "memory_migration_study/ner_detector.py",
    "memory_migration_study/plan_verifier.py",
    "memory_migration_study/policy.py",
    "memory_migration_study/policy_semantics.py",
    "memory_migration_study/privacy.py",
    "memory_migration_study/privacy_corpus.py",
    "memory_migration_study/privacy_egress.py",
    "memory_migration_study/privacy_payload_eval.py",
    "memory_migration_study/query_intent.py",
    "memory_migration_study/reference_memory.py",
    "memory_migration_study/request_projection.py",
    "memory_migration_study/reuse_benchmark.py",
    "memory_migration_study/role_cover.py",
    "memory_migration_study/role_query.py",
    "memory_migration_study/semantic_memory_benchmark.py",
    "memory_migration_study/semantic_refinement.py",
    "memory_migration_study/source_card_reader.py",
    "memory_migration_study/source_fact_cards.py",
    "memory_migration_study/span_answer_evidence.py",
    "memory_migration_study/span_answerer.py",
    "memory_migration_study/span_completion.py",
    "memory_migration_study/structured_candidates.py",
    "memory_migration_study/tasks.py",
    "memory_migration_study/union_detector.py",
    "scripts/run_boundary_transfer_diagnostic.py",
    "scripts/run_customer_schema_probe.py",
    "scripts/run_generation_union_transfer.py",
    "scripts/run_policy_semantic_study.py",
    "scripts/run_query_schema_transfer.py",
    "scripts/run_reference_memory_study.py",
    "scripts/run_source_card_reader.py",
    "scripts/run_span_answer_transfer.py",
)


def implementation_files():
    return [ROOT/name for name in REGISTERED_DEPENDENCIES]


def audit_dependency_closure():
    """Check declared local imports, including lazy imports, without importing.

    Existing helper modules create a conservative closure. Unrelated native and
    GLiClass code is not part of this reader and may be developed independently.
    """
    pending, seen = [Path(__file__).resolve()], set()
    def module(parts):
        if not parts or parts[0] not in {"memory_migration_study", "scripts"}:
            return False
        for count in range(1, len(parts)):
            init = ROOT.joinpath(*parts[:count], "__init__.py")
            if init.is_file():
                pending.append(init)
        file, package = ROOT.joinpath(*parts).with_suffix(".py"), ROOT.joinpath(*parts, "__init__.py")
        if file.is_file():
            pending.append(file)
            return False
        if package.is_file():
            pending.append(package)
        return package.is_file() or ROOT.joinpath(*parts).is_dir()
    while pending:
        path = pending.pop().resolve()
        if path in seen:
            continue
        seen.add(path)
        package = list(path.relative_to(ROOT).parts[:-1])
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8-sig"))):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    module(alias.name.split("."))
            elif isinstance(node, ast.ImportFrom):
                base = (package[:len(package)-node.level+1] if node.level else []) + (node.module.split(".") if node.module else [])
                if module(base):
                    for alias in node.names:
                        if alias.name != "*":
                            module(base+[alias.name])
            elif (isinstance(node, ast.Call) and node.args and isinstance(node.args[0], ast.Constant)
                    and isinstance(node.args[0].value, str)
                    and ((isinstance(node.func, ast.Attribute) and node.func.attr == "import_module")
                         or isinstance(node.func, ast.Name) and node.func.id == "__import__")):
                module(node.args[0].value.split("."))
    discovered = {path.relative_to(ROOT).as_posix() for path in seen}
    if discovered != set(REGISTERED_DEPENDENCIES):
        raise ValueError("registered_dependency_closure_changed")
    return sorted(discovered)


def assert_implementation(hashes):
    if {p.relative_to(ROOT).as_posix() for p in implementation_files()} != set(hashes):
        raise ValueError("frozen_source_membership_changed")
    if any(not (ROOT/name).is_file() or file_sha(ROOT/name) != expected for name, expected in hashes.items()):
        raise ValueError("frozen_implementation_changed")


class SourceCardTransport(AnswerTransport):
    def __init__(self, output, original):
        super().__init__(output, original)
        self.maximum, self.stage_counts, self.cell_counts = MAX_CALLS, Counter(), Counter()
        self.frozen_hashes = None

    def stage(self, stage, arm, story_id, task_id=None):
        if self.frozen_hashes is not None:
            assert_implementation(self.frozen_hashes)
        super().stage(stage, arm, story_id, task_id)

    def call(self, client, method, path, body):
        if method == "POST":
            # Keep closure attempts visible even after a stage cap is exhausted.
            if self.model_phase_closed:
                return super().call(client, method, path, body)
            if self.frozen_hashes is not None:
                assert_implementation(self.frozen_hashes)
            stage = self.context["stage"]
            if stage not in LIMITS or self.stage_counts[stage] >= LIMITS[stage]:
                raise ValueError("registered_stage_cap_reached")
            if stage == "answer":
                cell = tuple(self.context.get(k) for k in ("story_id", "task_id", "arm"))
                if cell[2] not in ARMS or self.cell_counts[cell] >= 1:
                    raise ValueError("one_answer_request_per_cell_required")
        return super().call(client, method, path, body)

    def append(self, record):
        if record["phase"] == "request":
            self.stage_counts[self.context["stage"]] += 1
            if self.context["stage"] == "answer":
                self.cell_counts[tuple(self.context.get(k) for k in ("story_id", "task_id", "arm"))] += 1
        super().append(record)


def protocol(corpus, config):
    corpus = Path(corpus)
    raw = (corpus/"development/runtime.json").read_bytes()
    evaluation_bytes = (corpus/"development/evaluation.json").read_bytes()
    runtime = json.loads(raw)
    if (len(runtime) != 8 or Counter(s["language"] for s in runtime) != {"en": 4, "zh": 4}
            or len({s["story_id"] for s in runtime}) != 8
            or any(len(s["tasks"]) != 5 or len({t["task_id"] for t in s["tasks"]}) != 5
                   or sum(t["actor_id"] == "owner" for t in s["tasks"]) != 4 for s in runtime)
            or any("@" in s["source"]["text"] or CONTROL_ID in {t["task_id"] for t in s["tasks"]} for s in runtime)
            or any(_digest(_policy(s["policy"])) != _digest(_policy(POLICY)) for s in runtime)):
        raise ValueError("registered_8_story_48_task_customer_scope_required")
    audit_dependency_closure()
    hashes = {p.relative_to(ROOT).as_posix(): file_sha(p) for p in implementation_files()}
    plan = {"version": VERSION, "arms": list(ARMS), "source_stories": 8, "registered_tasks": 48,
        "expected_rows": 144, "legal_per_arm": 32, "missing_per_arm": 8, "outsider_per_arm": 8,
        "runtime_sha256": hashlib.sha256(raw).hexdigest(), "evaluation_sha256": hashlib.sha256(evaluation_bytes).hexdigest(),
        "config_sha256": _digest(config), "implementation_sha256": hashes, "ordering_seed": SEED,
        "dependency_policy": "explicit AST-audited local import closure including lazy imports; unrelated GLiClass/native code excluded",
        "generation_limits": {"total": MAX_CALLS, **LIMITS}, "expected_generation_calls_if_18_facts": 146,
        "approved_policy": _policy(POLICY), "source_grammar_sha256": GRAMMAR_SHA256,
        "source_annotation": "same real original construction and Union labels per exact fact; no query in source cards",
        "prepare_mode": "generation", "privacy_pipeline": "legacy", "threshold": .5,
        "splitter": "cjk_aware", "max_encoded_tokens": 512,
        "query_detector": "unchanged A/default customer schema; one preparation shared by three branches",
        "source_cards": "all raw exact facts currently access+label validated before source-only frozen role projection",
        "projection": "same full original map; whole replacement alignment; full detection plus authenticated source-label protection; both extra views egress checked",
        "reader_identity": LocalSourceCardReader(config).cache_identity(),
        "F": "original full-context LocalFactAnswerer, existing conservative canonical, original restore; strict raw separately kept",
        "Flat-ID": "full masked query+memories and complete same source-bound value pool, closed request-local card_id",
        "Source-ID": "identical model/prompt/schema/pool/IDs/context; only extra role and masked support per card",
        "missing_control": {"task_id": CONTROL_ID, "queries": CONTROL_QUERIES, "expected_answer": "UNKNOWN", "source_precondition": "@ absent from all sources"},
        "evaluation_timing": "hash bytes before; parse labels only after all 144 rows and model_phase_closed",
        "scope": "Exposed eight bilingual synthetic development stories; not fresh64, native backend, semantic privacy or novel algorithm."}
    return plan, runtime, evaluation_bytes


def _archive(plan, output):
    for name, expected in plan["implementation_sha256"].items():
        data = (ROOT/name).read_bytes()
        if hashlib.sha256(data).hexdigest() != expected:
            raise ValueError("snapshot_source_changed")
        target = output/"implementation"/name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        if file_sha(target) != expected:
            raise ValueError("snapshot_archive_changed")
    assert_implementation(plan["implementation_sha256"])


def _original_authorizer(authority, records, actor, policy):
    by_id = {r["record_id"]: r for r in records}
    def authorize(rid, actual_actor, version):
        return (rid in by_id and actual_actor == actor and version == policy["version"]
                and authority.validate_access(by_id[rid], actor_id=actor, agent_id="target-agent", policy_version=version) is None)
    return authorize


def score(row, expected):
    authorized = row["actor_id"] == "owner"
    final = row.get("final_answer")
    model_unknown = row.get("model_response_status") == "ok" and (
        (row["arm"] == "F" and (row.get("raw_model_answer") or "").strip() == "UNKNOWN")
        or (row["arm"] != "F" and row.get("card_decision") == "UNKNOWN"))
    exact = authorized and isinstance(final, str) and final.strip().casefold() == expected.casefold()
    correct = exact and (row["task_class"] != "missing" or model_unknown)
    mask = row["masking"]
    gap_free = mask.get("ready") is True and mask.get("partial") == mask.get("unmasked") == 0
    strict = row.get("strict_final_answer")
    return {"correct": bool(correct), "joint_correct_no_masking_gap": bool(correct and gap_free),
        "model_chose_unknown": bool(model_unknown), "host_join_unknown": row["arm"] != "F" and row.get("resolved_answer") == "UNKNOWN",
        "unknown_with_required_fact": row["task_class"] == "legal" and row["required_fact_retained"] and final == "UNKNOWN",
        "strict_F_correct": bool(row["arm"] == "F" and isinstance(strict, str) and strict.strip().casefold() == expected.casefold()),
        "outsider_blocked": row["task_class"] == "outsider" and row.get("prepare_error") == "principal_not_authorized" and row["answer_calls"] == 0,
        "unauthorized_output": not authorized and (row["answer_calls"] > 0 or bool(final)),
        "restoration_failure": row.get("restoration_status") == "blocked"}


def aggregate(rows):
    keys = ("correct", "joint_correct_no_masking_gap", "model_chose_unknown", "host_join_unknown", "unknown_with_required_fact",
            "strict_F_correct", "outsider_blocked", "unauthorized_output", "restoration_failure")
    return {arm: {kind: {"registered_tasks": len(group), **{k: sum(r["score"][k] for r in group) for k in keys},
        "answer_calls": sum(r["answer_calls"] for r in group), "prepare_blocked": sum(r["prepare_status"] != "ok" for r in group),
        "projection_blocked": sum(r.get("projection_status") != "ok" for r in group)}
        for kind in ("legal", "missing", "outsider") for group in [[r for r in rows if r["arm"] == arm and r["task_class"] == kind]]} for arm in ARMS}


def render(output, report):
    body = '<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>来源卡闭集阅读开发对照</title><h1>F、Flat-ID、Source-ID</h1><p>旧8故事开发；同构建、标签、共享准备及完整原恢复。不是独立验收或创新。</p><table border="1"><tr><th>条件</th><th>联合/32</th><th>缺失/8</th><th>越权阻断/8</th></tr>'
    for arm, cell in report["arms"].items():
        body += '<tr><td>'+html.escape(arm)+'</td>'+''.join('<td>'+str(n)+'</td>' for n in (cell["legal"]["joint_correct_no_masking_gap"], cell["missing"]["correct"], cell["outsider"]["outsider_blocked"]))+'</tr>'
    body += '</table><p><a href="report.json">报告</a> · <a href="rows.json">完整逐题</a> · <a href="plan.json">冻结协议</a></p></html>'
    (output/"index.html").write_text(body, encoding="utf-8")


def run(corpus, output, model_root, config, observer, approved, *, progress=None):
    corpus, output = Path(corpus), Path(output)
    plan, runtime, evaluation_bytes = protocol(corpus, config)
    if _digest(plan) != _digest(approved):
        raise ValueError("approved_protocol_or_source_changed")
    output.mkdir(parents=True, exist_ok=False)
    _archive(plan, output)
    observer.frozen_hashes = dict(plan["implementation_sha256"])
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
    free, reader = LocalFactAnswerer(config), LocalSourceCardReader(config)
    save(output/"runtime_identity.json", {"ner": ner.identity, "local_generation": health,
        "union": union.cache_identity(), "union_detector_revision": revision, "reader": reader.cache_identity()})
    rows, contexts, builds, stores, annotations, pools, pending, journal, source_sets = [], [], [], [], [], [], [], [], []
    for story in runtime:
        sid, policy = story["story_id"], story["policy"]
        authority = AuditedAuthority(secrets.token_bytes(32), journal)
        before = dict(base.counts)
        built, pool, labels, records, group_status = _construct(story, authority, builder, union, recorder, observer, revision)
        built.update(inference_counts=base.delta(before), **_volume(records, story["source"]))
        builds.append(built); pools.append({"story_id": sid, "pool": pool}); annotations.extend(labels)
        stores.append({"story_id": sid, "builder": "union", "records": records, "union_label_set_status": group_status})
        authority.operation = sid+":source_cards"
        observer.stage("source_cards", "shared", sid)
        source_cards = build_source_fact_cards(records, policy, authority=authority, actor_id="owner", agent_id="target-agent",
            authorizer=_original_authorizer(authority, records, "owner", policy)) if records else None
        source_sets.append({"story_id": sid, "status": source_cards["status"] if source_cards else "not_run",
                            "error": source_cards.get("error") if source_cards else "label_set_unavailable",
                            "metadata": source_cards.get("metadata", {}) if source_cards else {}})
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
            scope = {"authority": authority, "actor_id": actor, "agent_id": "target-agent", "request_id": request_id,
                     "authorizer": _original_authorizer(authority, records, actor, policy)}
            projection = project_fact_cards(source_cards["source_table"], prepared, records, policy, **scope) if ready and source_cards and source_cards["status"] == "ok" else None
            context = {"context_id": context_id, "story_id": sid, "task_id": task["task_id"], "actor_id": actor,
                "agent_id": "target-agent", "request_id": request_id, "original_query": task["query"], "policy": policy,
                "record_scope_sha256": _digest(records), "prepare_status": prepared["status"] if prepared else "blocked",
                "prepare_error": prepared.get("error") if prepared else "label_set_unavailable",
                "outbound": deepcopy(prepared["payload"]) if ready else None,
                "actual_payload_sha256": _digest(prepared["payload"]) if ready else None,
                "detection": prepared.get("detection") if prepared else None, "checks": prepared.get("checks", []) if prepared else [],
                "prepare_metadata": prepared.get("metadata", {}) if prepared else {}, "egress": prepared.get("egress") if prepared else None,
                "inference_counts": detector.delta(before), "prepare_generation_calls_observed": observer.attempts-posts,
                "query_encoder_event_indices": list(range(qstart, len(query_events))),
                "projection_status": projection["status"] if projection else "not_run",
                "projection_error": projection.get("error") if projection else source_cards.get("error") if source_cards else "label_set_unavailable",
                "views": deepcopy(projection.get("views", {})) if projection else {},
                "response_schema": deepcopy(projection.get("response_schema")) if projection else None,
                "projection_metadata": projection.get("metadata", {}) if projection else {}}
            contexts.append(context)
            event(journal, "prepare_end", operation=authority.operation, context_id=context_id, prepare_status=context["prepare_status"])
            order = list(ARMS)
            random.Random(SEED+int(hashlib.sha256(context_id.encode()).hexdigest()[:8], 16)).shuffle(order)
            for arm in order:
                authority.operation = context_id+":"+arm
                row = {"context_id": context_id, "story_id": sid, "task_id": task["task_id"], "actor_id": actor,
                    "agent_id": "target-agent", "request_id": request_id, "language": story["language"], "template_family": story["template_family"],
                    "task_class": task["task_class"], "arm": arm, "common_build_status": built["status"], "union_label_set_status": group_status,
                    "prepare_status": context["prepare_status"], "prepare_error": context["prepare_error"],
                    "actual_payload_sha256": context["actual_payload_sha256"], "record_scope_sha256": context["record_scope_sha256"],
                    "projection_status": context["projection_status"], "projection_error": context["projection_error"],
                    "answer_status": "not_run", "model_response_status": "not_run", "answer_calls": 0, "answer_request_indices": [],
                    "raw_model_answer": None, "card_decision": None, "resolved_answer": None,
                    "final_answer": None, "restoration_status": None, "strict_final_answer": None}
                if ready:
                    reason = _current_access(authority, records, actor_id=actor, agent_id="target-agent", policy=policy)
                    if reason:
                        row.update(answer_status="blocked", answer_error=reason)
                    elif arm != "F" and (not projection or projection["status"] != "ok"):
                        row.update(answer_status="blocked", answer_error=context["projection_error"])
                    else:
                        observer.stage("answer", arm, sid, task["task_id"])
                        posts = observer.attempts
                        if arm == "F":
                            response = free(prepared["payload"])
                            candidate = response.get("answer")
                        else:
                            mode = "flat" if arm == "Flat-ID" else "source"
                            response = reader(projection["views"][mode], projection["table"], prepared, records, policy, arm=mode, **scope)
                            row["reader_response"] = deepcopy(response)
                            row["card_decision"] = response.get("decision")
                            resolution = resolve_fact_card_answer(response["answer"], projection["table"], prepared, records, policy, **scope) if response["status"] == "ok" else None
                            row["resolution"] = resolution
                            candidate = resolution.get("answer") if resolution and resolution["status"] == "ok" else None
                        model_status = response["status"]
                        pipeline_error = (row.get("resolution") or {}).get("error")
                        row.update(answer_status="blocked" if pipeline_error else response["status"], answer_error=pipeline_error or response.get("error"),
                            model_response_status=model_status, answer_calls=response["local_calls"],
                            answer_request_indices=list(range(posts+1, observer.attempts+1)), resolved_answer=candidate)
                        if row["answer_calls"] != observer.attempts-posts or row["answer_calls"] > 1:
                            raise ValueError("single_task_call_accounting_invalid")
                        terminal = observer.terminals.get(observer.attempts) if row["answer_calls"] else None
                        if terminal and terminal["phase"] == "response":
                            row["raw_model_answer"] = terminal["response"].get("message", {}).get("content")
                        if row["answer_status"] == "ok" and candidate is not None:
                            if arm == "F":
                                strict = restore_labeled_answer(candidate, prepared, records, policy, **scope)
                                row["strict_restoration"] = strict; row["strict_final_answer"] = strict.get("answer")
                            canonical = canonicalize_answer(candidate, prepared["payload"])
                            row["canonicalization"] = canonical
                            restored = restore_labeled_answer(canonical["answer"], prepared, records, policy, **scope)
                            row.update(final_answer=restored.get("answer"), restoration_status=restored["status"], restoration_error=restored.get("error"))
                rows.append(row); pending.append((row, story, task, records, prepared))
                event(journal, "task_processing_end", operation=authority.operation, context_id=context_id, arm=arm,
                      prepare_status=row["prepare_status"], answer_calls=row["answer_calls"])
                if progress:
                    progress({"completed": len(rows), "expected": 144, "story": sid, "arm": arm, "scored": False})
            for name, value in (("rows.json", rows), ("shared_contexts.json", contexts), ("query_encoder_events.json", query_events),
                    ("auth_events.json", journal), ("builds.json", builds), ("record_store.json", stores),
                    ("annotations.json", annotations), ("pools.json", pools), ("source_card_sets.json", source_sets)):
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
    path = output/"request_transport.jsonl"
    events = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()] if path.exists() else []
    posts = [e for e in events if e["phase"] == "request"]
    report = {"version": VERSION, "registered_rows": 144, "recorded_rows": len(rows), "source_stories": 8,
        "shared_contexts": len(contexts), "registered_tasks": 48, "arms": aggregate(rows),
        "common_build_failures": sum(b["status"] != "ok" for b in builds),
        "source_card_set_failures": sum(c["status"] != "ok" for c in source_sets),
        "union_label_set_failures": sum(s["union_label_set_status"] != "ok" for s in stores),
        "generation_calls_observed": observer.attempts, "generation_calls_by_stage": dict(observer.stage_counts),
        "generation_calls_by_arm": {arm: sum(e["stage"] == "answer" and e["arm"] == arm for e in posts) for arm in ARMS},
        "build_encoder_calls": base.counts["local_encoder"], "write_annotation_encoder_calls": union.counts["local_encoder"],
        "query_prepare_encoder_calls": detector.counts["local_encoder"],
        "total_encoder_calls": base.counts["local_encoder"]+union.counts["local_encoder"]+detector.counts["local_encoder"],
        "detector_call_accounting_complete": base.complete and union.complete and detector.complete,
        "implementation_unchanged": protocol(corpus, config)[0] == plan, "closed_phase_attempts": observer.closed_phase_attempts,
        "cloud_calls": 0, "new_api_cost_cny": 0, "scope": plan["scope"]}
    save(output/"report.json", report); render(output, report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--plan-only", action="store_true"); mode.add_argument("--execute", action="store_true")
    parser.add_argument("--approved-plan", type=Path)
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists() or output == ROOT/"results" or not output.is_relative_to(ROOT/"results"):
        raise ValueError("new_project_results_directory_required")
    corpus = ROOT/"examples/privacy_semantics_v1"
    config = json.loads((ROOT/"configs/local_privacy_detector.json").read_bytes())
    if args.plan_only:
        plan = protocol(corpus, config)[0]; output.mkdir(parents=True); save(output/"plan.json", plan)
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
    observer = SourceCardTransport(output, LocalSensitivityAgent._transport)
    completed, started = False, time.monotonic()
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
