"""Registered local A->B comparison: union annotation at write or migration.

Common exact facts are selected once. Independent union detection then labels
the same fact text before G/T storage; failed annotations never become clean
labels. This is a strong existing-mechanism baseline, not a novelty claim.
"""
from __future__ import annotations
import argparse
import copy
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
from memory_migration_study.detection_cache import DetectionCache, detector_revision
from memory_migration_study.local_detector import LocalSensitivityAgent
from memory_migration_study.memory_generation_experiment import LocalFactAnswerer, score_masking
from memory_migration_study.memory_labels import prepare_labeled_transfer, restore_labeled_answer
from memory_migration_study.ner_detector import GlinerEntityAgent, LocalNerRuntime
from memory_migration_study.privacy import _digest, _policy, detect_sensitive
from memory_migration_study.reference_memory import ReferenceMemoryBuilder, propose_fact_pool
from memory_migration_study.reuse_benchmark import save
from memory_migration_study.semantic_memory_benchmark import RecordingAnswerer, aggregate, score
from memory_migration_study.union_detector import IndependentUnionDetector
from scripts.run_policy_semantic_study import AuditedAuthority, SemanticTransport, event
from scripts.run_reference_memory_study import TypedCountingDetector, file_sha

VERSION = "generation_union_transfer_development_v1"
ARMS = {"M": ("ner", "migration", False), "U": ("ner", "migration", False),
        "G": ("union", "generation", False), "T": ("union", "two_stage", False)}
SEED = 2026102511
GENERATION_CAP = 848


class TransferTransport(SemanticTransport):
    def __init__(self, output, original):
        super().__init__(output, original)
        self.maximum = GENERATION_CAP


class AnnotationNerRecorder:
    """Tap actual annotation member responses only, without extra inference."""
    def __init__(self, detector):
        self.detector, self.capture = detector, None
        self.max_local_calls = detector.max_local_calls

    def cache_identity(self):
        return {"version": "annotation_ner_response_tap_v1", "detector": self.detector.cache_identity(),
                "implementation_sha256": file_sha(__file__)}

    def __call__(self, **kwargs):
        response = self.detector(**kwargs)
        if self.capture is not None:
            self.capture.append({"source_id": kwargs["source_id"],
                "text_sha256": hashlib.sha256(kwargs["text"].encode("utf-8")).hexdigest(),
                "policy_sha256": _digest(_policy(kwargs["policy"])), "response": copy.deepcopy(response)})
        return response


def _fact_identity(source, fact):
    identity = {"source_id": source["source_id"], "source_sha256": hashlib.sha256(source["text"].encode()).hexdigest(),
        "source_start": fact["source_start"], "source_end": fact["source_end"],
        "content_sha256": hashlib.sha256(fact["text"].encode()).hexdigest()}
    return identity, _digest(identity)


def _volume(records, source):
    return {"stored_characters": sum(len(r["text"]) for r in records),
        "stored_record_json_bytes": len(json.dumps(records, ensure_ascii=False).encode("utf-8")),
        "stored_source_copy_characters": sum(len(r["source"]["text"]) for r in records),
        "source_characters": len(source["text"])}


def render(output, report):
    keys = ("legal_tasks", "correct", "joint_correct_no_masking_gap", "secondary_serialization_correct",
        "ready", "build_block", "true_model_unknown", "ready_with_masking_gaps", "outsider_blocked")
    esc = lambda value: html.escape(str(value))
    document = ('<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>生成标注与迁移复核</title>'
        '<style>body{font:16px/1.7 system-ui;margin:32px}table{border-collapse:collapse}td,th{border:1px solid #aaa;padding:7px}</style>'
        '<h1>共同事实、两套标签：完整A→B开发对照</h1><p>一次真实编号选择与NER标注；同一事实再经独立联合检测生成第二套标签。'
        'M=NER迁移；U=联合检测迁移；G=联合生成标签、查询检测及失效回退；T=联合标签、全记忆复核。'
        '原权限、外发与恢复检查保持一致。合成开发数据已暴露，属于现有机制的工程效用检验，不是新盲测或创新证明。</p>')
    document += '<table><tr><th>条件</th>'+''.join('<th>'+esc(k)+'</th>' for k in keys)+'</tr>'
    for arm, cell in report["arms"].items():
        document += '<tr><td>'+arm+'</td>'+''.join('<td>'+esc(cell[k])+'</td>' for k in keys)+'</tr>'
    document += ('</table><p>初次构建和联合标注成本单列，复用成本按实际流水计数。失败、拒答、缺失事实保留完整分母。'
        '补括号仅是同一输出的次要分析。标签差异不产生新的授权或独立来源。</p>'
        '<p><a href="report.json">完整汇总</a> · <a href="plan.json">预注册</a> · <a href="annotations.json">逐事实标注证据</a> · '
        '<a href="fact_bindings.json">事实与两套记录绑定</a> · <a href="rows.json">逐题结果</a></p></html>')
    (output/"index.html").write_text(document, encoding="utf-8")


def run(corpus, output, model_root, config, observer, *, progress=None):
    corpus, output = Path(corpus), Path(output)
    runtime_bytes = (corpus/"development/runtime.json").read_bytes()
    evaluation_bytes = (corpus/"development/evaluation.json").read_bytes()
    runtime = json.loads(runtime_bytes)
    if (len(runtime) != 8 or len({s["story_id"] for s in runtime}) != 8
            or sum(len(s["tasks"]) for s in runtime) != 40
            or sum(t["actor_id"] == "owner" for s in runtime for t in s["tasks"]) != 32
            or any(len({t["task_id"] for t in s["tasks"]}) != len(s["tasks"]) for s in runtime)):
        raise ValueError("registered_development_matrix_required")
    output.mkdir(parents=True, exist_ok=False)
    package = ROOT/"memory_migration_study"
    entrypoints = [Path(__file__), ROOT/"scripts/run_policy_semantic_study.py",
                  ROOT/"scripts/run_reference_memory_study.py", ROOT/"scripts/run_boundary_transfer_diagnostic.py"]
    files = list(package.glob("*.py"))+entrypoints
    hashes = {str(p.relative_to(ROOT)): file_sha(p) for p in files}
    for path in files:
        destination = output/"implementation"/path.relative_to(ROOT)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, destination)
    plan = {"version": VERSION, "score_schema_version": 2, "split": "development", "arms": ARMS,
        "source_stories": 8, "expected_rows": 160, "legal_per_arm": 32, "outsider_per_arm": 8,
        "runtime_sha256": hashlib.sha256(runtime_bytes).hexdigest(),
        "evaluation_sha256": hashlib.sha256(evaluation_bytes).hexdigest(), "config_sha256": _digest(config),
        "implementation_sha256": hashes, "ordering_seed": SEED, "max_facts_per_story": 8,
        "generation_limits": {"total": 848, "build": 16, "write_annotation": 128,
                              "union_migration": 576, "answer": 128},
        "privacy_pipeline": "legacy", "query_intent": False, "cache_only_arm": "U",
        "annotation_failure": "any_failed_fact_blocks_entire_union_label_set; original_ner_set_retained",
        "label_requirements": "G/T require current common builder and actual union detector revisions",
        "secondary_serialization": "same_output_exact_outer_brackets_then_original_restore",
        "evaluation_timing": "after_model_phase_closed",
        "cost_scope": "Common construction and union write annotation paid once; operation costs by arm. Label-set counts are not independent fact constructions.",
        "scope": "Exposed synthetic development; same-host trusted full-source envelopes, signed exact-fact JSON handoff. Two labels are not independent sources. No native interoperability, privacy proof or novelty claim."}
    for name, value in (("plan.json", plan), ("runtime.json", runtime), ("config.json", config)):
        save(output/name, value)
    ner = LocalNerRuntime(model_root)
    recorder = AnnotationNerRecorder(GlinerEntityAgent(ner, approved_policies=[s["policy"] for s in runtime]))
    base_detector = TypedCountingDetector(recorder)
    local = LocalSensitivityAgent(config)
    health = local.health()
    union_detector = TypedCountingDetector(IndependentUnionDetector(recorder, local,
        member_kinds=("local_encoder", "local_generation")))
    builder = ReferenceMemoryBuilder(mode="select", detector=base_detector, config=config)
    answerer = RecordingAnswerer(LocalFactAnswerer(config))
    ner_revision, union_revision = detector_revision(base_detector), detector_revision(union_detector)
    save(output/"runtime_identity.json", {"ner": ner.identity, "local_generation": health,
        "ner_initialization_seconds": ner.initialization_seconds, "detector": base_detector.cache_identity(),
        "union": union_detector.cache_identity(), "ner_detector_revision": ner_revision, "union_detector_revision": union_revision})
    rows, builds, label_sets, stores, pools, annotations, bindings, pending, journal = [], [], [], [], [], [], [], [], []
    for story in runtime:
        sid, source, policy = story["story_id"], story["source"], story["policy"]
        normalized = _policy(policy)
        authority = AuditedAuthority(secrets.token_bytes(32), journal)
        cache = DetectionCache(max_entries=256, ttl_seconds=3600)
        pool = propose_fact_pool(source["text"], source["source_id"])
        pools.append({"story_id": sid, "pool": pool})
        observer.stage("build", "common", sid)
        before, posts_before = dict(base_detector.counts), observer.attempts
        built = builder(text=source["text"], source_id=source["source_id"], policy=policy, pool=pool)
        if built["status"] == "ok" and not 0 < len(built["facts"]) <= 8:
            raise ValueError("common_fact_count_contract_invalid")
        ner_records, union_records, story_annotations, story_bindings, union_facts = [], [], [], [], []
        if built["status"] == "ok":
            for fact in built["facts"]:
                ner_records.append(authority.build_record(source, fact, policy, owner_id="owner", readers=["owner"],
                    agent_id="source-agent", allowed_agent_ids=["target-agent"], builder_version=built["builder_version"], detector_version=ner_revision))
        ner_records = json.loads(json.dumps(ner_records, ensure_ascii=False))
        builds.append(dict(built, story_id=sid, language=story["language"], builder="reference",
            generation_calls_observed=observer.attempts-posts_before, inference_counts=base_detector.delta(before), **_volume(ner_records, source)))
        if ner_records:
            for index, fact in enumerate(built["facts"]):
                identity, fact_key = _fact_identity(source, fact)
                fid = fact.get("fid", built["selected_fids"][index])
                annotation_source = "write_"+fact_key[:32]
                payload = {"query": "", "memories": [{"source_id": annotation_source, "text": fact["text"]}]}
                observer.stage("write_annotation", "union_labels", sid)
                observer.context.update(fact_index=index, fid=fid, fact_key=fact_key)
                before, posts_before = dict(union_detector.counts), observer.attempts
                recorder.capture = []
                try:
                    detection = detect_sensitive(payload, policy, mode="combined", agent=union_detector)
                    members = copy.deepcopy(recorder.capture)
                finally:
                    recorder.capture = None
                okay = (detection["status"] == "ok" and detection["local_calls_complete"] is True
                    and detection.get("payload_sha256") == _digest(payload) and detection.get("policy_sha256") == _digest(normalized)
                    and union_detector.complete)
                new_fact = {**fact, "findings": [], "status": "ok" if okay else "needs_review"}
                if okay:
                    for finding in detection["findings"]:
                        if (finding["source_id"] != annotation_source or type(finding["start"]) is not int
                                or type(finding["end"]) is not int or not 0 <= finding["start"] < finding["end"] <= len(fact["text"])
                                or finding["category"] not in normalized["protected_categories"]):
                            raise ValueError("annotation_finding_parent_or_span_invalid")
                        new_fact["findings"].append({k: finding[k] for k in ("start", "end", "category")})
                union_facts.append(new_fact)
                annotation = {"story_id": sid, "fact_index": index, "fid": fid, "fact_key": fact_key,
                    **identity, "annotation_source_id": annotation_source, "input_payload": payload,
                    "status": "ok" if okay else "needs_review", "errors": list(detection["errors"]), "detection": detection,
                    "inference_counts": union_detector.delta(before), "generation_calls_observed": observer.attempts-posts_before,
                    "request_indices": list(range(posts_before+1, observer.attempts+1)), "member_raw_outputs": members,
                    "full_policy_sha256": _digest(policy), "policy_sha256": _digest(normalized)}
                story_annotations.append(annotation)
                story_bindings.append({"story_id": sid, "fact_index": index, "fid": fid, "fact_key": fact_key, **identity,
                    "ner_record_id": ner_records[index]["record_id"], "union_record_id": None, "annotation_status": annotation["status"]})
            if all(a["status"] == "ok" for a in story_annotations):
                for fact in union_facts:
                    union_records.append(authority.build_record(source, fact, policy, owner_id="owner", readers=["owner"],
                        agent_id="source-agent", allowed_agent_ids=["target-agent"], builder_version=built["builder_version"], detector_version=union_revision))
                union_records = json.loads(json.dumps(union_records, ensure_ascii=False))
                for binding, record in zip(story_bindings, union_records):
                    binding["union_record_id"] = record["record_id"]
        annotation_status = "ok" if union_records else "needs_review" if ner_records else "not_run"
        for item in story_annotations:
            item["group_status"] = annotation_status
            item["eligible_for_store"] = bool(union_records)
        annotations.extend(story_annotations)
        bindings.extend(story_bindings)
        by_family = {"ner": ner_records, "union": union_records}
        for family, records in by_family.items():
            label_sets.append({"story_id": sid, "language": story["language"], "builder": family,
                "status": "ok" if records else "needs_review", "common_build_status": built["status"],
                "annotation_status": "not_applicable" if family == "ner" else annotation_status,
                "local_calls": built["local_calls"], "common_construction_shared": True,
                "detector_revision": ner_revision if family == "ner" else union_revision, **_volume(records, source)})
            stores.append({"story_id": sid, "builder": family, "records": records})
        for name, value in (("builds.json", builds), ("label_sets.json", label_sets), ("record_store.json", stores),
                            ("pools.json", pools), ("annotations.json", annotations), ("fact_bindings.json", bindings)):
            save(output/name, value)
        for task in story["tasks"]:
            order = list(ARMS)
            random.Random(f"{SEED}:{sid}:{task['task_id']}").shuffle(order)
            for arm in order:
                family, mode, _ = ARMS[arm]
                records = by_family[family]
                authority.operation = f"{sid}:{task['task_id']}:{arm}"
                request_id = secrets.token_hex(16)
                event(journal, "prepare_start", operation=authority.operation, story_id=sid, task_id=task["task_id"], arm=arm,
                    actor_id=task["actor_id"], agent_id="target-agent", record_ids=[r["record_id"] for r in records],
                    record_set_sha256=_digest(records), request_sha256=hashlib.sha256(request_id.encode()).hexdigest())
                detector = union_detector if arm == "U" else base_detector
                observer.stage("union_migration" if arm == "U" else "prepare", arm, sid, task["task_id"])
                before, posts_before = dict(detector.counts), observer.attempts
                row = {"story_id": sid, "task_id": task["task_id"], "actor_id": task["actor_id"],
                    "language": story["language"], "template_family": story["template_family"], "arm": arm,
                    "mode": mode, "privacy_pipeline": "legacy", "intent_applied": False, "label_family": family,
                    "common_build_status": built["status"], "union_label_set_status": annotation_status,
                    "build_status": "ok" if records else "needs_review",
                    "prepare_status": "blocked", "prepare_error": "label_set_unavailable", "detector_calls": 0,
                    "answer_calls": 0, "model_answer": None, "final_answer": None, "restoration_status": None,
                    "secondary_serialization_registered": True}
                prepared = None
                if records:
                    options = {"detection_cache": cache} if arm == "U" else {}
                    if arm in {"G", "T"}:
                        options["label_requirements"] = {"expected_builder_version": built["builder_version"], "expected_detector_version": union_revision}
                    prepared = prepare_labeled_transfer(records, task["query"], policy, authority=authority, actor_id=task["actor_id"],
                        agent_id="target-agent", request_id=request_id, mode=mode, agent=detector, **options)
                    row.update(prepare_status=prepared["status"], prepare_error=prepared.get("error"),
                        module_authorization_error=prepared.get("error"), detector_calls=prepared.get("local_calls", 0),
                        detection=prepared.get("detection"), checks=prepared.get("checks"), prepare_metadata=prepared.get("metadata"), egress=prepared.get("egress"))
                    if prepared["status"] == "ok":
                        observer.stage("answer", arm, sid, task["task_id"])
                        answerer.last_payload = None
                        response = answerer(prepared["payload"])
                        row.update(answer_calls=response["local_calls"], model_answer=response.get("answer"), answer_status=response["status"],
                            answer_error=response.get("error"), outbound=answerer.last_payload, actual_payload_sha256=_digest(answerer.last_payload))
                        if response["status"] == "ok":
                            restored = restore_labeled_answer(response["answer"], prepared, records, policy, authority=authority,
                                actor_id=task["actor_id"], agent_id="target-agent", request_id=request_id)
                            row.update(final_answer=restored.get("answer"), restoration_status=restored["status"], restoration_error=restored.get("error"))
                            canonical = canonicalize_answer(response["answer"], answerer.last_payload)
                            secondary = restore_labeled_answer(canonical["answer"], prepared, records, policy, authority=authority,
                                actor_id=task["actor_id"], agent_id="target-agent", request_id=request_id)
                            row["secondary_serialization"] = {"decision": canonical["decision"], "canonical_answer": canonical["answer"],
                                "final_answer": secondary.get("answer"), "restoration_status": secondary["status"], "restoration_error": secondary.get("error")}
                row["inference_counts"] = detector.delta(before)
                row["prepare_generation_calls_observed"] = observer.attempts-posts_before-row["answer_calls"]
                rows.append(row)
                pending.append((row, story, records, prepared))
                event(journal, "task_processing_end", operation=authority.operation, prepare_status=row["prepare_status"], answer_calls=row["answer_calls"])
                save(output/"rows.json", rows)
                save(output/"auth_events.json", journal)
                if progress:
                    progress({"completed": len(rows), "expected": 160, "story": sid, "arm": arm, "prepare": row["prepare_status"], "scored": False})
    if (len(rows) != 160 or file_sha(corpus/"development/runtime.json") != plan["runtime_sha256"]
            or file_sha(corpus/"development/evaluation.json") != plan["evaluation_sha256"]):
        raise ValueError("study_matrix_or_source_changed")
    observer.model_phase_closed = True
    event(journal, "model_phase_closed", actual_generation_attempts=observer.attempts)
    evaluation = json.loads(evaluation_bytes)
    if set(evaluation) != {s["story_id"] for s in runtime}:
        raise ValueError("evaluation_story_mismatch")
    for row, story, records, prepared in pending:
        gold = evaluation[row["story_id"]]
        expected = gold["answers"].get(row["task_id"])
        row["required_fact_retained"] = bool(expected and any(expected in r["text"] for r in records))
        row["masking"] = score_masking(story, gold, records, prepared or {"status": "blocked"})
        row["score"] = score(row, gold)
        if prepared:
            prepared["mapping"] = None
    pending.clear()
    for name, value in (("rows.json", rows), ("evaluation.json", evaluation), ("auth_events.json", journal)):
        save(output/name, value)
    if hashes != {str(p.relative_to(ROOT)): file_sha(p) for p in list(package.glob("*.py"))+entrypoints}:
        raise ValueError("implementation_changed_during_study")
    transport = output/"request_transport.jsonl"
    events = [json.loads(line) for line in transport.read_text(encoding="utf-8").splitlines()] if transport.exists() else []
    posts = [e for e in events if e["phase"] == "request"]
    report = {"version": VERSION, "registered_rows": 160, "recorded_rows": len(rows), "source_stories": 8,
        "common_fact_constructions": len(builds), "label_set_instances": len(label_sets), "arms": aggregate(rows, label_sets, ARMS),
        "common_build_failures": sum(b["status"] != "ok" for b in builds),
        "union_label_set_failures": sum(s["builder"] == "union" and s["status"] != "ok" for s in label_sets),
        "generation_calls_observed": observer.attempts,
        **{field: sum(e["stage"] == stage for e in posts) for field, stage in
           (("builder_generations", "build"), ("write_annotation_generations", "write_annotation"),
            ("union_migration_generations", "union_migration"), ("answer_generations", "answer"))},
        "build_encoder_calls": sum(b["inference_counts"]["local_encoder"] for b in builds),
        "write_annotation_encoder_calls": sum(a["inference_counts"]["local_encoder"] for a in annotations),
        "total_encoder_calls": base_detector.counts["local_encoder"]+union_detector.counts["local_encoder"],
        "union_label_stories_ready": sum(s["builder"] == "union" and s["status"] == "ok" for s in label_sets),
        "per_arm_operation_costs": {arm: {"encoder_calls": sum(r["inference_counts"]["local_encoder"] for r in rows if r["arm"] == arm),
            "generation_calls": sum(r["prepare_generation_calls_observed"] for r in rows if r["arm"] == arm),
            "answer_calls": sum(r["answer_calls"] for r in rows if r["arm"] == arm),
            "union_cache_hits": sum((r.get("prepare_metadata") or {}).get("detection_cache", {}).get("hits", 0) for r in rows if r["arm"] == arm)} for arm in ARMS},
        "request_wire_json_bytes": sum(e["wire_json_utf8_bytes"] for e in posts),
        "detector_call_accounting_complete": base_detector.complete and union_detector.complete,
        "implementation_unchanged": True, "closed_phase_attempts": observer.closed_phase_attempts,
        "cloud_calls": 0, "new_api_cost_cny": 0, "cost_scope": plan["cost_scope"], "scope": plan["scope"]}
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
    def network_guard(name, values):
        if name == "socket.connect":
            address = values[1]
            if not isinstance(address, tuple) or address[0] not in {"127.0.0.1", "::1"}:
                network["external_attempts_blocked"] += 1
                raise RuntimeError("external_network_disabled")
            network["loopback_connections"] += 1
    sys.addaudithook(network_guard)
    config = json.loads((ROOT/"configs/local_privacy_detector.json").read_bytes())
    observer, completed, started = TransferTransport(output, LocalSensitivityAgent._transport), False, time.monotonic()
    try:
        with observer.installed():
            run(ROOT/"examples/privacy_semantics_v1", output, ROOT/".runtime/github_ner", config, observer,
                progress=lambda value: print(json.dumps(value), flush=True))
        completed = True
    finally:
        if output.exists():
            summary = dict(observer.summary(), completed=completed, elapsed_seconds=time.monotonic()-started,
                python_executable=sys.executable, python_version=sys.version, network=network,
                closed_phase_attempts=observer.closed_phase_attempts, registered_protocol=VERSION)
            save(output/"transport_audit.json", summary)
            save(output/"network_audit.json", network)
            print(json.dumps({"output": str(output), "audit": summary}, ensure_ascii=False), flush=True)


if __name__ == "__main__":
    main()
