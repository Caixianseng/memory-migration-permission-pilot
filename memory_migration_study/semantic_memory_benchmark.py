"""Paired end-to-end construction, privacy-label and query-intent experiment.

Models see runtime text only. Evaluation labels score after the transfer and
answer; they never choose facts, spans, intent, permissions or model output.
"""
from __future__ import annotations
import copy
import hashlib
import html
import json
from pathlib import Path
import random
import secrets
import shutil

from .coverage_memory import CoverageMemoryBuilder
from .detection_cache import detector_revision
from .local_detector import LocalSensitivityAgent
from .memory_builder import LocalMemoryBuilder
from .memory_generation_experiment import LocalFactAnswerer, score_masking
from .memory_labels import MemoryLabelAuthority, prepare_labeled_transfer, restore_labeled_answer
from .ner_detector import GlinerEntityAgent, LocalNerRuntime
from .privacy import _digest
from .query_intent import LocalQueryIntentClassifier, IntentAwareFactAnswerer
from .reuse_benchmark import save
from .union_detector import IndependentUnionDetector

ARMS = {
    "model_build_migration": ("model", "migration", False),
    "coverage_migration": ("coverage", "migration", False),
    "coverage_intent_migration": ("coverage", "migration", True),
    "coverage_intent_generation": ("coverage", "generation", True),
    "coverage_intent_two_stage": ("coverage", "two_stage", True),
    "coverage_raw_local": ("coverage", "raw", True),
}
VERSION = "semantic_memory_paired_v1"


def study_arms(paired_boundary=False):
    """Keep the original six defaults; opt in to five paired arms plus raw."""
    if type(paired_boundary) is not bool:
        raise ValueError("invalid_paired_boundary_mode")
    if not paired_boundary:
        return dict(ARMS)
    arms = {}
    for name, spec in ARMS.items():
        if spec[1] == "raw":
            arms[name] = spec
        else:
            arms[name+"__legacy"] = spec
            arms[name+"__boundary"] = spec
    return arms


class CountingDetector:
    """Observe physical member calls without recording text or candidates."""
    def __init__(self, detector, default_kind="local_encoder"):
        self.detector, self.default_kind = detector, default_kind
        self.max_local_calls = getattr(detector, "max_local_calls", 2)
        self.counts = dict(local_encoder=0, local_generation=0, unknown=0)
        self.complete = True

    def cache_identity(self):
        return self.detector.cache_identity()

    def __call__(self, **kwargs):
        result = self.detector(**kwargs)
        breakdown = result.get("inference_counts")
        if breakdown is None:
            breakdown = {self.default_kind: result.get("local_calls")}
        valid = (isinstance(breakdown, dict) and not set(breakdown) - set(self.counts)
                 and all(type(v) is int and v >= 0 for v in breakdown.values())
                 and type(result.get("local_calls")) is int and sum(breakdown.values()) == result["local_calls"])
        if valid:
            for kind, calls in breakdown.items():
                self.counts[kind] += calls
            if breakdown.get("unknown", 0) or result.get("local_calls_complete", True) is not True:
                self.complete = False
        else:
            self.complete = False
        return result

    def delta(self, before):
        return {kind: count-before[kind] for kind, count in self.counts.items()}


class RecordingAnswerer:
    """Benchmark-only capture of actual outbound synthetic inputs, never maps."""
    def __init__(self, answerer):
        self.answerer, self.last_payload = answerer, None

    def __call__(self, payload):
        self.last_payload = copy.deepcopy(payload)
        return self.answerer(payload)


def score(row, gold):
    expected = gold["answers"].get(row["task_id"])
    legal = row["actor_id"] == "owner"
    answer = row.get("final_answer")
    correct = legal and isinstance(answer, str) and answer.strip().casefold() == expected.casefold()
    secondary_enabled = row.get("secondary_serialization_registered") is True
    secondary_answer = (row.get("secondary_serialization") or {}).get("final_answer")
    secondary_correct = (legal and isinstance(secondary_answer, str)
                         and secondary_answer.strip().casefold() == expected.casefold())
    masking = row.get("masking")
    no_gap = (isinstance(masking, dict) and masking.get("ready") is True
              and type(masking.get("partial")) is int and masking["partial"] == 0
              and type(masking.get("unmasked")) is int and masking["unmasked"] == 0)
    return {"legal": legal, "correct": correct,
            "joint_correct_no_masking_gap": None if row.get("mode") == "raw" else
                bool(correct and row.get("prepare_status") == "ok" and no_gap),
            "secondary_serialization_correct": bool(secondary_correct) if secondary_enabled else None,
            "secondary_joint_correct_no_masking_gap": bool(secondary_correct and row.get("prepare_status") == "ok" and no_gap)
                if secondary_enabled else None,
            "build_block": legal and row.get("build_status") != "ok",
            "preprocessing_block": legal and row.get("prepare_status") != "ok",
            "true_model_unknown": legal and (row.get("model_answer") or "").strip().casefold() == "unknown",
            "restoration_failure": legal and row.get("restoration_status") == "blocked",
            "outsider_blocked": not legal and row.get("module_authorization_error") == "principal_not_authorized"
                                  and row.get("answer_calls", 0) == 0,
            "unauthorized_output": not legal and (row.get("prepare_status") == "ok" or bool(answer))}


def aggregate(rows, builds, arms=None):
    arms = ARMS if arms is None else arms
    out = {}
    for arm in arms:
        selected = [r for r in rows if r["arm"] == arm]
        legal = [r for r in selected if r["score"]["legal"]]
        ready = [r for r in legal if r.get("prepare_status") == "ok"]
        masked = [r for r in ready if r["mode"] != "raw"]
        family = arms[arm][0]
        creation = [b for b in builds if b["builder"] == family]
        out[arm] = {
            "registered_tasks": len(selected), "legal_tasks": len(legal),
            "correct": sum(r["score"]["correct"] for r in legal), "ready": len(ready),
            "joint_masked_legal_tasks": sum(r["mode"] != "raw" for r in legal),
            "joint_correct_no_masking_gap": None if arms[arm][1] == "raw" else
                sum(r["score"].get("joint_correct_no_masking_gap") is True for r in legal),
            "secondary_serialization_legal_tasks": sum(r.get("secondary_serialization_registered") is True for r in legal),
            "secondary_serialization_correct": None if not any(r.get("secondary_serialization_registered") is True for r in legal)
                else sum(r["score"].get("secondary_serialization_correct") is True for r in legal),
            "secondary_joint_correct_no_masking_gap": None if not any(r.get("secondary_serialization_registered") is True for r in legal)
                else sum(r["score"].get("secondary_joint_correct_no_masking_gap") is True for r in legal),
            **{key: sum(r["score"][key] for r in selected) for key in
               ("build_block", "preprocessing_block", "true_model_unknown", "restoration_failure", "outsider_blocked", "unauthorized_output")},
            "supported_legal_tasks": sum(r["required_fact_retained"] for r in legal),
            "ready_masked_requests": len(masked),
            "ready_with_masking_gaps": sum(r["masking"]["partial"] + r["masking"]["unmasked"] > 0 for r in masked),
            "complete_spans": sum(r["masking"]["complete"] for r in masked),
            "partial_spans": sum(r["masking"]["partial"] for r in masked),
            "unmasked_spans": sum(r["masking"]["unmasked"] for r in masked),
            "extra_masked_characters": sum(r["masking"]["extra_masked_characters"] for r in masked),
            "build_stories": len(creation), "build_successes": sum(b["status"] == "ok" for b in creation),
            "stored_characters": sum(b["stored_characters"] for b in creation),
            "stored_record_json_bytes": sum(b["stored_record_json_bytes"] for b in creation),
            "stored_source_copy_characters": sum(b["stored_source_copy_characters"] for b in creation),
            "source_characters": sum(b["source_characters"] for b in creation),
            "builder_calls_allocated": sum(b["local_calls"] for b in creation),
            "migration_detector_calls": sum(r["detector_calls"] for r in selected),
            "answer_calls": sum(r["answer_calls"] for r in selected),
            "intent_applied": sum(r.get("intent_applied", False) for r in selected),
            "by_language": {lang: {"legal": sum(r["language"] == lang for r in legal),
                                    "correct": sum(r["language"] == lang and r["score"]["correct"] for r in legal)}
                            for lang in ("en", "zh")}}
    return out


def run(corpus, output, model_root, config, *, split="development", detector_kind="gliner", progress=None,
        paired_boundary=False):
    if detector_kind not in {"gliner", "union"}:
        raise ValueError("unknown_detector_kind")
    arms = study_arms(paired_boundary)
    if paired_boundary and (split != "development" or detector_kind != "gliner"):
        raise ValueError("paired_boundary_protocol_requires_development_gliner")
    corpus, output = Path(corpus), Path(output)
    runtime_bytes = (corpus / split / "runtime.json").read_bytes()
    evaluation_bytes = (corpus / split / "evaluation.json").read_bytes()
    runtime = json.loads(runtime_bytes)
    evaluation = None if paired_boundary else json.loads(evaluation_bytes)
    expected_rows = sum(len(story["tasks"]) for story in runtime)*len(arms)
    legal_tasks = sum(task["actor_id"] == "owner" for story in runtime for task in story["tasks"])
    registered_generation_bounds = {"answers": legal_tasks*len(arms), "query_intent": legal_tasks,
                                    "model_build": len(runtime)*2}
    if paired_boundary and (registered_generation_bounds["answers"] > 352
            or registered_generation_bounds["query_intent"] > 32
            or registered_generation_bounds["model_build"] > 16
            or sum(registered_generation_bounds.values()) > 400):
        raise ValueError("paired_boundary_registered_generation_budget_exceeded")
    if (len({s["story_id"] for s in runtime}) != len(runtime)
            or any(len({t["task_id"] for t in s["tasks"]}) != len(s["tasks"]) for s in runtime)):
        raise ValueError("duplicate_story_or_task_identity")
    output.mkdir(parents=True, exist_ok=False)
    package = Path(__file__).parent
    hashes = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in package.glob("*.py")}
    entrypoints = [package.parent/"scripts"/"run_semantic_memory_benchmark.py"]
    paired_launcher = package.parent/"scripts"/"run_boundary_transfer_diagnostic.py"
    if paired_boundary and paired_launcher.exists():
        entrypoints.append(paired_launcher)
    entrypoint_hashes = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in entrypoints}
    archive = output / "implementation"
    archive.mkdir()
    for p in package.glob("*.py"):
        shutil.copy2(p, archive / p.name)
    for p in entrypoints:
        shutil.copy2(p, archive/p.name)
    save(output / "config.json", config)
    save(output / "plan.json", {"version": VERSION, "split": split, "detector_kind": detector_kind,
         "arms": arms, "paired_boundary": paired_boundary, "expected_rows": expected_rows, "ordering_seed": 2026102502,
         "score_schema_version": 2,
         "runtime_sha256": hashlib.sha256(runtime_bytes).hexdigest(),
         "evaluation_sha256": hashlib.sha256(evaluation_bytes).hexdigest(), "implementation_sha256": hashes,
         "entrypoint_sha256": entrypoint_hashes, "config_sha256": _digest(config),
         "evaluation_timing": "after_all_model_processing" if paired_boundary else "legacy_per_row_scoring",
         "secondary_serialization": "same_answer_exact_current_outbound_token_canonicalization_then_full_restore_no_new_model_calls" if paired_boundary else None,
         "generation_limits": {"max_generations": 400, "max_answer": 352, "max_intent": 32, "max_build": 16,
             "registered_upper_bounds": registered_generation_bounds,
             "hard_cap_enforced_by": "run_boundary_transfer_diagnostic launcher"} if paired_boundary else None,
         "config": config, "no_cloud": True, "threshold": .5,
         "unit": "Authored source story; related templates cluster stories. Tasks and repeated conditions are not independent stories.",
         "scope": "Full runtime construction, no gold-fed facts; lossless source chunks are a larger-storage baseline, not semantic compression. Raw control is synthetic local-only. Fixed restored CJK evidence boundaries in all arms."})
    save(output / "runtime.json", runtime)
    if not paired_boundary:
        save(output / "evaluation.json", evaluation)
    runtime_model = LocalNerRuntime(model_root)
    detector = GlinerEntityAgent(runtime_model, approved_policies=[s["policy"] for s in runtime])
    local = LocalSensitivityAgent(config)
    local.health()
    if detector_kind == "union":
        detector = IndependentUnionDetector(detector, local, member_kinds=("local_encoder", "local_generation"))
    detector = CountingDetector(detector)
    builders = {"model": LocalMemoryBuilder(config), "coverage": CoverageMemoryBuilder(detector=detector)}
    classifier = LocalQueryIntentClassifier(config)
    answerer = RecordingAnswerer(LocalFactAnswerer(config))
    intent_answerer = IntentAwareFactAnswerer(answerer=answerer)
    save(output / "runtime_identity.json", {"ner": runtime_model.identity,
         "initialization_seconds": runtime_model.initialization_seconds,
         "detector": detector.cache_identity()})
    rows, builds, intents, stores, pending_scores = [], [], [], [], []
    for story in runtime:
        source, policy, sid = story["source"], story["policy"], story["story_id"]
        authority = MemoryLabelAuthority(secrets.token_bytes(32))
        records_by_builder = {}
        for family, builder in builders.items():
            before_calls = dict(detector.counts)
            built = builder(text=source["text"], source_id=source["source_id"], policy=policy)
            records = []
            if built["status"] == "ok":
                for fact in built["facts"]:
                    records.append(authority.build_record(source, fact, policy, owner_id="owner", readers=["owner"],
                        agent_id="source-agent", allowed_agent_ids=["target-agent"], builder_version=built["builder_version"],
                        detector_version=detector_revision(detector) if family == "coverage" else built["builder_version"]))
            # Exercise a local persistence boundary; neither key nor recovery map is saved.
            records = json.loads(json.dumps(records, ensure_ascii=False))
            records_by_builder[family] = records
            stores.append({"story_id": sid, "builder": family, "records": records})
            builds.append(dict(built, story_id=sid, language=story["language"], builder=family,
                               source_characters=len(source["text"]), stored_characters=sum(len(r["text"]) for r in records),
                               stored_record_json_bytes=len(json.dumps(records, ensure_ascii=False).encode("utf-8")),
                               stored_source_copy_characters=sum(len(r["source"]["text"]) for r in records),
                               inference_counts=detector.delta(before_calls)))
        save(output / "record_store.json", stores)
        save(output / "builds.json", builds)
        for task in story["tasks"]:
            request_id = secrets.token_hex(16)
            intent = None
            if task["actor_id"] == "owner" and records_by_builder["coverage"]:
                intent = classifier(query=task["query"], request_id=request_id)
                intents.append(dict(intent, story_id=sid, task_id=task["task_id"]))
                save(output / "intents.json", intents)
            order = list(arms)
            random.Random(f"2026102502:{sid}:{task['task_id']}").shuffle(order)
            for arm in order:
                family, mode, use_intent = arms[arm]
                privacy_pipeline = "boundary" if paired_boundary and arm.endswith("__boundary") else "legacy"
                records = records_by_builder[family]
                built = next(b for b in reversed(builds) if b["story_id"] == sid and b["builder"] == family)
                row = {"story_id": sid, "language": story["language"], "template_family": story["template_family"],
                       "task_id": task["task_id"], "actor_id": task["actor_id"], "arm": arm, "mode": mode,
                       "privacy_pipeline": privacy_pipeline,
                       "secondary_serialization_registered": paired_boundary and mode != "raw",
                       "build_status": built["status"], "prepare_status": "blocked", "prepare_error": "memory_build_unavailable",
                       "detector_calls": 0, "answer_calls": 0, "model_answer": None, "final_answer": None,
                       "restoration_status": None, "intent_applied": False}
                answerer.last_payload = None
                prepared = None
                before_calls = dict(detector.counts)
                if records:
                    if mode == "raw":
                        errors = [authority.validate_access(r, actor_id=task["actor_id"], agent_id="target-agent", policy_version=policy["version"]) for r in records]
                        if any(errors):
                            row.update(prepare_error=next(e for e in errors if e), module_authorization_error=next(e for e in errors if e))
                        else:
                            prepared = {"status": "ok", "payload": {"query": task["query"], "memories": [{"source_id": r["record_id"], "text": r["text"]} for r in records]}}
                    else:
                        prepared = prepare_labeled_transfer(records, task["query"], policy, authority=authority,
                            actor_id=task["actor_id"], agent_id="target-agent", request_id=request_id, mode=mode,
                            agent=detector, privacy_pipeline=privacy_pipeline)
                        row.update(prepare_status=prepared["status"], prepare_error=prepared.get("error"),
                                   detector_calls=prepared.get("local_calls", 0), module_authorization_error=prepared.get("error"),
                                   checks=prepared.get("checks"), detection=prepared.get("detection"))
                        if paired_boundary:
                            row.update(prepare_metadata=copy.deepcopy(prepared.get("metadata", {})),
                                       egress=copy.deepcopy(prepared.get("egress")))
                    if prepared and prepared["status"] == "ok":
                        row.update(prepare_status="ok", prepare_error=None)
                        response = intent_answerer(prepared["payload"], intent_result=intent, original_query=task["query"], request_id=request_id) if use_intent else answerer(prepared["payload"])
                        row.update(answer_calls=response["local_calls"], model_answer=response.get("answer"),
                                   answer_status=response["status"], answer_error=response.get("error"),
                                   intent_applied=response.get("intent_applied", False), intent_error=response.get("intent_error"),
                                   actual_payload_sha256=response.get("actual_payload_sha256"), outbound=answerer.last_payload)
                        if response["status"] == "ok":
                            if mode == "raw":
                                row.update(final_answer=response["answer"], restoration_status="raw_local_control")
                            else:
                                restored = restore_labeled_answer(response["answer"], prepared, records, policy, authority=authority,
                                    actor_id=task["actor_id"], agent_id="target-agent", request_id=request_id)
                                row.update(final_answer=restored.get("answer"), restoration_status=restored["status"], restoration_error=restored.get("error"))
                                if paired_boundary:
                                    from .answer_serialization import canonicalize_answer
                                    canonical = canonicalize_answer(response["answer"], answerer.last_payload or prepared["payload"])
                                    secondary = restore_labeled_answer(canonical["answer"], prepared, records, policy,
                                        authority=authority, actor_id=task["actor_id"], agent_id="target-agent", request_id=request_id)
                                    row["secondary_serialization"] = {"decision": canonical["decision"],
                                        "canonical_answer": canonical["answer"], "final_answer": secondary.get("answer"),
                                        "restoration_status": secondary["status"], "restoration_error": secondary.get("error")}
                # Evaluation begins after every mechanism has finished for this row.
                row["inference_counts"] = detector.delta(before_calls)
                if paired_boundary:
                    # Opaque maps stay process-local until actual masking is
                    # scored; neither rows nor logs contain these references.
                    pending_scores.append((row, source, records, prepared))
                else:
                    gold = evaluation[sid]
                    expected = gold["answers"].get(task["task_id"])
                    row["required_fact_retained"] = bool(expected and any(expected in r["text"] for r in records))
                    if mode != "raw":
                        row["masking"] = score_masking({"source": source}, gold, records, prepared or {"status": "blocked"})
                    row["score"] = score(row, gold)
                    if prepared:
                        prepared["mapping"] = None
                rows.append(row)
                save(output / "rows.json", rows)
                if progress:
                    progress({"completed": len(rows), "expected": expected_rows, "story": sid, "arm": arm,
                              "prepare": row["prepare_status"], "correct": row.get("score", {}).get("correct")})
    if paired_boundary:
        if len(rows) != expected_rows:
            raise ValueError("registered_rows_missing")
        if hashlib.sha256((corpus/split/"evaluation.json").read_bytes()).hexdigest() != hashlib.sha256(evaluation_bytes).hexdigest():
            raise ValueError("evaluation_changed_during_study")
        evaluation = json.loads(evaluation_bytes)
        if set(evaluation) != {s["story_id"] for s in runtime}:
            raise ValueError("evaluation_story_identity_mismatch")
        for row, source, records, prepared in pending_scores:
            gold = evaluation[row["story_id"]]
            expected = gold["answers"].get(row["task_id"])
            row["required_fact_retained"] = bool(expected and any(expected in r["text"] for r in records))
            if row["mode"] != "raw":
                row["masking"] = score_masking({"source": source}, gold, records, prepared or {"status": "blocked"})
            row["score"] = score(row, gold)
            if prepared:
                prepared["mapping"] = None
        pending_scores.clear()
        save(output/"evaluation.json", evaluation)
        save(output/"rows.json", rows)
    after = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in package.glob("*.py")}
    if after != hashes or entrypoint_hashes != {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in entrypoints}:
        raise ValueError("implementation_changed_during_study")
    report = {"version": VERSION, "split": split, "detector_kind": detector_kind, "source_stories": len(runtime),
              "template_families": len({s["template_family"] for s in runtime}), "arms": aggregate(rows, builds, arms),
              "paired_boundary": paired_boundary, "registered_rows": expected_rows, "recorded_rows": len(rows),
              "legal_rows": sum(row["actor_id"] == "owner" for row in rows),
              "outsider_rows": sum(row["actor_id"] != "owner" for row in rows),
              "model_builder_generations": sum(b["local_calls"] for b in builds if b["builder"] == "model"),
              "coverage_builder_encoder_calls": sum(b["inference_counts"]["local_encoder"] for b in builds),
              "coverage_builder_detector_generations": sum(b["inference_counts"]["local_generation"] for b in builds),
              "query_intent_generations": sum(i["local_calls"] for i in intents),
              "migration_encoder_calls": sum(r["inference_counts"]["local_encoder"] for r in rows),
              "migration_detector_generations": sum(r["inference_counts"]["local_generation"] for r in rows),
              "detector_call_accounting_complete": detector.complete,
              "answer_generations": sum(r["answer_calls"] for r in rows),
              "implementation_unchanged": True, "cloud_calls": 0, "new_api_cost_cny": 0,
              "scope": "All registered stories/tasks retained. Lossless chunk baseline stores more source text; not semantic memory compression. Static host-owned grants; fresh request contexts. No native online revocation or semantic privacy proof."}
    save(output / "report.json", report)
    render(output, report)
    return report


def render(output, report):
    esc = lambda x: html.escape(str(x))
    keys = ("legal_tasks", "correct", "joint_correct_no_masking_gap", "secondary_serialization_correct",
            "secondary_joint_correct_no_masking_gap", "ready", "build_successes", "supported_legal_tasks", "true_model_unknown", "restoration_failure",
            "ready_with_masking_gaps", "extra_masked_characters", "migration_detector_calls", "answer_calls")
    body = '<!doctype html><meta charset="utf-8"><title>完整记忆构建与语义辅助对照</title><style>body{font:16px/1.7 system-ui;margin:32px}table{border-collapse:collapse;display:block;overflow:auto}td,th{border:1px solid #bcc;padding:8px}p{max-width:1100px}</style><h1>完整记忆构建与语义辅助对照</h1>'
    body += ('<p>既有开发故事，已暴露，用于开发诊断；本地真实模型构建与原文分块共享后，比较 legacy/boundary。'
             '主成绩保持原回答；序列化修复属于同一输出的次要配对分析，重新经过完整恢复核权，没有额外模型调用。'
             '安全效用交集仅覆盖受控静态授权和注册敏感跨度，不是全面安全证明。</p>') if report.get("paired_boundary") else '<p>新故事、真实本地构建、固定NER与回答模型。</p>'
    body += '<p>程序分块保留更多原文，是更大存储基线，不声称语义摘要。所有条件采用修复后的中文证据边界。闭集意图仅补充所问字段，不撤掉遮蔽、不赋予权限。raw 对照不适用遮蔽交集和序列化修复指标。</p>'
    body += '<p>范围：'+esc(report["split"])+'；故事 '+esc(report["source_stories"])+'；模板族 '+esc(report["template_families"])+ '。重复题和条件不是独立故事。云端调用及API新增费用为0。</p><table><tr><th>条件</th>'+''.join('<th>'+esc(k)+'</th>' for k in keys)+'</tr>'
    for arm, metrics in report["arms"].items():
        body += '<tr><td>'+esc(arm)+'</td>'+''.join('<td>'+esc(metrics[k])+'</td>' for k in keys)+'</tr>'
    body += '</table><p><a href="report.json">全部汇总与计算成本</a> · <a href="rows.json">真实逐题输入、模型回答及失败</a> · <a href="builds.json">构建覆盖与标签</a> · <a href="plan.json">冻结计划</a></p>'
    (Path(output)/"index.html").write_text(body, encoding="utf-8")
