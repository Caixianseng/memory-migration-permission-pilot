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
    return {"legal": legal,
            "correct": legal and isinstance(answer, str) and answer.strip().casefold() == expected.casefold(),
            "build_block": legal and row.get("build_status") != "ok",
            "preprocessing_block": legal and row.get("prepare_status") != "ok",
            "true_model_unknown": legal and (row.get("model_answer") or "").strip().casefold() == "unknown",
            "restoration_failure": legal and row.get("restoration_status") == "blocked",
            "outsider_blocked": not legal and row.get("module_authorization_error") == "principal_not_authorized"
                                  and row.get("answer_calls", 0) == 0,
            "unauthorized_output": not legal and (row.get("prepare_status") == "ok" or bool(answer))}


def aggregate(rows, builds):
    out = {}
    for arm in ARMS:
        selected = [r for r in rows if r["arm"] == arm]
        legal = [r for r in selected if r["score"]["legal"]]
        ready = [r for r in legal if r.get("prepare_status") == "ok"]
        masked = [r for r in ready if r["mode"] != "raw"]
        family = ARMS[arm][0]
        creation = [b for b in builds if b["builder"] == family]
        out[arm] = {
            "registered_tasks": len(selected), "legal_tasks": len(legal),
            "correct": sum(r["score"]["correct"] for r in legal), "ready": len(ready),
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


def run(corpus, output, model_root, config, *, split="development", detector_kind="gliner", progress=None):
    if detector_kind not in {"gliner", "union"}:
        raise ValueError("unknown_detector_kind")
    corpus, output = Path(corpus), Path(output)
    runtime_bytes = (corpus / split / "runtime.json").read_bytes()
    evaluation_bytes = (corpus / split / "evaluation.json").read_bytes()
    runtime, evaluation = json.loads(runtime_bytes), json.loads(evaluation_bytes)
    output.mkdir(parents=True, exist_ok=False)
    package = Path(__file__).parent
    hashes = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in package.glob("*.py")}
    archive = output / "implementation"
    archive.mkdir()
    for p in package.glob("*.py"):
        shutil.copy2(p, archive / p.name)
    save(output / "plan.json", {"version": VERSION, "split": split, "detector_kind": detector_kind, "arms": ARMS, "ordering_seed": 2026102502,
         "runtime_sha256": hashlib.sha256(runtime_bytes).hexdigest(),
         "evaluation_sha256": hashlib.sha256(evaluation_bytes).hexdigest(), "implementation_sha256": hashes,
         "config": config, "no_cloud": True, "threshold": .5,
         "unit": "Authored source story; related templates cluster stories. Tasks and repeated conditions are not independent stories.",
         "scope": "Full runtime construction, no gold-fed facts; lossless source chunks are a larger-storage baseline, not semantic compression. Raw control is synthetic local-only. Fixed restored CJK evidence boundaries in all arms."})
    save(output / "runtime.json", runtime)
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
    rows, builds, intents, stores = [], [], [], []
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
            order = list(ARMS)
            random.Random(f"2026102502:{sid}:{task['task_id']}").shuffle(order)
            for arm in order:
                family, mode, use_intent = ARMS[arm]
                records = records_by_builder[family]
                built = next(b for b in reversed(builds) if b["story_id"] == sid and b["builder"] == family)
                row = {"story_id": sid, "language": story["language"], "template_family": story["template_family"],
                       "task_id": task["task_id"], "actor_id": task["actor_id"], "arm": arm, "mode": mode,
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
                            actor_id=task["actor_id"], agent_id="target-agent", request_id=request_id, mode=mode, agent=detector)
                        row.update(prepare_status=prepared["status"], prepare_error=prepared.get("error"),
                                   detector_calls=prepared.get("local_calls", 0), module_authorization_error=prepared.get("error"),
                                   checks=prepared.get("checks"), detection=prepared.get("detection"))
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
                # Evaluation begins after every mechanism has finished for this row.
                row["inference_counts"] = detector.delta(before_calls)
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
                    progress({"completed": len(rows), "expected": len(runtime)*5*len(ARMS), "story": sid, "arm": arm,
                              "prepare": row["prepare_status"], "correct": row["score"]["correct"]})
    after = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in package.glob("*.py")}
    if after != hashes:
        raise ValueError("implementation_changed_during_study")
    report = {"version": VERSION, "split": split, "detector_kind": detector_kind, "source_stories": len(runtime),
              "template_families": len({s["template_family"] for s in runtime}), "arms": aggregate(rows, builds),
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
    keys = ("legal_tasks", "correct", "ready", "build_successes", "supported_legal_tasks", "true_model_unknown", "restoration_failure",
            "ready_with_masking_gaps", "extra_masked_characters", "migration_detector_calls", "answer_calls")
    body = '<!doctype html><meta charset="utf-8"><title>完整记忆构建与语义辅助对照</title><style>body{font:16px/1.7 system-ui;margin:32px}table{border-collapse:collapse;display:block;overflow:auto}td,th{border:1px solid #bcc;padding:8px}p{max-width:1100px}</style><h1>完整记忆构建与语义辅助对照</h1>'
    body += '<p>新故事、真实本地构建、固定NER与回答模型。程序分块保留更多原文，是更大存储基线，不声称语义摘要。所有条件采用修复后的中文证据边界。闭集意图仅补充所问字段，不撤掉遮蔽、不赋予权限。</p>'
    body += '<p>范围：'+esc(report["split"])+'；故事 '+esc(report["source_stories"])+'；模板族 '+esc(report["template_families"])+ '。重复题和条件不是独立故事。云端调用及API新增费用为0。</p><table><tr><th>条件</th>'+''.join('<th>'+esc(k)+'</th>' for k in keys)+'</tr>'
    for arm, metrics in report["arms"].items():
        body += '<tr><td>'+esc(arm)+'</td>'+''.join('<td>'+esc(metrics[k])+'</td>' for k in keys)+'</tr>'
    body += '</table><p><a href="report.json">全部汇总与计算成本</a> · <a href="rows.json">真实逐题输入、模型回答及失败</a> · <a href="builds.json">构建覆盖与标签</a> · <a href="plan.json">冻结计划</a></p>'
    (Path(output)/"index.html").write_text(body, encoding="utf-8")
