"""Authored A->B harness regressions, without weights, sockets or study data.

The ledger counts invocations of an injected transport callback through the real
StageTransport. They are fake POST attempts, not actual model or HTTP calls.
Builders, answer client, candidate pool, ACL signatures, JSON transfer, masking,
restoration and final scoring remain the real implementation.
"""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch

from memory_migration_study.local_detector import DIGEST, MODEL, VERSION
from memory_migration_study.memory_labels import MemoryLabelAuthority
from memory_migration_study.ner_detector import GlinerEntityAgent
from memory_migration_study.reference_memory import ReferenceMemoryBuilder


ROOT = Path(__file__).resolve().parents[1]


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


harness = load_module("reference_study_under_test", ROOT / "scripts/run_reference_memory_study.py")
authored = load_module("reference_study_authored_fixture", ROOT / "tests/test_study_semantic_memory_benchmark.py")


class FakeServer:
    """Protocol fake; answers derive only from the actual outbound payload."""
    def __init__(self, *, old_failure=False, bare_tokens=False):
        self.old_failure, self.bare_tokens = old_failure, bare_tokens
        self.posts, self.gold_parsed = [], False

    def transport(self, client, method, path, body=None):
        if method == "GET" and path == "/api/version":
            return {"version": VERSION}
        if method == "GET" and path == "/api/tags":
            return {"models": [{"name": MODEL, "digest": DIGEST}]}
        if (method, path) != ("POST", "/api/chat"):
            raise AssertionError("unexpected fake transport route")
        if self.gold_parsed:
            raise AssertionError("generation after evaluation was parsed")
        self.posts.append(copy.deepcopy(body))
        data = json.loads(body["messages"][1]["content"])
        if "facts" in body.get("format", {}).get("properties", {}):
            content = json.dumps({"status": "needs_review" if self.old_failure else "ok",
                "facts": [{"quote": data["text"], "findings": [
                    {"quote": "Cedar Foundry", "category": "CUSTOMER"},
                    {"quote": "relay@sample.test", "category": "EMAIL"}]}]})
        elif "candidates" in data:
            field = "selected_fids" if "selected_fids" in body["format"]["properties"] else "selected_quotes"
            key = "fid" if field == "selected_fids" else "text"
            content = json.dumps({"status": "ok", field: [c[key] for c in data["candidates"]]})
        else:
            text = "\n".join(m["text"] for m in data["memories"])
            query = data["query"].casefold()
            expression = (r"Contact: (.+?)\.$" if "email" in query else
                          r"Status: (.+?); Contact:" if "status" in query else
                          r"Customer: (.+?); Status:")
            match = re.search(expression, text)
            content = match.group(1) if match else "UNKNOWN"
            if self.bare_tokens and re.fullmatch(r"\[PVT_[^\[\]]+\]", content):
                content = content[1:-1]
        return {"model": MODEL, "done": True, "done_reason": "stop",
                "message": {"role": "assistant", "content": content},
                "prompt_eval_count": 100, "eval_count": 20}


class ReferenceMemoryStudyTests(unittest.TestCase):
    def run_authored(self, *, old_failure=False, bare_tokens=False, poisoned=False, tamper=False):
        # Distinct identities, copied authored fixtures, never real development
        # or heldout materials. The harness's fixed denominator is preserved.
        base_runtime, base_gold = authored.fixture()
        runtime, evaluation = [], {}
        for index in range(8):
            story = copy.deepcopy(base_runtime[0])
            sid = story["story_id"] = f"authored-reference-{index}"
            story["source"]["source_id"] = f"authored-reference-source-{index}"
            runtime.append(story)
            evaluation[sid] = copy.deepcopy(base_gold["authored-fixture"])
            if poisoned:
                evaluation[sid]["answers"] = {k: authored.CANARY for k in evaluation[sid]["answers"]}
        server, ner = FakeServer(old_failure=old_failure, bare_tokens=bare_tokens), authored.FakeNerRuntime()
        progress, access, built_records, pools, gold_reads = [], [], {}, [], []
        real_build, real_access = MemoryLabelAuthority.build_record, MemoryLabelAuthority.validate_access
        real_reference, real_loads = ReferenceMemoryBuilder.__call__, json.loads

        def build_record(authority, *args, **kwargs):
            record = real_build(authority, *args, **kwargs)
            if tamper:
                record["access"]["readers"].append("outsider")  # Deliberately do not re-sign.
            built_records[record["record_id"]] = (authority, record)
            return record

        def validate_access(authority, record, **kwargs):
            result = real_access(authority, record, **kwargs)
            access.append({"actor_id": kwargs["actor_id"], "result": result,
                "json_roundtrip": built_records[record["record_id"]][1] is not record})
            return result

        def reference(builder, **kwargs):
            pool = kwargs["pool"]
            before = harness._digest(pool)
            result = real_reference(builder, **kwargs)
            pools.append({"source_id": kwargs["source_id"], "pool_id": id(pool),
                "before": before, "after": harness._digest(pool)})
            return result

        def guarded_loads(value, *args, **kwargs):
            marker = authored.CANARY.encode() if isinstance(value, bytes) else authored.CANARY
            if isinstance(value, (str, bytes)) and marker in value:
                self.assertEqual(progress[-1]["completed"], 200)
                self.assertTrue(all(event["scored"] is False for event in progress))
                server.gold_parsed = True
                gold_reads.append(len(server.posts))
            return real_loads(value, *args, **kwargs)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            split = root / "corpus/development"
            split.mkdir(parents=True)
            for name, data in (("runtime", runtime), ("evaluation", evaluation)):
                (split / f"{name}.json").write_text(json.dumps(data), encoding="utf-8")
            inputs_before = {p.name: p.read_bytes() for p in split.iterdir()}
            observer = harness.StageTransport(root / "output", server.transport)
            # No socket/model can be reached even if the injected seam regresses.
            with patch.object(harness, "LocalNerRuntime", return_value=ner), \
                 patch.object(MemoryLabelAuthority, "build_record", new=build_record), \
                 patch.object(MemoryLabelAuthority, "validate_access", new=validate_access), \
                 patch.object(ReferenceMemoryBuilder, "__call__", new=reference), \
                 patch.object(json, "loads", new=guarded_loads), \
                 patch("socket.socket.connect", side_effect=AssertionError("network forbidden")), \
                 observer.installed():
                report = harness.run(root / "corpus", root / "output", "no-model-assets", {}, observer,
                                     progress=progress.append)
            self.assertEqual(inputs_before, {p.name: p.read_bytes() for p in split.iterdir()})
            output = root / "output"
            data = {name: real_loads((output / f"{name}.json").read_bytes())
                    for name in ("rows", "builds", "record_store", "pools", "plan")}
            events = [real_loads(line) for line in (output / "request_transport.jsonl").read_text(encoding="utf-8").splitlines()]
            self.assertEqual(report["arms"], harness.aggregate(data["rows"], data["builds"], harness.ARMS))
            self.assertEqual(report["generation_calls_observed"], len(server.posts))
            self.assertEqual(observer.attempts, len(server.posts))
            self.assertEqual(len([e for e in events if e["phase"] == "request"]), len(server.posts))
            self.assertEqual(len([e for e in events if e["phase"] == "response"]), len(server.posts))
            self.assertEqual(gold_reads, [len(server.posts)])
            self.assertTrue(report["implementation_unchanged"])
            self.assertTrue(report["detector_call_accounting_complete"])
            self.assertEqual(report["build_encoder_calls"] + report["migration_encoder_calls"], len(ner.calls))
            self.assertTrue((output / "index.html").is_file())
            for relative, digest in data["plan"]["implementation_sha256"].items():
                self.assertEqual(hashlib.sha256((output / "implementation" / relative).read_bytes()).hexdigest(), digest)
            captured = json.dumps({"posts": server.posts, "ner": ner.calls})
            for forbidden in (authored.CANARY, authored.OUTSIDER_QUERY, '"answers"', '"sensitive_spans"'):
                self.assertNotIn(forbidden, captured)
            for row in data["rows"]:
                self.assertEqual(row["score"], harness.score(row, evaluation[row["story_id"]]))
            return report, data, server, access, built_records, pools, progress

    def test_real_typed_gliner_adapter_does_not_turn_reference_labeling_unknown(self):
        runtime, _ = authored.fixture()
        story = runtime[0]
        ner = authored.FakeNerRuntime()
        detector = harness.TypedCountingDetector(GlinerEntityAgent(ner, approved_policies=[story["policy"]]))
        built = ReferenceMemoryBuilder(mode="retain_all", detector=detector)(
            text=story["source"]["text"], source_id=story["source"]["source_id"], policy=story["policy"])
        self.assertEqual(built["status"], "ok")
        self.assertGreater(len(ner.calls), 0)
        self.assertEqual(built["local_counts"]["unknown"], 0)
        self.assertEqual(built["local_counts"]["local_generation"], 0)
        self.assertEqual(built["local_counts"]["local_encoder"], len(ner.calls))

    def test_complete_matrix_real_signatures_shared_pool_and_callback_ledger(self):
        report, data, server, access, signed, pools, progress = self.run_authored()
        self.assertEqual(len(data["rows"]), 200)
        self.assertEqual(len(data["builds"]), 40)
        self.assertEqual(len(data["pools"]), 8)
        self.assertEqual({(r["story_id"], r["task_id"], r["arm"]) for r in data["rows"]},
            {(f"authored-reference-{i}", task, arm) for i in range(8)
             for task in ("name", "status", "repeat", "mail", "outsider") for arm in harness.ARMS})
        self.assertEqual(report["builder_generations"], 24)
        self.assertEqual(report["answer_generations"], 160)
        self.assertEqual(len(server.posts), 184)
        self.assertEqual(progress[-1]["completed"], 200)
        for metrics in report["arms"].values():
            self.assertEqual((metrics["legal_tasks"], metrics["correct"], metrics["outsider_blocked"]), (32, 32, 8))
            self.assertEqual(metrics["unauthorized_output"], 0)
            self.assertEqual(metrics["build_successes"], 8)
        for source_id in {p["source_id"] for p in pools}:
            group = [p for p in pools if p["source_id"] == source_id]
            self.assertEqual(len(group), 3)
            self.assertEqual(len({p["pool_id"] for p in group}), 1)
            self.assertTrue(all(p["before"] == p["after"] for p in group))
        self.assertTrue(access)
        self.assertTrue(all(a["json_roundtrip"] for a in access))
        outsider_access = [a for a in access if a["actor_id"] == "outsider"]
        self.assertEqual(len(outsider_access), 40)
        self.assertTrue(all(a["result"] == "principal_not_authorized" for a in outsider_access))
        for store in data["record_store"]:
            for record in store["records"]:
                authority, original = signed[record["record_id"]]
                self.assertIsNot(record, original)
                self.assertEqual(record["source"]["text"][record["source_start"]:record["source_end"]], record["text"])
                self.assertEqual(len(record["access_signature"]), 64)
                self.assertIsNone(authority.validate_access(record, actor_id="owner", agent_id="target-agent"))
        for row in data["rows"]:
            if row["actor_id"] == "outsider":
                self.assertEqual((row["answer_calls"], row["detector_calls"]), (0, 0))

    def test_failed_builder_keeps_denominators_without_claiming_authority_rejection(self):
        report, data, server, access, _, _, _ = self.run_authored(old_failure=True)
        metrics = report["arms"]["old_joint_quote"]
        self.assertEqual((len(data["rows"]), metrics["legal_tasks"], metrics["build_block"]), (200, 32, 32))
        self.assertEqual((metrics["build_successes"], metrics["ready"], metrics["outsider_blocked"]), (0, 0, 0))
        failed_builds = [b for b in data["builds"] if b["builder"] == "old_joint_quote"]
        self.assertTrue(all(b["facts"] and b["status"] == "needs_review" for b in failed_builds))
        self.assertTrue(all(not s["records"] for s in data["record_store"] if s["builder"] == "old_joint_quote"))
        self.assertEqual(report["answer_generations"], 128)
        self.assertEqual(len(server.posts), 152)
        self.assertEqual(len([a for a in access if a["actor_id"] == "outsider"]), 32)
        for row in data["rows"]:
            if row["arm"] == "old_joint_quote":
                self.assertEqual(row["prepare_error"], "memory_build_unavailable")
                self.assertEqual(row["answer_calls"], 0)

    def test_strict_secondary_reuses_raw_answer_without_overwriting_primary(self):
        report, data, server, _, _, _, _ = self.run_authored(bare_tokens=True)
        self.assertEqual((report["answer_generations"], len(server.posts)), (160, 184))
        for metrics in report["arms"].values():
            self.assertEqual((metrics["correct"], metrics["secondary_serialization_correct"]), (16, 32))
        repaired = [r for r in data["rows"] if r.get("secondary_serialization", {}).get("decision") == "added_outer_brackets"]
        self.assertEqual(len(repaired), 80)
        for row in repaired:
            self.assertFalse(row["model_answer"].startswith("["))
            self.assertEqual(row["secondary_serialization"]["canonical_answer"], "[" + row["model_answer"] + "]")
            self.assertIsNone(row["final_answer"])
            self.assertEqual(row["restoration_status"], "blocked")
            self.assertFalse(row["score"]["correct"])
            self.assertTrue(row["score"]["secondary_serialization_correct"])

    def test_scoring_canary_changes_only_final_scores_after_all_processing(self):
        report, data, server, _, _, _, _ = self.run_authored(poisoned=True)
        self.assertEqual((len(data["rows"]), len(server.posts)), (200, 184))
        for metrics in report["arms"].values():
            self.assertEqual((metrics["correct"], metrics["ready"], metrics["build_successes"]), (0, 32, 8))
        self.assertTrue(all(not r["required_fact_retained"] for r in data["rows"]))

    def test_unsigned_acl_change_is_rejected_by_real_transfer_before_answering(self):
        report, data, server, access, _, _, _ = self.run_authored(tamper=True)
        self.assertEqual((len(data["rows"]), report["answer_generations"], len(server.posts)), (200, 0, 24))
        self.assertTrue(all(r["prepare_error"] == "access_signature_invalid" for r in data["rows"]))
        self.assertTrue(all(a["result"] == "access_signature_invalid" for a in access))
        for metrics in report["arms"].values():
            self.assertEqual(metrics["ready"], 0)
            self.assertEqual(metrics["outsider_blocked"], 0)


if __name__ == "__main__":
    unittest.main()
