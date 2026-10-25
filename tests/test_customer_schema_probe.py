"""No model assets: fixed-schema protocol, late gold and metric contracts."""
import copy
import json
from pathlib import Path
import re
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scripts import run_customer_schema_probe as probe

CANARY = "SCORING_ONLY_PROBE_REFERENCE_6184"


class FakeProcessor:
    def transform_record(self, text, schema, *, max_len):
        return SimpleNamespace(input_ids=list(range(513 if "OVERSIZED" in text else 40)))


class FakeModel:
    def __init__(self):
        self.processor = FakeProcessor()
        self.calls = []

    def extract_entities(self, text, labels, *, threshold, include_confidence, include_spans):
        self.calls.append({"text": text, "labels": copy.deepcopy(labels), "threshold": threshold,
                           "include_confidence": include_confidence, "include_spans": include_spans})
        if "ENCODER_ERROR" in text:
            raise RuntimeError("self authored unavailable encoder")
        label = next(iter(labels))
        entities = []
        for value in (["Fictitious Buyer", "generic organization"] if label == "organization" else ["Fictitious Buyer"]):
            for match in re.finditer(re.escape(value), text):
                entities.append({"text": value, "start": match.start(), "end": match.end(), "confidence": .99})
        return {"entities": {label: entities}}


class FakeRuntime:
    identity = {"model_id": probe.MODEL_ID, "model_revision": probe.MODEL_REVISION,
                "code_revision": probe.CODE_REVISION, "weights_sha256": "0"*64}
    initialization_seconds = 0.0

    def __init__(self, root):
        self.model, self.calls = FakeModel(), []

    def infer(self, text, labels, *, splitter, threshold):
        self.calls.append({"text": text, "labels": copy.deepcopy(labels), "splitter": splitter, "threshold": threshold})
        encoded = self.model.processor.transform_record(text, labels, max_len=None)
        if len(encoded.input_ids) > 512:
            raise ValueError("input_budget_exceeded")
        return self.model.extract_entities(text, labels, threshold=threshold, include_confidence=True, include_spans=True)


def fixture(root, *, oversized=False, encoder_error=False):
    split, model = root/"corpus/development", root/"model"
    split.mkdir(parents=True)
    model.mkdir()
    runtime, evaluation = [], {}
    for i in range(8):
        sid, text = f"authored-schema-{i}", "Fictitious Buyer is a current client. A generic organization is a role."
        if i == 0 and oversized:
            text = "OVERSIZED "+text
        tasks = [{"task_id": "name", "actor_id": "owner", "query": "Name the generic organization."},
            {"task_id": "repeat", "actor_id": "owner", "query": "For Fictitious Buyer, what changed?"},
            {"task_id": "status", "actor_id": "owner", "query": "What is the status?"},
            {"task_id": "public", "actor_id": "owner", "query": "ENCODER_ERROR" if i == 0 and encoder_error else "Is it public?"},
            {"task_id": "outside", "actor_id": "outsider", "query": "OUTSIDER_MUST_NOT_REACH_ENCODER"}]
        runtime.append({"story_id": sid, "language": "en", "source": {"source_id": sid+"-source", "text": text},
            "tasks": tasks, "policy": copy.deepcopy(probe.POLICY)})
        a = text.index("Fictitious Buyer")
        evaluation[sid] = {"sensitive_spans": [{"start": a, "end": a+len("Fictitious Buyer")}],
            "answers": {"unused": CANARY}, "scoring_only_canary": CANARY}
    for name, data in (("runtime", runtime), ("evaluation", evaluation)):
        (split/(name+".json")).write_text(json.dumps(data), encoding="utf-8")
    (model/"receipt.json").write_text(json.dumps({"model_id": probe.MODEL_ID, "model_revision": probe.MODEL_REVISION,
        "code_revision": probe.CODE_REVISION, "files": {"model/model.safetensors": "0"*64}}), encoding="utf-8")
    return root/"corpus", model


class CustomerSchemaProbeTests(unittest.TestCase):
    def run_fake(self, *, oversized=False, encoder_error=False):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        corpus, model = fixture(root, oversized=oversized, encoder_error=encoder_error)
        planned = probe.run(corpus, root/"planned", model)
        self.assertEqual(planned["status"], "planned_only")
        runtime, progress, gold_reads = FakeRuntime(model), [], []
        real_loads = json.loads
        def loads(value, *args, **kwargs):
            marker = CANARY.encode() if isinstance(value, bytes) else CANARY
            if isinstance(value, (str, bytes)) and marker in value:
                self.assertEqual(len(runtime.calls), 80)
                self.assertEqual(len(progress), 80)
                self.assertTrue(all(not p["scored"] for p in progress))
                phase = real_loads((root/"executed/model_phase.json").read_bytes())
                self.assertTrue(phase["model_phase_closed"])
                gold_reads.append(len(runtime.calls))
            return real_loads(value, *args, **kwargs)
        with patch.object(json, "loads", new=loads), patch("socket.socket.connect", side_effect=AssertionError("network forbidden")):
            report = probe.run(corpus, root/"executed", model, execute=True,
                approved_plan=root/"planned/plan.json", runtime_factory=lambda _: runtime, progress=progress.append)
        data = {name: real_loads((root/"executed"/(name+".json")).read_bytes()) for name in ("plan", "rows", "references", "model_phase")}
        self.assertEqual(gold_reads, [80])
        self.assertEqual(report["recorded_rows"], 80)
        self.assertEqual(report["runtime_infer_attempts"], 80)
        self.assertEqual(report["extract_entities_calls"], len(runtime.model.calls))
        self.assertTrue(report["injected_test_runtime"])
        self.assertNotIn(CANARY, json.dumps(runtime.calls))
        self.assertNotIn("OUTSIDER_MUST_NOT", json.dumps(runtime.calls))
        self.assertTrue(all(c["splitter"] == "cjk_aware" and c["threshold"] == .5 for c in runtime.calls))
        return report, data, runtime

    def test_plan_only_does_not_parse_gold_or_load_runtime_and_changes_only_customer(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            corpus, model = fixture(root)
            real_loads = json.loads
            def no_gold(value, *args, **kwargs):
                self.assertNotIn(CANARY.encode() if isinstance(value, bytes) else CANARY, value)
                return real_loads(value, *args, **kwargs)
            with patch.object(json, "loads", new=no_gold):
                result = probe.run(corpus, root/"planned", model,
                    runtime_factory=lambda _: self.fail("runtime loaded during plan-only"))
            self.assertEqual(result["runtime_infer_attempts"], 0)
            plan = real_loads((root/"planned/plan.json").read_bytes())
            self.assertEqual((len(plan["units"]), len(plan["execution_order"])), (40, 80))
            self.assertEqual({k for k in plan["schemas"]["A"] if plan["schemas"]["A"][k] != plan["schemas"]["B"][k]}, {"CUSTOMER"})
            self.assertEqual(plan["schemas"]["B"]["CUSTOMER"][0], "customer organization")
            with self.assertRaisesRegex(ValueError, "matching_approved_plan_required"):
                probe.run(corpus, root/"blocked", model, execute=True, runtime_factory=lambda _: self.fail("unapproved model loaded"))
            self.assertFalse((root/"blocked").exists())

    def test_complete_80_calls_late_reference_and_independent_coverage_fp_checks(self):
        report, data, runtime = self.run_fake()
        self.assertEqual(report["extract_entities_calls"], 80)
        self.assertEqual(len({(r["unit_id"], r["arm"]) for r in data["rows"]}), 80)
        self.assertEqual(report["summary"]["paired"]["B_complete_regressions"], 0)
        self.assertEqual(report["summary"]["A"]["query"]["units_with_extra_characters"], 8)
        self.assertEqual(report["summary"]["B"]["query"]["units_with_extra_characters"], 0)
        for row in data["rows"]:
            gold = {(p, f["category"]) for f in row["reference"] for p in range(f["start"], f["end"])}
            predicted = {(p, f["category"]) for f in row["findings"] for p in range(f["start"], f["end"])}
            self.assertEqual(row["score"]["false_positive_characters"], len(predicted-gold))
            self.assertEqual(row["score"]["false_negative_characters"], len(gold-predicted))
            self.assertEqual(row["labels_sha256"], probe._digest(row["labels"]))

    def test_budget_rejection_and_error_keep_full_failure_denominators(self):
        report, data, runtime = self.run_fake(oversized=True, encoder_error=True)
        self.assertEqual(report["extract_entities_calls"], 78)
        self.assertEqual(sum(r["status"] != "ok" for r in data["rows"]), 4)
        rejected = [r for r in data["rows"] if r["error"] == "input_budget_exceeded"]
        self.assertEqual(len(rejected), 2)
        self.assertTrue(all(r["extract_entities_calls"] == 0 and r["encoding_observations"][0]["input_ids"] == 513 for r in rejected))
        self.assertTrue(all(r["score"]["missed"] == 1 and not r["score"]["all_complete_without_extra"] for r in rejected))
        for arm in ("A", "B"):
            self.assertEqual(report["summary"][arm]["all"]["registered_units"], 40)
            self.assertEqual(report["summary"][arm]["all"]["failed_units"], 2)

    def test_out_of_scope_business_policy_rejects_before_plan_or_encoder(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            corpus, model = fixture(root)
            file = corpus/"development/runtime.json"
            stories = json.loads(file.read_bytes())
            stories[0]["policy"]["instructions"] = "All organizations are secret, irrespective of customer role."
            file.write_text(json.dumps(stories), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "policy_scope_not_approved"):
                probe.run(corpus, root/"blocked", model, runtime_factory=lambda _: self.fail("out-of-scope model loaded"))
            self.assertFalse((root/"blocked").exists())


if __name__ == "__main__":
    unittest.main()
