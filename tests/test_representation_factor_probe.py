"""Offline controls for a development-only diagnostic; no real inference."""
from collections import Counter
from copy import deepcopy
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from memory_migration_study import focused_semantic_reader as legacy
from memory_migration_study.representation_factor_probe import (
    CONDITIONS, REPRESENTATIONS, PROMPTS, SYSTEMS, TYPE_LABELS, ModelBudget,
    canonical, digest, entity_map, model_body, substitute, validate_entities,
    call_model, score,
)
from scripts import run_representation_factor_20261027 as driver


class RepresentationFactorProbeTests(unittest.TestCase):
    def setUp(self):
        self.material = driver.parse(driver.MATERIAL)
        self.registry = driver.parse(driver.ENTITIES)
        self.story = self.material["stories"][-1]
        self.question = self.story["questions"][-1]
        self.entities = self.registry["stories"][self.story["id"]]
        self.nonce = "ABCDEF0123456789ABCDEF01"

    def body(self, representation="long_customer", prompt="original"):
        return model_body(self.story, self.question, self.entities, representation, prompt, self.nonce)

    def response(self, raw):
        return {"model": driver.MODEL, "done": True, "prompt_eval_count": 100, "eval_count": 7,
                "message": {"content": '{"answer_id":"UNKNOWN"}'}}

    def test_all_entities_roundtrip_with_four_candidates_in_every_body(self):
        validate_entities(self.material, self.registry)
        for story in self.material["stories"]:
            entities = self.registry["stories"][story["id"]]
            for representation in REPRESENTATIONS:
                mapping = entity_map(entities, representation, self.nonce)
                for question in story["questions"]:
                    body = model_body(story, question, entities, representation, "original", self.nonce)
                    user = json.loads(body["messages"][1]["content"])
                    self.assertEqual([r["answer_id"] for r in user["fact_cards"]], ["F1", "F2", "F3", "F4"])
                    self.assertEqual(substitute(user["query"], {v:k for k,v in mapping.items()}), question["text"])
                    self.assertEqual(set(user), {"query", "fact_cards"})
                    self.assertTrue(all(set(f) == {"answer_id", "statement"} for f in user["fact_cards"]))
                    if representation != "raw":
                        self.assertFalse(any(v.encode() in canonical(body) for v in story["sensitive_values"]))

    def test_original_raw_body_matches_old_reader_exactly_and_prompt_is_only_prompt_difference(self):
        raw = legacy.candidates(self.story, {o["key"]:o["text"] for o in self.story["objects"]})
        cap = SimpleNamespace(prepared=None, raw_candidates=raw)
        self.assertEqual(canonical(self.body("raw")), canonical(legacy.model_body(cap, self.question)))
        for representation in REPRESENTATIONS:
            left, right = self.body(representation), self.body(representation, "evidence")
            right["messages"][0]["content"] = left["messages"][0]["content"]
            self.assertEqual(canonical(left), canonical(right))
        self.assertEqual(SYSTEMS["original"], legacy.SYSTEM)
        self.assertNotIn("budget", SYSTEMS["evidence"].lower())
        self.assertNotIn("approv", SYSTEMS["evidence"].lower())

    def test_nonce_prefix_indices_and_type_width_are_bound_across_arms(self):
        self.assertTrue(all(len(label) == len("CUSTOMER") == 8 for label in TYPE_LABELS.values()))
        maps = {r:entity_map(self.entities, r, self.nonce) for r in REPRESENTATIONS}
        for value in self.story["sensitive_values"]:
            for short, long in (("short_customer", "long_customer"), ("short_typed", "long_typed")):
                self.assertEqual(maps[short][value].replace(self.nonce[:4], self.nonce, 1), maps[long][value])
            self.assertEqual(len(maps["short_customer"][value]), len(maps["short_typed"][value]))
            self.assertEqual(len(maps["long_customer"][value]), len(maps["long_typed"][value]))
            self.assertEqual(maps["long_customer"][value].rsplit("_", 1)[-1], maps["long_typed"][value].rsplit("_", 1)[-1])

    def test_nonbijective_unknown_type_or_original_overlap_registry_rejected(self):
        for mutation in ("duplicate", "type", "original", "order"):
            registry = deepcopy(self.registry)
            rows = registry["stories"][self.story["id"]]
            if mutation == "duplicate": rows[1]["pseudonym"] = rows[0]["pseudonym"]
            if mutation == "type": rows[0]["type"] = "CUSTOMER"
            if mutation == "original": rows[0]["pseudonym"] = rows[0]["value"]
            if mutation == "order": rows.reverse()
            with self.assertRaises(ValueError): validate_entities(self.material, registry)

    def test_plan_is_complete_balanced_and_does_not_parse_reference_or_call_network(self):
        original_parse = driver.parse
        def parse_without_reference(path):
            self.assertNotEqual(Path(path).resolve(), driver.REFERENCE.resolve())
            return original_parse(path)
        with patch.object(driver, "parse", side_effect=parse_without_reference), \
             patch.object(driver.LocalSensitivityAgent, "health", side_effect=AssertionError("network")), \
             patch.object(driver.LoopbackJSONSender, "__call__", side_effect=AssertionError("model")):
            plan = driver.build_plan()
        self.assertEqual(len(plan["requests"]), 144)
        for condition in CONDITIONS:
            positions = [r["position"] % 12 for r in plan["requests"] if r["condition"] == condition]
            self.assertEqual(Counter(positions), Counter(range(12)))
        for start in range(0, 144, 12):
            rows = plan["requests"][start:start+12]
            self.assertEqual(len({r["nonce"] for r in rows}), 1)
            self.assertEqual({r["condition"] for r in rows}, set(CONDITIONS))

    def test_failed_transport_consumes_one_attempt_without_retry_and_actual_bytes_match(self):
        calls = []
        def fail(raw):
            calls.append(raw)
            raise OSError("offline failure")
        body, budget = self.body(), ModelBudget(1)
        row = call_model({}, body, self.story["sensitive_values"], budget, sender=fail)
        self.assertEqual((row["status"], row["failure_class"], row["model_calls"]), ("error", "transport_failed", 1))
        self.assertEqual(calls, [canonical(body)])
        self.assertEqual(budget.attempted, 1)
        again = call_model({}, body, [], budget, sender=fail)
        self.assertEqual(again["failure_class"], "model_budget_exhausted")
        self.assertEqual(len(calls), 1)

    def test_wire_value_leak_blocks_before_attempt_and_response_escaped_leak_is_failure(self):
        body, budget = self.body(), ModelBudget(2)
        body["messages"][1]["content"] += self.story["sensitive_values"][0]
        calls = []
        def sender(raw): calls.append(raw); return self.response(raw)
        row = call_model({}, body, self.story["sensitive_values"], budget, sender=sender)
        self.assertEqual((row["failure_class"], row["model_calls"], calls), ("registered_sensitive_value_present", 0, []))
        def leaked(raw):
            response = self.response(raw)
            response["aux"] = ''.join('\\u%04x' % ord(c) for c in self.story["sensitive_values"][0])
            return response
        row = call_model({}, self.body(), self.story["sensitive_values"], budget, sender=leaked)
        self.assertEqual(row["failure_class"], "response_registered_value_present")

    def test_forged_output_and_token_overflow_are_retained_as_execution_failure(self):
        for bad in ("F9", "duplicate", "tokens"):
            def sender(raw):
                response = self.response(raw)
                if bad == "F9": response["message"]["content"] = '{"answer_id":"F9"}'
                if bad == "duplicate": response["message"]["content"] = '{"answer_id":"F1","answer_id":"UNKNOWN"}'
                if bad == "tokens": response["eval_count"] = 65
                return response
            row = call_model({}, self.body(), [], ModelBudget(1), sender=sender)
            self.assertEqual((row["status"], row["model_calls"]), ("error", 1))

    def test_scoring_preserves_all_cells_and_reports_legal_unknown_missing_hallucination_and_flips(self):
        reference = driver.parse(driver.REFERENCE)
        legal = next(r for r in reference["rows"] if r["kind"] == "legal")
        missing = next(r for r in reference["rows"] if r["kind"] == "missing")
        predictions = [dict(legal, condition="raw:original", status="ok", answer_id="UNKNOWN"),
            dict(legal, condition="raw:evidence", status="ok", answer_id=legal["expected_id"]),
            dict(missing, condition="raw:original", status="ok", answer_id="F1")]
        metrics = score(predictions, reference)
        self.assertEqual((metrics["planned_predictions"], metrics["observed_predictions"], len(metrics["rows"])), (144, 3, 144))
        outcomes = Counter(r["semantic_outcome"] for r in metrics["rows"])
        self.assertEqual(outcomes, {"legal_unknown":1, "correct":1, "missing_hallucination":1, "execution_failure":141})
        flip = metrics["paired_contrasts"][0]
        self.assertEqual((flip["planned_pairs"], flip["gain"], flip["loss"]), (12, 1, 0))
        with self.assertRaises(ValueError): score(predictions + predictions[:1], reference)

    def test_driver_hard_failure_stops_after_one_attempt_retains_143_not_run_and_exits_nonzero(self):
        calls = []
        def fail(raw):
            calls.append(raw)
            raise OSError("offline injected hard transport failure")
        plan = driver.build_plan()
        (driver.ROOT / "results").mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=driver.ROOT / "results") as scratch, \
             tempfile.TemporaryDirectory(dir=driver.ROOT / "results") as run_root:
            output = Path(run_root).resolve()
            output.rmdir()  # execute requires a fresh directory; tempfile owns cleanup.
            plan_path = Path(scratch) / "plan.json"
            driver.save(plan_path, plan)
            args = ["probe", "--execute", str(plan_path), "--expected-plan-sha256", digest(plan), "--output", str(output)]
            with patch.object(sys, "argv", args), \
                 patch.object(driver.LocalSensitivityAgent, "health", return_value={"offline_test_only": True}), \
                 patch.object(driver, "LoopbackJSONSender", return_value=fail), \
                 self.assertRaises(SystemExit) as stopped:
                driver.main()
            self.assertEqual(stopped.exception.code, 1)
            summary = driver.parse(output / "summary.json")
            predictions = driver.parse(output / "predictions.json")
            self.assertEqual((summary["status"], summary["model_calls"], len(calls)), ("failed_closed", 1, 1))
            self.assertEqual(Counter(p["status"] for p in predictions), {"error": 1, "not_run": 143})
            self.assertEqual(sum(p["model_calls"] for p in predictions), 1)
            self.assertEqual(driver.parse(output / "prediction_phase_closed.json")["reference_parsed"], False)

    def test_unrelated_deleted_module_does_not_pollute_frozen_dependency_inventory(self):
        foreign = SimpleNamespace(__file__=str(driver.ROOT / "results/deleted_unrelated_module.py"))
        with patch.dict(sys.modules, {"representation_probe_unrelated_deleted_module": foreign}):
            plan = driver.build_plan()
        self.assertEqual(set(plan["code_sha256"]), set(driver.CODE_INPUTS))
        self.assertEqual(len(plan["code_sha256"]), 14)


if __name__ == "__main__":
    unittest.main()
