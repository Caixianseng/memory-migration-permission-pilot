"""Offline contract tests. Test doubles never qualify as native evidence."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import run_native_semantic_validation as d

REAL_ROOT = d.ROOT


class NativeSemanticValidationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        (self.root / "results").mkdir()
        material = self.root / d.MATERIAL
        material.parent.mkdir(parents=True)
        material.write_bytes((REAL_ROOT / d.MATERIAL).read_bytes())
        # The reference is only for explicit offline scorer tests, not setup.
        self.patches = [patch.object(d, "ROOT", self.root), patch.object(d, "manifest", return_value={}),
                        patch.object(d, "install_qualification", return_value={"offline": True})]
        for p in self.patches:
            p.start(); self.addCleanup(p.stop)
        self.out = self.root / "results/run"
        self.plan = d.plan_only(self.out)
        self.story = d.story_material()

    def setup_caps(self):
        states, caps = d.setup_caps(self.plan, self.out, self.story)
        self.addCleanup(lambda: [setattr(cap, "closed", True) for cap in caps.values()])
        return states, caps

    def test_frozen_inventory_24_slots_12_per_client(self):
        self.assertEqual(len(self.plan["slots"]), 24)
        self.assertEqual(len(self.plan["pairs"]), 12)
        for client in ("qoder", "harness"):
            rows = [s for s in self.plan["slots"] if s["client"] == client]
            self.assertEqual(len(rows), 12)
            for stage in ("source", "target"):
                for view in ("raw", "private"):
                    self.assertEqual(len([s for s in rows if s["stage"] == stage and s["view"] == view]), 3)

    def test_plan_mode_does_not_invoke_clients_or_parse_reference(self):
        self.assertFalse((self.root / d.REFERENCE).exists())
        self.assertFalse((self.out / "execution_started.json").exists())
        self.assertNotIn("expected_id", d.encoded(self.plan).decode())
        self.assertNotIn("question_family", d.encoded(self.plan).decode())

    def test_all_four_cards_only_in_memory_and_preserved_system_question(self):
        for slot in self.plan["slots"]:
            cards = d.parse_memory(slot["agents_md"])
            self.assertEqual([c["answer_id"] for c in cards], list(d.IDS))
            self.assertNotIn("fact_cards", slot["prompt"])
            self.assertTrue(slot["prompt"].startswith(d.SYSTEM + d.ADAPTER))
            if slot["view"] == "raw":
                question = next(q for q in self.story["questions"] if q["id"] == slot["question_id"])
                self.assertIn(question["text"], slot["prompt"])

    def test_private_full_host_input_excludes_all_registered_values(self):
        for slot in self.plan["slots"]:
            if slot["view"] == "private":
                self.assertFalse(d.scan_registered({"prompt": slot["prompt"], "agents_md": slot["agents_md"]}, self.story["sensitive_values"]))
                self.assertIn("_CUSTOMER_", slot["agents_md"])

    def test_same_logical_question_has_equal_inputs_across_stage_clients(self):
        for view in ("raw", "private"):
            for question in ("Q1", "Q2", "Q3"):
                slots = [s for s in self.plan["slots"] if s["view"] == view and s["question_id"] == question]
                self.assertEqual(len({s["input_sha256"] for s in slots}), 1)

    def test_duplicate_or_reordered_cards_rejected(self):
        cards = d.parse_memory(self.plan["slots"][0]["agents_md"])
        cards.reverse()
        with self.assertRaisesRegex(ValueError, "four_card"):
            d.render_memory(cards)

    def test_memory_parser_rejects_extra_fields(self):
        text = self.plan["slots"][0]["agents_md"].replace('{"fact_cards":', '{"gold":"F1","fact_cards":')
        with self.assertRaisesRegex(ValueError, "fields_changed"):
            d.parse_memory(text)

    def test_plan_binding_detects_changed_input(self):
        path = self.out / "plan.json"
        changed = deepcopy(self.plan)
        changed["slots"][0]["prompt"] += "changed"
        path.write_bytes(d.encoded(changed))
        with self.assertRaisesRegex(ValueError, "input_order_changed"):
            d.approved(path)

    def test_scope_rejects_escape(self):
        with self.assertRaisesRegex(ValueError, "scope"):
            d.scope(self.root / "outside")

    def test_migration_reads_actual_source_and_packet_and_target(self):
        pair = self.plan["pairs"][0]
        state = d.migrate_pair(pair, self.out, self.story)
        self.assertEqual(state["source_cards"], state["target_cards"])
        self.assertTrue(state["evidence"]["source_target_exact"])
        self.assertEqual(len(state["packet"]["items"]), 4)
        self.assertNotIn(pair["source_only"], d.encoded(state["packet"]).decode())

    def test_actual_source_change_propagates_to_migration(self):
        pair = deepcopy(self.plan["pairs"][0])
        pair["raw_source_agents_md"] = pair["raw_source_agents_md"].replace("owns final approval", "owns documented final approval")
        state = d.migrate_pair(pair, self.out, self.story)
        self.assertIn("documented", state["target_cards"][0]["statement"])

    def test_independent_capabilities_share_only_visible_projection(self):
        states, caps = self.setup_caps()
        for pair in self.plan["pairs"]:
            if pair["view"] != "private":
                continue
            source = caps[pair["pair_id"] + "_source"]
            target = caps[pair["pair_id"] + "_target"]
            self.assertIsNot(source.authority, target.authority)
            self.assertIsNot(source.prepared, target.prepared)
            self.assertNotEqual(source.request_id, target.request_id)
            self.assertNotEqual(source.own_tokens, target.own_tokens)
            self.assertEqual(source.check()["decision"], "allow")
            self.assertEqual(target.check()["decision"], "allow")

    def test_host_controls_are_zero_model_and_requalify(self):
        states, caps = self.setup_caps()
        rows = d.host_controls(states, caps, self.plan)
        self.assertEqual(len(rows), 156)
        self.assertTrue(all(r["passed"] and r["model_calls"] == 0 for r in rows))

    def test_file_or_package_change_makes_current_host_check_unknown(self):
        states, caps = self.setup_caps()
        slot = self.plan["slots"][0]
        state = states[slot["pair_id"]]
        path = state["source"] / "AGENTS.md"
        path.write_text(path.read_text() + "changed", encoding="utf-8")
        self.assertEqual(caps[slot["slot_id"]].check()["decision"], "unknown")

    def test_cross_scope_prepared_swaps_and_closed_replay_reject(self):
        states, caps = self.setup_caps()
        pair = next(p for p in self.plan["pairs"] if p["view"] == "private")
        source, target = (caps[pair["pair_id"] + "_" + arm] for arm in ("source", "target"))
        kwargs = dict(story_id=self.story["id"], question_id=source.question_id, condition=source.condition, request_id=source.request_id)
        with self.assertRaisesRegex(ValueError, "scope_mismatch"):
            source.restore("F1", **{**kwargs, "request_id": target.request_id})
        original = source.prepared
        source.prepared = target.prepared
        self.assertEqual(source.restore("F1", **kwargs)["status"], "blocked")
        source.prepared = original
        source.closed = True
        with self.assertRaisesRegex(ValueError, "closed"):
            source.restore("UNKNOWN", **kwargs)

    def fake_call(self, answer='{"answer_id":"UNKNOWN"}', status="ok"):
        def call(client, workspace, prompt, runtime):
            self.assertTrue(any(self.out.glob("*_reservation.json")))
            return {"status": status, "answer": answer, "raw_response": answer,
                    "agent_memory_file_sha256": d.digest((workspace / "AGENTS.md").read_bytes()),
                    "native_instruction_loaded": True, "native_instruction_baselines": [{"offline_test": True}],
                    "version": "1.1.77", "model": "DeepSeek-Flash", "wrapper_version": "qoder-native-question-v1",
                    "cli_entry_sha256": "9a8fb19bb7f2dfe8d9d9933cb356fd21e789544316bacadc4f6c9b760bd41315",
                    "invocation_started": True, "error": None}
        return call

    def test_success_reserves_before_call_and_closes_capability(self):
        states, caps = self.setup_caps()
        slot = self.plan["slots"][0]
        budget = d.AttemptBudget()
        row = d.call_slot(slot, caps[slot["slot_id"]], states[slot["pair_id"]], self.story, self.out, budget, self.fake_call())
        self.assertEqual(row["status"], "ok", row)
        self.assertEqual(budget.attempts, 1)
        self.assertTrue(caps[slot["slot_id"]].closed)
        self.assertEqual(row["answer_id"], "UNKNOWN")

    def test_format_failure_still_scans_private_raw_and_source_only(self):
        states, caps = self.setup_caps()
        slot = next(s for s in self.plan["slots"] if s["view"] == "private")
        state = states[slot["pair_id"]]
        answer = 'bad-format ' + self.story["sensitive_values"][0] + state["pair"]["source_only"]
        row = d.call_slot(slot, caps[slot["slot_id"]], state, self.story, self.out, d.AttemptBudget(), self.fake_call(answer))
        self.assertTrue(row["response_registered_raw_present"])
        self.assertTrue(row["response_source_only_present"])
        self.assertEqual(row["failure_class"], "engineering")
        self.assertEqual(row["client_attempts"], 1)

    def test_plain_format_failure_separate_from_semantic_unknown(self):
        states, caps = self.setup_caps()
        slot = self.plan["slots"][0]
        row = d.call_slot(slot, caps[slot["slot_id"]], states[slot["pair_id"]], self.story, self.out, d.AttemptBudget(), self.fake_call("not JSON"))
        self.assertEqual(row["failure_class"], "format")

    def test_budget_hard_cap_and_invalid_client(self):
        budget = d.AttemptBudget()
        for _ in range(12):
            budget.reserve("qoder")
        with self.assertRaisesRegex(ValueError, "budget"):
            budget.reserve("qoder")
        for _ in range(12):
            budget.reserve("harness")
        self.assertEqual(budget.attempts, 24)
        with self.assertRaisesRegex(ValueError, "budget"):
            budget.reserve("other")

    def test_scoring_keeps_24_denominator_and_distinct_failures(self):
        refs = {"rows": [{"story_id": "dev_en_paraphrase", "question_id": q, "kind": kind, "expected_id": expected}
                         for q, kind, expected in (("Q1", "legal", "F1"), ("Q2", "legal", "F3"), ("Q3", "missing", "UNKNOWN"))]}
        rows = [{**s, "status": "ok", "answer_id": "UNKNOWN", "failure_class": None} for s in self.plan["slots"]]
        rows[0].update(status="error", failure_class="interface")
        metrics = d.score_rows(rows, refs)
        self.assertEqual(metrics["denominator"], 24)
        self.assertEqual(metrics["classifications"]["interface"], 1)
        self.assertEqual(sum(c["denominator"] for c in metrics["cells"].values()), 24)
        self.assertEqual(len(metrics["same_client_source_target_pairs"]), 12)
        self.assertTrue(all(p["host_inputs_equal"] for p in metrics["same_client_source_target_pairs"]))

    def test_scan_decoded_json_keys_and_unicode_escape(self):
        value = "Orin Bell"
        self.assertTrue(d.scan_registered(json.loads('{"Orin\\u0020Bell":"wrong-format"}'), [value]))
        self.assertTrue(d.scan_registered({"raw_response": value}, [value]))
        self.assertTrue(d.scan_registered({"raw_response": '{"invalid":"Orin\\u0020Bell"}'}, [value]))

    def test_interface_failure_stops_no_retry_and_closes_before_runtime_scoring(self):
        reference = {"rows": [{"story_id": "dev_en_paraphrase", "question_id": q, "kind": kind, "expected_id": expected}
                              for q, kind, expected in (("Q1", "legal", "F1"), ("Q2", "legal", "F3"), ("Q3", "missing", "UNKNOWN"))]}
        path = self.root / d.REFERENCE
        path.write_bytes(d.encoded(reference))
        frozen = self.out / "frozen_source" / d.REFERENCE
        frozen.parent.mkdir(parents=True)
        frozen.write_bytes(path.read_bytes())
        frozen_manifest = {d.REFERENCE: d.digest(path.read_bytes())}
        self.plan["implementation_sha256"] = frozen_manifest
        (self.out / "plan.json").write_bytes(d.encoded(self.plan))
        original_score = d.score_rows
        def score(rows, ref):
            closure = json.loads((self.out / "prediction_phase_closed.json").read_bytes())
            self.assertTrue(closure["all_24_slots_closed"])
            self.assertEqual(closure["prediction_file_sha256"], d.digest((self.out / "predictions.json").read_bytes()))
            return original_score(rows, ref)
        calls = []
        fake = self.fake_call(status="error")
        def call(*args):
            calls.append(args[0])
            return fake(*args)
        actual_slot = d.call_slot
        with patch.object(d, "manifest", return_value=frozen_manifest), patch.object(d, "score_rows", side_effect=score), patch.object(d, "call_slot", side_effect=lambda *args: actual_slot(*args, native_call=call)):
            summary = d.execute(self.out / "plan.json")
        self.assertEqual(len(calls), 1)
        self.assertEqual(summary["client_attempts"], 1)
        self.assertEqual(summary["status"], "engineering_failed")
        self.assertEqual(summary["metrics"]["denominator"], 24)
        self.assertEqual(summary["metrics"]["classifications"]["not_run"], 23)

    def test_public_execute_has_no_test_transport_parameter(self):
        import inspect
        self.assertEqual(list(inspect.signature(d.execute).parameters), ["path"])

    def test_harness_success_requires_guard_identity_cleanup_and_native_baseline(self):
        with self.assertRaisesRegex(ValueError, "harness_native_identity"):
            d.validate_native_receipt("harness", {"invocation_started": True}, "memory", "digest")


if __name__ == "__main__":
    unittest.main()
