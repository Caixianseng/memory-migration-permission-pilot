"""Offline native-style receipts; never launch clients or qualify a native run."""
from copy import deepcopy
import hashlib
import inspect
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import run_native_semantic_validation as base
from scripts import run_native_semantic_validation_continuation as d

REAL_ROOT = base.ROOT


def native_style_harness_receipt(memory):
    """Complete success-field shape observed from the official wrapper."""
    return {"status": "ok", "answer": '{"answer_id":"F1"}', "raw_response": '{"answer_id":"F1"}',
        "version": "0.2.1-rc.3", "model": "deepseek-flash", "wrapper_version": "deepseek-native-question-v3",
        "invocation_started": True, "agent_memory_file_sha256": base.digest(memory.encode()),
        "cli_entry_sha256": "ed8bd3ca840d67599bde74f940cdb1714f7b7a98cecd166705a42a661e5cd1b7",
        "runtime_archive_sha256": "04b32e3a872826ba15cfb2081c6a929a8d4ecaa65e09a2543e5a6b30e2eff1f0",
        "credentials_source_unchanged": True, "temporary_credentials_removed": True,
        "native_instruction_loaded": True, "native_instruction_baselines": [{"seq": 1,
            "source": {"kind": "agent-instructions", "baseline": True,
                "changes": [{"action": "set", "scope": ".\0AGENTS.md", "path": "AGENTS.md",
                             "digest": hashlib.sha1(memory.encode()).hexdigest()}]},
            "content": [{"type": "text", "text": memory}], "native_rendered_content_sha256": base.digest(memory.encode())}],
        "guard_counts": {"agent_attempt_count": 1, "stream_attempt_count": 1, "allowed_stream_count": 1,
            "dry_run": False, "reject_code": None, "requests": [{"count": 1, "maxTokens": 64, "bytes": 1000, "bodyhash": "a" * 64}],
            "shape": {"stage": "full_request", "provider_matches": True, "model_matches": True,
                "reasoning_off": True, "max_tokens_present": True, "max_tokens_type": "number", "tool_count": 0,
                "tools_type": "undefined", "roles": ["system", "user", "user", "user"], "unknown_key_count": 0}},
        "usage": {"inputTokens": 489, "outputTokens": 7, "totalTokens": 496}, "exit_code": 0, "error": None}


class NativeReceiptAlgorithmTests(unittest.TestCase):
    def setUp(self):
        self.memory = "# Controlled synthetic memory\nOrin Bell owns final approval.\n"
        self.receipt = native_style_harness_receipt(self.memory)
        self.sha = base.digest(self.memory.encode())

    def test_genuine_sha1_native_baseline_and_sha256_file_are_both_required(self):
        original = deepcopy(self.receipt)
        base.validate_native_receipt("harness", self.receipt, self.memory, self.sha)
        d.validate_receipt("harness", self.receipt, self.memory, self.sha)
        self.assertEqual(self.receipt, original)

    def test_sha256_in_native_sha1_field_is_not_accepted(self):
        self.receipt["native_instruction_baselines"][0]["source"]["changes"][0]["digest"] = self.sha
        with self.assertRaisesRegex(ValueError, "harness_memory_load_unproved"):
            base.validate_native_receipt("harness", self.receipt, self.memory, self.sha)
        with self.assertRaisesRegex(ValueError, "sha1_baseline"):
            d.validate_receipt("harness", self.receipt, self.memory, self.sha)

    def test_sha1_in_local_sha256_field_is_not_accepted(self):
        with self.assertRaisesRegex(ValueError, "sha256_mismatch"):
            base.validate_native_receipt("harness", self.receipt, self.memory, hashlib.sha1(self.memory.encode()).hexdigest())
        with self.assertRaisesRegex(ValueError, "sha256_mismatch"):
            d.validate_receipt("harness", self.receipt, self.memory, hashlib.sha1(self.memory.encode()).hexdigest())

    def test_missing_cleanup_guard_identity_and_loaded_proofs_reject(self):
        for field, replacement in (("credentials_source_unchanged", False), ("temporary_credentials_removed", False),
                                   ("version", "wrong"), ("native_instruction_loaded", False)):
            changed = deepcopy(self.receipt)
            changed[field] = replacement
            with self.assertRaises(ValueError):
                d.validate_receipt("harness", changed, self.memory, self.sha)
        self.receipt["guard_counts"]["allowed_stream_count"] = 2
        with self.assertRaisesRegex(ValueError, "guard_unproved"):
            d.validate_receipt("harness", self.receipt, self.memory, self.sha)

    def test_baseline_kind_path_text_and_exact_digest_are_bound(self):
        for location, value in (("kind", "unrelated"), ("path", "other.md"), ("digest", "b" * 40), ("text", "different memory")):
            changed = deepcopy(self.receipt)
            baseline = changed["native_instruction_baselines"][0]
            if location == "kind":
                baseline["source"]["kind"] = value
            elif location == "text":
                baseline["content"][0]["text"] = value
            else:
                baseline["source"]["changes"][0][location] = value
            with self.assertRaisesRegex(ValueError, "sha1_baseline"):
                d.validate_receipt("harness", changed, self.memory, self.sha)

    def test_production_entrypoints_expose_no_transport_injection(self):
        self.assertEqual(list(inspect.signature(d.execute).parameters), ["path"])
        self.assertNotIn("native_call", inspect.signature(d.call_slot).parameters)


class ContinuationPlanBudgetTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "results").mkdir()
        material = self.root / base.MATERIAL
        material.parent.mkdir(parents=True)
        material.write_bytes((REAL_ROOT / base.MATERIAL).read_bytes())
        for target, attr, value in ((base, "ROOT", self.root), (d, "ROOT", self.root)):
            p = patch.object(target, attr, value)
            p.start(); self.addCleanup(p.stop)
        for target, attr, value in ((base, "manifest", {}), (d, "manifest", {}), (base, "install_qualification", {"offline": True})):
            p = patch.object(target, attr, return_value=value)
            p.start(); self.addCleanup(p.stop)
        self.parent = self.root / "results/parent"
        self.parent_plan = base.plan_only(self.parent)
        rows = []
        for slot in self.parent_plan["slots"]:
            row = {k: slot[k] for k in ("index", "slot_id", "pair_id", "direction", "question_id", "stage", "view", "client", "input_sha256")}
            row.update(status="not_run", failure_class="not_run", answer_id=None, client_attempts=0)
            rows.append(row)
        for index in (0, 1):
            slot, row = self.parent_plan["slots"][index], rows[index]
            memory = slot["agents_md"]
            sha = base.digest(memory.encode())
            row.update(status="ok" if index == 0 else "error", failure_class=None if index == 0 else "engineering",
                error=None if index == 0 else "harness_memory_load_unproved", client_attempts=1,
                memory_before_sha256=sha, memory_after_sha256=sha, restoration_status="ok" if index == 0 else None)
            row["receipt"] = native_style_harness_receipt(memory)
            if index == 0:
                row["receipt"].update(version="1.1.77", model="DeepSeek-Flash", wrapper_version="qoder-native-question-v1",
                    cli_entry_sha256="9a8fb19bb7f2dfe8d9d9933cb356fd21e789544316bacadc4f6c9b760bd41315")
            (self.parent / slot["slot_id"]).mkdir()
            (self.parent / slot["slot_id"] / "AGENTS.md").write_bytes(memory.encode())
            base.save(self.parent / (slot["slot_id"] + "_result.json"), row)
            base.save(self.parent / (slot["slot_id"] + "_reservation.json"), {"index": index})
        base.save(self.parent / "predictions.json", rows)
        base.save(self.parent / "summary.json", {"status": "engineering_failed"})
        base.save(self.parent / "readonly_diagnosis.json", {"driver_error": "SHA1 versus SHA256"})
        base.save(self.parent / "prediction_phase_closed.json", {"all_24_slots_closed": True, "reserved_attempts": 2,
            "prediction_file_sha256": base.digest((self.parent / "predictions.json").read_bytes())})
        for attr, path in (("PARENT_EXPECTED_PLAN_HASH", "plan.json"), ("PARENT_EXPECTED_PREDICTIONS_HASH", "predictions.json")):
            p = patch.object(d, attr, base.digest((self.parent / path).read_bytes()))
            p.start(); self.addCleanup(p.stop)
        self.rows = rows

    def test_inherited_budget_leaves_exactly22_new_attempts(self):
        budget = d.ContinuationBudget(self.rows[:2])
        self.assertEqual(budget.attempts, 2)
        for client in ("qoder", "harness"):
            for _ in range(11):
                budget.reserve(client)
        self.assertEqual(budget.attempts, 24)
        self.assertEqual(budget.clients, {"qoder": 12, "harness": 12})
        with self.assertRaisesRegex(ValueError, "budget"):
            budget.reserve("harness")

    def test_parent_per_client_inheritance_cannot_be_changed(self):
        changed = deepcopy(self.rows[:2])
        changed[1]["client"] = "qoder"
        with self.assertRaisesRegex(ValueError, "parent_per_client"):
            d.ContinuationBudget(changed)

    def test_frozen_continuation_preserves_all_inputs_aliases_and_order(self):
        output = self.root / "results/continuation"
        plan = d.plan_only(self.parent, output)
        self.assertEqual(plan["slots"], self.parent_plan["slots"])
        self.assertEqual(plan["pairs"], self.parent_plan["pairs"])
        self.assertEqual(plan["execute_indices"], list(range(2, 24)))
        self.assertEqual(plan["native_inputs_sha256"], self.parent_plan["native_inputs_sha256"])
        self.assertEqual(d.approved(output / "plan.json")[0], plan)
        self.assertFalse((output / "execution_started.json").exists())

    def test_parent_evidence_mutation_blocks_continuation(self):
        output = self.root / "results/continuation"
        d.plan_only(self.parent, output)
        (self.parent / "readonly_diagnosis.json").write_text("{}", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "parent_evidence"):
            d.approved(output / "plan.json")

    def test_frozen_parent_copy_tampering_blocks(self):
        output = self.root / "results/continuation"
        d.plan_only(self.parent, output)
        (output / "frozen_parent/summary.json").write_text("{}", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "frozen_parent"):
            d.approved(output / "plan.json")

    def test_pending_indices_cannot_include_prior_native_attempts(self):
        output = self.root / "results/continuation"
        plan = d.plan_only(self.parent, output)
        plan["execute_indices"] = list(range(1, 24))
        (output / "plan.json").write_bytes(base.encoded(plan))
        with self.assertRaisesRegex(ValueError, "budget_changed"):
            d.approved(output / "plan.json")

    def test_posthoc_raw_restore_keeps_original_failure_and_names_new_scope(self):
        output = self.root / "results/continuation"
        plan = d.plan_only(self.parent, output)
        states, caps = base.setup_caps(plan, output, base.story_material())
        slot = plan["slots"][1]
        result = d.revalidate_inherited(slot, self.rows[1], caps[slot["slot_id"]], states[slot["pair_id"]], base.story_material())
        self.assertEqual(result["status"], "ok", result)
        self.assertEqual(result["original_status"], "error")
        self.assertIsNone(result["original_restoration_status"])
        self.assertEqual(result["current_phase_model_calls"], 0)
        self.assertIn("not original call-time restoration", result["restoration_scope"])
        self.assertEqual(result["answer_id"], "F1")


if __name__ == "__main__":
    unittest.main()
