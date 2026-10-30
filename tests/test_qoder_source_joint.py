"""Bounded source-provenance checks, all offline and synthetic.

These tests never prepare or run Qoder/Harness, probe accounts, or inspect real
memory. They exercise pure translation, a temporary trusted host, frozen-input
checks, and closed scoring records with handwritten outcomes.
"""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from experiments.qoder_source_generation_20261030 import joint_handoff as joint
from experiments.submission_acceptance_20261030.pipeline import JointHost, request


def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True), encoding="utf-8")


def h(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def spec():
    return {"facts": list(joint.FACTS), "tasks": deepcopy(joint.TASKS)}


class NativeSourceJointTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="source-joint-offline-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        for name in ("socket.socket", "socket.create_connection"):
            guard = patch(name, side_effect=AssertionError("network_forbidden"))
            guard.start(); self.addCleanup(guard.stop)
        for name in ("probe", "run_deepseek_question"):
            guard = patch.object(joint, name, side_effect=AssertionError("account_and_model_forbidden"))
            guard.start(); self.addCleanup(guard.stop)

    def closed_run(self, *, failed_source=False):
        out = self.base / "score-run"
        out.mkdir()
        material = spec()
        write_json(out / "input.json", material)
        expected = {"source-t1": "pine-source-8462@example.invalid", "source-t2": "北廊R-583柜",
                    "source-t3": "UNKNOWN", "source-t4": "UNKNOWN"}
        write_json(out / "evaluation_reference.json", expected)
        rows = []
        for task in material["tasks"]:
            for method in joint.METHODS:
                linked = method != "whole_block" and not failed_source
                rows.append({"slot": task["task_id"] + "-" + method, "task_id": task["task_id"],
                             "kind": task["kind"], "method": method,
                             "client_status": "not_run" if failed_source else "ok",
                             "raw_answer": None if failed_source else expected[task["task_id"]],
                             "final_answer": None if failed_source else expected[task["task_id"]],
                             "processing_error": "source_generation_failed" if failed_source else None,
                             "restoration_status": "blocked" if failed_source else "ok",
                             "shared_actual_call_with": task["task_id"] + "-whole_block" if linked else None,
                             "raw_registered_email_disclosure": None if failed_source else False,
                             "raw_forbidden_disclosure": None if failed_source else False})
        write_json(out / "predictions.json", rows)
        write_json(out / "plan.json", {"input_sha256": h(out / "input.json"),
                                       "references_sha256": h(out / "evaluation_reference.json")})
        write_json(out / "source_generation.json", {"status": "failed" if failed_source else "ok",
                                                   "tool_result_success": not failed_source})
        write_json(out / "accounting.json", {"source_generation_qualified": not failed_source,
                                             "harness_attempts": 0 if failed_source else 4})
        write_json(out / "prediction_phase_closed.json", {
            "predictions_sha256": h(out / "predictions.json"),
            "references_sha256": h(out / "evaluation_reference.json"),
            "source_generation_sha256": h(out / "source_generation.json"),
            "scoring_reference_opened": False, "all_slots_closed": True})
        return out, rows

    def refreeze_predictions(self, out, rows):
        write_json(out / "predictions.json", rows)
        closed = json.loads((out / "prediction_phase_closed.json").read_text(encoding="utf-8"))
        closed["predictions_sha256"] = h(out / "predictions.json")
        write_json(out / "prediction_phase_closed.json", closed)

    def test_source_case_preserves_actual_exact_text_and_positions(self):
        material = spec(); text = "\n".join(material["facts"]) + "\n"
        file = self.base / "AGENTS.md"; file.write_bytes(text.encode("utf-8"))
        case = joint.case_from_source(file.read_bytes().decode("utf-8"), material)
        self.assertEqual(case["source"]["text"], text)
        self.assertEqual(len(case["facts"]), 4)
        for fact in case["facts"]:
            self.assertEqual(text[fact["start"]:fact["end"]], fact["text"])
        self.assertFalse(case["facts"][2]["export_allowed"])
        self.assertTrue(case["facts"][2]["recipient_read"])

    def test_source_rewrite_or_extra_prelude_or_missing_newline_is_rejected(self):
        material = spec(); text = "\n".join(material["facts"]) + "\n"
        for changed in (text.rstrip("\n"), "# host-added heading\n" + text,
                        text.replace("8462", "9999"), text.replace("\n", "\r\n")):
            with self.subTest(changed=changed[:20]):
                with self.assertRaises(ValueError):
                    joint.case_from_source(changed, material)

    def test_ambiguous_native_fact_occurrences_are_rejected(self):
        material = spec(); material["facts"][1] = material["facts"][0]
        with self.assertRaisesRegex(ValueError, "ambiguous_fact"):
            joint.case_from_source("\n".join(material["facts"]) + "\n", material)

    def test_external_export_acl_blocks_f3_even_when_receiver_can_read(self):
        material = spec(); text = "\n".join(material["facts"]) + "\n"
        case = joint.case_from_source(text, material)
        host = JointHost(case, self.base / "host")
        private = host.rows["source-f3"]
        self.assertEqual(host.execute(request(case, private, "read"))["decision"], "allow")
        self.assertEqual(host.execute(request(case, private, "handoff"))["decision"], "deny")
        self.assertEqual(host.execute(request(case, host.rows["source-f1"], "handoff"))["decision"], "allow")

    def test_translation_preserves_token_position_and_plain_controls(self):
        old = "[PVT_" + "A" * 24 + "_EMAIL_1]"
        new = "[PVT_" + "B" * 24 + "_EMAIL_1]"
        self.assertEqual(joint.translate(old, "邮箱" + old, "邮箱" + new), new)
        self.assertEqual(joint.translate("UNKNOWN", "邮箱" + old, "邮箱" + new), "UNKNOWN")
        self.assertIsNone(joint.translate(None, "邮箱" + old, "邮箱" + new))

    def test_unregistered_answer_token_or_inventory_change_cannot_translate(self):
        old = "[PVT_" + "A" * 24 + "_EMAIL_1]"
        new = "[PVT_" + "B" * 24 + "_EMAIL_1]"
        fake = "[PVT_" + "C" * 24 + "_EMAIL_1]"
        with self.assertRaisesRegex(ValueError, "unregistered_shared_response_token"):
            joint.translate(fake, "邮箱" + old, "邮箱" + new)
        with self.assertRaisesRegex(ValueError, "token_inventory_changed"):
            joint.translate(old, "邮箱" + old, "没有任何token")

    def test_target_guard_and_template_hashes_are_checked_before_execution(self):
        root = self.base / "isolated-root"; root.mkdir()
        guard = root / "results/native_agent_probe_20261026/submission_request_guard_7500.mjs"
        guard.parent.mkdir(parents=True); guard.write_text("guard-fixture", encoding="utf-8")
        source = root / "frozen.py"; source.write_text("# frozen synthetic source", encoding="utf-8")
        out = root / "run"; out.mkdir()
        for filename in ("input.json", "evaluation_reference.json", "target_guard.patch.json"):
            write_json(out / filename, {})
        write_json(out / "plan.json", {"implementation_sha256": {"frozen.py": h(source)},
            "input_sha256": h(out / "input.json"), "references_sha256": h(out / "evaluation_reference.json"),
            "guard_sha256": h(guard), "target_template_sha256": h(out / "target_guard.patch.json")})
        with patch.object(joint, "ROOT", root):
            joint.checked_plan(out)
            guard.write_text("changed runtime guard", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "frozen_target_guard_changed"):
                joint.checked_plan(out)
            guard.write_text("guard-fixture", encoding="utf-8")
            write_json(out / "target_guard.patch.json", {"extra": "tool-enabled"})
            with self.assertRaisesRegex(ValueError, "frozen_target_guard_changed"):
                joint.checked_plan(out)

    def test_closed_prediction_or_reference_hash_change_is_rejected(self):
        out, rows = self.closed_run()
        rows[0]["final_answer"] = "changed after closure"
        write_json(out / "predictions.json", rows)
        with self.assertRaisesRegex(ValueError, "scoring_input_changed"):
            joint.score(out)
        self.refreeze_predictions(out, rows)
        write_json(out / "evaluation_reference.json", {"changed": "after closure"})
        with self.assertRaisesRegex(ValueError, "scoring_input_changed"):
            joint.score(out)

    def test_open_or_incomplete_phase_cannot_score(self):
        out, _ = self.closed_run()
        closed = json.loads((out / "prediction_phase_closed.json").read_text(encoding="utf-8"))
        closed["all_slots_closed"] = False
        write_json(out / "prediction_phase_closed.json", closed)
        with self.assertRaisesRegex(ValueError, "prediction_phase_not_closed"):
            joint.score(out)

    def test_failed_legal_task_stays_in_denominator_and_links_are_not_new_calls(self):
        out, rows = self.closed_run()
        failed = next(r for r in rows if r["slot"] == "source-t2-whole_block")
        failed.update(client_status="error", raw_answer=None, final_answer=None, processing_error="timeout")
        self.refreeze_predictions(out, rows)
        result = joint.score(out)
        groups = {g["method"]: g for g in result["groups"]}
        self.assertEqual(groups["whole_block"]["legal_planned"], 2)
        self.assertEqual(groups["whole_block"]["legal_correct"], 1)
        self.assertEqual(groups["whole_block"]["unobserved_rows"], 1)
        for name in ("per_fragment", "existing_selective"):
            self.assertEqual(groups[name]["actual_native_rows"], 0)
            self.assertEqual(groups[name]["linked_rows"], 4)
        self.assertEqual(result["stories"], 1)

    def test_missing_registered_slot_cannot_shrink_scoring_denominator(self):
        out, rows = self.closed_run()
        self.refreeze_predictions(out, rows[:-1])
        with self.assertRaises(ValueError):
            joint.score(out)

    def test_duplicate_slot_cannot_inflate_scoring_success(self):
        out, rows = self.closed_run()
        self.refreeze_predictions(out, rows + [deepcopy(rows[0])])
        with self.assertRaises(ValueError):
            joint.score(out)

    def test_source_generation_failure_is_not_labeled_qualified_or_observed_safety(self):
        out, _ = self.closed_run(failed_source=True)
        result = joint.score(out)
        self.assertIs(result.get("source_generation_qualified"), False)
        for group in result["groups"]:
            self.assertEqual(group["planned"], 4)
            self.assertEqual(group["legal_planned"], 2)
            self.assertEqual(group["legal_correct"], 0)
            self.assertEqual(group["unobserved_rows"], 4)
            self.assertEqual(group.get("raw_disclosure_observed_rows"), 0)

    def test_source_receipt_change_is_rejected_before_scoring(self):
        out, _ = self.closed_run()
        write_json(out / "source_generation.json", {"status": "failed", "tool_result_success": False})
        with self.assertRaisesRegex(ValueError, "source_generation_receipt_changed"):
            joint.score(out)

    def test_closed_summary_is_reproducible_without_rewriting_results(self):
        out, _ = self.closed_run()
        first = joint.score(out)
        summary_before = (out / "summary.json").read_bytes()
        self.assertIs(first["source_generation_qualified"], True)
        self.assertEqual(joint.score(out), first)
        self.assertEqual((out / "summary.json").read_bytes(), summary_before)


if __name__ == "__main__":
    unittest.main()
