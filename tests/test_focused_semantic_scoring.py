"""New development material and a scorer independent of model/native IO."""
from copy import deepcopy
import hashlib
import inspect
import json
from pathlib import Path
import unittest

from memory_migration_study.focused_semantic_scoring import CONDITIONS, score

ROOT = Path(__file__).resolve().parents[1]
MATERIAL = ROOT / "examples/focused_semantic_20261027/development.json"
REFERENCE = ROOT / "examples/focused_semantic_20261027/scoring_reference.json"


class FocusedSemanticScoringTests(unittest.TestCase):
    def setUp(self):
        self.material = json.loads(MATERIAL.read_text(encoding="utf-8"))
        self.reference = json.loads(REFERENCE.read_text(encoding="utf-8"))

    def predictions(self):
        return [dict(story_id=r["story_id"], question_id=r["question_id"],
                     condition=c, answer_id=r["expected_id"], status="ok",
                     request_sha256=hashlib.sha256(f"{r['story_id']}:{r['question_id']}:{c[-1]}".encode()).hexdigest())
                for r in self.reference["rows"] for c in CONDITIONS]

    def test_material_is_four_new_self_contained_development_stories(self):
        stories = self.material["stories"]
        self.assertEqual(len(stories), 4)
        self.assertEqual(sorted(s["language"] for s in stories), ["en", "en", "zh", "zh"])
        self.assertEqual(sum(s["source_backend"] == "webui" and s["target_backend"] == "cognee" for s in stories), 2)
        self.assertEqual(sum(s["source_backend"] == "cognee" and s["target_backend"] == "webui" for s in stories), 2)
        for story in stories:
            objects = {o["key"]: o["text"] for o in story["objects"]}
            self.assertEqual(set(objects), {"readonly", "managed"})
            self.assertTrue(all(len(text.splitlines()) == 2 for text in objects.values()))
            self.assertEqual({f["id"] for f in story["facts"]}, {"F1", "F2", "F3", "F4"})
            self.assertEqual({(f["object_key"], f["line_index"]) for f in story["facts"]},
                             {("readonly", 0), ("readonly", 1), ("managed", 0), ("managed", 1)})
            for fact in story["facts"]:
                self.assertIn(fact["value"], objects[fact["object_key"]].splitlines()[fact["line_index"]])
                self.assertIn(fact["value"], story["sensitive_values"])
            self.assertEqual({q["id"] for q in story["questions"]}, {"Q1", "Q2", "Q3"})

    def test_runtime_material_contains_no_scoring_fields_or_question_family(self):
        def walk(value):
            if isinstance(value, dict):
                for key, child in value.items():
                    self.assertNotIn(key, {"expected_id", "answer_id", "expected_answer", "kind", "family", "question_family"})
                    walk(child)
            elif isinstance(value, list):
                for child in value:
                    walk(child)
        walk(self.material)
        source = inspect.getsource(score)
        self.assertNotIn("read_text", source)
        self.assertNotIn("open(", source)
        self.assertEqual(set(inspect.signature(score).parameters), {"predictions", "reference"})

    def test_perfect_development_predictions_have_fixed_four_cell_denominators(self):
        result = score(self.predictions(), self.reference)
        self.assertEqual((result["planned_predictions"], result["observed_predictions"]), (48, 48))
        for cell in result["conditions"].values():
            self.assertEqual((cell["legal"], cell["legal_correct"], cell["missing"], cell["missing_correct"]), (8, 8, 4, 4))
        self.assertEqual(set(result["effects"].values()), {0.0})
        self.assertEqual({r["expected_id"] for r in self.reference["rows"] if r["kind"] == "legal"}, {"F1", "F2", "F3", "F4"})

    def test_missing_predictions_remain_in_all_denominators(self):
        result = score([], self.reference)
        self.assertEqual(result["missing_predictions"], 48)
        self.assertEqual(result["failure_classes"], {"missing_prediction": 48})
        for cell in result["conditions"].values():
            self.assertEqual((cell["legal"], cell["legal_correct"], cell["missing"], cell["missing_correct"], cell["failed_or_blocked"]), (8, 0, 4, 0, 12))

    def test_semantic_outcomes_are_visible_separately_from_execution_failures(self):
        rows = self.predictions()
        # Q1: one valid abstention and one wrong fact; Q3: one hallucination.
        rows[0]["answer_id"] = "UNKNOWN"
        rows[1]["answer_id"] = "F1"
        rows[8]["answer_id"] = "F2"
        rows[3].update(status="blocked", failure_class="authorization_deny", answer_id=None)
        result = score(rows, self.reference)
        self.assertEqual(result["semantic_outcomes"], {
            "correct": 44, "legal_unknown": 1, "wrong_fact": 1,
            "missing_hallucination": 1, "execution_failure": 1})
        self.assertEqual(result["failure_classes"], {"authorization_deny": 1})
        for condition, cell in result["conditions"].items():
            self.assertEqual(sum(cell["semantic_outcomes"].values()), 12)
        self.assertEqual(result["conditions"]["S0"]["semantic_outcomes"]["legal_unknown"], 1)
        self.assertEqual(result["conditions"]["S0"]["semantic_outcomes"]["missing_hallucination"], 1)

    def test_policy_denial_and_authority_unknown_are_not_model_unknown(self):
        predictions = self.predictions()
        for row in predictions:
            if row["question_id"] == "Q3":
                row.update(answer_id="UNKNOWN", status="policy_denied", failure_class="policy_denied")
            elif row["condition"] == "S0":
                row.update(answer_id="UNKNOWN", status="authorization_unknown", failure_class="authorization_unknown")
        result = score(predictions, self.reference)
        self.assertEqual(result["failure_classes"], {"authorization_unknown": 8, "policy_denied": 16})
        self.assertTrue(all(cell["missing_correct"] == 0 for cell in result["conditions"].values()))

    def test_legacy_conditions_unknown_questions_duplicates_and_bad_reference_rejected(self):
        for change, message in [({"condition": "N"}, "condition_invalid"),
                                ({"question_id": "hidden"}, "question_not_registered")]:
            rows = self.predictions()
            rows[0].update(change)
            with self.assertRaisesRegex(ValueError, message):
                score(rows, self.reference)
        rows = self.predictions()
        with self.assertRaisesRegex(ValueError, "duplicate_prediction"):
            score(rows + [rows[0]], self.reference)
        ref = deepcopy(self.reference)
        ref["rows"][0]["kind"] = "missing"
        with self.assertRaisesRegex(ValueError, "answer_kind_mismatch"):
            score([], ref)

    def test_forged_or_malformed_answer_ids_preserve_failure_rows(self):
        rows = self.predictions()
        rows[0]["answer_id"] = "F999"
        rows[1]["answer_id"] = '{"answer_id":"F2"}'
        rows[2].update(answer_id="F2", status="model_format_error")
        result = score(rows, self.reference)
        self.assertEqual(result["failure_classes"], {"invalid_answer_id": 2, "model_format_error": 1})
        self.assertEqual(result["conditions"]["S0"]["legal_correct"], 7)

    def test_equal_actual_requests_with_different_answers_are_runtime_variation(self):
        rows = self.predictions()
        target = next(r for r in rows if r["story_id"] == "dev_zh_roles" and r["question_id"] == "Q1" and r["condition"] == "T0")
        target["answer_id"] = "F1"
        result = score(rows, self.reference)
        pair = result["paired_comparisons"]["S0:T0"]
        self.assertEqual((pair["planned_legal_pairs"], pair["complete_pairs"], pair["answer_disagreements"], pair["runtime_variations"]), (8, 8, 1, 1))
        self.assertEqual(result["effects"]["migration_raw"], -1 / 8)
        self.assertEqual(next(r for r in pair["rows"] if r["answer_disagreement"])["attribution"], "runtime_variation")

    def test_wire_difference_or_missing_hash_cannot_claim_runtime_variation(self):
        for wire_hash in [None, "invalid", "f" * 64]:
            rows = self.predictions()
            rows[2].update(answer_id="F1", request_sha256=wire_hash)
            result = score(rows, self.reference)
            pair = result["paired_comparisons"]["S0:T0"]
            self.assertEqual((pair["answer_disagreements"], pair["runtime_variations"]), (1, 0))

    def test_bijective_entity_rename_preserves_expected_ids_and_value_binding(self):
        stories = deepcopy(self.material["stories"])
        predictions = self.predictions()
        baseline = score(predictions, self.reference)
        for story in stories:
            renames = {name: f"ENTITY_{i:02d}" for i, name in enumerate(story["sensitive_values"])}
            def rename(text):
                for original in sorted(renames, key=len, reverse=True):
                    text = text.replace(original, renames[original])
                return text
            story["objects"] = [dict(o, text=rename(o["text"])) for o in story["objects"]]
            story["questions"] = [dict(q, text=rename(q["text"])) for q in story["questions"]]
            story["facts"] = [dict(f, value=renames[f["value"]]) for f in story["facts"]]
            objects = {o["key"]: o["text"].splitlines() for o in story["objects"]}
            for fact in story["facts"]:
                self.assertIn(fact["value"], objects[fact["object_key"]][fact["line_index"]])
        self.assertEqual(score(predictions, self.reference), baseline)

    def test_candidate_order_changes_do_not_reassign_logical_ids(self):
        original = self.material["stories"][0]
        permuted = deepcopy(original)
        permuted["facts"] = list(reversed(permuted["facts"]))
        def source_map(story):
            objects = {o["key"]: o["text"].splitlines() for o in story["objects"]}
            return {f["id"]: objects[f["object_key"]][f["line_index"]] for f in story["facts"]}
        self.assertEqual(source_map(original), source_map(permuted))
        self.assertEqual(score(list(reversed(self.predictions())), self.reference), score(self.predictions(), self.reference))

    def test_relation_cross_swap_changes_reference_and_old_predictions_fail(self):
        original = self.material["stories"][0]
        changed = deepcopy(original)
        for obj in changed["objects"]:
            obj["text"] = obj["text"].replace("客户", "SWAP_TOKEN").replace("承运方", "客户").replace("SWAP_TOKEN", "承运方")
        objects = {o["key"]: o["text"].splitlines() for o in changed["objects"]}
        # The counterexample oracle uses exact explicitly altered relation text;
        # it is not an evaluated model or a new semantic extraction algorithm.
        q1 = [f["id"] for f in changed["facts"] if "雾岚计划的承运方" in objects[f["object_key"]][f["line_index"]]]
        q2 = [f["id"] for f in changed["facts"] if "溪桥计划的客户" in objects[f["object_key"]][f["line_index"]]]
        self.assertEqual((q1, q2), (["F1"], ["F4"]))
        changed_ref = deepcopy(self.reference)
        for row in changed_ref["rows"]:
            if row["story_id"] == original["id"] and row["question_id"] in {"Q1", "Q2"}:
                row["expected_id"] = q1[0] if row["question_id"] == "Q1" else q2[0]
        result = score(self.predictions(), changed_ref)
        self.assertTrue(all(cell["legal_correct"] == 6 for cell in result["conditions"].values()))


if __name__ == "__main__":
    unittest.main()
