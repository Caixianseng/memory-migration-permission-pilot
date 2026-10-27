"""Reference-audit checks; values are synthetic and never sent to a model."""
import unittest
from scripts.qualify_pisas_inputs import audit_annotations


class PisasQualificationTests(unittest.TestCase):
    def fixture(self):
        source = {"scenario_id": "case", "cast": [{"name": "A"}, {"name": "B"}], "timeline": [
            {"id": "artifact", "visible_to": ["A", "B"], "attributes": ["x"], "content": "A uses marker-720"}]}
        utility = {"scenario_id": "case", "allowed_answers": ["yes", "no"], "oracle_answer": "yes",
                   "attribute_values": {"x": {"source": "artifact", "value": "marker-720"}}}
        app = {"scenario_id": "case", "attributes": {"x": "inappropriate"}}
        visibility = {"scenario_id": "case", "attributes": {"x": {"holder": "A", "visible_to": ["A"], "hidden_from": ["B"]}}}
        return source, utility, app, visibility

    def test_existing_literal_exposure_is_identified_before_migration(self):
        result = audit_annotations(*self.fixture())
        self.assertEqual(result["reference_problems"], [])
        self.assertEqual(result["declared_initial_visibility_conflict_edges"], 1)
        self.assertEqual(result["literal_initial_visibility_conflict_edges"], 1)

    def test_nonliteral_annotation_is_not_claimed_as_verified_disclosure(self):
        source, utility, app, visibility = self.fixture()
        utility["attribute_values"]["x"]["value"] = "semantic rewrite absent from source"
        result = audit_annotations(source, utility, app, visibility)
        self.assertEqual(result["declared_initial_visibility_conflict_edges"], 1)
        self.assertEqual(result["literal_initial_visibility_conflict_edges"], 0)
        self.assertEqual(result["label_counts"]["nonliteral_reference_values"], 1)

    def test_mismatched_labels_and_unmapped_sources_are_not_silently_filled(self):
        source, utility, app, visibility = self.fixture()
        app["attributes"]["extra"] = "appropriate"
        utility["attribute_values"]["x"]["source"] = "missing"
        result = audit_annotations(source, utility, app, visibility)
        self.assertFalse(result["attribute_ids_agree"])
        self.assertIn("invalid_reference_source:x", result["reference_problems"])
        self.assertEqual(result["literal_assessed_attributes"], 1)
        self.assertEqual(result["literal_initial_visibility_conflict_edges"], 1)

    def test_system_reference_principal_is_unmapped_not_an_invalid_grant(self):
        source, utility, app, visibility = self.fixture()
        rule = visibility["attributes"]["x"]
        rule["holder"] = "task_system"
        rule["visible_to"].append("task_system")
        result = audit_annotations(source, utility, app, visibility)
        self.assertEqual(result["reference_problems"], [])
        self.assertEqual(result["unmapped_reference_principals"], {"x": ["task_system"]})
        self.assertEqual(result["literal_initial_visibility_conflict_edges"], 1)

    def test_missing_carrier_is_unassessed_not_zero_exposure(self):
        source, utility, app, visibility = self.fixture()
        source["timeline"][0]["attributes"] = []
        result = audit_annotations(source, utility, app, visibility)
        self.assertEqual(result["attributes_without_declared_carriers"], ["x"])
        self.assertEqual(result["literal_assessed_attributes"], 0)
        self.assertIsNone(result["literal_initial_visibility_conflict_edges"])
        self.assertIsNone(result["declared_initial_visibility_conflict_edges"])

    def test_zero_conflict_preserves_the_full_attribute_denominator(self):
        source, utility, app, visibility = self.fixture()
        source["timeline"][0]["visible_to"] = ["A"]
        result = audit_annotations(source, utility, app, visibility)
        self.assertEqual(result["literal_initial_visibility_conflict_edges"], 0)
        self.assertEqual(result["attributes"], 1)


if __name__ == "__main__":
    unittest.main()
