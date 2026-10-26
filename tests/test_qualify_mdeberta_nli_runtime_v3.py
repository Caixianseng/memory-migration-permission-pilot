"""Container compatibility must not hide missing or mismatched weights."""
import importlib.util
from pathlib import Path
import types
import unittest

PATH = Path(__file__).resolve().parents[1] / "scripts/qualify_mdeberta_nli_runtime_v3.py"
SPEC = importlib.util.spec_from_file_location("nli_v3_test", PATH)
v = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(v)


class V3Tests(unittest.TestCase):
    def test_pinned_v5_sets_are_canonicalized_without_dropping_keys(self):
        raw = {"missing_keys": set(), "unexpected_keys": {"deberta.embeddings.position_ids"},
               "mismatched_keys": set(), "error_msgs": []}
        result, containers = v.normalize_loading_info(raw)
        self.assertEqual(result["unexpected_keys"], ["deberta.embeddings.position_ids"])
        self.assertEqual(containers["unexpected_keys"], "set")
        self.assertIsInstance(raw["unexpected_keys"], set)

    def test_none_string_generator_and_duplicate_keys_are_rejected(self):
        base = {"missing_keys": [], "unexpected_keys": [], "mismatched_keys": [], "error_msgs": []}
        for value in (None, "key", iter(["key"]), ["same", "same"], [3]):
            with self.subTest(value=type(value).__name__), self.assertRaises(ValueError):
                v.normalize_loading_info({**base, "unexpected_keys": value})

    def test_nonempty_missing_mismatch_and_errors_survive_to_unchanged_validator(self):
        q = v.load_qualifier()
        # Obtain the load-validation closure through the real wrapper budget;
        # fake factory/model only, never import Transformers or Torch.
        class Classifier:
            def forward(self):
                raise AssertionError("no forward allowed")
        for name, value in (("missing_keys", {"classifier.weight"}),
                            ("mismatched_keys", {("classifier.weight", (1,), (2,))}),
                            ("error_msgs", ["loading failed"]),
                            ("unexpected_keys", {"unknown.weight"})):
            info = {"missing_keys": set(), "unexpected_keys": set(), "mismatched_keys": set(), "error_msgs": []}
            info[name] = value
            normalized, _ = v.normalize_loading_info(info)
            self.assertTrue(normalized[name])
            # Rejects before model fields can be consulted.
            spec = importlib.util.spec_from_file_location("nli_v2_validation_test", PATH.with_name("qualify_mdeberta_nli_runtime_v2.py"))
            old = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(old)
            with self.subTest(name=name), self.assertRaises(ValueError):
                old.validate_loading(types.SimpleNamespace(), normalized)
        self.assertEqual(q.RUNTIME["max_top_classifier_forwards"], 3)
        self.assertEqual(len(q.PAIRS), 3)


if __name__ == "__main__":
    unittest.main()
