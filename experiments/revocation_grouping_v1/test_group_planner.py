"""Meaningful offline grouping/cache boundary tests; no model/network calls."""
import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

try:
    from .group_planner import plan
    from .rebuild_cache import RebuildCache, CacheIntegrityError, CacheConflictError
except ImportError:
    from group_planner import plan
    from rebuild_cache import RebuildCache, CacheIntegrityError, CacheConflictError


def sources():
    return [{"source_id": "S01", "version": 1, "text": "meeting deadline room budget project", "acl_group": "A"},
            {"source_id": "S02", "version": 1, "text": "meeting deadline room attendees project", "acl_group": "A"},
            {"source_id": "S03", "version": 1, "text": "battery inspection calibration sensor", "acl_group": "B"},
            {"source_id": "S04", "version": 1, "text": "battery inspection safety sensor", "acl_group": "B"}]


class PlannerTests(unittest.TestCase):
    @staticmethod
    def measured():
        return {"input_overhead_tokens": 426.16096736780514, "input_tokens_per_utf8_byte": .2359994657654585,
                "output_overhead_tokens": 86.80174402594253, "output_tokens_per_utf8_byte": .025216921505268802,
                "output_similarity_tokens_per_utf8_byte": .42893987948646883}

    def test_default_without_measured_model_exactly_matches_executed_v1(self):
        file = Path(__file__).with_name("snapshots") / "planner_v1.py"
        spec = importlib.util.spec_from_file_location("frozen_planner_v1", file)
        old = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(old)
        history = {"masks": [["S01", "S03"], ["S02"]], "expected_changes": 4}
        for method in ("single", "whole", "fixed", "acl", "risk", "semantic", "joint"):
            config = {"method": method, "max_group_sources": 2}
            before, after = old.plan(sources(), history, config), plan(sources(), history, config)
            before.pop("planning_ms")
            after.pop("planning_ms")
            self.assertEqual(before, after)

    def test_measured_model_shared_by_plain_grouping_baselines(self):
        model = self.measured()
        records = sources()
        nbytes = sum(len(s["text"].encode("utf-8")) for s in records)
        outputs = model["output_overhead_tokens"] + model["output_tokens_per_utf8_byte"] * nbytes
        inputs = model["input_overhead_tokens"] + model["input_tokens_per_utf8_byte"] * nbytes
        expected = (inputs * 2 + outputs * 8 + 3 * outputs * 2) / 1e6
        whole = plan(records, {}, {"method": "whole", "measured_token_model": model})
        self.assertAlmostEqual(whole["estimated_cost"], expected)
        for method in ("single", "fixed", "acl", "risk", "semantic", "joint"):
            result = plan(records, {}, {"method": method, "measured_token_model": model})
            self.assertEqual(result["details"]["measured_token_model"], model)

    def test_measured_risk_ignores_similarity_and_semantic_ignores_risk(self):
        records, changed = sources(), copy.deepcopy(sources())
        for source in changed:
            source["text"] = "x" * len(source["text"].encode("utf-8"))
        cfg = {"method": "risk", "measured_token_model": self.measured()}
        history = {"masks": [["S01", "S03"]], "expected_changes": 5}
        a, b = plan(records, history, cfg), plan(changed, history, cfg)
        self.assertEqual(a["groups"], b["groups"])
        self.assertEqual(a["estimated_cost"], b["estimated_cost"])
        cfg["method"] = "semantic"
        a = plan(records, {"masks": [["S01"]], "expected_changes": 1}, cfg)
        b = plan(records, {"masks": [["S02", "S03"]], "expected_changes": 100}, cfg)
        self.assertEqual(a["groups"], b["groups"])
        self.assertEqual(a["estimated_cost"], b["estimated_cost"])

    def test_measured_similarity_keeps_signed_direction_and_output_floor(self):
        records = sources()[:2]
        model = self.measured()
        shared = {"max_group_sources": 1, "measured_token_model": model}
        # Force a fixed common partition by using whole vs semantic with two
        # identical sources; signed coefficient must change cost in its own direction.
        records[1]["text"] = records[0]["text"]
        base = plan(records, {}, {"method": "semantic", "max_group_sources": 2, "measured_token_model": {**model, "output_similarity_tokens_per_utf8_byte": 0}})
        negative = plan(records, {}, {"method": "semantic", "max_group_sources": 2, "measured_token_model": {**model, "output_similarity_tokens_per_utf8_byte": -100}})
        self.assertLess(negative["estimated_cost"], base["estimated_cost"])
        self.assertEqual(negative["details"]["measured_token_model"]["output_similarity_tokens_per_utf8_byte"], -100)
        self.assertGreater(negative["estimated_cost"], 0)

    def test_invalid_measured_model_fails_closed(self):
        for bad in (None, {}, {**self.measured(), "unknown": 1},
                    {**self.measured(), "input_overhead_tokens": -1},
                    {**self.measured(), "input_tokens_per_utf8_byte": True},
                    {**self.measured(), "output_similarity_tokens_per_utf8_byte": float("nan")},
                    {**self.measured(), "output_tokens_per_utf8_byte": float("inf")}):
            with self.subTest(value=bad), self.assertRaises(ValueError):
                plan(sources(), {}, {"measured_token_model": bad})

    def test_every_method_returns_exact_order_invariant_partition(self):
        for method in ("single", "whole", "fixed", "acl", "risk", "semantic", "joint"):
            with self.subTest(method=method):
                config = {"method": method, "max_group_sources": 2}
                history = {"masks": [["S01", "S02"], ["S03"], []], "expected_changes": 5}
                a, b = plan(sources(), history, config), plan(list(reversed(sources())), history, config)
                self.assertEqual(a["groups"], b["groups"])
                self.assertEqual(a["estimated_cost"], b["estimated_cost"])
                self.assertEqual(sorted(sid for group in a["groups"] for sid in group), ["S01", "S02", "S03", "S04"])
                if method != "whole":
                    self.assertLessEqual(max(map(len, a["groups"])), 2)

    def test_whole_not_artificially_limited(self):
        self.assertEqual(plan(sources(), {}, {"method": "whole", "max_group_sources": 1})["groups"], [["S01", "S02", "S03", "S04"]])

    def test_explicit_future_or_evaluation_input_is_rejected(self):
        for name in ("future_events", "events", "answers", "questions", "evaluation"):
            with self.assertRaisesRegex(ValueError, "future_events"):
                plan(sources(), {name: []}, {"method": "joint"})

    def test_forbidden_source_duplicate_and_bad_history_rejected(self):
        bad = sources()
        bad[0]["allowed"] = False
        with self.assertRaisesRegex(ValueError, "forbidden_source"):
            plan(bad)
        with self.assertRaisesRegex(ValueError, "duplicate_source_id"):
            plan(sources() + [sources()[0]])
        with self.assertRaisesRegex(ValueError, "historical_masks_invalid"):
            plan(sources(), {"masks": [[12]]})

    def test_semantic_ablation_does_not_depend_on_risk(self):
        a = plan(sources(), {"masks": [["S01"]], "expected_changes": 1}, {"method": "semantic"})
        b = plan(sources(), {"masks": [["S03", "S04"]], "expected_changes": 100}, {"method": "semantic"})
        self.assertEqual(a["groups"], b["groups"])
        self.assertEqual(a["estimated_cost"], b["estimated_cost"])
        self.assertFalse(a["details"]["risk_enabled"])

    def test_risk_ablation_ignores_words_when_lengths_unchanged(self):
        a = sources()
        b = copy.deepcopy(a)
        for source in b:
            source["text"] = "x" * len(source["text"].encode("utf-8"))
        history = {"masks": [["S01", "S02"], ["S03"], ["S04"]], "expected_changes": 6}
        left, right = plan(a, history, {"method": "risk"}), plan(b, history, {"method": "risk"})
        self.assertEqual(left["groups"], right["groups"])
        self.assertEqual(left["estimated_cost"], right["estimated_cost"])
        self.assertIsNone(left["details"]["semantic_features"])

    def test_joint_uses_history_and_preserves_input(self):
        records = sources()
        history = {"masks": [["S01", "S02"], ["S03", "S04"]], "expected_changes": 20}
        before = copy.deepcopy((records, history))
        result = plan(records, history, {"method": "joint"})
        self.assertEqual((records, history), before)
        self.assertTrue(result["details"]["risk_enabled"])
        self.assertIsNotNone(result["details"]["semantic_features"])
        self.assertTrue(result["details"]["cost_is_planning_proxy_not_measured_effect"])

    def test_joint_decision_trades_lexical_similarity_against_change_frequency(self):
        # A mechanical fixture, NOT evidence of lower cost/quality on real tasks:
        # semantic neighbours and historically co-revoked neighbours disagree.
        words = ["meeting room deadline project ", "meeting room deadline attendee ",
                 "battery inspection sensor project ", "battery inspection sensor calibration "]
        records = [{"source_id": f"S{i + 1:02}", "text": text * 30, "version": 1}
                   for i, text in enumerate(words)]
        history = {"masks": [["S01", "S03"], ["S02", "S04"]], "expected_deliveries": 30}
        low = plan(records, {**history, "expected_changes": 1}, {"method": "joint", "max_group_sources": 2})
        high = plan(records, {**history, "expected_changes": 3}, {"method": "joint", "max_group_sources": 2})
        self.assertEqual(low["groups"], [["S01", "S02"], ["S03", "S04"]])
        self.assertEqual(high["groups"], [["S01", "S03"], ["S02", "S04"]])


class CacheTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="d1-cache-")
        self.addCleanup(self.temp.cleanup)
        self.cache = RebuildCache(self.temp.name)
        self.inputs = sources()[:2]
        self.config = {"model": "test-only", "prompt_version": "frozen-v1"}
        self.receipt = {"status": "ok", "usage": {"input_tokens": 11, "output_tokens": 4}}

    def test_exact_binding_reuses_across_input_order(self):
        artifact = self.cache.store(self.inputs, self.config, "meeting summary", self.receipt)
        self.assertEqual(artifact, self.cache.lookup(list(reversed(self.inputs)), dict(reversed(list(self.config.items())))))
        self.assertEqual(artifact["source_ids"], ["S01", "S02"])
        self.assertEqual(len(artifact["dependencies"]), 2)

    def test_revoked_subset_content_version_grant_or_config_does_not_reuse(self):
        self.cache.store(self.inputs, self.config, "meeting summary", self.receipt)
        self.assertIsNone(self.cache.lookup(self.inputs[:1], self.config))
        for field, value in (("text", "changed input"), ("version", 2), ("permission_version", 2)):
            changed = copy.deepcopy(self.inputs)
            changed[0][field] = value
            self.assertIsNone(self.cache.lookup(changed, self.config))
        self.assertIsNone(self.cache.lookup(self.inputs, {**self.config, "prompt_version": "v2"}))

    def test_forbidden_inputs_and_empty_dependencies_rejected(self):
        forbidden = copy.deepcopy(self.inputs)
        forbidden[0]["allow"] = False
        for records in ([], forbidden):
            with self.assertRaises(ValueError):
                self.cache.lookup(records, self.config)

    def test_explicit_recheck_mode_reuses_after_reauthorization_and_keeps_true_provenance(self):
        config = {**self.config, "permission_reuse": "recheck_current_dependencies"}
        original = copy.deepcopy(self.inputs)
        original[0]["permission_version"] = 5
        original[1]["permission_version"] = 7
        artifact = self.cache.store(original, config, "meeting summary", self.receipt)
        reauthorized = copy.deepcopy(original)
        reauthorized[0]["permission_version"] = 9
        reauthorized[1]["permission_version"] = 11
        reused = self.cache.lookup(reauthorized, config)
        self.assertEqual(reused, artifact)
        self.assertEqual(reused["generated_at_permission_versions"], {"S01": 5, "S02": 7})
        self.assertEqual({item["permission_version"] for item in reused["dependencies"]}, {"revalidate-at-use"})
        self.assertNotEqual(self.cache.key(original, config), self.cache.key(original, self.config))
        self.assertEqual(self.cache.key(original, config), self.cache.key(reauthorized, config))

    def test_recheck_mode_still_separates_source_content_version_and_allowed_subsets(self):
        config = {**self.config, "permission_reuse": "recheck_current_dependencies"}
        self.cache.store(self.inputs, config, "meeting summary", self.receipt)
        self.assertIsNone(self.cache.lookup(self.inputs[:1], config))
        for field, value in (("text", "new content"), ("version", 2)):
            altered = copy.deepcopy(self.inputs)
            altered[0][field] = value
            self.assertIsNone(self.cache.lookup(altered, config))
        forbidden = copy.deepcopy(self.inputs)
        forbidden[0]["allow"] = False
        with self.assertRaisesRegex(ValueError, "forbidden_source"):
            self.cache.lookup(forbidden, config)

    def test_generation_permission_provenance_is_checksum_protected(self):
        config = {**self.config, "permission_reuse": "recheck_current_dependencies"}
        artifact = self.cache.store(self.inputs, config, "meeting summary", self.receipt)
        path = Path(self.temp.name) / (artifact["cache_key"] + ".json")
        body = json.loads(path.read_bytes())
        body["generated_at_permission_versions"]["S01"] = 100
        path.write_text(json.dumps(body), encoding="utf-8")
        with self.assertRaises(CacheIntegrityError):
            self.cache.lookup(self.inputs, config)

    def test_unknown_permission_reuse_mode_rejected(self):
        with self.assertRaisesRegex(ValueError, "unknown_permission_reuse_mode"):
            self.cache.lookup(self.inputs, {**self.config, "permission_reuse": "typo"})

    def test_tampering_fails_closed_instead_of_becoming_cache_miss(self):
        artifact = self.cache.store(self.inputs, self.config, "meeting summary", self.receipt)
        path = Path(self.temp.name) / (artifact["cache_key"] + ".json")
        body = json.loads(path.read_bytes())
        body["text"] = "tampered summary"
        path.write_text(json.dumps(body), encoding="utf-8")
        with self.assertRaises(CacheIntegrityError):
            self.cache.lookup(self.inputs, self.config)

    def test_existing_artifacts_are_immutable_and_caller_mutation_not_retained(self):
        stored = self.cache.store(self.inputs, self.config, "meeting summary", self.receipt)
        same = self.cache.store(self.inputs, self.config, "meeting summary", self.receipt)
        self.assertEqual(stored, same)
        with self.assertRaises(CacheConflictError):
            self.cache.store(self.inputs, self.config, "different output", self.receipt)
        self.receipt["usage"]["input_tokens"] = 900
        same["text"] = "caller mutation"
        self.assertEqual(self.cache.lookup(self.inputs, self.config)["text"], "meeting summary")
        self.assertEqual(self.cache.lookup(self.inputs, self.config)["receipt"]["usage"]["input_tokens"], 11)


if __name__ == "__main__":
    unittest.main()
