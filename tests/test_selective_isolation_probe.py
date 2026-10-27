"""Test diagnostic denominators and actual restoration, with all network denied."""
import unittest
from unittest.mock import patch
from memory_migration_study import privacy
from scripts import run_selective_isolation_probe as probe


class SelectiveIsolationProbeTests(unittest.TestCase):
    def setUp(self):
        for target in ("socket.socket", "socket.create_connection", "urllib.request.urlopen"):
            guard = patch(target, side_effect=AssertionError("network_forbidden"))
            guard.start()
            self.addCleanup(guard.stop)
        self.policy = {"version": "fixture-v1", "protected_categories": ["CUSTOMER"]}

    def make_trace(self, texts, keep, spans):
        cell = {"bundle": "pair", "text_indices": list(range(len(texts))), "profile": probe.original.PROFILES[1], "strategy": "record"}
        trace = {"cell": cell, "ready": bool(keep), "kept_source_ids": [f"source_{i:02d}" for i in keep],
                 "mask_footprint": {f"source_{i:02d}": bounds for i, bounds in spans.items()}, "request_id": "diagnostic"}
        trace["trace_sha256"] = probe.original._hash(trace)
        return trace

    def refs(self, texts, gold, facts):
        refs = {}
        for i, text in enumerate(texts):
            findings = [{"start": a, "end": b, "category": "CUSTOMER", "text": text[a:b]} for a, b in gold.get(i, [])]
            fact = facts[i]
            start = text.index(fact)
            refs[i] = {"expected": {probe.original.PROFILES[1]: {"decision": "sensitive" if findings else "not_sensitive",
                       "spans": findings, "must_mask_values": [f["text"] for f in findings]}},
                       "allowed_fact": {"text": fact, "start": start, "end": start+len(fact)}}
        return refs

    def test_grid_keeps_only_twelve_unique_texts_and_fixed_pairs(self):
        grid = probe.grid()
        self.assertEqual(len(grid), 144)
        self.assertEqual(sum(c["bundle"] == "single" for c in grid), 96)
        pairs = {tuple(c["text_indices"]) for c in grid if c["bundle"] == "pair"}
        self.assertEqual(pairs, {(i, i+1) for i in range(0, 12, 2)})

    def test_quarantine_is_not_counted_as_masked_or_fact_restorable(self):
        texts = ["甲是青河联盟；状态 amber", "状态 violet"]
        source = {"query": "", "memories": [{"source_id": "source_01", "text": texts[1]}]}
        detection = privacy.detect_sensitive(source, self.policy, mode="rules")
        prepared = privacy.prepare_private_payload(source, detection, actor_id=probe.ACTOR, request_id="diagnostic",
            policy_version=self.policy["version"], sensitivity_policy=self.policy, authorizer=probe.authorize({"source_01"}, self.policy))
        self.assertEqual(prepared["status"], "ok")
        trace = self.make_trace(texts, [1], {1: []})
        refs = self.refs(texts, {0: [(2, 6)]}, ["amber", "violet"])
        scored = probe.score(trace, prepared["mapping"], refs, texts, self.policy)
        self.assertEqual(scored["spans"][0]["state"], "record_quarantined")
        self.assertFalse(scored["facts"][0]["oracle_fact_restorable"])
        self.assertTrue(scored["facts"][1]["original_fact_retained_and_restorable"])
        group = next(iter(probe.summarize([scored]).values()))
        self.assertEqual((group["original_facts"], group["original_facts_retained_and_restorable"]), (2, 1))
        self.assertEqual((group["fully_masked_spans"], group["quarantined_spans_in_ready_requests"]), (0, 1))
        self.assertFalse(scored["model_generated_answer"])

    def test_partial_boundaries_remain_partial_and_not_safe(self):
        texts = ["客户为青河联盟；状态 amber"]
        trace = self.make_trace(texts, [0], {0: [[5, 7]]})
        source = {"query": "", "memories": [{"source_id": "source_00", "text": texts[0]}]}
        detected = privacy.detect_sensitive(source, self.policy, mode="rules")
        prepared = privacy.prepare_private_payload(source, detected, actor_id=probe.ACTOR, request_id="diagnostic",
            policy_version=self.policy["version"], sensitivity_policy=self.policy, authorizer=probe.authorize({"source_00"}, self.policy))
        scored = probe.score(trace, prepared["mapping"], self.refs(texts, {0: [(3, 7)]}, ["amber"]), texts, self.policy)
        self.assertEqual(scored["spans"][0]["state"], "partially_masked")
        self.assertFalse(scored["ready_with_complete_known_masking"])

    def test_blocked_request_has_no_false_full_mask_success(self):
        texts = ["客户青河联盟；状态 amber"]
        trace = self.make_trace(texts, [], {})
        scored = probe.score(trace, None, self.refs(texts, {0: [(2, 6)]}, ["amber"]), texts, self.policy)
        self.assertEqual(scored["spans"][0]["state"], "request_not_ready")
        self.assertEqual(scored["facts"][0]["restore_status"], "not_ready")
        self.assertFalse(scored["ready_with_complete_known_masking"])
        group = next(iter(probe.summarize([scored]).values()))
        self.assertIsNone(group["masked_unprotected_characters"])
        self.assertEqual(group["overmask_evaluable_sources"], 0)

    def test_original_source_text_and_opaque_order_cannot_be_relabelled(self):
        for mutation in ("source_text", "opaque_id"):
            with self.subTest(mutation=mutation):
                memories = [{"source_id": "source_00", "text": "状态 amber"}]
                source = {"query": "", "memories": memories}
                detection = privacy.detect_sensitive(source, self.policy, mode="rules")
                prepared = privacy.prepare_private_payload(source, detection, actor_id=probe.ACTOR, request_id="diagnostic",
                    policy_version=self.policy["version"], sensitivity_policy=self.policy, authorizer=probe.authorize({"source_00"}, self.policy))
                self.assertEqual(probe.retained_footprint(memories, prepared), (["source_00"], {"source_00": []}))
                if mutation == "source_text":
                    prepared["mapping"]._memories["source_00"] = "状态 violet"
                    prepared["payload"]["memories"][0]["text"] = "状态 violet"
                else:
                    prepared["payload"]["memories"][0]["source_id"] = "m_forged_1"
                with self.assertRaisesRegex(ValueError, "isolation_source_alignment_mismatch"):
                    probe.retained_footprint(memories, prepared)


if __name__ == "__main__":
    unittest.main()
