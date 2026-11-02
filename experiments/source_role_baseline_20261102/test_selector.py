"""Meaningful input-integrity and whole-message selection checks, no models."""

from dataclasses import replace
import unittest

from experiments.source_role_baseline_20261102.selector import (
    AuthorizedScope, LengthMetric, MessageEvidence, SourceBlob, render_payload,
    select, sha256,
)


def fixture():
    texts = ("User request: keep BOTH constraints.\n",
             "Assistant suggestion: use plan A.\n", "Assistant suggestion: use plan B.\n")
    source_text = "".join(texts)
    src = SourceBlob("S02", source_text, sha256(source_text))
    msgs, offset = [], 0
    for i, text in enumerate(texts):
        msgs.append(MessageEvidence("S02", f"m{i}", "user" if i == 0 else "assistant",
                                    offset, offset + len(text)))
        offset += len(text)
    scope = AuthorizedScope("owner", "harness", "v1", frozenset({"S02"}))
    def verify(s, m):
        return s == src and m in msgs
    return src, msgs, scope, verify


class SelectionTests(unittest.TestCase):
    def run_case(self, **kw):
        src, msgs, scope, verify = fixture()
        args = dict(sources=[src], messages=msgs, scope=scope, budget=5000,
                    strategy="source_role_round_robin", boundary_verifier=verify)
        args.update(kw)
        return select(**args)

    def test_exact_source_offsets_speaker_and_payload_bytes(self):
        src, _, _, _ = fixture()
        result = self.run_case()
        self.assertEqual(result["status"], "ok")
        for row in result["selected"]:
            self.assertEqual(row["text"], src.text[row["start"]:row["end"]])
            self.assertEqual(row["quote_sha256"], sha256(row["text"]))
        self.assertEqual(result["measured_payload_length"], len(result["payload"].encode("utf-8")))
        self.assertFalse(result["token_budget_qualified"])

    def test_unauthorized_input_rejected_before_boundary_callback(self):
        called = []
        scope = AuthorizedScope("owner", "harness", "v2", frozenset())
        with self.assertRaisesRegex(ValueError, "not_pre_authorized"):
            self.run_case(scope=scope, boundary_verifier=lambda *a: called.append(a))
        self.assertEqual(called, [])

    def test_flat_source_without_verified_role_boundaries_needs_review(self):
        result = self.run_case(boundary_verifier=None)
        self.assertEqual(result["status"], "needs_review")
        self.assertIsNone(result["payload"])
        missing = self.run_case(messages=[])
        self.assertEqual(missing["status"], "needs_review")
        self.assertIsNone(missing["payload"])

    def test_changed_source_hash_and_forged_role_do_not_pass(self):
        src, msgs, _, _ = fixture()
        with self.assertRaisesRegex(ValueError, "source_hash_mismatch"):
            self.run_case(sources=[replace(src, text=src.text + "secret")])
        changed = [replace(msgs[0], speaker="admin"), *msgs[1:]]
        self.assertEqual(self.run_case(messages=changed)["status"], "needs_review")

    def test_overlap_rejected_even_with_affirming_callback(self):
        _, msgs, _, _ = fixture()
        changed = [msgs[0], replace(msgs[1], start=1)]
        with self.assertRaisesRegex(ValueError, "overlapping"):
            self.run_case(messages=changed, boundary_verifier=lambda *a: True)

    def test_tight_budget_omits_whole_units_and_reports_overflow(self):
        result = self.run_case(budget=80)
        self.assertEqual(result["status"], "overflow")
        self.assertEqual(result["selected"], [])
        self.assertEqual(len(result["omitted"]), 3)
        self.assertEqual({x["reason"] for x in result["omitted"]}, {"unit_exceeds_budget"})
        self.assertLessEqual(result["measured_payload_length"], 80)

    def test_strategies_share_pool_and_do_not_rewrite_identity(self):
        # Change message ordering to make role balancing observably different.
        src, msgs, scope, _ = fixture()
        msgs = [replace(msgs[0], speaker="assistant"), replace(msgs[1], speaker="assistant"),
                replace(msgs[2], speaker="user")]
        a = self.run_case(messages=msgs, boundary_verifier=lambda s, m: s == src and m in msgs,
                          strategy="source_first")
        b = self.run_case(messages=msgs, boundary_verifier=lambda s, m: s == src and m in msgs)
        self.assertEqual(a["candidate_pool_sha256"], b["candidate_pool_sha256"])
        self.assertEqual([x["message_id"] for x in a["selected"]], ["m0", "m1", "m2"])
        self.assertEqual([x["message_id"] for x in b["selected"]], ["m0", "m2", "m1"])
        self.assertEqual({x["quote_sha256"] for x in a["selected"]},
                         {x["quote_sha256"] for x in b["selected"]})

    def test_foreign_source_and_scoring_arguments_rejected(self):
        _, msgs, _, _ = fixture()
        with self.assertRaisesRegex(ValueError, "message_source_not_in"):
            self.run_case(messages=[replace(msgs[0], source_id="S01")])
        with self.assertRaises(TypeError):
            self.run_case(gold_answer="do not read me")

    def test_byte_counter_cannot_be_claimed_as_model_token_counter(self):
        with self.assertRaisesRegex(ValueError, "only_exact_utf8"):
            self.run_case(metric=LengthMetric(metric_id="model-tokens", unit="tokens"))
        self.assertEqual(self.run_case(budget=0)["status"], "overflow")


if __name__ == "__main__":
    unittest.main()
