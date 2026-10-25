"""Serialization-only fixes still require the full signed A->B restore chain."""
import copy
import unittest

from memory_migration_study.answer_serialization import canonicalize_answer
from memory_migration_study.memory_labels import MemoryLabelAuthority, prepare_labeled_transfer, restore_labeled_answer
from memory_migration_study.privacy import _TOKEN


class NoModelDetector:
    def __call__(self, **_):
        return {"status": "ok", "findings": [], "errors": [], "local_calls": 0, "elapsed_seconds": 0.0}


class AnswerSerializationTests(unittest.TestCase):
    token = "[PVT_0123456789ABCDEF01234567_CUSTOMER_1]"

    def payload(self, token=None):
        return {"query": "Who is the customer?", "memories": [{"source_id": "m", "text": "Customer: " + (token or self.token)}]}

    def setUp(self):
        self.authority = MemoryLabelAuthority(b"serialization-test-host-authority-key-32-bytes")
        self.policy = {"version": "serialization-test-v1", "protected_categories": ["CUSTOMER"]}
        text = "Customer: Cedar Labs"
        self.record = self.make_record(text, [{"start": 10, "end": 20, "category": "CUSTOMER"}])

    def make_record(self, text, findings):
        source = {"source_id": "source-A", "text": text}
        fact = {"text": text, "source_start": 0, "source_end": len(text), "findings": findings}
        return self.authority.build_record(source, fact, self.policy, owner_id="owner", readers=["owner"],
            agent_id="agent-A", allowed_agent_ids=["agent-B"], builder_version="exact-copy-v1")

    def prepare(self, request="request-one", query="", records=None):
        return prepare_labeled_transfer([self.record] if records is None else records, query, self.policy,
            authority=self.authority, actor_id="owner", agent_id="agent-B", request_id=request,
            mode="generation", privacy_pipeline="boundary", agent=NoModelDetector())

    def restore(self, answer, prepared, *, records=None, **changes):
        scope = {"authority": self.authority, "actor_id": "owner", "agent_id": "agent-B", "request_id": "request-one"}
        scope.update(changes)
        return restore_labeled_answer(answer, prepared, [self.record] if records is None else records, self.policy, **scope)

    def test_only_missing_outer_brackets_of_whole_exact_current_token_are_added(self):
        payload = self.payload()
        before = copy.deepcopy(payload)
        result = canonicalize_answer(" \n"+self.token[1:-1]+"\t", payload)
        self.assertEqual(result, {"answer": self.token, "decision": "added_outer_brackets"})
        self.assertEqual(payload, before)

    def test_full_tokens_literals_and_raw_secrets_remain_unchanged(self):
        for answer in (self.token, " \n"+self.token+" ", "UNKNOWN", "Cedar Labs", "ready", ""):
            self.assertEqual(canonicalize_answer(answer, self.payload()), {"answer": answer, "decision": "unchanged"})

    def test_case_nonce_category_and_index_are_never_repaired(self):
        bare = self.token[1:-1]
        variants = (bare.lower(), bare.replace("01234567", "0123456", 1), bare.replace("01234567", "11234567", 1),
                    bare.replace("CUSTOMER", "PERSON"), bare[:-1]+"2", bare[:-1]+"01", bare[:-1]+"0",
                    bare.replace("CUSTOMER", "ADMIN"))
        for answer in variants:
            self.assertEqual(canonicalize_answer(answer, self.payload())["decision"], "unchanged")

    def test_prefix_suffix_quotes_prose_and_multiple_tokens_are_never_extracted(self):
        bare = self.token[1:-1]
        for answer in ("Answer: "+bare, bare+".", '"'+bare+'"', "`"+bare+"`", bare+"\nUNKNOWN",
                       bare+bare, self.token+self.token, "I refuse, but "+bare):
            self.assertEqual(canonicalize_answer(answer, self.payload()), {"answer": answer, "decision": "unchanged"})

    def test_valid_mixed_token_supported_but_malformed_payloads_do_not_repair(self):
        mixed = self.token.replace("CUSTOMER", "MIXED")
        self.assertEqual(canonicalize_answer(mixed[1:-1], self.payload(mixed))["answer"], mixed)
        for payload in (None, {}, {**self.payload(), "gold": "untrusted"},
                        {"query": "x", "memories": [{"source_id": "m", "text": self.token}, {"source_id": "m", "text": self.token}]}):
            self.assertEqual(canonicalize_answer(self.token[1:-1], payload), {"answer": self.token[1:-1], "decision": "invalid_payload"})
        for answer in (None, 1, {"answer": self.token}):
            self.assertEqual(canonicalize_answer(answer, self.payload()), {"answer": None, "decision": "invalid_answer"})

    def test_exactly_repaired_token_still_uses_real_signed_restoration(self):
        prepared = self.prepare()
        self.assertEqual(prepared["status"], "ok")
        token = _TOKEN.search(prepared["payload"]["memories"][0]["text"]).group()
        result = canonicalize_answer(token[1:-1], prepared["payload"])
        self.assertEqual(result["decision"], "added_outer_brackets")
        self.assertEqual(self.restore(result["answer"], prepared)["answer"], "Cedar Labs")

    def test_cross_request_bare_token_is_not_repaired_in_new_payload(self):
        old, new = self.prepare(), self.prepare(request="request-two")
        old_token = _TOKEN.search(old["payload"]["memories"][0]["text"]).group()
        self.assertNotIn(old_token, str(new["payload"]))
        result = canonicalize_answer(old_token[1:-1], new["payload"])
        self.assertEqual(result["decision"], "unchanged")
        self.assertEqual(self.restore(result["answer"], new, request_id="request-two")["status"], "blocked")

    def test_query_only_token_does_not_gain_memory_evidence(self):
        record = self.make_record("Status: ready", [])
        prepared = self.prepare(query="Customer: Question Only Ltd", records=[record])
        self.assertEqual(prepared["status"], "ok")
        token = _TOKEN.search(prepared["payload"]["query"]).group()
        result = canonicalize_answer(token[1:-1], prepared["payload"])
        self.assertEqual(result["decision"], "added_outer_brackets")
        self.assertEqual(self.restore(result["answer"], prepared, records=[record])["error"], "query_only_value_has_no_evidence")

    def test_current_actor_agent_request_policy_and_revocation_still_control_restore(self):
        prepared = self.prepare()
        token = _TOKEN.search(prepared["payload"]["memories"][0]["text"]).group()
        fixed = canonicalize_answer(token[1:-1], prepared["payload"])["answer"]
        for changes in ({"actor_id": "outsider"}, {"agent_id": "agent-C"}, {"request_id": "another-request"},
                        {"authorizer": lambda *_: False}):
            self.assertEqual(self.restore(fixed, prepared, **changes)["status"], "blocked")
        changed_policy = copy.deepcopy(self.policy)
        self.policy["instructions"] = "changed under same version"
        self.assertEqual(self.restore(fixed, prepared)["status"], "blocked")
        self.policy = changed_policy
        self.authority.revoke(self.record["record_id"])
        self.assertEqual(self.restore(fixed, prepared)["error"], "grant_revoked")

    def test_raw_secret_is_not_repaired_or_authorized(self):
        prepared = self.prepare()
        result = canonicalize_answer("Cedar Labs", prepared["payload"])
        self.assertEqual(result["decision"], "unchanged")
        self.assertEqual(self.restore(result["answer"], prepared)["status"], "blocked")


if __name__ == "__main__":
    unittest.main()
