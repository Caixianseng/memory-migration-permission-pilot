"""Offline hostile-input checks of real joint preparation and restoration.

All materials below are newly handwritten development controls, not retained
evaluation cases or score references. Networking is forbidden in each test.
"""
from copy import deepcopy
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch

from experiments.submission_acceptance_20261030.pipeline import (
    JointHost, JointTransaction, METHODS, RulesDetector, request, normalized_view,
)
from memory_migration_study import privacy


def development_case():
    texts = ["通知邮箱为audit-primary@example.invalid。", "备用邮箱为audit-secondary@example.invalid。"]
    source = "【合成离线审计材料】\n" + "\n".join(texts)
    facts = []
    for index, text in enumerate(texts, 1):
        start = source.index(text)
        facts.append({"fact_id": "audit-f" + str(index), "text": text,
                      "start": start, "end": start + len(text),
                      "allowed_principals": [{"user_id": "alice", "agent_id": "qoder"},
                                             {"user_id": "alice", "agent_id": "harness"}],
                      "export_allowed": True, "copy_allowed": True, "restore_allowed": True,
                      # A poison annotation: generation must replace, never replay, it.
                      "privacy_spans": [{"start": 0, "end": len(text), "category": "GOLD_MUST_NOT_BE_READ"}],
                      "detection_status": "not_a_detector_result"})
    return {"case_id": "audit-development-only", "split": "dev",
            "source": {"source_id": "audit-source", "text": source},
            "facts": facts, "trusted_independent_facts": True}


def task(question="通知邮箱是什么？"):
    return {"task_id": "audit-t1", "question": question,
            "field_label": "通知邮箱为", "kind": "legal", "fact_id": "audit-f1"}


class JointPipelineSecurityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="submission-redteam-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.serial = 0
        for name in ("socket.socket", "socket.create_connection"):
            guard = patch(name, side_effect=AssertionError("cloud_and_network_forbidden"))
            guard.start()
            self.addCleanup(guard.stop)

    def host(self, case=None):
        self.serial += 1
        return JointHost(development_case() if case is None else case, self.root / str(self.serial))

    def transaction(self, host=None, *, question=None, method="whole_block"):
        return JointTransaction(self.host() if host is None else host,
                                task() if question is None else task(question), method)

    def token(self, transaction, index=0):
        text = transaction.safe["memories"][index]["text"]
        result = privacy._TOKEN.search(text)
        self.assertIsNotNone(result, text)
        return result.group()

    def assertRejected(self, transaction, answer, *, errors):
        try:
            result = transaction.restore(answer)
        except ValueError as exc:
            self.assertIn(str(exc), errors)
            return
        self.assertEqual(result["status"], "blocked", result)
        self.assertIsNone(result.get("answer"))
        self.assertIn(result.get("error"), errors)

    def test_real_detection_ignores_input_annotations_and_does_not_mutate_input(self):
        original = development_case()
        before = deepcopy(original)
        real_detect = privacy.detect_sensitive
        with patch.object(privacy, "detect_sensitive", wraps=real_detect) as spy:
            host = self.host(original)
        self.assertEqual(spy.call_count, len(original["facts"]))
        self.assertTrue(all(call.kwargs["mode"] == "rules" for call in spy.call_args_list))
        self.assertTrue(host.generation_findings)
        self.assertEqual({f["category"] for f in host.generation_findings}, {"EMAIL"})
        self.assertEqual(original, before)
        detector = RulesDetector()
        result = detector(text=original["facts"][0]["text"], source_id="s1",
                          policy=host.policy, rule_findings=[])
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["findings"][0]["category"], "EMAIL")

    def test_each_baseline_uses_actual_protection_and_exact_value_restore(self):
        for method in METHODS:
            with self.subTest(method=method):
                transaction = self.transaction(method=method)
                view = transaction.target_text()
                self.assertNotIn("audit-primary@example.invalid", view)
                self.assertNotIn("audit-secondary@example.invalid", view)
                self.assertTrue(transaction.packet_validated)
                result = transaction.restore(self.token(transaction))
                self.assertEqual(result["status"], "ok", result)
                self.assertEqual(result["answer"], "audit-primary@example.invalid")

    def test_rules_detector_handles_reserved_query_source_without_duplicate_identity(self):
        detector = RulesDetector()
        result = detector(text="audit-query@example.invalid", source_id=privacy.QUERY_SOURCE,
                          policy={"version": "journal-v1", "protected_categories": ["EMAIL", "PERSON"]},
                          rule_findings=[])
        self.assertEqual(result["status"], "ok", result)
        self.assertEqual({f["category"] for f in result["findings"]}, {"EMAIL"})

    def test_equivalence_ignores_only_request_random_identifiers_not_information(self):
        first = {"query": "查邮件", "memories": [{"source_id": "m_AAAA_1", "text": "邮箱[PVT_AAAA_EMAIL_1]"}]}
        second = {"query": "查邮件", "memories": [{"source_id": "m_BBBB_1", "text": "邮箱[PVT_BBBB_EMAIL_1]"}]}
        # Use valid token syntax rather than relying on the test's short placeholders.
        first["memories"][0]["text"] = "邮箱[PVT_" + "A" * 24 + "_EMAIL_1]"
        second["memories"][0]["text"] = "邮箱[PVT_" + "B" * 24 + "_EMAIL_1]"
        self.assertEqual(normalized_view(first), normalized_view(second))
        changed = deepcopy(second)
        changed["query"] = "查另一对象的邮件"
        self.assertNotEqual(normalized_view(first), normalized_view(changed))
        changed = deepcopy(second)
        changed["memories"][0]["text"] += "额外原文事实"
        self.assertNotEqual(normalized_view(first), normalized_view(changed))

    def test_exact_source_id_mutation_never_exports(self):
        case = development_case()
        case["facts"][0]["declared_origin_source_id"] = "pretend-external-source"
        host = self.host(case)
        result = host.execute(request(host.case, host.rows["audit-f1"]))
        self.assertEqual(result["decision"], "deny")
        self.assertEqual(result["code"], "exact_origin_binding_failed")
        transaction = self.transaction(host)
        self.assertNotIn("audit-f1", transaction.selected)

    def test_wrong_source_span_is_rejected_before_a_memory_can_be_used(self):
        case = development_case()
        case["facts"][0]["start"] += 1
        try:
            host = self.host(case)
        except ValueError:
            return  # Exact-source issuance itself may reject malformed trusted input.
        result = host.execute(request(host.case, host.rows["audit-f1"]))
        self.assertNotEqual(result["decision"], "allow")

    def test_cross_user_and_unregistered_agent_cannot_read_or_handoff(self):
        host = self.host()
        base = request(host.case, host.rows["audit-f1"])
        for op in ("read", "handoff", "restore"):
            for change in ({"user_id": "bob"}, {"agent_id": "rogue"}):
                with self.subTest(op=op, change=change):
                    result = host.execute({**base, **change, "operation": op})
                    self.assertNotEqual(result["decision"], "allow")

    def test_forged_and_other_transaction_tokens_do_not_restore(self):
        host = self.host()
        first = self.transaction(host)
        second = self.transaction(host)
        self.assertRejected(first, self.token(second), errors={"unknown_or_embedded_token"})
        third = self.transaction(host)
        self.assertRejected(third, "[PVT_000000000000000000000000_EMAIL_1]",
                            errors={"unknown_or_embedded_token"})

    def test_question_only_value_cannot_become_memory_supported_answer(self):
        transaction = self.transaction(question="audit-query-only@example.invalid 的通知邮箱是什么？")
        query_token = privacy._TOKEN.search(transaction.safe["query"])
        self.assertIsNotNone(query_token)
        self.assertRejected(transaction, query_token.group(), errors={"query_only_value_has_no_evidence"})

    def test_unknown_answer_still_rechecks_unrelated_retained_record_revocation(self):
        host = self.host()
        transaction = self.transaction(host)
        host.revoke("audit-f2")
        self.assertRejected(transaction, "UNKNOWN", errors={"record_revoked", "grant_revoked",
                            "current_handoff_no_longer_allowed", "current_read_not_allowed"})

    def test_answer_for_one_record_still_rechecks_all_retained_records(self):
        host = self.host()
        transaction = self.transaction(host)
        first_token = self.token(transaction)
        host.revoke("audit-f2")
        self.assertRejected(transaction, first_token, errors={"record_revoked", "grant_revoked",
                            "current_handoff_no_longer_allowed", "current_read_not_allowed"})

    def test_unknown_current_authority_cannot_restore_even_unknown_answer(self):
        host = self.host()
        transaction = self.transaction(host)
        host.unknown = True
        self.assertRejected(transaction, "UNKNOWN", errors={"current_handoff_no_longer_allowed",
                            "current_read_not_allowed", "current_authorization_unknown"})

    def test_restore_permission_is_rechecked_for_all_records(self):
        host = self.host()
        transaction = self.transaction(host)
        host.rows["audit-f2"]["restore_allowed"] = False
        self.assertRejected(transaction, "UNKNOWN", errors={"explicit_operation_denied",
                            "explicit_restore_not_allowed"})

    def test_duplicate_restore_is_not_a_new_authorization(self):
        transaction = self.transaction()
        result = transaction.restore(self.token(transaction))
        self.assertEqual(result["status"], "ok")
        self.assertRejected(transaction, "UNKNOWN", errors={"transaction_already_consumed"})

    def test_modified_safe_payload_or_packet_cannot_be_restored(self):
        transaction = self.transaction()
        transaction.safe["query"] = "a substituted question"
        self.assertRejected(transaction, "UNKNOWN", errors={"transaction_binding_changed"})
        transaction = self.transaction()
        transaction.packet["items"][0]["text"] = "a substituted fact"
        self.assertRejected(transaction, "UNKNOWN", errors={"transaction_binding_changed",
                            "packet_integrity_invalid"})

    def test_mutated_task_or_retained_set_cannot_relax_the_restore_checks(self):
        transaction = self.transaction()
        transaction.retained.pop()
        self.assertRejected(transaction, "UNKNOWN", errors={"transaction_binding_changed"})
        transaction = self.transaction()
        transaction.task["question"] = "another subject"
        self.assertRejected(transaction, "UNKNOWN", errors={"transaction_binding_changed"})

    def test_query_and_memory_share_only_this_request_pseudonym(self):
        host = self.host()
        first = self.transaction(host, question="audit-primary@example.invalid 是哪个邮箱？")
        self.assertIn(self.token(first), first.safe["query"])
        second = self.transaction(host, question="audit-primary@example.invalid 是哪个邮箱？")
        self.assertNotEqual(self.token(first), self.token(second))

    def test_refusal_that_contains_a_raw_secret_is_blocked(self):
        transaction = self.transaction()
        self.assertRejected(transaction, "不能提供audit-primary@example.invalid",
                            errors={"raw_protected_value_in_answer"})


if __name__ == "__main__":
    unittest.main()
