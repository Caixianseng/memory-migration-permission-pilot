"""Handwritten contract examples; expectations are not produced by a host."""
from copy import deepcopy
from pathlib import Path
import ast
import unittest

from experiments.submission_acceptance_20261030 import reference


def fixture():
    text = "合成材料：验收区为甲区。"
    fact_text = "验收区为甲区。"
    start = text.index(fact_text)
    case = {"case_id": "gold-contract", "source": {"source_id": "source-gold", "text": text}}
    fact = {"fact_id": "gold-1", "text": fact_text, "start": start, "end": start + len(fact_text),
            "allowed_principals": [{"user_id": "alice", "agent_id": "qoder"},
                                   {"user_id": "alice", "agent_id": "harness"}],
            "export_allowed": True, "copy_allowed": True, "restore_allowed": True}
    request = {"user_id": "alice", "agent_id": "harness", "operation": "handoff",
               "resource_id": "gold-1", "source_id": "source-gold", "audience": "harness",
               "model_recipient": "harness-model-provider", "policy_version": "journal-v1", "now": 100}
    return case, fact, request


class SubmissionReferenceTests(unittest.TestCase):
    def setUp(self):
        self.case, self.fact, self.request = fixture()

    def assertDecision(self, expected, *, case=None, fact=None, request=None, state=None):
        actual = reference.judge(self.case if case is None else case,
                                 self.fact if fact is None else fact,
                                 self.request if request is None else request, state)
        self.assertEqual(actual["decision"], expected, actual)
        self.assertIs(actual["deliver"], expected == "Permit")
        return actual

    def test_normal_handoff(self):
        self.assertDecision("Permit")

    def test_read_does_not_imply_handoff_or_restore(self):
        fact = {**self.fact, "export_allowed": False, "restore_allowed": False}
        self.assertDecision("Permit", fact=fact, request={**self.request, "operation": "read"})
        self.assertDecision("Deny", fact=fact)
        self.assertDecision("Deny", fact=fact, request={**self.request, "operation": "restore"})

    def test_copy_and_sender_grants_are_independent_requirements(self):
        self.assertDecision("Deny", fact={**self.fact, "copy_allowed": False})
        self.assertDecision("Deny", fact={**self.fact, "allowed_principals": [self.fact["allowed_principals"][1]]})

    def test_cross_pairs_cannot_be_invented_from_two_valid_pairs(self):
        fact = {**self.fact, "allowed_principals": [{"user_id": "alice", "agent_id": "qoder"},
                                                   {"user_id": "bob", "agent_id": "harness"}]}
        for user, agent, expected in (("alice", "qoder", "Permit"), ("bob", "harness", "Permit"),
                                      ("alice", "harness", "Deny"), ("bob", "qoder", "Deny")):
            self.assertDecision(expected, fact=fact, request={**self.request, "user_id": user,
                                                             "agent_id": agent, "operation": "read"})

    def test_restore_only_targets_receiver_even_if_sender_can_read(self):
        self.assertDecision("Deny", request={**self.request, "agent_id": "qoder", "operation": "restore"})

    def test_every_bound_recipient_object_and_policy_field_is_enforced(self):
        for field in ("resource_id", "source_id", "audience", "model_recipient", "policy_version"):
            with self.subTest(field=field):
                self.assertDecision("Deny", request={**self.request, field: "another-valid-identifier"})

    def test_source_text_or_span_cannot_be_substituted(self):
        self.assertDecision("Deny", fact={**self.fact, "text": "验收区为乙区。"})
        self.assertDecision("Deny", fact={**self.fact, "start": self.fact["start"] + 1})
        self.assertDecision("Deny", fact={**self.fact, "declared_origin_source_id": "another-source"})

    def test_half_open_integer_time_window(self):
        for now, expected in ((-1, "Deny"), (0, "Permit"), (199, "Permit"), (200, "Deny")):
            with self.subTest(now=now):
                self.assertDecision(expected, request={**self.request, "now": now})
        for now in (True, 100.0, "100", None):
            self.assertDecision("Indeterminate", request={**self.request, "now": now})

    def test_revocation_changes_reference_not_only_actual_execution(self):
        self.assertDecision("Permit", state={"revoked": False, "authority_unknown": False})
        self.assertDecision("Deny", state={"revoked": True, "authority_unknown": False})

    def test_authority_unknown_is_not_a_business_denial(self):
        self.assertDecision("Indeterminate", state={"revoked": False, "authority_unknown": True})

    def test_known_denial_dominates_an_unknown_authority_or_missing_attribute(self):
        self.assertDecision("Deny", fact={**self.fact, "export_allowed": False},
                            state={"revoked": False, "authority_unknown": True})
        request = dict(self.request)
        request.pop("user_id")
        self.assertDecision("Deny", request=request, fact={**self.fact, "copy_allowed": False})

    def test_missing_or_string_boolean_grant_never_permits(self):
        for field in ("export_allowed", "copy_allowed", "restore_allowed"):
            for value in (None, "false", "true", 0, 1):
                request = {**self.request, "operation": "restore" if field == "restore_allowed" else "handoff"}
                self.assertDecision("Indeterminate", fact={**self.fact, field: value}, request=request)

    def test_missing_request_fields_never_permit(self):
        for field in self.request:
            request = dict(self.request)
            request.pop(field)
            self.assertDecision("Indeterminate", request=request)

    def test_explicit_state_requires_two_strict_boolean_flags(self):
        for state in ({}, {"revoked": False}, {"revoked": "false", "authority_unknown": False},
                      {"revoked": False, "authority_unknown": 0}, [], True):
            self.assertDecision("Indeterminate", state=state)

    def test_out_of_contract_operation_is_not_applicable(self):
        self.assertDecision("NotApplicable", request={**self.request, "operation": "delete"})

    def test_malformed_declarations_do_not_crash_or_deliver(self):
        for fact in ({}, {**self.fact, "start": True}, {**self.fact, "allowed_principals": None},
                     {**self.fact, "allowed_principals": [{"user_id": "alice"}]}):
            self.assertDecision("Indeterminate", fact=fact)
        for container in (None, [], "text"):
            self.assertEqual(reference.judge(container, self.fact, self.request)["decision"], "Indeterminate")

    def test_inputs_are_unchanged(self):
        before = deepcopy((self.case, self.fact, self.request))
        self.assertDecision("Permit")
        self.assertEqual(before, (self.case, self.fact, self.request))

    def test_reference_has_no_imports_or_file_access(self):
        source = Path(reference.__file__).read_text(encoding="utf-8")
        nodes = list(ast.walk(ast.parse(source)))
        self.assertFalse(any(isinstance(node, (ast.Import, ast.ImportFrom)) for node in nodes))
        self.assertFalse(any(isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                             and node.func.id in {"open", "exec", "eval", "__import__"} for node in nodes))


if __name__ == "__main__":
    unittest.main()
