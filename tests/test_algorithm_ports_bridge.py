"""Meaningful cross-interface checks; synthetic exact facts, no models."""
from copy import deepcopy
from pathlib import Path
import tempfile
import unittest

from experiments.algorithm_ports_20261029.dual_gate import HandoffSession, RECEIVER
from experiments.algorithm_ports_20261029.make_tasks import generate
from memory_migration_study.current_authority import prepare_current_transfer


class BridgeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.case = generate(97531, count=1)[0][0]
        self.session = HandoffSession(self.case, Path(self.temp.name) / "state")

    def token(self, request):
        text = request["prepared"]["payload"]["memories"][0]["text"]
        return text.split("customer code ")[1].rstrip(".")

    def test_signed_scope_survives_broker_projection_and_restoration(self):
        eligible, excluded = self.session.eligible()
        self.assertEqual((len(eligible), len(excluded)), (2, 2))
        request = self.session.prepare(eligible[:1], "bridge-positive")
        result = self.session.restore(self.token(request), request)
        self.assertEqual(result["status"], "ok", result)
        self.assertEqual(result["answer"], self.session.rows[eligible[0]["source"]["source_id"]]["protected_value"])

    def test_read_does_not_supply_export(self):
        readable_no_export = next(r for r in self.session.records
            if self.session.rows[r["source"]["source_id"]]["recipient_read"]
            and not self.session.rows[r["source"]["source_id"]]["export_allowed"])
        self.assertEqual(self.session.authority.access_decision(readable_no_export,
            actor_id=RECEIVER[0], agent_id=RECEIVER[1], policy_version="ports-v1")["decision"], "allow")
        with self.assertRaises(Exception):
            self.session.prepare([readable_no_export], "bridge-read-not-export")

    def test_missing_transfer_permission_is_not_allow(self):
        case = deepcopy(self.case)
        for row in case["records"]:
            row.pop("export_allowed")
        other = HandoffSession(case, Path(self.temp.name) / "missing")
        self.assertEqual(other.eligible()[0], [])

    def test_changed_signed_content_is_rejected(self):
        record = deepcopy(self.session.eligible()[0][0])
        record["text"] += " changed"
        with self.assertRaises(ValueError):
            self.session.prepare([record], "bridge-content-change")

    def test_cross_principal_restoration_is_blocked(self):
        request = self.session.prepare(self.session.eligible()[0][:1], "bridge-principal")
        result = self.session.restore(self.token(request), request, user="other_user")
        self.assertNotEqual(result["status"], "ok")

    def test_revocation_blocks_old_packet_and_new_selection_keeps_other_record(self):
        eligible = self.session.eligible()[0]
        request = self.session.prepare(eligible, "bridge-before-revoke")
        self.session.revoke(eligible[0]["source"]["source_id"])
        with self.assertRaises(Exception):
            self.session.restore(self.token(request), request)
        remaining = self.session.eligible()[0]
        self.assertEqual(len(remaining), 1)
        fresh = self.session.prepare(remaining, "bridge-after-revoke")
        self.assertEqual(self.session.restore(self.token(fresh), fresh)["status"], "ok")

    def test_unknown_token_and_raw_registered_value_are_rejected(self):
        request = self.session.prepare(self.session.eligible()[0][:1], "bridge-tokens")
        for answer in ["[PVT_" + "F" * 24 + "_CUSTOMER_999]", self.case["records"][0]["protected_value"]]:
            with self.subTest(answer_kind=answer[:4]):
                self.assertNotEqual(self.session.restore(answer, request)["status"], "ok")

    def test_restore_requires_original_request_identity(self):
        request = self.session.prepare(self.session.eligible()[0][:1], "bridge-request")
        bad = dict(request, request_id="different")
        with self.assertRaises(ValueError):
            self.session.restore(self.token(request), bad)

    def test_read_only_preparation_cannot_be_spliced_into_transfer_packet(self):
        allowed = self.session.prepare(self.session.eligible()[0][:1], "bridge-splice")
        read_only = next(r for r in self.session.records
            if self.session.rows[r["source"]["source_id"]]["recipient_read"]
            and not self.session.rows[r["source"]["source_id"]]["export_allowed"])
        prepared = prepare_current_transfer([read_only], self.case["query"], self.session.policy,
            authority=self.session.authority, actor_id=RECEIVER[0], agent_id=RECEIVER[1],
            request_id="bridge-splice", mode="generation",
            agent=lambda **_: {"status": "ok", "findings": [], "local_calls": 0})
        self.assertEqual(prepared["status"], "ok")
        spliced = dict(allowed, records=[read_only], prepared=prepared)
        with self.assertRaises(ValueError):
            self.session.restore(self.token(spliced), spliced)


if __name__ == "__main__":
    unittest.main()
