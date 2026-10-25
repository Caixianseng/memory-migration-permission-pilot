"""Authored mutation checks for independent role-query evidence checks."""
from copy import deepcopy
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from scripts import verify_role_query_transfer as audit
from tests import test_role_query_transfer as authored

TOKEN = "[PVT_" + "A"*24 + "_CUSTOMER_1]"
OTHER = "[PVT_" + "A"*24 + "_CUSTOMER_2]"
ALIASES = {"customer": ("customer", "客户"), "buyer": ("buyer", "买方"),
    "consignee": ("consignee", "收货方"), "account_holder": ("account holder", "账户持有人"),
    "audit_observer": ("audit observer", "审计观察机构"), "carrier": ("carrier", "承运商"),
    "status": ("status", "验收结论")}


class RoleQueryVerifierUnitTests(unittest.TestCase):
    def payload(self):
        return {"query": "For "+OTHER+", which buyer?", "memories": [{"source_id": "s1",
            "text": "Buyer: "+TOKEN+". Status: approved."}]}

    def test_closed_role_output_rejects_extras_duplicates_and_unregistered_roles(self):
        self.assertEqual(audit.strict_role('{"role":"buyer"}'), "buyer")
        for raw in ('{"role":"buyer","quote":"SECRET"}', '{"role":"buyer","role":"status"}',
                    '{"role":"administrator"}', '{"role":null}', 'UNKNOWN'):
            with self.assertRaises(ValueError):
                audit.strict_role(raw)

    def test_cards_are_source_anchored_not_query_values(self):
        payload = self.payload()
        cards = audit.derive_cards(payload, ALIASES)
        self.assertEqual([(c["role"], c["value"]) for c in cards], [("buyer", TOKEN), ("status", "approved")])
        self.assertNotIn(OTHER, {c["value"] for c in cards})
        self.assertEqual(audit.check_cards(cards, payload, ALIASES), cards)
        for field, value in (("source_id", "other-source"), ("value", OTHER), ("anchor_start", 1), ("support_end", 1)):
            mutated = deepcopy(cards)
            mutated[0][field] = value
            with self.assertRaisesRegex(ValueError, "role_cards_not_source_grammar"):
                audit.check_cards(mutated, payload, ALIASES)

    def test_duplicate_sources_and_cross_fact_support_are_not_invented(self):
        payload = {"query": "buyer?", "memories": [{"source_id": "first", "text": "Buyer:"},
            {"source_id": "second", "text": TOKEN}]}
        self.assertEqual(audit.derive_cards(payload, ALIASES), [])
        payload["memories"][1]["source_id"] = "first"
        with self.assertRaisesRegex(ValueError, "role_source_identity"):
            audit.derive_cards(payload, ALIASES)

    def test_dictionary_and_unique_join_do_not_promote_query_fact(self):
        payload = self.payload()
        cards = audit.derive_cards(payload, ALIASES)
        self.assertEqual(audit.dictionary_role(payload["query"], ALIASES), "buyer")
        self.assertEqual(audit.dictionary_role("Which buyer and carrier?", ALIASES), "UNKNOWN")
        self.assertEqual(audit.resolve_unique("buyer", cards), TOKEN)
        self.assertEqual(audit.resolve_unique("email", cards), "UNKNOWN")
        self.assertEqual(audit.resolve_unique("UNKNOWN", cards), "UNKNOWN")
        self.assertEqual(audit.resolve_unique("buyer", cards+[dict(cards[0], value=OTHER)]), "UNKNOWN")

    def test_canonical_corrects_only_current_complete_marker(self):
        payload = self.payload()
        self.assertEqual(audit.canonical(TOKEN[1:-1], payload), (TOKEN, "added_outer_brackets"))
        self.assertEqual(audit.canonical(TOKEN[1:-1]+"suffix", payload)[1], "unchanged")
        unknown = "PVT_"+"B"*24+"_CUSTOMER_1"
        self.assertEqual(audit.canonical(unknown, payload), (unknown, "unchanged"))

    def test_q1_actual_input_must_contain_query_only(self):
        prompt, schema = "Fixed role classifier", {"type": "object"}
        query = "Which buyer?"
        request = {"messages": [{"role": "system", "content": prompt},
            {"role": "user", "content": json.dumps({"query": query}, separators=(",", ":"))}], "format": schema}
        audit.query_only_request(request, query, prompt=prompt, schema=schema)
        for extra in ("memories", "answers", "reference", "score"):
            mutated = deepcopy(request)
            mutated["messages"][1]["content"] = json.dumps({"query": query, extra: "CANARY_NOT_A_QUERY"})
            with self.assertRaisesRegex(ValueError, "q1_not_query_only"):
                audit.query_only_request(mutated, query, prompt=prompt, schema=schema)

    def test_processing_failure_is_not_a_model_unknown_decision(self):
        task = {"actor_id": "owner", "task_class": "legal", "task_id": "private"}
        gold = {"answers": {"private": "Cedar Foundry"}}
        row = {"arm": "Q1", "answer_status": "needs_review", "classification": {"status": "needs_review", "role": "UNKNOWN"},
            "raw_model_answer": '{"role":"UNKNOWN"}', "final_answer": None, "resolved_answer": None,
            "strict_final_answer": None, "required_fact_retained": True, "answer_calls": 1,
            "masking": {"ready": True, "partial": 0, "unmasked": 0}, "restoration_status": None}
        result = audit.independent_score(row, task, gold)
        self.assertFalse(result["model_chose_unknown"])
        self.assertFalse(result["correct"])
        row.update(arm="F", raw_model_answer="UNKNOWN")
        self.assertFalse(audit.independent_score(row, task, gold)["model_chose_unknown"])


class RoleQueryArtifactVerifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temporary.name)
        cls.actual_run, cls.actual_protocol = authored.harness.run, authored.harness.protocol
        cls.make(cls.root/"complete")
        cls.source, cls.corpus = cls.root/"complete/output", cls.root/"complete/corpus"

    @classmethod
    def make(cls, root, **kwargs):
        config = {"endpoint": "http://127.0.0.1:11435", "model": audit.base.MODEL,
                  "expected_version": "0.40.8", "expected_digest": audit.base.MODEL_DIGEST, "timeout_seconds": 120}
        def protocol(corpus, _config):
            return cls.actual_protocol(corpus, config)
        def run(corpus, output, model_root, _config, observer, approved, **kw):
            return cls.actual_run(corpus, output, model_root, config, observer, approved, **kw)
        with patch.object(authored.harness, "protocol", side_effect=protocol), patch.object(authored.harness, "run", side_effect=run):
            authored.run_fixture(root, **kwargs)
        network = {"external_attempts_blocked": 0, "loopback_connections": 0}
        (root/"output/network_audit.json").write_text(json.dumps(network), encoding="utf-8")
        p = root/"output/transport_audit.json"
        value = json.loads(p.read_bytes())
        value["network"] = network
        p.write_text(json.dumps(value), encoding="utf-8")

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def copy(self):
        temp = tempfile.TemporaryDirectory(dir=self.root)
        self.addCleanup(temp.cleanup)
        output = Path(temp.name)/"output"
        shutil.copytree(self.source, output)
        return output

    def read(self, run, name):
        return json.loads((run/(name+".json")).read_bytes())

    def write(self, run, name, value):
        (run/(name+".json")).write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")

    def verify(self, run):
        return audit.verify(run, corpus=self.corpus)

    def test_complete_144_row_protocol_and_query_only_model_requests(self):
        result = self.verify(self.source)
        self.assertEqual((result["status"], result["registered_rows"], result["shared_contexts"], result["verification_model_calls"]), ("passed", 144, 48, 0))
        for arm in audit.ARMS:
            self.assertEqual(result["arms"][arm]["outsider"]["outsider_blocked"], 8)
        self.assertEqual(result["arms"]["Q1"]["legal"]["correct"], 32)

    def test_missing_rows_or_fabricated_calls_do_not_improve_denominator(self):
        for kind in ("missing", "outsider"):
            output = self.copy()
            rows = self.read(output, "rows")
            rows.remove(next(r for r in rows if r["task_class"] == kind))
            self.write(output, "rows", rows)
            with self.assertRaisesRegex(ValueError, "answer_matrix"):
                self.verify(output)
        output = self.copy()
        rows = self.read(output, "rows")
        next(r for r in rows if r["arm"] == "Q0")["answer_calls"] = 1
        self.write(output, "rows", rows)
        with self.assertRaisesRegex(ValueError, "answer_count_allocation"):
            self.verify(output)

    def test_cards_cannot_take_query_values_or_foreign_source_support(self):
        output = self.copy()
        contexts = self.read(output, "shared_contexts")
        context = next(c for c in contexts if c["role_cards"])
        context["role_cards"][0]["value"] = "SCORING_ONLY_FORGED_VALUE"
        context["role_cards_sha256"] = audit.digest(context["role_cards"])
        self.write(output, "shared_contexts", contexts)
        with self.assertRaisesRegex(ValueError, "role_cards_not_source_grammar"):
            self.verify(output)

    def test_actual_q1_request_cannot_receive_memories_even_with_coordinated_hashes(self):
        output = self.copy()
        events = [json.loads(line) for line in (output/"request_transport.jsonl").read_text(encoding="utf-8").splitlines()]
        request = next(e for e in events if e["phase"] == "request" and e["stage"] == "answer" and e["arm"] == "Q1")
        user = json.loads(request["request"]["messages"][1]["content"])
        user["memories"] = [{"text": "REFERENCE_ONLY_CANARY"}]
        request["request"]["messages"][1]["content"] = json.dumps(user, ensure_ascii=False, separators=(",", ":"))
        body = request["request"]
        wire = json.dumps(body, ensure_ascii=False).encode()
        request.update(wire_json_utf8_bytes=len(wire), wire_json_utf8_sha256=audit.sha(wire))
        for event in events:
            if event["index"] == request["index"]:
                event["request_sha256"] = audit.digest(body)
        (output/"request_transport.jsonl").write_text("".join(json.dumps(e, ensure_ascii=False)+"\n" for e in events), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "q1_not_query_only"):
            self.verify(output)

    def test_raw_response_and_host_join_or_aggregate_cannot_be_replaced(self):
        for field, value, error in (("raw_model_answer", '{"role":"carrier"}', "full_raw_model_answer"),
                                    ("resolved_answer", "FORGED_HOST_VALUE", "resolved_answer_not_role_join")):
            output = self.copy()
            rows = self.read(output, "rows")
            next(r for r in rows if r["arm"] == "Q1" and r["answer_calls"])[field] = value
            self.write(output, "rows", rows)
            with self.assertRaisesRegex(ValueError, error):
                self.verify(output)
        output = self.copy()
        report = self.read(output, "report")
        report["arms"]["Q1"]["legal"]["correct"] -= 1
        self.write(output, "report", report)
        with self.assertRaisesRegex(ValueError, "independent_aggregate"):
            self.verify(output)

    def test_closure_and_shared_authorization_cannot_be_skipped(self):
        output = self.copy()
        journal = self.read(output, "auth_events")
        journal[-2], journal[-1] = journal[-1], journal[-2]
        for i, item in enumerate(journal, 1):
            item["sequence"] = i
        self.write(output, "auth_events", journal)
        with self.assertRaisesRegex(ValueError, "evaluation_before_model_closure"):
            self.verify(output)

    def test_failed_annotations_keep_144_rows_and_no_fabricated_task_calls(self):
        root = self.root/"failed_annotations"
        self.make(root, annotation_failure=True)
        result = audit.verify(root/"output", corpus=root/"corpus")
        self.assertEqual(result["registered_rows"], 144)
        for arm in audit.ARMS:
            self.assertEqual(result["arms"][arm]["legal"]["registered_tasks"], 32)
            self.assertEqual(result["arms"][arm]["legal"]["correct"], 0)
            self.assertEqual(result["arms"][arm]["legal"]["answer_calls"], 0)


if __name__ == "__main__":
    unittest.main()
