"""Independent 96-cell checks over authored zero-network producer artifacts."""
from copy import deepcopy
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from memory_migration_study.local_detector import DIGEST, MODEL, VERSION
from scripts import verify_query_schema_transfer as verifier
from tests import test_query_schema_transfer as authored


class QuerySchemaVerifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temporary.name)
        cls.actual_run = authored.harness.run
        cls.make(cls.root/"authored", generic_query=True)
        cls.source, cls.corpus = cls.root/"authored/output", cls.root/"authored/corpus"

    @classmethod
    def make(cls, root, **kwargs):
        def configured(corpus, output, model_root, config, observer, **kw):
            pinned = {"endpoint": "http://127.0.0.1:11435", "model": MODEL, "expected_version": VERSION,
                      "expected_digest": DIGEST, "timeout_seconds": 120}
            return cls.actual_run(corpus, output, model_root, pinned, observer, **kw)
        with patch.object(authored.harness, "run", side_effect=configured):
            authored.QuerySchemaTransferTests().run_authored(root=root, **kwargs)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def copy(self):
        temporary = tempfile.TemporaryDirectory(dir=self.root)
        self.addCleanup(temporary.cleanup)
        output = Path(temporary.name)/"output"
        shutil.copytree(self.source, output)
        return output

    def read(self, path, name):
        return json.loads((path/(name+".json")).read_bytes())

    def write(self, path, name, data):
        (path/(name+".json")).write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")

    def verify(self, path):
        return verifier.verify(path, corpus=self.corpus)

    def test_complete_pairing_actual_schema_mask_reconstruction_and_scores(self):
        result = self.verify(self.source)
        self.assertEqual((result["status"], result["registered_rows"], result["paired_contexts"], result["verification_model_calls"]), ("passed", 96, 48, 0))
        self.assertEqual(result["physical_generation_attempts"], 97)
        self.assertEqual(result["query_encoder_calls"], {"A": 40, "B": 40})
        self.assertEqual(result["paired_comparison"]["changed_outbound"], 1)
        self.assertEqual(result["paired_comparison"]["identical_actual_answer_request"], 39)
        for arm in verifier.ARMS:
            self.assertEqual(result["arms"][arm]["legal"]["correct"], 32)
            self.assertEqual(result["arms"][arm]["missing"]["correct"], 8)
            self.assertEqual(result["arms"][arm]["outsider"]["outsider_blocked"], 8)

    def test_missing_outsider_and_fictional_calls_cannot_change_denominators(self):
        for kind in ("missing", "outsider"):
            output = self.copy()
            rows = self.read(output, "rows")
            rows.remove(next(r for r in rows if r["task_class"] == kind))
            self.write(output, "rows", rows)
            with self.assertRaisesRegex(ValueError, "answer_matrix"):
                self.verify(output)
        output = self.copy()
        rows = self.read(output, "rows")
        row = next(r for r in rows if r["answer_calls"])
        row["answer_calls"] += 1
        self.write(output, "rows", rows)
        with self.assertRaisesRegex(ValueError, "answer_count_allocation"):
            self.verify(output)

    def test_actual_schema_translation_and_forward_counts_are_not_model_claims(self):
        for field, value, code in (("actual_labels", {"organization": "unapproved description"}, "query_actual_schema"),
                                   ("translated_result", {"entities": {"organization": []}}, "query_translation_changed_entity"),
                                   ("extract_entities_calls", 2, "query_repeated_encoder")):
            output = self.copy()
            events = self.read(output, "query_encoder_events")
            event = next(e for e in events if e["arm"] == "A" and any(e["raw_result"]["entities"].values()))
            event[field] = deepcopy(value)
            self.write(output, "query_encoder_events", events)
            with self.assertRaisesRegex(ValueError, code):
                self.verify(output)
        output = self.copy()
        identity = self.read(output, "runtime_identity")
        original = identity["query_detectors"]["B"]["query"]["runtime"]["original_runtime"]
        original["weights_sha256"] = "mutated-"+str(original.get("weights_sha256"))
        self.write(output, "runtime_identity", identity)
        with self.assertRaisesRegex(ValueError, "query_changed_model_weights"):
            self.verify(output)

    def test_paired_nonce_tamper_and_coordinated_request_hash_tamper_are_rejected(self):
        output = self.copy()
        rows = self.read(output, "rows")
        row = next(r for r in rows if r["answer_calls"])
        row["outbound"]["memories"][0]["source_id"] = "m_"+"0"*24+"_1"
        row["actual_payload_sha256"] = verifier.digest(row["outbound"])
        self.write(output, "rows", rows)
        with self.assertRaisesRegex(ValueError, "paired_nonce_mismatch"):
            self.verify(output)
        output = self.copy()
        events = [json.loads(line) for line in (output/"request_transport.jsonl").read_text(encoding="utf-8").splitlines()]
        request = next(e for e in events if e["phase"] == "request" and e["stage"] == "answer")
        body = request["request"]
        payload = json.loads(body["messages"][1]["content"])
        payload["query"] += " FORGED_UNMASKED_QUERY"
        body["messages"][1]["content"] = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        wire = json.dumps(body, ensure_ascii=False).encode()
        for event in events:
            if event["index"] == request["index"]:
                event["request_sha256"] = verifier.digest(body)
        request.update(wire_json_utf8_bytes=len(wire), wire_json_utf8_sha256=verifier.sha(wire))
        (output/"request_transport.jsonl").write_text("".join(json.dumps(e, ensure_ascii=False)+"\n" for e in events), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "actual_answer_input"):
            self.verify(output)

    def test_raw_answer_and_secondary_summary_cannot_replace_primary(self):
        output = self.copy()
        rows = self.read(output, "rows")
        row = next(r for r in rows if r["answer_calls"])
        row["raw_model_answer"] += "\nFORGED_EXTRA_OUTPUT"
        self.write(output, "rows", rows)
        with self.assertRaisesRegex(ValueError, "full_raw_answer"):
            self.verify(output)
        output = self.copy()
        report = self.read(output, "report")
        report["arms"]["A"]["legal"]["correct"] -= 1
        self.write(output, "report", report)
        with self.assertRaisesRegex(ValueError, "independent_aggregate"):
            self.verify(output)

    def test_failure_and_overflow_fixtures_preserve_all_registered_cells(self):
        for scenario in ("annotation_failure", "oversized"):
            root = self.root/scenario
            self.make(root, **{scenario: True})
            result = verifier.verify(root/"output", corpus=root/"corpus")
            self.assertEqual(result["registered_rows"], 96)
            if scenario == "annotation_failure":
                self.assertTrue(all(result["arms"][a]["legal"]["label_set_unavailable"] == 32 for a in verifier.ARMS))
            else:
                self.assertEqual(result["query_encoder_calls"], {"A": 39, "B": 39})


if __name__ == "__main__":
    unittest.main()
