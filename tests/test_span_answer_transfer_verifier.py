"""Independent 144-cell audit tests over authored, zero-network pipeline data."""
from copy import deepcopy
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from memory_migration_study.local_detector import DIGEST, MODEL, VERSION
from scripts import verify_span_answer_transfer as verifier
from tests import test_span_answer_transfer as authored


class SpanTransferVerifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temporary.name)
        actual_run = authored.harness.run
        def configured(corpus, output, model_root, config, observer, **kwargs):
            pinned = {"endpoint": "http://127.0.0.1:11435", "model": MODEL, "expected_version": VERSION,
                      "expected_digest": DIGEST, "timeout_seconds": 120}
            return actual_run(corpus, output, model_root, pinned, observer, **kwargs)
        with patch.object(authored.harness, "run", side_effect=configured):
            authored.SpanAnswerTransferTests().run_authored(root=cls.root/"authored")
        cls.source = cls.root/"authored/output"
        cls.corpus = cls.root/"authored/corpus"

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def copy(self):
        temporary = tempfile.TemporaryDirectory(dir=self.root)
        self.addCleanup(temporary.cleanup)
        output = Path(temporary.name)/"output"
        shutil.copytree(self.source, output)
        return output

    def read(self, output, name):
        return json.loads((output/(name+".json")).read_bytes())

    def write(self, output, name, value):
        (output/(name+".json")).write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")

    def verify(self, output):
        return verifier.verify(output, corpus=self.corpus)

    def test_complete_actual_fake_pipeline_independent_source_restore_and_scores(self):
        receipt = self.verify(self.source)
        self.assertEqual((receipt["status"], receipt["registered_rows"], receipt["shared_contexts"]), ("passed", 144, 48))
        self.assertEqual(receipt["physical_generation_attempts"], 137)
        self.assertEqual(receipt["verification_model_calls"], 0)
        for arm in verifier.ARMS:
            self.assertEqual(receipt["arms"][arm]["legal"]["correct"], 32)
            self.assertEqual(receipt["arms"][arm]["missing"]["correct"], 8)
            self.assertEqual(receipt["arms"][arm]["outsider"]["outsider_blocked"], 8)
        self.assertIsNone(receipt["arms"]["span_pointer"]["legal"]["secondary_correct"])

    def test_missing_and_outsider_rows_cannot_be_removed_from_denominators(self):
        for kind in ("missing", "outsider"):
            output = self.copy()
            rows = self.read(output, "rows")
            rows.remove(next(r for r in rows if r["task_class"] == kind))
            self.write(output, "rows", rows)
            with self.assertRaisesRegex(ValueError, "answer_matrix"):
                self.verify(output)

    def test_coordinated_body_token_and_hash_tamper_still_fails_current_view_binding(self):
        output = self.copy()
        rows = self.read(output, "rows")
        row = next(r for r in rows if r["arm"] == "free_indexed" and r["answer_calls"])
        index = row["answer_request_indices"][0]
        path = output/"request_transport.jsonl"
        events = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
        request = next(e for e in events if e["phase"] == "request" and e["index"] == index)
        body = request["request"]
        data = json.loads(body["messages"][1]["content"])
        data["evidence"]["sources"][0]["tokens"][0][1] = "FORGED_SOURCE_WORD"
        body["messages"][1]["content"] = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
        new_hash = verifier.digest(body)
        wire = json.dumps(body, ensure_ascii=False).encode()
        for event in events:
            if event["index"] == index:
                event["request_sha256"] = new_hash
        request.update(wire_json_utf8_bytes=len(wire), wire_json_utf8_sha256=verifier.sha(wire))
        meta = row["answer_metadata"]
        meta.update(request_sha256=new_hash, messages_sha256=verifier.digest(body["messages"]),
            input_sha256=verifier.digest({"messages": body["messages"], "format": None}),
            packed_view_sha256=verifier.digest(data["evidence"]), input_budget_upper_bound=len(wire)+320+64)
        self.write(output, "rows", rows)
        path.write_text("".join(json.dumps(e, ensure_ascii=False)+"\n" for e in events), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "answer_metadata_packed_view_sha256"):
            self.verify(output)

    def test_extra_pointer_output_cannot_be_promoted_to_correct_missing_unknown(self):
        output = self.copy()
        rows = self.read(output, "rows")
        row = next(r for r in rows if r["arm"] == "span_pointer" and r["task_class"] == "missing")
        raw = '{"decision":"UNKNOWN","answer":"Cedar Foundry"}'
        row.update(raw_model_answer=raw, model_answer=raw)
        self.write(output, "rows", rows)
        path = output/"request_transport.jsonl"
        events = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
        event = next(e for e in events if e["phase"] == "response" and e["index"] == row["answer_request_indices"][0])
        event["response"]["message"]["content"] = raw
        event["response_sha256"] = verifier.digest(event["response"])
        path.write_text("".join(json.dumps(e, ensure_ascii=False)+"\n" for e in events), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "invalid_pointer_schema"):
            self.verify(output)

    def test_wrong_selected_source_fake_calls_and_pointer_secondary_are_rejected(self):
        for mutation, expected in (("source", "pointer_exact_source_span"), ("calls", "row_answer_call_allocation"),
                                   ("secondary", "pointer_repaired_after_model")):
            output = self.copy()
            rows = self.read(output, "rows")
            row = next(r for r in rows if r["arm"] == "span_pointer" and r["task_class"] == "legal")
            if mutation == "source":
                row["source_span"]["source_id"] = "another-memory-source"
            elif mutation == "calls":
                row["answer_calls"] = 0
            else:
                row["secondary_serialization_registered"] = True
                row["secondary_serialization"] = {"decision": "unchanged"}
            self.write(output, "rows", rows)
            with self.assertRaisesRegex(ValueError, expected):
                self.verify(output)


if __name__ == "__main__":
    unittest.main()
