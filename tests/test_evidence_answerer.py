import copy
import json
import unittest

from memory_migration_study.evidence_answerer import LocalEvidenceFactAnswerer
from memory_migration_study.local_detector import MODEL


class EvidenceAnswererTests(unittest.TestCase):
    token = "[PVT_0123456789ABCDEF01234567_CUSTOMER_1]"

    def setUp(self):
        self.payload = {"query": "Who is the customer?", "memories": [{"source_id": "m_1", "text": "Customer: "+self.token}]}
        self.candidates = [{"answer_id": "E_0123456789ABCDEF_1", "token": self.token}]
        self.requests = []

    def transport(self, method, path, body):
        self.requests.append(copy.deepcopy(body))
        answer = json.dumps({"answer_id": self.candidates[0]["answer_id"]}) if "format" in body else self.token
        return {"model": MODEL, "done": True, "done_reason": "stop", "message": {"role": "assistant", "content": answer},
                "prompt_eval_count": 100, "eval_count": 20}

    def test_three_modes_are_one_call_and_baseline_input_unchanged(self):
        answerer = LocalEvidenceFactAnswerer(transport=self.transport)
        original = copy.deepcopy(self.payload)
        for mode in ("free", "free_candidates", "evidence_id"):
            result = answerer(self.payload, mode=mode, candidates=None if mode == "free" else self.candidates)
            self.assertEqual(result["status"], "ok")
            self.assertEqual(result["local_calls"], 1)
        self.assertEqual(self.payload, original)
        self.assertEqual(json.loads(self.requests[0]["messages"][1]["content"]), self.payload)
        self.assertNotIn("format", self.requests[1])
        self.assertEqual(self.requests[0]["messages"][0], self.requests[1]["messages"][0])
        self.assertEqual(self.requests[2]["format"]["properties"]["answer_id"]["enum"], ["UNKNOWN", self.candidates[0]["answer_id"]])

    def test_query_cannot_add_a_candidate_and_overflow_is_not_truncated(self):
        answerer = LocalEvidenceFactAnswerer(transport=self.transport)
        no_memory = {"query": self.token, "memories": []}
        result = answerer(no_memory, mode="evidence_id", candidates=self.candidates)
        self.assertEqual(result["local_calls"], 0)
        self.assertEqual(result["status"], "error")
        for candidates in (self.candidates*33, [dict(self.candidates[0], readers=["all"])], [{"answer_id": "E1", "token": "raw name"}]):
            self.assertEqual(answerer(self.payload, mode="evidence_id", candidates=candidates)["local_calls"], 0)

    def test_complete_response_is_preserved_for_security_validation(self):
        raw = '{"answer_id":"UNKNOWN"} secret trailing text'
        def transport(*args):
            result = self.transport(*args)
            result["message"]["content"] = raw
            return result
        result = LocalEvidenceFactAnswerer(transport=transport)(self.payload, mode="evidence_id", candidates=self.candidates)
        self.assertEqual(result["answer"], raw)

    def test_invalid_envelope_usage_and_transport_do_not_become_successful_unknown(self):
        for field, value in (("done_reason", "length"), ("eval_count", 65), ("prompt_eval_count", 3073), ("prompt_eval_count", None)):
            def transport(*args, field=field, value=value):
                result = self.transport(*args)
                result[field] = value
                return result
            result = LocalEvidenceFactAnswerer(transport=transport)(self.payload)
            self.assertEqual(result["status"], "error")
            self.assertIsNone(result["answer"])
            self.assertEqual(result["local_calls"], 1)
        def failed(*args):
            raise RuntimeError("private exception details")
        result = LocalEvidenceFactAnswerer(transport=failed)(self.payload)
        self.assertNotIn("private", json.dumps(result))

    def test_budget_and_remote_config_rejected_before_generation(self):
        answerer = LocalEvidenceFactAnswerer(transport=self.transport)
        payload = {"query": "x"*5000, "memories": []}
        self.assertEqual(answerer(payload)["local_calls"], 0)
        self.assertEqual(answerer(self.payload, candidates=self.candidates)["local_calls"], 0)
        with self.assertRaises(ValueError):
            LocalEvidenceFactAnswerer({"endpoint": "https://remote.example"})


if __name__ == "__main__":
    unittest.main()
