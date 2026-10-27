"""Bounded driver checks use fake HTTP and synthetic materials only."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, Mock

from scripts import run_relation_event_probe as probe
from tests.test_relation_events import pool, prediction, event
from tests.test_relation_probe_scoring import fixture, policy


def envelope(value):
    return {"model": probe.MODEL, "done": True, "done_reason": "stop", "prompt_eval_count": 512,
        "eval_count": 40, "message": {"content": json.dumps(value)}}


class RelationEventProbeTests(unittest.TestCase):
    def setUp(self):
        self.network = []
        for target in ("socket.socket", "socket.create_connection", "urllib.request.urlopen"):
            guard = patch(target, side_effect=AssertionError("network_forbidden"))
            self.network.append(guard.start()); self.addCleanup(guard.stop)
        self.text = "Larch is a customer of our company. Status is amber."
        self.pool = pool(self.text, [("Larch", 0)])

    def tearDown(self):
        for guard in self.network: guard.assert_not_called()

    def test_both_requests_share_source_candidates_and_fixed_budget_without_file_access(self):
        with patch.object(Path, "read_text", side_effect=AssertionError("no_file_reads")):
            requests, preflight = probe.requests_for([self.text], [self.pool])
        self.assertEqual(len(requests), 2)
        source_inputs = [json.loads(body["messages"][1]["content"]) for body in requests.values()]
        self.assertEqual(source_inputs[0], source_inputs[1])
        self.assertEqual(source_inputs[0], {"text": self.text, "candidates": self.pool["candidates"]})
        for body in requests.values():
            self.assertEqual(body["options"], probe.OPTIONS)
        self.assertTrue(all(row["fits"] for row in preflight))

    def test_coverage_failure_retains_whole_pool_and_calls_no_model(self):
        failed = deepcopy(self.pool); failed.update(status="needs_review", error_kind="coverage", errors=["candidate_limit_exceeded"])
        failed = probe.relation._seal(failed, "pool_sha256")
        before = deepcopy(failed); transport = Mock(side_effect=AssertionError("model_forbidden"))
        for arm in probe.ARMS:
            status, response, raw = probe.observe(self.text, failed, arm, None, transport)
            self.assertEqual((status,response["local_calls"],raw),("coverage_review",0,None))
        transport.assert_not_called(); self.assertEqual(failed,before)

    def test_direct_unknown_is_review_and_missing_duplicate_candidate_is_invalid(self):
        labels = [{"cid":"C0", "label":"organization_unknown_relation"}]
        result = probe.response_from_labels(self.text,self.pool,labels)
        self.assertEqual((result["status"],result["errors"]),("needs_review",["semantic_uncertainty"]))
        for wrong in ([], labels*2, [{"cid":"C9","label":"current_customer"}]):
            with self.assertRaises(ValueError): probe.response_from_labels(self.text,self.pool,wrong)

    def test_rules_keep_buying_direction_and_missing_relation_unknown(self):
        cases = [("Larch is a customer of our company.","ok",True),
                 ("Larch is our customer.","ok",True),
                 ("Larch has never been our customer.","ok",False),
                 ("Larch is not a customer of our company.","ok",False),
                 ("Larch sells machinery to our company.","needs_review",False),
                 ("Larch buys machinery from our company.","ok",True),
                 ("our company buys machinery from Larch.","needs_review",False),
                 ("our company sells machinery to Larch.","ok",True)]
        for text,status,sensitive in cases:
            candidates=pool(text,[("Larch",text.index("Larch"))])
            actual=probe.fixed_rules(text,candidates)
            self.assertEqual((actual["status"],bool(actual["findings"])),(status,sensitive),text)

    def test_invalid_model_output_is_retained_without_repair(self):
        client=Mock(return_value=envelope({"candidates":[]}))
        status,response,raw=probe.observe(self.text,self.pool,probe.ARMS[0],{},client)
        self.assertEqual((status,response["local_calls"]),("model_output_invalid",1))
        self.assertIsNotNone(raw); self.assertEqual(client.call_count,1)

    def test_event_output_uses_real_validator_and_composer(self):
        candidate=self.pool["candidates"][0]
        extracted={"candidates":[prediction(self.text,candidate,relation_events=[event(self.text,candidate)])]}
        client=Mock(return_value=envelope(extracted))
        status,response,_=probe.observe(self.text,self.pool,probe.ARMS[2],{},client)
        self.assertEqual((status,len(response["findings"]),response["local_calls"]),("ok",1,1))
        self.assertEqual(client.call_count,1)

    def test_http_client_captures_raw_counts_before_failure_and_cannot_retry_after_closure(self):
        with tempfile.TemporaryDirectory() as temp:
            raw=json.dumps(envelope({"candidates":[]}))
            exchange=Mock(return_value=raw)
            client=probe.Client(Path(temp),exchange=exchange)
            body={"model":probe.MODEL,"options":deepcopy(probe.OPTIONS)}
            client("POST","/api/chat",body)
            capture=json.loads((Path(temp)/"transport_001.json").read_text())
            self.assertEqual(capture["raw_response"],raw); self.assertEqual(client.posts,1)
            client.closed=True
            with self.assertRaises(ValueError):client("POST","/api/chat",body)
            self.assertEqual(exchange.call_count,1)
        with tempfile.TemporaryDirectory() as temp:
            client=probe.Client(Path(temp),exchange=Mock(side_effect=RuntimeError("synthetic_failure")))
            with self.assertRaises(RuntimeError):client("POST","/api/chat",body)
            self.assertEqual(client.posts,1)
            self.assertEqual(client.events[0]["error_type"],"RuntimeError")

    def test_transport_budget_route_and_identity_rejected_before_exchange(self):
        with tempfile.TemporaryDirectory() as temp:
            exchange=Mock(); client=probe.Client(Path(temp),exchange=exchange)
            body={"model":probe.MODEL,"options":deepcopy(probe.OPTIONS)}
            client.posts=probe.LIMITS["posts"]
            with self.assertRaises(ValueError):client("POST","/api/chat",body)
            with self.assertRaises(ValueError):client("POST","/api/pull",body)
            with self.assertRaises(ValueError):client("GET","https://remote.example")
            exchange.assert_not_called()

    def strict_rows(self):
        texts,reference,old=fixture(12)
        rows=[deepcopy(row) for row in old if row["cell"]["profile"]==probe.PROFILE]
        renamed=dict(zip(probe.scoring.ARMS,probe.ARMS))
        for row in rows:
            row["cell"]["arm"]=renamed[row["cell"]["arm"]]
            row["redaction_trace"]=probe.redaction.audit_observation(texts[row["cell"]["text_index"]],policy(probe.PROFILE),row)
        return texts,reference,rows

    def test_complete_strict_grid_unknown_separate_partial_coverage_not_success(self):
        texts,reference,rows=self.strict_rows()
        row=rows[0]; name=reference["cases"][0]["expected"][probe.PROFILE]["spans"][0]["text"]
        row["response"]["findings"][0].update(end=len(name)-2,quote=name[:-2])
        row["preparation"]=probe.scoring.prepare_observation(texts[0],policy(probe.PROFILE),row["response"])
        row["redaction_trace"]=probe.redaction.audit_observation(texts[0],policy(probe.PROFILE),row)
        before=deepcopy(rows)
        result=probe.score_rows(rows,reference,texts)
        group=result["by_arm"][row["cell"]["arm"]]
        self.assertEqual(group["unknown_cells"],1);self.assertEqual(group["unknown_review_matches"],1)
        self.assertEqual(group["unknown_negative"],0)
        self.assertEqual(group["partially_covered_sensitive_spans"],1)
        self.assertLess(group["complete_sensitive_span_coverage"],1)
        self.assertEqual(rows,before)
        with self.assertRaises(ValueError):probe.score_rows(rows[:-1],reference,texts)
        rows[-1]=deepcopy(rows[0])
        with self.assertRaises(ValueError):probe.score_rows(rows,reference,texts)

    def test_preflight_rejects_long_inputs_without_truncation(self):
        text=self.text+" "+"x"*4000
        candidates=pool(text,[("Larch",0)])
        requests,preflight=probe.requests_for([text],[candidates])
        self.assertTrue(all(not r["fits"] for r in preflight))
        self.assertTrue(all(json.loads(body["messages"][1]["content"])["text"]==text for body in requests.values()))

    def test_full_fake_execution_parses_reference_only_after_prediction_closure(self):
        texts, reference, _ = fixture(12)
        pools = [pool(text, [("Fixture Office "+str(i), 0)]) for i,text in enumerate(texts)]
        requests, preflight = probe.requests_for(texts,pools)
        plan = {"policy":policy(probe.PROFILE),"preflight":preflight,"expected_model_posts":24}
        actual_client = probe.Client
        def exchange(method,path,body):
            if path=="/api/version":return json.dumps({"version":probe.OLLAMA_VERSION})
            if path=="/api/tags":return json.dumps({"models":[{"name":probe.MODEL,"digest":probe.DIGEST}]})
            data=json.loads(body["messages"][1]["content"])
            if "Classify each supplied" in body["messages"][0]["content"]:
                result={"candidates":[{"cid":c["cid"],"label":"organization_unknown_relation"} for c in data["candidates"]]}
            else:
                result={"candidates":[prediction(data["text"],c,entity="unknown") for c in data["candidates"]]}
            return json.dumps(envelope(result))
        with tempfile.TemporaryDirectory() as temp:
            output=Path(temp)
            (output/"evaluation.opaque.json").write_text(json.dumps(reference),encoding="utf-8")
            original_read=Path.read_text
            reference_reads=[]
            def guarded_read(path,*args,**kwargs):
                if path.name=="evaluation.opaque.json":
                    self.assertTrue((output/"prediction_phase_closed.json").is_file())
                    reference_reads.append(path)
                return original_read(path,*args,**kwargs)
            with patch.object(probe,"verify",return_value=(plan,texts,pools,requests)), \
                 patch.object(probe,"Client",side_effect=lambda out:actual_client(out,exchange=exchange)), \
                 patch.object(probe.sys,"addaudithook"), patch.object(Path,"read_text",guarded_read), \
                 patch("builtins.print"):
                report=probe.execute(output,"synthetic-plan-sha")
            self.assertEqual(len(reference_reads),1)
            self.assertEqual((report["status"],report["generation_posts"],report["rows"]),("complete",24,36))
            self.assertEqual(report["by_arm"][probe.ARMS[0]]["unknown_negative"],0)
            self.assertEqual(len(list(output.glob("transport_*.json"))),28)


if __name__ == "__main__":unittest.main()
