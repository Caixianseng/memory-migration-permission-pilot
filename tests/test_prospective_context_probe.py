"""Prospective driver checks with synthetic pools and fake generation only."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from scripts import run_prospective_context_probe as probe
from tests.test_candidate_context_probe import complete_pool
from tests.test_relation_event_probe import envelope
from tests.test_relation_probe_scoring import fixture, policy


class ProspectiveContextProbeTests(unittest.TestCase):
    def setUp(self):
        self.network=[]
        for name in ("socket.socket","socket.create_connection","urllib.request.urlopen"):
            guard=patch(name,side_effect=AssertionError("network_forbidden"))
            self.network.append(guard.start());self.addCleanup(guard.stop)

    def tearDown(self):
        for guard in self.network:guard.assert_not_called()

    def fake_client(self, output):
        def exchange(method,path,body):
            data=json.loads(body["messages"][1]["content"])
            return json.dumps(envelope({"candidates":[{"cid":c["cid"],"label":"organization_unknown_relation"} for c in data["candidates"]]}))
        return probe.BoundedClient(output,exchange=exchange)

    def test_plain_route_reuses_identical_observation_without_second_post(self):
        text="Larch is an organization.";pool=complete_pool(text,["Larch"])
        with tempfile.TemporaryDirectory() as temp:
            client=self.fake_client(Path(temp));selected,rows=probe.observe_pair(text,pool,client)
            self.assertEqual(selected["route"]["mode"],"plain")
            self.assertEqual(client.posts,1)
            self.assertEqual(rows["plain"]["raw_response"],rows["conditional"]["raw_response"])
            self.assertEqual(rows["plain"]["response"],rows["conditional"]["response"])
            self.assertEqual((rows["conditional"]["physical_generation_calls"],rows["conditional"]["shared_from"]),(0,"plain"))

    def test_duplicate_occurrence_route_keeps_inventory_and_uses_two_posts(self):
        text="Larch is our customer; Larch is printed on the folder."
        pool=complete_pool(text,["Larch"])
        second=deepcopy(pool["candidates"][0]);second.update(cid="C1",start=text.index("Larch",1),end=text.index("Larch",1)+5)
        pool["candidates"].append(second);pool["candidate_count"]=2
        pool["raw_result"]["entities"]["organization"].append({k:v for k,v in second.items() if k!="cid"}|{"confidence":.9})
        pool=probe.base.relation._seal(pool,"pool_sha256")
        with tempfile.TemporaryDirectory() as temp:
            client=self.fake_client(Path(temp));selected,rows=probe.observe_pair(text,pool,client,reverse=True)
            self.assertEqual((selected["route"]["mode"],client.posts),("marked",2))
            self.assertEqual(rows["conditional"]["input_mode"],"marked")
            bodies=[event["body"] for event in client.events]
            self.assertEqual(bodies[0]["messages"][0],bodies[1]["messages"][0])
            self.assertTrue(all(json.loads(body["messages"][1]["content"])["candidates"]==pool["candidates"] for body in bodies))

    def test_bad_pool_and_context_limit_block_both_arms_without_generation(self):
        text="Larch is an organization.";pool=complete_pool(text,["Larch"])
        failed=deepcopy(pool);failed.update(status="needs_review",error_kind="coverage",errors=["proposal_full_token_budget_exceeded"])
        failed=probe.base.relation._seal(failed,"pool_sha256")
        long=text+" x"*2100;long_pool=complete_pool(long,["Larch"])
        for text,pool in ((text,failed),(long,long_pool)):
            client=Mock(side_effect=AssertionError("generation_forbidden"))
            selected,rows=probe.observe_pair(text,pool,client)
            self.assertEqual(selected["status"],"coverage_review")
            self.assertTrue(all(row["status"]=="coverage_review" and row["physical_generation_calls"]==0 for row in rows.values()))
            client.assert_not_called()

    def test_new_client_has_48_cap_without_mutating_old_24_cap(self):
        self.assertEqual(probe.base.LIMITS["posts"],24)
        with tempfile.TemporaryDirectory() as temp:
            client=probe.BoundedClient(Path(temp),exchange=Mock(return_value="{}"));client.posts=47
            body={"model":probe.base.MODEL,"options":deepcopy(probe.base.OPTIONS)}
            client("POST","/api/chat",body);self.assertEqual(client.posts,48)
            with self.assertRaises(ValueError):client("POST","/api/chat",body)
            self.assertEqual(client.exchange.call_count,1)
        self.assertEqual(probe.base.LIMITS["posts"],24)

    def test_full_48_row_score_keeps_blocked_unknown_and_shared_rows(self):
        texts,reference,historical=fixture(24);rename=dict(zip(probe.scoring.ARMS[:2],probe.ARMS))
        rows=[deepcopy(row) for row in historical if row["cell"]["profile"]==probe.base.PROFILE and row["cell"]["arm"] in rename]
        for row in rows:
            i=row["cell"]["text_index"];row["cell"]["arm"]=rename[row["cell"]["arm"]]
            if i==0:row.update(status="coverage_review",response=probe.base.failure_response("input_budget_exceeded"))
            row["preparation"]=probe.scoring.prepare_observation(texts[i],policy(probe.base.PROFILE),row["response"])
            row["redaction_trace"]=probe.redaction.audit_observation(texts[i],policy(probe.base.PROFILE),row)
        before=deepcopy(rows);results=probe.score_rows(rows,reference,texts)
        self.assertFalse(results["advance_gate_passed"])
        self.assertEqual(results["by_arm"]["plain"],results["by_arm"]["conditional"])
        group=results["by_arm"]["plain"]
        self.assertEqual((group["cells"],group["known"],group["unknown"],group["unknown_review"]),(24,23,1,1))
        self.assertEqual(group["statuses"]["coverage_review"],1);self.assertGreater(group["fn"],0)
        self.assertEqual(rows,before)
        with self.assertRaises(ValueError):probe.score_rows(rows[:-1],reference,texts)

    def test_freeze_copies_opaque_reference_without_parsing(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);materials=root/"materials";materials.mkdir();(root/"results").mkdir()
            runtime={"schema_version":"relation_occurrence_probe_runtime_v1","texts":["Story "+str(i) for i in range(24)]}
            (materials/"runtime.json").write_text(json.dumps(runtime),encoding="utf-8")
            reference=b"deliberately invalid opaque JSON; scoring may only parse after closure"
            (materials/"evaluation.opaque.json").write_bytes(reference)
            receipt=root/".runtime/github_ner/receipt.json";receipt.parent.mkdir(parents=True);receipt.write_text("{}")
            with patch.object(probe,"ROOT",root),patch.object(probe,"check_method"),patch.object(probe.assets,"verify_assets"),patch.object(probe,"manifest",return_value={}):
                result=probe.freeze(root/"results/run",materials)
            self.assertEqual(result["new_model_calls"],0)
            self.assertEqual((root/"results/run/evaluation.opaque.json").read_bytes(),reference)

    def test_full_fake_execution_closes_48_rows_before_reference_and_counts_shared_calls(self):
        texts,reference,_=fixture(24)
        class FakeNer:
            identity={"fake":"ner"}
            def __init__(self):self.calls=0
            def infer(self,text,labels,**kwargs):
                name="Fixture Office "+str(self.calls);self.calls+=1
                return complete_pool(text,[name])["raw_result"]
        def exchange(method,path,body):
            if path=="/api/version":return json.dumps({"version":probe.base.OLLAMA_VERSION})
            if path=="/api/tags":return json.dumps({"models":[{"name":probe.base.MODEL,"digest":probe.base.DIGEST}]})
            data=json.loads(body["messages"][1]["content"])
            return json.dumps(envelope({"candidates":[{"cid":c["cid"],"label":"organization_unknown_relation"} for c in data["candidates"]]}))
        with tempfile.TemporaryDirectory() as temp:
            output=Path(temp);(output/"evaluation.opaque.json").write_text(json.dumps(reference),encoding="utf-8")
            plan={"policy":policy(probe.base.PROFILE),"assets_root":"fake","scope":"synthetic test"}
            original_read=Path.read_text;reads=[];client_class=probe.BoundedClient
            def guarded_read(path,*args,**kwargs):
                if path.name=="evaluation.opaque.json":
                    self.assertTrue((output/"prediction_phase_closed.json").is_file());reads.append(path)
                return original_read(path,*args,**kwargs)
            torch=SimpleNamespace(set_num_threads=Mock(),manual_seed=Mock(),get_num_interop_threads=lambda:2)
            with patch.object(probe,"verify",return_value=(plan,texts)),patch.object(probe.assets,"verify_assets"), \
                 patch.object(probe,"LocalNerRuntime",return_value=FakeNer()),patch.dict("sys.modules",{"torch":torch}), \
                 patch.object(probe,"BoundedClient",side_effect=lambda out:client_class(out,exchange=exchange)), \
                 patch.object(probe.sys,"addaudithook"),patch.object(Path,"read_text",guarded_read),patch("builtins.print"):
                report=probe.execute(output,"fake-plan-hash")
            self.assertEqual(len(reads),1)
            self.assertEqual((report["rows"],report["generation_posts"],report["shared_plain_rows"]),(48,24,24))
            self.assertEqual(report["ner_counts"],{"proposal_infer_invocations":24,"classification_extract_invocations":0})
            self.assertEqual(len(list(output.glob("ner_capture_*.json"))),24)
            self.assertFalse(report["advance_gate_passed"])


if __name__=="__main__":unittest.main()
