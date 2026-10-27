"""No native backend, model, encoder forward or line trace in these tests."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch
from scripts import native_vector_metadata_worker as worker
from scripts import run_native_vector_metadata_only as driver

SOURCE='''class ChromaClient:
    def search(self, collection_name, vectors, filter=None, limit=10):
        try:
            collection = self.client.get_collection(name=collection_name, embedding_function=None)
            if collection:
                result = collection.query(query_embeddings=vectors, n_results=limit, where=filter)
                distances = result['distances'][0]
                distances = [2 - dist for dist in distances]
                distances = [[dist / 2 for dist in distances]]
                return SearchResult(ids=result['ids'], distances=distances,
                    documents=result['documents'], metadatas=result['metadatas'])
            return None
        except Exception as e:
            return None
'''
SHA=hashlib.sha256(SOURCE.encode()).hexdigest()


class FakeClient:
    def __init__(self,phase=None):self.phase=phase;self.get_calls=0;self.query_calls=0;self.params=None
    def get_collection(self,**kwargs):
        self.get_calls+=1
        if self.phase=="get":raise RuntimeError("Error executing plan; Bearer PRIVATE.NOT.PERSISTED")
        return None if self.phase=="false_collection" else self
    def query(self,**kwargs):
        self.query_calls+=1;self.params=kwargs
        if self.phase=="query":raise ValueError("Error finding id PRIVATE.NOT.PERSISTED")
        if self.phase=="distance":return {}
        return {"distances":[[0.2]],"ids":[["owned"]],"documents":[["synthetic"]],"metadatas":[[{}]]}
    def count(self):raise AssertionError("extra count forbidden")
    def get(self):raise AssertionError("extra get forbidden")


def observed(phase=None,builder=None):
    result=object();scope={"SearchResult":builder or (lambda **kwargs:result)}
    exec(compile(SOURCE,"fake_chroma.py","exec"),scope)
    backend=scope["ChromaClient"]();backend.client=FakeClient(phase)
    search=worker.MetadataSearch(backend.search,{"owner":"native-owner"},
        lambda:{"snapshot_name":"before_revoke","native_request_index":35},source=SOURCE,filename="fake_chroma.py",expected_sha=SHA)
    return search,backend,result


def old_report():
    writes=[{"actor":"owner","text":"Synthetic main.","path":"/original/main"},
        {"actor":"assistant","text":"Synthetic main.","path":"/original/main"},
        {"actor":"assistant","text":"Independent control.","path":"/original/control"}]
    residents=[{"target_id":"old-"+a,"actor":a,"content":"Original fixed resident "+a,"path":"/resident-control/"+a} for a in driver.bridge.ACTORS]
    ids=["old-0","old-1","old-2"]+[r["target_id"] for r in residents]
    calls=[]
    def add(command,data,result=None):
        n=len(calls);calls.append({"command":command,"input":data,"result":result or {},"started_ns":n*10+1,"finished_ns":n*10+5})
    add("init",{});add("snapshot",{"target_ids":[]})
    for i,row in enumerate(writes):add("add",row,{"target_id":"old-"+str(i)})
    add("add_residents",{},{"residents":residents})
    for _ in range(3):add("snapshot",{"target_ids":ids})
    add("delete",{"actor":"owner","target_id":"old-0"});add("delete",{"actor":"assistant","target_id":"old-1"})
    for _ in range(2):add("snapshot",{"target_ids":ids})
    add("report",{});add("close",{})
    return {"target_rpc_receipts":calls,"resident_controls":residents,"trusted_fixture":{"source_only_canary":"SOURCE-ONLY"}}


class MetadataOnlyTests(unittest.TestCase):
    def test_success_is_same_object_one_call_and_never_settrace(self):
        search,backend,result=observed()
        with patch.object(sys,"settrace",side_effect=AssertionError("no tracing")):
            self.assertIs(search("user-memory-native-owner",[[0.0]*384],None,100),result)
        self.assertEqual((backend.client.get_calls,backend.client.query_calls),(1,1))
        self.assertEqual(backend.client.params,{"query_embeddings":[[0.0]*384],"n_results":100,"where":None})
        self.assertEqual(search.calls[0]["exception_events"],[])
        self.assertTrue(search.receipt["normal_path_ast_preserved"]);self.assertEqual(search.receipt["added_statements"],1)

    def test_original_exception_sites_remain_none_and_only_metadata_is_saved(self):
        for phase in ("get","query","distance"):
            search,backend,_=observed(phase)
            self.assertIsNone(search("user-memory-native-owner",[[0.0]*384],None,100))
            row=search.calls[0];self.assertEqual(row["none_reason"],"caught_exception")
            self.assertEqual(len(row["exception_events"]),1)
            self.assertTrue(row["exception_events"][0]["stack"])
            self.assertNotIn("PRIVATE.NOT.PERSISTED",json.dumps(row));self.assertNotIn("message",row["exception_events"][0])
            self.assertEqual(backend.client.get_calls,1)

    def test_result_constructor_failure_and_nonexception_none_are_distinct(self):
        def fail(**kwargs):raise TypeError("synthetic result validation failure")
        search,_,_=observed(builder=fail);self.assertIsNone(search("user-memory-native-owner",[[0]],None,100))
        self.assertEqual(search.calls[0]["exception_events"][0]["class"],"builtins.TypeError")
        search,_,_=observed("false_collection");self.assertIsNone(search("user-memory-native-owner",[[0]],None,100))
        self.assertEqual(search.calls[0]["none_reason"],"non_exception_branch");self.assertEqual(search.calls[0]["exception_events"],[])

    def test_catch_observer_failure_preserves_none_and_marks_evidence_unusable(self):
        search,backend,_=observed("query")
        with patch.object(worker,"exception_metadata",side_effect=ValueError("observer formatting failed")):
            self.assertIsNone(search("user-memory-native-owner",[[0]],None,100))
        self.assertEqual((backend.client.get_calls,backend.client.query_calls),(1,1))
        self.assertTrue(search.observer_failure);self.assertEqual(search.observer_errors,["metadata_observer_failed"])
        row=search.calls[0];self.assertTrue(row["observer_failure"])
        self.assertEqual(row["none_reason"],"observation_failed");self.assertEqual(row["exception_events"],[])
        self.assertNotIn("outward_exception",row)
        target=worker.MetadataTargetWorker.__new__(worker.MetadataTargetWorker)
        target.metadata_search=search;target.snapshot_ordinal=2
        with patch.object(worker.TargetWorker,"summary",return_value={}):summary=target.summary()["metadata_only"]
        self.assertTrue(summary["observer_failure"]);self.assertEqual(summary["observer_errors"],search.observer_errors)

    def test_unused_failing_observer_keeps_success_and_nonexception_none(self):
        for phase in (None,"false_collection"):
            search,backend,result=observed(phase)
            with patch.object(worker,"exception_metadata",side_effect=ValueError("must not run")) as metadata:
                actual=search("user-memory-native-owner",[[0]],None,100)
            self.assertIs(actual,result if phase is None else None);metadata.assert_not_called()
            self.assertFalse(search.observer_failure);self.assertEqual(search.observer_errors,[])
            self.assertFalse(search.calls[0]["observer_failure"])
            self.assertEqual((backend.client.get_calls,backend.client.query_calls),(1,1 if phase is None else 0))

    def test_outward_backend_exception_identity_survives_observer_failure(self):
        class BackendSignal(BaseException):pass
        original_error=BackendSignal("original backend signal")
        search,backend,_=observed()
        with patch.object(backend.client,"query",side_effect=original_error) as query,patch.object(
                worker,"exception_metadata",side_effect=ValueError("observer formatting failed")):
            with self.assertRaises(BackendSignal) as caught:search("user-memory-native-owner",[[0]],None,100)
        self.assertIs(caught.exception,original_error);query.assert_called_once();self.assertEqual(backend.client.get_calls,1)
        self.assertTrue(search.observer_failure);self.assertTrue(search.calls[0]["observer_failure"])
        self.assertEqual(search.observer_errors,["outward_exception_observer_failed"])
        self.assertNotIn("return_kind",search.calls[0]);self.assertNotIn("outward_exception",search.calls[0])

    def test_execute_rejects_failed_or_missing_observer_status_even_with_complete_counts(self):
        final={"native_requests":[{} for _ in range(164)],"native_embedding_function_invocations":21,
            "generation_attempts":0,"network_events":[],"metadata_only":{"snapshot_calls":6,"search_calls":15,
                "observer_errors":[],"observer_failure":False,"observations":[{"variant_calls":1,
                    "literal_original_function_calls":0,"trace_disabled_before":True,"trace_disabled_after":True,
                    "observer_failure":False,"exception_events":[]} for _ in range(15)]}}
        class Target:
            def __init__(self):self.calls=[{"command":"close"}];self.terminated=False
            def terminate(self):self.terminated=True
        cases=(("healthy",False,[],True),("failed",True,[],False),
            ("missing",None,[],False),("error_list",False,["metadata_observer_failed"],False))
        with tempfile.TemporaryDirectory(prefix="metadata-offline-") as folder:
            root=Path(folder);(root/"fixture.json").write_text("{}",encoding="utf-8")
            plan={"output":str(root),"python":"unused-python","legacy":"unused-legacy",
                "fixture_sha256":"unused","code_sha256":{},"asset_sha256":{}}
            for name,status,errors,accepted in cases:
                current=deepcopy(final);observations=current["metadata_only"];observations["observer_errors"]=errors
                if status is None:del observations["observer_failure"]
                else:observations["observer_failure"]=status
                complete={"final":current,"snapshots":{str(i):{"rows":[]} for i in range(6)},
                    "deletions":[{},{}],"checks":[{"passed":True} for _ in range(6)]}
                target=Target();saved=[]
                with self.subTest(case=name),patch.object(driver,"validate_plan",return_value=plan),patch.object(
                        driver.bridge,"file_sha256",return_value="offline"),patch.object(driver.bridge,"verify_sha_table",
                        return_value={"status":"passed"}),patch.object(driver,"save",side_effect=lambda path,data:saved.append((path,deepcopy(data)))),patch.object(
                        driver,"replay",return_value=complete):
                    report=driver.execute(root/"unused-plan.json",factory=lambda *args,**kwargs:target)
                self.assertIs(report["instrumentation_complete"],accepted);self.assertTrue(target.terminated)
                self.assertEqual(report["interpretation"],"not_reproduced_in_one_fixed_complete_lifecycle" if accepted else "failure_observed_or_run_incomplete")
                self.assertFalse(report["original_v3_failure_closed"]);self.assertEqual(saved[-1][1],report)

    def test_source_shape_and_existing_tracer_fail_closed(self):
        with self.assertRaises(ValueError):worker.instrument_search(SOURCE,"fake",{},lambda e:None,"0"*64)
        changed=SOURCE.replace("except Exception as e:","except ValueError as e:")
        with self.assertRaises(ValueError):worker.instrument_search(changed,"fake",{},lambda e:None,hashlib.sha256(changed.encode()).hexdigest())
        search,backend,_=observed()
        with patch.object(sys,"gettrace",return_value=object()),self.assertRaises(ValueError):search("user-memory-native-owner",[[0]],None,100)
        self.assertEqual(backend.client.get_calls,0)

    def test_complete_lifecycle_freezes_all_six_texts_gaps_snapshots_and_deletes(self):
        report=old_report();fixture=driver.freeze_fixture(report)
        self.assertEqual(len(fixture["writes"]),6);self.assertEqual(len(fixture["schedule"]),15)
        self.assertEqual([r["command"] for r in fixture["schedule"]],list(driver.COMMANDS))
        self.assertEqual([r["snapshot_name"] for r in fixture["schedule"] if r["command"]=="snapshot"],list(worker.SNAPSHOTS))
        self.assertEqual(fixture["writes"][3]["text"],report["resident_controls"][0]["content"])
        changed=deepcopy(report);changed["target_rpc_receipts"][10]["input"]["target_id"]="old-outsider"
        with self.assertRaises(ValueError):driver.freeze_fixture(changed)
        changed=deepcopy(report);changed["resident_controls"][0]["content"]="SOURCE-ONLY"
        with self.assertRaises(ValueError):driver.freeze_fixture(changed)

    def test_full_replay_continues_nulls_uses_fresh_ids_without_extra_queries(self):
        fixture=driver.freeze_fixture(old_report());calls=[];sleeps=[]
        class Target:
            def call(self,command,data):
                calls.append((command,deepcopy(data)))
                if command=="add":return {"target_id":"new-"+str(len([x for x in calls if x[0]=="add"])),"actor":data["actor"],"content":data["text"]}
                if command=="add_residents":return {"residents":[{"target_id":"new-"+x["logical_id"],"actor":x["actor"],"content":x["text"],"path":x["path"]} for x in fixture["writes"][3:]]}
                if command=="delete":return {"status":200,"deleted":True,**data}
                if command=="snapshot":return {"rows":[{"actor":"owner","operation":"semantic","status":200,"vector_result":None,"native_raw_body":"null"}]}
                return {}
        with patch.object(driver.bridge,"check_snapshot",return_value=False):result=driver.replay(Target(),fixture,sleep=sleeps.append)
        self.assertEqual([x[0] for x in calls],list(driver.COMMANDS));self.assertEqual(len(result["snapshots"]),6)
        self.assertEqual(len(result["deletions"]),2);self.assertTrue(all(not x["passed"] for x in result["checks"]))
        self.assertEqual(calls[9][1]["target_id"],"new-1");self.assertEqual(calls[10][1]["target_id"],"new-2")
        self.assertEqual(len(calls[11][1]["target_ids"]),6);self.assertEqual(len(sleeps),15)

    def test_foreign_id_or_auth_backend_error_is_not_an_ordinary_null(self):
        expected={a:{"owned"} for a in driver.bridge.ACTORS}
        for status,value in ((401,None),(500,None),(200,{"ids":[["foreign"]]})):
            snapshot={"rows":[{"actor":"owner","operation":"semantic","status":status,"vector_result":value}]}
            with self.subTest(status=status),self.assertRaises(ValueError):driver.validate_snapshot_security(snapshot,expected)


if __name__=="__main__":unittest.main()
