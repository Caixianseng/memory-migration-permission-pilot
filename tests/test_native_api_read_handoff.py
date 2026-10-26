"""Explicit fake native API protocol; no vendor/client/model execution."""
from __future__ import annotations
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest

from scripts import run_native_api_read_handoff as m


class FakeNative:
    def __init__(self, python, script, args, *, timeout=240, registry=None, fault=None):
        self.state=args[args.index("--state")+1]; self.source="source" in self.state
        self.cap=int(args[args.index("--http-cap")+1]); self.calls=[]; self.requests=[]
        self.datasets={}; self.facts={}; self.acl=set(); self.registry=registry; self.fault=fault
        self.identities={a:{"id":self.state+":user:"+a,"role":"user","credential_kind":"bearer"} for a in m.ACTORS}
        registry["source" if self.source else "target"]=self

    def trace(self, value, actor="owner", status=200):
        if len(self.requests)>=self.cap: raise AssertionError("fake observed hard cap exceeded")
        raw=value if isinstance(value,str) else json.dumps(value)
        row={"index":len(self.requests),"actor":actor,"status":status,"response_checked":True,
            "execution_error":None,"authorization_present":actor is not None,"api_key_present":False,
            "cookie_present":False,"native_raw_body":raw,"native_body_sha256":m.sha(raw.encode()),"byte_count":len(raw.encode())}
        self.requests.append(row); return {"status":status,"trace":deepcopy(row)}

    def summary(self):
        return {"native_requests":deepcopy(self.requests),"identities":deepcopy(self.identities),
            "datasets":deepcopy(self.datasets),"facts":deepcopy(self.facts),"network_events":[],
            "generation_attempts":0,"embedding_attempts":0,"inference_events":[],"client_credential_values_persisted":False}

    def allowed(self, actor, ds):return actor=="owner" or (actor,ds) in self.acl
    def note(self, ds):
        grants=[{"id":"grant-"+a+"-"+ds,"resource_type":"note","resource_id":self.datasets[ds]["id"],
            "principal_type":"user","principal_id":self.identities[a]["id"],"permission":"read","created_at":1}
            for a,d in sorted(self.acl) if d==ds]
        if self.fault in {"group","write","unknown_field","unmapped"} and grants:
            if self.fault=="group":grants[0]["principal_type"]="group"
            if self.fault=="write":grants[0]["permission"]="write"
            if self.fault=="unknown_field":grants[0]["purpose"]="unknown"
            if self.fault=="unmapped":grants[0]["principal_id"]="unknown-source-user"
        return {"id":self.datasets[ds]["id"],"user_id":self.identities["owner"]["id"],
            "title":"controlled_"+ds,"data":{"content":{"md":""},"files":[{"type":"file","id":self.facts[ds]["id"]}]},
            "meta":None,"write_access":True,"access_grants":grants}

    def call(self, command, data):
        if command=="init":
            for _ in range(18 if self.source else 16):self.trace({"credential_response":"omitted"},actor=None)
            result={"identities":deepcopy(self.identities)}
        elif command in {"summary","close"}:result=self.summary()
        elif command=="create_dataset":
            ds=data["dataset"];self.datasets[ds]={"id":self.state+":dataset:"+ds,"owner":"owner"}
            result=self.trace(self.datasets[ds])
        elif command=="add_exact_fact":
            ds=data["dataset"];self.facts[ds]={"id":self.state+":data:"+ds,"dataset":ds,
                "text":data["text"],"text_sha256":m.sha(data["text"].encode())}
            if not self.source:
                owner_exports=[c["result"]["trace"]["native_raw_body"] for c in self.registry["source"].calls
                    if c["command"]=="read_raw" and c["input"]["actor"]=="owner"]
                if data["text"] not in owner_exports:raise AssertionError("target wrote text absent from actual source API export")
            for _ in range(2 if self.source else 3):self.trace({"id":self.facts[ds]["id"]})
            result=self.trace(data["text"])
        elif command in {"grant","revoke"}:
            pair=(data["recipient"],data["dataset"])
            if command=="grant":self.acl.add(pair)
            else:self.acl.discard(pair)
            if self.source:result=self.trace({"access_grants":self.note(data["dataset"])["access_grants"]})
            else:result=self.trace({"message":"Permission assigned to principal" if command=="grant" else "Permission revoked from principal"})
        elif command=="read_raw":
            if self.source and data["actor"]=="owner" and self.fault=="source_error":result=self.trace({"detail":"source failed"},"owner",500)
            elif self.source and data["actor"]=="owner" and self.fault=="source_changed":result=self.trace("DIFFERENT_SOURCE_CONTENT","owner")
            elif self.allowed(data["actor"],data["dataset"]):result=self.trace(self.facts[data["fact_key"]]["text"],data["actor"])
            else:result=self.trace({"detail":"Forbidden"},data["actor"],403)
        elif command=="list_datasets":
            result=self.trace([d for ds,d in self.datasets.items() if self.allowed(data["actor"],ds)],data["actor"])
        elif command=="list_data":
            ds=data["dataset"]
            if self.allowed(data["actor"],ds):
                result=self.trace(self.note(ds) if self.source else [{"id":self.facts[ds]["id"]}],data["actor"])
            else:result=self.trace({"detail":"Forbidden"},data["actor"],403)
        else:raise AssertionError("unknown fake command")
        self.calls.append({"command":command,"input":deepcopy(data),"result":deepcopy(result)})
        return result
    def terminate(self):pass


class NativeApiHandoffTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.directory=Path(self.tmp.name)
        contract=m.parse(m.CONTRACT.read_bytes())
        self.plan={"facts":contract["facts"],"workers":{a:"fake_"+a for a in m.ARMS},"pythons":{a:"explicit_fake" for a in m.ARMS},
            "native_states":{a:"fake_"+a for a in m.ARMS},"wheel":"fake","legacy":"fake",
            "operator_consent":{"kind":"explicit_research_operator_consent","approved_for_controlled_synthetic_copy":True,
                "native_export_permission_verified":False,"native_share_permission_claimed":False}}

    def fake(self,fault=None,subdir="run"):
        registry={};out=self.directory/subdir;out.mkdir()
        result=m.execute(self.plan,out,input_check=lambda *args,**kwargs:None,
            rpc_factory=lambda *args,**kwargs:FakeNative(*args,registry=registry,fault=fault,**kwargs))
        return result,registry,out

    def test_complete_native_api_protocol_uses_source_bytes_and_preserves_independent_legal_access(self):
        result,registry,out=self.fake()
        self.assertEqual(result["status"],"fake_protocol_completed",result["failure"])
        self.assertEqual(result["instrumentation"]["source"]["physical_http"],91)
        self.assertEqual(result["instrumentation"]["target"]["physical_http"],78)
        self.assertEqual(registry["source"].cap,100);self.assertEqual(registry["target"].cap,90)
        self.assertEqual(result["read_relations_checked"],48);self.assertEqual(result["enumeration_observations"],48)
        self.assertEqual(result["old_packet_replay"],"current_source_revalidated_noop")
        self.assertEqual(registry["target"].acl,{("alice_reader","managed"),("bob_reader","managed")})
        writes=[c for c in registry["target"].calls if c["command"]=="add_exact_fact"]
        self.assertEqual(len(writes),2)
        changes=[c for c in registry["target"].calls if c["command"] in {"grant","revoke"}]
        self.assertEqual(len(changes),4)
        barriers=json.loads((out/"barriers.json").read_bytes())
        self.assertEqual(barriers[-1]["native_acl_changes"],[])
        packet=json.loads((out/"packets.json").read_bytes())[0]
        self.assertFalse(packet["native_export_authority_verified"])
        self.assertFalse(packet["complete_native_policy_exported"])
        self.assertIn({"actor":"alice_reader","object_id":"fact.readonly","available":True},
            [{k:r[k] for k in ("actor","object_id","available")} for r in packet["read_relations"]])

    def test_unknown_acl_is_unverified_before_any_target_is_started(self):
        for fault in ("group","write","unknown_field","unmapped"):
            with self.subTest(fault=fault):
                result,registry,out=self.fake(fault,fault)
                self.assertEqual(result["status"],"unverified_or_incomplete")
                self.assertIsNotNone(result["failure"])
                self.assertNotIn("target",registry)
                self.assertTrue((out/"events.json").is_file())

    def test_source_error_is_not_denial_or_target_fixture_fallback(self):
        result,registry,out=self.fake("source_error")
        self.assertEqual(result["failure"]["code"],"native_auth_or_execution_error")
        self.assertNotIn("target",registry)
        events=json.loads((out/"events.json").read_bytes())
        self.assertEqual(events[-1]["result"]["status"],500)
        self.assertEqual(json.loads((out/"source_snapshots.json").read_bytes()),[])

    def test_changed_source_content_stops_without_target_write_or_fixture_fallback(self):
        result,registry,out=self.fake("source_changed")
        self.assertEqual(result["failure"]["code"],"source_content_changed")
        self.assertNotIn("target",registry)
        self.assertIn("DIFFERENT_SOURCE_CONTENT",(out/"events.json").read_text())

    def small_snapshot(self,readers):
        records=[{"object_id":oid,"source_note_id":"note-"+ds,"source_file_id":"file-"+ds,
            "content_utf8":"API-"+ds,"content_sha256":m.sha(("API-"+ds).encode()),"byte_count":len(("API-"+ds).encode()),
            "owner_raw_native_index":1,"owner_policy_native_index":0} for oid,ds in m.DATASETS.items()]
        return {"source_subjects":{"owner":{"id":"owner"}},"records":records,
            "read_relations":[{"actor":a,"object_id":o,"available":(a,o) in readers} for a in m.SUBJECTS for o in m.DATASETS]}

    def test_old_snapshot_relation_cannot_resurrect_read_and_legitimate_second_fact_is_kept(self):
        initial=self.small_snapshot(m.expected_relations("initial"));current=self.small_snapshot(m.expected_relations("old_packet_replay"))
        packet=m.make_packet(initial,self.plan["operator_consent"]); before=m.canonical(packet)
        desired=m.current_projection(packet,current,self.plan["operator_consent"])
        self.assertEqual(desired,{("alice_reader","fact.managed"),("bob_reader","fact.managed")})
        self.assertEqual(m.canonical(packet),before)
        self.assertTrue(next(r for r in packet["read_relations"] if r["actor"]=="alice_reader" and r["object_id"]=="fact.readonly")["available"])

    def test_unknown_package_fields_or_changed_current_source_are_not_accepted(self):
        initial=self.small_snapshot(m.expected_relations("initial"));packet=m.make_packet(initial,self.plan["operator_consent"])
        bad=deepcopy(packet);bad["export_allowed"]=True
        with self.assertRaises(m.Unverified):m.current_projection(bad,initial,self.plan["operator_consent"])
        changed=deepcopy(initial);changed["records"][0]["content_utf8"]="changed"
        with self.assertRaisesRegex(m.Unverified,"source_content_or_object_changed"):m.current_projection(packet,changed,self.plan["operator_consent"])

    def test_missing_operator_copy_consent_stops_before_any_native_worker(self):
        self.plan["operator_consent"]["approved_for_controlled_synthetic_copy"]=False
        result,registry,_=self.fake()
        self.assertEqual(registry,{})
        self.assertEqual(result["failure"]["code"],"explicit_operator_consent_required")


if __name__=="__main__":unittest.main()
