import copy
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from memory_migration_study.policy_projection_gateway import AuthenticatedPrincipal, PolicyProjectionGateway
from memory_migration_study.policy_projection_reference import CORE_FIELDS, body_sha256


FIXTURE = Path(__file__).resolve().parents[1]/"docs/proposals/source_policy_projection_contract_v1_20261026.json"


class PolicyProjectionGatewayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture=json.loads(FIXTURE.read_text(encoding="utf-8"))

    def setUp(self):
        self.core=copy.deepcopy({k:self.fixture[k] for k in CORE_FIELDS})
        self.states={s["state_id"]:copy.deepcopy(s) for s in self.fixture["states"]}
        self.token=object();self.fetched=[];self.written=[]
        self.native={f["object_id"]:f["text"].encode("utf-8") for f in self.core["facts"]}
        self.gateway=self.make()

    def fetch(self,object_id):
        self.fetched.append(object_id)
        return self.native[object_id]

    def sink(self,object_id,data,metadata):
        self.written.append((object_id,data,metadata))
        return True

    def make(self,*,fetch=None,sinks=None):
        return PolicyProjectionGateway(self.core,self.states["initial"],fetch_fact=fetch or self.fetch,
            export_sinks={"destination.approved":self.sink} if sinks is None else sinks,controller_token=self.token)

    def actor(self,principal_id="alice.reader"):
        p=next(p for p in self.core["principals"] if p["principal_id"]==principal_id)
        return AuthenticatedPrincipal(p["user_id"],p["agent_id"])

    def read(self,actor="alice.reader",object_id="fact.managed",gateway=None):
        return (gateway or self.gateway).dispatch(self.actor(actor),{"operation":"read","object_id":object_id})

    def child_body(self,operation="share"):
        if operation=="share":
            return {"operation":"share","object_id":"fact.managed","recipient":"bob.worker",
                    "child_actions":["read"],"child_expires_at":30,"child_grant_id":"grant.share"}
        return {"operation":"delegate","object_id":"fact.managed","recipient":"alice.worker",
                "child_actions":["read"],"child_expires_at":20,"child_delegation_depth":0,"child_grant_id":"grant.delegate"}

    def install_children(self):
        for operation in ["share","delegate"]:
            reply=self.gateway.dispatch(self.actor(),self.child_body(operation))
            self.assertEqual(reply["decision"],"allow")
            self.assertEqual(reply["side_effect"]["status"],"confirmed")
        self.gateway.transition_state(self.states["with_children"],controller_token=self.token)

    def snapshot(self,gateway=None):
        return (gateway or self.gateway).get_state_snapshot(controller_token=self.token)

    def assert_no_fact(self,reply):
        self.assertIsNone(reply["data"])
        self.assertEqual(reply["delivered_fact_ids"],[])
        serialized=json.dumps(reply)
        for f in self.core["facts"]:self.assertNotIn(f["text"],serialized)

    def replay_body(self,job_id):
        job=next(j for j in self.core["job_manifests"] if j["job_id"]==job_id)
        return {"operation":"import_replay","object_id":job["payload"]["object_id"],
                "job_id":job_id,"payload":copy.deepcopy(job["payload"]),"body_sha256":job["body_sha256"]}

    def test_auth_layer_value_is_required_and_body_actor_cannot_impersonate(self):
        body={"operation":"read","object_id":"fact.readonly"}
        for principal in ["alice.reader",{"user_id":"user.alice","agent_id":"agent.reader"},None]:
            reply=self.gateway.dispatch(principal,body)
            self.assertEqual(reply["http_status"],403);self.assert_no_fact(reply)
        reply=self.gateway.dispatch(self.actor("bob.reader"),dict(body,actor="alice.reader"))
        self.assertEqual(reply["http_status"],400);self.assert_no_fact(reply)
        reply=self.gateway.dispatch(self.actor("bob.reader"),body)
        self.assertEqual(reply["decision"],"deny");self.assertEqual(reply["source_decision"],"deny")
        self.assertEqual(self.fetched,[])

    def test_user_agent_pairs_cannot_be_cartesian_combined(self):
        for actor in ["alice.worker","bob.reader","bob.worker"]:
            reply=self.read(actor,object_id="fact.readonly")
            self.assertEqual(reply["decision"],"deny");self.assert_no_fact(reply)
        reply=self.read(object_id="fact.readonly")
        self.assertEqual(reply["data"]["text"],self.native["fact.readonly"].decode())
        self.assertEqual(self.fetched,["fact.readonly"])

    def test_actual_native_exact_bytes_are_required_not_full_source_or_cached_fixture(self):
        self.native["fact.readonly"]=self.core["sources"][0]["text"].encode()
        reply=self.read(object_id="fact.readonly")
        self.assertEqual(reply["http_status"],502);self.assertEqual(reply["decision"],"error")
        self.assertEqual(reply["source_decision"],"allow");self.assertEqual(reply["reason"],"native_fact_integrity_failed")
        self.assert_no_fact(reply)

    def test_backend_null_wrong_types_errors_and_modified_bytes_never_fake_200(self):
        for value in [None,"string is not raw bytes",bytearray(b"x"),b"old-version"]:
            g=self.make(fetch=lambda _:value)
            reply=self.read(gateway=g)
            self.assertEqual(reply["http_status"],502);self.assertEqual(reply["decision"],"error")
            self.assertEqual(reply["source_decision"],"allow");self.assert_no_fact(reply)
        def broken(_):raise RuntimeError("private callback detail should not escape")
        reply=self.read(gateway=self.make(fetch=broken))
        self.assert_no_fact(reply);self.assertNotIn("private callback detail",json.dumps(reply))

    def test_allowed_read_does_not_register_or_enable_share(self):
        reply=self.read(object_id="fact.readonly");self.assertEqual(reply["http_status"],200)
        before=self.snapshot()
        body=self.child_body();body["object_id"]="fact.readonly"
        reply=self.gateway.dispatch(self.actor(),body)
        self.assertEqual(reply["decision"],"deny");self.assert_no_fact(reply)
        self.assertEqual(self.snapshot(),before)

    def test_share_has_real_registry_effect_and_recipient_can_then_read(self):
        self.assertEqual(self.read("bob.worker")["decision"],"deny")
        reply=self.gateway.dispatch(self.actor(),self.child_body())
        self.assertEqual(reply["decision"],"allow");self.assertEqual(reply["side_effect"]["grant_id"],"grant.share")
        self.assertEqual(reply["policy_revision"],1);self.assertEqual(reply["time"],10)
        snapshot=self.snapshot();self.assertIn("grant.share",snapshot["state"]["registered_grants"])
        self.assertEqual(len(snapshot["installed_children"]),1)
        delivered=self.read("bob.worker")
        self.assertEqual(delivered["data"]["text"],self.native["fact.managed"].decode())
        self.assertEqual(self.fetched,["fact.managed"])

    def test_delegate_registry_effect_expires_at_half_open_boundary(self):
        self.assertEqual(self.read("alice.worker")["decision"],"deny")
        reply=self.gateway.dispatch(self.actor(),self.child_body("delegate"))
        self.assertEqual(reply["decision"],"allow")
        self.assertEqual(self.read("alice.worker")["decision"],"allow")
        state=self.snapshot()["state"];state["time"]=20
        self.gateway.transition_state(state,controller_token=self.token)
        reply=self.read("alice.worker");self.assertEqual(reply["decision"],"deny");self.assert_no_fact(reply)

    def test_child_id_does_not_create_an_arbitrary_or_mismatched_grant(self):
        for change in [{"child_grant_id":"invented"},{"child_grant_id":"grant.delegate"},
                       {"child_grant_id":"grant.root"},{"child_actions":["read","export"]},
                       {"child_expires_at":29},{"recipient":"bob.reader"},{"child_delegation_depth":1}]:
            body=dict(self.child_body(),**change)
            reply=self.gateway.dispatch(self.actor(),body)
            self.assertEqual(reply["decision"],"deny");self.assert_no_fact(reply)
            self.assertEqual(self.snapshot()["installed_children"],[])
        self.assertEqual(self.fetched,[])

    def test_repeat_registration_is_idempotent_and_cannot_unrevoke_child(self):
        body=self.child_body()
        self.assertEqual(self.gateway.dispatch(self.actor(),body)["decision"],"allow")
        repeated=self.gateway.dispatch(self.actor(),body)
        self.assertTrue(repeated["side_effect"]["already_registered"])
        self.assertEqual(len(self.snapshot()["installed_children"]),1)
        state=self.snapshot()["state"];state.update(policy_revision=2,revoked_grants=["grant.share"])
        self.gateway.transition_state(state,controller_token=self.token)
        self.assertEqual(self.gateway.dispatch(self.actor(),body)["decision"],"deny")
        self.assertEqual(self.read("bob.worker")["decision"],"deny")

    def test_controller_cannot_prematurely_install_children_or_erase_operations(self):
        with self.assertRaisesRegex(ValueError,"invalid_or_rollback_state_transition"):
            self.gateway.transition_state(self.states["with_children"],controller_token=self.token)
        self.assertNotIn("grant.share",self.snapshot()["state"]["registered_grants"])
        self.install_children()
        changed=copy.deepcopy(self.states["with_children"]);changed["registered_grants"].remove("grant.share")
        with self.assertRaises(ValueError):self.gateway.transition_state(changed,controller_token=self.token)
        with self.assertRaises(ValueError):
            PolicyProjectionGateway(self.core,self.states["with_children"],fetch_fact=self.fetch,controller_token=self.token)

    def test_controller_only_snapshots_transitions_and_defensive_copies(self):
        for method,args in [(self.gateway.get_state_snapshot,()),(self.gateway.transition_state,(self.states["initial"],))]:
            with self.assertRaisesRegex(PermissionError,"^controller_required$"):method(*args,controller_token=object())
        snapshot=self.snapshot();snapshot["state"]["revoked_grants"].append("grant.root")
        self.assertEqual(self.snapshot()["state"]["revoked_grants"],[])
        body={"operation":"read","object_id":"fact.managed","state":self.states["root_revoked"]}
        reply=self.gateway.dispatch(self.actor(),body);self.assertEqual(reply["http_status"],400);self.assert_no_fact(reply)

    def test_time_revision_revocation_rollback_and_unknown_state_fields_rejected(self):
        state=self.snapshot()["state"];state.update(time=14,policy_revision=2,revoked_grants=["grant.root"])
        self.gateway.transition_state(state,controller_token=self.token)
        for change in [{"time":13},{"policy_revision":1},{"revoked_grants":[]},{"owner":"admin"},{"time":True}]:
            changed=dict(state,**change)
            with self.subTest(change=change):
                with self.assertRaises(ValueError):self.gateway.transition_state(changed,controller_token=self.token)
        changed=copy.deepcopy(state);changed.update(revoked_grants=["grant.root","grant.independent"])
        with self.assertRaises(ValueError):self.gateway.transition_state(changed,controller_token=self.token)
        self.assertEqual(self.snapshot()["state"],state)

    def test_exact_snapshot_forks_preserve_effects_without_turning_back_any_instance_clock(self):
        self.install_children();snapshot=self.snapshot()
        expired=PolicyProjectionGateway.from_snapshot(self.core,snapshot,fetch_fact=self.fetch,controller_token=self.token)
        revoked=PolicyProjectionGateway.from_snapshot(self.core,snapshot,fetch_fact=self.fetch,controller_token=self.token)
        self.assertEqual(expired.get_state_snapshot(controller_token=self.token),snapshot)
        self.assertEqual(revoked.get_state_snapshot(controller_token=self.token),snapshot)
        expired.transition_state(self.states["delegation_expired"],controller_token=self.token)
        revoked.transition_state(self.states["root_revoked"],controller_token=self.token)
        self.assertEqual(self.read("alice.worker",gateway=expired)["decision"],"deny")
        self.assertEqual(self.read("alice.worker",gateway=revoked)["decision"],"deny")
        self.assertEqual(self.read("bob.worker",gateway=revoked)["decision"],"deny")
        self.assertEqual(self.read("bob.reader",gateway=revoked)["decision"],"allow")
        self.assertEqual(self.read("alice.worker")["decision"],"allow")
        with self.assertRaises(ValueError):expired.transition_state(self.states["root_revoked"],controller_token=self.token)

    def test_snapshot_checksum_cannot_replace_missing_registration_provenance(self):
        self.install_children();snapshot=self.snapshot()
        mutations=[]
        s=copy.deepcopy(snapshot);s["state"]["time"]=100;mutations.append(s)
        s=copy.deepcopy(snapshot);s["installed_children"]=[];s["snapshot_sha256"]=body_sha256({k:v for k,v in s.items() if k!="snapshot_sha256"});mutations.append(s)
        s=copy.deepcopy(snapshot);s["installed_children"][0]["request"]["child_expires_at"]=25;s["snapshot_sha256"]=body_sha256({k:v for k,v in s.items() if k!="snapshot_sha256"});mutations.append(s)
        s=copy.deepcopy(snapshot);s["credential"]="not a supported field";mutations.append(s)
        for s in mutations:
            with self.assertRaisesRegex(ValueError,"^invalid_gateway_snapshot$"):
                PolicyProjectionGateway.from_snapshot(self.core,s,fetch_fact=self.fetch,controller_token=self.token)
        raw=json.dumps(snapshot)
        for fact in self.core["facts"]:self.assertNotIn(fact["text"],raw)

    def test_snapshot_cannot_restore_a_state_earlier_than_registered_actions(self):
        self.install_children();snapshot=self.snapshot()
        snapshot["state"]["time"]=9
        snapshot["snapshot_sha256"]=body_sha256({k:v for k,v in snapshot.items() if k!="snapshot_sha256"})
        with self.assertRaisesRegex(ValueError,"^invalid_gateway_snapshot$"):
            PolicyProjectionGateway.from_snapshot(self.core,snapshot,fetch_fact=self.fetch,controller_token=self.token)

    def test_managed_export_really_writes_only_controlled_sink_not_caller_data(self):
        reply=self.gateway.dispatch(self.actor(),{"operation":"export","object_id":"fact.managed","destination":"destination.approved"})
        self.assertEqual(reply["http_status"],200);self.assertEqual(reply["side_effect"]["status"],"confirmed")
        self.assert_no_fact(reply);self.assertEqual(len(self.written),1)
        object_id,data,metadata=self.written[0]
        self.assertEqual((object_id,data),("fact.managed",self.native["fact.managed"]))
        self.assertEqual(metadata["principal"],{"user_id":"user.alice","agent_id":"agent.reader"})
        self.assertEqual(metadata["content_sha256"],hashlib.sha256(data).hexdigest())

    def test_denied_destination_never_fetches_or_forwards_bytes(self):
        for destination in ["destination.other","https://caller-chosen.example"]:
            reply=self.gateway.dispatch(self.actor(),{"operation":"export","object_id":"fact.managed","destination":destination})
            self.assertEqual(reply["decision"],"deny");self.assert_no_fact(reply)
        self.assertEqual(self.fetched,[]);self.assertEqual(self.written,[])

    def test_sink_null_arbitrary_response_and_exception_are_errors_not_denials_or_success(self):
        for ack in [None,False,{"ok":True,"credential":"secret callback data"}]:
            gateway=self.make(sinks={"destination.approved":lambda *args:ack})
            reply=gateway.dispatch(self.actor(),{"operation":"export","object_id":"fact.managed","destination":"destination.approved"})
            self.assertEqual(reply["http_status"],502);self.assertEqual(reply["decision"],"error")
            self.assertEqual(reply["source_decision"],"allow");self.assertEqual(reply["side_effect"]["status"],"unverified")
            self.assert_no_fact(reply);self.assertNotIn("secret callback data",json.dumps(reply))
        def broken(*_):raise RuntimeError("secret sink credentials")
        reply=self.make(sinks={"destination.approved":broken}).dispatch(self.actor(),{"operation":"export","object_id":"fact.managed","destination":"destination.approved"})
        self.assertEqual(reply["decision"],"error");self.assertNotIn("secret sink credentials",json.dumps(reply))
        missing=self.make(sinks={}).dispatch(self.actor(),{"operation":"export","object_id":"fact.managed","destination":"destination.approved"})
        self.assertEqual(missing["decision"],"error");self.assertEqual(missing["side_effect"]["status"],"not_attempted")

    def test_current_authorization_rechecked_after_native_fetch_before_delivery(self):
        holder={}
        def fetch(object_id):
            state=holder["gateway"].get_state_snapshot(controller_token=self.token)["state"]
            state.update(policy_revision=2,revoked_grants=["grant.root"])
            holder["gateway"].transition_state(state,controller_token=self.token)
            return self.native[object_id]
        holder["gateway"]=self.make(fetch=fetch)
        reply=self.read(gateway=holder["gateway"])
        self.assertEqual(reply["http_status"],403);self.assertEqual(reply["source_decision"],"deny")
        self.assert_no_fact(reply);self.assertEqual(reply["policy_revision"],2)

    def test_new_state_expiry_and_changed_native_fact_cannot_reuse_old_allow(self):
        self.assertEqual(self.read()["decision"],"allow")
        self.native["fact.managed"]=b"rollback or newly modified fact bytes"
        state=self.snapshot()["state"];state.update(time=11,policy_revision=2)
        self.gateway.transition_state(state,controller_token=self.token)
        reply=self.read();self.assertEqual(reply["decision"],"error");self.assert_no_fact(reply)
        state["time"]=30;self.gateway.transition_state(state,controller_token=self.token)
        count=len(self.fetched);reply=self.read()
        self.assertEqual(reply["decision"],"deny");self.assert_no_fact(reply);self.assertEqual(len(self.fetched),count)

    def test_replay_keeps_exact_grant_dependency_and_independent_job_survives(self):
        self.install_children();self.gateway.transition_state(self.states["root_revoked"],controller_token=self.token)
        bad=self.gateway.dispatch(self.actor("alice.worker"),self.replay_body("job.dependent"))
        self.assertEqual(bad["decision"],"deny");self.assert_no_fact(bad);self.assertEqual(self.fetched,[])
        good=self.gateway.dispatch(self.actor("bob.reader"),self.replay_body("job.independent"))
        self.assertEqual(good["decision"],"allow");self.assertEqual(good["delivered_fact_ids"],["fact.managed"])

    def test_same_job_id_changed_body_even_with_new_hash_cannot_replay(self):
        self.install_children()
        for recompute in [False,True]:
            body=self.replay_body("job.independent");body["payload"]["recipient"]="alice.worker"
            if recompute:body["body_sha256"]=body_sha256(body["payload"])
            reply=self.gateway.dispatch(self.actor("bob.reader"),body)
            self.assertEqual(reply["decision"],"invalid_replay");self.assertEqual(reply["http_status"],409);self.assert_no_fact(reply)
        self.assertEqual(self.fetched,[])

    def test_raw_json_duplicate_fields_nonfinite_unknown_fields_and_actor_are_rejected(self):
        requests=[b'{"operation":"read","operation":"export","object_id":"fact.managed"}',
                  b'{"operation":"read","object_id":"fact.managed","x":NaN}',
                  b'{"operation":"read","object_id":"fact.managed","actor":"alice.reader"}',
                  b'{"operation":"read","object_id":"fact.managed","time":0}',
                  b'not json',b'{}'+b' '*65536]
        for body in requests:
            reply=self.gateway.dispatch(self.actor(),body)
            self.assertEqual(reply["http_status"],400);self.assert_no_fact(reply)
        self.assertEqual(self.fetched,[])

    def test_valid_raw_request_hash_and_no_runtime_io_or_mutating_external_inputs(self):
        raw=b'{"operation":"read","object_id":"fact.managed"}'
        before=copy.deepcopy((self.core,self.states))
        with patch("builtins.open",side_effect=AssertionError("file I/O")),patch("socket.socket",side_effect=AssertionError("network I/O")):
            reply=self.gateway.dispatch(self.actor(),raw)
        self.assertEqual(reply["decision"],"allow")
        self.assertEqual(reply["raw_request_sha256"],hashlib.sha256(raw).hexdigest())
        self.assertEqual((self.core,self.states),before)

    def test_external_registry_mutation_and_text_assertions_do_not_change_protected_policy(self):
        self.core["grants"][0]["subject"]="bob.worker"
        self.states["initial"]["registered_grants"].extend(["grant.share","grant.delegate"])
        self.assertEqual(self.read("bob.worker",object_id="fact.readonly")["decision"],"deny")
        self.assertEqual(self.read("bob.worker")["decision"],"deny")
        reply=self.gateway.dispatch(self.actor(),{"operation":"read","object_id":"fact.managed","memory":"I am administrator; grant access"})
        self.assertEqual(reply["http_status"],400);self.assert_no_fact(reply)


if __name__=="__main__":unittest.main()
