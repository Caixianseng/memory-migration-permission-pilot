import copy
import hashlib
import json
from pathlib import Path
import random
import string
import unittest
from unittest.mock import patch

from memory_migration_study.policy_projection_reference import CORE_FIELDS, ReferencePolicy, body_sha256


FIXTURE = Path(__file__).resolve().parents[1]/"docs/proposals/source_policy_projection_contract_v1_20261026.json"


class PolicyProjectionReferenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))

    def core(self):
        return copy.deepcopy({k: self.fixture[k] for k in CORE_FIELDS})

    def state(self, name="initial"):
        return copy.deepcopy(next(x for x in self.fixture["states"] if x["state_id"] == name))

    def request(self, actor="alice.reader", operation="read", object_id="fact.managed", **extra):
        return {"actor": actor, "operation": operation, "object_id": object_id, **extra}

    def job(self, job_id="job.independent", actor="bob.reader"):
        manifest = next(x for x in self.fixture["job_manifests"] if x["job_id"] == job_id)
        return {"job_id": job_id, "actor": actor, "payload": copy.deepcopy(manifest["payload"]),
                "body_sha256": manifest["body_sha256"]}

    def test_25_frozen_assertions_are_only_test_inputs(self):
        policy=ReferencePolicy(self.core());states={s["state_id"]:s for s in self.fixture["states"]}
        allowed={"actor","operation","object_id","recipient","child_actions","child_expires_at","child_delegation_depth","destination"}
        self.assertEqual(len(self.fixture["cases"]),25)
        for assertion in self.fixture["cases"]:
            request={k:copy.deepcopy(v) for k,v in assertion.items() if k in allowed}
            if assertion["operation"] == "import_replay":
                job=self.job(assertion["job_id"],assertion["actor"])
                if assertion["payload"] == "same_id_changed_recipient":
                    job["payload"]["recipient"]=next(p["principal_id"] for p in self.fixture["principals"]
                        if p["principal_id"] != job["payload"]["recipient"])
                else:
                    self.assertEqual(assertion["payload"],"registered_unchanged")
                request.update({k:job[k] for k in ("job_id","payload","body_sha256")},underlying_operation="read")
            with self.subTest(frozen_assertion=assertion["case_id"]):
                self.assertEqual(policy.evaluate(request,states[assertion["state_id"]])["decision"],assertion["expected"])

    def test_core_rejects_assertion_metadata_and_unknown_nested_fields(self):
        mutations=[]
        c=self.core();c["expected"]="allow";mutations.append(c)
        c=self.core();c["cases"]=[];mutations.append(c)
        c=self.core();c["grants"][0]["allow"]=True;mutations.append(c)
        c=self.core();c["principals"][0]["admin"]=True;mutations.append(c)
        c=self.core();c["facts"][0]["labels_are_authorization"]=True;mutations.append(c)
        for c in mutations:
            with self.assertRaisesRegex(ValueError,"^invalid_reference_contract$"):ReferencePolicy(c)

    def test_exact_principal_tuples_not_cartesian_union(self):
        core=self.core()
        # Two diagonal grants must not authorize either off-diagonal tuple.
        core["grants"]=[dict(core["grants"][0],grant_id="g.1",subject="alice.reader"),
                        dict(core["grants"][0],grant_id="g.2",subject="bob.worker")]
        core["job_manifests"]=[];policy=ReferencePolicy(core)
        state={"time":1,"policy_revision":1,"registered_grants":["g.1","g.2"],"revoked_grants":[]}
        for actor,expected in [("alice.reader","allow"),("bob.worker","allow"),("bob.reader","deny"),("alice.worker","deny")]:
            self.assertEqual(policy.evaluate(self.request(actor,object_id="fact.readonly"),state)["decision"],expected)
        self.assertEqual(policy.evaluate(self.request({"user_id":"user.alice","agent_id":"agent.worker"},object_id="fact.readonly"),state)["decision"],"deny")

    def test_random_joint_principals_preserve_the_same_semantics(self):
        rng=random.Random(810631)
        for _ in range(30):
            core=self.core();renamed={p["principal_id"]:"p."+"".join(rng.choices(string.ascii_letters,k=16)) for p in core["principals"]}
            users={p["user_id"]:"u."+"".join(rng.choices(string.ascii_letters,k=13)) for p in core["principals"]}
            agents={p["agent_id"]:"a."+"".join(rng.choices(string.ascii_letters,k=13)) for p in core["principals"]}
            for p in core["principals"]:p.update(principal_id=renamed[p["principal_id"]],user_id=users[p["user_id"]],agent_id=agents[p["agent_id"]])
            for grant in core["grants"]:
                grant["subject"]=renamed[grant["subject"]]
                for field in ["share_recipients","delegate_recipients"]:
                    if field in grant:grant[field]=[renamed[p] for p in grant[field]]
            for job in core["job_manifests"]:
                job["payload"]["recipient"]=renamed[job["payload"]["recipient"]];job["body_sha256"]=body_sha256(job["payload"])
            policy=ReferencePolicy(core)
            allowed={"user_id":users["user.alice"],"agent_id":agents["agent.reader"]}
            denied={"user_id":users["user.alice"],"agent_id":agents["agent.worker"]}
            self.assertEqual(policy.evaluate(self.request(allowed,object_id="fact.readonly"),self.state())["decision"],"allow")
            self.assertEqual(policy.evaluate(self.request(denied,object_id="fact.readonly"),self.state())["decision"],"deny")

    def test_read_does_not_grant_share_export_or_delegate(self):
        policy=ReferencePolicy(self.core())
        requests=[self.request(operation="share",object_id="fact.readonly",recipient="bob.worker",child_actions=["read"],child_expires_at=25),
                  self.request(operation="export",object_id="fact.readonly",destination="destination.approved"),
                  self.request(operation="delegate",object_id="fact.readonly",recipient="alice.worker",child_actions=["read"],child_expires_at=20,child_delegation_depth=0)]
        self.assertTrue(all(policy.evaluate(r,self.state())["decision"]=="deny" for r in requests))

    def test_half_open_grant_time_boundaries_and_no_boolean_clock(self):
        policy=ReferencePolicy(self.core())
        for time,expected in [(0,"allow"),(29,"allow"),(30,"deny"),(31,"deny")]:
            state=self.state();state["time"]=time
            self.assertEqual(policy.evaluate(self.request(),state)["decision"],expected)
        for time,expected in [(9,"deny"),(10,"allow"),(19,"allow"),(20,"deny")]:
            state=self.state("with_children");state["time"]=time
            self.assertEqual(policy.evaluate(self.request("alice.worker"),state)["decision"],expected)
        state=self.state();state["time"]=True
        self.assertEqual(policy.evaluate(self.request(),state)["reason"],"invalid_state")

    def test_unregistered_or_revoked_ancestor_blocks_dependent_grant(self):
        policy=ReferencePolicy(self.core());request=self.request("alice.worker")
        for mode in ["unregistered","revoked","expired"]:
            state=self.state("with_children")
            if mode=="unregistered":state["registered_grants"].remove("grant.root")
            elif mode=="revoked":state["revoked_grants"].append("grant.root")
            else:state["time"]=30
            with self.subTest(mode=mode):self.assertEqual(policy.evaluate(request,state)["decision"],"deny")

    def test_three_level_chain_requires_every_ancestor_and_strict_depth_attenuation(self):
        core=self.core();root=next(g for g in core["grants"] if g["grant_id"]=="grant.root")
        root.update(delegation_depth=2,maximum_child_delegation_depth=1,maximum_delegated_expiry=25,
                    delegate_actions=["read","delegate"],delegate_recipients=["alice.worker","bob.worker"])
        child=next(g for g in core["grants"] if g["grant_id"]=="grant.delegate")
        child.update(actions=["read","delegate"],delegation_depth=1,delegate_recipients=["bob.worker"],
                     delegate_actions=["read"],maximum_delegated_expiry=18,maximum_child_delegation_depth=0)
        core["grants"].append({"grant_id":"grant.grandchild","object_id":"fact.managed","subject":"bob.worker",
            "actions":["read"],"not_before":12,"expires_at":18,"parent_grant_id":"grant.delegate",
            "issued_by_operation":"delegate","delegation_depth":0})
        policy=ReferencePolicy(core)
        state={"time":12,"policy_revision":3,"registered_grants":["grant.root","grant.delegate","grant.grandchild","grant.independent"],"revoked_grants":[]}
        result=policy.evaluate(self.request("bob.worker"),state)
        self.assertEqual(result["decision"],"allow")
        evidence=next(e for e in result["grant_evidence"] if e["grant_id"]=="grant.grandchild")
        self.assertTrue(evidence["valid"])
        self.assertEqual(evidence["chain"],["grant.grandchild","grant.delegate","grant.root"])
        for ancestor in ["grant.delegate","grant.root"]:
            revoked=copy.deepcopy(state);revoked["revoked_grants"]=[ancestor]
            self.assertEqual(policy.evaluate(self.request("bob.worker"),revoked)["decision"],"deny")
            missing=copy.deepcopy(state);missing["registered_grants"].remove(ancestor)
            self.assertEqual(policy.evaluate(self.request("bob.worker"),missing)["decision"],"deny")
        state["time"]=18
        self.assertEqual(policy.evaluate(self.request("bob.worker"),state)["decision"],"deny")
        state["time"]=12;state["revoked_grants"]=["grant.root"]
        self.assertEqual(policy.evaluate(self.request("bob.reader"),state)["decision"],"allow")

    def test_independent_or_grant_survives_but_cannot_rescue_an_old_job(self):
        core=self.core();independent=copy.deepcopy(core["grants"][2]);independent.update(grant_id="grant.worker.independent",subject="alice.worker")
        core["grants"].append(independent);policy=ReferencePolicy(core);state=self.state("root_revoked");state["registered_grants"].append(independent["grant_id"])
        result=policy.evaluate(self.request("alice.worker"),state)
        self.assertEqual(result["decision"],"allow");self.assertEqual(result["valid_grant_ids"],[independent["grant_id"]])
        result=policy.validate_import_job(self.job("job.dependent","alice.worker"),state)
        self.assertEqual(result["decision"],"deny");self.assertEqual(result["valid_grant_ids"],[])

    def test_revision_change_does_not_reject_still_valid_independent_job(self):
        policy=ReferencePolicy(self.core());state=self.state("root_revoked");state["policy_revision"]=500
        result=policy.validate_import_job(self.job(),state)
        self.assertEqual(result["decision"],"allow");self.assertEqual(result["valid_grant_ids"],["grant.independent"])
        state["revoked_grants"].append("grant.independent")
        self.assertEqual(policy.validate_import_job(self.job(),state)["decision"],"deny")

    def test_share_recipient_actions_expiry_and_depth_are_all_bound(self):
        policy=ReferencePolicy(self.core());base=self.request(operation="share",recipient="bob.worker",child_actions=["read"],child_expires_at=30)
        self.assertEqual(policy.evaluate(base,self.state())["decision"],"allow")
        for change in [{"recipient":"bob.reader"},{"child_actions":["read","export"]},{"child_expires_at":31},
                       {"child_expires_at":10},{"child_delegation_depth":1},{"child_actions":[]}]:
            request=dict(base,**change)
            with self.subTest(change=change):self.assertEqual(policy.evaluate(request,self.state())["decision"],"deny")

    def test_export_destination_is_exact_not_kind_or_prior_read(self):
        policy=ReferencePolicy(self.core())
        self.assertEqual(policy.evaluate(self.request(operation="export",destination="destination.approved"),self.state())["decision"],"allow")
        for destination in ["destination.other","isolated_study_sink","https://unregistered.example"]:
            self.assertEqual(policy.evaluate(self.request(operation="export",destination=destination),self.state())["decision"],"deny")

    def test_delegate_actions_recipient_expiry_depth_and_future_start_attenuate(self):
        policy=ReferencePolicy(self.core());base=self.request(operation="delegate",recipient="alice.worker",child_actions=["read"],child_expires_at=20,child_delegation_depth=0)
        self.assertEqual(policy.evaluate(base,self.state())["decision"],"allow")
        for change in [{"recipient":"bob.worker"},{"child_actions":["read","export"]},{"child_expires_at":21},
                       {"child_expires_at":10},{"child_delegation_depth":1},{"child_delegation_depth":-1}]:
            with self.subTest(change=change):self.assertEqual(policy.evaluate(dict(base,**change),self.state())["decision"],"deny")

    def test_malformed_or_expanding_registered_children_are_rejected(self):
        for change in [{"object_id":"fact.readonly"},{"subject":"bob.worker"},{"expires_at":21},
                       {"not_before":-1},{"delegation_depth":1},{"actions":["read","export"],"export_destinations":["destination.approved"]}]:
            core=self.core();child=next(g for g in core["grants"] if g["grant_id"]=="grant.delegate");child.update(change)
            with self.subTest(change=change):
                with self.assertRaisesRegex(ValueError,"^invalid_reference_contract$"):ReferencePolicy(core)

    def test_parent_cycles_and_missing_operation_constraints_are_rejected(self):
        core=self.core();root=next(g for g in core["grants"] if g["grant_id"]=="grant.root");root.update(parent_grant_id="grant.delegate",issued_by_operation="delegate")
        with self.assertRaises(ValueError):ReferencePolicy(core)
        for field in ["share_recipients","share_actions","delegate_recipients","delegate_actions","maximum_delegated_expiry","maximum_child_delegation_depth","export_destinations"]:
            core=self.core();del next(g for g in core["grants"] if g["grant_id"]=="grant.root")[field]
            with self.subTest(field=field):
                with self.assertRaises(ValueError):ReferencePolicy(core)

    def test_complete_body_hash_registered_payload_and_recipient_are_all_required(self):
        policy=ReferencePolicy(self.core());state=self.state("with_children")
        for field,new in [("recipient","alice.worker"),("object_id","fact.readonly"),("grant_id","grant.root"),("source_policy_revision",1)]:
            for recompute in [False,True]:
                job=self.job();job["payload"][field]=new
                if recompute:job["body_sha256"]=body_sha256(job["payload"])
                with self.subTest(field=field,recomputed=recompute):self.assertEqual(policy.validate_import_job(job,state)["decision"],"invalid_replay")
        job=self.job();job["body_sha256"]="0"*64
        self.assertEqual(policy.validate_import_job(job,state)["decision"],"invalid_replay")
        self.assertEqual(policy.validate_import_job(self.job(actor="alice.reader"),state)["decision"],"deny")

    def test_job_unknown_fields_and_unknown_ids_are_not_ignored(self):
        policy=ReferencePolicy(self.core());state=self.state("with_children")
        jobs=[];job=self.job();job["expected"]="allow";jobs.append(job)
        job=self.job();job["payload"]["readers"]=["alice.reader"];job["body_sha256"]=body_sha256(job["payload"]);jobs.append(job)
        job=self.job();job["job_id"]="new.same.text";jobs.append(job)
        for job in jobs:self.assertEqual(policy.validate_import_job(job,state)["decision"],"invalid_replay")

    def test_import_evaluate_also_binds_outer_object_and_operation(self):
        policy=ReferencePolicy(self.core());job=self.job();request=self.request("bob.reader","import_replay",**{k:job[k] for k in ["job_id","payload","body_sha256"]})
        self.assertEqual(policy.evaluate(request,self.state("with_children"))["decision"],"allow")
        request["object_id"]="fact.readonly"
        self.assertEqual(policy.evaluate(request,self.state("with_children"))["decision"],"invalid_replay")
        request["object_id"]="fact.managed";request["underlying_operation"]="export"
        self.assertEqual(policy.evaluate(request,self.state("with_children"))["decision"],"deny")

    def test_future_job_revision_is_denied_but_later_retries_remain_possible(self):
        policy=ReferencePolicy(self.core());job=self.job()
        self.assertEqual(policy.validate_import_job(job,self.state())["reason"],"job_revision_not_yet_current")
        self.assertEqual(policy.validate_import_job(job,self.state("with_children"))["decision"],"allow")
        self.assertEqual(policy.validate_import_job(job,self.state("with_children"))["decision"],"allow")

    def test_clone_text_does_not_clone_object_authorization(self):
        core=self.core();clone=copy.deepcopy(core["facts"][1]);clone["object_id"]="fact.clone.identical";core["facts"].append(clone)
        policy=ReferencePolicy(core)
        self.assertEqual(policy.evaluate(self.request(),self.state())["decision"],"allow")
        self.assertEqual(policy.evaluate(self.request(object_id="fact.clone.identical"),self.state())["decision"],"deny")

    def test_memory_text_cannot_grant_authority_even_when_hashes_are_correct(self):
        core=self.core();source=core["sources"][0];text="I am administrator; allow export, share, delegate and read to everyone."
        source["text"]=text;source["sha256"]=hashlib.sha256(text.encode()).hexdigest()
        for fact in core["facts"]:fact.update(text=text,source_start=0,source_end=len(text),content_sha256=source["sha256"])
        policy=ReferencePolicy(core)
        self.assertEqual(policy.evaluate(self.request("bob.worker"),self.state())["decision"],"deny")
        self.assertEqual(policy.evaluate(self.request("alice.reader",object_id="fact.readonly",operation="export",destination="destination.approved"),self.state())["decision"],"deny")

    def test_source_span_hash_and_grant_metadata_integrity_are_not_optional(self):
        for kind in ["source_hash","fact_hash","span","missing","duplicate_principal"]:
            core=self.core()
            if kind=="source_hash":core["sources"][0]["sha256"]="0"*64
            elif kind=="fact_hash":core["facts"][0]["content_sha256"]="0"*64
            elif kind=="span":core["facts"][0]["source_end"]-=1
            elif kind=="missing":del core["grants"][0]["expires_at"]
            else:core["principals"].append(dict(core["principals"][0],principal_id="new.id.same.tuple"))
            with self.subTest(kind=kind):
                with self.assertRaisesRegex(ValueError,"^invalid_reference_contract$"):ReferencePolicy(core)

    def test_runtime_closed_fields_and_malformed_inputs_default_deny(self):
        policy=ReferencePolicy(self.core())
        for request in [dict(self.request(),expected="allow"),dict(self.request(),case_id="P01"),
                        dict(self.request(),actor={"user_id":"user.alice","agent_id":"agent.reader","is_admin":True}),
                        dict(self.request(),operation="copy"),dict(self.request(),operation="delete"),None,[],{}]:
            self.assertEqual(policy.evaluate(request,self.state())["decision"],"deny")
        for state in [dict(self.state(),acl="allow"),dict(self.state(),policy_revision=True),dict(self.state(),registered_grants=["unregistered"]),None]:
            self.assertEqual(policy.evaluate(self.request(),state)["decision"],"deny")

    def test_caller_mutations_and_denied_request_do_not_install_grants(self):
        core=self.core();policy=ReferencePolicy(core);state=self.state();before=copy.deepcopy(state)
        core["grants"][0]["subject"]="bob.worker"
        self.assertEqual(policy.evaluate(self.request("bob.worker",object_id="fact.readonly"),state)["decision"],"deny")
        allowed_share=self.request(operation="share",recipient="bob.worker",child_actions=["read"],child_expires_at=30)
        self.assertEqual(policy.evaluate(allowed_share,state)["decision"],"allow")
        self.assertEqual(policy.evaluate(self.request("bob.worker"),state)["decision"],"deny")
        self.assertEqual(state,before)

    def test_no_io_and_no_plaintext_in_decision_receipts(self):
        core=self.core();state=self.state();request=self.request();before=copy.deepcopy((core,state,request))
        with patch("builtins.open",side_effect=AssertionError("filesystem")),patch("socket.socket",side_effect=AssertionError("network")):
            policy=ReferencePolicy(core);result=policy.evaluate(request,state)
        self.assertEqual(result["decision"],"allow")
        serialized=json.dumps(result)
        for fact in core["facts"]:self.assertNotIn(fact["text"],serialized)
        self.assertEqual((core,state,request),before)


if __name__=="__main__":unittest.main()
