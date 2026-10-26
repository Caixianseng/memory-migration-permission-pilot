"""NLI contracts with fake classes only; never import/load a real ML runtime."""
from __future__ import annotations
from copy import deepcopy
import hashlib
import types
import unittest
from unittest.mock import patch

from memory_migration_study import nli_candidate as nli
from memory_migration_study.candidate_proposals import propose_candidates
from memory_migration_study.privacy import _digest,_policy


def counts():return {"model_loads":0,"model_load_attempts":0,"classifier_attempts":0,"encoder_attempts":0,
    "classifier_forward_calls":0,"encoder_forward_calls":0,"blocked_forward_entries":0}


class RuntimeContracts(unittest.TestCase):
    def test_default_has_zero_budget_and_does_not_load_or_tokenize(self):
        runtime=nli.PinnedNLIRuntime()
        self.assertEqual(runtime.maximum,0);self.assertIsNone(runtime.model);self.assertIsNone(runtime.tokenizer)
        self.assertEqual(runtime.snapshot_counts(),counts())
        for config in ({"max_forwards":True},{"max_forwards":-1},{"device":"cuda"}):
            with self.assertRaises(ValueError):nli.PinnedNLIRuntime(config)

    def test_two_actual_methods_are_counted_and_warmup_foreign_instance_extra_call_block(self):
        class Encoder:
            def forward(self,value):return value+1
        class Classifier:
            def __init__(self):self.encoder=Encoder()
            def forward(self,value):return self.encoder.forward(value)
        model=Classifier();ledger=counts();original_root=Classifier.forward;original_encoder=Encoder.forward
        with nli.ForwardLedger(Classifier,Encoder,ledger,2) as budget:
            with self.assertRaises(RuntimeError):model.forward(1)
            with self.assertRaises(RuntimeError):model.encoder.forward(1)
            self.assertEqual(ledger["classifier_forward_calls"],0);self.assertEqual(ledger["encoder_forward_calls"],0)
            budget.model=model;budget.encoder=model.encoder;budget.phase="inference"
            with self.assertRaises(RuntimeError):Classifier().forward(1)
            self.assertEqual(model.forward(1),2);self.assertEqual(model.forward(3),4)
            with self.assertRaises(RuntimeError):model.forward(1)
        self.assertIs(Classifier.forward,original_root);self.assertIs(Encoder.forward,original_encoder)
        self.assertEqual(ledger["classifier_forward_calls"],2);self.assertEqual(ledger["encoder_forward_calls"],2)
        self.assertEqual(ledger["blocked_forward_entries"],4)

    def test_full_pair_budget_and_shape_are_checked_without_truncation(self):
        full={"input_ids":list(range(512)),"attention_mask":[1]*512}
        self.assertEqual(nli._tokens(full),512)
        for invalid in ({"input_ids":list(range(513)),"attention_mask":[1]*513},
            {"input_ids":[1,2],"attention_mask":[1]}, {"input_ids":[True],"attention_mask":[1]},
            {"input_ids":[1],"attention_mask":[1],"gold":[0]}):
            with self.assertRaises(ValueError):nli._tokens(invalid)

    def test_actual_frozen_loading_checks_accept_sets_and_verify_buffer(self):
        class Buffer:
            shape=(1,512);dtype="torch.int64";device=types.SimpleNamespace(type="cpu");requires_grad=False
            def tolist(self):return [list(range(512))]
        buffer=Buffer();emb=types.SimpleNamespace(position_ids=buffer,position_biased_input=False,position_embeddings=None,
            _non_persistent_buffers_set={"position_ids"},_buffers={"position_ids":buffer})
        model=types.SimpleNamespace(config=types.SimpleNamespace(position_biased_input=False,max_position_embeddings=512),
            deberta=types.SimpleNamespace(embeddings=emb),state_dict=lambda:{})
        info={"missing_keys":set(),"unexpected_keys":{"deberta.embeddings.position_ids"},"mismatched_keys":frozenset(),"error_msgs":[]}
        result=nli.validate_weight_loading(model,info)
        self.assertTrue(result["accepted"]);self.assertEqual(result["source_container_types"]["missing_keys"],"set")
        wrong=deepcopy(info);wrong["missing_keys"]={"classifier.weight"}
        with self.assertRaises(ValueError):nli.validate_weight_loading(model,wrong)
        emb._non_persistent_buffers_set.clear()
        with self.assertRaises(ValueError):nli.validate_weight_loading(model,info)


class FakeRuntime:
    def __init__(self,states=(),*,maximum=100,oversize=False,root_delta=1,encoder_delta=1,fail=False):
        self.states=list(states);self.maximum=maximum;self.oversize=oversize;self.root_delta=root_delta;self.encoder_delta=encoder_delta;self.fail=fail
        self.counts=counts();self.tokenized=[];self.predictions=[]
    def health(self):return {"runtime_kind":"fake_only","model_id":nli.MODEL_ID,"revision":nli.REVISION,"max_forwards":self.maximum,"device":"cpu","dtype":"float32"}
    def reserved_tokens(self):return ["[CLS]","[SEP]"]
    def tokenize_pair(self,premise,hypothesis):
        self.tokenized.append((premise,hypothesis));data=hashlib.sha256((premise+"\n"+hypothesis).encode()).digest()
        ids=[1,*list(data[:8]),2]+([3]*600 if self.oversize else [])
        return {"input_ids":ids,"attention_mask":[1]*len(ids)}
    def snapshot_counts(self):return deepcopy(self.counts)
    def predict(self,inputs):
        self.predictions.append(deepcopy(inputs));self.counts["classifier_attempts"]+=1;self.counts["encoder_attempts"]+=1
        self.counts["classifier_forward_calls"]+=self.root_delta;self.counts["encoder_forward_calls"]+=self.encoder_delta
        if self.fail:raise RuntimeError("private model diagnostic must not escape")
        state=self.states[len(self.predictions)-1] if len(self.states)>=len(self.predictions) else "U"
        logits={"E":[4.0,0.0,0.0],"C":[0.0,0.0,4.0],"U":[0.0,4.0,0.0]}[state]
        return {"logits":logits,"shape":[1,3],"device":"cpu","dtype":"float32","label2id":deepcopy(nli.LABEL2ID)}


class CandidateContracts(unittest.TestCase):
    def fixture(self,text='Archive entry “Velin Harbor”.',*,categories=("CUSTOMER",),typed=(),query="",registry=()):
        payload={"query":query,"memories":[{"source_id":"hidden_development_filename","text":text}]}
        policy={"version":"hidden_split_policy","protected_categories":list(categories),"instructions":nli.TYPE_INSTRUCTIONS if categories else nli.PUBLIC_INSTRUCTIONS,
            "entity_registry":list(registry)}
        findings=[]
        for quote,category,method in typed:
            start=text.index(quote);findings.append({"source_id":payload["memories"][0]["source_id"],"start":start,"end":start+len(quote),"quote":quote,"category":category,"method":method})
        baseline={"status":"ok","errors":[],"payload_sha256":_digest(payload),"policy_sha256":_digest(_policy(policy)),"local_calls_complete":True,"local_calls":2,"findings":findings}
        return payload,policy,propose_candidates(payload,policy,findings,max_candidates=16),baseline
    def run_case(self,case,runtime,*,enabled=True):
        agent=nli.LocalNLICandidate({"allow_forward":enabled},approved_policies=[case[1]],runtime=runtime)
        p=agent.preflight(*case[:3]);return agent,p,agent.classify(*case[:3],preflight=p)
    def compose(self,case,p,stage,include_new):
        return nli.compose_nli_detection(case[0],case[1],case[3],case[2],stage,approved_policies=[case[1]],preflight=p,include_new=include_new)

    def test_full_source_exact_position_and_hidden_metadata(self):
        case=self.fixture('Full prefix. Entry “Velin Harbor”. Complete suffix.',typed=[("Velin Harbor","CUSTOMER","agent")],query="Question “Orin”.")
        runtime=FakeRuntime();agent=nli.LocalNLICandidate(approved_policies=[case[1]],runtime=runtime);p=agent.preflight(*case[:3])
        self.assertTrue(p["executable"]);self.assertEqual(p["request_count"],len(case[2]["candidates"])*4)
        for premise,hypothesis in runtime.tokenized:
            self.assertNotIn("hidden_",premise+hypothesis);self.assertNotIn("proposed_category",premise+hypothesis)
            self.assertEqual(premise.count("[[TARGET]]"),1)
            self.assertFalse("Question" in premise and "Complete suffix" in premise)
        self.assertEqual(runtime.predictions,[])

    def test_unique_category_protects_unknown_even_value_u_and_field_e(self):
        case=self.fixture();runtime=FakeRuntime(["U","E","U","E"]);_,p,stage=self.run_case(case,runtime)
        self.assertEqual(stage["status"],"typing_only");self.assertEqual(stage["findings"][0]["category"],"CUSTOMER")
        self.assertEqual(stage["decisions"][0]["reason"],"unique_policy_category_entailment")
        self.assertEqual(stage["root_forward_calls"],4);self.assertEqual(stage["encoder_forward_calls"],4)
        self.assertEqual(self.compose(case,p,stage,False)["findings"],[])
        self.assertEqual(self.compose(case,p,stage,True)["status"],"ok")
        self.assertEqual(len(runtime.predictions),4)

    def test_no_forced_category_and_review_does_not_stop_remaining_pairs(self):
        case=self.fixture('Entries “Velin” and “Orin”.');runtime=FakeRuntime(["U"]*4+["E","U","U","E"])
        _,p,stage=self.run_case(case,runtime)
        self.assertEqual(stage["status"],"needs_review");self.assertTrue(stage["processing_complete"])
        self.assertEqual(stage["evaluated_candidates"],2);self.assertEqual(len(runtime.predictions),8)
        self.assertEqual(stage["decisions"][0]["category"],None)
        self.assertEqual(self.compose(case,p,stage,False)["status"],"ok")
        self.assertEqual(self.compose(case,p,stage,True)["status"],"needs_review")

    def test_frozen_decision_conflicts_and_strong_negative_evidence(self):
        allowed=["CUSTOMER","PROJECT"]
        base={"role:value":"U","role:field_label":"U","role:generic_role":"U","category:CUSTOMER":"E","category:PROJECT":"U"}
        self.assertEqual(nli.decide_candidate(None,base,allowed)["decision"],"protect")
        for changed,prior,reason in (({"category:PROJECT":"E"},None,"multiple_category_entailments"),
            ({"role:value":"C"},None,"category_value_contradiction"),({},"PROJECT","typed_category_changed")):
            result=nli.decide_candidate(prior,{**base,**changed},allowed);self.assertEqual(result["reason"],reason);self.assertEqual(result["decision"],"needs_review")
        allc={**base,"category:CUSTOMER":"C","category:PROJECT":"C"}
        self.assertEqual(nli.decide_candidate(None,allc,allowed)["decision"],"nonvalue")
        neg={**base,"category:CUSTOMER":"U","role:value":"C","role:field_label":"E"}
        self.assertEqual(nli.decide_candidate(None,neg,allowed)["decision"],"nonvalue")
        self.assertEqual(nli.decide_candidate(None,{**neg,"role:field_label":"U"},allowed)["decision"],"needs_review")

    def test_softmax_keeps_neutral_and_does_not_normalize_across_hypotheses(self):
        raw={"logits":[3.0,3.0,-10.0],"shape":[1,3],"device":"cpu","dtype":"float32","label2id":nli.LABEL2ID}
        probabilities,status=nli._probabilities(raw);self.assertEqual(status,"U");self.assertLess(probabilities["entailment"],0.51)
        for logits in ([float("nan"),0,0],[True,0,0]):
            with self.assertRaises(ValueError):nli._probabilities({**raw,"logits":logits})

    def test_marker_control_token_and_overflow_block_entire_material_without_forward(self):
        for marker in ("[[TARGET]]","[[/TARGET]]","[CLS]"):
            case=self.fixture('Entry “Velin”. '+marker);runtime=FakeRuntime();_,p,stage=self.run_case(case,runtime)
            self.assertFalse(p["executable"]);self.assertFalse(stage["processing_complete"]);self.assertEqual(runtime.predictions,[])
        case=self.fixture('Entries “Velin” and “Orin”.');runtime=FakeRuntime(oversize=True);_,p,stage=self.run_case(case,runtime)
        self.assertFalse(p["executable"]);self.assertEqual(p["request_count"],8);self.assertEqual(len(runtime.tokenized),8)
        self.assertGreater(p["max_pair_tokens"],512);self.assertEqual(runtime.predictions,[])

    def test_zero_budget_preflight_is_valid_but_prediction_is_not_authorized(self):
        case=self.fixture();runtime=FakeRuntime(maximum=0);_,p,stage=self.run_case(case,runtime)
        self.assertTrue(p["executable"]);self.assertFalse(stage["processing_complete"]);self.assertEqual(runtime.predictions,[])
        self.assertEqual(stage["encoder_forward_calls"],0)

    def test_saved_preflight_recomputes_on_host_without_runtime_or_tokenizer(self):
        case=self.fixture();runtime=FakeRuntime(["E","U","U","E"]);_,p,stage=self.run_case(case,runtime)
        with patch.object(nli,"PinnedNLIRuntime",side_effect=AssertionError("no runtime on host")),patch.object(runtime,"tokenize_pair",side_effect=AssertionError("no retokenize")):
            out=nli.validate_nli_candidate(*case[:3],stage,approved_policies=[case[1]],preflight=p)
            self.assertEqual(out["findings"],stage["findings"])
            self.assertEqual(self.compose(case,p,stage,True)["status"],"ok")
        for mutation in ("logits","counter","token","source","contract"):
            s=deepcopy(stage);pf=deepcopy(p);payload=deepcopy(case[0])
            if mutation=="logits":s["raw_results"][0]["raw_result"]["logits"]=[0,0,4]
            if mutation=="counter":s["raw_results"][0]["classifier_forward_delta"]=True
            if mutation=="token":pf["requests"][0]["inputs"]["input_ids"][0]+=1
            if mutation=="source":payload["memories"][0]["text"]+=" changed"
            if mutation=="contract":pf["contract_sha256"]="0"*64
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):nli.validate_nli_candidate(payload,case[1],case[2],s,approved_policies=[case[1]],preflight=pf)

    def test_hard_and_registry_findings_survive_negative_semantic_predictions(self):
        for quote,category,method,registry in (("p@example.org","EMAIL","rules",()),("Velin","CUSTOMER","registry",({"value":"Velin","category":"CUSTOMER"},))):
            case=self.fixture('Entry “'+quote+'”.',categories=(category,),typed=[(quote,category,method)],registry=registry)
            for finding in case[3]["findings"]:finding.pop("quote",None)  # Production findings need not repeat source text.
            runtime=FakeRuntime(["C"]*20);_,p,stage=self.run_case(case,runtime);result=self.compose(case,p,stage,True)
            text=case[0]["memories"][0]["text"]
            self.assertEqual(result["status"],"ok");self.assertTrue(any(r["category"]==category and text[r["start"]:r["end"]]==quote for r in result["findings"]))
            self.assertTrue(result["nli_candidate"]["retained_immutable"])

    def test_actual_forward_error_or_encoder_mismatch_is_preserved_not_retried(self):
        case=self.fixture()
        for runtime in (FakeRuntime(fail=True),FakeRuntime(root_delta=1,encoder_delta=0),FakeRuntime(root_delta=1,encoder_delta=2)):
            _,p,stage=self.run_case(case,runtime)
            self.assertFalse(stage["processing_complete"]);self.assertEqual(len(runtime.predictions),1)
            result=self.compose(case,p,stage,True);self.assertEqual(result["status"],"needs_review")
            self.assertEqual(result["local_calls"],case[3]["local_calls"]+stage["encoder_forward_calls"])


if __name__=="__main__":unittest.main()
