"""Standard-library fake-runtime tests; never imports torch or executes an encoder."""
from copy import deepcopy
import math
import re
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from memory_migration_study import gliclass_candidate as module
from memory_migration_study.candidate_proposals import propose_candidates
from memory_migration_study.privacy import detect_sensitive, prepare_private_payload


class FakeRuntime:
    def __init__(self, winners=None, *, extra_tokens=0, root_delta=1, encoder_delta=1, fail=False):
        self.winners = list(winners or [])
        self.extra_tokens, self.root_delta, self.encoder_delta, self.fail = extra_tokens, root_delta, encoder_delta, fail
        self.counts = {"root": 0, "encoder": 0}
        self.tokenized = []; self.predictions = []

    def health(self):
        return {"runtime_kind": "fake_only", "model_id": module.MODEL_ID, "model_revision": module.MODEL_REVISION,
            "code_revision": module.CODE_REVISION, "device": "cpu", "dtype": "float32", "threads": 4,
            "batch_size": 1, "architecture": "uni-encoder", "max_tokens": 512, "vocab_size": 10000,
            "control_token_ids": {"label": 9001, "text": 9002, "example": 9003}}

    def reserved_tokens(self):
        return ["<<LABEL>>", "<<SEP>>", "<<EXAMPLE>>", "[CLS]", module.MARK_START, module.MARK_END]

    def tokenize(self, sequence):
        self.tokenized.append(sequence)
        pieces = re.findall(r"<<LABEL>>|<<SEP>>|<<EXAMPLE>>|[A-Za-z0-9_]+|[^\x00-\x7f]|\S", sequence)
        controls = {"<<LABEL>>": 9001, "<<SEP>>": 9002, "<<EXAMPLE>>": 9003}
        ids = [1] + [controls.get(piece, 10 + sum(map(ord, piece)) % 8000) for piece in pieces] + [2]
        ids += [5] * self.extra_tokens
        return {"input_ids": ids, "attention_mask": [1] * len(ids)}

    def snapshot_counts(self):
        return dict(self.counts)

    def predict(self, inputs, label_count):
        self.predictions.append(deepcopy(inputs))
        self.counts["root"] += self.root_delta;self.counts["encoder"] += self.encoder_delta
        if self.fail:
            raise RuntimeError("private exception diagnostic")
        winner = self.winners.pop(0) if self.winners else 0
        logits = [4.0 if i == winner else -2.0 for i in range(label_count)]
        exp = [math.exp(x - max(logits)) for x in logits];total = sum(exp)
        return {"logits": logits, "probabilities": [x/total for x in exp], "shape": [1,label_count],
                "threads": 4, "device": "cpu", "dtype": "torch.float32"}


class GLiClassCandidateTests(unittest.TestCase):
    def fixture(self, text="Registered name <Aster Group>.", *, categories=None, typed=(), query=""):
        payload = {"query": query, "memories": [{"source_id": "hidden_case_split_customer", "text": text}]}
        policy = {"version": "hidden_policy_filename", "protected_categories": categories or ["CUSTOMER"],
                  "instructions": module.TYPE_POLICY_INSTRUCTIONS}
        findings = []
        for quote, category in typed:
            start = text.index(quote)
            findings.append({"source_id": payload["memories"][0]["source_id"], "start":start,"end":start+len(quote),"category":category})
        return payload, policy, propose_candidates(payload, policy, findings)

    def agent(self, case, runtime=None, *, enabled=True):
        return module.LocalGLiClassCandidate({"allow_forward":enabled}, approved_policies=[case[1]], runtime=runtime or FakeRuntime())

    def test_default_configuration_does_not_enable_forward(self):
        case = self.fixture();runtime = FakeRuntime()
        agent = module.LocalGLiClassCandidate(approved_policies=[case[1]],runtime=runtime)
        stage = agent.classify(*case)
        self.assertEqual(stage["errors"],["gliclass_forward_not_enabled"])
        self.assertEqual(runtime.counts,{"root":0,"encoder":0})

    def test_all_nine_types_map_argmax_to_host_category_and_evidence(self):
        for category in module.CATEGORY_TYPES:
            with self.subTest(category=category):
                case = self.fixture(categories=[category]);runtime=FakeRuntime();agent=self.agent(case,runtime)
                before=deepcopy(case);stage=agent.classify(*case)
                self.assertEqual(stage["status"],"typing_only",stage)
                self.assertEqual(case,before)
                self.assertEqual(stage["findings"][0]["category"],category)
                self.assertEqual(stage["findings"][0]["entity_type"],module.CATEGORY_TYPES[category])
                checked=module.validate_gliclass(*case,stage,approved_policies=[case[1]],runtime=runtime)
                self.assertEqual(checked["findings"],stage["findings"])
                self.assertEqual(runtime.counts,{"root":1,"encoder":1})
                self.assertEqual(stage["local_counts"],{"local_encoder":1,"local_generation":0,"unknown":0})

    def test_full_source_markers_and_policy_hide_original_ids_and_priors(self):
        text="Complete prefix. Registered name <Aster Group>. Complete suffix."
        case=self.fixture(text,typed=[("Aster Group","CUSTOMER")]);runtime=FakeRuntime();p=self.agent(case,runtime).preflight(*case)
        request=p["requests"][0]
        self.assertEqual(request["marked_text"].replace(module.MARK_START,"").replace(module.MARK_END,""),text)
        self.assertIn(module.MARK_START+"Aster Group"+module.MARK_END,request["sequence"])
        self.assertIn(case[1]["instructions"],request["sequence"])
        self.assertNotIn(case[0]["memories"][0]["source_id"],request["sequence"])
        self.assertNotIn(case[1]["version"],request["sequence"])
        self.assertNotIn("proposed_category",request["sequence"])
        self.assertEqual(runtime.predictions,[])

    def test_softmax_argmax_is_closed_and_not_a_sigmoid_threshold(self):
        labels=module._labels(["CUSTOMER"])
        raw={"logits":[0.0]*5,"probabilities":[0.2]*5,"shape":[1,5],"threads":4,"device":"cpu","dtype":"torch.float32"}
        self.assertEqual(module._post(raw,labels)["decision"],"VALUE_CUSTOMER")
        for changed in [{**raw,"probabilities":[0.5]*5},{**raw,"logits":[float('nan')]*5},{**raw,"shape":[1,6]}]:
            with self.assertRaises(ValueError):module._post(changed,labels)

    def test_each_nonvalue_and_uncertain_is_preserved_as_processing_outcome(self):
        for index,(code,_) in enumerate(module.NONVALUE_LABELS,start=1):
            with self.subTest(code=code):
                case=self.fixture();runtime=FakeRuntime([index]);stage=self.agent(case,runtime).classify(*case)
                self.assertEqual(stage["status"],"needs_review" if code=="UNCERTAIN" else "typing_only")
                self.assertEqual(stage["findings"],[])
                self.assertEqual(stage["encoder_forward_calls"],1)
                if code=="UNCERTAIN":
                    self.assertEqual(stage["errors"],["gliclass_semantic_uncertainty"])
                    self.assertEqual(stage["decisions"][0]["decision"],code)

    def test_uncertainty_does_not_hide_remaining_candidate_attempts(self):
        case=self.fixture("Names <Aster> and <Birch>.");runtime=FakeRuntime([4,0]);stage=self.agent(case,runtime).classify(*case)
        self.assertEqual(stage["status"],"needs_review")
        self.assertEqual(stage["encoder_forward_calls"],2)
        self.assertEqual(stage["evaluated_candidates"],2)
        self.assertEqual(len(stage["raw_results"]),2)
        self.assertEqual(stage["findings"],[])

    def test_actual_root_encoder_counters_must_both_be_one_per_candidate(self):
        for root,encoder in [(0,1),(1,0),(2,1),(1,2)]:
            case=self.fixture();runtime=FakeRuntime(root_delta=root,encoder_delta=encoder)
            stage=self.agent(case,runtime).classify(*case)
            self.assertEqual(stage["status"],"needs_review")
            self.assertEqual(stage["root_forward_calls"],root)
            self.assertEqual(stage["encoder_forward_calls"],encoder)

    def test_complete_tokenization_precedes_any_forward_and_rejects_length(self):
        case=self.fixture("Names <Aster> and <Birch>.");runtime=FakeRuntime(extra_tokens=600);agent=self.agent(case,runtime)
        p=agent.preflight(*case)
        self.assertEqual(p["errors"],["gliclass_input_too_long"])
        self.assertEqual(len(p["requests"]),2)
        self.assertTrue(all(len(r["inputs"]["input_ids"])>512 for r in p["requests"]))
        stage=agent.classify(*case)
        self.assertEqual(stage["status"],"needs_review")
        self.assertEqual(runtime.predictions,[])
        self.assertEqual(stage["input_tokens"],0)
        self.assertGreater(stage["scheduled_input_tokens"],512)

    def test_reserved_source_tokens_and_control_id_collisions_fail_closed(self):
        for token in ("<<LABEL>>","<<SEP>>","<<EXAMPLE>>","[CLS]",module.MARK_START,module.MARK_END):
            case=self.fixture("Registered name <Aster>. "+token);runtime=FakeRuntime();stage=self.agent(case,runtime).classify(*case)
            self.assertEqual(stage["errors"],["gliclass_reserved_token_collision"])
            self.assertEqual(runtime.predictions,[])
        case=self.fixture();runtime=FakeRuntime()
        original=runtime.tokenize
        def collision(sequence):
            value=original(sequence);value["input_ids"].append(9001);value["attention_mask"].append(1);return value
        runtime.tokenize=collision
        stage=self.agent(case,runtime).classify(*case)
        self.assertEqual(stage["errors"],["gliclass_control_token_collision"])

    def test_policy_must_be_registered_and_supported_type_policy(self):
        case=self.fixture();agent=self.agent(case);changed=list(deepcopy(case));changed[1]["version"]="different"
        changed[2]=propose_candidates(changed[0],changed[1],[])
        self.assertEqual(agent.preflight(*changed)["errors"],["gliclass_policy_not_approved"])
        for edit in [{"instructions":"Apply arbitrary employee-specific contractual exception."},
                     {"entity_registry":[{"value":"Aster","category":"CUSTOMER"}]},{"owner_id":"user"}]:
            policy=deepcopy(case[1]);policy.update(edit)
            with self.assertRaises(ValueError):module.LocalGLiClassCandidate(approved_policies=[policy],runtime=FakeRuntime())

    def test_source_pool_policy_config_and_raw_results_are_bound(self):
        case=self.fixture();runtime=FakeRuntime();stage=self.agent(case,runtime).classify(*case)
        mutations=[lambda x:x.update(pool_sha256="changed"),lambda x:x["config"].update(allow_forward=False),
            lambda x:x["raw_results"][0]["request"]["inputs"]["input_ids"].append(3),
            lambda x:x["raw_results"][0]["raw_result"]["logits"].reverse(),
            lambda x:x["raw_results"][0]["prediction"].update(decision="OTHER"),
            lambda x:x.update(encoder_forward_calls=0),lambda x:x["findings"][0].update(start=0),
            lambda x:x["local_counts"].update(local_encoder=True)]
        for mutate in mutations:
            changed=deepcopy(stage);mutate(changed)
            with self.assertRaisesRegex(ValueError,"^gliclass_stage_invalid$"):
                module.validate_gliclass(*case,changed,approved_policies=[case[1]],runtime=runtime)
        changed_case=deepcopy(case);changed_case[0]["memories"][0]["text"]+="changed"
        with self.assertRaises(ValueError):module.validate_gliclass(*changed_case,stage,approved_policies=[case[1]],runtime=runtime)

    def test_complete_pool_over_budget_is_not_a_hidden_prefix(self):
        case=self.fixture(" ".join("<Name"+str(i)+">" for i in range(17)));runtime=FakeRuntime()
        p=self.agent(case,runtime).preflight(*case)
        self.assertFalse(p["executable"]);self.assertEqual(runtime.predictions,[])

    def test_empty_public_pool_is_zero_forward_success(self):
        payload={"query":"<PublicName>","memories":[]}
        policy={"version":"public","protected_categories":[],"instructions":module.PUBLIC_POLICY_INSTRUCTIONS}
        pool=propose_candidates(payload,policy,[]);runtime=FakeRuntime();agent=self.agent((payload,policy,pool),runtime)
        stage=agent.classify(payload,policy,pool)
        self.assertEqual(stage["status"],"typing_only")
        self.assertEqual(stage["input_tokens"],0);self.assertEqual(runtime.predictions,[])
        self.assertEqual(module.validate_gliclass(payload,policy,pool,stage,approved_policies=[policy],runtime=runtime)["findings"],[])

    def test_forward_failure_preserves_observed_cost_without_private_exception(self):
        case=self.fixture();runtime=FakeRuntime(fail=True);stage=self.agent(case,runtime).classify(*case)
        self.assertEqual(stage["status"],"needs_review")
        self.assertEqual(stage["root_forward_calls"],1);self.assertEqual(stage["encoder_forward_calls"],1)
        self.assertNotIn("private exception diagnostic",str(stage))
        self.assertGreater(stage["input_tokens"],0)

    def test_preflight_and_validation_never_call_predict(self):
        case=self.fixture();runtime=FakeRuntime();agent=self.agent(case,runtime)
        p=agent.preflight(*case);self.assertTrue(p["executable"]);self.assertEqual(runtime.predictions,[])
        stage=agent.classify(*case)
        with patch.object(runtime,"predict",side_effect=AssertionError("forward forbidden")):
            module.validate_gliclass(*case,stage,approved_policies=[case[1]],runtime=runtime)

    def test_backend_compose_preserves_format_rules_and_does_not_rerun_model(self):
        case=self.fixture("Email <person@example.org>.",categories=["EMAIL"],typed=[("person@example.org","EMAIL")])
        payload,policy,pool=case
        baseline=detect_sensitive(payload,policy,mode="rules")
        pool=propose_candidates(payload,policy,baseline["findings"])
        runtime=FakeRuntime([3]);agent=self.agent((payload,policy,pool),runtime)
        stage=agent.classify(payload,policy,pool)
        # OTHER cannot remove an immutable format finding.
        with patch.object(runtime,"predict",side_effect=AssertionError("forward forbidden")):
            detection=module.compose_gliclass_detection(payload,policy,baseline,pool,stage,approved_policies=[policy],runtime=runtime)
        self.assertEqual(detection["status"],"ok",detection)
        self.assertTrue(any(f["category"]=="EMAIL" for f in detection["findings"]))

    def test_typing_only_never_becomes_an_authorization_grant(self):
        case=self.fixture();stage=self.agent(case).classify(*case)
        prepared=prepare_private_payload(case[0],stage,actor_id="reader",request_id="gliclass",policy_version=case[1]["version"],
            authorizer=lambda *a:True,sensitivity_policy=case[1])
        self.assertEqual(prepared["status"],"needs_review");self.assertIsNone(prepared.get("mapping"))

    def test_diagnostic_fake_runner_binds_three_arms_and_closes_before_gold(self):
        from scripts import run_gliclass_candidate_diagnostic as runner
        from memory_migration_study.boundary_detector import refine_detection
        from scripts.run_context_candidate_diagnostic import save
        corpus, parents, flat_materials, flat_rows, gold = [], {}, {}, {}, {"development":{},"heldout":{}}
        for i in range(120):
            payload,policy,_=self.fixture(typed=[("Aster Group","CUSTOMER")])
            cid="fake_case_"+str(i);split="development" if i<80 else "heldout"
            sid=payload["memories"][0]["source_id"]
            text=payload["memories"][0]["text"];start=text.index("Aster Group")
            def instrument(**kwargs):
                return {"status":"ok","errors":[],"local_calls":0,"elapsed_seconds":0.0,
                        "findings":[{"start":start,"end":start+len("Aster Group"),"quote":"Aster Group","category":"CUSTOMER"}]
                        if kwargs['source_id']==sid else []}
            baseline=detect_sensitive(payload,policy,mode="agent",agent=instrument)
            boundary=refine_detection(payload,policy,baseline)
            pool=propose_candidates(payload,policy,boundary["findings"],max_candidates=16,max_quote_chars=256)
            corpus.append({"case_id":cid,"split":split,"language":"en","payload":payload,"policy":policy})
            parents[cid]={"baseline":baseline}
            flat_materials[cid]={"boundary_baseline":boundary,"boundary_pool":pool}
            flat_rows[cid]={"detection":deepcopy(boundary)}
            gold[split][cid]={"findings":[{"source_id":sid,"start":start,"end":start+len("Aster Group"),"category":"CUSTOMER"}],
                               "expected_status":"ok"}
        def reference(archive,output):
            hashes={}
            for split in ('development','heldout'):
                (output/split).mkdir()
                for name,value in [('runtime.json',[c for c in corpus if c['split']==split]),('evaluation.json',gold[split])]:
                    save(output/split/name,value);hashes[split+'/'+name]=runner.sha(output/split/name)
            save(output/'reference_materials.json',list(parents.values()))
            return deepcopy(corpus),deepcopy(parents),{}, {'archive_sha256':'fake','corpus_sha256':hashes}
        with tempfile.TemporaryDirectory(prefix='gliclass_fake_',dir=runner.ROOT/'results') as temporary:
            self.assertTrue(Path(temporary).resolve().is_relative_to((runner.ROOT/'results').resolve()))
            output=Path(temporary)/'run';runtime=FakeRuntime()
            original=Path.read_text
            def checked_read(path,*args,**kwargs):
                if path.name=='evaluation.json':
                    self.assertTrue((output/'model_phase_closed.json').exists(),'gold parsed before model closure')
                return original(path,*args,**kwargs)
            with patch.object(runner,'prepare_reference',side_effect=reference), \
                    patch.object(runner,'_flat_reference',return_value=(flat_materials,flat_rows,{'sha256':{},'scope':'fake'})), \
                    patch.object(runner,'_implementations',return_value=[Path(module.__file__).resolve(),Path(runner.__file__).resolve()]), \
                    patch.object(Path,'read_text',checked_read):
                report=runner.run(Path(temporary)/'not-read.zip',Path(temporary)/'not-read-flat',output,execute=True,runtime=runtime)
            self.assertEqual(report['rows'],360)
            self.assertEqual(report['new_encoder_forwards'],120)
            self.assertEqual(report['new_root_forwards'],120)
            self.assertEqual(report['new_generation_posts'],0)
            self.assertEqual(report['network']['blocked_connection_attempts'],0)
            self.assertFalse(report['independent_acceptance'])


if __name__=="__main__":unittest.main()
