import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


SCRIPT=Path(__file__).resolve().parents[1]/"scripts/qualify_mdeberta_nli_runtime.py"
spec=importlib.util.spec_from_file_location("qualify_nli_under_test",SCRIPT)
q=importlib.util.module_from_spec(spec);spec.loader.exec_module(q)


class RuntimeQualificationFakeTests(unittest.TestCase):
    def fake_rows(self):
        return q.run_pairs(lambda p,h:{"input_ids":[1,12,13,2],"attention_mask":[1,1,1,1]},
            lambda t:{"logits":[0.0,2.0,1.0],"shape":[1,3],"dtype":"float32","device":"cpu"},lambda:None)

    def result(self,plan_hash="a"*64):
        return {"plan_sha256":plan_hash,"status":"runtime_qualified","runtime_qualified":True,
            "model_loads":1,"actual_top_classifier_forwards":3,"top_classifier_entry_attempts":3,
            "blocked_forward_entries":0,"generation_calls":0,"cloud_calls":0,
            "guard":{"blocked_attempts":0},"rows":self.fake_rows()}

    def test_exact_public_pairs_only_and_full_preflight_before_any_forward(self):
        self.assertEqual(q.PAIRS[0]["premise"],"A person is reading a book.")
        self.assertEqual(q.PAIRS[1]["hypothesis"],"这扇门没有打开。")
        self.assertEqual(q.PAIRS[2]["hypothesis"],"The person is a doctor.")
        calls=[];count=0
        def tokens(p,h):
            nonlocal count
            count+=1;n=513 if count==3 else 4
            return {"input_ids":[1]*n,"attention_mask":[1]*n}
        with self.assertRaisesRegex(ValueError,"full_pair_token_budget_exceeded"):
            q.run_pairs(tokens,lambda _:calls.append("forward"),lambda:calls.append("start"))
        self.assertEqual(calls,[])

    def test_counter_wraps_actual_classifier_entry_blocks_warmup_and_fourth_call(self):
        class Classifier:
            def forward(self):return "ran"
        original=Classifier.forward;model=Classifier()
        with q.ForwardBudget(Classifier) as budget:
            with self.assertRaises(RuntimeError):model.forward()
            self.assertEqual(budget.actual,0)
            budget.model=model;budget.phase="inference"
            for _ in range(3):self.assertEqual(model.forward(),"ran")
            with self.assertRaises(RuntimeError):model.forward()
            self.assertEqual(budget.actual,3);self.assertEqual(budget.blocked,2)
        self.assertIs(Classifier.forward,original)

    def test_cpu_float32_finite_three_logits_are_required(self):
        baseline={"logits":[0.0,1.0,2.0],"shape":[1,3],"dtype":"float32","device":"cpu"}
        for change in [{"logits":[1,2]},{"logits":[1,float("nan"),3]},{"dtype":"float16"},
                       {"device":"cuda"},{"shape":[3]}]:
            with self.subTest(change=change):
                with self.assertRaisesRegex(ValueError,"logit_contract_invalid"):
                    q.run_pairs(lambda p,h:{"input_ids":[1,2],"attention_mask":[1,1]},
                        lambda _:dict(baseline,**change),lambda:None)

    def test_worker_job_and_environment_do_not_carry_expected_or_inherited_secrets(self):
        plan={"pairs":copy.deepcopy(list(q.PAIRS)),"runtime":q.RUNTIME}
        job=q.worker_job(plan,"a"*64)
        text=json.dumps(job)
        for forbidden in ["expected","gold","case_id","secret-test-key"]:self.assertNotIn(forbidden,text)
        with patch.dict(os.environ,{"HF_TOKEN":"secret-test-key","DEEPSEEK_API_KEY":"secret-test-key",
                                    "USERPROFILE":"sensitive-user-home"}):
            env=q.child_environment(Path("isolated-home"))
        self.assertNotIn("HF_TOKEN",env);self.assertNotIn("DEEPSEEK_API_KEY",env)
        self.assertNotIn("secret-test-key",json.dumps(env));self.assertNotEqual(env["USERPROFILE"],"sensitive-user-home")
        self.assertEqual(env["HF_HUB_OFFLINE"],"1")
        self.assertEqual(env["TEMP"],str(Path("isolated-home")));self.assertEqual(env["TMP"],env["TEMP"])

    def test_score_requires_original_prediction_closure_and_wrong_smoke_does_not_fail_runtime(self):
        with tempfile.TemporaryDirectory() as temporary:
            output=Path(temporary);q.save(output/"worker_predictions.json",self.result())
            closed={"closed":True,"prediction_sha256":q.sha(output/"worker_predictions.json"),"plan_sha256":"a"*64,"returncode":0}
            with self.assertRaisesRegex(ValueError,"prediction_phase_not_sealed"):q.score_closed(output,closed)
            q.save(output/"prediction_phase_closed.json",closed)
            report=q.score_closed(output,closed)
            self.assertTrue(report["runtime_qualified"]);self.assertEqual(report["smoke_correct"],1)
            self.assertFalse(report["method_acceptance"])

    def test_host_does_not_trust_a_runtime_true_with_bad_accounting_or_logits(self):
        for mutation in [lambda r:r.update(actual_top_classifier_forwards=4),
                         lambda r:r["rows"][0].update(predicted_label="contradiction"),
                         lambda r:r["rows"][0].update(device="cuda")]:
            with tempfile.TemporaryDirectory() as temporary:
                output=Path(temporary);result=self.result();mutation(result)
                q.save(output/"worker_predictions.json",result)
                closed={"closed":True,"prediction_sha256":q.sha(output/"worker_predictions.json"),"plan_sha256":"a"*64,"returncode":0}
                q.save(output/"prediction_phase_closed.json",closed)
                with self.assertRaises(ValueError):q.score_closed(output,closed)

    def fake_assets(self,root):
        files=[]
        config={"label2id":q.LABELS,"id2label":{str(v):k for k,v in q.LABELS.items()},
                "architectures":["DebertaV2ForSequenceClassification"],"max_position_embeddings":512}
        for name,_,_ in q.FILES:
            path=root/q.ASSETS/name;path.parent.mkdir(parents=True,exist_ok=True)
            path.write_bytes(q.encoded(config) if name=="config.json" else b"fake-only-not-a-model")
            files.append((name,path.stat().st_size,q.sha(path)))
        manifest={"model_id":q.MODEL_ID,"revision":q.REVISION,"files":[{"name":n,"size":s,"sha256":h} for n,s,h in files],
                  "declared_label2id":q.LABELS,"declared_max_positions":512,"total_bytes_including_model_card":sum(s for _,s,_ in files)}
        path=root/q.MANIFEST;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(q.encoded(manifest))
        for name in [q.SELF,q.COMMON,q.PYTHON,".venv-native-webui/pyvenv.cfg",*(".venv-native-webui/Lib/site-packages/"+n for n in q.RUNTIME_SOURCES)]:
            path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text("fake source or executable; never executed",encoding="utf-8")
        for name in q.DISTRIBUTIONS:
            path=root/".venv-native-webui/Lib/site-packages"/(name+"-1.0.dist-info")/"METADATA"
            path.parent.mkdir(parents=True,exist_ok=True);path.write_text("Name: "+name+"\nVersion: 1.0\n",encoding="utf-8")
        return tuple(files)

    def test_plan_only_hashes_all_assets_and_rejects_source_or_exact_json_changes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve();files=self.fake_assets(root)
            with patch.object(q,"ROOT",root),patch.object(q,"FILES",files):
                output=root/"results/qualification";plan=q.plan_only(output)
                verified,digest=q.approved_plan(output/"plan.json")
                self.assertEqual(plan,verified);self.assertEqual(len(digest),64)
                path=output/"plan.json";original=path.read_bytes();path.write_bytes(original+b" ")
                with self.assertRaisesRegex(ValueError,"approved_plan_or_runtime_changed"):q.approved_plan(path)
                path.write_bytes(original);(root/q.SELF).write_text("changed",encoding="utf-8")
                with self.assertRaises(ValueError):q.approved_plan(path)

    def test_execute_uses_one_isolated_child_and_closes_before_host_scores(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve();files=self.fake_assets(root)
            with patch.object(q,"ROOT",root),patch.object(q,"FILES",files):
                output=root/"results/qualification";q.plan_only(output)
                plan_hash=q.sha(output/"plan.json");result=self.result(plan_hash)
                class FakeChild:
                    returncode=0
                    def communicate(self,timeout=None):return b'{}',b''
                def spawn(command,**kwargs):
                    self.assertEqual(command[0],str(root/q.PYTHON));self.assertEqual(command[1:3],["-I","-B"])
                    self.assertNotIn("HF_TOKEN",kwargs["env"])
                    q.save(output/"worker_predictions.json",result)
                    return FakeChild()
                with patch.object(q.subprocess,"Popen",side_effect=spawn) as process:
                    report=q.execute(output/"plan.json")
                self.assertEqual(process.call_count,1);self.assertTrue(report["runtime_qualified"])
                self.assertEqual(report["smoke_correct"],1)
                with self.assertRaisesRegex(ValueError,"execution_already_started_no_automatic_retry"):q.execute(output/"plan.json")


if __name__=="__main__":unittest.main()
