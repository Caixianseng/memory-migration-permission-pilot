"""No Torch import, model load, network or encoder forward in these tests."""
from __future__ import annotations
import importlib.util
from collections import namedtuple
import os
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch

PATH=Path(__file__).resolve().parents[1]/"scripts/qualify_mdeberta_nli_runtime_v2.py"
SPEC=importlib.util.spec_from_file_location("qualification_v2_fake",PATH)
v=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(v)


class Buffer:
    shape=(1,512);dtype="torch.int64";device=types.SimpleNamespace(type="cpu");requires_grad=False
    def tolist(self):return [list(range(512))]


def model():
    b=Buffer();emb=types.SimpleNamespace(position_ids=b,position_biased_input=False,position_embeddings=None,
        _non_persistent_buffers_set={"position_ids"},_buffers={"position_ids":b})
    return types.SimpleNamespace(config=types.SimpleNamespace(position_biased_input=False,max_position_embeddings=512),
        deberta=types.SimpleNamespace(embeddings=emb),state_dict=lambda:{"classifier.weight":object()})


def info():
    return {"missing_keys":[],"unexpected_keys":[v.BUFFER_KEY],"mismatched_keys":[],"error_msgs":[]}


class V2Tests(unittest.TestCase):
    def test_native_identity_collection_is_metadata_only_and_has_no_subprocess(self):
        Version=namedtuple("Version","major minor micro releaselevel serial")
        archive=Path(sys.base_prefix)/"python312.zip"
        q=types.SimpleNamespace(PYTHON=sys.executable,sha=lambda p:"a"*64)
        with patch.object(v.sys,"version_info",Version(3,12,7,"final",0)),patch.object(v.sys,"version","3.12.7"),\
                patch.object(v.sys,"path",[str(archive)]),patch.object(v.subprocess,"run",side_effect=AssertionError("no child")):
            identity=v.python_identity(q,PATH.parent)
        self.assertTrue(identity["zip_in_sys_path"])
        self.assertEqual(Path(identity["stdlib_zip"]),archive.resolve())

    def test_exact_identity_requires_registered_current_interpreter_zip(self):
        base=Path(sys.base_prefix).resolve();python=Path(sys.executable).resolve()
        identity={"executable":str(python),"version":"3.12.7","base_prefix":str(base),"major_minor":[3,12],
            "stdlib_zip":str(base/"python312.zip"),"zip_in_sys_path":True,"zip_exists":False,"zip_size":None,"zip_sha256":None}
        self.assertEqual(v.validate_identity(identity,python),identity)
        for field,value in (("zip_in_sys_path",False),("stdlib_zip",str(base/"unrelated.zip")),("executable",str(base/"wrong.exe"))):
            changed={**identity,field:value}
            with self.subTest(field=field),self.assertRaises(ValueError):v.validate_identity(changed,python)

    def test_valid_buffer_is_verified_not_silently_ignored(self):
        result=v.validate_loading(model(),info())
        self.assertTrue(result["accepted"]);self.assertFalse(result["verified_nonpersistent_buffer"]["persistent"])
        clean=info();clean["unexpected_keys"]=[]
        self.assertTrue(v.validate_loading(model(),clean)["accepted"])

    def test_other_missing_mismatch_error_or_unexpected_keys_fail(self):
        for field,value in (("missing_keys",["classifier.weight"]),("mismatched_keys",[("x",[1],[2])]),
            ("error_msgs",["private exception text"]),("unexpected_keys",["deberta.embeddings.word_embeddings.weight"]),
            ("unexpected_keys",[v.BUFFER_KEY,v.BUFFER_KEY])):
            changed=info();changed[field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):v.validate_loading(model(),changed)

    def test_wrong_persistence_content_device_or_configuration_fail(self):
        mutations=(lambda m:setattr(m.config,"position_biased_input",True),
            lambda m:m.deberta.embeddings._non_persistent_buffers_set.clear(),
            lambda m:setattr(m.deberta.embeddings.position_ids,"tolist",lambda:[[0]*512]),
            lambda m:setattr(m.deberta.embeddings.position_ids,"device",types.SimpleNamespace(type="cuda")),
            lambda m:setattr(m,"state_dict",lambda:{v.BUFFER_KEY:object()}))
        for index,mutate in enumerate(mutations):
            m=model();mutate(m)
            with self.subTest(index=index),self.assertRaises(ValueError):v.validate_loading(m,info())

    def test_exact_zip_read_only_exception_rejects_neighbors_and_write(self):
        class BaseGuard:
            def __init__(self,*args):self.read_files=set();self.network=lambda *a:None
            def __call__(self,*args):raise PermissionError("original_scope_denial")
            def accounting(self):return {"blocked_attempts":0}
        q=types.SimpleNamespace(build_plan=lambda p:{},plan_only=lambda p:{},approved_plan=lambda p:None,
            save=lambda *a:None,score_closed=lambda *a:None,WorkerGuard=BaseGuard,ForwardBudget=object)
        zip_path=Path(sys.base_prefix)/"python312.zip";trace={"python_identity":{"stdlib_zip":str(zip_path)}}
        v.install(q,trace);guard=q.WorkerGuard(None,PATH,PATH.parent)
        guard("open",(str(zip_path),"rb",0))
        self.assertEqual(len(guard.accounting()["stdlib_zip_read_only_probes"]),1)
        for path,mode,flags in ((zip_path,"wb",os.O_WRONLY),(zip_path.parent/"other.zip","rb",0),(zip_path.parent/"secret.txt","r",0)):
            with self.subTest(path=path,mode=mode),self.assertRaises(PermissionError):guard("open",(str(path),mode,flags))

    def test_real_factory_object_preserved_forward_budget_unchanged(self):
        q=v.load_qualifier();loaded=model();factory_calls=[]
        class Classifier:
            def forward(self):return "real fake forward"
        loaded.forward=types.MethodType(Classifier.forward,loaded)
        class Auto:
            @classmethod
            def from_pretrained(cls,*args,**kwargs):factory_calls.append(kwargs);return loaded,info()
        with patch.dict(sys.modules,{"transformers":types.SimpleNamespace(AutoModelForSequenceClassification=Auto)}):
            with q.ForwardBudget(Classifier) as budget:
                self.assertIs(Auto.from_pretrained("public",token=False,local_files_only=True),loaded)
                self.assertEqual(budget.actual,0)
                with self.assertRaises(RuntimeError):Classifier.forward(loaded)
                self.assertEqual(budget.actual,0);self.assertEqual(budget.blocked,1)
                budget.model=loaded;budget.phase="inference"
                for _ in range(3):self.assertEqual(Classifier.forward(loaded),"real fake forward")
                with self.assertRaises(RuntimeError):Classifier.forward(loaded)
                self.assertEqual(budget.actual,3);self.assertEqual(budget.attempts,5)
        self.assertIs(factory_calls[0]["output_loading_info"],True)
        self.assertIs(factory_calls[0]["token"],False)
        self.assertEqual(q.PAIRS[0]["pair_id"],"P1");self.assertEqual(q.RUNTIME["max_top_classifier_forwards"],3)


if __name__=="__main__":unittest.main()
