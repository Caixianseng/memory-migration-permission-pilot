import importlib.util
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

FILE=Path(__file__).resolve().parents[1]/"scripts/diagnose_mdeberta_guard_io.py"
spec=importlib.util.spec_from_file_location("guard_diagnostic_test",FILE)
d=importlib.util.module_from_spec(spec);spec.loader.exec_module(d)


class DiagnosticFakeTests(unittest.TestCase):
    def test_loading_metadata_has_keys_and_counts_but_never_error_bodies(self):
        info={"missing_keys":["classifier.bias"],"unexpected_keys":[],
              "mismatched_keys":[("layer.weight",(1,),(2,))],"error_msgs":["SECRET diagnostic body"]}
        result=d.loading_summary(info)
        self.assertEqual(result["missing_keys"],{"count":1,"keys":["classifier.bias"]})
        self.assertEqual(result["mismatched_keys"]["keys"],["layer.weight"])
        self.assertEqual(result["error_msgs_count"],1)
        self.assertNotIn("SECRET",str(result))

    def test_real_loader_return_is_preserved_and_all_forward_entries_are_blocked(self):
        q=d.load_qualifier();trace={"loading_info":None,"blocked_classifier_entries":0}
        class Model:
            def forward(self):raise AssertionError("underlying forward must not run")
        model=Model();calls=[]
        class Auto:
            @classmethod
            def from_pretrained(cls,*args,**kwargs):
                calls.append(kwargs);return model,{"missing_keys":[],"unexpected_keys":[],"mismatched_keys":[],"error_msgs":[]}
        original=Model.forward;original_loader=Auto.from_pretrained.__func__
        _,Budget=d.wrappers(q,trace)
        with patch.dict(sys.modules,{"transformers":SimpleNamespace(AutoModelForSequenceClassification=Auto)}):
            with Budget(Model) as budget:
                loaded=Auto.from_pretrained("public-model",token=False,local_files_only=True)
                self.assertIs(loaded,model)
                budget.model=model;budget.phase="inference"
                with self.assertRaisesRegex(RuntimeError,"diagnostic_zero_forward_stop"):model.forward()
                self.assertEqual(budget.actual,0)
        self.assertIs(Model.forward,original);self.assertIs(Auto.from_pretrained.__func__,original_loader)
        self.assertTrue(calls[0]["output_loading_info"]);self.assertIs(calls[0]["token"],False)
        self.assertEqual(trace["actual_top_classifier_forwards"],0)

    def test_thin_guard_logs_only_original_denial_metadata_without_reading_source(self):
        class Base:
            def __call__(self,event,args):raise PermissionError("unchanged denial")
        trace={"denied_opens":[]};Guard,_=d.wrappers(SimpleNamespace(WorkerGuard=Base,ForwardBudget=object),trace)
        guard=Guard();guard.network=lambda *args:None
        with patch("builtins.open",side_effect=AssertionError("must not read source or target")):
            with self.assertRaises(PermissionError):guard("open",("imaginary-file","r",0))
            guard("open",(str(d.SELF),"r",0))
            with self.assertRaises(PermissionError):guard("open",(str(d.SELF),"w",1))
        self.assertEqual(trace["denied_opens"][0]["path"],"imaginary-file")
        self.assertTrue(trace["denied_opens"][0]["callers"])
        self.assertNotIn("contents",trace["denied_opens"][0])


if __name__=="__main__":unittest.main()
