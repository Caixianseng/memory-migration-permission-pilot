"""No native backend/model: meaningful schedule and failure denominator checks."""
from copy import deepcopy
import hashlib
import json
import unittest
from scripts.run_native_vector_timing import schedule, qualify_observation
from scripts.native_vector_trace_only_worker import error_metadata


class NativeVectorTimingTests(unittest.TestCase):
    def fixture(self):
        native={"id":"r1","content":"Synthetic fact","path":"f","type":"context","created_at":1,"updated_at":1}
        writes=[{"target_id":"r1","actor":"assistant","text":"Synthetic fact","path":"/f","native_item":native}]
        fixture=[{"text":str(i),"path":"/p"} for i in range(6)]
        trace={"actor":"assistant","original_calls":1,"trace_restored":True,"limit":100,"filter":None,
               "query_vectors":{"shape":[1,384],"finite":True},"exception_events":[]}
        query={"actor":"assistant","arm":"immediate","embedding_delta":1,"trace":[trace],
               "semantic_row":{"actor":"assistant","operation":"semantic","query":"Customer service and delivery status.",
                 "k":100,"status":200,"vector_result":{"ids":[["r1"]],"documents":[["f\nSynthetic fact"]],
                 "metadatas":[[{k:native[k] for k in ("created_at","updated_at","type","path")}]],"distances":[[1.0]]},"response_checked":True,
                 "execution_error":None,"native_raw_body":"{}"}}
        raw=json.dumps(query["semantic_row"]["vector_result"])
        query["semantic_row"].update(native_raw_body=raw,native_body_sha256=hashlib.sha256(raw.encode()).hexdigest())
        final={"native_embedding_function_invocations":7,"generation_attempts":0,"network_events":[],
          "timing":{"search_calls":1,"query_attempts":1,"observer_errors":[],"upserts":[
            {"text_sha256":[hashlib.sha256(("p\n"+r["text"]).encode()).hexdigest()],"original_calls":1,"returned":True} for r in fixture]}}
        return query,writes,final,fixture

    def test_valid_native_response_control_passes(self):
        self.assertTrue(qualify_observation(*self.fixture())["passed"])

    def test_balanced_order_per_actor_and_unique_cells(self):
        cells=schedule();self.assertEqual(len(cells),6)
        self.assertEqual({(c["pair"],a) for c in cells for a in c["arms"]},set((i,a) for i in range(6) for a in ("immediate","delay500")))
        for actor in ("assistant","owner","outsider"):
            self.assertEqual({c["arms"][0] for c in cells if c["actor"]==actor},{"immediate","delay500"})

    def test_null_is_failure_not_clean_absence(self):
        q,w,f,x=self.fixture();q["semantic_row"].update(vector_result=None,native_raw_body="null")
        result=qualify_observation(q,w,f,x)
        self.assertFalse(result["passed"]);self.assertTrue(result["null"]);self.assertTrue(result["instrumentation_complete"])

    def test_foreign_id_is_separate_security_stop_signal(self):
        q,w,f,x=self.fixture();q["semantic_row"]["vector_result"]["ids"]=[["other-user"]]
        r=qualify_observation(q,w,f,x);self.assertTrue(r["foreign_id"]);self.assertFalse(r["passed"])

    def test_delay_and_extra_search_cannot_qualify(self):
        q,w,f,x=self.fixture();q.update(arm="delay500",scheduled_ns=1,http_started_ns=499_999_999)
        self.assertFalse(qualify_observation(q,w,f,x)["instrumentation_complete"])
        q["http_started_ns"]=500_000_001;f["timing"]["search_calls"]=2
        self.assertFalse(qualify_observation(q,w,f,x)["instrumentation_complete"])

    def test_actual_fixture_hashes_not_regenerated_residents(self):
        q,w,f,x=self.fixture();f["timing"]["upserts"][0]["text_sha256"]=["0"*64]
        self.assertFalse(qualify_observation(q,w,f,x)["instrumentation_complete"])

    def test_exception_metadata_excludes_raw_message(self):
        value=error_metadata(ValueError("synthetic-private-message"))
        self.assertNotIn("synthetic-private-message",str(value));self.assertIn("message_sha256",value)


if __name__ == "__main__":
    unittest.main()
