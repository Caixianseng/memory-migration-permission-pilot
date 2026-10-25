"""Complete authored 144-row integration with injected transport, never weights."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from memory_migration_study.local_detector import MODEL
from memory_migration_study.memory_labels import MemoryLabelAuthority
from scripts import run_role_query_transfer as harness
from tests.test_query_schema_transfer import QueryRuntime
from tests.test_span_answer_transfer import SpanServer, fixture

CANARY = "ROLE_QUERY_SCORE_ONLY_CANARY_20261026"


class RoleServer(SpanServer):
    def transport(self, client, method, path, body=None):
        props = (body or {}).get("format", {}).get("properties", {})
        if method == "POST" and "role" in props:
            if self.gold_parsed:
                raise AssertionError("model called after gold")
            data = json.loads(body["messages"][1]["content"])
            if set(data) != {"query", "role_definitions"}:
                raise AssertionError("role model must see only query and fixed definitions")
            query = data["query"].lower()
            role = "email" if "email" in query or "邮箱" in query else "customer" if "customer" in query or "客户" in query else "status"
            self.posts.append(deepcopy(body))
            return {"model": MODEL, "done": True, "done_reason": "stop",
                    "message": {"role": "assistant", "content": json.dumps({"role": role})},
                    "prompt_eval_count": 100, "eval_count": 8}
        return super().transport(client, method, path, body)


def run_fixture(root, *, annotation_failure=False, revoke=False):
    root = Path(root)
    runtime, evaluation = fixture()
    for story in runtime:
        story["policy"] = deepcopy(harness.POLICY)
        # The authored fixture must use the frozen explicit source role grammar.
        story["source"]["text"] = story["source"]["text"].replace("Status:", "Business Status:").replace("状态：", "业务状态：")
        evaluation[story["story_id"]]["scoring_only_canary"] = CANARY
    split = root/"corpus/development"
    split.mkdir(parents=True)
    for name, value in (("runtime", runtime), ("evaluation", evaluation)):
        (split/(name+".json")).write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")
    server = RoleServer(annotation_failure=annotation_failure, bare=True, revoke=revoke)
    observer = harness.RoleQueryTransport(root/"output", server.transport)
    server.observer = observer
    ner, progress, prepares, parses = QueryRuntime("no model assets"), [], [], []
    real_build, real_prepare, real_loads = MemoryLabelAuthority.build_record, harness.prepare_labeled_transfer, json.loads
    def build_record(authority, source, *args, **kwargs):
        result = real_build(authority, source, *args, **kwargs)
        server.authorities[server.observer.context["story_id"]] = (authority, source["source_id"])
        return result
    def prepare(*args, **kwargs):
        prepares.append(kwargs["request_id"])
        return real_prepare(*args, **kwargs)
    def loads(value, *args, **kwargs):
        marker = CANARY.encode() if isinstance(value, bytes) else CANARY
        if isinstance(value, (bytes, str)) and marker in value:
            if not observer.model_phase_closed or len(progress) != 144:
                raise AssertionError("evaluation parsed before all processing ended")
            server.gold_parsed = True
            parses.append(len(server.posts))
        return real_loads(value, *args, **kwargs)
    with patch.object(harness, "LocalNerRuntime", return_value=ner), \
            patch.object(MemoryLabelAuthority, "build_record", new=build_record), \
            patch.object(harness, "prepare_labeled_transfer", new=prepare), \
            patch.object(json, "loads", new=loads), \
            patch("socket.socket.connect", side_effect=AssertionError("no network")), observer.installed():
        plan = harness.protocol(root/"corpus", {})[0]
        report = harness.run(root/"corpus", root/"output", "no model assets", {}, observer, plan, progress=progress.append)
    harness.save(root/"output/transport_audit.json", dict(observer.summary(), completed=True,
        test_transport_only=True, closed_phase_attempts=observer.closed_phase_attempts,
        generation_calls_by_stage=dict(observer.stage_counts), network={"external_attempts_blocked": 0}))
    harness.save(root/"output/network_audit.json", {"external_attempts_blocked": 0})
    rows = real_loads((root/"output/rows.json").read_bytes())
    contexts = real_loads((root/"output/shared_contexts.json").read_bytes())
    return report, rows, contexts, observer, server, prepares, parses


class RoleQueryTransferTests(unittest.TestCase):
    def test_processing_failures_are_not_true_model_unknown(self):
        row = {"actor_id": "owner", "task_class": "legal", "required_fact_retained": True,
               "masking": {"ready": True, "partial": 0, "unmasked": 0}, "answer_calls": 1,
               "arm": "Q1", "classification": {"status": "needs_review", "role": "UNKNOWN"},
               "answer_status": "needs_review", "raw_model_answer": "UNKNOWN", "final_answer": None}
        self.assertFalse(harness.score(row, "a fact")["model_chose_unknown"])
        self.assertFalse(harness.score(row, "a fact")["correct"])
        row["arm"] = "F"
        self.assertFalse(harness.score(row, "a fact")["model_chose_unknown"])
        row["answer_status"] = "ok"
        self.assertTrue(harness.score(row, "a fact")["model_chose_unknown"])

    def test_full_shared_preparation_gold_isolation_and_original_restoration(self):
        with tempfile.TemporaryDirectory() as tmp:
            report, rows, contexts, observer, server, prepares, parses = run_fixture(tmp)
            self.assertEqual((len(rows), len(contexts), len(prepares), len(set(prepares))), (144, 48, 48, 48))
            self.assertEqual(parses, [len(server.posts)])
            self.assertEqual(report["generation_calls_by_arm"], {"F": 40, "Q0": 0, "Q1": 40})
            self.assertTrue(all(report["arms"][arm]["outsider"]["outsider_blocked"] == 8 for arm in harness.ARMS))
            self.assertEqual(report["arms"]["F"]["legal"]["correct"], 32)
            self.assertEqual(report["arms"]["Q1"]["legal"]["correct"], 32)
            self.assertEqual(report["arms"]["Q1"]["missing"]["correct"], 8)
            self.assertEqual(observer.closed_phase_attempts, 0)
            self.assertEqual(report["generation_calls_observed"], len(server.posts))
            for c in contexts:
                self.assertNotIn("mapping", c)
                self.assertNotIn("table", c)
                children = [r for r in rows if r["context_id"] == c["context_id"]]
                self.assertEqual({r["actual_payload_sha256"] for r in children}, {c["actual_payload_sha256"]})
            requests = json.dumps(server.posts)
            self.assertNotIn(CANARY, requests)
            self.assertNotIn("OUTSIDER_NEVER_SEND_417", requests)
            self.assertNotIn("access_signature", requests)

    def test_failed_annotations_remain_in_denominator(self):
        with tempfile.TemporaryDirectory() as tmp:
            report, rows, _, _, _, _, _ = run_fixture(tmp, annotation_failure=True)
            self.assertEqual(len(rows), 144)
            for arm in harness.ARMS:
                self.assertEqual(report["arms"][arm]["legal"]["registered_tasks"], 32)
                self.assertEqual(report["arms"][arm]["legal"]["correct"], 0)
                self.assertEqual(report["arms"][arm]["legal"]["answer_calls"], 0)

    def test_current_revocation_blocks_stale_join_and_free_restoration(self):
        with tempfile.TemporaryDirectory() as tmp:
            report, rows, _, _, _, _, _ = run_fixture(tmp, revoke=True)
            self.assertEqual(len(rows), 144)
            self.assertTrue(any(r.get("answer_error") or r.get("restoration_error") for r in rows if r["task_class"] == "legal"))
            self.assertTrue(all(r["final_answer"] is None for r in rows if r["task_class"] == "legal" and r.get("restoration_status") == "blocked"))


if __name__ == "__main__":
    unittest.main()
