"""Full authored 144-row integration with injected NER/transport, no inference."""
from copy import deepcopy
import json
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch

from memory_migration_study.local_detector import MODEL
from memory_migration_study.memory_labels import MemoryLabelAuthority
from memory_migration_study.privacy import _TOKEN
from scripts import run_source_card_reader as harness
from tests.test_query_schema_transfer import QueryRuntime
from tests.test_span_answer_transfer import SpanServer, fixture

CANARY = "SOURCE_CARD_SCORE_ONLY_CANARY_20261026"


class CardServer(SpanServer):
    def transport(self, client, method, path, body=None):
        if method == "POST" and "card_id" in (body or {}).get("format", {}).get("properties", {}):
            if self.gold_parsed:
                raise AssertionError("model after gold")
            data = json.loads(body["messages"][1]["content"])
            if set(data) != {"query", "memories", "fact_cards"}:
                raise AssertionError("reader must receive only the complete masked view")
            query, text = data["query"].lower(), "\n".join(m["text"] for m in data["memories"])
            if "email" in query or "邮箱" in query:
                identifier = "UNKNOWN"
            else:
                if "customer" in query or "客户" in query:
                    value = _TOKEN.search(text).group()
                else:
                    match = re.search(r"Status:\s*(.+?)\.|状态：(.+?)。", text)
                    value = next(v for v in match.groups() if v is not None)
                identifier = next(c["card_id"] for c in data["fact_cards"] if c["value"] == value)
            self.posts.append(deepcopy(body))
            sid = self.observer.context["story_id"]
            if self.revoke and sid not in self.revoked:
                authority, source_id = self.authorities[sid]
                authority.revoke_source(source_id); self.revoked.add(sid)
            return {"model": MODEL, "done": True, "done_reason": "stop",
                    "message": {"role": "assistant", "content": json.dumps({"card_id": identifier})},
                    "prompt_eval_count": 400, "eval_count": 12}
        return super().transport(client, method, path, body)


def run_fixture(root, *, annotation_failure=False, revoke=False):
    root = Path(root)
    runtime, evaluation = fixture()
    for story in runtime:
        story["policy"] = deepcopy(harness.POLICY)
        story["source"]["text"] = story["source"]["text"].replace("Status:", "Business Status:").replace("状态：", "业务状态：")
        evaluation[story["story_id"]]["score_only_canary"] = CANARY
    split = root/"corpus/development"; split.mkdir(parents=True)
    for name, value in (("runtime", runtime), ("evaluation", evaluation)):
        (split/(name+".json")).write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")
    server = CardServer(annotation_failure=annotation_failure, bare=True, revoke=revoke)
    observer = harness.SourceCardTransport(root/"output", server.transport); server.observer = observer
    progress, prepares, parses = [], [], []
    real_build, real_prepare, real_loads = MemoryLabelAuthority.build_record, harness.prepare_labeled_transfer, json.loads
    def build_record(authority, source, *args, **kwargs):
        record = real_build(authority, source, *args, **kwargs)
        server.authorities[observer.context["story_id"]] = (authority, source["source_id"])
        return record
    def prepare(*args, **kwargs):
        prepares.append(kwargs["request_id"])
        return real_prepare(*args, **kwargs)
    def loads(value, *args, **kwargs):
        marker = CANARY.encode() if isinstance(value, bytes) else CANARY
        if isinstance(value, (str, bytes)) and marker in value:
            if not observer.model_phase_closed or len(progress) != 144:
                raise AssertionError("gold parsed before all processing")
            server.gold_parsed = True; parses.append(len(server.posts))
        return real_loads(value, *args, **kwargs)
    with patch.object(harness, "LocalNerRuntime", return_value=QueryRuntime("no weights")), \
            patch.object(MemoryLabelAuthority, "build_record", new=build_record), \
            patch.object(harness, "prepare_labeled_transfer", new=prepare), \
            patch.object(json, "loads", new=loads), \
            patch("socket.socket.connect", side_effect=AssertionError("no network")), observer.installed():
        plan = harness.protocol(root/"corpus", {})[0]
        report = harness.run(root/"corpus", root/"output", "no weights", {}, observer, plan, progress=progress.append)
    rows = real_loads((root/"output/rows.json").read_bytes())
    contexts = real_loads((root/"output/shared_contexts.json").read_bytes())
    return report, rows, contexts, observer, server, prepares, parses


class DriverTests(unittest.TestCase):
    def test_explicit_dependency_closure_allows_unrelated_parallel_modules(self):
        with tempfile.TemporaryDirectory() as root:
            clone = Path(root)
            for name in harness.REGISTERED_DEPENDENCIES:
                target = clone/name; target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((harness.ROOT/name).read_bytes())
            unrelated = clone/"memory_migration_study/gliclass_parallel_unrelated.py"
            unrelated.write_text("# independent work, never imported by reader\n", encoding="utf-8")
            with patch.object(harness, "ROOT", clone), patch.object(harness, "__file__", str(clone/"scripts/run_source_card_reader.py")):
                self.assertEqual(set(harness.audit_dependency_closure()), set(harness.REGISTERED_DEPENDENCIES))
                hashes = {name: harness.file_sha(clone/name) for name in harness.REGISTERED_DEPENDENCIES}
                harness.assert_implementation(hashes)
                unrelated.write_text("# independent work may continue\n", encoding="utf-8")
                harness.assert_implementation(hashes)
                registered = clone/"memory_migration_study/source_card_reader.py"
                registered.write_bytes(registered.read_bytes()+b"\n# registered mutation\n")
                with self.assertRaisesRegex(ValueError, "frozen_implementation_changed"):
                    harness.assert_implementation(hashes)

    def test_plan_and_stage_budgets_do_not_start_models(self):
        with tempfile.TemporaryDirectory() as root:
            observer = harness.SourceCardTransport(root, lambda *args: None)
            observer.stage("answer", "Flat-ID", "s", "t")
            observer.cell_counts[("s", "t", "Flat-ID")] = 1
            with self.assertRaisesRegex(ValueError, "one_answer_request"):
                observer.call(None, "POST", "/api/chat", {})
            observer.stage("answer", "Source-ID", "s", "t")
            observer.stage_counts["answer"] = 120
            with self.assertRaisesRegex(ValueError, "stage_cap"):
                observer.call(None, "POST", "/api/chat", {})
            self.assertEqual(observer.attempts, 0)
            self.assertEqual(harness.MAX_CALLS, 264)
            self.assertEqual(harness.LIMITS, {"build": 16, "write_annotation": 128, "answer": 120})
            observer.model_phase_closed = True
            with self.assertRaisesRegex(RuntimeError, "model_phase_closed"):
                observer.call(None, "POST", "/api/chat", {})
            self.assertEqual(observer.closed_phase_attempts, 1)
            self.assertEqual(observer.attempts, 0)

    def test_complete_matrix_shared_preparation_and_gold_closed(self):
        with tempfile.TemporaryDirectory() as root:
            report, rows, contexts, observer, server, prepares, parses = run_fixture(root)
            self.assertEqual((len(rows), len(contexts), len(prepares), len(set(prepares))), (144, 48, 48, 48))
            self.assertEqual(report["generation_calls_by_arm"], {"F": 40, "Flat-ID": 40, "Source-ID": 40})
            self.assertEqual(parses, [len(server.posts)])
            self.assertEqual(observer.closed_phase_attempts, 0)
            for arm in harness.ARMS:
                self.assertEqual(report["arms"][arm]["legal"]["correct"], 32)
                self.assertEqual(report["arms"][arm]["missing"]["correct"], 8)
                self.assertEqual(report["arms"][arm]["outsider"]["outsider_blocked"], 8)
            for context in contexts:
                self.assertNotIn("mapping", context); self.assertNotIn("table", context)
                if context["prepare_status"] == "ok":
                    flat, rich = context["views"]["flat"], context["views"]["source"]
                    self.assertEqual(flat["memories"], rich["memories"])
                    self.assertEqual(flat["fact_cards"], [{k: v for k, v in c.items() if k not in {"role", "support"}} for c in rich["fact_cards"]])
            requests = json.dumps(server.posts)
            for marker in (CANARY, "OUTSIDER_NEVER_SEND_417", "access_signature", '"answers"'):
                self.assertNotIn(marker, requests)
            self.assertEqual(len({(r["story_id"], r["task_id"], r["arm"]) for r in rows}), 144)
            archived = Path(root)/"output/implementation"
            for file in ("scripts/run_source_card_reader.py", "scripts/run_span_answer_transfer.py",
                         "scripts/run_query_schema_transfer.py", "memory_migration_study/request_projection.py",
                         "memory_migration_study/source_card_reader.py"):
                self.assertTrue((archived/file).is_file())

    def test_annotation_failures_retain_all_rows_and_no_answer_generations(self):
        with tempfile.TemporaryDirectory() as root:
            report, rows, _, _, _, _, _ = run_fixture(root, annotation_failure=True)
            self.assertEqual(len(rows), 144)
            for arm in harness.ARMS:
                self.assertEqual(report["arms"][arm]["legal"]["registered_tasks"], 32)
                self.assertEqual(report["arms"][arm]["legal"]["correct"], 0)
                self.assertEqual(report["generation_calls_by_arm"][arm], 0)

    def test_revocation_preserves_failure_without_restoration_bypass(self):
        with tempfile.TemporaryDirectory() as root:
            report, rows, _, _, _, _, _ = run_fixture(root, revoke=True)
            self.assertEqual(len(rows), 144)
            self.assertTrue(any(r.get("answer_error") or r.get("restoration_error") for r in rows if r["task_class"] == "legal"))
            self.assertTrue(all(r["final_answer"] is None for r in rows if r["task_class"] == "legal"))

    def test_failed_unknown_and_unrelated_unknown_value_do_not_pass_missing_control(self):
        row = {"actor_id": "owner", "task_class": "missing", "required_fact_retained": False,
               "arm": "Flat-ID", "model_response_status": "error", "card_decision": "UNKNOWN",
               "raw_model_answer": '{"card_id":"UNKNOWN"}', "final_answer": "UNKNOWN",
               "masking": {"ready": True, "partial": 0, "unmasked": 0}, "answer_calls": 1}
        self.assertFalse(harness.score(row, "UNKNOWN")["model_chose_unknown"])
        self.assertFalse(harness.score(row, "UNKNOWN")["correct"])
        row.update(model_response_status="ok", card_decision="C_VALID_1")
        self.assertFalse(harness.score(row, "UNKNOWN")["correct"])
        row["card_decision"] = "UNKNOWN"
        self.assertTrue(harness.score(row, "UNKNOWN")["correct"])


if __name__ == "__main__":
    unittest.main()
