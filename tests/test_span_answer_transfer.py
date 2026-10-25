"""Complete three-arm mechanism study on authored inputs; no actual inference."""
import copy
from collections import Counter
import json
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch

from tests.test_reference_memory_study import FakeServer, authored, load_module, ROOT
from memory_migration_study.local_detector import MODEL
from memory_migration_study.memory_labels import MemoryLabelAuthority
from memory_migration_study.privacy import _TOKEN

harness = load_module("span_answer_transfer_under_test", ROOT/"scripts/run_span_answer_transfer.py")
CANARY = "SPAN_STUDY_SCORING_ONLY_REFERENCE_5271"


class SpanServer(FakeServer):
    def __init__(self, *, annotation_failure=False, bad_pointer=False, query_only=False, bare=False, revoke=False):
        super().__init__()
        self.annotation_failure, self.bad_pointer, self.query_only, self.bare, self.revoke = annotation_failure, bad_pointer, query_only, bare, revoke
        self.observer, self.authorities, self.revoked = None, {}, set()

    def transport(self, client, method, path, body=None):
        if method != "POST":
            return super().transport(client, method, path, body)
        if self.gold_parsed:
            raise AssertionError("generation after scoring reference parsed")
        data = json.loads(body["messages"][1]["content"])
        properties = body.get("format", {}).get("properties", {})
        if "findings" in properties:
            failed = self.annotation_failure and self.observer.context["fact_index"] == 0
            content = json.dumps({"status": "needs_review" if failed else "ok", "findings": [] if failed else [
                {"quote": data["text"][s["start"]:s["end"]], "category": s["category"]}
                for s in authored.candidate_spans(data["text"]) if s["category"] == "CUSTOMER"]})
        elif "memories" in data or "payload" in data:
            payload = data.get("payload", data)
            query, text = payload["query"], "\n".join(m["text"] for m in payload["memories"])
            absent = "email" in query.casefold() or "邮箱" in query
            if self.query_only and query.startswith("Customer:"):
                value = _TOKEN.search(query).group()
            elif absent:
                value = "UNKNOWN"
            elif any(word in query.casefold() for word in ("customer", "buyer", "客户")):
                match = re.search(r"Customer:\s*(.+?);|客户：(.+?)；", text)
                value = next(g for g in match.groups() if g is not None) if match else "UNKNOWN"
            else:
                match = re.search(r"Status:\s*(.+?)\.|状态：(.+?)。", text)
                value = next(g for g in match.groups() if g is not None) if match else "UNKNOWN"
            arm = self.observer.context["arm"]
            if arm == "span_pointer":
                if self.bad_pointer or self.query_only and query.startswith("Customer:"):
                    selection = {"decision": "SPAN", "source": "E_"+"0"*32, "start_token": 0, "end_token": 0}
                elif value == "UNKNOWN":
                    selection = {"decision": "UNKNOWN"}
                else:
                    selection = None
                    for source in data["evidence"]["sources"]:
                        string = "".join(t[1] for t in source["tokens"])
                        a = string.find(value)
                        if a < 0:
                            continue
                        bounds, cursor = {}, 0
                        for index, token in source["tokens"]:
                            bounds[(cursor, cursor+len(token))] = index
                            cursor += len(token)
                        start = next((i for (left, right), i in bounds.items() if left == a), None)
                        end = next((i for (left, right), i in bounds.items() if right == a+len(value)), None)
                        if start is not None and end is not None:
                            selection = {"decision": "SPAN", "source": source["source"], "start_token": start, "end_token": end}
                            break
                    if selection is None:
                        raise AssertionError("fake answer not present as complete token span")
                content = json.dumps(selection)
            else:
                content = value[1:-1] if self.bare and _TOKEN.fullmatch(value) else value
            sid = self.observer.context["story_id"]
            if self.revoke and sid not in self.revoked:
                authority, source_id = self.authorities[sid]
                authority.revoke_source(source_id)
                self.revoked.add(sid)
        else:
            return super().transport(client, method, path, body)
        self.posts.append(copy.deepcopy(body))
        return {"model": MODEL, "done": True, "done_reason": "stop", "message": {"role": "assistant", "content": content},
                "prompt_eval_count": 100, "eval_count": 20}


def fixture():
    runtime, evaluation = [], {}
    for i in range(8):
        sid, lang = f"authored-span-{i}", "en" if i % 2 == 0 else "zh"
        text = "Customer: Cedar Foundry; Status: ready for loading." if lang == "en" else "客户：Cedar Foundry；状态：待装车。"
        if i == 0:
            text = text.replace("; Status:", ";\nStatus:")
        queries = ["Who is the customer?", "What is the status?", "Which customer organization?", "Repeat the status."] if lang == "en" else ["客户是谁？", "状态是什么？", "请给出客户名称。", "再说一次状态。"]
        tasks = [{"task_id": name, "actor_id": "owner", "query": q} for name, q in zip(("name", "status", "name2", "repeat"), queries)]
        tasks.append({"task_id": "outsider", "actor_id": "outsider", "query": "OUTSIDER_NEVER_SEND_417"})
        policy = {"version": "span-harness-fixture-v1", "protected_categories": ["CUSTOMER"], "instructions": "Customer full names are private; status is public."}
        runtime.append({"story_id": sid, "language": lang, "template_family": "authored-family-"+str(i % 4),
            "source": {"source_id": sid+"-source", "text": text}, "policy": policy, "tasks": tasks})
        a = text.index("Cedar Foundry")
        status = "ready for loading" if lang == "en" else "待装车"
        evaluation[sid] = {"answers": {"name": "Cedar Foundry", "status": status, "name2": "Cedar Foundry", "repeat": status},
            "sensitive_spans": [{"start": a, "end": a+len("Cedar Foundry")}], "scoring_only_canary": CANARY}
    return runtime, evaluation


class SpanAnswerTransferTests(unittest.TestCase):
    def run_authored(self, *, root=None, annotation_failure=False, bad_pointer=False, query_only=False,
                     bare=False, revoke=False, invalid_labels=False):
        runtime, evaluation = fixture()
        if query_only:
            for story in runtime:
                story["tasks"][0]["query"] = "Customer: UnsourcedAlias"
        server = SpanServer(annotation_failure=annotation_failure, bad_pointer=bad_pointer, query_only=query_only, bare=bare, revoke=revoke)
        ner, progress, parses, prepare_calls = authored.FakeNerRuntime(), [], [], []
        real_build, real_prepare, real_loads = MemoryLabelAuthority.build_record, harness.prepare_labeled_transfer, json.loads
        def build_record(authority, source, *args, **kwargs):
            record = real_build(authority, source, *args, **kwargs)
            server.authorities[server.observer.context["story_id"]] = (authority, source["source_id"])
            if invalid_labels:
                record["label_signature"] = "0"*64
            return record
        def prepare(records, query, policy, **kwargs):
            prepare_calls.append((kwargs["actor_id"], kwargs["request_id"], query))
            return real_prepare(records, query, policy, **kwargs)
        def loads(value, *args, **kwargs):
            marker = CANARY.encode() if isinstance(value, bytes) else CANARY
            if isinstance(value, (str, bytes)) and marker in value:
                self.assertTrue(observer.model_phase_closed)
                self.assertEqual(len(progress), 144)
                self.assertTrue(all(not p["scored"] for p in progress))
                server.gold_parsed = True
                parses.append(len(server.posts))
            return real_loads(value, *args, **kwargs)
        temp = tempfile.TemporaryDirectory() if root is None else None
        try:
            root = Path(temp.name if temp else root)
            split = root/"corpus/development"
            split.mkdir(parents=True)
            for name, value in (("runtime", runtime), ("evaluation", evaluation)):
                (split/(name+".json")).write_text(json.dumps(value), encoding="utf-8")
            observer = harness.AnswerTransport(root/"output", server.transport)
            server.observer = observer
            with patch.object(harness, "LocalNerRuntime", return_value=ner), \
                 patch.object(MemoryLabelAuthority, "build_record", new=build_record), \
                 patch.object(harness, "prepare_labeled_transfer", new=prepare), \
                 patch.object(json, "loads", new=loads), \
                 patch("socket.socket.connect", side_effect=AssertionError("network forbidden")), observer.installed():
                report = harness.run(root/"corpus", root/"output", "no-model-assets", {}, observer, progress=progress.append)
            network = {"loopback_connections": 0, "external_attempts_blocked": 0}
            harness.save(root/"output/transport_audit.json", dict(observer.summary(), completed=True,
                registered_protocol=harness.VERSION, closed_phase_attempts=observer.closed_phase_attempts,
                network=network, test_transport_only=True))
            harness.save(root/"output/network_audit.json", network)
            data = {name: real_loads((root/"output"/(name+".json")).read_bytes()) for name in
                ("plan", "runtime", "rows", "shared_contexts", "controls", "annotations", "builds", "record_store", "auth_events")}
            events = [real_loads(line) for line in (root/"output/request_transport.jsonl").read_text(encoding="utf-8").splitlines()]
            self.assertEqual((len(data["rows"]), len(data["shared_contexts"]), len(data["controls"])), (144, 48, 8))
            self.assertEqual(report["generation_calls_observed"], len(server.posts))
            self.assertEqual(report["shared_prepare_invocations"], len(prepare_calls))
            self.assertEqual(report["total_encoder_calls"], len(ner.calls))
            self.assertEqual(parses, [len(server.posts)])
            self.assertEqual(observer.closed_phase_attempts, 0)
            self.assertEqual(report["answer_generations"], sum(r["answer_calls"] for r in data["rows"]))
            self.assertEqual(len({(r["story_id"], r["task_id"], r["arm"]) for r in data["rows"]}), 144)
            captured = json.dumps({"posts": server.posts, "ner": ner.calls})
            for word in (CANARY, "OUTSIDER_NEVER_SEND_417", '"answers"', '"sensitive_spans"', '"task_id"', '"actor_id"', '"access_signature"'):
                self.assertNotIn(word, captured)
            for c in data["shared_contexts"]:
                self.assertNotIn("table", c)
                self.assertNotIn("mapping", c)
            return report, data, events, server
        finally:
            if temp:
                temp.cleanup()

    def test_full_144_same_preparation_views_original_responses_and_missing_controls(self):
        report, data, events, server = self.run_authored()
        self.assertEqual((report["builder_generations"], report["write_annotation_generations"], report["answer_generations"]), (8, 9, 120))
        self.assertEqual(report["shared_prepare_invocations"], 48)
        self.assertEqual(report["shared_prepare_encoder_calls"], 40)
        self.assertEqual(report["total_encoder_calls"], 58)
        for arm in harness.ARMS:
            self.assertEqual(report["arms"][arm]["legal"]["correct"], 32)
            self.assertEqual(report["arms"][arm]["missing"]["correct"], 8)
            self.assertEqual(report["arms"][arm]["outsider"]["outsider_blocked"], 8)
        contexts = {c["context_id"]: c for c in data["shared_contexts"]}
        responses = {e["index"]: e for e in events if e["phase"] == "response"}
        for context_id, context in contexts.items():
            if context["actor_id"] != "owner":
                continue
            arms = {r["arm"]: r for r in data["rows"] if r["context_id"] == context_id}
            requests = {arm: server.posts[r["answer_request_indices"][0]-1] for arm, r in arms.items()}
            self.assertEqual(requests["free_indexed"]["messages"][1], requests["span_pointer"]["messages"][1])
            self.assertEqual(json.loads(requests["free"]["messages"][1]["content"]), context["payload"])
            indexed = json.loads(requests["span_pointer"]["messages"][1]["content"])
            self.assertEqual(indexed["payload"], context["payload"])
            self.assertEqual(requests["free_indexed"]["options"], requests["span_pointer"]["options"])
        for row in data["rows"]:
            c = contexts[row["context_id"]]
            self.assertEqual(row["context_sha256"], c["context_sha256"])
            if row["answer_calls"]:
                response = responses[row["answer_request_indices"][0]]["response"]
                self.assertEqual(row["raw_model_answer"], response["message"]["content"])
            if row["arm"] == "span_pointer" and row["task_class"] == "legal":
                self.assertEqual(row["pointer_decision"], "SPAN")
                self.assertIsNotNone(row["source_span"])
                self.assertTrue(row["model_answer"].lstrip().startswith("{"))
                self.assertFalse(row["secondary_serialization_registered"])
            if row["actor_id"] == "outsider":
                self.assertEqual(row["answer_calls"], 0)
        self.assertEqual(Counter(c["language"] for c in data["controls"]), {"en": 4, "zh": 4})

    def test_annotation_failure_keeps_all_144_and_never_substitutes_clean_ner_labels(self):
        report, data, _, _ = self.run_authored(annotation_failure=True)
        self.assertEqual(report["common_build_failures"], 0)
        self.assertEqual(report["union_label_set_failures"], 8)
        self.assertEqual(report["answer_generations"], 0)
        self.assertEqual(report["shared_prepare_invocations"], 0)
        self.assertTrue(any(a["status"] == "ok" and not a["eligible_for_store"] for a in data["annotations"]))
        for arm in harness.ARMS:
            self.assertEqual(report["arms"][arm]["legal"]["registered_tasks"], 32)
            self.assertEqual(report["arms"][arm]["missing"]["registered_tasks"], 8)
            self.assertEqual(report["arms"][arm]["missing"]["correct"], 0)

    def test_bad_pointer_query_only_and_always_span_cannot_pass_absence_controls(self):
        report, data, _, _ = self.run_authored(bad_pointer=True, query_only=True)
        self.assertEqual(report["arms"]["span_pointer"]["legal"]["correct"], 0)
        self.assertEqual(report["arms"]["span_pointer"]["missing"]["correct"], 0)
        self.assertEqual(report["arms"]["span_pointer"]["missing"]["registered_tasks"], 8)
        for row in data["rows"]:
            if row["task_id"] == "name" and row["arm"] != "span_pointer":
                self.assertIsNone(row["final_answer"])
                self.assertEqual(row["restoration_error"], "query_only_value_has_no_evidence")
            if row["arm"] == "span_pointer":
                self.assertIsNone(row["final_answer"])
                self.assertNotIn("secondary_serialization", row)

    def test_bad_label_real_fallback_and_free_secondary_do_not_rewrite_primary(self):
        report, data, _, _ = self.run_authored(invalid_labels=True, bare=True)
        self.assertEqual(report["shared_prepare_encoder_calls"], 85)
        for arm in ("free", "free_indexed"):
            self.assertEqual(report["arms"][arm]["legal"]["correct"], 16)
            self.assertEqual(report["arms"][arm]["legal"]["secondary_correct"], 32)
        self.assertEqual(report["arms"]["span_pointer"]["legal"]["correct"], 32)
        for c in data["shared_contexts"]:
            if c["actor_id"] == "owner":
                self.assertTrue(all(not x["label_valid"] and x["fallback_reason"] == "label_signature_invalid" for x in c["checks"]))

    def test_source_revocation_between_response_and_resolution_blocks_restore_and_later_arms(self):
        report, data, _, _ = self.run_authored(revoke=True)
        self.assertEqual(report["answer_generations"], 8)
        self.assertTrue(all(r["final_answer"] is None for r in data["rows"]))
        for arm in harness.ARMS:
            self.assertEqual(report["arms"][arm]["legal"]["correct"], 0)
            self.assertEqual(report["arms"][arm]["missing"]["correct"], 0)
        returned = [r for r in data["rows"] if r["answer_calls"]]
        self.assertEqual(len(returned), 8)
        for row in returned:
            self.assertEqual(row.get("resolver_error") if row["arm"] == "span_pointer" else row.get("restoration_error"), "grant_revoked")


if __name__ == "__main__":
    unittest.main()
