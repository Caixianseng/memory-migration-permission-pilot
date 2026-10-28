"""Offline contract tests: synthetic fixtures, no real asset/model/network."""
from contextlib import redirect_stdout
from copy import deepcopy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from scripts import run_qwen35_model_probe as probe
from tests.test_source_annotation_probe import synthetic_materials
from tests.test_relation_probe_scoring import policy, response


class Qwen35ModelProbeTests(unittest.TestCase):
    def setUp(self):
        self.guards = []
        for name in ("socket.socket", "socket.create_connection", "urllib.request.urlopen"):
            item = patch(name, side_effect=AssertionError("network_forbidden"))
            self.guards.append(item.start())
            self.addCleanup(item.stop)
        self.p = policy(probe.prior.base.PROFILE)
        self.authority = probe.MemoryLabelAuthority(b"x" * 32)

    def tearDown(self):
        for guard in self.guards:
            guard.assert_not_called()

    def project(self, root):
        old, assets = root / "old", root / "assets"
        (old / "historical").mkdir(parents=True)
        assets.mkdir()
        (root / "results").mkdir()
        (root / "frozen.py").write_text("frozen", encoding="utf-8")
        texts, reference, receivers = synthetic_materials()
        probe.save(old / "historical/runtime.json", {"schema_version": "relation_occurrence_probe_runtime_v1", "texts": texts})
        probe.save(old / "historical/evaluation.opaque.json", reference)
        full = [{**deepcopy(r), "model": probe.prior.base.MODEL, "digest": probe.OLD_DIGEST} for r in receivers]
        probe.save(old / "source_annotations.json", [{"source_response": r} for r in full])
        probe.save(old / "receiver_responses.json", receivers)
        probe.save(old / "predictions.json", [])
        probe.save(old / "plan.json", {"policy": self.p, "inputs": {
            n: probe.sha(old / "historical" / n) for n in ("runtime.json", "evaluation.opaque.json")}})
        captures = {}
        for i, text in enumerate(texts):
            body = probe.build_request(text, "source_%02d" % i, self.p, [])
            body.pop("think")
            body["model"] = probe.prior.base.MODEL
            name = "transport_%03d.json" % i
            probe.save(old / name, {"method": "POST", "path": "/api/chat", "body": body,
                                    "raw_response": "{}", "error_type": None})
            captures[name] = probe.sha(old / name)
        probe.save(old / "prediction_phase_closed.json", {"plan_sha256": probe.sha(old / "plan.json"),
            "reference_parsed": False, "rows": 72, "predictions_sha256": probe.sha(old / "predictions.json"),
            "source_annotations_sha256": probe.sha(old / "source_annotations.json"), "capture_sha256": captures})
        pins = {n: probe.sha(old / n) for n in probe.PINNED}
        asset = {"status": "assets_verified", "model": probe.MODEL, "model_digest": "a" * 64,
                 "version": probe.RUNTIME_VERSION, "endpoint": probe.ENDPOINT, "generation_calls": 0}
        probe.save(assets / "asset_receipt.json", asset)
        probe.save(assets / "show.json", {"capabilities": ["completion", "thinking"]})
        for name in ("inference_request.json", "inference_response.json"):
            probe.save(assets / name, {"test": name})
        qualification = {"status": "qualified", **{k: asset[k] for k in ("model", "model_digest", "version", "endpoint")},
            "generation_calls": 1, "formal_texts": 0, "thinking_disabled": True, "json_schema_valid": True,
            "complete_generation": True, "request_sha256": probe.sha(assets / "inference_request.json"),
            "response_sha256": probe.sha(assets / "inference_response.json"),
            "asset_receipt_sha256": probe.sha(assets / "asset_receipt.json"),
            "adapter_identity": probe.Qwen35OccurrenceAgent(expected_digest=asset["model_digest"]).cache_identity()}
        probe.save(assets / "inference_qualification.json", qualification)
        for item in (patch.object(probe, "ROOT", root), patch.object(probe, "OLD", old), patch.object(probe, "PINNED", pins),
                     patch.object(probe, "manifest", side_effect=lambda: {"frozen.py": probe.sha(root / "frozen.py")})):
            item.start()
            self.addCleanup(item.stop)
        return texts, reference, receivers, assets

    def freeze(self, root, assets):
        output = root / "results/run"
        frozen = probe.freeze(output, assets / "asset_receipt.json", assets / "inference_qualification.json")
        return output, frozen["plan_sha256"]

    def test_receipts_require_one_successful_actual_identity_and_capture_hashes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            _, _, _, assets = self.project(root)
            a, q, paths = probe.qualified_receipts(assets / "asset_receipt.json", assets / "inference_qualification.json")
            self.assertEqual((a["model"], q["generation_calls"], len(paths)), (probe.MODEL, 1, 5))
            for key, value in (("thinking_disabled", False), ("generation_calls", True), ("formal_texts", 1),
                               ("model_digest", probe.OLD_DIGEST), ("status", "failed")):
                changed = {**q, key: value}
                with patch.object(probe, "read_json", side_effect=lambda p: a if Path(p).name == "asset_receipt.json" else changed):
                    with self.assertRaisesRegex(ValueError, "inference_qualification_required"):
                        probe.qualified_receipts(assets / "asset_receipt.json", assets / "inference_qualification.json")
            identity_changed = deepcopy(q)
            identity_changed["adapter_identity"]["think"] = 0
            with patch.object(probe, "read_json", side_effect=lambda p: a if Path(p).name == "asset_receipt.json" else identity_changed):
                with self.assertRaisesRegex(ValueError, "qualification_adapter_or_assets_changed"):
                    probe.qualified_receipts(assets / "asset_receipt.json", assets / "inference_qualification.json")
            (assets / "inference_response.json").write_text("changed", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "qualification_capture_changed"):
                probe.qualified_receipts(assets / "asset_receipt.json", assets / "inference_qualification.json")

    def test_freeze_and_verify_never_parse_gold_and_reject_code_drift(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            _, _, _, assets = self.project(root)
            original = probe.read_json
            def no_gold(path):
                self.assertNotIn("evaluation", Path(path).name)
                return original(path)
            with patch.object(probe, "read_json", side_effect=no_gold):
                output, frozen = self.freeze(root, assets)
                plan, texts, full, receivers, requests = probe.verify(output, frozen)
                self.assertEqual((len(texts), len(full), len(receivers), len(requests)), (24, 24, 24, 24))
                self.assertFalse(plan["reference_parsed"])
                self.assertTrue(all(len(pair) == 2 for pair in requests))
                with self.assertRaisesRegex(ValueError, "output_scope_or_exists"):
                    probe.freeze(output, assets / "asset_receipt.json", assets / "inference_qualification.json")
                (root / "frozen.py").write_text("changed", encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "frozen_contract_changed"):
                    probe.verify(output, frozen)

    def test_archived_or_current_receipt_changes_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            _, _, _, assets = self.project(root)
            output, frozen = self.freeze(root, assets)
            (output / "receipts/show.json").write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "receipt_changed"):
                probe.verify(output, frozen)

    def test_historical_roots_are_pinned_before_response_parse(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.project(root)
            (probe.OLD / "source_annotations.json").write_text("[]", encoding="utf-8")
            with patch.object(probe, "read_json") as reader:
                with self.assertRaisesRegex(ValueError, "historical_roots_changed"):
                    probe.historical_inputs()
                reader.assert_not_called()

    def test_three_arms_have_equal_empty_labels_and_do_not_union_predictions(self):
        text = "Firwood is our client. Paper style is matte."
        responses = dict(zip(probe.ARMS, [response(text), response(text, "Firwood"), response(text)]))
        rows = probe.prepare_case(0, text, self.p, responses, self.authority)
        self.assertEqual([len(r["exact_protective_findings"]) for r in rows], [0, 1, 0])
        self.assertTrue(all(r["record"]["label"]["findings"] == [] for r in rows))
        self.assertTrue(all(r["preparation"]["metadata"]["transfer_mode"] == "migration" for r in rows))
        self.assertEqual([r["observation_origin"] for r in rows], ["historical_replay", "new_local_generation", "historical_replay"])
        self.assertEqual([len(r["preparation"]["acl_negative_controls"]) for r in rows], [2, 2, 2])
        encoded = json.dumps(rows)
        for forbidden in ('"mapping"', '"_entries"', '"secret"'):
            self.assertNotIn(forbidden, encoded)

    def score_material(self, *, new_failure=None, empty_new=False):
        texts, reference, responses = synthetic_materials()
        rows = []
        for i, text in enumerate(texts):
            new = deepcopy(responses[i])
            if empty_new and i == 0:
                new = response(text)
            if new_failure is not None and i == 1:
                new = response(text, status="needs_review", errors=[new_failure], calls=0)
            rows.extend(probe.prepare_case(i, text, self.p, dict(zip(probe.ARMS, (responses[i], new, responses[i]))), self.authority))
        return probe.score_rows(rows, reference, texts), rows, texts, reference

    def test_gate_requires_precision_recall_actual_mask_utility_and_four_unknowns(self):
        scored, rows, texts, reference = self.score_material()
        self.assertTrue(scored["development_gate_passed"])
        self.assertTrue(all(scored["gate_components"].values()))
        self.assertEqual(scored["by_arm"][probe.ARMS[1]]["known_prepared"], 20)
        self.assertIsNone(scored["refusal_rate"])
        self.assertIsNone(scored["downstream_task_success"])
        self.assertIsNone(scored["independent_acceptance_passed"])
        with self.assertRaisesRegex(ValueError, "grid_incomplete"):
            probe.score_rows(rows[:-1], reference, texts)
        broken, *_ = self.score_material(empty_new=True)
        self.assertFalse(broken["development_gate_passed"])
        self.assertEqual(broken["by_arm"][probe.ARMS[1]]["prepared_incomplete_spans"], 1)

    def test_engineering_review_does_not_count_as_semantic_unknown_success(self):
        scored, *_ = self.score_material(new_failure="local_health_failed")
        group = scored["by_arm"][probe.ARMS[1]]
        self.assertEqual(group["unknown_blocked"], 4)
        self.assertEqual(group["semantic_unknown_review"], 3)
        self.assertFalse(scored["development_gate_passed"])

    def test_real_mask_footprint_reports_same_word_expansion_and_legitimate_loss(self):
        text = "Moss is our client. moss is a plant. Paper is matte."
        rows = probe.prepare_case(0, text, self.p, dict.fromkeys(probe.ARMS, response(text, "Moss")), self.authority)
        self.assertTrue(all(len(r["preparation"]["actual_mask_intervals"]) == 2 for r in rows))
        truth = {"decision": "sensitive", "spans": [{"start": 0, "end": 4, "text": "Moss", "category": "CUSTOMER"}]}
        for row in rows:
            v = probe.prior.span_score(text, row, truth, {"start": text.index("moss"), "end": text.index("moss") + 4})
            self.assertEqual((v["fully_masked_spans"], v["actual_masked_unprotected_chars"], v["allowed_fact_retained"]), (1, 4, 0))

    def test_bound_client_enforces_exact_initial_repair_bytes_and_both_budgets(self):
        with tempfile.TemporaryDirectory() as temp:
            requests = probe.requests_for(["A plain note."] * 24, self.p)
            exchange = Mock(return_value='{"prompt_eval_count":10,"eval_count":1}')
            client = probe.BoundedClient(Path(temp), requests, exchange=exchange)
            client.begin_text(0)
            changed = deepcopy(requests[0][0])
            changed["options"]["num_ctx"] = 4096.0
            with self.assertRaisesRegex(ValueError, "actual_request_changed"):
                client("POST", "/api/chat", changed)
            client("POST", "/api/chat", requests[0][0])
            with self.assertRaisesRegex(ValueError, "actual_request_changed"):
                client("POST", "/api/chat", requests[0][0])
            client("POST", "/api/chat", requests[0][1])
            with self.assertRaisesRegex(ValueError, "generation_budget"):
                client("POST", "/api/chat", requests[0][1])
            with self.assertRaisesRegex(ValueError, "text_repeated"):
                client.begin_text(0)
            client.begin_text(1)
            client.posts = 48
            with self.assertRaisesRegex(ValueError, "generation_budget"):
                client("POST", "/api/chat", requests[1][0])
            with self.assertRaisesRegex(ValueError, "transport_route_forbidden"):
                client("POST", "/api/pull", {})
            self.assertEqual(exchange.call_count, 2)
            client.closed = True
            with self.assertRaisesRegex(ValueError, "client_closed"):
                client("GET", "/api/version")

    def test_raw_response_is_preserved_and_bad_or_missing_token_counts_fail_closed(self):
        for raw in ({}, {"prompt_eval_count": True, "eval_count": 1},
                    {"prompt_eval_count": 10, "eval_count": False},
                    {"prompt_eval_count": 4097, "eval_count": 1},
                    {"prompt_eval_count": 10, "eval_count": 1025},
                    {"prompt_eval_count": 10, "eval_count": -1}):
            with self.subTest(raw=raw), tempfile.TemporaryDirectory() as temp:
                requests = probe.requests_for(["A plain note."] * 24, self.p)
                client = probe.BoundedClient(Path(temp), requests, exchange=Mock(return_value=json.dumps(raw)))
                client.begin_text(0)
                with self.assertRaisesRegex(ValueError, "actual_token_budget_or_count_missing"):
                    client("POST", "/api/chat", requests[0][0])
                event = probe.read_json(Path(temp) / "transport_001.json")
                self.assertEqual(json.loads(event["raw_response"]), raw)
                self.assertEqual(probe.wire_digest(json.loads(event["wire_body"])), event["wire_body_sha256"])
                self.assertEqual(client.inventory()["post_attempts"], 1)
                self.assertEqual(client.inventory()["raw_generation_responses"], 1)
                self.assertFalse(client.inventory()["token_counts_complete"])
                self.assertIsNone(client.inventory()["eval_count"])

    def test_non_200_http_error_body_is_retained_without_parsing_as_generation(self):
        with tempfile.TemporaryDirectory() as temp:
            requests = probe.requests_for(["A plain note."] * 24, self.p)
            client = probe.BoundedClient(Path(temp), requests)
            client.begin_text(0)
            reply = Mock(status=503)
            reply.read.return_value = b'{"error":"runner unavailable"}'
            connection = Mock()
            connection.getresponse.return_value = reply
            with patch.object(probe.http.client, "HTTPConnection", return_value=connection):
                with self.assertRaisesRegex(ValueError, "local_http_failure"):
                    client("POST", "/api/chat", requests[0][0])
            event = probe.read_json(Path(temp) / "transport_001.json")
            self.assertEqual(event["http_status"], 503)
            self.assertEqual(event["raw_response"], '{"error":"runner unavailable"}')
            self.assertEqual(client.inventory()["raw_generation_responses"], 1)
            self.assertEqual(client.inventory()["complete_generation_responses"], 0)
            connection.close.assert_called_once()

    def test_runtime_failure_stops_after_recording_prefix_without_reading_gold(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            _, _, _, assets = self.project(root)
            output, frozen = self.freeze(root, assets)
            _, _, _, _, requests = probe.verify(output, frozen)
            def exchange(method, path, body):
                if path == "/api/version":
                    return json.dumps({"version": probe.RUNTIME_VERSION})
                if path == "/api/tags":
                    return json.dumps({"models": [{"name": probe.MODEL, "digest": "a" * 64}]})
                return json.dumps({"model": probe.MODEL, "done": True, "done_reason": "stop",
                    "prompt_eval_count": 8, "eval_count": 1025,
                    "message": {"content": '{"status":"ok","findings":[]}'}})
            client = probe.BoundedClient(output, requests, exchange=exchange)
            original = probe.read_json
            def no_gold(path):
                self.assertNotIn("evaluation", Path(path).name)
                return original(path)
            with patch.object(probe, "BoundedClient", return_value=client), \
                    patch.object(probe.prior, "install_network_guard"), \
                    patch.object(probe, "read_json", side_effect=no_gold), redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(ValueError, "fatal_runtime_observation"):
                    probe.execute(output, frozen)
            state = original(output / "execution_final.json")
            self.assertEqual((state["status"], state["rows"], state["unobserved_texts"]), ("stopped", 3, 23))
            self.assertFalse(state["reference_parsed"])
            self.assertFalse(state["call_inventory"]["token_counts_complete"])
            self.assertFalse((output / "prediction_phase_closed.json").exists())
            self.assertFalse((output / "report.json").exists())
            self.assertTrue((output / "model_response_00.json").is_file())
            self.assertEqual(client.posts, 1)

    def test_reference_requires_closed_prediction_and_capture_hashes(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp)
            with patch.object(probe, "read_json", wraps=probe.read_json) as read:
                with self.assertRaises(FileNotFoundError):
                    probe.load_closed_reference(output, "frozen")
                self.assertEqual([Path(c.args[0]).name for c in read.call_args_list], ["prediction_phase_closed.json"])
            probe.save(output / "prediction_phase_closed.json", {"plan_sha256": "frozen", "reference_parsed": False,
                "rows": 72, "predictions_sha256": "changed", "model_responses_sha256": "changed", "capture_sha256": {}})
            probe.save(output / "predictions.json", [])
            with self.assertRaisesRegex(ValueError, "closed_prediction_changed"):
                probe.load_closed_reference(output, "frozen")

    def test_mocked_execute_closes_before_gold_and_never_reinfers_historical_arms(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            texts, _, responses, assets = self.project(root)
            output, frozen = self.freeze(root, assets)
            _, _, _, _, requests = probe.verify(output, frozen)
            by_text = dict(zip(texts, responses))
            def exchange(method, path, body):
                if path == "/api/version":
                    return json.dumps({"version": probe.RUNTIME_VERSION})
                if path == "/api/tags":
                    return json.dumps({"models": [{"name": probe.MODEL, "digest": "a" * 64}]})
                text = json.loads(body["messages"][1]["content"])["text"]
                r = by_text[text]
                raw = {"status": r["status"], "findings": [{"quote": f["quote"], "occurrence": 1,
                    "category": f["category"]} for f in r["findings"]]}
                return json.dumps({"model": probe.MODEL, "done": True, "done_reason": "stop",
                    "message": {"content": json.dumps(raw)}, "prompt_eval_count": 10, "eval_count": 3})
            client = probe.BoundedClient(output, requests, exchange=exchange)
            original, reads = probe.read_json, []
            def only_closed(path):
                if Path(path).name == "evaluation.opaque.json":
                    self.assertTrue(client.closed)
                    self.assertTrue((output / "prediction_phase_closed.json").is_file())
                    self.assertEqual(len(original(output / "predictions.json")), 72)
                    reads.append(path)
                return original(path)
            with patch.object(probe, "BoundedClient", return_value=client), \
                    patch.object(probe.prior, "install_network_guard"), \
                    patch.object(probe, "read_json", side_effect=only_closed), redirect_stdout(io.StringIO()):
                report = probe.execute(output, frozen)
            self.assertEqual(len(reads), 1)
            self.assertTrue(report["development_gate_passed"])
            self.assertEqual((client.posts, len(client.events)), (24, 72))
            self.assertEqual(report["historical_replay_rows"], 48)
            self.assertEqual(report["new_target_posts"], 0)
            self.assertEqual(report["total_new_generation_posts"], 25)
            self.assertEqual((report["prompt_eval_count"], report["eval_count"]), (240, 72))
            self.assertEqual(len(list(output.glob("transport_*.json"))), 72)
            self.assertEqual(original(output / "execution_final.json")["status"], "complete")
            with self.assertRaises(FileExistsError):
                with patch.object(probe.prior, "install_network_guard"):
                    probe.execute(output, frozen)


if __name__ == "__main__":
    unittest.main()
