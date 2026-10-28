"""Synthetic-only freeze, budget, closure and scoring tests; no live backend."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from scripts import run_qwen35_sampling_probe as probe
from tests.test_source_annotation_probe import synthetic_materials
from tests.test_relation_probe_scoring import policy


class Qwen35SamplingProbeTests(unittest.TestCase):
    def setUp(self):
        for target in ("socket.socket", "socket.create_connection", "urllib.request.urlopen"):
            guard = patch(target, side_effect=AssertionError("network_forbidden"))
            mocked = guard.start()
            self.addCleanup(guard.stop)
            self.addCleanup(mocked.assert_not_called)
        self.p = policy(probe.prior.base.PROFILE)

    def envelope(self, content=None, **changes):
        return {"model": probe.MODEL, "done": True, "done_reason": "stop",
            "message": {"content": json.dumps(content or {"status": "ok", "findings": []})},
            "prompt_eval_count": 30, "eval_count": 20, **changes}

    def project(self, root):
        old, receipts = root / "history", root / "receipts"
        (old / "historical/historical").mkdir(parents=True)
        receipts.mkdir()
        (root / "results").mkdir()
        (root / "frozen.py").write_text("synthetic implementation", encoding="utf-8")
        texts, reference, responses = synthetic_materials()
        probe.save(old / "historical/historical/runtime.json", {"texts": texts})
        probe.save(old / "historical/historical/evaluation.opaque.json", reference)
        inputs = {n: probe.sha(old / n) for n in ("historical/historical/runtime.json", "historical/historical/evaluation.opaque.json")}
        asset, qualification = receipts / "asset.json", receipts / "qualification.json"
        probe.save(asset, {"model_digest": probe.MODEL_DIGEST, "executable": str(root / "synthetic_ollama.exe"),
                           "executable_sha256": "b" * 64})
        probe.save(qualification, {"generation_calls": 1})
        probe.save(receipts / "runtime_ready.json", {"status": "ready", "version": probe.RUNTIME_VERSION, "model": probe.MODEL,
            "endpoint": probe.ENDPOINT, "model_digest": probe.MODEL_DIGEST,
            "executable": str(root / "synthetic_ollama.exe"), "executable_sha256": "b" * 64, "pid": 123,
            "generation_calls": 0, "download_calls": 0, "new_canary_calls": 0, "asset_receipt_sha256": probe.sha(asset),
            "old_qualification_sha256": probe.sha(qualification)})
        receipt_paths = {"asset_receipt.json": asset, "inference_qualification.json": qualification}
        for item in (patch.object(probe, "ROOT", root), patch.object(probe, "ASSET", asset),
            patch.object(probe, "QUALIFICATION", qualification), patch.object(probe.history, "HISTORY", old),
            patch.object(probe.history, "historical_inputs", return_value=(texts, self.p, responses, responses, inputs)),
            patch.object(probe.model_probe, "qualified_receipts", return_value=(probe.read_json(asset), probe.read_json(qualification), receipt_paths)),
            patch.object(probe, "manifest", side_effect=lambda: {"frozen.py": probe.sha(root / "frozen.py")})):
            item.start()
            self.addCleanup(item.stop)
        return texts, reference, responses, receipts / "runtime_ready.json"

    def exchange(self, texts, responses, *, invalid_first=False, broken_counts=False):
        attempts = {}
        def transport(method, path, body, event):
            if path == "/api/version":
                return json.dumps({"version": probe.RUNTIME_VERSION})
            if path == "/api/tags":
                return json.dumps({"models": [{"name": probe.MODEL, "digest": probe.MODEL_DIGEST}]})
            text = json.loads(body["messages"][1]["content"])["text"]
            i = texts.index(text)
            cell = (i, body["options"]["presence_penalty"])
            attempts[cell] = attempts.get(cell, 0) + 1
            r = responses[i]
            content = {"status": r["status"], "findings": [{"quote": f["quote"], "occurrence": 1,
                "category": f["category"]} for f in r["findings"]]}
            if invalid_first and attempts[cell] == 1:
                content = {"status": "ok", "findings": [{"quote": "Absent", "occurrence": 1, "category": "CUSTOMER"}]}
            value = self.envelope(content)
            if broken_counts:
                value["eval_count"] = None
            return json.dumps(value)
        return Mock(side_effect=transport)

    def test_ten_ids_twenty_cells_and_balanced_order_only_presence_differs(self):
        self.assertEqual(probe.TEXT_IDS, (1, 2, 4, 6, 11, 13, 14, 16, 19, 22))
        texts, _, _ = synthetic_materials()
        requests = probe.requests_for(texts, self.p)
        self.assertEqual(len(requests), 10)
        order = probe.generation_order()
        self.assertEqual(len(order), 20)
        self.assertEqual(sum(order[n]["arm"] == "presence_15" for n in range(0, 20, 2)), 5)
        for i in probe.TEXT_IDS:
            for attempt in range(2):
                a, b = (deepcopy(requests[str(i)][arm][attempt]) for arm in probe.NEW_ARMS)
                self.assertEqual(a["options"].pop("presence_penalty"), 1.5)
                self.assertEqual(b["options"].pop("presence_penalty"), 0.0)
                self.assertEqual(a, b)
                self.assertFalse(a["think"])

    def test_runtime_receipt_rejects_wrong_endpoint_digest_bool_and_unbound_assets(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            _, _, _, path = self.project(root)
            original = probe.read_json(path)
            for key, value in (("status", "qualified"), ("version", "wrong"), ("endpoint", "http://127.0.0.1:11436"),
                ("model_digest", "a" * 64), ("generation_calls", True), ("generation_calls", 1),
                ("download_calls", False), ("new_canary_calls", False), ("model", "wrong"),
                ("executable", "wrong.exe"), ("executable_sha256", "c" * 64), ("pid", True),
                ("asset_receipt_sha256", "a" * 64), ("old_qualification_sha256", "b" * 64)):
                path.write_text(json.dumps({**original, key: value}), encoding="utf-8")
                with self.subTest(key=key), self.assertRaisesRegex(ValueError, "runtime_not_ready_or_assets_changed"):
                    probe.qualified_runtime(path)

    def test_freeze_and_verify_do_not_read_gold_and_reject_wire_or_source_drift(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            _, _, _, runtime = self.project(root)
            original = probe.read_json
            def no_gold(path):
                self.assertNotIn("evaluation", Path(path).name)
                return original(path)
            with patch.object(probe, "read_json", side_effect=no_gold):
                out = root / "results/run"
                frozen = probe.freeze(out, runtime)["plan_sha256"]
                plan, _, _ = probe.verify(out, frozen)
                self.assertFalse(plan["reference_parsed"])
                self.assertEqual(plan["runtime_ready_generation_calls"], 0)
                with self.assertRaisesRegex(ValueError, "output_scope_or_exists"):
                    probe.freeze(out, runtime)
                (out / "request_wires.json").write_text("{}", encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "frozen_artifact_changed"):
                    probe.verify(out, frozen)

    def test_all_forty_rows_close_before_gold_and_execution_cannot_repeat(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            texts, _, responses, runtime = self.project(root)
            out = root / "results/run"
            frozen = probe.freeze(out, runtime)["plan_sha256"]
            original = probe.read_json
            def after_closure(path):
                if "evaluation" in Path(path).name:
                    closure = original(out / "prediction_phase_closed.json")
                    self.assertEqual(closure["rows"], 40)
                    self.assertEqual(closure["call_inventory"]["completed_cells"], 20)
                    self.assertEqual(closure["call_inventory"]["post_attempts"], 20)
                return original(path)
            fake = self.exchange(texts, responses)
            with patch.object(probe, "read_json", side_effect=after_closure):
                report = probe.execute(out, frozen, exchange=fake)
            self.assertTrue(report["effect_gate_passed"])
            self.assertFalse(report["proceed_full24"])
            self.assertIsNone(report["runtime_log_sampling_verified"])
            self.assertEqual(fake.call_count, 60)  # 40 health + 20 generation
            final = original(out / "execution_final.json")
            self.assertTrue(final["complete"])
            self.assertEqual(final["unobserved_rows"], 0)
            self.assertEqual(final["call_inventory"]["new_canary_calls"], 0)
            with self.assertRaises(FileExistsError):
                probe.execute(out, frozen, exchange=fake)
            self.assertEqual(fake.call_count, 60)

    def test_original_repairs_fit_forty_post_cap_with_no_extra_health_or_retry(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            texts, _, responses, runtime = self.project(root)
            out = root / "results/run"
            frozen = probe.freeze(out, runtime)["plan_sha256"]
            fake = self.exchange(texts, responses, invalid_first=True)
            report = probe.execute(out, frozen, exchange=fake)
            inventory = probe.read_json(out / "execution_final.json")["call_inventory"]
            self.assertEqual((inventory["post_attempts"], inventory["repair_posts"], inventory["health_gets"]), (40, 20, 40))
            for arm in probe.NEW_ARMS:
                self.assertEqual(report["by_arm"][arm]["initial_format_span_valid"], 0)
                self.assertEqual(report["by_arm"][arm]["initial_format_span_invalid"], 10)
                self.assertEqual(report["by_arm"][arm]["format_span_valid"], 10)
            events = [probe.read_json(p) for p in sorted(out.glob("transport_*.json"))]
            order = []
            for event in events:
                cell = {"text_index": event["text_index"], "arm": event["arm"]}
                if not order or order[-1] != cell:
                    order.append(cell)
            self.assertEqual(order, probe.generation_order())

    def test_missing_response_counts_stops_before_gold_and_keeps_failed_capture(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            texts, _, responses, runtime = self.project(root)
            out = root / "results/run"
            frozen = probe.freeze(out, runtime)["plan_sha256"]
            original = probe.read_json
            def no_gold(path):
                self.assertNotIn("evaluation", Path(path).name)
                return original(path)
            fake = self.exchange(texts, responses, broken_counts=True)
            with patch.object(probe, "read_json", side_effect=no_gold), self.assertRaisesRegex(ValueError, "cell_transport_or_count_failure"):
                probe.execute(out, frozen, exchange=fake)
            self.assertEqual(fake.call_count, 3)
            self.assertFalse((out / "prediction_phase_closed.json").exists())
            self.assertFalse((out / "report.json").exists())
            capture = original(out / "transport_003.json")
            self.assertEqual(capture["error_type"], "ValueError")
            self.assertIsNone(json.loads(capture["raw_response"])["eval_count"])
            self.assertFalse(original(out / "execution_final.json")["complete"])

    def test_client_rejects_order_changed_wires_duplicate_health_and_post_overrun(self):
        texts, _, _ = synthetic_materials()
        requests = probe.requests_for(texts, self.p)
        with tempfile.TemporaryDirectory() as temp:
            client = probe.BoundedClient(temp, requests, exchange=Mock(return_value=json.dumps(self.envelope())))
            with self.assertRaisesRegex(ValueError, "cell_order_or_duplicate"):
                client.begin_cell(1, "presence_zero")
            transport = client.begin_cell(1, "presence_15")
            with self.assertRaisesRegex(ValueError, "health_budget_or_order"):
                transport("GET", "/api/tags")
            transport("GET", "/api/version")
            transport("GET", "/api/tags")
            with self.assertRaisesRegex(ValueError, "health_budget_or_order"):
                transport("GET", "/api/version")
            changed = deepcopy(requests["1"]["presence_15"][0])
            changed["options"]["presence_penalty"] = True
            with self.assertRaisesRegex(ValueError, "actual_request_changed"):
                transport("POST", "/api/chat", changed)
            for body in requests["1"]["presence_15"]:
                transport("POST", "/api/chat", body)
            with self.assertRaisesRegex(ValueError, "generation_budget_or_path"):
                transport("POST", "/api/chat", requests["1"]["presence_15"][1])
            self.assertEqual(client.inventory()["post_attempts"], 2)

    def test_response_counts_reject_incomplete_model_or_bool_counts(self):
        for changes in ({"done": False}, {"done_reason": "length"}, {"model": "wrong"},
            {"prompt_eval_count": True}, {"eval_count": None}, {"eval_count": 1025},
            {"message": {"content": "{}", "thinking": "unexpected"}},
            {"message": {"content": "{}", "tool_calls": [{"x": 1}]}}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                probe.response_counts(self.envelope(**changes))

    def test_missing_repair_diagnostics_do_not_manufacture_initial_form_success(self):
        result = {"status": "ok", "errors": [], "local_calls": 2}
        self.assertEqual(probe.format_observation(result), (None, True))
        result["diagnostics"] = [{"attempt": 1, "stage": "output", "code": "invalid_span"}]
        self.assertEqual(probe.format_observation(result), (False, True))
        result["diagnostics"] = [{"attempt": True, "stage": "output", "code": "invalid_span"}]
        self.assertEqual(probe.format_observation(result), (None, True))

    def test_full_twenty_four_reference_validated_before_selected_id_scoring(self):
        texts, reference, responses = synthetic_materials()
        authority = probe.MemoryLabelAuthority(b"x" * 32)
        rows = []
        for i in probe.TEXT_IDS:
            rows.extend(probe.prepare_case(i, texts[i], self.p, {a: responses[i] for a in probe.ARMS}, authority))
        inventory = {"completed_cells": 20, "health_gets": 40, "post_attempts": 20,
            "complete_generation_responses": 20, "token_counts_complete": True}
        report = probe.score_rows(rows, reference, texts, inventory)
        self.assertTrue(report["effect_gate_passed"])
        changed = deepcopy(reference)
        changed["cases"][0]["text_sha256"] = "a" * 64  # ID 0 not in selected ten
        with self.assertRaises(ValueError):
            probe.score_rows(rows, changed, texts, inventory)
        altered = deepcopy(rows)
        altered[0]["cell"]["text_index"] = True
        with self.assertRaisesRegex(ValueError, "prediction_grid_incomplete"):
            probe.score_rows(altered, reference, texts, inventory)
        empty = deepcopy(rows)
        for row in empty:
            if row["cell"]["arm"] == "presence_zero":
                row["exact_protective_findings"] = []
        self.assertFalse(probe.score_rows(empty, reference, texts, inventory)["effect_gate_passed"])

    def test_unknown_mechanical_failure_is_not_semantic_success_and_no_mapping_logged(self):
        texts, reference, responses = synthetic_materials()
        rows, authority = [], probe.MemoryLabelAuthority(b"x" * 32)
        for i in probe.TEXT_IDS:
            source = {a: deepcopy(responses[i]) for a in probe.ARMS}
            if i == 13:
                source["presence_zero"].update(errors=["format_or_span_invalid"], local_calls=2)
            rows.extend(probe.prepare_case(i, texts[i], self.p, source, authority))
        report = probe.score_rows(rows, reference, texts, {"completed_cells": 20, "health_gets": 40,
            "post_attempts": 21, "complete_generation_responses": 21, "token_counts_complete": True})
        self.assertFalse(report["effect_gate_components"]["semantic_unknown_review"])
        self.assertLess(report["by_arm"]["presence_zero"]["format_span_valid"], 10)
        encoded = json.dumps(rows)
        for key in ('"mapping"', '"_entries"', '"secret"'):
            self.assertNotIn(key, encoded)

    def test_wall_and_network_guards_fail_before_any_real_request(self):
        texts, _, _ = synthetic_materials()
        with tempfile.TemporaryDirectory() as temp:
            client = probe.BoundedClient(temp, probe.requests_for(texts, self.p), now=Mock(side_effect=[0, 1801]))
            with self.assertRaisesRegex(ValueError, "wall_budget"):
                client.begin_cell(1, "presence_15")
        with probe.network_guard() as network:
            for action in (lambda: probe.socket.getaddrinfo("example.com", 443),
                lambda: probe.socket.socket.connect(None, ("127.0.0.1", 11436)),
                lambda: probe.socket.socket.connect_ex(None, ("127.0.0.1", 443))):
                with self.assertRaisesRegex(PermissionError, "network_destination_forbidden"):
                    action()
            self.assertEqual(network["blocked_connects"], 3)


if __name__ == "__main__":
    unittest.main()
