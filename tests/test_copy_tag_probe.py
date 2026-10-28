"""Synthetic offline contract tests; no real model, socket or corpus reference."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from scripts import run_copy_tag_probe as probe
from memory_migration_study.source_tagging import render_tagged
from tests.test_source_annotation_probe import synthetic_materials
from tests.test_relation_probe_scoring import policy, response


class CopyTagProbeTests(unittest.TestCase):
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

    @staticmethod
    def envelope(content="OK\nPlain text.", **updates):
        return {"content": content, "stop": True, "stop_type": "eos", "truncated": False,
                "tokens_evaluated": 20, "tokens_predicted": 12, **updates}

    def receipt(self):
        return {"endpoint": probe.ENDPOINT, "model_sha256": probe.MODEL_SHA256,
                "executable_sha256": "b" * 64, "n_ctx": 4096, "thinking": False,
                "canary": {"success": True, "generation_calls": 1}}

    def bundle(self, texts, receipt_hash=None):
        cases = []
        for i in probe.TEXT_IDS:
            c = probe.build_contract(texts[i])
            prompt = json.dumps({"fixture_index": i})
            messages = probe.build_messages(texts[i], self.p, c)
            cases.append({"text_index": i, "source_sha256": c["source_sha256"],
                "policy_sha256": probe.digest(self.p), "contract_sha256": c["contract_sha256"],
                "messages": messages, "prompt": prompt,
                "prompt_sha256": probe.text_sha(prompt), "token_count": 40,
                "apply_template_request": {"messages": deepcopy(messages)},
                "apply_template_response": {"prompt": prompt},
                "tokenize_request": {"content": prompt},
                "tokenize_response": {"tokens": list(range(40))}})
        return {"runtime_receipt_sha256": receipt_hash, "cases": cases}

    def requests(self):
        texts, _, _ = synthetic_materials()
        cases = probe.validate_compilation(self.receipt(), self.bundle(texts), texts, self.p)
        return probe.requests_for(cases, texts)

    def project(self, root):
        old, assets = root / "history", root / "assets"
        (old / "historical/historical").mkdir(parents=True)
        assets.mkdir()
        (root / "results").mkdir()
        (root / "frozen.py").write_text("frozen", encoding="utf-8")
        texts, reference, responses = synthetic_materials()
        probe.save(old / "historical/historical/runtime.json", {
            "schema_version": "relation_occurrence_probe_runtime_v1", "texts": texts})
        probe.save(old / "historical/historical/evaluation.opaque.json", reference)
        probe.save(old / "model_responses.json", responses)
        probe.save(old / "historical_conditional_responses.json", responses)
        probe.save(old / "plan.json", {"policy": self.p,
            "historical_conditional_sha256": probe.sha(old / "historical_conditional_responses.json"),
            "inputs": {"historical/" + name: probe.sha(old / "historical/historical" / name)
                for name in ("runtime.json", "evaluation.opaque.json")}})
        probe.save(old / "prediction_phase_closed.json", {"plan_sha256": probe.sha(old / "plan.json"),
            "reference_parsed": False, "rows": 72, "capture_sha256": {},
            "model_responses_sha256": probe.sha(old / "model_responses.json")})
        pins = {name: probe.sha(old / name) for name in probe.HISTORY_PINNED}
        probe.save(assets / "runtime.json", self.receipt())
        probe.save(assets / "prompts.json", self.bundle(texts, probe.sha(assets / "runtime.json")))
        for item in (patch.object(probe, "ROOT", root), patch.object(probe, "HISTORY", old),
                     patch.object(probe, "HISTORY_PINNED", pins),
                     patch.object(probe, "manifest", side_effect=lambda: {"frozen.py": probe.sha(root / "frozen.py")})):
            item.start()
            self.addCleanup(item.stop)
        return texts, reference, responses, assets

    def freeze(self, root, assets):
        output = root / "results/run"
        result = probe.freeze(output, assets / "runtime.json", assets / "prompts.json")
        return output, result["plan_sha256"]

    def test_messages_are_shared_policy_conditioned_label_free_and_grammar_is_only_arm_difference(self):
        text = "苔藓是客户；苔藓也是植物。"
        c = probe.build_contract(text)
        messages = probe.build_messages(text, self.p, c)
        self.assertIn("Trusted sensitivity policy", messages[0]["content"])
        self.assertNotIn("occurrence is", messages[0]["content"])
        self.assertEqual(json.loads(messages[1]["content"])["text"], text)
        self.assertNotIn("findings", json.loads(messages[1]["content"]))
        self.assertTrue(probe.header_grammar(c).startswith('root ::= ("OK\\n" | "REVIEW\\n") tag-body\n'))
        self.assertEqual(probe.header_grammar(c).count("root ::="), 1)
        requests = self.requests()
        for i in probe.TEXT_IDS:
            free, constrained = requests[str(i)]["free_tag"], deepcopy(requests[str(i)]["constrained_tag"])
            self.assertNotIn("grammar", free)
            self.assertIn("grammar", constrained)
            constrained.pop("grammar")
            self.assertEqual(free, constrained)

    def test_exact_source_parser_keeps_unicode_whitespace_and_occurrences(self):
        text = " moss 苔藓 e\u0301\n苔藓\r\n"
        c = probe.build_contract(text)
        start = text.rindex("苔藓")
        tagged = render_tagged(text, [(start, start + 2)], c)
        parsed = probe.parse_response(text, self.envelope("OK\n" + tagged), c)
        self.assertEqual(parsed["status"], "ok")
        self.assertEqual(parsed["findings"], [{"start": start, "end": start + 2, "quote": "苔藓", "category": "CUSTOMER"}])
        self.assertTrue(parsed["copy_verified"])
        self.assertFalse(parsed["authorization_granted"])
        for changed in (tagged.strip(), tagged.replace("e\u0301", "é"), tagged + "\n"):
            self.assertFalse(probe.parse_response(text, self.envelope("OK\n" + changed), c)["copy_verified"])

    def test_review_header_is_semantic_and_copy_failure_is_not_semantic_review(self):
        text, c = "Plain text.", probe.build_contract("Plain text.")
        reviewed = probe.parse_response(text, self.envelope("REVIEW\n" + text), c)
        self.assertEqual(reviewed["errors"], ["semantic_uncertainty"])
        self.assertTrue(reviewed["copy_verified"])
        broken = probe.parse_response(text, self.envelope("REVIEW\nPlain tex."), c)
        self.assertEqual(broken["status"], "needs_review")
        self.assertNotEqual(broken["errors"], ["semantic_uncertainty"])
        for raw in ("OK", "ok\n" + text, "OK\r\n" + text, " OK\n" + text):
            self.assertEqual(probe.parse_response(text, self.envelope(raw), c)["errors"], ["invalid_tag_header"])

    def test_runtime_receipt_and_token_budget_fail_closed(self):
        texts, _, _ = synthetic_materials()
        for key, value in (("endpoint", "http://127.0.0.1:11435"), ("model_sha256", "a" * 64),
                           ("thinking", True), ("n_ctx", 4097), ("executable_sha256", "missing"),
                           ("executable_sha256", None), ("canary", []),
                           ("canary", {"success": True, "generation_calls": True})):
            with self.subTest(key=key):
                r = {**self.receipt(), key: value}
                with self.assertRaisesRegex(ValueError, "runtime_not_qualified"):
                    probe.validate_compilation(r, self.bundle(texts), texts, self.p)
        for key, value in (("token_count", True), ("token_count", 3073),
                           ("source_sha256", "b" * 64), ("policy_sha256", "c" * 64),
                           ("contract_sha256", "c" * 64), ("messages", [])):
            bundle = self.bundle(texts)
            bundle["cases"][0][key] = value
            with self.assertRaisesRegex(ValueError, "prompt_binding_or_budget"):
                probe.validate_compilation(self.receipt(), bundle, texts, self.p)

    def test_client_enforces_one_call_per_cell_exact_bytes_16_posts_and_wall(self):
        with tempfile.TemporaryDirectory() as temp:
            requests = self.requests()
            exchange = Mock(return_value=json.dumps(self.envelope()))
            client = probe.BoundedClient(temp, requests, exchange=exchange)
            changed = {**requests["1"]["free_tag"], "temperature": 0.0}
            with self.assertRaisesRegex(ValueError, "actual_request_changed"):
                client.call(1, "free_tag", changed)
            with self.assertRaisesRegex(ValueError, "generation_order_changed"):
                client.call(1, "constrained_tag", requests["1"]["constrained_tag"])
            for cell in probe.generation_order():
                i, arm = cell["text_index"], cell["arm"]
                client.call(i, arm, requests[str(i)][arm])
            self.assertEqual(exchange.call_count, 16)
            with self.assertRaisesRegex(ValueError, "generation_budget_or_duplicate"):
                client.call(1, "free_tag", requests["1"]["free_tag"])
            self.assertEqual(client.inventory()["post_attempts"], 16)
            self.assertEqual(client.inventory()["generation_order"], probe.generation_order())
            first_arms = [probe.generation_order()[2 * i]["arm"] for i in range(8)]
            self.assertEqual(first_arms.count("free_tag"), 4)
            self.assertEqual(first_arms.count("constrained_tag"), 4)
            client.close()
            with self.assertRaisesRegex(ValueError, "client_closed"):
                client.call(1, "free_tag", requests["1"]["free_tag"])
        with tempfile.TemporaryDirectory() as temp:
            now = Mock(side_effect=[0, 1801])
            client = probe.BoundedClient(temp, self.requests(), exchange=exchange, now=now)
            with self.assertRaisesRegex(ValueError, "wall_budget"):
                client.call(1, "free_tag", client.requests["1"]["free_tag"])

    def test_actual_template_and_tokenization_captures_must_match(self):
        texts, _, _ = synthetic_materials()
        for key, value in (("apply_template_request", {"messages": []}),
                           ("apply_template_response", {"prompt": "wrong"}),
                           ("tokenize_request", {"content": "wrong"}),
                           ("tokenize_response", {"tokens": [1] * 39}),
                           ("tokenize_response", {"tokens": [True] * 40})):
            with self.subTest(key=key):
                bundle = self.bundle(texts)
                bundle["cases"][0][key] = value
                with self.assertRaisesRegex(ValueError, "template_or_tokenization_evidence_mismatch"):
                    probe.validate_compilation(self.receipt(), bundle, texts, self.p)

    def test_missing_incomplete_or_bad_counts_are_saved_and_cannot_be_repaired(self):
        bad = [{"content": "OK\nx"}, self.envelope(stop=False), self.envelope(stopped_limit=True),
               self.envelope(tokens_predicted=1025), self.envelope(tokens_evaluated=True),
               self.envelope(tokens_predicted=-1), self.envelope(truncated=True)]
        for value in bad:
            with self.subTest(value=value), tempfile.TemporaryDirectory() as temp:
                requests = self.requests()
                client = probe.BoundedClient(temp, requests, exchange=Mock(return_value=json.dumps(value)))
                with self.assertRaises(ValueError):
                    client.call(1, "free_tag", requests["1"]["free_tag"])
                event = probe.read_json(Path(temp) / "transport_001.json")
                self.assertEqual(json.loads(event["raw_response"]), value)
                self.assertFalse(client.inventory()["token_counts_complete"])
                with self.assertRaisesRegex(ValueError, "generation_budget_or_duplicate"):
                    client.call(1, "free_tag", requests["1"]["free_tag"])
        self.assertEqual(probe.response_counts({"content": "OK\nx", "stop": True,
            "stop_type": "eos", "truncated": False,
            "timings": {"prompt_n": 2, "predicted_n": 3}}), (2, 3))

    def test_new_and_legacy_completion_reasons_are_explicit(self):
        for reason in ("eos", "word"):
            self.assertEqual(probe.response_counts(self.envelope(stop_type=reason)), (20, 12))
        legacy = self.envelope()
        legacy.pop("stop_type")
        legacy.update(stopped_limit=False, stopped_eos=True, stopped_word=False)
        self.assertEqual(probe.response_counts(legacy), (20, 12))
        for changed in (self.envelope(stop_type="limit"), self.envelope(stop_type="unknown"),
                        self.envelope(stop_type=None), self.envelope(truncated=None),
                        {k: v for k, v in self.envelope().items() if k != "stop_type"},
                        {k: v for k, v in self.envelope().items() if k != "truncated"},
                        {**legacy, "stopped_eos": False}, {**legacy, "stopped_limit": True}):
            with self.subTest(changed=changed):
                with self.assertRaisesRegex(ValueError, "incomplete_generation_envelope"):
                    probe.response_counts(changed)

    def test_four_real_preparations_use_empty_labels_exact_footprints_and_acl(self):
        text = "Maple Ltd is our client. Paper style is matte."
        c = probe.build_contract(text)
        tag = render_tagged(text, [(0, 9)], c)
        new = probe.parse_response(text, self.envelope("OK\n" + tag), c)
        results = {"free_tag": new, "constrained_tag": new,
                   "qwen35_quote": response(text), "qwen3_conditional": response(text, "Maple Ltd")}
        rows = probe.prepare_case(1, text, self.p, results, self.authority)
        self.assertEqual([len(r["exact_protective_findings"]) for r in rows], [1, 1, 0, 1])
        self.assertTrue(all(r["record"]["label"]["findings"] == [] for r in rows))
        self.assertTrue(all(r["preparation"]["metadata"]["transfer_mode"] == "migration" for r in rows))
        self.assertEqual(rows[1]["preparation"]["actual_mask_intervals"], [[0, 9]])
        self.assertTrue(all(len(r["preparation"]["acl_negative_controls"]) == 2 for r in rows))
        encoded = json.dumps(rows)
        self.assertNotIn('"mapping"', encoded)
        self.assertNotIn('"_entries"', encoded)
        self.assertNotIn('"secret"', encoded)

    def score_fixture(self, *, empty=False, mechanical_unknown=False):
        texts, reference, receivers = synthetic_materials()
        rows = []
        for i in probe.TEXT_IDS:
            new = {**deepcopy(receivers[i]), "copy_verified": True}
            if empty:
                new.update(findings=[], status="ok", errors=[])
            if mechanical_unknown and i == 13:
                new.update(status="needs_review", errors=["source_copy_mismatch"], copy_verified=False)
            results = {"free_tag": new, "constrained_tag": new,
                       "qwen35_quote": receivers[i], "qwen3_conditional": receivers[i]}
            rows.extend(probe.prepare_case(i, texts[i], self.p, results, self.authority))
        inventory = {"post_attempts": 16, "token_counts_complete": True, "complete_generation_responses": 16,
                     "generation_order": probe.generation_order()}
        return probe.score_rows(rows, reference, texts, inventory), rows, texts, reference

    def test_scoring_validates_full24_original_ids_and_copy_only_cannot_pass_effect_gate(self):
        scored, rows, texts, reference = self.score_fixture()
        self.assertTrue(scored["mechanism_gate_passed"])
        self.assertTrue(scored["effect_gate_passed"])
        self.assertTrue(scored["proceed_full24"])
        self.assertEqual(scored["by_arm"]["constrained_tag"]["unknown"], 3)
        self.assertIsNone(scored["refusal_rate"])
        self.assertIsNone(scored["independent_acceptance_passed"])
        empty, *_ = self.score_fixture(empty=True)
        self.assertTrue(empty["mechanism_gate_passed"])
        self.assertFalse(empty["effect_gate_passed"])
        self.assertFalse(empty["proceed_full24"])
        self.assertGreater(empty["by_arm"]["constrained_tag"]["prepared_incomplete_spans"], 0)
        changed = deepcopy(reference)
        changed["cases"][0]["text_sha256"] = "a" * 64  # outside selected IDs, still checked
        with self.assertRaises(ValueError):
            probe.score_rows(rows, changed, texts, {"post_attempts": 16})
        with self.assertRaisesRegex(ValueError, "prediction_grid_incomplete"):
            probe.score_rows(rows[:-1], reference, texts, {})

    def test_copy_failure_on_unknown_is_not_scored_as_semantic_success(self):
        scored, *_ = self.score_fixture(mechanical_unknown=True)
        group = scored["by_arm"]["constrained_tag"]
        self.assertEqual(group["unknown_blocked"], 3)
        self.assertEqual(group["semantic_unknown_review"], 2)
        self.assertFalse(scored["effect_gate_components"]["semantic_unknown_review"])
        self.assertFalse(scored["mechanism_gate_passed"])

    def test_freeze_verify_reject_drift_without_reference_parse_or_http(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            _, _, _, assets = self.project(root)
            original = probe.read_json
            def no_gold(path):
                self.assertNotIn("evaluation", Path(path).name)
                return original(path)
            with patch.object(probe, "read_json", side_effect=no_gold):
                output, frozen = self.freeze(root, assets)
                plan, texts, requests = probe.verify(output, frozen)
                self.assertEqual((len(texts), len(requests)), (24, 8))
                self.assertFalse(plan["reference_parsed"])
                with self.assertRaisesRegex(ValueError, "output_scope_or_exists"):
                    probe.freeze(output, assets / "runtime.json", assets / "prompts.json")
                (output / "contracts.json").write_text("{}", encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "frozen_artifact_changed"):
                    probe.verify(output, frozen)

    def test_historical_roots_checked_before_any_saved_response_parse(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.project(root)
            (probe.HISTORY / "plan.json").write_text("{}", encoding="utf-8")
            with patch.object(probe, "read_json") as reader:
                with self.assertRaisesRegex(ValueError, "historical_roots_changed"):
                    probe.historical_inputs()
                reader.assert_not_called()

    def test_network_guard_refuses_dns_and_connect_ex_without_real_socket(self):
        with probe.network_guard() as stats:
            for action in (lambda: probe.socket.getaddrinfo("example.com", 443),
                           lambda: probe.socket.socket.connect(None, ("127.0.0.1", 11435)),
                           lambda: probe.socket.socket.connect_ex(None, ("127.0.0.1", 443))):
                with self.assertRaisesRegex(PermissionError, "network_destination_forbidden"):
                    action()
            self.assertEqual(stats["blocked_connects"], 3)
            self.assertEqual(stats["allowed_connects"], 0)

    def test_execute_closes_all32_before_reference_and_reexecution_is_blocked(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            texts, _, receivers, assets = self.project(root)
            output, frozen = self.freeze(root, assets)
            original = probe.read_json
            def no_early_gold(path):
                if "evaluation" in Path(path).name:
                    closed = original(output / "prediction_phase_closed.json")
                    self.assertEqual(closed["rows"], 32)
                    self.assertEqual(len(list(output.glob("transport_*.json"))), 16)
                return original(path)
            def exchange(body, event):
                i = json.loads(body["prompt"])["fixture_index"]
                spans = [(f["start"], f["end"]) for f in receivers[i]["findings"]]
                header = "REVIEW" if receivers[i]["status"] == "needs_review" else "OK"
                return json.dumps(self.envelope(header + "\n" + render_tagged(texts[i], spans)))
            mock = Mock(side_effect=exchange)
            with patch.object(probe, "read_json", side_effect=no_early_gold):
                report = probe.execute(output, frozen, exchange=mock)
            self.assertEqual(mock.call_count, 16)
            self.assertEqual([{"text_index": call.args[1]["text_index"], "arm": call.args[1]["arm"]}
                              for call in mock.call_args_list], probe.generation_order())
            self.assertTrue(report["proceed_full24"])
            final = original(output / "execution_final.json")
            self.assertTrue(final["complete"])
            self.assertEqual(final["unobserved_rows"], 0)
            self.assertEqual(original(output / "report.json")["call_inventory"]["cloud_calls"], 0)
            with self.assertRaises(FileExistsError):
                probe.execute(output, frozen, exchange=mock)
            self.assertEqual(mock.call_count, 16)

    def test_transport_failure_stops_prefix_without_reference_or_score(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            _, _, _, assets = self.project(root)
            output, frozen = self.freeze(root, assets)
            original = probe.read_json
            def no_gold(path):
                self.assertNotIn("evaluation", Path(path).name)
                return original(path)
            mock = Mock(return_value=json.dumps(self.envelope(tokens_evaluated=None)))
            with patch.object(probe, "read_json", side_effect=no_gold):
                with self.assertRaisesRegex(ValueError, "actual_token_budget_or_count_missing"):
                    probe.execute(output, frozen, exchange=mock)
            self.assertEqual(mock.call_count, 1)
            self.assertFalse((output / "prediction_phase_closed.json").exists())
            self.assertFalse((output / "report.json").exists())
            final = original(output / "execution_final.json")
            self.assertFalse(final["complete"])
            self.assertEqual(final["unobserved_rows"], 32)
            self.assertEqual(final["call_inventory"]["post_attempts"], 1)


if __name__ == "__main__":
    unittest.main()
