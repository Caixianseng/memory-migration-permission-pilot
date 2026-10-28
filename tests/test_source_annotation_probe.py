"""Offline source probe checks: fake runtime/transport, no real model or corpus gold."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from scripts import run_source_annotation_probe as probe
from memory_migration_study.memory_labels import restore_labeled_answer, prepare_labeled_transfer
from memory_migration_study.sensitivity_contract import category_contract
from tests.test_relation_probe_scoring import policy, response


class FakeAgent:
    max_local_calls = 2

    def __init__(self, result):
        self.result, self.inputs = result, []

    def __call__(self, **kwargs):
        self.inputs.append(deepcopy(kwargs))
        return deepcopy(self.result)


def synthetic_materials():
    texts, cases, receivers = [], [], []
    for i in range(24):
        name, fact = "Fixture Office " + str(i), "Paper style is matte " + str(i) + "."
        unknown = i in {1, 7, 13, 19}
        text = name + (" has an unknown customer relation. " if unknown else " is our customer. ") + fact
        texts.append(text)
        expected = {}
        for profile in probe.scoring.PROFILES:
            decision = "needs_review" if unknown and profile == probe.base.PROFILE else "sensitive"
            spans = [] if decision == "needs_review" else [{"start": 0, "end": len(name), "category": "CUSTOMER", "text": name}]
            expected[profile] = {"decision": decision, "spans": spans, "must_mask_values": [] if not spans else [name]}
        cases.append({"text_index": i, "text_sha256": probe.scoring._text_hash(text), "expected": expected,
            "allowed_fact": {"slot_id": "format", "text": fact, "start": text.index(fact),
                             "end": len(text), "match": "exact_substring"}})
        receivers.append(response(text, None if unknown else name,
            status="needs_review" if unknown else "ok", errors=["semantic_uncertainty"] if unknown else []))
    reference = {"schema_version": "relation_occurrence_probe_evaluation_v1", "runtime_sha256": probe.scoring._runtime_hash(texts),
        "profile_contract_sha256": {p: probe.scoring._hash(category_contract(p)) for p in probe.scoring.PROFILES}, "cases": cases}
    return texts, reference, receivers


class SourceAnnotationProbeTests(unittest.TestCase):
    def setUp(self):
        self.network = []
        for name in ("socket.socket", "socket.create_connection", "urllib.request.urlopen"):
            guard = patch(name, side_effect=AssertionError("network_forbidden"))
            self.network.append(guard.start())
            self.addCleanup(guard.stop)
        self.p = policy(probe.base.PROFILE)
        self.authority = probe.MemoryLabelAuthority(b"x" * 32)

    def tearDown(self):
        for guard in self.network:
            guard.assert_not_called()

    def case(self, text, source, receiver=None, index=0):
        agent = FakeAgent(source)
        annotation, rows = probe.observe_case(index, text, self.p, receiver or source,
                                              agent=agent, authority=self.authority)
        return annotation, rows, agent

    def test_empty_source_and_unknown_fail_closed_without_clean_signed_record(self):
        annotation, rows, agent = self.case("", response(""))
        self.assertEqual(agent.inputs, [])
        self.assertEqual(annotation["records"], [])
        self.assertTrue(all(r["status"] == "blocked" for r in rows))
        text = "Larch is our customer. Paper is matte."
        source = response(text, status="needs_review", errors=["semantic_uncertainty"])
        annotation, rows, _ = self.case(text, source, response(text, "Larch"))
        self.assertEqual(annotation["records"], [])
        self.assertEqual([r["status"] for r in rows], ["ok", "blocked", "blocked"])
        self.assertEqual(probe.comparison_signature(rows[1]), probe.comparison_signature(rows[2]))

    def test_full_text_source_only_inputs_and_signed_roundtrip_three_arms(self):
        text = "Larch is our customer. Paper is matte."
        annotation, rows, agent = self.case(text, response(text, "Larch"), response(text))
        self.assertEqual(len(agent.inputs), 1)
        self.assertEqual(agent.inputs[0]["text"], text)
        self.assertEqual(set(agent.inputs[0]), {"text", "source_id", "policy", "rule_findings"})
        self.assertEqual(agent.inputs[0]["rule_findings"], [])
        self.assertEqual(annotation["records"][0]["text"], text)
        self.assertEqual(rows[0]["exact_protective_findings"], [])
        self.assertEqual(rows[0]["record"]["label"]["findings"], [])
        self.assertEqual(rows[2]["record"]["label"]["findings"], [])
        self.assertEqual(probe.comparison_signature(rows[1]), probe.comparison_signature(rows[2]))
        for row in rows:
            self.assertEqual(row["new_target_posts"], 0)
            self.assertEqual(len(row["preparation"]["acl_negative_controls"]), 2)
        encoded = json.dumps({"annotation": annotation, "rows": rows}, allow_nan=False)
        for prohibited in ('"mapping"', '"_entries"', '"secret"', '"principal_binding"'):
            self.assertNotIn(prohibited, encoded)

    def test_empty_source_findings_still_assessed_and_receiver_unknown_stays_blocked(self):
        text = "Larch is an organization. Paper is matte."
        receiver = response(text, status="needs_review", errors=["semantic_uncertainty"])
        annotation, rows, _ = self.case(text, response(text), receiver)
        self.assertEqual(annotation["status"], "ok")
        self.assertEqual(annotation["annotation_state"], "observed_empty")
        self.assertFalse(annotation["projection"]["semantic_completeness_proven"])
        self.assertTrue(all(r["status"] != "ok" for r in rows))

    def test_tampered_content_blocked_and_revocation_before_restore(self):
        text = "Larch is our customer. Paper is matte."
        annotation, rows, _ = self.case(text, response(text, "Larch"))
        record = annotation["records"][0]
        changed = deepcopy(record)
        changed["text"] += " Changed"
        result = probe.prepare_record(text, changed, self.p, response(text, "Larch"),
            authority=self.authority, mode="two_stage", request_id="tampered")
        self.assertEqual(result["status"], "blocked")
        self.assertIsNone(result["payload"])
        replay = probe.scoring.ReplayDetector(text, record["record_id"], self.p, response(text, "Larch"))
        prepared = prepare_labeled_transfer([record], "", self.p, authority=self.authority,
            actor_id=probe.ACTOR, agent_id=probe.TARGET_AGENT, request_id="revoke", mode="two_stage", agent=replay)
        self.assertEqual(prepared["status"], "ok")
        self.authority.revoke(record["record_id"])
        restored = restore_labeled_answer(prepared["payload"]["memories"][0]["text"], prepared, [record], self.p,
            authority=self.authority, actor_id=probe.ACTOR, agent_id=probe.TARGET_AGENT, request_id="revoke")
        self.assertEqual(restored["status"], "blocked")

    def test_exact_labels_and_actual_repeat_expansion_are_separate(self):
        text = "Moss is our customer. moss describes a plant. Paper is matte."
        _, rows, _ = self.case(text, response(text, "Moss"), response(text))
        row = rows[1]
        self.assertEqual(len(row["exact_protective_findings"]), 1)
        self.assertEqual(len(row["preparation"]["actual_mask_intervals"]), 2)
        # Deliberately leave a matching string visible in a synthetic scored payload;
        # the declared original position footprint is the only scoring input.
        row["preparation"]["payload"]["memories"][0]["text"] += " Moss"
        truth = {"decision": "sensitive", "spans": [{"start": 0, "end": 4, "text": "Moss", "category": "CUSTOMER"}]}
        a = text.index("moss")
        values = probe.span_score(text, row, truth, {"start": a, "end": a+4})
        self.assertEqual(values["fully_masked_spans"], 1)
        self.assertEqual(values["allowed_fact_retained"], 0)
        self.assertEqual(values["raw_predicted_protective_tp"], 1)
        self.assertEqual(values["raw_predicted_protective_fp"], 0)
        self.assertEqual(values["actual_masked_unprotected_chars"], 4)
        self.assertEqual(values["known_prepared_with_unprotected_masking"], 1)

    def test_complete_72_row_score_preserves_denominators_and_strong_baseline(self):
        texts, reference, receivers = synthetic_materials()
        rows = []
        for i, text in enumerate(texts):
            _, case_rows, _ = self.case(text, receivers[i], receivers[i], index=i)
            rows.extend(case_rows)
        result = probe.score_rows(rows, reference, texts)
        self.assertTrue(result["union_comparison"]["equivalent"])
        for arm in probe.ARMS:
            group = result["by_arm"][arm]
            self.assertEqual((group["total"], group["known"], group["unknown"]), (24, 20, 4))
            self.assertEqual((group["known_prepared"], group["semantic_unknown_review"],
                              group["raw_predicted_protective_tp"], group["raw_predicted_protective_fn"]), (20, 4, 20, 0))
            self.assertEqual(group["unknown_blocked"], 4)
            self.assertEqual(group["unknown_blocked_without_semantic_uncertainty"], 0)
            self.assertEqual(group["allowed_fact_retained"], 20)
        self.assertEqual(set(result["case22"]), set(probe.ARMS))
        with self.assertRaisesRegex(ValueError, "grid_incomplete"):
            probe.score_rows(rows[:-1], reference, texts)

    def test_source_failure_remains_in_full_denominator_and_cannot_remove_receiver_fp(self):
        texts, reference, receivers = synthetic_materials()
        rows = []
        for i, text in enumerate(texts):
            source = receivers[i] if i else response(text, status="needs_review", errors=["semantic_uncertainty"])
            _, case_rows, _ = self.case(text, source, receivers[i], index=i)
            rows.extend(case_rows)
        result = probe.score_rows(rows, reference, texts)
        self.assertEqual(result["by_arm"]["source_label_transfer"]["known_prepared"], 19)
        self.assertEqual(result["by_arm"]["source_label_transfer"]["total"], 24)
        self.assertTrue(result["union_comparison"]["equivalent"])
        self.assertFalse(result["development_gate_passed"])
        text = "Moss is not our customer. Paper is matte."
        _, case_rows, _ = self.case(text, response(text), response(text, "Moss"))
        truth = {"decision": "not_sensitive", "spans": []}
        scores = [probe.span_score(text, row, truth, {"start": text.index("Paper"), "end": len(text)}) for row in case_rows]
        self.assertEqual([v["raw_predicted_protective_fp"] for v in scores], [1, 1, 1])

    def test_engineering_failure_is_blocked_but_not_semantic_unknown_success(self):
        text = "Larch is an organization. Paper is matte."
        technical = response(text, status="needs_review", errors=["local_health_failed"], calls=0)
        _, rows, _ = self.case(text, technical, technical)
        truth = {"decision": "needs_review", "spans": []}
        for row in rows:
            score = probe.span_score(text, row, truth, {"start": text.index("Paper"), "end": len(text)})
            self.assertEqual(score["unknown_blocked"], 1)
            self.assertEqual(score["semantic_unknown_review"], 0)
            self.assertEqual(score["unknown_blocked_without_semantic_uncertainty"], 1)
            self.assertIn("local_health_failed", row["block_reasons"])

    def test_fixed_bounded_client_and_audit_guard_reject_extra_or_external_work(self):
        with tempfile.TemporaryDirectory() as temp:
            client = probe.BoundedClient(Path(temp), exchange=Mock(return_value="{}"))
            body = {"model": probe.base.MODEL, "options": deepcopy(probe.base.OPTIONS)}
            client.begin_text(0)
            client("POST", "/api/chat", body)
            client("POST", "/api/chat", body)
            with self.assertRaisesRegex(ValueError, "source_generation_budget"):
                client("POST", "/api/chat", body)
            client.begin_text(1)
            client.posts = 48
            with self.assertRaisesRegex(ValueError, "source_generation_budget"):
                client("POST", "/api/chat", body)
            self.assertEqual(client.exchange.call_count, 2)
        network = {"loopback_connects": 0, "blocked_connects": 0}
        with patch.object(probe.sys, "addaudithook") as install:
            probe.install_network_guard(network)
        guard = install.call_args.args[0]
        guard("socket.connect", (None, ("127.0.0.1", 11435)))
        with self.assertRaisesRegex(RuntimeError, "external_network_forbidden"):
            guard("socket.connect", (None, ("example.com", 443)))
        self.assertEqual(network, {"loopback_connects": 1, "blocked_connects": 1})

    def mock_frozen_project(self, root):
        old = root / "old"
        old.mkdir()
        (root / "results").mkdir()
        (root / "code.py").write_text("frozen source", encoding="utf-8")
        texts, reference, receivers = synthetic_materials()
        runtime = {"schema_version": "relation_occurrence_probe_runtime_v1", "texts": texts}
        (old / "runtime.json").write_text(json.dumps(runtime, indent=2) + "\n", encoding="utf-8")
        probe.save(old / "evaluation.opaque.json", reference)
        predictions = [{"cell": {"text_index": i, "profile": probe.base.PROFILE, "arm": arm}, "response": r}
                       for i, r in enumerate(receivers) for arm in ("plain", "conditional")]
        probe.save(old / "predictions.json", predictions)
        probe.save(old / "plan.json", {"runtime_sha256": probe.sha(old / "runtime.json"),
            "reference_sha256": probe.sha(old / "evaluation.opaque.json"), "policy": self.p})
        probe.save(old / "prediction_phase_closed.json", {"plan_sha256": probe.sha(old / "plan.json"),
            "predictions_sha256": probe.sha(old / "predictions.json"), "reference_parsed": False, "rows": 48})
        pins = {name: probe.sha(old / name) for name in probe.PINNED}
        patches = [patch.object(probe, "ROOT", root), patch.object(probe, "OLD", old),
                   patch.object(probe, "PINNED", pins),
                   patch.object(probe, "manifest", side_effect=lambda: {"code.py": probe.sha(root / "code.py")})]
        for item in patches:
            item.start()
            self.addCleanup(item.stop)
        return texts, reference, receivers

    def test_freeze_and_verify_hashes_without_parsing_reference_and_refuse_drift(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.mock_frozen_project(root)
            original = probe.read_json
            def no_gold(path):
                self.assertNotIn("evaluation", Path(path).name)
                return original(path)
            with patch.object(probe, "read_json", side_effect=no_gold):
                output = root / "results/run"
                frozen = probe.freeze(output)
                probe.verify(output, frozen["plan_sha256"])
                with self.assertRaisesRegex(ValueError, "output_scope_or_exists"):
                    probe.freeze(output)
                (root / "code.py").write_text("drift", encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "frozen_contract_changed"):
                    probe.verify(output, frozen["plan_sha256"])

    def test_reference_reader_requires_closed_hashes_before_any_gold_read(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp)
            with patch.object(probe, "read_json", wraps=probe.read_json) as reader:
                with self.assertRaises(FileNotFoundError):
                    probe.load_closed_reference(output, "expected")
                self.assertEqual([Path(c.args[0]).name for c in reader.call_args_list], ["prediction_phase_closed.json"])
            probe.save(output / "predictions.json", [])
            probe.save(output / "source_annotations.json", [])
            probe.save(output / "prediction_phase_closed.json", {"plan_sha256": "expected", "reference_parsed": False,
                "rows": 72, "predictions_sha256": "tampered", "source_annotations_sha256": "tampered", "capture_sha256": {}})
            with patch.object(probe, "read_json", wraps=probe.read_json) as reader:
                with self.assertRaisesRegex(ValueError, "closed_prediction_changed"):
                    probe.load_closed_reference(output, "expected")
                self.assertEqual(len(reader.call_args_list), 1)

    def test_mock_execute_closes_all_rows_before_gold_and_uses_no_target_calls(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            texts, _, receivers = self.mock_frozen_project(root)
            output = root / "results/run"
            frozen = probe.freeze(output)
            client = probe.BoundedClient(output, exchange=Mock(return_value="{}"))
            by_text = dict(zip(texts, receivers))
            class Runtime:
                max_local_calls = 2
                def __call__(self, **kwargs):
                    client("POST", "/api/chat", {"model": probe.base.MODEL, "options": deepcopy(probe.base.OPTIONS),
                        "messages": [{"role": "user", "content": kwargs["text"]}]})
                    return deepcopy(by_text[kwargs["text"]])
            original = probe.read_json
            evaluation_reads = []
            def closed_only(path):
                if Path(path).name == "evaluation.opaque.json":
                    self.assertTrue(client.closed)
                    self.assertTrue((output / "prediction_phase_closed.json").is_file())
                    self.assertEqual(len(original(output / "predictions.json")), 72)
                    evaluation_reads.append(str(path))
                return original(path)
            with patch.object(probe, "BoundedClient", return_value=client), patch.object(probe, "OccurrenceQwenAgent", return_value=Runtime()), \
                    patch.object(probe, "install_network_guard"), patch.object(probe, "read_json", side_effect=closed_only):
                report = probe.execute(output, frozen["plan_sha256"])
            self.assertEqual(len(evaluation_reads), 1)
            self.assertEqual(report["status"], "complete")
            self.assertEqual((report["source_generation_posts"], report["new_target_posts"]), (24, 0))
            self.assertTrue(report["union_comparison"]["equivalent"])
            self.assertEqual(len(list(output.glob("transport_*.json"))), 24)


if __name__ == "__main__":
    unittest.main()
