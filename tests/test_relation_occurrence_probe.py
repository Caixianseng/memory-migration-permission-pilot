"""Synthetic driver contracts only; no real material, model or reference is read."""
from contextlib import contextmanager
from copy import deepcopy
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from scripts import run_relation_occurrence_probe as probe


class RelationOccurrenceProbeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.number = 0

    @contextmanager
    def frozen_case(self):
        self.number += 1
        root = self.root / str(self.number)
        root.mkdir()
        material = root / "synthetic-material"
        material.mkdir()
        texts = ["Synthetic statement " + str(index) + "." for index in range(12)]
        probe.common.save(material / "runtime.json", {
            "schema_version": "relation_occurrence_probe_runtime_v1", "texts": texts})
        opaque = b"Deliberately invalid JSON: reference must remain opaque before closure."
        (material / "evaluation.json").write_bytes(opaque)
        prereg = root / "prereg.md"
        prereg.write_text("Synthetic offline preregistration", encoding="utf-8")
        source = root / "fixture.py"
        source.write_text("# frozen synthetic source\n", encoding="utf-8")
        output = root / "run"
        nli = SimpleNamespace(health=lambda: {"identity": "synthetic-no-model"})
        with patch.object(probe, "ROOT", root), \
             patch.object(probe, "source_hashes", side_effect=lambda: {"fixture.py": probe.common.sha(source)}), \
             patch.object(probe.common, "checked_assets", return_value={"fixture": "no-model-assets"}), \
             patch.object(probe, "PinnedNLIRuntime", return_value=nli), \
             patch.object(probe, "LocalNerRuntime", side_effect=AssertionError("model loading forbidden")):
            result = probe.freeze(output, material, prereg)
            yield SimpleNamespace(output=output, material=material, texts=texts, source=source,
                                  opaque=opaque, plan_hash=result["plan_sha256"], result=result)

    def test_freeze_and_verify_keep_invalid_json_reference_opaque_without_model_loading(self):
        with self.frozen_case() as fixture:
            self.assertEqual(fixture.result["model_calls"], 0)
            self.assertEqual((fixture.output / "evaluation.opaque.json").read_bytes(), fixture.opaque)
            plan, texts = probe.verify(fixture.output, fixture.plan_hash)
            self.assertEqual(texts, fixture.texts)
            self.assertEqual(plan["limits"]["qwen_posts"], 48)
            self.assertEqual(len(plan["qwen_preflight"]), 24)
            self.assertTrue(all(row["fits"] for row in plan["qwen_preflight"]))
            self.assertFalse((fixture.output / "execution.json").exists())

    def test_input_source_or_archive_changes_are_rejected(self):
        for variant in ("input", "source", "archive"):
            with self.subTest(variant=variant), self.frozen_case() as fixture:
                if variant == "input":
                    path = fixture.output / "runtime.json"
                    path.write_bytes(path.read_bytes() + b" ")
                elif variant == "source":
                    fixture.source.write_text("# changed current source\n", encoding="utf-8")
                else:
                    (fixture.output / "implementation/fixture.py").write_text("# changed archive\n", encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "material_changed|source_changed|frozen_implementation_archive_changed"):
                    probe.verify(fixture.output, fixture.plan_hash)

    def test_post48_and_wall_limits_reject_before_an_extra_attempt(self):
        now = [0.0]
        with patch.object(probe.time, "monotonic", side_effect=lambda: now[0]):
            budget = probe.Budget()
            for _ in range(48):
                budget.generation()
            with self.assertRaisesRegex(ValueError, "post_budget_exceeded"):
                budget.generation()
            self.assertEqual(budget.posts, 48)
            now[0] = probe.LIMITS["wall_seconds"]
            with self.assertRaisesRegex(ValueError, "wall_budget_exceeded"):
                budget.check()

    def output_failure(self):
        text = "Synthetic organization mentioned here."
        cell = {"text_index": 0, "profile": probe.PROFILES[0], "arm": probe.ARMS[0]}
        policy = probe.make_policies()[cell["profile"]]
        data, trusted = probe.qwen.OccurrenceQwenAgent._validate_inputs(text, "probe", policy, [])
        messages, _ = probe.qwen.OccurrenceQwenAgent._prepare_messages(data, trusted)
        events = []
        for attempt in (1, 2):
            body = {"model": probe.qwen.MODEL,
                    "messages": messages + ([{"role": "user", "content": probe.qwen.REPAIR_PROMPT}] if attempt == 2 else []),
                    "format": probe.qwen._policy_schema(["CUSTOMER"]), "stream": False, "keep_alive": "30m",
                    "options": {"num_ctx": 4096, "num_predict": 1024, "temperature": 0, "seed": 42}}
            events.append({"method": "POST", "path": "/api/chat", "fixed_host": "127.0.0.1:11435",
                           "cell": cell, "request_object": body, "request_object_sha256": probe._digest(body),
                           "decoded_response": {"model": probe.qwen.MODEL, "done": True, "done_reason": "stop",
                               "message": {"content": json.dumps({"status": "ok", "findings": [
                                   {"quote": "Absent invented text", "occurrence": 1, "category": "CUSTOMER"}]})}}})
        response = {"status": "needs_review", "errors": ["format_or_span_invalid"], "findings": [],
                    "local_calls": 2, "diagnostics": [
                        {"attempt": attempt, "stage": "output", "code": "invalid_span"} for attempt in (1, 2)]}
        return text, cell, events, response

    def test_output_invalid_needs_two_complete_same_cell_generations_rejected_by_host(self):
        text, cell, events, response = self.output_failure()
        self.assertEqual(probe.qwen_status(response, events, cell, text), "model_output_invalid")
        for variant in ("one_post", "wrong_cell", "transport", "incomplete", "wrong_model", "content_missing",
                        "content_nonstring", "tool_call", "valid_replay", "call_count"):
            changed, observed = deepcopy(events), deepcopy(response)
            if variant == "one_post":
                changed.pop()
            elif variant == "wrong_cell":
                changed[1]["cell"] = dict(cell, text_index=1)
            elif variant == "transport":
                changed[1]["error_type"] = "RuntimeError"
            elif variant == "incomplete":
                changed[1]["decoded_response"]["done_reason"] = "length"
            elif variant == "wrong_model":
                changed[1]["decoded_response"]["model"] = "wrong-model"
            elif variant == "content_missing":
                del changed[1]["decoded_response"]["message"]["content"]
            elif variant == "content_nonstring":
                changed[1]["decoded_response"]["message"]["content"] = {}
            elif variant == "tool_call":
                changed[1]["decoded_response"]["message"]["tool_calls"] = ["forbidden"]
            elif variant == "valid_replay":
                changed[1]["decoded_response"]["message"]["content"] = '{"status":"ok","findings":[]}'
            else:
                observed["local_calls"] = 1
            with self.subTest(variant=variant):
                self.assertEqual(probe.qwen_status(observed, changed, cell, text), "engineering_error")

    def test_coverage_semantic_uncertainty_and_engineering_remain_distinct(self):
        text, cell, _, _ = self.output_failure()
        semantic = {"status": "needs_review", "errors": ["semantic_uncertainty"], "findings": [], "local_calls": 1}
        coverage = {"status": "needs_review", "errors": ["input_budget_exceeded"], "findings": [], "local_calls": 0}
        transport = dict(semantic, errors=["local_transport_failed"])
        self.assertEqual(probe.qwen_status(semantic, [], cell, text), "needs_review")
        self.assertEqual(probe.qwen_status(coverage, [], cell, text), "coverage_review")
        self.assertEqual(probe.qwen_status(transport, [], cell, text), "engineering_error")
        self.assertEqual(probe.qwen_status(dict(coverage, status="ok"), [], cell, text), "engineering_error")
        ok = {"status": "ok", "error_kind": None}
        self.assertEqual(probe.evidence_status(ok, ok, semantic), "needs_review")
        self.assertEqual(probe.evidence_status(dict(ok, error_kind="coverage"), ok, coverage), "coverage_review")
        with self.assertRaisesRegex(ValueError, "coverage_was_accepted"):
            probe.evidence_status(dict(ok, error_kind="coverage"), ok, {"status": "ok", "errors": []})
        with self.assertRaisesRegex(ValueError, "encoder_engineering_error"):
            probe.evidence_status(ok, dict(ok, error_kind="engineering"), coverage)

    def closed_rows(self):
        return [{"cell": {"text_index": index, "profile": profile, "arm": arm},
                 "response": {"status": "ok", "errors": [], "findings": [], "local_calls": 0},
                 "status": "ok", "preparation": {"status": "ok", "payload": {"synthetic": index}}}
                for index in range(12) for profile in probe.PROFILES for arm in probe.ARMS]

    def test_close_binds72_raw_predictions_before_reference_and_rejects_scoring_tamper(self):
        for tamper in (False, True):
            with self.subTest(tamper=tamper), self.frozen_case() as fixture:
                output, rows = fixture.output, self.closed_rows()
                before = deepcopy(rows)
                captures = ("http_transport_capture.json", "encoder_capture.json", "nli_capture.json")
                for name in captures:
                    probe.common.save(output / name, [])
                actual_read = probe.read_json
                reference_touched = []
                def guarded_read(path):
                    if Path(path).resolve() == (output / "evaluation.opaque.json").resolve():
                        closure = actual_read(output / "prediction_phase_closed.json")
                        self.assertFalse(closure["reference_parsed"])
                        self.assertEqual(closure["predictions_sha256"], probe.common.sha(output / "predictions.json"))
                        self.assertEqual(closure["opportunities"], 72)
                        self.assertTrue(all("score" not in row for row in actual_read(output / "predictions.json")))
                        reference_touched.append(True)
                        return {"runtime_sha256": probe.common.sha(output / "runtime.json")}
                    return actual_read(path)
                def score(observations, reference, texts):
                    self.assertEqual(reference_touched, [True])
                    scored = deepcopy(observations)
                    scored[0]["score"] = {"synthetic_only": True}
                    if tamper:
                        probe.common.save(output / "predictions.json", [{"tampered": True}])
                    return {"scored_rows": scored, "by_profile_arm": {}}
                budget = Mock()
                with patch.object(probe, "read_json", side_effect=guarded_read), \
                     patch.object(probe.scoring, "score_rows", side_effect=score):
                    if tamper:
                        with self.assertRaisesRegex(ValueError, "closed_evidence_changed"):
                            probe.close_predictions(output, fixture.plan_hash, rows, [], captures, {}, budget=budget)
                    else:
                        result = probe.close_predictions(output, fixture.plan_hash, rows, [], captures, {}, budget=budget)
                self.assertEqual(rows, before)
                self.assertEqual(reference_touched, [True])
                self.assertGreaterEqual(budget.check.call_count, 3)
                if tamper:
                    self.assertFalse((output / "scored_rows.json").exists())
                else:
                    self.assertEqual(result["status"], "complete")
                    self.assertEqual(actual_read(output / "predictions.json"), rows)
                    self.assertEqual(actual_read(output / "scored_rows.json")[0]["score"], {"synthetic_only": True})

    def test_wall_expiry_after_scoring_cannot_produce_a_complete_result(self):
        with self.frozen_case() as fixture:
            output, rows = fixture.output, self.closed_rows()
            captures = ("http_transport_capture.json", "encoder_capture.json", "nli_capture.json")
            for name in captures:
                probe.common.save(output / name, [])
            actual_read = probe.read_json
            score_finished = [False]
            def read_reference(path):
                if Path(path).resolve() == (output / "evaluation.opaque.json").resolve():
                    return {"runtime_sha256": probe.common.sha(output / "runtime.json")}
                return actual_read(path)
            def score(observations, reference, texts):
                score_finished[0] = True
                return {"scored_rows": deepcopy(observations), "by_profile_arm": {}}
            def check_budget():
                if score_finished[0]:
                    raise ValueError("relation_probe_wall_budget_exceeded")
            budget = SimpleNamespace(check=check_budget)
            with patch.object(probe, "read_json", side_effect=read_reference), \
                 patch.object(probe.scoring, "score_rows", side_effect=score), \
                 self.assertRaisesRegex(ValueError, "wall_budget_exceeded"):
                probe.close_predictions(output, fixture.plan_hash, rows, [], captures, {}, budget=budget)
            self.assertTrue(score_finished[0])
            self.assertFalse((output / "scored_rows.json").exists())
            self.assertEqual(actual_read(output / "predictions.json"), rows)

    def test_execute_counts_actual_same_cell_posts_and_stops_on_a_mismatched_receipt(self):
        original_qwen = probe.qwen.OccurrenceQwenAgent
        for mismatch in (False, True):
            with self.subTest(mismatch=mismatch):
                self.number += 1
                output = self.root / ("execute-" + str(self.number))
                output.mkdir()
                texts = ["Synthetic statement " + str(index) + "." for index in range(12)]
                plan = {"policies": probe.make_policies(), "assets": {"root": "unused-synthetic-model", "fixture": "no-model"},
                        "nli_health": {"fixture": "no-model"}, "threads": 2, "interop_threads": 2}
                backend = Mock()
                def local_transport(method, path, body=None):
                    if path == "/api/version":
                        return {"version": probe.qwen.VERSION}
                    if path == "/api/tags":
                        return {"models": [{"name": probe.qwen.MODEL, "digest": probe.qwen.DIGEST}]}
                    return {"model": probe.qwen.MODEL, "done": True, "done_reason": "stop",
                            "message": {"content": '{"status":"ok","findings":[]}'}}
                backend.side_effect = local_transport
                class LocalFixture(original_qwen):
                    def __init__(self):
                        super().__init__(transport=backend)
                    def __call__(self, **kwargs):
                        response = super().__call__(**kwargs)
                        response["local_calls"] += int(mismatch)
                        return response
                nli_counts = {key: 0 for key in ("classifier_forward_calls", "encoder_forward_calls",
                              "classifier_attempts", "encoder_attempts", "blocked_forward_entries")}
                nli_predict = Mock(side_effect=AssertionError("NLI model forbidden"))
                nli = SimpleNamespace(health=lambda: plan["nli_health"], snapshot_counts=lambda: dict(nli_counts),
                                      predict=nli_predict)
                class EncoderFixture:
                    def __init__(self, runtime, *, max_proposals, max_classifications, on_capture):
                        self.on_capture = on_capture
                        self.counts = {"proposal_infer_invocations": 0, "classification_extract_invocations": 0}
                    def snapshot_counts(self):
                        return dict(self.counts)
                def propose(text, *, runtime):
                    runtime.counts["proposal_infer_invocations"] += 1
                    runtime.on_capture({"kind": "proposal", "text": text})
                    return {"status": "ok", "error_kind": None,
                            "inference_counts": {"proposal_infer_invocations": 1}}
                gliner = {"status": "ok", "error_kind": None,
                          "inference_counts": {"classification_extract_invocations": 0}}
                nli_evidence = {"status": "ok", "error_kind": None,
                                "inference_counts": {"nli_predict_invocations": 0}}
                response = {"status": "ok", "errors": [], "findings": [], "local_calls": 0}
                fake_torch = SimpleNamespace(set_num_threads=Mock(), get_num_interop_threads=lambda: 2,
                                             set_num_interop_threads=Mock(), manual_seed=Mock())
                close = Mock(return_value={"status": "offline-test-complete"})
                with patch.object(probe, "verify", return_value=(plan, texts)), \
                     patch.object(probe.common, "checked_assets", return_value=plan["assets"]), \
                     patch.object(probe.common, "install_network_guard"), \
                     patch.object(probe, "PinnedNLIRuntime", return_value=nli), \
                     patch.object(probe, "LocalNerRuntime", return_value=SimpleNamespace(identity={"fixture": True})), \
                     patch.object(probe.relation, "GlinerOccurrenceRuntime", EncoderFixture), \
                     patch.object(probe.relation, "propose", side_effect=propose), \
                     patch.object(probe.relation, "classify_gliner", return_value=gliner), \
                     patch.object(probe.relation, "classify_nli", return_value=nli_evidence), \
                     patch.object(probe.relation, "decide", return_value=response), \
                     patch.object(probe.qwen, "OccurrenceQwenAgent", LocalFixture), \
                     patch.object(probe.scoring, "prepare_observation", return_value={"status": "ok"}), \
                     patch.object(probe, "close_predictions", close), \
                     patch.object(probe, "print"), patch.dict(sys.modules, {"torch": fake_torch}):
                    if mismatch:
                        with self.assertRaisesRegex(ValueError, "qwen_accounting_mismatch"):
                            probe.execute(output, "offline-plan")
                    else:
                        probe.execute(output, "offline-plan")
                execution = probe.read_json(output / "execution.json")
                if mismatch:
                    self.assertEqual(execution["status"], "stopped")
                    self.assertEqual(execution["qwen_posts"], 1)
                    close.assert_not_called()
                    self.assertFalse((output / "predictions.json").exists())
                else:
                    self.assertEqual(execution["opportunities"], 72)
                    self.assertEqual(execution["qwen_posts"], 24)
                    self.assertEqual(close.call_count, 1)
                    self.assertEqual(len(close.call_args.args[2]), 72)
                nli_predict.assert_not_called()


if __name__ == "__main__":
    unittest.main()
