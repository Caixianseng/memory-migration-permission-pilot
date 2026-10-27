"""Pinned native-attribute contract tests; standard-library fakes and no network."""
from copy import deepcopy
from dataclasses import dataclass
import socket
import sys
import threading
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import patch
import urllib.request

from memory_migration_study import native_span_attributes as native
from memory_migration_study.sensitivity_contract import bind_category_contract


@dataclass
class AttributeGroup:
    labels: list
    multi_label: bool = False
    threshold: float = .5
    applies_to: object = None
    qualify_labels: bool = False


class Schema:
    def __init__(self):
        self.entity_labels, self.groups = {}, {}

    def entities(self, labels):
        self.entity_labels = deepcopy(labels)
        return self

    def entity_attributes(self, groups):
        self.groups = deepcopy(groups)
        return self

    def build(self):
        return {"entities": deepcopy(self.entity_labels),
                "entity_attributes": {key: deepcopy(vars(value)) for key, value in self.groups.items()}}


class Processor:
    def __init__(self, tokens=512):
        self.tokens, self.inputs = tokens, []
        self.word_splitter = lambda text, lower=False: [(text, 0, len(text))]

    def transform_record(self, text, schema, *, max_len):
        self.inputs.append((text, deepcopy(schema.build()), max_len))
        return SimpleNamespace(input_ids=list(range(self.tokens)))


class Encoder:
    def __init__(self):
        self.calls = 0

    def forward(self, *args):
        self.calls += 1

    def __call__(self, *args):
        return self.forward(*args)


class Head:
    def __init__(self):
        self.calls = 0

    def score_explicit_spans(self, *args):
        self.calls += 1


class Model:
    def __init__(self, raw, tokens=512):
        self.raw, self.calls = deepcopy(raw), []
        self.processor, self.encoder, self.boundary_head = Processor(tokens), Encoder(), Head()
        self.failure = None

    def create_schema(self):
        return Schema()

    def _attach_entity_attributes(self, raw):
        if raw.get("entities", {}).get("organization"):
            self.boundary_head.score_explicit_spans(raw)
        if self.failure:
            raise self.failure

    def extract(self, text, schema, **options):
        self.calls.append((text, schema.build(), deepcopy(options)))
        self.encoder(text)
        self._attach_entity_attributes(self.raw)
        return deepcopy(self.raw)


class Ner:
    def __init__(self, raw, tokens=512):
        self.identity = {"model_id": "instrumented_fixture", "weights_sha256": "0" * 64, "threads": 2}
        self.model, self.lock = Model(raw, tokens), threading.Lock()


def entity(text, quote, label="current_customer", confidence=.9, *, start=None):
    start = text.index(quote) if start is None else start
    return {"text": quote, "start": start, "end": start + len(quote), "confidence": .8,
            native.ATTRIBUTE_NAME: {"label": native.CLASS_LABELS[label], "confidence": confidence}}


def raw_output(*entities):
    return {"entities": {"organization": list(entities)}}


class NativeSpanAttributeTests(unittest.TestCase):
    def setUp(self):
        # The schema module itself is injected: no actual package/model loading,
        # no model downloads and no local/remote server traffic are possible.
        fake_module = ModuleType("gliner2.inference.schema")
        fake_module.AttributeGroup = AttributeGroup
        self.module_patch = patch.dict(sys.modules, {"gliner2.inference.schema": fake_module})
        self.module_patch.start()
        self.addCleanup(self.module_patch.stop)
        for target in ("socket.socket", "socket.create_connection", "urllib.request.urlopen"):
            blocker = patch(target, side_effect=AssertionError("network_forbidden_in_native_fake_tests"))
            blocker.start()
            self.addCleanup(blocker.stop)
        self.text = "Sheaf is a common word. 我们的客户是 Sheaf Ltd."
        self.start = self.text.rindex("Sheaf")
        self.ner = Ner(raw_output(entity(self.text, "Sheaf Ltd", start=self.start)))
        self.runtime = native.NativeSpanAttributeRuntime(self.ner)
        base = {"version": "fixed-v1", "protected_categories": ["CUSTOMER"],
                "instructions": native.BUSINESS_SCOPE, "entity_registry": []}
        self.strict = bind_category_contract(base, "strict_customer_relation")
        self.broad = bind_category_contract(base, "any_specific_organization")

    def replay(self, evidence, policy=None, text=None):
        return native.decide(text or self.text, policy or self.strict, evidence)

    def test_schema_contains_full_labels_scope_guide_and_zero_inference_preflight(self):
        receipt = self.runtime.preflight(self.text)
        spec = native.compiled_spec()
        self.assertEqual(receipt["token_count"], 512)
        self.assertTrue(receipt["fits"])
        self.assertIsNone(receipt["max_len"])
        self.assertIn(native.BUSINESS_SCOPE, spec["entity_description"])
        self.assertIn(native.GLINER_GUIDE, spec["entity_description"])
        self.assertIn(spec["contracts"]["any_specific_organization"]["definitions"]["CUSTOMER"],
                      spec["entity_description"])
        group = receipt["schema"]["entity_attributes"][native.ATTRIBUTE_NAME]
        self.assertEqual(group, {"labels": list(native.CLASS_LABELS.values()), "multi_label": False,
                                "threshold": .5, "applies_to": ["organization"], "qualify_labels": True})
        self.assertEqual(self.ner.model.processor.inputs[0][0], self.text)
        self.assertIsNone(self.ner.model.processor.inputs[0][2])
        self.assertEqual(self.runtime.snapshot_counts(), dict.fromkeys(native.COUNTERS, 0))
        self.assertFalse(self.ner.model.calls)

    def test_one_extract_preserves_offsets_and_is_shared_by_two_profiles(self):
        evidence = self.runtime.infer(self.text)
        counts = self.runtime.snapshot_counts()
        strict, broad = self.replay(evidence), self.replay(evidence, self.broad)
        self.assertEqual(strict["status"], "ok")
        self.assertEqual(strict["findings"], broad["findings"])
        self.assertEqual(strict["findings"][0]["start"], self.start)
        self.assertEqual(strict["local_calls"], broad["local_calls"])
        self.assertEqual(strict["local_calls"], 0)
        self.assertEqual(counts, dict.fromkeys(native.COUNTERS, 1))
        self.assertEqual(evidence["counts"], counts)
        self.assertEqual(self.runtime.snapshot_counts(), counts)
        self.assertEqual(self.ner.model.calls[0][0], self.text)
        self.assertEqual(self.ner.model.calls[0][2], {"threshold": .5, "format_results": True,
            "include_confidence": True, "include_spans": True, "max_len": None})
        self.assertEqual(native.observation_status(strict, evidence), "ok")

    def test_same_surface_different_occurrence_keeps_native_spans(self):
        text = "Sheaf and Sheaf are organizations."
        ner = Ner(raw_output(entity(text, "Sheaf", start=0), entity(text, "Sheaf", start=10)))
        runtime = native.NativeSpanAttributeRuntime(ner)
        evidence = runtime.infer(text)
        response = native.decide(text, self.strict, evidence)
        self.assertEqual([f["start"] for f in response["findings"]], [0, 10])
        self.assertEqual(runtime.snapshot_counts()["extract_invocations"], 1)

    def test_empty_entities_keep_actual_nested_counter_values(self):
        self.ner.model.raw = raw_output()
        evidence = self.runtime.infer(self.text)
        self.assertEqual(evidence["entities"], [])
        self.assertEqual(self.replay(evidence)["status"], "ok")
        self.assertEqual(evidence["counts"], {"extract_invocations": 1, "encoder_forward_entries": 1,
            "attribute_attach_entries": 1, "explicit_span_score_entries": 0})

    def test_full_schema_513_tokens_blocks_extract_and_retains_coverage_reason(self):
        self.ner.model.processor.tokens = 513
        evidence = self.runtime.infer(self.text)
        response = self.replay(evidence)
        self.assertEqual(evidence["error_kind"], "coverage")
        self.assertEqual(evidence["errors"], ["input_budget_exceeded"])
        self.assertEqual(response["errors"], ["input_budget_exceeded"])
        self.assertEqual(native.observation_status(response, evidence), "coverage_review")
        self.assertEqual(evidence["counts"], dict.fromkeys(native.COUNTERS, 0))
        self.assertIsNone(evidence["raw_result"])
        self.assertFalse(self.ner.model.calls)

    def test_over_two_candidates_preserves_all_raw_results_and_reviews_both_profiles(self):
        text = "Aster, Birch and Cedar are our customers."
        ner = Ner(raw_output(*(entity(text, quote) for quote in ("Aster", "Birch", "Cedar"))))
        runtime = native.NativeSpanAttributeRuntime(ner)
        evidence = runtime.infer(text)
        self.assertEqual(len(evidence["entities"]), 3)
        self.assertEqual(len(evidence["raw_result"]["entities"]["organization"]), 3)
        self.assertEqual(evidence["errors"], ["candidate_budget_exceeded"])
        for policy in (self.strict, self.broad):
            response = native.decide(text, policy, evidence)
            self.assertEqual(response["findings"], [])
            self.assertEqual(native.observation_status(response, evidence), "coverage_review")
        self.assertEqual(evidence["counts"]["extract_invocations"], 1)

    def test_strict_five_class_table_and_broad_always_uses_native_ner(self):
        expected = {"current_customer": "sensitive", "former_customer": "sensitive",
                    "explicit_noncustomer": "not_sensitive", "organization_unknown_relation": "needs_review",
                    "not_specific_name": "not_sensitive"}
        for label, decision in expected.items():
            with self.subTest(label=label):
                self.ner.model.raw = raw_output(entity(self.text, "Sheaf Ltd", label, start=self.start))
                evidence = self.runtime.infer(self.text)
                strict, broad = self.replay(evidence), self.replay(evidence, self.broad)
                self.assertEqual(strict["candidate_decisions"][0]["decision"], decision)
                self.assertEqual(strict["status"], "needs_review" if decision == "needs_review" else "ok")
                self.assertEqual(broad["candidate_decisions"][0]["decision"], "sensitive")
                self.assertEqual(broad["status"], "ok")

    def test_native_low_confidence_argmax_requires_strict_review_but_not_broad(self):
        self.ner.model.raw = raw_output(entity(self.text, "Sheaf Ltd", "current_customer", .499, start=self.start))
        evidence = self.runtime.infer(self.text)
        strict, broad = self.replay(evidence), self.replay(evidence, self.broad)
        self.assertEqual(strict["errors"], ["semantic_uncertainty"])
        self.assertEqual(strict["findings"], [])
        self.assertEqual(native.observation_status(strict, evidence), "needs_review")
        self.assertEqual(broad["status"], "ok")
        self.assertEqual(len(broad["findings"]), 1)
        self.ner.model.raw["entities"]["organization"][0][native.ATTRIBUTE_NAME]["confidence"] = .5
        self.assertEqual(self.replay(self.runtime.infer(self.text))["status"], "ok")

    def test_call_cap_blocks_before_extract_and_retains_failed_attempt(self):
        runtime = native.NativeSpanAttributeRuntime(self.ner, max_extracts=1)
        runtime.infer(self.text)
        with self.assertRaisesRegex(ValueError, "extract_cap_exhausted"):
            runtime.infer(self.text)
        self.assertEqual(len(self.ner.model.calls), 1)
        self.assertEqual(runtime.events[-1]["before"], runtime.events[-1]["after"])
        for invalid in (-1, 13, True, 1.5):
            with self.assertRaises(ValueError):
                native.NativeSpanAttributeRuntime(self.ner, max_extracts=invalid)

    def test_native_output_is_strictly_validated_without_repair_or_gold(self):
        for variant in ("offset", "bool_offset", "duplicate", "extra", "permission", "low_ner",
                        "nan", "unknown_label", "qualified_label", "missing_attribute"):
            with self.subTest(variant=variant):
                raw = raw_output(entity(self.text, "Sheaf Ltd", start=self.start))
                item = raw["entities"]["organization"][0]
                if variant == "offset": item["start"] -= 1
                elif variant == "bool_offset": item["start"] = True
                elif variant == "duplicate": raw["entities"]["organization"] *= 2
                elif variant == "extra": item["permissions"] = ["public"]
                elif variant == "permission": raw["permissions"] = ["public"]
                elif variant == "low_ner": item["confidence"] = .49
                elif variant == "nan": item[native.ATTRIBUTE_NAME]["confidence"] = float("nan")
                elif variant == "unknown_label": item[native.ATTRIBUTE_NAME]["label"] = "current_customer"
                elif variant == "qualified_label": item[native.ATTRIBUTE_NAME]["label"] = "customer_relation: " + item[native.ATTRIBUTE_NAME]["label"]
                elif variant == "missing_attribute": del item[native.ATTRIBUTE_NAME]
                runtime = native.NativeSpanAttributeRuntime(Ner(raw))
                with self.assertRaises(ValueError):
                    runtime.infer(self.text)
                self.assertEqual(runtime.snapshot_counts()["extract_invocations"], 1)
                self.assertIn("decoded_output", runtime.events[-1])
                self.assertEqual(runtime.events[-1]["error_type"], "ValueError")

    def test_hooks_restore_class_methods_on_failure_and_do_not_stack(self):
        self.ner.model.failure = RuntimeError("fixture failure")
        with self.assertRaises(RuntimeError):
            self.runtime.infer(self.text)
        for obj, name in ((self.ner.model, "_attach_entity_attributes"),
                          (self.ner.model.encoder, "forward"),
                          (self.ner.model.boundary_head, "score_explicit_spans")):
            self.assertNotIn(name, vars(obj))
        self.ner.model.failure = None
        evidence = self.runtime.infer(self.text)
        self.assertEqual(evidence["counts"], dict.fromkeys(native.COUNTERS, 1))
        self.assertEqual(self.runtime.snapshot_counts(), dict.fromkeys(native.COUNTERS, 2))

    def test_hooks_restore_preexisting_instance_override(self):
        original = lambda *args: None
        self.ner.model.boundary_head.score_explicit_spans = original
        self.runtime.infer(self.text)
        self.assertIs(self.ner.model.boundary_head.score_explicit_spans, original)

    def test_changed_source_evidence_and_policy_fail_closed(self):
        evidence = self.runtime.infer(self.text)
        variants = []
        changed = deepcopy(evidence)
        changed["entities"][0]["start"] = 0
        variants.append((self.text, self.strict, changed))
        changed = deepcopy(evidence)
        changed["raw_result"]["entities"]["organization"][0][native.ATTRIBUTE_NAME]["label"] = native.CLASS_LABELS["explicit_noncustomer"]
        variants.append((self.text, self.strict, changed))
        variants.extend(((self.text + " altered", self.strict, evidence),
                         (self.text, dict(self.strict, instructions="Another owner"), evidence),
                         (self.text, dict(self.strict, max_text_chars=1), evidence),
                         (self.text, dict(self.strict, protected_categories=["PERSON"]), evidence)))
        for text, policy, item in variants:
            response = native.decide(text, policy, item)
            self.assertEqual(response["findings"], [])
            self.assertEqual(native.observation_status(response, item), "engineering_error")

    def test_runtime_identity_change_prevents_inference(self):
        self.ner.identity["weights_sha256"] = "1" * 64
        with self.assertRaisesRegex(ValueError, "identity_changed"):
            self.runtime.infer(self.text)
        self.assertEqual(self.runtime.snapshot_counts(), dict.fromkeys(native.COUNTERS, 0))

    def test_capture_callback_receives_defensive_copy_with_actual_raw_evidence(self):
        observed = []
        def capture(event):
            observed.append(deepcopy(event))
            event["after"]["extract_invocations"] = 1000
        runtime = native.NativeSpanAttributeRuntime(self.ner, on_capture=capture)
        evidence = runtime.infer(self.text)
        self.assertEqual(observed[0]["decoded_output"], evidence["raw_result"])
        self.assertEqual(runtime.events[0]["after"]["extract_invocations"], 1)
        self.assertEqual(runtime.snapshot_counts()["extract_invocations"], 1)

    def test_response_is_compatible_with_existing_pseudonymization_scoring(self):
        from scripts.relation_probe_scoring import prepare_observation, _validate_preparation, _validate_status
        evidence = self.runtime.infer(self.text)
        response = self.replay(evidence)
        observation = prepare_observation(self.text, self.strict, response)
        row = {"status": native.observation_status(response, evidence), "response": response,
               "preparation": observation, "cell": {"profile": "strict_customer_relation"}}
        self.assertEqual(_validate_status(row, self.text), {(self.start, self.start + 9, "CUSTOMER")})
        ready, payload_strings = _validate_preparation(row, self.text)
        self.assertTrue(ready)
        self.assertNotIn("Sheaf Ltd", "".join(payload_strings))
        self.assertIn("Sheaf is a common word", "".join(payload_strings))
        self.assertEqual(observation["acl_negative_control"]["status"], "rejected")
        self.assertNotIn("mapping", observation)
        self.assertEqual(observation["new_model_calls"], 0)
        self.assertEqual(self.runtime.snapshot_counts()["extract_invocations"], 1)

    def test_review_and_coverage_block_preparation_without_becoming_clean_empty_results(self):
        from scripts.relation_probe_scoring import prepare_observation, _validate_preparation, _validate_status
        self.ner.model.raw["entities"]["organization"][0][native.ATTRIBUTE_NAME]["confidence"] = .49
        for token_count, status in ((512, "needs_review"), (513, "coverage_review")):
            with self.subTest(status=status):
                self.ner.model.processor.tokens = token_count
                evidence = self.runtime.infer(self.text)
                response = self.replay(evidence)
                observation = prepare_observation(self.text, self.strict, response)
                row = {"status": native.observation_status(response, evidence), "response": response,
                       "preparation": observation, "cell": {"profile": "strict_customer_relation"}}
                self.assertEqual(row["status"], status)
                self.assertEqual(_validate_status(row, self.text), set())
                self.assertEqual(_validate_preparation(row, self.text), (False, []))
                self.assertIsNone(observation["payload"])
                self.assertEqual(observation["acl_negative_control"]["status"], "not_exercised")

    def test_network_guards_are_active(self):
        for operation in (lambda: socket.socket(), lambda: socket.create_connection(("127.0.0.1", 1)),
                          lambda: urllib.request.urlopen("https://invalid.example")):
            with self.assertRaisesRegex(AssertionError, "network_forbidden"):
                operation()


if __name__ == "__main__":
    unittest.main()
