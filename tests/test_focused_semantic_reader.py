"""Offline boundary tests only; test doubles never qualify as native evidence."""
from collections import Counter
from copy import deepcopy
import inspect
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from memory_migration_study.authority_freshness import SQLiteStateWitness, SignedSnapshotStore
from memory_migration_study.focused_semantic_reader import (
    CONDITIONS, POLICY, ModelBudget, assert_pair, call_arm, candidates, canonical,
    digest, make_capability, model_body, parse_selection,
)
from memory_migration_study.local_detector import MODEL
from scripts import run_focused_semantic_20261027 as driver

ROOT = Path(__file__).resolve().parents[1]


class OfflineObservedRun:
    """In-memory authorization observations for unit tests, never NativeRun."""
    def __init__(self, story):
        self.story = story
        self.plan = {"instances": {story["id"] + "." + arm: {"backend": story[arm + "_backend"]}
                                   for arm in ("source", "target")}}
        self.bodies = {story["id"] + "." + arm: {o["key"]: o["text"] for o in story["objects"]}
                       for arm in ("source", "target")}
        self.summaries = {name: {
            "identities": {"alice_reader": {"id": name + ".offline-user"}},
            "datasets": {key: {"id": name + ".offline-dataset." + key} for key in driver.KEYS},
            "facts": {key: {"id": name + ".offline-object." + key} for key in driver.KEYS},
        } for name in self.plan["instances"]}
        self.denied, self.unknown, self.calls = set(), set(), []

    def read(self, name, actor, key, phase):
        self.calls.append((name, actor, key, phase))
        if (name, key) in self.unknown:
            raise OSError("test-only-unavailable-observation")
        if (name, key) in self.denied:
            return {"decision": "deny", "text": None}
        return {"decision": "allow", "text": self.bodies[name][key]}

    def mutate(self, name, operation, key):
        if operation == "revoke":
            self.denied.add((name, key))
        else:
            self.denied.discard((name, key))


class FocusedSemanticReaderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.material = json.loads((ROOT / "examples/focused_semantic_20261027/development.json").read_text(encoding="utf-8"))
        self.story = self.material["stories"][0]
        self.question = self.story["questions"][0]
        self.bodies = {o["key"]: o["text"] for o in self.story["objects"]}
        self.run = OfflineObservedRun(self.story)
        witness = SQLiteStateWitness(self.root / "offline-witness.sqlite", create=True)
        store = SignedSnapshotStore(self.root / "offline-snapshots")
        self.sessions = {arm: driver.ArmSession(self.run, self.root, self.story, arm,
                                              self.bodies, witness, store)
                         for arm in ("source", "target")}
        self.raw_candidates = candidates(self.story, self.bodies)
        self.sent = []

    def cap(self, condition="S1", question=None):
        return make_capability(self.story, question or self.question, condition,
                               self.sessions["source" if condition.startswith("S") else "target"], self.raw_candidates)

    def sender(self, raw):
        self.sent.append(raw)
        return {"done": True, "model": MODEL, "message": {"content": '{"answer_id":"F2"}'},
                "prompt_eval_count": 100, "eval_count": 8}

    def restore(self, cap, selected="F2", **overrides):
        scope = {"story_id": cap.story_id, "question_id": cap.question_id,
                 "condition": cap.condition, "request_id": cap.request_id}
        scope.update(overrides)
        return cap.restore(selected, **scope)

    def test_actual_bodies_are_the_only_text_source_for_all_four_candidates(self):
        changed = deepcopy(self.bodies)
        changed["readonly"] = changed["readonly"].replace("客户是", "客户记录为")
        actual = candidates(self.story, changed)
        self.assertEqual([r["id"] for r in actual], ["F1", "F2", "F3", "F4"])
        self.assertIn("客户记录为", actual[0]["text"])
        self.assertNotEqual(actual[0]["text"], self.raw_candidates[0]["text"])
        for fact in actual:
            self.assertEqual(fact["text"], changed[fact["object_key"]].splitlines()[fact["line_index"]])
        with self.assertRaisesRegex(ValueError, "disagree"):
            assert_pair(self.raw_candidates, actual)

    def test_missing_duplicate_or_incomplete_candidates_fail(self):
        for bodies in [{"readonly": self.bodies["readonly"]},
                       dict(self.bodies, managed=self.bodies["managed"].splitlines()[0])]:
            with self.assertRaises(ValueError):
                candidates(self.story, bodies)
        story = deepcopy(self.story)
        story["facts"][3]["id"] = "F1"
        with self.assertRaisesRegex(ValueError, "four_unique_candidates"):
            candidates(story, self.bodies)

    def test_model_wire_contains_four_cards_no_values_labels_or_scoring_input(self):
        cap = self.cap("S1")
        body = model_body(cap, self.question, "A" * 24)
        user = json.loads(body["messages"][1]["content"])
        self.assertEqual(set(user), {"query", "fact_cards"})
        self.assertEqual([c["answer_id"] for c in user["fact_cards"]], ["F1", "F2", "F3", "F4"])
        self.assertTrue(all(set(c) == {"answer_id", "statement"} for c in user["fact_cards"]))
        raw = canonical(body)
        for value in self.story["sensitive_values"]:
            self.assertNotIn(value.encode(), raw)
        for forbidden in ("expected_id", "scoring_reference", "question_family", "line_index", "source_id", "source_start"):
            self.assertNotIn(forbidden.encode(), raw)

    def test_source_target_visible_wires_match_but_private_capabilities_are_independent(self):
        caps = {c: self.cap(c) for c in CONDITIONS}
        bodies = {c: model_body(cap, self.question, "B" * 24 if c.endswith("1") else None)
                  for c, cap in caps.items()}
        self.assertEqual(canonical(bodies["S0"]), canonical(bodies["T0"]))
        self.assertEqual(canonical(bodies["S1"]), canonical(bodies["T1"]))
        self.assertIsNot(caps["S1"].prepared, caps["T1"].prepared)
        self.assertNotEqual(caps["S1"].request_id, caps["T1"].request_id)
        self.assertNotEqual(caps["S1"].own_tokens, caps["T1"].own_tokens)
        budget = ModelBudget(4)
        for condition in CONDITIONS:
            row = call_arm(caps[condition], bodies[condition], self.story, self.question, budget, sender=self.sender)
            self.assertEqual(row["status"], "ok", row)
            self.assertEqual(row["request_sha256"], digest(self.sent[-1]))
        self.assertEqual(self.sent[0], self.sent[2])
        self.assertEqual(self.sent[1], self.sent[3])

    def test_restoration_scope_and_prepared_swaps_fail(self):
        source, target = self.cap("S1"), self.cap("T1")
        for override in ({"story_id": "another-story"}, {"question_id": "Q2"},
                         {"condition": "T1"}, {"request_id": target.request_id}):
            with self.assertRaisesRegex(ValueError, "scope_mismatch"):
                self.restore(source, **override)
        original = source.prepared
        source.prepared = target.prepared
        self.assertEqual(self.restore(source)["status"], "blocked")
        source.prepared = original
        source.own_tokens = dict(target.own_tokens)
        self.assertEqual(self.restore(source)["status"], "blocked")
        with self.assertRaisesRegex(ValueError, "forged_candidate"):
            self.restore(target, selected="F999")

    def test_same_arm_other_question_preparation_cannot_restore(self):
        first = self.cap("S1")
        next_question = self.cap("S1", self.story["questions"][1])
        first.prepared = next_question.prepared
        self.assertEqual(self.restore(first)["status"], "blocked")
        next_question.closed = True
        with self.assertRaisesRegex(ValueError, "closed"):
            self.restore(next_question)

    def test_target_only_revoke_blocks_target_and_preserves_source(self):
        source, target = self.cap("S1"), self.cap("T1")
        self.run.mutate(self.story["id"] + ".target", "revoke", "readonly")
        self.assertEqual(self.restore(target)["authorization"]["decision"], "deny")
        self.assertEqual(self.restore(source)["status"], "ok")
        self.assertTrue(any(name.endswith(".target") for name, *_ in self.run.calls))

    def test_source_revoke_blocks_all_arms_before_model(self):
        caps = {c: self.cap(c) for c in CONDITIONS}
        self.run.mutate(self.story["id"] + ".source", "revoke", "readonly")
        budget = ModelBudget(4)
        for c, cap in caps.items():
            body = model_body(cap, self.question, "C" * 24 if c.endswith("1") else None)
            row = call_arm(cap, body, self.story, self.question, budget, sender=self.sender)
            self.assertEqual((row["status"], row["failure_class"], row["model_calls"]), ("blocked", "authorization_deny", 0))
        self.assertEqual((budget.attempted, len(self.sent)), (0, 0))

    def test_unknown_and_cross_principals_are_distinct_from_deny(self):
        unknown = self.cap("S0")
        self.run.unknown.add((self.story["id"] + ".source", "readonly"))
        row = call_arm(unknown, model_body(unknown, self.question), self.story, self.question,
                       ModelBudget(1), sender=self.sender)
        self.assertEqual((row["status"], row["failure_class"]), ("blocked", "authorization_unknown"))
        self.run.unknown.clear()
        for principal in ({"user_id": "synthetic.bob", "agent_id": "synthetic.reader"},
                          {"user_id": "synthetic.alice", "agent_id": "synthetic.worker"}):
            cap = self.cap("S0")
            cap.principal = principal
            self.assertEqual(cap.check()["decision"], "deny")
        self.assertEqual(self.sent, [])

    def test_changed_source_or_target_actual_body_becomes_unknown(self):
        source, target = self.cap("S0"), self.cap("T0")
        self.run.bodies[self.story["id"] + ".target"]["readonly"] += "changed"
        self.assertEqual(target.check()["decision"], "unknown")
        self.assertEqual(source.check()["decision"], "allow")
        self.run.bodies[self.story["id"] + ".source"]["readonly"] += "changed"
        self.assertEqual(source.check()["decision"], "unknown")

    def test_budget_exhausted_prevents_transport_and_spending(self):
        for cap_value in (0, 49, True, -1):
            if cap_value == 0 and type(cap_value) is int:
                budget = ModelBudget(cap_value)
                cap = self.cap("S0")
                row = call_arm(cap, model_body(cap, self.question), self.story, self.question, budget, sender=self.sender)
                self.assertEqual(row["failure_class"], "model_budget_exhausted")
                self.assertEqual(row["model_calls"], 0)
            else:
                with self.assertRaisesRegex(ValueError, "invalid_model_cap"):
                    ModelBudget(cap_value)
        budget = ModelBudget(1)
        for expected in ("ok", "error"):
            cap = self.cap("S0")
            row = call_arm(cap, model_body(cap, self.question), self.story, self.question, budget, sender=self.sender)
            self.assertEqual(row["status"], expected)
        self.assertEqual((budget.attempted, len(self.sent)), (1, 1))

    def test_all_registered_values_scan_entire_private_body_before_spending(self):
        for index, value in enumerate(self.story["sensitive_values"]):
            for location in ("query", "extra_key", "format"):
                cap = self.cap("S1")
                body = model_body(cap, self.question, "D" * 24)
                if location == "query":
                    payload = json.loads(body["messages"][1]["content"])
                    payload["query"] += value
                    body["messages"][1]["content"] = canonical(payload).decode()
                elif location == "extra_key":
                    body[value] = "data"
                else:
                    body["format"] = deepcopy(body["format"])
                    body["format"]["description"] = value
                budget = ModelBudget(1)
                row = call_arm(cap, body, self.story, self.question, budget, sender=self.sender)
                self.assertEqual(row["failure_class"], "registered_sensitive_value_present", (index, location, row))
                self.assertEqual((budget.attempted, row["model_calls"]), (0, 0))
        self.assertEqual(self.sent, [])

    def test_input_budget_blocks_oversized_wire_before_authority_or_transport(self):
        cap = self.cap("S0")
        body = model_body(cap, self.question)
        body["messages"][1]["content"] += "x" * 5000
        self.run.calls.clear()
        budget = ModelBudget(1)
        row = call_arm(cap, body, self.story, self.question, budget, sender=self.sender)
        self.assertEqual(row["failure_class"], "conservative_input_budget_exceeded")
        self.assertEqual((budget.attempted, row["model_calls"], self.run.calls, self.sent), (0, 0, [], []))

    def test_observed_token_budget_must_be_verified_and_within_contract(self):
        for changes in ({"prompt_eval_count": 4033}, {"eval_count": 65},
                        {"prompt_eval_count": None}, {"eval_count": True}):
            cap = self.cap("S0")
            def send(raw, patch=changes):
                response = self.sender(raw)
                response.update(patch)
                return response
            row = call_arm(cap, model_body(cap, self.question), self.story, self.question,
                           ModelBudget(1), sender=send)
            self.assertEqual((row["status"], row["failure_class"], row["model_calls"]),
                             ("error", "observed_token_budget_unverified", 1))
            self.assertNotIn("final_answer", row)

    def test_malformed_duplicate_and_forged_model_answers_never_restore(self):
        for answer in ('{"answer_id":"F999"}', '{"answer_id":"F1","answer_id":"F2"}',
                       '{"answer_id":"F2","explanation":"x"}', 'F2', '{"answer_id":null}'):
            with self.assertRaises((ValueError, TypeError)):
                parse_selection(answer)
            cap = self.cap("S0")
            def send(raw, content=answer):
                result = self.sender(raw)
                result["message"]["content"] = content
                return result
            row = call_arm(cap, model_body(cap, self.question), self.story, self.question, ModelBudget(1), sender=send)
            self.assertEqual((row["status"], row["model_calls"]), ("error", 1))
            self.assertNotIn("final_answer", row)

    def test_all_question_latin_orders_have_each_condition_each_position_three_times(self):
        placements = {condition: Counter() for condition in CONDITIONS}
        for i, story in enumerate(self.material["stories"]):
            for j, _ in enumerate(story["questions"]):
                order = driver.call_order(i, j)
                self.assertEqual(set(order), set(CONDITIONS))
                for position, condition in enumerate(order):
                    placements[condition][position] += 1
        self.assertTrue(all(count == Counter({0: 3, 1: 3, 2: 3, 3: 3}) for count in placements.values()))

    def test_native_driver_exposes_no_fake_factory_and_reader_no_reference_io(self):
        self.assertEqual(set(inspect.signature(driver.execute).parameters), {"plan", "output"})
        self.assertEqual(set(inspect.signature(driver.NativeRun).parameters), {"plan", "output"})
        self.assertNotIn("rpc_factory", inspect.getsource(driver.NativeRun.launch))
        self.assertIn("WorkerRPC(", inspect.getsource(driver.NativeRun.launch))
        import memory_migration_study.focused_semantic_reader as reader
        self.assertNotIn("scoring_reference", inspect.getsource(reader))
        execute = inspect.getsource(driver.execute)
        self.assertLess(execute.index('"prediction_phase_closed.json"'), execute.index('reference = base.parse'))
        self.assertLess(execute.index('"predictions.json"'), execute.index('reference = base.parse'))

    def denial_result(self, payload, *, escaped):
        raw = json.dumps(payload, ensure_ascii=escaped, separators=(",", ":"))
        return {"status": 403, "trace": {
            "native_raw_body": raw, "native_body_sha256": digest(raw.encode()),
            "byte_count": len(raw.encode()), "status": 403, "actor": "alice_reader", "index": 1,
            "response_checked": True, "execution_error": None,
            "authorization_present": True, "api_key_present": False, "cookie_present": False}}

    def test_denial_with_plain_registered_value_is_rejected(self):
        native = driver.NativeRun({}, self.root)
        native.registries["offline"] = self.story["sensitive_values"]
        response = self.denial_result({"detail": "denied", "unexpected": self.story["sensitive_values"][0]}, escaped=False)
        with patch.object(native, "call", return_value=response):
            with self.assertRaisesRegex(ValueError, "denial_contains_registered_sensitive_value"):
                native.read("offline", "alice_reader", "readonly", "offline_denial_unit_test")

    def test_denial_with_unicode_escaped_registered_key_or_value_is_rejected(self):
        native = driver.NativeRun({}, self.root)
        native.registries["offline"] = self.story["sensitive_values"]
        secret = self.story["sensitive_values"][0]
        for payload in ({"detail": "denied", "unexpected": secret}, {"detail": "denied", secret: "unexpected"}):
            response = self.denial_result(payload, escaped=True)
            self.assertNotIn(secret, response["trace"]["native_raw_body"])
            with patch.object(native, "call", return_value=response):
                with self.assertRaisesRegex(ValueError, "denial_contains_registered_sensitive_value"):
                    native.read("offline", "alice_reader", "readonly", "offline_denial_unit_test")


if __name__ == "__main__":
    unittest.main()
