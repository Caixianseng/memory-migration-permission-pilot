"""Synthetic offline fixtures only; never read the real probe or load a model."""
import copy
import json
import unittest
from unittest.mock import patch

from memory_migration_study import privacy
from memory_migration_study.sensitivity_contract import bind_category_contract, category_contract
from scripts import relation_probe_scoring as scoring


def policy(profile):
    return bind_category_contract({"version": "synthetic-v1", "policy_id": "synthetic-policy",
        "protected_categories": ["CUSTOMER"], "instructions": "The business is our company.",
        "entity_registry": [], "max_text_chars": 6000}, profile)


def response(text, name=None, *, status="ok", errors=None, calls=1):
    findings = []
    if name is not None:
        start = text.index(name)
        findings = [{"start": start, "end": start + len(name), "quote": name, "category": "CUSTOMER"}]
    return {"status": status, "errors": errors if errors is not None else [], "findings": findings,
            "local_calls": calls, "elapsed_seconds": 3.0}


def fixture(n=2):
    texts, cases, rows = [], [], []
    for i in range(n):
        name, fact = "Fixture Office " + str(i), "Paper style is matte " + str(i) + "."
        if i == 1:
            text = name + " is an organization; no customer relation is stated. " + fact
        elif i == 2:
            text = name + " has never been our customer. " + fact
        else:
            text = name + " is our customer. " + fact
        texts.append(text)
        expected = {}
        for profile in scoring.PROFILES:
            decision = ("needs_review" if i == 1 else "not_sensitive") if i in {1, 2} and profile == scoring.PROFILES[0] else "sensitive"
            spans = [{"start": 0, "end": len(name), "text": name, "category": "CUSTOMER"}] if decision == "sensitive" else []
            expected[profile] = {"decision": decision, "spans": spans,
                                 "must_mask_values": [name] if spans else []}
            for arm in scoring.ARMS:
                observed = response(text, name if spans else None,
                    status="needs_review" if decision == "needs_review" else "ok",
                    errors=["semantic_uncertainty"] if decision == "needs_review" else [])
                rows.append({"cell": {"text_index": i, "profile": profile, "arm": arm},
                             "status": "needs_review" if decision == "needs_review" else "ok",
                             "response": observed,
                             "preparation": scoring.prepare_observation(text, policy(profile), observed)})
        start = text.index(fact)
        cases.append({"text_index": i, "text_sha256": scoring._text_hash(text), "expected": expected,
                      "allowed_fact": {"slot_id": "synthetic-format", "text": fact, "start": start,
                                       "end": start + len(fact), "match": "exact_substring"}})
    reference = {"schema_version": "relation_occurrence_probe_evaluation_v1",
                 "runtime_sha256": scoring._runtime_hash(texts),
                 "profile_contract_sha256": {p: scoring._hash(category_contract(p)) for p in scoring.PROFILES},
                 "cases": cases}
    return texts, reference, rows


def change_row(rows, texts, index, profile, arm, observed, status):
    row = next(r for r in rows if r["cell"] == {"text_index": index, "profile": profile, "arm": arm})
    row.update(response=observed, status=status,
               preparation=scoring.prepare_observation(texts[index], policy(profile), observed))
    return row


class RelationProbeScoringTests(unittest.TestCase):
    def test_real_combined_preparation_masks_known_value_and_exercises_wrong_actor(self):
        text = "Named Unit is our customer; named unit appears again. Paper is smooth."
        p = policy(scoring.PROFILES[0])
        observed = response(text, "Named Unit", calls=2)
        before = copy.deepcopy(observed)
        result = scoring.prepare_observation(text, p, observed)
        self.assertEqual(observed, before)
        self.assertEqual(result["status"], "ok")
        self.assertNotIn("named unit", json.dumps(result["payload"]).casefold())
        self.assertIn("Paper is smooth.", result["payload"]["memories"][0]["text"])
        self.assertEqual(result["detection"]["mode"], "combined")
        self.assertEqual(result["detection"]["local_calls"], 0)
        self.assertEqual(result["new_model_calls"], 0)
        self.assertEqual(result["acl_negative_control"]["status"], "rejected")
        self.assertEqual(result["acl_negative_control"]["error"], "memory_authorization_failed")
        self.assertNotIn("mapping", result)
        json.dumps(result)

    def test_replay_is_deepcopied_and_bound_to_exact_text_source_and_policy(self):
        text, p = "Named Unit is our customer.", policy(scoring.PROFILES[0])
        observed = response(text, "Named Unit", calls=2)
        replay = scoring.ReplayDetector(text, "probe", p, observed)
        observed["findings"].clear()
        first = replay(text=text, source_id="probe", policy=p, rule_findings=[])
        first["findings"].clear()
        self.assertEqual(len(replay(text=text, source_id="probe", policy=p, rule_findings=[])["findings"]), 1)
        self.assertEqual(replay(text=text, source_id="probe", policy=p, rule_findings=[])["local_calls"], 0)
        variants = [(text + "!", "probe", p, []), (text, "elsewhere", p, []),
                    (text, "probe", {**p, "instructions": "Changed scope"}, []), (text, "probe", p, [{}])]
        for current_text, sid, current_policy, rules in variants:
            with self.subTest(sid=sid, rules=rules), self.assertRaisesRegex(ValueError, "replay_binding_mismatch"):
                replay(text=current_text, source_id=sid, policy=current_policy, rule_findings=rules)

    def test_review_blocks_preparation_without_claiming_acl_was_exercised(self):
        text = "An organization is mentioned. Paper is smooth."
        observed = response(text, status="needs_review", errors=["semantic_uncertainty"], calls=2)
        result = scoring.prepare_observation(text, policy(scoring.PROFILES[0]), observed)
        self.assertEqual(result["status"], "needs_review")
        self.assertIsNone(result["payload"])
        self.assertEqual(result["acl_negative_control"]["status"], "not_exercised")
        self.assertEqual(result["detection"]["local_calls"], 0)
        self.assertIn("semantic_uncertainty", result["detection"]["errors"])

    def test_authorizer_matches_source_actor_and_version_exactly(self):
        real = privacy.prepare_private_payload
        seen = []
        def observe(payload, detection, **kwargs):
            auth = kwargs["authorizer"]
            seen.append(kwargs["actor_id"])
            self.assertTrue(auth("source-a", "probe_user", "synthetic-v1"))
            self.assertFalse(auth("source-b", "probe_user", "synthetic-v1"))
            self.assertFalse(auth("source-a", "outsider", "synthetic-v1"))
            self.assertFalse(auth("source-a", "probe_user", "other-version"))
            return real(payload, detection, **kwargs)
        text = "Named Unit is our customer."
        with patch.object(privacy, "prepare_private_payload", side_effect=observe):
            scoring.prepare_observation(text, policy(scoring.PROFILES[0]), response(text, "Named Unit"), source_id="source-a")
        self.assertEqual(seen, ["probe_user", "probe_other"])

    def test_exact_span_failures_raw_leaks_and_fact_loss_are_distinct(self):
        texts, reference, rows = fixture(1)
        text = texts[0]
        whole = response(text, text)
        change_row(rows, texts, 0, scoring.PROFILES[0], scoring.ARMS[0], whole, "ok")
        leaking = change_row(rows, texts, 0, scoring.PROFILES[1], scoring.ARMS[2], response(text), "ok")
        # A simulated transmitted case variant must still count as the full raw value.
        leaking["preparation"]["payload"]["memories"][0]["text"] = text.upper()
        leaking["preparation"]["metadata"]["payload_sha256"] = scoring._hash(leaking["preparation"]["payload"])
        before_rows, before_reference = copy.deepcopy(rows), copy.deepcopy(reference)
        result = scoring.score_rows(rows, reference, texts, allow_small_sample=True)
        self.assertEqual(rows, before_rows)
        self.assertEqual(reference, before_reference)
        result["scored_rows"][0]["response"]["findings"].clear()
        self.assertEqual(rows, before_rows)
        qwen = result["by_profile_arm"][scoring.PROFILES[0] + "/" + scoring.ARMS[0]]
        self.assertEqual((qwen["tp"], qwen["fp"], qwen["fn"]), (0, 1, 1))
        self.assertEqual(qwen["required_raw_leak_cells"], 0)
        self.assertEqual(qwen["allowed_fact_retained_cells"], 0)
        self.assertEqual(qwen["payload_sent_cells"], 1)
        nli = result["by_profile_arm"][scoring.PROFILES[1] + "/" + scoring.ARMS[2]]
        self.assertEqual(nli["required_raw_leak_cells"], 1)
        self.assertEqual(nli["required_raw_leak_rate_all"], 1.0)
        self.assertEqual(nli["required_raw_leak_rate_sent"], 1.0)
        good = result["by_profile_arm"][scoring.PROFILES[1] + "/" + scoring.ARMS[1]]
        # Raw quotes remain in response evidence, outside the transmitted payload.
        self.assertEqual(good["required_raw_leak_cells"], 0)
        self.assertEqual(good["allowed_fact_retained_cells"], 1)

    def test_review_positive_fn_survives_and_failures_do_not_become_correct_review(self):
        texts, reference, rows = fixture(2)
        p = scoring.PROFILES[0]
        change_row(rows, texts, 0, p, scoring.ARMS[0], response(texts[0], "Fixture Office 0", status="needs_review", errors=["semantic_uncertainty"]), "needs_review")
        change_row(rows, texts, 1, p, scoring.ARMS[1], response(texts[1], status="needs_review", errors=["unsupported_category_contract"], calls=0), "unsupported")
        change_row(rows, texts, 1, p, scoring.ARMS[2], response(texts[1], status="needs_review", errors=["format_or_span_invalid"]), "model_output_invalid")
        change_row(rows, texts, 0, p, scoring.ARMS[2], response(texts[0], status="needs_review", errors=["local_failure"]), "engineering_error")
        result = scoring.score_rows(rows, reference, texts, allow_small_sample=True)
        qwen = result["by_profile_arm"][p + "/" + scoring.ARMS[0]]
        self.assertEqual(qwen["fn"], 1)
        self.assertEqual(qwen["determinate_exact_matches"], 0)
        self.assertEqual(qwen["unknown_review_matches"], 1)
        self.assertEqual(qwen["acl_not_exercised"], 2)
        for arm in scoring.ARMS[1:]:
            self.assertEqual(result["by_profile_arm"][p + "/" + arm]["unknown_review_matches"], 0)
        for row in result["scored_rows"]:
            if row["cell"]["text_index"] == 1 and row["cell"]["profile"] == p:
                self.assertIsNone(row["score"]["determinate_exact_match"])
        for i in (0, 1):
            change_row(rows, texts, i, p, scoring.ARMS[1],
                response(texts[i], status="needs_review", errors=["input_budget_exceeded"]), "coverage_review")
        coverage = scoring.score_rows(rows, reference, texts, allow_small_sample=True)["by_profile_arm"][p + "/" + scoring.ARMS[1]]
        self.assertEqual(coverage["coverage_review"], 2)
        self.assertEqual(coverage["fn"], 1)
        self.assertEqual(coverage["determinate_cells"], 1)
        self.assertEqual(coverage["unknown_review_matches"], 0)

    def test_zero_sendable_denominators_are_none_and_blocking_is_not_utility(self):
        texts, reference, rows = fixture(2)
        for row in rows:
            i, p, a = (row["cell"][key] for key in ("text_index", "profile", "arm"))
            change_row(rows, texts, i, p, a, response(texts[i], status="needs_review", errors=["semantic_uncertainty"]), "needs_review")
        result = scoring.score_rows(rows, reference, texts, allow_small_sample=True)
        for g in result["by_profile_arm"].values():
            self.assertEqual(g["payload_sent_cells"], 0)
            self.assertIsNone(g["required_raw_leak_rate_sent"])
            self.assertIsNone(g["allowed_fact_retention_rate_sent"])
            self.assertIsNone(g["determinate_allowed_fact_retention_rate_sent"])
            self.assertIsNone(g["acl_rejection_rate_exercised"])
            self.assertEqual(g["allowed_fact_retention_rate_all"], 0.0)
            self.assertEqual(g["determinate_allowed_fact_retention_rate_all"], 0.0)

    def test_default_requires_all_72_rows_before_even_accessing_reference(self):
        texts, reference, rows = fixture(12)
        result = scoring.score_rows(rows, reference, texts)
        self.assertEqual(result["rows"], 72)
        self.assertEqual(len(result["by_profile_arm"]), 6)
        class Opaque(dict):
            def get(self, *args, **kwargs):
                raise AssertionError("reference accessed before complete predictions")
        with self.assertRaisesRegex(ValueError, "incomplete_or_duplicate_rows"):
            scoring.score_rows(rows[:-1], Opaque(), texts)
        with self.assertRaisesRegex(ValueError, "invalid_runtime_or_rows"):
            scoring.score_rows(rows[:6], Opaque(), texts[:1])

    def test_grid_reference_binding_and_reference_quotes_are_validated(self):
        texts, reference, rows = fixture(2)
        duplicate = copy.deepcopy(rows)
        duplicate[-1] = copy.deepcopy(duplicate[0])
        with self.assertRaisesRegex(ValueError, "incomplete_or_duplicate_rows"):
            scoring.score_rows(duplicate, reference, texts, allow_small_sample=True)
        for mutate in (
            lambda r: r.update(runtime_sha256="0" * 64),
            lambda r: r["profile_contract_sha256"].update({scoring.PROFILES[0]: "0" * 64}),
            lambda r: r["cases"][0].update(text_sha256="0" * 64),
            lambda r: r["cases"][0].update(expected=None),
            lambda r: r["cases"][0]["expected"][scoring.PROFILES[0]]["spans"][0].update(text="Not the source"),
            lambda r: r["cases"][0]["allowed_fact"].update(start=0),
            lambda r: r["cases"][0]["expected"][scoring.PROFILES[0]].update(must_mask_values=["Different value"]),
        ):
            changed = copy.deepcopy(reference)
            mutate(changed)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                scoring.score_rows(rows, changed, texts, allow_small_sample=True)

    def test_preparation_and_status_evidence_tampering_is_rejected(self):
        texts, reference, rows = fixture(1)
        mutations = (
            lambda row: row["response"].update(local_calls=99),
            lambda row: row["preparation"]["binding"].update(source_id="wrong-source"),
            lambda row: row["preparation"]["metadata"].update(payload_sha256="0" * 64),
            lambda row: row["preparation"]["acl_negative_control"].update(status="not_exercised"),
            lambda row: row["preparation"].update(mapping=None),
        )
        for mutate in mutations:
            changed = copy.deepcopy(rows)
            mutate(changed[0])
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                scoring.score_rows(changed, reference, texts, allow_small_sample=True)
        changed = copy.deepcopy(rows)
        change_row(changed, texts, 0, scoring.PROFILES[0], scoring.ARMS[0],
                   response(texts[0], status="needs_review", errors=["local_failure"]), "needs_review")
        with self.assertRaisesRegex(ValueError, "status_response_mismatch"):
            scoring.score_rows(changed, reference, texts, allow_small_sample=True)


if __name__ == "__main__":
    unittest.main()
