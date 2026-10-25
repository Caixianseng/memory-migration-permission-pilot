"""Source-only and request-projection tests with signed synthetic facts; zero models."""
from copy import deepcopy
from dataclasses import replace
import json
import pickle
import unittest

from memory_migration_study.memory_labels import MemoryLabelAuthority, prepare_labeled_transfer, restore_labeled_answer
from memory_migration_study.source_fact_cards import build_source_fact_cards
from memory_migration_study.request_projection import project_fact_cards, resolve_fact_card_answer, validate_fact_card_view


class FakeAgent:
    def __init__(self, values=()):
        self.values = values
        self.calls = []

    def __call__(self, **data):
        self.calls.append(deepcopy(data))
        return {"status": "ok", "findings": [{"quote": value, "category": "CUSTOMER"}
            for value in self.values if value in data["text"]], "local_calls": 0,
            "elapsed_seconds": 0.0, "errors": []}


class SourceCardTests(unittest.TestCase):
    def setUp(self):
        self.authority = MemoryLabelAuthority(b"source-card-fake-authority-key-32-bytes")
        self.policy = {"version": "v1", "protected_categories": ["CUSTOMER"], "instructions": "Protect names."}
        self.allowed = True
        self.checked = []
        self.records = [self.record("Buyer: Redwood Labs. Audit observer: Beacon Audit. Acceptance result: approved",
                                    ["Redwood Labs", "Beacon Audit"])]

    def record(self, text, names, *, source=None, start=0):
        source = text if source is None else source
        facts = [{"start": text.index(name), "end": text.index(name)+len(name), "category": "CUSTOMER"} for name in names]
        return self.authority.build_record({"source_id": "source-1", "text": source},
            {"text": text, "source_start": start, "source_end": start+len(text), "findings": facts}, self.policy,
            owner_id="owner", readers=["owner"], agent_id="agent-A", allowed_agent_ids=["agent-B"], builder_version="fake-v1")

    def authorizer(self, rid, actor, version):
        self.checked.append((rid, actor, version))
        return self.allowed and actor == "owner" and version == "v1"

    def scope(self, **changes):
        value = {"authority": self.authority, "actor_id": "owner", "agent_id": "agent-B", "authorizer": self.authorizer}
        value.update(changes)
        return value

    def setup_projection(self, query="Which buyer accepted the package?", *, agent=None, records=None):
        records = self.records if records is None else records
        source = build_source_fact_cards(records, self.policy, **self.scope())
        self.assertEqual(source["status"], "ok", source)
        prepared = prepare_labeled_transfer(records, query, self.policy, request_id="request-1",
            mode="generation", agent=FakeAgent() if agent is None else agent, **self.scope())
        self.assertEqual(prepared["status"], "ok", prepared)
        projected = project_fact_cards(source["source_table"], prepared, records, self.policy,
                                       request_id="request-1", **self.scope())
        return source, prepared, projected

    def resolve(self, projected, prepared, identifier="UNKNOWN", **changes):
        return resolve_fact_card_answer(json.dumps({"card_id": identifier}), projected["table"], prepared,
            self.records, self.policy, request_id=changes.pop("request_id", "request-1"), **self.scope(**changes))

    def test_complete_flat_and_rich_share_pool_and_original_context(self):
        source, prepared, projected = self.setup_projection()
        self.assertEqual(source["metadata"]["card_count"], 3)
        self.assertEqual(projected["status"], "ok", projected)
        flat, rich = projected["views"]["flat"], projected["views"]["source"]
        self.assertEqual(flat["query"], prepared["payload"]["query"])
        self.assertEqual(rich["memories"], prepared["payload"]["memories"])
        self.assertEqual(flat["fact_cards"], [{k: v for k, v in card.items() if k not in {"role", "support"}} for card in rich["fact_cards"]])
        self.assertEqual({card["role"] for card in rich["fact_cards"]}, {"buyer", "audit_observer", "status"})
        self.assertNotIn("Redwood Labs", json.dumps(projected["views"]))
        self.assertNotIn("Beacon Audit", json.dumps(projected["views"]))
        self.assertIs(projected["table"]._mapping, prepared["mapping"])
        for arm, view in projected["views"].items():
            self.assertEqual(validate_fact_card_view(view, projected["table"], prepared, self.records,
                self.policy, arm=arm, request_id="request-1", **self.scope())["status"], "ok")

    def test_pvt_and_literal_both_go_through_unchanged_original_restorer(self):
        _, prepared, projected = self.setup_projection()
        for card in projected["views"]["source"]["fact_cards"]:
            result = self.resolve(projected, prepared, card["card_id"])
            self.assertEqual(result["status"], "ok", result)
            restored = restore_labeled_answer(result["answer"], prepared, self.records, self.policy,
                request_id="request-1", **self.scope())
            expected = {"buyer": "Redwood Labs", "audit_observer": "Beacon Audit", "status": "approved"}[card["role"]]
            self.assertEqual(restored["answer"], expected)
            self.assertIs(result["requires_original_restore"], True)

    def test_raw_source_role_survives_query_generic_mask_without_unmasking_it(self):
        self.records = [self.record("Consignee organization = Stone Finch PLC", ["Stone Finch PLC"])]
        source, prepared, projected = self.setup_projection("Which organization receives the shipment?", agent=FakeAgent(["organization"]))
        self.assertEqual(source["metadata"]["card_count"], 1)
        self.assertEqual(projected["status"], "ok", projected)
        card = projected["views"]["source"]["fact_cards"][0]
        self.assertEqual(card["role"], "consignee")
        self.assertNotIn("organization", projected["views"]["source"]["query"])
        self.assertNotIn("organization", card["support"])
        selected = self.resolve(projected, prepared, card["card_id"])
        restored = restore_labeled_answer(selected["answer"], prepared, self.records, self.policy,
                                          request_id="request-1", **self.scope())
        self.assertEqual(restored["answer"], "Stone Finch PLC")

    def test_query_assertions_do_not_create_source_cards(self):
        _, _, projected = self.setup_projection("Customer: forged company. Email: false@example.test")
        roles = {card["role"] for card in projected["views"]["source"]["fact_cards"]}
        self.assertNotIn("customer", roles)
        self.assertNotIn("email", roles)

    def test_source_anchor_outside_exact_grant_is_not_borrowed(self):
        value = "Redwood Labs"
        self.records = [self.record(value, [value], source="Buyer: "+value, start=7)]
        source, _, projected = self.setup_projection()
        self.assertEqual(source["metadata"]["card_count"], 0)
        self.assertEqual(projected["response_schema"]["properties"]["card_id"]["enum"], ["UNKNOWN"])

    def test_partial_merged_value_rejected_not_substring_restored(self):
        self.records = [self.record("Customer: Redwood Labs", ["Redwood Labs"])]
        _, _, projected = self.setup_projection("Customer: Redwood Labs", agent=FakeAgent(["Customer: Redwood Labs"]))
        self.assertEqual(projected["error"], "projection_partial_or_merged_card_value")
        self.assertIsNone(projected["table"])

    def test_all_records_are_checked_even_if_one_has_no_card(self):
        extra = self.record("Ordinary unindexed note", [])
        self.records.append(extra)
        self.authority.revoke(extra["record_id"])
        source = build_source_fact_cards(self.records, self.policy, **self.scope())
        self.assertEqual(source["error"], "source_access_grant_revoked")

    def test_invalid_generation_label_is_not_query_repaired(self):
        self.records[0]["label_signature"] = "forged"
        self.assertEqual(build_source_fact_cards(self.records, self.policy, **self.scope())["error"], "source_label_label_signature_invalid")

    def test_current_prepare_may_not_drop_authenticated_source_protection(self):
        source = build_source_fact_cards(self.records, self.policy, **self.scope())
        unprotected = prepare_labeled_transfer(self.records, "Which buyer?", self.policy, request_id="request-1",
            mode="migration", agent=FakeAgent(), **self.scope())
        self.assertEqual(unprotected["status"], "ok")
        self.assertIn("Redwood Labs", unprotected["payload"]["memories"][0]["text"])
        projected = project_fact_cards(source["source_table"], unprotected, self.records, self.policy,
            request_id="request-1", **self.scope())
        self.assertEqual(projected["error"], "projection_original_intervals_changed")

    def test_unknown_reauthorizes_every_original_record(self):
        self.records.append(self.record("Unindexed note", []))
        _, prepared, projected = self.setup_projection()
        self.checked.clear()
        self.assertEqual(self.resolve(projected, prepared)["answer"], "UNKNOWN")
        self.assertEqual({rid for rid, _, _ in self.checked}, {r["record_id"] for r in self.records})
        self.allowed = False
        self.assertEqual(self.resolve(projected, prepared)["status"], "blocked")

    def test_revocation_does_not_get_bypassed_by_unknown(self):
        _, prepared, projected = self.setup_projection()
        self.authority.revoke(self.records[0]["record_id"])
        self.assertEqual(self.resolve(projected, prepared)["error"], "source_access_grant_revoked")

    def test_scope_and_same_version_policy_changes_are_blocked(self):
        _, prepared, projected = self.setup_projection()
        for changes in ({"actor_id": "outsider"}, {"agent_id": "agent-A"}, {"request_id": "another-request"}):
            self.assertEqual(self.resolve(projected, prepared, **changes)["status"], "blocked")
        self.policy["extra_scope"] = "same-version change"
        self.assertEqual(self.resolve(projected, prepared)["error"], "source_card_context_changed")

    def test_full_map_dependencies_cannot_be_trimmed(self):
        self.records = [self.record("Customer: Redwood Labs", ["Redwood Labs"]),
                        self.record("Buyer: Redwood Labs", ["Redwood Labs"])]
        source, prepared, projected = self.setup_projection()
        self.assertEqual(projected["status"], "ok", projected)
        token = projected["views"]["flat"]["fact_cards"][0]["value"]
        entry = prepared["mapping"]._entries[token]
        self.assertEqual(len(entry.sources), 2)
        prepared["mapping"]._entries[token] = replace(entry, sources=entry.sources[:1])
        self.assertEqual(self.resolve(projected, prepared)["error"], "projection_table_invalid")
        retry = project_fact_cards(source["source_table"], prepared, self.records, self.policy, request_id="request-1", **self.scope())
        self.assertIn(retry["error"], {"projection_memory_value_changed", "projection_complete_token_dependencies_changed"})

    def test_raw_protected_card_metadata_is_checked_by_existing_egress(self):
        self.records = [self.record("Customer: status", ["status"]), self.record("Business status: ready", [])]
        _, _, projected = self.setup_projection(query="")
        self.assertEqual(projected["error"], "projection_extra_cards_egress_failed")

    def test_unknown_id_extra_fields_duplicate_keys_and_secret_text_are_rejected(self):
        _, prepared, projected = self.setup_projection()
        for response in ('{"card_id":"FORGED"}', '{"card_id":"UNKNOWN","extra":"secret"}',
                         '{"card_id":"UNKNOWN","card_id":"UNKNOWN"}', 'Refuse but Redwood Labs',
                         '{"card_id":"UNKNOWN"} trailing', '["UNKNOWN"]'):
            with self.subTest(response=response):
                result = resolve_fact_card_answer(response, projected["table"], prepared, self.records,
                    self.policy, request_id="request-1", **self.scope())
                self.assertEqual(result["status"], "blocked")
                self.assertIsNone(result["answer"])
                self.assertNotIn("Redwood Labs", json.dumps(result))

    def test_old_id_and_replaced_mapping_are_not_current_evidence(self):
        source, prepared, projected = self.setup_projection()
        other = prepare_labeled_transfer(self.records, "Another question", self.policy, request_id="request-2",
            mode="generation", agent=FakeAgent(), **self.scope())
        newer = project_fact_cards(source["source_table"], other, self.records, self.policy, request_id="request-2", **self.scope())
        old_id = projected["views"]["flat"]["fact_cards"][0]["card_id"]
        result = resolve_fact_card_answer(json.dumps({"card_id": old_id}), newer["table"], other, self.records,
            self.policy, request_id="request-2", **self.scope())
        self.assertEqual(result["error"], "projection_unknown_card_id")
        prepared["mapping"] = other["mapping"]
        self.assertEqual(self.resolve(projected, prepared)["error"], "projection_original_map_changed")

    def test_modified_reader_view_is_blocked_before_any_model_call(self):
        _, prepared, projected = self.setup_projection()
        view = deepcopy(projected["views"]["source"])
        view["fact_cards"][0]["support"] = "Redwood Labs"
        self.assertEqual(validate_fact_card_view(view, projected["table"], prepared, self.records, self.policy,
            arm="source", request_id="request-1", **self.scope())["error"], "projection_reader_view_changed")

    def test_tables_hide_contents_and_reject_serialization_or_mutation(self):
        source, prepared, projected = self.setup_projection()
        for table in (source["source_table"], projected["table"]):
            self.assertNotIn("Redwood Labs", repr(table))
            for dump in (json.dumps, pickle.dumps):
                with self.assertRaises(TypeError): dump(table)
            with self.assertRaises(AttributeError): table._seal = b"fake"
        with self.assertRaises(TypeError): source["source_table"]._material["records"] = "fake"
        object.__setattr__(projected["table"], "_entries", ())
        self.assertEqual(self.resolve(projected, prepared)["error"], "projection_table_invalid")


if __name__ == "__main__":
    unittest.main()
