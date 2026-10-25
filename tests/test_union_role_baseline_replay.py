"""Pure span/grant replay tests; no encoder, model or real experimental gold."""
from copy import deepcopy
import unittest

from scripts.replay_union_role_baseline import project, source_binding, supported_records
from scripts.verify_reference_memory_study import digest, sha


ALIASES = {"customer": ("customer", "客户"), "buyer": ("buyer", "买方"), "consignee": ("consignee",),
           "account_holder": ("account holder",), "audit_observer": ("audit observer",), "carrier": ("carrier",), "status": ("status",)}


def fixture():
    source = {"source_id": "independent-source", "text": "buyer: Cedar Works"}
    text = source["text"]
    identity = {"source_id": source["source_id"], "source_sha256": sha(text), "source_start": 0, "source_end": len(text), "content_sha256": sha(text)}
    access = {**identity, "record_id": "record1", "owner_id": "owner", "readers": ["owner"], "origin_agent_id": "source-agent", "allowed_agent_ids": ["target-agent"], "scope_version": "exact_fact_source_span_v1", "epoch": 0}
    findings = [{"start": 7, "end": len(text), "category": "CUSTOMER"}]
    label = {**{k: v for k, v in identity.items() if k != "source_id"}, "record_id": "record1", "status": "ok", "findings": findings, "access_sha256": digest(access), "epoch": 0}
    record = {"record_id": "record1", "source_id": "record1", "source": {**source, "sha256": sha(text)}, "source_start": 0, "source_end": len(text), "text": text,
              "status": "ok", "access": access, "label": label, "access_signature": "a"*64, "label_signature": "b"*64}
    annotation = {**identity, "fid": "F1", "fact_key": digest(identity), "status": "ok", "group_status": "ok", "eligible_for_store": True, "detection": {"findings": findings}}
    fact = {"fid": "F1", "source_start": 0, "source_end": len(text), "text": text}
    return source, record, annotation, fact


class UnionRoleReplayTests(unittest.TestCase):
    def test_full_name_and_public_organization_roles_use_same_grammar_without_customer_upgrade(self):
        text = "买方林溪联合社；audit observer: Lake Institute; status: accepted"
        candidates = [{"start": 2, "end": 7, "quote": "林溪联合社"},
                      {"start": text.index("Lake Institute"), "end": text.index("Lake Institute")+14, "quote": "Lake Institute"}]
        actual = project(text, "S", candidates, ALIASES)
        self.assertEqual({f["role"] for f in actual}, {"buyer", "audit_observer", "status"})
        self.assertNotIn("customer", {f["role"] for f in actual})
        partial = project(text, "S", [{"start": 4, "end": 7, "quote": "联合社"}], ALIASES)
        self.assertNotIn("buyer", {f["role"] for f in partial})

    def test_value_anchor_and_support_cannot_borrow_different_records_or_sources(self):
        source, record, _, _ = fixture()
        card = project(source["text"], source["source_id"], [{"start": 7, "end": len(source["text"]), "quote": "Cedar Works"}], ALIASES)[0]
        self.assertEqual(supported_records(card, [record]), ["record1"])
        left, right = deepcopy(record), deepcopy(record)
        left.update(record_id="left", source_start=0, source_end=7)
        right.update(record_id="right", source_start=7)
        self.assertEqual(supported_records(card, [left, right]), [])
        wrong = deepcopy(record)
        wrong["source"]["source_id"] = "other-source-same-text"
        self.assertEqual(supported_records(card, [wrong]), [])

    def test_public_source_binding_checks_hash_range_and_fact_not_equal_surface_only(self):
        source, record, annotation, fact = fixture()
        self.assertEqual(source_binding(record, annotation, fact, source)["content_sha256"], sha(source["text"]))
        for change in ("origin", "span", "fact"):
            r, a, f = deepcopy(record), deepcopy(annotation), deepcopy(fact)
            if change == "origin":
                r["access"]["source_id"] = "same-text-different-origin"
            elif change == "span":
                r["source_start"] = 1
            else:
                a["fid"] = "another-selected-fact"
            with self.assertRaises(ValueError):
                source_binding(r, a, f, source)


if __name__ == "__main__":
    unittest.main()
