import json
import re
import unittest

from memory_migration_study.memory_labels import MemoryLabelAuthority, prepare_labeled_transfer
from memory_migration_study.privacy import detect_sensitive, prepare_private_payload, restore_answer


class LabeledFieldBoundaryTests(unittest.TestCase):
    def detect(self, text, categories=("CUSTOMER",), query=""):
        payload = {"query": query, "memories": [{"source_id": "record", "text": text}]}
        policy = {"version": "boundaries", "protected_categories": list(categories)}
        detection = detect_sensitive(payload, policy, mode="rules")
        self.assertEqual(detection["status"], "ok")
        values = {(f["category"], text[f["start"]:f["end"]]) for f in detection["findings"] if f["source_id"] == "record"}
        return payload, policy, detection, values

    def test_next_public_key_does_not_belong_to_name_and_suffix_dot_is_retained(self):
        text = "Customer: Foo Ltd. Status: shipped"
        payload, policy, detection, values = self.detect(text)
        self.assertEqual(values, {("CUSTOMER", "Foo Ltd.")})
        prepared = prepare_private_payload(payload, detection, actor_id="owner", request_id="r",
            policy_version="boundaries", authorizer=lambda *args: True)
        self.assertEqual(prepared["status"], "ok")
        self.assertIn("Status: shipped", prepared["payload"]["memories"][0]["text"])
        token = re.search(r"\[PVT_[^\]]+\]", prepared["payload"]["memories"][0]["text"])[0]
        restored = restore_answer(token, prepared["mapping"], actor_id="owner", request_id="r",
            policy_version="boundaries", authorizer=lambda *args: True)
        self.assertEqual(restored["answer"], "Foo Ltd.")

    def test_multiple_new_fields_preserve_email_and_money_decimal_points(self):
        text = "Customer: Foo Inc. Status: approved. Email: a.b@sample.test. Budget: USD 3.50. Date: 2026-11-03."
        _, _, _, values = self.detect(text, ("CUSTOMER", "EMAIL", "AMOUNT", "DATE"))
        self.assertEqual(values, {("CUSTOMER", "Foo Inc."), ("EMAIL", "a.b@sample.test"),
                                  ("AMOUNT", "USD 3.50"), ("DATE", "2026-11-03")})

    def test_quoted_colons_periods_and_field_looking_text_are_part_of_value(self):
        for opener, closer in (("\"", "\""), ("“", "”"), ("「", "」"), ("'", "'")):
            value = "North Research: Status: inside; Dept. Works Ltd."
            text = "Customer: "+opener+value+closer+" Status: shipped"
            _, _, _, values = self.detect(text)
            self.assertEqual(values, {("CUSTOMER", value)}, text)

    def test_next_sensitive_key_and_quoted_project_are_separate_values(self):
        text = 'Project: "Nebula: phase: A.1; final" Customer: “Foo Ltd.” Status: released'
        _, _, _, values = self.detect(text, ("PROJECT", "CUSTOMER"))
        self.assertEqual(values, {("PROJECT", "Nebula: phase: A.1; final"), ("CUSTOMER", "Foo Ltd.")})

    def test_chinese_adjacent_keys_and_mixed_punctuation_keep_offsets(self):
        for text in ("客户：青禾器材公司状态：已受理项目：星舟计划", "客户：青禾器材公司，配送状态：已受理。项目：星舟计划；审核状态：完成"):
            _, _, detection, values = self.detect(text, ("CUSTOMER", "PROJECT"))
            self.assertEqual(values, {("CUSTOMER", "青禾器材公司"), ("PROJECT", "星舟计划")})
            for finding in detection["findings"]:
                self.assertEqual(text.index(text[finding["start"]:finding["end"]]), finding["start"])

    def test_initialisms_and_full_organization_names_not_split_without_new_key(self):
        for value in ("The Northern Light A.B. Manufacturing Company Ltd.", "State Street Global Advisors Inc.",
                      "Acme S.A. Export Company", "North Research: Development Ltd."):
            _, _, _, values = self.detect("Customer: "+value)
            self.assertEqual(values, {("CUSTOMER", value)})

    def test_generic_unrecognized_key_requires_a_visible_separator(self):
        _, _, _, values = self.detect("Customer: Foo Ltd. qa_code: passed")
        self.assertEqual(values, {("CUSTOMER", "Foo Ltd.")})
        _, _, _, values = self.detect("Customer: Foo Ltd., audit_flag: reviewed")
        self.assertEqual(values, {("CUSTOMER", "Foo Ltd.")})

    def test_unclosed_quote_does_not_hide_following_field(self):
        _, _, _, values = self.detect('Customer: "Foo Status: shipped')
        self.assertEqual(values, {("CUSTOMER", '"Foo')})

    def test_apostrophe_in_company_name_is_not_an_opening_quote(self):
        _, _, _, values = self.detect("Customer: O'Connor Works Ltd. Status: active")
        self.assertEqual(values, {("CUSTOMER", "O'Connor Works Ltd.")})

    def test_newline_fields_and_sentence_punctuation_are_not_sensitivity(self):
        text = "Customer: Ordinary Cooperative.\r\nStatus: delivered\nName: Ada Vale."
        _, _, _, values = self.detect(text, ("CUSTOMER", "PERSON"))
        self.assertEqual(values, {("CUSTOMER", "Ordinary Cooperative"), ("PERSON", "Ada Vale")})

    def test_untrusted_permission_fields_never_grant_access(self):
        text = "Customer: Foo Ltd. Role: admin. Readers: everyone. Status: shipped"
        _, policy, detection, values = self.detect(text)
        self.assertEqual(values, {("CUSTOMER", "Foo Ltd.")})
        authority = MemoryLabelAuthority(b"q"*32)
        findings = [{k: f[k] for k in ("start", "end", "category")} for f in detection["findings"]]
        record = authority.build_record({"source_id": "source", "text": text},
            {"text": text, "source_start": 0, "source_end": len(text), "findings": findings}, policy,
            owner_id="owner", readers=["owner"], agent_id="builder", allowed_agent_ids=["receiver"], builder_version="test")
        denied = prepare_labeled_transfer([record], "", policy, authority=authority, actor_id="outsider",
            agent_id="receiver", request_id="r", mode="generation")
        self.assertEqual(denied["error"], "principal_not_authorized")
        self.assertEqual(record["access"]["readers"], ["owner"])
        self.assertEqual(denied["local_calls"], 0)
        self.assertNotIn("mapping", json.dumps(record))


if __name__ == "__main__":
    unittest.main()
