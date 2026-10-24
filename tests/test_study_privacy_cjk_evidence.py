"""Real preparation/recovery regressions for language-aware literal evidence."""
import unittest

from memory_migration_study.privacy import detect_sensitive, prepare_private_payload, restore_answer


class CjkEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.policy = {"version": "cjk-evidence-v1", "protected_categories": ["CUSTOMER"],
                       "entity_registry": [{"category": "CUSTOMER", "value": "稻原能源合作社"}]}

    def authorized(self, source_id, actor_id, version):
        return actor_id == "owner" and version == self.policy["version"]

    def prepare(self, text, *, query="业务状态是什么？", extra_memories=()):
        payload = {"query": query, "memories": [{"source_id": "memo", "text": text}, *extra_memories]}
        detected = detect_sensitive(payload, self.policy, mode="rules")
        self.assertEqual(detected["status"], "ok")
        prepared = prepare_private_payload(payload, detected, actor_id="owner", request_id="request-1",
                                           policy_version=self.policy["version"], authorizer=self.authorized)
        self.assertEqual(prepared["status"], "ok")
        return prepared

    def restore(self, answer, prepared, **overrides):
        args = dict(actor_id="owner", request_id="request-1", policy_version=self.policy["version"],
                    authorizer=self.authorized, sensitivity_policy=self.policy)
        args.update(overrides)
        return restore_answer(answer, prepared["mapping"], **args)

    def test_unspaced_chinese_fact_can_follow_predicate(self):
        for text, answer in (("客户：稻原能源合作社；业务状态为已核验。", "已核验"),
                             ("材料审核结果是需补件。", "需补件"),
                             ("当前流程已归档并等待审计。", "已归档")):
            with self.subTest(text=text):
                prepared = self.prepare(text)
                self.assertEqual(self.restore(answer, prepared), {"status": "ok", "answer": answer, "error": None})

    def test_mixed_han_ascii_and_numbers_keep_exact_source_evidence(self):
        prepared = self.prepare("任务状态为ready99，编号为ZX_24已核验。")
        for answer in ("ready99", "ZX_24"):
            self.assertEqual(self.restore(answer, prepared)["answer"], answer)
        for answer in ("ready", "ZX_2", "24"):
            self.assertEqual(self.restore(answer, prepared)["error"], "literal_has_no_memory_evidence")

    def test_ascii_word_fragments_prefixes_suffixes_and_identifiers_rejected(self):
        prepared = self.prepare("inactive flag_queued AlphaBeta X932")
        for answer in ("active", "queued", "Alpha", "Beta", "X93", "932"):
            with self.subTest(answer=answer):
                self.assertEqual(self.restore(answer, prepared)["error"], "literal_has_no_memory_evidence")
        self.assertEqual(self.restore("AlphaBeta", prepared)["answer"], "AlphaBeta")

    def test_non_han_unicode_alphabetic_word_fragments_still_rejected(self):
        prepared = self.prepare("ÉquipeAlpha παραδοτέο")
        for answer in ("Alpha", "Équipe", "παρα"):
            self.assertEqual(self.restore(answer, prepared)["error"], "literal_has_no_memory_evidence")
        self.assertEqual(self.restore("παραδοτέο", prepared)["answer"], "παραδοτέο")

    def test_known_chinese_private_name_and_partial_sensitive_spans_rejected(self):
        prepared = self.prepare("客户：稻原能源合作社；业务状态为已核验。")
        self.assertEqual(self.restore("稻原能源合作社", prepared)["error"], "raw_protected_value_in_answer")
        for answer in ("稻原", "能源合作社", "合作社"):
            self.assertEqual(self.restore(answer, prepared)["error"], "literal_has_no_memory_evidence")
        self.assertEqual(self.restore("已核验", prepared)["answer"], "已核验")

    def test_query_only_non_sensitive_fact_not_accepted_as_memory_evidence(self):
        prepared = self.prepare("该任务还没有业务状态。", query="已核验是否正确？")
        self.assertEqual(self.restore("已核验", prepared)["error"], "literal_has_no_memory_evidence")

    def test_query_only_private_token_cannot_become_evidence(self):
        prepared = self.prepare("该任务还没有客户名称。", query="客户：稻原能源合作社")
        token = prepared["payload"]["query"].split("：", 1)[1]
        self.assertEqual(self.restore(token, prepared)["error"], "query_only_value_has_no_evidence")

    def test_revoked_source_and_joint_source_authorization_checked(self):
        prepared = self.prepare("当前状态为待复查。", extra_memories=[{"source_id": "other", "text": "另一本地记录状态为待复查。"}])
        self.assertEqual(self.restore("待复查", prepared)["answer"], "待复查")
        self.assertEqual(self.restore("待复查", prepared, authorizer=lambda sid, *_: sid == "memo")["error"],
                         "restoration_authorization_failed")
        self.assertEqual(self.restore("待复查", prepared, authorizer=lambda *_: False)["error"],
                         "restoration_authorization_failed")

    def test_scope_and_policy_rechecked_for_chinese_literals(self):
        prepared = self.prepare("业务状态为已核验。")
        for change in ({"request_id": "another"}, {"actor_id": "outsider"}, {"policy_version": "new-version"}):
            self.assertEqual(self.restore("已核验", prepared, **change)["error"], "restoration_scope_mismatch")
        self.assertEqual(self.restore("已核验", prepared, sensitivity_policy={**self.policy, "instructions": "changed"})["error"],
                         "restoration_policy_mismatch")

    def test_multi_fact_embedded_tokens_and_unsupported_literals_still_blocked(self):
        prepared = self.prepare("客户：稻原能源合作社；状态为已核验；备选为待复查。")
        for answer, code in (("已核验；待复查", "not_a_single_fact"),
                             ("状态 [PVT_forged]", "unknown_or_embedded_token"),
                             ("从未出现的状态", "literal_has_no_memory_evidence")):
            self.assertEqual(self.restore(answer, prepared)["error"], code)


if __name__ == "__main__":
    unittest.main()
