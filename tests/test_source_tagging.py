"""Offline copy/tag language and parser contracts; no model or real backend."""
import ast
from copy import deepcopy
import hashlib
import json
import re
import unittest

from memory_migration_study import source_tagging as tagging


def interval_sets(length, cursor=0):
    yield []
    for start in range(cursor, length):
        for end in range(start + 1, length + 1):
            for tail in interval_sets(length, end):
                yield [(start, end), *tail]


def accepts_generated_gbnf(grammar, value):
    """Independent recognizer of literals/concatenation/alternation/references.

    This checks the emitted small GBNF subset, not a real llama.cpp installation.
    """
    rules = {}
    pattern = re.compile(r'"(?:\\.|[^"\\])*"|[a-z][a-z0-9-]*|\|')
    for line in grammar.splitlines():
        name, production = line.split(" ::= ", 1)
        tokens = pattern.findall(production)
        alternatives, current = [], []
        for token in tokens:
            if token == "|":
                alternatives.append(current)
                current = []
            else:
                current.append(("literal", ast.literal_eval(token)) if token.startswith('"') else ("rule", token))
        alternatives.append(current)
        rules[name] = alternatives
    cache = {}

    def ends(name, offset):
        key = (name, offset)
        if key in cache:
            return cache[key]
        found = set()
        for alternative in rules[name]:
            positions = {offset}
            for kind, item in alternative:
                positions = ({p + len(item) for p in positions if value.startswith(item, p)}
                             if kind == "literal" else {end for p in positions for end in ends(item, p)})
                if not positions:
                    break
            found.update(positions)
        cache[key] = found
        return found
    return len(value) in ends("root", 0)


class SourceTaggingTests(unittest.TestCase):
    def test_contract_is_deterministic_hash_bound_and_linear_rule_count(self):
        text = 'North "Elm" \\ 红杉\n'
        a = tagging.build_contract(text)
        self.assertEqual(a, tagging.build_contract(text))
        self.assertEqual(a["rule_count"], 2 * (len(text) + 1) + 1)
        self.assertEqual(a["source_sha256"], hashlib.sha256(text.encode()).hexdigest())
        self.assertEqual(a["grammar_sha256"], hashlib.sha256(a["grammar"].encode()).hexdigest())
        material = {k: v for k, v in a.items() if k != "contract_sha256"}
        encoded = json.dumps(material, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()
        self.assertEqual(a["contract_sha256"], hashlib.sha256(encoded).hexdigest())
        self.assertEqual(a["offset_unit"], "unicode_codepoint_half_open")

    def test_repeat_surface_names_select_only_second_occurrence(self):
        text = '苔藓是植物。客户名称是苔藓。'
        start = text.rindex('苔藓')
        contract = tagging.build_contract(text)
        output = tagging.render_tagged(text, [(start, start + 2)], contract)
        result = tagging.parse_tagged(text, output, contract)
        self.assertEqual(result["findings"], [{"start": start, "end": start + 2, "quote": '苔藓', "category": 'CUSTOMER'}])

    def test_adjacent_spans_remain_distinct(self):
        c = tagging.build_contract('甲乙')
        out = tagging.render_tagged('甲乙', [(0, 1), (1, 2)], c)
        self.assertIn(c['close_tag'] + c['open_tag'], out)
        self.assertEqual([(f['start'], f['end']) for f in tagging.parse_tagged('甲乙', out, c)['findings']], [(0, 1), (1, 2)])
        self.assertTrue(accepts_generated_gbnf(c['grammar'], out))

    def test_tag_collision_chooses_first_absent_pair_and_preserves_literals(self):
        text = '<M0> literal </M1> and <M00>'
        c = tagging.build_contract(text)
        self.assertEqual((c['open_tag'], c['close_tag']), ('<M2>', '</M2>'))
        out = tagging.render_tagged(text, [(0, 4)], c)
        self.assertEqual(tagging.parse_tagged(text, out, c)['findings'][0]['quote'], '<M0>')
        self.assertTrue(accepts_generated_gbnf(c['grammar'], out))

    def test_emoji_combining_char_and_extended_han_roundtrip(self):
        text = '😀e\u0301𠀋客户'
        c = tagging.build_contract(text)
        out = tagging.render_tagged(text, [(1, 4)], c)
        self.assertEqual(tagging.parse_tagged(text, out, c)['findings'][0]['quote'], 'e\u0301𠀋')
        self.assertTrue(accepts_generated_gbnf(c['grammar'], out))

    def test_grammar_escapes_all_controls_quotes_backslash_without_json_only_escapes(self):
        text = ''.join(chr(i) for i in range(32)) + chr(127) + '"\\😀'
        c = tagging.build_contract(text)
        self.assertIn(r'\x08', c['grammar'])
        self.assertIn(r'\x0C', c['grammar'])
        self.assertNotIn('"\\b"', c['grammar'])
        self.assertNotIn('"\\f"', c['grammar'])
        out = tagging.render_tagged(text, [(0, len(text))], c)
        self.assertEqual(tagging.parse_tagged(text, out, c)['findings'][0]['quote'], text)
        self.assertTrue(accepts_generated_gbnf(c['grammar'], out))

    def test_invalid_surrogates_are_rejected_in_source_and_output(self):
        for value in ('\ud800', '\udfff', 'a\udbffb'):
            with self.subTest(value=repr(value)), self.assertRaisesRegex(tagging.SourceTaggingError, 'invalid_unicode_surrogate'):
                tagging.build_contract(value)
        c = tagging.build_contract('a')
        with self.assertRaisesRegex(tagging.SourceTaggingError, 'invalid_unicode_surrogate'):
            tagging.parse_tagged('a', '\ud800', c)

    def test_input_and_grammar_caps_never_truncate(self):
        with self.assertRaisesRegex(tagging.SourceTaggingError, 'source_text_limit_exceeded'):
            tagging.build_contract('a' * 6001)
        with self.assertRaisesRegex(tagging.SourceTaggingError, 'source_grammar_limit_exceeded'):
            tagging.build_contract('a' * 6000)
        with self.assertRaisesRegex(tagging.SourceTaggingError, 'invalid_source_text'):
            tagging.build_contract(b'a')

    def test_contract_tampering_and_type_substitution_are_rejected(self):
        c = tagging.build_contract('a')
        for key, value in [('text', 'b'), ('grammar', c['grammar'] + '# changed\n'), ('open_tag', '<M7>'), ('source_chars', 1.0), ('source_chars', True), ('contract_sha256', '0' * 64), ('category', 'PERSON')]:
            changed = deepcopy(c)
            changed[key] = value
            with self.subTest(key=key, value=value), self.assertRaisesRegex(tagging.SourceTaggingError, 'source_tag_contract_mismatch'):
                tagging.parse_tagged('a', 'a', changed)

    def test_copy_edits_insertions_normalization_and_truncation_are_rejected(self):
        text = ' A e\u0301\nB '
        c = tagging.build_contract(text)
        for out in ('A e\u0301\nB ', ' A é\nB ', text + '!', text[:-1], text.replace('A', 'a'), text + '<M99>'):
            with self.subTest(output=out), self.assertRaises(tagging.SourceTaggingError):
                tagging.parse_tagged(text, out, c)

    def test_empty_nested_unbalanced_and_unknown_tags_fail(self):
        text = 'ab'
        c = tagging.build_contract(text)
        op, cl = c['open_tag'], c['close_tag']
        invalid = [op + cl + text, cl + text, op + text,
                   op + 'a' + op + 'b' + cl + cl, op + text + cl + cl,
                   '<M9>' + text + '</M9>']
        for out in invalid:
            with self.subTest(output=out), self.assertRaises(tagging.SourceTaggingError):
                tagging.parse_tagged(text, out, c)
            self.assertFalse(accepts_generated_gbnf(c['grammar'], out))

    def test_span_limit_and_bad_renderer_ranges(self):
        text = 'a' * 33
        c = tagging.build_contract(text)
        out = ''.join(c['open_tag'] + 'a' + c['close_tag'] for _ in text)
        with self.assertRaises(tagging.SourceTaggingError):
            tagging.parse_tagged(text, out, c)
        for spans in ([(0, 0)], [(1, 0)], [(0, 34)], [(0, 2), (1, 3)], [(2, 3), (0, 1)], [(False, 1)], [(0.0, 1)], [(i, i + 1) for i in range(33)]):
            with self.subTest(spans=spans), self.assertRaisesRegex(tagging.SourceTaggingError, 'invalid_tag_spans'):
                tagging.render_tagged(text, spans, c)
        accepted = tagging.render_tagged(text, [(i, i + 1) for i in range(32)], c)
        self.assertEqual(len(tagging.parse_tagged(text, accepted, c)['findings']), 32)

    def test_empty_source_and_untagged_source_do_not_claim_semantic_safety(self):
        for text in ('', 'ordinary role words'):
            c = tagging.build_contract(text)
            r = tagging.parse_tagged(text, text, c)
            self.assertEqual(r['findings'], [])
            self.assertFalse(r['semantic_verified'])
            self.assertFalse(r['authorization_granted'])
            self.assertTrue(accepts_generated_gbnf(c['grammar'], text))

    def test_tagged_ordinary_word_is_structurally_legal_not_sensitive_truth(self):
        text = 'company is a generic role'
        c = tagging.build_contract(text)
        r = tagging.parse_tagged(text, tagging.render_tagged(text, [(0, 7)], c), c)
        self.assertEqual(r['findings'][0]['quote'], 'company')
        self.assertFalse(r['semantic_verified'])
        self.assertFalse(c['semantic_guarantee'])

    def test_exhaustive_short_nonoverlapping_interval_sets_match_grammar_and_parser(self):
        for text in ('', 'a', 'ab', 'aba', '甲乙丙', '😀e\u0301', 'a b!'):
            c = tagging.build_contract(text)
            outputs = set()
            for spans in interval_sets(len(text)):
                out = tagging.render_tagged(text, spans, c)
                self.assertNotIn(out, outputs)
                outputs.add(out)
                self.assertTrue(accepts_generated_gbnf(c['grammar'], out), (text, spans))
                r = tagging.parse_tagged(text, out, c)
                self.assertEqual([(f['start'], f['end']) for f in r['findings']], spans)


if __name__ == '__main__':
    unittest.main()
