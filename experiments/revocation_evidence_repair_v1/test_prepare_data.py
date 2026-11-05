"""Data isolation and exact projection tests; no model or network access."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from .prepare_data import (current_planner_input, make_schedule, project_record,
                           select_records, write_once)


def record(identifier='q03'):
    return {'_id': identifier, 'question': 'Which place is mentioned?', 'answer': 'Alpha',
        'type': 'bridge', 'level': 'hard',
        'context': [['Original title', [' First sentence. ', '', 'Third\nline.']],
                    ['Second title', ['Second paragraph.']]],
        'supporting_facts': [['Original title', 0], ['Second title', 0]]}


class PrepareDataTests(unittest.TestCase):
    def test_select_ids_only_excludes_previous_registry(self):
        records = [record(identifier) for identifier in ('q04', 'q02', 'q00', 'q03', 'q01')]
        old = [{'cluster_id': 'q00'}, {'cluster_id': 'q01'}]
        selected = select_records(records, old, count=2)
        self.assertEqual([row['_id'] for row in selected], ['q02', 'q03'])
        modified = copy.deepcopy(records)
        for row in modified:
            row['answer'], row['supporting_facts'], row['context'] = 'OTHER', [], []
        self.assertEqual([row['_id'] for row in select_records(modified, old, count=2)], ['q02', 'q03'])

    def test_preserve_all_original_sentences_titles_offsets_and_neighbors(self):
        source_record = record()
        case, label = project_record(source_record)
        self.assertEqual(case['question'], source_record['question'])
        self.assertEqual(len(case['sources']), 4)
        for source in case['sources']:
            origin = source['origin']
            sentence = source_record['context'][origin['parent_index']][1][origin['sentence_index']]
            self.assertEqual(source['text'], origin['title'] + '\n' + sentence)
            self.assertEqual(source['text'][origin['quote_start']:origin['quote_end']], sentence)
            self.assertEqual(origin['quote_sha256'], hashlib.sha256(sentence.encode('utf-8')).hexdigest())
        self.assertEqual(case['hierarchy']['S001']['next_id'], 'S002')
        self.assertEqual(case['hierarchy']['S003']['next_id'], None)
        self.assertEqual(label['support_ids'], ['S001', 'S004'])
        self.assertFalse(label['support_annotation_is_exhaustive'])
        self.assertFalse({'answer', 'support_ids', 'type', 'level'} & set(case))

    def test_permissions_independent_of_gold_and_current_only_projection(self):
        case, _ = project_record(record())
        first = make_schedule(case, 1)
        changed_question = copy.deepcopy(case)
        changed_question['question'] = 'A changed question must not change the mask'
        self.assertEqual(make_schedule(changed_question, 1), first)
        schedule, episodes = first
        self.assertEqual(len(schedule[1]['allowed']), 3)  # floor(30% * 4) revoked
        self.assertEqual(schedule[0]['allowed'], schedule[2]['allowed'])
        receivers = [entry['receiver_context_id'] for entry in episodes['deliveries']]
        self.assertEqual(len(set(receivers)), 3)
        self.assertTrue(all(not row['receiver_has_received_package'] for row in episodes['deliveries']))
        projected = current_planner_input(case, ['S001', 'S003'])
        self.assertEqual(set(projected), {'question', 'current_sources', 'hierarchy'})
        self.assertEqual([source['source_id'] for source in projected['current_sources']], ['S001', 'S003'])
        self.assertEqual(projected['hierarchy']['S001']['next_id'], 'S003')
        self.assertNotIn('S002', projected['hierarchy'])
        projected['current_sources'][0]['text'] = 'modified'
        self.assertNotEqual(case['sources'][0]['text'], 'modified')

    def test_cycle_percent_assignment_without_looking_at_content(self):
        case, _ = project_record(record())
        self.assertEqual([make_schedule(case, index)[0][1]['revocation_percent']
                          for index in range(7)], [10, 30, 50, 10, 30, 50, 10])

    def test_invalid_selection_and_policy_fail_closed(self):
        with self.assertRaises(ValueError):
            select_records([record(), record()], [], count=1)
        with self.assertRaises(ValueError):
            select_records([record()], [{'cluster_id': 'missing'}], count=1)
        with self.assertRaises(ValueError):
            select_records([record()], [], count=True)
        case, _ = project_record(record())
        for allowed in (['missing'], ['S001', 'S001'], [1], 'S001'):
            with self.subTest(allowed=allowed), self.assertRaises(ValueError):
                current_planner_input(case, allowed)
        case['future_events'] = []
        with self.assertRaises(ValueError):
            current_planner_input(case, [])

    def test_frozen_output_cannot_be_replaced(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'value.json'
            write_once(path, b'{"v":1}\n')
            write_once(path, b'{"v":1}\n')
            with self.assertRaises(ValueError):
                write_once(path, b'{"v":2}\n')
            self.assertEqual(json.loads(path.read_text()), {'v': 1})


if __name__ == '__main__':
    unittest.main()
