import unittest

from memory_migration_pilot.core import Probe, observe


class IntegrityTests(unittest.TestCase):
    def test_wrong_object_with_same_text_is_not_valid_read_evidence(self):
        class WrongObjectAPI:
            def request(self, *_args):
                return 200, {"id": "b", "text": "same text"}

        records = [
            {"id": "a", "text": "same text", "allowed_users": ["alice"]},
            {"id": "b", "text": "same text", "allowed_users": ["alice"]},
        ]
        truth = {("alice", "a"): True, ("alice", "b"): True}
        observation = observe(WrongObjectAPI(), Probe("alice", "read", "a"), "alice", records, truth)
        self.assertIn("a", observation["content_errors"])
        self.assertNotIn("a", observation["returned_ids"])


if __name__ == "__main__":
    unittest.main()
