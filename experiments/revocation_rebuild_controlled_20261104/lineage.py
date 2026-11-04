"""Conservative, explicit input lineage for the controlled rebuild experiment.

This module records integrity and dependency edges, never authorization. All
permission decisions remain with the host's one NativeAgentBroker instance.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import hashlib
import json
import re


class LineageError(ValueError):
    pass


def need(condition, reason):
    if not condition:
        raise LineageError(reason)


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':'), allow_nan=False).encode('utf-8')


def sha(value):
    return hashlib.sha256(value if isinstance(value, bytes)
                          else value.encode('utf-8')).hexdigest()


def identifier(value):
    return isinstance(value, str) and re.fullmatch(
        r'[A-Za-z0-9][A-Za-z0-9_.:/-]{0,255}', value) is not None


@dataclass(frozen=True)
class Node:
    input_id: str
    text: str
    output_hash: str
    input_hash: str | None
    input_ids: tuple[str, ...]
    input_hashes: tuple[str, ...]
    source_ids: tuple[str, ...]


class Lineage:
    """Append-only nodes; every direct input contributes its full root closure."""
    def __init__(self, sources):
        need(isinstance(sources, list) and len(sources) == 4,
             'exactly_four_sources_required')
        self._nodes = {}
        for source in sources:
            need(isinstance(source, dict) and set(source) == {'source_id', 'text'},
                 'invalid_source_fields')
            sid, text = source['source_id'], source['text']
            need(identifier(sid) and sid not in self._nodes,
                 'invalid_or_duplicate_source_id')
            self._text(text)
            self._nodes[sid] = Node(sid, text, sha(text), None, (), (), (sid,))
        self.source_ids = tuple(self._nodes)

    @staticmethod
    def _text(text):
        need(isinstance(text, str) and text.strip() and '\0' not in text
             and len(text) <= 12000, 'invalid_node_text')

    def get(self, input_id):
        need(isinstance(input_id, str) and input_id in self._nodes,
             'unknown_registered_input')
        node = self._nodes[input_id]
        need(sha(node.text) == node.output_hash, 'registered_content_hash_changed')
        return node

    def closure(self, input_ids):
        need(isinstance(input_ids, (list, tuple)) and input_ids
             and all(identifier(i) for i in input_ids)
             and len(input_ids) == len(set(input_ids)),
             'nonempty_unique_registered_inputs_required')
        roots, visited, active = set(), set(), set()

        def visit(input_id):
            need(input_id not in active, 'lineage_cycle')
            if input_id in visited:
                return
            node = self.get(input_id)
            active.add(input_id)
            if input_id in self.source_ids:
                need(not node.input_ids and node.source_ids == (input_id,),
                     'source_node_changed')
                roots.add(input_id)
            else:
                need(node.input_ids and len(node.input_ids) == len(node.input_hashes),
                     'empty_or_corrupt_derived_dependencies')
                for parent, digest in zip(node.input_ids, node.input_hashes):
                    need(self.get(parent).output_hash == digest,
                         'registered_input_hash_changed')
                    visit(parent)
            active.remove(input_id)
            visited.add(input_id)

        for item in input_ids:
            visit(item)
        need(roots, 'empty_root_dependency_closure')
        return [s for s in self.source_ids if s in roots]

    def inputs(self, input_ids):
        self.closure(input_ids)
        return [{'input_id': i, 'text': self.get(i).text,
                 'input_hash': self.get(i).output_hash} for i in input_ids]

    def register(self, input_id, text, input_ids, *, input_hash):
        need(identifier(input_id) and input_id not in self._nodes,
             'invalid_or_duplicate_derived_id')
        need(input_id not in input_ids, 'lineage_cycle')
        self._text(text)
        roots = self.closure(input_ids)
        need(isinstance(input_hash, str) and re.fullmatch(r'[0-9a-f]{64}', input_hash),
             'invalid_generation_input_hash')
        node = Node(input_id, text, sha(text), input_hash, tuple(input_ids),
                    tuple(self.get(i).output_hash for i in input_ids), tuple(roots))
        self._nodes[input_id] = node
        return self.metadata(input_id)

    def metadata(self, input_id):
        node = self.get(input_id)
        return {'input_id': node.input_id, 'input_hash': node.input_hash,
                'output_hash': node.output_hash, 'input_ids': list(node.input_ids),
                'input_hashes': list(node.input_hashes),
                'source_ids': self.closure([input_id])}

    def has(self, input_id):
        return input_id in self._nodes

