"""Replay pinned upstream method bodies with mock stores, NOT full integrations.

The permission policy in this counterexample grants A,C and denies sibling B.
These generic upstream retrievers do not advertise that child search filters
authorize subsequent parent fetches. This is an integration-boundary example,
not a vulnerability claim against a configured production service.
MIT upstream source snapshots and notices are kept alongside this module.
"""
import ast
from collections import defaultdict
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Dict, List, Tuple, cast

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
CANARY = 'DENIED_SIBLING_B_72639'


class Node:
    def __init__(self, node_id, text='', parent=None, children=()):
        self.node_id, self.text = node_id, text
        self.parent_node = SimpleNamespace(node_id=parent) if parent else None
        self.child_nodes = [SimpleNamespace(node_id=c) for c in children]
        self.metadata = {'doc_id': parent} if parent else {}

    def get_content(self, **kwargs):
        return self.text


class NodeWithScore:
    def __init__(self, node, score=.9):
        self.node, self.score = node, score

    def get_score(self):
        return self.score


def method_from_snapshot(filename, class_name, method_name, globals_map):
    path = HERE / 'source_snapshots' / filename
    body = path.read_bytes()
    tree = ast.parse(body.decode('utf-8'))
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == class_name)
    method = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == method_name)
    source_lines = [method.lineno, method.end_lineno]
    # typing.override has no algorithmic body semantics; the decorator is the
    # sole removed AST element. The complete method body remains unchanged.
    removed_decorators = len(method.decorator_list)
    method.decorator_list = []
    module = ast.fix_missing_locations(ast.Module(body=[method], type_ignores=[]))
    namespace = dict(globals_map)
    exec(compile(module, str(path), 'exec'), namespace)
    return namespace[method_name], {'snapshot': str(path), 'sha256': hashlib.sha256(body).hexdigest(),
        'source_lines': source_lines, 'removed_typing_decorators': removed_decorators,
        'algorithmic_body_modified': False}


def main():
    output = REPO / 'results/permission_context_v1/upstream-method-replay-20261105-v1'
    output.mkdir(parents=True, exist_ok=False)
    parent = Node('P', 'A: project approved.\nB: ' + CANARY + '\nC: deadline Friday.', children=['A','B','C'])
    seeds = [Node('A', 'project approved.', 'P'), Node('C', 'deadline Friday.', 'P')]
    logger = SimpleNamespace(info=lambda *args, **kwargs: None)
    common = dict(Dict=Dict, List=List, Tuple=Tuple, defaultdict=defaultdict, cast=cast,
        BaseNode=Node, NodeWithScore=NodeWithScore,
        MetadataMode=SimpleNamespace(NONE='NONE'), logger=logger,
        truncate_text=lambda text, limit: text[:limit])
    rows = []
    llama, snapshot = method_from_snapshot('llama_auto_merging.py', 'AutoMergingRetriever',
        '_get_parents_and_merge', common)
    fetched = []

    def get_document(node_id):
        fetched.append(node_id)
        if node_id != 'P':
            raise ValueError('unexpected_mock_fetch')
        return parent

    mock = SimpleNamespace(_storage_context=SimpleNamespace(docstore=SimpleNamespace(get_document=get_document)),
                           _simple_ratio_thresh=.5, _verbose=False)
    merged, changed = llama(mock, [NodeWithScore(n) for n in seeds])
    rows.append({'upstream': 'run-llama/llama_index', 'commit': '444fdf0684707de62ebb447d658dba137dd9cb99',
        'method': '_get_parents_and_merge', 'snapshot': snapshot,
        'authorized_child_ids_entering_method': ['A', 'C'], 'denied_child_ids': ['B'],
        'parent_fetches': fetched, 'default_merge_ratio_threshold': .5,
        'merge_triggered': changed,
        'returned_parent_contains_denied_sibling': any(CANARY in n.node.get_content() for n in merged)})

    langchain, snapshot = method_from_snapshot('langchain_multi_vector.py', 'MultiVectorRetriever',
        '_get_relevant_documents', {'Document': Node, 'CallbackManagerForRetrieverRun': object,
            'SearchType': SimpleNamespace(similarity='similarity', mmr='mmr', similarity_score_threshold='threshold')})
    search_calls, parent_calls = [], []

    def similarity_search(query, **kwargs):
        search_calls.append({'query': query, 'kwargs': kwargs, 'returned_authorized_ids': ['A', 'C']})
        return seeds

    def mget(ids):
        parent_calls.append(ids)
        return [parent]

    mock = SimpleNamespace(search_type='similarity', search_kwargs={'filter': {'allow': True}},
        id_key='doc_id', vectorstore=SimpleNamespace(similarity_search=similarity_search),
        docstore=SimpleNamespace(mget=mget))
    result = langchain(mock, 'project deadline?', run_manager=None)
    rows.append({'upstream': 'langchain-ai/langchain', 'commit': 'bbcdd568cd02b81e5ede5aa525744e79e67c2278',
        'method': '_get_relevant_documents', 'snapshot': snapshot,
        'search_calls': search_calls, 'parent_mget_calls': parent_calls,
        'authorized_child_ids_entering_method': ['A', 'C'], 'denied_child_ids': ['B'],
        'returned_parent_contains_denied_sibling': any(CANARY in n.get_content() for n in result)})
    if not all(r['returned_parent_contains_denied_sibling'] for r in rows):
        raise AssertionError('expected_pinned_method_counterexample_not_reproduced')
    summary = {'scope': 'unchanged_upstream_method_bodies_with_mock_document_stores',
        'full_framework_integration_test': False, 'production_vulnerability_claim': False,
        'model_calls': 0, 'rows': rows,
        'finding': 'authorization of child retrieval alone does not authorize a subsequent mixed parent body'}
    (output / 'summary.json').write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps({'source_level_counterexamples_reproduced': len(rows), 'model_calls': 0,
        'full_framework_integration_test': False, 'output': str(output)}))


if __name__ == '__main__':
    main()
