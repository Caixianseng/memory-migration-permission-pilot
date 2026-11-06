"""CPU-only third-party qualification. No new repair method and no model calls."""
from __future__ import annotations
import hashlib
import importlib.metadata as md
import itertools
import json
import platform
import random
import sys
import tempfile
import time
import traceback
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
EVIDENCE = ROOT / 'research_paper_v1/evidence/external_candidates'
sys.path.insert(0, str(HERE / 'deps'))
sys.path.insert(0, str(ROOT))
SEED = 20261105


def graph_probe():
    import networkx as nx
    rng = random.Random(SEED)
    rows = []
    for trial in range(100):
        graph = nx.DiGraph()
        sources = [f's{i}' for i in range(5)]
        graph.add_nodes_from(sources)
        deps = {s: {s} for s in sources}
        derived = []
        for j in range(25):
            node = f'd{j}'
            parents = rng.sample(list(deps), rng.randint(1, min(4, len(deps))))
            graph.add_edges_from((p, node) for p in parents)
            deps[node] = set().union(*(deps[p] for p in parents))
            derived.append(node)
        for mask in range(32):
            revoked = {s for i, s in enumerate(sources) if mask & (1 << i)}
            expected = {d for d in derived if deps[d] & revoked}
            actual = set().union(*(nx.descendants(graph, s) for s in revoked)) if revoked else set()
            actual &= set(derived)
            rows.append({'trial': trial, 'revoked_mask': mask, 'expected': sorted(expected),
                         'actual': sorted(actual), 'match': expected == actual})
    # Intentional mutation control, not a discovered production defect.
    broken = nx.DiGraph([('s0', 'd0'), ('s1', 'd0')])
    broken.remove_edge('s1', 'd0')
    mutation = {'omitted_edge': ['s1', 'd0'], 'actual_dependency': ['s0', 's1'],
                'revoked': ['s1'], 'expected_affected': ['d0'],
                'observed_affected': sorted(nx.descendants(broken, 's1'))}
    return {'cases': len(rows), 'mismatches': sum(not r['match'] for r in rows),
            'rows': rows, 'missing_edge_negative_control': mutation,
            'contract': 'Complete source-to-derived DAG; conservative AND dependencies. Simple set intersection is equivalent oracle.'}


def z3_probe():
    import z3
    grants = z3.Bools('grant0 grant1 grant2')
    rows = []
    for dep_mask in range(1, 8):
        for observed in itertools.product((None, False, True), repeat=3):
            for epoch_match, nonce_fresh in itertools.product((False, True), repeat=2):
                solver = z3.Solver()
                solver.set(timeout=2000)
                for g, value in zip(grants, observed):
                    if value is not None:
                        solver.add(g == value)
                allow = z3.And(*[g for i, g in enumerate(grants) if dep_mask & (1 << i)],
                               z3.BoolVal(epoch_match), z3.BoolVal(nonce_fresh))
                outcomes = []
                witnesses = {}
                for name, expr in [('allow', allow), ('deny', z3.Not(allow))]:
                    solver.push(); solver.add(expr)
                    status = solver.check()
                    outcomes.append(str(status))
                    if status == z3.sat:
                        model = solver.model()
                        witnesses[name] = [z3.is_true(model.eval(g, model_completion=True)) for g in grants]
                    solver.pop()
                actual = ('unknown_solver' if 'unknown' in outcomes else
                          'ambiguous' if outcomes == ['sat', 'sat'] else
                          'must_allow' if outcomes == ['sat', 'unsat'] else 'must_deny')
                truth = []
                for completion in itertools.product((False, True), repeat=3):
                    if all(v is None or v == c for v, c in zip(observed, completion)):
                        truth.append(epoch_match and nonce_fresh and all(completion[i] for i in range(3) if dep_mask & (1 << i)))
                expected = 'must_allow' if all(truth) else 'must_deny' if not any(truth) else 'ambiguous'
                rows.append({'dependency_mask': dep_mask, 'observed_grants': observed,
                             'epoch_match': epoch_match, 'nonce_fresh': nonce_fresh,
                             'expected': expected, 'actual': actual, 'match': expected == actual,
                             'satisfiability': outcomes, 'witnesses': witnesses})
    example = next(r for r in rows if r['actual'] == 'ambiguous' and r['dependency_mask'] == 7
                   and r['observed_grants'] == (True, True, None))
    # False model supplied to a correct solver: omitted third dependency cannot be recovered.
    return {'cases': len(rows), 'mismatches': sum(not r['match'] for r in rows), 'rows': rows,
            'ambiguity_two_models': example,
            'missing_dependency_negative_control': {'declared_dependencies': [0, 1], 'actual_dependencies': [0, 1, 2],
               'permissions': [True, True, False], 'declared_formula_allows': True, 'actual_formula_allows': False},
            'contract': 'Bounded Boolean model only. Equivalent to simple enumeration/set checks here; not a new algorithm or hidden-source detector.'}


def stateful_probe():
    from hypothesis import find, seed, settings, strategies as st
    from hypothesis.stateful import RuleBasedStateMachine, rule, invariant, run_state_machine_as_test
    from experiments.persistent_exchange_v1.store import AgentStore, TrustedPolicy, StoreError, export_package, import_package, verify_events
    counts = Counter()
    failures = []
    runroot = HERE / 'runs'
    runroot.mkdir(exist_ok=True)

    class ExchangeMachine(RuleBasedStateMachine):
        def __init__(self):
            super().__init__()
            self.tmp = tempfile.TemporaryDirectory(prefix='state-', dir=runroot)
            base = Path(self.tmp.name)
            self.a = AgentStore(base / 'a.sqlite', 'A')
            self.b = AgentStore(base / 'b.sqlite', 'B')
            self.p = TrustedPolicy(base / 'policy.sqlite')
            self.ids = {f's{i}' for i in range(3)}
            for sid in sorted(self.ids): self.a.add_original(sid, f'Original private body {sid}')
            self.p.register_sources(self.a.originals(), owner_id='A')
            self.allowed = set(self.ids)
            self.p.set_permissions('B', sorted(self.allowed))
            self.a.add_memory('m0', 'Derived from source zero', source_ids=['s0'])
            self.a.add_memory('m1', 'Derived from zero and one', source_ids=['s1'], parent_memory_ids=['m0'])
            self.a.add_memory('m2', 'Derived from all three', source_ids=['s2'], parent_memory_ids=['m1'])
            self.packets = []
            self.consumed = set()
            self.accepted = set()
            self.n = 0
            counts['machine_examples'] += 1

        @rule(mask=st.integers(min_value=0, max_value=7))
        def change_permissions(self, mask):
            self.allowed = {f's{i}' for i in range(3) if mask & (1 << i)}
            self.p.set_permissions('B', sorted(self.allowed))
            counts['permission_changes'] += 1

        @rule(index=st.integers(min_value=0, max_value=2))
        def export(self, index):
            self.n += 1
            required = {f's{i}' for i in range(index + 1)}
            expected = required <= self.allowed
            try:
                packet = export_package(self.a, self.p, 'B', [f'm{index}'], batch_id=f'b{self.n}')
                actual = True
                self.packets.append(packet)
            except StoreError:
                actual = False
            assert actual == expected, ('export', expected, actual)
            counts['export_attempts'] += 1
            counts['exports_accepted' if actual else 'exports_rejected'] += 1

        @rule(index=st.integers(min_value=0, max_value=20))
        def import_existing(self, index):
            if not self.packets: return
            packet = self.packets[index % len(self.packets)]
            expected = (packet['epoch'] == self.p.epoch and packet['nonce'] not in self.consumed
                        and {s['source_id'] for s in packet['sources']} <= self.allowed)
            try:
                import_package(self.b, self.p, packet)
                actual = True
                self.consumed.add(packet['nonce'])
                self.accepted.add(packet['batch_id'])
            except StoreError:
                actual = False
            if actual != expected:
                failures.append({'expected': expected, 'actual': actual, 'epoch': self.p.epoch})
            assert actual == expected, ('import', expected, actual)
            counts['import_attempts'] += 1
            counts['imports_accepted' if actual else 'imports_rejected'] += 1

        @invariant()
        def receiver_has_no_original_plaintext(self):
            assert self.b.originals() == []
            assert {r[0] for r in self.b.db.execute('SELECT batch_id FROM batches')} == self.accepted
            verify_events(self.b.db)
            counts['invariant_checks'] += 1

        def teardown(self):
            self.a.close(); self.b.close(); self.p.close(); self.tmp.cleanup()

    # derandomize selects stable generated cases; random receipt nonces are opaque identifiers only.
    config = settings(max_examples=25, stateful_step_count=25, deadline=None, database=None, derandomize=True)
    run_state_machine_as_test(ExchangeMachine, settings=config)

    def stale_gate_disagrees(events):
        allowed, packet, mismatch = True, False, False
        for event in events:
            if event == 'export' and allowed: packet = True
            elif event == 'revoke': allowed = False
            elif event == 'import' and packet and not allowed: mismatch = True
        return mismatch
    witness = find(st.lists(st.sampled_from(['export', 'revoke', 'import']), min_size=0, max_size=12),
                   stale_gate_disagrees, settings=settings(max_examples=1000, deadline=None, database=None, derandomize=True))
    return {'counts': dict(counts), 'failures': failures, 'max_examples': 25, 'stateful_step_count': 25,
            'shrunk_mutation_control': witness,
            'contract': 'Actual existing SQLite host tested against current epoch + complete dependency + fresh nonce contract. No post-disclosure erasure claim. Mutated cached gate is separate toy control, not production defect.'}


def main():
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    result = {'schema': 'external-candidate-qualification-v1', 'seed': SEED,
              'python': sys.version, 'executable': sys.executable, 'platform': platform.platform(),
              'command': [sys.executable, str(Path(__file__).resolve())], 'packages': {}, 'probes': {}}
    for name in ['networkx', 'z3-solver', 'hypothesis', 'sortedcontainers']:
        try: result['packages'][name] = md.version(name)
        except md.PackageNotFoundError: result['packages'][name] = None
    probes = [('networkx', graph_probe)] if '--only-networkx' in sys.argv else [('networkx', graph_probe), ('z3', z3_probe), ('hypothesis', stateful_probe)]
    result['arguments'] = sys.argv[1:]
    for name, probe in probes:
        begin = time.perf_counter()
        try:
            data = probe()
            status = 'passed' if not data.get('mismatches', 0) and not data.get('failures', []) else 'failed'
            (EVIDENCE / (name + '_raw.json')).write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8')
            result['probes'][name] = {'status': status, 'elapsed_seconds': time.perf_counter() - begin,
               **{k: v for k, v in data.items() if k not in ('rows',)}}
        except Exception:
            result['probes'][name] = {'status': 'error', 'elapsed_seconds': time.perf_counter() - begin,
                                      'traceback': traceback.format_exc()}
    result['exit_code'] = 0 if all(p['status'] == 'passed' for p in result['probes'].values()) else 1
    target = 'networkx_qualification_results.json' if '--only-networkx' in sys.argv else 'qualification_results.json'
    (EVIDENCE / target).write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return result['exit_code']


if __name__ == '__main__':
    raise SystemExit(main())
