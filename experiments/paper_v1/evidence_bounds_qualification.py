"""Finite qualification of source-evidence bounds; standard library only.

We compare the ordinary set rule to independently enumerated admissible hidden
source histories. This is a bounded negative novelty check, not a new algorithm,
an LLM causal tracer, an SMT run, or a benchmark of commercial agents.
"""
from __future__ import annotations

import argparse
import hashlib
import itertools
import json
from collections import Counter
from pathlib import Path


def subsets(values):
    values = tuple(sorted(values))
    for mask in range(1 << len(values)):
        yield frozenset(v for i, v in enumerate(values) if mask & (1 << i))


def set_baseline(lower, upper, allowed):
    if lower - allowed:
        return 'deny'
    if not (upper - allowed):
        return 'allow'
    return 'unknown'


def enumeration_oracle(lower, upper, allowed):
    good, bad = [], []
    for optional in subsets(upper - lower):
        actual = lower | optional
        (good if actual <= allowed else bad).append(sorted(actual))
    if good and bad:
        return 'unknown', good[0], bad[0], len(good) + len(bad)
    if good:
        return 'allow', good[0], None, len(good)
    return 'deny', None, bad[0], len(bad)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    universe = tuple('S' + str(i) for i in range(4))
    rows, counts = [], Counter()
    total_histories = 0
    for state in itertools.product(('absent', 'possible', 'observed'), repeat=4):
        lower = frozenset(s for s, tag in zip(universe, state) if tag == 'observed')
        upper = frozenset(s for s, tag in zip(universe, state) if tag != 'absent')
        for allowed in subsets(universe):
            baseline = set_baseline(lower, upper, allowed)
            oracle, good, bad, histories = enumeration_oracle(lower, upper, allowed)
            assert baseline == oracle, (lower, upper, allowed, baseline, oracle)
            if oracle == 'unknown':
                assert lower <= set(good) <= upper and lower <= set(bad) <= upper
                assert set(good) <= allowed and not set(bad) <= allowed
            total_histories += histories
            counts[oracle] += 1
            rows.append({'lower': sorted(lower), 'upper': sorted(upper),
                         'allowed': sorted(allowed), 'set_baseline': baseline,
                         'enumeration_oracle': oracle, 'consistent_histories': histories,
                         'safe_witness': good, 'unsafe_witness': bad})
    payload = {
        'schema': 'paper-v1-evidence-bounds-qualification-v1', 'date': '2026-11-05',
        'contract': {'protected_object': 'use of a disallowed source in an artifact',
                     'semantic_rule': 'every actual source must be allowed (conservative input influence)',
                     'assumptions': ['The trusted bounds satisfy lower <= actual <= upper.',
                                     'Any subset between the bounds is admissible; no extra correlations.',
                                     'The finite universe is complete for this qualification.'],
                     'non_goals': ['Recover hidden commercial-client reads.',
                                   'Determine minimal semantic support or semantic leakage.',
                                   'Claim three-valued logic or set operations as novel.']},
        'summary': {'universe_size': len(universe), 'evidence_permission_cases': len(rows),
                    'enumerated_histories_across_cases': total_histories,
                    'verdict_counts': dict(counts), 'disagreements': 0,
                    'unknown_cases_with_safe_and_unsafe_witness': counts['unknown'],
                    'new_model_calls': 0, 'z3_or_hypothesis_used': False},
        'interpretation': 'Under this exact contract the set baseline already returns the exact three-valued verdict. A solver that merely recodes the same bounds cannot gain classification accuracy; a new claim needs additional validated constraints, a different cost objective, or a separately justified threat model.',
        'script_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'rows': rows,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(payload['summary'], ensure_ascii=False))


if __name__ == '__main__':
    main()
