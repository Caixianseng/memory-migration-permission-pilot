"""Offline nontriviality gate, not a new algorithm or a model evaluator."""
from __future__ import annotations

from .driver import SOURCE_IDS, verify_event_trace


def affected_units(dependencies, revoked=('S01',)):
    if type(dependencies) is not dict or not dependencies:
        raise ValueError('nonempty_dependency_inventory_required')
    revoked = set(revoked)
    result = []
    for unit, ids in dependencies.items():
        if (type(unit) is not str or not unit or type(ids) is not list or not ids
                or len(ids) != len(set(ids)) or not set(ids) <= set(SOURCE_IDS)):
            raise ValueError('trusted_dependency_inventory_invalid')
        if revoked.intersection(ids):
            result.append(unit)
    return result


def nontriviality_gate(dependencies, *, trusted_input_trace=False):
    """Classify a host-supplied actual-input DAG before any paid candidate test.

    A mixed AND graph and a source-isolated cache are explicit conventional
    controls. A partially affected mixed graph is only structurally eligible;
    it proves neither semantic independence nor quality/cost improvement.
    """
    if type(trusted_input_trace) is not bool:
        raise ValueError('trusted_input_trace_must_be_boolean')
    affected = affected_units(dependencies)
    unaffected = [unit for unit in dependencies if unit not in affected]
    if not trusted_input_trace:
        status, reason = 'inconclusive', 'actual_generation_input_trace_not_qualified'
    elif len(affected) == len(dependencies):
        status, reason = 'stop_candidate', 'all_units_affected_degenerates_to_full_rebuild'
    elif all(len(ids) == 1 for ids in dependencies.values()):
        status, reason = 'stop_candidate', 'equivalent_to_ordinary_independent_source_cache'
    elif not affected:
        status, reason = 'stop_candidate', 'no_revocation_repair_needed'
    else:
        status, reason = 'structurally_eligible_only', 'partial_influence_requires_quality_and_lifecycle_cost_evidence'
    return {'schema': 'pre-delivery-nontriviality-gate-v1',
            'nontriviality_gate': status, 'reason': reason,
            'affected_units': affected, 'unaffected_units': unaffected,
            'actual_input_trace_qualified_by_caller': trusted_input_trace,
            'method_advantage': None, 'research_passed': False,
            'new_algorithm_claim': False}


def inspect_event_trace(path):
    rows = verify_event_trace(path)
    kinds = [e['kind'] for e in rows]
    important = [e['kind'] for e in rows if e['kind'] in {
        'sources_registered', 'M_sealed', 'S01_export_revoked',
        'old_M_denied', 'R_sealed', 'delivery_committed'}]
    expected = ['sources_registered', 'M_sealed', 'S01_export_revoked',
                'old_M_denied', 'R_sealed', 'delivery_committed']
    return {'schema': 'pre-delivery-trace-inspection-v1',
            'integrity_verified': True, 'event_count': len(rows),
            'registered_event_sequence_complete': important == expected,
            'target_callback_outcome': (
                'failed_or_unknown' if 'target_failed_or_unknown' in kinds
                or any(e['kind'] == 'halted' and e['data'].get('reason')
                       == 'invalid_target_receipt_after_possible_send' for e in rows)
                else 'returned_unverified' if 'target_callback_returned' in kinds
                else 'not_recorded'),
            'instrument_only': any(e['instrument_only'] for e in rows),
            'real_model_trace': False, 'source_adapter_authentication_verified': False,
            'target_receipt_verified': False, 'research_passed': False,
            'qualification': 'event_order_only_requires_separate_native_trace_and_target_evidence'}
