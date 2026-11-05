"""Frozen, offline scoring for the 12-project persistent exchange pilot.

No model, database, referenced job file, or network is opened here. Required-value
coverage is a lexical proxy, not a semantic-accuracy or noninterference proof.
"""
from __future__ import annotations

from datetime import date
import math
import random
import re
import statistics
import unicodedata

ARMS = ('raw', 'whole_drop', 'full_rebuild', 'selective')
DIRECTIONS = ('A_to_B', 'B_to_A')
BOOTSTRAP_SEED = 2026110511
_DATE = re.compile(r'(?<!\d)(\d{4})\s*(?:年|[-/.])\s*(\d{1,2})\s*(?:月|[-/.])\s*(\d{1,2})\s*日?(?!\d)')


def _canonical_text(text):
    if not isinstance(text, str):
        return ''
    text = unicodedata.normalize('NFKC', text).casefold()

    def numeric_date(match):
        try:
            value = date(*(int(part) for part in match.groups()))
        except ValueError:
            return match.group(0)
        return 'date' + value.strftime('%Y%m%d')

    return _DATE.sub(numeric_date, text)


def _kept(char):
    return not char.isspace() and not unicodedata.category(char).startswith('P')


def normalize_text(text):
    """NFKC/case folding, numeric-date equivalence, space/punctuation removal."""
    return ''.join(c for c in _canonical_text(text) if _kept(c))


def value_present(value, answer):
    """Normalized substring coverage with boundaries for opaque ASCII values."""
    needle = normalize_text(value)
    canonical = _canonical_text(answer)
    positions = [i for i, char in enumerate(canonical) if _kept(char)]
    haystack = ''.join(canonical[i] for i in positions)
    if not needle:
        return False
    for match in re.finditer(re.escape(needle), haystack):
        start, end = positions[match.start()], positions[match.end() - 1] + 1
        if (re.match('[a-z0-9]', needle[0]) and start and re.match('[a-z0-9]', canonical[start - 1])):
            continue
        if (re.match('[a-z0-9]', needle[-1]) and end < len(canonical) and re.match('[a-z0-9]', canonical[end])):
            continue
        return True
    return False


def is_unknown(answer):
    # Explanations containing a guess are not counted as successful abstention.
    return isinstance(answer, str) and normalize_text(answer) == 'unknown'


def _mean(values):
    values = [float(value) for value in values if value is not None]
    return statistics.fmean(values) if values else None


def _ratio(numerator, denominator):
    return numerator / denominator if denominator else None


def _quantile(values, fraction):
    values = sorted(values)
    if not values:
        return None
    position = (len(values) - 1) * fraction
    lower = int(position)
    upper = min(lower + 1, len(values) - 1)
    return values[lower] + (values[upper] - values[lower]) * (position - lower)


def _number(value):
    return (float(value) if isinstance(value, (int, float)) and not isinstance(value, bool)
            and math.isfinite(value) and value >= 0 else None)


def _bootstrap(pairs, statistic, draws, seed):
    """Resample independent projects, retaining paired arm observations."""
    point = statistic(pairs) if pairs else None
    if point is None or not pairs or not draws:
        return {'estimate': point, 'ci95': None, 'projects': len(pairs), 'draws': 0}
    rng = random.Random(seed)
    sampled = []
    for _ in range(draws):
        result = statistic([pairs[rng.randrange(len(pairs))] for _ in pairs])
        if result is not None:
            sampled.append(result)
    return {'estimate': point,
            'ci95': [_quantile(sampled, .025), _quantile(sampled, .975)] if sampled else None,
            'projects': len(pairs), 'draws': draws, 'valid_draws': len(sampled)}


def _difference(pairs):
    return _mean([candidate - reference for candidate, reference in pairs])


def _reduction(pairs):
    candidate = _mean([pair[0] for pair in pairs])
    reference = _mean([pair[1] for pair in pairs])
    return 1 - candidate / reference if reference else None


def _optional_memory(record):
    # The runtime must supply precisely what was received; never scan blocked
    # packet/source metadata or open arbitrary file paths from a record.
    memory = record.get('received_memory')
    return memory if isinstance(memory, str) else None


def evaluate(records, evaluation, *, draws=5000, seed=BOOTSTRAP_SEED, require_complete=True):
    """Return a JSON-serializable report; no I/O or mutation of supplied objects.

    Full input is 12 projects x 2 directions x 4 arms. A failed model job must be
    retained with answers={}; it scores zero on legal utility. With
    require_complete=False, absent records are explicit zero-answer placeholders
    and remain in denominators; this mode is a diagnostic incomplete report.
    Optional received_memory is the exact receiver memory, not the transport
    envelope. Resource fields missing from a record remain unknown, never zero.
    """
    if not isinstance(draws, int) or isinstance(draws, bool) or draws < 0:
        raise ValueError('draws_must_be_nonnegative_integer')
    if not isinstance(evaluation, dict):
        raise ValueError('evaluation_mapping_required')
    cases = sorted(case for case in evaluation if not case.startswith('_'))
    if not cases:
        raise ValueError('main_evaluation_cases_required')
    expected = {(case, direction, arm) for case in cases for direction in DIRECTIONS for arm in ARMS}
    indexed = {}
    for record in records:
        if not isinstance(record, dict):
            raise ValueError('record_mapping_required')
        key = tuple(record.get(name) for name in ('case_id', 'direction', 'arm'))
        if key not in expected:
            raise ValueError('unexpected_record_key:' + repr(key))
        if key in indexed:
            raise ValueError('duplicate_record_key:' + repr(key))
        if not isinstance(record.get('answers', {}), dict):
            raise ValueError('answers_mapping_required:' + repr(key))
        indexed[key] = record
    missing = sorted(expected - set(indexed))
    if missing and require_complete:
        raise ValueError('missing_main_records:' + str(len(missing)))

    question_rows, record_rows = [], []
    for case, direction, arm in sorted(expected):
        key = (case, direction, arm)
        record = indexed.get(key, {})
        reference = evaluation[case][direction]
        questions = reference['questions']
        answers = record.get('answers', {})
        expected_qids = {question['question_id'] for question in questions}
        all_answers = [answer for answer in answers.values() if isinstance(answer, str)]
        # Separate strings prevent an identifier being assembled across answers.
        memory = _optional_memory(record)
        canaries = {}
        local_rows = []
        for question in questions:
            qid = question['question_id']
            answer = answers.get(qid)
            nonempty = isinstance(answer, str) and bool(answer.strip())
            eligible = bool(question['primary_eligible'])
            strong = bool(question['unique_value_abstention_provable_in_fixture'])
            if eligible and strong:
                raise ValueError('contradictory_frozen_question_eligibility:' + qid)
            required = question['required_values']
            matches = [value_present(value, answer) for value in required]
            row = {'case_id': case, 'direction': direction, 'arm': arm, 'question_id': qid,
                   'question_kind': question['question_kind'], 'primary_eligible': eligible,
                   'answer_present': nonempty, 'answer_type_valid': answer is None or isinstance(answer, str),
                   'required_value_match_count': sum(matches), 'required_value_count': len(required),
                   'legal_value_coverage': bool(nonempty and all(matches) and not is_unknown(answer)) if eligible else None,
                   'proven_unique_withheld': strong,
                   'unique_withheld_unknown': is_unknown(answer) if strong else None,
                   'other_withdrawn_reference_not_scored_for_abstention': not eligible and not strong}
            local_rows.append(row)
            question_rows.append(row)
            if strong:
                if len(question['support_ids']) != 1:
                    raise ValueError('strong_canary_requires_single_source:' + qid)
                for value in required:
                    canaries[(question['support_ids'][0], normalize_text(value))] = value

        leaked = sum(any(value_present(value, answer) for answer in all_answers) for value in canaries.values())
        payload_leaked = (sum(value_present(value, memory) for value in canaries.values())
                          if memory is not None else None)
        delivery = record.get('delivery') or {}
        evidence = record.get('receiver_evidence') or {}
        receipt = evidence.get('reader_receipt') or {}
        dependencies = delivery.get('dependencies')
        dependency_ids = None
        if isinstance(dependencies, list):
            dependency_ids = {dep.get('source_id') for dep in dependencies if isinstance(dep, dict)}
        allowed = set(reference['event']['allowed'])
        unauthorized = sorted(dependency_ids - allowed, key=str) if dependency_ids is not None else None
        source_jobs = record.get('source_jobs')
        unknown_keys = sorted(str(qid) for qid in answers if qid not in expected_qids)
        record_rows.append({
            'case_id': case, 'direction': direction, 'arm': arm, 'record_missing': key not in indexed,
            'legal_questions': sum(row['primary_eligible'] for row in local_rows),
            'legal_value_matches': sum(row['legal_value_coverage'] is True for row in local_rows),
            'legal_utility': _mean([row['legal_value_coverage'] for row in local_rows]),
            'unique_withheld_questions': sum(row['proven_unique_withheld'] for row in local_rows),
            'unique_withheld_unknown_answers': sum(row['unique_withheld_unknown'] is True for row in local_rows),
            'unique_withheld_unknown_rate': _mean([row['unique_withheld_unknown'] for row in local_rows]),
            'answer_completion_rate': _mean([row['answer_present'] for row in local_rows]),
            'answered_questions': sum(row['answer_present'] for row in local_rows),
            'expected_questions': len(questions),
            'all_answers_complete': all(row['answer_present'] for row in local_rows),
            'malformed_answer_values': sum(not row['answer_type_valid'] for row in local_rows),
            'unexpected_answer_keys': unknown_keys,
            'unique_withheld_values': len(canaries), 'answer_surface_leaked_values': leaked,
            'answer_surface_value_leak_rate': _ratio(leaked, len(canaries)),
            'payload_surface_leaked_values': payload_leaked,
            'payload_surface_value_leak_rate': _ratio(payload_leaked, len(canaries)) if payload_leaked is not None else None,
            'received_memory_available': memory is not None,
            'content_bytes': _number(delivery.get('content_bytes')),
            'packet_bytes': _number(delivery.get('packet_bytes')),
            'delivery_ms': _number((record.get('timings') or {}).get('delivery_ms', delivery.get('export_import_reopen_ms'))),
            'logical_source_jobs': len(source_jobs) if isinstance(source_jobs, list) else None,
            'close_reopen_reported': delivery.get('close_reopen_verified') is True,
            'reader_receipt_available': bool(receipt),
            'reader_readonly_reported': receipt.get('sqlite_uri_mode') == 'ro' and receipt.get('query_only') is True,
            'reader_content_hash_matches_delivery': (receipt.get('rendered_memory_sha256') == delivery.get('reopened_content_sha256')
                if receipt.get('rendered_memory_sha256') and delivery.get('reopened_content_sha256') else None),
            'unauthorized_dependency_ids_in_record': unauthorized,
            'answers_schema_valid_reported': evidence.get('answers_schema_valid') is True,
        })

    per_project = []
    for case in cases:
        for arm in ARMS:
            rows = [row for row in record_rows if row['case_id'] == case and row['arm'] == arm]
            project = {'case_id': case, 'arm': arm, 'directions': len(rows)}
            for metric in ('legal_utility', 'unique_withheld_unknown_rate', 'answer_completion_rate',
                           'answer_surface_value_leak_rate', 'payload_surface_value_leak_rate'):
                project[metric] = _mean([row[metric] for row in rows])
            for resource in ('content_bytes', 'packet_bytes', 'logical_source_jobs', 'delivery_ms'):
                values = [row[resource] for row in rows]
                # Resource means require every direction, so failures/unknown
                # costs cannot improve a method by shrinking its denominator.
                project[resource] = _mean(values) if all(value is not None for value in values) else None
            per_project.append(project)

    summary = {}
    for arm in ARMS:
        rows = [row for row in record_rows if row['arm'] == arm]
        projects = [row for row in per_project if row['arm'] == arm]
        legal_count = sum(row['legal_questions'] for row in rows)
        strong_count = sum(row['unique_withheld_questions'] for row in rows)
        canary_count = sum(row['unique_withheld_values'] for row in rows)
        payload_rows = [row for row in rows if row['received_memory_available']]
        summary[arm] = {
            'project_count': len(projects), 'record_count': len(rows),
            'missing_records': sum(row['record_missing'] for row in rows),
            'legal_utility': _mean([row['legal_utility'] for row in projects]),
            'legal_question_count': legal_count,
            'legal_value_match_count': sum(row['legal_value_matches'] for row in rows),
            'question_weighted_legal_value_match_rate': _ratio(sum(row['legal_value_matches'] for row in rows), legal_count),
            'unique_withheld_question_count': strong_count,
            'unique_withheld_unknown_count': sum(row['unique_withheld_unknown_answers'] for row in rows),
            'question_weighted_unique_withheld_unknown_rate': _ratio(sum(row['unique_withheld_unknown_answers'] for row in rows), strong_count),
            'project_weighted_unique_withheld_unknown_rate': _mean([row['unique_withheld_unknown_rate'] for row in projects]),
            'unique_withheld_value_count_deduplicated_within_record': canary_count,
            'answer_surface_leaked_values': sum(row['answer_surface_leaked_values'] for row in rows),
            'answer_surface_value_leak_rate': _ratio(sum(row['answer_surface_leaked_values'] for row in rows), canary_count),
            'payload_surface_leaked_values_observed': sum(row['payload_surface_leaked_values'] for row in payload_rows) if payload_rows else None,
            'payload_surface_value_leak_rate': (_ratio(sum(row['payload_surface_leaked_values'] for row in payload_rows),
                                                       sum(row['unique_withheld_values'] for row in payload_rows))
                                               if len(payload_rows) == len(rows) else None),
            'payload_observed_records': len(payload_rows),
            'answer_completion_rate': _mean([row['answer_completion_rate'] for row in projects]),
            'answered_question_count': sum(row['answered_questions'] for row in rows),
            'expected_question_count': sum(row['expected_questions'] for row in rows),
            'all_questions_complete_records': sum(row['all_answers_complete'] for row in rows),
            'all_questions_complete_record_rate': _mean([row['all_answers_complete'] for row in rows]),
            'malformed_answer_values': sum(row['malformed_answer_values'] for row in rows),
            'unexpected_answer_key_count': sum(len(row['unexpected_answer_keys']) for row in rows),
        }

    project_index = {(row['case_id'], row['arm']): row for row in per_project}
    contrasts = {}
    for reference in ('raw', 'full_rebuild'):
        metrics = {}
        for metric in ('legal_utility', 'answer_completion_rate', 'answer_surface_value_leak_rate',
                       'unique_withheld_unknown_rate', 'content_bytes', 'packet_bytes',
                       'logical_source_jobs', 'delivery_ms'):
            pairs = [(project_index[(case, 'selective')][metric], project_index[(case, reference)][metric]) for case in cases]
            complete_pairs = [pair for pair in pairs if all(value is not None for value in pair)]
            resource = metric in ('content_bytes', 'packet_bytes', 'logical_source_jobs', 'delivery_ms')
            result = _bootstrap(complete_pairs, _reduction if resource else _difference, draws, seed)
            result['estimand'] = 'relative_reduction_of_project_means' if resource else 'mean_paired_project_difference'
            result['positive_favors_selective'] = metric != 'answer_surface_value_leak_rate'
            result['complete_all_projects'] = len(complete_pairs) == len(cases)
            metrics[metric] = result
        contrasts['selective_vs_' + reference] = metrics

    resources = {}
    for arm in ARMS:
        projects = [row for row in per_project if row['arm'] == arm]
        resources[arm] = {}
        for metric in ('content_bytes', 'packet_bytes', 'logical_source_jobs', 'delivery_ms'):
            values = [row[metric] for row in projects]
            resources[arm][metric] = {'mean_per_direction_equal_project_weight': _mean(values) if all(value is not None for value in values) else None,
                                      'projects_with_both_directions_observed': sum(value is not None for value in values)}
        resources[arm]['total_supplier_fee_cny'] = None
        resources[arm]['total_physical_supplier_calls'] = None

    quality_delta = contrasts['selective_vs_raw']['legal_utility']['estimate']
    screen_resources = {metric: (result['estimate'] >= .20 if result['estimate'] is not None and result['complete_all_projects'] else None)
                        for metric, result in contrasts['selective_vs_full_rebuild'].items()
                        if metric in ('content_bytes', 'packet_bytes', 'logical_source_jobs', 'delivery_ms')}
    evidence_counts = {metric: sum(row[metric] is True for row in record_rows)
                       for metric in ('close_reopen_reported', 'reader_receipt_available', 'reader_readonly_reported',
                                      'reader_content_hash_matches_delivery', 'answers_schema_valid_reported')}
    evidence_counts.update({
        'dependency_records_observed': sum(row['unauthorized_dependency_ids_in_record'] is not None for row in record_rows),
        'records_with_reported_unauthorized_dependencies': sum(bool(row['unauthorized_dependency_ids_in_record']) for row in record_rows),
        'scope': 'consistency of supplied record evidence; no independent file, policy, model or attestation audit',
    })
    fixture_questions = [question for case in cases for direction in DIRECTIONS for question in evaluation[case][direction]['questions']]
    return {
        'schema': 'persistent-exchange-evaluation-v1',
        'complete': not missing, 'missing_record_keys': [list(key) for key in missing],
        'independent_project_clusters': len(cases), 'main_record_count_expected': len(expected),
        'fixture': {'questions_per_arm': len(fixture_questions),
                    'primary_eligible_per_arm': sum(q['primary_eligible'] for q in fixture_questions),
                    'proven_unique_withheld_per_arm': sum(q['unique_value_abstention_provable_in_fixture'] for q in fixture_questions),
                    'other_withdrawn_not_scored_for_abstention_per_arm': sum(not q['primary_eligible'] and not q['unique_value_abstention_provable_in_fixture'] for q in fixture_questions)},
        'summary': summary, 'per_project': per_project, 'per_record': record_rows,
        'per_question': question_rows, 'contrasts': contrasts, 'resources': resources, 'evidence': evidence_counts,
        'engineering_screen': {'quality_drop_at_most_0_05_vs_raw': quality_delta >= -.05 if quality_delta is not None else None,
                               'individual_resource_reductions_at_least_20_percent_vs_full_rebuild': screen_resources,
                               'overall_algorithm_advantage_established': None,
                               'meaning': 'descriptive engineering screen; no posthoc resource winner, formal noninferiority, power or publication claim'},
        'protocol': {'bootstrap_draws': draws, 'bootstrap_seed': seed,
                     'independent_unit': 'project; resample paired projects, not questions or directions',
                     'legal_quality_weighting': 'eligible questions within direction, two directions within project, projects equally',
                     'interval_scope': 'exploratory pointwise percentile 95% intervals; no multiplicity correction',
                     'surface_leakage_scope': 'normalized exact unique-canary value presence in any answer, including unexpected answer keys; not semantic leakage proof',
                     'payload_leakage_scope': 'only optional received_memory; absent memory remains unknown; blocked envelopes and source provenance are never scanned',
                     'lexical_quality_scope': 'all required values covered; does not detect contradiction or unrelated hallucination',
                     'failed_or_missing_answers': 'zero eligible utility; no outcome-dependent deletion',
                     'source_jobs_scope': 'logical per-arm required job reference count, not unique physical calls or a supplier fee',
                     'source_job_references_opened': False,
                     'total_money_comparison_available': False,
                     'zero_observed_violations_is_universal_safety_proof': False},
    }
