"""Source-only, post-run cost calibration; never opens target answers/events.

The first 64 bytes of each calls file identify the top-level role written first
by lifecycle_runner.invoke. Non-source files are not opened beyond that header.
Only source jobs whose every (source_id, text SHA256) matches the selected case
are admitted. This diagnostic does not change the frozen planner or partition.
"""
from __future__ import annotations
import argparse
import hashlib
import itertools
import json
import math
from pathlib import Path
import re
import statistics

from .group_planner import _features, _similarity


def sha(data):
    return hashlib.sha256(data).hexdigest()


def predict(coefficients, features):
    return coefficients[0] + sum(c * x for c, x in zip(coefficients[1:], features))


def eigenvalues_symmetric(matrix):
    """Small symmetric Jacobi solver, used only for design conditioning."""
    a = [row[:] for row in matrix]
    n = len(a)
    for _ in range(100):
        pairs = [(i, j) for i in range(n) for j in range(i + 1, n)]
        if not pairs:
            break
        p, q = max(pairs, key=lambda ij: abs(a[ij[0]][ij[1]]))
        if abs(a[p][q]) < 1e-12:
            break
        angle = .5 * math.atan2(2 * a[p][q], a[q][q] - a[p][p])
        cosine, sine = math.cos(angle), math.sin(angle)
        app, aqq, apq = a[p][p], a[q][q], a[p][q]
        for k in range(n):
            if k in (p, q):
                continue
            akp, akq = a[k][p], a[k][q]
            a[k][p] = a[p][k] = cosine * akp - sine * akq
            a[k][q] = a[q][k] = sine * akp + cosine * akq
        a[p][p] = cosine * cosine * app - 2 * sine * cosine * apq + sine * sine * aqq
        a[q][q] = sine * sine * app + 2 * sine * cosine * apq + cosine * cosine * aqq
        a[p][q] = a[q][p] = 0.0
    return sorted(a[i][i] for i in range(n))


def solve(matrix, values):
    a = [row[:] + [v] for row, v in zip(matrix, values)]
    n = len(a)
    for column in range(n):
        pivot = max(range(column, n), key=lambda i: abs(a[i][column]))
        if abs(a[pivot][column]) < 1e-15:
            raise ValueError('singular_regularized_design')
        a[column], a[pivot] = a[pivot], a[column]
        divisor = a[column][column]
        a[column] = [v / divisor for v in a[column]]
        for row in range(n):
            if row == column:
                continue
            factor = a[row][column]
            a[row] = [x - factor * y for x, y in zip(a[row], a[column])]
    return [row[-1] for row in a]


def fit_linear(features, outcomes):
    n, columns = len(features), len(features[0])
    means = [statistics.mean(row[j] for row in features) for j in range(columns)]
    raw_scales = [math.sqrt(statistics.mean((row[j] - means[j]) ** 2 for row in features)) for j in range(columns)]
    scales = [value if value > 1e-12 else 1.0 for value in raw_scales]
    design = [[1.0] + [(row[j] - means[j]) / scales[j] for j in range(columns)] for row in features]
    gram = [[sum(row[i] * row[j] for row in design) for j in range(columns + 1)] for i in range(columns + 1)]
    eigenvalues = eigenvalues_symmetric(gram)
    maximum = max(eigenvalues)
    rank = sum(value > max(1e-12, maximum * 1e-10) for value in eigenvalues)
    condition = math.sqrt(maximum / min(eigenvalues)) if rank == columns + 1 else None
    regularized = [row[:] for row in gram]
    ridge = 1e-8
    for j in range(1, columns + 1):
        regularized[j][j] += ridge
    rhs = [sum(row[j] * y for row, y in zip(design, outcomes)) for j in range(columns + 1)]
    normalized = solve(regularized, rhs)
    slopes = [normalized[j + 1] / scales[j] for j in range(columns)]
    coefficients = [normalized[0] - sum(c * mean for c, mean in zip(slopes, means)), *slopes]
    return {'coefficients': coefficients, 'observations': n, 'parameters': columns + 1,
            'standardized_design_rank': rank, 'standardized_design_condition_number': condition,
            'standardized_gram_eigenvalues': eigenvalues, 'feature_means': means, 'feature_scales': raw_scales,
            'ridge_on_standardized_slopes': ridge, 'intercept_penalized': False,
            'identification_unstable': rank < columns + 1 or condition is None or condition > 1000}


def errors(actual, predicted):
    differences = [p - a for a, p in zip(actual, predicted)]
    return {'n': len(actual), 'bias_predicted_minus_actual': statistics.mean(differences),
            'mae': statistics.mean(abs(d) for d in differences),
            'rmse': math.sqrt(statistics.mean(d * d for d in differences)),
            'mean_absolute_percentage_error': 100 * statistics.mean(abs(d) / a for a, d in zip(actual, differences) if a != 0),
            'max_absolute_error': max(abs(d) for d in differences)}


def leave_one_out(features, outcomes):
    predictions, coefficients = [], []
    for omit in range(len(outcomes)):
        x = [row for i, row in enumerate(features) if i != omit]
        y = [value for i, value in enumerate(outcomes) if i != omit]
        fitted = fit_linear(x, y)
        coefficients.append(fitted['coefficients'])
        predictions.append(predict(fitted['coefficients'], features[omit]))
    return {'errors': errors(outcomes, predictions),
            'coefficient_ranges': [[min(row[j] for row in coefficients), max(row[j] for row in coefficients)]
                                   for j in range(len(coefficients[0]))],
            'scope': 'leave one source job out within one story; NOT held-out-story generalization'}


def source_observations(run_root, case_id):
    frozen_file = run_root / 'frozen_cases.json'
    frozen = json.loads(frozen_file.read_bytes())
    case = next(c for c in frozen if c['case_id'] == case_id)
    sources = {s['source_id']: s['text'] for s in case['sources']}
    identities = {sid: sha(text.encode('utf-8')) for sid, text in sources.items()}
    for source in case['sources']:
        if source.get('sha256') != identities[source['source_id']]:
            raise ValueError('frozen_source_hash_mismatch')
    rows, excluded = [], []
    source_file_hashes = {}
    for file in sorted((run_root / 'calls').glob('*.json')):
        with file.open('rb') as stream:
            header = stream.read(64)
        # Root role occurs before messages/result, so this never reads a target answer.
        if not re.match(rb'\{\s*"role"\s*:\s*"source"\s*,', header):
            continue
        raw = file.read_bytes()
        call = json.loads(raw)
        if call['role'] != 'source':
            raise ValueError('source_header_role_mismatch')
        messages = call['messages']
        payload = json.loads(messages[-1]['content'])
        group = payload['sources']
        if not group or len({s['source_id'] for s in group}) != len(group):
            raise ValueError('invalid_source_group')
        if any(identities.get(s['source_id']) != sha(s['text'].encode('utf-8')) for s in group):
            excluded.append({'call_file': file.name, 'reason': 'source_id_and_text_hash_not_selected_case'})
            continue
        receipt = call['result']['receipt']
        if receipt.get('status') != 'ok' or receipt.get('physical_request_count') != 1:
            excluded.append({'call_file': file.name, 'reason': 'not_a_verified_successful_source_request'})
            continue
        inputs, outputs = receipt['input_tokens'], receipt['output_tokens']
        if type(inputs) is not int or type(outputs) is not int or min(inputs, outputs) <= 0:
            raise ValueError('source_usage_invalid')
        features = [_features(s['text']) for s in group]
        pairs = list(itertools.combinations(features, 2))
        similarity = statistics.mean(_similarity(left, right) for left, right in pairs) if pairs else 0.0
        nbytes = sum(len(s['text'].encode('utf-8')) for s in group)
        proxy = sum(max(1.0, len(s['text'].encode('utf-8')) / 3.0) for s in group)
        rows.append({'call_file': file.name, 'source_ids': [s['source_id'] for s in group],
                     'source_text_sha256': {s['source_id']: identities[s['source_id']] for s in group},
                     'source_bytes': nbytes, 'source_count': len(group), 'mean_pair_jaccard': similarity,
                     'bytes_times_mean_jaccard': nbytes * similarity,
                     'input_tokens': inputs, 'output_tokens': outputs, 'max_tokens': call['max_tokens'],
                     'default_input_tokens': 100 + proxy,
                     'default_joint_output_tokens': 16 + proxy * .4 * (1 - .5 * similarity),
                     'default_risk_output_tokens': 16 + proxy * .4,
                     'actual_peak_source_cost_cny': (inputs * 2 + outputs * 8) / 1e6})
        source_file_hashes[file.name] = sha(raw)
    return rows, excluded, {'selected_case_id': case_id, 'frozen_cases_sha256': sha(frozen_file.read_bytes()),
                            'selected_source_identities': identities, 'admitted_source_call_hashes': source_file_hashes}


def diagnose(run_root, case_id):
    rows, excluded, provenance = source_observations(run_root, case_id)
    if len(rows) < 5:
        raise ValueError('at_least_five_verified_source_jobs_required')
    xin = [[row['source_bytes']] for row in rows]
    xout = [[row['source_bytes'], row['bytes_times_mean_jaccard']] for row in rows]
    yin, yout = [r['input_tokens'] for r in rows], [r['output_tokens'] for r in rows]
    input_fit, output_fit = fit_linear(xin, yin), fit_linear(xout, yout)
    for row, fi, fo in zip(rows, xin, xout):
        row['fitted_input_tokens'] = predict(input_fit['coefficients'], fi)
        row['fitted_output_tokens'] = predict(output_fit['coefficients'], fo)
        row['default_joint_peak_source_cost_cny'] = (row['default_input_tokens'] * 2 + row['default_joint_output_tokens'] * 8) / 1e6
        row['default_risk_peak_source_cost_cny'] = (row['default_input_tokens'] * 2 + row['default_risk_output_tokens'] * 8) / 1e6
    input_fit.update(formula='input_tokens = overhead + byte_rate * source_bytes',
                     overhead=input_fit['coefficients'][0], byte_rate=input_fit['coefficients'][1],
                     training_error=errors(yin, [r['fitted_input_tokens'] for r in rows]),
                     leave_one_job_out=leave_one_out(xin, yin))
    output_fit.update(formula='output_tokens = output_overhead + output_byte_rate * bytes - lexical_redundancy_rate * bytes * mean_pair_jaccard',
                      output_overhead=output_fit['coefficients'][0], output_byte_rate=output_fit['coefficients'][1],
                      lexical_redundancy_rate=-output_fit['coefficients'][2],
                      training_error=errors(yout, [r['fitted_output_tokens'] for r in rows]),
                      leave_one_job_out=leave_one_out(xout, yout))
    output_ranges = output_fit['leave_one_job_out']['coefficient_ranges']
    warnings = ['One story and repeated/overlapping source groups; jobs are not independent stories.',
                'This is a post-run source-length diagnostic, not algorithm advantage or task-quality evidence.',
                'Output limits and maximum_words were derived from source bytes, so output-length regression is policy-dependent.',
                'No target answers, evaluation files, permission schedules, future events, or target receipts were opened.']
    if output_fit['lexical_redundancy_rate'] < 0:
        warnings.append('Unconstrained fit gives negative lexical_redundancy_rate: observed direction opposes the planner assumed compression benefit.')
    if output_ranges[2][0] <= 0 <= output_ranges[2][1]:
        warnings.append('Lexical coefficient changes sign under leave-one-job-out; do not use it as a reliable semantic-discount estimate.')
    if input_fit['overhead'] < 0 or output_fit['output_overhead'] < 0 or input_fit['byte_rate'] < 0 or output_fit['output_byte_rate'] < 0:
        warnings.append('At least one fitted intercept/rate is negative; unconstrained diagnostic coefficients must not be adopted blindly.')
    near_cap = sum(r['output_tokens'] >= .95 * r['max_tokens'] for r in rows)
    delta = [r['default_risk_peak_source_cost_cny'] - r['default_joint_peak_source_cost_cny'] for r in rows]
    actual = [r['actual_peak_source_cost_cny'] for r in rows]
    default_joint_errors = errors(actual, [r['default_joint_peak_source_cost_cny'] for r in rows])
    default_risk_errors = errors(actual, [r['default_risk_peak_source_cost_cny'] for r in rows])
    recommendation = (
        'If a single candidate revision is pursued, freeze a source-only calibration stage on separate development stories '
        'before planning: calibrate the input overhead/byte rate and validate the output-length model there, '
        'keeping lexical discount zero unless its direction and magnitude are stable. Evaluate the revised candidate '
        'on fresh stories against unchanged strong baselines; retain this run unchanged. No partition/target tuning follows from this diagnostic.'
    )
    return {'schema': 'source-only-cost-calibration-diagnostic-v1', 'provenance': provenance,
            'scope': {'case_id': case_id, 'source_jobs': len(rows), 'independent_stories': 1,
                      'model_calls_added': 0, 'target_answer_files_opened': 0, 'future_event_files_opened': 0,
                      'source_only_exclusions': excluded},
            'default_planner': {'generation_input_overhead_tokens': 100, 'source_proxy_tokens_per_byte': 1 / 3,
                                'output_overhead_tokens': 16, 'output_ratio': .4, 'redundancy_weight': .5},
            'default_errors': {'input_tokens': errors(yin, [r['default_input_tokens'] for r in rows]),
                               'joint_output_tokens': errors(yout, [r['default_joint_output_tokens'] for r in rows]),
                               'risk_output_tokens': errors(yout, [r['default_risk_output_tokens'] for r in rows]),
                               'joint_peak_source_cost_cny': default_joint_errors, 'risk_peak_source_cost_cny': default_risk_errors},
            'input_fit': input_fit, 'output_fit': output_fit,
            'ranges': {'source_bytes': [min(r['source_bytes'] for r in rows), max(r['source_bytes'] for r in rows)],
                       'jaccard': [min(r['mean_pair_jaccard'] for r in rows), max(r['mean_pair_jaccard'] for r in rows)],
                       'near_output_cap_jobs': near_cap},
            'joint_vs_risk_cost_model_diagnostic': {
                'mean_default_joint_discount_cny_per_job': statistics.mean(delta),
                'max_default_joint_discount_cny_per_job': max(delta),
                'mean_discount_divided_by_joint_cost_mae': statistics.mean(delta) / default_joint_errors['mae'] if default_joint_errors['mae'] else None,
                'interpretation': 'Compare predicted joint-vs-risk discount with source-cost prediction error. A small discount relative to model error can make joint decisions insensitive or unreliable; this does not by itself prove why partitions match.'},
            'warnings': warnings, 'one_proposed_revision': recommendation, 'observations': rows}


def validate_frozen_fit(run_root, case_id, fit_file):
    """Evaluate the frozen case000 coefficients on another source-only story.

    No coefficients are fitted, selected, clipped to a desired direction, or
    tuned against this story. max(1, output) is the preregistered v2 model floor.
    """
    frozen = json.loads(Path(fit_file).read_bytes())
    if frozen['scope']['case_id'] == case_id:
        raise ValueError('external_source_case_must_differ_from_fit_case')
    rows, excluded, provenance = source_observations(run_root, case_id)
    if not rows:
        raise ValueError('no_external_verified_source_jobs')
    ci, co = frozen['input_fit']['coefficients'], frozen['output_fit']['coefficients']
    for row in rows:
        row['frozen_fit_input_tokens'] = predict(ci, [row['source_bytes']])
        row['frozen_fit_output_tokens'] = max(1.0, predict(co, [row['source_bytes'], row['bytes_times_mean_jaccard']]))
        row['frozen_fit_no_similarity_output_tokens'] = max(1.0, predict(co, [row['source_bytes'], 0]))
    inputs, outputs = [r['input_tokens'] for r in rows], [r['output_tokens'] for r in rows]
    return {'schema': 'frozen-source-token-model-external-diagnostic-v2',
            'training_case': frozen['scope']['case_id'], 'external_case': case_id,
            'source_jobs': len(rows), 'independent_external_stories': 1, 'model_calls_added': 0,
            'target_answer_files_opened': 0, 'evaluation_files_opened': 0, 'future_event_files_opened': 0,
            'fit_file': str(fit_file), 'fit_file_sha256': sha(Path(fit_file).read_bytes()),
            'fit_coefficients_unchanged': {'input': ci, 'output': co},
            'provenance': provenance, 'source_only_exclusions': excluded,
            'errors': {
                'default_input_tokens': errors(inputs, [r['default_input_tokens'] for r in rows]),
                'frozen_fit_input_tokens': errors(inputs, [r['frozen_fit_input_tokens'] for r in rows]),
                'default_joint_output_tokens': errors(outputs, [r['default_joint_output_tokens'] for r in rows]),
                'frozen_fit_output_tokens': errors(outputs, [r['frozen_fit_output_tokens'] for r in rows]),
                'frozen_fit_no_similarity_output_tokens': errors(outputs, [r['frozen_fit_no_similarity_output_tokens'] for r in rows])},
            'warnings': ['Only one external source story; overlapping jobs are not independent cases.',
                         'Prediction error is not task quality or algorithm advantage.',
                         'Coefficients are retained even if this external diagnostic is worse; no second tuning follows.'],
            'observations': rows}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('run_root', type=Path)
    parser.add_argument('--case-id', default='personamem-v1-000')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--frozen-fit', type=Path)
    args = parser.parse_args()
    if args.output.exists():
        raise SystemExit('Output already exists; preserve the previous diagnostic.')
    report = (validate_frozen_fit(args.run_root.absolute(), args.case_id, args.frozen_fit)
              if args.frozen_fit else diagnose(args.run_root.absolute(), args.case_id))
    with args.output.open('x', encoding='utf-8') as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2, allow_nan=False)
    if args.frozen_fit:
        print(json.dumps({'output': str(args.output.absolute()), 'source_jobs': report['source_jobs'],
                          'errors': report['errors'], 'model_calls_added': 0}, ensure_ascii=False))
        return
    print(json.dumps({'output': str(args.output.absolute()), 'source_jobs': report['scope']['source_jobs'],
                      'input_overhead_fit': report['input_fit']['overhead'], 'input_byte_rate_fit': report['input_fit']['byte_rate'],
                      'output_redundancy_fit': report['output_fit']['lexical_redundancy_rate'],
                      'input_condition': report['input_fit']['standardized_design_condition_number'],
                      'output_condition': report['output_fit']['standardized_design_condition_number'],
                      'default_input_mae': report['default_errors']['input_tokens']['mae'],
                      'default_joint_output_mae': report['default_errors']['joint_output_tokens']['mae'],
                      'joint_discount_to_error': report['joint_vs_risk_cost_model_diagnostic']['mean_discount_divided_by_joint_cost_mae'],
                      'model_calls_added': 0}, ensure_ascii=False))


if __name__ == '__main__':
    main()
