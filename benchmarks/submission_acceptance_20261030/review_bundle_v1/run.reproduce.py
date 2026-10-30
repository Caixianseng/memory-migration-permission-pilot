"""Verify every packaged file before offline rescoring in temporary copies."""
from contextlib import ExitStack
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import stat
import sys
import tempfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent


def load(path):
    return json.loads(path.read_text(encoding='utf-8-sig'))


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')


def checked_path(relative):
    if (not isinstance(relative, str) or not relative or chr(92) in relative or ':' in relative
            or relative.startswith('/') or any(part in {'', '.', '..'} for part in relative.split('/'))):
        raise ValueError('unsafe_manifest_path')
    pure = PurePosixPath(relative)
    path = ROOT.joinpath(*pure.parts)
    if not path.resolve(strict=True).is_relative_to(ROOT):
        raise ValueError('manifest_path_escapes_bundle')
    for item in (path, *path.parents):
        attributes = item.lstat()
        if stat.S_ISLNK(attributes.st_mode) or getattr(attributes, 'st_file_attributes', 0) & getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 1024):
            raise ValueError('linked_bundle_path')
        if item == ROOT:
            break
    if not path.is_file():
        raise ValueError('manifest_target_not_file')
    return path


def verify():
    manifest = load(checked_path('manifest.json'))
    if manifest.get('schema') != 'submission_recompute_bundle_v1' or not isinstance(manifest.get('files'), dict):
        raise ValueError('invalid_manifest_schema')
    required = {'run.reproduce.py', 'README.md', 'requirements-reproduce.txt', 'runtime.json',
                'experiments/submission_acceptance_20261030/score.py'}
    if not required <= set(manifest['files']):
        raise ValueError('required_bundle_file_not_registered')
    for relative, expected in manifest['files'].items():
        if not isinstance(expected, str) or len(expected) != 64 or any(c not in '0123456789abcdef' for c in expected):
            raise ValueError('invalid_file_digest')
        if sha(checked_path(relative)) != expected:
            raise ValueError('bundle_file_hash_mismatch:'+relative)
    # Reject unregistered import modules as well as unexpected private files.
    actual = set()
    for path in ROOT.rglob('*'):
        attributes = path.lstat()
        if stat.S_ISLNK(attributes.st_mode) or getattr(attributes, 'st_file_attributes', 0) & getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 1024):
            raise ValueError('linked_unregistered_bundle_path')
        if path.is_file():
            actual.add(path.relative_to(ROOT).as_posix())
    if actual != set(manifest['files']) | {'manifest.json'}:
        raise ValueError('unregistered_or_missing_bundle_file')
    return manifest


def blocked(*args, **kwargs):
    raise RuntimeError('offline_recompute_forbids_network_and_child_processes')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, help='Optional NEW verification JSON outside the sealed bundle')
    args = parser.parse_args()
    manifest = verify()
    if args.out is not None:
        destination = args.out.resolve()
        if destination.is_relative_to(ROOT) or destination.exists():
            raise ValueError('verification_output_must_be_new_and_outside_bundle')
    # The bundle is the only project import root. -S avoids third-party packages;
    # -B avoids generating unregistered caches inside the sealed source tree.
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(ROOT))
    outcomes = []
    with ExitStack() as stack, tempfile.TemporaryDirectory(prefix='memory-recompute-') as temporary:
        stack.enter_context(patch('socket.create_connection', side_effect=blocked))
        stack.enter_context(patch('socket.getaddrinfo', side_effect=blocked))
        stack.enter_context(patch('socket.socket.connect', side_effect=blocked))
        stack.enter_context(patch('socket.socket.connect_ex', side_effect=blocked))
        stack.enter_context(patch('subprocess.Popen', side_effect=blocked))
        from experiments.submission_acceptance_20261030.score import score_run
        for entry in manifest['runs']:
            relative = entry['directory']
            if (not isinstance(relative, str) or not relative.startswith('runs/') or len(relative.split('/')) != 2
                    or not isinstance(entry.get('id'), str) or entry['id'] != relative.split('/')[1]
                    or not entry['id'].isascii() or not entry['id'].isalnum()):
                raise ValueError('unsafe_run_directory')
            source = checked_path(relative+'/predictions.json').parent
            destination = Path(temporary)/entry['id']
            destination.mkdir()
            for filename in ('plan.json', 'predictions.json', 'authorization_matrix.json', 'prediction_phase_closed.json'):
                shutil.copy2(checked_path(relative+'/'+filename), destination/filename)
            expected_path = checked_path(relative+'/summary.json')
            expected = load(expected_path)
            actual = score_run(destination)
            equal = canonical(actual) == canonical(expected)
            outcomes.append({'id': entry['id'], 'summary_json_equal': actual == expected,
                'summary_canonical_bytes_equal': equal,
                'summary_file_bytes_equal': (destination/'summary.json').read_bytes() == expected_path.read_bytes(),
                'expected_summary_sha256': sha(expected_path), 'recomputed_summary_sha256': sha(destination/'summary.json'),
                'planned_rows': actual['planned_rows'], 'stories_seen': actual['stories_seen'],
                'groups': len(actual['groups'])})
            if not equal:
                raise ValueError('recomputed_summary_differs:'+entry['id'])
    result = {'schema': 'submission_bundle_verification_v1', 'passed': True,
        'manifest_sha256': sha(ROOT/'manifest.json'), 'verified_files': len(manifest['files']),
        'runs': outcomes, 'model_calls': 0, 'network_calls': 0, 'client_calls': 0,
        'formal_independent_third_party_acceptance': False,
        'scope': 'Offline arithmetic rerun of recorded synthetic responses; no live migration, client, semantic privacy or general security proof.'}
    # Verify the package again after scoring. Scoring writes only to temporary files.
    verify()
    text = json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False)+'\n'
    if args.out is not None:
        with args.out.open('x', encoding='utf-8', newline='\n') as stream:
            stream.write(text)
    print(text, end='')


if __name__ == '__main__':
    main()
