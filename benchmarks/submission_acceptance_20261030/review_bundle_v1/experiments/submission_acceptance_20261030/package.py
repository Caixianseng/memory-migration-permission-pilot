"""Build a source-and-synthetic-evidence bundle for offline result recomputation.

Explicit allowlists only. Native homes, credentials, account snapshots and the
historical native-probe tree are never copied. This builder never runs a model.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import stat
import subprocess

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
REQUIRED_RUN_FILES = ('plan.json', 'predictions.json', 'authorization_matrix.json',
                      'prediction_phase_closed.json', 'summary.json')
OPTIONAL_RUN_FILES = ('challenges.json',)
TEST_FILES = ('test_submission_reference.py', 'test_submission_pipeline.py', 'test_submission_score.py')
SECRET_PATTERN = re.compile(rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|\bsk-[A-Za-z0-9_-]{24,}\b')
ACCOUNT_KEYS = frozenset(('client_attempts', 'observed_wallet_delta_cny', 'limit_cny',
    'supplier_atomic_cap', 'supplier_bill_verified', 'no_top_up', 'stopped_reason',
    'new_model_calls', 'estimated_cost_cny', 'observed_spend_cny'))
RECEIPT_KEYS = frozenset(('status', 'answer', 'raw_response', 'usage', 'model', 'version',
    'wrapper_version', 'error', 'invocation_started', 'native_instruction_loaded',
    'native_instruction_baselines', 'guard_counts', 'guard_bytes_scope', 'physical_model_requests',
    'credentials_source_unchanged', 'temporary_credentials_removed', 'exit_code',
    'agent_memory_file_sha256', 'guard_sha256', 'patch_template_sha256', 'cli_entry_sha256',
    'runtime_archive_sha256', 'argv_sha256', 'stderr_bytes', 'failure_rpc_method',
    'rpc_error_code', 'safe_stderr_codes', 'stdout_catalog_diagnostics', 'guard_evidence_error',
    'last_terminal_reason'))


def _sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _load(path):
    return json.loads(Path(path).read_text(encoding='utf-8-sig'))


def _save(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, sort_keys=True,
        indent=2, allow_nan=False)+'\n', encoding='utf-8', newline='\n')


def _regular(path, base):
    path, base = Path(path).absolute(), Path(base).resolve(strict=True)
    if not path.resolve(strict=True).is_relative_to(base):
        raise ValueError('input_path_outside_allowed_root')
    for item in (path, *path.parents):
        attrs = item.lstat()
        if stat.S_ISLNK(attrs.st_mode) or getattr(attrs, 'st_file_attributes', 0) & getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 1024):
            raise ValueError('linked_input_not_allowed')
        if item == base:
            break
    if not path.is_file():
        raise ValueError('input_not_regular_file')
    return path


def _copy_file(source, destination):
    source = _regular(source, ROOT)
    raw = source.read_bytes()
    if SECRET_PATTERN.search(raw):
        raise ValueError('possible_secret_in_allowlisted_file:'+source.relative_to(ROOT).as_posix())
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open('xb') as output:
        output.write(raw)


def _numeric_or_code(value):
    if value is None or type(value) is bool or type(value) is int:
        return True
    if type(value) is float:
        return math.isfinite(value)
    return isinstance(value, str) and len(value) <= 128 and bool(re.fullmatch(r'[A-Za-z0-9_.:+-]+', value))


REPRODUCE_SCRIPT = r'''"""Verify every packaged file before offline rescoring in temporary copies."""
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
'''


README = '''# 联合验收的离线复核包

本包包含固定源码、AI 辅助自编合成材料、选定运行的封存预测与评分输入。
默认只复核已记录响应，不启动 Qoder、Harness、本地检测模型或其他在线服务。

## 运行

在新解包目录中执行（不需要 pip，不需要账户凭证）：

```text
python -B -S run.reproduce.py
```

如需保存结果，输出文件必须不存在，且在制品包目录之外：

```text
python -B -S run.reproduce.py --out ../verification-new.json
```

实际运行使用的 Python 精确版本记在 runtime.json 中；建议使用相同版本。
重算路径仅使用标准库。源码包包括用于解释主机流程的既有模块，但不包含本地
客户端可执行文件、历史 native probe、运行 home、账户快照、凭证或恢复映射。
因此它不是可直接重新运行在线客户端的完整环境。模型服务的输出也不保证逐字复现。

## 核验与范围

run.reproduce.py 先检查 POSIX 相对路径、禁止链接/越根、逐文件 SHA-256 与额外文件，
再在临时目录重算全部选定运行的摘要。摘要按完整 JSON 及规范化 UTF-8 字节比较；
另报告物理文件字节是否相同（跨平台换行差异不构成数值差异）。封存原件不被覆盖。
评分期间常用 Python 网络连接 API 与子进程入口被禁止。该保护不是操作系统沙箱。

SHA-256 支持内容一致性，不证明清单真实性；可信分发时另行核对发布者给出的
manifest.json 摘要。修改代码、原始响应或真值后，不得沿用原有验收结论。

本包的 run.reproduce.py 是对已封存响应的算术重算，不能再次验证已销毁随机密钥下
当时的授权，也不能证明真实客户端主动遵守任意 ACL 或遗忘已读明文。
有限合成场景、EMAIL 格式规则和可信主机合同之外的语义隐私、安全与自然分布效果均未证明。
工程结果不表示新算法已经优于完整强基线。

该包经过代理自查也不能填写为正式外部人员验收。应由未参与实现的人在新环境按
说明执行，记录环境、差异和反馈。本包不会自动推送 GitHub、提交代码或公开账户数据。

## 文件来源和版本

manifest.json 记录打包时 git_base、每个复制文件的 SHA-256、选定运行与转换记录。
git_base 是当时的基线提交，不代表该提交已包含所有打包源码；working_tree_source_hashes
才记录实际随包交付的源码。运行计划里的哈希必须与复制源码一致，已声明但未提供的
native guard 等在线依赖另列，不冒充完整可重跑在线环境。

accounting.json（若有）仅含明确白名单的安全总计，不含账户明细。
*_receipt.json（若有）是保留状态、合成回答、用量计数和加载证据的字段投影；
本地路径等其他字段不复制，原文件 SHA-256 与所保留字段记在转换记录中。
每题 *_result.json 和 AGENTS.md 没有重复复制，必要的保护视图和回答已在 predictions.json 中。
'''


def build(runs, out):
    out = Path(out).absolute()
    # The user authorizes a new local package, never merging with existing trees.
    if out.exists():
        raise ValueError('bundle_output_must_be_new')
    if not out.parent.is_dir():
        raise ValueError('bundle_parent_must_exist')
    resolved_out = out.parent.resolve(strict=True)/out.name
    if not resolved_out.is_relative_to(ROOT):
        raise ValueError('bundle_output_must_stay_in_workspace')
    run_paths = [Path(run).resolve(strict=True) for run in runs]
    if not run_paths or len(set(run_paths)) != len(run_paths):
        raise ValueError('duplicate_run_directory')
    for run in run_paths:
        if not run.is_relative_to(ROOT/'results') or not run.is_dir():
            raise ValueError('run_must_be_workspace_results_directory')
        for filename in REQUIRED_RUN_FILES:
            _regular(run/filename, ROOT)
        plan = _load(run/'plan.json')
        if plan.get('schema') != 'submission_joint_acceptance_v1':
            raise ValueError('unsupported_run_schema')
        if _load(run/'prediction_phase_closed.json').get('all_slots_closed') is not True:
            raise ValueError('run_prediction_phase_not_closed')

    material = _load(HERE/'data/manifest.json')
    if material.get('schema') != 'submission_joint_data_manifest_v1' or material.get('frozen_material') is not True:
        raise ValueError('synthetic_material_manifest_missing_or_unfrozen')
    files = list(HERE.rglob('*.py')) + list((HERE/'data').glob('*.json')) + [HERE/'CONTRACT.md']
    files += list((ROOT/'experiments/journal_methods_20261030').glob('*.py'))
    files += list((ROOT/'memory_migration_study').glob('*.py'))
    files += [ROOT/'tests'/name for name in TEST_FILES]
    files = sorted(set(files))
    if any('__pycache__' in p.parts for p in files):
        raise ValueError('cache_was_selected_for_copy')
    code_hashes = {p.relative_to(ROOT).as_posix(): _sha(_regular(p, ROOT)) for p in files}
    # Freeze must refer to exactly the code that is handed to a reviewer.
    omitted = []
    for ordinal, run in enumerate(run_paths, 1):
        hashes = _load(run/'plan.json').get('implementation_sha256')
        if not isinstance(hashes, dict) or not hashes:
            raise ValueError('run_source_hashes_missing')
        for relative, expected in hashes.items():
            normalized = relative.replace(chr(92), '/')
            if normalized in code_hashes:
                if code_hashes[normalized] != expected:
                    raise ValueError('run_code_changed_since_freeze:'+normalized)
            else:
                omitted.append({'run': f'run{ordinal:02d}', 'relative_path': normalized,
                                'sha256': expected, 'reason': 'outside_offline_allowlist'})
    git_base = subprocess.run(['git','-c','safe.directory='+ROOT.as_posix(),'rev-parse','HEAD'],
        cwd=ROOT, capture_output=True, text=True, check=True, timeout=15).stdout.strip()
    out.mkdir()
    for source in files:
        _copy_file(source, out/source.relative_to(ROOT))
    transformed, entries = [], []
    for ordinal, run in enumerate(run_paths, 1):
        run_id = f'run{ordinal:02d}'
        destination = out/'runs'/run_id
        destination.mkdir(parents=True)
        for filename in REQUIRED_RUN_FILES + OPTIONAL_RUN_FILES:
            if (run/filename).exists():
                _copy_file(run/filename, destination/filename)
        for source in sorted(run.glob('*_receipt.json')):
            _regular(source, ROOT)
            value = _load(source)
            if not isinstance(value, dict):
                raise ValueError('invalid_receipt_object')
            safe = {key: value[key] for key in sorted(RECEIPT_KEYS & set(value))}
            text = json.dumps(safe, ensure_ascii=False, allow_nan=False).encode('utf-8')
            if SECRET_PATTERN.search(text):
                raise ValueError('possible_secret_in_projected_receipt')
            _save(destination/source.name, safe)
            transformed.append({'destination': (destination/source.name).relative_to(out).as_posix(),
                'original_sha256': _sha(source), 'transformation': 'explicit_receipt_field_projection',
                'retained_fields': sorted(safe)})
        accounting = run/'accounting.json'
        if accounting.exists():
            value = _load(_regular(accounting, ROOT))
            if not isinstance(value, dict):
                raise ValueError('invalid_accounting_object')
            safe = {key: value[key] for key in sorted(ACCOUNT_KEYS & set(value)) if _numeric_or_code(value[key])}
            safe['publication_projection'] = 'explicit_safe_totals_only_not_account_details'
            _save(destination/'accounting.json', safe)
            transformed.append({'destination': f'runs/{run_id}/accounting.json',
                'original_sha256': _sha(accounting), 'transformation': 'explicit_safe_total_field_projection',
                'retained_fields': sorted(safe)})
        entries.append({'id': run_id, 'directory': f'runs/{run_id}',
                        'source_summary_sha256': _sha(run/'summary.json'),
                        'client': _load(run/'plan.json').get('client')})
    (out/'run.reproduce.py').write_text(REPRODUCE_SCRIPT, encoding='utf-8', newline='\n')
    (out/'README.md').write_text(README, encoding='utf-8', newline='\n')
    (out/'requirements-reproduce.txt').write_text(
        '# Offline recomputation uses Python standard library only.\n# No pip packages required; exact tested interpreter is in runtime.json.\n', encoding='utf-8', newline='\n')
    _save(out/'runtime.json', {'python_implementation': platform.python_implementation(),
        'python_version': platform.python_version(), 'dependencies': [],
        'recompute_command': 'python -B -S run.reproduce.py',
        'native_client_dependencies_included': False})
    manifest = {'schema': 'submission_recompute_bundle_v1',
        'created_at_utc': datetime.now(timezone.utc).isoformat(), 'git_base': git_base,
        'git_base_contains_all_packaged_sources': False,
        'working_tree_source_hashes': code_hashes,
        'runs': entries, 'transformed_files': transformed,
        'declared_execution_dependencies_not_packaged': omitted,
        'formal_independent_third_party_acceptance': False,
        'scope': 'Closed synthetic response recomputation, not online execution or general security proof',
        'files': {p.relative_to(out).as_posix(): _sha(p) for p in sorted(out.rglob('*')) if p.is_file()}}
    _save(out/'manifest.json', manifest)
    return {'bundle': str(out), 'files': len(manifest['files']), 'runs': len(entries),
            'manifest_sha256': _sha(out/'manifest.json'), 'model_calls': 0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runs', type=Path, nargs='+', required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(build(args.runs, args.out), ensure_ascii=False))


if __name__ == '__main__':
    main()
