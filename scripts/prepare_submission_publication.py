"""Publish only the bounded synthetic recomputation artifact, never account homes.

This script copies a fixed manifest allowlist to a NEW benchmarks directory.
It neither changes the frozen bundle/results nor starts clients or model calls.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT/'results/submission_acceptance_20261030'
BUNDLE = SOURCE/'review_bundle_v1'
DEFAULT_OUT = ROOT/'benchmarks/submission_acceptance_20261030'
PUBLIC_RECEIPTS = {
    'review_bundle_v1_verification.json': SOURCE/'review_bundle_v1_verification.json',
    'delivery.json': SOURCE/'delivery.json',
    'native_receipt_audit.json': SOURCE/'native_run03/independent_receipt_audit.json',
}
SECRET = re.compile(rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|\bsk-[A-Za-z0-9_-]{24,}\b')
FORBIDDEN_PARTS = frozenset(('.git', '.runtime', '.aws', '.auth', '.dsh', '.ollama',
    'runtime', 'account_before.json', 'account_after.json', 'account_preflight.json',
    '.credentials.yaml', '.env'))


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read(path):
    return json.loads(Path(path).read_text(encoding='utf-8-sig'))


def save(path, value):
    with Path(path).open('x', encoding='utf-8', newline='\n') as stream:
        stream.write(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False)+'\n')


def safe_relative(value):
    if (not isinstance(value, str) or not value or chr(92) in value or ':' in value
            or value.startswith('/') or any(x in {'', '.', '..'} for x in value.split('/'))):
        raise ValueError('unsafe_relative_path')
    path = PurePosixPath(value)
    if any(part in FORBIDDEN_PARTS or part.startswith('.env.') for part in path.parts):
        raise ValueError('forbidden_publication_path')
    return path


def checked(path, base):
    path, base = Path(path).absolute(), Path(base).resolve(strict=True)
    if not path.resolve(strict=True).is_relative_to(base):
        raise ValueError('source_escapes_allowed_root')
    for item in (path, *path.parents):
        value = item.lstat()
        if stat.S_ISLNK(value.st_mode) or getattr(value, 'st_file_attributes', 0) & getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 1024):
            raise ValueError('linked_source_not_allowed')
        if item == base:
            break
    if not path.is_file():
        raise ValueError('source_is_not_file')
    return path


def inspect_bytes(path):
    raw = checked(path, ROOT).read_bytes()
    if SECRET.search(raw):
        raise ValueError('possible_secret_in_selected_publication_file:'+path.relative_to(ROOT).as_posix())
    return raw


def fixed_publication_inputs():
    manifest_path = checked(BUNDLE/'manifest.json', ROOT)
    manifest = read(manifest_path)
    if manifest.get('schema') != 'submission_recompute_bundle_v1' or not isinstance(manifest.get('files'), dict):
        raise ValueError('invalid_bundle_manifest')
    selected = {}
    for relative, expected in manifest['files'].items():
        path = BUNDLE.joinpath(*safe_relative(relative).parts)
        checked(path, BUNDLE)
        if sha(path) != expected:
            raise ValueError('frozen_bundle_hash_mismatch:'+relative)
        selected['review_bundle_v1/'+relative] = path
    # Do not allow an extra Python module, account file or unnoticed cache into
    # the sealed artifact through a recursive copy operation.
    inventory = set()
    for path in BUNDLE.rglob('*'):
        value = path.lstat()
        if stat.S_ISLNK(value.st_mode) or getattr(value, 'st_file_attributes', 0) & getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 1024):
            raise ValueError('linked_bundle_entry')
        if path.is_file():
            inventory.add(path.relative_to(BUNDLE).as_posix())
    if inventory != set(manifest['files']) | {'manifest.json'}:
        raise ValueError('bundle_has_unregistered_or_missing_files')
    selected['review_bundle_v1/manifest.json'] = manifest_path
    selected.update(PUBLIC_RECEIPTS)
    for path in selected.values():
        inspect_bytes(path)
    verification = read(PUBLIC_RECEIPTS['review_bundle_v1_verification.json'])
    if (verification.get('passed') is not True or verification.get('manifest_sha256') != sha(manifest_path)
            or verification.get('formal_independent_third_party_acceptance') is not False):
        raise ValueError('independent_bundle_verification_missing_or_changed')
    delivery = read(PUBLIC_RECEIPTS['delivery.json'])
    if delivery.get('bundle_manifest_sha256') != sha(manifest_path):
        raise ValueError('delivery_bundle_digest_mismatch')
    audit = read(PUBLIC_RECEIPTS['native_receipt_audit.json'])
    if (audit.get('actual_calls') != 8 or audit.get('linked_replays') != 16
            or audit.get('independent_stories') != 2 or audit.get('failures')):
        raise ValueError('native_audit_inventory_not_qualified')
    return selected, manifest


def failure_summary(name):
    run = SOURCE/name
    closure = read(checked(run/'prediction_phase_closed.json', ROOT))
    predictions_path = checked(run/'predictions.json', ROOT)
    if sha(predictions_path) != closure.get('predictions_sha256'):
        raise ValueError('failed_batch_closed_predictions_changed')
    rows = read(predictions_path)['rows']
    receipts = []
    stream_counts = []
    for path in sorted(run.glob('*_receipt.json')):
        value = read(checked(path, ROOT))
        error = value.get('error')
        if error is not None and (not isinstance(error, str) or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,160}', error)):
            raise ValueError('unexpected_noncode_failure_error')
        counts = value.get('guard_counts')
        counts = counts if isinstance(counts, dict) else {}
        allowed = counts.get('allowed_stream_count')
        if type(allowed) is not int:
            allowed = 0 if value.get('invocation_started') is False else None
        stream_counts.append(allowed)
        receipts.append({'receipt_name': path.name, 'original_sha256': sha(path),
            'status': value.get('status'), 'error': error,
            'invocation_started': value.get('invocation_started'),
            'native_instruction_loaded': value.get('native_instruction_loaded'),
            'allowed_model_streams': allowed,
            'guard_reject_code': counts.get('reject_code')})
    if not receipts or any(x is None for x in stream_counts) or sum(stream_counts) != 0:
        raise ValueError('failed_batch_zero_model_streams_not_evidenced')
    return {'schema':'submission_public_failure_summary_v1', 'run_label':name,
        'source_closure_sha256':sha(run/'prediction_phase_closed.json'),
        'source_predictions_sha256':sha(predictions_path),
        'planned_prediction_rows':len(rows), 'wrapper_attempts':closure.get('client_attempts'),
        'allowed_model_streams':sum(stream_counts),
        'observable_raw_answer_rows':sum(isinstance(r.get('raw_answer'), str) and bool(r['raw_answer']) for r in rows),
        'client_status_counts':dict(Counter(r.get('client_status') for r in rows)),
        'processing_status_counts':dict(Counter(r.get('processing_status') for r in rows)),
        'receipts':receipts, 'used_in_success_or_privacy_denominators':False,
        'formal_external_acceptance':False, 'supplier_bill_verified':False,
        'scope':'Preflight/guard failure, no allowed model stream. Missing responses are not successful safe answers. Original failed evidence remains local; no account snapshot or runtime was copied.'}


README = '''# Agent 记忆迁移：联合验收与可复核材料

本目录公开固定代码、AI 辅助自编合成数据、冻结配置及必要响应，供复核有限授权合同下的主要计算结果。
它不含本机账户快照、凭证、原生客户端安装目录、运行 home 或恢复映射。

## 一条命令复算

从仓库根目录运行，Python 3.12，标准库即可；不需要 pip、API Key 或模型服务：

```text
python -I -B -S benchmarks/submission_acceptance_20261030/review_bundle_v1/run.reproduce.py
```

脚本校验149个清单内文件后，在临时目录重算两份摘要；不覆盖封存原件，不调用模型。
如需保存输出，`--out` 必须指向包目录之外且尚不存在的文件。物理字节与规范化JSON的比较分别报告。
包的原始清单见 [manifest.json](review_bundle_v1/manifest.json)，运行边界见[包内说明](review_bundle_v1/README.md)。

## 本批结果应怎样读

| 材料 | 规模与证据 | 结论范围 |
|---|---|---|
| 离线联合链 | 9个合成故事、108行记录、6个条件汇总 | 确定性字段消费者，不能当作大模型回答正确率 |
| 原生Harness | 2个合成故事；8次实际模型调用、16行同输入关联重放，共24行方法记录 | 实际调用的4道合法题均正确，无UNKNOWN；2道权限排除题、2道缺失题均UNKNOWN |
| 内部工程核验 | 包内53项定向测试通过；两份摘要全部JSON及原字节复算一致 | 代理内部复核，不是未参与实现的外部人员验收 |

16行关联重放共享8次实际调用结果，不能当作新增模型调用或独立样本。方法条件在这批材料中给出等价安全输入，结果不能用于声称新算法超过完整强基线。
本批没有新增Qoder发送端模型调用；发送侧是受控合成来源和可信主机处理。真实Harness加载有原生事件证据，不能推广为所有异构Agent原生执行同一ACL协议。

这是受控EMAIL格式规则、精确字段与可信主机授权合同的资格验证，不覆盖一般语义敏感检测、任意摘要、恶意主机、所有权限系统或在线遗忘。
2个故事不是代表性总体；无观察到的登记精确原值披露不等于全面隐私安全。外部人员验收与新算法优势均未完成。

## 可复核证据

- [包内复算核验](review_bundle_v1_verification.json)
- [原生收据独立代理审计](native_receipt_audit.json)
- [本阶段交付声明](delivery.json)
- [失败批次安全摘要](failed_native_batches.json)：native_run01为模板/门禁接口错误，native_run02被请求长度门禁拦截；两批允许模型流均为0，失败原件在本机保留，没有计入成功/安全观测分母。
- [公开文件清单](publication_manifest.json)：包括原封存来源SHA-256及复制后SHA-256。

费用只可按记录的账户差额解释，供应商账单没有独立核验，不能由观测差额0推断所有调用免费。
历史实验不与本批合并成总体成功率。GitHub代码仓库不是永久学术存档或外部制品评价认证。

## 包内工程测试

在包目录执行；这与全仓库的CI回归是不同入口：

```text
cd benchmarks/submission_acceptance_20261030/review_bundle_v1
python -B -S -m unittest discover -s tests -p "test_submission*.py"
```

冻结包必须保留原始字节。仓库应使用 `.gitattributes` 的本目录 `-text` 规则，防止自动换行转换破坏哈希。
若文件被修改，先保留原件并形成新版本，不能编辑旧清单把失败变为通过。
'''


def prepare(out, *, dry_run=False):
    out = Path(out).absolute()
    if out.exists():
        raise ValueError('publication_output_must_be_new')
    if out.parent.resolve(strict=True) != (ROOT/'benchmarks').resolve(strict=True):
        raise ValueError('publication_must_be_a_new_direct_child_of_benchmarks')
    safe_relative(out.name)
    selected, manifest = fixed_publication_inputs()
    failures = [failure_summary(name) for name in ('native_run01', 'native_run02')]
    original_hashes = {str(p.relative_to(ROOT).as_posix()): sha(p) for p in selected.values()}
    if dry_run:
        return {'status':'qualified_dry_run', 'copied_files_planned':len(selected),
            'bundle_manifest_sha256':sha(BUNDLE/'manifest.json'), 'model_calls':0,
            'destinations':sorted(selected), 'failure_batches':failures}
    out.mkdir()
    for relative, source in selected.items():
        destination = out.joinpath(*safe_relative(relative).parts)
        destination.parent.mkdir(parents=True, exist_ok=True)
        raw = inspect_bytes(source)
        with destination.open('xb') as stream:
            stream.write(raw)
        if sha(destination) != sha(source):
            raise ValueError('publication_copy_hash_mismatch')
    save(out/'failed_native_batches.json', {'schema':'submission_public_failure_batches_v1', 'batches':failures})
    with (out/'README.md').open('x', encoding='utf-8', newline='\n') as stream:
        stream.write(README)
    files = {p.relative_to(out).as_posix():sha(p) for p in sorted(out.rglob('*')) if p.is_file()}
    if any(sha(ROOT/relative) != expected for relative,expected in original_hashes.items()):
        raise ValueError('original_changed_during_publication')
    publication = {'schema':'submission_publication_manifest_v1',
        'created_at_utc':datetime.now(timezone.utc).isoformat(),
        'source_bundle_manifest_sha256':sha(BUNDLE/'manifest.json'),
        'bundle_preserved_file_count':len(manifest['files'])+1,
        'copied_source_files':{relative:{'source_sha256':sha(source),'published_sha256':sha(out/relative)}
                               for relative,source in selected.items()},
        'model_calls':0,'network_calls':0,'client_calls':0,
        'original_files_changed':[], 'formal_external_person_acceptance':False,
        'source_account_snapshots_or_runtime_copied':False, 'files':files}
    save(out/'publication_manifest.json', publication)
    return {'status':'publication_prepared', 'directory':str(out),
        'files':len(files)+1, 'bundle_preserved_files':len(manifest['files'])+1,
        'bundle_manifest_sha256':sha(out/'review_bundle_v1/manifest.json'),
        'publication_manifest_sha256':sha(out/'publication_manifest.json'),
        'source_changes':0, 'model_calls':0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, default=DEFAULT_OUT)
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args()
    print(json.dumps(prepare(args.out, dry_run=args.dry_run),ensure_ascii=False,sort_keys=True,indent=2))


if __name__ == '__main__':
    main()
