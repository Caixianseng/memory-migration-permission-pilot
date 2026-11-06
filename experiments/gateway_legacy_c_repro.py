"""One bounded reproduction using the unchanged historical C implementation.

All writes go to a NEW directory. No old experiment or evaluation is rerun.
The old module supplies its original fixture, crash boundary and retry path.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
from datetime import datetime, timezone


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--historical-root', required=True)
    parser.add_argument('--out', required=True)
    args = parser.parse_args()
    old = Path(args.historical_root).resolve()
    target = Path(args.out).resolve()
    if target.exists():
        raise SystemExit('fresh output directory required; no implicit retries')
    target.mkdir(parents=True)
    source = old / 'experiments/core_delivery_followup_20261106/run_mixed_lifecycle.py'
    before = hashlib.sha256(source.read_bytes()).hexdigest()
    spec = importlib.util.spec_from_file_location('historical_followup', source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.fixture(target)
    method = 'source_dynamic_version_no_tx'
    pre = module.disk_state(target, method)
    command = [sys.executable, '-B', '-X', 'utf8', str(source), '--worker',
               str(target), method, 'after_first_effect_before_ack']
    start = datetime.now(timezone.utc).isoformat()
    child = subprocess.run(command, cwd=old, capture_output=True, text=True, timeout=30)
    post_crash = module.disk_state(target, method)
    packet = json.loads((target / 'old_done_packet.json').read_text(encoding='utf-8'))
    module.update_authority(target, 'source_v2_then_revoke_regrant')
    retry = module.invoke(target, packet, method)
    post_retry = module.disk_state(target, method)
    result = {
        'fresh_reproduction_number': 1, 'started_at': start,
        'finished_at': datetime.now(timezone.utc).isoformat(),
        'unchanged_source_sha256': before,
        'source_unchanged': hashlib.sha256(source.read_bytes()).hexdigest() == before,
        'child_exit': child.returncode, 'stdout': child.stdout, 'stderr': child.stderr,
        'before': pre, 'after_crash': post_crash, 'retry': retry, 'after_retry': post_retry,
        'reproduced': child.returncode == 91 and post_crash['effect_count'] == 1
           and len(post_crash['committed_effects_without_matching_consumed_seal']) == 1
           and not retry['accepted'] and retry.get('reason') == 'stale_policy_epoch',
        'interpretation': 'A committed legacy effect has no matching consumed seal and cannot be metadata-confirmed after epoch changes. This is not evidence of a new unauthorized first delivery.'}
    (target / 'result.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({k:result[k] for k in ('reproduced', 'child_exit', 'source_unchanged')}))
    return 0 if result['reproduced'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
