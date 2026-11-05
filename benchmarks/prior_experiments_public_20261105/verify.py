"""Check integrity and scope of the public aggregate projection, offline."""
from pathlib import Path
import hashlib
import json
import re

HERE = Path(__file__).resolve().parent


def verify():
    manifest = json.loads((HERE/'manifest.json').read_bytes())
    assert manifest['export_type'] == 'aggregate_projection_only'
    assert manifest['model_calls_by_exporter'] == 0
    assert manifest['independent_native_reaudit_possible_from_this_bundle_alone'] is False
    for name, expected in manifest['files'].items():
        assert Path(name).name == name and name.endswith('.json')
        raw = (HERE/name).read_bytes()
        assert len(raw) == expected['bytes']
        assert hashlib.sha256(raw).hexdigest() == expected['sha256']
        value = json.loads(raw)
        assert value['actual_supplier_bill_cny'] is None
        assert value['model_calls_by_exporter'] == 0
        assert value['raw_answers_original_data_native_logs_and_local_paths_included'] is False
        assert not re.search(r'[A-Za-z]:[\\/]|Bearer\s+[A-Za-z0-9_-]{15,}|\b(?:sk|ghp|github_pat)[-_][A-Za-z0-9_-]{16,}', raw.decode('utf-8'))
    assert len(manifest['files']) == 7
    print(json.dumps({'aggregate_integrity': 'passed', 'files': 7,
                      'model_calls': 0, 'native_execution_reverified': False}))


if __name__ == '__main__':
    verify()
