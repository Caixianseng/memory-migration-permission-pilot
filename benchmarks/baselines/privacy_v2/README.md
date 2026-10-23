# Frozen privacy v2.2 research baseline

This directory contains the 24 Python source files used as the historical
baseline for the v3 local privacy comparison. Their bytes match every entry in
`baseline_package_sha256` from the archived comparison plan. `manifest.json`
stores the same dictionary under `deployment_sha256`, which is the input
contract used by `scripts/compare_privacy_revisions_local.py`.

The directory is a package that can be loaded under a separate name:

```python
import importlib.util
import sys
from pathlib import Path

archive = Path("benchmarks/baselines/privacy_v2")
spec = importlib.util.spec_from_file_location(
    "privacy_revision_baseline",
    archive / "__init__.py",
    submodule_search_locations=[str(archive)],
)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
```

Use `--baseline-archive benchmarks/baselines/privacy_v2` and
`--baseline-manifest benchmarks/baselines/privacy_v2/manifest.json` with the
comparison script. Running that script additionally requires the local model
and detector configuration described in the main project documentation.

These are unmodified historical research sources, retained for comparison.
They are not a production privacy guarantee. No experiment results, caches,
credentials, model weights, or real private records are included here. Keep the
Python files unchanged so the baseline remains identifiable by its hashes.
