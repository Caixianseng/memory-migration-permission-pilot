# Native Cognee configuration helper

This directory carries one complete, user-authored configuration helper so a
Git clone does not depend on the ignored legacy 149-test project. It contains
no old experiment outputs, datasets, exports, credentials, runtime state,
third-party wheels, vendor source, or models.

`scripts/native_cognee_policy_worker.py` uses only
`configure_isolated_cognee` from the copied
`scripts/cognee_local_migration_probe.py`. The helper's top-level imports are
Python standard library modules. The historical `run()` command remains in the
complete file to preserve its pinned bytes; importing the module does not run
that command. Use the current worker/driver as the experiment entry point.

## Byte identity

- Complete helper: **20,732 bytes**.
- SHA-256: `11f295bf655690b33c9051a48b650bbb8592e5d83bfb78beba57ee5694de6aad`.
- Original line endings: **361 CRLF, 0 bare LF**. Do not reformat this file.
- The worker's `LEGACY_CONFIGURATION_SHA256` pins these same complete bytes.
- `ASSET_MANIFEST.json` records the source, scope, hash, and prerequisites.

Git must preserve the helper's bytes. The repository includes this single-file
attribute in `.gitattributes`:

```gitattributes
examples/native_cognee_probe_assets/scripts/cognee_local_migration_probe.py -text whitespace=cr-at-eol
```

The full source was reviewed without running it. No fixed actual secret was
found: API-key settings are empty, and the historical CLI constructs temporary
test passwords at runtime with `secrets`. No credential file was inspected or
copied.

## Runtime prerequisites

1. A separate **`.venv-native-cognee`** environment with the current worker's
   required dependencies. Cognee must be **1.6.5**. The tested Windows/Python 3.12
   pins are in `configs/native_cognee_windows_py312_requirements.txt`; install
   with `pip --isolated --only-binary=:all: --no-binary=langdetect -r` followed by
   that file. This helper itself does not install dependencies.
2. The separately obtained official
   `cognee-1.6.5-py3-none-any.whl`, SHA-256
   `aaef9fdc02f542b1d125cde21759dde2fac56355d8928e39c734e7b5c6705eca`.
   The wheel is not bundled. The worker compares the installed Cognee version
   and its selected actual vendor files against this wheel.
3. A **new ASCII-only child of system temp** for native state, with no preexisting
   databases or credentials. The current driver creates the unique path. The
   native auth store stays native inside that isolated state; do not publish it.
4. A fresh worker process. The helper configures process environment, creates
   state subdirectories, disables external connection probes and telemetry,
   clears model API-key variables, and installs a persistent audit hook. It
   should not be invoked inside an unrelated long-lived application process.
5. Where required by an older Windows Python runtime, an existing OpenSSL 3 DLL
   directory containing both expected DLLs. No DLLs are bundled here.

## Current entry points

The frozen worker accepts the new asset root without changing its code:

```text
--legacy-project examples/native_cognee_probe_assets
```

The current identity-qualification driver exposes the same root through
`--legacy`. From the repository root, with prerequisites already present:

```powershell
python scripts/run_cognee_identity_qualification.py --output results/cognee_identity_qualification_clone_check --legacy examples/native_cognee_probe_assets
```

Its defaults select `.venv-native-cognee/Scripts/python.exe` and
`.runtime/native_cognee_wheel/cognee-1.6.5-py3-none-any.whl`; `--python` and
`--wheel` can point to the corresponding provisioned files. The output directory
must be new. This command performs a real native identity qualification; it was
**not run for this packaging delivery**. No models, native service operations,
or dependency installation were performed while copying and checking this
asset. Existing identity qualification does not establish the later policy
projection matrix.
