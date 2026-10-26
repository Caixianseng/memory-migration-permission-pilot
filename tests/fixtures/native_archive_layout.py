"""Non-executable local files for archive/launcher tests, never native assets."""
from pathlib import Path


def archive_only_legacy(root):
    """Create named source/asset placeholders; none may be imported or loaded."""
    root = Path(root).resolve()
    scripts = root / "scripts"
    scripts.mkdir(parents=True)
    for name in ("qualify_migration.py", "openwebui_migration_probe.py"):
        (scripts / name).write_text(
            '# Synthetic source-archive fixture, not a legacy implementation.\n'
            'raise RuntimeError("archive_only_fixture_must_not_execute")\n',
            encoding="utf-8")
    assets = root / "runtime_assets"
    for name in ("model.safetensors", "config.json", "modules.json", "tokenizer.json",
                 "tokenizer_config.json", "1_Pooling/config.json"):
        path = assets / "models/minilm" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"NOT_A_MODEL_OR_VALID_TOKENIZER\n")
    for name in ("libcrypto-3-x64.dll", "libssl-3-x64.dll"):
        path = assets / "native_dlls" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"NOT_AN_EXECUTABLE_LIBRARY\n")
    return root


def archive_only_webui_python(root):
    """Return an inert executable path and expected source-hash support layout."""
    root = Path(root).resolve()
    python = root / "Scripts/python.exe"
    python.parent.mkdir(parents=True)
    python.write_bytes(b"NOT_AN_EXECUTABLE\n")
    package = root / "Lib/site-packages/open_webui"
    for name in ("config.py", "routers/memories.py", "utils/memory.py",
                 "retrieval/vector/main.py", "retrieval/vector/dbs/chroma.py"):
        path = package / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('# Synthetic archive-only WebUI source.\n'
                        'raise RuntimeError("archive_only_fixture_must_not_execute")\n',
                        encoding="utf-8")
    return python
