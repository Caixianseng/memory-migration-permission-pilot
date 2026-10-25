"""Repeat the existing import-only guard with address/stack observations.

Keeps the original receipt/source unchanged. No Memory/client/model is created.
"""
import argparse
import atexit
import hashlib
import json
from pathlib import Path
import sys
import traceback


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sdk-root", type=Path, default=Path(".runtime/native_mem0_sdk_v1"))
    parser.add_argument("--output", type=Path, default=Path("results/native_mem0_import_bind_trace_20261025.json"))
    args = parser.parse_args()
    source = args.sdk_root.resolve() / "import_qualification.py"
    output = args.output.resolve()
    if output.exists():
        raise FileExistsError("Refusing to overwrite bind qualification")
    events = []
    def capture(event, values):
        if event in {"socket.bind", "socket.connect", "socket.getaddrinfo", "socket.sendto"}:
            address = values[1] if event in {"socket.bind", "socket.connect"} and len(values) > 1 else None
            events.append({"event": event, "address": address,
                "stack": [{"file": frame.filename, "line": frame.lineno, "function": frame.name}
                          for frame in traceback.extract_stack(limit=18)[:-1]]})
    sys.addaudithook(capture)
    def save():
        output.write_text(json.dumps({"kind": "guarded_import_bind_attribution", "events": events,
            "original_script_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            "original_receipt_preserved": True, "generation_calls": 0, "encoder_calls": 0,
            "service_started": False, "all_attempts_still_blocked_by_original_guard": True},
            ensure_ascii=False, indent=2), encoding="utf-8")
    atexit.register(save)
    code = source.read_text(encoding="utf-8").replace('"import_qualification.json"', '"import_qualification_bind_trace.json"')
    exec(compile(code, str(source), "exec"), {"__file__": str(source), "__name__": "__main__"})
    save()


if __name__ == "__main__":
    main()
