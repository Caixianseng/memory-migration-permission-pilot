"""Own the local server lifecycle, two accounted preflights and one formal run."""
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time

from .dual_gate import HandoffSession
from .local_model import DIGEST, call_model, get_json
from .make_tasks import generate

ROOT = Path(__file__).resolve().parents[2]
EXE = ROOT / ".runtime/privacy_agent/ollama/ollama.exe"


def hash_file(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(8 * 1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def listening():
    with socket.socket() as connection:
        connection.settimeout(0.5)
        return connection.connect_ex(("127.0.0.1", 11435)) == 0


def cleanup(proc, started, output):
    exe_dir = str(EXE.parent).replace("'", "''")
    # This stops only this process and descendants with matching executable root
    # and creation times. It does not use a process name or kill unrelated servers.
    script = f"""
$ErrorActionPreference='Stop'
$rootId={proc.pid}
$started=[datetime]::Parse('{started}')
$all=@(Get-CimInstance Win32_Process)
$ids=[System.Collections.Generic.HashSet[int]]::new()
[void]$ids.Add($rootId)
for($i=0;$i -lt 8;$i++){{
  foreach($p in $all){{if($ids.Contains([int]$p.ParentProcessId)){{[void]$ids.Add([int]$p.ProcessId)}}}}
}}
$selected=@($all | Where-Object {{ $ids.Contains([int]$_.ProcessId) -and $_.ExecutablePath -and $_.ExecutablePath.StartsWith('{exe_dir}',[System.StringComparison]::OrdinalIgnoreCase) -and $_.CreationDate.ToUniversalTime() -ge $started.ToUniversalTime().AddSeconds(-2) }})
$receipt=@()
foreach($p in ($selected | Sort-Object @{{Expression={{if($_.ProcessId -eq $rootId){{1}}else{{0}}}}}})){{
 $q=Get-CimInstance Win32_Process -Filter ('ProcessId='+$p.ProcessId) -ErrorAction SilentlyContinue
 if($q -and $q.ExecutablePath -eq $p.ExecutablePath -and $q.CreationDate -eq $p.CreationDate){{Stop-Process -Id $p.ProcessId -Force -ErrorAction Stop;$receipt+=@{{pid=$p.ProcessId;identity_checked=$true;stopped=$true}}}}
}}
ConvertTo-Json -InputObject @($receipt) -Compress
"""
    encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
    result = subprocess.run(["powershell", "-NoProfile", "-EncodedCommand", encoded],
                            capture_output=True, text=True, timeout=20)
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        pass
    time.sleep(0.5)
    write(output / "cleanup.json", {"command_exit": result.returncode,
        "identity_checked_stops": result.stdout.strip(), "error": result.stderr[-1500:],
        "parent_returncode": proc.poll(), "port_listening_after": listening()})


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    if listening():
        raise RuntimeError("port_in_use_do_not_touch_foreign_service")
    assert hash_file(EXE) == "034a26a71836df581ef8b9ab4db489154f548c81b53aa8816d0e843b9e385c2b"
    weights = ROOT / ".runtime/privacy_agent/models/blobs/sha256-85e4a5b7b8ef0e48af0e8658f5aaab9c2324c76c1641493f4d1e25fce54b18b9"
    assert hash_file(weights) == "85e4a5b7b8ef0e48af0e8658f5aaab9c2324c76c1641493f4d1e25fce54b18b9"
    ledger = ROOT / "results/qoder_harness_plan_20261029/resource_ledger.json"
    (output / "ledger_before.json").write_bytes(ledger.read_bytes())
    environment = os.environ.copy()
    environment.update(OLLAMA_HOST="127.0.0.1:11435", OLLAMA_MODELS=str(weights.parent.parent),
        OLLAMA_NO_CLOUD="1", OLLAMA_NUM_PARALLEL="1", OLLAMA_MAX_LOADED_MODELS="1",
        OLLAMA_CONTEXT_LENGTH="4096", USERPROFILE=str(ROOT / ".runtime/privacy_agent/profile"))
    started = datetime.now(timezone.utc).isoformat()
    with (output / "server.stdout.private.log").open("wb") as outlog, (output / "server.stderr.private.log").open("wb") as errlog:
        proc = subprocess.Popen([str(EXE), "serve"], cwd=str(ROOT), env=environment,
            stdout=outlog, stderr=errlog, creationflags=subprocess.CREATE_NO_WINDOW)
        write(output / "lease.json", {"pid": proc.pid, "started_utc": started,
                                     "executable": str(EXE), "port": 11435})
        try:
            deadline = time.monotonic() + 45
            while True:
                if proc.poll() is not None:
                    raise RuntimeError("owned_server_exited_before_ready")
                try:
                    version, tags = get_json("/api/version"), get_json("/api/tags")
                    assert version["version"] == "0.40.8"
                    assert any(row.get("digest") == DIGEST for row in tags["models"])
                    break
                except (OSError, ValueError, KeyError, AssertionError):
                    if time.monotonic() >= deadline:
                        raise RuntimeError("owned_server_readiness_timeout")
                    time.sleep(0.5)
            write(output / "runtime.json", {"version": version, "model_tags": tags,
                "cloud_disabled_configuration": True, "whole_host_network_attestation": False})
            receipts = []
            for i in range(2):
                case = generate(200001 + i, count=1)[0][0]
                session = HandoffSession(case, output / ("preflight_state_" + str(i)))
                record = session.eligible()[0][0]
                station = record["text"].split()[1]
                case["query"] = "What is the customer code for station " + station + "? Return only the exact code or UNKNOWN."
                request = session.prepare([record], "preflight-" + str(i))
                result = call_model(request["prepared"]["payload"], phase="algorithm_ports_ltt_preflight",
                                    run_id="algorithm_ports_ltt:preflight01")
                restored = session.restore(result["answer"], request)
                expected = session.rows[record["source"]["source_id"]]["protected_value"]
                passed = restored.get("status") == "ok" and restored.get("answer") == expected
                receipts.append({"index": i, "transport": result, "restoration_status": restored.get("status"),
                                 "passed": passed})
                write(output / "preflight.json", receipts)
                if not passed:
                    raise RuntimeError("preflight_roundtrip_failed_no_formal_run")
                print(json.dumps({"preflight": i + 1, "passed": True}), flush=True)
            write(output / "ready_for_formal.json", {"status": "passed", "preflight_POSTs": 2})
            print("READY_FOR_ROOT_GO_FILE", flush=True)
            deadline = time.monotonic() + 600
            while not (output / "GO").exists():
                if (output / "STOP").exists() or time.monotonic() >= deadline:
                    raise RuntimeError("formal_not_started")
                time.sleep(1)
            command = [sys.executable, "-m", "experiments.algorithm_ports_20261029.run_ltt", "predict",
                       "--materials", str(ROOT / "results/algorithm_ports_20261029/ltt_materials"),
                       "--output", str(ROOT / "results/algorithm_ports_20261029/ltt_run01"),
                       "--endpoint", "http://127.0.0.1:11435"]
            run = subprocess.run(command, cwd=str(ROOT), timeout=1200)
            write(output / "formal_exit.json", {"returncode": run.returncode})
            if run.returncode:
                raise RuntimeError("formal_process_failed_preserved")
        except Exception as error:
            write(output / "failure.json", {"type": type(error).__name__, "message": str(error)})
            raise
        finally:
            cleanup(proc, started, output)


if __name__ == "__main__":
    main()
