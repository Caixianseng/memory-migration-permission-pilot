"""Execute the local-only full construction/intent/privacy paired study."""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=Path("examples/privacy_semantics_v1"))
    parser.add_argument("--split", choices=["development", "heldout"], default="development")
    parser.add_argument("--detector-kind", choices=["gliner", "union"], default="gliner")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--config", type=Path, default=Path("configs/local_privacy_detector.json"))
    parser.add_argument("--model-root", type=Path, default=Path(".runtime/github_ner"))
    args = parser.parse_args()
    network = {"loopback_connections": 0, "external_attempts_blocked": 0}
    def audit(event, values):
        if event == "socket.connect":
            address = values[1]
            if not isinstance(address, tuple) or address[0] not in {"127.0.0.1", "::1"}:
                network["external_attempts_blocked"] += 1
                raise RuntimeError("external_network_disabled")
            network["loopback_connections"] += 1
    sys.addaudithook(audit)
    from memory_migration_study.semantic_memory_benchmark import run
    from memory_migration_study.reuse_benchmark import save
    report = run(args.corpus, args.output, args.model_root, json.loads(args.config.read_text(encoding="utf-8")), split=args.split, detector_kind=args.detector_kind,
                 progress=lambda row: print(json.dumps(row), flush=True))
    save(args.output / "network_audit.json", network)
    print(json.dumps({"output": str(args.output), "report": report, "network": network}, ensure_ascii=False))
