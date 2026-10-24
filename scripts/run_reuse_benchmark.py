"""Compare optional role coverage and scoped detection caching; no paid API."""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from memory_migration_study.reuse_benchmark import run_role_comparison, run_cache_comparison, render_report, summary, save


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--with-local-model", action="store_true", help="Run the pinned local model; never invokes a cloud API")
    parser.add_argument("--config", type=Path, default=Path("configs/local_privacy_detector.json"))
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    roles = run_role_comparison(args.output / "roles")
    cache = None
    if args.with_local_model:
        config = json.loads(args.config.read_text(encoding="utf-8"))
        cache = run_cache_comparison(args.output / "cache", config,
                                    progress=lambda row: print(json.dumps(row, ensure_ascii=False), flush=True))
    result = summary(roles, cache)
    save(args.output / "summary.json", result)
    render_report(args.output, roles, cache)
    print(json.dumps({"output": str(args.output), "cloud_calls": 0, "cost_cny": 0}, ensure_ascii=False))
