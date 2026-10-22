"""Local study commands. Remote model requests require an explicit separate gate."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from .backend import HTTPAdapter
from .budget import ChatCompletionsConnector
from .evidence import evaluate, probe
from .prepare import prepare_gatemem
from .public_runner import run_public_pilot
from .runner import run_demo, save_json, write_report


def _load(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def main(argv=None):
    parser = argparse.ArgumentParser(description="Memory migration finite-domain study instrumentation")
    commands = parser.add_subparsers(dest="command", required=True)
    demo = commands.add_parser("demo")
    demo.add_argument("--output", type=Path, required=True)
    demo.add_argument("--seed", type=int, default=42)
    demo.add_argument("--diagnostics", action="store_true")
    demo.add_argument("--legacy-project", type=Path)
    demo.add_argument("--runtime", type=Path)
    demo.add_argument("--evaluation", type=Path)
    demo.add_argument("--model-config", type=Path)
    demo.add_argument("--enable-remote", action="store_true")
    demo.add_argument("--ledger", type=Path)
    public = commands.add_parser("public-pilot", description="One public episode under declared controlled policies; offline reference execution only")
    public.add_argument("--legacy-project", type=Path, required=True)
    public.add_argument("--output", type=Path, required=True)
    public.add_argument("--seed", type=int, default=42)
    native_public = commands.add_parser("native-webui-public", description="Native Open WebUI 0.12.3 public controlled-memory pilot; isolated process and local assets only")
    native_public.add_argument("--legacy-project", type=Path, required=True)
    native_public.add_argument("--output", type=Path, required=True)
    native_public.add_argument("--artifacts-root", type=Path)
    native_public.add_argument("--seed", type=int, default=42)
    prepare = commands.add_parser("prepare-gatemem")
    prepare.add_argument("--data-root", type=Path, required=True)
    prepare.add_argument("--output", type=Path, required=True)
    prepare.add_argument("--episodes-per-domain", type=int, default=1)
    prepare.add_argument("--limit", type=int, default=20)
    prepare.add_argument("--seed", type=int, default=42)
    evidence = commands.add_parser("evaluate-evidence")
    evidence.add_argument("--bundle", type=Path, required=True)
    evidence.add_argument("--output", type=Path, required=True)
    native = commands.add_parser("probe-native", description="Explicit standardized HTTP contract only; missing configuration is not_configured")
    native.add_argument("--config", type=Path)
    native.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.command == "native-webui-public":
        from .native_webui import run_native_webui_public
        result = run_native_webui_public(legacy_project=args.legacy_project, output=args.output,
                                         artifacts_root=args.artifacts_root, seed=args.seed)
        print(json.dumps({"manifest": str((args.output / "manifest.json").resolve()),
                          "status": result["status"], "real_llm": None, "remote_model_calls": 0}, ensure_ascii=False))
        if result["status"] != "completed":
            raise SystemExit(2 if result["status"] == "counterexample_found" else 1)
        return
    if args.command == "demo":
        answerer = None
        if args.enable_remote or args.model_config:
            if not args.enable_remote or not args.model_config or not args.ledger:
                parser.error("remote runs require --enable-remote, --model-config and --ledger together")
            answerer = ChatCompletionsConnector(_load(args.model_config), args.ledger, enable_remote=True)
            answerer._preflight()
        report = run_demo(args.output, seed=args.seed, diagnostics=args.diagnostics,
                          runtime_path=args.runtime, evaluation_path=args.evaluation, legacy_project=args.legacy_project, answerer=answerer)
        print(json.dumps({"report": str((args.output / "report.json").resolve()), "conditions": len(report["results"]), "real_llm_run": report["manifest"]["answerer_kind"] == "real_llm"}, ensure_ascii=False))
    elif args.command == "public-pilot":
        summary = run_public_pilot(args.legacy_project, args.output, seed=args.seed)
        print(json.dumps({"summary": str((args.output / "summary.json").resolve()),
                          "index": str((args.output / "index.html").resolve()),
                          "counts": summary["counts"], "real_llm_run": False,
                          "native_execution_performed": False}, ensure_ascii=False))
    elif args.command == "prepare-gatemem":
        bundle = prepare_gatemem(args.data_root, episodes_per_domain=args.episodes_per_domain, limit=args.limit, seed=args.seed)
        args.output.mkdir(parents=True, exist_ok=False)
        save_json(args.output / "candidates.json", bundle)
        print(json.dumps({"output": str(args.output.resolve()), "candidate_records": bundle["candidate_records"], "status": "needs_review"}))
    else:
        if args.command == "probe-native" and args.config is None:
            args.output.mkdir(parents=True, exist_ok=False)
            write_report(args.output, {"native_status": "not_configured", "results": [], "real_llm_metrics": None,
                                       "reason": "No explicit product HTTP contract configuration supplied"})
            print(json.dumps({"native_status": "not_configured"}))
            return 0
        if args.command == "evaluate-evidence":
            bundle = _load(args.bundle)
        else:
            cfg = _load(args.config)
            if cfg.get("backend_kind") not in {"native", "external_gated"} or not cfg.get("product") or not cfg.get("version"):
                raise ValueError("native contract requires explicit kind, product and version")
            case, plan = _load(args.config.parent / cfg["case_file"]), _load(args.config.parent / cfg["plan_file"])
            credentials = {a: os.environ.get(env, "") for a, env in cfg["credentials_env"].items()}
            adapter = HTTPAdapter(cfg["base_url"], credentials, case["actors"], cfg["controls"],
                                  backend_kind=cfg["backend_kind"], negative_contract=cfg.get("negative_contract") is True,
                                  expected_target_actor_ids=case["actor_mapping"])
            bundle = probe(case, plan, adapter)
            bundle["product"] = cfg["product"]
            bundle["product_version"] = cfg["version"]
        direct = evaluate(bundle)
        args.output.mkdir(parents=True, exist_ok=False)
        save_json(args.output / "evidence.json", bundle)
        write_report(args.output, {"results": [{"case_id": direct["case_id"], "condition": bundle["plan"]["method"], "direct": direct}],
                                   "real_llm_metrics": None, "native_status": bundle.get("native_status", "unknown")})
        print(json.dumps({"finite_scope_safe": direct["finite_scope_safe"], "known_w_plus": direct["known_w_plus"], "unknown_count": direct["unknown_count"]}))
    return 0
