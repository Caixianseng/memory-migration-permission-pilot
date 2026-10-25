"""Offline consistency audit of recorded GLiClass logits; never loads a model.

Token IDs are checked against saved qualification, not independently retokenized.
This audit does not certify model quality, an original HMAC, or novel research.
"""
from __future__ import annotations

import argparse
from collections import Counter
from copy import deepcopy
import hashlib
import json
import math
from pathlib import Path
import socket
import sys
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))
from memory_migration_study import gliclass_candidate as method
from memory_migration_study.boundary_detector import refine_detection
from memory_migration_study.candidate_proposals import propose_candidates
from verify_candidate_decision_diagnostic import _archive
from verify_context_candidate_diagnostic import score, sum_counts


def read(path):
    return json.loads(Path(path).read_bytes())


def sha(value):
    return hashlib.sha256(value).hexdigest()


def digest(value):
    return sha(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode())


class RecordedTokenizer:
    """Pure saved-token replay. It cannot perform classification or tokenization."""
    def __init__(self, identity, requests):
        self.identity = identity
        self.encoded = {}
        for request in requests:
            old = self.encoded.setdefault(request["sequence"], request["inputs"])
            if old != request["inputs"]:
                raise ValueError("conflicting_saved_tokenization")

    def health(self):
        return deepcopy(self.identity)

    def reserved_tokens(self):
        return ["<<LABEL>>", "<<SEP>>", "<<EXAMPLE>>", "[CLS]", "[SEP]", "[PAD]", "[MASK]",
                method.MARK_START, method.MARK_END]

    def tokenize(self, sequence):
        return deepcopy(self.encoded[sequence])

    def predict(self, *_args, **_kwargs):
        raise AssertionError("verification_must_never_infer")


def verify(run, *, archive=None, preflight_plan=None, flat_reference=None):
    run = Path(run).resolve()
    checks, phase = [], "setup"
    blocked = []
    def check(name, predicate):
        if not predicate:
            raise ValueError(name)
        checks.append(name)
    def deny(*_args, **_kwargs):
        blocked.append(True)
        raise AssertionError("verification_network_forbidden")
    report = {"version": "gliclass_recorded_logit_audit_v1", "status": "failed", "checks": checks,
              "verification_model_calls": 0, "independent_acceptance": False,
              "limitations": ["Replays recorded token IDs; it does not independently run the tokenizer or weights.",
                  "Forward-hook receipts are process observations, not a hardware or packet attestation.",
                  "Integrity and deterministic rescoring do not establish privacy quality or research novelty."]}
    try:
        with patch.object(socket.socket, "connect", deny), patch.object(socket, "create_connection", deny):
            check("results_scope", run.is_relative_to((ROOT / "results").resolve()))
            archive = Path(archive) if archive else ROOT / "benchmarks/artifacts/context_candidate_detection_20261026_v2.zip"
            blobs, _, _, reference, _ = _archive(archive)
            plan, closure, scored, materials = (read(run / n) for n in ("plan.json", "model_phase_closed.json", "rows.json", "materials.json"))
            check("closed_before_scoring", closure["model_phase_closed"] is True and
                  read(run / "score_phase_started.json")["closure_sha256"] == sha((run / "model_phase_closed.json").read_bytes()))
            for name, expected in closure["artifact_sha256"].items():
                check("closed_hash:" + name, sha((run / name).read_bytes()) == expected)
            check("preselected_arms", plan["primary"] == "gliclass_candidate" and plan["arms"] ==
                  ["standard_boundary_ner", "recorded_flat_primary", "gliclass_candidate"])
            for name, expected in plan["implementation_sha256"].items():
                check("frozen_source:" + name, sha((run / "frozen_source" / name).read_bytes()) == expected and
                      sha((ROOT / name).read_bytes()) == expected)
            if preflight_plan:
                prior = read(preflight_plan)
                for field in ("schedule", "arms", "primary", "implementation_sha256", "approved_policies", "max_encoder_forwards",
                              "max_root_forwards", "cpu_threads", "batch_size", "dtype", "max_tokens", "qualification_sha256"):
                    check("preflight_unchanged:" + field, prior[field] == plan[field])
            cases, gold = {}, {}
            for split in ("development", "heldout"):
                for name in ("runtime.json", "evaluation.json"):
                    check("fixed_corpus:" + split + "/" + name,
                          (run / split / name).read_bytes() == blobs[split + "/" + name])
                for case in read(run / split / "runtime.json"):
                    cases[case["case_id"]] = case | {"split": split}
                gold.update(read(run / split / "evaluation.json"))
            check("complete_120_cases", len(cases) == len(materials) == 120 and set(cases) == {m["case_id"] for m in materials})
            unscored = read(run / "unscored_rows.json")
            check("complete_360_rows", len(scored) == len(unscored) == 360 and
                  len({(r["case_id"], r["arm"]) for r in scored}) == 360 and
                  all(Counter(r["arm"] for r in scored if r["case_id"] == cid) == Counter(plan["arms"]) for cid in cases))
            check("scoring_only_added_score", [{k:v for k,v in r.items() if k != "score"} for r in scored] == unscored)
            ref = {m["case_id"]: m for m in reference}
            flat_dir = Path(flat_reference).resolve() if flat_reference else ROOT / plan["reference_flat"]["result_dir"]
            for name, expected in plan["reference_flat"]["sha256"].items():
                check("flat_reference_hash:" + name, sha((flat_dir / name).read_bytes()) == expected)
            flat_rows = {r["case_id"]: r for r in read(flat_dir / "unscored_rows.json")
                         if r["arm"] == plan["reference_flat"]["primary_arm"]}
            indices = {(r["case_id"], r["arm"]): r for r in scored}
            rebuilt_calls = []
            phase = "raw_logits_and_composition"
            for item in materials:
                cid, stage = item["case_id"], item["stage"]
                case = cases[cid]
                baseline = refine_detection(case["payload"], case["policy"], ref[cid]["baseline"])
                pool = propose_candidates(case["payload"], case["policy"], baseline["findings"], max_candidates=16, max_quote_chars=256)
                check("boundary_and_pool:" + cid, baseline == item["boundary_baseline"] and pool == item["boundary_pool"])
                check("control_baseline:" + cid, indices[cid,"standard_boundary_ner"]["detection"] == baseline)
                check("control_recorded_flat:" + cid, indices[cid,"recorded_flat_primary"]["detection"] == flat_rows[cid]["detection"])
                requests = item["preflight"]["requests"]
                runtime = RecordedTokenizer(stage["runtime"], requests)
                for record, request in zip(stage["raw_results"], requests):
                    logits, probs = record["raw_result"]["logits"], record["raw_result"]["probabilities"]
                    exp = [math.exp(v-max(logits)) for v in logits]
                    calc = [v/sum(exp) for v in exp]
                    winner = max(range(len(logits)), key=lambda i: logits[i])
                    check("independent_softmax:" + cid + "/" + record["cid"],
                          all(math.isfinite(v) for v in logits+probs) and len(probs) == len(request["labels"]) and
                          all(abs(a-b) <= 1e-6 for a,b in zip(probs,calc)) and
                          record["prediction"] == {"decision":request["labels"][winner]["decision"], "winner_index":winner,"score":probs[winner]})
                    check("input_and_forward_binding:" + cid + "/" + record["cid"], record["request"] == request and
                          request["token_count"] == len(request["inputs"]["input_ids"]) <= 512 and
                          digest(request["inputs"]) == request["input_sha256"] and
                          record["root_forward_delta"] == record["encoder_forward_delta"] == 1 and record["error"] is None and
                          cid not in request["sequence"] and case["policy"]["version"] not in request["sequence"])
                    rebuilt_calls.append({"index":len(rebuilt_calls),"case_id":cid,"split":item["split"], **record})
                rebuilt = method.compose_gliclass_detection(case["payload"], case["policy"], baseline, pool, stage,
                           approved_policies=plan["approved_policies"], runtime=runtime)
                check("optional_protection_composition:" + cid, rebuilt == indices[cid,"gliclass_candidate"]["detection"])
            calls = read(run / "encoder_calls.json")
            # Index is an observational display field; the remaining fields bind the actual requests/results.
            clean = lambda rows: [{k:v for k,v in r.items() if k != "index"} for r in rows]
            check("all_forward_receipts", clean(calls) == clean(rebuilt_calls) and len(calls) ==
                  closure["forward_counts"]["root"] == closure["forward_counts"]["encoder"] == plan["max_encoder_forwards"] == 111)
            phase = "independent_scoring"
            for row in scored:
                check("whole_span_score:" + row["case_id"] + "/" + row["arm"],
                      row["score"] == score(row["detection"], gold[row["case_id"]], cases[row["case_id"]]["payload"]))
            producer = read(run / "report.json")
            for split in ("development", "heldout"):
                for arm in plan["arms"]:
                    selected = [r for r in scored if r["split"] == split and r["arm"] == arm]
                    check("aggregate:" + split + "/" + arm, producer["summary"][split][arm]["accepted"] ==
                          sum_counts([r["score"]["accepted"] for r in selected]))
            check("zero_network_and_generation", read(run / "network_audit.json") ==
                  {"blocked_connection_attempts":0,"remote_model_calls":0,"qwen_calls":0} and
                  producer["new_generation_posts"] == producer["cloud_calls"] == producer["new_api_cost_cny"] == 0 and not blocked)
            report.update(status="passed", rows=len(scored), recorded_root_forwards=len(calls), recorded_encoder_forwards=len(calls),
                          source_materials=len(cases), default_changed=producer["default_changed"])
    except Exception as error:
        report["error"] = type(error).__name__ + ": " + str(error)
    report.update(phase=phase, check_count=len(checks), verification_network_attempts=len(blocked))
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("run", type=Path)
    parser.add_argument("--preflight-plan", type=Path)
    parser.add_argument("--flat-reference", type=Path, help="Recorded flat directory for a newly unpacked artifact.")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError("new_receipt_required")
    receipt = verify(args.run, preflight_plan=args.preflight_plan, flat_reference=args.flat_reference)
    receipt["verifier_sha256"] = sha(Path(__file__).read_bytes())
    args.output.write_text(json.dumps(receipt, ensure_ascii=False, indent=2)+"\n", encoding="utf-8")
    print(json.dumps({k:v for k,v in receipt.items() if k != "checks"}, ensure_ascii=False))
    raise SystemExit(0 if receipt["status"] == "passed" else 1)
