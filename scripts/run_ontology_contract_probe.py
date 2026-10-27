"""Freeze, then explicitly execute the bounded local CUSTOMER contract probe.

Reference bytes are opaque until the complete model loop closes. This runner
calls the real production adapters directly, with no answer model or fallback.
"""
from __future__ import annotations

import argparse
from collections import Counter
import copy
import hashlib
import json
from pathlib import Path
import shutil
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from memory_migration_study.local_detector import (
    DIGEST, MODEL, REPAIR_PROMPT, VERSION as QWEN_RUNTIME_VERSION, LocalSensitivityAgent,
)
from memory_migration_study.ner_detector import (
    CODE_REVISION, MODEL_ID, MODEL_REVISION, GlinerEntityAgent, LocalNerRuntime,
)
from memory_migration_study.privacy import _digest, _policy
from memory_migration_study.sensitivity_contract import (
    ANY_SPECIFIC_ORGANIZATION, STRICT_CUSTOMER_RELATION, bind_category_contract,
    category_contract, category_contract_identity,
)

VERSION = "ontology_contract_probe_runner_v1"
ARMS = ("legacy_instruction_qwen", "explicit_contract_qwen", "explicit_contract_gliner")
PROFILES = (STRICT_CUSTOMER_RELATION, ANY_SPECIFIC_ORGANIZATION)
SOURCE_ID = "probe"
SCOPE = ("The business scope is the writer's company, referred to in the text as "
         "we/us/our company or 我们/本公司.")
LIMITS = {"detector_opportunities": 96, "qwen_detector_opportunities": 64,
          "qwen_post_attempts": 128, "gliner_infer_invocations": 16,
          "wall_seconds": 3600, "num_ctx": 4096, "num_predict": 1024}


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(4 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def save(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def save_exclusive(path, value):
    """Closed evidence is created once; progress files use save() instead."""
    with Path(path).open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def read_runtime(path):
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if (not isinstance(value, dict) or set(value) != {"schema_version", "texts"}
            or value["schema_version"] != "ontology_contract_probe_runtime_v1"
            or not isinstance(value["texts"], list) or len(value["texts"]) != 16
            or any(not isinstance(text, str) or not text.strip() for text in value["texts"])
            or len(set(value["texts"])) != 16):
        raise ValueError("invalid_probe_runtime")
    return value["texts"]


def make_policies():
    policies = {}
    for profile in PROFILES:
        base = {"version": "ontology_contract_probe_policy_v1", "policy_id": "ontology_contract_probe",
                "protected_categories": ["CUSTOMER"], "max_text_chars": 6000,
                "instructions": SCOPE, "entity_registry": []}
        explicit = bind_category_contract(base, profile)
        legacy = dict(base, instructions=SCOPE + "\nCUSTOMER definition: "
                      + category_contract(profile)["definitions"]["CUSTOMER"])
        policies[profile] = {ARMS[0]: _policy(legacy), ARMS[1]: _policy(explicit), ARMS[2]: _policy(explicit)}
    return policies


def make_schedule():
    schedule = []
    for index in range(16):
        profiles = PROFILES if index % 2 == 0 else tuple(reversed(PROFILES))
        arms = ARMS[index % 3:] + ARMS[:index % 3]
        for profile in profiles:
            schedule.extend({"text_index": index, "profile": profile, "arm": arm} for arm in arms)
    return schedule


def preflight(texts, policies, schedule):
    budgets = []
    for cell in schedule:
        if cell["arm"] == ARMS[2]:
            continue
        text, policy = texts[cell["text_index"]], policies[cell["profile"]][cell["arm"]]
        data, trusted = LocalSensitivityAgent._validate_inputs(text, SOURCE_ID, policy, [])
        messages, version = LocalSensitivityAgent._prepare_messages(data, trusted)
        repaired = [*messages, {"role": "user", "content": REPAIR_PROMPT}]
        initial = LocalSensitivityAgent._request_budget(messages)
        repair = LocalSensitivityAgent._request_budget(repaired, repair=True)
        budgets.append({**cell, "prompt_version": version, "initial_bound": initial,
                        "repair_bound": repair, "fits_initial": initial <= 4096,
                        "fits_repair": repair <= 4096, "messages_sha256": _digest(messages)})
    return {"cells": budgets, "all_fit": all(row["fits_initial"] and row["fits_repair"] for row in budgets),
            "maximum_initial_bound": max(row["initial_bound"] for row in budgets),
            "maximum_repair_bound": max(row["repair_bound"] for row in budgets),
            "bound_kind": "Production adapter's UTF-8 content-byte bound, template reserve and 1024 output tokens; not a measured tokenizer count."}


def checked_assets(model_root):
    model_root = Path(model_root).resolve()
    receipt_path = model_root / "receipt.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    if (receipt.get("code_revision") != CODE_REVISION or receipt.get("model_revision") != MODEL_REVISION
            or receipt.get("model_id") != MODEL_ID or len(receipt.get("files", {})) != 99):
        raise ValueError("ner_receipt_contract_mismatch")
    actual = {}
    for name, expected in receipt["files"].items():
        path = (model_root / name).resolve()
        if not path.is_relative_to(model_root) or not path.is_file():
            raise ValueError("ner_asset_path_invalid")
        actual[name] = sha(path)
        if actual[name] != expected:
            raise ValueError("ner_asset_changed")
    return {"root": str(model_root), "receipt_sha256": sha(receipt_path), "files": actual,
            "code_revision": CODE_REVISION, "model_revision": MODEL_REVISION, "model_id": MODEL_ID}


def source_hashes():
    paths = list((ROOT / "memory_migration_study").glob("*.py")) + [Path(__file__).resolve()]
    return {path.relative_to(ROOT).as_posix(): sha(path) for path in sorted(paths)}


def verify_implementation_archive(output, sources):
    archive = Path(output) / "implementation"
    if (archive.is_symlink() or not archive.is_dir()
            or {path.relative_to(archive).as_posix() for path in archive.rglob("*") if path.is_file()} != set(sources)):
        raise ValueError("frozen_implementation_archive_membership_changed")
    for relative, expected in sources.items():
        path = archive / relative
        if path.is_symlink() or not path.resolve().is_relative_to(archive.resolve()) or sha(path) != expected:
            raise ValueError("frozen_implementation_archive_changed")


def freeze(output, data_root, model_root, prereg):
    output, data_root, prereg = Path(output).resolve(), Path(data_root).resolve(), Path(prereg).resolve()
    if output.exists():
        raise ValueError("output_already_exists")
    runtime_path, reference_path = data_root / "runtime.json", data_root / "evaluation.json"
    texts, policies, schedule = read_runtime(runtime_path), make_policies(), make_schedule()
    budget = preflight(texts, policies, schedule)
    if not budget["all_fit"]:
        return {"status": "preflight_budget_exceeded", "preflight": budget, "model_calls": 0}
    assets = checked_assets(model_root)
    sources = source_hashes()
    output.mkdir(parents=True)
    archive = output / "implementation"
    archive.mkdir()
    for relative in sources:
        target = archive / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, target)
    shutil.copy2(runtime_path, output / "runtime.json")
    # Copy opaque bytes, with no JSON parsing or reference-driven decisions.
    shutil.copy2(reference_path, output / "evaluation.opaque.json")
    shutil.copy2(prereg, output / "preregistration.md")
    save(output / "policies.json", policies)
    save(output / "schedule.json", schedule)
    save(output / "preflight.json", budget)
    plan = {"version": VERSION, "status": "frozen_not_executed", "output": str(output),
            "runtime_sha256": sha(runtime_path), "reference_opaque_sha256": sha(reference_path),
            "preregistration_sha256": sha(prereg), "source_sha256": sources, "assets": assets,
            "policies_sha256": sha(output / "policies.json"), "schedule_sha256": sha(output / "schedule.json"),
            "preflight_sha256": sha(output / "preflight.json"), "limits": LIMITS,
            "category_contracts": category_contract_identity(), "fixed_source_id": SOURCE_ID,
            "qwen": {"model": MODEL, "digest": DIGEST, "runtime": QWEN_RUNTIME_VERSION,
                     "endpoint": "http://127.0.0.1:11435", "timeout_seconds": 120},
            "gliner": {"splitter": "cjk_aware", "threshold": .5, "threads": 4},
            "methods": {ARMS[0]: "Original system prompt; scope plus identical profile definition in instructions; no category_contract.",
                        ARMS[1]: "Explicit fixed category_contract; scope-only instructions; legacy CUSTOMER gloss removed.",
                        ARMS[2]: "Explicit broad definition in actual organization label; strict unsupported before infer."},
            "scoring": "Exact Unicode code-point spans per profile/arm; determinate review keeps positive FN; reference-review cells require needs_review; unsupported is separate, never a correct review or a fair strict ranking entry.",
            "execution": "Serial fixed schedule; no outer retry; only production format/span repair; stop on engineering error or exceeded budget; reference parsed only after all 96 opportunities close.",
            "capture_scope": "Actual transport-call request objects and returned decoded envelopes; canonical object hashes, not intercepted HTTP wire bytes. NER infer invocations are not all neural forwards.",
            "scope": "Synthetic contract development probe; no general performance or privacy guarantee."}
    save(output / "plan.json", plan)
    return {"status": "frozen_not_executed", "plan": str(output / "plan.json"),
            "plan_sha256": sha(output / "plan.json"), "preflight": {key: value for key, value in budget.items() if key != "cells"},
            "model_calls": 0}


def verify_frozen(output, expected_plan_sha256):
    output = Path(output).resolve()
    if sha(output / "plan.json") != expected_plan_sha256:
        raise ValueError("plan_hash_mismatch")
    plan = json.loads((output / "plan.json").read_text(encoding="utf-8"))
    if plan["version"] != VERSION or plan["limits"] != LIMITS or plan["source_sha256"] != source_hashes():
        raise ValueError("frozen_runner_or_source_changed")
    verify_implementation_archive(output, plan["source_sha256"])
    checks = {"runtime.json": "runtime_sha256", "evaluation.opaque.json": "reference_opaque_sha256",
              "preregistration.md": "preregistration_sha256", "policies.json": "policies_sha256",
              "schedule.json": "schedule_sha256", "preflight.json": "preflight_sha256"}
    if any(sha(output / filename) != plan[key] for filename, key in checks.items()):
        raise ValueError("frozen_material_changed")
    if checked_assets(plan["assets"]["root"]) != plan["assets"]:
        raise ValueError("frozen_assets_changed")
    policies = json.loads((output / "policies.json").read_text(encoding="utf-8"))
    schedule = json.loads((output / "schedule.json").read_text(encoding="utf-8"))
    texts = read_runtime(output / "runtime.json")
    if policies != make_policies() or schedule != make_schedule() or not preflight(texts, policies, schedule)["all_fit"]:
        raise ValueError("frozen_policy_schedule_or_budget_changed")
    return plan, texts, policies, schedule


def install_network_guard(audit):
    def guard(event, args):
        if event == "socket.connect":
            address = args[1]
            if not isinstance(address, tuple) or address[:2] != ("127.0.0.1", 11435):
                audit["blocked_connects"] += 1
                raise RuntimeError("probe_network_destination_forbidden")
            audit["loopback_connect_attempts"] += 1
    sys.addaudithook(guard)


class Budget:
    def __init__(self):
        self.started = time.monotonic()
        self.posts, self.infers = 0, 0

    def check(self):
        if time.monotonic() - self.started >= LIMITS["wall_seconds"]:
            raise RuntimeError("probe_wall_budget_exceeded")

    def generation(self):
        self.check()
        if self.posts >= LIMITS["qwen_post_attempts"]:
            raise RuntimeError("probe_generation_budget_exceeded")
        self.posts += 1

    def inference(self):
        self.check()
        if self.infers >= LIMITS["gliner_infer_invocations"]:
            raise RuntimeError("probe_infer_budget_exceeded")
        self.infers += 1


class CapturedTransport:
    def __init__(self, actual_transport, budget, output):
        self.actual, self.budget, self.output = actual_transport, budget, output
        self.events, self.cell = [], None

    def __call__(self, method, path, body=None):
        self.budget.check()
        if method == "POST":
            if path != "/api/chat":
                raise RuntimeError("unexpected_probe_http_path")
            self.budget.generation()
        elif (method, path) not in {("GET", "/api/version"), ("GET", "/api/tags")}:
            raise RuntimeError("unexpected_probe_http_path")
        event = {"cell": copy.deepcopy(self.cell), "method": method, "path": path,
                 "fixed_host": "127.0.0.1:11435", "request_object": copy.deepcopy(body),
                 "request_object_sha256": _digest(body)}
        self.events.append(event)
        try:
            result = self.actual(method, path, body)
            event["decoded_response"] = copy.deepcopy(result)
            self.budget.check()
            return result
        except Exception as exc:
            event["error_type"] = type(exc).__name__
            raise
        finally:
            save(self.output / "http_transport_capture.json", self.events)


class CapturedNer:
    def __init__(self, actual_runtime, budget, output):
        self.actual, self.budget, self.output = actual_runtime, budget, output
        self.identity = actual_runtime.identity
        self.events, self.cell = [], None

    def infer(self, text, labels, **options):
        # The runner enforces strict's zero-infer budget independently of the
        # production adapter being measured.
        if not isinstance(self.cell, dict) or self.cell.get("profile") != ANY_SPECIFIC_ORGANIZATION:
            raise RuntimeError("probe_ner_profile_forbidden")
        self.budget.inference()
        event = {"cell": copy.deepcopy(self.cell), "text": text, "labels": copy.deepcopy(labels),
                 "options": options, "input_sha256": _digest({"text": text, "labels": labels, "options": options})}
        self.events.append(event)
        try:
            result = self.actual.infer(text, labels, **options)
            event["decoded_response"] = copy.deepcopy(result)
            self.budget.check()
            return result
        except Exception as exc:
            event["error_type"] = type(exc).__name__
            raise
        finally:
            save(self.output / "ner_infer_capture.json", self.events)


def observation_status(response, *, expected_unsupported=False):
    if not isinstance(response, dict) or not isinstance(response.get("errors"), list):
        return "engineering_error"
    errors = response["errors"]
    if expected_unsupported:
        return "unsupported" if (response.get("status") == "needs_review" and errors == ["unsupported_category_contract"]
                                 and response.get("local_calls") == 0 and response.get("findings") == []) else "engineering_error"
    if response.get("status") == "ok" and not errors:
        return "ok"
    if response.get("status") == "needs_review" and errors == ["semantic_uncertainty"]:
        return "needs_review"
    return "engineering_error"


def exact_findings(response, text):
    findings = response.get("findings")
    if not isinstance(findings, list):
        raise ValueError("probe_invalid_findings")
    spans = set()
    for finding in findings:
        a, b, category = (finding.get(key) for key in ("start", "end", "category")) if isinstance(finding, dict) else (None, None, None)
        if (type(a) is not int or type(b) is not int or not 0 <= a < b <= len(text)
                or category != "CUSTOMER" or finding.get("quote") != text[a:b]):
            raise ValueError("probe_invalid_finding_span")
        spans.add((a, b, category))
    return spans


def score_rows(rows, reference, texts):
    if (reference.get("schema_version") != "ontology_contract_probe_evaluation_v1"
            or reference.get("profile_contract_sha256") != {profile: _digest(category_contract(profile)) for profile in PROFILES}
            or reference.get("runtime_sha256") is None):
        raise ValueError("probe_reference_contract_mismatch")
    cases = reference.get("cases")
    if not isinstance(cases, list) or len(cases) != 16 or {case["text_index"] for case in cases} != set(range(16)):
        raise ValueError("probe_reference_indices_invalid")
    by_index = {case["text_index"]: case for case in cases}
    for index, case in by_index.items():
        if case["text_sha256"] != hashlib.sha256(texts[index].encode()).hexdigest():
            raise ValueError("probe_reference_text_mismatch")
    summary = {}
    for row in rows:
        cell = row["cell"]
        expected = by_index[cell["text_index"]]["expected"][cell["profile"]]
        decision = expected["decision"]
        expected_spans = set()
        for finding in expected["spans"]:
            a, b, category = finding["start"], finding["end"], finding["category"]
            if (type(a) is not int or type(b) is not int or not 0 <= a < b <= len(texts[cell["text_index"]])
                    or category != "CUSTOMER" or texts[cell["text_index"]][a:b] != finding["text"]):
                raise ValueError("probe_reference_span_invalid")
            expected_spans.add((a, b, category))
        if decision not in {"sensitive", "not_sensitive", "needs_review"}:
            raise ValueError("probe_reference_decision_invalid")
        predicted = exact_findings(row["response"], texts[cell["text_index"]]) if row["status"] == "ok" else set()
        actual_decision = ("sensitive" if predicted else "not_sensitive") if row["status"] == "ok" else row["status"]
        applicable = row["status"] != "unsupported"
        score = {"expected_decision": decision, "actual_decision": actual_decision,
                 "decision_matches": applicable and actual_decision == decision,
                 "applicable": applicable, "span_score": None,
                 "determinate_exact_match": None}
        if applicable and decision != "needs_review":
            score["span_score"] = {"tp": len(predicted & expected_spans), "fp": len(predicted - expected_spans),
                                   "fn": len(expected_spans - predicted)}
            score["determinate_exact_match"] = (row["status"] == "ok" and score["decision_matches"]
                                                and predicted == expected_spans)
        row["score"] = score
        key = cell["profile"] + "/" + cell["arm"]
        group = summary.setdefault(key, {"cells": 0, "applicable_cells": 0, "ok": 0, "needs_review": 0,
                                        "unsupported": 0, "decision_matches": 0, "reference_review_cells": 0,
                                        "reference_review_matches": 0, "determinate_applicable_cells": 0,
                                        "determinate_exact_matches": 0, "tp": 0, "fp": 0, "fn": 0})
        group["cells"] += 1
        group["applicable_cells"] += int(applicable)
        group[row["status"]] += 1
        group["decision_matches"] += int(score["decision_matches"])
        group["reference_review_cells"] += int(decision == "needs_review")
        group["reference_review_matches"] += int(decision == "needs_review" and score["decision_matches"])
        group["determinate_applicable_cells"] += int(score["determinate_exact_match"] is not None)
        group["determinate_exact_matches"] += int(score["determinate_exact_match"] is True)
        for metric, value in (score["span_score"] or {}).items():
            group[metric] += value
    for group in summary.values():
        group["processable_rate"] = group["ok"] / group["cells"]
        group["decision_match_rate"] = group["decision_matches"] / group["applicable_cells"] if group["applicable_cells"] else None
        group["determinate_exact_match_rate"] = (group["determinate_exact_matches"] / group["determinate_applicable_cells"]
                                                  if group["determinate_applicable_cells"] else None)
        group["precision"] = group["tp"] / (group["tp"] + group["fp"]) if group["tp"] + group["fp"] else None
        group["recall"] = group["tp"] / (group["tp"] + group["fn"]) if group["tp"] + group["fn"] else None
        group["eligible_for_same_profile_ranking"] = bool(group["applicable_cells"])
    return summary


def execute(output, expected_plan_sha256):
    output = Path(output).resolve()
    if (output / "execution.json").exists():
        raise ValueError("probe_execution_already_started")
    plan, texts, policies, schedule = verify_frozen(output, expected_plan_sha256)
    budget = Budget()
    network = {"loopback_connect_attempts": 0, "blocked_connects": 0}
    install_network_guard(network)
    rows, execution = [], {"version": VERSION, "plan_sha256": expected_plan_sha256, "status": "started"}
    save(output / "execution.json", execution)
    try:
        local = LocalSensitivityAgent({"timeout_seconds": plan["qwen"]["timeout_seconds"]})
        transport = CapturedTransport(local._transport, budget, output)
        local.transport = transport
        # This validates pinned Qwen assets without a generation.
        health = local.health()
        budget.check()
        actual_ner = LocalNerRuntime(plan["assets"]["root"], threads=plan["gliner"]["threads"])
        runtime = CapturedNer(actual_ner, budget, output)
        ner = GlinerEntityAgent(runtime, approved_policies=[policies[profile][ARMS[2]] for profile in PROFILES],
                                splitter=plan["gliner"]["splitter"], threshold=plan["gliner"]["threshold"])
        save(output / "detectors.json", {"qwen_health": health, "qwen_identity": local.cache_identity(),
                                          "ner_identity": ner.cache_identity(),
                                          "ner_initialization_seconds": actual_ner.initialization_seconds})
        for cell in schedule:
            budget.check()
            transport.cell = runtime.cell = cell
            detector = ner if cell["arm"] == ARMS[2] else local
            before = budget.infers if detector is ner else budget.posts
            response = detector(text=texts[cell["text_index"]], source_id=SOURCE_ID,
                                policy=copy.deepcopy(policies[cell["profile"]][cell["arm"]]), rule_findings=[])
            observed = (budget.infers if detector is ner else budget.posts) - before
            status = observation_status(response, expected_unsupported=detector is ner and cell["profile"] == STRICT_CUSTOMER_RELATION)
            row = {"cell": cell, "status": status, "response": response,
                   "qwen_post_attempts": observed if detector is local else 0,
                   "gliner_infer_invocations": observed if detector is ner else 0}
            rows.append(row)
            save(output / "rows.json", rows)
            budget.check()
            if status == "engineering_error" or response.get("local_calls") != observed:
                raise RuntimeError("probe_engineering_error_or_accounting_mismatch")
            exact_findings(response, texts[cell["text_index"]])
            print(json.dumps({"completed": len(rows), "total": len(schedule), **cell,
                              "status": status, "qwen_posts": budget.posts, "ner_infers": budget.infers}), flush=True)
        budget.check()
        if source_hashes() != plan["source_sha256"]:
            raise ValueError("probe_implementation_changed_during_execution")
        verify_implementation_archive(output, plan["source_sha256"])
        budget.check()
        if len(rows) != LIMITS["detector_opportunities"]:
            raise RuntimeError("probe_incomplete_prediction_inventory")
        # Freeze unscored observations before any reference parsing. Captures
        # are decoded transport/infer objects, never claimed intercepted wire.
        save_exclusive(output / "predictions.json", copy.deepcopy(rows))
        captures = {name: sha(output / name) for name in ("http_transport_capture.json", "ner_infer_capture.json")
                    if (output / name).is_file()}
        closure = {"version": VERSION, "plan_sha256": expected_plan_sha256,
                   "predictions_sha256": sha(output / "predictions.json"),
                   "completed_opportunities": len(rows), "all_96_opportunities_closed": True,
                   "source_sha256": dict(plan["source_sha256"]),
                   "implementation_and_archive_verified": True, "capture_objects_sha256": captures,
                   "capture_scope": "Decoded request/response objects; not intercepted HTTP wire bytes.",
                   "closed_at_unix_seconds": time.time(), "reference_parsed": False}
        save_exclusive(output / "prediction_phase_closed.json", closure)
        execution.update(status="model_loop_closed", reference_parsed=False,
                         predictions_sha256=closure["predictions_sha256"],
                         prediction_phase_closed_sha256=sha(output / "prediction_phase_closed.json"))
        save(output / "execution.json", execution)
        budget.check()
        # No reference JSON is loaded until the complete model loop is closed.
        if sha(output / "evaluation.opaque.json") != plan["reference_opaque_sha256"]:
            raise ValueError("probe_reference_changed")
        reference = json.loads((output / "evaluation.opaque.json").read_text(encoding="utf-8"))
        if reference["runtime_sha256"] != plan["runtime_sha256"]:
            raise ValueError("probe_reference_runtime_mismatch")
        scored_rows = copy.deepcopy(rows)
        summary = score_rows(scored_rows, reference, texts)
        if source_hashes() != plan["source_sha256"]:
            raise ValueError("probe_implementation_changed_during_execution")
        if (sha(output / "predictions.json") != closure["predictions_sha256"]
                or sha(output / "prediction_phase_closed.json") != execution["prediction_phase_closed_sha256"]
                or any(sha(output / name) != expected for name, expected in closure["capture_objects_sha256"].items())):
            raise ValueError("probe_closed_evidence_changed")
        report = {"version": VERSION, "plan_sha256": expected_plan_sha256, "status": "complete",
                  "independent_texts": 16, "opportunities": len(rows), "by_profile_arm": summary,
                  "qwen_post_attempts": budget.posts, "gliner_infer_invocations": budget.infers,
                  "gliner_strict_infer_invocations": sum(row["gliner_infer_invocations"] for row in rows if row["cell"]["profile"] == STRICT_CUSTOMER_RELATION),
                  "neural_forward_count": "not_instrumented", "cloud_calls": 0, "paid_calls": 0,
                  "native_client_calls": 0, "answer_model_calls": 0, "network": network,
                  "wall_seconds": time.monotonic() - budget.started,
                  "implementation_unchanged": True, "scope": plan["scope"],
                   "predictions_sha256": closure["predictions_sha256"],
                   "prediction_phase_closed_sha256": execution["prediction_phase_closed_sha256"],
                  "method_limit": "Definitions travel in different trusted fields, the legacy CUSTOMER gloss is removed, and strict capability gating is added; this is not an isolated pure-algorithm gain."}
        save_exclusive(output / "scored_rows.json", scored_rows)
        save(output / "report.json", report)
        execution.update(status="complete", reference_parsed=True)
        return report
    except Exception as exc:
        execution.update(status="stopped", error_type=type(exc).__name__, error_code=str(exc) if str(exc).startswith("probe_") else "probe_execution_error")
        raise
    finally:
        execution.update(completed_opportunities=len(rows), qwen_post_attempts=budget.posts,
                         gliner_infer_invocations=budget.infers, wall_seconds=time.monotonic() - budget.started,
                         network=network)
        save(output / "execution.json", execution)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--freeze", action="store_true")
    mode.add_argument("--execute", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--data-root", type=Path, default=ROOT / "examples/ontology_contract_probe_20261027")
    parser.add_argument("--model-root", type=Path, default=ROOT / ".runtime/github_ner")
    parser.add_argument("--prereg", type=Path, default=ROOT / "docs/共同敏感类别合同_修复与实测预注册_2026-10-27.md")
    parser.add_argument("--expected-plan-sha256")
    args = parser.parse_args()
    if args.freeze:
        result = freeze(args.output, args.data_root, args.model_root, args.prereg)
    else:
        if not args.expected_plan_sha256:
            parser.error("--execute requires --expected-plan-sha256")
        result = execute(args.output, args.expected_plan_sha256)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
