"""Zero-model falsification probe: complete facts + ordinary dependency cache.

This is a host-declared structured mechanism ceiling, not learned provenance,
native interoperability, end-to-end QA, or a proposed novel algorithm. Baselines
get identical complete atom/AND-OR structure. It intentionally does not compare
against a weak any-source or value-only lookup. Existing defaults stay intact.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import secrets
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from memory_migration_study.memory_labels import MemoryLabelAuthority, prepare_labeled_transfer, restore_labeled_answer
from memory_migration_study.privacy import _TOKEN, _digest
from memory_migration_study.request_projection import project_fact_cards, resolve_fact_card_answer
from memory_migration_study.source_fact_cards import build_source_fact_cards
from scripts.run_transfer_lifecycle_witness import run_witness

VERSION = "complete_fact_ordinary_cache_falsification_v1"
POLICY = {"version": "complete-fact-controlled-v1", "protected_categories": ["CUSTOMER", "AMOUNT"]}
SOURCES = {
    "S1": "Project Alpha | Customer: Cedar Collective | Budget: 260000 USD | Version: approved",
    "S2": "Project Alpha | Customer: Cedar Collective | Version: current",
    "S3": "Project Alpha | Budget: 260000 USD | Version: approved",
    "S4": "Project Alpha | Budget: 260000 USD | Version: forecast",
    "S5": "Project Beta | Budget: 260000 USD | Version: approved",
    "S6": "Project Alpha | Carrier: Cedar Collective | Version: current",
    "S7": "Project Alpha | Contract status: approved | Calculation reference: A1",
    "S8": "Project Alpha | Budget: 260000 USD | Calculation reference: A1",
    "S9": "Project Alpha | Customer: Cedar Collective | Copy of S1",
    "S10": "Project Alpha | Budget: 260000 USD | Version: approved | Negated: true",
}
# Keys retain subject, relation, value, version and negation. Values alone do not
# establish a relationship. Source structure is declared before events/queries.
ATOMS = {
    "customer_alpha": ("Alpha", "customer", "Cedar Collective", "current", False),
    "budget_alpha_approved": ("Alpha", "budget", "260000 USD", "approved", False),
    "budget_alpha_forecast": ("Alpha", "budget", "260000 USD", "forecast", False),
    "budget_beta_approved": ("Beta", "budget", "260000 USD", "approved", False),
    "carrier_alpha": ("Alpha", "carrier", "Cedar Collective", "current", False),
    "customer_alpha_copy_only": ("Alpha", "customer_copy_view", "Cedar Collective", "current", False),
    "budget_alpha_negated": ("Alpha", "budget", "260000 USD", "approved", True),
}
# AND within tuples, OR between tuples; copy retains its original root.
SUPPORT = {
    "customer_alpha": (("S1",), ("S2",), ("S1", "S9")),
    "budget_alpha_approved": (("S1",), ("S3",), ("S7", "S8")),
    "budget_alpha_forecast": (("S4",),),
    "budget_beta_approved": (("S5",),),
    "carrier_alpha": (("S6",),),
    "customer_alpha_copy_only": (("S1", "S9"),),
    "budget_alpha_negated": (("S10",),),
}


class Host:
    def __init__(self):
        self.authority = MemoryLabelAuthority(secrets.token_bytes(32))
        self.records, self.routes, self.versions = {}, {}, {}
        self.policy = deepcopy(POLICY)
        self.checks = 0
        for alias, text in SOURCES.items():
            findings = []
            for value, category in (("Cedar Collective", "CUSTOMER"), ("260000 USD", "AMOUNT")):
                if value in text:
                    a = text.index(value); findings.append({"start": a, "end": a + len(value), "category": category})
            self.records[alias] = self.authority.build_record({"source_id": alias, "text": text},
                {"text": text, "source_start": 0, "source_end": len(text), "findings": findings}, self.policy,
                owner_id="owner", readers=["owner"], agent_id="source-agent", allowed_agent_ids=["target-agent"],
                builder_version="manual_complete_fact_fixture_v1", detector_version="manual_labels_v1")
            self.routes[alias] = {"grant-a", "grant-b"} if alias == "S2" else {"grant-a"}
            self.versions[alias] = 0
        self.by_id = {record["record_id"]: alias for alias, record in self.records.items()}

    def authorizer(self, rid, actor, version):
        return actor == "owner" and version == self.policy["version"] and bool(self.routes[self.by_id[rid]])

    def allowed(self, alias):
        self.checks += 1
        return self.authority.validate_access(self.records[alias], actor_id="owner", agent_id="target-agent",
            authorizer=self.authorizer, policy_version=self.policy["version"]) is None

    def apply(self, event):
        kind, alias, *rest = event
        if kind == "source":
            self.authority.revoke_source(alias)
        elif kind == "grant":
            self.routes[alias].discard(rest[0])
        else:
            raise ValueError("unknown_event")
        self.versions[alias] += 1


def complete_recompute(host, atom_id, request_memo):
    """Full fact key, complete clauses, current auth; reuse checks per request."""
    for clause in sorted(SUPPORT[atom_id], key=lambda c: (len(c), c)):
        legal = True
        for alias in clause:
            if alias not in request_memo:
                request_memo[alias] = host.allowed(alias)
            legal = legal and request_memo[alias]
        if legal:
            return clause
    return None


class OrdinaryFactCache:
    """Ordinary memoization of complete dependency fingerprints, never a grant.

    Version counters are supplied by this trusted synthetic host. A baseline
    without reliable change notification must recheck current dependencies.
    Selected sources are independently rechecked before any delivery below.
    """
    def __init__(self):
        self.entries, self.hits, self.misses = {}, 0, 0

    def evaluate(self, host, atom_id, request_memo):
        dependencies = sorted({s for clause in SUPPORT[atom_id] for s in clause})
        key = (ATOMS[atom_id], SUPPORT[atom_id], _digest(host.policy), "owner", "target-agent",
            tuple((s, host.versions[s], _digest(host.records[s])) for s in dependencies))
        if key in self.entries:
            self.hits += 1
            return self.entries[key]
        self.misses += 1
        self.entries[key] = complete_recompute(host, atom_id, request_memo)
        return self.entries[key]


def current_delivery(host, witness):
    # Cached structure cannot bypass a current authorization decision.
    return witness is None or all(host.allowed(source) for source in witness)


def same_value_source_card_probe():
    host = Host()
    records = [host.records["S2"], host.records["S6"]]
    scope = dict(authority=host.authority, actor_id="owner", agent_id="target-agent", authorizer=host.authorizer)
    source = build_source_fact_cards(records, host.policy, **scope)
    prepared = prepare_labeled_transfer(records, "", host.policy, request_id="same-value-old", mode="generation", **scope)
    projected = project_fact_cards(source["source_table"], prepared, records, host.policy, request_id="same-value-old", **scope)
    if projected["status"] != "ok":
        raise AssertionError("source_card_qualification_failed")
    cards = projected["views"]["source"]["fact_cards"]
    customer = next(c for c in cards if c["role"] == "customer")
    same_token = len({c["value"] for c in cards}) == 1 and bool(_TOKEN.fullmatch(customer["value"]))
    host.apply(("source", "S6"))
    old = resolve_fact_card_answer(json.dumps({"card_id": customer["card_id"]}), projected["table"],
        prepared, records, host.policy, request_id="same-value-old", **scope)
    old_restore = restore_labeled_answer(customer["value"], prepared, records, host.policy, request_id="same-value-old", **scope)
    # Standard fresh recomputation selects the still-authorized original S2.
    current = [record for record in records if host.authority.validate_access(record, actor_id="owner",
        agent_id="target-agent", authorizer=host.authorizer, policy_version=host.policy["version"]) is None]
    fresh = prepare_labeled_transfer(current, "", host.policy, request_id="same-value-fresh", mode="generation", **scope)
    token = _TOKEN.search(fresh["payload"]["memories"][0]["text"]).group()
    restored = restore_labeled_answer(token, fresh, current, host.policy, request_id="same-value-fresh", **scope)
    return {"different_roles": sorted(c["role"] for c in cards), "one_value_token_for_two_relationships": same_token,
        "old_card_status": old["status"], "old_card_error": old["error"],
        "old_restore_status": old_restore["status"], "old_restore_error": old_restore["error"],
        "standard_fresh_existing_source_restores": restored["status"] == "ok" and restored["answer"] == "Cedar Collective",
        "mapping_cropped_or_reused": False, "model_calls": 0}


def unrelated_source_card_probe():
    host = Host(); records = [host.records["S2"]]
    scope = dict(authority=host.authority, actor_id="owner", agent_id="target-agent", authorizer=host.authorizer)
    source = build_source_fact_cards(records, host.policy, **scope)
    prepared = prepare_labeled_transfer(records, "", host.policy, request_id="unrelated-event", mode="generation", **scope)
    projected = project_fact_cards(source["source_table"], prepared, records, host.policy, request_id="unrelated-event", **scope)
    card = projected["views"]["source"]["fact_cards"][0]
    host.apply(("source", "S4"))  # No S4 record or value occurs in this request.
    old = resolve_fact_card_answer(json.dumps({"card_id": card["card_id"]}), projected["table"],
        prepared, records, host.policy, request_id="unrelated-event", **scope)
    original = restore_labeled_answer(card["value"], prepared, records, host.policy, request_id="unrelated-event", **scope)
    rebuilt = build_source_fact_cards(records, host.policy, **scope)
    fresh_projection = project_fact_cards(rebuilt["source_table"], prepared, records, host.policy,
        request_id="unrelated-event", **scope)
    return {"request_records_still_authorized": host.allowed("S2"), "unrelated_source_changed": "S4",
        "old_card_status": old["status"], "old_card_error": old["error"],
        "original_complete_restore_still_succeeds": original["status"] == "ok" and original["answer"] == "Cedar Collective",
        "normal_current_card_rebuild_succeeds": fresh_projection["status"] == "ok", "model_calls": 0}


def run_probe():
    host, cache = Host(), OrdinaryFactCache()
    phases = [
        ("initial", None, set(ATOMS)),
        ("one_auth_path_revoked", ("grant", "S2", "grant-a"), set(ATOMS)),
        ("compound_source_revoked", ("source", "S1"), set(ATOMS) - {"customer_alpha_copy_only"}),
        ("direct_budget_alternative_revoked", ("source", "S3"), set(ATOMS) - {"customer_alpha_copy_only"}),
        ("AND_member_revoked", ("source", "S7"), set(ATOMS) - {"customer_alpha_copy_only", "budget_alpha_approved"}),
        ("second_customer_auth_path_revoked", ("grant", "S2", "grant-b"), {"budget_alpha_forecast", "budget_beta_approved", "carrier_alpha", "budget_alpha_negated"}),
        ("other_project_budget_revoked", ("source", "S5"), {"budget_alpha_forecast", "carrier_alpha", "budget_alpha_negated"}),
    ]
    rows = []
    for name, event, expected in phases:
        if event:
            host.apply(event)
        for repeat in (0, 1):
            full_memo, cached_memo = {}, {}
            for atom_id in ATOMS:
                before = host.checks; full = complete_recompute(host, atom_id, full_memo); full_checks = host.checks - before
                before = host.checks; reused = cache.evaluate(host, atom_id, cached_memo); cached_checks = host.checks - before
                delivered = current_delivery(host, full) and current_delivery(host, reused)
                expected_legal = atom_id in expected
                rows.append({"phase": name, "repeat": repeat, "atom_id": atom_id, "expected_available": expected_legal,
                    "complete_recompute_available": full is not None, "ordinary_cache_available": reused is not None,
                    "witnesses_identical": full == reused, "current_delivery_checks_pass": delivered,
                    "pure_evaluation_full_current_checks": full_checks, "pure_evaluation_cache_current_checks": cached_checks,
                    "passed": (full is not None) == expected_legal and (reused is not None) == expected_legal and full == reused and delivered})
    old = run_witness()
    card = same_value_source_card_probe(); unrelated = unrelated_source_card_probe()
    passed = all(row["passed"] for row in rows) and old["all_checks_passed"] and card["old_card_status"] == "blocked" and card["old_restore_status"] == "blocked" and card["standard_fresh_existing_source_restores"] and unrelated["old_card_status"] == "blocked" and unrelated["original_complete_restore_still_succeeds"] and unrelated["normal_current_card_rebuild_succeeds"]
    return {"version": VERSION, "status": "passed" if passed else "failed", "scope": "Host-declared complete structured support; zero-model mechanism ceiling, not semantic extraction or task accuracy.",
        "atoms": len(ATOMS), "state_phases": len(phases), "repeated_requests": 2, "rows": rows,
        "all_baselines_equal_manual_reference": all(row["passed"] for row in rows),
        "ordinary_cache": {"hits": cache.hits, "misses": cache.misses, "cached_authorization_bypasses_delivery": False,
            "trusted_version_notification_assumed": True, "timing_or_cost_advantage_claimed": False},
        "existing_independent_grant_witness": {"all_checks_passed": old["all_checks_passed"], "checks": len(old["checks"]), "scope": old["scope"]},
        "source_card_granularity": card, "unrelated_source_card_invalidation": unrelated,
        "model_calls": 0, "native_client_calls": 0, "fresh64_read": False,
        "novel_algorithm_advantage_established": False,
        "negative_conclusion": "With complete correct atom/support inputs, standard full-fact recomputation and ordinary dependency-scoped caching handle every registered case. Current old-context overblocking does not defeat that baseline.",
        "limitations": ["All source independence, semantic atom keys and AND/OR support clauses are manually declared, not discovered.",
            "Synthetic authorization callbacks and versions are local trusted-host instruments, not native or distributed current-state guarantees.",
            "No natural-language extraction, paid/model answer, actual latency benchmark or paper novelty test."]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    target = args.output.resolve()
    if target.exists() or not target.is_relative_to(ROOT / "results"):
        raise ValueError("new_project_results_file_required")
    report = run_probe()
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2, allow_nan=False); stream.write("\n")
    print(json.dumps({"status": report["status"], "rows": len(report["rows"]), "model_calls": 0,
        "novel_algorithm_advantage_established": False, "report_sha256": hashlib.sha256(target.read_bytes()).hexdigest()}))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
