"""Small independent ACL executors, migration baselines, and counted API probes.

The target is a REFERENCE backend written for this experiment. Quotas and fault
injection are controlled experiments, never observations of a vendor product.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import random
import secrets
import socket
import sqlite3
import threading
import time
from collections import defaultdict
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, quote, unquote, urlparse


def digest(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def content_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def validate_records(records: list[dict], subjects: list[str]) -> None:
    if len(subjects) != len(set(subjects)) or not subjects:
        raise ValueError("subjects must be nonempty and unique")
    ids: set[str] = set()
    for record in records:
        if not isinstance(record.get("id"), str) or record["id"] in ids:
            raise ValueError("missing or duplicate record id")
        ids.add(record["id"])
        if not isinstance(record.get("text"), str):
            raise ValueError("record text must be a string")
        acl = record.get("allowed_users")
        if (not isinstance(acl, list) or any(u not in subjects for u in acl)
                or len(acl) != len(set(acl))):
            raise ValueError("missing or unknown controlled ACL")


def default_mapping(subjects: list[str], tenant: str = "target_lab") -> dict[str, str]:
    return {u: f"{tenant}|{u}" for u in subjects}


def validate_mapping(subjects: list[str], mapping: dict[str, str], tenant: str) -> None:
    if set(mapping) != set(subjects):
        raise ValueError("identity mapping must cover exactly the registered subjects")
    values = list(mapping.values())
    if any(not isinstance(v, str) or not v.startswith(tenant + "|")
           or not v.removeprefix(tenant + "|") for v in values):
        raise ValueError("identity mapping contains a missing or foreign-tenant subject")
    if len(values) != len(set(values)):
        raise ValueError("identity mapping collision")


def make_plan(
    records: list[dict], subjects: list[str], method: str,
    max_datasets: int | None = None, mapping: dict[str, str] | None = None,
    tenant: str = "target_lab",
) -> dict:
    """All methods use identical target capabilities and controlled policies.

    selective_groups is deliberately simple: equal-cost groups, additive legal
    read value. Ranking the groups is optimal FOR THIS LIMITED MODEL, not a new
    optimization algorithm. max_datasets is a simulated resource limit.
    """
    validate_records(records, subjects)
    mapping = default_mapping(subjects, tenant) if mapping is None else mapping
    validate_mapping(subjects, mapping, tenant)
    if max_datasets is not None and max_datasets < 0:
        raise ValueError("max_datasets must be nonnegative or None")
    if method not in {"acl_grouping", "per_item_reject", "selective_groups"}:
        raise ValueError("unknown migration method")
    groups: dict[tuple, list[dict]] = defaultdict(list)
    empty_acl: list[str] = []
    for record in records:
        acl = tuple(sorted(set(record["allowed_users"])))
        if acl:
            groups[acl].append(record)
        else:
            empty_acl.append(record["id"])
    keys = list(groups)
    cap = len(keys) if max_datasets is None else max_datasets
    batch_blocked = method == "acl_grouping" and len(keys) > cap
    if batch_blocked:
        chosen: list[tuple] = []
    elif method == "selective_groups":
        chosen = sorted(keys, key=lambda k: (-len(k) * len(groups[k]), k))[:cap]
    else:
        chosen = keys[:cap]
    containers = []
    kept: set[str] = set()
    for acl in chosen:
        objects = groups[acl]
        kept.update(r["id"] for r in objects)
        containers.append({
            "id": "dataset_" + digest(acl)[:16],
            "source_acl": list(acl),
            "members": sorted(mapping[u] for u in acl),
            "record_ids": [r["id"] for r in objects],
        })
    rejected = [
        {"id": r["id"], "reason": "no_legal_readers" if r["id"] in empty_acl
         else "batch_requires_more_datasets" if batch_blocked else "simulated_dataset_limit"}
        for r in records if r["id"] not in kept
    ]
    # No phantom authorization counterexample: a capacity rejection is a resource
    # witness. It is not evidence that the safe source ACL itself is inconsistent.
    state = "exact" if len(kept) == len(records) else "partial" if kept else "blocked"
    return {
        "method": method, "state": state, "containers": containers,
        "retained_ids": sorted(kept), "rejected": rejected,
        "mapping": dict(mapping), "tenant": tenant, "max_datasets": max_datasets,
        "required_acl_groups": len(groups),
        "retained_legal_reads": sum(len(r["allowed_users"]) for r in records if r["id"] in kept),
        "total_legal_reads": sum(len(r["allowed_users"]) for r in records),
        "is_new_algorithm": False,
        "resource_constraint_origin": "none" if max_datasets is None else "synthetic_stress_only",
    }


class ReferenceStore:
    """SQLite backend, with different source-record and target-dataset policies."""

    def __init__(self, db_path: Path, role: str, deployment_id: str,
                 fault: str = "none") -> None:
        if role not in {"source", "target"} or fault not in {"none", "list_acl_bypass"}:
            raise ValueError("unsupported role or fault")
        self.role, self.deployment_id, self.fault = role, deployment_id, fault
        self.lock = threading.RLock()
        self.conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self.conn.executescript("""
            CREATE TABLE records(id TEXT PRIMARY KEY, body TEXT NOT NULL,
                                 container TEXT, published INTEGER NOT NULL);
            CREATE TABLE record_acl(object_id TEXT NOT NULL, subject TEXT NOT NULL,
                                    PRIMARY KEY(object_id, subject));
            CREATE TABLE dataset_acl(container TEXT NOT NULL, subject TEXT NOT NULL,
                                     PRIMARY KEY(container, subject));
        """)
        self.expected_binding: str | None = None
        self.admitted_binding: str | None = None

    def seed_source(self, records: list[dict]) -> None:
        if self.role != "source":
            raise ValueError("source operation on target")
        with self.lock, self.conn:
            for r in records:
                self.conn.execute("INSERT INTO records VALUES(?,?,NULL,1)", (r["id"], r["text"]))
                self.conn.executemany("INSERT INTO record_acl VALUES(?,?)",
                                      [(r["id"], u) for u in set(r["allowed_users"])])

    def stage_target(self, records: list[dict], plan: dict, policy_version: str = "static-v1") -> dict:
        if self.role != "target":
            raise ValueError("target operation on source")
        by_id = {r["id"]: r for r in records}
        manifest = {
            "deployment_id": self.deployment_id, "policy_version": policy_version,
            "mapping": plan["mapping"], "tenant": plan["tenant"],
            "containers": plan["containers"],
            "contents": {i: content_hash(by_id[i]["text"]) for i in plan["retained_ids"]},
        }
        self.expected_binding = digest(manifest)
        with self.lock, self.conn:
            for group in plan["containers"]:
                self.conn.executemany("INSERT INTO dataset_acl VALUES(?,?)",
                                      [(group["id"], u) for u in group["members"]])
                for i in group["record_ids"]:
                    self.conn.execute("INSERT INTO records VALUES(?,?,?,0)",
                                      (i, by_id[i]["text"], group["id"]))
        return manifest

    def publish(self, manifest: dict) -> None:
        # Local binding check only, not a digital signature or proof of the real
        # product's concurrent/transactional publication behavior.
        if self.expected_binding is None or digest(manifest) != self.expected_binding:
            raise ValueError("admission manifest binding mismatch")
        with self.lock, self.conn:
            expected_contents = manifest["contents"]
            rows = self.conn.execute("SELECT id, body, container FROM records").fetchall()
            actual_contents = {i: content_hash(text) for i, text, _ in rows}
            expected_groups = {g["id"]: g for g in manifest["containers"]}
            actual_groups = defaultdict(set)
            for i, _, container in rows:
                actual_groups[container].add(i)
            actual_acl = defaultdict(set)
            for container, subject in self.conn.execute("SELECT container, subject FROM dataset_acl"):
                actual_acl[container].add(subject)
            if actual_contents != expected_contents:
                raise ValueError("staged contents changed after planning")
            if set(actual_acl) != set(expected_groups) or set(actual_groups) != set(expected_groups):
                raise ValueError("staged container set changed")
            for container, g in expected_groups.items():
                if actual_groups[container] != set(g["record_ids"]) or actual_acl[container] != set(g["members"]):
                    raise ValueError("staged permissions changed after planning")
            self.conn.execute("UPDATE records SET published=1")
            self.admitted_binding = self.expected_binding

    def read(self, subject: str, memory_id: str) -> tuple[int, dict]:
        with self.lock:
            if self.role == "source":
                row = self.conn.execute("""SELECT r.id,r.body FROM records r
                    JOIN record_acl a ON a.object_id=r.id
                    WHERE r.id=? AND a.subject=? AND r.published=1""", (memory_id, subject)).fetchone()
            else:
                row = self.conn.execute("""SELECT r.id,r.body FROM records r
                    JOIN dataset_acl a ON a.container=r.container
                    WHERE r.id=? AND a.subject=? AND r.published=1""", (memory_id, subject)).fetchone()
            return (200, {"id": row[0], "text": row[1]}) if row else (404, {"error": "not_found_or_not_allowed"})

    def list_records(self, subject: str) -> tuple[int, dict]:
        with self.lock:
            if self.role == "source":
                rows = self.conn.execute("""SELECT r.id,r.body FROM records r
                    JOIN record_acl a ON a.object_id=r.id
                    WHERE a.subject=? AND r.published=1 ORDER BY r.id""", (subject,)).fetchall()
            elif self.fault == "list_acl_bypass":
                # Deliberate local negative-control fault; NEVER a vendor finding.
                rows = self.conn.execute("SELECT id,body FROM records WHERE published=1 ORDER BY id").fetchall()
            else:
                rows = self.conn.execute("""SELECT r.id,r.body FROM records r
                    JOIN dataset_acl a ON a.container=r.container
                    WHERE a.subject=? AND r.published=1 ORDER BY r.id""", (subject,)).fetchall()
            return 200, {"items": [{"id": i, "text": text} for i, text in rows]}

    def close(self) -> None:
        self.conn.close()


class LocalAPI:
    """Loopback-only HTTP; tokens bind identities, query strings cannot do so."""

    def __init__(self, store: ReferenceStore, subjects: list[str]) -> None:
        self.store = store
        self.tokens = {s: secrets.token_urlsafe(24) for s in subjects}
        token_subjects = {token: subject for subject, token in self.tokens.items()}

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def setup(inner):
                super().setup()
                inner.connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

            def log_message(inner, *_args):
                pass

            def do_GET(inner):
                auth = inner.headers.get("Authorization", "")
                subject = token_subjects.get(auth.removeprefix("Bearer ")) if auth.startswith("Bearer ") else None
                if subject is None:
                    status, data = 401, {"error": "invalid_credentials"}
                else:
                    parsed = urlparse(inner.path)
                    # Identity is solely token-bound. Refuse, rather than trust,
                    # user/tenant/actor overrides in query parameters.
                    if set(parse_qs(parsed.query)) & {"user", "user_id", "actor", "tenant"}:
                        status, data = 400, {"error": "identity_override_not_supported"}
                    elif parsed.path == "/memories":
                        status, data = store.list_records(subject)
                    elif parsed.path.startswith("/memories/"):
                        status, data = store.read(subject, unquote(parsed.path[len("/memories/"):]))
                    else:
                        status, data = 404, {"error": "unknown_route"}
                raw = json.dumps(data, ensure_ascii=False).encode("utf-8")
                inner.send_response(status)
                inner.send_header("Content-Type", "application/json; charset=utf-8")
                inner.send_header("Content-Length", str(len(raw)))
                inner.send_header("Cache-Control", "no-store")
                inner.end_headers()
                inner.wfile.write(raw)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
        self.calls = 0

    def request(self, subject: str, operation: str, memory_id: str = "") -> tuple[int, dict]:
        if operation not in {"read", "list"}:
            raise ValueError("only read/list are implemented; search/context are unsupported")
        path = "/memories" if operation == "list" else "/memories/" + quote(memory_id, safe="")
        return self.raw_request(path, self.tokens.get(subject, "unknown-token"))

    def raw_request(self, path: str, token: str | None) -> tuple[int, dict]:
        self.calls += 1
        headers = {"Authorization": "Bearer " + token} if token else {}
        try:
            self.connection.request("GET", path, headers=headers)
            response = self.connection.getresponse()
            raw = response.read()
            return response.status, json.loads(raw)
        except (OSError, http.client.HTTPException, ValueError) as exc:
            self.connection.close()
            return 599, {"error": type(exc).__name__}

    def close(self) -> None:
        self.connection.close()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()


@dataclass(frozen=True)
class Probe:
    user: str
    operation: str
    memory_id: str = ""

    def as_dict(self) -> dict:
        return {"user": self.user, "operation": self.operation, "memory_id": self.memory_id}


def candidate_probes(subjects: list[str], records: list[dict]) -> list[Probe]:
    return [p for u in subjects for p in
            ([Probe(u, "read", r["id"]) for r in records] + [Probe(u, "list")])]


def observe(api: LocalAPI, probe: Probe, target_user: str, records: list[dict],
            source_truth: dict[tuple[str, str], bool]) -> dict:
    status, response = api.request(target_user, probe.operation, probe.memory_id)
    violations, content_errors = [], []
    expected_hashes = {r["id"]: content_hash(r["text"]) for r in records}
    if probe.operation == "read":
        items = [response] if status == 200 else []
        known = status in {200, 404}
        checked = [probe.memory_id] if known else []
        if status == 200 and response.get("id") != probe.memory_id:
            content_errors.append(probe.memory_id)
    else:
        items = response.get("items", []) if status == 200 else []
        known = status == 200 and isinstance(items, list)
        checked = list(expected_hashes) if known else []
    returned_ids = []
    for item in items:
        if not isinstance(item, dict) or not isinstance(item.get("id"), str):
            known = False
            continue
        i = item["id"]
        returned_ids.append(i)
        if not source_truth.get((probe.user, i), False):
            violations.append({"user": probe.user, "memory_id": i, "operation": probe.operation,
                               "kind": "unauthorized_disclosure"})
        if i not in expected_hashes or not isinstance(item.get("text"), str) or content_hash(item["text"]) != expected_hashes.get(i):
            content_errors.append(i)
    return {**probe.as_dict(), "http_status": status, "known": known,
            "checked_ids": checked, "returned_ids": returned_ids,
            "unexpected_ids": sorted(set(returned_ids) - set(expected_hashes)),
            "violations": violations, "content_errors": content_errors}


def collect_source_truth(api: LocalAPI, subjects: list[str], records: list[dict]) -> tuple[dict, list[dict]]:
    truth, evidence = {}, []
    declared = {r["id"]: set(r["allowed_users"]) for r in records}
    for user in subjects:
        visible = set()
        for record in records:
            status, response = api.request(user, "read", record["id"])
            if status not in {200, 404}:
                raise RuntimeError(f"source read indeterminate: {status}")
            allowed = status == 200
            if allowed != (user in declared[record["id"]]):
                raise RuntimeError("source execution disagrees with controlled policy")
            if allowed and (response.get("id") != record["id"] or
                            content_hash(response.get("text", "")) != content_hash(record["text"])):
                raise RuntimeError("source content mismatch")
            truth[(user, record["id"])] = allowed
            if allowed:
                visible.add(record["id"])
        status, response = api.request(user, "list")
        if status != 200 or {r["id"] for r in response.get("items", [])} != visible:
            raise RuntimeError("source list does not match source read policy")
        evidence.append({"user": user, "allowed_object_count": len(visible), "list_matches_reads": True})
    return truth, evidence


def run_full_audit(api: LocalAPI, subjects: list[str], records: list[dict], mapping: dict,
                   truth: dict) -> dict:
    observations = [observe(api, p, mapping[p.user], records, truth)
                    for p in candidate_probes(subjects, records)]
    legal = unauthorized = legal_ok = disclosures = content_bad = unknown = 0
    examples = []
    for observation in observations:
        if not observation["known"]:
            unknown += 1
            continue
        returned = set(observation["returned_ids"])
        for i in observation["checked_ids"]:
            if truth[(observation["user"], i)]:
                legal += 1
                if i in returned and i not in observation["content_errors"]:
                    legal_ok += 1
            else:
                unauthorized += 1
                if i in returned:
                    disclosures += 1
        content_bad += len(observation["content_errors"])
        examples.extend(observation["violations"])
    total_objects = len(records)
    total_legal = sum(bool(v) for v in truth.values()) * 2
    total_unauthorized = len(subjects) * len(records) * 2 - total_legal
    return {
        "api_calls": len(observations), "known_legal_cells": legal,
        "total_legal_cells": total_legal, "total_unauthorized_cells": total_unauthorized,
        "known_unauthorized_cells": unauthorized, "legal_reads_preserved": legal_ok,
        "legal_access_retention": legal_ok / total_legal if total_legal and not unknown else None,
        "unauthorized_disclosures": disclosures,
        "unexpected_id_disclosures": sum(len(o["unexpected_ids"]) for o in observations),
        "unauthorized_disclosure_rate": disclosures / total_unauthorized if total_unauthorized and not unknown else None,
        "content_errors": content_bad, "indeterminate_requests": unknown,
        "status": "counterexample_found" if examples else "unknown" if unknown else "no_counterexample_in_finite_domain",
        "counterexamples": examples[:30], "observations": observations,
        "registered_object_count": total_objects,
        "scope": "finite_local_reference_read_and_list_only",
    }


def probe_features(probe: Probe, records_by_id: dict) -> set[tuple]:
    # Pure public control-plane features, not test answers or fault information.
    if probe.operation == "list":
        return {("operation", "list"), ("user_operation", probe.user, "list")}
    acl = tuple(sorted(records_by_id[probe.memory_id]["allowed_users"]))
    return {("operation", "read"), ("acl", acl),
            ("decision", probe.user in acl), ("user_operation", probe.user, "read")}


def select_probe(pending: list[Probe], strategy: str, records_by_id: dict,
                 observed_features: set, history: list[dict]) -> Probe:
    if strategy in {"fixed", "random", "read_only", "enumerate"}:
        return pending[0]
    if strategy not in {"rule_coverage", "migration_relation"}:
        raise ValueError("unknown probe strategy")
    seen_operations = {h["operation"] for h in history}

    def score(p: Probe) -> int:
        gain = len(probe_features(p, records_by_id) - observed_features)
        if strategy == "rule_coverage":
            return gain
        # Unproven heuristic: explicitly sample each interface, then prioritize
        # denied/shared migration relationships. It never reads fault config or
        # the full-audit oracle. Equality with simple baselines is an honest result.
        novelty = 5 if p.operation not in seen_operations else 0
        if p.operation == "read":
            acl = records_by_id[p.memory_id]["allowed_users"]
            boundary = 2 if p.user not in acl else 1 if len(acl) > 1 else 0
        else:
            boundary = 0
        return gain + novelty + boundary

    return max(pending, key=score)


def run_budget_audit(api: LocalAPI, subjects: list[str], records: list[dict], mapping: dict,
                     truth: dict, strategy: str, budget: int, seed: int = 42) -> dict:
    if budget < 0:
        raise ValueError("budget must be nonnegative")
    all_probes = candidate_probes(subjects, records)
    pending = [p for p in all_probes if strategy != "read_only" or p.operation == "read"]
    if strategy == "random":
        random.Random(seed).shuffle(pending)
    history: list[dict] = []
    features: set = set()
    records_by_id = {r["id"]: r for r in records}
    first = None
    violations = []
    started = time.perf_counter()
    for _ in range(min(budget, len(pending))):
        selection_history = [{k: h[k] for k in ("operation", "http_status", "returned_ids")}
                             for h in history]
        probe = select_probe(pending, strategy, records_by_id, features, selection_history)
        pending.remove(probe)
        observation = observe(api, probe, mapping[probe.user], records, truth)
        history.append(observation)
        features.update(probe_features(probe, records_by_id))
        if observation["violations"]:
            first = len(history) if first is None else first
            violations.extend(observation["violations"])
    coverage = {(h["user"], i, h["operation"])
                for h in history if h["known"] for i in h["checked_ids"]}
    all_cells = len(subjects) * len(records) * 2
    untested = len(all_probes) - len(history)
    status = "counterexample_found" if violations else (
        "no_counterexample_in_finite_domain" if untested == 0 and all(h["known"] for h in history)
        else "unknown")
    return {
        "strategy": strategy, "budget": budget, "actual_api_calls": len(history),
        "candidate_requests": len(all_probes), "untested_requests": untested,
        "indeterminate_requests": sum(not h["known"] for h in history),
        "covered_cells": len(coverage), "total_cells": all_cells,
        "unknown_cell_fraction": (all_cells - len(coverage)) / all_cells if all_cells else None,
        "first_counterexample_cost": first, "counterexamples": violations[:30],
        "status": status, "elapsed_seconds": time.perf_counter() - started,
        "history": history, "selector_reads_hidden_fault_or_oracle": False,
    }
