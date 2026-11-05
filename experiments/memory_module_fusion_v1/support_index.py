"""Exact evidence support, positive AND/OR provenance, and permission deltas.

Only independently registered source slices are leaves. Rules are caller-verified
deterministic implications; their head names are never emitted as memory text.
Multiple rules are OR alternatives and a rule's body is AND. This module cannot
relabel or authorize an existing free-form/LLM artifact.

Offsets count Python Unicode characters, not UTF-8 bytes. A leaf binds the full
source hash, source version, offsets, exact quote and quote hash. Revocation
clears the affected dependency cone before computing its grounded least fixed
point; a cycle without a surviving source witness cannot support itself.

This is a small independent implementation of classical positive provenance
and delete/rederive ideas, not copied ProbLog/Prolog code. Minimal proof sets can
be exponential; the full and acyclic-counting baselines make that cost visible.
"""

from __future__ import annotations

import hashlib
import itertools
import json
import sqlite3
import time
from collections import defaultdict, deque
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class SourceBindingError(ValueError):
    """A source, grant, or exact slice does not match its registered binding."""


class UnsupportedFactError(ValueError):
    """No currently authorized, grounded proof exists for a requested fact."""


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _id(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("IDs must be nonempty strings")
    return value


@dataclass(frozen=True)
class _Source:
    source_id: str
    text: str
    version: str  # Canonical JSON preserves the caller's version type.
    sha256: str


class SupportIndex:
    """SQLite-backed exact witnesses and positive Horn support rules.

    New indexes default to deny-all. A reopened database preserves its grants;
    passing initially_allowed explicitly replaces them. Sources are immutable
    snapshots: use update_source() to install a new version, which revokes its
    old grant and does not silently rebind old spans.
    """

    def __init__(self, sources: Iterable[dict] | Mapping, derivations=None, *,
                 db_path: str | Path = ":memory:", initially_allowed=None):
        self.connection = sqlite3.connect(str(db_path))
        self.connection.row_factory = sqlite3.Row
        try:
            self._initialize(sources, derivations, initially_allowed)
        except BaseException:
            self.connection.close()
            raise

    def _initialize(self, sources, derivations, initially_allowed):
        self.connection.execute("PRAGMA foreign_keys=ON")
        self.connection.executescript("""
            CREATE TABLE IF NOT EXISTS support_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS support_sources(
                source_id TEXT PRIMARY KEY, text TEXT NOT NULL,
                version TEXT NOT NULL, sha256 TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS support_facts(
                fact_id TEXT PRIMARY KEY, canonical_quote TEXT);
            CREATE TABLE IF NOT EXISTS support_spans(
                span_id TEXT PRIMARY KEY, fact_id TEXT NOT NULL,
                source_id TEXT NOT NULL, source_version TEXT NOT NULL,
                source_sha256 TEXT NOT NULL, start INTEGER NOT NULL,
                end INTEGER NOT NULL, quote TEXT NOT NULL, quote_sha256 TEXT NOT NULL,
                FOREIGN KEY(fact_id) REFERENCES support_facts(fact_id),
                FOREIGN KEY(source_id) REFERENCES support_sources(source_id));
            CREATE INDEX IF NOT EXISTS support_spans_source ON support_spans(source_id);
            CREATE TABLE IF NOT EXISTS support_rules(rule_id TEXT PRIMARY KEY, head TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS support_body(
                rule_id TEXT NOT NULL, position INTEGER NOT NULL, fact_id TEXT NOT NULL,
                PRIMARY KEY(rule_id, position),
                FOREIGN KEY(rule_id) REFERENCES support_rules(rule_id),
                FOREIGN KEY(fact_id) REFERENCES support_facts(fact_id));
            CREATE INDEX IF NOT EXISTS support_reverse_body ON support_body(fact_id);
            CREATE TABLE IF NOT EXISTS support_grants(
                source_id TEXT PRIMARY KEY, version TEXT NOT NULL, sha256 TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS support_proofs(
                fact_id TEXT NOT NULL, span_ids TEXT NOT NULL,
                PRIMARY KEY(fact_id, span_ids));
        """)
        self.connection.execute(
            "INSERT OR IGNORE INTO support_meta VALUES('epoch','0')")
        self.connection.execute(
            "INSERT OR IGNORE INTO support_meta VALUES('policy_bound','0')")
        self.connection.commit()
        self.last_stats = {}
        self._load()
        records = self._source_records(sources)
        with self.connection:
            for record in records:
                previous = self._sources.get(record.source_id)
                if previous is not None and previous != record:
                    raise SourceBindingError("Stored source differs; call update_source explicitly")
                self.connection.execute("INSERT OR IGNORE INTO support_sources VALUES(?,?,?,?)",
                    (record.source_id, record.text, record.version, record.sha256))
        self._load()
        # Reconstruct from facts/grants rather than trusting persisted proof caches.
        self._refresh(set(self._facts), algorithm="initial_full")
        if derivations:
            for rule in derivations:
                self.add_rule(rule["head"], rule["body"], rule_id=rule.get("rule_id", rule.get("id")))
        if initially_allowed is not None:
            self.set_allowed(initially_allowed)

    @staticmethod
    def _source_records(sources):
        records = []
        if isinstance(sources, Mapping):
            if "text" in sources and any(key in sources for key in ("id", "source_id", "ID")):
                sources = [sources]
            else:
                sources = [dict(value, source_id=key) if isinstance(value, Mapping)
                           else {"source_id": key, "text": value} for key, value in sources.items()]
        seen = set()
        for value in sources:
            source_id = _id(value.get("source_id", value.get("id", value.get("ID"))))
            if source_id in seen:
                raise ValueError("Duplicate source ID")
            seen.add(source_id)
            text = value["text"]
            if not isinstance(text, str):
                raise ValueError("Source text must be a string")
            digest = _sha(text)
            expected = value.get("source_sha256", value.get("sha256"))
            if expected is not None and expected != digest:
                raise SourceBindingError("Source SHA-256 mismatch")
            records.append(_Source(source_id, text, _json(value.get("version", 1)), digest))
        return records

    def _load(self):
        self.epoch = int(self.connection.execute(
            "SELECT value FROM support_meta WHERE key='epoch'").fetchone()[0])
        self._policy_bound = self.connection.execute(
            "SELECT value FROM support_meta WHERE key='policy_bound'").fetchone()[0] == "1"
        self._sources = {row["source_id"]: _Source(**dict(row)) for row in
                         self.connection.execute("SELECT * FROM support_sources")}
        if any(_sha(source.text) != source.sha256 for source in self._sources.values()):
            raise SourceBindingError("Stored source text does not match its SHA-256 binding")
        self._facts = {row["fact_id"]: row["canonical_quote"] for row in
                       self.connection.execute("SELECT * FROM support_facts")}
        self._spans = {row["span_id"]: dict(row) for row in
                       self.connection.execute("SELECT * FROM support_spans")}
        self._spans_by_fact = defaultdict(set)
        self._source_facts = defaultdict(set)
        for span_id, span in self._spans.items():
            self._spans_by_fact[span["fact_id"]].add(span_id)
            self._source_facts[span["source_id"]].add(span["fact_id"])
        self._rules = {}
        self._reverse = defaultdict(set)
        self._rules_by_head = defaultdict(set)
        for row in self.connection.execute("SELECT * FROM support_rules ORDER BY rule_id"):
            body = tuple(item[0] for item in self.connection.execute(
                "SELECT fact_id FROM support_body WHERE rule_id=? ORDER BY position", (row["rule_id"],)))
            self._rules[row["rule_id"]] = (row["head"], body)
            self._rules_by_head[row["head"]].add(row["rule_id"])
            for fact in body:
                self._reverse[fact].add(row["head"])
        self._allowed = {row["source_id"]: (row["version"], row["sha256"]) for row in
                         self.connection.execute("SELECT * FROM support_grants")}
        self._proofs = {fact: set() for fact in self._facts}
        for row in self.connection.execute("SELECT * FROM support_proofs"):
            self._proofs.setdefault(row["fact_id"], set()).add(frozenset(json.loads(row["span_ids"])))

    @property
    def allowed_source_ids(self):
        return set(self._allowed)

    def _ensure_fact(self, fact_id):
        _id(fact_id)
        self.connection.execute("INSERT OR IGNORE INTO support_facts(fact_id) VALUES(?)", (fact_id,))

    def register_exact_span(self, source_id, start, end, fact_id=None, *, expected_quote=None):
        """Register a verified literal slice, never a paraphrase or model answer.

        Reusing a fact ID for source alternatives requires the identical quote.
        Different wording must use separate leaf IDs and an explicitly verified
        deterministic rule. An optional expected_quote is checked exactly.
        """
        source = self._sources[_id(source_id)]
        if (type(start) is not int or type(end) is not int or
                not 0 <= start < end <= len(source.text)):
            raise SourceBindingError("Invalid nonempty character offsets")
        quote = source.text[start:end]
        if expected_quote is not None and quote != expected_quote:
            raise SourceBindingError("Expected quote is not the exact source slice")
        identity = [source_id, source.version, source.sha256, start, end]
        fact_id = _id(fact_id) if fact_id is not None else "span:" + _sha(_json(identity))
        previous = self._facts.get(fact_id)
        if previous is not None and previous != quote:
            raise SourceBindingError("Alternative leaves for one fact must have identical quotes")
        span_id = "witness:" + _sha(_json([fact_id] + identity))
        if span_id in self._spans:
            return fact_id
        with self.connection:
            self._ensure_fact(fact_id)
            self.connection.execute("UPDATE support_facts SET canonical_quote=? WHERE fact_id=?",
                                    (quote, fact_id))
            self.connection.execute("INSERT INTO support_spans VALUES(?,?,?,?,?,?,?,?,?)",
                (span_id, fact_id, source_id, source.version, source.sha256,
                 start, end, quote, _sha(quote)))
        self._load()
        self._refresh(self._dirty_cone({fact_id}), algorithm="incremental_register")
        return fact_id

    def add_rule(self, head, body, rule_id=None):
        """Add a caller-verified deterministic implication; body is nonempty AND.

        This records support only. No head string is rendered and no arbitrary
        previously generated artifact can be attached to a rule.
        """
        head = _id(head)
        if isinstance(body, str):
            raise ValueError("body must be an iterable of fact IDs, not one string")
        body = tuple(sorted({_id(fact) for fact in body}))
        if not body:
            raise ValueError("Source-free rules are forbidden")
        rule_id = _id(rule_id) if rule_id is not None else "rule:" + _sha(_json([head, body]))
        if rule_id in self._rules:
            if self._rules[rule_id] != (head, body):
                raise ValueError("Rule ID already has a different implication")
            return rule_id
        with self.connection:
            for fact in (head,) + body:
                self._ensure_fact(fact)
            self.connection.execute("INSERT INTO support_rules VALUES(?,?)", (rule_id, head))
            self.connection.executemany("INSERT INTO support_body VALUES(?,?,?)",
                ((rule_id, position, fact) for position, fact in enumerate(body)))
        self._load()
        self._refresh(self._dirty_cone({head}), algorithm="incremental_rule")
        return rule_id

    def set_allowed(self, ids, epoch=None, *, versions=None):
        """Replace the current source grant set, binding grants to current versions.

        Epochs are monotone integers. Reusing one epoch for a different grant set
        is rejected; omitting epoch increments it automatically. versions, when
        supplied, independently verifies the caller's expected source versions.
        """
        started = time.perf_counter()
        if isinstance(ids, str):
            raise ValueError("ids must be an iterable, not one string")
        ids = {_id(source_id) for source_id in ids}
        unknown = ids - self._sources.keys()
        if unknown:
            raise SourceBindingError("Unknown allowed source IDs: " + repr(sorted(unknown)))
        versions = {} if versions is None else versions
        if set(versions) - ids:
            raise SourceBindingError("Version bindings name sources outside the grant set")
        for source_id, version in versions.items():
            if _json(version) != self._sources[source_id].version:
                raise SourceBindingError("Expected source version mismatch")
        next_epoch = self.epoch + 1 if epoch is None else epoch
        if type(next_epoch) is not int or next_epoch < self.epoch:
            raise ValueError("Epoch must be a monotone integer")
        allowed = {source_id: (self._sources[source_id].version, self._sources[source_id].sha256)
                   for source_id in ids}
        if self._policy_bound and next_epoch == self.epoch and allowed != self._allowed:
            raise ValueError("A changed grant set requires a newer epoch")
        changed = {source_id for source_id in set(allowed) | set(self._allowed)
                   if allowed.get(source_id) != self._allowed.get(source_id)}
        seeds = set().union(*(self._source_facts[source_id] for source_id in changed))
        with self.connection:
            self.connection.execute("DELETE FROM support_grants")
            self.connection.executemany("INSERT INTO support_grants VALUES(?,?,?)",
                ((source_id,) + binding for source_id, binding in sorted(allowed.items())))
            self.connection.execute("UPDATE support_meta SET value=? WHERE key='epoch'", (str(next_epoch),))
            self.connection.execute("UPDATE support_meta SET value='1' WHERE key='policy_bound'")
        self._allowed = allowed
        self.epoch = next_epoch
        self._policy_bound = True
        stats = self._refresh(self._dirty_cone(seeds), algorithm="incremental_permissions")
        stats["changed_sources"] = len(changed)
        stats["maintenance_elapsed_ms"] = (time.perf_counter() - started) * 1000
        self.last_stats = stats
        return dict(stats)

    def update_source(self, source_id, text, version):
        """Install a new immutable source version; old spans and grants stay invalid."""
        record = self._source_records([{"id": source_id, "text": text, "version": version}])[0]
        old = self._sources.get(source_id)
        if old == record:
            return self._refresh(set(), algorithm="incremental_source_noop")
        if old is not None and old.version == record.version:
            raise SourceBindingError("Changed source content requires a new version")
        seeds = self._source_facts[source_id]
        with self.connection:
            self.connection.execute("INSERT OR REPLACE INTO support_sources VALUES(?,?,?,?)",
                (record.source_id, record.text, record.version, record.sha256))
            self.connection.execute("DELETE FROM support_grants WHERE source_id=?", (source_id,))
            self.connection.execute("UPDATE support_meta SET value=? WHERE key='epoch'", (str(self.epoch + 1),))
        self._sources[source_id] = record
        self._allowed.pop(source_id, None)
        self.epoch += 1
        return self._refresh(self._dirty_cone(seeds), algorithm="incremental_source_update")

    def _dirty_cone(self, seeds):
        dirty = set(seeds)
        queue = deque(sorted(seeds))
        while queue:
            for head in self._reverse.get(queue.popleft(), ()):
                if head not in dirty:
                    dirty.add(head)
                    queue.append(head)
        return dirty

    def _live_span(self, span, stats):
        stats["span_checks"] += 1
        source = self._sources.get(span["source_id"])
        if source is None or self._allowed.get(span["source_id"]) != (source.version, source.sha256):
            return False
        return (span["source_version"] == source.version and
                span["source_sha256"] == source.sha256 and
                source.text[span["start"]:span["end"]] == span["quote"] and
                _sha(span["quote"]) == span["quote_sha256"])

    @staticmethod
    def _add_minimal(collection, candidate, stats):
        stats["proof_candidates"] += 1
        if any(existing <= candidate for existing in collection):
            return False
        collection.difference_update(existing for existing in tuple(collection) if candidate < existing)
        collection.add(candidate)
        return True

    def _solve(self, dirty, *, preserve):
        start = time.perf_counter()
        stats = defaultdict(int, {key: 0 for key in (
            "span_checks", "rule_evaluations", "premise_checks", "proof_unions", "proof_candidates")})
        proofs = {fact: set() for fact in dirty}
        def current(fact):
            return proofs[fact] if fact in dirty else self._proofs.get(fact, set()) if preserve else set()
        for span_id in sorted(set().union(*(self._spans_by_fact[fact] for fact in dirty))):
            span = self._spans[span_id]
            if self._live_span(span, stats):
                self._add_minimal(proofs[span["fact_id"]], frozenset({span_id}), stats)
        relevant = [self._rules[rule_id] for rule_id in sorted(
            set().union(*(self._rules_by_head[fact] for fact in dirty)))]
        changed = True
        while changed:
            stats["rounds"] += 1
            changed = False
            for head, body in relevant:
                stats["rule_evaluations"] += 1
                stats["premise_checks"] += len(body)
                if not all(current(fact) for fact in body):
                    continue
                # Snapshot lists: a self/cyclic head may also be a body fact.
                for combination in itertools.product(*(tuple(current(fact)) for fact in body)):
                    stats["proof_unions"] += 1
                    candidate = frozenset().union(*combination)
                    changed |= self._add_minimal(proofs[head], candidate, stats)
        stats.update(dirty_facts=len(dirty), total_facts=len(self._facts),
                     relevant_rules=len(relevant), active_facts=sum(bool(current(fact)) for fact in self._facts),
                     elapsed_ms=(time.perf_counter() - start) * 1000)
        return proofs, dict(stats)

    def _refresh(self, dirty, *, algorithm):
        # Withdraw before recomputation. A failed calculation leaves the dirty
        # region unavailable, never the old permission epoch's cached proof.
        with self.connection:
            self.connection.executemany("DELETE FROM support_proofs WHERE fact_id=?",
                                        ((fact,) for fact in dirty))
        for fact in dirty:
            self._proofs[fact] = set()
        proofs, stats = self._solve(dirty, preserve=True)
        with self.connection:
            self.connection.executemany("INSERT INTO support_proofs VALUES(?,?)",
                ((fact, _json(sorted(proof))) for fact in sorted(dirty) for proof in proofs[fact]))
        self._proofs.update(proofs)
        stats["algorithm"] = algorithm
        stats["epoch"] = self.epoch
        self.last_stats = stats
        return dict(stats)

    def active_facts(self):
        return {fact for fact, proofs in self._proofs.items() if proofs}

    def recompute_full(self):
        """Read-only baseline: discard every cached proof and scan every rule."""
        proofs, stats = self._solve(set(self._facts), preserve=False)
        stats["algorithm"] = "full_proof_recompute"
        return {"active_facts": {fact for fact, value in proofs.items() if value},
                "proofs": {fact: sorted([sorted(proof) for proof in value]) for fact, value in proofs.items()},
                "stats": stats}

    def evaluate_counting_acyclic(self):
        """Simple full topological support counts; deliberately rejects cycles."""
        start = time.perf_counter()
        stats = defaultdict(int, {key: 0 for key in ("span_checks", "rule_evaluations", "premise_checks")})
        parents = defaultdict(set)
        for head, body in self._rules.values():
            parents[head].update(body)
        indegree = {fact: len(parents[fact]) for fact in self._facts}
        queue = deque(sorted(fact for fact, degree in indegree.items() if degree == 0))
        order = []
        while queue:
            fact = queue.popleft()
            order.append(fact)
            for head in sorted(self._reverse.get(fact, ())):
                indegree[head] -= 1
                if indegree[head] == 0:
                    queue.append(head)
        if len(order) != len(self._facts):
            raise ValueError("Counting baseline requires an acyclic rule graph")
        counts = dict.fromkeys(self._facts, 0)
        by_head = defaultdict(list)
        for head, body in self._rules.values():
            by_head[head].append(body)
        for span in self._spans.values():
            if self._live_span(span, stats):
                counts[span["fact_id"]] += 1
        for head in order:
            for body in by_head[head]:
                stats["rule_evaluations"] += 1
                stats["premise_checks"] += len(body)
                counts[head] += int(all(counts[fact] > 0 for fact in body))
        stats.update(algorithm="acyclic_support_count", total_facts=len(counts),
                     active_facts=sum(value > 0 for value in counts.values()),
                     elapsed_ms=(time.perf_counter() - start) * 1000)
        return {"active_facts": {fact for fact, count in counts.items() if count},
                "counts": counts, "stats": dict(stats)}

    def _span_output(self, span_id):
        span = self._spans[span_id]
        source = self._sources[span["source_id"]]
        # Recheck the complete source at delivery time, not just a cached hash.
        if _sha(source.text) != source.sha256 or not self._live_span(span, defaultdict(int)):
            raise SourceBindingError("A proof's current source binding is no longer valid")
        return {"span_id": span_id, "source_id": span["source_id"],
                "version": json.loads(span["source_version"]),
                "source_sha256": span["source_sha256"], "start": span["start"], "end": span["end"],
                "excerpt": span["quote"], "quote": span["quote"],
                "quote_sha256": span["quote_sha256"], "text_sha256": span["quote_sha256"]}

    def witnesses_for(self, fact_id):
        """Return all minimal currently grounded proofs, including actual leaves."""
        _id(fact_id)
        result = []
        for proof in sorted(self._proofs.get(fact_id, ()), key=lambda value: (len(value), sorted(value))):
            spans = [self._span_output(span_id) for span_id in sorted(proof)]
            result.append({"fact_id": fact_id, "span_ids": sorted(proof), "spans": spans,
                           "source_ids": sorted({span["source_id"] for span in spans}), "epoch": self.epoch})
        return result

    def render_supported(self, fact_ids, *, strict=True):
        """Render one finite authorized proof per fact as original excerpts only.

        Each fact selects a deterministic smallest proof (span count, then IDs).
        Selection does not promise a globally cheapest shared witness cover.
        A consumer must still independently check its current broker grants.
        """
        if isinstance(fact_ids, str):
            raise ValueError("fact_ids must be an iterable, not one string")
        requested = list(dict.fromkeys(_id(fact) for fact in fact_ids))
        chosen, supported, missing = set(), [], []
        for fact in requested:
            proofs = self._proofs.get(fact, ())
            if not proofs:
                missing.append(fact)
                continue
            chosen.update(min(proofs, key=lambda value: (len(value), sorted(value))))
            supported.append(fact)
        if strict and missing:
            raise UnsupportedFactError("Unsupported facts: " + repr(missing))
        spans = [self._span_output(span_id) for span_id in sorted(chosen)]
        source_ids = sorted({span["source_id"] for span in spans})
        return {"fact_ids": supported, "missing_fact_ids": missing, "spans": spans, "excerpts": spans,
                "text": "\n\n".join(span["excerpt"] for span in spans),
                "source_ids": source_ids, "support_ids": source_ids,
                "source_hashes": {source_id: self._sources[source_id].sha256 for source_id in source_ids},
                "source_versions": {source_id: json.loads(self._sources[source_id].version) for source_id in source_ids},
                "epoch": self.epoch}

    def close(self):
        self.connection.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
