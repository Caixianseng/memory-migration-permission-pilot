"""Finite grounded positive-Datalog B/F research port; no product integration.

Source: Motik, Nenov, Piro and Horrocks, AAAI 2015, sections 2--4,
Algorithms 1--3, https://www.cs.ox.ac.uk/people/ian.horrocks/Publications/
download/2015/MNPH15b.pdf . This is independently written Python, not RDFox code.

The accepted subset is a finite SET of opaque ground atoms and finite positive
ground rules with nonempty conjunctive bodies. Multiple rules with the same
head are alternatives. No parsing/grounding of variable rules, negation,
aggregation, functions, equality, rule changes, or semantic independence tests
are supplied. Deletion removes explicit membership only. Derived membership is
then maintained according to the least fixed point of the unchanged program.

Inputs MUST be declared by a trusted host. In particular, source-copy ancestry,
exact principal/action/resource/destination grants and global obligations are
not inferred from an atom's string or from equal text. This module has no I/O,
models, native-client calls, authorization credentials, or delivery side effects.
"""
from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
import time
from typing import Mapping


VERSION = "finite_ground_positive_bf_port_v1"
SOURCE_URL = "https://www.cs.ox.ac.uk/people/ian.horrocks/Publications/download/2015/MNPH15b.pdf"


class PortContractError(ValueError):
    """Invalid declared mechanical contract; never a semantic privacy verdict."""


def _atom(value):
    # Opaque IDs remain byte-for-byte unchanged. No case folding or text matching.
    if (type(value) is not str or not value or value != value.strip()
            or any(ord(character) < 32 for character in value)):
        raise PortContractError("invalid_ground_atom")
    return value


def _facts(values):
    if type(values) not in {list, tuple, set, frozenset}:
        raise PortContractError("facts_require_finite_collection")
    return {_atom(value) for value in values}


@dataclass(frozen=True)
class GroundRule:
    """One complete ground derivation: head follows only if ALL body atoms hold."""
    head: str
    body: tuple[str, ...]

    def __post_init__(self):
        _atom(self.head)
        if type(self.body) is not tuple or not self.body:
            raise PortContractError("rule_requires_nonempty_ground_body_tuple")
        for atom in self.body:
            _atom(atom)


def _rules(values):
    if type(values) not in {list, tuple, set, frozenset}:
        raise PortContractError("rules_require_finite_collection")
    if any(type(rule) is not GroundRule for rule in values):
        raise PortContractError("rules_require_ground_rule_instances")
    # Datalog is set-valued: duplicate declarations are not independent proofs.
    return tuple(sorted(set(values), key=lambda rule: (rule.head, rule.body)))


def _metrics():
    return {
        "input_fact_items": 0, "input_rule_items": 0, "index_entries": 0,
        "membership_tests": 0, "body_index_candidates": 0,
        "repeated_atom_positions_skipped": 0,
        "backward_facts_checked": 0, "backward_rule_candidates": 0,
        "backward_rules_matched": 0, "saturation_rule_candidates": 0,
        "saturation_rule_derivations": 0, "deletion_rule_candidates": 0,
        "deletion_rule_derivations": 0, "insertion_rule_candidates": 0,
        "insertion_rule_derivations": 0, "examined_consequences": 0,
        "proved_facts": 0, "internally_removed_facts": 0,
        "internally_added_facts": 0, "workset_peak_memberships": 0,
        "baseline_rounds": 0, "baseline_rule_scans": 0,
    }


@dataclass(frozen=True)
class UpdateResult:
    operation: str
    materialized: frozenset[str]
    added: frozenset[str]
    removed: frozenset[str]
    explicit_count: int
    requested_deletions: int
    requested_insertions: int
    effective_deletions: int
    effective_insertions: int
    elapsed_ns: int
    work: dict[str, int]
    timing_scope: str = "input_validation+maintenance+net_delta+result_snapshot"


@dataclass
class _DeleteState:
    checked: set[str] = field(default_factory=set)          # C
    examined: set[str] = field(default_factory=set)         # D
    proved: set[str] = field(default_factory=set)           # P
    delayed: set[str] = field(default_factory=set)          # Y
    processed_delete: set[str] = field(default_factory=set) # O
    disproved: set[str] = field(default_factory=set)        # S
    processed_proof: set[str] = field(default_factory=set)  # V
    checked_queue: deque = field(default_factory=deque)
    examined_queue: deque = field(default_factory=deque)
    proved_queue: deque = field(default_factory=deque)

    def peak(self, work):
        # Structural footprint, NOT bytes, RSS, or number of independent sources.
        memberships = sum(len(value) for value in (
            self.checked, self.examined, self.proved, self.delayed,
            self.processed_delete, self.disproved, self.processed_proof,
            self.checked_queue, self.examined_queue, self.proved_queue))
        work["workset_peak_memberships"] = max(work["workset_peak_memberships"], memberships)


@dataclass
class _CheckFrame:
    fact: str
    next_rule: int = 0
    body: tuple[str, ...] | None = None
    next_atom: int = 0


class BfMaterialization:
    """Ground specialization of the paper's B/F deletion plus seminaive insert.

    ``facts``/``base_facts`` return immutable snapshots. ``last_result`` contains
    real counters/timing only after the corresponding operation has executed.
    Construction includes input validation, indexes and initial materialisation.
    No deletion path calls ``FullRecomputeBaseline`` or unconditionally performs
    an all-program fixed-point recomputation; an affected graph may still be large.
    """

    def __init__(self, base_facts, rules):
        started = time.perf_counter_ns()
        work = _metrics()
        self._base = _facts(base_facts)
        self._rules = _rules(rules)
        work["input_fact_items"], work["input_rule_items"] = len(base_facts), len(rules)
        self._by_head = defaultdict(list)
        self._by_body = defaultdict(list)
        for index, rule in enumerate(self._rules):
            self._by_head[rule.head].append(index)
            work["index_entries"] += 1
            for position, atom in enumerate(rule.body):
                self._by_body[atom].append((index, position))
                work["index_entries"] += 1
        self._materialized = set()
        self._insert_closure(self._base, work)
        self._last_result = self._result("init", set(), started, work, 0, len(self._base), 0, len(self._base))

    @property
    def facts(self):
        return frozenset(self._materialized)

    @property
    def base_facts(self):
        return frozenset(self._base)

    @property
    def last_result(self):
        return self._last_result

    @property
    def index_entries(self):
        return sum(map(len, self._by_head.values())) + sum(map(len, self._by_body.values()))

    def _result(self, operation, before, started, work, requested_delete,
                requested_insert, effective_delete, effective_insert):
        materialized = frozenset(self._materialized)
        added, removed = frozenset(self._materialized - before), frozenset(before - self._materialized)
        snapshot_work = dict(work)
        elapsed = time.perf_counter_ns() - started
        return UpdateResult(operation, materialized, added, removed, len(self._base),
            requested_delete, requested_insert, effective_delete, effective_insert,
            elapsed, snapshot_work)

    def _body_matches(self, fact, work):
        """matchBody(F), including the paper's unequal-prefix annotation (9)."""
        for index, position in self._by_body.get(fact, ()):
            work["body_index_candidates"] += 1
            rule = self._rules[index]
            # For repeated identical ground body atoms, only the first position
            # may match F; later positions violate B_j != F for j < i.
            if fact in rule.body[:position]:
                work["repeated_atom_positions_skipped"] += 1
                continue
            yield rule, position

    @staticmethod
    def _other_body_holds(rule, position, available, excluded, work):
        for index, atom in enumerate(rule.body):
            if index == position:
                continue
            work["membership_tests"] += 1
            if atom not in available or atom in excluded:
                return False
        return True

    @staticmethod
    def _prove(fact, state, work):
        if fact not in state.proved:
            state.proved.add(fact)
            state.proved_queue.append(fact)
            work["proved_facts"] += 1

    def _saturate(self, state, work):
        """Algorithm 3: forward proofs only from checked explicit/proved facts."""
        while state.checked_queue:
            fact = state.checked_queue.popleft()
            work["membership_tests"] += 2
            if fact in self._base or fact in state.delayed:
                self._prove(fact, state, work)
        while state.proved_queue:
            fact = state.proved_queue.popleft()
            if fact in state.processed_proof:
                continue
            state.processed_proof.add(fact)
            for rule, position in self._body_matches(fact, work):
                work["saturation_rule_candidates"] += 1
                if self._other_body_holds(rule, position, state.processed_proof, set(), work):
                    work["saturation_rule_derivations"] += 1
                    if rule.head in state.checked:
                        self._prove(rule.head, state, work)
                    else:
                        state.delayed.add(rule.head)
            state.peak(work)

    def _enter_check(self, fact, state, work):
        if fact in state.checked:
            return False
        state.checked.add(fact)
        state.checked_queue.append(fact)
        work["backward_facts_checked"] += 1
        self._saturate(state, work)
        state.peak(work)
        return fact not in state.proved

    def _check_provability(self, fact, state, work):
        """Algorithm 2, with an explicit call stack rather than Python recursion."""
        if not self._enter_check(fact, state, work):
            return
        stack = [_CheckFrame(fact)]
        while stack:
            frame = stack[-1]
            if frame.fact in state.proved:
                stack.pop()
                continue
            if frame.body is not None:
                if frame.next_atom < len(frame.body):
                    child = frame.body[frame.next_atom]
                    frame.next_atom += 1
                    if self._enter_check(child, state, work):
                        stack.append(_CheckFrame(child))
                    continue
                frame.body, frame.next_atom = None, 0
            candidates = self._by_head.get(frame.fact, ())
            if frame.next_rule >= len(candidates):
                stack.pop()
                continue
            rule = self._rules[candidates[frame.next_rule]]
            frame.next_rule += 1
            work["backward_rule_candidates"] += 1
            matched = True
            for atom in rule.body:
                work["membership_tests"] += 1
                if atom not in self._materialized or atom in state.disproved:
                    matched = False
                    break
            if matched:
                work["backward_rules_matched"] += 1
                frame.body = rule.body

    def _delete_closure(self, deleted, work):
        """Algorithm 1: support checking precedes conditional consequence work."""
        self._base.difference_update(deleted)
        state = _DeleteState()
        for fact in sorted(deleted):
            state.examined.add(fact)
            state.examined_queue.append(fact)
        while state.examined_queue:
            fact = state.examined_queue.popleft()
            work["examined_consequences"] += 1
            self._check_provability(fact, state, work)
            state.disproved.update(state.checked - state.proved)
            if fact not in state.proved:
                for rule, position in self._body_matches(fact, work):
                    work["deletion_rule_candidates"] += 1
                    if self._other_body_holds(rule, position, self._materialized,
                                              state.processed_delete, work):
                        work["deletion_rule_derivations"] += 1
                        if rule.head not in state.examined:
                            state.examined.add(rule.head)
                            state.examined_queue.append(rule.head)
                # O contains processed deletion-propagating facts, not a proved
                # alternative. Excluding a proved fact here would hide AND uses.
                state.processed_delete.add(fact)
            state.peak(work)
        removed = state.examined - state.proved
        self._materialized.difference_update(removed)
        work["internally_removed_facts"] += len(removed)

    def _insert_closure(self, inserted, work):
        """Seminaive forward insertion; each true ground rule fires on its last input."""
        fresh = set(inserted) - self._materialized
        processed = set(self._materialized)
        queue = deque(sorted(fresh))
        self._materialized.update(fresh)
        work["internally_added_facts"] += len(fresh)
        while queue:
            fact = queue.popleft()
            processed.add(fact)
            for rule, position in self._body_matches(fact, work):
                work["insertion_rule_candidates"] += 1
                if self._other_body_holds(rule, position, processed, set(), work):
                    work["insertion_rule_derivations"] += 1
                    if rule.head not in self._materialized:
                        self._materialized.add(rule.head)
                        queue.append(rule.head)
                        work["internally_added_facts"] += 1

    def delete(self, facts):
        return self.update(delete=facts, _operation="delete")

    def insert(self, facts):
        return self.update(insert=facts, _operation="insert")

    def update(self, *, delete=(), insert=(), _operation="update"):
        started = time.perf_counter_ns()
        removed_input, added_input = _facts(delete), _facts(insert)
        work = _metrics()
        work["input_fact_items"] = len(delete) + len(insert)
        before = set(self._materialized)
        # Public contract: E'=(E\delete) union insert. Insert wins on overlap;
        # repeated removals and additions retain ordinary set semantics.
        effective_delete = (removed_input & self._base) - added_input
        effective_insert = added_input - self._base
        if effective_delete:
            self._delete_closure(effective_delete, work)
        self._base.update(added_input)
        if effective_insert:
            self._insert_closure(effective_insert, work)
        self._last_result = self._result(_operation, before, started, work,
            len(removed_input), len(added_input), len(effective_delete), len(effective_insert))
        return self._last_result


class FullRecomputeBaseline:
    """Independent complete least-fixed-point recomputation, same accepted contract.

    It does not call B/F, use its indexes, proofs, or incremental materialisation.
    Every update scans the full rule program repeatedly from the new explicit set.
    Validation and result-snapshot costs are included by the same timer boundary.
    """

    def __init__(self, base_facts, rules):
        started = time.perf_counter_ns()
        self._base, self._rules = _facts(base_facts), _rules(rules)
        work = _metrics()
        work["input_fact_items"], work["input_rule_items"] = len(base_facts), len(rules)
        self._materialized = self._recompute(work)
        self._last_result = self._result("init", set(), started, work, 0, len(self._base), 0, len(self._base))

    @property
    def facts(self):
        return frozenset(self._materialized)

    @property
    def base_facts(self):
        return frozenset(self._base)

    @property
    def last_result(self):
        return self._last_result

    def _recompute(self, work):
        closure = set(self._base)
        while True:
            work["baseline_rounds"] += 1
            before = len(closure)
            for rule in self._rules:
                work["baseline_rule_scans"] += 1
                holds = True
                for atom in rule.body:
                    work["membership_tests"] += 1
                    if atom not in closure:
                        holds = False
                        break
                if holds:
                    closure.add(rule.head)
            if len(closure) == before:
                return closure

    def _result(self, operation, before, started, work, requested_delete,
                requested_insert, effective_delete, effective_insert):
        materialized = frozenset(self._materialized)
        added, removed = frozenset(self._materialized - before), frozenset(before - self._materialized)
        snapshot_work = dict(work)
        elapsed = time.perf_counter_ns() - started
        return UpdateResult(operation, materialized, added, removed, len(self._base),
            requested_delete, requested_insert, effective_delete, effective_insert,
            elapsed, snapshot_work)

    def delete(self, facts):
        return self.update(delete=facts, _operation="delete")

    def insert(self, facts):
        return self.update(insert=facts, _operation="insert")

    def update(self, *, delete=(), insert=(), _operation="update"):
        started = time.perf_counter_ns()
        removed_input, added_input = _facts(delete), _facts(insert)
        work = _metrics()
        work["input_fact_items"] = len(delete) + len(insert)
        before = set(self._materialized)
        effective_delete = (removed_input & self._base) - added_input
        effective_insert = added_input - self._base
        self._base.difference_update(removed_input)
        self._base.update(added_input)
        self._materialized = self._recompute(work)
        self._last_result = self._result(_operation, before, started, work,
            len(removed_input), len(added_input), len(effective_delete), len(effective_insert))
        return self._last_result


@dataclass(frozen=True, order=True)
class DeliveryKey:
    """Trusted benchmark target identity; not proof of authentication."""
    actor_id: str
    agent_id: str
    operation: str
    resource_id: str
    destination_id: str

    def __post_init__(self):
        for value in (self.actor_id, self.agent_id, self.operation,
                      self.resource_id, self.destination_id):
            _atom(value)


def delivery_projection(materialized, targets: Mapping, *, globally_forbidden):
    """Shared mechanical final gate for BOTH engines, with global deny precedence.

    The trusted fixture maps each exact principal/operation/resource/destination
    key to a NONEMPTY set of required positive support/authorization atoms. This
    helper neither registers grants nor infers equivalence or source independence.
    A global obligation supplied by the same fixture overrides every alternative.
    These deterministic checks must also be included in a later total-cost timer.
    """
    available = _facts(materialized)
    if type(targets) is not dict or type(globally_forbidden) not in {list, tuple, set, frozenset}:
        raise PortContractError("invalid_delivery_contract")
    if any(type(key) is not DeliveryKey for key in targets):
        raise PortContractError("invalid_delivery_key")
    if any(type(key) is not DeliveryKey for key in globally_forbidden):
        raise PortContractError("invalid_global_obligation")
    blocked = set(globally_forbidden)
    selected = set()
    for key, atoms in targets.items():
        required = _facts(atoms)
        if not required:
            raise PortContractError("empty_delivery_support")
        if key not in blocked and required <= available:
            selected.add(key)
    return frozenset(selected)
