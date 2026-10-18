"""Read local fixtures without executing upstream code or inferring product ACLs.

GateMem's policy is an explicitly controlled, single-speaker derived policy.
It is not GateMem's native governance policy or a benchmark evaluation.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any


_PUBLIC_ROOT = Path("benchmarks/migration_public_2026-10-18")
_NON_USER_ROLES = {"agent", "assistant", "system", "tool", "llm", "bot"}


def _is_data_root(path: Path) -> bool:
    return (path / "synthetic/synthetic_corpus.json").is_file() or (
        path / _PUBLIC_ROOT / "gatemem/raw/bench/data"
    ).is_dir()


def discover_data_root(start: Path) -> Path:
    """Find a dataset root, including the workspace's datasets/datasets layout."""
    start = Path(start).resolve()
    if start.is_file():
        start = start.parent
    for parent in (start, *start.parents):
        for candidate in (parent, parent / "datasets", parent / "datasets/datasets"):
            if _is_data_root(candidate):
                return candidate
    raise FileNotFoundError(f"Cannot locate local memory datasets from {start}")


def _json(path: Path) -> Any:
    with path.open("r", encoding="utf-8-sig") as handle:
        return json.load(handle)


def _jsonl(path: Path):
    with path.open("r", encoding="utf-8-sig") as handle:
        for line_number, line in enumerate(handle, 1):
            if line.strip():
                value = json.loads(line)
                if not isinstance(value, dict):
                    raise ValueError(f"Expected object in {path}:{line_number}")
                yield value


def _input_file(path: Path) -> dict:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return {"path": str(path.resolve()), "sha256": digest.hexdigest(), "bytes": path.stat().st_size}


def _new_audit(dataset: str) -> dict:
    return {
        "dataset": dataset,
        "source_entries": 0,
        "eligible_records": 0,
        "selected_records": 0,
        "excluded_by_reason": {},
        "exclusions": [],
        "policy_notes": [],
    }


def _scoped_subject(domain: str, episode_id: str, principal_id: str) -> str:
    """Do not assume an upstream name denotes the same identity in two episodes."""
    return json.dumps([domain, episode_id, principal_id], separators=(",", ":"), ensure_ascii=False)


def _exclude(audit: dict, source_id: str, reason: str) -> None:
    counts = audit["excluded_by_reason"]
    counts[reason] = counts.get(reason, 0) + 1
    audit["exclusions"].append({"source_id": source_id, "reason": reason})


def _load_synthetic(root: Path, group_config: Path | None) -> dict:
    if group_config is None:
        raise ValueError("synthetic requires --group-config with explicit {\"groups\": {...}} membership")
    source = root / "synthetic/synthetic_corpus.json"
    config_path = Path(group_config).resolve()
    data, config = _json(source), _json(config_path)
    subjects_raw = data.get("meta", {}).get("subjects")
    if not isinstance(subjects_raw, list) or not all(isinstance(x, str) and x for x in subjects_raw):
        raise ValueError("synthetic meta.subjects must explicitly list user identifiers")
    subjects = sorted(set(subjects_raw))
    known_users = set(subjects)
    groups = config.get("groups")
    if not isinstance(groups, dict) or not all(isinstance(k, str) and k for k in groups):
        raise ValueError("group config requires a groups object mapping group IDs to user lists")
    if known_users.intersection(groups):
        raise ValueError("Group identifiers must not collide with user identifiers")
    invalid_groups = {
        name for name, members in groups.items()
        if not isinstance(members, list)
        or not all(isinstance(member, str) and member in known_users for member in members)
    }
    records, seen = [], set()
    audit = _new_audit("synthetic")
    audit["policy_notes"] = [
        "R/state are synthetic reference policy, not verified third-party product ACLs.",
        "Project groups are expanded only from the supplied group configuration.",
        "Any unknown ACL token or invalid group rejects the complete record.",
        "deleted/expired are excluded from this static access-preservation experiment.",
    ]
    audit["invalid_config_groups"] = sorted(invalid_groups)
    entries = data.get("entries")
    if not isinstance(entries, list):
        raise ValueError("synthetic entries must be a list")
    for index, entry in enumerate(entries):
        audit["source_entries"] += 1
        if not isinstance(entry, dict):
            _exclude(audit, f"index:{index}", "malformed_entry")
            continue
        source_id = entry.get("entry_id")
        if not isinstance(source_id, str) or not source_id:
            _exclude(audit, f"index:{index}", "missing_source_id")
            continue
        if source_id in seen:
            _exclude(audit, source_id, "duplicate_source_id")
            continue
        seen.add(source_id)
        state = entry.get("state")
        if state not in {"active", "updated"}:
            _exclude(audit, source_id, f"state_{state}" if state in {"deleted", "expired"} else "unknown_state")
            continue
        acl = entry.get("R")
        if not isinstance(acl, list) or not all(isinstance(x, str) for x in acl):
            _exclude(audit, source_id, "malformed_acl")
            continue
        if any(token not in known_users and token not in groups for token in acl):
            _exclude(audit, source_id, "unknown_acl_principal_or_group")
            continue
        if any(token in invalid_groups for token in acl):
            _exclude(audit, source_id, "invalid_group_member")
            continue
        allowed = set()
        for token in acl:
            allowed.update([token] if token in known_users else groups[token])
        if not allowed:
            _exclude(audit, source_id, "no_authorized_users")
            continue
        text = entry.get("text")
        if not isinstance(text, str) or not text.strip():
            _exclude(audit, source_id, "missing_text")
            continue
        records.append({
            "id": source_id,
            "text": text,
            "allowed_users": sorted(allowed),
            "source_ref": {"dataset": "synthetic", "entry_id": source_id, "state": state},
        })
    return {
        "records": records, "subjects": subjects, "audit": audit,
        "input_files": [_input_file(source), _input_file(config_path)],
        "policy_origin": "synthetic_explicit_R_and_user_supplied_groups",
    }


def _load_gatemem(root: Path, domains: tuple, episodes_per_domain: int | None) -> dict:
    base = root / _PUBLIC_ROOT / "gatemem/raw/bench/data"
    records, subjects, files, seen = [], set(), [], set()
    audit = _new_audit("gatemem")
    audit.update({
        "available_episodes": 0, "selected_episodes": 0,
        "episodes_seen": 0, "episodes_with_valid_prefix": 0,
        "selected_prefix_raw_turns": 0, "episodes_by_domain": {},
    })
    audit["policy_notes"] = [
        "Controlled derived policy: each dialogue turn is private to its identified human speaker.",
        "Subject identities are scoped by domain and episode; matching raw IDs are not merged.",
        "This policy is not GateMem's original permission policy or its benchmark score.",
        "Only the first checkpoint's ID, episode, boundary and asker metadata are used.",
        "expected_action/judge_spec/leak_targets/query_text are never used to derive ACLs.",
        "No turn after the checkpoint boundary is eligible.",
    ]
    for domain in dict.fromkeys(domains):
        if not isinstance(domain, str) or not domain or Path(domain).name != domain or domain in {".", ".."}:
            raise ValueError("domains must be plain directory names")
        episode_path = base / domain / "episodes.jsonl"
        checkpoint_path = base / domain / "checkpoints.jsonl"
        files.extend([_input_file(episode_path), _input_file(checkpoint_path)])
        first_checkpoints = {}
        for checkpoint in _jsonl(checkpoint_path):
            episode_id = checkpoint.get("episode_id")
            if isinstance(episode_id, str) and episode_id not in first_checkpoints:
                # Do not retain reference answers, leak targets or query text.
                asker = checkpoint.get("asker")
                first_checkpoints[episode_id] = {
                    "checkpoint_id": checkpoint.get("checkpoint_id"),
                    "episode_id": episode_id,
                    "as_of_turn_id": checkpoint.get("as_of_turn_id"),
                    "asker": {key: asker.get(key) for key in ("principal_id", "role")} if isinstance(asker, dict) else {},
                }
        episodes = list(_jsonl(episode_path))
        selected = episodes[:episodes_per_domain] if episodes_per_domain else episodes
        audit["available_episodes"] += len(episodes)
        audit["selected_episodes"] += len(selected)
        audit["episodes_by_domain"][domain] = {"available": len(episodes), "selected": len(selected)}
        for episode in selected:
            audit["episodes_seen"] += 1
            episode_id = episode.get("episode_id")
            if not isinstance(episode_id, str) or not episode_id:
                _exclude(audit, f"{domain}:episode", "missing_episode_id")
                continue
            checkpoint = first_checkpoints.get(episode_id)
            turns = episode.get("turns")
            if checkpoint is None or not isinstance(turns, list):
                _exclude(audit, episode_id, "missing_checkpoint_or_turns")
                continue
            boundary = checkpoint.get("as_of_turn_id")
            indices = [i for i, turn in enumerate(turns) if isinstance(turn, dict) and turn.get("turn_id") == boundary]
            if boundary is None or len(indices) != 1:
                _exclude(audit, episode_id, "missing_or_ambiguous_boundary")
                continue
            principals = episode.get("entities", {}).get("principals", [])
            if not isinstance(principals, list):
                _exclude(audit, episode_id, "malformed_principals")
                continue
            principal_counts = Counter(
                p.get("principal_id") for p in principals
                if isinstance(p, dict) and isinstance(p.get("principal_id"), str)
            )
            humans = {
                p["principal_id"]: p["role"] for p in principals
                if isinstance(p, dict) and isinstance(p.get("principal_id"), str) and p["principal_id"]
                and isinstance(p.get("role"), str) and p["role"]
                and p["role"].lower() not in _NON_USER_ROLES
                and principal_counts[p["principal_id"]] == 1
            }
            subjects.update(_scoped_subject(domain, episode_id, principal_id) for principal_id in humans)
            audit["episodes_with_valid_prefix"] += 1
            prefix = turns[:indices[0] + 1]
            audit["selected_prefix_raw_turns"] += len(prefix)
            for index, turn in enumerate(prefix):
                audit["source_entries"] += 1
                if not isinstance(turn, dict):
                    _exclude(audit, f"{episode_id}:index:{index}", "malformed_turn")
                    continue
                turn_id = turn.get("turn_id")
                source_id = f"{episode_id}:{turn_id}" if isinstance(turn_id, str) and turn_id else f"{episode_id}:index:{index}"
                if not isinstance(turn_id, str) or not turn_id:
                    _exclude(audit, source_id, "missing_turn_id")
                    continue
                if source_id in seen:
                    _exclude(audit, source_id, "duplicate_source_id")
                    continue
                seen.add(source_id)
                if turn.get("turn_kind") != "dialogue":
                    _exclude(audit, source_id, "non_dialogue_turn")
                    continue
                speaker = turn.get("speaker")
                if not isinstance(speaker, dict) or not speaker.get("principal_id"):
                    _exclude(audit, source_id, "missing_speaker")
                    continue
                speaker_id = speaker["principal_id"]
                if not isinstance(speaker_id, str) or speaker_id not in humans:
                    _exclude(audit, source_id, "unknown_or_nonhuman_speaker")
                    continue
                if speaker.get("role") != humans[speaker_id]:
                    _exclude(audit, source_id, "speaker_role_mismatch")
                    continue
                text = turn.get("text")
                if not isinstance(text, str) or not text.strip():
                    _exclude(audit, source_id, "missing_text")
                    continue
                records.append({
                    "id": source_id, "text": text,
                    "allowed_users": [_scoped_subject(domain, episode_id, speaker_id)],
                    "source_ref": {
                        "dataset": "gatemem", "domain": domain, "episode_id": episode_id,
                        "turn_id": turn_id, "checkpoint_id": checkpoint["checkpoint_id"],
                        "as_of_turn_id": boundary, "asker": checkpoint["asker"],
                        "raw_speaker_id": speaker_id,
                        "policy": "controlled_single_speaker_private",
                    },
                })
    audit["episodes_not_selected"] = audit["available_episodes"] - audit["selected_episodes"]
    audit["episodes_per_domain"] = episodes_per_domain
    return {
        "records": records, "subjects": sorted(subjects), "audit": audit,
        "input_files": files, "policy_origin": "controlled_derived_single_speaker_private_not_original_gatemem_acl",
    }


def load_bundle(
    data_root: Path,
    dataset: str,
    limit: int = 60,
    seed: int = 42,
    group_config: Path | None = None,
    domains: tuple = ("office", "household"),
    episodes_per_domain: int | None = 1,
) -> dict:
    """Load bounded fixtures; limit=0 means all eligible records, not all raw rows."""
    if not isinstance(limit, int) or limit < 0:
        raise ValueError("limit must be a nonnegative integer")
    if episodes_per_domain is not None and (not isinstance(episodes_per_domain, int) or episodes_per_domain < 0):
        raise ValueError("episodes_per_domain must be nonnegative or None")
    root = discover_data_root(Path(data_root))
    if dataset == "synthetic":
        bundle = _load_synthetic(root, group_config)
    elif dataset == "gatemem":
        bundle = _load_gatemem(root, domains, episodes_per_domain)
    else:
        raise ValueError("dataset must be synthetic or gatemem")
    records = sorted(
        bundle["records"],
        key=lambda record: (hashlib.sha256(f"{seed}\0{dataset}\0{record['id']}".encode("utf-8")).hexdigest(), record["id"]),
    )
    audit = bundle["audit"]
    audit["eligible_records"] = len(records)
    if limit:
        records = records[:limit]
    bundle["records"] = records
    audit["selected_records"] = len(records)
    audit["not_selected_by_limit"] = audit["eligible_records"] - len(records)
    audit["selection"] = {"seed": seed, "limit": limit, "algorithm": "sha256(seed,dataset,source_id)"}
    return bundle
