"""Prepare a traceable, controlled seven-task fixture from one public episode.

Only the published natural text and an already executed application ACL are
reused. This is machine-checked span instrumentation, with no human or natural
ACL qualification and no claim of a generative-model evaluation.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re

from .policy import validate_case
from .tasks import validate_runtime


EPISODE = "office_episode_custom_en_001_maple_maplemark_dual_project"
AS_OF = "t009"
CASE_ID = EPISODE + "__t009_controlled"
QUALIFICATION = "controlled_machine_checked_fact_spans"
_EPISODES_REL = Path("datasets/benchmarks/migration_public_2026-10-18/gatemem/raw/bench/data/office/episodes.jsonl")
_SOURCE_REL = Path("results/public_acl_feasibility_2026-10-18/source_run_01")
_EPISODES_SHA256 = "e15797cc0ab778067e0235377a09811c73182b5e1aa28e2221adc5ef9638a409"
_SOURCE_COMMIT = "a983828b3bb7565e16e25ac8cdc2fc1982633b0b"
_ROLES = {"owner": "pm_ava_lin", "assistant": "assistant_erin_blake", "outsider": "employee_nina_torres"}
_READERS = {"t002": ["owner"], "t003": ["owner", "assistant"], "t005": ["owner"]}
_KINDS = {"t002": "customer", "t003": "date", "t005": "budget"}
_ORIGINAL_HASHES = {
    "t002": "4f2ccd44deb16454614c93d461bd1c52ef7e9a0800af1cdcece41e450199c294",
    "t003": "b1f2954d6fc279006dc929f9727858faf033379954adfaebf095b456348efae9",
    "t005": "dc75188febbfdc05d292bebffd08e37e91702b7f90ae222c242e65ca993a25d3",
}
_SPANS = {"t002": (42, 56), "t003": (43, 56), "t005": (38, 49)}
_QUESTIONS = {
    "customer": "As of the t009 snapshot, what is Project Maple's exact external customer?",
    "date": "As of the t009 snapshot, what is Project Maple's current target date?",
    "budget": "As of the t009 snapshot, what is Project Maple's provisional working budget?",
}
_PATTERNS = {
    "customer": re.compile(r"\bFor Maple, the exact external customer is ([^,\n]+), but\b"),
    "date": re.compile(r"\bRecording the current Maple target date as ([A-Z][a-z]+ \d{1,2}, \d{4}) while\b"),
    "budget": re.compile(r"\bMaple's provisional working budget is ([\d,]+ USD) before\b"),
}
_TASKS = [("owner", "t002"), ("owner", "t003"), ("owner", "t005"),
          ("assistant", "t003"), ("assistant", "t002"), ("assistant", "t005"), ("outsider", "t003")]


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _read(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _require(condition, reason):
    if not condition:
        raise ValueError(reason)


def _strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from _strings(key)
            yield from _strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)


def _validate_source_observations(source_result, records):
    """Check saved response bodies, rather than trusting historical pass flags."""
    requests = source_result.get("requests")
    _require(isinstance(requests, list), "source response observations are missing")
    by_id = {record["source_id"]: record for record in records}
    for observation in requests:
        _require(isinstance(observation, dict) and observation.get("viewer") in _ROLES,
                 "unregistered source observation viewer")
        viewer = observation["viewer"]
        values = list(_strings(observation.get("body")))
        for record in records:
            if viewer not in record["readers"]:
                indicators = [record["content"], record["original_text"], record["marker"],
                              *record["sensitive_fragments_for_probe"]]
                _require(not any(indicator in value for indicator in indicators for value in values),
                         "unauthorized content in saved source response")
    for viewer in _ROLES:
        listings = [q for q in requests if q.get("viewer") == viewer
                    and q.get("path") == "/source/records" and q.get("http") == 200]
        _require(len(listings) == 1, "exactly one successful source listing per viewer required")
        body = listings[0].get("body")
        _require(isinstance(body, dict) and isinstance(body.get("results"), list), "malformed source listing")
        rows = body["results"]
        _require(all(isinstance(row, dict) and isinstance(row.get("id"), str) for row in rows),
                 "malformed source listing row")
        wanted = {record["source_id"] for record in records if viewer in record["readers"]}
        _require(len(rows) == len(wanted) and {row["id"] for row in rows} == wanted,
                 "source listing does not match controlled readers")
        _require(all(row.get("memory") == by_id[row["id"]]["content"] for row in rows),
                 "source listing changed natural memory content")
        for record in records:
            path = "/source/records/" + record["source_id"]
            reads = [q for q in requests if q.get("viewer") == viewer and q.get("path") == path]
            _require(len(reads) == 1, "exactly one source read per registered pair required")
            response = reads[0]
            if viewer in record["readers"]:
                _require(response.get("http") == 200 and isinstance(response.get("body"), dict)
                         and response["body"].get("id") == record["source_id"]
                         and response["body"].get("memory") == record["content"],
                         "source authorized read is not qualified")
            else:
                _require(response.get("http") == 403, "source denied read is not qualified")
    return {"read_pairs_checked_from_bodies": 9, "listings_checked_from_bodies": 3,
            "source_boundary": "credential_bound_research_application_gateway_not_native_mem0_authentication"}


def _load_verified_source(project):
    source = project / _SOURCE_REL
    sr_path, policy_path = source / "source_result.json", source / "controlled_policy.json"
    sr = _read(sr_path)
    _require(sr.get("status") == "passed" and sr.get("source_version") == "2.2.1"
             and sr.get("native_mem0_authentication") is False, "unexpected source execution contract")
    files = sr.get("files")
    required = {"controlled_policy.json", "mem0_snapshot.json", "baseline_plans.json",
                "exact_acl_partition_0.json", "exact_acl_partition_1.json",
                "per_reader_copy_0.json", "per_reader_copy_1.json"}
    _require(isinstance(files, dict) and required <= set(files), "source artifact hash inventory incomplete")
    verified_files = {}
    for name, expected in files.items():
        _require(isinstance(name, str) and Path(name).name == name and "/" not in name and "\\" not in name,
                 "source artifact path must be a local filename")
        _require(isinstance(expected, str) and re.fullmatch(r"[0-9a-f]{64}", expected),
                 "malformed source artifact hash")
        path = source / name
        _require(_sha(path.read_bytes()) == expected, "source artifact hash mismatch: " + name)
        verified_files[name] = {"path": str(path.resolve()), "sha256": expected}
    policy = _read(policy_path)
    episodes_path = project / _EPISODES_REL
    episodes_bytes = episodes_path.read_bytes()
    _require(_sha(episodes_bytes) == _EPISODES_SHA256 == policy.get("source_sha256"),
             "pinned public episodes hash mismatch")
    _require(policy.get("episode_id") == EPISODE and policy.get("as_of_turn_id") == AS_OF
             and policy.get("source_commit") == _SOURCE_COMMIT, "public episode or snapshot mismatch")
    _require(policy.get("original_benchmark_acl_claimed") is False and policy.get("benchmark_checkpoints_used") is False,
             "controlled fixture must not claim original benchmark ACL or checkpoints")
    episodes = [json.loads(line) for line in episodes_bytes.decode("utf-8").splitlines() if line.strip()]
    selected = [episode for episode in episodes if episode.get("episode_id") == EPISODE]
    _require(len(selected) == 1, "exactly one pinned public episode required")
    episode = selected[0]
    prefix = []
    for turn in episode["turns"]:
        prefix.append(turn)
        if turn.get("turn_id") == AS_OF:
            break
    _require([turn.get("turn_id") for turn in prefix] == [f"t{i:03d}" for i in range(1, 10)],
             "fixed t009 public prefix is missing or reordered")
    turns = {turn["turn_id"]: turn for turn in prefix}
    public_principals = {person["principal_id"] for person in episode["entities"]["principals"]}
    _require(all(role in public_principals for role in _ROLES.values()), "public role reference missing")
    _require(isinstance(policy.get("principals"), dict) and set(policy["principals"]) == set(_ROLES),
             "controlled principals mismatch")
    _require(all(policy["principals"][actor].get("public_role_reference") == role for actor, role in _ROLES.items()),
             "controlled public role mapping mismatch")
    records = policy.get("records")
    _require(isinstance(records, list) and len(records) == 3
             and {record.get("key") for record in records} == set(_READERS), "exactly three selected source turns required")
    records = sorted(records, key=lambda record: record["key"])
    _require(all(isinstance(record.get("source_id"), str) and record["source_id"] for record in records)
             and len({record["source_id"] for record in records}) == 3, "source identities must be unique")
    anchors = {}
    for record in records:
        key, original = record["key"], record.get("original_text")
        _require(original == turns[key]["text"] and isinstance(original, str), "source natural text differs from public turn")
        _require(_sha(original.encode("utf-8")) == record.get("original_text_sha256") == _ORIGINAL_HASHES[key],
                 "source natural text hash mismatch")
        _require(record.get("readers") == _READERS[key], "controlled reader rules differ from executed fixture")
        marker = record.get("marker")
        _require(isinstance(marker, str) and re.fullmatch(r"CONTROLLED-MIGACL-" + key + r"-[0-9a-f]{16}", marker),
                 "unexpected transport probe marker")
        _require(record.get("content") == original + "\n" + marker, "source natural content or marker was rewritten")
        matched = _PATTERNS[_KINDS[key]].search(original)
        start, end = _SPANS[key]
        _require(matched is not None and matched.span(1) == (start, end)
                 and record.get("sensitive_fragments_for_probe") == [original[start:end]],
                 "fact anchor does not match pinned source span")
        anchors[key] = {"episode_file": str(episodes_path.resolve()), "episode_sha256": _EPISODES_SHA256,
                        "episode_id": EPISODE, "as_of_turn_id": AS_OF, "turn_id": key,
                        "native_source_id": record["source_id"], "original_text_sha256": _ORIGINAL_HASHES[key],
                        "span": {"start": start, "end": end, "unit": "unicode_codepoint", "interval": "half_open"},
                        "fact": original[start:end]}
    snapshot = _read(source / "mem0_snapshot.json")
    rows = snapshot.get("results")
    _require(isinstance(rows, list) and len(rows) == 3 and all(isinstance(row, dict) for row in rows),
             "native source export inventory is incomplete")
    _require({row.get("id") for row in rows} == {record["source_id"] for record in records},
             "native source export IDs differ")
    for record in records:
        row = next(row for row in rows if row["id"] == record["source_id"])
        _require(row.get("memory") == record["content"] and row.get("user_id") == "trusted_controlled_storage"
                 and row.get("metadata", {}).get("source_turn") == record["key"]
                 and row.get("metadata", {}).get("public_episode") == EPISODE,
                 "native source export lineage or text mismatch")
    observations = _validate_source_observations(sr, records)
    return records, anchors, policy, verified_files, sr_path, episodes_path, observations


def prepare_controlled_fixture(legacy_project: Path, output: Path) -> dict:
    """Write runtime/evaluation/provenance into a new directory; never mutate input."""
    project, output = Path(legacy_project).resolve(), Path(output).resolve()
    if output.exists():
        raise FileExistsError("controlled fixture output must be a new directory")
    records, anchors, policy, verified, sr_path, episodes_path, observations = _load_verified_source(project)
    actors = [{"actor_id": actor, "user_id": role, "agent_id": "memory_worker"} for actor, role in _ROLES.items()]
    runtime_records = [{"source_id": record["source_id"], "text": record["content"],
                        "source_readers": list(record["readers"]), "recipient_readers": list(record["readers"]),
                        "target_readers": list(record["readers"]), "export_allowed": True, "copy_allowed": True}
                       for record in records]
    by_key = {record["key"]: record for record in records}
    tasks, labels = [], []
    for actor, key in _TASKS:
        task_id = actor + "_maple_" + _KINDS[key]
        tasks.append({"case_id": CASE_ID, "task_id": task_id, "actor_id": actor, "query": _QUESTIONS[_KINDS[key]]})
        allowed = actor in _READERS[key]
        labels.append({"task_id": task_id, "task_type": "authorized_fact" if allowed else "denied_request",
                       "expected_answer": anchors[key]["fact"] if allowed else "UNKNOWN",
                       "required_fact_source_ids": [by_key[key]["source_id"]] if allowed else [],
                       "fact_anchor_key": key, "policy_basis": "explicit_controlled_administrator_reader_sets",
                       "forbidden_markers": [anchors[k]["fact"] for k in _READERS if actor not in _READERS[k]]})
    case = {"case_id": CASE_ID, "actors": actors,
            "actor_mapping": {actor: "target/public-controlled/" + role + "/memory_worker" for actor, role in _ROLES.items()},
            "records": runtime_records, "tasks": tasks}
    runtime = {"schema_version": 1, "cases": [case]}
    evaluation = {"schema_version": 1, "cases": {CASE_ID: {"tasks": labels, "fact_anchors": anchors}}}
    validate_case(case)
    validate_runtime(runtime)
    provenance = {
        "schema_version": 1, "qualification": QUALIFICATION, "case_id": CASE_ID,
        "independent_stories": 1, "records": 3, "tasks": 7, "authorized_fact_tasks": 4, "denied_tasks": 3,
        "natural_acl_qualified": 0, "human_review": None, "real_llm": None,
        "source_project": str(project), "public_episode_file": str(episodes_path.resolve()),
        "public_episode_sha256": _EPISODES_SHA256, "public_source_commit": _SOURCE_COMMIT,
        "episode_id": EPISODE, "as_of_turn_id": AS_OF, "prefix_turn_ids": [f"t{i:03d}" for i in range(1, 10)],
        "runtime_source_turn_ids": list(_READERS), "future_turns_used": False, "benchmark_checkpoints_used": False,
        "source_result": {"path": str(sr_path.resolve()), "sha256": _sha(sr_path.read_bytes())},
        "verified_source_files": verified, "source_observations": observations,
        "original_policy_author": policy.get("policy_author"), "original_human_reviewer": policy.get("human_reviewer"),
        "source_acl_origin": "previously_executed_researcher_declared_application_policy_on_public_content",
        "natural_acl_claimed": False,
        "recipient_and_target_rules": "new_controlled_experiment_configuration_equal_to_executed_source_reader_sets",
        "new_experiment_grants": {"export_allowed": True, "copy_allowed": True,
                                  "origin": "explicit_configuration_for_this_public_controlled_experiment",
                                  "upstream_original_grant_claimed": False, "human_review": None},
        "identity_binding": {"user_id_origin": "public_role_reference", "agent_id": "memory_worker",
                             "agent_binding": "application_level_only",
                             "native_backend_principal_scope": "user_credential_only",
                             "target_mapping": "deterministic_logical_names_require_separate_native_binding",
                             "native_target_identity_verified": False},
        "content": {"natural_text_rewritten": False, "original_probe_markers_retained": True,
                    "facts_are_original_text_spans": True, "runtime_contains_evaluation_labels": False},
        "native_export_contract": {"format": "mem0_get_all_results",
                                   "fields": ["id", "memory", "metadata", "user_id"],
                                   "storage_user_id_is_not_actor_acl": True},
        "limits": ["one_story_seven_controlled_tasks_not_seven_independent_samples",
                   "fact_span_correctness_only_no_paraphrase_or_general_semantic_claim",
                   "saved_source_execution_checked_not_new_native_target_execution"],
    }
    output.mkdir(parents=True, exist_ok=False)
    for name, data in (("runtime.json", runtime), ("evaluation.json", evaluation)):
        (output / name).write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    provenance["generated_file_sha256"] = {name: _sha((output / name).read_bytes())
                                           for name in ("runtime.json", "evaluation.json")}
    (output / "provenance.json").write_text(json.dumps(provenance, ensure_ascii=False, indent=2), encoding="utf-8")
    return {"status": "prepared", "qualification": QUALIFICATION, "case_id": CASE_ID,
            "independent_stories": 1, "records": 3, "tasks": 7, "natural_acl_qualified": 0,
            "human_review": None, "real_llm": None,
            "runtime_path": str(output / "runtime.json"), "evaluation_path": str(output / "evaluation.json"),
            "provenance_path": str(output / "provenance.json"),
            "files": {name: {"path": str(output / name), "sha256": _sha((output / name).read_bytes())}
                      for name in ("runtime.json", "evaluation.json", "provenance.json")}}


class SpanInstrumentationAnswerer:
    """Transparent fixed regex extraction over supplied context, without labels.

    These patterns recognize the three selected natural sentence forms. They
    contain no expected fact values, and cannot access evaluation/provenance.
    Authorization remains the caller's responsibility when assembling context.
    """
    kind = "deterministic_instrumentation"

    def __call__(self, *, query, memories, session_id):
        intents = [kind for kind in _PATTERNS if re.search(r"\b" + kind + r"\b", query, re.IGNORECASE)]
        if len(intents) != 1:
            return "UNKNOWN"
        matches = {match.group(1) for memory in memories
                   for match in _PATTERNS[intents[0]].finditer(memory["text"])}
        return next(iter(matches)) if len(matches) == 1 else "UNKNOWN"
