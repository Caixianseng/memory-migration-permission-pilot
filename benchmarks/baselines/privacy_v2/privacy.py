"""Local sensitivity detection and request-scoped, reversible pseudonymization.

This module has no network, filesystem, model-evaluation or logging dependencies.
Detection is not authorization. A redacted memory still needs its original ACL.
"""
from __future__ import annotations

from dataclasses import dataclass
import copy
import hashlib
import json
import math
import re
import secrets
from typing import Callable

CATEGORIES = frozenset("EMAIL PHONE ID PERSON ADDRESS CUSTOMER PROJECT AMOUNT DATE".split())
QUERY_SOURCE = "__query__"
_TOKEN = re.compile(r"\[PVT_[A-F0-9]{24}_[A-Z]+_\d+\]")
_RESERVED = re.compile(r"\[PVT_", re.IGNORECASE)
DETECTION_STRATEGY = "independent_union_v2"
_AGENT_ERROR_CODES = frozenset({
    "invalid_input_or_policy", "input_budget_exceeded", "local_health_failed",
    "local_transport_failed", "local_response_model_mismatch", "local_generation_incomplete",
    "local_response_invalid", "unexpected_model_behavior", "format_or_span_invalid",
    "repair_budget_exceeded", "semantic_uncertainty", "local_failure",
})
_AGENT_DIAGNOSTIC_STAGES = frozenset({"input", "budget", "health", "transport", "envelope", "output", "semantic"})
_AGENT_DIAGNOSTIC_CODES = _AGENT_ERROR_CODES | frozenset({
    "invalid_input", "invalid_policy", "invalid_categories", "invalid_candidates",
    "local_runtime_mismatch", "local_model_mismatch", "local_http_failure",
    "local_response_too_large", "local_response_decode_failed", "json_syntax_invalid",
    "duplicate_key", "invalid_schema", "invalid_span", "invalid_category",
})


def _digest(value) -> str:
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True,
                                     separators=(",", ":")).encode()).hexdigest()


def _sources(payload: dict) -> dict[str, str]:
    if not isinstance(payload, dict) or set(payload) != {"query", "memories"}:
        raise ValueError("invalid_payload_fields")
    if not isinstance(payload["query"], str) or not isinstance(payload["memories"], list):
        raise ValueError("invalid_payload_types")
    sources = {QUERY_SOURCE: payload["query"]}
    for memory in payload["memories"]:
        if not isinstance(memory, dict) or set(memory) != {"source_id", "text"}:
            raise ValueError("invalid_memory_fields")
        key = memory["source_id"]
        if not isinstance(key, str) or not key or key in sources or not isinstance(memory["text"], str):
            raise ValueError("invalid_memory_identity")
        sources[key] = memory["text"]
    return sources


def _policy(policy: dict) -> dict:
    if not isinstance(policy, dict) or not isinstance(policy.get("version"), str) or not policy["version"]:
        raise ValueError("invalid_policy_version")
    cats = policy.get("protected_categories")
    if not isinstance(cats, list) or any(not isinstance(x, str) or x not in CATEGORIES for x in cats):
        raise ValueError("invalid_policy_categories")
    maximum = policy.get("max_text_chars", 6000)
    if type(maximum) is not int or not 1 <= maximum <= 6000:
        raise ValueError("invalid_policy_length_limit")
    if not isinstance(policy.get("instructions", ""), str) or len(policy.get("instructions", "")) > 2000:
        raise ValueError("invalid_policy_instructions")
    if not isinstance(policy.get("policy_id", policy["version"]), str) or not policy.get("policy_id", policy["version"]):
        raise ValueError("invalid_policy_id")
    # A business owner may register an independent local vocabulary before any
    # scoring. Entries are sensitivity declarations, never authorization grants.
    registry = policy.get("entity_registry", [])
    if not isinstance(registry, list) or len(registry) > 1000:
        raise ValueError("invalid_policy_entity_registry")
    entries, total_chars = set(), 0
    for item in registry:
        if (not isinstance(item, dict) or set(item) != {"value", "category"}
                or not isinstance(item["value"], str) or not item["value"].strip()
                or item["value"] != item["value"].strip() or len(item["value"]) > 256
                or _RESERVED.search(item["value"]) or not isinstance(item["category"], str)
                or item["category"] not in CATEGORIES):
            raise ValueError("invalid_policy_entity_registry")
        total_chars += len(item["value"])
        if total_chars > 6000:
            raise ValueError("invalid_policy_entity_registry")
        entries.add((item["category"], item["value"]))
    # Explicit allowlist prevents accidental forwarding of gold labels or extra context.
    return {"version": policy["version"], "protected_categories": list(dict.fromkeys(cats)),
            "policy_id": policy.get("policy_id", policy["version"]), "max_text_chars": maximum,
            "instructions": policy.get("instructions", ""),
            "entity_registry": [{"category": category, "value": value} for category, value in sorted(entries)]}


def _occurrences(text: str, quote: str):
    start = 0
    while True:
        pos = text.find(quote, start)
        if pos < 0:
            return
        yield pos, pos + len(quote)
        start = pos + 1


def _equivalent_occurrences(text: str, quote: str):
    """Also mask spelling-case changes in queries; offsets still index raw text."""
    for match in re.finditer(r"(?=(" + re.escape(quote) + r"))", text, re.IGNORECASE):
        yield match.span(1)


def _rule_findings(text: str, source_id: str, policy: dict) -> list[dict]:
    findings = []

    def add(category, start, end, method="rules"):
        while start < end and text[start].isspace():
            start += 1
        while end > start and text[end - 1].isspace():
            end -= 1
        if start < end and category in policy["protected_categories"]:
            findings.append({"source_id": source_id, "start": start, "end": end,
                             "category": category, "policy_id": policy["policy_id"], "method": method})

    # ASCII boundaries allow Chinese field names directly next to numbers, but
    # prevent extracting phone/ID suffixes from a longer identifier. Numeric
    # punctuation also bounds amounts so a comma group cannot become a second
    # short amount candidate.
    amount_number = r"\d+(?:,\d{3})*(?:\.\d+)?(?:万|亿)?"
    patterns = {
        "EMAIL": r"(?<![\w.+-])[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+(?![\w-])",
        "PHONE": r"(?<![A-Za-z0-9_])(?:\+?86[- ]?)?1[3-9]\d{9}(?![A-Za-z0-9_])|(?<![A-Za-z0-9_])\+?\d{1,3}[- .](?:\d[- .]?){7,12}\d(?![A-Za-z0-9_])|(?<![A-Za-z0-9_])\(\d{3}\)[- .]?\d{3}[- .]?\d{4}(?![A-Za-z0-9_])",
        "ID": r"(?<![A-Za-z0-9_])\d{17}[\dXx](?![A-Za-z0-9_])|(?<![A-Za-z0-9_])\d{3}-\d{2}-\d{4}(?![A-Za-z0-9_])",
        "AMOUNT": rf"(?<![A-Za-z0-9_])(?:USD|CNY|RMB|EUR|GBP|人民币|[$¥€£])\s*{amount_number}(?![A-Za-z0-9_,]|\.\d)|(?<![A-Za-z0-9_,.]){amount_number}\s*(?:USD|CNY|RMB|EUR|GBP|美元|人民币|元)(?![A-Za-z0-9_])",
        "DATE": r"(?<!\d)\d{4}[-/]\d{1,2}[-/]\d{1,2}(?!\d)|\d{4}年\d{1,2}月\d{1,2}日|\b(?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2},?\s+\d{4}\b",
    }
    for category, pattern in patterns.items():
        for match in re.finditer(pattern, text, re.IGNORECASE):
            add(category, *match.span())

    # Format-neutral labelled fields. These are generic extractors, not fixture values.
    labels = {"PERSON": r"name|person|姓名|联系人|负责人",
              "ADDRESS": r"address|地址|住址",
              "CUSTOMER": r"customer|client|客户(?:名称)?",
              "PROJECT": r"project(?:\s+(?:name|code))?|项目(?:名称|代号)?",
              "ID": r"ID(?:\s+(?:number|card))?|passport|证件号|身份证号|护照号"}
    for category, label in labels.items():
        pattern = rf"(?<![A-Za-z0-9_])(?:{label})\s*[:：]\s*([^;；\n。!?]+)"
        for match in re.finditer(pattern, text, re.IGNORECASE):
            start, end = match.span(1)
            if end > start and text[end - 1] == ".":
                end -= 1
            add(category, start, end)
    # Simple standalone project references, including the current public-memory style.
    for match in re.finditer(r"(?i:\bproject)\s+([A-Za-z0-9][A-Za-z0-9_-]*)(?![A-Za-z0-9_-])", text):
        if match.group(1).casefold() not in {"is", "was", "has", "had", "will", "name", "code", "identifier", "status", "customer", "budget", "deadline", "the", "a", "an"}:
            add("PROJECT", *match.span(1))
    for item in policy["entity_registry"]:
        for start, end in _equivalent_occurrences(text, item["value"]):
            # Do not identify an ASCII vocabulary entry inside a different word.
            if (start and text[start - 1].isascii() and (text[start - 1].isalnum() or text[start - 1] == "_")
                    and item["value"][0].isascii() and item["value"][0].isalnum()):
                continue
            if (end < len(text) and text[end].isascii() and (text[end].isalnum() or text[end] == "_")
                    and item["value"][-1].isascii() and item["value"][-1].isalnum()):
                continue
            add(item["category"], start, end, method="registry")
    return findings


def detect_sensitive(payload: dict, sensitivity_policy: dict, *, agent=None, mode="combined") -> dict:
    """Detect spans with no labels, permissions or answers supplied to the model.

    Agent quotes must have one exact location, or explicit exact start/end offsets.
    Failed, absent or malformed agent output never becomes a clean empty detection.
    """
    result = {"status": "needs_review", "findings": [], "errors": [], "mode": mode,
              "strategy": DETECTION_STRATEGY if mode == "combined" else f"{mode}_v2",
              "local_calls": 0, "local_calls_complete": True, "agent_elapsed_seconds": 0.0,
              "agent_observations": []}
    try:
        sources, policy = _sources(payload), _policy(sensitivity_policy)
    except ValueError as exc:
        result["errors"] = [str(exc)]
        return result
    if mode not in {"rules", "agent", "combined"}:
        result["errors"] = ["invalid_detection_mode"]
        return result
    result.update(payload_sha256=_digest(payload), policy_version=policy["version"],
                  policy_id=policy["policy_id"], policy_sha256=_digest(policy),
                  protected_categories=policy["protected_categories"])
    all_findings = []
    for source_id, text in sources.items():
        if len(text) > policy["max_text_chars"]:
            result["errors"].append("text_exceeds_local_limit")
            continue
        if _RESERVED.search(text):
            result["errors"].append("reserved_token_in_input")
            continue
        rules = _rule_findings(text, source_id, policy)
        if mode in {"rules", "combined"}:
            all_findings.extend(rules)
        if not text.strip() or not policy["protected_categories"] or mode == "rules":
            continue
        if agent is None:
            result["errors"].append("local_agent_required")
            continue
        try:
            # Independent channels avoid priming the semantic detector with a
            # partial rule extraction. Their validated spans are unioned below.
            response = agent(text=text, source_id=source_id, policy=copy.deepcopy(policy), rule_findings=[])
        except Exception:
            result["local_calls_complete"] = False
            result["errors"].append("local_agent_error")
            continue
        observation = {"source_id_sha256": hashlib.sha256(source_id.encode()).hexdigest()}
        if isinstance(response, dict):
            calls = response.get("local_calls")
            elapsed = response.get("elapsed_seconds")
            if type(calls) is int and 0 <= calls <= 2:
                observation["local_calls"] = calls
                result["local_calls"] += calls
            if isinstance(elapsed, (int, float)) and not isinstance(elapsed, bool) and math.isfinite(elapsed) and elapsed >= 0:
                observation["elapsed_seconds"] = elapsed
                result["agent_elapsed_seconds"] += elapsed
            for key in ("model", "digest", "prompt_version"):
                value = response.get(key)
                if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_.:/-]{1,128}", value):
                    observation[key] = value
            errors = response.get("errors", [])
            if not isinstance(errors, list):
                result["errors"].append("local_agent_unrecognized_error")
            else:
                safe_errors = sorted({value if isinstance(value, str) and value in _AGENT_ERROR_CODES
                                      else "local_agent_unrecognized_error" for value in errors})
                if safe_errors:
                    observation["errors"] = safe_errors
                    result["errors"].extend(safe_errors)
            diagnostics = response.get("diagnostics", [])
            if isinstance(diagnostics, list):
                safe_diagnostics = []
                for item in diagnostics[:8]:
                    if (isinstance(item, dict) and type(item.get("attempt")) is int
                            and item["attempt"] in {0, 1, 2}
                            and isinstance(item.get("stage"), str) and item["stage"] in _AGENT_DIAGNOSTIC_STAGES
                            and isinstance(item.get("code"), str) and item["code"] in _AGENT_DIAGNOSTIC_CODES):
                        safe_diagnostics.append({key: item[key] for key in ("attempt", "stage", "code")})
                    else:
                        safe_diagnostics.append({"attempt": 0, "stage": "output",
                                                 "code": "local_agent_unrecognized_error"})
                if safe_diagnostics:
                    # Earlier repaired errors remain diagnostic only. The final
                    # status/errors above govern whether processing may proceed.
                    observation["diagnostics"] = safe_diagnostics
        if "local_calls" not in observation:
            result["local_calls_complete"] = False
        result["agent_observations"].append(observation)
        if not isinstance(response, dict) or response.get("status") != "ok" or not isinstance(response.get("findings"), list):
            result["errors"].append("local_agent_needs_review")
            continue
        for finding in response["findings"]:
            if (not isinstance(finding, dict) or not isinstance(finding.get("quote"), str)
                    or not finding["quote"] or not isinstance(finding.get("category"), str)
                    or finding["category"] not in CATEGORIES):
                result["errors"].append("invalid_agent_finding")
                continue
            locations = list(_occurrences(text, finding["quote"]))
            if "start" in finding or "end" in finding:
                candidate = (finding.get("start"), finding.get("end"))
                if any(type(value) is not int for value in candidate) or candidate not in locations:
                    result["errors"].append("invalid_agent_span")
                    continue
                locations = [candidate]
            if len(locations) != 1:
                result["errors"].append("ambiguous_agent_quote" if locations else "missing_agent_quote")
                continue
            if finding["category"] not in policy["protected_categories"]:
                result["errors"].append("agent_category_outside_policy")
                continue
            if finding["category"] in policy["protected_categories"]:
                start, end = locations[0]
                all_findings.append({"source_id": source_id, "start": start, "end": end,
                                     "category": finding["category"], "policy_id": policy["policy_id"],
                                     "method": "agent"})
    # Keep crossing/category-distinct overlaps for evaluation. A completely
    # contained short span of the same category adds no detection coverage and
    # otherwise double-counts a phone/amount suffix as a false positive.
    unique = {}
    for finding in all_findings:
        key = (finding["source_id"], finding["start"], finding["end"], finding["category"])
        if key in unique:
            methods = set(unique[key]["method"].split("+")) | {finding["method"]}
            unique[key]["method"] = "+".join(sorted(methods))
        else:
            unique[key] = dict(finding)
    maximal, furthest = [], {}
    for finding in sorted(unique.values(), key=lambda f: (f["source_id"], f["category"], f["start"], -f["end"])):
        group = (finding["source_id"], finding["category"])
        if finding["end"] <= furthest.get(group, -1):
            continue
        maximal.append(finding)
        furthest[group] = finding["end"]
    result["findings"] = sorted(maximal, key=lambda f: (f["source_id"], f["start"], f["end"], f["category"]))
    result["errors"] = sorted(set(result["errors"]))
    result["status"] = "needs_review" if result["errors"] else "ok"
    return result


@dataclass(frozen=True, repr=False)
class _Entry:
    value: str
    categories: tuple[str, ...]
    sources: tuple[str, ...]


class RestorationMap:
    """Opaque process-memory capability. Never serialize it or its private fields."""
    __slots__ = ("_actor_id", "_request_id", "_policy_version", "_policy_sha256", "_source_payload_sha256", "_nonce", "_entries",
                 "_memories", "_protected_values", "_sensitive_spans")

    def __init__(self, actor_id, request_id, policy_version, policy_sha256, source_payload_sha256, nonce, entries, memories, protected_values, sensitive_spans):
        for name, value in zip(self.__slots__, (actor_id, request_id, policy_version, policy_sha256, source_payload_sha256, nonce, entries,
                                              memories, protected_values, sensitive_spans)):
            object.__setattr__(self, name, value)

    def __setattr__(self, name, value):
        raise AttributeError("restoration maps are immutable")

    def __getstate__(self):
        raise TypeError("restoration maps must remain in process memory")

    def __repr__(self):
        return "<RestorationMap: redacted process-local capability>"


def _authorized(authorizer, source_id, actor_id, policy_version) -> bool:
    try:
        return authorizer(source_id, actor_id, policy_version) is True
    except Exception:
        return False


def _blocked_prepare(error: str) -> dict:
    return {"status": "needs_review", "payload": None, "mapping": None,
            "error": error, "metadata": {}}


def prepare_private_payload(payload: dict, detection: dict, *, actor_id: str,
                            request_id: str, policy_version: str, authorizer: Callable,
                            sensitivity_policy: dict | None = None) -> dict:
    """Replace protected occurrences consistently; keep restoration material local.

    A value detected once is masked at every occurrence, including spelling-case
    variations in queries. The authorized memory supplies the restored spelling.
    Overlapping intervals are merged, so no uncovered sensitive suffix remains.
    All memory sources must be authorized before any cloud payload is produced.
    New callers supply sensitivity_policy to bind the exact current normalized
    policy; a version string alone cannot identify same-version policy changes.
    """
    try:
        sources = _sources(payload)
    except ValueError as exc:
        return _blocked_prepare(str(exc))
    if any(not isinstance(value, str) or not value for value in (actor_id, request_id, policy_version)):
        return _blocked_prepare("invalid_request_scope")
    if (not isinstance(detection, dict) or detection.get("status") != "ok"
            or detection.get("payload_sha256") != _digest(payload)
            or detection.get("policy_version") != policy_version
            or not isinstance(detection.get("policy_sha256"), str)
            or re.fullmatch(r"[a-f0-9]{64}", detection["policy_sha256"]) is None
            or not isinstance(detection.get("findings"), list)):
        return _blocked_prepare("detection_not_valid_for_payload")
    if sensitivity_policy is not None:
        try:
            current_policy = _policy(sensitivity_policy)
        except ValueError:
            return _blocked_prepare("invalid_sensitivity_policy")
        if (detection["policy_sha256"] != _digest(current_policy)
                or current_policy["version"] != policy_version
                or detection.get("policy_id") != current_policy["policy_id"]
                or detection.get("protected_categories") != current_policy["protected_categories"]):
            return _blocked_prepare("detection_policy_mismatch")
    if any(_RESERVED.search(text) for text in sources.values()):
        return _blocked_prepare("reserved_token_in_input")
    if any(not _authorized(authorizer, sid, actor_id, policy_version) for sid in sources if sid != QUERY_SOURCE):
        return _blocked_prepare("memory_authorization_failed")

    values: dict[str, set[str]] = {}
    preferred_memory_values: dict[str, str] = {}
    for finding in detection["findings"]:
        if not isinstance(finding, dict):
            return _blocked_prepare("invalid_detection_finding")
        sid, start, end = finding.get("source_id"), finding.get("start"), finding.get("end")
        category = finding.get("category")
        if (not isinstance(sid, str) or sid not in sources or type(start) is not int or type(end) is not int
                or not 0 <= start < end <= len(sources[sid]) or not isinstance(category, str) or category not in CATEGORIES
                or category not in detection.get("protected_categories", [])
                or finding.get("policy_id") != detection.get("policy_id")):
            return _blocked_prepare("invalid_detection_finding")
        original_value = sources[sid][start:end]
        values.setdefault(original_value, set()).add(category)
        if sid != QUERY_SOURCE:
            preferred_memory_values.setdefault(original_value.casefold(), original_value)

    # Expand matching values before unioning overlaps; no original memory ids are sent.
    intervals: dict[str, list[dict]] = {}
    for sid, text in sources.items():
        candidates = []
        for value, categories in values.items():
            candidates.extend({"start": start, "end": end, "categories": set(categories)}
                              for start, end in _equivalent_occurrences(text, value))
        merged = []
        for item in sorted(candidates, key=lambda x: (x["start"], x["end"])):
            if merged and item["start"] < merged[-1]["end"]:
                merged[-1]["end"] = max(merged[-1]["end"], item["end"])
                merged[-1]["categories"].update(item["categories"])
            else:
                merged.append(item)
        intervals[sid] = merged

    nonce = secrets.token_hex(12).upper()
    value_info = {}
    for sid, items in intervals.items():
        for item in items:
            value = sources[sid][item["start"]:item["end"]]
            info = value_info.setdefault(value.casefold(), {"value": value, "categories": set(), "sources": set()})
            info["categories"].update(item["categories"])
            if sid != QUERY_SOURCE:
                if not info["sources"]:
                    info["value"] = preferred_memory_values.get(value.casefold(), value)
                info["sources"].add(sid)
    tokens, entries = {}, {}
    for index, (value, info) in enumerate(value_info.items(), 1):
        category = next(iter(info["categories"])) if len(info["categories"]) == 1 else "MIXED"
        token = f"[PVT_{nonce}_{category}_{index}]"
        tokens[value] = token
        entries[token] = _Entry(info["value"], tuple(sorted(info["categories"])), tuple(sorted(info["sources"])))
    transformed, plaintext_segments = {}, []
    for sid, text in sources.items():
        parts, cursor = [], 0
        for item in intervals[sid]:
            unchanged = text[cursor:item["start"]]
            plaintext_segments.append(unchanged)
            parts.extend((unchanged, tokens[text[item["start"]:item["end"]].casefold()]))
            cursor = item["end"]
        plaintext_segments.append(text[cursor:])
        transformed[sid] = "".join(parts) + text[cursor:]
    prepared = {"query": transformed[QUERY_SOURCE],
                "memories": [{"source_id": f"m_{nonce}_{index}", "text": transformed[m["source_id"]]}
                             for index, m in enumerate(payload["memories"], 1)]}
    # Any uncovered original sensitive value means the transformation failed closed.
    # Check unchanged plaintext, not incidental substring collisions in fresh
    # random identifiers (e.g. the protected one-letter name "A" in a nonce).
    if any(value.casefold() in text.casefold() for value in values for text in plaintext_segments):
        return _blocked_prepare("protected_value_remains_in_payload")
    mapping = RestorationMap(actor_id, request_id, policy_version, detection["policy_sha256"], _digest(payload), nonce, entries,
                             {sid: text for sid, text in sources.items() if sid != QUERY_SOURCE}, tuple(values),
                             {sid: tuple((item["start"], item["end"]) for item in items)
                              for sid, items in intervals.items() if sid != QUERY_SOURCE})
    return {"status": "ok", "payload": prepared, "mapping": mapping, "error": None,
            "metadata": {"replacement_count": sum(map(len, intervals.values())), "token_count": len(entries),
                         "policy_version": policy_version, "policy_sha256": detection["policy_sha256"],
                         "detection_strategy": detection.get("strategy"), "payload_sha256": _digest(prepared)}}


def restore_answer(answer: str, mapping: RestorationMap, *, actor_id: str, request_id: str,
                   policy_version: str, authorizer: Callable,
                   sensitivity_policy: dict | None = None) -> dict:
    """Validate one fact and current authority; optionally verify full policy content.

    New callers pass sensitivity_policy, including its independently supplied
    entity registry, so a policy change without a version increment is blocked.
    """
    def block(code):
        return {"status": "blocked", "answer": None, "error": code}

    if not isinstance(mapping, RestorationMap):
        return block("invalid_restoration_map")
    if (actor_id, request_id, policy_version) != (mapping._actor_id, mapping._request_id, mapping._policy_version):
        return block("restoration_scope_mismatch")
    if sensitivity_policy is not None:
        try:
            current_policy = _policy(sensitivity_policy)
        except ValueError:
            return block("invalid_sensitivity_policy")
        if current_policy["version"] != policy_version or _digest(current_policy) != mapping._policy_sha256:
            return block("restoration_policy_mismatch")
    if not isinstance(answer, str) or not answer.strip():
        return block("invalid_answer")
    value = answer.strip()
    if value == "UNKNOWN":
        return {"status": "ok", "answer": "UNKNOWN", "error": None}
    if value in mapping._entries:
        entry = mapping._entries[value]
        if not entry.sources:
            return block("query_only_value_has_no_evidence")
        # Conservative joint dependency: do not infer independent source legitimacy.
        if not all(_authorized(authorizer, sid, actor_id, policy_version) for sid in entry.sources):
            return block("restoration_authorization_failed")
        return {"status": "ok", "answer": entry.value, "error": None}
    if _RESERVED.search(value) or _TOKEN.search(value):
        return block("unknown_or_embedded_token")
    # A refusal containing a secret must not pass through as a harmless refusal.
    if any(secret.casefold() in value.casefold() for secret in mapping._protected_values):
        return block("raw_protected_value_in_answer")
    if len(value) > 256 or any(c in value for c in "\r\n;；。!！?？") or not any(c.isalnum() for c in value):
        return block("not_a_single_fact")
    # Only exact, bounded evidence substrings can pass as non-sensitive literals.
    supported = []
    for sid, memory in mapping._memories.items():
        for start, end in _occurrences(memory, value):
            left = start == 0 or not (memory[start - 1].isalnum() and value[0].isalnum())
            right = end == len(memory) or not (memory[end].isalnum() and value[-1].isalnum())
            sensitive = any(start < p_end and end > p_start for p_start, p_end in mapping._sensitive_spans.get(sid, ()))
            if left and right and not sensitive:
                supported.append(sid)
                break
    if not supported:
        return block("literal_has_no_memory_evidence")
    if not all(_authorized(authorizer, sid, actor_id, policy_version) for sid in supported):
        return block("restoration_authorization_failed")
    return {"status": "ok", "answer": value, "error": None}
