"""Explicit Qwen3.5 model qualification under the frozen occurrence method.

The prompt, schema, exact-position decoder, byte budgets and one repair are the
existing OccurrenceQwenAgent method. Only the real pinned model identity and an
explicit ``think: false`` request differ. This adapter discovers names from the
full text; it does not add or classify a separately supplied candidate inventory.
No old model alias, global constant mutation or response rewriting is used.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
import time

from . import local_detector as local
from . import occurrence_qwen as occurrence
from .privacy import _policy
from .sensitivity_contract import category_contract_identity

MODEL = "qwen3.5:4b-q4_K_M"
RUNTIME_VERSION = "0.40.8"
ADAPTER_VERSION = "qwen35_frozen_occurrence_adapter_v1"
ENDPOINT = "http://127.0.0.1:11435"
OPTIONS = {"num_ctx": 4096, "num_predict": 1024, "temperature": 0, "seed": 42}


def _request_from_messages(messages, categories):
    return {"model": MODEL, "messages": deepcopy(messages),
            "format": occurrence._policy_schema(categories),
            "stream": False, "keep_alive": "30m", "think": False,
            "options": deepcopy(OPTIONS)}


def build_request(text, source_id, policy, rule_findings, *, repair=False):
    """Pure initial/repair request for byte freezing; no transport or discovery.

    Match the callable's input validation and budgets. A repair appends only the
    unchanged frozen repair prompt; no failed model output or answer is included.
    The driver must bind these exact bytes to real captured requests separately.
    """
    if type(repair) is not bool:
        raise ValueError("invalid_input")
    normalized = _policy(policy)
    if "category_contract" not in normalized:
        raise ValueError("invalid_category_contract")
    data, trusted = occurrence.OccurrenceQwenAgent._validate_inputs(text, source_id, normalized, rule_findings)
    if len(text) > normalized["max_text_chars"]:
        raise ValueError("input_budget_exceeded")
    messages, _ = occurrence.OccurrenceQwenAgent._prepare_messages(data, trusted)
    if occurrence.OccurrenceQwenAgent._request_budget(messages) > 4096:
        raise ValueError("input_budget_exceeded")
    if repair:
        messages = [*messages, {"role": "user", "content": occurrence.REPAIR_PROMPT}]
        if occurrence.OccurrenceQwenAgent._request_budget(messages, repair=True) > 4096:
            raise ValueError("repair_budget_exceeded")
    return _request_from_messages(messages, trusted["protected_categories"])


class Qwen35OccurrenceAgent(occurrence.OccurrenceQwenAgent):
    """A distinct real identity with the unchanged full-text occurrence method.

    ``expected_digest`` must be the qualified full digest from trusted host
    provisioning, never a response-selected digest, truncated ID or old digest.
    Runtime 0.40.8 and the IPv4 loopback endpoint stay fixed. The injected
    transport is for offline tests/captured host transport, as in the old agent.
    A schema/span error permits one repair; transport, health, tools/thinking or
    incomplete generation fail closed without an additional generation attempt.
    """
    max_local_calls = 2

    def __init__(self, *, expected_digest, expected_version=RUNTIME_VERSION,
                 transport=None, timeout_seconds=120):
        if (not isinstance(expected_digest, str)
                or re.fullmatch(r"[0-9a-f]{64}", expected_digest) is None
                or expected_digest == local.DIGEST):
            raise ValueError("qualified_qwen35_digest_required")
        if expected_version != RUNTIME_VERSION:
            raise ValueError("pinned_runtime_required")
        if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 180:
            raise ValueError("invalid_local_timeout")
        if transport is not None and not callable(transport):
            raise ValueError("invalid_local_transport")
        # Do not invoke the old constructor: it deliberately accepts only its
        # old identity. These members always describe the actual new request.
        self.model, self.digest = MODEL, expected_digest
        self.runtime_version, self.timeout = RUNTIME_VERSION, timeout_seconds
        self.transport = transport if transport is not None else self._transport
        self.config = {"endpoint": ENDPOINT, "model": self.model,
                       "expected_version": self.runtime_version,
                       "expected_digest": self.digest, "timeout_seconds": self.timeout}

    def health(self):
        """Check the real new tag and full digest; never rewrite an old reply."""
        version = self.transport("GET", "/api/version")
        tags = self.transport("GET", "/api/tags")
        if not isinstance(version, dict) or version.get("version") != self.runtime_version:
            raise ValueError("local_runtime_mismatch")
        if not isinstance(tags, dict) or not isinstance(tags.get("models"), list):
            raise ValueError("local_model_mismatch")
        matching = [item for item in tags["models"] if isinstance(item, dict) and item.get("name") == self.model]
        if (len(matching) != 1 or not isinstance(matching[0].get("digest"), str)
                or matching[0]["digest"].removeprefix("sha256:") != self.digest):
            raise ValueError("local_model_mismatch")
        return {"version": self.runtime_version, "model": self.model,
                "digest": self.digest, "endpoint": ENDPOINT}

    def cache_identity(self):
        """Host-selected actual identity, including the explicit think setting."""
        return {"adapter_version": ADAPTER_VERSION,
                "implementation_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                "base_implementation_sha256": hashlib.sha256(Path(local.__file__).read_bytes()).hexdigest(),
                "occurrence_implementation_sha256": hashlib.sha256(Path(occurrence.__file__).read_bytes()).hexdigest(),
                "model": self.model, "digest": self.digest, "runtime": self.runtime_version,
                "prompt_version": occurrence.PROMPT_VERSION,
                "prompt_sha256": hashlib.sha256(occurrence.SYSTEM_PROMPT.encode()).hexdigest(),
                "repair_prompt_sha256": hashlib.sha256(occurrence.REPAIR_PROMPT.encode()).hexdigest(),
                "schema_sha256": hashlib.sha256(json.dumps(occurrence.SCHEMA, sort_keys=True).encode()).hexdigest(),
                "position_contract": "one_based_all_exact_substring_occurrences_including_overlaps",
                "category_contracts": category_contract_identity(), "config": deepcopy(self.config),
                "options": deepcopy(OPTIONS), "think": False, "max_local_calls": self.max_local_calls,
                "method": "frozen_occurrence_qwen_full_text",
                "method_changes": ["real_model_identity", "explicit_think_false"]}

    def __call__(self, *, text, source_id, policy, rule_findings):
        # Mechanically retain the frozen occurrence flow. Shared helpers below
        # are inherited directly; model/digest and think are explicit changes.
        started, calls, diagnostics = time.monotonic(), 0, []
        metadata = {"model": self.model, "digest": self.digest,
                    "prompt_version": occurrence.PROMPT_VERSION,
                    "adapter_version": ADAPTER_VERSION, "think": False}

        def diagnose(stage, code):
            diagnostics.append({"attempt": calls, "stage": stage, "code": code})

        def finish(status, findings, errors, repairs=0):
            return {"status": status, "findings": findings, "errors": errors,
                    "diagnostics": diagnostics, "local_calls": calls,
                    "local_calls_complete": True, "quote_wrapper_repairs": repairs,
                    "elapsed_seconds": round(time.monotonic() - started, 6), **metadata}

        try:
            normalized = _policy(policy)
            if "category_contract" not in normalized:
                raise ValueError("invalid_category_contract")
            data, trusted = self._validate_inputs(text, source_id, normalized, rule_findings)
            if len(text) > normalized["max_text_chars"]:
                raise ValueError("input_budget_exceeded")
            messages, metadata["prompt_version"] = self._prepare_messages(data, trusted)
        except (ValueError, TypeError, KeyError) as exc:
            code = local._safe_error_code(exc, "invalid_input_or_policy")
            diagnose("input", code)
            return finish("needs_review", [], [code])
        if self._request_budget(messages) > 4096:
            diagnose("budget", "input_budget_exceeded")
            return finish("needs_review", [], ["input_budget_exceeded"])
        try:
            self.health()
        except Exception as exc:
            diagnose("health", local._safe_error_code(exc, "local_health_failed"))
            return finish("needs_review", [], ["local_health_failed"])
        for attempt in range(2):
            request = _request_from_messages(messages, trusted["protected_categories"])
            calls += 1
            try:
                response = self.transport("POST", "/api/chat", request)
            except Exception as exc:
                diagnose("transport", local._safe_error_code(exc, "local_transport_failed"))
                return finish("needs_review", [], ["local_transport_failed"])
            if not isinstance(response, dict) or response.get("model") != self.model:
                diagnose("envelope", "local_response_model_mismatch")
                return finish("needs_review", [], ["local_response_model_mismatch"])
            if response.get("done") is not True or response.get("done_reason") != "stop":
                diagnose("envelope", "local_generation_incomplete")
                return finish("needs_review", [], ["local_generation_incomplete"])
            message = response.get("message")
            if not isinstance(message, dict) or not isinstance(message.get("content"), str):
                diagnose("envelope", "local_response_invalid")
                return finish("needs_review", [], ["local_response_invalid"])
            if message.get("thinking") or message.get("tool_calls"):
                diagnose("envelope", "unexpected_model_behavior")
                return finish("needs_review", [], ["unexpected_model_behavior"])
            try:
                result = self._validate_output(local._strict_json(message["content"]), text,
                                               trusted["protected_categories"])
            except (ValueError, TypeError, KeyError) as exc:
                diagnose("output", local._safe_error_code(exc, "invalid_schema"))
                if attempt == 1:
                    return finish("needs_review", [], ["format_or_span_invalid"])
                repaired = [*messages, {"role": "user", "content": occurrence.REPAIR_PROMPT}]
                if self._request_budget(repaired, repair=True) > 4096:
                    diagnose("budget", "repair_budget_exceeded")
                    return finish("needs_review", [], ["repair_budget_exceeded"])
                messages = repaired
                continue
            errors = ["semantic_uncertainty"] if result["status"] == "needs_review" else []
            if errors:
                diagnose("semantic", "semantic_uncertainty")
            return finish(result["status"], result["findings"], errors, result["quote_wrapper_repairs"])
        return finish("needs_review", [], ["local_failure"])
