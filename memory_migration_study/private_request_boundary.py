"""Final JSON-body checks for an explicitly controlled raw-bytes transport.

This boundary observes the complete JSON body it hands to the configured host
transport. It cannot attest to unseen Qoder/Harness plugins, HTTP requests made
outside this path, or unregistered sensitive semantics. The transport is a
trusted host capability; it must send these exact bytes without additions.
Ordinary receipts contain no messages, registered values, mappings or response.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import http.client
import json
import re
import threading
import unicodedata


SCOPE = "controlled_http_json_body_at_raw_bytes_transport_boundary"
_UNSET = object()
_UNICODE_ESCAPE = re.compile(r"\\u([0-9a-fA-F]{4})|\\U([0-9a-fA-F]{8})|\\x([0-9a-fA-F]{2})")


class BoundaryTransportError(RuntimeError):
    """A fixed diagnostic; no exception body or response text is retained."""


class _Blocked(ValueError):
    pass


def _canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def _no_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_json_keys")
        result[key] = value
    return result


def _decode(raw):
    return json.loads(raw, object_pairs_hook=_no_duplicate_keys)


def _strings(value):
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise _Blocked("non_string_json_key")
            yield key
            yield from _strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)
    elif isinstance(value, str):
        yield value
    elif value is not None and type(value) not in (bool, int, float):
        raise _Blocked("unsupported_json_value")


def _known_value_forms(text):
    """Conservative known-value matching, including literal Unicode escapes.

    This covers exact/case/Unicode compatibility forms and a bounded escape
    unfolding. It is not a detector for arbitrary encodings or inferred facts.
    """
    forms = set()
    for _ in range(4):
        forms.add(unicodedata.normalize("NFKC", text).casefold())

        def character(match):
            try:
                return chr(int(next(part for part in match.groups() if part is not None), 16))
            except (ValueError, OverflowError):
                return match.group()

        # A JSON string can itself contain a JSON-escaped string. Collapse one
        # literal backslash layer before decoding registered Unicode values.
        changed = _UNICODE_ESCAPE.sub(character, text.replace("\\\\", "\\"))
        try:
            changed = changed.encode("utf-16-le", "surrogatepass").decode("utf-16-le")
        except UnicodeError:
            pass
        if changed == text:
            break
        text = changed
    return forms


def _message_shape(messages):
    return (isinstance(messages, list) and len(messages) == 2
            and all(isinstance(row, dict) and set(row) == {"role", "content"}
                    and isinstance(row["content"], str) and bool(row["content"])
                    for row in messages)
            and [row["role"] for row in messages] == ["system", "user"])


@dataclass(frozen=True, repr=False)
class BoundaryResult:
    receipt: dict
    response: object = field(repr=False)

    def __repr__(self):
        return "<BoundaryResult status=" + repr(self.receipt["status"]) + " response=redacted>"

    def __iter__(self):
        # Supports: receipt, response = boundary.send(...)
        yield self.receipt
        yield self.response

    def __getitem__(self, name):
        if name == "receipt":
            return self.receipt
        if name == "response":
            return self.response
        raise KeyError(name)


class PrivateRequestBoundary:
    """One frozen complete context, fixed inference contract, bounded sends.

    ``expected_messages`` must be the trusted host's entire masked system/user
    pair. A schema, when used, is separately frozen with ``expected_format``;
    arbitrary extra format descriptions cannot be appended later. Registered
    values must come from detection or an independent policy registry, never
    evaluation answers. Keeping unregistered semantics safe is outside scope.
    """

    def __init__(self, expected_messages, registered_values, model_id, max_calls,
                 byte_limit=32768, *, seed=42, expected_format=_UNSET):
        if (not _message_shape(expected_messages)
                or not isinstance(model_id, str)
                or re.fullmatch(r"[A-Za-z0-9_.:/-]{1,256}", model_id) is None
                or type(max_calls) is not int or not 0 <= max_calls <= 1024
                or type(byte_limit) is not int or not 1 <= byte_limit <= 1024 * 1024
                or type(seed) is not int or not 0 <= seed <= 2**31 - 1
                or not isinstance(registered_values, (list, tuple))
                or any(not isinstance(value, str) or not value for value in registered_values)):
            raise ValueError("invalid_private_request_contract")
        self._messages_bytes = _canonical(expected_messages)
        self._model = model_id
        self._limit, self._byte_limit, self._seed = max_calls, byte_limit, seed
        self._format_bytes = None if expected_format is _UNSET else _canonical(expected_format)
        self._known = frozenset(form for value in registered_values for form in _known_value_forms(value))
        self._counts = {"attempted": 0, "succeeded": 0, "failed": 0, "blocked": 0}
        self._lock = threading.RLock()

    def __repr__(self):
        return "<PrivateRequestBoundary: full context and registry redacted>"

    def snapshot(self):
        with self._lock:
            return dict(self._counts)

    def _prepare(self, body):
        if not isinstance(body, dict):
            raise _Blocked("request_dictionary_required")
        # Reject input-only non-JSON values/keys before serialization. The
        # immutable decoded wire representation is still checked separately.
        for _ in _strings(body):
            pass
        try:
            raw = _canonical(body)
        except (TypeError, ValueError, UnicodeError, RecursionError):
            raise _Blocked("request_json_invalid") from None
        if len(raw) > self._byte_limit:
            raise _Blocked("request_byte_limit_exceeded")
        return raw

    def _check_bytes(self, raw):
        try:
            body = _decode(raw)
        except (TypeError, ValueError, UnicodeError):
            raise _Blocked("request_json_invalid") from None
        # Check all keys and values before the allowlist; a leak hidden under an
        # invalid field is still an observed sensitive-value block.
        for text in _strings(body):
            if any(known in form for form in _known_value_forms(text) for known in self._known):
                raise _Blocked("registered_sensitive_value_present")
        required = {"model", "messages", "stream", "options"}
        allowed = required | ({"format"} if self._format_bytes is not None else set())
        if set(body) != allowed:
            raise _Blocked("request_fields_not_registered")
        if body["model"] != self._model or body["stream"] is not False:
            raise _Blocked("model_or_stream_contract_changed")
        if (not _message_shape(body["messages"])
                or _canonical(body["messages"]) != self._messages_bytes):
            raise _Blocked("complete_context_changed")
        options = body["options"]
        if (not isinstance(options, dict) or set(options) != {"num_ctx", "num_predict", "temperature", "seed"}
                or type(options["num_ctx"]) is not int or options["num_ctx"] != 4096
                or type(options["num_predict"]) is not int or options["num_predict"] != 64
                or type(options["temperature"]) not in (int, float) or options["temperature"] != 0
                or type(options["seed"]) is not int or options["seed"] != self._seed):
            raise _Blocked("inference_options_changed")
        if self._format_bytes is not None and _canonical(body["format"]) != self._format_bytes:
            raise _Blocked("output_format_changed")

    def _receipt(self, status, code, raw, *, checked, attempted):
        return {"status": status, "code": code,
                "request_body_sha256": hashlib.sha256(raw).hexdigest() if raw is not None else None,
                "request_body_bytes": len(raw) if raw is not None else None,
                "body_contract_checked": checked, "transport_attempted": attempted,
                "full_request_observed": checked and attempted,
                "observation_scope": SCOPE, "sdk_request_observed": False,
                "model_invocations_verified": False, "counters": dict(self._counts)}

    def send(self, body, transport_bytes):
        """Validate and send the exact immutable bytes once, without retries.

        A transport exception consumes an attempt and returns no response. Its
        message is discarded. The result's safe repr omits response data; callers
        must explicitly handle ``response`` separately from ordinary receipts.
        """
        with self._lock:
            raw, checked = None, False
            try:
                if not callable(transport_bytes):
                    raise _Blocked("raw_bytes_transport_required")
                raw = self._prepare(body)
                self._check_bytes(raw)
                checked = True
                if self._counts["attempted"] >= self._limit:
                    raise _Blocked("transport_attempt_budget_exhausted")
            except (_Blocked, RecursionError) as error:
                self._counts["blocked"] += 1
                code = str(error) if isinstance(error, _Blocked) else "request_json_invalid"
                return BoundaryResult(self._receipt("blocked", code, raw, checked=checked, attempted=False), None)
            self._counts["attempted"] += 1
            try:
                response = transport_bytes(raw)
            except Exception:
                self._counts["failed"] += 1
                return BoundaryResult(self._receipt("transport_failed", "transport_failed", raw,
                                                    checked=True, attempted=True), None)
            self._counts["succeeded"] += 1
            return BoundaryResult(self._receipt("sent", None, raw, checked=True, attempted=True), response)


class LoopbackJSONSender:
    """Fixed local Ollama endpoint; http.client sends bytes without proxies.

    Instantiation does not connect. The host must explicitly call this sender.
    A fresh connection is used once and closed; no implicit retries or remote
    destinations are supported. Headers/URL are fixed, with no credentials.
    """

    def __init__(self, *, timeout=60, max_response_bytes=131072):
        if (type(timeout) not in (int, float) or not 0 < timeout <= 120
                or type(max_response_bytes) is not int or not 1 <= max_response_bytes <= 1024 * 1024):
            raise ValueError("invalid_loopback_transport_limits")
        self.timeout, self.max_response_bytes = timeout, max_response_bytes

    def __call__(self, raw):
        if not isinstance(raw, bytes):
            raise BoundaryTransportError("immutable_request_bytes_required")
        connection = http.client.HTTPConnection("127.0.0.1", 11435, timeout=self.timeout)
        try:
            connection.request("POST", "/api/chat", body=raw, headers={
                "Content-Type": "application/json", "Accept": "application/json",
                "Content-Length": str(len(raw))})
            response = connection.getresponse()
            if response.status < 200 or response.status >= 300:
                raise BoundaryTransportError("local_http_non_success")
            answer = response.read(self.max_response_bytes + 1)
            if len(answer) > self.max_response_bytes:
                raise BoundaryTransportError("local_http_response_oversize")
            parsed = _decode(answer)
            if not isinstance(parsed, dict):
                raise BoundaryTransportError("local_http_response_shape_invalid")
            return parsed
        except BoundaryTransportError:
            raise
        except Exception:
            raise BoundaryTransportError("local_http_transport_or_json_failed") from None
        finally:
            connection.close()
