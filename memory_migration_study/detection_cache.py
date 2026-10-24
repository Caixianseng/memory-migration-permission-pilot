"""Bounded process-local cache for validated semantic detections, never grants.

Only successful, completely validated outputs are cached. Entries store spans,
not text, pseudonyms or restoration maps. Every consumer still performs current
authorization, fresh rule checks, propagation, egress checks and restoration.
"""
from __future__ import annotations

from collections import OrderedDict
import copy
import hashlib
import hmac
import json
import secrets
import time

from .privacy import _digest, _policy, detect_sensitive

CACHE_VERSION = "scoped_semantic_cache_v1"


def detector_revision(agent):
    """Compact signed-label version binding the trusted full detector contract."""
    identity = agent.cache_identity()
    if not isinstance(identity, dict) or not identity:
        raise ValueError("detector_identity_required")
    json.dumps(identity, allow_nan=False)
    return "sha256:" + _digest(identity)


class DetectionCache:
    def __init__(self, *, max_entries=256, ttl_seconds=300, clock=time.monotonic):
        if type(max_entries) is not int or not 1 <= max_entries <= 4096:
            raise ValueError("invalid_cache_capacity")
        if type(ttl_seconds) not in (int, float) or not 0 < ttl_seconds <= 3600:
            raise ValueError("invalid_cache_ttl")
        self.max_entries, self.ttl_seconds, self.clock = max_entries, ttl_seconds, clock
        self.__entries, self.__secret = OrderedDict(), secrets.token_bytes(32)
        self.__counts = dict(hits=0, misses=0, bypasses=0, expired=0, evictions=0, stores=0)

    def __repr__(self):
        return f"<DetectionCache: {len(self.__entries)} local entries; contents redacted>"

    def __getstate__(self):
        raise TypeError("detection caches cannot be serialized")

    def clear(self):
        self.__entries.clear()

    def stats(self):
        return dict(self.__counts, entries=len(self.__entries), version=CACHE_VERSION)

    def bind(self, agent, *, scope):
        """scope comes from the trusted caller AFTER current access validation.

        A detector must expose a current, JSON-serializable cache_identity(). A
        missing or invalid identity bypasses reuse instead of guessing a version.
        Model-provided metadata is never used as the cache identity.
        """
        if not isinstance(scope, dict) or not scope:
            raise ValueError("trusted_cache_scope_required")
        scope = copy.deepcopy(scope)

        def wrapped(*, text, source_id, policy, rule_findings):
            try:
                identity = agent.cache_identity()
                if not isinstance(identity, dict) or not identity:
                    raise ValueError("missing_identity")
                identity_before = _digest(identity)
                # Include the full normalized policy, not only its version label.
                material = {"cache": CACHE_VERSION, "scope": scope, "detector": identity,
                            "source_id": source_id, "text": text, "policy": _policy(policy),
                            "rule_findings": rule_findings}
                serialized = json.dumps(material, ensure_ascii=False, sort_keys=True,
                                        separators=(",", ":"), allow_nan=False).encode()
            except (AttributeError, TypeError, ValueError):
                self.__counts["bypasses"] += 1
                return agent(text=text, source_id=source_id, policy=policy, rule_findings=rule_findings)
            key = hmac.new(self.__secret, serialized, hashlib.sha256).digest()
            now = self.clock()
            entry = self.__entries.get(key)
            if entry is not None and now - entry["created"] >= self.ttl_seconds:
                del self.__entries[key]
                self.__counts["expired"] += 1
                entry = None
            if entry is not None:
                self.__entries.move_to_end(key)
                self.__counts["hits"] += 1
                return {"status": "ok", "errors": [], "diagnostics": [],
                        "findings": [{"quote": text[a:b], "start": a, "end": b, "category": cat}
                                     for a, b, cat in entry["spans"]],
                        "local_calls": 0, "elapsed_seconds": 0.0, "cache_hit": True,
                        **entry["metadata"]}
            self.__counts["misses"] += 1
            response = agent(text=text, source_id=source_id, policy=policy, rule_findings=rule_findings)
            # Reuse the independent host validator, with no new model call.
            validation = detect_sensitive({"query": "", "memories": [{"source_id": "cache_check", "text": text}]},
                                          policy, mode="agent", agent=lambda **_: response)
            try:
                unchanged = _digest(agent.cache_identity()) == identity_before
            except (AttributeError, TypeError, ValueError):
                unchanged = False
            if validation["status"] == "ok" and validation["local_calls_complete"] and unchanged:
                spans = []
                for f in response["findings"]:
                    # Validation has checked exact, unique or explicitly indexed
                    # quotes. Store raw offsets; outer detection applies its own
                    # current rules and boundary/propagation logic on every hit.
                    start = f["start"] if "start" in f else text.index(f["quote"])
                    end = f["end"] if "end" in f else start + len(f["quote"])
                    spans.append((start, end, f["category"]))
                obs = validation["agent_observations"][0]
                metadata = {k: obs[k] for k in ("model", "digest", "prompt_version") if k in obs}
                self.__entries[key] = {"created": self.clock(), "spans": tuple(spans), "metadata": metadata}
                self.__entries.move_to_end(key)
                self.__counts["stores"] += 1
                while len(self.__entries) > self.max_entries:
                    self.__entries.popitem(last=False)
                    self.__counts["evictions"] += 1
            return response
        return wrapped
