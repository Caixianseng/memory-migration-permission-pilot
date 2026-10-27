"""Prospective source-only routing; no labels, scoring, generation or grants."""
from collections import Counter
from .candidate_context_batch import validate_pool

VERSION = "duplicate_candidate_surface_routing_v1"


def select_context_mode(text, pool):
    """Mark only when returned candidates repeat an identical surface string.

    This does not determine whether a word is an entity, complete missed names,
    or infer sensitivity. Pool/source validation remains mandatory. Exact case
    and Unicode equality are fixed; there is no semantic or answer-based route.
    """
    validate_pool(text, pool)
    counts = Counter(candidate["text"] for candidate in pool["candidates"])
    repeated = sorted(name for name, count in counts.items() if count > 1)
    return {"version": VERSION, "mode": "marked" if repeated else "plain",
            "repeated_surface_count": len(repeated), "pool_sha256": pool["pool_sha256"],
            "reason": "duplicate_returned_surface" if repeated else "no_duplicate_returned_surface"}
