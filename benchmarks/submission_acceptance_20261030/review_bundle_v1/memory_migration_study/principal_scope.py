"""Exact authenticated user/Agent scopes and explicit legacy cartesian meaning.

These helpers normalize identities already authenticated by the trusted host;
neither an identity dictionary nor a signed grant authenticates a caller. Legacy
independent lists mean their complete cartesian product, never guessed pairs.
"""
from __future__ import annotations

from dataclasses import dataclass


EXACT_PRINCIPAL_SCOPE_VERSION = "exact_user_agent_pairs_v1"
LEGACY_CARTESIAN_SCOPE_VERSION = "independent_user_agent_lists_v1"


def _identifier(value, *, strict=True):
    return (isinstance(value, str) and bool(value) and len(value) <= 256
            and (not strict or value == value.strip()))


@dataclass(frozen=True)
class PrincipalIdentity:
    user_id: str
    agent_id: str

    def __post_init__(self):
        if not all(_identifier(value) for value in (self.user_id, self.agent_id)):
            raise ValueError("invalid_authenticated_principal")

    def to_dict(self):
        return {"user_id": self.user_id, "agent_id": self.agent_id}


def normalize_principal(value):
    """Return the exact pair, rejecting extra fields instead of projecting them."""
    if isinstance(value, PrincipalIdentity):
        return value
    if not isinstance(value, dict) or set(value) != {"user_id", "agent_id"}:
        raise ValueError("invalid_authenticated_principal")
    return PrincipalIdentity(value["user_id"], value["agent_id"])


def normalize_principal_pairs(values):
    if not isinstance(values, (list, tuple)) or not values:
        raise ValueError("invalid_exact_principal_scope")
    identities = {normalize_principal(value) for value in values}
    return [identity.to_dict() for identity in sorted(identities, key=lambda p: (p.user_id, p.agent_id))]


def principal_scope_version(grant):
    """Validate and identify a grant's scope without converting its semantics.

    Old grants retain their original two fields and cartesian meaning. The
    exact mode intentionally omits those fields so old consumers fail closed.
    """
    if not isinstance(grant, dict):
        raise ValueError("invalid_principal_scope")
    if "principal_scope" in grant:
        if "readers" in grant or "allowed_agent_ids" in grant:
            raise ValueError("mixed_principal_scope")
        scope = grant["principal_scope"]
        if (not isinstance(scope, dict) or set(scope) != {"version", "principals"}
                or scope["version"] != EXACT_PRINCIPAL_SCOPE_VERSION):
            raise ValueError("invalid_exact_principal_scope")
        if scope["principals"] != normalize_principal_pairs(scope["principals"]):
            raise ValueError("noncanonical_exact_principal_scope")
        return EXACT_PRINCIPAL_SCOPE_VERSION
    for field in ("readers", "allowed_agent_ids"):
        values = grant.get(field)
        if (not isinstance(values, (list, tuple)) or not values
                or any(not _identifier(value, strict=False) for value in values)):
            raise ValueError("invalid_legacy_cartesian_scope")
    return LEGACY_CARTESIAN_SCOPE_VERSION


def grant_allows_principal(grant, *, user_id, agent_id):
    version = principal_scope_version(grant)
    if version == LEGACY_CARTESIAN_SCOPE_VERSION:
        # Retain the original list-membership semantics, including old IDs.
        return (isinstance(user_id, str) and isinstance(agent_id, str)
                and user_id in grant["readers"] and agent_id in grant["allowed_agent_ids"])
    principal = normalize_principal({"user_id": user_id, "agent_id": agent_id})
    return principal.to_dict() in grant["principal_scope"]["principals"]


def legacy_lists_for_exact_pairs(values, *, owner_id):
    """Explicit lossless downgrade, or reject; never flatten arbitrary pairs.

    Legacy issuance adds the owner as a reader. Require the owner to be an
    existing user as well as a complete product to avoid that extra widening.
    """
    pairs = normalize_principal_pairs(values)
    users = sorted({row["user_id"] for row in pairs})
    agents = sorted({row["agent_id"] for row in pairs})
    if owner_id not in users:
        raise ValueError("legacy_owner_would_expand_scope")
    if len(pairs) != len(users) * len(agents):
        raise ValueError("exact_principal_scope_not_cartesian")
    return {"readers": users, "allowed_agent_ids": agents}
