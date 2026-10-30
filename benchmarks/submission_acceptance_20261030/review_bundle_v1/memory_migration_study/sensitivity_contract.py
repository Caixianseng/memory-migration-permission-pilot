"""Optional, trusted CUSTOMER definitions shared by the local detector adapters.

The legacy policy has no category_contract field. These fixed profiles are
selected by the host before extraction; source text cannot supply definitions.
They do not grant access or establish a detector's empirical accuracy.
"""
from __future__ import annotations

from copy import deepcopy

CONTRACT_FIELD = "category_contract"
CONTRACT_VERSION = "customer_category_contract_v1"
STRICT_CUSTOMER_RELATION = "strict_customer_relation"
ANY_SPECIFIC_ORGANIZATION = "any_specific_organization"
_DEFINITIONS = {
    STRICT_CUSTOMER_RELATION: (
        "Full name of a specific organization explicitly identified in visible text as a "
        "customer, client or buyer in the business scope of trusted policy.instructions. "
        "Protect affirmative current and former/historical customer relations. An explicit "
        "not/never-customer relation alone does not qualify. If an organization is named but "
        "its customer relation is absent or ambiguous, return needs_review, not a clean empty "
        "result. Generic roles or definitions are not names; an ordinary word explicitly "
        "used as an organization's actual name can qualify."
    ),
    ANY_SPECIFIC_ORGANIZATION: (
        "Full name of any specific organization, company or cooperative, including legal "
        "suffixes, regardless of whether it is a current, former or non-customer. Generic "
        "roles, organization types, definitions and status words are not names unless "
        "explicitly used as a specific organization's actual name. No customer relation "
        "is required."
    ),
}
_POLICY_FIELDS = frozenset({"version", "protected_categories", "policy_id", "max_text_chars",
                            "instructions", "entity_registry", CONTRACT_FIELD})


def category_contract(profile):
    """Return fresh fixed definition bytes; arbitrary names/definitions are refused."""
    if not isinstance(profile, str) or profile not in _DEFINITIONS:
        raise ValueError("invalid_category_contract")
    return {"ontology_id": profile, "version": CONTRACT_VERSION,
            "definitions": {"CUSTOMER": _DEFINITIONS[profile]}}


def normalize_category_contract(policy):
    """Preserve legacy policies; reject malformed or extra explicit-contract fields."""
    if CONTRACT_FIELD not in policy:
        return None
    if set(policy) - _POLICY_FIELDS:
        raise ValueError("invalid_category_contract")
    supplied = policy[CONTRACT_FIELD]
    if not isinstance(supplied, dict):
        raise ValueError("invalid_category_contract")
    expected = category_contract(supplied.get("ontology_id"))
    if supplied != expected:
        raise ValueError("invalid_category_contract")
    return expected


def bind_category_contract(policy, profile):
    """Bind a host-selected profile to an ordinary existing sensitivity policy.

    This accepts neither source payloads, case identifiers nor evaluation labels.
    Rebinding a different existing contract requires constructing a new policy.
    Full policy validation remains in privacy._policy, as for legacy callers.
    """
    if not isinstance(policy, dict):
        raise ValueError("invalid_category_contract")
    bound = deepcopy(policy)
    existing = normalize_category_contract(bound)
    selected = category_contract(profile)
    if existing is not None and existing != selected:
        raise ValueError("category_contract_already_bound")
    bound[CONTRACT_FIELD] = selected
    normalize_category_contract(bound)
    return bound


def category_contract_identity():
    """Fixed adapter contract registry, included in cache and detector revisions."""
    return {profile: category_contract(profile) for profile in _DEFINITIONS}
