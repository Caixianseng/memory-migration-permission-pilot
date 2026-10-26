"""Frozen research-application ACL definitions, not a native Mem0 permission API.

Class definitions are extracted unchanged (LF-normalized) from the old local
qualification source. See legacy_acl_contract.provenance.json and README.md.
Importing this fixture only defines two standard-library-only classes.
"""
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType

# BEGIN FROZEN ACL EXCERPT
@dataclass(frozen=True)
class Principal:
    name: str
    source_scope: str
    actor_id: str
    organization_id: str


class RecordACL:
    """Frozen, server-owned exact readers for a controlled application boundary.

    This is not a native Mem0 ACL and is never inferred from benchmark answers.
    Unknown records/principals fail closed. Existing single-scope mode is unchanged.
    """
    def __init__(self, readers, principal_names):
        known = frozenset(principal_names)
        if not known or any(not isinstance(x, str) or not x for x in known):
            raise ValueError('Nonempty principal names required')
        normalized = {}
        for record_id, names in readers.items():
            if not isinstance(record_id, str) or not record_id or isinstance(names, str):
                raise ValueError('Record ids and explicit reader collections required')
            value = frozenset(names)
            if not value <= known:
                raise ValueError('ACL contains an undeclared principal')
            normalized[record_id] = value
        self.readers = MappingProxyType(normalized)

    def allows(self, principal, record_id):
        return principal.name in self.readers.get(record_id, ())
# END FROZEN ACL EXCERPT
