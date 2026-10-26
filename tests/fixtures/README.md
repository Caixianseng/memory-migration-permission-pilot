# Portable offline test fixtures

`legacy_acl_contract.py` freezes the actual `Principal` and `RecordACL` class
definitions used by the former local qualification application. The definitions
and decorator are copied unchanged, with line endings normalized to LF. The
provenance JSON records the original relative source path, full original file
SHA-256, source line ranges, original segment hashes and the normalized excerpt
hash. Tests verify the excerpt hash before using this contract.

This is a controlled **research-application ACL**, not a native Mem0 ACL or proof
of any vendor's authorization semantics. Only the two standard-library-only
definitions are distributed. Importing them does not start a server, load a
backend or access any model or credentials.

`native_archive_layout.py` separately creates explicitly synthetic temporary
files for source-archive and launcher tests. Its scripts raise if executed; its
model, DLL and executable placeholders are not usable assets. Those tests mock
native worker construction and never import or load the placeholders. They
verify archive ordering, target-only injection and rejection of a corrupted SDK
inventory, rather than claim a real native-backend run.
