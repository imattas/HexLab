# CLR declarative-security metadata

`parse_managed_declarative_security` reads the ECMA-335 `DeclSecurity`
metadata table (table 14). Each row retains its `SecurityAction` numeric value,
resolved `HasDeclSecurity` parent token (TypeDef, MethodDef, or Assembly),
metadata row offset, #Blob index and payload offset, and the exact serialized
PermissionSet bytes.

The parser validates the coded parent against the corresponding table, rejects
duplicate parent/action pairs, checks the tables-stream row extent and #Blob
length prefix, and bounds the table at 250,000 rows, each PermissionSet at
4 MiB, and aggregate payload bytes at 64 MiB. Action values and permission
payloads are retained without interpretation; unknown action values can be
inspected by callers without being mistaken for enforced policy.

This API does not decode declarative-security permission attributes, resolve
external permission types, or grant, deny, or otherwise enforce permissions.
It is metadata retention only. The surrounding managed loader remains partial
for other CLR metadata tables, runtime behavior, and complete CIL semantics.
