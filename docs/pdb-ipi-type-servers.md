# PDB IPI references across type servers

`import_pdb_function_ids(root_ids, root_guid, root_age, servers, graph,
imported)` adds a bounded join for `LF_FUNC_ID` and `LF_MFUNC_ID` records in
the root PDB and in each exact-identity type server already present in the
resolved `PdbTypeServerSet`. Each server IPI stream is read from that server's
own database. Results retain the owning PDB GUID and age, owning flattened TPI
namespace, local IPI index and record extent, encoded local TPI index, and the
resolved function-type namespace.

Function type and member-owner selectors are translated only through the
owning PDB's root or nested type-server map. The join requires an exact
namespace/index pair in the combined TPI graph and an imported signature at
that same pair. Unsupported leaves are counted. Missing or malformed server
IPI streams, unmapped selectors, missing TPI records, wrong record kinds,
unrepresentable signatures, invalid parent scopes, and parent-scope cycles
remain unresolved with diagnostics. Duplicate namespace/index pairs reject
the combined graph rather than choosing one record.

This slice covers IPI records present in the root PDB and resolved type-server
set. It does not fetch identities outside that set, persist IPI records, or
infer identity from display names. Member-owner agreement requires an exact
mapped type index; it does not canonicalize a forward aggregate to its
completed ODR definition. The pre-existing single-PDB import API remains
available and unchanged in behavior.
