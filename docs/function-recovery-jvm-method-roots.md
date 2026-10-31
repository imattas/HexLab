# JVM method roots

Every parsed JVM method with a `Code` attribute contributes a function seed at
the method's validated bytecode entry. This keeps local methods visible even
when the class does not reference them from another method. Abstract and native
methods have no local bytecode and do not receive roots.

The seed records the method-table index and source file offset of the `Code`
bytes. Recovery verifies that the complete bytecode range is initialized,
executable JVM code mapped in the input before publishing the seed. Invalid or
truncated mappings mark the function snapshot incomplete and retain an
unsupported candidate. The root evidence is persisted with derived-cache
version 97 and function-engine fingerprint v97.

This treats a class file's declared method bodies as local code. It does not
resolve class loading, reflection, method handles, bootstrap behavior, or
host-side callback targets, and it does not infer calls that are absent from
the class file's bytecode and bootstrap metadata.
