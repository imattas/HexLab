# Non-x86 reference producer provenance

Dataflow-resolved references from RISC-V 32/64, A32/Thumb, AArch64, MIPS32/64,
and PowerPC32/64 now retain bounded producer instruction IDs. This applies to
register-derived memory addresses, address-building immediates, and indirect
control-flow targets. The current instruction remains the reference source; the
producer list records earlier instructions that contributed to the tracked
register value.

The provenance pass consumes targets already resolved by each architecture's
address analysis. It does not create additional targets. It tracks immediate
address definitions, single-source register transforms, and full-width static
pointer loads whose contents resolve to a mapped image address. Multi-source
definitions retain producers only when the architecture-specific analysis has
already established the resulting address.

Producer lists are capped at 32 IDs. CFG propagation requires the exact same
register value-producer chain on every incoming path, so paths that produce an
equal address through different instructions lose producer attribution. The
existing bounded CFG propagation limits still apply. Non-x86 references expose
producer IDs only; the dependency-DAG view remains available for x86/x64.
Unresolved loads, unsupported address operations, and architectures without
register-derived address facts remain without producer attribution.
