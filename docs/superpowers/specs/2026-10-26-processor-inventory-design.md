# Processor inventory design

## Intent

Make the decoder's supported architecture/mode combinations discoverable from
the library and CLI, so users can see the exact bounded decoder surface before
opening a binary.

## Goals

- Expose a stable, read-only list of canonical decode contexts.
- Derive every row's display name and maximum instruction size from the existing
  `processor_capabilities` gate, rather than duplicate decoder truth.
- Add `hexlab_cli processors` for concise human-readable output.
- State clearly that an enabled decoder subset is not proof of full ISA,
  assembler, lifter, or debugger coverage.

## Approaches

- Keep a second hand-maintained CSV only: easy to edit, but it can drift from
  actual runtime support.
- Enumerate canonical contexts in the processor library and query the existing
  capability function: recommended because it makes the running decoder the
  source of truth while keeping documentation concise.
- Add a full per-instruction/layer coverage registry: more complete but crosses
  decoder, decompiler, debugger, and UI ownership boundaries; defer that larger
  inventory until those layers expose reliable coverage metadata.

## Design

The processor library exports a span of canonical `DecodeContext` entries.
Each entry is materialized as an inventory record using
`processor_capabilities`, which supplies the enabled status, name, byte limit,
and unsupported reason. The CLI prints supported records with architecture,
execution mode, byte order, maximum instruction size, and the decoder's own
subset label. It does not infer support in later layers.

## Limits

The inventory covers decoder contexts only. It does not claim complete
instruction-set coverage or enumerate assembler, analysis, decompiler, or
debugger support. Contexts with non-default raw-profile settings are described
by their canonical architecture/mode row and remain configurable separately.
