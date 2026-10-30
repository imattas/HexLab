# MOS6502 accumulator shift reference propagation

The block-local MOS6502 address tracker preserves a known accumulator value
through the accumulator forms `ASL A` and `LSR A`. Propagation requires the
decoder's exact A-register read/write form and expected register effects; the
shift wraps to eight bits and the shift instruction becomes the latest value
producer. A later `TAX` or `TAY` can carry the result into indexed-memory
reference resolution.

Only the accumulator data result is propagated. N/Z/C status updates are not
reported as analysis facts. Memory forms are not treated as accumulator
transforms; `ROL` and `ROR` remain unresolved because their data result depends
on incoming carry.
