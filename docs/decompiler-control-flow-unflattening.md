# Bounded control-flow flattening recovery

The native pseudocode formatter has a deliberately narrow pass for recovering
the common switch-dispatch flattening pattern. It runs before ordinary switch
structuring and only rewrites a function when the dispatcher and every state
transition are proven from the lifted CFG and typed IR.

## Accepted shape

The function must contain exactly one complete switch dispatcher whose selector
is a register value. Its CFG successors must exactly equal the case and default
destinations. The entry block and every predecessor of the dispatcher must
assign one constant of the selector's width to that same register, then flow
directly to the dispatcher. The state register must not be read elsewhere, and
no call or intrinsic may write it. Each constant must name an explicit switch
case; the dispatcher default is retained as a destination only for validating
the original graph. The pass redirects each proven transition edge to its case
destination, removes only the proven state assignments and dispatcher, prunes
unreachable blocks, recomputes SSA, and submits the resulting CFG to the normal
structurer.

## Fail-closed boundaries

This does not attempt symbolic execution, infer state values through arithmetic,
recognize memory-backed state, multiple dispatchers, conditional transition
blocks, partial switch tables, or transitions to the default arm. Aliased,
non-constant, multiply assigned, or otherwise live state registers reject the
transformation. Functions outside the bounded CFG limits or whose recovered CFG
still needs fallback formatting retain the original representation and its
diagnostics. The rewrite is therefore an optimization of presentation only;
the original lifted function remains untouched whenever proof is incomplete.
