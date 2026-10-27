# SSA input validation

`to_ssa` validates modeled register-output lists before assigning versions.
Call and intrinsic writes are capped at 256 registers per statement. Every
output register must have a nonzero width, and the same bank/index/width/high
byte view cannot appear twice in one output list. Intrinsic output formulas
may be omitted for opaque results; when present, they must contain exactly one
non-null expression per register output.

These checks prevent ambiguous multiple SSA definitions from being assigned to
one statement and bound work on malformed IR. They do not add architectural
register-alias canonicalization: distinct register views remain separate SSA
variables and must be normalized by the lifter when the architecture requires
write-through or zero-extension behavior.
