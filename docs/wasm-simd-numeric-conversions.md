# WebAssembly SIMD numeric conversion lifting

The Wasm lifter models the ten standard SIMD numeric conversions as unary
operations over one `v128` stack value, producing one `v128` stack value. The
instruction's canonical mnemonic is retained as the unary operation name, so
the numeric conversion, signedness, and lane selection stay explicit in IR.
Each operator rejects unexpected immediates or a mnemonic that does not match
its decoded subopcode.

| Subopcode | Operation | Lane behavior |
| --- | --- | --- |
| `0x5e` | `f32x4.demote_f64x2_zero` | Demote the two `f64` lanes to the two low `f32` lanes; the two high `f32` lanes are zero. |
| `0x5f` | `f64x2.promote_low_f32x4` | Promote the two low `f32` lanes to `f64`; the high two source lanes are ignored. |
| `0xf8` | `i32x4.trunc_sat_f32x4_s` | Truncate four `f32` lanes toward zero to signed `i32`, saturating out-of-range values. |
| `0xf9` | `i32x4.trunc_sat_f32x4_u` | Truncate four `f32` lanes toward zero to unsigned `i32`, saturating out-of-range values. |
| `0xfa` | `f32x4.convert_i32x4_s` | Convert four signed `i32` lanes to `f32`. |
| `0xfb` | `f32x4.convert_i32x4_u` | Convert four unsigned `i32` lanes to `f32`. |
| `0xfc` | `i32x4.trunc_sat_f64x2_s_zero` | Truncate two `f64` lanes toward zero to signed `i32` in the two low lanes; high lanes are zero. |
| `0xfd` | `i32x4.trunc_sat_f64x2_u_zero` | Truncate two `f64` lanes toward zero to unsigned `i32` in the two low lanes; high lanes are zero. |
| `0xfe` | `f64x2.convert_low_i32x4_s` | Convert the two low signed `i32` lanes to `f64`; high source lanes are ignored. |
| `0xff` | `f64x2.convert_low_i32x4_u` | Convert the two low unsigned `i32` lanes to `f64`; high source lanes are ignored. |

For the saturating truncations, NaN becomes zero and finite values outside the
destination range clamp to its minimum or maximum. Positive and negative
infinity clamp to the corresponding bound. The unsuffixed saturating result is
`i32x4`, including for the 64-bit floating source: it is not an `i64x2`
conversion. The `_zero` variants fill the two unused high 32-bit lanes with
zero.

Integer-to-float conversions use nearest-even rounding when a value is not
exactly representable in the destination format. `demote_f64x2_zero` also uses
nearest-even rounding for inexact `f64` to `f32` conversions.

The decoder already recognizes these subopcodes. The lifter records their
specified lane and saturation behavior in the canonical operation name; it
does not evaluate floating-point values or expand conversions into host
floating-point arithmetic.

References: [WebAssembly SIMD proposal](https://github.com/WebAssembly/spec/blob/main/proposals/simd/SIMD.md),
[WebAssembly Core Specification, vector instructions](https://www.w3.org/TR/2026/CRD-wasm-core-2-20260205/#vector-instructions%E2%91%A8).
