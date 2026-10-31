# x86 ADX carry-chain subset

The scalar decoder recognizes Intel ADX `ADCX` and `ADOX` in 16-bit and
32-bit contexts with 32-bit operands, and in 64-bit mode with 32-bit or 64-bit
operands. Intel's instruction reference specifies 32-bit operands outside
64-bit mode. `ADCX` requires the `66 0F 38 F6 /r` encoding; `ADOX` requires
`F3 0F 38 F6 /r`. The destination is a read/write GPR, and the second operand
is a read-only GPR or memory value. Reserved prefix combinations and LOCK are
not accepted.

`evaluate_x86_adx` is a pure value evaluator. Callers provide both input values
and the incoming CF/PF/ZF/SF/OF values. ADCX consumes and replaces CF while
preserving OF and the other represented flags. ADOX consumes and replaces OF
while preserving CF and the other represented flags. It uses modulo-width
addition and unsigned carry detection, including the incoming chain bit; it
does not perform a host signed addition. `evaluate_x86_adx_instruction`
validates the decoded shape before delegating. Memory acquisition and the
machine-state update remain the caller's responsibility.

Decoded instructions retain the generic whole-FLAGS register dependency for
existing consumers and additionally set `x86_flags_read_mask` and
`x86_flags_write_mask` to CF for ADCX or OF for ADOX. These optional masks let
data-flow clients preserve the independence of the two chains. Runtime
instruction execution, CPUID feature enforcement, and fused ADCX/ADOX sequence
recovery are also outside this slice.

Encoding and flag behavior follow the [Intel 64 and IA-32 Architectures
Software Developer's Manual, Volume 2](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-2a-manual.pdf).
