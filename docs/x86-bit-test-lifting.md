# x86 Register Bit-Test Lifting

Register-destination `BT`, `BTS`, `BTR`, and `BTC` forms now lift to typed
width-specific intrinsics for 16-, 32-, and 64-bit operands. The bit index is
reduced modulo the register width. `BT` leaves the destination unchanged;
`BTS`, `BTR`, and `BTC` set, clear, or toggle the selected destination bit.
All four forms set CF from the old selected bit.

The outgoing FLAGS expression preserves bits outside the arithmetic condition
set. CF is exact; PF, AF, ZF, SF, and OF are represented as unknown because
the architecture leaves them undefined for this family. Decoder effects read
incoming FLAGS for the preserved bits and write FLAGS for the results. The
existing `evaluate_x86_bit_operation_instruction` helper supplies concrete
register-form values and flag-definedness facts when callers have the input
values.

This lift deliberately covers only a GPR destination and an immediate or
same-width GPR index. Memory bit-string addressing, its signed index-derived
element offset, memory writes, and atomic LOCK behavior remain with the
existing opaque intrinsic path. CPU feature checks are not modeled.
