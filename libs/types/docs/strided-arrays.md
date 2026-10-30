# Strided arrays

`Type::strided_array` represents fixed-count arrays whose element starts are farther apart than the element object's size. The type's extent is `(count - 1) * stride + element_size`; layout reports this extent and keeps the element alignment. CodeView `LF_STRIDED_ARRAY` import now preserves its encoded stride instead of rejecting arrays with inter-element padding. Ordinary arrays continue to use tightly packed element sizes.

The model intentionally has no per-element padding layout entries; consumers can calculate element `i` at `i * array_stride()`. A zero-count strided array is rejected because CodeView's record supplies a total extent and stride that must describe at least one complete element. Serialization uses type record version 19; older records remain readable and imply a tightly packed stride.
