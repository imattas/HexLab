.text
.globl _entry
_entry:
  callq _callee
  .data_region
  .long 0x11223344
  .end_data_region
  retq
_callee:
  retq