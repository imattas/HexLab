.text
.globl _caller
_caller:
  callq _callee
  movb $0x12, _datum(%rip)
  movl $0x12345678, _datum(%rip)
  retq
.section __TEXT,__other,regular,pure_instructions
.globl _callee
_callee:
  retq
.data
.globl _datum
_datum:
  .quad _callee
  .quad _callee - _caller + 4
