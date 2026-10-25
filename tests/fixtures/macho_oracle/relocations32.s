.text
.globl _caller
_caller:
  calll _callee
  retl
.section __TEXT,__other,regular,pure_instructions
.globl _callee
_callee:
  retl
.data
.globl _datum
_datum:
  .long _callee
  .long _callee - _caller + 4
