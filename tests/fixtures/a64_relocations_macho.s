.text
.globl _owner
_owner:
    bl _callee
    bl _missing_call
    adrp x0, _data@PAGE
    add x0, x0, _data@PAGEOFF
    ret
.section __TEXT,__other,regular,pure_instructions
.globl _callee
_callee:
    ret
.data
_data:
    .quad 0
