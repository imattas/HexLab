.text
.global owner
.type owner, %function
owner:
    bl callee
    cbz x0, missing_condition
    tbz x1, #5, missing_test
    adr x2, missing_data
    bl missing_call
    b missing_jump
    ret
.section .callee,"ax",@progbits
.global callee
.type callee, %function
callee:
    ret
