.text
.global a64_scalar
a64_scalar:
    b .+8
    bl .-4
    b.ne .-4
    b.al .+8
    b.nv .+8
    cbz x0, .+8
    cbnz w30, .-4
    tbnz w1, #5, .+8
    tbz x2, #63, .-4
    br x3
    blr x4
    ret x30
    brk #0x123
    nop
    movz x0, #0x1234
    movk x1, #0xabcd, lsl #16
    movn w2, #0
    add x0, sp, #16
    subs xzr, x0, #1
    add sp, x0, #1, lsl #12
    adr x0, .+8
    ldr x0, [sp, #24]
    strb wzr, [x1, #1]
    ldrb w2, [x3, #4095]
    ldrh w4, [x5, #8190]
    str w6, [x7, #16380]
    str x8, [x9, #32760]
