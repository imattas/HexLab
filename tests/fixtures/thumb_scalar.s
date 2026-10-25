.syntax unified
.arch armv7-a
.thumb
.text
.global thumb_scalar
.thumb_func
thumb_scalar:
1:
    b.w .+8
    bl .+8
    b.w .-4
    bne.n 2f
    bne.w 1b
    blx .+8
    cbz r0, 2f
    cbnz r1, 2f
    bx lr
    blx r3
2:
    nop
    bkpt #0x12
    svc #0x34
    it eq
    moveq r0, #1
    ite ne
    movne r1, #2
    moveq r1, #3
    lsls r0, r1, #1
    lsrs r0, r1, #1
    asrs r0, r1, #1
    adds r0, r1, r2
    adds r0, r1, #2
    movs r0, #255
    cmp r0, #1
    adds r0, #1
    subs r0, #1
    ands r0, r1
    eors r0, r1
    lsls r0, r1
    lsrs r0, r1
    asrs r0, r1
    adcs r0, r1
    sbcs r0, r1
    rors r0, r1
    tst r0, r1
    rsbs r0, r1, #0
    cmp r0, r1
    cmn r0, r1
    orrs r0, r1
    muls r0, r1, r0
    bics r0, r1
    mvns r0, r1
    add r0, r1
    cmp r8, r0
    mov r0, r1
    mov pc, lr
    ldr r0, [pc, #4]
    str r0, [r1, r2]
    strh r0, [r1, r2]
    strb r0, [r1, r2]
    ldrsb r0, [r1, r2]
    ldr r0, [r1, r2]
    ldrh r0, [r1, r2]
    ldrb r0, [r1, r2]
    ldrsh r0, [r1, r2]
    str r0, [r1, #4]
    ldr r0, [r1, #4]
    strb r0, [r1, #1]
    ldrb r0, [r1, #1]
    strh r0, [r1, #2]
    ldrh r0, [r1, #2]
    str r0, [sp, #4]
    ldr r0, [sp, #4]
    adr.n r0, thumb_end
    add r0, sp, #4
    add sp, #4
    sub sp, #4
    push {r4, lr}
    pop {r4, pc}
    stmia r2!, {r0, r1}
    ldmia r1, {r0, r1}
    b.n 4f
    nop
4:
    .p2align 2
thumb_end:
