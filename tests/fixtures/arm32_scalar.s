.syntax unified
.arch armv7-a
.arm
.text
.global arm32_scalar
arm32_scalar:
    b .+8
    and r0, r1, #255
    eor r3, r2, r1, lsl #4
    sub r0, r1, #4
    rsb r0, r1, #0
    add r0, pc, #4
    adc r0, r1, r2
    sbc r0, r1, #1
    rsc r0, r1, #1
    tst r0, #255
    teq r0, r1
    cmp r0, #1
    cmn r0, #1
    orr r0, r1, r2
    mov r0, #0xff000000
    bic r0, r1, #15
    mvn r0, r1
    addsne r3, r2, #1
    movs r0, #0xff000000
    movs r0, r1, lsl r2
    mov r0, r1, lsr #32
    mov r0, r1, asr #32
    mov r0, r1, rrx
    mov pc, lr
    ldr r0, [r1, #4]
    ldr r0, [r1, #4]!
    ldr r0, [r1], #4
    ldr r0, [r1, #-4]
    str r0, [r1, r2, lsl #2]
    ldr r0, [pc, #4]
    ldr r0, [pc, #-4]
    ldrb r0, [r1, #1]
    ldrh r0, [r1, #2]
    ldrsb r0, [r1, #2]
    ldrsh r0, [r1, #2]
    strh r0, [r1, #2]
    ldr pc, [r1, #4]
    stmdb sp!, {r4, lr}
    ldmia sp!, {r4, pc}
    stmia r1, {r0, r2}
    stmib r1, {r0, r2}
    stmda r1, {r0, r2}
    stmdb r1, {r0, r2}
