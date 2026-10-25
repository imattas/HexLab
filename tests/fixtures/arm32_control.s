.syntax unified
.arch armv7-a
.arm
.text
.global arm32_control
arm32_control:
    b .+8
    bl .-4
    bne .-4
    ble .+8
    blxeq r3
    blx .+8
    blx .+10
    bx lr
    bxne lr
    blx r3
    nop
    nopne
    bkpt #0x1234
    svc #0x345678
    svcne #0x123
