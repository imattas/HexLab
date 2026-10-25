.section .text
.global _start
.type _start,@function
_start:
    nop
    mov $1, %eax
    xor %ebx, %ebx
    int $0x80
.size _start, .-_start
.section .note.GNU-stack,"",@progbits
