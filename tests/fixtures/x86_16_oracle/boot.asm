; Original fixed boot probes for HexLab tests. No user input is executed.
; NASM flat image, SeaBIOS floppy boot, QEMU TCG pentium3 model.
bits 16
org 0x7c00
    jmp 0:boot
boot:
    cli
    xor ax,ax
    mov ds,ax
    mov es,ax
    mov ss,ax
    mov esp,0x7000
    cld
    mov [boot_drive],dl
    sti
    mov bx,0x7e00
    mov ax,0x0210                 ; Read only our sixteen fixed stage2 sectors.
    mov cx,0x0002
    xor dh,dh
    mov dl,[boot_drive]
    int 0x13
    jc boot_failed
    cli
    jmp 0:stage2
boot_failed:
    mov dx,0xe9
    mov al,'F'
    out dx,al
    cli
.halt: hlt
    jmp .halt
boot_drive: db 0
times 510-($-$$) db 0
dw 0xaa55

%macro RECORD 1
    mov si,name_%1
    call emit
%endmacro
%macro COPY32 2
    mov esi,%1
    mov edi,%2
    mov ecx,%1_end-%1
    a32 rep movsb
%endmacro

stage2:
    xor ax,ax
    mov ds,ax
    mov es,ax
    mov ss,ax
    mov esp,0x7000
    cld
    mov si,header
    call puts
    mov eax,0x11220000
    mov ax,0x1234
    inc ax
    RECORD real_operand16
    add eax,1
    RECORD real_operand32

    mov ax,0x1000
    mov ds,ax
    mov ax,0x2000
    mov ss,ax
    mov esp,0x7000
    mov word [0x10],0x1111
    mov word [ss:0x10],0x2222
    mov bx,0x10
    xor eax,eax
    mov ax,[bx]
    RECORD real_ds_bx
    mov bp,0x10
    xor eax,eax
    mov ax,[bp]
    RECORD real_ss_bp
    mov byte [0x10],0x5a
    mov ax,0x1001
    mov es,ax
    xor eax,eax
    mov al,[es:0]
    RECORD real_alias
    xor ax,ax
    mov ds,ax
    mov ss,ax
    mov esp,0x7000

    in al,0x92
    and al,0xfe
    or al,2
    out 0x92,al
    mov byte [0x500],0x11
    mov ax,0xffff
    mov es,ax
    mov byte [es:0x510],0x22
    in al,0x92
    and al,0xfc
    out 0x92,al
    xor eax,eax
    mov al,[es:0x510]
    RECORD real_a20_disabled
    in al,0x92
    and al,0xfe
    or al,2
    out 0x92,al
    xor eax,eax
    mov al,[es:0x510]
    RECORD real_a20_enabled

%ifndef QEMU_SAFE_ONLY
    mov word [13*4],real_gp_handler
    mov word [13*4+2],0
    mov ax,[es:0xffff]            ;386-style real segment limit, not A20 wrapping.
real_limit_resume:
    movzx eax,word [real_gp_count]
    RECORD real_limit_faults
%endif

    mov ax,0x1000
    mov es,ax
    mov si,real_far_code
    xor di,di
    mov cx,real_far_code_end-real_far_code
    rep movsb
    call 0x1000:0
    RECORD real_far_stack
    lgdt [gdtr]
    lidt [idtr]
    mov eax,cr0
    or eax,1
    mov cr0,eax
    jmp 0x08:protected16

protected16:
    mov ax,0x10
    mov ds,ax
    mov es,ax
    mov ss,ax
    mov esp,0x7000
    mov eax,0x33440000
    mov ax,0x5678
    inc ax
    RECORD pm_operand16
    add eax,1
    RECORD pm_operand32
    push ax
    mov eax,esp
    pop bx
    RECORD pm_stack_value16
    push eax
    mov eax,esp
    pop ebx
    RECORD pm_stack_value32

    mov esp,0x10000
    push ax
    mov eax,esp
    pop bx
    mov esp,0x7000
    RECORD pm_stack_address16
    mov ax,0x18
    mov ss,ax
    mov esp,0x10000
    push ax
    mov eax,esp
    pop bx
    mov esp,0x7000
    RECORD pm_stack_address32
    mov ax,0x10
    mov ss,ax

%ifdef QEMU_SAFE_ONLY
    ; TCG omits ordinary data limit checks and truncates EIP at this page
    ; boundary. The full image runs unchanged under the precise Bochs oracle.
    jmp finish
%endif
    COPY32 sequential_code,0xffff
    jmp dword 0x08:0xffff
sequential_resume:
    RECORD pm_high_sequential
    COPY32 untaken_code,0xfffd
    jmp dword 0x08:0xfffd
untaken_resume:
    RECORD pm_high_untaken

    COPY32 high_call16_code,0x10020
    COPY32 low_call16_code,0x500
    jmp dword 0x08:0x10020
call16_resume:
    RECORD pm_high_call16_return
    COPY32 taken_code,0xffff
    COPY32 low_taken_code,0x80
    xor ax,ax
    jmp dword 0x08:0xffff
taken_resume:
    RECORD pm_high_taken

    COPY32 far16_code,0x40000
    COPY32 far32_code,0x40020
    call 0x30:0
    RECORD pm_far16_stack
    call dword 0x30:0x20
    RECORD pm_far32_stack

    mov dword [gp_resume],limit_resume
    mov ax,0x28
    mov ds,ax
    mov ax,[0xffff]               ; Full word crosses descriptor limitFFFF.
limit_resume:
    mov ax,0x10
    mov ds,ax
    mov eax,[gp_count]
    RECORD pm_limit_faults
    COPY32 one_nop,0x4ffff
    mov dword [gp_resume],code_limit_resume
    jmp dword 0x30:0xffff        ;One valid byte, then EIP10000 exceeds CS.limit.
code_limit_resume:
    mov eax,[gp_fault_eip]
    RECORD pm_code_limit_eip
    mov eax,[gp_count]
    RECORD pm_code_limit_faults
finish:
    mov si,done
    call puts
%ifndef BOCHS_HALT
    mov dx,0xf4
    mov eax,0x10
    out dx,eax                    ;32-bit exit device: (0x10<<1)|1 =33.
    mov dx,0xb004                 ; Bochs ACPI poweroff, reached only outside QEMU.
    mov ax,0x2000
    out dx,ax
%endif
    cli
.halt: hlt
    jmp .halt

; Printing never uses DS for strings: real probes intentionally vary DS/SS.
puts:
    mov dx,0xe9
.byte:
    cs lodsb
    test al,al
    jz .end
    out dx,al
    jmp .byte
.end: ret
%ifndef QEMU_SAFE_ONLY
real_gp_handler:
    push bp
    mov bp,sp
    mov word [ss:bp+2],real_limit_resume
    inc word [cs:real_gp_count]
    pop bp
    iret
%endif
emit:
    pushad
    mov ebp,eax
    call puts
    mov al,'='
    out dx,al
    mov ecx,8
.hex:
    rol ebp,4
    mov eax,ebp
    and al,0xf
    add al,'0'
    cmp al,'9'
    jbe .digit
    add al,7
.digit:
    out dx,al
    loop .hex
    mov al,10
    out dx,al
    popad
    ret

bits 32
gp_handler:
    push eax
    push ds
    mov ax,0x10
    mov ds,ax
    inc dword [gp_count]
    mov eax,[ss:esp+12]
    mov [gp_fault_eip],eax
    mov eax,[gp_resume]
    mov [ss:esp+12],eax            ; Error32, EIP32, CS32, FLAGS32; two saved registers.
    mov dword [ss:esp+16],0x08    ;Resume in the original flat code segment.
    pop ds
    pop eax
    add esp,4
    iretd
bits 16
align 8
gdt:
    dq 0
    dq 0x008f9a000000ffff         ;08: D0 code, flat, effective limitFFFFFFFF.
    dq 0x008f92000000ffff         ;10: B0 data/stack, flat, large limit.
    dq 0x00cf92000000ffff         ;18: B1 data/stack, flat, large limit.
    dq 0x00cf9a000000ffff         ;20: D1 code for exception gate.
    dq 0x000092020000ffff         ;28: B0 data, base20000, byte limitFFFF.
    dq 0x00009a040000ffff         ;30: D0 code, base40000, byte limitFFFF.
gdt_end:
gdtr: dw gdt_end-gdt-1
    dd gdt
align 8
idt:
    times 13 dq 0
    dw gp_handler,0x20
    db 0,0x8e
    dw 0
idt_end:
idtr: dw idt_end-idt-1
    dd idt
gp_count: dd 0
gp_resume: dd 0
gp_fault_eip: dd 0
real_gp_count: dw 0

; These bytes execute at fixed addresses. Expected results are independent of
; HexLab's decoder. Far jumps return to the low boot code without truncating
; the measured value in EAX.
real_far_code:
    mov eax,esp
    retf
real_far_code_end:
sequential_code:
    db 0x90,0x66,0xe8,0,0,0,0,0x66,0x58,0xea
    dw sequential_resume,0x08
sequential_code_end:
untaken_code:
    db 0x31,0xc0,0x75,0,0x66,0xe8,0,0,0,0,0x66,0x58,0xea
    dw untaken_resume,0x08
untaken_code_end:
high_call16_code:
    db 0xe8
    dw 0x04dd
high_call16_code_end:
low_call16_code:
    pop ax
    movzx eax,ax
    db 0xea
    dw call16_resume,0x08
low_call16_code_end:
taken_code:
    db 0x74,0x7f
taken_code_end:
low_taken_code:
    mov eax,0x80
    db 0xea
    dw taken_resume,0x08
low_taken_code_end:
far16_code:
    mov eax,esp
    retf
far16_code_end:
far32_code:
    mov eax,esp
    retfd
far32_code_end:
one_nop: db 0x90
one_nop_end:

header: db 'HX16_ORACLE_V1',10,0
done: db 'DONE',10,0
%macro NAME 1
name_%1: db %str(%1),0
%endmacro
NAME real_operand16
NAME real_operand32
NAME real_ds_bx
NAME real_ss_bp
NAME real_alias
NAME real_a20_disabled
NAME real_a20_enabled
NAME real_far_stack
NAME pm_operand16
NAME pm_operand32
NAME pm_stack_value16
NAME pm_stack_value32
NAME pm_stack_address16
NAME pm_stack_address32
NAME pm_high_sequential
NAME pm_high_untaken
NAME pm_high_call16_return
NAME pm_high_taken
NAME pm_far16_stack
NAME pm_far32_stack
NAME pm_limit_faults
NAME real_limit_faults
NAME pm_code_limit_eip
NAME pm_code_limit_faults
%if ($-$$)>17*512
    %error "Authored stage2 exceeds the sixteen loaded sectors"
%endif
times 1474560-($-$$) db 0
