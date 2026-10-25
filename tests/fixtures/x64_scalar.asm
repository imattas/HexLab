option casemap:none
.code
PUBLIC hexlab_scalar_fixture
hexlab_scalar_fixture PROC
    db 048h,089h,0e5h
    db 04dh,08bh,04ch,024h,008h
    db 048h,08dh,005h,010h,000h,000h,000h
    db 040h,088h,0e0h
    db 088h,0e0h
    db 048h,083h,0c0h,0ffh
    db 0f6h,0e3h             ; mul bl
    db 0f6h,0ebh             ; imul bl
    db 0f6h,0f3h             ; div bl
    db 0f6h,0fbh             ; idiv bl
    db 066h,0f7h,0e3h        ; mul bx
    db 0f7h,0ebh             ; imul ebx
    db 048h,0f7h,0f3h        ; div rbx
    db 049h,0f7h,07ch,024h,008h ; idiv qword ptr [r12+8]
    db 0e8h,0fbh,0ffh,0ffh,0ffh
    db 0ebh,0feh
    db 066h,0c3h
hexlab_scalar_fixture ENDP
END
