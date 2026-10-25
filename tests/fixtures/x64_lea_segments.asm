option casemap:none
.code
PUBLIC hexlab_lea_gs_absolute
hexlab_lea_gs_absolute PROC
    db 065h,048h,08dh,004h,025h,030h,000h,000h,000h
    ret
hexlab_lea_gs_absolute ENDP
PUBLIC hexlab_lea_gs_base
hexlab_lea_gs_base PROC
    db 065h,048h,08dh,041h,010h
    ret
hexlab_lea_gs_base ENDP
END
