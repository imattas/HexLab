#include <cstdint>
#include <cstdio>
#if !defined(_M_IX86)
#error This authored execution fixture requires actual 32-bit x86 code generation
#endif
static_assert(sizeof(void *) == 4);
// No arguments or input bytes are accepted. Every executed instruction is an
// authored bounded probe. Effective-address probes use LEA, never dereference
// synthetic addresses. Every stack adjustment is restored in its own block.
void record(const char *name, const char *bytes, uint32_t value, uint32_t flags, uint32_t extra = 0) {
    std::printf("%s %s %08x %08x %08x\n", name, bytes, value, flags, extra);
}
int main() {
    std::puts("HLX86CPU1 pointer=4");
    uint32_t value = 0, flags = 0, delta = 0;
    __asm {
        mov eax,0ffffffffh
        stc
        _emit 0x40
        mov value,eax
        pushfd
        pop flags
    }
    record("inc32", "40", value, flags);
    __asm {
        mov eax,080000000h
        clc
        _emit 0x48
        mov value,eax
        pushfd
        pop flags
    }
    record("dec32", "48", value, flags);
    __asm {
        mov eax,0abcd7fffh
        stc
        _emit 0x66
        _emit 0x40
        mov value,eax
        pushfd
        pop flags
    }
    record("inc16", "6640", value, flags);
    __asm {
        mov eax,01122ff44h
        stc
        _emit 0xfe
        _emit 0xc4
        mov value,eax
        pushfd
        pop flags
    }
    record("incah", "fec4", value, flags);
    __asm {
        push ebx
        push esi
        mov ebx,0ffffh
        mov esi,2
        xor eax,eax
        stc
        _emit 0x67
        _emit 0x8d
        _emit 0x00
        mov value,eax
        pushfd
        pop flags
        pop esi
        pop ebx
    }
    record("lea16", "678d00", value, flags);
    __asm {
        push ebx
        mov ebx,0100h
        mov ecx,3
        xor eax,eax
        stc
        _emit 0x8d
        _emit 0x44
        _emit 0x8b
        _emit 0xfc
        mov value,eax
        pushfd
        pop flags
        pop ebx
    }
    record("lea32", "8d448bfc", value, flags);
    __asm {
        mov edx,esp
        _emit 0x6a
        _emit 0xff
        mov eax,dword ptr[esp]
        mov ecx,esp
        add esp,4
        sub edx,ecx
        mov delta,edx
        mov value,eax
    }
    record("push32", "6aff", value, 0, delta);
    __asm {
        mov edx,esp
        _emit 0x66
        _emit 0x6a
        _emit 0xff
        movzx eax,word ptr[esp]
        mov ecx,esp
        add esp,2
        sub edx,ecx
        mov delta,edx
        mov value,eax
    }
    record("push16", "666aff", value, 0, delta);
    __asm {
        mov edx,esp
        mov eax,0aabbccddh
        _emit 0x66
        _emit 0x68
        _emit 0x34
        _emit 0x12
        _emit 0x66
        _emit 0x58
        mov ecx,esp
        sub edx,ecx
        mov delta,edx
        mov value,eax
    }
    record("pop16", "6658", value, 0, delta);
    return 0;
}
