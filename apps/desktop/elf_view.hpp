#pragma once
#include "project_view.hpp"
namespace hexlab::desktop {
inline wxString elf_symbol_bound(ElfSymbolCountSource source) {
    switch (source) {
    case ElfSymbolCountSource::section:
        return "section";
    case ElfSymbolCountSource::explicit_size:
        return "DT_SYMTABSZ";
    case ElfSymbolCountSource::sysv_hash:
        return "SysV hash";
    case ElfSymbolCountSource::gnu_hash:
        return "GNU hash";
    case ElfSymbolCountSource::unavailable:
        return "unavailable";
    }
    return "unknown";
}
inline wxString elf_number(std::uint64_t value) {
    return wxString::Format("0x%llx", static_cast<unsigned long long>(value));
}
inline wxString elf_symbol_state(ElfSymbolState state) {
    switch (state) {
    case ElfSymbolState::undefined:
        return "undefined";
    case ElfSymbolState::defined:
        return "defined";
    case ElfSymbolState::absolute:
        return "absolute";
    case ElfSymbolState::common:
        return "common";
    case ElfSymbolState::tls:
        return "TLS";
    case ElfSymbolState::reserved:
        return "reserved";
    }
    return "unknown";
}
inline wxString elf_dynamic_tag(std::int64_t tag) {
    switch (tag) {
    case 0:
        return "NULL";
    case 1:
        return "NEEDED";
    case 14:
        return "SONAME";
    case 15:
        return "RPATH";
    case 29:
        return "RUNPATH";
    default:
        return wxString::Format("tag %lld", static_cast<long long>(tag));
    }
}
inline wxString elf_kind(std::uint16_t type) {
    return type == 1 ? "REL" : type == 2 ? "EXEC" : type == 3 ? "DYN" : "unknown";
}
} // namespace hexlab::desktop
