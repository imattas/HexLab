#pragma once

#include "hexlab/debugger/debugger.hpp"

#include <cstdint>
#include <cstring>
#include <utility>
#include <vector>

namespace hexlab::debugger::detail {

// Linux's i386 NT_PRSTATUS register set, in the order used by the kernel's
// compat ptrace ABI. Keep this layout independent of the debugger host ABI:
// a 64-bit tracer can use it to inspect a 32-bit tracee.
struct I386UserRegisters {
    std::uint32_t ebx, ecx, edx, esi, edi, ebp, eax;
    std::uint32_t xds, xes, xfs, xgs, orig_eax, eip, xcs, eflags, esp, xss;
};

static_assert(sizeof(I386UserRegisters) == 17 * sizeof(std::uint32_t));

template<class T>
inline void add_i386_register(std::vector<RegisterValue>& output, const char* name, T value) {
    RegisterValue item;
    item.name = name;
    item.bytes.resize(sizeof(value));
    std::memcpy(item.bytes.data(), &value, sizeof(value));
    output.push_back(std::move(item));
}

inline std::vector<RegisterValue> i386_register_values(const I386UserRegisters& regs) {
    std::vector<RegisterValue> output;
    output.reserve(17);
#define HEXLAB_I386_ADD(name, field) add_i386_register(output, name, regs.field)
    HEXLAB_I386_ADD("eax", eax); HEXLAB_I386_ADD("ebx", ebx);
    HEXLAB_I386_ADD("ecx", ecx); HEXLAB_I386_ADD("edx", edx);
    HEXLAB_I386_ADD("esi", esi); HEXLAB_I386_ADD("edi", edi);
    HEXLAB_I386_ADD("ebp", ebp); HEXLAB_I386_ADD("esp", esp);
    HEXLAB_I386_ADD("eip", eip); HEXLAB_I386_ADD("eflags", eflags);
    HEXLAB_I386_ADD("cs", xcs); HEXLAB_I386_ADD("ss", xss);
    HEXLAB_I386_ADD("ds", xds); HEXLAB_I386_ADD("es", xes);
    HEXLAB_I386_ADD("fs", xfs); HEXLAB_I386_ADD("gs", xgs);
    HEXLAB_I386_ADD("orig_eax", orig_eax);
#undef HEXLAB_I386_ADD
    return output;
}

inline bool set_i386_register(I386UserRegisters& regs, const RegisterValue& source) {
#define HEXLAB_I386_SET(regname, field) \
    if (source.name == regname) { \
        if (source.bytes.size() != sizeof(regs.field)) return false; \
        std::memcpy(&regs.field, source.bytes.data(), sizeof(regs.field)); \
        return true; \
    }
    HEXLAB_I386_SET("eax", eax); HEXLAB_I386_SET("ebx", ebx);
    HEXLAB_I386_SET("ecx", ecx); HEXLAB_I386_SET("edx", edx);
    HEXLAB_I386_SET("esi", esi); HEXLAB_I386_SET("edi", edi);
    HEXLAB_I386_SET("ebp", ebp); HEXLAB_I386_SET("esp", esp);
    HEXLAB_I386_SET("eip", eip); HEXLAB_I386_SET("eflags", eflags);
    HEXLAB_I386_SET("cs", xcs); HEXLAB_I386_SET("ss", xss);
    HEXLAB_I386_SET("ds", xds); HEXLAB_I386_SET("es", xes);
    HEXLAB_I386_SET("fs", xfs); HEXLAB_I386_SET("gs", xgs);
    HEXLAB_I386_SET("orig_eax", orig_eax);
#undef HEXLAB_I386_SET
    return false;
}

// The kernel exposes i386 GPR and FP/SSE state as separate regsets. Keep
// cross-regset writes all-or-restored so a later failure cannot leave only
// half of an edited stopped context installed.
template<class ApplyFp, class ApplyGpr, class RestoreFp>
inline Status transact_i386_register_sets(bool write_fp, bool write_gpr,
                                          ApplyFp&& apply_fp, ApplyGpr&& apply_gpr,
                                          RestoreFp&& restore_fp) {
    if (write_fp) {
        auto status = apply_fp();
        if (!status) {
            auto rollback = restore_fp();
            if (!rollback)
                return Error{status.error().code, status.error().message +
                             "; rollback of i386 FP/SSE state failed: " + rollback.error().message};
            return status;
        }
    }
    if (write_gpr) {
        auto status = apply_gpr();
        if (!status) {
            if (write_fp) {
                auto rollback = restore_fp();
                if (!rollback)
                    return Error{status.error().code, status.error().message +
                                 "; rollback of i386 FP/SSE state failed: " + rollback.error().message};
            }
            return status;
        }
    }
    return std::monostate{};
}

} // namespace hexlab::debugger::detail
