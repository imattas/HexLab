#include "hexlab/loaders/raw.hpp"
#include "x86_profile_internal.hpp"
namespace hexlab {
Result<bool> validate_raw_coordinates(const RawOptions &o) {
    if (o.arm_profile) {
        if (o.x86_profile)
            return Error{ErrorCode::invalid_argument, "Raw ARM and x86 profiles are mutually exclusive"};
        auto expected = make_arm_raw_options(*o.arm_profile);
        if (!expected)
            return expected.error();
        const auto &e = expected.value();
        if (o.architecture != e.architecture || o.mode != e.mode || o.base != e.base || o.entry != e.entry ||
            o.readable != e.readable || o.writable != e.writable || o.executable != e.executable)
            return Error{ErrorCode::invalid_argument, "Raw fields disagree with embedded ARM profile"};
        return true;
    }
    if (o.x86_profile) {
        auto expected = make_x86_raw_options(*o.x86_profile);
        if (!expected)
            return expected.error();
        const auto &e = expected.value();
        if (o.architecture != e.architecture || o.mode != e.mode || o.base != e.base || o.entry != e.entry ||
            o.readable != e.readable || o.writable != e.writable || o.executable != e.executable)
            return Error{ErrorCode::invalid_argument, "Raw fields disagree with the embedded segment profile"};
        return true;
    }
    const bool legacy = o.architecture == Architecture::x86 && o.mode == ExecutionMode::x86_32;
    const bool long_mode = o.architecture == Architecture::x86_64 && o.mode == ExecutionMode::x86_64;
    const bool a64 = o.architecture == Architecture::arm64 && o.mode == ExecutionMode::a64;
    const bool m6502 = o.architecture == Architecture::mos6502 && o.mode == ExecutionMode::m6502;
    const bool rv32 = o.architecture == Architecture::riscv32 && o.mode == ExecutionMode::rv32;
    const bool rv64 = o.architecture == Architecture::riscv64 && o.mode == ExecutionMode::rv64;
    const bool mips64 = o.architecture == Architecture::mips64 && o.mode == ExecutionMode::mips64;
    const bool ppc32 = o.architecture == Architecture::powerpc && o.mode == ExecutionMode::ppc32;
    const bool ppc64 = o.architecture == Architecture::powerpc && o.mode == ExecutionMode::ppc64;
    if (!ppc32 && !ppc64 && o.order != ByteOrder::little)
        return Error{ErrorCode::invalid_argument, "Explicit raw byte order is currently available only for PowerPC"};
    if (!legacy && !long_mode && !a64 && !m6502 && !rv32 && !rv64 && !mips64 && !ppc32 && !ppc64)
        return Error{ErrorCode::unsupported, "Raw architecture/mode must be x86-32, x86-64, A64, MOS 6502, RV32I, RV64I, MIPS64, PPC32 or PPC64"};
    if (a64 && ((o.entry && (o.entry->offset & 3)) || (!o.entry && o.executable && (o.base.offset & 3))))
        return Error{ErrorCode::invalid_argument, "A64 raw code entry must be four-byte aligned"};
    if (legacy && o.base.offset > UINT32_MAX)
        return Error{ErrorCode::overflow, "Raw base exceeds the 32-bit address domain"};
    if (m6502 && (o.base.offset > UINT16_MAX || (o.entry && o.entry->offset > UINT16_MAX)))
        return Error{ErrorCode::overflow, "Raw MOS 6502 base and entry must fit its 16-bit address space"};
    if (rv32 && (o.base.offset > UINT32_MAX || (o.entry && o.entry->offset > UINT32_MAX)))
        return Error{ErrorCode::overflow, "Raw RV32I base and entry must fit its 32-bit address space"};
    if (ppc32 && (o.base.offset > UINT32_MAX || (o.entry && o.entry->offset > UINT32_MAX)))
        return Error{ErrorCode::overflow, "Raw PPC32 base and entry must fit its 32-bit address space"};
    if ((rv32 || rv64) && ((o.entry && (o.entry->offset & 3)) || (!o.entry && o.executable && (o.base.offset & 3))))
        return Error{ErrorCode::invalid_argument, "RISC-V raw code entry must be four-byte aligned"};
    if ((mips64 || ppc32 || ppc64) && ((o.entry && (o.entry->offset & 3)) || (!o.entry && o.executable && (o.base.offset & 3))))
        return Error{ErrorCode::invalid_argument, "MIPS64/PowerPC raw code entry must be four-byte aligned"};
    if (o.entry && (o.entry->space != o.base.space || o.entry->offset < o.base.offset))
        return Error{ErrorCode::invalid_argument, "Raw entry must use the mapping's address space and follow its base"};
    if (legacy && o.entry && o.entry->offset > UINT32_MAX)
        return Error{ErrorCode::overflow, "Raw entry exceeds the 32-bit address domain"};
    return true;
}
Result<std::shared_ptr<const Image>> load_raw(std::shared_ptr<const ByteStorage> storage, const RawOptions &o,
                                              std::stop_token stop) {
    if (stop.stop_requested())
        return Error{ErrorCode::canceled, "Raw loading canceled"};
    if (!storage)
        return Error{ErrorCode::invalid_argument, "Raw loader requires input storage"};
    auto valid = validate_raw_coordinates(o);
    if (!valid)
        return valid.error();
    if (o.x86_profile)
        return profile_detail::load_segmented(std::move(storage), *o.x86_profile, stop);
    ImageLayout layout{{o.base.space, static_cast<uint8_t>(o.arm_profile || o.mode == ExecutionMode::x86_32 || o.mode == ExecutionMode::rv32 || o.mode == ExecutionMode::ppc32 ? 32 :
                                                            o.mode == ExecutionMode::m6502 ? 16 : 64),
                        1, o.order},
                       o.architecture,
                       o.mode,
                       {{"raw", o.base, storage->size(), {0}, storage->size(), o.readable, o.writable, o.executable}},
                       {}};
    if (o.entry)
        layout.entries.push_back(*o.entry);
    else if (!o.arm_profile && storage->size() != 0 && o.executable)
        layout.entries.push_back(o.base);
    if (o.arm_profile) {
        auto normalized = make_arm_raw_options(*o.arm_profile, stop);
        if (!normalized)
            return normalized.error();
        const auto &profile = *normalized.value().arm_profile;
        layout.arm_profile.emplace();
        for (std::size_t n = 0; n < profile.ranges.size(); ++n) {
            if (stop.stop_requested())
                return Error{ErrorCode::canceled, "ARM raw mapping canceled"};
            const auto &range = profile.ranges[n];
            layout.arm_profile->ranges.push_back({{o.base.space, range.begin},
                                                  range.size,
                                                  range.kind,
                                                  {{ArmContextSourceKind::raw_declaration, 0, n + 1, {}}}});
        }
        if (profile.entry)
            layout.arm_profile->roots.push_back({{o.base.space, profile.entry->offset},
                                                 profile.entry->mode,
                                                 profile.entry->known_thumb_it_clear,
                                                 {{ArmContextSourceKind::raw_declaration, 0, 0, {}}}});
    }
    return Image::create(std::move(storage), std::move(layout));
}
} // namespace hexlab
