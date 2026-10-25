#pragma once
#include "hexlab/workspace/navigation.hpp"
#include <ostream>
#include <sstream>
namespace hexlab::cli {
inline std::string_view arm_range_label(ArmCodeKind kind) {
    switch (kind) {
    case ArmCodeKind::a32:
        return "a32";
    case ArmCodeKind::thumb:
        return "thumb";
    case ArmCodeKind::data:
        return "data";
    case ArmCodeKind::conflict:
        return "conflict";
    default:
        return "unknown";
    }
}
inline std::string_view mode_label(ExecutionMode mode) {
    switch (mode) {
    case ExecutionMode::x86_16:
        return "x86-16";
    case ExecutionMode::x86_32:
        return "x86-32";
    case ExecutionMode::x86_64:
        return "x86-64";
    case ExecutionMode::a64:
        return "a64";
    case ExecutionMode::jvm:
        return "jvm";
    default:
        return "data";
    }
}
inline void profile_description(std::ostream &out, const Image &image) {
    if (image.layout().architecture == Architecture::mips64)
        out << "Processor: MIPS64 mode=mips64\n";
    if (image.layout().architecture == Architecture::powerpc)
        out << "Processor: PowerPC mode=" << (image.layout().mode == ExecutionMode::ppc32 ? "ppc32" : "ppc64")
            << " endian=" << (image.layout().space.order == ByteOrder::big ? "big" : "little") << '\n';
    if (image.layout().arm_profile) {
        const auto &arm = *image.layout().arm_profile;
        out << "ARM profile: ranges=" << arm.ranges.size() << " roots=" << arm.roots.size() << '\n';
        for (const auto &range : arm.ranges) {
            std::ostringstream coordinate;
            coordinate << "va:" << range.begin.space.value << ":0x" << std::hex << range.begin.offset << " size=0x"
                       << range.size;
            out << "Range: " << coordinate.str() << " mode=" << arm_range_label(range.kind) << '\n';
        }
    }
    const auto &profile = image.layout().x86_profile;
    if (!profile)
        return;
    out << "X86 profile: " << (profile->environment == X86ImageEnvironment::real386 ? "real386" : "protected386")
        << " A20=" << (profile->a20 == A20Policy::enabled ? "enabled" : "disabled") << '\n';
    for (const auto &binding : profile->bindings) {
        auto context = image.decode_context();
        if (binding.space != image.layout().space.id)
            for (const auto &domain : image.layout().domains)
                if (domain.space.id == binding.space) {
                    context = domain.context;
                    break;
                }
        std::ostringstream selector;
        selector << "0x" << std::hex << binding.selector;
        out << "Domain: va:" << std::to_string(binding.space.value) << " selector=" << selector.str()
            << " mode=" << mode_label(context.mode) << " stack=" << std::to_string(context.stack_address_width) << '\n';
    }
}
inline void profile_coordinate(std::ostream &out, const Image &image, Location location,
                               std::string_view label = "logical", bool include_mode = true) {
    const auto *address = std::get_if<Address>(&location);
    if (image.layout().arm_profile && address) {
        const auto *range = image.arm_code_at(*address);
        if (include_mode)
            out << " mode=" << (range ? arm_range_label(range->kind) : "unknown");
        return;
    }
    if (!image.layout().x86_profile || !address || !image.logical_address(*address))
        return;
    out << ' ' << label << '=' << format_location(location, &image);
    if (include_mode) {
        const auto context = image.context_at(*address);
        if (context)
            out << " mode=" << mode_label(context.value().mode);
    }
}
} // namespace hexlab::cli
