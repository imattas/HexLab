#pragma once

#include "hexlab/debugger/debugger.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <string_view>

namespace hexlab::debugger::detail {

// Linux x86-64 PTRACE_GETFPREGS/SETFPREGS exposes the 512-byte FXSAVE image.
// Keep its register view pure and host-independent so layout and write
// validation are testable on non-Linux build hosts as well.
inline constexpr std::size_t x86_fxsave_size = 512;
struct X86FxsaveField { std::size_t offset; std::size_t width; };
inline constexpr std::uint64_t x86_avx_xstate_bit = 1ull << 2;
inline constexpr std::uint64_t x86_opmask_xstate_bit = 1ull << 5;
inline constexpr std::uint64_t x86_zmm_hi256_xstate_bit = 1ull << 6;
inline constexpr std::uint64_t x86_hi16_zmm_xstate_bit = 1ull << 7;
inline constexpr std::uint64_t x86_avx512_xstate_mask = x86_avx_xstate_bit | x86_opmask_xstate_bit |
    x86_zmm_hi256_xstate_bit | x86_hi16_zmm_xstate_bit;
inline constexpr bool x86_xcr0_enables_avx(std::uint64_t xcr0) {
    constexpr std::uint64_t required = (1ull << 1) | (1ull << 2);
    return (xcr0 & required) == required;
}
struct X86XstateLayout {
    std::size_t ymm_upper_offset;
    std::size_t component_size;
    std::uint64_t supported_features;
    std::size_t opmask_offset{};
    std::size_t opmask_size{};
    std::size_t zmm_hi256_offset{};
    std::size_t zmm_hi256_size{};
    std::size_t hi16_zmm_offset{};
    std::size_t hi16_zmm_size{};
};

inline std::uint64_t x86_xstate_bv(std::span<const std::byte> image);
inline void x86_set_xstate_bv(std::span<std::byte> image, std::uint64_t value);
inline constexpr std::size_t x86_xmm_offset(std::size_t index);

struct X86Avx512Register { bool vector; std::size_t index; };

inline std::optional<X86Avx512Register> parse_x86_avx512_register(std::string_view name) {
    const bool vector = name.starts_with("zmm");
    if (!vector && (name.size() < 2 || name.front() != 'k')) return {};
    const auto digits = name.substr(vector ? 3 : 1);
    if (digits.empty() || digits.size() > 2) return {};
    std::size_t index = 0;
    for (const auto digit : digits) {
        if (digit < '0' || digit > '9') return {};
        index = index * 10 + static_cast<std::size_t>(digit - '0');
    }
    if (vector ? index >= 32 : index >= 8) return {};
    return X86Avx512Register{vector, index};
}

inline bool x86_avx512_state_available(const X86XstateLayout& layout) {
    return (layout.supported_features & x86_avx512_xstate_mask) == x86_avx512_xstate_mask &&
        layout.opmask_size >= 8 * sizeof(std::uint64_t) &&
        layout.zmm_hi256_size >= 16 * 32 && layout.hi16_zmm_size >= 16 * 64;
}

inline bool x86_avx512_register_name(std::string_view name) {
    return parse_x86_avx512_register(name).has_value();
}

inline Result<std::vector<RegisterValue>> x86_avx512_register_values(
    std::span<const std::byte> image, const X86XstateLayout& layout) {
    if (!x86_avx512_state_available(layout) || image.size() < 576 ||
        layout.opmask_offset > image.size() || layout.opmask_size > image.size() - layout.opmask_offset ||
        layout.zmm_hi256_offset > image.size() || layout.zmm_hi256_size > image.size() - layout.zmm_hi256_offset ||
        layout.hi16_zmm_offset > image.size() || layout.hi16_zmm_size > image.size() - layout.hi16_zmm_offset ||
        layout.ymm_upper_offset > image.size() || 256 > image.size() - layout.ymm_upper_offset)
        return Error{ErrorCode::malformed, "Linux x86-64 XSAVE image has no complete AVX-512 register components"};
    std::uint64_t compacted{};
    std::memcpy(&compacted, image.data() + 520, sizeof(compacted));
    if (compacted & (1ull << 63))
        return Error{ErrorCode::unsupported, "compacted Linux x86-64 XSAVE images are not supported"};
    const auto state = x86_xstate_bv(image);
    std::vector<RegisterValue> result;
    result.reserve(40);
    for (std::size_t index = 0; index < 32; ++index) {
        RegisterValue value;
        value.name = "zmm" + std::to_string(index);
        value.bytes.resize(64);
        if (index < 16) {
            if (state & (1ull << 1))
                std::copy_n(image.begin() + static_cast<std::ptrdiff_t>(x86_xmm_offset(index)), 16, value.bytes.begin());
            if (state & x86_avx_xstate_bit)
                std::copy_n(image.begin() + static_cast<std::ptrdiff_t>(layout.ymm_upper_offset + index * 16), 16,
                            value.bytes.begin() + 16);
            if (state & x86_zmm_hi256_xstate_bit)
                std::copy_n(image.begin() + static_cast<std::ptrdiff_t>(layout.zmm_hi256_offset + index * 32), 32,
                            value.bytes.begin() + 32);
        } else if (state & x86_hi16_zmm_xstate_bit) {
            std::copy_n(image.begin() + static_cast<std::ptrdiff_t>(layout.hi16_zmm_offset + (index - 16) * 64), 64,
                        value.bytes.begin());
        }
        result.push_back(std::move(value));
    }
    for (std::size_t index = 0; index < 8; ++index) {
        RegisterValue value;
        value.name = "k" + std::to_string(index);
        value.bytes.resize(sizeof(std::uint64_t));
        if (state & x86_opmask_xstate_bit)
            std::copy_n(image.begin() + static_cast<std::ptrdiff_t>(layout.opmask_offset + index * sizeof(std::uint64_t)),
                        sizeof(std::uint64_t), value.bytes.begin());
        result.push_back(std::move(value));
    }
    return result;
}

inline Status write_x86_avx512_registers(std::span<std::byte> image, const X86XstateLayout& layout,
                                         std::span<const RegisterValue> registers) {
    auto decoded = x86_avx512_register_values(image, layout);
    if (!decoded) return decoded.error();
    std::vector<std::string_view> names;
    names.reserve(registers.size());
    std::uint64_t state = x86_xstate_bv(image);
    for (const auto& reg : registers) {
        if (!x86_avx512_register_name(reg.name))
            return Error{ErrorCode::invalid_argument, "unknown Linux x86-64 AVX-512 register"};
        if (std::find(names.begin(), names.end(), reg.name) != names.end())
            return Error{ErrorCode::invalid_argument, "duplicate Linux x86-64 AVX-512 register write"};
        names.push_back(reg.name);
        const auto parsed = *parse_x86_avx512_register(reg.name);
        if (parsed.vector ? reg.bytes.size() != 64 : reg.bytes.size() != sizeof(std::uint64_t))
            return Error{ErrorCode::invalid_argument, "Linux x86-64 AVX-512 register has incorrect width"};
        if (parsed.vector) {
            if (parsed.index < 16) state |= (1ull << 1) | x86_avx_xstate_bit | x86_zmm_hi256_xstate_bit;
            else state |= x86_hi16_zmm_xstate_bit;
        } else state |= x86_opmask_xstate_bit;
    }
    for (const auto& reg : registers) {
        const auto parsed = *parse_x86_avx512_register(reg.name);
        const auto index = parsed.index;
        if (!parsed.vector) {
            std::copy(reg.bytes.begin(), reg.bytes.end(), image.begin() +
                      static_cast<std::ptrdiff_t>(layout.opmask_offset + index * sizeof(std::uint64_t)));
        } else if (index < 16) {
            std::copy_n(reg.bytes.begin(), 16, image.begin() + static_cast<std::ptrdiff_t>(x86_xmm_offset(index)));
            std::copy_n(reg.bytes.begin() + 16, 16,
                        image.begin() + static_cast<std::ptrdiff_t>(layout.ymm_upper_offset + index * 16));
            std::copy_n(reg.bytes.begin() + 32, 32,
                        image.begin() + static_cast<std::ptrdiff_t>(layout.zmm_hi256_offset + index * 32));
        } else {
            std::copy(reg.bytes.begin(), reg.bytes.end(), image.begin() +
                      static_cast<std::ptrdiff_t>(layout.hi16_zmm_offset + (index - 16) * 64));
        }
    }
    if (!registers.empty()) x86_set_xstate_bv(image, state);
    return std::monostate{};
}

inline std::optional<X86FxsaveField> x86_xstate_ymm_upper_field(std::string_view name,
                                                                const X86XstateLayout& layout) {
    constexpr std::string_view prefix = "ymm";
    constexpr std::string_view suffix = "h";
    if (!name.starts_with(prefix) || !name.ends_with(suffix) || name.size() < 5 || name.size() > 6 ||
        !(layout.supported_features & x86_avx_xstate_bit) || layout.component_size < 16 * 16) return {};
    const auto digits = name.substr(prefix.size(), name.size() - prefix.size() - suffix.size());
    std::size_t index = 0;
    for (const auto digit : digits) {
        if (digit < '0' || digit > '9') return {};
        index = index * 10 + static_cast<std::size_t>(digit - '0');
    }
    if (index >= 16) return {};
    return X86FxsaveField{layout.ymm_upper_offset + index * 16, 16};
}

inline std::uint64_t x86_xstate_bv(std::span<const std::byte> image) {
    std::uint64_t value{};
    if (image.size() >= 520) std::memcpy(&value, image.data() + 512, sizeof(value));
    return value;
}

inline void x86_set_xstate_bv(std::span<std::byte> image, std::uint64_t value) {
    if (image.size() >= 520) std::memcpy(image.data() + 512, &value, sizeof(value));
}

inline Result<std::vector<RegisterValue>> x86_xstate_ymm_upper_register_values(
    std::span<const std::byte> image, const X86XstateLayout& layout) {
    if (!(layout.supported_features & x86_avx_xstate_bit) || layout.component_size < 256 ||
        layout.ymm_upper_offset > image.size() || 256 > image.size() - layout.ymm_upper_offset || image.size() < 576)
        return Error{ErrorCode::malformed, "Linux x86-64 XSAVE image has no complete AVX YMM component"};
    std::uint64_t compacted{};
    std::memcpy(&compacted, image.data() + 520, sizeof(compacted));
    if (compacted & (1ull << 63))
        return Error{ErrorCode::unsupported, "compacted Linux x86-64 XSAVE images are not supported"};
    std::vector<RegisterValue> result;
    result.reserve(16);
    const bool in_use = (x86_xstate_bv(image) & x86_avx_xstate_bit) != 0;
    for (std::size_t index = 0; index < 16; ++index) {
        RegisterValue value;
        value.name = "ymm" + std::to_string(index) + "h";
        value.bytes.resize(16);
        if (in_use)
            std::copy_n(image.begin() + static_cast<std::ptrdiff_t>(layout.ymm_upper_offset + index * 16), 16,
                        value.bytes.begin());
        result.push_back(std::move(value));
    }
    return result;
}

inline Status write_x86_xstate_ymm_upper_registers(std::span<std::byte> image,
                                                   const X86XstateLayout& layout,
                                                   std::span<const RegisterValue> registers) {
    auto validated = x86_xstate_ymm_upper_register_values(image, layout);
    if (!validated) return validated.error();
    std::array<std::optional<X86FxsaveField>, 64> fields{};
    if (registers.size() > fields.size())
        return Error{ErrorCode::resource_limit, "too many Linux x86-64 YMM upper register writes"};
    for (std::size_t index = 0; index < registers.size(); ++index) {
        fields[index] = x86_xstate_ymm_upper_field(registers[index].name, layout);
        if (!fields[index]) return Error{ErrorCode::invalid_argument, "unknown Linux x86-64 YMM upper register"};
        if (registers[index].bytes.size() != 16)
            return Error{ErrorCode::invalid_argument, "Linux x86-64 YMM upper register has incorrect width"};
        for (std::size_t prior = 0; prior < index; ++prior)
            if (registers[prior].name == registers[index].name)
                return Error{ErrorCode::invalid_argument, "duplicate Linux x86-64 YMM upper register write"};
    }
    for (std::size_t index = 0; index < registers.size(); ++index)
        std::copy(registers[index].bytes.begin(), registers[index].bytes.end(),
                  image.begin() + static_cast<std::ptrdiff_t>(fields[index]->offset));
    if (!registers.empty()) x86_set_xstate_bv(image, x86_xstate_bv(image) | x86_avx_xstate_bit);
    return std::monostate{};
}

inline constexpr std::size_t x86_st_offset(std::size_t index) { return 32 + index * 16; }
inline constexpr std::size_t x86_xmm_offset(std::size_t index) { return 160 + index * 16; }

inline std::optional<X86FxsaveField> x86_fxsave_field(std::string_view name) {
    if (name == "fcw") return X86FxsaveField{0, 2};
    if (name == "fsw") return X86FxsaveField{2, 2};
    if (name == "ftw") return X86FxsaveField{4, 1};
    if (name == "fop") return X86FxsaveField{6, 2};
    if (name == "fip") return X86FxsaveField{8, 8};
    if (name == "fdp") return X86FxsaveField{16, 8};
    if (name == "mxcsr") return X86FxsaveField{24, 4};
    const auto indexed = [&](std::string_view prefix, std::size_t count, std::size_t base,
                             std::size_t stride, std::size_t width) -> std::optional<X86FxsaveField> {
        if (!name.starts_with(prefix) || name.size() <= prefix.size() ||
            name.size() > prefix.size() + 2) return {};
        std::size_t index = 0;
        for (const auto digit : name.substr(prefix.size())) {
            if (digit < '0' || digit > '9') return {};
            index = index * 10 + static_cast<std::size_t>(digit - '0');
        }
        if (index >= count) return {};
        return X86FxsaveField{base + index * stride, width};
    };
    if (auto field = indexed("st", 8, 32, 16, 10)) return field;
    return indexed("xmm", 16, 160, 16, 16);
}

// Compat i386 exposes the same 512-byte FXSAVE legacy area through
// NT_X86_XSTATE, but its instruction/data pointers and visible XMM bank use
// the 32-bit ABI. Keep this map separate from the native x86-64 names and
// widths so selectors and upper XMM slots are not misrepresented.
inline std::optional<X86FxsaveField> x86_i386_fxsave_field(std::string_view name) {
    if (name == "fcw") return X86FxsaveField{0, 2};
    if (name == "fsw") return X86FxsaveField{2, 2};
    if (name == "ftw") return X86FxsaveField{4, 1};
    if (name == "fop") return X86FxsaveField{6, 2};
    if (name == "fip") return X86FxsaveField{8, 4};
    if (name == "fcs") return X86FxsaveField{12, 2};
    if (name == "fdp") return X86FxsaveField{16, 4};
    if (name == "fds") return X86FxsaveField{20, 2};
    if (name == "mxcsr") return X86FxsaveField{24, 4};
    const auto indexed = [&](std::string_view prefix, std::size_t count, std::size_t base,
                             std::size_t stride, std::size_t width) -> std::optional<X86FxsaveField> {
        if (!name.starts_with(prefix) || name.size() <= prefix.size() ||
            name.size() > prefix.size() + 1) return {};
        const auto digit = name[prefix.size()];
        if (digit < '0' || digit > '9') return {};
        const auto index = static_cast<std::size_t>(digit - '0');
        if (index >= count) return {};
        return X86FxsaveField{base + index * stride, width};
    };
    if (auto field = indexed("st", 8, 32, 16, 10)) return field;
    return indexed("xmm", 8, 160, 16, 16);
}

inline Result<std::vector<RegisterValue>> x86_i386_fxsave_register_values(
    std::span<const std::byte> image) {
    if (image.size() < x86_fxsave_size)
        return Error{ErrorCode::malformed, "i386 FP register image is shorter than FXSAVE"};
    static constexpr std::array<std::string_view, 9> control_names{
        "fcw", "fsw", "ftw", "fop", "fip", "fcs", "fdp", "fds", "mxcsr"};
    std::vector<RegisterValue> result;
    result.reserve(25);
    const auto append = [&](std::string name, X86FxsaveField field) {
        RegisterValue value;
        value.name = std::move(name);
        value.bytes.assign(image.begin() + static_cast<std::ptrdiff_t>(field.offset),
                           image.begin() + static_cast<std::ptrdiff_t>(field.offset + field.width));
        result.push_back(std::move(value));
    };
    for (const auto name : control_names) append(std::string(name), *x86_i386_fxsave_field(name));
    for (std::size_t index = 0; index < 8; ++index) {
        append("st" + std::to_string(index), {x86_st_offset(index), 10});
        append("xmm" + std::to_string(index), {x86_xmm_offset(index), 16});
    }
    return result;
}

inline Status write_x86_i386_fxsave_registers(std::span<std::byte> image,
                                              std::span<const RegisterValue> registers) {
    if (image.size() < x86_fxsave_size)
        return Error{ErrorCode::malformed, "i386 FP register image is shorter than FXSAVE"};
    std::array<std::optional<X86FxsaveField>, 64> fields{};
    if (registers.size() > fields.size())
        return Error{ErrorCode::resource_limit, "too many i386 FP register writes"};
    for (std::size_t index = 0; index < registers.size(); ++index) {
        fields[index] = x86_i386_fxsave_field(registers[index].name);
        if (!fields[index]) return Error{ErrorCode::invalid_argument, "unknown i386 FP register"};
        if (registers[index].bytes.size() != fields[index]->width)
            return Error{ErrorCode::invalid_argument, "i386 FP register has incorrect width"};
        if (registers[index].byte_order && *registers[index].byte_order != ByteOrder::little)
            return Error{ErrorCode::invalid_argument, "i386 FP register byte order is not little-endian"};
        if (registers[index].name == "mxcsr") {
            std::uint32_t value = 0, mask = 0;
            std::memcpy(&value, registers[index].bytes.data(), sizeof(value));
            std::memcpy(&mask, image.data() + 28, sizeof(mask));
            if (mask == 0) mask = 0x0000ffbf;
            if (value & ~mask)
                return Error{ErrorCode::invalid_argument, "MXCSR edit sets reserved bits"};
        }
        for (std::size_t prior = 0; prior < index; ++prior)
            if (registers[prior].name == registers[index].name)
                return Error{ErrorCode::invalid_argument, "duplicate i386 FP register write"};
    }
    for (std::size_t index = 0; index < registers.size(); ++index) {
        const auto field = *fields[index];
        std::copy(registers[index].bytes.begin(), registers[index].bytes.end(),
                  image.begin() + static_cast<std::ptrdiff_t>(field.offset));
    }
    return std::monostate{};
}

inline Result<std::vector<RegisterValue>> x86_fxsave_register_values(std::span<const std::byte> image) {
    if (image.size() < x86_fxsave_size)
        return Error{ErrorCode::malformed, "x86-64 FP register image is shorter than FXSAVE"};
    static constexpr std::array<std::string_view, 7> control_names{
        "fcw", "fsw", "ftw", "fop", "fip", "fdp", "mxcsr"};
    std::vector<RegisterValue> result;
    result.reserve(31);
    const auto append = [&](std::string name, X86FxsaveField field) {
        RegisterValue value;
        value.name = std::move(name);
        value.bytes.assign(image.begin() + static_cast<std::ptrdiff_t>(field.offset),
                           image.begin() + static_cast<std::ptrdiff_t>(field.offset + field.width));
        result.push_back(std::move(value));
    };
    for (const auto name : control_names) append(std::string(name), *x86_fxsave_field(name));
    for (std::size_t index = 0; index < 8; ++index)
        append("st" + std::to_string(index), {x86_st_offset(index), 10});
    for (std::size_t index = 0; index < 16; ++index)
        append("xmm" + std::to_string(index), {x86_xmm_offset(index), 16});
    return result;
}

inline Status write_x86_fxsave_registers(std::span<std::byte> image,
                                         std::span<const RegisterValue> registers) {
    if (image.size() < x86_fxsave_size)
        return Error{ErrorCode::malformed, "x86-64 FP register image is shorter than FXSAVE"};
    std::array<std::optional<X86FxsaveField>, 64> fields{};
    if (registers.size() > fields.size())
        return Error{ErrorCode::resource_limit, "too many x86-64 FP register writes"};
    for (std::size_t index = 0; index < registers.size(); ++index) {
        const auto field = x86_fxsave_field(registers[index].name);
        if (!field) return Error{ErrorCode::invalid_argument, "unknown x86-64 FP register"};
        if (registers[index].bytes.size() != field->width)
            return Error{ErrorCode::invalid_argument, "x86-64 FP register has incorrect width"};
        if (registers[index].byte_order && *registers[index].byte_order != ByteOrder::little)
            return Error{ErrorCode::invalid_argument, "x86-64 FP register byte order is not little-endian"};
        if (registers[index].name == "mxcsr") {
            std::uint32_t value = 0, mask = 0;
            std::memcpy(&value, registers[index].bytes.data(), sizeof(value));
            std::memcpy(&mask, image.data() + 28, sizeof(mask));
            if (mask == 0) mask = 0x0000ffbf;
            if (value & ~mask)
                return Error{ErrorCode::invalid_argument, "MXCSR edit sets reserved bits"};
        }
        for (std::size_t prior = 0; prior < index; ++prior)
            if (registers[prior].name == registers[index].name)
                return Error{ErrorCode::invalid_argument, "duplicate x86-64 FP register write"};
        fields[index] = field;
    }
    for (std::size_t index = 0; index < registers.size(); ++index) {
        const auto field = *fields[index];
        std::copy(registers[index].bytes.begin(), registers[index].bytes.end(),
                  image.begin() + static_cast<std::ptrdiff_t>(field.offset));
    }
    return std::monostate{};
}

} // namespace hexlab::debugger::detail
