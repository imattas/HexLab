#pragma once
#include "hexlab/loaders/raw.hpp"
#include <algorithm>
#include <stdexcept>

namespace hexlab::profile_detail {
struct Failure {
    Error error;
};
inline void require(bool condition, std::string message, ErrorCode code = ErrorCode::invalid_argument) {
    if (!condition)
        throw Failure{{code, std::move(message)}};
}
template <class T> T take(Result<T> value) {
    if (!value)
        throw Failure{value.error()};
    return std::move(value.value());
}
template <class F> auto guarded(F action) -> decltype(action()) {
    try {
        return action();
    } catch (const Failure &failure) {
        return failure.error;
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot allocate raw profile data"};
    } catch (const std::length_error &) {
        return Error{ErrorCode::resource_limit, "Raw profile exceeds container bounds"};
    }
}
inline bool utf8(std::string_view value, bool name) {
    std::size_t i = 0;
    while (i < value.size()) {
        const auto first = static_cast<unsigned char>(value[i++]);
        std::uint32_t cp = first, minimum = 0;
        unsigned count = 0;
        if (first >= 0xc2 && first <= 0xdf) {
            cp = first & 31;
            count = 1;
            minimum = 0x80;
        } else if (first >= 0xe0 && first <= 0xef) {
            cp = first & 15;
            count = 2;
            minimum = 0x800;
        } else if (first >= 0xf0 && first <= 0xf4) {
            cp = first & 7;
            count = 3;
            minimum = 0x10000;
        } else if (first >= 0x80)
            return false;
        if (count > value.size() - i)
            return false;
        for (unsigned j = 0; j < count; ++j) {
            const auto next = static_cast<unsigned char>(value[i++]);
            if ((next & 0xc0) != 0x80)
                return false;
            cp = (cp << 6) | (next & 63);
        }
        if (cp < minimum || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff) || cp == 0 || (cp >= 127 && cp <= 159))
            return false;
        if (cp < 32 && (name || (cp != 9 && cp != 10 && cp != 13)))
            return false;
    }
    return true;
}
inline const X86RawDomain *domain(const X86RawProfile &p, AddressSpaceId space) {
    auto found = std::find_if(p.domains.begin(), p.domains.end(), [&](const auto &d) { return d.space == space; });
    return found == p.domains.end() ? nullptr : &*found;
}
inline DecodeContext context(const X86RawProfile &p, const X86RawDomain &d) {
    if (!d.executable)
        return {Architecture::x86, ExecutionMode::unknown, ByteOrder::little, 0, true};
    if (p.environment == X86ImageEnvironment::real386)
        return {Architecture::x86, ExecutionMode::x86_16, ByteOrder::little, 16, true};
    const auto stack = std::find_if(p.domains.begin(), p.domains.end(),
                                    [&](const auto &item) { return item.selector == *p.stack_selector; });
    return {Architecture::x86, d.descriptor->default_big ? ExecutionMode::x86_32 : ExecutionMode::x86_16,
            ByteOrder::little, static_cast<std::uint8_t>(stack->descriptor->default_big ? 32 : 16), true};
}
Result<std::shared_ptr<const Image>> load_segmented(std::shared_ptr<const ByteStorage>, const X86RawProfile &,
                                                    std::stop_token);
} // namespace hexlab::profile_detail
