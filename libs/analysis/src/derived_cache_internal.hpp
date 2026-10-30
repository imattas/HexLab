#pragma once
#include "hexlab/analysis/derived_cache.hpp"
#include "functions_internal.hpp"
#include "source_context_internal.hpp"
namespace hexlab::derived_detail {
using function_detail::Failure;
using function_detail::take;
inline void require(bool value, const char *message, ErrorCode code = ErrorCode::malformed) {
    if (!value)
        throw Failure{{code, message}};
}
inline void canceled(std::stop_token stop) {
    require(!stop.stop_requested(), "Derived cache operation canceled", ErrorCode::canceled);
}
template <class F> auto guarded(F f) -> decltype(f()) {
    try {
        return f();
    } catch (const Failure &failure) {
        return failure.error;
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot allocate derived cache"};
    } catch (const std::length_error &) {
        return Error{ErrorCode::resource_limit, "Derived cache exceeds allocation limits"};
    }
}
struct Writer {
    std::vector<std::byte> bytes;
    std::stop_token stop;
    void append(std::span<const std::byte> value) {
        canceled(stop);
        require(value.size() <= derived_payload_limit - bytes.size(), "Derived cache exceeds 64 MiB budget",
                ErrorCode::resource_limit);
        bytes.insert(bytes.end(), value.begin(), value.end());
    }
    void number(uint64_t value, size_t width = 8) {
        std::array<std::byte, 8> data{};
        require(width <= 8, "Invalid canonical scalar width");
        for (size_t i = 0; i < width; ++i)
            data[width - i - 1] = std::byte(value >> (i * 8));
        append(std::span(data).first(width));
    }
    void flag(bool value) { number(value, 1); }
    void context(DecodeContext value, bool metadata = false) {
        require(metadata ? source_detail::valid_context(value) : processor_capabilities(value).can_decode,
                metadata ? "Invalid derived domain context" : "Derived cache requires an enabled processor context",
                ErrorCode::unsupported);
        number(static_cast<unsigned>(value.architecture), 1);
        number(static_cast<unsigned>(value.mode), 1);
        number(static_cast<unsigned>(value.order), 1);
        number(value.stack_address_width, 1);
        flag(value.segmented_memory);
    }
    void signed_number(int64_t value) { number(value < 0 ? uint64_t(-(value + 1)) * 2 + 1 : uint64_t(value) * 2); }
    void count(size_t value, size_t limit = derived_record_limit) {
        require(value <= limit, "Derived cache table exceeds record limit", ErrorCode::resource_limit);
        number(value, 4);
    }
    void text(std::string_view value, size_t limit = 65536) {
        require(value.size() <= limit, "Derived cache text exceeds field limit", ErrorCode::resource_limit);
        number(value.size(), 4);
        append(std::as_bytes(std::span(value)));
    }
    void address(Address value) {
        number(value.space.value, 4);
        number(value.offset);
    }
    void optional_address(const std::optional<Address> &value) {
        flag(value.has_value());
        if (value)
            address(*value);
    }
    void key(const AnalysisKey &value) {
        number(value.input.size);
        append(value.input.sha256);
        number(value.byte_revision);
        number(value.decision_revision);
        append(value.recipe_fingerprint);
        append(value.engine_fingerprint);
        flag(value.external_input_fingerprint.has_value());
        if (value.external_input_fingerprint)
            append(*value.external_input_fingerprint);
    }
    void reads(const ReadSet &reads) {
        count(reads.ranges().size());
        for (auto range : reads.ranges()) {
            number(range.begin.value);
            number(range.size);
        }
    }
    void stop_record(const FunctionStop &value) {
        address(value.address);
        number(static_cast<unsigned>(value.reason), 1);
        text(value.detail);
    }
    void optional_stop(const std::optional<FunctionStop> &value) {
        flag(value.has_value());
        if (value)
            stop_record(*value);
    }
    void fact_key(FactKey value) {
        number(static_cast<unsigned>(value.kind), 1);
        number(value.id);
    }
};
struct Reader {
    std::span<const std::byte> bytes;
    std::stop_token stop;
    size_t cursor = 0;
    std::span<const std::byte> read(size_t amount) {
        canceled(stop);
        require(amount <= bytes.size() - cursor, "Truncated derived cache");
        auto out = bytes.subspan(cursor, amount);
        cursor += amount;
        return out;
    }
    uint64_t number(size_t width = 8) {
        require(width <= 8, "Invalid cached scalar width");
        uint64_t value = 0;
        for (auto byte : read(width))
            value = (value << 8) | std::to_integer<unsigned>(byte);
        return value;
    }
    bool flag() {
        auto value = number(1);
        require(value <= 1, "Invalid cached boolean");
        return value != 0;
    }
    DecodeContext context(bool metadata = false) {
        DecodeContext value{static_cast<Architecture>(number(1)), static_cast<ExecutionMode>(number(1)),
                            static_cast<ByteOrder>(number(1)), static_cast<std::uint8_t>(number(1)), flag()};
        require(metadata ? source_detail::valid_context(value) : processor_capabilities(value).can_decode,
                metadata ? "Cached domain context is invalid" : "Cached processor context is not enabled",
                ErrorCode::unsupported);
        return value;
    }
    size_t count(size_t minimum, size_t limit = derived_record_limit) {
        auto value = number(4);
        require(minimum > 0 && value <= limit && value <= (bytes.size() - cursor) / minimum,
                "Invalid derived cache record count");
        return static_cast<size_t>(value);
    }
    std::string text(size_t limit = 65536) {
        auto size = number(4);
        require(size <= limit, "Cached text exceeds field budget");
        auto value = read(static_cast<size_t>(size));
        if (value.empty())
            return {};
        return {reinterpret_cast<const char *>(value.data()), value.size()};
    }
    Address address() {
        auto space = number(4);
        return {{static_cast<uint32_t>(space)}, number()};
    }
    std::optional<Address> optional_address() {
        if (!flag())
            return {};
        return address();
    }
    AnalysisKey key(bool has_external_fingerprint = true) {
        AnalysisKey out;
        out.input.size = number();
        auto d = read(32);
        std::copy(d.begin(), d.end(), out.input.sha256.begin());
        out.byte_revision = number();
        out.decision_revision = number();
        d = read(32);
        std::copy(d.begin(), d.end(), out.recipe_fingerprint.begin());
        d = read(32);
        std::copy(d.begin(), d.end(), out.engine_fingerprint.begin());
        if (has_external_fingerprint && flag()) {
            d = read(32);
            Sha256Digest external{};
            std::copy(d.begin(), d.end(), external.begin());
            out.external_input_fingerprint = external;
        }
        return out;
    }
    ReadSet reads() {
        ReadSet out;
        auto size = count(16);
        uint64_t end = 0;
        for (size_t i = 0; i < size; ++i) {
            FileOffset at{number()};
            auto length = number();
            require(length && (!i || at.value > end), "Noncanonical cached read ranges");
            end = take(checked_add(at.value, length));
            take(out.include(at, length));
        }
        return out;
    }
    FunctionStopReason reason() {
        auto value = number(1);
        require(value <= static_cast<unsigned>(FunctionStopReason::image_exclusion),
                "Unknown cached function stop reason");
        return static_cast<FunctionStopReason>(value);
    }
    FunctionStop stop_record() {
        auto at = address();
        auto why = reason();
        return {at, why, text()};
    }
    std::optional<FunctionStop> optional_stop() {
        if (!flag())
            return {};
        return stop_record();
    }
    FactKey fact_key() {
        auto kind = number(1);
        auto id = number();
        require(kind <= static_cast<unsigned>(FactKind::seed) && id, "Invalid cached dependency key");
        return {static_cast<FactKind>(kind), id};
    }
};
std::vector<std::byte> instruction_bytes(const Instruction &, std::stop_token);
inline DecodeContext context_for(std::span<const DomainContext> domains, Address address) {
    auto found = std::lower_bound(domains.begin(), domains.end(), address.space.value,
                                  [](const auto &d, auto id) { return d.space.value < id; });
    require(found != domains.end() && found->space == address.space, "Instruction uses an undeclared source domain");
    const auto end = std::upper_bound(found, domains.end(), address.space.value,
                                      [](auto id, const auto &row) { return id < row.space.value; });
    const auto baseline = found->context;
    const auto next = std::upper_bound(found, end, address.offset,
                                       [](std::uint64_t offset, const auto &row) {
                                           return row.range_size && offset < row.range_begin.offset;
                                       });
    if (next != found) {
        const auto &candidate = *std::prev(next);
        if (candidate.range_size && address.offset >= candidate.range_begin.offset &&
            address.offset - candidate.range_begin.offset < candidate.range_size)
            return candidate.context;
    }
    return baseline;
}
Instruction checked_instruction(std::span<const std::byte>, std::span<const DomainContext>, const Image *,
                                const AnalysisOptions&, std::stop_token);
Sha256Digest checksum(std::span<const std::byte>, std::stop_token);
inline bool same_reads(const ReadSet &a, const ReadSet &b) {
    auto x = a.ranges(), y = b.ranges();
    return x.size() == y.size() && std::equal(x.begin(), x.end(), y.begin(),
                                              [](auto l, auto r) { return l.begin == r.begin && l.size == r.size; });
}
} // namespace hexlab::derived_detail
