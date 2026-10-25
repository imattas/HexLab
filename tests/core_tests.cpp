#include "hexlab/core/address.hpp"
#include "hexlab/core/byte_reader.hpp"
#include <array>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <type_traits>
#include "support/checks.hpp"

namespace {
using namespace hexlab_test;
void address_tests() {
    using namespace hexlab;
    constexpr auto max = std::numeric_limits<std::uint64_t>::max();
    static_assert(!std::is_convertible_v<FileOffset, Address>);
    check(checked_add(2, 3).value() == 5, "addition");
    check(checked_add(max, 0).value() == max, "max plus zero");
    check(checked_add(max, 1).error().code == ErrorCode::overflow, "addition overflow");
    check(checked_multiply(max, 2).error().code == ErrorCode::overflow, "multiply overflow");
    check(checked_multiply(max, 0).value() == 0, "multiply zero");
    check(checked_multiply(7, 6).value() == 42, "multiply normal");
    check(advance({{7}, 0x1000}, 4).value() == Address{{7}, 0x1004}, "advance preserves space");
    check(advance({{7}, max}, 1).error().code == ErrorCode::overflow, "advance overflow");
    const auto range = AddressRange::create({{7}, 0x1000}, 4).value();
    check(range.contains({{7}, 0x1000}), "range first byte");
    check(range.contains({{7}, 0x1003}), "range last byte");
    check(!range.contains({{7}, 0x1004}), "exclude endpoint");
    check(!range.contains({{7}, 0x0fff}), "exclude before start");
    check(!range.contains({{8}, 0x1000}), "exclude other space");
    check(!AddressRange::create({{7}, 0}, 0).value().contains({{7}, 0}), "empty range");
    check(AddressRange::create({{7}, max}, 1).error().code == ErrorCode::overflow, "range endpoint overflow");
    check(AddressRange::create({{7}, max}, 0).has_value(), "empty at maximum");
    const Result<int> bad(Error{ErrorCode::invalid_argument, "bad"});
    check(!bad && bad.error().code == ErrorCode::invalid_argument, "result error state");
    logic_error([&] { (void)bad.value(); }, "const invalid value accessor");
    Result<int> mutable_bad(Error{ErrorCode::invalid_argument, "bad"});
    logic_error([&] { (void)mutable_bad.value(); }, "mutable invalid value accessor");
    const Result<int> good(7);
    logic_error([&] { (void)good.error(); }, "invalid error accessor");
}
void byte_tests() {
    using namespace hexlab;
    const std::array data{std::byte{0x01}, std::byte{0x23}, std::byte{0x45}, std::byte{0x67},
                          std::byte{0x89}, std::byte{0xab}, std::byte{0xcd}, std::byte{0xef}};
    ByteReader r(data);
    check(r.read_u32(ByteOrder::little).value() == 0x67452301, "little u32");
    check(r.position() == 4 && r.remaining() == 4, "u32 cursor");
    check(r.seek(0).value() == 0, "seek start");
    check(r.read_u32(ByteOrder::big).value() == 0x01234567, "big u32");
    (void)r.seek(0);
    check(r.read_u64(ByteOrder::little).value() == 0xEFCDAB8967452301ULL, "little u64");
    (void)r.seek(0);
    check(r.read_u64(ByteOrder::big).value() == 0x0123456789ABCDEFULL, "big u64");
    (void)r.seek(0);
    check(r.read_u8().value() == 1, "u8");
    check(r.read_u16(ByteOrder::little).value() == 0x4523 && r.position() == 3, "unaligned little u16");
    (void)r.seek(1);
    check(r.read_u16(ByteOrder::big).value() == 0x2345, "unaligned big u16");
    check(r.read_u64(ByteOrder::big).error().code == ErrorCode::out_of_bounds && r.position() == 3, "truncated u64 atomic");
    check(r.read_bytes(std::numeric_limits<std::size_t>::max()).error().code == ErrorCode::out_of_bounds && r.position() == 3, "oversized count atomic");
    check(r.seek(std::numeric_limits<std::size_t>::max()).error().code == ErrorCode::out_of_bounds && r.position() == 3, "oversized seek atomic");
    check(r.seek(8).value() == 8, "seek end");
    check(r.read_u8().error().code == ErrorCode::out_of_bounds && r.position() == 8, "one past end atomic");
    check(r.read_bytes(0).value().empty() && r.position() == 8, "zero read at end");
    (void)r.seek(2);
    const auto bytes = r.read_bytes(2).value();
    check(bytes.size() == 2 && bytes[0] == std::byte{0x45} && bytes[1] == std::byte{0x67} && r.position() == 4, "span read");
    ByteReader empty({});
    check(empty.read_bytes(0).value().empty(), "empty zero read");
    check(empty.read_u8().error().code == ErrorCode::out_of_bounds && empty.position() == 0, "empty input read atomic");
    check(empty.seek(1).error().code == ErrorCode::out_of_bounds && empty.position() == 0, "empty input seek atomic");
}
}
int main() {
    return hexlab_test::run([] { address_tests(); byte_tests(); });
}
