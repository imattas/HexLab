#include "hexlab/core/address.hpp"
#include <limits>

namespace hexlab {
Result<std::uint64_t> checked_add(std::uint64_t a, std::uint64_t b) {
    if (b > std::numeric_limits<std::uint64_t>::max() - a)
        return Error{ErrorCode::overflow, "Address addition overflows 64 bits"};
    return a + b;
}
Result<std::uint64_t> checked_multiply(std::uint64_t a, std::uint64_t b) {
    if (a != 0 && b > std::numeric_limits<std::uint64_t>::max() / a)
        return Error{ErrorCode::overflow, "Multiplication overflows 64 bits"};
    return a * b;
}
Result<Address> advance(Address address, std::uint64_t amount) {
    auto next = checked_add(address.offset, amount);
    if (!next) return next.error();
    return Address{address.space, next.value()};
}
Result<AddressRange> AddressRange::create(Address begin, std::uint64_t size) {
    const auto end = checked_add(begin.offset, size);
    if (!end) return end.error();
    return AddressRange(begin, size);
}
bool AddressRange::contains(Address address) const noexcept {
    return address.space == begin_.space && address.offset >= begin_.offset &&
           address.offset - begin_.offset < size_;
}
}
