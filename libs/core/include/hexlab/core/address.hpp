#pragma once
#include "hexlab/core/result.hpp"
#include "hexlab/core/core_export.hpp"
#include <cstdint>

namespace hexlab {
struct AddressSpaceId {
    std::uint32_t value;
    bool operator==(const AddressSpaceId&) const = default;
};
struct Address {
    AddressSpaceId space;
    std::uint64_t offset;
    bool operator==(const Address&) const = default;
};
struct FileOffset {
    std::uint64_t value;
    bool operator==(const FileOffset&) const = default;
};
HEXLAB_CORE_EXPORT Result<std::uint64_t> checked_add(std::uint64_t a, std::uint64_t b);
HEXLAB_CORE_EXPORT Result<std::uint64_t> checked_multiply(std::uint64_t a, std::uint64_t b);
HEXLAB_CORE_EXPORT Result<Address> advance(Address address, std::uint64_t amount);

// The exclusive endpoint must be representable; a nonempty range cannot
// include UINT64_MAX. Empty ranges are valid, including at that offset.
class HEXLAB_CORE_EXPORT AddressRange {
public:
    static Result<AddressRange> create(Address begin, std::uint64_t size);
    bool contains(Address address) const noexcept;
    Address begin() const noexcept { return begin_; }
    std::uint64_t size() const noexcept { return size_; }
private:
    AddressRange(Address begin, std::uint64_t size) : begin_(begin), size_(size) {}
    Address begin_;
    std::uint64_t size_;
};
}
