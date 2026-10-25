#include "hexlab/core/encoding.hpp"
namespace hexlab {
std::array<std::byte,8> encode_u64(std::uint64_t value) noexcept {
    std::array<std::byte,8> result{};
    for(std::size_t i=0;i<result.size();++i)result[i]=static_cast<std::byte>(value>>(56-i*8));
    return result;
}
Result<std::uint64_t> decode_u64(std::span<const std::byte> bytes){
    if(bytes.size()!=8)return Error{ErrorCode::invalid_argument,"Canonical uint64 requires exactly eight bytes"};
    std::uint64_t result=0;for(auto byte:bytes)result=(result<<8)|std::to_integer<std::uint64_t>(byte);return result;
}
}
