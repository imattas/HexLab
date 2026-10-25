#include "hexlab/image/byte_storage.hpp"
#include <algorithm>
namespace hexlab {
ByteStorage::~ByteStorage()=default;
Result<Sha256Digest> hash_source(const ByteStorage& source,std::stop_token stop){
    if(stop.stop_requested())return Error{ErrorCode::canceled,"Input hashing canceled"};
    Sha256 hash;std::uint64_t position=0;
    while(position<source.size()){
        if(stop.stop_requested())return Error{ErrorCode::canceled,"Input hashing canceled"};
        const auto amount=static_cast<std::size_t>(std::min<std::uint64_t>(65536,source.size()-position));
        auto view=source.read_at({position},amount);if(!view)return view.error();
        if(view.value().bytes.size()!=amount)return Error{ErrorCode::io,"Byte source returned an incomplete hash read"};
        auto result=hash.update(view.value().bytes);if(!result)return result.error();position+=amount;
    }
    if(stop.stop_requested())return Error{ErrorCode::canceled,"Input hashing canceled"};
    return hash.digest();
}
}
