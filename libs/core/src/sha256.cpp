#include "hexlab/core/sha256.hpp"
#include "hexlab/core/encoding.hpp"
#include <algorithm>
#include <bit>
#include <limits>

namespace hexlab {
namespace {
constexpr std::array<std::uint32_t,64> constants{
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};
}
void Sha256::compress(const std::byte* block) noexcept {
    std::array<std::uint32_t,64> words{};
    for(std::size_t i=0;i<16;++i)
        for(std::size_t j=0;j<4;++j)words[i]=(words[i]<<8)|std::to_integer<std::uint32_t>(block[i*4+j]);
    for(std::size_t i=16;i<words.size();++i){
        const auto x=words[i-15],y=words[i-2];
        const auto sigma0=std::rotr(x,7)^std::rotr(x,18)^(x>>3);
        const auto sigma1=std::rotr(y,17)^std::rotr(y,19)^(y>>10);
        words[i]=words[i-16]+sigma0+words[i-7]+sigma1;
    }
    auto a=state_[0],b=state_[1],c=state_[2],d=state_[3],e=state_[4],f=state_[5],g=state_[6],h=state_[7];
    for(std::size_t i=0;i<words.size();++i){
        const auto sum1=std::rotr(e,6)^std::rotr(e,11)^std::rotr(e,25);
        const auto choose=(e&f)^(~e&g);
        const auto t1=h+sum1+choose+constants[i]+words[i];
        const auto sum0=std::rotr(a,2)^std::rotr(a,13)^std::rotr(a,22);
        const auto majority=(a&b)^(a&c)^(b&c);
        h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+sum0+majority;
    }
    state_[0]+=a;state_[1]+=b;state_[2]+=c;state_[3]+=d;state_[4]+=e;state_[5]+=f;state_[6]+=g;state_[7]+=h;
}
Result<std::uint64_t> Sha256::update(std::span<const std::byte> input){
    constexpr auto max_bytes=std::numeric_limits<std::uint64_t>::max()/8;
    if(input.size()>max_bytes-total_)return Error{ErrorCode::overflow,"SHA256 message exceeds its 64-bit bit-length field"};
    total_+=input.size();
    if(used_){
        const auto amount=std::min(input.size(),tail_.size()-used_);
        std::copy_n(input.begin(),amount,tail_.begin()+static_cast<std::ptrdiff_t>(used_));used_+=amount;input=input.subspan(amount);
        if(used_==tail_.size()){compress(tail_.data());used_=0;}
    }
    while(input.size()>=tail_.size()){compress(input.data());input=input.subspan(tail_.size());}
    if(!input.empty()){std::copy(input.begin(),input.end(),tail_.begin());used_=input.size();}
    return total_;
}
Sha256Digest Sha256::digest() const noexcept {
    Sha256 final=*this;
    final.tail_[final.used_++]=std::byte{0x80};
    if(final.used_>56){std::fill(final.tail_.begin()+static_cast<std::ptrdiff_t>(final.used_),final.tail_.end(),std::byte{0});final.compress(final.tail_.data());final.used_=0;}
    std::fill(final.tail_.begin()+static_cast<std::ptrdiff_t>(final.used_),final.tail_.begin()+56,std::byte{0});
    const auto length=encode_u64(total_*8);std::copy(length.begin(),length.end(),final.tail_.begin()+56);final.compress(final.tail_.data());
    Sha256Digest result{};
    for(std::size_t i=0;i<final.state_.size();++i)
        for(std::size_t j=0;j<4;++j)result[i*4+j]=static_cast<std::byte>(final.state_[i]>>(24-j*8));
    return result;
}
std::string digest_hex(const Sha256Digest& digest){
    constexpr char digits[]="0123456789abcdef";std::string result;result.reserve(64);
    for(auto byte:digest){auto value=std::to_integer<unsigned>(byte);result.push_back(digits[value>>4]);result.push_back(digits[value&15]);}
    return result;
}
}
