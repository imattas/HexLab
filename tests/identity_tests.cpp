#include "hexlab/core/sha256.hpp"
#include "hexlab/core/encoding.hpp"
#include "hexlab/core/location.hpp"
#include "support/checks.hpp"
#include <filesystem>
#include <fstream>
#include <string_view>
#include <vector>
using namespace hexlab;
using namespace hexlab_test;
std::span<const std::byte> octets(std::string_view value){return std::as_bytes(std::span(value.data(),value.size()));}
void vector_test(std::string_view value,std::string_view expected){
    Sha256 hash;auto result=hash.update(octets(value));check(result && result.value()==value.size(),"hash reports total bytes");
    check(digest_hex(hash.digest())==expected,"independent SHA256 known answer");
    check(hash.digest()==hash.digest() && hash.bytes()==value.size(),"digest is nonmutating and repeatable");
}
void hash_tests(){
    vector_test("","e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    vector_test("abc","ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    vector_test("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq","248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    vector_test(std::string(1000000,'a'),"cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
    Sha256 continued;check(bool(continued.update(octets("abc"))),"prefix accepted");const auto prefix=continued.digest();
    check(bool(continued.update(octets("a"))) && continued.bytes()==4,"update after digest keeps prefix state");
    check(prefix!=continued.digest() && digest_hex(continued.digest())=="5c3f67b7fa84dfbe1118387cad14793929845a5bc7c0080c4d8309d37baa68d0","continued known answer");
    for(std::size_t length:{55u,56u,63u,64u,65u,119u,120u,127u,128u,129u}){
        const std::string value(length,'a');Sha256 whole;check(bool(whole.update(octets(value))),"whole boundary message accepted");
        for(std::size_t split=0;split<=length;++split){Sha256 parts;auto data=octets(value);check(bool(parts.update(data.first(split))) && bool(parts.update(data.subspan(split))) && parts.digest()==whole.digest(),"all split points retain padding/block correctness");}
    }
    std::vector<std::byte> binary;for(unsigned i=0;i<256;++i)binary.push_back(static_cast<std::byte>(i));Sha256 hash;check(bool(hash.update(binary)),"all byte values accepted");
    check(digest_hex(hash.digest())=="40aff2e9d2d8922e47afd4648e6967497158785fbd1da870e7110266bf944880","binary known answer");
}
void encoding_tests(){
    check(encode_u64(0)==std::array<std::byte,8>{},"zero encoding");
    const auto high=encode_u64(0x8000000000000000ULL);check(high[0]==std::byte{0x80} && high[7]==std::byte{0} && decode_u64(high).value()==0x8000000000000000ULL,"high unsigned bit survives canonical encoding");
    const auto max=encode_u64(UINT64_MAX);check(decode_u64(max).value()==UINT64_MAX,"maximum unsigned value survives");
    const auto ordered=encode_u64(0x0123456789abcdefULL);check(ordered[0]==std::byte{1} && ordered[7]==std::byte{0xef},"canonical big endian order");
    for(std::size_t n=0;n<8;++n)check(!decode_u64(std::span(max).first(n)),"short scalar encoding rejected");
    const std::array<std::byte,9> extra{};check(!decode_u64(extra),"long scalar encoding rejected");
    Location address=Address{{7},UINT64_MAX},file=FileOffset{UINT64_MAX};check(address!=file,"canonical location keeps address and file-offset domains distinct");
}
int write_oracle(const std::filesystem::path& path){
    std::filesystem::create_directories(path.parent_path());std::ofstream output(path,std::ios::binary|std::ios::trunc);Sha256 hash;
    std::vector<std::byte> block(16381);std::uint64_t done=0;const std::uint64_t size=1024*1024+13;
    while(done<size){const auto count=static_cast<std::size_t>(std::min<std::uint64_t>(block.size(),size-done));for(std::size_t i=0;i<count;++i)block[i]=static_cast<std::byte>((done+i)*37+11);output.write(reinterpret_cast<const char*>(block.data()),static_cast<std::streamsize>(count));if(!hash.update(std::span(block).first(count)))return 2;done+=count;}
    output.close();if(!output)return 2;std::cout<<digest_hex(hash.digest())<<'\n';return 0;
}
int main(int argc,char** argv){if(argc==3 && std::string_view(argv[1])=="--write-oracle")return write_oracle(argv[2]);return run([]{hash_tests();encoding_tests();});}
#include <algorithm>
