#pragma once
#include "hexlab/image/image.hpp"
namespace hexlab_test {
class MemoryStorage final:public hexlab::ByteStorage {
    std::shared_ptr<const std::vector<std::byte>> bytes_;
public:
    explicit MemoryStorage(std::vector<std::byte> bytes):bytes_(std::make_shared<const std::vector<std::byte>>(std::move(bytes))){}
    std::uint64_t size()const noexcept override{return bytes_->size();}
    hexlab::Result<hexlab::ByteView> read_at(hexlab::FileOffset at,std::size_t count)const override{
        if(at.value>size() || count>size()-at.value)return hexlab::Error{hexlab::ErrorCode::out_of_bounds,"Memory fixture read exceeds storage"};
        return hexlab::ByteView{bytes_,std::span(*bytes_).subspan(static_cast<std::size_t>(at.value),count)};
    }
};
inline std::shared_ptr<const hexlab::Image> memory_image(std::vector<std::byte> bytes,std::uint64_t base=0x1000){
    auto source=std::make_shared<MemoryStorage>(std::move(bytes));hexlab::Address entry{{0},base};
    hexlab::ImageLayout layout{{{0},64,1,hexlab::ByteOrder::little},hexlab::Architecture::x86_64,hexlab::ExecutionMode::x86_64,{{"fixture",entry,source->size(),{0},source->size(),true,false,true}},{entry}};
    return hexlab::Image::create(source,std::move(layout)).value();
}
}
