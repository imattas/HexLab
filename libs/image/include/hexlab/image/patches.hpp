#pragma once
#include "hexlab/image/byte_storage.hpp"
#include <vector>
namespace hexlab {
struct PatchSpan {FileOffset begin;std::vector<std::byte> original,replacement;bool operator==(const PatchSpan&)const=default;};
class PatchSet {
public:
    HEXLAB_IMAGE_EXPORT static Result<std::shared_ptr<const PatchSet>> create(const ByteStorage&,std::span<const PatchSpan>);
    std::span<const PatchSpan> spans() const noexcept{return spans_;}
private:
    explicit PatchSet(std::vector<PatchSpan> spans):spans_(std::move(spans)){}
    std::vector<PatchSpan> spans_;
};
HEXLAB_IMAGE_EXPORT Result<std::shared_ptr<const ByteStorage>> make_overlay(std::shared_ptr<const ByteStorage>,std::span<const PatchSpan>);
}
