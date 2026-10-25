#pragma once
#include "hexlab/loaders/pe.hpp"
#include "hexlab/image/patches.hpp"
#include <algorithm>
#include <limits>

namespace hexlab::pe_detail {
struct Failure { Error error; };
inline void require(bool ok,std::string message,ErrorCode code=ErrorCode::malformed) {
    if (!ok) throw Failure{{code,std::move(message)}};
}
inline void canceled(std::stop_token stop) {
    if (stop.stop_requested()) throw Failure{{ErrorCode::canceled,"PE loading canceled"}};
}
inline std::uint64_t add(std::uint64_t base,std::uint64_t amount,const char* field) {
    auto result=checked_add(base,amount);
    if (!result) throw Failure{{ErrorCode::overflow,std::string("PE arithmetic overflow: ")+field}};
    return result.value();
}
class FileReader {
public:
    explicit FileReader(const ByteStorage& storage):storage_(storage){}
    ByteView bytes(std::uint64_t offset,std::size_t size,const char* field) const {
        auto view=storage_.read_at({offset},size);
        if (!view) throw Failure{{ErrorCode::malformed,std::string("Truncated PE ")+field+" at file offset "+std::to_string(offset)}};
        return view.value();
    }
    template<class T> T integer(std::uint64_t offset,const char* field) const {
        const auto view=bytes(offset,sizeof(T),field);
        std::uint64_t value=0;
        for (std::size_t i=0;i<sizeof(T);++i) value|=std::to_integer<std::uint64_t>(view.bytes[i])<<(8*i);
        return static_cast<T>(value);
    }
private:
    const ByteStorage& storage_;
};
inline constexpr std::size_t record_limit=1000000;
class ImageReader {
public:
    ImageReader(const Image& image,const ImageMetadata& metadata,std::stop_token stop)
        :image_(image),metadata_(metadata),stop_(stop) {}
    Address address(std::uint64_t rva) const {
        require(rva<metadata_.image_size,"Metadata RVA exceeds image");
        return {image_.layout().space.id,add(metadata_.preferred_base,rva,"metadata VA")};
    }
    std::uint64_t image_size() const noexcept { return metadata_.image_size; }
    std::uint64_t initialized_extent(std::uint64_t rva) const {
        const auto va=address(rva);
        const auto* segment=image_.segment_at(va);
        require(segment!=nullptr,"PE metadata references an unmapped RVA");
        const auto relative=va.offset-segment->begin.offset;
        require(relative<segment->file_size,"PE metadata references uninitialized memory");
        return std::min<std::uint64_t>(segment->file_size-relative,metadata_.image_size-rva);
    }
    std::vector<std::byte> bytes(std::uint64_t rva,std::size_t size) const {
        canceled(stop_);
        require(rva<=metadata_.image_size && size<=metadata_.image_size-rva,"PE metadata range exceeds image");
        std::uint64_t done=0;
        while (done<size) done+=std::min<std::uint64_t>(size-done,initialized_extent(rva+done));
        auto value=image_.read(address(rva),size);
        if (!value) throw Failure{value.error()};
        return std::move(value.value());
    }
    std::vector<PeSourceSpan> sources(std::uint64_t rva,std::uint64_t size) const {
        require(rva<=metadata_.image_size && size<=metadata_.image_size-rva,"PE provenance range exceeds image");
        std::vector<PeSourceSpan> result;
        while (size) {
            const auto va=address(rva);
            const auto* segment=image_.segment_at(va);
            require(segment!=nullptr,"PE provenance references an unmapped RVA");
            const auto relative=va.offset-segment->begin.offset;
            require(relative<segment->file_size,"PE provenance references uninitialized memory");
            const auto amount=std::min<std::uint64_t>(size,segment->file_size-relative);
            const auto file=add(segment->file_begin.value,relative,"provenance file offset");
            if (!result.empty() && file>=result.back().offset.value && file-result.back().offset.value==result.back().size)
                result.back().size+=amount;
            else result.push_back({{file},amount});
            rva+=amount;
            size-=amount;
        }
        return result;
    }
    std::pair<std::string,std::vector<PeSourceSpan>> sourced_string(std::uint64_t rva,std::uint64_t end=UINT64_MAX) const {
        auto value=string(rva,end);
        auto span=sources(rva,value.size()+1);
        return {std::move(value),std::move(span)};
    }
    template<class T> T integer(std::uint64_t rva) const {
        const auto input=bytes(rva,sizeof(T));
        std::uint64_t value=0;
        for (std::size_t i=0;i<sizeof(T);++i) value|=std::to_integer<std::uint64_t>(input[i])<<(8*i);
        return static_cast<T>(value);
    }
    std::string string(std::uint64_t rva,std::uint64_t end=UINT64_MAX) const {
        std::string output;
        end=std::min<std::uint64_t>(end,metadata_.image_size);
        while (rva<end) {
            canceled(stop_);
            const auto amount=static_cast<std::size_t>(std::min<std::uint64_t>({256,end-rva,initialized_extent(rva)}));
            const auto input=bytes(rva,amount);
            for (auto ch:input) {
                if (ch==std::byte{0}) return output;
                if (output.size()>=65536) throw Failure{{ErrorCode::resource_limit,"PE metadata string exceeds 65536-byte inspection limit"}};
                output.push_back(static_cast<char>(std::to_integer<unsigned char>(ch)));
            }
            rva+=amount;
        }
        throw Failure{{ErrorCode::malformed,"PE metadata string lacks a terminator within its range"}};
    }
    void array(std::uint64_t rva,std::uint64_t count,std::size_t width) const {
        if (count>record_limit) throw Failure{{ErrorCode::resource_limit,"PE metadata table exceeds record budget"}};
        require(rva<=metadata_.image_size && count<=((metadata_.image_size-rva)/width),"PE metadata array exceeds image");
    }
private:
    const Image& image_;
    const ImageMetadata& metadata_;
    std::stop_token stop_;
};
template<class F> Result<std::size_t> guarded(F operation) {
    try {return operation();}
    catch (const Failure& failure) {return failure.error;}
    catch (const std::bad_alloc&) {return Error{ErrorCode::resource_limit,"Cannot allocate PE metadata"};}
    catch (const std::length_error&) {return Error{ErrorCode::resource_limit,"PE metadata size is too large"};}
}
Result<std::size_t> read_imports(const Image&,const Directory&,bool,ImageMetadata&,std::stop_token);
Result<std::size_t> read_certificates(const Image&,const Directory&,ImageMetadata&,std::stop_token);
Result<std::size_t> read_bound_imports(const Image&,const Directory&,ImageMetadata&,std::stop_token);
Result<std::size_t> read_delay_imports(const Image&,const Directory&,bool,ImageMetadata&,std::stop_token);
Result<std::size_t> read_debug_directory(const Image&,const Directory&,ImageMetadata&,std::stop_token);
Result<std::size_t> read_exports(const Image&,const Directory&,ImageMetadata&,std::stop_token);
Result<std::size_t> read_relocations(const Image&,const Directory&,ImageMetadata&,std::stop_token);
Result<std::size_t> read_tls(const Image&,const Directory&,bool,ImageMetadata&,std::stop_token);
Result<std::size_t> read_load_configuration(const Image&,const Directory&,bool,ImageMetadata&,std::stop_token);
Result<std::size_t> read_chpe_metadata(const Image&,const Directory&,bool,ImageMetadata&,std::stop_token);
Result<std::size_t> read_resources(const Image&,const Directory&,ImageMetadata&,std::stop_token);
Result<std::size_t> read_exception_directory(const Image&,const Directory&,ImageMetadata&,std::stop_token);
Result<std::size_t> read_msvc_rtti(const Image&,ImageMetadata&,std::stop_token);
struct RebasedPeImage { ImageLayout layout; std::vector<PatchSpan> patches; };
Result<RebasedPeImage> apply_pe_relocations(const Image&,ImageMetadata&,std::uint64_t,std::stop_token);
}
