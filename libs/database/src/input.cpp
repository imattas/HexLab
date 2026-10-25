#include "native_files.hpp"
#include "testing.hpp"
#include <algorithm>
#ifndef _WIN32
#include <cerrno>
#include <fcntl.h>
#include <unistd.h>
#endif
namespace hexlab::database::detail {
InputProvenance make_provenance(const std::filesystem::path& path,const std::filesystem::path& project){
    require(path.native().find(std::filesystem::path::value_type{})==std::filesystem::path::string_type::npos,"Invalid native provenance path");
    InputProvenance result;
#ifdef _WIN32
    require(path.native().size()<=32767,"Invalid native provenance path");result.encoding=NativeEncoding::utf16le;result.native_path=path;result.encoded_path.reserve(path.native().size()*2);
    for(auto unit:path.native()){result.encoded_path.push_back(std::byte(unit&255));result.encoded_path.push_back(std::byte((static_cast<unsigned>(unit)>>8)&255));}
#else
    const auto native=path.generic_u8string();require(native.size()<=131068,"Native provenance path exceeds its storage budget");result.encoding=NativeEncoding::utf8;result.native_path=path;
    result.encoded_path.assign(reinterpret_cast<const std::byte*>(native.data()),reinterpret_cast<const std::byte*>(native.data()+native.size()));
#endif
    if(!path.empty()){
        try{const auto original=std::filesystem::absolute(path);auto alternative=original.lexically_relative(std::filesystem::absolute(project).parent_path());if(alternative.empty())alternative=original;const auto relative=alternative.generic_u8string();if(relative.size()<=131072)result.relative_path.assign(reinterpret_cast<const char*>(relative.data()),relative.size());}
        catch(const std::filesystem::filesystem_error&){/* Native bytes remain authoritative provenance. */}
    }
    return result;
}
std::optional<InputProvenance> read_provenance(Connection& connection){
    auto row=take(connection.prepare("SELECT singleton,encoding,length(native_path),length(CAST(relative_path AS BLOB)),native_path,relative_path FROM input_provenance"));
    if(!take(row->step()))return {};
    require(take(row->integer(0))==1,"Unknown provenance record ID");const auto tag=take(row->integer(1)),size=take(row->integer(2)),relative_size=take(row->integer(3));
    require((tag==1 || tag==2) && size>=0 && size<=65534 && relative_size>=0 && relative_size<=131072,"Invalid native provenance encoding or extent");
    InputProvenance value;value.encoding=static_cast<NativeEncoding>(tag);value.encoded_path=take(row->blob(4));value.relative_path=take(row->text(5));require(value.relative_path.find('\0')==std::string::npos,"NUL in relative provenance path");
    if(value.encoding==NativeEncoding::utf16le){
        require(value.encoded_path.size()%2==0,"Truncated UTF-16 provenance");std::wstring path;
        for(size_t i=0;i<value.encoded_path.size();i+=2){const auto unit=std::to_integer<unsigned>(value.encoded_path[i])|(std::to_integer<unsigned>(value.encoded_path[i+1])<<8);require(unit!=0,"NUL in native provenance path");path.push_back(static_cast<wchar_t>(unit));}value.native_path=std::move(path);
    }else {
        require(std::find(value.encoded_path.begin(),value.encoded_path.end(),std::byte{0})==value.encoded_path.end(),"NUL in UTF-8 provenance path");
        if(!value.encoded_path.empty())value.native_path=std::filesystem::path(std::u8string(reinterpret_cast<const char8_t*>(value.encoded_path.data()),value.encoded_path.size()));
    }
    require(!take(row->step()),"Duplicate provenance records");return value;
}
void verify_patches(const ByteStorage& source,const UserState& user){
    for(const auto& patch:user.patches){const auto original=take(source.read_at(patch.begin,patch.original.size()));require(original.bytes.size()==patch.original.size() && std::equal(original.bytes.begin(),original.bytes.end(),patch.original.begin()),"Patch original bytes do not match embedded input");}
}
std::shared_ptr<const ByteStorage> extract_input(Connection& connection,const ProjectState& state,std::stop_token stop){
    if(stop.stop_requested())throw Failure{{ErrorCode::canceled,"Input extraction canceled"}};
    auto backing=reserve_owned_file(std::filesystem::temp_directory_path(),L"hexlab-input-");
#ifdef _WIN32
    NativeHandle output{CreateFileW(backing->path.c_str(),GENERIC_WRITE,0,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_TEMPORARY|FILE_FLAG_SEQUENTIAL_SCAN,nullptr)};
    if(output.value==INVALID_HANDLE_VALUE)throw Failure{native_error("Cannot write extracted input")};
#else
    NativeHandle output{::open(backing->path.c_str(),O_WRONLY|O_CLOEXEC)};
    if(output.value<0)throw Failure{native_error("Cannot write extracted input")};
#endif
    auto query=take(connection.prepare("SELECT position,length(data),data FROM input_chunks ORDER BY position"));uint64_t position=0;Sha256 hash;
    while(take(query->step())){
        if(stop.stop_requested())throw Failure{{ErrorCode::canceled,"Input extraction canceled"}};
        const auto at=take(decode_u64(take(query->blob(0))));const auto size=take(query->integer(1));
        require(position<state.input.size && at==position && size==static_cast<int64_t>(std::min<uint64_t>(1024*1024,state.input.size-position)),"Missing, unordered or oversized original-input chunk");
        const auto data=take(query->blob(2));require(data.size()==static_cast<size_t>(size),"Original chunk extent changed");take(hash.update(data));
        size_t done=0;while(done<data.size()){
#ifdef _WIN32
            DWORD written=0;if(!WriteFile(output.value,data.data()+done,static_cast<DWORD>(data.size()-done),&written,nullptr) || written==0)throw Failure{native_error("Cannot extract original-input chunk")};done+=written;
#else
            auto written=::write(output.value,data.data()+done,data.size()-done);if(written<0){if(errno==EINTR)continue;throw Failure{native_error("Cannot extract original-input chunk")};}if(!written)throw Failure{{ErrorCode::io,"Cannot extract original-input chunk"}};done+=static_cast<size_t>(written);
#endif
        }
        position+=data.size();
#ifdef HEXLAB_DATABASE_TESTING
        testing::input_checkpoint(position,backing->path);
#endif
    }
    if(stop.stop_requested())throw Failure{{ErrorCode::canceled,"Input extraction canceled"}};
    require(position==state.input.size && hash.digest()==state.input.sha256,"Embedded original size or SHA-256 mismatch");
#ifdef _WIN32
    if(!FlushFileBuffers(output.value))throw Failure{native_error("Cannot flush extracted input")};
    if(!CloseHandle(output.value)){output.value=INVALID_HANDLE_VALUE;throw Failure{native_error("Cannot close extracted input")};}output.value=INVALID_HANDLE_VALUE;
#else
    if(::fsync(output.value)!=0)throw Failure{native_error("Cannot flush extracted input")};
    if(::close(output.value)!=0){output.value=-1;throw Failure{native_error("Cannot close extracted input")};}output.value=-1;
#endif
    auto source=take(FileStorage::open_owned(backing->path,backing));verify_patches(*source,*state.user);return source;
}
}
namespace hexlab::database {
Result<bool> ProjectStore::import_input(const ByteStorage& source,const LoadRecipe& requested,const std::filesystem::path& provenance,std::stop_token stop){
    return detail::guarded([&]()->Result<bool>{
        std::lock_guard lock(impl_->mutex);
        if(impl_->mode==ProjectMode::read_only)return Error{ErrorCode::read_only,"Project is read only"};
        if(stop.stop_requested())return Error{ErrorCode::canceled,"Input import canceled"};
        if(source.size()>UINT64_MAX/8)return Error{ErrorCode::overflow,"Input exceeds SHA-256 length domain"};
        const auto recipe=detail::take(resolve_load_recipe(source,requested,stop));
        const auto encoded_recipe=detail::take(encode_recipe(recipe));auto native=detail::make_provenance(provenance,impl_->path);
        detail::Cancellation cancellation(*impl_->connection,stop);auto transaction=detail::take(Transaction::begin(*impl_->connection));auto before=detail::read_state(*impl_->connection);
        if(before->revisions.edit!=0 || before->input.size!=0 || before->provenance)return Error{ErrorCode::conflict,"Original input can only be imported into a new unedited project"};
        auto existing=detail::take(impl_->connection->prepare("SELECT count(*) FROM input_chunks"));detail::require(detail::take(existing->step()) && detail::take(existing->integer(0))==0,"Blank project contains unexpected input chunks");existing.reset();
        auto insert=detail::take(impl_->connection->prepare("INSERT INTO input_chunks VALUES(?1,?2)"));Sha256 hash;
        for(uint64_t position=0;position<source.size();){
            if(stop.stop_requested())return Error{ErrorCode::canceled,"Input import canceled"};
            const auto amount=static_cast<size_t>(std::min<uint64_t>(1024*1024,source.size()-position));auto view=detail::take(source.read_at({position},amount));
            if(view.bytes.size()!=amount)return Error{ErrorCode::io,"Input source returned an incomplete import read"};
            detail::take(hash.update(view.bytes));detail::take(insert->bind_blob(1,encode_u64(position)));detail::take(insert->bind_blob(2,view.bytes));detail::take(insert->step());detail::take(insert->reset());position+=amount;
        }
        auto after=std::make_shared<ProjectState>(*before);after->recipe=recipe;after->input={source.size(),hash.digest()};after->provenance=std::move(native);
        auto header=detail::take(impl_->connection->prepare("UPDATE project SET recipe=?1,input_size=?2,input_sha256=?3 WHERE singleton=1"));detail::take(header->bind_blob(1,encoded_recipe));detail::take(header->bind_blob(2,encode_u64(after->input.size)));detail::take(header->bind_blob(3,after->input.sha256));detail::take(header->step());
        auto path=detail::take(impl_->connection->prepare("INSERT INTO input_provenance VALUES(1,?1,?2,?3)"));detail::take(path->bind_integer(1,static_cast<int>(after->provenance->encoding)));detail::take(path->bind_blob(2,after->provenance->encoded_path));detail::take(path->bind_text(3,after->provenance->relative_path));detail::take(path->step());
        detail::take(transaction->commit());impl_->state=std::move(after);impl_->original.reset();return true;
    });
}
Result<std::shared_ptr<const ByteStorage>> ProjectStore::materialize_input(std::stop_token stop){
    return detail::guarded([&]()->Result<std::shared_ptr<const ByteStorage>>{
        std::lock_guard lock(impl_->mutex);if(stop.stop_requested())return Error{ErrorCode::canceled,"Input extraction canceled"};if(impl_->original)return impl_->original;
        detail::Cancellation cancellation(*impl_->connection,stop);detail::take(impl_->connection->execute("BEGIN"));
        struct Rollback {Connection& connection;bool active=true;~Rollback(){if(active){auto old=connection.exchange_cancellation({});(void)connection.execute("ROLLBACK");connection.exchange_cancellation(old);}}} rollback{*impl_->connection};
        auto state=detail::read_state(*impl_->connection);auto original=detail::extract_input(*impl_->connection,*state,stop);detail::take(impl_->connection->execute("COMMIT"));rollback.active=false;impl_->state=std::move(state);impl_->original=std::move(original);return impl_->original;
    });
}
ProjectMode ProjectStore::mode()const noexcept{return impl_->mode;}
}
