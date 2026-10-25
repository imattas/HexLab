#include "native_files.hpp"
namespace hexlab::database {
struct ProjectLease::Impl {detail::NativeHandle event;};
ProjectLease::ProjectLease(std::unique_ptr<Impl> impl):impl_(std::move(impl)){}
ProjectLease::~ProjectLease()=default;
Result<std::shared_ptr<ProjectLease>> ProjectLease::acquire(const ProjectUuid& uuid){
    return detail::guarded([&]()->Result<std::shared_ptr<ProjectLease>>{
        std::wstring name=L"Local\\HexLab.Project.";constexpr wchar_t digits[]=L"0123456789abcdef";
        for(auto byte:uuid){const auto value=std::to_integer<unsigned>(byte);name+=digits[value>>4];name+=digits[value&15];}
        auto impl=std::make_unique<Impl>();impl->event.value=CreateEventW(nullptr,TRUE,TRUE,name.c_str());
        if(!impl->event.value)return detail::native_error("Cannot acquire project process lease");
        if(GetLastError()==ERROR_ALREADY_EXISTS)return Error{ErrorCode::busy,"Project has another editable owner; opened read only"};
        return std::shared_ptr<ProjectLease>(new ProjectLease(std::move(impl)));
    });
}
}
