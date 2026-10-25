#pragma once
#include "hexlab/workspace/project.hpp"
#include "hexlab/database/codec.hpp"
#include <algorithm>
#include <type_traits>
namespace hexlab::project_detail {
struct Failure {Error error;};
template<class T>T take(Result<T> value){if(!value)throw Failure{value.error()};return std::move(value.value());}
inline void require(bool condition,const char* reason,ErrorCode code=ErrorCode::invalid_argument){if(!condition)throw Failure{{code,reason}};}
inline void canceled(std::stop_token stop){require(!stop.stop_requested(),"Project operation canceled",ErrorCode::canceled);}
template<class F>auto guarded(F function)->decltype(function()){
    try{return function();}catch(const Failure& error){return error.error;}
    catch(const std::bad_alloc&){return Error{ErrorCode::resource_limit,"Cannot allocate project command"};}
    catch(const std::length_error&){return Error{ErrorCode::resource_limit,"Project command exceeds allocation limits"};}
    catch(const std::filesystem::filesystem_error& error){return Error{ErrorCode::io,error.what()};}
}
void check_location(const ProjectSnapshot&,Location,bool allow_orphan=false);
void check_boundary(const ProjectSnapshot&,Address);
void check_range(const ProjectSnapshot&,Address,std::uint64_t,bool boundaries);
Instruction decision_instruction(const ProjectSnapshot&,Address);
bool mapped_location(const ProjectSnapshot&,Location);
std::shared_ptr<ProjectSnapshot> project_bytes(const ProjectSnapshot&,std::shared_ptr<const database::ProjectState>,std::stop_token);
ReadSet effective_changes(const ByteStorage&,const ByteStorage&,const ReadSet&,std::stop_token);
std::shared_ptr<const ProjectSnapshot> adopt_project_analysis(const ProjectSnapshot&,const ProjectAnalysis&,const AnalysisOptions&,std::stop_token);
std::shared_ptr<const ProjectPresentationIndex> make_presentation_index(std::shared_ptr<const database::UserState>,std::shared_ptr<const LoadedImage>,std::stop_token);
}
