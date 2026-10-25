#pragma once
#include "hexlab/database/project_state.hpp"
namespace hexlab::database {
template<class T>struct EntityChange {std::optional<T> before,after;};
using AnnotationChange=EntityChange<Annotation>;
using BookmarkChange=EntityChange<Bookmark>;
using RegionChange=EntityChange<RegionDecision>;
using FunctionChange=EntityChange<FunctionDecision>;
using ReferenceChange=EntityChange<UserReference>;
using TypeDefinitionChange=EntityChange<TypeDefinition>;
using TypeAssignmentChange=EntityChange<TypeAssignment>;
using DebugVariableChange=EntityChange<DebugVariable>;
using ProjectBreakpointChange=EntityChange<ProjectBreakpoint>;
struct PatchChange {std::vector<PatchSpan> before,after;};
using UserChange=std::variant<AnnotationChange,BookmarkChange,RegionChange,FunctionChange,ReferenceChange,PatchChange,TypeDefinitionChange,TypeAssignmentChange,DebugVariableChange,ProjectBreakpointChange>;
struct StateDelta {std::vector<UserChange> changes;};
HEXLAB_DATABASE_EXPORT Result<StateDelta> invert_delta(const StateDelta&);
}
