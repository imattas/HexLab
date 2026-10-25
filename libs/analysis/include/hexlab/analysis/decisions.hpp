#pragma once
#include "hexlab/core/location.hpp"
#include <vector>
namespace hexlab {
enum class RegionKind {code,data};
struct DecisionRange {Address begin;std::uint64_t size;bool operator==(const DecisionRange&)const=default;};
struct RegionDecision {std::uint64_t id;Address begin;std::uint64_t size;RegionKind kind;bool operator==(const RegionDecision&)const=default;};
struct FunctionDecision {std::uint64_t id;Address entry;bool suppressed;std::vector<DecisionRange> chunks;bool operator==(const FunctionDecision&)const=default;};
enum class UserReferenceKind {code,data,call,jump,read,write,address};
struct UserReference {std::uint64_t id;Location source,target;UserReferenceKind kind;bool operator==(const UserReference&)const=default;};
struct AnalysisDecisions {
    std::vector<RegionDecision> regions;
    std::vector<FunctionDecision> functions;
    std::vector<UserReference> references;
    bool operator==(const AnalysisDecisions&)const=default;
};
}
