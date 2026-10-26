#include "hexlab/decompiler/jvm_lifting.hpp"
#include <algorithm>
#include <array>
#include <deque>
#include <functional>
#include <iterator>
#include <limits>
#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <set>

namespace hexlab::decompiler {
namespace {
ValueType int32(){return {TypeKind::integer,32,true};}
ValueType int64(){return {TypeKind::integer,64,true};}
ValueType fp32(){return {TypeKind::floating,32,false};}
ValueType fp64(){return {TypeKind::floating,64,false};}
ValueType ref32(){return {TypeKind::pointer,32,false};}
ExpressionPtr con(std::uint64_t v,ValueType t){return std::make_shared<Expression>(Expression{t,ConstantValue{v,t}});}
ExpressionPtr reg(RegisterOperand r,ValueType t=int32()){return std::make_shared<Expression>(Expression{t,RegisterValue{r}});}
ExpressionPtr unknown(std::string description, ValueType t){return std::make_shared<Expression>(Expression{t,UnknownValue{std::move(description)}});}
ExpressionPtr bin(std::string op,ExpressionPtr a,ExpressionPtr b,ValueType t){return std::make_shared<Expression>(Expression{t,BinaryValue{std::move(op),std::move(a),std::move(b)}});}
ExpressionPtr un(std::string op,ExpressionPtr a,ValueType t){return std::make_shared<Expression>(Expression{t,UnaryValue{std::move(op),std::move(a)}});}
std::optional<std::uint64_t> imm(const Instruction &i,std::size_t n=0){if(n>=i.operands.size())return{};if(auto *v=std::get_if<ImmediateOperand>(&i.operands[n]))return v->value;return{};}
bool target(const Instruction &i){return i.flow==FlowKind::jump||i.flow==FlowKind::conditional_branch;}
Error no(std::string s){return {ErrorCode::unsupported,"JVM lift unsupported: "+std::move(s)};}
bool jvm_may_throw(std::uint8_t opcode) {
    // Keep in sync with JVM exceptional-edge recovery in functions.cpp.
    return (opcode >= 0x12 && opcode <= 0x14) ||
           (opcode >= 0x2e && opcode <= 0x35) || (opcode >= 0x4f && opcode <= 0x56) ||
           opcode == 0x6c || opcode == 0x6d || opcode == 0x70 || opcode == 0x71 ||
           (opcode >= 0xb2 && opcode <= 0xc3) || opcode == 0xc5 || opcode == 0xbf;
}
struct MemberReference { std::string owner, name, descriptor; };
struct DynamicCallSite { std::string name, descriptor; std::uint64_t bootstrap_index = 0; };
Result<std::string> cp_utf8(const JvmMetadata &metadata, std::uint64_t index) {
    if (index == 0 || index >= metadata.constant_pool.size() || metadata.constant_pool[index].tag != 1)
        return no("constant-pool UTF-8 reference is invalid");
    return metadata.constant_pool[index].text;
}
Result<std::string> cp_class_name(const JvmMetadata &metadata, std::uint64_t index) {
    if (index == 0 || index >= metadata.constant_pool.size() || metadata.constant_pool[index].tag != 7)
        return no("constant-pool class reference is invalid");
    return cp_utf8(metadata, metadata.constant_pool[index].first);
}
Result<MemberReference> cp_member(const JvmMetadata &metadata, std::uint64_t index, bool method) {
    if (index == 0 || index >= metadata.constant_pool.size()) return no("member constant-pool index is invalid");
    const auto &ref = metadata.constant_pool[index];
    if ((method && ref.tag != 10 && ref.tag != 11) || (!method && ref.tag != 9))
        return no("member constant-pool entry has the wrong reference kind");
    if (ref.first == 0 || ref.first >= metadata.constant_pool.size() || metadata.constant_pool[ref.first].tag != 7 ||
        ref.second == 0 || ref.second >= metadata.constant_pool.size() || metadata.constant_pool[ref.second].tag != 12)
        return no("member constant-pool entry is malformed");
    const auto &clazz = metadata.constant_pool[ref.first];
    const auto &nat = metadata.constant_pool[ref.second];
    auto owner = cp_utf8(metadata, clazz.first);
    if (!owner) return owner.error();
    auto name = cp_utf8(metadata, nat.first);
    if (!name) return name.error();
    auto descriptor = cp_utf8(metadata, nat.second);
    if (!descriptor) return descriptor.error();
    return MemberReference{std::move(owner.value()), std::move(name.value()), std::move(descriptor.value())};
}
Result<DynamicCallSite> cp_dynamic_call_site(const JvmMetadata &metadata, std::uint64_t index) {
    if (index == 0 || index >= metadata.constant_pool.size() || metadata.constant_pool[index].tag != 18)
        return no("invokedynamic constant-pool entry is invalid");
    const auto &dynamic = metadata.constant_pool[index];
    if (dynamic.second == 0 || dynamic.second >= metadata.constant_pool.size() ||
        metadata.constant_pool[dynamic.second].tag != 12)
        return no("invokedynamic name-and-type entry is malformed");
    const auto &name_and_type = metadata.constant_pool[dynamic.second];
    auto name = cp_utf8(metadata, name_and_type.first);
    if (!name) return name.error();
    auto descriptor = cp_utf8(metadata, name_and_type.second);
    if (!descriptor) return descriptor.error();
    return DynamicCallSite{std::move(name.value()), std::move(descriptor.value()), dynamic.first};
}
Result<DynamicCallSite> cp_dynamic_constant(const JvmMetadata &metadata, std::uint64_t index) {
    if (index == 0 || index >= metadata.constant_pool.size() || metadata.constant_pool[index].tag != 17)
        return no("dynamic constant-pool entry is invalid");
    const auto &dynamic = metadata.constant_pool[index];
    if (dynamic.second == 0 || dynamic.second >= metadata.constant_pool.size() ||
        metadata.constant_pool[dynamic.second].tag != 12)
        return no("dynamic constant name-and-type entry is malformed");
    const auto &name_and_type = metadata.constant_pool[dynamic.second];
    auto name = cp_utf8(metadata, name_and_type.first);
    if (!name) return name.error();
    auto descriptor = cp_utf8(metadata, name_and_type.second);
    if (!descriptor) return descriptor.error();
    return DynamicCallSite{std::move(name.value()), std::move(descriptor.value()), dynamic.first};
}
std::string string_constant_preview(std::string_view value) {
    constexpr std::size_t limit = 96;
    constexpr char hex[] = "0123456789abcdef";
    std::string out;
    const auto count = std::min(value.size(), limit);
    out.reserve(count * 4 + 16);
    for (std::size_t i = 0; i < count; ++i) {
        const auto c = static_cast<unsigned char>(value[i]);
        if (c == '\\' || c == '"') { out.push_back('\\'); out.push_back(static_cast<char>(c)); }
        else if (c == '\n') out += "\\n";
        else if (c == '\r') out += "\\r";
        else if (c == '\t') out += "\\t";
        else if (c < 0x20 || c >= 0x7f) {
            out += "\\x"; out.push_back(hex[c >> 4]); out.push_back(hex[c & 0x0f]);
        } else out.push_back(static_cast<char>(c));
    }
    if (value.size() > count) out += "...";
    return out;
}
Result<ValueType> descriptor_type(std::string_view descriptor, std::size_t &position, bool allow_void = false) {
    if (position >= descriptor.size()) return no("descriptor is truncated");
    const char code = descriptor[position++];
    switch (code) {
    case 'B': case 'C': case 'I': case 'S': case 'Z': return int32();
    case 'J': return int64();
    case 'F': return fp32();
    case 'D': return fp64();
    case 'V': if (allow_void) return ValueType{}; else return no("void appears in a value descriptor");
    case 'L': {
        const auto end = descriptor.find(';', position);
        if (end == std::string_view::npos || end == position) return no("reference descriptor is malformed");
        position = end + 1;
        return ref32();
    }
    case '[': {
        while (position < descriptor.size() && descriptor[position] == '[') ++position;
        auto element = descriptor_type(descriptor, position);
        if (!element) return element.error();
        return ref32();
    }
    default: return no("descriptor uses an unsupported type code");
    }
}
struct MethodDescriptor { std::vector<ValueType> parameters; std::optional<ValueType> result; };
// These identities are proof evidence for transport, not runtime object IDs.
// An empty identity is deliberately different from the verifier's Null type.
struct ReferenceIdentity {
    JvmVerificationKind kind = JvmVerificationKind::object;
    std::string descriptor;
    std::uint32_t allocation_offset = 0;
    std::string defining_loader;
    bool operator==(const ReferenceIdentity &) const = default;
};
using Reference = std::optional<ReferenceIdentity>;
struct ReferenceState {
    std::array<Reference, 256> locals{};
    std::vector<Reference> stack;
    bool operator==(const ReferenceState &) const = default;
};
Reference reference_descriptor(std::string_view descriptor) {
    if (descriptor.empty() || (descriptor.front() != 'L' && descriptor.front() != '[')) return {};
    std::size_t position = 0;
    const auto type = descriptor_type(descriptor, position);
    if (!type || position != descriptor.size() || type.value() != ref32()) return {};
    return ReferenceIdentity{JvmVerificationKind::object, std::string(descriptor), 0};
}
Reference reference_class(std::string_view name) {
    if (name.empty()) return {};
    return reference_descriptor(name.front() == '[' ? std::string(name) : "L" + std::string(name) + ";");
}
using TypeId = JvmTypeIdentity;
using TypeKey = std::pair<std::string, std::string>;
TypeKey type_key(const TypeId &id) { return {id.defining_loader, id.class_name}; }
constexpr std::size_t max_hierarchy_nodes = 16'384;
constexpr std::size_t max_hierarchy_edges = 65'536;
constexpr std::size_t max_walk_nodes = 16'384;
constexpr std::size_t max_walk_edges = 65'536;
constexpr std::size_t max_query_nodes = 65'536;
constexpr std::size_t max_query_edges = 262'144;
constexpr std::size_t max_common_candidates = 256;
struct HierarchyWork { std::size_t nodes = 0, edges = 0; };
struct HierarchyIndex {
    JvmHierarchyClass self;
    std::map<TypeKey, JvmHierarchyClass> nodes;
};
std::optional<HierarchyIndex> index_hierarchy(const JvmMetadata &md) {
    if (md.defining_loader.empty() || md.class_name.empty() || md.known_hierarchy.size() > max_hierarchy_nodes) return {};
    HierarchyIndex index;
    index.self.identity = {md.class_name, md.defining_loader};
    index.self.complete = true;
    if (!md.super_name.empty()) index.self.superclass = TypeId{md.super_name, md.defining_loader};
    for (const auto &name : md.interfaces) index.self.interfaces.push_back({name, md.defining_loader});
    std::size_t edges = 0;
    bool supplied_self = false;
    for (const auto &node : md.known_hierarchy) {
        if (node.identity.class_name.empty() || node.identity.defining_loader.empty() ||
            node.interfaces.size() > max_hierarchy_edges - std::min(edges, max_hierarchy_edges)) return {};
        edges += node.interfaces.size() + (node.superclass ? 1u : 0u);
        if (edges > max_hierarchy_edges) return {};
        const auto valid_edge = [](const TypeId &edge) { return !edge.class_name.empty() && !edge.defining_loader.empty(); };
        if ((node.superclass && !valid_edge(*node.superclass)) ||
            !std::all_of(node.interfaces.begin(), node.interfaces.end(), valid_edge)) return {};
        if (node.identity == index.self.identity) {
            // The analyzed class may appear once in the supplied graph only
            // when its complete direct edges exactly match the classfile.
            if (supplied_self || !node.complete || node.superclass != index.self.superclass ||
                node.interfaces != index.self.interfaces) return {};
            supplied_self = true;
            continue;
        }
        if (!index.nodes.emplace(type_key(node.identity), node).second) return {};
    }
    index.nodes.emplace(type_key(index.self.identity), index.self);
    return index;
}
std::optional<std::vector<TypeId>> complete_ancestors(const HierarchyIndex &index, const TypeId &start, HierarchyWork &work) {
    if (start.defining_loader.empty() || start.class_name.empty()) return {};
    struct Frame { const JvmHierarchyClass *node; std::size_t next_edge; };
    std::vector<TypeId> result;
    std::vector<Frame> stack;
    std::map<TypeKey, unsigned char> colors;
    std::size_t visited_nodes = 0, visited_edges = 0;
    const auto push = [&](const TypeId &id) -> bool {
        if (++visited_nodes > max_walk_nodes || ++work.nodes > max_query_nodes) return false;
        const auto found = index.nodes.find(type_key(id));
        if (found == index.nodes.end() || !found->second.complete) return false;
        const auto key = type_key(id);
        const auto color = colors.find(key);
        if (color != colors.end()) return color->second == 2; // gray is a cycle; black is a DAG convergence
        colors.emplace(key, 1);
        result.push_back(id);
        stack.push_back({&found->second, 0});
        return true;
    };
    if (!push(start)) return {};
    while (!stack.empty()) {
        auto &frame = stack.back();
        const auto edge_count = frame.node->interfaces.size() + (frame.node->superclass ? 1u : 0u);
        if (frame.next_edge == edge_count) {
            colors[type_key(frame.node->identity)] = 2;
            stack.pop_back();
            continue;
        }
        if (++visited_edges > max_walk_edges || ++work.edges > max_query_edges) return {};
        const TypeId &edge = frame.node->superclass && frame.next_edge == 0
            ? *frame.node->superclass
            : frame.node->interfaces[frame.next_edge++ - (frame.node->superclass ? 1u : 0u)];
        if (frame.node->superclass && frame.next_edge == 0) ++frame.next_edge;
        const auto color = colors.find(type_key(edge));
        if (color != colors.end()) {
            if (color->second == 1) return {};
            continue;
        }
        if (!push(edge)) return {};
    }
    return result;
}
Reference hierarchy_join(const HierarchyIndex &index, HierarchyWork &work, const ReferenceIdentity &left, const ReferenceIdentity &right) {
    const auto to_id = [](const ReferenceIdentity &value) -> std::optional<TypeId> {
        if (value.descriptor.size() < 3 || value.descriptor.front() != 'L' || value.descriptor.back() != ';' ||
            value.defining_loader.empty()) return {};
        return TypeId{value.descriptor.substr(1, value.descriptor.size() - 2), value.defining_loader};
    };
    auto a = to_id(left), b = to_id(right);
    if (!a || !b || a->defining_loader != b->defining_loader) return {};
    auto aa = complete_ancestors(index, *a, work), bb = complete_ancestors(index, *b, work);
    if (!aa || !bb) return {};
    std::vector<TypeId> common;
    std::set<TypeKey> right_ancestors;
    for (const auto &x : *bb) right_ancestors.insert(type_key(x));
    for (const auto &x : *aa) if (right_ancestors.contains(type_key(x))) common.push_back(x);
    if (common.empty() || common.size() > max_common_candidates) return {};
    std::vector<TypeId> minimal;
    std::size_t comparisons = 0;
    for (const auto &candidate : common) {
        bool has_more_specific = false;
        for (const auto &other : common) if (other != candidate) {
            if (++comparisons > max_walk_edges) return {};
            auto ancestors = complete_ancestors(index, other, work);
            if (!ancestors) return {};
            if (std::any_of(ancestors->begin(), ancestors->end(), [&](const auto &ancestor) {
                return type_key(ancestor) == type_key(candidate);
            })) has_more_specific = true;
        }
        if (!has_more_specific) minimal.push_back(candidate);
    }
    if (minimal.size() != 1) return {};
    auto joined = reference_class(minimal.front().class_name);
    if (joined) joined->defining_loader = minimal.front().defining_loader;
    return joined;
}
bool hierarchy_assignable(const HierarchyIndex &index, HierarchyWork &work, const ReferenceIdentity &actual, const ReferenceIdentity &expected) {
    if (actual == expected) return true;
    auto ancestors = complete_ancestors(index, TypeId{actual.descriptor.size() > 2 ? actual.descriptor.substr(1, actual.descriptor.size()-2) : "", actual.defining_loader}, work);
    if (!ancestors || expected.defining_loader.empty() || expected.descriptor.size() < 3 || expected.descriptor.front() != 'L' || expected.descriptor.back() != ';') return false;
    const TypeId target{expected.descriptor.substr(1, expected.descriptor.size()-2), expected.defining_loader};
    return std::find(ancestors->begin(), ancestors->end(), target) != ancestors->end();
}
Reference method_reference_result(std::string_view descriptor) {
    const auto end = descriptor.find(')');
    return end == std::string_view::npos ? Reference{} : reference_descriptor(descriptor.substr(end + 1));
}
Result<MethodDescriptor> parse_method_descriptor(std::string_view descriptor) {
    if (descriptor.empty() || descriptor.front() != '(') return no("method descriptor is malformed");
    std::size_t position = 1;
    MethodDescriptor parsed;
    while (position < descriptor.size() && descriptor[position] != ')') {
        auto type = descriptor_type(descriptor, position);
        if (!type) return type.error();
        parsed.parameters.push_back(type.value());
        if (parsed.parameters.size() > 255) return no("method descriptor exceeds the JVM parameter limit");
    }
    if (position >= descriptor.size() || descriptor[position++] != ')') return no("method descriptor has no close parenthesis");
    auto result = descriptor_type(descriptor, position, true);
    if (!result || position != descriptor.size()) return no("method return descriptor is malformed");
    if (result.value().kind != TypeKind::unknown) parsed.result = result.value();
    std::size_t parameter_slots=0;
    for(const auto &parameter:parsed.parameters)parameter_slots+=parameter.bits==64?2u:1u;
    if(parameter_slots>255)return no("method descriptor exceeds the JVM parameter-slot limit");
    return parsed;
}
}
Result<LiftedFunction> lift_jvm_function(const FunctionRecord &function,const FunctionSnapshot &snapshot,const JvmMetadata *metadata){
    std::map<std::uint64_t,std::shared_ptr<const BasicBlock>> blocks;
    for(const auto &b:snapshot.blocks){if(!b)return Error{ErrorCode::invalid_argument,"JVM snapshot has a null basic block"};if(!blocks.emplace(b->id.value,b).second)return Error{ErrorCode::invalid_argument,"JVM snapshot has duplicate basic-block IDs"};}
    const auto count = function.blocks.size();
    if (!count) return no("function has no basic blocks");
    // Build one bounded immutable graph index per lifted method. The subsequent
    // dataflow worklist may revisit joins many times, so it must not rebuild it.
    const auto hierarchy = metadata ? index_hierarchy(*metadata) : std::optional<HierarchyIndex>{};
    HierarchyWork hierarchy_work;
    std::map<std::uint64_t, std::size_t> block_positions;
    std::map<std::pair<std::uint32_t, std::uint64_t>, std::size_t> address_positions;
    std::vector<const BasicBlock *> sources(count);
    std::optional<std::size_t> entry;
    for (std::size_t i = 0; i < count; ++i) {
        const auto found = blocks.find(function.blocks[i].value);
        if (found == blocks.end()) return Error{ErrorCode::invalid_argument, "JVM function block is absent from snapshot"};
        sources[i] = found->second.get();
        for (const auto &fact : sources[i]->instructions)
            if (!fact) return Error{ErrorCode::invalid_argument, "JVM basic block contains a null instruction"};
        if (!block_positions.emplace(function.blocks[i].value, i).second ||
            !address_positions.emplace(std::pair{sources[i]->begin.space.value, sources[i]->begin.offset}, i).second)
            return no("duplicate basic-block identity or address");
        if (sources[i]->begin == function.entry) entry = i;
    }
    if (!entry) return no("function entry has no basic block");
    constexpr std::string_view exception_cap_diagnostic =
        "JVM exception table exceeds the bounded CFG handler budget";
    if (std::any_of(function.stops.begin(), function.stops.end(), [&](const auto &stop) {
            return stop.detail == exception_cap_diagnostic;
        }))
        return no("exception-edge coverage is incomplete because the bounded handler scan was exhausted");
    std::vector<std::vector<std::size_t>> successors(count), predecessors(count);
    std::vector<bool> handler_entries(count, false);
    for (std::size_t i = 0; i < count; ++i) {
        for (const auto &edge : sources[i]->successors) {
            std::optional<std::size_t> target_position;
            if (edge.block) {
                const auto found = block_positions.find(edge.block->value);
                if (found == block_positions.end()) return no("CFG successor block is outside the function");
                target_position = found->second;
            }
            if (edge.target) {
                const auto found = address_positions.find({edge.target->space.value, edge.target->offset});
                if (found != address_positions.end()) {
                    if (target_position && *target_position != found->second) return no("CFG edge identity disagrees with target address");
                    target_position = found->second;
                } else if (target_position) return no("CFG edge target address is outside its target block");
            }
            if (edge.kind == BlockEdgeKind::exception) {
                if (!target_position) return no("exception handler target is unresolved");
                handler_entries[*target_position] = true;
            } else if (target_position) {
                auto &targets = successors[i];
                if (std::find(targets.begin(), targets.end(), *target_position) == targets.end()) {
                    targets.push_back(*target_position);
                    predecessors[*target_position].push_back(i);
                }
            } else return no("CFG successor target is unresolved");
        }
    }
    for (std::size_t i = 0; i < count; ++i)
        if (handler_entries[i] && (i == *entry || !predecessors[i].empty()))
            return no("exception handler also has an ordinary entry path");
    const JvmCode *code = nullptr;
    const JvmMember *method = nullptr;
    if (metadata) for (const auto &member : metadata->methods)
        if (member.code && member.code->begin == function.entry) {
            if (code) return no("method Code metadata is ambiguous");
            code = &*member.code;
            method = &member;
        }
    if (code) for (const auto *block : sources) {
        if (block->begin.space != code->begin.space || block->begin.offset < code->begin.offset ||
            block->begin.offset - code->begin.offset >= code->code_size)
            return no("basic block lies outside the method Code range");
        for (const auto &fact : block->instructions)
            if (fact->instruction.address.space != code->begin.space || fact->instruction.address.offset < code->begin.offset ||
                fact->instruction.address.offset - code->begin.offset >= code->code_size)
                return no("instruction lies outside the method Code range");
    }
    const auto valid_stack = [&](const std::vector<ExpressionPtr> &stack) {
        if (stack.size() > 256) return false;
        std::size_t physical_slots = 0;
        for (const auto &value : stack) {
            if (!value) return false;
            physical_slots += value->type.bits == 64 ? 2 : 1;
        }
        return !code || physical_slots <= code->max_stack;
    };
    std::array<std::uint32_t, 256> versions{};
    struct ExceptionalReference {
        std::size_t target;
        std::shared_ptr<std::array<Reference, 256>> locals;
    };
    struct Transfer {
        LiftedBlock block;
        std::vector<ExpressionPtr> stack;
        std::vector<ExceptionalReference> exceptional_references;
    };
    // Shape inference and final emission deliberately share the same opcode
    // transfer, so stack manipulation and descriptor effects cannot diverge.
    const auto transfer = [&](std::size_t block_index, std::vector<ExpressionPtr> stack, bool shapes_only,
                              ReferenceState *references = nullptr) -> Result<Transfer> {
        const auto &src = *sources[block_index];
        LiftedBlock dst{src.id, src.begin, {}, src.successors};
        std::vector<ExceptionalReference> exceptional_references;
        std::shared_ptr<std::array<Reference, 256>> exceptional_locals;
        // Owning keys prevent allocator address reuse from attributing a popped
        // value's identity to an unrelated expression created later.
        std::map<ExpressionPtr, Reference, std::owner_less<ExpressionPtr>> identities;
        const auto identity = [&](const ExpressionPtr &value) -> Reference {
            const auto found = identities.find(value);
            return found == identities.end() ? Reference{} : found->second;
        };
        const auto evidence = [&](ExpressionPtr value, Reference reference) {
            if (reference && reference->defining_loader.empty() && metadata)
                reference->defining_loader = metadata->defining_loader;
            if (references && value->type == ref32()) identities[value] = std::move(reference);
            return value;
        };
        if (references) {
            if (references->stack.size() != stack.size()) return no("reference evidence disagrees with stack height");
            for (std::size_t slot = 0; slot < stack.size(); ++slot) evidence(stack[slot], references->stack[slot]);
        }
        if (code && !src.instructions.empty()) {
            for (const auto &fact : src.instructions) {
                if (!fact || fact->instruction.bytes.empty()) continue;
                const auto &source = fact->instruction.address;
                const auto opcode = std::to_integer<std::uint8_t>(fact->instruction.bytes.front());
                if (!jvm_may_throw(opcode)) continue;
                for (const auto &handler : code->exception_table) {
                    const auto start = code->begin.offset + handler.start_pc;
                    const auto end = code->begin.offset + handler.end_pc;
                    const auto target_address = Address{source.space, code->begin.offset + handler.handler_pc};
                    if (source.offset < start || source.offset >= end) continue;
                    if (std::none_of(src.successors.begin(), src.successors.end(), [&](const auto &edge) {
                            return edge.kind == BlockEdgeKind::exception && edge.source == source &&
                                   edge.target == target_address;
                        })) return no("protected throwing instruction is missing a handler edge");
                    std::optional<std::string> catch_type;
                    if (handler.catch_type) {
                        if (handler.catch_type >= metadata->constant_pool.size() ||
                            metadata->constant_pool[handler.catch_type].tag != 7)
                            return no("exception table catch type is not a valid CONSTANT_Class");
                        auto name = cp_class_name(*metadata, handler.catch_type);
                        if (!name) return name.error();
                        catch_type = std::move(name.value());
                    }
                    const auto existing = std::find_if(dst.exception_handlers.begin(), dst.exception_handlers.end(),
                        [&](const auto &dispatch) {
                            return dispatch.target == target_address && dispatch.catch_type == catch_type &&
                                   dispatch.catch_all == (handler.catch_type == 0);
                        });
                    if (existing == dst.exception_handlers.end()) {
                        LiftedBlock::ExceptionHandlerDispatch dispatch;
                        dispatch.target = target_address;
                        dispatch.catch_type = std::move(catch_type);
                        dispatch.catch_all = handler.catch_type == 0;
                        dispatch.protected_throw_sites.push_back(source);
                        dst.exception_handlers.push_back(std::move(dispatch));
                    } else if (std::find(existing->protected_throw_sites.begin(), existing->protected_throw_sites.end(),
                                         source) == existing->protected_throw_sites.end()) {
                        existing->protected_throw_sites.push_back(source);
                    }
                }
            }
        }
        for (const auto &edge : src.successors) if (edge.kind == BlockEdgeKind::exception) {
            if (!code || !edge.target) return no("exception edge has no method Code or target");
            const auto site = std::find_if(src.instructions.begin(), src.instructions.end(), [&](const auto &fact) {
                return fact->instruction.address == edge.source;
            });
            if (site == src.instructions.end() || (*site)->instruction.bytes.empty())
                return no("exception edge has no throwing instruction");
            const auto opcode = std::to_integer<std::uint8_t>((*site)->instruction.bytes.front());
            if (!jvm_may_throw(opcode) || std::next(site) != src.instructions.end())
                return no("exception edge does not end at a modeled throwing instruction");
            if (std::none_of(code->exception_table.begin(), code->exception_table.end(), [&](const auto &handler) {
                return edge.source.offset >= code->begin.offset + handler.start_pc &&
                       edge.source.offset < code->begin.offset + handler.end_pc &&
                       *edge.target == Address{code->begin.space, code->begin.offset + handler.handler_pc};
            })) return no("exception edge is absent from method exception table");
            auto timing = LiftedBlock::ExceptionMemoryTiming::opaque_effect;
            if ((opcode >= 0x2e && opcode <= 0x35) || (opcode >= 0x4f && opcode <= 0x56) ||
                opcode == 0xbe || opcode == 0xbf)
                timing = LiftedBlock::ExceptionMemoryTiming::before_instruction;
            if (opcode >= 0x12 && opcode <= 0x14) {
                const auto index = imm((*site)->instruction);
                if (!index || !metadata || *index >= metadata->constant_pool.size())
                    return no("throwing ldc has no valid constant-pool entry");
                const auto tag = metadata->constant_pool[*index].tag;
                if (tag == 3 || tag == 4 || tag == 5 || tag == 6)
                    timing = LiftedBlock::ExceptionMemoryTiming::before_instruction;
            }
            if (std::none_of(dst.exception_memory_edges.begin(), dst.exception_memory_edges.end(),
                    [&](const auto &candidate) { return candidate.target == *edge.target; }))
                dst.exception_memory_edges.push_back({edge.source, *edge.target, timing});
        }
        auto pop=[&](ValueType want)->Result<ExpressionPtr>{if(stack.empty())return no("operand stack underflow");auto v=stack.back();stack.pop_back();if(v->type!=want)return no("operand stack type mismatch");return v;};
        auto pop_any=[&]()->Result<ExpressionPtr>{if(stack.empty())return no("operand stack underflow in stack manipulation");auto v=stack.back();stack.pop_back();return v;};
        auto emit=[&](const InstructionFact &f,Statement s){dst.instructions.push_back({{f.instruction.address,f.id},std::move(s)});};
        for(std::size_t ix=0;ix<src.instructions.size();++ix){if(!valid_stack(stack))return no("operand stack exceeds max_stack or the 256 logical-slot IR limit");const auto &fact=src.instructions[ix];if(!fact)return Error{ErrorCode::invalid_argument,"JVM basic block contains a null instruction"};const auto &i=fact->instruction;if(i.context.architecture!=Architecture::jvm||i.bytes.empty())return no("non-JVM instruction in function");const auto op=std::to_integer<std::uint8_t>(i.bytes[0]);
            if (references) for (const auto &edge : src.successors)
                if (edge.kind == BlockEdgeKind::exception && edge.source == i.address && edge.target) {
                    const auto target = address_positions.find({edge.target->space.value, edge.target->offset});
                    if (target == address_positions.end()) return no("exception reference target is unresolved");
                    if (std::none_of(exceptional_references.begin(), exceptional_references.end(),
                            [&](const auto &snapshot) { return snapshot.target == target->second; })) {
                        if (!exceptional_locals)
                            exceptional_locals = std::make_shared<std::array<Reference, 256>>(references->locals);
                        exceptional_references.push_back({target->second, exceptional_locals});
                    }
                }
            if ((target(i) || (op >= 0xac && op <= 0xb1) || op == 0xbf) && ix+1 != src.instructions.size())
                return no("control transfer is not at basic-block end");
            if (target(i) && i.direct_target && std::none_of(src.successors.begin(), src.successors.end(), [&](const auto &edge) {
                    return edge.kind != BlockEdgeKind::exception && edge.target == i.direct_target;
                })) return no("decoded control-transfer target is absent from the CFG");
            if (i.flow == FlowKind::conditional_branch && std::none_of(src.successors.begin(), src.successors.end(), [](const auto &edge) {
                    return edge.kind == BlockEdgeKind::conditional_false && edge.target.has_value();
                })) return no("conditional CFG has no fallthrough successor");
            if(op==0x00)continue;
            if(op==0x01){stack.push_back(evidence(con(0,ref32()),ReferenceIdentity{JvmVerificationKind::null_value,{},0}));continue;}
            if(op>=0x02&&op<=0x08){const auto v=static_cast<std::int32_t>(op)-3;stack.push_back(con(static_cast<std::uint32_t>(v),int32()));continue;}
            if(op==0x09||op==0x0a){stack.push_back(con(op-0x09,int64()));continue;}
            if(op>=0x0b&&op<=0x0d){stack.push_back(con(op==0x0b?0:op==0x0c?0x3f800000:0x40000000,fp32()));continue;}
            if(op==0x0e||op==0x0f){stack.push_back(con(op-0x0e,fp64()));continue;}
            if(op==0x10||op==0x11){auto v=imm(i);if(!v)return no("integer push immediate unavailable");std::int64_t s=op==0x10?static_cast<std::int8_t>(*v):static_cast<std::int16_t>(*v);stack.push_back(con(static_cast<std::uint32_t>(s),int32()));continue;}
            if(op==0x12||op==0x13||op==0x14){
                if(!metadata)return no("ldc requires JVM constant-pool metadata");
                const auto index=imm(i);if(!index||!*index||*index>=metadata->constant_pool.size())return no("ldc constant-pool index is invalid");
                const auto &constant=metadata->constant_pool[*index];
                if(op==0x14){
                    if(constant.tag==5){stack.push_back(con(constant.first,int64()));continue;}
                    if(constant.tag==6){stack.push_back(con(constant.first,fp64()));continue;}
                    if(constant.tag!=17)return no("ldc2_w requires a long, double, or supported dynamic constant");
                }else{
                    if(constant.tag==3){stack.push_back(con(constant.first,int32()));continue;}
                    if(constant.tag==4){stack.push_back(con(constant.first,fp32()));continue;}
                    if(constant.tag==8){
                        auto value=cp_utf8(*metadata,constant.first);if(!value)return value.error();
                        const auto description="jvm_string_constant cp#"+std::to_string(*index)+" \""+string_constant_preview(value.value())+"\"";
                        Intrinsic load;load.name=description;load.memory_effect=IntrinsicMemoryEffect::unknown;load.result_type=ref32();
                        emit(*fact,std::move(load));stack.push_back(evidence(unknown(description,ref32()),reference_class("java/lang/String")));continue;
                    }
                    if(constant.tag==7){
                        auto name=cp_class_name(*metadata,*index);if(!name)return name.error();
                        const auto description="jvm_class_constant "+name.value()+" cp#"+std::to_string(*index);
                        Intrinsic load;load.name=description;load.memory_effect=IntrinsicMemoryEffect::unknown;load.result_type=ref32();
                        emit(*fact,std::move(load));stack.push_back(evidence(unknown(description,ref32()),reference_class("java/lang/Class")));continue;
                    }
                    if(constant.tag!=17)return no("ldc constant kind is not modeled");
                }
                auto dynamic=cp_dynamic_constant(*metadata,*index);if(!dynamic)return dynamic.error();
                std::size_t position=0;auto type=descriptor_type(dynamic.value().descriptor,position);
                if(!type||position!=dynamic.value().descriptor.size())return no("dynamic constant descriptor is malformed");
                const bool category2=type.value().bits==64;
                if(category2!=(op==0x14))return no("ldc form disagrees with dynamic constant category");
                const auto description="jvm_ldc_dynamic "+dynamic.value().name+":"+dynamic.value().descriptor+
                    " bootstrap#"+std::to_string(dynamic.value().bootstrap_index)+" cp#"+std::to_string(*index);
                Intrinsic load;load.name=description;load.memory_effect=IntrinsicMemoryEffect::unknown;load.result_type=type.value();
                emit(*fact,std::move(load));stack.push_back(evidence(unknown(description,type.value()),reference_descriptor(dynamic.value().descriptor)));continue;
            }
            const bool wide=i.mnemonic_override.starts_with("wide ");const auto sem_op=wide?static_cast<unsigned>(imm(i,0).value_or(op)):op;
            if((sem_op>=0x15&&sem_op<=0x19)||(sem_op>=0x1a&&sem_op<=0x2d)||(sem_op>=0x36&&sem_op<=0x3a)||(sem_op>=0x3b&&sem_op<=0x4e)){
                unsigned index=0;unsigned kind=0;bool store=sem_op>=0x36&&sem_op<=0x4e;
                if((sem_op>=0x15&&sem_op<=0x19)||(sem_op>=0x36&&sem_op<=0x3a)){auto v=imm(i,wide?1:0);if(!v)return no("local index unavailable");index=static_cast<unsigned>(*v);kind=store?sem_op-0x36:sem_op-0x15;}
                else if(!store){if(sem_op<=0x2d){kind=(sem_op-0x1a)/4;index=(sem_op-0x1a)%4;}}
                else {kind=(sem_op-0x3b)/4;index=(sem_op-0x3b)%4;}
                if(kind>4)return no("invalid local access kind");if(index>255)return no("local index exceeds common-IR register-key width");
                const auto type=kind==0?int32():kind==1?int64():kind==2?fp32():kind==3?fp64():ref32();RegisterOperand local{RegisterBank::jvm_local,static_cast<std::uint8_t>(index),type.bits,false};
                if (code && static_cast<std::size_t>(index) + (type.bits == 64 ? 2u : 1u) > code->max_locals)
                    return no("local access exceeds Code.max_locals");
                if (store) {
                    auto v=pop(type);if(!v)return v.error();emit(*fact,Assign{local,v.value()});
                    if (references) {
                        // A category-2 store invalidates both physical local slots.
                        references->locals[index] = type == ref32() ? identity(v.value()) : Reference{};
                        if (type.bits == 64 && index + 1 < references->locals.size()) references->locals[index + 1].reset();
                    }
                }
                else if (shapes_only) stack.push_back(evidence(unknown("local_shape", type),references ? references->locals[index] : Reference{}));
                else {
                    // Freeze the local at the load instruction. A later local
                    // store must not change a value still on the operand stack.
                    const auto slot = stack.size();
                    if (slot >= versions.size() || versions[slot] == std::numeric_limits<std::uint32_t>::max())
                        return no("stack SSA register/version limit exceeded");
                    const auto version = ++versions[slot];
                    const RegisterOperand temporary{RegisterBank::jvm_stack, static_cast<std::uint8_t>(slot), type.bits, false};
                    emit(*fact, Assign{temporary, reg(local, type), version});
                    stack.push_back(evidence(std::make_shared<Expression>(Expression{type, RegisterValue{temporary, version}}),
                                             references ? references->locals[index] : Reference{}));
                }
                continue;
            }
            if(sem_op==0x84){auto index=imm(i,wide?1:0),delta=imm(i,wide?2:1);if(!index||!delta)return no("iinc operands unavailable");if(*index>255)return no("iinc local index exceeds common-IR register-key width");if(code&&*index>=code->max_locals)return no("iinc local index exceeds Code.max_locals");if(references)references->locals[*index].reset();const auto d=wide?static_cast<std::int16_t>(*delta):static_cast<std::int8_t>(*delta);RegisterOperand local{RegisterBank::jvm_local,static_cast<std::uint8_t>(*index),32,false};emit(*fact,Assign{local,bin("add",reg(local),con(static_cast<std::uint32_t>(d),int32()),int32())});continue;}
            if(op>=0x2e&&op<=0x35){
                static constexpr const char *names[]={"iaload","laload","faload","daload","aaload","baload","caload","saload"};
                const ValueType types[]={int32(),int64(),fp32(),fp64(),ref32(),int32(),int32(),int32()};
                auto index=pop(int32());if(!index)return index.error();auto array=pop(ref32());if(!array)return array.error();
                Intrinsic load;load.name=std::string("jvm_")+names[op-0x2e];load.operands={array.value(),index.value()};
                load.memory_effect=IntrinsicMemoryEffect::read;load.result_type=types[op-0x2e];
                const auto result_name=load.name;const auto result_type=*load.result_type;emit(*fact,std::move(load));
                Reference element;
                if (op == 0x32) {
                    const auto array_type = identity(array.value());
                    if (array_type && array_type->kind == JvmVerificationKind::object &&
                        array_type->descriptor.starts_with("["))
                        element = reference_descriptor(std::string_view(array_type->descriptor).substr(1));
                }
                stack.push_back(evidence(unknown(result_name,result_type),std::move(element)));continue;
            }
            if(op>=0x4f&&op<=0x56){
                static constexpr const char *names[]={"iastore","lastore","fastore","dastore","aastore","bastore","castore","sastore"};
                const ValueType types[]={int32(),int64(),fp32(),fp64(),ref32(),int32(),int32(),int32()};
                const auto slot=op-0x4f;auto value=pop(types[slot]);if(!value)return value.error();
                auto index=pop(int32());if(!index)return index.error();auto array=pop(ref32());if(!array)return array.error();
                Intrinsic store;store.name=std::string("jvm_")+names[slot];store.operands={array.value(),index.value(),value.value()};
                store.memory_effect=IntrinsicMemoryEffect::write;emit(*fact,std::move(store));continue;
            }
            if(op==0xbc||op==0xbd){
                auto length=pop(int32());if(!length)return length.error();std::string element, array_descriptor;
                if(op==0xbc){
                    static constexpr const char *types[]={"","","","","boolean","char","float","double","byte","short","int","long"};
                    const auto atype=imm(i);if(!atype||*atype<4||*atype>11)return no("newarray primitive type is invalid");element=types[*atype];
                    static constexpr char codes[] = {'Z','C','F','D','B','S','I','J'};
                    array_descriptor = std::string("[") + codes[*atype - 4];
                }else{
                    if(!metadata)return no("reference array allocation requires JVM constant-pool metadata");
                    const auto index=imm(i);if(!index)return no("anewarray class index unavailable");
                    auto name=cp_class_name(*metadata,*index);if(!name)return name.error();element=std::move(name.value());
                    const auto component = reference_class(element);
                    if (component) array_descriptor = "[" + component->descriptor;
                }
                Intrinsic allocation;allocation.name="jvm_newarray "+element;allocation.operands.push_back(length.value());
                allocation.memory_effect=IntrinsicMemoryEffect::unknown;allocation.result_type=ref32();
                const auto result_name=allocation.name;emit(*fact,std::move(allocation));stack.push_back(evidence(unknown(result_name,ref32()),reference_descriptor(array_descriptor)));continue;
            }
            if(op==0xbe){
                auto array=pop(ref32());if(!array)return array.error();Intrinsic length;length.name="jvm_arraylength";
                length.operands.push_back(array.value());length.memory_effect=IntrinsicMemoryEffect::read;length.result_type=int32();
                emit(*fact,std::move(length));stack.push_back(unknown("jvm_arraylength",int32()));continue;
            }
            if(op==0xc0||op==0xc1){
                if(!metadata)return no("type check requires JVM constant-pool metadata");
                const auto index=imm(i);if(!index)return no("type-check class index unavailable");
                auto name=cp_class_name(*metadata,*index);if(!name)return name.error();
                auto object=pop(ref32());if(!object)return object.error();
                Intrinsic check;check.name=(op==0xc0?"jvm_checkcast ":"jvm_instanceof ")+name.value();
                check.operands.push_back(object.value());check.memory_effect=IntrinsicMemoryEffect::unknown;
                check.result_type=op==0xc0?ref32():int32();
                const auto description=check.name;const auto result=*check.result_type;
                emit(*fact,std::move(check));stack.push_back(evidence(unknown(description,result),op==0xc0?reference_class(name.value()):Reference{}));continue;
            }
            if(op==0xc2||op==0xc3){
                auto object=pop(ref32());if(!object)return object.error();
                Intrinsic monitor;monitor.name=op==0xc2?"jvm_monitorenter":"jvm_monitorexit";
                monitor.operands.push_back(object.value());monitor.memory_effect=IntrinsicMemoryEffect::unknown;
                emit(*fact,std::move(monitor));continue;
            }
            if(op==0xc5){
                if(!metadata)return no("multianewarray requires JVM constant-pool metadata");
                const auto index=imm(i),dimensions=imm(i,1);
                if(!index||!dimensions||!*dimensions)return no("multianewarray dimensions are invalid");
                auto descriptor=cp_class_name(*metadata,*index);if(!descriptor)return descriptor.error();
                const auto array_dimensions=static_cast<std::uint64_t>(std::count(descriptor.value().begin(),descriptor.value().end(),'['));
                std::size_t descriptor_position=0;auto array_type=descriptor_type(descriptor.value(),descriptor_position);
                if(!array_dimensions||array_dimensions>255||!array_type||array_type.value().kind!=TypeKind::pointer||
                   descriptor_position!=descriptor.value().size())return no("multianewarray class descriptor is malformed");
                if(*dimensions>array_dimensions)return no("multianewarray dimensions exceed the class descriptor rank");
                std::vector<ExpressionPtr> sizes(static_cast<std::size_t>(*dimensions));
                for(std::size_t n=sizes.size();n>0;--n){auto size=pop(int32());if(!size)return size.error();sizes[n-1]=size.value();}
                Intrinsic allocation;allocation.name="jvm_multianewarray "+descriptor.value()+" dims="+std::to_string(*dimensions);
                allocation.operands=std::move(sizes);allocation.memory_effect=IntrinsicMemoryEffect::unknown;allocation.result_type=ref32();
                const auto description=allocation.name;emit(*fact,std::move(allocation));stack.push_back(evidence(unknown(description,ref32()),reference_descriptor(descriptor.value())));continue;
            }
            if(op==0x57){auto a=pop_any();if(!a)return a.error();if(a.value()->type.bits>32)return no("pop cannot consume a category-2 value");continue;}
            if(op==0x58){auto a=pop_any();if(!a)return a.error();if(a.value()->type.bits<=32){auto b=pop_any();if(!b)return b.error();if(b.value()->type.bits>32)return no("pop2 has an invalid category form");}continue;}
            if(op>=0x59&&op<=0x5e){
                const auto cat2=[](const ExpressionPtr &value){return value->type.bits>32;};
                auto v1=pop_any();if(!v1)return v1.error();
                if(op==0x59){if(cat2(v1.value()))return no("dup requires a category-1 value");stack.push_back(v1.value());stack.push_back(v1.value());continue;}
                if(op==0x5a){auto v2=pop_any();if(!v2)return v2.error();if(cat2(v1.value())||cat2(v2.value()))return no("dup_x1 requires two category-1 values");stack.push_back(v1.value());stack.push_back(v2.value());stack.push_back(v1.value());continue;}
                if(op==0x5b){auto v2=pop_any();if(!v2)return v2.error();if(cat2(v1.value()))return no("dup_x2 top value must be category-1");if(cat2(v2.value())){stack.push_back(v1.value());stack.push_back(v2.value());stack.push_back(v1.value());}else{auto v3=pop_any();if(!v3)return v3.error();if(cat2(v3.value()))return no("dup_x2 category-1 form has an invalid shape");stack.push_back(v1.value());stack.push_back(v3.value());stack.push_back(v2.value());stack.push_back(v1.value());}continue;}
                if(op==0x5c){if(cat2(v1.value())){stack.push_back(v1.value());stack.push_back(v1.value());}else{auto v2=pop_any();if(!v2)return v2.error();if(cat2(v2.value()))return no("dup2 has an invalid category form");stack.push_back(v2.value());stack.push_back(v1.value());stack.push_back(v2.value());stack.push_back(v1.value());}continue;}
                if(op==0x5d){if(cat2(v1.value())){auto v2=pop_any();if(!v2)return v2.error();if(cat2(v2.value()))return no("dup2_x1 category-2 form requires a category-1 value below");stack.push_back(v1.value());stack.push_back(v2.value());stack.push_back(v1.value());}else{auto v2=pop_any();if(!v2)return v2.error();if(cat2(v2.value()))return no("dup2_x1 top pair must be category-1");auto v3=pop_any();if(!v3)return v3.error();if(cat2(v3.value()))return no("dup2_x1 category-1 form requires three category-1 values");stack.push_back(v2.value());stack.push_back(v1.value());stack.push_back(v3.value());stack.push_back(v2.value());stack.push_back(v1.value());}continue;}
                if(cat2(v1.value())){auto v2=pop_any();if(!v2)return v2.error();if(cat2(v2.value())){stack.push_back(v1.value());stack.push_back(v2.value());stack.push_back(v1.value());}else{auto v3=pop_any();if(!v3)return v3.error();if(cat2(v3.value()))return no("dup2_x2 has an invalid mixed category form");stack.push_back(v1.value());stack.push_back(v3.value());stack.push_back(v2.value());stack.push_back(v1.value());}}
                else{auto v2=pop_any();if(!v2)return v2.error();if(cat2(v2.value()))return no("dup2_x2 top pair must be category-1");auto v3=pop_any();if(!v3)return v3.error();if(cat2(v3.value())){stack.push_back(v2.value());stack.push_back(v1.value());stack.push_back(v3.value());stack.push_back(v2.value());stack.push_back(v1.value());}else{auto v4=pop_any();if(!v4)return v4.error();if(cat2(v4.value()))return no("dup2_x2 category-1 form requires four category-1 values");stack.push_back(v2.value());stack.push_back(v1.value());stack.push_back(v4.value());stack.push_back(v3.value());stack.push_back(v2.value());stack.push_back(v1.value());}}
                continue;
            }
            if(op==0x5f){auto v1=pop_any();if(!v1)return v1.error();auto v2=pop_any();if(!v2)return v2.error();if(v1.value()->type.bits>32||v2.value()->type.bits>32)return no("swap requires two category-1 values");stack.push_back(v1.value());stack.push_back(v2.value());continue;}
            if(op>=0x60&&op<=0x83){static constexpr const char *ops[]={"add","add","add","add","sub","sub","sub","sub","mul","mul","mul","mul","div","div","div","div","rem","rem","rem","rem","neg","neg","neg","neg","shl","shl","shr","shr","ushr","ushr","and","and","or","or","xor","xor"};const auto slot=op-0x60;const auto kind=op>=0x78?static_cast<unsigned>((op-0x78)%2):slot%4;const auto type=kind==0?int32():kind==1?int64():kind==2?fp32():fp64();const bool unary_op=op>=0x74&&op<=0x77;if(unary_op){auto a=pop(type);if(!a)return a.error();stack.push_back(un(ops[slot],a.value(),type));continue;}if(op==0x6c||op==0x6d||op==0x70||op==0x71)return no("integer division/remainder trap behavior is not represented");const bool shift=op==0x78||op==0x79||op==0x7a||op==0x7b||op==0x7c||op==0x7d;if(shift){auto rhs=pop(int32());if(!rhs)return rhs.error();auto lhs=pop(type);if(!lhs)return lhs.error();stack.push_back(bin(ops[slot],lhs.value(),rhs.value(),type));}else{auto rhs=pop(type);if(!rhs)return rhs.error();auto lhs=pop(type);if(!lhs)return lhs.error();stack.push_back(bin(ops[slot],lhs.value(),rhs.value(),type));}continue;}
            if(op>=0x94&&op<=0x98){const auto type=op==0x94?int64():op<=0x96?fp32():fp64();auto rhs=pop(type);if(!rhs)return rhs.error();auto lhs=pop(type);if(!lhs)return lhs.error();stack.push_back(bin(i.mnemonic_override,lhs.value(),rhs.value(),int32()));continue;}
            if(op>=0x85&&op<=0x93){const ValueType types[]={int64(),fp32(),fp64(),int32(),fp32(),fp64(),int32(),int64(),fp64(),int32(),int64(),fp32(),int32(),int32(),int32()};const ValueType from[]={int32(),int32(),int32(),int64(),int64(),int64(),fp32(),fp32(),fp32(),fp64(),fp64(),fp64(),int32(),int32(),int32()};auto v=pop(from[op-0x85]);if(!v)return v.error();stack.push_back(un(i.mnemonic_override,v.value(),types[op-0x85]));continue;}
            if(op>=0x99&&op<=0x9e){if(ix+1!=src.instructions.size())return no("conditional transfer is not block-terminating");if(!i.direct_target)return no("conditional target unavailable");auto v=pop(int32());if(!v)return v.error();static constexpr const char *cmp[]={"eq","ne","slt","sge","sgt","sle"};auto pred=bin(cmp[op-0x99],v.value(),con(0,int32()),{TypeKind::boolean,1,false});auto false_target=std::optional<Address>{};for(const auto &e:src.successors)if(e.kind==BlockEdgeKind::conditional_false&&e.target)false_target=e.target;emit(*fact,Branch{"predicate",i.direct_target,false_target,pred});continue;}
            if(op>=0x9f&&op<=0xa4){if(ix+1!=src.instructions.size())return no("conditional transfer is not block-terminating");if(!i.direct_target)return no("conditional target unavailable");auto rhs=pop(int32());if(!rhs)return rhs.error();auto lhs=pop(int32());if(!lhs)return lhs.error();static constexpr const char *cmp[]={"eq","ne","slt","sge","sgt","sle"};auto pred=bin(cmp[op-0x9f],lhs.value(),rhs.value(),{TypeKind::boolean,1,false});auto false_target=std::optional<Address>{};for(const auto &e:src.successors)if(e.kind==BlockEdgeKind::conditional_false&&e.target)false_target=e.target;emit(*fact,Branch{"predicate",i.direct_target,false_target,pred});continue;}
            if(op==0xa7||op==0xc8){if(!i.direct_target)return no("goto target unavailable");emit(*fact,Branch{"true",i.direct_target,{}});continue;}
            if(op>=0xac&&op<=0xb0){const auto type=op==0xac?int32():op==0xad?int64():op==0xae?fp32():op==0xaf?fp64():ref32();auto v=pop(type);if(!v)return v.error();if(!stack.empty())return no("return leaves extra operand-stack values");emit(*fact,Return{v.value()});continue;}
            if(op==0xb1){if(!stack.empty())return no("void return leaves operand-stack values");emit(*fact,Return{});continue;}
            if(op==0xbf){auto exception=pop(ref32());if(!exception)return exception.error();if(!stack.empty())return no("athrow leaves extra operand-stack values");Intrinsic effect;effect.name="jvm_athrow";effect.operands.push_back(exception.value());effect.memory_effect=IntrinsicMemoryEffect::none;emit(*fact,std::move(effect));continue;}
            if(op>=0xb2&&op<=0xb5){
                if(!metadata)return no("field access requires JVM constant-pool metadata");
                auto index=imm(i);if(!index)return no("field constant-pool index unavailable");
                auto member=cp_member(*metadata,*index,false);if(!member)return member.error();
                std::size_t position=0;auto type=descriptor_type(member.value().descriptor,position);
                if(!type||position!=member.value().descriptor.size())return no("field descriptor is malformed");
                // Resolution and static initialization can execute opaque code
                // before a field instruction throws. Preserve that uncertainty.
                Intrinsic effect;effect.memory_effect=IntrinsicMemoryEffect::unknown;
                const auto symbol=member.value().owner+"."+member.value().name;
                if(op==0xb2){effect.name="jvm_getstatic "+symbol;effect.result_type=type.value();const auto result_name=effect.name;emit(*fact,std::move(effect));stack.push_back(evidence(unknown(result_name,type.value()),reference_descriptor(member.value().descriptor)));continue;}
                if(op==0xb3){auto value=pop(type.value());if(!value)return value.error();effect.name="jvm_putstatic "+symbol;effect.operands.push_back(value.value());emit(*fact,std::move(effect));continue;}
                if(op==0xb4){auto object=pop(ref32());if(!object)return object.error();effect.name="jvm_getfield "+symbol;effect.operands.push_back(object.value());effect.result_type=type.value();auto result=evidence(unknown(effect.name,type.value()),reference_descriptor(member.value().descriptor));emit(*fact,std::move(effect));stack.push_back(std::move(result));continue;}
                auto value=pop(type.value());if(!value)return value.error();auto object=pop(ref32());if(!object)return object.error();effect.name="jvm_putfield "+symbol;effect.operands={object.value(),value.value()};emit(*fact,std::move(effect));continue;
            }
            if(op>=0xb6&&op<=0xb9){
                if(!metadata)return no("method invocation requires JVM constant-pool metadata");
                auto index=imm(i);if(!index)return no("method constant-pool index unavailable");
                auto member=cp_member(*metadata,*index,true);if(!member)return member.error();
                const bool is_static=op==0xb8;
                const auto reference_tag=metadata->constant_pool[*index].tag;
                if(op==0xb9&&reference_tag!=11)return no("invokeinterface requires an interface method reference");
                if(op==0xb6&&reference_tag!=10)return no("invokevirtual requires a class method reference");
                if((op==0xb7||op==0xb8)&&reference_tag==11&&metadata->major_version<52)
                    return no("interface method references for invokespecial/invokestatic require classfile version 52+");
                auto signature=parse_method_descriptor(member.value().descriptor);if(!signature)return signature.error();
                std::vector<ExpressionPtr> arguments(signature.value().parameters.size()+(is_static?0u:1u));
                for(std::size_t n=signature.value().parameters.size();n>0;--n){auto value=pop(signature.value().parameters[n-1]);if(!value)return value.error();arguments[n-1+(is_static?0u:1u)]=value.value();}
                if(!is_static){auto receiver=pop(ref32());if(!receiver)return receiver.error();arguments[0]=receiver.value();}
                if (references && op == 0xb7 && member.value().name == "<init>") {
                    const auto receiver = identity(arguments[0]);
                    const auto initialized = reference_class(member.value().owner);
                    const bool exact_new = receiver && initialized &&
                        receiver->kind == JvmVerificationKind::uninitialized &&
                        receiver->descriptor == initialized->descriptor && !signature.value().result;
                    const bool constructor_chain = method && metadata && method->name == "<init>" && receiver &&
                        receiver->kind == JvmVerificationKind::uninitialized_this && !signature.value().result &&
                        (member.value().owner == metadata->class_name ||
                         (!metadata->super_name.empty() && member.value().owner == metadata->super_name));
                    const auto initialized_this = constructor_chain ? reference_class(metadata->class_name) : Reference{};
                    if (receiver && (receiver->kind == JvmVerificationKind::uninitialized ||
                                     receiver->kind == JvmVerificationKind::uninitialized_this))
                        if (exceptional_locals)
                            for (auto &value : *exceptional_locals)
                                if (value == receiver) value.reset();
                    const auto initialize_alias = [&](Reference &value) {
                        if (!value || (value->kind != JvmVerificationKind::uninitialized &&
                                       value->kind != JvmVerificationKind::uninitialized_this)) return;
                        if (receiver && *value != *receiver) return;
                        // `new` aliases initialize only through the exact
                        // allocated class. `uninitializedThis` initializes
                        // only after this class or its direct superclass
                        // constructor returns normally.
                        value = exact_new ? initialized : constructor_chain ? initialized_this : Reference{};
                    };
                    for (auto &entry : identities) initialize_alias(entry.second);
                    for (auto &value : references->locals) initialize_alias(value);
                }
                if(op==0xb9){
                    if(!imm(i,1)||!imm(i,2)||*imm(i,2)!=0)return no("invokeinterface trailing operands are malformed");
                    std::size_t slots=1;for(const auto &parameter:signature.value().parameters)slots+=parameter.bits==64?2u:1u;
                    if(slots>255||*imm(i,1)!=slots)return no("invokeinterface argument-slot count disagrees with descriptor");
                }
                Intrinsic call;call.name="jvm_invoke "+member.value().owner+"."+member.value().name+member.value().descriptor;
                call.operands=std::move(arguments);call.memory_effect=IntrinsicMemoryEffect::unknown;
                if(signature.value().result)call.result_type=*signature.value().result;
                const auto result_name=call.name;const auto result_type=signature.value().result;
                emit(*fact,std::move(call));if(result_type)stack.push_back(evidence(unknown(result_name,*result_type),method_reference_result(member.value().descriptor)));continue;
            }
            if(op==0xba){
                if(!metadata)return no("invokedynamic requires JVM constant-pool metadata");
                auto index=imm(i);if(!index)return no("invokedynamic constant-pool index unavailable");
                if(!imm(i,1)||!imm(i,2)||*imm(i,1)!=0||*imm(i,2)!=0)
                    return no("invokedynamic reserved operands are malformed");
                auto site=cp_dynamic_call_site(*metadata,*index);if(!site)return site.error();
                auto signature=parse_method_descriptor(site.value().descriptor);if(!signature)return signature.error();
                std::vector<ExpressionPtr> arguments(signature.value().parameters.size());
                for(std::size_t n=signature.value().parameters.size();n>0;--n){
                    auto value=pop(signature.value().parameters[n-1]);if(!value)return value.error();
                    arguments[n-1]=value.value();
                }
                Intrinsic call;
                call.name="jvm_invokedynamic "+site.value().name+site.value().descriptor+
                          " bootstrap#"+std::to_string(site.value().bootstrap_index)+
                          " cp#"+std::to_string(*index);
                call.operands=std::move(arguments);call.memory_effect=IntrinsicMemoryEffect::unknown;
                if(signature.value().result)call.result_type=*signature.value().result;
                const auto result_name=call.name;const auto result_type=signature.value().result;
                emit(*fact,std::move(call));
                if(result_type)stack.push_back(evidence(unknown(result_name,*result_type),method_reference_result(site.value().descriptor)));
                continue;
            }
            if(op==0xbb){
                if(!metadata)return no("object allocation requires JVM constant-pool metadata");
                auto index=imm(i);if(!index)return no("class constant-pool index unavailable");
                auto name=cp_class_name(*metadata,*index);if(!name)return name.error();
                Intrinsic allocation;allocation.name="jvm_new "+name.value();allocation.memory_effect=IntrinsicMemoryEffect::unknown;allocation.result_type=ref32();
                Reference allocated;
                if (code) {
                    allocated = reference_class(name.value());
                    if (allocated && !name.value().starts_with("[")) {
                        allocated->kind = JvmVerificationKind::uninitialized;
                        allocated->allocation_offset = static_cast<std::uint32_t>(i.address.offset - code->begin.offset);
                    } else allocated.reset();
                }
                const auto result_name=allocation.name;emit(*fact,std::move(allocation));stack.push_back(evidence(unknown(result_name,ref32()),std::move(allocated)));continue;
            }
            if(op==0xaa||op==0xab){
                if(ix+1!=src.instructions.size()||!i.jvm_switch||i.flow!=FlowKind::switch_dispatch)
                    return no("switch metadata is unavailable or switch is not block-terminating");
                auto selector=pop(int32());if(!selector)return selector.error();
                LiftedBlock::SwitchDispatch dispatch;dispatch.selector=selector.value();
                dispatch.default_target=i.jvm_switch->default_target;
                for(const auto &item:i.jvm_switch->cases)
                    dispatch.cases.push_back({static_cast<std::uint64_t>(static_cast<std::int64_t>(item.value)),item.target});
                std::vector<Address> expected;expected.reserve(dispatch.cases.size()+1);
                for(const auto &item:dispatch.cases)expected.push_back(item.target);
                expected.push_back(*dispatch.default_target);
                for(const auto target:expected)
                    if(std::none_of(src.successors.begin(),src.successors.end(),[&](const auto &edge){return edge.kind != BlockEdgeKind::exception && edge.target==target;}))
                        return no("switch CFG is missing a decoded case/default edge");
                dst.switch_dispatch=std::move(dispatch);continue;
            }
            if(op==0xa8||op==0xa9||op==0xc9)return no("legacy jsr/ret subroutine flow");
            return no("opcode/effect not modeled: "+i.mnemonic_override);
        }
        if (!valid_stack(stack)) return no("operand stack exceeds max_stack or the 256 logical-slot IR limit");
        if (!stack.empty() && successors[block_index].empty())
            return no("nonempty operand stack has an exit or unresolved successor");
        if (references) {
            references->stack.clear();
            for (const auto &value : stack) references->stack.push_back(identity(value));
        }
        return Transfer{std::move(dst), std::move(stack), std::move(exceptional_references)};
    };
    using Shape = std::vector<ValueType>;
    std::vector<std::optional<Shape>> entries(count), exits(count);
    std::deque<std::size_t> work;
    entries[*entry] = Shape{};
    work.push_back(*entry);
    for (std::size_t i = 0; i < count; ++i) if (handler_entries[i]) {
        entries[i] = Shape{ref32()};
        work.push_back(i);
    }
    // Strict equality is a finite lattice: an entry moves from unresolved to
    // one exact shape. Every later predecessor, including a backedge, must
    // agree. No widening, guessed casts, or expression-identity comparison.
    while (!work.empty()) {
        const auto bi = work.front(); work.pop_front();
        std::vector<ExpressionPtr> input;
        for (const auto type : *entries[bi]) input.push_back(unknown("stack_shape", type));
        auto lifted = transfer(bi, std::move(input), true);
        if (!lifted) return lifted.error();
        Shape shape;
        for (const auto &value : lifted.value().stack) shape.push_back(value->type);
        exits[bi] = shape;
        for (const auto target : successors[bi]) {
            if (entries[target]) {
                if (*entries[target] != shape) return no("incompatible operand-stack heights or verifier value categories at a join/backedge");
            } else {
                entries[target] = shape;
                work.push_back(target);
            }
        }
    }
    for (std::size_t bi = 0; bi < count; ++bi) {
        if (!entries[bi] || !exits[bi]) return no("operand-stack shape is unresolved in an unreachable component");
    }
    // Reference evidence uses a separate, finite meet: disagreements erase an
    // identity rather than widen it to Object or confuse distinct `new` sites.
    // The ordinary shape pass above remains authoritative for primitives.
    std::map<std::uint32_t, const Instruction *> bytecode_instructions;
    if (code) for (const auto *source : sources) for (const auto &fact : source->instructions) {
        const auto offset = static_cast<std::uint32_t>(fact->instruction.address.offset - code->begin.offset);
        const auto [found, inserted] = bytecode_instructions.emplace(offset, &fact->instruction);
        if (!inserted) found->second = nullptr;
    }
    const auto verifier_reference = [&](const JvmVerificationType &type) -> Reference {
        if (!metadata || !method || !code) return {};
        switch (type.kind) {
        case JvmVerificationKind::null_value:
            return ReferenceIdentity{type.kind, {}, 0, metadata->defining_loader};
        case JvmVerificationKind::uninitialized_this: {
            auto value = reference_class(metadata->class_name);
            if (value) value->kind = type.kind;
            if (value) value->defining_loader = metadata->defining_loader;
            return value;
        }
        case JvmVerificationKind::object: {
            Reference value;
            if (type.class_index) {
                const auto name = cp_class_name(*metadata, type.class_index);
                if (!name) return {};
                value = reference_class(name.value());
            }
            if (type.descriptor_length) {
                if (type.descriptor_offset > method->descriptor.size() ||
                    type.descriptor_length > method->descriptor.size() - type.descriptor_offset) return {};
                auto descriptor = reference_descriptor(std::string_view(method->descriptor).substr(
                    type.descriptor_offset, type.descriptor_length));
                if (!descriptor || (value && value != descriptor)) return {};
                value = std::move(descriptor);
            }
            if (value) value->defining_loader = metadata->defining_loader;
            return value;
        }
        case JvmVerificationKind::uninitialized: {
            const auto found = bytecode_instructions.find(type.uninitialized_offset);
            if (found == bytecode_instructions.end() || !found->second) return {};
            const auto &instruction = *found->second;
            if (instruction.bytes.empty() || std::to_integer<std::uint8_t>(instruction.bytes[0]) != 0xbb) return {};
            const auto index = imm(instruction);
            if (!index) return {};
            const auto name = cp_class_name(*metadata, *index);
            if (!name || name.value().starts_with("[")) return {};
            auto value = reference_class(name.value());
            if (value) { value->kind = type.kind; value->allocation_offset = type.uninitialized_offset; value->defining_loader = metadata->defining_loader; }
            return value;
        }
        default: return {};
        }
    };
    struct HandlerCatchEvidence {
        bool seen = false;
        bool consistent = true;
        Reference type;
    };
    const auto common_catch_type = [&](const Reference &left, const Reference &right) -> Reference {
        if (!left || !right || left->kind != JvmVerificationKind::object ||
            right->kind != JvmVerificationKind::object) return {};
        if (left == right) return left;
        const auto class_name = [](const ReferenceIdentity &reference) -> std::optional<std::string> {
            if (reference.descriptor.size() < 3 || reference.descriptor.front() != 'L' ||
                reference.descriptor.back() != ';') return {};
            return reference.descriptor.substr(1, reference.descriptor.size() - 2);
        };
        const auto left_name = class_name(*left);
        const auto right_name = class_name(*right);
        if (!left_name || !right_name) return {};
        // Every catch clause (including catch-all) receives a Throwable.
        // For named catches this relies on the classfile's catch-type contract.
        if (!hierarchy) return {};
        return hierarchy_join(*hierarchy, hierarchy_work, *left, *right);
    };
    std::map<std::pair<std::uint32_t, std::uint64_t>, HandlerCatchEvidence> handler_catch_evidence;
    if (code && metadata) for (const auto &handler : code->exception_table) {
        const auto target_address = Address{code->begin.space, code->begin.offset + handler.handler_pc};
        if (!address_positions.contains({target_address.space.value, target_address.offset})) continue;
        Reference caught;
        if (!handler.catch_type) {
            caught = reference_class("java/lang/Throwable");
        } else {
            auto name = cp_class_name(*metadata, handler.catch_type);
            if (!name || name.value().empty() || name.value().starts_with("["))
                return no("exception handler has an invalid catch class");
            caught = reference_class(name.value());
        }
        if (caught) caught->defining_loader = metadata->defining_loader;
        auto &evidence = handler_catch_evidence[{target_address.space.value, target_address.offset}];
        if (!evidence.seen) {
            evidence.seen = true;
            evidence.type = std::move(caught);
        } else if (evidence.consistent && evidence.type != caught) {
            const auto joined = common_catch_type(evidence.type, caught);
            if (joined) evidence.type = joined;
            else {
                evidence.consistent = false;
                evidence.type.reset();
            }
        }
    }
    const auto verifier_value_type = [](JvmVerificationKind kind) -> std::optional<ValueType> {
        switch (kind) {
        case JvmVerificationKind::integer: return int32();
        case JvmVerificationKind::float_value: return fp32();
        case JvmVerificationKind::double_value: return fp64();
        case JvmVerificationKind::long_value: return int64();
        case JvmVerificationKind::null_value: case JvmVerificationKind::uninitialized_this:
        case JvmVerificationKind::object: case JvmVerificationKind::uninitialized: return ref32();
        default: return {};
        }
    };
    std::vector<const JvmStackMapFrame *> frames(count, nullptr);
    if (code && code->stack_map_table) {
        std::optional<std::uint32_t> previous;
        for (const auto &frame : code->stack_map_table->frames) {
            if (frame.bytecode_offset >= code->code_size || (previous && frame.bytecode_offset <= *previous))
                return no("StackMapTable has invalid or duplicate frame offsets");
            previous = frame.bytecode_offset;
            const auto position = address_positions.find({code->begin.space.value, code->begin.offset + frame.bytecode_offset});
            if (position != address_positions.end()) frames[position->second] = &frame;
        }
    }
    std::vector<std::optional<ReferenceState>> reference_entries(count), reference_exits(count);
    ReferenceState initial;
    if (code && code->stack_map_table) {
        std::size_t slot = 0;
        for (const auto &type : code->stack_map_table->initial_locals) {
            if (slot < initial.locals.size()) initial.locals[slot] = verifier_reference(type);
            slot += type.kind == JvmVerificationKind::long_value || type.kind == JvmVerificationKind::double_value ? 2u : 1u;
        }
        if (slot != code->stack_map_table->initial_local_slots || slot > code->max_locals)
            return no("StackMapTable implicit locals have inconsistent slot counts");
    }
    reference_entries[*entry] = initial;
    work.push_back(*entry);
    std::vector<Reference> handler_stack_references(count);
    for (std::size_t bi = 0; bi < count; ++bi) if (handler_entries[bi]) {
        // The handler stack value has the catch type only when every ordered
        // table clause reaching this target agrees exactly. A mixed-type
        // handler needs hierarchy-aware common-supertype computation.
        const auto evidence = handler_catch_evidence.find({sources[bi]->begin.space.value,
                                                           sources[bi]->begin.offset});
        if (evidence != handler_catch_evidence.end() && evidence->second.consistent)
            handler_stack_references[bi] = evidence->second.type;
    }
    const auto merge_reference_entry = [&](std::size_t target, const ReferenceState &incoming) -> Result<bool> {
        if (!reference_entries[target]) {
            reference_entries[target] = incoming;
            work.push_back(target);
            return true;
        }
        auto merged = *reference_entries[target];
        if (merged.stack.size() != incoming.stack.size())
            return no("reference evidence disagrees with stack shape");
        const auto join = [&](Reference &a, const Reference &b) {
            if (a == b) return;
            if (hierarchy && a && b && a->kind == JvmVerificationKind::object && b->kind == JvmVerificationKind::object) {
                auto widened = hierarchy_join(*hierarchy, hierarchy_work, *a, *b);
                if (widened) { a = std::move(widened); return; }
            }
            a.reset();
        };
        for (std::size_t slot = 0; slot < merged.locals.size(); ++slot) join(merged.locals[slot], incoming.locals[slot]);
        for (std::size_t slot = 0; slot < merged.stack.size(); ++slot) join(merged.stack[slot], incoming.stack[slot]);
        if (merged == *reference_entries[target]) return false;
        reference_entries[target] = std::move(merged);
        work.push_back(target);
        return true;
    };
    while (true) {
    while (!work.empty()) {
        const auto bi = work.front(); work.pop_front();
        auto state = *reference_entries[bi];
        if (const auto *frame = frames[bi]) {
            // A frame is a constraint, never a source of newly invented
            // evidence. Top, dropped locals and assignability widening erase
            // facts, so a later aload cannot resurrect a discarded identity.
            for (std::size_t slot = 0; slot < state.stack.size(); ++slot) {
                if (slot >= frame->stack.size() ||
                    (!hierarchy || !state.stack[slot] || !verifier_reference(frame->stack[slot]) ||
                     !hierarchy_assignable(*hierarchy, hierarchy_work, *state.stack[slot], *verifier_reference(frame->stack[slot])))) state.stack[slot].reset();
            }
            std::array<Reference, 256> constrained{};
            std::size_t slot = 0;
            for (const auto &local : frame->locals) {
                const auto expected = verifier_reference(local);
                if (slot < constrained.size() && expected && state.locals[slot] && hierarchy &&
                    hierarchy_assignable(*hierarchy, hierarchy_work, *state.locals[slot], *expected))
                    constrained[slot] = state.locals[slot];
                slot += local.kind == JvmVerificationKind::long_value || local.kind == JvmVerificationKind::double_value ? 2u : 1u;
            }
            state.locals = std::move(constrained);
        }
        std::vector<ExpressionPtr> input;
        for (const auto type : *entries[bi]) input.push_back(unknown("reference_shape", type));
        const auto lifted = transfer(bi, std::move(input), true, &state);
        if (!lifted) return lifted.error();
        for (const auto &snapshot : lifted.value().exceptional_references) {
            if (!handler_entries[snapshot.target]) return no("exception evidence targets a non-handler block");
            ReferenceState incoming;
            incoming.locals = *snapshot.locals;
            incoming.stack.push_back(handler_stack_references[snapshot.target]);
            auto merged = merge_reference_entry(snapshot.target, incoming);
            if (!merged) return merged.error();
        }
        if (reference_exits[bi] && *reference_exits[bi] == state) continue;
        reference_exits[bi] = state;
        for (const auto target : successors[bi]) {
            auto merged = merge_reference_entry(target, state);
            if (!merged) return merged.error();
        }
    }
    // Shape inference visits even handlers in disconnected components. Keep
    // those analyzable with unknown locals, without diluting reachable sites.
    std::size_t bi = 0;
    while (bi < count && (!handler_entries[bi] || reference_entries[bi])) ++bi;
    if (bi == count) break;
    ReferenceState unknown_handler;
    unknown_handler.stack.push_back(handler_stack_references[bi]);
    reference_entries[bi] = std::move(unknown_handler);
    work.push_back(bi);
    }
    std::vector<bool> needs_frame(count, false);
    for (std::size_t bi = 0; bi < count; ++bi) needs_frame[bi] = predecessors[bi].size() > 1;
    // Detect CFG backedges without relying on bytecode address or block order.
    std::vector<unsigned char> color(count, 0);
    for (std::size_t root = 0; root < count; ++root) if (!color[root]) {
        std::vector<std::pair<std::size_t, std::size_t>> pending{{root, 0}};
        color[root] = 1;
        while (!pending.empty()) {
            auto &[bi, next] = pending.back();
            if (next == successors[bi].size()) { color[bi] = 2; pending.pop_back(); continue; }
            const auto target = successors[bi][next++];
            if (color[target] == 1) needs_frame[target] = true;
            else if (!color[target]) { color[target] = 1; pending.push_back({target, 0}); }
        }
    }
    for (std::size_t bi = 0; bi < count; ++bi) {
        const bool references_on_stack = std::any_of(entries[bi]->begin(), entries[bi]->end(),
            [](const auto type) { return type == ref32(); });
        if (!needs_frame[bi] || !references_on_stack) continue;
        const auto *frame = frames[bi];
        if (!frame || !reference_entries[bi] || frame->stack.size() != entries[bi]->size())
            return no("reference stack join/backedge requires a complete exact StackMapTable frame");
        const auto &state = *reference_entries[bi];
        std::size_t stack_slots = 0;
        for (std::size_t slot = 0; slot < frame->stack.size(); ++slot) {
            const auto type = verifier_value_type(frame->stack[slot].kind);
            if (!type || *type != (*entries[bi])[slot])
                return no("StackMapTable stack category disagrees with inferred stack shape");
            stack_slots += type->bits == 64 ? 2u : 1u;
            if (*type == ref32()) {
                const auto expected = verifier_reference(frame->stack[slot]);
                if (!expected || !state.stack[slot] || !hierarchy ||
                    !hierarchy_assignable(*hierarchy, hierarchy_work, *state.stack[slot], *expected))
                    return no("reference stack join/backedge has unknown or unequal verifier identities");
            }
        }
        if (stack_slots != frame->stack_slots || !code || stack_slots > code->max_stack)
            return no("StackMapTable stack slot count is inconsistent");
        std::size_t local_slot = 0;
        for (const auto &local : frame->locals) {
            const auto type = verifier_value_type(local.kind);
            if (type && *type == ref32()) {
                const auto expected = verifier_reference(local);
                if (local_slot >= state.locals.size() || !expected || !state.locals[local_slot] || !hierarchy ||
                    !hierarchy_assignable(*hierarchy, hierarchy_work, *state.locals[local_slot], *expected))
                    return no("reference stack join/backedge has unproved verifier local identities");
            } else if (local.kind != JvmVerificationKind::top && local_slot < state.locals.size() && state.locals[local_slot])
                return no("StackMapTable primitive local conflicts with reference evidence");
            if (!type && local.kind != JvmVerificationKind::top) return no("StackMapTable local kind is unknown");
            local_slot += type && type->bits == 64 ? 2u : 1u;
        }
        if (local_slot != frame->local_slots || local_slot > code->max_locals)
            return no("StackMapTable local slot count is inconsistent");
    }
    std::vector<std::vector<std::uint32_t>> output_versions(count), phi_versions(count);
    for (std::size_t bi = 0; bi < count; ++bi) {
        for (std::size_t slot = 0; slot < exits[bi]->size(); ++slot) {
            if (versions[slot] == std::numeric_limits<std::uint32_t>::max()) return no("stack SSA version limit exceeded");
            output_versions[bi].push_back(++versions[slot]);
        }
        if (predecessors[bi].size() > 1) for (std::size_t slot = 0; slot < entries[bi]->size(); ++slot) {
            if (versions[slot] == std::numeric_limits<std::uint32_t>::max()) return no("stack SSA version limit exceeded");
            phi_versions[bi].push_back(++versions[slot]);
        }
    }
    LiftedFunction out{function.id, function.entry, {}, {}};
    for (std::size_t bi = 0; bi < count; ++bi) {
        std::vector<ExpressionPtr> input;
        std::vector<LiftedBlock::Phi> phis;
        for (std::size_t slot = 0; slot < entries[bi]->size(); ++slot) {
            const auto type = (*entries[bi])[slot];
            if (handler_entries[bi]) { input.push_back(unknown("caught_exception", type)); continue; }
            if (predecessors[bi].empty()) return no("nonempty entry stack has no predecessor value");
            const RegisterOperand stack_reg{RegisterBank::jvm_stack, static_cast<std::uint8_t>(slot), type.bits, false};
            const auto version = predecessors[bi].size() == 1
                ? output_versions[predecessors[bi].front()][slot] : phi_versions[bi][slot];
            if (predecessors[bi].size() > 1) {
                LiftedBlock::Phi phi{stack_reg, version, {}};
                for (const auto pred : predecessors[bi]) phi.inputs.push_back({sources[pred]->id, output_versions[pred][slot]});
                phis.push_back(std::move(phi));
            }
            input.push_back(std::make_shared<Expression>(Expression{type, RegisterValue{stack_reg, version}}));
        }
        auto lifted = transfer(bi, std::move(input), false);
        if (!lifted) return lifted.error();
        auto &block = lifted.value().block;
        const auto &stack = lifted.value().stack;
        block.phis = std::move(phis);
        if (stack.size() != exits[bi]->size()) return no("shape and emission passes disagree on stack height");
        std::vector<LiftedInstruction> definitions;
        InstructionOrigin origin{block.begin, 0};
        if (!block.instructions.empty()) origin = block.instructions.back().origin;
        else if (!sources[bi]->instructions.empty()) {
            const auto &last = *sources[bi]->instructions.back(); origin = {last.instruction.address, last.id};
        }
        for (std::size_t slot = 0; slot < stack.size(); ++slot) {
            if (stack[slot]->type != (*exits[bi])[slot]) return no("shape and emission passes disagree on stack type");
            const RegisterOperand stack_reg{RegisterBank::jvm_stack, static_cast<std::uint8_t>(slot), stack[slot]->type.bits, false};
            definitions.push_back({origin, Assign{stack_reg, stack[slot], output_versions[bi][slot]}});
        }
        auto insertion = block.instructions.end();
        if (insertion != block.instructions.begin() && std::holds_alternative<Branch>((insertion - 1)->statement)) --insertion;
        block.instructions.insert(insertion, definitions.begin(), definitions.end());
        out.blocks.push_back(std::move(block));
    }
    return out;
}
} // namespace hexlab::decompiler
