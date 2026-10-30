#include "graph_internal.hpp"
#include <array>
namespace hexlab::graph_detail {
std::string hexadecimal(uint64_t value){std::array<char,16> buffer{};auto end=std::to_chars(buffer.data(),buffer.data()+buffer.size(),value,16).ptr;return {buffer.data(),end};}
std::string location_text(Location value){auto [tag,space,offset]=location_key(value);return (tag?"file:":"va"+std::to_string(space)+":")+hexadecimal(offset);}
std::string formatted_location(const GraphLabels& labels,Location value){
    try{return safe_text(labels.location_formatter(value));}
    catch(const std::bad_alloc&){throw;}
    catch(...){throw Failure{{ErrorCode::invalid_argument,"Graph location formatter failed"}};}
}
// Preserve valid UTF-8, expose malformed metadata bytes as printable escapes.
std::string safe_text(std::string_view value,std::size_t budget){
    std::string out;for(size_t i=0;i<value.size();){unsigned char c=static_cast<unsigned char>(value[i]);size_t n=c<128?1:c>=0xc2 && c<=0xdf?2:c>=0xe0 && c<=0xef?3:c>=0xf0 && c<=0xf4?4:0;
        bool valid=n && i+n<=value.size();for(size_t j=1;valid && j<n;++j)valid=(static_cast<unsigned char>(value[i+j])&0xc0)==0x80;
        if(valid && n>=3){auto b=static_cast<unsigned char>(value[i+1]);valid=!(c==0xe0 && b<0xa0) && !(c==0xed && b>=0xa0) && !(c==0xf0 && b<0x90) && !(c==0xf4 && b>=0x90);}
        if(valid){if(out.size()+n>budget)break;out.append(value.substr(i,n));i+=n;}else{if(out.size()+4>budget)break;constexpr char digits[]="0123456789abcdef";out+="\\x";out+=digits[c>>4];out+=digits[c&15];++i;}}
    return out;
}
std::string external_text(const ExternalIdentity& value){
    if (value.wasm_function_index) {
        std::string text="wasm:"+safe_text(value.library)+"!"+(value.name?safe_text(*value.name):"<missing-name>");
        text+=" [function index "+std::to_string(*value.wasm_function_index);
        if(value.host_binding)text+=", host-binding "+safe_text(*value.host_binding);
        return text+"]";
    }
    return safe_text(value.library)+"!"+(value.name?safe_text(*value.name):"#"+std::to_string(value.ordinal.value_or(0)));
}
std::string external_identity_key(const ExternalIdentity& value){Hash h;h.text(value.library);h.number(value.name.has_value());if(value.name)h.text(*value.name);h.number(value.ordinal.has_value());if(value.ordinal)h.number(*value.ordinal);h.number(value.wasm_function_index.has_value());if(value.wasm_function_index)h.number(*value.wasm_function_index);h.number(value.host_binding.has_value());if(value.host_binding)h.text(*value.host_binding);auto d=h.hash.digest();return std::string(reinterpret_cast<const char*>(d.data()),d.size());}
void validate_options(const GraphOptions& o){require(o.node_budget<=1000000 && o.edge_budget<=4000000 && o.preview_lines<=1024 && o.call_depth>=1 && o.call_depth<=4,"Graph budget exceeds supported limits");for(double v:{o.node_width,o.line_height,o.rank_gap,o.node_gap,o.edge_gap})require(std::isfinite(v) && v>0 && v<=1000000,"Graph spacing must be positive and finite");}
void validate_model(const GraphModel& model,std::stop_token stop){
    require(model.nodes.size()<=1000000 && model.edges.size()<=4000000,"Graph model exceeds supported limits");
    require(model.kind>=GraphKind::function_cfg && model.kind<=GraphKind::function_calls,"Unknown graph kind");std::set<GraphNodeId> nodes;std::set<GraphEdgeId> edges;
    for(const auto& n:model.nodes){canceled(stop);require(n.id.value && nodes.insert(n.id).second,"Duplicate or zero graph node identity");require(std::isfinite(n.width) && std::isfinite(n.height) && n.width>0 && n.height>0 && n.width<=1000000000 && n.height<=1000000000,"Invalid graph node dimensions");require(n.label.size()<=262144 && n.comment.size()<=262144 && n.preview_lines<=1024,"Graph presentation exceeds supported limits");require(n.kind>=GraphNodeKind::block && n.kind<=GraphNodeKind::boundary,"Unknown graph node kind");}
    for(const auto& e:model.edges){canceled(stop);require(e.id.value && edges.insert(e.id).second,"Duplicate or zero graph edge identity");require(nodes.contains(e.source) && nodes.contains(e.target),"Graph edge has unknown endpoint");require(e.kind>=GraphEdgeKind::fallthrough && e.kind<=GraphEdgeKind::unresolved,"Unknown graph edge kind");}
}
Sha256Digest fingerprint(const GraphModel& m,std::stop_token stop){
    Hash h;h.text("HexLab graph v1");h.number(static_cast<unsigned>(m.kind));h.number(m.function.has_value());if(m.function)h.number(m.function->value);h.number(m.complete);h.number(m.omitted_nodes);h.number(m.omitted_edges);h.number(m.presentation_revision);
    h.number(m.source_key.has_value());if(m.source_key){auto& k=*m.source_key;h.number(k.input.size);h.bytes(k.input.sha256);h.number(k.byte_revision);h.number(k.decision_revision);h.bytes(k.recipe_fingerprint);h.bytes(k.engine_fingerprint);h.number(k.external_input_fingerprint.has_value());if(k.external_input_fingerprint)h.bytes(*k.external_input_fingerprint);}
    std::vector<const GraphNode*> ns;for(auto& n:m.nodes)ns.push_back(&n);std::sort(ns.begin(),ns.end(),[](auto a,auto b){return a->id<b->id;});h.number(ns.size());for(auto n:ns){canceled(stop);h.number(n->id.value);h.number(static_cast<unsigned>(n->kind));h.text(n->label);h.text(n->comment);h.real(n->width);h.real(n->height);h.number(n->preview_lines);h.number(n->omitted_comment_bytes);h.number(n->selection.has_value());if(n->selection)h.location(*n->selection);h.number(n->external.has_value());if(n->external)h.text(external_identity_key(*n->external));h.number(n->block? n->block->id.value:0);h.number(n->function?n->function->id.value:0);if(n->block){h.number(n->block->instructions.size());for(auto& fact:n->block->instructions){canceled(stop);require(bool(fact) && fact->instruction.length==fact->instruction.encoded_bytes().size(),"Invalid instruction fact in graph");h.number(fact->id);h.location(fact->instruction.address);h.bytes(fact->instruction.encoded_bytes());}}}
    std::vector<const GraphEdge*> es;for(auto& e:m.edges)es.push_back(&e);std::sort(es.begin(),es.end(),[](auto a,auto b){return a->id<b->id;});h.number(es.size());for(auto e:es){canceled(stop);h.number(e->id.value);h.number(e->source.value);h.number(e->target.value);h.number(static_cast<unsigned>(e->kind));h.number(e->reference?e->reference->value:0);h.number(e->selection.has_value());if(e->selection)h.location(*e->selection);h.number(e->target_location.has_value());if(e->target_location)h.location(*e->target_location);h.number(e->boundary);}return h.hash.digest();
}
namespace {
uint64_t identity(std::string_view domain,std::string_view key){Hash h;h.text(domain);h.text(key);auto digest=h.hash.digest();uint64_t id=0;for(size_t i=0;i<8;++i)id=(id<<8)|std::to_integer<unsigned>(digest[i]);return id?id:1;}
struct Builder {
    const GraphOptions& options;const GraphLabels& labels;std::stop_token stop;GraphModel graph;
    std::map<GraphNodeId,GraphNode> nodes;std::map<GraphNodeId,std::string> identities;
    std::map<GraphNodeId,const ExternalIdentity*> external_sources;
    uint64_t edge_count=0;std::vector<GraphNodeId> priority;
    GraphNodeId add(std::string key,GraphNode n){canceled(stop);GraphNodeId id{identity("node",key)};auto [where,inserted]=identities.emplace(id,key);require(inserted || where->second==key,"Graph node hash collision");if(inserted){n.id=id;nodes.emplace(id,std::move(n));priority.push_back(id);}return id;}
    GraphNodeId block(std::shared_ptr<const BasicBlock> b){GraphNode n;n.kind=GraphNodeKind::block;n.selection=b->begin;n.block=b;return add("block:"+hexadecimal(b->id.value),std::move(n));}
    GraphNodeId function(std::shared_ptr<const FunctionRecord> f){GraphNode n;n.kind=GraphNodeKind::function;n.selection=f->entry;n.function=f;return add("function:"+hexadecimal(f->id.value),std::move(n));}
    GraphNodeId boundary(Location address){GraphNode n;n.kind=GraphNodeKind::boundary;n.selection=address;return add("boundary:"+location_text(address),std::move(n));}
    GraphNodeId target(const Reference& ref,const std::map<LocationKey,std::shared_ptr<const FunctionRecord>>& entries){
        if(auto loc=std::get_if<Location>(&ref.target)){auto found=entries.find(location_key(*loc));return found==entries.end()?boundary(*loc):function(found->second);}
        GraphNode n;if(auto external=std::get_if<ExternalIdentity>(&ref.target)){n.kind=GraphNodeKind::external;auto id=add("external:"+external_identity_key(*external),std::move(n));external_sources.emplace(id,external);return id;}
        n.kind=GraphNodeKind::unresolved;n.selection=ref.source;return add("unknown:"+hexadecimal(ref.id.value),std::move(n));
    }
    void edge(GraphNodeId source,GraphNodeId target,GraphEdgeKind kind,Location site,std::optional<Location> location,std::optional<ReferenceId> reference={},uint64_t multiplicity=1){
        require(edge_count<=UINT64_MAX-multiplicity,"Graph edge count overflow");edge_count+=multiplicity;if(graph.edges.size()>=options.edge_budget)return;
        GraphEdge edge;edge.source=source;edge.target=target;edge.kind=kind;edge.selection=site;edge.target_location=location;edge.reference=reference;
        Hash h;h.text("edge");h.number(source.value);h.number(target.value);h.number(static_cast<unsigned>(kind));h.location(site);h.number(reference?reference->value:0);auto digest=h.hash.digest();uint64_t id=0;for(size_t i=0;i<8;++i)id=(id<<8)|std::to_integer<unsigned>(digest[i]);edge.id={id?id:1};graph.edges.push_back(edge);
    }
    std::shared_ptr<const GraphModel> finish(){
        const size_t keep=nodes.size()<=options.node_budget?nodes.size():options.node_budget>=2?options.node_budget-1:options.node_budget;
        std::set<GraphNodeId> retained;for(size_t i=0;i<keep;++i)retained.insert(priority[i]);graph.omitted_nodes=nodes.size()-keep;
        GraphNodeId stub{};if(graph.omitted_nodes && options.node_budget>=2){GraphNode n;n.kind=GraphNodeKind::boundary;n.label=std::to_string(graph.omitted_nodes)+" omitted nodes";stub={identity("budget",std::to_string(static_cast<unsigned>(graph.kind))+":"+(graph.function?hexadecimal(graph.function->value):"image"))};require(!nodes.contains(stub),"Graph boundary identity collision");n.id=stub;graph.nodes.push_back(std::move(n));}
        std::map<LocationKey,const GraphLabelOverride*> overrides;for(const auto& value:labels.overrides){canceled(stop);require(value.name.size()<=65536 && value.comment.size()<=1048576,"Graph label exceeds supported limits");require(overrides.emplace(location_key(value.location),&value).second,"Duplicate graph label location");}
        for(auto id:retained){canceled(stop);auto n=std::move(nodes.at(id));n.width=options.node_width;n.preview_lines=options.preview_lines;
            if(auto external=external_sources.find(id);external!=external_sources.end())n.external=*external->second;
            if(n.external)n.label=external_text(*n.external);else if(n.kind==GraphNodeKind::unresolved)n.label="Unresolved transfer at "+location_text(*n.selection);else if(n.selection)n.label=labels.location_formatter && (n.kind==GraphNodeKind::block || n.kind==GraphNodeKind::function)?formatted_location(labels,*n.selection):location_text(*n.selection);
            if(n.selection){auto label=overrides.find(location_key(*n.selection));if(label!=overrides.end()){if(!label->second->name.empty())n.label=safe_text(label->second->name);n.comment=safe_text(label->second->comment);n.omitted_comment_bytes=label->second->comment.size()>65536?label->second->comment.size()-65536:0;}}
            auto lines=n.block?std::min(options.preview_lines,n.block->instructions.size()):0;n.height=options.line_height*(3+static_cast<double>(lines));graph.nodes.push_back(std::move(n));}
        std::erase_if(graph.edges,[&](auto& e){bool a=retained.contains(e.source),b=retained.contains(e.target);if(a && b)return false;if(!stub.value)return true;e.boundary=true;if(!a)e.source=stub;if(!b)e.target=stub;return false;});
        graph.omitted_edges=edge_count-graph.edges.size();graph.complete=graph.complete && !graph.omitted_nodes && !graph.omitted_edges;
        std::sort(graph.nodes.begin(),graph.nodes.end(),[](auto& a,auto& b){return a.id<b.id;});std::sort(graph.edges.begin(),graph.edges.end(),[](auto& a,auto& b){return a.id<b.id;});validate_model(graph,stop);graph.key=fingerprint(graph,stop);return std::make_shared<const GraphModel>(std::move(graph));
    }
};
}
}
namespace hexlab {
Result<std::shared_ptr<const GraphModel>> build_graph(const FunctionSnapshot& functions,const ReferenceIndex& references,GraphKind kind,std::optional<FunctionId> function,const GraphOptions& options,const GraphLabels& labels,std::stop_token stop){return graph_detail::guarded([&]()->Result<std::shared_ptr<const GraphModel>>{
    using namespace graph_detail;validate_options(options);canceled(stop);require(functions.key==references.key(),"Graph sources have different analysis keys");require(labels.overrides.size()<=100000,"Too many graph label overrides");Builder b{options,labels,stop};b.graph.kind=kind;b.graph.function=function;b.graph.source_key=functions.key;b.graph.presentation_revision=labels.revision;b.graph.complete=functions.complete && references.complete();
    std::map<BlockId,std::shared_ptr<const BasicBlock>> blocks;std::map<FunctionId,std::shared_ptr<const FunctionRecord>> fs;std::map<LocationKey,std::shared_ptr<const FunctionRecord>> entries;
    for(auto& block:functions.blocks){canceled(stop);require(bool(block) && blocks.emplace(block->id,block).second,"Invalid or duplicate block");}for(auto& fn:functions.functions){canceled(stop);require(bool(fn) && fs.emplace(fn->id,fn).second && entries.emplace(location_key(fn->entry),fn).second,"Invalid or duplicate function");}
    if(kind==GraphKind::function_cfg){require(function.has_value() && fs.contains(*function),"CFG requires an existing function");auto fn=fs.at(*function);std::map<BlockId,GraphNodeId> owned;auto ids=fn->blocks;std::sort(ids.begin(),ids.end(),[&](auto a,auto z){require(blocks.contains(a) && blocks.contains(z),"Function has unknown block");bool ae=blocks.at(a)->begin==fn->entry,ze=blocks.at(z)->begin==fn->entry;return ae!=ze?ae:location_key(blocks.at(a)->begin)<location_key(blocks.at(z)->begin);});for(auto id:ids){require(blocks.contains(id),"Function has unknown block");owned.emplace(id,b.block(blocks.at(id)));}
        for(auto id:ids){canceled(stop);for(auto& successor:blocks.at(id)->successors){GraphNodeId target;std::optional<ReferenceId> ref;std::optional<Location> location;if(successor.target){location=*successor.target;target=successor.block && owned.contains(*successor.block)?owned.at(*successor.block):b.boundary(*successor.target);}else{const Reference* control=nullptr;for(auto& r:references.outgoing_view(successor.source))if(r.kind==ReferenceKind::jump || r.kind==ReferenceKind::conditional_jump || r.kind==ReferenceKind::imported_jump){control=&r;break;}if(control){target=b.target(*control,entries);ref=control->id;}else{GraphNode n;n.kind=GraphNodeKind::unresolved;n.selection=successor.source;target=b.add("unknown-site:"+location_text(successor.source),std::move(n));}}
            GraphEdgeKind edge_kind=GraphEdgeKind::unresolved;switch(successor.kind){case BlockEdgeKind::fallthrough:edge_kind=GraphEdgeKind::fallthrough;break;case BlockEdgeKind::conditional_true:edge_kind=GraphEdgeKind::conditional_true;break;case BlockEdgeKind::conditional_false:edge_kind=GraphEdgeKind::conditional_false;break;case BlockEdgeKind::jump:edge_kind=GraphEdgeKind::jump;break;case BlockEdgeKind::call_continuation:edge_kind=GraphEdgeKind::call_continuation;break;case BlockEdgeKind::delay_slot:edge_kind=GraphEdgeKind::delay_slot;break;default:break;}b.edge(owned.at(id),target,edge_kind,successor.source,location,ref);}}
    }else{
        const bool scoped=kind==GraphKind::function_calls;
        require(kind==GraphKind::image_calls || scoped,"Unknown graph kind");
        require(scoped ? function.has_value() && fs.contains(*function) : !function,
                scoped ? "Function call graph requires an existing function" : "Image call graph has no selected function");
        std::map<uint64_t,const std::vector<FunctionId>*> owners;
        std::map<LocationKey,const std::vector<FunctionId>*> sites;
        for(auto& [id,block]:blocks)for(auto& fact:block->instructions){canceled(stop);require(bool(fact),"Null instruction fact");owners.emplace(fact->id,&block->owners);sites.emplace(location_key(fact->instruction.address),&block->owners);}
        const auto source_owners=[&](const Reference& ref)->const std::vector<FunctionId>*{
            auto it=owners.find(ref.provenance.instruction_id);if(it!=owners.end())return it->second;
            auto site=sites.find(location_key(ref.source));return site==sites.end()?nullptr:site->second;
        };
        std::set<FunctionId> included;
        if(scoped){
            const auto selected=*function;included.insert(selected);
            std::set<FunctionId> frontier{selected};
            for(std::size_t depth=0;depth<options.call_depth && !frontier.empty();++depth){
                std::set<FunctionId> next;
                for(const auto& ref:references.all()){
                    canceled(stop);const bool call=ref.kind==ReferenceKind::call || ref.kind==ReferenceKind::imported_call || ref.kind==ReferenceKind::user_code;
                    const bool jump=ref.kind==ReferenceKind::jump || ref.kind==ReferenceKind::imported_jump;if(!call&&!jump)continue;
                    auto loc=std::get_if<Location>(&ref.target);if(jump && loc && !entries.contains(location_key(*loc)))continue;
                    const auto* list=source_owners(ref);
                    bool source_in_frontier=false;
                    if(list)for(auto owner:*list)if(frontier.contains(owner)){source_in_frontier=true;break;}
                    auto target=loc?entries.find(location_key(*loc)):entries.end();
                    const bool target_in_frontier=target!=entries.end()&&frontier.contains(target->second->id);
                    if(source_in_frontier && target!=entries.end() && !included.contains(target->second->id))next.insert(target->second->id);
                    if(target_in_frontier && list)for(auto owner:*list)if(fs.contains(owner)&&!included.contains(owner))next.insert(owner);
                }
                included.insert(next.begin(),next.end());frontier=std::move(next);
            }
            b.graph.function=selected;
            b.function(fs.at(selected));
            for(auto id:included)if(id!=selected)b.function(fs.at(id));
        }else for(auto& [id,fn]:fs)b.function(fn);
        std::map<const std::vector<FunctionId>*,std::vector<FunctionId>> owner_sets;
        for(auto& ref:references.all()){
            canceled(stop);bool call=ref.kind==ReferenceKind::call || ref.kind==ReferenceKind::imported_call || ref.kind==ReferenceKind::user_code;bool jump=ref.kind==ReferenceKind::jump || ref.kind==ReferenceKind::imported_jump;if(!call && !jump)continue;
            auto loc=std::get_if<Location>(&ref.target);if(jump && loc && !entries.contains(location_key(*loc)))continue;
            auto list=source_owners(ref);auto edge_kind=call?GraphEdgeKind::call:GraphEdgeKind::tail_candidate;std::optional<Location> numeric;if(loc)numeric=*loc;
            if(scoped){
                const auto selected=*function;bool outgoing=false;
                if(list)for(auto owner:*list)if(included.contains(owner)){outgoing=true;break;}
                auto target_entry=loc?entries.find(location_key(*loc)):entries.end();const bool incoming=target_entry!=entries.end()&&target_entry->second->id==selected;
                const bool target_included=target_entry!=entries.end()&&included.contains(target_entry->second->id);
                if(!outgoing&&!incoming)continue;
                if(target_entry!=entries.end()&&!target_included)continue;
                auto target=b.target(ref,entries);
                if(outgoing && list) {
                    for(auto id:*list)if(included.contains(id)&&fs.contains(id))b.edge(b.function(fs.at(id)),target,edge_kind,ref.source,numeric,ref.id);
                } else if(incoming) {
                    if(list && !list->empty())for(auto id:*list){canceled(stop);if(included.contains(id)&&fs.contains(id))b.edge(b.function(fs.at(id)),b.function(fs.at(selected)),edge_kind,ref.source,numeric,ref.id);}
                    else b.edge(b.boundary(ref.source),b.function(fs.at(selected)),edge_kind,ref.source,numeric,ref.id);
                }
                continue;
            }
            auto target=b.target(ref,entries);
            if(!list || list->empty())b.edge(b.boundary(ref.source),target,edge_kind,ref.source,numeric,ref.id);else{
                std::optional<FunctionId> self;if(jump && loc){auto found=entries.find(location_key(*loc));if(found!=entries.end())self=found->second->id;}
                size_t eligible=list->size();if(self){auto [set,inserted]=owner_sets.try_emplace(list);if(inserted){set->second=*list;std::sort(set->second.begin(),set->second.end());require(std::adjacent_find(set->second.begin(),set->second.end())==set->second.end(),"Duplicate block owner");}if(std::binary_search(set->second.begin(),set->second.end(),*self))--eligible;}
                size_t remaining=std::min(options.edge_budget-b.graph.edges.size(),eligible),emitted=0;
                if(remaining)for(auto id:*list){canceled(stop);if(self && id==*self)continue;auto owner=fs.find(id);require(owner!=fs.end(),"Block has unknown function owner");b.edge(b.function(owner->second),target,edge_kind,ref.source,numeric,ref.id);if(++emitted==remaining)break;}
                require(b.edge_count<=UINT64_MAX-(eligible-emitted),"Graph edge count overflow");b.edge_count+=eligible-emitted;}}
    }return b.finish();});}
}
