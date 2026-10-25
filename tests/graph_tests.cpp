#include "hexlab/analysis/graph.hpp"
#include "support/checks.hpp"
#include "support/fixture_files.hpp"
#include "support/analysis_fixture.hpp"
#include "support/test_entrypoint.hpp"
#include <algorithm>
#include <cmath>
#include <fstream>
#include <set>
using namespace hexlab;
using namespace hexlab_test;
struct GraphFixture {
    std::shared_ptr<const FunctionSnapshot> functions;std::shared_ptr<const ReferenceIndex> references;
    GraphFixture(std::vector<std::byte> data,ImageMetadata metadata={}){
        functions=recover_functions(*memory_image(std::move(data)),metadata,{},{},{}).value();references=derive_references(*functions,metadata,{},{}).value();
    }
    std::shared_ptr<const GraphModel> cfg(GraphOptions options={},GraphLabels labels={})const{return build_graph(*functions,*references,GraphKind::function_cfg,functions->functions[0]->id,options,labels,{}).value();}
};
GraphNode node(uint64_t id){GraphNode value;value.id={id};value.kind=GraphNodeKind::block;value.label="node "+std::to_string(id);value.width=120;value.height=60;return value;}
GraphEdge edge(uint64_t id,uint64_t from,uint64_t to){GraphEdge value;value.id={id};value.source={from};value.target={to};value.kind=GraphEdgeKind::jump;return value;}
void layout_tests(){
    GraphFixture loop(bytes({0xeb,0xfe}));auto graph=loop.cfg();auto first=layout_graph(*graph,{},{}).value(),again=layout_graph(*graph,{},{}).value();
    check(graph->nodes.size()==1 && graph->edges.size()==1 && first->routes[0].points.size()>=4,"self-loop has an explicit routed edge");
    check(first->positions==again->positions && first->routes==again->routes && first->key==again->key,"repeated original layout is deterministic");
    GraphModel cycle;cycle.nodes={node(1),node(2),node(3)};cycle.edges={edge(1,1,2),edge(2,2,1),edge(3,2,3)};
    auto condensed=layout_graph(cycle,{},{}).value();check(condensed->components.size()==2 && condensed->positions.size()==3 && condensed->routes.size()==3,"SCC condensation retains cyclic and acyclic components");
    for(const auto& position:condensed->positions)check(std::isfinite(position.bounds.x) && std::isfinite(position.bounds.y) && position.bounds.width>0 && position.bounds.height>0,"layout produces finite positive node rectangles");
    for(const auto& route:condensed->routes)for(const auto& point:route.points)check(std::isfinite(point.x) && std::isfinite(point.y),"edge ports and routes are finite");
    std::reverse(cycle.nodes.begin(),cycle.nodes.end());std::reverse(cycle.edges.begin(),cycle.edges.end());auto reordered=layout_graph(cycle,{},{}).value();check(reordered->positions==condensed->positions && reordered->routes==condensed->routes,"stable ordering is independent of model vector order");
    cycle.edges.push_back(edge(4,3,99));check(!layout_graph(cycle,{},{}),"unknown graph endpoint rejected");cycle.edges.pop_back();cycle.nodes[0].width=NAN;check(!layout_graph(cycle,{},{}),"nonfinite node dimensions rejected");
    std::stop_source stop;stop.request_stop();check(!layout_graph(*graph,{},stop.get_token()),"layout cancellation returns without publishing positions");
}
void topology_tests(){
    GraphFixture parallel(bytes({0x74,0,0xc3}));auto graph=parallel.cfg();check(graph->nodes.size()==2 && graph->edges.size()==2 && graph->edges[0].id!=graph->edges[1].id && graph->edges[0].target==graph->edges[1].target,"parallel true/false edges retain separate identities");
    GraphOptions budget;budget.node_budget=2;GraphFixture diamond(bytes({0x74,3,0x90,0xeb,1,0x90,0xc3}));graph=diamond.cfg(budget);
    check(graph->nodes.size()<=2 && !graph->complete && graph->omitted_nodes>0 && std::any_of(graph->nodes.begin(),graph->nodes.end(),[](const auto& value){return value.kind==GraphNodeKind::boundary;}),"node budget preserves an explicit boundary stub and omitted counts");
    budget={};budget.edge_budget=1;graph=diamond.cfg(budget);check(graph->edges.size()==1 && graph->omitted_edges>0 && !graph->complete,"edge budget does not silently claim a complete graph");
    auto data=std::vector<std::byte>(17);data[0]=std::byte{0xeb};data[1]=std::byte{14};data[8]=std::byte{0xeb};data[9]=std::byte{6};data[16]=std::byte{0xc3};ImageMetadata metadata;metadata.exports.push_back({1,"second",Address{{0},0x1008},{}});GraphFixture shared(data,metadata);
    auto a=build_graph(*shared.functions,*shared.references,GraphKind::function_cfg,shared.functions->functions[0]->id,{}, {},{}).value();auto b=build_graph(*shared.functions,*shared.references,GraphKind::function_cfg,shared.functions->functions[1]->id,{}, {},{}).value();
    bool same_tail=false;for(const auto& left:a->nodes)for(const auto& right:b->nodes)if(left.block && right.block && left.block->begin==Address{{0},0x1010} && left.id==right.id)same_tail=true;check(same_tail,"shared tail keeps one block identity across function graphs");
    auto imported=bytes({0xff,0x15,0x3a,0,0,0,0xc3});imported.resize(128);metadata={};metadata.imports.push_back({"fixture.dll","Target",{},{{0},0x1040},{{0},0x1040}});GraphFixture imports(imported,metadata);
    graph=build_graph(*imports.functions,*imports.references,GraphKind::image_calls,{}, {},{},{}).value();check(std::any_of(graph->nodes.begin(),graph->nodes.end(),[](const auto& value){return value.kind==GraphNodeKind::external && value.external && !value.selection;}),"call graph external stub never fabricates a runtime address");
    GraphFixture unresolved(bytes({0xff,0xd0,0xc3}));graph=build_graph(*unresolved.functions,*unresolved.references,GraphKind::image_calls,{}, {},{},{}).value();check(std::any_of(graph->nodes.begin(),graph->nodes.end(),[](const auto& value){return value.kind==GraphNodeKind::unresolved;}),"indirect call has an unresolved stub");
}
void function_call_neighborhood_tests(){
    auto code=bytes({0xe8,3,0,0,0,0xc3,0x90,0x90,0xc3,
                     0x90,0x90,0x90,0x90,0x90,0x90,0x90,
                     0xe8,0xeb,0xff,0xff,0xff,0xc3,
                     0xc3});
    ImageMetadata metadata;
    metadata.exports.push_back({1,"caller",Address{{0},0x1010},{}});
    metadata.exports.push_back({2,"unrelated",Address{{0},0x1016},{}});
    GraphFixture fixture(std::move(code),metadata);
    auto selected=std::find_if(fixture.functions->functions.begin(),fixture.functions->functions.end(),[](const auto& fn){return fn->entry==Address{{0},0x1000};});
    check(selected!=fixture.functions->functions.end(),"selected root function is recovered");
    auto graph=build_graph(*fixture.functions,*fixture.references,GraphKind::function_calls,(*selected)->id,{}, {},{}).value();
    std::set<std::uint64_t> entries;
    for(const auto& node:graph->nodes)if(node.function)entries.insert(node.function->entry.offset);
    check(graph->function==(*selected)->id && entries==std::set<std::uint64_t>{0x1000,0x1008,0x1010} && graph->edges.size()==2,
          "function call neighborhood contains its direct callers and callees but excludes unrelated image functions");
    check(std::all_of(graph->edges.begin(),graph->edges.end(),[&](const auto& edge){
              return std::any_of(graph->nodes.begin(),graph->nodes.end(),[&](const auto& node){return node.id==edge.source && node.function && node.function->id==(*selected)->id;}) ||
                     std::any_of(graph->nodes.begin(),graph->nodes.end(),[&](const auto& node){return node.id==edge.target && node.function && node.function->id==(*selected)->id;});
          }),"every neighborhood edge is incident to the selected function");
    check(!build_graph(*fixture.functions,*fixture.references,GraphKind::function_calls,{}, {},{},{}),
          "function call neighborhood requires a selected function");
}
void export_tests(const std::filesystem::path& directory){
    GraphFixture fixture(bytes({0x74,3,0x90,0xeb,1,0x90,0xc3}));GraphLabels labels;labels.revision=1;labels.overrides.push_back({Address{{0},0x1000},"entry \"quoted\" \\\n\xce\xb1","first line\nsecond line"});auto graph=fixture.cfg({},labels);auto layout=layout_graph(*graph,{},{}).value();
    const auto json=export_graph_json(*graph,*layout,{}).value(),dot=export_graph_dot(*graph,{}).value();
    check(json.find("\\\"quoted\\\"")!=std::string::npos && json.find("\\n")!=std::string::npos && dot.find("\\\"quoted\\\"")!=std::string::npos,"hostile quote slash and newline labels are escaped");
    check(json.find("\xce\xb1")!=std::string::npos,"valid Unicode label text is preserved");
    std::filesystem::create_directories(directory);std::ofstream(directory/L"fixture.json",std::ios::binary)<<json;std::ofstream(directory/L"fixture.dot",std::ios::binary)<<dot;
    auto mismatched=*layout;mismatched.model_key={};check(!export_graph_json(*graph,mismatched,{}),"export rejects layout from another graph key");
}
void boundary_tests(){
    GraphFixture fixture(bytes({0x74,3,0x90,0xeb,1,0x90,0xc3}));
    GraphOptions options;options.node_budget=0;auto empty=fixture.cfg(options);check(empty->nodes.empty() && empty->edges.empty() && !empty->complete && empty->omitted_nodes==4 && empty->omitted_edges==4,"zero-node budget counts every omitted node and edge");
    options.node_budget=1;auto root=fixture.cfg(options);check(root->nodes.size()==1 && root->nodes[0].selection==Location{Address{{0},0x1000}} && root->omitted_nodes==3,"one-node budget retains entry selection");
    options={};options.rank_gap=0;check(!build_graph(*fixture.functions,*fixture.references,GraphKind::function_cfg,fixture.functions->functions[0]->id,options,{},{}),"zero spacing rejected before model publication");
    auto changed=*fixture.functions;changed.key=AnalysisKey{};check(!build_graph(changed,*fixture.references,GraphKind::image_calls,{}, {},{},{}),"unrelated analysis provenance cannot be combined");
    GraphLabels labels;labels.overrides.push_back({Address{{0},0x1000},std::string("bad ")+char(-1),""});auto graph=fixture.cfg({},labels);auto json=export_graph_json(*graph).value();check(json.find(char(-1))==std::string::npos && json.find("bad \\\\xff")!=std::string::npos,"malformed raw text is represented without invalid UTF-8 output");
    auto modified=*graph;modified.nodes[0].label="mutated";check(!layout_graph(modified,{},{}),"changed presentation cannot reuse an old model key");
    auto layout=layout_graph(*graph,{},{}).value();for(auto& route:layout->routes)for(auto p:route.points)check(p.x>=layout->bounds.x && p.y>=layout->bounds.y && p.x<=layout->bounds.x+layout->bounds.width && p.y<=layout->bounds.y+layout->bounds.height,"layout bounds include every routed point");
    labels.overrides.push_back(labels.overrides[0]);check(!build_graph(*fixture.functions,*fixture.references,GraphKind::function_cfg,fixture.functions->functions[0]->id,{},labels,{}),"ambiguous duplicate label overrides rejected");
    std::stop_source stop;stop.request_stop();check(!export_graph_dot(*graph,stop.get_token()),"canceled export does not publish partial text");
}
int HEXLAB_TEST_MAIN(int argc,hexlab_test_arg_char** argv){return run([&]{layout_tests();topology_tests();function_call_neighborhood_tests();boundary_tests();export_tests(argc==2?hexlab_test_path(argv[1]):std::filesystem::path("graph-artifacts"));});}
