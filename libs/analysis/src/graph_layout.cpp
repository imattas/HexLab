#include "graph_internal.hpp"
#include <queue>
namespace hexlab {
Result<std::shared_ptr<const GraphLayout>> layout_graph(const GraphModel& model,const GraphOptions& options,std::stop_token stop){return graph_detail::guarded([&]()->Result<std::shared_ptr<const GraphLayout>>{
    using namespace graph_detail;validate_options(options);validate_model(model,stop);auto output=std::make_shared<GraphLayout>();output->model_key=fingerprint(model,stop);require(model.key==Sha256Digest{} || model.key==output->model_key,"Graph model fingerprint does not match its contents");
    std::vector<const GraphNode*> nodes;std::vector<const GraphEdge*> edges;for(auto& n:model.nodes)nodes.push_back(&n);for(auto& e:model.edges)edges.push_back(&e);
    std::sort(nodes.begin(),nodes.end(),[](auto a,auto b){return a->id<b->id;});std::sort(edges.begin(),edges.end(),[](auto a,auto b){return a->id<b->id;});
    const size_t size=nodes.size();std::map<GraphNodeId,size_t> index;for(size_t i=0;i<size;++i)index.emplace(nodes[i]->id,i);
    std::vector<std::vector<size_t>> forward(size),reverse(size);for(auto edge:edges){canceled(stop);size_t s=index.at(edge->source),t=index.at(edge->target);forward[s].push_back(t);reverse[t].push_back(s);}
    for(auto& row:forward)std::sort(row.begin(),row.end());for(auto& row:reverse)std::sort(row.begin(),row.end());
    // Iterative Kosaraju: no native recursion, even for a long linear CFG.
    std::vector<bool> visited(size,false);std::vector<size_t> finish;finish.reserve(size);
    for(size_t start=0;start<size;++start){canceled(stop);if(visited[start])continue;visited[start]=true;std::vector<std::pair<size_t,size_t>> stack{{start,0}};
        while(!stack.empty()){canceled(stop);auto& [node,next]=stack.back();if(next==forward[node].size()){finish.push_back(node);stack.pop_back();continue;}auto target=forward[node][next++];if(!visited[target]){visited[target]=true;stack.emplace_back(target,0);}}}
    std::fill(visited.begin(),visited.end(),false);std::vector<std::vector<size_t>> components;
    for(auto item=finish.rbegin();item!=finish.rend();++item){if(visited[*item])continue;std::vector<size_t> work{*item},component;visited[*item]=true;while(!work.empty()){canceled(stop);auto node=work.back();work.pop_back();component.push_back(node);for(auto target:reverse[node])if(!visited[target]){visited[target]=true;work.push_back(target);}}std::sort(component.begin(),component.end());components.push_back(std::move(component));}
    std::sort(components.begin(),components.end(),[](auto& a,auto& b){return a.front()<b.front();});std::vector<size_t> component_of(size);
    for(size_t i=0;i<components.size();++i){std::vector<GraphNodeId> ids;for(auto node:components[i]){component_of[node]=i;ids.push_back(nodes[node]->id);}output->components.push_back(std::move(ids));}
    std::vector<std::set<size_t>> dag(components.size());std::vector<size_t> incoming(components.size()),rank(components.size());
    for(size_t source=0;source<size;++source)for(auto target:forward[source]){canceled(stop);auto a=component_of[source],b=component_of[target];if(a!=b && dag[a].insert(b).second)++incoming[b];}
    std::priority_queue<size_t,std::vector<size_t>,std::greater<>> ready;for(size_t i=0;i<incoming.size();++i)if(!incoming[i])ready.push(i);
    while(!ready.empty()){canceled(stop);auto a=ready.top();ready.pop();for(auto b:dag[a]){rank[b]=std::max(rank[b],rank[a]+1);if(!--incoming[b])ready.push(b);}}
    const size_t ranks=rank.empty()?0:*std::max_element(rank.begin(),rank.end())+1;
    std::vector<std::vector<size_t>> layers(ranks),predecessors(components.size());
    for(size_t component=0;component<components.size();++component){
        layers[rank[component]].push_back(component);
        for(const auto target:dag[component])predecessors[target].push_back(component);
    }
    std::vector<size_t> layer_position(components.size());
    for(const auto& layer:layers)for(size_t position=0;position<layer.size();++position)layer_position[layer[position]]=position;
    struct OrderScore { size_t component=0; uint64_t sum=0,count=1; };
    const auto reorder_layer=[&](size_t layer_rank,const std::vector<std::vector<size_t>>& neighbors,size_t neighbor_rank){
        if(layer_rank>=layers.size() || layers[layer_rank].size()<2)return;
        canceled(stop);
        std::vector<OrderScore> scores;scores.reserve(layers[layer_rank].size());
        bool has_neighbor=false;
        for(const auto component:layers[layer_rank]){
            canceled(stop);OrderScore score;score.component=component;score.count=0;
            size_t scanned=0;
            for(const auto adjacent:neighbors[component]){
                if((scanned++&1023)==0)canceled(stop);
                if(rank[adjacent]==neighbor_rank){score.sum+=layer_position[adjacent];++score.count;has_neighbor=true;}
            }
            if(!score.count){score.sum=layer_position[component];score.count=1;}
            scores.push_back(score);
        }
        if(!has_neighbor)return;
        // At most one million components are accepted by validate_model, so
        // these cross-products remain below 10^18 and compare rational
        // barycenters exactly without platform-dependent floating point.
        std::stable_sort(scores.begin(),scores.end(),[](const OrderScore& left,const OrderScore& right){
            return left.sum*right.count<right.sum*left.count;
        });
        for(size_t position=0;position<scores.size();++position){
            layers[layer_rank][position]=scores[position].component;
            layer_position[scores[position].component]=position;
        }
    };
    std::vector<std::vector<size_t>> successors(components.size());
    for(size_t component=0;component<dag.size();++component)
        successors[component].assign(dag[component].begin(),dag[component].end());
    constexpr size_t crossing_reduction_passes=4;
    for(size_t pass=0;pass<crossing_reduction_passes;++pass){
        for(size_t layer=1;layer<ranks;++layer)reorder_layer(layer,predecessors,layer-1);
        if(ranks>1)for(size_t layer=ranks-1;layer>0;--layer)reorder_layer(layer-1,successors,layer);
    }
    std::vector<double> widths(ranks),x(ranks),y(ranks,40);
    for(size_t i=0;i<size;++i)widths[rank[component_of[i]]]=std::max(widths[rank[component_of[i]]],nodes[i]->width);for(size_t i=0;i<ranks;++i)x[i]=i?x[i-1]+widths[i-1]+options.rank_gap:40;
    std::vector<GraphRect> positions(size);for(size_t r=0;r<ranks;++r){canceled(stop);for(const auto c:layers[r]){for(auto node:components[c]){positions[node]={x[r],y[r],nodes[node]->width,nodes[node]->height};y[r]+=nodes[node]->height+options.node_gap;}y[r]+=options.node_gap;}}
    for(size_t i=0;i<size;++i)output->positions.push_back({nodes[i]->id,positions[i]});
    std::vector<size_t> source_total(size),target_total(size),source_port(size),target_port(size);for(auto edge:edges){++source_total[index.at(edge->source)];++target_total[index.at(edge->target)];}
    double right=0,bottom=0;for(auto& p:positions){right=std::max(right,p.x+p.width);bottom=std::max(bottom,p.y+p.height);}double lane=0;
    for(auto edge:edges){canceled(stop);auto a=index.at(edge->source),b=index.at(edge->target);auto s=positions[a],t=positions[b];double sy=s.y+s.height*static_cast<double>(++source_port[a])/static_cast<double>(source_total[a]+1),ty=t.y+t.height*static_cast<double>(++target_port[b])/static_cast<double>(target_total[b]+1);EdgeRoute route;route.edge=edge->id;
        if(t.x>s.x+s.width){double middle=(s.x+s.width+t.x)/2;route.points={{s.x+s.width,sy},{middle,sy},{middle,ty},{t.x,ty}};}
        else{double outside=right+options.edge_gap*(++lane),below=bottom+options.edge_gap*lane;route.points={{s.x+s.width,sy},{outside,sy},{outside,below},{t.x+t.width/2,below},{t.x+t.width/2,t.y+t.height}};}
        output->routes.push_back(std::move(route));}
    double max_x=right,max_y=bottom;for(auto& route:output->routes)for(auto& p:route.points){require(std::isfinite(p.x) && std::isfinite(p.y),"Graph route exceeds finite geometry");max_x=std::max(max_x,p.x);max_y=std::max(max_y,p.y);}output->bounds={0,0,max_x+40,max_y+40};
    Hash key;key.text("HexLab barycenter SCC layout v2");key.bytes(output->model_key);key.real(options.rank_gap);key.real(options.node_gap);key.real(options.edge_gap);for(auto& p:output->positions){canceled(stop);key.number(p.node.value);key.real(p.bounds.x);key.real(p.bounds.y);key.real(p.bounds.width);key.real(p.bounds.height);}for(auto& r:output->routes){key.number(r.edge.value);for(auto p:r.points){key.real(p.x);key.real(p.y);}}output->key=key.hash.digest();return std::shared_ptr<const GraphLayout>(std::move(output));});}
}
