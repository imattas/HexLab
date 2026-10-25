#include "graph_canvas.hpp"
#include "data_views.hpp"
#include "project_view.hpp"
#include <wx/clipbrd.h>
#include <wx/config.h>
#include <wx/dcbuffer.h>
#include <wx/dataobj.h>
#include <wx/menu.h>
#include <wx/settings.h>
#include <algorithm>
#include <charconv>
#include <cmath>
#include <cstdint>
#include <iterator>
#include <string>
#include <string_view>
#include <tuple>
namespace hexlab::desktop {
namespace {
int pixel(double value) { return static_cast<int>(std::round(std::clamp(value, -10000000., 10000000.))); }
double distance(GraphPoint at, GraphPoint first, GraphPoint last) {
    auto dx = last.x - first.x, dy = last.y - first.y;
    auto square = dx * dx + dy * dy;
    auto t = square ? std::clamp(((at.x - first.x) * dx + (at.y - first.y) * dy) / square, 0., 1.) : 0.;
    return std::hypot(at.x - first.x - t * dx, at.y - first.y - t * dy);
}
wxColour color(GraphEdgeKind kind) {
    switch (kind) {
    case GraphEdgeKind::conditional_true:
        return wxColour(35, 125, 65);
    case GraphEdgeKind::conditional_false:
        return wxColour(180, 75, 55);
    case GraphEdgeKind::call:
        return wxColour(95, 70, 175);
    case GraphEdgeKind::unresolved:
        return wxColour(150, 105, 20);
    default:
        return wxColour(55, 100, 155);
    }
}
int edge_priority(GraphEdgeKind kind) {
    switch (kind) {
    case GraphEdgeKind::conditional_true: return 0;
    case GraphEdgeKind::conditional_false: return 1;
    case GraphEdgeKind::fallthrough: return 2;
    case GraphEdgeKind::jump: return 3;
    case GraphEdgeKind::call: return 4;
    case GraphEdgeKind::call_continuation: return 5;
    case GraphEdgeKind::tail_candidate: return 6;
    case GraphEdgeKind::delay_slot: return 7;
    case GraphEdgeKind::unresolved: return 8;
    }
    return 9;
}
auto location_order_key(const std::optional<Location> &location) {
    if (!location) return std::tuple{2, std::uint32_t{0}, std::uint64_t{0}};
    if (const auto *address = std::get_if<Address>(&*location))
        return std::tuple{0, address->space.value, address->offset};
    return std::tuple{1, std::uint32_t{0}, std::get<FileOffset>(*location).value};
}
const char *edge_name(GraphEdgeKind kind) {
    switch (kind) {
    case GraphEdgeKind::fallthrough: return "fallthrough";
    case GraphEdgeKind::conditional_true: return "true branch";
    case GraphEdgeKind::conditional_false: return "false branch";
    case GraphEdgeKind::jump: return "jump";
    case GraphEdgeKind::call: return "call";
    case GraphEdgeKind::tail_candidate: return "tail candidate";
    case GraphEdgeKind::call_continuation: return "call continuation";
    case GraphEdgeKind::unresolved: return "unresolved edge";
    case GraphEdgeKind::delay_slot: return "delay slot";
    }
    return "edge";
}
} // namespace
GraphCanvas::GraphCanvas(wxWindow *parent) : wxPanel(parent) {
    SetName("graph-canvas");
    SetBackgroundStyle(wxBG_STYLE_PAINT);
    Bind(wxEVT_PAINT, &GraphCanvas::paint, this);
    Bind(wxEVT_LEFT_DOWN, [this](wxMouseEvent &event) {
        SetFocus();
        const auto selected = hit_test(event.GetPosition());
        if (selected && std::holds_alternative<GraphNodeId>(*selected)) {
            hit_ = selected;
            select_node_range(std::get<GraphNodeId>(*selected), event.ShiftDown(), event.ControlDown() || event.CmdDown());
            edge_focus_incoming_ = false;
            drag_node_ = std::get<GraphNodeId>(*selected);
            node_dragging_ = true;
            node_drag_moved_ = false;
            node_drag_start_ = event.GetPosition();
            node_drag_origin_ = to_model(node_drag_start_);
            CaptureMouse();
            Refresh();
            if (focus_changed) focus_changed();
        } else {
            activate(event.GetPosition(), false);
        }
    });
    Bind(wxEVT_LEFT_UP, [this](wxMouseEvent &event) {
        if (!node_dragging_) return;
        node_dragging_ = false;
        if (HasCapture()) ReleaseMouse();
        const bool moved = node_drag_moved_;
        node_drag_moved_ = false;
        drag_node_.reset();
        if (moved) persist_layout();
        if (!moved) activate(event.GetPosition(), false);
    });
    Bind(wxEVT_LEFT_DCLICK, [this](wxMouseEvent &event) { activate(event.GetPosition(), true); });
    Bind(wxEVT_RIGHT_UP, [this](wxMouseEvent &event) {
        SetFocus();
        show_context_menu(event.GetPosition());
    });
    Bind(wxEVT_MIDDLE_DOWN, [this](wxMouseEvent &event) {
        dragging_ = true;
        last_ = event.GetPosition();
        CaptureMouse();
    });
    Bind(wxEVT_MIDDLE_UP, [this](wxMouseEvent &) {
        dragging_ = false;
        if (HasCapture())
            ReleaseMouse();
    });
    Bind(wxEVT_MOUSE_CAPTURE_LOST, [this](wxMouseCaptureLostEvent &) {
        dragging_ = false;
        node_dragging_ = false;
        node_drag_moved_ = false;
        drag_node_.reset();
    });
    Bind(wxEVT_MOTION, [this](wxMouseEvent &event) {
        if (node_dragging_ && drag_node_ && event.LeftIsDown()) {
            const auto delta = event.GetPosition() - node_drag_start_;
            if (!node_drag_moved_ && (std::abs(delta.x) >= 4 || std::abs(delta.y) >= 4))
                node_drag_moved_ = true;
            if (node_drag_moved_) move_dragged_node(event.GetPosition());
        }
        if (dragging_) {
            auto at = event.GetPosition();
            pan_by(at - last_);
            last_ = at;
        }
    });
    Bind(wxEVT_MOUSEWHEEL,
         [this](wxMouseEvent &event) { zoom_by(event.GetWheelRotation() > 0 ? 1.2 : 1. / 1.2, event.GetPosition()); });
    Bind(wxEVT_CHAR_HOOK, [this](wxKeyEvent &event) {
        switch (event.GetKeyCode()) {
        case WXK_HOME:
            fit();
            break;
        case '+':
        case '=':
            zoom_by(1.2, wxPoint{GetClientSize().x / 2, GetClientSize().y / 2});
            break;
        case '-':
            zoom_by(1. / 1.2, wxPoint{GetClientSize().x / 2, GetClientSize().y / 2});
            break;
        case WXK_LEFT:
            if (event.ControlDown()) move_graph(false);
            else pan_by({40, 0});
            break;
        case WXK_RIGHT:
            if (event.ControlDown()) move_graph(true);
            else pan_by({-40, 0});
            break;
        case WXK_TAB:
            (void)move_node(!event.ShiftDown());
            break;
        case WXK_UP:
            if (event.ControlDown()) cycle_edges(false);
            else if (event.AltDown()) event.Skip();
            else if (event.ShiftDown()) pan_by({0, 40});
            else move_instruction(false);
            break;
        case WXK_DOWN:
            if (event.ControlDown()) cycle_edges(true);
            else if (event.AltDown()) event.Skip();
            else if (event.ShiftDown()) pan_by({0, -40});
            else move_instruction(true);
            break;
        case WXK_RETURN:
            if (hit_ && std::holds_alternative<GraphEdgeId>(*hit_)) {
                follow_edge(std::get<GraphEdgeId>(*hit_), true);
            } else if (graph_ && follow_selection) follow_selection();
            break;
        default:
            event.Skip();
        }
    });
}
bool GraphCanvas::set_graph(std::shared_ptr<const ProjectGraph> graph) {
    if (graph && (!graph->model || !graph->layout || graph->layout->model_key != graph->model->key))
        return false;
    if (graph == graph_)
        return true;
    auto previous = graph_ ? std::optional<Sha256Digest>{graph_->layout->key} : std::nullopt;
    graph_ = std::move(graph);
    nodes_.clear();
    edges_.clear();
    outgoing_edges_.clear();
    incoming_edges_.clear();
    position_by_node_.clear();
    positions_by_x_.clear();
    routes_by_x_.clear();
    navigation_nodes_.clear();
    node_navigation_order_.clear();
    placements_.clear();
    routes_.clear();
    hit_.reset();
    edge_focus_incoming_ = false;
    if (graph_) {
        for (std::size_t i = 0; i < graph_->model->nodes.size(); ++i) {
            auto &node = graph_->model->nodes[i];
            nodes_.emplace(node.id, &node);
            // Unresolved/boundary nodes describe transfers; their source address
            // can duplicate a real code node and must not become cursor stops.
            if (node.selection && (node.kind == GraphNodeKind::block || node.kind == GraphNodeKind::function))
                navigation_nodes_.push_back(&node);
        }
        for (auto it = selected_nodes_.begin(); it != selected_nodes_.end();) {
            if (!nodes_.contains(*it)) it = selected_nodes_.erase(it);
            else ++it;
        }
        if (selection_anchor_ && !nodes_.contains(*selection_anchor_)) selection_anchor_.reset();
        const auto key = [](Location location) {
            if (const auto *address = std::get_if<Address>(&location))
                return std::tuple{0, address->space.value, address->offset};
            return std::tuple{1, std::uint32_t{0}, std::get<FileOffset>(location).value};
        };
        std::stable_sort(navigation_nodes_.begin(), navigation_nodes_.end(), [&](auto *a, auto *b) {
            return key(*a->selection) < key(*b->selection);
        });
        for (auto &edge : graph_->model->edges) {
            edges_.emplace(edge.id, &edge);
            outgoing_edges_[edge.source].push_back(edge.id);
            incoming_edges_[edge.target].push_back(edge.id);
        }
        const auto sort_adjacency = [&](auto &adjacency, bool outgoing) {
            for (auto &[node, edge_ids] : adjacency) {
                (void)node;
                std::stable_sort(edge_ids.begin(), edge_ids.end(), [&](GraphEdgeId left, GraphEdgeId right) {
                    const auto *a = edges_.at(left), *b = edges_.at(right);
                    const auto a_endpoint = outgoing ? a->target : a->source;
                    const auto b_endpoint = outgoing ? b->target : b->source;
                    const auto *a_node = nodes_.at(a_endpoint), *b_node = nodes_.at(b_endpoint);
                    return std::tuple{edge_priority(a->kind), location_order_key(a_node->selection), a_endpoint.value,
                                      left.value} <
                           std::tuple{edge_priority(b->kind), location_order_key(b_node->selection), b_endpoint.value,
                                      right.value};
                });
            }
        };
        sort_adjacency(outgoing_edges_, true);
        sort_adjacency(incoming_edges_, false);
        placements_ = graph_->layout->positions;
        routes_ = graph_->layout->routes;
        positions_by_x_.reserve(placements_.size());
        for (std::size_t i = 0; i < placements_.size(); ++i) {
            const auto &position = placements_[i];
            positions_by_x_.push_back({position.bounds, i});
            position_by_node_.emplace(position.node, i);
            node_navigation_order_.push_back(position.node);
        }
        std::stable_sort(positions_by_x_.begin(), positions_by_x_.end(), [](const auto &a, const auto &b) {
            return a.bounds.x < b.bounds.x;
        });
        std::stable_sort(node_navigation_order_.begin(), node_navigation_order_.end(), [&](GraphNodeId left, GraphNodeId right) {
            const auto left_position = position_by_node_.find(left), right_position = position_by_node_.find(right);
            if (left_position == position_by_node_.end() || right_position == position_by_node_.end())
                return left.value < right.value;
            const auto &a = placements_[left_position->second].bounds;
            const auto &b = placements_[right_position->second].bounds;
            return std::tuple{a.y, a.x, left.value} < std::tuple{b.y, b.x, right.value};
        });
        routes_by_x_.reserve(routes_.size());
        for (std::size_t i = 0; i < routes_.size(); ++i) {
            const auto &route = routes_[i];
            if (route.points.empty()) continue;
            auto low = route.points.front(), high = low;
            for (const auto &point : route.points) {
                low.x = std::min(low.x, point.x); low.y = std::min(low.y, point.y);
                high.x = std::max(high.x, point.x); high.y = std::max(high.y, point.y);
            }
            routes_by_x_.push_back({{low.x - 8, low.y - 8, high.x - low.x + 16, high.y - low.y + 16}, i});
        }
        std::stable_sort(routes_by_x_.begin(), routes_by_x_.end(), [](const auto &a, const auto &b) {
            return a.bounds.x < b.bounds.x;
        });
        restore_persisted_layout();
        rebuild_geometry_indexes();
    }
    if (graph_ && previous != graph_->layout->key)
        fit();
    else
        Refresh();
    if (reveal_pending_) reveal_selection();
    return true;
}
wxPoint GraphCanvas::to_client(GraphPoint point) const {
    return {pixel(point.x * scale_ + origin_.x), pixel(point.y * scale_ + origin_.y)};
}
GraphPoint GraphCanvas::to_model(wxPoint point) const {
    return {(point.x - origin_.x) / scale_, (point.y - origin_.y) / scale_};
}
bool GraphCanvas::visible(GraphRect bounds) const {
    const auto view = viewport();
    return bounds.x + bounds.width >= view.x && bounds.y + bounds.height >= view.y &&
           bounds.x <= view.x + view.width && bounds.y <= view.y + view.height;
}
GraphRect GraphCanvas::viewport() const {
    const auto size = GetClientSize();
    const auto first = to_model({0, 0}), last = to_model({size.x, size.y});
    return {std::min(first.x, last.x), std::min(first.y, last.y), std::abs(last.x - first.x),
            std::abs(last.y - first.y)};
}
std::vector<std::size_t> GraphCanvas::indexed_candidates(const std::vector<IndexedBounds> &index,
                                                          GraphRect area) const {
    const auto right = area.x + area.width, bottom = area.y + area.height;
    const auto end = std::upper_bound(index.begin(), index.end(), right,
        [](double x, const IndexedBounds &item) { return x < item.bounds.x; });
    std::vector<std::size_t> result;
    for (auto it = index.begin(); it != end; ++it) {
        const auto &b = it->bounds;
        if (b.x + b.width >= area.x && b.y <= bottom && b.y + b.height >= area.y)
            result.push_back(it->index);
    }
    std::sort(result.begin(), result.end());
    return result;
}
std::size_t GraphCanvas::visible_nodes() const {
    if (!graph_)
        return 0;
    return std::count_if(placements_.begin(), placements_.end(),
                         [this](auto &p) { return visible(p.bounds); });
}
wxString GraphCanvas::focus_description() const {
    if (!graph_ || !hit_) return {};
    if (const auto *node_id = std::get_if<GraphNodeId>(&*hit_)) {
        const auto found = nodes_.find(*node_id);
        if (found == nodes_.end()) return {};
        return "Focused node: " + preview_text(found->second->label, 96);
    }
    const auto edge_found = edges_.find(std::get<GraphEdgeId>(*hit_));
    if (edge_found == edges_.end()) return {};
    const auto *edge = edge_found->second;
    const auto source = nodes_.find(edge->source), target = nodes_.find(edge->target);
    const auto source_name = source == nodes_.end() ? wxString("?") : preview_text(source->second->label, 48);
    const auto target_name = target == nodes_.end() ? wxString("?") : preview_text(target->second->label, 48);
    return wxString("Focused ") + edge_name(edge->kind) + ": " + source_name + " -> " + target_name;
}
bool GraphCanvas::focus_node(GraphNodeId id, bool navigate_to_location) {
    const auto found = nodes_.find(id);
    if (found == nodes_.end()) return false;
    hit_ = GraphHit{id};
    edge_focus_incoming_ = false;
    const auto position = position_by_node_.find(id);
    if (position != position_by_node_.end()) {
        const auto &bounds = placements_[position->second].bounds;
        const auto center = to_client({bounds.x + bounds.width / 2, bounds.y + bounds.height / 2});
        const auto size = GetClientSize();
        pan_by({size.x / 2 - center.x, size.y / 2 - center.y});
    } else {
        Refresh();
    }
    if (focus_changed) focus_changed();
    if (navigate_to_location && found->second->selection && navigate &&
        !navigate(*found->second->selection))
        return false;
    return true;
}
bool GraphCanvas::move_node(bool next) {
    if (!graph_ || node_navigation_order_.empty())
        return false;
    std::optional<GraphNodeId> current;
    if (hit_) {
        if (const auto *node = std::get_if<GraphNodeId>(&*hit_); node &&
            std::find(node_navigation_order_.begin(), node_navigation_order_.end(), *node) != node_navigation_order_.end())
            current = *node;
    }
    if (!current)
        current = focused_node();
    auto position = current ? std::find(node_navigation_order_.begin(), node_navigation_order_.end(), *current)
                            : node_navigation_order_.end();
    std::size_t index = next ? 0 : node_navigation_order_.size() - 1;
    if (position != node_navigation_order_.end()) {
        const auto current_index = static_cast<std::size_t>(position - node_navigation_order_.begin());
        index = next ? (current_index + 1) % node_navigation_order_.size()
                     : (current_index + node_navigation_order_.size() - 1) % node_navigation_order_.size();
    }
    return focus_node(node_navigation_order_[index]);
}
void GraphCanvas::fit() {
    if (!graph_)
        return;
    auto b = graph_->layout->bounds;
    if (!placements_.empty()) {
        const auto &first = placements_.front().bounds;
        b = first;
        for (const auto &placement : placements_) {
            const auto &r = placement.bounds;
            const auto right = std::max(b.x + b.width, r.x + r.width);
            const auto bottom = std::max(b.y + b.height, r.y + r.height);
            b.x = std::min(b.x, r.x);
            b.y = std::min(b.y, r.y);
            b.width = right - b.x;
            b.height = bottom - b.y;
        }
    }
    auto size = GetClientSize();
    scale_ = std::clamp(
        std::min(std::max(1, size.x - 48) / std::max(1., b.width), std::max(1, size.y - 48) / std::max(1., b.height)),
        .05, 4.);
    origin_ = {(size.x - b.width * scale_) / 2 - b.x * scale_, (size.y - b.height * scale_) / 2 - b.y * scale_};
    Refresh();
}
void GraphCanvas::reset_layout() {
    if (!graph_) return;
    if (auto *config = wxConfigBase::Get(false)) {
        (void)config->DeleteEntry(persisted_layout_key());
        (void)config->Flush();
    }
    placements_ = graph_->layout->positions;
    rebuild_geometry_indexes();
    fit();
}
wxString GraphCanvas::persisted_layout_key() const {
    if (!graph_ || !graph_->model) return {};
    return "/GraphLayouts/" + wxString::FromUTF8(digest_hex(graph_->model->key));
}
void GraphCanvas::restore_persisted_layout() {
    if (!graph_ || placements_.empty() || placements_.size() > 8192) return;
    auto *config = wxConfigBase::Get(false);
    if (!config) return;
    wxString saved;
    if (!config->Read(persisted_layout_key(), &saved) || saved.empty() || saved.length() > 1024 * 1024) return;
    const auto utf8 = saved.ToUTF8();
    if (!utf8) return;
    const std::string_view encoded(utf8.data(), utf8.length());
    if (!encoded.starts_with("v1;")) return;
    std::map<GraphNodeId, GraphPoint> points;
    std::size_t at = 3;
    while (at < encoded.size()) {
        const auto end = encoded.find(';', at);
        if (end == std::string_view::npos) return;
        const auto row = encoded.substr(at, end - at);
        const auto first = row.find(',');
        const auto second = first == std::string_view::npos ? first : row.find(',', first + 1);
        if (first == std::string_view::npos || second == std::string_view::npos) return;
        std::uint64_t id = 0;
        std::int64_t x = 0, y = 0;
        const auto parse = [](std::string_view value, auto &out) {
            const auto result = std::from_chars(value.data(), value.data() + value.size(), out);
            return result.ec == std::errc{} && result.ptr == value.data() + value.size();
        };
        if (!parse(row.substr(0, first), id) || !parse(row.substr(first + 1, second - first - 1), x) ||
            !parse(row.substr(second + 1), y) || std::abs(static_cast<double>(x)) > 1000000000. ||
            std::abs(static_cast<double>(y)) > 1000000000.) return;
        const GraphNodeId node{id};
        if (!position_by_node_.contains(node) || !points.emplace(node, GraphPoint{x / 1000., y / 1000.}).second) return;
        at = end + 1;
    }
    if (points.size() != placements_.size()) return;
    for (auto &placement : placements_) {
        const auto found = points.find(placement.node);
        if (found == points.end()) return;
        placement.bounds.x = found->second.x;
        placement.bounds.y = found->second.y;
    }
}
void GraphCanvas::persist_layout() const {
    if (!graph_ || placements_.empty() || placements_.size() > 8192) return;
    auto *config = wxConfigBase::Get(false);
    if (!config) return;
    std::string encoded("v1;");
    for (const auto &placement : placements_) {
        const auto &bounds = placement.bounds;
        if (!std::isfinite(bounds.x) || !std::isfinite(bounds.y) || std::abs(bounds.x) > 1000000. ||
            std::abs(bounds.y) > 1000000.) return;
        encoded += std::to_string(placement.node.value);
        encoded += ',';
        encoded += std::to_string(static_cast<std::int64_t>(std::llround(bounds.x * 1000.)));
        encoded += ',';
        encoded += std::to_string(static_cast<std::int64_t>(std::llround(bounds.y * 1000.)));
        encoded += ';';
        if (encoded.size() > 1024 * 1024) return;
    }
    (void)config->Write(persisted_layout_key(), wxString::FromUTF8(encoded));
    (void)config->Flush();
}
void GraphCanvas::pan_by(wxPoint amount) {
    origin_.x = std::clamp(origin_.x + amount.x, -1e9, 1e9);
    origin_.y = std::clamp(origin_.y + amount.y, -1e9, 1e9);
    Refresh();
}
void GraphCanvas::zoom_by(double factor, wxPoint anchor) {
    if (!std::isfinite(factor) || factor <= 0)
        return;
    auto at = to_model(anchor);
    scale_ = std::clamp(scale_ * factor, .05, 4.);
    origin_ = {anchor.x - at.x * scale_, anchor.y - at.y * scale_};
    Refresh();
}
void GraphCanvas::rebuild_geometry_indexes() {
    positions_by_x_.clear();
    positions_by_x_.reserve(placements_.size());
    node_navigation_order_.clear();
    node_navigation_order_.reserve(placements_.size());
    for (std::size_t i = 0; i < placements_.size(); ++i) {
        positions_by_x_.push_back({placements_[i].bounds, i});
        node_navigation_order_.push_back(placements_[i].node);
    }
    std::stable_sort(positions_by_x_.begin(), positions_by_x_.end(), [](const auto &a, const auto &b) {
        return a.bounds.x < b.bounds.x;
    });
    std::stable_sort(node_navigation_order_.begin(), node_navigation_order_.end(), [&](GraphNodeId left, GraphNodeId right) {
        const auto left_position = position_by_node_.find(left), right_position = position_by_node_.find(right);
        if (left_position == position_by_node_.end() || right_position == position_by_node_.end())
            return left.value < right.value;
        const auto &a = placements_[left_position->second].bounds;
        const auto &b = placements_[right_position->second].bounds;
        return std::tuple{a.y, a.x, left.value} < std::tuple{b.y, b.x, right.value};
    });

    routes_ = graph_->layout->routes;
    routes_by_x_.clear();
    routes_by_x_.reserve(routes_.size());
    for (std::size_t i = 0; i < routes_.size(); ++i) {
        auto &route = routes_[i];
        if (route.points.empty()) continue;
        const auto *edge = edges_.contains(route.edge) ? edges_.at(route.edge) : nullptr;
        if (edge) {
            const auto adjust_endpoint = [&](GraphNodeId id, GraphPoint &point) {
                const auto position = position_by_node_.find(id);
                if (position == position_by_node_.end()) return;
                const auto &current = placements_[position->second].bounds;
                const auto &original = graph_->layout->positions[position->second].bounds;
                point.x += current.x - original.x;
                point.y += current.y - original.y;
            };
            adjust_endpoint(edge->source, route.points.front());
            adjust_endpoint(edge->target, route.points.back());
        }
        auto low = route.points.front(), high = low;
        for (const auto &point : route.points) {
            low.x = std::min(low.x, point.x); low.y = std::min(low.y, point.y);
            high.x = std::max(high.x, point.x); high.y = std::max(high.y, point.y);
        }
        routes_by_x_.push_back({{low.x - 8, low.y - 8, high.x - low.x + 16, high.y - low.y + 16}, i});
    }
    std::stable_sort(routes_by_x_.begin(), routes_by_x_.end(), [](const auto &a, const auto &b) {
        return a.bounds.x < b.bounds.x;
    });
}
void GraphCanvas::move_dragged_node(wxPoint point) {
    if (!graph_ || !drag_node_) return;
    const auto position = position_by_node_.find(*drag_node_);
    if (position == position_by_node_.end()) return;
    const auto at = to_model(point);
    auto &bounds = placements_[position->second].bounds;
    bounds.x += at.x - node_drag_origin_.x;
    bounds.y += at.y - node_drag_origin_.y;
    node_drag_origin_ = at;
    rebuild_geometry_indexes();
    Refresh();
}
void GraphCanvas::select_node_range(GraphNodeId id, bool extend, bool toggle) {
    if (!nodes_.contains(id)) return;
    if (!extend && !toggle) {
        selected_nodes_.clear();
        selected_nodes_.insert(id);
        selection_anchor_ = id;
    } else if (extend && selection_anchor_) {
        const auto first = std::find(node_navigation_order_.begin(), node_navigation_order_.end(), *selection_anchor_);
        const auto last = std::find(node_navigation_order_.begin(), node_navigation_order_.end(), id);
        if (first == node_navigation_order_.end() || last == node_navigation_order_.end()) return;
        const auto lo = std::min(first, last), hi = std::max(first, last);
        if (!toggle) selected_nodes_.clear();
        for (auto it = lo; it != std::next(hi) && selected_nodes_.size() < max_selected_nodes_; ++it)
            selected_nodes_.insert(*it);
    } else if (toggle) {
        if (selected_nodes_.contains(id)) selected_nodes_.erase(id);
        else if (selected_nodes_.size() < max_selected_nodes_) selected_nodes_.insert(id);
        selection_anchor_ = id;
    } else {
        selected_nodes_.insert(id);
        selection_anchor_ = id;
    }
    Refresh();
}
void GraphCanvas::select(std::optional<Location> location) {
    const auto changed = selection_ != location;
    selection_ = location;
    // Keep graph focus attached to the location selected in another view.
    // Prefer a node's own location over a containing block so call graph
    // functions and boundary nodes remain individually focusable.
    std::optional<GraphNodeId> matching_node;
    if (location && graph_) {
        for (const auto &node : graph_->model->nodes)
            if (node.selection == location) { matching_node = node.id; break; }
        if (!matching_node) {
            for (const auto *node : navigation_nodes_)
                if (instruction_index(*node)) { matching_node = node->id; break; }
        }
    }
    if (matching_node) {
        if (selected_nodes_.empty()) selected_nodes_.insert(*matching_node);
        selection_anchor_ = *matching_node;
        hit_ = GraphHit{*matching_node};
        edge_focus_incoming_ = false;
        if (focus_changed) focus_changed();
    } else if (hit_ && std::holds_alternative<GraphNodeId>(*hit_) && changed) {
        hit_.reset();
        edge_focus_incoming_ = false;
        if (focus_changed) focus_changed();
    }
    if (hit_ && std::holds_alternative<GraphEdgeId>(*hit_) &&
        edges_.at(std::get<GraphEdgeId>(*hit_))->selection != selection_) {
        hit_.reset();
        edge_focus_incoming_ = false;
    }
    if (changed) reveal_selection();
    Refresh();
}
void GraphCanvas::reveal_selection() {
    if (!selection_) { reveal_pending_ = false; return; }
    if (!graph_) { reveal_pending_ = true; return; }
    for (const auto &position : placements_) {
        const auto node_it = nodes_.find(position.node);
        if (node_it == nodes_.end()) continue;
        const auto *node = node_it->second;
        const auto index = instruction_index(*node);
        if (!index && node->selection != selection_) continue;
        auto point = to_client({position.bounds.x + position.bounds.width / 2, position.bounds.y});
        const auto rows = instruction_rows(*node, position.bounds);
        if (index && rows.count)
            point.y = rows.y + static_cast<int>(*index - rows.first) * rows.line + rows.line / 2;
        if (!GetClientRect().Contains(point))
            pan_by({GetClientSize().x / 2 - point.x, GetClientSize().y / 2 - point.y});
        reveal_pending_ = false;
        return;
    }
    reveal_pending_ = true;
}
std::optional<std::size_t> GraphCanvas::instruction_index(const GraphNode &node) const {
    if (!node.block || !selection_) return {};
    const auto *address = std::get_if<Address>(&*selection_);
    if (!address) return {};
    for (std::size_t i = 0; i < node.block->instructions.size(); ++i) {
        const auto &instruction = node.block->instructions[i]->instruction;
        if (instruction.address.space == address->space && address->offset >= instruction.address.offset &&
            address->offset - instruction.address.offset < std::max<unsigned>(1, instruction.length)) return i;
    }
    return {};
}
GraphCanvas::InstructionRows GraphCanvas::instruction_rows(const GraphNode &node, GraphRect bounds) const {
    const auto top = to_client({bounds.x, bounds.y});
    const auto bottom = to_client({bounds.x + bounds.width, bounds.y + bounds.height});
    InstructionRows rows;
    rows.line = std::max(10, pixel(18 * scale_));
    rows.y = top.y + 6 + rows.line;
    if (!node.block || bottom.y - 4 <= rows.y) return rows;
    rows.count = std::min({node.preview_lines, node.block->instructions.size(),
                          static_cast<std::size_t>((bottom.y - 4 - rows.y) / rows.line)});
    if (const auto selected = instruction_index(node); selected && rows.count) {
        const auto centered = *selected > rows.count / 2 ? *selected - rows.count / 2 : 0;
        rows.first = std::min(centered, node.block->instructions.size() - rows.count);
    }
    return rows;
}
void GraphCanvas::move_instruction(bool next) {
    if (!graph_ || navigation_nodes_.empty() || !navigate) return;
    hit_.reset();
    edge_focus_incoming_ = false;
    if (focus_changed) focus_changed();
    const auto destination = [](const GraphNode &node, bool last) -> Location {
        if (node.block && !node.block->instructions.empty())
            return (last ? node.block->instructions.back() : node.block->instructions.front())->instruction.address;
        return *node.selection;
    };
    for (std::size_t n = 0; n < navigation_nodes_.size(); ++n) {
        const auto &node = *navigation_nodes_[n];
        const auto selected = instruction_index(node);
        if (!selected && node.selection != selection_) continue;
        if (selected && ((next && *selected + 1 < node.block->instructions.size()) || (!next && *selected > 0)))
            (void)navigate(node.block->instructions[next ? *selected + 1 : *selected - 1]->instruction.address);
        else if (next && n + 1 < navigation_nodes_.size()) (void)navigate(destination(*navigation_nodes_[n + 1], false));
        else if (!next && n > 0) (void)navigate(destination(*navigation_nodes_[n - 1], true));
        return;
    }
    (void)navigate(destination(*(next ? navigation_nodes_.front() : navigation_nodes_.back()), !next));
}
std::optional<GraphNodeId> GraphCanvas::focused_node() const {
    if (!graph_) return {};
    if (hit_) {
        if (const auto *node_id = std::get_if<GraphNodeId>(&*hit_))
            if (nodes_.contains(*node_id)) return *node_id;
    }
    if (!selection_) return {};
    for (const auto *node : navigation_nodes_)
        if (node->selection == selection_ || instruction_index(*node)) return node->id;
    return {};
}
void GraphCanvas::move_graph(bool forward) {
    if (!graph_) return;
    if (hit_ && std::holds_alternative<GraphEdgeId>(*hit_)) {
        follow_edge(std::get<GraphEdgeId>(*hit_), forward);
        return;
    }
    const auto node_id = focused_node();
    if (!node_id) return;
    const auto &adjacency = forward ? outgoing_edges_ : incoming_edges_;
    const auto found = adjacency.find(*node_id);
    if (found == adjacency.end() || found->second.empty()) return;
    edge_focus_incoming_ = !forward;
    hit_ = GraphHit{found->second.front()};
    Refresh();
    if (focus_changed) focus_changed();
}
void GraphCanvas::cycle_edges(bool next) {
    if (!graph_) return;
    GraphNodeId anchor{};
    std::optional<GraphEdgeId> current_edge;
    if (hit_ && std::holds_alternative<GraphEdgeId>(*hit_)) {
        current_edge = std::get<GraphEdgeId>(*hit_);
        const auto edge = edges_.find(*current_edge);
        if (edge == edges_.end()) return;
        anchor = edge_focus_incoming_ ? edge->second->target : edge->second->source;
    } else {
        const auto node = focused_node();
        if (!node) return;
        anchor = *node;
        edge_focus_incoming_ = false;
    }
    const auto &adjacency = edge_focus_incoming_ ? incoming_edges_ : outgoing_edges_;
    const auto found = adjacency.find(anchor);
    if (found == adjacency.end() || found->second.empty()) return;
    const auto &candidates = found->second;
    auto index = next ? std::size_t{0} : candidates.size() - 1;
    if (current_edge) {
        const auto current = std::find(candidates.begin(), candidates.end(), *current_edge);
        if (current == candidates.end()) return;
        const auto position = static_cast<std::size_t>(current - candidates.begin());
        index = next ? (position + 1) % candidates.size() :
                       (position + candidates.size() - 1) % candidates.size();
    }
    hit_ = GraphHit{candidates[index]};
    Refresh();
    if (focus_changed) focus_changed();
}
void GraphCanvas::follow_edge(GraphEdgeId edge_id, bool forward) {
    const auto found = edges_.find(edge_id);
    if (found == edges_.end()) return;
    const auto *edge = found->second;
    const auto destination_id = forward ? edge->target : edge->source;
    const auto destination = nodes_.find(destination_id);
    if (destination == nodes_.end()) return;
    const auto location = forward ? (edge->target_location ? edge->target_location : destination->second->selection)
                                 : destination->second->selection;
    hit_ = GraphHit{destination_id};
    edge_focus_incoming_ = false;
    reveal_node(destination_id);
    Refresh();
    if (focus_changed) focus_changed();
    if (location && navigate && !navigate(*location)) return;
}
void GraphCanvas::reveal_node(GraphNodeId id) {
    const auto position = position_by_node_.find(id);
    if (position == position_by_node_.end()) return;
    const auto &bounds = placements_[position->second].bounds;
    const auto top_left = to_client({bounds.x, bounds.y});
    const auto bottom_right = to_client({bounds.x + bounds.width, bounds.y + bounds.height});
    const auto size = GetClientSize();
    int dx = 0, dy = 0;
    if (top_left.x < 0) dx = -top_left.x;
    else if (bottom_right.x > size.x) dx = size.x - bottom_right.x;
    if (top_left.y < 0) dy = -top_left.y;
    else if (bottom_right.y > size.y) dy = size.y - bottom_right.y;
    if (dx || dy) pan_by({dx, dy});
}
std::optional<GraphHit> GraphCanvas::hit_test(wxPoint point) const {
    if (!graph_)
        return {};
    auto at = to_model(point);
    const auto node_candidates = indexed_candidates(positions_by_x_, {at.x, at.y, 0, 0});
    for (auto candidate = node_candidates.rbegin(); candidate != node_candidates.rend(); ++candidate) {
        const auto i = *candidate;
        const auto &placement = placements_[i];
        auto b = placement.bounds;
        if (at.x >= b.x && at.y >= b.y && at.x <= b.x + b.width && at.y <= b.y + b.height)
            return GraphHit{placement.node};
    }
    double best = 6. / scale_;
    std::optional<GraphHit> result;
    for (const auto route_index : indexed_candidates(routes_by_x_, {at.x - best, at.y - best, best * 2, best * 2})) {
        const auto &route = routes_[route_index];
        for (std::size_t point_index = 1; point_index < route.points.size(); ++point_index) {
            auto d = distance(at, route.points[point_index - 1], route.points[point_index]);
            if (d < best) {
                best = d;
                result = GraphHit{route.edge};
            }
        }
    }
    return result;
}
void GraphCanvas::activate(wxPoint point, bool follow) {
    hit_ = hit_test(point);
    edge_focus_incoming_ = false;
    Refresh();
    if (!hit_) {
        if (focus_changed) focus_changed();
        return;
    }
    std::optional<Location> location;
    bool instruction = false;
    if (auto node_id = std::get_if<GraphNodeId>(&*hit_)) {
        const auto *node = nodes_.at(*node_id);
        location = node->selection;
        const auto position_index = position_by_node_.find(*node_id);
        if (position_index == position_by_node_.end()) return;
        const auto rows = instruction_rows(*node, placements_[position_index->second].bounds);
        if (point.y >= rows.y && point.y < rows.y + static_cast<int>(rows.count) * rows.line) {
            const auto row = rows.first + static_cast<std::size_t>((point.y - rows.y) / rows.line);
            location = node->block->instructions[row]->instruction.address;
            instruction = true;
        }
    } else {
        const auto edge_id = std::get<GraphEdgeId>(*hit_);
        if (follow) {
            follow_edge(edge_id, true);
            return;
        }
        auto edge = edges_.at(edge_id);
        location = edge->selection;
    }
    if (location && navigate && !navigate(*location)) {
        if (focus_changed) focus_changed();
        return;
    }
    if (follow && instruction && follow_selection) follow_selection();
    if (focus_changed) focus_changed();
}
void GraphCanvas::show_context_menu(wxPoint point) {
    const auto selected = hit_test(point);
    if (!selected) return;
    hit_ = selected;
    edge_focus_incoming_ = false;
    Refresh();
    if (focus_changed) focus_changed();

    wxMenu menu;
    const auto append = [&](const wxString &label) { return menu.Append(wxID_ANY, label)->GetId(); };
    const auto copy_label_id = append("Copy node label");
    int follow_id = wxID_NONE;
    int copy_location_id = wxID_NONE;
    int rename_id = wxID_NONE;
    int comment_id = wxID_NONE;
    int bookmark_id = wxID_NONE;
    int follow_edge_id = wxID_NONE;
    wxString label;
    std::optional<Location> location;
    bool is_node = false;
    const auto action_available = [&](GraphContextAction action) {
        return !context_action_available || (location && context_action_available(*location, action));
    };

    if (const auto *node_id = std::get_if<GraphNodeId>(&*selected)) {
        const auto found = nodes_.find(*node_id);
        if (found == nodes_.end()) return;
        const auto *node = found->second;
        label = wxString::FromUTF8(node->label);
        location = node->selection;
        const auto placement = position_by_node_.find(*node_id);
        if (node->block && placement != position_by_node_.end()) {
            const auto rows = instruction_rows(*node, placements_[placement->second].bounds);
            if (point.y >= rows.y && point.y < rows.y + static_cast<int>(rows.count) * rows.line) {
                const auto row = rows.first + static_cast<std::size_t>((point.y - rows.y) / rows.line);
                if (row < node->block->instructions.size())
                    location = node->block->instructions[row]->instruction.address;
            }
        }
        is_node = true;
        if (location) {
            follow_id = append("Go to node location");
            copy_location_id = append("Copy location");
            const bool can_rename = std::holds_alternative<Address>(*location) && action_available(GraphContextAction::rename);
            const bool can_comment = action_available(GraphContextAction::comment);
            const bool can_bookmark = action_available(GraphContextAction::bookmark);
            if (can_rename || can_comment || can_bookmark) menu.AppendSeparator();
            if (can_rename) rename_id = append("Rename...");
            if (can_comment) comment_id = append("Comment...");
            if (can_bookmark) bookmark_id = append("Toggle bookmark...");
        }
    } else {
        const auto edge_id = std::get<GraphEdgeId>(*selected);
        const auto found = edges_.find(edge_id);
        if (found == edges_.end()) return;
        const auto *edge = found->second;
        menu.SetLabel(copy_label_id, "Copy edge description");
        const auto source = nodes_.find(edge->source), target = nodes_.find(edge->target);
        label = wxString::FromUTF8(edge_name(edge->kind));
        if (source != nodes_.end() && target != nodes_.end())
            label += " -> " + preview_text(source->second->label, 64) + " -> " + preview_text(target->second->label, 64);
        location = edge->target_location;
        if (!location && target != nodes_.end()) location = target->second->selection;
        if (!location) location = edge->selection;
        if (location) {
            follow_edge_id = append("Follow edge target");
            copy_location_id = append("Copy target location");
            const bool can_comment = action_available(GraphContextAction::comment);
            const bool can_bookmark = action_available(GraphContextAction::bookmark);
            if (can_comment || can_bookmark) menu.AppendSeparator();
            if (can_comment) comment_id = append("Comment...");
            if (can_bookmark) bookmark_id = append("Toggle bookmark...");
        }
    }

    const auto command = GetPopupMenuSelectionFromUser(menu, point);
    if (command == wxID_NONE) return;
    if (command == copy_label_id) {
        if (wxTheClipboard && wxTheClipboard->Open()) {
            wxTheClipboard->SetData(new wxTextDataObject(label));
            wxTheClipboard->Close();
        }
    } else if (command == copy_location_id && location) {
        if (wxTheClipboard && wxTheClipboard->Open()) {
            wxTheClipboard->SetData(new wxTextDataObject(location_text(*location)));
            wxTheClipboard->Close();
        }
    } else if (command == follow_id && is_node) {
        if (location && navigate) (void)navigate(*location);
    } else if (command == follow_edge_id && !is_node) {
        follow_edge(std::get<GraphEdgeId>(*selected), true);
    } else if (location && context_action) {
        if (command == rename_id) context_action(*location, GraphContextAction::rename);
        else if (command == comment_id) context_action(*location, GraphContextAction::comment);
        else if (command == bookmark_id) context_action(*location, GraphContextAction::bookmark);
    }
}
void GraphCanvas::paint(wxPaintEvent &) {
    wxAutoBufferedPaintDC dc(this);
    dc.SetBackground(wxBrush(wxColour(245, 247, 250)));
    dc.Clear();
    if (!graph_) {
        dc.DrawText("No current graph. Select a recovered function.", 16, 16);
        return;
    }
    for (const auto route_index : indexed_candidates(routes_by_x_, viewport())) {
        auto &route = routes_[route_index];
        if (route.points.size() < 2)
            continue;
        auto edge = edges_.at(route.edge);
        bool selected = hit_ && *hit_ == GraphHit{edge->id};
        auto ink = color(edge->kind);
        dc.SetPen(wxPen(ink, selected ? 3 : 1, edge->boundary ? wxPENSTYLE_SHORT_DASH : wxPENSTYLE_SOLID));
        for (std::size_t point_index = 1; point_index < route.points.size(); ++point_index)
            dc.DrawLine(to_client(route.points[point_index - 1]), to_client(route.points[point_index]));
        auto end = to_client(route.points.back()), prior = to_client(route.points[route.points.size() - 2]);
        auto angle = std::atan2(double(end.y - prior.y), double(end.x - prior.x));
        wxPoint arrow[] = {end,
                           {end.x - pixel(8 * std::cos(angle - .45)), end.y - pixel(8 * std::sin(angle - .45))},
                           {end.x - pixel(8 * std::cos(angle + .45)), end.y - pixel(8 * std::sin(angle + .45))}};
        dc.SetBrush(wxBrush(ink));
        dc.DrawPolygon(3, arrow);
    }
    auto font = wxSystemSettings::GetFont(wxSYS_ANSI_FIXED_FONT);
    font.SetPointSize(std::clamp(pixel(9 * scale_), 6, 24));
    dc.SetFont(font);
    for (const auto position_index : indexed_candidates(positions_by_x_, viewport())) {
        auto &placement = placements_[position_index];
        auto node = nodes_.at(placement.node);
        auto b = placement.bounds;
        auto top = to_client({b.x, b.y}), bottom = to_client({b.x + b.width, b.y + b.height});
        wxRect box(top, bottom);
        const auto selected_instruction = instruction_index(*node);
        bool selected = selected_nodes_.contains(node->id) || (selection_ && node->selection == selection_) || selected_instruction ||
                        (hit_ && *hit_ == GraphHit{node->id});
        dc.SetPen(wxPen(selected ? wxColour(30, 95, 170) : wxColour(130, 145, 165), selected ? 2 : 1));
        dc.SetBrush(wxBrush(node->kind == GraphNodeKind::unresolved ? wxColour(255, 243, 216)
                            : selected                              ? wxColour(220, 237, 255)
                                                                    : *wxWHITE));
        dc.DrawRoundedRectangle(box, 4);
        dc.SetClippingRegion(box.Deflate(4));
        int x = box.x + 4, y = box.y + 2;
        const auto rows = instruction_rows(*node, placement.bounds);
        auto label = preview_text(node->label, 160);
        if (node->block && rows.count < node->block->instructions.size())
            label += wxString::Format(" [%zu-%zu/%zu]", rows.first + 1, rows.first + rows.count,
                                      node->block->instructions.size());
        dc.DrawText(label, x, y);
        y = rows.y;
        if (node->block) {
            for (std::size_t row = rows.first; row < rows.first + rows.count; ++row) {
                const auto &fact = node->block->instructions[row];
                if (selected_instruction == row) {
                    dc.SetPen(*wxTRANSPARENT_PEN);
                    dc.SetBrush(wxBrush(wxColour(185, 215, 248)));
                    dc.DrawRectangle(box.x, y, box.width, rows.line);
                }
                dc.DrawText(location_text(fact->instruction.address) + "  " + text(format_instruction(fact->instruction)), x, y);
                y += rows.line;
            }
        }
        if (!node->comment.empty() && y + rows.line <= box.GetBottom())
            dc.DrawText("; " + preview_text(node->comment, 160), x, y);
        dc.DestroyClippingRegion();
    }
}
} // namespace hexlab::desktop
