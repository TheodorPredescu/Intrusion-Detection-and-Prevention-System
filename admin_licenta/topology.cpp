#include "topology.h"
#include "utils.h"

void Topology::draw(const double &current_time) {
    if (topology_reset || current_time >= previous_time + REFRESH_INTERVAL) {
        if (topology_reset) {
            topology_reset = false;
        }

        previous_time = current_time;
        pc_map = get_pc_info();
        topology_data_map = get_topology();
        node_positions.clear();

        std::map<std::string, int> allowed_connections;
    }

    if (!pc_map || topology_data_map.empty()) {
        return;
    }

    // TODO: I should filter the ones from topology that are found in the pc_map.allowed_file and then color
    // distinguish them First key is the tracked ip, second one is the connected ip, and the set is all the ports
    // allowed.
    std::map<std::string, std::map<std::string, std::set<int>>> allowed_ips_map;
    for (const auto &[pc_id, pc_info] : *pc_map) {
        allowed_ips_map.insert({pc_id, extract_allowed_ips(pc_info.allowed_file)});
    }

    // Build IP to PC mapping
    std::map<std::string, std::string> ip_to_pc_id;
    for (const auto &[pc_id, entry] : topology_data_map) {
        for (const auto &ip : entry.topology_ip) {
            ip_to_pc_id[ip] = pc_id;
        }
    }

    // Build connections from topology data
    std::set<std::string> all_nodes;
    std::map<std::string, std::set<std::string>> connections;

    for (const auto &[receiver_pc_id, entry] : topology_data_map) {
        all_nodes.insert(receiver_pc_id);

        // For each source IP that connected to this PC
        for (const auto &[src_ip, stats] : entry.connection_dict) {

            // If the source ip is found in the list of ips of the tracked pc, skip it.
            if (entry.topology_ip.find(src_ip) != entry.topology_ip.end()) {
                continue;
            }

            // Map src_ip to pc_id or keep as external IP
            const std::string sender = ip_to_pc_id.find(src_ip) != ip_to_pc_id.end() ? ip_to_pc_id[src_ip] : src_ip;
            all_nodes.insert(sender);

            connections[sender].insert(receiver_pc_id);
        }
    }

    if (node_positions.empty()) {
        node_positions = compute_graph_layout(all_nodes, connections);

        // Normalize to fit canvas
        float min_x = FLT_MAX, min_y = FLT_MAX;
        float max_x = -FLT_MAX, max_y = -FLT_MAX;
        for (const auto &[key, pos] : node_positions) {
            min_x = std::min(min_x, pos.x);
            min_y = std::min(min_y, pos.y);
            max_x = std::max(max_x, pos.x);
            max_y = std::max(max_y, pos.y);
        }

        const float range_x = max_x - min_x;
        const float range_y = max_y - min_y;
        const float target_spread = 600.0f;

        for (auto &[key, pos] : node_positions) {
            pos.x = range_x > 0 ? ((pos.x - min_x) / range_x) * target_spread : 0;
            pos.y = range_y > 0 ? ((pos.y - min_y) / range_y) * target_spread : 0;
        }
    }

    ImGui::BeginChild("canvas", ImVec2(0, 0), true);
    ImDrawList *dl = ImGui::GetWindowDrawList();
    ImVec2 canvas_pos = ImGui::GetCursorScreenPos();
    ImVec2 canvas_size = ImGui::GetContentRegionAvail();
    ImVec2 mouse = ImGui::GetMousePos();

    if (ImGui::IsWindowHovered()) {
        calculate_zoom_and_drag();
    }

    // Background
    dl->AddRectFilled(canvas_pos, ImVec2(canvas_pos.x + canvas_size.x, canvas_pos.y + canvas_size.y),
                      IM_COL32(30, 30, 40, 255));

    const float NODE_WIDTH = 150;
    const float NODE_HEIGHT = 80;
    const float PIN_RADIUS = 5;

    std::map<std::string, ImVec2> pin_positions;
    static int selected_node = -1;

    // Draw nodes
    for (const auto &node_ip : all_nodes) {
        bool is_pc = pc_map->find(node_ip) != pc_map->end();
        const PCInfo &pc = is_pc ? pc_map->at(node_ip) : PCInfo{};

        ImVec2 screen_node_pos = to_screen(node_positions[node_ip]);
        ImVec2 node_pos = ImVec2(screen_node_pos.x + canvas_pos.x, screen_node_pos.y + canvas_pos.y);
        ImVec2 node_size(NODE_WIDTH * topology_zoom, NODE_HEIGHT * topology_zoom);

        ImU32 node_color = is_pc ? IM_COL32(80, 150, 255, 255) : IM_COL32(255, 100, 100, 255);
        dl->AddRectFilled(node_pos, ImVec2(node_pos.x + node_size.x, node_pos.y + node_size.y), node_color, 8.0f);
        dl->AddRect(node_pos, ImVec2(node_pos.x + node_size.x, node_pos.y + node_size.y), IM_COL32(255, 255, 255, 200),
                    8.0f, 0, 2.0f);

        // std::string node_text = is_pc ? (pc.name.empty() ? pc.pc_id : pc.name) : node_key;
        // ImVec2 text_size = ImGui::CalcTextSize(node_text.c_str());
        // ImVec2 text_pos =
        //     ImVec2(node_pos.x + node_size.x / 2 - text_size.x / 2, node_pos.y + node_size.y / 2 - text_size.y /
        //     2);
        // dl->AddText(text_pos, IM_COL32_WHITE, node_text.c_str());
        // ____
        std::string node_text = is_pc ? (pc.name.empty() ? pc.pc_id : pc.name) : node_ip;
        const float font_size = ImGui::GetFontSize() * topology_zoom * 1.3f;
        const float font_scale = font_size / ImGui::GetFontSize();
        ImVec2 text_size = ImGui::CalcTextSize(node_text.c_str());
        text_size.x *= font_scale;
        text_size.y *= font_scale;
        ImVec2 text_pos =
            ImVec2(node_pos.x + node_size.x / 2 - text_size.x / 2, node_pos.y + node_size.y / 2 - text_size.y / 2);
        dl->AddText(ImGui::GetFont(), font_size, text_pos, IM_COL32_WHITE, node_text.c_str());
        // ____

        auto get_closest_edge = [](ImVec2 from_center, ImVec2 to_center, float width,
                                   float height) -> std::pair<ImVec2, std::string> {
            ImVec2 edges[4] = {
                ImVec2(from_center.x - width / 2, from_center.y), ImVec2(from_center.x + width / 2, from_center.y),
                ImVec2(from_center.x, from_center.y - height / 2), ImVec2(from_center.x, from_center.y + height / 2)};
            std::string names[4] = {"left", "right", "top", "bottom"};
            float min_dist = FLT_MAX;
            int closest = 0;
            for (int i = 0; i < 4; i++) {
                float dx = edges[i].x - to_center.x;
                float dy = edges[i].y - to_center.y;
                float dist = dx * dx + dy * dy;
                if (dist < min_dist) {
                    min_dist = dist;
                    closest = i;
                }
            }
            return {edges[closest], names[closest]};
        };

        ImVec2 node_center = ImVec2(node_pos.x + node_size.x / 2, node_pos.y + node_size.y / 2);

        int input_idx = 0;
        for (const auto &[src, dests] : connections) {
            if (dests.count(node_ip)) {
                ImVec2 src_screen = to_screen(node_positions[src]);
                ImVec2 src_center = ImVec2(src_screen.x + canvas_pos.x + NODE_WIDTH * topology_zoom / 2,
                                           src_screen.y + canvas_pos.y + NODE_HEIGHT * topology_zoom / 2);
                auto [pin_pos, edge] = get_closest_edge(node_center, src_center, node_size.x, node_size.y);
                dl->AddCircleFilled(pin_pos, PIN_RADIUS, IM_COL32(150, 200, 255, 255));
                pin_positions[node_ip + "_in_" + std::to_string(input_idx)] = pin_pos;
                input_idx++;
            }
        }

        if (connections.find(node_ip) != connections.end()) {
            int output_idx = 0;
            for (const auto &dst : connections[node_ip]) {
                ImVec2 dst_screen = to_screen(node_positions[dst]);
                ImVec2 dst_center = ImVec2(dst_screen.x + canvas_pos.x + NODE_WIDTH * topology_zoom / 2,
                                           dst_screen.y + canvas_pos.y + NODE_HEIGHT * topology_zoom / 2);
                auto [pin_pos, edge] = get_closest_edge(node_center, dst_center, node_size.x, node_size.y);
                dl->AddCircleFilled(pin_pos, PIN_RADIUS, IM_COL32(255, 200, 150, 255));
                pin_positions[node_ip + "_out_" + std::to_string(output_idx)] = pin_pos;
                output_idx++;
            }
        }

        bool hovered = mouse.x >= node_pos.x && mouse.x <= node_pos.x + node_size.x && mouse.y >= node_pos.y &&
                       mouse.y <= node_pos.y + node_size.y;
        if (hovered) {
            ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
            if (ImGui::IsMouseClicked(ImGuiMouseButton_Right)) {
                selected_node = std::hash<std::string>{}(node_ip);
                ImGui::OpenPopup("topology_menu");
            }
        }
    }

    // Draw links
    for (const auto &[src, dst_set] : connections) {
        int out_idx = 0;
        for (const auto &dst : dst_set) {
            const auto it_src = pin_positions.find(src + "_out_" + std::to_string(out_idx));
            int in_idx = 0;
            for (const auto &[s, dests] : connections) {
                if (dests.count(dst) && s == src) {
                    break;
                }
                if (dests.count(dst)) {
                    in_idx++;
                }
            }
            auto it_dst = pin_positions.find(dst + "_in_" + std::to_string(in_idx));
            if (it_src != pin_positions.end() && it_dst != pin_positions.end()) {
                const ImVec2 src_pin = it_src->second;
                const ImVec2 dst_pin = it_dst->second;

                // Node centers
                const ImVec2 src_to_screen = to_screen(node_positions[src]);
                const ImVec2 dst_to_screen = to_screen(node_positions[dst]);

                const ImVec2 src_node_pos = ImVec2(src_to_screen.x + canvas_pos.x, src_to_screen.y + canvas_pos.y);
                const ImVec2 dst_node_pos = ImVec2(dst_to_screen.x + canvas_pos.x, dst_to_screen.y + canvas_pos.y);

                const float src_node_center_x = src_node_pos.x + NODE_WIDTH * topology_zoom / 2;
                const float src_node_center_y = src_node_pos.y + NODE_HEIGHT * topology_zoom / 2;
                const float dst_node_center_x = dst_node_pos.x + NODE_WIDTH * topology_zoom / 2;
                const float dst_node_center_y = dst_node_pos.y + NODE_HEIGHT * topology_zoom / 2;

                // Offsets based on left/right and top/bottom
                float src_offset_x = 0;
                float src_offset_y = 0;

                if (src_pin.x < src_node_center_x) {
                    src_offset_x = -50.0f;
                } else if (src_pin.x > src_node_center_x) {
                    src_offset_x = 50.0f;
                }

                if (src_pin.y < src_node_center_y) {
                    src_offset_y = -50.0f;
                } else if (src_pin.y > src_node_center_y) {
                    src_offset_y = 50.0f;
                }

                float dst_offset_x = 0;
                float dst_offset_y = 0;

                if (dst_pin.x < dst_node_center_x) {
                    dst_offset_x = -50.0f;
                } else if (dst_pin.x > dst_node_center_x) {
                    dst_offset_x = 50.0f;
                }

                if (dst_pin.y < dst_node_center_y) {
                    dst_offset_y = -50.0f;
                } else if (dst_pin.y > dst_node_center_y) {
                    dst_offset_y = 50.0f;
                }

                dl->AddBezierCubic(src_pin, ImVec2(src_pin.x + src_offset_x, src_pin.y + src_offset_y),
                                   ImVec2(dst_pin.x + dst_offset_x, dst_pin.y + dst_offset_y), dst_pin,
                                   IM_COL32(100, 200, 255, 255), 2.0f);
            }
            out_idx++;
        }
    }

    // Hover detection (same as before)
    std::string hovered_node;
    for (const auto &node_key : all_nodes) {
        const ImVec2 screen_node_pos = to_screen(node_positions[node_key]);
        const ImVec2 node_pos = ImVec2(screen_node_pos.x + canvas_pos.x, screen_node_pos.y + canvas_pos.y);
        const ImVec2 node_size(NODE_WIDTH * topology_zoom, NODE_HEIGHT * topology_zoom);
        const bool hovered = mouse.x >= node_pos.x && mouse.x <= node_pos.x + node_size.x && mouse.y >= node_pos.y &&
                             mouse.y <= node_pos.y + node_size.y;
        if (hovered) {
            hovered_node = node_key;
            ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
            dl->AddRect(node_pos, ImVec2(node_pos.x + node_size.x, node_pos.y + node_size.y),
                        IM_COL32(255, 255, 100, 255), 8.0f, 0, 3.0f);
            break;
        }
    }

    // Hover message
    if (!hovered_node.empty()) {
        const bool is_pc = pc_map->find(hovered_node) != pc_map->end();
        const PCInfo &pc = is_pc ? pc_map->at(hovered_node) : PCInfo{};

        ImGui::SetNextWindowSizeConstraints(ImVec2(150, 0), ImVec2(400, 500));
        ImGui::BeginTooltip();

        if (is_pc) {
            ImGui::TextColored(ImVec4(0.4f, 0.8f, 0.4f, 1.0f), "ID: %s", hovered_node.c_str());
            ImGui::Text("Name: %s", pc.name.empty() ? pc.pc_id.c_str() : pc.name.c_str());
            ImGui::Text("Mode: %s", MODES[pc.current_mode]);

            // Show all topology IPs for this PC
            if (topology_data_map.find(hovered_node) != topology_data_map.end()) {
                const auto &entry = topology_data_map.at(hovered_node);
                if (!entry.topology_ip.empty()) {
                    ImGui::Separator();
                    ImGui::TextColored(ImVec4(1.0f, 1.0f, 0.0f, 1.0f), "IPs:");
                    for (const auto &ip : entry.topology_ip) {
                        ImGui::BulletText("%s", ip.c_str());
                    }
                }
            }
        } else {
            ImGui::TextColored(ImVec4(1.0f, 0.4f, 0.4f, 1.0f), "External IP: %s", hovered_node.c_str());

            // Find which PC(s) received from this external IP
            for (const auto &[pc_id, entry] : topology_data_map) {
                if (entry.connection_dict.find(hovered_node) != entry.connection_dict.end()) {
                    const auto &stats = entry.connection_dict.at(hovered_node);

                    ImGui::Separator();
                    ImGui::TextColored(ImVec4(0.4f, 0.8f, 0.4f, 1.0f), "To: %s", pc_id.c_str());

                    // Ports Out
                    if (!stats.ports_out.empty()) {
                        std::string ports_str = "Ports Out: ";
                        for (int port : stats.ports_out) {
                            ports_str += std::to_string(port) + ", ";
                        }
                        ports_str.pop_back();
                        ports_str.pop_back();
                        ImGui::TextWrapped("%s", ports_str.c_str());
                    }

                    // Ports In
                    if (!stats.ports_in.empty()) {
                        std::string ports_str;
                        if (stats.ports_in.size() == 1) {
                            ports_str = "To port: ";
                        } else {
                            ports_str = "To ports: ";
                        }
                        for (int port : stats.ports_in) {
                            ports_str += std::to_string(port) + ", ";
                        }
                        ports_str.pop_back();
                        ports_str.pop_back();
                        ImGui::TextWrapped("%s", ports_str.c_str());
                    }

                    // Protocols
                    if (!stats.protocols.empty()) {
                        std::string proto_str = "Protocols: ";
                        for (int proto : stats.protocols) {
                            proto_str += get_protocol_name(proto) + ", ";
                        }
                        proto_str.pop_back();
                        proto_str.pop_back();
                        ImGui::TextWrapped("%s", proto_str.c_str());
                    }

                    // MAC addresses
                    if (!stats.mac_addr.empty()) {
                        ImGui::TextColored(ImVec4(1.0f, 0.8f, 0.4f, 1.0f), "MAC Addresses:");
                        for (const auto &mac : stats.mac_addr) {
                            ImGui::BulletText("%s", mac.c_str());
                        }
                    }
                }
            }
        }

        ImGui::EndTooltip();
    }

    // Context menu (same as before)
    if (ImGui::BeginPopup("topology_menu")) {
        std::string selected_key;
        for (const auto &key : all_nodes) {
            if ((int)std::hash<std::string>{}(key) == selected_node) {
                selected_key = key;
                break;
            }
        }
        const bool is_pc = pc_map->find(selected_key) != pc_map->end();
        if (ImGui::MenuItem("View Info")) {
            printf("Info: %s\n", selected_key.c_str());
        }
        if (is_pc && ImGui::MenuItem("Edit Config")) {
            pc_id_selected = selected_key;
            page = Page::ClientDetail;
        }
        if (!is_pc && ImGui::MenuItem("Block IP")) {
            printf("Blocking %s\n", selected_key.c_str());
        }
        ImGui::EndPopup();
    }

    ImGui::EndChild();
}
