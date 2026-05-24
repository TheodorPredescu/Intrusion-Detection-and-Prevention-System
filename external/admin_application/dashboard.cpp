#include "dashboard.h"
#include "imgui/imgui.h"
#include "utils.h"
#include <cmath>
#include <iostream>

void Dashboard::refresh_data() {

    pc_map = get_pc_info();
    msg_history_vector = get_message_history("", pc_map);

    if (training_activate) {
        training_topology_map = std::make_unique<std::map<std::string, TopologyEntry>>(get_topology());
    }
}

void Dashboard::ui_train_component() {
    ImGui::SameLine();
    if (ImGui::Button(training_activate ? "Stop Training" : "Train")) {
        training_activate = !training_activate;

        if (training_activate) {
            training_pc_mode_before.clear();

            // Change the profile of all the pcs to MONITORING and save the initial modes for later restauration.
            for (const auto &[pc_id, pc_info] : *pc_map) {
                const std::string monitoring_config = config_change_state(pc_info.config_file, MONITORING);

                if (monitoring_config.empty()) {
                    printf("Something went wrong for the user %s;\n config file: '%s'\n", pc_id.c_str(),
                           pc_info.config_file.c_str());
                    continue;
                }

                training_pc_mode_before.insert({pc_id, pc_info.current_mode});
                send_config_via_api(pc_id, monitoring_config);
            }
        } else {

            std::map<std::string, std::set<int>> training_allowed_new_elements;

            // Save all the new connections `to be added` in a more friendly format.
            if (training_topology_map) {
                for (const auto &[_, pc_topology_info] : *training_topology_map) {
                    for (const auto &[src_ip, src_info] : pc_topology_info.connection_dict) {

                        for (const int port : src_info.ports_out) {
                            training_allowed_new_elements[src_ip].insert(port);
                        }
                    }
                }
            }

            // Add all the new allowed definitions into the allowed file for each element and change back the mode
            // to its original state.
            for (const auto &[pc_id, pc_info] : *pc_map) {
                const auto it = training_pc_mode_before.find(pc_id);

                if (it == training_pc_mode_before.end()) {
                    continue;
                }

                const std::string original_config = config_change_state(pc_info.config_file, it->second);
                const std::string new_allowed_file =
                    merge_allowed_with_ports_map(pc_info.allowed_file, training_allowed_new_elements);

                // Set all the information to all the pcs.
                printf("[TRAINING] new allowed file: '%s'\n[TRAINING] Old one: '%s'\n", new_allowed_file.c_str(),
                       pc_info.allowed_file.c_str());
                send_config_via_api(pc_id, original_config, new_allowed_file);
            }
        }
    }

    ImGui::Spacing();
    ImGui::Separator();
}

void Dashboard::draw_pc(const PCInfo &pc, const bool blink_visible) {
    ImGui::BeginGroup();

    // Client card background
    ImVec2 card_pos = ImGui::GetCursorScreenPos();
    ImVec2 card_size(500, 55);

    ImDrawList *dl = ImGui::GetWindowDrawList();
    dl->AddRectFilled(card_pos, ImVec2(card_pos.x + card_size.x, card_pos.y + card_size.y),
                      get_mode_background_color(pc.current_mode, blink_visible), 8.0f);
    dl->AddRect(card_pos, ImVec2(card_pos.x + card_size.x, card_pos.y + card_size.y), IM_COL32(150, 150, 150, 150),
                8.0f, 0, 2.0f);

    // Vertical padding
    ImGui::Dummy(ImVec2(0, 4));

    // I move to the next line
    ImGui::Dummy(ImVec2(6, 0));
    // Put content on the same line, so it starts from 10
    ImGui::SameLine();

    // Icon on the left
    if (pc.icon_texture_id != 0) {
        ImGui::Image((void *)(intptr_t)pc.icon_texture_id, ImVec2(38, 38), ImVec2(0, 0), ImVec2(1, 1),
                     ImVec4(1, 1, 1, 1), ImVec4(0.7f, 0.7f, 0.7f, 1.0f));
        ImGui::SameLine(65);
    } else {
        ImGui::SameLine(65);
    }

    // PC info to the right of icon
    ImGui::BeginGroup();
    if (!pc.name.empty()) {
        ImGui::Text("PC name: %s", pc.name.c_str());
    } else {
        ImGui::Text("PC ID: %s", pc.pc_id.c_str());
    }
    ImGui::TextDisabled("Updated: %s", pc.updated_at.c_str());
    ImGui::EndGroup();

    // Mode on the far right
    ImGui::SameLine(380);
    ImGui::PushStyleColor(ImGuiCol_Text, get_mode_color(pc.current_mode));
    ImGui::Text("Mode: %s", get_mode_name(pc.current_mode));
    ImGui::PopStyleColor();

    ImGui::Dummy(ImVec2(card_size.x, 0));
    ImGui::EndGroup();

    // Make the card clickable
    if (ImGui::IsItemHovered()) {
        ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
        if (ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
            pc_id_selected = pc.pc_id;
            page = Page::ClientDetail;
        } else if (ImGui::IsMouseClicked(ImGuiMouseButton_Right)) {
            // pc_context_menu_selected = &pc;
            pc_context_menu_id_selected = pc.pc_id;
            ImGui::OpenPopup("pc_context_menu");
        }
    }

    ImGui::Spacing();
    ImGui::Spacing();
}

void Dashboard::draw(const double &current_time) {
    // Blinking effect state
    blink_time += ImGui::GetIO().DeltaTime;
    const bool blink_visible = fmod(blink_time, 1.0f) < 0.5f;

    // __________________ REFRESH __________________
    if (current_time >= previous_time + REFRESH_INTERVAL) {
        std::cout << previous_time << ", " << current_time << std::endl;
        previous_time = current_time;
        refresh_data();
    }

    if (!pc_map || !msg_history_vector) {
        return;
    }

    ImGui::Text("Network Monitoring System");
    ImGui::Separator();
    ImGui::Spacing();

    ui_train_component();

    // Clients section
    ImGui::Text("Connected Clients");
    ImGui::Spacing();

    ImGui::BeginChild("clients_list", ImVec2(0, -200), true);

    // Get clients from your data structure
    for (const auto &[_, pc] : *pc_map) {
        draw_pc(pc, blink_visible);
    }

    // Popup on right click on a pc component.
    if (ImGui::BeginPopup("pc_context_menu")) {
        const PCInfo *ctx_pc = nullptr;
        if (!pc_context_menu_id_selected.empty()) {
            auto it = pc_map->find(pc_context_menu_id_selected);
            if (it != pc_map->end()) {
                ctx_pc = &it->second;
            }
        }

        if (ctx_pc) {

            ImGui::Text("PC: %s", ctx_pc->pc_id.c_str());
            ImGui::Separator();

            // if (ImGui::MenuItem("View Details")) {
            //     pc_id_selected = pc_context_menu_selected->pc_id;
            //     page = Page::ClientDetail;
            //     ImGui::CloseCurrentPopup();
            // }
            if (ImGui::MenuItem("Edit Config")) {
                pc_id_selected = ctx_pc->pc_id;
                page = Page::ClientDetail;
                ImGui::CloseCurrentPopup();
            }
            // ImGui::Separator();
            // if (ImGui::MenuItem("Restart")) {
            //     std::cout << "Restart " << ctx_pc->pc_id << "\n";
            //     ImGui::CloseCurrentPopup();
            // }
            // if (ImGui::MenuItem("Delete")) {
            //     std::cout << "Delete " << ctx_pc->pc_id << "\n";
            //     ImGui::CloseCurrentPopup();
            // }
        }

        ImGui::EndPopup();

        // Popup is open this frame
        is_context_menu_opened = true;
    } else if (is_context_menu_opened) {
        // pc_context_menu_selected = nullptr;
        pc_context_menu_id_selected.clear();
        is_context_menu_opened = false;
    }

    ImGui::EndChild();

    // Message history section
    ImGui::Separator();
    ImGui::Text("Recent Events (Last 20 logs)");

    ImGui::BeginChild("message_history", ImVec2(0, 0), true);

    for (const MessageReceived &msg : *msg_history_vector) {
        ImGui::PushStyleColor(ImGuiCol_Text, get_mode_color(msg.mode));
        ImGui::TextWrapped("%s", transform_messages_to_str(msg, pc_map).c_str());
        ImGui::PopStyleColor();
        ImGui::Separator();
    }

    ImGui::EndChild();
}
