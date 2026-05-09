#include "types.h"
#include "utils.h"
#include <memory>
#include <vector>

#include "host_detail.h"
#include <iostream>
#include <sstream>

#include "../../daemon/json.hpp"
using json = nlohmann::json;

void HostDetail::reset_config_modifications() {
    changed_config_server_port = "";
    changed_config_server_ip = "";
    changed_config_mode = NO_STATE;
    changed_config_allowed_file_path = "";
    changed_config_checker = false;
}

void HostDetail::reset_allowed_modifications() {
    changed_allowed_file.clear();
    changed_allowed_file_checker = false;
}

void HostDetail::reset_general_user_info() {
    changed_general_name_given = "";
    changed_general_checker = false;
}

void HostDetail::reset_modifications() {
    reset_config_modifications();
    reset_allowed_modifications();
    reset_general_user_info();
}

std::string HostDetail::create_config_info_string() {
    if (!changed_config_checker) {
        return "";
    }

    char buffer[2048];
    snprintf(buffer, sizeof(buffer), "server IP %s\nserver port %s\n%s\nallowed_file %s\n",
             changed_config_server_ip.c_str(), changed_config_server_port.c_str(), MODES[changed_config_mode],
             changed_config_allowed_file_path.c_str());

    return std::string(buffer);
}

void HostDetail::update_new_frame(const bool force_update) {
    last_pc_id = pc_id_selected;

    if (force_update) {
        // Reset all the 'changed_' variables.
        reset_modifications();
        changed_config_mode = pc_selected_data.current_mode;

        printf("Reseted the pc_selected_data\n");
    }

    msg_history_vector = get_message_history(pc_id_selected);

    std::string pcs_response;

    if (fetch_pc_config_from_api(pc_id_selected, pcs_response)) {
        try {
            // Parse JSON response
            auto config_json = json::parse(pcs_response);

            if (config_json.is_object()) {

                // Extract fields from JSON
                const std::string update_time = config_json.value("updated_at", "N/A");
                const bool update_time_changed = update_time != pc_selected_data.updated_at;

                // Config file
                if (force_update || update_time_changed) {

                    pc_selected_data.pc_id = config_json.value("pc_id", "");
                    pc_selected_data.updated_at = update_time;
                    pc_selected_data.allowed_file = config_json.value("allowed_file", "");
                    pc_selected_data.name = config_json.value("name", "");
                    pc_selected_data.config_file = config_json.value("config_file", "");

                    // General information
                    changed_general_name_given = pc_selected_data.name;
                    strncpy(name_given_buf, pc_selected_data.name.c_str(), sizeof(name_given_buf) - 1);

                    // Config file
                    extract_config_info(pc_selected_data.config_file, changed_config_server_ip,
                                        changed_config_server_port, changed_config_allowed_file_path);

                    strncpy(server_ip_buf, changed_config_server_ip.c_str(), sizeof(server_ip_buf) - 1);
                    strncpy(allowed_file_path_buf, changed_config_allowed_file_path.c_str(),
                            sizeof(allowed_file_path_buf) - 1);
                    strncpy(server_port_buf, changed_config_server_port.c_str(), sizeof(server_port_buf) - 1);

                    printf("changed to:\nserver ip:%s, server port:%s;\nallowed_path:%s\n",
                           changed_config_server_ip.c_str(), changed_config_server_port.c_str(),
                           changed_config_allowed_file_path.c_str());

                    // Current mode extracted from received config file
                    const int received_current_mode = extract_current_state(pc_selected_data.config_file);

                    printf("Received mode: %d\n", received_current_mode);
                    if (pc_selected_data.current_mode != received_current_mode) {

                        pc_selected_data.current_mode = received_current_mode;
                        changed_config_mode = received_current_mode;
                    }

                    // Icon update
                    std::string icon_bytes_encoded = config_json.value("icon", "");

                    if (pc_selected_data.icon_texture_id != 0) {
                        glDeleteTextures(1, &pc_selected_data.icon_texture_id);
                    }
                    if (selected_icon_texture_id != 0 && selected_icon_texture_id != pc_selected_data.icon_texture_id) {
                        glDeleteTextures(1, &pc_selected_data.icon_texture_id);
                    }

                    if (!icon_bytes_encoded.empty()) {
                        std::vector<uint8_t> icon_bytes = base64_decode(icon_bytes_encoded);
                        pc_selected_data.icon_texture_id = load_texture_from_memory(icon_bytes);
                        selected_icon_texture_id = pc_selected_data.icon_texture_id;
                    } else {
                        pc_selected_data.icon_texture_id = 0;
                        selected_icon_texture_id = 0;
                    }

                    icon_path_buf[0] = '\0';
                    icon_path_buf_tmp[0] = '\0';
                    icon_path_final[0] = '\0';
                }

            } else {
                printf("I did not received an object\n\n");
            }
        } catch (const std::exception &e) {
            std::cerr << "JSON parse error in fetching pcs: " << e.what() << "\n";

            pc_selected_data.pc_id = "";
            pc_selected_data.updated_at = "";
            pc_selected_data.config_file = "";
            pc_selected_data.allowed_file = "";
            pc_selected_data.current_mode = NO_STATE;
            pc_selected_data.name = "";
        }
    }

    if (!training_active_id.empty()) {
        msg_struct_info_map = std::make_unique<std::map<std::string, TopologyEntry>>(get_topology(pc_id_selected));
    }
}

int HostDetail::draw(const double &current_time) {

    if (pc_id_selected.empty()) {
        ImGui::Text("No PC selected");
        return -1;
    }

    bool update = false;
    if (request_update) {
        request_update = false;
        update = true;
    }

    if (pc_id_selected != last_pc_id) {
        update = true;
    }

    if (update || current_time >= previous_time + REFRESH_INTERVAL) {
        previous_time = current_time;
        update_new_frame(update);
    }

    if (pc_selected_data.pc_id.empty() || !msg_history_vector) {
        ImGui::TextDisabled("Failed to load the information about the user, retrying...");
        return -1;
    }

    // === HEADER SECTION ===
    ImGui::BeginGroup();

    // Icon group
    ImGui::BeginGroup();
    ImGui::Spacing();
    ImGui::Spacing();
    ImGui::Spacing();
    ImGui::SameLine(10);
    // Icon on the left
    if (selected_icon_texture_id != 0) {
        ImGui::Image((void *)(intptr_t)selected_icon_texture_id, ImVec2(80, 80), ImVec2(0, 0), ImVec2(1, 1),
                     ImVec4(1, 1, 1, 1), ImVec4(0.7f, 0.7f, 0.7f, 1.0f));
    }
    ImGui::EndGroup();

    // PC info on the right
    ImGui::SameLine(110);
    ImGui::BeginGroup();
    ImGui::Text("PC ID: %s", pc_selected_data.pc_id.c_str());

    ImGui::TextDisabled("Updated: %s", pc_selected_data.updated_at.c_str());

    ImGui::Spacing();
    ImGui::Text("name: ");
    ImGui::SameLine(80);
    ImGui::SetNextItemWidth(250);
    if (ImGui::InputText("##name_given", name_given_buf, sizeof(name_given_buf))) {
        changed_general_name_given = name_given_buf;
        changed_general_checker = true;
    }

    ImGui::BeginGroup();
    ImGui::Text("File Path:");
    ImGui::SameLine(80);
    ImGui::SetNextItemWidth(250);
    ImGui::InputText("##icon_path", icon_path_buf, sizeof(icon_path_buf));

    if (ImGui::Button("Load Image", ImVec2(100, 0))) {
        printf("Icon path: %s\n", icon_path_buf);
        const int selected_icon_texture_var = load_image_as_texture(icon_path_buf);
        if (selected_icon_texture_var != 0) {
            selected_icon_texture_id_tmp = selected_icon_texture_var;
            strncpy(icon_path_buf_tmp, icon_path_buf, sizeof(icon_path_buf) - 1);
            ImGui::OpenPopup("Icon Preview");
        }
    }

    ImGui::EndGroup();

    // Preview popup
    if (ImGui::BeginPopupModal("Icon Preview", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
        if (selected_icon_texture_id_tmp != 0) {
            ImGui::Image((void *)(intptr_t)selected_icon_texture_id_tmp, ImVec2(128, 128));
            ImGui::Spacing();
            if (ImGui::Button("Use This Icon", ImVec2(150, 0))) {
                if (pc_selected_data.icon_texture_id != 0) {
                    glDeleteTextures(1, &pc_selected_data.icon_texture_id);
                }

                if (selected_icon_texture_id != 0 && selected_icon_texture_id != pc_selected_data.icon_texture_id) {
                    glDeleteTextures(1, &selected_icon_texture_id);
                }

                pc_selected_data.icon_texture_id = selected_icon_texture_id_tmp;
                selected_icon_texture_id = selected_icon_texture_id_tmp;
                strncpy(icon_path_final, icon_path_buf_tmp, sizeof(icon_path_buf_tmp));
                changed_general_checker = true;
                ImGui::CloseCurrentPopup();
            }
            ImGui::SameLine();
            if (ImGui::Button("Cancel", ImVec2(150, 0))) {
                glDeleteTextures(1, &selected_icon_texture_id_tmp);
                ImGui::CloseCurrentPopup();
            }
        }
        ImGui::EndPopup();
    }
    // Ending pc info right side
    ImGui::EndGroup();

    // Ending pc info pannel
    ImGui::EndGroup();

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    // === DETAILS SECTION ===
    ImGui::Text("Configuration Details");

    // TODO: Rn I can only train one pc at a time. If I try to train a pc, go to another pc and try to train that
    // pc, the first pc will move to the old mode and close the training for it, leaving only one training session
    // active.
    //
    // Also if it fails, the training data will be lost.
    //
    // I need to not reset the topology connections when I change the mode. I need to save them and then filter
    // them/collor them differently
    if (ImGui::Button(training_active_id != pc_id_selected ? "Train" : "Stop Training")) {
        // Change the 'training_id' and reset the config when I activate 2 training sessions.
        if (training_active_id.empty()) {
            training_active_id = pc_id_selected;
        } else if (training_active_id == pc_id_selected) {
            training_active_id = "";
        } else {

            const int original_state = extract_current_state(config_before_training);
            if (original_state == NO_STATE) {
                return -1;
            }

            const std::string original_config = config_change_state(pc_selected_data.config_file, original_state);
            send_config_via_api(training_active_id, original_config);

            training_active_id = pc_id_selected;
            msg_struct_info_map = nullptr;

            printf("Reseted old training mode for user %s\n", training_active_id.c_str());
        }

        // Check and update the information in each case
        if (!training_active_id.empty()) {
            discard_allowed_changes = true;
            request_update = true;

            config_before_training = pc_selected_data.config_file;
            const std::string monitoring_config = config_change_state(pc_selected_data.config_file, MONITORING);

            if (monitoring_config.empty() || !send_config_via_api(pc_id_selected, monitoring_config)) {
                printf("Something went wrong for the user %s;\n config file: '%s'\n", pc_id_selected.c_str(),
                       pc_selected_data.config_file.c_str());
            }

        } else {
            std::string new_allwed_file = "";
            if (msg_struct_info_map && !pc_id_selected.empty()) {
                const auto entry = msg_struct_info_map->find(pc_id_selected);
                if (entry != msg_struct_info_map->end()) {
                    new_allwed_file = merge_allowed_with_topology(entry->second, allowed_lines);
                }
                msg_struct_info_map = nullptr;
            }

            const int original_state = extract_current_state(config_before_training);
            if (original_state != NO_STATE) {
                const std::string config_before_training =
                    config_change_state(pc_selected_data.config_file, original_state);

                printf("config: '%s'\nallowed file: '%s'\n", config_before_training.c_str(), new_allwed_file.c_str());
                send_config_via_api(pc_id_selected, config_before_training, new_allwed_file);
                request_update = true;
            }
        }
    }

    if (changed_config_checker || changed_general_checker || changed_allowed_file_checker) {
        ImGui::SameLine();
        if (ImGui::Button("Discard changes", ImVec2(130, 0))) {
            discard_allowed_changes = true;
            request_update = true;
        }
    }

    // A right side info text to tell if something is changed on the page
    if (changed_config_checker || changed_general_checker || changed_allowed_file_checker) {
        ImGui::SameLine(ImGui::GetWindowWidth() - 150);
        ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(255, 100, 100, 255));
        ImGui::Text("UNSAVED CHANGES");
        ImGui::PopStyleColor();
    }

    ImGui::BeginChild("details", ImVec2(0, 500), true);

    // Server IP
    ImGui::Text("Server IP:");
    ImGui::SameLine(150);
    ImGui::SetNextItemWidth(180);
    if (ImGui::InputText("##server_ip", server_ip_buf, sizeof(server_ip_buf))) {
        changed_config_server_ip = server_ip_buf;
        changed_config_checker = true;
    }
    ImGui::Spacing();

    // Server Port - use InputText instead to remove +/- buttons
    ImGui::Text("Server Port:");
    ImGui::SameLine(150);
    ImGui::SetNextItemWidth(180);
    if (ImGui::InputText("##server_port", server_port_buf, sizeof(server_port_buf), ImGuiInputTextFlags_CharsDecimal)) {
        try {
            const int server_port_int = std::stoi(server_port_buf);
            if (server_port_int > 0 && server_port_int <= 65535) {
                changed_config_server_port = std::to_string(server_port_int);
                changed_config_checker = true;
            } else {
                ImGui::OpenPopup("Invalid Port");
            }
        } catch (...) {
            ImGui::OpenPopup("Invalid Port");
        }
    }

    // Error popup
    if (ImGui::BeginPopupModal("Invalid Port", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::Text("Port must be between 1 and 65535!");
        if (ImGui::Button("OK", ImVec2(120, 0))) {
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
    }
    ImGui::Spacing();

    ImGui::Text("Mode:");
    ImGui::SameLine(150);
    ImGui::SetNextItemWidth(180);
    // Color only the preview text of the selected mode
    ImGui::PushStyleColor(ImGuiCol_Text, get_mode_color(changed_config_mode));
    bool combo_open = ImGui::BeginCombo("##mode_select", MODES[changed_config_mode]);
    ImGui::PopStyleColor();

    if (combo_open) {
        for (int i = 0; i < 4; i++) {
            bool is_selected = (changed_config_mode == i);

            // Only color the item that matches the current mode
            ImGui::PushStyleColor(ImGuiCol_Text, get_mode_color(i));

            if (ImGui::Selectable(MODES[i], is_selected)) {
                changed_config_mode = i;
                std::cout << "Mode changed to: " << MODES[i] << "\n";
                changed_config_checker = true;
            }

            ImGui::PopStyleColor();

            if (is_selected) {
                ImGui::SetItemDefaultFocus();
            }
        }
        ImGui::EndCombo();
    }

    ImGui::Spacing();

    // ============================= Allowed file =====================================
    ImGui::Text("Allowed File Path:");
    ImGui::SameLine(150);
    ImGui::SetNextItemWidth(250);
    if (ImGui::InputText("##allowed_file_path", allowed_file_path_buf, sizeof(allowed_file_path_buf))) {
        changed_config_allowed_file_path = allowed_file_path_buf;
        changed_config_checker = true;
    }

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    if (update || discard_allowed_changes) {
        allowed_lines.clear();
        changed_allowed_file_checker = false;
        discard_allowed_changes = false;

        std::istringstream iss(pc_selected_data.allowed_file);
        std::string line;

        while (std::getline(iss, line)) {
            line.erase(0, line.find_first_not_of(" \t\r\n"));
            line.erase(line.find_last_not_of(" \t\r\n") + 1);
            if (!line.empty()) {
                allowed_lines.push_back(line);
            }
        }
    }

    ImGui::BeginChild("allowed_list", ImVec2(0, 340), true);
    ImGui::AlignTextToFramePadding();
    ImGui::Text("Events definitions");

    ImGui::SameLine();
    if (ImGui::Button("Add New", ImVec2(100, 0))) {
        edit_idx = -1; // -1 means new entry
        memset(edit_line_buf, 0, sizeof(edit_line_buf));
        ImGui::OpenPopup("Edit IP Entry");
    }

    ImGui::Spacing();
    ImGui::Spacing();
    ImGui::Spacing();

    for (uint i = 0; i < allowed_lines.size(); ++i) {
        ImGui::Text("%s", allowed_lines[i].c_str());
        ImGui::SameLine(350);

        const std::string edit_button_label = "Edit##" + std::to_string(i);
        if (ImGui::Button(edit_button_label.c_str())) {
            edit_idx = i;
            strncpy(edit_line_buf, allowed_lines[i].c_str(), sizeof(edit_line_buf) - 1);
            ImGui::OpenPopup("Edit IP Entry");
        }
        ImGui::SameLine();

        const std::string delete_button_label = "Delete##" + std::to_string(i);
        if (ImGui::Button(delete_button_label.c_str())) {
            allowed_lines.erase(allowed_lines.begin() + i);
            changed_allowed_file_checker = true;
        }
    }

    // Edit/Add popup
    if (ImGui::BeginPopupModal("Edit IP Entry", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::Dummy(ImVec2(0, 5));
        ImGui::Indent(10);

        ImGui::InputText("Entry", edit_line_buf, sizeof(edit_line_buf));
        ImGui::Spacing();
        ImGui::TextDisabled("Format: 127.0.0.1 or 127.0.0.1:8080,8081");
        ImGui::Spacing();
        ImGui::Spacing();

        if (ImGui::Button("Save")) {
            if (edit_idx == -1) {
                // New entry
                allowed_lines.push_back(edit_line_buf);
            } else {
                // Edit existing
                allowed_lines[edit_idx] = edit_line_buf;
            }
            changed_allowed_file_checker = true;
            ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancel")) {
            ImGui::CloseCurrentPopup();
        }

        ImGui::Unindent(10);
        ImGui::Dummy(ImVec2(0, 5));

        ImGui::EndPopup();
    }
    ImGui::EndChild();

    // =========================== Update configuration ===========================

    if (ImGui::Button("Update", ImVec2(100, 0))) {
        printf("server ip:%s\nserver port:%s\nallowed path:%s\nchanged config bool:%d\n",
               changed_config_server_ip.c_str(), changed_config_server_port.c_str(),
               changed_config_allowed_file_path.c_str(), changed_config_checker);

        if (changed_config_checker || changed_allowed_file_checker || changed_general_checker) {
            const std::string new_config_file = create_config_info_string();

            std::string new_allwed_file = "";
            if (pc_selected_data.current_mode == MONITORING && changed_config_mode != MONITORING &&
                msg_struct_info_map != nullptr) {

                const auto entry = msg_struct_info_map->find(pc_id_selected);
                if (entry != msg_struct_info_map->end()) {
                    new_allwed_file = merge_allowed_with_topology(entry->second, allowed_lines);
                }
                msg_struct_info_map = nullptr;
                training_active_id = "";
            }

            // If it was not constructed using the `recreate_allowed_file`, recreate it manualy.
            if (new_allwed_file.empty()) {
                for (const auto &line : allowed_lines) {
                    new_allwed_file += line + "\n";
                }
            }

            printf("new allowed: %s\nold: %s\n", new_allwed_file.c_str(), pc_selected_data.allowed_file.c_str());

            send_config_via_api(pc_id_selected, new_config_file,
                                new_allwed_file != pc_selected_data.allowed_file ? new_allwed_file : "",
                                changed_general_name_given, icon_path_final);

            request_update = true;
        }
    }
    ImGui::EndChild();

    ImGui::Spacing();

    // === LOGS SECTION ===
    ImGui::Text("Current events");
    ImGui::BeginChild("logs", ImVec2(0, 0), true);

    if (msg_history_vector->empty()) {
        ImGui::TextDisabled("No activity recorded");
    } else {
        for (size_t index = 0; index < msg_history_vector->size(); index++) {
            const MessageReceived &msg = (*msg_history_vector)[index];

            ImGui::BeginGroup();

            ImGui::AlignTextToFramePadding();
            ImGui::PushStyleColor(ImGuiCol_Text, get_mode_color(msg.mode));
            ImGui::TextWrapped("%s", transform_messages_to_str(msg, nullptr).c_str());
            ImGui::PopStyleColor();

            // Add button on the right
            ImGui::SameLine(ImGui::GetWindowWidth() - 60);
            const std::string button_label = "+##add_" + std::to_string(index);
            if (ImGui::Button(button_label.c_str(), ImVec2(30, 20))) {
                printf("Add button clicked for message %ld\n", index);
                if (add_entity_in_allowed(allowed_lines, msg)) {
                    changed_allowed_file_checker = true;
                }
            }

            ImGui::EndGroup();
            ImGui::Separator();
        }
    }

    ImGui::EndChild();

    return 0;
};
