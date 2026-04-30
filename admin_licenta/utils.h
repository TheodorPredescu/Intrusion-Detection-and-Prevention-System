#ifndef UTILS_H
#define UTILS_H

#include "imgui/imgui.h"
#include "types.h"

#include <GL/gl.h>

#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

// ============================================================================
// ______________________________ Texture helpers _____________________________
// ============================================================================

GLuint load_image_as_texture(const char *filename);
GLuint load_texture_from_memory(const std::vector<uint8_t> &data);

std::vector<uint8_t> read_file_as_bytes(const std::string &path);
std::string base64_encode(const std::vector<uint8_t> &data);
std::vector<uint8_t> base64_decode(const std::string &encoded);

// ============================================================================
// ______________________________ Curl functions ______________________________
// ============================================================================

bool fetch_pc_list_config_from_api(std::string &out);
bool fetch_pc_config_from_api(const std::string &pc_id, std::string &out);
bool fetch_logs_from_api(const std::string &pc_id, int limit, std::string &out);
bool fetch_topology_info_from_api(const std::string &pc_id, std::string &out);
bool send_config_via_api(const std::string &pc_id, const std::string &config_file, const std::string allowed_file = "",
                         const std::string name = "", const std::string icon_path = "");

// ============================================================================
// __________________________________ Helpers _________________________________
// ============================================================================

std::map<std::string, ImVec2> compute_graph_layout(const std::set<std::string> &all_ips,
                                                   const std::map<std::string, std::set<std::string>> &connections);

std::string get_protocol_name(int protocol);
ImVec4 get_mode_color(int mode);
unsigned int get_mode_background_color(int mode, bool blink_visible);
const char *const get_mode_name(int mode);

std::vector<std::pair<std::string, std::string>> parse_connections(const std::string &log);

int extract_current_state(const std::string &config_file);
bool valid_mode(const int &mode);
std::string config_change_state(const std::string &config_file, const int &state);

void extract_config_info(const std::string &text, std::string &server_ip, std::string &server_port,
                         std::string &allowed_file);

std::map<std::string, PCInfo> *get_pc_info();
std::vector<MessageReceived> *get_message_history(const std::string &pc_id = "",
                                                  std::map<std::string, PCInfo> *pc_map = nullptr, int limit = -1);
std::map<std::string, TopologyEntry> get_topology(const std::string pc_id = "");

bool add_entity_in_allowed(std::vector<std::string> &allowed_lines, const MessageReceived &msg);
std::map<std::string, std::set<int>> extract_allowed_ips(const std::string &allowed_file);

std::string merge_allowed_with_topology(const TopologyEntry &information,
                                        const std::vector<std::string> &allowed_lines);
std::string merge_allowed_with_ports_map(const std::string &allowed_file,
                                         std::map<std::string, std::set<int>> ports_map);

std::string transform_messages_to_str(const MessageReceived &message, const std::map<std::string, PCInfo> *pc_map);

void set_pc_id_selected(const std::string new_pc_id);
std::string get_pc_id_selected();

void set_page(const Page new_page);
Page get_page();

void calculate_zoom_and_drag();
ImVec2 to_screen(const ImVec2 &world);

// ============================================================================
// __________________________ Topology view helpers ___________________________
// ============================================================================

// Defined in helpers.cpp, used by topology page
extern ImVec2 topology_pan;
extern float topology_zoom;

extern const float ZOOM_MIN;
extern const float ZOOM_MAX;

extern std::string pc_id_selected;
extern Page page;
#endif
