#include "imgui/backends/imgui_impl_glfw.h"
#include "imgui/backends/imgui_impl_opengl3.h"
#include "imgui/imgui.h"

#include <GL/gl.h>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstring>
#define STB_IMAGE_IMPLEMENTATION
#include "stb_image.h"

#include <GLFW/glfw3.h>
#include <cstdio>
#include <libssh/libssh.h>
#include <libssh/sftp.h>

#include <fcntl.h>
#include <sys/stat.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <curl/curl.h>
#include <fstream>
#include <iostream>
#include <map>
#include <memory>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "../daemon/json.hpp"

// States available.
#define LISTENING 0
#define MONITORING 1
#define REACTIVE 2
#define DISABLED 3
#define NO_STATE 255

const char *MODES[] = {"LISTENING", "MONITORING", "REACTIVE", "DISABLED"};

using json = nlohmann::json;

enum class Page { MainPage, Topology, ClientDetail };
static Page page;

// Options selected for config file.
static std::string pc_id_selected = "";
static std::string changed_config_server_ip = "";
static std::string changed_config_server_port = "";
static int changed_config_mode = NO_STATE;
static std::string changed_config_allowed_file_path = "";
static bool changed_config_checker = false;

// Options selected for allowed file.
static std::vector<std::string> changed_allowed_file;
static bool changed_allowed_file_checker = false;

// Options selected for general info.
static std::string changed_general_name_given = "";
static bool changed_general_checker = false;

static const double TARGET_FPS = 45.0;
static const double TARGET_FRAME_TIME = 1.0 / TARGET_FPS;

// ============================================================================
// ________________________________ DATA MODEL ________________________________
// ============================================================================

struct MessageReceived {
    std::string pc_id;
    std::string timestamp;
    std::string src_ip;
    std::string dst_ip;
    int src_port;
    int dst_port;
    int protocol;
    int mode;
};

/**
 * The `current_mode` will not be received via the API, but it will be searched and created from `config_file`, when it
 * is first received.
 */
struct PCInfo {
    std::string pc_id = "";
    std::string updated_at = "";
    std::string config_file = "";
    std::string allowed_file = "";

    /* This will not be received via the API, it will be created when its received.*/
    int current_mode = NO_STATE;

    GLuint icon_texture_id;
    std::string name = "";
};

struct ConnectionStats {
    std::set<int> ports_out;
    std::set<int> protocols;
    std::set<int> ttls;
    std::set<int> packet_lens;
    std::set<int> tcp_flags;
    std::set<int> ports_in;
    std::set<std::string> mac_addr;
};

struct TopologyEntry {
    // key: source ip; value: general information comming from that source
    std::map<std::string, ConnectionStats> connection_dict;
    // All the ips used by this pc.
    std::set<std::string> topology_ip;
};

struct TopologyType {
    std::map<std::string, TopologyEntry> topology_connection;
};

// ============================================================================

static ImVec2 topology_pan = ImVec2(0.0f, 0.0f);
static float topology_zoom = 1.0f;

static const float ZOOM_MIN = 0.3f;
static const float ZOOM_MAX = 3.0f;

// ============================================================================
// ______________________________ Texture helpers _____________________________
// ============================================================================

static GLuint load_image_as_texture(const char *filename) {

    int width, height, channels;
    unsigned char *data = stbi_load(filename, &width, &height, &channels, 4);

    if (!data) {
        std::cerr << "Failed to load image: " << filename << "\n";
        return 0;
    }

    GLuint texture_id;
    glGenTextures(1, &texture_id);
    glBindTexture(GL_TEXTURE_2D, texture_id);

    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);

    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, width, height, 0, GL_RGBA, GL_UNSIGNED_BYTE, data);

    stbi_image_free(data);
    return texture_id;
}

static GLuint load_texture_from_memory(const std::vector<uint8_t> &data) {

    if (data.empty()) {
        return 0;
    }

    int width, height, channels;
    unsigned char *img_data = stbi_load_from_memory(data.data(), data.size(), &width, &height, &channels, 4);

    if (!img_data) {
        return 0;
    }

    GLuint texture_id;
    glGenTextures(1, &texture_id);
    glBindTexture(GL_TEXTURE_2D, texture_id);

    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);

    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, width, height, 0, GL_RGBA, GL_UNSIGNED_BYTE, img_data);

    stbi_image_free(img_data);
    return texture_id;
}

static std::vector<uint8_t> read_file_as_bytes(const std::string &path) {
    std::ifstream file(path, std::ios::binary);
    return std::vector<uint8_t>(std::istreambuf_iterator<char>(file), {});
}

static std::string base64_encode(const std::vector<uint8_t> &data) {
    static const char chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string result;
    int val = 0, bits = -6;

    for (uint8_t c : data) {
        val = (val << 8) + c;
        bits += 8;
        while (bits >= 0) {
            result.push_back(chars[(val >> bits) & 0x3F]);
            bits -= 6;
        }
    }

    if (bits > -6) {
        result.push_back(chars[((val << 8) >> (bits + 8)) & 0x3F]);
    }

    while (result.size() % 4) {
        result.push_back('=');
    }

    return result;
}

static std::vector<uint8_t> base64_decode(const std::string &encoded) {
    static const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    std::vector<uint8_t> data;
    int val = 0, bits = -8;

    for (unsigned char c : encoded) {
        if (c == '=' || c == '\n') {
            continue;
        }
        auto pos = chars.find(c);
        if (pos == std::string::npos) {
            break;
        }
        val = (val << 6) + static_cast<int>(pos);
        bits += 6;
        if (bits >= 0) {
            data.push_back((val >> bits) & 0xFF);
            bits -= 8;
        }
    }

    return data;
}

// ============================================================================
// ______________________________ Curl functions ______________________________
// ============================================================================

static size_t write_callback(void *contents, size_t size, size_t nmemb, std::string *s) {
    size_t newLength = size * nmemb;
    try {
        s->append((char *)contents, newLength);
    } catch (std::bad_alloc &e) {
        return 0;
    }
    return newLength;
}

static bool fetch_pc_list_config_from_api(std::string &out) {
    CURL *curl = curl_easy_init();
    if (!curl) {
        std::cerr << "Failed to initialize CURL\n";
        return false;
    }

    // Build the API URL
    std::string url = "http://127.0.0.1:8080/config/admin";

    out.clear();

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &out);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 2L);

    CURLcode res = curl_easy_perform(curl);
    bool success = (res == CURLE_OK);

    curl_easy_cleanup(curl);
    return success;
}

static bool fetch_pc_config_from_api(const std::string &pc_id, std::string &out) {

    CURL *curl = curl_easy_init();
    if (!curl) {
        return -1;
    }

    std::string base_url = "http://127.0.0.1:8080/config/admin?pc_id=" + pc_id;

    curl_easy_setopt(curl, CURLOPT_URL, base_url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    out.clear();

    curl_easy_setopt(
        curl, CURLOPT_WRITEFUNCTION, +[](char *ptr, size_t size, size_t nmemb, void *userdata) -> size_t {
            auto *resp = static_cast<std::string *>(userdata);
            resp->append(ptr, size * nmemb);
            return size * nmemb;
        });

    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &out);

    CURLcode res = curl_easy_perform(curl);

    bool success = (res == CURLE_OK);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    return success;
}

static bool fetch_logs_from_api(const std::string &pc_id, const int limit, std::string &out) {
    CURL *curl = curl_easy_init();
    if (!curl) {
        std::cerr << "Failed to initialize CURL\n";
        return false;
    }

    // Build the API URL
    std::string url = "http://127.0.0.1:8080/logs";
    if (pc_id != "") {
        url += "?pc_id=" + pc_id;
    }

    if (limit > 0) {
        url += "?limit=" + std::to_string(limit);
    }

    out.clear();

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &out);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);        // 5 second timeout
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 2L); // 2 second connect timeout

    CURLcode res = curl_easy_perform(curl);

    bool success = (res == CURLE_OK);
    if (!success) {
        std::cerr << "CURL error " << pc_id << ": " << curl_easy_strerror(res) << "\n";
    }

    curl_easy_cleanup(curl);
    return success;
}

static bool fetch_topology_info_from_api(const std::string &pc_id, std::string &out) {

    CURL *curl = curl_easy_init();
    if (!curl) {
        return -1;
    }

    std::string base_url = "http://127.0.0.1:8080/topology";

    if (!pc_id.empty()) {
        base_url += "?pc_id=" + pc_id;
    }

    curl_easy_setopt(curl, CURLOPT_URL, base_url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    out.clear();

    curl_easy_setopt(
        curl, CURLOPT_WRITEFUNCTION, +[](char *ptr, size_t size, size_t nmemb, void *userdata) -> size_t {
            auto *resp = static_cast<std::string *>(userdata);
            resp->append(ptr, size * nmemb);
            return size * nmemb;
        });

    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &out);

    CURLcode res = curl_easy_perform(curl);

    bool success = (res == CURLE_OK);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    return success;
}

static bool send_config_via_api(const std::string &pc_id, const std::string &config_file,
                                const std::string allowed_file = "", const std::string name = "",
                                const std::string icon_path = "") {
    if (pc_id.empty()) {
        return false;
    }

    CURL *curl = curl_easy_init();
    if (!curl) {
        std::cerr << "Failed to initialize CURL\n";
        return false;
    }

    const std::string url = "http://127.0.0.1:8080/config/admin?pc_id=" + pc_id;

    // Build JSON body
    json body;
    if (!config_file.empty()) {
        body["config_file"] = config_file;
    }
    if (!allowed_file.empty()) {
        body["allowed_file"] = allowed_file;
    }
    if (!name.empty()) {
        body["name"] = name;
    }

    if (icon_path[0] != '\0') {
        std::vector<uint8_t> image_data = read_file_as_bytes(icon_path);
        std::string base64_icon = base64_encode(image_data);
        body["icon"] = base64_icon;
    }

    std::string json_str = body.dump();

    // Set up headers
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "POST");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_str.c_str());
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 2L);

    std::string response;
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    CURLcode res = curl_easy_perform(curl);
    bool success = (res == CURLE_OK);

    if (!success) {
        std::cerr << "CURL error in posting configuration: " << curl_easy_strerror(res) << "\n";
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    return success;
}

// ============================================================================
// __________________________________ HELPERS _________________________________
// ============================================================================
#ifdef _WIN32
#include <windows.h>
#endif

static std::map<std::string, ImVec2>
compute_graph_layout(const std::set<std::string> &all_ips,
                     const std::map<std::string, std::set<std::string>> &connections) {
    std::map<std::string, ImVec2> positions;

    // Get temp directory (cross-platform)
    std::string temp_dir;
#ifdef _WIN32
    char temp_path[MAX_PATH];
    GetTempPathA(MAX_PATH, temp_path);
    temp_dir = temp_path;
#else
    temp_dir = "/tmp/";
#endif

    std::string dot_file_path = temp_dir + "graph.dot";
    std::string txt_file_path = temp_dir + "graph.txt";

    // Generate dot
    std::string dot = "digraph G {\nrankdir=LR;\nnode [shape=box];\n";
    dot += "graph [overlap=false];\n";
    for (const auto &ip : all_ips) {
        dot += "  \"" + ip + "\";\n";
    }
    for (const auto &[src, dests] : connections) {
        for (const auto &dst : dests) {
            dot += "  \"" + src + "\" -> \"" + dst + "\";\n";
        }
    }
    dot += "}\n";

    std::ofstream dot_file(dot_file_path);
    dot_file << dot;
    dot_file.close();

    // Run graphviz (quote paths for Windows)
#ifdef _WIN32
    std::string cmd = "neato -Tplain \"" + dot_file_path + "\" -o \"" + txt_file_path + "\"";
#else
    std::string cmd = "neato -Tplain " + dot_file_path + " -o " + txt_file_path + " 2>/dev/null";
#endif
    system(cmd.c_str());

    // Parse positions
    std::ifstream result(txt_file_path);
    std::string line;
    while (std::getline(result, line)) {
        if (!line.empty() && line[0] == 'n') {
            std::istringstream iss(line);
            std::string node_type, ip_quoted;
            float x, y;
            iss >> node_type >> ip_quoted >> x >> y;
            std::string ip = ip_quoted.substr(1, ip_quoted.length() - 2);
            positions[ip] = ImVec2(x * 100, y * 100);
        }
    }
    result.close();

    // Cleanup
    std::remove(dot_file_path.c_str());
    std::remove(txt_file_path.c_str());

    return positions;
}

static std::string get_protocol_name(const int protocol) {
    switch (protocol) {
        case 1:
            return "ICMP";
        case 6:
            return "TCP";
        case 17:
            return "UDP";
        case 41:
            return "IPv6";
        case 58:
            return "ICMPv6";
        case 88:
            return "IGRP";
        default:
            return "UNKNOWN";
    }
}

static ImVec4 get_mode_color(const int mode) {
    switch (mode) {
        case LISTENING:
            return ImVec4(0.4f, 0.8f, 0.4f, 1.0f);
        case MONITORING:
            return ImVec4(0.4f, 0.6f, 1.0f, 1.0f);
        case REACTIVE:
            return ImVec4(1.0f, 0.4f, 0.4f, 1.0f);
        case DISABLED:
            return ImVec4(0.5f, 0.5f, 0.5f, 1.0f);
        default:
            return ImVec4(0.5f, 0.5f, 0.5f, 1.0f);
    }
}

static uint get_mode_background_color(const int mode, const bool blink_visible) {
    switch (mode) {
        case LISTENING:
            return IM_COL32(100, 200, 100, 50);
        case MONITORING:
            return IM_COL32(100, 150, 255, blink_visible ? 80 : 20);
        case REACTIVE:
            return IM_COL32(255, 100, 100, blink_visible ? 80 : 20);
        case DISABLED:
            return IM_COL32(100, 100, 100, 50);
        default:
            return IM_COL32(100, 100, 100, 50);
    }
}

static const char *const get_mode_name(const int mode) {

    switch (mode) {
        case LISTENING:
            return MODES[LISTENING];
        case MONITORING:
            return MODES[MONITORING];
        case REACTIVE:
            return MODES[REACTIVE];
        case DISABLED:
            return MODES[DISABLED];
        default:
            return "UNKNOWN";
    }
}

static void reset_config_modifications() {
    changed_config_server_port = "";
    changed_config_server_ip = "";
    changed_config_mode = NO_STATE;
    changed_config_allowed_file_path = "";
    changed_config_checker = false;
}

static void reset_allowed_modifications() {
    changed_allowed_file.clear();
    changed_allowed_file_checker = false;
}

static void reset_general_user_info() {
    changed_general_name_given = "";
    changed_general_checker = false;
}

static void reset_modifications() {
    reset_config_modifications();
    reset_allowed_modifications();
    reset_general_user_info();
}

std::vector<std::pair<std::string, std::string>> parse_connections(const std::string &log) {
    std::vector<std::pair<std::string, std::string>> connections;
    std::regex pattern(R"(SRC=([\d\.]+).*DST=([\d\.]+))");
    std::istringstream iss(log);
    std::string line;

    while (std::getline(iss, line)) {
        std::smatch match;
        if (std::regex_search(line, match, pattern) && match.size() == 3) {
            std::string src = match[1].str();
            std::string dst = match[2].str();

            if (dst == "255.255.255.255" || dst == "127.0.0.1" || src == "127.0.0.1" || src == "0.0.0.0") {
                continue;
            }

            connections.emplace_back(src, dst);
        }
    }
    return connections;
}

/**
 * @default value: `NO_STATE`
 */
static int extract_current_state(const std::string &config_file) {

    std::string result = config_file;
    for (auto &c : result) {
        c = std::tolower(c);
    }
    if (result.find("listening") != std::string::npos) {
        return LISTENING;
    }
    if (result.find("monitoring") != std::string::npos) {
        return MONITORING;
    }
    if (result.find("reactive") != std::string::npos) {
        return REACTIVE;
    }
    if (result.find("disabled") != std::string::npos) {
        return DISABLED;
    }
    return NO_STATE;
}

static bool valid_mode(const int &mode) {
    return mode >= 0 && mode <= DISABLED;
}

static std::string config_change_state(const std::string &config_file, const int &state) {

    if (!valid_mode(state)) {
        return "";
    }

    std::istringstream iss(config_file);
    std::string line;
    std::ostringstream oss;
    bool wrote_mode = false;

    while (std::getline(iss, line)) {
        if (wrote_mode) {
            oss << line << "\n";
            continue;
        }

        std::string line_upper = line;
        for (auto &c : line_upper) {
            c = std::toupper(c);
        }

        bool found_mode = false;
        for (const char *mode : MODES) {
            const size_t pozition = line_upper.find(mode);

            if (pozition != std::string::npos) {
                found_mode = true;
                break;
            }
        }

        if (found_mode) {
            oss << MODES[state] << "\n";
            wrote_mode = true;
        } else {
            oss << line << "\n";
        }
    }

    return wrote_mode ? oss.str() : "";
}

static void extract_config_info(const std::string &text, std::string &server_ip, std::string &server_port,
                                std::string &allowed_file) {

    std::istringstream iss(text);
    std::string line;

    while (std::getline(iss, line)) {
        // Trim whitespace
        line.erase(0, line.find_first_not_of(" \t\r\n"));
        line.erase(line.find_last_not_of(" \t\r\n") + 1);

        if (line.empty()) {
            continue;
        }

        // Parse server IP
        if (line.find("server IP") == 0) {
            server_ip = line.substr(line.find_last_of(" ") + 1);
        }
        // Parse server port
        else if (line.find("server port") == 0) {
            server_port = line.substr(line.find_last_of(" ") + 1);
        }
        // Parse allowed file
        else if (line.find("allowed_file") == 0) {
            allowed_file = line.substr(line.find_last_of(" ") + 1);
        }
    }
}

static std::string create_config_info_string() {
    if (!changed_config_checker) {
        return "";
    }

    char buffer[2048];
    snprintf(buffer, sizeof(buffer), "server IP %s\nserver port %s\n%s\nallowed_file %s\n",
             changed_config_server_ip.c_str(), changed_config_server_port.c_str(), MODES[changed_config_mode],
             changed_config_allowed_file_path.c_str());

    return std::string(buffer);
}

static std::map<std::string, PCInfo> *get_pc_info() {
    static std::map<std::string, PCInfo> pc_map;
    std::string pcs_response;

    if (fetch_pc_list_config_from_api(pcs_response)) {
        try {
            // Parse JSON response
            auto logs_json = json::parse(pcs_response);

            if (logs_json.is_array()) {

                pc_map.clear();

                for (const auto &pc_entry : logs_json) {

                    PCInfo pc;
                    // Extract fields from JSON
                    pc.pc_id = pc_entry.value("pc_id", "");
                    pc.name = pc_entry.value("name", "");
                    pc.updated_at = pc_entry.value("updated_at", "N/A");
                    pc.config_file = pc_entry.value("config_file", "");
                    pc.allowed_file = pc_entry.value("allowed_file", "");
                    pc.current_mode = extract_current_state(pc.config_file);

                    std::string icon_bytes_encoded = pc_entry.value("icon", "");
                    if (!icon_bytes_encoded.empty()) {
                        std::vector<uint8_t> icon_bytes = base64_decode(icon_bytes_encoded);
                        pc.icon_texture_id = load_texture_from_memory(icon_bytes);
                    } else {
                        pc.icon_texture_id = 0;
                    }

                    pc_map.insert({pc.pc_id, pc});
                }
            }
        } catch (const std::exception &e) {
            std::cerr << "JSON parse error in fetching pcs: " << e.what() << "\n";
        }
    }

    return &pc_map;
}

static std::vector<MessageReceived> *get_message_history(const std::string &pc_id = "",
                                                         std::map<std::string, PCInfo> *pc_map = nullptr,
                                                         const int limit = -1) {
    static std::vector<MessageReceived> message_history;

    message_history.clear();
    std::string pc_logs;

    if (fetch_logs_from_api(pc_id, limit, pc_logs)) {
        try {
            // Parse JSON response
            auto logs_json = json::parse(pc_logs);

            if (logs_json.contains("logs") && logs_json["logs"].is_array()) {
                for (const auto &log_entry : logs_json["logs"]) {

                    // Extract fields from JSON
                    MessageReceived message;
                    message.pc_id = log_entry.value("pc_id", "");
                    message.timestamp = log_entry.value("timestamp", "N/A");
                    message.src_ip = log_entry.value("src_ip", "");
                    message.dst_ip = log_entry.value("dst_ip", "");
                    message.src_port = log_entry.value("src_port", 0);
                    message.dst_port = log_entry.value("dst_port", 0);
                    message.protocol = log_entry.value("protocol", 0);
                    message.mode = log_entry.value("mode", NO_STATE);

                    message_history.push_back(message);
                }
            }
        } catch (const std::exception &e) {
            std::cerr << "JSON parse error for logs: " << e.what() << "\n";
        }
    }

    return &message_history;
}

static TopologyType get_topology(const std::string pc_id = "") {
    TopologyType topology;
    std::string topology_str;

    if (fetch_topology_info_from_api(pc_id, topology_str)) {
        try {
            printf("[TOPOLOGY] %s\n", topology_str.c_str());
            auto topology_json = json::parse(topology_str);

            if (topology_json.is_object()) {
                for (auto &[pc_id, entry_json] : topology_json.items()) {
                    TopologyEntry entry;

                    // Parse topology_ip set
                    if (entry_json.contains("topology_ip") && entry_json["topology_ip"].is_array()) {
                        for (const auto &ip : entry_json["topology_ip"]) {
                            entry.topology_ip.insert(ip.get<std::string>());
                        }
                    }

                    // Parse connection_dict
                    if (entry_json.contains("connection_dict") && entry_json["connection_dict"].is_object()) {
                        for (auto &[src_ip, stats_json] : entry_json["connection_dict"].items()) {
                            ConnectionStats stats;

                            // Helper lambda to parse int sets
                            auto parse_int_set = [](const json &j, const std::string &key) -> std::set<int> {
                                std::set<int> result;
                                if (j.contains(key) && j[key].is_array()) {
                                    for (const auto &val : j[key]) {
                                        result.insert(val.get<int>());
                                    }
                                }
                                return result;
                            };

                            // Helper lambda to parse string set
                            auto parse_str_set = [](const json &j, const std::string &key) -> std::set<std::string> {
                                std::set<std::string> result;
                                if (j.contains(key) && j[key].is_array()) {
                                    for (const auto &val : j[key]) {
                                        result.insert(val.get<std::string>());
                                    }
                                }
                                return result;
                            };

                            stats.ports_out = parse_int_set(stats_json, "ports_out");
                            stats.protocols = parse_int_set(stats_json, "protocols");
                            stats.ttls = parse_int_set(stats_json, "ttls");
                            stats.packet_lens = parse_int_set(stats_json, "packet_lens");
                            stats.tcp_flags = parse_int_set(stats_json, "tcp_flags");
                            stats.ports_in = parse_int_set(stats_json, "ports_in");
                            stats.mac_addr = parse_str_set(stats_json, "mac_addr");

                            entry.connection_dict[src_ip] = stats;
                        }
                    }

                    topology.topology_connection[pc_id] = entry;
                }
            }
        } catch (const std::exception &e) {
            std::cerr << "JSON parse error for topology: " << e.what() << "\n";
        }
    }

    return topology;
}

static bool add_entity_in_allowed(std::vector<std::string> &allowed_lines, const MessageReceived &msg) {

    std::string *found_line = nullptr;
    size_t colon_pos;

    for (std::string &line : allowed_lines) {
        colon_pos = line.find(":");
        std::string ip;

        if (colon_pos != std::string::npos) {
            ip = line.substr(0, colon_pos);
        } else {
            ip = line;
        }

        if (msg.src_ip == ip) {
            found_line = &line;
            break;
        }
    }

    if (found_line == nullptr) {
        allowed_lines.push_back(msg.src_ip + ": " + std::to_string(msg.src_port));
        return true;
    }

    if (colon_pos == std::string::npos) {
        return false;
    }

    std::istringstream iss((*found_line).substr(colon_pos + 1));
    std::string port_token;
    bool found_port = false;

    while (std::getline(iss, port_token, ',')) {
        try {
            int port = std::stoi(port_token);
            if (port == msg.src_port) {
                found_port = true;
                break;
            }

        } catch (const std::exception &e) {
            // Invalid port format, skip
            std::cerr << "Invalid port: " << port_token << "\n";
        }
    }

    if (!found_port) {
        (*found_line) += ", " + std::to_string(msg.src_port);
        return true;
    }

    return false;
}

static std::string merge_allowed_with_topology(const TopologyEntry &information,
                                               const std::vector<std::string> &allowed_lines) {

    static std::map<std::string, std::set<int>> allowed_ip_map;
    allowed_ip_map.clear();

    for (const std::string &line : allowed_lines) {
        const size_t colon_pos = line.find(":");

        // Just the ip, no ports written
        if (colon_pos == std::string::npos) {
            allowed_ip_map[line];
            continue;
        }

        // IP with ports
        const std::string ip = line.substr(0, colon_pos);
        const std::string ports_str = line.substr(colon_pos + 1);

        // Parse ports (comma-separated)
        std::istringstream iss(ports_str);
        std::string port_token;
        while (std::getline(iss, port_token, ',')) {
            try {
                uint port = std::stoul(port_token);

                if (port <= 65535) {
                    allowed_ip_map[ip].insert(port);
                } else {
                    std::cerr << "Port out of range: " << port << "\n";
                }
            } catch (const std::exception &e) {
                // Invalid port format, skip
                std::cerr << "Invalid port: " << port_token << "\n";
            }
        }
    }

    for (const auto &[ip, stats] : information.connection_dict) {
        auto it = allowed_ip_map.find(ip);

        // If its empty line, keep the profile (allow everithing)
        if (it != allowed_ip_map.end() && it->second.empty()) {
            continue;
        }

        std::set<int> &ip_set = allowed_ip_map[ip];
        printf("[TOPOLOGY] tried to add a new set for ip: %s\n", ip.c_str());
        for (const int &port : stats.ports_out) {
            ip_set.insert(port);
            printf("[TOPOLOGY] tried to add a new port : %d\n", port);
        }
    }

    std::string allowed_file = "";
    for (const auto &[ip, port_set] : allowed_ip_map) {
        allowed_file += ip;

        bool first = true;
        for (const int port : port_set) {
            if (first) {
                first = false;
                allowed_file += ": ";
            } else {
                allowed_file += ", ";
            }

            allowed_file += std::to_string(port);
        }

        allowed_file += "\n";
    }

    return allowed_file;
}

static std::string merge_allowed_with_ports_map(const std::string &allowed_file,
                                                std::map<std::string, std::set<int>> ports_map) {

    std::istringstream iss(allowed_file);
    std::string line;

    while (std::getline(iss, line)) {
        line.erase(0, line.find_first_not_of(" \t\r\n"));
        line.erase(line.find_last_not_of(" \t\r\n") + 1);
        if (line.empty()) {
            continue;
        }

        const size_t colon_pos = line.find(":");

        // If its only the ip in the original list, clear the set if the entity already exists or create empty entity
        if (colon_pos == std::string::npos) {
            ports_map[line].clear();
            continue;
        }

        // IP with ports
        std::string ip = line.substr(0, colon_pos);
        std::string ports_str = line.substr(colon_pos + 1);

        // Parse ports (comma-separated)
        std::istringstream iss(ports_str);
        std::string port_token;

        while (std::getline(iss, port_token, ',')) {
            try {
                uint port = std::stoul(port_token);

                if (port <= 65535) {
                    ports_map[ip].insert(port);
                } else {
                    std::cerr << "Port out of range: " << port << "\n";
                }
            } catch (const std::exception &e) {
                // Invalid port format, skip
                std::cerr << "Invalid port: " << port_token << "\n";
            }
        }
    }

    std::string new_allowed_file = "";

    for (const auto &[allowed_ip, allowed_port_set] : ports_map) {
        new_allowed_file += allowed_ip;

        bool first = true;
        for (const int port : allowed_port_set) {
            if (first) {
                first = false;
                new_allowed_file += ": ";
            } else {
                new_allowed_file += ", ";
            }

            new_allowed_file += std::to_string(port);
        }

        new_allowed_file += "\n";
    }

    return new_allowed_file;
}

static std::string transform_messages_to_str(const MessageReceived &message,
                                             const std::map<std::string, PCInfo> *const pc_map) {

    std::string name = "";
    if (pc_map != nullptr && !message.pc_id.empty()) {
        const auto it = (*pc_map).find(message.pc_id);
        if (it != (*pc_map).end() && !it->second.name.empty()) {
            name = it->second.name + " ";
        }
    }

    const std::string proto_name = get_protocol_name(message.protocol);

    std::stringstream ss;
    ss << name << "[" << message.timestamp << "] " << message.src_ip << ":" << message.src_port << " -> "
       << message.dst_ip << ":" << message.dst_port << " [" << proto_name << "]";

    return ss.str();
}

// ========================= Transformations from topology reactivity =========================

/**
 * Handles interactive panning and zooming of the topology view.
 */
static void calculate_zoom_and_drag() {

    const ImGuiIO &io = ImGui::GetIO();
    const ImVec2 mouse = io.MousePos;

    if (ImGui::IsWindowHovered() && ImGui::IsMouseDragging(ImGuiMouseButton_Left)) {
        topology_pan.x += io.MouseDelta.x;
        topology_pan.y += io.MouseDelta.y;
    }

    if (ImGui::IsWindowHovered() && io.MouseWheel != 0.0f) {
        const float zoom_factor = 1.0f + io.MouseWheel * 0.1f;
        float new_zoom = topology_zoom * zoom_factor;

        new_zoom = std::clamp(new_zoom, ZOOM_MIN, ZOOM_MAX);

        // Keep mouse position stable
        ImVec2 mouse_world;
        mouse_world.x = (mouse.x - topology_pan.x) / topology_zoom;
        mouse_world.y = (mouse.y - topology_pan.y) / topology_zoom;

        topology_zoom = new_zoom;

        topology_pan.x = mouse.x - mouse_world.x * topology_zoom;
        topology_pan.y = mouse.y - mouse_world.y * topology_zoom;
    }
}

/**
 * Converts a position from world-space to screen-space.
 *
 * Applies the current topology zoom (scale) and pan (translation)
 * so that world coordinates can be rendered correctly in ImGui.
 *
 * @param world  Position in world coordinates.
 * @return       Corresponding position in screen coordinates.
 */
static ImVec2 to_screen(const ImVec2 &world) {
    return ImVec2(world.x * topology_zoom + topology_pan.x, world.y * topology_zoom + topology_pan.y);
}

// ===================================================================================================
// ===================================== Main UI functionalities =====================================
// ===================================================================================================

static void draw_main_page(const double &current_time) {
    static const int REFRESH_INTERVAL = 5; // seconds
    static double previous_time = -REFRESH_INTERVAL;
    static bool is_context_menu_opened = false;
    static float blink_time = 0.0f;

    static std::map<std::string, PCInfo> *pc_map;

    static std::vector<MessageReceived> *message_history_vector; // Fetch logs every `REFRESH_INTERVAL` seconds

    static PCInfo const *pc_context_menu_selected = nullptr;

    static std::unique_ptr<TopologyType> training_topology_data = nullptr;
    static std::map<std::string, std::set<int>> training_allowed_new_elements;
    static std::map<std::string, int> training_pc_mode_before;
    static bool training_activate = false;

    ImGui::Text("Network Monitoring System");
    ImGui::Separator();
    ImGui::Spacing();

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

            // Save all the new connections `to be added` in a more friendly format.
            if (training_topology_data) {
                training_allowed_new_elements.clear();
                for (const auto &[_, pc_topology_info] : training_topology_data->topology_connection) {
                    for (const auto &[src_ip, src_info] : pc_topology_info.connection_dict) {

                        for (const int port : src_info.ports_out) {
                            training_allowed_new_elements[src_ip].insert(port);
                        }
                    }
                }
            }

            // Add all the new allowed definitions into the allowed file for each element and change back the mode to
            // its original state.
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

    // Clients section
    ImGui::Text("Connected Clients");
    ImGui::Spacing();

    ImGui::BeginChild("clients_list", ImVec2(0, -200), true);

    // Blinking effect state
    blink_time += ImGui::GetIO().DeltaTime;
    const bool blink_visible = fmod(blink_time, 1.0f) < 0.5f;

    // __________________ REFRESH __________________
    if (current_time >= previous_time + REFRESH_INTERVAL) {
        std::cout << previous_time << ", " << current_time << std::endl;
        previous_time = current_time;

        pc_map = get_pc_info();
        message_history_vector = get_message_history("", pc_map);

        if (training_activate) {
            training_topology_data = std::make_unique<TopologyType>(get_topology());
        }
    }

    // Get clients from your data structure
    for (const auto &[_, pc] : *pc_map) {
        ImGui::BeginGroup();

        // Client card background
        ImVec2 card_pos = ImGui::GetCursorScreenPos();
        ImVec2 card_size(500, 55);

        ImDrawList *dl = ImGui::GetWindowDrawList();
        dl->AddRectFilled(card_pos, ImVec2(card_pos.x + card_size.x, card_pos.y + card_size.y),
                          get_mode_background_color(pc.current_mode, blink_visible), 8.0f);
        dl->AddRect(card_pos, ImVec2(card_pos.x + card_size.x, card_pos.y + card_size.y), IM_COL32(150, 150, 150, 150),
                    8.0f, 0, 2.0f);

        // Padding

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
                pc_context_menu_selected = &pc;
                ImGui::OpenPopup("pc_context_menu");
            }
        }

        ImGui::Spacing();
        ImGui::Spacing();
    }

    // Popup on right click on a pc component.
    if (ImGui::BeginPopup("pc_context_menu")) {
        ImGui::Text("PC: %s", pc_context_menu_selected->pc_id.c_str());
        ImGui::Separator();

        if (ImGui::MenuItem("View Details")) {
            pc_id_selected = pc_context_menu_selected->pc_id;
            page = Page::ClientDetail;
            ImGui::CloseCurrentPopup();
        }
        if (ImGui::MenuItem("Edit Config")) {
            pc_id_selected = pc_context_menu_selected->pc_id;
            page = Page::ClientDetail;
            ImGui::CloseCurrentPopup();
        }
        ImGui::Separator();
        if (ImGui::MenuItem("Restart")) {
            std::cout << "Restart " << pc_context_menu_selected->pc_id << "\n";
            ImGui::CloseCurrentPopup();
        }
        if (ImGui::MenuItem("Delete")) {
            std::cout << "Delete " << pc_context_menu_selected->pc_id << "\n";
            ImGui::CloseCurrentPopup();
        }

        ImGui::EndPopup();

        // Popup is open this frame
        is_context_menu_opened = true;
    } else if (is_context_menu_opened) {
        pc_context_menu_selected = nullptr;
        is_context_menu_opened = false;
    }

    ImGui::EndChild();

    // Message history section
    ImGui::Separator();
    ImGui::Text("Recent Messages (Last 20)");

    ImGui::BeginChild("message_history", ImVec2(0, 0), true);

    for (const MessageReceived &msg : *message_history_vector) {
        ImGui::PushStyleColor(ImGuiCol_Text, get_mode_color(msg.mode));
        ImGui::TextWrapped("%s", transform_messages_to_str(msg, pc_map).c_str());
        ImGui::PopStyleColor();
        ImGui::Separator();
    }

    ImGui::EndChild();
}

static void draw_topology(const double &current_time) {
    static const float REFRESH_INTERVAL = 7;
    static double previous_time = -REFRESH_INTERVAL;
    static std::map<std::string, PCInfo> *pc_map = nullptr;
    static TopologyType topology_data;
    static std::map<std::string, ImVec2> node_positions;

    if (current_time >= previous_time + REFRESH_INTERVAL) {
        previous_time = current_time;
        pc_map = get_pc_info();
        topology_data = get_topology();
        node_positions.clear();
    }

    if (!pc_map || topology_data.topology_connection.empty()) {
        return;
    }

    // Build IP to PC mapping
    std::map<std::string, std::string> ip_to_pc_id;
    for (const auto &[pc_id, entry] : topology_data.topology_connection) {
        for (const auto &ip : entry.topology_ip) {
            ip_to_pc_id[ip] = pc_id;
        }
    }

    // Build connections from topology data
    std::set<std::string> all_nodes;
    std::map<std::string, std::set<std::string>> connections;

    for (const auto &[receiver_pc_id, entry] : topology_data.topology_connection) {
        all_nodes.insert(receiver_pc_id);

        // For each source IP that connected to this PC
        for (const auto &[src_ip, stats] : entry.connection_dict) {

            const auto it = entry.topology_ip.find(src_ip);
            if (it != entry.topology_ip.end()) {
                continue;
            }

            std::string sender;

            // Map src_ip to pc_id or keep as external IP
            if (ip_to_pc_id.find(src_ip) != ip_to_pc_id.end()) {
                sender = ip_to_pc_id[src_ip];
                all_nodes.insert(sender);
            } else {
                sender = src_ip;
                all_nodes.insert(sender);
            }

            connections[sender].insert(receiver_pc_id);
        }
    }

    if (node_positions.empty()) {
        node_positions = compute_graph_layout(all_nodes, connections);
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

    // Draw nodes (same as before)
    for (const auto &node_key : all_nodes) {
        bool is_pc = pc_map->find(node_key) != pc_map->end();
        const PCInfo &pc = is_pc ? pc_map->at(node_key) : PCInfo{};

        ImVec2 screen_node_pos = to_screen(node_positions[node_key]);
        ImVec2 node_pos = ImVec2(screen_node_pos.x + canvas_pos.x, screen_node_pos.y + canvas_pos.y);
        ImVec2 node_size(NODE_WIDTH * topology_zoom, NODE_HEIGHT * topology_zoom);

        ImU32 node_color = is_pc ? IM_COL32(80, 150, 255, 255) : IM_COL32(255, 100, 100, 255);
        dl->AddRectFilled(node_pos, ImVec2(node_pos.x + node_size.x, node_pos.y + node_size.y), node_color, 8.0f);
        dl->AddRect(node_pos, ImVec2(node_pos.x + node_size.x, node_pos.y + node_size.y), IM_COL32(255, 255, 255, 200),
                    8.0f, 0, 2.0f);

        std::string node_text = is_pc ? (pc.name.empty() ? pc.pc_id : pc.name) : node_key;
        ImVec2 text_size = ImGui::CalcTextSize(node_text.c_str());
        ImVec2 text_pos =
            ImVec2(node_pos.x + node_size.x / 2 - text_size.x / 2, node_pos.y + node_size.y / 2 - text_size.y / 2);
        dl->AddText(text_pos, IM_COL32_WHITE, node_text.c_str());

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
            if (dests.count(node_key)) {
                ImVec2 src_screen = to_screen(node_positions[src]);
                ImVec2 src_center = ImVec2(src_screen.x + canvas_pos.x + NODE_WIDTH * topology_zoom / 2,
                                           src_screen.y + canvas_pos.y + NODE_HEIGHT * topology_zoom / 2);
                auto [pin_pos, edge] = get_closest_edge(node_center, src_center, node_size.x, node_size.y);
                dl->AddCircleFilled(pin_pos, PIN_RADIUS, IM_COL32(150, 200, 255, 255));
                pin_positions[node_key + "_in_" + std::to_string(input_idx)] = pin_pos;
                input_idx++;
            }
        }

        if (connections.find(node_key) != connections.end()) {
            int output_idx = 0;
            for (const auto &dst : connections[node_key]) {
                ImVec2 dst_screen = to_screen(node_positions[dst]);
                ImVec2 dst_center = ImVec2(dst_screen.x + canvas_pos.x + NODE_WIDTH * topology_zoom / 2,
                                           dst_screen.y + canvas_pos.y + NODE_HEIGHT * topology_zoom / 2);
                auto [pin_pos, edge] = get_closest_edge(node_center, dst_center, node_size.x, node_size.y);
                dl->AddCircleFilled(pin_pos, PIN_RADIUS, IM_COL32(255, 200, 150, 255));
                pin_positions[node_key + "_out_" + std::to_string(output_idx)] = pin_pos;
                output_idx++;
            }
        }

        bool hovered = mouse.x >= node_pos.x && mouse.x <= node_pos.x + node_size.x && mouse.y >= node_pos.y &&
                       mouse.y <= node_pos.y + node_size.y;
        if (hovered) {
            ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
            if (ImGui::IsMouseClicked(ImGuiMouseButton_Right)) {
                selected_node = std::hash<std::string>{}(node_key);
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
            if (topology_data.topology_connection.find(hovered_node) != topology_data.topology_connection.end()) {
                const auto &entry = topology_data.topology_connection.at(hovered_node);
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
            for (const auto &[pc_id, entry] : topology_data.topology_connection) {
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
                        std::string ports_str = "Ports In: ";
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

static int draw_pc_page(const double &current_time) {
    static const float REFRESH_INTERVAL = 5;
    static double previous_time = -REFRESH_INTERVAL;

    /* This will keep information about the most recent information received from the server */
    static PCInfo pc_selected_data;
    static std::string last_pc_id = "";

    // For input fields
    static char server_ip_buf[256] = "";
    static char allowed_file_path_buf[512] = "";
    static char server_port_buf[32] = "";
    static char name_given_buf[256] = "";
    static char icon_path_buf[512] = "";
    static GLuint selected_icon_texture_id = 0;
    static char icon_path_final[512] = "";
    static char icon_path_buf_tmp[512] = "";
    static GLuint selected_icon_texture_id_tmp = 0;

    static bool request_update = false;

    static std::vector<MessageReceived> *message_history_vector;

    static std::unique_ptr<TopologyType> message_struct_info = nullptr;

    // Allowed var
    static int edit_idx = -1;
    static char edit_line_buf[512] = "";
    static std::vector<std::string> allowed_lines;
    static bool discard_allowed_changes = false;

    if (pc_id_selected.empty()) {
        ImGui::Text("No PC selected");
        return -1;
    }

    if (pc_id_selected != last_pc_id) {
        request_update = true;
    }

    if (request_update || current_time >= previous_time + REFRESH_INTERVAL) {
        previous_time = current_time;
        last_pc_id = pc_id_selected;

        if (request_update) {
            // Reset all the 'changed_' variables.
            reset_modifications();
            changed_config_mode = pc_selected_data.current_mode;

            printf("Reseted the pc_selected_data\n");
        }

        message_history_vector = get_message_history(pc_id_selected);

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
                    if (request_update || update_time_changed) {

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
                        if (selected_icon_texture_id != 0 &&
                            selected_icon_texture_id != pc_selected_data.icon_texture_id) {
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

                        changed_config_checker = false;
                        changed_general_checker = false;
                        changed_allowed_file_checker = false;
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

        if (pc_selected_data.current_mode == MONITORING) {
            message_struct_info = std::make_unique<TopologyType>(get_topology(pc_id_selected));
            printf("[TOPOLOGY] Created topology\n");
        }
    }

    if (pc_selected_data.pc_id.empty()) {
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
    ImGui::PushStyleColor(ImGuiCol_Text, get_mode_color(pc_selected_data.current_mode));
    if (ImGui::Combo("##mode_select", &changed_config_mode, MODES, 4)) {
        std::cout << "Mode changed to: " << MODES[changed_config_mode] << "\n";
        changed_config_checker = true;
    }

    ImGui::PopStyleColor();
    ImGui::Spacing();

    // Allowed File Path
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

    // ============================= Allowed file =====================================

    if (request_update || discard_allowed_changes) {

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

    ImGui::SameLine();
    if (ImGui::Button("Discard changed", ImVec2(130, 0))) {
        discard_allowed_changes = true;
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

    if (request_update == true) {
        request_update = false;
    }

    // =========================== Update configuration ===========================

    if (ImGui::Button("Update", ImVec2(100, 0))) {
        printf("server ip:%s\nserver port:%s\nallowed path:%s\nchanged config bool:%d\n",
               changed_config_server_ip.c_str(), changed_config_server_port.c_str(),
               changed_config_allowed_file_path.c_str(), changed_config_checker);

        if (changed_config_checker || changed_allowed_file_checker || changed_general_checker) {
            const std::string new_config_file = create_config_info_string();

            std::string new_allwed_file = "";
            if (pc_selected_data.current_mode == MONITORING && changed_config_mode != MONITORING &&
                message_struct_info != nullptr) {

                const auto entry = message_struct_info->topology_connection.find(pc_id_selected);
                if (entry != message_struct_info->topology_connection.end()) {
                    new_allwed_file = merge_allowed_with_topology(entry->second, allowed_lines);
                }
                message_struct_info = nullptr;
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

    if ((*message_history_vector).empty()) {
        ImGui::TextDisabled("No activity recorded");
    } else {
        for (size_t index = 0; index < message_history_vector->size(); index++) {
            const MessageReceived &msg = (*message_history_vector)[index];

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
}

// ==================================================================================================
// ============================================ Main ================================================
// ==================================================================================================

int main() {
    glfwInit();
    GLFWwindow *wnd = glfwCreateWindow(1400, 900, "Network Inspection App", nullptr, nullptr);
    glfwMakeContextCurrent(wnd);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGui::StyleColorsDark();
    ImGui_ImplGlfw_InitForOpenGL(wnd, true);
    ImGui_ImplOpenGL3_Init("#version 150");

    page = Page::MainPage;

    while (!glfwWindowShouldClose(wnd)) {
        const double frame_start = glfwGetTime();

        glfwPollEvents();
        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        ImGuiWindowFlags flags = ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize |
                                 ImGuiWindowFlags_NoBringToFrontOnFocus;

        ImGui::SetNextWindowPos(ImVec2(0, 0));
        ImGui::SetNextWindowSize(ImGui::GetIO().DisplaySize);

        ImGui::Begin("##root", nullptr, flags);

        // Create the main top buttons.
        if (ImGui::Button("Main page")) {
            page = Page::MainPage;
        }
        ImGui::SameLine();
        if (ImGui::Button("Network Topology")) {
            page = Page::Topology;
        }

        ImGui::Separator();

        // Based on the button pressed, draw the content of the page.
        switch (page) {
            case Page::MainPage:
                draw_main_page(frame_start);
                break;
            case Page::Topology:
                draw_topology(frame_start);
                break;
            case Page::ClientDetail:
                draw_pc_page(frame_start);
                break;
        }

        ImGui::End();

        ImGui::Render();
        int dw, dh;
        glfwGetFramebufferSize(wnd, &dw, &dh);
        glViewport(0, 0, dw, dh);
        glClearColor(0.05f, 0.05f, 0.08f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        glfwSwapBuffers(wnd);

        // Make the fps cap at `target_fps`.
        const double frame_end = glfwGetTime();
        const double frame_duration = frame_end - frame_start;
        if (frame_duration < TARGET_FRAME_TIME) {
            std::this_thread::sleep_for(std::chrono::duration<double>(TARGET_FRAME_TIME - frame_duration));
        }
    }

    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();
    glfwDestroyWindow(wnd);
    glfwTerminate();
    return 0;
}
