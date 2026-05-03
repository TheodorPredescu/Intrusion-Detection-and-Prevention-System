#include <GL/gl.h>
#include <cstdio>
#define STB_IMAGE_IMPLEMENTATION
#include "stb_image.h"
#include <curl/curl.h>
#include <fstream>
#include <iostream>
#include <regex>

#include "types.h"
#include "utils.h"

#include "../daemon/json.hpp"
using json = nlohmann::json;

std::string pc_id_selected = "";
Page page;
ImVec2 topology_pan = ImVec2(0.0f, 0.0f);
float topology_zoom = 1.0f;

const float ZOOM_MIN = 0.3f;
const float ZOOM_MAX = 3.0f;

GLuint load_image_as_texture(const char *filename) {

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

GLuint load_texture_from_memory(const std::vector<uint8_t> &data) {

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

std::vector<uint8_t> read_file_as_bytes(const std::string &path) {
    std::ifstream file(path, std::ios::binary);
    return std::vector<uint8_t>(std::istreambuf_iterator<char>(file), {});
}

std::string base64_encode(const std::vector<uint8_t> &data) {
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

std::vector<uint8_t> base64_decode(const std::string &encoded) {
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

bool fetch_pc_list_config_from_api(std::string &out) {
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

bool fetch_pc_config_from_api(const std::string &pc_id, std::string &out) {

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

bool fetch_logs_from_api(const std::string &pc_id, const int limit, std::string &out) {
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

bool fetch_topology_info_from_api(const std::string &pc_id, std::string &out) {

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

bool send_config_via_api(const std::string &pc_id, const std::string &config_file, const std::string allowed_file,
                         const std::string name, const std::string icon_path) {
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

bool reset_topology_connections() {
    CURL *curl = curl_easy_init();
    if (!curl) {
        std::cerr << "Failed to initialize CURL\n";
        return false;
    }

    std::string base_url = "http://127.0.0.1:8080/topology/reset";

    // Set up headers
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, base_url.c_str());
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "POST");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 2L);

    std::string response;
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    CURLcode res = curl_easy_perform(curl);
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

    bool success = (res == CURLE_OK && http_code >= 200 && http_code < 300);

    if (!success) {
        std::cerr << "CURL error: " << curl_easy_strerror(res) << " | HTTP: " << http_code << "\n";
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

std::map<std::string, ImVec2> compute_graph_layout(const std::set<std::string> &all_ips,
                                                   const std::map<std::string, std::set<std::string>> &connections) {
    std::map<std::string, ImVec2> positions;

    // Get temp directory (cross-platform)
    std::string temp_dir;
#ifdef _WIN32
    char temp_path[MAX_PATH];
    GetTempPathA(MAX_PATH, temp_path);
    temp_dir = temp_path;
#elif __linux__
    temp_dir = "/tmp/";
#endif

    std::string dot_file_path = temp_dir + "graph.dot";
    std::string txt_file_path = temp_dir + "graph.txt";

    // Generate dot
    // std::string dot = "digraph G {\nrankdir=LR;\nnode [shape=box];\n";
    // dot += "graph [overlap=false];\n";
    // for (const auto &ip : all_ips) {
    //     dot += "  \"" + ip + "\";\n";
    // }
    // for (const auto &[src, dests] : connections) {
    //     for (const auto &dst : dests) {
    //         dot += "  \"" + src + "\" -> \"" + dst + "\";\n";
    //     }
    // }
    // dot += "}\n";

    // Generate dot
    std::string dot = "graph G {\n"; // digraph -> graph (undirected)
    dot += "node [shape=box];\n";
    // dot += "graph [overlap=false];\n";
    dot += "graph [overlap=false, sep=\"1\", K=0.1];\n";
    // removed rankdir=LR — that's dot-specific and meaningless for neato/fdp
    for (const auto &ip : all_ips) {
        dot += "  \"" + ip + "\";\n";
    }
    for (const auto &[src, dests] : connections) {
        for (const auto &dst : dests) {
            dot += "  \"" + src + "\" -- \"" + dst + "\";\n"; // -> becomes --
        }
    }
    dot += "}\n";

    std::ofstream dot_file(dot_file_path);
    dot_file << dot;
    dot_file.close();

    // Run graphviz (quote paths for Windows)
    // #ifdef _WIN32
    //     std::string cmd = "neato -Tplain \"" + dot_file_path + "\" -o \"" + txt_file_path + "\"";
    // #else
    //     std::string cmd = "neato -Tplain " + dot_file_path + " -o " + txt_file_path + " 2>/dev/null";
    // #endif

#ifdef _WIN32
    std::string cmd = "fdp -Tplain -Gstart=2 \"" + dot_file_path + "\" -o \"" + txt_file_path + "\"";
#else
    std::string cmd = "fdp -Tplain -Gstart=2 " + dot_file_path + " -o " + txt_file_path + " 2>/dev/null";
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

std::string get_protocol_name(const int protocol) {
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

ImVec4 get_mode_color(const int mode) {
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

uint get_mode_background_color(const int mode, const bool blink_visible) {
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

const char *const get_mode_name(const int mode) {
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
int extract_current_state(const std::string &config_file) {

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

bool valid_mode(const int &mode) {
    return mode >= 0 && mode <= DISABLED;
}

std::string config_change_state(const std::string &config_file, const int &state) {

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

void extract_config_info(const std::string &text, std::string &server_ip, std::string &server_port,
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

std::map<std::string, PCInfo> *get_pc_info() {
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

std::vector<MessageReceived> *get_message_history(const std::string &pc_id, std::map<std::string, PCInfo> *pc_map,
                                                  const int limit) {
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

std::map<std::string, TopologyEntry> get_topology(const std::string pc_id) {
    std::map<std::string, TopologyEntry> topology_map;
    std::string topology_str;

    if (fetch_topology_info_from_api(pc_id, topology_str)) {
        try {
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

                    topology_map[pc_id] = entry;
                }
            }
        } catch (const std::exception &e) {
            std::cerr << "JSON parse error for topology: " << e.what() << "\n";
        }
    }

    return topology_map;
}

bool add_entity_in_allowed(std::vector<std::string> &allowed_lines, const MessageReceived &msg) {

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

    std::istringstream iss(found_line->substr(colon_pos + 1));
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
        *found_line += ", " + std::to_string(msg.src_port);
        return true;
    }

    return false;
}

// TODO: This needs to get checked
std::map<std::string, std::set<int>> extract_allowed_ips(const std::string &allowed_file) {

    std::map<std::string, std::set<int>> allowed_ip_map;

    std::istringstream iss(allowed_file);
    std::string line;

    while (std::getline(iss, line)) {

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

    return allowed_ip_map;
}

std::string merge_allowed_with_topology(const TopologyEntry &information,
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

std::string merge_allowed_with_ports_map(const std::string &allowed_file,
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

std::string transform_messages_to_str(const MessageReceived &message,
                                      const std::map<std::string, PCInfo> *const pc_map) {

    std::string name = "";
    if (pc_map != nullptr && !message.pc_id.empty()) {
        const auto it = pc_map->find(message.pc_id);
        if (it != pc_map->end() && !it->second.name.empty()) {
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
void calculate_zoom_and_drag() {

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
ImVec2 to_screen(const ImVec2 &world) {
    return ImVec2(world.x * topology_zoom + topology_pan.x, world.y * topology_zoom + topology_pan.y);
}
