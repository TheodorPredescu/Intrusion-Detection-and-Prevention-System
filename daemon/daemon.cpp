#include <arpa/inet.h>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <curl/curl.h>
#include <deque>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <netinet/in.h>
#include <signal.h>
#include <sstream>
#include <string>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>
#include <vector>

#include "daemon.h"
#include "json.hpp"
using json = nlohmann::json;

static bool running = true;

class ConfigDaemon {
  private:
    std::string config_file = "/etc/mymodule.conf";
    std::string pc_id_file = "/etc/mymodule_id";
    std::string pc_id = "";
    std::string allowed_file;
    int module_fd = -1;

    time_t last_config_mtime = 0;
    time_t last_allowed_mtime = 0;

    uint32_t current_server_ip = 0;
    std::string current_server_ip_str = "";
    uint16_t current_server_port = 0;
    std::string current_server_port_str = "";
    uint8_t current_state = DISABLED;

    const char *STATE_NAMES[4] = {"LISTENING", "MONITORING", "REACTIVE", "DISABLED"};

  public:
    ConfigDaemon() {
    }

    ~ConfigDaemon() {
        if (module_fd >= 0) {
            close(module_fd);
        }
    }

    bool init() {
        // Open /dev/mymodule
        module_fd = open("/dev/mymodule", O_RDWR);
        if (module_fd < 0) {
            std::cerr << "[DAEMON] Failed to open /dev/mymodule: " << strerror(errno) << "\n";
            return false;
        }
        std::cout << "[DAEMON] Connected to kernel module via /dev/mymodule\n";

        std::ifstream infile(pc_id_file);

        if (infile.is_open()) {
            // File exists → read first line
            if (std::getline(infile, pc_id) && !pc_id.empty()) {
                // Trim trailing whitespace
                pc_id.erase(pc_id.find_last_not_of(" \t\r\n") + 1);

                std::cout << "[DAEMON] Loaded PC ID: " << pc_id << "\n";
                return true;
            }

            std::cout << "[DAEMON] PC ID file exists but is empty\n";
            return true;
        }

        // File does not exist → create it
        std::ofstream outfile(pc_id_file);
        if (!outfile.is_open()) {
            std::cerr << "[DAEMON] Failed to create PC ID file: " << pc_id_file << "\n";
            return false;
        }

        std::cout << "[DAEMON] Created PC ID file: " << pc_id_file << "\n";
        return true;
    }

    time_t get_mtime(const std::string &path) {
        struct stat st;
        if (stat(path.c_str(), &st) < 0) {
            return 0;
        }
        return st.st_mtime;
    }

    bool parse_config() {
        std::ifstream file(config_file);
        if (!file.is_open()) {
            std::cerr << "[DAEMON] Cannot open config file: " << config_file << "\n";
            return false;
        }

        std::string line;
        //  Those will be in `__be` format saved.
        uint32_t parsed_ip = 0;

        // Those will be in `__be` format saved.
        uint16_t parsed_port = 0;
        uint8_t parsed_state = DISABLED;
        std::string parsed_allowed_file;

        while (std::getline(file, line)) {
            // Ignore empty lines and commented lines (#)
            if (line.empty() || line[0] == '#') {
                continue;
            }

            // Parse "server IP x.x.x.x"
            if (line.find("server IP") == 0) {
                unsigned int a, b, c, d;
                sscanf(line.c_str(), "server IP %u.%u.%u.%u", &a, &b, &c, &d);
                parsed_ip = htonl((a << 24) | (b << 16) | (c << 8) | d);
                std::cout << "[DAEMON] Parsed" << line << "\n";
            }
            // Parse "server port xxx"
            else if (line.find("server port") == 0) {
                uint16_t port;
                sscanf(line.c_str(), "server port %hu", &port);
                parsed_port = port;
                std::cout << "[DAEMON] Parsed server port: " << parsed_port << "\n";
            }
            // Parse allowed file path
            else if (line.find("allowed_file") == 0) {
                // Skip "allowed_file" (12 characters)
                size_t pos = 12;

                // Skip whitespace after the keyword
                pos = line.find_first_not_of(" \t", pos);
                if (pos == std::string::npos) {
                    std::cout << "[DAEMON] No path found after allowed_file\n";
                    continue;
                }

                // Take the rest of the line
                std::string path = line.substr(pos);

                // Optional: remove trailing whitespace
                size_t end = path.find_last_not_of(" \t\r\n");
                if (end != std::string::npos) {
                    path.erase(end + 1);
                }

                parsed_allowed_file = std::move(path);

                std::cout << "[DAEMON] Parsed allowed_file: \"" << parsed_allowed_file << "\"\n";

            } else {
                std::string trimmed_line = line;
                size_t first = line.find_first_not_of(" \t\r\n");
                size_t last = line.find_last_not_of(" \t\r\n");

                if (first != std::string::npos && last != std::string::npos) {
                    trimmed_line = line.substr(first, last - first + 1);
                }

                for (size_t i = 0; i < trimmed_line.length(); ++i) {
                    trimmed_line[i] = static_cast<char>(std::tolower(static_cast<unsigned char>(trimmed_line[i])));
                }

                if (trimmed_line == "listening") {
                    parsed_state = LISTENING;
                    std::cout << "[DAEMON] state changed to " << STATE_NAMES[parsed_state] << "\n";
                } else if (trimmed_line == "monitoring") {
                    parsed_state = MONITORING;
                    std::cout << "[DAEMON] state changed to " << STATE_NAMES[parsed_state] << "\n";
                } else if (trimmed_line == "reactive") {
                    parsed_state = REACTIVE;
                    std::cout << "[DAEMON] state changed to " << STATE_NAMES[parsed_state] << "\n";
                } else if (trimmed_line == "disabled") {
                    parsed_state = DISABLED;
                    std::cout << "[DAEMON] state changed to " << STATE_NAMES[parsed_state] << "\n";
                }
            }
        }

        file.close();

        // Check if anything changed
        if (parsed_ip != current_server_ip || parsed_port != current_server_port) {

            uint32_t host_ip = ntohl(parsed_ip);

            uint8_t a = (host_ip >> 24) & 0xFF;
            uint8_t b = (host_ip >> 16) & 0xFF;
            uint8_t c = (host_ip >> 8) & 0xFF;
            uint8_t d = (host_ip >> 0) & 0xFF;

            current_server_ip_str =
                std::to_string(a) + "." + std::to_string(b) + "." + std::to_string(c) + "." + std::to_string(d);
            current_server_port_str = std::to_string(parsed_port);

            current_server_ip = parsed_ip;
            current_server_port = parsed_port;

            server_info_ioctl info;
            info.server_ip = parsed_ip;
            info.server_port = parsed_port;

            if (ioctl(module_fd, IOCTL_SET_SERVER_INFO, &info) < 0) {
                std::cerr << "[DAEMON] ioctl SET_SERVER_INFO failed: " << strerror(errno) << "\n";
            } else {
                std::cout << "[DAEMON] ✓ Sent server info to kernel\n";
            }
        }

        if (parsed_state != current_state) {
            current_state = parsed_state;
            std::cout << "[DAEMON] Atempting to change the state on server to : " << STATE_NAMES[parsed_state] << "\n";

            if (ioctl(module_fd, IOCTL_SET_STATE, &parsed_state) < 0) {
                std::cerr << "[DAEMON] ioctl SET_STATE failed: " << strerror(errno) << "\n";
            } else {
                std::cout << "[DAEMON] ✓ State changed to: " << STATE_NAMES[parsed_state] << "\n";
            }
        }

        if (!parsed_allowed_file.empty() && parsed_allowed_file != allowed_file) {
            allowed_file = parsed_allowed_file;
            std::cout << "[DAEMON] Allowed file path updated: " << allowed_file << "\n";
        }

        return true;
    }

    bool parse_allowed_file() {
        if (allowed_file.empty()) {
            std::cout << "[DAEMON] No allowed_file specified\n";
            return true;
        }

        std::ifstream file(allowed_file);
        if (!file.is_open()) {
            std::cout << "[DAEMON] Cannot open allowed_file: " << allowed_file << " (creating empty)\n";
            return true; // Not fatal
        }

        // Clear old whitelist
        if (ioctl(module_fd, IOCTL_CLEAR_WHITELIST) < 0) {
            std::cerr << "[DAEMON] ioctl CLEAR_WHITELIST failed: " << strerror(errno) << "\n";
            return false;
        }

        std::string line;
        int entries_added = 0;

        while (std::getline(file, line)) {
            // Comments on #
            if (line.empty() || line[0] == '#') {
                continue;
            }

            allowed_entry_ioctl entry;
            memset(&entry, 0, sizeof(entry));

            // Parse "1.2.3.4:80,443" or "1.2.3.4"
            size_t colon_pos = line.find(':');

            if (colon_pos != std::string::npos) {
                // Has ports
                std::string ip_str = line.substr(0, colon_pos);
                std::string ports_str = line.substr(colon_pos + 1);

                unsigned int a, b, c, d;
                if (sscanf(ip_str.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) != 4) {
                    continue;
                }

                entry.ip = htonl((a << 24) | (b << 16) | (c << 8) | d);

                // Parse ports
                std::stringstream ss(ports_str);
                std::string port_str;
                while (std::getline(ss, port_str, ',')) {
                    if (entry.port_count >= MAX_ALLOWED_DEFINITION_FILE) {
                        break;
                    }
                    uint16_t port = std::stoi(port_str);
                    entry.ports[entry.port_count++] = port;
                }
            } else {
                // Just IP, no ports (allow any)
                unsigned int a, b, c, d;
                if (sscanf(line.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) != 4) {
                    continue;
                }

                entry.ip = htonl((a << 24) | (b << 16) | (c << 8) | d);
                entry.port_count = 0; // Allow any port
            }

            if (ioctl(module_fd, IOCTL_ADD_WHITELIST, &entry) < 0) {
                std::cerr << "[DAEMON] ioctl ADD_WHITELIST failed: " << strerror(errno) << "\n";
                return false;
            }
            entries_added++;
        }

        file.close();
        std::cout << "[DAEMON] ✓ Loaded " << entries_added << " whitelist entries\n";
        return true;
    }

    bool save_pc_id_to_file() {
        std::ofstream file(pc_id_file, std::ios::trunc);
        if (!file.is_open()) {
            return false;
        }

        file << pc_id << "\n";
        return true;
    }

    bool extract_and_store_pc_id(const std::string &response) {
        const std::string key = "\"pc_id\"";
        size_t pos = response.find(key);
        if (pos == std::string::npos) {
            return false;
        }

        size_t start = response.find('"', pos + key.length());
        if (start == std::string::npos) {
            return false;
        }

        start++; // move past first quote

        size_t end = response.find('"', start);
        if (end == std::string::npos) {
            return false;
        }

        std::string new_id = response.substr(start, end - start);

        if (new_id.empty()) {
            return false;
        }

        if (new_id == pc_id) {
            return true;
        }

        pc_id = new_id;

        if (!save_pc_id_to_file()) {
            std::cerr << "[DAEMON] Failed to persist PC ID\n";
            return false;
        }

        std::cout << "[DAEMON] Registered PC ID: " << pc_id << "\n";
        return true;
    }

    void send_to_backend(const std::vector<packet_data> &packets) {
        static std::deque<packet_data> pending_packets;
        static const size_t MAX_PENDING = 1000;

        if (packets.empty() && pending_packets.empty()) {
            return;
        }

        std::vector<packet_data> to_send;
        to_send.reserve(pending_packets.size() + packets.size());
        to_send.insert(to_send.end(), pending_packets.begin(), pending_packets.end());
        to_send.insert(to_send.end(), packets.begin(), packets.end());

        json payload = json::object();
        // Build JSON manually as string

        if (!pc_id.empty()) {
            payload["pc_id"] = pc_id;
        }

        json packets_array = json::array();
        for (const auto &pkt : to_send) {
            char saddr[16], daddr[16];
            inet_ntop(AF_INET, &pkt.saddr, saddr, sizeof(saddr));
            inet_ntop(AF_INET, &pkt.daddr, daddr, sizeof(daddr));

            // Format MACs
            char src_mac_str[18], dst_mac_str[18];
            snprintf(src_mac_str, sizeof(src_mac_str), "%02x:%02x:%02x:%02x:%02x:%02x", pkt.src_mac[0], pkt.src_mac[1],
                     pkt.src_mac[2], pkt.src_mac[3], pkt.src_mac[4], pkt.src_mac[5]);
            snprintf(dst_mac_str, sizeof(dst_mac_str), "%02x:%02x:%02x:%02x:%02x:%02x", pkt.dst_mac[0], pkt.dst_mac[1],
                     pkt.dst_mac[2], pkt.dst_mac[3], pkt.dst_mac[4], pkt.dst_mac[5]);

            json packet_obj = {{"saddr", saddr},
                               {"daddr", daddr},
                               {"sport", ntohs(pkt.sport)},
                               {"dport", ntohs(pkt.dport)},
                               {"protocol", pkt.protocol},
                               {"ttl", pkt.ttl},
                               {"packet_len", pkt.total_len},
                               {"tcp_flags", pkt.tcp_flags},
                               {"iface", std::string(pkt.indev)},
                               {"src_mac", src_mac_str},
                               {"dst_mac", dst_mac_str},
                               {"mode", current_state}};

            packets_array.push_back(std::move(packet_obj));
        }

        payload["packets"] = std::move(packets_array);
        std::string json_str = payload.dump();

        CURL *curl = curl_easy_init();
        if (!curl) {
            return;
        }

        const std::string base_url = "http://" + current_server_ip_str + ":" + current_server_port_str + "/packets";
        curl_easy_setopt(curl, CURLOPT_URL, base_url.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_str.c_str());

        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        std::string response;

        curl_easy_setopt(
            curl, CURLOPT_WRITEFUNCTION, +[](char *ptr, size_t size, size_t nmemb, void *userdata) -> size_t {
                auto *resp = static_cast<std::string *>(userdata);
                resp->append(ptr, size * nmemb);
                return size * nmemb;
            });

        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

        CURLcode res = curl_easy_perform(curl);
        if (res == CURLE_OK) {
            std::cout << "[DAEMON] ✓ Sent " << packets.size() << " packets";

            if (!pending_packets.empty()) {
                std::cout << " (including " << pending_packets.size() << " retried)";
            }
            printf("\n");
            pending_packets.clear();

            if (!response.empty()) {
                std::cout << "[DAEMON] Backend response: " << response << "\n";
                extract_and_store_pc_id(response);
            }
        } else {
            std::cerr << "[DAEMON] Failed: " << curl_easy_strerror(res) << "\n";

            // Save for retry, but cap the buffer
            for (const auto &pkt : packets) {
                if (pending_packets.size() >= MAX_PENDING) {
                    std::cerr << "[DAEMON] Pending buffer full (" << MAX_PENDING << "), dropping oldest packet\n";
                    pending_packets.pop_front();
                }
                pending_packets.push_back(pkt);
            }
            std::cout << "[DAEMON] Queued for retry: " << pending_packets.size() << " packets total\n";
        }

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    }

    bool send_configuration_profile(const bool config_changed, const bool allowed_changed) {

        if (config_changed == false && allowed_changed == false) {
            std::cerr << "[DAEMON] Tried to send modified files, but none were modified.\n";
            return false;
        }

        json payload = json::object();
        // Build JSON manually as string

        if (pc_id.empty()) {
            return false;
        }

        if (config_changed) {
            std::ifstream config_file_handle(config_file);

            if (!config_file_handle.is_open()) {
                std::cerr << "[DAEMON] Cannot open config file: " << config_file << "\n";
                return false;
            }

            std::ostringstream ss;

            ss << config_file_handle.rdbuf();
            payload["config_file"] = ss.str();
            payload["current_mode"] = current_state;
        }

        if (allowed_changed) {
            std::ifstream allowed_file_handle(allowed_file);

            if (!allowed_file_handle.is_open()) {
                std::cerr << "[DAEMON] Cannot open allowed file: " << allowed_file << "\n";
                return false;
            }

            std::ostringstream ss;
            ss << allowed_file_handle.rdbuf();
            payload["allowed_file"] = ss.str();
        }

        std::string json_str = payload.dump();

        CURL *curl = curl_easy_init();
        if (!curl) {
            return false;
        }

        const std::string base_url =
            "http://" + current_server_ip_str + ":" + current_server_port_str + "/config/user?pc_id=" + pc_id;
        curl_easy_setopt(curl, CURLOPT_URL, base_url.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_str.c_str());

        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        std::string response;

        curl_easy_setopt(
            curl, CURLOPT_WRITEFUNCTION, +[](char *ptr, size_t size, size_t nmemb, void *userdata) -> size_t {
                auto *resp = static_cast<std::string *>(userdata);
                resp->append(ptr, size * nmemb);
                return size * nmemb;
            });

        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

        CURLcode res = curl_easy_perform(curl);
        if (res == CURLE_OK) {
            std::cout << "[DAEMON] ✓ new config send to the server.\n";
        } else {
            std::cerr << "[DAEMON] Failed: " << curl_easy_strerror(res) << "\n";
            return false;
        }

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        return true;
    }

    void interruptible_sleep(int seconds) {
        for (int i = 0; i < seconds; i++) {
            if (!running) {
                break;
            }
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }

    void run_config_loop() {
        std::cout << "[DAEMON] Starting config monitor...\n";
        while (running) {
            bool entered_config = false;
            bool entered_allowed_file = false;

            time_t config_mtime = get_mtime(config_file);

            if (config_mtime > last_config_mtime) {
                std::cout << "[DAEMON] Config file changed, reloading...\n";
                if (parse_config()) {
                    entered_config = true;
                }
            }

            time_t allowed_mtime = get_mtime(allowed_file);
            if (allowed_mtime > last_allowed_mtime && !allowed_file.empty()) {
                std::cout << "[DAEMON] Whitelist file changed, reloading...\n";
                if (parse_allowed_file()) {
                    entered_allowed_file = true;
                }
            }

            if (entered_config || entered_allowed_file) {
                if (send_configuration_profile(entered_config, entered_allowed_file)) {
                    last_config_mtime = config_mtime;
                    last_allowed_mtime = allowed_mtime;
                }
            }

            interruptible_sleep(15);
        }
        std::cout << "[DAEMON] Config monitor exiting\n";
    }

    void run_packet_loop() {
        std::cout << "[DAEMON] Starting packet collector...\n";
        while (running) {
            packet_batch batch;
            memset(&batch, 0, sizeof(batch));

            if (ioctl(module_fd, IOCTL_GET_PACKETS, &batch) < 0) {
                std::cerr << "[DAEMON] ioctl GET_PACKETS failed\n";
            } else if (batch.count > 0) {
                std::cout << "[DAEMON] Got " << batch.count << " packets\n";
                std::vector<packet_data> pkts(batch.packets, batch.packets + batch.count);
                send_to_backend(pkts);
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        std::cout << "[DAEMON] Packet collector exiting\n";
    }

    void run_request_to_change_config_loop() {
        std::cout << "[DAEMON] Starting listening to request to change from server...\n";

        while (running) {

            if (pc_id.empty()) {
                interruptible_sleep(10);
                continue;
            }

            CURL *curl = curl_easy_init();
            if (!curl) {
                interruptible_sleep(10);
                continue;
            }

            const std::string base_url =
                "http://" + current_server_ip_str + ":" + current_server_port_str + "/config/user?pc_id=" + pc_id;
            curl_easy_setopt(curl, CURLOPT_URL, base_url.c_str());
            curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);

            struct curl_slist *headers = nullptr;
            headers = curl_slist_append(headers, "Accept: application/json");
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

            std::string response;

            curl_easy_setopt(
                curl, CURLOPT_WRITEFUNCTION, +[](char *ptr, size_t size, size_t nmemb, void *userdata) -> size_t {
                    auto *resp = static_cast<std::string *>(userdata);
                    resp->append(ptr, size * nmemb);
                    return size * nmemb;
                });

            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

            CURLcode res = curl_easy_perform(curl);
            if (res == CURLE_OK) {
                std::cout << "[DAEMON] received connection\n";
                if (!response.empty()) {
                    try {
                        json resp_json = json::parse(response);

                        // Example: server returns new config content
                        if (resp_json.contains("config_file") && resp_json["config_file"].is_string()) {
                            std::string new_config = resp_json["config_file"].get<std::string>();

                            if (new_config.empty()) {
                                std::cerr << "[DAEMON] Server sent empty config → refusing to overwrite\n";
                            } else {
                                // Write to disk and reload
                                std::string tmp_path = config_file + ".tmp";
                                std::string old_path = config_file + ".old";

                                std::ofstream tmp_file(tmp_path, std::ios::trunc);
                                std::cout << "[DAEMON] Updating config file from server\n";

                                if (tmp_file.is_open()) {
                                    tmp_file << new_config << std::flush;

                                    if (tmp_file.fail()) {
                                        std::cerr << "[DAEMON] Write to temp file failed: " << tmp_path << "\n";
                                        tmp_file.close();
                                        std::remove(tmp_path.c_str());
                                        continue;
                                    }

                                    tmp_file.close();

                                    std::remove(old_path.c_str());
                                    bool backup = false;

                                    if (std::rename(config_file.c_str(), old_path.c_str()) == 0) {
                                        backup = true;
                                    }

                                    if (std::rename(tmp_path.c_str(), config_file.c_str()) == 0) {
                                        std::cout << "[DAEMON] new config file added\n";
                                        std::remove(tmp_path.c_str());

                                    } else {
                                        std::cout << "[DAEMON] failed to add a new allowed file\n";

                                        if (backup) {
                                            std::rename(old_path.c_str(), config_file.c_str());
                                            std::remove(tmp_path.c_str());
                                        }
                                    }
                                } else {
                                    std::remove(tmp_path.c_str());
                                }
                            }
                        }

                        // Same for allowed file
                        if (resp_json.contains("allowed_file") && resp_json["allowed_file"].is_string()) {
                            std::string new_allowed_conf = resp_json["allowed_file"].get<std::string>();

                            if (!allowed_file.empty() && !new_allowed_conf.empty()) {

                                // Write to disk and reload
                                std::string tmp_path = allowed_file + ".tmp";
                                std::string old_path = allowed_file + ".old";

                                std::ofstream tmp_file(tmp_path, std::ios::trunc);
                                std::cout << "[DAEMON] Updating allowed file from server\n";

                                if (tmp_file.is_open()) {
                                    tmp_file << new_allowed_conf << std::flush;

                                    if (tmp_file.fail()) {
                                        std::cerr << "[DAEMON] Write to temp file failed: " << tmp_path << "\n";
                                        tmp_file.close();
                                        std::remove(tmp_path.c_str());
                                        continue;
                                    }

                                    tmp_file.close();

                                    std::remove(old_path.c_str());
                                    bool backup = false;

                                    if (std::rename(allowed_file.c_str(), old_path.c_str()) == 0) {
                                        backup = true;
                                    }

                                    if (std::rename(tmp_path.c_str(), allowed_file.c_str()) == 0) {
                                        std::cout << "[DAEMON] new allowed file added\n";
                                        std::remove(tmp_path.c_str());
                                    } else {
                                        std::cout << "[DAEMON] failed to add a new allowed file\n";

                                        if (backup) {
                                            std::rename(old_path.c_str(), allowed_file.c_str());
                                            std::remove(tmp_path.c_str());
                                        }
                                    }
                                } else {
                                    std::remove(tmp_path.c_str());
                                }
                            }
                        }
                    } catch (const json::exception &e) {
                        std::cerr << "[DAEMON] Failed to parse config response: " << e.what() << "\n";
                    }
                }
            } else {
                std::cerr << "[DAEMON] Failed: " << curl_easy_strerror(res) << "\n";
            }

            curl_slist_free_all(headers);
            curl_easy_cleanup(curl);

            interruptible_sleep(10);
        }

        std::cout << "[DAEMON] Config update request loop exiting\n";
    }
};

void signal_handler(int sig) {
    std::cout << "\n[DAEMON] Shutting down...\n";
    running = false;
}

int main(int argc, char *argv[]) {
    signal(SIGINT, signal_handler);  // Ctrl+C
    signal(SIGTERM, signal_handler); // systemctl stop

    ConfigDaemon daemon;

    if (!daemon.init()) {
        std::cerr << "[DAEMON] Initialization failed\n";
        return 1;
    }

    // Start watching for changes
    std::thread config_thread(&ConfigDaemon::run_config_loop, &daemon);
    std::thread packet_thread(&ConfigDaemon::run_packet_loop, &daemon);
    std::thread change_thread(&ConfigDaemon::run_request_to_change_config_loop, &daemon);

    config_thread.join();
    packet_thread.join();
    change_thread.join();

    std::cout << "[DAEMON] Exited cleanly\n";
    return 0;
}
