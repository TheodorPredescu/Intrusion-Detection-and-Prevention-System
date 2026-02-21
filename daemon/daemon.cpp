#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <curl/curl.h>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <signal.h>
#include <sstream>
#include <string>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>
#include <vector>

#include "daemon.h"

static bool running = true;

class ConfigDaemon {
  private:
    std::string config_file = "/etc/mymodule.conf";
    std::string allowed_file;
    int module_fd = -1;

    time_t last_config_mtime = 0;
    time_t last_allowed_mtime = 0;

    uint32_t current_server_ip = 0;
    uint16_t current_server_port = 0;
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

        last_config_mtime = get_mtime(config_file);

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
                std::cout << "[DAEMON] Parsed server IP\n";
            }
            // Parse "server port xxx"
            else if (line.find("server port") == 0) {
                uint16_t port;
                sscanf(line.c_str(), "server port %hu", &port);
                parsed_port = port;
                std::cout << "[DAEMON] Parsed server port: " << parsed_port << "\n";
            }
            // Parse state
            else if (line == "Listening") {
                parsed_state = LISTENING;
            } else if (line == "Monitoring") {
                parsed_state = MONITORING;
            } else if (line == "Reactive") {
                parsed_state = REACTIVE;
            } else if (line == "Disabled") {
                parsed_state = DISABLED;
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
            }
        }

        file.close();

        // Check if anything changed
        if (parsed_ip != current_server_ip || parsed_port != current_server_port) {
            current_server_ip = parsed_ip;
            current_server_port = parsed_port;

            server_info_ioctl info;
            info.server_ip = parsed_ip;
            info.server_port = parsed_port;

            if (ioctl(module_fd, IOCTL_SET_SERVER_INFO, &info) < 0) {
                std::cerr << "[DAEMON] ioctl SET_SERVER_INFO failed: " << strerror(errno) << "\n";
                return false;
            }
            std::cout << "[DAEMON] ✓ Sent server info to kernel\n";
        }

        if (parsed_state != current_state) {
            current_state = parsed_state;

            if (ioctl(module_fd, IOCTL_SET_STATE, &parsed_state) < 0) {
                std::cerr << "[DAEMON] ioctl SET_STATE failed: " << strerror(errno) << "\n";
                return false;
            }
            std::cout << "[DAEMON] ✓ State changed to: " << STATE_NAMES[parsed_state] << "\n";
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

        last_allowed_mtime = get_mtime(allowed_file);

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

    void send_to_backend(const std::vector<packet_data> &packets) {
        if (packets.empty()) {
            return;
        }

        // Build JSON manually as string
        std::string json = "{\"packets\":[";
        for (size_t i = 0; i < packets.size(); i++) {
            if (i > 0) {
                json += ",";
            }

            char saddr[16], daddr[16];
            inet_ntop(AF_INET, &packets[i].saddr, saddr, sizeof(saddr));
            inet_ntop(AF_INET, &packets[i].daddr, daddr, sizeof(daddr));

            // Format MAC addresses as XX:XX:XX:XX:XX:XX
            char src_mac_str[18], dst_mac_str[18];
            snprintf(src_mac_str, sizeof(src_mac_str), "%02x:%02x:%02x:%02x:%02x:%02x", packets[i].src_mac[0],
                     packets[i].src_mac[1], packets[i].src_mac[2], packets[i].src_mac[3], packets[i].src_mac[4],
                     packets[i].src_mac[5]);
            snprintf(dst_mac_str, sizeof(dst_mac_str), "%02x:%02x:%02x:%02x:%02x:%02x", packets[i].dst_mac[0],
                     packets[i].dst_mac[1], packets[i].dst_mac[2], packets[i].dst_mac[3], packets[i].dst_mac[4],
                     packets[i].dst_mac[5]);

            json += "{\"saddr\":\"" + std::string(saddr) + "\"," + "\"daddr\":\"" + std::string(daddr) + "\"," +
                    "\"sport\":" + std::to_string(ntohs(packets[i].sport)) + "," +
                    "\"dport\":" + std::to_string(ntohs(packets[i].dport)) + "," +
                    "\"protocol\":" + std::to_string(packets[i].protocol) + "," +
                    "\"ttl\":" + std::to_string(packets[i].ttl) + "," +
                    "\"packet_len\":" + std::to_string(packets[i].total_len) + "," +
                    "\"tcp_flags\":" + std::to_string(packets[i].tcp_flags) + "," + "\"iface\":\"" +
                    std::string(packets[i].indev) + "\"," + "\"src_mac\":\"" + std::string(src_mac_str) + "\"," +
                    "\"dst_mac\":\"" + std::string(dst_mac_str) + "\"}";
        }
        json += "]}";

        CURL *curl = curl_easy_init();
        if (!curl) {
            return;
        }

        curl_easy_setopt(curl, CURLOPT_URL, "http://127.0.0.1:8080/packets");
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json.c_str());

        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        CURLcode res = curl_easy_perform(curl);
        if (res == CURLE_OK) {
            std::cout << "[DAEMON] ✓ Sent " << packets.size() << " packets\n";
        } else {
            std::cerr << "[DAEMON] Failed: " << curl_easy_strerror(res) << "\n";
        }

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    }

    void run_config_loop() {
        std::cout << "[DAEMON] Starting config monitor...\n";
        while (running) {
            time_t config_mtime = get_mtime(config_file);
            if (config_mtime > last_config_mtime) {
                std::cout << "[DAEMON] Config file changed, reloading...\n";
                if (parse_config()) {
                    last_config_mtime = config_mtime;
                }
            }

            time_t allowed_mtime = get_mtime(allowed_file);
            if (allowed_mtime > last_allowed_mtime && !allowed_file.empty()) {
                std::cout << "[DAEMON] Whitelist file changed, reloading...\n";
                if (parse_allowed_file()) {
                    last_allowed_mtime = allowed_mtime;
                }
            }

            std::this_thread::sleep_for(std::chrono::seconds(5));
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

            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
        std::cout << "[DAEMON] Packet collector exiting\n";
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

    // Initial load
    if (!daemon.parse_config()) {
        std::cerr << "[DAEMON] Failed to parse config\n";
        return 1;
    }

    if (!daemon.parse_allowed_file()) {
        std::cerr << "[DAEMON] Failed to parse allowed file\n";
        return 1;
    }

    // Start watching for changes
    std::thread config_thread(&ConfigDaemon::run_config_loop, &daemon);
    std::thread packet_thread(&ConfigDaemon::run_packet_loop, &daemon);

    config_thread.join();
    packet_thread.join();

    std::cout << "[DAEMON] Exited cleanly\n";
    return 0;
}
