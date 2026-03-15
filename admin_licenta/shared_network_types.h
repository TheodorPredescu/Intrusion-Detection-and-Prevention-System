#ifndef SHARED_NETWORK_TYPES_H
#define SHARED_NETWORK_TYPES_H

#include "imgui.h"
#include <atomic>
#include <libssh/libssh.h>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

// Forward declaration (enough for pointer usage)
struct RemotePC {
    int id;
    std::string name;
    std::string host;
    std::string user;
    std::string pass;
    std::string bind_ip;

    ssh_session session = nullptr;

    std::vector<std::string> ips;
    ImVec2 pos{0, 0};
    std::string logBuffer;
    std::mutex logMutex;
    std::atomic<bool> running{false};
    std::thread logThread;

    std::string dns_name;

    std::string logStatus; // "OK", "ERROR", "NO DATA"

    // === CONFIG EDITOR STATE ===
    std::string mainConfig;
    std::string allowedConfig;
    std::string allowedPath;

    std::set<std::string> allowedIps;

    std::vector<char> mainEditBuf;
    std::vector<char> allowedEditBuf;

    bool configLoaded = false;
    bool editingMain = true;
    bool viewingLogs = false;

    int db_pc_id = -1;
};

enum class Mode { MainPage, AddPC, Topology, Logs, Config };

// ──────────────────────────────────────────────
// Functions you want to call from tcp_log_receiver
// ──────────────────────────────────────────────
using PCMap = std::map<std::string, std::unique_ptr<RemotePC>>;
using IPMap = std::unordered_map<std::string, RemotePC *>;

// forward declarations of frequently used functions
RemotePC *find_pc_by_ip(const std::string &ip);
std::vector<std::pair<std::string, std::string>> parse_connections(const std::string &log);
std::set<std::string> parse_allowed_ips(const std::string &text);

#endif
