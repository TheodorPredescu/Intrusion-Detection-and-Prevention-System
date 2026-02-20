#include "imgui/backends/imgui_impl_glfw.h"
#include "imgui/backends/imgui_impl_opengl3.h"
#include "imgui/imgui.h"
#include <GLFW/glfw3.h>
#include <libssh/libssh.h>
#include <libssh/sftp.h>

#include <fcntl.h>
#include <linux/stat.h>
#include <sys/stat.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <fstream>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

#include "database_handle.h"
#include "shared_network_types.h"
#include "tcp_log_receiver.h"

// ============================================================================
// DATA MODEL
// ============================================================================

struct ExternalNode {
    std::string ip;
    ImVec2 pos;
    std::set<RemotePC *> connected_pcs;
};

// Used when a new connection is atempted, to not block the execution line.
struct PendingConnection {
    std::string name;
    std::string host;
    std::string user;
    std::string pass;
    std::string bind_ip;
    std::atomic<bool> completed{false};
    std::atomic<bool> success{false};
    ssh_session session = nullptr;
    std::string error_msg;
    std::thread connection_thread;
};

// Global state for pending connections
static std::unique_ptr<PendingConnection> pending_connection = nullptr;
static std::mutex pending_connection_mutex;

// Global structures
static std::map<std::string, std::unique_ptr<RemotePC>> pc_by_name_host; // key: name + "|" + host
std::unordered_map<std::string, RemotePC *> ip_to_pc_map;                // fast IP → PC lookup
static int next_pc_id = 0;
static std::string selectedRemoveIP;
static int selectedRemoveIdx = 0; // persistent index
static std::vector<std::string> ip_list;

static ImVec2 topology_pan = ImVec2(0.0f, 0.0f);
static float topology_zoom = 1.0f;

static const float ZOOM_MIN = 0.3f;
static const float ZOOM_MAX = 3.0f;

// ============================================================================
// SSH LOG READ
// ============================================================================

// Used to Receive the ips from the `allowed_file`.
std::set<std::string> parse_allowed_ips(const std::string &text) {
    std::set<std::string> ips;
    std::istringstream iss(text);
    std::string line;

    while (std::getline(iss, line)) {
        // trim spaces
        line.erase(0, line.find_first_not_of(" \t\r\n"));
        line.erase(line.find_last_not_of(" \t\r\n") + 1);

        if (line.empty())
            continue;

        size_t colon = line.find(':');
        std::string ip = (colon == std::string::npos) ? line : line.substr(0, colon);

        ips.insert(ip);
    }

    return ips;
}

// static ssh_session connect_to_host(const char *host, const char *user, const char *pass, const char *bind_ip) {
//     const ssh_session session = ssh_new();
//     if (!session) {
//         return nullptr;
//     }
//
//     ssh_options_set(session, SSH_OPTIONS_HOST, host);
//     ssh_options_set(session, SSH_OPTIONS_USER, user);
//
//     // If a bind_ip was provided, set it up.
//     if (bind_ip && strlen(bind_ip) > 0) {
//         ssh_options_set(session, SSH_OPTIONS_BINDADDR, bind_ip);
//     }
//
//     const int strict = 0;
//     ssh_options_set(session, SSH_OPTIONS_STRICTHOSTKEYCHECK, &strict);
//
//     if (ssh_connect(session) != SSH_OK) {
//         goto fail;
//     }
//
//     if (ssh_userauth_password(session, nullptr, pass) != SSH_AUTH_SUCCESS) {
//         goto fail;
//     }
//
//     return session;
//
// fail:
//     std::cout << "Failed to connect\n";
//     ssh_disconnect(session);
//     ssh_free(session);
//     return nullptr;
// }

static bool read_remote_log(const ssh_session session, const char *cmd, std::string &out) {
    const ssh_channel ch = ssh_channel_new(session);
    if (!ch) {
        return false;
    }

    if (ssh_channel_open_session(ch) != SSH_OK || ssh_channel_request_exec(ch, cmd) != SSH_OK) {
        ssh_channel_free(ch);
        return false;
    }

    char buf[4096];
    int n;
    out.clear();

    while ((n = ssh_channel_read(ch, buf, sizeof(buf), 0)) > 0) {
        out.append(buf, n);
    }

    ssh_channel_close(ch);
    ssh_channel_free(ch);
    return true;
}

// ============================================================================
// LOG THREAD
// ============================================================================

static void start_log_thread(RemotePC *pc) {
    std::cout << "Starting log thread for " << pc->name << " (" << pc->host << ")\n";

    if (!pc->session) {
        pc->logStatus = "No session available";
        return;
    }

    pc->running = true;
    pc->logStatus = "Connected";

    pc->logThread = std::thread([pc] {
        while (pc->running) {
            std::string tmp;
            const bool success = read_remote_log(pc->session, "sudo cat /sys/kernel/debug/packet_logs", tmp);

            {
                std::lock_guard<std::mutex> lock(pc->logMutex);

                if (!success) {
                    pc->logStatus = "ERROR";
                } else if (tmp.empty()) {
                    pc->logStatus = "NO DATA";
                    pc->logBuffer.clear();
                } else {
                    pc->logStatus = "OK";
                    pc->logBuffer = std::move(tmp);
                }
            }

            std::this_thread::sleep_for(std::chrono::seconds(3));
        }

        // Cleanup when the thread exists
        ssh_disconnect(pc->session);
        ssh_free(pc->session);
        pc->session = nullptr;
    });
}

// ============================================================================
// HELPERS
// ============================================================================
static std::string make_key(const std::string &name, const std::string &host) {
    return name + "|" + host;
}

static void update_ip_map_for_pc(RemotePC *pc) {
    for (const std::string &ip : pc->ips) {
        // Add only the new elements info `ip_to_pc_map`
        ip_to_pc_map.emplace(ip, pc);
    }
}

RemotePC *find_pc_by_ip(const std::string &ip) {
    auto it = ip_to_pc_map.find(ip);
    return it != ip_to_pc_map.end() ? it->second : nullptr;
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

static bool load_file_from_ssh(const char *host, const char *user, const char *pass, const char *path,
                               std::string &out) {
    const ssh_session session = ssh_new();
    if (!session) {
        return false;
    }

    ssh_options_set(session, SSH_OPTIONS_HOST, host);
    ssh_options_set(session, SSH_OPTIONS_USER, user);

    if (ssh_connect(session) != SSH_OK) {
        ssh_free(session);
        return false;
    }

    if (ssh_userauth_password(session, nullptr, pass) != SSH_AUTH_SUCCESS) {
        ssh_disconnect(session);
        ssh_free(session);
        return false;
    }

    sftp_session sftp = sftp_new(session);
    if (!sftp || sftp_init(sftp) != SSH_OK) {
        sftp_free(sftp);
        ssh_disconnect(session);
        ssh_free(session);
        return false;
    }

    sftp_file file = sftp_open(sftp, path, O_RDONLY, 0);
    if (!file) {
        sftp_free(sftp);
        ssh_disconnect(session);
        ssh_free(session);
        return false;
    }

    char buf[4096];
    int n = 0;
    out.clear();

    while ((n = sftp_read(file, buf, sizeof(buf))) > 0) {
        out.append(buf, n);
    }

    sftp_close(file);
    sftp_free(sftp);
    ssh_disconnect(session);
    ssh_free(session);
    return true;
}

static bool remove_pc(const std::string &name, const std::string &host) {
    const std::string key = make_key(name, host);
    const auto it = pc_by_name_host.find(key);
    if (it == pc_by_name_host.end()) {
        return false; // PC not found
    }

    RemotePC *pc = it->second.get();

    // 1. Stop log thread
    pc->running = false;
    if (pc->logThread.joinable()) {
        pc->logThread.join();
    }

    // 2. Cleanup SSH session if still active
    if (pc->session) {
        ssh_disconnect(pc->session);
        ssh_free(pc->session);
        pc->session = nullptr;
    }

    // 3. Remove from IP → PC map
    for (const std::string &ip : pc->ips) {
        auto ip_it = ip_to_pc_map.find(ip);
        if (ip_it != ip_to_pc_map.end() && ip_it->second == pc) {
            ip_to_pc_map.erase(ip_it);
        }
    }

    // 4. Remove from main PC map
    pc_by_name_host.erase(it);

    std::cout << "Removed PC " << name << " (" << host << ")\n";
    return true;
}

static bool remove_pc_by_ip(const std::string &ip) {
    std::cout << "Tracked IPs:\n";
    for (const std::pair<std::string, RemotePC *> pair : ip_to_pc_map) {
        std::cout << "[" << pair.first << "] -> " << pair.second->name << " (" << pair.second->host << ")\n";
    }

    const RemotePC *pc = find_pc_by_ip(ip);
    if (!pc) {
        std::cout << "PC not found for IP: " << ip << "\n";
        return false;
    }

    std::cout << "Found pc by ip: " << pc->name << "\n";

    // IMPORTANT: Copy name and host BEFORE calling remove_pc
    std::string name = pc->name;
    std::string host = pc->host;

    return remove_pc(name, host);
}

// ============================================================================
// SSH Save
// ============================================================================
static int save_file_to_ssh(const char *host, const char *user, const char *pass, const char *path,
                            const std::string &data) {
    const ssh_session session = ssh_new();
    if (!session) {
        return -1;
    }

    ssh_options_set(session, SSH_OPTIONS_HOST, host);
    ssh_options_set(session, SSH_OPTIONS_USER, user);

    if (ssh_connect(session) != SSH_OK) {
        ssh_free(session);
        return -2;
    }

    if (ssh_userauth_password(session, nullptr, pass) != SSH_AUTH_SUCCESS) {
        ssh_disconnect(session);
        ssh_free(session);
        return -3;
    }

    sftp_session sftp = sftp_new(session);
    if (!sftp || sftp_init(sftp) != SSH_OK) {
        sftp_free(sftp);
        ssh_disconnect(session);
        ssh_free(session);
        return -4;
    }

    const sftp_file file = sftp_open(sftp, path, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);

    if (!file) {
        std::cerr << "SFTP open failed on " << path << ": " << ssh_get_error(session) << "\n";
        sftp_free(sftp);
        ssh_disconnect(session);
        ssh_free(session);
        return -5;
    }

    size_t left = data.size();
    const char *ptr = data.c_str();

    while (left > 0) {
        int written = sftp_write(file, ptr, left);
        if (written <= 0) {
            sftp_close(file);
            sftp_free(sftp);
            ssh_disconnect(session);
            ssh_free(session);
            return -6;
        }
        left -= written;
        ptr += written;
    }

    sftp_close(file);
    sftp_free(sftp);
    ssh_disconnect(session);
    ssh_free(session);
    return 1;
}

/**
 * Extract the allowed file name from the main buffer.
 *
 * @param text represents the main buffer in which it is searched.
 */
static std::string extract_allowed_file(const std::string &text) {
    const std::string key = "allowed_file ";
    size_t pos = text.find(key);
    if (pos == std::string::npos) {
        return "";
    }

    pos += key.length();
    const size_t end = text.find_first_of("\r\n", pos);
    return text.substr(pos, end - pos);
}

/**
 * Discovers the new ips that a pc might use in the logs.
 */
static void discover_new_ips() {
    for (const auto &[key, pc_uptr] : pc_by_name_host) {
        RemotePC *pc = pc_uptr.get();

        std::string log_copy;
        {
            std::lock_guard<std::mutex> lock(pc->logMutex);
            log_copy = pc->logBuffer;
        }

        std::vector<std::pair<std::string, std::string>> conns = parse_connections(log_copy);

        for (const auto &[_, dst_ip] : conns) {
            RemotePC *dst_pc = find_pc_by_ip(dst_ip);

            // Check if destination IP belongs to this PC but isn't tracked yet
            if (dst_pc) {
                continue;
            }
            bool ip_appears_in_pc = false;

            for (const auto &ip : pc->ips) {
                if (ip == dst_ip) {
                    ip_appears_in_pc = true;
                    break;
                }
            }

            if (ip_appears_in_pc == false) {
                pc->ips.push_back(dst_ip);
                update_ip_map_for_pc(pc);
            }
        }
    }
}

static void distribute_model_to_pcs(const std::string &model_code) {
    std::vector<std::thread> threads;

    for (const auto &[_, pc_uptr] : pc_by_name_host) {
        threads.emplace_back([pc = pc_uptr.get(), model_code]() {
            ssh_session session = ssh_new();
            if (!session)
                return;

            ssh_options_set(session, SSH_OPTIONS_HOST, pc->host.c_str());
            ssh_options_set(session, SSH_OPTIONS_USER, pc->user.c_str());

            if (ssh_connect(session) != SSH_OK) {
                ssh_free(session);
                return;
            }

            if (ssh_userauth_password(session, nullptr, pc->pass.c_str()) != SSH_AUTH_SUCCESS) {
                ssh_disconnect(session);
                ssh_free(session);
                return;
            }

            // Upload to /tmp
            sftp_session sftp = sftp_new(session);
            if (!sftp || sftp_init(sftp) != SSH_OK) {
                ssh_disconnect(session);
                ssh_free(session);
                return;
            }

            sftp_file file = sftp_open(sftp, "/tmp/model.bin.tmp", O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);

            if (!file) {
                sftp_free(sftp);
                ssh_disconnect(session);
                ssh_free(session);
                return;
            }

            const char *data = model_code.data();
            size_t remaining = model_code.size();

            while (remaining > 0) {
                int written = sftp_write(file, data, remaining);
                if (written <= 0)
                    break;
                data += written;
                remaining -= written;
            }

            sftp_close(file);
            sftp_free(sftp);

            if (remaining != 0) {
                ssh_disconnect(session);
                ssh_free(session);
                return;
            }

            // Move into place
            ssh_channel ch = ssh_channel_new(session);
            if (!ch || ssh_channel_open_session(ch) != SSH_OK) {
                ssh_disconnect(session);
                ssh_free(session);
                return;
            }

            const char *cmd = "sudo /usr/bin/mv -f /tmp/model.bin.tmp /etc/model.bin";

            if (ssh_channel_request_exec(ch, cmd) != SSH_OK) {
                ssh_channel_free(ch);
                ssh_disconnect(session);
                ssh_free(session);
                return;
            }

            ssh_channel_send_eof(ch);
            ssh_channel_close(ch);

            int status = ssh_channel_get_exit_status(ch);

            ssh_channel_free(ch);
            ssh_disconnect(session);
            ssh_free(session);

            if (status != 0) {
                // optional minimal error log
                std::cerr << "[DIST] Deployment failed on " << pc->name << "\n";
            }
        });
    }

    for (auto &t : threads)
        if (t.joinable())
            t.join();
}

static void trigger_model_training() {
    const char *filename = "train/model.bin";
    std::string content;
    struct stat st;

    if (stat("train", &st) == 0 && S_ISDIR(st.st_mode)) {
        std::ofstream f("train/train_trigger.txt");
        f << "train_now\n";
        f.close();
        std::cout << "[APP] Training triggered, waiting for model...\n";

        for (int i = 0; i < 120; i++) {
            std::ifstream f(filename);
            if (f.good()) {
                content = std::string((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
                std::cout << "[APP] Model ready (" << content.size() << " bytes)\n";

                // Distribute model to all PCs in new thread
                std::thread dist_thread(distribute_model_to_pcs, content);
                dist_thread.detach(); // Let it run in background
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
    } else {
        std::cerr << "[APP] train directory does not exist\n";
    }
}

// ===============================================================================================
// ================================== async connection handling
// ==================================
// ===============================================================================================

// Background connection function
static void async_connect(PendingConnection *pending) {
    const ssh_session session = ssh_new();
    if (!session) {
        pending->error_msg = "Failed to create SSH session";
        pending->success = false;
        pending->completed = true;
        return;
    }

    ssh_options_set(session, SSH_OPTIONS_HOST, pending->host.c_str());
    ssh_options_set(session, SSH_OPTIONS_USER, pending->user.c_str());

    if (!pending->bind_ip.empty() && pending->bind_ip.length() > 0) {
        ssh_options_set(session, SSH_OPTIONS_BINDADDR, pending->bind_ip.c_str());
    }

    const int strict = 0;
    ssh_options_set(session, SSH_OPTIONS_STRICTHOSTKEYCHECK, &strict);

    // Set timeout to avoid hanging forever
    const long timeout = 10; // 10 seconds
    ssh_options_set(session, SSH_OPTIONS_TIMEOUT, &timeout);

    if (ssh_connect(session) != SSH_OK) {
        pending->error_msg = "Failed to connect to " + pending->host + ": " + std::string(ssh_get_error(session));
        ssh_free(session);
        pending->success = false;
        pending->completed = true;
        return;
    }

    if (ssh_userauth_password(session, nullptr, pending->pass.c_str()) != SSH_AUTH_SUCCESS) {
        pending->error_msg = "Authentication failed for " + pending->host;
        ssh_disconnect(session);
        ssh_free(session);
        pending->success = false;
        pending->completed = true;
        return;
    }

    // Success!
    pending->session = session;
    pending->success = true;
    pending->completed = true;
}

// Start an async connection
static void start_async_connection(const char *name, const char *host, const char *user, const char *pass,
                                   const char *bind_ip) {

    std::lock_guard<std::mutex> lock(pending_connection_mutex);
    pending_connection = std::make_unique<PendingConnection>();

    pending_connection->name = name;
    pending_connection->host = host;
    pending_connection->user = user;
    pending_connection->pass = pass;
    pending_connection->bind_ip = (bind_ip && strlen(bind_ip) > 0) ? bind_ip : "";

    // Start the connection thread
    pending_connection->connection_thread = std::thread(async_connect, pending_connection.get());
}

// Check and process completed connections
static void process_pending_connections(std::string &successMsg, std::string &errorMsg) {
    std::lock_guard<std::mutex> lock(pending_connection_mutex);

    if (pending_connection == nullptr || !pending_connection->completed) {
        return;
    }
    // Join the thread
    if (pending_connection->connection_thread.joinable()) {
        pending_connection->connection_thread.join();
    }

    if (pending_connection->success == false) {
        // Connection failed
        errorMsg = pending_connection->error_msg;
        successMsg.clear();
        pending_connection = nullptr;
        return;
    }

    // Connection successful - add the PC
    std::string key = make_key(pending_connection->name, pending_connection->host);
    auto pc_it = pc_by_name_host.find(key);

    if (pc_it != pc_by_name_host.end()) {
        // Existing PC — add IP if new
        RemotePC *pc = pc_it->second.get();
        if (std::find(pc->ips.begin(), pc->ips.end(), pending_connection->host) == pc->ips.end()) {
            pc->ips.push_back(pending_connection->host);
            update_ip_map_for_pc(pc);
            successMsg = "Added IP " + pending_connection->host + " to existing PC " + pending_connection->name;

        } else {
            successMsg = "PC already exists with this configuration";
        }

        // Close the duplicate session
        ssh_disconnect(pending_connection->session);
        ssh_free(pending_connection->session);
    } else {
        // New PC
        auto pc = std::make_unique<RemotePC>();
        pc->id = next_pc_id++;
        pc->name = pending_connection->name;
        pc->host = pending_connection->host;
        pc->user = pending_connection->user;
        pc->pass = pending_connection->pass;
        pc->bind_ip = pending_connection->bind_ip;
        pc->session = pending_connection->session;
        pc->ips = {pending_connection->host};
        pc->pos = ImVec2(200 + pc->id * 200, 300);

        RemotePC *raw_ptr = pc.get();
        pc_by_name_host[key] = std::move(pc);
        update_ip_map_for_pc(raw_ptr);
        start_log_thread(raw_ptr);

        successMsg = "Successfully added PC " + pending_connection->name;
    }

    pending_connection.reset();
}

// Get count of pending connections
static bool is_connection_pending() {
    std::lock_guard<std::mutex> lock(pending_connection_mutex);
    return pending_connection != nullptr;
}

// ================================== Transformations from topology reactivity
// ==================================

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
// ===================================== Main UI functionalities
// =====================================
// ===================================================================================================

static void draw_add_pc() {
    static char name[32] = "pc1";
    static char host[64] = "192.168.0.113";
    static char ip[64] = "192.168.0.114";
    static char user[64] = "theodor";
    static char pass[64] = "theodor";
    static std::string errorMsg = "";
    static std::string successMsg = "";

    // Process any completed connections
    process_pending_connections(successMsg, errorMsg);

    // ========== ADD PC SECTION ==========
    ImGui::Text("Add New PC");
    ImGui::Separator();
    ImGui::Spacing();

    // Left side - form inputs
    ImGui::BeginChild("add_form", ImVec2(500, 0), false);

    ImGui::Text("Connection Details:");
    ImGui::Spacing();

    ImGui::PushItemWidth(200.0f);
    ImGui::InputText("PC Name", name, sizeof(name));
    ImGui::InputText("Host Address", host, sizeof(host));
    ImGui::InputText("Bind IP (optional)", ip, sizeof(ip));
    ImGui::Spacing();

    ImGui::InputText("Username", user, sizeof(user));
    ImGui::InputText("Password", pass, sizeof(pass), ImGuiInputTextFlags_Password);
    ImGui::PopItemWidth();

    ImGui::Spacing();
    ImGui::Spacing();

    const bool is_connecting = is_connection_pending();

    if (is_connecting) {
        ImGui::PushStyleColor(ImGuiCol_Button, IM_COL32(100, 100, 100, 255));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, IM_COL32(100, 100, 100, 255));
        ImGui::PushStyleColor(ImGuiCol_ButtonActive, IM_COL32(100, 100, 100, 255));
    }

    if (ImGui::Button("Add PC", ImVec2(150, 30)) && !is_connecting) {
        errorMsg.clear();
        successMsg.clear();

        if (strlen(name) > 0 && strlen(host) > 0) {
            // Start async connection

            // TODO: I check if this host ip matches ones already present, but
            // if its a sleeping host ip (not active)
            if (find_pc_by_ip(host) == nullptr) {
                start_async_connection(name, host, user, pass, ip);
                successMsg = "Connecting to " + std::string(host) + "...";
            } else {
                errorMsg = "This ip is already tracked.";
            }
        } else {
            errorMsg = "Name and Host are required fields";
        }
    }

    if (is_connecting) {
        ImGui::PopStyleColor(3);
        ImGui::SameLine();
        ImGui::Text("Connecting... ");
    } else {
        ImGui::SameLine();
        ImGui::TextDisabled("Bind IP represents the IP that will be used to\n"
                            "connect to the Host Address. If its left empty,\n"
                            "one will be selected automatically.");
    }

    ImGui::Spacing();
    ImGui::Spacing();

    // Display error or success messages
    if (!errorMsg.empty()) {
        ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(255, 100, 100, 255));
        ImGui::TextWrapped("%s", errorMsg.c_str());
        ImGui::PopStyleColor();
    }

    if (!successMsg.empty()) {
        ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(100, 255, 100, 255));
        ImGui::TextWrapped("%s", successMsg.c_str());
        ImGui::PopStyleColor();
    }

    if (ImGui::Button("Train", ImVec2(150, 30))) {
        trigger_model_training();
    }
    ImGui::EndChild();

    // Right side - remove PC section
    ImGui::SameLine();
    ImGui::BeginChild("remove_section", ImVec2(0, 0), true);

    ImGui::Text("Remove Tracked PC");
    ImGui::Separator();
    ImGui::Spacing();

    // Collect all IPs
    ip_list.clear();
    for (const auto &pair : ip_to_pc_map) {
        ip_list.push_back(pair.first);
    }

    if (!ip_list.empty()) {
        if (static_cast<long long>(selectedRemoveIdx) >= static_cast<long long>(ip_list.size())) {
            selectedRemoveIdx = 0; // reset if list shrunk
        }

        // Update selectedRemoveIP every frame
        selectedRemoveIP = ip_list[selectedRemoveIdx];

        ImGui::Text("Select PC by IP:");
        ImGui::PushItemWidth(-1); // Full width
        ImGui::Combo(
            "##remove_combo", &selectedRemoveIdx,
            [](void *data, int idx, const char **out_text) -> bool {
                auto &vec = *reinterpret_cast<std::vector<std::string> *>(data);
                *out_text = vec[idx].c_str();
                return true;
            },
            &ip_list, (int)ip_list.size());
        ImGui::PopItemWidth();

        ImGui::Spacing();

        if (ImGui::Button("Remove Selected PC", ImVec2(-1, 30))) {
            std::cout << "Trying to remove PC with IP: " << selectedRemoveIP << "\n";
            if (!selectedRemoveIP.empty()) {
                bool success = remove_pc_by_ip(selectedRemoveIP);
                if (success) {
                    std::cout << "Successfully removed PC with IP: " << selectedRemoveIP << "\n";
                    selectedRemoveIP.clear();
                    selectedRemoveIdx = 0;
                } else {
                    std::cout << "Failed to remove PC.\n";
                }
            }
        }

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        // Show list of all tracked PCs
        ImGui::Text("Currently Tracked PCs:");
        ImGui::Spacing();

        ImGui::BeginChild("pc_list", ImVec2(0, 0), false);
        for (const auto &[key, pc_uptr] : pc_by_name_host) {
            ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(120, 190, 255, 255));
            ImGui::Text("%s", pc_uptr->name.c_str());
            ImGui::PopStyleColor();

            for (const auto &pc_ip : pc_uptr->ips) {
                ImGui::BulletText("%s", pc_ip.c_str());
            }
            ImGui::Spacing();
        }
        ImGui::EndChild();

    } else {
        ImGui::TextDisabled("No PCs tracked yet.");
        ImGui::TextDisabled("Add a PC using the form on the left.");
    }

    ImGui::EndChild();
}

static void draw_topology() {
    ImGui::BeginChild("canvas", ImVec2(0, 0), true);
    ImDrawList *dl = ImGui::GetWindowDrawList();
    ImVec2 canvas_pos = ImGui::GetCursorScreenPos();
    ImVec2 canvas_size = ImGui::GetContentRegionAvail();

    calculate_zoom_and_drag();

    dl->AddRectFilled(canvas_pos, ImVec2(canvas_pos.x + canvas_size.x, canvas_pos.y + canvas_size.y),
                      IM_COL32(30, 30, 40, 255));

    ImVec2 center(canvas_pos.x + canvas_size.x * 0.5f, canvas_pos.y + canvas_size.y * 0.5f);

    // === 1. Collect monitored PCs ===
    std::vector<RemotePC *> monitored_pcs;
    for (const auto &[key, pc_uptr] : pc_by_name_host) {
        monitored_pcs.push_back(pc_uptr.get());
    }

    // === 3. Collect external IPs (first pass - only collect) ===

    // Store in a map the ip of the external pc and a set of all the pcs that
    // are connected to this ip.
    std::map<std::string, std::set<RemotePC *>> external_ip_to_pcs;
    std::map<RemotePC *, std::set<std::string>> pcs_to_ip;
    std::set<std::pair<int, int>> drawn_monitored_edges;

    for (RemotePC *pc : monitored_pcs) {
        std::string log_copy;
        {
            std::lock_guard<std::mutex> lock(pc->logMutex);
            log_copy = pc->logBuffer;
        }

        const auto conns = parse_connections(log_copy);

        for (const auto &[src_ip, dst_ip] : conns) {
            RemotePC *src_pc = find_pc_by_ip(src_ip);
            RemotePC *dst_pc = find_pc_by_ip(dst_ip);

            // Monitored to monitored - just dedup for later drawing
            if (src_pc && dst_pc && src_pc != dst_pc) {
                int a = src_pc->id, b = dst_pc->id;
                if (a > b) {
                    std::swap(a, b);
                }
                drawn_monitored_edges.insert({a, b});
            } else if (!src_pc && dst_pc) {
                // One side is external (meaning the destination is in the list
                // of tracked files, and the source is not)
                external_ip_to_pcs[src_ip].insert(dst_pc);
                pcs_to_ip[dst_pc].insert(src_ip);
            }
        }
    }

    // Space between consecutive rings
    const float ring_spacing = std::min(canvas_size.x, canvas_size.y) * 0.20f;
    const float inner_radius = std::min(canvas_size.x, canvas_size.y) * 0.25f;
    const size_t pc_count = monitored_pcs.size();
    const int nodes_per_ring = 8;
    std::map<RemotePC *, int> pcs_total_rings;

    for (RemotePC *pc : monitored_pcs) {
        int total_nodes = pcs_to_ip[pc].size();
        int ring_number = 0;
        if (total_nodes > 0) {
            ring_number = static_cast<int>(std::ceil(std::log2(static_cast<float>(total_nodes) / nodes_per_ring + 1)));
        }
        pcs_total_rings[pc] = ring_number;
    }

    for (size_t i = 0; i < pc_count; ++i) {
        if (pc_count <= 1) {
            monitored_pcs[i]->pos = center;
        } else {
            const float angle = i * (2.0f * M_PI / pc_count);
            const float extra_length = pcs_total_rings[monitored_pcs[i]] * ring_spacing;
            const float radius = inner_radius + extra_length;

            monitored_pcs[i]->pos = ImVec2(center.x + radius * cosf(angle), center.y + radius * sinf(angle));
        }
    }

    // === 4. Create and position external nodes ===
    std::map<std::string, ExternalNode> external_nodes;
    // Distance from the connected PC
    const float orbit_radius_base = std::min(canvas_size.x, canvas_size.y) * 0.20f;
    /* Max nodes per orbital ring before adding another ring */

    // First, count how many external nodes connect to each PC
    std::map<RemotePC *, int> nodes_per_pc;
    for (const auto &[ip, connected_pcs] : external_ip_to_pcs) {
        if (connected_pcs.size() == 1) {
            RemotePC *target_pc = *connected_pcs.begin();
            nodes_per_pc[target_pc]++;
        }
    }

    // Track how many nodes we've placed around each PC
    std::map<RemotePC *, int> current_index_per_pc;

    for (const auto &[ip, connected_pcs] : external_ip_to_pcs) {
        ExternalNode node;
        node.ip = ip;
        node.connected_pcs = connected_pcs;

        if (connected_pcs.empty()) {
            // Shouldn't happen, but fallback to center
            node.pos = ImVec2(center.x + orbit_radius_base, center.y);
        } else if (connected_pcs.size() == 1) {
            // Connected to single PC - position around it
            RemotePC *target_pc = *connected_pcs.begin();

            int current_idx = current_index_per_pc[target_pc]++;

            int ring_number = 0;
            int nodes_before = 0;
            int nodes_in_ring = nodes_per_ring;

            while (current_idx >= nodes_before + nodes_in_ring) {
                nodes_before += nodes_in_ring;
                ring_number++;

                // increase capacity each ring
                nodes_in_ring += nodes_per_ring;
            }

            const int position_in_ring = current_idx - nodes_before;

            const float orbit_radius = orbit_radius_base + ring_number * ring_spacing;
            float angle = (2.0f * M_PI * position_in_ring) / nodes_in_ring;

            if (ring_number % 2 == 1) {
                angle += M_PI / nodes_in_ring;
            }

            node.pos =
                ImVec2(target_pc->pos.x + orbit_radius * cosf(angle), target_pc->pos.y + orbit_radius * sinf(angle));

        } else {
            // Connected to multiple PCs - position at centroid
            ImVec2 centroid(0, 0);
            for (RemotePC *pc : connected_pcs) {
                centroid.x += pc->pos.x;
                centroid.y += pc->pos.y;
            }
            centroid.x /= connected_pcs.size();
            centroid.y /= connected_pcs.size();

            // Offset slightly outward from center
            ImVec2 dir(centroid.x - center.x, centroid.y - center.y);
            const float len = std::hypot(dir.x, dir.y);
            if (len > 1e-3f) {
                dir.x /= len;
                dir.y /= len;
                node.pos = ImVec2(centroid.x + dir.x * 60.0f, centroid.y + dir.y * 60.0f);
            } else {
                node.pos = centroid;
            }
        }

        external_nodes[ip] = node;
    }

    // === 5. Draw ALL connections (now with correct positions) ===
    for (RemotePC *pc : monitored_pcs) {
        std::string log_copy;
        {
            std::lock_guard<std::mutex> lock(pc->logMutex);
            log_copy = pc->logBuffer;
        }

        const auto conns = parse_connections(log_copy);

        for (const auto &[src_ip, dst_ip] : conns) {
            RemotePC *src_pc = find_pc_by_ip(src_ip);
            RemotePC *dst_pc = find_pc_by_ip(dst_ip);

            ImVec2 from_pos, to_pos;
            ImU32 line_color;

            if (src_pc && dst_pc) {
                // Monitored ↔ Monitored
                if (src_pc == dst_pc) {
                    continue;
                }

                int a = src_pc->id, b = dst_pc->id;
                if (a > b) {
                    std::swap(a, b);
                }

                if (drawn_monitored_edges.count({a, b}) == 0) {
                    continue; // already drawn? no - we draw all
                }

                from_pos = src_pc->pos;
                to_pos = dst_pc->pos;
                line_color = IM_COL32(100, 200, 255, 220);
            } else if (src_pc && external_nodes.count(dst_ip)) {
                // Monitored → External
                from_pos = src_pc->pos;
                to_pos = external_nodes[dst_ip].pos;
                line_color = IM_COL32(255, 100, 100, 220);
            } else if (external_nodes.count(src_ip) && dst_pc) {
                // External → Monitored
                from_pos = external_nodes[src_ip].pos;
                to_pos = dst_pc->pos;
                line_color = IM_COL32(255, 100, 100, 220);
            } else {
                continue; // both external - ignore and impossible
            }

            // Draw line
            dl->AddLine(to_screen(from_pos), to_screen(to_pos), line_color, 3.0f);
        }
    }

    // === 6. Draw external nodes ===
    int external_circle_radius = 55 * topology_zoom;
    int monitored_circle_radius = 65 * topology_zoom;
    int circle_segments = 64;
    for (const auto &[ip, node] : external_nodes) {
        bool is_allowed = false;

        auto it = external_ip_to_pcs.find(ip);
        if (it != external_ip_to_pcs.end() && it->second.size() == 1) {
            RemotePC *pc = *it->second.begin();
            if (pc->allowedIps.count(ip)) {
                is_allowed = true;
            }
        }

        ImU32 fillColor = is_allowed ? IM_COL32(255, 220, 80, 255) // yellow
                                     : IM_COL32(255, 80, 80, 255); // red

        ImU32 borderColor = is_allowed ? IM_COL32(255, 240, 120, 255) : IM_COL32(255, 120, 120, 255);

        dl->AddCircleFilled(to_screen(node.pos), external_circle_radius, fillColor);
        dl->AddCircle(to_screen(node.pos), external_circle_radius, borderColor, circle_segments, 4.0f);

        ImGui::SetWindowFontScale(topology_zoom);
        ImVec2 screen_pos = to_screen(node.pos);
        ImVec2 ts = ImGui::CalcTextSize(ip.c_str());

        dl->AddText(ImVec2(screen_pos.x - ts.x * 0.5f, screen_pos.y - ts.y * 0.5f), IM_COL32_WHITE, ip.c_str());
        ImGui::SetWindowFontScale(1.0f);

        // Hover for the other nodes presend.
        ImVec2 mouse = ImGui::GetMousePos();
        float dx = mouse.x - screen_pos.x;
        float dy = mouse.y - screen_pos.y;

        if (dx * dx + dy * dy <= external_circle_radius * external_circle_radius) {
            ImGui::BeginTooltip();
            ImGui::Text("IP: %s", ip.c_str());
            ImGui::Separator();

            if (is_allowed) {
                ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(255, 220, 80, 255));
                ImGui::Text("Status: Allowed");
                ImGui::PopStyleColor();
            } else {
                ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(255, 80, 80, 255));
                ImGui::Text("Status: External (Not Allowed)");
                ImGui::PopStyleColor();
            }

            if (!node.connected_pcs.empty()) {
                ImGui::Spacing();
                ImGui::Text("Connects to:");
                for (RemotePC *connected_pc : node.connected_pcs) {
                    ImGui::BulletText("%s", connected_pc->name.c_str());
                }
            }

            ImGui::EndTooltip();
        }
    }

    // === 7. Draw monitored nodes on top ===
    for (RemotePC *pc : monitored_pcs) {
        dl->AddCircleFilled(to_screen(pc->pos), monitored_circle_radius, IM_COL32(80, 150, 255, 255));
        dl->AddCircle(to_screen(pc->pos), monitored_circle_radius, IM_COL32(120, 190, 255, 255), circle_segments, 4.0f);

        std::string label = pc->name;
        if (!pc->ips.empty()) {
            label += "\n" + pc->ips[0];
        }

        ImGui::SetWindowFontScale(topology_zoom);
        ImVec2 ts = ImGui::CalcTextSize(label.c_str());
        ImVec2 screen_pos = to_screen(pc->pos);

        dl->AddText(ImVec2(screen_pos.x - ts.x * 0.5f, screen_pos.y - ts.y * 0.5f), IM_COL32_WHITE, label.c_str());
        ImGui::SetWindowFontScale(1.0f);

        // ===== HOVER TOOLTIP =====
        ImVec2 mouse = ImGui::GetMousePos();
        float dx = mouse.x - screen_pos.x;
        float dy = mouse.y - screen_pos.y;

        if (dx * dx + dy * dy <= monitored_circle_radius * monitored_circle_radius) {
            ImGui::BeginTooltip();
            ImGui::Text("PC: %s", pc->name.c_str());
            ImGui::Separator();

            for (const auto &ip : pc->ips) {
                ImGui::BulletText("%s", ip.c_str());
            }

            ImGui::EndTooltip();
        }
    }

    ImGui::EndChild();
}

static void draw_logs() {
    // TODO: Small bug. If this pc has another ip, it will not be updated right
    // away. I need to reenter on this page to see the modification.

    // To remember the selected option.
    static int selected = -1;
    ImGui::BeginChild("left", ImVec2(250, 0), true);
    int idx = 0;
    for (const auto &[key, pc_uptr] : pc_by_name_host) {
        RemotePC *pc = pc_uptr.get();
        std::string label =
            pc->name + " (" + std::to_string(pc->ips.size()) + " IP" + (pc->ips.size() > 1 ? "s" : "") + ")";
        for (const auto &ip : pc->ips) {
            label += "\n\t" + ip;
        }
        if (ImGui::Selectable(label.c_str(), selected == idx))
            selected = idx;
        idx++;
    }
    ImGui::EndChild();

    ImGui::SameLine();
    ImGui::BeginChild("right", ImVec2(0, 0), true);

    if (idx == 0) {
        ImGui::TextDisabled("No PC is currently tracked, add a PC to inspect logs.");
        ImGui::EndChild();

        // Reset the selected pc if all are removed.
        selected = -1;
        return;
    }

    if (selected < 0) {
        ImGui::TextDisabled("Select a PC from the left pannel to show its logs.");
        ImGui::EndChild();
        return;
    }

    idx = 0;
    for (const auto &[key, pc_uptr] : pc_by_name_host) {
        if (idx++ == selected) {
            std::lock_guard<std::mutex> lock(pc_uptr->logMutex);
            ImGui::TextUnformatted(pc_uptr->logBuffer.c_str());
            break;
        }
    }
    ImGui::EndChild();
}

// TODO: I can change the logs to not send all the data all the time, but change
// once its read (keeping the reading file way smaller) and just add them
// continously untill I detect a change in the config file (might be able to
// detect even if the mode was changed on each pc with a variable?).
static void draw_config_editor() {
    static int selectedPC = -1;
    static int writing_succedded = -1;

    ImGui::BeginChild("config_left", ImVec2(250, 0), true);
    int idx = 0;

    // Add this check at the start:
    if (selectedPC >= (int)pc_by_name_host.size()) {
        selectedPC = -1;
    }

    for (const auto &[key, pc_uptr] : pc_by_name_host) {

        std::string label = pc_uptr->name + " (" + std::to_string(pc_uptr->ips.size()) + " IP" +
                            (pc_uptr->ips.size() > 1 ? "s" : "") + ")";
        for (const auto &ip : pc_uptr->ips) {
            label += "\n\t" + ip;
        }

        if (ImGui::Selectable(label.c_str(), selectedPC == idx)) {
            selectedPC = idx;
            writing_succedded = -1;
        }
        idx++;
    }
    ImGui::EndChild();

    ImGui::SameLine();
    ImGui::BeginChild("config_right", ImVec2(0, 0), true);

    if (idx == 0) {
        ImGui::TextDisabled("No PC is currently tracked.");
        ImGui::EndChild();

        // Reset the pc index.
        selectedPC = -1;
        return;
    }

    if (selectedPC < 0) {
        ImGui::TextDisabled("Select a PC to edit its config.");
        ImGui::EndChild();
        return;
    }

    idx = 0;
    RemotePC *pc = nullptr;
    for (auto &[k, p] : pc_by_name_host) {
        if (idx++ == selectedPC) {
            pc = p.get();
            break;
        }
    }

    if (!pc) {
        ImGui::TextDisabled("Selected PC no longer exists.");
        ImGui::EndChild();
        return;
    }

    const char *MAIN_FILE = "/etc/mymodule.conf";

    // === Load config once ===
    if (!pc->configLoaded) {
        if (load_file_from_ssh(pc->host.c_str(), pc->user.c_str(), pc->pass.c_str(), MAIN_FILE, pc->mainConfig)) {

            pc->allowedPath = extract_allowed_file(pc->mainConfig);
            if (!pc->allowedPath.empty()) {
                load_file_from_ssh(pc->host.c_str(), pc->user.c_str(), pc->pass.c_str(), pc->allowedPath.c_str(),
                                   pc->allowedConfig);
            }

            pc->mainEditBuf.assign(pc->mainConfig.begin(), pc->mainConfig.end());
            pc->mainEditBuf.push_back('\0');

            pc->allowedEditBuf.assign(pc->allowedConfig.begin(), pc->allowedConfig.end());
            pc->allowedEditBuf.push_back('\0');

            pc->configLoaded = true;

            // Save in a different place the ips allowed.
            pc->allowedIps = parse_allowed_ips(pc->allowedConfig);
        }
    }

    // === Tabs ===
    if (ImGui::Button("Main Config")) {
        pc->editingMain = true;
        writing_succedded = -1;
    }

    ImGui::SameLine();
    if (!pc->allowedPath.empty()) {
        if (ImGui::Button("Allowed File")) {
            pc->editingMain = false;
            writing_succedded = -1;
        }
    }

    ImGui::Separator();

    std::string &active = pc->editingMain ? pc->mainConfig : pc->allowedConfig;
    std::vector<char> &buf = pc->editingMain ? pc->mainEditBuf : pc->allowedEditBuf;
    const char *path = pc->editingMain ? MAIN_FILE : pc->allowedPath.c_str();

    ImGui::Text("Editing: %s", path);

    auto resizeCb = [](ImGuiInputTextCallbackData *data) -> int {
        if (data->EventFlag == ImGuiInputTextFlags_CallbackResize) {
            auto *vec = reinterpret_cast<std::vector<char> *>(data->UserData);
            vec->resize(data->BufSize);
            data->Buf = vec->data();
        }
        return 0;
    };

    bool changed = ImGui::InputTextMultiline("##editor", buf.data(), buf.size(), ImVec2(-1, -60),
                                             ImGuiInputTextFlags_AllowTabInput | ImGuiInputTextFlags_CallbackResize,
                                             resizeCb, &buf);

    // If the input box changed, update the menu with still active.
    if (changed) {
        writing_succedded = -1;
        active = std::string(buf.data());
    }

    if (ImGui::Button("Save")) {
        writing_succedded = save_file_to_ssh(pc->host.c_str(), pc->user.c_str(), pc->pass.c_str(), path, active);
    }

    if (writing_succedded <= 0) {
        ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(255, 100, 100, 255));
        ImGui::TextWrapped("Failed to write the file, try again!");
        ImGui::PopStyleColor();
    }

    if (writing_succedded == 1) {
        ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(100, 255, 100, 255));
        ImGui::TextWrapped("Saved successfully to:%s\n", path);
        ImGui::PopStyleColor();

        // If we just saved the main config, check if allowed_file path changed
        if (pc->editingMain) {
            std::string newAllowed = extract_allowed_file(active);
            if (newAllowed != pc->allowedPath) {
                pc->allowedPath = newAllowed;
                if (!newAllowed.empty()) {
                    // Reload the new allowed file; Create a new ssh connection
                    // with that will be used to read.
                    if (load_file_from_ssh(pc->host.c_str(), pc->user.c_str(), pc->pass.c_str(), newAllowed.c_str(),
                                           pc->allowedConfig)) {
                        pc->allowedEditBuf.assign(pc->allowedConfig.begin(), pc->allowedConfig.end());
                        pc->allowedEditBuf.push_back('\0');
                    }
                }
            }
        }

        // Reload the allowed IPs
        pc->allowedIps = parse_allowed_ips(pc->allowedConfig);
    }
    ImGui::EndChild(); // config_right
}

// ===================================================================================================
// ============================================= Main
// ================================================
// ===================================================================================================
enum class Page { AddPC, Topology, Logs, Config };

int main() {
    if (!g_network_log_db.open()) {
        std::cerr << "Cannot initialize SQLite database → continuing without logging...\n";
    } else {
        g_tcp_log_receiver.start();
    }

    const double target_fps = 30.0;
    const double target_frame_time = 1.0 / target_fps;

    glfwInit();
    GLFWwindow *wnd = glfwCreateWindow(1400, 900, "Network Inspection App", nullptr, nullptr);
    glfwMakeContextCurrent(wnd);

    // Based on VSync
    // glfwSwapInterval(1);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGui::StyleColorsDark();
    ImGui_ImplGlfw_InitForOpenGL(wnd, true);
    ImGui_ImplOpenGL3_Init("#version 150");

    Page page = Page::AddPC;

    while (!glfwWindowShouldClose(wnd)) {
        double frame_start = glfwGetTime();

        glfwPollEvents();
        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        // Keep track of all new ips that a pc might have.
        discover_new_ips();

        ImGuiWindowFlags flags = ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize |
                                 ImGuiWindowFlags_NoBringToFrontOnFocus;

        ImGui::SetNextWindowPos(ImVec2(0, 0));
        ImGui::SetNextWindowSize(ImGui::GetIO().DisplaySize);

        ImGui::Begin("##root", nullptr, flags);

        // Create the main top buttons.
        if (ImGui::Button("Add PC"))
            page = Page::AddPC;
        ImGui::SameLine();
        if (ImGui::Button("Topology"))
            page = Page::Topology;
        ImGui::SameLine();
        if (ImGui::Button("Logs"))
            page = Page::Logs;
        ImGui::SameLine();
        if (ImGui::Button("Config"))
            page = Page::Config;

        ImGui::Separator();

        // Based on the button pressed, draw the content of the page.
        if (page == Page::AddPC)
            draw_add_pc();
        else if (page == Page::Topology)
            draw_topology();
        else if (page == Page::Logs)
            draw_logs();
        else if (page == Page::Config)
            draw_config_editor();

        ImGui::End();

        ImGui::Render();
        int dw, dh;
        glfwGetFramebufferSize(wnd, &dw, &dh);
        glViewport(0, 0, dw, dh);
        glClearColor(0.05f, 0.05f, 0.08f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        glfwSwapBuffers(wnd);

        double frame_end = glfwGetTime();
        double frame_duration = frame_end - frame_start;
        if (frame_duration < target_frame_time) {
            std::this_thread::sleep_for(std::chrono::duration<double>(target_frame_time - frame_duration));
        }
    }

    // Wait for any pending connections to complete
    {
        std::lock_guard<std::mutex> lock(pending_connection_mutex);
        if (pending_connection != nullptr) {
            if (pending_connection->connection_thread.joinable()) {
                pending_connection->connection_thread.join();
            }
            if (pending_connection->session) {
                ssh_disconnect(pending_connection->session);
                ssh_free(pending_connection->session);
            }
            pending_connection.reset();
        }
    }

    // Cleanup threads
    for (auto &[key, pc] : pc_by_name_host) {
        pc->running = false;
        if (pc->logThread.joinable()) {
            pc->logThread.join();
        }
    }

    g_tcp_log_receiver.stop();
    g_network_log_db.close();

    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();
    glfwDestroyWindow(wnd);
    glfwTerminate();
    return 0;
}
