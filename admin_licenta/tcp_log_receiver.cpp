#include "tcp_log_receiver.h"
#include "database_handle.h"
#include "shared_network_types.h"
#include <arpa/inet.h>
#include <fcntl.h>
#include <iostream>
#include <netinet/in.h>
#include <sstream>
#include <sys/socket.h>
#include <unistd.h>

TcpLogReceiver g_tcp_log_receiver;

TcpLogReceiver::TcpLogReceiver() = default;
TcpLogReceiver::~TcpLogReceiver() { stop(); }

void TcpLogReceiver::start() {
    if (running)
        return;
    running = true;

    listener_thread = std::thread(&TcpLogReceiver::listener_thread_func, this);
    parser_thread = std::thread(&TcpLogReceiver::parser_thread_func, this);

    std::cout << "[TCP-LOG] Receiver started on port 1234\n";
}

void TcpLogReceiver::stop() {
    if (!running)
        return;
    running = false;

    if (listener_thread.joinable())
        listener_thread.join();
    if (parser_thread.joinable())
        parser_thread.join();

    std::cout << "[TCP-LOG] Receiver stopped\n";
}

void TcpLogReceiver::listener_thread_func() {
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        std::cerr << "[TCP-LOG] socket failed\n";
        return;
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(1234);

    if (bind(server_fd, (sockaddr *)&addr, sizeof(addr)) < 0 ||
        listen(server_fd, 8) < 0) {
        std::cerr << "[TCP-LOG] bind/listen failed on port 1234\n";
        close(server_fd);
        return;
    }

    std::vector<int> clients;

    while (running) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(server_fd, &fds);
        int maxfd = server_fd;

        for (int fd : clients) {
            FD_SET(fd, &fds);
            if (fd > maxfd)
                maxfd = fd;
        }

        timeval tv{0, 150000}; // 150 ms
        if (select(maxfd + 1, &fds, nullptr, nullptr, &tv) <= 0)
            continue;

        // new connection
        if (FD_ISSET(server_fd, &fds)) {
            sockaddr_in client{};
            socklen_t len = sizeof(client);
            int fd = accept(server_fd, (sockaddr *)&client, &len);
            if (fd >= 0) {
                char ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &client.sin_addr, ip, sizeof(ip));
                std::cout << "[TCP-LOG] New client: " << ip << "\n";
                clients.push_back(fd);
            }
        }

        // read from clients
        for (size_t i = 0; i < clients.size();) {
            int fd = clients[i];
            if (!FD_ISSET(fd, &fds)) {
                ++i;
                continue;
            }

            char buf[8192];
            ssize_t n = read(fd, buf, sizeof(buf) - 1);

            if (n <= 0) {
                close(fd);
                clients.erase(clients.begin() + i);
                continue;
            }

            buf[n] = '\0';
            {
                std::lock_guard<std::mutex> lock(queue_mutex);
                raw_queue.emplace_back(buf);
            }

            ++i;
        }
    }

    for (int fd : clients)
        close(fd);
    close(server_fd);
}

void TcpLogReceiver::parser_thread_func() {
    std::vector<ConnectionEvent> batch;
    std::string local_chunk;

    while (running) {
        std::this_thread::sleep_for(std::chrono::milliseconds(600));

        {
            std::lock_guard lock(queue_mutex);
            if (raw_queue.empty())
                continue;
            for (auto &s : raw_queue)
                local_chunk += std::move(s);
            raw_queue.clear();
        }

        // Append to raw log buffer (for optional UI display)
        {
            std::lock_guard lock(raw_log_mutex);
            raw_log_buffer += local_chunk;
            if (raw_log_buffer.size() > 200000) // keep ~200 KB
                raw_log_buffer.erase(0, raw_log_buffer.size() - 150000);
        }

        // Parse and insert to DB
        std::istringstream iss(local_chunk);
        std::string line;
        batch.clear();

        while (std::getline(iss, line)) {
            if (line.empty())
                continue;

            // Parse netfilter format: KEY=VALUE KEY=VALUE ...
            ConnectionEvent event{};
            event.pc_id = 0;
            event.is_external = false;
            event.is_allowed = false;

            // Lambda to extract string values
            auto extract_field =
                [&line](const std::string &key) -> std::string {
                size_t pos = line.find(key + "=");
                if (pos == std::string::npos)
                    return "";
                size_t start = pos + key.length() + 1;
                size_t end = line.find(' ', start);
                if (end == std::string::npos)
                    return line.substr(start);
                return line.substr(start, end - start);
            };

            // Lambda to extract integer values
            auto extract_int = [&line](const std::string &key,
                                       int default_val = 0) -> int {
                size_t pos = line.find(key + "=");
                if (pos == std::string::npos)
                    return default_val;
                size_t start = pos + key.length() + 1;
                size_t end = line.find(' ', start);
                std::string val = (end == std::string::npos)
                                      ? line.substr(start)
                                      : line.substr(start, end - start);
                try {
                    return std::stoi(val);
                } catch (...) {
                    return default_val;
                }
            };

            // Extract all netfilter fields
            event.protocol = extract_int("PROTO");
            event.ttl = extract_int("TTL");
            event.packet_len = extract_int("LEN");
            event.iface = extract_field("IFACE");
            event.src_ip = extract_field("SRC");
            event.src_port = extract_int("SPORT");
            event.dst_ip = extract_field("DST");
            event.dst_port = extract_int("DPORT");
            event.src_mac = extract_field("SRC_MAC");
            event.dst_mac = extract_field("DST_MAC");
            event.tcp_flags = extract_int("TCP_FLAGS");

            // Only add if we got at least SRC and DST
            if (!event.src_ip.empty() && !event.dst_ip.empty()) {
                batch.push_back(event);
            }
        }

        if (!batch.empty())
            g_network_log_db.insert_connections_batch(batch);

        local_chunk.clear();
    }
}

std::string TcpLogReceiver::get_recent_raw_logs(size_t max_lines) const {
    std::lock_guard lock(raw_log_mutex);
    std::istringstream iss(raw_log_buffer);
    std::string line, result;
    size_t count = 0;
    while (std::getline(iss, line) && count < max_lines) {
        result += line + "\n";
        ++count;
    }
    return result;
}
