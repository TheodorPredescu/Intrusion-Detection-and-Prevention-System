#ifndef TCP_LOG_RECEIVER_H
#define TCP_LOG_RECEIVER_H

#include <atomic>
#include <string>
#include <thread>
#include <vector>
#include <mutex>

// Forward declaration so we can use the same struct
struct ConnectionEvent;

class TcpLogReceiver {
public:
    TcpLogReceiver();
    ~TcpLogReceiver();

    void start();           // starts listener + parser threads
    void stop();            // clean shutdown

    // Optional: get the last N lines of raw received data (for a new "Incoming Logs" tab)
    std::string get_recent_raw_logs(size_t max_lines = 500) const;

private:
    void listener_thread_func();
    void parser_thread_func();

    std::thread listener_thread;
    std::thread parser_thread;

    std::atomic<bool> running{false};

    // Thread-safe queue for raw data coming from sockets
    std::vector<std::string> raw_queue;
    mutable std::mutex       queue_mutex;

    // Very simple circular raw log buffer for UI
    std::string              raw_log_buffer;
    mutable std::mutex       raw_log_mutex;
};

extern TcpLogReceiver g_tcp_log_receiver;

#endif
