#ifndef DATABASE_HANDLE_H
#define DATABASE_HANDLE_H

#include <mutex>
#include <set>
#include <sqlite3.h>
#include <string>
#include <vector>

struct ConnectionEvent {
    int pc_id;
    std::string src_ip;
    std::string dst_ip;
    bool is_external;
    bool is_allowed;

    // Extended fields
    int protocol; // 6=TCP, 17=UDP, etc.
    int ttl;
    int packet_len;
    std::string iface; // Interface (e.g., "enp0s3")
    int src_port;
    int dst_port;
    std::string src_mac;
    std::string dst_mac;
    int tcp_flags; // Only for TCP
};

class NetworkLogDatabase {
  private:
    sqlite3 *db = nullptr;
    std::mutex db_mutex;
    std::string db_path;

    bool exec_no_callback(const char *sql);

  public:
    explicit NetworkLogDatabase(const std::string &path = "network_logs.db");
    ~NetworkLogDatabase();

    bool open();
    void close();

    // Returns database-internal pc_id (not the same as your app's id)
    int upsert_pc(const std::string &name, const std::string &host);

    bool insert_connection(const ConnectionEvent &event);
    bool insert_connections_batch(const std::vector<ConnectionEvent> &events);

    bool update_allowed_ips(int pc_db_id,
                            const std::set<std::string> &allowed_ips);

    // TODO: Not used rn – for debugging / exporting
    void export_recent_to_csv(const std::string &filename,
                              int limit = 50000) const;
};

extern NetworkLogDatabase g_network_log_db;

#endif
