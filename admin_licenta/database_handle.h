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
    // you can add more fields later (ports, protocol, size, …)
};

class NetworkLogDatabase {
  private:
    sqlite3 *db = nullptr;
    std::mutex db_mutex;
    std::string db_path;

    bool exec_no_callback(const char *sql);
    bool table_exists(const std::string &table_name);

  public:
    explicit NetworkLogDatabase(const std::string &path = "network_logs.db");
    ~NetworkLogDatabase();

    bool open();
    void close();

    // Returns database-internal pc_id (not the same as your app's id)
    int upsert_pc(const std::string &name, const std::string &host);

    bool insert_connection(int pc_db_id, const std::string &src_ip, const std::string &dst_ip, bool is_external,
                           bool is_allowed);

    bool insert_connections_batch(const std::vector<ConnectionEvent> &events);

    bool update_allowed_ips(int pc_db_id, const std::set<std::string> &allowed_ips);

    // Optional – for debugging / exporting
    void export_recent_to_csv(const std::string &filename, int limit = 50000) const;
};

extern NetworkLogDatabase g_network_log_db;

#endif
