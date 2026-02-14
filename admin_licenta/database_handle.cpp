#include "database_handle.h"
#include <fstream>
#include <iostream>
#include <sstream>

NetworkLogDatabase g_network_log_db("network_logs.db");

// ────────────────────────────────────────────
// Implementation
// ────────────────────────────────────────────

NetworkLogDatabase::NetworkLogDatabase(const std::string &path)
    : db_path(path) {}

NetworkLogDatabase::~NetworkLogDatabase() { close(); }

bool NetworkLogDatabase::open() {
    if (db)
        return true;

    int rc = sqlite3_open(db_path.c_str(), &db);
    if (rc != SQLITE_OK) {
        std::cerr << "Cannot open database: " << sqlite3_errmsg(db) << "\n";
        close();
        return false;
    }

    // Enable WAL mode → better concurrency
    exec_no_callback("PRAGMA journal_mode=WAL;");

    // Create schema if missing
    const char *schema = R"(
CREATE TABLE IF NOT EXISTS pc_info (
    pc_id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    host TEXT NOT NULL,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(name, host)
);

CREATE TABLE IF NOT EXISTS connections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pc_id INTEGER NOT NULL,
    ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    src_ip TEXT NOT NULL,
    dst_ip TEXT NOT NULL,
    src_port INTEGER,
    dst_port INTEGER,
    protocol INTEGER,                 -- 6=TCP, 17=UDP, etc.
    ttl INTEGER,
    packet_len INTEGER,
    iface TEXT,                        -- Interface name (e.g., enp0s3)
    src_mac TEXT,
    dst_mac TEXT,
    tcp_flags INTEGER,                 -- TCP flags (SYN, ACK, FIN, etc.)
    is_external INTEGER NOT NULL,      -- 0/1
    is_allowed INTEGER NOT NULL,       -- 0/1
    FOREIGN KEY (pc_id) REFERENCES pc_info(pc_id)
);

CREATE TABLE IF NOT EXISTS allowed_ips (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pc_id INTEGER NOT NULL,
    ip_address TEXT NOT NULL,
    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (pc_id) REFERENCES pc_info(pc_id),
    UNIQUE(pc_id, ip_address)
);

CREATE INDEX IF NOT EXISTS idx_conn_ts ON connections(ts);
CREATE INDEX IF NOT EXISTS idx_conn_pc ON connections(pc_id);
CREATE INDEX IF NOT EXISTS idx_conn_src ON connections(src_ip);
CREATE INDEX IF NOT EXISTS idx_conn_dst ON connections(dst_ip);
CREATE INDEX IF NOT EXISTS idx_conn_src_port ON connections(src_port);
CREATE INDEX IF NOT EXISTS idx_conn_dst_port ON connections(dst_port);
CREATE INDEX IF NOT EXISTS idx_conn_protocol ON connections(protocol);
CREATE INDEX IF NOT EXISTS idx_conn_external ON connections(is_external);
CREATE INDEX IF NOT EXISTS idx_conn_iface ON connections(iface);
    )";

    char *err = nullptr;
    rc = sqlite3_exec(db, schema, nullptr, nullptr, &err);
    if (rc != SQLITE_OK) {
        std::cerr << "Schema creation failed: " << err << "\n";
        sqlite3_free(err);
        close();
        return false;
    }

    std::cout << "[db] Opened " << db_path << " successfully\n";
    return true;
}

void NetworkLogDatabase::close() {
    if (db) {
        sqlite3_close(db);
        db = nullptr;
    }
}

bool NetworkLogDatabase::exec_no_callback(const char *sql) {
    char *err = nullptr;
    int rc = sqlite3_exec(db, sql, nullptr, nullptr, &err);
    if (rc != SQLITE_OK) {
        std::cerr << "SQL error: " << err << "\n";
        sqlite3_free(err);
        return false;
    }
    return true;
}

int NetworkLogDatabase::upsert_pc(const std::string &name,
                                  const std::string &host) {
    std::lock_guard lock(db_mutex);
    const char *sql = R"(
INSERT INTO pc_info (name, host, last_seen) VALUES (?, ?, CURRENT_TIMESTAMP)
ON CONFLICT(name, host) DO UPDATE SET last_seen = CURRENT_TIMESTAMP
RETURNING pc_id;
    )";

    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return -1;

    sqlite3_bind_text(stmt, 1, name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, host.c_str(), -1, SQLITE_TRANSIENT);

    int pc_id = -1;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        pc_id = sqlite3_column_int(stmt, 0);
    }

    sqlite3_finalize(stmt);
    return pc_id;
}

bool NetworkLogDatabase::insert_connection(const ConnectionEvent &event) {
    std::vector<ConnectionEvent> batch{event};
    return insert_connections_batch(batch);
}

bool NetworkLogDatabase::insert_connections_batch(
    const std::vector<ConnectionEvent> &events) {
    if (events.empty())
        return true;

    std::lock_guard lock(db_mutex);

    if (sqlite3_exec(db, "BEGIN IMMEDIATE;", nullptr, nullptr, nullptr) !=
        SQLITE_OK)
        return false;

    const char *sql = R"(
INSERT INTO connections (
    pc_id, src_ip, dst_ip, src_port, dst_port, protocol, ttl, packet_len,
    iface, src_mac, dst_mac, tcp_flags, is_external, is_allowed
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
    )";

    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        sqlite3_exec(db, "ROLLBACK;", nullptr, nullptr, nullptr);
        return false;
    }

    bool ok = true;
    for (const auto &ev : events) {
        sqlite3_bind_int(stmt, 1, ev.pc_id);
        sqlite3_bind_text(stmt, 2, ev.src_ip.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, ev.dst_ip.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 4, ev.src_port);
        sqlite3_bind_int(stmt, 5, ev.dst_port);
        sqlite3_bind_int(stmt, 6, ev.protocol);
        sqlite3_bind_int(stmt, 7, ev.ttl);
        sqlite3_bind_int(stmt, 8, ev.packet_len);
        sqlite3_bind_text(stmt, 9, ev.iface.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 10, ev.src_mac.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 11, ev.dst_mac.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 12, ev.tcp_flags);
        sqlite3_bind_int(stmt, 13, ev.is_external ? 1 : 0);
        sqlite3_bind_int(stmt, 14, ev.is_allowed ? 1 : 0);

        if (sqlite3_step(stmt) != SQLITE_DONE) {
            ok = false;
            break;
        }
        sqlite3_reset(stmt);
    }

    sqlite3_finalize(stmt);

    if (ok) {
        sqlite3_exec(db, "COMMIT;", nullptr, nullptr, nullptr);
    } else {
        sqlite3_exec(db, "ROLLBACK;", nullptr, nullptr, nullptr);
    }

    return ok;
}

bool NetworkLogDatabase::update_allowed_ips(int pc_db_id,
                                            const std::set<std::string> &ips) {
    std::lock_guard lock(db_mutex);

    // Clear old entries
    const char *del_sql = "DELETE FROM allowed_ips WHERE pc_id = ?;";
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db, del_sql, -1, &stmt, nullptr);
    sqlite3_bind_int(stmt, 1, pc_db_id);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    // Insert new ones
    const char *ins_sql =
        "INSERT OR IGNORE INTO allowed_ips (pc_id, ip_address) VALUES (?, ?);";
    sqlite3_prepare_v2(db, ins_sql, -1, &stmt, nullptr);
    for (const auto &ip : ips) {
        sqlite3_bind_int(stmt, 1, pc_db_id);
        sqlite3_bind_text(stmt, 2, ip.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(stmt);
        sqlite3_reset(stmt);
    }
    sqlite3_finalize(stmt);

    return true;
}

void NetworkLogDatabase::export_recent_to_csv(const std::string &filename,
                                              int limit) const {
    if (!db)
        return;

    std::ofstream f(filename);
    if (!f) {
        std::cerr << "Cannot open " << filename << " for writing\n";
        return;
    }

    std::ostringstream sql;
    sql << R"(
SELECT
    c.pc_id, p.name, c.ts,
    c.src_ip, c.src_port, c.dst_ip, c.dst_port,
    c.protocol, c.ttl, c.packet_len, c.iface,
    c.src_mac, c.dst_mac, c.tcp_flags,
    c.is_external, c.is_allowed
FROM connections c
JOIN pc_info p ON c.pc_id = p.pc_id
ORDER BY c.ts DESC
LIMIT )" << limit
        << ";";

    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql.str().c_str(), -1, &stmt, nullptr) !=
        SQLITE_OK)
        return;

    // header
    f << "pc_id,pc_name,timestamp,src_ip,src_port,dst_ip,dst_port,"
         "protocol,ttl,packet_len,iface,src_mac,dst_mac,tcp_flags,"
         "is_external,is_allowed\n";

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        f << sqlite3_column_int(stmt, 0) << ","
          << (const char *)sqlite3_column_text(stmt, 1) << ","
          << (const char *)sqlite3_column_text(stmt, 2) << ","
          << (const char *)sqlite3_column_text(stmt, 3) << ","
          << sqlite3_column_int(stmt, 4) << ","
          << (const char *)sqlite3_column_text(stmt, 5) << ","
          << sqlite3_column_int(stmt, 6) << "," << sqlite3_column_int(stmt, 7)
          << "," << sqlite3_column_int(stmt, 8) << ","
          << sqlite3_column_int(stmt, 9) << ","
          << (const char *)sqlite3_column_text(stmt, 10) << ","
          << (const char *)sqlite3_column_text(stmt, 11) << ","
          << (const char *)sqlite3_column_text(stmt, 12) << ","
          << sqlite3_column_int(stmt, 13) << "," << sqlite3_column_int(stmt, 14)
          << "," << sqlite3_column_int(stmt, 15) << "\n";
    }

    sqlite3_finalize(stmt);
    std::cout << "[db] Exported " << filename << "\n";
}
