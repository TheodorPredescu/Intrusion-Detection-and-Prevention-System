import sqlite3
from models import LogData, PacketData, FilesConfig
from typing import Optional, List, Any, overload
import base64
from datetime import datetime

DATABASE = "network_logs.db"
DEFAULT_ICON_PATH: str = "default_icon.png"


class Database:
    def __init__(self, db_path: str = DATABASE):
        self.db_path = db_path
        self.conn: Optional[sqlite3.Connection] = None
        self.DEFAULT_ICON: bytes

    def open(self) -> bool:
        """Open database and create schema if needed"""
        try:
            self.conn = sqlite3.connect(self.db_path, check_same_thread=False)

            # Enable WAL mode for concurrent read/write
            self.conn.execute("PRAGMA journal_mode=WAL;")

            # Create schema
            schema = """
            CREATE TABLE IF NOT EXISTS connections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mode INTEGER,
                pc_id TEXT NOT NULL,
                ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                src_ip TEXT NOT NULL,
                dst_ip TEXT NOT NULL,
                src_port INTEGER,
                dst_port INTEGER,
                protocol INTEGER,
                ttl INTEGER,
                packet_len INTEGER,
                iface TEXT,
                src_mac TEXT,
                dst_mac TEXT,
                tcp_flags INTEGER
            );
            
            CREATE INDEX IF NOT EXISTS idx_conn_ts ON connections(ts);
            CREATE INDEX IF NOT EXISTS idx_conn_pc ON connections(pc_id);
            CREATE INDEX IF NOT EXISTS idx_conn_src ON connections(src_ip);
            CREATE INDEX IF NOT EXISTS idx_conn_dst ON connections(dst_ip);
            CREATE INDEX IF NOT EXISTS idx_conn_src_port ON connections(src_port);
            CREATE INDEX IF NOT EXISTS idx_conn_dst_port ON connections(dst_port);
            CREATE INDEX IF NOT EXISTS idx_conn_protocol ON connections(protocol);
            CREATE INDEX IF NOT EXISTS idx_conn_iface ON connections(iface);

            CREATE TABLE IF NOT EXISTS pc_configs (
                pc_id TEXT PRIMARY KEY,
                config_file TEXT,
                allowed_file TEXT,
                icon BLOB,
                name TEXT DEFAULT "",
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE INDEX IF NOT EXISTS idx_pc_configs_updated ON pc_configs(updated_at);
            """

            self.conn.executescript(schema)
            self.conn.commit()

            print(f"[DB] Opened {self.db_path} successfully")

            with open(DEFAULT_ICON_PATH, "rb") as file:
                self.DEFAULT_ICON = file.read()

            return True

        except sqlite3.Error as e:
            print(f"[DB] Failed to open database: {e}")
            return False

    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()
            self.conn = None
            print("[DB] Database connection closed")

    def get_connection(self) -> sqlite3.Connection:
        """Get a new connection (for thread safety)"""
        return sqlite3.connect(self.db_path, timeout=10.0)

    @overload
    def get_config(self) -> Optional[List[FilesConfig]]: ...

    @overload
    def get_config(self, pc_id: str) -> Optional[FilesConfig]: ...

    def get_config(self, pc_id: str | None = None):
        """Get PC configuration"""
        conn = None
        try:
            conn = self.get_connection()
            cursor = conn.cursor()

            if pc_id is None:
                query = """
                    SELECT 
                        pc_id,
                        config_file,
                        allowed_file,
                        icon,
                        name,
                        updated_at
                    FROM pc_configs
                    ORDER BY updated_at DESC
                """

                cursor.execute(query)
                rows = cursor.fetchall()

                pcs = []
                for row in rows:
                    pcs.append(self.formatRow(row))

                print(f"[DB] Retrieved {len(pcs)} PCs from config")
                return pcs

            else:
                cursor.execute(
                    """
                    SELECT pc_id, config_file, allowed_file, icon, name, updated_at
                    FROM pc_configs
                    WHERE pc_id = ?
                """,
                    (pc_id,),
                )

                row = cursor.fetchone()
                if row is None:
                    return None
                return self.formatRow(row)

        except sqlite3.Error as e:
            print(f"[DB] Failed to get config: {e}")
            return None
        finally:
            if conn:
                conn.close()

    def get_default_icon(self) -> str:
        return base64.b64encode(self.DEFAULT_ICON).decode("utf-8")

    def formatRow(self, row: Any) -> FilesConfig:
        return FilesConfig(
            pc_id=row[0],
            config_file=row[1],
            allowed_file=row[2],
            icon=row[3] if row[3] else self.get_default_icon(),
            name=row[4],
            updated_at=row[5],
        )

    def save_config(
        self,
        pc_id: str,
        config_file: Optional[str] = None,
        allowed_file: Optional[str] = None,
        icon: Optional[str] = None,
        name: Optional[str] = None,
        date: Optional[datetime] = None,
    ) -> bool:
        """Save or update PC configuration (only updates provided fields)"""
        conn = None
        try:
            conn = self.get_connection()
            cursor = conn.cursor()

            # Check if record exists
            cursor.execute("SELECT 1 FROM pc_configs WHERE pc_id = ?", (pc_id,))
            exists = cursor.fetchone() is not None

            if exists:
                # Update only provided fields
                updates = []
                params = []

                if config_file:
                    updates.append("config_file = ?")
                    params.append(config_file)

                if allowed_file:
                    updates.append("allowed_file = ?")
                    params.append(allowed_file)

                if icon:
                    updates.append("icon = ?")
                    params.append(icon)

                if name:
                    updates.append("name = ?")
                    params.append(name)

                if date is not None:
                    updates.append("updated_at = ?")
                    params.append(date)

                if not updates:
                    # Nothing to update
                    return True

                updates.append("updated_at = CURRENT_TIMESTAMP")
                params.append(pc_id)

                query = f"UPDATE pc_configs SET {', '.join(updates)} WHERE pc_id = ?"
                cursor.execute(query, params)
            else:
                # Insert new record (both can be NULL)
                cursor.execute(
                    """
                    INSERT INTO pc_configs (pc_id, config_file, allowed_file, icon, name, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                """,
                    (pc_id, config_file, allowed_file, icon, name or "", date),
                )

            conn.commit()
            print(f"[DB] Saved config for pc_id={pc_id}")
            return True

        except sqlite3.Error as e:
            print(f"[DB] Failed to save config: {e}")
            if conn:
                conn.rollback()
            return False
        finally:
            if conn:
                conn.close()

    def get_logs(self, pc_id: Optional[str], limit: int, offset: int = 0):
        conn = None
        logs: List[LogData] = []

        try:
            conn = self.get_connection()
            cursor = conn.cursor()

            if pc_id:
                query = """
                    SELECT 
                        pc_id,
                        ts,
                        src_ip,
                        dst_ip,
                        src_port,
                        dst_port,
                        protocol,
                        ttl,
                        packet_len,
                        iface,
                        src_mac,
                        dst_mac,
                        tcp_flags,
                        mode
                    FROM connections
                    WHERE pc_id = ?
                    ORDER BY ts DESC
                    LIMIT ? OFFSET ?
                """
                cursor.execute(query, (pc_id, limit, offset))
            else:
                query = """
                    SELECT 
                        pc_id,
                        ts,
                        src_ip,
                        dst_ip,
                        src_port,
                        dst_port,
                        protocol,
                        ttl,
                        packet_len,
                        iface,
                        src_mac,
                        dst_mac,
                        tcp_flags,
                        mode
                    FROM connections
                    ORDER BY ts DESC
                    LIMIT ? OFFSET ?
                """
                cursor.execute(query, (limit, offset))
            rows = cursor.fetchall()
            for row in rows:
                logs.append(
                    LogData(
                        pc_id=row[0],
                        timestamp=row[1],
                        src_ip=row[2],
                        dst_ip=row[3],
                        src_port=row[4],
                        dst_port=row[5],
                        protocol=row[6],
                        ttl=row[7],
                        packet_len=row[8],
                        iface=row[9],
                        src_mac=row[10],
                        dst_mac=row[11],
                        tcp_flags=row[12],
                        mode=row[13],
                    )
                )

            print(f"[DB] Retrieved {len(logs)} logs for pc_id={pc_id}")

        except sqlite3.Error as e:
            print(f"[DB] Failed to fetch logs for pc_id={pc_id}: {e}")
            logs = []

        finally:
            if conn:
                conn.close()
            return logs

    def insert_packets_batch(self, packets: List["PacketData"], pc_id: str) -> int:
        """Batch insert packets into database"""
        if not packets:
            return 0

        conn = None
        try:
            conn = self.get_connection()
            cursor = conn.cursor()

            insert_query = """
                INSERT INTO connections
                (pc_id, mode, src_ip, dst_ip, src_port, dst_port, protocol, ttl,
                 packet_len, tcp_flags, iface, src_mac, dst_mac)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """

            values = [
                (
                    pc_id,
                    pkt.mode,
                    pkt.saddr,
                    pkt.daddr,
                    pkt.sport,
                    pkt.dport,
                    pkt.protocol,
                    pkt.ttl,
                    pkt.packet_len,
                    pkt.tcp_flags,
                    pkt.iface,
                    pkt.src_mac,
                    pkt.dst_mac,
                )
                for pkt in packets
            ]

            cursor.executemany(insert_query, values)
            conn.commit()
            processed = len(values)

            print(f"[DB] Inserted {processed} packets")
            return processed

        except sqlite3.Error as e:
            print(f"[DB] Batch insert failed: {e}")
            if conn:
                conn.rollback()
            return 0
        finally:
            if conn:
                conn.close()
