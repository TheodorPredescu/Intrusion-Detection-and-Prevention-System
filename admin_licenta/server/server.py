from contextlib import asynccontextmanager
import os
import time
import struct
import sqlite3
import pandas as pd
from typing import AsyncGenerator, List, Dict, Optional
from fastapi import FastAPI, BackgroundTasks
from pydantic import BaseModel
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler
import uvicorn
import uuid

SCALE = 1000000
DATABASE = 'network_logs.db'

# ============================================================================
# PYDANTIC MODELS (Request/Response validation)
# ============================================================================

class PacketData(BaseModel):
    saddr: str
    daddr: str
    sport: int
    dport: int
    protocol: int = 6
    ttl: int = 64
    packet_len: int = 0
    tcp_flags: int = 0
    iface: str = ''
    src_mac: str = ''
    dst_mac: str = ''

class PacketsRequest(BaseModel):
    packets: List[PacketData]
    pc_id: Optional[str] = None

class ModelStatus(BaseModel):
    loaded: bool
    num_support_vectors: int = 0
    last_trained: str = "Never"

# ============================================================================
# DATABASE
# ============================================================================

class Database:
    def __init__(self, db_path: str = DATABASE):
        self.db_path = db_path
        self.conn: Optional[sqlite3.Connection] = None
        
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
            """
            
            self.conn.executescript(schema)
            self.conn.commit()
            
            print(f"[DB] Opened {self.db_path} successfully")
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
    
    def insert_packets_batch(self, packets: List['PacketData'], pc_id: str) -> int:
        """Batch insert packets into database"""
        if not packets:
            return 0
        
        conn = None
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            insert_query = """
                INSERT INTO connections
                (pc_id, src_ip, dst_ip, src_port, dst_port, protocol, ttl,
                 packet_len, tcp_flags, iface, src_mac, dst_mac)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """
            
            values = [
                (
                    pc_id,
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
    
    
    # def export_for_training(self, limit: int = 100000) -> Optional[pd.DataFrame]:
    #     """Export data for ML training"""
    #     try:
    #         conn = self.get_connection()
    #
    #         query = """
    #             SELECT src_port, dst_port, protocol, ttl, packet_len, tcp_flags
    #             FROM connections
    #             LIMIT ?
    #         """
    #
    #         df = pd.read_sql_query(query, conn, params=(limit,))
    #         conn.close()
    #
    #         return df if len(df) > 0 else None
    #
    #     except Exception as e:
    #         print(f"[DB] Failed to export data: {e}")
    #         return None

# Global database instance
db = Database()
# ============================================================================
# ML MODEL CLASS
# ============================================================================

class MLModel:
    def __init__(self):
        self.model = None
        self.scaler = None
        self.loaded = False
        self.num_support_vectors = 0
        self.last_trained = "Never"
        self.load_model()
    
    # TODO: Need to check this
    def load_model(self):
        """Load trained model from binary"""
        if not os.path.exists('model.bin'):
            print("[ML] No model.bin found - predictions disabled")
            return
        
        try:
            with open('model.bin', 'rb') as f:
                num_features = struct.unpack('I', f.read(4))[0]
                
                means = []
                for _ in range(num_features):
                    means.append(struct.unpack('q', f.read(8))[0] / SCALE)
                
                stds = []
                for _ in range(num_features):
                    stds.append(struct.unpack('q', f.read(8))[0] / SCALE)
                
                self.scaler = StandardScaler()
                self.scaler.mean_ = means
                self.scaler.scale_ = stds
                
                offset = struct.unpack('q', f.read(8))[0] / SCALE
                num_vectors = struct.unpack('I', f.read(4))[0]
                
                self.num_support_vectors = num_vectors
                self.loaded = True
                self.last_trained = time.strftime('%Y-%m-%d %H:%M:%S')
                print(f"[ML] Model loaded ({num_vectors} support vectors)")
        except Exception as e:
            print(f"[ML] Failed to load model: {e}")
    
    # TODO: Not used rn.
    def predict(self, features: Dict[str, int]) -> int:
        """Predict if packet is anomaly (-1) or normal (1)"""
        if not self.loaded:
            return 1  # Default to normal if no model
        
        try:
            if self.scaler is None or self.model is None:
                raise ValueError
            # Extract features in correct order
            X = [[
                features['src_port'],
                features['dst_port'],
                features['protocol'],
                features['ttl'],
                features['packet_len'],
                features['tcp_flags']
            ]]
            
            X_scaled = self.scaler.transform(X)
            prediction = self.model.predict(X_scaled)
            return int(prediction[0])
        except Exception as e:
            print(f"[ML] Prediction error: {e}")
            return 1

# ============================================================================
# DATABASE FUNCTIONS
# ============================================================================


# TODO: Not used.
def export_oneclass_svm_binary(model, scaler, filename='model.bin'):
    """Export One-Class SVM to binary format"""
    tempFileName = filename + ".tmp"
    with open(tempFileName, 'wb') as f:
        f.write(struct.pack('I', 6))  # num features
        for mean in scaler.mean_:
            f.write(struct.pack('q', int(float(mean) * SCALE)))
        for std in scaler.scale_:
            f.write(struct.pack('q', int(float(std) * SCALE)))
        
        f.write(struct.pack('q', int(float(model.offset_[0]) * SCALE)))
        f.write(struct.pack('I', len(model.support_vectors_)))
        
        for sv in model.support_vectors_:
            for val in sv:
                f.write(struct.pack('q', int(float(val) * SCALE)))
        
        for coef in model.dual_coef_[0]:
            f.write(struct.pack('q', int(float(coef) * SCALE)))
    
    if os.path.exists(filename):
        os.remove(filename)
    os.rename(tempFileName, filename)
    print(f"[ML] One-Class SVM exported ({len(model.support_vectors_)} support vectors)")

# ============================================================================
# FASTAPI APP
# ============================================================================

# STARTUP
@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Run on application startup"""
    print("[APP] Starting Network Packet Receiver")
    
    if not db.open():
        print("[APP] FATAL: Failed to initialize database")
        raise RuntimeError("Database initialization failed")

    yield

    """Run on application shutdown"""
    print("[APP] Shutting down")

app = FastAPI(
    title="Network Packet Receiver",
    description="API for receiving and processing network packets with ML anomaly detection",
    version="1.0.0",
    lifespan=lifespan
)

# Global ML model instance
ml_model = MLModel()

@app.get("/")
async def root():
    """Health check endpoint"""
    return {
        "status": "running",
        "service": "Network Packet Receiver",
        "version": "1.0.0"
    }

@app.get("/health")
async def health():
    """Detailed health check"""
    return {
        "status": "healthy",
        "database": os.path.exists(DATABASE),
        "model_loaded": ml_model.loaded,
        "timestamp": time.strftime('%Y-%m-%d %H:%M:%S')
    }

@app.get("/model/status", response_model=ModelStatus)
async def model_status():
    """Get ML model status"""
    return ModelStatus(
        loaded=ml_model.loaded,
        num_support_vectors=ml_model.num_support_vectors,
        last_trained=ml_model.last_trained
    )

@app.post("/packets")
async def receive_packets(request: PacketsRequest):
    """
    Receive batch of network packets
    
    - **packets**: List of packet data to process
    """
    print(request)
    pc_id = request.pc_id
    generated_pc_id: str | None = None

    if not pc_id:
        generated_pc_id = str(uuid.uuid4())
        pc_id = generated_pc_id

    packets = request.packets
    if packets and len(packets) == 0:
        response_data = {
                "status": "ok",
                "message": "Empty request",
                "packets_received": 0,
            }

        if generated_pc_id is not None:
            print("\nsending the pc_id\n")
            response_data["pc_id"] = generated_pc_id

        return response_data

    n = len(packets)
    print(f"[API] Received batch of {n} packets")
    
    processed = db.insert_packets_batch(packets=packets, pc_id=pc_id)

    response_data = {
            "status": "ok",
            "message": f"Processed {processed}/{n} packets request",
            "packets_received": n,
        }

    if generated_pc_id is not None:
        response_data["pc_id"] = generated_pc_id

    return response_data

@app.post("/model/train")
async def train_model(background_tasks: BackgroundTasks):
    """
    Trigger model training on stored data
    """
    background_tasks.add_task(train_model_task)
    return {
        "status": "training_started",
        "message": "Model training started in background"
    }

@app.post("/model/reload")
async def reload_model():
    """
    Reload model from disk
    """
    global ml_model
    ml_model = MLModel()
    
    return {
        "status": "reloaded",
        "loaded": ml_model.loaded,
        "num_support_vectors": ml_model.num_support_vectors
    }

@app.post("/config/")
async def provide_config(request: dict):
    pc_id = request.get("pc_id")
    if not pc_id:
        return {"error": "missing pc_id"}

    # Here you decide what config to send for this pc_id
    # For example: read from DB, file, or generate dynamically
    config_content = """server IP 192.168.0.114
server port 8080
Monitoring
allowed_file /etc/allowed_file.txt
"""

    allowed_content = """192.168.0.125:8080, 8081
8.8.8.8
1.1.1.1
"""

    return {
        "status": "ok"
        # "config": config_content
        # "allowed": allowed_content
    }
# ============================================================================
# BACKGROUND TASKS
# ============================================================================

def train_model_task():
    """Train ML model on database data"""
    print("[ML] Training model...")
    
    try:
        conn = db.get_connection()
        df = pd.read_sql_query("""
            SELECT src_port, dst_port, protocol, ttl, packet_len, tcp_flags
            FROM connections
            ORDER BY ts DESC
            LIMIT 100000
        """, conn)
        conn.close()
        
        if len(df) < 100:
            print(f"[ML] Not enough data ({len(df)} samples)")
            return
        
        # Normalize and train
        scaler = StandardScaler()
        X = scaler.fit_transform(df[['src_port', 'dst_port', 'protocol', 'ttl', 'packet_len', 'tcp_flags']])
        
        model = OneClassSVM(kernel='rbf', gamma='auto', nu=0.02)
        model.fit(X)
        
        export_oneclass_svm_binary(model, scaler, 'model.bin')
        
        # Reload model
        global ml_model
        ml_model = MLModel()
        
        print(f"[ML] Model trained on {len(df)} samples")
    except Exception as e:
        print(f"[ML] Training error: {e}")

# ============================================================================
# MAIN
# ============================================================================

if __name__ == '__main__':
    # Run with uvicorn
    uvicorn.run(
        "server:app",
        host="0.0.0.0",
        port=8080,
        reload=True,
        log_level="info"
    )
