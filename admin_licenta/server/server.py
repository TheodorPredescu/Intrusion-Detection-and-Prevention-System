from contextlib import asynccontextmanager
import os
import time
import struct
import sqlite3
import pandas as pd
import threading
from typing import AsyncGenerator, List, Dict
from fastapi import FastAPI, BackgroundTasks
from pydantic import BaseModel
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler
import uvicorn

SCALE = 1000000

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

class StatusResponse(BaseModel):
    status: str
    message: str = ""
    packets_received: int = 0

class ModelStatus(BaseModel):
    loaded: bool
    num_support_vectors: int = 0
    last_trained: str = "Never"

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

def insert_packet_to_db(
    saddr: str, daddr: str, sport: int, dport: int, 
    protocol: int = 6, ttl: int = 64, packet_len: int = 0, 
    tcp_flags: int = 0, iface: str = '', src_mac: str = '', 
    dst_mac: str = '', pc_id: int = 1, is_external: int = 0, 
    is_allowed: int = 0
):
    """Insert packet into database"""
    try:
        conn = sqlite3.connect('../network_logs.db', timeout=10.0)
        c = conn.cursor()
        c.execute("""
            INSERT INTO connections 
            (pc_id, src_ip, dst_ip, src_port, dst_port, protocol, ttl, 
             packet_len, tcp_flags, iface, src_mac, dst_mac, is_external, is_allowed)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (pc_id, saddr, daddr, sport, dport, protocol, ttl, 
              packet_len, tcp_flags, iface, src_mac, dst_mac, is_external, is_allowed))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"[DB] Insert error: {e}")
        return False

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
    
    # Start training watcher in background thread
    watcher_thread = threading.Thread(target=watch_for_trigger, daemon=True)
    watcher_thread.start()
    
    print("[APP] Training watcher started")

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
        "database": os.path.exists('../network_logs.db'),
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

@app.post("/packets", response_model=StatusResponse)
async def receive_packets(request: PacketsRequest):
    """
    Receive batch of network packets
    
    - **packets**: List of packet data to process
    """
    packets = request.packets
    n = len(packets)
    if n == 0:
        return StatusResponse(status="ok", packets_received=0, message="Empty request")

    print(f"[API] Received batch of {n} packets")

    processed = 0

    conn = None
    try:
        conn = sqlite3.connect('../network_logs.db', timeout=10.0)
        cursor = conn.cursor()

        insert_query = """
            INSERT INTO connections
            (pc_id, src_ip, dst_ip, src_port, dst_port, protocol, ttl,
             packet_len, tcp_flags, iface, src_mac, dst_mac, is_external, is_allowed)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """

        values = []
        for pkt in packets:

            values.append(
                (
                    1, 
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
                    0,  # is_external — compute if needed
                    0,  # is_allowed   — compute if needed
                )
            )

        if values:
            cursor.executemany(insert_query, values)
            conn.commit()
            processed = len(values)

        print(f"[DB] Inserted {processed}/{n} packets")

    except Exception as e:
        print(f"[DB] Batch insert failed: {e}")
        if conn:
            conn.rollback()
    finally:
        if conn:
            conn.close()

    return StatusResponse(
        status="ok",
        message=f"Processed {processed}/{n} packets",
        packets_received=n,
    )

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

# ============================================================================
# BACKGROUND TASKS
# ============================================================================

def train_model_task():
    """Train ML model on database data"""
    print("[ML] Training model...")
    
    try:
        conn = sqlite3.connect('../network_logs.db')
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

def watch_for_trigger():
    """Watch for training trigger file"""
    print("[ML] Watching for train trigger...")
    
    while True:
        if os.path.exists('train_trigger.txt'):
            print("[ML] Training triggered!")
            train_model_task()
            os.remove('train_trigger.txt')
            time.sleep(5)
        
        time.sleep(1)

# ============================================================================
# MAIN
# ============================================================================

if __name__ == '__main__':
    # Run with uvicorn
    uvicorn.run(
        "train:app",  # Change "main" to your filename if different
        host="0.0.0.0",
        port=8080,
        reload=True,  # Auto-reload on code changes
        log_level="info"
    )
