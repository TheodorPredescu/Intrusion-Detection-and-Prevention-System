import os
import uuid
import struct
import uvicorn
import pandas as pd

from fastapi import FastAPI, Query
from sklearn.svm import OneClassSVM
from contextlib import asynccontextmanager
from sklearn.preprocessing import StandardScaler
from typing import AsyncGenerator, Dict, Optional

import models
from database_handle import Database

# Global database instance
db = Database()
# Global ML model instance
ml_model = models.MLModel()


config_content: Dict[str, models.FilesConfig] = {}
""" All the current configuration content of each pc saved 
in a map, with the pc_id as its key and the value a instance
of the class `FilesConfig`."""


# TODO: Not used.
def export_oneclass_svm_binary(model, scaler, filename="model.bin"):
    """Export One-Class SVM to binary format"""
    tempFileName = filename + ".tmp"
    with open(tempFileName, "wb") as f:
        f.write(struct.pack("I", 6))  # num features
        for mean in scaler.mean_:
            f.write(struct.pack("q", int(float(mean) * ml_model.SCALE)))
        for std in scaler.scale_:
            f.write(struct.pack("q", int(float(std) * ml_model.SCALE)))

        f.write(struct.pack("q", int(float(model.offset_[0]) * ml_model.SCALE)))
        f.write(struct.pack("I", len(model.support_vectors_)))

        for sv in model.support_vectors_:
            for val in sv:
                f.write(struct.pack("q", int(float(val) * ml_model.SCALE)))

        for coef in model.dual_coef_[0]:
            f.write(struct.pack("q", int(float(coef) * ml_model.SCALE)))

    if os.path.exists(filename):
        os.remove(filename)
    os.rename(tempFileName, filename)
    print(f"[ML] One-Class SVM exported ({len(model.support_vectors_)} support vectors)")


# ============================================================================
# ________________________________ FASTAPI APP _______________________________
# ============================================================================


# STARTUP
@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncGenerator[None, None]:
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
    lifespan=lifespan,
)


@app.post("/packets")
async def receive_packets(request: models.PacketsRequest):
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


# @app.post("/model/train")
# async def train_model(background_tasks: BackgroundTasks):
#     """
#     Trigger model training on stored data
#     """
#     background_tasks.add_task(train_model_task)
#     return {
#         "status": "training_started",
#         "message": "Model training started in background"
#     }

# @app.post("/model/reload")
# async def reload_model():
#     """
#     Reload model from disk
#     """
#     global ml_model
#     ml_model = MLModel()
#
#     return {
#         "status": "reloaded",
#         "loaded": ml_model.loaded,
#         "num_support_vectors": ml_model.num_support_vectors
#     }


# TODO: not used, but it should be implemented next.
@app.get("/config")
async def provide_config(pc_id: str = Query(...)):

    if pc_id is not None and pc_id in config_content:
        return config_content[pc_id]

    result = db.get_config(pc_id=pc_id)
    if result is not None:
        config_content[pc_id] = result
        return result

    return {"missing": "No config files found."}


@app.post("/config")
async def set_config(pc_id: str = Query(...), body: Optional[models.FilesConfig] = None):
    if pc_id not in config_content:
        db_config = db.get_config(pc_id)

        if db_config:
            config_content[pc_id] = models.FilesConfig(
                config_file=db_config.config_file,
                allowed_file=db_config.allowed_file,
                current_mode=db_config.current_mode,
            )
        else:
            config_content[pc_id] = models.FilesConfig()

    # If body provided, update fields
    if body is not None:
        if body.config_file is not None:
            config_content[pc_id].config_file = body.config_file

        if body.allowed_file is not None:
            config_content[pc_id].allowed_file = body.allowed_file

        if body.current_mode is not None:
            config_content[pc_id].current_mode = body.current_mode

        added_with_success = db.save_config(
            pc_id=pc_id,
            config_file=config_content[pc_id].config_file,
            allowed_file=config_content[pc_id].allowed_file,
            current_mode=config_content[pc_id].current_mode,
        )

        print(f"Tried to add it in the db the new configuration, result: {added_with_success}")

    return config_content[pc_id]


@app.get("/logs")
async def get_pc_logs(pc_id: Optional[str] = Query(None), limit: int = Query(20)):
    return {"logs": db.get_logs(pc_id, limit)}


@app.get("/pcs")
async def get_pcs():
    return {"pcs": db.get_pcs()}


# ============================================================================
# _____________________________ BACKGROUND TASKS _____________________________
# ============================================================================


# TODO: It is not used rn
def train_model_task():
    """Train ML model on database data"""
    print("[ML] Training model...")

    try:
        conn = db.get_connection()
        df = pd.read_sql_query(
            """
            SELECT src_port, dst_port, protocol, ttl, packet_len, tcp_flags
            FROM connections
            ORDER BY ts DESC
            LIMIT 100000
        """,
            conn,
        )
        conn.close()

        if len(df) < 100:
            print(f"[ML] Not enough data ({len(df)} samples)")
            return

        # Normalize and train
        scaler = StandardScaler()
        X = scaler.fit_transform(df[["src_port", "dst_port", "protocol", "ttl", "packet_len", "tcp_flags"]])

        model = OneClassSVM(kernel="rbf", gamma="auto", nu=0.02)
        model.fit(X)

        export_oneclass_svm_binary(model, scaler, "model.bin")

        # Reload model
        global ml_model
        ml_model = models.MLModel()

        print(f"[ML] Model trained on {len(df)} samples")
    except Exception as e:
        print(f"[ML] Training error: {e}")


# ============================================================================
# ___________________________________ MAIN ___________________________________
# ============================================================================

if __name__ == "__main__":
    # Run with uvicorn
    uvicorn.run("server:app", host="0.0.0.0", port=8080, reload=True, log_level="info")
