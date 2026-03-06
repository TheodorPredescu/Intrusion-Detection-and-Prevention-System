import os
import uuid
import struct
import uvicorn
import pandas as pd

from fastapi import FastAPI, Query
from sklearn.svm import OneClassSVM
from contextlib import asynccontextmanager
from sklearn.preprocessing import StandardScaler
from typing import AsyncGenerator, Dict, Optional, List, Union

import models
from database_handle import Database

# Global database instance
db = Database()
# Global ML model instance
ml_model = models.MLModel()


config_content: Dict[str, models.ConfigEntity] = {}
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

    print("[server] Adding entities into the db")
    for pc_id, config_entity in config_content.items():
        print(config_entity["config"])
        added_with_success = db.save_config(
            pc_id=pc_id,
            config_file=config_entity["config"].config_file,
            allowed_file=config_entity["config"].allowed_file,
            current_mode=config_entity["config"].current_mode,
            name=config_entity["config"].name,
        )
        if not added_with_success:
            print(f"[server] failed to add config for the user {pc_id}")

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


@app.get(
    "/config/user",
    response_model=Union[models.FilesConfig, dict[str, str]],
    response_model_exclude={"icon", "name", "updated_at"},
)
async def provide_config_for_user(
    pc_id: str = Query(...),
) -> models.FilesConfig | dict[str, str]:
    """
    Used by the user to update when a change is wanted.
    A change is requested by the `update` boolean from `config_content`.
    The user will call this function every N seconds and if it gets information, it will update.
    """

    no_need_resp = {"missing": "No config files found."}

    if pc_id in config_content:
        if config_content[pc_id]["update"]:
            config_content[pc_id]["update"] = False
            return config_content[pc_id]["config"]
        else:
            return no_need_resp

    result = db.get_config(pc_id=pc_id)
    print("Gotten from the db")
    print(result)

    if result is not None:
        config_content[pc_id] = {"config": result, "update": False}

    return no_need_resp


@app.get("/config/admin")
async def provide_config_for_admin(
    pc_id: str | None = Query(default=None),
) -> List[models.FilesConfig] | models.FilesConfig | dict[str, str]:

    no_need_resp = {"missing": "No config files found."}

    if pc_id is None:
        pc_dict = {}

        for entity in config_content.values():
            pc_dict[entity["config"].pc_id] = entity["config"]

        pc_list_db = db.get_config()
        if pc_list_db:
            for entity in pc_list_db:
                if entity.pc_id not in pc_dict:
                    pc_dict[entity.pc_id] = entity

        pc_list = list(pc_dict.values())

        return pc_list if pc_list else no_need_resp

    if pc_id in config_content:
        return config_content[pc_id]["config"]

    result = db.get_config(pc_id=pc_id)
    print("Gotten from the db")
    print(result)

    if result is not None:
        config_content[pc_id] = {"config": result, "update": False}
        return result

    return no_need_resp


@app.post("/config/user", response_model=models.FilesConfig, response_model_exclude={"icon", "name", "updated_at"})
async def set_config_user(pc_id: str = Query(...), body: Optional[models.FilesConfig] = None):
    """
    The client will send only the specific configuration that will be updated.
    This call will update the map from RAM.
    If some fields are missing, they will not be nulled (the update function supports optional parameters)
    """

    if pc_id not in config_content:
        db_config = db.get_config(pc_id)

        config_content[pc_id] = {
            "config": db_config if db_config else models.FilesConfig(),
            "update": False,
        }

    # If body provided, update fields in RAM, not in db
    if body is not None:
        if body.config_file is not None:
            config_content[pc_id]["config"].config_file = body.config_file

        if body.allowed_file is not None:
            config_content[pc_id]["config"].allowed_file = body.allowed_file

        if body.current_mode is not None:
            config_content[pc_id]["config"].current_mode = body.current_mode

    return config_content[pc_id]["config"]


@app.post("/config/admin")
async def set_config_admin(pc_id: str = Query(...), body: Optional[models.FilesConfig] = None):

    if pc_id not in config_content:
        db_config = db.get_config(pc_id)

        config_content[pc_id] = {
            "config": db_config if db_config else models.FilesConfig(),
            "update": True,
        }

    # If body provided, update fields in RAM, not in db
    if body is not None:
        if body.config_file is not None:
            config_content[pc_id]["config"].config_file = body.config_file

        if body.allowed_file is not None:
            config_content[pc_id]["config"].allowed_file = body.allowed_file

        if body.current_mode is not None:
            config_content[pc_id]["config"].current_mode = body.current_mode

        if body.icon is not None:
            config_content[pc_id]["config"].icon = body.icon

        if body.name:
            config_content[pc_id]["config"].name = body.name

    config_content[pc_id]["update"] = True
    return config_content[pc_id]


@app.get("/logs")
async def get_pc_logs(pc_id: Optional[str] = Query(None), limit: int = Query(20)):
    return {"logs": db.get_logs(pc_id, limit)}


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
