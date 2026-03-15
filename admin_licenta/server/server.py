import uuid
import uvicorn

from fastapi import FastAPI, Query
from contextlib import asynccontextmanager
from typing import AsyncGenerator, Dict, Optional, List, Union
from datetime import datetime
from collections import deque

import models
from database_handle import Database

# Global database instance
db = Database()

cache_dict: Dict[str, models.InfoCache] = {}
""" All the current configuration content of each pc saved 
in a map, with the pc_id as its key and the value a instance
of the class `FilesConfig`."""

all_logs: deque[models.LogData] = deque(maxlen=500)

# key packet Id of the receiver (ower user) and the sender should be
packet_map = models.TopologyType()


def topology_extraction(packetList: List[models.PacketData], pc_id: str):

    entity = packet_map.topology_connection.setdefault(pc_id, models.TopologyEntry())

    for packetEntity in packetList:
        # The user ip that received
        entity.topology_ip.add(packetEntity.daddr)

        connection = entity.connection_dict.setdefault(packetEntity.saddr, models.ConnectionStats())

        connection.ports_in.add(packetEntity.dport)
        connection.ports_out.add(packetEntity.sport)
        connection.protocols.add(packetEntity.protocol)
        connection.ttls.add(packetEntity.ttl)
        connection.packet_lens.add(packetEntity.packet_len)
        connection.tcp_flags.add(packetEntity.tcp_flags)
        connection.mac_addr.add(packetEntity.src_mac)


def packet_to_log(packetList: List[models.PacketData], pc_id: str) -> List[models.LogData]:
    logList: List[models.LogData] = []

    for packet in packetList:
        logList.append(
            models.LogData(
                pc_id=pc_id,
                mode=packet.mode,
                timestamp=packet.ts,
                src_ip=packet.saddr,
                dst_ip=packet.daddr,
                src_port=packet.sport,
                dst_port=packet.dport,
                protocol=packet.protocol,
                ttl=packet.ttl,
                packet_len=packet.packet_len,
                iface=packet.iface,
                src_mac=packet.src_mac,
                dst_mac=packet.dst_mac,
                tcp_flags=packet.tcp_flags,
            )
        )

    return logList


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
    for pc_id, config_entity in cache_dict.items():
        print(f"User with the id {pc_id}")
        print(config_entity["config"].config_file)
        print(config_entity["config"].allowed_file)
        print(config_entity["config"].name)
        print(config_entity["config"].updated_at)
        print("\n")

        added_with_success = db.save_config(
            pc_id=pc_id,
            config_file=config_entity["config"].config_file,
            allowed_file=config_entity["config"].allowed_file,
            name=config_entity["config"].name,
            icon=config_entity["config"].icon,
            date=config_entity["config"].updated_at,
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
    packets = request.packets

    response_data = {}

    if not pc_id:
        pc_id = str(uuid.uuid4())
        response_data["pc_id"] = pc_id

    topology_extraction(packets, pc_id)

    if pc_id in cache_dict:
        cache_dict[pc_id]["logs"].extendleft(reversed(packets))
    else:
        cache_dict[pc_id] = {
            "config": models.FilesConfig(pc_id=pc_id),
            "update": False,
            "logs": deque(packets),
        }

    all_logs.extendleft(reversed(packet_to_log(packets, pc_id)))

    response_data["status"] = "ok"
    if packets and len(packets) == 0:
        response_data["message"] = "Empty request"
        response_data["packets_received"] = 0

        return response_data

    n = len(packets)
    print(f"[API] Received batch of {n} packets")

    processed = db.insert_packets_batch(packets=packets, pc_id=pc_id)
    response_data["message"] = f"Processed {processed}/{n} packets request"

    return response_data


@app.get(
    "/config/user",
    response_model=Union[models.FilesConfig, dict[str, str]],
    response_model_exclude={"pc_id", "icon", "name", "updated_at"},
)
async def provide_config_for_user(
    pc_id: str = Query(...),
) -> models.FilesConfig | dict[str, str]:
    """
    Used by the user to update when a change is wanted.

    A change is requested by the `update` boolean from `config_content`.
    The user will call this function every N seconds and if it gets information, it will update.
    """

    missing_resp = {"missing": "No config files found."}
    no_modif_request = {"up_to_date": "No modification was made since the last request."}

    if pc_id in cache_dict:
        if cache_dict[pc_id]["update"]:
            cache_dict[pc_id]["update"] = False
            return cache_dict[pc_id]["config"]
        else:
            return no_modif_request

    result = db.get_config(pc_id=pc_id)

    if result:
        cache_dict[pc_id] = {"config": result, "update": False, "logs": deque()}

    return missing_resp


@app.get("/config/admin")
async def provide_config_for_admin(
    pc_id: str | None = Query(default=None),
) -> List[models.FilesConfig] | models.FilesConfig | dict[str, str]:

    no_need_resp = {"missing": "No config files found."}

    if not pc_id:
        pc_dict: Dict[str, models.InfoCache] = {}

        for entity in cache_dict.values():
            pc_dict[entity["config"].pc_id] = entity

        pc_list_db = db.get_config()
        if pc_list_db:
            for entity in pc_list_db:
                if entity.pc_id not in pc_dict:
                    pc_dict[entity.pc_id] = {"config": entity, "update": False, "logs": deque()}

                else:
                    if not pc_dict[entity.pc_id]["config"].config_file:
                        pc_dict[entity.pc_id]["config"].config_file = entity.config_file

                    if not pc_dict[entity.pc_id]["config"].allowed_file:
                        pc_dict[entity.pc_id]["config"].allowed_file = entity.allowed_file

                    if not pc_dict[entity.pc_id]["config"].icon:
                        pc_dict[entity.pc_id]["config"].icon = entity.icon

                    if not pc_dict[entity.pc_id]["config"].name:
                        pc_dict[entity.pc_id]["config"].name = entity.name

        pc_list = [entry["config"] for entry in pc_dict.values()]

        return pc_list if pc_list else no_need_resp

    if pc_id in cache_dict:
        return cache_dict[pc_id]["config"]

    result = db.get_config(pc_id=pc_id)

    if result:
        cache_dict[pc_id] = {"config": result, "update": False, "logs": deque()}
        return result

    return no_need_resp


@app.post("/config/user", response_model=models.FilesConfig, response_model_exclude={"icon", "name", "updated_at"})
async def set_config_user(pc_id: str = Query(...), body: Optional[models.FilesConfig] = None):
    """
    The client will send only the specific configuration that will be updated.
    This call will update the map from RAM.
    If some fields are missing, they will not be nulled (the update function supports optional parameters)
    """

    if pc_id not in cache_dict:
        db_config = db.get_config(pc_id)

        cache_dict[pc_id] = {
            "config": db_config if db_config else models.FilesConfig(pc_id=pc_id),
            "update": False,
            "logs": deque(),
        }

    # If body provided, update fields in RAM, not in db
    update_date = False

    if body:
        if body.config_file:
            cache_dict[pc_id]["config"].config_file = body.config_file
            update_date = True

        if body.allowed_file:
            cache_dict[pc_id]["config"].allowed_file = body.allowed_file
            update_date = True

    if update_date:
        cache_dict[pc_id]["config"].updated_at = datetime.now()

        # Reset the information from topology for that pc_id when a modification is detected
        packet_map.topology_connection[pc_id] = models.TopologyEntry()

    # Resolve any inconcinsancies between the pc from FilesConfig and the actual key used.
    if pc_id != cache_dict[pc_id]["config"].pc_id or not cache_dict[pc_id]["config"].pc_id:
        cache_dict[pc_id]["config"].pc_id = pc_id

    if not cache_dict[pc_id]["config"].icon:
        cache_dict[pc_id]["config"].icon = db.get_default_icon()

    return cache_dict[pc_id]["config"]


@app.post("/config/admin")
async def set_config_admin(pc_id: str = Query(...), body: Optional[models.FilesConfig] = None):

    if pc_id not in cache_dict:
        db_config = db.get_config(pc_id)

        cache_dict[pc_id] = {
            "config": db_config if db_config else models.FilesConfig(pc_id=pc_id),
            "update": True,
            "logs": deque(),
        }

    update_date = False
    updated_configuration = False

    # If body provided, update fields in RAM, not in db
    if body:
        if body.config_file:
            cache_dict[pc_id]["config"].config_file = body.config_file
            updated_configuration = True
            update_date = True

        if body.allowed_file:
            cache_dict[pc_id]["config"].allowed_file = body.allowed_file
            updated_configuration = True
            update_date = True

        if body.icon:
            cache_dict[pc_id]["config"].icon = body.icon
            update_date = True

        if body.name:
            cache_dict[pc_id]["config"].name = body.name
            update_date = True

    if update_date:
        cache_dict[pc_id]["config"].updated_at = datetime.now()

    # Reset the information from topology for that pc_id when a modification is detected
    if updated_configuration:
        packet_map.topology_connection[pc_id] = models.TopologyEntry()

    # Resolve any inconcinsancies between the pc from FilesConfig and the actual key used.
    if pc_id != cache_dict[pc_id]["config"].pc_id or not cache_dict[pc_id]["config"].pc_id:
        cache_dict[pc_id]["config"].pc_id = pc_id

    if not cache_dict[pc_id]["config"].icon:
        cache_dict[pc_id]["config"].icon = db.get_default_icon()

    cache_dict[pc_id]["update"] = True
    return cache_dict[pc_id]["config"]


# TODO: Not rly sure rn
@app.get("/logs")
async def get_pc_logs(pc_id: Optional[str] = Query(None), limit: int = Query(20)):
    if pc_id and pc_id in cache_dict:
        logs_list = list(cache_dict[pc_id]["logs"])[:limit]
        return {"logs": packet_to_log(logs_list, pc_id)}

    if pc_id:
        filtered = [log for log in all_logs if log.pc_id == pc_id][:limit]
        return {"logs": filtered}

    return {"logs": list(all_logs)[:limit]}
    # return {"logs": db.get_logs(pc_id, limit)}


@app.get("/topology")
async def get_topology(pc_id: Optional[str] = Query(None)):
    if pc_id:
        return {pc_id: packet_map.topology_connection.get(pc_id)}

    return packet_map.topology_connection


# ============================================================================
# ___________________________________ MAIN ___________________________________
# ============================================================================

if __name__ == "__main__":
    uvicorn.run("server:app", host="0.0.0.0", port=8080, reload=True, log_level="info")
