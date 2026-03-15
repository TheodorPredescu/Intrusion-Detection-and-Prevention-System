from datetime import datetime
import os
import time
import struct
from typing import Deque, Dict, Set, TypedDict
from pydantic import BaseModel, Field
from typing import List, Optional
from sklearn.preprocessing import StandardScaler


class PacketData(BaseModel):
    mode: int = 255
    ts: datetime = Field(default_factory=datetime.now)
    saddr: str
    daddr: str
    sport: int
    dport: int
    protocol: int = 6
    ttl: int = 64
    packet_len: int = 0
    tcp_flags: int = 0
    iface: str = ""
    src_mac: str = ""
    dst_mac: str = ""


class PacketsRequest(BaseModel):
    packets: List[PacketData]
    pc_id: Optional[str] = None


class ModelStatus(BaseModel):
    loaded: bool
    num_support_vectors: int = 0
    last_trained: str = "Never"


class FilesConfig(BaseModel):
    pc_id: str = ""
    config_file: str = ""
    allowed_file: str = ""
    icon: str = ""
    name: str = ""
    updated_at: datetime = Field(default_factory=datetime.now)


class LogData(BaseModel):
    pc_id: str
    mode: int
    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[int] = None
    ttl: Optional[int] = None
    packet_len: Optional[int] = None
    iface: Optional[str] = None
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    tcp_flags: Optional[int] = None


class InfoCache(TypedDict):
    config: FilesConfig
    update: bool
    logs: Deque[PacketData]


class ConnectionStats(BaseModel):
    ports_out: Set[int] = Field(default_factory=set)
    protocols: Set[int] = Field(default_factory=set)
    ttls: Set[int] = Field(default_factory=set)
    packet_lens: Set[int] = Field(default_factory=set)
    tcp_flags: Set[int] = Field(default_factory=set)
    ports_in: Set[int] = Field(default_factory=set)
    mac_addr: Set[str] = Field(default_factory=set)


class TopologyEntry(BaseModel):
    # key is src_ip
    connection_dict: Dict[str, ConnectionStats] = Field(default_factory=dict)

    # List with all found ips for this entity
    topology_ip: Set[str] = Field(default_factory=set)


class TopologyType(BaseModel):
    # key is pc_id
    topology_connection: Dict[str, TopologyEntry] = Field(default_factory=dict)


# ============================================================================
# ML MODEL CLASS
# ============================================================================


# TODO: Not used rn.
class MLModel:
    SCALE = 1000000

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
        if not os.path.exists("model.bin"):
            print("[ML] No model.bin found - predictions disabled")
            return

        try:
            with open("model.bin", "rb") as f:
                num_features = struct.unpack("I", f.read(4))[0]

                means = []
                for _ in range(num_features):
                    means.append(struct.unpack("q", f.read(8))[0] / self.SCALE)

                stds = []
                for _ in range(num_features):
                    stds.append(struct.unpack("q", f.read(8))[0] / self.SCALE)

                self.scaler = StandardScaler()
                self.scaler.mean_ = means
                self.scaler.scale_ = stds

                offset = struct.unpack("q", f.read(8))[0] / self.SCALE
                num_vectors = struct.unpack("I", f.read(4))[0]

                self.num_support_vectors = num_vectors
                self.loaded = True
                self.last_trained = time.strftime("%Y-%m-%d %H:%M:%S")
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
            X = [
                [
                    features["src_port"],
                    features["dst_port"],
                    features["protocol"],
                    features["ttl"],
                    features["packet_len"],
                    features["tcp_flags"],
                ]
            ]

            X_scaled = self.scaler.transform(X)
            prediction = self.model.predict(X_scaled)
            return int(prediction[0])
        except Exception as e:
            print(f"[ML] Prediction error: {e}")
            return 1
