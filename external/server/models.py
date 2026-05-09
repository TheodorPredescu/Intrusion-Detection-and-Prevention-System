from datetime import datetime
from typing import Deque, Dict, Set, TypedDict
from pydantic import BaseModel, Field
from typing import List, Optional


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
    ports_in: Set[int] = Field(default_factory=set)
    protocols: Set[int] = Field(default_factory=set)
    ttls: Set[int] = Field(default_factory=set)
    packet_lens: Set[int] = Field(default_factory=set)
    tcp_flags: Set[int] = Field(default_factory=set)
    mac_addr: Set[str] = Field(default_factory=set)


class TopologyEntry(BaseModel):
    """
    Represents a network topology entry.

    Attributes:
        connection_dict: Key is src_ip combined with port.
        topology_ip: Set of all discovered IPs for this entity.
    """

    connection_dict: Dict[str, ConnectionStats] = Field(default_factory=dict)
    """ The key used is source ip of the entity that tries to connect to this device. """

    # List with all found ips for this entity
    topology_ip: Set[str] = Field(default_factory=set)


class StatusUpdate(BaseModel):
    """
    Represents a respose format used to update the visibility of some entities in the topology map.
    """

    device_id: str
    """ A unique id used to identify the devices. """

    connection_unique_id: str
    """ Representing the key used in the `connection_dict`; a combination of the source_ip and the port source. """

    value: bool
    """ The new visibility status of this connection. """
