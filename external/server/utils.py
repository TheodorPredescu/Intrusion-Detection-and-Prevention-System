from typing import Dict, List
import models


def topology_extraction(
    connection_map: Dict[str, models.TopologyEntry], packetList: List[models.PacketData], pc_id: str
):

    entity = connection_map.setdefault(pc_id, models.TopologyEntry())

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
