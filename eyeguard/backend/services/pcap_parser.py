"""Software-only simulation / demo - no real systems will be contacted or modified."""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Dict, List

from ..logging_config import logger

try:
    from scapy.all import IP, rdpcap  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    rdpcap = None  # type: ignore
    IP = None  # type: ignore


@dataclass
class PcapSummary:
    total_packets: int
    unique_ips: List[str]
    top_ips: List[Dict[str, int]]
    protocol_counts: Dict[str, int]


class PcapParsingError(RuntimeError):
    pass


def parse_pcap(file_path: str) -> PcapSummary:
    if rdpcap is None or IP is None:
        raise PcapParsingError("Scapy is not available in this environment")
    try:
        packets = rdpcap(file_path)
    except Exception as exc:  # pragma: no cover - scapy parsing path
        logger.warning("pcap.parse_failed", error=str(exc))
        raise PcapParsingError("Unable to parse PCAP file") from exc

    total_packets = len(packets)
    ip_counter: Counter[str] = Counter()
    protocol_counter: Counter[str] = Counter()

    for packet in packets:
        if IP in packet:  # type: ignore[operator]
            layer = packet[IP]  # type: ignore[index]
            src = layer.src
            dst = layer.dst
            ip_counter.update([src, dst])
            proto = layer.proto
            protocol_name = _protocol_name(proto)
            protocol_counter.update([protocol_name])
        else:
            protocol_counter.update([packet.__class__.__name__])

    unique_ips = list(ip_counter.keys())
    top_ips = [{"ip": ip, "packet_count": count} for ip, count in ip_counter.most_common(5)]
    protocol_counts = dict(protocol_counter)

    return PcapSummary(
        total_packets=total_packets,
        unique_ips=unique_ips,
        top_ips=top_ips,
        protocol_counts=protocol_counts,
    )


def _protocol_name(proto: int) -> str:
    mapping = {1: "ICMP", 6: "TCP", 17: "UDP"}
    return mapping.get(proto, f"PROTO_{proto}")
