"""Software-only simulation / demo - no real systems will be contacted or modified."""
from __future__ import annotations

import asyncio
import copy
import os
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from collections import Counter, defaultdict
import ipaddress
import math
import statistics

from scapy.all import rdpcap  # Added for PCAP parsing
from scapy.layers.dns import DNS
from scapy.layers.inet import IP, TCP, UDP

from ..config import get_settings
from ..database import SessionLocal
from ..logging_config import logger
from ..models.schemas import (
    Alert,
    PcapAnalysisDetail,
    PcapAnalysisSummary,
    PcapJobStatus,
    Report,
    User,
)
from ..services import alerting, ti_aggregator, report_service
from ..services.pcap_model import adaptive_pcap_model
from ..utils.auth import get_current_user
from ..utils.ip_tools import normalize_ip
from ..utils import blocklist_store
from ..utils.state import state_store

settings = get_settings()
router = APIRouter(prefix="/api/pcap", tags=["pcap"])

ALLOWED_EXTENSIONS = {".pcap", ".pcapng"}
PCAP_MAGIC_NUMBERS = {b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1"}  # PCAP and PCAPNG
PCAP_JOB_RETENTION_SECONDS = 180


SEVERITY_ORDER = {"Info": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}

SERVICE_PORT_MAP = {
    22: "ssh",
    23: "telnet",
    135: "smb",
    139: "smb",
    445: "smb",
    3389: "rdp",
    5900: "vnc",
    5985: "winrm",
    5986: "winrm",
    1900: "ssdp",
}
SUSPICIOUS_SERVICE_NAMES = {"ssh", "rdp", "smb", "telnet", "winrm", "vnc"}
MALWARE_TAGS = {"malware", "ransomware", "botnet", "worm", "backdoor"}
C2_TAGS = {"c2", "command-and-control", "cnc", "beacon", "rat"}
BAD_INFRA_TAGS = {"bulletproof-hosting", "tor", "anonymous", "darknet", "malicious-hosting"}
PORT_SCAN_MIN_PORTS = 10
PORT_SCAN_MIN_ATTEMPTS_PER_5MIN = 100
BEACON_MIN_PACKETS = 12
BEACON_MIN_INTERVALS = 10
EXFIL_THRESHOLD_BYTES = 100 * 1024 * 1024


def _default_ip_stats() -> Dict[str, Any]:
    return {
        "total_packets_out": 0,
        "total_packets_in": 0,
        "total_bytes_out": 0,
        "total_bytes_in": 0,
        "connection_attempts": 0,
        "dst_ports": Counter(),
        "dst_ips": Counter(),
        "protocols": Counter(),
        "service_counts": Counter(),
        "service_windows": {},
        "internal_targets": set(),
        "lateral_targets": set(),
        "external_bytes_out": 0,
        "first_seen": None,
        "last_seen": None,
        "dest_tracking": {},
        "dns_stats": {"total": 0, "unique": set(), "high_entropy": 0, "long_names": 0},
    }


def _update_time_bounds(stats: Dict[str, Any], timestamp: float) -> None:
    if timestamp is None:
        return
    first = stats.get("first_seen")
    last = stats.get("last_seen")
    if first is None or timestamp < first:
        stats["first_seen"] = timestamp
    if last is None or timestamp > last:
        stats["last_seen"] = timestamp



def _update_dest_tracking(stats: Dict[str, Any], destination: str, timestamp: float) -> None:
    tracking = stats.setdefault("dest_tracking", {})
    record = tracking.setdefault(destination, {"packet_count": 0, "interval_count": 0, "mean": 0.0, "m2": 0.0, "last_ts": None})
    record["packet_count"] += 1
    last_ts = record.get("last_ts")
    if last_ts is not None:
        interval = max(0.0, float(timestamp) - float(last_ts))
        if interval > 0:
            count = record["interval_count"] + 1
            delta = interval - record["mean"]
            new_mean = record["mean"] + delta / count
            record["m2"] += delta * (interval - new_mean)
            record["mean"] = new_mean
            record["interval_count"] = count
    record["last_ts"] = timestamp



def _register_service_window(stats: Dict[str, Any], service: str, timestamp: float) -> None:
    windows = stats.setdefault("service_windows", {})
    entry = windows.setdefault(service, {"count": 0, "first": timestamp, "last": timestamp})
    entry["count"] += 1
    if timestamp < entry["first"]:
        entry["first"] = timestamp
    if timestamp > entry["last"]:
        entry["last"] = timestamp



def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    entropy = 0.0
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy



def _serialize_ip_activity(activity: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    serialized: Dict[str, Dict[str, Any]] = {}
    for ip, stats in activity.items():
        service_windows: Dict[str, Dict[str, float]] = {}
        for name, window in stats.get("service_windows", {}).items():
            service_windows[name] = {
                "count": window.get("count", 0),
                "first_seen": window.get("first"),
                "last_seen": window.get("last"),
            }
        dest_activity: Dict[str, Dict[str, float]] = {}
        for dest_ip, record in stats.get("dest_tracking", {}).items():
            interval_count = record.get("interval_count", 0)
            mean_interval = record.get("mean") if interval_count > 0 else None
            stdev = 0.0
            if interval_count > 0:
                variance = record.get("m2", 0.0) / interval_count if interval_count else 0.0
                stdev = math.sqrt(variance) if variance > 0 else 0.0
            dest_activity[dest_ip] = {
                "packet_count": record.get("packet_count", 0),
                "interval_count": interval_count,
                "mean_interval": mean_interval,
                "stdev_interval": stdev if interval_count > 0 else None,
            }
        dns_stats = stats.get("dns_stats", {})
        serialized[ip] = {
            "total_packets_out": stats.get("total_packets_out", 0),
            "total_packets_in": stats.get("total_packets_in", 0),
            "total_bytes_out": stats.get("total_bytes_out", 0),
            "total_bytes_in": stats.get("total_bytes_in", 0),
            "connection_attempts": stats.get("connection_attempts", 0),
            "distinct_dst_ports": len(stats.get("dst_ports", {})),
            "dst_port_counts": dict(stats.get("dst_ports", {})),
            "distinct_dst_ips": len(stats.get("dst_ips", {})),
            "dst_ip_counts": dict(stats.get("dst_ips", {})),
            "protocol_counts": dict(stats.get("protocols", {})),
            "internal_targets": sorted(stats.get("internal_targets", set())),
            "lateral_targets": sorted(stats.get("lateral_targets", set())),
            "external_bytes_out": stats.get("external_bytes_out", 0),
            "service_counts": dict(stats.get("service_counts", {})),
            "service_windows": service_windows,
            "dest_activity": dest_activity,
            "first_seen": stats.get("first_seen"),
            "last_seen": stats.get("last_seen"),
            "dns": {
                "total_queries": dns_stats.get("total", 0),
                "unique_domains": len(dns_stats.get("unique", set())),
                "high_entropy": dns_stats.get("high_entropy", 0),
                "long_domains": dns_stats.get("long_names", 0),
            },
        }
    return serialized


TLS_HANDSHAKE_TYPES = {
    0x01: "client_hello",
    0x02: "server_hello",
}

TLS_SERVER_PORTS = {443, 4443, 8443, 9443, 10443, 4433}
TLS_CIPHER_NAMES = {
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0x1304: "TLS_AES_128_CCM_SHA256",
    0x1305: "TLS_AES_128_CCM_8_SHA256",
    0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
    0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
}


def _format_tls_version(raw: object) -> Optional[str]:
    if raw is None:
        return None
    try:
        if isinstance(raw, bytes):
            if len(raw) < 2:
                return None
            major, minor = raw[0], raw[1]
        elif isinstance(raw, (tuple, list)):
            if len(raw) < 2:
                return None
            major, minor = int(raw[0]), int(raw[1])
        else:
            return None
    except Exception:
        return None
    mapping = {
        (3, 0): "SSL 3.0",
        (3, 1): "TLS 1.0",
        (3, 2): "TLS 1.1",
        (3, 3): "TLS 1.2",
        (3, 4): "TLS 1.3",
    }
    return mapping.get((major, minor), f"TLS {major}.{minor}")


def _format_cipher_suite(value: object) -> str:
    try:
        if isinstance(value, bytes):
            if len(value) < 2:
                return "0x0000"
            numeric = int.from_bytes(value[:2], "big")
        else:
            numeric = int(value)
    except Exception:
        return "0x0000"
    return TLS_CIPHER_NAMES.get(numeric, f"0x{numeric:04X}")


def _parse_tls_client_hello(body: bytes) -> Dict[str, Any]:
    info: Dict[str, Any] = {}
    try:
        if len(body) < 38:
            return info
        version = _format_tls_version(body[:2])
        if version:
            info["client_version"] = version
        idx = 34  # version (2) + random (32)
        if idx >= len(body):
            return info
        session_len = body[idx]
        idx += 1 + session_len
        if idx + 2 > len(body):
            return info
        cipher_len = int.from_bytes(body[idx:idx + 2], "big")
        idx += 2
        cipher_bytes = body[idx: idx + cipher_len]
        cipher_suites: List[str] = []
        for pos in range(0, min(len(cipher_bytes), 40), 2):
            chunk = cipher_bytes[pos:pos + 2]
            if len(chunk) < 2:
                break
            cipher_suites.append(_format_cipher_suite(chunk))
        if cipher_suites:
            info["cipher_suites"] = cipher_suites
        idx += cipher_len
        if idx >= len(body):
            return info
        comp_len = body[idx]
        idx += 1 + comp_len
        if idx + 2 > len(body):
            return info
        ext_len = int.from_bytes(body[idx:idx + 2], "big")
        idx += 2
        ext_end = min(len(body), idx + ext_len)
        sni_names: List[str] = []
        alpn_protocols: List[str] = []
        supported_versions: List[str] = []
        while idx + 4 <= ext_end:
            ext_type = int.from_bytes(body[idx:idx + 2], "big")
            ext_data_len = int.from_bytes(body[idx + 2:idx + 4], "big")
            idx += 4
            ext_data = body[idx:idx + ext_data_len]
            if ext_type == 0:  # server_name
                if len(ext_data) >= 5:
                    list_len = int.from_bytes(ext_data[0:2], "big")
                    pos = 2
                    while pos + 3 <= min(len(ext_data), list_len + 2):
                        name_type = ext_data[pos]
                        name_len = int.from_bytes(ext_data[pos + 1:pos + 3], "big")
                        pos += 3
                        name_bytes = ext_data[pos:pos + name_len]
                        pos += name_len
                        if name_bytes:
                            try:
                                sni_names.append(name_bytes.decode("utf-8", errors="ignore"))
                            except Exception:
                                sni_names.append(name_bytes.decode("latin-1", errors="ignore"))
            elif ext_type == 16:  # ALPN
                if len(ext_data) >= 2:
                    total_len = int.from_bytes(ext_data[0:2], "big")
                    pos = 2
                    while pos < min(len(ext_data), total_len + 2):
                        proto_len = ext_data[pos]
                        pos += 1
                        proto_bytes = ext_data[pos:pos + proto_len]
                        pos += proto_len
                        if proto_bytes:
                            alpn_protocols.append(proto_bytes.decode("utf-8", errors="ignore"))
            elif ext_type == 43:  # supported_versions
                if ext_data:
                    length = ext_data[0]
                    pos = 1
                    while pos + 1 < min(len(ext_data), length + 1):
                        ver = _format_tls_version(ext_data[pos:pos + 2])
                        if ver:
                            supported_versions.append(ver)
                        pos += 2
            idx += ext_data_len
        if sni_names:
            info["sni"] = sni_names[0]
            if len(sni_names) > 1:
                info["sni_alt"] = sni_names[1:5]
        if alpn_protocols:
            info["alpn"] = alpn_protocols
        if supported_versions:
            info["supported_versions"] = supported_versions
    except Exception:
        return info
    return info


def _parse_tls_server_hello(body: bytes) -> Dict[str, Any]:
    info: Dict[str, Any] = {}
    try:
        if len(body) < 38:
            return info
        version = _format_tls_version(body[:2])
        if version:
            info["server_version"] = version
        idx = 34  # version (2) + random (32)
        if idx >= len(body):
            return info
        session_len = body[idx]
        idx += 1 + session_len
        if idx + 2 > len(body):
            return info
        info["selected_cipher"] = _format_cipher_suite(body[idx:idx + 2])
        idx += 2
        if idx >= len(body):
            return info
        info["compression"] = body[idx]
        idx += 1
        if idx + 2 > len(body):
            return info
        ext_len = int.from_bytes(body[idx:idx + 2], "big")
        idx += 2
        ext_end = min(len(body), idx + ext_len)
        alpn_protocols: List[str] = []
        while idx + 4 <= ext_end:
            ext_type = int.from_bytes(body[idx:idx + 2], "big")
            ext_data_len = int.from_bytes(body[idx + 2:idx + 4], "big")
            idx += 4
            ext_data = body[idx:idx + ext_data_len]
            if ext_type == 43 and ext_data:
                selected = _format_tls_version(ext_data[:2])
                if selected:
                    info["selected_version"] = selected
            elif ext_type == 16 and ext_data:
                if len(ext_data) >= 2:
                    total_len = int.from_bytes(ext_data[0:2], "big")
                    pos = 2
                    while pos < min(len(ext_data), total_len + 2):
                        proto_len = ext_data[pos]
                        pos += 1
                        proto_bytes = ext_data[pos:pos + proto_len]
                        pos += proto_len
                        if proto_bytes:
                            alpn_protocols.append(proto_bytes.decode("utf-8", errors="ignore"))
            idx += ext_data_len
        if alpn_protocols:
            info["alpn"] = alpn_protocols
    except Exception:
        return info
    return info


def _parse_tls_handshake_records(payload: bytes, limit: int = 4) -> List[Dict[str, Any]]:
    if not payload or len(payload) < 5:
        return []
    records: List[Dict[str, Any]] = []
    offset = 0
    try:
        while offset + 5 <= len(payload) and len(records) < limit:
            content_type = payload[offset]
            if content_type != 0x16:
                break
            version_bytes = payload[offset + 1:offset + 3]
            record_length = int.from_bytes(payload[offset + 3:offset + 5], "big")
            data_start = offset + 5
            data_end = min(len(payload), data_start + record_length)
            handshake_data = payload[data_start:data_end]
            handshake_offset = 0
            while handshake_offset + 4 <= len(handshake_data) and len(records) < limit:
                handshake_type = handshake_data[handshake_offset]
                handshake_length = int.from_bytes(handshake_data[handshake_offset + 1:handshake_offset + 4], "big")
                if handshake_length <= 0:
                    break
                body_start = handshake_offset + 4
                body_end = min(len(handshake_data), body_start + handshake_length)
                if body_end <= body_start:
                    break
                body = handshake_data[body_start:body_end]
                info: Dict[str, Any] = {
                    "record_version": _format_tls_version(version_bytes),
                    "handshake_type": TLS_HANDSHAKE_TYPES.get(handshake_type, f"type_{handshake_type}"),
                }
                if handshake_type == 0x01:
                    info.update(_parse_tls_client_hello(body))
                elif handshake_type == 0x02:
                    info.update(_parse_tls_server_hello(body))
                cleaned = {k: v for k, v in info.items() if v not in (None, [], {}, "")}
                if cleaned:
                    records.append(cleaned)
                handshake_offset = body_end
            offset = data_end
    except Exception:
        return records
    return records


def _float_to_iso(timestamp: Optional[float]) -> Optional[str]:
    if timestamp is None:
        return None
    try:
        return datetime.fromtimestamp(float(timestamp), tz=timezone.utc).isoformat()
    except Exception:
        return None




def normalize_alert_severity(value: Optional[str]) -> str:
    normalized = str(value or "Low").title()
    if normalized not in SEVERITY_ORDER:
        normalized = "Low"
    return normalized



def _register_alert(
    alerts: Dict[str, Dict[str, Any]],
    indicator: str,
    *,
    severity: str,
    message: str,
    stats: Optional[Dict[str, Any]] = None,
    **extras: Any,
) -> Dict[str, Any]:
    normalized = normalize_alert_severity(severity)
    payload_stats = {k: v for k, v in (stats or {}).items() if v is not None}
    existing = alerts.get(indicator)
    if existing:
        current = normalize_alert_severity(existing.get("severity"))
        if SEVERITY_ORDER.get(normalized, 0) > SEVERITY_ORDER.get(current, 0):
            existing["severity"] = normalized
            existing["message"] = message
        merged_stats = dict(existing.get("stats") or {})
        merged_stats.update(payload_stats)
        existing["stats"] = merged_stats
        for key, value in extras.items():
            if isinstance(existing.get(key), list) and isinstance(value, list):
                for item in value:
                    if item not in existing[key]:
                        existing[key].append(item)
            elif value is not None:
                existing[key] = value
        existing.setdefault("status", "open")
        return existing
    entry: Dict[str, Any] = {
        "indicator": indicator,
        "severity": normalized,
        "message": message,
        "stats": payload_stats,
    }
    for key, value in extras.items():
        if value is not None:
            entry[key] = list(value) if isinstance(value, list) else value
    entry.setdefault("status", "open")
    alerts[indicator] = entry
    return entry


def _format_timestamp(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        else:
            value = value.astimezone(timezone.utc)
        return value.isoformat()
    if isinstance(value, str):
        return value
    return str(value)


class PcapParsingError(Exception):
    pass

def validate_pcap_header(file_path: str) -> bool:
    """Validate the PCAP file's magic number to ensure it's a valid PCAP/PCAPNG file."""
    try:
        with open(file_path, "rb") as f:
            magic = f.read(4)
            return magic in PCAP_MAGIC_NUMBERS
    except Exception as e:
        logger.warning("pcap.header_validation_failed", error=str(e))
        return False


def parse_pcap(file_path: str) -> Dict[str, Any]:
    """Parse a PCAP file and return a summary of its contents with per-IP activity metrics."""
    try:
        if not validate_pcap_header(file_path):
            raise PcapParsingError("Invalid PCAP/PCAPNG header: incorrect magic number")

        packets = rdpcap(file_path)
        total_packets = len(packets)
        total_bytes = 0
        unique_ips: set[str] = set()
        source_ips: set[str] = set()
        protocol_counts: Dict[str, int] = {}
        ip_packet_counts: Dict[str, int] = {}
        source_packet_counts: Dict[str, int] = {}
        ip_activity: Dict[str, Dict[str, Any]] = {}
        dns_activity: Dict[str, Dict[str, Any]] = {}
        tls_flows: Dict[Tuple[str, str, int], Dict[str, Any]] = {}

        for pkt in packets:
            if not pkt.haslayer(IP):
                continue

            ip_layer = pkt[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            length = int(len(pkt))
            total_bytes += length
            timestamp = float(getattr(pkt, "time", 0.0))

            unique_ips.add(src_ip)
            unique_ips.add(dst_ip)
            source_ips.add(src_ip)

            proto = ip_layer.proto
            protocol_name = {6: "TCP", 17: "UDP"}.get(proto, f"Protocol_{proto}")
            protocol_counts[protocol_name] = protocol_counts.get(protocol_name, 0) + 1

            ip_packet_counts[src_ip] = ip_packet_counts.get(src_ip, 0) + 1
            ip_packet_counts[dst_ip] = ip_packet_counts.get(dst_ip, 0) + 1
            source_packet_counts[src_ip] = source_packet_counts.get(src_ip, 0) + 1

            src_stats = ip_activity.get(src_ip)
            if src_stats is None:
                src_stats = _default_ip_stats()
                ip_activity[src_ip] = src_stats
            dst_stats = ip_activity.get(dst_ip)
            if dst_stats is None:
                dst_stats = _default_ip_stats()
                ip_activity[dst_ip] = dst_stats

            _update_time_bounds(src_stats, timestamp)
            _update_time_bounds(dst_stats, timestamp)

            src_stats["total_packets_out"] += 1
            src_stats["total_bytes_out"] += length
            src_stats["connection_attempts"] += 1
            src_stats["dst_ips"][dst_ip] += 1
            src_stats["protocols"][protocol_name] += 1

            dst_stats["total_packets_in"] += 1
            dst_stats["total_bytes_in"] += length
            dst_stats["protocols"][protocol_name] += 1

            _update_dest_tracking(src_stats, dst_ip, timestamp)

            try:
                dst_address = ipaddress.ip_address(dst_ip)
                if dst_address.is_private:
                    src_stats["internal_targets"].add(dst_ip)
                else:
                    src_stats["external_bytes_out"] += length
            except ValueError:
                pass

            destination_port: Optional[int] = None
            tcp_layer = None
            if pkt.haslayer(TCP):
                tcp_layer = pkt[TCP]
                destination_port = int(tcp_layer.dport)
            elif pkt.haslayer(UDP):
                destination_port = int(pkt[UDP].dport)

            dns_layer = pkt[DNS] if pkt.haslayer(DNS) else None
            if destination_port is not None:
                src_stats["dst_ports"][destination_port] += 1
                service_name = SERVICE_PORT_MAP.get(destination_port)
                if service_name:
                    src_stats["service_counts"][service_name] += 1
                    _register_service_window(src_stats, service_name, timestamp)
                    if service_name in {"smb", "rdp"}:
                        try:
                            if ipaddress.ip_address(dst_ip).is_private:
                                src_stats["lateral_targets"].add(dst_ip)
                        except ValueError:
                            pass
                if dns_layer is not None:
                    dns_stats = src_stats["dns_stats"]
                    dns_stats["total"] += 1
                    query_name = None
                    if getattr(dns_layer, "qd", None):
                        query_name = dns_layer.qd.qname
                    if query_name:
                        if isinstance(query_name, bytes):
                            domain = query_name.decode(errors="ignore").rstrip('.')
                        else:
                            domain = str(query_name).rstrip('.')
                        domain = domain.lower()
                        dns_stats["unique"].add(domain)
                        long_name = len(domain) >= 20
                        if long_name:
                            dns_stats["long_names"] += 1
                        entropy_source = ''.join(ch for ch in domain if ch.isalnum())
                        entropy_value = _shannon_entropy(entropy_source)
                        high_entropy = entropy_value >= 3.5
                        if high_entropy:
                            dns_stats["high_entropy"] += 1
                        entry = dns_activity.setdefault(
                            domain,
                            {
                                "count": 0,
                                "sources": set(),
                                "high_entropy": False,
                                "long_name": False,
                                "first_seen": timestamp,
                                "last_seen": timestamp,
                            },
                        )
                        entry["count"] += 1
                        entry["sources"].add(src_ip)
                        if high_entropy:
                            entry["high_entropy"] = True
                        if long_name:
                            entry["long_name"] = True
                        entry["first_seen"] = min(entry["first_seen"], timestamp)
                        entry["last_seen"] = max(entry["last_seen"], timestamp)
                elif dns_layer is not None:
                    dns_stats = src_stats["dns_stats"]
                    dns_stats["total"] += 1
            elif dns_layer is not None:
                dns_stats = src_stats["dns_stats"]
                dns_stats["total"] += 1

            tls_records: List[Dict[str, Any]] = []
            if tcp_layer is not None:
                raw_payload = bytes(tcp_layer.payload or b"")
                if raw_payload:
                    tls_records = _parse_tls_handshake_records(raw_payload)
            if tls_records:
                server_port = destination_port
                client_ip = src_ip
                server_ip = dst_ip
                if tcp_layer is not None and int(tcp_layer.sport) in TLS_SERVER_PORTS:
                    server_port = int(tcp_layer.sport)
                    server_ip = src_ip
                    client_ip = dst_ip
                elif destination_port in TLS_SERVER_PORTS:
                    server_port = int(destination_port)
                    server_ip = dst_ip
                    client_ip = src_ip
                elif server_port is None and tcp_layer is not None:
                    server_port = int(tcp_layer.sport)
                    server_ip = src_ip
                    client_ip = dst_ip
                server_port = int(server_port or 0)
                flow_key = (client_ip, server_ip, server_port)
                flow = tls_flows.setdefault(
                    flow_key,
                    {
                        "client_ip": client_ip,
                        "server_ip": server_ip,
                        "server_port": server_port,
                        "packet_count": 0,
                        "byte_count": 0,
                        "first_seen": timestamp,
                        "last_seen": timestamp,
                        "record_versions": set(),
                        "handshake_types": set(),
                        "supported_versions": set(),
                        "client_cipher_suites": set(),
                        "alpn": set(),
                    },
                )
                flow["packet_count"] += 1
                flow["byte_count"] += length
                flow["last_seen"] = timestamp
                for record in tls_records:
                    record_version = record.get("record_version")
                    if record_version:
                        flow["record_versions"].add(record_version)
                    handshake_type = record.get("handshake_type")
                    if handshake_type:
                        flow["handshake_types"].add(handshake_type)
                    if handshake_type == "client_hello":
                        if record.get("sni") and not flow.get("sni"):
                            flow["sni"] = record["sni"]
                        if record.get("sni_alt"):
                            alt = flow.setdefault("sni_alt", [])
                            for name in record["sni_alt"][:5]:
                                if name not in alt:
                                    alt.append(name)
                        for ver in record.get("supported_versions", []):
                            if ver:
                                flow["supported_versions"].add(ver)
                        for cipher in record.get("cipher_suites", []):
                            flow["client_cipher_suites"].add(cipher)
                        for proto in record.get("alpn", []):
                            flow["alpn"].add(proto)
                        flow["client_hello"] = record
                    elif handshake_type == "server_hello":
                        if record.get("selected_cipher"):
                            flow["selected_cipher"] = record["selected_cipher"]
                        if record.get("selected_version"):
                            flow["selected_version"] = record["selected_version"]
                        for proto in record.get("alpn", []):
                            flow["alpn"].add(proto)
                        flow["server_hello"] = record

        top_ips = [
            {"ip": ip, "packet_count": count}
            for ip, count in sorted(ip_packet_counts.items(), key=lambda item: item[1], reverse=True)[:10]
        ]
        top_source_ips = [
            {"ip": ip, "packet_count": count}
            for ip, count in sorted(source_packet_counts.items(), key=lambda item: item[1], reverse=True)[:10]
        ]

        analysis_start = None
        analysis_end = None
        for stats in ip_activity.values():
            first = stats.get("first_seen")
            last = stats.get("last_seen")
            if first is not None:
                analysis_start = first if analysis_start is None else min(analysis_start, first)
            if last is not None:
                analysis_end = last if analysis_end is None else max(analysis_end, last)
        analysis_window_seconds = 0.0
        if analysis_start is not None and analysis_end is not None:
            analysis_window_seconds = max(0.0, float(analysis_end) - float(analysis_start))

        serialized_activity = _serialize_ip_activity(ip_activity)

        dns_summary: List[Dict[str, Any]] = []
        for domain, payload in dns_activity.items():
            dns_summary.append(
                {
                    "domain": domain,
                    "count": payload["count"],
                    "sources": sorted(payload["sources"]),
                    "high_entropy": payload["high_entropy"],
                    "long_name": payload["long_name"],
                    "first_seen": payload["first_seen"],
                    "first_seen_iso": _float_to_iso(payload["first_seen"]),
                    "last_seen": payload["last_seen"],
                    "last_seen_iso": _float_to_iso(payload["last_seen"]),
                }
            )
        dns_summary.sort(key=lambda item: item["count"], reverse=True)

        tls_summary: List[Dict[str, Any]] = []
        for (_client_ip, _server_ip, _server_port), flow in tls_flows.items():
            entry = {
                "client_ip": flow["client_ip"],
                "server_ip": flow["server_ip"],
                "server_port": flow["server_port"],
                "packet_count": flow["packet_count"],
                "byte_count": flow["byte_count"],
                "first_seen": flow["first_seen"],
                "first_seen_iso": _float_to_iso(flow["first_seen"]),
                "last_seen": flow["last_seen"],
                "last_seen_iso": _float_to_iso(flow["last_seen"]),
                "record_versions": sorted(flow.get("record_versions", [])),
                "handshake_types": sorted(flow.get("handshake_types", [])),
            }
            if flow.get("sni"):
                entry["sni"] = flow["sni"]
            if flow.get("sni_alt"):
                entry["sni_alt"] = flow["sni_alt"]
            if flow.get("supported_versions"):
                entry["supported_versions"] = sorted(flow["supported_versions"])
            if flow.get("client_cipher_suites"):
                entry["client_cipher_suites"] = sorted(flow["client_cipher_suites"])[:10]
            if flow.get("selected_cipher"):
                entry["selected_cipher"] = flow["selected_cipher"]
            if flow.get("selected_version"):
                entry["selected_version"] = flow["selected_version"]
            if flow.get("alpn"):
                entry["alpn"] = sorted(flow["alpn"])
            if flow.get("client_hello"):
                entry["client_hello"] = flow["client_hello"]
            if flow.get("server_hello"):
                entry["server_hello"] = flow["server_hello"]
            tls_summary.append(entry)
        tls_summary.sort(key=lambda item: item["byte_count"], reverse=True)

        return {
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "unique_ips": sorted(unique_ips),
            "source_ips": sorted(source_ips),
            "top_ips": top_ips,
            "top_source_ips": top_source_ips,
            "protocol_counts": protocol_counts,
            "ip_activity": serialized_activity,
            "dns_activity": dns_summary,
            "tls_flows": tls_summary,
            "analysis_start": analysis_start,
            "analysis_end": analysis_end,
            "analysis_start_iso": _float_to_iso(analysis_start) if analysis_start is not None else None,
            "analysis_end_iso": _float_to_iso(analysis_end) if analysis_end is not None else None,
            "analysis_window_seconds": analysis_window_seconds,
        }
    except Exception as e:
        raise PcapParsingError(f"Failed to parse PCAP file: {str(e)}")


def _ensure_upload_dir(user_id: str) -> str:
    uploads_root = os.path.abspath(settings.uploads_path)
    user_dir = os.path.join(uploads_root, user_id)
    os.makedirs(user_dir, exist_ok=True)
    return user_dir

async def _update_pcap_job(job_id: str, **updates) -> None:
    sanitized = updates.copy()
    if "progress" in sanitized:
        try:
            sanitized["progress"] = max(0, min(100, int(sanitized["progress"])))
        except (TypeError, ValueError):
            sanitized.pop("progress", None)
    async with state_store._lock:  # type: ignore[attr-defined]
        state_store.update_pcap_job(job_id, sanitized)


async def _schedule_job_cleanup(job_id: str, delay: int = PCAP_JOB_RETENTION_SECONDS) -> None:
    try:
        await asyncio.sleep(delay)
    except asyncio.CancelledError:  # pragma: no cover - cooperative cancellation
        return
    async with state_store._lock:  # type: ignore[attr-defined]
        removed = state_store.remove_pcap_job(job_id)
    if removed:
        logger.debug("pcap.job.cleaned", job_id=job_id, retention_seconds=delay)


def _severity_value(level: str) -> int:
    return SEVERITY_ORDER.get(str(level or "").title(), 0)


def _reduce_severity(level: str) -> str:
    order = ["Info", "Low", "Medium", "High", "Critical"]
    current = _severity_value(level)
    if current <= 0:
        return "Info"
    target_index = max(0, current - 1)
    return order[target_index]


def _cap_severity(level: str, cap: str) -> str:
    if _severity_value(level) > _severity_value(cap):
        return cap
    return level


def _calculate_attempt_rate(count: int, first: float | None, last: float | None, default_window: float = 300.0) -> float:
    if count <= 0:
        return 0.0
    if first is None or last is None or last <= first:
        window = default_window
    else:
        window = max(default_window, float(last) - float(first))
    if window <= 0:
        return 0.0
    return count / (window / 60.0)


def _detect_beacon_candidates(dest_activity: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    candidates: List[Dict[str, Any]] = []
    for target, metrics in (dest_activity or {}).items():
        packet_count = metrics.get("packet_count", 0)
        interval_count = metrics.get("interval_count", 0)
        mean_interval = metrics.get("mean_interval")
        stdev_interval = metrics.get("stdev_interval")
        if packet_count >= BEACON_MIN_PACKETS and interval_count >= BEACON_MIN_INTERVALS and mean_interval:
            jitter = stdev_interval or 0.0
            if jitter <= max(1.0, 0.2 * float(mean_interval)):
                candidates.append({
                    "target": target,
                    "mean_interval": mean_interval,
                    "stdev_interval": jitter,
                    "packet_count": packet_count,
                })
    return candidates


def _determine_attack_type(
    rationale: List[str],
    *,
    severity: str,
    strong_anchor: bool,
    has_exfil: bool,
    has_lateral: bool,
    has_bruteforce: bool,
    has_beacon: bool,
    has_port_scan: bool,
    has_malware: bool,
    has_dns_anomaly: bool,
) -> Tuple[str, float]:
    base_type = "generic_suspicious"
    if has_exfil:
        base_type = "data_exfiltration"
    elif has_lateral:
        base_type = "smb_exploit/lateral_move"
    elif has_bruteforce and "rdp_bruteforce" in rationale:
        base_type = "rdp_bruteforce"
    elif has_bruteforce and "ssh_bruteforce" in rationale:
        base_type = "ssh_bruteforce"
    elif has_beacon:
        base_type = "beaconing_c2"
    elif has_malware:
        base_type = "malware_signature"
    elif has_dns_anomaly:
        base_type = "dga_dns/tunneling"
    elif has_port_scan:
        base_type = "port_scan"

    severity_value = _severity_value(severity)
    confidence = 0.35 + 0.05 * severity_value + 0.03 * len(rationale)
    if strong_anchor:
        confidence += 0.15
    confidence = max(0.1, min(0.99, confidence))

    attack_type = base_type
    if confidence < 0.7:
        attack_type = f"suspected_{base_type}"

    return attack_type, round(confidence, 2)


def _build_classification_message(indicator: str, classification: Dict[str, Any], ti_stats: Dict[str, int]) -> str:
    summary_bits: List[str] = [f"score {classification.get('score', 0)}"]
    rationale = classification.get("severity_rationale") or []
    if rationale:
        summary_bits.append("signals: " + ", ".join(rationale))
    vt_hits = ti_stats.get("vt_malicious")
    if vt_hits:
        summary_bits.append(f"VT={vt_hits}")
    abuse = ti_stats.get("abuse_score")
    if abuse:
        summary_bits.append(f"Abuse={abuse}")
    shodan = ti_stats.get("shodan_risk")
    if shodan:
        summary_bits.append(f"ShodanRisk={shodan}")
    attack_label = classification.get("attack_type", "generic_suspicious").replace("_", " ")
    return f"{attack_label} activity for {indicator}: " + "; ".join(summary_bits)


def _compute_indicator_classification(
    indicator: str,
    *,
    ti_results: Dict[str, Any],
    ti_stats: Dict[str, int],
    aggregated_summary: Dict[str, Any],
    metrics: Dict[str, Any],
    packet_count: int,
    analysis_window_seconds: float,
) -> Dict[str, Any]:
    score = 0
    rationale: List[str] = []
    categories: set[str] = set()
    signals_detail: Dict[str, Any] = {}
    strong_anchor = False

    def add_signal(name: str, condition: bool, points: int, category: str, *, anchor: bool = False, detail: Any = None) -> None:
        nonlocal score, strong_anchor
        if not condition:
            return
        score += points
        rationale.append(name)
        categories.add(category)
        if detail is not None:
            signals_detail[name] = detail
        else:
            signals_detail[name] = True
        if anchor:
            strong_anchor = True

    metrics = metrics or {}
    ti_results = ti_results or {}
    aggregated_summary = aggregated_summary or {}

    vt_data = (ti_results.get("virustotal") or {}).get("data", {})
    otx_data = (ti_results.get("otx") or {}).get("data", {})
    abuse_data = (ti_results.get("abuseipdb") or {}).get("data", {})
    shodan_data = (ti_results.get("shodan") or {}).get("data", {})

    vt_malicious = int(vt_data.get("malicious_count", 0))
    otx_pulses = int(otx_data.get("pulse_count", 0))
    abuse_score = int(abuse_data.get("abuse_score", 0))
    shodan_risk = int(shodan_data.get("risk", 0))
    shodan_tags = [str(tag).lower() for tag in shodan_data.get("tags", []) or []]
    shodan_ports = len(shodan_data.get("exposed_ports", []) or [])

    malicious_sources = aggregated_summary.get("malicious_sources", []) or []
    ti_positive = bool(aggregated_summary.get("is_malicious")) or vt_malicious >= 1 or otx_pulses >= 1 or abuse_score >= 80 or shodan_risk >= 70

    add_signal(
        "ti_match",
        ti_positive,
        10,
        "threat_intel",
        anchor=True,
        detail={
            "malicious_sources": malicious_sources,
            "vt_malicious": vt_malicious,
            "abuse_score": abuse_score,
            "shodan_risk": shodan_risk,
        },
    )

    has_malware = vt_malicious >= 5 or any(tag in MALWARE_TAGS for tag in shodan_tags) or shodan_ports >= 6
    add_signal(
        "malware_signature",
        has_malware,
        8,
        "malware",
        anchor=True,
        detail={"vt_malicious": vt_malicious, "shodan_ports": shodan_ports, "tags": shodan_tags[:5]},
    )

    known_bad_infra = any(tag in BAD_INFRA_TAGS for tag in shodan_tags)
    add_signal(
        "known_bad_asn",
        known_bad_infra,
        4,
        "infrastructure",
        detail={"tags": shodan_tags[:5]},
    )

    has_c2_tag = any(tag in C2_TAGS for tag in shodan_tags)
    add_signal(
        "c2_pattern",
        has_c2_tag,
        4,
        "c2",
        anchor=True,
        detail={"tags": shodan_tags[:5]},
    )

    total_packets_out = int(metrics.get("total_packets_out", 0))
    distinct_ports = int(metrics.get("distinct_dst_ports", 0))
    distinct_dests = int(metrics.get("distinct_dst_ips", 0))
    connection_attempts = int(metrics.get("connection_attempts", total_packets_out))
    service_counts = metrics.get("service_counts", {}) or {}
    service_windows = metrics.get("service_windows", {}) or {}
    dest_activity = metrics.get("dest_activity", {}) or {}
    external_bytes_out = int(metrics.get("external_bytes_out", 0))
    lateral_targets = metrics.get("lateral_targets", []) or []
    dns_stats = metrics.get("dns", {}) or {}

    first_seen = metrics.get("first_seen")
    last_seen = metrics.get("last_seen")
    duration_seconds = 0.0
    if first_seen is not None and last_seen is not None and last_seen >= first_seen:
        duration_seconds = max(0.0, float(last_seen) - float(first_seen))
    else:
        duration_seconds = analysis_window_seconds or 0.0

    window_seconds = max(analysis_window_seconds or 0.0, duration_seconds, 300.0)
    attempts_per_5min = (connection_attempts / window_seconds) * 300 if window_seconds else 0.0

    add_signal(
        "port_scan",
        distinct_ports >= PORT_SCAN_MIN_PORTS or attempts_per_5min >= PORT_SCAN_MIN_ATTEMPTS_PER_5MIN,
        5,
        "scanning",
        detail={"distinct_ports": distinct_ports, "attempts_per_5min": round(attempts_per_5min, 2)},
    )

    add_signal(
        "volume",
        total_packets_out > 5000 or distinct_dests > 20,
        2,
        "volume",
        detail={"total_packets_out": total_packets_out, "distinct_dests": distinct_dests},
    )

    beacon_candidates = _detect_beacon_candidates(dest_activity)
    has_beacon = bool(beacon_candidates)
    add_signal(
        "beaconing",
        has_beacon,
        3,
        "beacon",
        detail=beacon_candidates[:3],
    )

    ssh_count = int(service_counts.get("ssh", 0))
    ssh_window = service_windows.get("ssh") or {}
    ssh_rate = _calculate_attempt_rate(ssh_count, ssh_window.get("first_seen"), ssh_window.get("last_seen"))
    add_signal(
        "ssh_bruteforce",
        ssh_count >= 50 and ssh_rate >= 50,
        3,
        "bruteforce",
        detail={"attempts": ssh_count, "per_min": round(ssh_rate, 2)},
    )

    rdp_count = int(service_counts.get("rdp", 0))
    rdp_window = service_windows.get("rdp") or {}
    rdp_rate = _calculate_attempt_rate(rdp_count, rdp_window.get("first_seen"), rdp_window.get("last_seen"))
    add_signal(
        "rdp_bruteforce",
        rdp_count >= 50 and rdp_rate >= 50,
        3,
        "bruteforce",
        detail={"attempts": rdp_count, "per_min": round(rdp_rate, 2)},
    )

    smb_telnet = int(service_counts.get("smb", 0)) + int(service_counts.get("telnet", 0))
    add_signal(
        "smb_telnet",
        smb_telnet > 0,
        2,
        "exposure",
        detail={"count": smb_telnet},
    )

    has_lateral = len(lateral_targets) >= 5
    add_signal(
        "lateral_movement",
        has_lateral,
        4,
        "lateral",
        anchor=True,
        detail={"targets": lateral_targets[:5]},
    )

    has_exfil = external_bytes_out >= EXFIL_THRESHOLD_BYTES
    add_signal(
        "data_exfil",
        has_exfil,
        4,
        "exfil",
        anchor=True,
        detail={"bytes": external_bytes_out},
    )

    dns_queries = int(dns_stats.get("total_queries", 0))
    dns_unique = int(dns_stats.get("unique_domains", 0))
    dns_high_entropy = int(dns_stats.get("high_entropy", 0))
    has_dns_anomaly = dns_queries >= 20 and (dns_high_entropy >= 10 or dns_unique >= 15)
    add_signal(
        "dns_anomaly",
        has_dns_anomaly,
        2,
        "dns",
        detail={"queries": dns_queries, "unique": dns_unique, "high_entropy": dns_high_entropy},
    )

    if smb_telnet and score <= 1:
        add_signal(
            "suspicious_service_touch",
            True,
            1,
            "service",
            detail={"services": {k: v for k, v in service_counts.items() if k in SUSPICIOUS_SERVICE_NAMES}},
        )

    severity = "Info"
    if score >= 9:
        severity = "Critical"
    elif score >= 6:
        severity = "High"
    elif score >= 3:
        severity = "Medium"
    elif score >= 1:
        severity = "Low"

    categories_count = len(categories)
    if severity == "Critical" and not (score >= 9 and strong_anchor and categories_count >= 2):
        severity = "High"

    if "port_scan" in rationale and categories.issubset({"scanning", "volume"}):
        severity = _cap_severity(severity, "High")

    if set(rationale).issubset({"suspicious_service_touch"}):
        severity = "Low" if score >= 1 else "Info"

    if "beaconing" in rationale and not ({"threat_intel", "malware", "c2", "lateral", "exfil"} & categories):
        severity = _cap_severity(severity, "High")

    if duration_seconds and duration_seconds < 300 and severity in {"High", "Critical"}:
        severity = _reduce_severity(severity)

    attack_type, type_confidence = _determine_attack_type(
        rationale,
        severity=severity,
        strong_anchor=strong_anchor,
        has_exfil=has_exfil,
        has_lateral=has_lateral,
        has_bruteforce=("ssh_bruteforce" in rationale or "rdp_bruteforce" in rationale),
        has_beacon=has_beacon,
        has_port_scan=("port_scan" in rationale),
        has_malware=has_malware,
        has_dns_anomaly=has_dns_anomaly,
    )

    classification = {
        "indicator": indicator,
        "score": score,
        "severity": severity,
        "severity_rationale": rationale,
        "signals": signals_detail,
        "categories": sorted(categories),
        "strong_anchor": strong_anchor,
        "attack_type": attack_type,
        "type_confidence": type_confidence,
        "duration_seconds": duration_seconds,
        "attempts_per_5min": round(attempts_per_5min, 2),
    }

    return classification




async def _process_pcap_job(job_id: str, current_user: User, output_path: str, safe_name: str) -> None:
    summary: Dict[str, Any] = {}
    ip_payloads: List[Dict[str, Any]] = []
    alerts_by_ip: Dict[str, Dict[str, Any]] = {}
    analysis_errors: List[str] = []
    block_candidates: set[str] = set()
    blocked_auto_list: List[str] = []
    beacon_entries: List[Dict[str, Any]] = []
    beacon_seen: set[Tuple[str, str]] = set()
    bruteforce_entries: List[Dict[str, Any]] = []
    bruteforce_seen: set[Tuple[str, str]] = set()
    portscan_entries: List[Dict[str, Any]] = []
    exfil_entries: List[Dict[str, Any]] = []
    dns_anomaly_entries: List[Dict[str, Any]] = []
    threat_matches: List[Dict[str, Any]] = []
    threat_seen: set[str] = set()
    try:
        await _update_pcap_job(job_id, status="processing", stage="validation", message="Validating packet capture", progress=15)
        summary = parse_pcap(output_path)
    except PcapParsingError as exc:
        logger.warning("pcap.parse_failed", error=str(exc))
        await _update_pcap_job(job_id, status="failed", stage="validation", message=f"Invalid PCAP file: {exc}", progress=100)
        try:
            os.remove(output_path)
        except Exception:
            logger.warning("pcap.cleanup_failed", path=output_path)
        asyncio.create_task(_schedule_job_cleanup(job_id))
        return
    except Exception as exc:
        logger.exception("pcap.unexpected_parse_error", error=str(exc))
        await _update_pcap_job(job_id, status="failed", stage="validation", message="Failed to parse PCAP file.", progress=100)
        try:
            os.remove(output_path)
        except Exception:
            logger.warning("pcap.cleanup_failed", path=output_path)
        asyncio.create_task(_schedule_job_cleanup(job_id))
        return

    ip_activity = summary.get("ip_activity", {}) or {}
    beacon_candidates_from_activity: List[Dict[str, Any]] = []
    beacon_activity_seen: set[Tuple[str, str]] = set()
    for source_ip, stats in ip_activity.items():
        dest_activity = stats.get("dest_activity", {}) or {}
        for candidate in _detect_beacon_candidates(dest_activity):
            target = candidate.get("target")
            if not target:
                continue
            key = (source_ip, target)
            if key in beacon_activity_seen:
                continue
            beacon_activity_seen.add(key)
            entry = dict(candidate)
            entry["source_ip"] = source_ip
            beacon_candidates_from_activity.append(entry)
    analysis_window_seconds = float(summary.get("analysis_window_seconds", 0.0) or 0.0)

    unique_ips = summary.get("unique_ips", []) or []
    source_ips = summary.get("source_ips", []) or []
    top_ip_entries = summary.get("top_source_ips") or []
    if not isinstance(top_ip_entries, list):
        top_ip_entries = []
    if not top_ip_entries and source_ips:
        tentative_limit = max(settings.pcap_enrichment_ip_limit, 0) or 10
        top_ip_entries = [{"ip": ip, "packet_count": 0} for ip in source_ips[:tentative_limit]]
    if not top_ip_entries and unique_ips:
        tentative_limit = max(settings.pcap_enrichment_ip_limit, 0) or 10
        top_ip_entries = [{"ip": ip, "packet_count": 0} for ip in unique_ips[:tentative_limit]]

    source_ip_set: set[str] = set()
    for ip in source_ips:
        try:
            source_ip_set.add(normalize_ip(ip))
        except Exception:
            source_ip_set.add(str(ip))

    total_ips = len(source_ip_set) if source_ip_set else len(unique_ips)
    await _update_pcap_job(
        job_id,
        stage="enrichment",
        message="Running threat intelligence enrichment",
        progress=30,
        total_ips=total_ips,
    )

    detected_malicious_ips: set[str] = set()
    enrichment_limit = max(settings.pcap_enrichment_ip_limit, 0)
    total_to_enrich = len(top_ip_entries) if enrichment_limit == 0 else min(len(top_ip_entries), enrichment_limit)
    enriched_count = 0

    for index, entry in enumerate(top_ip_entries):
        ip = entry.get("ip")
        if not ip:
            continue
        packet_count = entry.get("packet_count", 0)
        try:
            normalized = normalize_ip(ip)
        except Exception:
            normalized = str(ip)
        payload = {
            "ip": normalized,
            "packet_count": packet_count,
            "source_results": {},
            "aggregated_summary": {
                "is_malicious": False,
                "malicious_sources": [],
                "summary_text": "Threat intelligence lookup not performed.",
            },
            "is_malicious": False,
            "severity": "Info",
        }
        ip_payloads.append(payload)



        should_enrich = enrichment_limit == 0 or index < enrichment_limit
        ti_stats: Dict[str, int] = {}
        malicious_sources: List[str] = []
        if should_enrich:
            try:
                result = await ti_aggregator.lookup_indicator("ip", normalized, user_id=current_user.id)
                verdict = result.aggregated_summary or {}
                payload["source_results"] = result.source_results
                payload["aggregated_summary"] = verdict
                payload["is_malicious"] = verdict.get("is_malicious", False)
                malicious_sources = verdict.get("malicious_sources", []) or []
            except Exception as exc:
                logger.warning("pcap.ti_lookup_failed", ip=normalized, error=str(exc))
                detail = f"Threat intelligence lookup failed for {normalized}: {exc}"
                payload.setdefault("errors", []).append(detail)
                analysis_errors.append(detail)

        severity_label, base_stats = alerting.severity_from_sources(payload.get("source_results") or {})
        ti_stats = dict(base_stats)
        ip_metrics = ip_activity.get(normalized, {})
        classification = _compute_indicator_classification(
            normalized,
            ti_results=payload.get("source_results") or {},
            ti_stats=ti_stats,
            aggregated_summary=payload.get("aggregated_summary") or {},
            metrics=ip_metrics,
            packet_count=packet_count,
            analysis_window_seconds=analysis_window_seconds,
        )

        normalized_severity = normalize_alert_severity(classification.get("severity"))
        payload["severity"] = normalized_severity
        payload["score"] = classification.get("score", 0)
        payload["severity_rationale"] = classification.get("severity_rationale", [])
        payload["attack_type"] = classification.get("attack_type")
        payload["type_confidence"] = classification.get("type_confidence")
        payload["classification_signals"] = classification.get("signals")
        payload["classification_categories"] = classification.get("categories")
        payload["classification"] = classification
        payload["duration_seconds"] = classification.get("duration_seconds")
        payload["attempts_per_5min"] = classification.get("attempts_per_5min")

        severity_stats = dict(ti_stats)
        severity_stats.update(
            {
                "score": classification.get("score", 0),
                "severity_rationale": classification.get("severity_rationale", []),
                "signals": classification.get("signals"),
                "attack_type": classification.get("attack_type"),
                "type_confidence": classification.get("type_confidence"),
                "attempts_per_5min": classification.get("attempts_per_5min"),
            }
        )
        if ip_metrics:
            payload["metrics"] = copy.deepcopy(ip_metrics)
            payload["first_seen"] = _float_to_iso(ip_metrics.get("first_seen"))
            payload["last_seen"] = _float_to_iso(ip_metrics.get("last_seen"))
            dest_activity = ip_metrics.get("dest_activity") or {}
            top_destinations = sorted(
                dest_activity.items(),
                key=lambda item: item[1].get("packet_count", 0),
                reverse=True,
            )[:5]
            if top_destinations:
                payload["top_destinations"] = [
                    {"ip": dest, **dict(dest_stats)}
                    for dest, dest_stats in top_destinations
                ]
            payload["dns_summary"] = ip_metrics.get("dns", {})

        payload["severity_stats"] = severity_stats

        is_source_candidate = not source_ip_set or normalized in source_ip_set
        if SEVERITY_ORDER.get(normalized_severity, 0) >= SEVERITY_ORDER["High"] and is_source_candidate:
            block_candidates.add(normalized)

        payload["is_malicious"] = payload.get("is_malicious") or _severity_value(normalized_severity) >= SEVERITY_ORDER["Medium"]
        message = _build_classification_message(normalized, classification, ti_stats)
        indicator_sources = malicious_sources or classification.get("severity_rationale", [])
        if payload["is_malicious"]:
            detected_malicious_ips.add(normalized)
            entry_payload = _register_alert(
                alerts_by_ip,
                normalized,
                severity=normalized_severity,
                message=message,
                stats=severity_stats,
                status="open",
                intel_sources=list(indicator_sources),
                aggregated_summary=payload.get("aggregated_summary"),
                source_results=payload.get("source_results"),
                packet_count=packet_count,
                score=classification.get("score"),
                severity_rationale=classification.get("severity_rationale"),
                attack_type=classification.get("attack_type"),
                type_confidence=classification.get("type_confidence"),
                source_candidate=is_source_candidate,
            )
            entry_payload.setdefault("classification", classification)
            entry_payload["source_candidate"] = is_source_candidate
            if indicator_sources:
                existing_sources = entry_payload.setdefault("intel_sources", [])
                for source in indicator_sources:
                    if source not in existing_sources:
                        existing_sources.append(source)
        else:
            payload.setdefault("intel_sources", list(indicator_sources))
        payload.setdefault("intel_sources", list(indicator_sources))
        signals_detail = classification.get("signals") or {}
        rationale = classification.get("severity_rationale") or []
        beacon_signal = signals_detail.get("beaconing")
        if isinstance(beacon_signal, list):
            for candidate in beacon_signal:
                if not isinstance(candidate, dict):
                    continue
                target_ip = candidate.get("target")
                key = (normalized, target_ip)
                if target_ip and key not in beacon_seen:
                    beacon_seen.add(key)
                    beacon_entries.append(
                        {
                            "source_ip": normalized,
                            "target": target_ip,
                            "mean_interval": candidate.get("mean_interval"),
                            "stdev_interval": candidate.get("stdev_interval"),
                            "packet_count": candidate.get("packet_count"),
                        }
                    )
        if "ssh_bruteforce" in rationale:
            detail = signals_detail.get("ssh_bruteforce") or {}
            if isinstance(detail, dict):
                key = (normalized, "ssh")
                if key not in bruteforce_seen:
                    bruteforce_seen.add(key)
                    bruteforce_entries.append(
                        {
                            "ip": normalized,
                            "service": "ssh",
                            "attempts": detail.get("attempts"),
                            "per_min": detail.get("per_min"),
                        }
                    )
        if "rdp_bruteforce" in rationale:
            detail = signals_detail.get("rdp_bruteforce") or {}
            if isinstance(detail, dict):
                key = (normalized, "rdp")
                if key not in bruteforce_seen:
                    bruteforce_seen.add(key)
                    bruteforce_entries.append(
                        {
                            "ip": normalized,
                            "service": "rdp",
                            "attempts": detail.get("attempts"),
                            "per_min": detail.get("per_min"),
                        }
                    )
        if "port_scan" in rationale:
            detail = signals_detail.get("port_scan") or {}
            if isinstance(detail, dict):
                portscan_entries.append(
                    {
                        "ip": normalized,
                        "distinct_ports": detail.get("distinct_ports"),
                        "attempts_per_5min": detail.get("attempts_per_5min"),
                    }
                )
        data_exfil_detail = signals_detail.get("data_exfil") if isinstance(signals_detail.get("data_exfil"), dict) else None
        if "data_exfil" in rationale or data_exfil_detail:
            detail = data_exfil_detail or signals_detail.get("data_exfil") or {}
            if isinstance(detail, dict):
                exfil_entries.append(
                    {
                        "ip": normalized,
                        "bytes_out": detail.get("bytes"),
                    }
                )
        if "dns_anomaly" in rationale:
            detail = signals_detail.get("dns_anomaly") or {}
            if isinstance(detail, dict):
                dns_anomaly_entries.append(
                    {
                        "ip": normalized,
                        "queries": detail.get("queries"),
                        "unique_domains": detail.get("unique"),
                        "high_entropy": detail.get("high_entropy"),
                    }
                )
        intel_sources_list = list(payload.get("intel_sources") or indicator_sources)
        summary_text = payload.get("aggregated_summary", {}).get("summary_text") or message
        if normalized not in threat_seen and (payload.get("is_malicious") or intel_sources_list):
            threat_seen.add(normalized)
            threat_matches.append(
                {
                    "ip": normalized,
                    "severity": normalized_severity,
                    "sources": intel_sources_list,
                    "score": payload.get("score"),
                    "summary": summary_text,
                }
            )
        if total_to_enrich:
            enriched_count = min(enriched_count + (1 if should_enrich else 0), total_to_enrich)
            progress = 30 + int((enriched_count / total_to_enrich) * 40)
            await _update_pcap_job(job_id, progress=progress)

        if payload.get("errors"):
            analysis_errors.extend(payload["errors"])

    for entry in beacon_candidates_from_activity:
        source_ip = entry.get("source_ip")
        target = entry.get("target")
        key = (source_ip, target) if source_ip and target else None
        if key and key not in beacon_seen:
            beacon_seen.add(key)
            beacon_entries.append(entry)

    await _update_pcap_job(job_id, stage="modeling", message="Evaluating model insights", progress=75)

    model_result = adaptive_pcap_model.analyze(summary, ip_payloads)
    model_insights = model_result.to_dict()
    global_severity = normalize_alert_severity(model_insights.get("severity"))
    highlight_indicators = model_insights.get("highlight_indicators") or []

    for payload in ip_payloads:
        current_severity = normalize_alert_severity(payload.get("severity"))
        if SEVERITY_ORDER.get(global_severity, 0) > SEVERITY_ORDER.get(current_severity, 0):
            payload["severity"] = global_severity
        if payload.get("ip") in highlight_indicators:
            payload.setdefault("flags", []).append("model-highlight")
            payload.setdefault("model_comments", []).append(
                f"Model flagged {payload['ip']} as part of {model_insights.get('attack_type', 'an attack')}"
            )
        if payload.get("ip") and SEVERITY_ORDER.get(normalize_alert_severity(payload.get("severity")), 0) >= SEVERITY_ORDER["High"]:
            if not source_ip_set or payload["ip"] in source_ip_set:
                block_candidates.add(payload["ip"])

    for entry in alerts_by_ip.values():
        current_severity = normalize_alert_severity(entry.get("severity"))
        if SEVERITY_ORDER.get(global_severity, 0) > SEVERITY_ORDER.get(current_severity, 0):
            entry["severity"] = global_severity
        entry.setdefault("model_severity", global_severity)

    if SEVERITY_ORDER.get(global_severity, 0) >= SEVERITY_ORDER.get("High", 0) and highlight_indicators:
        for raw_indicator in highlight_indicators[:2]:
            try:
                indicator = normalize_ip(raw_indicator)
            except Exception:
                indicator = str(raw_indicator)
            if source_ip_set and indicator not in source_ip_set:
                continue
            entry = _register_alert(
                alerts_by_ip,
                indicator,
                severity=global_severity,
                message=f"Model detected {model_insights.get('attack_type', 'an attack').lower()} pattern involving {indicator}.",
                stats={
                    "model_risk_score": model_insights.get("risk_score"),
                    "confidence": model_insights.get("confidence"),
                },
                status="open",
                model_generated=True,
            )
            entry.setdefault("flags", []).append("model-highlight")
            detected_malicious_ips.add(indicator)

    newly_blocked: List[str] = []
    blocked_metadata: Dict[str, Dict[str, Any]] = {}
    block_errors: Dict[str, str] = {}
    if block_candidates:
        async with state_store._lock:  # type: ignore[attr-defined]
            blocklist_snapshot: Optional[List[Dict[str, Any]]] = None
            for ip_value in sorted(block_candidates):
                changed = False
                added = False
                try:
                    changed, blocklist_snapshot = blocklist_store.add_entry(ip_value, current_user.id)
                except Exception as exc:
                    block_errors[ip_value] = f"Blocklist persistence failed: {exc}"
                try:
                    added = state_store.add_blocked_ip(ip_value, current_user.id)
                except Exception as exc:
                    block_errors[ip_value] = f"In-memory blocklist update failed: {exc}"
                if (changed or added) and ip_value not in newly_blocked:
                    newly_blocked.append(ip_value)
            if blocklist_snapshot is None:
                try:
                    blocklist_snapshot = blocklist_store.load_entries()
                except Exception as exc:
                    analysis_errors.append(f"Blocklist sync failed: {exc}")
                    blocklist_snapshot = None
            if blocklist_snapshot is not None:
                try:
                    state_store.sync_blocked_ips(blocklist_snapshot)
                except Exception as exc:
                    analysis_errors.append(f"Blocklist in-memory sync failed: {exc}")
            for ip_value in sorted(block_candidates):
                record = dict(state_store.blocked_ips.get(ip_value) or {})
                if record:
                    blocked_metadata[ip_value] = record
        blocked_auto_list = sorted(blocked_metadata.keys())
        if block_errors:
            for ip_value, error in block_errors.items():
                analysis_errors.append(f"Auto-block failed for {ip_value}: {error}")
        for ip_value in sorted(block_candidates):
            block_meta = blocked_metadata.get(ip_value)
            block_error = block_errors.get(ip_value)
            if block_error:
                entry = _register_alert(
                    alerts_by_ip,
                    ip_value,
                    severity="Critical",
                    message="Auto-block attempt failed; manual intervention required.",
                    stats={"auto_block": False},
                    auto_block_attempted=True,
                    auto_blocked=False,
                    block_error=block_error,
                    status="open",
                )
                entry.setdefault("auto_block_attempted", True)
                entry.setdefault("auto_blocked", False)
            elif block_meta:
                blocked_at = _format_timestamp(block_meta.get("created_at"))
                extras: Dict[str, Any] = {
                    "auto_block_attempted": True,
                    "auto_blocked": True,
                    "auto_closed_by_system": True,
                    "block_method": "network_policy_auto_block",
                    "status": "closed",
                    "status_locked": True,
                }
                if blocked_at:
                    extras["blocked_at"] = blocked_at
                blocked_by = block_meta.get("blocked_by")
                if blocked_by is not None:
                    extras["blocked_by"] = str(blocked_by)
                entry = _register_alert(
                    alerts_by_ip,
                    ip_value,
                    severity="Critical",
                    message="Auto-blocked due to critical PCAP verdict.",
                    stats={"auto_block": True},
                    **extras,
                )
                entry.setdefault("auto_blocked", True)
                entry.setdefault("auto_block_attempted", True)
                if blocked_at:
                    entry.setdefault("blocked_at", blocked_at)
        try:
            if blocked_metadata:
                async with SessionLocal() as session:
                    for ip_value in newly_blocked:
                        await report_service.add_blocked_ip(session, ip_value, current_user.id)
                    await session.commit()
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("pcap.auto_block.persist_failed", error=str(exc))
        block_message = "No critical indicators to block"
        if block_errors:
            block_message = "Auto-block attempt failed"
        elif newly_blocked:
            block_message = f"Blocking {len(newly_blocked)} critical indicators"
        elif blocked_metadata:
            block_message = "Blocklist already up to date"
        await _update_pcap_job(
            job_id,
            stage="blocklist",
            message=block_message,
            blocked_ips=blocked_auto_list,
            progress=95,
        )
    else:
        blocked_auto_list = []

    if blocked_auto_list and threat_matches:
        auto_block_set = set(blocked_auto_list)
        for entry in threat_matches:
            if entry.get("ip") in auto_block_set:
                entry["auto_blocked"] = True

    detected_malicious_ips.update(blocked_auto_list)

    alerts_info_list = [{**entry, "stats": entry.get("stats", {})} for entry in alerts_by_ip.values()]
    alerts_info = sorted(
        alerts_info_list,
        key=lambda entry: (-SEVERITY_ORDER.get(normalize_alert_severity(entry.get("severity")), 0), entry.get("indicator", "")),
    )
    malicious_count = len(alerts_info)
    malicious_indicator_list = [entry["indicator"] for entry in alerts_info]
    has_alerts = bool(alerts_info)
    blocked_ip_list = list(blocked_auto_list)
    unique_ip_count = len({str(ip) for ip in unique_ips})
    unique_source_count = len(source_ip_set) if source_ip_set else len({str(ip) for ip in source_ips})
    detection_summary: Dict[str, Any] = {}
    if beacon_entries:
        detection_summary["beaconing"] = beacon_entries
    if bruteforce_entries:
        detection_summary["bruteforce"] = bruteforce_entries
    if portscan_entries:
        detection_summary["port_scans"] = portscan_entries
    if exfil_entries:
        detection_summary["exfiltration"] = exfil_entries
    if dns_anomaly_entries:
        detection_summary["dns_anomaly"] = dns_anomaly_entries

    detection_counts = {key: len(value) for key, value in detection_summary.items()}

    alert_indicator_set = {entry.get("indicator") for entry in alerts_info if entry.get("indicator")}
    alerts_equal_malicious_ips = alert_indicator_set == detected_malicious_ips
    system_closed_alerts = [
        entry
        for entry in alerts_info
        if str(entry.get("status", "")).lower() == "closed"
    ]
    closed_alerts_hide_status_controls = all(
        entry.get("auto_closed_by_system") and entry.get("status_locked")
        for entry in system_closed_alerts
    ) if system_closed_alerts else True
    if system_closed_alerts:
        for entry in system_closed_alerts:
            entry.setdefault("status_locked", True)
            entry.setdefault("auto_closed_by_system", True)
    if detected_malicious_ips:
        alerts_equal_malicious_ips = alerts_equal_malicious_ips and len(alert_indicator_set) == len(detected_malicious_ips)
    blocked_ips_updated = True
    if blocked_auto_list:
        blocked_ips_updated = not block_errors and all(ip in blocked_metadata for ip in blocked_auto_list)
    else:
        blocked_ips_updated = not bool(block_errors)
    manual_add_remove_controls_work = all(
        hasattr(state_store, attr) for attr in ("add_blocked_ip", "remove_blocked_ip", "list_blocked_ips")
    )
    self_check = {
        "alerts_equal_malicious_ips": bool(alerts_equal_malicious_ips),
        "blocked_ips_updated": bool(blocked_ips_updated),
        "closed_alerts_hide_status_controls": bool(closed_alerts_hide_status_controls),
        "manual_add_remove_controls_work": bool(manual_add_remove_controls_work),
    }

    for check_name, passed in self_check.items():
        if not passed:
            analysis_errors.append(f"Self-check failed: {check_name}")
    total_bytes = summary.get("total_bytes", 0)
    summary_dns_activity = summary.get("dns_activity", [])
    summary_tls_flows = summary.get("tls_flows", [])
    analysis_start_iso = summary.get("analysis_start_iso")
    analysis_end_iso = summary.get("analysis_end_iso")
    ip_activity_snapshot = summary.get("ip_activity", {})

    analysis_errors = list(dict.fromkeys(analysis_errors))

    report_summary = {
        "description": f"PCAP {safe_name} processed",
        "total_packets": summary.get("total_packets", 0),
        "total_bytes": total_bytes,
        "unique_ips": unique_ip_count,
        "unique_ip_addresses": summary.get("unique_ips", []),
        "source_ips": summary.get("source_ips", []),
        "unique_source_ips": unique_source_count,
        "malicious_ips": malicious_count,
        "malicious_source_ips": malicious_indicator_list,
        "blocked_ip_count": len(blocked_ip_list),
        "protocol_counts": summary.get("protocol_counts", {}),
        "dns_activity": summary_dns_activity,
        "tls_summary": summary_tls_flows,
        "detections": detection_summary,
        "detection_counts": detection_counts,
        "threat_intel_matches": threat_matches,
        "threat_match_count": len(threat_matches),
        "beaconing_candidates": beacon_entries,
        "ip_activity": ip_activity_snapshot,
        "analysis_start": summary.get("analysis_start"),
        "analysis_start_iso": analysis_start_iso,
        "analysis_end": summary.get("analysis_end"),
        "analysis_end_iso": analysis_end_iso,
        "analysis_window_seconds": summary.get("analysis_window_seconds", 0.0),
        "model_attack_type": model_insights.get("attack_type"),
        "model_severity": model_insights.get("severity"),
        "model_risk_score": model_insights.get("risk_score"),
        "model_confidence": model_insights.get("confidence"),
        "analysis_errors": len(analysis_errors),
        "self_check": self_check,
    }

    created_at = datetime.utcnow()
    report_id = str(uuid.uuid4())

    analysis_record = {
        "id": report_id,
        "user_id": current_user.id,
        "created_at": created_at,
        "summary": report_summary,
        "ips": ip_payloads,
        "alerts": alerts_info,
        "has_alerts": has_alerts,
        "source_file": safe_name,
        "model_insights": model_insights,
        "errors": analysis_errors,
        "blocked_ips": blocked_ip_list,
        "malicious_indicators": malicious_indicator_list,
        "detections": detection_summary,
        "detection_counts": detection_counts,
        "dns_activity": summary_dns_activity,
        "tls_summary": summary_tls_flows,
        "threat_intel_matches": threat_matches,
        "threat_match_count": len(threat_matches),
        "self_check": self_check,
    }

    await _update_pcap_job(job_id, stage="persistence", message="Finalizing analysis results", progress=90, self_check=self_check)

    async with state_store._lock:  # type: ignore[attr-defined]
        state_store.save_pcap_analysis(analysis_record)
        state_store.reports[report_id] = Report(
            id=report_id,
            report_ref=report_id,
            user_id=current_user.id,
            type="pcap",
            title=f"PCAP Analysis - {safe_name}",
            source_filename=safe_name,
            has_alerts=has_alerts,
            created_at=created_at,
            summary=report_summary,
            cached=False,
        )
        actor = current_user.display_name or current_user.email
        for alert_entry in alerts_info:
            normalized_status = (alert_entry.get("status") or "open").lower()
            alert = Alert(
                id=str(uuid.uuid4()),
                detected_at=created_at,
                source_ip=alert_entry["indicator"],
                destination_ip=None,
                category="PCAP Malicious IP",
                severity=alert_entry["severity"],
                status=normalized_status.title(),
                rationale=alert_entry["message"],
                action_taken=None,
                auto_closed_by_system=bool(alert_entry.get("auto_closed_by_system")),
                status_locked=bool(alert_entry.get("status_locked")),
            )
            state_store.register_alert(alert, actor=actor, event="pcap.analysis.alert")
            alert_sources = alert_entry.get("intel_sources") or [alert_entry.get("severity", "info").lower()]
            state_store.record_threat_alert(
                {
                    "id": str(uuid.uuid4()),
                    "user_id": current_user.id,
                    "indicator": alert.source_ip,
                    "created_at": created_at,
                    "severity": alert.severity,
                    "sources": alert_sources,
                    "recommended_action": alert.action_taken or (alert.playbook or "Review PCAP response playbook"),
                    "rationale": alert.rationale,
                    "severity_breakdown": alert_entry.get("stats"),
                    "is_read": False,
                }
            )
        state_store.log_activity(
            actor=current_user.id,
            event="pcap.uploaded",
            metadata={
                "report_id": report_id,
                "file": safe_name,
                "total_packets": summary.get("total_packets", 0),
                "unique_source_ips": unique_source_count,
                "malicious_ips": malicious_count,
                "malicious_source_ips": malicious_indicator_list,
                "blocked_ips": blocked_ip_list,
                "blocked_ip_count": len(blocked_ip_list),
                "self_check": self_check,
            },
        )

    if has_alerts:
        recipients = state_store.collect_user_alert_targets(current_user)
        if recipients:
            lines = [f"- {entry['indicator']} ({entry['severity']}): {entry['message']}" for entry in alerts_info]
            body = "Malicious indicators detected in PCAP analysis:\n" + "\n".join(lines)
            state_store.send_email(
                subject="[EyeGuard] Malicious indicators detected in PCAP",
                body=body,
                recipients=recipients,
                category="pcap.alert",
                metadata={"report_id": report_id, "count": len(alerts_info)},
            )

    await _update_pcap_job(
        job_id,
        status="completed",
        stage="completed",
        message="Analysis complete",
        progress=100,
        report_ref=report_id,
        alerts_generated=malicious_count,
        blocked_ips=blocked_ip_list,
        self_check=self_check,
    )

    asyncio.create_task(_schedule_job_cleanup(job_id))

    try:
        os.remove(output_path)
    except Exception:
        logger.warning("pcap.cleanup_failed", path=output_path)

@router.post("/upload", response_model=PcapJobStatus)
async def upload_pcap(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
) -> PcapJobStatus:
    extension = os.path.splitext(file.filename or "")[1].lower()
    if extension not in ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=400, detail={"ok": False, "error": "Only .pcap or .pcapng files are supported."})

    uploads_dir = _ensure_upload_dir(current_user.id)
    timestamp = int(time.time())
    safe_name = file.filename or f"capture{extension}"
    output_name = f"{timestamp}_{safe_name}"
    output_path = os.path.join(uploads_dir, output_name)

    size_limit = settings.pcap_max_size_mb * 1024 * 1024
    total_bytes = 0
    try:
        with open(output_path, "wb") as destination:
            while chunk := await file.read(1024 * 1024):
                total_bytes += len(chunk)
                if total_bytes > size_limit:
                    await file.close()
                    os.remove(output_path)
                    raise HTTPException(
                        status_code=400,
                        detail={"ok": False, "error": f"PCAP exceeds size limit of {settings.pcap_max_size_mb} MB"},
                    )
                destination.write(chunk)
    except HTTPException:
        raise
    except Exception as exc:
        await file.close()
        if os.path.exists(output_path):
            os.remove(output_path)
        raise HTTPException(status_code=500, detail={"ok": False, "error": f"Failed to save file: {exc}"})
    finally:
        await file.close()

    job_id = str(uuid.uuid4())
    now = datetime.utcnow()
    job_record = {
        "id": job_id,
        "user_id": current_user.id,
        "status": "queued",
        "progress": 5,
        "stage": "uploaded",
        "message": "File received, preparing analysis",
        "report_ref": None,
        "alerts_generated": 0,
        "total_ips": 0,
        "filename": safe_name,
        "blocked_ips": [],
        "self_check": {},
        "created_at": now,
        "updated_at": now,
    }

    async with state_store._lock:  # type: ignore[attr-defined]
        state_store.upsert_pcap_job(job_record)

    asyncio.create_task(_process_pcap_job(job_id, current_user, output_path, safe_name))

    return PcapJobStatus(**job_record)
@router.get("/analyses", response_model=List[PcapAnalysisSummary])
async def list_pcap_analyses(current_user: User = Depends(get_current_user)) -> List[PcapAnalysisSummary]:
    async with state_store._lock:  # type: ignore[attr-defined]
        analyses = state_store.list_pcap_analyses(current_user.id)
    return [PcapAnalysisSummary(**entry) for entry in analyses]

@router.get("/analyses/{analysis_id}", response_model=PcapAnalysisDetail)
async def get_pcap_analysis(analysis_id: str, current_user: User = Depends(get_current_user)) -> PcapAnalysisDetail:
    async with state_store._lock:  # type: ignore[attr-defined]
        analysis = state_store.get_pcap_analysis(analysis_id)
        if not analysis or analysis.get("user_id") != current_user.id:
            raise HTTPException(status_code=404, detail={"error_code": "ANALYSIS_NOT_FOUND", "message": "PCAP analysis not found"})
    return PcapAnalysisDetail(**analysis)
@router.get("/jobs", response_model=List[PcapJobStatus])
async def list_pcap_jobs(current_user: User = Depends(get_current_user)) -> List[PcapJobStatus]:
    async with state_store._lock:  # type: ignore[attr-defined]
        jobs = state_store.list_pcap_jobs(current_user.id)
    return [PcapJobStatus(**job) for job in jobs]


@router.get("/jobs/{job_id}", response_model=PcapJobStatus)
async def get_pcap_job(job_id: str, current_user: User = Depends(get_current_user)) -> PcapJobStatus:
    async with state_store._lock:  # type: ignore[attr-defined]
        job = state_store.get_pcap_job(job_id)
    if not job or job.get("user_id") != current_user.id:
        raise HTTPException(status_code=404, detail={"error_code": "JOB_NOT_FOUND", "message": "PCAP job not found"})
    return PcapJobStatus(**job)
