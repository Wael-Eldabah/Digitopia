"""Software-only simulation / demo — no real systems will be contacted or modified."""
from __future__ import annotations

import ipaddress


def normalize_ip(ip: str) -> str:
    try:
        return str(ipaddress.ip_address(ip.strip()))
    except ValueError as exc:
        raise ValueError("Invalid IP address") from exc
