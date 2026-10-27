"""Lightweight in-memory view of an event used by detectors, the correlation
engine, baselines and evaluation (no ORM objects, so it is fast and testable)."""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from functools import lru_cache

# Canonical attack-stage vocabulary (ordered).
STAGES = ["reconnaissance", "scanning", "credential_access", "initial_access", "command_and_control", "exfiltration"]
STAGE_LABELS = {
    "reconnaissance": "Reconnaissance",
    "scanning": "Scanning",
    "credential_access": "Credential attack",
    "initial_access": "Access",
    "command_and_control": "Post-compromise / C2",
    "exfiltration": "Possible exfiltration",
}

# detector / signature tag -> stage
TAG_STAGE = {
    "host_sweep": "reconnaissance",
    "address_scan_notice": "reconnaissance",
    "port_scan": "scanning",
    "port_scan_notice": "scanning",
    "scan_signature": "scanning",
    "ssh_bruteforce": "credential_access",
    "bruteforce_signature": "credential_access",
    "password_guessing_notice": "credential_access",
    "auth_success_after_failures": "initial_access",
    "web_attack_signature": "initial_access",
    "beacon": "command_and_control",
    "c2_signature": "command_and_control",
    "large_outbound": "exfiltration",
    "dns_tunnel": "exfiltration",
    "dns_tunnel_signature": "exfiltration",
}


@dataclass
class EventView:
    event_id: str
    ts: datetime
    sensor: str
    log: str
    event_type: str
    src: str | None
    dst: str | None
    sport: int | None = None
    dport: int | None = None
    proto: str | None = None
    app: str | None = None
    signature: str | None = None
    signature_id: int | None = None
    category: str | None = None
    severity: int | None = None
    conn_state: str | None = None
    bytes_sent: int | None = None
    bytes_received: int | None = None
    duration: float | None = None
    dns_query: str | None = None
    host: str | None = None
    sni: str | None = None
    auth_success: bool | None = None
    community_id: str | None = None
    flow_uid: str | None = None
    has_warnings: bool = False
    tags: set[str] = field(default_factory=set)
    tag_evidence: dict[str, str] = field(default_factory=dict)

    @property
    def end(self) -> datetime:
        if self.duration and self.duration > 0:
            return self.ts + timedelta(seconds=min(self.duration, 86400))
        return self.ts

    @property
    def stage(self) -> str | None:
        """Most advanced stage implied by this event's tags (None for context events)."""
        stages = [TAG_STAGE[t] for t in self.tags if t in TAG_STAGE]
        if not stages:
            return None
        return max(stages, key=STAGES.index)

    @property
    def is_signal(self) -> bool:
        return bool(self.tags)


@lru_cache(maxsize=8)
def _nets(nets: tuple[str, ...]):
    return [ipaddress.ip_network(n) for n in nets]


def is_internal(ip: str | None, internal_networks: list[str]) -> bool:
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in n for n in _nets(tuple(internal_networks)))


def from_orm(e) -> EventView:
    return EventView(
        event_id=e.event_id, ts=e.timestamp_utc, sensor=e.source_sensor, log=e.source_log,
        event_type=e.event_type, src=e.source_ip, dst=e.destination_ip, sport=e.source_port,
        dport=e.destination_port, proto=e.transport_protocol, app=e.application_protocol,
        signature=e.alert_signature, signature_id=e.alert_signature_id, category=e.alert_category,
        severity=e.sensor_severity, conn_state=e.connection_state, bytes_sent=e.bytes_sent,
        bytes_received=e.bytes_received, duration=e.duration, dns_query=e.dns_query,
        host=e.http_host or e.destination_host, sni=e.tls_server_name, auth_success=e.auth_success,
        community_id=e.community_id, flow_uid=e.flow_uid, has_warnings=bool(e.normalization_warnings),
    )
