"""Behavioural detectors over normalised network events.

Each detector adds a *tag* (and a one-line evidence string) to the events that
support it. Tags are investigation hints, not verdicts. Only fields that exist
in network telemetry are used: IPs, ports, connection state, bytes, durations,
DNS queries, Zeek ssh auth_success, Suricata/Zeek alert text.

Tagged events are "signal" events; untagged events remain available as context
but are never used to create links.
"""
from __future__ import annotations

import math
import statistics
from collections import Counter, defaultdict
from datetime import timedelta

from app.attack_mapping.catalog import Catalog
from app.core.config import CorrelationSettings
from app.correlation.model import EventView, is_internal

FAILED_STATES = {"S0", "REJ", "RSTO", "RSTR", "RSTOS0", "RSTRH", "SH", "SHR", "OTH"}
SCAN_WINDOW = timedelta(minutes=15)
BRUTE_WINDOW = timedelta(hours=1)
SUCCESS_LOOKBACK = timedelta(hours=2)


def _add(ev: EventView, tag: str, evidence: str) -> None:
    ev.tags.add(tag)
    ev.tag_evidence.setdefault(tag, evidence)


def _windows(events: list[EventView], window: timedelta):
    """Yield maximal sliding-window slices over time-sorted events."""
    j = 0
    for i in range(len(events)):
        while events[i].ts - events[j].ts > window:
            j += 1
        yield events[j:i + 1]


def tag_signatures(events: list[EventView], catalog: Catalog) -> None:
    for ev in events:
        if ev.event_type == "ids_alert":
            _add(ev, "ids_alert", f"Suricata alert: {ev.signature or 'unnamed'}")
        elif ev.event_type == "zeek_notice":
            _add(ev, "zeek_notice", f"Zeek notice: {ev.category or ev.signature}")
        else:
            continue
        text = f"{ev.signature or ''} {ev.category or ''}"
        for rule in catalog.signature_rules:  # first matching rule wins
            if rule.pattern.search(text):
                tag = rule.tag
                if ev.event_type == "zeek_notice":
                    tag = {"scan_signature": "port_scan_notice",
                           "bruteforce_signature": "password_guessing_notice"}.get(tag, tag)
                _add(ev, tag, f"rule {rule.id} matched '{text.strip()[:120]}'")
                break


def tag_scans(events: list[EventView], cfg: CorrelationSettings) -> None:
    conns = [e for e in events if e.event_type == "connection" and e.src and e.dst]
    by_src: dict[str, list[EventView]] = defaultdict(list)
    for e in conns:
        by_src[e.src].append(e)
    for src, evs in by_src.items():
        evs.sort(key=lambda e: e.ts)
        failed = [e for e in evs if (e.conn_state or "") in FAILED_STATES or (e.duration or 0) < 0.01]
        # host sweep: many distinct destination hosts with failed/short connections
        for win in _windows(failed, SCAN_WINDOW):
            hosts = {e.dst for e in win}
            if len(hosts) >= cfg.scan_min_targets:
                for e in win:
                    _add(e, "host_sweep", f"{src} contacted {len(hosts)} hosts within 15 min (mostly failed/short)")
        # port scan: many distinct ports on one host
        by_dst: dict[str, list[EventView]] = defaultdict(list)
        for e in evs:
            by_dst[e.dst].append(e)
        for dst, devs in by_dst.items():
            for win in _windows(devs, SCAN_WINDOW):
                ports = {e.dport for e in win if e.dport is not None}
                if len(ports) >= cfg.scan_min_targets:
                    for e in win:
                        _add(e, "port_scan", f"{src} probed {len(ports)} ports on {dst} within 15 min")


def tag_ssh(events: list[EventView], cfg: CorrelationSettings) -> None:
    ssh = sorted((e for e in events if e.event_type == "ssh_auth" and e.src and e.dst), key=lambda e: e.ts)
    by_uid = defaultdict(list)
    for e in events:
        if e.event_type == "connection" and e.flow_uid:
            by_uid[e.flow_uid].append(e)
    pairs: dict[tuple[str, str], list[EventView]] = defaultdict(list)
    for e in ssh:
        pairs[(e.src, e.dst)].append(e)
    for (src, dst), evs in pairs.items():
        fails = [e for e in evs if e.auth_success is False]
        brute_members: set[str] = set()
        for win in _windows(fails, BRUTE_WINDOW):
            if len(win) >= cfg.bruteforce_min_failures:
                for e in win:
                    if e.event_id not in brute_members:
                        brute_members.add(e.event_id)
                        _add(e, "ssh_bruteforce", f"{len(win)} failed SSH logins {src} -> {dst} within 1 h")
                        for c in by_uid.get(e.flow_uid or "", []):
                            _add(c, "ssh_bruteforce", f"connection carrying a failed SSH login ({e.event_id})")
        for e in evs:
            if e.auth_success is True:
                prior = [f for f in fails if timedelta(0) <= e.ts - f.ts <= SUCCESS_LOOKBACK]
                if len(prior) >= cfg.bruteforce_min_failures:
                    _add(e, "auth_success_after_failures",
                         f"successful SSH login {src} -> {dst} after {len(prior)} failures in the previous 2 h")
                    for c in by_uid.get(e.flow_uid or "", []):
                        _add(c, "auth_success_after_failures",
                             f"session of the successful login ({e.event_id}), duration {c.duration or 0:.0f}s")


def tag_beacons(events: list[EventView], cfg: CorrelationSettings) -> None:
    nets = cfg.internal_networks
    series: dict[tuple, list[EventView]] = defaultdict(list)
    for e in events:
        if e.event_type == "connection" and is_internal(e.src, nets) and e.dst and not is_internal(e.dst, nets):
            series[(e.src, e.dst, e.dport)].append(e)
    by_uid = defaultdict(list)
    for e in events:
        if e.flow_uid and e.event_type in ("tls_handshake", "http_request"):
            by_uid[e.flow_uid].append(e)
    for (src, dst, port), evs in series.items():
        if len(evs) < cfg.beacon_min_connections:
            continue
        evs.sort(key=lambda e: e.ts)
        gaps = [(b.ts - a.ts).total_seconds() for a, b in zip(evs, evs[1:])]
        gaps = [g for g in gaps if g > 0]
        if len(gaps) < cfg.beacon_min_connections - 1:
            continue
        med = statistics.median(gaps)
        if med < 10:
            continue
        mad = statistics.median(abs(g - med) for g in gaps)
        jitter = mad / med
        if jitter <= cfg.beacon_max_jitter_ratio:
            ev_text = (f"{len(evs)} connections {src} -> {dst}:{port}, median interval {med:.0f}s, "
                       f"jitter {jitter:.1%}")
            for e in evs:
                _add(e, "beacon", ev_text)
                for x in by_uid.get(e.flow_uid or "", []):
                    _add(x, "beacon", f"TLS/HTTP record of a beacon-like connection ({e.event_id})")


def tag_transfers(events: list[EventView], cfg: CorrelationSettings) -> None:
    nets = cfg.internal_networks
    by_uid = defaultdict(list)
    for e in events:
        if e.flow_uid and e.event_type in ("tls_handshake", "http_request"):
            by_uid[e.flow_uid].append(e)
    for e in events:
        if (e.event_type in ("connection", "flow") and (e.bytes_sent or 0) >= cfg.exfil_min_bytes
                and is_internal(e.src, nets) and e.dst and not is_internal(e.dst, nets)):
            mb = (e.bytes_sent or 0) / 1e6
            _add(e, "large_outbound", f"{mb:,.0f} MB sent from {e.src} to external {e.dst}:{e.dport}")
            for x in by_uid.get(e.flow_uid or "", []):
                _add(x, "large_outbound", f"TLS/HTTP record of a large outbound transfer ({e.event_id})")


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def tag_dns(events: list[EventView], cfg: CorrelationSettings) -> None:
    for e in events:
        if e.event_type != "dns_query" or not e.dns_query or e.sensor != "zeek":
            continue
        label = e.dns_query.split(".")[0]
        if len(label) >= cfg.dns_tunnel_min_label_len and _entropy(label) >= 3.5:
            _add(e, "dns_tunnel", f"DNS label of {len(label)} chars with entropy {_entropy(label):.2f} bits/char")


def run_detectors(events: list[EventView], cfg: CorrelationSettings, catalog: Catalog) -> dict[str, int]:
    for e in events:
        e.tags.clear()
        e.tag_evidence.clear()
    tag_signatures(events, catalog)
    tag_scans(events, cfg)
    tag_ssh(events, cfg)
    tag_beacons(events, cfg)
    tag_transfers(events, cfg)
    tag_dns(events, cfg)
    counts: Counter = Counter()
    for e in events:
        counts.update(e.tags)
    return dict(counts)
