import os


def build_report(
    pcap_path: str,
    packets: list[dict],
    flows: list,
    tcp_events: list,
    tls_events: list[dict],
    filters: dict,
) -> dict:
    if not packets:
        capture_duration = 0.0
        total_bytes = 0
        capture_start = 0.0
    else:
        times = [p["frame.time_epoch"] for p in packets if p.get("frame.time_epoch") is not None]
        capture_start = min(times) if times else 0.0
        capture_end = max(times) if times else 0.0
        capture_duration = round(capture_end - capture_start, 3)
        total_bytes = sum((p.get("tcp.len") or 0) for p in packets)

    tcp_event_dicts = [e.to_dict() for e in tcp_events]
    for e in tcp_event_dicts:
        if capture_start and e.get("timestamp"):
            e["time_relative"] = round(e["timestamp"] - capture_start, 3)
        else:
            e["time_relative"] = 0.0

    for e in tls_events:
        if capture_start and e.get("timestamp"):
            e["time_relative"] = round(e["timestamp"] - capture_start, 3)
        else:
            e["time_relative"] = 0.0

    # Summary counts
    retrans = sum(1 for e in tcp_events if e.event_type == "retransmission")
    fast_retrans = sum(1 for e in tcp_events if e.event_type == "fast_retransmission")
    tcp_resets = sum(1 for e in tcp_events if e.event_type == "tcp_rst")
    dup_acks = sum(1 for e in tcp_events if e.event_type == "duplicate_ack")
    zero_wins = sum(1 for e in tcp_events if e.event_type == "zero_window")
    out_of_order = sum(1 for e in tcp_events if e.event_type == "out_of_order")
    high_rtt = sum(1 for e in tcp_events if e.event_type == "high_rtt")
    lost_segs = sum(1 for e in tcp_events if e.event_type == "lost_segment")
    tls_incomplete = sum(1 for e in tls_events if e["type"] == "tls_incomplete_handshake")
    tls_alerts = sum(1 for e in tls_events if e["type"] == "tls_alert")
    tls_complete = sum(1 for e in tls_events if e["type"] == "tls_handshake_complete")
    tls_downgrade = sum(1 for e in tls_events if e["type"] == "tls_version_downgrade")

    flows_with_disruptions = sum(1 for f in flows if f.disruption_count() > 0)

    # Merged timeline: combine TCP and TLS events, sort by time
    timeline = []
    for e in tcp_event_dicts:
        timeline.append({
            "time_relative": e["time_relative"],
            "timestamp": e.get("timestamp"),
            "frame": e.get("frame"),
            "layer": "tcp",
            "event_type": e["event_type"],
            "severity": e["severity"],
            "src": e["src"],
            "dst": e["dst"],
            "stream_id": e.get("stream_id"),
            "detail": e["detail"],
        })
    for e in tls_events:
        timeline.append({
            "time_relative": e.get("time_relative", 0),
            "timestamp": e.get("timestamp"),
            "frame": e.get("frame") or e.get("client_hello_frame") or e.get("server_hello_frame"),
            "layer": "tls",
            "event_type": e["type"],
            "severity": e["severity"],
            "src": e["src"],
            "dst": e["dst"],
            "stream_id": e.get("stream_id"),
            "detail": e["detail"],
        })
    timeline.sort(key=lambda x: x.get("time_relative") or 0)

    # Filter active_filters for display (omit empty values)
    active_filters = {k: v for k, v in filters.items() if v}

    return {
        "pcap_filename": os.path.basename(pcap_path),
        "capture_duration_s": capture_duration,
        "total_packets": len(packets),
        "total_bytes": total_bytes,
        "filters_applied": active_filters,
        "summary": {
            "total_flows": len(flows),
            "flows_with_disruptions": flows_with_disruptions,
            "retransmissions": retrans,
            "fast_retransmissions": fast_retrans,
            "tcp_resets": tcp_resets,
            "duplicate_acks": dup_acks,
            "zero_windows": zero_wins,
            "out_of_order": out_of_order,
            "lost_segments": lost_segs,
            "high_rtt_events": high_rtt,
            "tls_incomplete_handshakes": tls_incomplete,
            "tls_alerts": tls_alerts,
            "tls_handshakes_complete": tls_complete,
            "tls_version_downgrades": tls_downgrade,
        },
        "flows": [f.to_dict() for f in flows],
        "tcp_events": tcp_event_dicts,
        "tls_events": tls_events,
        "disruption_timeline": timeline,
    }
