from dataclasses import dataclass, field, asdict
from typing import Optional

HIGH_RTT_THRESHOLD_S = 0.1  # 100ms


@dataclass
class TCPEvent:
    event_type: str
    severity: str       # "info" | "warning" | "critical"
    frame: int
    timestamp: float
    stream_id: Optional[int]
    src: str
    dst: str
    detail: str
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["layer"] = "tcp"
        return d


def analyze_tcp(packets: list[dict], capture_start: float = 0.0) -> list[TCPEvent]:
    events: list[TCPEvent] = []

    for pkt in packets:
        frame = pkt.get("frame.number")
        ts = pkt.get("frame.time_epoch") or 0.0
        stream_id = pkt.get("tcp.stream")
        src_ip = pkt.get("ip.src", "")
        dst_ip = pkt.get("ip.dst", "")
        src_port = pkt.get("tcp.srcport", "")
        dst_port = pkt.get("tcp.dstport", "")
        src = f"{src_ip}:{src_port}"
        dst = f"{dst_ip}:{dst_port}"

        if pkt.get("tcp.analysis.fast_retransmission"):
            events.append(TCPEvent(
                event_type="fast_retransmission",
                severity="warning",
                frame=frame, timestamp=ts, stream_id=stream_id, src=src, dst=dst,
                detail="Fast retransmission (duplicate ACK triggered)",
            ))
        elif pkt.get("tcp.analysis.retransmission"):
            events.append(TCPEvent(
                event_type="retransmission",
                severity="warning",
                frame=frame, timestamp=ts, stream_id=stream_id, src=src, dst=dst,
                detail="TCP retransmission (packet loss or delayed ACK)",
            ))

        if pkt.get("tcp.flags.reset"):
            events.append(TCPEvent(
                event_type="tcp_rst",
                severity="critical",
                frame=frame, timestamp=ts, stream_id=stream_id, src=src, dst=dst,
                detail="TCP connection reset (RST flag)",
            ))

        if pkt.get("tcp.analysis.duplicate_ack"):
            dup_num = pkt.get("tcp.analysis.duplicate_ack_num")
            events.append(TCPEvent(
                event_type="duplicate_ack",
                severity="info",
                frame=frame, timestamp=ts, stream_id=stream_id, src=src, dst=dst,
                detail=f"Duplicate ACK #{dup_num}" if dup_num else "Duplicate ACK",
                extra={"dup_ack_num": dup_num},
            ))

        if pkt.get("tcp.analysis.out_of_order"):
            events.append(TCPEvent(
                event_type="out_of_order",
                severity="warning",
                frame=frame, timestamp=ts, stream_id=stream_id, src=src, dst=dst,
                detail="TCP out-of-order segment",
            ))

        if pkt.get("tcp.analysis.zero_window"):
            win = pkt.get("tcp.window_size")
            events.append(TCPEvent(
                event_type="zero_window",
                severity="critical",
                frame=frame, timestamp=ts, stream_id=stream_id, src=src, dst=dst,
                detail="TCP Zero Window — receiver buffer full, sender must wait",
                extra={"window_size": win},
            ))

        if pkt.get("tcp.analysis.lost_segment"):
            events.append(TCPEvent(
                event_type="lost_segment",
                severity="warning",
                frame=frame, timestamp=ts, stream_id=stream_id, src=src, dst=dst,
                detail="Lost segment detected (gap in sequence numbers)",
            ))

        rtt = pkt.get("tcp.analysis.ack_rtt")
        if rtt and rtt > HIGH_RTT_THRESHOLD_S:
            events.append(TCPEvent(
                event_type="high_rtt",
                severity="warning",
                frame=frame, timestamp=ts, stream_id=stream_id, src=src, dst=dst,
                detail=f"High RTT: {rtt * 1000:.1f} ms",
                extra={"rtt_ms": round(rtt * 1000, 2)},
            ))

    return events
