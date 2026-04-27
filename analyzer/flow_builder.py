from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Flow:
    stream_id: int
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str

    start_time: float
    end_time: float

    total_packets: int = 0
    bytes_src_to_dst: int = 0
    bytes_dst_to_src: int = 0

    syn_seen: bool = False
    fin_seen: bool = False
    rst_seen: bool = False

    retransmissions: int = 0
    fast_retransmissions: int = 0
    duplicate_acks: int = 0
    zero_windows: int = 0
    out_of_order: int = 0
    lost_segments: int = 0
    rst_frames: list = field(default_factory=list)

    has_tls: bool = False
    tls_sni: Optional[str] = None

    def disruption_count(self) -> int:
        return (
            self.retransmissions
            + self.fast_retransmissions
            + len(self.rst_frames)
            + self.zero_windows
            + self.out_of_order
            + self.lost_segments
        )

    def duration_s(self) -> float:
        return max(0.0, self.end_time - self.start_time)

    def to_dict(self) -> dict:
        return {
            "stream_id": self.stream_id,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_s": round(self.duration_s(), 3),
            "total_packets": self.total_packets,
            "bytes_src_to_dst": self.bytes_src_to_dst,
            "bytes_dst_to_src": self.bytes_dst_to_src,
            "syn_seen": self.syn_seen,
            "fin_seen": self.fin_seen,
            "rst_seen": self.rst_seen,
            "retransmissions": self.retransmissions,
            "fast_retransmissions": self.fast_retransmissions,
            "duplicate_acks": self.duplicate_acks,
            "zero_windows": self.zero_windows,
            "out_of_order": self.out_of_order,
            "lost_segments": self.lost_segments,
            "rst_frames": self.rst_frames,
            "disruption_count": self.disruption_count(),
            "has_tls": self.has_tls,
            "tls_sni": self.tls_sni,
        }


def build_flows(packets: list[dict]) -> list[Flow]:
    flows: dict[int, Flow] = {}

    for pkt in packets:
        stream_id = pkt.get("tcp.stream")
        if stream_id is None:
            continue

        src_ip = pkt.get("ip.src", "")
        dst_ip = pkt.get("ip.dst", "")
        src_port = pkt.get("tcp.srcport") or 0
        dst_port = pkt.get("tcp.dstport") or 0
        ts = pkt.get("frame.time_epoch") or 0.0
        pkt_len = pkt.get("tcp.len") or 0

        if stream_id not in flows:
            proto = "TCP"
            flows[stream_id] = Flow(
                stream_id=stream_id,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=proto,
                start_time=ts,
                end_time=ts,
            )

        f = flows[stream_id]
        f.total_packets += 1
        f.end_time = max(f.end_time, ts)

        # Track directionality for byte counts
        if src_ip == f.src_ip and src_port == f.src_port:
            f.bytes_src_to_dst += pkt_len
        else:
            f.bytes_dst_to_src += pkt_len

        if pkt.get("tcp.flags.syn"):
            f.syn_seen = True
        if pkt.get("tcp.flags.fin"):
            f.fin_seen = True
        if pkt.get("tcp.flags.reset"):
            f.rst_seen = True
            frame = pkt.get("frame.number")
            if frame is not None:
                f.rst_frames.append(frame)

        if pkt.get("tcp.analysis.retransmission"):
            if pkt.get("tcp.analysis.fast_retransmission"):
                f.fast_retransmissions += 1
            else:
                f.retransmissions += 1
        if pkt.get("tcp.analysis.duplicate_ack"):
            f.duplicate_acks += 1
        if pkt.get("tcp.analysis.zero_window"):
            f.zero_windows += 1
        if pkt.get("tcp.analysis.out_of_order"):
            f.out_of_order += 1
        if pkt.get("tcp.analysis.lost_segment"):
            f.lost_segments += 1

        if pkt.get("tls.handshake.type") or pkt.get("tls.record.content_type"):
            f.has_tls = True
            sni_list = pkt.get("tls.handshake.extensions_server_name", "")
            if sni_list and not f.tls_sni:
                f.tls_sni = sni_list if isinstance(sni_list, str) else sni_list[0]

    return sorted(flows.values(), key=lambda f: -f.disruption_count())
