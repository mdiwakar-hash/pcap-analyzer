import subprocess
import shutil
import os

TSHARK_PATH = (
    shutil.which("tshark")
    or "/Applications/Wireshark.app/Contents/MacOS/tshark"
)

TSHARK_FIELDS = [
    "frame.number",
    "frame.time_epoch",
    "ip.src",
    "ip.dst",
    "ip.proto",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.stream",
    "tcp.flags.syn",
    "tcp.flags.fin",
    "tcp.flags.reset",
    "tcp.flags.ack",
    "tcp.seq",
    "tcp.ack",
    "tcp.len",
    "tcp.window_size",
    "tcp.analysis.retransmission",
    "tcp.analysis.fast_retransmission",
    "tcp.analysis.duplicate_ack",
    "tcp.analysis.duplicate_ack_num",
    "tcp.analysis.out_of_order",
    "tcp.analysis.zero_window",
    "tcp.analysis.ack_rtt",
    "tcp.analysis.lost_segment",
    "tls.record.content_type",
    "tls.handshake.type",
    "tls.handshake.version",
    "tls.handshake.ciphersuite",
    "tls.handshake.extensions_server_name",
    "tls.alert_message.level",
    "tls.alert_message.desc",
]

FIELD_SEP = "|"


def run_tshark(pcap_path: str, display_filter: str | None = None) -> list[dict]:
    if not os.path.exists(TSHARK_PATH):
        raise RuntimeError(f"tshark not found at {TSHARK_PATH}")

    cmd = [
        TSHARK_PATH,
        "-r", pcap_path,
        "-T", "fields",
        "-E", f"separator={FIELD_SEP}",
        "-E", "occurrence=a",
    ]
    for field in TSHARK_FIELDS:
        cmd += ["-e", field]
    if display_filter:
        cmd += ["-Y", display_filter]

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

    packets = []
    for line in result.stdout.splitlines():
        parts = line.split(FIELD_SEP)
        if len(parts) == len(TSHARK_FIELDS):
            pkt = dict(zip(TSHARK_FIELDS, parts))
            packets.append(_normalize(pkt))

    return packets


def build_display_filter(filters: dict) -> str | None:
    parts = []

    if filters.get("endpoint_ip"):
        parts.append(f"ip.addr=={filters['endpoint_ip']}")
    if filters.get("src_ip"):
        parts.append(f"ip.src=={filters['src_ip']}")
    if filters.get("dst_ip"):
        parts.append(f"ip.dst=={filters['dst_ip']}")
    if filters.get("port"):
        try:
            p = int(filters["port"])
            parts.append(f"tcp.port=={p} or udp.port=={p}")
        except ValueError:
            pass
    if filters.get("protocol"):
        proto_map = {"TCP": "tcp", "UDP": "udp", "ICMP": "icmp"}
        proto = proto_map.get(filters["protocol"].upper(), filters["protocol"].lower())
        parts.append(proto)

    return " and ".join(f"({p})" for p in parts) if parts else None


def get_tshark_version() -> str:
    try:
        r = subprocess.run([TSHARK_PATH, "--version"], capture_output=True, text=True, timeout=10)
        first_line = r.stdout.splitlines()[0] if r.stdout else "unknown"
        return first_line
    except Exception:
        return "unknown"


def _multi(val: str) -> list[str]:
    """Split comma-separated tshark multi-value fields into a list."""
    if not val:
        return []
    return [x.strip() for x in val.split(",") if x.strip()]


def _normalize(pkt: dict) -> dict:
    """Coerce string values to appropriate Python types."""
    int_fields = {
        "frame.number", "tcp.srcport", "tcp.dstport", "tcp.stream",
        "tcp.seq", "tcp.ack", "tcp.len", "tcp.window_size",
    }
    float_fields = {"frame.time_epoch", "tcp.analysis.ack_rtt"}
    bool_fields = {
        "tcp.flags.syn", "tcp.flags.fin", "tcp.flags.reset", "tcp.flags.ack",
        "tcp.analysis.retransmission", "tcp.analysis.fast_retransmission",
        "tcp.analysis.duplicate_ack", "tcp.analysis.out_of_order",
        "tcp.analysis.zero_window", "tcp.analysis.lost_segment",
    }
    multi_fields = {
        "tls.record.content_type", "tls.handshake.type",
        "tls.handshake.version", "tls.handshake.ciphersuite",
        "tls.alert_message.level", "tls.alert_message.desc",
    }

    out = {}
    for k, v in pkt.items():
        if k in int_fields:
            try:
                out[k] = int(v)
            except (ValueError, TypeError):
                out[k] = None
        elif k in float_fields:
            try:
                out[k] = float(v)
            except (ValueError, TypeError):
                out[k] = None
        elif k in bool_fields:
            out[k] = v in ("1", "True", "true")
        elif k in multi_fields:
            out[k] = _multi(v)
        else:
            out[k] = v
    return out
