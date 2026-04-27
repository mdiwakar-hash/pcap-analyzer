from dataclasses import dataclass, field
from typing import Optional

# TLS handshake message types (RFC 8446 §4)
HS_CLIENT_HELLO = "1"
HS_SERVER_HELLO = "2"
HS_FINISHED = "20"

# TLS record content types
CT_CHANGE_CIPHER_SPEC = "20"
CT_ALERT = "21"
CT_HANDSHAKE = "22"
CT_APPLICATION_DATA = "23"

TLS_VERSION_NAMES = {
    "0x0300": "SSL 3.0",
    "0x0301": "TLS 1.0",
    "0x0302": "TLS 1.1",
    "0x0303": "TLS 1.2",
    "0x0304": "TLS 1.3",
}

# TLS 1.3-only cipher suites
TLS13_CIPHERS = {"0x1301", "0x1302", "0x1303", "0x1304", "0x1305"}

TLS_ALERT_LEVEL = {"1": "warning", "2": "fatal"}

TLS_ALERT_DESC = {
    "0": "close_notify",
    "10": "unexpected_message",
    "20": "bad_record_mac",
    "40": "handshake_failure",
    "42": "bad_certificate",
    "43": "unsupported_certificate",
    "44": "certificate_revoked",
    "45": "certificate_expired",
    "46": "certificate_unknown",
    "47": "illegal_parameter",
    "48": "unknown_ca",
    "49": "access_denied",
    "50": "decode_error",
    "51": "decrypt_error",
    "70": "protocol_version",
    "71": "insufficient_security",
    "80": "internal_error",
    "86": "inappropriate_fallback",
    "90": "user_canceled",
    "110": "no_renegotiation",
    "112": "missing_extension",
    "113": "unsupported_extension",
    "116": "certificate_unobtainable",
    "120": "unrecognized_name",
    "121": "bad_certificate_status_response",
    "122": "bad_certificate_hash_value",
    "123": "unknown_psk_identity",
    "124": "certificate_required",
    "255": "no_application_protocol",
}


@dataclass
class TLSFlow:
    stream_id: int
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    sni: Optional[str] = None

    client_hello_frame: Optional[int] = None
    client_hello_time: Optional[float] = None
    client_hello_version: Optional[str] = None
    client_hello_ciphers: list = field(default_factory=list)

    server_hello_frame: Optional[int] = None
    server_hello_time: Optional[float] = None
    server_hello_version: Optional[str] = None
    server_chosen_cipher: Optional[str] = None

    change_cipher_spec_seen: bool = False
    finished_seen: bool = False
    application_data_seen: bool = False

    rst_before_server_hello: bool = False
    rst_after_client_hello_frame: Optional[int] = None

    alerts: list = field(default_factory=list)

    handshake_complete: bool = False
    handshake_duration_ms: Optional[float] = None
    negotiated_tls_version: Optional[str] = None


def analyze_tls(packets: list[dict]) -> list[dict]:
    flows: dict[int, TLSFlow] = {}
    # Track which tcp.stream IDs have TLS activity
    tls_streams: set[int] = set()

    for pkt in packets:
        stream_id = pkt.get("tcp.stream")
        if stream_id is None:
            continue

        src_ip = pkt.get("ip.src", "")
        dst_ip = pkt.get("ip.dst", "")
        src_port = pkt.get("tcp.srcport") or 0
        dst_port = pkt.get("tcp.dstport") or 0
        frame = pkt.get("frame.number")
        ts = pkt.get("frame.time_epoch") or 0.0

        hs_types: list[str] = pkt.get("tls.handshake.type") or []
        ct_types: list[str] = pkt.get("tls.record.content_type") or []

        has_tls_content = bool(hs_types or ct_types)

        if has_tls_content:
            tls_streams.add(stream_id)
            if stream_id not in flows:
                flows[stream_id] = TLSFlow(
                    stream_id=stream_id,
                    src_ip=src_ip, dst_ip=dst_ip,
                    src_port=src_port, dst_port=dst_port,
                )

        if stream_id not in flows:
            # Non-TLS packet; check if RST on a known TLS stream (handled below)
            if pkt.get("tcp.flags.reset") and stream_id in tls_streams:
                f = flows.get(stream_id)
                if f and not f.server_hello_frame:
                    f.rst_before_server_hello = True
                    if f.rst_after_client_hello_frame is None:
                        f.rst_after_client_hello_frame = frame
            continue

        f = flows[stream_id]

        # ClientHello
        if HS_CLIENT_HELLO in hs_types and f.client_hello_frame is None:
            f.client_hello_frame = frame
            f.client_hello_time = ts
            ver_list = pkt.get("tls.handshake.version") or []
            f.client_hello_version = ver_list[0] if ver_list else None
            f.client_hello_ciphers = pkt.get("tls.handshake.ciphersuite") or []
            sni = pkt.get("tls.handshake.extensions_server_name", "")
            if sni:
                f.sni = sni if isinstance(sni, str) else sni

        # ServerHello
        if HS_SERVER_HELLO in hs_types and f.server_hello_frame is None:
            f.server_hello_frame = frame
            f.server_hello_time = ts
            ver_list = pkt.get("tls.handshake.version") or []
            f.server_hello_version = ver_list[0] if ver_list else None
            chosen = pkt.get("tls.handshake.ciphersuite") or []
            f.server_chosen_cipher = chosen[0] if chosen else None

        # Finished
        if HS_FINISHED in hs_types:
            f.finished_seen = True

        # Content type records
        if CT_CHANGE_CIPHER_SPEC in ct_types:
            f.change_cipher_spec_seen = True
        if CT_APPLICATION_DATA in ct_types:
            f.application_data_seen = True

        # Alert records
        if CT_ALERT in ct_types:
            levels = pkt.get("tls.alert_message.level") or []
            descs = pkt.get("tls.alert_message.desc") or []
            for i, lvl in enumerate(levels):
                desc_code = descs[i] if i < len(descs) else ""
                direction = "client" if src_ip == f.src_ip else "server"
                f.alerts.append({
                    "frame": frame,
                    "time": ts,
                    "level": TLS_ALERT_LEVEL.get(lvl, f"level_{lvl}"),
                    "level_code": lvl,
                    "description": TLS_ALERT_DESC.get(desc_code, f"alert_{desc_code}"),
                    "description_code": desc_code,
                    "direction": direction,
                    "src": f"{src_ip}:{src_port}",
                    "dst": f"{dst_ip}:{dst_port}",
                })

        # RST on a TLS stream
        if pkt.get("tcp.flags.reset"):
            tls_streams.add(stream_id)
            if not f.server_hello_frame:
                f.rst_before_server_hello = True
                if f.rst_after_client_hello_frame is None:
                    f.rst_after_client_hello_frame = frame

    # Derive state
    # Without session keys tshark can't see encrypted ApplicationData (content_type 23).
    # ChangeCipherSpec (or the server Finished record following ServerHello) is the
    # practical signal that the handshake succeeded.
    for f in flows.values():
        f.handshake_complete = (
            f.server_hello_frame is not None and f.change_cipher_spec_seen
        )
        if f.client_hello_time and f.server_hello_time:
            f.handshake_duration_ms = round(
                (f.server_hello_time - f.client_hello_time) * 1000, 2
            )
        # Determine TLS version: prefer cipher-based detection
        if f.server_chosen_cipher and f.server_chosen_cipher.lower() in TLS13_CIPHERS:
            f.negotiated_tls_version = "TLS 1.3"
        elif f.server_hello_version:
            f.negotiated_tls_version = TLS_VERSION_NAMES.get(
                f.server_hello_version.lower(), f.server_hello_version
            )

    return _build_events(flows)


def _build_events(flows: dict) -> list[dict]:
    events = []

    for f in flows.values():
        src = f"{f.src_ip}:{f.src_port}"
        dst = f"{f.dst_ip}:{f.dst_port}"
        base = {
            "stream_id": f.stream_id,
            "src": src,
            "dst": dst,
            "sni": f.sni,
            "layer": "tls",
        }

        # Incomplete handshake
        if f.client_hello_frame and not f.server_hello_frame:
            detail = (
                "RST received after ClientHello — server rejected connection before ServerHello"
                if f.rst_before_server_hello
                else "No ServerHello received (possible firewall drop or timeout)"
            )
            events.append({
                **base,
                "type": "tls_incomplete_handshake",
                "severity": "critical",
                "detail": detail,
                "client_hello_frame": f.client_hello_frame,
                "rst_frame": f.rst_after_client_hello_frame,
                "offered_version": TLS_VERSION_NAMES.get(
                    (f.client_hello_version or "").lower(), f.client_hello_version
                ),
                "offered_ciphers": f.client_hello_ciphers,
                "timestamp": f.client_hello_time,
            })

        # TLS alerts
        for alert in f.alerts:
            severity = "critical" if alert["level"] == "fatal" else "warning"
            events.append({
                **base,
                "type": "tls_alert",
                "severity": severity,
                "detail": f"{alert['level'].upper()} alert: {alert['description']} (from {alert['direction']})",
                "alert_level": alert["level"],
                "alert_description": alert["description"],
                "direction": alert["direction"],
                "frame": alert["frame"],
                "timestamp": alert["time"],
            })

        # Version downgrade
        if (
            f.server_hello_version
            and not f.negotiated_tls_version == "TLS 1.3"
        ):
            try:
                ver_int = int(f.server_hello_version, 16)
                if ver_int < 0x0303:  # below TLS 1.2
                    events.append({
                        **base,
                        "type": "tls_version_downgrade",
                        "severity": "warning",
                        "detail": (
                            f"Server negotiated {f.negotiated_tls_version} "
                            f"(client offered up to "
                            f"{TLS_VERSION_NAMES.get((f.client_hello_version or '').lower(), f.client_hello_version)})"
                        ),
                        "negotiated_version": f.negotiated_tls_version,
                        "timestamp": f.server_hello_time,
                    })
            except (ValueError, TypeError):
                pass

        # Completed handshake summary (informational)
        if f.handshake_complete:
            events.append({
                **base,
                "type": "tls_handshake_complete",
                "severity": "info",
                "detail": (
                    f"TLS handshake complete — {f.negotiated_tls_version or 'unknown version'}, "
                    f"cipher {f.server_chosen_cipher or 'unknown'}"
                    + (f", SNI: {f.sni}" if f.sni else "")
                    + (f", RTT: {f.handshake_duration_ms} ms" if f.handshake_duration_ms else "")
                ),
                "negotiated_version": f.negotiated_tls_version,
                "cipher": f.server_chosen_cipher,
                "handshake_duration_ms": f.handshake_duration_ms,
                "timestamp": f.server_hello_time,
                "server_hello_frame": f.server_hello_frame,
            })

    return sorted(events, key=lambda e: e.get("timestamp") or 0)
