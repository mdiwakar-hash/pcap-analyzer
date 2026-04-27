from .tshark_runner import run_tshark, build_display_filter
from .flow_builder import build_flows
from .tcp_analyzer import analyze_tcp
from .tls_analyzer import analyze_tls
from .report_builder import build_report


def run_analysis(pcap_path: str, filters: dict) -> dict:
    display_filter = build_display_filter(filters)
    packets = run_tshark(pcap_path, display_filter)

    if not packets:
        return {
            "error": "No packets matched the given filters (or the PCAP is empty).",
            "filters_applied": {k: v for k, v in filters.items() if v},
            "pcap_filename": pcap_path.split("/")[-1],
        }

    flows = build_flows(packets)
    tcp_events = analyze_tcp(packets)
    tls_events = analyze_tls(packets)
    return build_report(pcap_path, packets, flows, tcp_events, tls_events, filters)
