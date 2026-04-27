# PCAP Analyzer

A local web app for analyzing packet captures (.pcap) to identify where network traffic is being disrupted — at the TCP, TLS, or network layer.

## Features

- Upload any `.pcap` / `.pcapng` file via browser
- Filter by **Endpoint IP** (either direction), **Strict Src/Dst IP**, **Port**, **Protocol**
- Detects:
  - TCP retransmissions, fast retransmissions, RSTs, zero windows, out-of-order segments, high RTT
  - TLS incomplete handshakes (RST after ClientHello), TLS alert records, version downgrades
- Per-flow statistics table sorted by disruption count
- Disruption timeline with tabs for All / TCP / TLS events

## Requirements

- Python 3.11+ (no pip installs needed)
- [Wireshark / tshark](https://www.wireshark.org/download.html) — must be installed

## Run

```bash
python3 server.py
```

Opens at **http://127.0.0.1:8000**

## Usage

1. Click **Browse** or drag a `.pcap` file onto the upload area
2. Optionally enter filter criteria (IP addresses, port, protocol)
3. Click **Analyze**
4. Review summary cards, per-flow table, and the disruption events panel

## Architecture

```
server.py                  # HTTP server (stdlib only, port 8000)
analyzer/
  tshark_runner.py         # Runs tshark, parses pipe-delimited output
  flow_builder.py          # Groups packets into per-flow statistics
  tcp_analyzer.py          # TCP disruption event detection
  tls_analyzer.py          # TLS state machine + handshake analysis
  report_builder.py        # Assembles final JSON report
static/
  index.html               # Single-page frontend (vanilla JS)
```

tshark does all packet parsing in one pass using field extraction mode. Python only handles grouping, analysis logic, and serving the web UI.

## Notes

- PCAP files are deleted from disk immediately after analysis
- Files > 200 MB are rejected
- TLS decryption is not supported — handshake metadata is analyzed using tshark's built-in dissectors
