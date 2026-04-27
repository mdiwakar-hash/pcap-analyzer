import json
import os
from typing import Optional

SYSTEM_PROMPT = """You are a network reliability engineer diagnosing PCAP captures for a customer support team.
Analyze the JSON report and provide a concise plain-English diagnosis as 4-6 bullet points:
- Lead with the primary issue and its severity
- Identify the most disrupted flows by IP, port, and SNI where available
- Distinguish symptoms (retransmissions, RSTs) from likely root causes (congestion, firewall block, TLS misconfiguration)
- For TLS failures, note what they suggest (cert rejection, unsupported version, firewall blocking TLS handshake)
- Recommend 1-2 specific next investigative steps

Be specific — reference actual numbers, IPs, and SNI names. Do not just restate the raw numbers; interpret what they mean operationally."""


def generate_summary(report: dict) -> Optional[str]:
    """Generate a plain-English AI diagnosis. Returns None if ANTHROPIC_API_KEY is not set."""
    if not os.environ.get("ANTHROPIC_API_KEY"):
        return None

    try:
        import anthropic
    except ImportError:
        return None

    client = anthropic.Anthropic()

    # Trim to control token usage while keeping all diagnostically useful fields
    compact = {
        "pcap_filename": report.get("pcap_filename"),
        "capture_duration_s": report.get("capture_duration_s"),
        "total_packets": report.get("total_packets"),
        "filters_applied": report.get("filters_applied"),
        "summary": report.get("summary"),
        "flows": (report.get("flows") or [])[:20],
        "disruption_timeline": (report.get("disruption_timeline") or [])[:60],
    }

    response = client.messages.create(
        model="claude-opus-4-7",
        max_tokens=1024,
        thinking={"type": "adaptive"},
        system=[{
            "type": "text",
            "text": SYSTEM_PROMPT,
            "cache_control": {"type": "ephemeral"},
        }],
        messages=[{
            "role": "user",
            "content": f"Diagnose this PCAP analysis report:\n\n```json\n{json.dumps(compact, indent=2)}\n```",
        }],
    )

    for block in response.content:
        if block.type == "text":
            return block.text
    return None
