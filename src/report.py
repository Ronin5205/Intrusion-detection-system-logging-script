from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from src.utils import ensure_directory


def write_summary(path: Path, events: list[dict[str, Any]]) -> None:
    ensure_directory(path.parent)

    risk_counts = Counter(event.get("risk_level", "Low") for event in events)
    attack_counts = Counter(
        event.get("attack_type") for event in events if event.get("attack_type")
    )
    top_sources = Counter(
        event.get("src_ip") for event in events if event.get("src_ip")
    ).most_common(5)

    lines = [
        "Snort Alert Analysis Summary",
        "============================",
        "",
        f"Total Alerts: {len(events)}",
        f"Critical: {risk_counts.get('Critical', 0)}",
        f"High: {risk_counts.get('High', 0)}",
        f"Medium: {risk_counts.get('Medium', 0)}",
        f"Low: {risk_counts.get('Low', 0)}",
        "",
    ]

    if attack_counts:
        lines.append("Detected Attack Types")
        for attack_type, count in attack_counts.most_common():
            lines.append(f"- {attack_type}: {count}")
        lines.append("")

    if top_sources:
        lines.append("Top Source IPs")
        for ip, count in top_sources:
            lines.append(f"- {ip}: {count} alerts")
        lines.append("")

    path.write_text("\n".join(lines).strip() + "\n", encoding="utf-8")
