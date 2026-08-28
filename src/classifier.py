from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Any


RISK_LOW = "Low"
RISK_MEDIUM = "Medium"
RISK_HIGH = "High"
RISK_CRITICAL = "Critical"


class ThreatClassifier:
    """Advanced rule-based classification module (Section 4.3). No ML."""

    def __init__(self, config: dict[str, Any]) -> None:
        self.scan_threshold = int(config["scan_threshold"])
        self.time_window_seconds = int(config["time_window_seconds"])
        self.icmp_flood_threshold = int(config["icmp_flood_threshold"])
        self.brute_force_threshold = int(config["brute_force_threshold"])
        self.brute_force_keywords = [
            keyword.lower() for keyword in config["brute_force_keywords"]
        ]
        self.suspicious_host_min_signatures = int(config["suspicious_host_min_signatures"])
        self.suspicious_host_window_seconds = int(config["suspicious_host_window_seconds"])
        self.critical_priority = int(config["critical_priority"])
        self.medium_alert_threshold = int(config.get("medium_alert_threshold", 5))

        self.events_by_source: dict[str, deque[tuple[datetime, dict[str, Any]]]] = defaultdict(deque)
        self.bruteforce_pairs: dict[tuple[str, str], deque[datetime]] = defaultdict(deque)

    def classify_all(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        sorted_events = sorted(events, key=lambda item: item.get("timestamp") or "")
        return [self.classify(event) for event in sorted_events]

    def classify(self, event: dict[str, Any]) -> dict[str, Any]:
        timestamp = self._parse_timestamp(event.get("timestamp"))
        source = event.get("src_ip") or ""
        history = self.events_by_source[source]
        if timestamp is not None:
            history.append((timestamp, event))
            self._trim(history, timestamp, self.time_window_seconds)

        attack_type = self._detect_attack_type(event, timestamp, source, history)
        risk_level = self._score_risk(event, attack_type, history)

        enriched = dict(event)
        enriched["attack_type"] = attack_type or ""
        enriched["risk_level"] = risk_level
        enriched["likely_scanner"] = attack_type == "Port Scan"
        return enriched

    def _parse_timestamp(self, value: Any) -> datetime | None:
        if not value:
            return None
        text = str(value).strip()
        if text.endswith("Z"):
            text = text.replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    def _trim(self, history: deque[tuple[datetime, dict[str, Any]]], now: datetime, window: int) -> None:
        cutoff = now.timestamp() - window
        while history and history[0][0].timestamp() < cutoff:
            history.popleft()

    def _trim_pair(self, history: deque[datetime], now: datetime, window: int) -> None:
        cutoff = now.timestamp() - window
        while history and history[0].timestamp() < cutoff:
            history.popleft()

    def _detect_attack_type(
        self,
        event: dict[str, Any],
        timestamp: datetime | None,
        source: str,
        history: deque[tuple[datetime, dict[str, Any]]],
    ) -> str | None:
        message = (event.get("message") or "").lower()

        if timestamp is not None and any(keyword in message for keyword in self.brute_force_keywords):
            pair_key = (source, event.get("dst_ip") or "")
            pair_history = self.bruteforce_pairs[pair_key]
            pair_history.append(timestamp)
            self._trim_pair(pair_history, timestamp, self.time_window_seconds)
            if len(pair_history) >= self.brute_force_threshold:
                return "Brute Force"

        if event.get("protocol") in {"ICMP", "ICMPV6"}:
            icmp_count = sum(1 for _, item in history if item.get("protocol") in {"ICMP", "ICMPV6"})
            if icmp_count >= self.icmp_flood_threshold:
                return "ICMP Flood"

        if timestamp is not None:
            suspicious_history = self.events_by_source[source]
            self._trim(suspicious_history, timestamp, self.suspicious_host_window_seconds)
            if int(event.get("priority", 3)) <= self.critical_priority:
                unique_signatures = {
                    item.get("signature_id")
                    for _, item in suspicious_history
                    if item.get("signature_id") is not None
                }
                if len(unique_signatures) >= self.suspicious_host_min_signatures:
                    return "High Risk Host"

        if len(history) >= self.scan_threshold:
            return "Port Scan"

        return None

    def _score_risk(
        self,
        event: dict[str, Any],
        attack_type: str | None,
        history: deque[tuple[datetime, dict[str, Any]]],
    ) -> str:
        if attack_type == "High Risk Host":
            return RISK_CRITICAL
        if attack_type in {"Port Scan", "ICMP Flood", "Brute Force"}:
            if int(event.get("priority", 3)) <= self.critical_priority:
                return RISK_CRITICAL
            return RISK_HIGH
        if int(event.get("priority", 3)) <= self.critical_priority and attack_type:
            return RISK_CRITICAL
        if len(history) >= self.medium_alert_threshold:
            return RISK_MEDIUM
        return RISK_LOW
