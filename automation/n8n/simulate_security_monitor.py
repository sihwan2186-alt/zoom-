#!/usr/bin/env python3
"""Simulate the n8n Mediasoup security monitor scoring logic.

This helper does not contact n8n. It mirrors the workflow's risk scoring so the
research artifact can be validated without starting Docker.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SEVERITY_WEIGHT = {
    "critical": 90,
    "high": 70,
    "medium": 45,
    "low": 20,
    "informational": 5,
}


def normalize_string(value: Any, max_length: int = 128) -> str | None:
    if value is None:
        return None
    return str(value)[:max_length]


def bounded_number(value: Any, max_value: int = 10000) -> int | float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0
    if number < 0:
        return 0
    return min(number, max_value)


def parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    normalized = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


def score_event(body: dict[str, Any]) -> dict[str, Any]:
    raw_severity = str(body.get("severity", "informational")).lower()
    severity = raw_severity if raw_severity in SEVERITY_WEIGHT else "informational"
    raw_signals = body.get("signals") or {}

    event = {
        "source": normalize_string(body.get("source", "unknown")),
        "eventType": normalize_string(body.get("eventType", "unknown")),
        "roomId": normalize_string(body.get("roomId")),
        "participantId": normalize_string(body.get("participantId")),
        "timestamp": normalize_string(body.get("timestamp"), 64),
        "evidence": {
            "zapReport": normalize_string((body.get("evidence") or {}).get("zapReport"), 256),
            "strideReport": normalize_string((body.get("evidence") or {}).get("strideReport"), 256),
        },
        "signals": {
            "iceFailed": bounded_number(raw_signals.get("iceFailed")),
            "dtlsFailed": bounded_number(raw_signals.get("dtlsFailed")),
            "producerCount": bounded_number(raw_signals.get("producerCount")),
            "consumerCount": bounded_number(raw_signals.get("consumerCount")),
            "zapAlerts": bounded_number(raw_signals.get("zapAlerts")),
            "publicIpCandidateObserved": raw_signals.get("publicIpCandidateObserved") is True,
            "unauthorizedJoinAttempts": bounded_number(raw_signals.get("unauthorizedJoinAttempts")),
        },
    }

    score = SEVERITY_WEIGHT[severity]
    reasons: list[str] = []

    def add(condition: bool, points: int, reason: str) -> None:
        nonlocal score
        if condition:
            score += points
            reasons.append(reason)

    timestamp = parse_timestamp(event["timestamp"])
    if event["timestamp"] is not None and timestamp is None:
        add(True, 5, "Invalid event timestamp")
    if timestamp is not None:
        delta = abs((datetime.now(timezone.utc) - timestamp).total_seconds())
        add(delta > 10 * 60, 5, "Event timestamp is outside the 10 minute freshness window")

    signals = event["signals"]
    add(signals["iceFailed"] >= 3, 10, "ICE failure spike")
    add(signals["dtlsFailed"] >= 1, 10, "DTLS failure observed")
    add(signals["producerCount"] >= 10, 8, "Unexpected producer count")
    add(signals["consumerCount"] >= 80, 8, "Unexpected consumer fanout")
    add(signals["zapAlerts"] >= 4, 6, "ZAP alerts present")
    add(signals["publicIpCandidateObserved"] is True, 8, "Public IP candidate observed")
    add(signals["unauthorizedJoinAttempts"] >= 2, 10, "Repeated unauthorized join attempts")

    score = min(score, 100)
    if score >= 80:
        action = "contain: lock room, require moderator review, preserve evidence, notify security owner"
    elif score >= 60:
        action = "investigate: notify moderator and create follow-up ticket"
    else:
        action = "monitor: keep event in audit log"

    return {
        "event": event,
        "risk": {
            "severity": severity,
            "score": score,
            "reasons": reasons,
            "action": action,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "payload",
        nargs="?",
        default=Path(__file__).with_name("sample-alert.json"),
        type=Path,
        help="JSON payload file to score",
    )
    parser.add_argument("--token", default="change-me-before-demo")
    parser.add_argument("--expected-token", default="change-me-before-demo")
    args = parser.parse_args()

    body = json.loads(args.payload.read_text(encoding="utf-8"))
    if args.token != args.expected_token:
        result = {
            "security": {
                "authorized": False,
                "reason": "Invalid or missing X-Video-Security-Token header",
            },
            "risk": {
                "severity": "critical",
                "score": 0,
                "reasons": ["Webhook authentication failed"],
                "action": "reject: invalid webhook token",
            },
        }
    else:
        result = {
            "security": {
                "authorized": True,
                "tokenChecked": True,
            },
            **score_event(body),
        }
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
