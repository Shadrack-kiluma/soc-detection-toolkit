"""Explainable detections for normalized authentication events."""
from __future__ import annotations

from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from typing import Any

REQUIRED_FIELDS = ("timestamp", "username", "source_ip", "outcome")

RULES = {
    "AUTH-001": {
        "title": "Authentication burst from one source",
        "severity": "medium",
        "triage": [
            "Check whether the source is a shared VPN, proxy, or NAT egress.",
            "Review adjacent authentication events for successful logins and targeted accounts.",
            "Check rate limiting, MFA coverage, and identity-provider lockout telemetry.",
        ],
    },
    "AUTH-002": {
        "title": "Repeated failures against one account",
        "severity": "medium",
        "triage": [
            "Confirm the account owner through an approved channel.",
            "Review failures across all source addresses and identity-provider logs.",
            "Look for password reset, MFA fatigue, or session creation events nearby.",
        ],
    },
    "AUTH-003": {
        "title": "Possible password spray",
        "severity": "high",
        "triage": [
            "Check whether the source is expected infrastructure before treating it as hostile.",
            "Review targeted accounts for successful authentication and MFA events.",
            "Correlate against endpoint, VPN, and identity-provider telemetry; preserve relevant logs.",
        ],
    },
    "AUTH-004": {
        "title": "Successful login after repeated failures",
        "severity": "high",
        "triage": [
            "Validate the login with the account owner and identity-provider sign-in details.",
            "Review the resulting session, MFA result, device, and actions taken.",
            "Follow your incident process if the success is unauthorized; do not rely on this alert alone.",
        ],
    },
}


def parse_timestamp(value: str) -> datetime:
    """Parse ISO-8601 timestamps; timezone-naive values are interpreted as UTC."""
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise ValueError(f"invalid ISO-8601 timestamp {value!r}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _normalize(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized = []
    for index, event in enumerate(events, start=1):
        if not isinstance(event, dict):
            raise ValueError(f"event {index} must be a JSON object")
        missing = [key for key in REQUIRED_FIELDS if event.get(key) is None or str(event.get(key)).strip() == ""]
        if missing:
            raise ValueError(f"event {index} is missing required fields: {', '.join(missing)}")
        outcome = str(event["outcome"]).strip().lower()
        if outcome not in {"failure", "success"}:
            raise ValueError(f"event {index} has unsupported outcome {event['outcome']!r}; use failure or success")
        username = str(event["username"]).strip()
        source = str(event["source_ip"]).strip()
        try:
            source = str(ip_address(source))
        except ValueError as exc:
            raise ValueError(f"event {index} has invalid source_ip {source!r}") from exc
        timestamp = str(event["timestamp"]).strip()
        parsed_time = parse_timestamp(timestamp)
        normalized.append({
            **event,
            "username": username,
            "source_ip": source,
            "outcome": outcome,
            "_time": parsed_time,
            "_timestamp": parsed_time.isoformat().replace("+00:00", "Z"),
            "_input_order": index,
        })
    return sorted(normalized, key=lambda event: (event["_time"], event["_input_order"]))


def _finding(rule_id: str, *, timestamp: str, source_ip: str, username: str,
             event_count: int, window_minutes: int, evidence: list[str]) -> dict[str, Any]:
    rule = RULES[rule_id]
    return {
        "rule_id": rule_id,
        "severity": rule["severity"],
        "title": rule["title"],
        "timestamp": timestamp,
        "source_ip": source_ip,
        "username": username,
        "event_count": event_count,
        "window_minutes": window_minutes,
        "evidence": evidence,
        "recommended_triage": rule["triage"],
    }


def analyze(
    events: list[dict[str, Any]], *, failure_threshold: int = 5,
    window_minutes: int = 10, spray_account_threshold: int = 8,
    spray_max_attempts_per_account: int = 2,
) -> dict[str, Any]:
    """Analyze authentication events and return deterministic, explainable findings."""
    if failure_threshold < 2:
        raise ValueError("failure_threshold must be at least 2")
    if window_minutes < 1:
        raise ValueError("window_minutes must be at least 1")
    if spray_account_threshold < 3:
        raise ValueError("spray_account_threshold must be at least 3")
    if spray_max_attempts_per_account < 1:
        raise ValueError("spray_max_attempts_per_account must be at least 1")

    ordered = _normalize(events)
    window = timedelta(minutes=window_minutes)
    by_source: dict[str, deque[dict[str, Any]]] = defaultdict(deque)
    by_user: dict[str, deque[dict[str, Any]]] = defaultdict(deque)
    findings: list[dict[str, Any]] = []
    emitted_source_burst: set[str] = set()
    emitted_user_burst: set[str] = set()
    emitted_spray: set[str] = set()

    for event in ordered:
        timestamp = event["_time"]
        user = event["username"]
        source = event["source_ip"]
        if event["outcome"] == "failure":
            source_events = by_source[source]
            source_events.append(event)
            while source_events and timestamp - source_events[0]["_time"] > window:
                source_events.popleft()

            user_events = by_user[user]
            user_events.append(event)
            while user_events and timestamp - user_events[0]["_time"] > window:
                user_events.popleft()

            if len(source_events) >= failure_threshold and source not in emitted_source_burst:
                emitted_source_burst.add(source)
                accounts = sorted({item["username"] for item in source_events})
                findings.append(_finding(
                    "AUTH-001", timestamp=event["_timestamp"], source_ip=source,
                    username=user, event_count=len(source_events), window_minutes=window_minutes,
                    evidence=[f"{len(source_events)} failures from this source in {window_minutes} minutes.",
                              f"Distinct accounts in burst: {', '.join(accounts[:8])}."],
                ))

            if len(user_events) >= failure_threshold and user not in emitted_user_burst:
                emitted_user_burst.add(user)
                sources = sorted({item["source_ip"] for item in user_events})
                findings.append(_finding(
                    "AUTH-002", timestamp=event["_timestamp"], source_ip=source,
                    username=user, event_count=len(user_events), window_minutes=window_minutes,
                    evidence=[f"{len(user_events)} failures against this account in {window_minutes} minutes.",
                              f"Distinct source addresses: {', '.join(sources[:8])}."],
                ))

            counts = Counter(item["username"] for item in source_events)
            spray_accounts = sorted(counts)
            if (len(spray_accounts) >= spray_account_threshold
                    and all(count <= spray_max_attempts_per_account for count in counts.values())
                    and source not in emitted_spray):
                emitted_spray.add(source)
                findings.append(_finding(
                    "AUTH-003", timestamp=event["_timestamp"], source_ip=source,
                    username="multiple accounts", event_count=len(source_events), window_minutes=window_minutes,
                    evidence=[f"One source attempted {len(spray_accounts)} distinct accounts in {window_minutes} minutes.",
                              f"No targeted account exceeded {spray_max_attempts_per_account} failures in the window.",
                              f"Accounts observed: {', '.join(spray_accounts[:12])}."],
                ))
        else:
            prior = [item for item in by_user[user] if timedelta(0) <= timestamp - item["_time"] <= window]
            if len(prior) >= failure_threshold:
                findings.append(_finding(
                    "AUTH-004", timestamp=event["_timestamp"], source_ip=source,
                    username=user, event_count=len(prior), window_minutes=window_minutes,
                    evidence=[f"A successful login followed {len(prior)} failures against this account within {window_minutes} minutes.",
                              f"Success source: {source}."],
                ))

    findings.sort(key=lambda item: (item["timestamp"], item["rule_id"], item["username"]))
    return {
        "tool": "SOC Detection Toolkit",
        "events_analyzed": len(ordered),
        "findings_count": len(findings),
        "findings": findings,
        "disclaimer": "A detection is a triage lead, not proof of compromise. Validate against trusted telemetry and local context.",
    }



