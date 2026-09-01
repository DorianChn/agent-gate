"""Alerting for agent-gate (stdlib only).

Watches the audit stream for suspicious patterns — repeated denials,
sensitive-tool attempts, credential failures — and pushes alerts to sinks
(log line, generic webhook, Langfuse events API).

Rules are pure predicates over audit entries with an occurrence counter:

  Rule(tool="file_read", decision="deny", min_occurrences=3)
    fires when the same tool is denied 3 times in a row.

Sinks must not raise: delivery is best-effort and failures are swallowed
so alerting never breaks policy enforcement.
"""

from __future__ import annotations

import base64
import json
import threading
import time
import urllib.request
from typing import Any, Callable, Dict, List, Optional


class AlertRule:
    __slots__ = ("name", "tool", "decision", "role", "min_occurrences",
                 "cooldown_seconds")

    def __init__(self, name, tool=None, decision=None, role=None,
                 min_occurrences=1, cooldown_seconds=0):
        self.name = name
        self.tool = tool
        self.decision = decision
        self.role = role
        self.min_occurrences = max(1, int(min_occurrences))
        self.cooldown_seconds = cooldown_seconds

    def matches(self, entry: Dict[str, Any]) -> bool:
        if self.tool is not None and entry.get("tool") != self.tool:
            return False
        if self.decision is not None and entry.get("decision") != self.decision:
            return False
        if self.role is not None and entry.get("role") != self.role:
            return False
        return True


def default_rules() -> List[AlertRule]:
    """Sane defaults: any denial, plus a burst detector per tool."""
    return [
        AlertRule("deny_any", decision="deny", min_occurrences=1),
        AlertRule("deny_burst", decision="deny", min_occurrences=3,
                  cooldown_seconds=60),
    ]


class AlertSink:
    def emit(self, alert: Dict[str, Any]) -> None:
        raise NotImplementedError


class LogAlertSink(AlertSink):
    def __init__(self, stream=None):
        import sys

        self._stream = stream or sys.stderr

    def emit(self, alert):
        self._stream.write("[agent-gate][alert] %s\n"
                           % json.dumps(alert, ensure_ascii=False, sort_keys=True))
        self._stream.flush()


class WebhookAlertSink(AlertSink):
    """POST the alert as JSON to a webhook URL (best effort, 3s timeout)."""

    def __init__(self, url: str, headers: Optional[Dict[str, str]] = None,
                 timeout: float = 3.0):
        self.url = url
        self.headers = headers or {}
        self.timeout = timeout

    def emit(self, alert):
        try:
            req = urllib.request.Request(
                self.url,
                data=json.dumps(alert, ensure_ascii=False).encode("utf-8"),
                headers={"Content-Type": "application/json", **self.headers},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=self.timeout):
                pass
        except Exception:
            pass  # best effort


class LangfuseAlertSink(AlertSink):
    """Forward alerts to a Langfuse deployment's events API.

    POST {base_url}/api/public/events with basic auth
    (public_key : secret_key) and the alert as metadata. See
    https://langfuse.com/docs/api for the exact schema; this sink is a
    minimal integration point and may need adjustment for your version.
    """

    def __init__(self, base_url: str, public_key: str, secret_key: str,
                 timeout: float = 3.0):
        self.url = base_url.rstrip("/") + "/api/public/events"
        token = base64.b64encode(("%s:%s" % (public_key, secret_key)).encode("utf-8"))
        self.headers = {
            "Authorization": "Basic " + token.decode("ascii"),
            "Content-Type": "application/json",
        }
        self.timeout = timeout

    def emit(self, alert):
        try:
            body = {
                "name": alert.get("rule", "agent-gate.alert"),
                "timestamp": alert.get("ts"),
                "metadata": alert,
            }
            req = urllib.request.Request(
                self.url,
                data=json.dumps(body).encode("utf-8"),
                headers=self.headers,
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=self.timeout):
                pass
        except Exception:
            pass  # best effort


class AlertRouter:
    """Feeds audit entries into rules and fans out alerts to sinks."""

    def __init__(self, rules: List[AlertRule], sinks: List[AlertSink]):
        self.rules = rules
        self.sinks = sinks
        self._counters: Dict[str, int] = {}
        self._cooldown_until: Dict[str, float] = {}
        self._lock = threading.Lock()

    def feed(self, entry: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Evaluate one audit entry. Returns the alerts that fired."""
        fired: List[Dict[str, Any]] = []
        with self._lock:
            now = time.time()
            for rule in self.rules:
                if not rule.matches(entry):
                    continue
                key = "%s:%s" % (rule.name, entry.get("tool", ""))
                self._counters[key] = self._counters.get(key, 0) + 1
                if self._counters[key] < rule.min_occurrences:
                    continue
                if self._cooldown_until.get(key, 0) > now:
                    continue
                self._counters[key] = 0
                self._cooldown_until[key] = now + rule.cooldown_seconds
                alert = {
                    "rule": rule.name,
                    "ts": entry.get("ts"),
                    "tool": entry.get("tool"),
                    "decision": entry.get("decision"),
                    "role": entry.get("role"),
                    "request_id": entry.get("request_id"),
                    "reason": entry.get("reason"),
                }
                fired.append(alert)
                for sink in self.sinks:
                    try:
                        sink.emit(alert)
                    except Exception:
                        pass
        return fired


def build_router(alert_url: Optional[str] = None,
                 langfuse: Optional[Dict[str, str]] = None,
                 rules: Optional[List[AlertRule]] = None,
                 quiet: bool = False) -> Optional[AlertRouter]:
    """Build an AlertRouter from CLI-style options, or None if disabled.

    ``langfuse``: {"base_url", "public_key", "secret_key"}.
    ``quiet``: do not add the log sink (for tests / automation).
    """
    sinks: List[AlertSink] = []
    if not quiet:
        sinks.append(LogAlertSink())
    if alert_url:
        sinks.append(WebhookAlertSink(alert_url))
    if langfuse:
        sinks.append(LangfuseAlertSink(
            langfuse["base_url"], langfuse["public_key"], langfuse["secret_key"]))
    if not sinks:
        return None
    return AlertRouter(rules or default_rules(), sinks)
