"""JSON-lines audit trail for agent-gate.

Every tool-call decision is appended as one JSON object per line. Sensitive
parameter values (passwords, tokens, api keys, ...) are masked before
writing so secrets never reach the log. The log is append-only and
thread-safe.
"""

import json
import threading
import time
import uuid

SENSITIVE_KEYS = frozenset({
    "password", "passwd", "pwd", "secret", "token", "api_key", "apikey",
    "access_key", "authorization", "cookie", "private_key",
})

MASKED = "***"

# Values longer than this are truncated in logs/output so a huge payload
# (e.g. a multi-megabyte file content) cannot flood the audit trail.
MAX_STRING = 200


def request_id():
    return uuid.uuid4().hex[:12]


def _mask_value(key, value, sensitive):
    if isinstance(value, dict):
        return mask_params(value, sensitive)
    if isinstance(value, (list, tuple)):
        return [_mask_value(key, v, sensitive) for v in value]
    if key.lower() in sensitive:
        return MASKED
    if isinstance(value, str) and len(value) > MAX_STRING:
        return "%s...(%d bytes)" % (value[:MAX_STRING], len(value))
    return value


def mask_params(params, keys=None):
    """Return a copy of params with sensitive values masked and oversized
    strings truncated."""
    sensitive = set(SENSITIVE_KEYS) | set(keys or [])
    if not isinstance(params, dict):
        return params
    return {key: _mask_value(key, value, sensitive)
            for key, value in params.items()}


class AuditLogger:
    """Append-only JSON-lines logger with a mutex."""

    def __init__(self, path):
        self.path = path
        self._lock = threading.Lock()

    def log(self, entry):
        entry = dict(entry)
        entry.setdefault("ts", time.strftime("%Y-%m-%dT%H:%M:%S%z"))
        entry.setdefault("request_id", request_id())
        line = json.dumps(entry, ensure_ascii=False, sort_keys=True)
        with self._lock:
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        return entry["request_id"]

    def tail(self, limit=100, request_id=None, decision=None, role=None, tool=None):
        """Read recent entries (newest first) with optional filters."""
        entries = []
        with self._lock:
            try:
                with open(self.path, "r", encoding="utf-8") as fh:
                    for line in fh:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            entries.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
            except FileNotFoundError:
                return []
        if request_id:
            entries = [e for e in entries if e.get("request_id") == request_id]
        if decision:
            entries = [e for e in entries if e.get("decision") == decision]
        if role:
            entries = [e for e in entries if e.get("role") == role]
        if tool:
            entries = [e for e in entries if e.get("tool") == tool]
        entries.reverse()
        return entries[:limit]
