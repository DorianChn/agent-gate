"""HTTP gateway for agent-gate (stdlib only).

Exposes the policy engine as a small REST API so non-MCP consumers
(custom agents, scripts, dashboards) can enforce the same policy:

  GET  /healthz            -> {"status": "ok"}
  POST /v1/check           -> {role|token, tool, params}  -> decision
  POST /v1/token/issue     -> {role, scope, ttl, constraints?} -> token
  GET  /v1/audit           -> ?limit=&tool=&decision=&request_id=

No third-party dependencies; built on http.server.
"""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional

from .audit import AuditLogger
from .engine import Engine
from . import tokens as tk


class GatewayHandler(BaseHTTPRequestHandler):
    server_version = "agent-gate/1.0"
    engine: Engine  # injected by serve()

    # ------------------------------------------------------------------
    def _send(self, status: int, payload: Dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> Optional[Dict[str, Any]]:
        try:
            length = int(self.headers.get("Content-Length") or 0)
            if length <= 0:
                return None
            raw = self.rfile.read(length).decode("utf-8")
            data = json.loads(raw)
            return data if isinstance(data, dict) else None
        except (ValueError, json.JSONDecodeError):
            return None

    def log_message(self, fmt, *args):  # keep the console quiet
        pass

    # ------------------------------------------------------------------
    def do_GET(self):  # noqa: N802 - http.server API
        if self.path == "/healthz":
            self._send(200, {"status": "ok", "service": "agent-gate"})
            return
        if self.path.startswith("/v1/audit"):
            self._handle_audit()
            return
        self._send(404, {"error": "not found"})

    def do_POST(self):  # noqa: N802 - http.server API
        if self.path == "/v1/check":
            self._handle_check()
            return
        if self.path == "/v1/token/issue":
            self._handle_issue()
            return
        self._send(404, {"error": "not found"})

    # ------------------------------------------------------------------
    def _handle_check(self) -> None:
        data = self._read_json()
        if data is None:
            self._send(400, {"error": "invalid JSON body"})
            return
        tool = data.get("tool")
        raw_params = data.get("params")
        if raw_params is None:
            params = {}
        elif not isinstance(raw_params, dict):
            self._send(400, {"error": "'params' must be an object"})
            return
        else:
            params = raw_params
        if not isinstance(tool, str) or not tool:
            self._send(400, {"error": "missing 'tool'"})
            return
        if "token" in data:
            token = data["token"]
            if not isinstance(token, str) or not token:
                self._send(400, {"error": "'token' must be a non-empty string"})
                return
            try:
                decision = self.engine.check_token(token, tool, params)
            except tk.TokenError as exc:
                self._send(401, {"allowed": False, "error": str(exc)})
                return
        elif "role" in data:
            role = data["role"]
            if not isinstance(role, str) or not role:
                self._send(400, {"error": "'role' must be a non-empty string"})
                return
            decision = self.engine.check(role, tool, params)
        else:
            self._send(400, {"error": "require 'role' or 'token'"})
            return
        self._send(200 if decision.allowed else 403, decision.to_dict(params))

    def _handle_issue(self) -> None:
        data = self._read_json()
        if data is None:
            self._send(400, {"error": "invalid JSON body"})
            return
        role = data.get("role")
        scope = data.get("scope")
        raw_ttl = data.get("ttl", 300)
        try:
            if isinstance(raw_ttl, bool) or not isinstance(raw_ttl, (int, str)):
                raise ValueError
            ttl = int(raw_ttl)
        except (TypeError, ValueError, OverflowError):
            self._send(400, {"error": "'ttl' must be an integer"})
            return
        constraints = data.get("constraints")
        if not isinstance(role, str) or not isinstance(scope, str):
            self._send(400, {"error": "require 'role' and 'scope'"})
            return
        try:
            token = tk.issue(role, scope, ttl, self.engine.secret,
                             constraints=constraints)
        except (ValueError, TypeError) as exc:
            self._send(400, {"error": str(exc)})
            return
        self._send(200, {"token": token, "constraints": constraints})

    def _handle_audit(self) -> None:
        from urllib.parse import parse_qs, urlparse

        query = parse_qs(urlparse(self.path).query)
        try:
            limit = int(query.get("limit", ["50"])[0])
        except ValueError:
            limit = 50
        entries = self.engine.audit.tail(
            limit=limit,
            request_id=query.get("request_id", [None])[0],
            decision=query.get("decision", [None])[0],
            role=query.get("role", [None])[0],
            tool=query.get("tool", [None])[0],
        )
        self._send(200, {"count": len(entries), "entries": entries})


def serve(policy_path: str, secret: str, audit_path: str,
          host: str = "127.0.0.1", port: int = 8787,
          policy_secret: Optional[str] = None, alerts=None) -> None:
    engine = Engine(policy_path, secret, audit_path,
                    policy_secret=policy_secret, alerts=alerts)
    GatewayHandler.engine = engine
    server = ThreadingHTTPServer((host, port), GatewayHandler)
    print("agent-gate HTTP gateway on http://%s:%d (audit: %s)"
          % (host, port, audit_path), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
