"""MCP stdio gateway for agent-gate.

Sits between an MCP client (Claude Code, Cursor, Codex, ...) and an MCP
server process. Every `tools/call` request is checked against the policy
before it reaches the server:

  allow -> request is forwarded to the server, response passes through
  deny  -> a JSON-RPC error is returned to the client, the server never
           sees the call

Messages are JSON-RPC 2.0 lines over stdio. All other methods
(initialize, tools/list, notifications) are forwarded untouched.
"""

import json
import subprocess
import sys
import threading

from .engine import Engine
from . import tokens as tk

def run_proxy(policy_path, secret, audit_path, role, token, server_cmd):
    engine = Engine(policy_path, secret, audit_path)
    proc = subprocess.Popen(
        server_cmd,
        shell=True,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=sys.stderr,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    out_lock = threading.Lock()
    pending = {}
    pending_lock = threading.Lock()

    def server_to_client():
        try:
            for line in proc.stdout:
                try:
                    msg = json.loads(line)
                except json.JSONDecodeError:
                    msg = None
                if isinstance(msg, dict) and "id" in msg:
                    with pending_lock:
                        method = pending.get(msg.get("id"))
                    if method == "tools/list" and "result" in msg:
                        msg = _filter_tools_list(msg, engine, role)
                        line = json.dumps(msg, ensure_ascii=True)
                with out_lock:
                    sys.stdout.write(line + "\n")
                    sys.stdout.flush()
        except Exception:
            pass

    threading.Thread(target=server_to_client, daemon=True).start()

    try:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            if _intercept(msg, engine, role, token, out_lock):
                continue
            if isinstance(msg, dict) and msg.get("id") is not None:
                with pending_lock:
                    pending[msg.get("id")] = msg.get("method")
            proc.stdin.write(line + "\n")
            proc.stdin.flush()
    except (KeyboardInterrupt, BrokenPipeError):
        pass
    finally:
        try:
            proc.terminate()
        except Exception:
            pass
    return 0

def _filter_tools_list(msg, engine, role):
    """Trim the server's tool manifest to what the role may call.

    Least-discoverability: an agent cannot call a tool it cannot see.
    If the role is None (token-based gateway) the manifest is passed
    through unchanged.
    """
    result = msg.get("result")
    tools = (result or {}).get("tools")
    if not isinstance(tools, list) or role is None:
        return msg
    role_obj = engine.policy.get_role(role)
    if role_obj is None:
        return msg
    kept = [t for t in tools
            if isinstance(t, dict) and role_obj.match_tool(t.get("name", "")) is not None]
    msg["result"]["tools"] = kept
    return msg

    def reply(msg):
        with out_lock:
            sys.stdout.write(json.dumps(msg, ensure_ascii=True) + "\n")
            sys.stdout.flush()

    try:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(msg, dict) or msg.get("id") is None:
                continue
            method = msg.get("method")
            params = msg.get("params") or {}
            rid = msg.get("id")
            if method == "tools/list":
                reply({"jsonrpc": "2.0", "id": rid,
                       "result": router.aggregate_tools_list()["result"]})
            elif method == "tools/call":
                tool = params.get("name")
                arguments = params.get("arguments") or {}
                try:
                    if token:
                        decision = engine.check_token(token, tool, arguments)
                    else:
                        decision = engine.check(role, tool, arguments)
                except tk.TokenError as exc:
                    reply({"jsonrpc": "2.0", "id": rid,
                           "error": {"code": -32602, "message": str(exc)}})
                    continue
                if not decision.allowed:
                    reply({"jsonrpc": "2.0", "id": rid,
                           "error": {"code": -32602,
                                     "message": "denied by policy: %s" % decision.reason}})
                    continue
                conn = router.route(tool)
                if conn is None:
                    reply({"jsonrpc": "2.0", "id": rid,
                           "error": {"code": -32602,
                                     "message": "no server matches tool %r" % tool}})
                    continue
                resp = router.rpc(conn, "tools/call", params)
                resp["id"] = rid  # respond with the client's request id
                reply(resp)
            elif method == "initialize":
                first = next(iter(router._conns.values()), None)
                if first is not None:
                    resp = router.rpc(first, "initialize", params)
                    resp["id"] = rid
                    reply(resp)
            else:
                reply({"jsonrpc": "2.0", "id": rid,
                       "error": {"code": -32601, "message": "method not found: %s" % method}})
    except (KeyboardInterrupt, BrokenPipeError):
        pass
    finally:
        router.close()
    return 0

def _intercept(msg, engine, role, token, out_lock):
    """Return True if the message was handled locally (denied)."""
    if not isinstance(msg, dict) or msg.get("method") != "tools/call":
        return False
    params = msg.get("params") or {}
    name = params.get("name")
    arguments = params.get("arguments") or {}
    rid = msg.get("id")
    try:
        if token:
            decision = engine.check_token(token, name, arguments)
        else:
            decision = engine.check(role, name, arguments)
    except tk.TokenError as exc:
        _reply_error(rid, "credential rejected: %s" % exc, out_lock)
        return True
    if decision.allowed:
        return False
    _reply_error(rid, "denied by policy: %s" % decision.reason, out_lock)
    return True

def _reply_error(rid, message, out_lock):
    error = {
        "jsonrpc": "2.0",
        "id": rid,
        "error": {"code": -32602, "message": message},
    }
    with out_lock:
        sys.stdout.write(json.dumps(error, ensure_ascii=True) + "\n")
        sys.stdout.flush()
