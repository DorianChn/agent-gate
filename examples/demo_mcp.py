"""End-to-end demo: MCP client -> agent-gate proxy -> mock MCP server.

Shows the gateway intercepting `tools/call`: allowed calls reach the
server, denied calls never do and get a JSON-RPC error instead.

Usage:  python3 examples/demo_mcp.py
"""

import json
import os
import queue
import subprocess
import sys
import tempfile
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


class McpClient:
    def __init__(self, cmd):
        self.proc = subprocess.Popen(
            cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            text=True, encoding="utf-8", errors="replace",
        )
        self.q = queue.Queue()
        self._rid = 0
        threading.Thread(target=self._reader, daemon=True).start()

    def _reader(self):
        try:
            for line in self.proc.stdout:
                line = line.strip()
                if not line:
                    continue
                try:
                    self.q.put(json.loads(line))
                except json.JSONDecodeError:
                    continue
        except Exception:
            pass

    def send(self, method, params=None, timeout=10):
        self._rid += 1
        rid = self._rid
        self.proc.stdin.write(json.dumps({
            "jsonrpc": "2.0", "id": rid, "method": method,
            "params": params or {},
        }) + "\n")
        self.proc.stdin.flush()
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                msg = self.q.get(timeout=0.3)
            except queue.Empty:
                continue
            if msg.get("id") == rid:
                return msg
        return {"error": {"message": "timeout"}}

    def close(self):
        try:
            self.proc.terminate()
        except Exception:
            pass


def call(client, name, arguments, expect):
    resp = client.send("tools/call", {"name": name, "arguments": arguments})
    ok = "result" in resp
    status = "ALLOWED" if ok else "DENIED"
    marker = "ok" if ok == expect else "UNEXPECTED"
    print("  [%s] %-5s %s %s -> %s" % (
        marker, status, name, json.dumps(arguments, ensure_ascii=False), marker))
    if ok:
        print("        server result: %s" % json.dumps(
            resp["result"], ensure_ascii=False)[:120])
    else:
        print("        gateway error: %s" % resp["error"]["message"])
    return ok


def main():
    os.chdir(ROOT)
    audit_path = os.path.join(tempfile.mkdtemp(), "audit.jsonl")
    py = sys.executable
    server_cmd = '"%s" examples/mock_server.py' % py
    proxy_cmd = [
        py, "-m", "agent_gate.cli", "proxy",
        "--policy", "examples/policy.json",
        "--secret", "demo-secret",
        "--audit", audit_path,
        "--role", "researcher",
        "--server-cmd", server_cmd,
    ]
    print("== MCP gateway demo: client -> agent-gate proxy -> mock server")
    print("   gateway role: researcher (file_read under /tmp|/workspace, web_*)")
    print("   audit log:    %s" % audit_path)
    print()

    client = McpClient(proxy_cmd)
    try:
        init = client.send("initialize", {"protocolVersion": "2025-06-18",
                                          "capabilities": {},
                                          "clientInfo": {"name": "demo", "version": "1"}})
        print("[1] initialize -> %s" % json.dumps(
            init.get("result", init.get("error")), ensure_ascii=False)[:100])
        listed = client.send("tools/list")
        tools = listed.get("result", {}).get("tools", [])
        print("[2] tools/list -> %d tools exposed by the server" % len(tools))
        print()

        print("[3] tools/call policy enforcement:")
        call(client, "file_read", {"path": "/tmp/report.txt"}, True)
        call(client, "file_read", {"path": "/etc/passwd"}, False)
        call(client, "web_search", {"query": "agent security"}, True)
        call(client, "file_write", {"path": "/workspace/x.txt",
                                    "content": "pwned"}, False)
        print()

        from agent_gate.audit import AuditLogger
        entries = AuditLogger(audit_path).tail(limit=10)
        print("[4] audit trail written by the gateway (%d entries):" % len(entries))
        for e in entries:
            print("    %s  %-6s  role=%s  tool=%-10s  %s" % (
                e["ts"][11:19], e["decision"], e["role"], e["tool"], e["reason"]))
    finally:
        client.close()


if __name__ == "__main__":
    main()
