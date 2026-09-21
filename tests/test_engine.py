"""Unit tests for agent-gate core modules. Run: python -m unittest -v"""

import hashlib
import hmac
import json
import os
import sys
import tempfile
import time
import unittest

from agent_gate.audit import AuditLogger, mask_params
from agent_gate.engine import Denied, Engine
from agent_gate.policy import Policy, PolicyError
from agent_gate import tokens as tk

SECRET = "test-secret"

POLICY = {
    "default_action": "deny",
    "roles": {
        "researcher": {
            "tools": {
                "file_read": {
                    "params": {
                        "path": {"pattern": r"^(/tmp/|/workspace/)"},
                        "max_bytes": {"max": 1048576},
                    }
                },
                "web_*": {},
            }
        },
        "editor": {
            "tools": {
                "file_write": {
                    "params": {
                        "path": {"pattern": r"^(/workspace/)"},
                        "content": {"max_length": 1024},
                        "overwrite": {"allowed_values": [True, False]},
                    }
                },
                "*": {},
            }
        },
        "auditor": {"tools": {"audit_query": {}}},
    },
}

def make_engine(tmp):
    return Engine(POLICY, SECRET, os.path.join(tmp, "audit.jsonl"))

class TestPolicy(unittest.TestCase):
    def test_from_dict_and_role_match(self):
        p = Policy.from_dict(POLICY)
        self.assertIn("researcher", p.role_names())
        self.assertIsNotNone(p.get_role("researcher").match_tool("file_read"))
        self.assertIsNone(p.get_role("researcher").match_tool("file_write"))

    def test_wildcard_match(self):
        p = Policy.from_dict(POLICY)
        r = p.get_role("researcher")
        self.assertIsNotNone(r.match_tool("web_search"))
        self.assertIsNotNone(r.match_tool("web_fetch"))

    def test_catch_all(self):
        p = Policy.from_dict(POLICY)
        self.assertIsNotNone(p.get_role("editor").match_tool("anything"))

    def test_bad_policy_rejected(self):
        with self.assertRaises(PolicyError):
            Policy.from_dict({"roles": {"x": {"tools": "not-a-dict"}}})
        with self.assertRaises(PolicyError):
            Policy.from_dict({"roles": {"x": {"tools": {
                "t": {"params": {"p": {"bogus_rule": 1}}}}}}})
        with self.assertRaises(PolicyError):
            Policy.from_dict({"default_action": "maybe", "roles": {}})
        with self.assertRaises(PolicyError):
            Policy.from_json("{not json")

    def test_policy_sign_verify_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "policy.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(POLICY, fh)
            Policy.sign_file(path, "sig-secret")
            p = Policy.from_file(path, secret="sig-secret")
            self.assertIsNotNone(p.get_role("researcher"))

    def test_policy_tamper_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "policy.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(POLICY, fh)
            Policy.sign_file(path, "sig-secret")
            tampered = json.loads(json.dumps(POLICY))  # deep copy
            tampered["roles"]["researcher"]["tools"]["file_delete"] = {}
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(tampered, fh)
            with self.assertRaises(PolicyError):
                Policy.from_file(path, secret="sig-secret")

    def test_policy_missing_signature_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "policy.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(POLICY, fh)
            with self.assertRaises(PolicyError):
                Policy.from_file(path, secret="sig-secret")

    def test_engine_rejects_tampered_policy_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "policy.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(POLICY, fh)
            Policy.sign_file(path, "sig-secret")
            tampered = json.loads(json.dumps(POLICY))  # deep copy
            tampered["roles"]["researcher"]["tools"]["file_delete"] = {}
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(tampered, fh)
            with self.assertRaises(PolicyError):
                Engine(path, SECRET, os.path.join(tmp, "a.jsonl"),
                       policy_secret="sig-secret")

class TestTokens(unittest.TestCase):
    def test_issue_verify_roundtrip(self):
        token = tk.issue("researcher", "file_read,web_*", 300, SECRET, now=1000)
        role, scope, constraints = tk.verify(token, SECRET, now=1000)
        self.assertEqual((role, scope), ("researcher", "file_read,web_*"))
        self.assertIsNone(constraints)

    def test_issue_with_constraints_roundtrip(self):
        token = tk.issue("researcher", "file_read", 300, SECRET,
                         constraints={"path": {"pattern": r"^/tmp/"}}, now=1000)
        role, scope, constraints = tk.verify(token, SECRET, now=1000)
        self.assertEqual(role, "researcher")
        self.assertEqual(scope, "file_read")
        self.assertEqual(constraints["path"]["pattern"], r"^/tmp/")

    def test_constraints_tamper_detected(self):
        token = tk.issue("researcher", "file_read", 300, SECRET,
                         constraints={"path": {"pattern": r"^/tmp/"}}, now=1000)
        # Replace the constraints segment with a different pattern.
        parts = token.split(".")
        parts[3] = "eyJwYXRoIjp7InBhdHRlcm4iOiJeL2V0Yy8ifX0"  # {"path":{"pattern":"^/etc/"}}
        tampered = ".".join(parts)
        with self.assertRaises(tk.InvalidTokenError):
            tk.verify(tampered, SECRET, now=1000)

    def test_malformed_constraints_raise_invalid_token(self):
        payload = "ag1.researcher.file_read.a.1300"
        signature = hmac.new(
            SECRET.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256
        ).hexdigest()

        with self.assertRaises(tk.InvalidTokenError):
            tk.verify(payload + "." + signature, SECRET, now=1000)

    def test_legacy_token_without_constraints(self):
        # A 5-part token (no constraints segment) must still verify.
        payload = "ag1.researcher.file_read.1000"
        sig = hmac.new(SECRET.encode("utf-8"), payload.encode("utf-8"),
                       hashlib.sha256).hexdigest()
        legacy = payload + "." + sig
        role, scope, constraints = tk.verify(legacy, SECRET, now=999)
        self.assertEqual((role, scope), ("researcher", "file_read"))
        self.assertIsNone(constraints)

    def test_expired(self):
        token = tk.issue("researcher", "file_read", 10, SECRET, now=1000)
        with self.assertRaises(tk.ExpiredTokenError):
            tk.verify(token, SECRET, now=1011)

    def test_tampered(self):
        token = tk.issue("researcher", "file_read", 300, SECRET, now=1000)
        role, _, _ = tk.verify(token, SECRET, now=1000)
        self.assertEqual(role, "researcher")
        # Flip a character in the role field.
        parts = token.split(".")
        parts[1] = "editor" if parts[1] == "researcher" else "researcher"
        tampered = ".".join(parts)
        with self.assertRaises(tk.InvalidTokenError):
            tk.verify(tampered, SECRET, now=1000)

    def test_wrong_secret(self):
        token = tk.issue("researcher", "file_read", 300, SECRET, now=1000)
        with self.assertRaises(tk.InvalidTokenError):
            tk.verify(token, "other-secret", now=1000)

    def test_scope_match(self):
        self.assertTrue(tk.scope_matches("file_read,web_*", "web_search"))
        self.assertFalse(tk.scope_matches("file_read", "web_search"))

class TestAudit(unittest.TestCase):
    def test_mask_params(self):
        masked = mask_params({
            "path": "/tmp/a",
            "password": "hunter2",
            "nested": {"api_key": "k", "ok": 1},
        })
        self.assertEqual(masked["password"], "***")
        self.assertEqual(masked["nested"]["api_key"], "***")
        self.assertEqual(masked["path"], "/tmp/a")
        self.assertEqual(masked["nested"]["ok"], 1)

    def test_log_and_tail(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = AuditLogger(os.path.join(tmp, "a.jsonl"))
            rid = log.log({"decision": "allow", "role": "r", "tool": "t"})
            log.log({"decision": "deny", "role": "r", "tool": "t"})
            all_ = log.tail()
            self.assertEqual(len(all_), 2)
            denied = log.tail(decision="deny")
            self.assertEqual(len(denied), 1)
            by_rid = log.tail(request_id=rid)
            self.assertEqual(len(by_rid), 1)
            self.assertEqual(by_rid[0]["decision"], "allow")

class TestEngine(unittest.TestCase):
    def test_allowed_call(self):
        with tempfile.TemporaryDirectory() as tmp:
            eng = make_engine(tmp)
            d = eng.check("researcher", "file_read", {"path": "/tmp/a.txt"})
            self.assertTrue(d.allowed)

    def test_denied_role(self):
        with tempfile.TemporaryDirectory() as tmp:
            eng = make_engine(tmp)
            d = eng.check("researcher", "file_write", {"path": "/tmp/a.txt"})
            self.assertFalse(d.allowed)
            self.assertIn("not authorized", d.reason)

    def test_denied_param(self):
        with tempfile.TemporaryDirectory() as tmp:
            eng = make_engine(tmp)
            d = eng.check("researcher", "file_read", {"path": "/etc/passwd"})
            self.assertFalse(d.allowed)
            self.assertIn("pattern", d.reason)
            d2 = eng.check("researcher", "file_read",
                           {"path": "/tmp/big", "max_bytes": 999999999})
            self.assertFalse(d2.allowed)
            self.assertIn("max", d2.reason)

    def test_unknown_role_and_tool(self):
        with tempfile.TemporaryDirectory() as tmp:
            eng = make_engine(tmp)
            self.assertFalse(eng.check("ghost", "file_read").allowed)
            self.assertFalse(eng.check("auditor", "file_read").allowed)

    def test_audit_written_with_mask(self):
        with tempfile.TemporaryDirectory() as tmp:
            eng = make_engine(tmp)
            eng.check("researcher", "file_read",
                      {"path": "/tmp/a", "password": "hunter2"})
            entries = eng.audit.tail()
            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0]["params"]["password"], "***")

    def test_token_scoped(self):
        with tempfile.TemporaryDirectory() as tmp:
            eng = make_engine(tmp)
            token = tk.issue("researcher", "file_read", 300, SECRET)
            d = eng.check_token(token, "file_read", {"path": "/tmp/a"})
            self.assertTrue(d.allowed)
            d2 = eng.check_token(token, "web_search")
            self.assertFalse(d2.allowed)
            self.assertIn("scope", d2.reason)

    def test_token_scope_deny_writes_single_audit(self):
        # Regression: a scope denial used to write an allow record followed
        # by a deny record. It must produce exactly one (deny) record.
        with tempfile.TemporaryDirectory() as tmp:
            eng = make_engine(tmp)
            token = tk.issue("researcher", "file_read", 300, SECRET)
            d = eng.check_token(token, "web_search", {"query": "x"})
            self.assertFalse(d.allowed)
            entries = eng.audit.tail()
            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0]["decision"], "deny")

    def test_token_param_constraints_enforced(self):
        with tempfile.TemporaryDirectory() as tmp:
            eng = make_engine(tmp)
            # Policy allows reading anywhere under /tmp|/workspace; the
            # credential narrows it to /tmp only.
            token = tk.issue("researcher", "file_read", 300, SECRET,
                             constraints={"path": {"pattern": r"^/tmp/"}})
            self.assertTrue(eng.check_token(token, "file_read",
                                            {"path": "/tmp/a.txt"}).allowed)
            d = eng.check_token(token, "file_read", {"path": "/workspace/a.txt"})
            self.assertFalse(d.allowed)
            self.assertIn("constraint", d.reason)

    def test_token_constraint_deny_writes_single_audit(self):
        with tempfile.TemporaryDirectory() as tmp:
            eng = make_engine(tmp)
            token = tk.issue("researcher", "file_read", 300, SECRET,
                             constraints={"max_bytes": {"max": 100}})
            d = eng.check_token(token, "file_read",
                                {"path": "/tmp/a", "max_bytes": 999})
            self.assertFalse(d.allowed)
            entries = eng.audit.tail()
            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0]["decision"], "deny")

    def test_request_id_propagates_to_audit(self):
        with tempfile.TemporaryDirectory() as tmp:
            eng = make_engine(tmp)
            eng.check("researcher", "file_read", {"path": "/tmp/a"},
                      request_id="rid-123")
            entries = eng.audit.tail(request_id="rid-123")
            self.assertEqual(len(entries), 1)

    def test_execute_enforces_and_returns(self):
        calls = []

        def handler(tool, params):
            calls.append((tool, params))
            return {"status": "ok", "path": params["path"]}

        with tempfile.TemporaryDirectory() as tmp:
            eng = make_engine(tmp)
            token = tk.issue("researcher", "file_read", 300, SECRET)
            result = eng.execute(token, "file_read", {"path": "/tmp/a"}, handler)
            self.assertEqual(result["status"], "ok")
            self.assertEqual(len(calls), 1)
            with self.assertRaises(Denied) as ctx:
                eng.execute(token, "file_read", {"path": "/etc/passwd"}, handler)
            self.assertFalse(ctx.exception.decision.allowed)
            self.assertEqual(len(calls), 1, "handler must not run on denial")

class TestProxyToolsList(unittest.TestCase):
    def test_tools_list_filtered_by_role(self):
        from agent_gate.mcp_proxy import _filter_tools_list
        from agent_gate.engine import Engine as E

        manifest = {
            "jsonrpc": "2.0",
            "id": 2,
            "result": {
                "tools": [
                    {"name": "file_read", "inputSchema": {}},
                    {"name": "file_write", "inputSchema": {}},
                    {"name": "web_search", "inputSchema": {}},
                    {"name": "web_fetch", "inputSchema": {}},
                ]
            },
        }
        with tempfile.TemporaryDirectory() as tmp:
            eng = E(POLICY, SECRET, os.path.join(tmp, "a.jsonl"))
            out = _filter_tools_list(manifest, eng, "researcher")
            names = [t["name"] for t in out["result"]["tools"]]
            # researcher: file_read + web_*; file_write must be hidden
            self.assertIn("file_read", names)
            self.assertIn("web_search", names)
            self.assertIn("web_fetch", names)
            self.assertNotIn("file_write", names)

    def test_tools_list_passthrough_without_role(self):
        from agent_gate.mcp_proxy import _filter_tools_list
        from agent_gate.engine import Engine as E

        manifest = {"jsonrpc": "2.0", "id": 3,
                    "result": {"tools": [{"name": "file_write"}]}}
        with tempfile.TemporaryDirectory() as tmp:
            eng = E(POLICY, SECRET, os.path.join(tmp, "a.jsonl"))
            out = _filter_tools_list(manifest, eng, None)
            self.assertEqual(out["result"]["tools"][0]["name"], "file_write")

class TestAlerts(unittest.TestCase):
    def test_deny_burst_rule_fires(self):
        from agent_gate.alerts import AlertRule, AlertRouter, LogAlertSink

        sink = LogAlertSink()
        router = AlertRouter(
            [AlertRule("deny_burst", decision="deny", min_occurrences=3)],
            [sink],
        )
        entry = {"decision": "deny", "tool": "file_read", "role": "r",
                 "ts": "t", "reason": "x"}
        self.assertEqual(router.feed(entry), [])
        self.assertEqual(router.feed(entry), [])
        fired = router.feed(entry)
        self.assertEqual(len(fired), 1)
        self.assertEqual(fired[0]["rule"], "deny_burst")
        # counter resets; next single deny does not fire immediately
        self.assertEqual(router.feed(entry), [])

    def test_deny_burst_requires_consecutive_matching_events(self):
        from agent_gate.alerts import AlertRule, AlertRouter

        router = AlertRouter(
            [AlertRule("deny_burst", decision="deny", min_occurrences=3)],
            [],
        )
        deny = {"decision": "deny", "tool": "file_read"}
        allow = {"decision": "allow", "tool": "file_read"}
        other_tool = {"decision": "deny", "tool": "web_fetch"}

        self.assertEqual(router.feed(deny), [])
        self.assertEqual(router.feed(allow), [])
        self.assertEqual(router.feed(deny), [])
        self.assertEqual(router.feed(deny), [])
        self.assertEqual(router.feed(other_tool), [])
        # The two earlier file_read denials were separated by non-matches;
        # neither an allow nor another tool may contribute to the burst.
        self.assertEqual(router.feed(deny), [])

    def test_webhook_sink_receives_alert(self):
        import threading as _th
        from http.server import BaseHTTPRequestHandler, HTTPServer
        from agent_gate.alerts import AlertRule, AlertRouter, WebhookAlertSink

        received = {}

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers["Content-Length"])
                received["body"] = json.loads(self.rfile.read(length))
                self.send_response(200)
                self.end_headers()

            def log_message(self, *a):
                pass

        srv = HTTPServer(("127.0.0.1", 0), Handler)
        thread = _th.Thread(target=srv.serve_forever, daemon=True)
        thread.start()

        def stop_server():
            srv.shutdown()
            thread.join(timeout=2)
            srv.server_close()

        self.addCleanup(stop_server)

        router = AlertRouter(
            [AlertRule("deny_any", decision="deny")],
            [WebhookAlertSink("http://127.0.0.1:%d/hook" % srv.server_address[1])],
        )
        router.feed({"decision": "deny", "tool": "file_read", "role": "r",
                     "ts": "t", "reason": "x", "request_id": "rid1"})
        import time as _t
        for _ in range(50):
            if received:
                break
            _t.sleep(0.05)
        self.assertIn("rule", received.get("body", {}))
        self.assertEqual(received["body"]["rule"], "deny_any")

    def test_langfuse_sink_auth_header(self):
        from agent_gate.alerts import LangfuseAlertSink

        sink = LangfuseAlertSink("https://cloud.langfuse.com", "pk", "sk")
        self.assertTrue(sink.url.startswith("https://cloud.langfuse.com/api/public/events"))
        self.assertIn("Basic ", sink.headers["Authorization"])

class TestHttpGateway(unittest.TestCase):
    def _start_server(self):
        import threading as _threading
        from agent_gate.engine import Engine as _E
        from agent_gate.http_gateway import GatewayHandler
        from http.server import ThreadingHTTPServer

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        audit_path = os.path.join(tmp.name, "audit.jsonl")
        eng = _E(POLICY, SECRET, audit_path)
        GatewayHandler.engine = eng
        srv = ThreadingHTTPServer(("127.0.0.1", 0), GatewayHandler)
        t = _threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()

        def stop_server():
            srv.shutdown()
            t.join(timeout=2)
            srv.server_close()

        self.addCleanup(stop_server)
        return srv.server_address[1]

    def _post(self, port, path, body):
        import http.client

        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        raw = json.dumps(body).encode("utf-8")
        conn.request("POST", path, body=raw,
                     headers={"Content-Type": "application/json"})
        resp = conn.getresponse()
        data = json.loads(resp.read().decode("utf-8"))
        conn.close()
        return resp.status, data

    def test_healthz(self):
        import http.client

        port = self._start_server()
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", "/healthz")
        resp = conn.getresponse()
        self.assertEqual(resp.status, 200)
        conn.close()

    def test_check_allow_and_deny(self):
        port = self._start_server()
        status, data = self._post(port, "/v1/check",
                                  {"role": "researcher", "tool": "file_read",
                                   "params": {"path": "/tmp/a"}})
        self.assertEqual(status, 200)
        self.assertTrue(data["allowed"])
        status, data = self._post(port, "/v1/check",
                                  {"role": "researcher", "tool": "file_read",
                                   "params": {"path": "/etc/passwd"}})
        self.assertEqual(status, 403)
        self.assertFalse(data["allowed"])

    def test_token_issue_and_check(self):
        port = self._start_server()
        status, data = self._post(port, "/v1/token/issue",
                                  {"role": "researcher", "scope": "file_read",
                                   "ttl": 300})
        self.assertEqual(status, 200)
        token = data["token"]
        status, data = self._post(port, "/v1/check",
                                  {"token": token, "tool": "file_read",
                                   "params": {"path": "/tmp/a"}})
        self.assertEqual(status, 200)
        self.assertTrue(data["allowed"])

    def test_audit_endpoint(self):
        import http.client

        port = self._start_server()
        self._post(port, "/v1/check",
                   {"role": "researcher", "tool": "file_read",
                    "params": {"path": "/tmp/a"}})
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", "/v1/audit?limit=10&tool=file_read")
        resp = conn.getresponse()
        data = json.loads(resp.read().decode("utf-8"))
        conn.close()
        self.assertEqual(resp.status, 200)
        self.assertGreaterEqual(data["count"], 1)

