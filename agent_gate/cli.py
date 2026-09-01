"""Command-line interface for agent-gate.

Commands:
  check    evaluate one tool call (with or without a credential)
  token    issue / verify short-lived scoped credentials
  audit    inspect the audit trail
  proxy    run the MCP stdio gateway (see mcp_proxy.py)

Exit codes: 0 = allowed, 1 = denied/error, 2 = usage error.
"""

import argparse
import json
import sys

from .audit import AuditLogger, request_id as new_request_id
from .engine import Denied, Engine
from . import tokens as tk

def _out(obj):
    print(json.dumps(obj, ensure_ascii=True, sort_keys=True))
    sys.stdout.flush()

def cmd_check(args):
    engine = Engine(args.policy, args.secret, args.audit)
    params = {}
    if args.params_file:
        with open(args.params_file, "r", encoding="utf-8") as fh:
            params = json.load(fh)
    elif args.params:
        params = json.loads(args.params)
    rid = args.request_id or new_request_id()
    try:
        if args.token:
            decision = engine.check_token(args.token, args.tool, params,
                                          request_id=rid)
        else:
            decision = engine.check(args.role, args.tool, params,
                                    request_id=rid)
    except tk.TokenError as exc:
        _out({"allowed": False, "error": str(exc)})
        return 1
    _out(decision.to_dict(params))
    return 0 if decision.allowed else 1

def cmd_token(args):
    if args.command == "token-issue":
        constraints = None
        if getattr(args, "constraints_file", None):
            with open(args.constraints_file, "r", encoding="utf-8") as fh:
                constraints = json.load(fh)
        elif getattr(args, "constraint", None):
            constraints = json.loads(args.constraint)
        token = tk.issue(args.role, args.scope, args.ttl, args.secret,
                         constraints=constraints)
        _out({"token": token, "constraints": constraints})
        return 0
    # token-verify
    try:
        role, scope, constraints = tk.verify(args.token, args.secret)
    except tk.TokenError as exc:
        _out({"valid": False, "error": str(exc)})
        return 1
    _out({"valid": True, "role": role, "scope": scope,
          "constraints": constraints})
    return 0

def cmd_policy(args):
    from .policy import Policy
    if args.action == "sign":
        sig_path = Policy.sign_file(args.policy, args.secret)
        _out({"action": "sign", "policy": args.policy, "signature_file": sig_path})
        return 0
    # verify
    try:
        Policy.verify_file(args.policy, args.secret)
    except Exception as exc:  # PolicyError and OSError alike
        _out({"action": "verify", "valid": False, "error": str(exc)})
        return 1
    _out({"action": "verify", "valid": True, "policy": args.policy})
    return 0

def cmd_audit(args):
    entries = AuditLogger(args.log).tail(
        limit=args.limit, request_id=args.request_id,
        decision=args.decision, role=args.role, tool=args.tool,
    )
    _out({"count": len(entries), "entries": entries})
    return 0

def cmd_proxy(args):
    from .mcp_proxy import run_proxy
    return run_proxy(
        policy_path=args.policy,
        secret=args.secret,
        audit_path=args.audit,
        role=args.role,
        token=args.token,
        server_cmd=args.server_cmd,
    )

def build_parser():
    parser = argparse.ArgumentParser(
        prog="agent-gate",
        description="Tool-call policy gateway for AI agents",
    )
    sub = parser.add_subparsers(dest="command")

    p_check = sub.add_parser("check", help="evaluate one tool call")
    p_check.add_argument("--policy", required=True, help="path to policy JSON")
    p_check.add_argument("--secret", required=True, help="HMAC secret")
    p_check.add_argument("--audit", default="audit.jsonl", help="audit log path")
    p_check.add_argument("--role", help="role name (used when no token)")
    p_check.add_argument("--token", help="short-lived credential (optional)")
    p_check.add_argument("--tool", required=True, help="tool name")
    p_check.add_argument("--params", default=None,
                         help="tool params as JSON, e.g. '{\"path\": \"/tmp/a.txt\"}'")
    p_check.add_argument("--params-file", default=None,
                         help="read tool params from a JSON file (for large payloads)")
    p_check.add_argument("--request-id", default=None,
                         help="correlate this call in the audit trail (auto-generated if omitted)")
    p_check.set_defaults(func=cmd_check)

    p_issue = sub.add_parser("token-issue", help="issue a short-lived credential")
    p_issue.add_argument("--secret", required=True)
    p_issue.add_argument("--role", required=True)
    p_issue.add_argument("--scope", required=True,
                         help="comma-separated tool patterns, e.g. 'file_read,web_*'")
    p_issue.add_argument("--ttl", type=int, default=300, help="lifetime in seconds")
    p_issue.add_argument("--constraint", default=None,
                         help="JSON object of per-parameter rules, e.g. "
                              "'{\"path\": {\"pattern\": \"^/tmp/\"}}'")
    p_issue.add_argument("--constraints-file", default=None,
                         help="read per-parameter rules from a JSON file")
    p_issue.set_defaults(func=cmd_token)

    p_verify = sub.add_parser("token-verify", help="verify a credential")
    p_verify.add_argument("--secret", required=True)
    p_verify.add_argument("--token", required=True)
    p_verify.set_defaults(func=cmd_token)

    p_audit = sub.add_parser("audit", help="inspect the audit trail")
    p_audit.add_argument("--log", required=True, help="audit log path")
    p_audit.add_argument("--limit", type=int, default=100)
    p_audit.add_argument("--request-id")
    p_audit.add_argument("--decision", choices=["allow", "deny", "executed"])
    p_audit.add_argument("--role")
    p_audit.add_argument("--tool")
    p_audit.set_defaults(func=cmd_audit)

    p_proxy = sub.add_parser("proxy", help="run the MCP stdio gateway")
    p_proxy.add_argument("--policy", required=True)
    p_proxy.add_argument("--secret", required=True)
    p_proxy.add_argument("--audit", default="audit.jsonl")
    p_proxy.add_argument("--role", help="gateway role (mutually exclusive with --token)")
    p_proxy.add_argument("--token", help="gateway credential (mutually exclusive with --role)")
    p_proxy.add_argument("--server-cmd", required=True,
                         help="command that starts the MCP server, e.g. 'python mock_server.py'")
    p_proxy.set_defaults(func=cmd_proxy)

    p_policy = sub.add_parser("policy", help="sign / verify a policy file")
    p_policy.add_argument("action", choices=("sign", "verify"))
    p_policy.add_argument("--policy", required=True, help="path to policy JSON")
    p_policy.add_argument("--secret", required=True, help="signing secret")
    p_policy.set_defaults(func=cmd_policy)

    return parser

def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 2
    if args.command == "check" and not args.role and not args.token:
        parser.error("check requires --role or --token")
    if args.command == "proxy" and bool(args.role) == bool(args.token):
        parser.error("proxy requires exactly one of --role or --token")
    try:
        return args.func(args)
    except Denied as exc:
        _out(exc.decision.to_dict())
        return 1
    except Exception as exc:  # surface unexpected errors as JSON
        _out({"error": "%s: %s" % (type(exc).__name__, exc)})
        return 1

if __name__ == "__main__":
    sys.exit(main())
