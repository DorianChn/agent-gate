"""Policy engine for agent-gate.

The engine is the decision point for every tool call:

  allow?  -> role authorized for the tool?
             AND params satisfy the tool's param rules?
             AND (if a token is presented) the tool is inside the token scope?

Every decision is written to the audit log with masked params and a reason,
so a denied call leaves the same forensic trail as an allowed one.

Execution model: `execute` runs the handler ONLY if the call is allowed,
returning the handler result or a Denied result. This keeps the gateway
the single place where permission is enforced.
"""

import time

from .audit import AuditLogger, mask_params
from .policy import Policy, ParamRule
from .tokens import scope_matches, verify


class Denied(Exception):
    """Raised by Engine.execute when a call is not permitted."""

    def __init__(self, decision):
        super().__init__(decision.reason)
        self.decision = decision


class Decision:
    __slots__ = ("allowed", "reason", "role", "tool", "request_id",
                 "latency_ms", "scope")

    def __init__(self, allowed, reason, role, tool, request_id, latency_ms):
        self.allowed = allowed
        self.reason = reason
        self.role = role
        self.tool = tool
        self.request_id = request_id
        self.latency_ms = latency_ms
        self.scope = None

    def to_dict(self, params=None):
        d = {
            "decision": "allow" if self.allowed else "deny",
            "allowed": self.allowed,
            "reason": self.reason,
            "role": self.role,
            "tool": self.tool,
            "request_id": self.request_id,
            "latency_ms": self.latency_ms,
        }
        if params is not None:
            d["params"] = mask_params(params)
        return d


class Engine:
    def __init__(self, policy, secret, audit_path, sensitive_keys=None,
                 policy_secret=None):
        """policy: Policy | dict | JSON string | path to a JSON file.

        If ``policy`` is a file path and ``policy_secret`` is given, the
        policy signature (``<path>.sig``) is verified before use.
        """
        if isinstance(policy, Policy):
            self.policy = policy
        elif isinstance(policy, dict):
            self.policy = Policy.from_dict(policy)
        elif isinstance(policy, str):
            # A string is treated as a path to a policy file.
            self.policy = Policy.from_file(policy, secret=policy_secret)
        else:
            raise TypeError("policy must be Policy, dict, or file path")
        self.secret = secret
        self.audit = AuditLogger(audit_path)
        self.sensitive_keys = sensitive_keys

    # -- policy-only checks (no token) -------------------------------------
    def _evaluate(self, role, tool, params=None, request_id=None, scope=None,
                  constraints=None):
        """Evaluate role + params (+ optional credential scope and
        per-parameter constraints) in one pass and write exactly one audit
        record for the decision."""
        start = time.time()
        params = params or {}
        reason = None
        role_obj = self.policy.get_role(role)
        if role_obj is None:
            reason = "role '%s' is not defined in policy" % role
        else:
            rule = role_obj.match_tool(tool)
            if rule is None:
                reason = "tool '%s' is not authorized for role '%s'" % (tool, role)
            else:
                ok, perr = rule.check_params(params)
                if not ok:
                    reason = "tool '%s': %s" % (tool, perr)
                elif scope is not None and not scope_matches(scope, tool):
                    reason = "tool '%s' outside token scope '%s'" % (tool, scope)
                elif constraints:
                    for pname, pspec in constraints.items():
                        if pname not in params:
                            continue
                        err = ParamRule(pspec, "token-constraint.%s" % pname).check(params[pname])
                        if err:
                            reason = "token constraint '%s': %s" % (pname, err)
                            break
        allowed = reason is None
        decision = Decision(
            allowed=allowed,
            reason=reason or "allowed",
            role=role,
            tool=tool,
            request_id=request_id,
            latency_ms=round((time.time() - start) * 1000, 2),
        )
        self._record(decision, params)
        return decision

    def check(self, role, tool, params=None, request_id=None):
        """Return a Decision for a role-based call (no credential)."""
        return self._evaluate(role, tool, params, request_id=request_id)

    # -- token-scoped checks ----------------------------------------------
    def check_token(self, token, tool, params=None, request_id=None):
        """Verify the credential, then enforce policy + token scope +
        per-parameter constraints in one evaluation. A single audit record
        is written."""
        role, scope, constraints = verify(token, self.secret)
        decision = self._evaluate(role, tool, params, request_id=request_id,
                                  scope=scope, constraints=constraints)
        decision.scope = scope  # attach for convenience (not serialized)
        return decision

    # -- execution model ---------------------------------------------------
    def execute(self, token, tool, params=None, handler=None, request_id=None):
        """Run handler(tool, params) only if the token-scoped call is allowed.

        Raises Denied with the full Decision if not allowed. If handler is
        None, the call is authorized but nothing executes (dry-run).
        """
        decision = self.check_token(token, tool, params, request_id=request_id)
        if not decision.allowed:
            raise Denied(decision)
        if handler is None:
            return None
        result = handler(tool, params)
        self._record_result(decision, params, result)
        return result

    # -- internals ----------------------------------------------------------
    def _record(self, decision, params):
        entry = decision.to_dict(params)
        entry["params"] = mask_params(params, self.sensitive_keys)
        self.audit.log(entry)

    def _record_result(self, decision, params, result):
        summary = None
        if isinstance(result, dict):
            summary = {k: v for k, v in result.items()
                       if k in ("path", "rows", "size", "count", "status")}
        self.audit.log({
            "decision": "executed",
            "allowed": True,
            "reason": "executed",
            "role": decision.role,
            "tool": decision.tool,
            "request_id": decision.request_id,
            "latency_ms": decision.latency_ms,
            "params": mask_params(params, self.sensitive_keys),
            "result": summary,
        })
