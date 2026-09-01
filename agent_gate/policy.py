"""Policy model for agent-gate.

A policy maps roles to authorized tools and per-parameter rules.
Policies are plain JSON so they can be versioned, reviewed, and signed.

Example policy:

{
  "default_action": "deny",
  "roles": {
    "researcher": {
      "tools": {
        "file_read": {
          "params": {
            "path":       {"pattern": "^(/tmp/|/workspace/|C:\\\\tmp\\\\)"},
            "max_bytes":  {"max": 1048576}
          }
        },
        "web_search": {}
      }
    },
    "editor": {
      "tools": {
        "file_write": {
          "params": {
            "path":     {"pattern": "^(/workspace/|C:\\\\workspace\\\\)"},
            "content":  {"max_length": 65536}
          }
        }
      }
    }
  }
}

Supported parameter rules (all optional, combined with AND):
  allowed_values : value must be one of this list
  deny_values    : value must NOT be one of this list
  pattern        : value must match this regex (re.search)
  min / max      : numeric value must be within [min, max]
  max_length     : string value length must be <= max_length
"""

import fnmatch
import json
import re

class PolicyError(Exception):
    """Raised when a policy document is malformed."""

def _validate_rule(rule, path):
    if not isinstance(rule, dict):
        raise PolicyError("%s: rule must be an object" % path)
    supported = {
        "allowed_values", "deny_values", "pattern",
        "min", "max", "max_length",
    }
    unknown = set(rule) - supported
    if unknown:
        raise PolicyError("%s: unsupported rule keys %s" % (path, sorted(unknown)))

class ParamRule:
    """A single parameter constraint."""

    def __init__(self, spec, path):
        _validate_rule(spec, path)
        self._spec = spec
        self._pattern = None
        if "pattern" in spec:
            try:
                self._pattern = re.compile(spec["pattern"])
            except re.error as exc:
                raise PolicyError("%s: bad regex %r: %s" % (path, spec["pattern"], exc))

    def check(self, value):
        """Return None if the value is allowed, else an error message."""
        spec = self._spec
        if "allowed_values" in spec and value not in spec["allowed_values"]:
            return "value not in allowed_values"
        if "deny_values" in spec and value in spec["deny_values"]:
            return "value in deny_values"
        if self._pattern is not None:
            if not isinstance(value, str) or not self._pattern.search(value):
                return "value does not match pattern"
        if "min" in spec or "max" in spec:
            try:
                num = float(value)
            except (TypeError, ValueError):
                return "value is not numeric"
            if "min" in spec and num < spec["min"]:
                return "value below min"
            if "max" in spec and num > spec["max"]:
                return "value above max"
        if "max_length" in spec:
            if not isinstance(value, str) or len(value) > spec["max_length"]:
                return "value exceeds max_length"
        return None

class ToolRule:
    """Authorization rules for one tool name pattern."""

    def __init__(self, spec, path):
        if spec is None:
            spec = {}
        if not isinstance(spec, dict):
            raise PolicyError("%s: tool spec must be an object" % path)
        self.pattern = path.split("/")[-1]
        self.params = {}
        for pname, prspec in (spec.get("params") or {}).items():
            self.params[pname] = ParamRule(prspec, "%s.params.%s" % (path, pname))

    def check_params(self, params):
        """Return (ok, reason) for a params dict. Unknown params are allowed."""
        if not params:
            return True, None
        for pname, prule in self.params.items():
            if pname not in params:
                continue
            err = prule.check(params[pname])
            if err:
                return False, "param '%s': %s" % (pname, err)
        return True, None

class Role:
    """A role's authorized tool patterns."""

    def __init__(self, name, spec, path):
        if not isinstance(spec, dict) or not isinstance(spec.get("tools"), dict):
            raise PolicyError("%s: role must have a 'tools' object" % path)
        self.name = name
        self.tools = {}
        for tname, tspecl in spec["tools"].items():
            self.tools[tname] = ToolRule(tspecl, "%s.tools.%s" % (path, tname))

    def match_tool(self, tool):
        """Return the best-matching ToolRule for a tool name, or None."""
        # Exact match first, then wildcard patterns, most specific last.
        if tool in self.tools:
            return self.tools[tool]
        patterns = [p for p in self.tools if "*" in p or "?" in p]
        for pattern in sorted(patterns, key=len, reverse=True):
            if fnmatch.fnmatch(tool, pattern):
                return self.tools[pattern]
        return None

class Policy:
    """A loaded policy document."""

    def __init__(self, roles, default_action="deny"):
        self.roles = roles
        self.default_action = default_action
        if default_action not in ("allow", "deny"):
            raise PolicyError("default_action must be 'allow' or 'deny'")

    @classmethod
    def from_dict(cls, data):
        if not isinstance(data, dict):
            raise PolicyError("policy must be an object")
        roles = {}
        for rname, rspec in (data.get("roles") or {}).items():
            roles[rname] = Role(rname, rspec, "roles.%s" % rname)
        return cls(roles, data.get("default_action", "deny"))

    @classmethod
    def from_json(cls, text):
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise PolicyError("invalid JSON: %s" % exc)
        return cls.from_dict(data)

    @classmethod
    def from_file(cls, path):
        with open(path, "r", encoding="utf-8") as fh:
            return cls.from_json(fh.read())

    # ------------------------------------------------------------------
    # policy signing (HMAC-SHA256 over canonical JSON)
    # ------------------------------------------------------------------

    def get_role(self, name):
        return self.roles.get(name)

    def role_names(self):
        return sorted(self.roles)
