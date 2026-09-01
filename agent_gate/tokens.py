"""Short-lived scoped credentials for agent-gate.

Tokens are stateless: a signed payload holding role, tool scope, optional
per-parameter constraints, and expiry. The signature is HMAC-SHA256 over
the payload with a shared secret, so any node in a fleet can verify
without a session store. Expiry is checked with `int(time.time())` so
tokens can never outlive their TTL even if a client tries to rewrite the
payload (signature would not match).

Token layout (v1):
  ag1.<role>.<scope>.<constraints_b64url>.<expires>.<sig>     (6 parts)
  ag1.<role>.<scope>.<expires>.<sig>                          (5 parts, legacy)

``constraints`` is a JSON object mapping param names to the same rule
specs used by policies (pattern / allowed_values / max_length / ...).
An empty constraints segment means "no parameter constraints".
"""

import base64
import hashlib
import hmac
import json
import time

TOKEN_VERSION = "ag1"
_SEP = "."
_EMPTY_CONSTRAINTS = ""


class TokenError(Exception):
    """Base class for token failures."""


class ExpiredTokenError(TokenError):
    """Token is well-formed and correctly signed, but past its expiry."""


class InvalidTokenError(TokenError):
    """Token is malformed, tampered with, or signed by an unknown key."""


def _sign(secret, payload):
    return hmac.new(secret.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()


def _verify(secret, payload, signature):
    expected = _sign(secret, payload)
    return hmac.compare_digest(expected, signature)


def _encode_constraints(constraints):
    if not constraints:
        return _EMPTY_CONSTRAINTS
    raw = json.dumps(constraints, ensure_ascii=False, sort_keys=True).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _decode_constraints(encoded):
    if not encoded:
        return None
    try:
        pad = "=" * (-len(encoded) % 4)
        raw = base64.urlsafe_b64decode(encoded + pad)
        value = json.loads(raw.decode("utf-8"))
    except (ValueError, TypeError):
        raise InvalidTokenError("bad constraints payload")
    if not isinstance(value, dict):
        raise InvalidTokenError("constraints must be an object")
    return value


def issue(role, scope, ttl, secret, constraints=None, now=None):
    """Issue a short-lived credential.

    scope:        comma-separated tool name patterns, e.g. "file_read,web_search".
    constraints:  optional dict of param-name -> rule spec, e.g.
                  {"path": {"pattern": "^/tmp/"}}. Applied on top of the
                  role's policy when the token is used.
    """
    now = int(time.time()) if now is None else int(now)
    if ttl <= 0:
        raise ValueError("ttl must be positive")
    if constraints is not None and not isinstance(constraints, dict):
        raise TypeError("constraints must be a dict or None")
    expires = now + int(ttl)
    cseg = _encode_constraints(constraints)
    payload = _SEP.join([TOKEN_VERSION, role, scope, cseg, str(expires)])
    return payload + _SEP + _sign(secret, payload)


def _split(token):
    """Split a token into (payload_segments, constraints, expires, sig).

    ``payload_segments`` is the exact list used to rebuild and verify the
    signature (its length depends on the token layout version).
    """
    parts = token.split(_SEP)
    if len(parts) == 6:
        version, role, scope, cseg, exp_str, sig = parts
        segs = [version, role, scope, cseg, exp_str]
    elif len(parts) == 5:  # legacy tokens without a constraints segment
        version, role, scope, exp_str, sig = parts
        segs = [version, role, scope, exp_str]
        cseg = _EMPTY_CONSTRAINTS
    else:
        raise InvalidTokenError("malformed token")
    if version != TOKEN_VERSION:
        raise InvalidTokenError("unsupported token version %r" % version)
    if not exp_str.isdigit():
        raise InvalidTokenError("bad expiry field")
    return segs, cseg, int(exp_str), sig


def verify(token, secret, now=None):
    """Verify a token. Returns (role, scope, constraints).

    ``constraints`` is a dict or None. Raises TokenError on failure.
    """
    now = int(time.time()) if now is None else int(now)
    segs, cseg, expires, sig = _split(token)
    payload = _SEP.join(segs)
    if not _verify(secret, payload, sig):
        raise InvalidTokenError("signature mismatch (tampered or wrong key)")
    if now >= expires:
        raise ExpiredTokenError("token expired at %d" % expires)
    role = segs[1]
    scope = segs[2]
    return role, scope, _decode_constraints(cseg)


def scope_matches(scope, tool):
    """True if a tool name is covered by a comma-separated scope."""
    import fnmatch

    for pattern in scope.split(","):
        pattern = pattern.strip()
        if not pattern:
            continue
        if fnmatch.fnmatch(tool, pattern):
            return True
    return False
