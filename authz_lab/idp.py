"""Identity provider (authorization server) and signed tokens.

Tokens are JWT-like: base64url(JSON claims) + "." + HMAC-SHA256 signature.
A real deployment would use asymmetric signatures (e.g., RS256/ES256) so that
services only hold a public key; HMAC keeps this lab dependency-free and does
not change the consistency behavior being studied.
"""
import base64
import hashlib
import hmac
import itertools
import json

# Role -> permissions. Each permission is "resource:action".
ROLE_PERMISSIONS = {
    "viewer": {"report:read"},
    "admin": {"report:read", "payout:update", "ledger:write"},
    "refunder": {"refund:create"},
}


def permissions_for(roles) -> set:
    perms = set()
    for role in roles:
        perms |= ROLE_PERMISSIONS.get(role, set())
    return perms


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def sign_token(claims: dict, secret: bytes) -> str:
    body = _b64(json.dumps(claims, sort_keys=True).encode())
    sig = hmac.new(secret, body.encode(), hashlib.sha256).hexdigest()
    return f"{body}.{sig}"


def verify_token(token: str, secret: bytes, now: float):
    """Local verification: signature and expiry only. Returns claims or None.

    This is exactly what a service does with a self-contained token: it never
    contacts the identity provider, so it cannot see a later revocation.
    """
    try:
        body, sig = token.split(".")
    except ValueError:
        return None
    expected = hmac.new(secret, body.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return None
    claims = json.loads(_unb64(body))
    if claims["exp"] <= now:
        return None
    return claims


class Unreachable(Exception):
    """Raised when a service cannot reach the identity provider."""


class IdentityProvider:
    def __init__(self, clock, secret: bytes = b"lab-secret", token_ttl: float = 300.0):
        self.clock = clock
        self.secret = secret
        self.token_ttl = token_ttl
        self.roles = {}          # authoritative user -> set(roles)
        self.disabled = set()    # authoritative revocations
        self.bus = None          # optional EventBus for pushed updates
        self.reachable = True
        self.calls = {"issue": 0, "introspect": 0}
        self._jti = itertools.count()

    # ----- administration (the authoritative state) -----
    def add_user(self, user: str, roles):
        self.roles[user] = set(roles)

    def disable(self, user: str):
        """Revoke a user (e.g., employee terminated)."""
        self.disabled.add(user)
        if self.bus:
            self.bus.publish({"type": "revoke", "sub": user})

    def grant(self, user: str, role: str):
        self.roles[user].add(role)
        if self.bus:
            self.bus.publish({"type": "roles", "sub": user, "roles": sorted(self.roles[user])})

    # ----- endpoints used by clients and services -----
    def issue(self, user: str, issued_at: float | None = None, ttl: float | None = None) -> str:
        """Issue (or refresh) a token. Refused for disabled users."""
        self.calls["issue"] += 1
        if user in self.disabled:
            raise PermissionError(f"{user} is disabled")
        iat = self.clock.now if issued_at is None else issued_at
        claims = {
            "sub": user,
            "roles": sorted(self.roles[user]),
            "iat": iat,
            "exp": iat + (ttl or self.token_ttl),
            "jti": next(self._jti),
        }
        return sign_token(claims, self.secret)

    def introspect(self, token: str) -> dict:
        """RFC 7662-style introspection: is the token active *right now*?"""
        self.calls["introspect"] += 1
        if not self.reachable:
            raise Unreachable()
        claims = verify_token(token, self.secret, self.clock.now)
        if claims is None or claims["sub"] in self.disabled:
            return {"active": False}
        return {"active": True, "sub": claims["sub"], "roles": sorted(self.roles[claims["sub"]])}
