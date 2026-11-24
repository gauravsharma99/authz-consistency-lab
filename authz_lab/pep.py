"""Policy enforcement points (PEPs): the three strategies compared in the paper.

Every PEP answers one question: may the bearer of `token` perform
`permission` right now? They differ only in *where their knowledge comes
from*, and therefore in how stale it can be.

`tier` is the action's risk tier (1 = high impact, 3 = low impact).
"""
from .idp import Unreachable, permissions_for, verify_token


class LocalTokenPEP:
    """Trusts the signed token alone (typical JWT validation at a gateway)."""

    def __init__(self, name, clock, secret):
        self.name, self.clock, self.secret = name, clock, secret

    def allows(self, token, permission, tier=3) -> bool:
        claims = verify_token(token, self.secret, self.clock.now)
        return bool(claims) and permission in permissions_for(claims["roles"])


class IntrospectionPEP:
    """Asks the identity provider, caching each answer for `cache_ttl` seconds.

    cache_ttl = 0 means a synchronous check on every request. If the identity
    provider is unreachable and the cached answer has expired, it fails closed.
    """

    def __init__(self, name, clock, idp, cache_ttl: float):
        self.name, self.clock, self.idp, self.cache_ttl = name, clock, idp, cache_ttl
        self.cache = {}  # token -> (fetched_at, response)

    def allows(self, token, permission, tier=3) -> bool:
        now = self.clock.now
        hit = self.cache.get(token)
        if hit and now - hit[0] < self.cache_ttl:
            resp = hit[1]
        else:
            try:
                resp = self.idp.introspect(token)
            except Unreachable:
                return False
            self.cache[token] = (now, resp)
        return resp["active"] and permission in permissions_for(resp["roles"])


class PushRevocationPEP:
    """Validates tokens locally but also applies revocations/role changes pushed
    over the event bus.

    If `heartbeat_timeout` is set, the PEP notices when the bus has gone quiet
    for longer than that and fails closed for actions in `strict_tiers`, since
    it can no longer be sure it has heard about recent revocations.
    """

    def __init__(self, name, clock, secret, heartbeat_timeout=None, strict_tiers=(1,)):
        self.name, self.clock, self.secret = name, clock, secret
        self.heartbeat_timeout = heartbeat_timeout
        self.strict_tiers = set(strict_tiers)
        self.revoked = set()
        self.role_updates = {}
        self.last_heartbeat = clock.now

    def on_event(self, event):
        self.last_heartbeat = self.clock.now  # any delivery proves the channel works
        if event["type"] == "revoke":
            self.revoked.add(event["sub"])
        elif event["type"] == "roles":
            self.role_updates[event["sub"]] = event["roles"]

    def channel_stale(self) -> bool:
        return (self.heartbeat_timeout is not None
                and self.clock.now - self.last_heartbeat > self.heartbeat_timeout)

    def allows(self, token, permission, tier=3) -> bool:
        claims = verify_token(token, self.secret, self.clock.now)
        if not claims or claims["sub"] in self.revoked:
            return False
        if tier in self.strict_tiers and self.channel_stale():
            return False
        roles = self.role_updates.get(claims["sub"], claims["roles"])
        return permission in permissions_for(roles)


class NoCheckPEP:
    """An internal service that trusts the network and checks nothing."""

    def __init__(self, name):
        self.name = name

    def allows(self, token, permission, tier=3) -> bool:
        return True
