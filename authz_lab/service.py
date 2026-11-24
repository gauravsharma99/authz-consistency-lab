"""Microservices and a client that holds (and refreshes) a token."""
from .idp import verify_token


class Service:
    """A service checks its own PEP, then calls its downstream services.

    A request succeeds only if every service on the path allows it.
    """

    def __init__(self, name, pep, downstream=()):
        self.name, self.pep, self.downstream = name, pep, list(downstream)

    def handle(self, token, permission, tier=3) -> bool:
        if not self.pep.allows(token, permission, tier):
            return False
        return all(svc.handle(token, permission, tier) for svc in self.downstream)


class Client:
    """Holds a token and refreshes it from the identity provider when it expires."""

    def __init__(self, user, idp, issued_at=None):
        self.user, self.idp = user, idp
        self.token = idp.issue(user, issued_at=issued_at)

    def current_token(self):
        if verify_token(self.token, self.idp.secret, self.idp.clock.now) is None:
            try:
                self.token = self.idp.issue(self.user)
            except PermissionError:
                pass  # refresh refused (user disabled); keep the dead token
        return self.token

    def call(self, service, permission, tier=3) -> bool:
        return service.handle(self.current_token(), permission, tier)
