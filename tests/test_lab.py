import os
import random
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from authz_lab import (  # noqa: E402
    Client, EventBus, IdentityProvider, IntrospectionPEP, LocalTokenPEP,
    PushRevocationPEP, Scheduler, Service, sign_token, verify_token,
)


class TokenTests(unittest.TestCase):
    def test_valid_token_verifies(self):
        tok = sign_token({"sub": "a", "roles": [], "exp": 10}, b"k")
        self.assertEqual(verify_token(tok, b"k", now=5)["sub"], "a")

    def test_expired_token_rejected(self):
        tok = sign_token({"sub": "a", "roles": [], "exp": 10}, b"k")
        self.assertIsNone(verify_token(tok, b"k", now=10))

    def test_tampered_token_rejected(self):
        tok = sign_token({"sub": "a", "roles": [], "exp": 10}, b"k")
        self.assertIsNone(verify_token(tok, b"wrong-key", now=5))

    def test_disabled_user_cannot_refresh(self):
        idp = IdentityProvider(Scheduler())
        idp.add_user("a", ["admin"])
        idp.disable("a")
        with self.assertRaises(PermissionError):
            idp.issue("a")


class PEPTests(unittest.TestCase):
    def setUp(self):
        self.clock = Scheduler()
        self.idp = IdentityProvider(self.clock, token_ttl=300)
        self.idp.add_user("alice", ["admin"])
        self.token = self.idp.issue("alice")

    def test_local_token_pep_ignores_revocation_until_expiry(self):
        pep = LocalTokenPEP("gw", self.clock, self.idp.secret)
        self.idp.disable("alice")
        self.assertTrue(pep.allows(self.token, "payout:update"))   # stale permit
        self.clock.run(300)
        self.assertFalse(pep.allows(self.token, "payout:update"))

    def test_introspection_cache_bounds_staleness(self):
        pep = IntrospectionPEP("orders", self.clock, self.idp, cache_ttl=30)
        self.assertTrue(pep.allows(self.token, "payout:update"))
        self.idp.disable("alice")
        self.clock.run(29)
        self.assertTrue(pep.allows(self.token, "payout:update"))   # cached answer
        self.clock.run(30)
        self.assertFalse(pep.allows(self.token, "payout:update"))

    def test_introspection_fails_closed_when_idp_unreachable(self):
        pep = IntrospectionPEP("orders", self.clock, self.idp, cache_ttl=0)
        self.idp.reachable = False
        self.assertFalse(pep.allows(self.token, "report:read"))

    def test_push_revocation_takes_effect_after_delivery(self):
        bus = EventBus(self.clock, random.Random(1), delay_mean=1.0, delay_jitter=0.0)
        self.idp.bus = bus
        pep = PushRevocationPEP("ledger", self.clock, self.idp.secret)
        bus.subscribe(pep)
        self.idp.disable("alice")
        self.assertTrue(pep.allows(self.token, "payout:update"))
        self.clock.run(1.0)
        self.assertFalse(pep.allows(self.token, "payout:update"))

    def test_heartbeat_rule_fails_closed_only_for_strict_tiers(self):
        pep = PushRevocationPEP("ledger", self.clock, self.idp.secret, heartbeat_timeout=10)
        self.clock.run(11)   # no heartbeats delivered
        self.assertFalse(pep.allows(self.token, "payout:update", tier=1))
        self.assertTrue(pep.allows(self.token, "report:read", tier=3))

    def test_partition_queues_revocation_until_heal(self):
        bus = EventBus(self.clock, random.Random(1), delay_mean=1.0, delay_jitter=0.0)
        self.idp.bus = bus
        pep = PushRevocationPEP("ledger", self.clock, self.idp.secret)
        bus.subscribe(pep)
        bus.partition("ledger")
        self.idp.disable("alice")
        self.clock.run(50)
        self.assertTrue(pep.allows(self.token, "payout:update"))
        bus.heal("ledger")
        self.clock.run(52)
        self.assertFalse(pep.allows(self.token, "payout:update"))


class PathTests(unittest.TestCase):
    def test_path_denies_if_any_hop_denies(self):
        clock = Scheduler()
        idp = IdentityProvider(clock, token_ttl=300)
        idp.add_user("alice", ["admin"])
        gw = LocalTokenPEP("gw", clock, idp.secret)
        orders = IntrospectionPEP("orders", clock, idp, cache_ttl=0)
        path = Service("gw", gw, [Service("orders", orders)])
        client = Client("alice", idp)
        self.assertTrue(client.call(path, "payout:update"))
        idp.disable("alice")
        self.assertFalse(client.call(path, "payout:update"))         # orders catches it
        self.assertTrue(client.call(Service("gw-only", gw), "payout:update"))  # gateway alone does not


if __name__ == "__main__":
    unittest.main()
