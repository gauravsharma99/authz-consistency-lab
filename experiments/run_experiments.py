"""Runs the four experiments reported in the paper and writes results/.

Usage (from the repository root):
    python experiments/run_experiments.py            # full run (200 trials)
    python experiments/run_experiments.py --trials 20  # quick run
"""
import argparse
import csv
import os
import random
import statistics
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from authz_lab import (  # noqa: E402
    Client, EventBus, IdentityProvider, IntrospectionPEP, LocalTokenPEP,
    NoCheckPEP, PushRevocationPEP, Scheduler, Service,
)

RESULTS = os.path.join(os.path.dirname(__file__), "..", "results")
REVOKE_AT = 3600.0       # simulated time at which the revocation/grant happens
REQUEST_EVERY = 0.5      # attacker/client request interval (seconds)

# Single-enforcement-point configurations compared in Experiments 1 and 2.
CONFIGS = {
    "A": ("JWT only, 60-min token", dict(kind="jwt", ttl=3600)),
    "B": ("JWT only, 5-min token + refresh", dict(kind="jwt", ttl=300)),
    "C": ("Introspection, 30-s cache", dict(kind="introspect", ttl=3600, cache=30)),
    "D": ("5-min JWT + pushed revocation", dict(kind="push", ttl=300)),
    "E": ("Introspection, no cache (synchronous)", dict(kind="introspect", ttl=3600, cache=0)),
}


def summarize(values):
    values = sorted(values)
    p95 = values[min(len(values) - 1, int(0.95 * len(values)))]
    return statistics.mean(values), p95, values[-1]


def build_single(cfg, rng):
    clock = Scheduler()
    idp = IdentityProvider(clock, token_ttl=cfg["ttl"])
    if cfg["kind"] == "jwt":
        pep = LocalTokenPEP("svc", clock, idp.secret)
    elif cfg["kind"] == "introspect":
        pep = IntrospectionPEP("svc", clock, idp, cache_ttl=cfg["cache"])
    else:
        bus = EventBus(clock, rng)
        idp.bus = bus
        pep = PushRevocationPEP("svc", clock, idp.secret)
        bus.subscribe(pep)
    return clock, idp, Service("svc", pep)


# ---------------------------------------------------------------------------
# Experiment 1: how long does a revoked user keep access?
# ---------------------------------------------------------------------------
def exp1_revocation_window(trials, seed):
    rows = []
    for key, (label, cfg) in CONFIGS.items():
        windows = []
        for t in range(trials):
            rng = random.Random(seed * 1000 + t)
            clock, idp, svc = build_single(cfg, rng)
            idp.add_user("alice", ["admin"])
            issued = REVOKE_AT - rng.uniform(0, cfg["ttl"])   # token minted at a random time
            client = Client("alice", idp, issued_at=issued)
            state = {"denied_at": None}

            def attempt():
                ok = client.call(svc, "payout:update", tier=1)
                if clock.now >= REVOKE_AT and not ok:
                    state["denied_at"] = clock.now

            # Random phase so cache refreshes are not aligned with the revocation.
            start = max(issued, REVOKE_AT - 90 + rng.uniform(0, 30))
            clock.every(REQUEST_EVERY, attempt, start=start)
            clock.at(REVOKE_AT, idp.disable, "alice")
            clock.run(REVOKE_AT + 5000, stop=lambda: state["denied_at"] is not None)
            windows.append(state["denied_at"] - REVOKE_AT)
        mean, p95, mx = summarize(windows)
        rows.append({"config": key, "description": label, "mean_s": round(mean, 1),
                     "p95_s": round(p95, 1), "max_s": round(mx, 1)})
    return rows


# ---------------------------------------------------------------------------
# Experiment 2: what does freshness cost the identity provider?
# ---------------------------------------------------------------------------
def exp2_idp_load(seed, users=200, per_user_interval=0.2, duration=120.0):
    rows = []
    for key, (label, cfg) in CONFIGS.items():
        rng = random.Random(seed)
        clock, idp, svc = build_single(cfg, rng)
        if cfg["kind"] == "push":
            idp.bus.start_heartbeats()
        counter = {"requests": 0}
        for u in range(users):
            name = f"user{u}"
            idp.add_user(name, ["viewer"])
            client = Client(name, idp, issued_at=-rng.uniform(0, cfg["ttl"]))

            def attempt(c=client):
                counter["requests"] += 1
                c.call(svc, "report:read", tier=3)

            clock.every(per_user_interval, attempt, start=rng.uniform(0, per_user_interval))
        idp.calls = {"issue": 0, "introspect": 0}   # ignore initial token issuance
        clock.run(duration)
        idp_calls = sum(idp.calls.values())
        rows.append({"config": key, "description": label,
                     "requests_per_s": round(counter["requests"] / duration),
                     "idp_calls_per_s": round(idp_calls / duration, 2),
                     "idp_calls_per_1000_requests": round(1000 * idp_calls / counter["requests"], 2)})
    return rows


# ---------------------------------------------------------------------------
# Experiment 3: layered enforcement along a request path
# ---------------------------------------------------------------------------
def build_path(rng):
    """gateway (JWT, 5-min) -> orders (introspection, 30-s cache) -> ledger (push)."""
    clock = Scheduler()
    idp = IdentityProvider(clock, token_ttl=300)
    bus = EventBus(clock, rng)
    idp.bus = bus
    gw_pep = LocalTokenPEP("gateway", clock, idp.secret)
    orders_pep = IntrospectionPEP("orders", clock, idp, cache_ttl=30)
    ledger_pep = PushRevocationPEP("ledger", clock, idp.secret)
    bus.subscribe(ledger_pep)
    ledger = Service("ledger", ledger_pep)
    orders = Service("orders", orders_pep, [ledger])
    entry_points = {
        "Full path (gateway -> orders -> ledger)": Service("gateway", gw_pep, [orders]),
        "Gateway check alone (JWT)": Service("gw-only", gw_pep),
        "Orders check alone (introspection)": Service("orders-only", orders_pep),
        "Ledger check alone (push)": Service("ledger-only", ledger_pep),
        "Unchecked internal service": Service("reporting", NoCheckPEP("reporting")),
    }
    return clock, idp, entry_points


def exp3_path(trials, seed, horizon=1000.0):
    results = {}
    for mode in ("revoke", "grant"):
        samples = {}
        never = {}
        pre_allowed = set()
        for t in range(trials):
            rng = random.Random(seed * 7000 + t)
            clock, idp, entries = build_path(rng)
            user, perm, role = (("alice", "payout:update", ["admin"]) if mode == "revoke"
                                else ("bob", "refund:create", ["viewer"]))
            idp.add_user(user, role)
            issued = REVOKE_AT - rng.uniform(0, 300)
            client = Client(user, idp, issued_at=issued)
            changed = {}

            def attempt():
                if clock.now < REVOKE_AT:
                    for name, svc in entries.items():   # warm caches before the change
                        if client.call(svc, perm, tier=1) and mode == "grant":
                            pre_allowed.add(name)       # allowed before it was granted
                    return
                for name, svc in entries.items():
                    if name in changed:
                        continue
                    ok = client.call(svc, perm, tier=1)
                    if (mode == "revoke" and not ok) or (mode == "grant" and ok):
                        changed[name] = clock.now - REVOKE_AT

            clock.every(REQUEST_EVERY, attempt, start=REVOKE_AT - 90 + rng.uniform(0, 30))
            if mode == "revoke":
                clock.at(REVOKE_AT, idp.disable, user)
            else:
                clock.at(REVOKE_AT, idp.grant, user, "refunder")
            clock.run(REVOKE_AT + horizon, stop=lambda: len(changed) == len(entries))
            for name in entries:
                if name in changed:
                    samples.setdefault(name, []).append(changed[name])
                else:
                    never[name] = never.get(name, 0) + 1
        rows = []
        for name in entries:
            if name in pre_allowed:
                label = "allowed before grant"
                rows.append({"entry_point": name, "mean_s": label, "p95_s": label, "max_s": label})
            elif never.get(name):
                rows.append({"entry_point": name, "mean_s": "never", "p95_s": "never", "max_s": "never"})
            else:
                mean, p95, mx = summarize(samples[name])
                rows.append({"entry_point": name, "mean_s": round(mean, 1),
                             "p95_s": round(p95, 1), "max_s": round(mx, 1)})
        results[mode] = rows
    return results


# ---------------------------------------------------------------------------
# Experiment 4: a network partition cuts the ledger off from the event bus
# ---------------------------------------------------------------------------
def exp4_partition(trials, seed, part_start=-30.0, part_end=120.0):
    rows = []
    for variant, hb in (("Push, no heartbeat rule", None), ("Push + 10-s heartbeat rule", 10.0)):
        windows, legit = [], {1: [0, 0], 3: [0, 0]}
        for t in range(trials):
            rng = random.Random(seed * 9000 + t)
            clock = Scheduler()
            idp = IdentityProvider(clock, token_ttl=300)
            bus = EventBus(clock, rng)
            idp.bus = bus
            pep = PushRevocationPEP("ledger", clock, idp.secret, heartbeat_timeout=hb)
            bus.subscribe(pep)
            bus.start_heartbeats()
            ledger = Service("ledger", pep)
            idp.add_user("alice", ["admin"])
            idp.add_user("carol", ["admin"])
            attacker = Client("alice", idp, issued_at=REVOKE_AT - rng.uniform(0, 300))
            honest = Client("carol", idp, issued_at=REVOKE_AT - rng.uniform(0, 300))
            state = {"denied_at": None}
            p0, p1 = REVOKE_AT + part_start, REVOKE_AT + part_end

            def attempt():
                now = clock.now
                if now >= REVOKE_AT and state["denied_at"] is None:
                    if not attacker.call(ledger, "payout:update", tier=1):
                        state["denied_at"] = now
                if p0 <= now < p1:
                    for tier, perm in ((1, "payout:update"), (3, "report:read")):
                        legit[tier][0] += honest.call(ledger, perm, tier=tier)
                        legit[tier][1] += 1

            clock.every(REQUEST_EVERY, attempt, start=REVOKE_AT - 120 + rng.uniform(0, REQUEST_EVERY))
            clock.at(p0, bus.partition, "ledger")
            clock.at(p1, bus.heal, "ledger")
            clock.at(REVOKE_AT, idp.disable, "alice")
            clock.run(p1 + 10)
            windows.append((state["denied_at"] or clock.now) - REVOKE_AT)
        mean, p95, mx = summarize(windows)
        rows.append({"variant": variant, "revoked_window_mean_s": round(mean, 1),
                     "revoked_window_max_s": round(mx, 1),
                     "legit_tier1_success_pct": round(100 * legit[1][0] / legit[1][1], 1),
                     "legit_tier3_success_pct": round(100 * legit[3][0] / legit[3][1], 1)})
    return rows


# ---------------------------------------------------------------------------
def write_csv(name, rows):
    with open(os.path.join(RESULTS, name), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)


def md_table(rows):
    keys = list(rows[0].keys())
    out = ["| " + " | ".join(keys) + " |", "|" + "---|" * len(keys)]
    out += ["| " + " | ".join(str(r[k]) for k in keys) + " |" for r in rows]
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--trials", type=int, default=200)
    ap.add_argument("--seed", type=int, default=655)
    args = ap.parse_args()
    os.makedirs(RESULTS, exist_ok=True)
    t0 = time.time()

    e1 = exp1_revocation_window(args.trials, args.seed)
    e2 = exp2_idp_load(args.seed)
    e3 = exp3_path(args.trials, args.seed)
    e4 = exp4_partition(args.trials, args.seed)

    write_csv("exp1_revocation_window.csv", e1)
    write_csv("exp2_idp_load.csv", e2)
    write_csv("exp3_path_revoke.csv", e3["revoke"])
    write_csv("exp3_path_grant.csv", e3["grant"])
    write_csv("exp4_partition.csv", e4)

    report = "\n\n".join([
        f"# Results (trials={args.trials}, seed={args.seed})",
        "## Experiment 1: time until a revoked user is denied (seconds)", md_table(e1),
        "## Experiment 2: identity-provider load (1,000 req/s from 200 users, 120 s)", md_table(e2),
        "## Experiment 3a: revocation along a path (seconds until denied)", md_table(e3["revoke"]),
        "## Experiment 3b: new permission along a path (seconds until allowed)", md_table(e3["grant"]),
        "## Experiment 4: ledger partitioned from the event bus for 150 s", md_table(e4),
    ])
    with open(os.path.join(RESULTS, "results.md"), "w", encoding="utf-8") as f:
        f.write(report + "\n")
    print(report)
    print(f"\nFinished in {time.time() - t0:.1f} s of real time.")


if __name__ == "__main__":
    main()
