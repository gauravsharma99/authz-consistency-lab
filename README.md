# authz-consistency-lab

A small, dependency-free Python simulation that measures **authorization consistency** in a microservice system: how long a revoked user keeps access, how long a newly granted permission takes to work, and what each design costs the identity provider.

Written for the CYBR 655 (Distributed Systems Security) final project, *Authorization Consistency in Distributed Microservices*.

## What it models

| Component | File | Role |
|---|---|---|
| `Scheduler` | `authz_lab/sim.py` | Discrete-event clock. Simulated time lets an hour of traffic run in seconds and be reproduced exactly from a seed. |
| `IdentityProvider` | `authz_lab/idp.py` | Issues signed, JWT-like tokens (HMAC-SHA256), handles refresh, supports RFC 7662-style introspection, and records revocations and role grants. |
| `EventBus` | `authz_lab/bus.py` | Pushes revocation and role events with random delivery delay, plus heartbeats and network partitions. |
| PEPs | `authz_lab/pep.py` | Three enforcement strategies: `LocalTokenPEP` (trust the token), `IntrospectionPEP` (ask the IdP and cache the answer), `PushRevocationPEP` (local check plus pushed events, with an optional fail-closed heartbeat rule). Also `NoCheckPEP` (a service that checks nothing). |
| `Service`, `Client` | `authz_lab/service.py` | Services that check their own PEP and then call downstream services, and a client that refreshes its token. |

Every action has a **risk tier** (1 = high impact, such as payouts; 3 = low impact, such as reading a report). The heartbeat rule uses the tier to decide what fails closed.

## Experiments

```
python experiments/run_experiments.py              # 200 trials per config, about 30 s
python experiments/run_experiments.py --trials 20  # quick run
python -m unittest discover -s tests -v            # 11 unit tests
```

Results are written to `results/` (CSV files plus `results.md`).

1. **Revocation window.** A user is disabled at a random point in their token's life. How long do they keep access under five configurations (A–E)?
2. **Identity-provider load.** 1,000 requests per second from 200 users. How many calls does the IdP receive under each configuration?
3. **Layered enforcement.** The path is gateway (JWT) → orders (introspection, 30-s cache) → ledger (push). The experiment compares revocation and grant times for the whole path against each service called directly.
4. **Partition.** The ledger is cut off from the event bus for 150 s around a revocation. The experiment compares running with and without the fail-closed heartbeat rule.

## Results (200 trials, seed 655)

| Config | Mean time a revoked user keeps access | Max | IdP calls per 1,000 requests |
|---|---|---|---|
| A: JWT only, 60-min token | 1,752.6 s | 3,577.2 s | 0.03 |
| B: JWT only, 5-min token + refresh | 146.2 s | 298.1 s | 0.57 |
| C: Introspection, 30-s cache | 14.8 s | 29.5 s | 6.73 |
| D: 5-min JWT + pushed revocation | 1.2 s | 2.7 s | 0.57 |
| E: Introspection, no cache | 0.3 s | 0.5 s | 1,000.03 |

**Layered checks (Experiment 3):**
- A revocation takes effect on the full path as fast as the *fastest* check: 1.2 s, the same as the ledger alone.
- A new permission works on the full path only as fast as the *slowest* check: 152.5 s, the same as the gateway alone.
- An internal service with no check of its own never stopped the revoked user.

**Partition (Experiment 4):**
- Without the heartbeat rule, a revoked user kept high-impact access for 96.3 s on average.
- With a 10-s heartbeat rule, they lost it immediately. The trade-off is that legitimate high-impact requests to the partitioned ledger succeeded only 6% of the time; low-impact reads stayed at 100%.

The full tables are in [`results/results.md`](results/results.md).

## Limitations

This is a simulation, not a benchmark of real products. Delays are modeled, not measured. HMAC stands in for asymmetric token signatures, and network latency to the IdP is not modeled. The experiments isolate *consistency behavior*; they say nothing about throughput or latency.

## Requirements

Python 3.10 or newer. No third-party packages.
