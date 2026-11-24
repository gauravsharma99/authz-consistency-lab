# Results (trials=200, seed=655)

## Experiment 1: time until a revoked user is denied (seconds)

| config | description | mean_s | p95_s | max_s |
|---|---|---|---|---|
| A | JWT only, 60-min token | 1752.6 | 3430.0 | 3577.2 |
| B | JWT only, 5-min token + refresh | 146.2 | 285.8 | 298.1 |
| C | Introspection, 30-s cache | 14.8 | 28.4 | 29.5 |
| D | 5-min JWT + pushed revocation | 1.2 | 2.2 | 2.7 |
| E | Introspection, no cache (synchronous) | 0.3 | 0.5 | 0.5 |

## Experiment 2: identity-provider load (1,000 req/s from 200 users, 120 s)

| config | description | requests_per_s | idp_calls_per_s | idp_calls_per_1000_requests |
|---|---|---|---|---|
| A | JWT only, 60-min token | 1000 | 0.03 | 0.03 |
| B | JWT only, 5-min token + refresh | 1000 | 0.57 | 0.57 |
| C | Introspection, 30-s cache | 1000 | 6.73 | 6.73 |
| D | 5-min JWT + pushed revocation | 1000 | 0.57 | 0.57 |
| E | Introspection, no cache (synchronous) | 1000 | 1000.03 | 1000.03 |

## Experiment 3a: revocation along a path (seconds until denied)

| entry_point | mean_s | p95_s | max_s |
|---|---|---|---|
| Full path (gateway -> orders -> ledger) | 1.2 | 2.1 | 2.7 |
| Gateway check alone (JWT) | 152.5 | 282.7 | 300.2 |
| Orders check alone (introspection) | 15.3 | 28.6 | 29.8 |
| Ledger check alone (push) | 1.2 | 2.1 | 2.7 |
| Unchecked internal service | never | never | never |

## Experiment 3b: new permission along a path (seconds until allowed)

| entry_point | mean_s | p95_s | max_s |
|---|---|---|---|
| Full path (gateway -> orders -> ledger) | 152.5 | 282.7 | 300.2 |
| Gateway check alone (JWT) | 152.5 | 282.7 | 300.2 |
| Orders check alone (introspection) | 14.8 | 28.3 | 29.8 |
| Ledger check alone (push) | 1.2 | 2.1 | 2.7 |
| Unchecked internal service | allowed before grant | allowed before grant | allowed before grant |

## Experiment 4: ledger partitioned from the event bus for 150 s

| variant | revoked_window_mean_s | revoked_window_max_s | legit_tier1_success_pct | legit_tier3_success_pct |
|---|---|---|---|---|
| Push, no heartbeat rule | 96.3 | 123.0 | 100.0 | 100.0 |
| Push + 10-s heartbeat rule | 0.2 | 0.5 | 6.0 | 100.0 |
