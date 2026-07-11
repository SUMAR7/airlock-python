# Airlock examples

Runnable examples that show Airlock end-to-end with zero infrastructure (each
uses the zero-config SQLite store — no Postgres, no cloud account required).

- [`double_refund/`](double_refund/) — the 60-second starter. The same refund,
  retried once: **without** Airlock the customer is refunded twice; **with**
  Airlock, exactly once. Start here.

More examples (durable human approval, the audit chain, at-most-once
degradation) are on the way.
