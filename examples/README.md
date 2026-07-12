# Airlock examples

Runnable examples that show Airlock end-to-end with zero infrastructure (each
uses the zero-config SQLite store — no Postgres, no cloud account required).

- [`double_refund/`](double_refund/) — the 60-second starter. The same refund,
  retried once: **without** Airlock the customer is refunded twice; **with**
  Airlock, exactly once. Start here.
- [`hosted_gated/`](hosted_gated/) — a human in the loop. A payout **gates** for
  approval with a curated **summary + context** the reviewer sees (raw args never
  transit), and structured **reject reason codes** the agent branches on. Shows
  both paths: approve → commit exactly once; reject with a code → no effect, the
  code surfaced on `ApprovalRejected`.

More examples (the audit chain, at-most-once degradation) are on the way.
