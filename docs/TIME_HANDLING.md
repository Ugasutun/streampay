# Time handling: the three clocks

StreamPay balances depend on *when* you ask. Three independent clocks feed the
same accrual formula, and their divergence is observable by users:

| # | Clock | Where it runs | What it decides |
|---|-------|---------------|-----------------|
| 1 | Local wall clock (`Date.now()/1000`) | browser, 1 s ticker | the live counter value a user reads |
| 2 | Ledger time at the pinned read | Soroban RPC simulate (`available`, `get_stream`), refreshed every 15 s | the confirmed available a withdraw is guarded by |
| 3 | `ledger().timestamp()` | contract, at the ledger the tx *lands* in | what `withdraw` will actually pay |

The 15 s refresh + 1 s ticker architecture is documented in
[FRONTEND_DATA_ARCHITECTURE.md](FRONTEND_DATA_ARCHITECTURE.md); this document
defines the time-handling contract on top of it and is derived from the
findings of the clock-skew suite (issue #211).

## Skew vocabulary

The one shared vocabulary across `frontend/lib/clock-skew.ts`, the Rust tests
and the live probe:

- **epsilon** — one ledger-second, the smallest increment the contract
  observes (`EPSILON_SECONDS = 1n`). `epsilonUnits(snapshot, t)` is the accrual
  observable within one epsilon at ledger time `t`; it is *zero* for streams
  slower than 1 unit/second.
- **drift** — the bounded local/ledger disagreement, in whole seconds. The
  property domain is **±10 s** (`MAX_SKEW_SECONDS`), covering NTP correction
  windows and typical container clock error.
- **boundary** — a skew sample within ±1 s of `start_time` or `end_time`,
  where the half-open window `[start, end)` makes clock semantics sharpest.

## The UX contract (normative)

> **A live counter may show stale-down, never over-up.** The number a user
> acts on must never exceed what `withdraw` will actually pay.

Formalised as tested properties:

- **P1 — never over-up.** For any `(local_time, ledger_time)` pair with
  `local_time − ledger_time ≤ +10 s`, the *guarded* displayed available never
  exceeds contract-available at that ledger moment plus exactly one epsilon:
  `displayed ≤ contractAvailable(ledger_time) + epsilonUnits(ledger_time)`.
  Implemented by `guardedLiveDisplay()` and enforced by the live-accrual
  engine (`frontend/lib/live-accrual.ts`).
- **P2 — stale-down is allowed.** A local clock *behind* the ledger can only
  under-report; corrections downward (after a refresh, a raced withdrawal, or
  an NTP step) are legitimate and must never be smoothed upward.
- **P3 — the actionable value is the confirmed one.** Withdraw amount inputs
  are validated against the simulate-confirmed `available` (clock #2), never
  against ticker output (clock #1). `withdraw_max` is skew-proof by
  construction because the amount is computed contract-side.
- **P4 — epsilon lead is free.** With skew ≤ +1 s the guard is a no-op: an
  honest clock keeps ticking normally and any amount it displays is payable
  one ledger later (`honest_clock_may_lead_by_exactly_one_epsilon`, Rust).
- **P5 — drift domain.** Nightly probes fail if the local clock ever *leads*
  the ledger by more than 10 s; leading is the only dangerous direction.
  Being behind is recorded as a warning metric (stale-down).

## Findings (from the suite, pinned by tests)

1. **The client and contract math agree exactly at identical timestamps,
   including both window edges.** The frontend uses `now < start` /
   `now > end`, the contract uses `now <= start` / `now >= end`
   ([stream.rs:154](../contracts/streaming-payments/src/stream.rs)); floor
   division makes the rendered values equal at `start` and `end`. No flicker
   comes from the formula itself. *(parity test, `clock-skew.test.ts`)*
2. **The raw ticker obeys P1 only up to a +1 s lead.** Every additional second
   of lead over-shows one `epsilonUnits` of accrual (measured: a 10 s-fast
   clock on a 1000-unit/s stream over-shows by 9000 units beyond the epsilon
   budget). Any over-up is bounded by the accrual of the skew horizon,
   `available(t + skew) − available(t)` — so in a ±10 s domain it is bounded
   and, crucially, *reverts fail-safe* rather than over-paying
   (`AmountExceedsAvailable`, Rust matrix: 84 skew cells, every attempt either
   landed or reverted, never overpaid).
3. **Ledger inclusion is a free buffer.** A tx can only land at a ledger
   *after* the moment the client acted on; for honest clocks the landing
   ledger is ≥ local time, so everything displayed is payable by the time
   enforcement happens. Skew beyond +1 s consumes that buffer.
4. **Pending-tx staleness is the residual over-up hazard.** A concurrent
   withdrawal on another device makes the stale display exceed the on-chain
   truth by up to the raced amount for one refresh interval (15 s). No display
   function computed from a stale snapshot can prevent this; the contract is
   that the client (a) acts on the confirmed value only, and (b) refreshes
   immediately after its own mutating tx (`live-accrual.test.ts`).
5. **Second-boundary flicker is real but benign.** `Math.floor(Date.now() /
   1000)` means sub-second local movement must not re-render, and a refresh
   re-anchoring the counter down mid-window is allowed by P2. The engine
   suppresses identical-value emissions.
6. **The indexer as-of mixes clocks.** `frontend/lib/indexer-client.ts`
   derives `asOfLedger` from `sim.latestLedger` but `asOfTimestamp` from
   *local* `Date.now()` — the `Age` / `X-As-Of-Timestamp` headers therefore
   inherit client drift, while the indexer itself stores the authoritative
   `ledger_closed_at` per event (`indexer/src/store.ts`, `decoder.ts`).
   **Rule:** any as-of value served to users must be anchored to
   `ledgerClosedAt` (clock #2/#3), never to a browser clock; `Age` must be
   computed server-side. The contract-side `set_ledger_time` /
   `offset_ledger_time` testutils helpers exist so contract tests can replay
   as-of behaviour at any ledger moment.
7. **Stream creation anchors the on-chain window to the creator's clock.**
   `frontend/lib/stellar.ts` sets `start_time = floor(Date.now()/1000) + 1`.
   A creator with a +10 s-fast clock gets a stream that "does not exist" for
   10 ledger-seconds; a slow clock starts accrual immediately. Accepted for
   v1 (bounded, harmless: accrual is relative), recorded as a known
   divergence source.

## Where the rules live in code

| Rule | Implementation | Test |
|------|----------------|------|
| Guarded display (P1/P4) | `frontend/lib/clock-skew.ts` (`guardedLiveDisplay`) | `lib/clock-skew.test.ts` |
| Ticker loop + ledger anchor (P1/P2) | `frontend/lib/live-accrual.ts` (engine used by `app/stream/[id]/page.tsx`, `components/StreamDetailClient.tsx`) | `lib/live-accrual.test.ts` (fake timers + mocked reads) |
| Actionable value = confirmed (P3) | `overWithdrawal` guard in both detail views | `lib/live-accrual.test.ts` |
| Contract fail-safe | `withdraw` vs `available_amount` | `contracts/streaming-payments/src/clock_skew_test.rs` |
| Ledger-time offsets | `Fixture::set_ledger_time` / `offset_ledger_time` (testutils) | `ledger_time_offset_helpers_move_the_contract_clock` |
| Drift domain (P5) | `scripts/clock-skew-probe.mjs` | nightly `.github/workflows/nightly-clock-skew.yml`, artifacts per run |

## Running it

```bash
# deterministic suite (frontend CI job, "Clock-skew property + live-accrual tests")
cd frontend && node --experimental-strip-types --test lib/clock-skew.test.ts lib/live-accrual.test.ts

# contract matrix
cargo test -p streampay-contract clock_skew

# live probe (60 min default; writes samples.jsonl, summary.json, chart.html)
cd scripts && npm ci && node clock-skew-probe.mjs --minutes=60 --interval=15
```

The nightly probe's uploaded artifact (`clock-skew-probe-<run>`) is the
validation evidence: it charts local-vs-ledger divergence for a full hour and
embeds the property verdict in `summary.json`.
