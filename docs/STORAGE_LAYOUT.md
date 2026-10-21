# Storage layout: golden regression suite

Issue #210. This document is the operations manual for
`contracts/streaming-payments/src/storage_golden/` and the committed corpus in
`test_fixtures/storage/`. It answers three questions: what the suite protects,
how to run it, and how to *accept* a layout change on purpose.

## What can break without breaking Rust

Storage layout is the on-ledger XDR shape of everything the contract persists.
A change that compiles, passes every unit test, and keeps Rust semantics can
still make already-deployed instances unreadable. The silent ones:

| Change | Why Rust does not notice | Caught by |
| --- | --- | --- |
| Renaming a `#[contracttype]` struct field | field names are written onto the wire as symbols by the symbol-named map encoding; Rust reads by position/name locally | `decode::golden_records_decode_and_roundtrip`, `decode::harness_detects_field_rename_by_construction` |
| Renaming an enum variant | same: the variant symbol is the encoding | `mid_enum::stream_status_wire_forms_are_pinned`, `mid_enum::intent_status_wire_forms_are_pinned` |
| Retyping a field (`u64` → `i128`, `bool` → `u32`) | both sides exist in Rust; the blob does not decode | `decode` (typed decode fails, message names the field) |
| Adding/removing a struct field | the SDK tolerates it locally | `decode` (field diff names the missing/extra key) |
| Mid-enum semantic shift (variant swapped, discriminant reused) | still decodes as the same Rust variant | `mid_enum::semantic_variant_shift_is_caught_even_when_decode_accepts_it` |
| New storage key, new key enum variant | nothing old breaks; nothing new is pinned | `generate` panics on unknown keys; `decode::golden_manifest_covers_every_persisted_kind` |
| Event topic/payload layout (`#[topic]` moves a field into the topics) | indexers and off-chain readers break first | `decode::golden_events_roundtrip` |
| A migration that loses or rewrites data across an upgrade | each build is internally consistent | `replay::upgrade_replay_preserves_every_record` |
| A record the *released* build wrote that this build cannot read at all | the current build only ever reads what the current build wrote | `replay::current_types_read_baseline_records_or_the_break_is_declared` (§ Declared cross-release breaks) |

## Layout

```
contracts/streaming-payments/src/storage_golden/
  mod.rs        blob IO (read + write), ScVal rendering, key→kind dispatch,
                field diffing
  scenario.rs   the canonical lifecycle: streams, intents, fees, policy,
                governance, the oracle clock, a two-step stream ownership
                transfer, the sponsored-claim path, freeze + migrate, upgrade
                proposal (T0 .. T0+21d)
  generate.rs   #[ignore]d test: runs the scenario, writes the corpus
  decode.rs     CI test: decodes the corpus with the in-development types
  mid_enum.rs   CI test: proves the harness is not blind to enum drift
  replay.rs     CI test: boots the released wasm, upgrades to this build,
                re-reads every key; plus the cross-release decode probe that
                needs no build of this source

test_fixtures/storage/
  manifest.json     one entry per record/event: kind, durability, key render,
                    and the golden field→value map
  records/*.bin     44 blobs, one per persisted key (32 distinct kinds)
  events/*.bin      33 blobs, one per emitted event
  baseline/…wasm    the release-line (v0.3.0) bytecode the replay boots
```

Blob formats (both are `u32` little-endian length prefixes, then XDR):

* record: `u32le | LedgerKey xdr | u32le | LedgerEntry xdr`
* event: `u32le | ScVec topics xdr | u32le | ScVal data xdr`

Instance-storage keys (`governor`, `fee_bps`, …) are *not* ledger entries of
their own — they live inside the `contract_instance` value. `generate` pins each
one as a standalone record too (durability labelled `Instance`) so a layout
change fails with the per-key name instead of one opaque diff inside the
instance blob.

The scenario is deterministic: same source, same 44 records and 33 events,
byte-for-byte. CI depends on that (see the freshness gate below). The addresses
it uses come from the test host's generated-address sequence, and the stream and
intent ids are asserted on the generator path (`1..=6`, `1..=4`), so a fixture
file name keeps meaning the same stream.

The same scenario runs in two modes. The generator runs everything. The replay
and the decode probe run it against the released bytecode, which does not have
the entrypoints added after `v0.3.0`, so the oracle / ownership / sponsorship
steps are skipped there and the released build writes 12 record kinds.

## Running it

```bash
# The decode + mid_enum + replay tests, as CI runs them:
STORAGE_GOLDEN_REQUIRE_WASM=1 cargo test -p streampay-contract --lib --locked storage_golden

# Regenerate the corpus (only after the acceptance procedure below):
cargo test -p streampay-contract --lib --locked storage_golden::generate -- --ignored
```

`replay` is the only test that needs a compiled wasm of the *current* source,
because it upgrades the running instance to those exact bytes:

```bash
(cd contracts/streaming-payments && stellar contract build)   # CI path
```

Use `stellar contract build`, not a bare `cargo build --target wasm32v1-none`:
the CLI's optimize/embed pass is what makes the artifact deployable. Measured on
this source the CLI yields 78,266 bytes, inside the 77 KB budget in
`.github/workflows/ci.yml`; the same contract built without that pass measured
162,714 bytes — over the protocol's 131,072-byte contract-code entry limit, so
the host refuses to write it and the upgrade cannot be replayed. Current
soroban-sdk makes the distinction for you: a bare cargo build for the wasm target
now stops with `soroban-sdk requires stellar-cli v25.2.0+ to build a contract`.
The replay detects an unusable artifact and reports it as such rather than as a
layout failure.

With no usable artifact the replay prints `SKIP upgrade_replay: …` and passes, so
a unit-test-only run on a fresh clone is not broken — but in CI
`STORAGE_GOLDEN_REQUIRE_WASM=1` turns the same skip into a failure, which is why
`.github/workflows/ci.yml` builds the wasm *before* the test steps and sets the
variable at job level. Every other test in the module, including the cross-build
decode probe, needs nothing but the committed fixtures.

## In CI

| Step | Fails when |
| --- | --- |
| `Wasm build (stellar contract build)` | the artifact the replay upgrades to cannot be built (step runs before the tests on purpose) |
| `Wasm size budget check` | the built artifact exceeds `WASM_SIZE_BUDGET_KB` — also the early warning that the replay is about to lose its deployable artifact |
| `Unit + property tests` | any golden record/event no longer decodes, round-trips, survives the replay, or shifts cross-release decode coverage, with `STORAGE_GOLDEN_REQUIRE_WASM=1` making a silent skip impossible |
| `Storage-layout fixture corpus is up to date` | regenerating fixtures changes `test_fixtures/storage/` — i.e. someone edited a blob or the scenario drifted without following the acceptance procedure |

## Declared cross-release breaks

`replay::current_types_read_baseline_records_or_the_break_is_declared` writes the
scenario through the committed baseline artifact and then feeds every record the
released build stored through *this* build's typed decoders. The kinds that fail
must equal `DECLARED_BASELINE_BREAKS` in `replay.rs` exactly — in either
direction:

* a kind that starts failing and is not in the list ⇒ the test fails, naming the
  kind and the decode error. That is on-chain state a released instance holds and
  the next build cannot read. Write a migration, or declare the break with a
  paragraph in `replay.rs` explaining why this one is acceptable.
* a kind in the list that now decodes ⇒ the test fails too. The break got fixed
  (usually by a migration landing), so remove the entry, which re-enables the
  typed read-backs in `upgrade_replay_preserves_every_record`.

The list cannot silently narrow coverage and cannot go stale.

**Currently declared: `stream`.** This is the suite's first real finding, not a
test artifact. `87d1648` ("optional oracle-resolved stream clock") added
`use_oracle: bool` as a required field of the stored `Stream` struct. The wire
encoding is a symbol-keyed map and the decoder requires every field, so a
`Stream` record written before that merge has no `use_oracle` key and does not
decode at all. There is no `schema_version` movement (`TARGET_SCHEMA_VERSION` is
still 2) and no backfill in `migrate_storage`, so any instance deployed before
`87d1648` would lose access to its own streams on the next upgrade. The same
change is why `test_snapshots/schedule_test/*.json` on `main` are missing
`use_oracle`: the committed snapshots were not regenerated with it.

Until that is resolved, the replay still proves the parts that do not depend on
reading a `Stream` with this build's types: every persistent record is
byte-identical across the upgrade, the instance flips exactly its executable
hash and consumes exactly the `PendingUpgrade` key, `ContractUpgraded` carries
the new hash, and the intent / policy / treasury / index / migration read-backs
all survive.

## Accepting a layout change (the only sanctioned path)

A layout change is a **breaking on-chain migration**: instances already on
testnet/mainnet hold the old bytes. Never regenerate to make a red test green.

1. Confirm the failure is intentional and stated in the PR description: which
   kind, which field, old wire form → new wire form.
2. Decide the migration story **before** touching fixtures — a `schema_version`
   bump plus a bounded `migrate_storage` path, or an explicit "no deployed
   instance holds this key yet". If neither exists, this is a bug, not a layout
   change.
3. Run the scenario/generator on a scratch branch:
   `cargo test -p streampay-contract --lib --locked storage_golden::generate -- --ignored`
4. Review `git diff test_fixtures/storage/manifest.json` field by field. Every
   changed line must be one you predicted; an unrelated key moving means the
   scenario picked up extra state — fix the scenario, not the corpus.
5. Keep `COVERED_KINDS` (`decode.rs`) in step with the contract: a new persisted
   key gets a new entry, a dispatch arm in `kind_for_key` (`mod.rs`), and a
   `typed_roundtrip` decoder arm. Adding a key without them fails the generator
   by design.
6. Document the migration in `docs/UPGRADES.md` and note the affected keys here
   if the change alters which records survive an upgrade.
7. Re-capture the baseline wasm **only** when the released line moved (§
   Replacing the baseline below).

### Reviewer sign-off checklist

- [ ] The PR states the storage change as a wire-form diff, not a Rust diff.
- [ ] `schema_version` moved (or the author proves no live instance holds the key).
- [ ] A migration path exists, is bounded, and is covered by its own tests.
- [ ] The diff of `manifest.json` contains only the predicted fields.
- [ ] Old blobs still decode (`decode::golden_records_decode_and_roundtrip`) or
      their removal is explained — deleting a golden record is a deliberate act.
- [ ] `replay` still proves byte-identical survival for every untouched key.
- [ ] `DECLARED_BASELINE_BREAKS` is unchanged, or the change (added or removed
      entry) is explained in the PR — see § Declared cross-release breaks.
- [ ] Two reviewers, one of whom has read `docs/UPGRADES.md`.
- [ ] The testnet smoke (§ below) was run if the change affects an
      already-deployed instance.

## Replacing the baseline wasm

`test_fixtures/storage/baseline/streampay-v0.3.0-baseline.wasm` is the release
bytecode the replay boots and upgrades away from. Replace it when the promoted
release moves (a release cut, not a feature merge):

```bash
git switch <the released tag or main commit>
(cd contracts/streaming-payments && stellar contract build)
cp target/wasm32v1-none/release/streampay_contract.wasm \
   "$REPO/test_fixtures/storage/baseline/streampay-<new version>-baseline.wasm"
```

Update `baseline_wasm_path()` in `storage_golden/mod.rs` and the file name here.
The replay asserts the running instance really is the committed artifact
(`the replay must boot the committed baseline wasm`), so a stale or mislabelled
baseline fails loudly rather than upgrading from the wrong bytes. If the new
baseline happens to hash equal to the in-development build, the replay prints a
`NOTE:` and only the data-survival assertions carry signal.

`*.wasm` is gitignored repo-wide; `!test_fixtures/**/*.wasm` re-includes the
fixture deliberately, so this artifact is a tracked file.

## Testnet smoke (two-phase, manual)

`scripts/storage_golden_smoke.sh` repeats the replay against a real chain. It
deploys the committed baseline wasm, writes data through it by reusing
`scripts/deploy_testnet.sh`, records ten read-backs, and proposes the upgrade to
the freshly built artifact. The contract enforces a 24 h timelock
(`MIN_UPGRADE_DELAY_SECONDS`), so the run is necessarily split:

```bash
scripts/storage_golden_smoke.sh --dry-run write   # offline plan + preflight
scripts/storage_golden_smoke.sh write             # deploy, write, propose
# … 24 h …
scripts/storage_golden_smoke.sh verify            # upgrade, re-read, diff, write
```

`verify` fails naming the exact JSON field that moved, checks accrual never
regressed, then proves the new bytecode still writes (`execute_scheduled`,
`withdraw_max`). Per-run state lives in `.storage_golden_smoke/` (gitignored);
the evidence is the `pre.*.json` / `post.*.json` pair for every read. It needs
`stellar-cli`, `cargo`, `node`, `curl`, and testnet funds, and is not part of CI.

While `stream` is in `DECLARED_BASELINE_BREAKS`, expect this rehearsal to fail in
`verify` on the `stream` read: that re-read goes through the upgraded instance,
and this build's `get_stream` cannot decode a record the baseline wrote. It is the
same break the offline probe pins, on a real chain, and it disappears when the
migration lands.

## Known limits

* Only `ContractData` keys are pinned: token balances and other contracts'
  storage are out of scope (SAC layout is chain-defined).
* The suite pins XDR shape, not interpretation: a change that keeps the wire
  form and alters meaning (e.g. re-scaling a rate) is an accrual-behaviour
  question and belongs to the model/differential tests.
* Field *order* in a `#[contracttype]` struct is wire-neutral and is
  deliberately not flagged: the host canonicalises symbol-keyed maps, so both
  the golden blob and a fresh encode present keys sorted by symbol, not by
  declaration order (verified with a probe: a reordered `Stream` still decoded
  and re-encoded to byte-identical XDR). Renaming, removing, or changing the
  type of a field is a real break and is caught — a planted rename of
  `Stream.withdrawn` made every golden stream record fail to decode.
* TTL/rent parameters are recorded as the snapshot holds them; eviction behaviour
  is covered by `infra/ttl-sentinel`, not here.
* `render` is the diffing grammar: adding an `ScVal` variant means extending it
  in `mod.rs` or the generator reports the unknown shape.
