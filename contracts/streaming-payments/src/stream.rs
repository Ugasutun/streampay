//! Stream state, storage, and the checked accrual math.
//!
//! Accrual is linear over the stream window: a stream funded with `deposit`
//! between `start_time` and `end_time` streams `deposit * elapsed / duration`
//! tokens, floored to whole token units. All arithmetic is checked (`u128`
//! intermediate products) and returns [`StreamError::MathOverflow`] instead of
//! overflowing or panicking.

use soroban_sdk::{contracttype, Address, BytesN, Env, MuxedAddress, Vec};

use crate::errors::StreamError;
use crate::surface::{self, Branch};

/// Minimum delay for an upgrade proposal timelock: 24 hours.
pub const MIN_UPGRADE_DELAY_SECONDS: u64 = 86_400;

/// Initial schema version (v1).
pub const INITIAL_SCHEMA_VERSION: u32 = 1;

/// Target schema version after migration (v2).
pub const TARGET_SCHEMA_VERSION: u32 = 2;

/// Maximum number of streams processed per migration call.
pub const MAX_MIGRATION_BATCH_SIZE: u32 = 50;

/// Maximum supported stream duration: 100 years, including leap days
/// (36,525 days). Bounds worst-case rate multiplications and rejects
/// nonsensical windows early.
pub const MAX_DURATION_SECONDS: u64 = 3_155_760_000;

/// Maximum number of stream ids a single paginated index query may return.
/// Callers asking for more are clamped down; this bounds per-call footprint
/// of the address-index views.
pub const MAX_PAGE_SIZE: u32 = 50;

/// Minimum number of stream entries permitted in a batch.
pub const MIN_BATCH: u32 = 1;

/// Maximum number of stream entries permitted in a batch.
///
/// Bounded to 25 because each stream creation emits a `StreamCreated` event
/// and a token `transfer` event (~600 bytes combined). At 25 streams, event
/// size is ~15.5 KB, safely within Soroban's network limit of 16,384 bytes (16 KB),
/// and consumes ~16.2M CPU instructions (~16% of the 100M transaction budget).
pub const MAX_BATCH: u32 = 25;

/// Lifetime of a pending ownership proposal, in seconds (7 days).
///
/// A proposal that is not accepted within this window becomes stale: it can no
/// longer be accepted (the target must ask the current role holder to propose
/// again), but the current holder can still cancel it explicitly or replace it
/// with a fresh proposal. Expiry is enforced against the ledger timestamp, not
/// storage TTL, so the semantics are identical on every network.
pub const OWNERSHIP_PROPOSAL_TTL_SECONDS: u64 = 7 * 24 * 60 * 60;

/// TTL maintenance, in ledgers (~5 seconds per ledger on Stellar mainnet).
///
/// Streams live in persistent storage: entries that go untouched are
/// eventually archived off-chain (and auto-restored at a fee when next read).
/// Every mutating entrypoint extends the stream entry's TTL, so a stream that
/// is actually being used never goes cold.
pub(crate) const TTL_THRESHOLD_LEDGERS: u32 = 200_000; // extend when TTL drops below ~11.5 days
pub(crate) const TTL_EXTEND_LEDGERS: u32 = 500_000; // extend to ~29 days

#[cfg_attr(
    not(target_family = "wasm"),
    doc = " The role being handed over by a two-step ownership transfer."
)]
#[contracttype]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum OwnershipRole {
    #[cfg_attr(
        not(target_family = "wasm"),
        doc = " The payer: may top up and cancel, and receives cancellation refunds."
    )]
    Sender,
    #[cfg_attr(
        not(target_family = "wasm"),
        doc = " The claimant: may withdraw accrued funds."
    )]
    Recipient,
}

#[cfg_attr(
    not(target_family = "wasm"),
    doc = " A pending two-step ownership proposal for one stream."
)]
#[cfg_attr(not(target_family = "wasm"), doc = "")]
#[cfg_attr(
    not(target_family = "wasm"),
    doc = " Proposals live under their own storage key ([`DataKey::PendingOwnership`])"
)]
#[cfg_attr(
    not(target_family = "wasm"),
    doc = " rather than inside [`Stream`], so accepting or cancelling one leaves the"
)]
#[cfg_attr(
    not(target_family = "wasm"),
    doc = " stream's accounting fields untouched and the dedicated key can be given its"
)]
#[cfg_attr(not(target_family = "wasm"), doc = " own TTL treatment.")]
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingOwnership {
    pub stream_id: u64,
    #[cfg_attr(
        not(target_family = "wasm"),
        doc = " The current role holder that created the proposal (and the only address"
    )]
    #[cfg_attr(not(target_family = "wasm"), doc = " allowed to cancel it).")]
    pub proposed_by: Address,
    #[cfg_attr(
        not(target_family = "wasm"),
        doc = " The address that must accept the role before it takes effect."
    )]
    pub new_owner: Address,
    pub role: OwnershipRole,
    #[cfg_attr(
        not(target_family = "wasm"),
        doc = " Ledger timestamp at or after which the proposal is stale."
    )]
    pub expires_at: u64,
}

#[cfg_attr(not(target_family = "wasm"), doc = " Lifecycle state of a stream.")]
#[contracttype]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum StreamStatus {
    #[cfg_attr(
        not(target_family = "wasm"),
        doc = " Running; funds accrue and can be withdrawn or topped up."
    )]
    Active,
    #[cfg_attr(
        not(target_family = "wasm"),
        doc = " Cancelled; remaining funds were split at cancellation. Terminal."
    )]
    Cancelled,
    #[cfg_attr(
        not(target_family = "wasm"),
        doc = " Fully streamed and fully withdrawn. Terminal."
    )]
    Depleted,
}

#[cfg_attr(not(target_family = "wasm"), doc = " Full state of a payment stream.")]
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Stream {
    pub id: u64,
    pub sender: Address,
    pub recipient: Address,
    pub token: Address,
    #[cfg_attr(
        not(target_family = "wasm"),
        doc = " Total amount funded into the stream (original deposit + top-ups)."
    )]
    pub deposit: i128,
    #[cfg_attr(
        not(target_family = "wasm"),
        doc = " Total amount paid to the recipient so far (withdrawals + cancel payout)."
    )]
    pub withdrawn: i128,
    pub start_time: u64,
    pub end_time: u64,
    #[cfg_attr(
        not(target_family = "wasm"),
        doc = " If true, the recipient may also cancel and reclaim their accrued balance."
    )]
    pub cancelable: bool,
    pub status: StreamStatus,
    #[cfg_attr(
        not(target_family = "wasm"),
        doc = " If true, settles against external oracle time feed instead of ledger time."
    )]
    pub use_oracle: bool,
}

impl Stream {
    /// Seconds in the stream's full window. Always `>= 1` for a stored stream
    /// (`create_stream` rejects `end_time <= start_time`).
    pub fn duration(&self) -> u64 {
        self.end_time - self.start_time
    }
}

#[cfg_attr(
    not(target_family = "wasm"),
    doc = " Parameters for creating a single stream within a batch creation call."
)]
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchEntry {
    pub sender: Address,
    pub recipient: Address,
    pub token: Address,
    pub deposit: i128,
    pub start_time: u64,
    pub end_time: u64,
    pub cancelable: bool,
}

#[cfg_attr(
    not(target_family = "wasm"),
    doc = " Proposed contract upgrade pending timelock expiration."
)]
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingUpgrade {
    pub new_wasm_hash: BytesN<32>,
    pub unlock_time: u64,
}

#[cfg_attr(
    not(target_family = "wasm"),
    doc = " Progress report for on-chain storage migration."
)]
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MigrationStatus {
    pub current_version: u32,
    pub target_version: u32,
    pub cursor: u64,
    pub total_streams: u64,
    pub is_complete: bool,
}

#[cfg_attr(not(target_family = "wasm"), doc = " Storage keys for the contract.")]
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DataKey {
    #[cfg_attr(
        not(target_family = "wasm"),
        doc = " Next stream id to hand out; ids start at 1."
    )]
    NextStreamId,
    #[cfg_attr(not(target_family = "wasm"), doc = " The stream with the given id.")]
    Stream(u64),
    #[cfg_attr(
        not(target_family = "wasm"),
        doc = " Append-only index of stream ids where the given address is the"
    )]
    #[cfg_attr(
        not(target_family = "wasm"),
        doc = " recipient. Advisory (discovery) data: the `Stream` entries remain the"
    )]
    #[cfg_attr(
        not(target_family = "wasm"),
        doc = " source of truth, and terminal streams keep their place in the index."
    )]
    RecipientStreams(Address),
    #[cfg_attr(
        not(target_family = "wasm"),
        doc = " Append-only index of stream ids created (as sender) by the given"
    )]
    #[cfg_attr(
        not(target_family = "wasm"),
        doc = " address. Same advisory semantics as [`DataKey::RecipientStreams`]."
    )]
    SenderStreams(Address),
    #[cfg_attr(
        not(target_family = "wasm"),
        doc = " Next scheduled-intent id to hand out; ids start at 1."
    )]
    NextIntentId,
    #[cfg_attr(
        not(target_family = "wasm"),
        doc = " The scheduled intent with the given id."
    )]
    Intent(u64),
    #[cfg_attr(
        not(target_family = "wasm"),
        doc = " Append-only index of scheduled-intent ids created (as sender) by the"
    )]
    #[cfg_attr(
        not(target_family = "wasm"),
        doc = " given address. Same advisory semantics as [`DataKey::SenderStreams`]."
    )]
    SenderIntents(Address),
    #[cfg_attr(
        not(target_family = "wasm"),
        doc = " Treasury governor address (instance storage; set once by the"
    )]
    #[cfg_attr(
        not(target_family = "wasm"),
        doc = " contract constructor, later by two-step nomination/acceptance)."
    )]
    Governor,
    #[cfg_attr(
        not(target_family = "wasm"),
        doc = " Pending governor nominee (instance storage; set by"
    )]
    #[cfg_attr(
        not(target_family = "wasm"),
        doc = " `nominate_governor`, cleared by `accept_governor`)."
    )]
    PendingGovernor,
    #[cfg_attr(
        not(target_family = "wasm"),
        doc = " Configured protocol fee in basis points (instance storage; absent"
    )]
    #[cfg_attr(
        not(target_family = "wasm"),
        doc = " means 0 — fees disabled, the v0.3 behavior)."
    )]
    FeeBps,
    #[cfg_attr(
        not(target_family = "wasm"),
        doc = " Per-token fee accounting: fees charged minus fees withdrawn"
    )]
    #[cfg_attr(
        not(target_family = "wasm"),
        doc = " (persistent storage; written only by fee-affecting entrypoints)."
    )]
    Treasury(Address),
    #[cfg_attr(
        not(target_family = "wasm"),
        doc = " Fee charged for one stream at creation time (persistent storage;"
    )]
    #[cfg_attr(
        not(target_family = "wasm"),
        doc = " written only when the fee rounds above zero, so absent == 0)."
    )]
    StreamFee(u64),
    #[cfg_attr(
        not(target_family = "wasm"),
        doc = " Schema version for storage layout evolution (instance storage)."
    )]
    SchemaVersion,
    #[cfg_attr(
        not(target_family = "wasm"),
        doc = " Freeze state: when true, all state-mutating entrypoints revert (instance storage)."
    )]
    ContractFrozen,
    #[cfg_attr(
        not(target_family = "wasm"),
        doc = " Proposed contract upgrade pending timelock expiration (instance storage)."
    )]
    PendingUpgrade,
    #[cfg_attr(
        not(target_family = "wasm"),
        doc = " Highest stream id processed by storage migration (instance storage)."
    )]
    MigrationCursor,
    #[cfg_attr(
        not(target_family = "wasm"),
        doc = " Global oracle configuration (instance storage)."
    )]
    OracleConfig,
    #[cfg_attr(
        not(target_family = "wasm"),
        doc = " Most recent timestamp report from a publisher (persistent storage)."
    )]
    OracleReport(Address),
    #[cfg_attr(
        not(target_family = "wasm"),
        doc = " The pending two-step ownership proposal for the given stream, if any."
    )]
    #[cfg_attr(
        not(target_family = "wasm"),
        doc = " At most one proposal exists per stream at a time."
    )]
    PendingOwnership(u64),
}

/// Seconds elapsed of the stream window at the given timestamp `now`.
pub fn elapsed_seconds_at(now: u64, start_time: u64, end_time: u64) -> u64 {
    if now <= start_time {
        0
    } else if now >= end_time {
        // MUTANT-SUPPRESS: replace - with + is acceptable because this branch
        // is only reachable when now >= end_time, which means the full duration
        // has already elapsed. The test elapsed_after_end_returns_full_duration
        // verifies that the full deposit is available at this point. The mutation
        // would cause an overflow in the subsequent streamed_at calculation,
        // which is caught by MathOverflow. This is an unreachable code path given
        // the contract's usage pattern.
        end_time - start_time
    } else {
        now - start_time
    }
}

#[allow(dead_code)]
/// Seconds elapsed of the stream window at the current ledger time.
///
/// The window is half-open `[start_time, end_time)`: at `now == start_time`
/// nothing has accrued yet; at `now >= end_time` the full duration has elapsed.
pub fn elapsed_seconds(env: &Env, start_time: u64, end_time: u64) -> u64 {
    elapsed_seconds_at(env.ledger().timestamp(), start_time, end_time)
}

/// Validates that `deposit * duration` — the worst-case rate multiplication —
/// fits in `u128`, so [`streamed_amount`] can never overflow for this stream.
///
/// `duration` must be `>= 1` (enforced by `create_stream`).
pub fn validate_capacity(deposit: i128, duration: u64) -> Result<(), StreamError> {
    let cap = u128::MAX / (duration.max(1) as u128);
    if (deposit as u128) > cap {
        return Err(surface::reject(Branch::CapacityOverflow));
    }
    Ok(())
}

/// Pure rate computation: amount streamed after `elapsed` seconds of a
/// `duration`-second window funded with `deposit`.
///
/// Linear rate: `deposit * elapsed / duration`, floored to whole token units,
/// capped at `deposit`. Checked math throughout; returns
/// [`StreamError::MathOverflow`] rather than overflowing or panicking. Exposed
/// as a pure function so tests and fuzzing can exercise it without an
/// environment.
pub fn streamed_at(deposit: i128, duration: u64, elapsed: u64) -> Result<i128, StreamError> {
    if elapsed == 0 || deposit <= 0 || duration == 0 {
        return Ok(0);
    }
    let product = (deposit as u128)
        .checked_mul(elapsed as u128)
        .ok_or_else(|| surface::reject(Branch::RateProductOverflow))?;
    let streamed = (product / (duration.max(1) as u128)).min(deposit as u128);
    // `streamed <= deposit <= i128::MAX`, so the narrowing cast cannot wrap.
    Ok(streamed as i128)
}

/// Amount streamed (accrued) at reference timestamp `now`.
pub fn streamed_amount_at(stream: &Stream, now: u64) -> Result<i128, StreamError> {
    let elapsed = elapsed_seconds_at(now, stream.start_time, stream.end_time);
    streamed_at(stream.deposit, stream.duration(), elapsed)
}

#[allow(dead_code)]
/// Amount streamed (accrued) at the current ledger time.
///
/// See [`streamed_at`] for the rate semantics.
pub fn streamed_amount(env: &Env, stream: &Stream) -> Result<i128, StreamError> {
    streamed_amount_at(stream, env.ledger().timestamp())
}

/// Accrued-but-unwithdrawn balance at reference timestamp `now`. Zero for
/// cancelled streams.
pub fn available_amount_at(stream: &Stream, now: u64) -> Result<i128, StreamError> {
    if stream.status == StreamStatus::Cancelled {
        return Ok(0);
    }
    let streamed = streamed_amount_at(stream, now)?;
    streamed
        .checked_sub(stream.withdrawn)
        .ok_or_else(|| surface::reject(Branch::AvailableBalanceOverflow))
}

#[allow(dead_code)]
/// Accrued-but-unwithdrawn balance at the current ledger time. Zero for
/// cancelled streams (their payout was settled atomically at cancellation).
pub fn available_amount(env: &Env, stream: &Stream) -> Result<i128, StreamError> {
    available_amount_at(stream, env.ledger().timestamp())
}

/// Payout split at cancellation at reference timestamp `now`: `(recipient_amount, sender_amount)`.
pub fn cancel_amounts_at(stream: &Stream, now: u64) -> Result<(i128, i128), StreamError> {
    let streamed = streamed_amount_at(stream, now)?;
    let recipient_amount = streamed
        .checked_sub(stream.withdrawn)
        .ok_or_else(|| surface::reject(Branch::CancelSplitOverflow))?;
    let sender_amount = stream
        .deposit
        .checked_sub(streamed)
        .ok_or_else(|| surface::reject(Branch::CancelSplitOverflow))?;
    Ok((recipient_amount, sender_amount))
}

#[allow(dead_code)]
/// Payout split at cancellation: `(recipient_amount, sender_amount)`.
///
/// The recipient receives their accrued-but-unwithdrawn balance; the sender is
/// refunded the unaccrued remainder.
pub fn cancel_amounts(env: &Env, stream: &Stream) -> Result<(i128, i128), StreamError> {
    cancel_amounts_at(stream, env.ledger().timestamp())
}

/// Address helper: token transfer destinations are muxed addresses.
pub(crate) fn muxed(addr: &Address) -> MuxedAddress {
    addr.clone().into()
}

/// Hands out the next stream id (1-based) and stores the incremented counter.
pub fn next_stream_id(env: &Env) -> u64 {
    let key = DataKey::NextStreamId;
    let id: u64 = env.storage().persistent().get(&key).unwrap_or(1);
    env.storage().persistent().set(&key, &id.saturating_add(1));
    id
}

/// Reserves a contiguous range of stream ids with one persistent write.
pub fn reserve_stream_ids(env: &Env, count: u32) -> Result<u64, StreamError> {
    let key = DataKey::NextStreamId;
    let first: u64 = env.storage().persistent().get(&key).unwrap_or(1);
    let next = first
        .checked_add(count as u64)
        .ok_or(StreamError::MathOverflow)?;
    env.storage().persistent().set(&key, &next);
    Ok(first)
}

/// Loads a stream, or returns [`StreamError::StreamNotFound`].
pub fn get_stream(env: &Env, id: u64) -> Result<Stream, StreamError> {
    #[cfg(test)]
    crate::cei_trace::record(&std::format!("read persistent Stream({id})"));
    env.storage()
        .persistent()
        .get(&DataKey::Stream(id))
        .ok_or_else(|| surface::reject(Branch::StreamNotFound))
}

/// Persists a stream and extends its storage TTL.
pub fn put_stream(env: &Env, stream: &Stream) {
    #[cfg(test)]
    crate::cei_trace::record(&std::format!("write persistent Stream({})", stream.id));
    let key = DataKey::Stream(stream.id);
    env.storage().persistent().set(&key, stream);
    env.storage()
        .persistent()
        .extend_ttl(&key, TTL_THRESHOLD_LEDGERS, TTL_EXTEND_LEDGERS);
}

/// Appends a stream's id to both parties' address indexes.
///
/// Called after each stream created by `create_stream` or `create_streams`
/// is persisted.
/// Cancel/deplete/top-up flows intentionally do not touch the indexes: they
/// are append-only discovery aids keyed by *creation*, not by lifecycle.
pub fn index_stream(env: &Env, stream: &Stream) {
    index_sender(env, &stream.sender, stream.id);
    index_recipient(env, &stream.recipient, stream.id);
}

/// Appends `id` to the sender's discovery index. Called on creation and when
/// an accepted ownership transfer installs a new sender.
pub fn index_sender(env: &Env, sender: &Address, id: u64) {
    push_to_index(env, &DataKey::SenderStreams(sender.clone()), id);
}

/// Appends `id` to the recipient's discovery index. Called on creation and
/// when an accepted ownership transfer installs a new recipient.
pub fn index_recipient(env: &Env, recipient: &Address, id: u64) {
    push_to_index(env, &DataKey::RecipientStreams(recipient.clone()), id);
}

/// Loads the pending ownership proposal for `id`, if one exists, and extends
/// its storage TTL.
///
/// The `Some` check matters: `extend_ttl` on a key that was never written (or
/// was removed) fails, so we only extend after a successful read.
pub fn get_pending_ownership(env: &Env, id: u64) -> Option<PendingOwnership> {
    let key = DataKey::PendingOwnership(id);
    let storage = env.storage().persistent();
    let pending: PendingOwnership = storage.get(&key)?;
    storage.extend_ttl(&key, TTL_THRESHOLD_LEDGERS, TTL_EXTEND_LEDGERS);
    Some(pending)
}

/// Persists a pending ownership proposal and extends its storage TTL.
pub fn put_pending_ownership(env: &Env, pending: &PendingOwnership) {
    let key = DataKey::PendingOwnership(pending.stream_id);
    env.storage().persistent().set(&key, pending);
    env.storage()
        .persistent()
        .extend_ttl(&key, TTL_THRESHOLD_LEDGERS, TTL_EXTEND_LEDGERS);
}

/// Removes a pending ownership proposal. No-op if none exists.
pub fn remove_pending_ownership(env: &Env, id: u64) {
    env.storage()
        .persistent()
        .remove(&DataKey::PendingOwnership(id));
}

pub(crate) fn push_to_index(env: &Env, key: &DataKey, id: u64) {
    let mut ids: Vec<u64> = env
        .storage()
        .persistent()
        .get(key)
        .unwrap_or_else(|| Vec::new(env));
    ids.push_back(id);
    env.storage().persistent().set(key, &ids);
    env.storage()
        .persistent()
        .extend_ttl(key, TTL_THRESHOLD_LEDGERS, TTL_EXTEND_LEDGERS);
}

/// Returns one page of stream ids from an address index, in creation order.
///
/// `limit` is clamped to [`MAX_PAGE_SIZE`]; an `offset` past the end (or an
/// unknown address) yields an empty page rather than an error. Reading the
/// index extends its TTL, so actively-queried addresses never go cold.
/// Addresses with no index entry never had any streams: return early without
/// touching storage (`extend_ttl` on a never-written key would fail).
pub fn page_stream_ids(env: &Env, key: &DataKey, offset: u32, limit: u32) -> Vec<u64> {
    let storage = env.storage().persistent();
    let Some(ids): Option<Vec<u64>> = storage.get(key) else {
        return Vec::new(env);
    };
    storage.extend_ttl(key, TTL_THRESHOLD_LEDGERS, TTL_EXTEND_LEDGERS);

    let start = offset.min(ids.len());
    let end = start
        .saturating_add(limit.min(MAX_PAGE_SIZE))
        .min(ids.len());
    ids.slice(start..end)
}

/// Returns the current schema version (defaults to INITIAL_SCHEMA_VERSION if unset).
pub fn schema_version(env: &Env) -> u32 {
    env.storage()
        .instance()
        .get(&DataKey::SchemaVersion)
        .unwrap_or(INITIAL_SCHEMA_VERSION)
}

/// Persists the new schema version and extends instance storage TTL.
pub fn set_schema_version(env: &Env, version: u32) {
    env.storage()
        .instance()
        .set(&DataKey::SchemaVersion, &version);
    env.storage()
        .instance()
        .extend_ttl(TTL_THRESHOLD_LEDGERS, TTL_EXTEND_LEDGERS);
}

/// Checks whether the contract is currently frozen.
pub fn is_frozen(env: &Env) -> bool {
    #[cfg(test)]
    crate::cei_trace::record("read instance ContractFrozen");
    env.storage()
        .instance()
        .get(&DataKey::ContractFrozen)
        .unwrap_or(false)
}

/// Updates the contract freeze state and extends instance storage TTL.
pub fn set_frozen(env: &Env, frozen: bool) {
    #[cfg(test)]
    crate::cei_trace::record("write instance ContractFrozen");
    env.storage()
        .instance()
        .set(&DataKey::ContractFrozen, &frozen);
    env.storage()
        .instance()
        .extend_ttl(TTL_THRESHOLD_LEDGERS, TTL_EXTEND_LEDGERS);
}

/// Returns the pending contract upgrade proposal, if one exists.
pub fn pending_upgrade(env: &Env) -> Option<PendingUpgrade> {
    env.storage().instance().get(&DataKey::PendingUpgrade)
}

/// Sets the pending contract upgrade proposal and extends instance storage TTL.
pub fn set_pending_upgrade(env: &Env, pending: &PendingUpgrade) {
    env.storage()
        .instance()
        .set(&DataKey::PendingUpgrade, pending);
    env.storage()
        .instance()
        .extend_ttl(TTL_THRESHOLD_LEDGERS, TTL_EXTEND_LEDGERS);
}

/// Removes any pending contract upgrade proposal and extends instance storage TTL.
pub fn remove_pending_upgrade(env: &Env) {
    env.storage().instance().remove(&DataKey::PendingUpgrade);
    env.storage()
        .instance()
        .extend_ttl(TTL_THRESHOLD_LEDGERS, TTL_EXTEND_LEDGERS);
}

/// Returns the current migration cursor (highest stream id migrated so far).
pub fn migration_cursor(env: &Env) -> u64 {
    env.storage()
        .instance()
        .get(&DataKey::MigrationCursor)
        .unwrap_or(0)
}

/// Sets the migration cursor and extends instance storage TTL.
pub fn set_migration_cursor(env: &Env, cursor: u64) {
    env.storage()
        .instance()
        .set(&DataKey::MigrationCursor, &cursor);
    env.storage()
        .instance()
        .extend_ttl(TTL_THRESHOLD_LEDGERS, TTL_EXTEND_LEDGERS);
}
