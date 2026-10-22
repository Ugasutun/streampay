//! Fixture corpus for the golden storage-layout regression suite (issue #210).
//!
//! Storage layout is silently broken by record changes that keep Rust
//! semantics but shift the on-ledger XDR — renamed fields and enum variants
//! (the symbol-named encoding writes variant/field names onto the wire),
//! retyped fields, and new or removed keys. This module builds the corpus
//! that net pins:
//!
//! * `scenario` — one deterministic scenario that writes an instance of every
//!   persisted record type and emits every `#[contractevent]` the contract has.
//! * `generate` — a `#[ignore]`d test that runs the scenario and dumps the exact
//!   `LedgerKey`/`LedgerEntry` XDR (plus emitted-event XDR) and a field-level
//!   manifest under `test_fixtures/storage/`.
//!
//! Regenerate after any storage-layout change:
//!
//! ```text
//! cargo test -p streampay-contract --lib --locked storage_golden::generate -- --ignored
//! ```
//!
//! Decoding the committed blobs back with the in-development types, and the
//! assertions that fail when the layout moves, live alongside this generator.

#![cfg(test)]

extern crate std;

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::format;
use std::path::{Path, PathBuf};
use std::string::{String, ToString};
use std::vec::Vec;

use serde::{Deserialize, Serialize};
use soroban_sdk::xdr::{
    self, ContractDataEntry, LedgerEntry, LedgerEntryData, LedgerKey, LedgerKeyContractData,
    WriteXdr,
};
use soroban_sdk::{Env, IntoVal, TryFromVal, Val};
pub(crate) mod generate;
pub(crate) mod scenario;

/// Repo-level fixture directory: `<repo root>/test_fixtures/storage`.
pub(crate) fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../test_fixtures/storage")
}

pub(crate) fn records_dir() -> PathBuf {
    fixtures_dir().join("records")
}

pub(crate) fn events_dir() -> PathBuf {
    fixtures_dir().join("events")
}

pub(crate) fn manifest_path() -> PathBuf {
    fixtures_dir().join("manifest.json")
}

/// Baseline (release-line, v0.3.0) wasm. The scenario uploads it as the
/// upgrade target its `ContractUpgraded` payload points at, and the replay
/// harness boots it to compare a released build against the in-development
/// one.
pub(crate) fn baseline_wasm_path() -> PathBuf {
    fixtures_dir().join("baseline/streampay-v0.3.0-baseline.wasm")
}

/// The committed baseline artifact, verified against the digest pinned in
/// `baseline/BASELINE.sha256`. Every reader of the baseline bytecode goes
/// through here: a swapped or corrupted artifact fails loudly before the
/// replay boots or upgrades from it, instead of silently treating the wrong
/// bytes as the released build.
pub(crate) fn baseline_wasm_bytes(env: &Env) -> Vec<u8> {
    use soroban_sdk::Bytes;
    let path = baseline_wasm_path();
    let bytes = std::fs::read(&path)
        .unwrap_or_else(|e| panic!("{} is a committed fixture: {e}", path.display()));
    let sums_path = fixtures_dir().join("baseline/BASELINE.sha256");
    let sums = std::fs::read_to_string(&sums_path)
        .unwrap_or_else(|e| panic!("{} pins the baseline digest: {e}", sums_path.display()));
    let pinned = sums
        .lines()
        .map(|l| l.trim())
        .find(|l| !l.is_empty() && !l.starts_with('#'))
        .and_then(|l| l.split_whitespace().next())
        .expect("BASELINE.sha256 has no digest line");
    let got = env
        .crypto()
        .sha256(&Bytes::from_slice(env, &bytes))
        .to_bytes()
        .to_array();
    let got: String = got.iter().map(|b| format!("{b:02x}")).collect();
    if got != pinned {
        panic!(
            "baseline wasm digest mismatch: {} hashes to {got} but {} pins {pinned}: \
             the replay must boot exactly the pinned release bytes (see \
             docs/STORAGE_LAYOUT.md, 'Replacing the baseline wasm')",
            path.display(),
            sums_path.display(),
        );
    }
    bytes
}

// ------------------------------------------------------------- xdr <-> bin --

/// Record blob layout: `u32le | LedgerKey xdr | u32le | LedgerEntry xdr`.
pub(crate) fn write_record_bin(
    path: &Path,
    key: &LedgerKey,
    entry: &LedgerEntry,
) -> Result<(), String> {
    let key_bytes = key
        .to_xdr(xdr::Limits::none())
        .map_err(|e| format!("key to_xdr: {e:?}"))?;
    let entry_bytes = entry
        .to_xdr(xdr::Limits::none())
        .map_err(|e| format!("entry to_xdr: {e:?}"))?;
    let mut out = Vec::new();
    out.extend_from_slice(&(key_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&key_bytes);
    out.extend_from_slice(&(entry_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&entry_bytes);
    std::fs::write(path, out).map_err(|e| format!("write {}: {e}", path.display()))
}

/// Event blob layout: `u32le | ScVec topics xdr | u32le | ScVal data xdr`.
pub(crate) fn write_event_bin(
    path: &Path,
    topics: &xdr::ScVec,
    data: &xdr::ScVal,
) -> Result<(), String> {
    let topics_bytes = topics
        .to_xdr(xdr::Limits::none())
        .map_err(|e| format!("topics to_xdr: {e:?}"))?;
    let data_bytes = data
        .to_xdr(xdr::Limits::none())
        .map_err(|e| format!("data to_xdr: {e:?}"))?;
    let mut out = Vec::new();
    out.extend_from_slice(&(topics_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&topics_bytes);
    out.extend_from_slice(&(data_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&data_bytes);
    std::fs::write(path, out).map_err(|e| format!("write {}: {e}", path.display()))
}

/// Extracts the `(key, ContractDataEntry)` of a record blob. The durability
/// lives on the entry (the key's is authoritative for the LedgerKey form).
pub(crate) fn contract_data(
    key: &LedgerKey,
    entry: &LedgerEntry,
) -> (xdr::ScVal, ContractDataEntry) {
    let LedgerKey::ContractData(LedgerKeyContractData { key: k, .. }) = key else {
        panic!("fixture key is not a ContractData ledger key");
    };
    let LedgerEntryData::ContractData(cd) = &entry.data else {
        panic!("fixture entry is not a ContractData ledger entry");
    };
    (k.clone(), cd.clone())
}

/// The main contract's events from one invocation, in emission order.
pub(crate) fn events_from(
    env: &Env,
    all: &soroban_sdk::testutils::ContractEvents,
    contract: &soroban_sdk::Address,
) -> Vec<xdr::ContractEvent> {
    let want = Some(contract_id(env, contract));
    all.events()
        .iter()
        .filter(|e| e.contract_id == want)
        .cloned()
        .collect()
}

/// The 32-byte contract id behind a deployed contract address. Host-free
/// lookups (snapshot scanning, event filtering) need the raw hash, and the
/// address must be read back through the env that owns it.
pub(crate) fn contract_id(env: &Env, a: &soroban_sdk::Address) -> xdr::ContractId {
    let val: Val = a.clone().into_val(env);
    match xdr::ScVal::try_from_val(env, &val).expect("address scval") {
        xdr::ScVal::Address(xdr::ScAddress::Contract(h)) => h,
        other => panic!("not a contract address: {other:?}"),
    }
}

/// The contract id of a snapshot ledger key's contract, if it is one.
pub(crate) fn sc_address_contract_id(a: &xdr::ScAddress) -> Option<&xdr::ContractId> {
    match a {
        xdr::ScAddress::Contract(h) => Some(h),
        _ => None,
    }
}

// ------------------------------------------------------------------ render --

/// Deterministic textual rendering of an `ScVal`, shared by the generator
/// manifest and the decode tests. The grammar is layout-sensitive: map key
/// symbols, vec element order (including enum variant symbols), and the
/// concrete `ScVal` variant of every scalar are all part of the output, so
/// any wire change shows up as a field-level string diff.
pub(crate) fn render(env: &Env, sc: &xdr::ScVal) -> String {
    let _ = env;
    match sc {
        xdr::ScVal::Void => "void".to_string(),
        xdr::ScVal::Bool(b) => format!("bool:{b}"),
        xdr::ScVal::U32(v) => format!("u32:{v}"),
        xdr::ScVal::I32(v) => format!("i32:{v}"),
        xdr::ScVal::U64(v) => format!("u64:{v}"),
        xdr::ScVal::I64(v) => format!("i64:{v}"),
        xdr::ScVal::Timepoint(v) => format!("timepoint:{}", u64::from(v.clone())),
        xdr::ScVal::Duration(v) => format!("duration:{}", u64::from(v.clone())),
        xdr::ScVal::U128(u) => format!("u128:{}", (u.hi as u128) << 64 | u.lo as u128),
        xdr::ScVal::I128(i) => format!(
            "i128:{}",
            (i.hi as i128) << 64 | (i.lo as i128) & u64::MAX as i128
        ),
        xdr::ScVal::U256(u) => format!(
            "u256:{:016x}{:016x}{:016x}{:016x}",
            u.hi_hi, u.hi_lo, u.lo_hi, u.lo_lo
        ),
        xdr::ScVal::I256(_) | xdr::ScVal::Error(_) => format!("{sc:?}"),
        xdr::ScVal::Bytes(b) => format!("bytes:{}", hex(&b.0)),
        xdr::ScVal::String(s) => format!("string:{}", s.to_utf8_string_lossy()),
        xdr::ScVal::Symbol(s) => format!("symbol:{}", s.to_utf8_string_lossy()),
        xdr::ScVal::Vec(Some(v)) => {
            let items: Vec<String> = v.0.iter().map(|e| render(env, e)).collect();
            format!("vec[{}]", items.join(","))
        }
        xdr::ScVal::Vec(None) => "vec[]".to_string(),
        xdr::ScVal::Map(Some(m)) => {
            let items: Vec<String> =
                m.0.iter()
                    .map(|e| format!("{}={}", render(env, &e.key), render(env, &e.val)))
                    .collect();
            format!("map{{{}}}", items.join(","))
        }
        xdr::ScVal::Map(None) => "map{}".to_string(),
        xdr::ScVal::Address(a) => format!("address:{}", render_address(a)),
        xdr::ScVal::ContractInstance(inst) => {
            let executable = match &inst.executable {
                xdr::ContractExecutable::Wasm(h) => format!("wasm:{}", hex(&h.0)),
                xdr::ContractExecutable::StellarAsset => "stellar_asset".to_string(),
                xdr::ContractExecutable::ExternalRef(_) => "external_ref".to_string(),
            };
            let storage = match &inst.storage {
                Some(m) => {
                    let items: Vec<String> =
                        m.0.iter()
                            .map(|e| format!("{}={}", render(env, &e.key), render(env, &e.val)))
                            .collect();
                    items.join(";")
                }
                None => String::new(),
            };
            format!("instance{{{executable};{storage}}}")
        }
        xdr::ScVal::LedgerKeyContractInstance => "ledger_key_contract_instance".to_string(),
        xdr::ScVal::LedgerKeyNonce(n) => format!("ledger_key_nonce:{}", n.nonce),
        xdr::ScVal::ExecutableTag(t) => format!("executable_tag:{}", t.to_utf8_string_lossy()),
    }
}

fn render_address(a: &xdr::ScAddress) -> String {
    match a {
        xdr::ScAddress::Account(_) | xdr::ScAddress::Contract(_) => format!("{a}"),
        xdr::ScAddress::MuxedAccount(m) => format!("{}", m.ed25519),
        xdr::ScAddress::ClaimableBalance(_) | xdr::ScAddress::LiquidityPool(_) => {
            format!("{a:?}")
        }
    }
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

// ------------------------------------------------------------------ labels --

/// Stable, address-independent kind name for a storage key: the snake-case
/// of the `DataKey`/`PolicyDataKey` variant (or `contract_instance`). This
/// is the manifest's dispatch key: adding a new storage variant without a
/// dispatch arm here fails the generator and the decode test by
/// construction, which is the point.
pub(crate) fn kind_for_key(env: &Env, key_sc: &xdr::ScVal) -> Option<String> {
    use crate::governance::GovernanceDataKey;
    use crate::policy::PolicyDataKey;
    use crate::sponsor::SponsorKey;
    use crate::stream::DataKey;
    if key_sc == &xdr::ScVal::LedgerKeyContractInstance {
        return Some("contract_instance".to_string());
    }
    if let Ok(dk) = DataKey::try_from_val(env, key_sc) {
        return Some(sanitize(match dk {
            DataKey::NextStreamId => "next_stream_id",
            DataKey::Stream(_) => "stream",
            DataKey::RecipientStreams(_) => "recipient_streams",
            DataKey::SenderStreams(_) => "sender_streams",
            DataKey::NextIntentId => "next_intent_id",
            DataKey::Intent(_) => "intent",
            DataKey::SenderIntents(_) => "sender_intents",
            DataKey::Governor => "governor",
            DataKey::PendingGovernor => "pending_governor",
            DataKey::FeeBps => "fee_bps",
            DataKey::Treasury(_) => "treasury",
            DataKey::StreamFee(_) => "stream_fee",
            DataKey::SchemaVersion => "schema_version",
            DataKey::ContractFrozen => "contract_frozen",
            DataKey::PendingUpgrade => "pending_upgrade",
            DataKey::MigrationCursor => "migration_cursor",
            DataKey::OracleConfig => "oracle_config",
            DataKey::OracleReport(_) => "oracle_report",
            DataKey::PendingOwnership(_) => "pending_ownership",
        }));
    }
    if let Ok(pk) = PolicyDataKey::try_from_val(env, key_sc) {
        return Some(sanitize(match pk {
            PolicyDataKey::Admin => "admin",
            PolicyDataKey::PendingAdmin => "pending_admin",
            PolicyDataKey::TimelockDelay => "timelock_delay",
            PolicyDataKey::Asset(_) => "asset",
            PolicyDataKey::QueuedAsset(_) => "queued_asset",
            PolicyDataKey::StreamPolicy(_) => "stream_policy",
            PolicyDataKey::GlobalStreamPolicy => "global_stream_policy",
        }));
    }
    if let Ok(sk) = SponsorKey::try_from_val(env, key_sc) {
        return Some(sanitize(match sk {
            SponsorKey::SponsorConfig(_) => "sponsor_config",
            SponsorKey::OperatorKey(_) => "operator_key",
            SponsorKey::SponsorPeriod(_) => "sponsor_period",
            SponsorKey::BeneficiaryKey(_) => "beneficiary_key",
            SponsorKey::BeneficiarySpend(_, _) => "beneficiary_spend",
            SponsorKey::ClaimNonce(_, _, _) => "claim_nonce",
        }));
    }
    if let Ok(gk) = GovernanceDataKey::try_from_val(env, key_sc) {
        return Some(sanitize(match gk {
            GovernanceDataKey::Signers => "signers",
            GovernanceDataKey::VetoWindow => "veto_window",
            GovernanceDataKey::ProposalCount => "proposal_count",
            GovernanceDataKey::Proposal(_) => "proposal",
        }));
    }
    None
}

/// Filesystem-safe record name derived from a label.
pub(crate) fn sanitize(label: &str) -> String {
    let mut out = String::new();
    for c in label.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
        } else if !out.ends_with('_') {
            out.push('_');
        }
    }
    let trimmed = out.trim_matches('_').to_string();
    // Address-keyed labels differ only past char 40 of the strkey; cap length
    // and rely on the manifest `key` render for exact identity.
    if trimmed.len() > 48 {
        trimmed[..48].to_string()
    } else {
        trimmed
    }
}

// ------------------------------------------------------- field-level diffs --

/// Flattens a golden value ScVal into (field name -> render) pairs for the
/// manifest and the decode diff. Struct maps key by field symbol; everything
/// else lives under the single `value` key. Instance entries flatten their
/// per-key storage entries.
pub(crate) fn fields_of(env: &Env, kind: &str, val: &xdr::ScVal) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    match (kind, val) {
        ("contract_instance", xdr::ScVal::ContractInstance(inst)) => {
            let exec = match &inst.executable {
                xdr::ContractExecutable::Wasm(h) => format!("wasm:{}", hex(&h.0)),
                other => format!("{other:?}"),
            };
            out.insert("executable".to_string(), exec);
            if let Some(m) = &inst.storage {
                for e in m.0.iter() {
                    out.insert(
                        format!("storage[{}]", render(env, &e.key)),
                        render(env, &e.val),
                    );
                }
            }
            out
        }
        (_, xdr::ScVal::Map(Some(m))) => {
            for e in m.0.iter() {
                let key = match &e.key {
                    xdr::ScVal::Symbol(s) => s.to_utf8_string_lossy(),
                    other => render(env, other),
                };
                out.insert(key, render(env, &e.val));
            }
            out
        }
        _ => {
            out.insert("value".to_string(), render(env, val));
            out
        }
    }
}

// ------------------------------------------------------------- manifest ----

/// One committed storage record and its field-level golden rendering.
///
/// `kind` is a stable, environment-independent name derived from the
/// storage-key variant (never from an address); `key` is the full `render`
/// of the ScVal key for human review; `fields` maps each field name to its
/// golden rendering. The decode test diffs these field-by-field after
/// decoding the blob with the in-development types.
#[derive(Serialize, Deserialize)]
pub(crate) struct RecordMeta {
    pub file: String,
    pub kind: String,
    pub durability: String,
    pub key: String,
    pub fields: BTreeMap<String, String>,
}

/// One committed event payload, keyed by event name (first topic).
#[derive(Serialize, Deserialize)]
pub(crate) struct EventMeta {
    pub file: String,
    pub name: String,
    pub topics: String,
    pub data: String,
    pub fields: BTreeMap<String, String>,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct Manifest {
    pub records: Vec<RecordMeta>,
    pub events: Vec<EventMeta>,
}
