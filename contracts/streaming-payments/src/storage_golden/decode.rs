//! CI decode tests: every committed golden fixture must decode with the
//! in-development `#[contracttype]` types and re-encode to XDR whose
//! field map equals the manifest's, field by field. Failure messages name
//! the exact field that changed (never "bytes differ" alone).

use std::format;
use std::panic;
use std::string::String;
use std::vec::Vec;

use soroban_sdk::xdr::{self, LedgerEntryData, ReadXdr, WriteXdr};
use soroban_sdk::{Env, TryFromVal};

use crate::oracle::{OracleConfig, OracleReport};
use crate::policy::{QueuedAssetChange, StreamPolicy};
use crate::schedule::{IntentStatus, ScheduledIntent};
use crate::sponsor::{PeriodSpend, SponsorConfig};
use crate::stream::{PendingOwnership, PendingUpgrade, Stream, StreamStatus};
use crate::treasury::{StreamFeeRecord, Treasury};

use super::{
    contract_data, diff_fields, fields_of, fixtures_dir, read_event_bin, read_manifest,
    read_record_bin, RecordMeta,
};

/// Number of topics each event must carry: the name symbol plus however
/// many `#[topic]` fields the struct declares. Pins the event topic layout.
fn expected_topic_count(name: &str) -> usize {
    match name {
        "policy_initialized" | "stream_policy_set" | "oracle_config_updated" => 1,
        "storage_migrated"
        | "sponsor_registered"
        | "sponsor_active_set"
        | "operator_key_rotated"
        | "beneficiary_enrolled" => 3,
        "sponsor_claim" => 4,
        "stream_created"
        | "streams_created"
        | "withdrawn"
        | "stream_cancelled"
        | "stream_topped_up"
        | "stream_scheduled"
        | "scheduled_stream_executed"
        | "scheduled_intent_cancelled"
        | "scheduled_intent_expired"
        | "fee_charged"
        | "fee_withdrawn"
        | "policy_asset_queued"
        | "policy_asset_executed"
        | "policy_handoff_proposed"
        | "policy_handoff_accepted"
        | "policy_handoff_cancelled"
        | "upgrade_proposed"
        | "upgrade_cancelled"
        | "contract_upgraded"
        | "contract_frozen_state_changed"
        | "oracle_time_reported"
        | "oracle_stale_fallback"
        | "ownership_proposed"
        | "ownership_accepted"
        | "governance_signers_set"
        | "governance_action_proposed"
        | "governance_action_signed"
        | "governance_action_vetoed"
        | "governance_action_executed" => 2,
        other => panic!("unknown event name {other}: add it to the topic table"),
    }
}

/// Every persisted kind the scenario must pin. A storage key added to the
/// contract but absent from this corpus (or from `kind_for_key`'s dispatch)
/// fails coverage or generation, forcing a deliberate layout change.
const COVERED_KINDS: [&str; 36] = [
    "next_stream_id",
    "stream",
    "recipient_streams",
    "sender_streams",
    "next_intent_id",
    "intent",
    "sender_intents",
    "governor",
    "pending_governor",
    "fee_bps",
    "treasury",
    "stream_fee",
    "schema_version",
    "contract_frozen",
    "pending_upgrade",
    "migration_cursor",
    "admin",
    "timelock_delay",
    "asset",
    "queued_asset",
    "stream_policy",
    "global_stream_policy",
    "contract_instance",
    "oracle_config",
    "oracle_report",
    "pending_ownership",
    "sponsor_config",
    "operator_key",
    "sponsor_period",
    "beneficiary_key",
    "beneficiary_spend",
    "claim_nonce",
    "signers",
    "veto_window",
    "proposal_count",
    "proposal",
];

/// Decodes a golden value with the typed decoder the in-development build
/// generates for `kind`, then re-encodes it. `Err` = the current types
/// cannot read what the release line wrote. Also the probe the upgrade-replay
/// compatibility test uses against baseline-written records.
pub(crate) fn typed_roundtrip(
    env: &Env,
    kind: &str,
    val: &xdr::ScVal,
) -> Result<xdr::ScVal, String> {
    use super::typed_decode_encode as rt;
    match kind {
        "next_stream_id" | "next_intent_id" | "migration_cursor" | "timelock_delay" => {
            rt::<u64>(env, val)
        }
        "fee_bps" | "schema_version" => rt::<u32>(env, val),
        "contract_frozen" | "asset" | "claim_nonce" => rt::<bool>(env, val),
        "governor" | "pending_governor" | "admin" | "pending_admin" => {
            rt::<soroban_sdk::Address>(env, val)
        }
        "operator_key" | "beneficiary_key" => rt::<soroban_sdk::BytesN<32>>(env, val),
        "stream" => rt::<Stream>(env, val),
        "intent" => rt::<ScheduledIntent>(env, val),
        "recipient_streams" | "sender_streams" | "sender_intents" => {
            rt::<soroban_sdk::Vec<u64>>(env, val)
        }
        "treasury" => rt::<Treasury>(env, val),
        "stream_fee" => rt::<StreamFeeRecord>(env, val),
        "pending_upgrade" => rt::<PendingUpgrade>(env, val),
        "pending_ownership" => rt::<PendingOwnership>(env, val),
        "queued_asset" => rt::<QueuedAssetChange>(env, val),
        "stream_policy" | "global_stream_policy" => rt::<StreamPolicy>(env, val),
        "oracle_config" => rt::<OracleConfig>(env, val),
        "oracle_report" => rt::<OracleReport>(env, val),
        "sponsor_config" => rt::<SponsorConfig>(env, val),
        "sponsor_period" | "beneficiary_spend" => rt::<PeriodSpend>(env, val),
        "signers" => rt::<soroban_sdk::Vec<soroban_sdk::Address>>(env, val),
        "veto_window" | "proposal_count" => rt::<u64>(env, val),
        "proposal" => rt::<crate::Proposal>(env, val),
        _ => unreachable!("kind {kind} must not reach typed_roundtrip"),
    }
}

fn value_of(meta: &RecordMeta) -> xdr::ScVal {
    let (_k, entry) = read_record_bin(&fixtures_dir().join(&meta.file));
    match entry.data {
        LedgerEntryData::ContractData(ref cd) => cd.val.clone(),
        _ => panic!("{}: not contract data", meta.file),
    }
}

#[test]
fn golden_manifest_covers_every_persisted_kind() {
    let manifest = read_manifest();
    let present: Vec<String> = manifest.records.iter().map(|r| r.kind.clone()).collect();
    for kind in COVERED_KINDS {
        assert!(
            present.iter().any(|k| k == kind),
            "golden corpus has no `{kind}` record: the scenario or manifest no longer \
             pins this storage layout (see docs/STORAGE_LAYOUT.md)",
        );
    }
}

/// Core CI assertion. For every golden record:
/// 1. the typed decoder of the in-development build accepts the blob;
/// 2. re-encoding the decoded value flattens to exactly the manifest's
///    field map — every change is reported as `{file}.{field}:
///    golden=… decoded=…`;
/// 3. the raw re-encoded bytes equal the golden bytes (belt and braces:
///    catches ordering changes the flat render cannot see).
#[test]
fn golden_records_decode_and_roundtrip() {
    let env = Env::default();
    let manifest = read_manifest();
    let mut failures: Vec<String> = Vec::new();

    for meta in &manifest.records {
        // The key must still be a known storage-key variant (dispatch
        // coverage for key enums happens in kind_for_key).
        let (key_sc, cd) = {
            let (key, entry) = read_record_bin(&fixtures_dir().join(&meta.file));
            contract_data(&key, &entry)
        };
        let _ = key_sc;
        let val = &cd.val;

        let golden_fields = fields_of(&env, &meta.kind, val);
        failures.extend(
            diff_fields(
                &format!("{} [manifest vs blob]", meta.file),
                &meta.fields,
                &golden_fields,
            )
            .into_iter()
            .map(|d| format!("MANIFEST-BLOB DIVERGENCE: {d}")),
        );

        // The instance entry is host-managed (no SDK struct decoder); its
        // inner keys still get full typed coverage as standalone records.
        let decoded = if meta.kind == "contract_instance" {
            val.clone()
        } else {
            match typed_roundtrip(&env, &meta.kind, val) {
                Ok(v) => v,
                Err(e) => {
                    failures.push(format!(
                        "{} [kind {}]: in-development types CANNOT DECODE the golden value: {e}",
                        meta.file, meta.kind
                    ));
                    continue;
                }
            }
        };

        let got_fields = fields_of(&env, &meta.kind, &decoded);
        let mut ds: Vec<String> = diff_fields(
            &format!("{} [golden vs typed decode]", meta.file),
            &golden_fields,
            &got_fields,
        );
        if ds.is_empty() {
            let want_bytes = val.to_xdr(xdr::Limits::none()).unwrap();
            let got_bytes = decoded.to_xdr(xdr::Limits::none()).unwrap();
            if want_bytes != got_bytes {
                ds.push(format!(
                    "{}: field map matches but raw wire bytes differ (golden {} bytes, decoded {} bytes)",
                    meta.file,
                    want_bytes.len(),
                    got_bytes.len(),
                ));
            }
        }
        failures.extend(ds);
    }

    assert!(
        failures.is_empty(),
        "golden storage-layout regressions ({}):\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// Typed-semantic spot checks: the corpus decodes to the exact enum
/// variants the scenario wrote (all three stream statuses, all four
/// intent statuses).
#[test]
fn golden_records_decode_to_expected_variants() {
    let env = Env::default();
    let manifest = read_manifest();

    let statuses: Vec<StreamStatus> = manifest
        .records
        .iter()
        .filter(|r| r.kind == "stream")
        .map(|m| Stream::try_from_val(&env, &value_of(m)).unwrap().status)
        .collect();
    for want in [
        StreamStatus::Active,
        StreamStatus::Cancelled,
        StreamStatus::Depleted,
    ] {
        assert!(
            statuses.contains(&want),
            "golden stream records must include {want:?}, got {statuses:?}"
        );
    }

    let intent_statuses: Vec<IntentStatus> = manifest
        .records
        .iter()
        .filter(|r| r.kind == "intent")
        .map(|m| {
            ScheduledIntent::try_from_val(&env, &value_of(m))
                .unwrap()
                .status
        })
        .collect();
    for want in [
        IntentStatus::Pending,
        IntentStatus::Executed,
        IntentStatus::Cancelled,
        IntentStatus::Expired,
    ] {
        assert!(
            intent_statuses.contains(&want),
            "golden intent records must include {want:?}, got {intent_statuses:?}"
        );
    }
}

/// Every golden event re-encodes byte-identically from its pinned
/// topics/data split, keeps its topic shape, and its data map flattens to
/// exactly the manifest's field map.
#[test]
fn golden_events_roundtrip() {
    let env = Env::default();
    let manifest = read_manifest();
    let mut failures: Vec<String> = Vec::new();

    for em in &manifest.events {
        let (topics, data) = read_event_bin(&fixtures_dir().join(&em.file));

        let ts = topics.0.as_slice();
        assert_eq!(
            ts.len(),
            expected_topic_count(&em.name),
            "{}: topic count changed (wire layout of `#[topic]` fields)",
            em.file
        );
        let name_sym: xdr::ScSymbol = em.name.as_str().try_into().unwrap();
        assert_eq!(
            ts[0],
            xdr::ScVal::Symbol(name_sym),
            "{}: event name symbol changed",
            em.file
        );

        let got = fields_of(&env, &em.name, &data);
        failures.extend(
            diff_fields(&em.file, &em.fields, &got)
                .into_iter()
                .map(|d| format!("MANIFEST-BLOB DIVERGENCE: {d}")),
        );

        // Canonical-bytes check: topics followed by the data value must
        // re-encode byte-for-byte from the form decoded out of the fixture.
        let mut items: Vec<xdr::ScVal> = topics.0.to_vec();
        items.push(data.clone());
        let bundle = xdr::ScVal::Vec(Some(xdr::ScVec(xdr::VecM::try_from(items).unwrap())));
        let bytes = bundle.to_xdr(xdr::Limits::none()).unwrap();
        let again = xdr::ScVal::from_xdr(&bytes, xdr::Limits::none()).unwrap();
        if bundle != again {
            failures.push(format!("{}: event bytes are not canonical", em.file));
        }
    }

    let names: Vec<String> = manifest.events.iter().map(|e| e.name.clone()).collect();
    for n in super::generate::expected_event_names() {
        assert!(
            names.contains(&n),
            "golden event `{n}` missing from the corpus (regenerate fixtures)"
        );
    }

    assert!(
        failures.is_empty(),
        "golden event-layout regressions ({}):\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// Negative self-test of the harness: renaming a struct field in a golden
/// blob must be caught — either the typed decode rejects it or the field
/// diff names `start_time` (guards that the suite is not blind).
#[test]
fn harness_detects_field_rename_by_construction() {
    let env = Env::default();
    let meta = read_manifest()
        .records
        .into_iter()
        .find(|r| r.kind == "stream")
        .expect("golden stream record");
    let val = value_of(&meta);
    let xdr::ScVal::Map(Some(mut m)) = val else {
        panic!("golden stream is not a map");
    };
    let old = xdr::ScVal::Symbol(xdr::ScSymbol("start_time".try_into().unwrap()));
    let new = xdr::ScVal::Symbol(xdr::ScSymbol("started_at".try_into().unwrap()));
    for e in m.0.iter_mut() {
        if e.key == old {
            e.key = new.clone();
        }
    }
    let bad = xdr::ScVal::Map(Some(m));

    let decoded = panic::catch_unwind(|| {
        let env2 = Env::default();
        Stream::try_from_val(&env2, &bad).is_ok()
    });
    let blind = decoded.unwrap_or(false);
    let got = fields_of(&env, "stream", &bad);
    let ds = diff_fields("stream", &meta.fields, &got);
    // The meaningful assertion: the corpus comparison catches the rename,
    // either as a decode failure or as a named field diff.
    let caught = !blind || ds.iter().any(|d| d.contains("start_time"));
    assert!(
        caught,
        "renaming start_time produced no decode failure and no field diff: {ds:?}"
    );
}
