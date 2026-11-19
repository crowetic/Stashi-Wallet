//! Explicitly approved, restart-safe Ironwood -> owned Sapling preparation.
//! The signed transaction is durable before any input reservation or network call.
use super::*;
use pirate_core::selection::{NoteType, SelectableNote};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fs::{File, OpenOptions};
use std::io::Write;

const FEE: u64 = 10_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QortalPreparationRequest {
    pub input: String,
    /// Total required for the contract, including the subsequent funding fee.
    pub required_amount: u64,
    /// Absent for a read-only quote/status. Exact quote approval is required to sign.
    pub approved_quote: Option<String>,
    pub max_fee: Option<u64>,
}

#[derive(Serialize, Deserialize)]
struct Journal {
    version: u32,
    network: String,
    source_key_id: i64,
    destination: String,
    quote: String,
    signed: SignedTx,
    context: tx_flow::BroadcastContext,
}

fn private_file(path: &Path, create_new: bool) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    if create_new {
        options.create_new(true);
    } else {
        options.create(true).truncate(false);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    Ok(options.open(path)?)
}

fn save_journal(path: &Path, journal: &Journal) -> Result<()> {
    // Never replace an outstanding intent. A crash leaves either no final file or
    // the complete signed transaction. Temporary files cannot authorize broadcast.
    anyhow::ensure!(
        !path.exists(),
        "Preparation intent already exists; resume it instead"
    );
    let temp = path.with_extension(format!("{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| -> Result<()> {
        let mut file = private_file(&temp, true)?;
        file.write_all(&serde_json::to_vec(journal)?)?;
        file.sync_all()?;
        fs::rename(&temp, path)?;
        #[cfg(unix)]
        File::open(
            path.parent()
                .ok_or_else(|| anyhow!("Missing journal directory"))?,
        )?
        .sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result
}

fn totals(notes: &[SelectableNote]) -> Result<(u64, u64)> {
    notes
        .iter()
        .try_fold((0u64, 0u64), |(sapling, ironwood), note| {
            match note.note_type {
                NoteType::Sapling => Ok((
                    sapling
                        .checked_add(note.value)
                        .ok_or_else(|| anyhow!("Balance overflow"))?,
                    ironwood,
                )),
                NoteType::Ironwood => Ok((
                    sapling,
                    ironwood
                        .checked_add(note.value)
                        .ok_or_else(|| anyhow!("Balance overflow"))?,
                )),
            }
        })
}

fn quote_id(
    wallet: &str,
    network: &str,
    key: i64,
    destination: &str,
    required: u64,
    target_height: u64,
    notes: &[SelectableNote],
) -> Result<String> {
    let mut inputs = notes
        .iter()
        .map(|n| {
            let nf = n
                .nullifier
                .as_ref()
                .filter(|nf| nf.len() == 32)
                .ok_or_else(|| anyhow!("Preparation input nullifier is missing"))?;
            Ok((hex::encode(nf), n.value))
        })
        .collect::<Result<Vec<_>>>()?;
    inputs.sort();
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(&(
        1,
        wallet,
        network,
        key,
        destination,
        required,
        target_height,
        FEE,
        inputs,
    ))?)))
}

fn reserve(repo: &Repository, journal: &Journal) -> Result<()> {
    let ctx = &journal.context;
    let txid = <[u8; 32]>::try_from(hex::decode(&journal.signed.txid)?.as_slice())
        .map_err(|_| anyhow!("Invalid preparation transaction ID"))?;
    let nullifiers = ctx
        .spent_nullifiers
        .iter()
        .map(|nf| {
            <[u8; 32]>::try_from(nf.as_slice()).map_err(|_| anyhow!("Invalid preparation input"))
        })
        .collect::<Result<Vec<_>>>()?;
    // Intent first: a crash between these writes remains recoverable and expiry
    // reconciliation always has the information needed to release reserved notes.
    repo.upsert_outgoing_transaction_intent(
        ctx.account_id,
        &journal.signed.txid,
        ctx.sent_amount,
        ctx.fee,
        (ctx.created_at_ms / 1000) as i64,
        ctx.expiry_height,
    )?;
    repo.reserve_signed_transaction_inputs(ctx.account_id, &nullifiers, &txid)?;
    Ok(())
}

fn validate_journal(
    journal: &Journal,
    wallet: &str,
    network: &str,
    key: i64,
    account: i64,
) -> Result<()> {
    anyhow::ensure!(
        journal.version == 1
            && journal.context.wallet_id == wallet
            && journal.network == network
            && journal.source_key_id == key
            && journal.context.account_id == account
            && journal.context.fee == FEE
            && journal.context.change_amount == 0
            && journal.context.expiry_height > 0,
        "Preparation journal does not match this wallet; preserve it for recovery"
    );
    let tx = read_pirate_transaction(&journal.signed.raw)?;
    anyhow::ensure!(
        tx.txid().to_string() == journal.signed.txid
            && journal.signed.raw.len() == journal.signed.size,
        "Preparation journal transaction is corrupt; preserve it for recovery"
    );
    Ok(())
}

/// Query without approval; with exact approval, sign once and rebroadcast only
/// the saved bytes. The destination is derived locally, never supplied by callers.
pub async fn qortal_trade_preparation(
    wallet_id: WalletId,
    request: QortalPreparationRequest,
) -> Result<Value> {
    require_wallet_signing_session(&wallet_id)?;
    anyhow::ensure!(
        request.approved_quote.is_some() == request.max_fee.is_some(),
        "Preparation approval must include its exact fee"
    );
    anyhow::ensure!(
        request.required_amount > 0,
        "Trade funding amount must be positive"
    );
    sync_control::require_spendability_ready_with_sync_trigger(&wallet_id)?;
    let db_path = encrypted_db::wallet_db_path_for(&wallet_id)?;
    // OS lock is released on process exit; no stale lock deletion or timeout guess.
    let lock = private_file(&db_path.with_extension("qortal-preparation.lock"), false)?;
    lock.try_lock()
        .map_err(|_| anyhow!("Another preparation request is active"))?;
    let (db, repo) = open_wallet_db_for(&wallet_id)?;
    let secret = repo
        .get_wallet_secret(&wallet_id)?
        .ok_or_else(|| anyhow!("Wallet secret is missing"))?;
    let source =
        qortal::resolve_qortal_source_key_id(&repo, secret.account_id, &wallet_id, &request.input)?;
    let network_type = match get_wallet_meta(&wallet_id)?.network_type.as_deref() {
        Some("testnet") => NetworkType::Testnet,
        Some("regtest") => NetworkType::Regtest,
        None | Some("mainnet") => NetworkType::Mainnet,
        Some(_) => return Err(anyhow!("Unknown preparation wallet network")),
    };
    let network = format!("{network_type:?}");
    let path = db_path.with_extension(format!("qortal-preparation-{source}.json"));
    let mut existing = if path.exists() {
        let journal: Journal = serde_json::from_slice(&fs::read(&path)?)?;
        validate_journal(&journal, &wallet_id, &network, source, secret.account_id)?;
        let state = pirate_storage_sqlite::SyncStateStorage::new(&db).load_sync_state()?;
        if repo.outgoing_transaction_is_confirmed(&journal.signed.txid)?
            || state.local_height > u64::from(journal.context.expiry_height)
        {
            repo.release_expired_outgoing_notes(secret.account_id, state.local_height)?;
            fs::rename(
                &path,
                path.with_extension(format!("{}.completed", journal.signed.txid)),
            )?;
            None
        } else {
            Some(journal)
        }
    } else {
        None
    };
    if let Some(ref journal) = existing {
        reserve(&repo, journal)?;
    }
    let (anchors, notes) = qortal_p2sh::load_funding_notes(&db, &repo, secret.account_id, source)?;
    let (sapling, ironwood) = totals(&notes)?;
    let total = sapling
        .checked_add(ironwood)
        .ok_or_else(|| anyhow!("Balance overflow"))?;
    if existing.is_none() && sapling > 0 && total >= request.required_amount {
        return Ok(json!({"status":"ready", "saplingAmount":sapling, "ironwoodAmount":ironwood}));
    }
    if existing.is_none()
        && (sapling > 0
            || ironwood
                .checked_sub(FEE)
                .is_none_or(|n| n < request.required_amount))
    {
        return Ok(
            json!({"status":"insufficient", "saplingAmount":sapling, "ironwoodAmount":ironwood}),
        );
    }
    let mut journal = if let Some(journal) = existing.take() {
        journal
    } else {
        let key = repo
            .get_account_key_by_id(source)?
            .ok_or_else(|| anyhow!("Source key is missing"))?;
        let key_bytes = key
            .sapling_extsk
            .as_deref()
            .ok_or_else(|| anyhow!("Source Sapling spending key is missing"))?;
        let spending = ExtendedSpendingKey::from_bytes(key_bytes)
            .map_err(|e| anyhow!("Invalid Sapling key: {e}"))?;
        let destination = spending
            .to_extended_fvk()
            .derive_address(0)
            .encode_for_network(network_type);
        // Register the owned external address before output construction, allowing
        // scanning to discover the preparation output even across a restart.
        let address = spending.to_extended_fvk().derive_address(0);
        let diversifier_index_88 = spending
            .to_extended_fvk()
            .diversifier_index(&address)
            .map(|(i, _)| i);
        let quote = quote_id(
            &wallet_id,
            &network,
            source,
            &destination,
            request.required_amount,
            anchors.target_height,
            &notes,
        )?;
        let amount = ironwood - FEE;
        if request.approved_quote.as_deref() != Some(&quote) || request.max_fee != Some(FEE) {
            anyhow::ensure!(
                request.approved_quote.is_none(),
                "Preparation quote changed; request and approve a new quote"
            );
            return Ok(
                json!({"status":"needsPreparation", "quoteId":quote, "fee":FEE,
                "amount":amount, "destination":destination, "saplingAmount":sapling, "ironwoodAmount":ironwood}),
            );
        }
        if let Some(owned) = repo.get_address_by_string(secret.account_id, &destination)? {
            anyhow::ensure!(
                owned.key_id == Some(source),
                "Preparation destination key metadata is inconsistent"
            );
        } else {
            repo.upsert_address(&StoredAddress {
                id: None,
                key_id: Some(source),
                account_id: secret.account_id,
                diversifier_index: 0,
                diversifier_index_88,
                address: destination.clone(),
                address_type: AddressType::Sapling,
                label: None,
                created_at: chrono::Utc::now().timestamp(),
                color_tag: DbColorTag::None,
                address_scope: StoredAddressScope::External,
            })?;
        }
        let filter = Some(vec![source]);
        let pending = build_tx_filtered(
            wallet_id.clone(),
            vec![Output::new(destination.clone(), amount, None)],
            Some(FEE),
            filter.clone(),
            None,
        )?;
        anyhow::ensure!(
            pending.fee == FEE
                && pending.change == 0
                && pending.total_amount == amount
                && pending.input_total == ironwood,
            "Preparation amount or fee changed; no transaction was signed"
        );
        let signed = sign_tx_filtered(wallet_id.clone(), pending, filter, None)?;
        let context = tx_flow::saved_broadcast_context(&signed.txid)?;
        let journal = Journal {
            version: 1,
            network,
            source_key_id: source,
            destination,
            quote,
            signed,
            context,
        };
        validate_journal(
            &journal,
            &wallet_id,
            &journal.network,
            source,
            secret.account_id,
        )?;
        save_journal(&path, &journal)?;
        journal
    };
    reserve(&repo, &journal)?;
    let mut broadcast_attempted = false;
    // Pending status never sends. Resubmission requires explicit approval of the
    // original quote and fee; it reuses bytes even if balance/input selection changed.
    if request.approved_quote.as_deref() == Some(&journal.quote) && request.max_fee == Some(FEE) {
        journal.context.created_at_ms = unix_timestamp_millis();
        tx_flow::store_broadcast_context(&journal.signed.txid, journal.context.clone());
        drop(repo);
        drop(db);
        broadcast_attempted = true;
        // Unknown acceptance remains pending. It must never prompt a replacement
        // transaction; the signed journal is retained until scan/expiry resolves it.
        if let Err(error) =
            tx_flow::broadcast_tx_for_wallet(wallet_id, journal.signed.clone()).await
        {
            tracing::warn!(txid = %journal.signed.txid, %error,
                "ARRR preparation acceptance is unresolved; retaining the signed transaction for recovery");
        }
    }
    Ok(
        json!({"status":"pending", "txid":journal.signed.txid, "quoteId":journal.quote,
        "fee":FEE, "amount":journal.context.sent_amount, "destination":journal.destination,
        "broadcastAttempted":broadcast_attempted}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn note(value: u64, tag: u8) -> SelectableNote {
        let mut note = SelectableNote::new(value, vec![tag; 32], 100, vec![tag; 32], 0);
        note.note_type = NoteType::Ironwood;
        note.nullifier = Some(vec![tag; 32]);
        note
    }
    #[test]
    fn qortal_preparation_quote_binds_owned_destination_wallet_network_amount_and_inputs() {
        let notes = vec![note(50_000, 1), note(60_000, 2)];
        let quote = quote_id("wallet", "Mainnet", 1, "owned", 40_000, 100, &notes).unwrap();
        assert_eq!(
            quote,
            quote_id(
                "wallet",
                "Mainnet",
                1,
                "owned",
                40_000,
                100,
                &[note(60_000, 2), note(50_000, 1)]
            )
            .unwrap()
        );
        for other in [
            quote_id("other", "Mainnet", 1, "owned", 40_000, 100, &notes),
            quote_id("wallet", "Testnet", 1, "owned", 40_000, 100, &notes),
            quote_id("wallet", "Mainnet", 2, "owned", 40_000, 100, &notes),
            quote_id("wallet", "Mainnet", 1, "other", 40_000, 100, &notes),
            quote_id("wallet", "Mainnet", 1, "owned", 40_001, 100, &notes),
            quote_id("wallet", "Mainnet", 1, "owned", 40_000, 101, &notes),
            quote_id(
                "wallet",
                "Mainnet",
                1,
                "owned",
                40_000,
                100,
                &[note(50_001, 1), note(60_000, 2)],
            ),
        ] {
            assert_ne!(quote, other.unwrap());
        }
    }
    #[test]
    fn qortal_preparation_journal_survives_process_memory_loss_and_detects_corrupt_transaction() {
        use zcash_primitives::transaction::{Authorized, TransactionData};
        use zcash_protocol::consensus::{BlockHeight, BranchId};
        let tx = TransactionData::<Authorized>::from_parts_v6(
            BranchId::Nu6_3,
            0,
            BlockHeight::from_u32(120),
            None,
            None,
            None,
            None,
        )
        .freeze()
        .unwrap();
        let mut raw = vec![];
        tx.write(&mut raw).unwrap();
        let journal = Journal {
            version: 1,
            network: "Mainnet".into(),
            source_key_id: 7,
            destination: "owned".into(),
            quote: "approved".into(),
            signed: SignedTx {
                txid: tx.txid().to_string(),
                size: raw.len(),
                raw,
            },
            context: tx_flow::BroadcastContext {
                wallet_id: "wallet".into(),
                account_id: 1,
                spent_nullifiers: vec![vec![1; 32]],
                sent_amount: 40_000,
                fee: FEE,
                change_amount: 0,
                expiry_height: 120,
                created_at_ms: 1000,
            },
        };
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("intent.json");
        save_journal(&path, &journal).unwrap();
        drop(journal);
        let mut restored: Journal = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        validate_journal(&restored, "wallet", "Mainnet", 7, 1).unwrap();
        assert_eq!(restored.signed.txid, tx.txid().to_string());
        assert!(validate_journal(&restored, "other", "Mainnet", 7, 1).is_err());
        assert!(validate_journal(&restored, "wallet", "Testnet", 7, 1).is_err());
        restored.signed.raw[0] ^= 1;
        assert!(validate_journal(&restored, "wallet", "Mainnet", 7, 1).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
}
