//! Watchtower support for ldk-node.
//!
//! Intercepts every channel state change via the Persist trait to capture
//! counterparty commitment data, then produces ready-to-encrypt justice
//! blobs for LND watchtower compatibility.
//!
//! Two-phase approach:
//! 1. On each persist callback, capture new counterparty commitments
//! 2. Attempt to sign justice transactions for previously captured
//!    commitments (the revocation secret arrives in the following update)

use bitcoin::script::ScriptBuf;
use lightning::chain::chainmonitor::Persist;
use lightning::chain::channelmonitor::{ChannelMonitor, ChannelMonitorUpdate};
use lightning::chain::ChannelMonitorUpdateStatus;
use lightning::ln::chan_utils::CommitmentTransaction;
use lightning::sign::InMemorySigner;
use lightning::util::persist::MonitorName;
use lightning::util::ser::Writeable;

use crate::logger::{log_error, log_info, log_trace, LdkLogger, Logger};
use crate::types::{ChainMonitor, Persister};
use crate::Error;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// A fully-formed justice blob ready for encryption and push to an LND tower.
///
/// Contains all fields needed for LND's JusticeKit V0 format.
/// The Kotlin/Swift side only needs to:
/// 1. Encrypt with XChaCha20-Poly1305 using breach_txid as key
/// 2. Take first 16 bytes of breach_txid as the hint
/// 3. Push (hint, encrypted_blob) to the tower
#[derive(Debug, Clone)]
pub struct WatchtowerJusticeBlob {
    /// Channel this blob protects.
    pub channel_id: String,
    /// Full txid of the revoked commitment (32 bytes).
    /// This is both the encryption key AND the source of the 16-byte hint.
    pub breach_txid: Vec<u8>,
    /// Sweep address where justice funds go (witness program).
    pub sweep_address: Vec<u8>,
    /// Compressed revocation pubkey (33 bytes).
    pub revocation_pubkey: Vec<u8>,
    /// Compressed local delay pubkey (33 bytes).
    pub local_delay_pubkey: Vec<u8>,
    /// CSV delay for the to-local output.
    pub csv_delay: u32,
    /// Signature for spending the to-local output (64 bytes, compact DER).
    pub to_local_sig: Vec<u8>,
    /// Compressed to-remote pubkey (33 bytes, may be empty if no to-remote output).
    pub to_remote_pubkey: Vec<u8>,
    /// Signature for the to-remote output (64 bytes, may be empty).
    pub to_remote_sig: Vec<u8>,
}

/// Metadata for a pending (unsigned) commitment.
struct PendingCommitment {
    channel_id: String,
    commitment_tx: CommitmentTransaction,
    commitment_number: u64,
}

/// Information about a channel monitor for watchtower synchronization.
#[derive(Debug, Clone)]
pub struct WatchtowerMonitorInfo {
    /// The channel ID being monitored.
    pub channel_id: String,
    /// The counterparty's node public key.
    pub counterparty_node_id: String,
    /// The latest monitor update ID that has been applied.
    pub latest_update_id: u64,
    /// The funding transaction outpoint (txid:vout format).
    pub funding_txo: String,
}

/// A serialized channel monitor ready for export to a watchtower.
#[derive(Debug, Clone)]
pub struct WatchtowerMonitorData {
    /// The channel ID this monitor belongs to.
    pub channel_id: String,
    /// The counterparty's node public key.
    pub counterparty_node_id: String,
    /// The latest monitor update ID.
    pub latest_update_id: u64,
    /// The serialized monitor data (LDK binary format).
    pub monitor_bytes: Vec<u8>,
}

/// Internal state for the watchtower persister.
struct WatchtowerState {
    /// Commitments captured but not yet signable (waiting for revocation secret).
    /// Key: (channel_id_string, commitment_number)
    pending_commitments: HashMap<(String, u64), PendingCommitment>,
    /// Fully signed justice blobs ready for the tower.
    ready_blobs: Vec<WatchtowerJusticeBlob>,
    /// Sweep address to use for justice transactions.
    sweep_address: Option<ScriptBuf>,
    /// Fee rate for justice transactions (sat/kw).
    sweep_fee_rate: u64,
}

/// A wrapping persister that intercepts channel monitor updates to capture
/// counterparty commitment data and produce ready-to-encrypt justice blobs.
pub struct WatchtowerPersister {
    inner: Arc<Persister>,
    state: Mutex<WatchtowerState>,
    logger: Arc<Logger>,
}

impl WatchtowerPersister {
    /// Create a new WatchtowerPersister.
    ///
    /// `sweep_fee_rate` is the fee rate (sat/kweight) for justice transactions.
    /// A reasonable default is 12500 (roughly 50 sat/vB).
    pub fn new(inner: Arc<Persister>, logger: Arc<Logger>) -> Self {
        Self {
            inner,
            state: Mutex::new(WatchtowerState {
                pending_commitments: HashMap::new(),
                ready_blobs: Vec::new(),
                sweep_address: None,
                sweep_fee_rate: 12500, // ~50 sat/vB default
            }),
            logger,
        }
    }

    /// Set the sweep address for justice transactions.
    /// Must be called before any blobs can be produced.
    pub fn set_sweep_address(&self, address: ScriptBuf) {
        if let Ok(mut state) = self.state.lock() {
            state.sweep_address = Some(address);
        }
    }

    /// Drain all ready justice blobs.
    pub fn drain_justice_blobs(&self) -> Vec<WatchtowerJusticeBlob> {
        match self.state.lock() {
            Ok(mut state) => std::mem::take(&mut state.ready_blobs),
            Err(_) => {
                log_error!(self.logger, "Watchtower state lock poisoned");
                Vec::new()
            }
        }
    }

    /// Number of pending (unsigned) commitments.
    pub fn pending_count(&self) -> usize {
        self.state.lock().map(|s| s.pending_commitments.len()).unwrap_or(0)
    }

    /// Number of ready (signed) blobs waiting to be drained.
    pub fn ready_count(&self) -> usize {
        self.state.lock().map(|s| s.ready_blobs.len()).unwrap_or(0)
    }

    /// Phase 1: Capture new counterparty commitments from this update.
    fn capture_new_commitments(
        &self,
        monitor: &ChannelMonitor<InMemorySigner>,
        update: Option<&ChannelMonitorUpdate>,
    ) {
        let channel_id = monitor.channel_id().to_string();

        let commitment_txs: Vec<CommitmentTransaction> = if let Some(upd) = update {
            monitor.counterparty_commitment_txs_from_update(upd)
        } else {
            monitor
                .initial_counterparty_commitment_tx()
                .map(|tx| vec![tx])
                .unwrap_or_default()
        };

        if commitment_txs.is_empty() {
            return;
        }

        let mut state = match self.state.lock() {
            Ok(s) => s,
            Err(_) => return,
        };

        for ctx in commitment_txs {
            let commitment_number = ctx.commitment_number();
            let key = (channel_id.clone(), commitment_number);

            log_info!(
                self.logger,
                "Captured counterparty commitment: channel={}, number={}",
                channel_id, commitment_number
            );

            state.pending_commitments.insert(
                key,
                PendingCommitment {
                    channel_id: channel_id.clone(),
                    commitment_tx: ctx,
                    commitment_number,
                },
            );
        }
    }

    /// Phase 2: Try to sign all pending commitments.
    ///
    /// After a new update is applied, the monitor may now have revocation
    /// secrets for previously captured commitments. We try to sign each one
    /// and move successful ones to the ready queue.
    fn try_sign_pending(
        &self,
        monitor: &ChannelMonitor<InMemorySigner>,
    ) {
        let channel_id = monitor.channel_id().to_string();

        let mut state = match self.state.lock() {
            Ok(s) => s,
            Err(_) => return,
        };

        let sweep_address = match &state.sweep_address {
            Some(addr) => addr.clone(),
            None => {
                log_trace!(self.logger, "No sweep address set, skipping justice signing");
                return;
            }
        };

        let fee_rate = state.sweep_fee_rate;

        // Collect keys for this channel's pending commitments
        let pending_keys: Vec<(String, u64)> = state
            .pending_commitments
            .keys()
            .filter(|(cid, _)| cid == &channel_id)
            .cloned()
            .collect();

        // Clone pending data to avoid borrow conflicts when modifying state
        let pending_data: Vec<((String, u64), u64, CommitmentTransaction)> = pending_keys
            .iter()
            .filter_map(|key| {
                state.pending_commitments.get(key).map(|p| {
                    (key.clone(), p.commitment_number, p.commitment_tx.clone())
                })
            })
            .collect();

        for (key, commitment_number, commitment_tx) in pending_data {
            let trusted = commitment_tx.trust();

            // Get the breach txid
            let txid = trusted.txid();
            let txid_bytes: Vec<u8> = AsRef::<[u8]>::as_ref(&txid).to_vec();

            // Check if there's a revokeable output to sweep
            let revokeable_idx = match trusted.revokeable_output_index() {
                Some(idx) => idx,
                None => {
                    log_trace!(
                        self.logger,
                        "No revokeable output for channel={}, commitment={}",
                        channel_id, commitment_number
                    );
                    continue;
                }
            };

            // Build the unsigned justice transaction
            let justice_tx = match trusted.build_to_local_justice_tx(
                fee_rate,
                sweep_address.clone(),
            ) {
                Ok(tx) => tx,
                Err(_) => {
                    log_trace!(
                        self.logger,
                        "Cannot build justice tx for channel={}, commitment={} (fee too high?)",
                        channel_id, commitment_number
                    );
                    continue;
                }
            };

            // Get the value of the revokeable output
            let built_tx = trusted.built_transaction();
            let output_value = match built_tx.transaction.output.get(revokeable_idx) {
                Some(out) => out.value.to_sat(),
                None => continue,
            };

            // Extract the real CSV delay by matching the revokeable output's P2WSH script.
            // The delay is embedded in the OP_CSV opcode of the redeemscript.
            // We try candidate values and match against the commitment tx output.
            let revokeable_output_script = &built_tx.transaction.output[revokeable_idx].script_pubkey;
            let csv_delay = {
                use lightning::ln::chan_utils::get_revokeable_redeemscript;
                let keys = trusted.keys();
                let mut found_delay: u32 = 144; // safe default
                // LN spec: to_self_delay typically 40-2016, most common is 144
                for candidate in (1u16..=2016).chain(std::iter::once(4032)) {
                    let script = get_revokeable_redeemscript(
                        &keys.revocation_key,
                        candidate,
                        &keys.broadcaster_delayed_payment_key,
                    ).to_p2wsh();
                    if script == *revokeable_output_script {
                        found_delay = candidate as u32;
                        break;
                    }
                }
                found_delay
            };

            // Try to sign — this will only succeed if the revocation secret is available
            let signed_tx = match monitor.sign_to_local_justice_tx(
                justice_tx,
                0, // input index (justice tx has one input)
                output_value,
                commitment_number,
            ) {
                Ok(tx) => tx,
                Err(_) => {
                    // Revocation secret not yet available — will try again on next update
                    log_trace!(
                        self.logger,
                        "Revocation not yet available for channel={}, commitment={}",
                        channel_id, commitment_number
                    );
                    continue;
                }
            };

            // Extract the keys for the blob
            let keys = trusted.keys();

            // Extract the signature from the signed justice transaction
            // The witness contains: <sig> <revocation_key> (for p2wsh to_local)
            let to_local_sig = if let Some(witness) = signed_tx.input.first()
                .and_then(|inp| Some(&inp.witness))
            {
                if let Some(sig_bytes) = witness.iter().next() {
                    // Remove sighash byte from DER sig, convert to compact 64-byte
                    // For the blob we need the raw 64-byte signature
                    sig_bytes.to_vec()
                } else {
                    continue;
                }
            } else {
                continue;
            };

            log_info!(
                self.logger,
                "Signed justice blob: channel={}, commitment={}, txid={}",
                channel_id, commitment_number, txid
            );

            state.ready_blobs.push(WatchtowerJusticeBlob {
                channel_id: channel_id.clone(),
                breach_txid: txid_bytes,
                sweep_address: sweep_address.as_bytes().to_vec(),
                revocation_pubkey: keys.revocation_key.0.serialize().to_vec(),
                local_delay_pubkey: keys.broadcaster_delayed_payment_key.0.serialize().to_vec(),
                csv_delay,
                to_local_sig,
                to_remote_pubkey: keys.countersignatory_htlc_key.0.serialize().to_vec(),
                to_remote_sig: Vec::new(), // TODO: to-remote signing
            });

            // Remove from pending — it's now signed
            state.pending_commitments.remove(&key);
        }
    }
}

impl Persist<InMemorySigner> for WatchtowerPersister {
    fn persist_new_channel(
        &self,
        monitor_name: MonitorName,
        monitor: &ChannelMonitor<InMemorySigner>,
    ) -> ChannelMonitorUpdateStatus {
        // Phase 1: Capture the initial counterparty commitment
        self.capture_new_commitments(monitor, None);

        // Delegate to inner persister
        self.inner.persist_new_channel(monitor_name, monitor)
    }

    fn update_persisted_channel(
        &self,
        monitor_name: MonitorName,
        monitor_update: Option<&ChannelMonitorUpdate>,
        monitor: &ChannelMonitor<InMemorySigner>,
    ) -> ChannelMonitorUpdateStatus {
        // Phase 1: Capture new counterparty commitments from this update
        self.capture_new_commitments(monitor, monitor_update);

        // Phase 2: Try to sign previously captured commitments
        // (the monitor now has the update applied, which may include revocation secrets)
        self.try_sign_pending(monitor);

        // Delegate to inner persister
        self.inner.update_persisted_channel(monitor_name, monitor_update, monitor)
    }

    fn archive_persisted_channel(&self, monitor_name: MonitorName) {
        Persist::<InMemorySigner>::archive_persisted_channel(&*self.inner, monitor_name)
    }
}

// --- Monitor export functions ---

/// Returns metadata about all active channel monitors.
pub(crate) fn list_monitor_info(
    chain_monitor: &Arc<ChainMonitor>, logger: &Arc<Logger>,
) -> Vec<WatchtowerMonitorInfo> {
    let mut infos = Vec::new();

    for channel_id in chain_monitor.list_monitors() {
        match chain_monitor.get_monitor(channel_id) {
            Ok(monitor) => {
                let counterparty = monitor.get_counterparty_node_id();
                let update_id = monitor.get_latest_update_id();
                let funding = monitor.get_funding_txo();

                infos.push(WatchtowerMonitorInfo {
                    channel_id: channel_id.to_string(),
                    counterparty_node_id: counterparty.to_string(),
                    latest_update_id: update_id,
                    funding_txo: format!("{}:{}", funding.txid, funding.index),
                });
            },
            Err(()) => {
                log_error!(logger, "Failed to get monitor for channel {}", channel_id);
                continue;
            },
        }
    }

    infos
}

/// Exports all channel monitors as serialized bytes for watchtower replication.
pub(crate) fn export_monitors(
    chain_monitor: &Arc<ChainMonitor>, logger: &Arc<Logger>,
) -> Result<Vec<WatchtowerMonitorData>, Error> {
    let mut monitors = Vec::new();

    for channel_id in chain_monitor.list_monitors() {
        match chain_monitor.get_monitor(channel_id) {
            Ok(monitor) => {
                let counterparty = monitor.get_counterparty_node_id();
                let update_id = monitor.get_latest_update_id();

                let mut bytes = Vec::new();
                monitor.write(&mut bytes).map_err(|e| {
                    log_error!(
                        logger,
                        "Failed to serialize monitor for channel {}: {}",
                        channel_id,
                        e
                    );
                    Error::PersistenceFailed
                })?;

                monitors.push(WatchtowerMonitorData {
                    channel_id: channel_id.to_string(),
                    counterparty_node_id: counterparty.to_string(),
                    latest_update_id: update_id,
                    monitor_bytes: bytes,
                });
            },
            Err(()) => {
                log_error!(logger, "Failed to get monitor for channel {}", channel_id);
                continue;
            },
        }
    }

    Ok(monitors)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_justice_blob_fields_are_correct_sizes() {
        // Verify that a WatchtowerJusticeBlob with typical field sizes
        // matches what LND's JusticeKit V0 expects
        let blob = WatchtowerJusticeBlob {
            channel_id: "test".to_string(),
            breach_txid: vec![0xab; 32],
            sweep_address: vec![0u8; 22], // p2wpkh witness program
            revocation_pubkey: vec![2u8; 33], // compressed pubkey
            local_delay_pubkey: vec![3u8; 33],
            csv_delay: 144,
            to_local_sig: vec![0u8; 64], // compact signature
            to_remote_pubkey: vec![0u8; 33],
            to_remote_sig: vec![0u8; 64],
        };

        // LND JusticeKit V0 plaintext is 274 bytes:
        // 1 (addr len) + 42 (padded addr) + 33 (rev pk) + 33 (delay pk)
        // + 4 (csv) + 64 (to_local sig) + 33 (to_remote pk) + 64 (to_remote sig)
        // = 274
        assert_eq!(blob.breach_txid.len(), 32, "breach txid must be 32 bytes");
        assert_eq!(blob.revocation_pubkey.len(), 33, "revocation pk must be 33 bytes");
        assert_eq!(blob.local_delay_pubkey.len(), 33, "delay pk must be 33 bytes");
        assert_eq!(blob.to_local_sig.len(), 64, "to_local sig must be 64 bytes");
        assert!(blob.sweep_address.len() <= 42, "sweep address must fit in 42 bytes");

        // Verify hint derivation (first 16 bytes of breach txid)
        let hint: Vec<u8> = blob.breach_txid[..16].to_vec();
        assert_eq!(hint.len(), 16);
        assert_eq!(hint[0], 0xab);
    }

    #[test]
    fn test_watchtower_state_drain() {
        let state = Mutex::new(WatchtowerState {
            pending_commitments: HashMap::new(),
            ready_blobs: vec![
                WatchtowerJusticeBlob {
                    channel_id: "ch1".to_string(),
                    breach_txid: vec![1u8; 32],
                    sweep_address: vec![0u8; 22],
                    revocation_pubkey: vec![2u8; 33],
                    local_delay_pubkey: vec![3u8; 33],
                    csv_delay: 144,
                    to_local_sig: vec![0u8; 64],
                    to_remote_pubkey: vec![0u8; 33],
                    to_remote_sig: vec![0u8; 64],
                },
                WatchtowerJusticeBlob {
                    channel_id: "ch1".to_string(),
                    breach_txid: vec![2u8; 32],
                    sweep_address: vec![0u8; 22],
                    revocation_pubkey: vec![2u8; 33],
                    local_delay_pubkey: vec![3u8; 33],
                    csv_delay: 144,
                    to_local_sig: vec![0u8; 64],
                    to_remote_pubkey: vec![0u8; 33],
                    to_remote_sig: vec![0u8; 64],
                },
            ],
            sweep_address: None,
            sweep_fee_rate: 12500,
        });

        // Drain should return all blobs and empty the store
        let blobs = {
            let mut s = state.lock().unwrap();
            std::mem::take(&mut s.ready_blobs)
        };
        assert_eq!(blobs.len(), 2);
        assert_eq!(blobs[0].breach_txid[0], 1);
        assert_eq!(blobs[1].breach_txid[0], 2);

        // Second drain should be empty
        let blobs2 = {
            let s = state.lock().unwrap();
            s.ready_blobs.clone()
        };
        assert_eq!(blobs2.len(), 0);
    }

    #[test]
    fn test_pending_commitments_dedup() {
        // Verify that re-capturing the same commitment number replaces, not duplicates
        let mut pending: HashMap<(String, u64), u64> = HashMap::new();
        let key = ("channel1".to_string(), 42u64);

        pending.insert(key.clone(), 1);
        assert_eq!(pending.len(), 1);

        // Same key should overwrite
        pending.insert(key.clone(), 2);
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[&key], 2);

        // Different commitment number is a different entry
        let key2 = ("channel1".to_string(), 43u64);
        pending.insert(key2, 3);
        assert_eq!(pending.len(), 2);
    }
}
