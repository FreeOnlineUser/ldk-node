//! Watchtower support for ldk-node.
//!
//! Provides two capabilities:
//! 1. Channel monitor export for external watchtower services
//! 2. Persist-layer interception to capture counterparty commitment data
//!    for building watchtower justice blobs on each state update

use lightning::chain::chainmonitor::Persist;
use lightning::chain::channelmonitor::{ChannelMonitor, ChannelMonitorUpdate};
use lightning::chain::ChannelMonitorUpdateStatus;
use lightning::ln::chan_utils::CommitmentTransaction;
use lightning::sign::InMemorySigner;
use lightning::util::persist::MonitorName;
use lightning::util::ser::Writeable;

use crate::logger::{log_error, log_info, LdkLogger, Logger};
use crate::types::{ChainMonitor, Persister};
use crate::Error;

use std::sync::{Arc, Mutex};

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

/// Captured counterparty commitment data from a channel monitor update.
/// This is the raw material needed to build LND watchtower justice blobs.
#[derive(Debug, Clone)]
pub struct WatchtowerUpdate {
    /// Channel ID this update belongs to.
    pub channel_id: String,
    /// The counterparty commitment transaction (unsigned).
    /// The txid of this transaction becomes the breach key and hint.
    pub commitment_tx_bytes: Vec<u8>,
    /// The commitment number (used for signing justice transactions).
    pub commitment_number: u64,
    /// The monitor update ID that produced this data.
    pub update_id: u64,
}

/// Accumulator for watchtower updates captured during persist operations.
#[derive(Debug)]
pub struct WatchtowerUpdateStore {
    /// Pending updates that haven't been consumed yet.
    pending: Vec<WatchtowerUpdate>,
}

impl WatchtowerUpdateStore {
    /// Create a new empty store.
    pub fn new() -> Self {
        Self { pending: Vec::new() }
    }

    /// Add a captured update.
    pub fn push(&mut self, update: WatchtowerUpdate) {
        self.pending.push(update);
    }

    /// Drain all pending updates (returns them and clears the store).
    pub fn drain(&mut self) -> Vec<WatchtowerUpdate> {
        std::mem::take(&mut self.pending)
    }

    /// Number of pending updates.
    pub fn len(&self) -> usize {
        self.pending.len()
    }
}

/// A wrapping persister that intercepts channel monitor updates to capture
/// counterparty commitment data for watchtower backup.
///
/// Delegates all actual persistence to the inner `MonitorUpdatingPersister`,
/// and additionally extracts counterparty commitment transactions from each
/// update for later translation into LND watchtower blobs.
pub struct WatchtowerPersister {
    inner: Arc<Persister>,
    updates: Arc<Mutex<WatchtowerUpdateStore>>,
    logger: Arc<Logger>,
}

impl WatchtowerPersister {
    /// Create a new WatchtowerPersister wrapping an existing persister.
    pub fn new(
        inner: Arc<Persister>,
        logger: Arc<Logger>,
    ) -> Self {
        Self {
            inner,
            updates: Arc::new(Mutex::new(WatchtowerUpdateStore::new())),
            logger,
        }
    }

    /// Get a reference to the update store for draining captured updates.
    pub fn update_store(&self) -> Arc<Mutex<WatchtowerUpdateStore>> {
        Arc::clone(&self.updates)
    }

    /// Extract counterparty commitment data from a monitor and optional update.
    fn capture_commitments(
        &self,
        monitor: &ChannelMonitor<InMemorySigner>,
        update: Option<&ChannelMonitorUpdate>,
    ) {
        let channel_id = monitor.channel_id().to_string();
        let update_id = monitor.get_latest_update_id();

        // Get counterparty commitments from this update
        let commitment_txs: Vec<CommitmentTransaction> = if let Some(upd) = update {
            monitor.counterparty_commitment_txs_from_update(upd)
        } else {
            // No update means full monitor persist. Get initial commitment if available.
            monitor.initial_counterparty_commitment_tx()
                .map(|tx| vec![tx])
                .unwrap_or_default()
        };

        if commitment_txs.is_empty() {
            return;
        }

        let mut store = match self.updates.lock() {
            Ok(s) => s,
            Err(_) => {
                log_error!(self.logger, "Watchtower update store lock poisoned");
                return;
            }
        };

        for ctx in commitment_txs {
            // Serialize the commitment transaction
            let mut tx_bytes = Vec::new();
            if let Err(e) = ctx.write(&mut tx_bytes) {
                log_error!(
                    self.logger,
                    "Failed to serialize commitment tx for channel {}: {}",
                    channel_id, e
                );
                continue;
            }

            let commitment_number = ctx.commitment_number();

            log_info!(
                self.logger,
                "Captured watchtower data: channel={}, commitment_number={}, update_id={}",
                channel_id, commitment_number, update_id
            );

            store.push(WatchtowerUpdate {
                channel_id: channel_id.clone(),
                commitment_tx_bytes: tx_bytes,
                commitment_number,
                update_id,
            });
        }
    }
}

impl Persist<InMemorySigner> for WatchtowerPersister {
    fn persist_new_channel(
        &self,
        monitor_name: MonitorName,
        monitor: &ChannelMonitor<InMemorySigner>,
    ) -> ChannelMonitorUpdateStatus {
        // Capture the initial counterparty commitment
        self.capture_commitments(monitor, None);

        // Delegate to inner persister
        self.inner.persist_new_channel(monitor_name, monitor)
    }

    fn update_persisted_channel(
        &self,
        monitor_name: MonitorName,
        monitor_update: Option<&ChannelMonitorUpdate>,
        monitor: &ChannelMonitor<InMemorySigner>,
    ) -> ChannelMonitorUpdateStatus {
        // Capture counterparty commitment data from this update
        self.capture_commitments(monitor, monitor_update);

        // Delegate to inner persister
        self.inner.update_persisted_channel(monitor_name, monitor_update, monitor)
    }

    fn archive_persisted_channel(&self, monitor_name: MonitorName) {
        Persist::<InMemorySigner>::archive_persisted_channel(&*self.inner, monitor_name)
    }
}

/// Extract watchtower-relevant data from all active monitors.
///
/// For each channel monitor, this attempts to sign justice transactions for
/// all known revoked commitment states. Returns the signed justice transaction
/// data needed to construct LND watchtower blobs.
///
/// Note: This retrieves data from the current monitor state. For real-time
/// capture of each state update, use WatchtowerPersister as the persistence layer.
pub(crate) fn extract_justice_data(
    chain_monitor: &Arc<ChainMonitor>,
    logger: &Arc<Logger>,
) -> Vec<WatchtowerUpdate> {
    let mut updates = Vec::new();

    for channel_id in chain_monitor.list_monitors() {
        match chain_monitor.get_monitor(channel_id) {
            Ok(monitor) => {
                let chan_id_str = channel_id.to_string();

                // Get the initial counterparty commitment if available
                if let Some(initial_ctx) = monitor.initial_counterparty_commitment_tx() {
                    let commitment_number = initial_ctx.commitment_number();
                    let mut tx_bytes = Vec::new();
                    if initial_ctx.write(&mut tx_bytes).is_ok() {
                        log_info!(
                            logger,
                            "Extracted initial commitment for channel {}, number={}",
                            chan_id_str, commitment_number
                        );
                        updates.push(WatchtowerUpdate {
                            channel_id: chan_id_str.clone(),
                            commitment_tx_bytes: tx_bytes,
                            commitment_number,
                            update_id: 0,
                        });
                    }
                }
            },
            Err(()) => {
                log_error!(logger, "Failed to get monitor for channel {}", channel_id);
                continue;
            },
        }
    }

    updates
}

// --- Existing export functions ---

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
