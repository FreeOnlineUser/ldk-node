// Watchtower support for ldk-node.
//
// Provides channel monitor export functionality so that external watchtower
// services can monitor channels and broadcast justice transactions if a
// counterparty attempts to cheat while the mobile node is offline.
//
// This module enables cross-implementation watchtower compatibility, allowing
// ldk-node clients to leverage existing LND watchtowers or custom watchtower
// services.

use lightning::util::ser::Writeable;

use crate::logger::{log_error, LdkLogger, Logger};
use crate::types::ChainMonitor;
use crate::Error;

use std::sync::Arc;

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
///
/// Each returned `WatchtowerMonitorData` contains the full serialized monitor
/// which can be deserialized by any LDK-compatible watchtower service to
/// independently watch the chain and broadcast justice transactions.
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
