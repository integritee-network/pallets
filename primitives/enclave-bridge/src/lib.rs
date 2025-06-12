/*
	Copyright 2021 Integritee AG and Supercomputing Systems AG

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

		http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.

*/

//!Primitives for enclave-bridge
#![cfg_attr(not(feature = "std"), no_std)]
pub use common_primitives::{EnclaveFingerprint, ShardIdentifier};
use parity_scale_codec::{Decode, DecodeWithMemTracking, Encode};
use scale_info::TypeInfo;
use sp_std::prelude::*;

pub const ENCLAVE_BRIDGE: &str = "enclave_bridge";

#[derive(
	Encode,
	Decode,
	DecodeWithMemTracking,
	Default,
	Clone,
	PartialEq,
	Eq,
	sp_core::RuntimeDebug,
	TypeInfo,
)]
pub struct Request {
	pub shard: ShardIdentifier,
	pub cyphertext: Vec<u8>,
}

#[derive(
	Encode,
	Decode,
	DecodeWithMemTracking,
	Default,
	Clone,
	PartialEq,
	Eq,
	sp_core::RuntimeDebug,
	TypeInfo,
)]
pub struct ShardSignerStatus<AccountId, BlockNumber> {
	pub signer: AccountId,
	pub fingerprint: EnclaveFingerprint,
	pub last_activity: BlockNumber,
}
pub const MAX_SHARD_STATUS_SIGNER_COUNT: u32 = 10;

#[derive(
	Encode, Decode, DecodeWithMemTracking, Clone, PartialEq, Eq, sp_core::RuntimeDebug, TypeInfo,
)]
pub struct ShardConfig<AccountId> {
	/// enclave fingerprint which may perform state transitions on this shard
	pub enclave_fingerprint: EnclaveFingerprint,
	/// an optional limit on the number of validateers
	pub max_instances: Option<u32>,
	/// an optional set of authorities for permissioned sidechains
	pub authorities: Option<Vec<AccountId>>,
	/// maintenance mode blocks any upcoming state transitions on this shard
	pub maintenance_mode: bool,
}

impl<AccountId> ShardConfig<AccountId> {
	pub fn new(fingerprint: EnclaveFingerprint) -> Self {
		ShardConfig {
			enclave_fingerprint: fingerprint,
			max_instances: None,
			authorities: None,
			maintenance_mode: false,
		}
	}
}

#[derive(
	Encode, Decode, DecodeWithMemTracking, Clone, PartialEq, Eq, sp_core::RuntimeDebug, TypeInfo,
)]
pub struct UpgradableShardConfig<AccountId, BlockNumber> {
	/// the currently active config
	pub active_config: ShardConfig<AccountId>,
	/// temporary store for an upcoming upgraded shard config with enactment time
	pub pending_upgrade: Option<ShardConfig<AccountId>>,
	/// enact after importing this parentchain block on the sidechain
	pub upgrade_at: Option<BlockNumber>,
}

impl<AccountId, BlockNumber> From<ShardConfig<AccountId>>
	for UpgradableShardConfig<AccountId, BlockNumber>
{
	fn from(shard_config: ShardConfig<AccountId>) -> Self {
		UpgradableShardConfig {
			active_config: shard_config,
			pending_upgrade: None,
			upgrade_at: None,
		}
	}
}

impl<AccountId, BlockNumber> UpgradableShardConfig<AccountId, BlockNumber> {
	pub fn with_pending_upgrade(
		mut self,
		new_shard_config: ShardConfig<AccountId>,
		block_number: BlockNumber,
	) -> Self {
		self.pending_upgrade = Some(new_shard_config);
		self.upgrade_at = Some(block_number);
		self
	}
}
