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
use codec::{Decode, Encode};
pub use common_primitives::{EnclaveFingerprint, ShardIdentifier};
use scale_info::TypeInfo;
use sp_std::prelude::*;

#[derive(Encode, Decode, Default, Clone, PartialEq, Eq, sp_core::RuntimeDebug, TypeInfo)]
pub struct Request {
	pub shard: ShardIdentifier,
	pub cyphertext: Vec<u8>,
}

#[derive(Encode, Decode, Default, Clone, PartialEq, Eq, sp_core::RuntimeDebug, TypeInfo)]
pub struct ShardSignerStatus<AccountId, BlockNumber> {
	pub signer: AccountId,
	pub fingerprint: EnclaveFingerprint,
	pub last_activity: BlockNumber,
}
