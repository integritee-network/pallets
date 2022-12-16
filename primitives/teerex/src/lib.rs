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

//!Primitives for teerex
#![cfg_attr(not(feature = "std"), no_std)]
use codec::{Decode, Encode};
use common_primitives::PalletString;
use scale_info::TypeInfo;
use sp_core::H256;
use sp_std::prelude::*;

#[derive(Encode, Decode, Copy, Clone, PartialEq, Eq, sp_core::RuntimeDebug, TypeInfo)]
pub enum SgxBuildMode {
	Debug,
	Production,
}

impl Default for SgxBuildMode {
	fn default() -> Self {
		SgxBuildMode::Production
	}
}

#[derive(Encode, Decode, Default, Copy, Clone, PartialEq, Eq, sp_core::RuntimeDebug, TypeInfo)]
pub struct Enclave<PubKey, Url> {
	pub pubkey: PubKey, // FIXME: this is redundant information
	pub mr_enclave: [u8; 32],
	// Todo: make timestamp: Moment
	pub timestamp: u64, // unix epoch in milliseconds
	pub url: Url,       // utf8 encoded url
	pub sgx_mode: SgxBuildMode,
}

impl<PubKey, Url> Enclave<PubKey, Url> {
	pub fn new(
		pubkey: PubKey,
		mr_enclave: [u8; 32],
		timestamp: u64,
		url: Url,
		sgx_build_mode: SgxBuildMode,
	) -> Self {
		Enclave { pubkey, mr_enclave, timestamp, url, sgx_mode: sgx_build_mode }
	}
}

/// The list of valid TCBs for an enclave.
#[derive(Encode, Decode, Clone, PartialEq, Eq, sp_core::RuntimeDebug, TypeInfo)]
pub struct QeTcb {
	pub isvsvn: u16,
}

impl QeTcb {
	pub fn new(isvsvn: u16) -> Self {
		Self { isvsvn }
	}
}

/// This represents all the collateral data that we need to store on chain in order to verify
/// the quoting enclave validity of another enclave that wants to register itself on chain
#[derive(Encode, Decode, Default, Clone, PartialEq, Eq, sp_core::RuntimeDebug, TypeInfo)]
pub struct QuotingEnclave {
	// Todo: make timestamp: Moment
	pub issue_date: u64, // unix epoch in milliseconds
	// Todo: make timestamp: Moment
	pub next_update: u64, // unix epoch in milliseconds
	pub miscselect: [u8; 4],
	pub miscselect_mask: [u8; 4],
	pub attributes: [u8; 16],
	pub attributes_mask: [u8; 16],
	pub mrsigner: [u8; 32],
	pub isvprodid: u16,
	/// Contains only the TCB versions that are considered UpToDate
	pub tcb: Vec<QeTcb>,
}

impl QuotingEnclave {
	pub fn new(
		issue_date: u64,
		next_update: u64,
		miscselect: [u8; 4],
		miscselect_mask: [u8; 4],
		attributes: [u8; 16],
		attributes_mask: [u8; 16],
		mrsigner: [u8; 32],
		isvprodid: u16,
		tcb: Vec<QeTcb>,
	) -> Self {
		Self {
			issue_date,
			next_update,
			miscselect,
			miscselect_mask,
			attributes,
			attributes_mask,
			mrsigner,
			isvprodid,
			tcb,
		}
	}
}

#[derive(Encode, Decode, Default, Clone, PartialEq, Eq, sp_core::RuntimeDebug, TypeInfo)]
pub struct TcbVersionStatus {
	cpusvn: [u8; 16],
	pcesvn: u16,
}

impl TcbVersionStatus {
	pub fn new(cpusvn: [u8; 16], pcesvn: u16) -> Self {
		Self { cpusvn, pcesvn }
	}
}

/// This represents all the collateral data that we need to store on chain in order to verify
/// the quoting enclave validity of another enclave that wants to register itself on chain
#[derive(Encode, Decode, Default, Clone, PartialEq, Eq, sp_core::RuntimeDebug, TypeInfo)]
pub struct TcbInfoOnChain {
	// Todo: make timestamp: Moment
	pub issue_date: u64, // unix epoch in milliseconds
	// Todo: make timestamp: Moment
	pub next_update: u64, // unix epoch in milliseconds
	tcb_levels: Vec<TcbVersionStatus>,
}

impl TcbInfoOnChain {
	pub fn new(issue_date: u64, next_update: u64, tcb_levels: Vec<TcbVersionStatus>) -> Self {
		Self { issue_date, next_update, tcb_levels }
	}
}

pub type Fmspc = [u8; 6];
pub type ShardIdentifier = H256;

#[derive(Encode, Decode, Default, Clone, PartialEq, Eq, sp_core::RuntimeDebug, TypeInfo)]
pub struct Request {
	pub shard: ShardIdentifier,
	pub cyphertext: Vec<u8>,
}
