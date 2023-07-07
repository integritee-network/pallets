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
use scale_info::TypeInfo;
use sp_core::{bounded_vec::BoundedVec, ConstU32, H256};
use sp_runtime::MultiSigner;
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

#[derive(Encode, Decode, Copy, Clone, PartialEq, Eq, sp_core::RuntimeDebug, TypeInfo)]
pub enum SgxAttestationMethod {
	Skip { proxied: bool },
	Ias,
	Dcap { proxied: bool },
}

impl Default for SgxAttestationMethod {
	fn default() -> Self {
		SgxAttestationMethod::Skip { proxied: false }
	}
}

const SGX_REPORT_DATA_SIZE: usize = 64;
#[derive(Debug, Encode, Decode, Copy, Clone, PartialEq, Eq, TypeInfo)]
#[repr(C)]
pub struct SgxReportData {
	pub d: [u8; SGX_REPORT_DATA_SIZE],
}

impl Default for SgxReportData {
	fn default() -> Self {
		SgxReportData { d: [0u8; SGX_REPORT_DATA_SIZE] }
	}
}

impl From<&[u8; 32]> for SgxReportData {
	fn from(pubkey: &[u8; 32]) -> Self {
		let mut data = SgxReportData::default();
		data.d[..32].copy_from_slice(pubkey);
		data
	}
}

impl AsRef<[u8; 64]> for SgxReportData {
	fn as_ref(&self) -> &[u8; 64] {
		&self.d
	}
}

impl SgxReportData {
	pub fn lower32(&self) -> [u8; 32] {
		let mut lower = [0u8; 32];
		lower.copy_from_slice(&self.d[..32]);
		lower
	}
}

#[derive(Encode, Decode, Default, Copy, Clone, PartialEq, Eq, sp_core::RuntimeDebug, TypeInfo)]
pub enum SgxStatus {
	#[default]
	Invalid,
	Ok,
	GroupOutOfDate,
	GroupRevoked,
	ConfigurationNeeded,
}

pub type OpaqueSigner = BoundedVec<u8, ConstU32<66>>;
pub type EnclaveFingerprint = H256;

#[derive(Encode, Decode, Clone, PartialEq, Eq, sp_core::RuntimeDebug, TypeInfo)]
pub enum AnySigner {
	Opaque(OpaqueSigner),
	Known(MultiSigner),
}

impl From<MultiSigner> for AnySigner {
	fn from(signer: MultiSigner) -> Self {
		AnySigner::Known(signer)
	}
}

impl From<sp_core::ed25519::Public> for AnySigner {
	fn from(signer: sp_core::ed25519::Public) -> Self {
		AnySigner::Known(MultiSigner::from(signer))
	}
}

impl From<OpaqueSigner> for AnySigner {
	fn from(signer_bytes: OpaqueSigner) -> Self {
		AnySigner::Opaque(signer_bytes)
	}
}

#[derive(Encode, Decode, Copy, Clone, PartialEq, Eq, sp_core::RuntimeDebug, TypeInfo)]
pub enum MultiEnclave<Url> {
	Sgx(SgxEnclave<Url>),
}

impl<Url> From<SgxEnclave<Url>> for MultiEnclave<Url> {
	fn from(sgx_enclave: SgxEnclave<Url>) -> Self {
		MultiEnclave::Sgx(sgx_enclave)
	}
}

impl<Url> MultiEnclave<Url> {
	pub fn author(self) -> AnySigner {
		match self {
			MultiEnclave::Sgx(enclave) => AnySigner::Opaque(
				OpaqueSigner::try_from(enclave.mr_signer.to_vec()).unwrap_or_default(),
			),
		}
	}

	pub fn fingerprint(self) -> EnclaveFingerprint {
		match self {
			MultiEnclave::Sgx(enclave) => EnclaveFingerprint::from(enclave.mr_enclave),
		}
	}

	pub fn instance_signer(self) -> AnySigner {
		match self {
			MultiEnclave::Sgx(enclave) => match enclave.maybe_pubkey() {
				Some(pubkey) =>
					AnySigner::from(MultiSigner::from(sp_core::ed25519::Public::from_raw(pubkey))),
				None => AnySigner::Opaque(
					OpaqueSigner::try_from(enclave.report_data.d.to_vec()).unwrap_or_default(),
				),
			},
		}
	}

	pub fn instance_url(self) -> Option<Url> {
		match self {
			MultiEnclave::Sgx(enclave) => enclave.url,
		}
	}

	pub fn attestation_timestamp(self) -> u64 {
		match self {
			MultiEnclave::Sgx(enclave) => enclave.timestamp,
		}
	}

	pub fn attestaion_proxied(self) -> bool {
		match self {
			MultiEnclave::Sgx(enclave) => match enclave.attestation_method {
				SgxAttestationMethod::Skip { proxied: true } |
				SgxAttestationMethod::Dcap { proxied: true } => true,
				_ => false,
			},
		}
	}
}

#[derive(Encode, Decode, Default, Copy, Clone, PartialEq, Eq, sp_core::RuntimeDebug, TypeInfo)]
pub struct SgxEnclave<Url> {
	pub report_data: SgxReportData,
	pub mr_enclave: MrEnclave,
	pub mr_signer: MrSigner,
	pub timestamp: u64,   // unix epoch in milliseconds
	pub url: Option<Url>, // utf8 encoded url
	pub build_mode: SgxBuildMode,
	pub attestation_method: SgxAttestationMethod,
	pub status: SgxStatus,
}

impl<Url> SgxEnclave<Url> {
	pub fn new(
		report_data: SgxReportData,
		mr_enclave: MrEnclave,
		mr_signer: MrSigner,
		timestamp: u64,
		build_mode: SgxBuildMode,
		status: SgxStatus,
	) -> Self {
		SgxEnclave {
			report_data,
			mr_enclave,
			mr_signer,
			timestamp,
			url: None,
			build_mode,
			attestation_method: SgxAttestationMethod::default(),
			status,
		}
	}

	pub fn maybe_pubkey<PubKey>(&self) -> Option<PubKey>
	where
		PubKey: Decode,
	{
		match PubKey::decode(&mut self.report_data.lower32().as_ref()) {
			Ok(p) => match self.attestation_method {
				SgxAttestationMethod::Dcap { proxied: false } |
				SgxAttestationMethod::Skip { proxied: false } |
				SgxAttestationMethod::Ias => Some(p),
				_ => None,
			},
			Err(_) => None,
		}
	}

	pub fn with_url(mut self, url: Url) -> Self {
		self.url = Some(url);
		self
	}

	pub fn with_attestation_method(mut self, attestation_method: SgxAttestationMethod) -> Self {
		self.attestation_method = attestation_method;
		self
	}

	pub fn with_pubkey(mut self, pubkey: &[u8]) -> Self {
		let mut data = SgxReportData::default();
		data.d[..pubkey.len()].copy_from_slice(pubkey);
		self.report_data = data;
		self
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
pub struct SgxQuotingEnclave {
	// Todo: make timestamp: Moment
	pub issue_date: u64, // unix epoch in milliseconds
	// Todo: make timestamp: Moment
	pub next_update: u64, // unix epoch in milliseconds
	pub miscselect: [u8; 4],
	pub miscselect_mask: [u8; 4],
	pub attributes: [u8; 16],
	pub attributes_mask: [u8; 16],
	pub mrsigner: MrSigner,
	pub isvprodid: u16,
	/// Contains only the TCB versions that are considered UpToDate
	pub tcb: Vec<QeTcb>,
}

impl SgxQuotingEnclave {
	#[allow(clippy::too_many_arguments)]
	pub fn new(
		issue_date: u64,
		next_update: u64,
		miscselect: [u8; 4],
		miscselect_mask: [u8; 4],
		attributes: [u8; 16],
		attributes_mask: [u8; 16],
		mrsigner: MrSigner,
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

	pub fn attributes_flags_mask_as_u64(&self) -> u64 {
		let slice_as_array: [u8; 8] = self.attributes_mask[0..8].try_into().unwrap();
		u64::from_le_bytes(slice_as_array)
	}

	pub fn attributes_flags_as_u64(&self) -> u64 {
		let slice_as_array: [u8; 8] = self.attributes[0..8].try_into().unwrap();
		u64::from_le_bytes(slice_as_array)
	}
}

#[derive(Encode, Decode, Default, Clone, PartialEq, Eq, sp_core::RuntimeDebug, TypeInfo)]
pub struct TcbVersionStatus {
	pub cpusvn: Cpusvn,
	pub pcesvn: Pcesvn,
}

impl TcbVersionStatus {
	pub fn new(cpusvn: Cpusvn, pcesvn: Pcesvn) -> Self {
		Self { cpusvn, pcesvn }
	}

	pub fn verify_examinee(&self, examinee: &TcbVersionStatus) -> bool {
		for (v, r) in self.cpusvn.iter().zip(examinee.cpusvn.iter()) {
			if *v > *r {
				return false
			}
		}
		self.pcesvn <= examinee.pcesvn
	}
}

/// This represents all the collateral data that we need to store on chain in order to verify
/// the quoting enclave validity of another enclave that wants to register itself on chain
#[derive(Encode, Decode, Default, Clone, PartialEq, Eq, sp_core::RuntimeDebug, TypeInfo)]
pub struct SgxTcbInfoOnChain {
	// Todo: make timestamp: Moment
	pub issue_date: u64, // unix epoch in milliseconds
	// Todo: make timestamp: Moment
	pub next_update: u64, // unix epoch in milliseconds
	tcb_levels: Vec<TcbVersionStatus>,
}

impl SgxTcbInfoOnChain {
	pub fn new(issue_date: u64, next_update: u64, tcb_levels: Vec<TcbVersionStatus>) -> Self {
		Self { issue_date, next_update, tcb_levels }
	}

	pub fn verify_examinee(&self, examinee: &TcbVersionStatus) -> bool {
		for tb in &self.tcb_levels {
			if tb.verify_examinee(examinee) {
				return true
			}
		}
		false
	}
}

pub type MrSigner = [u8; 32];
pub type MrEnclave = [u8; 32];
pub type Fmspc = [u8; 6];
pub type Cpusvn = [u8; 16];
pub type Pcesvn = u16;
pub type ShardIdentifier = H256;

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

#[cfg(test)]
mod tests {
	use super::*;
	use hex_literal::hex;

	#[test]
	fn tcb_full_is_valid() {
		// The strings are the hex encodings of the 16-byte CPUSVN numbers
		let reference = TcbVersionStatus::new(hex!("11110204018007000000000000000000"), 7);
		assert!(reference.verify_examinee(&reference));
		assert!(reference
			.verify_examinee(&TcbVersionStatus::new(hex!("11110204018007000000000000000000"), 7)));
		assert!(reference
			.verify_examinee(&TcbVersionStatus::new(hex!("21110204018007000000000000000001"), 7)));
		assert!(!reference
			.verify_examinee(&TcbVersionStatus::new(hex!("10110204018007000000000000000000"), 6)));
		assert!(!reference
			.verify_examinee(&TcbVersionStatus::new(hex!("11110204018007000000000000000000"), 6)));
	}
}
