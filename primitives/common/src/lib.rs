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
#![cfg_attr(not(feature = "std"), no_std)]
//!Primitives for all pallets
extern crate derive_more;
use derive_more::From;
use parity_scale_codec::{Decode, DecodeWithMemTracking, Encode};
use scale_info::TypeInfo;
use sp_core::{bounded::BoundedVec, ConstU32, H256};
use sp_runtime::MultiSigner;
use sp_std::vec;

#[cfg(not(feature = "std"))]
use sp_std::vec::Vec;

/// Substrate runtimes provide no string type. Hence, for arbitrary data of varying length the
/// `Vec<u8>` is used. In the polkadot-js the typedef `Text` is used to automatically
/// utf8 decode bytes into a string.
#[cfg(not(feature = "std"))]
pub type PalletString = Vec<u8>;
#[cfg(feature = "std")]
pub type PalletString = String;

pub type OpaqueSigner = BoundedVec<u8, ConstU32<66>>;
pub type EnclaveFingerprint = H256;
pub type ShardIdentifier = H256;

pub trait AsByteOrNoop {
	fn as_bytes_or_noop(&self) -> &[u8];
}

impl AsByteOrNoop for PalletString {
	#[cfg(feature = "std")]
	fn as_bytes_or_noop(&self) -> &[u8] {
		self.as_bytes()
	}

	#[cfg(not(feature = "std"))]
	fn as_bytes_or_noop(&self) -> &[u8] {
		self
	}
}

#[derive(
	Encode,
	Decode,
	DecodeWithMemTracking,
	Clone,
	PartialEq,
	Eq,
	From,
	sp_core::RuntimeDebug,
	TypeInfo,
)]
pub enum AnySigner {
	Opaque(OpaqueSigner),
	Known(MultiSigner),
}
impl Default for AnySigner {
	fn default() -> Self {
		AnySigner::Opaque(OpaqueSigner::default())
	}
}

impl From<[u8; 32]> for AnySigner {
	fn from(pubkey: [u8; 32]) -> Self {
		// zero padding is necessary because the chain storage does that anyway for bounded vec
		let mut zero_padded_pubkey = pubkey.to_vec();
		zero_padded_pubkey.append(&mut vec![0; 34]);
		AnySigner::Opaque(
			OpaqueSigner::try_from(zero_padded_pubkey).expect("66 >= 32 + 34. q.e.d."),
		)
	}
}

impl From<[u8; 64]> for AnySigner {
	fn from(pubkey: [u8; 64]) -> Self {
		// zero padding is necessary because the chain storage does that anyway for bounded vec
		let mut zero_padded_pubkey = pubkey.to_vec();
		zero_padded_pubkey.append(&mut vec![0; 2]);
		AnySigner::Opaque(OpaqueSigner::try_from(zero_padded_pubkey).expect("66 > 64 + 2. q.e.d."))
	}
}
