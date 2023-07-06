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

pub use sgx_verify::test_data;
pub use teerex_primitives::{SgxEnclave, MrEnclave};
use teerex_primitives::SgxReportData;

pub fn get_signer<AccountId: From<[u8; 32]>>(pubkey: &[u8; 32]) -> AccountId {
	AccountId::from(*pubkey)
}

pub trait TestEnclave<Url> {
	fn test_enclave() -> SgxEnclave<Url>;
	fn with_pubkey(self, pubkey: Vec<u8>) -> SgxEnclave<Url>;
	fn with_mr_enclave(self, mr_enclave: MrEnclave) -> SgxEnclave<Url>;
	fn with_timestamp(self, timestamp: u64) -> SgxEnclave<Url>;
	fn with_url(self, url: Url) -> SgxEnclave<Url>;
}

impl<Url: Default> TestEnclave<Url> for SgxEnclave<Url> {
	fn test_enclave() -> Self {
		SgxEnclave::default()
	}

	fn with_pubkey(mut self, pubkey: Vec<u8>) -> Self {
		let mut data = SgxReportData::default();
		data.d[..pubkey.len()].copy_from_slice(&pubkey[..]);
		self.report_data = data;
		self
	}

	fn with_mr_enclave(mut self, mr_enclave: MrEnclave) -> Self {
		self.mr_enclave = mr_enclave;
		self
	}

	fn with_timestamp(mut self, timestamp: u64) -> Self {
		self.timestamp = timestamp;
		self
	}

	fn with_url(mut self, url: Url) -> Self {
		self.url = Some(url);
		self
	}
}
