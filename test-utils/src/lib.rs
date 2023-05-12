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
pub use teerex_primitives::{Enclave, MrEnclave};

pub fn get_signer<AccountId: From<[u8; 32]>>(pubkey: &[u8; 32]) -> AccountId {
	AccountId::from(*pubkey)
}

pub trait TestEnclave<AccountId, Url> {
	fn test_enclave(pubkey: AccountId) -> Enclave<AccountId, Url>;
	fn with_mr_enclave(self, mr_enclave: MrEnclave) -> Enclave<AccountId, Url>;
	fn with_timestamp(self, timestamp: u64) -> Enclave<AccountId, Url>;
	fn with_url(self, url: Url) -> Enclave<AccountId, Url>;
}

impl<AccountId, Url: Default> TestEnclave<AccountId, Url> for Enclave<AccountId, Url> {
	fn test_enclave(pubkey: AccountId) -> Self {
		Enclave::new(
			pubkey,
			Default::default(),
			Default::default(),
			Default::default(),
			Default::default(),
		)
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
		self.url = url;
		self
	}
}
