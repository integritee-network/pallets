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

#![cfg(any(test, feature = "runtime-benchmarks"))]

use crate::Enclave;

impl<AccountId, Url> Enclave<AccountId, Url> {
	pub fn with_pubkey(mut self, pubkey: AccountId) -> Self {
		self.pubkey = pubkey;
		self
	}

	pub fn with_mr_enclave(mut self, mr_enclave: [u8; 32]) -> Self {
		self.mr_enclave = mr_enclave;
		self
	}

	pub fn with_timestamp(mut self, timestamp: u64) -> Self {
		self.timestamp = timestamp;
		self
	}

	pub fn with_url(mut self, url: Url) -> Self {
		self.url = url;
		self
	}
}
