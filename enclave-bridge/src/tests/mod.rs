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

use crate::mock::*;
use codec::{Decode, Encode};
use frame_support::assert_ok;
use teerex_primitives::{EnclaveFingerprint, MultiEnclave, SgxEnclave};
use test_utils::TestEnclave;

mod test_indirect_invocation;
mod test_publish_hash;
mod test_shard_config;

fn get_bonding_account(enclave: &MultiEnclave<Vec<u8>>) -> AccountId {
	AccountId::decode(&mut enclave.fingerprint().encode().as_ref()).unwrap()
}

fn now() -> u64 {
	<timestamp::Pallet<Test>>::get()
}

fn register_sovereign_test_enclave(
	signer: &AccountId,
	fingerprint: EnclaveFingerprint,
) -> MultiEnclave<Vec<u8>> {
	let enclave = MultiEnclave::from(
		SgxEnclave::test_enclave()
			.with_mr_enclave(fingerprint.into())
			.with_pubkey(&signer.encode()[..])
			.with_timestamp(now()),
	);
	assert_ok!(Teerex::add_enclave(signer, enclave.clone()));
	enclave
}

pub const NOW: u64 = 1587899785000;
