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

use crate::{mock::*, Enclave, EnclaveRegistry};
use frame_support::assert_ok;
use sp_keyring::AccountKeyring;
use test_utils::ias::{
	consts::{TEST4_MRENCLAVE, URL},
	TestEnclave,
};

fn now() -> u64 {
	<timestamp::Pallet<Test>>::get()
}

fn test_enclave() -> Enclave<AccountId, Vec<u8>> {
	Enclave::test_enclave(AccountKeyring::Alice.to_account_id())
		.with_timestamp(now())
		.with_url(URL.to_vec())
}

#[test]
fn register_enclave_with_empty_mrenclave_works() {
	new_test_ext().execute_with(|| {
		assert_ok!(Teerex::register_enclave(
			Origin::signed(AccountKeyring::Alice.to_account_id()),
			Vec::new(),
			URL.to_vec()
		));

		assert_eq!(Teerex::enclave_count(), 1);
		assert_eq!(<EnclaveRegistry<Test>>::get(1).unwrap(), test_enclave());
	})
}

#[test]
fn register_enclave_with_mrenclave_works() {
	new_test_ext().execute_with(|| {
		assert_ok!(Teerex::register_enclave(
			Origin::signed(AccountKeyring::Alice.to_account_id()),
			TEST4_MRENCLAVE.to_vec(),
			URL.to_vec()
		));

		let enc = test_enclave().with_mr_enclave(TEST4_MRENCLAVE);

		assert_eq!(Teerex::enclave_count(), 1);
		assert_eq!(<EnclaveRegistry<Test>>::get(1).unwrap(), enc);
	})
}

#[test]
fn register_enclave_with_faulty_mrenclave_inserts_default() {
	new_test_ext().execute_with(|| {
		assert_ok!(Teerex::register_enclave(
			Origin::signed(AccountKeyring::Alice.to_account_id()),
			[1u8, 2].to_vec(),
			URL.to_vec()
		));

		assert_eq!(Teerex::enclave_count(), 1);
		assert_eq!(<EnclaveRegistry<Test>>::get(1).unwrap(), test_enclave());
	})
}

#[test]
fn register_enclave_with_empty_url_inserts_default() {
	new_test_ext().execute_with(|| {
		assert_ok!(Teerex::register_enclave(
			Origin::signed(AccountKeyring::Alice.to_account_id()),
			Vec::new(),
			Vec::new(),
		));

		let enc = test_enclave().with_url(Default::default());

		assert_eq!(Teerex::enclave_count(), 1);
		assert_eq!(<EnclaveRegistry<Test>>::get(1).unwrap(), enc);
	})
}
