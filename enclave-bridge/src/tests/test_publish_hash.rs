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

use super::*;
use crate::{Error, Event as EnclaveBridgeEvent, DATA_LENGTH_LIMIT};
use frame_support::{assert_err, assert_ok};
use sp_core::H256;
use sp_keyring::Sr25519Keyring as Keyring;

#[test]
fn publish_hash_works() {
	use frame_system::{EventRecord, Phase};

	new_test_ext().execute_with(|| {
		let enclave_signer = Keyring::Eve.to_account_id();
		let _enclave =
			register_sovereign_test_enclave(&enclave_signer, EnclaveFingerprint::default());

		// There are no events emitted at the genesis block.
		System::set_block_number(1);
		System::reset_events();

		let hash = H256::from([1u8; 32]);
		let extra_topics = vec![H256::from([2u8; 32]), H256::from([3u8; 32])];
		let data = b"hello world".to_vec();

		// publish with extra topics and data
		assert_ok!(EnclaveBridge::publish_hash(
			RuntimeOrigin::signed(enclave_signer.clone()),
			hash,
			extra_topics.clone(),
			data.clone()
		));

		// publish without extra topics and data
		assert_ok!(EnclaveBridge::publish_hash(
			RuntimeOrigin::signed(enclave_signer.clone()),
			hash,
			vec![],
			vec![]
		));

		let fingerprint = Teerex::sovereign_enclaves(&enclave_signer).unwrap().fingerprint();
		let mut topics = extra_topics;
		topics.push(fingerprint);

		// Check that topics are reflected in the event record.
		assert_eq!(
			System::events(),
			vec![
				EventRecord {
					phase: Phase::Initialization,
					event: EnclaveBridgeEvent::PublishedHash {
						enclave_fingerprint: fingerprint,
						hash,
						data
					}
					.into(),
					topics,
				},
				EventRecord {
					phase: Phase::Initialization,
					event: EnclaveBridgeEvent::PublishedHash {
						enclave_fingerprint: fingerprint,
						hash,
						data: vec![]
					}
					.into(),
					topics: vec![fingerprint],
				},
			]
		);
	})
}

#[test]
fn publish_hash_with_unregistered_enclave_fails() {
	new_test_ext().execute_with(|| {
		let enclave_signer = Keyring::Eve.to_account_id();

		assert_err!(
			EnclaveBridge::publish_hash(
				RuntimeOrigin::signed(enclave_signer),
				[1u8; 32].into(),
				vec![],
				vec![]
			),
			pallet_teerex::Error::<Test>::EnclaveIsNotRegistered
		);
	})
}

#[test]
fn publish_hash_with_too_many_topics_fails() {
	new_test_ext().execute_with(|| {
		let enclave_signer = Keyring::Eve.to_account_id();
		let _enclave =
			register_sovereign_test_enclave(&enclave_signer, EnclaveFingerprint::default());

		let hash = H256::from([1u8; 32]);
		let extra_topics = vec![
			H256::from([0u8; 32]),
			H256::from([1u8; 32]),
			H256::from([2u8; 32]),
			H256::from([3u8; 32]),
			H256::from([4u8; 32]),
			H256::from([5u8; 32]),
		];

		assert_err!(
			EnclaveBridge::publish_hash(
				RuntimeOrigin::signed(enclave_signer),
				hash,
				extra_topics,
				vec![]
			),
			Error::<Test>::TooManyTopics
		);
	})
}

#[test]
fn publish_hash_with_too_much_data_fails() {
	new_test_ext().execute_with(|| {
		let enclave_signer = Keyring::Eve.to_account_id();
		let _enclave =
			register_sovereign_test_enclave(&enclave_signer, EnclaveFingerprint::default());

		let hash = H256::from([1u8; 32]);
		let data = vec![0u8; DATA_LENGTH_LIMIT + 1];

		assert_err!(
			EnclaveBridge::publish_hash(RuntimeOrigin::signed(enclave_signer), hash, vec![], data),
			Error::<Test>::DataTooLong
		);
	})
}
