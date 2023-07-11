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

use crate::{
	mock::*, Error, Event as EnclaveBridgeEvent, ExecutedUnshieldCalls, Request, DATA_LENGTH_LIMIT,
};
use codec::{Decode, Encode};
use enclave_bridge_primitives::{EnclaveFingerprint, ShardIdentifier};
use frame_support::{assert_err, assert_ok};
use sp_core::H256;
use sp_keyring::AccountKeyring;
use teerex_primitives::{MultiEnclave, SgxEnclave};
use test_utils::TestEnclave;

// give get_signer a concrete type
fn get_signer(pubkey: &[u8; 32]) -> AccountId {
	test_utils::get_signer(pubkey)
}

fn get_bonding_account(enclave: &MultiEnclave<Vec<u8>>) -> AccountId {
	AccountId::decode(&mut enclave.fingerprint().encode().as_ref()).unwrap()
}

fn now() -> u64 {
	<timestamp::Pallet<Test>>::get()
}

fn register_sovereign_test_enclave(signer: &AccountId) -> MultiEnclave<Vec<u8>> {
	let enclave = MultiEnclave::from(
		SgxEnclave::test_enclave()
			.with_pubkey(&signer.encode()[..])
			.with_timestamp(now()),
	);
	assert_ok!(Teerex::add_enclave(signer, enclave.clone()));
	enclave
}

pub const NOW: u64 = 1587899785000;

#[test]
fn invoke_works() {
	new_test_ext().execute_with(|| {
		let req = Request { shard: ShardIdentifier::default(), cyphertext: vec![0u8, 1, 2, 3, 4] };
		// don't care who signs
		let signer = AccountKeyring::Alice.to_account_id();

		assert!(EnclaveBridge::invoke(RuntimeOrigin::signed(signer), req.clone()).is_ok());
		let expected_event = RuntimeEvent::EnclaveBridge(
			EnclaveBridgeEvent::IndirectInvocationRegistered(req.shard),
		);
		println!("events:{:?}", System::events());
		assert!(System::events().iter().any(|a| a.event == expected_event));
	})
}

#[test]
fn unshield_is_only_executed_once_for_the_same_call_hash() {
	new_test_ext().execute_with(|| {
		Timestamp::set_timestamp(NOW);
		let enclave_signer = AccountKeyring::Eve.to_account_id();
		let shielder = AccountKeyring::Alice.to_account_id();
		let beneficiary = AccountKeyring::Bob.to_account_id();

		let call_hash: H256 = H256::from([1u8; 32]);

		let enclave = register_sovereign_test_enclave(&enclave_signer);
		let bonding_account = get_bonding_account(&enclave);

		let amount = 50;

		assert_ok!(Balances::transfer(
			RuntimeOrigin::signed(shielder),
			bonding_account.clone(),
			1 << 50
		));

		assert!(EnclaveBridge::unshield_funds(
			RuntimeOrigin::signed(enclave_signer.clone()),
			beneficiary.clone(),
			amount,
			bonding_account.clone(),
			call_hash
		)
		.is_ok());
		let expected_event = RuntimeEvent::EnclaveBridge(EnclaveBridgeEvent::UnshieldedFunds(
			beneficiary.clone(),
			amount,
		));
		assert!(System::events().iter().any(|a| a.event == expected_event));

		System::reset_events();

		assert!(EnclaveBridge::unshield_funds(
			RuntimeOrigin::signed(enclave_signer),
			beneficiary,
			amount,
			bonding_account,
			call_hash
		)
		.is_ok());
		assert!(!System::events().iter().any(|a| a.event == expected_event));

		assert_eq!(<ExecutedUnshieldCalls<Test>>::get(call_hash), 2)
	})
}

#[test]
fn verify_unshield_funds_works() {
	new_test_ext().execute_with(|| {
		Timestamp::set_timestamp(NOW);
		let enclave_signer = AccountKeyring::Eve.to_account_id();
		let shielder = AccountKeyring::Alice.to_account_id();
		let beneficiary = AccountKeyring::Bob.to_account_id();

		let call_hash: H256 = H256::from([1u8; 32]);

		let enclave = register_sovereign_test_enclave(&enclave_signer);
		let bonding_account = get_bonding_account(&enclave);

		let incognito_account_encrypted = vec![1, 2, 3];
		assert!(EnclaveBridge::shield_funds(
			RuntimeOrigin::signed(shielder.clone()),
			incognito_account_encrypted.clone(),
			100,
			bonding_account.clone(),
		)
		.is_ok());

		assert_eq!(Balances::free_balance(bonding_account.clone()), 100);

		let expected_event = RuntimeEvent::EnclaveBridge(EnclaveBridgeEvent::ShieldFunds(
			incognito_account_encrypted,
			100,
		));
		assert!(System::events().iter().any(|a| a.event == expected_event));

		assert!(EnclaveBridge::unshield_funds(
			RuntimeOrigin::signed(enclave_signer),
			beneficiary.clone(),
			50,
			bonding_account.clone(),
			call_hash
		)
		.is_ok());
		assert_eq!(Balances::free_balance(bonding_account), 50);

		let expected_event =
			RuntimeEvent::EnclaveBridge(EnclaveBridgeEvent::UnshieldedFunds(beneficiary, 50));
		assert!(System::events().iter().any(|a| a.event == expected_event));
	})
}

#[test]
fn unshield_funds_from_not_registered_enclave_errs() {
	new_test_ext().execute_with(|| {
		Timestamp::set_timestamp(NOW);
		let enclave_signer = AccountKeyring::Eve.to_account_id();
		let beneficiary = AccountKeyring::Bob.to_account_id();
		let bonding_account = get_signer(&[111u8; 32]);
		let call_hash: H256 = H256::from([1u8; 32]);

		assert_err!(
			EnclaveBridge::unshield_funds(
				RuntimeOrigin::signed(enclave_signer),
				beneficiary,
				51,
				bonding_account,
				call_hash
			),
			pallet_teerex::Error::<Test>::EnclaveIsNotRegistered
		);
	})
}

#[test]
fn unshield_funds_from_enclave_neq_bonding_account_errs() {
	new_test_ext().execute_with(|| {
		Timestamp::set_timestamp(NOW);
		let enclave_signer = AccountKeyring::Eve.to_account_id();
		let shielder = AccountKeyring::Alice.to_account_id();
		let beneficiary = AccountKeyring::Bob.to_account_id();
		let incognito_account_encrypted = vec![1, 2, 3];

		let call_hash: H256 = H256::from([1u8; 32]);

		let enclave = register_sovereign_test_enclave(&enclave_signer);
		let not_bonding_account = get_bonding_account(&enclave);
		let bonding_account = get_signer(&[222u8; 32]);

		//Ensure that both bonding account have funds
		assert!(EnclaveBridge::shield_funds(
			RuntimeOrigin::signed(shielder.clone()),
			incognito_account_encrypted.clone(),
			100,
			bonding_account.clone(),
		)
		.is_ok());

		assert!(EnclaveBridge::shield_funds(
			RuntimeOrigin::signed(shielder.clone()),
			incognito_account_encrypted.clone(),
			100,
			not_bonding_account.clone(),
		)
		.is_ok());

		assert_err!(
			EnclaveBridge::unshield_funds(
				RuntimeOrigin::signed(enclave_signer),
				beneficiary,
				50,
				bonding_account.clone(),
				call_hash
			),
			Error::<Test>::WrongFingerprintForBondingAccount
		);

		assert_eq!(Balances::free_balance(bonding_account), 100);
		assert_eq!(Balances::free_balance(not_bonding_account), 100);
	})
}

#[test]
fn confirm_processed_parentchain_block_works() {
	new_test_ext().execute_with(|| {
		let block_hash = H256::default();
		let merkle_root = H256::default();
		let block_number = 3;
		let enclave_signer = AccountKeyring::Eve.to_account_id();
		let _enclave = register_sovereign_test_enclave(&enclave_signer);

		assert_ok!(EnclaveBridge::confirm_processed_parentchain_block(
			RuntimeOrigin::signed(enclave_signer.clone()),
			ShardIdentifier::default(),
			block_hash,
			block_number,
			merkle_root,
		));

		let expected_event =
			RuntimeEvent::EnclaveBridge(EnclaveBridgeEvent::ProcessedParentchainBlock(
				ShardIdentifier::default(),
				block_hash,
				merkle_root,
				block_number,
			));
		assert!(System::events().iter().any(|a| a.event == expected_event));
	})
}

#[test]
fn confirm_processed_parentchain_block_from_unregistered_enclave_fails() {
	new_test_ext().execute_with(|| {
		let enclave_signer = AccountKeyring::Eve.to_account_id();
		let shard = ShardIdentifier::from(EnclaveFingerprint::default());

		assert_err!(
			EnclaveBridge::confirm_processed_parentchain_block(
				RuntimeOrigin::signed(enclave_signer),
				shard,
				H256::default(),
				3,
				H256::default(),
			),
			pallet_teerex::Error::<Test>::EnclaveIsNotRegistered
		);
	})
}

#[test]
fn confirm_processed_parentchain_block_from_wrong_enclave_fails() {
	new_test_ext().execute_with(|| {
		let enclave_signer = AccountKeyring::Eve.to_account_id();
		let _enclave = register_sovereign_test_enclave(&enclave_signer);
		let shard = ShardIdentifier::from([42u8; 32]);

		assert_err!(
			EnclaveBridge::confirm_processed_parentchain_block(
				RuntimeOrigin::signed(enclave_signer),
				shard,
				H256::default(),
				3,
				H256::default(),
			),
			Error::<Test>::WrongFingerprintForShard
		);
	})
}

#[test]
fn publish_hash_works() {
	use frame_system::{EventRecord, Phase};

	new_test_ext().execute_with(|| {
		let enclave_signer = AccountKeyring::Eve.to_account_id();
		let _enclave = register_sovereign_test_enclave(&enclave_signer);

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
		topics.push(fingerprint.into());

		// Check that topics are reflected in the event record.
		assert_eq!(
			System::events(),
			vec![
				EventRecord {
					phase: Phase::Initialization,
					event: EnclaveBridgeEvent::PublishedHash {
						fingerprint: fingerprint.into(),
						hash,
						data
					}
					.into(),
					topics,
				},
				EventRecord {
					phase: Phase::Initialization,
					event: EnclaveBridgeEvent::PublishedHash {
						fingerprint: fingerprint.into(),
						hash,
						data: vec![]
					}
					.into(),
					topics: vec![fingerprint.into()],
				},
			]
		);
	})
}

#[test]
fn publish_hash_with_unregistered_enclave_fails() {
	new_test_ext().execute_with(|| {
		let enclave_signer = AccountKeyring::Eve.to_account_id();

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
		let enclave_signer = AccountKeyring::Eve.to_account_id();
		let _enclave = register_sovereign_test_enclave(&enclave_signer);

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
		let enclave_signer = AccountKeyring::Eve.to_account_id();
		let _enclave = register_sovereign_test_enclave(&enclave_signer);

		let hash = H256::from([1u8; 32]);
		let data = vec![0u8; DATA_LENGTH_LIMIT + 1];

		assert_err!(
			EnclaveBridge::publish_hash(RuntimeOrigin::signed(enclave_signer), hash, vec![], data),
			Error::<Test>::DataTooLong
		);
	})
}
