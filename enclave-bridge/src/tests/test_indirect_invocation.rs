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
use crate::{Error, Event as EnclaveBridgeEvent, ExecutedUnshieldCalls, Request, ShardConfig};
use enclave_bridge_primitives::{EnclaveFingerprint, ShardIdentifier};
use frame_support::{assert_err, assert_ok};
use sp_core::H256;
use sp_keyring::Sr25519Keyring as Keyring;

#[test]
fn invoke_works() {
	new_test_ext().execute_with(|| {
		let req = Request { shard: ShardIdentifier::default(), cyphertext: vec![0u8, 1, 2, 3, 4] };
		// don't care who signs
		let signer = Keyring::Alice.to_account_id();

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
		let enclave_signer = Keyring::Eve.to_account_id();
		let shielder = Keyring::Alice.to_account_id();
		let beneficiary = Keyring::Bob.to_account_id();

		let call_hash: H256 = H256::from([1u8; 32]);

		let enclave =
			register_sovereign_test_enclave(&enclave_signer, EnclaveFingerprint::default());
		let bonding_account = get_bonding_account(&enclave);
		let shard = ShardIdentifier::from(enclave.fingerprint());

		let amount = 50;

		assert_ok!(Balances::transfer_allow_death(
			RuntimeOrigin::signed(shielder),
			bonding_account.clone(),
			1 << 50
		));

		assert!(EnclaveBridge::unshield_funds(
			RuntimeOrigin::signed(enclave_signer.clone()),
			shard,
			beneficiary.clone(),
			amount,
			call_hash
		)
		.is_ok());
		let expected_event = RuntimeEvent::EnclaveBridge(EnclaveBridgeEvent::UnshieldedFunds {
			shard,
			beneficiary: beneficiary.clone(),
			amount,
		});
		assert!(System::events().iter().any(|a| a.event == expected_event));

		System::reset_events();

		assert!(EnclaveBridge::unshield_funds(
			RuntimeOrigin::signed(enclave_signer),
			shard,
			beneficiary,
			amount,
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
		let enclave_signer = Keyring::Eve.to_account_id();
		let shielder = Keyring::Alice.to_account_id();
		let beneficiary = Keyring::Bob.to_account_id();

		let call_hash: H256 = H256::from([1u8; 32]);

		let enclave =
			register_sovereign_test_enclave(&enclave_signer, EnclaveFingerprint::default());
		let bonding_account = get_bonding_account(&enclave);
		let shard = ShardIdentifier::from(enclave.fingerprint());

		let incognito_account_encrypted = vec![1, 2, 3];
		assert!(EnclaveBridge::shield_funds(
			RuntimeOrigin::signed(shielder.clone()),
			shard,
			incognito_account_encrypted.clone(),
			100,
		)
		.is_ok());

		assert_eq!(Balances::free_balance(bonding_account.clone()), 100);

		let expected_event = RuntimeEvent::EnclaveBridge(EnclaveBridgeEvent::ShieldFunds {
			shard,
			encrypted_beneficiary: incognito_account_encrypted,
			amount: 100,
		});
		assert!(System::events().iter().any(|a| a.event == expected_event));

		assert!(EnclaveBridge::unshield_funds(
			RuntimeOrigin::signed(enclave_signer),
			shard,
			beneficiary.clone(),
			50,
			call_hash
		)
		.is_ok());
		assert_eq!(Balances::free_balance(bonding_account), 50);

		let expected_event = RuntimeEvent::EnclaveBridge(EnclaveBridgeEvent::UnshieldedFunds {
			shard,
			beneficiary,
			amount: 50,
		});
		assert!(System::events().iter().any(|a| a.event == expected_event));
	})
}

#[test]
fn unshield_funds_from_not_registered_enclave_errs() {
	new_test_ext().execute_with(|| {
		Timestamp::set_timestamp(NOW);
		let enclave_signer = Keyring::Eve.to_account_id();
		let beneficiary = Keyring::Bob.to_account_id();
		let call_hash: H256 = H256::from([1u8; 32]);
		let shard = ShardIdentifier::default();
		assert_err!(
			EnclaveBridge::unshield_funds(
				RuntimeOrigin::signed(enclave_signer),
				shard,
				beneficiary,
				51,
				call_hash
			),
			pallet_teerex::Error::<Test>::EnclaveIsNotRegistered
		);
	})
}

#[test]
fn unshield_funds_from_enclave_on_wrong_shard_errs() {
	new_test_ext().execute_with(|| {
		Timestamp::set_timestamp(NOW);
		let enclave_signer = Keyring::Eve.to_account_id();
		let shielder = Keyring::Alice.to_account_id();
		let beneficiary = Keyring::Bob.to_account_id();
		let incognito_account_encrypted = vec![1, 2, 3];

		let call_hash: H256 = H256::from([1u8; 32]);

		let enclave =
			register_sovereign_test_enclave(&enclave_signer, EnclaveFingerprint::default());
		let shard = ShardIdentifier::from(enclave.fingerprint());
		let not_shard = ShardIdentifier::from([222u8; 32]);
		let bonding_account = AccountId::decode(&mut shard.as_ref()).unwrap();
		let not_bonding_account = AccountId::decode(&mut not_shard.as_ref()).unwrap();

		//Ensure that both bonding account have funds
		assert!(EnclaveBridge::shield_funds(
			RuntimeOrigin::signed(shielder.clone()),
			shard,
			incognito_account_encrypted.clone(),
			100,
		)
		.is_ok());

		assert!(EnclaveBridge::shield_funds(
			RuntimeOrigin::signed(shielder.clone()),
			not_shard,
			incognito_account_encrypted.clone(),
			100,
		)
		.is_ok());

		assert_err!(
			EnclaveBridge::unshield_funds(
				RuntimeOrigin::signed(enclave_signer),
				not_shard,
				beneficiary,
				50,
				call_hash
			),
			Error::<Test>::WrongFingerprintForShard
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
		let enclave_signer = Keyring::Eve.to_account_id();
		let _enclave =
			register_sovereign_test_enclave(&enclave_signer, EnclaveFingerprint::default());

		assert_ok!(EnclaveBridge::confirm_processed_parentchain_block(
			RuntimeOrigin::signed(enclave_signer.clone()),
			ShardIdentifier::default(),
			block_hash,
			block_number,
			merkle_root,
		));

		let expected_event =
			RuntimeEvent::EnclaveBridge(EnclaveBridgeEvent::ProcessedParentchainBlock {
				shard: ShardIdentifier::default(),
				block_hash,
				trusted_calls_merkle_root: merkle_root,
				block_number,
			});
		assert!(System::events().iter().any(|a| a.event == expected_event));
	})
}

#[test]
fn confirm_processed_parentchain_block_from_unregistered_enclave_fails() {
	new_test_ext().execute_with(|| {
		let enclave_signer = Keyring::Eve.to_account_id();
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
		let enclave_signer = Keyring::Eve.to_account_id();
		let _enclave =
			register_sovereign_test_enclave(&enclave_signer, EnclaveFingerprint::default());
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
fn confirm_processed_parentchain_block_from_updated_enclave_works() {
	new_test_ext().execute_with(|| {
		Timestamp::set_timestamp(NOW);
		run_to_block(1);
		let enclave_signer = Keyring::Eve.to_account_id();
		let enclave =
			register_sovereign_test_enclave(&enclave_signer, EnclaveFingerprint::default());
		let shard = ShardIdentifier::from(enclave.fingerprint());
		// initialize shard
		assert_ok!(EnclaveBridge::update_shard_config(
			RuntimeOrigin::signed(enclave_signer.clone()),
			shard,
			ShardConfig::new(enclave.fingerprint()),
			0,
		));

		assert_ok!(EnclaveBridge::confirm_processed_parentchain_block(
			RuntimeOrigin::signed(enclave_signer.clone()),
			ShardIdentifier::default(),
			H256::default(),
			1,
			H256::default(),
		));

		let new_fingerprint = EnclaveFingerprint::from([2u8; 32]);

		assert_ok!(EnclaveBridge::update_shard_config(
			RuntimeOrigin::signed(enclave_signer.clone()),
			shard,
			ShardConfig::new(new_fingerprint),
			1,
		));

		// should still work with old enclave because update not yet enacted
		assert_ok!(EnclaveBridge::confirm_processed_parentchain_block(
			RuntimeOrigin::signed(enclave_signer.clone()),
			ShardIdentifier::default(),
			H256::default(),
			1,
			H256::default(),
		));

		run_to_block(2);

		// enclave upgrade of instance takes place
		register_sovereign_test_enclave(&enclave_signer, new_fingerprint);

		// now retry as new enclave with same signer
		assert_ok!(EnclaveBridge::confirm_processed_parentchain_block(
			RuntimeOrigin::signed(enclave_signer.clone()),
			ShardIdentifier::default(),
			H256::default(),
			2,
			H256::default(),
		));
	})
}
