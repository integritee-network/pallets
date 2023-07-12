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
use crate::{Error, Event as EnclaveBridgeEvent, ShardConfigRegistry};
use enclave_bridge_primitives::{ShardConfig, ShardIdentifier, UpgradableShardConfig};
use frame_support::{assert_err, assert_ok};
use sp_keyring::AccountKeyring;
use teerex_primitives::EnclaveFingerprint;

#[test]
fn initial_update_shard_config_works() {
	new_test_ext().execute_with(|| {
		Timestamp::set_timestamp(NOW);
		let enclave_signer = AccountKeyring::Eve.to_account_id();
		let enclave =
			register_sovereign_test_enclave(&enclave_signer, EnclaveFingerprint::default());
		assert!(EnclaveBridge::update_shard_config(
			RuntimeOrigin::signed(enclave_signer.clone()),
			enclave.fingerprint(),
			ShardConfig::new(enclave.fingerprint()),
			0,
		)
		.is_ok());

		let expected_event = RuntimeEvent::EnclaveBridge(EnclaveBridgeEvent::ShardConfigUpdated(
			enclave.fingerprint(),
		));
		assert!(System::events().iter().any(|a| a.event == expected_event));
	})
}

#[test]
fn initial_update_shard_config_as_non_enclave_fails() {
	new_test_ext().execute_with(|| {
		Timestamp::set_timestamp(NOW);
		let enclave_signer = AccountKeyring::Eve.to_account_id();
		assert_err!(
			EnclaveBridge::update_shard_config(
				RuntimeOrigin::signed(enclave_signer.clone()),
				ShardIdentifier::from([1u8; 32]),
				ShardConfig::new(EnclaveFingerprint::default()),
				0,
			),
			pallet_teerex::Error::<Test>::EnclaveIsNotRegistered
		);
	})
}

#[test]
/// any registered enclave should be able to create arbitrary new shards as long as they don't exist yet
fn initial_update_shard_config_on_foreign_shard_works() {
	new_test_ext().execute_with(|| {
		Timestamp::set_timestamp(NOW);
		let enclave_signer = AccountKeyring::Eve.to_account_id();
		let enclave =
			register_sovereign_test_enclave(&enclave_signer, EnclaveFingerprint::default());

		let new_shard = ShardIdentifier::from([1u8; 32]);
		assert_ok!(EnclaveBridge::update_shard_config(
			RuntimeOrigin::signed(enclave_signer.clone()),
			new_shard,
			ShardConfig::new(enclave.fingerprint()),
			0,
		));
	})
}

#[test]
fn update_shard_config_to_new_fingerprint_works() {
	new_test_ext().execute_with(|| {
		Timestamp::set_timestamp(NOW);
		let enclave_signer = AccountKeyring::Eve.to_account_id();
		let enclave =
			register_sovereign_test_enclave(&enclave_signer, EnclaveFingerprint::default());
		let shard = ShardIdentifier::from(enclave.fingerprint());
		assert_ok!(EnclaveBridge::update_shard_config(
			RuntimeOrigin::signed(enclave_signer.clone()),
			shard,
			ShardConfig::new(enclave.fingerprint()),
			0,
		));

		let expected_event =
			RuntimeEvent::EnclaveBridge(EnclaveBridgeEvent::ShardConfigUpdated(shard));
		assert!(System::events().iter().any(|a| a.event == expected_event));

		assert_ok!(EnclaveBridge::update_shard_config(
			RuntimeOrigin::signed(enclave_signer.clone()),
			shard,
			ShardConfig::new([1u8; 32].into()),
			10,
		));

		let expected_event =
			RuntimeEvent::EnclaveBridge(EnclaveBridgeEvent::ShardConfigUpdated(shard));
		assert!(System::events().iter().any(|a| a.event == expected_event));
	})
}

#[test]
fn update_existing_shard_config_as_non_enclave_fails() {
	new_test_ext().execute_with(|| {
		Timestamp::set_timestamp(NOW);
		let enclave_signer = AccountKeyring::Eve.to_account_id();
		let enclave =
			register_sovereign_test_enclave(&enclave_signer, EnclaveFingerprint::default());

		// initialize shard
		assert_ok!(EnclaveBridge::update_shard_config(
			RuntimeOrigin::signed(enclave_signer.clone()),
			ShardIdentifier::from(enclave.fingerprint()),
			ShardConfig::new(enclave.fingerprint()),
			0,
		));

		// try to update as non-enclave
		assert_err!(
			EnclaveBridge::update_shard_config(
				RuntimeOrigin::signed(AccountKeyring::Alice.to_account_id()),
				ShardIdentifier::from(enclave.fingerprint()),
				ShardConfig::new(enclave.fingerprint()),
				0,
			),
			pallet_teerex::Error::<Test>::EnclaveIsNotRegistered
		);
	})
}

#[test]
fn update_existing_shard_config_as_wrong_enclave_fails() {
	new_test_ext().execute_with(|| {
		Timestamp::set_timestamp(NOW);
		let enclave_signer = AccountKeyring::Eve.to_account_id();
		let enclave =
			register_sovereign_test_enclave(&enclave_signer, EnclaveFingerprint::default());
		let wrong_enclave_signer = AccountKeyring::Ferdie.to_account_id();
		let wrong_enclave = register_sovereign_test_enclave(
			&wrong_enclave_signer,
			EnclaveFingerprint::from([1u8; 32]),
		);
		// initialize shard
		assert_ok!(EnclaveBridge::update_shard_config(
			RuntimeOrigin::signed(enclave_signer.clone()),
			ShardIdentifier::from(enclave.fingerprint()),
			ShardConfig::new(enclave.fingerprint()),
			0,
		));
		// try to update as wrong-enclave
		assert_err!(
			EnclaveBridge::update_shard_config(
				RuntimeOrigin::signed(wrong_enclave_signer.clone()),
				ShardIdentifier::from(enclave.fingerprint()),
				ShardConfig::new(wrong_enclave.fingerprint()),
				0,
			),
			Error::<Test>::WrongFingerprintForShard
		);
	})
}

#[test]
fn get_maybe_updated_shard_config_works() {
	new_test_ext().execute_with(|| {
		Timestamp::set_timestamp(NOW);
		run_to_block(1);
		let enclave_signer = AccountKeyring::Eve.to_account_id();
		let enclave =
			register_sovereign_test_enclave(&enclave_signer, EnclaveFingerprint::default());
		let initial_fingerprint = enclave.fingerprint();
		let shard = ShardIdentifier::from(initial_fingerprint);
		// initialize shard
		assert_ok!(EnclaveBridge::update_shard_config(
			RuntimeOrigin::signed(enclave_signer.clone()),
			shard,
			ShardConfig::new(initial_fingerprint),
			0,
		));

		assert_eq!(
			EnclaveBridge::get_maybe_updated_shard_config(shard)
				.unwrap()
				.enclave_fingerprint,
			initial_fingerprint
		);

		let new_fingerprint = EnclaveFingerprint::from([2u8; 32]);
		let new_shard_config = ShardConfig::new(new_fingerprint);

		assert_ok!(EnclaveBridge::update_shard_config(
			RuntimeOrigin::signed(enclave_signer.clone()),
			shard,
			new_shard_config.clone(),
			1,
		));
		assert_eq!(<frame_system::Pallet<Test>>::block_number(), 1);

		assert_eq!(
			<ShardConfigRegistry<Test>>::iter()
				.collect::<Vec<(ShardIdentifier, UpgradableShardConfig<AccountId, BlockNumber>)>>()[0]
				.1,
			UpgradableShardConfig::from(ShardConfig::new(initial_fingerprint))
				.with_pending_upgrade(new_shard_config, 2)
		);
		// should still work with old enclave because update not yet enacted
		assert_eq!(
			EnclaveBridge::get_maybe_updated_shard_config(shard)
				.unwrap()
				.enclave_fingerprint,
			enclave.fingerprint()
		);

		run_to_block(2);

		assert_eq!(<frame_system::Pallet<Test>>::block_number(), 2);
		assert_eq!(
			EnclaveBridge::get_maybe_updated_shard_config(shard)
				.unwrap()
				.enclave_fingerprint,
			new_fingerprint
		);
	})
}
