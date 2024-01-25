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
use crate::{Error, Event as EnclaveBridgeEvent};
use enclave_bridge_primitives::ShardIdentifier;
use frame_support::{assert_noop, assert_ok};
use sp_keyring::AccountKeyring;
use teerex_primitives::EnclaveFingerprint;

#[test]
fn purge_enclave_from_shard_status_works_if_present() {
	new_test_ext().execute_with(|| {
		Timestamp::set_timestamp(NOW);
		let enclave_signer_1 = AccountKeyring::Eve.to_account_id();
		let enclave_signer_2 = AccountKeyring::Ferdie.to_account_id();
		let enclave_fingerprint = EnclaveFingerprint::default();
		let shard = ShardIdentifier::default();
		assert_ok!(EnclaveBridge::touch_shard(
			shard,
			&enclave_signer_1.clone(),
			enclave_fingerprint,
			1
		));
		assert_ok!(EnclaveBridge::purge_enclave_from_shard_status(
			RuntimeOrigin::root(),
			shard,
			enclave_signer_1.clone(),
		));
		let expected_event =
			RuntimeEvent::EnclaveBridge(EnclaveBridgeEvent::PurgedEnclaveFromShardConfig {
				shard,
				subject: enclave_signer_1.clone(),
			});
		println!("events:{:?}", System::events());
		assert!(System::events().iter().any(|a| a.event == expected_event));

		assert!(EnclaveBridge::shard_status(shard).is_some());
		assert_eq!(EnclaveBridge::shard_status(shard).unwrap().len(), 0);
		assert_ok!(EnclaveBridge::touch_shard(
			shard,
			&enclave_signer_1.clone(),
			enclave_fingerprint,
			2
		));
		assert_ok!(EnclaveBridge::touch_shard(
			shard,
			&enclave_signer_2.clone(),
			enclave_fingerprint,
			2
		));
		assert!(EnclaveBridge::shard_status(shard).is_some());
		assert_eq!(EnclaveBridge::shard_status(shard).unwrap().len(), 2);

		assert_ok!(EnclaveBridge::purge_enclave_from_shard_status(
			RuntimeOrigin::root(),
			shard,
			enclave_signer_1,
		));

		assert!(EnclaveBridge::shard_status(shard).is_some());
		assert_eq!(EnclaveBridge::shard_status(shard).unwrap().len(), 1);
		assert_eq!(EnclaveBridge::shard_status(shard).unwrap()[0].signer, enclave_signer_2);
	})
}

#[test]
fn purge_enclave_from_shard_status_for_inexistent_shard_is_err() {
	new_test_ext().execute_with(|| {
		Timestamp::set_timestamp(NOW);
		let enclave_signer_1 = AccountKeyring::Eve.to_account_id();
		let shard = ShardIdentifier::default();

		assert_noop!(
			EnclaveBridge::purge_enclave_from_shard_status(
				RuntimeOrigin::root(),
				shard,
				enclave_signer_1.clone(),
			),
			Error::<Test>::ShardNotFound
		);
	})
}

#[test]
fn purge_enclave_from_shard_status_fails_if_not_root() {
	new_test_ext().execute_with(|| {
		Timestamp::set_timestamp(NOW);
		let enclave_signer_1 = AccountKeyring::Eve.to_account_id();
		let enclave_fingerprint = EnclaveFingerprint::default();
		let shard = ShardIdentifier::default();
		assert_ok!(EnclaveBridge::touch_shard(
			shard,
			&enclave_signer_1.clone(),
			enclave_fingerprint,
			1
		));
		assert!(EnclaveBridge::purge_enclave_from_shard_status(
			RuntimeOrigin::signed(enclave_signer_1.clone()),
			shard,
			enclave_signer_1.clone(),
		)
		.is_err());
	})
}
