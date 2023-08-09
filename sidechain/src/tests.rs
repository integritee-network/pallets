/*
	Copyright 2021 Integritee AG and Supercomputing Systems AG

	Licensed under the MICROSOFT REFERENCE SOURCE LICENSE (MS-RSL) (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

		https://referencesource.microsoft.com/license.html

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.

*/

use crate::{mock::*, Error, Event as SidechainEvent};
use codec::Encode;
use enclave_bridge_primitives::{ShardConfig, ShardIdentifier};
use frame_support::{assert_err, assert_ok, dispatch::DispatchResultWithPostInfo};
use pallet_teerex::Pallet as Teerex;
use sidechain_primitives::SidechainBlockConfirmation;
use sp_core::H256;
use sp_keyring::AccountKeyring;
use teerex_primitives::{
	EnclaveFingerprint, MrSigner, MultiEnclave, SgxAttestationMethod, SgxEnclave,
};
use test_utils::{test_data::consts::*, TestEnclave};

// give get_signer a concrete type
fn get_signer(pubkey: &[u8; 32]) -> AccountId {
	test_utils::get_signer(pubkey)
}

#[test]
fn confirm_imported_sidechain_block_invalid_next_finalization_candidate() {
	new_test_ext().execute_with(|| {
		Timestamp::set_timestamp(TEST7_TIMESTAMP);
		let hash = H256::default();
		let signer7 = get_signer(TEST7_SIGNER_PUB);
		let shard7 = H256::from_slice(&TEST7_MRENCLAVE);

		let block_number = 1;

		register_ias_enclave7();

		assert_err!(
			Sidechain::confirm_imported_sidechain_block(
				RuntimeOrigin::signed(signer7.clone()),
				shard7,
				block_number,
				block_number,
				hash
			),
			Error::<Test>::InvalidNextFinalizationCandidateBlockNumber,
		);
	})
}

#[test]
fn confirm_imported_sidechain_block_works_for_correct_shard() {
	new_test_ext().execute_with(|| {
		Timestamp::set_timestamp(TEST7_TIMESTAMP);
		let hash = H256::default();
		let signer7 = get_signer(TEST7_SIGNER_PUB);
		let shard7 = H256::from_slice(&TEST7_MRENCLAVE);

		let block_number = 1;
		let next_finalization_block_candidate = 20;

		register_ias_enclave7();

		assert_ok!(Sidechain::confirm_imported_sidechain_block(
			RuntimeOrigin::signed(signer7.clone()),
			shard7,
			block_number,
			next_finalization_block_candidate,
			hash
		));

		let expected_event = RuntimeEvent::Sidechain(SidechainEvent::FinalizedSidechainBlock {
			shard: shard7,
			block_header_hash: hash,
			validateer: signer7,
		});
		assert!(System::events().iter().any(|a| a.event == expected_event));
	})
}

#[test]
fn confirm_imported_sidechain_block_from_shard_neq_mrenclave_errs() {
	new_test_ext().execute_with(|| {
		Timestamp::set_timestamp(TEST7_TIMESTAMP);
		let hash = H256::default();
		let signer7 = get_signer(TEST7_SIGNER_PUB);
		let shard4 = H256::from_slice(&TEST4_MRENCLAVE);

		register_ias_enclave7();

		let block_number = 1;

		assert_err!(
			Sidechain::confirm_imported_sidechain_block(
				RuntimeOrigin::signed(signer7),
				shard4,
				block_number,
				block_number,
				hash
			),
			pallet_enclave_bridge::Error::<Test>::WrongFingerprintForShard
		);
	})
}

#[test]
fn confirm_imported_sidechain_block_correct_order() {
	new_test_ext().execute_with(|| {
		Timestamp::set_timestamp(TEST7_TIMESTAMP);
		let shard7 = H256::from_slice(&TEST7_MRENCLAVE);

		register_ias_enclave7();

		assert_ok!(confirm_sidechain_block7(1, 2, H256::random(), true));
		assert_eq!(Sidechain::latest_sidechain_block_confirmation(shard7).block_number, 1);
		assert_eq!(Sidechain::sidechain_block_finalization_candidate(shard7), 2);
		assert_ok!(confirm_sidechain_block7(2, 3, H256::random(), true));
		assert_eq!(Sidechain::latest_sidechain_block_confirmation(shard7).block_number, 2);
		assert_eq!(Sidechain::sidechain_block_finalization_candidate(shard7), 3);
		assert_ok!(confirm_sidechain_block7(3, 4, H256::random(), true));
		assert_eq!(Sidechain::latest_sidechain_block_confirmation(shard7).block_number, 3);
		assert_eq!(Sidechain::sidechain_block_finalization_candidate(shard7), 4);
		assert_ok!(confirm_sidechain_block7(4, 5, H256::random(), true));
		assert_eq!(Sidechain::latest_sidechain_block_confirmation(shard7).block_number, 4);
		assert_eq!(Sidechain::sidechain_block_finalization_candidate(shard7), 5);
		assert_ok!(confirm_sidechain_block7(5, 6, H256::random(), true));
		assert_eq!(Sidechain::latest_sidechain_block_confirmation(shard7).block_number, 5);
		assert_eq!(Sidechain::sidechain_block_finalization_candidate(shard7), 6);
	})
}

#[test]
fn confirm_imported_sidechain_block_wrong_next() {
	new_test_ext().execute_with(|| {
		Timestamp::set_timestamp(TEST7_TIMESTAMP);
		let shard7 = H256::from_slice(&TEST7_MRENCLAVE);

		register_ias_enclave7();

		assert_ok!(confirm_sidechain_block7(1, 2, H256::random(), true));
		assert_eq!(Sidechain::latest_sidechain_block_confirmation(shard7).block_number, 1);
		assert_eq!(Sidechain::sidechain_block_finalization_candidate(shard7), 2);
		assert_ok!(confirm_sidechain_block7(2, 4, H256::random(), true));
		assert_eq!(Sidechain::latest_sidechain_block_confirmation(shard7).block_number, 2);
		assert_eq!(Sidechain::sidechain_block_finalization_candidate(shard7), 4);
		assert_err!(
			confirm_sidechain_block7(3, 4, H256::random(), true),
			Error::<Test>::ReceivedUnexpectedSidechainBlock
		);
		assert_eq!(Sidechain::latest_sidechain_block_confirmation(shard7).block_number, 2);
		assert_eq!(Sidechain::sidechain_block_finalization_candidate(shard7), 4);
		assert_ok!(confirm_sidechain_block7(4, 5, H256::random(), true));
		assert_eq!(Sidechain::latest_sidechain_block_confirmation(shard7).block_number, 4);
		assert_eq!(Sidechain::sidechain_block_finalization_candidate(shard7), 5);
	})
}

#[test]
fn confirm_imported_sidechain_block_outdated() {
	new_test_ext().execute_with(|| {
		Timestamp::set_timestamp(TEST7_TIMESTAMP);
		let shard7 = H256::from_slice(&TEST7_MRENCLAVE);

		register_ias_enclave7();

		assert_ok!(confirm_sidechain_block7(1, 2, H256::random(), true));
		assert_eq!(Sidechain::latest_sidechain_block_confirmation(shard7).block_number, 1);
		assert_eq!(Sidechain::sidechain_block_finalization_candidate(shard7), 2);
		assert_ok!(confirm_sidechain_block7(2, 4, H256::random(), true));
		assert_eq!(Sidechain::latest_sidechain_block_confirmation(shard7).block_number, 2);
		assert_eq!(Sidechain::sidechain_block_finalization_candidate(shard7), 4);
		assert_err!(
			confirm_sidechain_block7(2, 4, H256::random(), true),
			Error::<Test>::ReceivedUnexpectedSidechainBlock
		);
		assert_eq!(Sidechain::latest_sidechain_block_confirmation(shard7).block_number, 2);
		assert_eq!(Sidechain::sidechain_block_finalization_candidate(shard7), 4);
		assert_ok!(confirm_sidechain_block7(4, 5, H256::random(), true));
		assert_eq!(Sidechain::latest_sidechain_block_confirmation(shard7).block_number, 4);
		assert_eq!(Sidechain::sidechain_block_finalization_candidate(shard7), 5);
	})
}

#[test]
fn dont_process_confirmation_of_second_registered_enclave() {
	new_test_ext().execute_with(|| {
		Timestamp::set_timestamp(TEST7_TIMESTAMP);
		let shard7 = H256::from_slice(&TEST7_MRENCLAVE);

		register_ias_enclave(TEST7_SIGNER_PUB, TEST7_CERT);
		assert_ok!(confirm_sidechain_block(shard7, TEST7_SIGNER_PUB, 1, 2, H256::default(), true));
		assert_eq!(Sidechain::latest_sidechain_block_confirmation(shard7).block_number, 1);
		register_ias_enclave(TEST6_SIGNER_PUB, TEST6_CERT);

		System::reset_events();
		assert_ok!(confirm_sidechain_block(shard7, TEST6_SIGNER_PUB, 1, 2, H256::default(), false));
		let expected_event = RuntimeEvent::Sidechain(SidechainEvent::FinalizedSidechainBlock {
			shard: shard7,
			block_header_hash: H256::default(),
			validateer: get_signer(TEST6_SIGNER_PUB),
		});
		assert!(!System::events().iter().any(|a| a.event == expected_event));
	})
}

#[test]
fn confirm_imported_sidechain_block_works_for_correct_shard_with_updated_fingerprint() {
	new_test_ext().execute_with(|| {
		Timestamp::set_timestamp(TEST7_TIMESTAMP);
		run_to_block(1);
		let enclave_signer = AccountKeyring::Eve.to_account_id();
		let enclave =
			register_sovereign_test_enclave(&enclave_signer, EnclaveFingerprint::default());
		let shard = ShardIdentifier::from(enclave.fingerprint());
		let hash = H256::default();
		// initialize shard
		assert_ok!(EnclaveBridge::update_shard_config(
			RuntimeOrigin::signed(enclave_signer.clone()),
			shard,
			ShardConfig::new(enclave.fingerprint()),
			0,
		));

		assert_ok!(Sidechain::confirm_imported_sidechain_block(
			RuntimeOrigin::signed(enclave_signer.clone()),
			shard,
			1,
			2,
			hash
		));

		let expected_event = RuntimeEvent::Sidechain(SidechainEvent::FinalizedSidechainBlock {
			shard,
			block_header_hash: hash,
			validateer: enclave_signer.clone(),
		});
		assert!(System::events().iter().any(|a| a.event == expected_event));

		let new_fingerprint = EnclaveFingerprint::from([2u8; 32]);

		assert_ok!(EnclaveBridge::update_shard_config(
			RuntimeOrigin::signed(enclave_signer.clone()),
			shard,
			ShardConfig::new(new_fingerprint),
			1,
		));

		// should still work with old enclave because update not yet enacted
		assert_ok!(Sidechain::confirm_imported_sidechain_block(
			RuntimeOrigin::signed(enclave_signer.clone()),
			shard,
			2,
			3,
			hash
		));

		let expected_event = RuntimeEvent::Sidechain(SidechainEvent::FinalizedSidechainBlock {
			shard,
			block_header_hash: hash,
			validateer: enclave_signer.clone(),
		});
		assert!(System::events().iter().any(|a| a.event == expected_event));

		run_to_block(2);

		// enclave upgrade of instance takes place
		register_sovereign_test_enclave(&enclave_signer, new_fingerprint);

		// now retry as new enclave with same signer
		assert_ok!(Sidechain::confirm_imported_sidechain_block(
			RuntimeOrigin::signed(enclave_signer.clone()),
			shard,
			3,
			4,
			hash
		));

		let expected_event = RuntimeEvent::Sidechain(SidechainEvent::FinalizedSidechainBlock {
			shard,
			block_header_hash: hash,
			validateer: enclave_signer,
		});
		assert!(System::events().iter().any(|a| a.event == expected_event));
	})
}

#[test]
fn two_sidechains_with_different_fingerprint_works() {
	new_test_ext().execute_with(|| {
		Timestamp::set_timestamp(TEST7_TIMESTAMP);
		run_to_block(1);
		let enclave_signer1 = AccountKeyring::Eve.to_account_id();
		let enclave1 =
			register_sovereign_test_enclave(&enclave_signer1, EnclaveFingerprint::default());
		let shard1 = ShardIdentifier::from(enclave1.fingerprint());
		let hash1 = H256::default();
		assert_ok!(Sidechain::confirm_imported_sidechain_block(
			RuntimeOrigin::signed(enclave_signer1.clone()),
			shard1,
			1,
			2,
			hash1
		));

		let expected_event = RuntimeEvent::Sidechain(SidechainEvent::FinalizedSidechainBlock {
			shard: shard1,
			block_header_hash: hash1,
			validateer: enclave_signer1.clone(),
		});
		assert!(System::events().iter().any(|a| a.event == expected_event));

		run_to_block(2);
		Timestamp::set_timestamp(TEST7_TIMESTAMP);
		let enclave_signer2 = AccountKeyring::Ferdie.to_account_id();
		let enclave2 =
			register_sovereign_test_enclave(&enclave_signer2, EnclaveFingerprint::from([1u8; 32]));
		let shard2 = ShardIdentifier::from(enclave2.fingerprint());
		let hash2 = H256::from([2u8; 32]);

		assert_ok!(Sidechain::confirm_imported_sidechain_block(
			RuntimeOrigin::signed(enclave_signer2.clone()),
			shard2,
			1,
			10,
			hash2
		));

		let expected_event = RuntimeEvent::Sidechain(SidechainEvent::FinalizedSidechainBlock {
			shard: shard2,
			block_header_hash: hash2,
			validateer: enclave_signer2.clone(),
		});
		assert!(System::events().iter().any(|a| a.event == expected_event));

		let shard_status1 = EnclaveBridge::shard_status(shard1).unwrap();
		let shard_status2 = EnclaveBridge::shard_status(shard2).unwrap();
		assert_eq!(shard_status1.len(), 1);
		assert_eq!(shard_status2.len(), 1);
		assert_eq!(shard_status1[0].signer, enclave_signer1);
		assert_eq!(shard_status2[0].signer, enclave_signer2);
		assert_eq!(shard_status1[0].fingerprint, enclave1.fingerprint());
		assert_eq!(shard_status2[0].fingerprint, enclave2.fingerprint());
		assert_eq!(shard_status1[0].fingerprint, enclave1.fingerprint());
		assert_eq!(shard_status2[0].fingerprint, enclave2.fingerprint());
		assert_eq!(shard_status1[0].last_activity, 1u32);
		assert_eq!(shard_status2[0].last_activity, 2u32);
		assert_eq!(
			Sidechain::latest_sidechain_block_confirmation(shard1),
			SidechainBlockConfirmation { block_number: 1, block_header_hash: hash1 }
		);
		assert_eq!(
			Sidechain::latest_sidechain_block_confirmation(shard2),
			SidechainBlockConfirmation { block_number: 1, block_header_hash: hash2 }
		);
		assert_eq!(Sidechain::sidechain_block_finalization_candidate(shard1), 2);
		assert_eq!(Sidechain::sidechain_block_finalization_candidate(shard2), 10);
	})
}

fn register_ias_enclave7() {
	register_ias_enclave(TEST7_SIGNER_PUB, TEST7_CERT);
}

fn register_ias_enclave(signer_pub_key: &MrSigner, cert: &[u8]) {
	let signer = get_signer(signer_pub_key);

	//Ensure that enclave is registered
	assert_ok!(Teerex::<Test>::register_sgx_enclave(
		RuntimeOrigin::signed(signer.clone()),
		cert.to_vec(),
		Some(URL.to_vec()),
		SgxAttestationMethod::Ias { proxied: false },
	));
	assert!(Teerex::<Test>::sovereign_enclaves(signer).is_some());
}

fn confirm_sidechain_block7(
	block_number: u64,
	next_finalized_block_number: u64,
	block_header_hash: H256,
	assert_event: bool,
) -> DispatchResultWithPostInfo {
	let shard7 = H256::from_slice(&TEST7_MRENCLAVE);
	confirm_sidechain_block(
		shard7,
		TEST7_SIGNER_PUB,
		block_number,
		next_finalized_block_number,
		block_header_hash,
		assert_event,
	)
}

fn confirm_sidechain_block(
	shard: H256,
	signer_pub_key: &[u8; 32],
	block_number: u64,
	next_finalized_block_number: u64,
	block_header_hash: H256,
	assert_event: bool,
) -> DispatchResultWithPostInfo {
	let signer = get_signer(signer_pub_key);
	if assert_event {
		System::reset_events();
	}
	Sidechain::confirm_imported_sidechain_block(
		RuntimeOrigin::signed(signer.clone()),
		shard,
		block_number,
		next_finalized_block_number,
		block_header_hash,
	)?;

	if assert_event {
		let expected_event = RuntimeEvent::Sidechain(SidechainEvent::FinalizedSidechainBlock {
			shard,
			block_header_hash,
			validateer: signer,
		});
		assert!(System::events().iter().any(|a| a.event == expected_event));
	}
	Ok(().into())
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
	assert_ok!(Teerex::<Test>::add_enclave(signer, enclave.clone()));
	enclave
}

/// Run until a particular block.
pub fn run_to_block(n: u32) {
	use frame_support::traits::{OnFinalize, OnInitialize};
	while System::block_number() < n {
		if System::block_number() > 1 {
			System::on_finalize(System::block_number());
		}
		Timestamp::on_finalize(System::block_number());
		System::set_block_number(System::block_number() + 1);
		System::on_initialize(System::block_number());
	}
}

fn now() -> u64 {
	<pallet_timestamp::Pallet<Test>>::get()
}
