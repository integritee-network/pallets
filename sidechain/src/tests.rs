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
use enclave_bridge_primitives::{ShardConfig, ShardIdentifier};
use frame_support::{assert_err, assert_ok, dispatch::DispatchResultWithPostInfo};
use pallet_teerex::Pallet as Teerex;
use parity_scale_codec::Encode;
use sidechain_primitives::{SidechainBlockConfirmation, SidechainBlockNumber};
use sp_core::H256;
use sp_keyring::Sr25519Keyring as Keyring;
use teerex_primitives::{
	EnclaveFingerprint, MrSigner, MultiEnclave, SgxAttestationMethod, SgxEnclave,
};
use test_utils::{test_data::consts::*, TestEnclave};

// give get_signer a concrete type
fn get_signer(pubkey: &[u8; 32]) -> AccountId {
	test_utils::get_signer(pubkey)
}

#[test]
fn confirm_imported_sidechain_block_works_for_correct_shard() {
	new_test_ext().execute_with(|| {
		Timestamp::set_timestamp(TEST7_TIMESTAMP);
		let signer7 = get_signer(TEST7_SIGNER_PUB);
		let shard7 = H256::from_slice(&TEST7_MRENCLAVE);

		let block_a =
			SidechainBlockConfirmation { block_number: 2, block_header_hash: [2; 32].into() };

		let block_b =
			SidechainBlockConfirmation { block_number: 25, block_header_hash: [25; 32].into() };

		register_ias_enclave7();

		assert_ok!(Sidechain::confirm_imported_sidechain_block(
			RuntimeOrigin::signed(signer7.clone()),
			shard7,
			None,
			block_a
		));

		let expected_event = RuntimeEvent::Sidechain(SidechainEvent::FinalizedSidechainBlock {
			shard: shard7,
			block_number: block_a.block_number,
			block_header_hash: block_a.block_header_hash,
			validateer: signer7.clone(),
		});
		assert!(System::events().iter().any(|a| a.event == expected_event));

		assert_ok!(Sidechain::confirm_imported_sidechain_block(
			RuntimeOrigin::signed(signer7.clone()),
			shard7,
			Some(block_a),
			block_b
		));

		let expected_event = RuntimeEvent::Sidechain(SidechainEvent::FinalizedSidechainBlock {
			shard: shard7,
			block_number: block_b.block_number,
			block_header_hash: block_b.block_header_hash,
			validateer: signer7,
		});
		assert!(System::events().iter().any(|a| a.event == expected_event));
	})
}

#[test]
fn confirm_imported_sidechain_block_from_shard_neq_mrenclave_errs() {
	new_test_ext().execute_with(|| {
		Timestamp::set_timestamp(TEST7_TIMESTAMP);

		let signer7 = get_signer(TEST7_SIGNER_PUB);
		let shard4 = H256::from_slice(&TEST4_MRENCLAVE);

		register_ias_enclave7();

		let block_a =
			SidechainBlockConfirmation { block_number: 2, block_header_hash: [2; 32].into() };

		assert_err!(
			Sidechain::confirm_imported_sidechain_block(
				RuntimeOrigin::signed(signer7),
				shard4,
				None,
				block_a
			),
			pallet_enclave_bridge::Error::<Test>::WrongFingerprintForShard
		);
	})
}

#[test]
fn confirm_imported_sidechain_block_outdated_candidate_block_number_fails() {
	new_test_ext().execute_with(|| {
		Timestamp::set_timestamp(TEST7_TIMESTAMP);
		let shard7 = H256::from_slice(&TEST7_MRENCLAVE);

		register_ias_enclave7();

		assert_ok!(confirm_sidechain_block7(None, 100, true));
		assert_eq!(
			Sidechain::latest_sidechain_block_confirmation(shard7)
				.unwrap_or_default()
				.block_number,
			100
		);
		// resubmission must fail
		assert_err!(confirm_sidechain_block7(None, 100, true), Error::<Test>::AncestorMissing);

		assert_ok!(confirm_sidechain_block7(Some(100), 101, true));
		assert_eq!(
			Sidechain::latest_sidechain_block_confirmation(shard7)
				.unwrap_or_default()
				.block_number,
			101
		);
		// resubmission must fail with correct ancestor too
		assert_err!(
			confirm_sidechain_block7(Some(100), 101, true),
			Error::<Test>::FinalizationCandidateIsOutdated
		);
		// outdated blocks must fail
		assert_err!(
			confirm_sidechain_block7(Some(101), 101, true),
			Error::<Test>::FinalizationCandidateIsOutdated
		);
		assert_err!(
			confirm_sidechain_block7(Some(101), 100, true),
			Error::<Test>::FinalizationCandidateIsOutdated
		);
	})
}

#[test]
fn dont_process_confirmation_of_second_registered_enclave() {
	new_test_ext().execute_with(|| {
		Timestamp::set_timestamp(TEST7_TIMESTAMP);
		let shard7 = H256::from_slice(&TEST7_MRENCLAVE);

		register_ias_enclave(TEST7_SIGNER_PUB, TEST7_CERT);
		assert_ok!(confirm_sidechain_block(shard7, TEST7_SIGNER_PUB, None, 1, true));
		assert_eq!(
			Sidechain::latest_sidechain_block_confirmation(shard7)
				.unwrap_or_default()
				.block_number,
			1
		);
		register_ias_enclave(TEST6_SIGNER_PUB, TEST6_CERT);

		System::reset_events();
		assert_ok!(confirm_sidechain_block(shard7, TEST6_SIGNER_PUB, Some(1), 2, false));
		assert_eq!(
			Sidechain::latest_sidechain_block_confirmation(shard7)
				.unwrap_or_default()
				.block_number,
			1
		);
		let expected_event = RuntimeEvent::Sidechain(SidechainEvent::FinalizedSidechainBlock {
			shard: shard7,
			block_number: 1,
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

		let block_a =
			SidechainBlockConfirmation { block_number: 1, block_header_hash: H256::default() };

		assert_ok!(Sidechain::confirm_imported_sidechain_block(
			RuntimeOrigin::signed(enclave_signer.clone()),
			shard,
			None,
			block_a,
		));

		let expected_event = RuntimeEvent::Sidechain(SidechainEvent::FinalizedSidechainBlock {
			shard,
			block_number: block_a.block_number,
			block_header_hash: block_a.block_header_hash,
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

		let block_b =
			SidechainBlockConfirmation { block_number: 2, block_header_hash: H256::default() };

		// should still work with old enclave because update not yet enacted
		assert_ok!(Sidechain::confirm_imported_sidechain_block(
			RuntimeOrigin::signed(enclave_signer.clone()),
			shard,
			Some(block_a),
			block_b
		));

		let expected_event = RuntimeEvent::Sidechain(SidechainEvent::FinalizedSidechainBlock {
			shard,
			block_number: block_b.block_number,
			block_header_hash: block_b.block_header_hash,
			validateer: enclave_signer.clone(),
		});
		assert!(System::events().iter().any(|a| a.event == expected_event));

		// enclave upgrade of instance takes place
		register_sovereign_test_enclave(&enclave_signer, new_fingerprint);

		let block_c =
			SidechainBlockConfirmation { block_number: 3, block_header_hash: H256::default() };

		// before enactment, new enclave should not yet be allowed to finalize
		assert_err!(
			Sidechain::confirm_imported_sidechain_block(
				RuntimeOrigin::signed(enclave_signer.clone()),
				shard,
				Some(block_b),
				block_c
			),
			pallet_enclave_bridge::Error::<Test>::WrongFingerprintForShard
		);

		run_to_block(2);

		// now retry as new enclave with same signer
		assert_ok!(Sidechain::confirm_imported_sidechain_block(
			RuntimeOrigin::signed(enclave_signer.clone()),
			shard,
			Some(block_b),
			block_c
		));

		let expected_event = RuntimeEvent::Sidechain(SidechainEvent::FinalizedSidechainBlock {
			shard,
			block_number: block_c.block_number,
			block_header_hash: block_c.block_header_hash,
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
		let enclave_signer1 = Keyring::Eve.to_account_id();
		let enclave1 =
			register_sovereign_test_enclave(&enclave_signer1, EnclaveFingerprint::default());
		let shard1 = ShardIdentifier::from(enclave1.fingerprint());
		let shard1_block_a =
			SidechainBlockConfirmation { block_number: 1, block_header_hash: H256::default() };
		assert_ok!(Sidechain::confirm_imported_sidechain_block(
			RuntimeOrigin::signed(enclave_signer1.clone()),
			shard1,
			None,
			shard1_block_a
		));

		let expected_event = RuntimeEvent::Sidechain(SidechainEvent::FinalizedSidechainBlock {
			shard: shard1,
			block_number: shard1_block_a.block_number,
			block_header_hash: shard1_block_a.block_header_hash,
			validateer: enclave_signer1.clone(),
		});
		assert!(System::events().iter().any(|a| a.event == expected_event));

		run_to_block(2);
		Timestamp::set_timestamp(TEST7_TIMESTAMP);
		let enclave_signer2 = Keyring::Ferdie.to_account_id();
		let enclave2 =
			register_sovereign_test_enclave(&enclave_signer2, EnclaveFingerprint::from([1u8; 32]));
		let shard2 = ShardIdentifier::from(enclave2.fingerprint());
		let shard2_block_a = SidechainBlockConfirmation {
			block_number: 1,
			block_header_hash: H256::from([2u8; 32]),
		};

		assert_ok!(Sidechain::confirm_imported_sidechain_block(
			RuntimeOrigin::signed(enclave_signer2.clone()),
			shard2,
			None,
			shard2_block_a
		));

		let expected_event = RuntimeEvent::Sidechain(SidechainEvent::FinalizedSidechainBlock {
			shard: shard2,
			block_number: shard2_block_a.block_number,
			block_header_hash: shard2_block_a.block_header_hash,
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
			Some(SidechainBlockConfirmation {
				block_number: shard1_block_a.block_number,
				block_header_hash: shard1_block_a.block_header_hash
			})
		);
		assert_eq!(
			Sidechain::latest_sidechain_block_confirmation(shard2),
			Some(SidechainBlockConfirmation {
				block_number: shard2_block_a.block_number,
				block_header_hash: shard2_block_a.block_header_hash
			})
		);
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
		SgxAttestationMethod::Ias,
	));
	assert!(Teerex::<Test>::sovereign_enclaves(signer).is_some());
}

fn confirm_sidechain_block7(
	maybe_ancestor_block_number: Option<u8>,
	candidate_block_number: u8,
	assert_event: bool,
) -> DispatchResultWithPostInfo {
	let shard7 = H256::from_slice(&TEST7_MRENCLAVE);
	confirm_sidechain_block(
		shard7,
		TEST7_SIGNER_PUB,
		maybe_ancestor_block_number,
		candidate_block_number,
		assert_event,
	)
}

fn confirm_sidechain_block(
	shard: H256,
	signer_pub_key: &[u8; 32],
	maybe_ancestor_block_number: Option<u8>,
	candidate_block_number: u8,
	assert_event: bool,
) -> DispatchResultWithPostInfo {
	let signer = get_signer(signer_pub_key);
	if assert_event {
		System::reset_events();
	}
	let maybe_ancestor =
		maybe_ancestor_block_number.map(|block_number| SidechainBlockConfirmation {
			block_number: block_number as SidechainBlockNumber,
			block_header_hash: [block_number; 32].into(),
		});
	let candidate = SidechainBlockConfirmation {
		block_number: candidate_block_number as SidechainBlockNumber,
		block_header_hash: [candidate_block_number; 32].into(),
	};
	Sidechain::confirm_imported_sidechain_block(
		RuntimeOrigin::signed(signer.clone()),
		shard,
		maybe_ancestor,
		candidate,
	)?;

	if assert_event {
		let expected_event = RuntimeEvent::Sidechain(SidechainEvent::FinalizedSidechainBlock {
			shard,
			block_number: candidate.block_number,
			block_header_hash: candidate.block_header_hash,
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
