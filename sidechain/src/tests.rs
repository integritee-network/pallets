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

use crate::{mock::*, Error, Event as SidechainEvent, Teerex};
use frame_support::{assert_err, assert_ok, dispatch::DispatchResultWithPostInfo};
use sp_core::H256;
use test_utils::ias::consts::*;

// give get_signer a concrete type
fn get_signer(pubkey: &[u8; 32]) -> AccountId {
	test_utils::get_signer(pubkey)
}

#[test]
fn confirm_imported_sidechain_block_works_for_correct_shard() {
	new_test_ext().execute_with(|| {
		Timestamp::set_timestamp(TEST7_TIMESTAMP);
		let hash = H256::default();
		let signer7 = get_signer(TEST7_SIGNER_PUB);
		let shard7 = H256::from_slice(&TEST7_MRENCLAVE);

		register_enclave7();

		assert_ok!(Sidechain::confirm_imported_sidechain_block(
			Origin::signed(signer7.clone()),
			shard7,
			1,
			1,
			hash
		));

		let expected_event =
			Event::Sidechain(SidechainEvent::FinalizedSidechainBlock(signer7, hash));
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

		register_enclave7();

		assert_err!(
			Sidechain::confirm_imported_sidechain_block(
				Origin::signed(signer7),
				shard4,
				1,
				1,
				hash
			),
			pallet_teerex::Error::<Test>::WrongMrenclaveForShard
		);
	})
}

#[test]
fn confirm_imported_sidechain_block_correct_order() {
	new_test_ext().execute_with(|| {
		Timestamp::set_timestamp(TEST7_TIMESTAMP);
		let shard7 = H256::from_slice(&TEST7_MRENCLAVE);

		register_enclave7();

		assert_ok!(confirm_block7(1, H256::random(), true));
		assert_eq!(Sidechain::latest_sidechain_block_confirmation(shard7).block_number, 1);
		assert_ok!(confirm_block7(2, H256::random(), true));
		assert_eq!(Sidechain::latest_sidechain_block_confirmation(shard7).block_number, 2);
		assert_ok!(confirm_block7(3, H256::random(), true));
		assert_eq!(Sidechain::latest_sidechain_block_confirmation(shard7).block_number, 3);
		assert_ok!(confirm_block7(4, H256::random(), true));
		assert_eq!(Sidechain::latest_sidechain_block_confirmation(shard7).block_number, 4);
		assert_ok!(confirm_block7(5, H256::random(), true));
		assert_eq!(Sidechain::latest_sidechain_block_confirmation(shard7).block_number, 5);
	})
}

#[test]
fn confirm_imported_sidechain_first_imported_block() {
	new_test_ext().execute_with(|| {
		Timestamp::set_timestamp(TEST7_TIMESTAMP);
		let shard7 = H256::from_slice(&TEST7_MRENCLAVE);

		register_enclave7();

		let hash_block_3 = H256::random();

		assert_ok!(confirm_block7(1, H256::random(), true));
		assert_eq!(Sidechain::latest_sidechain_block_confirmation(shard7).block_number, 1);
		// Queue block number 3. Should not be imported right now, because confirmation of block number 2 is missing
		assert_ok!(confirm_block7(3, hash_block_3, false));
		assert_eq!(Sidechain::latest_sidechain_block_confirmation(shard7).block_number, 1);
		// Queue another block with number 3. Should not be imported at all, because it was not the first one
		assert_ok!(confirm_block7(3, H256::random(), false));
		assert_eq!(Sidechain::latest_sidechain_block_confirmation(shard7).block_number, 1);
		// Queue block number 2. Block number 3 should now be confirmed as well.
		assert_ok!(confirm_block7(2, H256::random(), true));
		assert_eq!(Sidechain::latest_sidechain_block_confirmation(shard7).block_number, 3);
		assert_eq!(
			Sidechain::latest_sidechain_block_confirmation(shard7).block_header_hash,
			hash_block_3
		);
	})
}

#[test]
fn confirm_imported_sidechain_block_wrong_order() {
	new_test_ext().execute_with(|| {
		Timestamp::set_timestamp(TEST7_TIMESTAMP);
		let shard7 = H256::from_slice(&TEST7_MRENCLAVE);

		register_enclave7();

		assert_ok!(confirm_block7(1, H256::random(), true));
		assert_eq!(Sidechain::latest_sidechain_block_confirmation(shard7).block_number, 1);
		assert_ok!(confirm_block7(4, H256::random(), false));
		assert_eq!(Sidechain::latest_sidechain_block_confirmation(shard7).block_number, 1);
		assert_ok!(confirm_block7(3, H256::random(), false));
		assert_eq!(Sidechain::latest_sidechain_block_confirmation(shard7).block_number, 1);
		assert_ok!(confirm_block7(2, H256::random(), true));
		assert_eq!(Sidechain::latest_sidechain_block_confirmation(shard7).block_number, 4);
		assert_ok!(confirm_block7(5, H256::random(), true));
		assert_eq!(Sidechain::latest_sidechain_block_confirmation(shard7).block_number, 5);
	})
}

#[test]
fn confirm_imported_sidechain_block_too_late() {
	new_test_ext().execute_with(|| {
		Timestamp::set_timestamp(TEST7_TIMESTAMP);
		let shard7 = H256::from_slice(&TEST7_MRENCLAVE);

		register_enclave7();

		assert_ok!(confirm_block7(1, H256::random(), true));
		assert_eq!(Sidechain::latest_sidechain_block_confirmation(shard7).block_number, 1);
		assert_ok!(confirm_block7(2, H256::random(), true));
		assert_eq!(Sidechain::latest_sidechain_block_confirmation(shard7).block_number, 2);
		assert_ok!(confirm_block7(3, H256::random(), true));
		assert_eq!(Sidechain::latest_sidechain_block_confirmation(shard7).block_number, 3);
		assert_ok!(confirm_block7(4, H256::random(), true));
		assert_eq!(Sidechain::latest_sidechain_block_confirmation(shard7).block_number, 4);
		assert_err!(confirm_block7(2, H256::random(), true), Error::<Test>::OutdatedBlockNumber);
		assert_eq!(Sidechain::latest_sidechain_block_confirmation(shard7).block_number, 4);
		assert_err!(confirm_block7(3, H256::random(), true), Error::<Test>::OutdatedBlockNumber);
		assert_eq!(Sidechain::latest_sidechain_block_confirmation(shard7).block_number, 4);
	})
}

#[test]
fn confirm_imported_sidechain_block_far_too_early() {
	new_test_ext().execute_with(|| {
		Timestamp::set_timestamp(TEST7_TIMESTAMP);
		let shard7 = H256::from_slice(&TEST7_MRENCLAVE);

		register_enclave7();

		assert_ok!(confirm_block7(1, H256::random(), true));
		assert_eq!(Sidechain::latest_sidechain_block_confirmation(shard7).block_number, 1);
		assert_ok!(confirm_block7(2, H256::random(), true));
		assert_eq!(Sidechain::latest_sidechain_block_confirmation(shard7).block_number, 2);
		assert_ok!(confirm_block7(2 + EARLY_BLOCK_PROPOSAL_LENIENCE, H256::random(), false));
		assert_eq!(Sidechain::latest_sidechain_block_confirmation(shard7).block_number, 2);
		assert_err!(
			confirm_block7(3 + EARLY_BLOCK_PROPOSAL_LENIENCE, H256::random(), false),
			Error::<Test>::BlockNumberTooHigh
		);
		assert_eq!(Sidechain::latest_sidechain_block_confirmation(shard7).block_number, 2);
	})
}

#[test]
fn dont_process_confirmation_of_second_registered_enclave() {
	new_test_ext().execute_with(|| {
		Timestamp::set_timestamp(TEST7_TIMESTAMP);
		let shard7 = H256::from_slice(&TEST7_MRENCLAVE);

		register_enclave(TEST7_SIGNER_PUB, TEST7_CERT, 1);
		register_enclave(TEST6_SIGNER_PUB, TEST6_CERT, 2);

		assert_ok!(confirm_block(shard7, TEST6_SIGNER_PUB, 1, H256::default(), false));
		assert_eq!(Sidechain::latest_sidechain_block_confirmation(shard7).block_number, 0);
	})
}

fn register_enclave7() {
	register_enclave(TEST7_SIGNER_PUB, TEST7_CERT, 1);
}

fn register_enclave(signer_pub_key: &[u8; 32], cert: &[u8], expected_enclave_count: u64) {
	let signer7 = get_signer(signer_pub_key);

	//Ensure that enclave is registered
	assert_ok!(Teerex::<Test>::register_enclave(
		Origin::signed(signer7),
		cert.to_vec(),
		URL.to_vec(),
	));
	assert_eq!(Teerex::<Test>::enclave_count(), expected_enclave_count);
}

fn confirm_block7(
	block_number: u64,
	block_header_hash: H256,
	check_for_event: bool,
) -> DispatchResultWithPostInfo {
	let shard7 = H256::from_slice(&TEST7_MRENCLAVE);
	confirm_block(shard7, TEST7_SIGNER_PUB, block_number, block_header_hash, check_for_event)
}

fn confirm_block(
	shard7: H256,
	signer_pub_key: &[u8; 32],
	block_number: u64,
	block_header_hash: H256,
	check_for_event: bool,
) -> DispatchResultWithPostInfo {
	let signer7 = get_signer(signer_pub_key);

	Sidechain::confirm_imported_sidechain_block(
		Origin::signed(signer7.clone()),
		shard7,
		block_number,
		1,
		block_header_hash,
	)?;

	if check_for_event {
		let expected_event =
			Event::Sidechain(SidechainEvent::FinalizedSidechainBlock(signer7, block_header_hash));
		assert!(System::events().iter().any(|a| a.event == expected_event));
	}
	Ok(().into())
}
