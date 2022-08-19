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

use crate::{mock::*, Error, Event as SidechainEvent, SidechainHeader, Teerex};
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
		let block_hash = H256::default();
		let signer7 = get_signer(TEST7_SIGNER_PUB);
		let shard7 = H256::from_slice(&TEST7_MRENCLAVE);

		register_enclave7();

		let header = SidechainHeader {
			parent_hash: block_hash,
			block_number: 1,
			shard_id: shard7,
			block_data_hash: block_hash,
		};

		assert_ok!(Sidechain::confirm_imported_sidechain_block(
			Origin::signed(signer7.clone()),
			shard7.clone(),
			1,
			header.hash()
		));

		let expected_event =
			Event::Sidechain(SidechainEvent::ImportedSidechainBlock(signer7, header.hash()));
		assert!(System::events().iter().any(|a| a.event == expected_event));
	})
}

#[test]
fn confirm_imported_sidechain_block_from_shard_neq_mrenclave_errs() {
	new_test_ext().execute_with(|| {
		Timestamp::set_timestamp(TEST7_TIMESTAMP);
		let block_hash = H256::default();
		let signer7 = get_signer(TEST7_SIGNER_PUB);
		let shard4 = H256::from_slice(&TEST4_MRENCLAVE);

		register_enclave7();

		let header = SidechainHeader {
			parent_hash: block_hash,
			block_number: 1,
			shard_id: shard4,
			block_data_hash: block_hash,
		};

		assert_err!(
			Sidechain::confirm_imported_sidechain_block(
				Origin::signed(signer7.clone()),
				shard4.clone(),
				1,
				header.hash()
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

		let header1 = new_header(1, H256::default());
		let header2 = new_header(2, header1.hash());
		let header3 = new_header(3, header2.hash());
		let header4 = new_header(4, header3.hash());
		let header5 = new_header(5, header4.hash());

		assert_ok!(confirm_block7(header1, true));
		assert_eq!(Sidechain::latest_sidechain_block_confirmation(shard7).block_number, 1);
		assert_ok!(confirm_block7(header2, true));
		assert_eq!(Sidechain::latest_sidechain_block_confirmation(shard7).block_number, 2);
		assert_ok!(confirm_block7(header3, true));
		assert_eq!(Sidechain::latest_sidechain_block_confirmation(shard7).block_number, 3);
		assert_ok!(confirm_block7(header4, true));
		assert_eq!(Sidechain::latest_sidechain_block_confirmation(shard7).block_number, 4);
		assert_ok!(confirm_block7(header5, true));
		assert_eq!(Sidechain::latest_sidechain_block_confirmation(shard7).block_number, 5);
	})
}

#[test]
fn confirm_imported_sidechain_first_imported_block() {
	new_test_ext().execute_with(|| {
		Timestamp::set_timestamp(TEST7_TIMESTAMP);
		let shard7 = H256::from_slice(&TEST7_MRENCLAVE);

		register_enclave7();

		let header1 = new_header(1, H256::default());
		let header2 = new_header(2, header1.hash());
		let mut header3a = new_header(3, header2.hash());
		header3a.block_data_hash = [2; 32].into();
		let mut header3b = new_header(3, header2.hash());
		header3b.block_data_hash = [3; 32].into();

		assert_ok!(confirm_block7(header1, true));
		assert_eq!(Sidechain::latest_sidechain_block_confirmation(shard7).block_number, 1);
		assert_ok!(confirm_block7(header3a, false));
		assert_eq!(Sidechain::latest_sidechain_block_confirmation(shard7).block_number, 1);
		assert_ok!(confirm_block7(header3b, false));
		assert_eq!(Sidechain::latest_sidechain_block_confirmation(shard7).block_number, 1);
		assert_ok!(confirm_block7(header2, true));
		assert_eq!(Sidechain::latest_sidechain_block_confirmation(shard7).block_number, 3);
		assert_eq!(
			Sidechain::latest_sidechain_block_confirmation(shard7).block_header_hash,
			header3a.hash()
		);
	})
}

#[test]
fn confirm_imported_sidechain_block_wrong_order() {
	new_test_ext().execute_with(|| {
		Timestamp::set_timestamp(TEST7_TIMESTAMP);
		let shard7 = H256::from_slice(&TEST7_MRENCLAVE);

		register_enclave7();

		let header1 = new_header(1, H256::default());
		let header2 = new_header(2, header1.hash());
		let header3 = new_header(3, header2.hash());
		let header4 = new_header(4, header3.hash());
		let header5 = new_header(5, header4.hash());

		assert_ok!(confirm_block7(header1, true));
		assert_eq!(Sidechain::latest_sidechain_block_confirmation(shard7).block_number, 1);
		assert_ok!(confirm_block7(header4, false));
		assert_eq!(Sidechain::latest_sidechain_block_confirmation(shard7).block_number, 1);
		assert_ok!(confirm_block7(header3, false));
		assert_eq!(Sidechain::latest_sidechain_block_confirmation(shard7).block_number, 1);
		assert_ok!(confirm_block7(header2, true));
		assert_eq!(Sidechain::latest_sidechain_block_confirmation(shard7).block_number, 4);
		assert_ok!(confirm_block7(header5, true));
		assert_eq!(Sidechain::latest_sidechain_block_confirmation(shard7).block_number, 5);
	})
}

#[test]
fn confirm_imported_sidechain_block_too_late() {
	new_test_ext().execute_with(|| {
		Timestamp::set_timestamp(TEST7_TIMESTAMP);
		let shard7 = H256::from_slice(&TEST7_MRENCLAVE);

		register_enclave7();

		let header1 = new_header(1, H256::default());
		let header2 = new_header(2, header1.hash());
		let header3 = new_header(3, header2.hash());
		let header4 = new_header(4, header3.hash());
		let header2b = new_header(2, header4.hash());
		let header3b = new_header(3, header2.hash());

		assert_ok!(confirm_block7(header1, true));
		assert_eq!(Sidechain::latest_sidechain_block_confirmation(shard7).block_number, 1);
		assert_ok!(confirm_block7(header2, true));
		assert_eq!(Sidechain::latest_sidechain_block_confirmation(shard7).block_number, 2);
		assert_ok!(confirm_block7(header3, true));
		assert_eq!(Sidechain::latest_sidechain_block_confirmation(shard7).block_number, 3);
		assert_ok!(confirm_block7(header4, true));
		assert_eq!(Sidechain::latest_sidechain_block_confirmation(shard7).block_number, 4);
		assert_err!(confirm_block7(header2b, true), Error::<Test>::OutdatedBlockNumber);
		assert_eq!(Sidechain::latest_sidechain_block_confirmation(shard7).block_number, 4);
		assert_err!(confirm_block7(header3b, true), Error::<Test>::OutdatedBlockNumber);
		assert_eq!(Sidechain::latest_sidechain_block_confirmation(shard7).block_number, 4);
	})
}

#[test]
fn confirm_imported_sidechain_block_far_too_early() {
	new_test_ext().execute_with(|| {
		Timestamp::set_timestamp(TEST7_TIMESTAMP);
		let shard7 = H256::from_slice(&TEST7_MRENCLAVE);

		register_enclave7();

		let header1 = new_header(1, H256::default());
		let header2 = new_header(2, header1.hash());
		let header3 = new_header(2 + EARLY_BLOCK_PROPOSAL_LENIENCE, header2.hash());
		let header4 = new_header(3 + EARLY_BLOCK_PROPOSAL_LENIENCE, header3.hash());

		assert_ok!(confirm_block7(header1, true));
		assert_eq!(Sidechain::latest_sidechain_block_confirmation(shard7).block_number, 1);
		assert_ok!(confirm_block7(header2, true));
		assert_eq!(Sidechain::latest_sidechain_block_confirmation(shard7).block_number, 2);
		assert_ok!(confirm_block7(header3, false));
		assert_eq!(Sidechain::latest_sidechain_block_confirmation(shard7).block_number, 2);
		assert_err!(confirm_block7(header4, false), Error::<Test>::BlockNumberTooHigh);
		assert_eq!(Sidechain::latest_sidechain_block_confirmation(shard7).block_number, 2);
	})
}

#[test]
fn dont_process_confirmation_of_second_registered_enclave() {
	new_test_ext().execute_with(|| {
		Timestamp::set_timestamp(TEST7_TIMESTAMP);
		let block_hash = H256::default();
		let signer7 = get_signer(TEST7_SIGNER_PUB);
		let shard7 = H256::from_slice(&TEST7_MRENCLAVE);

		register_enclave(TEST7_SIGNER_PUB, TEST7_CERT, 1);
		register_enclave(TEST6_SIGNER_PUB, TEST6_CERT, 2);

		let header1 = new_header(1, H256::default());

		assert_ok!(confirm_block(shard7, TEST6_SIGNER_PUB, header1, false));
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
		Origin::signed(signer7.clone()),
		cert.to_vec(),
		URL.to_vec(),
	));
	assert_eq!(Teerex::<Test>::enclave_count(), expected_enclave_count);
}

fn confirm_block7(header: SidechainHeader, check_for_event: bool) -> DispatchResultWithPostInfo {
	let shard7 = H256::from_slice(&TEST7_MRENCLAVE);
	confirm_block(shard7, TEST7_SIGNER_PUB, header, check_for_event)
}

fn confirm_block(
	shard7: H256,
	signer_pub_key: &[u8; 32],
	header: SidechainHeader,
	check_for_event: bool,
) -> DispatchResultWithPostInfo {
	let signer7 = get_signer(signer_pub_key);

	let header_clone = header.clone();
	Sidechain::confirm_imported_sidechain_block(
		Origin::signed(signer7.clone()),
		shard7.clone(),
		header_clone.block_number,
		header_clone.hash(),
	)?;

	if check_for_event {
		let expected_event =
			Event::Sidechain(SidechainEvent::ImportedSidechainBlock(signer7, header.hash()));
		assert!(System::events().iter().any(|a| a.event == expected_event));
	}
	Ok(().into())
}

fn new_header(block_number: u64, parent_hash: H256) -> SidechainHeader {
	let block_hash = [(block_number % 8) as u8; 32].into();
	let shard7 = H256::from_slice(&TEST7_MRENCLAVE);

	let header = SidechainHeader {
		parent_hash,
		block_number,
		shard_id: shard7,
		block_data_hash: block_hash,
	};

	header
}
