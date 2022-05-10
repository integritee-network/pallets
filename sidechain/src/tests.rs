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
fn confirm_proposed_sidechain_block_works_for_correct_shard() {
	new_test_ext().execute_with(|| {
		Timestamp::set_timestamp(TEST7_TIMESTAMP);
		let block_hash = H256::default();
		let signer7 = get_signer(TEST7_SIGNER_PUB);
		let shard7 = H256::from_slice(&TEST7_MRENCLAVE);

		register_enclave();

		let header = SidechainHeader {
			parent_hash: block_hash,
			block_number: 1,
			shard_id: shard7,
			block_data_hash: block_hash,
		};

		assert_ok!(Sidechain::confirm_proposed_sidechain_block(
			Origin::signed(signer7.clone()),
			shard7.clone(),
			header.clone(),
		));

		let expected_event =
			Event::Sidechain(SidechainEvent::ProposedSidechainBlock(signer7, block_hash));
		assert!(System::events().iter().any(|a| a.event == expected_event));
	})
}

#[test]
fn confirm_proposed_sidechain_block_from_shard_neq_mrenclave_errs() {
	new_test_ext().execute_with(|| {
		Timestamp::set_timestamp(TEST7_TIMESTAMP);
		let block_hash = H256::default();
		let signer7 = get_signer(TEST7_SIGNER_PUB);
		let shard4 = H256::from_slice(&TEST4_MRENCLAVE);

		register_enclave();

		let header = SidechainHeader {
			parent_hash: block_hash,
			block_number: 1,
			shard_id: shard4,
			block_data_hash: block_hash,
		};

		assert_err!(
			Sidechain::confirm_proposed_sidechain_block(
				Origin::signed(signer7.clone()),
				shard4.clone(),
				header,
			),
			pallet_teerex::Error::<Test>::WrongMrenclaveForShard
		);
	})
}

#[test]
fn confirm_proposed_sidechain_block_correct_order() {
	new_test_ext().execute_with(|| {
		Timestamp::set_timestamp(TEST7_TIMESTAMP);
		let shard7 = H256::from_slice(&TEST7_MRENCLAVE);

		register_enclave();

		let header1 = new_header(1, H256::default());
		let header2 = new_header(2, header1.hash());
		let header3 = new_header(3, header2.hash());
		let header4 = new_header(4, header3.hash());
		let header5 = new_header(5, header4.hash());

		assert_ok!(confirm_block(header1, true));
		assert_eq!(Sidechain::latest_sidechain_header(shard7).block_number, 1);
		assert_ok!(confirm_block(header2, true));
		assert_eq!(Sidechain::latest_sidechain_header(shard7).block_number, 2);
		assert_ok!(confirm_block(header3, true));
		assert_eq!(Sidechain::latest_sidechain_header(shard7).block_number, 3);
		assert_ok!(confirm_block(header4, true));
		assert_eq!(Sidechain::latest_sidechain_header(shard7).block_number, 4);
		assert_ok!(confirm_block(header5, true));
		assert_eq!(Sidechain::latest_sidechain_header(shard7).block_number, 5);
	})
}

#[test]
fn confirm_proposed_sidechain_first_proposed_block() {
	new_test_ext().execute_with(|| {
		Timestamp::set_timestamp(TEST7_TIMESTAMP);
		let shard7 = H256::from_slice(&TEST7_MRENCLAVE);

		register_enclave();

		let header1 = new_header(1, H256::default());
		let header2 = new_header(2, header1.hash());
		let mut header3a = new_header(3, header2.hash());
		header3a.block_data_hash = [2; 32].into();
		let mut header3b = new_header(3, header2.hash());
		header3b.block_data_hash = [3; 32].into();

		assert_ok!(confirm_block(header1, true));
		assert_eq!(Sidechain::latest_sidechain_header(shard7).block_number, 1);
		assert_ok!(confirm_block(header3a, false));
		assert_eq!(Sidechain::latest_sidechain_header(shard7).block_number, 1);
		assert_ok!(confirm_block(header3b, false));
		assert_eq!(Sidechain::latest_sidechain_header(shard7).block_number, 1);
		assert_ok!(confirm_block(header2, true));
		assert_eq!(Sidechain::latest_sidechain_header(shard7).block_number, 3);
		assert_eq!(
			Sidechain::latest_sidechain_header(shard7).block_data_hash,
			header3a.block_data_hash
		);
	})
}

#[test]
fn confirm_proposed_sidechain_block_wrong_order() {
	new_test_ext().execute_with(|| {
		Timestamp::set_timestamp(TEST7_TIMESTAMP);
		let shard7 = H256::from_slice(&TEST7_MRENCLAVE);

		register_enclave();

		let header1 = new_header(1, H256::default());
		let header2 = new_header(2, header1.hash());
		let header3 = new_header(3, header2.hash());
		let header4 = new_header(4, header3.hash());
		let header5 = new_header(5, header4.hash());

		assert_ok!(confirm_block(header1, true));
		assert_eq!(Sidechain::latest_sidechain_header(shard7).block_number, 1);
		assert_ok!(confirm_block(header4, false));
		assert_eq!(Sidechain::latest_sidechain_header(shard7).block_number, 1);
		assert_ok!(confirm_block(header3, false));
		assert_eq!(Sidechain::latest_sidechain_header(shard7).block_number, 1);
		assert_ok!(confirm_block(header2, true));
		assert_eq!(Sidechain::latest_sidechain_header(shard7).block_number, 4);
		assert_ok!(confirm_block(header5, true));
		assert_eq!(Sidechain::latest_sidechain_header(shard7).block_number, 5);
	})
}

#[test]
fn confirm_proposed_sidechain_block_too_late() {
	new_test_ext().execute_with(|| {
		Timestamp::set_timestamp(TEST7_TIMESTAMP);
		let shard7 = H256::from_slice(&TEST7_MRENCLAVE);

		register_enclave();

		let header1 = new_header(1, H256::default());
		let header2 = new_header(2, header1.hash());
		let header3 = new_header(3, header2.hash());
		let header4 = new_header(4, header3.hash());
		let header2b = new_header(2, header4.hash());
		let header3b = new_header(3, header2.hash());

		assert_ok!(confirm_block(header1, true));
		assert_eq!(Sidechain::latest_sidechain_header(shard7).block_number, 1);
		assert_ok!(confirm_block(header2, true));
		assert_eq!(Sidechain::latest_sidechain_header(shard7).block_number, 2);
		assert_ok!(confirm_block(header3, true));
		assert_eq!(Sidechain::latest_sidechain_header(shard7).block_number, 3);
		assert_ok!(confirm_block(header4, true));
		assert_eq!(Sidechain::latest_sidechain_header(shard7).block_number, 4);
		assert_err!(confirm_block(header2b, true), Error::<Test>::OutdatedBlockNumber);
		assert_eq!(Sidechain::latest_sidechain_header(shard7).block_number, 4);
		assert_err!(confirm_block(header3b, true), Error::<Test>::OutdatedBlockNumber);
		assert_eq!(Sidechain::latest_sidechain_header(shard7).block_number, 4);
	})
}

#[test]
fn confirm_proposed_sidechain_block_far_too_early() {
	new_test_ext().execute_with(|| {
		Timestamp::set_timestamp(TEST7_TIMESTAMP);
		let shard7 = H256::from_slice(&TEST7_MRENCLAVE);

		register_enclave();

		let header1 = new_header(1, H256::default());
		let header2 = new_header(2, header1.hash());
		let header3 = new_header(2 + EARLY_BLOCK_PROPOSAL_LENIENCE, header2.hash());
		let header4 = new_header(3 + EARLY_BLOCK_PROPOSAL_LENIENCE, header3.hash());

		assert_ok!(confirm_block(header1, true));
		assert_eq!(Sidechain::latest_sidechain_header(shard7).block_number, 1);
		assert_ok!(confirm_block(header2, true));
		assert_eq!(Sidechain::latest_sidechain_header(shard7).block_number, 2);
		assert_ok!(confirm_block(header3, false));
		assert_eq!(Sidechain::latest_sidechain_header(shard7).block_number, 2);
		assert_err!(confirm_block(header4, false), Error::<Test>::BlockNumberTooHigh);
		assert_eq!(Sidechain::latest_sidechain_header(shard7).block_number, 2);
	})
}
#[test]
fn confirm_proposed_sidechain_block_wrong_parent_hash() {
	new_test_ext().execute_with(|| {
		Timestamp::set_timestamp(TEST7_TIMESTAMP);
		let shard7 = H256::from_slice(&TEST7_MRENCLAVE);

		register_enclave();

		let header1 = new_header(1, H256::default());
		let header2 = new_header(2, H256::default());

		assert_ok!(confirm_block(header1, true));
		assert_eq!(Sidechain::latest_sidechain_header(shard7).block_number, 1);
		assert_ok!(confirm_block(header2, false));
		assert_eq!(Sidechain::latest_sidechain_header(shard7).block_number, 1);
	})
}

fn register_enclave() {
	let signer7 = get_signer(TEST7_SIGNER_PUB);

	//Ensure that enclave is registered
	assert_ok!(Teerex::<Test>::register_enclave(
		Origin::signed(signer7.clone()),
		TEST7_CERT.to_vec(),
		URL.to_vec(),
	));
	assert_eq!(Teerex::<Test>::enclave_count(), 1);
}

fn confirm_block(header: SidechainHeader, check_for_event: bool) -> DispatchResultWithPostInfo {
	let shard7 = H256::from_slice(&TEST7_MRENCLAVE);
	let signer7 = get_signer(TEST7_SIGNER_PUB);

	Sidechain::confirm_proposed_sidechain_block(
		Origin::signed(signer7.clone()),
		shard7.clone(),
		header.clone(),
	)?;

	if check_for_event {
		let expected_event = Event::Sidechain(SidechainEvent::ProposedSidechainBlock(
			signer7,
			header.block_data_hash,
		));
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
