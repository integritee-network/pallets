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
use crate::{mock::*, Event as ParentchainEvent};
use frame_support::{assert_err, assert_ok};
use sp_core::H256;
use sp_keyring::AccountKeyring;
use sp_runtime::{
	generic,
	traits::{BlakeTwo256, Header as HeaderT},
	DispatchError::BadOrigin,
};

pub type Header = generic::Header<BlockNumber, BlakeTwo256>;

#[test]
fn verify_storage_works() {
	let block_number = 3;
	let parent_hash = H256::from_low_u64_be(420);

	let header: Header = HeaderT::new(
		block_number,
		Default::default(),
		Default::default(),
		parent_hash,
		Default::default(),
	);
	let hash = header.hash();

	new_test_ext().execute_with(|| {
		assert_ok!(ParentchainIntegritee::set_block(RuntimeOrigin::root(), header));
		assert_eq!(ParentchainIntegritee::block_number(), block_number);
		assert_eq!(ParentchainIntegritee::parent_hash(), parent_hash);
		assert_eq!(ParentchainIntegritee::block_hash(), hash);

		System::assert_last_event(RuntimeEvent::ParentchainIntegritee(
			ParentchainEvent::SetBlock { block_number, parent_hash, block_hash: hash },
		));
	})
}

#[test]
fn multi_pallet_instance_storage_works() {
	let block_number = 3;
	let parent_hash = H256::from_low_u64_be(420);

	let header: Header = HeaderT::new(
		block_number,
		Default::default(),
		Default::default(),
		parent_hash,
		Default::default(),
	);
	let hash = header.hash();

	let block_number_a = 5;
	let parent_hash_a = H256::from_low_u64_be(421);

	let header_a: Header = HeaderT::new(
		block_number_a,
		Default::default(),
		Default::default(),
		parent_hash_a,
		Default::default(),
	);
	let hash_a = header_a.hash();

	new_test_ext().execute_with(|| {
		assert_ok!(ParentchainIntegritee::set_block(RuntimeOrigin::root(), header));
		assert_eq!(ParentchainIntegritee::block_number(), block_number);
		assert_eq!(ParentchainIntegritee::parent_hash(), parent_hash);
		assert_eq!(ParentchainIntegritee::block_hash(), hash);

		System::assert_last_event(RuntimeEvent::ParentchainIntegritee(
			ParentchainEvent::SetBlock { block_number, parent_hash, block_hash: hash },
		));

		assert_ok!(ParentchainTargetA::set_block(RuntimeOrigin::root(), header_a));
		assert_eq!(ParentchainTargetA::block_number(), block_number_a);
		assert_eq!(ParentchainTargetA::parent_hash(), parent_hash_a);
		assert_eq!(ParentchainTargetA::block_hash(), hash_a);

		System::assert_last_event(RuntimeEvent::ParentchainTargetA(ParentchainEvent::SetBlock {
			block_number: block_number_a,
			parent_hash: parent_hash_a,
			block_hash: hash_a,
		}));

		// double check previous storage
		assert_eq!(ParentchainIntegritee::block_number(), block_number);
		assert_eq!(ParentchainIntegritee::block_hash(), hash);
	})
}

#[test]
fn non_root_account_errs() {
	let header = HeaderT::new(
		1,
		Default::default(),
		Default::default(),
		[69; 32].into(),
		Default::default(),
	);

	new_test_ext().execute_with(|| {
		let root = AccountKeyring::Ferdie.to_account_id();
		assert_err!(
			ParentchainIntegritee::set_block(RuntimeOrigin::signed(root), header),
			BadOrigin
		);
	})
}
