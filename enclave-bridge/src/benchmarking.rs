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

//! Teerex pallet benchmarking

#![cfg(any(test, feature = "runtime-benchmarks"))]

use super::*;
use codec::Encode;
use frame_benchmarking::{account, benchmarks};
use frame_system::RawOrigin;
use pallet_teerex::Pallet as Teerex;
use sp_runtime::traits::Hash;
use sp_std::vec;
use teerex_primitives::{MultiEnclave, SgxEnclave};
use test_utils::test_data::ias::*;

fn generate_accounts<T: Config>(amount: u32) -> Vec<T::AccountId> {
	(0..amount).map(|n| account("dummy name", n, n)).collect()
}

benchmarks! {
	// Note: The storage-map structure has the following complexity for updating:
	//   DB Reads: O(1) Encoding: O(1) DB Writes: O(1)
	//
	// Hence, it does not matter how many other enclaves are registered for the benchmark.

	where_clause {  where T::AccountId: From<[u8; 32]>, T::Hash: From<[u8; 32]>,}

	// Benchmark `call_worker`. There are no worst conditions. The benchmark showed that
	// execution time is constant irrespective of cyphertext size.
	invoke {
		let accounts: Vec<T::AccountId> = generate_accounts::<T>(1);
		let req = Request { shard:H256::from_slice(&TEST4_SETUP.mrenclave), cyphertext: vec![1u8; 2000]};
	}: _(RawOrigin::Signed(accounts[0].clone()), req)

	// Benchmark `confirm_processed_parentchain_block` with the worst possible conditions:
	// * sender enclave is registered
	confirm_processed_parentchain_block {
		let accounts: Vec<T::AccountId> = generate_accounts::<T>(1);
		add_sovereign_enclaves_to_registry::<T>(&accounts);

		let block_hash: H256 = [2; 32].into();
		let merkle_root: H256 = [4; 32].into();
		let block_number: u32 = 0;
		let shard = ShardIdentifier::from(EnclaveFingerprint::default());

	}: _(RawOrigin::Signed(accounts[0].clone()), shard, block_hash, block_number.into(), merkle_root)

	// Benchmark `publish_hash` with the worst possible conditions:
	// * sender enclave is registered
	//
	// and parametrize the benchmark with the variably sized parameters. Note: The initialization
	// of `l`/`t` includes the upper borders.
	publish_hash {
		let l in 0 .. DATA_LENGTH_LIMIT as u32;
		let t in 1 .. TOPICS_LIMIT as u32;

		// There are no events emitted at the genesis block.
		frame_system::Pallet::<T>::set_block_number(1u32.into());
		frame_system::Pallet::<T>::reset_events();

		let accounts: Vec<T::AccountId> = generate_accounts::<T>(1);
		add_sovereign_enclaves_to_registry::<T>(&accounts);
		let account = accounts[0].clone();

	}: _(RawOrigin::Signed(account), [1u8; 32].into(), topics::<T>(t), get_data(l))
	verify {
		// Event comparison in an actual node is way too cumbersome as the `RuntimeEvent`
		// does not implement `PartialEq`. So we only verify that the event is emitted here,
		// and we do more thorough checks in the normal cargo tests.
		assert_eq!(frame_system::Pallet::<T>::events().len(), 1);
	}

	// worst case is updating an existing shard config
	update_shard_config {
		let accounts: Vec<T::AccountId> = generate_accounts::<T>(1);
		add_sovereign_enclaves_to_registry::<T>(&accounts);

		let shard = ShardIdentifier::from(EnclaveFingerprint::default());
		let shard_config = ShardConfig::new(EnclaveFingerprint::default());
		// initialize
		//Pallet::<T>::update_shard_config(RuntimeOrigin::signed(accounts[0].clone()), shard, shard_config, 0);
		<ShardConfigRegistry<T>>::insert(shard, UpgradableShardConfig::from(shard_config.clone()));
		let new_shard_config = ShardConfig::new(EnclaveFingerprint::from([1u8; 32]));

	}: _(RawOrigin::Signed(accounts[0].clone()), shard, new_shard_config, 11u8.into())
	verify {
		// Event comparison in an actual node is way too cumbersome as the `RuntimeEvent`
		// does not implement `PartialEq`. So we only verify that the event is emitted here,
		// and we do more thorough checks in the normal cargo tests.
		assert_eq!(frame_system::Pallet::<T>::events().len(), 1);
	}
}

fn add_sovereign_enclaves_to_registry<T: Config>(accounts: &[T::AccountId]) {
	for a in accounts.iter() {
		Teerex::<T>::add_enclave(
			a,
			MultiEnclave::from(SgxEnclave::test_enclave().with_pubkey(&a.encode()[..])),
		)
		.unwrap();
	}
}

fn get_data(x: u32) -> Vec<u8> {
	vec![0u8; x.try_into().unwrap()]
}

/// Returns [number] unique topics.
fn topics<T: frame_system::Config>(number: u32) -> Vec<T::Hash> {
	let vec = vec![
		T::Hashing::hash(&[0u8; 32]),
		T::Hashing::hash(&[1u8; 32]),
		T::Hashing::hash(&[2u8; 32]),
		T::Hashing::hash(&[3u8; 32]),
		T::Hashing::hash(&[4u8; 32]),
	];

	vec[..number.try_into().unwrap()].to_vec()
}

#[cfg(test)]
use crate::{Config, Pallet as PalletModule};

#[cfg(test)]
use frame_benchmarking::impl_benchmark_test_suite;
use test_utils::TestEnclave;

#[cfg(test)]
impl_benchmark_test_suite!(PalletModule, crate::mock::new_test_ext(), crate::mock::Test,);
