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

//! Sidechain pallet benchmarking

#![cfg(any(test, feature = "runtime-benchmarks"))]

use super::*;
use frame_benchmarking::{account, benchmarks};
use frame_system::RawOrigin;
use pallet_teerex::Pallet as Teerex;
use parity_scale_codec::Encode;
use test_utils::test_data::ias::*;

fn assert_latest_worker_update<T: Config>(sender: &T::AccountId, shard: &ShardIdentifier) {
	assert_eq!(EnclaveBridge::<T>::most_recent_shard_update(shard).unwrap().signer, *sender);
}

fn generate_accounts<T: Config>(amount: u32) -> Vec<T::AccountId> {
	(0..amount).map(|n| account("dummy name", n, n)).collect()
}

fn add_enclaves_to_registry<T: Config>(accounts: &[T::AccountId]) {
	for a in accounts.iter() {
		Teerex::<T>::add_enclave(
			a,
			MultiEnclave::from(
				SgxEnclave::test_enclave()
					.with_pubkey(&a.encode())
					.with_mr_enclave(TEST4_SETUP.mrenclave),
			),
		)
		.unwrap();
	}
}

benchmarks! {
	// Benchmark `confirm_imported_sidechain_block` with the worst possible conditions:
	// * sender enclave is registered
	confirm_imported_sidechain_block {
		let accounts: Vec<T::AccountId> = generate_accounts::<T>(1);
		add_enclaves_to_registry::<T>(&accounts);

		let shard: ShardIdentifier = H256::from_slice(&TEST4_SETUP.mrenclave);
		let hash: H256 = [2; 32].into();
		let block_number = 1;
		let next_finalization_candidate_block_number = 20;
	}: _(RawOrigin::Signed(accounts[0].clone()), shard, block_number, next_finalization_candidate_block_number, hash)
	verify {
		assert_latest_worker_update::<T>(&accounts[0], &shard)
	}
}

#[cfg(test)]
use crate::{Config, Pallet as PalletModule};

#[cfg(test)]
use frame_benchmarking::impl_benchmark_test_suite;
use teerex_primitives::{MultiEnclave, SgxEnclave};
use test_utils::TestEnclave;

#[cfg(test)]
impl_benchmark_test_suite!(PalletModule, crate::mock::new_test_ext(), crate::mock::Test,);
