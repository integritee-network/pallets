/*
	Copyright 2021 Integritee AG and Supercomputing Systems AG

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <https://www.gnu.org/licenses/>.

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
		let ancestor = SidechainBlockConfirmation {
			block_number: 2,
			block_header_hash: [2; 32].into()
		};
		let candidate = SidechainBlockConfirmation {
			block_number: 25,
			block_header_hash: [25; 32].into()
		};
	}: _(RawOrigin::Signed(accounts[0].clone()), shard, Some(ancestor), candidate)
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
