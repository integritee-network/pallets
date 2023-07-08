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

use crate::{
	mock::{MaxSilenceTime, Timestamp},
	test_helpers::{get_test_tcb_info, register_test_quoting_enclave},
	Pallet as Teerex,
};
use frame_benchmarking::{account, benchmarks};
use frame_system::RawOrigin;
use sp_runtime::traits::{CheckedConversion, Hash};
use sp_std::vec;
use test_utils::{
	get_signer,
	test_data::{consts::*, dcap::*, ias::*},
};

fn ensure_not_skipping_ra_check() {
	#[cfg(not(test))]
	if cfg!(feature = "skip-ias-check") {
		panic!("Benchmark does not allow the `skip-ias-check` flag.");
	};
}

fn generate_accounts<T: Config>(amount: u32) -> Vec<T::AccountId> {
	(0..amount).map(|n| account("dummy name", n, n)).collect()
}

benchmarks! {
	// Note: The storage-map structure has the following complexity for updating:
	//   DB Reads: O(1) Encoding: O(1) DB Writes: O(1)
	//
	// Hence, it does not matter how many other enclaves are registered for the benchmark.

	where_clause {  where T::AccountId: From<[u8; 32]>, T::Hash: From<[u8; 32]>,}

	// Benchmark `register_ias_enclave` with the worst possible conditions:
	// * remote attestation is valid
	// * enclave already exists
	register_sgx_enclave {
		ensure_not_skipping_ra_check();
		timestamp::Pallet::<T>::set_timestamp(TEST4_SETUP.timestamp.checked_into().unwrap());
		let signer: T::AccountId = get_signer(TEST4_SETUP.signer_pub);

		// simply register the enclave before to make sure it already
		// exists when running the benchmark
		Teerex::<T>::register_sgx_enclave(
			RawOrigin::Signed(signer.clone()).into(),
			TEST4_SETUP.cert.to_vec(),
			Some(URL.to_vec()),
			SgxAttestationMethod::Ias
		).unwrap();

	}: _(RawOrigin::Signed(signer.clone()), TEST4_SETUP.cert.to_vec(), Some(URL.to_vec()), SgxAttestationMethod::Ias)
	verify {
		assert!(crate::SovereignEnclaves::<T>::contains_key(&signer));
	}

	// Benchmark `register_quoting_enclave` with the worst possible conditions:
	// * quoting enclave registration succeeds
	register_quoting_enclave {
		ensure_not_skipping_ra_check();
		timestamp::Pallet::<T>::set_timestamp(TEST_VALID_COLLATERAL_TIMESTAMP.checked_into().unwrap());
		let signer: T::AccountId = get_signer(&TEST1_DCAP_QUOTE_SIGNER);

	}: _(RawOrigin::Signed(signer), QUOTING_ENCLAVE.to_vec(), QUOTING_ENCLAVE_SIGNATURE.to_vec(), QE_IDENTITY_ISSUER_CHAIN.to_vec())
	verify {
		let qe = Pallet::<T>::quoting_enclave();
		assert_eq!(qe.isvprodid, 1);
	}

	// Benchmark `register_tcb_info` with the worst possible conditions:
	// * tcb registration succeeds
	register_tcb_info {
		ensure_not_skipping_ra_check();
		timestamp::Pallet::<T>::set_timestamp(TEST_VALID_COLLATERAL_TIMESTAMP.checked_into().unwrap());
		let signer: T::AccountId = get_signer(&TEST1_DCAP_QUOTE_SIGNER);
		register_test_quoting_enclave::<T>(signer.clone());

	}: _(RawOrigin::Signed(signer), TCB_INFO.to_vec(), TCB_INFO_SIGNATURE.to_vec(), TCB_INFO_CERTIFICATE_CHAIN.to_vec())
	verify {
		// This is the date that the is registered in register_tcb_info and represents the date 2023-04-16T12:45:32Z
		assert_eq!(get_test_tcb_info::<T>().next_update, 1681649132000);
	}
/*
	// Benchmark `register_dcap_enclave` with the worst possible conditions:
	// * dcap registration succeeds
	register_sgx_enclave {
		ensure_not_skipping_ra_check();
		timestamp::Pallet::<T>::set_timestamp(TEST_VALID_COLLATERAL_TIMESTAMP.checked_into().unwrap());
		let signer: T::AccountId = get_signer(&TEST1_DCAP_QUOTE_SIGNER);

		register_test_quoting_enclave::<T>(signer.clone());
		register_test_tcb_info::<T>(signer.clone());

	}: _(RawOrigin::Signed(signer), TEST1_DCAP_QUOTE.to_vec(), Some(URL.to_vec()), SgxAttestationMethod::Dcap { proxied: false })
	verify {
		assert_eq!(Teerex::<T>::enclave_count(), 1);
	}
*/
	// Benchmark `unregister_enclave` enclave with the worst possible conditions:
	// * enclave exists
	// * enclave is not the most recently registered enclave
	unregister_sovereign_enclave {
		let enclave_count = 3;
		let accounts: Vec<T::AccountId> = generate_accounts::<T>(enclave_count);
		add_enclaves_to_registry::<T>(&accounts);
		Timestamp::set_timestamp(TEST4_TIMESTAMP + <MaxSilenceTime>::get() + 1);

	}: _(RawOrigin::Signed(accounts[0].clone()), accounts[0].clone())
	verify {
		assert!(!crate::SovereignEnclaves::<T>::contains_key(&accounts[0]));
	}

	// Benchmark `call_worker`. There are no worst conditions. The benchmark showed that
	// execution time is constant irrespective of cyphertext size.
	call_worker {
		let accounts: Vec<T::AccountId> = generate_accounts::<T>(1);
		let req = Request { shard:H256::from_slice(&TEST4_SETUP.mrenclave), cyphertext: vec![1u8; 2000]};
	}: _(RawOrigin::Signed(accounts[0].clone()), req)

	// Benchmark `confirm_processed_parentchain_block` with the worst possible conditions:
	// * sender enclave is registered
	confirm_processed_parentchain_block {
		let accounts: Vec<T::AccountId> = generate_accounts::<T>(1);
		add_enclaves_to_registry::<T>(&accounts);

		let block_hash: H256 = [2; 32].into();
		let merkle_root: H256 = [4; 32].into();
		let block_number: u32 = 0;

	}: _(RawOrigin::Signed(accounts[0].clone()), block_hash, block_number.into(), merkle_root)

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
		add_enclaves_to_registry::<T>(&accounts);
		let account = accounts[0].clone();

	}: _(RawOrigin::Signed(account), [1u8; 32].into(), topics::<T>(t), get_data(l))
	verify {
		// Event comparison in an actual node is way too cumbersome as the `RuntimeEvent`
		// does not implement `PartialEq`. So we only verify that the event is emitted here,
		// and we do more thorough checks in the normal cargo tests.
		assert_eq!(frame_system::Pallet::<T>::events().len(), 1);
	}
}

fn add_enclaves_to_registry<T: Config>(accounts: &[T::AccountId]) {
	for a in accounts.iter() {
		Teerex::<T>::add_enclave(
			a,
			&MultiEnclave::from(SgxEnclave::test_enclave().with_mr_enclave(TEST4_SETUP.mrenclave)),
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
