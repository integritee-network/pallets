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
	test_helpers::{get_test_tcb_info, register_test_quoting_enclave, register_test_tcb_info},
	Pallet as Teerex,
};
use frame_benchmarking::{account, benchmarks};
use frame_system::RawOrigin;
use sp_runtime::traits::CheckedConversion;
use test_utils::{
	get_signer,
	test_data::{consts::*, dcap::*, ias::*},
};

const MAX_SILENCE_TIME: u64 = 172_800_000; // 48h

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

	// Benchmark `register_sgx_enclave` with the worst possible conditions (DCAP sovereign is more involved than Ias or proxied DCAP):
	// * dcap registration succeeds
	register_sgx_enclave {
		ensure_not_skipping_ra_check();
		timestamp::Pallet::<T>::set_timestamp(TEST_VALID_COLLATERAL_TIMESTAMP.checked_into().unwrap());
		let signer: T::AccountId = get_signer(&TEST1_DCAP_QUOTE_SIGNER);

		register_test_quoting_enclave::<T>(signer.clone());
		register_test_tcb_info::<T>(signer.clone());

	}: _(RawOrigin::Signed(signer), TEST1_DCAP_QUOTE.to_vec(), Some(URL.to_vec()), SgxAttestationMethod::Dcap { proxied: false })
	verify {
		let enclave_vec = <SovereignEnclaves<T>>::iter()
		.collect::<Vec<(T::AccountId, MultiEnclave<Vec<u8>>)>>();
		assert_eq!(enclave_vec.len(), 1);
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

	// Benchmark `unregister_sovereign_enclave` enclave with the worst possible conditions:
	// * enclave exists
	// * enclave is not the most recently registered enclave
	unregister_sovereign_enclave {
		let enclave_count = 3;
		let accounts: Vec<T::AccountId> = generate_accounts::<T>(enclave_count);
		add_sovereign_enclaves_to_registry::<T>(&accounts);
		timestamp::Pallet::<T>::set_timestamp((TEST4_TIMESTAMP + MAX_SILENCE_TIME + 1).checked_into().unwrap());

	}: _(RawOrigin::Signed(accounts[0].clone()), accounts[0].clone())
	verify {
		assert!(!crate::SovereignEnclaves::<T>::contains_key(&accounts[0]));
	}

	// Benchmark `unregister_proxied_enclave` enclave with the worst possible conditions:
	// * enclave exists
	// * enclave is not the most recently registered enclave
	unregister_proxied_enclave {
		let enclave_count = 3;
		let accounts: Vec<T::AccountId> = generate_accounts::<T>(enclave_count);
		add_proxied_enclaves_to_registry::<T>(&accounts);
		let (key0, value0) = <ProxiedEnclaves<T>>::iter()
		.collect::<Vec<(EnclaveInstanceAddress<T::AccountId>, MultiEnclave<Vec<u8>>)>>()[0].clone();
		timestamp::Pallet::<T>::set_timestamp((TEST4_TIMESTAMP + MAX_SILENCE_TIME + 1).checked_into().unwrap());

	}: _(RawOrigin::Signed(accounts[0].clone()), key0.clone())
	verify {
		assert!(!crate::ProxiedEnclaves::<T>::contains_key(&key0));
	}
}

fn add_sovereign_enclaves_to_registry<T: Config>(accounts: &[T::AccountId]) {
	for a in accounts.iter() {
		Teerex::<T>::add_enclave(
			a,
			MultiEnclave::from(SgxEnclave::test_enclave().with_mr_enclave(TEST4_SETUP.mrenclave)),
		)
		.unwrap();
	}
}

fn add_proxied_enclaves_to_registry<T: Config>(accounts: &[T::AccountId]) {
	for a in accounts.iter() {
		Teerex::<T>::add_enclave(
			a,
			MultiEnclave::from(
				SgxEnclave::test_enclave()
					.with_mr_enclave(TEST4_SETUP.mrenclave)
					.with_attestation_method(SgxAttestationMethod::Dcap { proxied: true }),
			),
		)
		.unwrap();
	}
}

#[cfg(test)]
use crate::{Config, Pallet as PalletModule};

#[cfg(test)]
use frame_benchmarking::impl_benchmark_test_suite;
use test_utils::TestEnclave;

#[cfg(test)]
impl_benchmark_test_suite!(PalletModule, crate::mock::new_test_ext(), crate::mock::Test,);
