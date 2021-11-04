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

//! Market pallet benchmarking

#![cfg(any(test, feature = "runtime-benchmarks"))]

use super::*;

use crate::Pallet as Exchange;
use ::test_utils::{
	get_signer,
	ias::{consts::*, ias::*},
};
use frame_benchmarking::benchmarks;
use frame_system::RawOrigin;
use pallet_teerex::Pallet as Teerex;
use sp_runtime::traits::CheckedConversion;
use sp_std::borrow::ToOwned;

fn ensure_not_skipping_ra_check() {
	#[cfg(not(test))]
	if cfg!(feature = "skip-ias-check") {
		panic!("Benchmark does not allow the `skip-ias-check` flag.");
	};
}
benchmarks! {
	where_clause {  where T::AccountId: From<[u8; 32]> }
	update_exchange_rate {
		ensure_not_skipping_ra_check();
		timestamp::Pallet::<T>::set_timestamp(TEST4_SETUP.timestamp.checked_into().unwrap());
		let signer: T::AccountId = get_signer(TEST4_SETUP.signer_pub);
		let currency = "usd".as_bytes().to_owned();
		let rate = U32F32::from_num(43.65);
		// simply register the enclave before to make sure it already
		// exists when running the benchmark
		Teerex::<T>::register_enclave(
			RawOrigin::Signed(signer.clone()).into(),
			TEST4_SETUP.cert.to_vec(),
			URL.to_vec()
		).unwrap();


	}: _(RawOrigin::Signed(signer), currency, Some(rate))
	verify {
		assert_eq!(Exchange::<T>::exchange_rate("usd".as_bytes().to_owned()), U32F32::from_num(43.65));
	}
}

#[cfg(test)]
use crate::{Config, Pallet as PalletModule};

#[cfg(test)]
use frame_benchmarking::impl_benchmark_test_suite;

#[cfg(test)]
impl_benchmark_test_suite!(PalletModule, crate::mock::new_test_ext(), crate::mock::Test,);
