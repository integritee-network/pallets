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

//! Teeracle pallet benchmarking

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
use teeracle_primitives::{MarketDataSourceString, TradingPairString};

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
		let trading_pair: TradingPairString =  "DOT/USD".to_owned().into();
		let rate = U32F32::from_num(43.65);
		let data_source: MarketDataSourceString = "https://api.coingecko.com".to_owned().into();
		// simply register the enclave before to make sure it already
		// exists when running the benchmark
		Teerex::<T>::register_enclave(
			RawOrigin::Signed(signer.clone()).into(),
			TEST4_SETUP.cert.to_vec(),
			URL.to_vec()
		).unwrap();
		let mrenclave = Teerex::<T>::enclave(1).mr_enclave;
		Exchange::<T>::add_to_whitelist(RawOrigin::Root.into(), data_source.clone(), mrenclave).unwrap();

	}: _(RawOrigin::Signed(signer), data_source.clone(), trading_pair.clone(), Some(rate))
	verify {
		assert_eq!(Exchange::<T>::exchange_rate(trading_pair, data_source), U32F32::from_num(43.65));
	}

	add_to_whitelist {
		let mrenclave = TEST4_MRENCLAVE;
		let data_source: MarketDataSourceString = "https://api.coingecko.com".to_owned().into();

	}: _(RawOrigin::Root, data_source.clone(), mrenclave)
	verify {
		// help the compiler with type inference
		assert_eq!(Exchange::<T>::whitelist(data_source).len(), 1, "mrenclave not added to whitelist")
	}

	remove_from_whitelist {
		let mrenclave = TEST4_MRENCLAVE;
		let data_source: MarketDataSourceString = "https://api.coingecko.com".to_owned().into();

		Exchange::<T>::add_to_whitelist(RawOrigin::Root.into(), data_source.clone(), mrenclave).unwrap();

	}: _(RawOrigin::Root, data_source.clone(), mrenclave)
	verify {
		assert_eq!(Exchange::<T>::whitelist(data_source).len(), 0, "mrenclave not removed from whitelist")
	}
}

#[cfg(test)]
use crate::{Config, Pallet as PalletModule};

#[cfg(test)]
use frame_benchmarking::impl_benchmark_test_suite;

#[cfg(test)]
impl_benchmark_test_suite!(PalletModule, crate::mock::new_test_ext(), crate::mock::Test,);
