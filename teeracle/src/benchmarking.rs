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

use crate::Pallet as Teeracle;
use frame_benchmarking::benchmarks;
use frame_system::RawOrigin;
use pallet_teerex::Pallet as Teerex;
use sp_runtime::traits::CheckedConversion;
use sp_std::prelude::*;
use teeracle_primitives::{DataSource, OracleDataName, TradingPairString};
use teerex_primitives::SgxAttestationMethod;

use test_utils::{
	get_signer,
	test_data::{consts::*, ias::*},
};

benchmarks! {
	where_clause {
		where
			T::AccountId: From<[u8; 32]>,
			T::Hash: From<[u8; 32]>,
			T: pallet_aura::Config,
			T::Moment: CheckedConversion,
	}
	update_exchange_rate {
		<pallet_aura::CurrentSlot<T> as StorageValue<Slot>>::put(Slot::from(TEST4_SETUP.timestamp.saturating_div(T::SlotDuration::get().checked_into().unwrap())));
		pallet_timestamp::Pallet::<T>::set_timestamp(TEST4_SETUP.timestamp.checked_into().unwrap());
		let signer: T::AccountId = get_signer(TEST4_SETUP.signer_pub);
		let trading_pair: TradingPairString =  "DOT/USD".into();
		let rate = U32F32::from_num(43.65);
		let data_source: DataSource = "https://api.coingecko.com".into();
		// simply register the enclave before to make sure it already
		// exists when running the benchmark
		Teerex::<T>::register_sgx_enclave(
			RawOrigin::Signed(signer.clone()).into(),
			TEST4_SETUP.cert.to_vec(),
			Some(URL.to_vec()),
			SgxAttestationMethod::Ias,
		).unwrap();
		let fingerprint = Teerex::<T>::sovereign_enclaves(&signer).unwrap().fingerprint();
		Teeracle::<T>::add_to_whitelist(RawOrigin::Root.into(), data_source.clone(), fingerprint).unwrap();

	}: _(RawOrigin::Signed(signer), data_source.clone(), trading_pair.clone(), Some(rate))
	verify {
		assert_eq!(Teeracle::<T>::exchange_rate(trading_pair, data_source), U32F32::from_num(43.65));
	}

	update_oracle {
		<pallet_aura::CurrentSlot<T> as StorageValue<Slot>>::put(Slot::from(TEST4_SETUP.timestamp.saturating_div(T::SlotDuration::get().checked_into().unwrap())));
		pallet_timestamp::Pallet::<T>::set_timestamp(TEST4_SETUP.timestamp.checked_into().unwrap());
		let signer: T::AccountId = get_signer(TEST4_SETUP.signer_pub);
		let oracle_name = OracleDataName::from("Test_Oracle_Name");
		let data_source = DataSource::from("Test_Source_Name");
		let oracle_blob: crate::OracleDataBlob<T> =
			vec![1].try_into().expect("Can Convert to OracleDataBlob<T>; QED");
		// simply register the enclave before to make sure it already
		// exists when running the benchmark
		Teerex::<T>::register_sgx_enclave(
			RawOrigin::Signed(signer.clone()).into(),
			TEST4_SETUP.cert.to_vec(),
			Some(URL.to_vec()),
			SgxAttestationMethod::Ias,
		).unwrap();
		let fingerprint = Teerex::<T>::sovereign_enclaves(&signer).unwrap().fingerprint();
		Teeracle::<T>::add_to_whitelist(RawOrigin::Root.into(), data_source.clone(), fingerprint).unwrap();
	}: _(RawOrigin::Signed(signer), oracle_name.clone(), data_source.clone(), oracle_blob.clone())
	verify {
		assert_eq!(Teeracle::<T>::oracle_data(oracle_name, data_source), oracle_blob);
	}

	add_to_whitelist {
		let fingerprint = EnclaveFingerprint::from(TEST4_MRENCLAVE);
		let data_source: DataSource = "https://api.coingecko.com".into();

	}: _(RawOrigin::Root, data_source.clone(), fingerprint)
	verify {
		assert_eq!(Teeracle::<T>::whitelist(data_source).len(), 1, "mrenclave not added to whitelist")
	}

	remove_from_whitelist {
		let fingerprint = EnclaveFingerprint::from(TEST4_MRENCLAVE);
		let data_source: DataSource = "https://api.coingecko.com".into();

		Teeracle::<T>::add_to_whitelist(RawOrigin::Root.into(), data_source.clone(), fingerprint).unwrap();

	}: _(RawOrigin::Root, data_source.clone(), fingerprint)
	verify {
		assert_eq!(Teeracle::<T>::whitelist(data_source).len(), 0, "mrenclave not removed from whitelist")
	}
}

#[cfg(test)]
use crate::{Config, Pallet as PalletModule};

#[cfg(test)]
use frame_benchmarking::impl_benchmark_test_suite;
use frame_support::{traits::Get, StorageValue};
use sp_consensus_aura::Slot;

#[cfg(test)]
impl_benchmark_test_suite!(PalletModule, crate::mock::new_test_ext(), crate::mock::Test,);
