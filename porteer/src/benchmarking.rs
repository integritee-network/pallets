/*
	Copyright 2021 Integritee AG

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

//! Porteer pallet benchmarking

#![cfg(any(test, feature = "runtime-benchmarks"))]

use super::*;

use crate::Pallet;
use frame_benchmarking::{account, benchmarks};
use frame_support::traits::fungible;
use frame_system::RawOrigin;
use sp_std::prelude::*;

benchmarks! {
	set_porteer_config {
		let config = PorteerConfig { send_enabled: true, receive_enabled: false };
	}: _(RawOrigin::Root, config)
	verify {
		assert_eq!(PorteerConfigValue::<T>::get(), config);
	}
	set_watchdog {
		let bob: T::AccountId = account("bob", 1, 1);
	}: _(RawOrigin::Root, bob.clone())
	verify {
		assert_eq!(WatchdogAccount::<T>::get(), Some(bob));
	}
	watchdog_heartbeat {
		let bob: T::AccountId = account("bob", 1, 1);
		WatchdogAccount::<T>::set(Some(bob.clone()));
	}: _(RawOrigin::Signed(bob.clone()))
	verify {
		let now = pallet_timestamp::Pallet::<T>::get();
		assert_eq!(LastHeartBeat::<T>::get(), now);
	}
	set_xcm_fee_params {
		let fee_params = XcmFeeParams { hop1: 1u32.into(), hop2: 2u32.into(), hop3: 3u32.into() };
	}: _(RawOrigin::Root, fee_params)
	verify {
		assert_eq!(XcmFeeConfig::<T>::get(), fee_params);
	}
	add_location_to_whitelist {
		let location = T::BenchmarkHelper::get_whitelisted_location();
	}: _(RawOrigin::Root, location.clone())
	verify {
		assert!(ForwardLocationWhitelist::<T>::contains_key(location));
	}

	remove_location_from_whitelist {
		let location = T::BenchmarkHelper::get_whitelisted_location();
		ForwardLocationWhitelist::<T>::insert(location.clone(), ());
	}: _(RawOrigin::Root, location.clone())
	verify {
		assert!(!ForwardLocationWhitelist::<T>::contains_key(location));
	}
	port_tokens {
		let alice: T::AccountId = account("alice", 1, 1);
		let port_amount: BalanceOf<T> = 4_000_000_000u32.into();
		<T::Fungible as fungible::Mutate<_>>::set_balance(&alice, port_amount);
		let location = <T as Config>::BenchmarkHelper::get_whitelisted_location();

	}: _(RawOrigin::Signed(alice.clone()), port_amount, Some(location))
	verify {
		assert_eq!(<T::Fungible as fungible::Inspect<_>>::balance(&alice), 0u32.into());
	}

	mint_ported_tokens {
		let bob: T::AccountId = account("bob", 1, 1);
		let mint_amount: BalanceOf<T> = 4_000_000_000u32.into();
		<T::Fungible as fungible::Mutate<_>>::set_balance(&bob, 0u32.into());
		let location = <T as Config>::BenchmarkHelper::get_whitelisted_location();

	}: _(RawOrigin::Root, bob.clone(), mint_amount, Some(location), 0u32.into())
	verify {
		assert_eq!(<T::Fungible as fungible::Inspect<_>>::balance(&bob), mint_amount);
	}
}

#[cfg(test)]
use crate::{Config, Pallet as PalletModule};

#[cfg(test)]
use frame_benchmarking::impl_benchmark_test_suite;

#[cfg(test)]
impl_benchmark_test_suite!(PalletModule, crate::mock::new_test_ext(), crate::mock::Test,);
