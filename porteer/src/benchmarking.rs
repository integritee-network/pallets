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
		// Todo: how to get the proper origin from the mock??
		let signer: T::AccountId = account("alice", 1, 1);
		let config = PorteerConfig { send_enabled: true, receive_enabled: true };

	}: _(RawOrigin::Signed(signer.clone()), config)
	verify {
		// assert!(TeerDays::<T>::teerday_bonds(&signer).is_some());
	}
	port_tokens {
		let signer: T::AccountId = account("alice", 1, 1);
		let signer_free: BalanceOf<T> = 4_000_000_000u32.into();
		<T::Fungible as fungible::Mutate<_>>::set_balance(&signer, signer_free);

	}: _(RawOrigin::Signed(signer.clone()), signer_free)
	verify {
		// assert!(TeerDays::<T>::teerday_bonds(&signer).is_some());
	}

	mint_ported_tokens {
		// Todo: how to get the proper origin from the mock??
		let signer: T::AccountId = account("alice", 1, 1);
		let bob: T::AccountId = account("bob", 1, 1);
		let mint_into_bob: BalanceOf<T> = 4_000_000_000u32.into();
		<T::Fungible as fungible::Mutate<_>>::set_balance(&bob, 0u32.into());

	}: _(RawOrigin::Signed(signer.clone()), bob, mint_into_bob)
	verify {
		// assert!(TeerDays::<T>::teerday_bonds(&signer).is_some());
	}
}

#[cfg(test)]
use crate::{Config, Pallet as PalletModule};

#[cfg(test)]
use frame_benchmarking::impl_benchmark_test_suite;

#[cfg(test)]
impl_benchmark_test_suite!(PalletModule, crate::mock::new_test_ext(), crate::mock::Test,);
