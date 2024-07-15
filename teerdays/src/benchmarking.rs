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

//! TeerDays pallet benchmarking

#![cfg(any(test, feature = "runtime-benchmarks"))]

use super::*;

use crate::Pallet as TeerDays;
use frame_benchmarking::{account, benchmarks};
use frame_system::RawOrigin;
use sp_std::prelude::*;

benchmarks! {
	where_clause {  where T::AccountId: From<[u8; 32]>, T::Hash: From<[u8; 32]> }
	bond {
		pallet_timestamp::Pallet::<T>::set_timestamp(0u32.into());
		let signer: T::AccountId = account("alice", 1, 1);
		T::Currency::make_free_balance_be(&signer, 10_000u32.into());
	}: _(RawOrigin::Signed(signer.clone()), 1_000u32.into())
	verify {
		assert!(TeerDays::<T>::teerday_bonds(&signer).is_some());
	}

	unbond {
		pallet_timestamp::Pallet::<T>::set_timestamp(0u32.into());
		let signer: T::AccountId = account("alice", 1, 1);
		T::Currency::make_free_balance_be(&signer, 10_000u32.into());
		TeerDays::<T>::bond(RawOrigin::Signed(signer.clone()).into(), 1_000u32.into())?;
	}: _(RawOrigin::Signed(signer.clone()), 500u32.into())
	verify {
		assert!(TeerDays::<T>::teerday_bonds(&signer).is_some());
	}

	update_other {
		pallet_timestamp::Pallet::<T>::set_timestamp(0u32.into());
		let signer: T::AccountId = account("alice", 1, 1);
		T::Currency::make_free_balance_be(&signer, 10_000u32.into());
		TeerDays::<T>::bond(RawOrigin::Signed(signer.clone()).into(), 1_000u32.into())?;
	}: _(RawOrigin::Signed(signer.clone()), signer.clone())
	verify {
		assert!(TeerDays::<T>::teerday_bonds(&signer).is_some());
	}
	withdraw_unbonded {
		pallet_timestamp::Pallet::<T>::set_timestamp(42u32.into());
		let signer: T::AccountId = account("alice", 1, 1);
		T::Currency::make_free_balance_be(&signer, 10_000u32.into());
		T::Currency::set_lock(TEERDAYS_ID, &signer, 1_000u32.into(), WithdrawReasons::all());
		PendingUnlock::<T>::insert::<_, (T::Moment, BalanceOf<T>)>(&signer, (42u32.into(), 1_000u32.into()));
	}: _(RawOrigin::Signed(signer.clone()))
	verify {
		assert!(TeerDays::<T>::pending_unlock(&signer).is_none());
	}

}

#[cfg(test)]
use crate::{Config, Pallet as PalletModule};

#[cfg(test)]
use frame_benchmarking::impl_benchmark_test_suite;

#[cfg(test)]
impl_benchmark_test_suite!(PalletModule, crate::mock::new_test_ext(), crate::mock::Test,);
