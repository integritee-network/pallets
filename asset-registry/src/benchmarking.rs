// This file is part of Trappist.
// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Benchmarking setup for pallet-asset-registry
use super::*;

#[allow(unused)]
use crate::Pallet as AssetRegistry;
use frame_benchmarking::benchmarks;
use frame_support::assert_ok;
use frame_system::RawOrigin;
use staging_xcm::opaque::latest::{
	Junction::{GeneralIndex, PalletInstance, Parachain},
	Location,
};

benchmarks! {
	register_reserve_asset {
		let asset_id = T::BenchmarkHelper::get_registered_asset();
		let asset_location = Location {
			parents: 1,
			interior: [Parachain(Default::default()), PalletInstance(Default::default()), GeneralIndex(Default::default())].into()
		};
	}: _(RawOrigin::Root, asset_id.clone(), asset_location.clone())
	verify {
		assert_eq!(AssetIdLocation::<T>::get(asset_id), Some(asset_location));
	}

	unregister_reserve_asset {
		let asset_id = T::BenchmarkHelper::get_registered_asset();
		let asset_location = Location {
			parents: 1,
			interior: [Parachain(Default::default()), PalletInstance(Default::default()), GeneralIndex(Default::default())].into()
		};
		assert_ok!(AssetRegistry::<T>::register_reserve_asset(RawOrigin::Root.into(), asset_id.clone(), asset_location));
		assert!(AssetIdLocation::<T>::contains_key(asset_id.clone()));
	}: _(RawOrigin::Root, asset_id.clone())
	verify {
		assert_eq!(AssetIdLocation::<T>::get(asset_id), None);
	}

	impl_benchmark_test_suite!(AssetRegistry, crate::mock::new_test_ext(), crate::mock::Test);
}
