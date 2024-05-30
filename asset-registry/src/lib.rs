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

#![cfg_attr(not(feature = "std"), no_std)]
#![allow(clippy::large_enum_variant)]

/// Edit this file to define custom logic or remove it if it is not needed.
/// Learn more about FRAME and the core library of Substrate FRAME pallets:
/// <https://docs.substrate.io/reference/frame-pallets/>
pub use pallet::*;

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;
pub mod weights;
pub use weights::*;

#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use frame_support::{pallet_prelude::*, traits::tokens::fungibles::Inspect};
	use frame_system::pallet_prelude::*;

	use staging_xcm::latest::{
		Junction::{AccountId32, AccountKey20, GeneralIndex, PalletInstance, Parachain},
		Location,
	};

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	type AssetIdOf<T> =
		<<T as Config>::Assets as Inspect<<T as frame_system::Config>::AccountId>>::AssetId;

	#[cfg(feature = "runtime-benchmarks")]
	pub trait BenchmarkHelper<AssetId> {
		fn get_registered_asset() -> AssetId;
	}

	#[pallet::config]
	pub trait Config: frame_system::Config {
		type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
		type ReserveAssetModifierOrigin: EnsureOrigin<Self::RuntimeOrigin>;
		type Assets: Inspect<Self::AccountId>;
		type WeightInfo: WeightInfo;
		/// Helper trait for benchmarks.
		#[cfg(feature = "runtime-benchmarks")]
		type BenchmarkHelper: BenchmarkHelper<AssetIdOf<Self>>;
	}

	#[pallet::storage]
	pub type AssetIdLocation<T: Config> = StorageMap<_, Blake2_128Concat, AssetIdOf<T>, Location>;

	#[pallet::storage]
	pub type AssetLocationId<T: Config> = StorageMap<_, Blake2_128Concat, Location, AssetIdOf<T>>;

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		ReserveAssetRegistered { asset_id: AssetIdOf<T>, asset_location: Location },
		ReserveAssetUnregistered { asset_id: AssetIdOf<T>, asset_location: Location },
	}

	#[pallet::error]
	pub enum Error<T> {
		/// The Asset ID is already registered
		AssetAlreadyRegistered,
		/// The Asset ID does not exist
		AssetDoesNotExist,
		/// The Asset ID is not registered
		AssetIsNotRegistered,
		/// Invalid Location
		WrongLocation,
	}

	#[pallet::call]
	#[allow(clippy::large_enum_variant)]
	impl<T: Config> Pallet<T> {
		#[pallet::call_index(0)]
		#[pallet::weight(<T as pallet::Config>::WeightInfo::register_reserve_asset())]
		pub fn register_reserve_asset(
			origin: OriginFor<T>,
			asset_id: AssetIdOf<T>,
			asset_location: Location,
		) -> DispatchResult {
			T::ReserveAssetModifierOrigin::ensure_origin(origin)?;

			// verify asset exists on pallet-assets
			ensure!(T::Assets::asset_exists(asset_id.clone()), Error::<T>::AssetDoesNotExist);

			// verify asset is not yet registered
			ensure!(
				!AssetIdLocation::<T>::contains_key(asset_id.clone()),
				Error::<T>::AssetAlreadyRegistered
			);

			// verify Location is valid
			ensure!(Self::valid_asset_location(&asset_location), Error::<T>::WrongLocation);

			// register asset_id => asset_location
			AssetIdLocation::<T>::insert(asset_id.clone(), asset_location.clone());
			// register asset_location => asset_id
			AssetLocationId::<T>::insert(asset_location.clone(), asset_id.clone());

			Self::deposit_event(Event::ReserveAssetRegistered { asset_id, asset_location });
			Ok(())
		}

		#[pallet::call_index(1)]
		#[pallet::weight(<T as pallet::Config>::WeightInfo::unregister_reserve_asset())]
		pub fn unregister_reserve_asset(
			origin: OriginFor<T>,
			asset_id: AssetIdOf<T>,
		) -> DispatchResult {
			T::ReserveAssetModifierOrigin::ensure_origin(origin)?;

			// remove asset_id => asset_location, while getting the value
			let asset_location =
				AssetIdLocation::<T>::mutate_exists(asset_id.clone(), Option::take)
					.ok_or(Error::<T>::AssetIsNotRegistered)?;
			// remove asset_location => asset_id
			AssetLocationId::<T>::remove(asset_location.clone());

			Self::deposit_event(Event::ReserveAssetUnregistered { asset_id, asset_location });
			Ok(())
		}
	}

	impl<T: Config> Pallet<T> {
		//Validates that the location points to an asset (Native, Frame based, Erc20) as described
		// in the xcm-format:  https://github.com/paritytech/xcm-format#concrete-identifiers
		fn valid_asset_location(location: &Location) -> bool {
			let (split_multilocation, last_junction) = location.clone().split_last_interior();

			let check = matches!(
				last_junction,
				Some(AccountId32 { .. }) |
					Some(AccountKey20 { .. }) |
					Some(PalletInstance(_)) |
					Some(Parachain(_)) | None
			);

			check |
				match last_junction {
					Some(GeneralIndex(_)) => {
						let penultimate = split_multilocation.last();
						matches!(penultimate, Some(PalletInstance(_)))
					},
					_ => false,
				}
		}
	}

	impl<T: Config> xcm_primitives::AssetLocationGetter<AssetIdOf<T>> for Pallet<T> {
		fn get_asset_location(asset_id: AssetIdOf<T>) -> Option<Location> {
			AssetIdLocation::<T>::get(asset_id)
		}

		fn get_asset_id(asset_type: &Location) -> Option<AssetIdOf<T>> {
			AssetLocationId::<T>::get(asset_type)
		}
	}
}
