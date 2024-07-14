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

use frame_support::{
	sp_runtime::SaturatedConversion,
	traits::{fungibles::Inspect, Currency},
	weights::Weight,
};
use sp_runtime::traits::MaybeEquivalence;
#[cfg(not(test))]
use sp_runtime::DispatchResult;
use sp_std::marker::PhantomData;
use staging_xcm::{
	latest::{Asset, AssetId, Fungibility::Fungible, Junctions::Here, Location},
	v4::XcmContext,
};
use staging_xcm_executor::{
	traits::{DropAssets, Error as MatchError, MatchesFungibles},
	AssetsInHolding,
};

pub struct AsAssetLocation<AssetId, AssetIdInfoGetter>(PhantomData<(AssetId, AssetIdInfoGetter)>);
impl<AssetId, AssetIdInfoGetter> MaybeEquivalence<Location, AssetId>
	for AsAssetLocation<AssetId, AssetIdInfoGetter>
where
	AssetId: Clone,
	AssetIdInfoGetter: AssetLocationGetter<AssetId>,
{
	fn convert(asset_location: &Location) -> Option<AssetId> {
		AssetIdInfoGetter::get_asset_id(asset_location)
	}

	fn convert_back(asset_id: &AssetId) -> Option<Location> {
		AssetIdInfoGetter::get_asset_location(asset_id.clone())
	}
}

pub trait AssetLocationGetter<AssetId> {
	fn get_asset_location(asset_id: AssetId) -> Option<Location>;
	fn get_asset_id(asset_location: &Location) -> Option<AssetId>;
}

pub struct ConvertedRegisteredAssetId<AssetId, Balance, ConvertAssetId, ConvertBalance>(
	PhantomData<(AssetId, Balance, ConvertAssetId, ConvertBalance)>,
);
impl<
		AssetId: Clone,
		Balance: Clone,
		ConvertAssetId: MaybeEquivalence<Location, AssetId>,
		ConvertBalance: MaybeEquivalence<Balance, u128>,
	> MatchesFungibles<AssetId, Balance>
	for ConvertedRegisteredAssetId<AssetId, Balance, ConvertAssetId, ConvertBalance>
{
	fn matches_fungibles(a: &Asset) -> Result<(AssetId, Balance), MatchError> {
		let (amount, id) = match (&a.fun, &a.id) {
			(Fungible(ref amount), AssetId(id)) => (amount, id),
			_ => return Err(MatchError::AssetNotHandled),
		};
		let what = ConvertAssetId::convert(id).ok_or(MatchError::AssetNotHandled)?;
		let amount = ConvertBalance::convert_back(amount)
			.ok_or(MatchError::AmountToBalanceConversionFailed)?;
		Ok((what, amount))
	}
}

pub trait DropAssetsWeigher {
	fn fungible() -> Weight;
	fn native() -> Weight;
	fn default() -> Weight;
}

pub struct IntegriteeDropAssets<
	AssetId,
	AssetIdInfoGetter,
	AssetsPallet,
	BalancesPallet,
	XcmPallet,
	AccountId,
	Weigher,
>(
	PhantomData<(
		AssetId,
		AssetIdInfoGetter,
		AssetsPallet,
		BalancesPallet,
		XcmPallet,
		AccountId,
		Weigher,
	)>,
);

impl<AssetId, AssetIdInfoGetter, AssetsPallet, BalancesPallet, XcmPallet, AccountId, Weigher>
	DropAssets
	for IntegriteeDropAssets<
		AssetId,
		AssetIdInfoGetter,
		AssetsPallet,
		BalancesPallet,
		XcmPallet,
		AccountId,
		Weigher,
	>
where
	AssetIdInfoGetter: AssetLocationGetter<AssetId>,
	AssetsPallet: Inspect<AccountId, AssetId = AssetId>,
	BalancesPallet: Currency<AccountId>,
	XcmPallet: DropAssets,
	Weigher: DropAssetsWeigher,
{
	// assets are whatever the Holding Register had when XCVM halts
	fn drop_assets(origin: &Location, mut assets: AssetsInHolding, context: &XcmContext) -> Weight {
		const NATIVE_LOCATION: Location = Location { parents: 0, interior: Here };

		let mut weight: Weight = {
			assets.non_fungible.clear();
			Weigher::default()
		};

		assets.fungible.retain(|id, &mut amount| {
			let location = &id.0;

			match AssetIdInfoGetter::get_asset_id(location) {
				Some(asset_id) => {
					weight.saturating_accrue(Weigher::fungible());

					// only trap if amount ≥ min_balance
					// do nothing otherwise (asset is lost)
					amount.saturated_into::<AssetsPallet::Balance>() >=
						AssetsPallet::minimum_balance(asset_id)
				},
				None => {
					weight.saturating_accrue(Weigher::native());

					// only trap if native token and amount ≥ min_balance
					// do nothing otherwise (asset is lost)
					*location == NATIVE_LOCATION &&
						amount.saturated_into::<BalancesPallet::Balance>() >=
							BalancesPallet::minimum_balance()
				},
			}
		});

		// we have filtered out non-compliant assets
		// insert valid assets into the asset trap implemented by XcmPallet
		weight.saturating_add(XcmPallet::drop_assets(origin, assets, context))
	}
}

/// Pause and resume execution of XCM
#[cfg(not(test))]
pub trait PauseXcmExecution {
	fn suspend_xcm_execution() -> DispatchResult;
	fn resume_xcm_execution() -> DispatchResult;
}
#[cfg(not(test))]
impl PauseXcmExecution for () {
	fn suspend_xcm_execution() -> DispatchResult {
		Ok(())
	}
	fn resume_xcm_execution() -> DispatchResult {
		Ok(())
	}
}
