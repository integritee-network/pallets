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

use frame_support::{assert_noop, assert_ok};
use staging_xcm::{latest::prelude::*, opaque::lts::NetworkId::Rococo};

use crate::{mock::*, AssetIdLocation, AssetLocationId, Error};

pub fn asset_hub_asset_location() -> Location {
	Location {
		parents: 1,
		interior: [
			Parachain(StatemineParaIdInfo::get()),
			PalletInstance(StatemineAssetsInstanceInfo::get()),
			GeneralIndex(StatemineAssetIdInfo::get()),
		]
		.into(),
	}
}

mod register_reserve_assest {
	use super::*;

	#[test]
	fn register_reserve_asset_works() {
		new_test_ext().execute_with(|| {
			assert_ok!(AssetRegistry::register_reserve_asset(
				RuntimeOrigin::root(),
				LOCAL_ASSET_ID,
				asset_hub_asset_location(),
			));

			assert_eq!(
				AssetIdLocation::<Test>::get(LOCAL_ASSET_ID),
				Some(asset_hub_asset_location())
			);
			assert_eq!(
				AssetLocationId::<Test>::get(asset_hub_asset_location()),
				Some(LOCAL_ASSET_ID)
			);
		});
	}

	#[test]
	fn cannot_register_unexisting_asset() {
		new_test_ext().execute_with(|| {
			let unexisting_asset_id = 9999;

			assert_noop!(
				AssetRegistry::register_reserve_asset(
					RuntimeOrigin::root(),
					unexisting_asset_id,
					asset_hub_asset_location(),
				),
				Error::<Test>::AssetDoesNotExist
			);
		});
	}

	#[test]
	fn cannot_double_register() {
		new_test_ext().execute_with(|| {
			assert_ok!(AssetRegistry::register_reserve_asset(
				RuntimeOrigin::root(),
				LOCAL_ASSET_ID,
				asset_hub_asset_location(),
			));

			assert_noop!(
				AssetRegistry::register_reserve_asset(
					RuntimeOrigin::root(),
					LOCAL_ASSET_ID,
					asset_hub_asset_location(),
				),
				Error::<Test>::AssetAlreadyRegistered
			);
		});
	}

	#[test]
	fn valid_locations_succeed() {
		let native_frame_based_currency =
			Location { parents: 1, interior: [Parachain(1000), PalletInstance(1)].into() };
		let multiasset_pallet_instance = Location {
			parents: 1,
			interior: [Parachain(1000), PalletInstance(1), GeneralIndex(2)].into(),
		};
		let relay_native_currency = Location { parents: 1, interior: Junctions::Here };
		let erc20_frame_sm_asset = Location {
			parents: 1,
			interior: [
				Parachain(1000),
				PalletInstance(2),
				AccountId32 { network: Some(Rococo.into()), id: [0; 32] },
			]
			.into(),
		};
		let erc20_ethereum_sm_asset = Location {
			parents: 1,
			interior: [
				Parachain(2000),
				AccountKey20 { network: Some(Ethereum { chain_id: 56 }), key: [0; 20] },
			]
			.into(),
		};

		new_test_ext().execute_with(|| {
			assert_ok!(AssetRegistry::register_reserve_asset(
				RuntimeOrigin::root(),
				LOCAL_ASSET_ID,
				native_frame_based_currency,
			));
		});
		new_test_ext().execute_with(|| {
			assert_ok!(AssetRegistry::register_reserve_asset(
				RuntimeOrigin::root(),
				LOCAL_ASSET_ID,
				multiasset_pallet_instance,
			));
		});
		new_test_ext().execute_with(|| {
			assert_ok!(AssetRegistry::register_reserve_asset(
				RuntimeOrigin::root(),
				LOCAL_ASSET_ID,
				relay_native_currency,
			));
		});
		new_test_ext().execute_with(|| {
			assert_ok!(AssetRegistry::register_reserve_asset(
				RuntimeOrigin::root(),
				LOCAL_ASSET_ID,
				erc20_frame_sm_asset,
			));
		});
		new_test_ext().execute_with(|| {
			assert_ok!(AssetRegistry::register_reserve_asset(
				RuntimeOrigin::root(),
				LOCAL_ASSET_ID,
				erc20_ethereum_sm_asset,
			));
		});
	}

	#[test]
	fn invalid_locations_fail() {
		let governance_location = Location {
			parents: 1,
			interior: [Parachain(1000), Plurality { id: BodyId::Executive, part: BodyPart::Voice }]
				.into(),
		};
		let invalid_general_index =
			Location { parents: 1, interior: [Parachain(1000), GeneralIndex(1u128)].into() };

		new_test_ext().execute_with(|| {
			assert_noop!(
				AssetRegistry::register_reserve_asset(
					RuntimeOrigin::root(),
					LOCAL_ASSET_ID,
					governance_location,
				),
				Error::<Test>::WrongLocation
			);

			assert_noop!(
				AssetRegistry::register_reserve_asset(
					RuntimeOrigin::root(),
					LOCAL_ASSET_ID,
					invalid_general_index,
				),
				Error::<Test>::WrongLocation
			);
		})
	}
}

mod unregister_reserve_asset {
	use super::*;

	#[test]
	fn unregister_reserve_asset_works() {
		new_test_ext().execute_with(|| {
			assert_ok!(AssetRegistry::register_reserve_asset(
				RuntimeOrigin::root(),
				LOCAL_ASSET_ID,
				asset_hub_asset_location(),
			));

			assert_ok!(AssetRegistry::unregister_reserve_asset(
				RuntimeOrigin::root(),
				LOCAL_ASSET_ID
			));

			assert!(AssetIdLocation::<Test>::get(LOCAL_ASSET_ID).is_none());
			assert!(AssetLocationId::<Test>::get(asset_hub_asset_location()).is_none());
		});
	}

	#[test]
	fn cannot_register_unregistered_asset() {
		new_test_ext().execute_with(|| {
			assert_noop!(
				AssetRegistry::unregister_reserve_asset(RuntimeOrigin::root(), LOCAL_ASSET_ID),
				Error::<Test>::AssetIsNotRegistered
			);
		});
	}
}
