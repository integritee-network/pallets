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
use crate::{mock::*, ExchangeRates};
use frame_support::{assert_err, assert_ok};
use pallet_teerex::Error;
use sp_runtime::DispatchError::BadOrigin;
use substrate_fixed::types::U32F32;
use test_utils::ias::consts::{
	TEST4_CERT, TEST4_MRENCLAVE, TEST4_SIGNER_PUB, TEST4_TIMESTAMP, TEST5_MRENCLAVE,
	TEST5_SIGNER_PUB, TEST8_MRENCLAVE, URL,
};

// give get_signer a concrete type
fn get_signer(pubkey: &[u8; 32]) -> AccountId {
	test_utils::get_signer(pubkey)
}

fn register_enclave_and_add_oracle_to_whitelist_ok() {
	Timestamp::set_timestamp(TEST4_TIMESTAMP);
	let signer = get_signer(TEST4_SIGNER_PUB);
	assert_ok!(Teerex::register_enclave(
		Origin::signed(signer.clone()),
		TEST4_CERT.to_vec(),
		URL.to_vec()
	));
	let mrenclave = Teerex::enclave(1).mr_enclave;
	assert_ok!(Exchange::add_to_whitelist(Origin::root(), mrenclave));
}

fn update_exchange_rate_for_dollars_ok(rate: Option<U32F32>) {
	let signer = get_signer(TEST4_SIGNER_PUB);
	assert_ok!(Exchange::update_exchange_rate(
		Origin::signed(signer),
		"usd".as_bytes().to_owned(),
		rate
	));
}

#[test]
fn verifiy_update_exchange_rate_works() {
	new_test_ext().execute_with(|| {
		register_enclave_and_add_oracle_to_whitelist_ok();

		let rate = U32F32::from_num(43.65);
		update_exchange_rate_for_dollars_ok(Some(rate));
		let expected_event = Event::Exchange(crate::Event::ExchangeRateUpdated(
			"usd".as_bytes().to_owned(),
			Some(rate),
		));
		assert!(System::events().iter().any(|a| a.event == expected_event));
		assert_eq!(Exchange::exchange_rate("usd".as_bytes().to_owned()), rate);

		let rate2 = U32F32::from_num(4294967295.65);
		update_exchange_rate_for_dollars_ok(Some(rate2));
		assert_eq!(Exchange::exchange_rate("usd".as_bytes().to_owned()), rate2);
	})
}

#[test]
fn verifiy_get_existing_exchange_rate_works() {
	new_test_ext().execute_with(|| {
		let rate = U32F32::from_num(43.65);
		register_enclave_and_add_oracle_to_whitelist_ok();
		update_exchange_rate_for_dollars_ok(Some(rate));
		assert_eq!(Exchange::exchange_rate("usd".as_bytes().to_owned()), rate);
	})
}

#[test]
fn verifiy_get_inexisting_exchange_rate_is_zero() {
	new_test_ext().execute_with(|| {
		assert_eq!(ExchangeRates::<Test>::contains_key("eur".as_bytes().to_owned()), false);
		assert_eq!(Exchange::exchange_rate("eur".as_bytes().to_owned()), U32F32::from_num(0));
	})
}

#[test]
fn verifiy_update_exchange_rate_to_none_delete_exchange_rate() {
	new_test_ext().execute_with(|| {
		register_enclave_and_add_oracle_to_whitelist_ok();
		let rate = U32F32::from_num(43.65);
		update_exchange_rate_for_dollars_ok(Some(rate));

		update_exchange_rate_for_dollars_ok(None);

		let expected_event =
			Event::Exchange(crate::Event::ExchangeRateDeleted("usd".as_bytes().to_owned()));
		assert!(System::events().iter().any(|a| a.event == expected_event));
		assert_eq!(ExchangeRates::<Test>::contains_key("usd".as_bytes().to_owned()), false);
	})
}

#[test]
fn verifiy_update_exchange_rate_to_zero_delete_exchange_rate() {
	new_test_ext().execute_with(|| {
		register_enclave_and_add_oracle_to_whitelist_ok();
		let rate = Some(U32F32::from_num(43.65));
		update_exchange_rate_for_dollars_ok(rate);

		update_exchange_rate_for_dollars_ok(Some(U32F32::from_num(0)));

		let expected_event =
			Event::Exchange(crate::Event::ExchangeRateDeleted("usd".as_bytes().to_owned()));
		assert!(System::events().iter().any(|a| a.event == expected_event));
		assert_eq!(ExchangeRates::<Test>::contains_key("usd".as_bytes().to_owned()), false);
	})
}

#[test]
fn verifiy_update_exchange_rate_from_not_registered_enclave_fails() {
	new_test_ext().execute_with(|| {
		let signer = get_signer(TEST4_SIGNER_PUB);
		let rate = U32F32::from_num(43.65);
		assert_err!(
			Exchange::update_exchange_rate(
				Origin::signed(signer),
				"usd".as_bytes().to_owned(),
				Some(rate)
			),
			Error::<Test>::EnclaveIsNotRegistered
		);
	})
}

#[test]
fn verifiy_update_exchange_rate_from_not_whitelisted_oracle_fails() {
	new_test_ext().execute_with(|| {
		Timestamp::set_timestamp(TEST4_TIMESTAMP);
		let signer = get_signer(TEST4_SIGNER_PUB);
		assert_ok!(Teerex::register_enclave(
			Origin::signed(signer.clone()),
			TEST4_CERT.to_vec(),
			URL.to_vec()
		));

		let rate = U32F32::from_num(43.65);
		assert_err!(
			Exchange::update_exchange_rate(
				Origin::signed(signer),
				"usd".as_bytes().to_owned(),
				Some(rate)
			),
			crate::Error::<Test>::UntrustedOracle
		);
	})
}

#[test]
fn verifiy_add_to_whitelist_works() {
	new_test_ext().execute_with(|| {
		assert_ok!(Exchange::add_to_whitelist(Origin::root(), TEST4_MRENCLAVE));
		let expected_event = Event::Exchange(crate::Event::AddedToWhitelist(TEST4_MRENCLAVE));
		assert!(System::events().iter().any(|a| a.event == expected_event));
		assert_eq!(Exchange::whitelisted_oracle_count(), 1);
	})
}

#[test]
fn verifiy_add_two_times_to_whitelist_fails() {
	new_test_ext().execute_with(|| {
		assert_ok!(Exchange::add_to_whitelist(Origin::root(), TEST4_MRENCLAVE));
		assert_err!(
			Exchange::add_to_whitelist(Origin::root(), TEST4_MRENCLAVE),
			crate::Error::<Test>::AlreadyWhitelistedOracle
		);
		assert_eq!(Exchange::whitelisted_oracle_count(), 1);
	})
}

#[test]
fn verifiy_add_too_many_oracles_to_whitelist_fails() {
	new_test_ext().execute_with(|| {
		assert_ok!(Exchange::add_to_whitelist(Origin::root(), TEST4_MRENCLAVE));
		assert_ok!(Exchange::add_to_whitelist(Origin::root(), TEST5_MRENCLAVE));
		assert_err!(
			Exchange::add_to_whitelist(Origin::root(), TEST8_MRENCLAVE),
			crate::Error::<Test>::TooManyOracles
		);
		assert_eq!(Exchange::whitelisted_oracle_count(), 2);
	})
}

#[test]
fn verifiy_non_root_add_to_whitelist_fails() {
	new_test_ext().execute_with(|| {
		let signer = get_signer(TEST5_SIGNER_PUB);
		assert_err!(Exchange::add_to_whitelist(Origin::signed(signer), TEST4_MRENCLAVE), BadOrigin);
		assert_eq!(Exchange::whitelisted_oracle_count(), 0);
	})
}

#[test]
fn verifiy_remove_from_whitelist_works() {
	new_test_ext().execute_with(|| {
		assert_ok!(Exchange::add_to_whitelist(Origin::root(), TEST4_MRENCLAVE));
		assert_ok!(Exchange::remove_from_whitelist(Origin::root(), TEST4_MRENCLAVE));
		let expected_event = Event::Exchange(crate::Event::RemovedFromWhitelist(TEST4_MRENCLAVE));
		assert!(System::events().iter().any(|a| a.event == expected_event));
		assert_eq!(Exchange::whitelisted_oracle_count(), 0);
	})
}

#[test]
fn verifiy_remove_from_whitelist_not_whitelisted_fails() {
	new_test_ext().execute_with(|| {
		assert_ok!(Exchange::add_to_whitelist(Origin::root(), TEST4_MRENCLAVE));
		assert_err!(
			Exchange::remove_from_whitelist(Origin::root(), TEST5_MRENCLAVE),
			crate::Error::<Test>::NonWhitelistedOracle
		);
		assert_eq!(Exchange::whitelisted_oracle_count(), 1);
	})
}

#[test]
fn verifiy_remove_from_empty_whitelist_doesnt_crash() {
	new_test_ext().execute_with(|| {
		assert_eq!(Exchange::whitelisted_oracle_count(), 0);
		assert_err!(
			Exchange::remove_from_whitelist(Origin::root(), TEST5_MRENCLAVE),
			crate::Error::<Test>::NonWhitelistedOracle
		);
		assert_eq!(Exchange::whitelisted_oracle_count(), 0);
	})
}

#[test]
fn verifiy_non_root_remove_from_whitelist_fails() {
	new_test_ext().execute_with(|| {
		let signer = get_signer(TEST5_SIGNER_PUB);
		assert_ok!(Exchange::add_to_whitelist(Origin::root(), TEST4_MRENCLAVE));
		assert_err!(
			Exchange::remove_from_whitelist(Origin::signed(signer), TEST4_MRENCLAVE),
			BadOrigin
		);
		assert_eq!(Exchange::whitelisted_oracle_count(), 1);
	})
}

#[test]
fn verifiy_clear_whitelist_works() {
	new_test_ext().execute_with(|| {
		let signer = get_signer(TEST5_SIGNER_PUB);
		assert_ok!(Exchange::add_to_whitelist(Origin::root(), TEST4_MRENCLAVE));
		assert_ok!(Exchange::add_to_whitelist(Origin::root(), TEST5_MRENCLAVE));
		assert_eq!(Exchange::whitelisted_oracle_count(), 2);

		assert_ok!(Exchange::clear_whitelist(Origin::root()));
		let expected_event = Event::Exchange(crate::Event::OracleWhitelistCleared);
		assert!(System::events().iter().any(|a| a.event == expected_event));
		assert_eq!(Exchange::whitelisted_oracle_count(), 0);
	})
}

#[test]
fn verifiy_non_root_clear_whitelist_fails() {
	new_test_ext().execute_with(|| {
		let signer = get_signer(TEST5_SIGNER_PUB);
		assert_ok!(Exchange::add_to_whitelist(Origin::root(), TEST4_MRENCLAVE));
		assert_err!(Exchange::clear_whitelist(Origin::signed(signer)), BadOrigin);
		assert_eq!(Exchange::whitelisted_oracle_count(), 1);
	})
}
