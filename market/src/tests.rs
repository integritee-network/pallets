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
use frame_support::assert_ok;
use substrate_fixed::types::U32F32;

fn verifiy_update_exchange_rate_for_dollars(rate: U32F32) {
	assert_ok!(Exchange::update_exchange_rate(
		Origin::signed(100),
		"usd".as_bytes().to_owned(),
		Some(rate)
	));
	let expected_event =
		Event::Exchange(crate::Event::ExchangeRateUpdated("usd".as_bytes().to_owned(), Some(rate)));
	assert!(System::events().iter().any(|a| a.event == expected_event));
}

#[test]
fn verifiy_update_exchange_rate_works() {
	new_test_ext().execute_with(|| {
		let rate = U32F32::from_num(43.65);
		verifiy_update_exchange_rate_for_dollars(rate);
		assert_eq!(Exchange::exchange_rate("usd".as_bytes().to_owned()), rate);
		let rate2 = U32F32::from_num(4294967295.65);
		verifiy_update_exchange_rate_for_dollars(rate2);
		assert_eq!(Exchange::exchange_rate("usd".as_bytes().to_owned()), rate2);
	})
}

#[test]
fn verifiy_get_existing_exchange_rate_works() {
	new_test_ext().execute_with(|| {
		let rate = U32F32::from_num(43.65);
		verifiy_update_exchange_rate_for_dollars(rate);
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
		let rate = U32F32::from_num(43.65);
		verifiy_update_exchange_rate_for_dollars(rate);
		assert_ok!(Exchange::update_exchange_rate(
			Origin::signed(100),
			"usd".as_bytes().to_owned(),
			None
		));
		let expected_event =
			Event::Exchange(crate::Event::ExchangeRateDeleted("usd".as_bytes().to_owned()));
		assert!(System::events().iter().any(|a| a.event == expected_event));
		assert_eq!(ExchangeRates::<Test>::contains_key("usd".as_bytes().to_owned()), false);
	})
}

#[test]
fn verifiy_update_exchange_rate_to_zero_delete_exchange_rate() {
	new_test_ext().execute_with(|| {
		let rate = U32F32::from_num(43.65);
		let key = "usd".as_bytes().to_owned();
		verifiy_update_exchange_rate_for_dollars(rate);
		assert_ok!(Exchange::update_exchange_rate(
			Origin::signed(100),
			key.clone(),
			Some(U32F32::from_num(0))
		));
		let expected_event = Event::Exchange(crate::Event::ExchangeRateDeleted(key.clone()));
		assert!(System::events().iter().any(|a| a.event == expected_event));
		assert_eq!(ExchangeRates::<Test>::contains_key(key), false);
	})
}
