use crate::{mock::*, pallet, BalanceOf, Event as PorteerEvent, *};
use frame_support::{assert_noop, assert_ok, pallet_prelude::Hooks, traits::Currency};
use sp_keyring::Sr25519Keyring as Keyring;
use sp_runtime::{
	DispatchError::{BadOrigin, Token},
	TokenError::FundsUnavailable,
};

#[test]
fn set_porteer_config_works() {
	new_test_ext().execute_with(|| {
		let alice = Keyring::Alice.to_account_id();

		assert_eq!(
			PorteerConfigValue::<Test>::get(),
			PorteerConfig { send_enabled: true, receive_enabled: true }
		);

		let config = PorteerConfig { send_enabled: false, receive_enabled: true };
		assert_ok!(Porteer::set_porteer_config(RuntimeOrigin::signed(alice.clone()), config));

		let expected_event =
			RuntimeEvent::Porteer(PorteerEvent::PorteerConfigSet { value: config });
		assert!(System::events().iter().any(|a| a.event == expected_event));

		assert_eq!(PorteerConfigValue::<Test>::get(), config);
	})
}

#[test]
fn set_porteer_config_errs_when_missing_privileges() {
	new_test_ext().execute_with(|| {
		let bob = Keyring::Bob.to_account_id();

		let config = PorteerConfig { send_enabled: true, receive_enabled: true };
		assert_noop!(
			Porteer::set_porteer_config(RuntimeOrigin::signed(bob.clone()), config),
			BadOrigin
		);
	})
}

#[test]
fn set_watchdog_works() {
	new_test_ext().execute_with(|| {
		let alice = Keyring::Alice.to_account_id();
		let bob = Keyring::Bob.to_account_id();

		assert_eq!(WatchdogAccount::<Test>::get(), None);

		assert_ok!(Porteer::set_watchdog(RuntimeOrigin::signed(alice.clone()), bob.clone()));

		let expected_event =
			RuntimeEvent::Porteer(PorteerEvent::WatchdogSet { account: bob.clone() });
		assert!(System::events().iter().any(|a| a.event == expected_event));

		assert_eq!(WatchdogAccount::<Test>::get(), Some(bob));
	})
}

#[test]
fn set_watchdog_errs_when_missing_privileges() {
	new_test_ext().execute_with(|| {
		let bob = Keyring::Bob.to_account_id();
		let charlie = Keyring::Charlie.to_account_id();

		assert_noop!(Porteer::set_watchdog(RuntimeOrigin::signed(bob.clone()), charlie), BadOrigin);
	})
}

#[test]
fn watchdog_heartbeat_works() {
	new_test_ext().execute_with(|| {
		let alice = Keyring::Alice.to_account_id();
		let bob = Keyring::Bob.to_account_id();

		assert_ok!(Porteer::set_watchdog(RuntimeOrigin::signed(alice.clone()), bob.clone()));

		assert_eq!(LastHeartBeat::<Test>::get(), 0);
		let current_block = System::block_number();

		assert_ok!(Porteer::watchdog_heartbeat(RuntimeOrigin::signed(bob.clone())));

		let expected_event = RuntimeEvent::Porteer(PorteerEvent::WatchdogHeartBeatReceived);
		assert!(System::events().iter().any(|a| a.event == expected_event));
		assert_eq!(LastHeartBeat::<Test>::get(), current_block);
	})
}

#[test]
fn watchdog_heartbeat_errs_when_no_watchdog_is_set() {
	new_test_ext().execute_with(|| {
		let alice = Keyring::Alice.to_account_id();
		let bob = Keyring::Bob.to_account_id();

		assert_ok!(Porteer::set_watchdog(RuntimeOrigin::signed(alice.clone()), alice.clone()));

		assert_noop!(
			Porteer::watchdog_heartbeat(RuntimeOrigin::signed(bob.clone())),
			Error::<Test>::InvalidWatchdogAccount
		);
	})
}

#[test]
fn watchdog_heartbeat_errs_with_missing_privileges() {
	new_test_ext().execute_with(|| {
		let bob = Keyring::Bob.to_account_id();

		assert_noop!(
			Porteer::watchdog_heartbeat(RuntimeOrigin::signed(bob.clone())),
			Error::<Test>::InvalidWatchdogAccount
		);
	})
}

#[test]
fn bridge_stays_enabled_at_heartbeat_timeout_threshold() {
	new_test_ext().execute_with(|| {
		let current_block = System::block_number();
		LastHeartBeat::<Test>::set(current_block);
		assert_eq!(LastHeartBeat::<Test>::get(), current_block);

		Porteer::on_initialize(current_block + HeartBeatTimeout::get());

		let unexpected_event = RuntimeEvent::Porteer(PorteerEvent::BridgeDisabled);
		assert!(!System::events().iter().any(|a| a.event == unexpected_event));
	})
}

#[test]
fn bridge_is_disabled_after_timeout_threshold() {
	new_test_ext().execute_with(|| {
		let current_block = System::block_number();
		LastHeartBeat::<Test>::set(current_block);
		assert_eq!(LastHeartBeat::<Test>::get(), current_block);

		Porteer::on_initialize(current_block + HeartBeatTimeout::get() + 1);

		let expected_event = RuntimeEvent::Porteer(PorteerEvent::BridgeDisabled);
		assert!(System::events().iter().any(|a| a.event == expected_event));
	})
}

#[test]
fn set_xcm_fee_params_works() {
	new_test_ext().execute_with(|| {
		let alice = Keyring::Alice.to_account_id();

		assert_eq!(XcmFeeConfig::<Test>::get(), XcmFeeParams::default());

		let new_fee_params = XcmFeeParams { hop1: 1, hop2: 2, hop3: 3 };
		assert_ok!(Porteer::set_xcm_fee_params(
			RuntimeOrigin::signed(alice.clone()),
			new_fee_params
		));

		let expected_event =
			RuntimeEvent::Porteer(PorteerEvent::XcmFeeConfigSet { fees: new_fee_params });
		assert!(System::events().iter().any(|a| a.event == expected_event));

		assert_eq!(XcmFeeConfig::<Test>::get(), new_fee_params);
	})
}

#[test]
fn add_location_to_whitelist_works() {
	new_test_ext().execute_with(|| {
		let alice = Keyring::Alice.to_account_id();

		let location = WHITELISTED_LOCATION;
		assert_ok!(Porteer::add_location_to_whitelist(
			RuntimeOrigin::signed(alice.clone()),
			location
		));

		let expected_event =
			RuntimeEvent::Porteer(PorteerEvent::AddedLocationToWhitelist { location });
		assert!(System::events().iter().any(|a| a.event == expected_event));

		assert!(ForwardLocationWhitelist::<Test>::contains_key(location));
	})
}

#[test]
fn add_location_to_whitelist_errs_with_missing_privileges() {
	new_test_ext().execute_with(|| {
		let bob = Keyring::Bob.to_account_id();

		let location = WHITELISTED_LOCATION;
		assert_noop!(
			Porteer::add_location_to_whitelist(RuntimeOrigin::signed(bob.clone()), location),
			BadOrigin
		);
	})
}

#[test]
fn add_location_to_whitelist_errs_with_already_existing_location() {
	new_test_ext().execute_with(|| {
		let alice = Keyring::Alice.to_account_id();

		let location = WHITELISTED_LOCATION;
		ForwardLocationWhitelist::<Test>::insert(location, ());

		assert_noop!(
			Porteer::add_location_to_whitelist(RuntimeOrigin::signed(alice.clone()), location),
			Error::<Test>::LocationAlreadyInWhitelist
		);
	})
}

#[test]
fn remove_location_from_whitelist_works() {
	new_test_ext().execute_with(|| {
		let alice = Keyring::Alice.to_account_id();

		let location = WHITELISTED_LOCATION;
		ForwardLocationWhitelist::<Test>::insert(location, ());

		assert_ok!(Porteer::remove_location_from_whitelist(
			RuntimeOrigin::signed(alice.clone()),
			location
		));

		let expected_event =
			RuntimeEvent::Porteer(PorteerEvent::RemovedLocationFromWhitelist { location });
		assert!(System::events().iter().any(|a| a.event == expected_event));

		assert!(!ForwardLocationWhitelist::<Test>::contains_key(location));
	})
}

#[test]
fn remove_location_from_whitelist_errs_with_missing_privileges() {
	new_test_ext().execute_with(|| {
		let bob = Keyring::Bob.to_account_id();

		let location = WHITELISTED_LOCATION;
		assert_noop!(
			Porteer::remove_location_from_whitelist(RuntimeOrigin::signed(bob.clone()), location),
			BadOrigin
		);
	})
}

#[test]
fn remove_location_from_whitelist_errs_with_nonexistent_location() {
	new_test_ext().execute_with(|| {
		let alice = Keyring::Alice.to_account_id();

		let location = WHITELISTED_LOCATION;

		assert_noop!(
			Porteer::remove_location_from_whitelist(RuntimeOrigin::signed(alice.clone()), location),
			Error::<Test>::LocationNotInWhitelist
		);
	})
}

#[test]
fn port_tokens_works() {
	new_test_ext().execute_with(|| {
		let alice = Keyring::Alice.to_account_id();
		let alice_free: BalanceOf<Test> = 15_000_000_000_000u128;
		<Test as pallet::Config>::Fungible::make_free_balance_be(&alice, alice_free);

		assert_ok!(Porteer::port_tokens(RuntimeOrigin::signed(alice.clone()), alice_free, None));

		let expected_event = RuntimeEvent::Porteer(PorteerEvent::PortedTokens {
			who: alice.clone(),
			amount: alice_free,
		});
		assert!(System::events().iter().any(|a| a.event == expected_event));

		assert_eq!(Balances::free_balance(alice), 0);
	})
}

#[test]
fn port_tokens_errs_when_sending_disabled() {
	new_test_ext().execute_with(|| {
		let alice = Keyring::Alice.to_account_id();

		let config = PorteerConfig { send_enabled: false, receive_enabled: true };
		assert_ok!(Porteer::set_porteer_config(RuntimeOrigin::signed(alice.clone()), config));

		assert_noop!(
			Porteer::port_tokens(RuntimeOrigin::signed(alice.clone()), 1, None),
			Error::<Test>::PorteerOperationDisabled
		);
	})
}

#[test]
fn port_tokens_errs_when_missing_funds() {
	new_test_ext().execute_with(|| {
		let alice = Keyring::Bob.to_account_id();
		let alice_free: BalanceOf<Test> = 15_000_000_000_000u128;
		<Test as pallet::Config>::Fungible::make_free_balance_be(&alice, alice_free);

		assert_noop!(
			Porteer::port_tokens(RuntimeOrigin::signed(alice.clone()), alice_free + 1, None),
			Token(FundsUnavailable)
		);
	})
}

#[test]
fn minting_ported_tokens_works() {
	new_test_ext().execute_with(|| {
		let alice = Keyring::Alice.to_account_id();
		let bob = Keyring::Bob.to_account_id();
		<Test as pallet::Config>::Fungible::make_free_balance_be(&bob, 0);
		let mint_amount: BalanceOf<Test> = 15_000_000_000_000u128;

		assert_ok!(Porteer::mint_ported_tokens(
			RuntimeOrigin::signed(alice.clone()),
			bob.clone(),
			mint_amount,
			None
		));

		let expected_event = RuntimeEvent::Porteer(PorteerEvent::MintedPortedTokens {
			who: bob.clone(),
			amount: mint_amount,
		});
		assert!(System::events().iter().any(|a| a.event == expected_event));

		assert_eq!(Balances::free_balance(&bob), mint_amount);
	})
}

#[test]
fn minting_ported_tokens_errs_with_wrong_origin() {
	new_test_ext().execute_with(|| {
		let bob = Keyring::Bob.to_account_id();

		assert_noop!(
			Porteer::mint_ported_tokens(RuntimeOrigin::signed(bob.clone()), bob, 1, None),
			BadOrigin
		);
	})
}

#[test]
fn minting_ported_tokens_errs_when_receiving_disabled() {
	new_test_ext().execute_with(|| {
		let alice = Keyring::Alice.to_account_id();

		let config = PorteerConfig { send_enabled: true, receive_enabled: false };
		assert_ok!(Porteer::set_porteer_config(RuntimeOrigin::signed(alice.clone()), config));

		assert_noop!(
			Porteer::mint_ported_tokens(RuntimeOrigin::signed(alice.clone()), alice, 1, None),
			Error::<Test>::PorteerOperationDisabled
		);
	})
}

#[test]
fn minting_ported_tokens_with_forwarding_works() {
	new_test_ext().execute_with(|| {
		let alice = Keyring::Alice.to_account_id();
		let bob = Keyring::Bob.to_account_id();
		<Test as pallet::Config>::Fungible::make_free_balance_be(&bob, 0);
		let ed = <Test as pallet::Config>::Fungible::minimum_balance();
		let mint_amount: BalanceOf<Test> = 15_000_000_000_000u128;

		assert_ok!(Porteer::add_location_to_whitelist(
			RuntimeOrigin::signed(alice.clone()),
			WHITELISTED_LOCATION
		));

		assert_ok!(Porteer::mint_ported_tokens(
			RuntimeOrigin::signed(alice.clone()),
			bob.clone(),
			mint_amount,
			Some(WHITELISTED_LOCATION)
		));

		// We keep 2 the ED during forwarding
		assert_eq!(Balances::free_balance(&bob), 2 * ed);
	})
}

#[test]
fn minting_ported_tokens_with_forwarding_non_whitelisted_location_preserves_balance() {
	// We want to test that the `#[transactional]` does indeed roll back the state
	// in case of a failed forward.
	new_test_ext().execute_with(|| {
		let alice = Keyring::Alice.to_account_id();
		let bob = Keyring::Bob.to_account_id();
		<Test as pallet::Config>::Fungible::make_free_balance_be(&bob, 0);
		let mint_amount: BalanceOf<Test> = 15_000_000_000_000u128;

		// Don't whitelist the location

		assert_ok!(Porteer::mint_ported_tokens(
			RuntimeOrigin::signed(alice.clone()),
			bob.clone(),
			mint_amount,
			Some(WHITELISTED_LOCATION)
		));

		let expected_event =
			RuntimeEvent::Porteer(PorteerEvent::TriedToForwardTokensToIllegalLocation {
				location: WHITELISTED_LOCATION,
			});
		assert!(System::events().iter().any(|a| a.event == expected_event));

		// Bob's balance should be unchanged as nothing has been forwarded.
		assert_eq!(Balances::free_balance(&bob), mint_amount);
	})
}

#[test]
fn minting_ported_tokens_with_forwarding_unsupported_location_preserves_balance() {
	// We want to test that the `#[transactional]` does indeed roll back the state
	// in case of a failed forward.
	new_test_ext().execute_with(|| {
		let alice = Keyring::Alice.to_account_id();
		let bob = Keyring::Bob.to_account_id();
		<Test as pallet::Config>::Fungible::make_free_balance_be(&bob, 0);
		let mint_amount: BalanceOf<Test> = 15_000_000_000_000u128;

		assert_ok!(Porteer::add_location_to_whitelist(
			RuntimeOrigin::signed(alice.clone()),
			WHITELISTED_BUT_UNSUPPORTED_LOCATION
		));

		assert_ok!(Porteer::mint_ported_tokens(
			RuntimeOrigin::signed(alice.clone()),
			bob.clone(),
			mint_amount,
			Some(WHITELISTED_BUT_UNSUPPORTED_LOCATION)
		));

		let expected_event = RuntimeEvent::Porteer(PorteerEvent::FailedToForwardTokens {
			who: bob.clone(),
			amount: mint_amount,
			location: WHITELISTED_BUT_UNSUPPORTED_LOCATION,
		});
		assert!(System::events().iter().any(|a| a.event == expected_event));

		// Bob's balance should be unchanged as nothing has been forwarded.
		assert_eq!(Balances::free_balance(&bob), mint_amount);
	})
}
