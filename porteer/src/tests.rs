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
	// This test tests the whole logic:
	// 1. Updating the heartbeat timeout works
	// 2. The bridge stays active within the timeout
	// 3. The sending side of the bridge is disabled after the timeout is reached.
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

		// Test that bridge stays enabled for the next block
		Porteer::on_initialize(current_block + 1);

		let unexpected_event = RuntimeEvent::Porteer(PorteerEvent::BridgeDisabled);
		assert!(!System::events().iter().any(|a| a.event == unexpected_event));

		assert_eq!(
			PorteerConfigValue::<Test>::get(),
			PorteerConfig { send_enabled: true, receive_enabled: true }
		);

		// Test that bridge stays enabled until the HeartbeatTimout
		Porteer::on_initialize(current_block + HeartBeatTimeout::get());

		let unexpected_event = RuntimeEvent::Porteer(PorteerEvent::BridgeDisabled);
		assert!(!System::events().iter().any(|a| a.event == unexpected_event));

		assert_eq!(
			PorteerConfigValue::<Test>::get(),
			PorteerConfig { send_enabled: true, receive_enabled: true }
		);

		// Bridge Send is disabled after HeartbeatTimeout has passed
		Porteer::on_initialize(current_block + HeartBeatTimeout::get() + 1);

		let expected_event = RuntimeEvent::Porteer(PorteerEvent::BridgeDisabled);
		assert!(System::events().iter().any(|a| a.event == expected_event));

		assert_eq!(
			PorteerConfigValue::<Test>::get(),
			PorteerConfig { send_enabled: false, receive_enabled: true }
		);
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

		assert_eq!(
			PorteerConfigValue::<Test>::get(),
			PorteerConfig { send_enabled: true, receive_enabled: true }
		);
	})
}

#[test]
fn bridge_send_is_disabled_after_timeout_threshold() {
	new_test_ext().execute_with(|| {
		let current_block = System::block_number();
		LastHeartBeat::<Test>::set(current_block);
		assert_eq!(LastHeartBeat::<Test>::get(), current_block);

		Porteer::on_initialize(current_block + HeartBeatTimeout::get() + 1);

		let expected_event = RuntimeEvent::Porteer(PorteerEvent::BridgeDisabled);
		assert!(System::events().iter().any(|a| a.event == expected_event));

		assert_eq!(
			PorteerConfigValue::<Test>::get(),
			PorteerConfig { send_enabled: false, receive_enabled: true }
		);
	})
}

#[test]
fn bridge_send_disabling_is_noop_if_already_disabled() {
	new_test_ext().execute_with(|| {
		let current_block = System::block_number();

		PorteerConfigValue::<Test>::set(PorteerConfig {
			send_enabled: false,
			receive_enabled: true,
		});
		LastHeartBeat::<Test>::set(current_block);
		assert_eq!(LastHeartBeat::<Test>::get(), current_block);

		Porteer::on_initialize(current_block + HeartBeatTimeout::get() + 1);

		let unexpected_event = RuntimeEvent::Porteer(PorteerEvent::BridgeDisabled);
		assert!(!System::events().iter().any(|a| a.event == unexpected_event));
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
fn port_tokens_works() {
	new_test_ext().execute_with(|| {
		let alice = Keyring::Alice.to_account_id();
		let alice_free: BalanceOf<Test> = 15_000_000_000_000u128;
		<Test as pallet::Config>::Fungible::make_free_balance_be(&alice, alice_free);

		assert_ok!(Porteer::port_tokens(RuntimeOrigin::signed(alice.clone()), alice_free));

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
			Porteer::port_tokens(RuntimeOrigin::signed(alice.clone()), 1),
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
			Porteer::port_tokens(RuntimeOrigin::signed(alice.clone()), alice_free + 1),
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
			mint_amount
		));

		assert_eq!(Balances::free_balance(&bob), mint_amount);
	})
}

#[test]
fn minting_ported_tokens_errs_with_wrong_origin() {
	new_test_ext().execute_with(|| {
		let bob = Keyring::Bob.to_account_id();

		assert_noop!(
			Porteer::mint_ported_tokens(RuntimeOrigin::signed(bob.clone()), bob, 1),
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
			Porteer::mint_ported_tokens(RuntimeOrigin::signed(alice.clone()), alice, 1),
			Error::<Test>::PorteerOperationDisabled
		);
	})
}
