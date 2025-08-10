use crate::{mock::*, pallet, BalanceOf, Event as PorteerEvent, *};
use frame_support::{assert_noop, assert_ok, traits::Currency};
use sp_keyring::Sr25519Keyring as Keyring;
use sp_runtime::{
	DispatchError::{BadOrigin, Token},
	TokenError::FundsUnavailable,
};

#[test]
fn set_porteer_config_works() {
	new_test_ext().execute_with(|| {
		let alice = Keyring::Alice.to_account_id();

		let config = PorteerConfig { send_enabled: true, receive_enabled: true };
		assert_ok!(Porteer::set_porteer_config(RuntimeOrigin::signed(alice.clone()), config));

		let expected_event =
			RuntimeEvent::Porteer(PorteerEvent::PorteerConfigSet { value: config });
		assert!(System::events().iter().any(|a| a.event == expected_event));
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
