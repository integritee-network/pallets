use crate::{mock::*, pallet, BalanceOf, Event as PorteerEvent, *};
use frame_support::{assert_noop, assert_ok, traits::Currency};
use sp_keyring::Sr25519Keyring as Keyring;
use sp_runtime::{
	DispatchError::{BadOrigin, Token},
	TokenError::FundsUnavailable,
};

#[test]
fn set_bridge_config_works() {
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
fn set_bridge_config_errs_when_missing_privileges() {
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
