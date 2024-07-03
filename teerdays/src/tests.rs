use crate::{mock::*, BalanceOf, Event as TeerDaysEvent};
use frame_support::assert_ok;
use sp_keyring::AccountKeyring;
#[test]
fn bonding_works() {
	new_test_ext().execute_with(|| {
		let now: Moment = 42;
		pallet_timestamp::Pallet::<Test>::set(RuntimeOrigin::none(), now)
			.expect("set timestamp should work");
		let alice = AccountKeyring::Alice.to_account_id();
		let amount: BalanceOf<Test> = 10_000_000_000_000;
		assert_ok!(TeerDays::bond(RuntimeOrigin::signed(alice.clone()), amount));

		let expected_event =
			RuntimeEvent::TeerDays(TeerDaysEvent::Bonded { account: alice.clone(), amount });
		assert!(System::events().iter().any(|a| a.event == expected_event));

		let teerdays =
			TeerDays::teerdays(&alice).expect("TeerDays entry for bonded account should exist");
		assert_eq!(teerdays.bond, amount);
		assert_eq!(teerdays.accumulated_teerdays, 0);
		assert_eq!(teerdays.last_updated, now);
	})
}
