use crate::{mock::*, BalanceOf, Event as TeerDaysEvent};
use frame_support::{
	assert_ok,
	traits::{OnFinalize, OnInitialize},
};
use sp_keyring::AccountKeyring;
use sp_runtime::Saturating;

pub fn run_to_block(n: u32) {
	while System::block_number() < n {
		if System::block_number() > 1 {
			System::on_finalize(System::block_number());
		}
		Timestamp::on_finalize(System::block_number());
		System::set_block_number(System::block_number() + 1);
		System::on_initialize(System::block_number());
	}
}

pub fn set_timestamp(t: u64) {
	let _ = pallet_timestamp::Pallet::<Test>::set(RuntimeOrigin::none(), t);
}

#[test]
fn bonding_works() {
	new_test_ext().execute_with(|| {
		let now: Moment = 42;
		set_timestamp(now);
		let alice = AccountKeyring::Alice.to_account_id();
		let amount: BalanceOf<Test> = 10_000_000_000_000;
		assert_ok!(TeerDays::bond(RuntimeOrigin::signed(alice.clone()), amount));

		let expected_event =
			RuntimeEvent::TeerDays(TeerDaysEvent::Bonded { account: alice.clone(), amount });
		assert!(System::events().iter().any(|a| a.event == expected_event));

		let teerdays = TeerDays::teerday_bonds(&alice)
			.expect("TeerDays entry for bonded account should exist");
		assert_eq!(teerdays.bond, amount);
		assert_eq!(teerdays.accumulated_tokentime, 0);
		assert_eq!(teerdays.last_updated, now);

		let account_info = System::account(&alice);
		assert_eq!(account_info.consumers, 2);
		assert_eq!(account_info.data.frozen, amount);
	})
}
#[test]
fn unbonding_works() {
	new_test_ext().execute_with(|| {
		run_to_block(1);
		let now: Moment = 42;
		set_timestamp(now);
		let alice = AccountKeyring::Alice.to_account_id();
		let amount: BalanceOf<Test> = 10_000_000_000_000;
		assert_ok!(TeerDays::bond(RuntimeOrigin::signed(alice.clone()), amount));

		run_to_block(2);
		let now = now + MomentsPerDay::get();
		set_timestamp(now);

		let tokentime_accumulated = amount.saturating_mul(MomentsPerDay::get() as Balance);

		let unbond_amount = amount / 3;
		assert_ok!(TeerDays::unbond(RuntimeOrigin::signed(alice.clone()), unbond_amount));

		let expected_event = RuntimeEvent::TeerDays(TeerDaysEvent::Unbonded {
			account: alice.clone(),
			amount: unbond_amount,
		});
		assert!(System::events().iter().any(|a| a.event == expected_event));

		let teerdays = TeerDays::teerday_bonds(&alice)
			.expect("TeerDays entry for bonded account should exist");
		assert_eq!(teerdays.bond, amount - unbond_amount);
		assert_eq!(
			teerdays.accumulated_tokentime,
			tokentime_accumulated.saturating_mul(amount - unbond_amount) / amount
		);

		let account_info = System::account(&alice);
		assert_eq!(account_info.consumers, 2);
		assert_eq!(account_info.data.frozen, amount - unbond_amount);
	})
}

#[test]
fn update_other_works() {
	new_test_ext().execute_with(|| {
		run_to_block(1);
		let now: Moment = 42;
		set_timestamp(now);
		let alice = AccountKeyring::Alice.to_account_id();
		let amount: BalanceOf<Test> = 10_000_000_000_000;
		assert_ok!(TeerDays::bond(RuntimeOrigin::signed(alice.clone()), amount));

		run_to_block(2);

		let now = now + MomentsPerDay::get();
		set_timestamp(now);

		assert_ok!(TeerDays::update_other(RuntimeOrigin::signed(alice.clone()), alice.clone()));

		let teerdays = TeerDays::teerday_bonds(&alice)
			.expect("TeerDays entry for bonded account should exist");
		assert_eq!(teerdays.bond, amount);
		assert_eq!(teerdays.last_updated, now);
		assert_eq!(
			teerdays.accumulated_tokentime,
			amount.saturating_mul(MomentsPerDay::get() as Balance)
		);
	})
}
