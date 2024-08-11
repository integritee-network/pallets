use crate::{mock::*, pallet, BalanceOf, Error, Event as TeerDaysEvent};
use frame_support::{
    assert_noop, assert_ok,
    traits::{Currency, OnFinalize, OnInitialize},
};
use sp_keyring::AccountKeyring;

pub fn run_to_block(n: u32) {
    while System::block_number() < n {
        if System::block_number() > 1 {
            System::on_finalize(System::block_number());
        }
        Timestamp::on_finalize(System::block_number());
        System::reset_events();
        System::set_block_number(System::block_number() + 1);
        System::on_initialize(System::block_number());
    }
}

pub fn set_timestamp(t: u64) {
    let _ = pallet_timestamp::Pallet::<Test>::set(RuntimeOrigin::none(), t);
}

#[test]
fn bond_works() {
    new_test_ext().execute_with(|| {
        let now: Moment = 42;
        set_timestamp(now);
        let alice = AccountKeyring::Alice.to_account_id();
        let alice_free: BalanceOf<Test> = 15_000_000_000_000;
        <Test as pallet::Config>::Currency::make_free_balance_be(&alice, alice_free);
        let amount: BalanceOf<Test> = 10_000_000_000_000;
        assert_ok!(TeerDays::bond(RuntimeOrigin::signed(alice.clone()), amount));

        let expected_event =
            RuntimeEvent::TeerDays(TeerDaysEvent::Bonded { account: alice.clone(), amount });
        assert!(System::events().iter().any(|a| a.event == expected_event));

        let teerdays = TeerDays::teerday_bonds(&alice)
            .expect("TeerDays entry for bonded account should exist");
        assert_eq!(teerdays.value, amount);
        assert_eq!(teerdays.accumulated_tokentime, 0);
        assert_eq!(teerdays.last_updated, now);

        let account_info = System::account(&alice);
        assert_eq!(account_info.consumers, 1);
        assert_eq!(account_info.data.frozen, amount);
    })
}

#[test]
fn bond_saturates_at_free() {
    new_test_ext().execute_with(|| {
        let now: Moment = 42;
        set_timestamp(now);
        let alice = AccountKeyring::Alice.to_account_id();
        let alice_free: BalanceOf<Test> = 5_000_000_000_000;
        <Test as pallet::Config>::Currency::make_free_balance_be(&alice, alice_free);
        let amount: BalanceOf<Test> = 10_000_000_000_000;
        assert_ok!(TeerDays::bond(RuntimeOrigin::signed(alice.clone()), amount));

        let expected_event = RuntimeEvent::TeerDays(TeerDaysEvent::Bonded {
            account: alice.clone(),
            amount: alice_free,
        });
        assert!(System::events().iter().any(|a| a.event == expected_event));

        let teerdays = TeerDays::teerday_bonds(&alice)
            .expect("TeerDays entry for bonded account should exist");
        assert_eq!(teerdays.value, alice_free);
        assert_eq!(teerdays.accumulated_tokentime, 0);
        assert_eq!(teerdays.last_updated, now);

        let account_info = System::account(&alice);
        assert_eq!(account_info.consumers, 1);
        assert_eq!(account_info.data.frozen, alice_free);
    })
}

#[test]
fn bond_extra_works() {
    new_test_ext().execute_with(|| {
        run_to_block(1);
        let now: Moment = 42;
        set_timestamp(now);

        let alice = AccountKeyring::Alice.to_account_id();
        let amount: BalanceOf<Test> = 10_000_000_000_000;
        assert_ok!(TeerDays::bond(RuntimeOrigin::signed(alice.clone()), amount));

        run_to_block(2);
        let now = now + 10_000;
        set_timestamp(now);

        let extra_amount = amount / 2;
        assert_ok!(TeerDays::bond_extra(RuntimeOrigin::signed(alice.clone()), extra_amount));

        let expected_event = RuntimeEvent::TeerDays(TeerDaysEvent::Bonded {
            account: alice.clone(),
            amount: extra_amount,
        });
        assert!(System::events().iter().any(|a| a.event == expected_event));

        let teerdays = TeerDays::teerday_bonds(&alice)
            .expect("TeerDays entry for bonded account should exist");
        assert_eq!(teerdays.value, amount + extra_amount);
        assert_eq!(teerdays.accumulated_tokentime, amount * 10_000);
        assert_eq!(teerdays.last_updated, now);

        let account_info = System::account(&alice);
        assert_eq!(account_info.data.frozen, amount + extra_amount);
    })
}

#[test]
fn bond_extra_saturates_at_free_margin() {
    new_test_ext().execute_with(|| {
        run_to_block(1);
        let now: Moment = 42;
        set_timestamp(now);

        let alice = AccountKeyring::Alice.to_account_id();
        let alice_free: BalanceOf<Test> = 11_000_000_000_000;
        <Test as pallet::Config>::Currency::make_free_balance_be(&alice, alice_free);
        let amount: BalanceOf<Test> = 10_000_000_000_000;
        assert_ok!(TeerDays::bond(RuntimeOrigin::signed(alice.clone()), amount));

        let teerdays = TeerDays::teerday_bonds(&alice)
            .expect("TeerDays entry for bonded account should exist");
        assert_eq!(teerdays.value, amount);
        assert_eq!(teerdays.accumulated_tokentime, 0);
        assert_eq!(teerdays.last_updated, now);

        let account_info = System::account(&alice);
        assert_eq!(account_info.consumers, 1);
        assert_eq!(account_info.data.frozen, amount);

        run_to_block(2);
        let now = now + 10_000;
        set_timestamp(now);

        let extra_amount = amount / 2;
        assert_ok!(TeerDays::bond_extra(RuntimeOrigin::signed(alice.clone()), extra_amount));

        let expected_event = RuntimeEvent::TeerDays(TeerDaysEvent::Bonded {
            account: alice.clone(),
            amount: 1_000_000_000_000,
        });
        assert_eq!(System::events().get(1).unwrap().event, expected_event);

        let teerdays = TeerDays::teerday_bonds(&alice)
            .expect("TeerDays entry for bonded account should exist");
        assert_eq!(teerdays.value, amount + 1_000_000_000_000);
        assert_eq!(teerdays.accumulated_tokentime, amount * 10_000);
        assert_eq!(teerdays.last_updated, now);

        let account_info = System::account(&alice);
        assert_eq!(account_info.data.frozen, amount + 1_000_000_000_000);
    })
}

#[test]
fn withdrawing_unbonded_after_unlock_period_works() {
    new_test_ext().execute_with(|| {
        run_to_block(1);
        let now: Moment = 42;
        set_timestamp(now);
        let alice = AccountKeyring::Alice.to_account_id();

        let account_info = System::account(&alice);
        assert_eq!(account_info.consumers, 0);
        assert_eq!(account_info.data.frozen, 0);

        let amount: BalanceOf<Test> = 10_000_000_000_000;
        assert_ok!(TeerDays::bond(RuntimeOrigin::signed(alice.clone()), amount));

        run_to_block(2);
        let now = now + UnlockPeriod::get();
        set_timestamp(now);

        let tokentime_accumulated = amount.saturating_mul(UnlockPeriod::get() as Balance);

        let unbond_amount = amount / 5;
        assert_ok!(TeerDays::unbond(RuntimeOrigin::signed(alice.clone()), unbond_amount));

        let expected_event = RuntimeEvent::TeerDays(TeerDaysEvent::Unbonded {
            account: alice.clone(),
            amount: unbond_amount,
            burned_tokentime: tokentime_accumulated / 5,
        });
        assert!(System::events().iter().any(|a| a.event == expected_event));

        let teerdays = TeerDays::teerday_bonds(&alice)
            .expect("TeerDays entry for bonded account should exist");
        assert_eq!(teerdays.value, amount - unbond_amount);
        // accumulated tokentime is reduced pro-rata
        assert_eq!(
            teerdays.accumulated_tokentime,
            tokentime_accumulated.saturating_mul(amount - unbond_amount) / amount
        );

        // can't unbond again
        assert_noop!(
			TeerDays::unbond(RuntimeOrigin::signed(alice.clone()), unbond_amount),
			Error::<Test>::PendingUnlock
		);
        // withdrawing not yet possible.
        assert_noop!(
			TeerDays::withdraw_unbonded(RuntimeOrigin::signed(alice.clone())),
			Error::<Test>::PendingUnlock
		);

        run_to_block(3);
        let now = now + UnlockPeriod::get();
        set_timestamp(now);
        assert_ok!(TeerDays::withdraw_unbonded(RuntimeOrigin::signed(alice.clone())));

        let account_info = System::account(&alice);
        assert_eq!(account_info.consumers, 1);
        assert_eq!(account_info.data.frozen, amount - unbond_amount);

        run_to_block(4);
        let now = now + UnlockPeriod::get();
        set_timestamp(now);

        // unbond more than we have -> should saturate
        assert_ok!(TeerDays::unbond(RuntimeOrigin::signed(alice.clone()), amount));
        assert!(TeerDays::teerday_bonds(&alice).is_none());

        run_to_block(5);
        let now = now + UnlockPeriod::get();
        set_timestamp(now);
        assert_ok!(TeerDays::withdraw_unbonded(RuntimeOrigin::signed(alice.clone())));

        let account_info = System::account(&alice);
        assert_eq!(account_info.consumers, 0);
        assert_eq!(account_info.data.frozen, 0);
    })
}

#[test]
fn unbonding_saturates_at_bonded() {
    new_test_ext().execute_with(|| {
        run_to_block(1);
        let now: Moment = 42;
        set_timestamp(now);
        let alice = AccountKeyring::Alice.to_account_id();

        let account_info = System::account(&alice);
        assert_eq!(account_info.consumers, 0);
        assert_eq!(account_info.data.frozen, 0);

        let amount: BalanceOf<Test> = 10_000_000_000_000;
        assert_ok!(TeerDays::bond(RuntimeOrigin::signed(alice.clone()), amount));

        let unbond_amount = amount * 2;
        assert_ok!(TeerDays::unbond(RuntimeOrigin::signed(alice.clone()), unbond_amount));

        let expected_event = RuntimeEvent::TeerDays(TeerDaysEvent::Unbonded {
            account: alice.clone(),
            amount,
            burned_tokentime: 0, //no time has elapsed
        });
        assert!(System::events().iter().any(|a| a.event == expected_event));
        assert!(TeerDays::teerday_bonds(&alice).is_none());
        assert_eq!(TeerDays::pending_unlock(&alice).unwrap().1, amount);
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

        let now = now + UnlockPeriod::get();
        set_timestamp(now);

        assert_ok!(TeerDays::update_other(RuntimeOrigin::signed(alice.clone()), alice.clone()));

        let teerdays = TeerDays::teerday_bonds(&alice)
            .expect("TeerDays entry for bonded account should exist");
        assert_eq!(teerdays.value, amount);
        assert_eq!(teerdays.last_updated, now);
        assert_eq!(
            teerdays.accumulated_tokentime,
            amount.saturating_mul(UnlockPeriod::get() as Balance)
        );
    })
}
