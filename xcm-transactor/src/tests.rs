use crate::{mock::*, Error, Event, Config};
use cumulus_primitives_core::ParaId;
use sp_keyring::AccountKeyring;
use frame_support::{assert_err, assert_noop, assert_ok};

#[test]
fn swap_ump_fails_not_privileged() {
    new_test_ext().execute_with(|| {
        let alice = AccountKeyring::Alice.to_account_id();
        assert_noop!(
            XcmTransactor::send_swap_ump(RuntimeOrigin::signed(alice), ParaId::from(2015), ParaId::from(2014)),
            sp_runtime::DispatchError::BadOrigin
        );
    })
}

#[test]
fn swap_ump_fails_equal_para_ids() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            XcmTransactor::send_swap_ump(RuntimeOrigin::root(), ParaId::from(2015), ParaId::from(2015)),
            Error::<Test>::SwapIdsEqual
        );
    })
}

#[test]
fn swap_ump_fails_1_id_invalid() {
    new_test_ext().execute_with(|| {
        let shell_id = <Test as Config>::ShellRuntimeParaId::get();
        assert_noop!(
            XcmTransactor::send_swap_ump(RuntimeOrigin::root(), shell_id, ParaId::from(20000)),
            Error::<Test>::InvalidSwapIds
        );
    })
}