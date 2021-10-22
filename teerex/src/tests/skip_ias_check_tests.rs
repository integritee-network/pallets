use crate::mock::*;
use crate::test_utils::consts::*;
use crate::{Enclave, EnclaveRegistry};
use frame_support::{assert_ok, StorageMap};
use sp_keyring::AccountKeyring;

type TestEnclave = Enclave<AccountId, Vec<u8>>;

fn now() -> u64 {
    <timestamp::Pallet<Test>>::get()
}

fn test_enclave() -> TestEnclave {
    Enclave::default()
        .with_pubkey(AccountKeyring::Alice.to_account_id())
        .with_timestamp(now())
        .with_url(URL.to_vec())
}

#[test]
fn register_enclave_with_empty_mrenclave_works() {
    new_test_ext().execute_with(|| {
        assert_ok!(Teerex::register_enclave(
            Origin::signed(AccountKeyring::Alice.to_account_id()),
            Vec::new(),
            URL.to_vec()
        ));

        assert_eq!(Teerex::enclave_count(), 1);
        assert_eq!(<EnclaveRegistry<Test>>::get(1), test_enclave());
    })
}

#[test]
fn register_enclave_with_mrenclave_works() {
    new_test_ext().execute_with(|| {
        assert_ok!(Teerex::register_enclave(
            Origin::signed(AccountKeyring::Alice.to_account_id()),
            TEST4_MRENCLAVE.to_vec(),
            URL.to_vec()
        ));

        let enc = test_enclave().with_mr_enclave(TEST4_MRENCLAVE);

        assert_eq!(Teerex::enclave_count(), 1);
        assert_eq!(<EnclaveRegistry<Test>>::get(1), enc);
    })
}

#[test]
fn register_enclave_with_faulty_mrenclave_inserts_default() {
    new_test_ext().execute_with(|| {
        assert_ok!(Teerex::register_enclave(
            Origin::signed(AccountKeyring::Alice.to_account_id()),
            [1u8, 2].to_vec(),
            URL.to_vec()
        ));

        assert_eq!(Teerex::enclave_count(), 1);
        assert_eq!(<EnclaveRegistry<Test>>::get(1), test_enclave());
    })
}

#[test]
fn register_enclave_with_empty_url_inserts_default() {
    new_test_ext().execute_with(|| {
        assert_ok!(Teerex::register_enclave(
            Origin::signed(AccountKeyring::Alice.to_account_id()),
            Vec::new(),
            Vec::new(),
        ));

        let enc = test_enclave().with_url(Default::default());

        assert_eq!(Teerex::enclave_count(), 1);
        assert_eq!(<EnclaveRegistry<Test>>::get(1), enc);
    })
}
