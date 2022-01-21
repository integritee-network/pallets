use crate::{mock::*, Enclave, EnclaveRegistry};
use frame_support::{assert_ok, StorageMap};
use sp_keyring::AccountKeyring;
use test_utils::ias::{
	consts::{TEST4_MRENCLAVE, URL},
	TestEnclave,
};

fn now() -> u64 {
	<timestamp::Pallet<Test>>::get()
}

fn test_enclave() -> Enclave<AccountId, Vec<u8>> {
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

#[test]
fn confirm_processed_parentchain_block_ok() {
	new_test_ext().execute_with(|| {
		Timestamp::set_timestamp(TEST7_TIMESTAMP);
		let block_hash = system::pallet::BlockHash::<Test>::get(0);
		let merkle_root = H256::default();
		let signer7 = get_signer(TEST7_SIGNER_PUB);
		assert_ok!(Teerex::register_enclave(
			Origin::signed(signer7.clone()),
			TEST7_CERT.to_vec(),
			URL.to_vec(),
		));
		assert_eq!(Teerex::enclave_count(), 1);

		assert_ok!(Teerex::confirm_processed_parentchain_block(
			Origin::signed(signer7.clone()),
			block_hash.clone(),
			merkle_root.clone(),
		));
	})
}

#[test]
fn confirm_processed_parentchain_block_bad_hash_error() {
	new_test_ext().execute_with(|| {
		Timestamp::set_timestamp(TEST7_TIMESTAMP);
		let block_hash = H256::default();
		let merkle_root = H256::default();
		let signer7 = get_signer(TEST7_SIGNER_PUB);
		assert_ok!(Teerex::register_enclave(
			Origin::signed(signer7.clone()),
			TEST7_CERT.to_vec(),
			URL.to_vec(),
		));
		assert_eq!(Teerex::enclave_count(), 1);

		// should fail because block_hash is invalid
		assert_err!(Teerex::confirm_processed_parentchain_block(
			Origin::signed(signer7.clone()),
			block_hash.clone(),
			merkle_root.clone(),
		));
	})
}
