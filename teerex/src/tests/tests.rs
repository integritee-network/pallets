/*
    Copyright 2021 Integritee AG and Supercomputing Systems AG

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.

*/

//use super::*;
use crate::mock::*;
use crate::test_utils::consts::*;
use crate::{ConfirmedCalls, Enclave, EnclaveRegistry, Error, RawEvent, Request, ShardIdentifier};
use frame_support::{assert_err, assert_ok, IterableStorageMap, StorageMap};
use ias_verify::SgxBuildMode;
use sp_core::H256;
use sp_keyring::AccountKeyring;

fn list_enclaves() -> Vec<(u64, Enclave<AccountId, Vec<u8>>)> {
    <EnclaveRegistry<Test>>::iter().collect::<Vec<(u64, Enclave<AccountId, Vec<u8>>)>>()
}

// give get_signer a concrete type
fn get_signer(pubkey: &[u8; 32]) -> AccountId {
    crate::test_utils::get_signer(pubkey)
}

#[test]
fn add_enclave_works() {
    new_test_ext().execute_with(|| {
        // set the now in the runtime such that the remote attestation reports are within accepted range (24h)
        Timestamp::set_timestamp(TEST4_TIMESTAMP);
        let signer = get_signer(TEST4_SIGNER_PUB);
        assert_ok!(Teerex::register_enclave(
            Origin::signed(signer),
            TEST4_CERT.to_vec(),
            URL.to_vec()
        ));
        assert_eq!(Teerex::enclave_count(), 1);
    })
}

#[test]
fn add_and_remove_enclave_works() {
    new_test_ext().execute_with(|| {
        let _ = env_logger::init();
        Timestamp::set_timestamp(TEST4_TIMESTAMP);
        let signer = get_signer(TEST4_SIGNER_PUB);
        assert_ok!(Teerex::register_enclave(
            Origin::signed(signer.clone()),
            TEST4_CERT.to_vec(),
            URL.to_vec()
        ));
        assert_eq!(Teerex::enclave_count(), 1);
        assert_ok!(Teerex::unregister_enclave(Origin::signed(signer)));
        assert_eq!(Teerex::enclave_count(), 0);
        assert_eq!(list_enclaves(), vec![])
    })
}

#[test]
fn list_enclaves_works() {
    new_test_ext().execute_with(|| {
        Timestamp::set_timestamp(TEST4_TIMESTAMP);
        let signer = get_signer(TEST4_SIGNER_PUB);
        let e_1: Enclave<AccountId, Vec<u8>> = Enclave {
            pubkey: signer.clone(),
            mr_enclave: TEST4_MRENCLAVE,
            timestamp: TEST4_TIMESTAMP,
            url: URL.to_vec(),
            sgx_mode: SgxBuildMode::Debug,
        };
        assert_ok!(Teerex::register_enclave(
            Origin::signed(signer.clone()),
            TEST4_CERT.to_vec(),
            URL.to_vec(),
        ));
        assert_eq!(Teerex::enclave_count(), 1);
        let enclaves = list_enclaves();
        assert_eq!(enclaves[0].1.pubkey, signer);
        assert!(enclaves.contains(&(1, e_1.clone())));
    })
}

#[test]
fn remove_middle_enclave_works() {
    new_test_ext().execute_with(|| {
        // use the newest timestamp, is as now such that all reports are valid
        Timestamp::set_timestamp(TEST7_TIMESTAMP);

        let signer5 = get_signer(TEST5_SIGNER_PUB);
        let signer6 = get_signer(TEST6_SIGNER_PUB);
        let signer7 = get_signer(TEST7_SIGNER_PUB);

        // add enclave 1
        let e_1: Enclave<AccountId, Vec<u8>> = Enclave {
            pubkey: signer5.clone(),
            mr_enclave: TEST5_MRENCLAVE,
            timestamp: TEST5_TIMESTAMP,
            url: URL.to_vec(),
            sgx_mode: SgxBuildMode::Debug,
        };

        let e_2: Enclave<AccountId, Vec<u8>> = Enclave {
            pubkey: signer6.clone(),
            mr_enclave: TEST6_MRENCLAVE,
            timestamp: TEST6_TIMESTAMP,
            url: URL.to_vec(),
            sgx_mode: SgxBuildMode::Debug,
        };

        let e_3: Enclave<AccountId, Vec<u8>> = Enclave {
            pubkey: signer7.clone(),
            mr_enclave: TEST7_MRENCLAVE,
            timestamp: TEST7_TIMESTAMP,
            url: URL.to_vec(),
            sgx_mode: SgxBuildMode::Debug,
        };

        assert_ok!(Teerex::register_enclave(
            Origin::signed(signer5.clone()),
            TEST5_CERT.to_vec(),
            URL.to_vec(),
        ));
        assert_eq!(Teerex::enclave_count(), 1);
        assert_eq!(list_enclaves(), vec![(1, e_1.clone())]);

        // add enclave 2
        assert_ok!(Teerex::register_enclave(
            Origin::signed(signer6.clone()),
            TEST6_CERT.to_vec(),
            URL.to_vec(),
        ));
        assert_eq!(Teerex::enclave_count(), 2);
        let enclaves = list_enclaves();
        assert!(enclaves.contains(&(1, e_1.clone())));
        assert!(enclaves.contains(&(2, e_2.clone())));

        // add enclave 3
        assert_ok!(Teerex::register_enclave(
            Origin::signed(signer7.clone()),
            TEST7_CERT.to_vec(),
            URL.to_vec(),
        ));
        assert_eq!(Teerex::enclave_count(), 3);
        let enclaves = list_enclaves();
        assert!(enclaves.contains(&(1, e_1.clone())));
        assert!(enclaves.contains(&(2, e_2.clone())));
        assert!(enclaves.contains(&(3, e_3.clone())));

        // remove enclave 2
        assert_ok!(Teerex::unregister_enclave(Origin::signed(signer6)));
        assert_eq!(Teerex::enclave_count(), 2);
        let enclaves = list_enclaves();
        assert!(enclaves.contains(&(1, e_1.clone())));
        assert!(enclaves.contains(&(2, e_3.clone())));
    })
}

#[test]
fn register_enclave_with_different_signer_fails() {
    new_test_ext().execute_with(|| {
        let signer = get_signer(TEST7_SIGNER_PUB);
        assert_err!(
            Teerex::register_enclave(Origin::signed(signer), TEST5_CERT.to_vec(), URL.to_vec()),
            Error::<Test>::SenderIsNotAttestedEnclave
        );
    })
}

#[test]
fn register_enclave_with_to_old_attestation_report_fails() {
    new_test_ext().execute_with(|| {
        Timestamp::set_timestamp(TEST7_TIMESTAMP + TWENTY_FOUR_HOURS + 1);
        let signer = get_signer(TEST7_SIGNER_PUB);
        assert_err!(
            Teerex::register_enclave(Origin::signed(signer), TEST7_CERT.to_vec(), URL.to_vec(),),
            Error::<Test>::RemoteAttestationTooOld
        );
    })
}

#[test]
fn register_enclave_with_almost_too_old_report_works() {
    new_test_ext().execute_with(|| {
        Timestamp::set_timestamp(TEST7_TIMESTAMP + TWENTY_FOUR_HOURS - 1);
        let signer = get_signer(TEST7_SIGNER_PUB);
        assert_ok!(Teerex::register_enclave(
            Origin::signed(signer),
            TEST7_CERT.to_vec(),
            URL.to_vec(),
        ));
    })
}

#[test]
fn update_enclave_url_works() {
    new_test_ext().execute_with(|| {
        Timestamp::set_timestamp(TEST4_TIMESTAMP);

        let signer = get_signer(TEST4_SIGNER_PUB);
        let url2 = "my fancy url".as_bytes();
        let _e_1: Enclave<AccountId, Vec<u8>> = Enclave {
            pubkey: signer.clone(),
            mr_enclave: TEST4_MRENCLAVE,
            timestamp: TEST4_TIMESTAMP,
            url: url2.to_vec(),
            sgx_mode: SgxBuildMode::Debug,
        };

        assert_ok!(Teerex::register_enclave(
            Origin::signed(signer.clone()),
            TEST4_CERT.to_vec(),
            URL.to_vec(),
        ));
        assert_eq!(Teerex::enclave(1).url, URL.to_vec());

        assert_ok!(Teerex::register_enclave(
            Origin::signed(signer.clone()),
            TEST4_CERT.to_vec(),
            url2.to_vec(),
        ));
        assert_eq!(Teerex::enclave(1).url, url2.to_vec());
        let enclaves = list_enclaves();
        assert_eq!(enclaves[0].1.pubkey, signer)
    })
}

#[test]
fn update_ipfs_hash_works() {
    new_test_ext().execute_with(|| {
        Timestamp::set_timestamp(TEST4_TIMESTAMP);

        let ipfs_hash = "QmYY9U7sQzBYe79tVfiMyJ4prEJoJRWCD8t85j9qjssS9y";
        let shard = H256::from_slice(&TEST4_MRENCLAVE);
        let request_hash = H256::default();
        let signer = get_signer(TEST4_SIGNER_PUB);

        assert_ok!(Teerex::register_enclave(
            Origin::signed(signer.clone()),
            TEST4_CERT.to_vec(),
            URL.to_vec(),
        ));
        assert_eq!(Teerex::enclave_count(), 1);
        assert_ok!(Teerex::confirm_call(
            Origin::signed(signer.clone()),
            shard.clone(),
            request_hash.clone(),
            ipfs_hash.as_bytes().to_vec()
        ));
        assert_eq!(
            Teerex::latest_ipfs_hash(shard.clone()),
            ipfs_hash.as_bytes().to_vec()
        );
        assert_eq!(Teerex::worker_for_shard(shard.clone()), 1u64);

        let expected_event = Event::Teerex(RawEvent::UpdatedIpfsHash(
            shard.clone(),
            1,
            ipfs_hash.as_bytes().to_vec(),
        ));
        assert!(System::events().iter().any(|a| a.event == expected_event));

        let expected_event = Event::Teerex(RawEvent::CallConfirmed(signer.clone(), request_hash));
        assert!(System::events().iter().any(|a| a.event == expected_event));
    })
}

#[test]
fn ipfs_update_from_unregistered_enclave_fails() {
    new_test_ext().execute_with(|| {
        let ipfs_hash = "QmYY9U7sQzBYe79tVfiMyJ4prEJoJRWCD8t85j9qjssS9y";
        let signer = get_signer(TEST4_SIGNER_PUB);
        assert_err!(
            Teerex::confirm_call(
                Origin::signed(signer),
                H256::default(),
                H256::default(),
                ipfs_hash.as_bytes().to_vec()
            ),
            Error::<Test>::EnclaveIsNotRegistered
        );
    })
}

#[test]
fn call_worker_works() {
    new_test_ext().execute_with(|| {
        let req = Request {
            shard: ShardIdentifier::default(),
            cyphertext: vec![0u8, 1, 2, 3, 4],
        };
        // don't care who signs
        let signer = get_signer(TEST4_SIGNER_PUB);
        assert!(Teerex::call_worker(Origin::signed(signer), req.clone()).is_ok());
        let expected_event = Event::Teerex(RawEvent::Forwarded(req.shard));
        println!("events:{:?}", System::events());
        assert!(System::events().iter().any(|a| a.event == expected_event));
    })
}

#[test]
fn unshield_is_only_executed_once_for_the_same_call_hash() {
    new_test_ext().execute_with(|| {
        Timestamp::set_timestamp(TEST4_TIMESTAMP);
        let signer = get_signer(TEST4_SIGNER_PUB);
        let call_hash: H256 = H256::from([1u8; 32]);
        let bonding_account = get_signer(&TEST4_MRENCLAVE);

        assert_ok!(Teerex::register_enclave(
            Origin::signed(signer.clone()),
            TEST4_CERT.to_vec(),
            URL.to_vec(),
        ));

        assert_ok!(Balances::transfer(
            Origin::signed(AccountKeyring::Alice.to_account_id()),
            bonding_account.clone(),
            1 << 50
        ));

        assert!(Teerex::unshield_funds(
            Origin::signed(signer.clone()),
            AccountKeyring::Alice.to_account_id(),
            50,
            bonding_account.clone(),
            call_hash.clone()
        )
        .is_ok());

        assert!(Teerex::unshield_funds(
            Origin::signed(signer.clone()),
            AccountKeyring::Alice.to_account_id(),
            50,
            bonding_account.clone(),
            call_hash.clone()
        )
        .is_ok());

        assert_eq!(<ConfirmedCalls>::get(call_hash), 2)
    })
}
#[test]
fn timestamp_callback_works() {
    new_test_ext().execute_with(|| {
        set_timestamp(TEST7_TIMESTAMP);

        let signer5 = get_signer(TEST5_SIGNER_PUB);
        let signer6 = get_signer(TEST6_SIGNER_PUB);
        let signer7 = get_signer(TEST7_SIGNER_PUB);

        // add enclave 1
        let e_2: Enclave<AccountId, Vec<u8>> = Enclave {
            pubkey: signer6.clone(),
            mr_enclave: TEST6_MRENCLAVE,
            timestamp: TEST6_TIMESTAMP,
            url: URL.to_vec(),
            sgx_mode: SgxBuildMode::Debug,
        };

        let e_3: Enclave<AccountId, Vec<u8>> = Enclave {
            pubkey: signer7.clone(),
            mr_enclave: TEST7_MRENCLAVE,
            timestamp: TEST7_TIMESTAMP,
            url: URL.to_vec(),
            sgx_mode: SgxBuildMode::Debug,
        };

        //Register 3 enclaves: 5, 6 ,7
        assert_ok!(Teerex::register_enclave(
            Origin::signed(signer5.clone()),
            TEST5_CERT.to_vec(),
            URL.to_vec(),
        ));
        assert_ok!(Teerex::register_enclave(
            Origin::signed(signer6.clone()),
            TEST6_CERT.to_vec(),
            URL.to_vec(),
        ));
        assert_ok!(Teerex::register_enclave(
            Origin::signed(signer7.clone()),
            TEST7_CERT.to_vec(),
            URL.to_vec(),
        ));
        assert_eq!(Teerex::enclave_count(), 3);

        //enclave 5 silent since 49h -> unregistered
        run_to_block(2);
        set_timestamp(TEST5_TIMESTAMP + 2 * TWENTY_FOUR_HOURS + 1);

        let expected_event = Event::Teerex(RawEvent::RemovedEnclave(signer5));
        assert!(System::events().iter().any(|a| a.event == expected_event));
        assert_eq!(Teerex::enclave_count(), 2);
        //2 and 3 are still there. 3 and 1 were swapped -> 3 and 2
        let enclaves = list_enclaves();
        assert!(enclaves.contains(&(1, e_3.clone())));
        assert!(enclaves.contains(&(2, e_2.clone())));

        run_to_block(3);
        //enclave 6 and 7 still registered: not long enough silent
        set_timestamp(TEST6_TIMESTAMP + 2 * TWENTY_FOUR_HOURS);
        assert_eq!(Teerex::enclave_count(), 2);

        //unregister 6 to generate an error next call of callbakc
        assert_ok!(Teerex::unregister_enclave(Origin::signed(signer6.clone())));
        let expected_event = Event::Teerex(RawEvent::RemovedEnclave(signer6));
        assert!(System::events().iter().any(|a| a.event == expected_event));
        assert_eq!(Teerex::enclave_count(), 1);

        //enclave 6 and 7 silent since TWENTY_FOUR_HOURS + 1 -> unregistered
        run_to_block(4);
        set_timestamp(TEST7_TIMESTAMP + 2 * TWENTY_FOUR_HOURS + 1);
        let expected_event = Event::Teerex(RawEvent::RemovedEnclave(signer7));
        assert!(System::events().iter().any(|a| a.event == expected_event));
        assert_eq!(Teerex::enclave_count(), 0);
    })
}

#[test]
fn debug_mode_enclave_attest_works_when_sgx_debug_mode_is_allowed() {
    new_test_ext().execute_with(|| {
        set_timestamp(TEST4_TIMESTAMP);
        let signer4 = get_signer(TEST4_SIGNER_PUB);
        let e_0: Enclave<AccountId, Vec<u8>> = Enclave {
            pubkey: signer4.clone(),
            mr_enclave: TEST4_MRENCLAVE,
            timestamp: TEST4_TIMESTAMP,
            url: URL.to_vec(),
            sgx_mode: SgxBuildMode::Debug,
        };

        //Register an enclave compiled in debug mode
        assert_ok!(Teerex::register_enclave(
            Origin::signed(signer4.clone()),
            TEST4_CERT.to_vec(),
            URL.to_vec(),
        ));
        assert_eq!(Teerex::enclave_count(), 1);
        let enclaves = list_enclaves();
        assert!(enclaves.contains(&(1, e_0.clone())));
    })
}

#[test]
fn production_mode_enclave_attest_works_when_sgx_debug_mode_is_allowed() {
    new_test_ext().execute_with(|| {
        new_test_ext().execute_with(|| {
            set_timestamp(TEST8_TIMESTAMP);
            let signer8 = get_signer(TEST8_SIGNER_PUB);
            let e_0: Enclave<AccountId, Vec<u8>> = Enclave {
                pubkey: signer8.clone(),
                mr_enclave: TEST8_MRENCLAVE,
                timestamp: TEST8_TIMESTAMP,
                url: URL.to_vec(),
                sgx_mode: SgxBuildMode::Production,
            };

            //Register an enclave compiled in production mode
            assert_ok!(Teerex::register_enclave(
                Origin::signed(signer8.clone()),
                TEST8_CERT.to_vec(),
                URL.to_vec(),
            ));
            assert_eq!(Teerex::enclave_count(), 1);
            let enclaves = list_enclaves();
            assert!(enclaves.contains(&(1, e_0.clone())));
        })
    })
}

#[test]
fn debug_mode_enclave_attest_fails_when_sgx_debug_mode_not_allowed() {
    new_test_production_ext().execute_with(|| {
        set_timestamp(TEST4_TIMESTAMP);
        let signer4 = get_signer(TEST4_SIGNER_PUB);
        //Try to register an enclave compiled in debug mode
        assert_err!(
            Teerex::register_enclave(
                Origin::signed(signer4.clone()),
                TEST4_CERT.to_vec(),
                URL.to_vec(),
            ),
            Error::<Test>::SgxModeNotAllowed
        );
        assert_eq!(Teerex::enclave_count(), 0);
    })
}
#[test]
fn production_mode_enclave_attest_works_when_sgx_debug_mode_not_allowed() {
    new_test_production_ext().execute_with(|| {
        set_timestamp(TEST8_TIMESTAMP);
        let signer8 = get_signer(TEST8_SIGNER_PUB);
        let e_0: Enclave<AccountId, Vec<u8>> = Enclave {
            pubkey: signer8.clone(),
            mr_enclave: TEST8_MRENCLAVE,
            timestamp: TEST8_TIMESTAMP,
            url: URL.to_vec(),
            sgx_mode: SgxBuildMode::Production,
        };

        //Register an enclave compiled in production mode
        assert_ok!(Teerex::register_enclave(
            Origin::signed(signer8.clone()),
            TEST8_CERT.to_vec(),
            URL.to_vec(),
        ));
        assert_eq!(Teerex::enclave_count(), 1);
        let enclaves = list_enclaves();
        assert!(enclaves.contains(&(1, e_0.clone())));
    })
}

#[test]
fn verify_unshield_funds_works() {
    new_test_ext().execute_with(|| {
        Timestamp::set_timestamp(TEST4_TIMESTAMP);
        let signer4 = get_signer(TEST4_SIGNER_PUB);
        let call_hash: H256 = H256::from([1u8; 32]);
        let bonding_account = get_signer(&TEST4_MRENCLAVE);
        let incognito_account = INCOGNITO_ACCOUNT.to_vec();

        //Register enclave
        assert_ok!(Teerex::register_enclave(
            Origin::signed(signer4.clone()),
            TEST4_CERT.to_vec(),
            URL.to_vec(),
        ));
        assert_eq!(Teerex::enclave_count(), 1);

        assert!(Teerex::shield_funds(
            Origin::signed(AccountKeyring::Alice.to_account_id()),
            incognito_account.clone(),
            100,
            bonding_account.clone(),
        )
        .is_ok());

        assert_eq!(Balances::free_balance(bonding_account.clone()), 100);

        let expected_event = Event::Teerex(RawEvent::ShieldFunds(incognito_account));
        assert!(System::events().iter().any(|a| a.event == expected_event));

        assert!(Teerex::unshield_funds(
            Origin::signed(signer4.clone()),
            AccountKeyring::Alice.to_account_id(),
            50,
            bonding_account.clone(),
            call_hash.clone()
        )
        .is_ok());
        assert_eq!(Balances::free_balance(bonding_account), 50);

        let expected_event = Event::Teerex(RawEvent::UnshieldedFunds(
            AccountKeyring::Alice.to_account_id(),
        ));
        assert!(System::events().iter().any(|a| a.event == expected_event));
    })
}

#[test]
fn verify_unshield_funds_from_not_registered_enclave_fails() {
    new_test_ext().execute_with(|| {
        Timestamp::set_timestamp(TEST4_TIMESTAMP);
        let signer4 = get_signer(TEST4_SIGNER_PUB);
        let call_hash: H256 = H256::from([1u8; 32]);

        assert_eq!(Teerex::enclave_count(), 0);

        assert_err!(
            Teerex::unshield_funds(
                Origin::signed(signer4.clone()),
                AccountKeyring::Alice.to_account_id(),
                51,
                signer4.clone(),
                call_hash.clone()
            ),
            Error::<Test>::EnclaveIsNotRegistered
        );
    })
}

#[test]
fn verify_unshield_funds_from_enclave_not_bonding_account_fails() {
    new_test_ext().execute_with(|| {
        Timestamp::set_timestamp(TEST7_TIMESTAMP);
        let signer4 = get_signer(TEST4_SIGNER_PUB);
        let call_hash: H256 = H256::from([1u8; 32]);
        let bonding_account = get_signer(&TEST4_MRENCLAVE);
        let incognito_account = INCOGNITO_ACCOUNT;
        let not_bonding_account = get_signer(&TEST7_MRENCLAVE);

        //Ensure that enclave is registered
        assert_ok!(Teerex::register_enclave(
            Origin::signed(signer4.clone()),
            TEST4_CERT.to_vec(),
            URL.to_vec(),
        ));

        //Ensure that bonding account has funds
        assert!(Teerex::shield_funds(
            Origin::signed(AccountKeyring::Alice.to_account_id()),
            incognito_account.to_vec(),
            100,
            bonding_account.clone(),
        )
        .is_ok());

        assert!(Teerex::shield_funds(
            Origin::signed(AccountKeyring::Alice.to_account_id()),
            incognito_account.to_vec(),
            50,
            not_bonding_account.clone(),
        )
        .is_ok());

        assert_err!(
            Teerex::unshield_funds(
                Origin::signed(signer4.clone()),
                AccountKeyring::Alice.to_account_id(),
                50,
                not_bonding_account.clone(),
                call_hash.clone()
            ),
            Error::<Test>::WrongMrenclaveForBondingAccount
        );

        assert_eq!(Balances::free_balance(bonding_account.clone()), 100);
        assert_eq!(Balances::free_balance(not_bonding_account.clone()), 50);
    })
}

#[test]
fn verify_call_confirmation_from_shards_not_enclave_fails() {
    new_test_ext().execute_with(|| {
        Timestamp::set_timestamp(TEST7_TIMESTAMP);
        let ipfs_hash = "QmYY9U7sQzBYe79tVfiMyJ4prEJoJRWCD8t85j9qjssS9y";
        let request_hash = H256::default();
        let signer7 = get_signer(TEST7_SIGNER_PUB);
        let shard4 = H256::from_slice(&TEST4_MRENCLAVE);

        //Ensure that enclave is registered
        assert_ok!(Teerex::register_enclave(
            Origin::signed(signer7.clone()),
            TEST7_CERT.to_vec(),
            URL.to_vec(),
        ));

        assert_err!(
            Teerex::confirm_call(
                Origin::signed(signer7.clone()),
                shard4.clone(),
                request_hash.clone(),
                ipfs_hash.as_bytes().to_vec()
            ),
            Error::<Test>::WrongMrenclaveForShard
        );
    })
}

#[test]
fn update_block_confirmation_works() {
    new_test_ext().execute_with(|| {
        Timestamp::set_timestamp(TEST7_TIMESTAMP);
        let ipfs_hash = "QmYY9U7sQzBYe79tVfiMyJ4prEJoJRWCD8t85j9qjssS9y";
        let block_hash = H256::default();
        let signer7 = get_signer(TEST7_SIGNER_PUB);
        let shard7 = H256::from_slice(&TEST7_MRENCLAVE);

        //Ensure that enclave is registered
        assert_ok!(Teerex::register_enclave(
            Origin::signed(signer7.clone()),
            TEST7_CERT.to_vec(),
            URL.to_vec(),
        ));
        assert_eq!(Teerex::enclave_count(), 1);

        assert_ok!(Teerex::confirm_block(
            Origin::signed(signer7.clone()),
            shard7.clone(),
            block_hash.clone(),
            ipfs_hash.as_bytes().to_vec()
        ));

        let expected_event = Event::Teerex(RawEvent::UpdatedIpfsHash(
            shard7.clone(),
            1,
            ipfs_hash.as_bytes().to_vec(),
        ));
        assert!(System::events().iter().any(|a| a.event == expected_event));

        let expected_event = Event::Teerex(RawEvent::BlockConfirmed(signer7.clone(), block_hash));
        assert!(System::events().iter().any(|a| a.event == expected_event));
    })
}

#[test]
fn verify_block_confirmation_from_shards_not_enclave_fails() {
    new_test_ext().execute_with(|| {
        Timestamp::set_timestamp(TEST7_TIMESTAMP);
        let ipfs_hash = "QmYY9U7sQzBYe79tVfiMyJ4prEJoJRWCD8t85j9qjssS9y";
        let block_hash = H256::default();
        let signer7 = get_signer(TEST7_SIGNER_PUB);
        let shard4 = H256::from_slice(&TEST4_MRENCLAVE);

        //Ensure that enclave is registered
        assert_ok!(Teerex::register_enclave(
            Origin::signed(signer7.clone()),
            TEST7_CERT.to_vec(),
            URL.to_vec(),
        ));
        assert_eq!(Teerex::enclave_count(), 1);

        assert_err!(
            Teerex::confirm_block(
                Origin::signed(signer7.clone()),
                shard4.clone(),
                block_hash.clone(),
                ipfs_hash.as_bytes().to_vec()
            ),
            Error::<Test>::WrongMrenclaveForShard
        );
    })
}
