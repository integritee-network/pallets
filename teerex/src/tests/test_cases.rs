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

use crate::{
	mock::*,
	test_helpers::{register_test_quoting_enclave, register_test_tcb_info},
	Error, Event as TeerexEvent, ExecutedCalls, Request, SgxEnclave, ShardIdentifier,
	SovereignEnclaves, DATA_LENGTH_LIMIT,
};
use codec::Encode;
use frame_support::{assert_err, assert_ok};
use hex_literal::hex;
use sgx_verify::test_data::dcap::TEST1_DCAP_QUOTE_SIGNER;
use sp_core::H256;
use sp_keyring::AccountKeyring;
use sp_runtime::{MultiSignature, MultiSigner};
use teerex_primitives::{
	AnySigner, MultiEnclave, SgxAttestationMethod, SgxBuildMode, SgxReportData, SgxStatus,
};
use test_utils::test_data::{
	consts::*,
	dcap::{TEST1_DCAP_QUOTE, TEST_VALID_COLLATERAL_TIMESTAMP},
};

fn list_enclaves() -> Vec<(AccountId, MultiEnclave<Vec<u8>>)> {
	<SovereignEnclaves<Test>>::iter().collect::<Vec<(AccountId, MultiEnclave<Vec<u8>>)>>()
}

// give get_signer a concrete type
fn get_signer(pubkey: &[u8; 32]) -> AccountId {
	test_utils::get_signer(pubkey)
}

#[test]
fn add_and_remove_dcap_enclave_works() {
	new_test_ext().execute_with(|| {
		Timestamp::set_timestamp(TEST_VALID_COLLATERAL_TIMESTAMP);

		let alice = AccountKeyring::Alice.to_account_id();
		register_test_quoting_enclave::<Test>(alice.clone());
		register_test_tcb_info::<Test>(alice);

		let signer = get_signer(&TEST1_DCAP_QUOTE_SIGNER);
		assert_ok!(Teerex::register_sgx_enclave(
			RuntimeOrigin::signed(signer.clone()),
			TEST1_DCAP_QUOTE.to_vec(),
			Some(URL.to_vec()),
			SgxAttestationMethod::Dcap { proxied: false }
		));
		assert!(<SovereignEnclaves<Test>>::contains_key(&signer));
		assert_eq!(
			Teerex::sovereign_enclaves(&signer).unwrap().attestation_timestamp(),
			TEST_VALID_COLLATERAL_TIMESTAMP
		);
		assert_ok!(Teerex::unregister_enclave(RuntimeOrigin::signed(signer.clone())));
		assert!(!<SovereignEnclaves<Test>>::contains_key(&signer));
		assert_eq!(list_enclaves(), vec![])
	})
}

#[test]
fn register_quoting_enclave_works() {
	new_test_ext().execute_with(|| {
		let alice = AccountKeyring::Alice.to_account_id();
		let qe = Teerex::quoting_enclave();
		assert_eq!(qe.mrsigner, [0u8; 32]);
		assert_eq!(qe.isvprodid, 0);
		Timestamp::set_timestamp(TEST_VALID_COLLATERAL_TIMESTAMP);
		register_test_quoting_enclave::<Test>(alice);
		let qe = Teerex::quoting_enclave();
		assert_eq!(qe.isvprodid, 1);

		let expected_event =
			RuntimeEvent::Teerex(TeerexEvent::SgxQuotingEnclaveRegistered { quoting_enclave: qe });
		assert!(System::events().iter().any(|a| a.event == expected_event))
	})
}

#[test]
fn register_tcb_info_works() {
	new_test_ext().execute_with(|| {
		Timestamp::set_timestamp(TEST_VALID_COLLATERAL_TIMESTAMP);

		register_test_tcb_info::<Test>(AccountKeyring::Alice.to_account_id());
		let fmspc = hex!("00906EA10000");
		let tcb_info = Teerex::tcb_info(fmspc);
		// This is the date that the is registered in register_tcb_info and represents the date 2023-04-16T12:45:32Z
		assert_eq!(tcb_info.next_update, 1681649132000);

		let expected_event = RuntimeEvent::Teerex(TeerexEvent::SgxTcbInfoRegistered {
			fmspc,
			on_chain_info: tcb_info,
		});
		assert!(System::events().iter().any(|a| a.event == expected_event))
	})
}

#[test]
fn add_enclave_works() {
	new_test_ext().execute_with(|| {
		// set the now in the runtime such that the remote attestation reports are within accepted range (24h)
		Timestamp::set_timestamp(TEST4_TIMESTAMP);
		let signer = get_signer(TEST4_SIGNER_PUB);
		assert_ok!(Teerex::register_sgx_enclave(
			RuntimeOrigin::signed(signer.clone()),
			TEST4_CERT.to_vec(),
			Some(URL.to_vec()),
			SgxAttestationMethod::Ias
		));
		assert!(<SovereignEnclaves<Test>>::contains_key(&signer));
	})
}

#[test]
fn add_and_remove_enclave_works() {
	new_test_ext().execute_with(|| {
		Timestamp::set_timestamp(TEST4_TIMESTAMP);
		let signer = get_signer(TEST4_SIGNER_PUB);
		assert_ok!(Teerex::register_sgx_enclave(
			RuntimeOrigin::signed(signer.clone()),
			TEST4_CERT.to_vec(),
			Some(URL.to_vec()),
			SgxAttestationMethod::Ias
		));
		assert!(<SovereignEnclaves<Test>>::contains_key(&signer));
		assert_ok!(Teerex::unregister_enclave(RuntimeOrigin::signed(signer.clone())));
		assert!(!<SovereignEnclaves<Test>>::contains_key(&signer));
		assert_eq!(list_enclaves(), vec![])
	})
}

#[test]
fn add_enclave_without_timestamp_fails() {
	new_test_ext().execute_with(|| {
		Timestamp::set_timestamp(0);
		let signer = get_signer(TEST4_SIGNER_PUB);
		assert!(Teerex::register_sgx_enclave(
			RuntimeOrigin::signed(signer.clone()),
			TEST4_CERT.to_vec(),
			Some(URL.to_vec()),
			SgxAttestationMethod::Ias
		)
		.is_err());
		assert!(!<SovereignEnclaves<Test>>::contains_key(&signer));
	})
}

#[test]
fn list_enclaves_works() {
	new_test_ext().execute_with(|| {
		Timestamp::set_timestamp(TEST4_TIMESTAMP);
		let signer = get_signer(TEST4_SIGNER_PUB);
		let e_1: SgxEnclave<Vec<u8>> = SgxEnclave {
			report_data: SgxReportData::from(TEST4_SIGNER_PUB),
			mr_enclave: TEST4_MRENCLAVE,
			timestamp: TEST4_TIMESTAMP,
			url: Some(URL.to_vec()),
			build_mode: SgxBuildMode::Debug,
			mr_signer: TEST4_MRSIGNER,
			attestation_method: SgxAttestationMethod::Ias,
			status: SgxStatus::ConfigurationNeeded,
		};
		assert_ok!(Teerex::register_sgx_enclave(
			RuntimeOrigin::signed(signer.clone()),
			TEST4_CERT.to_vec(),
			Some(URL.to_vec()),
			SgxAttestationMethod::Ias,
		));
		assert!(<SovereignEnclaves<Test>>::contains_key(&signer));
		let enclaves = list_enclaves();
		assert_eq!(enclaves[0].1, MultiEnclave::from(e_1));
	})
}

#[test]
fn register_ias_enclave_with_different_signer_fails() {
	new_test_ext().execute_with(|| {
		let signer = get_signer(TEST7_SIGNER_PUB);
		assert_err!(
			Teerex::register_sgx_enclave(
				RuntimeOrigin::signed(signer),
				TEST5_CERT.to_vec(),
				Some(URL.to_vec()),
				SgxAttestationMethod::Ias
			),
			Error::<Test>::SenderIsNotAttestedEnclave
		);
	})
}

#[test]
fn register_ias_enclave_with_to_old_attestation_report_fails() {
	new_test_ext().execute_with(|| {
		Timestamp::set_timestamp(TEST7_TIMESTAMP + TWENTY_FOUR_HOURS + 1);
		let signer = get_signer(TEST7_SIGNER_PUB);
		assert_err!(
			Teerex::register_sgx_enclave(
				RuntimeOrigin::signed(signer),
				TEST7_CERT.to_vec(),
				Some(URL.to_vec()),
				SgxAttestationMethod::Ias
			),
			Error::<Test>::RemoteAttestationTooOld
		);
	})
}

#[test]
fn register_ias_enclave_with_almost_too_old_report_works() {
	new_test_ext().execute_with(|| {
		Timestamp::set_timestamp(TEST7_TIMESTAMP + TWENTY_FOUR_HOURS - 1);
		let signer = get_signer(TEST7_SIGNER_PUB);
		assert_ok!(Teerex::register_sgx_enclave(
			RuntimeOrigin::signed(signer),
			TEST7_CERT.to_vec(),
			Some(URL.to_vec()),
			SgxAttestationMethod::Ias
		));
	})
}

#[test]
fn update_enclave_url_works() {
	new_test_ext().execute_with(|| {
		Timestamp::set_timestamp(TEST4_TIMESTAMP);

		let signer = get_signer(TEST4_SIGNER_PUB);
		let url2 = "my fancy url".as_bytes();
		let _e_1: SgxEnclave<Vec<u8>> = SgxEnclave {
			report_data: SgxReportData::from(TEST4_SIGNER_PUB),
			mr_enclave: TEST4_MRENCLAVE,
			timestamp: TEST4_TIMESTAMP,
			url: None,
			build_mode: SgxBuildMode::Debug,
			mr_signer: TEST4_MRSIGNER,
			attestation_method: SgxAttestationMethod::Ias,
			status: SgxStatus::ConfigurationNeeded,
		};

		assert_ok!(Teerex::register_sgx_enclave(
			RuntimeOrigin::signed(signer.clone()),
			TEST4_CERT.to_vec(),
			Some(URL.to_vec()),
			SgxAttestationMethod::Ias
		));
		assert_eq!(Teerex::sovereign_enclaves(&signer).unwrap().instance_url(), Some(URL.to_vec()));

		assert_ok!(Teerex::register_sgx_enclave(
			RuntimeOrigin::signed(signer.clone()),
			TEST4_CERT.to_vec(),
			Some(url2.to_vec()),
			SgxAttestationMethod::Ias
		));
		assert_eq!(
			Teerex::sovereign_enclaves(&signer).unwrap().instance_url(),
			Some(url2.to_vec())
		);
	})
}

#[test]
fn update_ipfs_hash_works() {
	new_test_ext().execute_with(|| {
		Timestamp::set_timestamp(TEST4_TIMESTAMP);
		let block_hash = H256::default();
		let merkle_root = H256::default();
		let block_number = 3;
		let signer = get_signer(TEST4_SIGNER_PUB);

		assert_ok!(Teerex::register_sgx_enclave(
			RuntimeOrigin::signed(signer.clone()),
			TEST4_CERT.to_vec(),
			Some(URL.to_vec()),
			SgxAttestationMethod::Ias
		));
		assert!(<SovereignEnclaves<Test>>::contains_key(&signer));
		assert_ok!(Teerex::confirm_processed_parentchain_block(
			RuntimeOrigin::signed(signer.clone()),
			block_hash,
			block_number,
			merkle_root,
		));

		let expected_event = RuntimeEvent::Teerex(TeerexEvent::ProcessedParentchainBlock(
			signer,
			block_hash,
			merkle_root,
			block_number,
		));
		assert!(System::events().iter().any(|a| a.event == expected_event));
	})
}

#[test]
fn ipfs_update_from_unregistered_enclave_fails() {
	new_test_ext().execute_with(|| {
		let signer = get_signer(TEST4_SIGNER_PUB);
		assert_err!(
			Teerex::confirm_processed_parentchain_block(
				RuntimeOrigin::signed(signer),
				H256::default(),
				3,
				H256::default(),
			),
			Error::<Test>::EnclaveIsNotRegistered
		);
	})
}

#[test]
fn call_worker_works() {
	new_test_ext().execute_with(|| {
		let req = Request { shard: ShardIdentifier::default(), cyphertext: vec![0u8, 1, 2, 3, 4] };
		// don't care who signs
		let signer = get_signer(TEST4_SIGNER_PUB);
		assert!(Teerex::call_worker(RuntimeOrigin::signed(signer), req.clone()).is_ok());
		let expected_event = RuntimeEvent::Teerex(TeerexEvent::Forwarded(req.shard));
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

		assert_ok!(Teerex::register_sgx_enclave(
			RuntimeOrigin::signed(signer.clone()),
			TEST4_CERT.to_vec(),
			Some(URL.to_vec()),
			SgxAttestationMethod::Ias
		));

		assert_ok!(Balances::transfer(
			RuntimeOrigin::signed(AccountKeyring::Alice.to_account_id()),
			bonding_account.clone(),
			1 << 50
		));

		assert!(Teerex::unshield_funds(
			RuntimeOrigin::signed(signer.clone()),
			AccountKeyring::Alice.to_account_id(),
			50,
			bonding_account.clone(),
			call_hash
		)
		.is_ok());

		assert!(Teerex::unshield_funds(
			RuntimeOrigin::signed(signer),
			AccountKeyring::Alice.to_account_id(),
			50,
			bonding_account,
			call_hash
		)
		.is_ok());

		assert_eq!(<ExecutedCalls<Test>>::get(call_hash), 2)
	})
}

#[test]
fn debug_mode_enclave_attest_works_when_sgx_debug_mode_is_allowed() {
	new_test_ext().execute_with(|| {
		set_timestamp(TEST4_TIMESTAMP);
		let signer4 = get_signer(TEST4_SIGNER_PUB);
		let e_0: SgxEnclave<Vec<u8>> = SgxEnclave {
			report_data: SgxReportData::from(TEST4_SIGNER_PUB),
			mr_enclave: TEST4_MRENCLAVE,
			timestamp: TEST4_TIMESTAMP,
			url: Some(URL.to_vec()),
			build_mode: SgxBuildMode::Debug,
			mr_signer: TEST4_MRSIGNER,
			attestation_method: SgxAttestationMethod::Ias,
			status: SgxStatus::ConfigurationNeeded,
		};

		//Register an enclave compiled in debug mode
		assert_ok!(Teerex::register_sgx_enclave(
			RuntimeOrigin::signed(signer4.clone()),
			TEST4_CERT.to_vec(),
			Some(URL.to_vec()),
			SgxAttestationMethod::Ias
		));
		assert!(<SovereignEnclaves<Test>>::contains_key(&signer4));
		let enclaves = list_enclaves();
		assert!(enclaves.contains(&(signer4, MultiEnclave::from(e_0))));
	})
}

#[test]
fn production_mode_enclave_attest_works_when_sgx_debug_mode_is_allowed() {
	new_test_ext().execute_with(|| {
		new_test_ext().execute_with(|| {
			set_timestamp(TEST8_TIMESTAMP);
			let signer8 = get_signer(TEST8_SIGNER_PUB);
			let e_0: SgxEnclave<Vec<u8>> = SgxEnclave {
				report_data: SgxReportData::from(TEST8_SIGNER_PUB),
				mr_enclave: TEST8_MRENCLAVE,
				timestamp: TEST8_TIMESTAMP,
				url: Some(URL.to_vec()),
				build_mode: SgxBuildMode::Production,
				mr_signer: TEST8_MRSIGNER,
				attestation_method: SgxAttestationMethod::Ias,
				status: SgxStatus::Invalid,
			};

			//Register an enclave compiled in production mode
			assert_ok!(Teerex::register_sgx_enclave(
				RuntimeOrigin::signed(signer8.clone()),
				TEST8_CERT.to_vec(),
				Some(URL.to_vec()),
				SgxAttestationMethod::Ias
			));
			assert!(<SovereignEnclaves<Test>>::contains_key(&signer8));
			let enclaves = list_enclaves();
			assert!(enclaves.contains(&(signer8, MultiEnclave::from(e_0))));
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
			Teerex::register_sgx_enclave(
				RuntimeOrigin::signed(signer4.clone()),
				TEST4_CERT.to_vec(),
				Some(URL.to_vec()),
				SgxAttestationMethod::Ias
			),
			Error::<Test>::SgxModeNotAllowed
		);
		assert!(!<SovereignEnclaves<Test>>::contains_key(&signer4));
	})
}
#[test]
fn production_mode_enclave_attest_works_when_sgx_debug_mode_not_allowed() {
	new_test_production_ext().execute_with(|| {
		set_timestamp(TEST8_TIMESTAMP);
		let signer8 = get_signer(TEST8_SIGNER_PUB);
		let e_0: SgxEnclave<Vec<u8>> = SgxEnclave {
			report_data: SgxReportData::from(TEST8_SIGNER_PUB),
			mr_enclave: TEST8_MRENCLAVE,
			timestamp: TEST8_TIMESTAMP,
			url: Some(URL.to_vec()),
			build_mode: SgxBuildMode::Production,
			mr_signer: TEST8_MRSIGNER,
			attestation_method: SgxAttestationMethod::Ias,
			status: SgxStatus::Invalid,
		};

		//Register an enclave compiled in production mode
		assert_ok!(Teerex::register_sgx_enclave(
			RuntimeOrigin::signed(signer8.clone()),
			TEST8_CERT.to_vec(),
			Some(URL.to_vec()),
			SgxAttestationMethod::Ias
		));
		assert!(<SovereignEnclaves<Test>>::contains_key(&signer8));
		let enclaves = list_enclaves();
		assert!(enclaves.contains(&(signer8, MultiEnclave::from(e_0))));
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
		assert_ok!(Teerex::register_sgx_enclave(
			RuntimeOrigin::signed(signer4.clone()),
			TEST4_CERT.to_vec(),
			Some(URL.to_vec()),
			SgxAttestationMethod::Ias
		));
		assert!(<SovereignEnclaves<Test>>::contains_key(&signer4));

		assert!(Teerex::shield_funds(
			RuntimeOrigin::signed(AccountKeyring::Alice.to_account_id()),
			incognito_account.clone(),
			100,
			bonding_account.clone(),
		)
		.is_ok());

		assert_eq!(Balances::free_balance(bonding_account.clone()), 100);

		let expected_event = RuntimeEvent::Teerex(TeerexEvent::ShieldFunds(incognito_account));
		assert!(System::events().iter().any(|a| a.event == expected_event));

		assert!(Teerex::unshield_funds(
			RuntimeOrigin::signed(signer4),
			AccountKeyring::Alice.to_account_id(),
			50,
			bonding_account.clone(),
			call_hash
		)
		.is_ok());
		assert_eq!(Balances::free_balance(bonding_account), 50);

		let expected_event = RuntimeEvent::Teerex(TeerexEvent::UnshieldedFunds(
			AccountKeyring::Alice.to_account_id(),
		));
		assert!(System::events().iter().any(|a| a.event == expected_event));
	})
}

#[test]
fn unshield_funds_from_not_registered_enclave_errs() {
	new_test_ext().execute_with(|| {
		Timestamp::set_timestamp(TEST4_TIMESTAMP);
		let signer4 = get_signer(TEST4_SIGNER_PUB);
		let call_hash: H256 = H256::from([1u8; 32]);

		assert_eq!(list_enclaves().len(), 0);

		assert_err!(
			Teerex::unshield_funds(
				RuntimeOrigin::signed(signer4.clone()),
				AccountKeyring::Alice.to_account_id(),
				51,
				signer4,
				call_hash
			),
			Error::<Test>::EnclaveIsNotRegistered
		);
	})
}

#[test]
fn unshield_funds_from_enclave_neq_bonding_account_errs() {
	new_test_ext().execute_with(|| {
		Timestamp::set_timestamp(TEST7_TIMESTAMP);
		let signer4 = get_signer(TEST4_SIGNER_PUB);
		let call_hash: H256 = H256::from([1u8; 32]);
		let bonding_account = get_signer(&TEST4_MRENCLAVE);
		let incognito_account = INCOGNITO_ACCOUNT;
		let not_bonding_account = get_signer(&TEST7_MRENCLAVE);

		//Ensure that enclave is registered
		assert_ok!(Teerex::register_sgx_enclave(
			RuntimeOrigin::signed(signer4.clone()),
			TEST4_CERT.to_vec(),
			Some(URL.to_vec()),
			SgxAttestationMethod::Ias
		));

		//Ensure that bonding account has funds
		assert!(Teerex::shield_funds(
			RuntimeOrigin::signed(AccountKeyring::Alice.to_account_id()),
			incognito_account.to_vec(),
			100,
			bonding_account.clone(),
		)
		.is_ok());

		assert!(Teerex::shield_funds(
			RuntimeOrigin::signed(AccountKeyring::Alice.to_account_id()),
			incognito_account.to_vec(),
			50,
			not_bonding_account.clone(),
		)
		.is_ok());

		assert_err!(
			Teerex::unshield_funds(
				RuntimeOrigin::signed(signer4),
				AccountKeyring::Alice.to_account_id(),
				50,
				not_bonding_account.clone(),
				call_hash
			),
			Error::<Test>::WrongMrenclaveForBondingAccount
		);

		assert_eq!(Balances::free_balance(bonding_account), 100);
		assert_eq!(Balances::free_balance(not_bonding_account), 50);
	})
}

#[test]
fn confirm_processed_parentchain_block_works() {
	new_test_ext().execute_with(|| {
		Timestamp::set_timestamp(TEST7_TIMESTAMP);
		let block_hash = H256::default();
		let merkle_root = H256::default();
		let block_number = 3;
		let signer7 = get_signer(TEST7_SIGNER_PUB);

		//Ensure that enclave is registered
		assert_ok!(Teerex::register_sgx_enclave(
			RuntimeOrigin::signed(signer7.clone()),
			TEST7_CERT.to_vec(),
			Some(URL.to_vec()),
			SgxAttestationMethod::Ias
		));
		assert!(<SovereignEnclaves<Test>>::contains_key(&signer7));

		assert_ok!(Teerex::confirm_processed_parentchain_block(
			RuntimeOrigin::signed(signer7.clone()),
			block_hash,
			block_number,
			merkle_root,
		));

		let expected_event = RuntimeEvent::Teerex(TeerexEvent::ProcessedParentchainBlock(
			signer7,
			block_hash,
			merkle_root,
			block_number,
		));
		assert!(System::events().iter().any(|a| a.event == expected_event));
	})
}

#[test]
fn ensure_registered_enclave_works() {
	new_test_ext().execute_with(|| {
		Timestamp::set_timestamp(TEST4_TIMESTAMP);
		let signer4 = get_signer(TEST4_SIGNER_PUB);
		let signer6 = get_signer(TEST6_SIGNER_PUB);

		//Ensure that enclave is registered
		assert_ok!(Teerex::register_sgx_enclave(
			RuntimeOrigin::signed(signer4.clone()),
			TEST4_CERT.to_vec(),
			Some(URL.to_vec()),
			SgxAttestationMethod::Ias
		));
		assert_ok!(Teerex::ensure_registered_enclave(&signer4));
		assert_err!(
			Teerex::ensure_registered_enclave(&signer6),
			Error::<Test>::EnclaveIsNotRegistered
		);
	})
}

#[test]
fn publish_hash_works() {
	use frame_system::{EventRecord, Phase};

	new_test_ext().execute_with(|| {
		Timestamp::set_timestamp(TEST4_TIMESTAMP);
		let signer4 = get_signer(TEST4_SIGNER_PUB);

		//Ensure that enclave is registered
		assert_ok!(Teerex::register_sgx_enclave(
			RuntimeOrigin::signed(signer4.clone()),
			TEST4_CERT.to_vec(),
			Some(URL.to_vec()),
			SgxAttestationMethod::Ias
		));

		// There are no events emitted at the genesis block.
		System::set_block_number(1);
		System::reset_events();

		let hash = H256::from([1u8; 32]);
		let extra_topics = vec![H256::from([2u8; 32]), H256::from([3u8; 32])];
		let data = b"hello world".to_vec();

		// publish with extra topics and data
		assert_ok!(Teerex::publish_hash(
			RuntimeOrigin::signed(signer4.clone()),
			hash,
			extra_topics.clone(),
			data.clone()
		));

		// publish without extra topics and data
		assert_ok!(Teerex::publish_hash(
			RuntimeOrigin::signed(signer4.clone()),
			hash,
			vec![],
			vec![]
		));

		let mr_enclave = Teerex::sovereign_enclaves(&signer4).unwrap().fingerprint();
		let mut topics = extra_topics;
		topics.push(mr_enclave.into());

		// Check that topics are reflected in the event record.
		assert_eq!(
			System::events(),
			vec![
				EventRecord {
					phase: Phase::Initialization,
					event: TeerexEvent::PublishedHash {
						fingerprint: mr_enclave.into(),
						hash,
						data
					}
					.into(),
					topics,
				},
				EventRecord {
					phase: Phase::Initialization,
					event: TeerexEvent::PublishedHash {
						fingerprint: mr_enclave.into(),
						hash,
						data: vec![]
					}
					.into(),
					topics: vec![mr_enclave.into()],
				},
			]
		);
	})
}

#[test]
fn publish_hash_with_unregistered_enclave_fails() {
	new_test_ext().execute_with(|| {
		let signer4 = get_signer(TEST4_SIGNER_PUB);

		assert_err!(
			Teerex::publish_hash(RuntimeOrigin::signed(signer4), [1u8; 32].into(), vec![], vec![]),
			Error::<Test>::EnclaveIsNotRegistered
		);
	})
}

#[test]
fn publish_hash_with_too_many_topics_fails() {
	new_test_ext().execute_with(|| {
		Timestamp::set_timestamp(TEST4_TIMESTAMP);
		let signer4 = get_signer(TEST4_SIGNER_PUB);

		//Ensure that enclave is registered
		assert_ok!(Teerex::register_sgx_enclave(
			RuntimeOrigin::signed(signer4.clone()),
			TEST4_CERT.to_vec(),
			Some(URL.to_vec()),
			SgxAttestationMethod::Ias
		));

		let hash = H256::from([1u8; 32]);
		let extra_topics = vec![
			H256::from([0u8; 32]),
			H256::from([1u8; 32]),
			H256::from([2u8; 32]),
			H256::from([3u8; 32]),
			H256::from([4u8; 32]),
			H256::from([5u8; 32]),
		];

		assert_err!(
			Teerex::publish_hash(RuntimeOrigin::signed(signer4), hash, extra_topics, vec![]),
			Error::<Test>::TooManyTopics
		);
	})
}

#[test]
fn publish_hash_with_too_much_data_fails() {
	new_test_ext().execute_with(|| {
		Timestamp::set_timestamp(TEST4_TIMESTAMP);
		let signer4 = get_signer(TEST4_SIGNER_PUB);

		//Ensure that enclave is registered
		assert_ok!(Teerex::register_sgx_enclave(
			RuntimeOrigin::signed(signer4.clone()),
			TEST4_CERT.to_vec(),
			Some(URL.to_vec()),
			SgxAttestationMethod::Ias
		));

		let hash = H256::from([1u8; 32]);
		let data = vec![0u8; DATA_LENGTH_LIMIT + 1];

		assert_err!(
			Teerex::publish_hash(RuntimeOrigin::signed(signer4), hash, vec![], data),
			Error::<Test>::DataTooLong
		);
	})
}
