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
	AllowSkippingAttestation, Error, Event as TeerexEvent, ProxiedEnclaves, SgxAllowDebugMode,
	SgxEnclave, SovereignEnclaves,
};
use frame_support::{assert_err, assert_ok, traits::StorageInstance, StorageValue};
use hex_literal::hex;
use pallet_aura::CurrentSlot;
use sgx_verify::{
	collateral::EnclaveIdentity,
	test_data::dcap::{
		QUOTING_ENCLAVE, TEST1_DCAP_QUOTE_MRENCLAVE, TEST1_DCAP_QUOTE_SIGNER, TEST2_DCAP_QUOTE_HEX,
	},
	verify_dcap_quote,
};
use sp_consensus_aura::Slot;
use sp_keyring::AccountKeyring;

use teerex_primitives::{
	AnySigner, EnclaveInstanceAddress, MultiEnclave, SgxAttestationMethod, SgxBuildMode,
	SgxReportData, SgxStatus, SgxTcbInfoOnChain, TcbStatus, TcbVersionStatus,
};
use test_utils::test_data::{
	consts::*,
	dcap::{TEST1_DCAP_QUOTE, TEST_VALID_COLLATERAL_TIMESTAMP},
};

fn list_sovereign_enclaves() -> Vec<(AccountId, MultiEnclave<Vec<u8>>)> {
	<SovereignEnclaves<Test>>::iter().collect::<Vec<(AccountId, MultiEnclave<Vec<u8>>)>>()
}

fn list_proxied_enclaves() -> Vec<(EnclaveInstanceAddress<AccountId>, MultiEnclave<Vec<u8>>)> {
	<ProxiedEnclaves<Test>>::iter()
		.collect::<Vec<(EnclaveInstanceAddress<AccountId>, MultiEnclave<Vec<u8>>)>>()
}

// give get_signer a concrete type
fn get_signer(pubkey: &[u8; 32]) -> AccountId {
	test_utils::get_signer(pubkey)
}

fn set_timestamp(moment: u64) {
	<pallet_aura::CurrentSlot<Test> as StorageValue<Slot>>::put(Slot::from(
		moment / SlotDuration::get(),
	));
	Timestamp::set_timestamp(moment);
}

#[test]
fn set_security_flags_works() {
	new_test_ext().execute_with(|| {
		assert_ok!(Teerex::set_security_flags(RuntimeOrigin::root(), true, false));
		assert_eq!(<AllowSkippingAttestation<Test>>::get(), true);
		assert_eq!(<SgxAllowDebugMode<Test>>::get(), false);
		let expected_event = RuntimeEvent::Teerex(TeerexEvent::UpdatedSecurityFlags {
			allow_skipping_attestation: true,
			sgx_allow_debug_mode: false,
		});
		assert!(System::events().iter().any(|a| a.event == expected_event))
	})
}

#[test]
fn set_security_flags_as_non_root_fails() {
	new_test_ext().execute_with(|| {
		let alice = AccountKeyring::Alice.to_account_id();
		assert!(Teerex::set_security_flags(RuntimeOrigin::signed(alice), true, false).is_err());
	})
}

#[test]
fn add_and_remove_dcap_enclave_works() {
	new_test_ext().execute_with(|| {
		set_timestamp(TEST_VALID_COLLATERAL_TIMESTAMP);

		let alice = AccountKeyring::Alice.to_account_id();
		register_test_quoting_enclave::<Test>(alice.clone());
		register_test_tcb_info::<Test>(alice.clone());

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
		set_timestamp(TEST_VALID_COLLATERAL_TIMESTAMP + <MaxAttestationRenewalPeriod>::get() + 1);
		assert_ok!(Teerex::unregister_sovereign_enclave(
			RuntimeOrigin::signed(alice.clone()),
			signer.clone()
		));
		assert!(!<SovereignEnclaves<Test>>::contains_key(&signer));
		assert_eq!(list_sovereign_enclaves(), vec![])
	})
}

#[test]
fn add_and_remove_dcap_proxied_enclave_works() {
	new_test_ext().execute_with(|| {
		set_timestamp(TEST_VALID_COLLATERAL_TIMESTAMP);

		let alice = AccountKeyring::Alice.to_account_id();
		register_test_quoting_enclave::<Test>(alice.clone());
		register_test_tcb_info::<Test>(alice.clone());

		let instance_address = EnclaveInstanceAddress {
			fingerprint: TEST1_DCAP_QUOTE_MRENCLAVE.into(),
			registrar: alice.clone(),
			signer: AnySigner::try_from(TEST1_DCAP_QUOTE_SIGNER).unwrap(),
		};

		assert_ok!(Teerex::register_sgx_enclave(
			RuntimeOrigin::signed(alice.clone()),
			TEST1_DCAP_QUOTE.to_vec(),
			None,
			SgxAttestationMethod::Dcap { proxied: true }
		));
		assert_eq!(list_proxied_enclaves().len(), 1);
		assert!(<ProxiedEnclaves<Test>>::contains_key(&instance_address));
		set_timestamp(TEST_VALID_COLLATERAL_TIMESTAMP + <MaxAttestationRenewalPeriod>::get() + 1);
		assert_ok!(Teerex::unregister_proxied_enclave(
			RuntimeOrigin::signed(alice.clone()),
			instance_address.clone()
		));
		assert!(!<ProxiedEnclaves<Test>>::contains_key(&instance_address));
		assert_eq!(list_proxied_enclaves(), vec![])
	})
}

#[test]
fn outdated_tcb_status_is_reported_correctly() {
	let tcb_info_onchain = SgxTcbInfoOnChain::new(
		1693476000000,
		1914399873000,
		vec![TcbVersionStatus::new(
			hex!("0C0C0303FFFF00000000000000000000"),
			13,
			TcbStatus::OutOfDate,
		)],
	);
	let qe_identity: EnclaveIdentity = serde_json::from_slice(QUOTING_ENCLAVE).unwrap();
	let quoting_enclave = qe_identity.to_quoting_enclave();

	let quote_bytes = hex::decode(TEST2_DCAP_QUOTE_HEX.trim()).unwrap();
	let (_fmspc, tcb_info, _report) =
		verify_dcap_quote(quote_bytes.as_slice(), 1693475073000, &quoting_enclave).unwrap();
	assert_eq!(tcb_info_onchain.verify_examinee(&tcb_info), Some(SgxStatus::GroupOutOfDate));
}

#[test]
fn skip_attestation_add_sovereign_enclave_works_if_allowed() {
	new_test_ext().execute_with(|| {
		set_timestamp(TEST_VALID_COLLATERAL_TIMESTAMP);
		<AllowSkippingAttestation<Test>>::set(true);
		let alice = AccountKeyring::Alice.to_account_id();
		assert_ok!(Teerex::register_sgx_enclave(
			RuntimeOrigin::signed(alice.clone()),
			TEST1_DCAP_QUOTE.to_vec(),
			Some(URL.to_vec()),
			SgxAttestationMethod::Skip { proxied: false }
		));
		assert!(<SovereignEnclaves<Test>>::contains_key(&alice));
		if let MultiEnclave::Sgx(sgx_enclave) = Teerex::sovereign_enclaves(&alice).unwrap() {
			assert_eq!(
				sgx_enclave.attestation_method,
				SgxAttestationMethod::Skip { proxied: false }
			);
		} else {
			panic!("wrong enclave type")
		}

		<AllowSkippingAttestation<Test>>::set(false);
		assert_err!(
			Teerex::register_sgx_enclave(
				RuntimeOrigin::signed(alice.clone()),
				TEST1_DCAP_QUOTE.to_vec(),
				Some(URL.to_vec()),
				SgxAttestationMethod::Skip { proxied: false }
			),
			Error::<Test>::SkippingAttestationIsNotAllowed
		);
	})
}

#[test]
fn skip_attestation_add_proxied_enclave_works_if_allowed() {
	new_test_ext().execute_with(|| {
		set_timestamp(TEST_VALID_COLLATERAL_TIMESTAMP);
		<AllowSkippingAttestation<Test>>::set(true);
		let alice = AccountKeyring::Alice.to_account_id();
		let instance_address = EnclaveInstanceAddress {
			fingerprint: TEST1_DCAP_QUOTE_MRENCLAVE.into(),
			registrar: alice.clone(),
			signer: AnySigner::from(AccountKeyring::Alice.public().0),
		};

		assert_ok!(Teerex::register_sgx_enclave(
			RuntimeOrigin::signed(alice.clone()),
			TEST1_DCAP_QUOTE_MRENCLAVE.to_vec(),
			None,
			SgxAttestationMethod::Skip { proxied: true }
		));
		assert_eq!(list_proxied_enclaves()[0].0, instance_address);
		assert!(<ProxiedEnclaves<Test>>::contains_key(&instance_address));
		if let MultiEnclave::Sgx(sgx_enclave) = Teerex::proxied_enclaves(&instance_address).unwrap()
		{
			assert_eq!(
				sgx_enclave.attestation_method,
				SgxAttestationMethod::Skip { proxied: true }
			);
		} else {
			panic!("wrong enclave type")
		}

		<AllowSkippingAttestation<Test>>::set(false);
		assert_err!(
			Teerex::register_sgx_enclave(
				RuntimeOrigin::signed(alice.clone()),
				TEST1_DCAP_QUOTE.to_vec(),
				Some(URL.to_vec()),
				SgxAttestationMethod::Skip { proxied: false }
			),
			Error::<Test>::SkippingAttestationIsNotAllowed
		);
	})
}

#[test]
fn unregister_active_sovereign_enclave_fails() {
	new_test_ext().execute_with(|| {
		set_timestamp(TEST_VALID_COLLATERAL_TIMESTAMP);
		let alice = AccountKeyring::Alice.to_account_id();
		register_test_quoting_enclave::<Test>(alice.clone());
		register_test_tcb_info::<Test>(alice.clone());

		let signer = get_signer(&TEST1_DCAP_QUOTE_SIGNER);
		assert_ok!(Teerex::register_sgx_enclave(
			RuntimeOrigin::signed(signer.clone()),
			TEST1_DCAP_QUOTE.to_vec(),
			Some(URL.to_vec()),
			SgxAttestationMethod::Dcap { proxied: false }
		));
		assert!(<SovereignEnclaves<Test>>::contains_key(&signer));

		set_timestamp(
			TEST_VALID_COLLATERAL_TIMESTAMP + <MaxAttestationRenewalPeriod>::get() / 2 + 1,
		);

		assert_err!(
			Teerex::unregister_sovereign_enclave(
				RuntimeOrigin::signed(alice.clone()),
				signer.clone()
			),
			Error::<Test>::UnregisterActiveEnclaveIsNotAllowed
		);
		assert!(<SovereignEnclaves<Test>>::contains_key(&signer));
	})
}

#[test]
fn unregister_active_proxied_enclave_fails() {
	new_test_ext().execute_with(|| {
		set_timestamp(TEST_VALID_COLLATERAL_TIMESTAMP);

		let alice = AccountKeyring::Alice.to_account_id();
		register_test_quoting_enclave::<Test>(alice.clone());
		register_test_tcb_info::<Test>(alice.clone());

		let instance_address = EnclaveInstanceAddress {
			fingerprint: TEST1_DCAP_QUOTE_MRENCLAVE.into(),
			registrar: alice.clone(),
			signer: AnySigner::try_from(TEST1_DCAP_QUOTE_SIGNER).unwrap(),
		};

		assert_ok!(Teerex::register_sgx_enclave(
			RuntimeOrigin::signed(alice.clone()),
			TEST1_DCAP_QUOTE.to_vec(),
			None,
			SgxAttestationMethod::Dcap { proxied: true }
		));
		assert!(<ProxiedEnclaves<Test>>::contains_key(&instance_address));

		set_timestamp(
			TEST_VALID_COLLATERAL_TIMESTAMP + <MaxAttestationRenewalPeriod>::get() / 2 + 1,
		);

		assert_err!(
			Teerex::unregister_proxied_enclave(
				RuntimeOrigin::signed(alice.clone()),
				instance_address.clone(),
			),
			Error::<Test>::UnregisterActiveEnclaveIsNotAllowed
		);
		assert!(<ProxiedEnclaves<Test>>::contains_key(&instance_address));
	})
}

#[test]
fn register_quoting_enclave_works() {
	new_test_ext().execute_with(|| {
		let alice = AccountKeyring::Alice.to_account_id();
		let qe = Teerex::quoting_enclave();
		assert_eq!(qe.mrsigner, [0u8; 32]);
		assert_eq!(qe.isvprodid, 0);
		set_timestamp(TEST_VALID_COLLATERAL_TIMESTAMP);
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
		set_timestamp(TEST_VALID_COLLATERAL_TIMESTAMP);

		register_test_tcb_info::<Test>(AccountKeyring::Alice.to_account_id());
		let fmspc = hex!("00906EA10000");
		let tcb_info = Teerex::tcb_info(fmspc).unwrap();
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
		set_timestamp(TEST4_TIMESTAMP);
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
		set_timestamp(TEST4_TIMESTAMP);
		let alice = AccountKeyring::Alice.to_account_id();
		let signer = get_signer(TEST4_SIGNER_PUB);
		assert_ok!(Teerex::register_sgx_enclave(
			RuntimeOrigin::signed(signer.clone()),
			TEST4_CERT.to_vec(),
			Some(URL.to_vec()),
			SgxAttestationMethod::Ias
		));
		assert!(<SovereignEnclaves<Test>>::contains_key(&signer));

		set_timestamp(TEST4_TIMESTAMP + <MaxAttestationRenewalPeriod>::get() + 1);
		assert_ok!(Teerex::unregister_sovereign_enclave(
			RuntimeOrigin::signed(alice.clone()),
			signer.clone()
		));
		assert!(!<SovereignEnclaves<Test>>::contains_key(&signer));
		assert_eq!(list_sovereign_enclaves(), vec![])
	})
}

#[test]
fn add_enclave_without_timestamp_fails() {
	new_test_ext().execute_with(|| {
		set_timestamp(0);
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
		set_timestamp(TEST4_TIMESTAMP);
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
		let enclaves = list_sovereign_enclaves();
		assert_eq!(enclaves[0].1, MultiEnclave::from(e_1));
	})
}

#[test]
fn register_ias_enclave_with_different_signer_fails() {
	new_test_ext().execute_with(|| {
		let signer = get_signer(TEST7_SIGNER_PUB);
		set_timestamp(TEST7_TIMESTAMP);
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
		set_timestamp(TEST7_TIMESTAMP + TWENTY_FOUR_HOURS + 1);
		let signer = get_signer(TEST7_SIGNER_PUB);
		assert_err!(
			Teerex::register_sgx_enclave(
				RuntimeOrigin::signed(signer),
				TEST7_CERT.to_vec(),
				Some(URL.to_vec()),
				SgxAttestationMethod::Ias
			),
			Error::<Test>::RemoteAttestationIsTooOld
		);
	})
}

#[test]
fn register_ias_enclave_with_almost_too_old_report_works() {
	new_test_ext().execute_with(|| {
		set_timestamp(TEST7_TIMESTAMP + TWENTY_FOUR_HOURS - 1);
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
		set_timestamp(TEST4_TIMESTAMP);

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
		let enclaves = list_sovereign_enclaves();
		assert!(enclaves.contains(&(signer4, MultiEnclave::from(e_0))));
	})
}

#[test]
fn production_mode_enclave_attest_works_when_sgx_debug_mode_is_allowed() {
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
		let enclaves = list_sovereign_enclaves();
		assert!(enclaves.contains(&(signer8, MultiEnclave::from(e_0))));
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
			Error::<Test>::SgxModeIsNotAllowed
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
		let enclaves = list_sovereign_enclaves();
		assert!(enclaves.contains(&(signer8, MultiEnclave::from(e_0))));
	})
}
