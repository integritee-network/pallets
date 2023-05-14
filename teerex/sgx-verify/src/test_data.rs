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

pub mod ias {
	use super::consts::*;
	use teerex_primitives::MrEnclave;

	#[derive(Copy, Clone)]
	pub struct IasSetup {
		pub cert: &'static [u8],
		pub signer_pub: &'static [u8; 32],
		pub mrenclave: MrEnclave,
		pub timestamp: u64,
	}

	pub const TEST4_SETUP: IasSetup = IasSetup {
		cert: TEST4_CERT,
		signer_pub: TEST4_SIGNER_PUB,
		mrenclave: TEST4_MRENCLAVE,
		timestamp: TEST4_TIMESTAMP,
	};

	pub const TEST5_SETUP: IasSetup = IasSetup {
		cert: TEST5_CERT,
		signer_pub: TEST5_SIGNER_PUB,
		mrenclave: TEST5_MRENCLAVE,
		timestamp: TEST5_TIMESTAMP,
	};

	pub const TEST6_SETUP: IasSetup = IasSetup {
		cert: TEST6_CERT,
		signer_pub: TEST6_SIGNER_PUB,
		mrenclave: TEST6_MRENCLAVE,
		timestamp: TEST6_TIMESTAMP,
	};

	pub const TEST7_SETUP: IasSetup = IasSetup {
		cert: TEST7_CERT,
		signer_pub: TEST7_SIGNER_PUB,
		mrenclave: TEST7_MRENCLAVE,
		timestamp: TEST7_TIMESTAMP,
	};
}

pub mod dcap {
	use hex_literal::hex;

	pub const DCAP_QUOTE_CERT: &str = include_str!("../test-data/dcap/dcap_quote_cert.der");
	pub const TEST1_DCAP_QUOTE: &[u8] = include_bytes!("../test-data/ra_dcap_dump_quote.ra");
	pub const TEST1_DCAP_QUOTE_SIGNER: [u8; 32] = [
		65, 89, 193, 118, 86, 172, 17, 149, 206, 160, 174, 75, 219, 151, 51, 235, 110, 135, 20, 55,
		147, 162, 106, 110, 143, 207, 57, 64, 67, 63, 203, 95,
	];

	#[derive(Copy, Clone, Debug, PartialOrd, Ord, PartialEq, Eq)]
	pub struct QuotingEnclave {
		pub qe_identity_cert: &'static str,
		pub qe_identity_issuer_chain: &'static [u8],
		pub quoting_enclave: &'static [u8],
		pub quoting_enclave_signature: [u8; 64],
	}

	pub const TEST1_QUOTING_ENCLAVE: QuotingEnclave = QuotingEnclave {
		qe_identity_cert: QE_IDENTITY_CERT,
		qe_identity_issuer_chain: QE_IDENTITY_ISSUER_CHAIN,
		quoting_enclave: QUOTING_ENCLAVE,
		quoting_enclave_signature: QUOTING_ENCLAVE_SIGNATURE,
	};

	pub const PCK_CRL: &[u8] = include_bytes!("../test-data/dcap/pck_crl.der");

	pub const QE_IDENTITY_CERT: &str = include_str!("../test-data/dcap/qe_identity_cert.pem");
	pub const QE_IDENTITY_ISSUER_CHAIN: &[u8] =
		include_bytes!("../test-data/dcap/qe_identity_issuer_chain.pem");
	pub const QUOTING_ENCLAVE: &[u8] = br#"{"id":"QE","version":2,"issueDate":"2022-12-04T22:45:33Z","nextUpdate":"2023-01-03T22:45:33Z","tcbEvaluationDataNumber":13,"miscselect":"00000000","miscselectMask":"FFFFFFFF","attributes":"11000000000000000000000000000000","attributesMask":"FBFFFFFFFFFFFFFF0000000000000000","mrsigner":"8C4F5775D796503E96137F77C68A829A0056AC8DED70140B081B094490C57BFF","isvprodid":1,"tcbLevels":[{"tcb":{"isvsvn":6},"tcbDate":"2022-11-09T00:00:00Z","tcbStatus":"UpToDate"},{"tcb":{"isvsvn":5},"tcbDate":"2020-11-11T00:00:00Z","tcbStatus":"OutOfDate","advisoryIDs":["INTEL-SA-00477"]},{"tcb":{"isvsvn":4},"tcbDate":"2019-11-13T00:00:00Z","tcbStatus":"OutOfDate","advisoryIDs":["INTEL-SA-00334","INTEL-SA-00477"]},{"tcb":{"isvsvn":2},"tcbDate":"2019-05-15T00:00:00Z","tcbStatus":"OutOfDate","advisoryIDs":["INTEL-SA-00219","INTEL-SA-00293","INTEL-SA-00334","INTEL-SA-00477"]},{"tcb":{"isvsvn":1},"tcbDate":"2018-08-15T00:00:00Z","tcbStatus":"OutOfDate","advisoryIDs":["INTEL-SA-00202","INTEL-SA-00219","INTEL-SA-00293","INTEL-SA-00334","INTEL-SA-00477"]}]}"#;
	pub const QUOTING_ENCLAVE_SIGNATURE: [u8; 64] = hex!("47accba321e57c20722a0d3d1db11c9b52661239857dc578ca1bde13976ee288cf39f72111ffe445c7389ef56447c79e30e6b83a8863ed9880de5bde4a8d5c91");

	#[derive(Copy, Clone, Debug, PartialOrd, Ord, PartialEq, Eq)]
	pub struct TcbInfo {
		pub tcb_info: &'static [u8],
		pub signature: [u8; 64],
		pub certificate_chain: &'static [u8],
	}

	pub const TEST1_TCB_INFO: TcbInfo = TcbInfo {
		tcb_info: TCB_INFO,
		signature: TCB_INFO_SIGNATURE,
		certificate_chain: TCB_INFO_CERTIFICATE_CHAIN,
	};

	pub const TCB_INFO: &[u8] = br#"{"id":"SGX","version":3,"issueDate":"2022-11-17T12:45:32Z","nextUpdate":"2023-04-16T12:45:32Z","fmspc":"00906EA10000","pceId":"0000","tcbType":0,"tcbEvaluationDataNumber":12,"tcbLevels":[{"tcb":{"sgxtcbcomponents":[{"svn":17},{"svn":17},{"svn":2},{"svn":4},{"svn":1},{"svn":128},{"svn":7},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0}],"pcesvn":11},"tcbDate":"2021-11-10T00:00:00Z","tcbStatus":"SWHardeningNeeded","advisoryIDs":["INTEL-SA-00334"]},{"tcb":{"sgxtcbcomponents":[{"svn":17},{"svn":17},{"svn":2},{"svn":4},{"svn":1},{"svn":128},{"svn":7},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0}],"pcesvn":10},"tcbDate":"2020-11-11T00:00:00Z","tcbStatus":"OutOfDate","advisoryIDs":["INTEL-SA-00161","INTEL-SA-00219","INTEL-SA-00289","INTEL-SA-00334"]},{"tcb":{"sgxtcbcomponents":[{"svn":17},{"svn":17},{"svn":2},{"svn":4},{"svn":1},{"svn":128},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0}],"pcesvn":11},"tcbDate":"2021-11-10T00:00:00Z","tcbStatus":"ConfigurationAndSWHardeningNeeded","advisoryIDs":["INTEL-SA-00161","INTEL-SA-00219","INTEL-SA-00289","INTEL-SA-00334"]},{"tcb":{"sgxtcbcomponents":[{"svn":17},{"svn":17},{"svn":2},{"svn":4},{"svn":1},{"svn":128},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0}],"pcesvn":10},"tcbDate":"2020-11-11T00:00:00Z","tcbStatus":"OutOfDateConfigurationNeeded","advisoryIDs":["INTEL-SA-00477","INTEL-SA-00161","INTEL-SA-00219","INTEL-SA-00289","INTEL-SA-00334"]},{"tcb":{"sgxtcbcomponents":[{"svn":15},{"svn":15},{"svn":2},{"svn":4},{"svn":1},{"svn":128},{"svn":7},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0}],"pcesvn":10},"tcbDate":"2020-06-10T00:00:00Z","tcbStatus":"OutOfDate","advisoryIDs":["INTEL-SA-00381","INTEL-SA-00389","INTEL-SA-00477","INTEL-SA-00161","INTEL-SA-00219","INTEL-SA-00289","INTEL-SA-00334"]},{"tcb":{"sgxtcbcomponents":[{"svn":15},{"svn":15},{"svn":2},{"svn":4},{"svn":1},{"svn":128},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0}],"pcesvn":10},"tcbDate":"2020-06-10T00:00:00Z","tcbStatus":"OutOfDateConfigurationNeeded","advisoryIDs":["INTEL-SA-00161","INTEL-SA-00219","INTEL-SA-00289","INTEL-SA-00381","INTEL-SA-00389","INTEL-SA-00477","INTEL-SA-00334"]},{"tcb":{"sgxtcbcomponents":[{"svn":14},{"svn":14},{"svn":2},{"svn":4},{"svn":1},{"svn":128},{"svn":7},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0}],"pcesvn":10},"tcbDate":"2019-12-11T00:00:00Z","tcbStatus":"OutOfDate","advisoryIDs":["INTEL-SA-00320","INTEL-SA-00329","INTEL-SA-00161","INTEL-SA-00219","INTEL-SA-00289","INTEL-SA-00381","INTEL-SA-00389","INTEL-SA-00477","INTEL-SA-00334"]},{"tcb":{"sgxtcbcomponents":[{"svn":14},{"svn":14},{"svn":2},{"svn":4},{"svn":1},{"svn":128},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0}],"pcesvn":10},"tcbDate":"2019-12-11T00:00:00Z","tcbStatus":"OutOfDateConfigurationNeeded","advisoryIDs":["INTEL-SA-00161","INTEL-SA-00219","INTEL-SA-00289","INTEL-SA-00320","INTEL-SA-00329","INTEL-SA-00381","INTEL-SA-00389","INTEL-SA-00477","INTEL-SA-00334"]},{"tcb":{"sgxtcbcomponents":[{"svn":13},{"svn":13},{"svn":2},{"svn":4},{"svn":1},{"svn":128},{"svn":3},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0}],"pcesvn":9},"tcbDate":"2019-11-13T00:00:00Z","tcbStatus":"OutOfDate","advisoryIDs":["INTEL-SA-00161","INTEL-SA-00219","INTEL-SA-00289","INTEL-SA-00320","INTEL-SA-00329","INTEL-SA-00381","INTEL-SA-00389","INTEL-SA-00477","INTEL-SA-00334"]},{"tcb":{"sgxtcbcomponents":[{"svn":13},{"svn":13},{"svn":2},{"svn":4},{"svn":1},{"svn":128},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0}],"pcesvn":9},"tcbDate":"2019-11-13T00:00:00Z","tcbStatus":"OutOfDateConfigurationNeeded","advisoryIDs":["INTEL-SA-00161","INTEL-SA-00219","INTEL-SA-00289","INTEL-SA-00320","INTEL-SA-00329","INTEL-SA-00381","INTEL-SA-00389","INTEL-SA-00477","INTEL-SA-00334"]},{"tcb":{"sgxtcbcomponents":[{"svn":6},{"svn":6},{"svn":2},{"svn":4},{"svn":1},{"svn":128},{"svn":1},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0}],"pcesvn":7},"tcbDate":"2019-05-15T00:00:00Z","tcbStatus":"OutOfDate","advisoryIDs":["INTEL-SA-00220","INTEL-SA-00270","INTEL-SA-00293","INTEL-SA-00161","INTEL-SA-00219","INTEL-SA-00289","INTEL-SA-00320","INTEL-SA-00329","INTEL-SA-00381","INTEL-SA-00389","INTEL-SA-00477","INTEL-SA-00334"]},{"tcb":{"sgxtcbcomponents":[{"svn":6},{"svn":6},{"svn":2},{"svn":4},{"svn":1},{"svn":128},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0}],"pcesvn":7},"tcbDate":"2019-05-15T00:00:00Z","tcbStatus":"OutOfDateConfigurationNeeded","advisoryIDs":["INTEL-SA-00161","INTEL-SA-00220","INTEL-SA-00270","INTEL-SA-00293","INTEL-SA-00219","INTEL-SA-00289","INTEL-SA-00320","INTEL-SA-00329","INTEL-SA-00381","INTEL-SA-00389","INTEL-SA-00477","INTEL-SA-00334"]},{"tcb":{"sgxtcbcomponents":[{"svn":5},{"svn":5},{"svn":2},{"svn":4},{"svn":1},{"svn":128},{"svn":1},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0}],"pcesvn":7},"tcbDate":"2019-01-09T00:00:00Z","tcbStatus":"OutOfDate","advisoryIDs":["INTEL-SA-00233","INTEL-SA-00161","INTEL-SA-00220","INTEL-SA-00270","INTEL-SA-00293","INTEL-SA-00219","INTEL-SA-00289","INTEL-SA-00320","INTEL-SA-00329","INTEL-SA-00381","INTEL-SA-00389","INTEL-SA-00477","INTEL-SA-00334"]},{"tcb":{"sgxtcbcomponents":[{"svn":5},{"svn":5},{"svn":2},{"svn":4},{"svn":1},{"svn":128},{"svn":1},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0}],"pcesvn":6},"tcbDate":"2018-08-15T00:00:00Z","tcbStatus":"OutOfDate","advisoryIDs":["INTEL-SA-00161","INTEL-SA-00233","INTEL-SA-00220","INTEL-SA-00270","INTEL-SA-00293","INTEL-SA-00219","INTEL-SA-00289","INTEL-SA-00320","INTEL-SA-00329","INTEL-SA-00381","INTEL-SA-00389","INTEL-SA-00477","INTEL-SA-00334"]},{"tcb":{"sgxtcbcomponents":[{"svn":5},{"svn":5},{"svn":2},{"svn":4},{"svn":1},{"svn":128},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0}],"pcesvn":7},"tcbDate":"2019-01-09T00:00:00Z","tcbStatus":"OutOfDateConfigurationNeeded","advisoryIDs":["INTEL-SA-00161","INTEL-SA-00233","INTEL-SA-00220","INTEL-SA-00270","INTEL-SA-00293","INTEL-SA-00219","INTEL-SA-00289","INTEL-SA-00320","INTEL-SA-00329","INTEL-SA-00381","INTEL-SA-00389","INTEL-SA-00477","INTEL-SA-00334"]},{"tcb":{"sgxtcbcomponents":[{"svn":5},{"svn":5},{"svn":2},{"svn":4},{"svn":1},{"svn":128},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0}],"pcesvn":6},"tcbDate":"2018-08-15T00:00:00Z","tcbStatus":"OutOfDateConfigurationNeeded","advisoryIDs":["INTEL-SA-00203","INTEL-SA-00161","INTEL-SA-00233","INTEL-SA-00220","INTEL-SA-00270","INTEL-SA-00293","INTEL-SA-00219","INTEL-SA-00289","INTEL-SA-00320","INTEL-SA-00329","INTEL-SA-00381","INTEL-SA-00389","INTEL-SA-00477","INTEL-SA-00334"]},{"tcb":{"sgxtcbcomponents":[{"svn":4},{"svn":4},{"svn":2},{"svn":4},{"svn":1},{"svn":128},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0}],"pcesvn":5},"tcbDate":"2018-01-04T00:00:00Z","tcbStatus":"OutOfDate","advisoryIDs":["INTEL-SA-00106","INTEL-SA-00115","INTEL-SA-00135","INTEL-SA-00203","INTEL-SA-00161","INTEL-SA-00233","INTEL-SA-00220","INTEL-SA-00270","INTEL-SA-00293","INTEL-SA-00219","INTEL-SA-00289","INTEL-SA-00320","INTEL-SA-00329","INTEL-SA-00381","INTEL-SA-00389","INTEL-SA-00477","INTEL-SA-00334"]},{"tcb":{"sgxtcbcomponents":[{"svn":2},{"svn":2},{"svn":2},{"svn":4},{"svn":1},{"svn":128},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0}],"pcesvn":4},"tcbDate":"2017-07-26T00:00:00Z","tcbStatus":"OutOfDate","advisoryIDs":["INTEL-SA-00088","INTEL-SA-00106","INTEL-SA-00115","INTEL-SA-00135","INTEL-SA-00203","INTEL-SA-00161","INTEL-SA-00233","INTEL-SA-00220","INTEL-SA-00270","INTEL-SA-00293","INTEL-SA-00219","INTEL-SA-00289","INTEL-SA-00320","INTEL-SA-00329","INTEL-SA-00381","INTEL-SA-00389","INTEL-SA-00477","INTEL-SA-00334"]}]}"#;
	pub const TCB_INFO_SIGNATURE: [u8; 64] =  hex!("71746f2148ecba04e35cf1ac77a7e6267ce99f6781c1031f724bb5bd94b8c1b6e4c07c01dc151692aa75be80dfba7350bb80c58314a6975189597e28e9bbc75c");
	pub const TCB_INFO_CERTIFICATE_CHAIN: &[u8] =
		include_bytes!("../test-data/dcap/tcb_info_issuer_chain.pem");

	/// Timestamp for which the collateral data must be valid. Represents 2022-12-21 08:12:27
	pub const TEST_VALID_COLLATERAL_TIMESTAMP: u64 = 1671606747000;
}

pub mod consts {
	use hex_literal::hex;
	use teerex_primitives::{MrEnclave, MrSigner};

	pub const INCOGNITO_ACCOUNT: [u8; 32] = [
		44, 106, 196, 170, 141, 51, 4, 200, 143, 12, 167, 255, 252, 221, 15, 119, 228, 141, 94, 2,
		132, 145, 21, 17, 52, 41, 40, 220, 157, 130, 48, 176,
	];

	// reproduce with "integritee_service dump_ra"
	pub const TEST4_CERT: &[u8] = include_bytes!("../test-data/ra_dump_cert_TEST4.der");
	pub const TEST5_CERT: &[u8] = include_bytes!("../test-data/ra_dump_cert_TEST5.der");
	pub const TEST6_CERT: &[u8] = include_bytes!("../test-data/ra_dump_cert_TEST6.der");
	pub const TEST7_CERT: &[u8] = include_bytes!("../test-data/ra_dump_cert_TEST7.der");
	pub const TEST8_CERT: &[u8] = include_bytes!("../test-data/ra_dump_cert_TEST8_PRODUCTION.der");

	// reproduce with integritee-service signing-key
	pub const TEST4_SIGNER_PUB: &MrSigner =
		include_bytes!("../test-data/enclave-signing-pubkey-TEST4.bin");
	// equal to TEST4! because of MRSIGNER policy it was possible to change the MRENCLAVE but keep the secret
	pub const TEST5_SIGNER_PUB: &MrSigner =
		include_bytes!("../test-data/enclave-signing-pubkey-TEST5.bin");
	pub const TEST6_SIGNER_PUB: &MrSigner =
		include_bytes!("../test-data/enclave-signing-pubkey-TEST6.bin");
	pub const TEST7_SIGNER_PUB: &MrSigner =
		include_bytes!("../test-data/enclave-signing-pubkey-TEST7.bin");
	pub const TEST8_SIGNER_PUB: &MrSigner =
		include_bytes!("../test-data/enclave-signing-pubkey-TEST8-PRODUCTION.bin");

	// reproduce with "make mrenclave" in worker repo root
	// MRSIGNER is always 83d719e77deaca1470f6baf62a4d774303c899db69020f9c70ee1dfc08c7ce9e
	pub const TEST4_MRENCLAVE: MrEnclave =
		hex!("7a3454ec8f42e265cb5be7dfd111e1d95ac6076ed82a0948b2e2a45cf17b62a0");
	pub const TEST5_MRENCLAVE: MrEnclave =
		hex!("f4dedfc9e5fcc48443332bc9b23161c34a3c3f5a692eaffdb228db27b704d9d1");
	pub const TEST6_MRENCLAVE: MrEnclave =
		hex!("f4dedfc9e5fcc48443332bc9b23161c34a3c3f5a692eaffdb228db27b704d9d1");
	pub const TEST7_MRENCLAVE: MrEnclave =
		hex!("f4dedfc9e5fcc48443332bc9b23161c34a3c3f5a692eaffdb228db27b704d9d1");
	// production mode
	// MRSIGNER is 117f95f65f06afb5764b572156b8b525c6230db7d6b1c94e8ebdb7fba068f4e8
	pub const TEST8_MRENCLAVE: MrEnclave =
		hex!("bcf66abfc6b3ef259e9ecfe4cf8df667a7f5a546525dee16822741b38f6e6050");

	// unix epoch. must be later than this
	pub const TEST4_TIMESTAMP: u64 = 1587899785000;
	pub const TEST5_TIMESTAMP: u64 = 1587900013000;
	pub const TEST6_TIMESTAMP: u64 = 1587900233000;
	pub const TEST7_TIMESTAMP: u64 = 1587900450000;
	pub const TEST8_TIMESTAMP: u64 = 1634156700000;

	pub const TWENTY_FOUR_HOURS: u64 = 60 * 60 * 24 * 1000;

	pub const URL: &[u8] =
		&[119, 115, 58, 47, 47, 49, 50, 55, 46, 48, 46, 48, 46, 49, 58, 57, 57, 57, 49];
}
