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

#![cfg(any(test, feature = "runtime-benchmarks"))]

use crate::Enclave;

pub fn get_signer<AccountId: From<[u8; 32]>>(pubkey: &[u8; 32]) -> AccountId {
    AccountId::from(*pubkey)
}

impl<AccountId, Url> Enclave<AccountId, Url> {
    pub fn with_pubkey(mut self, pubkey: AccountId) -> Self {
        self.pubkey = pubkey;
        self
    }

    pub fn with_mr_enclave(mut self, mr_enclave: [u8; 32]) -> Self {
        self.mr_enclave = mr_enclave;
        self
    }

    pub fn with_timestamp(mut self, timestamp: u64) -> Self {
        self.timestamp = timestamp;
        self
    }

    pub fn with_url(mut self, url: Url) -> Self {
        self.url = url;
        self
    }
}

pub mod ias {
    use super::consts::*;

    #[derive(Copy, Clone)]
    pub struct IasSetup {
        pub cert: &'static [u8],
        pub signer_pub: &'static [u8; 32],
        pub mrenclave: [u8; 32],
        pub timestamp: u64,
    }

    pub const TEST4_SETUP: IasSetup = IasSetup {
        cert: TEST4_CERT,
        signer_pub: TEST4_SIGNER_PUB,
        mrenclave: TEST4_MRENCLAVE,
        timestamp: TEST4_TIMESTAMP,
    };

    // todo: migrate tests to use IasSetup
    #[allow(unused)]
    pub const TEST5_SETUP: IasSetup = IasSetup {
        cert: TEST5_CERT,
        signer_pub: TEST5_SIGNER_PUB,
        mrenclave: TEST5_MRENCLAVE,
        timestamp: TEST5_TIMESTAMP,
    };

    #[allow(unused)]
    pub const TEST6_SETUP: IasSetup = IasSetup {
        cert: TEST6_CERT,
        signer_pub: TEST6_SIGNER_PUB,
        mrenclave: TEST6_MRENCLAVE,
        timestamp: TEST6_TIMESTAMP,
    };

    #[allow(unused)]
    pub const TEST7_SETUP: IasSetup = IasSetup {
        cert: TEST7_CERT,
        signer_pub: TEST7_SIGNER_PUB,
        mrenclave: TEST7_MRENCLAVE,
        timestamp: TEST7_TIMESTAMP,
    };
}

pub mod consts {
    use hex_literal::hex;

    pub const INCOGNITO_ACCOUNT: [u8; 32] = [
        44, 106, 196, 170, 141, 51, 4, 200, 143, 12, 167, 255, 252, 221, 15, 119, 228, 141, 94, 2,
        132, 145, 21, 17, 52, 41, 40, 220, 157, 130, 48, 176,
    ];

    // reproduce with "integritee_service dump_ra"
    pub const TEST4_CERT: &[u8] = include_bytes!("../ias-verify/test/ra_dump_cert_TEST4.der");
    pub const TEST5_CERT: &[u8] = include_bytes!("../ias-verify/test/ra_dump_cert_TEST5.der");
    pub const TEST6_CERT: &[u8] = include_bytes!("../ias-verify/test/ra_dump_cert_TEST6.der");
    pub const TEST7_CERT: &[u8] = include_bytes!("../ias-verify/test/ra_dump_cert_TEST7.der");
    pub const TEST8_CERT: &[u8] =
        include_bytes!("../ias-verify/test/ra_dump_cert_TEST8_PRODUCTION.der");

    // reproduce with integritee-service signing-key
    pub const TEST4_SIGNER_PUB: &[u8; 32] =
        include_bytes!("../ias-verify/test/enclave-signing-pubkey-TEST4.bin");
    // equal to TEST4! because of MRSIGNER policy it was possible to change the MRENCLAVE but keep the secret
    pub const TEST5_SIGNER_PUB: &[u8; 32] =
        include_bytes!("../ias-verify/test/enclave-signing-pubkey-TEST5.bin");
    pub const TEST6_SIGNER_PUB: &[u8; 32] =
        include_bytes!("../ias-verify/test/enclave-signing-pubkey-TEST6.bin");
    pub const TEST7_SIGNER_PUB: &[u8; 32] =
        include_bytes!("../ias-verify/test/enclave-signing-pubkey-TEST7.bin");
    pub const TEST8_SIGNER_PUB: &[u8; 32] =
        include_bytes!("../ias-verify/test/enclave-signing-pubkey-TEST8-PRODUCTION.bin");

    // reproduce with "make mrenclave" in worker repo root
    // MRSIGNER is always 83d719e77deaca1470f6baf62a4d774303c899db69020f9c70ee1dfc08c7ce9e
    pub const TEST4_MRENCLAVE: [u8; 32] =
        hex!("7a3454ec8f42e265cb5be7dfd111e1d95ac6076ed82a0948b2e2a45cf17b62a0");
    pub const TEST5_MRENCLAVE: [u8; 32] =
        hex!("f4dedfc9e5fcc48443332bc9b23161c34a3c3f5a692eaffdb228db27b704d9d1");
    pub const TEST6_MRENCLAVE: [u8; 32] =
        hex!("f4dedfc9e5fcc48443332bc9b23161c34a3c3f5a692eaffdb228db27b704d9d1");
    pub const TEST7_MRENCLAVE: [u8; 32] =
        hex!("f4dedfc9e5fcc48443332bc9b23161c34a3c3f5a692eaffdb228db27b704d9d1");
    // production mode
    // MRSIGNER is 117f95f65f06afb5764b572156b8b525c6230db7d6b1c94e8ebdb7fba068f4e8
    pub const TEST8_MRENCLAVE: [u8; 32] =
        hex!("bcf66abfc6b3ef259e9ecfe4cf8df667a7f5a546525dee16822741b38f6e6050");

    // unix epoch. must be later than this
    pub const TEST4_TIMESTAMP: u64 = 1587899785000;
    pub const TEST5_TIMESTAMP: u64 = 1587900013000;
    pub const TEST6_TIMESTAMP: u64 = 1587900233000;
    pub const TEST7_TIMESTAMP: u64 = 1587900450000;
    pub const TEST8_TIMESTAMP: u64 = 1634156700000;

    pub const TWENTY_FOUR_HOURS: u64 = 60 * 60 * 24 * 1000;

    pub const URL: &[u8] = &[
        119, 115, 58, 47, 47, 49, 50, 55, 46, 48, 46, 48, 46, 49, 58, 57, 57, 57, 49,
    ];
}
