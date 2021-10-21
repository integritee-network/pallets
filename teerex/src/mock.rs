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

// Creating mock runtime here
use crate as pallet_teerex;
use frame_support::pallet_prelude::ProvideInherent;
use frame_support::parameter_types;
use frame_support::traits::{OnFinalize, OnInitialize, UnfilteredDispatchable};

use frame_system as system;
use pallet_teerex::Config;
use sp_core::H256;
use sp_keyring::AccountKeyring;
use sp_runtime::{
    generic,
    traits::{BlakeTwo256, IdentifyAccount, IdentityLookup, Verify},
};

pub type Signature = sp_runtime::MultiSignature;
pub type AccountId = <<Signature as Verify>::Signer as IdentifyAccount>::AccountId;
pub type Address = sp_runtime::MultiAddress<AccountId, ()>;

pub type BlockNumber = u32;
pub type Header = generic::Header<BlockNumber, BlakeTwo256>;
pub type Block = generic::Block<Header, UncheckedExtrinsic>;
pub type UncheckedExtrinsic = generic::UncheckedExtrinsic<Address, Call, Signature, SignedExtra>;

pub type SignedExtra = (
    frame_system::CheckSpecVersion<Test>,
    frame_system::CheckTxVersion<Test>,
    frame_system::CheckGenesis<Test>,
    frame_system::CheckEra<Test>,
    frame_system::CheckNonce<Test>,
    frame_system::CheckWeight<Test>,
);

frame_support::construct_runtime!(
    pub enum Test where
        Block = Block,
        NodeBlock = Block,
        UncheckedExtrinsic = UncheckedExtrinsic,
    {
        System: frame_system::{Pallet, Call, Config, Storage, Event<T>},
        Balances: pallet_balances::{Pallet, Call, Storage, Config<T>, Event<T>},
        Timestamp: timestamp::{Pallet, Call, Storage, Inherent},
        Teerex: pallet_teerex::{Pallet, Call, Storage, Event<T>},
    }
);

parameter_types! {
    pub const BlockHashCount: u32 = 250;
}
impl frame_system::Config for Test {
    type BaseCallFilter = frame_support::traits::AllowAll;
    type BlockWeights = ();
    type BlockLength = ();
    type DbWeight = ();
    type Origin = Origin;
    type Index = u64;
    type Call = Call;
    type BlockNumber = BlockNumber;
    type Hash = H256;
    type Hashing = BlakeTwo256;
    type AccountId = AccountId;
    type Lookup = IdentityLookup<Self::AccountId>;
    type Header = Header;
    type Event = Event;
    type BlockHashCount = BlockHashCount;
    type Version = ();
    type PalletInfo = PalletInfo;
    type AccountData = pallet_balances::AccountData<Balance>;
    type OnNewAccount = ();
    type OnKilledAccount = ();
    type SystemWeightInfo = ();
    type SS58Prefix = ();
    type OnSetCode = ();
}

pub type Balance = u64;

parameter_types! {
    pub const ExistentialDeposit: u64 = 1;
}

impl pallet_balances::Config for Test {
    type MaxLocks = ();
    type Balance = u64;
    type DustRemoval = ();
    type Event = Event;
    type ExistentialDeposit = ExistentialDeposit;
    type AccountStore = System;
    type WeightInfo = ();
    type MaxReserves = ();
    type ReserveIdentifier = ();
}

parameter_types! {
        pub const MinimumPeriod: u64 = 6000 / 2;
}

pub type Moment = u64;

impl timestamp::Config for Test {
    type Moment = Moment;
    type OnTimestampSet = Teerex;
    type MinimumPeriod = MinimumPeriod;
    type WeightInfo = ();
}

parameter_types! {
    pub const MomentsPerDay: u64 = 86_400_000; // [ms/d]
    pub const MaxSilenceTime: u64 = 172_800_000; // 48h
}

impl Config for Test {
    type Event = Event;
    type Currency = Balances;
    type MomentsPerDay = MomentsPerDay;
    type MaxSilenceTime = MaxSilenceTime;
    type WeightInfo = ();
}

// This function basically just builds a genesis storage key/value store according to
// our desired mockup. RA from enclave compiled in debug mode is allowed
pub fn new_test_ext() -> sp_io::TestExternalities {
    let mut t = system::GenesisConfig::default()
        .build_storage::<Test>()
        .unwrap();
    pallet_balances::GenesisConfig::<Test> {
        balances: vec![(AccountKeyring::Alice.to_account_id(), 1 << 60)],
    }
    .assimilate_storage(&mut t)
    .unwrap();
    crate::GenesisConfig {
        allow_sgx_debug_mode: true,
    }
    .assimilate_storage(&mut t)
    .unwrap();
    let mut ext: sp_io::TestExternalities = t.into();
    ext.execute_with(|| System::set_block_number(1));
    ext
}

//Build genesis storage for mockup, where RA from enclave compiled in debug mode is NOT allowed
pub fn new_test_production_ext() -> sp_io::TestExternalities {
    let mut t = system::GenesisConfig::default()
        .build_storage::<Test>()
        .unwrap();
    pallet_balances::GenesisConfig::<Test> {
        balances: vec![(AccountKeyring::Alice.to_account_id(), 1 << 60)],
    }
    .assimilate_storage(&mut t)
    .unwrap();
    crate::GenesisConfig {
        allow_sgx_debug_mode: false,
    }
    .assimilate_storage(&mut t)
    .unwrap();
    let mut ext: sp_io::TestExternalities = t.into();
    ext.execute_with(|| System::set_block_number(1));
    ext
}

//Help method for the OnTimestampSet to be called
pub fn set_timestamp(t: u64) {
    let _ = <timestamp::Pallet<Test> as ProvideInherent>::Call::set(t)
        .dispatch_bypass_filter(Origin::none());
}

/// Run until a particular block.
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
