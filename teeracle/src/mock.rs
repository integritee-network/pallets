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
use crate as pallet_teeracle;
use frame_support::{derive_impl, parameter_types, traits::ConstBool};
use frame_system as system;
use pallet_teeracle::Config;
use sp_consensus_aura::sr25519::AuthorityId as AuraId;
use sp_core::{ConstU32, H256};
use sp_keyring::AccountKeyring;
use sp_runtime::{
	generic,
	traits::{BlakeTwo256, IdentifyAccount, IdentityLookup, Verify},
	BuildStorage,
};

pub type Signature = sp_runtime::MultiSignature;
pub type AccountId = <<Signature as Verify>::Signer as IdentifyAccount>::AccountId;
pub type Address = sp_runtime::MultiAddress<AccountId, ()>;

pub type BlockNumber = u32;
pub type Header = generic::Header<BlockNumber, BlakeTwo256>;
pub type UncheckedExtrinsic =
	generic::UncheckedExtrinsic<Address, RuntimeCall, Signature, SignedExtra>;

pub type SignedExtra = (
	frame_system::CheckSpecVersion<Test>,
	frame_system::CheckTxVersion<Test>,
	frame_system::CheckGenesis<Test>,
	frame_system::CheckEra<Test>,
	frame_system::CheckNonce<Test>,
	frame_system::CheckWeight<Test>,
);

frame_support::construct_runtime!(
	pub enum Test
	{
		Aura: pallet_aura,
		System: frame_system,
		Balances: pallet_balances,
		Timestamp: pallet_timestamp,
		Teerex: pallet_teerex,
		Teeracle: pallet_teeracle,
	}
);

parameter_types! {
	pub const BlockHashCount: u32 = 250;
}

#[derive_impl(frame_system::config_preludes::SolochainDefaultConfig as frame_system::DefaultConfig)]
impl frame_system::Config for Test {
	type BaseCallFilter = frame_support::traits::Everything;
	type BlockWeights = ();
	type BlockLength = ();
	type Block = generic::Block<Header, UncheckedExtrinsic>;
	type DbWeight = ();
	type RuntimeOrigin = RuntimeOrigin;
	type Nonce = u64;
	type RuntimeCall = RuntimeCall;
	type RuntimeTask = RuntimeTask;
	type Hash = H256;
	type Hashing = BlakeTwo256;
	type AccountId = AccountId;
	type Lookup = IdentityLookup<Self::AccountId>;
	type RuntimeEvent = RuntimeEvent;
	type BlockHashCount = BlockHashCount;
	type Version = ();
	type PalletInfo = PalletInfo;
	type AccountData = pallet_balances::AccountData<Balance>;
	type OnNewAccount = ();
	type OnKilledAccount = ();
	type SystemWeightInfo = ();
	type SS58Prefix = ();
	type OnSetCode = ();
	type MaxConsumers = frame_support::traits::ConstU32<16>;
}

parameter_types! {
	pub const SlotDuration: u64 = 6000;
}
impl pallet_aura::Config for Test {
	type AuthorityId = AuraId;
	type DisabledValidators = ();
	type MaxAuthorities = ConstU32<32>;
	type AllowMultipleBlocksPerSlot = ConstBool<false>;
	type SlotDuration = SlotDuration;
}
pub type Balance = u64;

parameter_types! {
	pub const ExistentialDeposit: u64 = 1;
}

impl pallet_balances::Config for Test {
	type MaxLocks = ();
	type Balance = u64;
	type DustRemoval = ();
	type RuntimeEvent = RuntimeEvent;
	type ExistentialDeposit = ExistentialDeposit;
	type AccountStore = System;
	type WeightInfo = ();
	type MaxReserves = ();
	type ReserveIdentifier = ();
	type RuntimeFreezeReason = ();
	type FreezeIdentifier = ();
	type MaxFreezes = ();
	type RuntimeHoldReason = ();
}

parameter_types! {
		pub const MinimumPeriod: u64 = 6000 / 2;
}

pub type Moment = u64;

impl pallet_timestamp::Config for Test {
	type Moment = Moment;
	type OnTimestampSet = Aura;
	type MinimumPeriod = MinimumPeriod;
	type WeightInfo = ();
}

parameter_types! {
	pub const MomentsPerDay: u64 = 86_400_000; // [ms/d]
	pub const MaxAttestationRenewalPeriod: u64 = 172_800_000; // 48h
	pub const MaxWhitelistedReleases: u32 = 10;
	pub const MaxOracleBlobLen: u32 = 4096;
}

impl pallet_teerex::Config for Test {
	type RuntimeEvent = RuntimeEvent;
	type MomentsPerDay = MomentsPerDay;
	type WeightInfo = ();
	type MaxAttestationRenewalPeriod = MaxAttestationRenewalPeriod;
}

impl Config for Test {
	type RuntimeEvent = RuntimeEvent;
	type WeightInfo = ();
	type MaxWhitelistedReleases = MaxWhitelistedReleases;
	type MaxOracleBlobLen = MaxOracleBlobLen;
}

// This function basically just builds a genesis storage key/value store according to
// our desired mockup. RA from enclave compiled in debug mode is allowed
pub fn new_test_ext() -> sp_io::TestExternalities {
	let mut t = system::GenesisConfig::<Test>::default().build_storage().unwrap();
	pallet_balances::GenesisConfig::<Test> {
		balances: vec![(AccountKeyring::Alice.to_account_id(), 1 << 60)],
	}
	.assimilate_storage(&mut t)
	.unwrap();
	pallet_teerex::GenesisConfig::<Test> {
		allow_sgx_debug_mode: true,
		allow_skipping_attestation: true,
		_config: Default::default(),
	}
	.assimilate_storage(&mut t)
	.unwrap();

	let mut ext: sp_io::TestExternalities = t.into();
	ext.execute_with(|| System::set_block_number(1));
	ext
}
