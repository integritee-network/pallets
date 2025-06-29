/*
	Copyright 2021 Integritee AG

	Licenced under GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version. You may obtain a copy of the
	License at

		<http://www.gnu.org/licenses/>.

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
*/

// Creating mock runtime here
use crate as pallet_teerdays;
use frame_support::{derive_impl, ord_parameter_types, parameter_types};
use frame_system as system;
use frame_system::{EnsureNever, EnsureSignedBy};
use pallet_teerdays::Config;
use sp_core::hex2array;
use sp_keyring::Sr25519Keyring as Keyring;
use sp_runtime::{
	traits::{IdentifyAccount, Verify},
	BuildStorage,
};

pub type Signature = sp_runtime::MultiSignature;
pub type AccountId = <<Signature as Verify>::Signer as IdentifyAccount>::AccountId;
// pub type Address = sp_runtime::MultiAddress<AccountId, ()>;
//
// pub type BlockNumber = u32;
// pub type Header = generic::Header<BlockNumber, BlakeTwo256>;

frame_support::construct_runtime!(
	pub enum Test
	{
		System: frame_system::{Pallet, Call, Config<T>, Storage, Event<T>},
		Balances: pallet_balances::{Pallet, Call, Storage, Config<T>, Event<T>},
		Porteer: crate::{Pallet, Call, Storage, Event<T>},
	}
);

type Block = frame_system::mocking::MockBlock<Test>;

parameter_types! {
	pub const BlockHashCount: u32 = 250;
}
#[derive_impl(frame_system::config_preludes::SolochainDefaultConfig as frame_system::DefaultConfig)]
impl frame_system::Config for Test {
	type Block = Block;
	type AccountId = AccountId;
	type AccountData = pallet_balances::AccountData<Balance>;
}

pub type Balance = u128;

parameter_types! {
	pub const ExistentialDeposit: u128 = 1;
}

#[derive_impl(pallet_balances::config_preludes::TestDefaultConfig)]
impl pallet_balances::Config for Test {
	type AccountStore = System;
	type Balance = Balance;
}

ord_parameter_types! {
	pub const Alice: AccountId = AccountId::new(hex2array!("d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d"));
}

impl Config for Test {
	type RuntimeEvent = RuntimeEvent;
	type WeightInfo = ();
	type PorteerAdmin = EnsureSignedBy<Alice, AccountId>;
	type TokenSenderOriginLocation = EnsureNever<AccountId>;
	type SendTokensToDestination = ();
	type Fungible = Balances;
}

// This function basically just builds a genesis storage key/value store according to
// our desired mockup. RA from enclave compiled in debug mode is allowed
pub fn new_test_ext() -> sp_io::TestExternalities {
	let mut t = system::GenesisConfig::<Test>::default().build_storage().unwrap();
	pallet_balances::GenesisConfig::<Test> {
		balances: vec![(Keyring::Alice.to_account_id(), 1 << 60)],
		..Default::default()
	}
	.assimilate_storage(&mut t)
	.unwrap();

	let mut ext: sp_io::TestExternalities = t.into();
	ext.execute_with(|| System::set_block_number(1));
	ext
}
