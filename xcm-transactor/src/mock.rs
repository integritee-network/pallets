/*
	Copyright 2021 Integritee AG & Parity Technologies (UK) Ltd.

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

use crate as pallet_xcm_transactor;
use core::default::Default;
use frame_support::{derive_impl, parameter_types};
use frame_system::EnsureRoot;
use sp_core::H256;
use sp_runtime::{
	generic,
	traits::{BlakeTwo256, IdentifyAccount, IdentityLookup, Verify},
};
use staging_xcm::latest::prelude::*;
use xcm_transactor_primitives::*;

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
		System: frame_system,
		Balances: pallet_balances,
		XcmTransactor: pallet_xcm_transactor,
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
	pub const ShellRuntimeParaId: u32 = 2223u32;
	pub const IntegriteeKsmParaId: u32 = 2015u32;
}

pub struct DummySendXcm;
impl SendXcm for DummySendXcm {
	type Ticket = ();

	fn validate(
		_destination: &mut Option<Location>,
		_message: &mut Option<Xcm<()>>,
	) -> SendResult<Self::Ticket> {
		Ok(((), Assets::new()))
	}

	fn deliver(_ticket: Self::Ticket) -> Result<XcmHash, SendError> {
		Ok([0; 32])
	}
}

impl pallet_xcm_transactor::Config for Test {
	type RuntimeEvent = RuntimeEvent;
	type RelayCallBuilder = RelayCallBuilder<IntegriteeKsmParaId>;
	type XcmSender = DummySendXcm;
	type SwapOrigin = EnsureRoot<AccountId>;
	type ShellRuntimeParaId = ShellRuntimeParaId;
	type IntegriteeKsmParaId = IntegriteeKsmParaId;
	type WeightInfo = ();
}
