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

use crate::{mock::*, Config, Error};
use codec::{Decode, Encode};
use cumulus_primitives_core::ParaId;
use frame_support::{assert_noop, assert_ok};
use sp_keyring::AccountKeyring;
use xcm_transactor_primitives::*;

#[subxt::subxt(runtime_metadata_url = "wss://kusama-rpc.polkadot.io:443")]
pub mod kusama {}

use kusama::runtime_types::{
	kusama_runtime::RuntimeCall as KusamaRuntimeCall,
	polkadot_runtime_common::paras_registrar::pallet::Call as KsmRegistrarCall,
};

#[test]
fn swap_ump_fails_not_privileged() {
	new_test_ext().execute_with(|| {
		let alice = AccountKeyring::Alice.to_account_id();
		assert_noop!(
			XcmTransactor::send_swap_ump(
				RuntimeOrigin::signed(alice),
				ParaId::from(2015),
				ParaId::from(2014),
				10_000_000_000u64.into(),
				10_000_000_000u64.into()
			),
			sp_runtime::DispatchError::BadOrigin
		);
	})
}

#[test]
fn swap_ump_fails_equal_para_ids() {
	new_test_ext().execute_with(|| {
		assert_noop!(
			XcmTransactor::send_swap_ump(
				RuntimeOrigin::root(),
				ParaId::from(2015),
				ParaId::from(2015),
				10_000_000_000u64.into(),
				10_000_000_000u64.into()
			),
			Error::<Test>::SwapIdsEqual
		);
	})
}

#[test]
fn swap_ump_fails_1_id_invalid() {
	new_test_ext().execute_with(|| {
		let shell_id = <Test as Config>::ShellRuntimeParaId::get();
		assert_noop!(
			XcmTransactor::send_swap_ump(
				RuntimeOrigin::root(),
				shell_id.into(),
				ParaId::from(20000),
				10_000_000_000u64.into(),
				10_000_000_000u64.into()
			),
			Error::<Test>::InvalidSwapIds
		);
	})
}

#[test]
fn swap_ump_fails_2_id_invalid() {
	new_test_ext().execute_with(|| {
		let integritee_id = <Test as Config>::IntegriteeKsmParaId::get();
		assert_noop!(
			XcmTransactor::send_swap_ump(
				RuntimeOrigin::root(),
				integritee_id.into(),
				ParaId::from(20000),
				10_000_000_000u64.into(),
				10_000_000_000u64.into()
			),
			Error::<Test>::InvalidSwapIds
		);
	})
}

#[test]
fn swap_ump_success() {
	new_test_ext().execute_with(|| {
		let shell_id = <Test as Config>::ShellRuntimeParaId::get();
		let integritee_id = <Test as Config>::IntegriteeKsmParaId::get();
		assert_ok!(XcmTransactor::send_swap_ump(
			RuntimeOrigin::root(),
			shell_id.into(),
			integritee_id.into(),
			10_000_000_000u64.into(),
			10_000_000_000u64.into()
		));
		assert!(System::events().iter().any(|swap| matches!(
			swap.event,
			RuntimeEvent::XcmTransactor(crate::Event::SwapTransactSent { .. })
		)));
	})
}

#[test]
fn decode_swap_ump_in_kusama_success() {
	let shell_id: ParaId = <Test as Config>::ShellRuntimeParaId::get().into();
	let integritee_id: ParaId = <Test as Config>::IntegriteeKsmParaId::get().into();
	let encoded_call =
		<Test as Config>::RelayCallBuilder::swap_call(shell_id, integritee_id).encode();

	let kusama_call = KusamaRuntimeCall::decode(&mut &encoded_call[..])
		.expect("Can Decode into a Kusama Runtime Call; QED");
	if let KusamaRuntimeCall::Registrar(KsmRegistrarCall::swap { id, other }) = kusama_call {
		assert_eq!(shell_id, ParaId::from(id.0));
		assert_eq!(integritee_id, ParaId::from(other.0));
	} else {
		panic!();
	}
}
