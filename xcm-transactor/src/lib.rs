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

#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;

#[frame_support::pallet]
pub mod pallet {
	use cumulus_primitives_core::ParaId;
	use sp_std::vec::Vec;
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;
	use xcm::latest::{prelude::*, Weight as XcmWeight};
	use xcm_transactor_primitives::*;

	#[pallet::pallet]
	#[pallet::generate_store(pub(super) trait Store)]
	#[pallet::without_storage_info]
	pub struct Pallet<T>(PhantomData<T>);

	#[pallet::config]
	pub trait Config: frame_system::Config {
		type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

		type RelayCallBuilder: BuildRelayCall;

		type XcmSender: SendXcm;

		#[pallet::constant]
		type ShellRuntimeParaId: Get<u32>;

		#[pallet::constant]
		type IntegriteeKsmParaId: Get<u32>;

		#[pallet::constant]
		type WeightForParaSwap: Get<XcmWeight>;

		type WeightInfo;
	}

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		TransactSent { para_a: ParaId, para_b: ParaId },
	}

	#[pallet::error]
	pub enum Error<T> {
		InvalidSwapIds,
		SwapIdsEqual,
		TransactFailed,
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		// This function should really only be called once via governance
		// There is chance for it to be called another time or two in the future
		// This weight is ARBITRARY.
		#[pallet::call_index(0)]
		#[pallet::weight(46_200_000)]
		pub fn send_swap_ump(
			origin: OriginFor<T>,
			para_a: ParaId,
			para_b: ParaId,
		) -> DispatchResult {
			ensure_root(origin)?;
			ensure!(para_a != para_b, Error::<T>::SwapIdsEqual);

			let shell_id = ParaId::from(T::ShellRuntimeParaId::get());
			let integritee_id = ParaId::from(T::IntegriteeKsmParaId::get());
			let input_valid = vec![para_a, para_b]
				.iter()
				.filter(|&&id| id == shell_id || id == integritee_id)
				.count() == 2;
			if !input_valid {
				return Err(Error::<T>::InvalidSwapIds.into())
			}

			let call = T::RelayCallBuilder::swap_call(para_a, para_b);
			let xcm_message =
				T::RelayCallBuilder::construct_transact_xcm(call, T::WeightForParaSwap::get());
			T::XcmSender::send_xcm(Parent, xcm_message).map_err(|_| Error::<T>::TransactFailed)?;

			Self::deposit_event(Event::<T>::TransactSent { para_a, para_b });
			Ok(())
		}
	}
}
