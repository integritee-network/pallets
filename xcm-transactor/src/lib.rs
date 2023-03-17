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
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;
	use sp_std::vec;
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

		type SwapOrigin: EnsureOrigin<Self::RuntimeOrigin>;

		#[pallet::constant]
		type ShellRuntimeParaId: Get<u32>;

		#[pallet::constant]
		type IntegriteeKsmParaId: Get<u32>;

		type WeightInfo;
	}

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		SwapTransactSent { para_a: ParaId, para_b: ParaId },
	}

	#[pallet::error]
	pub enum Error<T> {
		InvalidSwapIds,
		SwapIdsEqual,
		TransactFailed,
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// Send swap instruction to the relay chain to swap the slot lease of our two parachains.
		/// This needs to be done from within a pallet as the `XCM` origin must be the parachain
		/// itself.
		///
		/// This function should really only be called once via governance, on each chain that
		/// performs the slot swap.
		///
		/// Sane weight values:
		///  Rococo-Local as of 11.01.2022:
		///		* xcm_weight: 10_000_000_000
		///		* buy_execution_weight: 500_000_000
		///  Kusama as of 11.01.2022:
		///		* xcm_weight: 10_000_000_000
		///		* buy_execution_weight: 5_000_000_000
		///
		#[pallet::call_index(0)]
		#[pallet::weight(46_200_000)] // Arbitrary weight.
		pub fn send_swap_ump(
			origin: OriginFor<T>,
			self_id: ParaId,
			other_id: ParaId,
			xcm_weight: XcmWeight,
			buy_execution_fee: u128,
		) -> DispatchResult {
			T::SwapOrigin::ensure_origin(origin)?;
			ensure!(self_id != other_id, Error::<T>::SwapIdsEqual);

			let valid_ids =
				[T::ShellRuntimeParaId::get().into(), T::IntegriteeKsmParaId::get().into()];

			ensure!(valid_ids.contains(&self_id), Error::<T>::InvalidSwapIds);
			ensure!(valid_ids.contains(&other_id), Error::<T>::InvalidSwapIds);

			let call = T::RelayCallBuilder::swap_call(self_id, other_id);
			let xcm_message =
				T::RelayCallBuilder::construct_transact_xcm(call, xcm_weight, buy_execution_fee);

			// Todo: If we ever do this in the future again, we should also put the xcm-hash and
			// the price in the deposited event.
			let (_hash, _price) = send_xcm::<T::XcmSender>(Parent.into(), xcm_message)
				.map_err(|_| Error::<T>::TransactFailed)?;

			Self::deposit_event(Event::<T>::SwapTransactSent { para_a: self_id, para_b: other_id });
			Ok(())
		}
	}
}
