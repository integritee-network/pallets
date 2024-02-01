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
// Reacivating the tests again when we need them.
// Maintaining subxt is a pain currently.
// #[cfg(test)]
// mod tests;

const LOG: &str = "xcm-transactor";

#[frame_support::pallet]
pub mod pallet {
	use super::LOG;
	use cumulus_primitives_core::ParaId;
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;
	use sp_std::vec;
	use staging_xcm::latest::{prelude::*, Weight as XcmWeight};
	use xcm_transactor_primitives::*;

	#[pallet::pallet]
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
		SentXcm { hash: XcmHash },
		SwapTransactSent { para_a: ParaId, para_b: ParaId },
	}

	#[pallet::error]
	pub enum Error<T> {
		/// The swap IDs do not correspond to the runtime-configured value.
		InvalidSwapIds,
		/// Swap IDs need to be different.
		SwapIdsEqual,
		/// The desired destination was unreachable, generally because there is a no way of routing
		/// to it.
		Unreachable,
		/// Destination is routable, but there is some issue with the transport mechanism. This is
		/// considered fatal.
		Transport,
		/// Destination is known to be unroutable. This is considered fatal.
		Unroutable,
		/// The given message cannot be translated into a format that the destination can be expected
		/// to interpret.
		DestinationUnsupported,
		/// Fees needed to be paid in order to send the message were unavailable.
		FeesNotMet,
		/// Some XCM send error occurred.
		XcmSendError,
	}

	impl<T: Config> From<SendError> for Error<T> {
		fn from(e: SendError) -> Self {
			// Inspired by https://github.com/paritytech/polkadot/blob/09b61286da11921a3dda0a8e4015ceb9ef9cffca/xcm/pallet-xcm/src/lib.rs#L447
			match e {
				SendError::NotApplicable => Error::<T>::Unreachable,
				SendError::Transport(_) => Error::<T>::Transport,
				SendError::Unroutable => Error::<T>::Unroutable,
				SendError::DestinationUnsupported => Error::<T>::DestinationUnsupported,
				SendError::Fees => Error::<T>::FeesNotMet,
				_ => Error::<T>::XcmSendError,
			}
		}
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
		#[pallet::weight({46_200_000})] // Arbitrary weight.
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

			let (hash, _price) =
				send_xcm::<T::XcmSender>(Parent.into(), xcm_message).map_err(|e| {
					log::error!(target: LOG, "Error sending xcm: {:?}", e);
					Error::<T>::from(e)
				})?;

			Self::deposit_event(Event::<T>::SentXcm { hash });
			Self::deposit_event(Event::<T>::SwapTransactSent { para_a: self_id, para_b: other_id });
			Ok(())
		}
	}
}
