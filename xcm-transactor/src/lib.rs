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
	use xcm::latest::{Weight as XcmWeight, prelude::*};
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
		TransactSent {
			para_a: ParaId,
			para_b: ParaId,
		},
	}

	#[pallet::error]
	pub enum Error<T> {
		InvalidSwapIds,
		SwapIdsEqual,
		TransactFailed,
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		#[pallet::weight(0)]
		pub fn send_swap_ump(origin: OriginFor<T>, para_a: ParaId, para_b: ParaId) -> DispatchResult {
			ensure_root(origin)?;
			ensure!(
				para_a != para_b,
				Error::<T>::SwapIdsEqual
			);

			let shell_id = ParaId::from(T::ShellRuntimeParaId::get());
			let integritee_id = ParaId::from(T::IntegriteeKsmParaId::get());
			let input_valid =
				vec![para_a, para_b].iter().filter(|&&id| id == shell_id || id == integritee_id).count() == 2;
			if !input_valid {
				return Err(Error::<T>::InvalidSwapIds.into())
			}

			let call = T::RelayCallBuilder::swap_call(para_a, para_b);
			let xcm_message = T::RelayCallBuilder::construct_transact_xcm(call, T::WeightForParaSwap::get());
			T::XcmSender::send_xcm(Parent, xcm_message).map_err(|_| Error::<T>::TransactFailed)?;

			Self::deposit_event(Event::<T>::TransactSent{ para_a, para_b });
			Ok(())
		}
	}
}
