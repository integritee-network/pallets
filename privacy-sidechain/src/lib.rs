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

//! This is a module which listens to transfer events from a parachain sovereign account
//! and automatically shields the balance of parachain account in the sidechain state
//! The module also will allow someone to unshield funds and have the unshielded funds sent
//! from the sovereign parachain account to the desired account on the parachain assosciated parachain
//!

#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;

#[frame_support::pallet]
pub mod pallet {
	// use crate::weights::WeightInfo;
	use cumulus_primitives_core::ParaId;
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;

	#[pallet::pallet]
	#[pallet::generate_store(pub(super) trait Store)]
	pub struct Pallet<T>(PhantomData<T>);

	#[pallet::config]
	pub trait Config: frame_system::Config {
		type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
		type WeightInfo;
	}

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		// TODO: DELETE & REPLACE
		PrivacyEvent,
	}

	#[pallet::error]
	pub enum Error<T> {
		// TODO: DELETE & REPLACE
		PrivacyError
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {

		#[pallet::call_index(0)]
		#[pallet::weight(46_200_000)]
		pub fn test_extrinsic(origin: OriginFor<T>) -> DispatchResult {
			let _ = ensure_signed(origin)?;
			// frame_system::remark(b"Hello");
			Self::deposit_event(Event::<T>::PrivacyEvent);
			Ok(())
		}
	}

}
