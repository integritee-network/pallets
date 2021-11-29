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
//! # Cryptocurrency teeracle pallet
//!
//! The teeracle pallet provides functionality for handling exchange rates of the coin (ex: TEER) to different currencies
//!
//! - [`Config`]
//! - [`Call`]
//! - [`Pallet`]
//!
//! ## Overview
//!
//! The teeracle pallet provides functions for:
//!
//! - Setting exchange rates.
//!
//!
#![cfg_attr(not(feature = "std"), no_std)]
pub use crate::weights::WeightInfo;
pub use pallet::*;
pub use substrate_fixed::types::U32F32;

#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;
	use sp_std::prelude::*;
	use teeracle_primitives::*;

	#[pallet::pallet]
	#[pallet::generate_store(pub(super) trait Store)]
	pub struct Pallet<T>(PhantomData<T>);

	#[pallet::config]
	pub trait Config: frame_system::Config + pallet_teerex::Config {
		/// The overarching event type.
		type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;
		type WeightInfo: WeightInfo;
	}

	#[pallet::storage]
	#[pallet::getter(fn exchange_rate)]
	pub(super) type ExchangeRates<T> =
		StorageMap<_, Blake2_128Concat, CurrencyString, ExchangeRate, ValueQuery>;

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		/// The exchange rate of currency was set/updated. \[currency], [new value\]
		ExchangeRateUpdated(CurrencyString, Option<ExchangeRate>),
		ExchangeRateDeleted(CurrencyString),
	}

	#[pallet::error]
	pub enum Error<T> {
		InvalidCurrency,
	}

	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		#[pallet::weight(<T as Config>::WeightInfo::update_exchange_rate())]
		pub fn update_exchange_rate(
			origin: OriginFor<T>,
			currency: CurrencyString,
			new_value: Option<ExchangeRate>,
		) -> DispatchResultWithPostInfo {
			let sender = ensure_signed(origin)?;
			<pallet_teerex::Module<T>>::is_registered_enclave(&sender)?;
			if new_value.is_none() || new_value == Some(U32F32::from_num(0)) {
				log::info!("Delete exchange rate : {:?}", new_value);
				ExchangeRates::<T>::mutate_exists(currency.clone(), |rate| *rate = None);
				Self::deposit_event(Event::ExchangeRateDeleted(currency));
			} else {
				log::info!("Update exchange rate : {:?}", new_value);
				ExchangeRates::<T>::mutate_exists(currency.clone(), |rate| *rate = new_value);
				Self::deposit_event(Event::ExchangeRateUpdated(currency, new_value));
			}
			Ok(().into())
		}
	}
}

mod benchmarking;
#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;
pub mod weights;
