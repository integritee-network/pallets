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
use codec::Encode;
pub use pallet::*;
pub use substrate_fixed::types::U32F32;

#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use frame_support::{pallet_prelude::*, WeakBoundedVec};
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
		/// Max number of whitelisted oracles allowed
		#[pallet::constant]
		type MaxOracles: Get<u32>;
	}

	/// Exchange rates chain's cryptocurrency/currency
	#[pallet::storage]
	#[pallet::getter(fn exchange_rate)]
	pub(super) type ExchangeRates<T: Config> =
		StorageMap<_, Blake2_128Concat, CurrencyString, ExchangeRate, ValueQuery>;

	/// whitelist of trusted exchange rate oracles
	#[pallet::storage]
	#[pallet::getter(fn whitelist)]
	pub(super) type Whitelist<T: Config> =
		StorageValue<_, WeakBoundedVec<[u8; 32], T::MaxOracles>, ValueQuery>;

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		/// The exchange rate of currency was set/updated. \[currency], [new value\]
		ExchangeRateUpdated(CurrencyString, Option<ExchangeRate>),
		ExchangeRateDeleted(CurrencyString),
		AddedToWhitelist([u8; 32]),
		RemovedFromWhitelist([u8; 32]),
		OracleWhitelistCleared,
	}

	#[pallet::error]
	pub enum Error<T> {
		InvalidCurrency,
		/// Too many oracles in the whitelist.
		TooManyOracles,
		NonWhitelistedOracle,
		AlreadyWhitelistedOracle,
	}

	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		#[pallet::weight(<T as Config>::WeightInfo::add_to_whitelist())]
		pub fn add_to_whitelist(origin: OriginFor<T>, mrenclave: [u8; 32]) -> DispatchResult {
			ensure_root(origin)?;
			ensure!(!Self::is_whitelisted(mrenclave), <Error<T>>::AlreadyWhitelistedOracle);
			<Whitelist<T>>::try_append(mrenclave).map_err(|_| Error::<T>::TooManyOracles)?;
			Self::deposit_event(Event::AddedToWhitelist(mrenclave));
			Ok(())
		}
		#[pallet::weight(<T as Config>::WeightInfo::remove_from_whitelist())]
		pub fn remove_from_whitelist(origin: OriginFor<T>, mrenclave: [u8; 32]) -> DispatchResult {
			ensure_root(origin)?;
			ensure!(Self::is_whitelisted(mrenclave), <Error<T>>::NonWhitelistedOracle);
			Whitelist::<T>::mutate(|mrenclaves| {
				mrenclaves.retain(|m| m.encode() != mrenclave.encode())
			});
			Self::deposit_event(Event::RemovedFromWhitelist(mrenclave));
			Ok(())
		}

		#[pallet::weight(<T as Config>::WeightInfo::clear_whitelist())]
		pub fn clear_whitelist(origin: OriginFor<T>) -> DispatchResult {
			ensure_root(origin)?;
			<Whitelist<T>>::kill();
			Self::deposit_event(Event::OracleWhitelistCleared);
			Ok(())
		}

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
impl<T: Config> Pallet<T> {
	fn is_whitelisted(mrenclave: [u8; 32]) -> bool {
		Self::whitelist().iter().any(|m| m.encode() == mrenclave.encode())
	}

	pub fn whitelisted_oracle_count() -> u32 {
		Self::whitelist().len() as u32
	}
}

mod benchmarking;
#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;
pub mod weights;
