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
use pallet_teerex::Pallet as Teerex;
pub use substrate_fixed::types::U32F32;
use teeracle_primitives::{DataSource, MAX_ORACLE_DATA_NAME_LEN};
use teerex_primitives::EnclaveFingerprint;

const MAX_TRADING_PAIR_LEN: usize = 11;
const MAX_SOURCE_LEN: usize = 40;

#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use frame_support::{pallet_prelude::*, BoundedVec, WeakBoundedVec};
	use frame_system::pallet_prelude::*;
	use sp_std::prelude::*;
	use teeracle_primitives::*;

	pub type OracleDataBlob<T> = BoundedVec<u8, <T as Config>::MaxOracleBlobLen>;

	#[pallet::pallet]
	#[pallet::without_storage_info]
	pub struct Pallet<T>(PhantomData<T>);

	#[pallet::config]
	pub trait Config: frame_system::Config + pallet_teerex::Config {
		type WeightInfo: WeightInfo;
		/// Max number of whitelisted oracle's releases allowed
		#[pallet::constant]
		type MaxWhitelistedReleases: Get<u32>;

		#[pallet::constant]
		type MaxOracleBlobLen: Get<u32>;
	}

	/// Exchange rates chain's cryptocurrency/currency (trading pair) from different sources
	#[pallet::storage]
	#[pallet::getter(fn exchange_rate)]
	pub(super) type ExchangeRates<T: Config> = StorageDoubleMap<
		_,
		Blake2_128Concat,
		TradingPairString,
		Blake2_128Concat,
		DataSource,
		ExchangeRate,
		ValueQuery,
	>;

	#[pallet::storage]
	#[pallet::getter(fn oracle_data)]
	pub(super) type OracleData<T> = StorageDoubleMap<
		_,
		Blake2_128Concat,
		OracleDataName,
		Blake2_128Concat,
		DataSource,
		OracleDataBlob<T>,
		ValueQuery,
	>;

	/// whitelist of trusted oracle's releases for different data sources
	#[pallet::storage]
	#[pallet::getter(fn whitelist)]
	pub(super) type Whitelists<T: Config> = StorageMap<
		_,
		Blake2_128Concat,
		DataSource,
		WeakBoundedVec<EnclaveFingerprint, T::MaxWhitelistedReleases>,
		ValueQuery,
	>;

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		/// The exchange rate of trading pair was set/updated with value from source.
		ExchangeRateUpdated {
			data_source: DataSource,
			trading_pair: TradingPairString,
			exchange_rate: ExchangeRate,
		},
		/// The exchange rate of trading pair was deleted.
		ExchangeRateDeleted { data_source: DataSource, trading_pair: TradingPairString },
		/// a generic named oracle has updated its data blob
		OracleUpdated { oracle_data_name: OracleDataName, data_source: DataSource },
		/// an oracle fingerprint has been added to the whitelist
		AddedToWhitelist { data_source: DataSource, enclave_fingerprint: EnclaveFingerprint },
		/// an oracle fingerprint has been removed from the whitelist
		RemovedFromWhitelist { data_source: DataSource, enclave_fingerprint: EnclaveFingerprint },
	}

	#[pallet::error]
	pub enum Error<T> {
		/// Too many enclave fingerprints in the whitelist for this data source.
		FingerprintWhitelistOverflow,
		/// calling enclave fingerprint not whitelisted for this data source.
		FingerprintNotWhitelisted,
		/// enclave fingerprint already whitelisted for this data source.
		FingerprintAlreadyWhitelisted,
		/// trading pair string too long
		TradingPairStringTooLong,
		/// generic oracle data name string too long
		OracleDataNameStringTooLong,
		/// data source string too long
		DataSourceStringTooLong,
		/// generic oracle blob too big
		OracleBlobTooBig,
	}

	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		#[pallet::call_index(0)]
		#[pallet::weight((<T as Config>::WeightInfo::add_to_whitelist(), DispatchClass::Normal, Pays::Yes))]
		pub fn add_to_whitelist(
			origin: OriginFor<T>,
			data_source: DataSource,
			enclave_fingerprint: EnclaveFingerprint,
		) -> DispatchResult {
			ensure_root(origin)?;
			ensure!(data_source.len() <= MAX_SOURCE_LEN, Error::<T>::DataSourceStringTooLong);
			ensure!(
				!Self::is_whitelisted(&data_source, enclave_fingerprint),
				<Error<T>>::FingerprintAlreadyWhitelisted
			);
			<Whitelists<T>>::try_mutate(data_source.clone(), |fingerprints| {
				fingerprints.try_push(enclave_fingerprint)
			})
			.map_err(|_| Error::<T>::FingerprintWhitelistOverflow)?;
			Self::deposit_event(Event::AddedToWhitelist { data_source, enclave_fingerprint });
			Ok(())
		}
		#[pallet::call_index(1)]
		#[pallet::weight((<T as Config>::WeightInfo::remove_from_whitelist(), DispatchClass::Normal, Pays::Yes))]
		pub fn remove_from_whitelist(
			origin: OriginFor<T>,
			data_source: DataSource,
			enclave_fingerprint: EnclaveFingerprint,
		) -> DispatchResult {
			ensure_root(origin)?;
			ensure!(
				Self::is_whitelisted(&data_source, enclave_fingerprint),
				<Error<T>>::FingerprintNotWhitelisted
			);
			<Whitelists<T>>::mutate(&data_source, |fingerprints| {
				fingerprints.retain(|m| *m != enclave_fingerprint)
			});
			Self::deposit_event(Event::RemovedFromWhitelist { data_source, enclave_fingerprint });
			Ok(())
		}

		#[pallet::call_index(2)]
		#[pallet::weight((<T as Config>::WeightInfo::update_oracle(), DispatchClass::Normal, Pays::Yes))]
		pub fn update_oracle(
			origin: OriginFor<T>,
			oracle_data_name: OracleDataName,
			data_source: DataSource,
			new_blob: OracleDataBlob<T>,
		) -> DispatchResultWithPostInfo {
			let sender = ensure_signed(origin)?;
			let enclave = Teerex::<T>::sovereign_enclaves(&sender)
				.ok_or(pallet_teerex::Error::<T>::EnclaveIsNotRegistered)?;

			ensure!(
				Self::is_whitelisted(&data_source, enclave.fingerprint()),
				<Error<T>>::FingerprintNotWhitelisted
			);
			ensure!(
				oracle_data_name.len() <= MAX_ORACLE_DATA_NAME_LEN,
				Error::<T>::OracleDataNameStringTooLong
			);
			ensure!(data_source.len() <= MAX_SOURCE_LEN, Error::<T>::DataSourceStringTooLong);
			ensure!(
				new_blob.len() as u32 <= T::MaxOracleBlobLen::get(),
				Error::<T>::OracleBlobTooBig
			);

			OracleData::<T>::insert(&oracle_data_name, &data_source, new_blob);
			Self::deposit_event(Event::<T>::OracleUpdated { oracle_data_name, data_source });
			Ok(().into())
		}

		#[pallet::call_index(3)]
		#[pallet::weight((<T as Config>::WeightInfo::update_exchange_rate(), DispatchClass::Normal, Pays::Yes))]
		pub fn update_exchange_rate(
			origin: OriginFor<T>,
			data_source: DataSource,
			trading_pair: TradingPairString,
			new_value: Option<ExchangeRate>,
		) -> DispatchResultWithPostInfo {
			let sender = ensure_signed(origin)?;
			let enclave = Teerex::<T>::sovereign_enclaves(&sender)
				.ok_or(pallet_teerex::Error::<T>::EnclaveIsNotRegistered)?;

			// Todo: Never checks data source len
			ensure!(
				trading_pair.len() <= MAX_TRADING_PAIR_LEN,
				Error::<T>::TradingPairStringTooLong
			);
			ensure!(
				Self::is_whitelisted(&data_source, enclave.fingerprint()),
				<Error<T>>::FingerprintNotWhitelisted
			);
			if new_value.is_none() || new_value == Some(U32F32::from_num(0)) {
				log::info!("Delete exchange rate : {:?}", new_value);
				ExchangeRates::<T>::mutate_exists(&trading_pair, &data_source, |rate| *rate = None);
				Self::deposit_event(Event::ExchangeRateDeleted { data_source, trading_pair });
			} else {
				log::info!("Update exchange rate : {:?}", new_value);
				ExchangeRates::<T>::mutate_exists(&trading_pair, &data_source, |rate| {
					*rate = new_value
				});
				Self::deposit_event(Event::ExchangeRateUpdated {
					data_source,
					trading_pair,
					exchange_rate: new_value.expect("previously checked that is Some"),
				});
			}
			Ok(().into())
		}
	}
}
impl<T: Config> Pallet<T> {
	fn is_whitelisted(data_source: &DataSource, fingerprint: EnclaveFingerprint) -> bool {
		Self::whitelist(data_source).contains(&fingerprint)
	}
}

mod benchmarking;
#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;
pub mod weights;
