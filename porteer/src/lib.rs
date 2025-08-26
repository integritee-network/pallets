/*
	Copyright 2021 Integritee AG

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

//! # Porteer Pallet
//!
//! The Porteer pallets enables sending and receiving native tokens between a
//! Kusama and Polkadot parachain, where both parachains have the same native token.
//!
//! The tokens are burnt on the sender chain and then minted on the receiving chain. Hence, it is
//! safe, as no tokens can be minted without being burned first. They may fail to be minted on the
//! receiving chain, however, due to an unexpected error (e.g. XCM error), which would need
//! governance to mint those missing tokens.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;
#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;

pub mod weights;

pub use crate::weights::WeightInfo;
use frame_support::{transactional, Parameter};
pub use pallet::*;
use parity_scale_codec::MaxEncodedLen;
use sp_runtime::{
	traits::{AtLeast32BitUnsigned, MaybeSerializeDeserialize, Member},
	DispatchError,
};

pub const LOG_TARGET: &str = "integritee::porteer";

#[frame_support::pallet]
pub mod pallet {
	use super::{ForwardPortedTokens, PortTokens, LOG_TARGET};
	use crate::weights::WeightInfo;
	use core::fmt::Debug;
	use frame_support::{
		pallet_prelude::*,
		traits::{
			fungible,
			tokens::{Fortitude, Precision, Preservation},
		},
		Deserialize, Serialize,
	};
	use frame_system::pallet_prelude::*;
	use sp_runtime::Saturating;
	use sp_std::vec::Vec;

	pub type AccountIdOf<T> = <T as frame_system::Config>::AccountId;
	pub type BalanceOf<T> = <<T as Config>::Fungible as fungible::Inspect<AccountIdOf<T>>>::Balance;

	const STORAGE_VERSION: StorageVersion = StorageVersion::new(0);
	#[pallet::pallet]
	#[pallet::storage_version(STORAGE_VERSION)]
	#[pallet::without_storage_info]
	pub struct Pallet<T>(PhantomData<T>);

	#[derive(
		Debug,
		Default,
		Serialize,
		Deserialize,
		Encode,
		Decode,
		DecodeWithMemTracking,
		Copy,
		Clone,
		PartialEq,
		Eq,
		PartialOrd,
		Ord,
		TypeInfo,
	)]
	pub struct PorteerConfig {
		pub send_enabled: bool,
		pub receive_enabled: bool,
	}

	#[derive(
		Debug,
		Default,
		Serialize,
		Deserialize,
		Encode,
		Decode,
		DecodeWithMemTracking,
		Copy,
		Clone,
		PartialEq,
		Eq,
		PartialOrd,
		Ord,
		TypeInfo,
	)]
	/// XCM fees to be paid at the respective hops. Which is either:
	/// 1. AHK -> AHP -> IP
	/// or
	/// 2. AHP -> AHK -> IK
	pub struct XcmFeeParams<Balance> {
		pub hop1: Balance,
		pub hop2: Balance,
		pub hop3: Balance,
	}

	/// Configuration trait.
	#[pallet::config]
	pub trait Config: frame_system::Config + pallet_timestamp::Config {
		type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
		type WeightInfo: WeightInfo;

		/// Can enable/disable the bridge, e.g. council/technical committee.
		type PorteerAdmin: EnsureOrigin<Self::RuntimeOrigin>;

		/// Porteering tokens will fail (balances unchanged) if: LastHeartBeat < Now - HeartBeatTimeout
		type HeartBeatTimeout: Get<Self::Moment>;

		/// Will be (Integritee Kusama, PalletIndex(PorteerIndex)) on Integritee Polkadot
		/// and possibly `NeverEnsureOrigin` on Integritee Kusama.
		type TokenSenderLocationOrigin: EnsureOrigin<Self::RuntimeOrigin>;

		/// Abstraction to send tokens to the destination.
		/// This will be tricky part that handles all the XCM stuff.
		type PortTokensToDestination: PortTokens<
			AccountId = AccountIdOf<Self>,
			Balance = BalanceOf<Self>,
			Location = Self::Location,
		>;

		/// Abstraction to forward ported tokens to another location like Asset Hub or Hydration.
		type ForwardPortedTokensToDestinations: ForwardPortedTokens<
			AccountId = AccountIdOf<Self>,
			Balance = BalanceOf<Self>,
			Location = Self::Location,
		>;

		/// The location representation used by this pallet.
		type Location: Parameter + Member + MaybeSerializeDeserialize + Debug + Ord + MaxEncodedLen;

		/// The bonding balance.
		type Fungible: fungible::Inspect<AccountIdOf<Self>> + fungible::Mutate<AccountIdOf<Self>>;

		#[cfg(feature = "runtime-benchmarks")]
		type BenchmarkHelper: BenchmarkHelper<Self::Location>;
	}

	#[cfg(feature = "runtime-benchmarks")]
	pub trait BenchmarkHelper<Location> {
		fn get_whitelisted_location() -> Location;
	}

	#[pallet::event]
	#[pallet::generate_deposit(pub (super) fn deposit_event)]
	pub enum Event<T: Config> {
		/// An account's bond has been increased by an amount.
		PorteerConfigSet { value: PorteerConfig },
		/// Added a new location to the whitelist for forwarding.
		AddedLocationToWhitelist { location: T::Location },
		/// Removed a location from the whitelist for forwarding.
		RemovedLocationFromWhitelist { location: T::Location },
		/// A new watchdog account has been set.
		WatchdogSet { account: AccountIdOf<T> },
		/// The watchdog has signalled that dry-running the bridge worked.
		WatchdogHeartBeatReceived,
		/// The bridge has been disabled due to a heartbeat timeout
		BridgeDisabled,
		/// The XcmFeeConfig has been set.
		XcmFeeConfigSet { fees: XcmFeeParams<BalanceOf<T>> },
		/// Ported some tokens to the destination chain.
		PortedTokens { who: AccountIdOf<T>, amount: BalanceOf<T> },
		/// Minted some tokens ported from another chain!
		MintedPortedTokens {
			who: AccountIdOf<T>,
			amount: BalanceOf<T>,
			sender_nonce: <<T as Config>::PortTokensToDestination as PortTokens>::Nonce,
		},
		/// Forwarded some minted tokens to another location.
		ForwardedPortedTokens { who: AccountIdOf<T>, amount: BalanceOf<T>, location: T::Location },
		/// Failed to forward the tokens to the final destination.
		FailedToForwardTokens { who: AccountIdOf<T>, amount: BalanceOf<T>, location: T::Location },
		/// Tried to forward the tokens to an illegal destination, hence the operation was
		/// aborted (tokens were successfully minted on this chain though).
		IllegalForwardingLocation { location: T::Location },
	}

	#[pallet::error]
	pub enum Error<T> {
		/// The attempted operation was disabled.
		PorteerOperationDisabled,
		/// The location to be added to the whitelist exists already.
		LocationAlreadyInWhitelist,
		/// The location to be removed from the whitelist does not exist.
		LocationNotInWhitelist,
		/// Invalid Watchdog Account
		InvalidWatchdogAccount,
		/// And error during initiation of porting the tokens occurred (balances unchanged).
		PortTokensInitError,
		/// And error during initiation of porting the tokens occurred (balances unchanged).
		ForwardTokensError,
		/// Watchdog heartbeat is too old. We cannot be sure that the bridge is operable.
		WatchdogHeartbeatIsTooOld,
	}

	#[pallet::storage]
	pub(super) type PorteerConfigValue<T: Config> = StorageValue<_, PorteerConfig, ValueQuery>;

	#[pallet::storage]
	pub type ForwardLocationWhitelist<T: Config> = StorageMap<_, Blake2_128Concat, T::Location, ()>;

	/// The Watchdog will send frequent heartbeats signaling that the bridge is still operable.
	#[pallet::storage]
	pub(super) type WatchdogAccount<T: Config> = StorageValue<_, AccountIdOf<T>, OptionQuery>;

	/// The timestamp at which the last heartbeat was received.
	#[pallet::storage]
	pub(super) type LastHeartBeat<T: Config> = StorageValue<_, T::Moment, ValueQuery>;

	/// The timestamp at which the last heartbeat was received.
	#[pallet::storage]
	pub(super) type PortTokensNonce<T: Config> =
		StorageValue<_, <<T as Config>::PortTokensToDestination as PortTokens>::Nonce, ValueQuery>;

	/// Entails the amount of fees needed at the respective hops.
	#[pallet::storage]
	pub(super) type XcmFeeConfig<T: Config> =
		StorageValue<_, XcmFeeParams<BalanceOf<T>>, ValueQuery>;

	#[pallet::genesis_config]
	#[derive(frame_support::DefaultNoBound)]
	pub struct GenesisConfig<T: Config> {
		pub porteer_config: PorteerConfig,
		pub watchdog: Option<AccountIdOf<T>>,
		pub initial_location_whitelist: Option<Vec<T::Location>>,
		pub initial_xcm_fees: Option<XcmFeeParams<BalanceOf<T>>>,
		#[serde(skip)]
		pub _config: sp_std::marker::PhantomData<T>,
	}

	#[pallet::genesis_build]
	impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
		fn build(&self) {
			PorteerConfigValue::<T>::put(self.porteer_config);
			if let Some(ref watchdog) = self.watchdog {
				WatchdogAccount::<T>::put(watchdog);
			}
			if let Some(ref whitelist) = self.initial_location_whitelist {
				for location in whitelist {
					ForwardLocationWhitelist::<T>::insert(location, ());
				}
			}
			if let Some(ref xcm_fees) = self.initial_xcm_fees {
				XcmFeeConfig::<T>::put(xcm_fees)
			}
		}
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// Sets the new PorteerConfig.
		///
		/// Can only be called by the `PorteerAdmin`.
		#[pallet::call_index(0)]
		#[pallet::weight(< T as Config >::WeightInfo::set_porteer_config())]
		pub fn set_porteer_config(origin: OriginFor<T>, config: PorteerConfig) -> DispatchResult {
			let _signer = T::PorteerAdmin::ensure_origin(origin)?;

			PorteerConfigValue::<T>::put(config);

			Self::deposit_event(Event::<T>::PorteerConfigSet { value: config });
			Ok(())
		}

		#[pallet::call_index(1)]
		#[pallet::weight(< T as Config >::WeightInfo::set_porteer_config())]
		pub fn add_location_to_whitelist(
			origin: OriginFor<T>,
			location: T::Location,
		) -> DispatchResult {
			let _signer = T::PorteerAdmin::ensure_origin(origin)?;

			if ForwardLocationWhitelist::<T>::contains_key(&location) {
				return Err(Error::<T>::LocationAlreadyInWhitelist.into());
			}

			ForwardLocationWhitelist::<T>::insert(&location, ());

			Self::deposit_event(Event::<T>::AddedLocationToWhitelist { location });
			Ok(())
		}

		#[pallet::call_index(2)]
		#[pallet::weight(< T as Config >::WeightInfo::set_porteer_config())]
		pub fn remove_location_from_whitelist(
			origin: OriginFor<T>,
			location: T::Location,
		) -> DispatchResult {
			let _signer = T::PorteerAdmin::ensure_origin(origin)?;

			if !ForwardLocationWhitelist::<T>::contains_key(&location) {
				return Err(Error::<T>::LocationNotInWhitelist.into());
			}

			ForwardLocationWhitelist::<T>::remove(&location);

			Self::deposit_event(Event::<T>::RemovedLocationFromWhitelist { location });
			Ok(())
		}

		/// Sets the new watchdog account.
		///
		/// Can only be called by the `PorteerAdmin`.
		#[pallet::call_index(3)]
		#[pallet::weight(< T as Config >::WeightInfo::set_watchdog())]
		pub fn set_watchdog(origin: OriginFor<T>, account: AccountIdOf<T>) -> DispatchResult {
			let _signer = T::PorteerAdmin::ensure_origin(origin)?;

			WatchdogAccount::<T>::put(&account);

			Self::deposit_event(Event::<T>::WatchdogSet { account });
			Ok(())
		}

		/// Signals that the bridge is still operable aka that a dryrun works.
		///
		/// Can only be called by the `WatchdogAccount`.
		#[pallet::call_index(4)]
		#[pallet::weight(<T as Config>::WeightInfo::watchdog_heartbeat())]
		pub fn watchdog_heartbeat(origin: OriginFor<T>) -> DispatchResultWithPostInfo {
			let signer = ensure_signed(origin)?;

			let watchdog = WatchdogAccount::<T>::get().ok_or(Error::<T>::InvalidWatchdogAccount)?;
			ensure!(signer == watchdog, Error::<T>::InvalidWatchdogAccount);

			LastHeartBeat::<T>::put(pallet_timestamp::Pallet::<T>::get());

			Self::deposit_event(Event::<T>::WatchdogHeartBeatReceived);
			Ok(Pays::No.into())
		}

		/// Sets the `XcmFeeConfig` to keep the bridge working.
		///
		/// Can only be called by the `PorteerAdmin`.
		#[pallet::call_index(5)]
		#[pallet::weight(< T as Config >::WeightInfo::set_xcm_fee_params())]
		pub fn set_xcm_fee_params(
			origin: OriginFor<T>,
			fees: XcmFeeParams<BalanceOf<T>>,
		) -> DispatchResult {
			let _signer = T::PorteerAdmin::ensure_origin(origin)?;

			XcmFeeConfig::<T>::put(fees);

			Self::deposit_event(Event::<T>::XcmFeeConfigSet { fees });
			Ok(())
		}

		/// Burns and then sends tokens to the destination as implemented by the `SendTokensToDestination`.
		///
		/// Optionally, the tokens can be forwarded to another location like Asset Hub or Hydration, and
		/// in the future even Ethereum.
		#[pallet::call_index(6)]
		#[pallet::weight(< T as Config >::WeightInfo::port_tokens())]
		pub fn port_tokens(
			origin: OriginFor<T>,
			amount: BalanceOf<T>,
			forward_tokens_to_location: Option<T::Location>,
		) -> DispatchResult {
			let signer = ensure_signed(origin)?;

			Self::ensure_sending_tokens_enabled()?;

			let now = pallet_timestamp::Pallet::<T>::get();
			if LastHeartBeat::<T>::get() <
				now.saturating_sub(<T as Config>::HeartBeatTimeout::get())
			{
				return Err(Error::<T>::WatchdogHeartbeatIsTooOld.into());
			};

			<T::Fungible as fungible::Mutate<_>>::burn_from(
				&signer,
				amount,
				Preservation::Expendable,
				Precision::Exact,
				Fortitude::Polite,
			)?;

			let nonce = PortTokensNonce::<T>::mutate(|n| {
				*n = n.saturating_add(1u32.into());
				*n
			});

			T::PortTokensToDestination::port_tokens(
				signer.clone(),
				amount,
				forward_tokens_to_location,
				nonce,
			)
			.map_err(|e| {
				log::error!(target: LOG_TARGET, "Port tokens error: {:?}", e);
				Error::<T>::PortTokensInitError
			})?;

			Self::deposit_event(Event::<T>::PortedTokens { who: signer, amount });
			Ok(())
		}

		/// Mints the native tokens on this chain, which are supposed to have been
		/// burned on the other chain.
		///
		/// Can only be called from the `TokenSenderOriginLocation`.
		#[pallet::call_index(7)]
		#[pallet::weight(< T as Config >::WeightInfo::mint_ported_tokens())]
		pub fn mint_ported_tokens(
			origin: OriginFor<T>,
			beneficiary: AccountIdOf<T>,
			amount: BalanceOf<T>,
			forward_tokens_to_location: Option<T::Location>,
			sender_nonce: <<T as Config>::PortTokensToDestination as PortTokens>::Nonce,
		) -> DispatchResult {
			let _signer = T::TokenSenderLocationOrigin::ensure_origin(origin)?;

			Self::ensure_receiving_tokens_enabled()?;

			<T::Fungible as fungible::Mutate<_>>::mint_into(&beneficiary, amount)?;

			Self::deposit_event(Event::<T>::MintedPortedTokens {
				who: beneficiary.clone(),
				amount,
				sender_nonce,
			});

			// Forward the tokens if desired
			if let Some(l) = forward_tokens_to_location {
				if ForwardLocationWhitelist::<T>::contains_key(&l) {
					let result = Self::forward_tokens(beneficiary.clone(), amount, l.clone());
					match result {
						Ok(_) => Self::deposit_event(Event::<T>::ForwardedPortedTokens {
							who: beneficiary.clone(),
							amount,
							location: l,
						}),
						Err(_) => Self::deposit_event(Event::<T>::FailedToForwardTokens {
							who: beneficiary.clone(),
							amount,
							location: l,
						}),
					}
				} else {
					Self::deposit_event(Event::<T>::IllegalForwardingLocation { location: l })
				}
			}
			Ok(())
		}
	}
}

pub trait PortTokens {
	type AccountId;

	type Balance;
	type Nonce: Parameter
		+ Member
		+ AtLeast32BitUnsigned
		+ Default
		+ Copy
		+ MaybeSerializeDeserialize
		+ MaxEncodedLen;

	type Location;

	type Error: core::fmt::Debug;

	fn port_tokens(
		who: Self::AccountId,
		amount: Self::Balance,
		forward_tokens_to: Option<Self::Location>,
		nonce: Self::Nonce,
	) -> Result<(), Self::Error>;
}

pub trait ForwardPortedTokens {
	type AccountId;

	type Balance;

	type Location;

	type Error: core::fmt::Debug;

	fn forward_ported_tokens(
		who: Self::AccountId,
		amount: Self::Balance,
		forward_tokens_to: Self::Location,
	) -> Result<(), Self::Error>;
}

impl<T: Config> Pallet<T> {
	/// Tries to forward the tokens to the destination location.
	///
	/// We use `#[transactional]` here because we want to roll back changes happening in this
	/// function in case an error occurs while returning an `Ok(())` from the extrinsic dispatching
	/// this function.
	#[transactional]
	fn forward_tokens(
		beneficiary: AccountIdOf<T>,
		amount: BalanceOf<T>,
		location: T::Location,
	) -> Result<(), DispatchError> {
		// The trait implementation will evaluate if the forwarding
		// should respect the ED.
		T::ForwardPortedTokensToDestinations::forward_ported_tokens(beneficiary, amount, location)
			.map_err(|e| {
				log::error!(target: LOG_TARGET, "Forward tokens error: {:?}", e);
				Error::<T>::ForwardTokensError.into()
			})
	}

	pub fn xcm_fee_config() -> XcmFeeParams<BalanceOf<T>> {
		XcmFeeConfig::<T>::get()
	}

	fn ensure_sending_tokens_enabled() -> Result<(), Error<T>> {
		if PorteerConfigValue::<T>::get().send_enabled {
			Ok(())
		} else {
			Err(Error::<T>::PorteerOperationDisabled)
		}
	}

	fn ensure_receiving_tokens_enabled() -> Result<(), Error<T>> {
		if PorteerConfigValue::<T>::get().receive_enabled {
			Ok(())
		} else {
			Err(Error::<T>::PorteerOperationDisabled)
		}
	}
}
