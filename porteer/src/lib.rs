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

use sp_runtime::Saturating;
#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;
#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;

pub mod weights;

use frame_support::pallet_prelude::Get;
use sp_runtime::Weight;

pub use crate::weights::WeightInfo;
pub use pallet::*;

pub const LOG_TARGET: &str = "integritee::porteer";

#[frame_support::pallet]
pub mod pallet {
	use super::{PortTokens, LOG_TARGET};
	use crate::weights::WeightInfo;
	use frame_support::{
		pallet_prelude::*,
		traits::{
			fungible,
			tokens::{Fortitude, Precision, Preservation},
		},
		Deserialize, Serialize,
	};
	use frame_system::pallet_prelude::*;

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

		/// The bridge will be disabled if: LastHeartBeat < Now - HeartBeatTimeout
		type HeartBeatTimeout: Get<Self::Moment>;

		/// Will be (Integritee Kusama, PalletIndex(PorteerIndex)) on Integritee Polkadot
		/// and possibly `NeverEnsureOrigin` on Integritee Kusama.
		type TokenSenderLocationOrigin: EnsureOrigin<Self::RuntimeOrigin>;

		/// Abstraction to send tokens to the destination.
		/// This will be tricky part that handles all the XCM stuff.
		type PortTokensToDestination: PortTokens<
			AccountId = AccountIdOf<Self>,
			Balance = BalanceOf<Self>,
		>;

		/// The bonding balance.
		type Fungible: fungible::Inspect<AccountIdOf<Self>> + fungible::Mutate<AccountIdOf<Self>>;
	}

	#[pallet::event]
	#[pallet::generate_deposit(pub (super) fn deposit_event)]
	pub enum Event<T: Config> {
		/// An account's bond has been increased by an amount.
		PorteerConfigSet { value: PorteerConfig },
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
		MintedPortedTokens { who: AccountIdOf<T>, amount: BalanceOf<T> },
	}

	#[pallet::error]
	pub enum Error<T> {
		/// The attempted operation was disabled.
		PorteerOperationDisabled,
		/// Invalid Watchdog Account
		InvalidWatchdogAccount,
		/// And error during initiation of porting the tokens occurred (balances unchanged).
		PortTokensInitError,
	}

	#[pallet::storage]
	pub(super) type PorteerConfigValue<T: Config> = StorageValue<_, PorteerConfig, ValueQuery>;

	/// The Watchdog will send frequent heartbeats signaling that the bridge is still operable.
	#[pallet::storage]
	pub(super) type WatchdogAccount<T: Config> = StorageValue<_, AccountIdOf<T>, OptionQuery>;

	/// The block number at which the last heartbeat was received.
	#[pallet::storage]
	pub(super) type LastHeartBeat<T: Config> = StorageValue<_, T::Moment, ValueQuery>;

	/// Entails the amount of fees need at the respective hops.
	#[pallet::storage]
	pub(super) type XcmFeeConfig<T: Config> =
		StorageValue<_, XcmFeeParams<BalanceOf<T>>, ValueQuery>;

	#[pallet::genesis_config]
	#[derive(frame_support::DefaultNoBound)]
	pub struct GenesisConfig<T> {
		pub porteer_config: PorteerConfig,
		#[serde(skip)]
		pub _config: sp_std::marker::PhantomData<T>,
	}

	#[pallet::genesis_build]
	impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
		fn build(&self) {
			PorteerConfigValue::<T>::put(self.porteer_config);
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

		/// Sets the new watchdog account.
		///
		/// Can only be called by the `PorteerAdmin`.
		#[pallet::call_index(1)]
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
		#[pallet::call_index(2)]
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
		#[pallet::call_index(3)]
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

		/// Burns and then sends tokens to the destination as implemented by the `SendTokensToDestination`
		#[pallet::call_index(4)]
		#[pallet::weight(< T as Config >::WeightInfo::port_tokens())]
		pub fn port_tokens(origin: OriginFor<T>, amount: BalanceOf<T>) -> DispatchResult {
			let signer = ensure_signed(origin)?;

			Self::ensure_sending_tokens_enabled()?;

			<T::Fungible as fungible::Mutate<_>>::burn_from(
				&signer,
				amount,
				Preservation::Expendable,
				Precision::Exact,
				Fortitude::Polite,
			)?;

			T::PortTokensToDestination::port_tokens(&signer, amount).map_err(|e| {
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
		#[pallet::call_index(5)]
		#[pallet::weight(< T as Config >::WeightInfo::mint_ported_tokens())]
		pub fn mint_ported_tokens(
			origin: OriginFor<T>,
			beneficiary: AccountIdOf<T>,
			amount: BalanceOf<T>,
		) -> DispatchResult {
			// Todo: Check what is the best practice here
			let _signer = T::TokenSenderLocationOrigin::ensure_origin(origin)?;

			Self::ensure_receiving_tokens_enabled()?;

			<T::Fungible as fungible::Mutate<_>>::mint_into(&beneficiary, amount)?;

			Self::deposit_event(Event::<T>::MintedPortedTokens { who: beneficiary, amount });
			Ok(())
		}
	}

	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
		fn on_initialize(_: BlockNumberFor<T>) -> Weight {
			Self::disable_send_if_timeout_reached()
		}
	}
}

pub trait PortTokens {
	type AccountId;

	type Balance;

	type Error: core::fmt::Debug;

	fn port_tokens(who: &Self::AccountId, amount: Self::Balance) -> Result<(), Self::Error>;
}

impl<T: Config> Pallet<T> {
	fn disable_send_if_timeout_reached() -> Weight {
		let total_weight: Weight = Weight::zero();

		let now = pallet_timestamp::Pallet::<T>::get();
		if LastHeartBeat::<T>::get() < now.saturating_sub(<T as Config>::HeartBeatTimeout::get()) {
			// read `LastHeartBeat`, Timestamp
			total_weight.saturating_add(<T as frame_system::Config>::DbWeight::get().reads(2));

			let mut config = PorteerConfigValue::<T>::get();
			total_weight.saturating_add(<T as frame_system::Config>::DbWeight::get().reads(1));

			if config.send_enabled {
				config.send_enabled = false;
				PorteerConfigValue::<T>::put(config);
				Self::deposit_event(Event::<T>::BridgeDisabled);

				// write config, deposit event
				total_weight.saturating_add(<T as frame_system::Config>::DbWeight::get().writes(2));
			}
		}

		total_weight
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
