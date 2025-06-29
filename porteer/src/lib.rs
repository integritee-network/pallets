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
pub use pallet::*;

#[frame_support::pallet]
pub mod pallet {
	use crate::weights::WeightInfo;
	use frame_support::{pallet_prelude::*, traits::fungible};
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

	/// Configuration trait.
	#[pallet::config]
	pub trait Config: frame_system::Config {
		type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
		type WeightInfo: WeightInfo;

		/// Can enable/disable the bridge, e.g. council/technical committee.
		type PorteerAdmin: EnsureOrigin<Self::RuntimeOrigin>;

		/// Will be (Integritee Kusama, PalletIndex(PorteerIndex)) on Integritee Polkadot
		/// and possibly `NeverEnsureOrigin` on Integritee Kusama.
		type TokenSenderOriginLocation: EnsureOrigin<Self::RuntimeOrigin>;

		/// Abstraction to send tokens to the destination.
		/// This will be tricky part that handles all the XCM stuff.
		type SendTokensToDestination;

		/// The bonding balance.
		type Fungible: fungible::Inspect<AccountIdOf<Self>> + fungible::Mutate<AccountIdOf<Self>>;
	}

	#[pallet::event]
	#[pallet::generate_deposit(pub (super) fn deposit_event)]
	pub enum Event<T: Config> {
		/// An account's bond has been increased by an amount
		PorteerConfigSet { value: PorteerConfig },
	}

	#[pallet::error]
	pub enum Error<T> {
		/// The attempted operation was disabled.
		PorteerOperationDisabled,
	}

	#[pallet::storage]
	pub(super) type PorteerConfigValue<T: Config> = StorageValue<_, PorteerConfig, ValueQuery>;

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// Sets the new PorteerConfig.
		#[pallet::call_index(0)]
		#[pallet::weight(< T as Config >::WeightInfo::set_porteer_config())]
		pub fn set_porteer_config(origin: OriginFor<T>, config: PorteerConfig) -> DispatchResult {
			let _signer = T::PorteerAdmin::ensure_origin(origin)?;

			PorteerConfigValue::<T>::put(config);

			Self::deposit_event(Event::<T>::PorteerConfigSet { value: config });
			Ok(())
		}
	}
}

impl<T: Config> Pallet<T> {}
