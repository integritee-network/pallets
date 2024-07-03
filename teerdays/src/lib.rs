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

//! # Teerdays Pallet
//! A pallet which allows bonding native TEER tokens and accumulate TEERdays the longer the tokens are bonded
//! TEERdays will serve as a basis for governance and other features in the future

#![cfg_attr(not(feature = "std"), no_std)]

use frame_support::{
	pallet_prelude::DispatchResult,
	traits::{Currency, LockIdentifier},
};
pub use pallet::*;
use teerdays_primitives::TeerDayBond;

pub(crate) const TEERDAYS_ID: LockIdentifier = *b"teerdays";
pub type BalanceOf<T> =
	<<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance;

pub type TeerDayBondOf<T> = TeerDayBond<BalanceOf<T>, <T as pallet_timestamp::Config>::Moment>;
#[frame_support::pallet]
pub mod pallet {
	use crate::{weights::WeightInfo, BalanceOf, TeerDayBondOf, TEERDAYS_ID};
	use frame_support::{
		pallet_prelude::*,
		traits::{Currency, InspectLockableCurrency, LockableCurrency, WithdrawReasons},
	};
	use frame_system::pallet_prelude::*;
	use sp_runtime::{
		traits::{CheckedDiv, Zero},
		Saturating,
	};

	const STORAGE_VERSION: StorageVersion = StorageVersion::new(0);
	#[pallet::pallet]
	#[pallet::storage_version(STORAGE_VERSION)]
	#[pallet::without_storage_info]
	pub struct Pallet<T>(PhantomData<T>);

	/// Configuration trait.
	#[pallet::config]
	pub trait Config: frame_system::Config + pallet_timestamp::Config {
		type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
		type WeightInfo: WeightInfo;

		/// The bonding balance.
		type Currency: LockableCurrency<
				Self::AccountId,
				Moment = BlockNumberFor<Self>,
				Balance = Self::CurrencyBalance,
			> + InspectLockableCurrency<Self::AccountId>;

		/// Just the `Currency::Balance` type; we have this item to allow us to constrain it to
		/// `CheckedDiv` and `From<Moment>`.
		type CurrencyBalance: sp_runtime::traits::AtLeast32BitUnsigned
			+ parity_scale_codec::FullCodec
			+ Copy
			+ MaybeSerializeDeserialize
			+ sp_std::fmt::Debug
			+ Default
			+ CheckedDiv
			+ From<Self::Moment>
			+ TypeInfo
			+ MaxEncodedLen;

		#[pallet::constant]
		type MomentsPerDay: Get<Self::Moment>;
	}

	#[pallet::event]
	#[pallet::generate_deposit(pub (super) fn deposit_event)]
	pub enum Event<T: Config> {
		Bonded { account: T::AccountId, amount: BalanceOf<T> },
		Unbonded { account: T::AccountId, amount: BalanceOf<T> },
	}

	#[pallet::error]
	pub enum Error<T> {
		/// Each account can only bond once
		AlreadyBonded,
		/// Insufficient bond
		InsufficientBond,
		/// account has no bond
		NoBond,
		/// Some corruption in internal state.
		BadState,
	}

	/// Lazy
	#[pallet::storage]
	#[pallet::getter(fn teerday_bonds)]
	pub type TeerDayBonds<T: Config> =
		StorageMap<_, Blake2_128Concat, T::AccountId, TeerDayBondOf<T>, OptionQuery>;

	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		#[pallet::call_index(0)]
		#[pallet::weight(< T as Config >::WeightInfo::bond())]
		pub fn bond(
			origin: OriginFor<T>,
			#[pallet::compact] value: BalanceOf<T>,
		) -> DispatchResult {
			let signer = ensure_signed(origin)?;
			ensure!(!TeerDayBonds::<T>::contains_key(&signer), Error::<T>::AlreadyBonded);
			ensure!(value >= T::Currency::minimum_balance(), Error::<T>::InsufficientBond);

			frame_system::Pallet::<T>::inc_consumers(&signer).map_err(|_| Error::<T>::BadState)?;

			let free_balance = T::Currency::free_balance(&signer);
			let value = value.min(free_balance);
			Self::deposit_event(Event::<T>::Bonded { account: signer.clone(), amount: value });
			T::Currency::set_lock(TEERDAYS_ID, &signer, value, WithdrawReasons::all());
			let teerday_bond = TeerDayBondOf::<T> {
				bond: value,
				last_updated: pallet_timestamp::Pallet::<T>::get(),
				accumulated_tokentime: BalanceOf::<T>::zero(),
			};
			TeerDayBonds::<T>::insert(&signer, teerday_bond);
			Ok(())
		}

		#[pallet::call_index(2)]
		#[pallet::weight(< T as Config >::WeightInfo::unbond())]
		pub fn unbond(
			origin: OriginFor<T>,
			#[pallet::compact] value: BalanceOf<T>,
		) -> DispatchResult {
			let signer = ensure_signed(origin)?;

			let bond = TeerDayBonds::<T>::get(&signer).ok_or(Error::<T>::NoBond)?;
			let now = pallet_timestamp::Pallet::<T>::get();
			let bond = bond.update(now);

			let new_bonded_amount = bond.bond.saturating_sub(value);

			// burn tokentime pro rata
			let new_tokentime = bond
				.accumulated_tokentime
				.checked_div(&bond.bond)
				.unwrap_or_default()
				.saturating_mul(new_bonded_amount);

			let new_bond = TeerDayBondOf::<T> {
				bond: new_bonded_amount,
				last_updated: now,
				accumulated_tokentime: new_tokentime,
			};

			if new_bond.bond < T::Currency::minimum_balance() {
				TeerDayBonds::<T>::remove(&signer);
				T::Currency::remove_lock(TEERDAYS_ID, &signer);
				frame_system::Pallet::<T>::dec_consumers(&signer);
			} else {
				TeerDayBonds::<T>::insert(&signer, new_bond);
				T::Currency::set_lock(TEERDAYS_ID, &signer, new_bond.bond, WithdrawReasons::all());
			}
			Self::deposit_event(Event::<T>::Unbonded { account: signer.clone(), amount: value });
			Ok(())
		}

		#[pallet::call_index(3)]
		#[pallet::weight(< T as Config >::WeightInfo::unbond())]
		pub fn update_other(origin: OriginFor<T>, who: T::AccountId) -> DispatchResult {
			let signer = ensure_signed(origin)?;
			let bond = TeerDayBonds::<T>::get(&signer).ok_or(Error::<T>::NoBond)?;
			let now = pallet_timestamp::Pallet::<T>::get();
			let bond = bond.update(now);
			TeerDayBonds::<T>::insert(&signer, bond);
			Ok(())
		}
	}
}

/*
impl<T: Config> Pallet<T> {
	fn do_update_teerdays(account: T::AccountId) -> DispatchResult {
		let bond = TeerDayBonds::<T>::get(&account).ok_or(Error::<T>::NoBond)?;
		let new_bond = bond.update(now);
		TeerDayBonds::<T>::insert(account, new_bond);
		Ok(())
	}
	fn do_withdraw_unbonded(controller: &T::AccountId, num_slashing_spans: u32) -> DispatchResult {
		let current_bond = crate::TeerDayBonds(controller).map_err(|_| Error::<T>::NoBond)?;
		let free_balance = T::Currency::free_balance(controller);
		let value = current_bond.bond.min(free_balance);
		T::Currency::remove_lock(TEERDAYS_ID, controller);
		T::Currency::set_lock(TEERDAYS_ID, controller, value, WithdrawReasons::all());
		Ok(())
	}
}*/

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;
pub mod weights;
