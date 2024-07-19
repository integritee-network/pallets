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
//!
//! ### Terminology
//! - **Bonding**: Locking up TEER tokens for a certain period of time into the future.
//!     Bonded TEER tokens are not liquid and appear in "frozen" balance but can still be used for voting in network governance
//! - **Unbonding**: Starting the unlock process of bonded TEER tokens
//! - **TEERdays**: Accumulated time of bonded TEER tokens
//! - **TokenTime**: The technical unit of TEERdays storage: TokenTime = Balance (TEER with its 12 digits) * Moment (Milliseconds)
//!
//! ### Usage Lifecycle
//!
//! 1. Bond TEER tokens: `bond(value)`
//! 2. Increase Bond if you like: `bond_extra(value)`
//! 3. *Use your accumulated TEERdays for governance or other features*
//! 4. Unbond TEER tokens: `unbond(value)`.
//!    - unbonding is only possible if no unlock is pending
//!    - unbonding burns accumulated TEERdays pro rata bonded amount before and after unbonding
//! 5. wait for `UnlockPeriod` to pass
//! 6. Withdraw unbonded TEER tokens: `withdraw_unbonded()`
//!
//! ### Developer Notes
//!
//! Accumulated TokenTime is updated lazily. This means that the `update_other` function must be called if the
//! total amount of accumulated TEERdays is relevant for i.e. determining the electorate in
//! TEERday-based voting. If necessary, this update can be enforced by other pallets using `do_update_teerdays(account)`
//! Failing to update all bonded accounts may lead to underestimation of total electorate voting power
//!
//! #### Numerical stability
//! Assuming:
//! - Balance is u128, decimals: 12, total supply cap: 10^7 TEER
//! - Moment is u64, unit: ms
//!
//! 100years in milliseconds (Moment) are 42bits
//! 10MTEER with 12 digits are 60bits
//! 100years of total supply locked still fits u128
//! therefore, it is safe to use the Balance type for TEERdays
//!

#![cfg_attr(not(feature = "std"), no_std)]

pub use crate::weights::WeightInfo;
use frame_support::traits::{
	Currency, InspectLockableCurrency, LockIdentifier, LockableCurrency, WithdrawReasons,
};
pub use pallet::*;
use sp_runtime::Saturating;
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

		/// The period of time that must pass before a bond can be unbonded.
		/// Must use the same unit which the timestamp pallet uses
		#[pallet::constant]
		type UnlockPeriod: Get<Self::Moment>;
	}

	#[pallet::event]
	#[pallet::generate_deposit(pub (super) fn deposit_event)]
	pub enum Event<T: Config> {
		/// An account's bond has been increased by an amount
		Bonded { account: T::AccountId, amount: BalanceOf<T> },
		/// An account's bond has been decreased by an amount
		Unbonded { account: T::AccountId, amount: BalanceOf<T> },
		/// An account's accumulated tokentime has been updated
		TokenTimeUpdated { account: T::AccountId, bond: TeerDayBondOf<T> },
		/// An account has successfully withdrawn a previously unbonded amount after unlock period has passed
		Withdrawn { account: T::AccountId, amount: BalanceOf<T> },
	}

	#[pallet::error]
	pub enum Error<T> {
		/// Each account can only bond once
		AlreadyBonded,
		/// Insufficient bond
		InsufficientBond,
		/// Insufficient unbond
		InsufficientUnbond,
		/// account has no bond
		NoBond,
		/// Can't unbond while unlock is pending
		PendingUnlock,
		/// no unlock is pending
		NotUnlocking,
		/// Some corruption in internal state.
		BadState,
	}

	/// a store for all active bonds. tokentime is updated lazily
	#[pallet::storage]
	#[pallet::getter(fn teerday_bonds)]
	pub type TeerDayBonds<T: Config> =
		StorageMap<_, Blake2_128Concat, T::AccountId, TeerDayBondOf<T>, OptionQuery>;

	/// a store for all pending unlocks which are awaiting the unlock period to pass.
	/// Withdrawal happens lazily and causes entry removal from this store
	#[pallet::storage]
	#[pallet::getter(fn pending_unlock)]
	pub type PendingUnlock<T: Config> =
		StorageMap<_, Blake2_128Concat, T::AccountId, (T::Moment, BalanceOf<T>), OptionQuery>;

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// Bond TEER tokens. This will lock the tokens in order to start accumulating TEERdays
		/// The minimum bond is the existential deposit
		#[pallet::call_index(0)]
		#[pallet::weight(< T as Config >::WeightInfo::bond())]
		pub fn bond(
			origin: OriginFor<T>,
			#[pallet::compact] value: BalanceOf<T>,
		) -> DispatchResult {
			let signer = ensure_signed(origin)?;
			ensure!(!TeerDayBonds::<T>::contains_key(&signer), Error::<T>::AlreadyBonded);
			ensure!(value >= T::Currency::minimum_balance(), Error::<T>::InsufficientBond);

			let free_balance = T::Currency::free_balance(&signer);
			let value = value.min(free_balance);
			Self::deposit_event(Event::<T>::Bonded { account: signer.clone(), amount: value });
			T::Currency::set_lock(TEERDAYS_ID, &signer, value, WithdrawReasons::all());
			let teerday_bond = TeerDayBondOf::<T> {
				value,
				last_updated: pallet_timestamp::Pallet::<T>::get(),
				accumulated_tokentime: BalanceOf::<T>::zero(),
			};
			TeerDayBonds::<T>::insert(&signer, teerday_bond);
			Ok(())
		}

		/// Increase an existing bond on the signer's account
		/// The minimum additional bond specified by `value` must exceed the existential deposit
		#[pallet::call_index(1)]
		#[pallet::weight(< T as Config >::WeightInfo::bond())]
		pub fn bond_extra(
			origin: OriginFor<T>,
			#[pallet::compact] value: BalanceOf<T>,
		) -> DispatchResult {
			let signer = ensure_signed(origin)?;
			ensure!(value >= T::Currency::minimum_balance(), Error::<T>::InsufficientBond);
			let bond = Self::do_update_teerdays(&signer)?;
			let free_balance = T::Currency::free_balance(&signer);
			// free confusingly includes the already bonded amount, so we need to subtract it
			let value = value.min(free_balance.saturating_sub(bond.value));
			let new_bond_value = bond.value.saturating_add(value);
			Self::deposit_event(Event::<T>::Bonded { account: signer.clone(), amount: value });
			T::Currency::set_lock(TEERDAYS_ID, &signer, new_bond_value, WithdrawReasons::all());
			let teerday_bond = TeerDayBondOf::<T> {
				value: new_bond_value,
				last_updated: bond.last_updated,
				accumulated_tokentime: bond.accumulated_tokentime,
			};
			TeerDayBonds::<T>::insert(&signer, teerday_bond);
			Ok(())
		}

		/// Decrease an existing bond on the signer's account
		/// The minimum unbond specified by `value` must exceed the existential deposit
		/// If `value` is equal or greater than the current bond, the bond will be removed
		/// The unbonded amount will still be subject to an unbonding period before the amount can be withdrawn
		/// Unbonding will burn accumulated TEERdays pro rata.
		#[pallet::call_index(2)]
		#[pallet::weight(< T as Config >::WeightInfo::unbond())]
		pub fn unbond(
			origin: OriginFor<T>,
			#[pallet::compact] value: BalanceOf<T>,
		) -> DispatchResult {
			let signer = ensure_signed(origin)?;
			ensure!(Self::pending_unlock(&signer).is_none(), Error::<T>::PendingUnlock);
			ensure!(value >= T::Currency::minimum_balance(), Error::<T>::InsufficientUnbond);
			let bond = Self::do_update_teerdays(&signer)?;
			let now = bond.last_updated;

			let new_bonded_amount = bond.value.saturating_sub(value);
			let unbonded_amount = bond.value.saturating_sub(new_bonded_amount);

			// burn tokentime pro rata
			let new_tokentime = bond
				.accumulated_tokentime
				.checked_div(&bond.value)
				.unwrap_or_default()
				.saturating_mul(new_bonded_amount);

			let new_bond = TeerDayBondOf::<T> {
				value: new_bonded_amount,
				last_updated: now,
				accumulated_tokentime: new_tokentime,
			};

			if new_bond.value < T::Currency::minimum_balance() {
				TeerDayBonds::<T>::remove(&signer);
			} else {
				TeerDayBonds::<T>::insert(&signer, new_bond);
			}
			PendingUnlock::<T>::insert(&signer, (now + T::UnlockPeriod::get(), unbonded_amount));

			Self::deposit_event(Event::<T>::Unbonded {
				account: signer.clone(),
				amount: unbonded_amount,
			});
			Ok(())
		}

		/// Update the accumulated tokentime for an account lazily
		/// This can be helpful if other pallets use TEERdays and need to ensure the total
		/// accumulated tokentime is up to date.
		#[pallet::call_index(3)]
		#[pallet::weight(< T as Config >::WeightInfo::update_other())]
		pub fn update_other(origin: OriginFor<T>, who: T::AccountId) -> DispatchResult {
			let _signer = ensure_signed(origin)?;
			let _bond = Self::do_update_teerdays(&who)?;
			Ok(())
		}

		/// Withdraw an unbonded amount after the unbonding period has expired
		#[pallet::call_index(4)]
		#[pallet::weight(< T as Config >::WeightInfo::withdraw_unbonded())]
		pub fn withdraw_unbonded(origin: OriginFor<T>) -> DispatchResult {
			let signer = ensure_signed(origin)?;
			let unlocked = Self::try_withdraw_unbonded(&signer)?;
			Self::deposit_event(Event::<T>::Withdrawn {
				account: signer.clone(),
				amount: unlocked,
			});
			Ok(())
		}
	}
}

impl<T: Config> Pallet<T> {
	/// accumulates pending tokentime and updates state
	/// bond must exist or will err.
	/// returns the updated bond and deposits an event `BondUpdated`
	fn do_update_teerdays(
		account: &T::AccountId,
	) -> Result<TeerDayBondOf<T>, sp_runtime::DispatchError> {
		let bond = Self::teerday_bonds(account).ok_or(Error::<T>::NoBond)?;
		let now = pallet_timestamp::Pallet::<T>::get();
		let bond = bond.update(now);
		TeerDayBonds::<T>::insert(account, bond);
		Self::deposit_event(Event::<T>::TokenTimeUpdated { account: account.clone(), bond });
		Ok(bond)
	}

	fn try_withdraw_unbonded(
		account: &T::AccountId,
	) -> Result<BalanceOf<T>, sp_runtime::DispatchError> {
		let (due, amount) = Self::pending_unlock(account).ok_or(Error::<T>::NotUnlocking)?;
		let now = pallet_timestamp::Pallet::<T>::get();
		if now < due {
			return Err(Error::<T>::PendingUnlock.into())
		}
		let locked = T::Currency::balance_locked(TEERDAYS_ID, account);
		let amount = amount.min(locked);
		if amount == locked {
			T::Currency::remove_lock(TEERDAYS_ID, account);
		} else {
			T::Currency::set_lock(
				TEERDAYS_ID,
				account,
				locked.saturating_sub(amount),
				WithdrawReasons::all(),
			);
		}
		PendingUnlock::<T>::remove(account);
		Ok(amount)
	}
}

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;
#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;
pub mod weights;
