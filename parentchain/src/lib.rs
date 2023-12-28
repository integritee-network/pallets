#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

#[frame_support::pallet]
pub mod pallet {
	use crate::weights::WeightInfo;
	use frame_support::{pallet_prelude::*, sp_runtime::traits::Header};
	use frame_system::pallet_prelude::*;

	const STORAGE_VERSION: StorageVersion = StorageVersion::new(1);
	#[pallet::pallet]
	#[pallet::storage_version(STORAGE_VERSION)]
	#[pallet::without_storage_info]
	pub struct Pallet<T, I = ()>(PhantomData<(T, I)>);

	/// Configuration trait.
	#[pallet::config]
	pub trait Config<I: 'static = ()>: frame_system::Config {
		type RuntimeEvent: From<Event<Self, I>>
			+ IsType<<Self as frame_system::Config>::RuntimeEvent>;
		type WeightInfo: WeightInfo;
	}

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config<I>, I: 'static = ()> {
		/// a parentchain block has been registered
		SetBlock {
			block_number: T::BlockNumber,
			parent_hash: T::Hash,
			block_hash: T::Hash,
		},
		ShardVaultInitialized {
			account: T::AccountId,
		},
	}

	#[pallet::error]
	pub enum Error<T, I = ()> {
		/// Sahrd vault has been previously initialized and can't be overwritten
		ShardVaultAlreadyInitialized,
	}

	/// The current block number being processed. Set by `set_block`.
	#[pallet::storage]
	#[pallet::getter(fn shard_vault)]
	pub(super) type ShardVault<T: Config<I>, I: 'static = ()> =
		StorageValue<_, T::AccountId, OptionQuery>;

	/// The current block number being processed. Set by `set_block`.
	#[pallet::storage]
	#[pallet::getter(fn block_number)]
	pub(super) type Number<T: Config<I>, I: 'static = ()> =
		StorageValue<_, T::BlockNumber, OptionQuery>;

	/// Hash of the previous block. Set by `set_block`.
	#[pallet::storage]
	#[pallet::getter(fn parent_hash)]
	pub(super) type ParentHash<T: Config<I>, I: 'static = ()> =
		StorageValue<_, T::Hash, OptionQuery>;

	/// Hash of the last block. Set by `set_block`.
	#[pallet::storage]
	#[pallet::getter(fn block_hash)]
	pub(super) type BlockHash<T: Config<I>, I: 'static = ()> =
		StorageValue<_, T::Hash, OptionQuery>;

	#[pallet::hooks]
	impl<T: Config<I>, I: 'static> Hooks<BlockNumberFor<T>> for Pallet<T, I> {}

	#[pallet::call]
	impl<T: Config<I>, I: 'static> Pallet<T, I> {
		#[pallet::call_index(0)]
		#[pallet::weight(T::WeightInfo::set_block())]
		pub fn set_block(origin: OriginFor<T>, header: T::Header) -> DispatchResult {
			ensure_root(origin)?;
			<Number<T, I>>::put(header.number());
			<ParentHash<T, I>>::put(header.parent_hash());
			<BlockHash<T, I>>::put(header.hash());
			Self::deposit_event(Event::SetBlock {
				block_number: *header.number(),
				parent_hash: *header.parent_hash(),
				block_hash: header.hash(),
			});
			Ok(())
		}

		#[pallet::call_index(1)]
		#[pallet::weight(T::WeightInfo::set_block())]
		pub fn init_shard_vault(origin: OriginFor<T>, account: T::AccountId) -> DispatchResult {
			ensure_root(origin)?;
			ensure!(Self::shard_vault().is_none(), Error::<T, I>::ShardVaultAlreadyInitialized);
			<crate::pallet::ShardVault<T, I>>::put(account.clone());
			Self::deposit_event(crate::pallet::Event::ShardVaultInitialized { account });
			Ok(())
		}
	}
}

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;
pub mod weights;
