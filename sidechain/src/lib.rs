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

#![cfg_attr(not(feature = "std"), no_std)]

use codec::Encode;
use frame_support::{dispatch::DispatchResultWithPostInfo, traits::Get};
use frame_system::{self};
use pallet_teerex::Pallet as Teerex;
use sidechain_primitives::SidechainBlockConfirmation;
use sp_core::H256;
use sp_std::{prelude::*, str};
use teerex_primitives::ShardIdentifier;

pub use crate::weights::WeightInfo;

// Disambiguate associated types
pub type AccountId<T> = <T as frame_system::Config>::AccountId;
pub type ShardBlockNumber = (ShardIdentifier, u64);

pub use pallet::*;

#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;

	#[pallet::pallet]
	#[pallet::generate_store(pub(super) trait Store)]
	#[pallet::without_storage_info]
	pub struct Pallet<T>(PhantomData<T>);

	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {}

	#[pallet::config]
	pub trait Config: frame_system::Config + pallet_teerex::Config {
		type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;
		type WeightInfo: WeightInfo;
		// If a block arrives far too early, an error should be returned
		#[pallet::constant]
		type EarlyBlockProposalLenience: Get<u64>;
	}

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		ProposedSidechainBlock(T::AccountId, H256),
		FinalizedSidechainBlock(T::AccountId, H256),
	}

	// Enclave index of the worker that recently committed an update.
	#[pallet::storage]
	#[pallet::getter(fn worker_for_shard)]
	pub type WorkerForShard<T: Config> =
		StorageMap<_, Blake2_128Concat, ShardIdentifier, u64, ValueQuery>;

	#[pallet::storage]
	#[pallet::getter(fn latest_sidechain_block_confirmation)]
	pub type LatestSidechainBlockConfirmation<T: Config> =
		StorageMap<_, Blake2_128Concat, ShardIdentifier, SidechainBlockConfirmation, ValueQuery>;

	#[pallet::storage]
	pub type SidechainBlockConfirmationQueue<T: Config> =
		StorageMap<_, Blake2_128Concat, ShardBlockNumber, SidechainBlockConfirmation, ValueQuery>;

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// The integritee worker calls this function for every imported sidechain_block.
		#[pallet::weight((<T as Config>::WeightInfo::confirm_imported_sidechain_block(), DispatchClass::Normal, Pays::Yes))]
		pub fn confirm_imported_sidechain_block(
			origin: OriginFor<T>,
			shard_id: ShardIdentifier,
			block_number: u64,
			block_number_diff: u64,
			block_header_hash: H256,
		) -> DispatchResultWithPostInfo {
			let confirmation = SidechainBlockConfirmation { block_number, block_header_hash };

			let sender = ensure_signed(origin)?;
			Teerex::<T>::is_registered_enclave(&sender)?;
			let sender_index = Teerex::<T>::enclave_index(&sender);
			let sender_enclave = Teerex::<T>::enclave(sender_index)
				.ok_or(pallet_teerex::Error::<T>::EmptyEnclaveRegistry)?;
			ensure!(
				sender_enclave.mr_enclave.encode() == shard_id.encode(),
				pallet_teerex::Error::<T>::WrongMrenclaveForShard
			);

			// Simple logic for now: only accept blocks from first registered enclave.
			if sender_index != 1 {
				log::debug!(
					"Ignore block confirmation from registered enclave with index {:?}",
					sender_index
				);
				return Ok(().into())
			}

			let lenience = T::EarlyBlockProposalLenience::get();
			let mut latest_confirmation = <LatestSidechainBlockConfirmation<T>>::get(shard_id);
			let latest_block_number = latest_confirmation.block_number;
			let block_number = confirmation.block_number;

			if block_number > Self::add_to_block_number(latest_block_number, lenience)? {
				// Block is far too early and hence refused.
				return Err(<Error<T>>::BlockNumberTooHigh.into())
			} else if block_number >
				Self::add_to_block_number(latest_block_number, block_number_diff)?
			{
				// Block is too early and stored in the queue for later import.
				if !<SidechainBlockConfirmationQueue<T>>::contains_key((shard_id, block_number)) {
					<SidechainBlockConfirmationQueue<T>>::insert(
						(shard_id, block_number),
						confirmation,
					);
				}
			} else if block_number ==
				Self::add_to_block_number(latest_block_number, block_number_diff)?
			{
				Self::finalize_block(shard_id, confirmation, &sender, sender_index);
				latest_confirmation = confirmation;

				Self::finalize_blocks_from_queue(
					shard_id,
					&sender,
					sender_index,
					latest_confirmation,
					block_number_diff,
				)?;
			} else if block_number > latest_block_number {
				// Block does not belong to the finalized ones.
				return Err(<Error<T>>::ReceivedUnexpectedSidechainBlock.into())
			} else {
				// Block is too late and hence refused.
				return Err(<Error<T>>::OutdatedBlockNumber.into())
			}

			Ok(().into())
		}
	}

	#[pallet::error]
	pub enum Error<T> {
		/// A proposed block is too early.
		BlockNumberTooHigh,
		/// A proposed block is too late and already outdated.
		OutdatedBlockNumber,
		/// A proposed block is unexpected.
		ReceivedUnexpectedSidechainBlock,
	}
}

impl<T: Config> Pallet<T> {
	fn finalize_block(
		shard_id: ShardIdentifier,
		confirmation: SidechainBlockConfirmation,
		sender: &T::AccountId,
		sender_index: u64,
	) {
		<LatestSidechainBlockConfirmation<T>>::insert(shard_id, confirmation);
		<WorkerForShard<T>>::insert(shard_id, sender_index);
		let block_header_hash = confirmation.block_header_hash;
		log::debug!(
			"Imported sidechain block confirmed with shard {:?}, block header hash {:?}",
			shard_id,
			block_header_hash
		);
		Self::deposit_event(Event::FinalizedSidechainBlock(sender.clone(), block_header_hash));
	}

	fn finalize_blocks_from_queue(
		shard_id: ShardIdentifier,
		sender: &T::AccountId,
		sender_index: u64,
		mut latest_confirmation: SidechainBlockConfirmation,
		block_number_diff: u64,
	) -> DispatchResultWithPostInfo {
		let mut latest_block_number = latest_confirmation.block_number;
		let mut expected_block_number =
			Self::add_to_block_number(latest_block_number, block_number_diff)?;
		let lenience = T::EarlyBlockProposalLenience::get();
		let mut i: u64 = 0;
		while <SidechainBlockConfirmationQueue<T>>::contains_key((shard_id, expected_block_number)) &&
			i < lenience
		{
			Self::check_queue_is_empty_until_expected_block(
				shard_id,
				latest_block_number,
				block_number_diff,
			)?;
			let confirmation =
				<SidechainBlockConfirmationQueue<T>>::take((shard_id, expected_block_number));

			Self::finalize_block(shard_id, confirmation, sender, sender_index);
			latest_confirmation = confirmation;

			latest_block_number = latest_confirmation.block_number;
			expected_block_number =
				Self::add_to_block_number(latest_block_number, block_number_diff)?;
			i = Self::add_to_block_number(i, 1)?;
		}
		Ok(().into())
	}

	fn check_queue_is_empty_until_expected_block(
		shard_id: ShardIdentifier,
		latest_block_number: u64,
		block_number_diff: u64,
	) -> DispatchResultWithPostInfo {
		for i in 0..block_number_diff {
			let block_number_to_check = Self::add_to_block_number(latest_block_number, i)?;
			if <SidechainBlockConfirmationQueue<T>>::contains_key((shard_id, block_number_to_check))
			{
				return Err(<Error<T>>::ReceivedUnexpectedSidechainBlock.into())
			}
		}

		Ok(().into())
	}

	fn add_to_block_number(block_number: u64, diff: u64) -> Result<u64, &'static str> {
		block_number.checked_add(diff).ok_or("[Sidechain]: Overflow adding new block")
	}
}

mod benchmarking;
#[cfg(test)]
mod mock;
#[cfg(all(test, not(feature = "skip-ias-check")))]
mod tests;
pub mod weights;
