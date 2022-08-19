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
use sidechain_primitives::types::header::SidechainHeader;
use sp_core::H256;
use sp_std::{prelude::*, str};
use teerex_primitives::ShardIdentifier;

pub use crate::weights::WeightInfo;

// Disambiguate associated types
pub type AccountId<T> = <T as frame_system::Config>::AccountId;
pub type ShardBlockNumber = (ShardIdentifier, u64);

pub use pallet::*;

#[cfg(feature = "std")]
use serde::{Deserialize, Serialize};

#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;

	#[pallet::pallet]
	#[pallet::generate_store(pub(super) trait Store)]
	#[pallet::without_storage_info]
	pub struct Pallet<T>(PhantomData<T>);

	#[derive(PartialEq, Eq, Clone, Encode, Decode, Debug, Copy, Default, TypeInfo)]
	#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
	pub struct SidechainBlockConfirmation {
		pub block_number: u64,
		/// Hash of the block header. TODO check
		pub block_header_hash: H256,
	}

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
	}

	// Enclave index of the worker that recently committed an update.
	#[pallet::storage]
	#[pallet::getter(fn worker_for_shard)]
	pub type WorkerForShard<T: Config> =
		StorageMap<_, Blake2_128Concat, ShardIdentifier, u64, ValueQuery>;

	#[pallet::storage]
	#[pallet::getter(fn latest_sidechain_header)]
	pub type LatestSidechainHeader<T: Config> =
		StorageMap<_, Blake2_128Concat, ShardIdentifier, SidechainHeader, ValueQuery>;

	#[pallet::storage]
	pub type SidechainHeaderQueue<T: Config> = StorageDoubleMap<
		_,
		Blake2_128Concat,
		ShardBlockNumber,
		Blake2_128Concat,
		H256,
		SidechainHeader,
		ValueQuery,
	>;

	#[pallet::storage]
	#[pallet::getter(fn latest_sidechain_block_confirmation)]
	pub(super) type LatestSidechainBlockConfirmation<T: Config> =
		StorageValue<_, SidechainBlockConfirmation, ValueQuery>;

	#[pallet::storage]
	pub type SidechainBlockConfirmationQueue<T: Config> =
		StorageMap<_, Blake2_128Concat, ShardBlockNumber, SidechainBlockConfirmation, ValueQuery>;

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// The integritee worker calls this function for every proposed sidechain_block.
		#[pallet::weight((<T as Config>::WeightInfo::confirm_proposed_sidechain_block(), DispatchClass::Normal, Pays::Yes))]
		pub fn confirm_proposed_sidechain_block(
			origin: OriginFor<T>,
			shard_id: ShardIdentifier,
			header: SidechainHeader,
		) -> DispatchResultWithPostInfo {
			let sender = ensure_signed(origin)?;
			Teerex::<T>::is_registered_enclave(&sender)?;
			let sender_index = Teerex::<T>::enclave_index(&sender);
			let sender_enclave = Teerex::<T>::enclave(sender_index)
				.ok_or(pallet_teerex::Error::<T>::EmptyEnclaveRegistry)?;
			ensure!(
				sender_enclave.mr_enclave.encode() == shard_id.encode(),
				pallet_teerex::Error::<T>::WrongMrenclaveForShard
			);

			let lenience = T::EarlyBlockProposalLenience::get();
			let mut latest_header = <LatestSidechainHeader<T>>::get(shard_id);
			let latest_block_number = latest_header.block_number;
			let block_number = header.block_number;

			if block_number > Self::add_to_block_number(latest_block_number, lenience)? {
				// Block is far too early and hence refused.
				return Err(<Error<T>>::BlockNumberTooHigh.into())
			} else if block_number > Self::add_to_block_number(latest_block_number, 1)? {
				// Block is too early and stored in the queue for later import.
				if !<SidechainHeaderQueue<T>>::contains_key(
					(shard_id, block_number),
					header.parent_hash,
				) {
					<SidechainHeaderQueue<T>>::insert(
						(shard_id, block_number),
						header.parent_hash,
						header,
					);
				}
			} else if block_number == Self::add_to_block_number(latest_block_number, 1)? {
				// Block number is correct to be imported.
				// Confirm that the parent hash is the hash of the previous block.
				// Block number 1 does not have a previous block, hence skip checking there.
				if latest_header.hash() == header.parent_hash || header.block_number == 1 {
					Self::confirm_sidechain_block_old(shard_id, header, &sender, sender_index);
					latest_header = header;
				}
				Self::finalize_blocks_from_queue_old(
					shard_id,
					&sender,
					sender_index,
					latest_header,
				)?;
			} else {
				// Block is too late and hence refused.
				return Err(<Error<T>>::OutdatedBlockNumber.into())
			}

			Ok(().into())
		}

		/// The integritee worker calls this function for every imported sidechain_block.
		#[pallet::weight((<T as Config>::WeightInfo::confirm_imported_sidechain_block(), DispatchClass::Normal, Pays::Yes))]
		pub fn confirm_imported_sidechain_block(
			origin: OriginFor<T>,
			shard_id: ShardIdentifier,
			header: SidechainHeader,
		) -> DispatchResultWithPostInfo {
			let sender = ensure_signed(origin)?;
			Teerex::<T>::is_registered_enclave(&sender)?;
			let sender_index = Teerex::<T>::enclave_index(&sender);
			let sender_enclave = Teerex::<T>::enclave(sender_index)
				.ok_or(pallet_teerex::Error::<T>::EmptyEnclaveRegistry)?;
			ensure!(
				sender_enclave.mr_enclave.encode() == shard_id.encode(),
				pallet_teerex::Error::<T>::WrongMrenclaveForShard
			);

			let lenience = T::EarlyBlockProposalLenience::get();
			let mut latest_header = <LatestSidechainHeader<T>>::get(shard_id);
			let latest_block_number = latest_header.block_number;
			let block_number = header.block_number;

			if block_number > Self::add_to_block_number(latest_block_number, lenience)? {
				// Block is far too early and hence refused.
				return Err(<Error<T>>::BlockNumberTooHigh.into())
			} else if block_number > Self::add_to_block_number(latest_block_number, 1)? {
				// Block is too early and stored in the queue for later import.
				if !<SidechainHeaderQueue<T>>::contains_key(
					(shard_id, block_number),
					header.parent_hash,
				) {
					<SidechainHeaderQueue<T>>::insert(
						(shard_id, block_number),
						header.parent_hash,
						header,
					);
				}
			} else if block_number == Self::add_to_block_number(latest_block_number, 1)? {
				// Block number is correct to be imported.
				// Confirm that the parent hash is the hash of the previous block.
				// Block number 1 does not have a previous block, hence skip checking there.
				if latest_header.hash() == header.parent_hash || header.block_number == 1 {
					Self::confirm_sidechain_block_old(shard_id, header, &sender, sender_index);
					latest_header = header;
				}
				Self::finalize_blocks_from_queue_old(
					shard_id,
					&sender,
					sender_index,
					latest_header,
				)?;
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
		/// A propsed block is too late and already outdated.
		OutdatedBlockNumber,
	}
}

impl<T: Config> Pallet<T> {
	fn confirm_sidechain_block(
		shard_id: ShardIdentifier,
		header: SidechainHeader,
		sender: &T::AccountId,
		sender_index: u64,
	) {
		<LatestSidechainHeader<T>>::insert(shard_id, header);
		<WorkerForShard<T>>::insert(shard_id, sender_index);
		let block_hash = header.block_data_hash;
		log::debug!(
			"Proposed sidechain block confirmed with shard {:?}, block hash {:?}",
			shard_id,
			block_hash
		);
		Self::deposit_event(Event::ProposedSidechainBlock(sender.clone(), block_hash));
	}

	fn finalize_blocks_from_queue(
		shard_id: ShardIdentifier,
		sender: &T::AccountId,
		sender_index: u64,
		mut latest_header: SidechainHeader,
	) -> DispatchResultWithPostInfo {
		let mut latest_block_number = latest_header.block_number;
		let mut expected_block_number = Self::add_to_block_number(latest_block_number, 1)?;
		let lenience = T::EarlyBlockProposalLenience::get();
		let mut i: u64 = 0;
		while <SidechainHeaderQueue<T>>::contains_key(
			(shard_id, expected_block_number),
			latest_header.hash(),
		) && i < lenience
		{
			let header = <SidechainHeaderQueue<T>>::take(
				(shard_id, expected_block_number),
				latest_header.hash(),
			);
			let _ = <SidechainHeaderQueue<T>>::clear_prefix(
				(shard_id, expected_block_number),
				u32::MAX,
				None,
			);
			// Confirm that the parent hash is the hash of the previous block.
			// Block number 1 does not have a previous block, hence skip checking there.
			if latest_header.hash() == header.parent_hash || header.block_number == 1 {
				Self::confirm_sidechain_block_old(shard_id, header, &sender, sender_index);
				latest_header = header;
			}
			latest_block_number = latest_header.block_number;
			expected_block_number = Self::add_to_block_number(latest_block_number, 1)?;
			i = Self::add_to_block_number(i, 1)?;
		}
		Ok(().into())
	}

	fn confirm_sidechain_block_old(
		shard_id: ShardIdentifier,
		header: SidechainHeader,
		sender: &T::AccountId,
		sender_index: u64,
	) {
		<LatestSidechainHeader<T>>::insert(shard_id, header);
		<WorkerForShard<T>>::insert(shard_id, sender_index);
		let block_hash = header.block_data_hash;
		log::debug!(
			"Proposed sidechain block confirmed with shard {:?}, block hash {:?}",
			shard_id,
			block_hash
		);
		Self::deposit_event(Event::ProposedSidechainBlock(sender.clone(), block_hash));
	}

	fn finalize_blocks_from_queue_old(
		shard_id: ShardIdentifier,
		sender: &T::AccountId,
		sender_index: u64,
		mut latest_header: SidechainHeader,
	) -> DispatchResultWithPostInfo {
		let mut latest_block_number = latest_header.block_number;
		let mut expected_block_number = Self::add_to_block_number(latest_block_number, 1)?;
		let lenience = T::EarlyBlockProposalLenience::get();
		let mut i: u64 = 0;
		while <SidechainHeaderQueue<T>>::contains_key(
			(shard_id, expected_block_number),
			latest_header.hash(),
		) && i < lenience
		{
			let header = <SidechainHeaderQueue<T>>::take(
				(shard_id, expected_block_number),
				latest_header.hash(),
			);
			let _ = <SidechainHeaderQueue<T>>::clear_prefix(
				(shard_id, expected_block_number),
				u32::MAX,
				None,
			);
			// Confirm that the parent hash is the hash of the previous block.
			// Block number 1 does not have a previous block, hence skip checking there.
			if latest_header.hash() == header.parent_hash || header.block_number == 1 {
				Self::confirm_sidechain_block_old(shard_id, header, &sender, sender_index);
				latest_header = header;
			}
			latest_block_number = latest_header.block_number;
			expected_block_number = Self::add_to_block_number(latest_block_number, 1)?;
			i = Self::add_to_block_number(i, 1)?;
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
