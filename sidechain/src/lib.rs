/*
	Copyright 2021 Integritee AG and Supercomputing Systems AG

	Licensed under the MICROSOFT REFERENCE SOURCE LICENSE (MS-RSL) (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

		https://referencesource.microsoft.com/license.html

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.

*/

#![cfg_attr(not(feature = "std"), no_std)]

use enclave_bridge_primitives::ShardIdentifier;
use frame_support::dispatch::DispatchResultWithPostInfo;
use frame_system::{self};
use pallet_enclave_bridge::Pallet as EnclaveBridge;
use sidechain_primitives::SidechainBlockConfirmation;
use sp_core::H256;
use sp_std::{prelude::*, str, vec};

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
	#[pallet::without_storage_info]
	pub struct Pallet<T>(PhantomData<T>);

	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {}

	#[pallet::config]
	pub trait Config:
		frame_system::Config + pallet_teerex::Config + pallet_enclave_bridge::Config
	{
		type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
		type WeightInfo: WeightInfo;
	}

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		/// a sidechain block has been finalized
		FinalizedSidechainBlock {
			shard: ShardIdentifier,
			block_header_hash: H256,
			validateer: T::AccountId,
		},
	}

	#[pallet::storage]
	#[pallet::getter(fn latest_sidechain_block_confirmation)]
	pub type LatestSidechainBlockConfirmation<T: Config> =
		StorageMap<_, Blake2_128Concat, ShardIdentifier, SidechainBlockConfirmation, ValueQuery>;

	#[pallet::storage]
	#[pallet::getter(fn sidechain_block_finalization_candidate)]
	pub type SidechainBlockFinalizationCandidate<T: Config> =
		StorageMap<_, Blake2_128Concat, ShardIdentifier, u64, ValueQuery>;

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// The integritee worker calls this function for every imported sidechain_block.
		#[pallet::call_index(0)]
		#[pallet::weight((<T as Config>::WeightInfo::confirm_imported_sidechain_block(), DispatchClass::Normal, Pays::Yes))]
		pub fn confirm_imported_sidechain_block(
			origin: OriginFor<T>,
			shard: ShardIdentifier,
			block_number: u64,
			next_finalization_candidate_block_number: u64,
			block_header_hash: H256,
		) -> DispatchResultWithPostInfo {
			let sender = ensure_signed(origin)?;
			let (_enclave, shard_status) =
				EnclaveBridge::<T>::get_sovereign_enclave_and_touch_shard(
					&sender,
					shard,
					<frame_system::Pallet<T>>::block_number(),
				)?;

			// TODO: Simple logic for now: only accept blocks from first registered enclave.
			if sender != shard_status[0].signer {
				log::debug!(
					"Ignore block confirmation from registered enclave with index > 1: {:?}",
					sender
				);
				return Ok(().into())
			}
			let finalization_candidate_block_number =
				<SidechainBlockFinalizationCandidate<T>>::try_get(shard).unwrap_or(1);

			ensure!(
				block_number == finalization_candidate_block_number,
				<Error<T>>::ReceivedUnexpectedSidechainBlock
			);
			ensure!(
				next_finalization_candidate_block_number > finalization_candidate_block_number,
				<Error<T>>::InvalidNextFinalizationCandidateBlockNumber
			);

			<SidechainBlockFinalizationCandidate<T>>::insert(
				shard,
				next_finalization_candidate_block_number,
			);
			Self::finalize_block(
				shard,
				SidechainBlockConfirmation { block_number, block_header_hash },
				&sender,
			);
			Ok(().into())
		}
	}

	#[pallet::error]
	pub enum Error<T> {
		/// A proposed block is unexpected.
		ReceivedUnexpectedSidechainBlock,
		/// The value for the next finalization candidate is invalid.
		InvalidNextFinalizationCandidateBlockNumber,
	}
}

impl<T: Config> Pallet<T> {
	fn finalize_block(
		shard: ShardIdentifier,
		confirmation: SidechainBlockConfirmation,
		sender: &T::AccountId,
	) {
		<LatestSidechainBlockConfirmation<T>>::insert(shard, confirmation);
		let block_header_hash = confirmation.block_header_hash;
		log::debug!(
			"Imported sidechain block confirmed with shard {:?}, block header hash {:?}",
			shard,
			block_header_hash
		);
		Self::deposit_event(Event::FinalizedSidechainBlock {
			shard,
			block_header_hash,
			validateer: sender.clone(),
		});
	}
}

mod benchmarking;
#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;
pub mod weights;
