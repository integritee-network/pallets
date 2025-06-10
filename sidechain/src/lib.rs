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
use sidechain_primitives::{SidechainBlockConfirmation, SidechainBlockNumber};
use sp_core::H256;
use sp_std::{prelude::*, str, vec};

pub use crate::weights::WeightInfo;

// Disambiguate associated types
pub type AccountId<T> = <T as frame_system::Config>::AccountId;
pub type ShardAndBlockNumber = (ShardIdentifier, SidechainBlockNumber);

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
			block_number: SidechainBlockNumber,
			block_header_hash: H256,
			validateer: T::AccountId,
		},
	}

	#[pallet::error]
	pub enum Error<T> {
		/// A proposed finalization candidate block is outdated
		FinalizationCandidateIsOutdated,
		/// The provided last finalized ancestor block number doesn't match.
		/// This can mean a fork happened or the sender validateer is not up to date with L1
		AncestorNumberMismatch,
		/// The provided last finalized ancestor block hash doesn't match.
		/// This can mean a fork happened or the sender validateer is not up to date with L1
		AncestorHashMismatch,
		/// sender hasn't provided an ancestor although an ancestor has been finalized
		AncestorMissing,
	}

	#[pallet::storage]
	#[pallet::getter(fn latest_sidechain_block_confirmation)]
	pub type LatestSidechainBlockConfirmation<T: Config> =
		StorageMap<_, Blake2_128Concat, ShardIdentifier, SidechainBlockConfirmation, OptionQuery>;

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// The integritee worker calls this function for every imported sidechain_block.
		#[pallet::call_index(0)]
		#[pallet::weight((<T as Config>::WeightInfo::confirm_imported_sidechain_block(), DispatchClass::Normal, Pays::Yes))]
		pub fn confirm_imported_sidechain_block(
			origin: OriginFor<T>,
			shard: ShardIdentifier,
			latest_finalized_ancestor: Option<SidechainBlockConfirmation>,
			finalization_candidate: SidechainBlockConfirmation,
		) -> DispatchResultWithPostInfo {
			let sender = ensure_signed(origin)?;
			let (_enclave, shard_status) =
				EnclaveBridge::<T>::get_sovereign_enclave_and_touch_shard(
					&sender,
					shard,
					<frame_system::Pallet<T>>::block_number(),
				)?;

			// TODO: Simple but robust logic for now:
			// https://github.com/integritee-network/pallets/issues/254
			// accept only blocks from first validateer in shard_status
			if sender != shard_status[0].signer {
				log::debug!(
					"Ignore block confirmation from registered enclave with index > 1: {:?}",
					sender
				);
				return Ok(().into());
			}

			if let Some(known_ancestor) = Self::latest_sidechain_block_confirmation(shard) {
				let provided_ancestor =
					latest_finalized_ancestor.ok_or(Error::<T>::AncestorMissing)?;
				ensure!(
					finalization_candidate.block_number > known_ancestor.block_number,
					<Error<T>>::FinalizationCandidateIsOutdated
				);
				ensure!(
					known_ancestor.block_number == provided_ancestor.block_number,
					<Error<T>>::AncestorNumberMismatch
				);
				ensure!(
					known_ancestor.block_header_hash == provided_ancestor.block_header_hash,
					<Error<T>>::AncestorHashMismatch
				);
			}
			Self::finalize_block(shard, finalization_candidate, &sender);
			Ok(().into())
		}
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
		let block_number = confirmation.block_number;
		log::debug!(
			"Imported sidechain block {} confirmed with shard {:?}, block header hash {:?}",
			block_number,
			shard,
			block_header_hash
		);
		Self::deposit_event(Event::FinalizedSidechainBlock {
			shard,
			block_number,
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
