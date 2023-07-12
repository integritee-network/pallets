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

use codec::Encode;
use enclave_bridge_primitives::*;
use frame_support::{
	dispatch::{DispatchErrorWithPostInfo, DispatchResult, DispatchResultWithPostInfo},
	ensure,
	traits::{Currency, ExistenceRequirement},
};
use frame_system::{self, ensure_signed};
use sp_core::H256;
use sp_runtime::traits::{SaturatedConversion, Saturating};
use sp_std::{prelude::*, str, vec};

pub use crate::weights::WeightInfo;

// Disambiguate associated types
pub type AccountId<T> = <T as frame_system::Config>::AccountId;
pub type BalanceOf<T> = <<T as Config>::Currency as Currency<AccountId<T>>>::Balance;
pub type ShardSignerStatusVec<T> = Vec<
	ShardSignerStatus<
		<T as frame_system::Config>::AccountId,
		<T as frame_system::Config>::BlockNumber,
	>,
>;

pub use pallet::*;
use pallet_teerex::Pallet as Teerex;
use teerex_primitives::MultiEnclave;

/// Maximum number of topics for the `publish_hash` call.
const TOPICS_LIMIT: usize = 5;
/// Maximum number of bytes for the `data` in the `publish_hash` call.
const DATA_LENGTH_LIMIT: usize = 100;

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
	pub trait Config: frame_system::Config + timestamp::Config + pallet_teerex::Config {
		type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
		type Currency: Currency<<Self as frame_system::Config>::AccountId>;
		type WeightInfo: WeightInfo;
	}

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		IndirectInvocationRegistered(ShardIdentifier),
		ShieldFunds(Vec<u8>, BalanceOf<T>),
		UnshieldedFunds(T::AccountId, BalanceOf<T>),
		ProcessedParentchainBlock(ShardIdentifier, H256, H256, T::BlockNumber),
		/// An enclave with [mr_enclave] has published some [hash] with some metadata [data].
		PublishedHash {
			fingerprint: EnclaveFingerprint,
			hash: H256,
			data: Vec<u8>,
		},
		ShardConfigUpdated(ShardIdentifier),
	}

	#[pallet::storage]
	#[pallet::getter(fn shard_status)]
	pub type ShardStatus<T: Config> = StorageMap<
		_,
		Blake2_128Concat,
		ShardIdentifier,
		Vec<ShardSignerStatus<T::AccountId, T::BlockNumber>>,
		OptionQuery,
	>;

	#[pallet::storage]
	#[pallet::getter(fn shard_config)]
	pub type ShardConfigRegistry<T: Config> = StorageMap<
		_,
		Blake2_128Concat,
		ShardIdentifier,
		UpgradableShardConfig<T::AccountId, T::BlockNumber>,
		OptionQuery,
	>;

	#[pallet::storage]
	#[pallet::getter(fn confirmed_calls)]
	pub type ExecutedUnshieldCalls<T: Config> =
		StorageMap<_, Blake2_128Concat, H256, u64, ValueQuery>;

	#[pallet::call]
	impl<T: Config> Pallet<T>
	where
		// Needed for the conversion of `mr_enclave` to a `Hash`.
		// The condition holds for all known chains.
		<T as frame_system::Config>::Hash: From<[u8; 32]>,
	{
		#[pallet::call_index(0)]
		#[pallet::weight((<T as Config>::WeightInfo::call_worker(), DispatchClass::Normal, Pays::Yes))]
		pub fn invoke(origin: OriginFor<T>, request: Request) -> DispatchResult {
			let _sender = ensure_signed(origin)?;
			log::info!("invoke with {:?}", request);
			Self::deposit_event(Event::IndirectInvocationRegistered(request.shard));
			Ok(())
		}

		/// The integritee worker calls this function for every processed parentchain_block to confirm a state update.
		#[pallet::call_index(1)]
		#[pallet::weight((<T as Config>::WeightInfo::confirm_processed_parentchain_block(), DispatchClass::Normal, Pays::Yes))]
		pub fn confirm_processed_parentchain_block(
			origin: OriginFor<T>,
			shard: ShardIdentifier,
			block_hash: H256,
			block_number: T::BlockNumber,
			trusted_calls_merkle_root: H256,
		) -> DispatchResultWithPostInfo {
			let sender = ensure_signed(origin)?;
			Self::get_sovereign_enclave_and_touch_shard(&sender, shard)?;

			log::debug!(
				"Processed parentchain block confirmed by sovereign enclave {:?} for shard {:}, block hash {:?}",
				sender,
				shard,
				block_hash
			);
			Self::deposit_event(Event::ProcessedParentchainBlock(
				shard,
				block_hash,
				trusted_calls_merkle_root,
				block_number,
			));
			Ok(().into())
		}

		/// Sent by a client who requests to get shielded funds managed by an enclave. For this on-chain balance is sent to the bonding_account of the enclave.
		/// The bonding_account does not have a private key as the balance on this account is exclusively managed from withing the pallet_teerex.
		/// Note: The bonding_account is bit-equivalent to the worker shard.
		#[pallet::call_index(2)]
		#[pallet::weight((1000, DispatchClass::Normal, Pays::No))]
		pub fn shield_funds(
			origin: OriginFor<T>,
			incognito_account_encrypted: Vec<u8>,
			amount: BalanceOf<T>,
			shard: ShardIdentifier,
		) -> DispatchResultWithPostInfo {
			let sender = ensure_signed(origin)?;
			let bonding_account = T::AccountId::decode(&mut shard.encode().as_ref())
				.expect("always possible to decode [u8;32]");
			T::Currency::transfer(
				&sender,
				&bonding_account,
				amount,
				ExistenceRequirement::AllowDeath,
			)?;
			Self::deposit_event(Event::ShieldFunds(incognito_account_encrypted, amount));
			Ok(().into())
		}

		/// Sent by enclaves only as a result of an `unshield` request from a client to an enclave.
		#[pallet::call_index(3)]
		#[pallet::weight((1000, DispatchClass::Normal, Pays::No))]
		pub fn unshield_funds(
			origin: OriginFor<T>,
			beneficiary: T::AccountId,
			amount: BalanceOf<T>,
			shard: ShardIdentifier,
			call_hash: H256,
		) -> DispatchResultWithPostInfo {
			let sender = ensure_signed(origin)?;
			Self::get_sovereign_enclave_and_touch_shard(&sender, shard)?;
			let bonding_account = T::AccountId::decode(&mut shard.encode().as_ref())
				.expect("always possible to decode [u8;32]");
			if !<ExecutedUnshieldCalls<T>>::contains_key(call_hash) {
				log::info!("Executing unshielding call: {:?}", call_hash);
				T::Currency::transfer(
					&bonding_account,
					&beneficiary,
					amount,
					ExistenceRequirement::AllowDeath,
				)?;
				<ExecutedUnshieldCalls<T>>::insert(call_hash, 0);
				Self::deposit_event(Event::UnshieldedFunds(beneficiary, amount));
			} else {
				log::info!("Already executed unshielding call: {:?}", call_hash);
			}

			<ExecutedUnshieldCalls<T>>::mutate(call_hash, |confirmations| *confirmations += 1);
			Ok(().into())
		}

		/// Publish a hash as a result of an arbitrary enclave operation.
		///
		/// The `mrenclave` of the origin will be used as an event topic a client can subscribe to.
		/// `extra_topics`, if any, will be used as additional event topics.
		///
		/// `data` can be anything worthwhile publishing related to the hash. If it is a
		/// utf8-encoded string, the UIs will usually even render the text.
		#[pallet::call_index(4)]
		#[pallet::weight((<T as Config>::WeightInfo::publish_hash(extra_topics.len().saturated_into(), data.len().saturated_into()), DispatchClass::Normal, Pays::Yes))]
		pub fn publish_hash(
			origin: OriginFor<T>,
			hash: H256,
			extra_topics: Vec<T::Hash>,
			data: Vec<u8>,
		) -> DispatchResultWithPostInfo {
			let sender = ensure_signed(origin)?;
			let enclave = Teerex::<T>::get_sovereign_enclave(&sender)?;
			Self::touch_shard(enclave.fingerprint(), &sender)?;

			ensure!(extra_topics.len() <= TOPICS_LIMIT, <Error<T>>::TooManyTopics);
			ensure!(data.len() <= DATA_LENGTH_LIMIT, <Error<T>>::DataTooLong);

			let mut topics = extra_topics;
			topics.push(T::Hash::from(enclave.fingerprint().into()));

			Self::deposit_event_indexed(
				&topics,
				Event::PublishedHash { fingerprint: enclave.fingerprint(), hash, data },
			);

			Ok(().into())
		}

		/// Update shard config
		/// To be respected by L2 instances after `enactment_delay` parentchain blocks
		/// If no previous config exists, the `enactment_delay` parameter will be ignored
		/// and the `shard_config` will be active immediately
		#[pallet::call_index(5)]
		#[pallet::weight((1000, DispatchClass::Normal, Pays::No))]
		pub fn update_shard_config(
			origin: OriginFor<T>,
			shard: ShardIdentifier,
			shard_config: ShardConfig<T::AccountId>,
			enactment_delay: T::BlockNumber,
		) -> DispatchResultWithPostInfo {
			let sender = ensure_signed(origin)?;
			let enclave = Teerex::<T>::get_sovereign_enclave(&sender)?;
			let current_block_number = <frame_system::Pallet<T>>::block_number();
			let new_upgradable_shard_config: UpgradableShardConfig<T::AccountId, T::BlockNumber> =
				match Self::get_maybe_updated_shard_config(shard) {
					Some(old_config) => {
						ensure!(
							old_config.enclave_fingerprint == enclave.fingerprint(),
							Error::<T>::WrongFingerprintForShard
						);
						UpgradableShardConfig::from(old_config).with_pending_upgrade(
							shard_config,
							current_block_number.saturating_add(enactment_delay),
						)
					},
					None => {
						// if shard does not exist, we allow any ShardIdentifier to be created by any registered enclave
						shard_config.into()
					},
				};

			Self::touch_shard(shard, &sender)?;
			<ShardConfigRegistry<T>>::insert(shard, new_upgradable_shard_config.clone());

			Self::deposit_event(Event::ShardConfigUpdated(shard));
			log::info!(
				"shard config updated for {:?}, new config: {:?}",
				shard,
				new_upgradable_shard_config
			);
			Ok(().into())
		}
	}

	#[pallet::error]
	pub enum Error<T> {
		/// The shard doesn't match the enclave.
		WrongFingerprintForShard,
		/// The number of `extra_topics` passed to `publish_hash` exceeds the limit.
		TooManyTopics,
		/// The length of the `data` passed to `publish_hash` exceeds the limit.
		DataTooLong,
	}
}

impl<T: Config> Pallet<T> {
	/// Deposit a pallets teerex event with the corresponding topics.
	///
	/// Handles the conversion to the overarching event type.
	fn deposit_event_indexed(topics: &[T::Hash], event: Event<T>) {
		<frame_system::Pallet<T>>::deposit_event_indexed(
			topics,
			<T as Config>::RuntimeEvent::from(event).into(),
		)
	}

	pub fn get_maybe_updated_shard_config(
		shard: ShardIdentifier,
	) -> Option<ShardConfig<T::AccountId>> {
		let current_block_number = <frame_system::Pallet<T>>::block_number();
		Self::shard_config(shard).map(|current| {
			current.update_at.clone().filter(|&at| at <= current_block_number).map_or_else(
				|| current.active_config.clone(),
				|_| current.pending_update.unwrap_or(current.active_config.clone()),
			)
		})
	}

	pub fn get_sovereign_enclave_and_touch_shard(
		enclave_signer: &T::AccountId,
		shard: ShardIdentifier,
	) -> Result<MultiEnclave<Vec<u8>>, DispatchErrorWithPostInfo> {
		let enclave = Teerex::<T>::get_sovereign_enclave(enclave_signer)?;
		ensure!(
			enclave.fingerprint() ==
				Self::get_maybe_updated_shard_config(shard)
					.unwrap_or(ShardConfig::new(shard))
					.enclave_fingerprint,
			<Error<T>>::WrongFingerprintForShard
		);
		Self::touch_shard(shard, &enclave_signer)?;
		Ok(enclave)
	}

	pub fn touch_shard(
		shard: ShardIdentifier,
		enclave_signer: &T::AccountId,
	) -> Result<ShardSignerStatusVec<T>, DispatchErrorWithPostInfo> {
		let enclave = Teerex::<T>::get_sovereign_enclave(enclave_signer)?;

		let current_block_number = <frame_system::Pallet<T>>::block_number();

		let new_status = ShardSignerStatus {
			signer: enclave_signer.clone(),
			fingerprint: enclave.fingerprint(),
			last_activity: current_block_number,
		};

		let signer_statuses = <ShardStatus<T>>::get(shard)
			.map(|mut status_vec| {
				if let Some(index) = status_vec.iter().position(|i| &i.signer == enclave_signer) {
					status_vec[index] = new_status.clone();
				} else {
					status_vec.push(new_status.clone());
				}
				status_vec
			})
			.unwrap_or_else(|| vec![new_status]);

		<ShardStatus<T>>::insert(shard, signer_statuses.clone());
		Ok(signer_statuses)
	}

	pub fn most_recent_shard_update(
		shard: &ShardIdentifier,
	) -> Option<ShardSignerStatus<T::AccountId, T::BlockNumber>> {
		<ShardStatus<T>>::get(shard)
			.map(|mut statuses| {
				statuses.sort_by_key(|a| a.last_activity);
				statuses.last().cloned()
			})
			.unwrap_or_default()
	}
}

#[cfg(any(test, feature = "runtime-benchmarks"))]
mod benchmarking;
#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;
pub mod weights;
