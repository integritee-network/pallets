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

pub use crate::weights::WeightInfo;
use enclave_bridge_primitives::{
	Request, ShardConfig, ShardIdentifier, ShardSignerStatus as ShardSignerStatusGeneric,
	UpgradableShardConfig, ENCLAVE_BRIDGE, MAX_SHARD_STATUS_SIGNER_COUNT,
};
use frame_support::{
	dispatch::{DispatchErrorWithPostInfo, DispatchResult, DispatchResultWithPostInfo},
	ensure,
	pallet_prelude::ConstU32,
	traits::{Currency, ExistenceRequirement},
};
use frame_system::{self, ensure_signed, pallet_prelude::BlockNumberFor};
use pallet_teerex::Pallet as Teerex;
use parity_scale_codec::Encode;
use sp_core::{bounded::BoundedVec, H256};
use sp_runtime::traits::{SaturatedConversion, Saturating};
use sp_std::{prelude::*, str, vec};
use teerex_primitives::{EnclaveFingerprint, MultiEnclave};
// Disambiguate associated types
pub type AccountId<T> = <T as frame_system::Config>::AccountId;
pub type BalanceOf<T> = <<T as Config>::Currency as Currency<AccountId<T>>>::Balance;
pub type ShardSignerStatus<T> =
	ShardSignerStatusGeneric<<T as frame_system::Config>::AccountId, BlockNumberFor<T>>;
pub type ShardSignerStatusVec<T> =
	BoundedVec<ShardSignerStatus<T>, ConstU32<MAX_SHARD_STATUS_SIGNER_COUNT>>;

pub use pallet::*;

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
	pub trait Config:
		frame_system::Config + pallet_timestamp::Config + pallet_teerex::Config
	{
		type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
		type Currency: Currency<<Self as frame_system::Config>::AccountId>;
		type WeightInfo: WeightInfo;
	}

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		/// an indirect invocation has been registered for execution on L2
		IndirectInvocationRegistered(ShardIdentifier),
		/// funds have been shielded to L2
		ShieldFunds {
			shard: ShardIdentifier,
			encrypted_beneficiary: Vec<u8>,
			amount: BalanceOf<T>,
		},
		/// funds have been unshielded from L2 back to L1
		UnshieldedFunds {
			shard: ShardIdentifier,
			beneficiary: T::AccountId,
			amount: BalanceOf<T>,
		},
		/// L2 confirmed processing of a parentchain block
		ProcessedParentchainBlock {
			shard: ShardIdentifier,
			block_hash: H256,
			trusted_calls_merkle_root: H256,
			block_number: BlockNumberFor<T>,
		},
		/// An enclave has published some [hash] with some metadata [data].
		PublishedHash {
			enclave_fingerprint: EnclaveFingerprint,
			hash: H256,
			data: Vec<u8>,
		},
		ShardConfigUpdated(ShardIdentifier),
		/// An enclave has been purged from a shard status. Most likely due to inactivity
		PurgedEnclaveFromShardConfig {
			shard: ShardIdentifier,
			subject: T::AccountId,
		},
	}

	#[pallet::error]
	pub enum Error<T> {
		/// The shard doesn't match the enclave.
		WrongFingerprintForShard,
		/// The number of `extra_topics` passed to `publish_hash` exceeds the limit.
		TooManyTopics,
		/// The length of the `data` passed to `publish_hash` exceeds the limit.
		DataTooLong,
		/// Too many enclaves in ShardStatus
		TooManyEnclaves,
		/// No such enclave was found in shard status
		EnclaveNotFoundInShardStatus,
		/// Shard not found
		ShardNotFound,
	}

	#[pallet::storage]
	#[pallet::getter(fn shard_status)]
	pub type ShardStatus<T: Config> =
		StorageMap<_, Blake2_128Concat, ShardIdentifier, ShardSignerStatusVec<T>, OptionQuery>;

	/// this registry holds shard configurations as well as pending updates thereof.
	/// We decided to put config and update data in the same storage for performance reasons.
	/// see argumentation and benchmarks here:
	/// https://github.com/integritee-network/pallets/pull/201#discussion_r1263668271
	#[pallet::storage]
	#[pallet::getter(fn shard_config)]
	pub type ShardConfigRegistry<T: Config> = StorageMap<
		_,
		Blake2_128Concat,
		ShardIdentifier,
		UpgradableShardConfig<T::AccountId, BlockNumberFor<T>>,
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
		#[pallet::weight((<T as Config>::WeightInfo::invoke(), DispatchClass::Normal, Pays::Yes))]
		pub fn invoke(origin: OriginFor<T>, request: Request) -> DispatchResult {
			let _sender = ensure_signed(origin)?;
			log::info!(target: ENCLAVE_BRIDGE, "invoke with {:?}", request);
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
			block_number: BlockNumberFor<T>,
			trusted_calls_merkle_root: H256,
		) -> DispatchResultWithPostInfo {
			let sender = ensure_signed(origin)?;
			Self::get_sovereign_enclave_and_touch_shard(
				&sender,
				shard,
				<frame_system::Pallet<T>>::block_number(),
			)?;

			log::debug!(
				"Processed parentchain block confirmed by sovereign enclave {:?} for shard {:}, block hash {:?}",
				sender,
				shard,
				block_hash
			);
			Self::deposit_event(Event::ProcessedParentchainBlock {
				shard,
				block_hash,
				trusted_calls_merkle_root,
				block_number,
			});
			Ok(().into())
		}

		/// Sent by a client who requests to get shielded funds managed by an enclave. For this on-chain balance is sent to the bonding_account of the enclave.
		/// The bonding_account does not have a private key as the balance on this account is exclusively managed from withing the pallet_teerex.
		/// Note: The bonding_account is bit-equivalent to the worker shard.
		#[pallet::call_index(2)]
		#[pallet::weight((<T as Config>::WeightInfo::shield_funds(), DispatchClass::Normal, Pays::Yes))]
		pub fn shield_funds(
			origin: OriginFor<T>,
			shard: ShardIdentifier,
			incognito_account_encrypted: Vec<u8>,
			amount: BalanceOf<T>,
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
			Self::deposit_event(Event::ShieldFunds {
				shard,
				encrypted_beneficiary: incognito_account_encrypted,
				amount,
			});
			Ok(().into())
		}

		/// Sent by enclaves only as a result of an `unshield` request from a client to an enclave.
		#[pallet::call_index(3)]
		#[pallet::weight((<T as Config>::WeightInfo::unshield_funds(), DispatchClass::Normal, Pays::Yes))]
		pub fn unshield_funds(
			origin: OriginFor<T>,
			shard: ShardIdentifier,
			beneficiary: T::AccountId,
			amount: BalanceOf<T>,
			call_hash: H256,
		) -> DispatchResultWithPostInfo {
			let sender = ensure_signed(origin)?;
			Self::get_sovereign_enclave_and_touch_shard(
				&sender,
				shard,
				<frame_system::Pallet<T>>::block_number(),
			)?;
			let bonding_account = T::AccountId::decode(&mut shard.encode().as_ref())
				.expect("always possible to decode [u8;32]");
			if !<ExecutedUnshieldCalls<T>>::contains_key(call_hash) {
				log::info!(target: ENCLAVE_BRIDGE, "Executing unshielding call: {:?}", call_hash);
				T::Currency::transfer(
					&bonding_account,
					&beneficiary,
					amount,
					ExistenceRequirement::AllowDeath,
				)?;
				<ExecutedUnshieldCalls<T>>::insert(call_hash, 0);
				Self::deposit_event(Event::UnshieldedFunds { shard, beneficiary, amount });
			} else {
				log::info!(
					target: ENCLAVE_BRIDGE,
					"Already executed unshielding call: {:?}",
					call_hash
				);
			}

			<ExecutedUnshieldCalls<T>>::mutate(call_hash, |confirmations| *confirmations += 1);
			Ok(().into())
		}

		/// Publish a hash as a result of an arbitrary enclave operation.
		///
		/// The `mrenclave` of the origin will be used as an event topic a client can subscribe to.
		/// The concept of shards isn't applied here because a proof of computation should be bound
		/// to the fingerprint of the enclave. A shard would only be necessary if state needs to be
		/// persisted across upgrades.
		///
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
			Self::touch_shard(
				enclave.fingerprint(),
				&sender,
				enclave.fingerprint(),
				<frame_system::Pallet<T>>::block_number(),
			)?;

			ensure!(extra_topics.len() <= TOPICS_LIMIT, <Error<T>>::TooManyTopics);
			ensure!(data.len() <= DATA_LENGTH_LIMIT, <Error<T>>::DataTooLong);

			let mut topics = extra_topics;
			topics.push(T::Hash::from(enclave.fingerprint().into()));

			Self::deposit_event_indexed(
				&topics,
				Event::PublishedHash { enclave_fingerprint: enclave.fingerprint(), hash, data },
			);

			Ok(().into())
		}

		/// Update shard config
		/// To be respected by L2 instances after `enactment_delay` parentchain blocks
		/// If no previous config exists, the `enactment_delay` parameter will be ignored
		/// and the `shard_config` will be active immediately
		#[pallet::call_index(5)]
		#[pallet::weight((<T as Config>::WeightInfo::update_shard_config(), DispatchClass::Normal, Pays::Yes))]
		pub fn update_shard_config(
			origin: OriginFor<T>,
			shard: ShardIdentifier,
			shard_config: ShardConfig<T::AccountId>,
			enactment_delay: BlockNumberFor<T>,
		) -> DispatchResultWithPostInfo {
			let maybe_sender = ensure_signed_or_root(origin)?;

			let current_block_number = <frame_system::Pallet<T>>::block_number();
			let new_upgradable_shard_config: UpgradableShardConfig<
				T::AccountId,
				BlockNumberFor<T>,
			> = match Self::get_maybe_updated_shard_config(shard, current_block_number, false) {
				Some(old_config) => {
					if let Some(sender) = maybe_sender {
						let enclave = Teerex::<T>::get_sovereign_enclave(&sender)?;
						ensure!(
							old_config.enclave_fingerprint == enclave.fingerprint(),
							Error::<T>::WrongFingerprintForShard
						);
						Self::touch_shard(
							shard,
							&sender,
							enclave.fingerprint(),
							current_block_number,
						)?;
					}
					UpgradableShardConfig::from(old_config).with_pending_upgrade(
						shard_config,
						current_block_number.saturating_add(enactment_delay),
					)
				},
				None => {
					// if shard does not exist, we allow any ShardIdentifier to be created by any registered enclave or root
					if let Some(sender) = maybe_sender {
						let enclave = Teerex::<T>::get_sovereign_enclave(&sender)?;
						Self::touch_shard(
							shard,
							&sender,
							enclave.fingerprint(),
							current_block_number,
						)?;
					}
					shard_config.into()
				},
			};

			<ShardConfigRegistry<T>>::insert(shard, new_upgradable_shard_config.clone());

			log::info!(
				target: ENCLAVE_BRIDGE,
				"shard config updated for {:?}, new config: {:?}",
				shard,
				new_upgradable_shard_config
			);
			Self::deposit_event(Event::ShardConfigUpdated(shard));
			Ok(().into())
		}
		/// Purge enclave from shard status
		/// this is a root call to be used for maintenance. Shall eventually be replaced by a lazy timeout
		#[pallet::call_index(6)]
		#[pallet::weight((<T as Config>::WeightInfo::purge_enclave_from_shard_status(), DispatchClass::Normal, Pays::No))]
		pub fn purge_enclave_from_shard_status(
			origin: OriginFor<T>,
			shard: ShardIdentifier,
			subject: T::AccountId,
		) -> DispatchResultWithPostInfo {
			ensure_root(origin)?;

			let new_status: ShardSignerStatusVec<T> = Self::shard_status(shard)
				.ok_or(Error::<T>::ShardNotFound)?
				.iter()
				.cloned()
				.filter(|signer_status| signer_status.signer != subject)
				.collect::<Vec<ShardSignerStatus<T>>>()
				.try_into()
				.expect("can only become smaller by filtering");

			<crate::pallet::ShardStatus<T>>::insert(shard, new_status);

			log::info!(
				target: ENCLAVE_BRIDGE,
				"purged {:?} from shard status for {:?}",
				subject,
				shard,
			);
			Self::deposit_event(crate::pallet::Event::PurgedEnclaveFromShardConfig {
				shard,
				subject,
			});
			Ok(().into())
		}
	}
}

impl<T: Config> Pallet<T> {
	#[allow(clippy::type_complexity)]
	pub fn get_sovereign_enclave_and_touch_shard(
		enclave_signer: &T::AccountId,
		shard: ShardIdentifier,
		current_block_number: BlockNumberFor<T>,
	) -> Result<(MultiEnclave<Vec<u8>>, ShardSignerStatusVec<T>), DispatchErrorWithPostInfo> {
		let enclave = Teerex::<T>::get_sovereign_enclave(enclave_signer)?;
		ensure!(
			enclave.fingerprint() ==
				Self::get_maybe_updated_shard_config(shard, current_block_number, true)
					.unwrap_or_else(|| ShardConfig::new(shard))
					.enclave_fingerprint,
			<Error<T>>::WrongFingerprintForShard
		);
		let shard_status =
			Self::touch_shard(shard, enclave_signer, enclave.fingerprint(), current_block_number)?;
		Ok((enclave, shard_status))
	}

	pub fn get_maybe_updated_shard_config(
		shard: ShardIdentifier,
		current_block_number: BlockNumberFor<T>,
		apply_due_update: bool,
	) -> Option<ShardConfig<T::AccountId>> {
		Self::shard_config(shard).map(|current| {
			current.upgrade_at.filter(|&at| at <= current_block_number).map_or_else(
				|| current.active_config.clone(),
				|_| {
					current.pending_upgrade.map_or(current.active_config.clone(), |due_update| {
						if apply_due_update {
							<ShardConfigRegistry<T>>::insert(
								shard,
								UpgradableShardConfig::from(due_update.clone()),
							);
						}
						due_update
					})
				},
			)
		})
	}

	/// will update the `last_activity` field for `enclave_signer` in a shard's status
	pub fn touch_shard(
		shard: ShardIdentifier,
		enclave_signer: &T::AccountId,
		enclave_fingerprint: EnclaveFingerprint,
		current_block_number: BlockNumberFor<T>,
	) -> Result<ShardSignerStatusVec<T>, DispatchErrorWithPostInfo> {
		let new_status = ShardSignerStatus::<T> {
			signer: enclave_signer.clone(),
			fingerprint: enclave_fingerprint,
			last_activity: current_block_number,
		};

		let signer_statuses: Vec<ShardSignerStatus<T>> = Self::shard_status(shard)
			.map(|status_bvec| {
				let mut status_vec = status_bvec.to_vec();
				if let Some(index) = status_vec.iter().position(|i| &i.signer == enclave_signer) {
					status_vec[index] = new_status.clone();
				} else {
					status_vec.push(new_status.clone());
				}
				status_vec
			})
			.unwrap_or_else(|| vec![new_status]);

		let signer_statuses = ShardSignerStatusVec::<T>::try_from(signer_statuses)
			.map_err(|_| Error::<T>::TooManyEnclaves)?;
		log::trace!(
			target: ENCLAVE_BRIDGE,
			"touched shard: {:?}, signer statuses: {:?}",
			shard,
			signer_statuses
		);
		<ShardStatus<T>>::insert(shard, signer_statuses.clone());
		Ok(signer_statuses)
	}

	pub fn most_recent_shard_update(shard: &ShardIdentifier) -> Option<ShardSignerStatus<T>> {
		<ShardStatus<T>>::get(shard)
			.map(|mut statuses| {
				statuses.sort_by_key(|a| a.last_activity);
				statuses.last().cloned()
			})
			.unwrap_or_default()
	}

	/// Deposit a pallets teerex event with the corresponding topics.
	///
	/// Handles the conversion to the overarching event type.
	fn deposit_event_indexed(topics: &[T::Hash], event: Event<T>) {
		<frame_system::Pallet<T>>::deposit_event_indexed(
			topics,
			<T as Config>::RuntimeEvent::from(event).into(),
		)
	}
}

#[cfg(any(test, feature = "runtime-benchmarks"))]
mod benchmarking;
#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;
pub mod weights;
