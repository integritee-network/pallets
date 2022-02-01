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

use codec::{Decode, Encode};
use frame_support::{
	decl_error, decl_event, decl_module, decl_storage,
	dispatch::DispatchResult,
	ensure,
	traits::{Currency, ExistenceRequirement, Get, OnTimestampSet},
	weights::{DispatchClass, Pays},
};
use frame_system::{self as system, ensure_signed};
use sp_core::H256;
use sp_runtime::traits::SaturatedConversion;
use sp_std::{prelude::*, str};
use teerex_primitives::*;

#[cfg(not(feature = "skip-ias-check"))]
use ias_verify::{verify_ias_report, SgxReport};

pub use crate::weights::WeightInfo;
use ias_verify::SgxBuildMode;

// Disambiguate associated types
pub type AccountId<T> = <T as frame_system::Config>::AccountId;
pub type BalanceOf<T> = <<T as Config>::Currency as Currency<AccountId<T>>>::Balance;

pub use pallet::*;

const MAX_RA_REPORT_LEN: usize = 4096;
const MAX_URL_LEN: usize = 256;
#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;

	#[pallet::pallet]
	#[pallet::generate_store(pub(super) trait Store)]
	pub struct Pallet<T, I = ()>(PhantomData<T>);

	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		type Error = Error<T>;

		// the integritee-service wants to register his enclave
		#[pallet::weight(<T as Config>::WeightInfo::register_enclave(), DispatchClass::Normal, Pays::Yes)]
		pub fn register_enclave(
			origin: OriginFor<T>,
			ra_report: Vec<u8>,
			worker_url: Vec<u8>,
		) -> DispatchResultWithPostInfo {
			log::info!("teerex: called into runtime call register_enclave()");
			let sender = ensure_signed(origin)?;
			ensure!(ra_report.len() <= MAX_RA_REPORT_LEN, <Error<T>>::RaReportTooLong);
			ensure!(worker_url.len() <= MAX_URL_LEN, <Error<T>>::EnclaveUrlTooLong);
			log::info!("teerex: parameter lenght ok");

			#[cfg(not(feature = "skip-ias-check"))]
			let enclave = Self::verify_report(&sender, ra_report).map(|report| {
				Enclave::new(
					sender.clone(),
					report.mr_enclave,
					report.timestamp,
					worker_url.clone(),
					report.build_mode,
				)
			})?;

			#[cfg(not(feature = "skip-ias-check"))]
			if !<AllowSGXDebugMode>::get() && enclave.sgx_mode == SgxBuildMode::Debug {
				log::error!("substraTEE_registry: debug mode is not allowed to attest!");
				return Err(<Error<T>>::SgxModeNotAllowed.into())
			}

			#[cfg(feature = "skip-ias-check")]
			log::warn!("[teerex]: Skipping remote attestation check. Only dev-chains are allowed to do this!");

			#[cfg(feature = "skip-ias-check")]
			let enclave = Enclave::new(
				sender.clone(),
				// insert mrenclave if the ra_report represents one, otherwise insert default
				<[u8; 32]>::decode(&mut ra_report.as_slice()).unwrap_or_default(),
				<timestamp::Pallet<T>>::get().saturated_into(),
				worker_url.clone(),
				SgxBuildMode::default(),
			);

			Self::add_enclave(&sender, &enclave)?;
			Self::deposit_event(RawEvent::AddedEnclave(sender, worker_url));
			Ok(().into())
		}

		// TODO: we can't expect a dead enclave to unregister itself
		// alternative: allow anyone to unregister an enclave that hasn't recently supplied a RA
		// such a call should be feeless if successful
		#[pallet::weight(<T as Config>::WeightInfo::unregister_enclave(), DispatchClass::Normal, Pays::Yes)]
		pub fn unregister_enclave(origin: OriginFor<T>) -> DispatchResultWithPostInfo {
			let sender = ensure_signed(origin)?;

			Self::remove_enclave(&sender)?;
			Self::deposit_event(RawEvent::RemovedEnclave(sender));
			Ok(())
		}

		#[pallet::weight(<T as Config>::WeightInfo::call_worker(), DispatchClass::Normal, Pays::Yes)]
		pub fn call_worker(origin: OriginFor<T>, request: Request) -> DispatchResult {
			let _sender = ensure_signed(origin)?;
			log::info!("call_worker with {:?}", request);
			Self::deposit_event(RawEvent::Forwarded(request.shard));
			Ok(().into())
		}

		/// The integritee worker calls this function for every processed parentchain_block to confirm a state update.
		#[pallet::weight(<T as Config>::WeightInfo::confirm_processed_parentchain_block(), DispatchClass::Normal, Pays::Yes)]
		pub fn confirm_processed_parentchain_block(
			origin: OriginFor<T>,
			block_hash: H256,
			trusted_calls_merkle_root: H256,
		) -> DispatchResultWithPostInfo {
			let sender = ensure_signed(origin)?;
			Self::is_registered_enclave(&sender)?;
			log::debug!(
				"Processed parentchain block confirmed for mrenclave {:?}, block hash {:?}",
				sender,
				block_hash
			);
			Self::deposit_event(RawEvent::ProcessedParentchainBlock(
				sender,
				block_hash,
				trusted_calls_merkle_root,
			));
			Ok(().into())
		}

		/// The integritee worker calls this function for every proposed sidechain_block.
		#[pallet::weight(<T as Config>::WeightInfo::confirm_proposed_sidechain_block(), DispatchClass::Normal, Pays::Yes)]
		pub fn confirm_proposed_sidechain_block(
			origin: OriginFor<T>,
			shard_id: ShardIdentifier,
			block_hash: H256,
		) -> DispatchResultWithPostInfo {
			let sender = ensure_signed(origin)?;
			Self::is_registered_enclave(&sender)?;
			let sender_index = Self::enclave_index(&sender);
			ensure!(
				<EnclaveRegistry::<T>>::get(sender_index).mr_enclave.encode() == shard_id.encode(),
				<Error<T>>::WrongMrenclaveForShard
			);
			<WorkerForShard>::insert(shard_id, sender_index);
			log::debug!(
				"Proposed sidechain block confirmed with shard {:?}, block hash {:?}",
				shard_id,
				block_hash
			);
			Self::deposit_event(RawEvent::ProposedSidechainBlock(sender, block_hash));
			Ok(().into())
		}

		/// Sent by a client who requests to get shielded funds managed by an enclave. For this on-chain balance is sent to the bonding_account of the enclave.
		/// The bonding_account does not have a private key as the balance on this account is exclusively managed from withing the pallet_teerex.
		/// Note: The bonding_account is bit-equivalent to the worker shard.
		#[pallet::weight(1000, DispatchClass::Normal, Pays::No)]
		pub fn shield_funds(
			origin: OriginFor<T>,
			incognito_account_encrypted: Vec<u8>,
			amount: BalanceOf<T>,
			bonding_account: T::AccountId,
		) -> DispatchResultWithPostInfo {
			let sender = ensure_signed(origin)?;
			T::Currency::transfer(
				&sender,
				&bonding_account,
				amount,
				ExistenceRequirement::AllowDeath,
			)?;
			Self::deposit_event(RawEvent::ShieldFunds(incognito_account_encrypted));
			Ok(().into())
		}

		/// Sent by enclaves only as a result of an `unshield` request from a client to an enclave.
		#[pallet::weight(1000, DispatchClass::Normal, Pays::No)]
		pub fn unshield_funds(
			origin: OriginFor<T>,
			public_account: T::AccountId,
			amount: BalanceOf<T>,
			bonding_account: T::AccountId,
			call_hash: H256,
		) -> DispatchResultWithPostInfo {
			let sender = ensure_signed(origin)?;
			Self::is_registered_enclave(&sender)?;
			let sender_index = <EnclaveIndex<T>>::get(sender);
			ensure!(
				<EnclaveRegistry::<T>>::get(sender_index).mr_enclave.encode() ==
					bonding_account.encode(),
				<Error<T>>::WrongMrenclaveForBondingAccount
			);

			if !<ExecutedCalls>::contains_key(call_hash) {
				log::info!("Executing unshielding call: {:?}", call_hash);
				T::Currency::transfer(
					&bonding_account,
					&public_account,
					amount,
					ExistenceRequirement::AllowDeath,
				)?;
				<ExecutedCalls>::insert(call_hash, 0);
				Self::deposit_event(RawEvent::UnshieldedFunds(public_account));
			} else {
				log::info!("Already executed unshielding call: {:?}", call_hash);
			}

			<ExecutedCalls>::mutate(call_hash, |confirmations| *confirmations += 1);
			Ok(().into())
		}
	}

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: system::Config> {
		AddedEnclave(T::AccountId, Vec<u8>),
		RemovedEnclave(T::AccountId),
		Forwarded(ShardIdentifier),
		ShieldFunds(Vec<u8>),
		UnshieldedFunds(T::AccountId),
		ProcessedParentchainBlock(T::AccountId, H256, H256),
		ProposedSidechainBlock(T::AccountId, H256),
	}

	#[pallet::error]
	pub enum Error<T> {
		/// Failed to decode enclave signer.
		EnclaveSignerDecodeError,
		/// Sender does not match attested enclave in report.
		SenderIsNotAttestedEnclave,
		/// Verifying RA report failed.
		RemoteAttestationVerificationFailed,
		RemoteAttestationTooOld,
		/// The enclave cannot attest, because its building mode is not allowed.
		SgxModeNotAllowed,
		/// The enclave is not registered.
		EnclaveIsNotRegistered,
		/// The bonding account doesn't match the enclave.
		WrongMrenclaveForBondingAccount,
		/// The shard doesn't match the enclave.
		WrongMrenclaveForShard,
		/// The worker url is too long.
		EnclaveUrlTooLong,
		/// The Remote Attestation report is too long.
		RaReportTooLong,
		/// The enclave doesn't exists.
		InexistentEnclave,
	}

	// Watch out: we start indexing with 1 instead of zero in order to
	// avoid ambiguity between Null and 0.
	#[pallet::storage]
	#[pallet::getter(fn enclave)]
	pub type EnclaveRegistry<T: Config> =
		StorageMap<_, Blake2_128Concat, u64, Enclave<T::AccountId, Vec<u8>>, ValueQuery>;

	#[pallet::storage]
	#[pallet::getter(fn enclave_count)]
	pub type EnclaveCount<T: Config> =
		StorageValue<_, u64, Enclave<T::AccountId, Vec<u8>>, OptionQuery>;

	// #[pallet::config]
	// pub trait Config: frame_system::Config + pallet_teerex::Config {
	// 	/// The overarching event type.
	// 	type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;
	// 	type WeightInfo: WeightInfo;
	// 	/// Max number of whitelisted oracle's releases allowed
	// 	#[pallet::constant]
	// 	type MaxWhitelistedReleases: Get<u32>;
	// }
}

pub trait Config: system::Config + timestamp::Config {
	type Event: From<Event<Self>> + Into<<Self as system::Config>::Event>;
	type Currency: Currency<<Self as system::Config>::AccountId>;
	type MomentsPerDay: Get<Self::Moment>;
	type WeightInfo: WeightInfo;
	type MaxSilenceTime: Get<Self::Moment>;
}

decl_storage! {
	trait Store for Module<T: Config> as Teerex {
		// Simple lists are not supported in runtime modules as theoretically O(n)
		// operations can be executed while only being charged O(1), see substrate
		// Kitties tutorial Chapter 2, Tracking all Kitties.

		// watch out: we start indexing with 1 instead of zero in order to
		// avoid ambiguity between Null and 0
		pub EnclaveRegistry get(fn enclave): map hasher(blake2_128_concat) u64 => Enclave<T::AccountId, Vec<u8>>;
		pub EnclaveCount get(fn enclave_count): u64;
		pub EnclaveIndex get(fn enclave_index): map hasher(blake2_128_concat) T::AccountId => u64;
		// enclave index of the worker that recently committed an update
		pub WorkerForShard get(fn worker_for_shard) : map hasher(blake2_128_concat) ShardIdentifier => u64;
		pub ExecutedCalls get(fn confirmed_calls): map hasher(blake2_128_concat) H256 => u64;
		pub AllowSGXDebugMode get(fn allow_sgx_debug_mode) config(allow_sgx_debug_mode): bool;
	}
}

impl<T: Config> Module<T> {
	fn add_enclave(
		sender: &T::AccountId,
		enclave: &Enclave<T::AccountId, Vec<u8>>,
	) -> DispatchResult {
		let enclave_idx = if <EnclaveIndex<T>>::contains_key(sender) {
			log::info!("Updating already registered enclave");
			<EnclaveIndex<T>>::get(sender)
		} else {
			let enclaves_count = Self::enclave_count()
				.checked_add(1)
				.ok_or("[Teerex]: Overflow adding new enclave to registry")?;
			<EnclaveIndex<T>>::insert(sender, enclaves_count);
			<EnclaveCount>::put(enclaves_count);
			enclaves_count
		};

		<EnclaveRegistry<T>>::insert(enclave_idx, &enclave);
		Ok(())
	}

	fn remove_enclave(sender: &T::AccountId) -> DispatchResult {
		ensure!(<EnclaveIndex<T>>::contains_key(sender), <Error<T>>::InexistentEnclave);
		let index_to_remove = <EnclaveIndex<T>>::take(sender);

		let enclaves_count = Self::enclave_count();
		let new_enclaves_count = enclaves_count
			.checked_sub(1)
			.ok_or("[Teerex]: Underflow removing an enclave from the registry")?;

		Self::swap_and_pop(index_to_remove, new_enclaves_count + 1)?;
		<EnclaveCount>::put(new_enclaves_count);

		Ok(())
	}

	/// Our list implementation would introduce holes in out list if if we try to remove elements from the middle.
	/// As the order of the enclave entries is not important, we use the swap an pop method to remove elements from
	/// the registry.
	fn swap_and_pop(index_to_remove: u64, new_enclaves_count: u64) -> DispatchResult {
		if index_to_remove != new_enclaves_count {
			let last_enclave = <EnclaveRegistry<T>>::get(&new_enclaves_count);
			<EnclaveRegistry<T>>::insert(index_to_remove, &last_enclave);
			<EnclaveIndex<T>>::insert(last_enclave.pubkey, index_to_remove);
		}

		<EnclaveRegistry<T>>::remove(new_enclaves_count);
		Ok(())
	}

	fn unregister_silent_workers(now: T::Moment) {
		let minimum = (now - T::MaxSilenceTime::get()).saturated_into::<u64>();
		let silent_workers = <EnclaveRegistry<T>>::iter()
			.filter(|e| e.1.timestamp < minimum)
			.map(|e| e.1.pubkey);
		for index in silent_workers {
			let result = Self::remove_enclave(&index);
			match result {
				Ok(_) => {
					log::info!("Unregister enclave because silent worker : {:?}", index);
					Self::deposit_event(RawEvent::RemovedEnclave(index));
				},
				Err(e) => {
					log::error!("Cannot unregister enclave : {:?}", e);
				},
			};
		}
	}
	/// Check if the sender is a registered enclave
	pub fn is_registered_enclave(
		account: &T::AccountId,
	) -> Result<bool, sp_runtime::DispatchError> {
		ensure!(<EnclaveIndex<T>>::contains_key(&account), <Error<T>>::EnclaveIsNotRegistered);
		Ok(true)
	}

	#[cfg(not(feature = "skip-ias-check"))]
	fn verify_report(
		sender: &T::AccountId,
		ra_report: Vec<u8>,
	) -> Result<SgxReport, sp_runtime::DispatchError> {
		let report = verify_ias_report(&ra_report)
			.map_err(|_| <Error<T>>::RemoteAttestationVerificationFailed)?;
		log::info!("RA Report: {:?}", report);

		let enclave_signer = T::AccountId::decode(&mut &report.pubkey[..])
			.map_err(|_| <Error<T>>::EnclaveSignerDecodeError)?;
		ensure!(sender == &enclave_signer, <Error<T>>::SenderIsNotAttestedEnclave);

		// TODO: activate state checks as soon as we've fixed our setup
		// ensure!((report.status == SgxStatus::Ok) | (report.status == SgxStatus::ConfigurationNeeded),
		//     "RA status is insufficient");
		// log::info!("teerex: status is acceptable");

		Self::ensure_timestamp_within_24_hours(report.timestamp)?;
		Ok(report)
	}

	#[cfg(not(feature = "skip-ias-check"))]
	fn ensure_timestamp_within_24_hours(report_timestamp: u64) -> DispatchResult {
		use sp_runtime::traits::CheckedSub;

		let elapsed_time = <timestamp::Pallet<T>>::get()
			.checked_sub(&T::Moment::saturated_from(report_timestamp))
			.ok_or("Underflow while calculating elapsed time since report creation")?;

		if elapsed_time < T::MomentsPerDay::get() {
			Ok(())
		} else {
			Err(<Error<T>>::RemoteAttestationTooOld.into())
		}
	}
}

impl<T: Config> OnTimestampSet<T::Moment> for Module<T> {
	fn on_timestamp_set(moment: T::Moment) {
		Self::unregister_silent_workers(moment)
	}
}

mod benchmarking;
#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;
pub mod weights;
