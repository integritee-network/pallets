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
use frame_support::{
	dispatch::{DispatchErrorWithPostInfo, DispatchResult, DispatchResultWithPostInfo},
	ensure,
	traits::{Currency, ExistenceRequirement, Get, OnTimestampSet},
};
use frame_system::{self, ensure_signed};
use sgx_verify::{
	deserialize_enclave_identity, deserialize_tcb_info, extract_certs, verify_certificate_chain,
};
use sp_core::H256;
use sp_runtime::{traits::SaturatedConversion, Saturating};
use sp_std::{prelude::*, str};
use teerex_primitives::*;

pub use crate::weights::WeightInfo;
use teerex_primitives::{SgxBuildMode, SgxStatus};

// Disambiguate associated types
pub type AccountId<T> = <T as frame_system::Config>::AccountId;
pub type BalanceOf<T> = <<T as Config>::Currency as Currency<AccountId<T>>>::Balance;

pub use pallet::*;

const SGX_RA_PROOF_MAX_LEN: usize = 5000;

const MAX_URL_LEN: usize = 256;
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
	pub trait Config: frame_system::Config + timestamp::Config {
		type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
		type Currency: Currency<<Self as frame_system::Config>::AccountId>;

		#[pallet::constant]
		type MomentsPerDay: Get<Self::Moment>;

		type WeightInfo: WeightInfo;

		/// If a worker does not re-register within `MaxSilenceTime`, it will be unregistered.
		#[pallet::constant]
		type MaxSilenceTime: Get<Self::Moment>;
	}

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		AddedEnclave {
			registered_by: T::AccountId,
			worker_url: Option<Vec<u8>>,
			tcb_status: Option<SgxStatus>,
			attestation_method: SgxAttestationMethod,
		},
		RemovedEnclave(T::AccountId),
		Forwarded(ShardIdentifier),
		ShieldFunds(Vec<u8>),
		UnshieldedFunds(T::AccountId),
		ProcessedParentchainBlock(T::AccountId, H256, H256, T::BlockNumber),
		/// An enclave with [mr_enclave] has published some [hash] with some metadata [data].
		PublishedHash {
			fingerprint: EnclaveFingerprint,
			hash: H256,
			data: Vec<u8>,
		},
		SgxTcbInfoRegistered {
			fmspc: Fmspc,
			on_chain_info: SgxTcbInfoOnChain,
		},
		SgxQuotingEnclaveRegistered {
			quoting_enclave: SgxQuotingEnclave,
		},
	}

	// Watch out: we start indexing with 1 instead of zero in order to
	// avoid ambiguity between Null and 0.
	#[pallet::storage]
	#[pallet::getter(fn sovereign_enclaves)]
	pub type SovereignEnclaves<T: Config> =
		StorageMap<_, Blake2_128Concat, T::AccountId, MultiEnclave<Vec<u8>>, OptionQuery>;

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
	#[pallet::getter(fn quoting_enclave)]
	pub type SgxQuotingEnclaveRegistry<T: Config> = StorageValue<_, SgxQuotingEnclave, ValueQuery>;

	#[pallet::storage]
	#[pallet::getter(fn tcb_info)]
	pub type SgxTcbInfo<T: Config> =
		StorageMap<_, Blake2_128Concat, Fmspc, SgxTcbInfoOnChain, ValueQuery>;

	#[pallet::storage]
	#[pallet::getter(fn confirmed_calls)]
	pub type ExecutedCalls<T: Config> = StorageMap<_, Blake2_128Concat, H256, u64, ValueQuery>;

	#[pallet::storage]
	#[pallet::getter(fn allow_sgx_debug_mode)]
	pub type SgxAllowDebugMode<T: Config> = StorageValue<_, bool, ValueQuery>;

	#[pallet::genesis_config]
	#[cfg_attr(feature = "std", derive(Default))]
	pub struct GenesisConfig {
		pub allow_sgx_debug_mode: bool,
	}

	#[pallet::genesis_build]
	impl<T: Config> GenesisBuild<T> for GenesisConfig {
		fn build(&self) {
			SgxAllowDebugMode::<T>::put(self.allow_sgx_debug_mode);
		}
	}

	#[pallet::call]
	impl<T: Config> Pallet<T>
	where
		// Needed for the conversion of `mr_enclave` to a `Hash`.
		// The condition holds for all known chains.
		<T as frame_system::Config>::Hash: From<[u8; 32]>,
	{
		// the integritee-service wants to register his enclave
		#[pallet::call_index(0)]
		#[pallet::weight((<T as Config>::WeightInfo::register_ias_enclave(), DispatchClass::Normal, Pays::Yes))]
		pub fn register_sgx_enclave(
			origin: OriginFor<T>,
			proof: Vec<u8>,
			worker_url: Option<Vec<u8>>,
			attestation_method: SgxAttestationMethod,
		) -> DispatchResultWithPostInfo {
			log::info!("teerex: called into runtime call register_sgx_enclave()");
			let sender = ensure_signed(origin)?;
			ensure!(proof.len() <= SGX_RA_PROOF_MAX_LEN, <Error<T>>::RaProofTooLong);
			ensure!(
				worker_url.clone().unwrap_or_default().len() <= MAX_URL_LEN,
				<Error<T>>::EnclaveUrlTooLong
			);
			log::info!("teerex: parameter length ok");

			let enclave = match attestation_method {
				SgxAttestationMethod::Ias => {
					let report = sgx_verify::verify_ias_report(&proof)
						.map_err(|_| <Error<T>>::RemoteAttestationVerificationFailed)?;
					log::info!("teerex: IAS report successfully verified");
					let enclave = SgxEnclave::new(
						report.report_data,
						report.mr_enclave,
						report.mr_signer,
						report.timestamp,
						report.build_mode,
						report.status,
					)
					.with_attestation_method(SgxAttestationMethod::Ias);

					ensure!(
						Ok(sender.clone()) ==
							T::AccountId::decode(&mut report.report_data.lower32().as_ref()),
						<Error<T>>::SenderIsNotAttestedEnclave
					);

					// TODO: activate state checks as soon as we've fixed our setup #83
					// ensure!((report.status == SgxStatus::Ok) | (report.status == SgxStatus::ConfigurationNeeded),
					//     "RA status is insufficient");
					// log::info!("teerex: status is acceptable");

					Self::ensure_timestamp_within_24_hours(report.timestamp)?;
					enclave
				},
				SgxAttestationMethod::Dcap { proxied } => {
					let verification_time = <timestamp::Pallet<T>>::get();

					let qe = <SgxQuotingEnclaveRegistry<T>>::get();
					let (fmspc, tcb_info, report) = sgx_verify::verify_dcap_quote(
						&proof,
						verification_time.saturated_into(),
						&qe,
					)
					.map_err(|e| {
						log::warn!("verify_dcap_quote failed: {:?}", e);
						<Error<T>>::RemoteAttestationVerificationFailed
					})?;

					if !proxied {
						ensure!(
							Ok(sender.clone()) ==
								T::AccountId::decode(&mut report.report_data.lower32().as_ref()),
							<Error<T>>::SenderIsNotAttestedEnclave
						);
					}

					log::info!("teerex: DCAP quote verified. FMSPC from quote: {:?}", fmspc);
					let tcb_info_on_chain = <SgxTcbInfo<T>>::get(fmspc);
					ensure!(tcb_info_on_chain.verify_examinee(&tcb_info), "tcb_info is outdated");

					let enclave = SgxEnclave::new(
						report.report_data,
						report.mr_enclave,
						report.mr_signer,
						report.timestamp,
						report.build_mode,
						report.status,
					)
					.with_attestation_method(SgxAttestationMethod::Dcap { proxied });

					// TODO: activate state checks as soon as we've fixed our setup #83
					// ensure!((report.status == SgxStatus::Ok) | (report.status == SgxStatus::ConfigurationNeeded),
					//     "RA status is insufficient");
					// log::info!("teerex: status is acceptable");
					enclave
				},
				SgxAttestationMethod::Skip { proxied } => SgxEnclave::new(
					SgxReportData::default(),
					// insert mrenclave if the ra_report represents one, otherwise insert default
					<MrEnclave>::decode(&mut proof.as_slice()).unwrap_or_default(),
					MrSigner::default(),
					<timestamp::Pallet<T>>::get().saturated_into(),
					SgxBuildMode::default(),
					SgxStatus::Invalid,
				)
				.with_pubkey(sender.encode().as_ref())
				.with_attestation_method(SgxAttestationMethod::Skip { proxied }),
			};

			if !<SgxAllowDebugMode<T>>::get() && enclave.build_mode == SgxBuildMode::Debug {
				log::warn!("teerex: debug mode is not allowed to attest!");
				return Err(<Error<T>>::SgxModeNotAllowed.into())
			}

			let enclave = match worker_url {
				Some(ref url) => enclave.with_url(url.clone()),
				None => enclave,
			};

			Self::add_enclave(&sender, &MultiEnclave::from(enclave.clone()))?;
			Self::poke_shard(enclave.mr_enclave.into(), &sender)?;

			Self::deposit_event(Event::AddedEnclave {
				registered_by: sender,
				worker_url,
				tcb_status: Some(enclave.status),
				attestation_method: enclave.attestation_method,
			});
			Ok(().into())
		}

		#[pallet::call_index(1)]
		#[pallet::weight((<T as Config>::WeightInfo::unregister_enclave(), DispatchClass::Normal, Pays::Yes))]
		pub fn unregister_enclave(origin: OriginFor<T>) -> DispatchResultWithPostInfo {
			log::info!("teerex: called into runtime call unregister_enclave()");
			let sender = ensure_signed(origin)?;

			Self::remove_enclave(&sender)?;
			Self::deposit_event(Event::RemovedEnclave(sender));
			Ok(().into())
		}

		#[pallet::call_index(2)]
		#[pallet::weight((<T as Config>::WeightInfo::call_worker(), DispatchClass::Normal, Pays::Yes))]
		pub fn call_worker(origin: OriginFor<T>, request: Request) -> DispatchResult {
			let _sender = ensure_signed(origin)?;
			log::info!("call_worker with {:?}", request);
			Self::deposit_event(Event::Forwarded(request.shard));
			Ok(())
		}

		/// The integritee worker calls this function for every processed parentchain_block to confirm a state update.
		#[pallet::call_index(3)]
		#[pallet::weight((<T as Config>::WeightInfo::confirm_processed_parentchain_block(), DispatchClass::Normal, Pays::Yes))]
		pub fn confirm_processed_parentchain_block(
			origin: OriginFor<T>,
			block_hash: H256,
			block_number: T::BlockNumber,
			trusted_calls_merkle_root: H256,
		) -> DispatchResultWithPostInfo {
			let sender = ensure_signed(origin)?;
			let enclave =
				<SovereignEnclaves<T>>::get(&sender).ok_or(<Error<T>>::EnclaveIsNotRegistered)?;
			Self::poke_shard(enclave.fingerprint().into(), &sender)?;

			log::debug!(
				"Processed parentchain block confirmed for mrenclave {:?}, block hash {:?}",
				sender,
				block_hash
			);
			Self::deposit_event(Event::ProcessedParentchainBlock(
				sender,
				block_hash,
				trusted_calls_merkle_root,
				block_number,
			));
			Ok(().into())
		}

		/// Sent by a client who requests to get shielded funds managed by an enclave. For this on-chain balance is sent to the bonding_account of the enclave.
		/// The bonding_account does not have a private key as the balance on this account is exclusively managed from withing the pallet_teerex.
		/// Note: The bonding_account is bit-equivalent to the worker shard.
		#[pallet::call_index(4)]
		#[pallet::weight((1000, DispatchClass::Normal, Pays::No))]
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
			Self::deposit_event(Event::ShieldFunds(incognito_account_encrypted));
			Ok(().into())
		}

		/// Sent by enclaves only as a result of an `unshield` request from a client to an enclave.
		#[pallet::call_index(5)]
		#[pallet::weight((1000, DispatchClass::Normal, Pays::No))]
		pub fn unshield_funds(
			origin: OriginFor<T>,
			public_account: T::AccountId,
			amount: BalanceOf<T>,
			bonding_account: T::AccountId,
			call_hash: H256,
		) -> DispatchResultWithPostInfo {
			let sender = ensure_signed(origin)?;
			let sender_enclave =
				<SovereignEnclaves<T>>::get(&sender).ok_or(<Error<T>>::EnclaveIsNotRegistered)?;
			Self::poke_shard(sender_enclave.fingerprint().into(), &sender)?;

			ensure!(
				sender_enclave.fingerprint().encode() == bonding_account.encode(),
				<Error<T>>::WrongMrenclaveForBondingAccount
			);

			if !<ExecutedCalls<T>>::contains_key(call_hash) {
				log::info!("Executing unshielding call: {:?}", call_hash);
				T::Currency::transfer(
					&bonding_account,
					&public_account,
					amount,
					ExistenceRequirement::AllowDeath,
				)?;
				<ExecutedCalls<T>>::insert(call_hash, 0);
				Self::deposit_event(Event::UnshieldedFunds(public_account));
			} else {
				log::info!("Already executed unshielding call: {:?}", call_hash);
			}

			<ExecutedCalls<T>>::mutate(call_hash, |confirmations| *confirmations += 1);
			Ok(().into())
		}

		#[pallet::call_index(7)]
		#[pallet::weight((<T as Config>::WeightInfo::register_quoting_enclave(), DispatchClass::Normal, Pays::Yes))]
		pub fn register_quoting_enclave(
			origin: OriginFor<T>,
			enclave_identity: Vec<u8>,
			signature: Vec<u8>,
			certificate_chain: Vec<u8>,
		) -> DispatchResultWithPostInfo {
			log::info!("teerex: called into runtime call register_quoting_enclave()");
			// Quoting enclaves are registered globally and not for a specific sender
			let _sender = ensure_signed(origin)?;
			let quoting_enclave = Self::verify_quoting_enclave(
				enclave_identity.clone(),
				signature,
				certificate_chain,
			)?;
			<SgxQuotingEnclaveRegistry<T>>::put(&quoting_enclave);
			Self::deposit_event(Event::SgxQuotingEnclaveRegistered { quoting_enclave });
			Ok(().into())
		}

		#[pallet::call_index(8)]
		#[pallet::weight((<T as Config>::WeightInfo::register_tcb_info(), DispatchClass::Normal, Pays::Yes))]
		pub fn register_tcb_info(
			origin: OriginFor<T>,
			tcb_info: Vec<u8>,
			signature: Vec<u8>,
			certificate_chain: Vec<u8>,
		) -> DispatchResultWithPostInfo {
			log::info!("teerex: called into runtime call register_tcb_info()");
			// TCB info is registered globally and not for a specific sender
			let _sender = ensure_signed(origin)?;
			let (fmspc, on_chain_info) =
				Self::verify_tcb_info(tcb_info, signature, certificate_chain)?;
			<SgxTcbInfo<T>>::insert(fmspc, &on_chain_info);
			Self::deposit_event(Event::SgxTcbInfoRegistered { fmspc, on_chain_info });
			Ok(().into())
		}

		/// Publish a hash as a result of an arbitrary enclave operation.
		///
		/// The `mrenclave` of the origin will be used as an event topic a client can subscribe to.
		/// `extra_topics`, if any, will be used as additional event topics.
		///
		/// `data` can be anything worthwhile publishing related to the hash. If it is a
		/// utf8-encoded string, the UIs will usually even render the text.
		#[pallet::call_index(9)]
		#[pallet::weight((<T as Config>::WeightInfo::publish_hash(extra_topics.len().saturated_into(), data.len().saturated_into()), DispatchClass::Normal, Pays::Yes))]
		pub fn publish_hash(
			origin: OriginFor<T>,
			hash: H256,
			extra_topics: Vec<T::Hash>,
			data: Vec<u8>,
		) -> DispatchResultWithPostInfo {
			let sender = ensure_signed(origin)?;
			let enclave =
				<SovereignEnclaves<T>>::get(&sender).ok_or(<Error<T>>::EnclaveIsNotRegistered)?;
			Self::poke_shard(enclave.fingerprint().into(), &sender)?;

			ensure!(extra_topics.len() <= TOPICS_LIMIT, <Error<T>>::TooManyTopics);
			ensure!(data.len() <= DATA_LENGTH_LIMIT, <Error<T>>::DataTooLong);

			let mut topics = extra_topics;
			topics.push(T::Hash::from(enclave.clone().fingerprint().into()));

			Self::deposit_event_indexed(
				&topics,
				Event::PublishedHash { fingerprint: enclave.fingerprint(), hash, data },
			);

			Ok(().into())
		}
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
		RaProofTooLong,
		/// No enclave is registered.
		EmptyEnclaveRegistry,
		/// The provided collateral data is invalid
		CollateralInvalid,
		/// The number of `extra_topics` passed to `publish_hash` exceeds the limit.
		TooManyTopics,
		/// The length of the `data` passed to `publish_hash` exceeds the limit.
		DataTooLong,
	}
}

impl<T: Config> Pallet<T> {
	pub fn add_enclave(
		sender: &T::AccountId,
		multi_enclave: &MultiEnclave<Vec<u8>>,
	) -> DispatchResultWithPostInfo {
		if multi_enclave.clone().attestaion_proxied() {
			log::warn!("proxied enclaves not supported yet");
			return Err(Error::<T>::SenderIsNotAttestedEnclave.into())
		}

		<SovereignEnclaves<T>>::insert(sender, multi_enclave);
		Ok(().into())
	}

	fn remove_enclave(sender: &T::AccountId) -> DispatchResultWithPostInfo {
		ensure!(<SovereignEnclaves<T>>::contains_key(sender), <Error<T>>::EnclaveIsNotRegistered);
		<SovereignEnclaves<T>>::remove(sender);
		Ok(().into())
	}

	/// Check if the sender is a registered enclave
	pub fn ensure_registered_enclave(
		account: &T::AccountId,
	) -> Result<(), DispatchErrorWithPostInfo> {
		ensure!(<SovereignEnclaves<T>>::contains_key(account), <Error<T>>::EnclaveIsNotRegistered);
		Ok(())
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

	fn verify_quoting_enclave(
		enclave_identity: Vec<u8>,
		signature: Vec<u8>,
		certificate_chain: Vec<u8>,
	) -> Result<SgxQuotingEnclave, DispatchErrorWithPostInfo> {
		let verification_time: u64 = <timestamp::Pallet<T>>::get().saturated_into();
		let certs = extract_certs(&certificate_chain);
		ensure!(certs.len() >= 2, "Certificate chain must have at least two certificates");
		let intermediate_slices: Vec<&[u8]> = certs[1..].iter().map(Vec::as_slice).collect();
		let leaf_cert =
			verify_certificate_chain(&certs[0], &intermediate_slices, verification_time)?;
		let enclave_identity =
			deserialize_enclave_identity(&enclave_identity, &signature, &leaf_cert)?;

		if enclave_identity.is_valid(verification_time.try_into().unwrap()) {
			Ok(enclave_identity.to_quoting_enclave())
		} else {
			Err(<Error<T>>::CollateralInvalid.into())
		}
	}

	pub fn verify_tcb_info(
		tcb_info: Vec<u8>,
		signature: Vec<u8>,
		certificate_chain: Vec<u8>,
	) -> Result<(Fmspc, SgxTcbInfoOnChain), DispatchErrorWithPostInfo> {
		let verification_time: u64 = <timestamp::Pallet<T>>::get().saturated_into();
		let certs = extract_certs(&certificate_chain);
		ensure!(certs.len() >= 2, "Certificate chain must have at least two certificates");
		let intermediate_slices: Vec<&[u8]> = certs[1..].iter().map(Vec::as_slice).collect();
		let leaf_cert =
			verify_certificate_chain(&certs[0], &intermediate_slices, verification_time)?;
		let tcb_info = deserialize_tcb_info(&tcb_info, &signature, &leaf_cert)?;
		if tcb_info.is_valid(verification_time.try_into().unwrap()) {
			Ok(tcb_info.to_chain_tcb_info())
		} else {
			Err(<Error<T>>::CollateralInvalid.into())
		}
	}

	fn ensure_timestamp_within_24_hours(report_timestamp: u64) -> DispatchResultWithPostInfo {
		use sp_runtime::traits::CheckedSub;

		let elapsed_time = <timestamp::Pallet<T>>::get()
			.checked_sub(&T::Moment::saturated_from(report_timestamp))
			.ok_or("Underflow while calculating elapsed time since report creation")?;

		if elapsed_time < T::MomentsPerDay::get() {
			Ok(().into())
		} else {
			Err(<Error<T>>::RemoteAttestationTooOld.into())
		}
	}

	fn poke_shard(
		shard: ShardIdentifier,
		enclave_signer: &T::AccountId,
	) -> DispatchResultWithPostInfo {
		let enclave = Self::sovereign_enclaves(enclave_signer.clone())
			.ok_or(<Error<T>>::EnclaveIsNotRegistered)?;

		let current_block_number = <frame_system::Pallet<T>>::block_number();

		let fresh_status = ShardSignerStatus {
			signer: enclave_signer.clone(),
			fingerprint: enclave.fingerprint(),
			last_activity: current_block_number,
		};

		let signer_statuses = if let Some(mut status_vec) = <ShardStatus<T>>::get(shard) {
			if let Some(index) = status_vec.iter().position(|i| i.signer == *enclave_signer) {
				status_vec[index] = fresh_status;
			} else {
				status_vec.push(fresh_status)
			}
			status_vec
		} else {
			vec![fresh_status]
		};
		<ShardStatus<T>>::insert(shard, signer_statuses);
		Ok(().into())
	}
}

#[cfg(any(test, feature = "runtime-benchmarks"))]
mod benchmarking;
#[cfg(test)]
mod mock;
#[cfg(any(test, feature = "runtime-benchmarks"))]
pub mod test_helpers;
#[cfg(test)]
mod tests;
pub mod weights;
