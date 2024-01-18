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
	dispatch::{DispatchErrorWithPostInfo, DispatchResultWithPostInfo},
	ensure,
	pallet_prelude::StorageVersion,
	traits::Get,
};
use frame_system::{self, ensure_signed};
use sgx_verify::{
	deserialize_enclave_identity, deserialize_tcb_info, extract_certs, verify_certificate_chain,
};
use sp_runtime::{traits::SaturatedConversion, Saturating};
use sp_std::{prelude::*, str, vec};
use teerex_primitives::*;

pub use crate::weights::WeightInfo;
use teerex_primitives::{SgxBuildMode, SgxStatus};

// Disambiguate associated types
pub type AccountId<T> = <T as frame_system::Config>::AccountId;

pub use pallet::*;

const SGX_RA_PROOF_MAX_LEN: usize = 5000;

const MAX_URL_LEN: usize = 256;

const STORAGE_VERSION: StorageVersion = StorageVersion::new(2);

#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;

	#[pallet::pallet]
	#[pallet::storage_version(STORAGE_VERSION)]
	#[pallet::without_storage_info]
	pub struct Pallet<T>(PhantomData<T>);

	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {}

	#[pallet::config]
	pub trait Config: frame_system::Config + timestamp::Config {
		type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

		#[pallet::constant]
		type MomentsPerDay: Get<Self::Moment>;

		type WeightInfo: WeightInfo;

		/// If a worker does not re-register within `MaxAttestationRenewalPeriod`, it can be unregistered by anyone.
		#[pallet::constant]
		type MaxAttestationRenewalPeriod: Get<Self::Moment>;
	}

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		/// An Intel SGX enclave has been added to the enclave registry
		AddedSgxEnclave {
			registered_by: T::AccountId,
			worker_url: Option<Vec<u8>>,
			tcb_status: Option<SgxStatus>,
			attestation_method: SgxAttestationMethod,
		},
		/// a sovereign enclave has been removed from the enclave registry
		RemovedSovereignEnclave(T::AccountId),
		/// a proxied enclave has been removed from the enclave registry
		RemovedProxiedEnclave(EnclaveInstanceAddress<T::AccountId>),
		/// Intel SGX TCB info has been registered
		SgxTcbInfoRegistered { fmspc: Fmspc, on_chain_info: SgxTcbInfoOnChain },
		/// An Intel SGX quoting enclave has been registered
		SgxQuotingEnclaveRegistered { quoting_enclave: SgxQuotingEnclave },
		/// the enclave registry security flags have been updated
		UpdatedSecurityFlags { allow_skipping_attestation: bool, sgx_allow_debug_mode: bool },
	}

	#[pallet::error]
	pub enum Error<T> {
		/// Failed to decode enclave signer.
		EnclaveSignerDecodeError,
		/// Sender does not match attested enclave in report.
		SenderIsNotAttestedEnclave,
		/// Verifying RA report failed.
		RemoteAttestationVerificationFailed,
		/// IAS remote attestation is too old
		RemoteAttestationIsTooOld,
		/// The enclave cannot attest, because its building mode is not allowed.
		SgxModeIsNotAllowed,
		/// The enclave is not registered.
		EnclaveIsNotRegistered,
		/// The worker url is too long.
		EnclaveUrlIsTooLong,
		/// The Remote Attestation proof is too long.
		RaProofIsTooLong,
		/// No enclave is registered.
		EmptyEnclaveRegistry,
		/// The provided collateral data is invalid
		CollateralIsInvalid,
		/// It is not allowed to unregister enclaves with recent activity
		UnregisterActiveEnclaveIsNotAllowed,
		/// skipping attestation not allowed by configuration
		SkippingAttestationIsNotAllowed,
		/// No TCB info could be found onchain for the examinee's fmspc
		MissingTcbInfoForFmspc,
		/// Either the enclave TCB has outdated status or the onchain TCB collateral is outdated
		TcbInfoIsOutdated,

		// mapped errors from sgx_verify
		/// An error originating in the sgx_verify crate
		OtherSgxVerifyError(sgx_verify::Error),
		CaVerificationFailed,
		CertificateChainIsInvalid,
		CertificateChainIsTooShort,
		CpuSvnDecodingError,
		CpuSvnLengthMismatch,
		CpuSvnOidIsMissing,
		DcapKeyTypeMismatch,
		DcapQuoteDecodingError,
		DcapQuoteIsTooLong,
		DcapQuoteVersionMismatch,
		DerEncodingError,
		EnclaveIdentityDecodingError,
		EnclaveIdentitySignatureIsInvalid,
		FmspcDecodingError,
		FmspcLengthMismatch,
		FmspcOidIsMissing,
		IntelExtensionAmbiguity,
		IntelExtensionCertificateDecodingError,
		IsvEnclaveReportSignatureIsInvalid,
		KeyLengthIsInvalid,
		LeafCertificateParsingError,
		NetscapeDecodingError,
		NetscapeDerError,
		PceSvnDecodingError,
		PceSvnLengthMismatch,
		PceSvnOidIsMissing,
		PckCertFormatMismatch,
		PublicKeyIsInvalid,
		QeHasRejectedEnclave,
		QeReportHashMismatch,
		QuoteBodyDecodingError,
		QuoteBodyIsInvalid,
		QuoteBodyMissing,
		QuoteStatusMissing,
		RsaSignatureIsInvalid,
		SgxReportParsingError,
		TcbInfoIsInvalid,
		TimestampIsInvalid,
		TimestampIsMissing,
	}

	impl<T> From<sgx_verify::Error> for Error<T> {
		fn from(e: sgx_verify::Error) -> Self {
			use sgx_verify::Error as Theirs;
			match e {
				Theirs::CaVerificationFailed => Self::CaVerificationFailed,
				Theirs::CertificateChainIsInvalid => Self::CertificateChainIsInvalid,
				Theirs::CertificateChainIsTooShort => Self::CertificateChainIsTooShort,
				Theirs::CpuSvnDecodingError => Self::CpuSvnDecodingError,
				Theirs::CpuSvnLengthMismatch => Self::CpuSvnLengthMismatch,
				Theirs::CpuSvnOidIsMissing => Self::CpuSvnOidIsMissing,
				Theirs::DcapKeyTypeMismatch => Self::DcapKeyTypeMismatch,
				Theirs::DcapQuoteDecodingError => Self::DcapQuoteDecodingError,
				Theirs::DcapQuoteIsTooLong => Self::DcapQuoteIsTooLong,
				Theirs::DcapQuoteVersionMismatch => Self::DcapQuoteVersionMismatch,
				Theirs::DerEncodingError => Self::DerEncodingError,
				Theirs::EnclaveIdentityDecodingError => Self::EnclaveIdentityDecodingError,
				Theirs::EnclaveIdentitySignatureIsInvalid =>
					Self::EnclaveIdentitySignatureIsInvalid,
				Theirs::FmspcDecodingError => Self::FmspcDecodingError,
				Theirs::FmspcLengthMismatch => Self::FmspcLengthMismatch,
				Theirs::FmspcOidIsMissing => Self::FmspcOidIsMissing,
				Theirs::IntelExtensionAmbiguity => Self::IntelExtensionAmbiguity,
				Theirs::IntelExtensionCertificateDecodingError =>
					Self::IntelExtensionCertificateDecodingError,
				Theirs::IsvEnclaveReportSignatureIsInvalid =>
					Self::IsvEnclaveReportSignatureIsInvalid,
				Theirs::KeyLengthIsInvalid => Self::KeyLengthIsInvalid,
				Theirs::LeafCertificateParsingError => Self::LeafCertificateParsingError,
				Theirs::NetscapeDecodingError => Self::NetscapeDecodingError,
				Theirs::NetscapeDerError => Self::NetscapeDerError,
				Theirs::PceSvnDecodingError => Self::PceSvnDecodingError,
				Theirs::PceSvnLengthMismatch => Self::PceSvnLengthMismatch,
				Theirs::PceSvnOidIsMissing => Self::PceSvnOidIsMissing,
				Theirs::PckCertFormatMismatch => Self::PckCertFormatMismatch,
				Theirs::PublicKeyIsInvalid => Self::PublicKeyIsInvalid,
				Theirs::QeHasRejectedEnclave => Self::QeHasRejectedEnclave,
				Theirs::QeReportHashMismatch => Self::QeReportHashMismatch,
				Theirs::QuoteBodyDecodingError => Self::QuoteBodyDecodingError,
				Theirs::QuoteBodyIsInvalid => Self::QuoteBodyIsInvalid,
				Theirs::QuoteBodyMissing => Self::QuoteBodyMissing,
				Theirs::QuoteStatusMissing => Self::QuoteStatusMissing,
				Theirs::RsaSignatureIsInvalid => Self::RsaSignatureIsInvalid,
				Theirs::SgxReportParsingError => Self::SgxReportParsingError,
				Theirs::TcbInfoIsInvalid => Self::TcbInfoIsInvalid,
				Theirs::TimestampIsInvalid => Self::TimestampIsInvalid,
				Theirs::TimestampIsMissing => Self::TimestampIsMissing,
			}
		}
	}

	#[pallet::storage]
	#[pallet::getter(fn sovereign_enclaves)]
	pub type SovereignEnclaves<T: Config> =
		StorageMap<_, Blake2_128Concat, T::AccountId, MultiEnclave<Vec<u8>>, OptionQuery>;

	#[pallet::storage]
	#[pallet::getter(fn proxied_enclaves)]
	pub type ProxiedEnclaves<T: Config> = StorageMap<
		_,
		Blake2_128Concat,
		EnclaveInstanceAddress<T::AccountId>,
		MultiEnclave<Vec<u8>>,
		OptionQuery,
	>;

	#[pallet::storage]
	#[pallet::getter(fn quoting_enclave)]
	pub type SgxQuotingEnclaveRegistry<T: Config> = StorageValue<_, SgxQuotingEnclave, ValueQuery>;

	#[pallet::storage]
	#[pallet::getter(fn tcb_info)]
	pub type SgxTcbInfo<T: Config> =
		StorageMap<_, Blake2_128Concat, Fmspc, SgxTcbInfoOnChain, OptionQuery>;

	#[pallet::type_value]
	pub fn DefaultSgxAllowDebugMode<T: Config>() -> bool {
		false
	}

	#[pallet::storage]
	#[pallet::getter(fn allow_sgx_debug_mode)]
	pub type SgxAllowDebugMode<T: Config> =
		StorageValue<_, bool, ValueQuery, DefaultSgxAllowDebugMode<T>>;

	#[pallet::type_value]
	pub fn DefaultAllowSkippingAttestation<T: Config>() -> bool {
		false
	}

	#[pallet::storage]
	#[pallet::getter(fn allow_skipping_attestation)]
	pub type AllowSkippingAttestation<T: Config> =
		StorageValue<_, bool, ValueQuery, DefaultAllowSkippingAttestation<T>>;

	#[pallet::genesis_config]
	#[derive(frame_support::DefaultNoBound)]
	pub struct GenesisConfig<T> {
		pub allow_sgx_debug_mode: bool,
		pub allow_skipping_attestation: bool,
		#[serde(skip)]
		pub _config: sp_std::marker::PhantomData<T>,
	}

	#[pallet::genesis_build]
	impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
		fn build(&self) {
			SgxAllowDebugMode::<T>::put(self.allow_sgx_debug_mode);
			AllowSkippingAttestation::<T>::put(self.allow_skipping_attestation);
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
		#[pallet::weight((<T as Config>::WeightInfo::register_sgx_enclave(), DispatchClass::Normal, Pays::Yes))]
		pub fn register_sgx_enclave(
			origin: OriginFor<T>,
			proof: Vec<u8>,
			worker_url: Option<Vec<u8>>,
			attestation_method: SgxAttestationMethod,
		) -> DispatchResultWithPostInfo {
			log::debug!(target: TEEREX, "called into runtime call register_sgx_enclave()");
			let sender = ensure_signed(origin)?;
			ensure!(proof.len() <= SGX_RA_PROOF_MAX_LEN, Error::<T>::RaProofIsTooLong);
			if let Some(ref url) = worker_url {
				ensure!(url.len() <= MAX_URL_LEN, Error::<T>::EnclaveUrlIsTooLong);
			}
			log::debug!(target: TEEREX, "parameter length ok");

			let enclave = match attestation_method {
				SgxAttestationMethod::Ias => {
					let report = sgx_verify::verify_ias_report(&proof).map_err(|e| {
						log::info!(target: TEEREX, "verify_ias_quote failed: {:?}", e);
						Error::<T>::from(e)
					})?;
					log::debug!(target: TEEREX, "IAS report successfully verified");

					Self::ensure_timestamp_within_24_hours(report.timestamp)?;

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
						Error::<T>::SenderIsNotAttestedEnclave
					);

					// TODO: activate state checks as soon as we've fixed our setup #83
					// ensure!((report.status == SgxStatus::Ok) | (report.status == SgxStatus::ConfigurationNeeded),
					//     "RA status is insufficient");
					// log::info!(target: TEEREX, "status is acceptable");

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
						log::info!(target: TEEREX, "verify_dcap_quote failed: {:?}", e);
						Error::<T>::from(e)
					})?;

					if !proxied {
						ensure!(
							Ok(sender.clone()) ==
								T::AccountId::decode(&mut report.report_data.lower32().as_ref()),
							Error::<T>::SenderIsNotAttestedEnclave
						);
					}

					log::debug!(
						target: TEEREX,
						"DCAP quote verified. FMSPC from quote: {}",
						hex::encode(fmspc)
					);
					let sgx_status = match <SgxTcbInfo<T>>::get(fmspc) {
						Some(reference) =>
							if let Some(status) = reference.verify_examinee(&tcb_info) {
								log::trace!("TCB info verification passed");
								status
							} else {
								return Err(Error::<T>::TcbInfoIsOutdated.into())
							},
						None => {
							log::warn!(
								"No TCB info could be found onchain for the examinee's fmspc: {}",
								hex::encode(fmspc)
							);
							return Err(Error::<T>::MissingTcbInfoForFmspc.into())
						},
					};

					// TODO: activate state checks as soon as we've fixed our setup #83
					// ensure!((report.status == SgxStatus::Ok) | (report.status == SgxStatus::ConfigurationNeeded),
					//     "RA status is insufficient");
					// log::info!(target: TEEREX, "status is acceptable");

					SgxEnclave::new(
						report.report_data,
						report.mr_enclave,
						report.mr_signer,
						report.timestamp,
						report.build_mode,
						sgx_status,
					)
					.with_attestation_method(SgxAttestationMethod::Dcap { proxied })
				},
				SgxAttestationMethod::Skip { proxied } => {
					if !Self::allow_skipping_attestation() {
						log::debug!(target: TEEREX, "skipping attestation not allowed",);
						return Err(Error::<T>::SkippingAttestationIsNotAllowed.into())
					}
					log::debug!(target: TEEREX, "skipping attestation verification",);
					SgxEnclave::new(
						SgxReportData::default(),
						// insert mrenclave if the ra_report represents one, otherwise insert default
						<MrEnclave>::decode(&mut proof.as_slice()).unwrap_or_default(),
						MrSigner::default(),
						<timestamp::Pallet<T>>::get().saturated_into(),
						SgxBuildMode::default(),
						SgxStatus::Invalid,
					)
					.with_pubkey(sender.encode().as_ref())
					.with_attestation_method(SgxAttestationMethod::Skip { proxied })
				},
			};

			if !<SgxAllowDebugMode<T>>::get() && enclave.build_mode == SgxBuildMode::Debug {
				log::info!(target: TEEREX, "debug mode is not allowed to attest!");
				return Err(Error::<T>::SgxModeIsNotAllowed.into())
			}

			let enclave = match worker_url {
				Some(ref url) => enclave.with_url(url.clone()),
				None => enclave,
			};

			Self::add_enclave(&sender, MultiEnclave::from(enclave.clone()))?;

			log::info!(
				target: TEEREX,
				"registered sgx enclave. sender: {:?}, attestation method: {:?}",
				sender,
				enclave.attestation_method
			);
			Self::deposit_event(Event::AddedSgxEnclave {
				registered_by: sender,
				worker_url,
				tcb_status: Some(enclave.status),
				attestation_method: enclave.attestation_method,
			});
			Ok(().into())
		}

		#[pallet::call_index(1)]
		#[pallet::weight((<T as Config>::WeightInfo::unregister_sovereign_enclave(), DispatchClass::Normal, Pays::Yes))]
		pub fn unregister_sovereign_enclave(
			origin: OriginFor<T>,
			enclave_signer: T::AccountId,
		) -> DispatchResultWithPostInfo {
			log::debug!(target: TEEREX, "called into runtime call unregister_sovereign_enclave()");
			ensure_signed(origin)?;
			let enclave = Self::sovereign_enclaves(&enclave_signer)
				.ok_or(Error::<T>::EnclaveIsNotRegistered)?;
			let now = <timestamp::Pallet<T>>::get();
			let oldest_acceptable_attestation_time = now
				.saturating_sub(T::MaxAttestationRenewalPeriod::get())
				.saturated_into::<u64>();
			if enclave.attestation_timestamp() < oldest_acceptable_attestation_time {
				<SovereignEnclaves<T>>::remove(&enclave_signer);
			} else {
				return Err(Error::<T>::UnregisterActiveEnclaveIsNotAllowed.into())
			}
			log::debug!(target: TEEREX, "removed sovereign enclave {:?}", enclave_signer);
			Self::deposit_event(Event::RemovedSovereignEnclave(enclave_signer));
			Ok(().into())
		}

		#[pallet::call_index(2)]
		#[pallet::weight((<T as Config>::WeightInfo::unregister_proxied_enclave(), DispatchClass::Normal, Pays::Yes))]
		pub fn unregister_proxied_enclave(
			origin: OriginFor<T>,
			address: EnclaveInstanceAddress<T::AccountId>,
		) -> DispatchResultWithPostInfo {
			log::debug!(target: TEEREX, "called into runtime call unregister_proxied_enclave()");
			ensure_signed(origin)?;
			let enclave =
				Self::proxied_enclaves(&address).ok_or(Error::<T>::EnclaveIsNotRegistered)?;
			let now = <timestamp::Pallet<T>>::get();
			let oldest_acceptable_attestation_time = now
				.saturating_sub(T::MaxAttestationRenewalPeriod::get())
				.saturated_into::<u64>();
			if enclave.attestation_timestamp() < oldest_acceptable_attestation_time {
				<ProxiedEnclaves<T>>::remove(&address);
			} else {
				return Err(Error::<T>::UnregisterActiveEnclaveIsNotAllowed.into())
			}
			log::info!(target: TEEREX, "removed proxied enclave {:?}", address);
			Self::deposit_event(Event::RemovedProxiedEnclave(address));
			Ok(().into())
		}

		#[pallet::call_index(3)]
		#[pallet::weight((<T as Config>::WeightInfo::register_quoting_enclave(), DispatchClass::Normal, Pays::Yes))]
		pub fn register_quoting_enclave(
			origin: OriginFor<T>,
			enclave_identity: Vec<u8>,
			signature: Vec<u8>,
			certificate_chain: Vec<u8>,
		) -> DispatchResultWithPostInfo {
			log::debug!(target: TEEREX, "Called into runtime call register_quoting_enclave()");
			// Quoting enclaves are registered globally and not for a specific sender
			let _sender = ensure_signed(origin)?;
			let quoting_enclave = Self::verify_quoting_enclave(
				enclave_identity.clone(),
				signature,
				certificate_chain,
			)?;
			<SgxQuotingEnclaveRegistry<T>>::put(&quoting_enclave);
			log::info!(target: TEEREX, "registered quoting enclave");
			Self::deposit_event(Event::SgxQuotingEnclaveRegistered { quoting_enclave });
			Ok(().into())
		}

		#[pallet::call_index(4)]
		#[pallet::weight((<T as Config>::WeightInfo::register_tcb_info(), DispatchClass::Normal, Pays::Yes))]
		pub fn register_tcb_info(
			origin: OriginFor<T>,
			tcb_info: Vec<u8>,
			signature: Vec<u8>,
			certificate_chain: Vec<u8>,
		) -> DispatchResultWithPostInfo {
			log::debug!(target: TEEREX, "Called into runtime call register_tcb_info()");
			// TCB info is registered globally and not for a specific sender
			let _sender = ensure_signed(origin)?;
			log::trace!(target: TEEREX, "In register_tcb_info(), origin is ensured to be signed");
			let (fmspc, on_chain_info) =
				Self::verify_tcb_info(tcb_info, signature, certificate_chain)?;
			<SgxTcbInfo<T>>::insert(fmspc, &on_chain_info);
			log::info!(target: TEEREX, "registered tcb info for fmspc: {:?}", fmspc);
			Self::deposit_event(Event::SgxTcbInfoRegistered { fmspc, on_chain_info });
			Ok(().into())
		}

		#[pallet::call_index(5)]
		#[pallet::weight((<T as Config>::WeightInfo::set_security_flags(), DispatchClass::Normal, Pays::Yes))]
		pub fn set_security_flags(
			origin: OriginFor<T>,
			allow_skipping_attestation: bool,
			sgx_allow_debug_mode: bool,
		) -> DispatchResultWithPostInfo {
			log::debug!(target: TEEREX, "Called into runtime call set_security_flags()");
			ensure_root(origin)?;
			<AllowSkippingAttestation<T>>::set(allow_skipping_attestation);
			<SgxAllowDebugMode<T>>::set(sgx_allow_debug_mode);
			log::info!(target: TEEREX, "set security flags");
			Self::deposit_event(Event::UpdatedSecurityFlags {
				allow_skipping_attestation,
				sgx_allow_debug_mode,
			});
			Ok(().into())
		}
	}
}

impl<T: Config> Pallet<T> {
	pub fn add_enclave(
		sender: &T::AccountId,
		multi_enclave: MultiEnclave<Vec<u8>>,
	) -> DispatchResultWithPostInfo {
		if multi_enclave.attestaion_proxied() {
			<ProxiedEnclaves<T>>::insert(
				EnclaveInstanceAddress {
					fingerprint: multi_enclave.fingerprint(),
					registrar: sender.clone(),
					signer: multi_enclave.instance_signer(),
				},
				multi_enclave,
			);
		} else {
			<SovereignEnclaves<T>>::insert(sender, multi_enclave);
		}
		Ok(().into())
	}

	pub fn get_sovereign_enclave(
		account: &T::AccountId,
	) -> Result<MultiEnclave<Vec<u8>>, DispatchErrorWithPostInfo> {
		<SovereignEnclaves<T>>::get(account).ok_or(Error::<T>::EnclaveIsNotRegistered.into())
	}

	fn verify_quoting_enclave(
		enclave_identity: Vec<u8>,
		signature: Vec<u8>,
		certificate_chain: Vec<u8>,
	) -> Result<SgxQuotingEnclave, DispatchErrorWithPostInfo> {
		let verification_time: u64 = <timestamp::Pallet<T>>::get().saturated_into();
		let certs = extract_certs(&certificate_chain);
		ensure!(certs.len() >= 2, Error::<T>::CertificateChainIsTooShort);
		let intermediate_slices: Vec<webpki::types::CertificateDer> =
			certs[1..].iter().map(|c| c.as_slice().into()).collect();
		let leaf_cert_der = webpki::types::CertificateDer::from(certs[0].as_slice());
		let leaf_cert = webpki::EndEntityCert::try_from(&leaf_cert_der)
			.map_err(|_| Error::<T>::LeafCertificateParsingError)?;
		verify_certificate_chain(&leaf_cert, &intermediate_slices, verification_time)
			.map_err(Error::<T>::from)?;

		let enclave_identity =
			deserialize_enclave_identity(&enclave_identity, &signature, &leaf_cert)
				.map_err(Error::<T>::from)?;

		if enclave_identity.is_valid(verification_time.try_into().unwrap()) {
			Ok(enclave_identity.to_quoting_enclave())
		} else {
			Err(Error::<T>::CollateralIsInvalid.into())
		}
	}

	pub fn verify_tcb_info(
		tcb_info: Vec<u8>,
		signature: Vec<u8>,
		certificate_chain: Vec<u8>,
	) -> Result<(Fmspc, SgxTcbInfoOnChain), DispatchErrorWithPostInfo> {
		let verification_time: u64 = <timestamp::Pallet<T>>::get().saturated_into();
		let certs = extract_certs(&certificate_chain);
		ensure!(certs.len() >= 2, Error::<T>::CertificateChainIsTooShort);
		log::trace!(target: TEEREX, "Self::verify_tcb_info, certs len is >= 2.");
		let intermediate_slices: Vec<webpki::types::CertificateDer> =
			certs[1..].iter().map(|c| c.as_slice().into()).collect();
		let leaf_cert_der = webpki::types::CertificateDer::from(certs[0].as_slice());
		let leaf_cert = webpki::EndEntityCert::try_from(&leaf_cert_der)
			.map_err(|_| Error::<T>::LeafCertificateParsingError)?;
		verify_certificate_chain(&leaf_cert, &intermediate_slices, verification_time)
			.map_err(Error::<T>::from)?;
		let tcb_info =
			deserialize_tcb_info(&tcb_info, &signature, &leaf_cert).map_err(Error::<T>::from)?;
		log::trace!(target: TEEREX, "Self::deserialize_tcb_info succeded.");
		if tcb_info.is_valid(verification_time.try_into().unwrap()) {
			Ok(tcb_info.to_chain_tcb_info())
		} else {
			Err(Error::<T>::CollateralIsInvalid.into())
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
			Err(Error::<T>::RemoteAttestationIsTooOld.into())
		}
	}
}

#[cfg(any(test, feature = "runtime-benchmarks"))]
mod benchmarking;
#[cfg(test)]
mod mock;

pub mod migrations;

#[cfg(any(test, feature = "runtime-benchmarks"))]
pub mod test_helpers;
#[cfg(test)]
mod tests;
pub mod weights;
