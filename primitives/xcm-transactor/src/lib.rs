#![cfg_attr(not(feature = "std"), no_std)]
use codec::{Decode, Encode, FullCodec};
pub use cumulus_primitives_core::ParaId;
use frame_support::RuntimeDebug;
use xcm::{latest::Weight as XcmWeight, prelude::*};

pub trait BuildRelayCall {
	type RelayCall: FullCodec;
	/// TODO: Add Notes about which function this is and why it is being used
	///
	///
	fn swap_call(self_para_id: ParaId, other_para_id: ParaId) -> Self::RelayCall;

	/// Wraps constructed Relaychain Call in an XCM message to be dispatched via 'send_xcm'
	///
	/// Params:
	/// - RelayCall (Different depending on Kusama or Polkadot)
	/// - execution to be purchased via BuyExecution Xcm Instruction
	/// - Weight required to execute this call.
	///
	/// Returns:
	/// - Corresponding Xcm Message for Transacting on this RelayCall
	///
	fn construct_transact_xcm(call: Self::RelayCall, weight: XcmWeight) -> Xcm<()>;
}

#[derive(Encode, Decode, RuntimeDebug)]
pub enum RegistrarCall {
	/// Corresponds to the swap extrinsic index within the Registrar Pallet
	#[codec(index = 3)]
	Swap(ParaId, ParaId),
}

#[cfg(feature = "kusama")]
pub mod ksm {
	use crate::*;
	#[derive(Encode, Decode, RuntimeDebug)]
	pub enum RelayRuntimeCall {
		/// Corresponds to the pallet index within the Kusama Runtime
		#[codec(index = 70)]
		Registrar(RegistrarCall),
	}
}

#[cfg(feature = "polkadot")]
pub mod dot {
	use crate::*;
	#[derive(Encode, Decode, RuntimeDebug)]
	pub enum RelayRuntimeCall {
		/// Corresponds to the pallet index within the Polkadot Runtime
		#[codec(index = 70)]
		Registrar(RegistrarCall),
	}
}

#[cfg(feature = "kusama")]
pub use ksm::*;

#[cfg(feature = "polkadot")]
pub use dot::*;

pub struct RelayCallBuilderType;
impl BuildRelayCall for RelayCallBuilderType {
	type RelayCall = RelayRuntimeCall;

	fn swap_call(self_para_id: ParaId, other_para_id: ParaId) -> Self::RelayCall {
		Self::RelayCall::Registrar(RegistrarCall::Swap(self_para_id, other_para_id))
	}

	fn construct_transact_xcm(call: Self::RelayCall, weight: XcmWeight) -> Xcm<()> {
		Xcm(vec![Transact {
			origin_type: OriginKind::Native,
			require_weight_at_most: weight,
			call: call.encode().into(),
		}])
	}
}
