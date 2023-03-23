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

use codec::{Decode, Encode, FullCodec};
pub use cumulus_primitives_core::ParaId;
use frame_support::{
	pallet_prelude::{Get, PhantomData},
	RuntimeDebug,
};
use sp_std::vec;
use xcm::{latest::Weight as XcmWeight, prelude::*};

pub trait BuildRelayCall {
	type RelayCall: FullCodec;
	/// Constructs the RelayCall RegistrarCall to be fed into 'construct_transact_xcm()'
	///
	/// Params:
	/// - ParaIds for the parachains involved in swapping
	///
	/// Returns:
	/// - constructed RelayCall to be fed to `construct_transact_xcm()`
	///
	fn swap_call(self_para_id: ParaId, other_para_id: ParaId) -> Self::RelayCall;

	/// Wraps constructed Relaychain Call in an XCM message to be dispatched via 'send_xcm'
	///
	/// Params:
	/// - RelayCall (Different depending on Kusama or Polkadot)
	/// - execution to be purchased via BuyExecution XCM Instruction
	/// - Weight required to execute this call.
	/// - Amount of execution to buy on the relay chain. This parameter is exposed because it varies
	/// depending on the relay chain.
	///
	/// Returns:
	/// - Corresponding XCM Message for Transacting on this RelayCall
	fn construct_transact_xcm(
		call: Self::RelayCall,
		weight: XcmWeight,
		buy_execution_fee: u128,
	) -> Xcm<()>;
}

#[derive(Encode, Decode, RuntimeDebug)]
pub enum RegistrarCall {
	/// Corresponds to the swap extrinsic index within the Registrar Pallet
	#[codec(index = 3)]
	Swap { this: ParaId, other: ParaId },
}

#[cfg(feature = "ksm")]
pub mod ksm {
	use crate::*;
	#[derive(Encode, Decode, RuntimeDebug)]
	pub enum RelayRuntimeCall {
		/// Corresponds to the pallet index within the Kusama Runtime
		#[codec(index = 70)]
		Registrar(RegistrarCall),
	}
}

#[cfg(feature = "dot")]
pub mod dot {
	use crate::*;
	#[derive(Encode, Decode, RuntimeDebug)]
	pub enum RelayRuntimeCall {
		/// Corresponds to the pallet index within the Polkadot Runtime
		#[codec(index = 70)]
		Registrar(RegistrarCall),
	}
}

#[cfg(feature = "ksm")]
pub use ksm::*;

#[cfg(feature = "dot")]
pub use dot::*;

pub struct RelayCallBuilder<Id>(PhantomData<Id>);
impl<Id: Get<ParaId>> BuildRelayCall for RelayCallBuilder<Id> {
	type RelayCall = RelayRuntimeCall;

	fn swap_call(self_para_id: ParaId, other_para_id: ParaId) -> Self::RelayCall {
		Self::RelayCall::Registrar(RegistrarCall::Swap { this: self_para_id, other: other_para_id })
	}

	fn construct_transact_xcm(
		call: Self::RelayCall,
		weight: XcmWeight,
		buy_execution_fee: u128,
	) -> Xcm<()> {
		let asset =
			MultiAsset { id: Concrete(Here.into()), fun: Fungibility::Fungible(buy_execution_fee) };
		Xcm(vec![
			WithdrawAsset(asset.clone().into()),
			BuyExecution { fees: asset, weight_limit: Unlimited },
			Transact {
				origin_kind: OriginKind::Native,
				require_weight_at_most: weight,
				call: call.encode().into(),
			},
			RefundSurplus,
			DepositAsset {
				assets: All.into(),
				beneficiary: X1(Parachain(Id::get().into())).into(),
			},
		])
	}
}
