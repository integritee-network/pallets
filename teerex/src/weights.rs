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

//! Autogenerated weights for pallet_teerex with reference hardware:
//! * Core(TM) i7-10875H
//! * 32GB of RAM
//! * NVMe SSD
//!
//!
//! THIS FILE WAS AUTO-GENERATED USING THE SUBSTRATE BENCHMARK CLI VERSION 3.0.0
//! DATE: 2021-07-08, STEPS: `[50, ]`, REPEAT: 20, LOW RANGE: `[]`, HIGH RANGE: `[]`
//! EXECUTION: Some(Wasm), WASM-EXECUTION: Compiled, CHAIN: Some("integritee-rococo-local-dev"), DB CACHE: 128

// Executed Command:
// ./target/release/integritee-collator
// benchmark
// --chain=integritee-rococo-local-dev
// --steps=50
// --repeat=20
// --pallet=pallet_teerex
// --extrinsic=*
// --execution=wasm
// --wasm-execution=compiled
// --heap-pages=4096
// --output=./polkadot-parachains/integritee-runtime/src/weights/pallet_teerex.rs
// --template=./scripts/frame-weight-template.hbs

#![allow(unused_parens)]
#![allow(unused_imports)]

use frame_support::{
	traits::Get,
	weights::{constants::RocksDbWeight, Weight},
};
use sp_std::marker::PhantomData;

/// Weight functions needed for pallet_teerex.
pub trait WeightInfo {
	fn register_ias_enclave() -> Weight;
	fn register_quoting_enclave() -> Weight;
	fn register_tcb_info() -> Weight;
	fn register_dcap_enclave() -> Weight;
	fn unregister_enclave() -> Weight;
	fn call_worker() -> Weight;
	fn confirm_processed_parentchain_block() -> Weight;
	fn publish_hash(l: u32, t: u32) -> Weight;
}

/// Weights for pallet_teerex using the Integritee parachain node and recommended hardware.
pub struct IntegriteeWeight<T>(PhantomData<T>);
impl<T: frame_system::Config> WeightInfo for IntegriteeWeight<T> {
	/// Storage: Timestamp Now (r:1 w:0)
	/// Proof: Timestamp Now (max_values: Some(1), max_size: Some(8), added: 503, mode: MaxEncodedLen)
	/// Storage: Teerex AllowSGXDebugMode (r:1 w:0)
	/// Proof Skipped: Teerex AllowSGXDebugMode (max_values: Some(1), max_size: None, mode: Measured)
	/// Storage: Teerex EnclaveIndex (r:1 w:0)
	/// Proof Skipped: Teerex EnclaveIndex (max_values: None, max_size: None, mode: Measured)
	/// Storage: Teerex EnclaveRegistry (r:0 w:1)
	/// Proof Skipped: Teerex EnclaveRegistry (max_values: None, max_size: None, mode: Measured)
	fn register_ias_enclave() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `336`
		//  Estimated: `4481`
		// Minimum execution time: 1_340_798 nanoseconds.
		Weight::from_ref_time(1_465_198_000)
			.saturating_add(Weight::from_proof_size(4481))
			.saturating_add(T::DbWeight::get().reads(3))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: Timestamp Now (r:1 w:0)
	/// Proof: Timestamp Now (max_values: Some(1), max_size: Some(8), added: 503, mode: MaxEncodedLen)
	/// Storage: Teerex QuotingEnclaveRegistry (r:0 w:1)
	/// Proof Skipped: Teerex QuotingEnclaveRegistry (max_values: Some(1), max_size: None, mode: Measured)
	fn register_quoting_enclave() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `94`
		//  Estimated: `597`
		// Minimum execution time: 1_421_398 nanoseconds.
		Weight::from_ref_time(1_605_297_000)
			.saturating_add(Weight::from_proof_size(597))
			.saturating_add(T::DbWeight::get().reads(1))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: Timestamp Now (r:1 w:0)
	/// Proof: Timestamp Now (max_values: Some(1), max_size: Some(8), added: 503, mode: MaxEncodedLen)
	/// Storage: Teerex TcbInfo (r:0 w:1)
	/// Proof Skipped: Teerex TcbInfo (max_values: None, max_size: None, mode: Measured)
	fn register_tcb_info() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `94`
		//  Estimated: `597`
		// Minimum execution time: 1_591_698 nanoseconds.
		Weight::from_ref_time(1_901_097_000)
			.saturating_add(Weight::from_proof_size(597))
			.saturating_add(T::DbWeight::get().reads(1))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: Timestamp Now (r:1 w:0)
	/// Proof: Timestamp Now (max_values: Some(1), max_size: Some(8), added: 503, mode: MaxEncodedLen)
	/// Storage: Teerex QuotingEnclaveRegistry (r:1 w:0)
	/// Proof Skipped: Teerex QuotingEnclaveRegistry (max_values: Some(1), max_size: None, mode: Measured)
	/// Storage: Teerex TcbInfo (r:1 w:0)
	/// Proof Skipped: Teerex TcbInfo (max_values: None, max_size: None, mode: Measured)
	/// Storage: Teerex AllowSGXDebugMode (r:1 w:0)
	/// Proof Skipped: Teerex AllowSGXDebugMode (max_values: Some(1), max_size: None, mode: Measured)
	/// Storage: Teerex EnclaveIndex (r:1 w:1)
	/// Proof Skipped: Teerex EnclaveIndex (max_values: None, max_size: None, mode: Measured)
	/// Storage: Teerex EnclaveCount (r:1 w:1)
	/// Proof Skipped: Teerex EnclaveCount (max_values: Some(1), max_size: None, mode: Measured)
	/// Storage: Teerex EnclaveRegistry (r:0 w:1)
	/// Proof Skipped: Teerex EnclaveRegistry (max_values: None, max_size: None, mode: Measured)
	fn register_dcap_enclave() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `457`
		//  Estimated: `9680`
		// Minimum execution time: 2_856_095 nanoseconds.
		Weight::from_ref_time(3_253_895_000)
			.saturating_add(Weight::from_proof_size(9680))
			.saturating_add(T::DbWeight::get().reads(6))
			.saturating_add(T::DbWeight::get().writes(3))
	}
	/// Storage: Teerex EnclaveIndex (r:1 w:2)
	/// Proof Skipped: Teerex EnclaveIndex (max_values: None, max_size: None, mode: Measured)
	/// Storage: Teerex EnclaveCount (r:1 w:1)
	/// Proof Skipped: Teerex EnclaveCount (max_values: Some(1), max_size: None, mode: Measured)
	/// Storage: Teerex EnclaveRegistry (r:1 w:2)
	/// Proof Skipped: Teerex EnclaveRegistry (max_values: None, max_size: None, mode: Measured)
	fn unregister_enclave() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `504`
		//  Estimated: `6957`
		// Minimum execution time: 44_600 nanoseconds.
		Weight::from_ref_time(45_600_000)
			.saturating_add(Weight::from_proof_size(6957))
			.saturating_add(T::DbWeight::get().reads(3))
			.saturating_add(T::DbWeight::get().writes(5))
	}
	fn call_worker() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 17_100 nanoseconds.
		Weight::from_ref_time(17_300_000).saturating_add(Weight::from_proof_size(0))
	}
	/// Storage: Teerex EnclaveIndex (r:1 w:0)
	/// Proof Skipped: Teerex EnclaveIndex (max_values: None, max_size: None, mode: Measured)
	fn confirm_processed_parentchain_block() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `242`
		//  Estimated: `2717`
		// Minimum execution time: 25_400 nanoseconds.
		Weight::from_ref_time(29_300_000)
			.saturating_add(Weight::from_proof_size(2717))
			.saturating_add(T::DbWeight::get().reads(1))
	}
	/// Storage: Teerex EnclaveIndex (r:1 w:0)
	/// Proof Skipped: Teerex EnclaveIndex (max_values: None, max_size: None, mode: Measured)
	/// Storage: Teerex EnclaveRegistry (r:1 w:0)
	/// Proof Skipped: Teerex EnclaveRegistry (max_values: None, max_size: None, mode: Measured)
	/// Storage: System EventTopics (r:6 w:6)
	/// Proof Skipped: System EventTopics (max_values: None, max_size: None, mode: Measured)
	/// The range of component `l` is `[0, 100]`.
	/// The range of component `t` is `[1, 5]`.
	fn publish_hash(l: u32, t: u32) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `362`
		//  Estimated: `8511 + t * (2475 ±0)`
		// Minimum execution time: 37_200 nanoseconds.
		Weight::from_ref_time(43_344_069)
			.saturating_add(Weight::from_proof_size(8511))
			// Standard Error: 9_065
			.saturating_add(Weight::from_ref_time(2_808).saturating_mul(l.into()))
			// Standard Error: 198_651
			.saturating_add(Weight::from_ref_time(2_508_713).saturating_mul(t.into()))
			.saturating_add(T::DbWeight::get().reads(3))
			.saturating_add(T::DbWeight::get().reads((1_u64).saturating_mul(t.into())))
			.saturating_add(T::DbWeight::get().writes(1))
			.saturating_add(T::DbWeight::get().writes((1_u64).saturating_mul(t.into())))
			.saturating_add(Weight::from_proof_size(2475).saturating_mul(t.into()))
	}
}

/// For tests, weights have been generated with the integritee-node.
impl WeightInfo for () {
	/// Storage: Timestamp Now (r:1 w:0)
	/// Proof: Timestamp Now (max_values: Some(1), max_size: Some(8), added: 503, mode: MaxEncodedLen)
	/// Storage: Teerex AllowSGXDebugMode (r:1 w:0)
	/// Proof Skipped: Teerex AllowSGXDebugMode (max_values: Some(1), max_size: None, mode: Measured)
	/// Storage: Teerex EnclaveIndex (r:1 w:0)
	/// Proof Skipped: Teerex EnclaveIndex (max_values: None, max_size: None, mode: Measured)
	/// Storage: Teerex EnclaveRegistry (r:0 w:1)
	/// Proof Skipped: Teerex EnclaveRegistry (max_values: None, max_size: None, mode: Measured)
	fn register_ias_enclave() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `299`
		//  Estimated: `4370`
		// Minimum execution time: 1_512_300 nanoseconds.
		Weight::from_ref_time(2_591_400_000)
			.saturating_add(Weight::from_proof_size(4370))
			.saturating_add(RocksDbWeight::get().reads(3))
			.saturating_add(RocksDbWeight::get().writes(1))
	}
	/// Storage: Timestamp Now (r:1 w:0)
	/// Proof: Timestamp Now (max_values: Some(1), max_size: Some(8), added: 503, mode: MaxEncodedLen)
	/// Storage: Teerex TcbInfo (r:0 w:1)
	/// Proof Skipped: Teerex TcbInfo (max_values: None, max_size: None, mode: Measured)
	fn register_tcb_info() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `57`
		//  Estimated: `560`
		// Minimum execution time: 1_816_099 nanoseconds.
		Weight::from_ref_time(3_147_800_000)
			.saturating_add(Weight::from_proof_size(560))
			.saturating_add(RocksDbWeight::get().reads(1))
			.saturating_add(RocksDbWeight::get().writes(1))
	}
	/// Storage: Timestamp Now (r:1 w:0)
	/// Proof: Timestamp Now (max_values: Some(1), max_size: Some(8), added: 503, mode: MaxEncodedLen)
	/// Storage: Teerex QuotingEnclaveRegistry (r:0 w:1)
	/// Proof Skipped: Teerex QuotingEnclaveRegistry (max_values: Some(1), max_size: None, mode: Measured)
	fn register_quoting_enclave() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `57`
		//  Estimated: `560`
		// Minimum execution time: 1_562_200 nanoseconds.
		Weight::from_ref_time(1_847_900_000)
			.saturating_add(Weight::from_proof_size(560))
			.saturating_add(RocksDbWeight::get().reads(1))
			.saturating_add(RocksDbWeight::get().writes(1))
	}
	/// Storage: Timestamp Now (r:1 w:0)
	/// Proof: Timestamp Now (max_values: Some(1), max_size: Some(8), added: 503, mode: MaxEncodedLen)
	/// Storage: Teerex QuotingEnclaveRegistry (r:1 w:0)
	/// Proof Skipped: Teerex QuotingEnclaveRegistry (max_values: Some(1), max_size: None, mode: Measured)
	/// Storage: Teerex TcbInfo (r:1 w:0)
	/// Proof Skipped: Teerex TcbInfo (max_values: None, max_size: None, mode: Measured)
	/// Storage: Teerex AllowSGXDebugMode (r:1 w:0)
	/// Proof Skipped: Teerex AllowSGXDebugMode (max_values: Some(1), max_size: None, mode: Measured)
	/// Storage: Teerex EnclaveIndex (r:1 w:1)
	/// Proof Skipped: Teerex EnclaveIndex (max_values: None, max_size: None, mode: Measured)
	/// Storage: Teerex EnclaveCount (r:1 w:1)
	/// Proof Skipped: Teerex EnclaveCount (max_values: Some(1), max_size: None, mode: Measured)
	/// Storage: Teerex EnclaveRegistry (r:0 w:1)
	/// Proof Skipped: Teerex EnclaveRegistry (max_values: None, max_size: None, mode: Measured)
	fn register_dcap_enclave() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `420`
		//  Estimated: `9458`
		// Minimum execution time: 3_071_800 nanoseconds.
		Weight::from_ref_time(4_260_200_000)
			.saturating_add(Weight::from_proof_size(9458))
			.saturating_add(RocksDbWeight::get().reads(6))
			.saturating_add(RocksDbWeight::get().writes(3))
	}
	/// Storage: Teerex EnclaveIndex (r:1 w:2)
	/// Proof Skipped: Teerex EnclaveIndex (max_values: None, max_size: None, mode: Measured)
	/// Storage: Teerex EnclaveCount (r:1 w:1)
	/// Proof Skipped: Teerex EnclaveCount (max_values: Some(1), max_size: None, mode: Measured)
	/// Storage: Teerex EnclaveRegistry (r:1 w:2)
	/// Proof Skipped: Teerex EnclaveRegistry (max_values: None, max_size: None, mode: Measured)
	fn unregister_enclave() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `504`
		//  Estimated: `6957`
		// Minimum execution time: 50_600 nanoseconds.
		Weight::from_ref_time(51_200_000)
			.saturating_add(Weight::from_proof_size(6957))
			.saturating_add(RocksDbWeight::get().reads(3))
			.saturating_add(RocksDbWeight::get().writes(5))
	}
	fn call_worker() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 21_800 nanoseconds.
		Weight::from_ref_time(26_600_000).saturating_add(Weight::from_proof_size(0))
	}
	/// Storage: Teerex EnclaveIndex (r:1 w:0)
	/// Proof Skipped: Teerex EnclaveIndex (max_values: None, max_size: None, mode: Measured)
	fn confirm_processed_parentchain_block() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `242`
		//  Estimated: `2717`
		// Minimum execution time: 27_800 nanoseconds.
		Weight::from_ref_time(28_700_000)
			.saturating_add(Weight::from_proof_size(2717))
			.saturating_add(RocksDbWeight::get().reads(1))
	}
	/// Storage: Teerex EnclaveIndex (r:1 w:0)
	/// Proof Skipped: Teerex EnclaveIndex (max_values: None, max_size: None, mode: Measured)
	/// Storage: Teerex EnclaveRegistry (r:1 w:0)
	/// Proof Skipped: Teerex EnclaveRegistry (max_values: None, max_size: None, mode: Measured)
	/// Storage: System EventTopics (r:6 w:6)
	/// Proof Skipped: System EventTopics (max_values: None, max_size: None, mode: Measured)
	/// The range of component `l` is `[0, 100]`.
	/// The range of component `t` is `[1, 5]`.
	fn publish_hash(l: u32, t: u32) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `362`
		//  Estimated: `8511 + t * (2475 ±0)`
		// Minimum execution time: 41_400 nanoseconds.
		Weight::from_ref_time(28_179_644)
			.saturating_add(Weight::from_proof_size(8511))
			// Standard Error: 21_336
			.saturating_add(Weight::from_ref_time(318_271).saturating_mul(l.into()))
			// Standard Error: 467_546
			.saturating_add(Weight::from_ref_time(7_329_090).saturating_mul(t.into()))
			.saturating_add(RocksDbWeight::get().reads(3))
			.saturating_add(RocksDbWeight::get().reads((1_u64).saturating_mul(t.into())))
			.saturating_add(RocksDbWeight::get().writes(1))
			.saturating_add(RocksDbWeight::get().writes((1_u64).saturating_mul(t.into())))
			.saturating_add(Weight::from_proof_size(2475).saturating_mul(t.into()))
	}
}
