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
	fn register_sgx_enclave() -> Weight;
	fn register_quoting_enclave() -> Weight;
	fn register_tcb_info() -> Weight;
	fn unregister_sovereign_enclave() -> Weight;
	fn unregister_proxied_enclave() -> Weight;
	fn set_security_flags() -> Weight;
}

/// Weights for pallet_teerex using the Integritee parachain node and recommended hardware.
pub struct IntegriteeWeight<T>(PhantomData<T>);
impl<T: frame_system::Config> WeightInfo for IntegriteeWeight<T> {
	/// Storage: Timestamp Now (r:1 w:0)
	/// Proof: Timestamp Now (max_values: Some(1), max_size: Some(8), added: 503, mode: MaxEncodedLen)
	/// Storage: Teerex SgxQuotingEnclaveRegistry (r:1 w:0)
	/// Proof Skipped: Teerex SgxQuotingEnclaveRegistry (max_values: Some(1), max_size: None, mode: Measured)
	/// Storage: Teerex SgxTcbInfo (r:1 w:0)
	/// Proof Skipped: Teerex SgxTcbInfo (max_values: None, max_size: None, mode: Measured)
	/// Storage: Teerex SgxAllowDebugMode (r:1 w:0)
	/// Proof Skipped: Teerex SgxAllowDebugMode (max_values: Some(1), max_size: None, mode: Measured)
	/// Storage: Teerex SovereignEnclaves (r:0 w:1)
	/// Proof Skipped: Teerex SovereignEnclaves (max_values: None, max_size: None, mode: Measured)
	fn register_sgx_enclave() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `394`
		//  Estimated: `3859`
		// Minimum execution time: 2_017_551_000 picoseconds.
		Weight::from_parts(2_049_028_000, 0)
			.saturating_add(Weight::from_parts(0, 3859))
			.saturating_add(T::DbWeight::get().reads(4))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: Timestamp Now (r:1 w:0)
	/// Proof: Timestamp Now (max_values: Some(1), max_size: Some(8), added: 503, mode: MaxEncodedLen)
	/// Storage: Teerex SgxQuotingEnclaveRegistry (r:0 w:1)
	/// Proof Skipped: Teerex SgxQuotingEnclaveRegistry (max_values: Some(1), max_size: None, mode: Measured)
	fn register_quoting_enclave() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `95`
		//  Estimated: `1493`
		// Minimum execution time: 1_016_200_000 picoseconds.
		Weight::from_parts(1_031_990_000, 0)
			.saturating_add(Weight::from_parts(0, 1493))
			.saturating_add(T::DbWeight::get().reads(1))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: Timestamp Now (r:1 w:0)
	/// Proof: Timestamp Now (max_values: Some(1), max_size: Some(8), added: 503, mode: MaxEncodedLen)
	/// Storage: Teerex SgxTcbInfo (r:0 w:1)
	/// Proof Skipped: Teerex SgxTcbInfo (max_values: None, max_size: None, mode: Measured)
	fn register_tcb_info() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `95`
		//  Estimated: `1493`
		// Minimum execution time: 1_120_761_000 picoseconds.
		Weight::from_parts(1_128_361_000, 0)
			.saturating_add(Weight::from_parts(0, 1493))
			.saturating_add(T::DbWeight::get().reads(1))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: Teerex SovereignEnclaves (r:1 w:1)
	/// Proof Skipped: Teerex SovereignEnclaves (max_values: None, max_size: None, mode: Measured)
	/// Storage: Timestamp Now (r:1 w:0)
	/// Proof: Timestamp Now (max_values: Some(1), max_size: Some(8), added: 503, mode: MaxEncodedLen)
	fn unregister_sovereign_enclave() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `473`
		//  Estimated: `3938`
		// Minimum execution time: 17_250_000 picoseconds.
		Weight::from_parts(18_139_000, 0)
			.saturating_add(Weight::from_parts(0, 3938))
			.saturating_add(T::DbWeight::get().reads(2))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: Teerex ProxiedEnclaves (r:1 w:1)
	/// Proof Skipped: Teerex ProxiedEnclaves (max_values: None, max_size: None, mode: Measured)
	/// Storage: Timestamp Now (r:1 w:0)
	/// Proof: Timestamp Now (max_values: Some(1), max_size: Some(8), added: 503, mode: MaxEncodedLen)
	fn unregister_proxied_enclave() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `575`
		//  Estimated: `4040`
		// Minimum execution time: 20_486_000 picoseconds.
		Weight::from_parts(21_264_000, 0)
			.saturating_add(Weight::from_parts(0, 4040))
			.saturating_add(T::DbWeight::get().reads(2))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	fn set_security_flags() -> Weight {
		Weight::from_parts(46_200_000, 0u64)
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
	fn register_sgx_enclave() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `299`
		//  Estimated: `4370`
		// Minimum execution time: 1_512_300 nanoseconds.
		Weight::from_parts(2_591_400_000, 0u64)
			.saturating_add(Weight::from_parts(0u64, 4370))
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
		Weight::from_parts(3_147_800_000, 0u64)
			.saturating_add(Weight::from_parts(0u64, 560))
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
		Weight::from_parts(1_847_900_000, 0u64)
			.saturating_add(Weight::from_parts(0u64, 560))
			.saturating_add(RocksDbWeight::get().reads(1))
			.saturating_add(RocksDbWeight::get().writes(1))
	}
	/// Storage: Teerex SovereignEnclaves (r:1 w:1)
	/// Proof Skipped: Teerex SovereignEnclaves (max_values: None, max_size: None, mode: Measured)
	/// Storage: Timestamp Now (r:1 w:0)
	/// Proof: Timestamp Now (max_values: Some(1), max_size: Some(8), added: 503, mode: MaxEncodedLen)
	fn unregister_sovereign_enclave() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `473`
		//  Estimated: `3938`
		// Minimum execution time: 17_250_000 picoseconds.
		Weight::from_parts(18_139_000, 0)
			.saturating_add(Weight::from_parts(0, 3938))
			.saturating_add(RocksDbWeight::get().reads(2))
			.saturating_add(RocksDbWeight::get().writes(1))
	}
	/// Storage: Teerex ProxiedEnclaves (r:1 w:1)
	/// Proof Skipped: Teerex ProxiedEnclaves (max_values: None, max_size: None, mode: Measured)
	/// Storage: Timestamp Now (r:1 w:0)
	/// Proof: Timestamp Now (max_values: Some(1), max_size: Some(8), added: 503, mode: MaxEncodedLen)
	fn unregister_proxied_enclave() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `575`
		//  Estimated: `4040`
		// Minimum execution time: 20_486_000 picoseconds.
		Weight::from_parts(21_264_000, 0)
			.saturating_add(Weight::from_parts(0, 4040))
			.saturating_add(RocksDbWeight::get().reads(2))
			.saturating_add(RocksDbWeight::get().writes(1))
	}
	fn set_security_flags() -> Weight {
		Weight::from_parts(46_200_000, 0u64)
	}
}
