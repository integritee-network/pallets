/*
Copyright 2021 Integritee AG

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
use frame_support::{traits::Get, weights::Weight};
use sp_std::marker::PhantomData;

/// Weight functions needed for pallet_exchange.
pub trait WeightInfo {
	fn add_to_whitelist() -> Weight;
	fn remove_from_whitelist() -> Weight;
	fn update_exchange_rate() -> Weight;
	fn update_oracle() -> Weight;
}

pub struct IntegriteeWeight<T>(PhantomData<T>);
impl<T: frame_system::Config> WeightInfo for IntegriteeWeight<T> {
	/// Storage: `Teerex::SovereignEnclaves` (r:1 w:0)
	/// Proof: `Teerex::SovereignEnclaves` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `Teeracle::Whitelists` (r:1 w:0)
	/// Proof: `Teeracle::Whitelists` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `Teeracle::ExchangeRates` (r:1 w:1)
	/// Proof: `Teeracle::ExchangeRates` (`max_values`: None, `max_size`: None, mode: `Measured`)
	fn update_exchange_rate() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `454`
		//  Estimated: `3919`
		// Minimum execution time: 44_730_000 picoseconds.
		Weight::from_parts(49_230_000, 0)
			.saturating_add(Weight::from_parts(0, 3919))
			.saturating_add(T::DbWeight::get().reads(3))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: `Teerex::SovereignEnclaves` (r:1 w:0)
	/// Proof: `Teerex::SovereignEnclaves` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `Teeracle::Whitelists` (r:1 w:0)
	/// Proof: `Teeracle::Whitelists` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `Teeracle::OracleData` (r:0 w:1)
	/// Proof: `Teeracle::OracleData` (`max_values`: None, `max_size`: None, mode: `Measured`)
	fn update_oracle() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `445`
		//  Estimated: `3910`
		// Minimum execution time: 37_526_000 picoseconds.
		Weight::from_parts(41_294_000, 0)
			.saturating_add(Weight::from_parts(0, 3910))
			.saturating_add(T::DbWeight::get().reads(2))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: `Teeracle::Whitelists` (r:1 w:1)
	/// Proof: `Teeracle::Whitelists` (`max_values`: None, `max_size`: None, mode: `Measured`)
	fn add_to_whitelist() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `6`
		//  Estimated: `3471`
		// Minimum execution time: 17_640_000 picoseconds.
		Weight::from_parts(19_529_000, 0)
			.saturating_add(Weight::from_parts(0, 3471))
			.saturating_add(T::DbWeight::get().reads(1))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: `Teeracle::Whitelists` (r:1 w:1)
	/// Proof: `Teeracle::Whitelists` (`max_values`: None, `max_size`: None, mode: `Measured`)
	fn remove_from_whitelist() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `107`
		//  Estimated: `3572`
		// Minimum execution time: 20_741_000 picoseconds.
		Weight::from_parts(21_866_000, 0)
			.saturating_add(Weight::from_parts(0, 3572))
			.saturating_add(T::DbWeight::get().reads(1))
			.saturating_add(T::DbWeight::get().writes(1))
	}
}
// For tests
impl WeightInfo for () {
	fn add_to_whitelist() -> Weight {
		Weight::from_parts(46_200_000, 0u64)
	}
	fn remove_from_whitelist() -> Weight {
		Weight::from_parts(46_200_000, 0u64)
	}
	fn update_exchange_rate() -> Weight {
		Weight::from_parts(46_200_000, 0u64)
	}
	fn update_oracle() -> Weight {
		Weight::from_parts(46_200_000, 0u64)
	}
}
