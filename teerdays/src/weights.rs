/*
	Copyright 2021 Integritee AG

	Licenced under GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version. You may obtain a copy of the
	License at

		<http://www.gnu.org/licenses/>.

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
*/
use frame_support::{traits::Get, weights::Weight};
use sp_std::marker::PhantomData;

/// Weight functions needed for pallet_teerdays.
pub trait WeightInfo {
	fn bond() -> Weight;
	fn unbond() -> Weight;
	fn update_other() -> Weight;
	fn withdraw_unbonded() -> Weight;
}

/// Weights for pallet_sidechain using the Integritee parachain node and recommended hardware.
pub struct IntegriteeWeight<T>(PhantomData<T>);
impl<T: frame_system::Config> WeightInfo for IntegriteeWeight<T> {
	/// Storage: `TeerDays::TeerDayBonds` (r:1 w:1)
	/// Proof: `TeerDays::TeerDayBonds` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `System::Account` (r:1 w:1)
	/// Proof: `System::Account` (`max_values`: None, `max_size`: Some(128), added: 2603, mode: `MaxEncodedLen`)
	/// Storage: `Balances::Locks` (r:1 w:1)
	/// Proof: `Balances::Locks` (`max_values`: None, `max_size`: Some(1299), added: 3774, mode: `MaxEncodedLen`)
	/// Storage: `Balances::Freezes` (r:1 w:0)
	/// Proof: `Balances::Freezes` (`max_values`: None, `max_size`: Some(49), added: 2524, mode: `MaxEncodedLen`)
	/// Storage: `Timestamp::Now` (r:1 w:0)
	/// Proof: `Timestamp::Now` (`max_values`: Some(1), `max_size`: Some(8), added: 503, mode: `MaxEncodedLen`)
	fn bond() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `240`
		//  Estimated: `4764`
		// Minimum execution time: 82_957_000 picoseconds.
		Weight::from_parts(86_401_000, 0)
			.saturating_add(Weight::from_parts(0, 4764))
			.saturating_add(T::DbWeight::get().reads(5))
			.saturating_add(T::DbWeight::get().writes(3))
	}
	/// Storage: `TeerDays::PendingUnlock` (r:1 w:1)
	/// Proof: `TeerDays::PendingUnlock` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `TeerDays::TeerDayBonds` (r:1 w:1)
	/// Proof: `TeerDays::TeerDayBonds` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `Timestamp::Now` (r:1 w:0)
	/// Proof: `Timestamp::Now` (`max_values`: Some(1), `max_size`: Some(8), added: 503, mode: `MaxEncodedLen`)
	fn unbond() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `253`
		//  Estimated: `3718`
		// Minimum execution time: 53_559_000 picoseconds.
		Weight::from_parts(56_711_000, 0)
			.saturating_add(Weight::from_parts(0, 3718))
			.saturating_add(T::DbWeight::get().reads(3))
			.saturating_add(T::DbWeight::get().writes(2))
	}
	/// Storage: `TeerDays::TeerDayBonds` (r:1 w:1)
	/// Proof: `TeerDays::TeerDayBonds` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `Timestamp::Now` (r:1 w:0)
	/// Proof: `Timestamp::Now` (`max_values`: Some(1), `max_size`: Some(8), added: 503, mode: `MaxEncodedLen`)
	fn update_other() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `253`
		//  Estimated: `3718`
		// Minimum execution time: 34_156_000 picoseconds.
		Weight::from_parts(37_183_000, 0)
			.saturating_add(Weight::from_parts(0, 3718))
			.saturating_add(T::DbWeight::get().reads(2))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: `TeerDays::PendingUnlock` (r:1 w:1)
	/// Proof: `TeerDays::PendingUnlock` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `Timestamp::Now` (r:1 w:0)
	/// Proof: `Timestamp::Now` (`max_values`: Some(1), `max_size`: Some(8), added: 503, mode: `MaxEncodedLen`)
	/// Storage: `Balances::Locks` (r:1 w:1)
	/// Proof: `Balances::Locks` (`max_values`: None, `max_size`: Some(1299), added: 3774, mode: `MaxEncodedLen`)
	/// Storage: `Balances::Freezes` (r:1 w:0)
	/// Proof: `Balances::Freezes` (`max_values`: None, `max_size`: Some(49), added: 2524, mode: `MaxEncodedLen`)
	/// Storage: `System::Account` (r:1 w:1)
	/// Proof: `System::Account` (`max_values`: None, `max_size`: Some(128), added: 2603, mode: `MaxEncodedLen`)
	fn withdraw_unbonded() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `400`
		//  Estimated: `4764`
		// Minimum execution time: 80_293_000 picoseconds.
		Weight::from_parts(82_512_000, 0)
			.saturating_add(Weight::from_parts(0, 4764))
			.saturating_add(T::DbWeight::get().reads(5))
			.saturating_add(T::DbWeight::get().writes(3))
	}
}

// For tests
impl WeightInfo for () {
	fn bond() -> Weight {
		Weight::from_parts(2_591_400_000, 0u64)
	}
	fn unbond() -> Weight {
		Weight::from_parts(2_591_400_000, 0u64)
	}
	fn update_other() -> Weight {
		Weight::from_parts(2_591_400_000, 0u64)
	}

	fn withdraw_unbonded() -> Weight {
		Weight::from_parts(2_591_400_000, 0u64)
	}
}
