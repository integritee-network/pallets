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
	fn set_porteer_config() -> Weight;
}

/// Weights for pallet_sidechain using the Integritee parachain node and recommended hardware.
pub struct IntegriteeWeight<T>(PhantomData<T>);
impl<T: frame_system::Config> WeightInfo for IntegriteeWeight<T> {
	fn set_porteer_config() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `240`
		//  Estimated: `4764`
		// Minimum execution time: 82_957_000 picoseconds.
		Weight::from_parts(86_401_000, 0)
			.saturating_add(Weight::from_parts(0, 4764))
			.saturating_add(T::DbWeight::get().reads(5))
			.saturating_add(T::DbWeight::get().writes(3))
	}
}

// For tests
impl WeightInfo for () {
	fn set_porteer_config() -> Weight {
		Weight::from_parts(2_591_400_000, 0u64)
	}
}
