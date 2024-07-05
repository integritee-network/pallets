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

use frame_support::weights::Weight;
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
	fn bond() -> Weight {
		todo!()
	}
	fn unbond() -> Weight {
		todo!()
	}

	fn update_other() -> Weight {
		todo!()
	}

	fn withdraw_unbonded() -> Weight {
		todo!()
	}
}

// For tests
impl WeightInfo for () {
	fn bond() -> Weight {
		todo!()
	}
	fn unbond() -> Weight {
		todo!()
	}
	fn update_other() -> Weight {
		todo!()
	}

	fn withdraw_unbonded() -> Weight {
		todo!()
	}
}
