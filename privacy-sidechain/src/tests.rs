/*
	Copyright 2021 Integritee AG & Parity Technologies (UK) Ltd.

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

use crate::{mock::*, Config, Error, Event};
use codec::{Decode, Encode};
use cumulus_primitives_core::ParaId;
use frame_support::{assert_noop, assert_ok};
// use sp_keyring::AccountKeyring;

#[test]
fn my_test() {
    new_test_ext().execute_with(|| {
        assert_ok!(PrivacySidechain::test_extrinsic(RuntimeOrigin::signed(ALICE)));
        assert!(
            System::events().iter().any(|r| r.event == Event::<Test>::PrivacyEvent.into())
        );
    })
}