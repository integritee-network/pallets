use parity_scale_codec::{Decode, Encode};
use scale_info::TypeInfo;
use sp_runtime::Permill;

pub const TEERDAY: Permill = Permill::from_percent(100);
#[derive(Encode, Decode, Copy, Clone, PartialEq, Eq, Default, sp_core::RuntimeDebug, TypeInfo)]
pub struct TeerDayBond<Balance, Moment> {
	pub bond: Balance,
	pub last_updated: Moment,
	pub accumulated_teerdays: Balance,
}
