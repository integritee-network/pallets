use parity_scale_codec::{Compact, Decode, Encode};
use scale_info::TypeInfo;
use sp_runtime::{
	traits::{AtLeast32BitUnsigned, UniqueSaturatedFrom},
	SaturatedConversion, Saturating,
};
use std::ops::Mul;

#[derive(Encode, Decode, Copy, Clone, PartialEq, Eq, Default, sp_core::RuntimeDebug, TypeInfo)]
pub struct TeerDayBond<Balance, Moment> {
	pub bond: Balance,
	pub last_updated: Moment,
	// the unit here is actually balance * moments.
	pub accumulated_tokentime: Balance,
}

impl<Balance, Moment> TeerDayBond<Balance, Moment>
where
	Moment: Clone + Copy + Encode + Decode + Saturating,
	Balance: AtLeast32BitUnsigned + Clone + Copy + Encode + Decode + Default + From<Moment>,
{
	pub fn update(self, now: Moment) -> Self {
		let elapsed: Balance = now.saturating_sub(self.last_updated).into();
		let new_tokentime =
			self.accumulated_tokentime.saturating_add(self.bond.saturating_mul(elapsed));
		Self { bond: self.bond, last_updated: now, accumulated_tokentime: new_tokentime }
	}
}
