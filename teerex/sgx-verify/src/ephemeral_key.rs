/*
	Copyright 2021 Integritee AG and Supercomputing Systems AG

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <https://www.gnu.org/licenses/>.

*/

use crate::{utils::length_from_raw_data, CertDer};
use sp_std::convert::TryFrom;

#[allow(dead_code)]
pub struct EphemeralKey<'a>(&'a [u8]);

pub const PRIME256V1_OID: &[u8; 10] = &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
impl<'a> TryFrom<CertDer<'a>> for EphemeralKey<'a> {
	type Error = &'static str;

	fn try_from(value: CertDer<'a>) -> Result<Self, Self::Error> {
		let cert_der = value.0;

		let mut offset = cert_der
			.windows(PRIME256V1_OID.len())
			.position(|window| window == PRIME256V1_OID)
			.ok_or("Certificate does not contain 'PRIME256V1_OID'")?;

		offset += PRIME256V1_OID.len() + 1; // OID length + TAG (0x03)

		// Obtain Public Key length
		let len = length_from_raw_data(cert_der, &mut offset)?;

		// Obtain Public Key
		offset += 1;
		let pub_k = cert_der.get(offset + 2..offset + len).ok_or("Index out of bounds")?; // skip "00 04"

		#[cfg(test)]
		println!("verifyRA ephemeral public key: {pub_k:x?}");
		Ok(EphemeralKey(pub_k))
	}
}
