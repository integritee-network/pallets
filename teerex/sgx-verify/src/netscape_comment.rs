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

use crate::{utils::length_from_raw_data, CertDer};
use frame_support::ensure;
use sp_std::{convert::TryFrom, prelude::Vec};

pub struct NetscapeComment<'a> {
	pub attestation_raw: &'a [u8],
	pub sig: Vec<u8>,
	pub sig_cert: Vec<u8>,
}

pub const NS_CMT_OID: &[u8; 11] =
	&[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x86, 0xF8, 0x42, 0x01, 0x0D];

impl<'a> TryFrom<CertDer<'a>> for NetscapeComment<'a> {
	type Error = &'static str;

	fn try_from(value: CertDer<'a>) -> Result<Self, Self::Error> {
		// Search for Netscape Comment OID
		let cert_der = value.0;

		let mut offset = cert_der
			.windows(NS_CMT_OID.len())
			.position(|window| window == NS_CMT_OID)
			.ok_or("Certificate does not contain 'ns_cmt_oid'")?;

		offset += 12; // 11 + TAG (0x04)

		#[cfg(test)]
		println!("netscape");
		// Obtain Netscape Comment length
		let len = length_from_raw_data(cert_der, &mut offset)?;
		// Obtain Netscape Comment
		offset += 1;
		let netscape_raw = cert_der
			.get(offset..offset + len)
			.ok_or("Index out of bounds")?
			.split(|x| *x == 0x7C) // 0x7C is the character '|'
			.collect::<Vec<&[u8]>>();
		ensure!(netscape_raw.len() == 3, "Invalid netscape payload");

		let sig = base64::decode(netscape_raw[1]).map_err(|_| "Signature Decoding Error")?;

		let sig_cert = base64::decode_config(netscape_raw[2], base64::STANDARD)
			.map_err(|_| "Cert Decoding Error")?;

		Ok(NetscapeComment { attestation_raw: netscape_raw[0], sig, sig_cert })
	}
}
