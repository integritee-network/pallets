/*
	Copyright 2022 Integritee AG and Supercomputing Systems AG

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

#![cfg_attr(not(feature = "std"), no_std)]
pub extern crate alloc;

use alloc::string::String;
use chrono::prelude::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sp_std::prelude::*;

#[derive(Serialize, Deserialize)]
pub struct Tcb {
	isvsvn: u16,
}

impl Tcb {
	pub fn is_valid(&self) -> bool {
		// At the time of writing this code everything older than 6 is outdated
		// Intel does the same check in their DCAP implementation
		self.isvsvn >= 6
	}
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbLevel {
	tcb: Tcb,
	tcb_date: DateTime<Utc>,
	tcb_status: String,
	#[serde(rename = "advisoryIDs")]
	#[serde(skip_serializing_if = "Option::is_none")]
	advisory_ids: Option<Vec<String>>,
}

impl TcbLevel {
	pub fn is_valid(&self) -> bool {
		self.tcb.is_valid() && self.tcb_status == "UpToDate"
	}
}

#[derive(Serialize, Deserialize)]
struct TcbComponent {
	svn: u8,
}

#[derive(Serialize, Deserialize)]
pub struct TcbFull {
	sgxtcbcomponents: Vec<TcbComponent>,
	pcesvn: u8,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbLevelFull {
	tcb: TcbFull,
	tcb_date: DateTime<Utc>,
	tcb_status: String,
	#[serde(rename = "advisoryIDs")]
	#[serde(skip_serializing_if = "Option::is_none")]
	advisory_ids: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnclaveIdentity {
	id: String,
	version: u16,
	pub issue_date: DateTime<Utc>,
	pub next_update: DateTime<Utc>,
	tcb_evaluation_data_number: u16,
	miscselect: String,
	miscselect_mask: String,
	attributes: String,
	attributes_mask: String,
	mrsigner: String,
	pub isvprodid: u16,
	pub tcb_levels: Vec<TcbLevel>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbInfo {
	id: String,
	version: u8,
	pub issue_date: DateTime<Utc>,
	pub next_update: DateTime<Utc>,
	pub fmspc: String,
	pce_id: String,
	tcb_type: u16,
	tcb_evaluation_data_number: u16,
	tcb_levels: Vec<TcbLevelFull>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbInfoSigned {
	pub tcb_info: TcbInfo,
	pub signature: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnclaveIdentitySigned {
	pub enclave_identity: EnclaveIdentity,
	pub signature: String,
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn tcb_level_is_valid() {
		let t: TcbLevel = serde_json::from_str(
			r#"{"tcb":{"isvsvn":6}, "tcbDate":"2021-11-10T00:00:00Z", "tcbStatus":"UpToDate" }"#,
		)
		.unwrap();
		assert!(t.is_valid());

		let t: TcbLevel = serde_json::from_str(
			r#"{"tcb":{"isvsvn":6}, "tcbDate":"2025-11-10T00:00:00Z", "tcbStatus":"OutOfDate" }"#,
		)
		.unwrap();
		assert!(!t.is_valid());
	}
}
