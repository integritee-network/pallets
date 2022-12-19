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

use crate::{alloc::string::ToString, SgxReportBody};
use alloc::{format, string::String};
use chrono::prelude::{DateTime, Utc};
use serde::{de::Error, Deserialize, Deserializer, Serialize, Serializer};
use sp_std::prelude::*;
use teerex_primitives::{Fmspc, QeTcb, QuotingEnclave, TcbInfoOnChain, TcbVersionStatus};

/// The data structures in here are designed such that they can be used to serialize/deserialize
/// the "TCB info" and "enclave identity" collateral data in JSON format provided by intel
/// See https://api.portal.trustedservices.intel.com/documentation for further information and examples

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
	/// Intel does not verify the tcb_date in their code and their API documentation also does
	/// not mention it needs verification.
	tcb_date: DateTime<Utc>,
	tcb_status: String,
	#[serde(rename = "advisoryIDs")]
	#[serde(skip_serializing_if = "Option::is_none")]
	advisory_ids: Option<Vec<String>>,
}

impl TcbLevel {
	pub fn is_valid(&self) -> bool {
		// UpToDate is the only valid status (the other being OutOfDate and Revoked)
		// A possible extension would be to also verify that the advisory_ids list is empty,
		// but I think this could also lead to all TcbLevels being invalid
		self.tcb.is_valid() && self.tcb_status == "UpToDate"
	}
}

#[derive(Serialize, Deserialize)]
struct TcbComponent {
	svn: u8,
	#[serde(skip_serializing_if = "Option::is_none")]
	category: Option<String>,
	#[serde(rename = "type")] //type is a keyword so we rename the field
	#[serde(skip_serializing_if = "Option::is_none")]
	tcb_type: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct TcbFull {
	sgxtcbcomponents: [TcbComponent; 16],
	pcesvn: u16,
}

impl TcbFull {
	fn is_valid(&self, reference: &TcbFull) -> bool {
		for (v, r) in self.sgxtcbcomponents.iter().zip(reference.sgxtcbcomponents.iter()) {
			if v.svn < r.svn {
				return false
			}
		}
		return self.pcesvn >= reference.pcesvn
	}
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbLevelFull {
	tcb: TcbFull,
	/// Intel does not verify the tcb_date in their code and their API documentation also does
	/// not mention it needs verification.
	tcb_date: DateTime<Utc>,
	tcb_status: String,
	#[serde(rename = "advisoryIDs")]
	#[serde(skip_serializing_if = "Option::is_none")]
	advisory_ids: Option<Vec<String>>,
}

impl TcbLevelFull {
	pub fn is_valid(&self) -> bool {
		// A possible extension would be to also verify that the advisory_ids list is empty,
		// but I think this could also lead to all TcbLevels being invalid
		self.tcb_status == "UpToDate" || self.tcb_status == "SWHardeningNeeded"
	}
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnclaveIdentity {
	id: String,
	version: u16,
	issue_date: DateTime<Utc>,
	next_update: DateTime<Utc>,
	tcb_evaluation_data_number: u16,
	#[serde(deserialize_with = "deserialize_from_hex::<_, 4>")]
	#[serde(serialize_with = "serialize_to_hex::<_, 4>")]
	miscselect: [u8; 4],
	#[serde(deserialize_with = "deserialize_from_hex::<_, 4>")]
	#[serde(serialize_with = "serialize_to_hex::<_, 4>")]
	miscselect_mask: [u8; 4],
	#[serde(deserialize_with = "deserialize_from_hex::<_, 16>")]
	#[serde(serialize_with = "serialize_to_hex::<_, 16>")]
	attributes: [u8; 16],
	#[serde(deserialize_with = "deserialize_from_hex::<_, 16>")]
	#[serde(serialize_with = "serialize_to_hex::<_, 16>")]
	attributes_mask: [u8; 16],
	#[serde(deserialize_with = "deserialize_from_hex::<_, 32>")]
	#[serde(serialize_with = "serialize_to_hex::<_, 32>")]
	mrsigner: [u8; 32],
	pub isvprodid: u16,
	pub tcb_levels: Vec<TcbLevel>,
}

fn serialize_to_hex<S, const N: usize>(x: &[u8; N], s: S) -> Result<S::Ok, S::Error>
where
	S: Serializer,
{
	s.serialize_str(&hex::encode(x).to_uppercase())
}

fn deserialize_from_hex<'de, D, const N: usize>(deserializer: D) -> Result<[u8; N], D::Error>
where
	D: Deserializer<'de>,
{
	let s: &str = Deserialize::deserialize(deserializer)?;
	let hex = hex::decode(&s).map_err(|_| D::Error::custom("Failed to deserialize hex string"))?;
	hex.try_into().map_err(|_| D::Error::custom("Invalid hex length"))
}

impl EnclaveIdentity {
	/// This extracts the necessary information into the struct that we actually store in the chain
	pub fn to_quoting_enclave(&self) -> QuotingEnclave {
		let mut valid_tcbs: Vec<QeTcb> = Vec::new();
		for tcb in &self.tcb_levels {
			if tcb.is_valid() {
				valid_tcbs.push(QeTcb::new(tcb.tcb.isvsvn));
			}
		}
		QuotingEnclave::new(
			self.issue_date.timestamp_millis().try_into().unwrap(),
			self.next_update.timestamp_millis().try_into().unwrap(),
			self.miscselect,
			self.miscselect_mask,
			self.attributes,
			self.attributes_mask,
			self.mrsigner,
			self.isvprodid,
			valid_tcbs,
		)
	}

	pub fn is_valid(&self, timestamp_millis: i64) -> bool {
		self.id == "QE" &&
			self.version == 2 &&
			self.issue_date.timestamp_millis() < timestamp_millis &&
			timestamp_millis < self.next_update.timestamp_millis()
	}
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbInfo {
	id: String,
	version: u8,
	issue_date: DateTime<Utc>,
	next_update: DateTime<Utc>,
	#[serde(deserialize_with = "deserialize_from_hex::<_, 6>")]
	#[serde(serialize_with = "serialize_to_hex::<_, 6>")]
	pub fmspc: teerex_primitives::Fmspc,
	pce_id: String,
	tcb_type: u16,
	tcb_evaluation_data_number: u16,
	tcb_levels: Vec<TcbLevelFull>,
}

impl TcbInfo {
	/// This extracts the necessary information into the struct that we actually store in the chain
	pub fn to_chain_tcb_info(&self) -> (Fmspc, TcbInfoOnChain) {
		let mut valid_tcbs: Vec<TcbVersionStatus> = Vec::new();
		for tcb in &self.tcb_levels {
			// Only store TCB levels on chain that are currently valid
			if tcb.is_valid() {
				let mut components = [0u8; 16];
				for (i, t) in tcb.tcb.sgxtcbcomponents.iter().enumerate() {
					components[i] = t.svn;
				}
				valid_tcbs.push(TcbVersionStatus::new(components, tcb.tcb.pcesvn));
			}
		}
		(
			self.fmspc,
			TcbInfoOnChain::new(
				self.issue_date.timestamp_millis().try_into().unwrap(),
				self.next_update.timestamp_millis().try_into().unwrap(),
				valid_tcbs,
			),
		)
	}

	pub fn is_valid(&self, timestamp_millis: i64) -> bool {
		self.id == "SGX" &&
			self.version == 3 &&
			self.issue_date.timestamp_millis() < timestamp_millis &&
			timestamp_millis < self.next_update.timestamp_millis()
	}
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

/// Separates the actual data part from the signature for an Intel collateral in JSON format
/// Returns the data part and signature as a pair
fn separate_json_data_and_signature(data_name: &str, data: &[u8]) -> Option<(String, String)> {
	let json = String::from_utf8_lossy(data);
	// search pattern is something like `{"tcbInfo":`. Should be at the very beginning
	let search_pattern = format!("{{\"{}\":", data_name);
	let json = json.replace(&search_pattern, "");

	let parts = json.split(r#","signature":""#).collect::<Vec<&str>>();
	if parts.len() != 2 || parts[1].len() < 2 {
		return None
	}
	let data = &parts[0];
	let signature = &parts[1][0..parts[1].len() - 2]; // Remove the two last chars that 'close' the json
	Some((data.to_string(), signature.to_string()))
}

#[cfg(test)]
mod tests {
	use super::*;
	use der::ErrorKind::DateTime;

	#[test]
	fn separate_json_data_and_signature_enclave_identity() {
		let json = include_bytes!("../test/dcap/qe_identity.json");
		let (data, signature) = separate_json_data_and_signature("enclaveIdentity", json).unwrap();
		assert_eq!(
			data,
			r#"{"id":"QE","version":2,"issueDate":"2022-12-04T22:45:33Z","nextUpdate":"2023-01-03T22:45:33Z","tcbEvaluationDataNumber":13,"miscselect":"00000000","miscselectMask":"FFFFFFFF","attributes":"11000000000000000000000000000000","attributesMask":"FBFFFFFFFFFFFFFF0000000000000000","mrsigner":"8C4F5775D796503E96137F77C68A829A0056AC8DED70140B081B094490C57BFF","isvprodid":1,"tcbLevels":[{"tcb":{"isvsvn":6},"tcbDate":"2022-11-09T00:00:00Z","tcbStatus":"UpToDate"},{"tcb":{"isvsvn":5},"tcbDate":"2020-11-11T00:00:00Z","tcbStatus":"OutOfDate","advisoryIDs":["INTEL-SA-00477"]},{"tcb":{"isvsvn":4},"tcbDate":"2019-11-13T00:00:00Z","tcbStatus":"OutOfDate","advisoryIDs":["INTEL-SA-00334","INTEL-SA-00477"]},{"tcb":{"isvsvn":2},"tcbDate":"2019-05-15T00:00:00Z","tcbStatus":"OutOfDate","advisoryIDs":["INTEL-SA-00219","INTEL-SA-00293","INTEL-SA-00334","INTEL-SA-00477"]},{"tcb":{"isvsvn":1},"tcbDate":"2018-08-15T00:00:00Z","tcbStatus":"OutOfDate","advisoryIDs":["INTEL-SA-00202","INTEL-SA-00219","INTEL-SA-00293","INTEL-SA-00334","INTEL-SA-00477"]}]}"#
		);
		assert_eq!(signature, "47accba321e57c20722a0d3d1db11c9b52661239857dc578ca1bde13976ee288cf39f72111ffe445c7389ef56447c79e30e6b83a8863ed9880de5bde4a8d5c91");
	}

	#[test]
	fn separate_json_data_and_signature_tcb_info() {
		let json = include_bytes!("../test/dcap/tcb_info.json");
		let (data, signature) = separate_json_data_and_signature("tcbInfo", json).unwrap();
		assert_eq!(
			data,
			r#"{"id":"SGX","version":3,"issueDate":"2022-11-17T12:45:32Z","nextUpdate":"2023-04-16T12:45:32Z","fmspc":"00906EA10000","pceId":"0000","tcbType":0,"tcbEvaluationDataNumber":12,"tcbLevels":[{"tcb":{"sgxtcbcomponents":[{"svn":17},{"svn":17},{"svn":2},{"svn":4},{"svn":1},{"svn":128},{"svn":7},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0}],"pcesvn":11},"tcbDate":"2021-11-10T00:00:00Z","tcbStatus":"SWHardeningNeeded","advisoryIDs":["INTEL-SA-00334"]},{"tcb":{"sgxtcbcomponents":[{"svn":17},{"svn":17},{"svn":2},{"svn":4},{"svn":1},{"svn":128},{"svn":7},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0}],"pcesvn":10},"tcbDate":"2020-11-11T00:00:00Z","tcbStatus":"OutOfDate","advisoryIDs":["INTEL-SA-00161","INTEL-SA-00219","INTEL-SA-00289","INTEL-SA-00334"]},{"tcb":{"sgxtcbcomponents":[{"svn":17},{"svn":17},{"svn":2},{"svn":4},{"svn":1},{"svn":128},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0}],"pcesvn":11},"tcbDate":"2021-11-10T00:00:00Z","tcbStatus":"ConfigurationAndSWHardeningNeeded","advisoryIDs":["INTEL-SA-00161","INTEL-SA-00219","INTEL-SA-00289","INTEL-SA-00334"]},{"tcb":{"sgxtcbcomponents":[{"svn":17},{"svn":17},{"svn":2},{"svn":4},{"svn":1},{"svn":128},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0}],"pcesvn":10},"tcbDate":"2020-11-11T00:00:00Z","tcbStatus":"OutOfDateConfigurationNeeded","advisoryIDs":["INTEL-SA-00477","INTEL-SA-00161","INTEL-SA-00219","INTEL-SA-00289","INTEL-SA-00334"]},{"tcb":{"sgxtcbcomponents":[{"svn":15},{"svn":15},{"svn":2},{"svn":4},{"svn":1},{"svn":128},{"svn":7},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0}],"pcesvn":10},"tcbDate":"2020-06-10T00:00:00Z","tcbStatus":"OutOfDate","advisoryIDs":["INTEL-SA-00381","INTEL-SA-00389","INTEL-SA-00477","INTEL-SA-00161","INTEL-SA-00219","INTEL-SA-00289","INTEL-SA-00334"]},{"tcb":{"sgxtcbcomponents":[{"svn":15},{"svn":15},{"svn":2},{"svn":4},{"svn":1},{"svn":128},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0}],"pcesvn":10},"tcbDate":"2020-06-10T00:00:00Z","tcbStatus":"OutOfDateConfigurationNeeded","advisoryIDs":["INTEL-SA-00161","INTEL-SA-00219","INTEL-SA-00289","INTEL-SA-00381","INTEL-SA-00389","INTEL-SA-00477","INTEL-SA-00334"]},{"tcb":{"sgxtcbcomponents":[{"svn":14},{"svn":14},{"svn":2},{"svn":4},{"svn":1},{"svn":128},{"svn":7},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0}],"pcesvn":10},"tcbDate":"2019-12-11T00:00:00Z","tcbStatus":"OutOfDate","advisoryIDs":["INTEL-SA-00320","INTEL-SA-00329","INTEL-SA-00161","INTEL-SA-00219","INTEL-SA-00289","INTEL-SA-00381","INTEL-SA-00389","INTEL-SA-00477","INTEL-SA-00334"]},{"tcb":{"sgxtcbcomponents":[{"svn":14},{"svn":14},{"svn":2},{"svn":4},{"svn":1},{"svn":128},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0}],"pcesvn":10},"tcbDate":"2019-12-11T00:00:00Z","tcbStatus":"OutOfDateConfigurationNeeded","advisoryIDs":["INTEL-SA-00161","INTEL-SA-00219","INTEL-SA-00289","INTEL-SA-00320","INTEL-SA-00329","INTEL-SA-00381","INTEL-SA-00389","INTEL-SA-00477","INTEL-SA-00334"]},{"tcb":{"sgxtcbcomponents":[{"svn":13},{"svn":13},{"svn":2},{"svn":4},{"svn":1},{"svn":128},{"svn":3},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0}],"pcesvn":9},"tcbDate":"2019-11-13T00:00:00Z","tcbStatus":"OutOfDate","advisoryIDs":["INTEL-SA-00161","INTEL-SA-00219","INTEL-SA-00289","INTEL-SA-00320","INTEL-SA-00329","INTEL-SA-00381","INTEL-SA-00389","INTEL-SA-00477","INTEL-SA-00334"]},{"tcb":{"sgxtcbcomponents":[{"svn":13},{"svn":13},{"svn":2},{"svn":4},{"svn":1},{"svn":128},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0}],"pcesvn":9},"tcbDate":"2019-11-13T00:00:00Z","tcbStatus":"OutOfDateConfigurationNeeded","advisoryIDs":["INTEL-SA-00161","INTEL-SA-00219","INTEL-SA-00289","INTEL-SA-00320","INTEL-SA-00329","INTEL-SA-00381","INTEL-SA-00389","INTEL-SA-00477","INTEL-SA-00334"]},{"tcb":{"sgxtcbcomponents":[{"svn":6},{"svn":6},{"svn":2},{"svn":4},{"svn":1},{"svn":128},{"svn":1},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0}],"pcesvn":7},"tcbDate":"2019-05-15T00:00:00Z","tcbStatus":"OutOfDate","advisoryIDs":["INTEL-SA-00220","INTEL-SA-00270","INTEL-SA-00293","INTEL-SA-00161","INTEL-SA-00219","INTEL-SA-00289","INTEL-SA-00320","INTEL-SA-00329","INTEL-SA-00381","INTEL-SA-00389","INTEL-SA-00477","INTEL-SA-00334"]},{"tcb":{"sgxtcbcomponents":[{"svn":6},{"svn":6},{"svn":2},{"svn":4},{"svn":1},{"svn":128},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0}],"pcesvn":7},"tcbDate":"2019-05-15T00:00:00Z","tcbStatus":"OutOfDateConfigurationNeeded","advisoryIDs":["INTEL-SA-00161","INTEL-SA-00220","INTEL-SA-00270","INTEL-SA-00293","INTEL-SA-00219","INTEL-SA-00289","INTEL-SA-00320","INTEL-SA-00329","INTEL-SA-00381","INTEL-SA-00389","INTEL-SA-00477","INTEL-SA-00334"]},{"tcb":{"sgxtcbcomponents":[{"svn":5},{"svn":5},{"svn":2},{"svn":4},{"svn":1},{"svn":128},{"svn":1},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0}],"pcesvn":7},"tcbDate":"2019-01-09T00:00:00Z","tcbStatus":"OutOfDate","advisoryIDs":["INTEL-SA-00233","INTEL-SA-00161","INTEL-SA-00220","INTEL-SA-00270","INTEL-SA-00293","INTEL-SA-00219","INTEL-SA-00289","INTEL-SA-00320","INTEL-SA-00329","INTEL-SA-00381","INTEL-SA-00389","INTEL-SA-00477","INTEL-SA-00334"]},{"tcb":{"sgxtcbcomponents":[{"svn":5},{"svn":5},{"svn":2},{"svn":4},{"svn":1},{"svn":128},{"svn":1},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0}],"pcesvn":6},"tcbDate":"2018-08-15T00:00:00Z","tcbStatus":"OutOfDate","advisoryIDs":["INTEL-SA-00161","INTEL-SA-00233","INTEL-SA-00220","INTEL-SA-00270","INTEL-SA-00293","INTEL-SA-00219","INTEL-SA-00289","INTEL-SA-00320","INTEL-SA-00329","INTEL-SA-00381","INTEL-SA-00389","INTEL-SA-00477","INTEL-SA-00334"]},{"tcb":{"sgxtcbcomponents":[{"svn":5},{"svn":5},{"svn":2},{"svn":4},{"svn":1},{"svn":128},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0}],"pcesvn":7},"tcbDate":"2019-01-09T00:00:00Z","tcbStatus":"OutOfDateConfigurationNeeded","advisoryIDs":["INTEL-SA-00161","INTEL-SA-00233","INTEL-SA-00220","INTEL-SA-00270","INTEL-SA-00293","INTEL-SA-00219","INTEL-SA-00289","INTEL-SA-00320","INTEL-SA-00329","INTEL-SA-00381","INTEL-SA-00389","INTEL-SA-00477","INTEL-SA-00334"]},{"tcb":{"sgxtcbcomponents":[{"svn":5},{"svn":5},{"svn":2},{"svn":4},{"svn":1},{"svn":128},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0}],"pcesvn":6},"tcbDate":"2018-08-15T00:00:00Z","tcbStatus":"OutOfDateConfigurationNeeded","advisoryIDs":["INTEL-SA-00203","INTEL-SA-00161","INTEL-SA-00233","INTEL-SA-00220","INTEL-SA-00270","INTEL-SA-00293","INTEL-SA-00219","INTEL-SA-00289","INTEL-SA-00320","INTEL-SA-00329","INTEL-SA-00381","INTEL-SA-00389","INTEL-SA-00477","INTEL-SA-00334"]},{"tcb":{"sgxtcbcomponents":[{"svn":4},{"svn":4},{"svn":2},{"svn":4},{"svn":1},{"svn":128},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0}],"pcesvn":5},"tcbDate":"2018-01-04T00:00:00Z","tcbStatus":"OutOfDate","advisoryIDs":["INTEL-SA-00106","INTEL-SA-00115","INTEL-SA-00135","INTEL-SA-00203","INTEL-SA-00161","INTEL-SA-00233","INTEL-SA-00220","INTEL-SA-00270","INTEL-SA-00293","INTEL-SA-00219","INTEL-SA-00289","INTEL-SA-00320","INTEL-SA-00329","INTEL-SA-00381","INTEL-SA-00389","INTEL-SA-00477","INTEL-SA-00334"]},{"tcb":{"sgxtcbcomponents":[{"svn":2},{"svn":2},{"svn":2},{"svn":4},{"svn":1},{"svn":128},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0}],"pcesvn":4},"tcbDate":"2017-07-26T00:00:00Z","tcbStatus":"OutOfDate","advisoryIDs":["INTEL-SA-00088","INTEL-SA-00106","INTEL-SA-00115","INTEL-SA-00135","INTEL-SA-00203","INTEL-SA-00161","INTEL-SA-00233","INTEL-SA-00220","INTEL-SA-00270","INTEL-SA-00293","INTEL-SA-00219","INTEL-SA-00289","INTEL-SA-00320","INTEL-SA-00329","INTEL-SA-00381","INTEL-SA-00389","INTEL-SA-00477","INTEL-SA-00334"]}]}"#
		);
		assert_eq!(signature, "71746f2148ecba04e35cf1ac77a7e6267ce99f6781c1031f724bb5bd94b8c1b6e4c07c01dc151692aa75be80dfba7350bb80c58314a6975189597e28e9bbc75c");
	}

	#[test]
	fn tcb_level_is_valid() {
		let t: TcbLevel = serde_json::from_str(
			r#"{"tcb":{"isvsvn":6}, "tcbDate":"2021-11-10T00:00:00Z", "tcbStatus":"UpToDate" }"#,
		)
		.unwrap();
		assert!(t.is_valid());

		let t: TcbLevel = serde_json::from_str(
			r#"{"tcb":{"isvsvn":6}, "tcbDate":"2021-11-10T00:00:00Z", "tcbStatus":"OutOfDate" }"#,
		)
		.unwrap();
		assert!(!t.is_valid());

		let t: TcbLevel = serde_json::from_str(
			r#"{"tcb":{"isvsvn":5}, "tcbDate":"2021-11-10T00:00:00Z", "tcbStatus":"UpToDate" }"#,
		)
		.unwrap();
		assert!(!t.is_valid());
	}

	#[test]
	fn tcb_full_is_valid() {
		let reference = r#"{"sgxtcbcomponents":[{"svn":5},{"svn":5},{"svn":2},{"svn":4},{"svn":1},{"svn":128},{"svn":1},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0}],"pcesvn":7}"#;
		let reference: TcbFull = serde_json::from_str(reference).unwrap();

		let invalid_pcesvn = r#"{"sgxtcbcomponents":[{"svn":5},{"svn":5},{"svn":2},{"svn":4},{"svn":1},{"svn":128},{"svn":1},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0}],"pcesvn":6}"#;
		let invalid_pcesvn: TcbFull = serde_json::from_str(invalid_pcesvn).unwrap();
		assert!(!invalid_pcesvn.is_valid(&reference));

		let invalid_component = r#"{"sgxtcbcomponents":[{"svn":5},{"svn":5},{"svn":2},{"svn":4},{"svn":1},{"svn":127},{"svn":1},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0}],"pcesvn":7}"#;
		let invalid_component: TcbFull = serde_json::from_str(invalid_component).unwrap();
		assert!(!invalid_component.is_valid(&reference));

		let missing_component = r#"{"sgxtcbcomponents":[{"svn":5},{"svn":5},{"svn":2},{"svn":4},{"svn":1},{"svn":128},{"svn":1},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0}],"pcesvn":7}"#;
		let missing_component: Result<TcbFull, serde_json::Error> =
			serde_json::from_str(missing_component);
		assert!(missing_component.is_err());
	}
}
