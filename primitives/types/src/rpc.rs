/*
	Copyright 2021 Integritee AG and Supercomputing Systems AG

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

extern crate alloc;

use crate::DirectRequestStatus;
use alloc::{borrow::ToOwned, string::String, vec::Vec};
use codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

#[derive(Encode, Decode, Debug)]
pub struct RpcReturnValue {
	pub value: Vec<u8>,
	pub do_watch: bool,
	pub status: DirectRequestStatus,
	//pub signature: Signature,
}
impl RpcReturnValue {
	pub fn new(val: Vec<u8>, watch: bool, status: DirectRequestStatus) -> Self {
		Self {
			value: val,
			do_watch: watch,
			status,
			//signature: sign,
		}
	}

	pub fn from_error_message(error_msg: &str) -> Self {
		RpcReturnValue {
			value: error_msg.encode(),
			do_watch: false,
			status: DirectRequestStatus::Error,
		}
	}
}

#[derive(Clone, Encode, Decode, Debug, Serialize, Deserialize)]
pub struct RpcResponse {
	pub jsonrpc: String,
	pub result: String, // hex encoded RpcReturnValue
	pub id: u32,
}

#[derive(Clone, Encode, Decode, Serialize, Deserialize)]
pub struct RpcRequest {
	pub jsonrpc: String,
	pub method: String,
	pub params: Vec<String>,
	pub id: i32,
}

impl RpcRequest {
	pub fn compose_jsonrpc_call(
		method: String,
		params: Vec<String>,
	) -> Result<String, serde_json::Error> {
		serde_json::to_string(&RpcRequest { jsonrpc: "2.0".to_owned(), method, params, id: 1 })
	}
}
