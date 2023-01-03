#![no_main]

use codec::{Decode, Encode};
use libfuzzer_sys::fuzz_target;
use sgx_verify::DcapQuote;

fuzz_target!(|data: &[u8]| {
	let mut copy = data;
	let quote: Result<DcapQuote, codec::Error> = Decode::decode(&mut copy);
	//assert!(quote.is_err());
});
