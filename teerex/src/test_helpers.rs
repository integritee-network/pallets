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

use crate::{Config, Pallet, SgxTcbInfo};
use frame_support::assert_ok;
use frame_system::RawOrigin;
use sgx_verify::test_data::dcap::{
	QE_IDENTITY_ISSUER_CHAIN, QUOTING_ENCLAVE, QUOTING_ENCLAVE_SIGNATURE, TCB_INFO,
	TCB_INFO_CERTIFICATE_CHAIN, TCB_INFO_FMSPC, TCB_INFO_SIGNATURE,
};
use teerex_primitives::SgxTcbInfoOnChain;

/// Registers a predefined quoting enclave.
///
/// This can be done by any account.
pub fn register_test_quoting_enclave<T>(account: T::AccountId)
where
	T: Config,
	<T as frame_system::Config>::Hash: From<[u8; 32]>,
{
	let quoting_enclave = QUOTING_ENCLAVE;
	let signature = QUOTING_ENCLAVE_SIGNATURE;
	let certificate_chain = QE_IDENTITY_ISSUER_CHAIN;

	assert_ok!(Pallet::<T>::register_quoting_enclave(
		RawOrigin::Signed(account).into(),
		quoting_enclave.to_vec(),
		signature.to_vec(),
		certificate_chain.to_vec(),
	));
}

/// Registers a predefined TCB-Info.
///
/// This can be done by any account.
pub fn register_test_tcb_info<T>(account: T::AccountId)
where
	T: Config,
	<T as frame_system::Config>::Hash: From<[u8; 32]>,
{
	let tcb_info = TCB_INFO;
	let signature = TCB_INFO_SIGNATURE;
	let certificate_chain = TCB_INFO_CERTIFICATE_CHAIN;

	assert_ok!(Pallet::<T>::register_tcb_info(
		RawOrigin::Signed(account).into(),
		tcb_info.to_vec(),
		signature.to_vec(),
		certificate_chain.to_vec(),
	));
}

/// Gets the above tcb info.
pub fn get_test_tcb_info<T>() -> SgxTcbInfoOnChain
where
	T: Config,
	<T as frame_system::Config>::Hash: From<[u8; 32]>,
{
	SgxTcbInfo::<T>::get(TCB_INFO_FMSPC).unwrap()
}
