use crate::{Config, Pallet, TcbInfo};
use frame_support::assert_ok;
use frame_system::RawOrigin;
use hex_literal::hex;
use sgx_verify::test_data::dcap::{
	QE_IDENTITY_ISSUER_CHAIN, QUOTING_ENCLAVE, QUOTING_ENCLAVE_SIGNATURE, TCB_INFO,
	TCB_INFO_CERTIFICATE_CHAIN, TCB_INFO_SIGNATURE,
};
use teerex_primitives::TcbInfoOnChain;

/// Registers a predefined quoting enclave.
///
/// This can be done by any account.
pub fn register_quoting_enclave<T>(account: T::AccountId)
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
pub fn get_test_tcb_info<T>() -> TcbInfoOnChain
where
	T: Config,
	<T as frame_system::Config>::Hash: From<[u8; 32]>,
{
	let fmspc = hex!("00906EA10000");
	TcbInfo::<T>::get(fmspc)
}
