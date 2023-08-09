use super::*;

use frame_support::{pallet_prelude::*, storage_alias, traits::OnRuntimeUpgrade};

/// The log target.
const TARGET: &str = "teerex::migration::v1";

mod v0 {
	use super::*;

	#[derive(
		Encode, Decode, Default, Copy, Clone, PartialEq, Eq, sp_core::RuntimeDebug, TypeInfo,
	)]
	pub struct EnclaveV0<PubKey, Url> {
		pub pubkey: PubKey,
		pub mr_enclave: MrEnclave,
		pub timestamp: u64, // unix epoch in milliseconds
		pub url: Url,       // utf8 encoded url
		pub sgx_mode: SgxBuildMode,
	}

	#[storage_alias]
	pub(super) type EnclaveRegistry<T: Config> =
		StorageMap<Pallet<T>, Blake2_128Concat, u64, EnclaveV0<AccountId<T>, Vec<u8>>, OptionQuery>;

	#[storage_alias]
	pub(super) type EnclaveCount<T: Config> = StorageValue<Pallet<T>, u64, ValueQuery>;

	#[storage_alias]
	pub(super) type EnclaveIndex<T: Config> =
		StorageMap<Pallet<T>, Blake2_128Concat, AccountId<T>, u64, ValueQuery>;

	#[storage_alias]
	pub(super) type AllowSGXDebugMode<T: Config> = StorageValue<Pallet<T>, bool, ValueQuery>;
}

pub mod v1 {
	use super::*;

	pub struct MigrateV0toV1<T>(sp_std::marker::PhantomData<T>);

	impl<T: Config + frame_system::Config> OnRuntimeUpgrade for MigrateV0toV1<T> {
		#[cfg(feature = "try-runtime")]
		fn pre_upgrade() -> Result<Vec<u8>, &'static str> {
			let current_version = Pallet::<T>::current_storage_version();
			let onchain_version = Pallet::<T>::on_chain_storage_version();
			ensure!(onchain_version == 0 && current_version == 1, "only migration from v0 to v1");

			let enclave_count = v0::EnclaveCount::<T>::get() as u64;
			log::info!(target: TARGET, "{} enclaves will be purged", enclave_count,);

			let allow_debug_mode = v0::AllowSGXDebugMode::<T>::get();
			log::info!(target: TARGET, "SGX debug mode was allowed: {}", allow_debug_mode);
			Ok((enclave_count, allow_debug_mode).encode())
		}

		/// we simply purge the enclave registry as it renews within 24h anyway
		fn on_runtime_upgrade() -> Weight {
			let current_version = Pallet::<T>::current_storage_version();
			let onchain_version = Pallet::<T>::on_chain_storage_version();

			log::info!(
				target: TARGET,
				"Running migration with current storage version {:?} / onchain {:?}",
				current_version,
				onchain_version
			);

			let mut purged_keys = 0u64;
			if onchain_version >= current_version {
				log::warn!(
					target: TARGET,
					"skipping on_runtime_upgrade: executed on wrong storage version."
				);
				return T::DbWeight::get().reads(1)
			}

			let allow_debug_mode = v0::AllowSGXDebugMode::<T>::get();
			v0::AllowSGXDebugMode::<T>::kill();
			crate::SgxAllowDebugMode::<T>::put(allow_debug_mode);

			v0::EnclaveCount::<T>::kill();
			purged_keys += v0::EnclaveRegistry::<T>::clear(u32::MAX, None).unique as u64;
			purged_keys += v0::EnclaveIndex::<T>::clear(u32::MAX, None).unique as u64;

			StorageVersion::new(1).put::<Pallet<T>>();
			T::DbWeight::get().reads_writes(purged_keys + 1, purged_keys + 3)
		}

		#[cfg(feature = "try-runtime")]
		fn post_upgrade(state: Vec<u8>) -> Result<(), &'static str> {
			assert_eq!(Pallet::<T>::on_chain_storage_version(), 1, "must upgrade");

			let (_enclave_count, allow_debug_mode): (u64, bool) =
				Decode::decode(&mut &state[..]).expect("pre_upgrade provides a valid state; qed");
			let new_enclave_count = v0::EnclaveCount::<T>::get() as u64;
			let new_allow_debug_mode = crate::SgxAllowDebugMode::<T>::get() as bool;

			assert_eq!(new_enclave_count, 0, "must purge all enclaves");
			assert_eq!(new_allow_debug_mode, allow_debug_mode, "must keep debug mode setting");
			Ok(())
		}
	}
}

#[cfg(test)]
#[cfg(feature = "try-runtime")]
mod test {
	use super::*;
	use crate::migrations::v0::EnclaveV0;
	use frame_support::traits::OnRuntimeUpgrade;
	use mock::{new_test_ext, Test as TestRuntime};

	#[allow(deprecated)]
	#[test]
	fn migration_v0_to_v1_works() {
		new_test_ext().execute_with(|| {
			StorageVersion::new(0).put::<Pallet<TestRuntime>>();

			// Insert some values into the v0 storage:

			v0::EnclaveRegistry::<TestRuntime>::insert(
				0,
				EnclaveV0 {
					pubkey: [0u8; 32].into(),
					mr_enclave: MrEnclave::default(),
					timestamp: 0,
					url: "".into(),
					sgx_mode: SgxBuildMode::default(),
				},
			);
			v0::EnclaveIndex::<TestRuntime>::insert(AccountId::<TestRuntime>::from([0u8; 32]), 0);
			v0::EnclaveCount::<TestRuntime>::put(1);
			v0::AllowSGXDebugMode::<TestRuntime>::put(true);

			// Migrate.
			let state = v1::MigrateV0toV1::<TestRuntime>::pre_upgrade().unwrap();
			let _weight = v1::MigrateV0toV1::<TestRuntime>::on_runtime_upgrade();
			v1::MigrateV0toV1::<TestRuntime>::post_upgrade(state).unwrap();

			// Check that all values got migrated.

			assert_eq!(v0::EnclaveCount::<TestRuntime>::get(), 0);
			assert_eq!(crate::SgxAllowDebugMode::<TestRuntime>::get(), true);
			assert_eq!(v0::EnclaveRegistry::<TestRuntime>::iter_keys().count(), 0);
			assert_eq!(v0::EnclaveIndex::<TestRuntime>::iter_keys().count(), 0);
			assert_eq!(v0::AllowSGXDebugMode::<TestRuntime>::get(), false);
		});
	}
}
