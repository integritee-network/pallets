use super::*;

use frame_support::{pallet_prelude::*, storage_alias, traits::OnRuntimeUpgrade};

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
	/// The log target.
	const TARGET: &str = "teerex::migration::v1";

	#[derive(
		Encode, Decode, Default, Copy, Clone, PartialEq, Eq, sp_core::RuntimeDebug, TypeInfo,
	)]
	pub struct SgxTcbInfoOnChainV1 {
		pub issue_date: u64,
		pub next_update: u64,
	}

	#[storage_alias]
	pub type SgxTcbInfo<T: Config> =
		StorageMap<Pallet<T>, Blake2_128Concat, Fmspc, SgxTcbInfoOnChainV1, OptionQuery>;

	pub struct MigrateV0toV1<T>(sp_std::marker::PhantomData<T>);

	impl<T: Config + frame_system::Config> OnRuntimeUpgrade for MigrateV0toV1<T> {
		#[cfg(feature = "try-runtime")]
		fn pre_upgrade() -> Result<Vec<u8>, sp_runtime::DispatchError> {
			let onchain_version = Pallet::<T>::on_chain_storage_version();

			let enclave_count = v0::EnclaveCount::<T>::get() as u64;
			log::info!(
				target: TARGET,
				"teerexV1: {} v0 enclaves are present before eventual upgrade",
				enclave_count,
			);

			let allow_debug_mode = v0::AllowSGXDebugMode::<T>::get();
			log::info!(
				target: TARGET,
				"teerexV1: SGX debug mode (v0) was allowed pre_upgrade: {}",
				allow_debug_mode
			);
			Ok((onchain_version, enclave_count, allow_debug_mode).encode())
		}

		/// we simply purge the enclave registry as it renews within 24h anyway
		fn on_runtime_upgrade() -> Weight {
			let current_version = StorageVersion::new(1);
			let onchain_version = Pallet::<T>::on_chain_storage_version();

			log::info!(
				target: TARGET,
				"teerexV1: Running migration with current storage version {:?} / onchain {:?}",
				current_version,
				onchain_version
			);

			let mut purged_keys = 0u64;
			if onchain_version >= current_version {
				log::warn!(target: TARGET,"teerexV1: skipping on_runtime_upgrade: executed on same or newer storage version."
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
		fn post_upgrade(state: Vec<u8>) -> Result<(), sp_runtime::DispatchError> {
			let (pre_onchain_version, _enclave_count, allow_debug_mode): (
				StorageVersion,
				u64,
				bool,
			) = Decode::decode(&mut &state[..]).expect("pre_upgrade provides a valid state; qed");
			let post_onchain_version = Pallet::<T>::on_chain_storage_version();
			if pre_onchain_version >= post_onchain_version {
				log::info!(target: TARGET,"teerexV1: migration was skipped because onchain version was greater or equal to the target version of this migration step");
				return Ok(())
			}

			assert_eq!(Pallet::<T>::on_chain_storage_version(), 1, "must upgrade");
			let new_enclave_count = v0::EnclaveCount::<T>::get() as u64;
			let new_allow_debug_mode = crate::SgxAllowDebugMode::<T>::get() as bool;

			assert_eq!(new_enclave_count, 0, "must purge all enclaves");
			assert_eq!(new_allow_debug_mode, allow_debug_mode, "must keep debug mode setting");
			Ok(())
		}
	}
}

pub mod v2 {
	use super::*;
	/// The log target.
	const TARGET: &str = "teerex::migration::v2";

	pub struct MigrateV1toV2<T>(sp_std::marker::PhantomData<T>);

	impl<T: Config + frame_system::Config> OnRuntimeUpgrade for MigrateV1toV2<T> {
		#[cfg(feature = "try-runtime")]
		fn pre_upgrade() -> Result<Vec<u8>, &'static str> {
			let current_version = Pallet::<T>::current_storage_version();
			let onchain_version = Pallet::<T>::on_chain_storage_version();
			ensure!(onchain_version == 1 && current_version == 2, "only migration from v1 to v2");

			let tcb_info_count = v1::SgxTcbInfo::<T>::iter_keys().count() as u64;
			log::info!(
				target: TARGET,
				"teerexV2: TCB info for {} fmspc entries will be purged",
				tcb_info_count
			);
			Ok((tcb_info_count).encode())
		}

		/// we simply purge the enclave registry as it renews within 24h anyway
		fn on_runtime_upgrade() -> Weight {
			let current_version = Pallet::<T>::current_storage_version();
			let onchain_version = Pallet::<T>::on_chain_storage_version();

			log::info!(
				target: TARGET,
				"teerexV2: Running migration with current storage version {:?} / onchain {:?}",
				current_version,
				onchain_version
			);

			let mut purged_keys = 0u64;
			if onchain_version >= current_version {
				log::warn!(
					target: TARGET,
					"teerexV2: skipping on_runtime_upgrade: executed on wrong storage version."
				);
				return T::DbWeight::get().reads(1)
			}

			purged_keys += v1::SgxTcbInfo::<T>::clear(u32::MAX, None).unique as u64;

			StorageVersion::new(2).put::<Pallet<T>>();
			T::DbWeight::get().reads_writes(purged_keys + 1, purged_keys + 3)
		}

		#[cfg(feature = "try-runtime")]
		fn post_upgrade(state: Vec<u8>) -> Result<(), &'static str> {
			assert_eq!(Pallet::<T>::on_chain_storage_version(), 2, "must upgrade");

			let _: u64 =
				Decode::decode(&mut &state[..]).expect("pre_upgrade provides a valid state; qed");
			let new_tcb_info_count = v1::SgxTcbInfo::<T>::iter_keys().count() as u64;

			assert_eq!(new_tcb_info_count, 0, "must purge all TCB info entries");
			Ok(())
		}
	}
}

#[cfg(test)]
#[cfg(feature = "try-runtime")]
mod test {
	use super::*;
	use crate::migrations::{v0::EnclaveV0, v1::SgxTcbInfoOnChainV1};
	use frame_support::{assert_storage_noop, traits::OnRuntimeUpgrade};
	use mock::{new_test_ext, Test as TestRuntime};

	#[allow(deprecated)]
	#[test]
	fn migration_v0_to_v2_works() {
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

			// Migrate V0 to V1.
			let state = v1::MigrateV0toV1::<TestRuntime>::pre_upgrade().unwrap();
			let _weight = v1::MigrateV0toV1::<TestRuntime>::on_runtime_upgrade();
			v1::MigrateV0toV1::<TestRuntime>::post_upgrade(state).unwrap();
			// Migrate V1 to V2
			let state = v2::MigrateV1toV2::<TestRuntime>::pre_upgrade().unwrap();
			let _weight = v2::MigrateV1toV2::<TestRuntime>::on_runtime_upgrade();
			v2::MigrateV1toV2::<TestRuntime>::post_upgrade(state).unwrap();

			// Check that all values got migrated.
			assert_eq!(v0::EnclaveCount::<TestRuntime>::get(), 0);
			assert_eq!(crate::SgxAllowDebugMode::<TestRuntime>::get(), true);
			assert_eq!(v0::EnclaveRegistry::<TestRuntime>::iter_keys().count(), 0);
			assert_eq!(v0::EnclaveIndex::<TestRuntime>::iter_keys().count(), 0);
			assert_eq!(v0::AllowSGXDebugMode::<TestRuntime>::get(), false);
		});
	}

	#[allow(deprecated)]
	#[test]
	fn migration_v1_to_v2_works() {
		new_test_ext().execute_with(|| {
			StorageVersion::new(1).put::<Pallet<TestRuntime>>();
			assert_eq!(Pallet::<TestRuntime>::on_chain_storage_version(), 1);

			// Insert some values into the v1 storage:
			v1::SgxTcbInfo::<TestRuntime>::insert(Fmspc::default(), SgxTcbInfoOnChainV1::default());

			// Migrate.
			let state = v2::MigrateV1toV2::<TestRuntime>::pre_upgrade().unwrap();
			let _weight = v2::MigrateV1toV2::<TestRuntime>::on_runtime_upgrade();
			v2::MigrateV1toV2::<TestRuntime>::post_upgrade(state).unwrap();

			// Check that all values got migrated.
			assert_eq!(v1::SgxTcbInfo::<TestRuntime>::iter_keys().count(), 0);
		});
	}
	#[allow(deprecated)]
	#[test]
	fn migration_v1_to_v1_is_noop() {
		new_test_ext().execute_with(|| {
			StorageVersion::new(1).put::<Pallet<TestRuntime>>();

			// Insert some values into the v1 storage:
			v1::SgxTcbInfo::<TestRuntime>::insert(Fmspc::default(), SgxTcbInfoOnChainV1::default());
			// introduce outdated stuff that would be migrated if the migration would not be a noop
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

			let state = v1::MigrateV0toV1::<TestRuntime>::pre_upgrade().unwrap();
			assert_storage_noop!(v1::MigrateV0toV1::<TestRuntime>::on_runtime_upgrade());
			v1::MigrateV0toV1::<TestRuntime>::post_upgrade(state).unwrap();
		});
	}
}
