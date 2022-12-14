#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

#[frame_support::pallet]
pub mod pallet {
	use cumulus_primitives_core::ParaId;
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;
	use xcm::latest::prelude::*;
	use xcm_transactor_primitives::*;

	#[pallet::pallet]
	#[pallet::generate_store(pub(super) trait Store)]
	#[pallet::without_storage_info]
	pub struct Pallet<T>(PhantomData<T>);

	#[pallet::config]
	pub trait Config: frame_system::Config {
		type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

		type RelayCallBuilder: BuildRelayCall;

		type XcmSender: SendXcm;

		#[pallet::constant]
		type ShellRuntimeParaId: Get<ParaId>;

		#[pallet::constant]
		type IntegriteeKsmParaId: Get<ParaId>;
	}

	#[pallet::event]
	pub enum Event<T: Config> {
		TransactSent,
	}

	#[pallet::error]
	pub enum Error<T> {
		TransactFailed,
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		#[pallet::weight(0)]
		pub fn send_swap_ump(origin: OriginFor<T>) -> DispatchResult {
			ensure_root(origin)?;
			Ok(())
		}
	}
}
