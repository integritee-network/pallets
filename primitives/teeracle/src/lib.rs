//!Primitives for teeracle
#![cfg_attr(not(feature = "std"), no_std)]
use common_primitives::PalletString;
use sp_std::prelude::*;
use substrate_fixed::types::U32F32;

pub type ExchangeRate = U32F32;
pub type TradingPairString = PalletString;
pub type MarketDataSourceString = PalletString;
