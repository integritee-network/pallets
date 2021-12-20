//!Primitives for teeracle
#![cfg_attr(not(feature = "std"), no_std)]
use sp_std::prelude::*;
use substrate_fixed::types::U32F32;

pub type ExchangeRate = U32F32;
pub type CurrencyString = Vec<u8>;
pub type MarketDataSourceString = Vec<u8>;
