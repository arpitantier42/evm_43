// Copyright 2017-2022 Parity Technologies (UK) Ltd.
// This file is part of vine.

// vine is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// vine is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with vine.  If not, see <http://www.gnu.org/licenses/>.
//! Autogenerated weights for `pallet_indices`
//!
//! THIS FILE WAS AUTO-GENERATED USING THE SUBSTRATE BENCHMARK CLI VERSION 4.0.0-dev
//! DATE: 2022-12-15, STEPS: `50`, REPEAT: 20, LOW RANGE: `[]`, HIGH RANGE: `[]`
//! HOSTNAME: `bm6`, CPU: `Intel(R) Core(TM) i7-7700K CPU @ 4.20GHz`
//! EXECUTION: Some(Wasm), WASM-EXECUTION: Compiled, CHAIN: Some("vine-dev"), DB CACHE: 1024

// Executed Command:
// ./target/production/vine
// benchmark
// pallet
// --chain=vine-dev
// --steps=50
// --repeat=20
// --pallet=pallet_indices
// --extrinsic=*
// --execution=wasm
// --wasm-execution=compiled
// --header=./file_header.txt
// --output=./runtime/vine/src/weights/

#![cfg_attr(rustfmt, rustfmt_skip)]
#![allow(unused_parens)]
#![allow(unused_imports)]

use frame_support::{traits::Get, weights::Weight};
use sp_std::marker::PhantomData;

/// Weight functions for `pallet_indices`.
pub struct WeightInfo<T>(PhantomData<T>);
impl<T: frame_system::Config> pallet_indices::WeightInfo for WeightInfo<T> {
	// Storage: Indices Accounts (r:1 w:1)
	fn claim() -> Weight {
		// Minimum execution time: 27_438 nanoseconds.
		Weight::from_ref_time(27_968_000)
			.saturating_add(T::DbWeight::get().reads(1))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	// Storage: Indices Accounts (r:1 w:1)
	// Storage: System Account (r:1 w:1)
	fn transfer() -> Weight {
		// Minimum execution time: 33_878 nanoseconds.
		Weight::from_ref_time(34_231_000)
			.saturating_add(T::DbWeight::get().reads(2))
			.saturating_add(T::DbWeight::get().writes(2))
	}
	// Storage: Indices Accounts (r:1 w:1)
	fn free() -> Weight {
		// Minimum execution time: 28_102 nanoseconds.
		Weight::from_ref_time(28_607_000)
			.saturating_add(T::DbWeight::get().reads(1))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	// Storage: Indices Accounts (r:1 w:1)
	// Storage: System Account (r:1 w:1)
	fn force_transfer() -> Weight {
		// Minimum execution time: 28_602 nanoseconds.
		Weight::from_ref_time(28_983_000)
			.saturating_add(T::DbWeight::get().reads(2))
			.saturating_add(T::DbWeight::get().writes(2))
	}
	// Storage: Indices Accounts (r:1 w:1)
	fn freeze() -> Weight {
		// Minimum execution time: 33_679 nanoseconds.
		Weight::from_ref_time(34_218_000)
			.saturating_add(T::DbWeight::get().reads(1))
			.saturating_add(T::DbWeight::get().writes(1))
	}
}
