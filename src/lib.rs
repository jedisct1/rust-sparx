//! A implementation of the SPARX block cipher for Rust.
//!
//! See <https://www.cryptolux.org/index.php/SPARX> for more information about SPARX.

#![cfg_attr(feature = "clippy", feature(plugin))]
#![cfg_attr(feature = "clippy", plugin(clippy))]
#![cfg_attr(feature = "clippy", allow(identity_op))]
#![cfg_attr(not(test), no_std)]

extern crate byteorder;
#[cfg(test)]
extern crate core;

pub mod sparx64;
pub mod sparx128;
