//! A implementation of the SPARX block cipher for Rust.
//!
//! See <https://www.cryptolux.org/index.php/SPARX> for more information about SPARX.

#![allow(clippy::erasing_op)]
#![allow(clippy::identity_op)]

#![cfg_attr(not(test), no_std)]

pub mod sparx128;
pub mod sparx64;
