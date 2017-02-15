#![cfg_attr(feature="clippy", feature(plugin))]
#![cfg_attr(feature="clippy", plugin(clippy))]
#![cfg_attr(not(test), no_std)]

extern crate byteorder;
#[cfg(test)]
extern crate core;

pub mod sparx64;
