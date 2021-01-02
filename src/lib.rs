#![cfg_attr(feature = "bench", feature(test))]
#![allow(unused_imports, unused_variables, dead_code)]

#[allow(unused_imports)]
#[macro_use]
extern crate log;
extern crate rand;
#[allow(unused_imports)]
#[macro_use]
extern crate bitflags;
extern crate punycode;

// extern crate ed25519_dalek;

#[allow(unused_macros)]
#[macro_use]
pub mod macros;

pub mod error;
pub mod wire;
pub mod name;

// pub mod handshake;
