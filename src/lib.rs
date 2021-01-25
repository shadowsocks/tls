#![cfg_attr(feature = "bench", feature(test))]
#![feature(trait_alias, seek_convenience)]
#![allow(unused_imports, unused_variables, dead_code)]


#[allow(unused_imports)]
#[macro_use]
extern crate log;
// NOTE: 后面直接使用 `getrandom` 库来替代，以减少依赖数量和编译时间。
extern crate rand;
extern crate punycode;

#[allow(unused_macros)]
#[macro_use]
pub mod macros;

pub mod buffer;

pub mod serde;

pub mod error;
pub mod repr;
pub mod wire;
pub mod name;

pub mod crypto;
// pub mod random;

mod client;
mod server;

pub use self::client::*;
pub use self::server::*;

pub mod stream;