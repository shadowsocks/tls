// https://github.com/cloudflare/boringtun/blob/master/src/crypto/x25519/mod.rs

// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Elliptic-curve Diffie-Hellman exchange over Curve25519.

use rand;

// use crate::noise::errors::WireGuardError;
// use crate::noise::make_array;
// use base64::decode;
use std::ops::Add;
use std::ops::Mul;
use std::ops::Sub;
use std::str::FromStr;


#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct InvalidKey;

impl std::error::Error for InvalidKey { }

impl core::fmt::Display for InvalidKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "InvalidKey")
    }
}



#[inline(always)]
pub fn make_array<A, T>(slice: &[T]) -> A
where
    A: Sized + Default + AsMut<[T]> + std::borrow::Borrow<[T]>,
    T: Copy,
{
    let mut arr: A = Default::default();
    let arr_len = arr.borrow().len();
    <A as AsMut<[T]>>::as_mut(&mut arr).copy_from_slice(&slice[0..arr_len]);
    arr
}


const MASK_63BITS: u128 = 0x7fff_ffff_ffff_ffff;
const MASK_64BITS: u128 = 0xffff_ffff_ffff_ffff;


#[repr(C)]
#[derive(Debug)]
/// A secret X25519 key.
pub struct X25519SecretKey {
    internal: [u8; 32],
}

#[allow(clippy::new_without_default)]
impl X25519SecretKey {
    pub const KEY_LEN: usize = 32;
    
    // /// Generate a new secret key using the OS rng.
    // pub fn new() -> Self {
    //     let mut private_key = [0u8; 32];
    //     rand::Rng::fill(&mut rand::rngs::OsRng, &mut private_key);
    //     X25519SecretKey {
    //         internal: private_key,
    //     }
    // }
    
    pub fn generate<T: rand::Rng + rand::CryptoRng>(csprng: &mut T) -> Self {
        let mut private_key = [0u8; 32];
        rand::Rng::fill(csprng, &mut private_key);

        Self { internal: private_key }
    }

    /// Compute the public key for this secret key.
    pub fn public_key(&self) -> X25519PublicKey {
        X25519PublicKey {
            internal: x25519_public_key(&self.internal[..]),
        }
    }

    /// Derive a shared key from the secret key of this peer and the public key of a remote peer.
    pub fn shared_key(&self, peer_public: &X25519PublicKey) -> Result<[u8; 32], InvalidKey> {
        let shared_key = x25519_shared_key(&peer_public.internal[..], &self.internal[..]);

        constant_time_key_compare(&self.internal[..], &peer_public.internal[..], false)?;
        constant_time_zero_key_check(&shared_key[..])?;

        Ok(shared_key)
    }

    /// Return the private key represented as a byte array.
    pub fn as_bytes(&self) -> &[u8] {
        &self.internal[..]
    }
}

// impl FromStr for X25519SecretKey {
//     type Err = &'static str;

//     /// Can parse a secret key from a hex or base64 encoded string.
//     fn from_str(s: &str) -> Result<Self, Self::Err> {
//         let mut key = X25519SecretKey {
//             internal: [0u8; 32],
//         };

//         match s.len() {
//             64 => {
//                 // Try to parse as hex
//                 for i in 0..32 {
//                     key.internal[i] = u8::from_str_radix(&s[i * 2..=i * 2 + 1], 16)
//                         .map_err(|_| "Illegal character in key")?;
//                 }
//             }
//             43 | 44 => {
//                 // Try to parse as base64
//                 if let Ok(decoded_key) = decode(s) {
//                     if decoded_key.len() == key.internal.len() {
//                         key.internal[..].copy_from_slice(&decoded_key);
//                     } else {
//                         return Err("Illegal character in key");
//                     }
//                 }
//             }
//             _ => return Err("Illegal key size"),
//         }

//         Ok(key)
//     }
// }

impl Drop for X25519SecretKey {
    fn drop(&mut self) {
        // Force zero out of the memory on Drop
        unsafe { std::ptr::write_volatile(&mut self.internal, [0u8; 32]) }
    }
}

#[repr(C)]
#[derive(Debug, PartialEq, Eq, Hash)]
/// A public X25519, derived from a secret key.
pub struct X25519PublicKey {
    internal: [u8; 32],
}

impl X25519PublicKey {
    pub const KEY_LEN: usize = 32;

    // Check if this public key is equal to `other` in constant-time.
    pub fn constant_time_is_equal(&self, other: &X25519PublicKey) -> Result<(), InvalidKey> {
        constant_time_key_compare(&self.internal[..], &other.internal[..], true)
    }

    // Return the public key represented as a byte array.
    pub fn as_bytes(&self) -> &[u8] {
        &self.internal[..]
    }
}

/// Will panic if the slice.len() != 32.
impl<'a> From<&'a [u8]> for X25519PublicKey {
    fn from(slice: &[u8]) -> Self {
        let mut internal = [0u8; 32];
        internal[..].copy_from_slice(slice);
        X25519PublicKey { internal }
    }
}

impl Default for X25519PublicKey {
    fn default() -> Self {
        Self { internal: [0u8; Self::KEY_LEN] }
    }
}

impl Drop for X25519PublicKey {
    fn drop(&mut self) {
        // Force zero out of the memory on Drop
        unsafe { std::ptr::write_volatile(&mut self.internal, [0u8; 32]) }
    }
}

// impl FromStr for X25519PublicKey {
//     type Err = &'static str;
//     fn from_str(s: &str) -> Result<Self, Self::Err> {
//         Ok(X25519PublicKey {
//             internal: X25519SecretKey::from_str(s)?.internal,
//         })
//     }
// }

#[derive(Clone, Copy)]
// Internal structs for fast arithmetic
struct Felem([u64; 4]);
struct Felem2([u64; 8]);

#[cfg_attr(feature = "cargo-clippy", allow(clippy::suspicious_arithmetic_impl))]
impl Add for Felem {
    type Output = Felem;
    #[inline(always)]
    // Addition modulo 2^255 - 19
    fn add(self, other: Felem) -> Felem {
        let x0 = u128::from(self.0[0]);
        let x1 = u128::from(self.0[1]);
        let x2 = u128::from(self.0[2]);
        let x3 = u128::from(self.0[3]);

        let y0 = u128::from(other.0[0]);
        let y1 = u128::from(other.0[1]);
        let y2 = u128::from(other.0[2]);
        let y3 = u128::from(other.0[3]);

        let mut acc0 = x0.wrapping_add(y0);
        let mut acc1 = x1.wrapping_add(y1).wrapping_add(acc0 >> 64);
        let mut acc2 = x2.wrapping_add(y2).wrapping_add(acc1 >> 64);
        let mut acc3 = x3.wrapping_add(y3).wrapping_add(acc2 >> 64);

        let mut top = (acc3 >> 63) & 0xffff_ffff_ffff_ffff;
        acc0 &= 0xffff_ffff_ffff_ffff;
        acc1 &= 0xffff_ffff_ffff_ffff;
        acc2 &= 0xffff_ffff_ffff_ffff;
        acc3 &= 0x7fff_ffff_ffff_ffff;

        top = top.wrapping_mul(19);
        acc0 = acc0.wrapping_add(top);
        acc1 = acc1.wrapping_add(acc0 >> 64);
        acc2 = acc2.wrapping_add(acc1 >> 64);
        acc3 = acc3.wrapping_add(acc2 >> 64);

        Felem([acc0 as u64, acc1 as u64, acc2 as u64, acc3 as u64])
    }
}

#[cfg_attr(feature = "cargo-clippy", allow(clippy::suspicious_arithmetic_impl))]
impl Sub for Felem {
    type Output = Felem;
    #[inline(always)]
    // Subtraction modulo 2^255 - 19
    fn sub(self, other: Felem) -> Felem {
        static POLY_X4: [u128; 4] = [
            0x1_ffff_ffff_ffff_ffb4,
            0x1_ffff_ffff_ffff_fffe,
            0x1_ffff_ffff_ffff_fffe,
            0x1_ffff_ffff_ffff_fffe,
        ];

        let x0 = u128::from(self.0[0]);
        let x1 = u128::from(self.0[1]);
        let x2 = u128::from(self.0[2]);
        let x3 = u128::from(self.0[3]);

        let y0 = u128::from(other.0[0]);
        let y1 = u128::from(other.0[1]);
        let y2 = u128::from(other.0[2]);
        let y3 = u128::from(other.0[3]);

        let mut acc0 = POLY_X4[0].wrapping_sub(y0).wrapping_add(x0);
        let mut acc1 = POLY_X4[1]
            .wrapping_sub(y1)
            .wrapping_add(x1)
            .wrapping_add(acc0 >> 64);
        let mut acc2 = POLY_X4[2]
            .wrapping_sub(y2)
            .wrapping_add(x2)
            .wrapping_add(acc1 >> 64);
        let mut acc3 = POLY_X4[3]
            .wrapping_sub(y3)
            .wrapping_add(x3)
            .wrapping_add(acc2 >> 64);

        let mut top = (acc3 >> 63) & 0xffff_ffff_ffff_ffff;
        acc0 &= 0xffff_ffff_ffff_ffff;
        acc1 &= 0xffff_ffff_ffff_ffff;
        acc2 &= 0xffff_ffff_ffff_ffff;
        acc3 &= 0x7fff_ffff_ffff_ffff;

        top = top.wrapping_mul(19);
        acc0 = acc0.wrapping_add(top);
        acc1 = acc1.wrapping_add(acc0 >> 64);
        acc2 = acc2.wrapping_add(acc1 >> 64);
        acc3 = acc3.wrapping_add(acc2 >> 64);

        Felem([acc0 as u64, acc1 as u64, acc2 as u64, acc3 as u64])
    }
}

#[cfg_attr(feature = "cargo-clippy", allow(clippy::suspicious_arithmetic_impl))]
impl Mul for Felem {
    type Output = Felem;
    #[inline(always)]
    // Multiplication modulo 2^255 - 19
    fn mul(self, other: Felem) -> Felem {
        let x0 = u128::from(self.0[0]);
        let x1 = u128::from(self.0[1]);
        let x2 = u128::from(self.0[2]);
        let x3 = u128::from(self.0[3]);

        // y0
        let y0 = u128::from(other.0[0]);
        let mut t = x0.wrapping_mul(y0);
        let acc0 = t & 0xffff_ffff_ffff_ffff;
        let mut acc1 = t >> 64;

        t = x1.wrapping_mul(y0);
        acc1 = acc1.wrapping_add(t);
        let mut acc2 = acc1 >> 64;
        acc1 &= 0xffff_ffff_ffff_ffff;

        t = x2.wrapping_mul(y0);
        acc2 = acc2.wrapping_add(t);
        let mut acc3 = acc2 >> 64;
        acc2 &= 0xffff_ffff_ffff_ffff;

        t = x3.wrapping_mul(y0);
        acc3 = acc3.wrapping_add(t);
        let mut acc4 = acc3 >> 64;
        acc3 &= 0xffff_ffff_ffff_ffff;

        // y1
        let y1 = u128::from(other.0[1]);
        t = x0.wrapping_mul(y1);
        acc1 = acc1.wrapping_add(t);
        let mut top = acc1 >> 64;
        acc1 &= 0xffff_ffff_ffff_ffff;

        t = x1.wrapping_mul(y1);
        acc2 = acc2.wrapping_add(top);
        acc2 = acc2.wrapping_add(t);
        top = acc2 >> 64;
        acc2 &= 0xffff_ffff_ffff_ffff;

        t = x2.wrapping_mul(y1);
        acc3 = acc3.wrapping_add(top);
        acc3 = acc3.wrapping_add(t);
        top = acc3 >> 64;
        acc3 &= 0xffff_ffff_ffff_ffff;

        t = x3.wrapping_mul(y1);
        acc4 = acc4.wrapping_add(top);
        acc4 = acc4.wrapping_add(t);
        let mut acc5 = acc4 >> 64;
        acc4 &= 0xffff_ffff_ffff_ffff;

        // y2
        let y2 = u128::from(other.0[2]);
        t = x0.wrapping_mul(y2);
        acc2 = acc2.wrapping_add(t);
        top = acc2 >> 64;
        acc2 &= 0xffff_ffff_ffff_ffff;

        t = x1.wrapping_mul(y2);
        acc3 = acc3.wrapping_add(top);
        acc3 = acc3.wrapping_add(t);
        top = acc3 >> 64;
        acc3 &= 0xffff_ffff_ffff_ffff;

        t = x2.wrapping_mul(y2);
        acc4 = acc4.wrapping_add(top);
        acc4 = acc4.wrapping_add(t);
        top = acc4 >> 64;
        acc4 &= 0xffff_ffff_ffff_ffff;

        t = x3.wrapping_mul(y2);
        acc5 = acc5.wrapping_add(top);
        acc5 = acc5.wrapping_add(t);
        let mut acc6 = acc5 >> 64;
        acc5 &= 0xffff_ffff_ffff_ffff;

        // y3
        let y3 = u128::from(other.0[3]);
        t = x0.wrapping_mul(y3);
        acc3 = acc3.wrapping_add(t);
        top = acc3 >> 64;
        acc3 &= 0xffff_ffff_ffff_ffff;

        t = x1.wrapping_mul(y3);
        acc4 = acc4.wrapping_add(top);
        acc4 = acc4.wrapping_add(t);
        top = acc4 >> 64;
        acc4 &= 0xffff_ffff_ffff_ffff;

        t = x2.wrapping_mul(y3);
        acc5 = acc5.wrapping_add(top);
        acc5 = acc5.wrapping_add(t);
        top = acc5 >> 64;
        acc5 &= 0xffff_ffff_ffff_ffff;

        t = x3.wrapping_mul(y3);
        acc6 = acc6.wrapping_add(top);
        acc6 = acc6.wrapping_add(t);
        let acc7 = acc6 >> 64;
        acc6 &= 0xffff_ffff_ffff_ffff;

        // Modulo
        mod_25519(Felem2([
            acc0 as u64,
            acc1 as u64,
            acc2 as u64,
            acc3 as u64,
            acc4 as u64,
            acc5 as u64,
            acc6 as u64,
            acc7 as u64,
        ]))
    }
}

impl Felem {
    #[inline(always)]
    // Repeatedly square modulo 2^255 - 19
    fn sqr(self, mut rep: u32) -> Felem {
        let mut ret = self;
        while rep > 0 {
            ret = mod_25519(sqr_256(ret));
            rep -= 1;
        }
        ret
    }
}

#[inline(always)]
// Square modulo 2^255 - 19
fn sqr_256(x: Felem) -> Felem2 {
    let x0 = u128::from(x.0[0]);
    let x1 = u128::from(x.0[1]);
    let x2 = u128::from(x.0[2]);
    let x3 = u128::from(x.0[3]);

    // y0
    let mut acc1 = x1.wrapping_mul(x0);
    let mut acc2 = x2.wrapping_mul(x0);
    let mut acc3 = x3.wrapping_mul(x0);

    acc2 = acc2.wrapping_add(acc1 >> 64);
    acc3 = acc3.wrapping_add(acc2 >> 64);
    let mut acc4 = acc3 >> 64;

    acc1 &= 0xffff_ffff_ffff_ffff;
    acc2 &= 0xffff_ffff_ffff_ffff;
    acc3 &= 0xffff_ffff_ffff_ffff;

    // y1
    let mut t = x2.wrapping_mul(x1);
    acc3 = acc3.wrapping_add(t);

    t = x3.wrapping_mul(x1);
    acc4 = acc4.wrapping_add(acc3 >> 64).wrapping_add(t);

    let mut acc5 = acc4 >> 64;

    acc3 &= 0xffff_ffff_ffff_ffff;
    acc4 &= 0xffff_ffff_ffff_ffff;

    // y2
    t = x3.wrapping_mul(x2);
    acc5 = acc5.wrapping_add(t);

    let mut acc6 = acc5 >> 64;
    acc5 &= 0xffff_ffff_ffff_ffff;

    acc6 = acc6 << 1 | acc5 >> 63;
    acc5 = acc5 << 1 | acc4 >> 63;
    acc4 = acc4 << 1 | acc3 >> 63;
    acc3 = acc3 << 1 | acc2 >> 63;
    acc2 = acc2 << 1 | acc1 >> 63;
    acc1 <<= 1;

    let mut acc7 = acc6 >> 64;
    acc1 &= 0xffff_ffff_ffff_ffff;
    acc2 &= 0xffff_ffff_ffff_ffff;
    acc3 &= 0xffff_ffff_ffff_ffff;
    acc4 &= 0xffff_ffff_ffff_ffff;
    acc5 &= 0xffff_ffff_ffff_ffff;
    acc6 &= 0xffff_ffff_ffff_ffff;

    let acc0 = x0.wrapping_mul(x0);
    acc1 = acc1.wrapping_add(acc0 >> 64);

    t = x1.wrapping_mul(x1);
    acc2 = acc2.wrapping_add(acc1 >> 64).wrapping_add(t);
    acc3 = acc3.wrapping_add(acc2 >> 64);

    t = x2.wrapping_mul(x2);
    acc4 = acc4.wrapping_add(acc3 >> 64).wrapping_add(t);
    acc5 = acc5.wrapping_add(acc4 >> 64);

    t = x3.wrapping_mul(x3);
    acc6 = acc6.wrapping_add(acc5 >> 64).wrapping_add(t);
    acc7 = acc7.wrapping_add(acc6 >> 64);

    Felem2([
        acc0 as u64,
        acc1 as u64,
        acc2 as u64,
        acc3 as u64,
        acc4 as u64,
        acc5 as u64,
        acc6 as u64,
        acc7 as u64,
    ])

    // Modulo
}

#[inline(always)]
fn mod_25519(x: Felem2) -> Felem {
    let c38 = 38 as u128;

    let mut acc0 = u128::from(x.0[0]);
    let mut acc1 = u128::from(x.0[1]);
    let mut acc2 = u128::from(x.0[2]);
    let mut acc3 = u128::from(x.0[3]);
    let mut acc4 = u128::from(x.0[4]);
    let mut acc5 = u128::from(x.0[5]);
    let mut acc6 = u128::from(x.0[6]);
    let mut acc7 = u128::from(x.0[7]);

    acc4 = acc4.wrapping_mul(c38);
    acc5 = acc5.wrapping_mul(c38);
    acc6 = acc6.wrapping_mul(c38);
    acc7 = acc7.wrapping_mul(c38);

    acc0 = acc0.wrapping_add(acc4);

    acc1 = acc1.wrapping_add(acc0 >> 64);
    acc1 = acc1.wrapping_add(acc5);

    acc2 = acc2.wrapping_add(acc1 >> 64);
    acc2 = acc2.wrapping_add(acc6);

    acc3 = acc3.wrapping_add(acc2 >> 64);
    acc3 = acc3.wrapping_add(acc7);

    let mut top = (acc3 >> 63) & 0xffff_ffff_ffff_ffff;

    acc0 &= 0xffff_ffff_ffff_ffff;
    acc1 &= 0xffff_ffff_ffff_ffff;
    acc2 &= 0xffff_ffff_ffff_ffff;
    acc3 &= 0x7fff_ffff_ffff_ffff;

    top = top.wrapping_mul(19);

    acc0 = acc0.wrapping_add(top);
    acc1 = acc1.wrapping_add(acc0 >> 64);
    acc2 = acc2.wrapping_add(acc1 >> 64);
    acc3 = acc3.wrapping_add(acc2 >> 64);

    Felem([acc0 as u64, acc1 as u64, acc2 as u64, acc3 as u64])
}

fn mod_final_25519(x: Felem) -> Felem {
    let mut acc0 = u128::from(x.0[0]);
    let mut acc1 = u128::from(x.0[1]);
    let mut acc2 = u128::from(x.0[2]);
    let mut acc3 = u128::from(x.0[3]);

    let mut top = acc3 >> 63;
    acc3 &= MASK_63BITS;
    top = top.wrapping_mul(19);
    acc0 = acc0.wrapping_add(top);
    acc1 = acc1.wrapping_add(acc0 >> 64);
    acc2 = acc2.wrapping_add(acc1 >> 64);
    acc3 = acc3.wrapping_add(acc2 >> 64);

    // Mask
    acc0 &= MASK_64BITS;
    acc1 &= MASK_64BITS;
    acc2 &= MASK_64BITS;
    acc3 &= MASK_64BITS;

    // At this point, acc{0-3} is in the range between 0 and 2^255 + 18, inclusively. It's not
    // under 2^255 - 19 yet. So we are doing another round of modulo operation.

    top = acc0.wrapping_add(19) >> 64;
    top = acc1.wrapping_add(top) >> 64;
    top = acc2.wrapping_add(top) >> 64;
    top = acc3.wrapping_add(top) >> 63;
    top = top.wrapping_mul(19);

    // top is 19 if acc{0-3} is between 2^255 - 19 and 2^255 + 18, inclusively. Otherwise, it's
    // zero.

    acc0 = acc0.wrapping_add(top);
    acc1 = acc1.wrapping_add(acc0 >> 64);
    acc2 = acc2.wrapping_add(acc1 >> 64);
    acc3 = acc3.wrapping_add(acc2 >> 64);
    acc3 &= MASK_63BITS;

    // Now acc{0-3} is between 0 and 2^255 - 20, inclusively.

    Felem([acc0 as u64, acc1 as u64, acc2 as u64, acc3 as u64])
}

// Modular inverse
fn mod_inv_25519(x: Felem) -> Felem {
    let m1 = x;
    let m10 = x.sqr(1);
    let m1001 = m10.sqr(2) * m1;
    let m1011 = m1001 * m10;

    let x5 = m1011.sqr(1) * m1001;
    let x10 = x5.sqr(5) * x5;
    let x20 = x10.sqr(10) * x10;
    let x40 = x20.sqr(20) * x20;
    let x50 = x40.sqr(10) * x10;
    let x100 = x50.sqr(50) * x50;

    let t = x100.sqr(100) * x100;
    let t2 = t.sqr(50) * x50;
    t2.sqr(5) * m1011
}

#[inline(always)]
// Swap two values a and b in constant time iff swap == 1
fn constant_time_swap(a: Felem, b: Felem, swap: u64) -> (Felem, Felem) {
    let mask = 0_u64.wrapping_sub(swap);

    let mut v = [0_u64; 4];
    let mut a_out = [0_u64; 4];
    let mut b_out = [0_u64; 4];

    v[0] = mask & (a.0[0] ^ b.0[0]);
    v[1] = mask & (a.0[1] ^ b.0[1]);
    v[2] = mask & (a.0[2] ^ b.0[2]);
    v[3] = mask & (a.0[3] ^ b.0[3]);

    a_out[0] = v[0] ^ a.0[0];
    a_out[1] = v[1] ^ a.0[1];
    a_out[2] = v[2] ^ a.0[2];
    a_out[3] = v[3] ^ a.0[3];

    b_out[0] = v[0] ^ b.0[0];
    b_out[1] = v[1] ^ b.0[1];
    b_out[2] = v[2] ^ b.0[2];
    b_out[3] = v[3] ^ b.0[3];

    (Felem(a_out), Felem(b_out))
}

fn x25519_public_key(secret_key: &[u8]) -> [u8; 32] {
    let u = [
        9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ];

    x25519_shared_key(&u, secret_key)
}

fn x25519_shared_key(peer_key: &[u8], secret_key: &[u8]) -> [u8; 32] {
    if peer_key.len() != 32 || secret_key.len() != 32 {
        panic!("Illegal values for x25519");
    }

    let mut scalar = [0_u8; 32];
    let mut shared_key = [0_u8; 32];
    scalar[..].copy_from_slice(&secret_key[..]);

    assert!(peer_key.len() == 32);
    let u = Felem([
        u64::from_le_bytes(make_array(&peer_key[0..])),
        u64::from_le_bytes(make_array(&peer_key[8..])),
        u64::from_le_bytes(make_array(&peer_key[16..])),
        u64::from_le_bytes(make_array(&peer_key[24..])),
    ]);

    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;

    let x_1 = u;
    let mut x_2 = Felem([1, 0, 0, 0]);
    let mut z_2 = Felem([0, 0, 0, 0]);
    let mut x_3 = u;
    let mut z_3 = Felem([1, 0, 0, 0]);
    let a24 = Felem([121_666, 0, 0, 0]);
    let mut swap = 0;

    for pos in (0..=254).rev() {
        let bit_val = u64::from((scalar[pos / 8] >> (pos & 7)) & 1);

        swap ^= bit_val;
        let (mut x2, mut x3) = constant_time_swap(x_2, x_3, swap);
        let (mut z2, mut z3) = constant_time_swap(z_2, z_3, swap);
        swap = bit_val;

        let mut tmp0 = x3 - z3;
        let mut tmp1 = x2 - z2;
        x2 = x2 + z2;
        z2 = x3 + z3;

        z3 = x2 * tmp0;
        z2 = z2 * tmp1;

        tmp0 = tmp1.sqr(1);
        tmp1 = x2.sqr(1);
        x3 = z3 + z2;
        z2 = z3 - z2;

        x_2 = tmp1 * tmp0;
        tmp1 = tmp1 - tmp0;
        z2 = z2.sqr(1);

        z3 = a24 * tmp1;
        x_3 = x3.sqr(1);
        tmp0 = tmp0 + z3;

        z_3 = x_1 * z2;
        z_2 = tmp1 * tmp0;
    }

    let (x2, _) = constant_time_swap(x_2, x_3, swap);
    let (z2, _) = constant_time_swap(z_2, z_3, swap);

    let key = mod_final_25519(x2 * mod_inv_25519(z2));

    shared_key[0..8].copy_from_slice(&key.0[0].to_le_bytes());
    shared_key[8..16].copy_from_slice(&key.0[1].to_le_bytes());
    shared_key[16..24].copy_from_slice(&key.0[2].to_le_bytes());
    shared_key[24..32].copy_from_slice(&key.0[3].to_le_bytes());

    shared_key
}

// Compare two 32 byte keys for equality.
//
// eq = true indicates we compare for equality (Err if not equal)
// eq = false indicates we compare for inequality (Err if equal)
fn constant_time_key_compare(key1: &[u8], key2: &[u8], eq: bool) -> Result<(), InvalidKey> {
    if key1.len() != 32 || key2.len() != 32 {
        return Err(InvalidKey);
    }

    let mut r = 0u8;
    for i in 0..32 {
        r |= key1[i] ^ key2[i];
    }

    if (r == 0) ^ eq {
        Err(InvalidKey)
    } else {
        Ok(())
    }
}

// Check if the slice is 32 byte long and is all zeroes.
fn constant_time_zero_key_check(key: &[u8]) -> Result<(), InvalidKey> {
    if key.len() != 32 {
        return Err(InvalidKey);
    }

    let mut r = 0u8;

    for b in key {
        r |= b;
    }

    if r == 0 {
        Err(InvalidKey)
    } else {
        Ok(())
    }
}




#[cfg(test)]
mod tests {
    use super::{mod_final_25519, mod_inv_25519, x25519_shared_key, Felem};

    #[allow(dead_code)]
    struct X25519ArithTest {
        x: [u64; 4],
        y: [u64; 4],
        expected_mul: [u64; 8],
        expected_modmul: [u64; 4],
        expected_sqr: [u64; 8],
        expected_modsqr: [u64; 4],
        expected_modinv: [u64; 4],
        expected_modadd: [u64; 4],
    }

    #[test]
    fn x25519_arith_test_vectors() {
        for i in ARITH_TEST_VECTORS.iter() {
            assert_eq!(
                i.expected_modmul,
                mod_final_25519(Felem(i.x) * Felem(i.y)).0
            );
            assert_eq!(i.expected_modsqr, mod_final_25519(Felem(i.x).sqr(1)).0);
            assert_eq!(i.expected_modinv, mod_inv_25519(Felem(i.x)).0);
            assert_eq!(
                i.expected_modadd,
                mod_final_25519(Felem(i.x) + Felem(i.y)).0
            );
        }
    }

    #[test]
    fn x25519_mod_final_test() {
        let max = Felem([
            0xffff_ffff_ffff_ffec,
            0xffff_ffff_ffff_ffff,
            0xffff_ffff_ffff_ffff,
            0x7fff_ffff_ffff_ffff,
        ]);

        let zero = Felem([
            0x0000_0000_0000_0000,
            0x0000_0000_0000_0000,
            0x0000_0000_0000_0000,
            0x0000_0000_0000_0000,
        ]);

        let one = Felem([
            0x0000_0000_0000_0001,
            0x0000_0000_0000_0000,
            0x0000_0000_0000_0000,
            0x0000_0000_0000_0000,
        ]);

        assert_eq!(mod_final_25519(max).0, max.0);
        assert_eq!(mod_final_25519(max + one).0, zero.0);
    }

    #[test]
    fn x25519_test_vectors() {
        let base: [u8; 32] = [
            9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ];
        let secret = [
            234, 69, 216, 5, 208, 56, 44, 91, 123, 8, 33, 121, 137, 15, 255, 76, 154, 107, 73, 68,
            249, 251, 216, 186, 120, 219, 220, 214, 134, 87, 221, 17,
        ];
        let expected = [
            132, 192, 36, 81, 34, 82, 24, 235, 228, 205, 255, 152, 83, 86, 197, 150, 82, 184, 166,
            230, 82, 51, 255, 148, 239, 202, 195, 11, 156, 37, 43, 16,
        ];

        assert_eq!(x25519_shared_key(&base, &secret), expected);
    }

    static ARITH_TEST_VECTORS: [X25519ArithTest; 8] = [
        X25519ArithTest {
            x: [
                0xE97D2220819A3E29,
                0x3B6DBE02D31423FC,
                0x6CDA39476B4F99ED,
                0xC0598CF213CF1A1D,
            ],
            y: [
                0x33389459E37FE135,
                0x48EB023707F9AC61,
                0x17E197A52386A5BC,
                0xD2278E5446047752,
            ],
            expected_mul: [
                0x117A038796E7E77D,
                0x13B3D9044B8E5CCD,
                0x697326EDE8412464,
                0x96C12F052421C472,
                0x427C2677F8994677,
                0xBBB89BA1292C39ED,
                0x328FA5B3AC138833,
                0x9DE72E340B4D45FC,
            ],
            expected_modmul: [
                0xEFE7B9567DA860B7,
                0xF11AF2F0681EF604,
                0xEAC5BF9973275C11,
                0x07120ABED19A27E1,
            ],
            expected_sqr: [
                0xF6B93DD42A6BE291,
                0x74F56FEE2547930C,
                0x42B866BCF6B23C50,
                0x6C7316B947839066,
                0x6ABF25DEF37E3B87,
                0x39BC1EBF3AA792D9,
                0x4562F9C30C42D78A,
                0x908672BE6BA217C0,
            ],
            expected_modsqr: [
                0xCF18DCEC4F28BBCC,
                0x06E20050DA275F52,
                0x8F6979B0C89E3AD5,
                0x60681EFD419316F0,
            ],
            expected_modinv: [
                0xAAC44D4AE16D9CCF,
                0xDEFA0E23212DD655,
                0xC137BC72CBC02D2F,
                0x4CAC9F74EB0F9657,
            ],
            expected_modadd: [
                0x1CB5B67A651A1F97,
                0x8458C039DB0DD05E,
                0x84BBD0EC8ED63FA9,
                0x12811B4659D3916F,
            ],
        },
        X25519ArithTest {
            x: [
                0x69D7D01A7C0207E3,
                0xB6EAF69A61F58E69,
                0xBC6C0620A5DF8749,
                0xC44F32C0D5B651B3,
            ],
            y: [
                0xDE492E6A6E2F9AFF,
                0x224E1508FE4F7BB4,
                0x6AC55A9B6FA973C7,
                0xE7B1CA677D6862C8,
            ],
            expected_mul: [
                0xA74AEABBBB71691D,
                0x11C172677A3617FD,
                0x7F4EDC46A2B3C6C8,
                0xE3EF8172C37226B8,
                0x26E89CE4186237DA,
                0x57C7E44293DF6C3B,
                0x4CFBE41364954B29,
                0xB1ABCCC3F23F92B4,
            ],
            expected_modmul: [
                0x6DD234975A05B77B,
                0x196D54496D6028C5,
                0xECB2B72790DCEEEB,
                0x436FE688B8E1ED7B,
            ],
            expected_sqr: [
                0x2E9671C407CA3349,
                0x16E97CEA08494E58,
                0xFECA2E7B347E0630,
                0x163A681ED42FD9EF,
                0xFACFAA5BE8EC37F9,
                0xEFCC4AD052C767FE,
                0x21415D0FF7C1801A,
                0x96895E37A452F85E,
            ],
            expected_modsqr: [
                0x6969BB689ADA8583,
                0xAF3C97D651E2BE31,
                0xEE7DFED9FB370A2F,
                0x6E9E64613880B7E8,
            ],
            expected_modinv: [
                0x57380C7DAA1A5B69,
                0xA8097E5D8CB8A22E,
                0x059B5FBA266D7182,
                0x009E5544442B01BA,
            ],
            expected_modadd: [
                0x4820FE84EA31A31B,
                0xD9390BA360450A1E,
                0x273160BC1588FB10,
                0x2C00FD28531EB47C,
            ],
        },
        X25519ArithTest {
            x: [
                0xE9E5D0F41E7488E3,
                0x14594C4DB31AF90C,
                0xE9536849D760F23E,
                0xE1005A9A51FC95F4,
            ],
            y: [
                0x9265196ED69D261D,
                0x44A001DD634FC191,
                0x6E6B4A40CDBD6853,
                0xF6EE5BC05A5DC08D,
            ],
            expected_mul: [
                0xC238FC9C74BC33B7,
                0xC00A1B71918F7548,
                0xBE115A7F11FAFC30,
                0x0C7B46DA4E3E81D1,
                0xECAA72C1682E055A,
                0xFDB9DBE5C146B22F,
                0xC5BA45AFF7AA097E,
                0xD907D608B6264606,
            ],
            expected_modmul: [
                0xE3860551EB9103D3,
                0x69A0BF8C420DE865,
                0x17B7B29DD538650A,
                0x43A50C2557ECE6D3,
            ],
            expected_sqr: [
                0x8C5355D98AE9F949,
                0xD11EE674AC0EA339,
                0x026C98D3365085D9,
                0x57C898A35A360AD5,
                0xACAE98F3590428A6,
                0x297521C4AC3AAB6E,
                0xD9BB0C25B7EEF435,
                0xC5C19F43642EDE44,
            ],
            expected_modsqr: [
                0x2E3E09F8C188064E,
                0xF881E9A63CC415A7,
                0x5430666C83C8C5BD,
                0x32863CA4392B090D,
            ],
            expected_modinv: [
                0xE029E39C9892894F,
                0xF5328FF0C1859F9D,
                0xE9083DFD943D8EA0,
                0x4799EFA93C695043,
            ],
            expected_modadd: [
                0x7C4AEA62F511AF39,
                0x58F94E2B166ABA9E,
                0x57BEB28AA51E5A91,
                0x57EEB65AAC5A5682,
            ],
        },
        X25519ArithTest {
            x: [
                0x2D5542183EAF12A3,
                0x0C767D346D125150,
                0x13ADAF80EB2E0F63,
                0xDA6B7C3A8E22C28F,
            ],
            y: [
                0xD0C8B33E96F0D531,
                0x2F5EADF580C75BEC,
                0xB7CF17DE2DCD8416,
                0xFB7D320B454560A1,
            ],
            expected_mul: [
                0x608BA852A4D43033,
                0xA1F3D111435A079B,
                0x39C29495653C51BD,
                0x5DB147DF7F3517C5,
                0xD67265962AFC0B40,
                0x63B6BEEE87407917,
                0xBAC07FE3D25DDADE,
                0xD69233FBADEF6BE8,
            ],
            expected_modmul: [
                0x3586BC9D063DE073,
                0x6F14287956EC0125,
                0xF25590669F2ACEC0,
                0x3764FF3B50BF1C50,
            ],
            expected_sqr: [
                0xC406CF51703553C9,
                0x27846328DF567B4D,
                0x99D31E6BA5490E59,
                0x33A3CC1B7C5B6E81,
                0x1D3D1464AF18C8A9,
                0x9C7F6AE8B6F42C21,
                0xB4439A8C6EBA8794,
                0xBA5B3CB4CF4ECB80,
            ],
            expected_modsqr: [
                0x1B17D6436DE320F4,
                0x626E41B407950838,
                0x5BDC0F4414F92E68,
                0x5D2ECEF2420DA39C,
            ],
            expected_modinv: [
                0xFBBCC5F8B283A8DE,
                0x82F7C78A59091E55,
                0x7BD47157242F39C5,
                0x4D897B10C38FA5B2,
            ],
            expected_modadd: [
                0xFE1DF556D59FE80D,
                0x3BD52B29EDD9AD3C,
                0xCB7CC75F18FB9379,
                0x55E8AE45D3682330,
            ],
        },
        X25519ArithTest {
            x: [
                0x61B8C4EF03E34ABF,
                0xE541B4A599D21181,
                0xE73C3B4C27B8C5EE,
                0xF0C399F6EDCC3069,
            ],
            y: [
                0x15B955E37838732F,
                0xCA4C191C5360293A,
                0x05E52F0D245E6A66,
                0xC816B0677D0175FE,
            ],
            expected_mul: [
                0xA8E29DBFB3168611,
                0xC14BCEA53EE74945,
                0xCB91935693CDA73C,
                0x877CA14DB71167D2,
                0xCF96CDD658BF9D0A,
                0xE52C62442E23972D,
                0x6D40D36F048DE4BF,
                0xBC2E26FFF31D8D1E,
            ],
            expected_modmul: [
                0x79452B90DF87D9B5,
                0xC5E264C4182FBA12,
                0x0330F5D140DD9BB8,
                0x76566B4BCD745A57,
            ],
            expected_sqr: [
                0x7D7926301E8CFA81,
                0x458CC473DA6164FA,
                0x36B8C2F97BF126C3,
                0x36EBF723747BBBD4,
                0xE62F80EF1BBEEEDD,
                0x44EECB7DCB0A98E5,
                0x46168B60CF37E4C4,
                0xE26F5622E8A63644,
            ],
            expected_modsqr: [
                0xA88649AE3CE47448,
                0x80FEF91FFDF4171A,
                0x9E1173583E3D1BE5,
                0x5372C051FD27C9F6,
            ],
            expected_modinv: [
                0x335DBEB2F0090695,
                0x3750ED20AE0C09E4,
                0x61634512F0C2CEBF,
                0x21C10AA0D36492D0,
            ],
            expected_modadd: [
                0x77721AD27C1BBE27,
                0xAF8DCDC1ED323ABB,
                0xED216A594C173055,
                0x38DA4A5E6ACDA667,
            ],
        },
        X25519ArithTest {
            x: [
                0xE2570A6193C70883,
                0x23CD50142AFED51F,
                0xFCC8371BC391C69A,
                0xF785FF3869016ECB,
            ],
            y: [
                0x69574DA6E093DC6B,
                0xAF17535BD40858D4,
                0xF59874B7E88E7F52,
                0xE16614739CEB93DF,
            ],
            expected_mul: [
                0x0EC7207652BA22C1,
                0xEF34F5394A33A03D,
                0x6C7E58647B9BC9F7,
                0x1B9216376CC1F739,
                0xAE39449C94CF0238,
                0x59240C002A4A8E97,
                0xDC420586EBA29B1F,
                0xD9EF787A859F9600,
            ],
            expected_modmul: [
                0xEB474FB469747BD1,
                0x2A8EBD3F9144CAC0,
                0x1E4B2A6B75BED09F,
                0x751DF86742723B5A,
            ],
            expected_sqr: [
                0xF3D6DDCAADF27309,
                0xFED071AF35FBAEC5,
                0x55F8445808C45D0C,
                0x28195EB53286D559,
                0x1AA54B0283A3B3DB,
                0xE9D081DB0DFD48DD,
                0xB82C0A1BAE861503,
                0xEF53D8A209AF4CE9,
            ],
            expected_modsqr: [
                0xE860002A383F2AD0,
                0xB3C3B83349947F97,
                0xAC81C473F0AB7BA1,
                0x2E8B86C2A28C400A,
            ],
            expected_modinv: [
                0x8CBABFE0DFA3DB9C,
                0x71B444FE7789A984,
                0x2564681A444E1F84,
                0x103E67AB1C54F933,
            ],
            expected_modadd: [
                0x4BAE5808745AE527,
                0xD2E4A36FFF072DF4,
                0xF260ABD3AC2045EC,
                0x58EC13AC05ED02AB,
            ],
        },
        X25519ArithTest {
            x: [
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
            ],
            y: [
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
            ],
            expected_mul: [
                0x0000000000000001,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0xFFFFFFFFFFFFFFFE,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
            ],
            expected_modmul: [
                0x0000000000000559,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
            ],
            expected_sqr: [
                0x0000000000000001,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0xFFFFFFFFFFFFFFFE,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
            ],
            expected_modsqr: [
                0x0000000000000559,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
            ],
            expected_modinv: [
                0x7C8A60DD67C8A600,
                0x8A60DD67C8A60DD6,
                0x60DD67C8A60DD67C,
                0x5D67C8A60DD67C8A,
            ],
            expected_modadd: [
                0x000000000000004A,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
            ],
        },
        X25519ArithTest {
            x: [
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
            ],
            y: [
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
            ],
            expected_mul: [
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
            ],
            expected_modmul: [
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
            ],
            expected_sqr: [
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
            ],
            expected_modsqr: [
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
            ],
            expected_modinv: [
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
            ],
            expected_modadd: [
                0x0000000000000025,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
            ],
        },
    ];
}