use crate::wire::*;
use crate::error::{Error, ErrorKind};

use std::convert::TryFrom;
use std::ops::RangeInclusive;
use std::io::{self, Read, Write};


pub trait Serialize {
    fn serialize<T: AsMut<[u8]> + AsRef<[u8]>>(&self, serializer: &mut Serializer<T>) -> Result<usize, Error>;
}

macro_rules! primitive_impl {
    ($ty:ident, $method:ident) => {
        impl Serialize for $ty {
            #[inline]
            fn serialize<T: AsMut<[u8]> + AsRef<[u8]>>(&self, serializer: &mut Serializer<T>) -> Result<usize, Error> {
                serializer.$method(*self)
            }
        }
    }
}

primitive_impl!(u8, serialize_u8);
primitive_impl!(u16, serialize_u16);
primitive_impl!(u32, serialize_u32);
primitive_impl!(u64, serialize_u64);
primitive_impl!(usize, serialize_usize);


pub struct Serializer<T> {
    inner: T,
    pos: usize,
}

impl<T> Serializer<T> {
    pub const fn new(inner: T) -> Serializer<T> {
        Serializer { pos: 0, inner }
    }

    pub fn into_inner(self) -> T {
        self.inner
    }

    pub const fn get_ref(&self) -> &T {
        &self.inner
    }

    pub fn get_mut(&mut self) -> &mut T {
        &mut self.inner
    }

    pub const fn position(&self) -> usize {
        self.pos
    }

    pub fn set_position(&mut self, pos: usize) {
        self.pos = pos;
    }
}

impl<T: AsMut<[u8]> + AsRef<[u8]>> Serializer<T> {
    pub fn buf_len(&self) -> usize {
        self.inner.as_ref().len()
    }

    pub fn remainder_len(&self) -> usize {
        self.buf_len() - self.pos
    }

    pub fn serialize_u8(&mut self, v: u8) -> Result<usize, Error> {
        self.serialize_bytes(&[v])
    }

    pub fn serialize_u16(&mut self, v: u16) -> Result<usize, Error> {
        self.serialize_bytes(&v.to_be_bytes())
    }

    pub fn serialize_u32(&mut self, v: u32) -> Result<usize, Error> {
        self.serialize_bytes(&v.to_be_bytes())
    }

    pub fn serialize_u64(&mut self, v: u64) -> Result<usize, Error> {
        self.serialize_bytes(&v.to_be_bytes())
    }

    pub fn serialize_usize(&mut self, v: usize) -> Result<usize, Error> {
        self.serialize_bytes(&v.to_be_bytes())
    }

    pub fn serialize_bytes(&mut self, v: &[u8]) -> Result<usize, Error> {
        let amt = v.len();

        if amt > self.remainder_len() {
            return Err(Error::new(ErrorKind::InternalError, "failed to write whole buffer"));
        }

        let buf   = self.inner.as_mut();
        let start = self.pos;
        let end   = start + amt;

        buf[start..end].copy_from_slice(v);

        self.pos += amt;

        Ok(amt)
    }

    pub fn serialize_len_value<F: FnOnce(&mut Serializer<T>) -> Result<(), Error>>(&mut self, num_len_octets: usize, min_len: usize, max_len: usize, serialize_fn: F) -> Result<usize, Error> {
        if num_len_octets > self.remainder_len() {
            return Err(Error::new(ErrorKind::InternalError, "failed to write whole buffer"));
        }

        // NOTE: 先跳过 LEN 字段。
        self.pos += num_len_octets;
        
        let start = self.pos;

        serialize_fn(self)?;

        let end = self.pos;

        let amt = end - start;

        let buf = self.inner.as_mut();
        let len_pos = start - num_len_octets;

        if amt < min_len || amt > max_len {
            return Err(Error::new(ErrorKind::InternalError, format!("the number of bytes of the vector is limited, The number of bytes must be within the range of {}..={}.", min_len, max_len)));
        }

        let len_octets = &(amt as u64).to_be_bytes()[core::mem::size_of::<u64>() - num_len_octets..];
        assert_eq!(len_octets.len(), num_len_octets);

        // NOTE: 返回填充 LEN 字段。
        buf[len_pos..len_pos + num_len_octets].copy_from_slice(len_octets);

        Ok(amt + num_len_octets)
    }

    // NOTE: <2..2^16-2>
    //       <1..2^8-1>
    //       <0..32>
    pub fn serialize_vector<F: FnOnce(&mut Serializer<T>) -> Result<(), Error>>(&mut self, len_range: RangeInclusive<usize>, serialize_fn: F) -> Result<usize, Error> {
        const U8_MAX: usize  = u8::MAX as usize;
        const U16_MAX: usize = u16::MAX as usize;
        const U24_MAX: usize = 16777215; // 2 ** 24 - 1
        #[cfg(any(target_pointer_width = "32", target_pointer_width = "64"))]
        const U32_MAX: usize = u32::MAX as usize;

        const U16_MIN: usize =  U8_MAX + 1;
        const U24_MIN: usize = U16_MAX + 1;
        const U32_MIN: usize = U24_MAX + 1;

        let min_len = *(len_range.start());
        let max_len = *(len_range.end());
        debug_assert!(min_len <= max_len);

        let num_len_octets = match max_len {
                  0..=U8_MAX  => 1,
            U16_MIN..=U16_MAX => 2,
            U24_MIN..=U24_MAX => 3,
            #[cfg(any(target_pointer_width = "32", target_pointer_width = "64"))]
            U32_MIN..=U32_MAX => 4,
            // NOTE: RFC 上面没有这么大的数据结构需要序列化，所以我们直接 panic。
            _ => unreachable!("Oops ?"),
        };

        self.serialize_len_value(num_len_octets, min_len, max_len, serialize_fn)
    }

    pub fn serialize_many<F: FnOnce(&mut Serializer<T>) -> Result<(), Error>>(&mut self, serialize_fn: F) -> Result<usize, Error> {
        let start = self.pos;
        
        serialize_fn(self)?;

        let end = self.pos;
        let amt = end - start;

        Ok(amt)
    }
}


pub fn serialize<T: AsMut<[u8]> + AsRef<[u8]>, V: Serialize>(serializer: &mut Serializer<T>, val: V) -> Result<usize, Error> {
    val.serialize(serializer)
}
    
pub fn write_tls_plaintext_record<T: AsMut<[u8]> + AsRef<[u8]>, F: FnOnce(&mut Serializer<T>) -> Result<(), Error>>(serializer: &mut Serializer<T>, kind: ContentKind, version: ProtocolVersion, serialize_fn: F) -> Result<usize, Error> {
    // 5.1.  Record Layer
    // https://tools.ietf.org/html/rfc8446#section-5.1
    // struct {
    //     ContentType type;
    //     ProtocolVersion legacy_record_version;
    //     uint16 length;
    //     opaque fragment[TLSPlaintext.length];
    // } TLSPlaintext;
    serializer.serialize_many(|serializer| {
        serializer.serialize_bytes(&[
            kind.0, version.major, version.minor,
        ])?;
        serializer.serialize_vector(0..=u16::MAX as usize, serialize_fn)?;

        Ok(())
    })
}

fn ser_example() -> Result<(), Box<dyn std::error::Error>> {
    let mut buffer = vec![0u8; 4096];
    let mut serializer = Serializer::new(&mut buffer);

    let amt = serializer.serialize_bytes(&[1, 2, 3])?;

    let amt = serializer.serialize_vector(0..=32, |serializer| {
        let amt = serializer.serialize_bytes(&[1, 2, 3])?;

        let amt = serializer.serialize_vector(0..=32, |serializer| {
            let amt = serializer.serialize_u8(128)?;

            Ok(())
        })?;

        Ok(())
    })?;

    Ok(())
}
