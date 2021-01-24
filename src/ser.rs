use crate::wire::*;
use crate::error::{Error, ErrorKind};

use core::convert::TryFrom;
use core::ops::RangeInclusive;


pub trait Serialize {
    fn serialize<T: AsMut<[u8]> + AsRef<[u8]>>(&self, serializer: &mut Serializer<T>) -> Result<(), Error>;
}

macro_rules! primitive_impl {
    ($ty:ident, $method:ident) => {
        impl Serialize for $ty {
            #[inline]
            fn serialize<T: AsMut<[u8]> + AsRef<[u8]>>(&self, serializer: &mut Serializer<T>) -> Result<(), Error> {
                serializer.$method(*self)
            }
        }
    }
}

primitive_impl!(u8, serialize_u8);
primitive_impl!(u16, serialize_u16);
primitive_impl!(u32, serialize_u32);


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

    pub fn serialize_u8(&mut self, v: u8) -> Result<(), Error> {
        self.serialize_slice(&[v])
    }

    pub fn serialize_u16(&mut self, v: u16) -> Result<(), Error> {
        self.serialize_slice(&v.to_be_bytes())
    }

    pub fn serialize_u24(&mut self, v: u32) -> Result<(), Error> {
        const U24_MAX: u32 = 16777215; // 2 ** 24 - 1
        
        debug_assert!(v <= U24_MAX);

        self.serialize_slice(&v.to_be_bytes()[1..])
    }

    pub fn serialize_u32(&mut self, v: u32) -> Result<(), Error> {
        self.serialize_slice(&v.to_be_bytes())
    }

    #[inline]
    fn serialize_len_value<F: FnOnce(&mut Serializer<T>) -> Result<(), Error>>(&mut self, num_len_octets: usize, min_len: usize, max_len: usize, serialize_fn: F) -> Result<(), Error> {
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

        Ok(())
    }

    // NOTE: <2..2^16-2>
    //       <1..2^8-1>
    //       <0..32>
    pub fn serialize_vector<F: FnOnce(&mut Serializer<T>) -> Result<(), Error>>(&mut self, len_range: RangeInclusive<usize>, serialize_fn: F) -> Result<(), Error> {
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

    pub fn serialize_slice(&mut self, v: &[u8]) -> Result<(), Error> {
        let amt = v.len();

        if amt > self.remainder_len() {
            return Err(Error::new(ErrorKind::InternalError, "failed to write whole buffer"));
        }

        let buf   = self.inner.as_mut();
        let start = self.pos;
        let end   = start + amt;

        buf[start..end].copy_from_slice(v);

        self.pos += amt;

        // Ok(amt)
        Ok(())
    }

    pub fn serialize_many_with<F: FnOnce(&mut Serializer<T>) -> Result<(), Error>>(&mut self, serialize_fn: F) -> Result<usize, Error> {
        let start = self.pos;
        
        serialize_fn(self)?;

        let end = self.pos;
        let amt = end - start;

        Ok(amt)
    }

    pub fn serialize<V: Serialize>(&mut self, val: &V) -> Result<(), Error> {
        val.serialize(self)
    }
}


macro_rules! wrap_impl {
    ($ty:ident, $method:ident) => {
        impl Serialize for $ty {
            #[inline]
            fn serialize<T: AsMut<[u8]> + AsRef<[u8]>>(&self, serializer: &mut Serializer<T>) -> Result<(), Error> {
                serializer.$method(self.0)
            }
        }
    }
}

wrap_impl!(ContentKind,       serialize_u8);
wrap_impl!(HandshakeKind,     serialize_u8);
wrap_impl!(CompressionMethod, serialize_u8);
wrap_impl!(ECPointFormat,     serialize_u8);

wrap_impl!(ExtensionKind,   serialize_u16);
wrap_impl!(CipherSuite,     serialize_u16);
wrap_impl!(SupportedGroup,  serialize_u16);
wrap_impl!(SignatureScheme, serialize_u16);


impl Serialize for ProtocolVersion {
    #[inline]
    fn serialize<T: AsMut<[u8]> + AsRef<[u8]>>(&self, serializer: &mut Serializer<T>) -> Result<(), Error> {
        serializer.serialize_slice(&self.to_be_bytes())
    }
}

impl Serialize for Random {
    #[inline]
    fn serialize<T: AsMut<[u8]> + AsRef<[u8]>>(&self, serializer: &mut Serializer<T>) -> Result<(), Error> {
        serializer.serialize_slice(self.as_bytes())
    }
}

impl Serialize for SessionId {
    #[inline]
    fn serialize<T: AsMut<[u8]> + AsRef<[u8]>>(&self, serializer: &mut Serializer<T>) -> Result<(), Error> {
        serializer.serialize_vector(0..=SessionId::MAX_LEN, |serializer| serializer.serialize_slice(self.as_bytes()))
    }
}
