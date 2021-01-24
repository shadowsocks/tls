use crate::wire::*;
use crate::error::{Error, ErrorKind};

use core::convert::TryFrom;
use core::ops::RangeInclusive;


pub trait Deserialize: Sized {
    fn deserialize<T: AsRef<[u8]>>(deserializer: &mut Deserializer<T>) -> Result<Self, Error>;
}

macro_rules! primitive_impl {
    ($ty:ident, $method:ident) => {
        impl Deserialize for $ty {
            #[inline]
            fn deserialize<T: AsRef<[u8]>>(deserializer: &mut Deserializer<T>) -> Result<Self, Error> {
                deserializer.$method()
            }
        }
    }
}

primitive_impl!(u8, deserialize_u8);
primitive_impl!(u16, deserialize_u16);
primitive_impl!(u32, deserialize_u32);


pub struct Deserializer<T> {
    inner: T,
    pos: usize,
}

impl<T: AsRef<[u8]>> Deserializer<T> {
    pub fn new(inner: T) -> Deserializer<T> {
        Deserializer { pos: 0, inner }
    }

    pub fn into_inner(self) -> T {
        self.inner
    }

    pub fn get_ref(&self) -> &T {
        &self.inner
    }

    pub fn get_mut(&mut self) -> &mut T {
        &mut self.inner
    }

    pub fn position(&self) -> usize {
        self.pos
    }

    pub fn set_position(&mut self, pos: usize) {
        self.pos = pos;
    }
}

impl<T: AsRef<[u8]>> Deserializer<T> {
    #[inline]
    pub fn buf_len(&self) -> usize {
        self.inner.as_ref().len()
    }
    
    pub fn remainder_len(&self) -> usize {
        self.buf_len() - self.pos
    }
    
    pub fn deserialize_u8(&mut self) -> Result<u8, Error> {
        let mut buf = [0u8; 1];

        self.deserialize_slice(&mut buf)?;

        Ok(buf[0])
    }

    pub fn deserialize_u16(&mut self) -> Result<u16, Error> {
        let mut buf = [0u8; 2];

        self.deserialize_slice(&mut buf)?;

        Ok(u16::from_be_bytes(buf))
    }

    pub fn deserialize_u24(&mut self) -> Result<u32, Error> {
        let mut buf = [0u8; 4];

        self.deserialize_slice(&mut buf[1..])?;

        Ok(u32::from_be_bytes(buf))
    }

    pub fn deserialize_u32(&mut self) -> Result<u32, Error> {
        let mut buf = [0u8; 4];

        self.deserialize_slice(&mut buf)?;

        Ok(u32::from_be_bytes(buf))
    }

    pub fn deserialize_vector(&mut self, len_range: RangeInclusive<usize>) -> Result<&[u8], Error> {
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

        let len_octets = match num_len_octets {
            1 => usize::try_from(self.deserialize_u8()?).unwrap(),
            2 => usize::try_from(self.deserialize_u16()?).unwrap(),
            3 => usize::try_from(self.deserialize_u24()?).unwrap(),
            4 => usize::try_from(self.deserialize_u32()?).unwrap(),
            _ => unreachable!("Oops ?"),
        };

        let payload = self.deserialize_many(len_octets)?;

        Ok(payload)
    }

    pub fn deserialize_slice(&mut self, out: &mut [u8]) -> Result<(), Error> {
        let slice = self.deserialize_many(out.len())?;
        out.copy_from_slice(slice);

        Ok(())
    }

    pub fn deserialize_many(&mut self, len: usize) -> Result<&[u8], Error> {
        if len > self.remainder_len() {
            return Err(Error::new(ErrorKind::InternalError, "failed to fill whole buffer"));
        }

        let buf   = self.inner.as_ref();
        let start = self.pos;
        let end   = start + len;

        self.pos += len;

        Ok(&buf[start..end])
    }

    pub fn deserialize_many_with<F: FnOnce(&mut Deserializer<T>) -> Result<(), Error>>(&mut self, deserialize_fn: F) -> Result<usize, Error> {
        let start = self.pos;
        
        deserialize_fn(self)?;
        
        let end = self.pos;
        let amt = end - start;
    
        Ok(amt)
    }

    #[inline]
    pub fn deserialize<V: Deserialize>(deserializer: &mut Deserializer<T>) -> Result<V, Error> {
        V::deserialize(deserializer)
    }
}

macro_rules! wrap_impl {
    ($ty:ident, $method:ident) => {
        impl Deserialize for $ty {
            #[inline]
            fn deserialize<T: AsRef<[u8]>>(deserializer: &mut Deserializer<T>) -> Result<Self, Error> {
                let v = deserializer.$method()?;
                Ok($ty(v))
            }
        }
    }
}

wrap_impl!(ContentKind,       deserialize_u8);
wrap_impl!(HandshakeKind,     deserialize_u8);
wrap_impl!(CompressionMethod, deserialize_u8);
wrap_impl!(ECPointFormat,     deserialize_u8);

wrap_impl!(ExtensionKind,   deserialize_u16);
wrap_impl!(CipherSuite,     deserialize_u16);
wrap_impl!(SupportedGroup,  deserialize_u16);
wrap_impl!(SignatureScheme, deserialize_u16);


impl Deserialize for ProtocolVersion {
    #[inline]
    fn deserialize<T: AsRef<[u8]>>(deserializer: &mut Deserializer<T>) -> Result<Self, Error> {
        let bytes = deserializer.deserialize_many(2)?;
        Ok(ProtocolVersion::new(bytes[0], bytes[1]))
    }
}

impl Deserialize for Random {
    #[inline]
    fn deserialize<T: AsRef<[u8]>>(deserializer: &mut Deserializer<T>) -> Result<Self, Error> {
        let mut buf = [0u8; 32];
        deserializer.deserialize_slice(&mut buf)?;
        Ok(Random(buf))
    }
}

impl Deserialize for SessionId {
    #[inline]
    fn deserialize<T: AsRef<[u8]>>(deserializer: &mut Deserializer<T>) -> Result<Self, Error> {
        let len = deserializer.deserialize_u8()? as usize;
        if len > SessionId::MAX_LEN {
            return Err(Error::from(ErrorKind::DecodeError));
        }

        let mut buf = [0u8; 32];

        deserializer.deserialize_slice(&mut buf[..len])?;

        Ok(SessionId {
            len: len as u8,
            data: buf,
        })
    }
}

