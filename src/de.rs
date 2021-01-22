use crate::wire::*;
use crate::error::{Error, ErrorKind};

use std::ops::FnMut;
use std::convert::TryFrom;
use std::ops::RangeInclusive;
use std::io::{self, Read, Write};


pub trait Deserialize: Sized {
    fn deserialize<T: AsRef<[u8]>>(deserializer: &mut Deserializer<T>) -> Result<Self, Error>;
}

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
    pub fn buf_len(&self) -> usize {
        self.inner.as_ref().len()
    }

    pub fn remainder_len(&self) -> usize {
        self.buf_len() - self.pos
    }

    pub fn deserialize_u8(&mut self) -> Result<u8, Error> {
        let bytes = self.deserialize_bytes(1)?;

        Ok(bytes[0])
    }

    pub fn deserialize_u16(&mut self) -> Result<u16, Error> {
        let mut buf = [0u8; 2];

        let bytes = self.deserialize_bytes(2)?;
        buf.copy_from_slice(bytes);

        Ok(u16::from_be_bytes(buf))
    }

    pub fn deserialize_u24(&mut self) -> Result<u32, Error> {
        let mut buf = [0u8; 4];

        let bytes = self.deserialize_bytes(3)?;
        buf[1..].copy_from_slice(bytes);

        Ok(u32::from_be_bytes(buf))
    }

    pub fn deserialize_u32(&mut self) -> Result<u32, Error> {
        let mut buf = [0u8; 4];

        let bytes = self.deserialize_bytes(4)?;
        buf.copy_from_slice(bytes);
        
        Ok(u32::from_be_bytes(buf))
    }

    pub fn deserialize_bytes<'a>(&'a mut self, amt: usize) -> Result<&'a [u8], Error> {
        if amt > self.remainder_len() {
            return Err(Error::new(ErrorKind::InternalError, "failed to fill whole buffer"));
        }
        
        let buf   = self.inner.as_ref();
        let start = self.pos;
        let end   = start + amt;

        self.pos += amt;

        Ok(&buf[start..end])
    }

    pub fn deserialize_len_value<F: FnOnce(&mut Deserializer<&[u8]>) -> Result<(), Error>>(&mut self, num_len_octets: usize, min_len: usize, max_len: usize, serialize_fn: F) -> Result<usize, Error> {
        let len_octets = match num_len_octets {
            1 => usize::try_from(self.deserialize_u8()?).unwrap(),
            2 => usize::try_from(self.deserialize_u16()?).unwrap(),
            3 => usize::try_from(self.deserialize_u24()?).unwrap(),
            4 => usize::try_from(self.deserialize_u32()?).unwrap(),
            _ => unreachable!("Oops ?"),
        };

        let payload = self.deserialize_bytes(len_octets)?;

        let mut deserializer = Deserializer::new(payload);
        serialize_fn(&mut deserializer)?;
        
        let remainder_len = deserializer.remainder_len();
        if remainder_len > 0 {
            trace!("[Deserializer] {} bytes droped.", remainder_len);
        }
        
        Ok(len_octets)
    }

    pub fn deserialize_vector<F: FnOnce(&mut Deserializer<&[u8]>) -> Result<(), Error>>(&mut self, len_range: RangeInclusive<usize>, serialize_fn: F) -> Result<usize, Error> {
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

        self.deserialize_len_value(num_len_octets, min_len, max_len, serialize_fn)
    }
}


fn de_example() -> Result<(), Box<dyn std::error::Error>> {
    let buffer = vec![0u8; 4096];
    let mut deserializer = Deserializer::new(&buffer);
    
    let bytes = deserializer.deserialize_bytes(10)?;

    let amt = deserializer.deserialize_vector(0..=32, |deserializer| {
        let bytes = deserializer.deserialize_bytes(10)?;

        let amt = deserializer.deserialize_vector(0..=32, |deserializer| {
            let val = deserializer.deserialize_u8()?;

            Ok(())
        })?;

        Ok(())
    })?;

    Ok(())
}