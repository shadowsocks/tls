use crate::wire::*;
use crate::error::{Error, ErrorKind};

use core::ops::RangeInclusive;


#[derive(Debug)]
pub struct Buffer<T> {
    inner: T,
    pos: usize,
}

impl<T> Buffer<T> {
    pub const fn new(inner: T) -> Buffer<T> {
        Buffer { pos: 0, inner }
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

impl<T: AsRef<[u8]>> Buffer<T> {
    pub fn remainder(&self) -> &[u8] {
        let buf = self.inner.as_ref();
        &buf[self.pos..]
    }

    #[inline]
    pub fn buf_len(&self) -> usize {
        self.inner.as_ref().len()
    }

    pub fn remainder_len(&self) -> usize {
        self.buf_len() - self.pos
    }
}

impl<T: AsMut<[u8]> + AsRef<[u8]>> Buffer<T> {
    pub fn serialize_u8(&mut self, v: u8) -> Result<(), Error> {
        self.serialize_slice(&[v])
    }

    pub fn serialize_u16(&mut self, v: u16) -> Result<(), Error> {
        self.serialize_slice(&v.to_be_bytes())
    }

    pub fn serialize_u24(&mut self, v: u32) -> Result<(), Error> {
        debug_assert!(v <= U24_MAX as u32);
        self.serialize_slice(&v.to_be_bytes()[1..])
    }

    pub fn serialize_u32(&mut self, v: u32) -> Result<(), Error> {
        self.serialize_slice(&v.to_be_bytes())
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

        Ok(())
    }

    #[inline]
    fn serialize_len_value<R, F: FnOnce(&mut Buffer<T>) -> Result<R, Error>>(
        &mut self, 
        num_len_octets: usize, 
        min_len: usize, 
        max_len: usize, 
        serialize_fn: F
    ) -> Result<R, Error> {
        if num_len_octets > self.remainder_len() {
            return Err(Error::new(ErrorKind::InternalError, "failed to write whole buffer"));
        }

        // NOTE: 先跳过 LEN 字段。
        self.pos += num_len_octets;
        
        let start = self.pos;
        let ret = serialize_fn(self)?;
        let end = self.pos;
        let amt = end - start;

        let buf = self.inner.as_mut();
        let len_pos = start - num_len_octets;

        if amt < min_len || amt > max_len {
            return Err(Error::new(ErrorKind::InternalError, 
                format!("the number of bytes of the vector is limited, The number of bytes must be within the range of {}..={}.", 
                    min_len, max_len)));
        }

        let len_octets = &(amt as u64).to_be_bytes()[core::mem::size_of::<u64>() - num_len_octets..];
        assert_eq!(len_octets.len(), num_len_octets);

        // NOTE: 返回填充 LEN 字段。
        buf[len_pos..len_pos + num_len_octets].copy_from_slice(len_octets);

        Ok(ret)
    }

    // NOTE: <2..2^16-2>
    //       <1..2^8-1>
    //       <0..32>
    pub fn serialize_vector<R, F: FnOnce(&mut Buffer<T>) -> Result<R, Error>>(
        &mut self, 
        len_range: RangeInclusive<usize>, 
        serialize_fn: F
    ) -> Result<R, Error> {
        const U16_MIN: usize =  U8_MAX + 1;
        const U24_MIN: usize = U16_MAX + 1;
        const U32_MIN: usize = U24_MAX + 1;

        let min_len = *(len_range.start());
        let max_len = *(len_range.end());
        debug_assert!(min_len <= max_len);

        let num_len_octets = match max_len {
                  0..=U8_MAX  => 1,
            U16_MIN..=U16_MAX => 2,
            #[cfg(any(target_pointer_width = "32", target_pointer_width = "64"))]
            U24_MIN..=U24_MAX => 3,
            #[cfg(any(target_pointer_width = "32", target_pointer_width = "64"))]
            U32_MIN..=U32_MAX => 4,
            // NOTE: RFC 上面没有这么大的数据结构需要序列化，所以我们直接 panic。
            _ => unreachable!("Oops ?"),
        };

        self.serialize_len_value(num_len_octets, min_len, max_len, serialize_fn)
    }

    pub fn serialize_with<F: FnOnce(&mut Buffer<T>) -> Result<(), Error>>(
        &mut self, 
        serialize_fn: F
    ) -> Result<usize, Error> {
        let start = self.pos;
        
        serialize_fn(self)?;

        let end = self.pos;
        let amt = end - start;

        Ok(amt)
    }
}


impl<T: AsRef<[u8]>> Buffer<T> {
    pub fn deserialize_u8(&mut self) -> Result<u8, Error> {
        let mut buf = [0u8; 1];
        self.deserialize_slice_and_copy(&mut buf)?;
        Ok(buf[0])
    }

    pub fn deserialize_u16(&mut self) -> Result<u16, Error> {
        let mut buf = [0u8; 2];
        self.deserialize_slice_and_copy(&mut buf)?;
        Ok(u16::from_be_bytes(buf))
    }

    pub fn deserialize_u24(&mut self) -> Result<u32, Error> {
        let mut buf = [0u8; 4];
        self.deserialize_slice_and_copy(&mut buf[1..])?;
        Ok(u32::from_be_bytes(buf))
    }

    pub fn deserialize_u32(&mut self) -> Result<u32, Error> {
        let mut buf = [0u8; 4];
        self.deserialize_slice_and_copy(&mut buf)?;
        Ok(u32::from_be_bytes(buf))
    }

    pub fn deserialize_slice(&mut self, len: usize) -> Result<&[u8], Error> {
        if len > self.remainder_len() {
            return Err(Error::new(ErrorKind::InternalError, "failed to fill whole buffer"));
        }

        let buf   = self.inner.as_ref();
        let start = self.pos;
        let end   = start + len;

        self.pos += len;

        Ok(&buf[start..end])
    }

    pub fn deserialize_slice_and_copy(&mut self, dst: &mut [u8]) -> Result<(), Error> {
        let slice = self.deserialize_slice(dst.len())?;
        dst.copy_from_slice(slice);
        Ok(())
    }

    pub fn deserialize_vector(&mut self, len_range: RangeInclusive<usize>) -> Result<&[u8], Error> {
        const U16_MIN: usize =  U8_MAX + 1;
        const U24_MIN: usize = U16_MAX + 1;
        const U32_MIN: usize = U24_MAX + 1;
        
        let min_len = *(len_range.start());
        let max_len = *(len_range.end());
        debug_assert!(min_len <= max_len);

        let len_octets = match max_len {
                  0..=U8_MAX  => self.deserialize_u8()? as usize,
            U16_MIN..=U16_MAX => self.deserialize_u16()? as usize,
            #[cfg(any(target_pointer_width = "32", target_pointer_width = "64"))]
            U24_MIN..=U24_MAX => self.deserialize_u24()? as usize,
            #[cfg(any(target_pointer_width = "32", target_pointer_width = "64"))]
            U32_MIN..=U32_MAX => self.deserialize_u32()? as usize,
            // NOTE: RFC 上面没有这么大的数据结构需要序列化，所以我们直接 panic。
            _ => unreachable!("Oops ?"),
        };

        let payload = self.deserialize_slice(len_octets)?;

        Ok(payload)
    }

    pub fn deserialize_with<F: FnOnce(&mut Buffer<T>) -> Result<(), Error>>(&mut self, deserialize_fn: F) -> Result<usize, Error> {
        let start = self.pos;
        
        deserialize_fn(self)?;
        
        let end = self.pos;
        let amt = end - start;
        
        Ok(amt)
    }
}

impl<T: AsMut<[u8]> + AsRef<[u8]>> Buffer<T> {
    #[inline]
    pub fn serialize<V: Serialize>(&mut self, val: &V) -> Result<(), Error> {
        val.serialize(self)
    }
}

impl<T: AsRef<[u8]>> Buffer<T> {
    #[inline]
    pub fn deserialize<'a, V: Deserialize<'a>>(&'a mut self) -> Result<V, Error> {
        V::deserialize(self)
    }
}

pub trait Serialize {
    fn serialize<T: AsMut<[u8]> + AsRef<[u8]>>(&self, serializer: &mut Buffer<T>) -> Result<(), Error>;
}

pub trait Deserialize<'de>: Sized {
    fn deserialize<T: AsRef<[u8]>>(deserializer: &'de mut Buffer<T>) -> Result<Self, Error>;
}

pub trait DeserializeOwned: for<'de> Deserialize<'de> { }


// ============= 序列化基础原始类型 ============
impl Serialize for u8 {
    #[inline]
    fn serialize<T: AsMut<[u8]> + AsRef<[u8]>>(&self, serializer: &mut Buffer<T>) -> Result<(), Error> {
        serializer.serialize_u8(*self)
    }
}
impl Serialize for u16 {
    #[inline]
    fn serialize<T: AsMut<[u8]> + AsRef<[u8]>>(&self, serializer: &mut Buffer<T>) -> Result<(), Error> {
        serializer.serialize_u16(*self)
    }
}
impl Serialize for u32 {
    #[inline]
    fn serialize<T: AsMut<[u8]> + AsRef<[u8]>>(&self, serializer: &mut Buffer<T>) -> Result<(), Error> {
        serializer.serialize_u32(*self)
    }
}
impl Serialize for () {
    #[inline]
    fn serialize<T: AsMut<[u8]> + AsRef<[u8]>>(&self, serializer: &mut Buffer<T>) -> Result<(), Error> {
        Ok(())
    }
}

// ============= 反序列化基础原始类型 ============
impl<'de> Deserialize<'de> for u8 {
    #[inline]
    fn deserialize<T: AsRef<[u8]>>(deserializer: &mut Buffer<T>) -> Result<Self, Error> {
        deserializer.deserialize_u8()
    }
}
impl DeserializeOwned for u8 { }

impl<'de> Deserialize<'de> for u16 {
    #[inline]
    fn deserialize<T: AsRef<[u8]>>(deserializer: &mut Buffer<T>) -> Result<Self, Error> {
        deserializer.deserialize_u16()
    }
}
impl DeserializeOwned for u16 { }

impl<'de> Deserialize<'de> for u32 {
    #[inline]
    fn deserialize<T: AsRef<[u8]>>(deserializer: &mut Buffer<T>) -> Result<Self, Error> {
        deserializer.deserialize_u32()
    }
}
impl DeserializeOwned for u32 { }

impl<'de> Deserialize<'de> for () {
    #[inline]
    fn deserialize<T: AsRef<[u8]>>(deserializer: &mut Buffer<T>) -> Result<Self, Error> {
        Ok(())
    }
}
impl DeserializeOwned for () { }


// ======================= 序列化复杂的数据（没有作为单独的 struct 存在的必要） ======================
impl<T: AsMut<[u8]> + AsRef<[u8]>> Buffer<T> {
    pub fn serialize_tls_plaintext_record<F: FnOnce(&mut Buffer<T>) -> Result<(), Error>>(
        &mut self,
        kind: ContentKind,
        version: ProtocolVersion,
        serialize_fn: F
    ) -> Result<(), Error> {
        // 5.1.  Record Layer
        // https://tools.ietf.org/html/rfc8446#section-5.1
        // struct {
        //     ContentType type;
        //     ProtocolVersion legacy_record_version;
        //     uint16 length;
        //     opaque fragment[TLSPlaintext.length];
        // } TLSPlaintext;
        self.serialize_slice(&[
            kind.0, version.major, version.minor,
        ])?;
        self.serialize_vector(0..=U16_MAX, serialize_fn)
    }

    pub fn serialize_handshake<F: FnOnce(&mut Buffer<T>) -> Result<(), Error>>(
        &mut self,
        kind: HandshakeKind,
        serialize_fn: F
    ) -> Result<(), Error> {
        // B.3.  Handshake Protocol
        // https://tools.ietf.org/html/rfc8446#appendix-B.3
        // struct {
        //     HandshakeType msg_type;    /* handshake type */
        //     uint24 length;             /* bytes in message */
        //     select (Handshake.msg_type) {
        //         case client_hello:          ClientHello;
        //         case server_hello:          ServerHello;
        //         case end_of_early_data:     EndOfEarlyData;
        //         case encrypted_extensions:  EncryptedExtensions;
        //         case certificate_request:   CertificateRequest;
        //         case certificate:           Certificate;
        //         case certificate_verify:    CertificateVerify;
        //         case finished:              Finished;
        //         case new_session_ticket:    NewSessionTicket;
        //         case key_update:            KeyUpdate;
        //     };
        // } Handshake;
        self.serialize_u8(kind.0)?;
        self.serialize_vector(0..=U24_MAX, serialize_fn)
    }

    pub fn serialize_extension<F: FnOnce(&mut Buffer<T>) -> Result<(), Error>>(
        &mut self,
        kind: ExtensionKind,
        serialize_fn: F
    ) -> Result<(), Error> {
        // B.3.1.  Key Exchange Messages
        // https://tools.ietf.org/html/rfc8446#appendix-B.3.1
        // struct {
        //     ExtensionType extension_type;
        //     opaque extension_data<0..2^16-1>;
        // } Extension;

        // Extension Kind
        self.serialize_slice(&kind.to_be_bytes())?;
        // Extension Data
        // <0..2^16-1>
        self.serialize_vector(0..=U16_MAX, serialize_fn)
    }

    pub fn serialize_ext_supported_versions(&mut self, supported_versions: &[ProtocolVersion]) -> Result<(), Error> {
        // 4.2.1.  Supported Versions
        // https://tools.ietf.org/html/rfc8446#section-4.2.1
        self.serialize_extension(ExtensionKind::SUPPORTED_VERSIONS, |serializer| {
            // ProtocolVersion versions<2..254>;
            serializer.serialize_vector(2..=254, |serializer| {
            for version in supported_versions.iter() {
                    serializer.serialize_slice(&version.to_be_bytes())?;
                }

                Ok(())
            })
        })
    }

    pub fn serialize_ext_selected_version(&mut self, selected_version: ProtocolVersion) -> Result<(), Error> {
        self.serialize_extension(ExtensionKind::SUPPORTED_VERSIONS, |serializer| {
            serializer.serialize_slice(&selected_version.to_be_bytes())
        })
    }

    pub fn serialize_ext_server_names<S: AsRef<str>>(&mut self, server_names: &[S]) -> Result<(), Error> {
        // 3.  Server Name Indication
        // https://tools.ietf.org/html/rfc6066#section-3
        self.serialize_extension(ExtensionKind::SERVER_NAME, |serializer| {
            // ServerName server_name_list<1..2^16-1>
            serializer.serialize_vector(1..=U16_MAX, |serializer| {
                for server_name in server_names.iter() {
                    // host name kind
                    serializer.serialize_u8(ServerNameKind::HOST_NAME.0)?;
                    // opaque HostName<1..2^16-1>;
                    // host name slice
                    serializer.serialize_vector(1..=U16_MAX, |serializer| {
                        serializer.serialize_slice(server_name.as_ref().as_bytes())
                    })?;
                }

                Ok(())
            })
        })
    }

    pub fn serialize_ext_application_protos<B: AsRef<[u8]>>(&mut self, application_protos: &[B]) -> Result<(), Error> {
        // 3.1.  The Application-Layer Protocol Negotiation Extension
        // https://tools.ietf.org/html/rfc7301#section-3.1
        self.serialize_extension(ExtensionKind::APPLICATION_LAYER_PROTOCOL_NEGOTIATION, |serializer| {
            // ProtocolName protocol_name_list<2..2^16-1>
            serializer.serialize_vector(2..=U16_MAX, |serializer| {
                for application_proto in application_protos.iter() {
                    // opaque ProtocolName<1..2^8-1>;
                    serializer.serialize_vector(1..=U8_MAX, |serializer| {
                        serializer.serialize_slice(application_proto.as_ref())
                    })?;
                }

                Ok(())
            })
        })
    }

    pub fn serialize_ext_selected_application_proto<B: AsRef<[u8]>>(&mut self, application_proto: B) -> Result<(), Error> {
        self.serialize_extension(ExtensionKind::APPLICATION_LAYER_PROTOCOL_NEGOTIATION, |serializer| {
            serializer.serialize_vector(1..=U8_MAX, |serializer| {
                serializer.serialize_slice(application_proto.as_ref())
            })
        })
    }

    pub fn serialize_ext_supported_groups(&mut self, supported_groups: &[SupportedGroup]) -> Result<(), Error> {
        // 4.2.7.  Supported Groups
        // https://tools.ietf.org/html/rfc8446#section-4.2.7
        self.serialize_extension(ExtensionKind::SUPPORTED_GROUPS, |serializer| {
            // NamedGroup named_group_list<2..2^16-1>;
            serializer.serialize_vector(2..=U16_MAX, |serializer| {
                for group in supported_groups.iter() {
                    serializer.serialize_slice(&group.to_be_bytes())?;
                }

                Ok(())
            })
        })
    }

    pub fn serialize_ext_signature_algorithms(&mut self, signature_algorithms: &[SignatureScheme]) -> Result<(), Error> {
        // 4.2.3.  Signature Algorithms
        // https://tools.ietf.org/html/rfc8446#section-4.2.3
        self.serialize_extension(ExtensionKind::SIGNATURE_ALGORITHMS, |serializer| {
            // SignatureScheme supported_signature_algorithms<2..2^16-2>;
            serializer.serialize_vector(2..=U16_MAX - 1, |serializer| {
                for signature_algorithm in signature_algorithms.iter() {
                    serializer.serialize_slice(&signature_algorithm.to_be_bytes())?;
                }

                Ok(())
            })
        })
    }

    pub fn serialize_ext_ec_point_foramts(&mut self, ec_point_foramts: &[ECPointFormat]) -> Result<(), Error> {
        // 5.1.2.  Supported Point Formats Extension
        // https://tools.ietf.org/html/rfc8422#section-5.1.2
        self.serialize_extension(ExtensionKind::EC_POINT_FORMATS, |serializer| {
            // ECPointFormat ec_point_format_list<1..2^8-1>
            serializer.serialize_vector(1..=U8_MAX, |serializer| {
                for ec_point_foramt in ec_point_foramts.iter() {
                    serializer.serialize_slice(&ec_point_foramt.to_be_bytes())?;
                }

                Ok(())
            })
        })
    }

    pub fn serialize_ext_key_shares<B: AsRef<[u8]>>(&mut self, key_shares: &[KeyShareEntry<B>]) -> Result<(), Error> {
        // 4.2.8.  Key Share
        // https://tools.ietf.org/html/rfc8446#section-4.2.8
        self.serialize_extension(ExtensionKind::KEY_SHARE, |serializer| {
            // struct {
            //     KeyShareEntry client_shares<0..2^16-1>;
            // } KeyShareClientHello;
            serializer.serialize_vector(0..=U16_MAX, |serializer| {
                for key_share_entry in key_shares.iter() {
                    // write_ext_key_share_entry(serializer, &key_share_entry)?;

                    // struct {
                    //     NamedGroup group;
                    //     opaque key_exchange<1..2^16-1>;
                    // } KeyShareEntry;
                    serializer.serialize_slice(&key_share_entry.group.to_be_bytes())?;
                    serializer.serialize_vector(1..=U16_MAX, |serializer| {
                        serializer.serialize_slice(key_share_entry.key.as_ref())
                    })?;
                }

                Ok(())
            })
        })
    }

    pub fn serialize_ext_key_share<B: AsRef<[u8]>>(&mut self, key_share_entry: &KeyShareEntry<B>) -> Result<(), Error> {
        self.serialize_extension(ExtensionKind::KEY_SHARE, |serializer| {
            // struct {
            //     KeyShareEntry server_share;
            // } KeyShareServerHello;
            // 
            // struct {
            //     NamedGroup group;
            //     opaque key_exchange<1..2^16-1>;
            // } KeyShareEntry;
            serializer.serialize_slice(&key_share_entry.group.to_be_bytes())?;
            serializer.serialize_vector(1..=U16_MAX, |serializer| {
                serializer.serialize_slice(key_share_entry.key.as_ref())
            })
        })
    }
}

