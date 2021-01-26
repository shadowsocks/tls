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
        debug_assert!(v <= U24_MAX as u32);

        self.serialize_slice(&v.to_be_bytes()[1..])
    }

    pub fn serialize_u32(&mut self, v: u32) -> Result<(), Error> {
        self.serialize_slice(&v.to_be_bytes())
    }

    #[inline]
    fn serialize_len_value<R, F: FnOnce(&mut Serializer<T>) -> Result<R, Error>>(
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
    pub fn serialize_vector<R, F: FnOnce(&mut Serializer<T>) -> Result<R, Error>>(
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

    pub fn serialize_many_with<F: FnOnce(&mut Serializer<T>) -> Result<(), Error>>(
        &mut self, 
        serialize_fn: F
    ) -> Result<usize, Error> {
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


impl Serialize for () {
    fn serialize<T: AsMut<[u8]> + AsRef<[u8]>>(&self, serializer: &mut Serializer<T>) -> Result<(), Error> {
        Ok(())
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




pub fn write_tls_plaintext_record<T: AsMut<[u8]> + AsRef<[u8]>, F: FnOnce(&mut Serializer<T>) -> Result<(), Error>>(
    serializer: &mut Serializer<T>, 
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
    serializer.serialize_slice(&[
        kind.0, version.major, version.minor,
    ])?;
    serializer.serialize_vector(0..=u16::MAX as usize, serialize_fn)
}

pub fn write_extension<T: AsMut<[u8]> + AsRef<[u8]>, F: FnOnce(&mut Serializer<T>) -> Result<(), Error>>(
    serializer: &mut Serializer<T>, 
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
    serializer.serialize_slice(&kind.to_be_bytes())?;
    // Extension Data
    // <0..2^16-1>
    serializer.serialize_vector(0..=65535, serialize_fn)
}


pub fn write_ext_supported_versions<T: AsMut<[u8]> + AsRef<[u8]>>(
    serializer: &mut Serializer<T>, 
    supported_versions: &[ProtocolVersion]
) -> Result<(), Error> {
    // 4.2.1.  Supported Versions
    // https://tools.ietf.org/html/rfc8446#section-4.2.1
    // 
    // struct {
    //     select (Handshake.msg_type) {
    //         case client_hello:
    //             ProtocolVersion versions<2..254>;
    // 
    //         case server_hello: /* and HelloRetryRequest */
    //             ProtocolVersion selected_version;
    //     };
    // } SupportedVersions;
    write_extension(serializer, ExtensionKind::SUPPORTED_VERSIONS, |serializer| {
        // protocol versions
        serializer.serialize_vector(2..=254, |serializer| {
            for version in supported_versions.iter() {
                serializer.serialize_slice(&version.to_be_bytes())?;
            }

            Ok(())
        })
    })
}

pub fn write_ext_selected_version<T: AsMut<[u8]> + AsRef<[u8]>>(
    serializer: &mut Serializer<T>, 
    selected_version: ProtocolVersion
) -> Result<(), Error> {
    write_extension(serializer, ExtensionKind::SUPPORTED_VERSIONS, |serializer| {
        serializer.serialize_slice(&selected_version.to_be_bytes())
    })
}

pub fn write_ext_server_names<S: AsRef<str>, T: AsMut<[u8]> + AsRef<[u8]>>(
    serializer: &mut Serializer<T>, 
    server_names: &[S]
) -> Result<(), Error> {
    // 3.  Server Name Indication
    // https://tools.ietf.org/html/rfc6066#section-3
    // 
    // struct {
    //     NameType name_type;
    //     select (name_type) {
    //         case host_name: HostName;
    //     } name;
    // } ServerName;
    // 
    // enum {
    //     host_name(0), (255)
    // } NameType;
    // 
    // opaque HostName<1..2^16-1>;
    // 
    // struct {
    //     ServerName server_name_list<1..2^16-1>
    // } ServerNameList;
    write_extension(serializer, ExtensionKind::SERVER_NAME, |serializer| {
        // server names
        serializer.serialize_vector(1..=65535, |serializer| {
            for server_name in server_names.iter() {
                // host name kind
                serializer.serialize_u8(ServerNameKind::HOST_NAME.0)?;
                // host name slice
                serializer.serialize_vector(1..=65535, |serializer| {
                    serializer.serialize_slice(server_name.as_ref().as_bytes())
                })?;
            }

            Ok(())
        })
    })
}

pub fn write_ext_application_protos<B: AsRef<[u8]>, T: AsMut<[u8]> + AsRef<[u8]>>(
    serializer: &mut Serializer<T>, 
    application_protos: &[B]
) -> Result<(), Error> {
    // 3.1.  The Application-Layer Protocol Negotiation Extension
    // https://tools.ietf.org/html/rfc7301#section-3.1
    // 
    // opaque ProtocolName<1..2^8-1>;
    // 
    // struct {
    //     ProtocolName protocol_name_list<2..2^16-1>
    // } ProtocolNameList;
    write_extension(serializer, ExtensionKind::APPLICATION_LAYER_PROTOCOL_NEGOTIATION, |serializer| {
        serializer.serialize_vector(2..=65535, |serializer| {
            for application_proto in application_protos.iter() {
                serializer.serialize_vector(1..=255, |serializer| {
                    serializer.serialize_slice(application_proto.as_ref())
                })?;
            }

            Ok(())
        })
    })
}

pub fn write_ext_selected_application_proto<B: AsRef<[u8]>, T: AsMut<[u8]> + AsRef<[u8]>>(
    serializer: &mut Serializer<T>, 
    application_proto: B
) -> Result<(), Error> {
    write_extension(serializer, ExtensionKind::APPLICATION_LAYER_PROTOCOL_NEGOTIATION, |serializer| {
        serializer.serialize_vector(1..=255, |serializer| {
            serializer.serialize_slice(application_proto.as_ref())
        })
    })
}

pub fn write_ext_supported_groups<T: AsMut<[u8]> + AsRef<[u8]>>(
    serializer: &mut Serializer<T>, 
    supported_groups: &[SupportedGroup]
) -> Result<(), Error> {
    // 4.2.7.  Supported Groups
    // https://tools.ietf.org/html/rfc8446#section-4.2.7
    // 
    // enum {
    //     /* Elliptic Curve Groups (ECDHE) */
    //     secp256r1(0x0017), secp384r1(0x0018), secp521r1(0x0019),
    //     x25519(0x001D), x448(0x001E),
    // 
    //     /* Finite Field Groups (DHE) */
    //     ffdhe2048(0x0100), ffdhe3072(0x0101), ffdhe4096(0x0102),
    //     ffdhe6144(0x0103), ffdhe8192(0x0104),
    // 
    //     /* Reserved Code Points */
    //     ffdhe_private_use(0x01FC..0x01FF),
    //     ecdhe_private_use(0xFE00..0xFEFF),
    //     (0xFFFF)
    // } NamedGroup;
    // 
    // struct {
    //     NamedGroup named_group_list<2..2^16-1>;
    // } NamedGroupList;
    write_extension(serializer, ExtensionKind::SUPPORTED_GROUPS, |serializer| {
        serializer.serialize_vector(2..=65535, |serializer| {
            for group in supported_groups.iter() {
                serializer.serialize_slice(&group.to_be_bytes())?;
            }

            Ok(())
        })
    })
}

pub fn write_ext_signature_algorithms<T: AsMut<[u8]> + AsRef<[u8]>>(
    serializer: &mut Serializer<T>, 
    signature_algorithms: &[SignatureScheme]
) -> Result<(), Error> {
    // 4.2.3.  Signature Algorithms
    // https://tools.ietf.org/html/rfc8446#section-4.2.3
    // 
    // enum {
    //     /* RSASSA-PKCS1-v1_5 algorithms */
    //     rsa_pkcs1_sha256(0x0401),
    //     rsa_pkcs1_sha384(0x0501),
    //     rsa_pkcs1_sha512(0x0601),
    // 
    //     /* ECDSA algorithms */
    //     ecdsa_secp256r1_sha256(0x0403),
    //     ecdsa_secp384r1_sha384(0x0503),
    //     ecdsa_secp521r1_sha512(0x0603),
    // 
    //     /* RSASSA-PSS algorithms with public key OID rsaEncryption */
    //     rsa_pss_rsae_sha256(0x0804),
    //     rsa_pss_rsae_sha384(0x0805),
    //     rsa_pss_rsae_sha512(0x0806),
    // 
    //     /* EdDSA algorithms */
    //     ed25519(0x0807),
    //     ed448(0x0808),
    // 
    //     /* RSASSA-PSS algorithms with public key OID RSASSA-PSS */
    //     rsa_pss_pss_sha256(0x0809),
    //     rsa_pss_pss_sha384(0x080a),
    //     rsa_pss_pss_sha512(0x080b),
    // 
    //     /* Legacy algorithms */
    //     rsa_pkcs1_sha1(0x0201),
    //     ecdsa_sha1(0x0203),
    // 
    //     /* Reserved Code Points */
    //     private_use(0xFE00..0xFFFF),
    //     (0xFFFF)
    // } SignatureScheme;
    // 
    // struct {
    //     SignatureScheme supported_signature_algorithms<2..2^16-2>;
    // } SignatureSchemeList;
    write_extension(serializer, ExtensionKind::SIGNATURE_ALGORITHMS, |serializer| {
        serializer.serialize_vector(2..=65534, |serializer| {
            for signature_algorithm in signature_algorithms.iter() {
                serializer.serialize_slice(&signature_algorithm.to_be_bytes())?;
            }

            Ok(())
        })
    })
}

pub fn write_ext_ec_point_foramts<T: AsMut<[u8]> + AsRef<[u8]>>(
    serializer: &mut Serializer<T>, 
    ec_point_foramts: &[ECPointFormat]
) -> Result<(), Error> {
    // 5.1.2.  Supported Point Formats Extension
    // https://tools.ietf.org/html/rfc8422#section-5.1.2
    // 
    // enum {
    //     uncompressed (0),
    //     deprecated (1..2),
    //     reserved (248..255)
    // } ECPointFormat;
    // struct {
    //     ECPointFormat ec_point_format_list<1..2^8-1>
    // } ECPointFormatList;
    write_extension(serializer, ExtensionKind::EC_POINT_FORMATS, |serializer| {
        serializer.serialize_vector(1..=255, |serializer| {
            for ec_point_foramt in ec_point_foramts.iter() {
                serializer.serialize_slice(&ec_point_foramt.to_be_bytes())?;
            }

            Ok(())
        })
    })
}

fn write_ext_key_share_entry<B: AsRef<[u8]>, T: AsMut<[u8]> + AsRef<[u8]>>(
    serializer: &mut Serializer<T>, 
    key_share_entry: &KeyShareEntry<B>
) -> Result<(), Error> {
    serializer.serialize_slice(&key_share_entry.group.to_be_bytes())?;
    serializer.serialize_vector(1..=65535, |serializer| {
        serializer.serialize_slice(key_share_entry.key.as_ref())
    })
}

pub fn write_ext_key_shares<B: AsRef<[u8]>, T: AsMut<[u8]> + AsRef<[u8]>>(
    serializer: &mut Serializer<T>, 
    key_shares: &[KeyShareEntry<B>]
) -> Result<(), Error> {
    // 4.2.8.  Key Share
    // https://tools.ietf.org/html/rfc8446#section-4.2.8
    // 
    // struct {
    //     NamedGroup group;
    //     opaque key_exchange<1..2^16-1>;
    // } KeyShareEntry;
    // 
    // struct {
    //     KeyShareEntry client_shares<0..2^16-1>;
    // } KeyShareClientHello;
    // 
    // struct {
    //     KeyShareEntry server_share;
    // } KeyShareServerHello;
    // 
    // struct {
    //     NamedGroup selected_group;
    // } KeyShareHelloRetryRequest;
    write_extension(serializer, ExtensionKind::KEY_SHARE, |serializer| {
        serializer.serialize_vector(0..=65535, |serializer| {
            for key_share_entry in key_shares.iter() {
                write_ext_key_share_entry(serializer, &key_share_entry)?;
            }

            Ok(())
        })
    })
}

pub fn write_ext_key_share<B: AsRef<[u8]>, T: AsMut<[u8]> + AsRef<[u8]>>(
    serializer: &mut Serializer<T>, 
    key_share: &KeyShareEntry<B>
) -> Result<(), Error> {
    write_extension(serializer, ExtensionKind::KEY_SHARE, |serializer| {
        write_ext_key_share_entry(serializer, key_share)
    })
}

pub fn write_handshake<T: AsMut<[u8]> + AsRef<[u8]>, F: FnOnce(&mut Serializer<T>) -> Result<(), Error>>(
    serializer: &mut Serializer<T>, 
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
    serializer.serialize_u8(kind.0)?;
    serializer.serialize_vector(0..=U24_MAX, serialize_fn)
}
