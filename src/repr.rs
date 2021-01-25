use crate::wire::*;
use crate::serde::*;
use crate::error::{Error, ErrorKind};
use crate::crypto::X25519PublicKey;

use core::marker::PhantomData;


// B.3.1.  Key Exchange Messages
// https://tools.ietf.org/html/rfc8446#appendix-B.3.1
// struct {
//     ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
//     Random random;
//     opaque legacy_session_id<0..32>;
//     CipherSuite cipher_suites<2..2^16-2>;
//     opaque legacy_compression_methods<1..2^8-1>;
//     Extension extensions<8..2^16-1>;
// } ClientHello;
#[derive(Debug)]
pub struct HandshakeClientHello<S, B, CS, CM, V, N, P, G, SIG, ECP>
where 
    S: AsRef<str>, 
    B: AsRef<[u8]>, 
    CS: AsRef<[CipherSuite]>, 
    CM: AsRef<[CompressionMethod]>, 
    V: AsRef<[ProtocolVersion]>,
    N: AsRef<[S]>, 
    P: AsRef<[B]>, 
    G: AsRef<[SupportedGroup]>,
    SIG: AsRef<[SignatureScheme]>,
    ECP: AsRef<[ECPointFormat]>,
{
    pub version: ProtocolVersion,
    pub random : Random,
    pub session_id: SessionId,
    pub cipher_suites: CS,
    pub compression_methods: CM,

    pub ext_supported_versions: V,
    pub ext_server_names: N,
    pub ext_application_protocols: P,
    pub ext_supported_groups: G,
    pub ext_signature_algorithms: SIG,
    pub ext_ec_point_formats: ECP,
    pub ext_key_share_x25519: Option<X25519PublicKey>,

    pub(crate) _s: PhantomData<S>,
    pub(crate) _b: PhantomData<B>,
}

pub type HandshakeClientHelloOwned = HandshakeClientHello<String, Vec<u8>, 
    Vec<CipherSuite>, Vec<CompressionMethod>, Vec<ProtocolVersion>, Vec<String>, Vec<Vec<u8>>, 
    Vec<SupportedGroup>, Vec<SignatureScheme>, Vec<ECPointFormat>>;


impl<S, B, CS, CM, V, N, P, G, SIG, ECP> Serialize for HandshakeClientHello<S, B, CS, CM, V, N, P, G, SIG, ECP>
where
    S: AsRef<str>, 
    B: AsRef<[u8]>, 
    CS: AsRef<[CipherSuite]>, 
    CM: AsRef<[CompressionMethod]>, 
    V: AsRef<[ProtocolVersion]>,
    N: AsRef<[S]>, 
    P: AsRef<[B]>, 
    G: AsRef<[SupportedGroup]>,
    SIG: AsRef<[SignatureScheme]>,
    ECP: AsRef<[ECPointFormat]>,
{
    fn serialize<T: AsMut<[u8]> + AsRef<[u8]>>(&self, serializer: &mut Serializer<T>) -> Result<(), Error> {
        let supported_cipher_suites = self.cipher_suites.as_ref();
        let compression_methods = self.compression_methods.as_ref();

        serializer.serialize_slice(&self.version.to_be_bytes())?;
        serializer.serialize_slice(self.random.as_bytes())?;

        // <0..32>
        serializer.serialize_vector(0..=32, |serializer| serializer.serialize_slice(self.session_id.as_bytes()))?;

        // <2..2^16-2>
        serializer.serialize_vector(2..=65534, |serializer| {
            for cipher_suite in supported_cipher_suites.iter() {
                serializer.serialize_slice(&cipher_suite.to_be_bytes())?;
            }

            Ok(())
        })?;

        // <1..2^8-1>
        serializer.serialize_vector(1..=255, |serializer| {
            for cm in compression_methods.iter() {
                serializer.serialize_slice(&cm.to_be_bytes())?;
            }
            Ok(())
        })?;

        // Extension extensions<8..2^16-1>;
        serializer.serialize_vector(8..=65535, |serializer| {
            let supported_versions = self.ext_supported_versions.as_ref();
            let server_names = self.ext_server_names.as_ref();
            let application_protocols = self.ext_application_protocols.as_ref();
            let signature_algorithms = self.ext_signature_algorithms.as_ref();
            let supported_groups = self.ext_supported_groups.as_ref();
            let ec_point_formats = self.ext_ec_point_formats.as_ref();

            write_ext_supported_versions(serializer, supported_versions)?;

            if !server_names.is_empty() {
                write_ext_server_names(serializer, server_names)?;
            }
            
            if !application_protocols.is_empty() {
                write_ext_application_protos(serializer, application_protocols)?;
            }

            if !signature_algorithms.is_empty() {
                write_ext_signature_algorithms(serializer, signature_algorithms)?;
            }

            if !supported_groups.is_empty() {
                write_ext_supported_groups(serializer, supported_groups)?;
            }

            if !ec_point_formats.is_empty() {
                write_ext_ec_point_foramts(serializer, ec_point_formats)?;
            }
            
            if let Some(x25519_public_key) = &self.ext_key_share_x25519 {
                let client_key_shares: &[KeyShareEntry<&[u8]>] = &[
                    KeyShareEntry { group: SupportedGroup::X25519, key: x25519_public_key.as_bytes() },
                ];
                write_ext_key_shares(serializer, client_key_shares)?;
            }
            
            // session ticket
            // encrypt-then-mac
            // extended master secret
            Ok(())
        })
    }
}


// B.3.1.  Key Exchange Messages
// https://tools.ietf.org/html/rfc8446#appendix-B.3.1
// struct {
//     ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
//     Random random;
//     opaque legacy_session_id_echo<0..32>;
//     CipherSuite cipher_suite;
//     uint8 legacy_compression_method = 0;
//     Extension extensions<6..2^16-1>;
// } ServerHello;
#[derive(Debug)]
pub struct HandshakeServerHello<B: AsRef<[u8]>> {
    pub version: ProtocolVersion,
    pub random : Random,
    pub session_id: SessionId,
    pub cipher_suite: CipherSuite,
    pub compression_method: CompressionMethod,

    pub ext_selected_version: Option<ProtocolVersion>,
    pub ext_selected_application_protocol: Option<B>,
    pub ext_key_share_x25519: Option<X25519PublicKey>,
}

pub type HandshakeServerHelloOwned = HandshakeServerHello<Vec<u8>>;

impl<B: AsRef<[u8]>> Serialize for HandshakeServerHello<B> {
    fn serialize<T: AsMut<[u8]> + AsRef<[u8]>>(&self, serializer: &mut Serializer<T>) -> Result<(), Error> {
        // write_handshake(serializer, HandshakeKind::SERVER_HELLO, |serializer| {
            serializer.serialize_slice(&self.version.to_be_bytes())?;
            serializer.serialize_slice(self.random.as_bytes())?;

            // <0..32>
            serializer.serialize_vector(0..=32, |serializer| serializer.serialize_slice(self.session_id.as_bytes()))?;

            serializer.serialize_slice(&self.cipher_suite.to_be_bytes())?;
            serializer.serialize_slice(&self.compression_method.to_be_bytes())?;

            // extensions<6..2^16-1>
            serializer.serialize_vector(6..=65535, |serializer| {
                if let Some(selected_version) = self.ext_selected_version {
                    write_ext_selected_version(serializer, selected_version)?;
                }
                
                if let Some(ref selected_application_protocol) = self.ext_selected_application_protocol {
                    write_ext_selected_application_proto(serializer, selected_application_protocol)?;
                }
                
                if let Some(ref x25519_public_key) = self.ext_key_share_x25519 {
                    let server_key_share: KeyShareEntry<&[u8]> = KeyShareEntry {
                        group: SupportedGroup::X25519,
                        key: x25519_public_key.as_bytes(),
                    };

                    write_ext_key_share(serializer, &server_key_share)?;
                }

                Ok(())
            })

            // Ok(())
        // })
    }
}

impl Deserialize for HandshakeServerHelloOwned {
    fn deserialize<T: AsRef<[u8]>>(deserializer: &mut Deserializer<T>) -> Result<Self, Error> {
        let version = deserializer.deserialize::<ProtocolVersion>()?;
        let random = deserializer.deserialize::<Random>()?;
        let session_id = deserializer.deserialize::<SessionId>()?;
        let cipher_suite = deserializer.deserialize::<CipherSuite>()?;
        let compression_method = deserializer.deserialize::<CompressionMethod>()?;

        let mut ext_selected_version = None;
        let mut ext_selected_application_protocol = None;
        let mut ext_key_share_x25519 = None;

        // extensions<6..2^16-1>
        let exts_payload = deserializer.deserialize_vector(6..=65535)?;
        let mut deserializer = Deserializer::new(exts_payload);
        loop {
            let rlen = deserializer.remainder_len();
            if rlen == 0 {
                break;
            }

            let kind = deserializer.deserialize::<ExtensionKind>()?;
            let payload = deserializer.deserialize_vector(0..=65535)?;
            let mut deserializer = Deserializer::new(payload);
            match kind {
                ExtensionKind::SUPPORTED_VERSIONS => {
                    ext_selected_version = Some(deserializer.deserialize::<ProtocolVersion>()?);
                },
                ExtensionKind::KEY_SHARE => {
                    let group = deserializer.deserialize::<SupportedGroup>()?;
                    let key = deserializer.deserialize_vector(1..=65535)?;
                    match group {
                        SupportedGroup::X25519 => {
                            if key.len() != X25519PublicKey::KEY_LEN {
                                return Err(Error::from(ErrorKind::DecodeError));
                            }
                            ext_key_share_x25519 = Some(X25519PublicKey::from(key));
                        },
                        _ => {
                            // ignore
                        }
                    }
                },
                ExtensionKind::APPLICATION_LAYER_PROTOCOL_NEGOTIATION => {
                    let payload = deserializer.deserialize_vector(1..=255)?;
                    ext_selected_application_protocol = Some(payload.to_vec());
                },
                _ => {
                    // ignore
                }
            }
        }

        Ok(Self {
            version, random, session_id, cipher_suite, compression_method,
            ext_selected_version, ext_selected_application_protocol, ext_key_share_x25519,
        })
    }
}


impl<C: Serialize> Serialize for TlsPlaintext<C> {
    fn serialize<T: AsMut<[u8]> + AsRef<[u8]>>(&self, serializer: &mut Serializer<T>) -> Result<(), Error> {
        serializer.serialize(&self.kind)?;
        serializer.serialize(&self.version)?;
        serializer.serialize_vector(0..=U16_MAX, |serializer| serializer.serialize(&self.content))
    }
}

impl<C: Deserialize> Deserialize for TlsPlaintext<C> {
    fn deserialize<T: AsRef<[u8]>>(deserializer: &mut Deserializer<T>) -> Result<Self, Error> {
        let kind = deserializer.deserialize::<ContentKind>()?;
        let version = deserializer.deserialize::<ProtocolVersion>()?;
        
        let payload = deserializer.deserialize_vector(0..=U16_MAX)?;

        let mut deserializer = Deserializer::new(payload);
        let content = deserializer.deserialize::<C>()?;

        Ok(Self { kind, version, content })
    }
}


impl<M: Serialize> Serialize for Handshake<M> {
    fn serialize<T: AsMut<[u8]> + AsRef<[u8]>>(&self, serializer: &mut Serializer<T>) -> Result<(), Error> {
        serializer.serialize(&self.kind)?;
        serializer.serialize_vector(0..=U24_MAX, |serializer| serializer.serialize(&self.message))
    }
}

impl<M: Deserialize> Deserialize for Handshake<M> {
    fn deserialize<T: AsRef<[u8]>>(deserializer: &mut Deserializer<T>) -> Result<Self, Error> {
        let kind = deserializer.deserialize::<HandshakeKind>()?;
        let payload = deserializer.deserialize_vector(0..=U24_MAX)?;

        let mut deserializer = Deserializer::new(payload);
        let message = deserializer.deserialize::<M>()?;

        Ok(Self { kind, message })
    }
}

pub type Ch = TlsPlaintext<Handshake<HandshakeClientHelloOwned>>;
