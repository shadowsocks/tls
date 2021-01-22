use crate::wire::*;
use crate::x25519::X25519SecretKey;
use crate::x25519::X25519PublicKey;
use crate::error::{Error, ErrorKind};
use crate::ser::Serializer;
use crate::ser::write_tls_plaintext_record;

use std::convert::TryFrom;
use std::io::{self, Read, Write, Seek, SeekFrom};


#[derive(Debug, Clone)]
pub struct HandshakeConfig {
    pub server_names: Vec<String>,
    pub supported_versions: Vec<ProtocolVersion>,
    pub application_protocols: Vec<Vec<u8>>,
    pub supported_cipher_suites: Vec<CipherSuite>,
    pub supported_groups: Vec<SupportedGroup>,
    pub signature_algorithms: Vec<SignatureScheme>,
    pub ec_point_formats: Vec<ECPointFormat>,
}

impl HandshakeConfig {
    pub fn add_server_name(&mut self, server_name: &str) {
        self.server_names.push(server_name.to_string());
    }

    pub fn add_application_protocol(&mut self, application_protocol: &[u8]) {
        self.application_protocols.push(application_protocol.to_vec());
    }

    pub fn add_cipher_suite(&mut self, cipher_suite: CipherSuite) {
        self.supported_cipher_suites.push(cipher_suite);
    }
}

impl Default for HandshakeConfig {
    fn default() -> Self {
        HandshakeConfig {
            server_names: vec![],
            supported_versions: vec![
                ProtocolVersion::TLS_V1_3,
                ProtocolVersion::TLS_V1_2, 
            ],
            application_protocols: vec![],
            supported_cipher_suites: vec![
                CipherSuite::TLS_AES_128_GCM_SHA256,       // 0x13, 0x01
                CipherSuite::TLS_CHACHA20_POLY1305_SHA256, // 0x13, 0x03
            ],
            supported_groups: vec![
                // SupportedGroup::X448,
                SupportedGroup::X25519,
            ],
            signature_algorithms: vec![
                SignatureScheme::ED25519,
            ],
            ec_point_formats: vec![
                ECPointFormat::UNCOMPRESSED,
            ],
        }
    }
}

pub struct Session {
    client_random: Random,
    client_session_id: SessionId,
    server_random: Random,
    server_session_id: SessionId,
    client_x25519_secret_key: X25519SecretKey,
    server_x25519_public_key: X25519PublicKey,
    // Negotiated
    version: ProtocolVersion,
    cipher_suite: CipherSuite,
    alpn: Option<Vec<u8>>,
}

pub fn write_extension<T: AsMut<[u8]> + AsRef<[u8]>, F: FnMut(&mut Serializer<T>) -> Result<(), Error>>(serializer: &mut Serializer<T>, kind: ExtensionKind, serialize_fn: F) -> Result<usize, Error> {
    // B.3.1.  Key Exchange Messages
    // https://tools.ietf.org/html/rfc8446#appendix-B.3.1
    // struct {
    //     ExtensionType extension_type;
    //     opaque extension_data<0..2^16-1>;
    // } Extension;
    serializer.serialize_many(|serializer| {
        // Extension Kind
        serializer.serialize_bytes(&kind.to_be_bytes())?;
        // Extension Data
        // <0..2^16-1>
        serializer.serialize_vector(0..=65535, serialize_fn)?;

        Ok(())
    })
}


pub fn write_ext_supported_versions<T: AsMut<[u8]> + AsRef<[u8]>>(serializer: &mut Serializer<T>, supported_versions: &[ProtocolVersion]) -> Result<usize, Error> {
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
                serializer.serialize_bytes(&version.to_be_bytes())?;
            }

            Ok(())
        })?;

        Ok(())
    })
}

pub fn write_ext_selected_version<T: AsMut<[u8]> + AsRef<[u8]>>(serializer: &mut Serializer<T>, selected_version: ProtocolVersion) -> Result<usize, Error> {
    write_extension(serializer, ExtensionKind::SUPPORTED_VERSIONS, |serializer| {
        serializer.serialize_bytes(&selected_version.to_be_bytes())?;

        Ok(())
    })
}

pub fn write_ext_server_names<S: AsRef<str>, T: AsMut<[u8]> + AsRef<[u8]>>(serializer: &mut Serializer<T>, server_names: &[S]) -> Result<usize, Error> {
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
                    serializer.serialize_bytes(server_name.as_ref().as_bytes())?;
                    Ok(())
                })?;
            }

            Ok(())
        })?;

        Ok(())
    })
}

pub fn write_ext_application_protos<B: AsRef<[u8]>, T: AsMut<[u8]> + AsRef<[u8]>>(serializer: &mut Serializer<T>, application_protos: &[B]) -> Result<usize, Error> {
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
                    serializer.serialize_bytes(application_proto.as_ref())?;
                    Ok(())
                })?;
            }

            Ok(())
        })?;

        Ok(())
    })
}

pub fn write_ext_supported_groups<T: AsMut<[u8]> + AsRef<[u8]>>(serializer: &mut Serializer<T>, supported_groups: &[SupportedGroup]) -> Result<usize, Error> {
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
                serializer.serialize_bytes(&group.to_be_bytes())?;
            }

            Ok(())
        })?;

        Ok(())
    })
}

pub fn write_ext_signature_algorithms<T: AsMut<[u8]> + AsRef<[u8]>>(serializer: &mut Serializer<T>, signature_algorithms: &[SignatureScheme]) -> Result<usize, Error> {
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
                serializer.serialize_bytes(&signature_algorithm.to_be_bytes())?;
            }

            Ok(())
        })?;

        Ok(())
    })
}

pub fn write_ext_ec_point_foramts<T: AsMut<[u8]> + AsRef<[u8]>>(serializer: &mut Serializer<T>, ec_point_foramts: &[ECPointFormat]) -> Result<usize, Error> {
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
        serializer.serialize_vector(2..=255, |serializer| {
            for ec_point_foramt in ec_point_foramts.iter() {
                serializer.serialize_bytes(&ec_point_foramt.to_be_bytes())?;
            }

            Ok(())
        })?;

        Ok(())
    })
}

fn write_ext_key_share_entry<B: AsRef<[u8]>, T: AsMut<[u8]> + AsRef<[u8]>>(serializer: &mut Serializer<T>, key_share_entry: &KeyShareEntry<B>) -> Result<usize, Error> {
    serializer.serialize_many(|serializer| {
        serializer.serialize_bytes(&key_share_entry.group.to_be_bytes())?;
        serializer.serialize_vector(1..=65535, |serializer| {
            serializer.serialize_bytes(key_share_entry.key.as_ref())?;

            Ok(())
        })?;

        Ok(())
    })
}

pub fn write_ext_key_shares<B: AsRef<[u8]>, T: AsMut<[u8]> + AsRef<[u8]>>(serializer: &mut Serializer<T>, key_shares: &[KeyShareEntry<B>]) -> Result<usize, Error> {
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
        })?;

        Ok(())
    })
}

pub fn write_ext_key_share<B: AsRef<[u8]>, T: AsMut<[u8]> + AsRef<[u8]>>(serializer: &mut Serializer<T>, key_share: &KeyShareEntry<B>) -> Result<usize, Error> {
    write_extension(serializer, ExtensionKind::KEY_SHARE, |serializer| {
        write_ext_key_share_entry(serializer, key_share)?;

        Ok(())
    })
}


    
pub fn write_handshake<T: AsMut<[u8]> + AsRef<[u8]>, F: FnMut(&mut Serializer<T>) -> Result<(), Error>>(serializer: &mut Serializer<T>, kind: HandshakeKind, serialize_fn: F) -> Result<usize, Error> {
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
    const U24_MAX: usize = 16777215; // 2 ** 24 - 1

    serializer.serialize_many(|serializer| {
        serializer.serialize_u8(kind.0)?;
        serializer.serialize_vector(0..=U24_MAX, serialize_fn)?;

        Ok(())
    })
}


pub fn write_handshake_client_hello<T: AsMut<[u8]> + AsRef<[u8]>>(serializer: &mut Serializer<T>, config: &HandshakeConfig, session: &Session) -> Result<usize, Error> {
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
    let random = session.client_random;
    let session_id = session.client_session_id;

    let x25519_public_key = session.client_x25519_secret_key.public_key();
    let client_key_shares: &[KeyShareEntry<&[u8]>] = &[
        KeyShareEntry { group: SupportedGroup::X25519, key: x25519_public_key.as_bytes() },
    ];

    write_tls_plaintext_record(serializer, ContentKind::HANDSHAKE, ProtocolVersion::TLS_V1_2, |serializer| {
        write_handshake(serializer, HandshakeKind::CLIENT_HELLO, |serializer| {
            serializer.serialize_bytes(&ProtocolVersion::TLS_V1_2.to_be_bytes())?;
            serializer.serialize_bytes(random.as_bytes())?;

            // serializer.serialize_u8(session_id.len())?;         // Session id bytes len
            // serializer.serialize_bytes(session_id.as_bytes())?;
            // <0..32>
            serializer.serialize_vector(0..=32, |serializer| {
                serializer.serialize_bytes(session_id.as_bytes())?;
                Ok(())
            })?;

            // <2..2^16-2>
            serializer.serialize_vector(2..=65534, |serializer| {
                for cipher_suite in config.supported_cipher_suites.iter() {
                    // cursor.write_all(&cipher_suite.to_be_bytes())?;
                    serializer.serialize_bytes(&cipher_suite.to_be_bytes())?;
                }

                Ok(())
            })?;

            // <1..2^8-1>
            serializer.serialize_vector(1..=255, |serializer| {
                serializer.serialize_bytes(&CompressionMethod::NULL.to_be_bytes())?;
                Ok(())
            })?;

            // Extension extensions<8..2^16-1>;
            serializer.serialize_vector(8..=65535, |serializer| {
                write_ext_supported_versions(serializer, &config.supported_versions)?;

                if !config.server_names.is_empty() {
                    write_ext_server_names(serializer, &config.server_names)?;
                }
                
                if !config.application_protocols.is_empty() {
                    write_ext_application_protos(serializer, &config.application_protocols[..])?;
                }

                if !config.supported_groups.is_empty() {
                    write_ext_supported_groups(serializer, &config.supported_groups[..])?;
                }

                if !config.signature_algorithms.is_empty() {
                    write_ext_signature_algorithms(serializer, &config.signature_algorithms[..])?;
                }

                if !config.ec_point_formats.is_empty() {
                    write_ext_ec_point_foramts(serializer, &config.ec_point_formats[..])?;
                }

                // session ticket
                // encrypt-then-mac
                // extended master secret
                write_ext_key_shares(serializer, client_key_shares)?;

                Ok(())
            })?;

            Ok(())
        })?;

        Ok(())
    })
}
