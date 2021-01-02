use super::ProtocolVersion;

use std::convert::TryFrom;
use std::io::{self, Read, Write};


// 4.2.  Extensions
// https://tools.ietf.org/html/rfc8446#section-4.2
// 
// Transport Layer Security (TLS) Extensions
// https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExtensionKind(pub u16);

impl ExtensionKind {
    // SNI
    // https://tools.ietf.org/html/rfc6066#section-3
    pub const SERVER_NAME: Self            = Self(0);
    pub const MAX_FRAGMENT_LENGTH: Self    = Self(1);
    pub const CLIENT_CERTIFICATE_URL: Self = Self(2);
    pub const TRUSTED_CA_KEYS: Self        = Self(3);
    pub const TRUNCATED_HMAC: Self         = Self(4);
    pub const STATUS_REQUEST: Self         = Self(5);
    pub const USER_MAPPING: Self           = Self(6);
    pub const CLIENT_AUTHZ: Self           = Self(7);
    pub const SERVER_AUTHZ: Self           = Self(8);
    pub const CERT_TYPE: Self              = Self(9);
    pub const SUPPORTED_GROUPS: Self       = Self(10);
    pub const EC_POINT_FORMATS: Self       = Self(11);
    pub const SRP: Self                    = Self(12);
    pub const SIGNATURE_ALGORITHMS: Self   = Self(13);
    pub const USE_SRTP: Self               = Self(14);
    pub const HEARTBEAT: Self              = Self(15);
    // ALPN
    // https://tools.ietf.org/html/rfc7301#section-3.1
    pub const APPLICATION_LAYER_PROTOCOL_NEGOTIATION: Self = Self(16);
    pub const STATUS_REQUEST_V2: Self                      = Self(17);
    pub const SIGNED_CERTIFICATE_TIMESTAMP: Self           = Self(18);
    pub const CLIENT_CERTIFICATE_TYPE: Self                = Self(19);
    pub const SERVER_CERTIFICATE_TYPE: Self                = Self(20);
    pub const PADDING: Self                                = Self(21);
    pub const ENCRYPT_THEN_MAC: Self                       = Self(22);
    pub const EXTENDED_MASTER_SECRET: Self                 = Self(23);
    pub const TOKEN_BINDING: Self                          = Self(24);
    pub const CACHED_INFO: Self                            = Self(25);
    pub const TLS_LTS: Self                                = Self(26);
    pub const COMPRESS_CERTIFICATE: Self      = Self(27);
    pub const RECORD_SIZE_LIMIT: Self         = Self(28);
    pub const PWD_PROTECT: Self               = Self(29);
    pub const PWD_CLEAR: Self                 = Self(30);
    pub const PASSWORD_SALT: Self             = Self(31);
    pub const TICKET_PINNING: Self            = Self(32);
    pub const TLS_CERT_WITH_EXTERN_PSK: Self  = Self(33);
    pub const DELEGATED_CREDENTIALS: Self     = Self(34);
    pub const SESSION_TICKET: Self            = Self(35);
    pub const PRE_SHARED_KEY: Self            = Self(41);
    pub const EARLY_DATA: Self                = Self(42);
    pub const SUPPORTED_VERSIONS: Self        = Self(43);
    pub const COOKIE: Self                    = Self(44);
    pub const PSK_KEY_EXCHANGE_MODES: Self    = Self(45);
    pub const CERTIFICATE_AUTHORITIES: Self   = Self(47);
    pub const OID_FILTERS: Self               = Self(48);
    pub const POST_HANDSHAKE_AUTH: Self       = Self(49);
    pub const SIGNATURE_ALGORITHMS_CERT: Self = Self(50);
    pub const KEY_SHARE: Self                 = Self(51);
    pub const TRANSPARENCY_INFO: Self         = Self(52);
    pub const CONNECTION_ID: Self             = Self(53);
    pub const EXTERNAL_ID_HASH: Self          = Self(55);
    pub const EXTERNAL_SESSION_ID: Self       = Self(56);
    pub const RENEGOTIATION_INFO: Self        = Self(65281);

    pub const fn to_be_bytes(&self) -> [u8; 2] {
        self.0.to_be_bytes()
    }
}

impl std::fmt::Display for ExtensionKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::SERVER_NAME => write!(f, "SERVER_NAME"),
            Self::MAX_FRAGMENT_LENGTH => write!(f, "MAX_FRAGMENT_LENGTH"),
            Self::CLIENT_CERTIFICATE_URL => write!(f, "CLIENT_CERTIFICATE_URL"),
            Self::TRUSTED_CA_KEYS => write!(f, "TRUSTED_CA_KEYS"),
            Self::TRUNCATED_HMAC => write!(f, "TRUNCATED_HMAC"),
            Self::STATUS_REQUEST => write!(f, "STATUS_REQUEST"),
            Self::USER_MAPPING => write!(f, "USER_MAPPING"),
            Self::CLIENT_AUTHZ => write!(f, "CLIENT_AUTHZ"),
            Self::SERVER_AUTHZ => write!(f, "SERVER_AUTHZ"),
            Self::CERT_TYPE => write!(f, "CERT_TYPE"),
            Self::SUPPORTED_GROUPS => write!(f, "SUPPORTED_GROUPS"),
            Self::EC_POINT_FORMATS => write!(f, "EC_POINT_FORMATS"),
            Self::SRP => write!(f, "SRP"),
            Self::SIGNATURE_ALGORITHMS => write!(f, "SIGNATURE_ALGORITHMS"),
            Self::USE_SRTP => write!(f, "USE_SRTP"),
            Self::HEARTBEAT => write!(f, "HEARTBEAT"),
            Self::APPLICATION_LAYER_PROTOCOL_NEGOTIATION => write!(f, "APPLICATION_LAYER_PROTOCOL_NEGOTIATION"),
            Self::STATUS_REQUEST_V2 => write!(f, "STATUS_REQUEST_V2"),
            Self::SIGNED_CERTIFICATE_TIMESTAMP => write!(f, "SIGNED_CERTIFICATE_TIMESTAMP"),
            Self::CLIENT_CERTIFICATE_TYPE => write!(f, "CLIENT_CERTIFICATE_TYPE"),
            Self::SERVER_CERTIFICATE_TYPE => write!(f, "SERVER_CERTIFICATE_TYPE"),
            Self::PADDING => write!(f, "PADDING"),
            Self::ENCRYPT_THEN_MAC => write!(f, "ENCRYPT_THEN_MAC"),
            Self::EXTENDED_MASTER_SECRET => write!(f, "EXTENDED_MASTER_SECRET"),
            Self::TOKEN_BINDING => write!(f, "TOKEN_BINDING"),
            Self::CACHED_INFO => write!(f, "CACHED_INFO"),
            Self::TLS_LTS => write!(f, "TLS_LTS"),
            Self::COMPRESS_CERTIFICATE => write!(f, "COMPRESS_CERTIFICATE"),
            Self::RECORD_SIZE_LIMIT => write!(f, "RECORD_SIZE_LIMIT"),
            Self::PWD_PROTECT => write!(f, "PWD_PROTECT"),
            Self::PWD_CLEAR => write!(f, "PWD_CLEAR"),
            Self::PASSWORD_SALT => write!(f, "PASSWORD_SALT"),
            Self::TICKET_PINNING => write!(f, "TICKET_PINNING"),
            Self::TLS_CERT_WITH_EXTERN_PSK => write!(f, "TLS_CERT_WITH_EXTERN_PSK"),
            Self::DELEGATED_CREDENTIALS => write!(f, "DELEGATED_CREDENTIALS"),
            Self::SESSION_TICKET => write!(f, "SESSION_TICKET"),
            Self::PRE_SHARED_KEY => write!(f, "PRE_SHARED_KEY"),
            Self::EARLY_DATA => write!(f, "EARLY_DATA"),
            Self::SUPPORTED_VERSIONS => write!(f, "SUPPORTED_VERSIONS"),
            Self::COOKIE => write!(f, "COOKIE"),
            Self::PSK_KEY_EXCHANGE_MODES => write!(f, "PSK_KEY_EXCHANGE_MODES"),
            Self::CERTIFICATE_AUTHORITIES => write!(f, "CERTIFICATE_AUTHORITIES"),
            Self::OID_FILTERS => write!(f, "OID_FILTERS"),
            Self::POST_HANDSHAKE_AUTH => write!(f, "POST_HANDSHAKE_AUTH"),
            Self::SIGNATURE_ALGORITHMS_CERT => write!(f, "SIGNATURE_ALGORITHMS_CERT"),
            Self::KEY_SHARE => write!(f, "KEY_SHARE"),
            Self::TRANSPARENCY_INFO => write!(f, "TRANSPARENCY_INFO"),
            Self::CONNECTION_ID => write!(f, "CONNECTION_ID"),
            Self::EXTERNAL_ID_HASH => write!(f, "EXTERNAL_ID_HASH"),
            Self::EXTERNAL_SESSION_ID => write!(f, "EXTERNAL_SESSION_ID"),
            Self::RENEGOTIATION_INFO => write!(f, "RENEGOTIATION_INFO"),
            _ => write!(f, "Unknow({})", self.0),
        }
    }
}

// 3.  Server Name Indication
// https://tools.ietf.org/html/rfc6066#section-3
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServerNameKind(pub u8);

impl ServerNameKind {
    pub const HOST_NAME: Self = Self(0);

    pub const fn to_be_bytes(&self) -> [u8; 1] {
        self.0.to_be_bytes()
    }
}

impl std::fmt::Display for ServerNameKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::HOST_NAME => write!(f, "HOST_NAME"),
            _ => write!(f, "Unknow({})", self.0),
        }
    }
}

// TLS Certificate Types
// https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#tls-extensiontype-values-3
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CertificateKind(pub u8);

impl CertificateKind {
    // Was X.509 before TLS 1.3.
    // https://tools.ietf.org/html/rfc6091#section-3.1
    pub const X509: Self             = Self(0);
    // Used in TLS versions prior to 1.3.
    pub const OPENPGP_RESERVED: Self = Self(1);
    pub const RAW_PUBLIC_KEY: Self   = Self(2);

    pub const fn to_be_bytes(&self) -> [u8; 1] {
        self.0.to_be_bytes()
    }
}

impl std::fmt::Display for CertificateKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::X509 => write!(f, "X509"),
            Self::OPENPGP_RESERVED => write!(f, "OPENPGP_RESERVED"),
            Self::RAW_PUBLIC_KEY => write!(f, "RAW_PUBLIC_KEY"),
            _ => write!(f, "Unknow({})", self.0),
        }
    }
}

// TLS Certificate Status Types
// https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#certificate-status
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CertificateStatusKind(pub u8);

impl CertificateStatusKind {
    pub const OCSP: Self                = Self(1);
    // Used in TLS versions prior to 1.3.
    pub const OCSP_MULTI_RESERVED: Self = Self(2);

    pub const fn to_be_bytes(&self) -> [u8; 1] {
        self.0.to_be_bytes()
    }
}

impl std::fmt::Display for CertificateStatusKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::OCSP => write!(f, "OCSP"),
            Self::OCSP_MULTI_RESERVED => write!(f, "OCSP_MULTI_RESERVED"),
            _ => write!(f, "Unknow({})", self.0),
        }
    }
}

// TLS CachedInformationType Values
// https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#cachedinformationtype
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CachedInformationType(pub u8);

impl CachedInformationType {
    pub const CERT: Self     = Self(1);
    pub const CERT_REQ: Self = Self(2);

    pub const fn to_be_bytes(&self) -> [u8; 1] {
        self.0.to_be_bytes()
    }
}

impl std::fmt::Display for CachedInformationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::CERT => write!(f, "CERT"),
            Self::CERT_REQ => write!(f, "CERT_REQ"),
            _ => write!(f, "Unknow({})", self.0),
        }
    }
}

// TLS Certificate Compression Algorithm IDs
// https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#tls-certificate-compression-algorithm-ids
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CertificateCompressionAlgorithm(pub u16);

impl CertificateCompressionAlgorithm {
    pub const ZLIB: Self   = Self(1);
    pub const BROTLI: Self = Self(2);
    pub const ZSTD: Self   = Self(3);

    pub const fn to_be_bytes(&self) -> [u8; 2] {
        self.0.to_be_bytes()
    }
}

impl std::fmt::Display for CertificateCompressionAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::ZLIB => write!(f, "ZLIB"),
            Self::BROTLI => write!(f, "BROTLI"),
            Self::ZSTD => write!(f, "ZSTD"),
            _ => write!(f, "Unknow({})", self.0),
        }
    }
}

// TLS Supported Groups
// https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8
// NOTE:
//      In versions of TLS prior to TLS 1.3, this extension was named "elliptic_curves" 
//      and only contained elliptic curve groups.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SupportedGroup(pub u16);

impl SupportedGroup {
    pub const SECT163K1: Self = Self(1);
    pub const SECT163R1: Self = Self(2);
    pub const SECT163R2: Self = Self(3);
    pub const SECT193R1: Self = Self(4);
    pub const SECT193R2: Self = Self(5);
    pub const SECT233K1: Self = Self(6);
    pub const SECT233R1: Self = Self(7);
    pub const SECT239K1: Self = Self(8);
    pub const SECT283K1: Self = Self(9);
    pub const SECT283R1: Self = Self(10);
    pub const SECT409K1: Self = Self(11);
    pub const SECT409R1: Self = Self(12);
    pub const SECT571K1: Self = Self(13);
    pub const SECT571R1: Self = Self(14);
    pub const SECP160K1: Self = Self(15);
    pub const SECP160R1: Self = Self(16);
    pub const SECP160R2: Self = Self(17);
    pub const SECP192K1: Self = Self(18);
    pub const SECP192R1: Self = Self(19);
    pub const SECP224K1: Self = Self(20);
    pub const SECP224R1: Self = Self(21);
    pub const SECP256K1: Self = Self(22);
    pub const SECP256R1: Self = Self(23);
    pub const SECP384R1: Self = Self(24);
    pub const SECP521R1: Self = Self(25);
    pub const BRAINPOOLP256R1: Self = Self(26);
    pub const BRAINPOOLP384R1: Self = Self(27);
    pub const BRAINPOOLP512R1: Self = Self(28);
    pub const X25519: Self          = Self(29);
    pub const X448: Self            = Self(30);
    pub const BRAINPOOLP256R1TLS13: Self = Self(31);
    pub const BRAINPOOLP384R1TLS13: Self = Self(32);
    pub const BRAINPOOLP512R1TLS13: Self = Self(33);
    pub const GC256A: Self = Self(34);
    pub const GC256B: Self = Self(35);
    pub const GC256C: Self = Self(36);
    pub const GC256D: Self = Self(37);
    pub const GC512A: Self = Self(38);
    pub const GC512B: Self = Self(39);
    pub const GC512C: Self = Self(40);
    pub const CURVESM2: Self = Self(41);
    pub const FFDHE2048: Self = Self(256);
    pub const FFDHE3072: Self = Self(257);
    pub const FFDHE4096: Self = Self(258);
    pub const FFDHE6144: Self = Self(259);
    pub const FFDHE8192: Self = Self(260);
    pub const ARBITRARY_EXPLICIT_PRIME_CURVES: Self = Self(65281);
    pub const ARBITRARY_EXPLICIT_CHAR2_CURVES: Self = Self(65282);

    pub const fn to_be_bytes(&self) -> [u8; 2] {
        self.0.to_be_bytes()
    }
}

impl std::fmt::Display for SupportedGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::SECT163K1 => write!(f, "SECT163K1"),
            Self::SECT163R1 => write!(f, "SECT163R1"),
            Self::SECT163R2 => write!(f, "SECT163R2"),
            Self::SECT193R1 => write!(f, "SECT193R1"),
            Self::SECT193R2 => write!(f, "SECT193R2"),
            Self::SECT233K1 => write!(f, "SECT233K1"),
            Self::SECT233R1 => write!(f, "SECT233R1"),
            Self::SECT239K1 => write!(f, "SECT239K1"),
            Self::SECT283K1 => write!(f, "SECT283K1"),
            Self::SECT283R1 => write!(f, "SECT283R1"),
            Self::SECT409K1 => write!(f, "SECT409K1"),
            Self::SECT409R1 => write!(f, "SECT409R1"),
            Self::SECT571K1 => write!(f, "SECT571K1"),
            Self::SECT571R1 => write!(f, "SECT571R1"),
            Self::SECP160K1 => write!(f, "SECP160K1"),
            Self::SECP160R1 => write!(f, "SECP160R1"),
            Self::SECP160R2 => write!(f, "SECP160R2"),
            Self::SECP192K1 => write!(f, "SECP192K1"),
            Self::SECP192R1 => write!(f, "SECP192R1"),
            Self::SECP224K1 => write!(f, "SECP224K1"),
            Self::SECP224R1 => write!(f, "SECP224R1"),
            Self::SECP256K1 => write!(f, "SECP256K1"),
            Self::SECP256R1 => write!(f, "SECP256R1"),
            Self::SECP384R1 => write!(f, "SECP384R1"),
            Self::SECP521R1 => write!(f, "SECP521R1"),
            Self::BRAINPOOLP256R1 => write!(f, "BRAINPOOLP256R1"),
            Self::BRAINPOOLP384R1 => write!(f, "BRAINPOOLP384R1"),
            Self::BRAINPOOLP512R1 => write!(f, "BRAINPOOLP512R1"),
            Self::X25519 => write!(f, "X25519"),
            Self::X448 => write!(f, "X448"),
            Self::BRAINPOOLP256R1TLS13 => write!(f, "BRAINPOOLP256R1TLS13"),
            Self::BRAINPOOLP384R1TLS13 => write!(f, "BRAINPOOLP384R1TLS13"),
            Self::BRAINPOOLP512R1TLS13 => write!(f, "BRAINPOOLP512R1TLS13"),
            Self::GC256A => write!(f, "GC256A"),
            Self::GC256B => write!(f, "GC256B"),
            Self::GC256C => write!(f, "GC256C"),
            Self::GC256D => write!(f, "GC256D"),
            Self::GC512A => write!(f, "GC512A"),
            Self::GC512B => write!(f, "GC512B"),
            Self::GC512C => write!(f, "GC512C"),
            Self::CURVESM2 => write!(f, "CURVESM2"),
            Self::FFDHE2048 => write!(f, "FFDHE2048"),
            Self::FFDHE3072 => write!(f, "FFDHE3072"),
            Self::FFDHE4096 => write!(f, "FFDHE4096"),
            Self::FFDHE6144 => write!(f, "FFDHE6144"),
            Self::FFDHE8192 => write!(f, "FFDHE8192"),
            Self::ARBITRARY_EXPLICIT_PRIME_CURVES => write!(f, "ARBITRARY_EXPLICIT_PRIME_CURVES"),
            Self::ARBITRARY_EXPLICIT_CHAR2_CURVES => write!(f, "ARBITRARY_EXPLICIT_CHAR2_CURVES"),
            _ => write!(f, "Unknow({})", self.0),
        }
    }
}

// TLS SignatureScheme
// https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-signaturescheme
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignatureScheme(pub u16);

impl SignatureScheme {
    pub const RSA_PKCS1_SHA1: Self                    = Self(0x0201);
    pub const ECDSA_SHA1: Self                        = Self(0x0203);
    pub const RSA_PKCS1_SHA256: Self                  = Self(0x0401);
    pub const ECDSA_SECP256R1_SHA256: Self            = Self(0x0403);
    pub const RSA_PKCS1_SHA256_LEGACY: Self           = Self(0x0420);
    pub const RSA_PKCS1_SHA384: Self                  = Self(0x0501);
    pub const ECDSA_SECP384R1_SHA384: Self            = Self(0x0503);
    pub const RSA_PKCS1_SHA384_LEGACY: Self           = Self(0x0520);
    pub const RSA_PKCS1_SHA512: Self                  = Self(0x0601);
    pub const ECDSA_SECP521R1_SHA512: Self            = Self(0x0603);
    pub const RSA_PKCS1_SHA512_LEGACY: Self           = Self(0x0620);
    pub const ECCSI_SHA256: Self                      = Self(0x0704);
    pub const ISO_IBS1: Self                          = Self(0x0705);
    pub const ISO_IBS2: Self                          = Self(0x0706);
    pub const ISO_CHINESE_IBS: Self                   = Self(0x0707);
    pub const SM2SIG_SM3: Self                        = Self(0x0708);
    pub const GOSTR34102012_256A: Self                = Self(0x0709);
    pub const GOSTR34102012_256B: Self                = Self(0x070A);
    pub const GOSTR34102012_256C: Self                = Self(0x070B);
    pub const GOSTR34102012_256D: Self                = Self(0x070C);
    pub const GOSTR34102012_512A: Self                = Self(0x070D);
    pub const GOSTR34102012_512B: Self                = Self(0x070E);
    pub const GOSTR34102012_512C: Self                = Self(0x070F);
    pub const RSA_PSS_RSAE_SHA256: Self               = Self(0x0804);
    pub const RSA_PSS_RSAE_SHA384: Self               = Self(0x0805);
    pub const RSA_PSS_RSAE_SHA512: Self               = Self(0x0806);
    pub const ED25519: Self                           = Self(0x0807);
    pub const ED448: Self                             = Self(0x0808);
    pub const RSA_PSS_PSS_SHA256: Self                = Self(0x0809);
    pub const RSA_PSS_PSS_SHA384: Self                = Self(0x080A);
    pub const RSA_PSS_PSS_SHA512: Self                = Self(0x080B);
    pub const ECDSA_BRAINPOOLP256R1TLS13_SHA256: Self = Self(0x081A);
    pub const ECDSA_BRAINPOOLP384R1TLS13_SHA384: Self = Self(0x081B);
    pub const ECDSA_BRAINPOOLP512R1TLS13_SHA512: Self = Self(0x081C);

    pub const fn to_be_bytes(&self) -> [u8; 2] {
        self.0.to_be_bytes()
    }
}

impl std::fmt::Display for SignatureScheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::RSA_PKCS1_SHA1 => write!(f, "RSA_PKCS1_SHA1"),
            Self::ECDSA_SHA1 => write!(f, "ECDSA_SHA1"),
            Self::RSA_PKCS1_SHA256 => write!(f, "RSA_PKCS1_SHA256"),
            Self::ECDSA_SECP256R1_SHA256 => write!(f, "ECDSA_SECP256R1_SHA256"),
            Self::RSA_PKCS1_SHA256_LEGACY => write!(f, "RSA_PKCS1_SHA256_LEGACY"),
            Self::RSA_PKCS1_SHA384 => write!(f, "RSA_PKCS1_SHA384"),
            Self::ECDSA_SECP384R1_SHA384 => write!(f, "ECDSA_SECP384R1_SHA384"),
            Self::RSA_PKCS1_SHA384_LEGACY => write!(f, "RSA_PKCS1_SHA384_LEGACY"),
            Self::RSA_PKCS1_SHA512 => write!(f, "RSA_PKCS1_SHA512"),
            Self::ECDSA_SECP521R1_SHA512 => write!(f, "ECDSA_SECP521R1_SHA512"),
            Self::RSA_PKCS1_SHA512_LEGACY => write!(f, "RSA_PKCS1_SHA512_LEGACY"),
            Self::ECCSI_SHA256 => write!(f, "ECCSI_SHA256"),
            Self::ISO_IBS1 => write!(f, "ISO_IBS1"),
            Self::ISO_IBS2 => write!(f, "ISO_IBS2"),
            Self::ISO_CHINESE_IBS => write!(f, "ISO_CHINESE_IBS"),
            Self::SM2SIG_SM3 => write!(f, "SM2SIG_SM3"),
            Self::GOSTR34102012_256A => write!(f, "GOSTR34102012_256A"),
            Self::GOSTR34102012_256B => write!(f, "GOSTR34102012_256B"),
            Self::GOSTR34102012_256C => write!(f, "GOSTR34102012_256C"),
            Self::GOSTR34102012_256D => write!(f, "GOSTR34102012_256D"),
            Self::GOSTR34102012_512A => write!(f, "GOSTR34102012_512A"),
            Self::GOSTR34102012_512B => write!(f, "GOSTR34102012_512B"),
            Self::GOSTR34102012_512C => write!(f, "GOSTR34102012_512C"),
            Self::RSA_PSS_RSAE_SHA256 => write!(f, "RSA_PSS_RSAE_SHA256"),
            Self::RSA_PSS_RSAE_SHA384 => write!(f, "RSA_PSS_RSAE_SHA384"),
            Self::RSA_PSS_RSAE_SHA512 => write!(f, "RSA_PSS_RSAE_SHA512"),
            Self::ED25519 => write!(f, "ED25519"),
            Self::ED448 => write!(f, "ED448"),
            Self::RSA_PSS_PSS_SHA256 => write!(f, "RSA_PSS_PSS_SHA256"),
            Self::RSA_PSS_PSS_SHA384 => write!(f, "RSA_PSS_PSS_SHA384"),
            Self::RSA_PSS_PSS_SHA512 => write!(f, "RSA_PSS_PSS_SHA512"),
            Self::ECDSA_BRAINPOOLP256R1TLS13_SHA256 => write!(f, "ECDSA_BRAINPOOLP256R1TLS13_SHA256"),
            Self::ECDSA_BRAINPOOLP384R1TLS13_SHA384 => write!(f, "ECDSA_BRAINPOOLP384R1TLS13_SHA384"),
            Self::ECDSA_BRAINPOOLP512R1TLS13_SHA512 => write!(f, "ECDSA_BRAINPOOLP512R1TLS13_SHA512"),
            _ => write!(f, "Unknow({})", self.0),
        }
    }
}

// TLS PskKeyExchangeMode
// https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-pskkeyexchangemode
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PskKeyExchangeMode(pub u8);

impl PskKeyExchangeMode {
    pub const PSK_KE: Self     = Self(0);
    pub const PSK_DHE_KE: Self = Self(1);

    pub const fn to_be_bytes(&self) -> [u8; 1] {
        self.0.to_be_bytes()
    }
}

impl std::fmt::Display for PskKeyExchangeMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::PSK_KE => write!(f, "PSK_KE"),
            Self::PSK_DHE_KE => write!(f, "PSK_DHE_KE"),
            _ => write!(f, "Unknow({})", self.0),
        }
    }
}

// TLS SignatureAlgorithm
// https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-16
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignatureAlgorithm(pub u8);

impl SignatureAlgorithm {
    pub const RSA: Self     = Self(1);
    pub const DSA: Self     = Self(2);
    pub const ECDSA: Self   = Self(3);
    pub const ED25519: Self = Self(7);
    pub const ED448: Self   = Self(8);
    pub const GOSTR34102012_256: Self = Self(64);
    pub const GOSTR34102012_512: Self = Self(65);

    pub const fn to_be_bytes(&self) -> [u8; 1] {
        self.0.to_be_bytes()
    }
}

impl std::fmt::Display for SignatureAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::RSA => write!(f, "RSA"),
            Self::DSA => write!(f, "DSA"),
            Self::ECDSA => write!(f, "ECDSA"),
            Self::ED25519 => write!(f, "ED25519"),
            Self::ED448 => write!(f, "ED448"),
            Self::GOSTR34102012_256 => write!(f, "GOSTR34102012_256"),
            Self::GOSTR34102012_512 => write!(f, "GOSTR34102012_512"),
            _ => write!(f, "Unknow({})", self.0),
        }
    }
}

// TLS HashAlgorithm
// https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-18
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HashAlgorithm(pub u8);

impl HashAlgorithm {
    pub const MD5: Self       = Self(1);
    pub const SHA1: Self      = Self(2);
    pub const SHA224: Self    = Self(3);
    pub const SHA256: Self    = Self(4);
    pub const SHA384: Self    = Self(5);
    pub const SHA512: Self    = Self(6);
    pub const INTRINSIC: Self = Self(8);

    pub const fn to_be_bytes(&self) -> [u8; 1] {
        self.0.to_be_bytes()
    }
}

impl std::fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::MD5 => write!(f, "MD5"),
            Self::SHA1 => write!(f, "SHA1"),
            Self::SHA224 => write!(f, "SHA224"),
            Self::SHA256 => write!(f, "SHA256"),
            Self::SHA384 => write!(f, "SHA384"),
            Self::SHA512 => write!(f, "SHA512"),
            Self::INTRINSIC => write!(f, "INTRINSIC"),
            _ => write!(f, "Unknow({})", self.0),
        }
    }
}

// TLS EC Point Formats
// https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-9
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ECPointFormat(pub u8);

impl ECPointFormat {
    pub const UNCOMPRESSED: Self              = Self(0);
    pub const ANSIX962_COMPRESSED_PRIME: Self = Self(1);
    pub const ANSIX962_COMPRESSED_CHAR2: Self = Self(2);

    pub const fn to_be_bytes(&self) -> [u8; 1] {
        self.0.to_be_bytes()
    }
}

impl std::fmt::Display for ECPointFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::UNCOMPRESSED => write!(f, "UNCOMPRESSED"),
            Self::ANSIX962_COMPRESSED_PRIME => write!(f, "ANSIX962_COMPRESSED_PRIME"),
            Self::ANSIX962_COMPRESSED_CHAR2 => write!(f, "ANSIX962_COMPRESSED_CHAR2"),
            _ => write!(f, "Unknow({})", self.0),
        }
    }
}

// TLS EC Curve Types
// https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-10
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ECCurveKind(pub u8);

impl ECCurveKind {
    pub const EXPLICIT_PRIME: Self = Self(1);
    pub const EXPLICIT_CHAR2: Self = Self(2);
    pub const NAMED_CURVE: Self    = Self(3);

    pub const fn to_be_bytes(&self) -> [u8; 1] {
        self.0.to_be_bytes()
    }
}

impl std::fmt::Display for ECCurveKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::EXPLICIT_PRIME => write!(f, "EXPLICIT_PRIME"),
            Self::EXPLICIT_CHAR2 => write!(f, "EXPLICIT_CHAR2"),
            Self::NAMED_CURVE => write!(f, "NAMED_CURVE"),
            _ => write!(f, "Unknow({})", self.0),
        }
    }
}

// TLS Application-Layer Protocol Negotiation (ALPN) Protocol IDs
// https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids
#[derive(Clone, Copy, Debug, Eq)]
pub struct ApplicationLayerProtocol<T: AsRef<[u8]>>(pub T);

impl ApplicationLayerProtocol<&'static str> {
    pub const HTTP0_9: Self        = Self("http/0.9");
    pub const HTTP1_0: Self        = Self("http/1.0");
    pub const HTTP1_1: Self        = Self("http/1.1");
    pub const HTTP2_OVER_TLS: Self = Self("h2");
    pub const HTTP2_OVER_TCP: Self = Self("h2c");

    pub const SPDY_1: Self         = Self("spdy/1");
    pub const SPDY_2: Self         = Self("spdy/2");
    pub const SPDY_3: Self         = Self("spdy/3");

    // WebRTC Media and Data
    pub const WEBRTC: Self               = Self("webrtc");
    // Confidential WebRTC Media and Data
    pub const CONFIDENTIAL_WEBRTC: Self  = Self("c-webrtc");
    pub const FTP: Self                  = Self("ftp");
    pub const IMAP: Self                 = Self("imap");
    pub const POP3: Self                 = Self("pop3");
    // ManageSieve
    pub const MANAGE_SIEVE: Self         = Self("managesieve");
    pub const COAP: Self                 = Self("coap");
    // OASIS Message Queuing Telemetry
    pub const MQTT: Self                 = Self("mqtt");
    pub const DNS_OVER_TLS: Self         = Self("dot");
    // XMPP jabber:client namespace
    pub const XMPP_CLIENT: Self          = Self("xmpp-client");
    // XMPP jabber:server namespace
    pub const XMPP_SERVER: Self          = Self("xmpp-server");
    pub const ACME_TLS_1: Self           = Self("acme-tls/1");
    // Traversal Using Relays around NAT (TURN)
    pub const STUN_TURN: Self            = Self("stun.turn");
    // NAT discovery using Session Traversal Utilities for NAT (STUN)
    pub const STUN_NAT_DISCOVERY: Self   = Self("stun.nat-discovery");
    // Network Time Security Key Establishment, version 1
    pub const NETWORK_TIME_SECURITY_KEY_ESTABLISHMENT_1: Self = Self("ntske/1");
    
    pub const fn as_bytes(&self) -> &'static [u8] {
        self.0.as_bytes()
    }
}

impl<T: AsRef<[u8]>> AsRef<[u8]> for ApplicationLayerProtocol<T> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<T: AsRef<[u8]>> PartialEq for ApplicationLayerProtocol<T> {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_ref() == other.0.as_ref()
    }
}

impl std::fmt::Display for ApplicationLayerProtocol<&str> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::fmt::Display for ApplicationLayerProtocol<&[u8]> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let _ = write!(f, "0x");
        for byte in self.0.iter() {
            let _ = write!(f, "{:x}", byte);
        }
        Ok(())
    }
}

impl std::fmt::Display for ApplicationLayerProtocol<Vec<u8>> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let _ = write!(f, "0x");
        for byte in self.0.iter() {
            let _ = write!(f, "{:x}", byte);
        }
        Ok(())
    }
}

impl std::fmt::Display for ApplicationLayerProtocol<&Vec<u8>> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let _ = write!(f, "0x");
        for byte in self.0.iter() {
            let _ = write!(f, "{:x}", byte);
        }
        Ok(())
    }
}


pub fn write_ext_client_supported_versions(cursor: &mut io::Cursor<Vec<u8>>, versions: &[ProtocolVersion]) -> Result<(), io::Error> {
    // Extension: Supported Versions
    // https://tools.ietf.org/html/rfc8446#section-4.2.1
    if versions.is_empty() {
        return Err(io::Error::new(io::ErrorKind::Other, "payload size limit."));
    }
    cursor.write_all(&ExtensionKind::SUPPORTED_VERSIONS.0.to_be_bytes())?; // ExtensionKind

    transaction!(cursor, u16, 2, 0, 65535, {
        transaction!(cursor, u8, 1, 2, 255, {
            for version in versions.iter() {
                cursor.write_all(&version.to_be_bytes())?;
            }
        });
    });

    Ok(())
}
pub fn write_ext_server_supported_version(cursor: &mut io::Cursor<Vec<u8>>, version: ProtocolVersion) -> Result<(), io::Error> {
    // Extension: Supported Versions
    // https://tools.ietf.org/html/rfc8446#section-4.2.1
    cursor.write_all(&ExtensionKind::SUPPORTED_VERSIONS.0.to_be_bytes())?; // ExtensionKind

    transaction!(cursor, u16, 2, 0, 65535, {
        cursor.write_all(&version.to_be_bytes())?;
    });

    Ok(())
}

fn write_ext_server_name(cursor: &mut io::Cursor<Vec<u8>>, server_name: &str) -> Result<(), io::Error> {
    let len = u16::try_from(server_name.len()).map_err(|_| io::Error::new(io::ErrorKind::Other, "payload size limit."))?;
    assert!(len > 0);

    cursor.write_all(&[ServerNameKind::HOST_NAME.0])?;
    cursor.write_all(&len.to_be_bytes())?;
    cursor.write_all(server_name.as_bytes())
}
pub fn write_ext_server_names(cursor: &mut io::Cursor<Vec<u8>>, server_names: &[&str]) -> Result<(), io::Error> {
    // Extension: ServerName
    // https://tools.ietf.org/html/rfc6066#section-3
    // 
    // TODO: HostName 的编码是 ASCII 编码，不是 UTF-8 编码。
    //       所以针对国际化的域名，可能需要经过 PunnyCode 编码后再使用。
    //       目前，这里不做处理。
    if server_names.is_empty() {
        return Err(io::Error::new(io::ErrorKind::Other, "payload size limit."));
    }
    cursor.write_all(&ExtensionKind::SERVER_NAME.0.to_be_bytes())?; // ExtensionKind

    transaction!(cursor, u16, 2, 0, 65535, {
        transaction!(cursor, u16, 2, 4, 65535, {
            for server_name in server_names.iter() {
                write_ext_server_name(cursor, server_name)?;
            }
        });
    });

    Ok(())
}

fn write_ext_application_proto(cursor: &mut io::Cursor<Vec<u8>>, application_proto: &[u8]) -> Result<(), io::Error> {
    let len = u8::try_from(application_proto.len()).map_err(|_| io::Error::new(io::ErrorKind::Other, "payload size limit."))?;
    assert!(len > 0);

    cursor.write_all(&[len])?;
    cursor.write_all(application_proto)
}
pub fn write_ext_application_protos(cursor: &mut io::Cursor<Vec<u8>>, application_protos: &[&[u8]]) -> Result<(), io::Error> {
    // Extension: Application-Layer Protocol Negotiation Extension
    // https://tools.ietf.org/html/rfc7301#section-3.1
    if application_protos.is_empty() {
        return Err(io::Error::new(io::ErrorKind::Other, "payload size limit."));
    }

    cursor.write_all(&ExtensionKind::APPLICATION_LAYER_PROTOCOL_NEGOTIATION.0.to_be_bytes())?; // ExtensionKind
    transaction!(cursor, u16, 2, 0, 65535, {
        transaction!(cursor, u16, 2, 2, 65535, {
            for application_proto in application_protos.iter() {
                write_ext_application_proto(cursor, application_proto)?;
            }
        });
    });

    Ok(())
}

pub fn write_ext_supported_groups(cursor: &mut io::Cursor<Vec<u8>>, supported_groups: &[SupportedGroup]) -> Result<(), io::Error> {
    // Extension: SUPPORTED_GROUPS
    // https://tools.ietf.org/html/rfc8446#section-4.2.7
    if supported_groups.is_empty() {
        return Err(io::Error::new(io::ErrorKind::Other, "payload size limit."));
    }

    cursor.write_all(&ExtensionKind::SUPPORTED_GROUPS.0.to_be_bytes())?; // ExtensionKind
    transaction!(cursor, u16, 2, 0, 65535, {
        transaction!(cursor, u16, 2, 2, 65535, {
            for group in supported_groups.iter() {
                cursor.write_all(&group.to_be_bytes())?;
            }
        });
    });

    Ok(())
}

pub fn write_ext_signature_algorithms(cursor: &mut io::Cursor<Vec<u8>>, signature_algorithms: &[SignatureScheme]) -> Result<(), io::Error> {
    // Extension: SIGNATURE_ALGORITHMS
    // https://tools.ietf.org/html/rfc8446#section-4.2.3
    if signature_algorithms.is_empty() {
        return Err(io::Error::new(io::ErrorKind::Other, "payload size limit."));
    }

    cursor.write_all(&ExtensionKind::SIGNATURE_ALGORITHMS.0.to_be_bytes())?; // ExtensionKind
    transaction!(cursor, u16, 2, 0, 65535, {
        transaction!(cursor, u16, 2, 2, 65535, {
            for signature_algorithm in signature_algorithms.iter() {
                cursor.write_all(&signature_algorithm.to_be_bytes())?; // u16
            }
        });
    });

    Ok(())
}

pub fn write_ext_ec_point_foramts(cursor: &mut io::Cursor<Vec<u8>>, ec_point_foramts: &[ECPointFormat]) -> Result<(), io::Error> {
    // Extension: EC_POINT_FORMATS
    // https://tools.ietf.org/html/rfc8422#section-5.1.2
    if ec_point_foramts.is_empty() {
        return Err(io::Error::new(io::ErrorKind::Other, "payload size limit."));
    }

    cursor.write_all(&ExtensionKind::EC_POINT_FORMATS.0.to_be_bytes())?; // ExtensionKind
    transaction!(cursor, u16, 2, 0, 65535, {
        transaction!(cursor, u8, 1, 1, 255, {
            for ec_point_foramt in ec_point_foramts.iter() {
                cursor.write_all(&[ec_point_foramt.0])?;
            }
        });
    });

    Ok(())
}

pub fn write_ext_psk_key_exchange_modes(cursor: &mut io::Cursor<Vec<u8>>, psk_key_exchange_modes: &[PskKeyExchangeMode]) -> Result<(), io::Error> {
    // Extension: PSK_KEY_EXCHANGE_MODES
    // https://tools.ietf.org/html/rfc8446#section-4.2.9
    if psk_key_exchange_modes.is_empty() {
        return Err(io::Error::new(io::ErrorKind::Other, "payload size limit."));
    }

    cursor.write_all(&ExtensionKind::PSK_KEY_EXCHANGE_MODES.0.to_be_bytes())?; // ExtensionKind
    transaction!(cursor, u16, 2, 0, 65535, {
        transaction!(cursor, u8, 1, 1, 255, {
            for psk_key_exchange_mode in psk_key_exchange_modes.iter() {
                cursor.write_all(&[psk_key_exchange_mode.0])?;
            }
        });
    });

    Ok(())
}


// 4.2.8.  Key Share
// https://tools.ietf.org/html/rfc8446#section-4.2.8
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyShareEntry<T: AsRef<[u8]>> {
    pub group: SupportedGroup,
    pub key: T
}

// struct {
//     NamedGroup group;
//     opaque key_exchange<1..2^16-1>;
// } KeyShareEntry;
// struct {
//     KeyShareEntry client_shares<0..2^16-1>;
// } KeyShareClientHello;
// struct {
//     KeyShareEntry server_share;
// } KeyShareServerHello;
// struct {
//     NamedGroup selected_group;
// } KeyShareHelloRetryRequest;
fn write_ext_key_share<T: AsRef<[u8]>>(cursor: &mut io::Cursor<Vec<u8>>, key_share: &KeyShareEntry<T>) -> Result<(), io::Error> {
    // 5.  The X25519 and X448 Functions (密钥的生成)
    // https://tools.ietf.org/html/rfc7748#section-5
    let key_exchange = key_share.key.as_ref();
    let all_zero = key_exchange.iter().all(|&n| n == 0);
    if all_zero {
        // NOTE: 密钥不能为全零
        return Err(io::Error::new(io::ErrorKind::Other, "all zero."));
    }
    let key_exchange_len = key_exchange.len();
    // <1..2^16-1>
    let key_exchange_len = u16::try_from(key_exchange_len).map_err(|_| io::Error::new(io::ErrorKind::Other, "payload size limit."))?;
    
    cursor.write_all(&key_share.group.to_be_bytes())?;
    cursor.write_all(&key_exchange_len.to_be_bytes())?;
    cursor.write_all(key_exchange)
}
pub fn write_ext_client_key_shares<T: AsRef<[u8]>>(cursor: &mut io::Cursor<Vec<u8>>, key_shares: &[KeyShareEntry<T>]) -> Result<(), io::Error> {
    // Extension: KEY_SHARE
    // https://tools.ietf.org/html/rfc8446#section-4.2.8
    if key_shares.is_empty() {
        return Err(io::Error::new(io::ErrorKind::Other, "payload size limit."));
    }

    cursor.write_all(&ExtensionKind::KEY_SHARE.0.to_be_bytes())?; // ExtensionKind
    transaction!(cursor, u16, 2, 0, 65535, {
        transaction!(cursor, u16, 2, 36, 65535, {
            for key_share in key_shares.iter() {
                write_ext_key_share(cursor, key_share)?;
            }
        });
    });

    Ok(())
}
pub fn write_ext_server_key_share<T: AsRef<[u8]>>(cursor: &mut io::Cursor<Vec<u8>>, key_share: &KeyShareEntry<T>) -> Result<(), io::Error> {
    cursor.write_all(&ExtensionKind::KEY_SHARE.0.to_be_bytes())?; // ExtensionKind
    transaction!(cursor, u16, 2, 0, 65535, {
        write_ext_key_share(cursor, key_share)?;
    });

    Ok(())
}

// | server_name [RFC6066]                            |      CH, EE |
// | max_fragment_length [RFC6066]                    |      CH, EE |
// | status_request [RFC6066]                         |  CH, CR, CT |
// | supported_groups [RFC7919]                       |      CH, EE |
// | signature_algorithms (RFC 8446)                  |      CH, CR |
// | use_srtp [RFC5764]                               |      CH, EE |
// | heartbeat [RFC6520]                              |      CH, EE |
// | application_layer_protocol_negotiation [RFC7301] |      CH, EE |
// | signed_certificate_timestamp [RFC6962]           |  CH, CR, CT |
// | client_certificate_type [RFC7250]                |      CH, EE |
// | server_certificate_type [RFC7250]                |      CH, EE |
// | padding [RFC7685]                                |          CH |
// | key_share (RFC 8446)                             | CH, SH, HRR |
// | pre_shared_key (RFC 8446)                        |      CH, SH |
// | psk_key_exchange_modes (RFC 8446)                |          CH |
// | early_data (RFC 8446)                            | CH, EE, NST |
// | cookie (RFC 8446)                                |     CH, HRR |
// | supported_versions (RFC 8446)                    | CH, SH, HRR |
// | certificate_authorities (RFC 8446)               |      CH, CR |
// | post_handshake_auth (RFC 8446)                   |          CH |
// | signature_algorithms_cert (RFC 8446)             |      CH, CR |
// 
// | oid_filters (RFC 8446)                           |          CR |

// TLS ClientCertificateType Identifiers
// https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-2
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClientCertificateKind(pub u8);

impl ClientCertificateKind {
    pub const RSA_SIGN: Self                  = Self(1);
    pub const DSS_SIGN: Self                  = Self(2);
    pub const RSA_FIXED_DH: Self              = Self(3);
    pub const DSS_FIXED_DH: Self              = Self(4);
    pub const RSA_EPHEMERAL_DH_RESERVED: Self = Self(5);
    pub const DSS_EPHEMERAL_DH_RESERVED: Self = Self(6);
    pub const FORTEZZA_DMS_RESERVED: Self     = Self(20);
    pub const ECDSA_SIGN: Self       = Self(64);
    pub const RSA_FIXED_ECDH: Self   = Self(65);
    pub const ECDSA_FIXED_ECDH: Self = Self(66);
    pub const GOST_SIGN256: Self     = Self(67);
    pub const GOST_SIGN512: Self     = Self(68);

    pub const fn to_be_bytes(&self) -> [u8; 1] {
        self.0.to_be_bytes()
    }
}

impl std::fmt::Display for ClientCertificateKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::RSA_SIGN => write!(f, "RSA_SIGN"),
            Self::DSS_SIGN => write!(f, "DSS_SIGN"),
            Self::RSA_FIXED_DH => write!(f, "RSA_FIXED_DH"),
            Self::DSS_FIXED_DH => write!(f, "DSS_FIXED_DH"),
            Self::RSA_EPHEMERAL_DH_RESERVED => write!(f, "RSA_EPHEMERAL_DH_RESERVED"),
            Self::DSS_EPHEMERAL_DH_RESERVED => write!(f, "DSS_EPHEMERAL_DH_RESERVED"),
            Self::FORTEZZA_DMS_RESERVED => write!(f, "FORTEZZA_DMS_RESERVED"),
            Self::ECDSA_SIGN => write!(f, "ECDSA_SIGN"),
            Self::RSA_FIXED_ECDH => write!(f, "RSA_FIXED_ECDH"),
            Self::ECDSA_FIXED_ECDH => write!(f, "ECDSA_FIXED_ECDH"),
            Self::GOST_SIGN256 => write!(f, "GOST_SIGN256"),
            Self::GOST_SIGN512 => write!(f, "GOST_SIGN512"),
            _ => write!(f, "Unknow({})", self.0),
        }
    }
}

// TLS Supplemental Data Formats (SupplementalDataType)
// https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-12
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SupplementalDataKind(pub u16);

impl SupplementalDataKind {
    pub const USER_MAPPING_DATA: Self = Self(0);
    pub const AUTHZ_DATA: Self        = Self(16386);

    pub const fn to_be_bytes(&self) -> [u8; 2] {
        self.0.to_be_bytes()
    }
}

impl std::fmt::Display for SupplementalDataKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::USER_MAPPING_DATA => write!(f, "USER_MAPPING_DATA"),
            Self::AUTHZ_DATA => write!(f, "AUTHZ_DATA"),
            _ => write!(f, "Unknow({})", self.0),
        }
    }
}

// TLS UserMappingType Values
// https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-14
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UserMappingKind(pub u8);

impl UserMappingKind {
    pub const UPN_DOMAIN_HINT: Self = Self(64);

    pub const fn to_be_bytes(&self) -> [u8; 1] {
        self.0.to_be_bytes()
    }
}

impl std::fmt::Display for UserMappingKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::UPN_DOMAIN_HINT => write!(f, "UPN_DOMAIN_HINT"),
            _ => write!(f, "Unknow({})", self.0),
        }
    }
}


// TLS Exporter Labels
// https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#exporter-labels
// TODO.


// TLS Authorization Data Formats
// https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#authorization-data
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthorizationDataFormat(pub u8);

impl AuthorizationDataFormat {
    pub const X509_ATTR_CERT: Self             = Self(0);
    pub const SAML_ASSERTION: Self             = Self(1);
    pub const X509_ATTR_CERT_URL: Self         = Self(2);
    pub const SAML_ASSERTION_URL: Self         = Self(3);
    pub const KEYNOTE_ASSERTION_LIST: Self     = Self(64);
    pub const KEYNOTE_ASSERTION_LIST_URL: Self = Self(65);
    pub const DTCP_AUTHORIZATION: Self         = Self(66);

    pub const fn to_be_bytes(&self) -> [u8; 1] {
        self.0.to_be_bytes()
    }
}

impl std::fmt::Display for AuthorizationDataFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::X509_ATTR_CERT => write!(f, "X509_ATTR_CERT"),
            Self::SAML_ASSERTION => write!(f, "SAML_ASSERTION"),
            Self::X509_ATTR_CERT_URL => write!(f, "X509_ATTR_CERT_URL"),
            Self::SAML_ASSERTION_URL => write!(f, "SAML_ASSERTION_URL"),
            Self::KEYNOTE_ASSERTION_LIST => write!(f, "KEYNOTE_ASSERTION_LIST"),
            Self::KEYNOTE_ASSERTION_LIST_URL => write!(f, "KEYNOTE_ASSERTION_LIST_URL"),
            Self::DTCP_AUTHORIZATION => write!(f, "DTCP_AUTHORIZATION"),
            _ => write!(f, "Unknow({})", self.0),
        }
    }
}