use crate::wire::*;

// 5.1.  Record Layer
// https://tools.ietf.org/html/rfc8446#section-5.1
pub const RECORD_HDR_LEN: usize  = 5;
pub const RECORD_MAX_DLEN: usize = U14_MAX;
pub const RECORD_MAX_LEN: usize  = RECORD_HDR_LEN + RECORD_MAX_DLEN;

// TLS ContentType
// https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-5
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContentKind(pub u8);

impl ContentKind {
    pub const CHANGE_CIPHER_SPEC: Self = Self(20);
    pub const ALERT: Self              = Self(21);
    pub const HANDSHAKE: Self          = Self(22);
    pub const APPLICATION_DATA: Self   = Self(23);
    pub const HEARTBEAT: Self          = Self(24);
    // TEMPORARY - registered 2019-07-02, expires 2020-07-02
    pub const TLS12_CID: Self          = Self(25);

    pub const fn to_be_bytes(&self) -> [u8; 1] {
        self.0.to_be_bytes()
    }
}

impl std::fmt::Display for ContentKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::CHANGE_CIPHER_SPEC => write!(f, "CHANGE_CIPHER_SPEC"),
            Self::ALERT => write!(f, "ALERT"),
            Self::HANDSHAKE => write!(f, "HANDSHAKE"),
            Self::APPLICATION_DATA => write!(f, "APPLICATION_DATA"),
            Self::HEARTBEAT => write!(f, "HEARTBEAT"),
            Self::TLS12_CID => write!(f, "TLS12_CID"),
            _ => write!(f, "Unknow({})", self.0),
        }
    }
}

// 5.1.  Record Layer
// https://tools.ietf.org/html/rfc8446#section-5.1
// struct {
//     ContentType type;
//     ProtocolVersion legacy_record_version;
//     uint16 length;
//     opaque fragment[TLSPlaintext.length];
// } TLSPlaintext;
#[derive(Debug)]
pub struct TlsPlaintext<C> {
    pub kind: ContentKind,
    pub version: ProtocolVersion,
    pub content: C,
}

// struct {
//   opaque content[TLSPlaintext.length];
//   ContentType type;
//   uint8 zeros[length_of_padding];
// } TLSInnerPlaintext;
// 
// struct {
//   ContentType opaque_type = application_data; /* 23 */
//   ProtocolVersion legacy_record_version = 0x0303; /* TLS v1.2 */
//   uint16 length;
//   opaque encrypted_record[TLSCiphertext.length];
// } TLSCiphertext;