
// TLS HandshakeType
// https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-7
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HandshakeKind(pub u8);

impl HandshakeKind {
    // Used in TLS versions prior to 1.3.
    pub const HELLO_REQUEST_RESERVED: Self        = Self(0);
    pub const CLIENT_HELLO: Self                  = Self(1);
    pub const SERVER_HELLO: Self                  = Self(2);
    // Assigned for interim draft, but the functionality was moved to a different message.
    pub const HELLO_VERIFY_REQUEST_RESERVED: Self = Self(3);
    pub const NEW_SESSION_TICKET: Self            = Self(4);
    pub const END_OF_EARLY_DATA: Self             = Self(5);
    // Assigned for interim draft, but the functionality was moved to an extension.
    pub const HELLO_RETRY_REQUEST_RESERVED: Self  = Self(6);
    pub const ENCRYPTED_EXTENSIONS: Self          = Self(8);
    pub const CERTIFICATE: Self                   = Self(11);
    // Used in TLS versions prior to 1.3.
    pub const SERVER_KEY_EXCHANGE_RESERVED: Self  = Self(12);
    pub const CERTIFICATE_REQUEST: Self           = Self(13);
    // Used in TLS versions prior to 1.3.
    pub const SERVER_HELLO_DONE_RESERVED: Self    = Self(14);
    pub const CERTIFICATE_VERIFY: Self            = Self(15);
    // Used in TLS versions prior to 1.3.
    pub const CLIENT_KEY_EXCHANGE_RESERVED: Self  = Self(16);
    pub const FINISHED: Self                      = Self(20);
    // Used in TLS versions prior to 1.3.
    pub const CERTIFICATE_URL_RESERVED: Self      = Self(21);
    // Used in TLS versions prior to 1.3.
    pub const CERTIFICATE_STATUS_RESERVED: Self   = Self(22);
    // Used in TLS versions prior to 1.3.
    pub const SUPPLEMENTAL_DATA_RESERVED: Self    = Self(23);
    pub const KEY_UPDATE: Self                    = Self(24);
    pub const COMPRESSED_CERTIFICATE: Self        = Self(25);
    pub const MESSAGE_HASH: Self                  = Self(254);

    pub const fn to_be_bytes(&self) -> [u8; 1] {
        self.0.to_be_bytes()
    }
}

impl std::fmt::Display for HandshakeKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::HELLO_REQUEST_RESERVED => write!(f, "HELLO_REQUEST_RESERVED"),
            Self::CLIENT_HELLO => write!(f, "CLIENT_HELLO"),
            Self::SERVER_HELLO => write!(f, "SERVER_HELLO"),
            Self::HELLO_VERIFY_REQUEST_RESERVED => write!(f, "HELLO_VERIFY_REQUEST_RESERVED"),
            Self::NEW_SESSION_TICKET => write!(f, "NEW_SESSION_TICKET"),
            Self::END_OF_EARLY_DATA => write!(f, "END_OF_EARLY_DATA"),
            Self::HELLO_RETRY_REQUEST_RESERVED => write!(f, "HELLO_RETRY_REQUEST_RESERVED"),
            Self::ENCRYPTED_EXTENSIONS => write!(f, "ENCRYPTED_EXTENSIONS"),
            Self::CERTIFICATE => write!(f, "CERTIFICATE"),
            Self::SERVER_KEY_EXCHANGE_RESERVED => write!(f, "SERVER_KEY_EXCHANGE_RESERVED"),
            Self::CERTIFICATE_REQUEST => write!(f, "CERTIFICATE_REQUEST"),
            Self::SERVER_HELLO_DONE_RESERVED => write!(f, "SERVER_HELLO_DONE_RESERVED"),
            Self::CERTIFICATE_VERIFY => write!(f, "CERTIFICATE_VERIFY"),
            Self::CLIENT_KEY_EXCHANGE_RESERVED => write!(f, "CLIENT_KEY_EXCHANGE_RESERVED"),
            Self::FINISHED => write!(f, "FINISHED"),
            Self::CERTIFICATE_URL_RESERVED => write!(f, "CERTIFICATE_URL_RESERVED"),
            Self::CERTIFICATE_STATUS_RESERVED => write!(f, "CERTIFICATE_STATUS_RESERVED"),
            Self::SUPPLEMENTAL_DATA_RESERVED => write!(f, "SUPPLEMENTAL_DATA_RESERVED"),
            Self::KEY_UPDATE => write!(f, "KEY_UPDATE"),
            Self::COMPRESSED_CERTIFICATE => write!(f, "COMPRESSED_CERTIFICATE"),
            Self::MESSAGE_HASH => write!(f, "MESSAGE_HASH"),
            _ => write!(f, "Unknow({})", self.0),
        }
    }
}


// Transport Layer Security Protocol Compression Methods
// https://tools.ietf.org/html/rfc3749
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompressionMethod(pub u8);

impl CompressionMethod {
    pub const NULL: Self    = Self(0);
    // 15.  Orphaned Registries
    // https://tools.ietf.org/html/rfc8447#section-15
    // 
    // NOTE: TLSv1.3 遗弃了这个压缩方法，所以该值只会在 TLSv1.3 之前的版本协议当中会用到！
    pub const DEFLATE: Self = Self(1);

    pub const fn to_be_bytes(&self) -> [u8; 1] {
        self.0.to_be_bytes()
    }
}

impl std::fmt::Display for CompressionMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::NULL => write!(f, "NULL"),
            Self::DEFLATE => write!(f, "DEFLATE"),
            _ => write!(f, "Unknow({})", self.0),
        }
    }
}

// 7.4.1.2.  Client Hello
// https://tools.ietf.org/html/rfc5246#section-7.4.1.2
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Random(pub [u8; 32]);

impl Random {
    pub fn random() -> Self {
        let mut thread_rng = rand::thread_rng();
        let mut data = [0u8; 32];
        rand::Rng::fill(&mut thread_rng, &mut data);

        Self(data)
    }

    pub fn random_with_timestamp() -> Self {
        let now: u64 = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            Ok(now) => now.as_secs(),
            Err(e) => panic!(e),
        };
        assert!(now < std::u32::MAX as u64);
        let octes = (now as u32).to_be_bytes();

        let mut data = [0u8; 32];
        data[0] = octes[0];
        data[1] = octes[1];
        data[2] = octes[2];
        data[3] = octes[3];

        let mut thread_rng = rand::thread_rng();
        rand::Rng::fill(&mut thread_rng, &mut data[4..]);
        
        Self(data)
    }

    // Used in TLS versions prior to 1.3.
    pub fn gmt_unix_time(&self) -> u32 {
        u32::from_be_bytes([
            self.0[0], self.0[1], 
            self.0[2], self.0[3],
        ])
    }

    // Used in TLS versions prior to 1.3.
    pub fn random_bytes(&self) -> &[u8] {
        &self.0[4..]
    }
}

pub fn random_session_id() -> [u8; 32] {
    let mut arr = [0u8; 32];
    let mut thread_rng = rand::thread_rng();
    rand::Rng::fill(&mut thread_rng, &mut arr);

    arr
}


