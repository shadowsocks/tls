// A.3.  Alert Messages
// https://tools.ietf.org/html/rfc5246#appendix-A.3
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AlertLevel(pub u8);

impl AlertLevel {
    pub const WARN: Self  = Self(0x01);
    pub const FATAL: Self = Self(0x02);

    pub const fn to_be_bytes(&self) -> [u8; 1] {
        self.0.to_be_bytes()
    }
}

impl core::fmt::Display for AlertLevel {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::WARN => write!(f, "WARN"),
            Self::FATAL => write!(f, "FATAL"),
            _ => write!(f, "Unknow({})", self.0),
        }
    }
}

// TLS Alerts
// https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-6
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AlertDescription(pub u8);

impl AlertDescription {
    pub const CLOSE_NOTIFY: Self                   = Self(0);
    pub const UNEXPECTED_MESSAGE: Self             = Self(10);
    pub const BAD_RECORD_MAC: Self                 = Self(20);
    // Used in TLS versions prior to 1.3.
    pub const DECRYPTION_FAILED_RESERVED: Self     = Self(21);
    pub const RECORD_OVERFLOW: Self                = Self(22);
    // Used in TLS versions prior to 1.3.
    pub const DECOMPRESSION_FAILURE_RESERVED: Self = Self(30);
    pub const HANDSHAKE_FAILURE: Self              = Self(40);
    // Used in SSLv3 but not in TLS.
    pub const NO_CERTIFICATE_RESERVED: Self        = Self(41);
    pub const BAD_CERTIFICATE: Self                = Self(42);
    pub const UNSUPPORTED_CERTIFICATE: Self        = Self(43);
    pub const CERTIFICATE_REVOKED: Self            = Self(44);
    pub const CERTIFICATE_EXPIRED: Self            = Self(45);
    pub const CERTIFICATE_UNKNOWN: Self            = Self(46);
    pub const ILLEGAL_PARAMETER: Self              = Self(47);
    pub const UNKNOWN_CA: Self                     = Self(48);
    pub const ACCESS_DENIED: Self                  = Self(49);
    pub const DECODE_ERROR: Self                   = Self(50);
    pub const DECRYPT_ERROR: Self                  = Self(51);
    // Used in TLS 1.0 but not TLS 1.1 or later.
    pub const EXPORT_RESTRICTION_RESERVED: Self    = Self(60);
    pub const PROTOCOL_VERSION: Self               = Self(70);
    pub const INSUFFICIENT_SECURITY: Self          = Self(71);
    pub const INTERNAL_ERROR: Self                 = Self(80);
    pub const INAPPROPRIATE_FALLBACK: Self         = Self(86);
    pub const USER_CANCELED: Self                  = Self(90);
    // Used in TLS versions prior to 1.3.
    pub const NO_RENEGOTIATION_RESERVED: Self      = Self(100);
    pub const MISSING_EXTENSION: Self              = Self(109);
    pub const UNSUPPORTED_EXTENSION: Self          = Self(110);
    // Used in TLS versions prior to 1.3.
    pub const CERTIFICATE_UNOBTAINABLE_RESERVED: Self   = Self(111);
    pub const UNRECOGNIZED_NAME: Self                   = Self(112);
    pub const BAD_CERTIFICATE_STATUS_RESPONSE: Self     = Self(113);
    // Used in TLS versions prior to 1.3.
    pub const BAD_CERTIFICATE_HASH_VALUE_RESERVED: Self = Self(114);
    pub const UNKNOWN_PSK_IDENTITY: Self                = Self(115);
    pub const CERTIFICATE_REQUIRED: Self                = Self(116);
    pub const NO_APPLICATION_PROTOCOL: Self             = Self(120);

    pub const fn to_be_bytes(&self) -> [u8; 1] {
        self.0.to_be_bytes()
    }
}

impl core::fmt::Display for AlertDescription {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::CLOSE_NOTIFY       => write!(f, "CLOSE_NOTIFY"),
            Self::UNEXPECTED_MESSAGE => write!(f, "UNEXPECTED_MESSAGE"),
            Self::BAD_RECORD_MAC     => write!(f, "BAD_RECORD_MAC"),
            Self::DECRYPTION_FAILED_RESERVED => write!(f, "DECRYPTION_FAILED_RESERVED"),
            Self::RECORD_OVERFLOW => write!(f, "RECORD_OVERFLOW"),
            Self::DECOMPRESSION_FAILURE_RESERVED => write!(f, "DECOMPRESSION_FAILURE_RESERVED"),
            Self::HANDSHAKE_FAILURE => write!(f, "HANDSHAKE_FAILURE"),
            Self::NO_CERTIFICATE_RESERVED => write!(f, "NO_CERTIFICATE_RESERVED"),
            Self::BAD_CERTIFICATE => write!(f, "BAD_CERTIFICATE"),
            Self::UNSUPPORTED_CERTIFICATE => write!(f, "UNSUPPORTED_CERTIFICATE"),
            Self::CERTIFICATE_REVOKED => write!(f, "CERTIFICATE_REVOKED"),
            Self::CERTIFICATE_EXPIRED => write!(f, "CERTIFICATE_EXPIRED"),
            Self::CERTIFICATE_UNKNOWN => write!(f, "CERTIFICATE_UNKNOWN"),
            Self::ILLEGAL_PARAMETER => write!(f, "ILLEGAL_PARAMETER"),
            Self::UNKNOWN_CA => write!(f, "UNKNOWN_CA"),
            Self::ACCESS_DENIED => write!(f, "ACCESS_DENIED"),
            Self::DECODE_ERROR => write!(f, "DECODE_ERROR"),
            Self::DECRYPT_ERROR => write!(f, "DECRYPT_ERROR"),
            Self::EXPORT_RESTRICTION_RESERVED => write!(f, "EXPORT_RESTRICTION_RESERVED"),
            Self::PROTOCOL_VERSION => write!(f, "PROTOCOL_VERSION"),
            Self::INSUFFICIENT_SECURITY => write!(f, "INSUFFICIENT_SECURITY"),
            Self::INTERNAL_ERROR => write!(f, "INTERNAL_ERROR"),
            Self::INAPPROPRIATE_FALLBACK => write!(f, "INAPPROPRIATE_FALLBACK"),
            Self::USER_CANCELED => write!(f, "USER_CANCELED"),
            Self::NO_RENEGOTIATION_RESERVED => write!(f, "NO_RENEGOTIATION_RESERVED"),
            Self::MISSING_EXTENSION => write!(f, "MISSING_EXTENSION"),
            Self::UNSUPPORTED_EXTENSION => write!(f, "UNSUPPORTED_EXTENSION"),
            Self::CERTIFICATE_UNOBTAINABLE_RESERVED => write!(f, "CERTIFICATE_UNOBTAINABLE_RESERVED"),
            Self::UNRECOGNIZED_NAME => write!(f, "UNRECOGNIZED_NAME"),
            Self::BAD_CERTIFICATE_STATUS_RESPONSE => write!(f, "BAD_CERTIFICATE_STATUS_RESPONSE"),
            Self::BAD_CERTIFICATE_HASH_VALUE_RESERVED => write!(f, "BAD_CERTIFICATE_HASH_VALUE_RESERVED"),
            Self::UNKNOWN_PSK_IDENTITY => write!(f, "UNKNOWN_PSK_IDENTITY"),
            Self::CERTIFICATE_REQUIRED => write!(f, "CERTIFICATE_REQUIRED"),
            Self::NO_APPLICATION_PROTOCOL => write!(f, "NO_APPLICATION_PROTOCOL"),
            _ => write!(f, "Unknow({})", self.0),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Alert {
    pub level: AlertLevel,
    pub description: AlertDescription,
}

impl Alert {
    pub const fn to_be_bytes(&self) -> [u8; 2] {
        [self.level.0, self.description.0]
    }
}

impl core::fmt::Display for Alert {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "TLS {}: {}", self.level, self.description)
    }
}

#[derive(Debug)]
pub struct AlertPacket<T> {
    inner: T,
}

impl<T> AlertPacket<T> {
    pub fn into_inner(self) -> T {
        self.inner
    }
}

impl<T: AsRef<[u8]>> AlertPacket<T> {
    pub fn new_unchecked(inner: T) -> Self {
        Self { inner }
    }

    pub fn new_checked(inner: T) -> Result<Self, crate::error::Error> {
        let tmp = Self::new_unchecked(inner);
        if tmp.len() < 2 {
            return Err(crate::error::Error::from(crate::error::ErrorKind::DecodeError));
        }

        Ok(tmp)
    }

    pub fn len(&self) -> usize {
        let data = self.inner.as_ref();
        data.len()
    }

    pub fn level(&self) -> AlertLevel {
        let data = self.inner.as_ref();
        AlertLevel(data[0])
    }

    pub fn description(&self) -> AlertDescription {
        let data = self.inner.as_ref();
        AlertDescription(data[1])
    }

    pub fn as_alert(&self) -> Alert {
        let level = self.level();
        let description = self.description();

        Alert { level, description }
    }
}

impl<T: AsMut<[u8]>> AlertPacket<T> {
    pub fn set_level(&mut self, level: AlertLevel) {
        let data = self.inner.as_mut();
        data[0] = level.0;
    }

    pub fn set_description(&mut self, descp: AlertDescription) {
        let data = self.inner.as_mut();
        data[1] = descp.0;
    }
}
