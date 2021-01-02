
// The TLS Protocol Version 1.0
// https://tools.ietf.org/html/rfc2246

// The Transport Layer Security (TLS) Protocol Version 1.1
// https://tools.ietf.org/html/rfc4346

// The Transport Layer Security (TLS) Protocol Version 1.2
// https://tools.ietf.org/html/rfc5246

// The Transport Layer Security (TLS) Protocol Version 1.3
// https://tools.ietf.org/html/rfc8446

// 6.2.1.  Fragmentation
// https://tools.ietf.org/html/rfc5246#section-6.2.1

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct ProtocolVersion {
    pub major: u8,
    pub minor: u8,
}

impl ProtocolVersion {
    pub const SSL_V2: Self   = Self { major: 2, minor: 0 };
    pub const SSL_V3: Self   = Self { major: 3, minor: 0 };
    pub const TLS_V1_0: Self = Self { major: 3, minor: 1 };
    pub const TLS_V1_1: Self = Self { major: 3, minor: 2 };
    pub const TLS_V1_2: Self = Self { major: 3, minor: 3 };
    pub const TLS_V1_3: Self = Self { major: 3, minor: 4 };
    
    pub const fn to_be_bytes(&self) -> [u8; 2] {
        [self.major, self.minor]
    }

    pub fn is_deprecated(&self) -> bool {
        // https://en.wikipedia.org/wiki/Transport_Layer_Security#History_and_development
        // SSL 1.0     Unpublished     Unpublished
        // SSL 2.0     1995    Deprecated in 2011 (RFC 6176)
        // SSL 3.0     1996    Deprecated in 2015 (RFC 7568)
        // TLS 1.0     1999    Deprecated in 2020 [11][12][13]
        // TLS 1.1     2006    Deprecated in 2020 [11][12][13]
        // TLS 1.2     2008    
        // TLS 1.3     2018    
        match *self {
            Self::SSL_V2 => true,
            Self::SSL_V3 => true,
            Self::TLS_V1_0 => true,
            Self::TLS_V1_1 => true,
            Self::TLS_V1_2 => false,
            Self::TLS_V1_3 => false,
            _ => false,
        }
    }
    
    pub fn is_undeprecated(&self) -> bool {
        !self.is_deprecated()
    }

    pub fn is_assigned(&self) -> bool {
        !self.is_unassigned()
    }

    pub fn is_unassigned(&self) -> bool {
        match *self {
            Self::SSL_V2 
            | Self::SSL_V3
            | Self::TLS_V1_0
            | Self::TLS_V1_1
            | Self::TLS_V1_2
            | Self::TLS_V1_3 => false,
            _ => true,
        }
    }
}

impl std::fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::SSL_V2 => write!(f, "SSLv2"),
            Self::SSL_V3 => write!(f, "SSLv3"),
            Self::TLS_V1_0 => write!(f, "TLSv1.0"),
            Self::TLS_V1_1 => write!(f, "TLSv1.1"),
            Self::TLS_V1_2 => write!(f, "TLSv1.2"),
            Self::TLS_V1_3 => write!(f, "TLSv1.3"),
            _ => write!(f, "Unassigned(major={}, minor={})", self.major, self.minor),
        }
    }
}
