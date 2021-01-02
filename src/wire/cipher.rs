
// TLS Cipher Suites
// https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CipherSuite(pub u16);

impl CipherSuite {
    pub const fn to_be_bytes(&self) -> [u8; 2] {
        self.0.to_be_bytes()
    }
    
    pub const fn v12_cipher_suites() -> [Self; 6] {
        // TLS v1.2 Recommend Cipher Suites
        [
            Self::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            Self::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            Self::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            Self::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            Self::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            Self::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        ]
    }
    
    pub const fn v13_cipher_suites() -> [Self; 5] {
        // TLS v1.3 Cipher Suites
        [
            Self::TLS_AES_128_GCM_SHA256,
            Self::TLS_AES_256_GCM_SHA384,
            Self::TLS_CHACHA20_POLY1305_SHA256,
            Self::TLS_AES_128_CCM_SHA256,
            Self::TLS_AES_128_CCM_8_SHA256,
        ]
    }

    // A.5. The CipherSuite   (TLS 1.0)
    // https://tools.ietf.org/html/rfc2246#appendix-A.5
    // 
    // A.5. The CipherSuite   (TLS 1.1)
    // https://tools.ietf.org/html/rfc4346#appendix-A.5
    // 
    // A.5.  The Cipher Suite (TLS 1.2)
    // https://tools.ietf.org/html/rfc5246#appendix-A.5
    pub const TLS_NULL_WITH_NULL_NULL: Self               = Self(u16::from_be_bytes([0x00, 0x00]));
    pub const TLS_RSA_WITH_NULL_MD5: Self                 = Self(u16::from_be_bytes([0x00, 0x01]));
    pub const TLS_RSA_WITH_NULL_SHA: Self                 = Self(u16::from_be_bytes([0x00, 0x02]));
    pub const TLS_RSA_EXPORT_WITH_RC4_40_MD5: Self        = Self(u16::from_be_bytes([0x00, 0x03]));
    pub const TLS_RSA_WITH_RC4_128_MD5: Self              = Self(u16::from_be_bytes([0x00, 0x04]));
    pub const TLS_RSA_WITH_RC4_128_SHA: Self              = Self(u16::from_be_bytes([0x00, 0x05]));
    pub const TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5: Self    = Self(u16::from_be_bytes([0x00, 0x06]));
    pub const TLS_RSA_WITH_IDEA_CBC_SHA: Self             = Self(u16::from_be_bytes([0x00, 0x07]));
    pub const TLS_RSA_EXPORT_WITH_DES40_CBC_SHA: Self     = Self(u16::from_be_bytes([0x00, 0x08]));
    pub const TLS_RSA_WITH_DES_CBC_SHA: Self              = Self(u16::from_be_bytes([0x00, 0x09]));
    pub const TLS_RSA_WITH_3DES_EDE_CBC_SHA: Self         = Self(u16::from_be_bytes([0x00, 0x0A]));
    pub const TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA: Self  = Self(u16::from_be_bytes([0x00, 0x0B]));
    pub const TLS_DH_DSS_WITH_DES_CBC_SHA: Self           = Self(u16::from_be_bytes([0x00, 0x0C]));
    pub const TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA: Self      = Self(u16::from_be_bytes([0x00, 0x0D]));
    pub const TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA: Self  = Self(u16::from_be_bytes([0x00, 0x0E]));
    pub const TLS_DH_RSA_WITH_DES_CBC_SHA: Self           = Self(u16::from_be_bytes([0x00, 0x0F]));
    pub const TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA: Self      = Self(u16::from_be_bytes([0x00, 0x10]));
    pub const TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA: Self = Self(u16::from_be_bytes([0x00, 0x11]));
    pub const TLS_DHE_DSS_WITH_DES_CBC_SHA: Self          = Self(u16::from_be_bytes([0x00, 0x12]));
    pub const TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA: Self     = Self(u16::from_be_bytes([0x00, 0x13]));
    pub const TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA: Self = Self(u16::from_be_bytes([0x00, 0x14]));
    pub const TLS_DHE_RSA_WITH_DES_CBC_SHA: Self          = Self(u16::from_be_bytes([0x00, 0x15]));
    pub const TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA: Self     = Self(u16::from_be_bytes([0x00, 0x16]));
    pub const TLS_DH_ANON_EXPORT_WITH_RC4_40_MD5: Self    = Self(u16::from_be_bytes([0x00, 0x17]));
    pub const TLS_DH_ANON_WITH_RC4_128_MD5: Self          = Self(u16::from_be_bytes([0x00, 0x18]));
    pub const TLS_DH_ANON_EXPORT_WITH_DES40_CBC_SHA: Self = Self(u16::from_be_bytes([0x00, 0x19]));
    pub const TLS_DH_ANON_WITH_DES_CBC_SHA: Self          = Self(u16::from_be_bytes([0x00, 0x1A]));
    pub const TLS_DH_ANON_WITH_3DES_EDE_CBC_SHA: Self     = Self(u16::from_be_bytes([0x00, 0x1B]));

    // A.5. The CipherSuite   (TLS 1.1)
    // https://tools.ietf.org/html/rfc4346#appendix-A.5
    pub const TLS_KRB5_WITH_DES_CBC_SHA: Self             = Self(u16::from_be_bytes([0x00, 0x1E]));
    pub const TLS_KRB5_WITH_3DES_EDE_CBC_SHA: Self        = Self(u16::from_be_bytes([0x00, 0x1F]));
    pub const TLS_KRB5_WITH_RC4_128_SHA: Self             = Self(u16::from_be_bytes([0x00, 0x20]));
    pub const TLS_KRB5_WITH_IDEA_CBC_SHA: Self            = Self(u16::from_be_bytes([0x00, 0x21]));
    pub const TLS_KRB5_WITH_DES_CBC_MD5: Self             = Self(u16::from_be_bytes([0x00, 0x22]));
    pub const TLS_KRB5_WITH_3DES_EDE_CBC_MD5: Self        = Self(u16::from_be_bytes([0x00, 0x23]));
    pub const TLS_KRB5_WITH_RC4_128_MD5: Self             = Self(u16::from_be_bytes([0x00, 0x24]));
    pub const TLS_KRB5_WITH_IDEA_CBC_MD5: Self            = Self(u16::from_be_bytes([0x00, 0x25]));
    pub const TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA: Self   = Self(u16::from_be_bytes([0x00, 0x26]));
    pub const TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA: Self   = Self(u16::from_be_bytes([0x00, 0x27]));
    pub const TLS_KRB5_EXPORT_WITH_RC4_40_SHA: Self       = Self(u16::from_be_bytes([0x00, 0x28]));
    pub const TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5: Self   = Self(u16::from_be_bytes([0x00, 0x29]));
    pub const TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5: Self   = Self(u16::from_be_bytes([0x00, 0x2A]));
    pub const TLS_KRB5_EXPORT_WITH_RC4_40_MD5: Self       = Self(u16::from_be_bytes([0x00, 0x2B]));
    pub const TLS_PSK_WITH_NULL_SHA: Self                 = Self(u16::from_be_bytes([0x00, 0x2C]));
    pub const TLS_DHE_PSK_WITH_NULL_SHA: Self             = Self(u16::from_be_bytes([0x00, 0x2D]));
    pub const TLS_RSA_PSK_WITH_NULL_SHA: Self             = Self(u16::from_be_bytes([0x00, 0x2E]));
    pub const TLS_RSA_WITH_AES_128_CBC_SHA: Self          = Self(u16::from_be_bytes([0x00, 0x2F]));
    pub const TLS_DH_DSS_WITH_AES_128_CBC_SHA: Self       = Self(u16::from_be_bytes([0x00, 0x30]));
    pub const TLS_DH_RSA_WITH_AES_128_CBC_SHA: Self       = Self(u16::from_be_bytes([0x00, 0x31]));
    pub const TLS_DHE_DSS_WITH_AES_128_CBC_SHA: Self      = Self(u16::from_be_bytes([0x00, 0x32]));
    pub const TLS_DHE_RSA_WITH_AES_128_CBC_SHA: Self      = Self(u16::from_be_bytes([0x00, 0x33]));
    pub const TLS_DH_ANON_WITH_AES_128_CBC_SHA: Self      = Self(u16::from_be_bytes([0x00, 0x34]));
    pub const TLS_RSA_WITH_AES_256_CBC_SHA: Self          = Self(u16::from_be_bytes([0x00, 0x35]));
    pub const TLS_DH_DSS_WITH_AES_256_CBC_SHA: Self       = Self(u16::from_be_bytes([0x00, 0x36]));
    pub const TLS_DH_RSA_WITH_AES_256_CBC_SHA: Self       = Self(u16::from_be_bytes([0x00, 0x37]));
    pub const TLS_DHE_DSS_WITH_AES_256_CBC_SHA: Self      = Self(u16::from_be_bytes([0x00, 0x38]));
    pub const TLS_DHE_RSA_WITH_AES_256_CBC_SHA: Self      = Self(u16::from_be_bytes([0x00, 0x39]));
    pub const TLS_DH_ANON_WITH_AES_256_CBC_SHA: Self      = Self(u16::from_be_bytes([0x00, 0x3A]));

    // A.5.  The Cipher Suite (TLS 1.2)
    // https://tools.ietf.org/html/rfc5246#appendix-A.5
    pub const TLS_RSA_WITH_NULL_SHA256: Self              = Self(u16::from_be_bytes([0x00, 0x3B]));
    pub const TLS_RSA_WITH_AES_128_CBC_SHA256: Self       = Self(u16::from_be_bytes([0x00, 0x3C]));
    pub const TLS_RSA_WITH_AES_256_CBC_SHA256: Self       = Self(u16::from_be_bytes([0x00, 0x3D]));
    pub const TLS_DH_DSS_WITH_AES_128_CBC_SHA256: Self    = Self(u16::from_be_bytes([0x00, 0x3E]));
    pub const TLS_DH_RSA_WITH_AES_128_CBC_SHA256: Self    = Self(u16::from_be_bytes([0x00, 0x3F]));
    pub const TLS_DHE_DSS_WITH_AES_128_CBC_SHA256: Self   = Self(u16::from_be_bytes([0x00, 0x40]));
    pub const TLS_RSA_WITH_CAMELLIA_128_CBC_SHA: Self     = Self(u16::from_be_bytes([0x00, 0x41]));
    pub const TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA: Self  = Self(u16::from_be_bytes([0x00, 0x42]));
    pub const TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA: Self  = Self(u16::from_be_bytes([0x00, 0x43]));
    pub const TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA: Self = Self(u16::from_be_bytes([0x00, 0x44]));
    pub const TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA: Self = Self(u16::from_be_bytes([0x00, 0x45]));
    pub const TLS_DH_ANON_WITH_CAMELLIA_128_CBC_SHA: Self = Self(u16::from_be_bytes([0x00, 0x46]));
    pub const TLS_DHE_RSA_WITH_AES_128_CBC_SHA256: Self   = Self(u16::from_be_bytes([0x00, 0x67]));
    pub const TLS_DH_DSS_WITH_AES_256_CBC_SHA256: Self    = Self(u16::from_be_bytes([0x00, 0x68]));
    pub const TLS_DH_RSA_WITH_AES_256_CBC_SHA256: Self    = Self(u16::from_be_bytes([0x00, 0x69]));
    pub const TLS_DHE_DSS_WITH_AES_256_CBC_SHA256: Self   = Self(u16::from_be_bytes([0x00, 0x6A]));
    pub const TLS_DHE_RSA_WITH_AES_256_CBC_SHA256: Self   = Self(u16::from_be_bytes([0x00, 0x6B]));
    pub const TLS_DH_ANON_WITH_AES_128_CBC_SHA256: Self   = Self(u16::from_be_bytes([0x00, 0x6C]));
    pub const TLS_DH_ANON_WITH_AES_256_CBC_SHA256: Self   = Self(u16::from_be_bytes([0x00, 0x6D]));

    // Camellia Cipher Suites for TLS
    // https://tools.ietf.org/html/rfc5932
    pub const TLS_RSA_WITH_CAMELLIA_256_CBC_SHA: Self     = Self(u16::from_be_bytes([0x00, 0x84]));
    pub const TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA: Self  = Self(u16::from_be_bytes([0x00, 0x85]));
    pub const TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA: Self  = Self(u16::from_be_bytes([0x00, 0x86]));
    pub const TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA: Self = Self(u16::from_be_bytes([0x00, 0x87]));
    pub const TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA: Self = Self(u16::from_be_bytes([0x00, 0x88]));
    pub const TLS_DH_ANON_WITH_CAMELLIA_256_CBC_SHA: Self = Self(u16::from_be_bytes([0x00, 0x89]));
    pub const TLS_PSK_WITH_RC4_128_SHA: Self              = Self(u16::from_be_bytes([0x00, 0x8A]));
    pub const TLS_PSK_WITH_3DES_EDE_CBC_SHA: Self         = Self(u16::from_be_bytes([0x00, 0x8B]));
    pub const TLS_PSK_WITH_AES_128_CBC_SHA: Self          = Self(u16::from_be_bytes([0x00, 0x8C]));
    pub const TLS_PSK_WITH_AES_256_CBC_SHA: Self          = Self(u16::from_be_bytes([0x00, 0x8D]));
    pub const TLS_DHE_PSK_WITH_RC4_128_SHA: Self          = Self(u16::from_be_bytes([0x00, 0x8E]));
    pub const TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA: Self     = Self(u16::from_be_bytes([0x00, 0x8F]));
    pub const TLS_DHE_PSK_WITH_AES_128_CBC_SHA: Self      = Self(u16::from_be_bytes([0x00, 0x90]));
    pub const TLS_DHE_PSK_WITH_AES_256_CBC_SHA: Self      = Self(u16::from_be_bytes([0x00, 0x91]));
    pub const TLS_RSA_PSK_WITH_RC4_128_SHA: Self          = Self(u16::from_be_bytes([0x00, 0x92]));
    pub const TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA: Self     = Self(u16::from_be_bytes([0x00, 0x93]));
    pub const TLS_RSA_PSK_WITH_AES_128_CBC_SHA: Self      = Self(u16::from_be_bytes([0x00, 0x94]));
    pub const TLS_RSA_PSK_WITH_AES_256_CBC_SHA: Self      = Self(u16::from_be_bytes([0x00, 0x95]));
    pub const TLS_RSA_WITH_SEED_CBC_SHA: Self             = Self(u16::from_be_bytes([0x00, 0x96]));
    pub const TLS_DH_DSS_WITH_SEED_CBC_SHA: Self          = Self(u16::from_be_bytes([0x00, 0x97]));
    pub const TLS_DH_RSA_WITH_SEED_CBC_SHA: Self          = Self(u16::from_be_bytes([0x00, 0x98]));
    pub const TLS_DHE_DSS_WITH_SEED_CBC_SHA: Self         = Self(u16::from_be_bytes([0x00, 0x99]));
    pub const TLS_DHE_RSA_WITH_SEED_CBC_SHA: Self         = Self(u16::from_be_bytes([0x00, 0x9A]));
    pub const TLS_DH_ANON_WITH_SEED_CBC_SHA: Self         = Self(u16::from_be_bytes([0x00, 0x9B]));
    pub const TLS_RSA_WITH_AES_128_GCM_SHA256: Self       = Self(u16::from_be_bytes([0x00, 0x9C]));
    pub const TLS_RSA_WITH_AES_256_GCM_SHA384: Self       = Self(u16::from_be_bytes([0x00, 0x9D]));
    pub const TLS_DHE_RSA_WITH_AES_128_GCM_SHA256: Self   = Self(u16::from_be_bytes([0x00, 0x9E]));
    pub const TLS_DHE_RSA_WITH_AES_256_GCM_SHA384: Self   = Self(u16::from_be_bytes([0x00, 0x9F]));
    pub const TLS_DH_RSA_WITH_AES_128_GCM_SHA256: Self    = Self(u16::from_be_bytes([0x00, 0xA0]));
    pub const TLS_DH_RSA_WITH_AES_256_GCM_SHA384: Self    = Self(u16::from_be_bytes([0x00, 0xA1]));
    pub const TLS_DHE_DSS_WITH_AES_128_GCM_SHA256: Self   = Self(u16::from_be_bytes([0x00, 0xA2]));
    pub const TLS_DHE_DSS_WITH_AES_256_GCM_SHA384: Self   = Self(u16::from_be_bytes([0x00, 0xA3]));
    pub const TLS_DH_DSS_WITH_AES_128_GCM_SHA256: Self    = Self(u16::from_be_bytes([0x00, 0xA4]));
    pub const TLS_DH_DSS_WITH_AES_256_GCM_SHA384: Self    = Self(u16::from_be_bytes([0x00, 0xA5]));
    pub const TLS_DH_ANON_WITH_AES_128_GCM_SHA256: Self   = Self(u16::from_be_bytes([0x00, 0xA6]));
    pub const TLS_DH_ANON_WITH_AES_256_GCM_SHA384: Self   = Self(u16::from_be_bytes([0x00, 0xA7]));
    pub const TLS_PSK_WITH_AES_128_GCM_SHA256: Self       = Self(u16::from_be_bytes([0x00, 0xA8]));
    pub const TLS_PSK_WITH_AES_256_GCM_SHA384: Self       = Self(u16::from_be_bytes([0x00, 0xA9]));
    pub const TLS_DHE_PSK_WITH_AES_128_GCM_SHA256: Self   = Self(u16::from_be_bytes([0x00, 0xAA]));
    pub const TLS_DHE_PSK_WITH_AES_256_GCM_SHA384: Self   = Self(u16::from_be_bytes([0x00, 0xAB]));
    pub const TLS_RSA_PSK_WITH_AES_128_GCM_SHA256: Self   = Self(u16::from_be_bytes([0x00, 0xAC]));
    pub const TLS_RSA_PSK_WITH_AES_256_GCM_SHA384: Self   = Self(u16::from_be_bytes([0x00, 0xAD]));
    pub const TLS_PSK_WITH_AES_128_CBC_SHA256: Self       = Self(u16::from_be_bytes([0x00, 0xAE]));
    pub const TLS_PSK_WITH_AES_256_CBC_SHA384: Self       = Self(u16::from_be_bytes([0x00, 0xAF]));
    pub const TLS_PSK_WITH_NULL_SHA256: Self              = Self(u16::from_be_bytes([0x00, 0xB0]));
    pub const TLS_PSK_WITH_NULL_SHA384: Self              = Self(u16::from_be_bytes([0x00, 0xB1]));
    pub const TLS_DHE_PSK_WITH_AES_128_CBC_SHA256: Self   = Self(u16::from_be_bytes([0x00, 0xB2]));
    pub const TLS_DHE_PSK_WITH_AES_256_CBC_SHA384: Self   = Self(u16::from_be_bytes([0x00, 0xB3]));
    pub const TLS_DHE_PSK_WITH_NULL_SHA256: Self          = Self(u16::from_be_bytes([0x00, 0xB4]));
    pub const TLS_DHE_PSK_WITH_NULL_SHA384: Self          = Self(u16::from_be_bytes([0x00, 0xB5]));
    pub const TLS_RSA_PSK_WITH_AES_128_CBC_SHA256: Self   = Self(u16::from_be_bytes([0x00, 0xB6]));
    pub const TLS_RSA_PSK_WITH_AES_256_CBC_SHA384: Self   = Self(u16::from_be_bytes([0x00, 0xB7]));
    pub const TLS_RSA_PSK_WITH_NULL_SHA256: Self          = Self(u16::from_be_bytes([0x00, 0xB8]));
    pub const TLS_RSA_PSK_WITH_NULL_SHA384: Self          = Self(u16::from_be_bytes([0x00, 0xB9]));
    pub const TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256: Self  = Self(u16::from_be_bytes([0x00, 0xBA]));
    pub const TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256: Self  = Self(u16::from_be_bytes([0x00, 0xBB]));
    pub const TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256: Self  = Self(u16::from_be_bytes([0x00, 0xBC]));
    pub const TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256: Self = Self(u16::from_be_bytes([0x00, 0xBD]));
    pub const TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256: Self = Self(u16::from_be_bytes([0x00, 0xBE]));
    pub const TLS_DH_ANON_WITH_CAMELLIA_128_CBC_SHA256: Self = Self(u16::from_be_bytes([0x00, 0xBF]));
    pub const TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256: Self     = Self(u16::from_be_bytes([0x00, 0xC0]));
    pub const TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256: Self  = Self(u16::from_be_bytes([0x00, 0xC1]));
    pub const TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256: Self  = Self(u16::from_be_bytes([0x00, 0xC2]));
    pub const TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256: Self = Self(u16::from_be_bytes([0x00, 0xC3]));
    pub const TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256: Self = Self(u16::from_be_bytes([0x00, 0xC4]));
    pub const TLS_DH_ANON_WITH_CAMELLIA_256_CBC_SHA256: Self = Self(u16::from_be_bytes([0x00, 0xC5]));
    pub const TLS_SM4_GCM_SM3: Self                          = Self(u16::from_be_bytes([0x00, 0xC6]));
    pub const TLS_SM4_CCM_SM3: Self                          = Self(u16::from_be_bytes([0x00, 0xC7]));
    pub const TLS_EMPTY_RENEGOTIATION_INFO_SCSV: Self        = Self(u16::from_be_bytes([0x00, 0xFF]));

    // TLS 1.3 Cipher Suites
    // https://tools.ietf.org/html/rfc8446#appendix-B.4
    // 
    // CipherSuite TLS_AEAD_HASH = VALUE;
    // 
    // +-----------+------------------------------------------------+
    // | Component | Contents                                       |
    // +-----------+------------------------------------------------+
    // | TLS       | The string "TLS"                               |
    // |           |                                                |
    // | AEAD      | The AEAD algorithm used for record protection  |
    // |           |                                                |
    // | HASH      | The hash algorithm used with HKDF              |
    // |           |                                                |
    // | VALUE     | The two-byte ID assigned for this cipher suite |
    // +-----------+------------------------------------------------+
    // 
    // +------------------------------+-------------+
    // | Description                  | Value       |
    // +------------------------------+-------------+
    // | TLS_AES_128_GCM_SHA256       | {0x13,0x01} |
    // |                              |             |
    // | TLS_AES_256_GCM_SHA384       | {0x13,0x02} |
    // |                              |             |
    // | TLS_CHACHA20_POLY1305_SHA256 | {0x13, 0x03}|
    // |                              |             |
    // | TLS_AES_128_CCM_SHA256       | {0x13,0x04} |
    // |                              |             |
    // | TLS_AES_128_CCM_8_SHA256     | {0x13,0x05} |
    // +------------------------------+-------------+
    pub const TLS_AES_128_GCM_SHA256: Self       = Self(u16::from_be_bytes([0x13, 0x01]));
    pub const TLS_AES_256_GCM_SHA384: Self       = Self(u16::from_be_bytes([0x13, 0x02]));
    pub const TLS_CHACHA20_POLY1305_SHA256: Self = Self(u16::from_be_bytes([0x13, 0x03]));
    pub const TLS_AES_128_CCM_SHA256: Self       = Self(u16::from_be_bytes([0x13, 0x04]));
    pub const TLS_AES_128_CCM_8_SHA256: Self     = Self(u16::from_be_bytes([0x13, 0x05]));

    pub const TLS_FALLBACK_SCSV: Self            = Self(u16::from_be_bytes([0x56, 0x00]));

    // Elliptic Curve Cryptography (ECC) Cipher Suites for Transport Layer Security (TLS) Versions 1.2 and Earlier
    // 
    // 6.  Cipher Suites
    // https://tools.ietf.org/html/rfc8422#section-6
    pub const TLS_ECDH_ECDSA_WITH_NULL_SHA: Self = Self(u16::from_be_bytes([0xC0, 0x01]));
    pub const TLS_ECDH_ECDSA_WITH_RC4_128_SHA: Self = Self(u16::from_be_bytes([0xC0, 0x02]));
    pub const TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA: Self = Self(u16::from_be_bytes([0xC0, 0x03]));
    pub const TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA: Self = Self(u16::from_be_bytes([0xC0, 0x04]));
    pub const TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA: Self = Self(u16::from_be_bytes([0xC0, 0x05]));
    pub const TLS_ECDHE_ECDSA_WITH_NULL_SHA: Self = Self(u16::from_be_bytes([0xC0, 0x06]));
    pub const TLS_ECDHE_ECDSA_WITH_RC4_128_SHA: Self = Self(u16::from_be_bytes([0xC0, 0x07]));
    pub const TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA: Self = Self(u16::from_be_bytes([0xC0, 0x08]));
    pub const TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA: Self = Self(u16::from_be_bytes([0xC0, 0x09]));
    pub const TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA: Self = Self(u16::from_be_bytes([0xC0, 0x0A]));
    pub const TLS_ECDH_RSA_WITH_NULL_SHA: Self = Self(u16::from_be_bytes([0xC0, 0x0B]));
    pub const TLS_ECDH_RSA_WITH_RC4_128_SHA: Self = Self(u16::from_be_bytes([0xC0, 0x0C]));
    pub const TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA: Self = Self(u16::from_be_bytes([0xC0, 0x0D]));
    pub const TLS_ECDH_RSA_WITH_AES_128_CBC_SHA: Self = Self(u16::from_be_bytes([0xC0, 0x0E]));
    pub const TLS_ECDH_RSA_WITH_AES_256_CBC_SHA: Self = Self(u16::from_be_bytes([0xC0, 0x0F]));
    pub const TLS_ECDHE_RSA_WITH_NULL_SHA: Self = Self(u16::from_be_bytes([0xC0, 0x10]));
    pub const TLS_ECDHE_RSA_WITH_RC4_128_SHA: Self = Self(u16::from_be_bytes([0xC0, 0x11]));
    pub const TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA: Self = Self(u16::from_be_bytes([0xC0, 0x12]));
    pub const TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA: Self = Self(u16::from_be_bytes([0xC0, 0x13]));
    pub const TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA: Self = Self(u16::from_be_bytes([0xC0, 0x14]));
    pub const TLS_ECDH_ANON_WITH_NULL_SHA: Self = Self(u16::from_be_bytes([0xC0, 0x15]));
    pub const TLS_ECDH_ANON_WITH_RC4_128_SHA: Self = Self(u16::from_be_bytes([0xC0, 0x16]));
    pub const TLS_ECDH_ANON_WITH_3DES_EDE_CBC_SHA: Self = Self(u16::from_be_bytes([0xC0, 0x17]));
    pub const TLS_ECDH_ANON_WITH_AES_128_CBC_SHA: Self = Self(u16::from_be_bytes([0xC0, 0x18]));
    pub const TLS_ECDH_ANON_WITH_AES_256_CBC_SHA: Self = Self(u16::from_be_bytes([0xC0, 0x19]));
    pub const TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA: Self = Self(u16::from_be_bytes([0xC0, 0x1A]));
    pub const TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA: Self = Self(u16::from_be_bytes([0xC0, 0x1B]));
    pub const TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA: Self = Self(u16::from_be_bytes([0xC0, 0x1C]));
    pub const TLS_SRP_SHA_WITH_AES_128_CBC_SHA: Self = Self(u16::from_be_bytes([0xC0, 0x1D]));
    pub const TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA: Self = Self(u16::from_be_bytes([0xC0, 0x1E]));
    pub const TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA: Self = Self(u16::from_be_bytes([0xC0, 0x1F]));
    pub const TLS_SRP_SHA_WITH_AES_256_CBC_SHA: Self = Self(u16::from_be_bytes([0xC0, 0x20]));
    pub const TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA: Self = Self(u16::from_be_bytes([0xC0, 0x21]));
    pub const TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA: Self = Self(u16::from_be_bytes([0xC0, 0x22]));
    pub const TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256: Self = Self(u16::from_be_bytes([0xC0, 0x23]));
    pub const TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384: Self = Self(u16::from_be_bytes([0xC0, 0x24]));
    pub const TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256: Self = Self(u16::from_be_bytes([0xC0, 0x25]));
    pub const TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384: Self = Self(u16::from_be_bytes([0xC0, 0x26]));
    pub const TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256: Self = Self(u16::from_be_bytes([0xC0, 0x27]));
    pub const TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384: Self = Self(u16::from_be_bytes([0xC0, 0x28]));
    pub const TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256: Self = Self(u16::from_be_bytes([0xC0, 0x29]));
    pub const TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384: Self = Self(u16::from_be_bytes([0xC0, 0x2A]));

    pub const TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: Self = Self(u16::from_be_bytes([0xC0, 0x2B]));
    pub const TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: Self = Self(u16::from_be_bytes([0xC0, 0x2C]));

    pub const TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256: Self = Self(u16::from_be_bytes([0xC0, 0x2D]));
    pub const TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384: Self = Self(u16::from_be_bytes([0xC0, 0x2E]));

    pub const TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: Self = Self(u16::from_be_bytes([0xC0, 0x2F]));
    pub const TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: Self = Self(u16::from_be_bytes([0xC0, 0x30]));

    pub const TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256: Self = Self(u16::from_be_bytes([0xC0, 0x31]));
    pub const TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384: Self = Self(u16::from_be_bytes([0xC0, 0x32]));
    pub const TLS_ECDHE_PSK_WITH_RC4_128_SHA: Self = Self(u16::from_be_bytes([0xC0, 0x33]));
    pub const TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA: Self = Self(u16::from_be_bytes([0xC0, 0x34]));
    pub const TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA: Self = Self(u16::from_be_bytes([0xC0, 0x35]));
    pub const TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA: Self = Self(u16::from_be_bytes([0xC0, 0x36]));
    pub const TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256: Self = Self(u16::from_be_bytes([0xC0, 0x37]));
    pub const TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384: Self = Self(u16::from_be_bytes([0xC0, 0x38]));
    pub const TLS_ECDHE_PSK_WITH_NULL_SHA: Self = Self(u16::from_be_bytes([0xC0, 0x39]));
    pub const TLS_ECDHE_PSK_WITH_NULL_SHA256: Self = Self(u16::from_be_bytes([0xC0, 0x3A]));
    pub const TLS_ECDHE_PSK_WITH_NULL_SHA384: Self = Self(u16::from_be_bytes([0xC0, 0x3B]));
    pub const TLS_RSA_WITH_ARIA_128_CBC_SHA256: Self = Self(u16::from_be_bytes([0xC0, 0x3C]));
    pub const TLS_RSA_WITH_ARIA_256_CBC_SHA384: Self = Self(u16::from_be_bytes([0xC0, 0x3D]));
    pub const TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256: Self = Self(u16::from_be_bytes([0xC0, 0x3E]));
    pub const TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384: Self = Self(u16::from_be_bytes([0xC0, 0x3F]));
    pub const TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256: Self = Self(u16::from_be_bytes([0xC0, 0x40]));
    pub const TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384: Self = Self(u16::from_be_bytes([0xC0, 0x41]));
    pub const TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256: Self = Self(u16::from_be_bytes([0xC0, 0x42]));
    pub const TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384: Self = Self(u16::from_be_bytes([0xC0, 0x43]));
    pub const TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256: Self = Self(u16::from_be_bytes([0xC0, 0x44]));
    pub const TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384: Self = Self(u16::from_be_bytes([0xC0, 0x45]));
    pub const TLS_DH_ANON_WITH_ARIA_128_CBC_SHA256: Self = Self(u16::from_be_bytes([0xC0, 0x46]));
    pub const TLS_DH_ANON_WITH_ARIA_256_CBC_SHA384: Self = Self(u16::from_be_bytes([0xC0, 0x47]));
    pub const TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256: Self = Self(u16::from_be_bytes([0xC0, 0x48]));
    pub const TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384: Self = Self(u16::from_be_bytes([0xC0, 0x49]));
    pub const TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256: Self = Self(u16::from_be_bytes([0xC0, 0x4A]));
    pub const TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384: Self = Self(u16::from_be_bytes([0xC0, 0x4B]));
    pub const TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256: Self = Self(u16::from_be_bytes([0xC0, 0x4C]));
    pub const TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384: Self = Self(u16::from_be_bytes([0xC0, 0x4D]));
    pub const TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256: Self = Self(u16::from_be_bytes([0xC0, 0x4E]));
    pub const TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384: Self = Self(u16::from_be_bytes([0xC0, 0x4F]));
    pub const TLS_RSA_WITH_ARIA_128_GCM_SHA256: Self = Self(u16::from_be_bytes([0xC0, 0x50]));
    pub const TLS_RSA_WITH_ARIA_256_GCM_SHA384: Self = Self(u16::from_be_bytes([0xC0, 0x51]));
    pub const TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256: Self = Self(u16::from_be_bytes([0xC0, 0x52]));
    pub const TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384: Self = Self(u16::from_be_bytes([0xC0, 0x53]));
    pub const TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256: Self = Self(u16::from_be_bytes([0xC0, 0x54]));
    pub const TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384: Self = Self(u16::from_be_bytes([0xC0, 0x55]));
    pub const TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256: Self = Self(u16::from_be_bytes([0xC0, 0x56]));
    pub const TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384: Self = Self(u16::from_be_bytes([0xC0, 0x57]));
    pub const TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256: Self = Self(u16::from_be_bytes([0xC0, 0x58]));
    pub const TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384: Self = Self(u16::from_be_bytes([0xC0, 0x59]));
    pub const TLS_DH_ANON_WITH_ARIA_128_GCM_SHA256: Self = Self(u16::from_be_bytes([0xC0, 0x5A]));
    pub const TLS_DH_ANON_WITH_ARIA_256_GCM_SHA384: Self = Self(u16::from_be_bytes([0xC0, 0x5B]));
    pub const TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256: Self = Self(u16::from_be_bytes([0xC0, 0x5C]));
    pub const TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384: Self = Self(u16::from_be_bytes([0xC0, 0x5D]));
    pub const TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256: Self = Self(u16::from_be_bytes([0xC0, 0x5E]));
    pub const TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384: Self = Self(u16::from_be_bytes([0xC0, 0x5F]));
    pub const TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256: Self = Self(u16::from_be_bytes([0xC0, 0x60]));
    pub const TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384: Self = Self(u16::from_be_bytes([0xC0, 0x61]));
    pub const TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256: Self = Self(u16::from_be_bytes([0xC0, 0x62]));
    pub const TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384: Self = Self(u16::from_be_bytes([0xC0, 0x63]));
    pub const TLS_PSK_WITH_ARIA_128_CBC_SHA256: Self = Self(u16::from_be_bytes([0xC0, 0x64]));
    pub const TLS_PSK_WITH_ARIA_256_CBC_SHA384: Self = Self(u16::from_be_bytes([0xC0, 0x65]));
    pub const TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256: Self = Self(u16::from_be_bytes([0xC0, 0x66]));
    pub const TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384: Self = Self(u16::from_be_bytes([0xC0, 0x67]));
    pub const TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256: Self = Self(u16::from_be_bytes([0xC0, 0x68]));
    pub const TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384: Self = Self(u16::from_be_bytes([0xC0, 0x69]));
    pub const TLS_PSK_WITH_ARIA_128_GCM_SHA256: Self = Self(u16::from_be_bytes([0xC0, 0x6A]));
    pub const TLS_PSK_WITH_ARIA_256_GCM_SHA384: Self = Self(u16::from_be_bytes([0xC0, 0x6B]));
    pub const TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256: Self = Self(u16::from_be_bytes([0xC0, 0x6C]));
    pub const TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384: Self = Self(u16::from_be_bytes([0xC0, 0x6D]));
    pub const TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256: Self = Self(u16::from_be_bytes([0xC0, 0x6E]));
    pub const TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384: Self = Self(u16::from_be_bytes([0xC0, 0x6F]));
    pub const TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256: Self = Self(u16::from_be_bytes([0xC0, 0x70]));
    pub const TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384: Self = Self(u16::from_be_bytes([0xC0, 0x71]));
    pub const TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256: Self = Self(u16::from_be_bytes([0xC0, 0x72]));
    pub const TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384: Self = Self(u16::from_be_bytes([0xC0, 0x73]));
    pub const TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256: Self = Self(u16::from_be_bytes([0xC0, 0x74]));
    pub const TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384: Self = Self(u16::from_be_bytes([0xC0, 0x75]));
    pub const TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256: Self = Self(u16::from_be_bytes([0xC0, 0x76]));
    pub const TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384: Self = Self(u16::from_be_bytes([0xC0, 0x77]));
    pub const TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256: Self = Self(u16::from_be_bytes([0xC0, 0x78]));
    pub const TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384: Self = Self(u16::from_be_bytes([0xC0, 0x79]));
    pub const TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256: Self = Self(u16::from_be_bytes([0xC0, 0x7A]));
    pub const TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384: Self = Self(u16::from_be_bytes([0xC0, 0x7B]));
    pub const TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256: Self = Self(u16::from_be_bytes([0xC0, 0x7C]));
    pub const TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384: Self = Self(u16::from_be_bytes([0xC0, 0x7D]));
    pub const TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256: Self = Self(u16::from_be_bytes([0xC0, 0x7E]));
    pub const TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384: Self = Self(u16::from_be_bytes([0xC0, 0x7F]));
    pub const TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256: Self = Self(u16::from_be_bytes([0xC0, 0x80]));
    pub const TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384: Self = Self(u16::from_be_bytes([0xC0, 0x81]));
    pub const TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256: Self = Self(u16::from_be_bytes([0xC0, 0x82]));
    pub const TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384: Self = Self(u16::from_be_bytes([0xC0, 0x83]));
    pub const TLS_DH_ANON_WITH_CAMELLIA_128_GCM_SHA256: Self = Self(u16::from_be_bytes([0xC0, 0x84]));
    pub const TLS_DH_ANON_WITH_CAMELLIA_256_GCM_SHA384: Self = Self(u16::from_be_bytes([0xC0, 0x85]));
    pub const TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256: Self = Self(u16::from_be_bytes([0xC0, 0x86]));
    pub const TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384: Self = Self(u16::from_be_bytes([0xC0, 0x87]));
    pub const TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256: Self = Self(u16::from_be_bytes([0xC0, 0x88]));
    pub const TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384: Self = Self(u16::from_be_bytes([0xC0, 0x89]));
    pub const TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256: Self = Self(u16::from_be_bytes([0xC0, 0x8A]));
    pub const TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384: Self = Self(u16::from_be_bytes([0xC0, 0x8B]));
    pub const TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256: Self = Self(u16::from_be_bytes([0xC0, 0x8C]));
    pub const TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384: Self = Self(u16::from_be_bytes([0xC0, 0x8D]));
    pub const TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256: Self = Self(u16::from_be_bytes([0xC0, 0x8E]));
    pub const TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384: Self = Self(u16::from_be_bytes([0xC0, 0x8F]));
    pub const TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256: Self = Self(u16::from_be_bytes([0xC0, 0x90]));
    pub const TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384: Self = Self(u16::from_be_bytes([0xC0, 0x91]));
    pub const TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256: Self = Self(u16::from_be_bytes([0xC0, 0x92]));
    pub const TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384: Self = Self(u16::from_be_bytes([0xC0, 0x93]));
    pub const TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256: Self = Self(u16::from_be_bytes([0xC0, 0x94]));
    pub const TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384: Self = Self(u16::from_be_bytes([0xC0, 0x95]));
    pub const TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256: Self = Self(u16::from_be_bytes([0xC0, 0x96]));
    pub const TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384: Self = Self(u16::from_be_bytes([0xC0, 0x97]));
    pub const TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256: Self = Self(u16::from_be_bytes([0xC0, 0x98]));
    pub const TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384: Self = Self(u16::from_be_bytes([0xC0, 0x99]));
    pub const TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256: Self = Self(u16::from_be_bytes([0xC0, 0x9A]));
    pub const TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384: Self = Self(u16::from_be_bytes([0xC0, 0x9B]));
    pub const TLS_RSA_WITH_AES_128_CCM: Self = Self(u16::from_be_bytes([0xC0, 0x9C]));
    pub const TLS_RSA_WITH_AES_256_CCM: Self = Self(u16::from_be_bytes([0xC0, 0x9D]));
    pub const TLS_DHE_RSA_WITH_AES_128_CCM: Self = Self(u16::from_be_bytes([0xC0, 0x9E]));
    pub const TLS_DHE_RSA_WITH_AES_256_CCM: Self = Self(u16::from_be_bytes([0xC0, 0x9F]));
    pub const TLS_RSA_WITH_AES_128_CCM_8: Self = Self(u16::from_be_bytes([0xC0, 0xA0]));
    pub const TLS_RSA_WITH_AES_256_CCM_8: Self = Self(u16::from_be_bytes([0xC0, 0xA1]));
    pub const TLS_DHE_RSA_WITH_AES_128_CCM_8: Self = Self(u16::from_be_bytes([0xC0, 0xA2]));
    pub const TLS_DHE_RSA_WITH_AES_256_CCM_8: Self = Self(u16::from_be_bytes([0xC0, 0xA3]));
    pub const TLS_PSK_WITH_AES_128_CCM: Self = Self(u16::from_be_bytes([0xC0, 0xA4]));
    pub const TLS_PSK_WITH_AES_256_CCM: Self = Self(u16::from_be_bytes([0xC0, 0xA5]));
    pub const TLS_DHE_PSK_WITH_AES_128_CCM: Self = Self(u16::from_be_bytes([0xC0, 0xA6]));
    pub const TLS_DHE_PSK_WITH_AES_256_CCM: Self = Self(u16::from_be_bytes([0xC0, 0xA7]));
    pub const TLS_PSK_WITH_AES_128_CCM_8: Self = Self(u16::from_be_bytes([0xC0, 0xA8]));
    pub const TLS_PSK_WITH_AES_256_CCM_8: Self = Self(u16::from_be_bytes([0xC0, 0xA9]));
    pub const TLS_PSK_DHE_WITH_AES_128_CCM_8: Self = Self(u16::from_be_bytes([0xC0, 0xAA]));
    pub const TLS_PSK_DHE_WITH_AES_256_CCM_8: Self = Self(u16::from_be_bytes([0xC0, 0xAB]));
    pub const TLS_ECDHE_ECDSA_WITH_AES_128_CCM: Self = Self(u16::from_be_bytes([0xC0, 0xAC]));
    pub const TLS_ECDHE_ECDSA_WITH_AES_256_CCM: Self = Self(u16::from_be_bytes([0xC0, 0xAD]));
    pub const TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8: Self = Self(u16::from_be_bytes([0xC0, 0xAE]));
    pub const TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8: Self = Self(u16::from_be_bytes([0xC0, 0xAF]));
    pub const TLS_ECCPWD_WITH_AES_128_GCM_SHA256: Self = Self(u16::from_be_bytes([0xC0, 0xB0]));
    pub const TLS_ECCPWD_WITH_AES_256_GCM_SHA384: Self = Self(u16::from_be_bytes([0xC0, 0xB1]));
    pub const TLS_ECCPWD_WITH_AES_128_CCM_SHA256: Self = Self(u16::from_be_bytes([0xC0, 0xB2]));
    pub const TLS_ECCPWD_WITH_AES_256_CCM_SHA384: Self = Self(u16::from_be_bytes([0xC0, 0xB3]));
    pub const TLS_SHA256_SHA256: Self = Self(u16::from_be_bytes([0xC0, 0xB4]));
    pub const TLS_SHA384_SHA384: Self = Self(u16::from_be_bytes([0xC0, 0xB5]));

    pub const TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC: Self = Self(u16::from_be_bytes([0xC1, 0x00]));
    pub const TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC: Self      = Self(u16::from_be_bytes([0xC1, 0x01]));
    pub const TLS_GOSTR341112_256_WITH_28147_CNT_IMIT: Self      = Self(u16::from_be_bytes([0xC1, 0x02]));
    pub const TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L: Self    = Self(u16::from_be_bytes([0xC1, 0x03]));
    pub const TLS_GOSTR341112_256_WITH_MAGMA_MGM_L: Self         = Self(u16::from_be_bytes([0xC1, 0x04]));
    pub const TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S: Self    = Self(u16::from_be_bytes([0xC1, 0x05]));
    pub const TLS_GOSTR341112_256_WITH_MAGMA_MGM_S: Self         = Self(u16::from_be_bytes([0xC1, 0x06]));

    // ChaCha20-Poly1305 Cipher Suites for Transport Layer Security (TLS)
    // 
    // 2.  ChaCha20 Cipher Suites
    // https://tools.ietf.org/html/rfc7905#section-2
    pub const TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: Self   = Self(u16::from_be_bytes([0xCC, 0xA8]));
    pub const TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: Self = Self(u16::from_be_bytes([0xCC, 0xA9]));
    pub const TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256: Self     = Self(u16::from_be_bytes([0xCC, 0xAA]));
    pub const TLS_PSK_WITH_CHACHA20_POLY1305_SHA256: Self         = Self(u16::from_be_bytes([0xCC, 0xAB]));
    pub const TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256: Self   = Self(u16::from_be_bytes([0xCC, 0xAC]));
    pub const TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256: Self     = Self(u16::from_be_bytes([0xCC, 0xAD]));
    pub const TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256: Self     = Self(u16::from_be_bytes([0xCC, 0xAE]));

    pub const TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256: Self   = Self(u16::from_be_bytes([0xD0, 0x01]));
    pub const TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384: Self   = Self(u16::from_be_bytes([0xD0, 0x02]));
    pub const TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256: Self = Self(u16::from_be_bytes([0xD0, 0x03]));
    pub const TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256: Self   = Self(u16::from_be_bytes([0xD0, 0x05]));
}

impl std::fmt::Display for CipherSuite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::TLS_NULL_WITH_NULL_NULL => write!(f, "TLS_NULL_WITH_NULL_NULL"),
            Self::TLS_RSA_WITH_NULL_MD5 => write!(f, "TLS_RSA_WITH_NULL_MD5"),
            Self::TLS_RSA_WITH_NULL_SHA => write!(f, "TLS_RSA_WITH_NULL_SHA"),
            Self::TLS_RSA_EXPORT_WITH_RC4_40_MD5 => write!(f, "TLS_RSA_EXPORT_WITH_RC4_40_MD5"),
            Self::TLS_RSA_WITH_RC4_128_MD5 => write!(f, "TLS_RSA_WITH_RC4_128_MD5"),
            Self::TLS_RSA_WITH_RC4_128_SHA => write!(f, "TLS_RSA_WITH_RC4_128_SHA"),
            Self::TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5 => write!(f, "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5"),
            Self::TLS_RSA_WITH_IDEA_CBC_SHA => write!(f, "TLS_RSA_WITH_IDEA_CBC_SHA"),
            Self::TLS_RSA_EXPORT_WITH_DES40_CBC_SHA => write!(f, "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA"),
            Self::TLS_RSA_WITH_DES_CBC_SHA => write!(f, "TLS_RSA_WITH_DES_CBC_SHA"),
            Self::TLS_RSA_WITH_3DES_EDE_CBC_SHA => write!(f, "TLS_RSA_WITH_3DES_EDE_CBC_SHA"),
            Self::TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA => write!(f, "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA"),
            Self::TLS_DH_DSS_WITH_DES_CBC_SHA => write!(f, "TLS_DH_DSS_WITH_DES_CBC_SHA"),
            Self::TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA => write!(f, "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA"),
            Self::TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA => write!(f, "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA"),
            Self::TLS_DH_RSA_WITH_DES_CBC_SHA => write!(f, "TLS_DH_RSA_WITH_DES_CBC_SHA"),
            Self::TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA => write!(f, "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA"),
            Self::TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA => write!(f, "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA"),
            Self::TLS_DHE_DSS_WITH_DES_CBC_SHA => write!(f, "TLS_DHE_DSS_WITH_DES_CBC_SHA"),
            Self::TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA => write!(f, "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA"),
            Self::TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA => write!(f, "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA"),
            Self::TLS_DHE_RSA_WITH_DES_CBC_SHA => write!(f, "TLS_DHE_RSA_WITH_DES_CBC_SHA"),
            Self::TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA => write!(f, "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA"),
            Self::TLS_DH_ANON_EXPORT_WITH_RC4_40_MD5 => write!(f, "TLS_DH_ANON_EXPORT_WITH_RC4_40_MD5"),
            Self::TLS_DH_ANON_WITH_RC4_128_MD5 => write!(f, "TLS_DH_ANON_WITH_RC4_128_MD5"),
            Self::TLS_DH_ANON_EXPORT_WITH_DES40_CBC_SHA => write!(f, "TLS_DH_ANON_EXPORT_WITH_DES40_CBC_SHA"),
            Self::TLS_DH_ANON_WITH_DES_CBC_SHA => write!(f, "TLS_DH_ANON_WITH_DES_CBC_SHA"),
            Self::TLS_DH_ANON_WITH_3DES_EDE_CBC_SHA => write!(f, "TLS_DH_ANON_WITH_3DES_EDE_CBC_SHA"),
            Self::TLS_KRB5_WITH_DES_CBC_SHA => write!(f, "TLS_KRB5_WITH_DES_CBC_SHA"),
            Self::TLS_KRB5_WITH_3DES_EDE_CBC_SHA => write!(f, "TLS_KRB5_WITH_3DES_EDE_CBC_SHA"),
            Self::TLS_KRB5_WITH_RC4_128_SHA => write!(f, "TLS_KRB5_WITH_RC4_128_SHA"),
            Self::TLS_KRB5_WITH_IDEA_CBC_SHA => write!(f, "TLS_KRB5_WITH_IDEA_CBC_SHA"),
            Self::TLS_KRB5_WITH_DES_CBC_MD5 => write!(f, "TLS_KRB5_WITH_DES_CBC_MD5"),
            Self::TLS_KRB5_WITH_3DES_EDE_CBC_MD5 => write!(f, "TLS_KRB5_WITH_3DES_EDE_CBC_MD5"),
            Self::TLS_KRB5_WITH_RC4_128_MD5 => write!(f, "TLS_KRB5_WITH_RC4_128_MD5"),
            Self::TLS_KRB5_WITH_IDEA_CBC_MD5 => write!(f, "TLS_KRB5_WITH_IDEA_CBC_MD5"),
            Self::TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA => write!(f, "TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA"),
            Self::TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA => write!(f, "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA"),
            Self::TLS_KRB5_EXPORT_WITH_RC4_40_SHA => write!(f, "TLS_KRB5_EXPORT_WITH_RC4_40_SHA"),
            Self::TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5 => write!(f, "TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5"),
            Self::TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5 => write!(f, "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5"),
            Self::TLS_KRB5_EXPORT_WITH_RC4_40_MD5 => write!(f, "TLS_KRB5_EXPORT_WITH_RC4_40_MD5"),
            Self::TLS_PSK_WITH_NULL_SHA => write!(f, "TLS_PSK_WITH_NULL_SHA"),
            Self::TLS_DHE_PSK_WITH_NULL_SHA => write!(f, "TLS_DHE_PSK_WITH_NULL_SHA"),
            Self::TLS_RSA_PSK_WITH_NULL_SHA => write!(f, "TLS_RSA_PSK_WITH_NULL_SHA"),
            Self::TLS_RSA_WITH_AES_128_CBC_SHA => write!(f, "TLS_RSA_WITH_AES_128_CBC_SHA"),
            Self::TLS_DH_DSS_WITH_AES_128_CBC_SHA => write!(f, "TLS_DH_DSS_WITH_AES_128_CBC_SHA"),
            Self::TLS_DH_RSA_WITH_AES_128_CBC_SHA => write!(f, "TLS_DH_RSA_WITH_AES_128_CBC_SHA"),
            Self::TLS_DHE_DSS_WITH_AES_128_CBC_SHA => write!(f, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA"),
            Self::TLS_DHE_RSA_WITH_AES_128_CBC_SHA => write!(f, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA"),
            Self::TLS_DH_ANON_WITH_AES_128_CBC_SHA => write!(f, "TLS_DH_ANON_WITH_AES_128_CBC_SHA"),
            Self::TLS_RSA_WITH_AES_256_CBC_SHA => write!(f, "TLS_RSA_WITH_AES_256_CBC_SHA"),
            Self::TLS_DH_DSS_WITH_AES_256_CBC_SHA => write!(f, "TLS_DH_DSS_WITH_AES_256_CBC_SHA"),
            Self::TLS_DH_RSA_WITH_AES_256_CBC_SHA => write!(f, "TLS_DH_RSA_WITH_AES_256_CBC_SHA"),
            Self::TLS_DHE_DSS_WITH_AES_256_CBC_SHA => write!(f, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA"),
            Self::TLS_DHE_RSA_WITH_AES_256_CBC_SHA => write!(f, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA"),
            Self::TLS_DH_ANON_WITH_AES_256_CBC_SHA => write!(f, "TLS_DH_ANON_WITH_AES_256_CBC_SHA"),
            Self::TLS_RSA_WITH_NULL_SHA256 => write!(f, "TLS_RSA_WITH_NULL_SHA256"),
            Self::TLS_RSA_WITH_AES_128_CBC_SHA256 => write!(f, "TLS_RSA_WITH_AES_128_CBC_SHA256"),
            Self::TLS_RSA_WITH_AES_256_CBC_SHA256 => write!(f, "TLS_RSA_WITH_AES_256_CBC_SHA256"),
            Self::TLS_DH_DSS_WITH_AES_128_CBC_SHA256 => write!(f, "TLS_DH_DSS_WITH_AES_128_CBC_SHA256"),
            Self::TLS_DH_RSA_WITH_AES_128_CBC_SHA256 => write!(f, "TLS_DH_RSA_WITH_AES_128_CBC_SHA256"),
            Self::TLS_DHE_DSS_WITH_AES_128_CBC_SHA256 => write!(f, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256"),
            Self::TLS_RSA_WITH_CAMELLIA_128_CBC_SHA => write!(f, "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA"),
            Self::TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA => write!(f, "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA"),
            Self::TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA => write!(f, "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA"),
            Self::TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA => write!(f, "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA"),
            Self::TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA => write!(f, "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA"),
            Self::TLS_DH_ANON_WITH_CAMELLIA_128_CBC_SHA => write!(f, "TLS_DH_ANON_WITH_CAMELLIA_128_CBC_SHA"),
            Self::TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 => write!(f, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256"),
            Self::TLS_DH_DSS_WITH_AES_256_CBC_SHA256 => write!(f, "TLS_DH_DSS_WITH_AES_256_CBC_SHA256"),
            Self::TLS_DH_RSA_WITH_AES_256_CBC_SHA256 => write!(f, "TLS_DH_RSA_WITH_AES_256_CBC_SHA256"),
            Self::TLS_DHE_DSS_WITH_AES_256_CBC_SHA256 => write!(f, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256"),
            Self::TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 => write!(f, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"),
            Self::TLS_DH_ANON_WITH_AES_128_CBC_SHA256 => write!(f, "TLS_DH_ANON_WITH_AES_128_CBC_SHA256"),
            Self::TLS_DH_ANON_WITH_AES_256_CBC_SHA256 => write!(f, "TLS_DH_ANON_WITH_AES_256_CBC_SHA256"),
            Self::TLS_RSA_WITH_CAMELLIA_256_CBC_SHA => write!(f, "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA"),
            Self::TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA => write!(f, "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA"),
            Self::TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA => write!(f, "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA"),
            Self::TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA => write!(f, "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA"),
            Self::TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA => write!(f, "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA"),
            Self::TLS_DH_ANON_WITH_CAMELLIA_256_CBC_SHA => write!(f, "TLS_DH_ANON_WITH_CAMELLIA_256_CBC_SHA"),
            Self::TLS_PSK_WITH_RC4_128_SHA => write!(f, "TLS_PSK_WITH_RC4_128_SHA"),
            Self::TLS_PSK_WITH_3DES_EDE_CBC_SHA => write!(f, "TLS_PSK_WITH_3DES_EDE_CBC_SHA"),
            Self::TLS_PSK_WITH_AES_128_CBC_SHA => write!(f, "TLS_PSK_WITH_AES_128_CBC_SHA"),
            Self::TLS_PSK_WITH_AES_256_CBC_SHA => write!(f, "TLS_PSK_WITH_AES_256_CBC_SHA"),
            Self::TLS_DHE_PSK_WITH_RC4_128_SHA => write!(f, "TLS_DHE_PSK_WITH_RC4_128_SHA"),
            Self::TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA => write!(f, "TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA"),
            Self::TLS_DHE_PSK_WITH_AES_128_CBC_SHA => write!(f, "TLS_DHE_PSK_WITH_AES_128_CBC_SHA"),
            Self::TLS_DHE_PSK_WITH_AES_256_CBC_SHA => write!(f, "TLS_DHE_PSK_WITH_AES_256_CBC_SHA"),
            Self::TLS_RSA_PSK_WITH_RC4_128_SHA => write!(f, "TLS_RSA_PSK_WITH_RC4_128_SHA"),
            Self::TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA => write!(f, "TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA"),
            Self::TLS_RSA_PSK_WITH_AES_128_CBC_SHA => write!(f, "TLS_RSA_PSK_WITH_AES_128_CBC_SHA"),
            Self::TLS_RSA_PSK_WITH_AES_256_CBC_SHA => write!(f, "TLS_RSA_PSK_WITH_AES_256_CBC_SHA"),
            Self::TLS_RSA_WITH_SEED_CBC_SHA => write!(f, "TLS_RSA_WITH_SEED_CBC_SHA"),
            Self::TLS_DH_DSS_WITH_SEED_CBC_SHA => write!(f, "TLS_DH_DSS_WITH_SEED_CBC_SHA"),
            Self::TLS_DH_RSA_WITH_SEED_CBC_SHA => write!(f, "TLS_DH_RSA_WITH_SEED_CBC_SHA"),
            Self::TLS_DHE_DSS_WITH_SEED_CBC_SHA => write!(f, "TLS_DHE_DSS_WITH_SEED_CBC_SHA"),
            Self::TLS_DHE_RSA_WITH_SEED_CBC_SHA => write!(f, "TLS_DHE_RSA_WITH_SEED_CBC_SHA"),
            Self::TLS_DH_ANON_WITH_SEED_CBC_SHA => write!(f, "TLS_DH_ANON_WITH_SEED_CBC_SHA"),
            Self::TLS_RSA_WITH_AES_128_GCM_SHA256 => write!(f, "TLS_RSA_WITH_AES_128_GCM_SHA256"),
            Self::TLS_RSA_WITH_AES_256_GCM_SHA384 => write!(f, "TLS_RSA_WITH_AES_256_GCM_SHA384"),
            Self::TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 => write!(f, "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"),
            Self::TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 => write!(f, "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"),
            Self::TLS_DH_RSA_WITH_AES_128_GCM_SHA256 => write!(f, "TLS_DH_RSA_WITH_AES_128_GCM_SHA256"),
            Self::TLS_DH_RSA_WITH_AES_256_GCM_SHA384 => write!(f, "TLS_DH_RSA_WITH_AES_256_GCM_SHA384"),
            Self::TLS_DHE_DSS_WITH_AES_128_GCM_SHA256 => write!(f, "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256"),
            Self::TLS_DHE_DSS_WITH_AES_256_GCM_SHA384 => write!(f, "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384"),
            Self::TLS_DH_DSS_WITH_AES_128_GCM_SHA256 => write!(f, "TLS_DH_DSS_WITH_AES_128_GCM_SHA256"),
            Self::TLS_DH_DSS_WITH_AES_256_GCM_SHA384 => write!(f, "TLS_DH_DSS_WITH_AES_256_GCM_SHA384"),
            Self::TLS_DH_ANON_WITH_AES_128_GCM_SHA256 => write!(f, "TLS_DH_ANON_WITH_AES_128_GCM_SHA256"),
            Self::TLS_DH_ANON_WITH_AES_256_GCM_SHA384 => write!(f, "TLS_DH_ANON_WITH_AES_256_GCM_SHA384"),
            Self::TLS_PSK_WITH_AES_128_GCM_SHA256 => write!(f, "TLS_PSK_WITH_AES_128_GCM_SHA256"),
            Self::TLS_PSK_WITH_AES_256_GCM_SHA384 => write!(f, "TLS_PSK_WITH_AES_256_GCM_SHA384"),
            Self::TLS_DHE_PSK_WITH_AES_128_GCM_SHA256 => write!(f, "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256"),
            Self::TLS_DHE_PSK_WITH_AES_256_GCM_SHA384 => write!(f, "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384"),
            Self::TLS_RSA_PSK_WITH_AES_128_GCM_SHA256 => write!(f, "TLS_RSA_PSK_WITH_AES_128_GCM_SHA256"),
            Self::TLS_RSA_PSK_WITH_AES_256_GCM_SHA384 => write!(f, "TLS_RSA_PSK_WITH_AES_256_GCM_SHA384"),
            Self::TLS_PSK_WITH_AES_128_CBC_SHA256 => write!(f, "TLS_PSK_WITH_AES_128_CBC_SHA256"),
            Self::TLS_PSK_WITH_AES_256_CBC_SHA384 => write!(f, "TLS_PSK_WITH_AES_256_CBC_SHA384"),
            Self::TLS_PSK_WITH_NULL_SHA256 => write!(f, "TLS_PSK_WITH_NULL_SHA256"),
            Self::TLS_PSK_WITH_NULL_SHA384 => write!(f, "TLS_PSK_WITH_NULL_SHA384"),
            Self::TLS_DHE_PSK_WITH_AES_128_CBC_SHA256 => write!(f, "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256"),
            Self::TLS_DHE_PSK_WITH_AES_256_CBC_SHA384 => write!(f, "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384"),
            Self::TLS_DHE_PSK_WITH_NULL_SHA256 => write!(f, "TLS_DHE_PSK_WITH_NULL_SHA256"),
            Self::TLS_DHE_PSK_WITH_NULL_SHA384 => write!(f, "TLS_DHE_PSK_WITH_NULL_SHA384"),
            Self::TLS_RSA_PSK_WITH_AES_128_CBC_SHA256 => write!(f, "TLS_RSA_PSK_WITH_AES_128_CBC_SHA256"),
            Self::TLS_RSA_PSK_WITH_AES_256_CBC_SHA384 => write!(f, "TLS_RSA_PSK_WITH_AES_256_CBC_SHA384"),
            Self::TLS_RSA_PSK_WITH_NULL_SHA256 => write!(f, "TLS_RSA_PSK_WITH_NULL_SHA256"),
            Self::TLS_RSA_PSK_WITH_NULL_SHA384 => write!(f, "TLS_RSA_PSK_WITH_NULL_SHA384"),
            Self::TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256 => write!(f, "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256"),
            Self::TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256 => write!(f, "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256"),
            Self::TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256 => write!(f, "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256"),
            Self::TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256 => write!(f, "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256"),
            Self::TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 => write!(f, "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256"),
            Self::TLS_DH_ANON_WITH_CAMELLIA_128_CBC_SHA256 => write!(f, "TLS_DH_ANON_WITH_CAMELLIA_128_CBC_SHA256"),
            Self::TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256 => write!(f, "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256"),
            Self::TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256 => write!(f, "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256"),
            Self::TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256 => write!(f, "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256"),
            Self::TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256 => write!(f, "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256"),
            Self::TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256 => write!(f, "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256"),
            Self::TLS_DH_ANON_WITH_CAMELLIA_256_CBC_SHA256 => write!(f, "TLS_DH_ANON_WITH_CAMELLIA_256_CBC_SHA256"),
            Self::TLS_SM4_GCM_SM3 => write!(f, "TLS_SM4_GCM_SM3"),
            Self::TLS_SM4_CCM_SM3 => write!(f, "TLS_SM4_CCM_SM3"),
            Self::TLS_EMPTY_RENEGOTIATION_INFO_SCSV => write!(f, "TLS_EMPTY_RENEGOTIATION_INFO_SCSV"),
            Self::TLS_AES_128_GCM_SHA256 => write!(f, "TLS_AES_128_GCM_SHA256"),
            Self::TLS_AES_256_GCM_SHA384 => write!(f, "TLS_AES_256_GCM_SHA384"),
            Self::TLS_CHACHA20_POLY1305_SHA256 => write!(f, "TLS_CHACHA20_POLY1305_SHA256"),
            Self::TLS_AES_128_CCM_SHA256 => write!(f, "TLS_AES_128_CCM_SHA256"),
            Self::TLS_AES_128_CCM_8_SHA256 => write!(f, "TLS_AES_128_CCM_8_SHA256"),
            Self::TLS_FALLBACK_SCSV => write!(f, "TLS_FALLBACK_SCSV"),
            Self::TLS_ECDH_ECDSA_WITH_NULL_SHA => write!(f, "TLS_ECDH_ECDSA_WITH_NULL_SHA"),
            Self::TLS_ECDH_ECDSA_WITH_RC4_128_SHA => write!(f, "TLS_ECDH_ECDSA_WITH_RC4_128_SHA"),
            Self::TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA => write!(f, "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA"),
            Self::TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA => write!(f, "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA"),
            Self::TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA => write!(f, "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA"),
            Self::TLS_ECDHE_ECDSA_WITH_NULL_SHA => write!(f, "TLS_ECDHE_ECDSA_WITH_NULL_SHA"),
            Self::TLS_ECDHE_ECDSA_WITH_RC4_128_SHA => write!(f, "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA"),
            Self::TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA => write!(f, "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA"),
            Self::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA => write!(f, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"),
            Self::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA => write!(f, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"),
            Self::TLS_ECDH_RSA_WITH_NULL_SHA => write!(f, "TLS_ECDH_RSA_WITH_NULL_SHA"),
            Self::TLS_ECDH_RSA_WITH_RC4_128_SHA => write!(f, "TLS_ECDH_RSA_WITH_RC4_128_SHA"),
            Self::TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA => write!(f, "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA"),
            Self::TLS_ECDH_RSA_WITH_AES_128_CBC_SHA => write!(f, "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA"),
            Self::TLS_ECDH_RSA_WITH_AES_256_CBC_SHA => write!(f, "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA"),
            Self::TLS_ECDHE_RSA_WITH_NULL_SHA => write!(f, "TLS_ECDHE_RSA_WITH_NULL_SHA"),
            Self::TLS_ECDHE_RSA_WITH_RC4_128_SHA => write!(f, "TLS_ECDHE_RSA_WITH_RC4_128_SHA"),
            Self::TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA => write!(f, "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"),
            Self::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA => write!(f, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"),
            Self::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA => write!(f, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"),
            Self::TLS_ECDH_ANON_WITH_NULL_SHA => write!(f, "TLS_ECDH_ANON_WITH_NULL_SHA"),
            Self::TLS_ECDH_ANON_WITH_RC4_128_SHA => write!(f, "TLS_ECDH_ANON_WITH_RC4_128_SHA"),
            Self::TLS_ECDH_ANON_WITH_3DES_EDE_CBC_SHA => write!(f, "TLS_ECDH_ANON_WITH_3DES_EDE_CBC_SHA"),
            Self::TLS_ECDH_ANON_WITH_AES_128_CBC_SHA => write!(f, "TLS_ECDH_ANON_WITH_AES_128_CBC_SHA"),
            Self::TLS_ECDH_ANON_WITH_AES_256_CBC_SHA => write!(f, "TLS_ECDH_ANON_WITH_AES_256_CBC_SHA"),
            Self::TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA => write!(f, "TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA"),
            Self::TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA => write!(f, "TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA"),
            Self::TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA => write!(f, "TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA"),
            Self::TLS_SRP_SHA_WITH_AES_128_CBC_SHA => write!(f, "TLS_SRP_SHA_WITH_AES_128_CBC_SHA"),
            Self::TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA => write!(f, "TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA"),
            Self::TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA => write!(f, "TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA"),
            Self::TLS_SRP_SHA_WITH_AES_256_CBC_SHA => write!(f, "TLS_SRP_SHA_WITH_AES_256_CBC_SHA"),
            Self::TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA => write!(f, "TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA"),
            Self::TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA => write!(f, "TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA"),
            Self::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 => write!(f, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"),
            Self::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 => write!(f, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"),
            Self::TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256 => write!(f, "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256"),
            Self::TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384 => write!(f, "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384"),
            Self::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 => write!(f, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"),
            Self::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 => write!(f, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"),
            Self::TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 => write!(f, "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256"),
            Self::TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384 => write!(f, "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384"),
            Self::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 => write!(f, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"),
            Self::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 => write!(f, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"),
            Self::TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 => write!(f, "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256"),
            Self::TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 => write!(f, "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384"),
            Self::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 => write!(f, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"),
            Self::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 => write!(f, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"),
            Self::TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 => write!(f, "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256"),
            Self::TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384 => write!(f, "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384"),
            Self::TLS_ECDHE_PSK_WITH_RC4_128_SHA => write!(f, "TLS_ECDHE_PSK_WITH_RC4_128_SHA"),
            Self::TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA => write!(f, "TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA"),
            Self::TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA => write!(f, "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA"),
            Self::TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA => write!(f, "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA"),
            Self::TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256 => write!(f, "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256"),
            Self::TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384 => write!(f, "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384"),
            Self::TLS_ECDHE_PSK_WITH_NULL_SHA => write!(f, "TLS_ECDHE_PSK_WITH_NULL_SHA"),
            Self::TLS_ECDHE_PSK_WITH_NULL_SHA256 => write!(f, "TLS_ECDHE_PSK_WITH_NULL_SHA256"),
            Self::TLS_ECDHE_PSK_WITH_NULL_SHA384 => write!(f, "TLS_ECDHE_PSK_WITH_NULL_SHA384"),
            Self::TLS_RSA_WITH_ARIA_128_CBC_SHA256 => write!(f, "TLS_RSA_WITH_ARIA_128_CBC_SHA256"),
            Self::TLS_RSA_WITH_ARIA_256_CBC_SHA384 => write!(f, "TLS_RSA_WITH_ARIA_256_CBC_SHA384"),
            Self::TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256 => write!(f, "TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256"),
            Self::TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384 => write!(f, "TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384"),
            Self::TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256 => write!(f, "TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256"),
            Self::TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384 => write!(f, "TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384"),
            Self::TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256 => write!(f, "TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256"),
            Self::TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384 => write!(f, "TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384"),
            Self::TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256 => write!(f, "TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256"),
            Self::TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384 => write!(f, "TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384"),
            Self::TLS_DH_ANON_WITH_ARIA_128_CBC_SHA256 => write!(f, "TLS_DH_ANON_WITH_ARIA_128_CBC_SHA256"),
            Self::TLS_DH_ANON_WITH_ARIA_256_CBC_SHA384 => write!(f, "TLS_DH_ANON_WITH_ARIA_256_CBC_SHA384"),
            Self::TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256 => write!(f, "TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256"),
            Self::TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384 => write!(f, "TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384"),
            Self::TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256 => write!(f, "TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256"),
            Self::TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384 => write!(f, "TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384"),
            Self::TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256 => write!(f, "TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256"),
            Self::TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384 => write!(f, "TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384"),
            Self::TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256 => write!(f, "TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256"),
            Self::TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384 => write!(f, "TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384"),
            Self::TLS_RSA_WITH_ARIA_128_GCM_SHA256 => write!(f, "TLS_RSA_WITH_ARIA_128_GCM_SHA256"),
            Self::TLS_RSA_WITH_ARIA_256_GCM_SHA384 => write!(f, "TLS_RSA_WITH_ARIA_256_GCM_SHA384"),
            Self::TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256 => write!(f, "TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256"),
            Self::TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384 => write!(f, "TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384"),
            Self::TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256 => write!(f, "TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256"),
            Self::TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384 => write!(f, "TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384"),
            Self::TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256 => write!(f, "TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256"),
            Self::TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384 => write!(f, "TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384"),
            Self::TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256 => write!(f, "TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256"),
            Self::TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384 => write!(f, "TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384"),
            Self::TLS_DH_ANON_WITH_ARIA_128_GCM_SHA256 => write!(f, "TLS_DH_ANON_WITH_ARIA_128_GCM_SHA256"),
            Self::TLS_DH_ANON_WITH_ARIA_256_GCM_SHA384 => write!(f, "TLS_DH_ANON_WITH_ARIA_256_GCM_SHA384"),
            Self::TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256 => write!(f, "TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256"),
            Self::TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384 => write!(f, "TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384"),
            Self::TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256 => write!(f, "TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256"),
            Self::TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384 => write!(f, "TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384"),
            Self::TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256 => write!(f, "TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256"),
            Self::TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384 => write!(f, "TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384"),
            Self::TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256 => write!(f, "TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256"),
            Self::TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384 => write!(f, "TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384"),
            Self::TLS_PSK_WITH_ARIA_128_CBC_SHA256 => write!(f, "TLS_PSK_WITH_ARIA_128_CBC_SHA256"),
            Self::TLS_PSK_WITH_ARIA_256_CBC_SHA384 => write!(f, "TLS_PSK_WITH_ARIA_256_CBC_SHA384"),
            Self::TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256 => write!(f, "TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256"),
            Self::TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384 => write!(f, "TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384"),
            Self::TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256 => write!(f, "TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256"),
            Self::TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384 => write!(f, "TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384"),
            Self::TLS_PSK_WITH_ARIA_128_GCM_SHA256 => write!(f, "TLS_PSK_WITH_ARIA_128_GCM_SHA256"),
            Self::TLS_PSK_WITH_ARIA_256_GCM_SHA384 => write!(f, "TLS_PSK_WITH_ARIA_256_GCM_SHA384"),
            Self::TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256 => write!(f, "TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256"),
            Self::TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384 => write!(f, "TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384"),
            Self::TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256 => write!(f, "TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256"),
            Self::TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384 => write!(f, "TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384"),
            Self::TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256 => write!(f, "TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256"),
            Self::TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384 => write!(f, "TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384"),
            Self::TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 => write!(f, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256"),
            Self::TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 => write!(f, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384"),
            Self::TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 => write!(f, "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256"),
            Self::TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 => write!(f, "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384"),
            Self::TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 => write!(f, "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256"),
            Self::TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384 => write!(f, "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384"),
            Self::TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256 => write!(f, "TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256"),
            Self::TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384 => write!(f, "TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384"),
            Self::TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256 => write!(f, "TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256"),
            Self::TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384 => write!(f, "TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384"),
            Self::TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 => write!(f, "TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256"),
            Self::TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 => write!(f, "TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384"),
            Self::TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256 => write!(f, "TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256"),
            Self::TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384 => write!(f, "TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384"),
            Self::TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256 => write!(f, "TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256"),
            Self::TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384 => write!(f, "TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384"),
            Self::TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256 => write!(f, "TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256"),
            Self::TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384 => write!(f, "TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384"),
            Self::TLS_DH_ANON_WITH_CAMELLIA_128_GCM_SHA256 => write!(f, "TLS_DH_ANON_WITH_CAMELLIA_128_GCM_SHA256"),
            Self::TLS_DH_ANON_WITH_CAMELLIA_256_GCM_SHA384 => write!(f, "TLS_DH_ANON_WITH_CAMELLIA_256_GCM_SHA384"),
            Self::TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 => write!(f, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256"),
            Self::TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 => write!(f, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384"),
            Self::TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 => write!(f, "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256"),
            Self::TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 => write!(f, "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384"),
            Self::TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 => write!(f, "TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256"),
            Self::TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 => write!(f, "TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384"),
            Self::TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256 => write!(f, "TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256"),
            Self::TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384 => write!(f, "TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384"),
            Self::TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256 => write!(f, "TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256"),
            Self::TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384 => write!(f, "TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384"),
            Self::TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256 => write!(f, "TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256"),
            Self::TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384 => write!(f, "TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384"),
            Self::TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256 => write!(f, "TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256"),
            Self::TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384 => write!(f, "TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384"),
            Self::TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256 => write!(f, "TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256"),
            Self::TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384 => write!(f, "TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384"),
            Self::TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 => write!(f, "TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256"),
            Self::TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 => write!(f, "TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384"),
            Self::TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256 => write!(f, "TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256"),
            Self::TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384 => write!(f, "TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384"),
            Self::TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 => write!(f, "TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256"),
            Self::TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 => write!(f, "TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384"),
            Self::TLS_RSA_WITH_AES_128_CCM => write!(f, "TLS_RSA_WITH_AES_128_CCM"),
            Self::TLS_RSA_WITH_AES_256_CCM => write!(f, "TLS_RSA_WITH_AES_256_CCM"),
            Self::TLS_DHE_RSA_WITH_AES_128_CCM => write!(f, "TLS_DHE_RSA_WITH_AES_128_CCM"),
            Self::TLS_DHE_RSA_WITH_AES_256_CCM => write!(f, "TLS_DHE_RSA_WITH_AES_256_CCM"),
            Self::TLS_RSA_WITH_AES_128_CCM_8 => write!(f, "TLS_RSA_WITH_AES_128_CCM_8"),
            Self::TLS_RSA_WITH_AES_256_CCM_8 => write!(f, "TLS_RSA_WITH_AES_256_CCM_8"),
            Self::TLS_DHE_RSA_WITH_AES_128_CCM_8 => write!(f, "TLS_DHE_RSA_WITH_AES_128_CCM_8"),
            Self::TLS_DHE_RSA_WITH_AES_256_CCM_8 => write!(f, "TLS_DHE_RSA_WITH_AES_256_CCM_8"),
            Self::TLS_PSK_WITH_AES_128_CCM => write!(f, "TLS_PSK_WITH_AES_128_CCM"),
            Self::TLS_PSK_WITH_AES_256_CCM => write!(f, "TLS_PSK_WITH_AES_256_CCM"),
            Self::TLS_DHE_PSK_WITH_AES_128_CCM => write!(f, "TLS_DHE_PSK_WITH_AES_128_CCM"),
            Self::TLS_DHE_PSK_WITH_AES_256_CCM => write!(f, "TLS_DHE_PSK_WITH_AES_256_CCM"),
            Self::TLS_PSK_WITH_AES_128_CCM_8 => write!(f, "TLS_PSK_WITH_AES_128_CCM_8"),
            Self::TLS_PSK_WITH_AES_256_CCM_8 => write!(f, "TLS_PSK_WITH_AES_256_CCM_8"),
            Self::TLS_PSK_DHE_WITH_AES_128_CCM_8 => write!(f, "TLS_PSK_DHE_WITH_AES_128_CCM_8"),
            Self::TLS_PSK_DHE_WITH_AES_256_CCM_8 => write!(f, "TLS_PSK_DHE_WITH_AES_256_CCM_8"),
            Self::TLS_ECDHE_ECDSA_WITH_AES_128_CCM => write!(f, "TLS_ECDHE_ECDSA_WITH_AES_128_CCM"),
            Self::TLS_ECDHE_ECDSA_WITH_AES_256_CCM => write!(f, "TLS_ECDHE_ECDSA_WITH_AES_256_CCM"),
            Self::TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 => write!(f, "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8"),
            Self::TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8 => write!(f, "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8"),
            Self::TLS_ECCPWD_WITH_AES_128_GCM_SHA256 => write!(f, "TLS_ECCPWD_WITH_AES_128_GCM_SHA256"),
            Self::TLS_ECCPWD_WITH_AES_256_GCM_SHA384 => write!(f, "TLS_ECCPWD_WITH_AES_256_GCM_SHA384"),
            Self::TLS_ECCPWD_WITH_AES_128_CCM_SHA256 => write!(f, "TLS_ECCPWD_WITH_AES_128_CCM_SHA256"),
            Self::TLS_ECCPWD_WITH_AES_256_CCM_SHA384 => write!(f, "TLS_ECCPWD_WITH_AES_256_CCM_SHA384"),
            Self::TLS_SHA256_SHA256 => write!(f, "TLS_SHA256_SHA256"),
            Self::TLS_SHA384_SHA384 => write!(f, "TLS_SHA384_SHA384"),
            Self::TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC => write!(f, "TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC"),
            Self::TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC => write!(f, "TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC"),
            Self::TLS_GOSTR341112_256_WITH_28147_CNT_IMIT => write!(f, "TLS_GOSTR341112_256_WITH_28147_CNT_IMIT"),
            Self::TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L => write!(f, "TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L"),
            Self::TLS_GOSTR341112_256_WITH_MAGMA_MGM_L => write!(f, "TLS_GOSTR341112_256_WITH_MAGMA_MGM_L"),
            Self::TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S => write!(f, "TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S"),
            Self::TLS_GOSTR341112_256_WITH_MAGMA_MGM_S => write!(f, "TLS_GOSTR341112_256_WITH_MAGMA_MGM_S"),
            Self::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => write!(f, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"),
            Self::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 => write!(f, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"),
            Self::TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => write!(f, "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256"),
            Self::TLS_PSK_WITH_CHACHA20_POLY1305_SHA256 => write!(f, "TLS_PSK_WITH_CHACHA20_POLY1305_SHA256"),
            Self::TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256 => write!(f, "TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256"),
            Self::TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256 => write!(f, "TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256"),
            Self::TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256 => write!(f, "TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256"),
            Self::TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256 => write!(f, "TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256"),
            Self::TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384 => write!(f, "TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384"),
            Self::TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256 => write!(f, "TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256"),
            Self::TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256 => write!(f, "TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256"),
            _ => {
                let bytes = self.0.to_be_bytes();
                write!(f, "Unknow({}, {})", bytes[0], bytes[1])
            },
        }
    }
}