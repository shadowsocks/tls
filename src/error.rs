use std::fmt;


#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ErrorKind {
    CloseNotify,
    UnexpectedMessage,
    BadRecordMac,
    // Used in TLS versions prior to 1.3.
    DecryptionFailed,
    RecordOverflow,
    // Used in TLS versions prior to 1.3.
    DecompressionFailure,
    HandshakeFailure,
    // Used in SSLv3 but not in TLS.
    NoCertificate,
    BadCertificate,
    UnsupportedCertificate,
    CertificateRevoked,
    CertificateExpired,
    CertificateUnknown,
    IllegalParameter,
    UnknownCa,
    AccessDenied,
    DecodeError,
    DecryptError,
    // Used in TLS 1.0 but not TLS 1.1 or later.
    ExportRestriction,
    ProtocolVersion,
    InsufficientSecurity,
    // I/O Error
    InternalError,
    InappropriateFallback,
    UserCanceled,
    // Used in TLS versions prior to 1.3.
    NoRenegotiation,
    MissingExtension,
    UnsupportedExtension,
    // Used in TLS versions prior to 1.3.
    CertificateUnobtainable,
    UnrecognizedName,
    BadCertificateStatusResponse,
    // Used in TLS versions prior to 1.3.
    BadCertificateHashValue,
    UnknownPskIdentity,
    CertificateRequired,
    NoApplicationProtocol,
}

impl ErrorKind {
    pub fn as_str(&self) -> &'static str {
        todo!()
    }
}

pub struct Error {
    kind: ErrorKind,
    error: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl Error {
    pub fn new<E: Into<Box<dyn std::error::Error + Send + Sync>>>(kind: ErrorKind, error: E) -> Self {
        Self { kind, error: Some(error.into()) }
    }
    
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debuger = f.debug_struct("Error");
        debuger.field("kind", &self.kind);
        if let Some(ref e) = self.error {
            debuger.field("error", &e);
        }
        debuger.finish()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.error {
            None => write!(f, "{}", self.kind.as_str()),
            Some(ref e) => e.fmt(f),
        }
    }
}

impl From<ErrorKind> for Error {
    #[inline]
    fn from(kind: ErrorKind) -> Error {
        Error { kind, error: None }
    }
}

impl From<std::io::Error> for Error {
    #[inline]
    fn from(e: std::io::Error) -> Error {
        Error { kind: ErrorKind::InternalError, error: Some(Box::new(e)) }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.error {
            Some(ref e) => e.source(),
            None => None,
        }
    }
}