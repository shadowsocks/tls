// TLS Heartbeat Modes
// https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#heartbeat-modes
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeartbeatMode(pub u8);

impl HeartbeatMode {
    pub const PEER_ALLOWED_TO_SEND: Self      = Self(1);
    pub const PEER_NOT_ALLOWED_TO_SEND: Self  = Self(2);

    pub const fn to_be_bytes(&self) -> [u8; 1] {
        self.0.to_be_bytes()
    }
}

impl std::fmt::Display for HeartbeatMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::PEER_ALLOWED_TO_SEND => write!(f, "PEER_ALLOWED_TO_SEND"),
            Self::PEER_NOT_ALLOWED_TO_SEND => write!(f, "PEER_NOT_ALLOWED_TO_SEND"),
            _ => write!(f, "Unknow({})", self.0),
        }
    }
}

// TLS Heartbeat Message Types
// https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#heartbeat-message-types
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeartbeatMessageKind(pub u8);

impl HeartbeatMessageKind {
    pub const HEARTBEAT_REQUEST: Self   = Self(1);
    pub const HEARTBEAT_RESPONSE: Self  = Self(2);

    pub const fn to_be_bytes(&self) -> [u8; 1] {
        self.0.to_be_bytes()
    }
}

impl std::fmt::Display for HeartbeatMessageKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::HEARTBEAT_REQUEST  => write!(f, "HEARTBEAT_REQUEST"),
            Self::HEARTBEAT_RESPONSE => write!(f, "HEARTBEAT_RESPONSE"),
            _ => write!(f, "Unknow({})", self.0),
        }
    }
}
