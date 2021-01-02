// use crate::record::ContentKind;
// use crate::record::MAX_RECORD_DATA_LEN;
// use crate::extension::ExtensionKind;
// use crate::handshake::HandshakeKind;
use crate::wire::*;


use std::convert::TryFrom;

// struct {
//     ContentType type;
//     ProtocolVersion legacy_record_version;
//     uint16 length;
//     opaque fragment[TLSPlaintext.length];
// } TLSPlaintext;
// 
// struct Handshake {
//     kind: HandshakeKind,
//     length: u24,
//     payload: ClientHello {
//         version: ProtocolVersion,
//         random : [u8; 32],
//         session_id_len: u8,           // <0..32>
//         session_id: Vec<u8>,
//         ciphers_len: u16,             // <2..2^16-2>
//         cipher_suites: Vec<u16>,
//         comp_len: u8,                 // <1..2^8-1>
//         compression_methods: Vec<u8>,
//         ext_len: u16,                 // <8..2^16-1>
//         extensions: Vec<Extension>,
//     }
// }

macro_rules! write_plaintext_record {
    ($cursor:tt, $record_kind:ident, $version:ident, $code:stmt) => {
        $cursor.write_all(&ContentKind::$record_kind.to_be_bytes())?;
        $cursor.write_all(&ProtocolVersion::$version.to_be_bytes())?;
        // 2**14 - 1 = 16383
        // MAX_RECORD_DATA_LEN
        transaction!($cursor, u16, 2, 0, 16383, $code);
    }
}

macro_rules! write_handshake {
    ($cursor:tt, $handshake_kind:ident, $code:stmt) => {
        $cursor.write_all(&HandshakeKind::$handshake_kind.to_be_bytes())?;
        // 2**24 - 1 = 16777215
        transaction!($cursor, u24, 3, 0, 16777215, $code);
    }
}

macro_rules! transaction {
    ($cursor:tt, $length_type:ty, $length_octets_len:literal, $min:literal, $max:literal, $code:stmt) => {
        let start_pos = $cursor.position();
        $cursor.set_position(start_pos + $length_octets_len);
        $code
        {
            let end_pos = $cursor.position();
            let data_len = end_pos - start_pos;
            #[allow(unused_comparisons)]
            if data_len < $length_octets_len || data_len < $min || data_len > $max {
                return Err(io::Error::new(io::ErrorKind::Other, "payload size limit."));
            }
            let data_len = data_len - $length_octets_len;
            let data_len: $length_type = <$length_type>::try_from(data_len).unwrap();

            let raw_buf = $cursor.get_mut();
            let start = usize::try_from(start_pos).expect("oops.");
            let end = start + $length_octets_len;
            &mut raw_buf[start..end].copy_from_slice(&data_len.to_be_bytes());
        }
    }
}


#[allow(non_camel_case_types)]
pub struct u24(u32);

impl u24 {
    pub const fn max_value() -> u32 {
        // 2**24
        16777216u32
    }

    pub const fn to_be_bytes(&self) -> [u8; 3] {
        let octets = self.0.to_be_bytes();
        [octets[1], octets[2], octets[3]]
    }
}

impl std::convert::TryFrom<u32> for u24 {
    type Error = ();

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        if value > Self::max_value() {
            Err(())
        } else {
            Ok(u24(value))
        }
    }
}

impl std::convert::TryFrom<u64> for u24 {
    type Error = ();

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        if value > Self::max_value() as u64 {
            Err(())
        } else {
            Ok(u24(value as u32))
        }
    }
}

impl std::convert::TryInto<u64> for u24 {
    type Error = ();

    fn try_into(self) -> Result<u64, Self::Error> {
        Ok(self.0 as u64)
    }
}