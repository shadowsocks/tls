use std::io;

/// 255 octets or less
pub const MAXIMUM_NAMES_SIZE: usize = 255;
/// 63 octets or less
pub const MAXIMUM_LABEL_SIZE: usize = 63;


// 域名字符集
// 
// 2.3.1. Preferred name syntax
// https://tools.ietf.org/html/rfc1035#section-2.3.1
// 
// Domain name syntax
// https://en.wikipedia.org/wiki/Domain_name#Domain_name_syntax
pub fn is_ascii_name(s: &str) -> bool {
    for ch in s.as_bytes() {
        match ch {
            b'a' ..= b'z' | b'A' ..= b'Z' | b'0' ..= b'9' | b'-' | b'_' => { },
            // internationalized domain name
            _ => return false,
        }
    }
    return true
}

pub fn encode(s: &str) -> Result<String, io::Error> {
    let mut name = punycode::encode(s).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid Domain Name."))?;
    name.insert_str(0, "xn--");
    
    Ok(name)
}

