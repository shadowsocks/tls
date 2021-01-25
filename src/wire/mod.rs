
pub const U8_MAX: usize  = u8::MAX as usize;
pub const U14_MAX: usize =    16383; // 2 ** 14 - 1
pub const U16_MAX: usize = u16::MAX as usize;
pub const U24_MAX: usize = 16777215; // 2 ** 24 - 1
#[cfg(any(target_pointer_width = "32", target_pointer_width = "64"))]
pub const U32_MAX: usize = u32::MAX as usize;


mod version;
mod cipher;
mod alert;
mod heartbeat;
mod handshake;
mod record;
mod extension;

pub use self::version::*;
pub use self::cipher::*;
pub use self::alert::*;
pub use self::heartbeat::*;
pub use self::handshake::*;
pub use self::record::*;
pub use self::extension::*;