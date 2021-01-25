use crate::wire::*;
use crate::error::Error;
use crate::error::ErrorKind;


macro_rules! alert {
    ($level:tt, $descp:tt) => ( Alert { level: AlertLevel::$level, description: AlertDescription::$descp } )
}

macro_rules! err {
    ($level:tt) => (
        io::Error::from(io::ErrorKind::$level)
    );
    ($level:tt, $descp:expr) => (
        io::Error::new(io::ErrorKind::$level, $descp)
    )
}

macro_rules! tls_err {
    ($level:tt) => (
        Error::from(ErrorKind::$level)
    );
    ($level:tt, $descp:tt) => (
        Error::new(ErrorKind::$level, $descp)
    )
}
